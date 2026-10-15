"""Saved model-endpoint environment with per-session confirmation.

Two layers of state, both outside any project and never containing a secret:

* the **saved environment** (config dir): `endpoint.json` in the runner's endpoint schema plus
  `environment.json` metadata. It survives across sessions.
* the **session record** (state dir): which saved environment, identified by fingerprint, the user
  confirmed in this agent session. A new session id therefore always starts unconfirmed, and editing the
  saved environment invalidates earlier confirmations.

Resulting states (`evaluate`): no-environment, needs-confirmation, ready, broken. The agent protocol that
uses them is documented in SKILL.md ("Environment gate").
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import ProxyHandler, Request, build_opener

import secret_store
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"runtime"))
from context_contract import interpret_context, check_context

SESSION_RE = re.compile(r'[A-Za-z0-9_.-]{1,64}')
SESSION_TTL_SECONDS = 7 * 24 * 3600
EXIT_NO_ENV, EXIT_NEEDS_CONFIRM, EXIT_BROKEN = 10, 11, 12
DUMMY_KEY = 'local-no-auth'


class EnvError(RuntimeError):
    def __init__(self, message, state='broken', reason=''):
        super().__init__(message)
        self.state = state
        self.reason = reason


# --------------------------------------------------------------------------- paths

def config_dir() -> Path:
    if os.environ.get('PI_LAB_CONFIG_DIR'):
        return Path(os.environ['PI_LAB_CONFIG_DIR']).expanduser()
    base = os.environ.get('XDG_CONFIG_HOME') or str(Path.home() / '.config')
    new_dir = Path(base).expanduser() / 'pi-agent-test-env' / 'environment'
    old_dir = Path(base).expanduser() / 'pi-agentic-development' / 'environment'
    if not new_dir.exists() and old_dir.exists():
        return old_dir
    return new_dir


def state_dir() -> Path:
    if os.environ.get('PI_LAB_STATE_DIR'):
        return Path(os.environ['PI_LAB_STATE_DIR']).expanduser()
    new_dir = Path.home() / '.local/state/pi-agent-test-env'
    old_dir = Path.home() / '.local/state/pi-agentic-development'
    if not new_dir.exists() and old_dir.exists():
        return old_dir
    return new_dir


def endpoint_path() -> Path:
    return config_dir() / 'endpoint.json'


def meta_path() -> Path:
    return config_dir() / 'environment.json'


def session_path(session: str) -> Path:
    return state_dir() / 'sessions' / f'{session}.json'


def resolve_session(value: str | None) -> str:
    session = value or os.environ.get('PI_LAB_SESSION') or ''
    if not session:
        raise EnvError('No session id. Generate one with `env new-session`, then pass --session ID '
                       '(or export PI_LAB_SESSION) on every call during this conversation.',
                       'needs-session', 'missing-session')
    if not SESSION_RE.fullmatch(session):
        raise EnvError('Session id must match [A-Za-z0-9_.-]{1,64}', 'needs-session', 'invalid-session')
    return session


def new_session_id() -> str:
    return 'pl-' + hashlib.sha256(os.urandom(16)).hexdigest()[:16]


# --------------------------------------------------------------------------- storage

def _write_json(path: Path, value, mode=0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(f'.{path.name}.{os.getpid()}.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        json.dump(value, handle, indent=2)
        handle.write('\n')
    os.replace(tmp, path)


def fingerprint_of(endpoint: dict) -> str:
    canonical = json.dumps(endpoint, sort_keys=True, separators=(',', ':'))
    return 'env:' + hashlib.sha256(canonical.encode()).hexdigest()[:12]


def load_saved() -> tuple[dict, dict] | None:
    """Return (endpoint, meta) or None. A corrupt file is reported as broken, not hidden."""
    if not endpoint_path().exists():
        return None
    try:
        endpoint = json.loads(endpoint_path().read_text(encoding='utf-8'))
        meta = json.loads(meta_path().read_text(encoding='utf-8')) if meta_path().exists() else {}
    except (OSError, ValueError) as exc:
        raise EnvError(f'Saved environment is unreadable: {exc}', 'broken', 'environment-corrupt') from None
    if not isinstance(endpoint, dict) or not isinstance(meta, dict):
        raise EnvError('Saved environment has an unexpected structure', 'broken', 'environment-corrupt')
    return endpoint, meta


def save_environment(endpoint: dict, name: str = 'default') -> dict:
    meta = {'schema': 1, 'name': name, 'saved_at': int(time.time()), 'fingerprint': fingerprint_of(endpoint)}
    _write_json(endpoint_path(), endpoint)
    _write_json(meta_path(), meta)
    return meta


def clear_environment() -> bool:
    removed = False
    for path in (endpoint_path(), meta_path()):
        if path.exists():
            path.unlink()
            removed = True
    return removed


def purge_old_sessions(now: float | None = None) -> None:
    root = state_dir() / 'sessions'
    if not root.is_dir():
        return
    now = now or time.time()
    for path in root.glob('*.json'):
        try:
            if now - path.stat().st_mtime > SESSION_TTL_SECONDS:
                path.unlink()
        except OSError:
            pass


def read_session(session: str) -> dict:
    path = session_path(session)
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def confirm_session(session: str, fingerprint: str) -> dict:
    record = {'session': session, 'confirmed_fingerprint': fingerprint, 'confirmed_at': int(time.time())}
    purge_old_sessions()
    _write_json(session_path(session), record)
    return record


def forget_session(session: str) -> bool:
    path = session_path(session)
    if path.exists():
        path.unlink()
        return True
    return False


# --------------------------------------------------------------------------- HTTP

def _opener():
    return build_opener(ProxyHandler({}))


def http_json(url: str, key: str = '', timeout: float = 10.0, body: dict | None = None):
    headers = {'Content-Type': 'application/json'} if body is not None else {}
    if key:
        headers['Authorization'] = 'Bearer ' + key
    data = json.dumps(body).encode() if body is not None else None
    request = Request(url, data=data, headers=headers, method='POST' if body is not None else 'GET')
    with _opener().open(request, timeout=timeout) as response:
        return json.loads(response.read(8 * 1024 * 1024))


def normalize_base_url(value: str) -> str:
    value = (value or '').strip().rstrip('/')
    parts = urlsplit(value)
    if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password \
            or parts.query or parts.fragment:
        raise EnvError('base_url must be http(s)://host[:port][/v1] without credentials, query, or fragment',
                       'invalid-input', 'invalid-base-url')
    path = parts.path.rstrip('/')
    if not path:
        path = '/v1'  # the most common server layout; the user can override by passing the full path
    if not path.endswith('/v1'):
        raise EnvError('This runner needs an OpenAI Chat Completions base_url ending in /v1',
                       'invalid-input', 'invalid-base-url')
    return urlunsplit((parts.scheme, parts.netloc, path, '', ''))


def classify_http(exc: Exception) -> tuple[str, str]:
    if isinstance(exc, HTTPError):
        return ('endpoint-auth-failed' if exc.code in (401, 403) else 'endpoint-unreachable'), f'HTTP {exc.code}'
    if isinstance(exc, (URLError, OSError, TimeoutError)):
        return 'endpoint-unreachable', str(getattr(exc, 'reason', exc))
    return 'endpoint-unreachable', f'unreadable response: {exc}'


# --------------------------------------------------------------------------- discovery

META_KEYS = ('n_ctx_train', 'n_params', 'size', 'n_vocab')


def model_summary(item, models=None, props=None):
    context=interpret_context(item.get('id'),models or [item],props)
    sources=context['effective_sources']
    meta=item.get('meta') if isinstance(item.get('meta'),dict) else {}
    out={'id':item.get('id'),'owned_by':item.get('owned_by'),
            'context_window_hint':context['effective_limit'],
            'context_hint_source':next((x['source'].removeprefix('models.') for x in sources if x['value']==context['effective_limit']),None),
            'context':context,'meta':{k:v for k,v in meta.items() if k in META_KEYS}}
    architecture=item.get('architecture') if isinstance(item.get('architecture'),dict) else {}
    modalities=item.get('capabilities') or architecture.get('input_modalities')
    if modalities:out['capabilities_hint']=modalities
    return out


def fetch_props(base_url,key,timeout):
    try:return http_json(base_url[:-3]+'/props',key,timeout)
    except Exception:return None


def discover(base_url: str, api_key_env: str, timeout: float = 10.0, store=None) -> dict:
    base_url = normalize_base_url(base_url)
    secret_store.check_name(api_key_env)
    key, source = secret_store.resolve_secret(api_key_env, store)
    attempts = [(key, source or 'none')] if not key else [(key, source), ('', 'none')]
    last = None
    for attempt_key, label in attempts:
        try:
            listing = http_json(base_url + '/models', attempt_key, timeout)
            break
        except Exception as exc:  # noqa: BLE001 - classified below
            last = exc
            continue
    else:
        reason, detail = classify_http(last)
        if reason == 'endpoint-auth-failed' and not key:
            detail += f'; no key found in {api_key_env}. Store it with `secrets set {api_key_env}`'
        raise EnvError(f'Cannot list models at {base_url}/models: {detail}', 'broken', reason)
    items = [m for m in listing.get('data', []) if isinstance(m, dict) and m.get('id')] \
        if isinstance(listing, dict) else []
    if not items:
        raise EnvError(f'{base_url}/models answered but listed no models', 'broken', 'model-not-found')
    result = {'base_url': base_url, 'api_key_env': api_key_env,
              'auth': 'key' if label != 'none' else 'not-required (request succeeded without a key)',
              'key_source': label, 'models': []}
    props=fetch_props(base_url,attempt_key,timeout)
    result['models']=[model_summary(m,items,props) for m in items]
    return result


# --------------------------------------------------------------------------- health

def health_check(endpoint: dict, store=None, timeout: float = 15.0, chat: bool = True) -> dict:
    """Host-side check of the saved environment. Raises EnvError(state='broken') with a reason code."""
    base_url, name = endpoint.get('host_base_url',endpoint.get('base_url','')), endpoint.get('api_key_env','')
    try:
        secret_store.check_name(name)
        key, source = secret_store.resolve_secret(name, store)
    except secret_store.SecretError as exc:
        raise EnvError(str(exc), 'broken', 'secret-store-insecure') from None
    if not key:
        raise EnvError(f'Key variable {name} is not set in the environment or the secret store', 'broken',
                       'missing-secret')
    try:
        listing = http_json(base_url.rstrip('/') + '/models', key, timeout)
    except Exception as exc:  # noqa: BLE001
        reason, detail = classify_http(exc)
        raise EnvError(f'{base_url}/models: {detail}', 'broken', reason) from None
    ids = [m.get('id') for m in listing.get('data', []) if isinstance(m, dict)]
    if endpoint.get('model') not in ids:
        raise EnvError(f'Model {endpoint.get("model")} is no longer listed; server offers {ids[:8]}', 'broken',
                       'model-not-found')
    context=interpret_context(endpoint['model'],listing.get('data',[]),fetch_props(base_url,key,timeout))
    try:check_context(context,endpoint['context_window'])
    except ValueError as exc:raise EnvError(str(exc),'broken','context-too-small') from None
    detail = {'models_listed': len(ids), 'key_source': source, 'chat': 'skipped','context':context}
    if chat:
        body = {'model': endpoint['model'], 'messages': [{'role': 'user', 'content': 'Reply with OK.'}],
                endpoint.get('compat', {}).get('maxTokensField', 'max_tokens'): 16, 'stream': False}
        try:
            reply = http_json(base_url.rstrip('/') + '/chat/completions', key, max(timeout, 60.0), body)
        except Exception as exc:  # noqa: BLE001
            reason, text = classify_http(exc)
            raise EnvError(f'Chat completion failed: {text}', 'broken', 'chat-failed' if reason == 'endpoint-unreachable' else reason) from None
        if not isinstance(reply, dict) or not reply.get('choices'):
            raise EnvError('Chat completion returned no choices', 'broken', 'chat-failed')
        detail['chat'] = 'ok'
    return detail


# --------------------------------------------------------------------------- state machine

def summary(endpoint: dict) -> dict:
    return {k: endpoint.get(k) for k in ('base_url', 'host_base_url', 'model', 'api_key_env', 'context_window', 'max_tokens', 'input', 'reasoning','sampling','server_provenance')}


def evaluate(session: str | None, check: bool = True, store=None, chat: bool = False) -> dict:
    session = resolve_session(session)
    try:
        saved = load_saved()
    except EnvError as exc:
        return {'state': 'broken', 'reason': exc.reason, 'detail': str(exc), 'session': session,
                'next': 'Ask the user to set up a new environment (discover, then save) or clear the corrupt one.'}
    if not saved:
        return {'state': 'no-environment', 'session': session,
                'next': 'Ask the user for the server base URL only; use PI_API_KEY from the environment/store, then run `env discover`. '
                        'Only if authentication fails, have the user enter PI_API_KEY securely in their own terminal. Let the user choose a live-listed model, then `env save`.'}
    endpoint, meta = saved
    fingerprint = fingerprint_of(endpoint)
    report = {'session': session, 'fingerprint': fingerprint, 'environment': summary(endpoint),
              'saved_name': meta.get('name'), 'saved_at': meta.get('saved_at')}
    if read_session(session).get('confirmed_fingerprint') != fingerprint:
        report.update(state='needs-confirmation',
                      next='Show the environment to the user and ask: use it, or set up a new one? '
                           'On "use", run `env confirm`; on "new", run discover/save.')
        return report
    if check:
        try:
            report['health'] = health_check(endpoint, store, chat=chat)
        except EnvError as exc:
            report.update(state='broken', reason=exc.reason, detail=str(exc),
                          next='Tell the user what failed and ask: fix the variable (key/URL/model) or set up a '
                               'new environment. Do not silently fall back to another server or model.')
            return report
    report['state'] = 'ready'
    return report


def require_ready(session: str | None, store=None) -> Path:
    """Gate for commands that run children without an explicit --endpoint."""
    report = evaluate(session, check=True, store=store)
    if report['state'] != 'ready':
        raise EnvError(report.get('detail') or report['next'], report['state'], report.get('reason', ''))
    return endpoint_path()


EXIT_CODES = {'ready': 0, 'no-environment': EXIT_NO_ENV, 'needs-confirmation': EXIT_NEEDS_CONFIRM,
              'broken': EXIT_BROKEN}


# --------------------------------------------------------------------------- CLI

def add_parser(sub) -> None:
    env = sub.add_parser('env', help='Saved model environment: status, discover, save, confirm, check, clear')
    ops = env.add_subparsers(dest='env_op', required=True)
    ops.add_parser('new-session', help='Print a fresh session id for this agent conversation')
    st = ops.add_parser('status', help='Evaluate the gate: no-environment | needs-confirmation | ready | broken')
    st.add_argument('--session')
    st.add_argument('--no-check', action='store_true', help='Skip the live server check')
    st.add_argument('--chat', action='store_true', help='Also run one tiny chat completion')
    cf = ops.add_parser('confirm', help='Record that the user approved the saved environment for this session')
    cf.add_argument('--session')
    for command in (st,cf):
        command.add_argument('--id',help='Explicit named indexed environment; uses offline per-profile state')
        command.add_argument('--catalog-dir')
        command.add_argument('--secrets-dir')
    ds = ops.add_parser('discover', help='List models and parameters offered by a server')
    ds.add_argument('--base-url', required=True)
    ds.add_argument('--api-key-env', default='PI_API_KEY')
    ds.add_argument('--timeout', type=float, default=10.0)
    sv = ops.add_parser('save', help='Validate and save the chosen environment (and confirm it for the session)')
    sv.add_argument('--base-url', required=True)
    sv.add_argument('--host-base-url',help='Host discovery/health route; defaults to child --base-url')
    sv.add_argument('--model', required=True)
    sv.add_argument('--api-key-env', default='PI_API_KEY')
    sv.add_argument('--context-window', type=int, required=True)
    sv.add_argument('--max-tokens', type=int, required=True)
    sv.add_argument('--image-input', action='store_true', help='Declare text+image input (only if the whole path handles images)')
    sv.add_argument('--reasoning', action='store_true', help='Enable reasoning with default settings')
    sv.add_argument('--reasoning-level', choices=['off', 'minimal', 'low', 'medium', 'high'], help='Thinking level for reasoning models')
    sv.add_argument('--reasoning-budget', type=int, help='Requested reasoning budget; reviewed Pi 0.87.1 profile rejects numeric budgets (no hard ceiling promised)')
    sv.add_argument('--max-tokens-field', choices=['max_tokens', 'max_completion_tokens'], default='max_tokens')
    sv.add_argument('--sampling',help='JSON object of bounded qualified sampling controls')
    sv.add_argument('--server-provenance',help='JSON object of optional user-declared server metadata')
    sv.add_argument('--name', default='default')
    sv.add_argument('--no-auth', action='store_true',
                    help='Server needs no key: store a nonsecret dummy value for the key variable if it is unset')
    sv.add_argument('--no-verify', action='store_true', help='Do not run the live health check before saving')
    sv.add_argument('--session', help='Confirm for this session after saving (default: PI_LAB_SESSION if set)')
    ck = ops.add_parser('check', help='Live health check of the saved environment (models list + tiny chat)')
    ck.add_argument('--id',help='Explicit indexed profile; bounded broker admission required')
    ck.add_argument('--session');ck.add_argument('--catalog-dir');ck.add_argument('--secrets-dir')
    ck.add_argument('--image');ck.add_argument('--resources');ck.add_argument('--platform',choices=['linux/arm64','linux/amd64'])
    ck.add_argument('--no-chat', action='store_true')
    cl = ops.add_parser('clear', help='Delete the saved environment')
    cl.add_argument('--session', help='Also forget this session confirmation')
    ops.add_parser('path', help='Print the saved endpoint file path')
    listing=ops.add_parser('list',help='Offline metadata-only indexed environment list')
    listing.add_argument('--json',action='store_true');listing.add_argument('--catalog-dir');listing.add_argument('--secrets-dir')
    inspect=ops.add_parser('inspect',help='Offline indexed inspection; detailed configuration is private-only')
    inspect.add_argument('--id');inspect.add_argument('--index',type=int);inspect.add_argument('--catalog-revision',type=int)
    inspect.add_argument('--private',action='store_true');inspect.add_argument('--json',action='store_true')
    inspect.add_argument('--catalog-dir');inspect.add_argument('--secrets-dir')
    for name in ('register','update','revoke','delete'):
        indexed=ops.add_parser(name,help='Explicit offline indexed catalog mutation')
        indexed.add_argument('--id',required=True);indexed.add_argument('--catalog-dir');indexed.add_argument('--secrets-dir')
        if name in ('register','update'):
            indexed.add_argument('--config',required=True);indexed.add_argument('--default',action='store_true')
        if name!='register':indexed.add_argument('--expected-revision',type=int,required=True)


def run(args, validate_endpoint, store=None) -> int:
    """`validate_endpoint(path) -> dict` is the runner's load_endpoint, injected to avoid a circular import."""
    def out(value):
        print(json.dumps(value, indent=2))

    op = args.env_op
    if op in ('list','inspect','register','update','revoke','delete') or getattr(args,'id',None) is not None:
        import inference_catalog
        return inference_catalog.command(args)
    try:
        if op == 'new-session':
            print(new_session_id())
            return 0
        if op == 'path':
            print(endpoint_path())
            return 0
        if op == 'status':
            report = evaluate(args.session, check=not args.no_check, store=store, chat=args.chat)
            out(report)
            return EXIT_CODES.get(report['state'], 2)
        if op == 'confirm':
            session = resolve_session(args.session)
            saved = load_saved()
            if not saved:
                raise EnvError('No saved environment to confirm', 'no-environment', 'environment-missing')
            record = confirm_session(session, fingerprint_of(saved[0]))
            out({'confirmed': True, 'session': session, 'fingerprint': record['confirmed_fingerprint']})
            return 0
        if op == 'discover':
            out(discover(args.base_url, args.api_key_env, args.timeout, store))
            return 0
        if op == 'check':
            saved = load_saved()
            if not saved:
                raise EnvError('No saved environment', 'no-environment', 'environment-missing')
            out({'ok': True, **health_check(saved[0], store, chat=not args.no_chat)})
            return 0
        if op == 'clear':
            removed = clear_environment()
            forgotten = forget_session(resolve_session(args.session)) if args.session else False
            out({'cleared': removed, 'session_forgotten': forgotten})
            return 0
        return save(args, validate_endpoint, store, out)
    except EnvError as exc:
        out({'state': exc.state, 'reason': exc.reason, 'detail': str(exc)})
        return EXIT_CODES.get(exc.state, 2)
    except secret_store.SecretError as exc:
        out({'state': 'broken', 'reason': 'secret-store-insecure', 'detail': str(exc)})
        return EXIT_BROKEN


def save(args, validate_endpoint, store, out) -> int:
    base_url = normalize_base_url(args.base_url)
    name = secret_store.check_name(args.api_key_env)
    endpoint = {'base_url': base_url, 'api_key_env': name, 'model': args.model,
                'context_window': args.context_window, 'max_tokens': args.max_tokens,
                'input': ['text', 'image'] if args.image_input else ['text'],
                'compat': {'maxTokensField': args.max_tokens_field}}
    if getattr(args,'host_base_url',None):endpoint['host_base_url']=normalize_base_url(args.host_base_url)
    if args.reasoning_level or args.reasoning_budget:
        r = {}
        if args.reasoning_level:
            r['level'] = args.reasoning_level
            r['enabled'] = args.reasoning_level != 'off'
        else:
            r['enabled'] = True
            r['level'] = 'low'
        if args.reasoning_budget:
            r['budget_tokens'] = args.reasoning_budget
        endpoint['reasoning'] = r
    elif args.reasoning:
        endpoint['reasoning'] = True
    for field in ('sampling','server_provenance'):
        if getattr(args,field,None):
            try:endpoint[field]=json.loads(getattr(args,field))
            except ValueError:raise EnvError(f'{field} must be valid JSON','invalid-input','invalid-endpoint') from None
    candidate = config_dir() / '.candidate.json'
    _write_json(candidate, endpoint)
    try:
        try:
            endpoint = validate_endpoint(candidate)
        except Exception as exc:  # noqa: BLE001 - the runner's validation message is the useful part
            raise EnvError(f'Invalid environment: {exc}', 'invalid-input', 'invalid-endpoint') from None
    finally:
        candidate.unlink(missing_ok=True)
    key, _ = secret_store.resolve_secret(name, store)
    if not key and args.no_auth:
        secret_store.write_secret(name, DUMMY_KEY, store)
    if not args.no_verify:
        health_check(endpoint, store, chat=True)
    meta = save_environment(endpoint, args.name)
    result = {'saved': True, 'path': str(endpoint_path()), 'fingerprint': meta['fingerprint'],
              'environment': summary(endpoint)}
    session = args.session or os.environ.get('PI_LAB_SESSION')
    if session:
        confirm_session(resolve_session(session), meta['fingerprint'])
        result['confirmed_for_session'] = session
    out(result)
    return 0
