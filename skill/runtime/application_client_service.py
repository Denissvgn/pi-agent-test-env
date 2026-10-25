"""Owned scoped helper. Authority-only mode has no application effects.

Configuration and application values arrive once on private stdin. Client requests
cannot add authority, rotate credentials, name files, or select outbound routes.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import argparse
import copy
import json
import os
import secrets
import stat
import sys
import threading
import uuid

sys.path[:0] = [str(Path(__file__).resolve().parents[1] / 'scripts'),
                str(Path(__file__).resolve().parent)]
import application_contracts as c
import application_credentials as credentials

MAX_CONFIG_BYTES = 2 * 1024 * 1024
MAX_REQUEST_BYTES = 65536
MAX_RESULT_BYTES = 8192
APPLICATION_AUTH_HEADER = 'X-Agent-API-Key'
TRUSTED_CODE = ('runtime/application_client_service.py', 'runtime/prompt_contract.py',
                'scripts/application_contracts.py', 'scripts/application_documents.py',
                'scripts/resources.py', 'scripts/application_credentials.py',
                'scripts/secret_store.py', 'scripts/stage_control.py',
                'runtime/native_budget_service.py', 'runtime/application_budget.py',
                'scripts/tool_budgets.py', 'runtime/native_tool_contracts.py',
                'runtime/release_contracts.py', 'runtime/application_execution_service.py',
                'runtime/application_api.py', 'runtime/application_browser.py',
                'runtime/application-browser-cdp.mjs', 'runtime/browser-options.mjs',
                'runtime/application_runtime_contracts.py',
                'scripts/application_evidence.py', 'runtime/application_files.py')
BINDING_FIELDS = {'run_id', 'trial_id', 'attempt_id', 'stage_id', 'segment_id',
                  'session_id', 'plan_sha256'}
SCOPE_FIELDS = BINDING_FIELDS | {'stage_name', 'participant', 'operation_ids',
                                 'credential_aliases', 'authority_generation'}
STARTUP_CODES = frozenset(('contract_invalid','request_invalid','credential_scope_invalid',
    'authority_changed','evidence_unavailable','operation_not_granted','accounting_unavailable',
    'reporting_only','tool_budget_exhausted','runtime_mismatch','cleanup_unconfirmed'))
MAX_STARTUP_FRAMES = 12
MAX_STARTUP_FRAME_SCAN = 128


class ServiceError(ValueError):
    def __init__(self, reason='operation_not_granted'):
        self.reason = reason
        super().__init__(reason)


def _startup_error_classes(module_name, class_name):
    """Use genuine already-loaded classes, including the script/import copies."""
    module=sys.modules.get(module_name)
    candidate=vars(module).get(class_name) if module is not None else None
    return (candidate,) if type(candidate) is type and issubclass(candidate,BaseException) else ()


def _startup_details(error):
    service_classes=(ServiceError,)+_startup_error_classes('application_client_service','ServiceError')
    budget_classes=_startup_error_classes('tool_budgets','BudgetError')
    if isinstance(error,c.ContractError):category='contract'
    elif isinstance(error,service_classes):category='service'
    elif budget_classes and isinstance(error,budget_classes):category='budget'
    elif isinstance(error,OSError):category='os'
    else:category='other'
    code='unknown'
    if category in ('contract','service','budget'):
        candidate=getattr(error,'reason',None)
        if type(candidate) is str and candidate in STARTUP_CODES:code=candidate
    number=getattr(error,'errno',None) if category=='os' else None
    number=number if type(number) is int and 1<=number<=4095 else None
    root=Path(__file__).resolve().parents[1]
    trusted={str(root/relative):relative for relative in TRUSTED_CODE}
    frames=[];truncated=False;trace=error.__traceback__;scanned=0
    while trace is not None and scanned<MAX_STARTUP_FRAME_SCAN:
        scanned+=1;relative=trusted.get(trace.tb_frame.f_code.co_filename);line=trace.tb_lineno
        if relative is not None and type(line) is int and 1<=line<=1000000:
            if len(frames)==MAX_STARTUP_FRAMES:frames.pop(0);truncated=True
            frames.append({'file':relative,'line':line})
        else:truncated=True
        trace=trace.tb_next
    if trace is not None:truncated=True
    return {'schema':1,'category':category,'code':code,'errno':number,
            'frames':frames,'frames_truncated':truncated}


def _emit_startup_failure(error):
    """A bounded static diagnostic, never exception strings, source or locals."""
    try:
        result={'schema':1,'status':'blocked','reason':'client_start_failed',
                'diagnostic':_startup_details(error)}
        wire=json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False)
        if len(wire.encode())>4096:raise ValueError()
    except BaseException:
        wire='{"schema":1,"status":"blocked","reason":"client_start_failed"}'
    stream=sys.stderr
    if stream is None:return False
    try:
        stream.write(wire+'\n');stream.flush()
        return True
    except BaseException:
        # A broken diagnostic sink must not make the interpreter format the
        # original private exception context, including during final flushing.
        sys.stderr=None
        return False


def token(value):
    if type(value) is not str or len(value) != 64 or any(ch not in '0123456789abcdef' for ch in value):
        raise ServiceError('request_invalid')
    return value


def validate_scope(scope, plan):
    c.exact(scope, SCOPE_FIELDS, '/scope')
    for field in BINDING_FIELDS - {'plan_sha256'}:
        if field == 'trial_id' and scope[field] is None:
            continue
        try:
            if str(uuid.UUID(scope[field])) != scope[field]:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise ServiceError('request_invalid') from None
    if scope['plan_sha256'] != plan['plan_sha256']:
        raise ServiceError('operation_not_granted')
    try:
        if str(uuid.UUID(scope['authority_generation'])) != scope['authority_generation']:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise ServiceError('request_invalid') from None
    stage = next((s for s in plan['stages'] if s['id'] == scope['stage_name']), None)
    if (stage is None or scope['participant'] != stage['participant']
            or scope['operation_ids'] != stage['operations']
            or scope['credential_aliases'] != stage['credential_aliases']):
        raise ServiceError('operation_not_granted')
    return stage


def verify_code(identity):
    c.exact(identity, set(TRUSTED_CODE), '/code_identity')
    import hashlib
    for relative, expected in identity.items():
        c.sha256(expected, '/code_identity/' + c.escape(relative))
        path = Path(__file__).resolve().parents[1] / relative
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1048576:
                raise ServiceError('authority_changed')
            actual = hashlib.sha256(source.read(1048577)).hexdigest()
        if not secrets.compare_digest(actual, expected):
            raise ServiceError('authority_changed')


class CapabilityService:
    """Immutable configuration plus monotonic revocation; values never serialize."""
    def __init__(self, configuration):
        c.exact(configuration, {'schema', 'document_type', 'plan', 'authorities',
                                'capabilities', 'control_token', 'evidence_root', 'code_identity', 'mode'}, '')
        c.choice(configuration['schema'], (1,), '/schema')
        c.choice(configuration['document_type'], ('application_client_private_bootstrap',), '/document_type')
        c.choice(configuration['mode'], ('authority-only',), '/mode')
        self.plan = c.validate_ir(configuration['plan'])
        verify_code(configuration['code_identity'])
        self._control_token = token(configuration['control_token'])
        c.exact(configuration['authorities'], {s['id'] for s in self.plan['stages']}, '/authorities')
        self._authorities = copy.deepcopy(configuration['authorities'])
        for stage in self.plan['stages']:
            values = self._authorities[stage['id']]
            c.exact(values, set(stage['credential_aliases']), '/authorities/' + stage['id'])
            for alias, value in values.items():
                c.text(value, '/authorities/' + stage['id'] + '/' + alias, 8192)
                if len(value) < 16 or not value.isascii() or any(ord(ch) <= 32 or ord(ch) == 127 for ch in value):
                    raise ServiceError('credential_scope_invalid')
        self.redactor = credentials.Redactor([value for aliases in self._authorities.values() for value in aliases.values()])
        c.array(configuration['capabilities'], '/capabilities', 64, 1)
        self._grants = []
        for grant in configuration['capabilities']:
            c.exact(grant, {'token', 'scope'}, '/capabilities')
            selected = token(grant['token'])
            validate_scope(grant['scope'], self.plan)
            if secrets.compare_digest(selected, self._control_token) or any(
                    secrets.compare_digest(selected, existing['token']) for existing in self._grants):
                raise ServiceError('operation_not_granted')
            if self._grants and any(grant['scope'][key] != self._grants[0]['scope'][key]
                                    for key in ('run_id', 'trial_id', 'attempt_id', 'authority_generation')):
                raise ServiceError('operation_not_granted')
            self._grants.append({'token': selected, 'scope': copy.deepcopy(grant['scope']), 'revoked': False})
        self._lock = threading.RLock()
        self._evidence_root = Path(configuration['evidence_root'])
        descriptor = os.open(self._evidence_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise ServiceError('evidence_unavailable')
        finally:
            os.close(descriptor)

    def __repr__(self):
        return '<CapabilityService private authority withheld>'

    def _lookup(self, bearer):
        # Compare every fixed-length token through the same constant-time primitive.
        selected = None
        valid = type(bearer) is str and len(bearer) == 64 and all(ch in '0123456789abcdef' for ch in bearer)
        candidate = bearer if valid else '0' * 64
        for grant in self._grants:
            if secrets.compare_digest(candidate, grant['token']):
                selected = grant
        if not valid or selected is None or selected['revoked']:
            raise ServiceError()
        return selected

    def authorize(self, bearer, scope, operation_id=None):
        with self._lock:
            grant = self._lookup(bearer)
            if scope != grant['scope']:
                raise ServiceError()
            validate_scope(scope, self.plan)
            if operation_id is not None and operation_id not in scope['operation_ids']:
                raise ServiceError()
            return copy.deepcopy(scope)

    def private_authority(self, bearer, scope, operation_id):
        """Trusted adapter extension point; never included in any HTTP response."""
        admitted = self.authorize(bearer, scope, operation_id)
        operation = next(op for op in self.plan['application']['operations'] if op['id'] == operation_id)
        alias = operation['credential_alias']
        return self._authorities[admitted['stage_name']][alias]

    def request(self, path, bearer, body):
        with self._lock:
            if path == '/control':
                valid = type(bearer) is str and len(bearer) == 64 and all(ch in '0123456789abcdef' for ch in bearer)
                candidate = bearer if valid else '0' * 64
                matched = secrets.compare_digest(candidate, self._control_token)
                if not valid or not matched:
                    raise ServiceError()
                c.exact(body, {'schema', 'action', 'capability'}, '')
                c.choice(body['schema'], (1,), '/schema')
                c.choice(body['action'], ('revoke',), '/action')
                selected = token(body['capability'])
                found = False
                for grant in self._grants:
                    if secrets.compare_digest(selected, grant['token']):
                        grant['revoked'] = True; found = True
                if not found:
                    raise ServiceError()
                return {'schema': 1, 'ok': True, 'revoked': True}
            if path != '/ipc':
                raise ServiceError('request_invalid')
            c.exact(body, {'schema', 'action', 'scope', 'operation_id'}, '')
            c.choice(body['schema'], (1,), '/schema')
            c.choice(body['action'], ('status', 'validate'), '/action')
            operation = body['operation_id']
            if (body['action'] == 'status' and operation is not None
                    or body['action'] == 'validate' and type(operation) is not str):
                raise ServiceError('request_invalid')
            scope = self.authorize(bearer, body['scope'], operation)
            return {'schema': 1, 'ok': True, 'stage_name': scope['stage_name'],
                    'participant': scope['participant'], 'operation_ids': scope['operation_ids'],
                    'credential_aliases': scope['credential_aliases'],
                    'authority_generation': scope['authority_generation'],
                    'business_effects_enabled': False}


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'
    def setup(self):
        self.request.settimeout(5)
        super().setup()

    def log_message(self, *args):
        pass

    def _send(self, status, value):
        body = c.canonical(self.server.authority.redactor.value(value))
        maximum = 256 * 1024 if (self.path == '/budget' or self.path == '/control'
                  and getattr(self.server.authority, 'mode', None) == 'application-execution') else MAX_RESULT_BYTES
        if len(body) > maximum:
            status, body = 503, b'{"schema":1,"ok":false,"reason":"evidence_unavailable"}'
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.connection.settimeout(5)
        try:
            lengths = self.headers.get_all('Content-Length', [])
            auth = self.headers.get_all('Authorization', [])
            if (len(lengths) != 1 or len(auth) != 1 or self.headers.get('Transfer-Encoding')
                    or self.headers.get('Content-Type') != 'application/json'
                    or not auth[0].startswith('Bearer ')):
                raise ServiceError('request_invalid')
            if not lengths[0].isascii() or not lengths[0].isdigit():
                raise ServiceError('request_invalid')
            length = int(lengths[0])
            maximum = (2 * 1024 * 1024 if self.path == '/budget' else
                       320 * 1024 if self.path == '/tool' else MAX_REQUEST_BYTES)
            if not 1 <= length <= maximum:
                raise ServiceError('request_invalid')
            body = self.rfile.read(length)
            if len(body) != length:
                raise ServiceError('request_invalid')
            result = self.server.authority.request(self.path, auth[0][7:], c.loads(body, max_bytes=maximum))
            self._send(200, result)
        except (c.ContractError, ServiceError, OSError, ValueError) as exc:
            self._send(403, {'schema': 1, 'ok': False,
                             'reason': exc.reason if isinstance(exc, ServiceError) else 'request_invalid'})

    def do_GET(self):
        self._send(405, {'schema': 1, 'ok': False, 'reason': 'request_invalid'})


class Server(HTTPServer):
    allow_reuse_address = False
    def __init__(self, address, authority):
        self.authority = authority
        super().__init__(address, Handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--listen', choices=('127.0.0.1', '0.0.0.0'), default='0.0.0.0')
    parser.add_argument('--port', type=int, default=8081)
    args = parser.parse_args()
    body = sys.stdin.buffer.read(MAX_CONFIG_BYTES + 1)
    if len(body) > MAX_CONFIG_BYTES:
        raise ServiceError('request_invalid')
    configuration = c.loads(body, max_bytes=MAX_CONFIG_BYTES)
    if configuration.get('document_type') == 'native_budget_private_bootstrap':
        from native_budget_service import BudgetOnlyService
        authority = BudgetOnlyService(configuration, verify_code=verify_code)
    elif configuration.get('document_type') == 'application_execution_private_bootstrap':
        from application_execution_service import ApplicationService
        authority = ApplicationService(configuration)
    else:
        authority = CapabilityService(configuration)
    server = Server((args.listen, args.port), authority)
    print(json.dumps({'schema': 1, 'status': 'ready', 'port': server.server_port,
                      'business_effects_enabled': False}), flush=True)
    server.serve_forever(poll_interval=0.1)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Private configuration and exception contents must never enter logs.
        _emit_startup_failure(error)
        raise SystemExit(2) from None
