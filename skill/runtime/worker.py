#!/usr/bin/env python3
"""Container-side operations. No Docker CLI/socket; no automatic package installation.

Release contract: references/PI-COMPATIBILITY.md (source-inspected Pi 0.87.1).
Source inspection alone does not qualify execution. Budget/settings mapping,
ordered events and continued segments require observed runtime evidence.
"""
from __future__ import annotations
import argparse
import errno
import hashlib
import browser_sandbox
import json
import math
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, ProxyHandler, build_opener
import uuid
from pi_contract import model_configuration
import release_contracts
from context_contract import interpret_context, check_context
from usage_contract import summarize

APPLICATION_PROFILE_ROOT = Path('/opt/pi-profile')
APPLICATION_RUNTIME_ROOT = Path('/opt/pi-lab')
APPLICATION_TOOLS = ['app_api','app_browser','artifact_read','artifact_write','report_write','budget_status']


def _application_digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def _application_read(path,maximum,private=False):
    if type(path) is not str or not path.startswith('/') or '\0' in path:
        raise ValueError('Invalid compiled application execution')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>maximum
                or private and ((info.st_mode&0o777)!=0o400 or info.st_uid!=os.getuid())):
            raise ValueError('Invalid compiled application execution')
        with os.fdopen(fd,'rb',closefd=False) as source:body=source.read(maximum+1)
        after=os.fstat(fd)
        if (len(body)>maximum or any(getattr(info,key)!=getattr(after,key) for key in
                ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_nlink','st_mode'))):
            raise ValueError('Invalid compiled application execution')
        return body
    finally:os.close(fd)


def application_extension_identity(release,profile_binding,tool_schema_sha256):
    """Hash the actual fixed extension loadout through the shared pure contract."""
    import application_runtime_contracts
    files={}
    for path in application_runtime_contracts.APPLICATION_EXTENSION_PATHS:
        root=APPLICATION_PROFILE_ROOT if path.startswith('/opt/pi-profile/') else APPLICATION_RUNTIME_ROOT
        body=_application_read(str(root/Path(path).name),1048576)
        files[path]=hashlib.sha256(body).hexdigest()
    return application_runtime_contracts.extension_identity(release,profile_binding,tool_schema_sha256,files)


def validate_application_execution(task,profile_context,release):
    """Admit frozen application bytes before settings or any inference process.

    The parent independently admits the compiled plan and exact image/runtime.
    This check binds the worker's prompt, profile assets and private tool scope.
    """
    import application_runtime_contracts
    try:
        marker=task['application_execution']
        fields={'schema','plan_sha256','stage_id','effective_prompt_sha256','tool_schema_sha256','profile_binding','extension_order_sha256'}
        if type(marker) is not dict or set(marker)!=fields or type(marker['schema']) is not int or marker['schema']!=1:
            raise ValueError()
        for field in ('plan_sha256','effective_prompt_sha256','tool_schema_sha256','extension_order_sha256'):
            if type(marker[field]) is not str or not re.fullmatch('[a-f0-9]{64}',marker[field]):raise ValueError()
        if (type(task['prompt']) is not str or not task['prompt'] or
                hashlib.sha256(task['prompt'].encode()).hexdigest()!=marker['effective_prompt_sha256']
                or 'native_budget_context' in task):raise ValueError()
        native={'max_tool_calls':500,'reporting_reserve_calls':20,'reporting_reserve_seconds':120}
        if (any(type(task.get(key)) is not int or not 0<task[key]<=bound for key,bound in native.items())
                or not task['reporting_reserve_calls']<task['max_tool_calls']
                or type(task.get('timeout_seconds')) is not int
                or not task['reporting_reserve_seconds']<task['timeout_seconds']<=3600):raise ValueError()
        if (type(profile_context) is not dict or set(profile_context)!={'schema','profile','profile_sha256',
                'run_id','attempt_id','stage_id','segment_id','allowed_tools'}
                or type(profile_context['schema']) is not int or profile_context['schema']!=1):raise ValueError()
        profile=profile_context['profile']
        if (type(profile) is not dict or set(profile)!={'schema','document_type','id','kind','components','tools','required_tools','assets','service_endpoints'}
                or type(profile['schema']) is not int or profile['schema']!=1 or profile['document_type']!='agent_profile'
                or profile['kind']!='application-client' or profile['id']!='application-client'
                or profile['components']!=[application_runtime_contracts.profile_component(release)]
                or profile['tools']!=APPLICATION_TOOLS or profile['required_tools']!=[]
                or profile['service_endpoints']!=['http://pi-application:8081/tool']):raise ValueError()
        if type(profile['assets']) is not list or len(profile['assets'])!=2:raise ValueError()
        asset_map={};identity_profile=json.loads(json.dumps(profile))
        for asset in identity_profile['assets']:
            if type(asset) is not dict or set(asset)!={'source','target','sha256'}:raise ValueError()
            target=asset['target']
            if type(target) is not str or target not in ('application-client.mjs','instructions.md') or target in asset_map:raise ValueError()
            body=_application_read(str(APPLICATION_PROFILE_ROOT/target),1048576)
            actual=hashlib.sha256(body).hexdigest()
            if asset['sha256']!=actual:raise ValueError()
            asset_map[target]=actual;asset.pop('source')
        binding={'id':'application-client','pi_release':release,'sha256':_application_digest(identity_profile),'assets':asset_map}
        if marker['profile_binding']!=binding or profile_context['profile_sha256']!=binding['sha256']:raise ValueError()
        context=json.loads(_application_read(task['application_context'],65536,private=True))
        if (type(context) is not dict or set(context)!={'schema','scope','capability','base_url','tool_schemas','budget_context'}
                or type(context['schema']) is not int or context['schema']!=1
                or context['base_url']!='http://pi-application:8081/tool'
                or type(context['capability']) is not str or not re.fullmatch('[a-f0-9]{64}',context['capability'])):raise ValueError()
        scope=context['scope'];budget=context['budget_context'];definitions=context['tool_schemas'];tools=task['tools']
        scope_fields={'run_id','trial_id','attempt_id','stage_id','segment_id','session_id','plan_sha256',
                      'stage_name','participant','operation_ids','credential_aliases','authority_generation'}
        if type(scope) is not dict or set(scope)!=scope_fields:raise ValueError()
        for field in ('run_id','attempt_id','stage_id','segment_id','session_id','authority_generation'):
            if type(scope[field]) is not str or str(uuid.UUID(scope[field]))!=scope[field]:raise ValueError()
        if scope['trial_id'] is not None and (type(scope['trial_id']) is not str or str(uuid.UUID(scope['trial_id']))!=scope['trial_id']):raise ValueError()
        if (scope['plan_sha256']!=marker['plan_sha256'] or scope['stage_name']!=marker['stage_id']
                or type(marker['stage_id']) is not str or not re.fullmatch('[a-z0-9][a-z0-9-]{0,63}',marker['stage_id'])
                or scope['session_id']!=task['session_id']
                or any(profile_context[key]!=scope[key] for key in ('run_id','attempt_id','stage_id','segment_id'))):raise ValueError()
        for key,cap in (('prior_turns','max_turns'),('prior_reported_tokens','max_total_tokens')):
            if type(task.get(key,0)) is not int or type(task.get(cap)) is not int or not 0<=task.get(key,0)<=task[cap]:raise ValueError()
        if task.get('resume_session'):
            continuation=task.get('application_continuation')
            if (task['resume_session']!='/opt/pi-control/segments/'+scope['segment_id']+'/session.jsonl'
                    or type(continuation) is not dict
                    or set(continuation)!={'schema','command_id','continues_segment_id','message','sha256'}
                    or type(continuation['schema']) is not int or continuation['schema']!=1):raise ValueError()
            for key in ('command_id','continues_segment_id'):
                if type(continuation[key]) is not str or str(uuid.UUID(continuation[key]))!=continuation[key]:raise ValueError()
            if (continuation['continues_segment_id']==scope['segment_id'] or type(continuation['message']) is not str
                    or not 0<len(continuation['message'].encode())<=16384
                    or hashlib.sha256(continuation['message'].encode()).hexdigest()!=continuation['sha256']):raise ValueError()
        elif ('application_continuation' in task or task.get('prior_turns',0)!=0 or task.get('prior_reported_tokens',0)!=0):
            raise ValueError()
        if (type(tools) is not list or not tools or any(type(name) is not str for name in tools)
                or len(set(tools))!=len(tools) or set(tools)-set(APPLICATION_TOOLS) or 'budget_status' not in tools
                or sorted(tools)!=profile_context['allowed_tools'] or type(definitions) is not list
                or definitions!=task['tool_schemas'] or len(definitions)!=len(tools)):
            raise ValueError()
        if any(type(item) is not dict or set(item)!={'name','description','parameters'} for item in definitions):raise ValueError()
        if [item['name'] for item in definitions]!=tools:raise ValueError()
        schema_sha=_application_digest(sorted(definitions,key=lambda item:item['name']))
        extension_sha=application_extension_identity(release,binding,schema_sha)['sha256']
        budget_fields={'schema','pi_release','scope','allowed_tools','prepare_arguments','extension_order_sha256',
                       'tool_schema_sha256','base_url','capability'}
        if (type(budget) is not dict or set(budget)!=budget_fields or type(budget['schema']) is not int or budget['schema']!=1
                or budget['pi_release']!=release or budget['scope']!=scope or budget['allowed_tools']!=tools
                or budget['prepare_arguments']!={name:'none' for name in tools}
                or budget['base_url']!='http://pi-application:8081/budget'
                or type(budget['capability']) is not str or not re.fullmatch('[a-f0-9]{64}',budget['capability'])
                or budget['capability']==context['capability']
                or budget['extension_order_sha256']!=extension_sha or marker['extension_order_sha256']!=extension_sha
                or schema_sha!=marker['tool_schema_sha256'] or budget['tool_schema_sha256']!=schema_sha):raise ValueError()
        return context
    except (OSError,ValueError,KeyError,TypeError,AttributeError,OverflowError):
        raise ValueError('Invalid compiled application execution') from None

REQUIRED_FLAGS = list(release_contracts.COMMON_FLAGS)


def emit(value):
    print(json.dumps(value, ensure_ascii=False), flush=True)


def execute(argv, timeout=30, env=None):
    p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         start_new_session=True, env=env)
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        out, err = p.communicate()
        raise RuntimeError(f'Timed out: {argv[0]}; {err.decode(errors="replace")[-1000:]}')
    if p.returncode:
        raise RuntimeError(f'{argv[0]} exited {p.returncode}: {err.decode(errors="replace")[-4000:]}')
    return out.decode(errors='replace').strip()


def chromium_path():
    candidates = [os.environ.get('PUPPETEER_EXECUTABLE_PATH'),
                  os.environ.get('CHROME_BIN'), shutil.which('chromium'),
                  shutil.which('chromium-browser')]
    for value in candidates:
        if value and os.path.isfile(value) and os.access(value, os.X_OK):
            return value
    raise RuntimeError('Linux Chromium missing. Build the browser image; do not install apt packages at runtime.')


def environment_probe(contract):
    result = {'required_commands': {}, 'probes': []}
    for name in contract.get('required_commands', []):
        path = shutil.which(name)
        if path is None:
            raise RuntimeError(f'Project image requirement is missing: {name}')
        result['required_commands'][name] = path
    for item in contract.get('probes', []):
        output = execute(item['argv'], timeout=item['timeout_seconds'])
        if 'stdout_regex' in item and not re.search(item['stdout_regex'], output):
            raise RuntimeError(f'Environment probe {item["name"]} did not match its required version/output: {output[:1000]}')
        result['probes'].append({'name': item['name'], 'argv': item['argv'], 'stdout': output[:4000]})
    return result


def select_cwd(task):
    root = Path('/workspace').resolve()
    target = (root / task.get('cwd', '.')).resolve()
    if not target.is_relative_to(root) or not target.is_dir():
        raise RuntimeError(f'Stage cwd does not exist inside /workspace: {target}')
    os.chdir(target)
    return str(target)


def probe(profile):
    result = {'platform': platform.system(), 'architecture': platform.machine(),
              'python': platform.python_version(), 'uid': os.getuid()}
    for name, argv in {'node': ['node', '--version'], 'npm': ['npm', '--version'],
                       'pi': ['pi', '--version'], 'git': ['git', '--version'],
                       'bash': ['bash', '--version'], 'rg': ['rg', '--version']}.items():
        if not shutil.which(argv[0]):
            raise RuntimeError(f'Missing executable: {argv[0]}')
        result[name] = execute(argv).splitlines()[0]
    version = tuple(int(x) for x in result['node'].lstrip('v').split('.')[:2])
    if version < (22, 19):
        raise RuntimeError(f'This baseline requires Node >=22.19, found {result["node"]}')
    release = release_contracts.observed(result['pi'])
    required_flags = release_contracts.contract(release)['required_flags']
    help_text = execute(['pi', '--help'])
    missing = [flag for flag in required_flags if flag not in help_text]
    if missing:
        raise RuntimeError(f'Pi CLI incompatible: missing {missing}. Pin a compatible version and rebuild.')
    result['required_flags'] = required_flags
    result['release_contract'] = release_contracts.identity(release)
    if profile == 'browser':
        result['chromium_path'] = chromium_path()
        result['chromium'] = execute([result['chromium_path'], '--version'])
    contract_path = Path('/opt/pi-control/environment.json')
    if contract_path.exists():
        result['project_environment'] = environment_probe(json.loads(contract_path.read_text()))
    emit(result)


def boundary():
    if os.getuid() == 0:
        raise RuntimeError('Agent container must not run as root')
    if Path('/var/run/docker.sock').exists() or Path('/run/podman/podman.sock').exists():
        raise RuntimeError('A container engine socket was exposed')
    marker = uuid.uuid4().hex
    inside = Path('/workspace') / ('.pi-boundary-' + marker)
    # On a read-only project, only the runtime subdirectory is writable.
    if os.environ.get('PI_LAB_READONLY_PROJECT') == '1':
        inside = Path(os.environ['TMPDIR']) / marker
    inside.write_text('ok')
    inside.unlink()
    outside_targets = [Path('/tmp'), Path('/'), Path('/etc'), Path('/usr'), Path('/var'), Path('/home'), Path('/opt/pi-lab')]
    for target in outside_targets:
        if not target.exists():
            continue
        outside = target / ('pi-boundary-' + marker)
        try:
            outside.write_text('unexpected')
        except OSError as exc:
            if exc.errno not in (errno.EROFS, errno.EACCES, errno.EPERM, errno.ENOENT):
                raise
        else:
            outside.unlink()
            raise RuntimeError(f'Unexpected writable path outside workspace: {outside}')
    ext_path = Path('/opt/pi-lab/workspace-boundary.mjs')
    if ext_path.exists():
        code = ext_path.read_text(encoding='utf-8')
        if 'isWithinWorkspace' not in code:
            raise RuntimeError('workspace-boundary.mjs missing isWithinWorkspace check')
    emit({'workspace_access':os.environ.get('PI_LAB_STAGE_ACCESS','unknown'),
          'writable_probe_location':str(inside.parent),'sampled_outside_write_denied':True,
          'boundary_extension_present':ext_path.is_file(),'uid':os.getuid()})


def preflight(config, chat=False, request_timeout=120):
    if type(request_timeout) is not int or not 1<=request_timeout<=1200:
        raise ValueError('Preflight request timeout must be a bounded integer')
    base = config['base_url'].rstrip('/')
    key = os.environ.get('PI_LAB_API_KEY', '')
    if not key:
        raise RuntimeError('PI_LAB_API_KEY is empty')
    client = build_opener(ProxyHandler({}))
    headers = {'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'}
    def request(route, payload=None, server_root=False):
        data = None if payload is None else json.dumps(payload).encode()
        req = Request((base[:-3] if server_root else base) + route, data=data, headers=headers,
                      method='GET' if data is None else 'POST')
        try:
            with client.open(req, timeout=request_timeout) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
                if len(raw) > 4 * 1024 * 1024:
                    raise RuntimeError('API response exceeded 4 MiB')
                return json.loads(raw)
        except HTTPError as exc:
            detail = exc.read(2000).decode(errors='replace').replace(key, '<REDACTED>')
            raise RuntimeError(f'HTTP {exc.code} from {route}: {detail}') from None
        except URLError as exc:
            raise RuntimeError(f'Cannot reach API from the Pi container: {exc.reason}') from None
    t0 = time.monotonic()
    listing = request('/models')
    found = next((m for m in listing.get('data', []) if isinstance(m,dict) and m.get('id') == config['model']), None)
    if found is None:
        raise RuntimeError(f'Exact model ID not present in /models: {config["model"]}. No fallback allowed.')
    try:props=request('/props',server_root=True)
    except (RuntimeError,ValueError):props=None
    context=interpret_context(config['model'],listing.get('data',[]),props)
    check_context(context,config['context_window'])
    report = {'base_url': base, 'model': config['model'], 'model_found': True,
              'context':context,'loaded': found.get('loaded'),'http_models_ok': True}
    if chat:
        nonce = uuid.uuid4().hex
        reply = request('/chat/completions', {'model': config['model'],
                        'messages': [{'role': 'user', 'content': 'Reply with this string only: ' + nonce}],
                        config.get('compat', {}).get('maxTokensField', 'max_tokens'): min(128, config['max_tokens']), 'stream': False, 'tools': []})
        if not reply.get('choices'):
            raise RuntimeError('Chat endpoint returned no choices')
        report.update(http_chat_ok=True, response_id=reply.get('id'), usage=reply.get('usage'),
                      nonce_echoed=nonce in str(reply['choices'][0].get('message', {}).get('content', '')))
    report['elapsed_seconds'] = round(time.monotonic() - t0, 3)
    emit(report)


def browser(webgl=False):
    args = [chromium_path(), '--headless', '--disable-dev-shm-usage',
            '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
            '--disable-breakpad', '--disable-crash-reporter',
            '--user-data-dir=' + tempfile.mkdtemp(prefix='chrome-', dir=os.environ['TMPDIR'])]
    if os.environ.get('CHROME_NO_SANDBOX') == '1':
        args += ['--no-sandbox']
    if os.environ.get('CHROME_SOFTWARE_WEBGL') == '1':
        args += ['--use-gl=angle', '--use-angle=swiftshader-webgl', '--enable-unsafe-swiftshader']
    args += ['--dump-dom', 'file:///opt/pi-lab/browser-fixture.html']
    html = execute(args, timeout=60)
    sandbox = {'namespace_and_seccomp_verified': False, 'origin': 'explicit sandbox opt-out'}
    if os.environ.get('CHROME_NO_SANDBOX') != '1':
        # A fresh Chromium invocation with the same policy/flags checks actual
        # namespace + seccomp state. Internal scheme navigation is diagnostic only.
        status_args = args[:-2] + ['--allow-chrome-scheme-url', '--dump-dom', 'chrome://sandbox']
        sandbox = browser_sandbox.observed(execute(status_args, timeout=20))
    dom_ok = 'id="probe">BROWSER_OK<' in html
    webgl_ok = 'id="webgl">WEBGL_OK<' in html
    emit({'browser_dom_ok': dom_ok, 'webgl_ok': webgl_ok,
          'no_browser_sandbox': os.environ.get('CHROME_NO_SANDBOX') == '1',
          'software_webgl': os.environ.get('CHROME_SOFTWARE_WEBGL') == '1', 'dom': html})
    emit({'browser_sandbox': sandbox})
    if not dom_ok or (webgl and not webgl_ok):
        raise RuntimeError('Browser execution or required WebGL context failed')
    if os.environ.get('CHROME_NO_SANDBOX') != '1' and not sandbox['namespace_and_seccomp_verified']:
        raise RuntimeError('Chromium namespace/seccomp sandbox state not verified')


def norm_arch_str(value: str) -> str:
    return {'aarch64': 'arm64', 'arm64': 'arm64', 'x86_64': 'amd64', 'amd64': 'amd64'}.get(value, value)


def capability_facts(task: dict,cwd: str) -> dict:
    access=os.environ.get('PI_LAB_STAGE_ACCESS',task.get('access','unknown'))
    network=os.environ.get('PI_LAB_NETWORK_MODE','unknown')
    runtime=os.environ.get('PI_LAB_RUNTIME_PATH')
    root_setting=os.environ.get('PI_LAB_ROOT_READONLY')
    writable=[]
    if access=='rw':writable.append('/workspace')
    if runtime:writable.append(runtime)
    if root_setting=='1':writable.append('/opt/pi-control/outbox')
    tools=[name for name in ('node','npm','python3','git','bash','rg') if shutil.which(name)]
    try:browser=chromium_path()
    except RuntimeError:browser=None
    return {'schema':1,'configured_platform':os.environ.get('CONTAINER_ARCH'),
            'observed_architecture':norm_arch_str(platform.machine()),'host_platform':os.environ.get('HOST_ARCH'),
            'cwd':cwd,'workspace':{'path':'/workspace','access':access},
            'configured_root_read_only':root_setting=='1' if root_setting is not None else None,
            'writable_locations':writable,'temporary_directory':os.environ.get('TMPDIR'),
            'network':{'mode':network,'external_routing':'disabled' if network=='none' else 'unverified',
                       'destination_allowlist':False},
            'pi_startup_network_disabled':os.environ.get('PI_OFFLINE','').lower() in ('1','true','yes'),
            'available_commands':tools,'chromium_path':browser,'pi_tools':list(task.get('tools',[])),
            'package_installation_policy':'disallowed_in_agent',
            'bash_guard':'additional pattern filter; not a shell parser or general confinement proof'}


def get_capabilities_manifest(task: dict,cwd: str) -> str:
    facts=capability_facts(task,cwd)
    return ('=== ENVIRONMENT CAPABILITIES MANIFEST ===\n'+json.dumps(facts,indent=2)+'\n'
            'The configured OS/mount boundary permits only the listed writable locations. '
            'The project access mode applies to the whole mount; cwd is not a subtree sandbox. '
            'PI_OFFLINE disables Pi startup network work, independently of Docker routing. '
            'Command discovery does not prove a functional application/browser test. '
            'Use existing toolchains and $TMPDIR; report missing requirements. '
            'Do not install packages, invoke Docker/other agents or change the selected endpoint.\n'
            '==========================================\n\n')


def control_dirs() -> tuple[Path, Path]:
    # Never discover controls through a child-writable project alias.
    base = Path('/opt/pi-control')
    return base / 'inbox', base / 'outbox'


_ACKED_DIRECTIVES = set()
_DIRECTIVES = {}


def directive_context():
    try:
        return json.loads(Path(os.environ.get('PI_LAB_STAGE_CONTEXT','/opt/pi-control/stage.json')).read_text())
    except (OSError,ValueError):
        return {}


def valid_directive(data, kind):
    context = directive_context()
    if not isinstance(data,dict): return False
    try:
        if str(uuid.UUID(data.get('id',''))) != data['id']: return False
    except (ValueError,TypeError,AttributeError): return False
    if kind == 'steer' and (not isinstance(data.get('message'),str) or not data['message'].strip()
                            or type(data.get('interrupt')) is not bool): return False
    return (data.get('schema') == 2 and data.get('kind') == kind
            and all(data.get(k) == context.get(k) and context.get(k)
                    for k in ('run_id','attempt_id','stage_id'))
            and data.get('segment_id') == context.get('segment_id')
            and data.get('expected_stage_revision') == context.get('stage_revision'))


def queued_directive(inbox, kind):
    pending=[]
    for path in (inbox / 'directives').glob('*.json'):
        try:
            data=json.loads(path.read_text())
            if valid_directive(data,kind) and data['id'] not in _ACKED_DIRECTIVES:
                pending.append(data)
        except (OSError,ValueError): pass
    if pending:
        data=min(pending,key=lambda d:(d.get('created_at',''),d['id']))
        _DIRECTIVES[data['id']]=data
        return data
    return None


def check_hotfix(inbox_dir, outbox_dir=None):
    return queued_directive(inbox_dir, 'patch')


def acknowledge_directive(outbox_dir, directive_id, status):
    data=_DIRECTIVES.get(directive_id)
    if not data: return
    ack={k:data.get(k) for k in ('schema','id','run_id','attempt_id','stage_id','segment_id')}
    ack.update(status=status, timestamp=time.time(), expected_stage_revision=data['expected_stage_revision'])
    try:
        folder=outbox_dir/'acks';folder.mkdir(exist_ok=True)
        (folder/(directive_id+'.json')).write_text(json.dumps(ack))
        (outbox_dir/(('hotfix' if data['kind']=='patch' else 'steer')+'_ack.json')).write_text(json.dumps(ack))
    finally:
        _ACKED_DIRECTIVES.add(directive_id)


def acknowledge_hotfix(outbox_dir, patch_id, target, status='observed'):
    # Observation only; the host patch protocol determines application.
    acknowledge_directive(outbox_dir,patch_id,status)


def write_heartbeat(outbox_dir: Path, data: dict):
    if not outbox_dir.exists():
        return
    try:
        tmp = outbox_dir / 'heartbeat.json.tmp'
        target = outbox_dir / 'heartbeat.json'
        tmp.write_text(json.dumps(data, indent=2))
        tmp.replace(target)
    except Exception:
        pass


def sync_dynamic_limits(inbox_dir: Path, task: dict) -> bool:
    try:
        data=json.loads((inbox_dir/'limits.json').read_text())
        if not valid_directive(data,'extend_budget'):return False
        revision=data.get('budget_revision')
        if type(revision) is not int or revision<0 or revision<=task.get('_budget_revision',-1):return False
        caps={'max_turns':100,'timeout_seconds':3600,'max_total_tokens':10000000}
        if any(type(data.get(k)) is not int or not 0<data[k]<=maximum for k,maximum in caps.items()):return False
        native={'max_tool_calls':500,'reporting_reserve_calls':20,'reporting_reserve_seconds':120}
        if set(native)&set(task):
            if not set(native)<=set(task) or any(type(data.get(k)) is not int or not 0<data[k]<=maximum for k,maximum in native.items()):return False
            if (data['max_tool_calls']<task['max_tool_calls']
                    or any(data[key]!=task[key] for key in ('reporting_reserve_calls','reporting_reserve_seconds'))):return False
        remaining=data.get('remaining_seconds')
        if type(remaining) not in (int,float) or not math.isfinite(remaining) or not 0<=remaining<=3600:return False
        for key in caps:task[key]=data[key]
        if set(native)<=set(task):
            for key in native:task[key]=data[key]
        task['_budget_revision']=revision
        # A relative duration, never a host clock timestamp. Repeated reads of
        # this revision cannot renew the timer. The host independently enforces it.
        task['_worker_deadline']=time.monotonic()+remaining
        ack={k:data.get(k) for k in ('schema','id','run_id','attempt_id','stage_id','segment_id')}
        ack.update(budget_revision=revision,status='observed',timestamp=time.time(),expected_stage_revision=data['expected_stage_revision'])
        outbox=control_dirs()[1]
        if outbox.exists():
            (outbox/'limits_ack.json').write_text(json.dumps(ack))
        return True
    except (OSError,ValueError,TypeError):return False


def check_steering(inbox_dir, outbox_dir=None):
    return queued_directive(inbox_dir,'steer')


def acknowledge_steering(outbox_dir, steer_id, status='active'):
    acknowledge_directive(outbox_dir,steer_id,status)


def agent_pi_arguments(config,task,home,thinking_args,profile_context=None):
    selected = release_contracts.contract(task.get('pi_release', '0.87.1'))
    boundary_ext = '/opt/pi-lab/workspace-boundary.mjs'
    base_args = ['pi', '--provider', 'local-lab', '--model', config['model'],
                 '--mode', 'json', '--print', '--offline',
                 '-e', boundary_ext,
                 '--no-extensions', '--no-skills',
                 '--no-prompt-templates', '--no-context-files', '--no-themes', '--no-approve',
                 '--session-dir', str(home.parent / 'sessions'), '--tools', ','.join(task['tools'])]
    base_args += selected['extra_cli_flags'] + thinking_args
    if profile_context:
        base_args += ['-e','/opt/pi-lab/profile-monitor.mjs']
        if profile_context['profile']['kind']=='application-client':base_args += ['-e','/opt/pi-profile/application-client.mjs']
        elif profile_context['profile']['kind']!='builtin':base_args += ['-e','/opt/pi-profile/fixture-lookup.mjs']
    if task.get('native_budget_context') and not (profile_context and profile_context['profile']['kind']=='application-client'):
        base_args += ['-e','/opt/pi-lab/tool-budget.mjs']
    return base_args


def agent(config, task):
    native_fields = {'max_tool_calls', 'reporting_reserve_calls', 'reporting_reserve_seconds'}
    application = 'application_execution' in task or 'application_context' in task
    if application:
        if not native_fields <= set(task) or not task.get('application_context') or not task.get('application_execution'):
            raise ValueError('Invalid compiled application execution')
        if 'native_budget_context' in task:raise ValueError('Invalid compiled application execution')
    elif native_fields & set(task):
        if not native_fields <= set(task) or not task.get('native_budget_context'):
            raise ValueError('Declared native tool budget has no admitted guard context')
        os.environ['PI_LAB_TOOL_BUDGET_CONTEXT'] = task['native_budget_context']
    elif task.get('native_budget_context'):
        raise ValueError('Native budget context requires explicit native limits')
    actual_release = release_contracts.observed(execute(['pi', '--version']))
    if actual_release != task.get('pi_release'):
        raise ValueError('Worker Pi version differs from the admitted image/task')
    release_contracts.validate_binding(task.get('release_contract'), actual_release)
    if application:
        try:profile_context=json.loads(_application_read(task['agent_profile_context'],65536))
        except (OSError,ValueError,KeyError,TypeError):raise ValueError('Invalid compiled application execution') from None
        validate_application_execution(task,profile_context,actual_release)
        os.environ['PI_LAB_APPLICATION_CONTEXT']=task['application_context']
        os.environ.pop('PI_LAB_TOOL_BUDGET_CONTEXT',None)
    else:
        os.environ.pop('PI_LAB_APPLICATION_CONTEXT',None)
        profile_context=json.loads(Path(task['agent_profile_context']).read_text()) if task.get('agent_profile_context') else None
        if profile_context and profile_context['profile'].get('kind')=='application-client':
            raise ValueError('Application profile requires compiled execution metadata')
    if profile_context:
        profile = profile_context['profile']
        if (not application and profile.get('kind') != 'builtin'
                and profile.get('components') != [release_contracts.contract(actual_release)['fixture_component']]):
            raise ValueError('Worker fixture profile differs from the admitted Pi release')
        os.environ['PI_LAB_PROFILE_CONTEXT']=task['agent_profile_context']
    cwd = select_cwd(task)
    home = Path(os.environ['PI_CODING_AGENT_DIR'])
    home.mkdir(parents=True, exist_ok=True)
    inbox_dir, outbox_dir = control_dirs()
    models,settings,thinking_args,configuration_receipt=model_configuration(config,task.get('pi_release'))
    (home/'models.json').write_text(json.dumps(models,indent=2))
    (home/'settings.json').write_text(json.dumps(settings,indent=2))
    (home.parent/'effective-configuration.json').write_text(json.dumps(configuration_receipt,indent=2))
    base_args=agent_pi_arguments(config,task,home,thinking_args,profile_context)
    if application:
        continuation=task.get('application_continuation')
        initial_prompt=continuation['message'] if task.get('resume_session') else task['prompt']
        (home.parent/'application-prompt.json').write_text(json.dumps({'schema':1,
            'frozen_effective_prompt_sha256':task['application_execution']['effective_prompt_sha256'],
            'sent_prompt_sha256':hashlib.sha256(initial_prompt.encode()).hexdigest(),
            'continuation':{key:continuation[key] for key in ('command_id','continues_segment_id','sha256')} if continuation else None},indent=2))
    else:initial_prompt = (
        get_capabilities_manifest(task, cwd) +
        f'Work only on the task below. The project root is /workspace; your starting directory is {cwd}. '
        'Work on the project within its configured access mode. Runtime temporary files use $TMPDIR. '
        'The Linux root filesystem is read-only. Write temporary files under $TMPDIR. Do not install operating-system packages; '
        'report a missing environment requirement. Do not invoke Docker, other agents, or another '
        'model endpoint. Do not weaken container or browser isolation. Use real available tools and '
        'run the required tests; do not mock the model, fabricate traces, or call an unrun test passed. '
        'If blocked, describe the exact command, exit status and missing prerequisite. '
        'Do not modify protected tests or acceptance criteria. Final answer: changes, executed tests, '
        'results, and unresolved limitations.\n\n' + task['prompt']
    )

    if profile_context and profile_context['profile']['kind']=='fixture-lookup':
        initial_prompt+='\n\nDeclared integration instructions:\n'+Path('/opt/pi-profile/instructions.md').read_text()
    (home.parent/'effective-prompt.txt').write_text(initial_prompt)
    turns = task.get('prior_turns',0)
    tokens = task.get('prior_reported_tokens',0)
    completed_messages=[];observed_tool_starts={};observed_tool_seconds=0.0
    start = time.monotonic()
    last_tool = ''
    recent_tools = []
    current_prompt = initial_prompt
    is_continue = False
    arch_norm = norm_arch_str(platform.machine())

    def emit_hb(status='running', pid=None, exit_code=None):
        now_t = time.monotonic()
        elapsed = round(now_t - start, 2)
        d = {
            'schema':2, 'stage_id':directive_context().get('stage_id'),
            'segment_id':directive_context().get('segment_id'),
            'phase': 'agent', 'turn': turns, 'max_turns': task['max_turns'],
            'tokens': tokens, 'tokens_used': tokens, 'max_total_tokens': task['max_total_tokens'],
            'usage':summarize(completed_messages),
            'usage_scope':'current_segment; budget tokens include prior segments',
            'usage_known':task.get('prior_usage_known',True) and summarize(completed_messages)['categories']['total']['missing_messages']==0,
            'timing':{'segment_end_to_end_seconds':elapsed,'inference_seconds':None,
                      'observed_tool_event_interval_seconds':round(observed_tool_seconds,3),
                      'tool_timing_origin':'worker event-arrival monotonic intervals; not server timing'},
            'elapsed_seconds': elapsed,
            'timeout_seconds': task['timeout_seconds'], 'last_tool': last_tool,
            'recent_tools': recent_tools[-5:], 'status': status,
            'container_arch': arch_norm, 'timestamp': time.time()
        }
        if pid is not None:
            d['pid'] = pid
        if exit_code is not None:
            d['exit_code'] = exit_code
        write_heartbeat(outbox_dir, d)

    sync_dynamic_limits(inbox_dir,task)
    args=list(base_args)
    if task.get('resume_session'):
        # Fresh runtime; copy the exact parent-frozen context, never latest-session lookup.
        resume=home.parent/'sessions'/'resume.jsonl';resume.parent.mkdir(exist_ok=True)
        resume.write_bytes(_application_read(task['resume_session'],32*1024*1024) if application else Path(task['resume_session']).read_bytes())
        args += ['--session',str(resume)]
    else:args += ['--session-id',task['session_id']]
    p=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
    cancelled=False
    interrupt_requested=False
    def stop_for_user(signum,frame):
        nonlocal cancelled
        cancelled=True
        if p.poll() is None:os.killpg(p.pid,signal.SIGKILL)
    def interrupt_for_parent(signum,frame):
        nonlocal interrupt_requested
        if not interrupt_requested and p.poll() is None:
            interrupt_requested=True;p.send_signal(signal.SIGINT)
    old_handlers={sig:signal.getsignal(sig) for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGUSR1)}
    signal.signal(signal.SIGINT,stop_for_user);signal.signal(signal.SIGTERM,stop_for_user)
    signal.signal(signal.SIGUSR1,interrupt_for_parent)
    try:
        p.stdin.write(initial_prompt.encode());p.stdin.close()
        sel = selectors.DefaultSelector()
        sel.register(p.stdout, selectors.EVENT_READ, sys.stdout.buffer)
        sel.register(p.stderr, selectors.EVENT_READ, sys.stderr.buffer)
        partial = b''
        limited = False
        interrupted_for_steer = False
        last_hb_time = 0.0

        emit_hb('running', pid=p.pid)

        while sel.get_map():
            now_mono = time.monotonic()
            sync_dynamic_limits(inbox_dir,task)
            if now_mono > task.get('_worker_deadline',start+task['timeout_seconds']):
                limited = True
            if limited and p.poll() is None:
                os.killpg(p.pid, signal.SIGKILL)

            # Check dynamic limits
            sync_dynamic_limits(inbox_dir, task)

            # Update heartbeat periodically (~1s)
            if now_mono - last_hb_time >= 1.0:
                last_hb_time = now_mono
                emit_hb('running', pid=p.pid)

            for selected, _ in sel.select(timeout=0.25):
                chunk = os.read(selected.fileobj.fileno(), 65536)
                if not chunk:
                    sel.unregister(selected.fileobj)
                    continue
                selected.data.write(chunk)
                selected.data.flush()
                if selected.fileobj is p.stdout:
                    partial += chunk
                    while b'\n' in partial:
                        line, partial = partial.split(b'\n', 1)
                        try:
                            record = json.loads(line)
                        except (ValueError, UnicodeDecodeError):
                            continue
                        if not isinstance(record, dict):
                            continue
                        rec_type = record.get('type')
                        if rec_type == 'turn_start':
                            turns += 1
                        elif rec_type == 'tool_execution_start':
                            observed_tool_starts[record.get('toolCallId')]=time.monotonic()
                            last_tool = record.get('toolName', '')
                            if last_tool:
                                recent_tools.append(last_tool)
                        elif rec_type == 'tool_execution_end':
                            began=observed_tool_starts.pop(record.get('toolCallId'),None)
                            if began is not None:observed_tool_seconds+=time.monotonic()-began
                        elif rec_type == 'message_end':
                            message = record.get('message', {})
                            if message.get('role') == 'assistant':
                                completed_messages.append(message)
                                tokens=task.get('prior_reported_tokens',0)+summarize(completed_messages)['categories']['total']['known_sum']
                        if turns > task['max_turns'] or tokens > task['max_total_tokens']:
                            limited = True
                    if len(partial) > 16 * 1024 * 1024:
                        limited = True

        code = p.wait()

        if limited:
            emit_hb('limited', pid=p.pid)
            print('PI_LAB_LIMIT: wall time, turn count, token count or event-size budget exceeded', file=sys.stderr)
            return 124

        emit_hb('cancelled' if cancelled else 'completed',exit_code=code)
        return 130 if cancelled else code
    finally:
        for sig,handler in old_handlers.items():signal.signal(sig,handler)
        sel.close() if 'sel' in locals() else None
        if p.poll() is None:
            os.killpg(p.pid,signal.SIGKILL);p.wait()
        p.stdout.close();p.stderr.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('operation', choices=['probe', 'boundary', 'preflight', 'browser', 'agent', 'check', 'gateway'])
    p.add_argument('--profile', choices=['core', 'browser'], default='core')
    p.add_argument('--chat', action='store_true')
    p.add_argument('--request-timeout',type=int,default=120)
    p.add_argument('--webgl', action='store_true')
    p.add_argument('--task', default='/opt/pi-control/task.json')
    p.add_argument('--config', default='/opt/pi-control/endpoint.json')
    a = p.parse_args()
    if a.operation == 'gateway':
        import inference_gateway
        return inference_gateway.main(a.config)
    if a.operation == 'probe':
        probe(a.profile)
    elif a.operation == 'boundary':
        boundary()
    elif a.operation == 'browser':
        browser(a.webgl)
    elif a.operation == 'preflight':
        preflight(json.loads(Path(a.config).read_text()), a.chat,a.request_timeout)
    elif a.operation == 'agent':
        return agent(json.loads(Path(a.config).read_text()), json.loads(Path(a.task).read_text()))
    else:
        task = json.loads(Path(a.task).read_text())
        select_cwd(task)
        for key in ('PI_LAB_API_KEY', 'UNSLOTH_API_KEY', 'OPENAI_API_KEY'):
            os.environ.pop(key, None)
        os.execvp(task['argv'][0], task['argv'])
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        print(f'PI_LAB_ERROR: {exc}', file=sys.stderr)
        sys.exit(2)
