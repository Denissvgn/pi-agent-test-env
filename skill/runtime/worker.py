#!/usr/bin/env python3
"""Container-side operations. No Docker CLI/socket; no automatic package installation.

Release contract: references/PI-COMPATIBILITY.md (source-inspected Pi 0.87.1).
Source inspection alone does not qualify execution. Budget/settings mapping,
ordered events and continued segments require observed runtime evidence.
"""
from __future__ import annotations
import argparse
import errno
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
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, ProxyHandler, build_opener
import uuid
from pi_contract import model_configuration
from context_contract import interpret_context, check_context
from usage_contract import summarize

REQUIRED_FLAGS = ['--mode', '--provider', '--model', '--tools', '--session-dir', '--session', '--session-id',
                  '--no-extensions', '--no-skills', '--no-context-files',
                  '--no-prompt-templates', '--no-themes', '--no-approve', '--offline']


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
    help_text = execute(['pi', '--help'])
    missing = [flag for flag in REQUIRED_FLAGS if flag not in help_text]
    if missing:
        raise RuntimeError(f'Pi CLI incompatible: missing {missing}. Pin a compatible version and rebuild.')
    result['required_flags'] = REQUIRED_FLAGS
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


def preflight(config, chat=False):
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
            with client.open(req, timeout=120) as response:
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
        remaining=data.get('remaining_seconds')
        if type(remaining) not in (int,float) or not math.isfinite(remaining) or not 0<=remaining<=3600:return False
        for key in caps:task[key]=data[key]
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
    boundary_ext = '/opt/pi-lab/workspace-boundary.mjs'
    base_args = ['pi', '--provider', 'local-lab', '--model', config['model'],
                 '--mode', 'json', '--print', '--offline',
                 '-e', boundary_ext,
                 '--no-extensions', '--no-skills',
                 '--no-prompt-templates', '--no-context-files', '--no-themes', '--no-approve',
                 '--session-dir', str(home.parent / 'sessions'), '--tools', ','.join(task['tools'])]
    base_args += thinking_args
    if profile_context:
        base_args += ['-e','/opt/pi-lab/profile-monitor.mjs']
        if profile_context['profile']['kind']!='builtin':base_args += ['-e','/opt/pi-profile/fixture-lookup.mjs']
    return base_args


def agent(config, task):
    cwd = select_cwd(task)
    home = Path(os.environ['PI_CODING_AGENT_DIR'])
    home.mkdir(parents=True, exist_ok=True)
    inbox_dir, outbox_dir = control_dirs()
    models,settings,thinking_args,configuration_receipt=model_configuration(config,task.get('pi_release'))
    (home/'models.json').write_text(json.dumps(models,indent=2))
    (home/'settings.json').write_text(json.dumps(settings,indent=2))
    (home.parent/'effective-configuration.json').write_text(json.dumps(configuration_receipt,indent=2))
    profile_context=json.loads(Path(task['agent_profile_context']).read_text()) if task.get('agent_profile_context') else None
    if profile_context:os.environ['PI_LAB_PROFILE_CONTEXT']=task['agent_profile_context']
    base_args=agent_pi_arguments(config,task,home,thinking_args,profile_context)
    manifest = get_capabilities_manifest(task, cwd)
    initial_prompt = (
        manifest +
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

    if profile_context and profile_context['profile']['kind']!='builtin':
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
        resume.write_bytes(Path(task['resume_session']).read_bytes())
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
    p.add_argument('operation', choices=['probe', 'boundary', 'preflight', 'browser', 'agent', 'check'])
    p.add_argument('--profile', choices=['core', 'browser'], default='core')
    p.add_argument('--chat', action='store_true')
    p.add_argument('--webgl', action='store_true')
    p.add_argument('--task', default='/opt/pi-control/task.json')
    p.add_argument('--config', default='/opt/pi-control/endpoint.json')
    a = p.parse_args()
    if a.operation == 'probe':
        probe(a.profile)
    elif a.operation == 'boundary':
        boundary()
    elif a.operation == 'browser':
        browser(a.webgl)
    elif a.operation == 'preflight':
        preflight(json.loads(Path(a.config).read_text()), a.chat)
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
