#!/usr/bin/env python3
"""Host-side orchestration for real Pi agents. Python >=3.10, local Docker daemon.

The parent has Docker access; children do not. Results live outside the child mount.
See SKILL.md and references/SECURITY.md before use.
"""
from __future__ import annotations
import argparse
import copy
import datetime as dt
import fnmatch
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any
from urllib.parse import urlsplit
import uuid

from evidence import analyze
from resources import configure, requested_policy, thread_environment, admission_lock, admission_diagnostic, AdmissionError
from builder import limited_build
import secret_store
import application_credentials
import browser_security
import pr_review_gate
import lab_env
import stage_control as controls
import workspace_patch
import outcomes
import scoring
import segments
import experiments
import agent_profiles
import provenance
from usage_contract import combine as combine_usage, summarize as summarize_usage
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime'))
import pi_contract
import release_contracts
from diagnostics import classify_docker_error, first_line, remedy

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / 'runtime'
DEFAULT_IMAGE = 'pi-agent-tests:core'
DEFAULT_VERSION = ''  # Builds require an explicitly selected, verified Pi version.
TOOLS = {'read', 'write', 'edit', 'bash', 'grep', 'find', 'ls'}
EXCLUDES = {'.git', '.pi', '.agents', '.pi-runtime', '.pi-lab', 'node_modules',
            '.venv', 'venv', '__pycache__', '.DS_Store', '.npmrc', '.netrc', '.ssh', '.aws', '.kube'}
SECRET_PATTERNS = ['.env', '.env.*', '*.pem', '*.key', 'id_rsa*', 'id_ed25519*']
ACTIVE: set[str] = set()
EXIT_NEEDS_SECRET = 3


class LabError(RuntimeError):
    """A blocker. `reason` is a stable machine-readable code; `remedy` is the next action."""
    def __init__(self, message: str, reason: str = '', remedy: str = ''):
        super().__init__(message)
        self.reason = reason
        self.remedy = remedy


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def save(path: Path, value: Any) -> None:
    """Atomic parent-side JSON write. Never call this on a child-writable path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise LabError(f'Refusing symlinked parent record: {path}')
    temp = path.with_name('.' + path.name + '-' + uuid.uuid4().hex)
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as output:
            output.write(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def command(argv: list[str], timeout: int = 30, required: bool = True):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LabError(f'{argv[0]}: {exc}') from exc
    if required and result.returncode:
        raise LabError(result.stderr.strip() or result.stdout.strip() or f'Command exited {result.returncode}: {argv[0]}')
    return result


def norm_arch(value: str) -> str:
    return {'aarch64': 'arm64', 'arm64': 'arm64', 'x86_64': 'amd64', 'amd64': 'amd64'}.get(value, value)


def docker_info() -> dict:
    """`docker info`, with permission/daemon/CLI failures turned into actionable blockers."""
    if not shutil.which('docker'):
        raise LabError('Docker CLI not found on this host.', 'docker-cli-missing', remedy('docker-cli-missing'))
    try:
        result = command(['docker', 'info', '--format', '{{json .}}'], timeout=30, required=False)
    except LabError as exc:
        reason = classify_docker_error(str(exc))
        raise LabError(f'Docker check failed: {first_line(str(exc))}', reason, remedy(reason)) from None
    if getattr(result, 'returncode', 0):
        text = (getattr(result, 'stderr', '') or '') + '\n' + (getattr(result, 'stdout', '') or '')
        reason = classify_docker_error(text)
        raise LabError(f'Docker daemon is not usable: {first_line(getattr(result, "stderr", "") or text)}', reason, remedy(reason))
    try:
        info = json.loads(result.stdout)
    except ValueError:
        raise LabError('docker info returned non-JSON output', 'docker-error', remedy('docker-error')) from None
    if info.get('ServerErrors'):
        text = ' '.join(map(str, info['ServerErrors']))
        reason = classify_docker_error(text)
        raise LabError(f'Docker daemon is not usable: {first_line(text)}', reason, remedy(reason))
    return info


def require_host(args) -> dict:
    info = docker_info()
    if info.get('OSType') != 'linux':
        raise LabError('A Linux container engine is required')
    context = command(['docker', 'context', 'show']).stdout.strip()
    ctx = json.loads(command(['docker', 'context', 'inspect', context]).stdout)[0]
    endpoint = os.environ.get('DOCKER_HOST') or ctx.get('Endpoints', {}).get('docker', {}).get('Host', '')
    if endpoint.startswith(('ssh://', 'tcp://', 'http://', 'https://')):
        raise LabError('Remote Docker daemon not supported by this runner: bind sources must exist on the daemon host.',
                       'docker-remote', remedy('docker-remote'))
    if args.uid <= 0 or args.gid < 0:
        raise LabError('Use a non-root host user (or explicitly choose a nonzero --uid and prepare ownership).')
    host_machine = norm_arch(platform.machine())
    daemon_arch = norm_arch(info.get('Architecture', ''))
    if getattr(args, 'browser_sandbox_policy', 'docker-default') == 'chromium-userns' and daemon_arch != 'arm64':
        raise LabError('chromium-userns requires observed ARM64 daemon architecture; host inference or emulation is insufficient', 'browser-policy-invalid')
    if args.platform is None:
        args.platform = 'linux/' + (daemon_arch or host_machine)
    if args.platform not in ('linux/arm64', 'linux/amd64'):
        raise LabError(f'This skill supports linux/arm64 and linux/amd64, found {args.platform}')
    args.native_platform = 'linux/' + (daemon_arch or host_machine)
    limits = configure(args, info)
    return {'docker_context': context, 'docker_version': info.get('ServerVersion'),
            'host_machine': host_machine, 'daemon_architecture': daemon_arch,
            'native_platform': args.native_platform, 'selected_platform': args.platform, 'resources': limits}


def checked_path(path: Path) -> Path:
    result = path.expanduser().resolve()
    if any(c in str(result) for c in ',\n\r'):
        raise LabError('Docker bind source paths containing commas or newlines are not supported')
    return result


def state_dir(workspace: Path, label: str, uid: int | None = None) -> Path:
    p = workspace
    p.mkdir(parents=True, exist_ok=True)
    for part in ('.pi-lab', label):
        p = p / part
        if p.is_symlink():
            raise LabError(f'Refusing symlinked runtime directory: {p}')
        p.mkdir(exist_ok=True)
    for name in ('agent', 'home', 'tmp', 'cache', 'config', 'run', 'sessions'):
        dest = p / name
        if dest.is_symlink():
            raise LabError(f'Refusing symlink: {dest}')
        dest.mkdir(exist_ok=True)
        if name == 'run':
            dest.chmod(0o700)
    if uid is not None:
        for path in [p, *p.iterdir()]:
            path.chmod(0o700 if uid == os.getuid() else 0o777)
    return p


def control_channels(control: Path, uid: int | None = None) -> tuple[Path, Path]:
    """Initialize fresh trusted sources before launch; errors fail closed."""
    inbox, outbox = control / 'inbox', control / 'outbox'
    for path in (inbox, outbox):
        if path.is_symlink():
            raise LabError(f'Refusing symlinked control channel: {path}')
        path.mkdir(parents=True, exist_ok=True)
    same_user = hasattr(os, 'getuid') and uid == os.getuid()
    outbox.chmod(0o700 if same_user else 0o777)
    return inbox, outbox


def docker_args(args, image: str, workspace: Path, control: Path, state: Path,
                name: str, network: str, access: str = 'rw', key: bool = False, helpers: Path | None = None) -> list[str]:
    runtime = '/pi-state'
    helpers = helpers or RUNTIME
    if workspace.resolve()==helpers.resolve() or workspace.resolve() in helpers.resolve().parents:
        raise LabError('Runtime helpers must have no writable project alias')
    result = ['docker', 'run', '--name', name, '--init', '--platform', args.platform,
              '--label=org.pi-agent-test-env.managed=1',
              '--label=org.pi-agentic-development.managed=1',
              '--read-only', '--user', f'{args.uid}:{args.gid}', '--cap-drop=ALL',
              '--security-opt=no-new-privileges=true', '--ipc=none', '--pids-limit', str(getattr(args, 'pids_limit', 256)),
              '--memory', args.memory, '--memory-swap', args.memory, '--cpus', str(args.cpus), '--network', network,
              '--workdir=/workspace', '--entrypoint=python3',
              '--mount', f'type=bind,src={workspace},dst=/workspace,bind-recursive=disabled' + (',readonly' if access == 'ro' else ''),
              '--mount', f'type=bind,src={helpers},dst=/opt/pi-lab,readonly,bind-recursive=disabled',
              '--mount', f'type=bind,src={control},dst=/opt/pi-control,readonly,bind-recursive=disabled']
    # Construction is pure: never initialize or chmod child-modifiable sources here.
    outbox = control / 'outbox'
    result += ['--mount', f'type=bind,src={outbox},dst=/opt/pi-control/outbox,bind-recursive=disabled',
               '--mount', f'type=bind,src={state},dst={runtime},bind-recursive=disabled']
    env = {'HOME': runtime + '/home', 'PI_CODING_AGENT_DIR': runtime + '/agent',
           'TMPDIR': runtime + '/tmp', 'TMP': runtime + '/tmp', 'TEMP': runtime + '/tmp',
           'XDG_CACHE_HOME': runtime + '/cache', 'XDG_CONFIG_HOME': runtime + '/config',
           'XDG_RUNTIME_DIR': runtime + '/run', 'npm_config_cache': runtime + '/cache/npm',
           'PIP_CACHE_DIR': runtime + '/cache/pip', 'PUPPETEER_CACHE_DIR': runtime + '/cache/puppeteer',
           'PUPPETEER_SKIP_DOWNLOAD': 'true', 'PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD': '1',
           'PUPPETEER_EXECUTABLE_PATH': getattr(args, 'chromium_path', '/usr/bin/chromium'),
           'CHROME_BIN': getattr(args, 'chromium_path', '/usr/bin/chromium'),
           'PI_LAB_READONLY_PROJECT': '1' if access == 'ro' else '0',
           'PI_LAB_STAGE_ACCESS':access,'PI_LAB_NETWORK_MODE':network,
           'PI_LAB_ROOT_READONLY':'1','PI_LAB_RUNTIME_PATH':runtime,
           'HOST_ARCH': getattr(args, 'native_platform', args.platform),
           'CONTAINER_ARCH': args.platform,
           'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONUNBUFFERED': '1', 'PI_OFFLINE': '1',
           'CHROME_NO_SANDBOX': '1' if args.allow_browser_no_sandbox else '0',
           'CHROME_SOFTWARE_WEBGL': '1' if args.software_webgl else '0',
           'NO_PROXY': '*', 'no_proxy': '*', 'USER': 'pi-lab', 'LOGNAME': 'pi-lab'}
    env.update(thread_environment(getattr(args, 'jobs', 1)))
    for k, v in env.items():
        result += ['--env', f'{k}={v}']
    if getattr(args, 'host_gateway', False):
        result += ['--add-host', 'host.docker.internal:host-gateway']
    if key:
        result += ['--env', 'PI_LAB_API_KEY']
    else:
        # A reused image must not contain credentials (also checked by image_info).
        result += ['--env', 'PI_LAB_API_KEY=']
    result += browser_security.docker_options(args, workspace)
    return result + [image, '/opt/pi-lab/worker.py']


def stream_run(argv: list[str], logdir: Path, timeout: int, name: str,
               secret: str = '', max_bytes: int = 64 * 1024 * 1024, stage=None, keep_budget=False, resume_budget=False,
               application_secrets=None, redaction_secrets=()) -> dict:
    """Drain both pipes continuously. Bound wall time/log size; remove the container on all exits."""
    logdir.mkdir(parents=True, exist_ok=True)
    save(logdir / 'command.json', {'argv': argv, 'api_key_inherited': bool(secret), 'started_at': now()})
    application_secrets = application_secrets or {}
    redactor = application_credentials.Redactor([secret, *application_secrets.values(), *redaction_secrets])
    env = {k: v for k, v in os.environ.items() if not k.startswith('PI_APP_')}
    env.update(application_secrets)
    if secret:
        env['PI_LAB_API_KEY'] = secret
    else:
        env.pop('PI_LAB_API_KEY', None)
    over = threading.Event()
    capture_errors: list[str] = []
    start = time.monotonic()
    ACTIVE.add(name)
    budget = None
    cleanup_deadline = None
    grace = max(0.1, min(30,timeout-stage[1]['original_limits']['timeout_seconds'])) if stage else 10
    p = None
    result = {'exit_code': 2, 'started':False, 'timed_out': False, 'log_limit_exceeded': False}
    def drain(pipe, path):
        total = 0
        pending = b''
        try:
            with path.open('wb') as out:
                while True:
                    data = pipe.read(65536)
                    if not data:
                        if pending:
                            out.write(redactor.bytes(pending))
                        break
                    total += len(data)
                    if total > max_bytes:
                        over.set()
                        continue
                    pending += data
                    while b'\n' in pending:
                        line, pending = pending.split(b'\n', 1)
                        out.write(redactor.bytes(line) + b'\n')
                        out.flush()
                    if len(pending) > 16 * 1024 * 1024:
                        over.set()
                        pending = b''
        except Exception as exc:
            capture_errors.append(redactor.value(str(exc)))
            over.set()
        finally:
            pipe.close()
    def cleanup_time():
        return max(.1,(cleanup_deadline or (time.monotonic()+grace))-time.monotonic())
    def docker_command(argv):
        try:
            return command(argv,timeout=min(5,cleanup_time()),required=False)
        except (LabError,OSError) as exc:
            return argparse.Namespace(returncode=1,stdout='',stderr=str(exc))
    try:
        if stage:
            budget=controls.read(controls.budget_path(stage[0],stage[1])) if resume_budget else controls.start_budget(stage[0],stage[1],start,grace)
            if resume_budget:controls.publish_budget(stage[0],stage[1],budget)
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, start_new_session=True)
        result['started']=True
        threads = [threading.Thread(target=drain, args=(p.stdout, logdir / 'stdout.jsonl'), daemon=True),
                   threading.Thread(target=drain, args=(p.stderr, logdir / 'stderr.log'), daemon=True)]
        for t in threads:
            t.start()
        while p.poll() is None:
            if stage:
                controls.capture_observations(stage[0],stage[1])
                budget=controls.process_budget_requests(stage[0],stage[1])
                state=controls.resolve(stage[0],stage[1]['stage_id'])[1]
                for directive in segments.pending(stage[0],stage[1],state.get('segment_id'),set(result.get('interrupts_applied',[]))):
                    if directive.get('interrupt'):
                        sent=docker_command(['docker','kill','--signal=SIGUSR1',name]) if argv[:2]==['docker','run'] else None
                        if sent is None:
                            try:p.send_signal(signal.SIGUSR1)
                            except ProcessLookupError:sent=argparse.Namespace(returncode=1)
                        if sent is None or sent.returncode==0:
                            result.setdefault('interrupts_applied',[]).append(directive['id'])
                            controls.audit(stage[0],directive,'applied',action='interrupt_signal',host_applied=True)
            expired = time.monotonic() >= budget['deadline_host_monotonic'] if budget else time.monotonic()-start > timeout
            if expired or over.is_set():
                result['timed_out'] = not over.is_set()
                result['log_limit_exceeded'] = over.is_set()
                cleanup_deadline=time.monotonic()+grace
                if argv[:2] == ['docker','run']:
                    docker_command(['docker','rm','-f',name])
                else:
                    os.killpg(p.pid,signal.SIGTERM)
                try:
                    p.wait(timeout=cleanup_time())
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid,signal.SIGKILL)
                break
            time.sleep(0.1)
        code = p.wait()
        if cleanup_deadline is None:cleanup_deadline=time.monotonic()+grace
        result['exit_code'] = 124 if result['timed_out'] else (2 if over.is_set() else code)
        for t in threads:
            t.join(timeout=cleanup_time())
        if over.is_set() and not capture_errors:
            result['log_limit_exceeded']=True;result['exit_code']=2
        if any(t.is_alive() for t in threads) or capture_errors:
            result['exit_code'] = 2
            result['capture_errors'] = capture_errors or ['Log reader did not finish']
    except KeyboardInterrupt:
        result['exit_code'] = 130
        result['cancelled']=True
        raise
    finally:
        if cleanup_deadline is None:cleanup_deadline=time.monotonic()+grace
        if stage and budget is not None:
            try:
                final_budget=controls.process_budget_requests(stage[0],stage[1],closing=not keep_budget)
                result['original_limits']=final_budget['original_limits']
                result['effective_limits']=final_budget['effective_limits']
                result['budget_revision']=final_budget['revision']
                result['cleanup_grace_seconds']=final_budget['cleanup_grace_seconds']
            except (OSError,ValueError,controls.ControlError) as exc:
                result['budget_error']=str(exc);result['exit_code']=2
        if argv[:2] == ['docker', 'run']:
            inspect = docker_command(['docker', 'inspect', name])
            if inspect.returncode == 0:
                try:
                    data = json.loads(inspect.stdout)[0]
                    result['container_state'] = {k: data.get('State', {}).get(k) for k in ('ExitCode', 'OOMKilled', 'Error')}
                    result['applied_limits'] = {k: data.get('HostConfig', {}).get(k) for k in ('NanoCpus', 'CpuPeriod', 'CpuQuota', 'Memory', 'MemorySwap', 'PidsLimit')}
                    if result['container_state'].get('OOMKilled'):
                        result['exit_code'] = result.get('exit_code') or 137
                except (ValueError, KeyError, IndexError) as exc:
                    result['inspection_warning'] = str(exc)
            else:
                result['inspection_warning'] = inspect.stderr.strip()
        cleanup = docker_command(['docker', 'rm', '-f', name]) if argv[:2]==['docker','run'] else argparse.Namespace(returncode=0,stderr='')
        # Timeout cleanup may already have removed it. A Docker connection failure is not "not found".
        if cleanup.returncode and 'No such container' not in cleanup.stderr:
            result['cleanup_warning'] = cleanup.stderr.strip()
        result['cleanup_confirmed'] = cleanup.returncode == 0 or 'No such container' in cleanup.stderr
        if p is not None:
            if argv[:2] != ['docker','run']:
                try:os.killpg(p.pid,signal.SIGKILL)
                except ProcessLookupError:pass
            elif p.poll() is None:p.kill()
            p.wait()
        ACTIVE.discard(name)
        trigger='timeout' if result['timed_out'] else ('log_limit' if result['log_limit_exceeded'] else ('completed' if result['exit_code']==0 else 'process_error'))
        if result.get('container_state',{}).get('OOMKilled'):trigger='oom'
        if result.get('interrupts_applied') and trigger=='process_error':trigger='interrupted'
        if result.get('cancelled'):trigger='cancelled'
        result['termination_reason']=trigger
        if not result.get('cleanup_confirmed'):
            result['termination_trigger']=trigger;result['termination_reason']='cleanup_error';result['exit_code']=2
        result['elapsed_seconds'] = round(time.monotonic() - start, 3)
        sanitized = redactor.value(result)
        result.clear(); result.update(sanitized)
        save(logdir / 'process.json', result)
    return result


def image_info(image: str, selected_platform: str) -> dict:
    data = json.loads(command(['docker', 'image', 'inspect', image]).stdout)[0]
    actual = data.get('Os', '') + '/' + norm_arch(data.get('Architecture', ''))
    if actual != selected_platform:
        raise LabError(f'{image}: {actual}, required {selected_platform}. Do not mix Linux ARM64 with linux64/x86 Chrome.')
    if data.get('Config', {}).get('Volumes'):
        raise LabError('Image declares VOLUME entries; implicit writable mounts violate this runtime contract')
    for value in data.get('Config', {}).get('Env') or []:
        name, _, content = value.partition('=')
        if name.startswith('PI_APP_'):
            raise LabError('Image declares the reserved application-credential namespace; use a clean image')
        if content and re.search(r'(API_KEY|ACCESS_TOKEN|AUTH_TOKEN|PASSWORD|SECRET)$', name):
            raise LabError(f'Image contains potential baked credential variable {name}; use a clean image')
    return {'id': data['Id'], 'reference': image, 'platform': actual,
            'repo_digests': data.get('RepoDigests', []), 'created': data.get('Created')}


def probe_image(args, image: str) -> dict:
    info = image_info(image, args.platform)
    scratch = checked_path(Path.home() / '.cache' / 'pi-agent-test-env')
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='probe-', dir=scratch) as td:
        top = Path(td)
        workspace = top / 'workspace'
        control = top / 'control'
        workspace.mkdir()
        control.mkdir()
        environment = load_environment(Path(args.environment)) if getattr(args, 'environment', None) else validate_environment({})
        save(control / 'environment.json', environment)
        (control / 'environment.json').chmod(0o644)
        control_channels(control, args.uid)
        state = state_dir(top, 'probe', args.uid)
        name = 'pi-lab-probe-' + uuid.uuid4().hex[:10]
        argv = docker_args(args, info['id'], workspace, control, state, name, 'none')
        receipt_path=None
        if getattr(args,'_attempt_root',None):
            receipts=Path(args._attempt_root)/'image-probes';receipts.mkdir(exist_ok=True)
            receipt_path=receipts/(name+'.json')
            probe_receipt={'schema':1,'kind':'image_probe',**args._attempt_identity,'container':name,
                           'image':info['id'],'control':str(control),'process':None}
            controls.atomic(receipt_path,probe_receipt)
        try:
            result = stream_run(argv + ['probe', '--profile', args.profile], top / 'logs', 90 + sum(p['timeout_seconds'] for p in environment['probes']), name)
        finally:
            if receipt_path and (top/'logs/process.json').exists():
                probe_receipt['process']=controls.read(top/'logs/process.json')
                controls.atomic(receipt_path,probe_receipt)
        if result['exit_code']:
            detail = (top / 'logs/stderr.log').read_text(errors='replace')[-6000:]
            raise LabError(f'Image capability probe failed: {detail}')
        try:
            info['capabilities'] = json.loads((top / 'logs/stdout.jsonl').read_text())
        except ValueError as exc:
            raise LabError('Image probe did not produce valid JSON') from exc
        args.chromium_path = info['capabilities'].get('chromium_path', '/usr/bin/chromium')
    return info


def admit_image(image, expected=None):
    try:
        selected = release_contracts.image_identity(image, expected)
        reported = image.get('capabilities', {}).get('release_contract')
        if reported is not None:
            release_contracts.validate_binding(reported, selected['release'])
    except ValueError as exc:
        raise LabError(str(exc), 'unsupported-pi-release',
                       'Select and qualify an exact reviewed Pi 0.87.1 or 1.2.0 image; no fallback.') from exc
    return selected


def ensure_image(args) -> dict:
    if args.pi_version:
        try: release_contracts.contract(args.pi_version)
        except ValueError as exc: raise LabError(str(exc), 'unsupported-pi-release') from exc
    host = require_host(args)
    attempted = []
    candidates = list(dict.fromkeys([args.image] + args.reuse))
    if args.policy != 'build':
        for candidate in candidates:
            try:
                receipt = probe_image(args, candidate)
                receipt['release_contract'] = admit_image(receipt, args.pi_version or None)
                if candidate != args.image:
                    command(['docker', 'image', 'tag', receipt['id'], args.image])
                receipt.update(action='reused', alias=args.image, host=host)
                if args.receipt:
                    save(checked_path(Path(args.receipt)), receipt)
                return receipt
            except LabError as exc:
                attempted.append({'candidate': candidate, 'reason': str(exc)})
    if args.policy == 'reuse':
        raise LabError('No acceptable existing image: ' + json.dumps(attempted))
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?', args.pi_version):
        raise LabError('A build needs --pi-version with an explicitly verified version (no default/latest/range). Reuse does not require a build pin.')
    for package in args.apt_package:
        if not re.fullmatch(r'[a-z0-9][a-z0-9+.-]*(?:=[A-Za-z0-9.+:~_-]+)?', package):
            raise LabError(f'Invalid apt package spec: {package}')
    dockerfile = checked_path(Path(args.dockerfile)) if args.dockerfile else ROOT / 'docker/Dockerfile'
    context = checked_path(Path(args.build_context)) if args.build_context else (dockerfile.parent if args.dockerfile else ROOT / 'docker')
    if not dockerfile.is_file() or not context.is_dir() or context in (Path('/'), Path.home()):
        raise LabError('Use an existing reviewed Dockerfile and a dedicated environment-only build context, not / or home')
    build_receipt = limited_build(args, dockerfile, context, command)
    receipt = probe_image(args, args.image)
    receipt['release_contract'] = admit_image(receipt, args.pi_version)
    receipt.update(action='built', host=host, prior_candidates=attempted,
                   requested_pi_version=args.pi_version,
                   base_image=args.base_image, build=build_receipt)
    if args.receipt:
        save(checked_path(Path(args.receipt)), receipt)
    return receipt


def expand_parameter(value: str) -> str:
    if not isinstance(value, str):
        raise LabError('Expected a string parameter')
    def replace(match):
        name = match.group(1)
        found = os.environ.get(name, '')
        if not found:
            raise LabError(f'Export {name} or replace the template value before running')
        return found
    return re.sub(r'\$\{([A-Z_][A-Z0-9_]*)\}', replace, value)


def load_endpoint(path: Path) -> dict:
    c = json.loads(path.expanduser().read_text())
    required = {'base_url', 'model', 'context_window', 'max_tokens', 'api_key_env'}
    allowed = required | {'input', 'compat', 'reasoning','host_base_url','sampling','server_provenance'}
    if not isinstance(c, dict) or not required.issubset(c) or set(c) - allowed:
        raise LabError('Endpoint needs base_url, model, context_window, max_tokens, api_key_env; optional input, compat, reasoning, host_base_url. No literal keys or unknown fields.')
    for route in ('base_url','host_base_url'):
        value=c.get(route,c['base_url'])
        if not isinstance(value,str):raise LabError(f'{route} must be a URL string')
        c[route]=expand_parameter(value).rstrip('/')
        u=urlsplit(c[route])
        if u.scheme not in ('http','https') or not u.hostname or u.username or u.password or u.query or u.fragment:
            raise LabError(f'Invalid {route}: use trusted http(s), without URL credentials/query/fragment')
        try:u.port
        except ValueError:raise LabError(f'Invalid {route} port') from None
        if not u.path.rstrip('/').endswith('/v1'):raise LabError(f'{route} requires a Chat Completions URL ending in /v1')
    c['model'] = expand_parameter(c['model'])
    if not isinstance(c['api_key_env'], str) or not re.fullmatch(r'[A-Z_][A-Z0-9_]*', c['api_key_env']):
        raise LabError('api_key_env must name an environment variable, not contain a secret')
    if not c['model'].strip() or c['model'].startswith('REPLACE_'):
        raise LabError('Exact model ID is required; replace the example placeholder')
    if not all(type(c[k]) is int for k in ('context_window', 'max_tokens')) or not (0 < c['max_tokens'] < c['context_window']):
        raise LabError('Require 0 < max_tokens < context_window, both integers')
    if c.get('input', ['text']) not in (['text'], ['text', 'image']):
        raise LabError('input must be [text] or [text, image]')
    if 'reasoning' in c:
        r = c['reasoning']
        if isinstance(r, bool):
            pass
        elif isinstance(r, dict):
            allowed_r = {'enabled', 'level', 'budget_tokens'}
            if set(r) - allowed_r:
                raise LabError("reasoning dict only accepts 'enabled', 'level', 'budget_tokens'")
            if 'enabled' in r and type(r['enabled']) is not bool:
                raise LabError('reasoning.enabled must be a boolean')
            if 'level' in r and r['level'] not in ('off', 'minimal', 'low', 'medium', 'high'):
                raise LabError("reasoning.level must be one of 'off', 'minimal', 'low', 'medium', 'high'")
            if 'budget_tokens' in r:
                if type(r['budget_tokens']) is not int or r['budget_tokens'] <= 0 or r['budget_tokens'] >= c['context_window']:
                    raise LabError('reasoning.budget_tokens must be an integer between 1 and context_window')
        else:
            raise LabError("reasoning must be a boolean or a dict with 'enabled', 'level', 'budget_tokens'")
    try:pi_contract.sampling_settings(c)
    except ValueError as exc:raise LabError(str(exc)) from exc
    declared=c.get('server_provenance',{})
    if not isinstance(declared,dict) or set(declared)-{'engine','version','weights','quantization','configuration_digest'} or any(not isinstance(x,str) or not x.strip() or len(x)>512 for x in declared.values()):
        raise LabError('server_provenance accepts bounded user-declared engine/version/weights/quantization/configuration_digest strings only')
    compat = c.get('compat', {})
    bool_fields = {'supportsStore', 'supportsDeveloperRole', 'supportsReasoningEffort', 'supportsUsageInStreaming'}
    if not isinstance(compat, dict) or set(compat) - (bool_fields | {'maxTokensField'}):
        raise LabError('Unknown endpoint compat field; extend the adapter with tests instead of passing arbitrary request fields')
    if any(type(compat[k]) is not bool for k in bool_fields & compat.keys()):
        raise LabError('compat capability fields must be booleans')
    if compat.get('maxTokensField', 'max_tokens') not in ('max_tokens', 'max_completion_tokens'):
        raise LabError('Unsupported maxTokensField')
    return c


def validate_environment(value: dict) -> dict:
    """A trusted, offline, key-free image capability contract. Not project setup."""
    if not isinstance(value, dict) or set(value) - {'schema', 'required_commands', 'probes'} or value.get('schema', 1) != 1:
        raise LabError('Environment schema 1 accepts required_commands and probes only')
    names = value.get('required_commands', [])
    if not isinstance(names, list) or len(names) > 40 or not all(isinstance(x, str) and re.fullmatch(r'[A-Za-z0-9_.+-]+', x) for x in names):
        raise LabError('required_commands must be a list of executable names, not paths/shell expressions')
    probes = value.get('probes', [])
    if not isinstance(probes, list) or len(probes) > 12:
        raise LabError('At most 12 environment probes are allowed')
    output = {'schema': 1, 'required_commands': list(dict.fromkeys(names)), 'probes': []}
    seen = set()
    for probe in probes:
        if not isinstance(probe, dict) or set(probe) - {'name', 'argv', 'stdout_regex', 'timeout_seconds'}:
            raise LabError('Unknown environment probe field')
        t = dict(probe)
        name = t.get('name', '')
        if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,50}', name) or name in seen:
            raise LabError('Environment probes need unique lowercase names')
        seen.add(name)
        argv = t.get('argv')
        if not isinstance(argv, list) or not argv or not all(isinstance(x, str) and x and '\x00' not in x for x in argv):
            raise LabError('Environment probe argv must be a nonempty string array')
        t.setdefault('timeout_seconds', 30)
        if type(t['timeout_seconds']) is not int or not 0 < t['timeout_seconds'] <= 120:
            raise LabError('Environment probe timeout must be 1..120 seconds')
        if 'stdout_regex' in t:
            if not isinstance(t['stdout_regex'], str) or len(t['stdout_regex']) > 1000:
                raise LabError('stdout_regex must be a short regular expression')
            try:
                re.compile(t['stdout_regex'])
            except re.error as exc:
                raise LabError(f'Invalid stdout_regex: {exc}') from exc
        output['probes'].append(t)
    return output


def load_environment(path: Path) -> dict:
    return validate_environment(json.loads(path.expanduser().read_text()))


def working_directory(value: str) -> str:
    if value == '.':
        return '.'
    return safe_relative(value)


def check_project_contract(workspace: Path, plan: dict) -> None:
    for name in list(dict.fromkeys(plan.get('required_paths', []) + plan['protected_paths'])):
        path = workspace / name
        if not path.exists():
            raise LabError(f'Required/protected project path is missing: {name}; adapt the plan before execution')
        if not path.resolve().is_relative_to(workspace.resolve()):
            raise LabError(f'Project path escapes the workspace: {name}')
    # Stage cwd must exist before setup; creating an output directory is part of a command.
    for stage in plan['agents'] + plan['setup'] + plan['checks']:
        path = (workspace / stage.get('cwd', '.')).resolve()
        if not path.is_relative_to(workspace.resolve()) or not path.is_dir():
            raise LabError(f'Missing or escaping stage cwd: {stage.get("cwd", ".")}')


def safe_relative(value: str) -> str:
    if not isinstance(value, str):
        raise LabError('Expected a project-relative string path')
    p = Path(value)
    if not value or not p.parts or p.is_absolute() or '..' in p.parts or '\x00' in value or '\\' in value or p.parts[0] == '.pi-lab':
        raise LabError(f'Expected a project-relative path outside .pi-lab: {value!r}')
    return p.as_posix()


def validate_plan(value: dict, base: Path, agent_profile=None) -> dict:
    agent_profile=agent_profile or agent_profiles.builtin()
    if not isinstance(value, dict):
        raise LabError('Plan must be a JSON object')
    if value.get('schema') != 1:
        raise LabError('Plan schema must be 1')
    if set(value) - {'schema', 'name', 'agents', 'setup', 'checks', 'protected_paths', 'required_paths'}:
        raise LabError('Unknown plan field')
    for field in ('agents', 'checks', 'setup', 'protected_paths', 'required_paths'):
        if not isinstance(value.get(field, []), list):
            raise LabError(f'Plan {field} must be an array')
    if not value.get('agents') or not value.get('checks'):
        raise LabError('A plan needs real agent stages AND independent checks; prose alone cannot pass')
    if len(value['agents']) > 8 or len(value['checks']) > 20 or len(value.get('setup', [])) > 20:
        raise LabError('Plan exceeds bounded agent/check count')
    result = {'schema': 1, 'name': value.get('name', 'agent-tests'), 'agents': [],
              'setup': [], 'checks': [], 'protected_paths': [], 'required_paths': []}
    for name in value.get('required_paths', []):
        result['required_paths'].append(safe_relative(name))
    for protected in value.get('protected_paths', []):
        result['protected_paths'].append(safe_relative(protected))
    names = set()
    for i, task in enumerate(value['agents']):
        if not isinstance(task, dict):
            raise LabError('Each agent stage must be an object')
        if set(task) - {'name', 'prompt', 'prompt_file', 'tools', 'require_tools', 'access',
                        'timeout_seconds', 'max_turns', 'max_total_tokens', 'cwd', 'application_secrets'}:
            raise LabError(f'Unknown field in agent {i}')
        t = dict(task)
        if 'application_secrets' in t:
            try:
                t['application_secrets'] = application_credentials.validate(t['application_secrets'])
            except application_credentials.CredentialError as exc:
                raise LabError(str(exc), exc.reason) from None
        if ('prompt' in t) == ('prompt_file' in t):
            raise LabError('Each agent needs exactly one of prompt or prompt_file')
        if 'prompt_file' in t:
            source = (base / t.pop('prompt_file')).resolve()
            t['prompt'] = source.read_text()
        if not isinstance(t['prompt'], str) or not t['prompt'].strip() or len(t['prompt'].encode()) > 128 * 1024:
            raise LabError('Agent prompt must be nonempty and at most 128 KiB')
        t.setdefault('name', f'agent-{i+1}')
        if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,50}', t['name']) or t['name'] in names:
            raise LabError('Agent names must be unique lowercase slugs')
        names.add(t['name'])
        t['cwd'] = working_directory(t.get('cwd', '.'))
        t.setdefault('tools', ['read', 'bash', 'edit', 'write', 'grep', 'find', 'ls'])
        t.setdefault('require_tools', ['read'])
        if not isinstance(t['tools'], list) or not isinstance(t['require_tools'], list) or not all(isinstance(tool, str) for tool in t['tools'] + t['require_tools']):
            raise LabError('Tool allowlists must be string arrays')
        if not t['tools'] or set(t['tools']) - (TOOLS|set(agent_profile['tools'])) or set(t['require_tools']) - set(t['tools']):
            raise LabError('Invalid tools/require_tools')
        t.setdefault('access', 'rw')
        if t['access'] not in ('ro', 'rw'):
            raise LabError('access must be ro or rw')
        for name, default, maximum in [('timeout_seconds', 900, 3600), ('max_turns', 24, 100),
                                      ('max_total_tokens', 500000, 10000000)]:
            t.setdefault(name, default)
            if type(t[name]) is not int or not 0 < t[name] <= maximum:
                raise LabError(f'Invalid {name}')
        result['agents'].append(t)
    for section in ('setup', 'checks'):
        for i, task in enumerate(value.get(section, [])):
            if not isinstance(task, dict):
                raise LabError('Each setup/check stage must be an object')
            if set(task) - {'name', 'argv', 'timeout_seconds', 'network', 'cwd', 'scorer'}:
                raise LabError(f'Unknown {section} field')
            t = dict(task)
            argv = t.get('argv')
            if not isinstance(argv, list) or not argv or not all(isinstance(x, str) and x and '\x00' not in x for x in argv):
                raise LabError('Check argv must be a nonempty string array; not a shell string')
            t.setdefault('name', f'{section}-{i+1}')
            if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,50}', t['name']):
                raise LabError('Check names must be lowercase slugs')
            t['cwd'] = working_directory(t.get('cwd', '.'))
            t.setdefault('timeout_seconds', 300)
            t.setdefault('network', 'none')
            if t['network'] not in ('none', 'inherit') or type(t['timeout_seconds']) is not int or not 0 < t['timeout_seconds'] <= 3600:
                raise LabError('Invalid check timeout/network')
            if 'scorer' in t:
                if section!='checks':raise LabError('Scorers are independent checks only')
                t['scorer']=scoring.validate(t['scorer'],base)
            result[section].append(t)
    return result


def is_excluded(name: str, additional: list[str]) -> bool:
    return name in EXCLUDES or any(fnmatch.fnmatch(name, p) for p in SECRET_PATTERNS + additional)


def check_in_place_tree(project: Path) -> None:
    """Inspect every mounted entry, independently of snapshot/hash exclusions.

    Directory descriptors and no-follow metadata/open calls avoid traversing
    links. This admission check still assumes cooperating host writers honor
    the existing lease; it cannot prevent later hostile host mutations.
    """
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

    def inspection_error(path, exc):
        return LabError(f'--in-place cannot inspect {path}: {exc.strerror or str(exc)}',
                        'in-place-inspection-error',
                        'Restore inspection access or use an isolated snapshot; no writable project stage started.')

    def inspect(parent_fd, name, relative):
        path = project / relative
        try:
            info = os.lstat(name, dir_fd=parent_fd)
        except OSError as exc:
            raise inspection_error(path, exc) from exc
        if stat.S_ISLNK(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink > 1):
            raise LabError(f'--in-place refuses symlinks/hardlinks; use a snapshot: {path}',
                           'in-place-linked-entry')
        if relative == Path('.') and not stat.S_ISDIR(info.st_mode):
            raise LabError(f'--in-place needs a project directory: {path}', 'invalid-project')
        if not stat.S_ISDIR(info.st_mode):
            return
        # Normal directory link counts are not shared regular-file hazards.
        try:
            fd = os.open(name, directory_flags, dir_fd=parent_fd)
            try:
                with os.scandir(fd) as entries:
                    for entry in entries:
                        inspect(fd, entry.name, relative / entry.name)
            finally:
                os.close(fd)
        except OSError as exc:
            raise inspection_error(path, exc) from exc

    inspect(None, project, Path('.'))


def snapshot(src: Path, dst: Path, additional: list[str], limit_mb: int, score_copy=False) -> dict:
    total = 0
    skipped = []
    dst.mkdir()
    def walk(folder: Path, target: Path):
        nonlocal total
        for child in sorted(folder.iterdir()):
            rel = child.relative_to(src).as_posix()
            excluded=is_excluded(child.name,additional)
            if score_copy and child.name in {'node_modules','.venv','venv','__pycache__'}:excluded=False
            if excluded:
                skipped.append(rel)
                continue
            if child.is_symlink():
                if score_copy:
                    (target/child.name).symlink_to(os.readlink(child));continue
                # Copy no symlinks by default: absolute host links, traversal and platform caches are not portable.
                skipped.append(rel + ' [symlink]')
                continue
            mode = child.stat().st_mode
            if stat.S_ISDIR(mode):
                (target / child.name).mkdir()
                walk(child, target / child.name)
            elif stat.S_ISREG(mode):
                total += child.stat().st_size
                if total > limit_mb * 1024 * 1024:
                    raise LabError(f'Project copy exceeds {limit_mb} MiB; add --exclude or stage a smaller checkout')
                shutil.copy2(child, target / child.name)  # New inode, not a hard link.
            else:
                skipped.append(rel + ' [special file]')
    walk(src, dst)
    return {'copied_bytes': total, 'skipped': skipped}


def tree_hashes(root: Path, include_ignored: bool = False) -> dict[str, str]:
    result = {}
    if not root.exists():
        return result
    def entry(p, rel):
        if p.is_symlink():
            result[rel] = 'symlink:' + os.readlink(p)
        elif p.is_file():
            with p.open('rb') as f:
                h = hashlib.file_digest(f, 'sha256') if hasattr(hashlib, 'file_digest') else None
                if h is None:
                    h = hashlib.sha256()
                    for b in iter(lambda: f.read(1024 * 1024), b''):
                        h.update(b)
            result[rel] = f'{stat.S_IMODE(p.stat().st_mode):04o}:' + h.hexdigest()
    if root.is_file() or root.is_symlink():
        entry(root, '.')
        return result
    for base, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if include_ignored or d not in EXCLUDES)
        for name in list(dirs) + sorted(files):
            p = Path(base) / name
            if include_ignored or name not in EXCLUDES:
                entry(p, p.relative_to(root).as_posix())
    return result


def protected_hashes(workspace: Path, paths: list[str]) -> dict:
    result={}
    for name in paths:
        current=workspace
        for part in Path(name).parts:
            current=current/part
            if current.is_symlink():
                # Under the stopped-writer lease, do not hash through an ancestor
                # link into host files. Record the mutation itself instead.
                result[name]={'linked_component':current.relative_to(workspace).as_posix(),
                              'link_target_digest':hashlib.sha256(os.readlink(current).encode()).hexdigest()}
                break
        else:result[name]=tree_hashes(workspace/name,include_ignored=True)
    return result


def trusted_runtime(runroot):
    """Freeze helpers before any child starts, including self-evaluation in place."""
    target=runroot/'trusted-runtime'
    with controls.lock(runroot):
        if target.exists():
            if tree_hashes(target,include_ignored=True)!=controls.read(runroot/'runtime-snapshot.json'):
                raise LabError('Runtime snapshot changed')
            return target
        for path in RUNTIME.rglob('*'):
            if path.is_symlink() or (path.is_file() and path.stat().st_nlink!=1):
                raise LabError('Runtime helper sources must be non-linked reviewed files')
        temp=runroot/('.trusted-runtime-'+uuid.uuid4().hex)
        try:
            shutil.copytree(RUNTIME,temp,ignore=shutil.ignore_patterns('__pycache__'))
            save(runroot/'runtime-snapshot.json',tree_hashes(temp,include_ignored=True))
            temp.rename(target)
        finally:
            if temp.exists():shutil.rmtree(temp)
    return target


def run_stage(args, image: str, runroot: Path, workspace: Path, label: str,
              operation: list[str], task=None, endpoint=None, secret='', access='rw', network=None, timeout=120, scorer_assets=None,
              application_secrets=None, redaction_secrets=()):
    application_secrets = application_secrets or {}
    if (task or {}).get('application_secrets') and not application_secrets:
        raise LabError('Assigned application credentials were not resolved', 'application-credentials')
    if application_secrets and (operation[0] != 'agent' or workspace != runroot / 'workspace'
                                or set(application_secrets) != set((task or {}).get('application_secrets', {}))):
        raise LabError('Application credentials require an assigned agent and owned snapshot', 'application-credentials')
    if workspace.resolve()==runroot.resolve() or workspace.resolve() in runroot.resolve().parents:
        raise LabError('Parent run/control sources must remain outside the workspace')
    helpers=trusted_runtime(runroot)
    # UUID sources are created exactly once, outside every writable child mount.
    stage_id = str(uuid.uuid4())
    control = runroot / 'controls' / stage_id
    control.mkdir(parents=True)
    inbox, outbox = control_channels(control, args.uid)
    channels = {'label': label, 'stage_id': stage_id, 'control': str(control),
                'inbox': str(inbox), 'outbox': str(outbox)}
    if endpoint is not None:
        save(control / 'endpoint.json', endpoint)
        (control / 'endpoint.json').chmod(0o644)
    if task is not None:
        save(control / 'task.json', task)
        (control / 'task.json').chmod(0o644)
    if (runroot / 'challenge.json').exists():
        save(control / 'challenge.json', json.loads((runroot / 'challenge.json').read_text()))
        (control / 'challenge.json').chmod(0o644)
    state = state_dir(runroot / 'children', stage_id, args.uid)
    name = 'pi-lab-' + uuid.uuid4().hex[:12]
    argv = docker_args(args, image, workspace, control, state, name, network or args.network, access, bool(secret), helpers=helpers)
    if scorer_assets:
        argv[-2:-2]=['--mount',f"type=bind,src={scorer_assets['root']},dst=/opt/pi-scorer,readonly,bind-recursive=disabled"]
    desc = controls.create(runroot, workspace, label, operation[0], task, control, state, stage_id, name, getattr(args,'lock_file',default_lock_file()))
    credential_receipt = runroot / 'stages' / stage_id / 'application-credentials.json'
    if application_secrets:
        controls.atomic(credential_receipt, {'schema': 1, 'references': task['application_secrets'], 'status': 'pending'})
    argv[-2:-2]=['--env',f"PI_LAB_RUN_ID={desc['run_id']}",'--env',f"PI_LAB_ATTEMPT_ID={desc['attempt_id']}"]
    with controls.lock(runroot):
        running = controls.transition(runroot, desc, 'running', started_at=now())
    result = {}
    try:
        controls.atomic(control / 'stage.json', {**desc, 'stage_revision':running['revision']}, 0o644)
        if operation[0]=='agent':
            result=segments.execute(sys.modules[__name__],args,image,runroot,workspace,label,task,endpoint,secret,desc,access,network or args.network,timeout,helpers,
                                    application_secrets=application_secrets, redaction_secrets=redaction_secrets)
        else:result = stream_run(argv + operation, runroot / label, timeout, name, secret, redaction_secrets=redaction_secrets)
        return result
    finally:
        if not result and (runroot/label/'process.json').exists():
            try:result=controls.read(runroot/label/'process.json')
            except (OSError,ValueError,controls.ControlError):pass
        try:controls.capture_observations(runroot,desc)
        except (OSError,ValueError,controls.ControlError):
            result['observation_error']=True;result['exit_code']=2
        controls.transition(runroot, desc, 'stopping')
        if application_secrets:
            receipt = application_credentials.finish(runroot, desc, application_secrets, secret, result, redaction_secrets)
            controls.atomic(credential_receipt, {**receipt, 'references': task['application_secrets']})
            result['application_credentials'] = receipt
            if receipt['status'] != 'removed' or receipt['workspace'] != 'clean':
                result.update(exit_code=2, termination_reason='application_credential_cleanup')
                result['cleanup_confirmed'] = False
                if result.get('evidence'):
                    result['evidence'].update(agent_invocation_verified=False, completion_verified=False, invocation_status='invalid')
            save(runroot / label / 'process.json', result)
        controls.transition(runroot, desc, 'stopped', exit_code=result.get('exit_code'),
                            cleanup_confirmed=result.get('cleanup_confirmed', False))
        controls.transition(runroot, desc, 'finalized')


def endpoint_secret(endpoint: dict, args) -> str:
    """Resolve the endpoint key from the environment or the host secret store.

    Missing keys raise a 'missing-secret' blocker (exit 3) naming the exact command
    that lets the user type the key with hidden input. Prompting happens only when
    explicitly requested with --prompt-secret, so an unattended agent never hangs.
    """
    name = endpoint['api_key_env']
    store = getattr(args, 'secrets_dir', None)
    try:
        value, source = secret_store.resolve_secret(name, store)
    except secret_store.SecretError as exc:
        raise LabError(str(exc), 'secret-store-insecure', remedy('secret-store-insecure')) from None
    if not value and getattr(args, 'prompt_secret', False):
        try:
            value = secret_store.prompt_secret(name)
        except secret_store.SecretError as exc:
            raise LabError(str(exc), 'missing-secret', remedy('missing-secret', name=name)) from None
        path = secret_store.write_secret(name, value, store)
        print(f'Stored {name} in {path} (0600, {secret_store.fingerprint(value)}).', file=sys.stderr)
        source = 'prompt'
    if not value:
        raise LabError(f'The endpoint key {name} is not set in the environment or the secret store '
                       f'({secret_store.secret_path(name, store)}).', 'missing-secret', remedy('missing-secret', name=name))
    args.secret_source = source
    return value


def secret_store_outside(project: Path | None, args) -> None:
    if project is None:
        return
    store = checked_path(secret_store.default_store() if not getattr(args, 'secrets_dir', None) else Path(args.secrets_dir))
    if store == project or project in store.parents:
        raise LabError(f'The secret store {store} is inside the project and would be visible to agents. Move it '
                       '(PI_LAB_SECRETS_DIR or --secrets-dir) outside the project.', 'secret-store-insecure',
                       remedy('secret-store-insecure'))


def resolve_endpoint_path(args) -> Path:
    """Explicit --endpoint wins; otherwise the saved environment, which must be confirmed and healthy."""
    if getattr(args, 'endpoint', None):
        return checked_path(Path(args.endpoint))
    try:
        return lab_env.require_ready(getattr(args, 'session', None), getattr(args, 'secrets_dir', None))
    except lab_env.EnvError as exc:
        steps = {'needs-session': 'Run `env new-session`, keep the id for this conversation, pass --session ID.',
                 'no-environment': 'Run the environment setup flow: `env discover`, user picks a model, `env save`.',
                 'needs-confirmation': 'Ask the user to confirm the saved environment, then run `env confirm --session ID`.',
                 'broken': 'Ask the user to fix the failing variable or set up a new environment (`env status` explains).'}
        raise LabError(str(exc), 'environment-' + exc.state, steps.get(exc.state, '')) from None


def run_suite(args, smoke=False, initial_record=None):
    initial=copy.deepcopy(initial_record) if initial_record is not None else outcomes.initial()
    try:attempt=outcomes.Attempt(args,initial)
    except (OSError,ValueError,controls.ControlError):
        report=outcomes.fallback(initial,'evidence_destination','evidence_destination_unavailable')
        print(json.dumps(report),file=sys.stderr)
        return 2
    args._attempt_root=attempt.root
    args._attempt_identity={k:attempt.record[k] for k in ('run_id','attempt_id')}
    attempt.record['probe_receipt_contract']=1
    attempt.persist()
    try:
        attempt.record['infrastructure']['phase']='admission'
        requested_policy(args)
        if getattr(args,'project',None):
            project=checked_path(Path(args.project));lease=Path(args.lock_file).expanduser().absolute()
            if lease==project or project in lease.parents or project in lease.resolve().parents:
                raise LabError('The host admission lock must remain outside the project')
        with admission_lock(args.lock_file,args.lock_wait_seconds):
            _execute_suite(args,attempt,smoke)
    except KeyboardInterrupt:
        _observe_last_process(attempt)
        attempt.cancel()
        if getattr(args,'score_after_cancel',False) and attempt.record['scoring']['status']=='skipped':
            try:
                with admission_lock(args.lock_file,args.lock_wait_seconds):
                    plan=controls.read(attempt.root/'plan.json')
                    receipts={i:controls.read(attempt.root/'scorers'/(str(i)+'.json')) for i,t in enumerate(plan['checks']) if t.get('scorer')}
                    score_artifacts(args,attempt,plan,attempt.record['image'],Path(attempt.record['workspace']),receipts,post_cancel=True)
            except Exception:
                attempt.record['scoring'].update(status='skipped',reason='post_cancellation_scoring_unavailable')
    except Exception as exc:
        _observe_last_process(attempt)
        attempt.fail(exc)
    try:report=attempt.finalize()
    except (OSError,ValueError,controls.ControlError):
        report=outcomes.fallback(attempt.record,'finalization','evidence_finalization_failed')
        print(json.dumps(report),file=sys.stderr)
        return 2
    print(json.dumps(report,indent=2,ensure_ascii=False))
    return report['exit_code']


def _observe_last_process(attempt):
    try:
        desc,_=controls.resolve(attempt.root)
        path=attempt.root/desc['label']/'process.json'
        if not path.exists():return
        result=controls.read(path);attempt.process(result)
        attempt.record['last_process']=result
        if desc['kind']=='agent' and result.get('started'):
            attempt.record['invocation']['status']='invalid'
    except (OSError,ValueError,controls.ControlError):pass


def _execute_suite(args,attempt,smoke=False):
    runroot=attempt.root;summary=attempt.record
    summary['event_contract']=args.event_contract
    profile=agent_profiles.load(args.agent_profile) if getattr(args,'agent_profile',None) else agent_profiles.builtin()
    args.frozen_agent_profile=agent_profiles.freeze(profile,runroot/'agent-profile')
    summary['agent_profile']={'id':profile['id'],'kind':profile['kind'],'sha256':agent_profiles.identity(profile),'requested':profile,'loading':'unverified'}
    summary['infrastructure']['phase']='endpoint'
    endpoint = load_endpoint(resolve_endpoint_path(args))
    summary['endpoint']={k:v for k,v in endpoint.items() if k not in ('base_url','host_base_url')}
    summary['endpoint']['routes']={name:{'url':endpoint.get(name,endpoint['base_url']),'digest':hashlib.sha256(endpoint.get(name,endpoint['base_url']).encode()).hexdigest()} for name in ('base_url','host_base_url')}
    summary['infrastructure']['phase']='secret'
    secret = endpoint_secret(endpoint, args)
    # Admit every reference before image probes, setup or any worker dispatch.
    project = checked_path(Path(args.project)) if args.project else None
    admitted_plan = None
    stage_credentials = {}
    if not smoke and project is not None and args.plan:
        planpath = checked_path(Path(args.plan))
        admitted_plan = validate_plan(json.loads(planpath.read_text()), planpath.parent, profile)
        secret_store_outside(project, args)
        stage_credentials = application_credentials.resolve(admitted_plan, endpoint, secret,
            getattr(args, 'secrets_dir', None) or secret_store.default_store(), project, runroot, args.in_place,
            forbidden_roots=[ROOT, getattr(args, '_experiment_root', None)])
    redaction_secrets = [value for assigned in stage_credentials.values() for value in assigned.values()]
    summary['infrastructure']['phase']='host'
    summary['host'] = require_host(args)
    args.frozen_browser_security = browser_security.freeze(args, runroot / 'browser-security')
    summary['browser_security'] = args.frozen_browser_security
    summary['infrastructure']['phase']='image'
    image = probe_image(args, args.image);summary['image']=image
    args.release_contract = admit_image(image)
    args.observed_pi_version = args.release_contract['release']
    summary['release_contract'] = args.release_contract
    if args.event_contract != release_contracts.contract(args.observed_pi_version)['completion']:
        raise LabError('Reviewed Pi releases require agent_settled; process-exit is historical inspection only',
                       'unsupported-event-contract')
    try:_,_,_,reasoning_receipt=pi_contract.model_configuration(endpoint,args.observed_pi_version)
    except ValueError as exc:
        raise LabError(str(exc),'unsupported-pi-settings','Review PI-COMPATIBILITY.md; omit numeric reasoning budgets for this profile or qualify the explicitly selected release.') from exc
    try: agent_profiles.admit(profile, args.observed_pi_version)
    except ValueError as exc: raise LabError(str(exc), 'unsupported-agent-profile') from exc
    summary['reasoning']=reasoning_receipt
    summary['provenance']=provenance.execution(endpoint,image,ROOT)
    attempt.persist()
    if project is not None and (not project.is_dir() or project == Path('/') or project == Path.home()):
        raise LabError('Choose a project directory, not / or your complete home','invalid-project')
    secret_store_outside(project, args)
    summary['infrastructure']['phase']='plan'
    attempt.persist()
    print(f'Run evidence: {runroot}',file=sys.stderr)
    try:
        if smoke:
            workspace = runroot / 'workspace'
            workspace.mkdir()
            challenge = {'nonce': uuid.uuid4().hex, 'a': int(uuid.uuid4().hex[:6], 16),
                         'b': int(uuid.uuid4().hex[:6], 16)}
            save(runroot / 'challenge.json', challenge)
            plan = validate_plan({'schema': 1, 'name': 'real-agent-smoke', 'agents': [{
                'name': 'smoke-agent', 'tools': ['read', 'write', 'bash'],
                'require_tools': ['read', 'write', 'bash'], 'max_turns': 10, 'timeout_seconds': 600,
                'prompt': 'This is a real tool-use acceptance test. First use the read tool to read '
                          '/opt/pi-control/challenge.json. Then use the write tool to create '
                          '/workspace/agent-proof.json with exactly two JSON keys: nonce copied from '
                          'the challenge, and sum equal to a+b. Next use the bash tool to run Python '
                          'and verify that file against /opt/pi-control/challenge.json, using assertions. '
                          'Print AGENT_PROOF_OK on success. Do not merely describe these actions. '
                          'Finish with a short factual result.'}],
                'checks': [{'name': 'independent-proof',
                            'argv': ['python3', '/opt/pi-lab/verify-smoke.py']}], 'protected_paths': []}, ROOT)
            summary['workspace_mode'] = 'new-smoke-workspace'
        else:
            if project is None or not args.plan:
                raise LabError('run needs --project and --plan')
            plan = admitted_plan
            if args.in_place:
                # Admission covers the complete writable mount; tree_hashes()
                # remains a filtered change inventory, not a safety scanner.
                check_in_place_tree(project)
                workspace = project
                summary['workspace_mode'] = 'IN_PLACE_ORIGINAL_FILES'
            else:
                workspace = runroot / 'workspace'
                summary['copy'] = snapshot(project, workspace, args.exclude, args.max_project_mb)
                summary['workspace_mode'] = 'isolated-copy'
        plan=agent_profiles.apply(plan,profile)
        if stage_credentials:
            values = [value for assigned in stage_credentials.values() for value in assigned.values()]
            redactor = application_credentials.Redactor([secret, *values])
            if redactor.contains(json.dumps(plan, ensure_ascii=False).encode()) or not application_credentials.workspace_inspected_clean(workspace, redactor):
                shutil.rmtree(workspace)
                raise LabError('Credential-bearing or uninspectable plan/snapshot; no worker dispatched', 'application-credentials')
        summary['provenance']['agent_profile']={'id':profile['id'],'sha256':agent_profiles.identity(profile),'assets':{a['target']:a['sha256'] for a in profile['assets']}}
        check_project_contract(workspace, plan)
        save(runroot / 'plan.json', plan)
        scorer_receipts={}
        for index,check in enumerate(plan['checks']):
            if check.get('scorer'):
                parent=runroot/'scorers';parent.mkdir(exist_ok=True)
                scorer_receipts[index]=scoring.freeze(check['scorer'],parent/str(index))
                save(parent/(str(index)+'.json'),scorer_receipts[index])
        summary['workspace'] = str(workspace)
        before = tree_hashes(workspace)
        save(runroot / 'files-before.json', before)
        summary['provenance'].update(snapshot_sha256=provenance.digest(before),
            source_sha256=provenance.digest(tree_hashes(project)) if project else None,
            plan_sha256=provenance.digest(plan),scorers={str(k):v for k,v in scorer_receipts.items()})
        summary['provenance']['source_scope']='included project tree (runner exclusions apply); symlinks recorded without following'
        attempt.persist()
        expected_protected = protected_hashes(workspace, plan['protected_paths'])
        save(runroot / 'protected-before.json', expected_protected)
        for phase in ('setup', 'checks'):
            for t in plan[phase]:
                allowed = args.allow_setup_network if phase == 'setup' else args.allow_check_network
                if t['network'] == 'inherit' and not allowed:
                    raise LabError(f'{phase}/{t["name"]} requests networking: review it and explicitly allow that phase')
        summary['infrastructure']['phase']='preflight'
        boundary_result = run_stage(args, image['id'], runroot, workspace, 'boundary', ['boundary'], network='none', redaction_secrets=redaction_secrets)
        attempt.process(boundary_result)
        if boundary_result['exit_code'] or boundary_result.get('cleanup_confirmed') is not True:
            raise LabError('Filesystem isolation probe failed; inspect boundary/stderr.log')
        api = run_stage(args, image['id'], runroot, workspace, 'preflight', ['preflight'],
                        endpoint=endpoint, secret=secret, timeout=150, redaction_secrets=redaction_secrets)
        attempt.process(api)
        if api['exit_code'] or api.get('cleanup_confirmed') is not True:
            raise LabError('Model endpoint preflight failed; inspect preflight/stderr.log. No fallback used.')
        if args.profile == 'browser':
            browser_result = run_stage(args, image['id'], runroot, workspace, 'browser',
                                      ['browser'] + (['--webgl'] if args.software_webgl else []), network='none', redaction_secrets=redaction_secrets)
            attempt.process(browser_result)
            if browser_result['exit_code'] or browser_result.get('cleanup_confirmed') is not True:
                raise LabError('Real Chromium smoke failed. Inspect browser/stderr.log; do not auto-disable its sandbox.')
        summary['infrastructure']['phase']='setup'
        for i, t in enumerate(plan['setup']):
            label = f'setup-{i+1}-{t["name"]}'
            r = run_stage(args, image['id'], runroot, workspace, label, ['check'], task=t,
                          network=args.network if t['network'] == 'inherit' else 'none', timeout=t['timeout_seconds'], redaction_secrets=redaction_secrets)
            attempt.process(r)
            if r['exit_code'] or r.get('cleanup_confirmed') is not True:
                raise LabError(f'Setup command failed: {label}')
        summary['infrastructure'].update(status='ready',phase='agents')
        failed = False
        for i, task in enumerate(plan['agents']):
            label = f'agent-{i+1}-{task["name"]}'
            previous_invocation=summary['invocation']['status']
            summary['invocation']['attempted_stages']+=1
            summary['invocation']['status']='invalid'
            attempt.persist()
            r = run_stage(args, image['id'], runroot, workspace, label, ['agent'], task=task,
                          endpoint=endpoint, secret=secret, access=task['access'], timeout=task['timeout_seconds'] + 30,
                          application_secrets=stage_credentials.get(task['name']), redaction_secrets=redaction_secrets)
            summary['invocation']['status']='invalid'
            attempt.cause(r.get('termination_reason','completed' if r['exit_code']==0 else 'process_error'),r['exit_code'])
            if not r.get('cleanup_confirmed',False):attempt.cause('cleanup_error')
            version=re.search(r'\b(\d+\.\d+\.\d+)\b',image.get('capabilities',{}).get('pi',''))
            evidence = r.get('evidence') or analyze(runroot / label / 'stdout.jsonl', endpoint['model'], task['require_tools'], r['exit_code'], args.event_contract,
                               release=version.group(1) if version else None)
            save(runroot / label / 'evidence.json', evidence)
            (runroot / label / 'final.txt').write_text(evidence['final_text'])
            observations=[{'segment_id':s['segment_id'],**s['evidence'].get('agent_profile',{})} for s in r.get('segments',[])]
            summary['agent_profile'].setdefault('observed_stages',[]).append({'name':task['name'],'segments':observations})
            if observations and all(s.get('loading')=='observed' for row in summary['agent_profile']['observed_stages'] for s in row['segments']):summary['agent_profile']['loading']='observed'
            summary['agents'].append({'name': task['name'], 'logs': label, 'process': r,
                                      'invocation_verified': evidence['agent_invocation_verified'], 'errors': evidence['errors']})
            save(runroot / 'summary.json', summary)
            summary['invocation']['status']=evidence.get('invocation_status','verified' if evidence['agent_invocation_verified'] else 'invalid')
            if previous_invocation=='recovered' and evidence.get('completion_verified',evidence['agent_invocation_verified']):summary['invocation']['status']='recovered'
            if not evidence.get('completion_verified',evidence['agent_invocation_verified']) or r.get('cleanup_confirmed') is not True:
                summary['scoring'].update(status='skipped',reason='invocation_failed')
                failed = True
                break
        summary['measurement']={'usage':combine_usage([row['process'].get('usage',summarize_usage([])) for row in summary['agents']]),
            'agent_process_seconds':sum(row['process'].get('timing',{}).get('stage_end_to_end_seconds',row['process'].get('elapsed_seconds',0)) for row in summary['agents']),
            'inference_seconds':None,'inference_timing_status':'not_exposed'}
        score_artifacts(args,attempt,plan,image,workspace,scorer_receipts,redaction_secrets=redaction_secrets)
        safe=all(row['process'].get('cleanup_confirmed') is True for row in summary['agents'])
        if safe:
            after = tree_hashes(workspace)
            save(runroot / 'files-after.json', after)
            changed = {p: {'before': before.get(p), 'after': after.get(p)}
                       for p in sorted(before.keys() | after.keys()) if before.get(p) != after.get(p)}
            save(runroot / 'changes.json', changed)
        summary['assistance']=controls.assistance(runroot)
        # Terminal status is derived only by the sealed outcome finalizer.
        summary['scope'] = 'Only the supplied plan and checks; not proof of general model or product correctness.'
    except KeyboardInterrupt:
        raise
    except Exception:
        raise
    finally:
        attempt.persist()


def score_artifacts(args,attempt,plan,image,workspace,receipts,post_cancel=False,redaction_secrets=()):
    summary=attempt.record;runroot=attempt.root
    def skipped(reason,start=0):
        rows=[{'schema':1,'scorer_id':t.get('scorer',{}).get('id','command-only'),
               'status':'skipped','reason':reason,'task_status':'unknown','score':None,'test_counts':None,'assertions':None}
              for t in plan['checks'][start:]]
        return rows
    if summary['invocation']['attempted_stages']==0:
        summary['scoring'].update(status='skipped',reason='agent_not_started',results=skipped('agent_not_started'));return
    processes=[r['process'] for r in summary['agents']]
    if not processes and summary.get('last_process'):processes=[summary['last_process']]
    reason=None
    if not processes or any(r.get('cleanup_confirmed') is not True for r in processes):reason='cleanup_unconfirmed'
    elif not workspace.is_dir() or workspace.is_symlink():reason='workspace_missing'
    elif summary['termination']['reason']=='cancelled' and not post_cancel:reason='user_cancelled'
    if reason:
        summary['scoring'].update(status='skipped',reason=reason,results=skipped(reason));return
    expected=controls.read(runroot/'protected-before.json')
    current=protected_hashes(workspace,plan['protected_paths'])
    summary['protected_paths_unchanged']=current==expected
    summary['protected_inputs']['status']='unchanged' if current==expected else 'changed'
    save(runroot/'protected-after.json',current)
    frozen=runroot/'score-workspace'
    try:snapshot(workspace,frozen,[],args.max_project_mb,score_copy=True)
    except (OSError,LabError):
        summary['scoring'].update(status='skipped',reason='workspace_snapshot_failed',results=skipped('workspace_snapshot_failed'));return
    summary['scoring']={'status':'running','reason':None,'results':[]}
    results=[]
    for index,check in enumerate(plan['checks']):
        label=f'check-{index+1}-{check["name"]}'
        # Every verifier sees the same stopped artifact snapshot in its own copy.
        copy_root=runroot/('score-subject-'+str(index))
        snapshot(frozen,copy_root,[],args.max_project_mb,score_copy=True)
        protected_before=protected_hashes(copy_root,plan['protected_paths'])
        try:
            process=run_stage(args,image['id'],runroot,copy_root,label,['check'],task=check,
                              network=args.network if check['network']=='inherit' else 'none',
                              timeout=check['timeout_seconds'],access='ro' if check.get('scorer') else 'rw',
                              scorer_assets=receipts.get(index),redaction_secrets=redaction_secrets)
        except KeyboardInterrupt:
            result={'schema':1,'scorer_id':check.get('scorer',{}).get('id','command-only'),'status':'cancelled',
                    'reason':'user_cancelled','task_status':'unknown','score':None,'test_counts':None,'assertions':None}
            results.append(result);results.extend(skipped('user_cancelled',index+1))
            summary['scoring'].update(status='cancelled',reason='user_cancelled',results=results)
            save(runroot/label/'score.json',result)
            raise
        except (OSError,LabError,controls.ControlError):
            # A launch/cleanup exception cannot authorize another runtime stage.
            process={'exit_code':2,'cleanup_confirmed':False}
        output=(runroot/label/'stdout.jsonl').read_text() if (runroot/label/'stdout.jsonl').exists() else ''
        result=scoring.evaluate(check.get('scorer'),receipts.get(index),process,output,summary['run_id'],summary['attempt_id'])
        if process.get('cleanup_confirmed') is True and protected_hashes(copy_root,plan['protected_paths'])!=protected_before:
            result.update(status='error',reason='acceptance_inputs_changed',task_status='unknown',score=None,test_counts=None)
        result['command_sha256']=hashlib.sha256(json.dumps(check['argv']).encode()).hexdigest()
        result['post_cancellation']=post_cancel
        save(runroot/label/'score.json',result);results.append(result)
        summary['checks'].append({'name':check['name'],'logs':label,'process':process,'scorer':result})
        summary['scoring']['results']=list(results);attempt.persist()
        if process.get('cleanup_confirmed') is not True:
            results.extend(skipped('cleanup_unconfirmed',index+1));break
    summary['scoring'],summary['task_result']=scoring.aggregate(results)


def preflight_only(args):
    c = load_endpoint(resolve_endpoint_path(args))
    key = endpoint_secret(c, args)
    host = require_host(args)
    image = probe_image(args, args.image)
    args.release_contract = admit_image(image)
    args.observed_pi_version = args.release_contract['release']
    try: pi_contract.model_configuration(c, args.observed_pi_version)
    except ValueError as exc: raise LabError(str(exc), 'unsupported-pi-settings') from exc
    parent = checked_path(Path(args.results_dir))
    parent.mkdir(parents=True, exist_ok=True)
    runroot = parent / ('preflight-' + uuid.uuid4().hex[:12])
    runroot.mkdir(mode=0o700)
    workspace = runroot / 'workspace'
    workspace.mkdir()
    result = run_stage(args, image['id'], runroot, workspace, 'preflight', ['preflight', '--chat'],
                       endpoint=c, secret=key, timeout=160)
    report = {'run_dir': str(runroot), 'host': host, 'image': image, 'endpoint': c,
              'key_source': getattr(args, 'secret_source', ''), 'process': result}
    if result['exit_code']:
        tail = (runroot / 'preflight' / 'stderr.log').read_text(errors='replace')[-2000:] if (runroot / 'preflight' / 'stderr.log').exists() else ''
        report['stderr_tail'] = tail
        low = tail.lower()
        if 'http 401' in low or 'http 403' in low:
            report.update(reason='endpoint-auth-failed', remedy=remedy('endpoint-auth-failed', name=c['api_key_env']))
        elif 'cannot reach api' in low:
            report.update(reason='endpoint-unreachable', remedy=remedy('endpoint-unreachable'))
        elif 'model id not present' in low:
            report.update(reason='model-not-found', remedy=remedy('model-not-found'))
    save(runroot / 'summary.json', report)
    print(json.dumps(report, indent=2))
    return 0 if result['exit_code'] == 0 else 2


def find_run_dir(args) -> Path:
    if getattr(args, 'run', None):
        return checked_path(Path(args.run))
    results = checked_path(Path(args.results_dir))
    latest = results / 'latest'
    if latest.exists():
        try:
            return latest.resolve()
        except Exception:
            pass
    runs = sorted([p for p in results.glob('*') if p.is_dir() and p.name != 'latest'],
                  key=lambda p: p.stat().st_mtime)
    if runs:
        return runs[-1]
    raise LabError(f'No runs found in {results}')


def stage_channels(runroot: Path, stage_label: str) -> tuple[Path, Path]:
    try:
        desc, _ = controls.resolve(runroot, stage_label)
        return Path(desc['inbox']), Path(desc['outbox'])
    except (OSError, ValueError, controls.ControlError):
        # Inspection only; never use this legacy path for mutation.
        return runroot / 'controls' / stage_label / 'inbox', runroot / 'controls' / stage_label / 'outbox'


def mutable_stage(args):
    runroot = find_run_dir(args)
    try:
        desc,state = controls.resolve(runroot, getattr(args,'stage',None))
        controls.check_mutable(desc,state,getattr(args,'revision',None))
        return runroot,desc,state
    except (OSError,ValueError,controls.ControlError) as exc:
        raise LabError(str(exc), 'invalid-stage-control') from exc


def budget_warnings(heartbeat: dict, threshold: float = 0.8) -> list[str]:
    """Advise the parent before a stage dies of exit 124 with almost-finished work."""
    pairs = [('turn', 'max_turns', 'turns', '--turns +10'),
             ('elapsed_seconds', 'timeout_seconds', 'wall time', '--timeout +600'),
             ('tokens', 'max_total_tokens', 'tokens', '--tokens +500000')]
    out = []
    if heartbeat.get('status') not in (None, 'running'):
        return out
    for used_key, max_key, label, flag in pairs:
        used, limit = heartbeat.get(used_key), heartbeat.get(max_key)
        if isinstance(used, (int, float)) and isinstance(limit, (int, float)) and limit > 0 and used / limit >= threshold:
            out.append(f'WARNING: {used / limit:.0%} of the {label} budget used. If progress is real, run: '
                       f'python3 "$SKILL_DIR/scripts/pi_lab.py" extend-budget {flag}')
    return out


def cmd_status(args):
    runroot = find_run_dir(args)
    summary_file = runroot / 'summary.json'
    summary = json.loads(summary_file.read_text()) if summary_file.exists() else {}
    active_file = runroot / 'active_stage.json'
    active = json.loads(active_file.read_text()) if active_file.exists() else {}

    try:
        desc, state = controls.resolve(runroot, getattr(args, 'stage', None))
        active = {**desc, **state}
    except (OSError, ValueError, controls.ControlError):
        if getattr(args, 'stage', None):
            raise LabError('Unknown/ambiguous stage')
        desc = None
    stage_label = active.get('label') or 'unknown'
    heartbeat_file = Path(desc['outbox']) / 'heartbeat.json' if desc else None
    heartbeat = {}
    credential_stage = desc and (runroot / 'stages' / desc['stage_id'] / 'application-credentials.json').exists()
    if heartbeat_file and heartbeat_file.exists() and not credential_stage:
        try:
            observed = controls.observations(desc)
            heartbeat = observed.get('heartbeat', {})
        except ValueError:
            heartbeat = {}

    out = []
    out.append("=== PI RUN STATUS ===")
    out.append(f"Run Directory: {runroot}")
    out.append(f"Overall Status: {summary.get('status', 'UNKNOWN')} (Started: {summary.get('started_at', 'unknown')})")
    if summary.get('reason'):
        out.append(f"Blocked Reason: {summary['reason']}")
        out.append(f"Remedy: {summary.get('remedy', '')}")
    host_info = summary.get('host', {})
    out.append(f"Host Architecture: {host_info.get('native_platform', 'unknown')} (Selected: {host_info.get('selected_platform', 'unknown')})")
    out.append(f"Image: {summary.get('image', {}).get('reference', 'unknown')}")
    out.append(f"Active Stage: {stage_label} (Status: {active.get('status', 'running')}, Exit: {active.get('exit_code', '-')})")
    if desc and (controls.budget_path(runroot,desc)).exists():
        budget=controls.read(controls.budget_path(runroot,desc))
        out.append(f"Parent Budget: revision {budget['revision']} ({budget['phase']}), effective {budget['effective_limits']}")
        for path in sorted((controls.budget_path(runroot,desc).parent/'budget-updates').glob('*.json'))[-3:]:
            update=controls.read(path)
            out.append(f"Budget command {update['id']}: {update['status']} (host authoritative; worker observation untrusted)")
    if heartbeat:
        out.append("--- Live Telemetry (reported by the child; untrusted) ---")
        out.append(f"Heartbeat Status: {heartbeat.get('status', 'unknown')}")
        turn = heartbeat.get('turn', 0)
        max_turns = heartbeat.get('max_turns', '?')
        out.append(f"Turns: {turn} / {max_turns}")
        tokens = heartbeat.get('tokens', 0)
        max_tokens = heartbeat.get('max_total_tokens', '?')
        out.append(f"Tokens: {tokens} / {max_tokens}")
        usage=heartbeat.get('usage',{}).get('categories',{})
        if usage:out.append('Reported usage: '+', '.join(f'{name}={value.get("reported") if value.get("reported") is not None else "unknown"}' for name,value in usage.items()))
        elapsed = heartbeat.get('elapsed_seconds', 0)
        timeout = heartbeat.get('timeout_seconds', '?')
        out.append(f"Elapsed: {elapsed}s / {timeout}s")
        out.append(f"Last Tool: {heartbeat.get('last_tool') or 'none'}")
        if heartbeat.get('recent_tools'):
            out.append(f"Recent Tools: {', '.join(str(x)[:100] for x in heartbeat['recent_tools'][:5])}")
        out.append(f"Container Architecture: {heartbeat.get('container_arch', 'unknown')}")
        out.extend(budget_warnings(heartbeat))

    # Tail the stage's real stderr log (stdout.jsonl holds large JSON events).
    fpath = Path(active.get('logs',runroot/stage_label)) / 'stderr.log'
    if fpath.exists() and fpath.stat().st_size > 0:
        lines = fpath.read_text(errors='replace').splitlines()
        if lines:
            out.append(f"--- Tail of {stage_label}/stderr.log (last 5 lines) ---")
            out.extend(line[:300] for line in lines[-5:])
    out.append("=====================")
    print('\n'.join(out))
    return 0


def audited_command(args,kind,function):
    runroot=find_run_dir(args)
    try:
        desc,state=controls.resolve(runroot,getattr(args,'stage',None));desc={**desc,'segment_id':state.get('segment_id',desc['segment_id'])}
    except (OSError,ValueError,controls.ControlError):
        identity=controls.read(runroot/'identity.json') if (runroot/'identity.json').exists() else {}
        desc={**identity,'stage_id':None,'segment_id':None}
    payload={k:getattr(args,k,None) for k in ('stage','revision','budget_revision','turns','timeout','tokens','message','interrupt','target')}
    context={k:desc.get(k) for k in ('run_id','attempt_id','stage_id','segment_id')}
    context.update(id=str(uuid.uuid4()),intervention_id=str(uuid.uuid4()),kind=kind,
                   payload_digest=hashlib.sha256(json.dumps(payload,sort_keys=True).encode()).hexdigest())
    args._intervention=context
    controls.audit(runroot,context,'requested')
    try:
        result=function(args)
    except (LabError,controls.ControlError,OSError,ValueError) as exc:
        accepted=any(e.get('id')==context['id'] and e['status']=='accepted' for e in controls.history(runroot))
        controls.audit(runroot,context,'application_error' if accepted else 'rejected',reason_code='control_operation_failed')
        raise
    return result


def cmd_extend_budget(args):
    return audited_command(args,'extend_budget',_cmd_extend_budget)


def _cmd_extend_budget(args):
    runroot,desc,state = mutable_stage(args)
    wait=float(getattr(args,'wait_seconds',0))
    if not math.isfinite(wait) or not 0<=wait<=10:raise LabError('wait-seconds must be finite and 0..10')
    with controls.lock(runroot,desc['stage_id']):
        desc,state=controls.resolve(runroot,desc['stage_id'])
        controls.check_mutable(desc,state,getattr(args,'revision',None))
        result=_extend_budget(args,runroot,desc,state)
    response=controls.budget_path(runroot,desc).parent/'budget-updates'/(result['command_id']+'.json')
    deadline=time.monotonic()+wait
    while wait and time.monotonic()<deadline:
        if response.exists():
            observed=controls.read(response);result={**result,**observed};break
        time.sleep(.02)
    print(json.dumps(result))
    return 1 if result['status']=='rejected' else 0


def _extend_budget(args,runroot,desc,state):
    budget=controls.read(controls.budget_path(runroot,desc))
    if budget['phase']!='active' or time.monotonic()>=budget['deadline_host_monotonic']:
        raise LabError('Budget update is late or no active supervisor')
    expected=getattr(args,'budget_revision',None)
    if expected is not None and expected!=budget['revision']:raise LabError('Stale budget revision')
    values=dict(budget['effective_limits'])
    for flag,key in [('turns','max_turns'),('timeout','timeout_seconds'),('tokens','max_total_tokens')]:
        value=getattr(args,flag,None)
        if value is None:continue
        if not re.fullmatch(r'\+?[0-9]+',str(value)):raise LabError('Budget must be a positive integer or +increment')
        number=int(str(value).lstrip('+'))
        new=values[key]+number if str(value).startswith('+') else number
        if not 0<new<=controls.LIMIT_MAX[key] or new<=values[key]:raise LabError('Budget update must increase within finite allowed bounds')
        values[key]=new
    if values==budget['effective_limits']:raise LabError('No effective budget increase requested')
    request=controls.command_record(desc,state,'extend_budget',{
        'expected_budget_revision':budget['revision'],'limits':values},args._intervention)
    folder=controls.budget_path(runroot,desc).parent/'budget-requests';folder.mkdir(exist_ok=True)
    controls.atomic(folder/(request['id']+'.json'),request)
    controls.audit(runroot,request,'queued')
    result={'status':'queued','command_id':request['id'],'stage_id':desc['stage_id']}
    return result


def cmd_steer(args):
    return audited_command(args,'steer',_cmd_steer)


def _cmd_steer(args):
    runroot,desc,state = mutable_stage(args)
    with controls.lock(runroot,desc['stage_id']):
        desc,state = controls.resolve(runroot,desc['stage_id'])
        controls.check_mutable(desc,state,getattr(args,'revision',None))
        data=controls.command_record(desc,state,'steer',{'message':args.message,'interrupt':bool(args.interrupt)},args._intervention)
        if not isinstance(args.message,str) or not args.message.strip() or len(args.message.encode())>128*1024:raise LabError('Steering message must be nonempty and bounded')
        controls.audit(runroot,data,'accepted')
        path=Path(desc['inbox'])/'directives';path.mkdir(exist_ok=True)
        controls.atomic(path/(data['id']+'.json'),data,0o644)
        controls.audit(runroot,data,'queued')
    print(json.dumps({'status':'queued','stage_id':desc['stage_id'],'command_id':data['id']}))
    return 0


def cmd_patch_session(args):
    return audited_command(args,'patch',_cmd_patch_session)


def _cmd_patch_session(args):
    runroot=find_run_dir(args)
    try:
        if getattr(args,'message',None) or getattr(args,'interrupt',False):
            raise controls.ControlError('Prepared-stage patching has no live steering; omit --message/--interrupt')
        desc,state=controls.resolve(runroot,getattr(args,'stage',None))
        lease=desc.get('admission_lock_file')
        if not lease or Path(lease)==Path(desc['workspace']) or Path(desc['workspace']) in Path(lease).parents:
            raise controls.ControlError('No safe host writer lease recorded; patching unsupported')
        with admission_lock(lease,0), controls.lock(runroot):
            desc,state=controls.resolve(runroot,getattr(args,'stage',None))
            with controls.lock(runroot,desc['stage_id']):
                desc,state=controls.resolve(runroot,desc['stage_id'])
                # Until a qualified writer-quiescence mechanism exists, reject
                # active patches. Pending stages are serialized with launch.
                controls.check_mutable(desc,state,getattr(args,'revision',None),allow_pending=True)
                for path in (runroot/'stages').glob('*/descriptor.json'):
                    other=controls.read(path)
                    if other['stage_id']==desc['stage_id'] or other['workspace']!=desc['workspace']: continue
                    lifecycle=controls.read(path.parent/'state.json')
                    if lifecycle['status']!='finalized' or not lifecycle.get('cleanup_confirmed'):
                        raise controls.ControlError('Workspace writers are active or cleanup is unconfirmed')
                source=checked_path(Path(args.file))
                fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                with os.fdopen(fd,'rb') as f:
                    if not stat.S_ISREG(os.fstat(f.fileno()).st_mode): raise workspace_patch.PatchError('Patch source must be regular')
                    content=f.read(16*1024*1024+1)
                target=getattr(args,'target',None) or source.name
                if len(content)>16*1024*1024:raise workspace_patch.PatchError('Patch too large')
                workspace_patch.preflight(desc['workspace'],desc['workspace_identity'],target,desc['protected_paths'])
                record=controls.command_record(desc,state,'patch',{'target':target,'sha256':hashlib.sha256(content).hexdigest()},args._intervention)
                controls.audit(runroot,record,'accepted',patch_sha256=record['sha256'])
                workspace_patch.apply(desc['workspace'],desc['workspace_identity'],target,content,desc['protected_paths'])
                controls.audit(runroot,record,'applied',patch_sha256=record['sha256'],host_applied=True)
                folder=Path(desc['inbox'])/'directives';folder.mkdir(exist_ok=True)
                controls.atomic(folder/(record['id']+'.json'),record,0o644)
        print(json.dumps({'status':'applied','command_id':record['id'],'stage_id':desc['stage_id'],'target':target}))
        return 0
    except AdmissionError:
        raise
    except (OSError,ValueError,controls.ControlError,workspace_patch.PatchError) as exc:
        raise LabError(str(exc),'unsafe-workspace-patch') from exc


def host_endpoint_check(endpoint: dict, key: str, timeout: float = 10.0) -> tuple[str, str, str]:
    """GET /models from the host. Returns (status, detail, reason). Container reachability is
    confirmed separately by `preflight`; a host pass does not prove the child can connect."""
    from urllib.error import HTTPError, URLError
    from urllib.request import ProxyHandler, Request, build_opener
    base=endpoint.get('host_base_url',endpoint['base_url'])
    req = Request(base.rstrip('/') + '/models', headers={'Authorization': 'Bearer ' + key})
    try:
        with build_opener(ProxyHandler({})).open(req, timeout=timeout) as response:
            listing = json.loads(response.read(4 * 1024 * 1024))
    except HTTPError as exc:
        reason = 'endpoint-auth-failed' if exc.code in (401, 403) else 'endpoint-unreachable'
        return 'fail', f'HTTP {exc.code} from /models', reason
    except (URLError, OSError, ValueError) as exc:
        return 'fail', f'Cannot reach host route {base}: {getattr(exc, "reason", exc)}', 'endpoint-unreachable'
    ids = [m.get('id') for m in listing.get('data', []) if isinstance(m, dict)]
    if endpoint['model'] not in ids:
        return 'fail', f'Model {endpoint["model"]} not listed; server offers {ids[:5]}', 'model-not-found'
    return 'ok', f'{endpoint["model"]} is listed by the server', ''


def cmd_doctor(args) -> int:
    """Check every prerequisite and report all blockers at once, each with a remedy."""
    checks = []

    def add(check_name, status, detail, reason='', **fields):
        item = {'check': check_name, 'status': status, 'detail': detail}
        if reason:
            item['reason'] = reason
            item['remedy'] = remedy(reason, **fields)
        checks.append(item)

    add('python', 'ok' if sys.version_info >= (3, 10) else 'fail', platform.python_version())
    docker_ok = False
    try:
        info = docker_info()
        docker_ok = True
        add('docker', 'ok', f'Docker {info.get("ServerVersion")} ({info.get("OSType")}/{norm_arch(info.get("Architecture", ""))})')
    except LabError as exc:
        add('docker', 'fail', str(exc), exc.reason or 'docker-error')
    if docker_ok:
        try:
            context = command(['docker', 'context', 'show']).stdout.strip()
            ctx = json.loads(command(['docker', 'context', 'inspect', context]).stdout)[0]
            host = os.environ.get('DOCKER_HOST') or ctx.get('Endpoints', {}).get('docker', {}).get('Host', '')
            if host.startswith(('ssh://', 'tcp://', 'http://', 'https://')):
                add('docker-context', 'fail', f'{context} -> {host}', 'docker-remote')
            else:
                add('docker-context', 'ok', f'{context} -> {host or "default socket"}')
        except LabError as exc:
            add('docker-context', 'fail', str(exc), 'docker-context-invalid')
        result = command(['docker', 'image', 'inspect', '--format', '{{.Architecture}}', args.image], required=False)
        if result.returncode:
            add('image', 'fail', f'{args.image} not present locally', 'image-missing', image=args.image)
        else:
            add('image', 'ok', f'{args.image} ({result.stdout.strip()}); run `doctor --probe-image` for a full capability probe')
    else:
        add('image', 'skip', 'Docker unavailable')

    endpoint_path = args.endpoint or (str(lab_env.endpoint_path()) if lab_env.endpoint_path().exists() else None)
    if not args.endpoint:
        session = args.session or os.environ.get('PI_LAB_SESSION')
        if not lab_env.endpoint_path().exists():
            add('environment', 'fail', 'No saved model environment', 'environment-missing')
        elif not session:
            add('environment', 'warn', 'Saved environment found; pass --session ID to check confirmation')
        else:
            gate = lab_env.evaluate(session, check=False)
            add('environment', 'ok' if gate['state'] == 'ready' else 'fail', f'{gate["state"]} (session {session})',
                '' if gate['state'] == 'ready' else 'environment-' + gate['state'])
    key = ''
    endpoint = None
    if endpoint_path:
        try:
            endpoint = load_endpoint(checked_path(Path(endpoint_path)))
            add('endpoint-file', 'ok', f'{endpoint_path}: {endpoint["model"]} at host {endpoint.get("host_base_url",endpoint["base_url"])}; child {endpoint["base_url"]}')
        except (LabError, controls.ControlError, ValueError, OSError) as exc:
            add('endpoint-file', 'fail', f'{endpoint_path}: {exc}')
    else:
        add('endpoint-file', 'skip', 'No --endpoint given and no saved environment')
    if endpoint:
        name = endpoint['api_key_env']
        st = secret_store.status(name, getattr(args, 'secrets_dir', None))
        if st.get('store_ok') is False:
            add('endpoint-key', 'fail', st.get('store_error', 'insecure secret file'), 'secret-store-insecure')
        elif st['active_source'] == 'missing':
            add('endpoint-key', 'fail', f'{name} not in environment or {st["store_path"]}', 'missing-secret', name=name)
        else:
            add('endpoint-key', 'ok', f'{name} from {st["active_source"]} ({st["fingerprint"]})')
            key = secret_store.resolve_secret(name, getattr(args, 'secrets_dir', None))[0]
        if key and not args.skip_network:
            status_, detail, reason = host_endpoint_check(endpoint, key)
            add('endpoint-host-reachability', status_, detail, reason, name=name)
        elif not key:
            add('endpoint-host-reachability', 'skip', 'No key available')

    if args.project:
        project = checked_path(Path(args.project))
        leaked = sorted({str(p.relative_to(project)) for pat in SECRET_PATTERNS for p in project.rglob(pat)
                         if p.is_file() and not any(part in ('node_modules', '.git') for part in p.parts)})[:10]
        if leaked:
            add('project-secrets', 'warn', 'Key-like files inside the project are excluded from snapshots but '
                f'exposed to agents with --in-place: {leaked}. Prefer `secrets set` and delete project copies.')
        else:
            add('project-secrets', 'ok', 'No key-like files in the project')

    if args.probe_image and docker_ok:
        requested_policy(args)
        with admission_lock(args.lock_file, args.lock_wait_seconds):
            try:
                require_host(args)
                probed_image = probe_image(args, args.image)
                selected = admit_image(probed_image)
                caps = probed_image['capabilities']
                add('image-probe', 'ok', f'pi {caps.get("pi")}, node {caps.get("node")}, {caps.get("architecture")}')
                add('pi-release-contract', 'ok', selected['id'])
            except LabError as exc:
                add('image-probe', 'fail', str(exc)[:1000], exc.reason or 'image-missing', image=args.image)

    blockers = [c for c in checks if c['status'] == 'fail']
    report = {'status': 'BLOCKED' if blockers else 'READY', 'checks': checks,
              'scope': 'Prerequisite diagnostics; Pi release admission is observed only with --probe-image',
              'next_steps': [f'[{c["check"]}] {c["remedy"]}' for c in blockers if c.get('remedy')]}
    print(json.dumps(report, indent=2))
    if any(c.get('reason') == 'missing-secret' for c in blockers) and len(blockers) == 1:
        return EXIT_NEEDS_SECRET
    return 2 if blockers else 0


def cmd_secrets(args) -> int:
    store = getattr(args, 'secrets_dir', None)
    try:
        if args.secrets_op == 'set':
            if args.from_file:
                value = secret_store.clean_value(checked_path(Path(args.from_file)).read_text(encoding='utf-8'))
            elif args.stdin:
                value = secret_store.read_stdin_secret()
            else:
                value = secret_store.prompt_secret(args.name)
            path = secret_store.write_secret(args.name, value, store)
            print(json.dumps({'stored': args.name, 'path': str(path), 'mode': '0600',
                              'fingerprint': secret_store.fingerprint(value),
                              'note': 'Inference resolution prefers exported variables; application references use the store only.'}, indent=2))
            return 0
        if args.secrets_op == 'clear':
            removed = secret_store.delete_secret(args.name, store)
            print(json.dumps({'cleared': args.name, 'removed': removed}, indent=2))
            return 0
        names = list(args.names)
        if not names:
            path = Path(args.endpoint) if args.endpoint else lab_env.endpoint_path()
            names = [load_endpoint(checked_path(path))['api_key_env']] if path.exists() else ['PI_API_KEY']
        report = [secret_store.status(n, store) for n in names]
        print(json.dumps(report, indent=2))
        return 0 if all(r['active_source'] != 'missing' and r.get('store_ok') is not False for r in report) else EXIT_NEEDS_SECRET
    except secret_store.SecretError as exc:
        raise LabError(str(exc), 'missing-secret', remedy('missing-secret', name=getattr(args, 'name', 'KEY_NAME'))) from None
    return 0


def default_runs_dir() -> str:
    new_dir = Path.home() / '.local/state/pi-agent-test-env/runs'
    old_dir = Path.home() / '.local/state/pi-agentic-development/runs'
    if not new_dir.exists() and old_dir.exists():
        return str(old_dir)
    return str(new_dir)


def default_lock_file() -> str:
    new_lock = Path.home() / '.local/state/pi-agent-test-env/operation.lock'
    old_lock = Path.home() / '.local/state/pi-agentic-development/operation.lock'
    if not new_lock.parent.exists() and old_lock.parent.exists():
        return str(old_lock)
    return str(new_lock)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='op', required=True)
    pr_review_gate.add_arguments(sub.add_parser('pr-review-gate', help='Read-only parent GitHub review readiness; no Docker/model execution'))
    experiments.add_parser(sub)
    profile=sub.add_parser('validate-agent-profile');profile.add_argument('--agent-profile',required=True)
    validate = sub.add_parser('validate-plan')
    validate.add_argument('--plan', required=True)
    validate.add_argument('--agent-profile',help='Explicit reviewed custom-tool contract; validation does not load it')

    status_cmd = sub.add_parser('status', help='Inspect live or completed run status, heartbeat, and tool execution')
    status_cmd.add_argument('--run', help='Path to specific run directory (defaults to latest run in results-dir)')
    status_cmd.add_argument('--results-dir', default=default_runs_dir())
    status_cmd.add_argument('--stage', help='Stage UUID or unique label')

    extend_cmd = sub.add_parser('extend-budget', help='Dynamically extend turn, timeout, or token budgets for an active run')
    extend_cmd.add_argument('--run', help='Path to run directory (defaults to latest in results-dir)')
    extend_cmd.add_argument('--results-dir', default=default_runs_dir())
    extend_cmd.add_argument('--stage', help='Specific stage name (defaults to active stage)')
    extend_cmd.add_argument('--revision', type=int, help='Expected parent stage revision')
    extend_cmd.add_argument('--turns', help='Additional turns (e.g. +10) or new turn ceiling')
    extend_cmd.add_argument('--timeout', help='Additional timeout seconds (e.g. +300) or new timeout ceiling')
    extend_cmd.add_argument('--tokens', help='Additional token budget or new token ceiling')
    extend_cmd.add_argument('--budget-revision', type=int, help='Expected supervisor budget revision')
    extend_cmd.add_argument('--wait-seconds', type=float, default=0, help='Wait up to 10 seconds for supervisor application')

    steer_cmd = sub.add_parser('steer', help='Queue guidance for the next exact-session segment; optional parent interrupt')
    steer_cmd.add_argument('--run', help='Path to run directory (defaults to latest in results-dir)')
    steer_cmd.add_argument('--results-dir', default=default_runs_dir())
    steer_cmd.add_argument('--stage', help='Specific stage name (defaults to active stage)')
    steer_cmd.add_argument('--revision', type=int, help='Expected parent stage revision')
    steer_cmd.add_argument('--message', required=True, help='Steering prompt / directive to inject into the agent session')
    steer_cmd.add_argument('--interrupt', action='store_true', help='Request supervisor interruption and authorized linked continuation')

    patch_cmd = sub.add_parser('patch-session', help='Patch a prepared pending stage; active or uncertain writers are rejected')
    patch_cmd.add_argument('--run', help='Path to specific run directory (defaults to latest in results-dir)')
    patch_cmd.add_argument('--results-dir', default=default_runs_dir())
    patch_cmd.add_argument('--stage', help='Specific stage name (defaults to active stage)')
    patch_cmd.add_argument('--revision', type=int, help='Expected parent stage revision')
    patch_cmd.add_argument('--file', required=True, help='Path to source file on host to apply as patch')
    patch_cmd.add_argument('--target', help='Target path within workspace (defaults to relative path of --file or basename)')
    patch_cmd.add_argument('--message', help='Unsupported for pending-stage patching; explicitly rejected')
    patch_cmd.add_argument('--interrupt', action='store_true', help='Unsupported for pending-stage patching; explicitly rejected')

    sec_cmd = sub.add_parser('secrets', help='Manage inference/application keys in the host-side owner-only secret store')
    sec_sub = sec_cmd.add_subparsers(dest='secrets_op', required=True)
    sec_set = sec_sub.add_parser('set', help='Store a key with hidden terminal input (or --stdin / --from-file)')
    sec_set.add_argument('name', nargs='?', default='PI_API_KEY', help='Named host-store entry (default inference key: PI_API_KEY)')
    sec_set.add_argument('--stdin', action='store_true', help='Read secret from stdin (e.g. piped from password manager)')
    sec_set.add_argument('--from-file', help='Read secret from an existing local file')
    sec_set.add_argument('--secrets-dir', help='Override secrets store directory')
    sec_clear = sec_sub.add_parser('clear', help='Remove a stored key')
    sec_clear.add_argument('name', nargs='?', default='PI_API_KEY', help='Named host-store entry (default inference key: PI_API_KEY)')
    sec_clear.add_argument('--secrets-dir')
    sec_status = sec_sub.add_parser('status', help='Show fingerprint and source (never the secret itself)')
    sec_status.add_argument('names', nargs='*', help='Key names (defaults to key named in endpoint file, or PI_API_KEY)')
    sec_status.add_argument('--endpoint')
    sec_status.add_argument('--secrets-dir')

    lab_env.add_parser(sub)

    doc = sub.add_parser('doctor', help='Check every prerequisite and report all blockers at once with concrete remedies')
    doc.add_argument('--image', default=DEFAULT_IMAGE)
    doc.add_argument('--endpoint', help='Endpoint JSON (defaults to the saved environment)')
    doc.add_argument('--session', help='Agent session id, to report the confirmation state')
    doc.add_argument('--project', help='Project directory to check for leaked secrets')
    doc.add_argument('--secrets-dir', help='Override secrets store directory')
    doc.add_argument('--skip-network', action='store_true', help='Skip host /models network probe')
    doc.add_argument('--probe-image', action='store_true', help='Run full container capability probe (requires Docker)')
    doc.add_argument('--lock-file', default=default_lock_file())
    doc.add_argument('--lock-wait-seconds', type=int, default=0)
    doc.add_argument('--platform', choices=['linux/arm64', 'linux/amd64'])
    doc.add_argument('--profile', choices=['core', 'browser'], default='core')
    doc.add_argument('--browser-sandbox-policy', choices=browser_security.POLICIES, default='docker-default')
    doc.add_argument('--environment')
    doc.add_argument('--resources')
    doc.add_argument('--memory')
    doc.add_argument('--cpus', type=float)
    doc.add_argument('--pids-limit', type=int)
    doc.add_argument('--jobs', type=int)
    doc.add_argument('--allow-browser-no-sandbox', action='store_true')
    doc.add_argument('--software-webgl', action='store_true')
    doc.add_argument('--uid', type=int, default=os.getuid() if hasattr(os, 'getuid') else 1000)
    doc.add_argument('--gid', type=int, default=os.getgid() if hasattr(os, 'getgid') else 1000)

    for name in ('ensure-image', 'preflight', 'smoke', 'run', 'browser-check'):
        q = sub.add_parser(name)
        q.add_argument('--image', default=DEFAULT_IMAGE, required=name=='browser-check')
        q.add_argument('--profile', choices=['core', 'browser'], default='browser' if name=='browser-check' else 'core')
        q.add_argument('--browser-sandbox-policy', choices=browser_security.POLICIES, default='docker-default',
                       help='Explicit browser container policy; chromium-userns retains Chromium namespace/seccomp sandboxing')
        q.add_argument('--environment', help='Reviewed JSON file with additional image commands/version probes')
        q.add_argument('--host-gateway', action='store_true', help='Map host.docker.internal to host-gateway for local Linux Docker')
        q.add_argument('--platform', choices=['linux/arm64', 'linux/amd64'])
        q.add_argument('--uid', type=int, default=os.getuid() if hasattr(os, 'getuid') else 1000)
        q.add_argument('--gid', type=int, default=os.getgid() if hasattr(os, 'getgid') else 1000)
        q.add_argument('--resources', help='Resource policy JSON; defaults: 2 CPUs, 4 GiB, 256 PIDs, 2 jobs; auto-capped to half of Docker allocation')
        q.add_argument('--memory', help='Override runtime hard memory cap, e.g. 4g; swap is disabled')
        q.add_argument('--cpus', type=float, help='Override runtime CPU-equivalent ceiling (not CPU percent)')
        q.add_argument('--pids-limit', type=int, help='Runtime maximum number of tasks/threads')
        q.add_argument('--jobs', type=int, help='Advisory build/test thread limit, within the CPU budget')
        q.add_argument('--lock-file', default=default_lock_file())
        q.add_argument('--lock-wait-seconds', type=int, default=0, help='Wait for a cooperating run; default fails busy rather than stacking containers')
        q.add_argument('--allow-browser-no-sandbox', action='store_true',
                       help='Explicit opt-in for trusted local pages only; never auto-enabled')
        q.add_argument('--software-webgl', action='store_true',
                       help='Explicit opt-in to unsafe SwiftShader software rendering for trusted tests')
        if name == 'browser-check':
            q.add_argument('--results-dir', default=default_runs_dir())
        if name == 'ensure-image':
            q.add_argument('--policy', choices=['auto', 'reuse', 'build'], default='auto')
            q.add_argument('--reuse', action='append', default=[], metavar='TRUSTED_IMAGE')
            q.add_argument('--pi-version', default=DEFAULT_VERSION)
            q.add_argument('--base-image', default='node:24-bookworm-slim')
            q.add_argument('--apt-package', action='append', default=[])
            q.add_argument('--receipt')
            q.add_argument('--dockerfile', help='Reviewed custom environment Dockerfile; must honor PI_VERSION and supply baseline tools')
            q.add_argument('--build-context', help='Dedicated trusted environment-only build context; defaults to Dockerfile directory')
            q.add_argument('--build-cpus', type=float, help='CPU ceiling for the dedicated BuildKit container')
            q.add_argument('--build-memory', help='Memory ceiling for BuildKit; swap disabled')
            q.add_argument('--build-parallelism', type=int, help='Maximum parallel BuildKit steps')
            q.add_argument('--build-timeout', type=int, help='Image-build wall-time budget in seconds')
            q.add_argument('--buildkit-image', default='moby/buildkit:buildx-stable-1', help='Trusted BuildKit image; use a digest for reproducibility')
        if name in ('run', 'smoke', 'preflight'):
            q.add_argument('--endpoint', help='Explicit endpoint JSON; default is the saved, session-confirmed environment')
            q.add_argument('--session', help='Agent session id (or PI_LAB_SESSION) for the saved-environment gate')
            q.add_argument('--network', default='bridge')
            q.add_argument('--results-dir', default=default_runs_dir())
            q.add_argument('--secrets-dir', help='Override secrets store directory')
            q.add_argument('--prompt-secret', action='store_true', help='Prompt interactively on terminal if the inference key is missing')
        if name in ('run', 'smoke'):
            q.add_argument('--agent-profile',help='Explicit reviewed integration profile; defaults to empty built-in baseline')
            q.add_argument('--event-contract', choices=['settled', 'process-exit'], default='settled',
                           help='Default requires agent_settled; process-exit is explicit legacy Pi JSON one-shot compatibility')
            q.add_argument('--project')
            q.add_argument('--plan')
            q.add_argument('--in-place', action='store_true')
            q.add_argument('--exclude', action='append', default=[])
            q.add_argument('--max-project-mb', type=int, default=2048)
            q.add_argument('--allow-setup-network', action='store_true')
            q.add_argument('--allow-check-network', action='store_true')
            q.add_argument('--score-after-cancel', action='store_true', help='Explicitly authorize independent scoring after cancellation before any scorer starts')
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    if args.op == 'pr-review-gate':return pr_review_gate.command(args)
    if args.op in ('validate-experiment','experiment-prepare','experiment-run','experiment-resume','experiment-export','experiment-report'):return experiments.command(args,sys.modules[__name__])
    if args.op=='validate-agent-profile':
        profile=agent_profiles.load(args.agent_profile);print(json.dumps({'valid':True,'profile_id':profile['id'],'sha256':agent_profiles.identity(profile)}));return 0
    if args.op == 'validate-plan':
        path = checked_path(Path(args.plan))
        profile=agent_profiles.load(args.agent_profile) if args.agent_profile else agent_profiles.builtin()
        plan = validate_plan(json.loads(path.read_text()), path.parent,profile)
        print(json.dumps({'valid': True, 'name': plan['name'], 'agents': len(plan['agents']),
                          'checks': len(plan['checks']), 'setup': len(plan['setup'])}, indent=2))
        return 0
    if args.op == 'status':
        return cmd_status(args)
    if args.op == 'extend-budget':
        return cmd_extend_budget(args)
    if args.op == 'steer':
        return cmd_steer(args)
    if args.op == 'patch-session':
        return cmd_patch_session(args)
    if args.op == 'secrets':
        return cmd_secrets(args)
    if args.op == 'doctor':
        return cmd_doctor(args)
    if args.op == 'env':
        return lab_env.run(args, lambda path: load_endpoint(checked_path(path)))
    if args.op in ('run','smoke'):
        return run_suite(args,smoke=args.op=='smoke')
    requested_policy(args)  # Validate budgets before any Docker action.
    with admission_lock(args.lock_file, args.lock_wait_seconds):
        return dispatch(args)


def browser_check(args):
    """Independent, credential-free browser admission; no model environment required."""
    if args.profile != 'browser':
        raise LabError('browser-check requires the browser profile', 'browser-policy-invalid')
    if args.allow_browser_no_sandbox:
        raise LabError('browser-check requires verified sandboxing; the opt-out is available only for separate trusted browser runs', 'browser-policy-invalid')
    host = require_host(args)
    if not host.get('daemon_architecture') or args.platform != getattr(args, 'native_platform', None):
        raise LabError('browser-check requires the Docker daemon native platform; emulation cannot qualify native admission', 'browser-policy-invalid')
    root = checked_path(Path(args.results_dir)) / ('browser-' + uuid.uuid4().hex)
    root.mkdir(parents=True, mode=0o700)
    args._attempt_root = root
    args._attempt_identity = {'run_id': str(uuid.uuid4()), 'attempt_id': str(uuid.uuid4())}
    save(root / 'identity.json', {'schema': 2, **args._attempt_identity})
    report = {'schema': 1, 'document_type': 'browser_admission', 'status': 'BLOCKED',
              'image_reference': args.image, 'host': host, 'evidence': str(root),
              'credentials_supplied': False, 'pi_participant_invocations': 0,
              'scope': 'Browser DOM/JavaScript and sandbox admission only; no application or model qualification'}
    save(root / 'browser-admission.json', report)
    try:
        args.frozen_browser_security = browser_security.freeze(args, root / 'browser-security')
        report['browser_security'] = args.frozen_browser_security
        image = probe_image(args, args.image); report['image'] = image
        report['provenance'] = provenance.execution({}, image, ROOT)
        workspace = root / 'workspace'; workspace.mkdir()
        args.network = 'none'
        process = run_stage(args, image['id'], root, workspace, 'browser',
                            ['browser'] + (['--webgl'] if args.software_webgl else []), network='none', timeout=90)
        report['process'] = process
        stdout = root / 'browser' / 'stdout.jsonl'
        observations = [json.loads(line) for line in stdout.read_text().splitlines() if line.strip()]
        report['observations'] = observations
        dom = [row for row in observations if isinstance(row, dict) and row.get('browser_dom_ok') is True]
        sandbox = [row.get('browser_sandbox', {}) for row in observations if isinstance(row, dict) and 'browser_sandbox' in row]
        passed = (process.get('exit_code') == 0 and process.get('cleanup_confirmed') is True and len(dom) == 1
                  and dom[0].get('no_browser_sandbox') is False
                  and (not args.software_webgl or dom[0].get('webgl_ok') is True)
                  and len(sandbox) == 1 and sandbox[0].get('namespace_and_seccomp_verified') is True)
        report['status'] = 'PASS' if passed else 'BLOCKED'
        if not passed:
            detail = (root / 'browser/stderr.log').read_text(errors='replace')
            report['reason'] = 'browser-sandbox-blocked' if any(s in detail for s in ('namespace', 'sys_chroot', 'No usable sandbox')) else 'browser-admission-failed'
            if report['reason'] == 'browser-sandbox-blocked':report['remedy'] = remedy(report['reason'])
    except KeyboardInterrupt:
        report['reason'] = 'cancelled'
        raise
    except (OSError, ValueError, LabError, controls.ControlError) as exc:
        report['reason'] = getattr(exc, 'reason', '') or 'browser-admission-failed'
        report['error_type'] = type(exc).__name__
    finally:
        save(root / 'browser-admission.json', report)
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'PASS' else 2


def dispatch(args):
    if args.op == 'browser-check':
        return browser_check(args)
    if args.op == 'ensure-image':
        print(json.dumps(ensure_image(args), indent=2))
        return 0
    if args.op == 'preflight':
        return preflight_only(args)
    return run_suite(args, smoke=args.op == 'smoke')


def _interrupt(signum, frame):
    raise KeyboardInterrupt


def cli_failure(exc):
    diagnostic = admission_diagnostic(exc)
    if diagnostic is not None:
        print(json.dumps({'schema':1,'document_type':'admission_failure','status':'BLOCKED','exit_code':2,
                          'infrastructure':{**diagnostic,'error_digest':hashlib.sha256(str(exc).encode()).hexdigest()}}),
              file=sys.stderr)
        return 2
    reason = getattr(exc, 'reason', '')
    tag = f' [{reason}]' if reason else ''
    print(f'BLOCKED{tag}: {exc}', file=sys.stderr)
    remedy_text = getattr(exc, 'remedy', '')
    if remedy_text:
        print(f'Remedy: {remedy_text}', file=sys.stderr)
    return EXIT_NEEDS_SECRET if reason == 'missing-secret' else 2


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, _interrupt)
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('INTERRUPTED', file=sys.stderr)
        sys.exit(130)
    except (LabError, controls.ControlError, ValueError, OSError) as exc:
        sys.exit(cli_failure(exc))
