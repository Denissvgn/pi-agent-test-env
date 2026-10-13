#!/usr/bin/env python3
"""Freeze and collect the serial native ARM64 Pi migration qualification.

This maintainer tool owns only its named services and evidence directory. It
invokes the existing runner; it neither merges nor publishes, and never treats
scripted inference as real-model acceptance. See --help for separate gates.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SKILL = REPO / 'skill'
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(SKILL / 'scripts'))
sys.path.insert(0, str(SKILL / 'runtime'))
import fixtures
import pi_lab as lab
import release_contracts
import secret_store
import provenance
import experiments
import application_credentials

BASE = 'node@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20'
BUILDKIT = 'moby/buildkit@sha256:cec9f139f45e93c5c69c60f8b07cfad9f43f4ef6b6a6cd917527fea5ff2e3dea'
REAL = ('N04', 'N05', 'N06', 'N07', 'N08')


def atomic(path, value, mode=0o600):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix('.pending')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, 'w') as stream: json.dump(value, stream, indent=2); stream.write('\n')
    temp.replace(path)


def read(path):
    return json.loads(Path(path).read_text())


def command(argv, timeout=120, required=True):
    result = subprocess.run(argv, text=True, capture_output=True, timeout=timeout)
    if required and result.returncode:
        raise RuntimeError('Command failed: '+argv[0]+' '+str(result.returncode)+' '+result.stderr[-1500:])
    return result


def native(image=None):
    info = json.loads(command(['docker', 'info', '--format', '{{json .}}']).stdout)
    if info['OSType'] != 'linux' or lab.norm_arch(info['Architecture']) != 'arm64':
        raise RuntimeError('Qualification requires an observed native Linux ARM64 daemon')
    if image:
        data = json.loads(command(['docker', 'image', 'inspect', image]).stdout)[0]
        if data['Os'] != 'linux' or lab.norm_arch(data['Architecture']) != 'arm64':
            raise RuntimeError('Image architecture is not native ARM64')
        return data['Id']
    return {k: info.get(k) for k in ('OSType', 'Architecture', 'ServerVersion', 'KernelVersion', 'NCPU', 'MemTotal')}


def cells():
    values = []
    for release in release_contracts.RELEASES:
        for mode in ('settings', 'length', 'error', 'abort'):
            values.append({'id': f'N03-{release}-{mode}', 'gate': 'N03', 'release': release,
                           'kind': mode, 'real_model': False, 'segments_max': 5 if mode == 'settings' else 1})
    for gate, kind, maximum in (('N04', 'smoke', 1), ('N05', 'coding', 2), ('N06', 'fixture', 1),
                                ('N07', 'credentials', 3), ('N08', 'browser', 1)):
        for release in release_contracts.RELEASES:
            for repetition in range(1, 4):
                for variant in (('builtin', 'fixture') if gate == 'N06' else ('primary',)):
                    values.append({'id': f'{gate}-{release}-{repetition}-{variant}', 'gate': gate,
                        'release': release, 'kind': kind, 'variant': variant,
                        'repetition': repetition, 'real_model': True, 'segments_max': maximum})
    for release in release_contracts.RELEASES:
        for index, kind in enumerate(('abort', 'timeout', 'recovery', 'crash', 'discovery',
                                     'boundary', 'contamination', 'provider-fatal'), 1):
            values.append({'id': f'F{index:02}-{release}', 'gate': 'N09', 'release': release,
                           'kind': kind, 'real_model': False,
                           'segments_max': 2 if kind in ('recovery', 'crash') else 1})
    return values


def source_identity():
    root = provenance.execution({}, {},SKILL)
    files = {str(p.relative_to(REPO)): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(HERE.glob('*.py'))}
    inputs = {}
    for relative in ('assets', 'docker', 'examples'):
        for path in sorted((SKILL/relative).rglob('*')):
            if '__pycache__' in path.parts or not path.is_file(): continue
            if path.is_symlink(): raise ValueError('Linked qualification input rejected')
            inputs[str(path.relative_to(SKILL))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {'runner': root['runner_content_sha256'], 'contracts': release_contracts.snapshot(),
            'harness_files': files, 'harness_sha256': provenance.digest(files),
            'input_files': inputs, 'input_sha256': provenance.digest(inputs)}


def reuse_admitted_images(prior, source):
    if prior is None: return {}
    prior = Path(prior).resolve(); manifest = read(prior/'manifest.json'); state = read(prior/'state.json')
    if read(prior/'integrity.json').get('manifest_sha256') != hashlib.sha256((prior/'manifest.json').read_bytes()).hexdigest():
        raise ValueError('Prior image source manifest changed')
    if (state['phase'] not in ('images_admitted','qualified')
            or any(manifest['source'].get(k) != source[k] for k in ('runner','contracts','input_sha256'))
            or any(manifest.get(k) != value for k,value in (('base',BASE),('buildkit',BUILDKIT),('platform','linux/arm64')))):
        raise ValueError('Prior images have a different or incomplete runtime/input admission scope')
    expected = {profile+'-'+release for release in release_contracts.RELEASES for profile in ('core','browser')}
    if not isinstance(state.get('images'),dict) or set(state['images']) != expected:
        raise ValueError('Prior image admissions are incomplete')
    selected = {}
    for release in release_contracts.RELEASES:
        for profile in ('core','browser'):
            key = profile+'-'+release; image = state['images'][key]
            if not isinstance(image,dict) or not isinstance(image.get('id'),str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', image['id']):
                raise ValueError('Image reuse requires an immutable image ID')
            lab.admit_image(image, release)
            selected[key] = image['id']
    return selected


def freeze(root, session, reuse_images_from=None):
    root = Path(root).resolve()
    if root.exists(): raise ValueError('Qualification output must be new')
    endpoint = lab.load_endpoint(lab.resolve_endpoint_path(argparse.Namespace(endpoint=None, session=session)))
    model_fields = {k: v for k, v in endpoint.items() if k != 'api_key_env'}
    values = cells()
    source = source_identity()
    reusable_images = reuse_admitted_images(reuse_images_from, source)
    assert len(values) == 60 and sum(c['segments_max'] for c in values) == 90
    root.mkdir(parents=True, mode=0o700)
    atomic(root / 'manifest.json', {'schema': 1, 'kind': 'native_arm64_qualification',
        'qualification_id': str(uuid.uuid4()), 'created_at': lab.now(), 'source': source,
        'reusable_images': reusable_images,
        'endpoint_sha256': provenance.digest(model_fields), 'model': endpoint['model'],
        'context_window': endpoint['context_window'], 'max_tokens': endpoint['max_tokens'],
        'model_server_budget': {'origin': 'user_selected_existing_deployment', 'limits': 'unknown',
                                'deployment_changed': False},
        'base': BASE, 'buildkit': BUILDKIT, 'platform': 'linux/arm64',
        'cells': values, 'participant_segments_ceiling': 96,
        'build_seconds_ceiling': 10800, 'execution_seconds_ceiling': 14400,
        'automatic_retries': 0, 'scope': 'Scripted protocol/faults and real-model gates remain distinct'})
    atomic(root/'integrity.json', {'manifest_sha256': hashlib.sha256((root/'manifest.json').read_bytes()).hexdigest()})
    atomic(root / 'state.json', {'schema': 1, 'phase': 'frozen', 'images': {}, 'cells': [], 'attempted_cells': [],
                               'participant_segments': 0, 'started_at': None})
    return root


def verify(root):
    manifest = read(root / 'manifest.json')
    if read(root/'integrity.json').get('manifest_sha256') != hashlib.sha256((root/'manifest.json').read_bytes()).hexdigest():
        raise ValueError('Frozen qualification manifest changed')
    if (manifest.get('cells') != cells() or manifest.get('participant_segments_ceiling') != 96
            or manifest.get('build_seconds_ceiling') != 10800
            or manifest.get('execution_seconds_ceiling') != 14400
            or manifest.get('automatic_retries') != 0 or manifest.get('platform') != 'linux/arm64'
            or manifest.get('base') != BASE or manifest.get('buildkit') != BUILDKIT):
        raise ValueError('Qualification matrix or fixed limits differ from the reviewed plan')
    if manifest['source'] != source_identity():
        raise ValueError('Runner/contracts/harness changed; freeze a new qualification, never relabel old cells')
    reusable = manifest.get('reusable_images', {})
    expected_images = {profile+'-'+release for release in release_contracts.RELEASES for profile in ('core','browser')}
    if (not isinstance(reusable,dict) or reusable and set(reusable) != expected_images
            or any(not isinstance(value,str) or not re.fullmatch(r'sha256:[a-f0-9]{64}',value) for value in reusable.values())):
        raise ValueError('Frozen image reuse identities are incomplete or mutable')
    return manifest, read(root / 'state.json')


def invoke(root, label, arguments, *, timeout=800, control=None):
    folder = root / 'commands' / label; folder.mkdir(parents=True, exist_ok=False)
    argv = [sys.executable, str(SKILL / 'scripts/pi_lab.py'), *arguments]
    atomic(folder / 'intent.json', {'argv': argv, 'started_at': lab.now()})
    with (folder / 'stdout.json').open('w') as out, (folder / 'stderr.log').open('w') as err:
        process = subprocess.Popen(argv, stdout=out, stderr=err, start_new_session=True,
                                   env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        start = time.monotonic()
        action = None
        try:
            while process.poll() is None:
                if control and action is None: action = control(process)
                if time.monotonic() - start > timeout:
                    process.send_signal(signal.SIGINT); process.wait(timeout=30)
                    raise TimeoutError('Qualification command deadline exceeded')
                time.sleep(.1)
        except BaseException:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                try: process.wait(timeout=30)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
            raise
    result = {'exit_code': process.returncode, 'elapsed_seconds': time.monotonic()-start,
              'action': action, 'command_dir': str(folder)}
    atomic(folder / 'process.json', result)
    return result


def images(root, session):
    manifest, state = verify(root)
    if state['phase'] != 'frozen': raise ValueError('Image gate cannot repeat existing collection')
    state['host'] = native(); start = time.monotonic()
    for source in (BASE, BUILDKIT): native(source)
    for release in release_contracts.RELEASES:
        for profile in ('core', 'browser'):
            if time.monotonic() - start >= manifest['build_seconds_ceiling']: raise TimeoutError('Image-preparation ceiling reached')
            tag = f'pi-migration:{profile}-{release}-arm64-'+manifest['qualification_id'][:8]
            reusable = manifest.get('reusable_images', {}).get(profile+'-'+release)
            receipt = root / 'images' / f'{profile}-{release}.json'
            args = ['ensure-image', '--image', reusable or tag, '--profile', profile, '--policy', 'reuse' if reusable else 'build',
                '--pi-version', release, '--platform', 'linux/arm64', '--base-image', BASE,
                '--buildkit-image', BUILDKIT, '--resources', str(SKILL/'assets/resources/low-impact.json'),
                '--build-cpus', '1', '--build-memory', '2g', '--build-parallelism', '1',
                '--build-timeout', '2400', '--receipt', str(receipt)]
            if profile == 'browser': args += ['--browser-sandbox-policy', 'chromium-userns']
            result = invoke(root, f'N01-{profile}-{release}', args, timeout=2550)
            if result['exit_code']: raise RuntimeError('Image admission failed; dependent gates blocked')
            observed = read(receipt); native(observed['id'])
            if reusable and observed['id'] != reusable: raise RuntimeError('Reused image differs from the frozen immutable ID')
            lab.admit_image(observed, release)
            state['images'][profile+'-'+release] = observed
            atomic(root/'state.json', state)
    for release in release_contracts.RELEASES:
        result = invoke(root, 'N02-'+release, ['browser-check', '--image', state['images']['browser-'+release]['id'],
            '--platform', 'linux/arm64', '--browser-sandbox-policy', 'chromium-userns',
            '--resources', str(SKILL/'assets/resources/browser.json'), '--cpus', '2', '--memory', '2g',
            '--pids-limit', '512', '--jobs', '1', '--results-dir', str(root/'browser-admission')], timeout=240)
        if result['exit_code']: raise RuntimeError('Sandboxed browser admission failed')
    state['phase'] = 'images_admitted'; atomic(root/'state.json', state)


class Services:
    def __init__(self, root, image, real_endpoint):
        self.root = root; self.image = native(image)
        self.private = Path(tempfile.mkdtemp(prefix='pi-qualification-private-'))
        self.control_dir = self.private/'control'; self.control_dir.mkdir(mode=0o700)
        self.store = self.private/'store'; self.store.mkdir(mode=0o700)
        self.inference = secrets.token_hex(32); self.observer = secrets.token_hex(32)
        secret_store.write_secret('QUALIFICATION_INFERENCE', self.inference, self.store)
        key, _ = secret_store.resolve_secret(real_endpoint['api_key_env'])
        if not key: raise ValueError('Confirmed model key is unavailable')
        secret_store.write_secret(real_endpoint['api_key_env'], key, self.store)
        self.network = 'pi-qualification-'+uuid.uuid4().hex[:10]
        self.name = self.network+'-authority'; self.config = None
        self.observations = root/'service-observations'; self.observations.mkdir()

    def configure(self, mode, nonce):
        self.references = {'A': 'QUALIFICATION_APP_A', 'B': 'QUALIFICATION_APP_B'}
        self.app = {'A': 'QA_quoted"slash\\'+secrets.token_hex(24), 'B': 'QB_'+secrets.token_hex(24)}
        for role in self.references: secret_store.write_secret(self.references[role], self.app[role], self.store)
        self.config = {'mode': mode, 'nonce': nonce, 'app_keys': self.app,
                       'inference_key': self.inference, 'observer_key': self.observer}
        atomic(self.control_dir/'control.json', self.config)

    def mode(self, value):
        self.config['mode'] = value; atomic(self.control_dir/'control.json', self.config)

    def start(self):
        command(['docker', 'network', 'create', '--label', 'org.pi-qualification.owned=true', self.network])
        self.configure('settings', uuid.uuid4().hex)
        argv = ['docker', 'run', '--detach', '--name', self.name, '--platform', 'linux/arm64',
            '--label', 'org.pi-qualification.owned=true', '--network', self.network,
            '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--ipc=none',
            '--cpus', '.25', '--memory', '128m', '--memory-swap', '128m', '--pids-limit', '64',
            '--user', f'{os.getuid()}:{os.getgid()}', '--env', 'PYTHONDONTWRITEBYTECODE=1',
            '--publish', '127.0.0.1::8080', '--mount', f'type=bind,src={self.control_dir},dst=/private,readonly',
            '--mount', f'type=bind,src={self.observations},dst=/observations',
            '--mount', f'type=bind,src={HERE},dst=/qualification,readonly', '--entrypoint', 'python3',
            self.image, '/qualification/service.py', '--control', '/private/control.json',
            '--observations', '/observations/observations.json']
        command(argv)
        port = command(['docker', 'port', self.name, '8080/tcp']).stdout.strip().rsplit(':', 1)[1]
        self.host = 'http://127.0.0.1:'+port
        self.child = 'http://'+self.name+':8080'
        for _ in range(100):
            try: self.snapshot(); return
            except OSError: time.sleep(.1)
        raise RuntimeError('Owned diagnostic service did not become ready')

    def request(self, path, body=None):
        req = urllib.request.Request(self.host+path, data=json.dumps(body).encode() if body is not None else None,
            headers={'X-Qualification-Observer': self.observer, 'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=3) as response: return json.load(response)

    def snapshot(self): return self.request('/observer')
    def reset(self): return self.request('/reset', {})

    def close(self):
        import shutil
        deadline = time.monotonic() + 30
        def cleanup(argv):
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise TimeoutError('Owned service cleanup deadline reached')
            return command(argv, timeout=min(10, remaining), required=False)
        cleanup(['docker', 'rm', '--force', self.name])
        absent = cleanup(['docker', 'container', 'inspect', self.name])
        if absent.returncode == 0 or 'No such container' not in absent.stderr:
            raise RuntimeError('Authority container cleanup unconfirmed; private state retained')
        cleanup(['docker', 'network', 'rm', self.network])
        network = cleanup(['docker', 'network', 'inspect', self.network])
        if network.returncode == 0 or not any(text in network.stderr for text in ('No such network', 'not found')):
            raise RuntimeError('Authority network cleanup unconfirmed; private state retained')
        shutil.rmtree(self.private)
        atomic(self.root/'service-cleanup.json', {'container': self.name, 'confirmed_absent': True,
            'network': self.network, 'network_confirmed_absent': True,
            'private_store_removed': True, 'original_model_store_unchanged': True})


def run_roots(parent):
    # The runner also creates a convenience `latest` symlink. It is an alias,
    # never a second owned run or a path for controls/segment accounting.
    return [path for path in sorted(parent.glob('*'))
            if path.is_dir() and not path.is_symlink()]


def registered_segments(root):
    parents = list((root/'cells').glob('*/runs')) + list((root/'cells').glob('*/experiment/runs'))
    return sum(len(list((run/'stages').glob('*/segments/*.json')))
               for parent in parents for run in run_roots(parent))


def run_result(folder):
    values = [run/'result.json' for run in run_roots(folder/'runs') if (run/'result.json').is_file()]
    if len(values) != 1: raise RuntimeError('Expected exactly one sealed run result')
    return values[0].parent, read(values[0])


def active_run(folder):
    roots = run_roots(folder/'runs')
    for root in roots:
        descriptors = list((root/'stages').glob('*/descriptor.json'))
        for path in reversed(descriptors):
            descriptor = read(path)
            try:
                stage = read(path.parent/'state.json')
            except FileNotFoundError:
                # Creation publishes the descriptor before initial state. The
                # next bounded control poll will observe the completed pair.
                continue
            if descriptor['kind'] == 'agent' and stage['status'] == 'running': return root, descriptor
    return None, None


def checker_env(extra=None):
    result = {k: v for k, v in os.environ.items() if not k.startswith('PI_APP_') and k != 'PI_LAB_API_KEY'}
    result['PYTHONDONTWRITEBYTECODE'] = '1'
    result.update(extra or {})
    return result


def sensitive_clean(run, values):
    """Only assigned raw runtimes must be purged; an unassigned stage stays key-free."""
    pool = application_credentials.Redactor(values)
    for path in run.rglob('*'):
        if path.is_symlink(): raise RuntimeError('Linked public evidence cannot be inspected safely')
        if path.is_file() and path.stat().st_nlink != 1:
            raise RuntimeError('Multiply linked public evidence cannot be inspected safely')
        if path.is_file() and pool.contains(path.read_bytes()):
            raise RuntimeError('Application canary retained in public run evidence')
    for receipt in (run/'stages').glob('*/application-credentials.json'):
        value = read(receipt)
        if value.get('status') != 'removed': raise RuntimeError('Sensitive cleanup receipt is incomplete')
        desc = read(receipt.parent/'descriptor.json')
        runtimes = [Path(desc['runtime'])]
        for meta in (receipt.parent/'segments').glob('*.json'):
            runtimes.append(Path(read(meta)['runtime']))
        if any(path.exists() for path in runtimes): raise RuntimeError('Assigned raw runtime retained after cleanup')
        if list(Path(desc['control']).glob('**/session.jsonl')):
            raise RuntimeError('Assigned resume-session copy retained after cleanup')


def crash_integrity(runs, values):
    count = sum(len(list((run/'stages').glob('*/segments/*.json'))) for run in runs)
    if count != 2: raise RuntimeError('Crash cell lacks its two registered process segments')
    for run in runs: sensitive_clean(run, values)
    return count


def validate_cell_execution(mode, result, invocation, observed, count, expected_count, stopped_processes=None):
    codes = {'PASS':0,'FAIL':1,'BLOCKED':2,'INTERRUPTED':2,'RECOVERED':1}
    if result['exit_code'] != codes[result['status']] or invocation['exit_code'] != result['exit_code']:
        raise RuntimeError('Sealed outcome and controller exit disagree')
    if count != expected_count: raise RuntimeError('Cell registered segment count differs from the frozen maximum')
    processes = stopped_processes if stopped_processes is not None else [agent['process'] for agent in result['agents']]
    if not processes or any(process.get('cleanup_confirmed') is not True for process in processes):
        raise RuntimeError('Participant cleanup was not independently confirmed')
    failures = [failure for process in processes for segment in process.get('segments', [])
                for failure in segment.get('evidence', {}).get('unsuccessful_messages', [])]
    if mode in ('length','error','provider-fatal'):
        required = 'length' if mode == 'length' else 'error'
        if required not in failures: raise RuntimeError('Expected unsuccessful assistant cause was not observed')
    if mode == 'timeout' and not all(process.get('timed_out') is True and process.get('exit_code') == 124
            and process.get('termination_reason') == 'timeout' for process in processes):
        raise RuntimeError('Deadline oracle requires actual timeout cause, not another failure')
    if mode == 'abort' and (invocation.get('action') != 'parent_cancelled_before_first_assistant'
            or result['scoring']['status'] not in ('skipped','cancelled')
            or any(process.get('cancelled') is not True or process.get('termination_reason') != 'cancelled' for process in processes)):
        raise RuntimeError('Cancellation oracle lacks parent cancellation or suppressed scoring')
    if mode == 'provider-fatal' and invocation.get('action') != 'fatal_provider_released':
        raise RuntimeError('Provider-fatal oracle lacks the controlled fatal response')
    if mode == 'recovery' and observed.get('applied_interrupt') is not True:
        raise RuntimeError('Recovery oracle lacks independently applied parent interrupt')
    if mode == 'boundary' and (not observed.get('protected_before')
            or observed.get('protected_before') != observed.get('protected_after')):
        raise RuntimeError('Boundary oracle lacks unchanged protected hashes')
    if mode == 'contamination' and Path(result['workspace']).exists():
        raise RuntimeError('Contamination oracle requires discarded shared workspace')


def validate_crash_execution(first, successor, abandoned):
    if (first.get('exit_code') != -signal.SIGKILL
            or first.get('action') != 'owner_controller_killed_after_persisted_tool_round'
            or successor.get('exit_code') != 0
            or abandoned.get('controller_interruption', {}).get('kind') != 'controller_lost'
            or abandoned['controller_interruption'].get('cleanup_confirmed') is not True):
        raise RuntimeError('Crash oracle requires actual owner kill and independently reconciled controller loss')


def validate_contamination_execution(run, project, result):
    """Post-start policy failure is FAIL; physical cleanup has a separate receipt."""
    agents = result.get('agents', [])
    descriptors = [read(path) for path in (run/'stages').glob('*/descriptor.json')]
    assigned = [desc for desc in descriptors if desc['kind'] == 'agent']
    if (result.get('status') != 'FAIL' or len(agents) != 1 or len(assigned) != 1
            or assigned[0].get('label') != 'agent-1-diagnostic'
            or result.get('scoring', {}).get('status') != 'skipped'
            or result.get('scoring', {}).get('reason') != 'cleanup_unconfirmed'
            or result.get('checks') or any(desc.get('label', '').startswith('check-') for desc in descriptors)):
        raise RuntimeError('Contamination oracle requires the policy failure and no successor/scorer')
    process = agents[0]['process']
    if (process.get('cleanup_confirmed') is not False
            or process.get('termination_reason') != 'application_credential_cleanup'
            or process.get('application_credentials') != {'schema':1,'status':'removed','workspace':'discarded'}
            or Path(result['workspace']) != run/'workspace' or Path(result['workspace']).exists()
            or lab.tree_hashes(project) != read(run/'files-before.json')):
        raise RuntimeError('Contamination oracle requires discarded owned snapshot and unchanged source')
    receipt = read(run/'stages'/assigned[0]['stage_id']/'application-credentials.json')
    if receipt.get('status') != 'removed' or receipt.get('workspace') != 'discarded':
        raise RuntimeError('Contamination oracle lacks independent sensitive cleanup receipt')
    metas = list((run/'stages').glob('*/segments/*.json'))
    if len(metas) != 1: raise RuntimeError('Contamination oracle requires one registered segment')
    logs = Path(read(metas[0])['logs'])
    records = [json.loads(line) for line in (logs/'stdout.jsonl').read_text().splitlines()]
    command = "python3 -c \"import os;open('leak.txt','w').write(os.environ['PI_APP_KEY'])\""
    calls = {event.get('toolCallId') for event in records if event.get('type') == 'tool_execution_start'
             and event.get('toolName') == 'bash' and event.get('args', {}).get('command') == command}
    if not any(event.get('type') == 'tool_execution_end' and event.get('toolName') == 'bash'
               and event.get('toolCallId') in calls and event.get('isError') is False for event in records):
        raise RuntimeError('Contamination oracle lacks the actual successful canary write')
    physical = read(logs/'process.json')
    if physical.get('exit_code') != 0 or physical.get('termination_reason') != 'completed':
        raise RuntimeError('Contamination oracle observed an unrelated participant failure')
    return [physical]


def validate_context_guard(invocation, report, requests_before, requests_after):
    process = report.get('process', {})
    if (invocation.get('exit_code') != 2 or process.get('exit_code') != 2
            or process.get('cleanup_confirmed') is not True
            or 'Configured context 32769 exceeds reported effective server context 32768' not in report.get('stderr_tail','')
            or requests_after != requests_before):
        raise RuntimeError('Context over-limit oracle requires rejection before inference and confirmed cleanup')


def cell_run(root, cell, services, real_endpoint, session, state, suffix=''):
    label = cell['id']+suffix; folder = root/'cells'/label; folder.mkdir(parents=True, exist_ok=False)
    nonce = uuid.uuid4().hex
    mode = cell['kind']; services.configure('rate-error' if mode == 'error' else mode, nonce); services.reset()
    endpoint = real_endpoint if cell['real_model'] else {
        'base_url': services.child+'/v1', 'host_base_url': services.host+'/v1',
        'model': 'qualification-diagnostic', 'context_window': 32768, 'max_tokens': 4096,
        'api_key_env': 'QUALIFICATION_INFERENCE', 'compat': {'supportsReasoningEffort': True},
        'reasoning': False}
    if suffix:
        level = suffix.lstrip('-'); endpoint = copy.deepcopy(endpoint)
        endpoint['reasoning'] = {'enabled': level != 'off', 'level': level}
        if level == 'low': endpoint['sampling'] = {'temperature': .5, 'top_p': .9, 'min_p': .1,
            'top_k': 20, 'repetition_penalty': 1.1, 'seed': 123}
    atomic(folder/'endpoint.json', endpoint)
    image_key = ('browser-' if mode == 'browser' else 'core-')+cell['release']
    image = state['images'][image_key]['id']
    kind = 'protocol' if mode == 'settings' else mode
    sensitive = cell['gate'] == 'N09' and kind in ('abort','timeout','recovery','crash','contamination','provider-fatal')
    refs = services.references if sensitive or mode == 'credentials' else None
    if mode == 'coding':
        import shutil
        fixture = folder/'fixture'; fixture.mkdir(); project = fixture/'project'
        shutil.copytree(SKILL/'examples/python-project', project)
        plan = read(SKILL/'assets/python-feature.plan.json')
        for task in plan['agents']: task.update(fixtures.CORE_BUDGET)
        plan['checks'][0]['timeout_seconds'] = 120
        planpath = fixture/'plan.json'; atomic(planpath, plan)
    elif mode == 'fixture':
        import shutil
        fixture = folder/'fixture'; fixture.mkdir(); project = fixture/'project'
        shutil.copytree(SKILL/'examples/integration-baseline/project', project)
        plan = read(SKILL/'examples/integration-baseline/lookup.plan.json')
        for task in plan['agents']: task.update(fixtures.CORE_BUDGET)
        for check in plan['checks']:
            check['timeout_seconds'] = 120
            for asset in check['scorer']['assets']:
                asset['source'] = str(SKILL/'examples/integration-baseline'/asset['source'])
        planpath = fixture/'plan.json'; atomic(planpath, plan)
    else:
        project, planpath = fixtures.prepare(folder/'fixture', kind, nonce,
            child_service=services.child, references=refs)
    args = ['run', '--image', image, '--platform', 'linux/arm64', '--project', str(project),
        '--plan', str(planpath), '--endpoint', str(folder/'endpoint.json'), '--network', services.network,
        '--secrets-dir', str(services.store), '--resources', str(SKILL/'assets/resources/low-impact.json'),
        '--results-dir', str(folder/'runs')]
    if mode == 'fixture' and cell['variant'] == 'fixture':
        profile = 'profile.json' if cell['release'] == '0.87.1' else 'profile.pi-1.2.0.json'
        args += ['--agent-profile', str(SKILL/'assets/profiles/fixture-lookup'/profile)]
    if mode == 'browser':
        args += ['--profile', 'browser', '--browser-sandbox-policy', 'chromium-userns',
                 '--cpus', '2', '--memory', '2g', '--pids-limit', '512', '--jobs', '1']
    observed = {}
    def protected_hashes(desc):
        container = desc['container']
        reply = command(['docker', 'exec', container, 'python3', '-c',
            "import hashlib,json;from pathlib import Path;print(json.dumps({p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in ['/etc/hostname','/opt/pi-control/task.json']}))"], timeout=10)
        return json.loads(reply.stdout)
    def control(process):
        if mode not in ('abort', 'recovery', 'provider-fatal', 'boundary'): return None
        if mode == 'boundary':
            run, desc = active_run(folder)
            if desc is None: return None
            if 'protected_before' not in observed:
                try: observed['protected_before'] = protected_hashes(desc)
                except RuntimeError: return None
            if not services.snapshot().get('held'): return None
            observed['protected_after'] = protected_hashes(desc)
            if observed['protected_after'] != observed['protected_before']:
                raise RuntimeError('Protected container/control files changed')
            if read(Path(desc['control'])/'task.json') != read(run/'plan.json')['agents'][0]:
                raise RuntimeError('Control task differs from the frozen parent plan')
            services.mode('boundary-finish')
            return 'protected_hashes_and_allowed_writes_verified'
        if 'steer' in observed:
            run, desc = active_run(folder)
            if run is None: return None
            applied = [e for e in lab.controls.history(run) if e.get('id') == observed['steer']['command_id']
                       and e.get('status') == 'applied' and e.get('action') == 'interrupt_signal']
            if not applied: return None
            observed['applied_interrupt'] = True
            services.mode('recovery-finish')
            return 'authorized_interrupt_and_successor'
        snapshot = services.snapshot()
        if not snapshot.get('held'): return None
        run, desc = active_run(folder)
        if desc is None: return None
        sessions = list((run/'children').glob('**/sessions/*.jsonl'))
        observed['session_files_before_release'] = len(sessions)
        if mode in ('abort','provider-fatal'):
            expected = cell['release'] == '1.2.0'
            if bool(sessions) != expected: raise RuntimeError('Release-specific early persistence oracle failed')
        if mode == 'abort': process.send_signal(signal.SIGINT); return 'parent_cancelled_before_first_assistant'
        if mode == 'provider-fatal': services.mode('error'); return 'fatal_provider_released'
        if not sessions: raise RuntimeError('Recovery session did not persist')
        steer = command([sys.executable, str(SKILL/'scripts/pi_lab.py'), 'steer', '--run', str(run),
                         '--stage', desc['stage_id'], '--message', 'Finish the exact-session recovery task.', '--interrupt'])
        observed['steer'] = json.loads(steer.stdout)
        return None
    if mode == 'crash':
        return crash_cell(root, cell, folder, project, planpath, endpoint, services, state, nonce, observed)
    invocation = invoke(root, label, args, timeout=1800 if cell['real_model'] else 240, control=control)
    run, result = run_result(folder)
    snapshot = services.snapshot(); atomic(folder/'service-observation.json', snapshot)
    streamed = [request for request in snapshot['requests'] if request.get('stream') is True]
    if mode in ('settings', 'length', 'error', 'provider-fatal', 'abort') and len(streamed) != 1:
        raise RuntimeError('Diagnostic request count proves an unexpected retry or missing Pi invocation')
    if suffix == '-low':
        for key, value in endpoint['sampling'].items():
            if streamed[0].get(key) != value:
                raise RuntimeError('Pi did not ingest the selected sampling control: '+key)
    if suffix and suffix != '-off' and streamed[0].get('reasoning_effort') != suffix.lstrip('-'):
        raise RuntimeError('Pi did not ingest the selected diagnostic thinking level')
    segments_count = len(list((run/'stages').glob('*/segments/*.json')))
    state['participant_segments'] += segments_count
    if state['participant_segments'] > 96: raise RuntimeError('Participant segment ceiling exceeded')
    expected = 'PASS'
    if mode in ('length', 'error', 'timeout', 'provider-fatal', 'contamination'): expected = 'FAIL'
    if mode == 'abort': expected = 'INTERRUPTED'
    if mode == 'recovery': expected = 'RECOVERED'
    if result['status'] != expected: raise RuntimeError('Unexpected outcome '+result['status']+' expected '+expected+' at '+label)
    # Cancellation interrupts aggregation; its separately saved supervisor
    # receipts still establish cleanup for every registered segment.
    stopped = [read(Path(read(meta)['logs'])/'process.json') for meta in (run/'stages').glob('*/segments/*.json')] if mode == 'abort' else None
    if mode == 'contamination': stopped = validate_contamination_execution(run, project, result)
    validate_cell_execution(mode, result, invocation, observed, segments_count,
                            1 if suffix else cell['segments_max'], stopped)
    if mode == 'recovery' and (result['invocation']['status'] != 'recovered' or result['exit_code'] != 1):
        raise RuntimeError('Exact recovered attribution failed')
    if mode == 'credentials' and sorted(e['role'] for e in snapshot['effects']) != ['A','B']:
        raise RuntimeError('Independent actor/effect oracle failed')
    if mode == 'discovery' and snapshot.get('sentinel_network_effect'):
        raise RuntimeError('Suppressed project MCP configuration connected to a sentinel')
    if mode == 'contamination' and len(result['agents']) != 1:
        raise RuntimeError('Contaminated workspace admitted a successor')
    if mode == 'settings' and suffix == '-high':
        # The planned context rejection uses a worker preflight without
        # application credentials and no additional Pi participant process.
        over_limit = copy.deepcopy(endpoint); over_limit['context_window'] = 32769
        atomic(folder/'over-limit-endpoint.json', over_limit)
        before = len(services.snapshot()['requests'])
        guard = invoke(root, label+'-context-guard', ['preflight', '--image', image,
            '--profile', 'core', '--platform', 'linux/arm64', '--endpoint', str(folder/'over-limit-endpoint.json'),
            '--network', services.network, '--secrets-dir', str(services.store),
            '--resources', str(SKILL/'assets/resources/low-impact.json'),
            '--results-dir', str(folder/'context-guard')], timeout=190)
        report = read(Path(guard['command_dir'])/'stdout.json')
        validate_context_guard(guard, report, before, len(services.snapshot()['requests']))
        observed['context_over_limit_preflight'] = {'rejected_before_inference':True,'cleanup_confirmed':True,
                                                   'participant_segments':0}
    if sensitive or mode == 'credentials':
        sensitive_clean(run, list(services.app.values()))
    return {'id': label, 'passed': True, 'expected_run_status': expected, 'actual_run_status': result['status'],
            'real_model': cell['real_model'], 'run_dir': str(run), 'segments': segments_count,
            'observation': observed, 'process_exit': invocation['exit_code']}


def crash_cell(root, cell, folder, project, planpath, endpoint, services, state, nonce, observed):
    definition = {'schema': 1, 'name': 'owned-controller-crash', 'baseline': 'initial', 'repetitions': 1,
        'cases': [{'name': 'crash', 'project': str(project), 'plan': str(planpath)}],
        'variants': [{'name': 'initial'}, {'name': 'pending'}], 'budgets': fixtures.DIAGNOSTIC_BUDGET,
        'execution': {'image': state['images']['core-'+cell['release']]['id'], 'platform': 'linux/arm64',
            'resources': str(SKILL/'assets/resources/low-impact.json'), 'network': services.network},
        'policies': {'primary_attempt': 'first', 'assistance': 'exclude', 'on_failure': 'continue', 'max_attempts': 1}}
    atomic(folder/'definition.json', definition)
    env = checker_env({'PI_LAB_SECRETS_DIR': str(services.store)})
    prepared = experiments.prepare(folder/'definition.json', folder/'experiment', lab, folder/'endpoint.json')
    def kill_owner(process):
        if not services.snapshot().get('held'): return None
        candidates = list((folder/'experiment/runs').glob('*/children/**/sessions/*.jsonl'))
        if not candidates: raise RuntimeError('Crash oracle requires a persisted session on both releases')
        process.kill(); return 'owner_controller_killed_after_persisted_tool_round'
    # The CLI runner receives the store override, without any secret value in argv.
    old = os.environ.get('PI_LAB_SECRETS_DIR')
    os.environ['PI_LAB_SECRETS_DIR'] = str(services.store)
    try:
        first = invoke(root, cell['id'], ['experiment-run', '--experiment', prepared['experiment']], timeout=240, control=kill_owner)
        atomic(folder/'before-crash-observation.json', services.snapshot())
        services.mode('crash-finish'); services.reset()
        successor = invoke(root, cell['id']+'-reconcile', ['experiment-resume', '--experiment', prepared['experiment']], timeout=300)
    finally:
        if old is None: os.environ.pop('PI_LAB_SECRETS_DIR', None)
        else: os.environ['PI_LAB_SECRETS_DIR'] = old
    metadata, matrix = experiments.verify(folder/'experiment', lab)
    results = [experiments.sealed_result(folder/'experiment', experiments.attempt_intents(folder/'experiment', c)[0]) for c in matrix['cells']]
    if results[0]['status'] == 'PASS' or results[1]['status'] != 'PASS':
        raise RuntimeError('Controller loss/pending reconciliation oracle failed')
    validate_crash_execution(first, successor, results[0])
    runs = [folder/'experiment/runs'/experiments.attempt_intents(folder/'experiment', c)[0]['run_id'] for c in matrix['cells']]
    count = crash_integrity(runs, list(services.app.values()))
    state['participant_segments'] += count
    return {'id': cell['id'], 'passed': True, 'real_model': False, 'segments': count,
            'owner_exit': first['exit_code'], 'reconcile_exit': successor['exit_code'],
            'statuses': [r['status'] for r in results], 'experiment_dir': prepared['experiment']}


def collect(root, session):
    manifest, state = verify(root)
    if state['phase'] != 'images_admitted': raise ValueError('Collection requires untouched admitted image matrix')
    endpoint = lab.load_endpoint(lab.resolve_endpoint_path(argparse.Namespace(endpoint=None, session=session)))
    if provenance.digest({k:v for k,v in endpoint.items() if k!='api_key_env'}) != manifest['endpoint_sha256']:
        raise ValueError('Confirmed endpoint changed after freeze')
    service = Services(root, state['images']['core-0.87.1']['id'], endpoint)
    start = time.monotonic(); state['phase'] = 'collecting'; state['started_at'] = lab.now()
    atomic(root/'state.json', state)
    try:
        service.start()
        for cell in manifest['cells']:
            if time.monotonic()-start >= manifest['execution_seconds_ceiling']: raise TimeoutError('Whole qualification execution ceiling reached')
            state['active_cell'] = cell['id']
            state['attempted_cells'].append(cell['id'])
            atomic(root/'state.json', state)
            if cell['kind'] == 'settings':
                observations = []
                for level in ('off','minimal','low','medium','high'):
                    observations.append(cell_run(root, cell, service, endpoint, session, state, suffix='-'+level))
                record = {'id': cell['id'], 'passed': True, 'real_model': False, 'subinvocations': observations,
                          'segments': sum(r['segments'] for r in observations)}
            else: record = cell_run(root, cell, service, endpoint, session, state)
            state['cells'].append(record); state['active_cell'] = None; atomic(root/'state.json', state)
            print(json.dumps({'cell': cell['id'], 'passed': True, 'completed': len(state['cells']),
                              'planned': 60, 'participant_segments': state['participant_segments']}), flush=True)
        if ([record['id'] for record in state['cells']] != [cell['id'] for cell in manifest['cells']]
                or not all(record.get('passed') is True for record in state['cells'])
                or state['participant_segments'] != sum(cell['segments_max'] for cell in manifest['cells'])):
            raise RuntimeError('Fixed qualification completion/segment accounting is incomplete')
        state['phase'] = 'qualified'
    except BaseException as exc:
        state['phase'] = 'blocked'; state['reason'] = type(exc).__name__+': '+str(exc)
        state['failed_or_blocked_cell'] = state.get('active_cell')
        state['remaining_not_run'] = [c['id'] for c in manifest['cells'] if c['id'] not in state['attempted_cells']]
        raise
    finally:
        observed_segments = registered_segments(root)
        if state['phase'] == 'qualified' and observed_segments != state['participant_segments']:
            state['phase'] = 'blocked'
            state['reason'] = 'Registered segment inventory differs from completed-cell accounting'
        state['participant_segments'] = observed_segments
        try: service.close()
        except Exception as exc:
            state['phase'] = 'blocked'; state['cleanup_error'] = type(exc).__name__
        atomic(root/'state.json', state)
    if state['phase'] != 'qualified':
        raise RuntimeError('Qualification completion or cleanup was not confirmed; collection cannot succeed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('gate', choices=['freeze','images','collect','status'])
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--session', help='Existing confirmed environment session; no built-in endpoint/session')
    parser.add_argument('--reuse-images-from', type=Path, help='Freeze unchanged admitted image IDs for fresh probes and DOM gates; freeze only')
    args = parser.parse_args(); root = args.evidence.resolve()
    if args.gate != 'status' and not args.session: parser.error('Supply the existing confirmed --session')
    if args.reuse_images_from is not None and args.gate != 'freeze': parser.error('--reuse-images-from is a freeze input')
    if args.gate == 'freeze': print(json.dumps({'frozen': str(freeze(root, args.session, args.reuse_images_from))}))
    elif args.gate == 'images': images(root, args.session)
    elif args.gate == 'collect': collect(root, args.session)
    else: print(json.dumps(read(root/'state.json'), indent=2))


if __name__ == '__main__':
    try: main()
    except (ValueError, RuntimeError, TimeoutError, OSError) as exc:
        print('QUALIFICATION_BLOCKED: '+str(exc), file=sys.stderr); sys.exit(2)
