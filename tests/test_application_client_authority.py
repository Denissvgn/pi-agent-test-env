"""A04 real local helper processes and mocked Docker boundaries; no live qualification."""
import argparse
import copy
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import time
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'skill/scripts'), str(ROOT / 'skill/runtime')]
import application_client as client
import application_client_service as service
import application_compiler as compiler
import application_credentials as credentials
import ownership_registry as ownership
from parallel_allocator import Allocator
import secret_store
import test_application_compiler as compiler_fixtures

KEY_A = 'disposable-application-alice-123456'
KEY_B = 'disposable-application-bob-98765432'
INFERENCE_KEY = 'disposable-inference-key-123456789'


def code_identity():
    return {name: hashlib.sha256((ROOT / 'skill' / name).read_bytes()).hexdigest()
            for name in client.TRUSTED_CODE}


def binding(plan):
    value = {name: str(uuid.uuid4()) for name in service.BINDING_FIELDS - {'plan_sha256', 'trial_id'}}
    return {**value, 'trial_id': None, 'plan_sha256': plan['plan_sha256']}


class BaseFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pi-client-authority-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.project = self.root / 'project'; self.project.mkdir(mode=0o700)
        (self.project / 'original.txt').write_text('Protected original input.\n')
        self.runroot = self.root / 'run'; self.runroot.mkdir(mode=0o700)
        (self.runroot / 'workspace').mkdir(mode=0o700)
        self.store = self.root / 'private-store'
        secret_store.write_secret('DIAGNOSTIC_ALICE', KEY_A, self.store)
        secret_store.write_secret('DIAGNOSTIC_BOB', KEY_B, self.store)
        source, kwargs = compiler_fixtures.inputs()
        self.plan = compiler.compile_plan(source, **kwargs)

    def admit(self, plan=None, **kwargs):
        values = dict(endpoint={'api_key_env': 'PI_API_KEY'}, inference_key=INFERENCE_KEY,
                      store=self.store, project=self.project, runroot=self.runroot)
        values.update(kwargs)
        return client.admit(self.plan if plan is None else plan, **values)

    def authority(self):
        authority = self.admit(); grant = authority.grant('participant', binding(self.plan))
        return authority, grant

    def configuration(self, authority):
        evidence = self.root / ('evidence-' + uuid.uuid4().hex); evidence.mkdir(mode=0o700)
        return json.loads(authority._bootstrap(evidence, code_identity()))

    def process(self, config):
        process = subprocess.Popen([sys.executable, str(ROOT / 'skill/runtime/application_client_service.py'),
                                    '--listen', '127.0.0.1', '--port', '0'],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env={'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'PYTHONDONTWRITEBYTECODE': '1'},
                                   start_new_session=True)
        def stop():
            if process.poll() is None:
                process.terminate(); process.wait(timeout=5)
            for stream in (process.stdin, process.stdout, process.stderr):
                if not stream.closed: stream.close()
        self.addCleanup(stop)
        client._send_bootstrap(process, client.c.canonical(config))
        ready = client._ready(process)
        return process, ready['port']

    def request(self, port, grant, *, action='status', operation=None, path='/ipc', body=None, bearer=None):
        return client._request('127.0.0.1', port, path,
                               grant.capability if bearer is None else bearer,
                               body if body is not None else {'schema': 1, 'action': action,
                                                             'scope': grant.scope, 'operation_id': operation})


class AuthorityAdmissionTests(BaseFixture):
    def test_ac16_authority_repr_and_worker_independent_contexts_withhold_values(self):
        authority, grant = self.authority()
        public = repr(authority) + repr(grant) + json.dumps(grant.context()) + json.dumps(authority.independent_context())
        self.assertNotIn(KEY_A, public); self.assertNotIn(KEY_B, public); self.assertNotIn(INFERENCE_KEY, public)
        self.assertNotIn('PI_APP_', public)
        self.assertEqual(authority.independent_context(), {'schema': 1, 'application_access': False})
        with self.assertRaises(TypeError): json.dumps(authority)
        changed = authority.plan; changed['application']['credentials']['persona'] = 'OTHER'
        self.assertEqual(authority.plan['application']['credentials']['persona'], 'DIAGNOSTIC_ALICE')

    def test_ac18_missing_insecure_in_place_and_colliding_credentials_fail_admission(self):
        for fault in ('missing', 'file-mode', 'directory-mode', 'in-place', 'same-reference', 'same-value', 'unicode'):
            with self.subTest(fault=fault):
                self.store.chmod(0o700)
                secret_store.write_secret('DIAGNOSTIC_ALICE', KEY_A, self.store)
                parameters = {}
                if fault == 'missing': (self.store / 'DIAGNOSTIC_ALICE').unlink()
                elif fault == 'file-mode': (self.store / 'DIAGNOSTIC_ALICE').chmod(0o644)
                elif fault == 'directory-mode': self.store.chmod(0o755)
                elif fault == 'in-place': parameters['in_place'] = True
                elif fault == 'same-reference': parameters['endpoint'] = {'api_key_env': 'DIAGNOSTIC_ALICE'}
                elif fault == 'same-value': parameters['inference_key'] = KEY_A
                else: secret_store.write_secret('DIAGNOSTIC_ALICE', 'clé-application-123456789', self.store)
                with mock.patch('subprocess.Popen') as launch, self.assertRaises(ValueError):
                    self.admit(**parameters)
                launch.assert_not_called()

    def test_ac18_source_literal_key_is_refused_even_in_final_rendered_prompt(self):
        source, kwargs = compiler_fixtures.inputs()
        source['stages'][0]['prompt'] += ' forbidden=' + KEY_A
        plan = compiler.compile_plan(source, **kwargs)
        with self.assertRaises(credentials.CredentialError): self.admit(plan)

    def test_ac18_secret_store_inside_project_evidence_or_package_rejects(self):
        for parent in (self.project, self.runroot):
            store = parent / 'secrets'; secret_store.write_secret('DIAGNOSTIC_ALICE', KEY_A, store)
            with self.assertRaises(credentials.CredentialError): self.admit(store=store)

    def test_ac18_rotation_fails_before_image_probe_network_or_launch(self):
        authority, grant = self.authority()
        secret_store.write_secret('DIAGNOSTIC_ALICE', KEY_B, self.store)
        lab = mock.Mock()
        with self.assertRaises(client.ClientError) as caught:
            client.OwnedHelper.start(authority, lab=lab, args=argparse.Namespace(), registry=mock.Mock(),
                                     allocator=mock.Mock(), participant_resources={}, popen=mock.Mock())
        self.assertEqual(caught.exception.reason, 'authority_changed')
        self.assertEqual(lab.mock_calls, [])

    def test_ac18_all_selected_inference_authorities_are_exhaustive_and_collision_free(self):
        source, kwargs = compiler_fixtures.inputs(compiler_fixtures.two_stages())
        kwargs['inference_bindings']['second'].update(kind='indexed', configuration_sha256='6' * 64)
        plan = compiler.compile_plan(source, **kwargs)
        selected = {'5' * 64: {'reference': 'FIRST_INFERENCE', 'value': INFERENCE_KEY},
                    '6' * 64: {'reference': 'SECOND_INFERENCE', 'value': 'disposable-inference-second-12345'}}
        with self.assertRaises(client.ClientError): self.admit(plan)
        valid = self.admit(plan, inference_authorities=selected)
        self.assertTrue(valid.redactor().contains(selected['6' * 64]['value'].encode()))
        for fault in ['missing', 'extra', 'reference', 'value']:
            with self.subTest(fault=fault):
                authorities = copy.deepcopy(selected)
                if fault == 'missing': authorities.pop('6' * 64)
                elif fault == 'extra': authorities['7' * 64] = {'reference': None, 'value': ''}
                elif fault == 'reference': authorities['6' * 64]['reference'] = 'DIAGNOSTIC_ALICE'
                else: authorities['6' * 64]['value'] = KEY_A
                with self.assertRaises(client.ClientError): self.admit(plan, inference_authorities=authorities)
        self.assertNotIn(selected['6' * 64]['value'], repr(valid))

    def test_ac18_literals_of_any_selected_inference_key_are_rejected_and_keyless_is_explicit(self):
        source, kwargs = compiler_fixtures.inputs()
        kwargs['inference_bindings']['participant']['kind'] = 'indexed'
        selected = {'5' * 64: {'reference': 'SECOND_INFERENCE', 'value': 'second-private-inference-key-12345'}}
        source['stages'][0]['prompt'] += selected['5' * 64]['value']
        plan = compiler.compile_plan(source, **kwargs)
        with self.assertRaises(client.ClientError): self.admit(plan, inference_authorities=selected)
        source, kwargs = compiler_fixtures.inputs(); kwargs['inference_bindings']['participant']['kind'] = 'indexed'
        plan = compiler.compile_plan(source, **kwargs)
        authority = self.admit(plan, inference_key='', inference_authorities={'5' * 64: {'reference': None, 'value': ''}})
        self.assertNotIn(INFERENCE_KEY, repr(authority))

    def test_ac17_scope_is_exact_and_new_grants_cannot_change_plan_or_name_unknown_stages(self):
        authority = self.admit()
        for stage, bound in [('unassigned', binding(self.plan)), ('participant', {**binding(self.plan), 'plan_sha256': 'a' * 64})]:
            with self.assertRaises(ValueError): authority.grant(stage, bound)
        bound = binding(self.plan); grant = authority.grant('participant', bound)
        with self.assertRaises(ValueError): authority.grant('participant', bound)
        self.assertNotIn(KEY_A, str(grant.scope))

    def test_ac16_only_assigned_aliases_exist_in_private_stage_authority(self):
        source = compiler_fixtures.two_stages()
        source['application']['credentials']['second-persona'] = 'DIAGNOSTIC_BOB'
        operation = copy.deepcopy(source['application']['operations'][0])
        operation.update(id='identity-second', credential_alias='second-persona')
        source['application']['operations'].append(operation)
        second = source['stages'][1]
        second.update(credential_aliases=['second-persona'], operations=['identity-second'])
        second['completion']['pagination'] = []; second['completion']['publications'] = []
        source, kwargs = compiler_fixtures.inputs(source)
        plan = compiler.compile_plan(source, **kwargs)
        authority = self.admit(plan)
        first_binding = binding(plan)
        second_binding = {**binding(plan), **{key: first_binding[key] for key in ('run_id', 'trial_id', 'attempt_id')}}
        first = authority.grant('participant', first_binding); second = authority.grant('second', second_binding)
        helper = service.CapabilityService(self.configuration(authority))
        self.assertEqual(helper.private_authority(first.capability, first.scope, 'identity'), KEY_A)
        self.assertEqual(helper.private_authority(second.capability, second.scope, 'identity-second'), KEY_B)
        with self.assertRaises(service.ServiceError): helper.private_authority(first.capability, second.scope, 'identity-second')
        self.assertNotIn(KEY_A, repr(helper)); self.assertNotIn(KEY_B, repr(helper))


class LocalServiceTests(BaseFixture):
    def test_ac16_real_process_receives_private_stdin_and_returns_only_public_metadata(self):
        authority, grant = self.authority(); config = self.configuration(authority)
        process, port = self.process(config)
        result = self.request(port, grant, action='validate', operation='identity')
        self.assertEqual(result['credential_aliases'], ['persona'])
        self.assertFalse(result['business_effects_enabled'])
        self.assertNotIn(KEY_A, repr(process.args) + json.dumps(result))
        self.assertNotIn(KEY_B, json.dumps(result)); self.assertNotIn(INFERENCE_KEY, json.dumps(result))
        for path in self.runroot.rglob('*'):
            if path.is_file(): self.assertNotIn(KEY_A.encode(), path.read_bytes())

    def test_ac17_wrong_stage_segment_attempt_actor_operation_and_revocation_deny(self):
        authority, grant = self.authority(); config = self.configuration(authority)
        process, port = self.process(config)
        for field, bad in [('stage_id', str(uuid.uuid4())), ('segment_id', str(uuid.uuid4())),
                           ('attempt_id', str(uuid.uuid4())), ('authority_generation', str(uuid.uuid4())),
                           ('participant', {**grant.scope['participant'], 'actor_id': 'actor-bob'})]:
            with self.subTest(field=field):
                scope = {**grant.scope, field: bad}
                with self.assertRaises(client.ClientError):
                    self.request(port, grant, body={'schema': 1, 'action': 'status', 'scope': scope, 'operation_id': None})
        with self.assertRaises(client.ClientError): self.request(port, grant, action='validate', operation='undeclared')
        self.request(port, grant, path='/control', bearer=authority._control_token,
                     body={'schema': 1, 'action': 'revoke', 'capability': grant.capability})
        with self.assertRaises(client.ClientError): self.request(port, grant)
        self.assertIsNone(process.poll())

    def test_ac17_no_arbitrary_proxy_file_secret_lookup_or_implicit_workflow_routes(self):
        authority, grant = self.authority(); process, port = self.process(self.configuration(authority))
        for path in ['/proxy', '/secrets', '/files', '/login', '/ipc?url=https://example.invalid']:
            with self.subTest(path=path), self.assertRaises(client.ClientError): self.request(port, grant, path=path)
        for action in ['fetch', 'read_file', 'login', 'retry', 'workflow']:
            with self.subTest(action=action), self.assertRaises(client.ClientError): self.request(port, grant, action=action)
        with self.assertRaises(client.ClientError):
            self.request(port, grant, path='/control', body={'schema': 1, 'action': 'revoke', 'capability': grant.capability})

    def test_ac17_invalid_unicode_short_tokens_never_alias_zero_capability(self):
        authority, grant = self.authority(); config = self.configuration(authority)
        config['capabilities'][0]['token'] = '0' * 64
        helper = service.CapabilityService(config)
        for invalid in ['', 'short', 'é' * 64, None, True, 'A' * 64]:
            with self.subTest(invalid=invalid), self.assertRaises(service.ServiceError):
                helper.authorize(invalid, grant.scope, 'identity')
        self.assertEqual(helper.authorize('0' * 64, grant.scope, 'identity'), grant.scope)
        config['control_token'] = '0' * 64; config['capabilities'][0]['token'] = '1' * 64
        helper = service.CapabilityService(config)
        for invalid in ['é' * 64, 'short', None]:
            with self.assertRaises(service.ServiceError):
                helper.request('/control', invalid, {'schema': 1, 'action': 'revoke', 'capability': '1' * 64})

    def test_ac17_raw_duplicate_json_oversized_requests_and_duplicate_auth_reject(self):
        authority, grant = self.authority(); process, port = self.process(self.configuration(authority))
        for raw in [b'{"schema":1,"schema":1}', b'x' * (service.MAX_REQUEST_BYTES + 1)]:
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            connection.request('POST', '/ipc', raw, {'Authorization': 'Bearer ' + grant.capability,
                                                    'Content-Type': 'application/json'})
            response = connection.getresponse(); self.assertEqual(response.status, 403)
            self.assertLess(len(response.read()), 8193); connection.close()
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        connection.putrequest('POST', '/ipc')
        for _ in range(2): connection.putheader('Authorization', 'Bearer ' + grant.capability)
        connection.putheader('Content-Type', 'application/json'); connection.putheader('Content-Length', '2')
        connection.endheaders(b'{}')
        response = connection.getresponse(); self.assertEqual(response.status, 403); response.read(); connection.close()

    def test_ac17_stalled_headers_have_a_finite_socket_deadline(self):
        authority, grant = self.authority(); process, port = self.process(self.configuration(authority))
        connection = socket.create_connection(('127.0.0.1', port), timeout=7)
        connection.sendall(b'POST /ipc HTTP/1.1\r\nHost:')
        started = time.monotonic()
        self.assertEqual(connection.recv(1), b'')
        self.assertLess(time.monotonic() - started, 6.5)
        connection.close()
        self.assertTrue(self.request(port, grant)['ok'])

    def test_ac19_partial_startup_stdout_cannot_block_readiness_indefinitely(self):
        process = subprocess.Popen([sys.executable, '-c',
            'import sys,time;sys.stdout.write("{");sys.stdout.flush();time.sleep(5)'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            started = time.monotonic()
            with self.assertRaises(client.ClientError): client._ready(process, deadline=.1)
            self.assertLess(time.monotonic() - started, 1)
        finally:
            process.terminate(); process.wait(timeout=5); process.stdout.close(); process.stderr.close()

    def test_ac17_authority_only_mode_cannot_implicitly_enable_business_router(self):
        authority, grant = self.authority(); config = self.configuration(authority)
        self.assertEqual(config['mode'], 'authority-only')
        config['mode'] = 'application'
        with self.assertRaises(ValueError): service.CapabilityService(config)
        with self.assertRaises(ValueError): authority._bootstrap(config['evidence_root'], code_identity(), mode='application')

    def test_ac16_code_identity_is_explicit_and_tampering_blocks_service_start(self):
        authority, grant = self.authority(); config = self.configuration(authority)
        config['code_identity']['scripts/resources.py'] = 'a' * 64
        with self.assertRaises(service.ServiceError): service.CapabilityService(config)
        config = self.configuration(authority); config['code_identity']['arbitrary.py'] = 'a' * 64
        with self.assertRaises(ValueError): service.CapabilityService(config)


# The subprocess below is real Python HTTP IPC. Docker image/network/limits/ownership
# observations are controlled boundary fixtures and never claim container qualification.
LOCAL_DOCKER_LAUNCHER = '''
import json,sys
from pathlib import Path
sys.path[:0]=[sys.argv[1]+'/scripts',sys.argv[1]+'/runtime']
import application_client_service as service
config=json.loads(sys.stdin.buffer.read(service.MAX_CONFIG_BYTES+1))
if config.get('document_type')=='application_execution_private_bootstrap':
    evidence=Path(sys.argv[2])/Path(config['authority']['evidence_root']).relative_to('/pi-client/evidence')
    state=Path(sys.argv[3])/Path(config['state_root']).relative_to('/pi-client/state')
    config['authority']['evidence_root']=str(evidence)
    config['state_root']=str(state)
    config['outputs_root']=str(evidence/'outputs')
    from application_execution_service import ApplicationService
    authority=ApplicationService(config)
else:
    config['evidence_root']=sys.argv[2]
    authority=service.CapabilityService(config)
server=service.Server(('127.0.0.1',0),authority)
print(json.dumps({'schema':1,'status':'ready','port':server.server_port,'business_effects_enabled':False}),flush=True)
server.serve_forever(poll_interval=.1)
'''


class DockerBoundary:
    def __init__(self):
        self.events = []; self.process = None; self.argv = None; self.port = None
        self.networks = {}; self.records = None; self.absence = True
        self.image = 'sha256:' + 'a' * 64
        self.env = None; self.foreign = None;self.removed=False;self.name_missing=False;self.name_foreign=False

    def image_info(self, image, platform):
        self.events.append('image_info')
        return {'id': image, 'platform': platform}

    def command(self, argv, **kwargs):
        self.events.append(list(argv))
        reply = subprocess.CompletedProcess(argv, 0, '', '')
        if argv[1:2] == ['info']:
            reply.stdout = 'fixture-daemon'
        elif argv[1:3] == ['network', 'create']:
            labels = {}
            for index, arg in enumerate(argv):
                if arg == '--label':
                    key, value = argv[index + 1].split('=', 1); labels[key] = value
            self.networks[argv[-1]] = labels
        elif argv[1:3] == ['network', 'inspect']:
            if argv[-1] not in self.networks:
                reply.returncode = 1; reply.stderr = 'network ' + argv[-1] + ' not found'
            else: reply.stdout = json.dumps([{'Driver': 'bridge', 'Labels': self.networks[argv[-1]], 'Containers': {}}])
        elif argv[1:3] == ['network', 'rm']:
            self.networks.pop(argv[-1], None)
        elif argv[1:3] == ['rm', '--force']:
            self.removed=True
            if self.process is not None and self.process.poll() is None:
                self.process.terminate(); self.process.wait(timeout=5)
        elif argv[1:3] == ['container', 'inspect']:
            by_name=argv[-1]!='f'*64
            if self.process is None or self.removed or by_name and self.name_missing:
                reply.returncode = 1; reply.stderr = 'No such container: '+argv[-1]
                if not self.absence: reply.stderr = 'daemon unavailable'
            else:
                record = next(row for row in self.records() if row.get('application_helper'))
                reply.stdout = json.dumps([{'Id': 'f' * 64, 'Image': record['image'], 'Config': {'Labels': {
                    ownership.LABEL: record['launch_id'], ownership.REGISTRY_LABEL: record['registry']}},
                    'Mounts': [{'Source': m['source'], 'Destination': m['target'], 'RW': m['rw']} for m in record['mounts']],
                    'HostConfig': {'NanoCpus': 1000000000, 'Memory': 512 * 1024**2,
                                   'MemorySwap': 512 * 1024**2, 'PidsLimit': 128},
                    'NetworkSettings': {'Ports': {'8081/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(self.port)}]}}}])
                if self.foreign:
                    data = json.loads(reply.stdout)
                    if self.foreign == 'labels': data[0]['Config']['Labels'] = {}
                    elif self.foreign == 'image': data[0]['Image'] = 'sha256:' + 'b' * 64
                    else: data[0]['Mounts'] = []
                    reply.stdout = json.dumps(data)
                if by_name and self.name_foreign:
                    data=json.loads(reply.stdout);data[0]['Id']='e'*64;data[0]['Config']['Labels']={};reply.stdout=json.dumps(data)
        return reply

    def popen(self, argv, **kwargs):
        self.events.append('Popen'); self.argv = argv; self.env = kwargs['env']
        evidence = next(arg.split('src=', 1)[1].split(',', 1)[0] for arg in argv if 'dst=/pi-client/evidence' in arg)
        code = next(arg.split('src=', 1)[1].split(',', 1)[0] for arg in argv if 'dst=/opt/pi-application' in arg)
        state = next(arg.split('src=', 1)[1].split(',', 1)[0] for arg in argv if 'dst=/pi-client/state' in arg)
        self.process = subprocess.Popen([sys.executable, '-I', '-B', '-c', LOCAL_DOCKER_LAUNCHER, code, evidence, state], **kwargs)
        return self.process


class OwnedLifecycleTests(BaseFixture):
    def launch(self, capacity=None, authority=None, boundary=None):
        authority = authority or self.authority()[0]
        boundary = boundary or DockerBoundary()
        registry = ownership.Registry(self.root / ('registry-' + uuid.uuid4().hex), command=boundary.command)
        registry.bind_daemon('fixture-daemon')
        boundary.records = registry.load
        pool = Allocator(capacity or {'cpu_millis': 4000, 'memory_mib': 8192, 'pids_limit': 1024})
        args = argparse.Namespace(platform='linux/arm64', native_platform='linux/arm64', uid=os.getuid(), gid=os.getgid())
        original_ready = client._ready
        def ready(process, deadline=10):
            result = original_ready(process, deadline); boundary.port = result['port']; return result
        with mock.patch.object(client, '_ready', side_effect=ready):
            helper = client.OwnedHelper.start(authority, lab=boundary, args=args, registry=registry,
                                               allocator=pool, participant_resources={'cpu_millis': 1000,
                                               'memory_mib': 2048, 'pids_limit': 256}, popen=boundary.popen)
        self.addCleanup(lambda: helper.cleanup(writers_absent=True))
        return helper, boundary, registry, pool

    def test_ac19_full_topology_registered_before_launch_and_private_stdin_only(self):
        helper, boundary, registry, pool = self.launch()
        self.assertEqual(len(pool.records), 2)
        self.assertEqual(helper.participant_reservation.state, 'reserved')
        self.assertEqual(pool.used(), {'cpu_millis': 2000, 'memory_mib': 2560, 'pids_limit': 384})
        self.assertEqual(len(registry.load()), 2)
        self.assertEqual(boundary.events[0], ['docker', 'info', '--format', '{{.ID}}'])
        self.assertIn('image_info', boundary.events)
        self.assertIn('--pull=never', boundary.argv)
        self.assertIn('--platform', boundary.argv); self.assertIn('linux/arm64', boundary.argv)
        for flag in ['--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges=true']:
            self.assertIn(flag, boundary.argv)
        self.assertNotIn(KEY_A, json.dumps(boundary.argv) + json.dumps(boundary.env) + json.dumps(registry.load()))
        self.assertNotIn(INFERENCE_KEY, json.dumps(boundary.env))
        grants = helper.authority._grants
        context = helper.context(grants[0]); self.assertEqual(context['base_url'], 'http://pi-application:8081/ipc')
        self.assertNotIn(KEY_A, json.dumps(context))
        code = next(m for m in helper.record['mounts'] if m['target'] == '/opt/pi-application')
        self.assertFalse(code['rw'])
        self.assertEqual(set(helper.record['code_identity']), set(client.TRUSTED_CODE))
        for path in helper.private_root.rglob('*'):
            if path.is_file(): self.assertNotIn(KEY_A.encode(), path.read_bytes())
        (helper.evidence_root / 'retained-receipt.json').write_text('{"sanitized":true}')
        self.assertTrue(helper.cleanup(writers_absent=True)['safe_to_continue'])
        self.assertTrue(helper.require_clean()); self.assertFalse(helper.private_root.exists())
        self.assertTrue((helper.evidence_root / 'retained-receipt.json').exists())
        self.assertTrue(all(r['status'] == 'released' for r in registry.load()))

    def failing_boundary(self, stderr='controlled helper bootstrap failure',stdout='{"schema":1,"status":"blocked"}'):
        boundary=DockerBoundary()
        def popen(argv,**kwargs):
            boundary.argv=argv;boundary.env=kwargs['env'];boundary.events.append('Popen')
            program='import sys;sys.stdin.buffer.read();sys.stderr.write('+repr(stderr)+');print('+repr(stdout)+',flush=True);raise SystemExit(2)'
            boundary.process=subprocess.Popen([sys.executable,'-I','-B','-c',program],**kwargs)
            return boundary.process
        boundary.popen=popen;return boundary

    def test_failed_start_attaches_actual_cleanup_and_safe_phase_before_caller_assignment(self):
        boundary=self.failing_boundary()
        with self.assertRaises(client.ClientError) as caught:self.launch(boundary=boundary)
        error=caught.exception
        self.assertEqual(error.reason,'evidence_unavailable');self.assertTrue(error.application_helper_launch_attempted)
        startup=client.validate_startup_failure(error.application_helper_startup,runroot=self.runroot)
        self.assertEqual(startup['phase'],'service_readiness');self.assertEqual(startup['reason'],'evidence_unavailable')
        receipt=error.application_helper_cleanup;self.assertTrue(receipt['safe_to_continue']);self.assertEqual(receipt['status'],'removed')
        path=Path(startup['diagnostic']['path']);body=path.read_bytes()
        self.assertEqual(hashlib.sha256(body).hexdigest(),startup['diagnostic']['sha256'])
        self.assertIn('controlled helper bootstrap failure',json.loads(body)['stderr'])
        self.assertNotIn(KEY_A,str(error)+repr(error)+json.dumps(startup));self.assertFalse(list((self.runroot/'application-helpers').iterdir()))
        self.assertFalse((self.runroot/'stages').exists());self.assertNotIn('helper',error.__dict__)

    def test_verified_id_is_persisted_before_any_private_bootstrap_delivery(self):
        boundary=DockerBoundary();original=client._send_bootstrap
        def deliver(process,body,timeout=10):
            record=next(row for row in boundary.records() if row.get('application_helper'))
            self.assertEqual(record.get('container_id'),'f'*64)
            boundary.name_missing=True
            return original(process,body,timeout)
        with mock.patch.object(client,'_send_bootstrap',side_effect=deliver):self.launch(boundary=boundary)

    def test_renamed_original_and_same_name_foreign_cleanup_target_only_bound_original_id(self):
        for foreign in (False,True):
            with self.subTest(foreign=foreign):
                helper,boundary,registry,_=self.launch();private=helper.private_root
                boundary.name_missing=not foreign;boundary.name_foreign=foreign;before=len(boundary.events)
                self.assertTrue(helper.cleanup(writers_absent=True)['safe_to_continue']);self.assertFalse(private.exists())
                actions=[event for event in boundary.events[before:] if isinstance(event,list)]
                inspections=[event[-1] for event in actions if event[1:3]==['container','inspect']]
                self.assertTrue(inspections);self.assertEqual(set(inspections),{'f'*64})
                self.assertEqual([event[-1] for event in actions if event[1:3]==['rm','--force']],['f'*64])
                self.assertTrue(all(row['status']=='released' for row in registry.load()))

    def test_missing_id_never_uses_name_absence_to_purge_or_deliver_bootstrap(self):
        boundary=DockerBoundary();boundary.name_missing=True
        with mock.patch.object(client.OwnedHelper,'_bind_container_identity',side_effect=client.ClientError('cleanup_unconfirmed')),\
             mock.patch.object(client,'_send_bootstrap') as bootstrap,mock.patch.object(client.shutil,'rmtree') as purge,\
             self.assertRaises(client.ClientError) as caught:
            self.launch(boundary=boundary)
        bootstrap.assert_not_called();purge.assert_not_called()
        error=caught.exception;self.assertEqual(error.application_helper_startup['phase'],'container_identity')
        self.assertFalse(error.application_helper_cleanup['safe_to_continue'])
        record=next(row for row in boundary.records() if row.get('application_helper'))
        self.assertEqual(record['status'],'quarantined');self.assertNotIn('container_id',record)
        self.assertTrue(Path(record['private_store']).exists())
        self.assertFalse(any(isinstance(event,list) and event[1:3]==['rm','--force'] for event in boundary.events))

    def test_secret_in_already_consumed_readiness_stdout_withholds_both_pipes(self):
        boundary=self.failing_boundary(stdout=json.dumps({'schema':1,'status':KEY_A,'business_effects_enabled':False}))
        with self.assertRaises(client.ClientError) as caught:self.launch(boundary=boundary)
        error=caught.exception;diagnostic=error.application_helper_startup['diagnostic']
        payload=json.loads(Path(diagnostic['path']).read_bytes())
        self.assertEqual(payload['output_status'],'withheld');self.assertEqual((payload['stdout'],payload['stderr']),('',''))
        self.assertTrue(error.application_helper_cleanup['safe_to_continue'])
        self.assertNotIn(KEY_A,json.dumps(error.__dict__)+str(error)+repr(error))

    def test_cleanup_exception_cannot_replace_original_start_error_or_invent_a_receipt(self):
        original=client.OwnedHelper.cleanup
        def cleanup_then_fail(helper,**kwargs):
            original(helper,**kwargs);raise RuntimeError('controlled cleanup failure')
        with mock.patch.object(client.OwnedHelper,'cleanup',side_effect=cleanup_then_fail,autospec=True),self.assertRaises(client.ClientError) as caught:
            self.launch(boundary=self.failing_boundary())
        self.assertEqual(caught.exception.reason,'evidence_unavailable')
        self.assertEqual(caught.exception.application_helper_startup['phase'],'service_readiness')
        self.assertFalse(hasattr(caught.exception,'application_helper_cleanup'))

    def test_reviewed_application_boot_uses_only_actual_frozen_bundle_in_isolated_python(self):
        for release in ('0.87.1','1.2.0'):
            with self.subTest(release=release):self.frozen_reviewed_boot(release)

    def frozen_reviewed_boot(self,release):
        import agent_profiles,provenance
        from application_execution_authority import ReviewedAuthority
        source,_=compiler_fixtures.inputs();source['runtime']['pi_release']=release
        source,kwargs=compiler_fixtures.inputs(source);profile=agent_profiles.application(release)
        runner=provenance.execution({}, {},ROOT/'skill');kwargs['runner_sha256']=runner['runner_content_sha256']
        for stage in source['stages']:
            name=stage['id'];kwargs['profile_bindings'][name]={'id':'application-client','pi_release':source['runtime']['pi_release'],
                'sha256':agent_profiles.identity(profile),'assets':{asset['target']:asset['sha256'] for asset in profile['assets']}}
            for asset in profile['assets']:kwargs['input_assets']['profiles/'+name+'/'+asset['target']]=agent_profiles.read_asset(asset['source'])
            kwargs['prompt_policy']['profile_instructions'][name]=kwargs['input_assets']['profiles/'+name+'/instructions.md'].decode()
        plan=compiler.compile_plan(source,**kwargs)
        authority=ReviewedAuthority(plan,endpoint={'api_key_env':'PI_API_KEY'},inference_key=INFERENCE_KEY,
            store=self.store,project=self.project,runroot=self.runroot,runner_files=runner['runner_files'])
        grant=authority.grant('participant',binding(plan));helper,boundary,_,_=self.launch(authority=authority)
        code=Path(next(m['source'] for m in helper.record['mounts'] if m['target']=='/opt/pi-application'))
        self.assertEqual({str(p.relative_to(code)) for p in code.rglob('*') if p.is_file()},set(client.TRUSTED_CODE))
        for name,digest in helper.record['code_identity'].items():self.assertEqual(hashlib.sha256((code/name).read_bytes()).hexdigest(),digest)
        result=client._request('127.0.0.1',boundary.port,'/control',authority._control_token,
            {'schema':1,'action':'activate','capability':grant.capability,'remaining_seconds':180})
        self.assertTrue(result['ok']);self.assertFalse(any(result['budget']['counts'].values()))
        self.assertTrue((helper.evidence_data_root/'raw').is_dir());self.assertTrue((helper.evidence_data_root/'outputs').is_dir())
        self.assertTrue(helper.cleanup(writers_absent=True)['safe_to_continue'])

    def test_ac18_missing_or_contaminated_snapshot_cannot_reach_probe_or_launch(self):
        for fault in ['missing', 'application', 'inference']:
            with self.subTest(fault=fault):
                workspace = self.runroot / 'workspace'
                if workspace.exists(): shutil.rmtree(workspace)
                if fault != 'missing':
                    workspace.mkdir(mode=0o700)
                    (workspace / 'literal.txt').write_text(KEY_A if fault == 'application' else INFERENCE_KEY)
                boundary = DockerBoundary()
                with self.assertRaises(client.ClientError): self.launch(boundary=boundary)
                self.assertEqual(boundary.events, [])
                self.assertTrue((self.project / 'original.txt').exists())

    def test_ac18_original_project_cannot_alias_owned_snapshot_subtree(self):
        nested = self.runroot / 'workspace/original-project'; nested.mkdir()
        with self.assertRaises(client.ClientError): self.admit(project=nested)

    def test_ac19_registry_capacity_or_aggregate_resource_failure_never_probes_or_launches(self):
        authority, grant = self.authority(); boundary = DockerBoundary()
        registry = ownership.Registry(self.root / 'registry', command=boundary.command)
        registry.bind_daemon('fixture-daemon')
        args = argparse.Namespace(platform='linux/arm64', native_platform='linux/arm64', uid=os.getuid(), gid=os.getgid())
        for fault in ('registry', 'aggregate'):
            pool = Allocator({'cpu_millis': 1500, 'memory_mib': 8192, 'pids_limit': 1024})
            manager = mock.patch.object(registry, 'require_capacity', side_effect=ownership.RegistryCapacityError()) if fault == 'registry' else mock.patch.object(registry, 'check_cancel')
            with manager, self.subTest(fault=fault), self.assertRaises(ValueError):
                client.OwnedHelper.start(authority, lab=boundary, args=args, registry=registry, allocator=pool,
                                         participant_resources={'cpu_millis': 1000, 'memory_mib': 2048, 'pids_limit': 256},
                                         popen=boundary.popen)
            self.assertEqual(boundary.events, [])
            self.assertIsNone(boundary.process)

    def test_ac18_wrong_architecture_or_lower_worker_reservation_rejects_without_launch(self):
        authority, grant = self.authority(); boundary = DockerBoundary()
        args = argparse.Namespace(platform='linux/amd64', native_platform='linux/amd64', uid=os.getuid(), gid=os.getgid())
        registry = ownership.Registry(self.root / 'registry', command=boundary.command)
        registry.bind_daemon('fixture-daemon')
        pool = Allocator({'cpu_millis': 4000, 'memory_mib': 8192, 'pids_limit': 1024})
        with self.assertRaises(client.ClientError):
            client.OwnedHelper.start(authority, lab=boundary, args=args, registry=registry, allocator=pool,
                                     participant_resources={'cpu_millis': 1000, 'memory_mib': 2048, 'pids_limit': 256}, popen=boundary.popen)
        args.platform = args.native_platform = 'linux/arm64'
        with self.assertRaises(client.ClientError):
            client.OwnedHelper.start(authority, lab=boundary, args=args, registry=registry, allocator=pool,
                                     participant_resources={'cpu_millis': 1000, 'memory_mib': 1, 'pids_limit': 256}, popen=boundary.popen)
        self.assertEqual(boundary.events, [])

    def test_ac19_docker_routing_environment_is_preserved_without_ambient_keys(self):
        selected = {'DOCKER_CONTEXT': 'fixture-selected-context', 'DOCKER_HOST': 'unix:///fixture/docker.sock',
                    'DOCKER_CONFIG': '/fixture/docker-config', 'DOCKER_TLS_VERIFY': '1',
                    'DOCKER_CERT_PATH': '/fixture/certificates', 'DOCKER_API_VERSION': '1.51',
                    'PI_APP_FORBIDDEN': KEY_A, 'OPENAI_API_KEY': INFERENCE_KEY}
        with mock.patch.dict(os.environ, selected):
            helper, boundary, registry, pool = self.launch()
            for key in client.DOCKER_ENVIRONMENT: self.assertEqual(boundary.env[key], selected[key])
            self.assertNotIn('PI_APP_FORBIDDEN', boundary.env); self.assertNotIn('OPENAI_API_KEY', boundary.env)
            self.assertTrue(helper.cleanup(writers_absent=True)['safe_to_continue'])

    def test_ac19_observed_wrong_image_architecture_blocks_before_launch(self):
        authority, grant = self.authority(); boundary = DockerBoundary()
        boundary.image_info = lambda image, platform: {'id': image, 'platform': 'linux/amd64'}
        with self.assertRaises(client.ClientError): self.launch(authority=authority, boundary=boundary)
        self.assertNotIn('Popen', boundary.events)
        self.assertFalse(any(isinstance(event, list) and event[1:3] == ['network', 'create'] for event in boundary.events))

    def test_ac20_unknown_writers_or_absence_quarantine_without_purge(self):
        for fault in ('participant-writer', 'helper-absence'):
            with self.subTest(fault=fault):
                helper, boundary, registry, pool = self.launch()
                path = helper.private_root
                if fault == 'helper-absence': boundary.absence = False
                receipt = helper.cleanup(writers_absent=(fault != 'participant-writer'))
                self.assertFalse(receipt['safe_to_continue']); self.assertTrue(path.exists())
                self.assertTrue(pool.closed)
                self.assertEqual(helper.record['status'], 'quarantined')
                with self.assertRaises(client.ClientError): helper.require_clean()
                self.assertEqual((self.project / 'original.txt').read_text(), 'Protected original input.\n')

    def test_ac20_failed_private_purge_quarantines_and_keeps_originals(self):
        helper, boundary, registry, pool = self.launch()
        with mock.patch.object(client.shutil, 'rmtree', side_effect=OSError('disposable purge failure')):
            receipt = helper.cleanup(writers_absent=True)
        self.assertFalse(receipt['safe_to_continue']); self.assertTrue(helper.private_root.exists())
        self.assertTrue(pool.closed); self.assertTrue((self.project / 'original.txt').exists())

    def test_ac20_generic_registry_recovery_refuses_unconfirmed_application_private_state(self):
        helper, boundary, registry, pool = self.launch()
        # Simulate the owner disappearing: generic recovery may stop the helper,
        # but it must refuse private state instead of silently marking it released.
        with self.assertRaises(ownership.RegistryError): registry.reconcile()
        self.assertTrue(helper.private_root.exists())
        self.assertNotEqual(next(r for r in registry.load() if r.get('application_helper'))['status'], 'released')

    def test_ac20_foreign_same_name_container_is_never_force_removed(self):
        for foreign in ['labels', 'image', 'mounts']:
            with self.subTest(foreign=foreign):
                helper, boundary, registry, pool = self.launch()
                boundary.foreign = foreign
                before = len(boundary.events)
                receipt = helper.cleanup(writers_absent=True)
                self.assertFalse(receipt['safe_to_continue'])
                self.assertFalse(any(isinstance(event, list) and event[1:3] == ['rm', '--force']
                                     for event in boundary.events[before:]))
                self.assertEqual(helper.record['status'], 'quarantined')
                # Test-owned local IPC process is disposable; this is not Docker
                # ownership cleanup or permission to delete the foreign container.
                boundary.process.terminate(); boundary.process.wait(timeout=5)
                boundary.process.stdout.close(); boundary.process.stderr.close()

    def test_ac20_startup_foreign_ownership_mismatch_quarantines_without_delete(self):
        for foreign in ['labels', 'image', 'mounts']:
            with self.subTest(foreign=foreign):
                boundary = DockerBoundary(); boundary.foreign = foreign
                try:
                    with self.assertRaises(client.ClientError): self.launch(boundary=boundary)
                    self.assertFalse(any(isinstance(event, list) and event[1:3] == ['rm', '--force']
                                         for event in boundary.events))
                    self.assertEqual(next(r for r in boundary.records() if r.get('application_helper'))['status'], 'quarantined')
                finally:
                    if boundary.process is not None:
                        boundary.process.terminate(); boundary.process.wait(timeout=5)
                        boundary.process.stdout.close(); boundary.process.stderr.close()

    def test_ac20_unsanitized_evidence_quarantines_and_retains_owned_store(self):
        helper, boundary, registry, pool = self.launch()
        (helper.evidence_root / 'unsafe.txt').write_text(KEY_A)
        receipt = helper.cleanup(writers_absent=True)
        self.assertFalse(receipt['safe_to_continue']); self.assertEqual(receipt['evidence'], 'quarantined')
        self.assertTrue(helper.evidence_root.exists()); self.assertTrue(helper.private_root.exists())
        self.assertTrue(pool.closed)

    def test_ac20_dirty_owned_snapshot_is_discarded_after_confirmed_absence(self):
        helper, boundary, registry, pool = self.launch()
        (self.runroot / 'workspace/leak.txt').write_text(KEY_A)
        receipt = helper.cleanup(writers_absent=True)
        self.assertFalse(receipt['safe_to_continue']); self.assertEqual(receipt['workspace'], 'discarded')
        self.assertFalse((self.runroot / 'workspace').exists())
        self.assertTrue((self.project / 'original.txt').exists())

    def test_ac17_stage_end_revokes_service_and_parent_worker_context(self):
        helper, boundary, registry, pool = self.launch(); grant = helper.authority._grants[0]
        self.request(boundary.port, grant)
        helper.revoke(grant)
        with self.assertRaises(client.ClientError): self.request(boundary.port, grant)
        with self.assertRaises(client.ClientError): helper.context(grant)
        with self.assertRaises(client.ClientError): helper.authority.grant('participant', binding(self.plan))


class StartupDiagnosticTests(BaseFixture):
    def process_output(self,body,*,stall=False):
        program='import sys,time;sys.stdout.buffer.write('+repr(body)+');sys.stdout.flush();'+('time.sleep(10)' if stall else 'sys.stderr.write("controlled stderr")')
        process=subprocess.Popen([sys.executable,'-I','-B','-c',program],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        def stop():
            if process.poll() is None:process.terminate();process.wait(timeout=2)
            process.stdout.close();process.stderr.close()
        self.addCleanup(stop);return process
    def diagnostic(self,body):
        authority,grant=self.authority();authority._inference_values.append('quoted-inference-"\\-canary')
        authority._budget_tokens={'controlled':'b'*64}
        helper=argparse.Namespace(authority=authority,process=self.process_output(body),
            reservations=[argparse.Namespace(capability='c'*64)],_participant_reservation=argparse.Namespace(capability='d'*64),
            name='pi-application-'+uuid.uuid4().hex[:16])
        result=client._startup_diagnostic(helper,'service_readiness',client.ClientError('evidence_unavailable'))
        payload=json.loads(Path(result['diagnostic']['path']).read_bytes())
        return helper,result,payload
    def test_complete_owned_pipes_are_retained_in_private_receipt_only(self):
        helper,result,payload=self.diagnostic(b'controlled stdout')
        self.assertEqual(payload['output_status'],'complete');self.assertEqual(payload['stdout'],'controlled stdout')
        self.assertEqual(payload['stderr'],'controlled stderr');self.assertNotIn('stdout',result)
        self.assertEqual(Path(result['diagnostic']['path']).stat().st_mode&0o777,0o600)
        self.assertEqual(client.validate_startup_failure(result,runroot=self.runroot),result)
    def test_all_authority_and_capability_classes_and_json_escapes_are_withheld(self):
        authority,grant=self.authority();authority._inference_values.append('quoted-inference-"\\-canary');authority._budget_tokens={'controlled':'b'*64}
        authority._values['participant']['second-known-alias']=KEY_B
        helper=argparse.Namespace(authority=authority,reservations=[argparse.Namespace(capability='c'*64)],
            _participant_reservation=argparse.Namespace(capability='d'*64))
        values=[KEY_A,KEY_B,INFERENCE_KEY,authority._control_token,grant.capability,'b'*64,'c'*64,'d'*64,'quoted-inference-"\\-canary']
        for value in values:
            for escaped in (value,json.dumps(value)[1:-1]):
                helper.name='pi-application-'+uuid.uuid4().hex[:16];helper.process=self.process_output(escaped.encode())
                result=client._startup_diagnostic(helper,'service_readiness',client.ClientError('evidence_unavailable'))
                payload=json.loads(Path(result['diagnostic']['path']).read_bytes())
                self.assertEqual(payload['output_status'],'withheld');self.assertEqual((payload['stdout'],payload['stderr']),('',''))
                self.assertNotIn(value,json.dumps(result)+json.dumps(payload))
    def test_invalid_utf8_control_bytes_truncation_and_timeout_never_retain_partial_output(self):
        for body in (b'unsafe\xff',b'unsafe\x00',b'unsafe\x1b',b'unsafe\x7f','unsafe\u0085'.encode()):
            _,_,payload=self.diagnostic(body);self.assertEqual(payload['output_status'],'withheld')
        for process in (self.process_output(b'x'*4096),self.process_output(b'partial',stall=True)):
            result=client._startup_output(process,maximum=1024,seconds=.2)
            self.assertEqual(result,{'status':'withheld','stdout':b'','stderr':b''})
    def test_unknown_phase_reason_and_forged_descriptors_cannot_enter_parent_projection(self):
        _,result,_=self.diagnostic(b'safe')
        variants=[{**result,'phase':'hostile-private-value'},{**result,'reason':'hostile-private-value'},{**result,'extra':True},
            {**result,'diagnostic':{'path':str(self.root/'foreign.json'),'sha256':'a'*64}},
            {**result,'diagnostic':{**result['diagnostic'],'sha256':'not-a-digest'}}]
        for value in variants:
            with self.subTest(value=value),self.assertRaises(ValueError):client.validate_startup_failure(value,runroot=self.runroot)


if __name__ == '__main__':
    unittest.main()
