"""A10 budget-only parent/lifecycle tests with real ledgers and mocked Docker/IPC.

No Docker daemon, sockets, Pi, model or browser is started. In-process service
calls exercise the private bootstrap and control protocol behind the fake launch.
"""
import argparse
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'skill/scripts'), str(ROOT / 'skill/runtime')]
import application_client as owned
import application_client_service as service
import native_budget_client as native_client
import native_budget_service
import native_tool_contracts
import ownership_registry
from parallel_allocator import Allocator
from tool_budgets import BudgetError

CANARY = 'synthetic-budget-private-canary-123456'
WEIGHT = {'cpu_millis': 1000, 'memory_mib': 2048, 'pids_limit': 256}


class FakeProcess:
    def __init__(self):
        self.stdin, self.stdout, self.stderr = io.BytesIO(), io.BytesIO(), io.BytesIO()
        self.running = True
    def poll(self): return None if self.running else 0
    def wait(self, timeout=None): self.running = False; return 0
    def kill(self): self.running = False


class BudgetDockerFixture:
    """Only the Docker ownership boundary is synthetic; service/ledgers are real."""
    def __init__(self, case, registry):
        self.case, self.registry = case, registry
        self.events, self.argv, self.environment, self.bootstrap = [], None, None, None
        self.process, self.helper_service = None, None
        self.networks = {}; self.network_id = 'a' * 64
        self.network_mismatch = None; self.container_network_id = None

    def image_info(self, image, platform):
        self.events.append(['image_info', image, platform])
        return {'id': image, 'platform': platform}

    def command(self, argv, **kwargs):
        self.events.append(list(argv))
        result = subprocess.CompletedProcess(argv, 0, '', '')
        if argv[1:2] == ['info']:
            result.stdout = 'fixture-daemon'
        elif argv[1:3] == ['network', 'create']:
            labels = {}
            for index, item in enumerate(argv):
                if item == '--label':
                    key, value = argv[index + 1].split('=', 1); labels[key] = value
            self.networks[argv[-1]] = labels
        elif argv[1:3] == ['network', 'inspect']:
            name = argv[-1]
            if name not in self.networks:
                result.returncode = 1; result.stderr = 'network ' + name + ' not found'
            else:
                data = {'Id': self.network_id, 'Driver': 'bridge', 'Labels': self.networks[name],
                        'Containers': {'external-participant': {}} if name.startswith('borrowed-') else {}}
                if self.network_mismatch == 'labels': data['Labels'] = {}
                elif self.network_mismatch == 'driver': data['Driver'] = 'host'
                elif self.network_mismatch == 'id': data['Id'] = 'not-a-container-network-id'
                elif self.network_mismatch == 'id-format': data['Id'] = 'g' * 64
                result.stdout = json.dumps([data])
        elif argv[1:3] == ['network', 'rm']:
            self.networks.pop(argv[-1], None)
        elif argv[1:3] == ['rm', '--force']:
            if self.process is not None: self.process.running = False
        elif argv[1:3] == ['container', 'inspect']:
            if self.process is None or not self.process.running:
                result.returncode = 1; result.stderr = 'No such container: '+argv[-1]
            else:
                record = next(record for record in self.registry.load() if record.get('application_helper'))
                network = self.argv[self.argv.index('--network') + 1]
                data = {'Id': 'f' * 64, 'Image': record['image'], 'Config': {'Labels': {
                    ownership_registry.LABEL: record['launch_id'], ownership_registry.REGISTRY_LABEL: self.registry.registry_id}},
                    'Mounts': [{'Source': mount['source'], 'Destination': mount['target'], 'RW': mount['rw']} for mount in record['mounts']],
                    'HostConfig': {'NanoCpus': 1000000000, 'Memory': 512 * 1024**2,
                                   'MemorySwap': 512 * 1024**2, 'PidsLimit': 128},
                    'NetworkSettings': {'Ports': {'8081/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '48888'}]},
                                        'Networks': {network: {'NetworkID': self.container_network_id or self.network_id}}}}
                result.stdout = json.dumps([data])
        return result

    def popen(self, argv, **kwargs):
        self.events.append(['Popen'])
        self.argv, self.environment = argv, kwargs['env']
        self.case.assertTrue(any(record.get('application_helper') and record['status'] == 'intent' for record in self.registry.load()))
        self.process = FakeProcess()
        return self.process

    def bootstrap_pipe(self, process, body):
        self.bootstrap = body
        config = json.loads(body)
        mounts = {}
        for index, item in enumerate(self.argv):
            if item == '--mount':
                fields = dict(part.split('=', 1) for part in self.argv[index + 1].split(',') if '=' in part)
                mounts[fields['dst']] = fields['src']
        config['evidence_root'] = mounts['/pi-client/evidence']
        config['state_root'] = mounts['/pi-client/state']
        code = Path(mounts['/opt/pi-application'])
        def verify(identity):
            self.case.assertEqual(set(identity), set(service.TRUSTED_CODE))
            self.case.assertEqual(identity, {name: hashlib.sha256((code / name).read_bytes()).hexdigest() for name in identity})
        self.helper_service = native_budget_service.BudgetOnlyService(config, verify_code=verify, clock=lambda: 1000)

    def request(self, host, port, path, bearer, body):
        self.case.assertEqual(host, '127.0.0.1'); self.case.assertEqual(port, 48888)
        return self.helper_service.request(path, bearer, body)


class NativeBudgetClientTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='native-budget-client-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.project = self.root / 'project'; self.project.mkdir(mode=0o700)
        (self.project / 'source.txt').write_text('immutable original\n')
        self.runroot = self.root / 'run'; self.runroot.mkdir(mode=0o700)
        (self.runroot / 'workspace').mkdir(mode=0o700)
        self.runtime = {'pi_release': '1.2.0', 'image_id': 'sha256:' + 'a' * 64,
                        'platform': 'linux/arm64', 'container_profile': 'core',
                        'resources': {'schema': 1, 'runtime': {'cpus': 1, 'memory': '2g', 'pids_limit': 256, 'jobs': 1}}}
        self.task = {'name': 'developer', 'tools': ['read', 'edit', 'budget_status'],
                     'timeout_seconds': 300, 'max_turns': 16, 'max_total_tokens': 64000,
                     'max_tool_calls': 32, 'reporting_reserve_calls': 6, 'reporting_reserve_seconds': 30}
        self.args = argparse.Namespace(platform='linux/arm64', native_platform='linux/arm64', uid=os.getuid(), gid=os.getgid())
        self.registry = ownership_registry.Registry(self.root / 'registry')
        self.registry.bind_daemon('fixture-daemon')
        self.pool = Allocator({'cpu_millis': 4000, 'memory_mib': 8192, 'pids_limit': 1024})
        self.lab = BudgetDockerFixture(self, self.registry)
        self.registry.command = self.lab.command

    def authority(self, *, task=None, runtime=None, profile='builtin'):
        return native_client.NativeBudgetAuthority(runtime=self.runtime if runtime is None else runtime,
            task=self.task if task is None else task, plan_sha256='b' * 64,
            project=self.project, runroot=self.runroot, profile=profile, redaction_values=[CANARY])

    def grant(self, authority):
        binding = {name: str(uuid.uuid4()) for name in service.BINDING_FIELDS - {'plan_sha256', 'trial_id'}}
        binding.update(trial_id=None, plan_sha256='b' * 64)
        return authority.grant('developer', binding)

    def external_reservation(self, grant, **changes):
        binding = {'generation': self.registry.generation, 'workspace': str(self.runroot / 'workspace'),
                   **{name: grant.scope[name] for name in ('run_id', 'attempt_id', 'trial_id', 'stage_id')}}
        binding.update(changes)
        item = self.pool.request('external-' + uuid.uuid4().hex, binding, WEIGHT, 30, 'stage')
        self.pool.dispatch()
        self.pool.consume(item.identity, item.capability, item.binding, item.resources)
        self.pool.running(item.identity)
        return item

    def borrowed_network(self):
        record = self.registry.network_intent('borrowed-fixture-network')
        self.lab.networks[record['container']] = {ownership_registry.LABEL: record['launch_id'],
                                                ownership_registry.REGISTRY_LABEL: self.registry.registry_id}
        return record

    def launch(self, authority=None, *, external=None, network=None):
        authority = authority or self.authority()
        if not authority._grants: self.grant(authority)
        with mock.patch.object(owned, '_send_bootstrap', side_effect=self.lab.bootstrap_pipe), \
             mock.patch.object(owned, '_ready', return_value={'schema': 1, 'status': 'ready', 'business_effects_enabled': False}), \
             mock.patch.object(owned, '_request', side_effect=self.lab.request):
            helper = owned.OwnedHelper.start(authority, lab=self.lab, args=self.args, registry=self.registry,
                allocator=self.pool, participant_resources=WEIGHT, participant_reservation=external,
                borrowed_network=network, popen=self.lab.popen)
        self.addCleanup(lambda: self.cleanup(helper))
        return helper

    def cleanup(self, helper):
        with mock.patch.object(owned, '_request', side_effect=self.lab.request):
            return helper.cleanup(writers_absent=True)

    def test_constructor_preserves_input_and_admits_only_exact_native_declarations(self):
        before = copy.deepcopy((self.runtime, self.task))
        authority = self.authority(); grant = self.grant(authority)
        self.assertEqual((self.runtime, self.task), before)
        self.assertEqual(authority.tools, native_tool_contracts.selected_tools('1.2.0', self.task['tools']))
        self.assertEqual(authority.preparation, {'read': 'none', 'edit': 'reviewed_pure', 'budget_status': 'none'})
        context = authority.budget_context(grant, 'c' * 64)
        self.assertEqual(context['tool_schema_sha256'], owned.c.digest(sorted(authority.tools, key=lambda tool: tool['name'])))
        self.assertEqual(context['base_url'], 'http://pi-application:8081/budget')
        self.assertNotEqual(context['capability'], grant.capability)
        self.assertNotIn(CANARY, json.dumps(context) + repr(authority) + repr(grant))
        spec = authority.launch_spec(); spec['runtime']['image_id'] = 'changed'
        self.assertEqual(authority.launch_spec()['runtime']['image_id'], self.runtime['image_id'])

    def test_missing_or_partial_native_budget_tuple_never_creates_helper(self):
        for fields in [[], ['max_tool_calls'], ['max_tool_calls', 'reporting_reserve_calls']]:
            task = {key:value for key,value in self.task.items() if key not in ('max_tool_calls', 'reporting_reserve_calls', 'reporting_reserve_seconds') or key in fields}
            original = copy.deepcopy(task)
            with self.subTest(fields=fields), self.assertRaises(ValueError): self.authority(task=task)
            self.assertEqual(task, original)
        self.assertEqual(self.lab.events, [])

    def test_unknown_tools_release_profile_or_missing_status_are_rejected_at_admission(self):
        for tools, profile in [(['powershell', 'budget_status'], 'builtin'),
                               (['read'], 'builtin'), (['read', 'fixture_lookup', 'budget_status'], 'builtin'),
                               (['read', 'budget_status'], 'fixture-lookup')]:
            task = {**self.task, 'tools': tools}
            with self.subTest(tools=tools, profile=profile), self.assertRaises(ValueError): self.authority(task=task, profile=profile)
        runtime = {**self.runtime, 'pi_release': 'latest'}
        with self.assertRaises(ValueError): self.authority(runtime=runtime)
        self.assertEqual(self.lab.events, [])

    def test_fixture_profile_uses_the_preserved_native_schema(self):
        task = {**self.task, 'tools': ['read', 'fixture_lookup', 'budget_status']}
        authority = self.authority(task=task, profile='fixture-lookup')
        self.assertEqual(authority.tools, native_tool_contracts.selected_tools('1.2.0', task['tools']))

    def test_grants_require_exact_stage_plan_and_one_prepared_invocation(self):
        authority = self.authority(); grant = self.grant(authority)
        with self.assertRaises(ValueError): self.grant(authority)
        with self.assertRaises(ValueError): authority.budget_context(owned.Grant(grant.scope, 'f' * 64), 'c' * 64)
        with self.assertRaises(ValueError): authority.budget_context(grant, 'invalid')
        other = self.authority()
        bound = {key:value for key,value in grant.scope.items() if key in service.BINDING_FIELDS}; bound['plan_sha256'] = 'd' * 64
        with self.assertRaises(ValueError): other.grant('developer', bound)

    def test_cached_limits_schemas_and_preparation_cannot_change_after_admission(self):
        for field in ['limits', 'tools', 'preparation', 'task', 'runtime']:
            authority = self.authority(); self.grant(authority)
            if field == 'limits': authority.limits['max_tool_calls'] = 500
            elif field == 'tools': authority.tools[0]['parameters']['additionalProperties'] = False
            elif field == 'preparation': authority.preparation['edit'] = 'none'
            elif field == 'task': authority.task['max_tool_calls'] = 500
            else: authority.runtime['image_id'] = 'sha256:' + 'd' * 64
            with self.subTest(field=field), self.assertRaises(ValueError): self.launch(authority)
            self.assertNotIn(['Popen'], self.lab.events)

    def test_budget_only_bootstrap_has_no_application_route_or_persisted_keys(self):
        helper = self.launch(); authority = helper.authority; grant = authority._grants[0]
        config = json.loads(self.lab.bootstrap)
        self.assertEqual(config['mode'], 'budget-only')
        for field in ['application', 'plan', 'operations', 'authorities', 'credentials']:
            self.assertNotIn(field, config)
        self.assertEqual(config['stage']['tools'], native_tool_contracts.selected_tools('1.2.0', self.task['tools']))
        public = json.dumps(self.lab.argv) + json.dumps(self.lab.environment) + json.dumps(self.registry.load())
        for secret in [CANARY, grant.capability, authority._control_token, *authority._budget_tokens.values()]:
            self.assertNotIn(secret, public)
            for path in self.runroot.rglob('*'):
                if path.is_file(): self.assertNotIn(secret.encode(), path.read_bytes())
        for route in ['/app_api', '/api', '/proxy', '/files']:
            with self.assertRaises(ValueError): self.lab.helper_service.request(route, grant.capability, {})
        self.assertTrue(self.cleanup(helper)['safe_to_continue'])
        self.assertTrue((self.project / 'source.txt').exists())

    def test_dirty_snapshot_and_requested_or_observed_native_mismatch_never_popen(self):
        (self.runroot / 'workspace/secret.txt').write_text(CANARY)
        with self.assertRaises(ValueError): self.launch()
        self.assertEqual(self.lab.events, [])
        (self.runroot / 'workspace/secret.txt').unlink()
        self.args.native_platform = 'linux/amd64'
        with self.assertRaises(ValueError): self.launch()
        self.assertEqual(self.lab.events, [])
        self.args.native_platform = 'linux/arm64'
        self.lab.image_info = lambda image, platform: {'id': image, 'platform': 'linux/amd64'}
        with self.assertRaises(ValueError): self.launch()
        self.assertNotIn(['Popen'], self.lab.events)

    def test_external_stage_and_borrowed_network_are_never_released_by_helper_cleanup(self):
        authority = self.authority(); grant = self.grant(authority)
        external = self.external_reservation(grant); borrowed = self.borrowed_network()
        helper = self.launch(authority, external=external, network=borrowed)
        self.assertIs(helper.participant_reservation, external)
        self.assertEqual(len(helper.reservations), 1)
        self.assertTrue(helper.borrowed_network)
        network_before = copy.deepcopy(next(record for record in self.registry.load() if record['launch_id'] == borrowed['launch_id']))
        self.assertTrue(self.cleanup(helper)['safe_to_continue'])
        self.assertEqual(external.state, 'running')
        self.assertEqual(network_before, next(record for record in self.registry.load() if record['launch_id'] == borrowed['launch_id']))
        self.assertIn(borrowed['container'], self.lab.networks)
        self.assertFalse(any(isinstance(event, list) and event[1:3] in (['network', 'create'], ['network', 'rm']) for event in self.lab.events))

    def test_invalid_external_reservations_cannot_admit_a_helper(self):
        for fault in ['unknown', 'generation', 'resources', 'released', 'other-stage', 'other-attempt', 'other-trial', 'workspace']:
            authority = self.authority(); grant = self.grant(authority)
            changes = {}
            if fault == 'generation': changes['generation'] = str(uuid.uuid4())
            elif fault == 'other-stage': changes['stage_id'] = str(uuid.uuid4())
            elif fault == 'other-attempt': changes['attempt_id'] = str(uuid.uuid4())
            elif fault == 'other-trial': changes['trial_id'] = str(uuid.uuid4())
            elif fault == 'workspace': changes['workspace'] = str(self.project)
            item = self.external_reservation(grant, **changes)
            if fault == 'unknown': self.pool.records.pop(item.identity)
            elif fault == 'resources': item.resources = {**WEIGHT, 'memory_mib': 1024}
            elif fault == 'released': self.pool.release(item.identity, True, True)
            self.lab.events.clear()
            with self.subTest(fault=fault), self.assertRaises(ValueError): self.launch(authority, external=item)
            self.assertNotIn(['Popen'], self.lab.events)
            if item.identity in self.pool.records and item.state in ('reserved', 'launching', 'running'):
                self.pool.release(item.identity, True, True)

    def test_borrowed_network_registry_and_docker_identity_must_match(self):
        for fault in ['foreign-registry', 'unregistered-record', 'labels', 'driver', 'id', 'id-format', 'container-network']:
            authority = self.authority(); grant = self.grant(authority)
            external = self.external_reservation(grant); network = self.borrowed_network()
            if fault == 'foreign-registry': network['registry'] = 'foreign'
            elif fault == 'unregistered-record': network['created_at'] += '-not-the-record'
            elif fault == 'container-network': self.lab.container_network_id = 'b' * 64
            else: self.lab.network_mismatch = fault
            self.lab.events.clear()
            with self.subTest(fault=fault), self.assertRaises(ValueError): self.launch(authority, external=external, network=network)
            if fault != 'container-network': self.assertNotIn(['Popen'], self.lab.events)
            self.assertFalse(any(isinstance(event, list) and event[1:3] == ['network', 'rm'] for event in self.lab.events))
            self.assertEqual(external.state, 'running')
            self.pool.release(external.identity, True, True)
            self.lab.network_mismatch = None; self.lab.container_network_id = None
            self.lab.networks.clear()
            # Each case is a separate controlled registry/resource epoch.
            for path in self.registry.root.glob('*.json'): path.unlink()


if __name__ == '__main__':
    unittest.main()
