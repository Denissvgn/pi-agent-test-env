"""Closed SDK admission is pure and precedes provider/native/private operations."""
import copy
import hashlib
import json
from pathlib import Path
import sys
from unittest import TestCase, mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skill/scripts'))
from operation_sdk import policy


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def example_policy(operation='plan_validate_source_v1'):
    sdk = {name: 'a' * 64 for name in policy.CONSUMER_FILES}
    files = {'scripts/application_contracts.py': 'b' * 64, 'runtime/prompt_contract.py': 'c' * 64,
             'scripts/resources.py': 'd' * 64, 'MANIFEST.sha256': 'e' * 64}
    files.update({'scripts/operation_sdk/' + name: pin for name, pin in sdk.items()})
    return dict(schema=1, document_type='operation_sdk_policy', policy_id='12345678-1234-4234-8234-123456789abc',
        actor_id='87654321-4321-4321-8321-cba987654321', participant_id='root', stage_id='prepare', operation=operation,
        deployment=dict(profile='linux_arm64_cpython_3_12_13', provider_root='/opt/provider',
            provider_files=files, provider_sizes={name: 100 for name in files}, provider_inventory_sha256=digest(files),
            modules={'application_contracts': 'scripts/application_contracts.py',
                     'resources': 'scripts/resources.py', 'prompt_contract': 'runtime/prompt_contract.py'}, resources={},
            consumer_root='/opt/provider/scripts/operation_sdk', consumer_files=sdk,
            python_path='/usr/local/bin/python3.12', python_sha256='f' * 64,
            runtime_files={'/usr/local/bin/python3.12': 'f' * 64},
            runtime_sizes={'/usr/local/bin/python3.12': 16000},
            runtime_modules={name: {'kind': 'built-in', 'path': None, 'spec_name': name} for name in ('builtins', 'sys')},
            mapped_files=['/usr/local/bin/python3.12']),
        input=dict(source_id='11111111-1111-4111-8111-111111111111', kind='pipe', identity=[17, 23], maximum_bytes=65536),
        scope=dict(base=None, profile=None, resource=None, dependencies=[], metadata=[], external_bindings=False,
                   store=None, coordination=None, references=[], write_reference=None, value_contract=None),
        limits=dict(max_control_bytes=524288, max_payload_bytes=1048576, max_result_bytes=2097152,
            failure_reserve_bytes=8192, max_read_refs=128, max_ref_bytes=16384, max_read_bytes=1048576,
            max_pattern_count=4096, max_pattern_bytes=8388608, max_regex_bytes=16777216,
            max_owned_fds=48, max_mutating_calls=4096, max_runtime_millis=30000,
            max_memory_bytes=536870912, max_pids=128, max_cpu_millis=30000, max_cpu_millicores=1000,
            max_source_files=4096, max_source_file_bytes=67108864, max_source_bytes=134217728,
            max_runtime_modules=512, max_native_libraries=64,
            max_dependency_file_bytes=16777216, max_dependency_bytes=67108864,
            max_secret_bytes=1024, max_plan_agents=1, max_plan_checks=20, max_plan_setup=20,
            max_prompt_bytes=8192, max_scorer_assets=0))


def example_request(value):
    return dict(schema=1, document_type='operation_sdk_request', operation=value['operation'],
        policy_sha256=digest(value), actor_id=value['actor_id'],
        participant_id=value['participant_id'], stage_id=value['stage_id'],
        operation_id='22222222-2222-4222-8222-222222222222',
        request_id='33333333-3333-4333-8333-333333333333',
        worker_id='44444444-4444-4444-8444-444444444444',
        channel_id='55555555-5555-4555-8555-555555555555',
        source_id=value['input']['source_id'] if value['input'] is not None else None,
        created_ns=100, expires_ns=1000000100)


class OperationPolicyTests(TestCase):
    def compile(self, value, request=None, **kwargs):
        return policy.compile_admission(value, example_request(value) if request is None else request,
            trusted_policy_sha256=digest(value), now_ns=100, **kwargs)

    def test_valid_admission_is_pure_immutable_and_grants_only_selected_operation(self):
        value = example_policy()
        with (mock.patch('os.open', side_effect=AssertionError('preflight native lookup')),
              mock.patch('builtins.open', side_effect=AssertionError('preflight provider lookup'))):
            compiled = self.compile(value)
        self.assertEqual(compiled.operation, 'plan_validate_source_v1')
        self.assertFalse(compiled.operational_approval)
        body = compiled.policy(); value['deployment']['modules'].clear()
        compiled.policy()['deployment']['modules'].clear()
        self.assertEqual(compiled.policy(), body)

    def test_external_trusted_digest_cannot_be_taken_from_request_or_provider(self):
        value = example_policy()
        for pin in (None, '', '0' * 64, True, 'b' * 64):
            with self.subTest(pin=pin), self.assertRaises(policy.PolicyError):
                policy.compile_admission(value, example_request(value), trusted_policy_sha256=pin, now_ns=100)

    def test_closed_fields_exact_types_and_whole_string_bindings(self):
        changes = [('schema', True), ('schema', 1.0), ('operation', 'arbitrary_cli'),
                   ('actor_id', '87654321-4321-4321-8321-cba987654321\n'),
                   ('deployment.provider_root', '/opt/../provider'), ('deployment.python_sha256', 'f' * 64 + '\n'),
                   ('limits.max_owned_fds', True), ('limits.max_payload_bytes', 100000000),
                   ('limits.max_cpu_millis', 1500),
                   ('scope.write_reference', 'APP_REAL'), ('extra', True)]
        for dotted, replacement in changes:
            value = example_policy(); parent = value; parts = dotted.split('.')
            for part in parts[:-1]: parent = parent[part]
            parent[parts[-1]] = replacement
            with self.subTest(field=dotted), self.assertRaises(policy.PolicyError): self.compile(value)

    def test_request_operation_actor_source_and_lifetime_are_exact(self):
        value = example_policy()
        for field, change in [('operation', 'redact_bytes_v1'), ('actor_id', '00000000-0000-4000-8000-000000000000'),
                              ('source_id', '66666666-6666-4666-8666-666666666666'),
                              ('created_ns', True), ('expires_ns', 100), ('expires_ns', 1000000000000)]:
            request = example_request(value); request[field] = change
            with self.subTest(field=field), self.assertRaises(policy.PolicyError): self.compile(value, request)

    def test_verification_forecast_counts_both_passes_and_bootstrap_before_lookup(self):
        value=example_policy();value['limits']['max_source_files']=len(value['deployment']['provider_files'])
        with (mock.patch('os.open',side_effect=AssertionError('lookup before file forecast')),
              self.assertRaises(policy.PolicyError)):
            self.compile(value)

    def test_descriptor_forecast_includes_the_full_provider_tree(self):
        value=example_policy();name='examples/'+'/'.join(['nested']*20)+'/fixture.json'
        value['deployment']['provider_files'][name]='a'*64;value['deployment']['provider_sizes'][name]=1
        value['deployment']['provider_inventory_sha256']=digest(value['deployment']['provider_files'])
        value['limits']['max_owned_fds']=16
        with (mock.patch('os.open',side_effect=AssertionError('lookup before full tree forecast')),
              self.assertRaises(policy.PolicyError)):
            self.compile(value)

    def test_provider_module_resource_and_runtime_closure_is_independently_bound(self):
        for mutate in ('module', 'runtime', 'sdk', 'inventory'):
            value = example_policy()
            if mutate == 'module': value['deployment']['modules']['other'] = '../unapproved.py'
            elif mutate == 'runtime': value['deployment']['mapped_files'] = ['/unapproved/lib.so']
            elif mutate == 'sdk': del value['deployment']['consumer_files']['worker.py']
            else: value['deployment']['provider_inventory_sha256'] = 'b' * 64
            with self.subTest(mutation=mutate), self.assertRaises(policy.PolicyError): self.compile(value)

    def test_private_operations_require_exact_existing_store_and_coordination(self):
        for operation in ('credentials_collect_v1', 'redact_bytes_v1', 'secret_register_create_only_v1'):
            with self.subTest(operation=operation), self.assertRaises(policy.PolicyError):
                self.compile(example_policy(operation))

    def test_registration_never_inherits_reader_or_default_store_authority(self):
        value = example_policy('secret_register_create_only_v1')
        value['deployment']['modules'] = {}
        value['scope'].update(store={'path': '/private/store', 'identity': [17, 25]},
                              coordination={'path': '/private/coord.lock', 'identity': [17, 26]},
                              write_reference='APP_FAKE', value_contract='application_credential_1',
                              references=[{'reference': 'INFERENCE_FAKE', 'alias': None, 'role': 'inference',
                                'value_contract': 'normalized_secret_1', 'identity': [17, 28],
                                'size': 32, 'mtime_ns': 10, 'ctime_ns': 10}])
        compiled = self.compile(value)
        self.assertEqual(compiled.policy()['scope']['write_reference'], 'APP_FAKE')
        for change in ('missing_coordination', 'code_overlap', 'bad_name', 'read_overlap'):
            trial = copy.deepcopy(value)
            if change == 'missing_coordination': trial['scope']['coordination'] = None
            elif change == 'code_overlap': trial['scope']['store']['path'] = '/opt/provider/keys'
            elif change == 'bad_name': trial['scope']['write_reference'] = 'APP_FAKE\n'
            else: trial['scope']['references'] = [{'reference': 'APP_FAKE', 'alias': 'PI_APP_KEY',
                'role': 'application', 'identity': [17, 27], 'size': 32, 'mtime_ns': 10, 'ctime_ns': 10}]
            with self.subTest(change=change), self.assertRaises(policy.PolicyError): self.compile(trial)

    def test_legacy_dependencies_are_closed_explicit_and_read_only(self):
        value = example_policy('plan_validate_legacy_v1')
        with self.assertRaises(policy.PolicyError): self.compile(value)
        value['scope']['base'] = '/opt/project'
        value['scope']['dependencies'] = [{'path': '/opt/project/prompt.txt', 'sha256': 'a' * 64,
                                           'maximum_bytes': 4096, 'role': 'prompt'}]
        self.assertEqual(self.compile(value).operation, value['operation'])
        value['scope']['dependencies'].append(dict(value['scope']['dependencies'][0]))
        with self.assertRaises(policy.PolicyError): self.compile(value)

    def test_dependency_cannot_disagree_with_an_overlapping_resource_hash(self):
        value=example_policy('plan_validate_legacy_v1');root=value['deployment']['provider_root']
        name='assets/prompt.txt';value['deployment']['provider_files'][name]='a'*64
        value['deployment']['provider_sizes'][name]=64;value['deployment']['resources'][name]='a'*64
        value['deployment']['provider_inventory_sha256']=digest(value['deployment']['provider_files'])
        value['scope']['base']=root+'/assets';value['scope']['dependencies']=[dict(path=root+'/'+name,
            sha256='b'*64,maximum_bytes=1,role='prompt')]
        with (mock.patch('os.open',side_effect=AssertionError('overlap before lookup')),self.assertRaises(policy.PolicyError)):
            self.compile(value)

    def test_unambiguous_domain_bound_context_changes_with_each_request_binding(self):
        value = example_policy(); first = self.compile(value)
        request = example_request(value); request['channel_id'] = '66666666-6666-4666-8666-666666666666'
        second = self.compile(value, request)
        self.assertNotEqual(first.context_sha256, second.context_sha256)
        self.assertEqual(first.context_sha256, self.compile(value).context_sha256)

    def test_browser_resource_read_does_not_grant_module_or_cli_permission(self):
        value = example_policy('resource_read_v1'); value['input'] = None
        value['deployment']['provider_files']['assets/browser-policy.json'] = 'a' * 64
        value['deployment']['provider_sizes']['assets/browser-policy.json'] = 25583
        value['deployment']['resources']['assets/browser-policy.json'] = 'a' * 64
        value['deployment']['modules'] = {}
        value['deployment']['provider_inventory_sha256'] = digest(value['deployment']['provider_files'])
        value['scope']['resource'] = {'path': 'assets/browser-policy.json', 'maximum_bytes': 65536}
        request = example_request(example_policy()); request.update(operation=value['operation'],
            policy_sha256=digest(value), source_id=None)
        compiled = self.compile(value, request)
        self.assertEqual(compiled.operation, 'resource_read_v1')
        value['scope']['resource']['path'] = 'scripts/pi_lab.py'
        with self.assertRaises(policy.PolicyError): self.compile(value)
