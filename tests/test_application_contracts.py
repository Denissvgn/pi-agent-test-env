"""A01 offline independent contract oracles; fixtures do not qualify a live runtime.

Golden predecessor hashes were captured before the application implementation.
Historical receipts are copied byte-for-byte, never migrated by these tests.
"""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

REPOSITORY = Path(__file__).resolve().parents[1]
SKILL = REPOSITORY / 'skill'
FIXTURES = Path(__file__).resolve().parent / 'fixtures/application-contracts'
sys.path[:0] = [str(SKILL / 'scripts'), str(SKILL / 'runtime')]
import application_contracts as contracts
import agent_profiles
import experiments
import outcomes
import pi_lab as lab
import provenance
import release_contracts
import application_runtime_contracts

POSITIVE = json.loads((FIXTURES / 'positive.json').read_text())
BASELINE = json.loads((FIXTURES / 'legacy-baseline.json').read_text())


def independent_canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def independent_digest(value):
    return hashlib.sha256(independent_canonical(value)).hexdigest()


def execution_fixture():
    """Deliberately construct final IR independently of the implementation."""
    source = copy.deepcopy(POSITIVE['source'])
    source['document_type'] = 'application_execution_plan'
    source['compiler_contract'] = {'id': 'application-plan-v1', 'revision': 1,
                                   'sha256': '1' * 64}
    source['input_hashes'] = {name: '2' * 64 for name in
                             ('source', 'profiles', 'prompt_renderer', 'operations',
                              'completion', 'scorers', 'release_contract', 'runner')}
    for stage in source['stages']:
        stage['effective_prompt'] = stage.pop('prompt')
        prompt_bytes = len(stage['effective_prompt'].encode())
        stage['tools'] = ['app_api', 'artifact_read', 'artifact_write',
                          'report_write', 'budget_status']
        stage['prompt_admission'] = {
            'method': 'conservative_bytes', 'prompt_bytes': prompt_bytes,
            'tool_schema_bytes': 4096, 'framing_upper_bound': 1024,
            'reply_tokens': 4096, 'history_reserve_tokens': 2048,
            'context_window': 32768, 'total_upper_bound': prompt_bytes + 11264}
        stage['profile_binding'] = {'id': 'application-client', 'pi_release': '1.2.0',
                                    'sha256': '3' * 64, 'assets': {'adapter.mjs': '4' * 64}}
        stage['inference_binding'] = {
            'kind': 'legacy', 'configuration_sha256': '5' * 64,
            'context_window': 32768, 'max_tokens': 4096, 'input_modalities': ['text'],
            'selection': {'owner': 'compiler_input', 'id': 'diagnostic-input'}}
        stage['resolved_operations'] = copy.deepcopy(source['application']['operations'])
        stage['tool_schemas'] = json.loads((FIXTURES / 'native-tools.json').read_text())
    for check in source['checks']:
        if 'scorer' in check:
            check['scorer']['assets'] = [
                {'target': asset['target'], 'sha256': '6' * 64}
                for asset in check['scorer']['assets']]
    source['plan_sha256'] = independent_digest(source)
    return source


class StrictContractTests(unittest.TestCase):
    def source(self):
        return copy.deepcopy(POSITIVE['source'])

    def reject(self, validator, value, pointer=None, reason=None):
        before = copy.deepcopy(value)
        with self.assertRaises(contracts.ContractError) as captured:
            validator(value)
        error = captured.exception
        self.assertIsInstance(error.reason, str)
        self.assertTrue(error.reason)
        self.assertIsInstance(error.pointer, str)
        self.assertTrue(error.pointer == '' or error.pointer.startswith('/'))
        if pointer is not None:
            self.assertTrue(error.pointer.startswith(pointer), error.pointer)
        if reason is not None:
            self.assertEqual(error.reason, reason)
        self.assertEqual(value, before)
        return error

    def test_ac01_positive_envelopes_are_explicit_idempotent_and_deep_copied(self):
        cases = [(contracts.validate_source, POSITIVE['source']),
                 (contracts.validate_operation, POSITIVE['source']['application']['operations'][0]),
                 (contracts.validate_completion, POSITIVE['source']['stages'][0]['completion']),
                 (contracts.validate_report, POSITIVE['report'])]
        cases += [(contracts.validate_receipt, r) for r in POSITIVE['receipts']]
        for validator, value in cases:
            with self.subTest(validator=validator.__name__):
                expected = copy.deepcopy(value)
                actual = validator(value)
                self.assertEqual(actual, expected)
                self.assertEqual(validator(actual), actual)
                self.assertIsNot(actual, value)
                self.assertEqual(value, expected)

    def test_ac01_reject_unknown_fields_in_every_document(self):
        for validator, value in (
                (contracts.validate_source, POSITIVE['source']),
                (contracts.validate_operation, POSITIVE['source']['application']['operations'][0]),
                (contracts.validate_completion, POSITIVE['source']['stages'][0]['completion']),
                (contracts.validate_receipt, POSITIVE['receipts'][0]),
                (contracts.validate_report, POSITIVE['report'])):
            with self.subTest(validator=validator.__name__):
                value = copy.deepcopy(value); value['unreviewed'] = 'must reject'
                self.reject(validator, value, '/unreviewed')

    def test_ac01_reject_wrong_document_types_and_boolean_schema(self):
        for validator, value in ((contracts.validate_source, POSITIVE['source']),
                                 (contracts.validate_receipt, POSITIVE['receipts'][0]),
                                 (contracts.validate_report, POSITIVE['report'])):
            for field, replacement in [('schema', True), ('schema', 1.0),
                                       ('schema', '1'), ('schema', 2),
                                       ('document_type', 'application_execution_plan')]:
                with self.subTest(validator=validator.__name__, field=field, value=replacement):
                    item = copy.deepcopy(value); item[field] = replacement
                    self.reject(validator, item, '/' + field)

    def test_ac01_all_required_source_fields_are_required(self):
        for key in POSITIVE['source']:
            with self.subTest(key=key):
                value = self.source(); del value[key]
                self.reject(contracts.validate_source, value)

    def test_ac01_unknown_nested_fields_reject_with_local_pointer(self):
        for path in [('runtime',), ('application',), ('stages', 0),
                     ('stages', 0, 'participant'), ('stages', 0, 'limits'),
                     ('application', 'operations', 0), ('checks', 0)]:
            with self.subTest(path=path):
                value = self.source(); node = value
                for key in path: node = node[key]
                node['surprise'] = 'untrusted'
                self.reject(contracts.validate_source, value,
                            '/' + '/'.join(map(str, path)) + '/surprise')

    def test_ac01_json_duplicate_keys_nonfinite_and_bad_utf8_reject(self):
        for raw in ['{"schema":1,"schema":1}', '{"outer":{"key":1,"key":2}}',
                    '{"n":NaN}', '{"n":Infinity}', '{"n":-Infinity}',
                    '1e999', b'\xff', '{"unterminated":']:
            with self.subTest(raw=raw):
                with self.assertRaises(contracts.ContractError): contracts.loads(raw)

    def test_ac01_json_byte_limit_and_depth_limit(self):
        self.assertEqual(contracts.loads(b'{"ok":true}', max_bytes=11), {'ok': True})
        with self.assertRaises(contracts.ContractError):
            contracts.loads('{"unicode":"é"}', max_bytes=15)
        for raw in ['[' * 200 + '0' + ']' * 200,
                    '{"nested":' * 200 + 'null' + '}' * 200]:
            with self.assertRaises(contracts.ContractError): contracts.loads(raw)

    def test_ac01_in_memory_nonfinite_and_excessive_nesting_reject(self):
        for number in [float('nan'), float('inf'), float('-inf')]:
            value = self.source(); value['stages'][0]['limits']['max_turns'] = number
            with self.assertRaises(contracts.ContractError): contracts.validate_source(value)
        value = self.source(); nested = {}
        for _ in range(200): nested = {'properties': nested}
        value['application']['operations'][0]['response_schema'] = nested
        with self.assertRaises(contracts.ContractError): contracts.validate_source(value)

    def test_ac01_no_external_or_local_schema_refs_and_no_io(self):
        for ref in ['https://example.invalid/schema', 'file:///etc/passwd', '#/$defs/hidden']:
            with self.subTest(ref=ref):
                value = self.source()
                value['application']['operations'][0]['response_schema'] = {'$ref': ref}
                with mock.patch('builtins.open', side_effect=AssertionError('unexpected file I/O')), \
                     mock.patch.object(socket, 'create_connection', side_effect=AssertionError('network I/O')), \
                     mock.patch.object(subprocess, 'run', side_effect=AssertionError('process dispatch')):
                    self.reject(contracts.validate_source, value, '/application/operations/0/response_schema')

    def test_ac01_validators_do_not_mutate_nested_inputs(self):
        value = self.source(); actual = contracts.validate_source(value)
        actual['stages'][0]['participant']['actor_id'] = 'changed'
        actual['application']['operations'][0]['response_schema']['required'].clear()
        self.assertEqual(value, POSITIVE['source'])

    def test_ac01_canonical_bytes_are_utf8_sorted_without_unicode_normalization(self):
        value = {'z': ['é', 'e\u0301'], 'a': {'b': False, 'a': 1}}
        expected = b'{"a":{"a":1,"b":false},"z":["\xc3\xa9","e\xcc\x81"]}'
        self.assertEqual(contracts.canonical(value), expected)
        self.assertEqual(contracts.digest(value), hashlib.sha256(expected).hexdigest())
        self.assertNotEqual(contracts.digest(['é']), contracts.digest(['e\u0301']))
        self.assertNotEqual(contracts.digest([1, 2]), contracts.digest([2, 1]))
        for value in [float('nan'), float('inf')]:
            with self.assertRaises(contracts.ContractError): contracts.canonical(value)

    def test_ac02_dependencies_missing_self_duplicate_and_cycle(self):
        for dependencies in [['missing'], ['participant'], ['other', 'other']]:
            value = self.source(); value['stages'][0]['depends_on'] = dependencies
            self.reject(contracts.validate_source, value, '/stages/0/depends_on')
        value = self.two_stages()
        value['stages'][0]['depends_on'] = ['second']
        value['stages'][1]['depends_on'] = ['participant']
        self.reject(contracts.validate_source, value, '/stages', 'dependency_invalid')

    def two_stages(self):
        value = self.source(); other = copy.deepcopy(value['stages'][0])
        other['id'] = 'second'; other['completion']['id'] = 'second-report'
        other['completion']['report_path'] = 'second/completion.json'
        other['completion']['artifacts'][0]['path'] = 'second/summary.md'
        value['stages'].append(other)
        return value

    def test_ac02_valid_forward_dependency_is_not_reordered_by_pure_validation(self):
        value = self.two_stages(); value['stages'][0]['depends_on'] = ['second']
        self.assertEqual(contracts.validate_source(value), value)

    def test_ac02_stage_and_check_ids_are_globally_unique(self):
        value = self.two_stages(); value['stages'][1]['id'] = 'participant'
        self.reject(contracts.validate_source, value, '/stages/1/id')
        value = self.source(); value['checks'][0]['id'] = 'participant'
        self.reject(contracts.validate_source, value, '/checks/0/id')

    def test_ac02_exact_participant_tuple_requires_all_four_fields(self):
        for field in ['application_id', 'tenant_id', 'actor_id', 'role']:
            for bad in [None, '', ' ', True, 1, ['actor-alice']]:
                with self.subTest(field=field, bad=bad):
                    value = self.source(); value['stages'][0]['participant'][field] = bad
                    self.reject(contracts.validate_source, value, '/stages/0/participant/' + field)
            value = self.source(); del value['stages'][0]['participant'][field]
            self.reject(contracts.validate_source, value, '/stages/0/participant')

    def test_ac02_completion_identity_must_match_exact_stage_tuple(self):
        for field in ['application_id', 'tenant_id', 'actor_id', 'role']:
            with self.subTest(field=field):
                value = self.source(); value['stages'][0]['completion']['participant'][field] += '-other'
                self.reject(contracts.validate_source, value, '/stages/0/completion/participant')

    def test_ac02_application_identity_must_match_application_declaration(self):
        value = self.source()
        for location in [value['stages'][0]['participant'], value['stages'][0]['completion']['participant']]:
            location['application_id'] = 'other-app'
        self.reject(contracts.validate_source, value, '/stages/0/participant')

    def test_ac02_exact_release_and_arm64_immutable_runtime_required(self):
        for field, values in [('pi_release', ['latest', '^1.2.0', '1.2.0+local', '1.2.1', None]),
                              ('image_id', ['latest', 'sha256:a', 'sha256:' + 'A' * 64]),
                              ('platform', ['linux/amd64', 'darwin/arm64', None]),
                              ('inference_owner', ['automatic', None])]:
            for bad in values:
                with self.subTest(field=field, bad=bad):
                    value = self.source(); value['runtime'][field] = bad
                    self.reject(contracts.validate_source, value, '/runtime/' + field)
        for release in ['0.87.1', '1.2.0']:
            value = self.source(); value['runtime']['pi_release'] = release
            self.assertEqual(contracts.validate_source(value), value)

    def test_ac02_paths_are_contained_posix_and_globally_unique(self):
        for bad in ['/tmp/report.json', '../escape.json', 'outputs/../escape.json',
                    'outputs//report.json', 'outputs/./report.json', 'outputs\\report.json',
                    'outputs/', '.', '', 'outputs/\x00report']:
            for field in ['report_path', 'artifact_path']:
                with self.subTest(path=bad, field=field):
                    value = self.source(); completion = value['stages'][0]['completion']
                    if field == 'report_path': completion['report_path'] = bad
                    else: completion['artifacts'][0]['path'] = bad
                    self.reject(contracts.validate_source, value, '/stages/0/completion')
        value = self.two_stages()
        value['stages'][1]['completion']['artifacts'][0]['path'] = 'outputs/summary.md'
        self.reject(contracts.validate_source, value, '/stages/1/completion')

    def test_ac02_stage_operation_and_credential_grants_are_explicit(self):
        for field, replacement in [('credential_aliases', ['ambient']),
                                   ('operations', ['undeclared']),
                                   ('browser_targets', ['unlisted']),
                                   ('profile', 'builtin')]:
            with self.subTest(field=field):
                value = self.source(); value['stages'][0][field] = replacement
                self.reject(contracts.validate_source, value, '/stages/0/' + field)
        value = self.source(); value['stages'][0]['operations'].remove('identity')
        self.reject(contracts.validate_source, value, '/stages/0')

    def test_ac02_bounds_and_booleans_do_not_coerce(self):
        for field, values in [('max_tool_calls', [True, 0, 501, 2.0]),
                              ('reporting_reserve_calls', [0, 21, 32]),
                              ('reporting_reserve_seconds', [0, 121, 300])]:
            for bad in values:
                with self.subTest(field=field, bad=bad):
                    value = self.source(); value['stages'][0]['limits'][field] = bad
                    self.reject(contracts.validate_source, value, '/stages/0/limits')
        for field in ['stages', 'checks']:
            value = self.source(); value[field] = []
            self.reject(contracts.validate_source, value, '/' + field)

    def test_ac02_input_artifact_producer_must_exist_and_be_dependency(self):
        value = self.source(); del value['stages'][0]['input_artifacts']
        self.reject(contracts.validate_source, value, '/stages/0')
        value = self.source()
        value['stages'][0]['input_artifacts'] = [{'stage_id': 'missing', 'artifact_id': 'summary'}]
        self.reject(contracts.validate_source, value, '/stages/0/input_artifacts')

    def test_ac04_report_cannot_be_publication_payload(self):
        value = self.source(); completion = value['stages'][0]['completion']
        completion['artifacts'][0]['path'] = completion['report_path']
        self.reject(contracts.validate_source, value, '/stages/0/completion')
        value = self.source()
        value['stages'][0]['completion']['publications'][0]['artifact_id'] = 'completion'
        self.reject(contracts.validate_source, value, '/stages/0/completion/publications')

    def test_ac04_publication_target_artifact_pair_cannot_have_two_grants(self):
        completion = copy.deepcopy(self.source()['stages'][0]['completion'])
        other = copy.deepcopy(completion['publications'][0])
        other.update(id='second-publication', operation_id='second-operation')
        completion['publications'].append(other)
        self.reject(contracts.validate_completion, completion, '/publications/1/target_id')

    def test_ac02_read_id_cannot_ambiguously_shadow_output_or_another_input(self):
        for items in ([{'stage_id': 'producer', 'artifact_id': 'summary'}],
                      [{'stage_id': 'producer', 'artifact_id': 'incoming'},
                       {'stage_id': 'other', 'artifact_id': 'incoming'}]):
            value = self.source()
            value['stages'][0]['input_artifacts'] = items
            self.reject(contracts.validate_source, value, '/stages/0/input_artifacts')

    def test_ac04_publication_contract_matches_operation_artifact_target_and_state(self):
        for field, bad in [('id', 'other-publication'), ('operation_id', 'list-records'),
                           ('artifact_id', 'other-artifact'), ('target_id', 'other-target'),
                           ('required_state', 'draft')]:
            with self.subTest(field=field):
                value = self.source()
                value['stages'][0]['completion']['publications'][0][field] = bad
                self.reject(contracts.validate_source, value, '/stages/0/completion/publications')

    def test_ac04_publication_requires_declared_artifact_payload_source(self):
        operation = copy.deepcopy(POSITIVE['source']['application']['operations'][2])
        operation['publication']['payload_source'] = 'report_manifest'
        self.reject(contracts.validate_operation, operation, '/publication/payload_source')

    def test_ac01_receipt_bindings_are_strict_and_release_specific(self):
        for field, bad in [('plan_sha256', 'abc'), ('stage_id', 'not-a-uuid'),
                           ('pi_release', 'latest')]:
            with self.subTest(field=field):
                receipt = copy.deepcopy(POSITIVE['receipts'][0]); receipt['binding'][field] = bad
                self.reject(contracts.validate_receipt, receipt, '/binding/' + field)
        receipt = copy.deepcopy(POSITIVE['receipts'][0]); receipt['binding']['secret'] = 'no'
        self.reject(contracts.validate_receipt, receipt, '/binding/secret')

    def test_ac04_publication_grants_cannot_escape_completion_receipt_contract(self):
        value = self.source()
        other = copy.deepcopy(value['application']['operations'][-1])
        other['id'] = 'publish-again'
        value['application']['operations'].append(other)
        value['stages'][0]['operations'].append('publish-again')
        self.reject(contracts.validate_source, value, '/stages/0/completion/publications')

    def test_ac01_result_bound_can_always_hold_truthful_receipt_metadata(self):
        value = self.source()
        value['application']['operations'][0]['max_result_bytes'] = 255
        self.reject(contracts.validate_source, value, '/application/operations/0/max_result_bytes')
        value['application']['operations'][0]['max_result_bytes'] = 256
        contracts.validate_source(value)

    def test_ac01_native_call_ids_preserve_provider_bytes_without_path_semantics(self):
        for native in ['call_ABC-123', 'a/b:c|d.1', 'call"quoted']:
            receipt = copy.deepcopy(POSITIVE['receipts'][0])
            receipt['native_call_id'] = native
            self.assertEqual(contracts.validate_receipt(receipt)['native_call_id'], native)
        for native in ['', 'a b', 'a\nb', 'é', 'a' * 129, None]:
            receipt = copy.deepcopy(POSITIVE['receipts'][0])
            receipt['native_call_id'] = native
            self.reject(contracts.validate_receipt, receipt, '/native_call_id')

    def test_ac01_receipt_evidence_paths_hashes_and_bounds(self):
        for field, bad in [('path', '../private.txt'), ('sha256', 'not-a-hash'), ('bytes', True),
                           ('bytes', -1), ('kind', 'model-summary')]:
            with self.subTest(field=field):
                receipt = copy.deepcopy(POSITIVE['receipts'][0]); receipt['evidence'][0][field] = bad
                self.reject(contracts.validate_receipt, receipt, '/evidence/0/' + field)

    def test_ac01_report_duplicate_ids_wrong_hash_types_and_unsafe_paths(self):
        report = copy.deepcopy(POSITIVE['report']); report['artifacts'].append(copy.deepcopy(report['artifacts'][0]))
        self.reject(contracts.validate_report, report, '/artifacts')
        for field, bad in [('path', '../summary.md'), ('bytes', True), ('sha256', 'invalid')]:
            with self.subTest(field=field):
                report = copy.deepcopy(POSITIVE['report']); report['artifacts'][0][field] = bad
                self.reject(contracts.validate_report, report, '/artifacts/0/' + field)
        report = copy.deepcopy(POSITIVE['report']); report['publications'].append(copy.deepcopy(report['publications'][0]))
        self.reject(contracts.validate_report, report, '/publications')

    def test_ac01_final_ir_positive_frozen_prompt_and_digest(self):
        value = execution_fixture()
        self.assertEqual(contracts.validate_ir(value), value)
        self.assertEqual(contracts.validate_ir(contracts.validate_ir(value)), value)
        value['stages'][0]['effective_prompt'] += '\nChanged prompt.'
        self.reject(contracts.validate_ir, value)

    def test_ac01_final_ir_rejects_unknown_fields_and_source_prompt(self):
        value = execution_fixture(); value['surprise'] = True
        self.reject(contracts.validate_ir, value, '/surprise')
        value = execution_fixture(); value['stages'][0]['prompt'] = 'Not the frozen prompt.'
        self.reject(contracts.validate_ir, value, '/stages/0/prompt')

    def test_ac02_final_ir_profile_release_and_resolved_authority_match(self):
        value = execution_fixture(); value['stages'][0]['profile_binding']['pi_release'] = '0.87.1'
        value['plan_sha256'] = independent_digest({k:v for k,v in value.items() if k != 'plan_sha256'})
        self.reject(contracts.validate_ir, value, '/stages/0/profile_binding')
        value = execution_fixture(); value['stages'][0]['resolved_operations'][2]['path_template'] = '/elsewhere'
        value['plan_sha256'] = independent_digest({k:v for k,v in value.items() if k != 'plan_sha256'})
        self.reject(contracts.validate_ir, value, '/stages/0/resolved_operations')

    def test_ac01_pagination_schema_fields_have_reviewed_scalar_and_collection_types(self):
        for field, replacement in [
                ('next_cursor', {'type': 'integer', 'minimum': 0, 'maximum': 10}),
                ('next_cursor', {'type': 'string', 'maxLength': 256}),
                ('items', {'type': 'string', 'maxLength': 100}),
                ('snapshot_id', {'type': 'array', 'maxItems': 2,
                                 'items': {'type': 'string', 'maxLength': 128}})]:
            with self.subTest(field=field, schema=replacement):
                value = self.source()
                value['application']['operations'][1]['response_schema']['properties'][field] = replacement
                self.reject(contracts.validate_source, value, '/application/operations/1')

    def test_ac01_result_projection_paths_must_exist_in_response_schema(self):
        for fields in [['/undeclared'], ['/items', '/undeclared'], ['/snapshot_id/child']]:
            with self.subTest(fields=fields):
                value = self.source(); value['application']['operations'][1]['result_fields'] = fields
                self.reject(contracts.validate_source, value, '/application/operations/1')

    def browser_source(self):
        value = self.source()
        value['runtime'].update(container_profile='browser', browser_sandbox_policy='chromium-userns')
        target = {
            'id': 'publish-button', 'page_identity': 'diagnostic-summary-v1',
            'url': 'http://fixture.invalid:8080/summary',
            'locator': '[data-testid="publish-summary"]', 'actions': ['click'],
            'credential_alias': 'persona', 'allowed_operation_ids': ['publish-summary'],
            'static_resources': [], 'request_body_template': {
                'target_id': 'team-summary', 'artifact_id': 'summary',
                'artifact_sha256': '${artifact.summary.sha256}'},
            'input_schema': {'type': 'object', 'properties': {},
                             'required': [], 'additionalProperties': False}}
        value['application']['browser_targets'] = [target]
        value['stages'][0]['browser_targets'] = ['publish-button']
        return value

    def test_ac01_browser_template_only_uses_granted_artifacts_and_declared_input(self):
        value = self.browser_source()
        self.assertEqual(contracts.validate_source(value), value)
        for replacement in ['${artifact.undeclared.sha256}', '${input.value}', '${input.option_id}']:
            with self.subTest(replacement=replacement):
                value = self.browser_source()
                value['application']['browser_targets'][0]['request_body_template']['artifact_sha256'] = replacement
                self.reject(contracts.validate_source, value)
        value = self.browser_source()
        value['application']['browser_targets'][0]['request_body_template']['nested'] = ['${input.value}']
        self.reject(contracts.validate_source, value)

    def test_ac01_malformed_ir_types_always_raise_contract_error(self):
        fields = [('runtime',), ('application',), ('stages',), ('checks',),
                  ('compiler_contract',), ('input_hashes',),
                  ('stages', 0, 'tools'), ('stages', 0, 'profile_binding'),
                  ('stages', 0, 'inference_binding'), ('stages', 0, 'prompt_admission'),
                  ('stages', 0, 'resolved_operations')]
        for path in fields:
            for malformed in [None, True, 17, '', [], {'not': 'this shape'}]:
                with self.subTest(path=path, malformed=malformed):
                    value = execution_fixture(); node = value
                    for field in path[:-1]: node = node[field]
                    node[path[-1]] = malformed
                    with self.assertRaises(contracts.ContractError): contracts.validate_ir(value)

    def test_ac01_nested_duplicate_key_error_points_to_full_document_location(self):
        with self.assertRaises(contracts.ContractError) as raised:
            contracts.loads('{"outer":{"key":1,"key":2}}')
        self.assertEqual(raised.exception.pointer, '/outer/key')

    def test_ac01_browser_url_rejects_controls_and_noncanonical_paths(self):
        for suffix in ['/summary\n', '/summary/../other', '/summary/./other',
                       '/summary//other', '/summary/', '/%2e%2e/private']:
            with self.subTest(path=suffix):
                value = self.browser_source()
                value['application']['browser_targets'][0]['url'] = 'http://fixture.invalid:8080' + suffix
                self.reject(contracts.validate_source, value, '/application/browser_targets/0/url')

    def test_ac01_static_resources_require_unique_canonical_paths(self):
        resource = {'method': 'GET', 'origin': 'fixture', 'path': '/assets/style.css',
                    'media_type': 'text/css', 'max_bytes': 4096}
        for bad in ['/assets/../style.css', '/assets//style.css', '/assets/./style.css',
                    '/assets/style.css\n', '//assets/style.css']:
            with self.subTest(path=bad):
                value = self.browser_source()
                value['application']['browser_targets'][0]['static_resources'] = [{**resource, 'path': bad}]
                self.reject(contracts.validate_source, value, '/application/browser_targets/0/static_resources')
        value = self.browser_source()
        value['application']['browser_targets'][0]['static_resources'] = [resource, copy.deepcopy(resource)]
        self.reject(contracts.validate_source, value, '/application/browser_targets/0/static_resources')

    def test_ac01_pinned_addresses_are_explicit_ip_strings(self):
        for bad in [3232235777, True, None, 'fixture.invalid', '192.0.2.10/32']:
            with self.subTest(address=bad):
                value = self.source(); value['application']['origins']['fixture']['allowed_addresses'] = [bad]
                self.reject(contracts.validate_source, value, '/application/origins/fixture/allowed_addresses')

    def test_ac01_overlapping_ranged_regexes_are_rejected(self):
        for pattern in ['^[a-z]{0,4000}[a-z]{0,4000}$', '^[a-z]{1,2}[a-z]{1,2}$',
                        '^(a+)+$', '^.*$']:
            with self.subTest(pattern=pattern):
                value = self.source()
                value['application']['operations'][0]['response_schema']['properties']['actor_id']['pattern'] = pattern
                self.reject(contracts.validate_source, value, '/application/operations/0/response_schema')

    def test_ac01_zero_tool_schema_or_framing_proof_cannot_admit_ir(self):
        for field in ['tool_schema_bytes', 'framing_upper_bound']:
            with self.subTest(field=field):
                value = execution_fixture(); admission = value['stages'][0]['prompt_admission']
                admission['total_upper_bound'] -= admission[field]; admission[field] = 0
                value['plan_sha256'] = independent_digest({k:v for k,v in value.items() if k != 'plan_sha256'})
                self.reject(contracts.validate_ir, value, '/stages/0/prompt_admission')

    def test_ac02_unicode_equivalent_output_paths_conflict_without_normalizing_content(self):
        value = self.two_stages()
        value['stages'][0]['completion']['artifacts'][0]['path'] = 'outputs/café.md'
        value['stages'][1]['completion']['artifacts'][0]['path'] = 'outputs/cafe\u0301.md'
        original = copy.deepcopy(value)
        self.reject(contracts.validate_source, value)
        self.assertEqual(value, original)
        self.assertNotEqual(contracts.canonical('café'), contracts.canonical('cafe\u0301'))
        self.assertEqual(contracts.canonical('cafe\u0301'), '"cafe\u0301"'.encode())
        completion = copy.deepcopy(value['stages'][0]['completion'])
        second = copy.deepcopy(completion['artifacts'][0]); second['id'] = 'second-summary'
        second['path'] = 'outputs/cafe\u0301.md'; completion['artifacts'].append(second)
        self.reject(contracts.validate_completion, completion)

    def test_ac01_final_ir_prompt_admission_arithmetic_is_verified(self):
        value = execution_fixture(); value['stages'][0]['prompt_admission']['total_upper_bound'] -= 1
        value['plan_sha256'] = independent_digest({k:v for k,v in value.items() if k != 'plan_sha256'})
        self.reject(contracts.validate_ir, value, '/stages/0/prompt_admission')


class ApplicationRuntimeRegistryTests(unittest.TestCase):
    def test_ac03_new_registry_rejects_unknown_releases_without_fallback(self):
        for release in [None, True, 'latest', '1.2.1', '1.2.0+local', '^0.87.1']:
            for function in [application_runtime_contracts.contract, application_runtime_contracts.identity]:
                with self.subTest(release=release, function=function.__name__):
                    with self.assertRaises(ValueError): function(release)

    def test_ac03_new_runtime_contract_copies_cannot_change_registry_or_old_identity(self):
        for release in ['0.87.1', '1.2.0']:
            with self.subTest(release=release):
                before = application_runtime_contracts.identity(release)
                value = application_runtime_contracts.contract(release)
                self.assertEqual(value['legacy_release_identity'], BASELINE['release_identities'][release])
                self.assertEqual(value['release'], release)
                value['source_pins'].clear()
                value['legacy_release_identity']['sha256'] = '0' * 64
                value['compiler']['id'] = 'mutated'
                self.assertEqual(application_runtime_contracts.identity(release), before)
                self.assertTrue(application_runtime_contracts.contract(release)['source_pins'])
                self.assertEqual(release_contracts.identity(release), BASELINE['release_identities'][release])
        self.assertNotEqual(application_runtime_contracts.identity('0.87.1')['sha256'],
                            application_runtime_contracts.identity('1.2.0')['sha256'])

    def test_ac01_compiler_contract_copy_isolation_and_independent_identity(self):
        before = application_runtime_contracts.compiler_identity()
        value = application_runtime_contracts.compiler_contract()
        expected = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        self.assertEqual(before['sha256'], expected)
        value['max_stages'] = 10000
        self.assertEqual(application_runtime_contracts.compiler_identity(), before)


class LegacyCompatibilityTests(unittest.TestCase):
    def test_ac03_exact_predecessor_release_identity_golden_hashes(self):
        self.assertEqual({release: release_contracts.identity(release)
                          for release in ('0.87.1', '1.2.0')}, BASELINE['release_identities'])
        self.assertEqual(release_contracts.RELEASES, ('0.87.1', '1.2.0'))

    def test_ac03_predecessor_contract_and_fixture_profile_raw_bytes(self):
        for name, expected in BASELINE['file_sha256'].items():
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256((REPOSITORY / name).read_bytes()).hexdigest(), expected)
        for name, expected in BASELINE['profile_identities'].items():
            with self.subTest(profile=name):
                profile = agent_profiles.load(SKILL / 'assets/profiles/fixture-lookup' / name)
                self.assertEqual(agent_profiles.identity(profile), expected)

    def test_ac03_legacy_normalization_and_digests_do_not_grow_new_fields(self):
        for fixture in BASELINE['legacy_plans']:
            with self.subTest(schema=fixture['source']['schema']):
                normalized = lab.validate_plan(copy.deepcopy(fixture['source']), REPOSITORY, external_bindings=True)
                self.assertEqual(normalized, fixture['normalized'])
                self.assertEqual(provenance.digest(normalized), fixture['sha256'])
                self.assertNotIn('max_tool_calls', normalized['agents'][0])
                self.assertNotIn('completion', normalized)

    def test_ac03_copied_historical_experiment_matrix_and_result_bytes_are_frozen(self):
        for name, expected in BASELINE['archived_bytes'].items():
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest(), expected)
        experiment = experiments.read_json(FIXTURES / 'historical-experiment.json')
        matrix = experiments.read_json(FIXTURES / 'historical-matrix.json')
        self.assertEqual(experiment['document_type'], 'experiment')
        self.assertEqual(experiment['schema'], 1)
        self.assertEqual(matrix['experiment_id'], experiment['experiment_id'])
        self.assertNotIn('completion', experiment)

    def test_ac03_archived_sealed_result_reader_preserves_bytes_and_status(self):
        historical = (FIXTURES / 'historical-result.json').read_bytes()
        value = json.loads(historical)
        self.assertEqual(outcomes.status(value), ('BLOCKED', 2))
        self.assertNotIn('completion', value)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); run = root / 'runs' / value['run_id']; run.mkdir(parents=True)
            path = run / 'result.json'; path.write_bytes(historical)
            intent = {field: value.get(field) for field in
                      ('experiment_id', 'trial_id', 'attempt_id', 'run_id', 'attempt_index',
                       'retry_of_attempt_id', 'configuration_digest')}
            intent.update(result_sha256=hashlib.sha256(historical).hexdigest(), status='finalized')
            self.assertEqual(experiments.sealed_result(root, intent), value)
            self.assertEqual(path.read_bytes(), historical)
            path.write_bytes(historical + b'\n')
            with self.assertRaisesRegex(experiments.ExperimentError, 'changed'):
                experiments.sealed_result(root, intent)


if __name__ == '__main__':
    unittest.main()
