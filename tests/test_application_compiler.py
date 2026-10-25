"""A02 independent offline compiler oracles; synthetic inputs grant no runtime authority."""
import copy
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest import mock

REPOSITORY = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPOSITORY / 'skill/scripts'), str(REPOSITORY / 'skill/runtime')]
import application_contracts as contracts
import application_compiler as compiler
import prompt_contract
import resources

POSITIVE = json.loads((REPOSITORY / 'tests/fixtures/application-contracts/positive.json').read_text())


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
                      allow_nan=False).encode('utf-8')


def sha(value):
    return hashlib.sha256(value).hexdigest()


def inputs(source=None):
    """Explicit synthetic compile inputs, independent of installed profile/runtime registries."""
    source = copy.deepcopy(POSITIVE['source'] if source is None else source)
    release = source['runtime']['pi_release']
    profiles, inference, assets, instructions, variants = {}, {}, {}, {}, {}
    for stage in source['stages']:
        sid = stage['id']
        instructions[sid] = 'Reviewed fixture profile instructions for ' + sid + '.'
        variants[sid] = 'Explicit fixture variant instructions for ' + sid + '.'
        profile_assets = {'instructions.md': instructions[sid].encode(),
                          'application-client.mjs': b'// offline synthetic profile; never execute\n'}
        profiles[sid] = {'id': 'application-client', 'pi_release': release,
                         'sha256': '3' * 64,
                         'assets': {target: sha(body) for target, body in profile_assets.items()}}
        for target, body in profile_assets.items():
            assets['profiles/' + sid + '/' + target] = body
        inference[sid] = {'kind': 'legacy', 'configuration_sha256': '5' * 64,
                          'context_window': 1000000, 'max_tokens': 4096,
                          'input_modalities': ['text'],
                          'selection': {'owner': source['runtime']['inference_owner'],
                                        'id': 'explicit-' + sid}}
    for check in source['checks']:
        for asset in check.get('scorer', {}).get('assets', []):
            assets[asset['source']] = ('offline independent scorer asset: ' + asset['source']).encode()
    return source, {'profile_bindings': profiles, 'inference_bindings': inference,
                    'prompt_policy': {'system_instructions': 'Reviewed fixed system policy.',
                                      'profile_instructions': instructions,
                                      'variant_instructions': variants,
                                      'framing_upper_bounds': {release: 1024},
                                      'bound_source_sha256': '8' * 64,
                                      'byte_bound_reviewed': True},
                    'input_assets': assets, 'runner_sha256': '9' * 64}


def two_stages():
    source = copy.deepcopy(POSITIVE['source'])
    other = copy.deepcopy(source['stages'][0])
    other['id'] = 'second'
    other['completion']['id'] = 'second-report'
    other['completion']['report_path'] = 'second/completion.json'
    other['completion']['artifacts'][0]['path'] = 'second/summary.md'
    source['stages'].append(other)
    return source


def browser_source():
    source = copy.deepcopy(POSITIVE['source'])
    source['runtime']['container_profile'] = 'browser'
    source['runtime']['browser_sandbox_policy'] = 'chromium-userns'
    source['application']['browser_targets'] = [{
        'id': 'records-page', 'page_identity': 'diagnostic-records',
        'url': 'http://fixture.invalid:8080/records', 'locator': None,
        'actions': ['navigate', 'snapshot'], 'credential_alias': 'persona',
        'allowed_operation_ids': ['list-records'], 'static_resources': [],
        'request_body_template': None,
        'input_schema': {'type': 'object', 'properties': {}, 'required': [],
                         'additionalProperties': False}}]
    source['stages'][0]['browser_targets'] = ['records-page']
    return source


def set_profile_instructions(kwargs, sid, text):
    kwargs['prompt_policy']['profile_instructions'][sid] = text
    body = text.encode()
    kwargs['input_assets']['profiles/' + sid + '/instructions.md'] = body
    kwargs['profile_bindings'][sid]['assets']['instructions.md'] = sha(body)


class ApplicationCompilerTests(unittest.TestCase):
    def compile(self, source=None):
        source, kwargs = inputs(source)
        return compiler.compile_plan(source, **kwargs)

    def reject(self, source, kwargs):
        before = copy.deepcopy((source, kwargs))
        with self.assertRaises(contracts.ContractError) as caught:
            compiler.compile_plan(source, **kwargs)
        self.assertIsInstance(caught.exception.pointer, str)
        self.assertTrue(caught.exception.pointer == '' or caught.exception.pointer.startswith('/'))
        self.assertEqual((source, kwargs), before)
        return caught.exception

    def test_ac05_repeated_compilation_is_byte_identical_and_inputs_are_immutable(self):
        for release in ('0.87.1', '1.2.0'):
            with self.subTest(release=release):
                source = copy.deepcopy(POSITIVE['source'])
                source['runtime']['pi_release'] = release
                source, kwargs = inputs(source)
                before = copy.deepcopy((source, kwargs))
                first = compiler.compile_plan(source, **kwargs)
                second = compiler.compile_plan(copy.deepcopy(source), **copy.deepcopy(kwargs))
                self.assertEqual(canonical(first), canonical(second))
                self.assertEqual((source, kwargs), before)
                expected = sha(canonical({k: v for k, v in first.items() if k != 'plan_sha256'}))
                self.assertEqual(first['plan_sha256'], expected)
                self.assertEqual(first['document_type'], 'application_execution_plan')
                self.assertEqual(first['schema'], 1)

    def test_ac05_dictionary_insertion_order_does_not_change_canonical_output(self):
        source, kwargs = inputs()
        def reverse_dicts(value):
            if isinstance(value, dict):
                return {key: reverse_dicts(child) for key, child in reversed(list(value.items()))}
            if isinstance(value, list):
                return [reverse_dicts(child) for child in value]
            return value
        first = compiler.compile_plan(source, **kwargs)
        second = compiler.compile_plan(reverse_dicts(source), **reverse_dicts(kwargs))
        self.assertEqual(canonical(first), canonical(second))

    def test_ac05_dependency_order_and_frozen_materialization(self):
        source = two_stages()
        source['stages'][0]['depends_on'] = ['second']
        incoming = copy.deepcopy(source['stages'][1]['completion']['artifacts'][0])
        incoming.update(id='incoming', path='second/incoming.md')
        source['stages'][1]['completion']['artifacts'].append(incoming)
        source['stages'][0]['input_artifacts'] = [{'stage_id': 'second', 'artifact_id': 'incoming'}]
        source, kwargs = inputs(source)
        plan = compiler.compile_plan(source, **kwargs)
        self.assertEqual([s['id'] for s in plan['stages']], ['second', 'participant'])
        for stage in plan['stages']:
            self.assertNotIn('prompt', stage)
            self.assertEqual(stage['tools'], ['app_api', 'artifact_read', 'artifact_write',
                                              'report_write', 'budget_status'])
            self.assertEqual(stage['profile_binding'], kwargs['profile_bindings'][stage['id']])
            self.assertEqual(stage['inference_binding'], kwargs['inference_bindings'][stage['id']])
            self.assertEqual(stage['resolved_operations'], source['application']['operations'])
        frozen = plan['checks'][0]['scorer']['assets']
        expected = [{'target': a['target'], 'sha256': sha(kwargs['input_assets'][a['source']])}
                    for a in source['checks'][0]['scorer']['assets']]
        self.assertEqual(frozen, expected)
        self.assertTrue(all('source' not in item for item in frozen))
        self.assertEqual(plan['stages'][1]['input_artifacts'], source['stages'][0]['input_artifacts'])

    def test_ac05_browser_tool_is_materialized_only_for_a_declared_target(self):
        plain, browser = self.compile(), self.compile(browser_source())
        self.assertNotIn('app_browser', plain['stages'][0]['tools'])
        self.assertIn('app_browser', browser['stages'][0]['tools'])
        self.assertEqual(set(browser['stages'][0]['tools']) - set(plain['stages'][0]['tools']),
                         {'app_browser'})
        self.assertNotEqual(plain['plan_sha256'], browser['plan_sha256'])

    def test_ac05_sparse_source_resources_are_frozen_as_complete_explicit_limits(self):
        source, kwargs = inputs()
        source['runtime']['resources'] = {}
        before = copy.deepcopy(source)
        plan = compiler.compile_plan(source, **kwargs)
        self.assertEqual(plan['runtime']['resources'], resources.validate_policy({}))
        self.assertEqual(set(plan['runtime']['resources']),
                         {'schema', 'runtime', 'build', 'host_budget'})
        self.assertEqual(set(plan['runtime']['resources']['runtime']),
                         {'cpus', 'memory', 'pids_limit', 'jobs'})
        self.assertEqual(source, before)
        self.assertEqual(contracts.validate_ir(plan), plan)

    def test_ac08_changed_reviewed_resource_defaults_change_frozen_ir_and_digest(self):
        source, kwargs = inputs()
        source['runtime']['resources'] = {}
        first = compiler.compile_plan(source, **kwargs)
        changed_defaults = copy.deepcopy(resources.DEFAULTS)
        changed_defaults['runtime']['cpus'] += 0.5
        with mock.patch.object(resources, 'DEFAULTS', changed_defaults):
            second = compiler.compile_plan(source, **kwargs)
            self.assertEqual(second['runtime']['resources'], resources.validate_policy({}))
            # Already explicit plans retain their meaning after a default-policy change.
            self.assertEqual(contracts.validate_ir(first), first)
        self.assertEqual(first['input_hashes']['source'], second['input_hashes']['source'])
        self.assertNotEqual(first['runtime']['resources'], second['runtime']['resources'])
        self.assertNotEqual(first['plan_sha256'], second['plan_sha256'])
        self.assertEqual(source['runtime']['resources'], {})

    def test_ac06_rehashed_sparse_final_resources_cannot_use_ambient_defaults(self):
        for sparse in ({}, {'schema': 1}, {'runtime': {'cpus': 1}}):
            with self.subTest(resources=sparse):
                value = self.compile()
                value['runtime']['resources'] = sparse
                value['plan_sha256'] = sha(canonical({key: child for key, child in value.items()
                                                     if key != 'plan_sha256'}))
                with self.assertRaises(contracts.ContractError) as caught:
                    contracts.validate_ir(value)
                self.assertEqual(caught.exception.pointer, '/runtime/resources')

    def test_ac06_final_validation_is_idempotent_deep_copy_and_performs_no_io(self):
        value = self.compile()
        before = canonical(value)
        with ExitStack() as stack:
            for target in ('builtins.open', 'io.open', 'os.open', 'subprocess.run',
                           'subprocess.Popen', 'socket.create_connection', 'socket.socket'):
                stack.enter_context(mock.patch(target, side_effect=AssertionError('unexpected I/O')))
            stack.enter_context(mock.patch.dict(os.environ, {'PI_APP_CANARY': 'NEVER_RESOLVE'}, clear=True))
            first = contracts.validate_ir(value)
            second = contracts.validate_ir(first)
        self.assertEqual(canonical(first), before)
        self.assertEqual(canonical(second), before)
        self.assertIsNot(first, value)
        self.assertIsNot(first['stages'][0], value['stages'][0])
        first['stages'][0]['participant']['actor_id'] = 'mutated-copy'
        self.assertEqual(canonical(value), before)

    def test_ac06_compilation_consumes_only_explicit_inputs(self):
        source, kwargs = inputs()
        with ExitStack() as stack:
            for target in ('builtins.open', 'io.open', 'os.open', 'subprocess.run',
                           'subprocess.Popen', 'socket.create_connection', 'socket.socket'):
                stack.enter_context(mock.patch(target, side_effect=AssertionError('unexpected I/O')))
            stack.enter_context(mock.patch.dict(os.environ, {'PI_APP_CANARY': 'NEVER_RESOLVE'}, clear=True))
            plan = compiler.compile_plan(source, **kwargs)
        self.assertNotIn('NEVER_RESOLVE', canonical(plan).decode())

    def test_ac07_full_prompt_contains_frozen_policy_capabilities_contract_and_budget(self):
        source, kwargs = inputs()
        plan = compiler.compile_plan(source, **kwargs)
        stage = plan['stages'][0]
        prompt = stage['effective_prompt']
        for marker in [kwargs['prompt_policy']['system_instructions'],
                       kwargs['prompt_policy']['profile_instructions']['participant'],
                       kwargs['prompt_policy']['variant_instructions']['participant'],
                       source['stages'][0]['prompt'], 'actor-alice', 'team-1',
                       'participant-report', 'outputs/completion.json', 'outputs/summary.md',
                       'publish-summary', 'max_tool_calls', 'reporting_reserve_calls']:
            self.assertIn(marker, prompt)
        for tool in stage['tools']:
            self.assertIn(tool, prompt)
        proof = stage['prompt_admission']
        self.assertEqual(proof['method'], 'conservative_bytes')
        self.assertEqual(proof['prompt_bytes'], len(prompt.encode()))
        self.assertGreater(proof['tool_schema_bytes'], 0)
        self.assertEqual(proof['tool_schema_bytes'], len(canonical(prompt_contract.tool_schemas(stage))))
        self.assertEqual(proof['framing_upper_bound'], 1024)
        self.assertEqual(proof['reply_tokens'], 4096)
        self.assertGreaterEqual(proof['history_reserve_tokens'], 2048)
        self.assertEqual(proof['total_upper_bound'], sum(proof[k] for k in
                         ('prompt_bytes', 'tool_schema_bytes', 'framing_upper_bound',
                          'reply_tokens', 'history_reserve_tokens')))
        # Secondary consistency check: the frozen source inputs reconstruct the same bytes.
        rendered_stage = copy.deepcopy(stage)
        rendered_stage['prompt'] = source['stages'][0]['prompt']
        rendered_stage['_resolved_browser_targets'] = []
        self.assertEqual(prompt, prompt_contract.render(
            rendered_stage, system_instructions=kwargs['prompt_policy']['system_instructions'],
            profile_instructions=kwargs['prompt_policy']['profile_instructions']['participant'],
            variant_instructions=kwargs['prompt_policy']['variant_instructions']['participant']))

    def test_ac07_rehashed_final_proof_cannot_understate_native_schema_size(self):
        value = self.compile()
        proof = value['stages'][0]['prompt_admission']
        proof['total_upper_bound'] -= proof['tool_schema_bytes'] - 1
        proof['tool_schema_bytes'] = 1
        value['plan_sha256'] = sha(canonical({key: child for key, child in value.items()
                                             if key != 'plan_sha256'}))
        with self.assertRaises(contracts.ContractError):
            contracts.validate_ir(value)

    def near_prompt_limit(self):
        source, kwargs = inputs()
        plan = compiler.compile_plan(source, **kwargs)
        overhead = plan['stages'][0]['prompt_admission']['prompt_bytes'] - len(source['stages'][0]['prompt'].encode())
        source['stages'][0]['prompt'] = 'x' * (131072 - overhead - 64)
        plan = compiler.compile_plan(source, **kwargs)
        self.assertLessEqual(plan['stages'][0]['prompt_admission']['prompt_bytes'], 131072)
        self.assertGreaterEqual(plan['stages'][0]['prompt_admission']['prompt_bytes'], 130000)
        return source, kwargs

    def overhead_changes(self):
        def profile(source, kwargs):
            text = kwargs['prompt_policy']['profile_instructions']['participant'] + 'p' * 512
            set_profile_instructions(kwargs, 'participant', text)
        def variant(source, kwargs):
            kwargs['prompt_policy']['variant_instructions']['participant'] += 'v' * 512
        def system(source, kwargs):
            kwargs['prompt_policy']['system_instructions'] += 's' * 512
        def schema(source, kwargs):
            source['application']['operations'][0]['response_schema']['properties']['extra'] = {
                'type': 'string', 'maxLength': 1024, 'enum': ['z' * 512]}
        def completion(source, kwargs):
            source['stages'][0]['completion']['artifacts'].append({
                'id': 'additional-artifact', 'path': 'outputs/' + 'r' * 240 + '.txt',
                'media_type': 'text/plain', 'max_bytes': 16})
        return {'profile': profile, 'variant': variant, 'system': system,
                'schema': schema, 'completion': completion}

    def test_ac07_each_full_prompt_overhead_can_cross_the_128_kib_limit(self):
        base_source, base_kwargs = self.near_prompt_limit()
        for name, mutate in self.overhead_changes().items():
            with self.subTest(overhead=name):
                source, kwargs = copy.deepcopy((base_source, base_kwargs))
                mutate(source, kwargs)
                self.reject(source, kwargs)

    def test_ac07_each_full_prompt_overhead_can_cross_context(self):
        source, kwargs = inputs()
        total = compiler.compile_plan(source, **kwargs)['stages'][0]['prompt_admission']['total_upper_bound']
        kwargs['inference_bindings']['participant']['context_window'] = total + 64
        compiler.compile_plan(source, **kwargs)
        for name, mutate in self.overhead_changes().items():
            with self.subTest(overhead=name):
                changed, supplied = copy.deepcopy((source, kwargs))
                mutate(changed, supplied)
                self.reject(changed, supplied)

    def test_ac07_utf8_bytes_are_counted_rather_than_character_count(self):
        source, kwargs = self.near_prompt_limit()
        source['stages'][0]['prompt'] += 'é' * 40
        self.assertLess(len(source['stages'][0]['prompt']), 131072)
        self.reject(source, kwargs)

    def test_ac07_every_selected_indexed_stage_is_admitted_without_fallback(self):
        source, kwargs = inputs(two_stages())
        for binding in kwargs['inference_bindings'].values():
            binding['kind'] = 'indexed'
        valid = compiler.compile_plan(source, **kwargs)
        self.assertTrue(all(s['inference_binding']['kind'] == 'indexed' for s in valid['stages']))
        for sid in ('participant', 'second'):
            with self.subTest(stage=sid):
                changed = copy.deepcopy(kwargs)
                changed['inference_bindings'][sid]['context_window'] = 6145
                self.reject(source, changed)

    def test_ac07_unknown_unreviewed_or_missing_overhead_is_rejected(self):
        for key, bad in [('byte_bound_reviewed', False), ('byte_bound_reviewed', 'true'),
                         ('bound_source_sha256', ''), ('framing_upper_bounds', {}),
                         ('framing_upper_bounds', {'1.2.0': 0}),
                         ('framing_upper_bounds', {'1.2.0': True}),
                         ('framing_upper_bounds', {'1.2.0': 65537}),
                         ('framing_upper_bounds', {'0.87.1': 1024}),
                         ('framing_upper_bounds', {'1.2.0': 1024, '0.87.1': 1024})]:
            with self.subTest(key=key, bad=bad):
                source, kwargs = inputs()
                kwargs['prompt_policy'][key] = bad
                self.reject(source, kwargs)
        for key in inputs()[1]['prompt_policy']:
            source, kwargs = inputs()
            del kwargs['prompt_policy'][key]
            self.reject(source, kwargs)

    def test_ac08_effective_semantic_factors_change_the_plan_identity(self):
        source, kwargs = inputs()
        baseline = compiler.compile_plan(source, **kwargs)['plan_sha256']
        mutations = {
            'task_prompt': lambda s, k: s['stages'][0].__setitem__('prompt', 'Changed explicit task'),
            'system_prompt': lambda s, k: k['prompt_policy'].__setitem__('system_instructions', 'Changed fixed policy'),
            'variant_prompt': lambda s, k: k['prompt_policy']['variant_instructions'].__setitem__('participant', 'Changed variant'),
            'profile_prompt': lambda s, k: set_profile_instructions(k, 'participant', 'Changed reviewed profile text'),
            'profile_identity': lambda s, k: k['profile_bindings']['participant'].__setitem__('sha256', 'a' * 64),
            'runtime_image': lambda s, k: s['runtime'].__setitem__('image_id', 'sha256:' + 'b' * 64),
            'runtime_resource': lambda s, k: s['runtime']['resources']['runtime'].__setitem__('cpus', 0.5),
            'operation_route': lambda s, k: s['application']['operations'][1].__setitem__('path_template', '/records-v2'),
            'operation_projection': lambda s, k: s['application']['operations'][1].__setitem__('max_result_bytes', 4096),
            'credential_reference': lambda s, k: s['application']['credentials'].__setitem__('persona', 'DIAGNOSTIC_BOB'),
            'report_path': lambda s, k: s['stages'][0]['completion'].__setitem__('report_path', 'outputs/other.json'),
            'report_artifact_capacity': lambda s, k: s['stages'][0]['completion']['artifacts'][0].__setitem__('max_bytes', 8192),
            'report_pagination': lambda s, k: s['stages'][0]['completion']['pagination'][0].__setitem__('require_exhausted', False),
            'budget': lambda s, k: s['stages'][0]['limits'].__setitem__('max_tool_calls', 33),
            'endpoint_identity': lambda s, k: k['inference_bindings']['participant'].__setitem__('configuration_sha256', 'c' * 64),
            'reply_cap': lambda s, k: k['inference_bindings']['participant'].__setitem__('max_tokens', 4097),
            'framing_bound': lambda s, k: k['prompt_policy']['framing_upper_bounds'].__setitem__('1.2.0', 1025),
            'bound_provenance': lambda s, k: k['prompt_policy'].__setitem__('bound_source_sha256', 'd' * 64),
            'runner': lambda s, k: k.__setitem__('runner_sha256', 'e' * 64),
            'scorer_bytes': lambda s, k: k['input_assets'].__setitem__('root_evaluate.py', b'changed scorer bytes'),
            'scorer_threshold': lambda s, k: s['checks'][0]['scorer']['score_domain'].__setitem__('pass_threshold', 0.75)}
        def actor(s, k):
            s['stages'][0]['participant']['actor_id'] = 'actor-bob'
            s['stages'][0]['completion']['participant']['actor_id'] = 'actor-bob'
        mutations['participant_identity'] = actor
        seen = set()
        for factor, mutate in mutations.items():
            with self.subTest(factor=factor):
                changed, supplied = copy.deepcopy((source, kwargs))
                mutate(changed, supplied)
                result = compiler.compile_plan(changed, **supplied)
                self.assertNotEqual(result['plan_sha256'], baseline)
                self.assertNotIn(result['plan_sha256'], seen)
                seen.add(result['plan_sha256'])

    def test_ac08_profile_asset_content_is_hash_bound(self):
        source, kwargs = inputs()
        first = compiler.compile_plan(source, **kwargs)
        body = b'// different reviewed synthetic profile bytes\n'
        kwargs['input_assets']['profiles/participant/application-client.mjs'] = body
        self.reject(source, kwargs)
        kwargs['profile_bindings']['participant']['assets']['application-client.mjs'] = sha(body)
        second = compiler.compile_plan(source, **kwargs)
        self.assertNotEqual(first['plan_sha256'], second['plan_sha256'])

    def test_ac08_native_schema_content_is_frozen_beyond_its_byte_count(self):
        source, kwargs = inputs()
        first = compiler.compile_plan(source, **kwargs)
        original_schemas = prompt_contract.tool_schemas
        expected = original_schemas(first['stages'][0])
        self.assertEqual(first['stages'][0]['tool_schemas'], expected)
        before = canonical(first)

        def changed_schema(stage):
            schemas = copy.deepcopy(original_schemas(stage))
            description = schemas[0]['description']
            schemas[0]['description'] = ('X' if description[0] != 'X' else 'Y') + description[1:]
            return schemas

        with mock.patch.object(prompt_contract, 'tool_schemas', side_effect=changed_schema):
            second = compiler.compile_plan(source, **kwargs)
            # The semantic change deliberately preserves all byte-count evidence.
            self.assertEqual(first['stages'][0]['prompt_admission'],
                             second['stages'][0]['prompt_admission'])
            self.assertEqual(len(canonical(first['stages'][0]['tool_schemas'])),
                             len(canonical(second['stages'][0]['tool_schemas'])))
            self.assertNotEqual(first['stages'][0]['tool_schemas'],
                                second['stages'][0]['tool_schemas'])
            self.assertNotEqual(first['plan_sha256'], second['plan_sha256'])
            self.assertEqual(contracts.validate_ir(second), second)
            with self.assertRaises(contracts.ContractError):
                contracts.validate_ir(first)
        self.assertEqual(canonical(first), before)
        self.assertEqual(contracts.validate_ir(first), first)

    def test_explicit_maps_require_each_stage_and_reject_undeclared_stage_bindings(self):
        for name in ('profile_bindings', 'inference_bindings'):
            for change in ('missing', 'extra'):
                with self.subTest(map=name, change=change):
                    source, kwargs = inputs()
                    if change == 'missing': kwargs[name].clear()
                    else: kwargs[name]['unassigned'] = copy.deepcopy(kwargs[name]['participant'])
                    self.reject(source, kwargs)
        for name in ('profile_instructions', 'variant_instructions'):
            for change in ('missing', 'extra'):
                source, kwargs = inputs()
                if change == 'missing': kwargs['prompt_policy'][name].clear()
                else: kwargs['prompt_policy'][name]['unassigned'] = 'unscoped text'
                self.reject(source, kwargs)

    def test_binding_shapes_scopes_and_profile_instructions_cannot_be_overridden(self):
        for map_name, field, bad in [
                ('profile_bindings', 'pi_release', '0.87.1'),
                ('profile_bindings', 'id', 'builtin'),
                ('profile_bindings', 'secret', 'never admitted'),
                ('inference_bindings', 'selection', {'owner': 'experiment_variant', 'id': 'wrong-owner'}),
                ('inference_bindings', 'api_key', 'never admitted'),
                ('inference_bindings', 'context_window', True),
                ('inference_bindings', 'input_modalities', ['text', 'image'])]:
            with self.subTest(map=map_name, field=field):
                source, kwargs = inputs()
                kwargs[map_name]['participant'][field] = bad
                self.reject(source, kwargs)
        source, kwargs = inputs()
        kwargs['prompt_policy']['profile_instructions']['participant'] = 'Unbound replacement text'
        self.reject(source, kwargs)
        source, kwargs = inputs()
        kwargs['prompt_policy']['surprise'] = 'undeclared policy'
        self.reject(source, kwargs)

    def test_asset_inputs_are_exact_bounded_byte_maps(self):
        for change in ('missing_scorer', 'missing_profile', 'extra', 'not_bytes', 'wrong_hash',
                       'missing_required_profile_asset', 'oversize'):
            with self.subTest(change=change):
                source, kwargs = inputs()
                assets = kwargs['input_assets']
                if change == 'missing_scorer': del assets['root_evaluate.py']
                elif change == 'missing_profile': del assets['profiles/participant/instructions.md']
                elif change == 'extra': assets['unexpected.txt'] = b'unused'
                elif change == 'not_bytes': assets['root_evaluate.py'] = 'not frozen bytes'
                elif change == 'wrong_hash': assets['profiles/participant/application-client.mjs'] = b'tampered'
                elif change == 'oversize': assets['root_evaluate.py'] = b'x' * (32 * 1024 * 1024 + 1)
                else:
                    del assets['profiles/participant/application-client.mjs']
                    del kwargs['profile_bindings']['participant']['assets']['application-client.mjs']
                self.reject(source, kwargs)

    def test_source_cannot_enter_compiler_as_final_ir_and_bad_hashes_are_rejected(self):
        final = self.compile()
        _, kwargs = inputs()
        self.reject(final, kwargs)
        for field, bad in [('runner_sha256', 'not-a-digest'), ('runner_sha256', None)]:
            source, kwargs = inputs()
            kwargs[field] = bad
            self.reject(source, kwargs)


if __name__ == '__main__':
    unittest.main()
