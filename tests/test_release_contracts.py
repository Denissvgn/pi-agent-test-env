"""Offline release-admission regressions; no Docker or model execution."""
import argparse
import contextlib
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1] / 'skill'
sys.path.insert(0, str(ROOT / 'runtime'))
sys.path.insert(0, str(ROOT / 'scripts'))
import release_contracts as contracts
import pi_lab as lab
import worker
import pi_contract
from evidence import analyze
import segments
import agent_profiles
import experiments
import provenance
import application_credentials


class AdmissionTests(unittest.TestCase):
    def test_client_json_value_inside_a_tool_json_event_is_redacted_losslessly(self):
        key = 'synthetic-quoted"slash\\-application-123456'
        wire = json.dumps({'content': json.dumps(key)}).encode()
        redacted = application_credentials.Redactor([key]).bytes(wire)
        decoded = json.loads(redacted)
        self.assertNotIn(key, decoded['content'])
        self.assertIn('<REDACTED>', decoded['content'])

    def test_exact_versions_have_distinct_stable_contracts_and_copies(self):
        old = contracts.identity('0.87.1')
        new = contracts.identity('1.2.0')
        self.assertNotEqual(old['sha256'], new['sha256'])
        changed = contracts.contract('0.87.1')
        changed['required_flags'].clear()
        self.assertIn('--no-extensions', contracts.contract('0.87.1')['required_flags'])
        self.assertEqual(old, contracts.identity('0.87.1'))
        self.assertNotIn('--no-mcp', contracts.contract('0.87.1')['required_flags'])
        self.assertIn('--no-mcp', contracts.contract('1.2.0')['required_flags'])

    def test_unknown_ambiguous_or_prerelease_observations_are_not_admitted(self):
        for raw in (None, '', '1.2.1', '1.2.0-rc.1', '1.2.0+local',
                    'Pi 1.2.0', '1.2.0\n0.87.1', True, 'unreviewed'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                contracts.observed(raw)

    def test_image_target_and_worker_receipt_cannot_conflict(self):
        image = {'capabilities': {'pi': '0.87.1'}}
        self.assertEqual(lab.admit_image(image)['release'], '0.87.1')
        with self.assertRaisesRegex(lab.LabError, 'differs'):
            lab.admit_image(image, '1.2.0')
        image['capabilities']['release_contract'] = contracts.identity('1.2.0')
        with self.assertRaisesRegex(lab.LabError, 'mismatch'):
            lab.admit_image(image)
        for revision in (True, 1.0, None, '1'):
            value = contracts.identity('0.87.1'); value['revision'] = revision
            with self.assertRaises(ValueError): contracts.validate_binding(value, '0.87.1')

    def test_unreviewed_build_rejected_before_docker(self):
        args = argparse.Namespace(pi_version='1.2.0-rc.1')
        with mock.patch.object(lab, 'require_host') as host:
            with self.assertRaises(lab.LabError):
                lab.ensure_image(args)
        host.assert_not_called()

    def test_reuse_does_not_tag_an_image_with_the_wrong_target(self):
        args = argparse.Namespace(pi_version='1.2.0', image='target', reuse=['old'],
                                  policy='reuse', receipt=None)
        image = {'id': 'sha256:synthetic', 'capabilities': {'pi': '0.87.1'}}
        with mock.patch.object(lab, 'require_host', return_value={}), \
             mock.patch.object(lab, 'probe_image', return_value=image), \
             mock.patch.object(lab, 'command') as command:
            with self.assertRaisesRegex(lab.LabError, 'No acceptable'):
                lab.ensure_image(args)
        command.assert_not_called()

    def test_worker_version_and_contract_fail_before_configuration_or_inference(self):
        for task in ({'pi_release': '0.87.1', 'release_contract': contracts.identity('0.87.1')},
                     {'pi_release': '1.2.0', 'release_contract': contracts.identity('0.87.1')},
                     {'pi_release': '1.2.0'}):
            with self.subTest(task=task), \
                 mock.patch.object(worker, 'execute', return_value='1.2.0'), \
                 mock.patch.object(worker, 'select_cwd') as cwd, \
                 mock.patch.object(worker, 'model_configuration') as model:
                with self.assertRaises(ValueError):
                    worker.agent({}, task)
                cwd.assert_not_called()
                model.assert_not_called()

    def test_unreviewed_suite_image_cannot_launch_setup_worker_or_scorer(self):
        from test_results import fixture, mocked_suite
        with tempfile.TemporaryDirectory() as td, contextlib.ExitStack() as stack:
            args = fixture(Path(td))
            mocked_suite(stack)
            stack.enter_context(mock.patch.object(lab, 'probe_image', return_value={
                'id': 'synthetic', 'capabilities': {'pi': 'unreviewed'}}))
            stage = stack.enter_context(mock.patch.object(lab, 'run_stage'))
            score = stack.enter_context(mock.patch.object(lab.scoring, 'freeze'))
            worker_stage = stack.enter_context(mock.patch.object(lab.segments, 'execute'))
            self.assertEqual(lab.run_suite(args), 2)
            stage.assert_not_called()
            score.assert_not_called()
            worker_stage.assert_not_called()

    def test_probe_requires_release_specific_flags(self):
        def run(release, include_mcp):
            def execute(argv, **kwargs):
                if argv == ['pi', '--version']: return release
                if argv == ['node', '--version']: return 'v24.21.0'
                if argv == ['pi', '--help']:
                    return ' '.join(contracts.COMMON_FLAGS) + (' --no-mcp' if include_mcp else '')
                return 'synthetic version'
            with mock.patch.object(worker.shutil, 'which', return_value='/synthetic'), \
                 mock.patch.object(worker, 'execute', side_effect=execute), \
                 mock.patch.object(worker, 'emit') as emit:
                worker.probe('core')
                return emit.call_args.args[0]
        self.assertEqual(run('0.87.1', False)['release_contract'], contracts.identity('0.87.1'))
        with self.assertRaisesRegex(RuntimeError, '--no-mcp'):
            run('1.2.0', False)
        self.assertEqual(run('1.2.0', True)['release_contract'], contracts.identity('1.2.0'))


class MappingTests(unittest.TestCase):
    def endpoint(self):
        return {'base_url': 'http://fixture.invalid/v1', 'model': 'exact/model',
                'context_window': 32768, 'max_tokens': 4096}

    def test_preserved_old_emission_matches_the_recorded_baseline_mapper(self):
        # Frozen old semantics are independent expected values, not calls to new code.
        expected_settings = {'packages': [], 'extensions': [], 'defaultThinkingLevel': 'off',
            'retry': {'enabled': False, 'provider': {'maxRetries': 0}},
            'compaction': {'enabled': False}, 'cacheWarming': 'off'}
        expected_model = {'id': 'exact/model', 'name': 'exact/model', 'input': ['text'],
            'contextWindow': 32768, 'maxTokens': 4096,
            'compat': {'maxTokensField': 'max_tokens'}, 'reasoning': False}
        models, settings, argv, _ = pi_contract.model_configuration(self.endpoint(), '0.87.1')
        self.assertEqual(settings, expected_settings)
        self.assertEqual(models, {'providers': {'local-lab': {'baseUrl': 'http://fixture.invalid/v1',
            'api': 'openai-completions', 'apiKey': '$PI_LAB_API_KEY', 'models': [expected_model]}}})
        self.assertEqual(argv, ['--thinking', 'off'])

    def test_both_release_settings_levels_sampling_and_argv(self):
        for release in contracts.RELEASES:
            for level in pi_contract.LEVELS:
                config = {**self.endpoint(), 'reasoning': {'enabled': level != 'off', 'level': level},
                          'sampling': {'temperature': 0.5, 'seed': 123}}
                models, settings, thinking, receipt = pi_contract.model_configuration(config, release)
                model = models['providers']['local-lab']['models'][0]
                self.assertEqual(model['samplingParams'], config['sampling'])
                self.assertEqual(settings['defaultThinkingLevel'], level)
                self.assertFalse(settings['retry']['enabled'])
                self.assertEqual(settings['retry']['provider']['maxRetries'], 0)
                self.assertFalse(settings['compaction']['enabled'])
                self.assertEqual(settings['cacheWarming'], 'off')
                self.assertEqual(receipt['release_contract'], contracts.identity(release))
                args = worker.agent_pi_arguments(config, {'tools': ['read'], 'pi_release': release},
                                                 Path('/synthetic/agent'), thinking)
                self.assertEqual('--no-mcp' in args, release == '1.2.0')
                self.assertIn('--no-extensions', args)
                self.assertEqual(args[args.index('--tools')+1], 'read')

    def test_unknown_off_and_unsupported_controls_never_fall_back_or_drop(self):
        for release in (None, 'unreviewed', '1.2.0-beta'):
            with self.assertRaises(ValueError):
                pi_contract.model_configuration({**self.endpoint(), 'reasoning': False}, release)
        for release in contracts.RELEASES:
            for bad in ({'reasoning': {'enabled': True, 'level': 'low', 'budget_tokens': 1024}},
                        {'sampling': {'model': 'other'}}, {'sampling': {'temperature': True}},
                        {'sampling': {'seed': 1.5}}, {'sampling': {'max_tokens': 999999}}):
                with self.subTest(release=release, bad=bad), self.assertRaises(ValueError):
                    pi_contract.model_configuration({**self.endpoint(), **bad}, release)


class FrozenRegistryTests(unittest.TestCase):
    def fixture(self):
        from test_experiments import ExperimentFixture
        value = ExperimentFixture(); value.setUp(); self.addCleanup(value.doCleanups)
        value.prepare()
        return value

    def reseal(self, root):
        import hashlib
        path = root / 'integrity.json'; value = json.loads(path.read_text())
        value['files']['experiment.json'] = lab.tree_hashes(root / 'experiment.json', include_ignored=True)['.']
        value['fingerprint'] = provenance.digest(value['files'])
        path.chmod(0o600); path.write_text(json.dumps(value))

    def test_preparation_freezes_contracts_without_docker_and_tamper_blocks_execution(self):
        fixture = self.fixture(); root = fixture.root / 'prepared'
        metadata, _ = experiments.verify(root, lab)
        self.assertEqual(metadata['release_contracts'], contracts.snapshot())
        metadata['release_contracts']['1.2.0']['sha256'] = '0' * 64
        path = root / 'experiment.json'; path.chmod(0o600); path.write_text(json.dumps(metadata))
        self.reseal(root)
        runner = mock.Mock()
        with self.assertRaisesRegex(experiments.ExperimentError, 'release contracts'):
            experiments.execute(root, lab, runner=runner)
        runner.assert_not_called()
        self.assertFalse((root / 'attempts').exists())

    def test_historical_metadata_stays_readable_but_cannot_execute_as_current(self):
        fixture = self.fixture(); root = fixture.root / 'prepared'
        metadata, _ = experiments.verify(root, lab)
        metadata.pop('release_contracts')
        path = root / 'experiment.json'; path.chmod(0o600); path.write_text(json.dumps(metadata))
        self.reseal(root); before = path.read_bytes()
        saved, _ = experiments.verify(root, lab)
        self.assertNotIn('release_contracts', saved)
        self.assertEqual(path.read_bytes(), before)
        with self.assertRaisesRegex(experiments.ExperimentError, 'release contracts'):
            experiments.execute(root, lab, runner=mock.Mock())
        self.assertEqual(path.read_bytes(), before)

    def test_unknown_native_image_rejected_before_attempt_reservation(self):
        fixture = self.fixture(); root = fixture.root / 'prepared'
        with mock.patch.object(experiments.platform, 'machine', return_value='arm64'), \
             mock.patch.object(experiments.lab_env, 'require_ready', return_value=fixture.root / 'endpoint.json'), \
             mock.patch.object(experiments.resources, 'admission_lock', return_value=contextlib.nullcontext()), \
             mock.patch.object(lab, 'require_host', return_value={}), \
             mock.patch.object(lab, 'probe_image', return_value={'id': 'synthetic', 'capabilities': {'pi': 'future'}}), \
             mock.patch.object(experiments, 'reserve_attempt') as reserve:
            with self.assertRaises(lab.LabError):
                experiments.execute(root, lab, session='synthetic')
        reserve.assert_not_called()


class ProfileReleaseTests(unittest.TestCase):
    def test_matching_profiles_are_explicit_and_never_substituted(self):
        old = agent_profiles.load(ROOT / 'assets/profiles/fixture-lookup/profile.json')
        new = agent_profiles.load(ROOT / 'assets/profiles/fixture-lookup/profile.pi-1.2.0.json')
        self.assertNotEqual(agent_profiles.identity(old), agent_profiles.identity(new))
        self.assertEqual(old['assets'], new['assets'])
        for profile, release in ((old, '0.87.1'), (new, '1.2.0')):
            self.assertEqual(agent_profiles.admit(profile, release), contracts.identity(release))
            with self.assertRaises(agent_profiles.ProfileError):
                agent_profiles.admit(profile, '1.2.0' if release == '0.87.1' else '0.87.1')
        bad = copy.deepcopy(new); bad['components'][0]['pi_release'] = '1.2.1'
        with self.assertRaises(agent_profiles.ProfileError):
            agent_profiles.validate(bad, ROOT / 'assets/profiles/fixture-lookup')

    def test_generators_keep_old_calls_and_select_new_profile_from_observed_receipt(self):
        import importlib.util
        import subprocess
        for name, output_option in (('application-baseline', '--output-dir'),
                                    ('integration-baseline', '--output')):
            script = ROOT / 'examples' / name / 'configure.py'
            spec = importlib.util.spec_from_file_location(name + '-migration-test', script)
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            generator = module.definitions if name == 'application-baseline' else module.definition
            image = 'sha256:' + 'a' * 64
            self.assertEqual(generator(image), generator(image, '0.87.1'))
            for release in contracts.RELEASES:
                with tempfile.TemporaryDirectory() as td:
                    root = Path(td); receipt = root / 'receipt.json'; output = root / 'output'
                    receipt.write_text(json.dumps({'id': image, 'platform': 'linux/arm64',
                                                   'capabilities': {'pi': release}}))
                    result = subprocess.run([sys.executable, str(script), '--image-receipt', str(receipt),
                                             output_option, str(output)], capture_output=True, text=True, timeout=8)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    if name == 'integration-baseline':
                        value = json.loads(output.read_text())
                        profile = agent_profiles.load(value['variants'][1]['agent_profile'])
                        self.assertEqual(profile['components'][0]['pi_release'], release)
                    before = {p.name: p.read_bytes() for p in output.iterdir()} if output.is_dir() else output.read_bytes()
                    again = subprocess.run([sys.executable, str(script), '--image-receipt', str(receipt),
                                            output_option, str(output)], capture_output=True, timeout=8)
                    self.assertNotEqual(again.returncode, 0)
                    after = {p.name: p.read_bytes() for p in output.iterdir()} if output.is_dir() else output.read_bytes()
                    self.assertEqual(before, after)


class ContinuationBindingTests(unittest.TestCase):
    def record(self, release='0.87.1', image='sha256:old'):
        return {'segment_id': 's1', 'ordinal': 1, 'session_id': 'session',
                'execution_identity': {'image_id': image, 'release_contract': contracts.identity(release)},
                'process': {'cleanup_confirmed': True},
                'evidence': {'session_id': 'session', 'identity_verified': True,
                             'agent_invocation_verified': True, 'successful_tools': {'read': 1},
                             'final_text': 'done'}}

    def test_exact_admitted_identity_required_across_both_releases(self):
        for release in contracts.RELEASES:
            record = self.record(release)
            expected = copy.deepcopy(record['execution_identity'])
            self.assertTrue(segments.aggregate([record], 'model', ['read'], set(), expected)['completion_verified'])
            for fault in ('image', 'release', 'digest', 'absent'):
                changed = copy.deepcopy(record)
                if fault == 'image': changed['execution_identity']['image_id'] = 'sha256:other'
                if fault == 'release': changed['execution_identity']['release_contract'] = contracts.identity('1.2.0' if release == '0.87.1' else '0.87.1')
                if fault == 'digest': changed['execution_identity']['release_contract']['sha256'] = '0' * 64
                if fault == 'absent': changed.pop('execution_identity')
                self.assertFalse(segments.aggregate([changed], 'model', ['read'], set(), expected)['completion_verified'])

    def test_authorized_interrupt_cannot_clear_original_tool_or_retry_violation(self):
        first = self.record('1.2.0')
        first['process']['interrupts_applied'] = ['command']
        first['evidence'].update(agent_invocation_verified=False, policy_errors=['Tool outside declared allowlist: other'])
        second = self.record('1.2.0')
        second.update(segment_id='s2', ordinal=2, continues_segment_id='s1',
                      command_id='command', session_sha256='synthetic')
        self.assertFalse(segments.aggregate([first, second], 'model', ['read'], {'command'},
                                          first['execution_identity'])['completion_verified'])
        first['evidence']['policy_errors'] = ['Pi settled with aborted work; no clean completion']
        result = segments.aggregate([first, second], 'model', ['read'], {'command'}, first['execution_identity'])
        self.assertTrue(result['completion_verified'])
        self.assertEqual(result['invocation_status'], 'recovered')
        self.assertFalse(result['agent_invocation_verified'])

    def test_profile_receipt_violation_cannot_be_cleared_by_a_clean_successor(self):
        for release in contracts.RELEASES:
            first = self.record(release)
            first['process']['interrupts_applied'] = ['command']
            first['evidence'].update(agent_invocation_verified=False, protocol_errors=[], policy_errors=[],
                agent_profile={'loading': 'unverified', 'errors': ['Effective active tool set differs from declared allowlist']})
            second = self.record(release)
            second.update(segment_id='s2', ordinal=2, continues_segment_id='s1',
                          command_id='command', session_sha256='synthetic')
            result = segments.aggregate([first, second], 'model', ['read'], {'command'}, first['execution_identity'])
            self.assertFalse(result['completion_verified'])
            self.assertEqual(result['invocation_status'], 'invalid')

    def test_early_user_only_session_can_be_frozen_without_inventing_assistant_identity(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root / 'sessions').mkdir()
            records = [{'type': 'session', 'version': 3, 'id': 'early', 'cwd': '/workspace'},
                       {'type': 'model_change', 'provider': 'local-lab', 'modelId': 'model'},
                       {'type': 'message', 'message': {'role': 'user', 'content': 'task'}}]
            source = root / 'sessions/early.jsonl'
            source.write_text(''.join(json.dumps(x) + '\n' for x in records))
            target = root / 'frozen.jsonl'
            segments.freeze_session(root, 'early', '/workspace', 'model', target)
            self.assertEqual(source.read_bytes(), target.read_bytes())
            with self.assertRaises(segments.controls.ControlError):
                segments.freeze_session(root, 'early', '/other', 'model', target)


class EventContractTests(unittest.TestCase):
    def trace(self, release):
        data = json.loads((ROOT / 'references/pi-0.87.1.examples.json').read_text())
        events = copy.deepcopy(data['event_examples'][0]['records'])
        if release == '1.2.0': events[-1]['aborted'] = False
        return events

    def result(self, release, events=None, exit_code=0, **kwargs):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'events.jsonl'
            path.write_text(''.join(json.dumps(e) + '\n' for e in
                                    (self.trace(release) if events is None else events)))
            return analyze(path, 'example/model', [], exit_code, release=release, **kwargs)

    def test_both_clean_contracts_and_preserved_fieldless_old_trace(self):
        for release in contracts.RELEASES:
            result = self.result(release)
            self.assertTrue(result['agent_invocation_verified'], result['errors'])
            self.assertEqual(result['release_contract'], contracts.identity(release))
        self.assertNotIn('aborted', self.trace('0.87.1')[-1])

    def test_cancelled_and_malformed_settlement_cannot_be_verified(self):
        for value in (True, None, 'false', 0, 1, [], {}):
            with self.subTest(value=value):
                events = self.trace('1.2.0'); events[-1]['aborted'] = value
                result = self.result('1.2.0', events)
                self.assertFalse(result['completion_verified'])
                self.assertFalse(result['agent_invocation_verified'])
                self.assertEqual(result['invocation_status'], 'invalid')
        events = self.trace('1.2.0'); events[-1].pop('aborted')
        self.assertFalse(self.result('1.2.0', events)['protocol_valid'])

    def test_wrong_contract_unknown_version_and_nested_calls_fail_closed(self):
        self.assertFalse(self.result('0.87.1', self.trace('1.2.0'))['protocol_valid'])
        for version in (None, '1.2.0-rc.1', '1.2.1'):
            self.assertFalse(self.result(version, self.trace('0.87.1'))['completion_verified'])
        events = self.trace('1.2.0')
        next(e for e in events if e['type'] == 'tool_execution_start')['parentToolCallId'] = 'outer'
        self.assertFalse(self.result('1.2.0', events)['protocol_valid'])

    def test_zero_process_exit_does_not_clear_unsuccessful_assistant_state(self):
        for release in contracts.RELEASES:
            for stop in ('length', 'error', 'aborted'):
                events = self.trace(release)
                final = next(e['message'] for e in reversed(events)
                             if e['type'] == 'message_end' and e['message']['role'] == 'assistant')
                final['stopReason'] = stop
                self.assertFalse(self.result(release, events)['agent_invocation_verified'])

    def test_legacy_is_explicit_historical_only_and_never_reviewed_release_fallback(self):
        for release in contracts.RELEASES:
            for historical in (False, True):
                result = self.result(release, self.trace(release)[:-1],
                                     completion_contract='process-exit', historical=historical)
                self.assertFalse(result['agent_invocation_verified'])
        result = self.result(None, self.trace('0.87.1')[:-1],
                             completion_contract='process-exit', historical=True)
        self.assertTrue(result['protocol_valid'])
        self.assertEqual(result['analysis_scope'], 'historical trace inspection')
        self.assertIsNone(result['release_contract'])
        self.assertFalse(self.result(None, self.trace('0.87.1')[:-1],
                                     completion_contract='process-exit')['completion_verified'])

    def test_duplicate_premature_and_late_settlement_work_reject_on_both_releases(self):
        for release in contracts.RELEASES:
            for fault in ('duplicate', 'early', 'missing', 'late'):
                with self.subTest(release=release, fault=fault):
                    events = self.trace(release)
                    if fault == 'duplicate': events.append(copy.deepcopy(events[-1]))
                    if fault == 'early': events.insert(1, copy.deepcopy(events[-1]))
                    if fault == 'missing': events.pop()
                    if fault == 'late': events.append({'type': 'agent_start'})
                    self.assertFalse(self.result(release, events)['completion_verified'])


if __name__ == '__main__':
    unittest.main()
