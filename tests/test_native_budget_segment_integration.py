"""Real runner/segment/coordinator wiring; Docker/helper/Pi boundaries are mocked.

Synthetic retained Pi traces establish orchestration only. No process, Docker,
network, browser or model is launched. FakeHelper is not a native ledger oracle.
"""
import argparse
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'skill/scripts'), str(ROOT / 'skill/runtime')]
import application_credentials as credentials
import native_budget_execution as execution
import ownership_registry
import pi_lab as lab
import provenance
import resources
import stage_control as controls
import test_controls as control_fixtures
import test_native_budget_execution as execution_fixtures
import test_results as result_fixtures


class SyntheticProcess:
    pid = 12345
    def __init__(self, trace):
        self.stdout = io.BytesIO(''.join(json.dumps(row) + '\n' for row in trace).encode())
        self.stderr = io.BytesIO()
    def poll(self): return 0
    def wait(self, timeout=None): return 0
    def kill(self): pass


class SegmentWiringTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve(); self.run = self.root / 'run'; self.run.mkdir()
        self.workspace = self.run / 'workspace'; self.workspace.mkdir()
        self.project = self.root / 'project'; self.project.mkdir()
        self.args = control_fixtures.args(network='bridge', profile='core', native_platform='linux/arm64',
            observed_pi_version='0.87.1', event_contract='settled', project=str(self.project), in_place=False,
            lock_file=str(self.root / 'lease'))
        policy = copy.deepcopy(resources.DEFAULTS)
        policy['runtime'] = {'cpus': 1., 'memory': '1g', 'pids_limit': 256, 'jobs': 1}
        self.args.resource_report = {'effective': policy}
        self.plan = lab.validate_plan({'schema': 1, 'agents': [{'name': 'dev', 'prompt': 'Synthetic orchestration',
            'tools': ['read'], 'require_tools': ['read'], 'timeout_seconds': 90, 'max_turns': 10,
            'max_total_tokens': 10000, 'max_tool_calls': 8, 'reporting_reserve_calls': 2,
            'reporting_reserve_seconds': 10}], 'checks': [{'argv': ['true']}]}, self.run)
        self.task = self.plan['agents'][0]
        controls.atomic(self.run / 'plan.json', self.plan)
        self.registry = argparse.Namespace(binding={}, generation='fixture', load=lambda: [])
        self.registry.intent = lambda argv, name, binding: ({'launch_id': name}, argv)
        self.registry.check_cancel = lambda: None
        self.registry.confirm_absent = lambda launch: not (self.unknown_successor and len(self.launches) > 1)
        token = ownership_registry.CURRENT.set(self.registry)
        self.addCleanup(ownership_registry.CURRENT.reset, token)
        self.events, self.coordinators, self.helpers, self.launches, self.contexts, self.known_values = [], [], [], [], [], []
        self.continue_once = False; self.unknown_successor = False; self.finish_values = None
        self.application_secrets = {}
        self.stack = contextlib.ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(lab, 'docker_info', return_value={'NCPU': 8, 'MemTotal': 16 * 1024 ** 3}))
        self.stack.enter_context(mock.patch.object(lab, 'command', side_effect=self.docker))
        self.popen = self.stack.enter_context(mock.patch.object(lab.subprocess, 'Popen', side_effect=self.launch))
        self.stack.enter_context(mock.patch.object(execution.OwnedHelper, 'start', side_effect=self.helper))
        original_prepare = execution.prepare
        def prepare(*args, **kwargs):
            self.events.append('prepare'); co = original_prepare(*args, **kwargs); self.coordinators.append(co)
            for name in ('begin_segment', 'mark_running', 'after_segment', 'close'):
                original = getattr(co, name)
                def observed(*values, _name=name, _original=original, **fields):
                    self.events.append((_name, values, fields))
                    return _original(*values, **fields)
                setattr(co, name, observed)
            return co
        self.stack.enter_context(mock.patch.object(execution, 'prepare', side_effect=prepare))
        original_collect = provenance.collect_emitted
        def collect(*args, **kwargs):
            self.events.append('provenance')
            self.assertTrue(self.coordinators[-1]._settled)
            return original_collect(*args, **kwargs)
        self.stack.enter_context(mock.patch.object(provenance, 'collect_emitted', side_effect=collect))
        original_finish = credentials.finish
        def finish(run, desc, app_values, inference_key, result, redaction_values=()):
            self.finish_values = list(redaction_values)
            return original_finish(run, desc, app_values, inference_key, result, redaction_values)
        self.stack.enter_context(mock.patch.object(credentials, 'finish', side_effect=finish))
        self.stack.enter_context(mock.patch.dict(os.environ, {'PI_APP_UNASSIGNED': 'ambient-application-canary'}))

    def helper(self, authority, **kwargs):
        self.events.append('helper_start')
        self.assertFalse(list(Path(authority.runroot).glob('controls/*/segments/*/task.json')))
        helper = execution_fixtures.FakeHelper(authority, **kwargs)
        helper.value['per_tool']['read'] = helper.value['per_tool'].pop('bash')
        self.helpers.append(helper)
        return helper

    def docker(self, argv, **kwargs):
        if argv[1:2] == ['inspect']:
            return subprocess.CompletedProcess(argv, 0, json.dumps([{'State': {'ExitCode': 0}, 'HostConfig': {}}]), '')
        if argv[1:3] == ['rm', '-f']:
            bad = self.unknown_successor and len(self.launches) > 1
            return subprocess.CompletedProcess(argv, 1 if bad else 0, '', 'daemon unavailable' if bad else '')
        raise AssertionError('Unexpected mocked Docker boundary: ' + str(argv[:3]))

    def launch(self, argv, **kwargs):
        self.events.append('Popen'); self.launches.append((argv, kwargs))
        co = self.coordinators[-1]
        self.assertEqual(co.reservation.state, 'launching')
        self.assertFalse(co._running)
        segment = controls.resolve(self.run, co.desc['stage_id'])[1]['segment_id']
        control = Path(co.desc['control']) / 'segments' / segment
        task = controls.read(control / 'task.json')
        path = control / 'native-budget-context.json'
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
        context = controls.read(path); self.contexts.append(context)
        self.known_values.extend(co.redaction_values())
        self.assertEqual(task['native_budget_context'], '/opt/pi-control/segments/' + segment + '/native-budget-context.json')
        self.assertNotIn(context['capability'], json.dumps(task))
        self.assertEqual({item for item in argv if item.startswith('PI_APP_')}, set(self.application_secrets))
        self.assertEqual({key: value for key, value in kwargs['env'].items() if key.startswith('PI_APP_')},
                         self.application_secrets)
        if self.unknown_successor and len(self.launches) == 2:
            raise KeyboardInterrupt('synthetic successor interrupted before Popen returned')
        trace = result_fixtures.SegmentTests().trace(task['session_id'], model='fixture-model')
        runtime = next(item.split('src=', 1)[1].split(',dst=', 1)[0] for item in argv if 'dst=/pi-state,' in item)
        (Path(runtime) / 'sessions/session.jsonl').write_text(json.dumps(trace[0]) + '\n')
        helper = self.helpers[-1]
        helper.value['counts']['attempted'] += 1; helper.value['counts']['charged'] += 1
        helper.value['per_tool']['read']['attempted'] += 1; helper.value['per_tool']['read']['charged'] += 1
        helper.value['remaining_calls'] -= 1; helper.value['remaining_admissible_calls'] -= 1
        helper.value['business_calls_remaining'] -= 1
        if self.continue_once and len(self.launches) == 1:
            with contextlib.redirect_stdout(io.StringIO()):
                lab.cmd_steer(control_fixtures.args(run=str(self.run), stage=co.desc['stage_id'],
                    message='Explicitly authorized second segment', interrupt=False))
        return SyntheticProcess(trace)

    def execute(self):
        return lab.run_stage(self.args, 'sha256:' + 'a' * 64, self.run, self.workspace, 'agent-1-dev',
            ['agent'], task=self.task, endpoint={'model': 'fixture-model'}, secret='synthetic-inference-canary', timeout=90,
            application_secrets=self.application_secrets)

    def test_actual_runner_admits_private_context_before_pi_and_checkpoints_before_provenance(self):
        result = self.execute()
        self.assertEqual(result['exit_code'], 0, result)
        self.assertTrue(result['cleanup_confirmed'])
        self.assertTrue(result['evidence']['completion_verified'], result['evidence'])
        self.assertLess(self.events.index('prepare'), self.events.index('helper_start'))
        self.assertLess(self.events.index('helper_start'), self.events.index('Popen'))
        names = [event[0] if isinstance(event, tuple) else event for event in self.events]
        self.assertLess(names.index('begin_segment'), names.index('Popen'))
        self.assertLess(names.index('Popen'), names.index('mark_running'))
        self.assertLess(names.index('after_segment'), names.index('provenance'))
        self.assertEqual(result['native_tool_budget']['counts']['charged'], 1)
        self.assertEqual(result['application_credentials']['status'], 'removed')
        self.assertEqual(result['application_credentials']['workspace'], 'clean')
        self.assertFalse(list(self.run.glob('controls/*/segments/*/native-budget-context.json')))
        self.assertFalse(list(self.run.glob('children/.pi-lab/*/sessions/session.jsonl')))
        self.assertNotIn('native_context_sink', vars(self.args))
        serialized = json.dumps(result) + ''.join(path.read_text() for path in self.run.glob('agent-1-dev/segments/*/command.json'))
        for context in self.contexts:
            self.assertNotIn(context['capability'], serialized)

    def test_explicit_continuation_preserves_one_helper_session_and_cumulative_counts(self):
        self.continue_once = True
        result = self.execute()
        self.assertTrue(result['evidence']['completion_verified'], result)
        self.assertEqual(len(self.launches), 2)
        self.assertEqual(len(self.helpers), 1)
        self.assertEqual(self.contexts[0]['scope']['session_id'], self.contexts[1]['scope']['session_id'])
        self.assertNotEqual(self.contexts[0]['capability'], self.contexts[1]['capability'])
        self.assertEqual(result['native_tool_budget']['counts']['charged'], 2)
        self.assertTrue(result['segments'][1]['session_sha256'])
        for context in self.contexts:
            self.assertIn(context['capability'], self.finish_values)

    def test_all_known_private_capabilities_reach_sensitive_stage_finish_scan(self):
        result = self.execute()
        self.assertEqual(result['application_credentials']['workspace'], 'clean')
        self.assertIsNotNone(self.finish_values)
        self.assertTrue(set(self.known_values).issubset(set(self.finish_values)),
                        'Capabilities known before allocator rotation/release must remain scan inputs')

    def test_explicit_legacy_application_assignment_keeps_its_existing_env_scope(self):
        self.task['application_secrets'] = {'PI_APP_KEY': 'LEGACY_PERSONA'}
        controls.atomic(self.run / 'plan.json', self.plan)
        self.application_secrets = {'PI_APP_KEY': 'synthetic-legacy-application-canary'}
        result = self.execute()
        self.assertEqual(result['exit_code'], 0, result)
        argv, fields = self.launches[0]
        self.assertIn('PI_APP_KEY', argv)
        self.assertEqual(fields['env']['PI_APP_KEY'], self.application_secrets['PI_APP_KEY'])
        self.assertNotIn(self.application_secrets['PI_APP_KEY'], json.dumps(argv))
        self.assertNotIn('PI_APP_UNASSIGNED', fields['env'])
        self.assertEqual(result['application_credentials']['workspace'], 'clean')

    def test_interrupted_successor_unknown_writer_never_inherits_prior_clean_receipt(self):
        self.continue_once = self.unknown_successor = True
        with self.assertRaises(KeyboardInterrupt): self.execute()
        co = self.coordinators[-1]
        closes = [event for event in self.events if isinstance(event, tuple) and event[0] == 'close']
        self.assertFalse(closes[-1][2]['writers_confirmed'])
        self.assertEqual(co.reservation.state, 'quarantined')
        self.assertFalse(co.closed)
        self.assertTrue(list(self.run.glob('controls/*/segments/*/native-budget-context.json')))
        receipt = controls.read(self.run / 'stages' / co.desc['stage_id'] / 'application-credentials.json')
        self.assertEqual((receipt['status'], receipt['workspace']), ('cleanup_unconfirmed', 'quarantined'))
        self.assertEqual(sum(event == 'provenance' for event in self.events), 1)

    def test_missing_native_coordinator_cannot_start_pi(self):
        with mock.patch.object(execution, 'prepare', return_value=None):
            with self.assertRaises((AttributeError, ValueError, controls.ControlError)): self.execute()
        self.popen.assert_not_called()


class PartialHelperStartTests(unittest.TestCase):
    def test_failed_helper_start_with_live_allocator_intent_blocks_cleanup(self):
        fixture = execution_fixtures.CoordinatorTests(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        co = fixture.prepare()
        def interrupted(authority, allocator, **kwargs):
            item = allocator.request('partial-helper', {'generation': 'fixture'},
                {'cpu_millis': 1000, 'memory_mib': 512, 'pids_limit': 128}, 30, 'helper')
            allocator.dispatch()
            self.assertEqual(item.state, 'reserved')
            raise OSError('synthetic partial helper launch')
        fixture.start.side_effect = interrupted
        with self.assertRaises(execution.NativeExecutionError): fixture.begin(co)
        self.assertTrue(co._helper_attempted)
        self.assertIsNone(co.helper)
        with mock.patch.object(execution, '_purge_context') as purge:
            with self.assertRaises(execution.NativeExecutionError): co.close(True)
        purge.assert_not_called()
        self.assertFalse(co.pool.dependent_cleanup_confirmed)
        self.assertTrue(co.pool.closed)
        self.assertFalse(co.closed)

    def test_failed_helper_start_with_unreleased_registry_record_blocks_cleanup(self):
        fixture = execution_fixtures.CoordinatorTests(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        co = fixture.prepare()
        fixture.start.side_effect = OSError('synthetic launch after durable registry intent')
        fixture.registry.load = lambda: [{'application_helper': True, 'client_mode': 'budget-only',
            'binding': {'stage_id': fixture.desc['stage_id']}, 'status': 'launching'}]
        with self.assertRaises(execution.NativeExecutionError): fixture.begin(co)
        self.assertIsNone(co.helper)
        with mock.patch.object(execution, '_purge_context') as purge:
            with self.assertRaises(execution.NativeExecutionError): co.close(True)
        purge.assert_not_called()
        self.assertFalse(co.pool.dependent_cleanup_confirmed)
        self.assertTrue(co.pool.closed)
        self.assertFalse(co.closed)


if __name__ == '__main__': unittest.main()
