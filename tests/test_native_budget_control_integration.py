"""Host controls and real helper ledgers, entirely in process.

The adapter replaces only private transport. No subprocess, socket, Docker,
native tool, model or application request is executed by these tests.
"""
import contextlib
import copy
import io
import itertools
import json
from pathlib import Path
import sys
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'skill/scripts'), str(ROOT / 'skill/runtime')]
import experiments
import pi_lab as lab
import stage_control as controls
import test_experiments as experiment_fixture
import test_native_budget_service as service_fixture

LEGACY = {'timeout_seconds': 100, 'max_turns': 10, 'max_total_tokens': 1000}
NATIVE = {'max_tool_calls': 6, 'reporting_reserve_calls': 2, 'reporting_reserve_seconds': 10}


class InProcessControl:
    """Parent protocol adapter backed by an actual BudgetOnlyService ledger."""
    def __init__(self, instance, run, desc):
        self.instance, self.run, self.desc = instance, run, desc
        self.calls = []
        self.loss = None
        self.applying = []

    def status(self, force=False):
        self.calls.append(('status', force))
        return self.instance.request('/control', '1' * 64,
                                     {'schema': 1, 'action': 'status'})['budget']

    def extend(self, *, command_id, max_tool_calls, remaining_seconds):
        self.calls.append(('extend', command_id, max_tool_calls, remaining_seconds))
        response = controls.budget_path(self.run, self.desc).parent / 'budget-updates' / (command_id + '.json')
        self.applying.append(controls.read(response))
        result = self.instance.request('/control', '1' * 64, {'schema': 1, 'action': 'extend',
            'max_tool_calls': max_tool_calls, 'remaining_seconds': remaining_seconds})['budget']
        if self.loss is not None:
            raise self.loss
        return result


class NativeBudgetControlIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = service_fixture.NativeBudgetServiceTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.clock = mock.patch('time.monotonic', return_value=100.0)
        self.clock.start(); self.addCleanup(self.clock.stop)

    def stage(self, *, native=True, start=True):
        run = self.root / 'run'; run.mkdir()
        workspace = self.root / 'workspace'; workspace.mkdir()
        stage_id = str(uuid.uuid4())
        control = run / 'controls' / stage_id; control.mkdir(parents=True)
        for name in ('inbox', 'outbox'):
            (control / name).mkdir()
        state = run / 'children' / stage_id; state.mkdir(parents=True)
        limits = {**LEGACY, **(NATIVE if native else {})}
        desc = controls.create(run, workspace, 'implementer', 'agent', limits, control,
                               state, stage_id, 'synthetic-container')
        controls.transition(run, desc, 'running')
        self.fixture.scope.update(run_id=desc['run_id'], attempt_id=desc['attempt_id'], stage_id=stage_id)
        self.fixture.config['stage']['scope'] = self.fixture.scope
        instance = self.fixture.create() if native else None
        adapter = InProcessControl(instance, run, desc) if native else None
        if start:
            controls.start_budget(run, desc, 100.0, native_control=adapter)
        return run, desc, adapter

    def queue(self, run, desc, *flags):
        args = lab.parser().parse_args(['extend-budget', '--run', str(run), '--stage', desc['stage_id'],
            '--revision', '1', '--budget-revision', str(controls.read(controls.budget_path(run, desc))['revision']),
            *flags])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(lab.cmd_extend_budget(args), 0)
        return json.loads(output.getvalue())

    def command(self, run, desc, limits, *, audit=True):
        state = controls.resolve(run, desc['stage_id'])[1]
        record = controls.command_record(desc, state, 'extend_budget',
            {'expected_budget_revision': 0, 'limits': limits})
        if audit:
            controls.audit(run, record, 'requested')
        folder = controls.budget_path(run, desc).parent / 'budget-requests'
        folder.mkdir(exist_ok=True)
        controls.atomic(folder / (record['id'] + '.json'), record)
        return record

    def response(self, run, desc, command):
        return controls.read(controls.budget_path(run, desc).parent / 'budget-updates' /
                             ((command.get('command_id') or command['id']) + '.json'))

    def test_declared_native_budget_requires_live_parent_control_before_publication(self):
        run, desc, adapter = self.stage(start=False)
        with self.assertRaisesRegex(controls.ControlError, 'live parent control'):
            controls.start_budget(run, desc, 100.0)
        self.assertFalse(controls.budget_path(run, desc).exists())
        self.assertFalse((Path(desc['inbox']) / 'limits.json').exists())
        self.assertEqual(adapter.calls, [])

    def test_queued_audited_tool_call_increase_updates_one_shared_counter_without_reopening_business(self):
        run, desc, adapter = self.stage()
        result = self.fixture.batch(adapter.instance, 4)
        before = result['snapshot']
        self.assertEqual(before['phase'], 'reporting')
        command = self.queue(run, desc, '--tool-calls', '+3')
        self.assertEqual(command['status'], 'queued')
        self.assertEqual([event['status'] for event in controls.history(run)], ['requested', 'queued'])
        self.assertEqual(adapter.instance.ledger.snapshot()['limits']['max_tool_calls'], 6)
        budget = controls.process_budget_requests(run, desc, native_control=adapter)
        after = adapter.instance.ledger.snapshot()
        self.assertEqual(budget['revision'], 1)
        self.assertEqual(budget['original_limits'], {**LEGACY, **NATIVE})
        self.assertEqual(budget['effective_limits'], {**LEGACY, **NATIVE, 'max_tool_calls': 9})
        self.assertEqual(budget['native_tool_budget'], after)
        self.assertEqual(after['counts'], before['counts'])
        self.assertEqual(after['phase'], 'reporting')
        self.assertTrue(after['assisted'])
        for key in ('reporting_reserve_calls', 'reporting_reserve_seconds'):
            self.assertEqual(after['limits'][key], NATIVE[key])
        self.assertEqual(adapter.applying[0]['status'], 'applying')
        self.assertEqual(adapter.applying[0]['helper_applied'], 'unverified')
        self.assertEqual([event['status'] for event in controls.history(run)],
                         ['requested', 'queued', 'accepted', 'applied'])
        inbox = controls.read(Path(desc['inbox']) / 'limits.json')
        self.assertEqual((inbox['id'], inbox['budget_revision'], inbox['max_tool_calls']),
                         (command['command_id'], 1, 9))
        self.assertTrue(self.response(run, desc, command)['host_applied'])
        controls.process_budget_requests(run, desc, native_control=adapter)
        self.assertEqual(sum(call[0] == 'extend' for call in adapter.calls), 1)

    def test_reserve_edit_rejects_without_contacting_helper(self):
        run, desc, adapter = self.stage()
        before = adapter.instance.ledger.snapshot()
        command = self.command(run, desc, {**LEGACY, **NATIVE, 'max_tool_calls': 9,
                                          'reporting_reserve_calls': 3})
        budget = controls.process_budget_requests(run, desc, native_control=adapter)
        self.assertEqual(self.response(run, desc, command)['status'], 'rejected')
        self.assertEqual(budget['revision'], 0)
        self.assertEqual(adapter.instance.ledger.snapshot(), before)
        self.assertFalse(any(call[0] == 'extend' for call in adapter.calls))

    def test_unaudited_native_extension_cannot_grow_helper_or_host(self):
        run, desc, adapter = self.stage()
        command = self.command(run, desc, {**LEGACY, **NATIVE, 'max_tool_calls': 9}, audit=False)
        budget = controls.process_budget_requests(run, desc, native_control=adapter)
        self.assertEqual(self.response(run, desc, command)['status'], 'rejected')
        self.assertEqual(budget['effective_limits']['max_tool_calls'], 6)
        self.assertEqual(adapter.instance.ledger.snapshot()['limits']['max_tool_calls'], 6)
        self.assertFalse(any(call[0] == 'extend' for call in adapter.calls))

    def test_committed_helper_extension_response_loss_blocks_all_future_processing(self):
        run, desc, adapter = self.stage()
        self.fixture.batch(adapter.instance, 1)
        command = self.queue(run, desc, '--tool-calls', '+3')
        adapter.loss = OSError('synthetic response loss after helper committed')
        with self.assertRaisesRegex(controls.ControlError, 'unconfirmed'):
            controls.process_budget_requests(run, desc, native_control=adapter)
        self.assertEqual(adapter.applying[0]['status'], 'applying')
        self.assertEqual(adapter.instance.ledger.snapshot()['limits']['max_tool_calls'], 9)
        self.assertEqual(adapter.instance.ledger.snapshot()['counts']['charged'], 1)
        budget = controls.read(controls.budget_path(run, desc))
        self.assertEqual(budget['native_budget_error'], 'accounting_unavailable')
        self.assertEqual((budget['revision'], budget['effective_limits']['max_tool_calls']), (0, 6))
        response = self.response(run, desc, command)
        self.assertEqual((response['status'], response['helper_applied'], response['reason']),
                         ('rejected', 'unknown', 'native_budget_update_unconfirmed'))
        self.command(run, desc, {**LEGACY, **NATIVE, 'max_tool_calls': 10})
        count = len(adapter.calls)
        for closing in (False, True, False):
            with self.assertRaisesRegex(controls.ControlError, 'unconfirmed'):
                controls.process_budget_requests(run, desc, closing=closing, native_control=adapter)
        self.assertEqual(len(adapter.calls), count)
        self.assertEqual(sum(call[0] == 'extend' for call in adapter.calls), 1)

    def test_interrupted_applying_record_is_never_treated_as_confirmed_on_reentry(self):
        run, desc, adapter = self.stage()
        command = self.queue(run, desc, '--tool-calls', '+3')
        adapter.loss = KeyboardInterrupt('synthetic parent interruption after commit')
        with self.assertRaises(KeyboardInterrupt):
            controls.process_budget_requests(run, desc, native_control=adapter)
        self.assertEqual(self.response(run, desc, command)['status'], 'applying')
        self.assertEqual(adapter.instance.ledger.snapshot()['limits']['max_tool_calls'], 9)
        calls = len(adapter.calls)
        with self.assertRaisesRegex(controls.ControlError, 'Interrupted|unconfirmed'):
            controls.process_budget_requests(run, desc, native_control=adapter)
        self.assertEqual(len(adapter.calls), calls)

    def test_legacy_controls_keep_original_limit_fields_and_reject_new_native_ceiling(self):
        run, desc, adapter = self.stage(native=False)
        self.assertIsNone(adapter)
        before = controls.read(controls.budget_path(run, desc))
        self.assertEqual(before['original_limits'], LEGACY)
        self.assertEqual(before['effective_limits'], LEGACY)
        self.assertNotIn('native_tool_budget', before)
        with self.assertRaisesRegex(lab.LabError, 'declared before execution'):
            self.queue(run, desc, '--tool-calls', '+3')
        self.queue(run, desc, '--turns', '+2')
        after = controls.process_budget_requests(run, desc)
        self.assertEqual(after['effective_limits'], {**LEGACY, 'max_turns': 12})
        self.assertNotIn('native_tool_budget', after)


class NativeBudgetSchemaIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = experiment_fixture.ExperimentFixture()
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.fixture.definition['budgets'] = dict(LEGACY)
        self.fixture.root = self.fixture.root.resolve()

    def test_standalone_optional_tuple_has_no_defaults_and_remains_exact(self):
        original = copy.deepcopy(self.fixture.plan)
        legacy = lab.validate_plan(original, self.fixture.root)['agents'][0]
        self.assertFalse(set(NATIVE) & set(legacy))
        self.assertNotIn('budget_status', legacy['tools'])
        plan = copy.deepcopy(original)
        plan['agents'][0].update(LEGACY, **NATIVE)
        result = lab.validate_plan(plan, self.fixture.root)['agents'][0]
        self.assertEqual({key: result[key] for key in NATIVE}, NATIVE)
        self.assertEqual(result['tools'].count('budget_status'), 1)
        self.assertEqual(original, self.fixture.plan)

    def test_partial_native_tuple_rejected_in_standalone_and_experiment_budgets(self):
        keys = sorted(NATIVE)
        for length in (1, 2):
            for chosen in itertools.combinations(keys, length):
                with self.subTest(fields=chosen):
                    partial = {key: NATIVE[key] for key in chosen}
                    plan = copy.deepcopy(self.fixture.plan)
                    plan['agents'][0].update(LEGACY, **partial)
                    with self.assertRaises(lab.LabError):
                        lab.validate_plan(plan, self.fixture.root)
                    definition = copy.deepcopy(self.fixture.definition)
                    definition['budgets'].update(partial)
                    with self.assertRaises(ValueError):
                        self.fixture.validate(definition)

    def test_experiment_normalized_and_frozen_native_tools_and_limits_agree(self):
        self.fixture.definition['budgets'].update(NATIVE)
        definition = self.fixture.validate(self.fixture.definition)
        normalized = definition['cases'][0]['plan']['agents'][0]
        self.assertEqual(normalized['tools'].count('budget_status'), 1)
        self.assertEqual({key: normalized[key] for key in NATIVE}, NATIVE)
        self.fixture.prepare()
        metadata, matrix = experiments.verify(self.fixture.root / 'prepared', lab)
        for cell in matrix['cells']:
            with self.subTest(variant=cell['variant'], repetition=cell['repetition']):
                frozen = json.loads((self.fixture.root / 'prepared' / cell['plan']).read_text())['agents'][0]
                self.assertEqual(frozen['tools'], normalized['tools'])
                self.assertEqual({key: frozen[key] for key in NATIVE}, NATIVE)
                self.assertEqual(cell['budgets'], {**LEGACY, **NATIVE})

    def test_absent_experiment_native_limits_are_not_added_when_freezing(self):
        self.fixture.write('experiment.json', self.fixture.definition)
        self.fixture.prepare()
        _, matrix = experiments.verify(self.fixture.root / 'prepared', lab)
        for cell in matrix['cells']:
            frozen = json.loads((self.fixture.root / 'prepared' / cell['plan']).read_text())['agents'][0]
            self.assertFalse(set(NATIVE) & set(frozen))
            self.assertNotIn('budget_status', frozen['tools'])
            self.assertEqual(cell['budgets'], LEGACY)


if __name__ == '__main__': unittest.main()
