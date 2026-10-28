"""Native accounting outcome/export integration; no runtime or model execution."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'skill/scripts'), str(ROOT / 'skill/runtime')]
import experiments
import indexed_contract
import native_budget_reporting as reporting
import outcomes
import pi_lab as lab
import stage_control as controls
import test_indexed_experiments as indexed_fixture
import test_native_budget_reporting as reporting_fixture
import test_results as result_fixture


def passing(record=None):
    record = outcomes.initial() if record is None else copy.deepcopy(record)
    record['infrastructure'].update(status='ready', phase='agents')
    record['invocation'].update(status='verified', attempted_stages=1)
    record['termination'].update(reason='completed', process_exit_code=0)
    record['scoring'].update(status='completed')
    record['task_result'].update(status='pass', score=1)
    record['protected_inputs'].update(status='unchanged')
    return record


def native_record(process=None):
    record = passing()
    if process is not None:
        record['agents'] = [{'name': 'dev', 'process': process}]
    record['native_tool_budgets'] = reporting.record_projection(record,
        stage_names=['dev'], required_stages=['dev'])
    return record


class OutcomeGateTests(unittest.TestCase):
    def test_required_stage_missing_all_accounting_cannot_pass_other_successful_gates(self):
        for process in (None, {}, {'exit_code': 0, 'cleanup_confirmed': True, 'events': {'tool_calls': 100}}):
            record = native_record(process)
            before = copy.deepcopy(record)
            self.assertEqual(outcomes.status(record), ('FAIL', 1))
            self.assertEqual(record, before)
            stage = record['native_tool_budgets']['stages'][0]
            self.assertEqual(stage, {'stage': 'dev', **reporting.unavailable()})

    def test_valid_parent_accounting_can_pass_and_preserves_unknown_execution(self):
        record = native_record(reporting_fixture.process())
        self.assertEqual(outcomes.status(record), ('PASS', 0))
        self.assertIsNone(record['native_tool_budgets']['stages'][0]['budget']['counts']['executed'])
        self.assertEqual(record['native_tool_budgets']['stages'][0]['budget']['counts']['executed_unknown'], 1)
        for status, expected in [('recovered', ('RECOVERED', 1)), ('verified', ('ASSISTED', 1))]:
            changed = copy.deepcopy(record); changed['invocation']['status'] = status
            changed['assistance']['status'] = 'assisted'
            self.assertEqual(outcomes.status(changed), expected)

    def test_malformed_process_accounting_rejects_even_if_declared_projection_claims_success(self):
        original = native_record(reporting_fixture.process())
        for kind in ('missing-snapshot', 'missing-manifest', 'bool-schema', 'counter', 'untrusted-tool', 'error'):
            record = copy.deepcopy(original); process = record['agents'][0]['process']
            if kind == 'missing-snapshot': del process['native_tool_budget']
            elif kind == 'missing-manifest': del process['native_tool_manifest']
            elif kind == 'bool-schema': process['native_tool_manifest']['schema'] = True
            elif kind == 'counter': process['native_tool_budget']['counts']['charged'] += 1
            elif kind == 'untrusted-tool': process['native_tool_manifest']['tools'].append('private-token-canary')
            else: process['native_tool_budget_error'] = 'cleanup_unconfirmed'
            with self.subTest(kind=kind): self.assertEqual(outcomes.status(record), ('FAIL', 1))

    def test_invalid_declared_envelopes_and_snapshot_disagreement_cannot_pass(self):
        original = native_record(reporting_fixture.process())
        cases = [[], {}, {'schema': 1, 'scope': reporting.SCOPE, 'stages': []}]
        for key, value in [('schema', True), ('scope', 'other'), ('stages', [None])]:
            changed = copy.deepcopy(original['native_tool_budgets']); changed[key] = value; cases.append(changed)
        changed = copy.deepcopy(original['native_tool_budgets'])
        changed['stages'][0]['budget']['counts']['charged'] = 999; cases.append(changed)
        changed = copy.deepcopy(original['native_tool_budgets'])
        changed['stages'].append(copy.deepcopy(changed['stages'][0])); cases.append(changed)
        for declaration in cases:
            with self.subTest(declaration=declaration):
                record = copy.deepcopy(original); record['native_tool_budgets'] = declaration
                self.assertEqual(outcomes.status(record), ('FAIL', 1))

    def test_unavailable_accounting_and_cleanup_error_preserve_partial_counts_but_fail(self):
        for kind in ('accounting', 'cleanup'):
            process = reporting_fixture.process()
            if kind == 'accounting':
                process['native_tool_budget']['accounting'] = 'unavailable'
                process['native_tool_budget']['remaining_admissible_calls'] = 0
            else: process['native_tool_budget_error'] = 'cleanup_unconfirmed'
            record = native_record(process)
            self.assertEqual(outcomes.status(record), ('FAIL', 1))
            stage = record['native_tool_budgets']['stages'][0]
            self.assertEqual(stage['accounting'], 'unavailable')
            self.assertEqual(stage['budget']['counts']['charged'], 3)
            self.assertIsNone(stage['budget']['counts']['executed'])

    def test_legacy_success_and_failure_statuses_do_not_add_native_fields(self):
        record = passing(); encoded = json.dumps(record, separators=(',', ':'))
        self.assertEqual(outcomes.status(record), ('PASS', 0))
        self.assertEqual(json.dumps(record, separators=(',', ':')), encoded)
        self.assertNotIn('native_tool_budgets', record)
        record['task_result']['status'] = 'fail'
        self.assertEqual(outcomes.status(record), ('FAIL', 1))
        record['termination']['reason'] = 'cancelled'
        self.assertEqual(outcomes.status(record), ('INTERRUPTED', 2))


class SuiteProjectionTests(unittest.TestCase):
    def suite(self, native, process):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve(); args = result_fixture.fixture(root)
        if native:
            source = controls.read(args.plan)
            source['agents'][0].update(max_tool_calls=8, reporting_reserve_calls=2, reporting_reserve_seconds=10)
            controls.atomic(args.plan, source)
        attempt = outcomes.Attempt(args)
        seen = []
        def stage(args, image, run, workspace, label, operation, **kwargs):
            if operation[0] == 'boundary':
                seen.append(copy.deepcopy(attempt.record.get('native_tool_budgets')))
            folder = run / label; folder.mkdir(exist_ok=True)
            if operation[0] == 'agent':
                evidence = {'agent_invocation_verified': True, 'completion_verified': True,
                            'invocation_status': 'verified', 'errors': [], 'final_text': 'synthetic'}
                return {'exit_code': 0, 'cleanup_confirmed': True, 'evidence': evidence, **copy.deepcopy(process)}
            return {'exit_code': 0, 'cleanup_confirmed': True}
        def score(args, attempt, *values, **kwargs):
            attempt.record['scoring']['status'] = 'completed'
            attempt.record['task_result'].update(status='pass', score=1)
            attempt.record['protected_inputs']['status'] = 'unchanged'
            attempt.record['termination']['reason'] = 'completed'
        with contextlib.ExitStack() as stack:
            result_fixture.mocked_suite(stack)
            stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            stack.enter_context(mock.patch.object(lab, 'run_stage', side_effect=stage))
            stack.enter_context(mock.patch.object(lab, 'score_artifacts', side_effect=score))
            lab._execute_suite(args, attempt)
        return attempt.finalize(), seen

    def test_suite_marks_required_native_stage_before_dispatch_and_keeps_missing_proof_unavailable(self):
        record, before = self.suite(True, {})
        self.assertEqual(before[0]['stages'], [{'stage': 'dev', **reporting.unavailable()}])
        self.assertEqual(record['native_tool_budgets'], before[0])
        self.assertEqual(record['status'], 'FAIL')
        self.assertEqual(record['task_result']['status'], 'pass')

    def test_suite_updates_projection_from_parent_accounting_after_stage(self):
        record, before = self.suite(True, reporting_fixture.process())
        self.assertEqual(before[0]['stages'][0]['accounting'], 'unavailable')
        self.assertEqual(record['native_tool_budgets']['stages'][0]['accounting'], 'available')
        self.assertEqual(record['native_tool_budgets']['stages'][0]['budget']['counts']['charged'], 3)
        self.assertEqual(record['status'], 'PASS')

    def test_legacy_suite_retains_its_optional_field_absence(self):
        record, before = self.suite(False, {})
        self.assertEqual(before, [None])
        self.assertNotIn('native_tool_budgets', record)
        self.assertEqual(record['status'], 'PASS')


class PublicExperimentRequiredStagesTests(unittest.TestCase):
    def prepared(self, native=True):
        fixture = indexed_fixture.IndexedSetup(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        if native:
            fixture.definition['budgets'].update(max_tool_calls=8, reporting_reserve_calls=2, reporting_reserve_seconds=30)
            fixture.definition['indexed_execution']['native_budget'] = indexed_contract.native_helper_contract()
        fixture.write('experiment.json', fixture.definition)
        root = fixture.root / 'indexed'
        experiments.prepare(fixture.root / 'experiment.json', root, lab, session='fixture', catalog=fixture.catalog)
        metadata, matrix = experiments.verify(root, lab)
        return root, metadata, matrix

    def seal_fixture(self, root, metadata, cell, process=None):
        intent, _ = experiments.reserve_attempt(root, metadata, cell)
        record = passing(intent['initial_record'])
        if process is not None: record['agents'] = [{'name': 'dev', 'process': process}]
        record.update(sealed=True)
        record['status'], record['exit_code'] = outcomes.status(record)
        folder = root / 'runs' / intent['run_id']; folder.mkdir(parents=True)
        controls.atomic(folder / 'result.json', record)

    def test_export_uses_frozen_required_stages_when_attempt_omits_all_native_metadata(self):
        root, metadata, matrix = self.prepared()
        self.seal_fixture(root, metadata, matrix['cells'][0])
        receipt = experiments.export_ledger(root, lab, public=True)
        body = Path(receipt['path']).read_text(); rows = [json.loads(line) for line in body.splitlines()]
        stage = rows[0]['attempts'][0]['native_tool_budgets']['stages'][0]
        self.assertEqual(stage, {'stage': 1, **reporting.unavailable()})
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(row['attempts'] == [] for row in rows[1:]))
        for private in ('alpha', 'beta', 'dev', 'authority_id', 'fingerprint', str(root)):
            self.assertNotIn(private, body)

    def test_export_preserves_valid_parent_counts_and_only_public_stage_ordinals(self):
        root, metadata, matrix = self.prepared()
        self.seal_fixture(root, metadata, matrix['cells'][0], reporting_fixture.process())
        receipt = experiments.export_ledger(root, lab, public=True)
        rows = [json.loads(line) for line in Path(receipt['path']).read_text().splitlines()]
        stage = rows[0]['attempts'][0]['native_tool_budgets']['stages'][0]
        self.assertEqual((stage['stage'], stage['accounting']), (1, 'available'))
        self.assertEqual(stage['budget']['counts']['charged'], 3)
        self.assertIsNone(stage['budget']['counts']['executed'])

    def test_legacy_public_export_has_no_native_accounting_field(self):
        root, metadata, matrix = self.prepared(False)
        self.seal_fixture(root, metadata, matrix['cells'][0])
        receipt = experiments.export_ledger(root, lab, public=True)
        body = Path(receipt['path']).read_text()
        self.assertNotIn('native_tool_budgets', body)
        rows = [json.loads(line) for line in body.splitlines()]
        self.assertEqual(rows[0]['attempts'][0]['status'], 'PASS')


if __name__ == '__main__': unittest.main()
