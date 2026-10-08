"""Durable stop/retry/cancellation regressions; synthetic outcomes, no model/Docker."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

import test_experiments as fixtures
import experiments
import outcomes
import pi_lab as lab


class StopPolicyTests(fixtures.ControlledFixture):
    def prepare_stop(self, policy='stop', name='prepared'):
        self.definition['policies']['on_failure'] = policy
        self.write('experiment.json', self.definition)
        self.prepare(name)
        root = (self.root / name).resolve()
        metadata, matrix = experiments.verify(root, lab)
        return root, metadata, matrix

    def seed(self, root, metadata, cell, status='FAIL', index=1, previous=None):
        intent, path = experiments.reserve_attempt(root, metadata, cell, index, previous)
        args = experiments.trial_args(root, metadata, cell, lab, None)
        attempt = outcomes.Attempt(args, copy.deepcopy(intent['initial_record']))
        record = attempt.record
        record['probe_receipt_contract'] = 1
        record['infrastructure'].update(status='ready', phase='agents')
        record['invocation'].update(status='verified', attempted_stages=1)
        record['termination'].update(reason='completed', process_exit_code=0)
        record['protected_inputs']['status'] = 'unchanged'
        record['scoring']['status'] = 'completed'
        record['task_result'].update(status='pass', score=1)
        if status == 'FAIL':
            record['invocation']['status'] = 'invalid'
        elif status == 'BLOCKED':
            record['infrastructure']['status'] = 'failed'
            record['invocation']['status'] = 'not_started'
        elif status == 'INTERRUPTED':
            attempt.cancel()
        elif status == 'RECOVERED':
            record['invocation']['status'] = 'recovered'
        with mock.patch.object(outcomes.controls, 'assistance', return_value={
                'status': 'assisted' if status == 'ASSISTED' else 'autonomous'}):
            result = attempt.finalize()
        self.assertEqual(result['status'], status)
        body = (attempt.root / 'result.json').read_bytes()
        intent.update(status='finalized', result=str((attempt.root / 'result.json').relative_to(root)),
                      result_sha256=__import__('hashlib').sha256(body).hexdigest())
        lab.save(path, intent)
        return intent, attempt.root / 'result.json', body

    def passing_runner(self, calls, cleanup_error=False):
        def runner(args, initial_record):
            calls.append(initial_record['trial_id'])
            attempt = outcomes.Attempt(args, copy.deepcopy(initial_record))
            record = attempt.record
            record['probe_receipt_contract'] = 1
            record['infrastructure'].update(status='ready', phase='agents')
            record['invocation'].update(status='verified', attempted_stages=1)
            record['termination'].update(reason='cleanup_error' if cleanup_error else 'completed', process_exit_code=0)
            record['protected_inputs']['status'] = 'unchanged'
            record['scoring']['status'] = 'completed'
            record['task_result'].update(status='pass', score=1)
            return attempt.finalize()['exit_code']
        return runner

    def resume_without_reservations(self, root, *, expected='halted', **options):
        calls = []
        with mock.patch.object(experiments, 'reserve_attempt', wraps=experiments.reserve_attempt) as reserve:
            result = experiments.execute(root, lab, resume=True,
                runner=self.passing_runner(calls), **options)
            reserve.assert_not_called()
        self.assertEqual(calls, [])
        self.assertEqual(result['status'], expected)
        self.assertEqual(result['exit_code'], 1 if expected == 'halted' else 0)
        return result

    def test_cleanup_blocked_failure_remains_halted_after_confirmed_cleanup(self):
        root, _, _ = self.prepare_stop()
        first = experiments.execute(root, lab, runner=self.controlled_runner([], {0: 'cleanup'}))
        self.assertEqual((first['status'], first['exit_code']), ('blocked', 2))
        with mock.patch.object(experiments, 'cleanup_owned') as native_cleanup:
            result = self.resume_without_reservations(root, cleanup=lambda *a: [{'cleanup': 'synthetic_confirmed'}])
            native_cleanup.assert_not_called()
        self.assertEqual(result['completed_this_call'], 0)
        self.resume_without_reservations(root)

    def test_controller_loss_after_seal_does_not_run_pending_cells(self):
        root, _, matrix = self.prepare_stop()
        base = self.controlled_runner([], {0: 'invocation'})
        def crash(*args, **kwargs):
            base(*args, **kwargs)
            raise SystemExit('synthetic loss after sealed result')
        with self.assertRaises(SystemExit):
            experiments.execute(root, lab, runner=crash)
        intent = experiments.attempt_intents(root, matrix['cells'][0])[0]
        path = root / 'runs' / intent['run_id'] / 'result.json'
        before = path.read_bytes()
        self.resume_without_reservations(root)
        self.assertEqual(path.read_bytes(), before)

    def test_all_nonpass_outcomes_and_stale_states_preserve_stop(self):
        for outcome in ('FAIL', 'BLOCKED', 'INTERRUPTED', 'ASSISTED', 'RECOVERED'):
            for state in ('prepared', 'running', 'blocked', 'interrupted', 'completed', 'halted'):
                with self.subTest(outcome=outcome, state=state):
                    root, metadata, matrix = self.prepare_stop(name=outcome + '-' + state)
                    _, path, before = self.seed(root, metadata, matrix['cells'][0], outcome)
                    lab.save(root / 'state.json', {'schema': 1, 'status': state, 'active_attempt_id': None})
                    self.resume_without_reservations(root)
                    self.assertEqual(path.read_bytes(), before)

    def test_successful_retry_only_selected_cell_and_history_survives_state_loss(self):
        root, metadata, matrix = self.prepare_stop()
        cell = matrix['cells'][0]
        original, path, before = self.seed(root, metadata, cell)
        calls = []
        with mock.patch.object(experiments, 'reserve_attempt', wraps=experiments.reserve_attempt) as reserve:
            result = experiments.execute(root, lab, resume=True, retry_trial=cell['trial_id'],
                                         runner=self.controlled_runner(calls))
            self.assertEqual(reserve.call_count, 1)
            self.assertEqual(reserve.call_args.args[2]['trial_id'], cell['trial_id'])
        self.assertEqual(len(calls), 1)
        self.assertEqual((result['status'], result['exit_code']), ('halted', 1))
        self.assertEqual(path.read_bytes(), before)
        intents = experiments.attempt_intents(root, cell)
        self.assertEqual(len(intents), 2)
        self.assertEqual(intents[1]['retry_of_attempt_id'], original['attempt_id'])
        self.assertEqual(experiments.sealed_result(root, intents[1])['status'], 'PASS')
        rows = experiments.ledger_rows(root, lab)
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[0]['primary_attempt_id'], original['attempt_id'])
        self.assertEqual(sum(bool(row['attempts']) for row in rows), 1)
        lab.save(root / 'state.json', {'schema': 1, 'status': 'prepared', 'active_attempt_id': None})
        self.resume_without_reservations(root)

    def test_retry_refusals_reserve_nothing(self):
        for kind in ('unknown', 'clean', 'exhausted'):
            with self.subTest(kind=kind):
                root, metadata, matrix = self.prepare_stop(name=kind)
                cell = matrix['cells'][0]
                intent, _, _ = self.seed(root, metadata, cell, 'PASS' if kind == 'clean' else 'FAIL')
                if kind == 'exhausted':
                    self.seed(root, metadata, cell, index=2, previous=intent['attempt_id'])
                retry = str(__import__('uuid').uuid4()) if kind == 'unknown' else cell['trial_id']
                with mock.patch.object(experiments, 'reserve_attempt') as reserve, self.assertRaises(experiments.ExperimentError):
                    experiments.execute(root, lab, resume=True, retry_trial=retry, runner=mock.Mock())
                reserve.assert_not_called()

    def test_uncertain_cleanup_blocks_retry_and_pending_work(self):
        root, _, matrix = self.prepare_stop()
        experiments.execute(root, lab, runner=self.controlled_runner([], {0: 'cleanup'}))
        for retry in (None, matrix['cells'][0]['trial_id']):
            with self.subTest(retry=retry), mock.patch.object(experiments, 'reserve_attempt') as reserve:
                runner = mock.Mock()
                with self.assertRaisesRegex(experiments.ExperimentError, 'uncertain'):
                    experiments.execute(root, lab, resume=True, retry_trial=retry, runner=runner,
                        cleanup=mock.Mock(side_effect=experiments.ExperimentError('ownership uncertain')))
                reserve.assert_not_called(); runner.assert_not_called()

    def test_retry_cancellation_and_cleanup_keep_documented_exits(self):
        for kind in ('cancelled', 'cleanup'):
            with self.subTest(kind=kind):
                root, metadata, matrix = self.prepare_stop(name='prepared-' + kind)
                cell = matrix['cells'][0]
                _, path, before = self.seed(root, metadata, cell)
                calls = []
                if kind == 'cancelled':
                    def runner(args, initial_record):
                        calls.append(initial_record['trial_id'])
                        attempt = outcomes.Attempt(args, initial_record)
                        attempt.record['probe_receipt_contract'] = 1
                        attempt.cancel(); attempt.finalize()
                else:
                    runner = self.passing_runner(calls, cleanup_error=True)
                result = experiments.execute(root, lab, resume=True, retry_trial=cell['trial_id'], runner=runner)
                self.assertEqual(len(calls), 1)
                self.assertEqual((result['status'], result['exit_code']),
                                 ('interrupted' if kind == 'cancelled' else 'blocked', 2))
                self.assertEqual(path.read_bytes(), before)

    def test_before_reservation_cancel_creates_no_attempt_and_resume_can_proceed(self):
        root, _, matrix = self.prepare_stop()
        with mock.patch.object(experiments, 'reserve_attempt', side_effect=KeyboardInterrupt):
            result = experiments.execute(root, lab, runner=mock.Mock())
        self.assertEqual((result['status'], result['exit_code']), ('interrupted', 2))
        self.assertTrue(all(not experiments.attempt_intents(root, c) for c in matrix['cells']))
        resumed = experiments.execute(root, lab, resume=True, runner=self.controlled_runner([]))
        self.assertEqual(resumed['completed_this_call'], 4)

    def test_cancelled_sealed_history_stop_halts_continue_explicitly_resumes(self):
        for policy in ('stop', 'continue'):
            with self.subTest(policy=policy):
                root, metadata, matrix = self.prepare_stop(policy, policy)
                _, path, before = self.seed(root, metadata, matrix['cells'][0], 'INTERRUPTED')
                lab.save(root / 'state.json', {'schema': 1, 'status': 'interrupted', 'active_attempt_id': None})
                calls = []
                result = experiments.execute(root, lab, resume=True, runner=self.passing_runner(calls))
                self.assertEqual(len(calls), 0 if policy == 'stop' else 3)
                self.assertEqual(result['status'], 'halted' if policy == 'stop' else 'completed')
                self.assertEqual(path.read_bytes(), before)

    def test_cancel_after_sealed_pass_does_not_rewrite_pass(self):
        root, _, matrix = self.prepare_stop()
        base = self.controlled_runner([])
        def cancelled(*args, **kwargs):
            base(*args, **kwargs)
            raise KeyboardInterrupt
        result = experiments.execute(root, lab, runner=cancelled)
        self.assertEqual(result['status'], 'interrupted')
        intent = experiments.attempt_intents(root, matrix['cells'][0])[0]
        path = root / 'runs' / intent['run_id'] / 'result.json'; before = path.read_bytes()
        resumed = experiments.execute(root, lab, resume=True, runner=self.controlled_runner([]))
        self.assertEqual(resumed['completed_this_call'], 3)
        self.assertEqual(experiments.sealed_result(root, intent)['status'], 'PASS')
        self.assertEqual(path.read_bytes(), before)

    def test_continue_nonpass_and_stop_allpass_do_not_halt(self):
        for policy, outcome in [('continue', 'FAIL'), ('stop', 'PASS')]:
            root, metadata, matrix = self.prepare_stop(policy, policy)
            self.seed(root, metadata, matrix['cells'][0], outcome)
            lab.save(root / 'state.json', {'schema': 1, 'status': 'running', 'active_attempt_id': None})
            result = experiments.execute(root, lab, resume=True, runner=self.passing_runner([]))
            self.assertEqual((result['status'], result['completed_this_call']), ('completed', 3))

    def test_continue_cleanup_recovery_runs_pending_after_known_cleanup(self):
        root, _, _ = self.prepare_stop('continue')
        first = experiments.execute(root, lab, runner=self.passing_runner([], cleanup_error=True))
        self.assertEqual(first['status'], 'blocked')
        calls = []
        result = experiments.execute(root, lab, resume=True, runner=self.passing_runner(calls),
                                     cleanup=lambda *a: [{'cleanup': 'synthetic_confirmed'}])
        self.assertEqual((result['status'], len(calls)), ('completed', 3))

    def test_known_cancel_after_reservation_is_preserved_under_both_policies(self):
        for policy in ('stop', 'continue'):
            with self.subTest(policy=policy):
                root, metadata, matrix = self.prepare_stop(policy, policy)
                intent, _ = experiments.reserve_attempt(root, metadata, matrix['cells'][0])
                lab.save(root / 'state.json', {'schema': 1, 'status': 'interrupted',
                    'active_attempt_id': intent['attempt_id'], 'interruption_kind': 'explicit_controller_cancel'})
                calls = []
                with mock.patch.object(lab, 'default_lock_file', return_value=str(self.root / 'fixture-core.lock')):
                    result = experiments.execute(root, lab, resume=True, runner=self.passing_runner(calls))
                cancelled = experiments.sealed_result(root, experiments.attempt_intents(root, matrix['cells'][0])[0])
                self.assertEqual(cancelled['status'], 'INTERRUPTED')
                self.assertEqual(cancelled['termination']['reason'], 'cancelled')
                self.assertEqual(cancelled['controller_interruption']['kind'], 'explicit_controller_cancel')
                self.assertEqual((result['status'], len(calls)), ('halted', 0) if policy == 'stop' else ('completed', 3))

    def test_later_nonpass_attempt_is_not_hidden_by_a_clean_primary(self):
        root, metadata, matrix = self.prepare_stop()
        primary, path, before = self.seed(root, metadata, matrix['cells'][0], 'PASS')
        self.seed(root, metadata, matrix['cells'][0], 'FAIL', index=2, previous=primary['attempt_id'])
        self.resume_without_reservations(root)
        self.assertEqual(path.read_bytes(), before)

    def test_nonpass_records_cannot_skip_required_sections_under_either_policy(self):
        for policy in ('stop', 'continue'):
            for fault in ('scoring', 'task_result', 'protected_inputs', 'assistance', 'invalid-infrastructure', 'invalid-process'):
                with self.subTest(policy=policy, fault=fault):
                    root, metadata, matrix = self.prepare_stop(policy, policy + '-' + fault)
                    intent, path, _ = self.seed(root, metadata, matrix['cells'][0])
                    value = json.loads(path.read_text())
                    if fault == 'invalid-infrastructure': value['infrastructure']['status'] = None
                    elif fault == 'invalid-process': value['agents'] = [{'process': None}]
                    else: value.pop(fault)
                    path.write_text(json.dumps(value))
                    intent['result_sha256'] = __import__('hashlib').sha256(path.read_bytes()).hexdigest()
                    lab.save(next((root / 'attempts' / matrix['cells'][0]['trial_id']).glob('*.json')), intent)
                    with mock.patch.object(experiments, 'reserve_attempt', wraps=experiments.reserve_attempt) as reserve:
                        calls = []
                        with self.assertRaises(experiments.ExperimentError):
                            experiments.execute(root, lab, resume=True, runner=self.passing_runner(calls))
                        reserve.assert_not_called(); self.assertEqual(calls, [])

    def test_corrupt_results_and_inconsistent_states_fail_closed(self):
        for fault in ('missing', 'corrupt', 'unknown-outcome', 'missing-outcome', 'nonstring-outcome',
                      'mismatched-outcome', 'malformed-state', 'unknown-state', 'nonstring-state',
                      'corrupt-state', 'missing-state', 'invalid-active-id',
                      'halted-empty', 'halted-pass', 'halted-continue'):
            with self.subTest(fault=fault):
                policy = 'continue' if fault == 'halted-continue' else 'stop'
                root, metadata, matrix = self.prepare_stop(policy, fault)
                if fault != 'halted-empty':
                    intent, result_path, _ = self.seed(root, metadata, matrix['cells'][0],
                        'PASS' if fault == 'halted-pass' else 'FAIL')
                    if fault in ('missing', 'corrupt'):
                        if fault == 'missing': result_path.unlink()
                        else: result_path.write_text('{')
                    elif fault in ('unknown-outcome', 'missing-outcome', 'nonstring-outcome', 'mismatched-outcome'):
                        value = json.loads(result_path.read_text())
                        if fault == 'unknown-outcome': value['status'] = 'UNKNOWN'
                        elif fault == 'nonstring-outcome': value['status'] = []
                        elif fault == 'mismatched-outcome': value['status'] = 'PASS'; value['exit_code'] = 0
                        else: value.pop('status')
                        result_path.write_text(json.dumps(value))
                        intent['result_sha256'] = __import__('hashlib').sha256(result_path.read_bytes()).hexdigest()
                        lab.save(next((root / 'attempts' / matrix['cells'][0]['trial_id']).glob('*.json')), intent)
                state = {'schema': 1, 'status': 'halted' if fault.startswith('halted') else 'running', 'active_attempt_id': None}
                if fault == 'malformed-state': state = []
                elif fault == 'unknown-state': state['status'] = 'bogus'
                elif fault == 'nonstring-state': state['status'] = []
                elif fault == 'invalid-active-id': state['active_attempt_id'] = 'bogus'
                lab.save(root / 'state.json', state)
                if fault == 'corrupt-state': (root / 'state.json').write_text('{')
                elif fault == 'missing-state': (root / 'state.json').unlink()
                with mock.patch.object(experiments, 'reserve_attempt') as reserve:
                    runner = mock.Mock()
                    with self.assertRaises(experiments.ExperimentError):
                        experiments.execute(root, lab, resume=True, runner=runner)
                    reserve.assert_not_called(); runner.assert_not_called()

    def test_real_subprocess_crashes_at_four_persistence_boundaries(self):
        script = self.root / 'crash.py'
        script.write_text('''import os,sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,sys.argv[1]);sys.path.insert(0,sys.argv[2])
import test_experiments as fixtures,experiments,pi_lab as lab,outcomes
case=fixtures.ControlledFixture();case.root=Path(sys.argv[3]);mode=sys.argv[4]
base=case.controlled_runner([],{0:'invocation'});atomic=experiments.controls.atomic
def runner(*a,**k):
 base(*a,**k)
 if mode=='after_seal':os._exit(73)
def write(path,value,*a,**k):
 if mode=='before_halt_write' and Path(path).name=='state.json' and value.get('status')=='halted':os._exit(73)
 answer=atomic(path,value,*a,**k)
 if mode=='after_intent' and value.get('document_type')=='attempt_intent' and value.get('status')=='finalized':os._exit(73)
 return answer
def before_seal(self):os._exit(73)
with patch.object(experiments.controls,'atomic',side_effect=write):
 if mode=='before_seal':
  with patch.object(outcomes.Attempt,'finalize',before_seal):experiments.execute(case.root/'prepared',lab,runner=runner)
 else:experiments.execute(case.root/'prepared',lab,runner=runner)
''')
        for mode in ('after_seal', 'after_intent', 'before_halt_write', 'before_seal'):
            with self.subTest(mode=mode):
                # ControlledFixture's real subprocess runner uses this fixed path.
                self.prepare_stop()
                root = self.root / 'prepared'
                argv = [sys.executable, str(script), str(Path(__file__).resolve().parent),
                        str(fixtures.ROOT / 'scripts'), str(self.root), mode]
                result = subprocess.run(argv, capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 73, result.stderr)
                matrix = experiments.verify(root, lab)[1]
                intent = experiments.attempt_intents(root, matrix['cells'][0])[0]
                sealed = experiments.sealed_result(root, intent)
                result_path = root / 'runs' / intent['run_id'] / 'result.json'
                before = result_path.read_bytes() if sealed is not None else None
                with mock.patch.object(lab, 'default_lock_file', return_value=str(self.root / 'fixture-core.lock')):
                    self.resume_without_reservations(root)
                final = experiments.sealed_result(root, experiments.attempt_intents(root, matrix['cells'][0])[0])
                self.assertEqual(final['status'], 'BLOCKED' if mode == 'before_seal' else 'FAIL')
                if sealed is None:
                    self.assertEqual(final['controller_interruption']['kind'], 'controller_lost')
                    self.assertEqual(final['termination']['trigger'], 'controller_lost')
                    self.assertEqual(final['invocation']['status'], 'not_started')
                    self.assertIsNone(final['task_result']['score'])
                else:
                    self.assertEqual(result_path.read_bytes(), before)
                print(json.dumps({'evidence': 'real local controller subprocess; synthetic outcomes',
                    'boundary': mode, 'command': argv, 'exit_code': result.returncode,
                    'resumed_status': 'halted', 'sealed_status': final['status'],
                    'pending_reservations': 0, 'pending_runner_calls': 0}))
                # Preserve each disposable experiment rather than modify it in place.
                root.rename(self.root / mode)


if __name__ == '__main__':
    unittest.main()
