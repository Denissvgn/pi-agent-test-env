"""Temporary historical-cleanup replay regressions; never native evidence.

All PID/process/network operations are mocked before fixture construction. These
fixtures contain synthetic metadata only, not retained application campaigns.
"""
import copy
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

TESTS = Path(__file__).resolve().parent
sys.path[:0] = [str(TESTS), str(TESTS.parent / 'skill/scripts')]
import ownership_registry as registry
import test_ownership_registry as owner_fixtures
import test_application_launch as launch_fixtures


class _InertEffects(unittest.TestCase):
    def setUp(self):
        self.pid = mock.Mock(side_effect=ProcessLookupError)
        for target, replacement in (
                ('os.kill', self.pid),
                ('subprocess.Popen', mock.Mock(side_effect=AssertionError('No process delegate'))),
                ('subprocess.run', mock.Mock(side_effect=AssertionError('No process/ps delegate'))),
                ('os.system', mock.Mock(side_effect=AssertionError('No shell delegate'))),
                ('socket.socket', mock.Mock(side_effect=AssertionError('No network delegate')))):
            patch = mock.patch(target, replacement)
            patch.start()
            self.addCleanup(patch.stop)


class HistoricalAdmissionTests(_InertEffects):
    def setUp(self):
        super().setUp()
        self.owner = owner_fixtures.QualificationPreworkerTests()
        self.owner.setUp()
        self.addCleanup(self.owner.doCleanups)
        self.registry = self.owner.registry

    def released(self):
        self.owner.write()
        self.assertEqual(self.owner.helper['status'], 'released')
        self.pid.reset_mock()
        self.pid.side_effect = AssertionError('Historical replay probed a reusable PID')
        return self.owner.helper

    def snapshot(self):
        owner = self.owner
        paths = [Path(owner.stage_ref['path']), Path(owner.process_ref['path']),
                 Path(owner.result_ref['path']), owner.q / 'state.json',
                 owner.q / 'launch-ledger/ledger.json', owner.control / 'task.json',
                 owner.control / 'endpoint.json', owner.control / 'stage.json',
                 Path(owner.helper['qualification_preworker_cleanup']['path']),
                 self.registry.root / (owner.helper['launch_id'] + '.json')]
        return {str(path): path.read_bytes() for path in paths}

    def assert_no_native_or_purge(self):
        self.owner.command.assert_not_called()
        self.owner.clean.assert_not_called()

    def test_initial_publication_checks_live_controller_even_with_released_record(self):
        self.pid.side_effect = None
        self.pid.return_value = None  # The synthetic PID is currently live.
        with self.assertRaises(registry.RegistryError):
            self.owner.write()
        self.pid.assert_called_with(self.owner.active['pid'], 0)
        self.assertFalse((self.owner.proofs / 'preworker.json').exists())
        self.assert_no_native_or_purge()

    def test_initial_publication_observes_absence_before_committing_sidecar(self):
        self.pid.reset_mock()
        reference = self.owner.write()
        self.assertTrue(self.pid.called)
        self.assertTrue(all(call.args == (self.owner.active['pid'], 0)
                            for call in self.pid.call_args_list))
        self.assertEqual(self.owner.helper['qualification_preworker_cleanup'], reference)
        self.assert_no_native_or_purge()

    def test_release_stays_live_strict_and_quarantines_on_current_controller(self):
        self.owner.write()
        self.owner.helper['status'] = 'absent'
        self.registry.write(self.owner.helper)
        self.pid.reset_mock()
        self.pid.side_effect = None
        self.pid.return_value = None
        with self.assertRaises(registry.RegistryError):
            self.registry.release(self.owner.helper, True)
        self.pid.assert_called_with(self.owner.active['pid'], 0)
        self.assertEqual(self.owner.helper['status'], 'quarantined')
        self.assert_no_native_or_purge()

    def test_released_pid_reuse_reconciles_without_pid_ps_or_any_write(self):
        record = self.released()
        before = self.snapshot()
        with mock.patch.object(self.registry, 'write', wraps=self.registry.write) as write:
            self.assertEqual(self.registry.reconcile(), [])
            write.assert_not_called()
        self.assertEqual(self.snapshot(), before)
        self.pid.assert_not_called()
        self.assert_no_native_or_purge()
        for reference in (None, record['qualification_preworker_cleanup']):
            proof = registry.validate_qualification_preworker_cleanup(
                record, reference, historical_replay=True)
            self.assertEqual(proof['controller']['pid'], self.owner.active['pid'])
        self.pid.assert_not_called()

    def test_replay_status_reference_and_bool_binding_reject_before_proof_read(self):
        record = self.released()
        attached = record['qualification_preworker_cleanup']
        cases = [(dict(record, status=status), None, True)
                 for status in ('intent', 'running', 'absent', 'quarantined')]
        cases += [(record, dict(attached, sha256='0' * 64), True)]
        cases += [(record, None, bad) for bad in (None, 0, 1, 'true', [])]
        with mock.patch.object(registry, '_qualification_reference',
                               side_effect=AssertionError('Proof opened before replay binding')) as read:
            for candidate, reference, historical in cases:
                with self.subTest(status=candidate['status'], historical=historical), \
                        self.assertRaises(registry.RegistryError):
                    registry.validate_qualification_preworker_cleanup(
                        candidate, reference, historical_replay=historical)
            read.assert_not_called()
        self.pid.assert_not_called()

    def test_rehashed_false_historical_claims_are_not_accepted_as_released(self):
        record = self.released()
        reference = copy.deepcopy(record['qualification_preworker_cleanup'])
        path = Path(reference['path'])
        original_bytes = path.read_bytes()
        original = json.loads(original_bytes)
        changes = (
            lambda p: p['controller'].update(pid_absence_observed=False),
            lambda p: p['controller'].update(provenance='fresh_numeric_PID_guess'),
            lambda p: p['controller'].update(pid=self.owner.active['pid'] - 1),
            lambda p: p['qualification'].update(participant_segments=1),
            lambda p: p['stage'].update(worker_launch_attempted=True),
            lambda p: p['stage'].update(application_context_issued=True),
            lambda p: p['launches'][0].update(physical_absence_confirmed=False),
            lambda p: p['private_cleanup']['control'].update(all_parent_authorities_scanned=False),
            lambda p: p['private_cleanup']['helper'].update(container_id_provenance='name_inferred'),
        )
        for change in changes:
            value = copy.deepcopy(original)
            change(value)
            record['qualification_preworker_cleanup'] = self.owner.fixture.put(path, value)
            self.registry.write(record)
            with self.subTest(change=change), \
                    mock.patch.object(self.registry, 'write', wraps=self.registry.write) as write:
                with self.assertRaises(registry.RegistryError):
                    self.registry.reconcile()
                write.assert_not_called()
            path.write_bytes(original_bytes)
            record['qualification_preworker_cleanup'] = reference
            self.registry.write(record)
        self.pid.assert_not_called()
        self.assert_no_native_or_purge()

    def test_retained_control_and_sidecar_tampering_still_deny_without_writes(self):
        record = self.released()
        for path in (self.owner.control / 'task.json',
                     Path(record['qualification_preworker_cleanup']['path'])):
            original = path.read_bytes()
            path.write_bytes(original + b' ')
            with self.subTest(path=path.name), \
                    mock.patch.object(self.registry, 'write', wraps=self.registry.write) as write:
                with self.assertRaises(registry.RegistryError):
                    self.registry.reconcile()
                write.assert_not_called()
            path.write_bytes(original)
        self.pid.assert_not_called()
        self.assert_no_native_or_purge()

    def test_rehashed_lineage_clock_change_is_not_historical_cleanup(self):
        record = self.released()
        sidecar = Path(record['qualification_preworker_cleanup']['path'])
        payload = json.loads(sidecar.read_bytes())
        ledger_ref = payload['qualification']['lineage'][-1]['ledger']
        ledger_path = Path(ledger_ref['path'])
        ledger = json.loads(ledger_path.read_bytes())
        ledger['deadline'] += 1
        ledger['deadline_wall'] += 1
        payload['qualification']['lineage'][-1]['ledger'] = self.owner.fixture.put(ledger_path, ledger)
        record['qualification_preworker_cleanup'] = self.owner.fixture.put(sidecar, payload)
        self.registry.write(record)
        with self.assertRaises(registry.RegistryError):
            self.registry.reconcile()
        self.pid.assert_not_called()
        self.assert_no_native_or_purge()

    def test_rehashed_frozen_failure_cannot_be_relabelled_clean(self):
        record = self.released()
        sidecar = Path(record['qualification_preworker_cleanup']['path'])
        payload = json.loads(sidecar.read_bytes())
        state_path = Path(payload['stage']['state']['path'])
        stage_state = json.loads(state_path.read_bytes())
        stage_state['cleanup_confirmed'] = True
        payload['stage']['state'] = self.owner.fixture.put(state_path, stage_state)
        record['qualification_preworker_cleanup'] = self.owner.fixture.put(sidecar, payload)
        self.registry.write(record)
        with self.assertRaises(registry.RegistryError):
            self.registry.reconcile()
        self.pid.assert_not_called()
        self.assert_no_native_or_purge()

    def test_cid_and_immutable_record_identity_remain_mandatory(self):
        record = self.released()
        original = copy.deepcopy(record)
        changes = (lambda r: r.pop('container_id'),
                   lambda r: r.update(container_id='f' * 63),
                   lambda r: r['code_identity'].update({'runtime/service.py': 'b' * 64}))
        for change in changes:
            candidate = copy.deepcopy(original)
            change(candidate)
            self.registry.write(candidate)
            with self.subTest(change=change), self.assertRaises(registry.RegistryError):
                self.registry.reconcile()
            self.registry.write(original)
        self.pid.assert_not_called()
        self.assert_no_native_or_purge()

    def test_recreated_sensitive_namespace_is_not_purged_or_ignored(self):
        record = self.released()
        for path in (Path(record['private_store']), self.owner.envelope, self.owner.workspace):
            path.mkdir(mode=0o700)
            with self.subTest(path=path.name), \
                    mock.patch.object(self.registry, 'write', wraps=self.registry.write) as write:
                with self.assertRaises(registry.RegistryError):
                    self.registry.reconcile()
                write.assert_not_called()
            self.assertTrue(path.is_dir())
            path.rmdir()
        self.pid.assert_not_called()
        self.assert_no_native_or_purge()

    def test_pending_helper_still_quarantines_instead_of_historical_replay(self):
        record = self.released()
        for status in ('intent', 'running', 'absent', 'quarantined'):
            record['status'] = status
            self.registry.write(record)
            with self.subTest(status=status), self.assertRaises(registry.RegistryError):
                self.registry.reconcile()
            current = next(row for row in self.registry.load()
                           if row['launch_id'] == record['launch_id'])
            self.assertEqual(current['status'], 'quarantined')
        self.pid.assert_not_called()
        self.assert_no_native_or_purge()

    def test_unrelated_released_helper_cannot_borrow_the_historical_exception(self):
        record = self.released()
        unrelated = copy.deepcopy(record)
        unrelated['launch_id'] = str(__import__('uuid').uuid4())
        unrelated.pop('qualification_preworker_cleanup')
        self.registry.write(unrelated)
        self.registry.network_intent('pending-unrelated-network')
        with self.assertRaises(registry.RegistryError):
            self.registry.reconcile()
        self.pid.assert_not_called()
        self.assert_no_native_or_purge()


class PredecessorHistoricalAdmissionTests(_InertEffects):
    def setUp(self):
        super().setUp()
        owner = owner_fixtures.QualificationPreworkerTests()
        original_setup = owner.setUp
        target_pid = 2**31 - 2

        def setup_distinct_controller():
            original_setup()
            owner.active['pid'] = target_pid
            state_path = owner.q / 'state.json'
            state = json.loads(state_path.read_bytes())
            state['active_cell']['pid'] = target_pid
            state_ref = owner.fixture.put(state_path, state)
            owner.proof['controller']['pid'] = target_pid
            owner.proof['qualification']['lineage'][-1]['state'] = state_ref

        owner.setUp = setup_distinct_controller
        self.linear = launch_fixtures.LinearCampaignCarryTests()
        with mock.patch.object(owner_fixtures, 'QualificationPreworkerTests', return_value=owner):
            self.linear.setUp()
        self.addCleanup(self.linear.doCleanups)
        self.target_pid = target_pid
        self.ancestor_pid = self.linear.f.active['pid']
        self.assertNotEqual(self.target_pid, self.ancestor_pid)
        self.pid.reset_mock()

        def old_ancestor_absent(pid, sig):
            if pid == self.target_pid:
                raise AssertionError('Reused released controller PID was probed')
            raise ProcessLookupError

        self.pid.side_effect = old_ancestor_absent

    def test_predecessor_replays_released_target_without_skipping_ancestor_gates(self):
        owner = self.linear.owner
        paths = [self.linear.q / 'state.json', self.linear.q / 'launch-ledger/ledger.json',
                 Path(owner.helper['qualification_preworker_cleanup']['path'])]
        before = {str(path): path.read_bytes() for path in paths}
        with mock.patch.object(registry, 'validate_qualification_preworker_cleanup',
                               wraps=registry.validate_qualification_preworker_cleanup) as validate:
            summary = launch_fixtures.launch.validate_predecessor(
                self.linear.predecessor, daemon_id=self.linear.f.daemon,
                clock=self.linear.f.clock, wall=self.linear.f.wall)
        self.assertEqual((summary['attempts'], summary['participant_segments'], summary['planned_cells']),
                         (19, 0, 56))
        target_calls = [call for call in validate.call_args_list
                        if call.args[0]['launch_id'] == owner.helper['launch_id']]
        self.assertTrue(target_calls)
        self.assertTrue(all(call.kwargs.get('historical_replay') is True for call in target_calls))
        self.assertNotIn(mock.call(self.target_pid, 0), self.pid.call_args_list)
        self.assertIn(mock.call(self.ancestor_pid, 0), self.pid.call_args_list)
        self.assertEqual({str(path): path.read_bytes() for path in paths}, before)
        owner.command.assert_not_called()
        owner.clean.assert_not_called()

    def test_predecessor_replay_still_rejects_rehashed_false_sidecar(self):
        owner = self.linear.owner
        path = Path(owner.helper['qualification_preworker_cleanup']['path'])
        payload = json.loads(path.read_bytes())
        payload['qualification']['participant_segments'] = 1
        reference = owner.fixture.put(path, payload)
        owner.helper['qualification_preworker_cleanup'] = reference
        owner.registry.write(owner.helper)
        self.linear.predecessor['cleanup_receipts'] = [reference]
        with self.assertRaises(launch_fixtures.launch.LaunchError):
            self.linear.create()
        self.assertFalse((self.linear.f.root / 'third-ledger').exists())
        self.assertNotIn(mock.call(self.target_pid, 0), self.pid.call_args_list)
        owner.command.assert_not_called()
        owner.clean.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
