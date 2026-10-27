"""Cross-command owner-proof regressions, using only disposable fixture state."""
import contextlib
import errno
import json
import io
import os
from pathlib import Path
import unittest
from unittest import mock
import uuid

import test_application_owner_cleanup as fixtures


class OwnerProofReviewTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.OwnerCleanupTests()
        self.f.setUp(); self.addCleanup(self.f.doCleanups)
        self.api = self.f.api

    def related_worker(self, request):
        f = self.f
        worker = {k: v for k, v in f.helper.items() if k not in (
            'application_helper', 'client_mode', 'private_store', 'code_identity')}
        worker.update(launch_id=str(uuid.uuid4()), container='pi-owned-probe',
                      container_id='d' * 64, mounts=[], status='absent')
        f.owner.write(worker)
        controller = request['controller']
        invocation = json.loads(Path(controller['invocation']['path']).read_text())
        invocation['launch_ids'] = sorted([f.helper['launch_id'], worker['launch_id']])
        controller['invocation'] = f.put(Path(controller['invocation']['path']), invocation)
        terminal = json.loads(Path(controller['terminal']['path']).read_text())
        terminal['invocation'] = controller['invocation']
        controller['terminal'] = f.put(Path(controller['terminal']['path']), terminal)
        argv = ['docker', 'run', '--name', worker['container'], '--label',
                fixtures.registry.LABEL + '=' + worker['launch_id'], '--label',
                fixtures.registry.REGISTRY_LABEL + '=' + worker['registry'],
                worker['image'], '/opt/pi-lab/worker.py', 'probe']
        invocation = {'schema': 1, 'document_type': 'owned_process_invocation', 'pid': 2147482998,
                      'argv': argv, 'cwd': str(f.root), 'runroot': str(f.run),
                      'registry': worker['registry'], 'generation': worker['generation'],
                      'launch_ids': [worker['launch_id']]}
        ref = f.put(f.evidence / 'probe-invocation.json', invocation)
        terminal = {'schema': 1, 'document_type': 'owned_process_terminal', 'pid': invocation['pid'],
                    'argv': argv, 'cwd': str(f.root), 'invocation': ref, 'actual_exit': 0}
        request['launchers'].append({'launch_id': worker['launch_id'], 'invocation': ref,
                                    'terminal': f.put(f.evidence / 'probe-terminal.json', terminal)})
        return worker

    def test_generic_recovery_preserves_original_failed_credentials_under_accepted_owner_proof(self):
        f = self.f; request = f.request(); worker = self.related_worker(request)
        before = f.metadata(); f.recover(request)
        with f.held():f.owner.reconcile()
        self.assertEqual(f.metadata(), before)
        self.assertEqual(next(r for r in f.owner.load() if r['launch_id'] == worker['launch_id'])['status'], 'released')
        with f.held():self.assertTrue(self.api.validate_accepted(f.owner, f.helper))

    def test_related_record_iteration_order_is_not_proof_identity(self):
        f = self.f; request = f.request(); self.related_worker(request); f.recover(request)
        original = f.owner.load
        with f.held(), mock.patch.object(f.owner, 'load', side_effect=lambda: list(reversed(original()))):
            self.assertTrue(self.api.validate_accepted(f.owner, f.helper))

    def test_runner_identity_failure_does_not_leak_a_created_receipt(self):
        f = self.f; request = f.request('helper_only'); created = []
        original = fixtures.maintenance._new_receipt_directory
        def capture(*args, **kwargs):
            value = original(*args, **kwargs); created.append((value, value.fd, value.parent)); return value
        try:
            with mock.patch.object(fixtures.maintenance, '_new_receipt_directory', side_effect=capture), \
                 mock.patch.object(fixtures.maintenance, '_runner_identity', side_effect=OSError(errno.EIO, 'private-canary')):
                with self.assertRaises(fixtures.registry.RegistryError):f.recover(request)
            for unused, fd, parent in created:
                for descriptor in (fd, parent):
                    with self.assertRaises(OSError):os.fstat(descriptor)
            self.assertTrue(f.workspace.exists())
        finally:
            for value, unused, other in created:value.close()

    def reader_sizes(self, invoke):
        readers = []; original = self.api.Reader
        class CountingReader(original):
            def __init__(self):
                super().__init__(); readers.append(self)
        with mock.patch.object(self.api, 'Reader', CountingReader):invoke()
        paths = set().union(*(reader.references for reader in readers))
        return sum(Path(path).stat().st_size for path in paths)

    def test_retained_replay_applies_one_aggregate_budget_to_the_transitive_read_graph(self):
        f = self.f; request = f.request(); f.recover(request)
        with f.held():
            total = self.reader_sizes(lambda: self.api.validate_accepted(f.owner, f.helper))
            # Each former sub-reader fits; their complete graph exceeds this
            # candidate budget. A single graph must be denied before acceptance.
            bound = total - 1
            with mock.patch.object(self.api, 'MAX_AGGREGATE_BYTES', bound):
                with self.assertRaises(fixtures.registry.RegistryError):self.api.validate_accepted(f.owner, f.helper)

    def test_runtime_replay_applies_one_aggregate_budget_to_the_transitive_read_graph(self):
        f = self.f
        with f.held():
            f.runtime_cleanup(); f.owner.close()
            total = self.reader_sizes(lambda: self.api.validate_accepted(f.owner, f.helper))
            bound = total - 1
            with mock.patch.object(self.api, 'MAX_AGGREGATE_BYTES', bound):
                with self.assertRaises(fixtures.registry.RegistryError):self.api.validate_accepted(f.owner, f.helper)

    def test_cli_does_not_delete_its_request_from_a_discarded_workspace(self):
        import pi_lab
        f = self.f; request = f.request('helper_only')
        source = f.put(f.workspace / 'request.json', request); output = io.StringIO()
        with mock.patch.object(self.api, '_owner_docker', side_effect=f.owner.command), contextlib.redirect_stdout(output):
            code = pi_lab.main(['application-owner-recover', '--lock-file', str(f.lease), '--request', source['path'],
                                '--output-dir', str(f.root / 'recovery'), '--discard-workspace'])
        self.assertEqual(code, 2); self.assertTrue(Path(source['path']).exists())
        self.assertTrue(f.workspace.exists()); self.assertEqual(f.calls, [])

    def test_reused_reference_keeps_its_strongest_privacy_requirement(self):
        f = self.f; ref = f.put(f.evidence / 'private-proof.json', {'schema': 1})
        reader = self.api.Reader(); reader.read(ref['path'], private=True)
        Path(ref['path']).chmod(0o644); f.evidence.chmod(0o755)
        with self.assertRaises(fixtures.registry.RegistryError):reader.reference(ref)

    def test_lost_selected_proof_during_generic_recovery_does_not_fall_back_to_raw_repair(self):
        f = self.f; request = f.request(); worker = self.related_worker(request); f.recover(request)
        before = f.metadata(); original = f.owner.write
        def lost(row):
            original(row)
            if row['launch_id'] == worker['launch_id']:
                self.api._index(f.owner, f.helper).unlink(missing_ok=True)
                self.api._selection(f.owner, f.helper).unlink(missing_ok=True)
        with f.held(), mock.patch.object(f.owner, 'write', side_effect=lost), self.assertRaises(fixtures.registry.RegistryError):
            f.owner.reconcile()
        self.assertEqual(f.metadata(), before)

    def test_legacy_sensitive_recovery_still_runs_without_new_owner_proof(self):
        f = self.f
        row = {k: v for k, v in f.helper.items() if k not in (
            'application_helper', 'client_mode', 'private_store', 'code_identity')}
        row.update(status='absent'); f.owner.write(row)
        cleanup = mock.Mock(); f.owner.recover_sensitive = cleanup
        with f.held():f.owner.reconcile()
        cleanup.assert_called_once_with(f.run)

    def test_reordered_saved_subjects_remain_valid_but_duplicate_subjects_deny(self):
        f = self.f; request = f.request(); self.related_worker(request); f.recover(request)
        receipt_path = f.root / 'recovery/recovery.json'
        receipt = json.loads(receipt_path.read_text()); receipt['related_subjects'].reverse()
        ref = f.put(receipt_path, receipt)
        index_path = self.api._index(f.owner, f.helper)
        index = json.loads(index_path.read_text()); index['receipt'] = ref; f.put(index_path, index)
        with f.held():self.assertTrue(self.api.validate_accepted(f.owner, f.helper))
        receipt['related_subjects'].append(receipt['related_subjects'][0])
        index['receipt'] = f.put(receipt_path, receipt); f.put(index_path, index)
        with f.held(), self.assertRaises(fixtures.registry.RegistryError):self.api.validate_accepted(f.owner, f.helper)

    def test_normal_browser_stage_can_finalize_with_complete_agent_cleanup(self):
        f = self.f; request = f.request(); stage = request['stages'][0]
        receipt = {'schema': 1, 'status': 'removed', 'workspace': 'clean'}
        f.put(f.run / 'stages' / stage / 'application-credentials.json', receipt)
        f.put(f.run / 'stages' / stage / 'state.json', {'schema': 2, 'status': 'finalized', 'cleanup_confirmed': True})
        f.put(f.run / 'agent-1-participant/process.json', {'cleanup_confirmed': True, 'application_credentials': receipt,
            'application_helper_cleanup': {'status': 'removed', 'workspace': 'clean', 'safe_to_continue': True}})
        for value in (f.run / 'controls').rglob('application-context.json'):value.unlink()
        browser = str(uuid.uuid4())
        f.put(f.run / 'stages' / browser / 'descriptor.json', {'schema': 2, 'kind': 'browser', 'stage_id': browser,
                                                           **f.helper['binding']})
        f.put(f.run / 'stages' / browser / 'state.json', {'schema': 2, 'status': 'finalized', 'cleanup_confirmed': True})
        with f.held():
            f.runtime_cleanup(); f.owner.close()
            self.assertTrue(self.api.validate_accepted(f.owner, f.helper))

    def external_owner(self, source, *, rw=True, runroot=None):
        f = self.f
        row = {'schema': 1, 'launch_id': str(uuid.uuid4()), 'generation': str(uuid.uuid4()),
               'registry': f.owner.registry_id, 'status': 'running', 'container': 'pi-other-owned-holder',
               'image': 'sha256:' + 'e' * 64, 'container_id': 'f' * 64, 'daemon': 'fixture-daemon',
               'runroot': str(runroot or f.root / 'other-run'),
               'mounts': [{'source': str(source), 'target': '/workspace', 'rw': rw}]}
        f.owner.write(row); return row

    def test_pending_other_run_writer_of_the_owned_workspace_blocks_before_cleanup(self):
        f = self.f; request = f.request('helper_only'); self.external_owner(f.workspace)
        with self.assertRaises(fixtures.registry.RegistryError):f.recover(request)
        self.assertTrue(f.workspace.exists()); self.assertEqual(f.calls, [])

    def test_pending_other_run_readonly_holder_of_the_run_blocks_before_cleanup(self):
        f = self.f; request = f.request('helper_only'); self.external_owner(f.run, rw=False)
        with self.assertRaises(fixtures.registry.RegistryError):f.recover(request)
        self.assertTrue(f.workspace.exists()); self.assertEqual(f.calls, [])

    def test_pending_alias_runroot_is_not_excluded_from_holder_coverage(self):
        f = self.f; request = f.request('helper_only'); alias = f.root / 'run-alias'; alias.symlink_to(f.run, target_is_directory=True)
        row = self.external_owner(f.root / 'disjoint', runroot=alias); row['mounts'] = []; f.owner.write(row)
        with self.assertRaises(fixtures.registry.RegistryError):f.recover(request)
        self.assertTrue(f.workspace.exists()); self.assertEqual(f.calls, [])

    def test_disjoint_pending_owner_does_not_require_unrelated_cleanup(self):
        f = self.f; request = f.request('helper_only'); self.external_owner(f.root / 'disjoint')
        self.assertEqual(f.recover(request)['status'], 'CLEANED')

    def test_generic_reconciliation_can_clear_later_pending_overlaps_before_fresh_dispatch(self):
        f = self.f; request = f.request('helper_only'); before = f.metadata(); f.recover(request)
        row = self.external_owner(f.workspace)
        with f.held():f.owner.reconcile()
        self.assertEqual(next(r for r in f.owner.load() if r['launch_id'] == row['launch_id'])['status'], 'released')
        self.assertEqual(f.metadata(), before)
        with f.held():self.assertTrue(self.api.validate_accepted(f.owner, f.helper))


if __name__ == '__main__':
    unittest.main()
