"""Real temporary native lease/registry; execution and Docker remain mocked."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tests.test_results import lab, fixture
import ownership_registry
import resources


class SuiteNativeAdmissionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.args = fixture(self.root)
        self.lease = Path(self.args.lock_file)
        self.lease.write_bytes(b'original native lease metadata\n')
        self.lease.chmod(0o600)
        info = self.lease.stat()
        self.identity = {'device': info.st_dev, 'inode': info.st_ino}
        self.registry = Path(str(self.lease) + '.registry')
        self.registry.mkdir(mode=0o700)

    def snapshot(self):
        info = self.lease.stat()
        return self.lease.read_bytes(), info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns

    def execute(self, identity=None, body=None):
        before = self.snapshot()
        seen = []
        def dispatched(args, attempt, smoke=False):
            current = ownership_registry.CURRENT.get()
            self.assertIsNotNone(current)
            self.assertEqual(current.root, self.registry)
            self.assertEqual(os.fstat(current.lease_fd).st_ino, self.identity['inode'])
            self.assertEqual(current.binding['run_id'], attempt.record['run_id'])
            self.assertEqual(before, self.snapshot())
            seen.append(attempt.root)
            if body: return body(args, attempt, smoke)
            raise lab.LabError('literal stopped fixture', 'fixture-complete')
        with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(lab, '_execute_suite', side_effect=dispatched), \
             mock.patch.object(lab, 'admission_lock', side_effect=AssertionError('ordinary lease path forbidden')) as ordinary, \
             mock.patch.object(lab, 'command', side_effect=AssertionError('no Docker command')):
            code = lab.run_suite(self.args, existing_lease_identity=self.identity if identity is None else identity)
        ordinary.assert_not_called()
        self.assertIsNone(ownership_registry.CURRENT.get())
        self.assertEqual(before, self.snapshot())
        completed = list(Path(self.args.results_dir).glob('*/result.json'))
        completed = [path for path in completed if not path.parent.is_symlink()]
        self.assertEqual(len(completed), 1)
        result = json.loads(completed[0].read_text())
        return code, result, seen

    def test_exact_native_lease_preserves_bytes_and_normal_registry_lifecycle(self):
        code, result, seen = self.execute()
        self.assertEqual(len(seen), 1)
        self.assertEqual(code, 2)
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertEqual(list(self.registry.iterdir()), [])

    def test_wrong_identity_denies_dispatch_without_fallback_or_lease_mutation(self):
        code, result, seen = self.execute({**self.identity, 'inode': self.identity['inode'] + 1})
        self.assertFalse(seen)
        self.assertEqual(code, 2)
        self.assertEqual(result['infrastructure']['reason'], 'admission-lock-unavailable')

    def test_missing_original_lease_is_not_created(self):
        self.lease.unlink()
        with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(lab, '_execute_suite') as run, \
             mock.patch.object(lab, 'admission_lock', side_effect=AssertionError('no ordinary fallback')):
            self.assertEqual(lab.run_suite(self.args, existing_lease_identity=self.identity), 2)
        run.assert_not_called()
        self.assertFalse(self.lease.exists())

    def test_missing_registry_is_not_initialized_by_execution(self):
        self.registry.rmdir()
        code, result, seen = self.execute()
        self.assertFalse(seen)
        self.assertEqual(code, 2)
        self.assertFalse(self.registry.exists())

    def test_unknown_or_boolean_identity_never_dispatches(self):
        for value in ({'device': True, 'inode': 1}, {'device': 1, 'inode': 1, 'extra': 2}):
            with self.subTest(value=value):
                self.args.results_dir = str(self.root / ('results-' + str(len(value))))
                with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(lab, '_execute_suite') as run:
                    self.assertEqual(lab.run_suite(self.args, existing_lease_identity=value), 2)
                run.assert_not_called()

    def test_nondata_identity_cannot_invoke_a_copy_callback(self):
        class InvalidIdentity:
            def __deepcopy__(self, memo):
                raise AssertionError('identity invoked a callback')
        code, result, seen = self.execute(InvalidIdentity())
        self.assertEqual(code, 2)
        self.assertFalse(seen)

    def test_registry_terminal_failure_vetoes_a_successful_body(self):
        def successful(args, attempt, smoke):
            attempt.record['infrastructure']['status'] = 'ready'
            attempt.record['invocation']['status'] = 'verified'
            attempt.record['termination']['reason'] = 'completed'
            attempt.record['scoring']['status'] = 'completed'
            attempt.record['task_result']['status'] = 'pass'
            attempt.record['protected_inputs']['status'] = 'unchanged'
        with mock.patch.object(ownership_registry.Registry, 'close', side_effect=ownership_registry.RegistryError('literal close failure')):
            code, result, seen = self.execute(body=successful)
        self.assertTrue(seen)
        self.assertEqual(code, 1)
        self.assertEqual(result['status'], 'FAIL')

    def test_parallel_and_explicit_native_admission_cannot_be_mixed(self):
        self.args._parallel_session = mock.Mock()
        code, result, seen = self.execute()
        self.assertFalse(seen)
        self.args._parallel_session.admission.assert_not_called()
        self.assertEqual(code, 2)

    def test_existing_cli_without_native_identity_keeps_ordinary_admission(self):
        with contextlib.redirect_stdout(io.StringIO()), \
             mock.patch.object(lab, 'admission_lock', return_value=contextlib.nullcontext()) as ordinary, \
             mock.patch.object(lab, '_execute_suite', side_effect=lab.LabError('literal fixture', 'fixture-complete')):
            self.assertEqual(lab.run_suite(self.args), 2)
        ordinary.assert_called_once_with(self.args.lock_file, self.args.lock_wait_seconds)

    def test_authorized_post_cancel_scoring_reacquires_same_existing_lease(self):
        self.args.score_after_cancel = True
        def cancelled(args, attempt, smoke):
            lab.save(attempt.root / 'plan.json', {'checks': []})
            attempt.record['image'] = {'id': 'literal-no-execution'}
            attempt.record['workspace'] = str(self.root / 'project')
            raise KeyboardInterrupt()
        observed = []
        def score(args, attempt, plan, image, workspace, receipts, post_cancel=False):
            current = ownership_registry.CURRENT.get()
            self.assertIsNotNone(current)
            self.assertEqual(current.root, self.registry)
            self.assertTrue(post_cancel)
            observed.append(os.fstat(current.lease_fd).st_ino)
        with mock.patch.object(lab, 'score_artifacts', side_effect=score), \
             mock.patch.object(resources, 'existing_admission_lock', wraps=resources.existing_admission_lock) as admission:
            code, result, seen = self.execute(body=cancelled)
        self.assertEqual(code, 2)
        self.assertEqual(result['status'], 'INTERRUPTED')
        self.assertEqual(observed, [self.identity['inode']])
        self.assertEqual(admission.call_count, 2)


if __name__ == '__main__': unittest.main(verbosity=2)
