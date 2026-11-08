"""Existing native lease admission with synthetic registries; no real actors."""
import os
from pathlib import Path
import tempfile
from unittest import TestCase, mock

from tests.test_resources import res
import ownership_registry as ownership


class ExistingAdmissionTests(TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.lease = self.root/'original.lock'
        self.lease.write_bytes(b'original owner metadata\n'); self.lease.chmod(0o600)
        info = self.lease.stat(); self.identity = {'device':info.st_dev,'inode':info.st_ino}

    def snapshot(self):
        info = self.lease.stat()
        return (self.lease.read_bytes(), info.st_dev, info.st_ino, info.st_mode,
                info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def test_original_lease_is_not_written_and_normal_registry_lifecycle_remains(self):
        before = self.snapshot(); registry = mock.Mock(); events = []
        registry.reconcile.side_effect = lambda:events.append('reconcile')
        registry.close.side_effect = lambda:events.append('close')
        def gate(**values):
            events.append('gate'); self.assertEqual(values['lock_path'], self.lease)
            self.assertEqual(os.fstat(values['lease_fd']).st_ino, self.identity['inode'])
        with (mock.patch.object(ownership,'Registry',return_value=registry) as factory,
              mock.patch('os.chmod',side_effect=AssertionError('lease chmod')),
              mock.patch('os.truncate',side_effect=AssertionError('lease truncate'))):
            with res.existing_admission_lock(self.lease, self.identity, before_registry=gate) as actual:
                self.assertIs(actual, registry); self.assertIs(ownership.CURRENT.get(), registry)
                events.append('body')
        factory.assert_called_once_with(Path(str(self.lease)+'.registry'), create=False)
        self.assertEqual(events, ['gate','reconcile','body','close'])
        self.assertIsNone(ownership.CURRENT.get()); self.assertEqual(before, self.snapshot())

    def test_missing_or_wrong_original_never_creates_a_lease_or_opens_registry(self):
        for variant in ('missing','identity'):
            path = self.lease if variant=='identity' else self.root/'missing'/'original.lock'
            expected = {**self.identity, 'inode':self.identity['inode']+1} if variant=='identity' else self.identity
            with self.subTest(variant=variant), mock.patch.object(ownership,'Registry') as factory:
                with self.assertRaises(res.AdmissionError):
                    with res.existing_admission_lock(path, expected):self.fail('dispatched')
                factory.assert_not_called()
            if variant=='missing':self.assertFalse(path.parent.exists())

    def test_unresolved_ownership_still_blocks_and_context_does_not_escape(self):
        registry = mock.Mock(); registry.reconcile.side_effect = ownership.RegistryError('synthetic unresolved owner')
        with mock.patch.object(ownership,'Registry',return_value=registry):
            with self.assertRaises(res.AdmissionError) as caught:
                with res.existing_admission_lock(self.lease,self.identity):self.fail('bypassed reconciliation')
        self.assertEqual(caught.exception.reason,'host-registry-unsafe')
        self.assertIsNone(ownership.CURRENT.get()); registry.close.assert_not_called()

    def test_close_failure_vetoes_success_and_restores_context(self):
        registry = mock.Mock(); registry.close.side_effect = ownership.RegistryError('synthetic close failure')
        with mock.patch.object(ownership,'Registry',return_value=registry):
            with self.assertRaises(res.AdmissionError):
                with res.existing_admission_lock(self.lease,self.identity):pass
        self.assertIsNone(ownership.CURRENT.get())

    def test_gate_replacement_denies_before_registry_and_symlink_never_opens_registry(self):
        def replace(**unused):
            self.lease.rename(self.root/'original-retained'); self.lease.write_bytes(b'new'); self.lease.chmod(0o600)
        with mock.patch.object(ownership,'Registry') as factory:
            with self.assertRaises(res.AdmissionError):
                with res.existing_admission_lock(self.lease,self.identity,before_registry=replace):pass
            factory.assert_not_called()
        self.lease.unlink(); self.lease.symlink_to(self.root/'original-retained')
        with mock.patch.object(ownership,'Registry') as factory:
            with self.assertRaises(res.AdmissionError):
                with res.existing_admission_lock(self.lease,self.identity):pass
            factory.assert_not_called()

    def test_invalid_identity_is_rejected_before_file_or_registry_access(self):
        for value in (None, [], {}, {'device':True,'inode':1}, {'device':1,'inode':0},
                      {'device':1,'inode':1,'approved':True}):
            with (self.subTest(value=value), mock.patch('os.open',side_effect=AssertionError('invalid identity IO')),
                  self.assertRaises(res.AdmissionError)):
                with res.existing_admission_lock(self.lease,value):pass

    def test_preflight_denial_and_body_exception_restore_original_lock(self):
        before=self.snapshot()
        def deny(**unused):raise res.AdmissionError('host-registry-unsafe')
        with mock.patch.object(ownership,'Registry') as factory:
            with self.assertRaises(res.AdmissionError):
                with res.existing_admission_lock(self.lease,self.identity,before_registry=deny):pass
            factory.assert_not_called()
        registry=mock.Mock()
        with mock.patch.object(ownership,'Registry',return_value=registry):
            with self.assertRaisesRegex(RuntimeError,'synthetic body'):
                with res.existing_admission_lock(self.lease,self.identity):raise RuntimeError('synthetic body')
            self.assertIsNone(ownership.CURRENT.get())
            with res.existing_admission_lock(self.lease,self.identity):pass
        self.assertEqual(before,self.snapshot())

    def test_existing_lock_conflict_and_named_loss_before_close_are_fatal(self):
        registry=mock.Mock()
        with mock.patch.object(ownership,'Registry',return_value=registry):
            with res.existing_admission_lock(self.lease,self.identity):
                with self.assertRaises(res.AdmissionError):
                    with res.existing_admission_lock(self.lease,self.identity):pass
            with self.assertRaises(res.AdmissionError):
                with res.existing_admission_lock(self.lease,self.identity):self.lease.unlink()
        self.assertIsNone(ownership.CURRENT.get())

    def test_missing_registry_never_creates_new_coordination_state(self):
        before=self.snapshot()
        with self.assertRaises(res.AdmissionError):
            with res.existing_admission_lock(self.lease,self.identity):pass
        self.assertEqual(before,self.snapshot())
        self.assertFalse(Path(str(self.lease)+'.registry').exists())
