"""The restrictive callback must precede SDK effects inside the original lock."""
import contextlib
import fcntl
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

REPO = next(p for p in Path(__file__).resolve().parents
            if (p / 'skill/scripts/resources.py').is_file())
sys.path.insert(0, str(REPO / 'skill/scripts'))
import ownership_registry
import resources


class OriginalLeasePreflight(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='original-lease-preflight-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.lock = self.root / 'host.lock'
        self.lock.write_bytes(b'preserved-header\n')
        self.lock.chmod(0o600)
        self.registry_root = Path(str(self.lock) + '.registry')
        self.denials = contextlib.ExitStack()
        self.addCleanup(self.denials.close)
        for target in ('subprocess.Popen', 'subprocess.run', 'socket.socket', 'os.kill'):
            self.denials.enter_context(mock.patch(target, side_effect=AssertionError('native effect forbidden')))

    def assert_locked(self):
        fd = os.open(self.lock, os.O_RDWR)
        try:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)

    def assert_unlocked(self):
        fd = os.open(self.lock, os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def test_invalid_callback_rejects_before_any_path_io(self):
        with mock.patch.object(resources, 'Path', side_effect=AssertionError('path IO before type check')):
            with self.assertRaises(resources.AdmissionError):
                with resources.admission_lock(str(self.lock), before_registry=1):
                    self.fail('invalid callback admitted')
        self.assertEqual(self.lock.read_bytes(), b'preserved-header\n')
        self.assertFalse(self.registry_root.exists())

    def test_denial_holds_original_flock_and_prevents_header_and_constructor(self):
        called = []
        class Denied(ValueError):
            pass
        def before_registry(*, lease_fd, lock_path, registry_root):
            called.append(lease_fd)
            self.assertEqual(lock_path, self.lock)
            self.assertEqual(registry_root, self.registry_root)
            self.assertEqual(os.fstat(lease_fd).st_ino, self.lock.stat().st_ino)
            self.assert_locked()
            self.assertFalse(self.registry_root.exists())
            self.assertEqual(self.lock.read_bytes(), b'preserved-header\n')
            raise Denied('controlled metadata denial')
        with mock.patch.object(ownership_registry, 'Registry', side_effect=AssertionError('constructor before guard')):
            with self.assertRaises(Denied):
                with resources.admission_lock(self.lock, before_registry=before_registry):
                    self.fail('denied callback yielded')
        self.assertEqual(len(called), 1)
        self.assertEqual(self.lock.read_bytes(), b'preserved-header\n')
        self.assertFalse(self.registry_root.exists())
        self.assert_unlocked()

    def test_positive_callback_yields_original_registry_and_current_then_restores(self):
        called = []
        previous = ownership_registry.CURRENT.get()
        def before_registry(*, lease_fd, lock_path, registry_root):
            called.append(lease_fd)
            self.assert_locked()
            self.assertFalse(registry_root.exists())
            self.assertEqual(self.lock.read_bytes(), b'preserved-header\n')
        with resources.admission_lock(self.lock, before_registry=before_registry) as registry:
            self.assertIs(type(registry), ownership_registry.Registry)
            self.assertIs(ownership_registry.CURRENT.get(), registry)
            self.assertEqual(registry.root, self.registry_root)
            self.assertEqual(registry.lease_fd, called[0])
            self.assert_locked()
            self.assertEqual(registry.require_capacity(210)['retained_records'], 0)
        self.assertEqual(len(called), 1)
        self.assertIs(ownership_registry.CURRENT.get(), previous)
        self.assert_unlocked()

    def test_legacy_none_keeps_original_context_path(self):
        previous = ownership_registry.CURRENT.get()
        with resources.admission_lock(self.lock) as registry:
            self.assertIs(ownership_registry.CURRENT.get(), registry)
            self.assertEqual(registry.require_capacity(210)['retained_records'], 0)
        self.assertIs(ownership_registry.CURRENT.get(), previous)
        self.assert_unlocked()


if __name__ == '__main__':
    unittest.main(verbosity=2)
