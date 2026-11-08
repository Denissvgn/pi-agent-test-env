"""Fixed native boundary: no hidden EINTR retry and correct native file mode."""
import ctypes
import errno
import os
from pathlib import Path
import stat
import tempfile
from unittest import TestCase, mock

from tools.qualification import secret_registration_posix as native


class RegistrationPosixTests(TestCase):
    def test_native_variadic_open_and_openat_apply_private_mode(self):
        with tempfile.TemporaryDirectory(prefix='registration-posix-') as name:
            root = Path(name).resolve()
            parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                for relative in (False, True):
                    path = 'relative' if relative else str(root / 'absolute')
                    fd = native.open_file(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                                          0o600, dir_fd=parent if relative else None)
                    try:
                        self.assertEqual(stat.S_IMODE(os.fstat(fd).st_mode), 0o600)
                        self.assertFalse(os.get_inheritable(fd))
                    finally:
                        native.close(fd)
            finally:
                os.close(parent)

    def test_each_fixed_mutating_boundary_exposes_eintr_after_one_invocation(self):
        invocations = [('open', lambda: native.open_file('/literal', os.O_RDONLY)),
                       ('openat', lambda: native.open_file('literal', os.O_RDONLY, dir_fd=7)),
                       ('write', lambda: native.write(7, b'literal-fake-bytes')),
                       ('fsync', lambda: native.fsync(7)),
                       ('linkat', lambda: native.link('temp', 'final', src_dir_fd=7, dst_dir_fd=7)),
                       ('unlinkat', lambda: native.unlink('temp', dir_fd=7)),
                       ('close', lambda: native.close(7))]
        for name, invoke in invocations:
            def interrupted(*arguments):
                ctypes.set_errno(errno.EINTR)
                return -1
            function = mock.Mock(side_effect=interrupted)
            with self.subTest(boundary=name), mock.patch.object(native, '_functions', {name: function}):
                with self.assertRaises(OSError) as caught: invoke()
                self.assertEqual(caught.exception.errno, errno.EINTR)
                self.assertEqual(function.call_count, 1)

    def test_partial_native_return_is_not_completed_by_an_internal_loop(self):
        function = mock.Mock(return_value=3)
        with mock.patch.object(native, '_functions', {'write': function}):
            self.assertEqual(native.write(7, b'literal-fake-bytes'), 3)
        self.assertEqual(function.call_count, 1)

    def test_unsupported_platform_refuses_without_loading_a_library(self):
        with (mock.patch.object(native, '_functions', None), mock.patch.object(native.sys, 'platform', 'win32'),
              mock.patch.object(native.ctypes, 'CDLL', side_effect=AssertionError('unsupported native load'))):
            with self.assertRaises(OSError) as caught: native.ready()
        self.assertEqual(caught.exception.errno, errno.ENOTSUP)
