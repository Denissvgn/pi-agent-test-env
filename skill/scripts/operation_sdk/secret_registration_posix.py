"""Fixed single-invocation POSIX calls for experimental SDK registration.

Python's higher-level wrappers can retry EINTR or hide a close EINTR. These
bindings retain the first C-library return, without retry or fallback. Native
library/interpreter origin approval belongs to the enclosing trusted consumer.
"""
import ctypes
import errno
import os
import sys


_functions = None


def ready():
    global _functions
    if _functions is not None:
        return
    if os.name != 'posix' or sys.platform not in ('linux', 'darwin'):
        raise OSError(errno.ENOTSUP, 'unsupported_posix_boundary')
    if not all(hasattr(os, name) for name in ('O_NOFOLLOW', 'O_DIRECTORY', 'O_CLOEXEC', 'O_NONBLOCK')):
        raise OSError(errno.ENOTSUP, 'unsupported_posix_boundary')
    if (ctypes.sizeof(ctypes.c_int) != 4 or ctypes.sizeof(ctypes.c_void_p) != 8
            or ctypes.sizeof(ctypes.c_size_t) != 8 or ctypes.sizeof(ctypes.c_ssize_t) != 8):
        raise OSError(errno.ENOTSUP, 'unsupported_posix_abi')
    library = ctypes.CDLL(None, use_errno=True)
    signatures = {
        # Only fixed arguments belong in argtypes for variadic functions. On
        # Apple ARM64 the variadic mode is passed differently from fixed args.
        'open': ([ctypes.c_char_p, ctypes.c_int], ctypes.c_int),
        'openat': ([ctypes.c_int, ctypes.c_char_p, ctypes.c_int], ctypes.c_int),
        'write': ([ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t], ctypes.c_ssize_t),
        'fsync': ([ctypes.c_int], ctypes.c_int),
        'linkat': ([ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int], ctypes.c_int),
        'unlinkat': ([ctypes.c_int, ctypes.c_char_p, ctypes.c_int], ctypes.c_int),
        'close': ([ctypes.c_int], ctypes.c_int),
    }
    functions = {}
    try:
        for name, (arguments, result) in signatures.items():
            function = getattr(library, name)
            function.argtypes, function.restype = arguments, result
            functions[name] = function
    except AttributeError:
        raise OSError(errno.ENOTSUP, 'unsupported_posix_boundary') from None
    _functions = functions


def _call(name, *arguments):
    ready()
    ctypes.set_errno(0)
    result = _functions[name](*arguments)
    saved_errno = ctypes.get_errno()
    if result < 0:
        raise OSError(saved_errno or errno.EIO, 'posix_call_unconfirmed')
    return result


def open_file(path, flags, mode=0o600, *, dir_fd=None):
    encoded = os.fsencode(path)
    if b'\0' in encoded:
        raise ValueError('posix_path')
    if dir_fd is None:
        return _call('open', encoded, flags, ctypes.c_uint(mode))
    return _call('openat', dir_fd, encoded, flags, ctypes.c_uint(mode))


def write(fd, body):
    body = bytes(body)
    buffer = ctypes.create_string_buffer(body, len(body))
    return _call('write', fd, buffer, len(body))


def fsync(fd):
    _call('fsync', fd)


def link(source, target, *, src_dir_fd, dst_dir_fd, follow_symlinks=False):
    if follow_symlinks is not False:
        raise ValueError('posix_link_flags')
    # Zero flags intentionally does not follow the source symlink.
    _call('linkat', src_dir_fd, os.fsencode(source), dst_dir_fd, os.fsencode(target), 0)


def unlink(name, *, dir_fd):
    _call('unlinkat', dir_fd, os.fsencode(name), 0)


def close(fd):
    _call('close', fd)
