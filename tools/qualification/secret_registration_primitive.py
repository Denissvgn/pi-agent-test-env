"""Experimental explicit-FD create-only primitive, outside the installed skill.

This supplies native mechanics, not authority or an operational handler. Callers
must approve code/runtime/effects and hold their coordination through receiver
acceptance. Only fresh synthetic stores are qualified by the maintainer tests.
No store discovery, payload readback, output, failure unlink or retry is present.
"""
from dataclasses import dataclass, field
import json
import os
import re
import stat
import sys
import threading

from . import secret_registration_contract as model
from . import secret_registration_posix as native


# Fixed private boundaries are patchable only by the test owner, not API inputs.
_open, _write, _fsync = native.open_file, native.write, native.fsync
_link, _unlink, _close = native.link, native.unlink, native.close
_operation_gate = threading.Lock()


class RegistrationError(ValueError):
    """Fixed pre-effect refusal without input/exception/value interpolation."""


class _Stopped(Exception):
    def __init__(self, reason):
        self.reason = reason


@dataclass(frozen=True)
class RegistrationLimits:
    max_mutating_calls: int
    max_owned_fds: int
    max_control_bytes: int


@dataclass(frozen=True)
class RegistrationForecast:
    max_calls: int
    max_owned_fds: int
    control_bytes: int


@dataclass(frozen=True, repr=False)
class RegistrationResult:
    _body: bytes = field(repr=False)
    owned_fd_tokens: tuple
    forecast: RegistrationForecast

    def to_wire(self):
        return json.loads(self._body)

    def __repr__(self):
        return 'RegistrationResult()'


def _require(condition, reason='invalid_input'):
    if not condition:
        raise RegistrationError(reason)


def _wire(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode()


def _base(operation, context, value_contract):
    return dict(schema=1, document_type='secret_registration_worker_observation', operation_id=operation,
                context_binding_sha256=context, value_contract=value_contract, outcome='refused',
                reason='invalid_input', phase='preflight', calls=[], trace_complete=True, effects='none',
                file_persistence='not_started', directory_persistence='not_started', final_verified=False,
                owned_fd_closure='confirmed', ack_ready=False, admission_authorized=False)


def _prepare(store_path, store_fd, expected_identity, reference, operation, context, value, selected, limits):
    _require(type(store_path) is str and store_path.startswith('/') and store_path != '/')
    _require(not any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in store_path))
    _require(len(store_path.encode('utf-8')) <= 4096)
    parts = store_path[1:].split('/')
    _require(1 <= len(parts) <= 32 and all(p and p not in ('.', '..') for p in parts))
    _require(type(store_fd) is int and 0 <= store_fd <= 2**31 - 1)
    _require(type(expected_identity) in (tuple, list) and len(expected_identity) == 2
             and all(type(n) is int and n > 0 for n in expected_identity))
    _require(type(reference) is str and re.fullmatch('[A-Z_][A-Z0-9_]{0,63}', reference) is not None)
    try:
        model._uuid(operation); model._sha(context)
        length = model.validate_value(value, selected)
    except model.TraceError:
        raise RegistrationError('invalid_input') from None
    _require(type(limits) is RegistrationLimits)
    for number, minimum, maximum in ((limits.max_mutating_calls, 1, 4096),
                                      (limits.max_owned_fds, 0, 128),
                                      (limits.max_control_bytes, 1, 1048576)):
        _require(type(number) is int and minimum <= number <= maximum, 'invalid_limits')
    fd_count = len(parts) + 2  # root + parents, duplicate store, value.
    calls = length + 5 + fd_count  # Worst case: each positive write advances one byte.
    _require(fd_count <= limits.max_owned_fds and calls <= limits.max_mutating_calls, 'forecast_refused')
    largest = _base(operation, context, selected)
    largest.update(outcome='uncertain', reason='owned_fd_close_unconfirmed', phase='directory_fsync')
    row = dict(ordinal=4096, kind='directory_fsync', state='confirmed',
               fd_token='ancestor:' + '9' * 55, attempted_bytes=16384, confirmed_bytes=16384)
    largest['calls'] = [row] * calls
    control = len(json.dumps(largest, ensure_ascii=True).encode()) + 8192
    _require(control <= limits.max_control_bytes, 'forecast_refused')
    return parts, value.encode('utf-8'), RegistrationForecast(calls, fd_count, control)


def _identity(info):
    return info.st_dev, info.st_ino


def _directory_signature(info):
    return info.st_dev, info.st_ino, info.st_uid, info.st_mode


class _Operation:
    def __init__(self, store_path, caller, expected, parts, reference, operation, context, selected, body, forecast):
        self.path, self.caller, self.expected = store_path, caller, tuple(expected)
        self.parts, self.reference = parts, reference
        self.temp = '.' + reference + '.' + operation + '.pending'
        self.body, self.forecast = body, forecast
        self.report = _base(operation, context, selected)
        self.owned, self.acquired, self.chain = {}, [], []
        self.store = self.value_fd = self.value_identity = None
        self.uncertain = False
        self.closed_unknown = set()
        self.entered_business = False

    def own(self, token, fd):
        self.owned[token] = fd
        self.acquired.append(token)
        return fd

    def row(self, kind, token=None, attempted=None):
        # Admission reserves the entire worst-case ledger, including cleanup.
        if len(self.report['calls']) >= self.forecast.max_calls:
            raise RuntimeError('admitted_ledger_exhausted')
        row = dict(ordinal=len(self.report['calls']) + 1, kind=kind, state='attempted',
                   fd_token=token, attempted_bytes=attempted, confirmed_bytes=0 if kind == 'write' else None)
        self.report['calls'].append(row)
        self.report['phase'] = kind
        return row

    def ancestor_ok(self, info):
        mode = stat.S_IMODE(info.st_mode)
        protected = not mode & 0o022 or info.st_uid == 0 and mode & stat.S_ISVTX
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()) or not protected:
            raise _Stopped('permission_error')

    def preflight(self):
        try:
            native.ready()
        except (OSError, AttributeError):
            raise _Stopped('unsupported_filesystem') from None
        self.store = self.own('store_duplicate', os.dup(self.caller))
        root = self.own('ancestor:0', _open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC))
        info = os.fstat(root); self.ancestor_ok(info)
        self.chain.append((root, None, '/', _directory_signature(info)))
        parent = root
        for index, name in enumerate(self.parts[:-1], 1):
            child = self.own('ancestor:' + str(index), _open(name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent))
            info = os.fstat(child); self.ancestor_ok(info)
            self.chain.append((child, parent, name, _directory_signature(info)))
            parent = child
        self.verify_chain()
        for name, reason in ((self.reference, 'target_exists'), (self.temp, 'temp_exists')):
            try:
                os.stat(name, dir_fd=self.store, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise _Stopped(reason)

    def verify_chain(self):
        try:
            for fd, parent, name, signature in self.chain:
                held = os.fstat(fd)
                named = os.stat(name, follow_symlinks=False) if parent is None else os.stat(
                    name, dir_fd=parent, follow_symlinks=False)
                if _directory_signature(held) != signature or _directory_signature(named) != signature:
                    raise _Stopped('identity_mismatch')
            held = os.fstat(self.store)
            named = os.stat(self.parts[-1], dir_fd=self.chain[-1][0], follow_symlinks=False)
            caller = os.fstat(self.caller)
            if (not stat.S_ISDIR(held.st_mode) or _identity(held) != self.expected
                    or _directory_signature(held) != _directory_signature(named)
                    or _directory_signature(held) != _directory_signature(caller)):
                raise _Stopped('identity_mismatch')
            if held.st_uid != os.geteuid() or stat.S_IMODE(held.st_mode) != 0o700:
                raise _Stopped('permission_error')
        except (OSError, _Stopped):
            if self.entered_business:
                self.report['trace_complete'] = False
            raise _Stopped('identity_mismatch') from None

    def verify_value(self, links, size, *, temp=True, final=False):
        held = os.fstat(self.value_fd)
        signature = (_identity(held), held.st_uid, stat.S_IMODE(held.st_mode), held.st_nlink, held.st_size)
        if (not stat.S_ISREG(held.st_mode) or _identity(held) != self.value_identity
                or held.st_uid != os.geteuid() or stat.S_IMODE(held.st_mode) != 0o600
                or held.st_nlink != links or held.st_size != size):
            raise _Stopped('identity_mismatch')
        for name in ([self.temp] if temp else []) + ([self.reference] if final else []):
            named = os.stat(name, dir_fd=self.store, follow_symlinks=False)
            observed = (_identity(named), named.st_uid, stat.S_IMODE(named.st_mode), named.st_nlink, named.st_size)
            if not stat.S_ISREG(named.st_mode) or observed != signature:
                raise _Stopped('identity_mismatch')

    def current_value(self, links, size, *, temp=True, final=False):
        try:
            self.verify_value(links, size, temp=temp, final=final)
            if not temp:
                try:
                    os.stat(self.temp, dir_fd=self.store, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise _Stopped('identity_mismatch')
        except (OSError, _Stopped):
            self.report['trace_complete'] = False
            raise _Stopped('identity_mismatch') from None

    def effect(self, kind, action, verify=None):
        self.verify_chain()
        if kind in ('file_fsync', 'link'):
            self.current_value(1, len(self.body))
        elif kind == 'temp_unlink':
            self.current_value(2, len(self.body), final=True)
        elif kind == 'directory_fsync':
            self.current_value(1, len(self.body), temp=False, final=True)
        row = self.row(kind)
        self.entered_business = True
        try:
            action()
            if verify is not None:
                verify()
        except BaseException as error:
            no_effect = isinstance(error, FileExistsError) and kind in ('temp_create', 'link')
            row['state'] = 'no_effect' if no_effect else 'unknown'
            self.uncertain |= not no_effect
            if not no_effect:
                if kind in ('temp_create', 'link', 'temp_unlink'): self.report['effects'] = 'unknown'
                if kind == 'file_fsync': self.report['file_persistence'] = 'unknown'
                if kind == 'directory_fsync': self.report['directory_persistence'] = 'unknown'
            if no_effect:
                raise _Stopped('temp_exists' if kind == 'temp_create' else 'target_exists') from None
            raise _Stopped('interrupted' if isinstance(error, (KeyboardInterrupt, SystemExit)) else 'io_error') from None
        row['state'] = 'confirmed'
        if kind == 'temp_create': self.report['effects'] = 'temp_only'
        if kind == 'file_fsync': self.report['file_persistence'] = 'confirmed'
        if kind == 'link': self.report['effects'] = 'leaf_with_temp'
        if kind == 'temp_unlink': self.report['effects'] = 'leaf_only'
        if kind == 'directory_fsync': self.report['directory_persistence'] = 'confirmed'

    def create_temp(self):
        self.value_fd = self.own('value', _open(self.temp,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            0o600, dir_fd=self.store))
        self.value_identity = _identity(os.fstat(self.value_fd))

    def write_value(self):
        total = 0
        while total < len(self.body):
            self.verify_chain()
            self.current_value(1, total)
            row = self.row('write', 'value', len(self.body) - total)
            try:
                count = _write(self.value_fd, self.body[total:])
                if type(count) is not int or not 0 <= count <= len(self.body) - total:
                    raise _Stopped('io_error')
                if count == 0:
                    row['state'] = 'no_effect'
                    raise _Stopped('io_error')
                self.current_value(1, total + count)
            except BaseException as error:
                if row['state'] != 'no_effect':
                    row['state'] = 'unknown'; self.uncertain = True
                raise _Stopped('interrupted' if isinstance(error, (KeyboardInterrupt, SystemExit)) else 'io_error') from None
            total += count
            row.update(state='confirmed', confirmed_bytes=count)

    def close_owned(self):
        for token in reversed(tuple(self.owned)):
            fd = self.owned.pop(token)  # Ambiguous numeric FD is never retried.
            row = self.row('fd_close', token)
            try:
                _close(fd)
                row['state'] = 'confirmed'
            except BaseException:
                row['state'] = 'unknown'
                self.closed_unknown.add(token)
                self.uncertain = True
        if self.closed_unknown:
            self.report.update(owned_fd_closure='unknown', reason='owned_fd_close_unconfirmed')
        if 'value' in self.closed_unknown: self.report['file_persistence'] = 'unknown'
        if 'store_duplicate' in self.closed_unknown: self.report['directory_persistence'] = 'unknown'

    def run(self):
        try:
            self.preflight()
            self.effect('temp_create', self.create_temp, lambda: self.current_value(1, 0))
            self.write_value()
            self.effect('file_fsync', lambda: _fsync(self.value_fd), lambda: self.current_value(1, len(self.body)))
            self.effect('link', lambda: _link(self.temp, self.reference, src_dir_fd=self.store,
                dst_dir_fd=self.store, follow_symlinks=False), lambda: self.current_value(2, len(self.body), final=True))
            self.effect('temp_unlink', lambda: _unlink(self.temp, dir_fd=self.store),
                        lambda: self.current_value(1, len(self.body), temp=False, final=True))
            self.effect('directory_fsync', lambda: _fsync(self.store))
            self.report['phase'] = 'final_verify'
            self.verify_chain()
            self.current_value(1, len(self.body), temp=False, final=True)
            self.report['final_verified'] = True
            self.report['reason'] = 'ok'
        except _Stopped as error:
            self.report['reason'] = error.reason
        except BaseException as error:
            self.report['reason'] = 'interrupted' if isinstance(error, (KeyboardInterrupt, SystemExit)) else 'io_error'
            if self.entered_business:
                self.report['trace_complete'] = False
        finally:
            self.close_owned()
        if not self.report['trace_complete']:
            self.report.update(effects='unknown', file_persistence='unknown',
                               directory_persistence='unknown', owned_fd_closure='unknown')
            self.uncertain = True
        ready = (self.report['reason'] == 'ok' and self.report['final_verified']
                 and self.report['trace_complete'] and not self.closed_unknown)
        if ready:
            self.report.update(outcome='created', ack_ready=True, phase='ack_ready')
        else:
            self.report['outcome'] = ('uncertain' if self.uncertain else
                                      'refused' if self.report['effects'] == 'none' else 'blocked')
        observation = _wire(self.report)
        if len(observation) > self.forecast.control_bytes:
            raise RuntimeError('admitted_control_exhausted')
        return RegistrationResult(observation, tuple(self.acquired), self.forecast)


def register_create_only(*, store_path, store_fd, expected_identity, reference, operation_id,
                         context_sha256, value, value_contract, limits):
    """Write one explicit absent leaf; return a private observation, never authority.

    The caller must already hold its original directory FD and independent
    no-reader/no-competing-writer authority. No default path or activation exists.
    Native loading/effects are reached only after the complete pure forecast.
    """
    parts, body, forecast = _prepare(store_path, store_fd, expected_identity, reference, operation_id,
                                     context_sha256, value, value_contract, limits)
    _require(sys.implementation.name == 'cpython' and threading.active_count() == 1, 'unsupported_runtime')
    _require(_operation_gate.acquire(blocking=False), 'operation_busy')
    try:
        return _Operation(store_path, store_fd, expected_identity, parts, reference, operation_id,
                          context_sha256, value_contract, body, forecast).run()
    finally:
        _operation_gate.release()
