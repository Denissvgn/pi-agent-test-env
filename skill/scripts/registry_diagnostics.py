"""Closed host-registry diagnostics; never classify exception text or digests.

Observation hooks preserve exception identity so expected FileNotFoundError
handling still works. Only a phase boundary translates an escaping failure.
"""
import contextlib
import contextvars
from dataclasses import dataclass
import errno
import functools
import subprocess

PHASES = frozenset({
    'unspecified', 'registry_initialization', 'inventory', 'reconciliation',
    'qualification_service_cleanup', 'qualification_preworker_cleanup',
    'application_cleanup', 'daemon_observation', 'inference_termination',
    'writer_inspection', 'writer_termination', 'persist_absent', 'network_cleanup',
    'sensitive_recovery', 'private_store_cleanup', 'persist_release',
    'registry_write', 'terminal_close', 'lease_observation', 'recovery_receipt',
    'owner_legacy_validation', 'owner_legacy_scope', 'owner_legacy_publication', 'owner_legacy_replay',
})
CONDITIONS = frozenset({
    'validation_failed', 'filesystem_operation_failed', 'command_timeout',
    'capacity_exceeded', 'unsafe_path', 'unsafe_record', 'malformed_record',
    'unexpected_entry', 'inventory_unbounded', 'cleanup_proof_invalid',
    'owned_application_cleanup_required', 'application_cleanup_pending',
    'daemon_unavailable', 'daemon_changed', 'inference_uncertain',
    'gateway_pending', 'writer_observation_failed', 'ownership_mismatch',
    'writer_cleanup_failed', 'writer_absence_unconfirmed',
    'sensitive_cleanup_pending', 'sensitive_identity_mismatch',
    'network_cleanup_failed', 'lease_changed',
    'owner_writer_pending', 'owner_scope_unsupported', 'owner_discard_required', 'owner_identity_required',
    'owner_legacy_unsupported', 'owner_legacy_incomplete', 'owner_proof_publication_incomplete',
})
OPERATIONS = frozenset({
    'validate', 'directory_create', 'inventory_read', 'record_read', 'proof_read',
    'temporary_create', 'file_write', 'file_fsync', 'atomic_replace',
    'temporary_cleanup', 'directory_open', 'directory_fsync', 'daemon_info',
    'container_inspect', 'container_remove', 'network_inspect', 'network_remove',
    'purge', 'lease_open', 'lease_lock',
})
OS_ERRORS = frozenset({'none', 'permission_denied', 'read_only', 'storage_exhausted',
    'io_error', 'missing', 'unsafe_link', 'invalid_operation', 'unsupported',
    'resource_exhausted', 'other'})
EFFECTS = frozenset({'none_observed', 'may_have_occurred'})
_ERRNOS = {
    errno.EACCES: 'permission_denied', errno.EPERM: 'permission_denied',
    errno.EROFS: 'read_only', errno.ENOSPC: 'storage_exhausted',
    errno.EDQUOT: 'storage_exhausted', errno.EIO: 'io_error',
    errno.ENOENT: 'missing', errno.ELOOP: 'unsafe_link',
    errno.EINVAL: 'invalid_operation', errno.ENOTSUP: 'unsupported',
    errno.EMFILE: 'resource_exhausted', errno.ENFILE: 'resource_exhausted',
}
_CURRENT = contextvars.ContextVar('registry_diagnostic_phase', default=None)
_OPERATIONS = contextvars.ContextVar('registry_diagnostic_operations', default=())
_STAMP = object()


@dataclass(frozen=True)
class _Snapshot:
    phase: str
    condition: str
    operation: str
    os_error: str
    effects: str


def project(value):
    """Return a fresh allowlisted projection; invalid or forged shapes disappear."""
    if type(value) is not _Snapshot:
        return None
    fields = ('phase', 'condition', 'operation', 'os_error', 'effects')
    catalogs = (PHASES, CONDITIONS, OPERATIONS, OS_ERRORS, EFFECTS)
    values = [getattr(value, field, None) for field in fields]
    if any(type(item) is not str or item not in catalog for item, catalog in zip(values, catalogs)):
        return None
    return {'schema': 1, **dict(zip(fields, values))}


def _attached(exc):
    value = getattr(exc, '_registry_observation', None)
    if (type(value) is tuple and len(value) == 3 and value[0] is _STAMP
            and type(value[2]) is tuple and project(value[1])):
        return value[1]
    return None


def _origin(exc):
    return exc._registry_observation[2] if _attached(exc) is not None else None


def _remember(exc, snapshot, origin=None):
    exc._registry_observation = (_STAMP, snapshot, _OPERATIONS.get() if origin is None else origin)


def _capture(exc=None, condition=None):
    frame = _CURRENT.get()
    phase, default, operation, state = frame or ('unspecified', 'validation_failed', 'validate', [False])
    os_error = 'none'
    condition = condition or default
    if isinstance(exc, OSError):
        condition = 'filesystem_operation_failed'
        os_error = _ERRNOS.get(exc.errno, 'other') if type(exc.errno) is int else 'other'
    elif isinstance(exc, subprocess.TimeoutExpired):
        condition = 'command_timeout'
    value = _Snapshot(phase, condition, operation, os_error,
                      'may_have_occurred' if state[0] else 'none_observed')
    if project(value) is None:
        raise ValueError('Invalid registry diagnostic catalog selection')
    return value


class RegistryError(ValueError):
    reason = 'host-registry-unsafe'

    def __init__(self, detail='', *, condition=None, cause=None):
        super().__init__(detail)
        snapshot = (snapshot_of(cause) or _attached(cause)) if cause is not None else None
        _remember(self, snapshot or _capture(cause, condition), _origin(cause))


class RegistryCapacityError(RegistryError):
    reason = 'host-registry-capacity'

    def __init__(self, detail=''):
        super().__init__(detail, condition='capacity_exceeded')


def snapshot_of(exc):
    return _attached(exc) if type(exc) in (RegistryError, RegistryCapacityError) else None


def diagnostic(exc):
    return project(snapshot_of(exc))


def annotate(exc, condition):
    """Attach a known predicate without changing a caller's exception type."""
    if condition not in CONDITIONS:
        raise ValueError('Invalid registry diagnostic condition')
    if _CURRENT.get() is not None:
        _remember(exc, _capture(exc, condition))
    return exc


@contextlib.contextmanager
def phase(name, condition='validation_failed', *, inherit=False):
    """Translate escaping known failures, preserving the innermost trusted context."""
    if name not in PHASES or condition not in CONDITIONS:
        raise ValueError('Invalid registry diagnostic phase')
    previous = _CURRENT.get()
    state = previous[3] if previous else [False]
    frame = previous if inherit and previous else (name, condition, 'validate', state)
    token = _CURRENT.set(frame)
    try:
        yield
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError,
            TypeError, KeyError, IndexError, AttributeError) as exc:
        snapshot = snapshot_of(exc) or _attached(exc)
        if snapshot is None:
            snapshot = _capture(exc)
        elif snapshot.phase == 'unspecified':
            snapshot = _Snapshot(frame[0], snapshot.condition, frame[2], snapshot.os_error,
                                 'may_have_occurred' if state[0] else snapshot.effects)
        if state[0] and snapshot.effects != 'may_have_occurred':
            snapshot = _Snapshot(snapshot.phase, snapshot.condition, snapshot.operation,
                                 snapshot.os_error, 'may_have_occurred')
        if type(exc) in (RegistryError, RegistryCapacityError):
            _remember(exc, snapshot, _origin(exc))
            raise
        error = RegistryError(str(exc))
        _remember(error, snapshot, _origin(exc))
        raise error from None
    finally:
        _CURRENT.reset(token)


def scoped(name, condition='validation_failed', *, inherit=False):
    def decorate(fn):
        @functools.wraps(fn)
        def call(*args, **kwargs):
            with phase(name, condition, inherit=inherit):
                return fn(*args, **kwargs)
        return call
    return decorate


@contextlib.contextmanager
def operation(name, *, mutating=False):
    """Inactive outside registry phases; never change caught exception types."""
    if name not in OPERATIONS:
        raise ValueError('Invalid registry diagnostic operation')
    previous = _CURRENT.get()
    if previous is None:
        yield
        return
    phase_name, condition, unused, state = previous
    if mutating:
        state[0] = True
    token = _CURRENT.set((phase_name, condition, name, state))
    path = _OPERATIONS.get() + (object(),)
    operation_token = _OPERATIONS.set(path)
    try:
        yield
    except Exception as exc:
        snapshot = _attached(exc)
        origin = _origin(exc)
        # Only a failure observed inside this particular operation can keep its
        # inner context. A reused exception must not replay an earlier attempt.
        if snapshot is None or origin[:len(path)] != path:
            selected = snapshot.condition if snapshot_of(exc) is not None else None
            _remember(exc, _capture(exc, selected))
        raise
    finally:
        _OPERATIONS.reset(operation_token)
        _CURRENT.reset(token)


def observed(name):
    def decorate(fn):
        @functools.wraps(fn)
        def call(*args, **kwargs):
            with operation(name):
                return fn(*args, **kwargs)
        return call
    return decorate
