"""Non-authoritative qualification timing; never changes an admission deadline.

Callbacks retain closed metadata in bounded RAM. The caller holds the existing
qualification instrumentation lock. Receipt I/O is allowed only after terminal().
No application arguments, bootstrap, exception text or subprocess output is read.
"""
import contextlib
import functools
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / 'reports/application-agent-enhancements'
MAX_EVENTS = 12
MAX_BYTES = 8192
EVENTS = ('guard_enter', 'prelaunch_checks_done', 'reserve_done',
          'dispatch_ready_done', 'delegate_enter', 'delegate_return',
          'capture_enter', 'capture_return', 'guard_return',
          'identity_bind_enter', 'identity_bind_return', 'guard_failed')
STATUSES = ('observed', 'returned', 'raised')
REASONS = ('invalid_event', 'invalid_status', 'invalid_clock', 'clock_regressed',
           'event_out_of_order', 'event_duplicate', 'event_limit',
           'deadline_invalid', 'deadline_duplicate', 'recorder_error',
           'not_terminal', 'receipt_limit')
SOURCE_PATHS = {'guard': ROOT / 'tools/qualification/application_launch.py',
                'runtime': ROOT / 'skill/scripts/application_client.py',
                'orchestrator': ROOT / 'tools/qualification/application_client.py'}
ORCHESTRATOR_PATHS = {
    'qualification': ROOT / 'tools/qualification/application_client.py',
    'startup_diagnostic': ROOT / 'tools/qualification/application_startup_diagnostic.py'}

SERVICE_PHASES = ('authority_validation', 'ownership_check', 'daemon_check',
                  'container_check', 'command_preparation', 'authority_commit',
                  'durable_fence', 'ownership_recheck', 'delegate_gate', 'delegate')
READINESS_PHASES = ('authority_validation', 'ownership_check', 'container_check',
                    'daemon_check', 'authority_commit', 'durable_fence',
                    'ownership_recheck', 'readiness_acceptance')
MAX_SERVICE_DIAGNOSTIC_BYTES = 4096
_SERVICE_SECONDS_BOUND = 86400


def _service_number(value, *, signed=False):
    try:
        return (type(value) in (int, float) and math.isfinite(value)
                and (-_SERVICE_SECONDS_BOUND if signed else 0) <= value <= _SERVICE_SECONDS_BOUND)
    except (OverflowError, ValueError, TypeError):
        return False


def _service_copy(value):
    """Validate before serialization; unknown strings/objects are never rendered."""
    fields = {'schema', 'document_type', 'phase', 'elapsed_seconds', 'observations'}
    row_fields = {'phase', 'entered_elapsed_seconds', 'observed_elapsed_seconds',
                  'command_remaining_seconds', 'campaign_remaining_seconds', 'campaign_observed_elapsed_seconds', 'cleanup_remaining_seconds'}
    if (type(value) is not dict or len(value) != len(fields)
            or any(type(key) is not str for key in value) or set(value) != fields
            or type(value['schema']) is not int or value['schema'] != 1
            or type(value['document_type']) is not str
            or value['document_type'] != 'qualification_service_deadline_diagnostic'
            or type(value['phase']) is not str or value['phase'] not in SERVICE_PHASES + READINESS_PHASES
            or not _service_number(value['elapsed_seconds'])):
        return None
    observations = value['observations']
    if type(observations) is not list or not 1 <= len(observations) <= len(SERVICE_PHASES):
        return None
    rows = []
    previous = 0
    sequences = [SERVICE_PHASES, READINESS_PHASES]
    for index, row in enumerate(observations):
        if (type(row) is not dict or len(row) != len(row_fields)
                or any(type(key) is not str for key in row) or set(row) != row_fields
                or type(row['phase']) is not str):
            return None
        sequences = [sequence for sequence in sequences if index < len(sequence) and row['phase'] == sequence[index]]
        if not sequences:
            return None
        entered, observed = row['entered_elapsed_seconds'], row['observed_elapsed_seconds']
        if not (_service_number(entered) and _service_number(observed)
                and previous <= entered <= observed <= value['elapsed_seconds']):
            return None
        for name in ('command_remaining_seconds', 'campaign_remaining_seconds', 'cleanup_remaining_seconds'):
            if row[name] is not None and not _service_number(row[name], signed=True):
                return None
        campaign_at = row['campaign_observed_elapsed_seconds']
        if ((row['campaign_remaining_seconds'] is None) != (campaign_at is None)
                or campaign_at is not None and not (_service_number(campaign_at) and entered <= campaign_at <= observed)):
            return None
        rows.append({name: row[name] for name in row_fields})
        previous = observed
    if value['phase'] != rows[-1]['phase']:
        return None
    copied = {'schema': 1, 'document_type': 'qualification_service_deadline_diagnostic',
              'phase': value['phase'], 'elapsed_seconds': value['elapsed_seconds'], 'observations': rows}
    if len(json.dumps(copied, allow_nan=False, separators=(',', ':')).encode()) > MAX_SERVICE_DIAGNOSTIC_BYTES:
        return None
    return copied


def extract_service_diagnostic(error):
    """Return a strict closed copy, or None; never inspect exception text/args."""
    if not isinstance(error, BaseException):
        return None
    try:
        attributes = BaseException.__getattribute__(error, '__dict__')
        return _service_copy(attributes.get('service_deadline_diagnostic'))
    except (KeyboardInterrupt, SystemExit, GeneratorExit, TimeoutError):
        raise
    except Exception:
        return None


class ServiceDiagnostic:
    """At most ten RAM-only observations; no authority calls or hot-path I/O.

    Campaign remaining values come only from the guard's existing observations.
    A phase without such an observation has a null campaign value.
    """
    def __init__(self, *, clock, command_deadline=None, cleanup_deadline=None, readiness=False):
        self.clock = clock
        self.command_deadline = command_deadline
        self.cleanup_deadline = cleanup_deadline
        self.started = None
        self.rows = []
        self.failed_rows = None
        self.valid = True
        self.phases = READINESS_PHASES if readiness is True else SERVICE_PHASES
        self.mark('authority_validation')

    def _stamp(self, observed_now=None):
        now = self.clock() if observed_now is None else observed_now
        if type(now) not in (int, float) or not math.isfinite(now):
            self.valid = False
            return None
        if self.started is None:
            self.started = now
        elapsed = now - self.started
        if not _service_number(elapsed) or self.rows and elapsed < self.rows[-1]['observed_elapsed_seconds']:
            self.valid = False
            return None
        return now, elapsed

    @staticmethod
    def _remaining(deadline, now):
        if type(deadline) not in (int, float):
            return None
        value = deadline - now
        return value if _service_number(value, signed=True) else None

    def _refresh(self, now, elapsed):
        row = self.rows[-1]
        row['observed_elapsed_seconds'] = elapsed
        row['command_remaining_seconds'] = self._remaining(self.command_deadline, now)
        row['cleanup_remaining_seconds'] = self._remaining(self.cleanup_deadline, now)

    def mark(self, phase, *, observed_now=None):
        try:
            if not self.valid:
                return
            if type(phase) is not str or len(self.rows) >= len(self.phases) or phase != self.phases[len(self.rows)]:
                self.valid = False
                return
            stamped = self._stamp(observed_now)
            if stamped is None:
                return
            now, elapsed = stamped
            if self.rows:
                self._refresh(now, elapsed)
            self.rows.append({'phase': phase, 'entered_elapsed_seconds': elapsed,
                              'observed_elapsed_seconds': elapsed, 'command_remaining_seconds': None,
                              'campaign_remaining_seconds': None, 'campaign_observed_elapsed_seconds': None,
                              'cleanup_remaining_seconds': None})
            self._refresh(now, elapsed)
        except (KeyboardInterrupt, SystemExit, GeneratorExit, TimeoutError):
            raise
        except Exception:
            self.valid = False

    def observed_remaining(self, now, campaign):
        # This timestamp and campaign value were already read by left(state).
        try:
            if not self.valid or self.started is None:
                return
            elapsed = now - self.started
            if not _service_number(elapsed) or elapsed < self.rows[-1]['observed_elapsed_seconds']:
                self.valid = False
                return
            self._refresh(now, elapsed)
            self.rows[-1]['campaign_remaining_seconds'] = campaign if _service_number(campaign, signed=True) else None
            self.rows[-1]['campaign_observed_elapsed_seconds'] = elapsed if self.rows[-1]['campaign_remaining_seconds'] is not None else None
        except (KeyboardInterrupt, SystemExit, GeneratorExit, TimeoutError):
            raise
        except Exception:
            self.valid = False

    def freeze_failure(self):
        """Keep the original failing phase separate from later failure accounting."""
        if self.failed_rows is not None or not self.valid or not self.rows:
            return
        stamped = self._stamp()
        if stamped is not None:
            self._refresh(*stamped)
            self.failed_rows = [dict(row) for row in self.rows]

    def snapshot(self):
        if not self.valid or not self.rows:
            return None
        stamped = self._stamp()
        if stamped is None:
            return None
        now, elapsed = stamped
        if self.failed_rows is None:
            self._refresh(now, elapsed)
        rows = self.failed_rows if self.failed_rows is not None else self.rows
        return _service_copy({'schema': 1, 'document_type': 'qualification_service_deadline_diagnostic',
                              'phase': rows[-1]['phase'], 'elapsed_seconds': elapsed,
                              'observations': rows})


class TimingContextError(ValueError):
    def __init__(self):
        super().__init__('timing_context_unavailable')


def _number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _close(fd):
    if fd is not None:
        try:
            os.close(fd)
        except Exception:
            pass


class Recorder:
    """One helper, at most twelve closed events; ordinary failures never raise.

    Process cancellation is not a recorder error: KeyboardInterrupt/SystemExit
    propagate unless recording would mask an already raised original exception.
    """
    def __init__(self, *, clock=time.monotonic):
        self._clock = clock
        self._events = []
        self._deadline = None
        self._reason = None
        self._terminal = False

    def unavailable(self, reason='recorder_error'):
        if self._reason is None:
            self._reason = reason if reason in REASONS else 'recorder_error'
        return False

    def emit(self, event, *, status='observed'):
        try:
            if self._terminal:
                return self.unavailable('not_terminal')
            if type(event) is not str or event not in EVENTS:
                return self.unavailable('invalid_event')
            if type(status) is not str or status not in STATUSES:
                return self.unavailable('invalid_status')
            if len(self._events) >= MAX_EVENTS:
                return self.unavailable('event_limit')
            if any(row['event'] == event for row in self._events):
                return self.unavailable('event_duplicate')
            if self._events and EVENTS.index(event) <= EVENTS.index(self._events[-1]['event']):
                return self.unavailable('event_out_of_order')
            now = self._clock()
            if not _number(now):
                return self.unavailable('invalid_clock')
            if self._events and now < self._events[-1]['monotonic']:
                return self.unavailable('clock_regressed')
            self._events.append({'event': event, 'status': status, 'monotonic': now})
            return True
        except Exception:
            return self.unavailable()

    def observe_deadline(self, deadline):
        try:
            if self._terminal:
                return self.unavailable('not_terminal')
            if self._deadline is not None:
                return self.unavailable('deadline_duplicate')
            if not _number(deadline) or deadline <= 0:
                return self.unavailable('deadline_invalid')
            self._deadline = deadline
            return True
        except Exception:
            return self.unavailable()

    def terminal(self):
        """Stop observations, not an assertion that native cleanup succeeded."""
        self._terminal = True

    def record_metadata(self):
        rows = [dict(row) for row in self._events]
        by_name = {row['event']: row for row in rows}
        valid = self._reason is None

        def duration(start, end):
            if valid and start in by_name and end in by_name:
                value = by_name[end]['monotonic'] - by_name[start]['monotonic']
                if _number(value):
                    return value
            return None

        entry = by_name.get('identity_bind_enter')
        remaining = None
        if valid and entry is not None and self._deadline is not None:
            remaining = self._deadline - entry['monotonic']
            if not math.isfinite(remaining):
                remaining = None
        ended = by_name.get('identity_bind_return')
        return {'schema': 1, 'document_type': 'qualification_helper_identity_timing',
                'status': 'recorded' if valid else 'timing_unavailable',
                'reason': self._reason, 'terminal': self._terminal,
                'events': rows, 'runtime_deadline_monotonic': self._deadline,
                'runtime_identity_seconds': 5, 'guard_capture_seconds': 5,
                'identity_start_inferred_monotonic': (self._deadline - 5
                    if valid and self._deadline is not None else None),
                'identity_start_scope': 'inferred from observed deadline and unchanged runtime five-second contract',
                'identity_bind_remaining_seconds_at_entry': remaining,
                'identity_deadline_already_expired_at_entry': (remaining <= 0
                    if remaining is not None else None),
                'identity_bind_outcome': ended['status'] if ended else 'not_observed',
                'durations': {'guard_prelaunch_seconds': duration('guard_enter', 'delegate_enter'),
                    'delegate_seconds': duration('delegate_enter', 'delegate_return'),
                    'guard_capture_seconds': duration('capture_enter', 'capture_return'),
                    'guard_callback_seconds': duration('guard_enter', 'guard_return'),
                    'identity_bind_seconds': duration('identity_bind_enter', 'identity_bind_return')},
                'native_success_attested': False, 'deadline_changed': False,
                'extra_dispatches': 0,
                'scope': 'Parent timing observations only; no admission, cleanup, task or model success inferred.'}


def _best_effort(recorder, method, *args, **kwargs):
    try:
        return getattr(recorder, method)(*args, **kwargs)
    except Exception:
        try:
            recorder.unavailable()
        except Exception:
            pass
        return False


@contextlib.contextmanager
def observe_identity_binding(helper_class, recorder_for_helper):
    """Observe the original method while the caller holds its existing patch lock.

    The provider selects a recorder by the helper's owned registered identity.
    No helper/argument representation is retained. Nested installation refuses;
    original arguments, result and exceptions are forwarded exactly once.
    """
    original = getattr(helper_class, '_bind_container_identity', None)
    if not callable(original) or getattr(original, '_application_timing_wrapped', False):
        raise TimingContextError()
    present = '_bind_container_identity' in helper_class.__dict__

    @functools.wraps(original)
    def observed(helper, *args, **kwargs):
        try:
            recorder = recorder_for_helper(helper)
        except Exception:
            recorder = None
        if recorder is not None:
            deadline = args[0] if len(args) == 1 and not kwargs else (
                kwargs['deadline'] if not args and set(kwargs) == {'deadline'} else None)
            _best_effort(recorder, 'observe_deadline', deadline)
            _best_effort(recorder, 'emit', 'identity_bind_enter')
        try:
            result = original(helper, *args, **kwargs)
        except BaseException:
            if recorder is not None:
                # A second diagnostic exception must not replace the original.
                try:
                    _best_effort(recorder, 'emit', 'identity_bind_return', status='raised')
                except BaseException:
                    pass
            raise
        if recorder is not None:
            _best_effort(recorder, 'emit', 'identity_bind_return', status='returned')
        return result

    observed._application_timing_wrapped = True
    setattr(helper_class, '_bind_container_identity', observed)
    try:
        yield
    finally:
        if present:
            setattr(helper_class, '_bind_container_identity', original)
        else:
            delattr(helper_class, '_bind_container_identity')


def _open_chain(path):
    fds = [os.open('/', os.O_RDONLY | os.O_DIRECTORY)]
    edges = []
    try:
        for name in path.parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=fds[-1])
            edges.append((fds[-1], name, child))
            fds.append(child)
        return fds, edges
    except BaseException:
        for fd in reversed(fds):
            _close(fd)
        raise


def _fence(edges):
    for parent, name, child in edges:
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        opened = os.fstat(child)
        if not stat.S_ISDIR(named.st_mode) or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError()


def _source_hashes(kind):
    result = {}
    paths = {**SOURCE_PATHS, 'orchestrator': ORCHESTRATOR_PATHS[kind]}
    for name, path in paths.items():
        fds, edges = _open_chain(path.parent)
        leaf = None
        try:
            _fence(edges)
            leaf = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
                           dir_fd=fds[-1])
            before = os.fstat(leaf)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_uid != os.getuid() or before.st_mode & 0o022
                    or before.st_size > 1048576):
                raise ValueError()
            body = bytearray()
            while len(body) <= 1048576:
                part = os.read(leaf, min(65536, 1048577 - len(body)))
                if not part:
                    break
                body.extend(part)
            after = os.fstat(leaf)
            if len(body) != before.st_size or any(getattr(before, key) != getattr(after, key)
                    for key in ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')):
                raise ValueError()
            _fence(edges)
            result[name] = hashlib.sha256(body).hexdigest()
        finally:
            _close(leaf)
            for fd in reversed(fds):
                _close(fd)
    return result


def source_hashes(*, kind='qualification'):
    """Actual fixed public sources for this scope, or None on ordinary failure."""
    try:
        return _source_hashes(kind)
    except Exception:
        return None


def flush_terminal(directory, recorder, *, identity, source_hashes):
    """One exclusive fixed-name receipt, only in a precreated private reports dir.

    Ordinary failures return fixed unavailable metadata and cannot mask a primary
    outcome. Existing/partial leaves remain; no removal, retry or replacement.
    """
    fds = []
    leaf = None
    unavailable = {'status': 'timing_unavailable', 'written': False,
                   'path': None, 'sha256': None}
    try:
        if type(recorder) is not Recorder or not recorder._terminal:
            return unavailable
        if type(identity) is not dict or set(identity) != {'kind', 'scope_id', 'cell_id', 'launch_id'}:
            return unavailable
        if identity['kind'] not in ('qualification', 'startup_diagnostic'):
            return unavailable
        for field in ('scope_id', 'launch_id'):
            if type(identity[field]) is not str or str(uuid.UUID(identity[field])) != identity[field]:
                return unavailable
        if type(identity['cell_id']) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', identity['cell_id']) is None:
            return unavailable
        actual = _source_hashes(identity['kind'])
        if type(source_hashes) is not dict or source_hashes != actual:
            return unavailable
        raw = os.fspath(directory)
        path = Path(raw)
        if (type(raw) is not str or not path.is_absolute() or str(path) != raw
                or '..' in path.parts or not path.is_relative_to(REPORTS)):
            return unavailable
        value = recorder.record_metadata()
        value.update(identity=dict(identity), source_hashes=actual)
        body = (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
        if len(body) > MAX_BYTES:
            recorder.unavailable('receipt_limit')
            return unavailable
        fds, edges = _open_chain(path)
        parent = os.fstat(fds[-1])
        if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700:
            return unavailable
        _fence(edges)
        name = 'identity-timing-' + identity['launch_id'] + '.json'
        leaf = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                       0o600, dir_fd=fds[-1])
        left = memoryview(body)
        while left:
            written = os.write(leaf, left)
            if written <= 0:
                raise OSError()
            left = left[written:]
        os.fsync(leaf)
        _fence(edges)
        os.fsync(fds[-1])
        return {'status': value['status'], 'written': True, 'path': str(path / name),
                'sha256': hashlib.sha256(body).hexdigest()}
    except Exception:
        return unavailable
    finally:
        _close(leaf)
        for fd in reversed(fds):
            _close(fd)
