"""Finite Docker resource budgets and same-user admission control (host-side).

No cgroup changes are made to the model server or unrelated containers. Quotas
are per container; the host lock serializes this runner's cooperating processes.
"""
from __future__ import annotations
import contextlib
import copy
import fcntl
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import threading
import time
from types import MappingProxyType
import registry_diagnostics

ADMISSION_FAILURES = MappingProxyType({
    'host-registry-capacity': (
        'The bounded host launch registry has insufficient capacity',
        'Keep dependent execution stopped. Preserve ownership and failure history; request reviewed registry maintenance or a bounded capacity change before fresh dispatch. Do not delete records or bypass the host lease.'),
    'host-registry-unsafe': (
        'Prior owned execution cannot be safely reconciled',
        'Keep dependent execution stopped. Inspect the owner-only launch registry and confirm owned writer absence and sensitive cleanup before requesting recovery; do not delete records or bypass the host lease.'),
    'host-admission-busy': (
        'Another pi-agent-test-env operation holds the host lock; wait or use --lock-wait-seconds',
        'Wait for the owning operation to finish, or use --lock-wait-seconds with a bounded value up to 3600. A holder record whose pid no longer exists is not a stuck lock: the kernel releases the lease when its process dies. Do not delete the lock or use another lock file to bypass admission.'),
    'resource-policy-invalid': (
        'The resource policy or admission wait is invalid',
        'Review the resource policy and CLI overrides against RESOURCES.md. Use finite supported limits and a lock wait in 0..3600 seconds; correct the input before dispatch.'),
    'admission-lock-insecure': (
        'Refusing a symlinked admission-lock file',
        'Use the reviewed same-user admission lock outside the project. Resolve the unsafe lock path with its owner before retrying; do not delete an active lock or substitute a bypass lock.'),
    'admission-lock-unavailable': (
        'The admission lock could not be accessed',
        'Check access to the reviewed admission-lock directory and file on the parent host. Preserve existing lock ownership and do not bypass the lease.'),
})


class AdmissionError(ValueError):
    """Known parent failure; only the closed catalog is public diagnostic authority."""
    def __init__(self, reason, detail='', *, registry_error=None):
        if not isinstance(reason, str) or reason not in ADMISSION_FAILURES:
            raise ValueError('Unknown admission failure code')
        self._admission_reason = reason
        self._registry_diagnostic = registry_diagnostics.snapshot_of(registry_error)
        super().__init__(detail or ADMISSION_FAILURES[reason][0])

    @property
    def reason(self):
        return admission_diagnostic(self)['reason']

    @property
    def remedy(self):
        return admission_diagnostic(self).get('remedy', '')


def admission_diagnostic(exc):
    """Do not classify arbitrary exception text, hashes or reason/remedy attributes."""
    import indexed_contract
    import ownership_registry
    if type(exc) in (ownership_registry.RegistryError, ownership_registry.RegistryCapacityError):
        code = 'host-registry-capacity' if type(exc) is ownership_registry.RegistryCapacityError else 'host-registry-unsafe'
        return admission_diagnostic(AdmissionError(code, registry_error=exc))
    selected=indexed_contract.diagnostic(exc)
    if selected is not None:return selected
    if not isinstance(exc, AdmissionError):
        return None
    if type(exc) is not AdmissionError:
        return {'reason': 'admission-error'}
    code = exc._admission_reason
    if not isinstance(code, str) or code not in ADMISSION_FAILURES:
        return {'reason': 'admission-error'}
    message, guidance = ADMISSION_FAILURES[code]
    result = {'reason': code, 'message': message, 'remedy': guidance}
    context = registry_diagnostics.project(getattr(exc, '_registry_diagnostic', None))
    if code in ('host-registry-unsafe', 'host-registry-capacity') and context is not None:
        result['registry_diagnostic'] = context
    return result

HOLDER_RECORD_LIMIT = 4096
_HOLDER_OP = re.compile(r'[a-z][a-z0-9-]{0,63}')
_HOLDER_RUN = re.compile(r'[0-9A-Za-z][0-9A-Za-z._-]{0,63}')
_holder_guard = threading.Lock()
_holder_op = None
_holder_next_run = None
_holder_leases = []


def _holder_fields(value):
    """Closed projection of a holder record: (pid, op, started_unix, run_id) or None."""
    if type(value) is not dict:
        return None
    pid, op, started, run_id = (value.get(name) for name in ('pid', 'op', 'started_unix', 'run_id'))
    if type(pid) is not int or not 1 <= pid < 2 ** 31:
        return None
    if type(started) not in (int, float) or not 0 <= started < 2 ** 40:
        return None
    if op is not None and (type(op) is not str or not _HOLDER_OP.fullmatch(op)):
        return None
    if run_id is not None and (type(run_id) is not str or not _HOLDER_RUN.fullmatch(run_id)):
        return None
    return pid, op, started, run_id


def _holder_line(started, run_id=None):
    """The one-line record of this process; op and run_id appear once they are known."""
    record = {'pid': os.getpid(), 'started_unix': started}
    if _holder_op is not None:
        record['op'] = _holder_op
    if run_id is not None:
        record['run_id'] = run_id
    return json.dumps(record) + '\n'


def describe_holder(*, op=None, run_id=None, held=False):
    """Name this process's command and run in the holder record of its lease.

    The command name applies to every lease this process takes from now on. A
    run id is kept for the next admission_lock call only; with held=True it is
    instead written in place into the leases this process holds now. The record
    is informational: a value outside the record contract is ignored and a
    failed rewrite never raises.
    """
    global _holder_op, _holder_next_run
    with _holder_guard:
        if type(op) is str and _HOLDER_OP.fullmatch(op):
            _holder_op = op
        if type(run_id) is not str or not _HOLDER_RUN.fullmatch(run_id):
            return
        if not held:
            _holder_next_run = run_id
            return
        for lease in _holder_leases:
            lease['run_id'] = run_id
            try:
                handle = lease['handle']
                handle.seek(0)
                handle.truncate()
                handle.write(_holder_line(lease['started'], run_id))
                handle.flush()
            except (OSError, ValueError):
                pass


def _take_holder_run():
    global _holder_next_run
    with _holder_guard:
        run_id, _holder_next_run = _holder_next_run, None
    return run_id


def _pid_exists(pid):
    try:
        os.kill(pid, 0)
    except PermissionError:
        return True
    except (OSError, OverflowError, ValueError):
        return False
    return True


def _holder_of_descriptor(fd, identity=None):
    """Read at most HOLDER_RECORD_LIMIT bytes of one regular file; never waits."""
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_size > HOLDER_RECORD_LIMIT:
        return None
    if identity is not None and (info.st_dev, info.st_ino) != identity:
        return None
    data = os.pread(fd, HOLDER_RECORD_LIMIT + 1, 0)
    if len(data) > HOLDER_RECORD_LIMIT:
        return None
    text = data.decode('utf-8')
    if text.endswith('\n'):
        text = text[:-1]
    if not text or '\n' in text:
        return None
    fields = _holder_fields(json.loads(text))
    if fields is None:
        return None
    pid, op, started, run_id = fields
    result = {'pid': pid, 'op': op, 'started_unix': started,
              'age_seconds': round(max(0.0, time.time() - started), 3)}
    if run_id is not None:
        result['run_id'] = run_id
    result['alive'] = _pid_exists(pid)
    return result


def read_holder(path, *, identity=None):
    """The holder named by a lease's record, or None when it cannot be told.

    The record is read without the lease: one non-blocking open that refuses a
    symbolic link, one bounded read, a closed projection. Nothing here raises, so
    a missing, replaced, oversized or malformed record never changes admission.
    alive only says whether a process with that pid exists now.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            return _holder_of_descriptor(fd, identity)
        finally:
            os.close(fd)
    except Exception:
        return None


def _name_holder(exc, path, fd):
    """Attach the holder of the lease behind fd to its busy failure; returns exc."""
    try:
        if type(exc) is AdmissionError and exc._admission_reason == 'host-admission-busy':
            info = os.fstat(fd)
            exc._lease_holder = read_holder(path, identity=(info.st_dev, info.st_ino))
    except Exception:
        pass
    return exc


def admission_holder(exc):
    """The holder observed when admission failed busy, or None; never arbitrary data."""
    if type(exc) is not AdmissionError or exc._admission_reason != 'host-admission-busy':
        return None
    value = getattr(exc, '_lease_holder', None)
    fields = _holder_fields(value)
    if fields is None or set(value) - {'pid', 'op', 'started_unix', 'age_seconds', 'run_id', 'alive'}:
        return None
    age, alive = value.get('age_seconds'), value.get('alive')
    if type(age) not in (int, float) or not 0 <= age < 2 ** 40 or type(alive) is not bool:
        return None
    pid, op, started, run_id = fields
    result = {'pid': pid, 'op': op, 'started_unix': started, 'age_seconds': age}
    if run_id is not None:
        result['run_id'] = run_id
    result['alive'] = alive
    return result


def holder_text(holder):
    """One text line for a holder from admission_holder or lease_state."""
    text = 'Held by pid %d (%s) for %d seconds' % (holder['pid'], holder['op'] or 'unknown', holder['age_seconds'])
    if not holder['alive']:
        text += ' (no process with that pid exists; the record is stale)'
    return text


def lease_state(path):
    """Observe a lease without entering it: state free, held or unavailable.

    A missing lease is free. Otherwise a non-blocking shared flock on a read-only
    descriptor is tried and released at once; when it is refused the holder is
    read as in read_holder. The lease is never created, written, chmodded or
    followed through a symbolic link, and nothing here raises.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return {'state': 'free', 'holder': None}
    except Exception:
        return {'state': 'unavailable', 'holder': None}
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return {'state': 'unavailable', 'holder': None}
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            try:
                holder = _holder_of_descriptor(fd)
            except Exception:
                holder = None
            return {'state': 'held', 'holder': holder}
        fcntl.flock(fd, fcntl.LOCK_UN)
        return {'state': 'free', 'holder': None}
    except Exception:
        return {'state': 'unavailable', 'holder': None}
    finally:
        os.close(fd)


DEFAULTS = {
    'schema': 1,
    'runtime': {'cpus': 2.0, 'memory': '4g', 'pids_limit': 256, 'jobs': 2},
    'build': {'cpus': 2.0, 'memory': '4g', 'max_parallelism': 2, 'timeout_seconds': 1800},
    'host_budget': {'cpu_fraction': 0.5, 'memory_fraction': 0.5},
}


def memory_bytes(value):
    if not isinstance(value, str) or not re.fullmatch(r'[1-9][0-9]*[mg]', value.lower()):
        raise AdmissionError('resource-policy-invalid', 'Memory must be a finite positive MiB/GiB string, e.g. 1024m or 4g')
    try:
        n = int(value[:-1]) * (1024 ** (2 if value[-1].lower() == 'm' else 3))
    except ValueError as exc:
        raise AdmissionError('resource-policy-invalid', str(exc)) from None
    if n < 64 * 1024 ** 2:
        raise AdmissionError('resource-policy-invalid', 'Memory must be at least 64 MiB')
    return n


def validate_policy(value):
    if not isinstance(value, dict) or set(value) - set(DEFAULTS) or value.get('schema', 1) != 1:
        raise AdmissionError('resource-policy-invalid', 'Resource policy schema 1 accepts runtime, build, host_budget')
    result = copy.deepcopy(DEFAULTS)
    for section in ('runtime', 'build', 'host_budget'):
        supplied = value.get(section, {})
        if not isinstance(supplied, dict) or set(supplied) - set(DEFAULTS[section]):
            raise AdmissionError('resource-policy-invalid', f'Unknown resource field in {section}')
        result[section].update(supplied)
    for section in ('runtime', 'build'):
        cpus = result[section]['cpus']
        if type(cpus) not in (int, float) or not 0.1 <= cpus <= 256 or not math.isfinite(cpus):
            raise AdmissionError('resource-policy-invalid', f'{section}.cpus must be finite and in 0.1..256; 0/unlimited is not allowed')
        memory_bytes(result[section]['memory'])
    bounds = [('runtime', 'pids_limit', 64, 4096), ('runtime', 'jobs', 1, 64),
              ('build', 'max_parallelism', 1, 16), ('build', 'timeout_seconds', 60, 14400)]
    for section, field, low, high in bounds:
        value = result[section][field]
        if type(value) is not int or not low <= value <= high:
            raise AdmissionError('resource-policy-invalid', f'{section}.{field} must be in {low}..{high}')
    for field in ('cpu_fraction', 'memory_fraction'):
        value = result['host_budget'][field]
        if type(value) not in (int, float) or not 0.05 <= value <= 0.9 or not math.isfinite(value):
            raise AdmissionError('resource-policy-invalid', f'host_budget.{field} must be in 0.05..0.9')
    return result


def requested_policy(args):
    try:
        value = json.loads(Path(args.resources).expanduser().read_text()) if getattr(args, 'resources', None) else {}
    except (OSError, ValueError) as exc:
        raise AdmissionError('resource-policy-invalid', str(exc)) from None
    result = validate_policy(value)
    overrides = {'cpus': ('runtime', 'cpus'), 'memory': ('runtime', 'memory'),
                 'pids_limit': ('runtime', 'pids_limit'), 'jobs': ('runtime', 'jobs'),
                 'build_cpus': ('build', 'cpus'), 'build_memory': ('build', 'memory'),
                 'build_parallelism': ('build', 'max_parallelism'),
                 'build_timeout': ('build', 'timeout_seconds')}
    for option, (section, field) in overrides.items():
        supplied = getattr(args, option, None)
        if supplied is not None:
            result[section][field] = supplied
    return validate_policy(result)


def configure(args, docker_info):
    """Clamp against total resources allocated to the daemon, not host os.cpu_count()."""
    requested = copy.deepcopy(getattr(args, '_resource_request', None) or requested_policy(args))
    args._resource_request = copy.deepcopy(requested)
    cpus = docker_info.get('NCPU')
    memory = docker_info.get('MemTotal')
    if type(cpus) is not int or cpus < 1 or type(memory) is not int or memory <= 0:
        raise ValueError('Docker did not report NCPU/MemTotal; cannot establish the resource budget')
    warnings = '\n'.join(docker_info.get('Warnings') or []).lower()
    if any(text in warnings for text in ('no memory limit support', 'no cpu cfs quota support', 'no swap limit support')):
        raise ValueError('Docker reports missing CPU/memory/swap limit support; fix the daemon, not an unlimited fallback')
    effective = copy.deepcopy(requested)
    cap_cpu = math.floor(cpus * requested['host_budget']['cpu_fraction'] * 1000) / 1000
    cap_mem = int(memory * requested['host_budget']['memory_fraction']) // (1024 ** 2) * (1024 ** 2)
    if cap_cpu < 0.1 or cap_mem < 64 * 1024 ** 2:
        raise ValueError('Docker allocation is too small for the configured host-budget fractions')
    for section in ('runtime', 'build'):
        effective[section]['cpus'] = min(float(requested[section]['cpus']), cap_cpu)
        effective[section]['memory'] = str(min(memory_bytes(requested[section]['memory']), cap_mem) // (1024 ** 2)) + 'm'
    jobs = max(1, math.floor(effective['runtime']['cpus']))
    effective['runtime']['jobs'] = min(requested['runtime']['jobs'], jobs)
    effective['build']['max_parallelism'] = min(requested['build']['max_parallelism'], max(1, math.floor(effective['build']['cpus'])))
    for field in ('cpus', 'memory', 'pids_limit', 'jobs'):
        setattr(args, field, effective['runtime'][field])
    # Retain the original policy. A second configure must not mistake clamped values for CLI overrides.
    args.resource_report = {'requested': requested, 'effective': effective,
                            'docker_cpus': cpus, 'docker_memory_bytes': memory,
                            'memory_swap': effective['runtime']['memory'],
                            'parallel_stages': 1, 'scope': 'Cooperating runs of this runner under the same host lock; model server excluded'}
    return args.resource_report


def thread_environment(jobs):
    n = str(jobs)
    return {'PI_TEST_JOBS': n, 'OMP_NUM_THREADS': n, 'OPENBLAS_NUM_THREADS': n,
            'MKL_NUM_THREADS': n, 'NUMEXPR_NUM_THREADS': n, 'VECLIB_MAXIMUM_THREADS': n,
            'UV_THREADPOOL_SIZE': n, 'CMAKE_BUILD_PARALLEL_LEVEL': n, 'MAKEFLAGS': '-j' + n,
            'CARGO_BUILD_JOBS': n, 'RAYON_NUM_THREADS': n, 'GOMAXPROCS': n,
            'npm_config_jobs': n}


def _queued_flock(fd, wait_seconds):
    """Wait in the kernel queue on this FD, with a composable one-shot alarm.

    Only the main thread owns Python signal handlers. Periodic, blocked or
    already-pending alarms cannot be borrowed safely and reject before flock.
    The caller owns the FD and closes it on every failure, including a signal
    arriving immediately after acquisition.
    """
    required = ('pthread_sigmask', 'sigpending', 'sigwait', 'getitimer', 'setitimer')
    if (threading.current_thread() is not threading.main_thread()
            or any(not hasattr(signal, name) for name in required)):
        raise AdmissionError('admission-lock-unavailable')
    alarm = signal.SIGALRM
    protected_signals = {alarm, signal.SIGINT}
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    installed = False
    previous_handler = None
    outer_deadline = None
    outer_fired = False
    deliver_outer = False
    callback_error = None
    wait_deadline = time.monotonic() + wait_seconds
    try:
        signal.pthread_sigmask(signal.SIG_BLOCK, protected_signals)
        if protected_signals.intersection(previous_mask) or alarm in signal.sigpending():
            raise AdmissionError('admission-lock-unavailable')
        observed_at = time.monotonic()
        remaining, interval = signal.getitimer(signal.ITIMER_REAL)
        previous_handler = signal.getsignal(alarm)
        if interval or (remaining and not callable(previous_handler)):
            raise AdmissionError('admission-lock-unavailable')
        if remaining:
            # Sample before getitimer: installation can shorten, never extend,
            # the existing outer deadline.
            outer_deadline = observed_at + remaining

        def arm():
            deadline = wait_deadline
            if outer_deadline is not None and not outer_fired:
                deadline = min(deadline, outer_deadline)
            signal.setitimer(signal.ITIMER_REAL, max(0.000001, deadline - time.monotonic()))

        def expired(signum, frame):
            nonlocal outer_fired, callback_error
            now = time.monotonic()
            try:
                if outer_deadline is not None and not outer_fired and now >= outer_deadline:
                    outer_fired = True
                    previous_handler(signum, frame)
                elif now < wait_deadline:
                    # An explicit external SIGALRM retains the original callback.
                    if callable(previous_handler):
                        previous_handler(signum, frame)
                    else:
                        raise AdmissionError('admission-lock-unavailable')
            except BaseException as exc:
                callback_error = exc
                raise
            if time.monotonic() >= wait_deadline:
                raise AdmissionError('host-admission-busy')
            arm()

        signal.signal(alarm, expired)
        installed = True
        arm()
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError as exc:
            if exc is callback_error:
                raise
            raise AdmissionError('admission-lock-unavailable') from None
        # A delayed signal must not admit a lock acquired after its wait bound.
        if time.monotonic() >= wait_deadline:
            raise AdmissionError('host-admission-busy')
    finally:
        try:
            # A SIGINT raised as this syscall returns must still run restoration.
            signal.pthread_sigmask(signal.SIG_BLOCK, protected_signals)
        finally:
            try:
                if installed:
                    signal.setitimer(signal.ITIMER_REAL, 0)
                    # Discard only our alarm before reinstalling the outer handler.
                    # A due, undispatched outer timer is delivered below immediately.
                    if alarm in signal.sigpending():
                        signal.sigwait({alarm})
                    signal.signal(alarm, previous_handler)
                    if outer_deadline is not None and not outer_fired:
                        remaining = outer_deadline - time.monotonic()
                        if remaining <= 0:
                            deliver_outer = True
                        else:
                            signal.setitimer(signal.ITIMER_REAL, remaining)
            finally:
                try:
                    signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
                finally:
                    if deliver_outer:
                        previous_handler(alarm, None)


@contextlib.contextmanager
def _registry_admission(path, fd, *, before_registry=None, existing_identity=None):
    """The same registry reconciliation/CURRENT/terminal gates for both leases."""
    def check():
        if existing_identity is not None:
            import registry_maintenance
            try:observed = registry_maintenance._check_lock(fd, path)
            except OSError:raise AdmissionError('admission-lock-unavailable') from None
            if observed != existing_identity:
                raise AdmissionError('admission-lock-unavailable')
    check()
    if before_registry is not None:
        before_registry(lease_fd=fd, lock_path=path, registry_root=Path(str(path)+'.registry'))
    check()
    import ownership_registry
    try:
        with registry_diagnostics.phase('registry_initialization'):
            options = {'create':False} if existing_identity is not None else {}
            registry=ownership_registry.Registry(Path(str(path)+'.registry'), **options)
            registry.lease_fd=fd
            with registry_diagnostics.phase('reconciliation'):
                registry.reconcile()
    except (ownership_registry.RegistryError,OSError,ValueError) as exc:
        code='host-registry-capacity' if type(exc) is ownership_registry.RegistryCapacityError else 'host-registry-unsafe'
        raise AdmissionError(code,str(exc),registry_error=exc) from None
    check()
    token=ownership_registry.CURRENT.set(registry)
    try:
        yield registry
        check()
        try:
            with registry_diagnostics.phase('terminal_close'):registry.close()
        except (ownership_registry.RegistryError,OSError,ValueError) as exc:
            code='host-registry-capacity' if type(exc) is ownership_registry.RegistryCapacityError else 'host-registry-unsafe'
            raise AdmissionError(code,str(exc),registry_error=exc) from None
        check()
    finally:ownership_registry.CURRENT.reset(token)


@contextlib.contextmanager
def existing_admission_lock(path, expected_identity, wait_seconds=0, *, before_registry=None):
    """Admit under an exact existing native lease without changing its bytes.

    This host primitive neither grants operation authority nor interprets guest
    identities. It preserves ordinary reconciliation and terminal gates, requires
    the registry to exist and never creates, truncates, chmods or replaces a lease.
    Execution/carrier and credential contracts must be qualified separately.
    """
    if (type(expected_identity) is not dict or set(expected_identity) != {'device','inode'}
            or any(type(n) is not int or not 1 <= n < 2**64 for n in expected_identity.values())
            or before_registry is not None and not callable(before_registry)):
        raise AdmissionError('resource-policy-invalid')
    expected_identity = dict(expected_identity)
    import registry_maintenance
    with registry_maintenance.existing_lease(path, wait_seconds) as (fd, identity, selected):
        if identity != expected_identity:raise AdmissionError('admission-lock-unavailable')
        with _registry_admission(selected,fd,before_registry=before_registry,
                                 existing_identity=expected_identity) as registry:
            yield registry


@contextlib.contextmanager
def admission_lock(path, wait_seconds=0, *, before_registry=None):
    """Serialize this tool across cooperating processes for one host user.

    flock releases automatically on crash. File stays in place to avoid unlink races.
    This is not a host-wide scheduler; separate users/lock files do not cooperate.
    A trusted host preflight may deny entry before Registry effects; it never
    replaces the original reconciliation, CURRENT context or cleanup path.
    """
    if before_registry is not None and not callable(before_registry):
        raise AdmissionError('resource-policy-invalid', 'before_registry must be callable or null')
    if type(wait_seconds) not in (int, float) or not 0 <= wait_seconds <= 3600:
        raise AdmissionError('resource-policy-invalid', 'lock wait must be between 0 and 3600 seconds')
    path = Path(path).expanduser()
    run_id = _take_holder_run()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            raise AdmissionError('admission-lock-insecure')
        handle = path.open('a+')
    except OSError as exc:
        raise AdmissionError('admission-lock-unavailable', str(exc)) from None
    with handle:
        try:
            os.chmod(path, 0o600)
        except OSError as exc:
            raise AdmissionError('admission-lock-unavailable', str(exc)) from None
        if wait_seconds:
            try:
                _queued_flock(handle.fileno(), wait_seconds)
            except AdmissionError as exc:
                _name_holder(exc, path, handle.fileno())
                raise
        else:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise _name_holder(AdmissionError('host-admission-busy'), path, handle.fileno()) from None
            except OSError as exc:
                raise AdmissionError('admission-lock-unavailable', str(exc)) from None
        try:
            if before_registry is not None:
                before_registry(lease_fd=handle.fileno(), lock_path=path.absolute(),
                                registry_root=Path(str(path.absolute())+'.registry'))
            lease = {'handle': handle, 'started': time.time(), 'run_id': run_id}
            try:
                handle.seek(0)
                handle.truncate()
                handle.write(_holder_line(lease['started'], run_id))
                handle.flush()
            except OSError as exc:
                raise AdmissionError('admission-lock-unavailable', str(exc)) from None
            # Only a lease whose record this process wrote is rewritten in place later.
            with _holder_guard:
                _holder_leases.append(lease)
            with _registry_admission(path.absolute(),handle.fileno()) as registry:
                yield registry
        finally:
            with _holder_guard:
                _holder_leases[:] = [entry for entry in _holder_leases if entry['handle'] is not handle]
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
