"""Explicit inspection and reconciliation under the existing same-user lease.

Inspection is offline and read-only. Recovery reuses the ordinary reconciliation
predicates and never dispatches a fresh probe, participant, or inference request.
Neither report is an admission credential.
"""
import collections
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import uuid

import ownership_registry
import registry_diagnostics as diagnostics
import resources
import stage_control as controls

MAX_RECEIPT_BYTES = 4 * 1024 * 1024


@diagnostics.observed('directory_open')
def _directory_fd(path):
    """Walk a canonical absolute directory without following any symlink."""
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _identity(info):
    return info.st_dev, info.st_ino


class _Receipt:
    """Hold the selected directory and parent FDs for the entire recovery."""
    def __init__(self, path, parent):
        self.path = path
        self.parent = parent
        self.parent_identity = None
        self.fd = None
        self.identity = None
        self.previous = None

    @classmethod
    def create(cls, path, *, parent_fd=None):
        if parent_fd is not None and type(parent_fd) is not int:
            raise diagnostics.RegistryError('Invalid retained receipt parent', condition='unsafe_path')
        with diagnostics.operation('directory_open'):
            parent = os.dup(parent_fd) if parent_fd is not None else _directory_fd(path.parent)
        receipt = cls(path, parent)
        try:
            receipt.parent_identity = _identity(os.fstat(receipt.parent))
            with diagnostics.operation('directory_create', mutating=True):
                os.mkdir(path.name, mode=0o700, dir_fd=receipt.parent)
            with diagnostics.operation('directory_open'):
                receipt.fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                     dir_fd=receipt.parent)
            receipt.identity = _identity(os.fstat(receipt.fd))
            receipt.verify_namespace()
            if os.listdir(receipt.fd):
                raise diagnostics.RegistryError('Recovery receipt directory is not new', condition='unsafe_path')
            return receipt
        except BaseException:
            receipt.close()
            raise

    def close(self):
        fd, parent = self.fd, self.parent
        self.fd = self.parent = None
        try:
            if fd is not None:os.close(fd)
        finally:
            if parent is not None:os.close(parent)

    @diagnostics.observed('directory_open')
    def verify_namespace(self):
        parent = _directory_fd(self.path.parent)
        try:
            if _identity(os.fstat(parent)) != self.parent_identity:
                raise diagnostics.RegistryError('Recovery receipt parent changed', condition='unsafe_path')
        finally:os.close(parent)
        held = os.fstat(self.fd)
        named = os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False)
        if (not stat.S_ISDIR(named.st_mode) or _identity(named) != self.identity
                or _identity(held) != self.identity or held.st_uid != os.getuid()
                or stat.S_IMODE(held.st_mode) & 0o077):
            raise diagnostics.RegistryError('Recovery receipt directory changed', condition='unsafe_path')

    @diagnostics.observed('proof_read')
    def verify_previous(self):
        try:
            fd = os.open('recovery.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        except FileNotFoundError:
            if self.previous is None:return
            raise
        with os.fdopen(fd, 'rb') as source:
            info = os.fstat(source.fileno())
            if (self.previous is None or not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid() or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > MAX_RECEIPT_BYTES
                    or _identity(info) != self.previous[0]):
                raise diagnostics.RegistryError('Recovery receipt identity changed', condition='unsafe_record')
            body = source.read(MAX_RECEIPT_BYTES + 1)
            after = os.fstat(source.fileno())
        named = os.stat('recovery.json', dir_fd=self.fd, follow_symlinks=False)
        if (len(body) > MAX_RECEIPT_BYTES or hashlib.sha256(body).hexdigest() != self.previous[1]
                or _identity(after) != _identity(named) or after.st_nlink != 1):
            raise diagnostics.RegistryError('Recovery receipt contents changed', condition='unsafe_record')

    def publish(self, report):
        body = (json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode()
        if len(body) > MAX_RECEIPT_BYTES:
            raise diagnostics.RegistryError('Recovery receipt exceeds its bounded limit', condition='inventory_unbounded')
        self.verify_namespace()
        self.verify_previous()
        name = '.recovery.json-' + uuid.uuid4().hex
        primary = None
        try:
            with diagnostics.operation('temporary_create', mutating=True):
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
            with os.fdopen(fd, 'wb') as output:
                with diagnostics.operation('file_write', mutating=True):
                    output.write(body)
                    output.flush()
                with diagnostics.operation('file_fsync', mutating=True):os.fsync(output.fileno())
                identity = _identity(os.fstat(output.fileno()))
            # These checks detect replacement. FD-relative publication also
            # prevents redirection if the namespace changes after the checks.
            self.verify_namespace()
            self.verify_previous()
            with diagnostics.operation('atomic_replace', mutating=True):
                os.replace(name, 'recovery.json', src_dir_fd=self.fd, dst_dir_fd=self.fd)
            self.previous = identity, hashlib.sha256(body).hexdigest()
            self.verify_namespace()
            self.verify_previous()
            with diagnostics.operation('directory_fsync', mutating=True):
                os.fsync(self.fd)
                os.fsync(self.parent)
            self.verify_namespace()
        except BaseException as exc:
            primary = exc
            raise
        finally:
            try:
                with diagnostics.operation('temporary_cleanup', mutating=True):
                    try:os.unlink(name, dir_fd=self.fd)
                    except FileNotFoundError:pass
            except OSError:
                if primary is None:raise


def _runner_identity():
    root = Path(__file__).resolve().parents[1]
    files = {}
    for folder in ('scripts', 'runtime'):
        for path in sorted((root / folder).rglob('*')):
            if path.is_file() and not path.is_symlink() and '__pycache__' not in path.parts:
                files[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def add_arguments(sub, default_lock):
    for name, help_text in (
        ('registry-inspect', 'Read-only offline registry inspection under the existing host lease'),
        ('registry-recover', 'Reconcile prior ownership without dispatch; retain a separate recovery receipt')):
        parser = sub.add_parser(name, help=help_text)
        parser.add_argument('--lock-file', default=default_lock)
        parser.add_argument('--lock-wait-seconds', type=float, default=0)
        if name == 'registry-recover':
            parser.add_argument('--output-dir', required=True, help='New owner-only receipt directory outside all retained execution paths')


def _check_lock(fd, path):
    info = os.fstat(fd)
    named = os.stat(path, follow_symlinks=False)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o077
            or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
        raise resources.AdmissionError('admission-lock-unavailable')
    return {'device': info.st_dev, 'inode': info.st_ino}


@contextlib.contextmanager
def existing_lease(path, wait_seconds=0):
    """No creation, chmod, truncation or replacement, including on a missing lock."""
    if type(wait_seconds) not in (int, float) or not 0 <= wait_seconds <= 3600:
        raise resources.AdmissionError('resource-policy-invalid')
    path = Path(path).expanduser().absolute()
    fd = None
    locked = False
    try:
        try:
            if path.is_symlink():
                raise resources.AdmissionError('admission-lock-insecure')
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            _check_lock(fd, path)
        except OSError as exc:
            raise resources.AdmissionError('admission-lock-unavailable', str(exc)) from None
        if wait_seconds:
            # The queue already classifies flock errors and deliberately lets
            # an existing outer timer's exception propagate unchanged.
            resources._queued_flock(fd, wait_seconds)
        else:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise resources.AdmissionError('host-admission-busy') from None
            except OSError as exc:
                raise resources.AdmissionError('admission-lock-unavailable', str(exc)) from None
        locked = True
        try:identity = _check_lock(fd, path)
        except OSError as exc:
            raise resources.AdmissionError('admission-lock-unavailable', str(exc)) from None
        yield fd, identity, path
    finally:
        if fd is not None:
            try:
                if locked:fcntl.flock(fd, fcntl.LOCK_UN)
            finally:os.close(fd)


def _summary(records):
    return {
        'total': len(records),
        'statuses': dict(sorted(collections.Counter(r['status'] for r in records).items())),
        'application_helpers': sum(r.get('application_helper') is True for r in records),
        'qualification_receipts': sum('qualification_service_cleanup' in r or 'qualification_preworker_cleanup' in r for r in records),
    }


def _failure(report, exc):
    public = resources.admission_diagnostic(exc)
    if public is None:
        # An unexpected maintenance error is never permission to print private data.
        public = resources.admission_diagnostic(resources.AdmissionError('host-registry-unsafe'))
    report.update(status='BLOCKED', exit_code=2,
                  infrastructure={**public, 'error_digest': hashlib.sha256(str(exc).encode()).hexdigest()})


@diagnostics.scoped('recovery_receipt')
def _new_receipt_directory(output, lease, registry, records):
    path = Path(output).expanduser().absolute()
    if path.is_symlink() or '..' in path.parts:
        raise diagnostics.RegistryError('Unsafe recovery receipt path', condition='unsafe_path')
    path = path.parent.resolve(strict=True) / path.name
    protected = [lease.resolve(), registry.root]
    for record in records:
        values = [record.get('runroot'), record.get('private_store'), record.get('gateway_state')]
        values.extend(m['source'] for m in record['mounts'])
        for value in values:
            if value:
                if not isinstance(value, str) or not Path(value).is_absolute():
                    raise diagnostics.RegistryError('Unsafe retained recovery path', condition='unsafe_path')
                protected.append(Path(value).resolve())
    if any(path == root or root in path.parents or path in root.parents for root in protected):
        raise diagnostics.RegistryError('Recovery receipt overlaps retained execution state', condition='unsafe_path')
    return _Receipt.create(path)


@diagnostics.scoped('recovery_receipt')
def _publish(receipt, report):
    receipt.publish(report)


def _interrupt(report, phase):
    report.update(status='INTERRUPTED', exit_code=130, interrupted_phase=phase)


def _recover(registry, receipt, report, records):
    report['reconciliation'] = 'not_started'
    try:
        with diagnostics.phase('recovery_receipt'):_publish(receipt, report)
    except KeyboardInterrupt:
        _interrupt(report, 'initial_receipt_publication')
        raise
    before = {r['launch_id']: r['status'] for r in records}
    report['reconciliation'] = 'attempted'
    try:
        registry.reconcile()
        report.update(status='RECONCILED', exit_code=0, reconciliation='completed')
    except KeyboardInterrupt:
        _interrupt(report, 'reconciliation')
    except Exception as exc:
        _failure(report, exc)
    # Observe once, still under the lease. Interruption here must not skip the
    # terminal receipt or trigger another reconciliation/observation attempt.
    try:
        after = registry.load()
        report['after'] = _summary(after)
        report['transitions'] = [[r['launch_id'], before.get(r['launch_id']), r['status']]
            for r in after if before.get(r['launch_id']) != r['status']]
    except KeyboardInterrupt:
        report['after_observation'] = 'interrupted'
        _interrupt(report, 'after_observation')
    except Exception as exc:
        report['after_observation'] = 'unavailable'
        if report['exit_code'] == 0:_failure(report, exc)
    report['finished_at'] = controls.now()
    try:
        with diagnostics.phase('recovery_receipt'):_publish(receipt, report)
        report['receipt_persistence'] = 'confirmed'
    except KeyboardInterrupt:
        report['receipt_persistence'] = 'unconfirmed'
        _interrupt(report, 'terminal_receipt_publication')
    except Exception as exc:
        report['receipt_persistence'] = 'unconfirmed'
        report['receipt_failure'] = resources.admission_diagnostic(exc)
        if report['exit_code'] == 0:_failure(report, exc)


def command(args, *, registry_factory=None):
    inspect = args.op == 'registry-inspect'
    report = {
        'schema': 1, 'document_type': 'registry_inspection' if inspect else 'registry_recovery',
        'invocation_id': str(uuid.uuid4()), 'started_at': controls.now(),
        'status': 'RUNNING', 'exit_code': 2, 'admission_authorized': False,
        'new_containers': 0, 'participant_stages': 0, 'model_requests': 0,
        'scope': 'offline_read_only' if inspect else 'prior_ownership_reconciliation_only',
    }
    receipt = None
    registry_factory = registry_factory or ownership_registry.Registry
    try:
        with diagnostics.phase('registry_initialization'):
            report['runner_content_sha256'] = _runner_identity()
        with existing_lease(args.lock_file, args.lock_wait_seconds) as (fd, identity, lease):
            report['lease'] = identity
            registry = registry_factory(Path(str(lease) + '.registry'), create=False)
            registry.lease_fd = fd
            report['registry_id'] = registry.registry_id
            records = registry.load()
            report['before'] = _summary(records)
            if inspect:
                report['untested'] = ['daemon_and_writer_observation', 'inference_termination',
                    'sensitive_recovery', 'record_write_and_fsync', 'durable_release']
                # Metadata references are validated launch UUIDs, never private paths.
                report['pending_launch_ids'] = [r['launch_id'] for r in records if r['status'] != 'released']
                report['historical_application_helper_ids'] = [r['launch_id'] for r in records
                    if r['status'] == 'released' and r.get('application_helper') is True]
                import application_owner_cleanup
                report['application_cleanup'] = application_owner_cleanup.inspect_helpers(registry, records)
                registry.validate_history(records, quarantine=False)
                report.update(status='OBSERVED', exit_code=0)
            else:
                receipt = _new_receipt_directory(args.output_dir, lease, registry, records)
                try:
                    _recover(registry, receipt, report, records)
                finally:
                    try:
                        with diagnostics.phase('recovery_receipt'):receipt.close()
                    except Exception as exc:
                        report['receipt_close_failure'] = resources.admission_diagnostic(exc)
                        report['receipt_persistence'] = 'unconfirmed'
                        if report['exit_code'] == 0:_failure(report, exc)
    except KeyboardInterrupt:
        report.update(status='INTERRUPTED', exit_code=130)
        if receipt is not None:report['receipt_persistence'] = 'unconfirmed'
    except Exception as exc:
        _failure(report, exc)
        if receipt is not None:report['receipt_persistence'] = 'unconfirmed'
    report.setdefault('finished_at', controls.now())
    if receipt is None and not inspect:report['receipt_persistence'] = 'not_started'
    print(json.dumps(report, indent=2))
    return report['exit_code']
