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
        if path.is_symlink():
            raise resources.AdmissionError('admission-lock-insecure')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        _check_lock(fd, path)
        if wait_seconds:
            resources._queued_flock(fd, wait_seconds)
        else:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise resources.AdmissionError('host-admission-busy') from None
        locked = True
        identity = _check_lock(fd, path)
        yield fd, identity, path
    except OSError as exc:
        raise resources.AdmissionError('admission-lock-unavailable', str(exc)) from None
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
    with diagnostics.operation('directory_create', mutating=True):
        path.mkdir(mode=0o700)  # Must be new; never overwrite an old receipt directory.
    return path


@diagnostics.scoped('recovery_receipt')
def _publish(directory, report):
    controls.atomic(directory / 'recovery.json', report)
    with diagnostics.operation('directory_open'):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with diagnostics.operation('directory_fsync', mutating=True):os.fsync(fd)
    finally:os.close(fd)
    # Persist creation of the new receipt directory before recovery effects.
    with diagnostics.operation('directory_open'):
        fd = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with diagnostics.operation('directory_fsync', mutating=True):os.fsync(fd)
    finally:os.close(fd)


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
                registry.validate_history(records, quarantine=False)
                report.update(status='OBSERVED', exit_code=0)
            else:
                receipt = _new_receipt_directory(args.output_dir, lease, registry, records)
                report['reconciliation'] = 'not_started'
                with diagnostics.phase('recovery_receipt'):
                    _publish(receipt, report)
                before = {r['launch_id']: r['status'] for r in records}
                report['reconciliation'] = 'attempted'
                try:
                    registry.reconcile()
                    report.update(status='RECONCILED', exit_code=0, reconciliation='completed')
                except KeyboardInterrupt:
                    report.update(status='INTERRUPTED', exit_code=130)
                except Exception as exc:
                    _failure(report, exc)
                # This observation cannot repair or authorize anything. Failure is retained.
                try:
                    after = registry.load()
                    report['after'] = _summary(after)
                    report['transitions'] = [[r['launch_id'], before.get(r['launch_id']), r['status']]
                        for r in after if before.get(r['launch_id']) != r['status']]
                except Exception as exc:
                    report['after_observation'] = 'unavailable'
                    if report['exit_code'] == 0:_failure(report, exc)
                report['finished_at'] = controls.now()
                try:
                    with diagnostics.phase('recovery_receipt'):
                        _publish(receipt, report)
                    report['receipt_persistence'] = 'confirmed'
                except Exception as exc:
                    report['receipt_persistence'] = 'unconfirmed'
                    report['receipt_failure'] = resources.admission_diagnostic(exc)
                    if report['exit_code'] == 0:_failure(report, exc)
    except KeyboardInterrupt:
        report.update(status='INTERRUPTED', exit_code=130)
    except Exception as exc:
        _failure(report, exc)
        if receipt is not None:report['receipt_persistence'] = 'unconfirmed'
    report.setdefault('finished_at', controls.now())
    if receipt is None and not inspect:report['receipt_persistence'] = 'not_started'
    print(json.dumps(report, indent=2))
    return report['exit_code']
