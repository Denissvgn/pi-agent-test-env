"""registry-compact: archive released registry records under the existing lease.

Compaction selects released container, network and builder records that no
pending, quarantined or owner-proof record needs. It appends them to the
owner-only released-archive.jsonl in the registry directory, syncs the archive
and the directory, and only then removes the record files. It never creates the
lease, dispatches Docker or contacts a model.
"""
import json
from pathlib import Path
import sys
import uuid

import ownership_registry
import registry_maintenance as maintenance
import stage_control as controls


def register(subparsers):
    parser = subparsers.add_parser(
        'registry-compact', help='Archive released registry records to free capacity (experimental)')
    parser.add_argument('--dry-run', action='store_true',
                        help='Report what would be archived and change nothing (default: off, which archives and removes the selected records)')
    parser.add_argument('--lock-file', default=_default_lock(),
                        help='Select the existing lease and its registry (default: PI_LAB_LOCK_FILE or shared per-user lease)')
    parser.add_argument('--lock-wait-seconds', type=float, default=0,
                        help='Wait this many seconds for the lease (default: %(default)s, fail if busy)')
    parser.set_defaults(handler=command)


def _default_lock():
    # pi_lab runs as __main__ from the command line; never import it a second time.
    for name in ('pi_lab', '__main__'):
        module = sys.modules.get(name)
        if callable(getattr(module, 'default_lock_file', None)):
            return module.default_lock_file()
    import pi_lab
    return pi_lab.default_lock_file()


def command(args, *, registry_factory=None):
    report = {
        'schema': 1, 'document_type': 'registry_compaction', 'invocation_id': str(uuid.uuid4()),
        'started_at': controls.now(), 'status': 'RUNNING', 'exit_code': 2, 'dry_run': args.dry_run is True,
        'admission_authorized': False, 'new_containers': 0, 'model_requests': 0,
    }
    registry_factory = registry_factory or ownership_registry.Registry
    try:
        with maintenance.existing_lease(args.lock_file, args.lock_wait_seconds) as (fd, identity, lease):
            report['lease'] = identity
            registry = registry_factory(Path(str(lease) + '.registry'), create=False)
            registry.lease_fd = fd
            report['registry_id'] = registry.registry_id
            result = registry.compact(dry_run=args.dry_run is True)
            report.update(
                before={'records': result['before']}, after={'records': result['after']},
                selected=result['selected'], archived=result['archived'],
                already_archived=result['already_archived'], limit=result['limit'],
                warnings=maintenance.capacity_warnings(result['after']),
                status='DRY_RUN' if args.dry_run is True else 'COMPACTED', exit_code=0)
    except KeyboardInterrupt:
        report.update(status='INTERRUPTED', exit_code=130)
    except Exception as exc:
        maintenance._failure(report, exc)
    report['finished_at'] = controls.now()
    print(json.dumps(report, indent=2))
    return report['exit_code']
