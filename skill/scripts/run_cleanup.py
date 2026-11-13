"""What one run left behind in Docker: list it, or remove it under the host lease.

`leftovers` reads Docker and run directories and changes nothing. `cleanup`
removes containers and then networks that carry BOTH the managed label and the
given run id. It selects them by those labels and by Docker ID, never by a name
pattern, and only while it holds the host lease. The ownership registry stays
the authority: admission reconciles it first and cleanup writes no record.
"""
import datetime
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess

import diagnostics
import outcomes
import ownership_registry
import resources
import stage_control as controls

MANAGED = ownership_registry.MANAGED_LABEL
RUN = ownership_registry.RUN_LABEL
NO_RUN = ownership_registry.NO_RUN
DOCKER_SECONDS = 30
STATUS_SECONDS = 5
MAX_ROWS = 4096
MAX_RUN_DIRECTORIES = 4096
MAX_STAGES = 256


class CleanupError(ValueError):
    """A blocker with a stable reason; the common failure path prints it."""
    def __init__(self, message, reason, remedy=''):
        super().__init__(message)
        self.reason = reason
        self.remedy = remedy


class DockerUnavailable(Exception):
    """Docker could not be asked, or answered in a form that is not understood."""


def _docker(arguments, timeout=DOCKER_SECONDS):
    try:
        return subprocess.run(['docker', *arguments], capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise DockerUnavailable(type(exc).__name__) from None


def _asked(arguments, timeout=DOCKER_SECONDS):
    reply = _docker(arguments, timeout)
    if reply.returncode:
        raise DockerUnavailable(diagnostics.first_line(reply.stderr) or 'docker exited ' + str(reply.returncode))
    return reply.stdout


def _blocked(exc):
    reason = diagnostics.classify_docker_error(str(exc))
    return CleanupError('Docker cannot be asked: ' + str(exc), reason, diagnostics.remedy(reason))


def valid_run_id(value):
    return (type(value) is str and value != NO_RUN
            and ownership_registry.run_label(value) == RUN + '=' + value)


def _age(created, now=None):
    """Seconds since Docker's CreatedAt text, or None when it cannot be read."""
    match = re.match(r'(\d{4}-\d\d-\d\d)[ T](\d\d:\d\d:\d\d)(?:\.\d+)?\s*(Z|[+-]\d\d:?\d\d)?', created or '')
    if match is None:
        return None
    zone = (match.group(3) or '+0000').replace('Z', '+0000').replace(':', '')
    try:
        moment = datetime.datetime.strptime(match.group(1) + ' ' + match.group(2) + ' ' + zone, '%Y-%m-%d %H:%M:%S %z')
    except ValueError:
        return None
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return max(0, int((now - moment).total_seconds()))


def _filters(run_id, managed):
    result = ['--filter', 'label=' + MANAGED + '=1'] if managed else []
    return result + ['--filter', 'label=' + RUN + ('=' + run_id if run_id else '')]


def labelled(kind, run_id=None, managed=False, timeout=DOCKER_SECONDS):
    """Containers or networks that carry the run label, as Docker reports them.

    The daemon's filter narrows the listing; each row's own labels decide.
    """
    columns = ['{{.ID}}', '{{.Names}}' if kind == 'container' else '{{.Name}}',
               '{{.State}}' if kind == 'container' else '', '{{.CreatedAt}}',
               '{{.Label "' + MANAGED + '"}}', '{{.Label "' + RUN + '"}}']
    listing = ['ps', '-a'] if kind == 'container' else ['network', 'ls']
    output = _asked(listing + ['--no-trunc', *_filters(run_id, managed), '--format', '\t'.join(columns)], timeout)
    rows = []
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split('\t')
        parts += [''] * (len(columns) - len(parts))  # absent trailing labels
        if len(parts) != len(columns) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', parts[0]):
            raise DockerUnavailable('unexpected ' + kind + ' listing')
        row = {'kind': kind, 'id': parts[0], 'name': parts[1], 'state': parts[2] or None,
               'created': parts[3], 'age_seconds': _age(parts[3]), 'run_id': parts[5],
               'managed': parts[4] == '1'}
        if not row['run_id'] or (run_id and row['run_id'] != run_id) or (managed and not row['managed']):
            continue
        rows.append(row)
        if len(rows) > MAX_ROWS:
            raise DockerUnavailable('unbounded ' + kind + ' listing')
    return rows


def _resources(run_id=None, managed=False, timeout=DOCKER_SECONDS):
    return labelled('container', run_id, managed, timeout) + labelled('network', run_id, managed, timeout)


def run_identity(root):
    """The run id a run directory records, or None."""
    try:
        value = controls.read(Path(root) / 'identity.json')
    except (OSError, ValueError, controls.ControlError):
        return None
    run_id = value.get('run_id') if isinstance(value, dict) else None
    return run_id if valid_run_id(run_id) else None


def run_directories(results_dir):
    """Run id -> directory, for the run directories directly inside results_dir."""
    index = {}
    try:
        entries = sorted(Path(results_dir).expanduser().iterdir())
    except OSError:
        return index
    for entry in entries[:MAX_RUN_DIRECTORIES]:
        if entry.is_symlink() or not entry.is_dir():
            continue
        run_id = run_identity(entry)
        if run_id:
            index.setdefault(run_id, entry.resolve())
    return index


def find_run(value, results_dir):
    """(run id, run directory or None) from a run id or a run directory."""
    path = Path(value).expanduser()
    if path.is_dir():
        root = path.resolve()
        run_id = run_identity(root)
        if run_id is None:
            raise CleanupError('Not a run directory (no readable identity.json): ' + str(root), 'run-not-found',
                               'Pass the run id or the run directory that `run` reported as evidence.')
        return run_id, root
    if not valid_run_id(value):
        raise CleanupError('--run takes a run id or an existing run directory', 'run-not-found',
                           'Pass the run id or the run directory that `run` reported as evidence.')
    direct = Path(results_dir).expanduser() / value
    if not direct.is_symlink() and direct.is_dir() and run_identity(direct) == value:
        return value, direct.resolve()
    return value, run_directories(results_dir).get(value)


def recorded_leases(root):
    """Lease files the run's stages recorded at admission; empty before the first stage."""
    found = set()
    try:
        folders = sorted((Path(root) / 'stages').iterdir())[:MAX_STAGES]
    except OSError:
        return found
    for folder in folders:
        try:
            value = controls.read(folder / 'descriptor.json')
        except (OSError, ValueError, controls.ControlError):
            continue
        lease = value.get('admission_lock_file') if isinstance(value, dict) else None
        if isinstance(lease, str) and os.path.isabs(lease):
            found.add(lease)
    return found


def lease_held(path):
    """True while an operation holds this lease, False when none does, None when unknown.

    A momentary shared, non-blocking probe on a read-only descriptor: nothing is
    created, written or replaced. A missing lease file has no holder.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return False
    except OSError:
        return None
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        except OSError:
            return None
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


def sealed(root):
    return (Path(root) / 'result.json').exists()


def run_state(root, fallback_lease):
    """`sealed`, `supervisor_gone`, `active` or `unknown` for one run directory.

    A supervisor holds its host lease from admission until its stages are done,
    so a free lease means no supervisor is left for an unsealed run.
    """
    if sealed(root):
        return 'sealed'
    held = [lease_held(path) for path in sorted(recorded_leases(root) or {str(fallback_lease)})]
    if any(value is True for value in held):
        return 'active'
    return 'unknown' if any(value is None for value in held) else 'supervisor_gone'


def _lease_path(value):
    return Path(value).expanduser().absolute()


def observe(run_id, root, results_dir, lock_file):
    """Classify every labelled resource; read-only."""
    known = {run_id: root} if run_id and root is not None else {}
    if not run_id:
        known = run_directories(results_dir)
    states = {}
    result = {'leftovers': [], 'unclassified': [], 'active_resources': 0}
    for row in _resources(run_id):
        folder = known.get(row['run_id'])
        if row['run_id'] == NO_RUN:
            result['unclassified'].append({**row, 'reason': 'no_run'})
        elif folder is None:
            result['unclassified'].append({**row, 'reason': 'run_directory_not_found'})
        else:
            if row['run_id'] not in states:
                states[row['run_id']] = run_state(folder, _lease_path(lock_file))
            state = states[row['run_id']]
            if state == 'active':
                result['active_resources'] += 1
            elif state == 'unknown':
                result['unclassified'].append({**row, 'reason': 'lease_unreadable'})
            else:
                result['leftovers'].append({**row, 'run_state': state, 'run_dir': str(folder)})
    return result


def _describe(row):
    age = 'age unknown' if row['age_seconds'] is None else 'age ' + str(row['age_seconds']) + 's'
    state = row['state'] or '-'
    return f"{row['kind']:<9} {row['name']}  {state}  {age}  run {row['run_id']}"


def cmd_leftovers(args):
    run_id, root = find_run(args.run, args.results_dir) if args.run else (None, None)
    try:
        observed = observe(run_id, root, args.results_dir, args.lock_file)
    except DockerUnavailable as exc:
        raise _blocked(exc) from None
    report = {'schema': 1, 'document_type': 'run_leftovers', 'status': 'OBSERVED', 'exit_code': 0,
              'run_id': run_id, 'run_dir': str(root) if root is not None else None,
              'results_dir': str(Path(args.results_dir).expanduser()), **observed,
              'scope': 'Read-only: Docker listings by run label and run directories; nothing was changed'}
    if args.json:
        print(json.dumps(report, indent=2))
        return 0
    out = ['=== RUN LEFTOVERS ===']
    for row in report['leftovers']:
        suffix = '' if row['managed'] else '; not managed, cleanup leaves it'
        out.append(_describe(row) + f" ({row['run_state']}{suffix})")
    if not report['leftovers']:
        out.append('No leftovers' + (f' for run {run_id}.' if run_id else '.'))
    for row in report['unclassified']:
        out.append('Not classified: ' + _describe(row) + f" ({row['reason']})")
    if report['active_resources']:
        out.append(f"{report['active_resources']} resource(s) of active runs are not listed.")
    out.append('Nothing was changed.')
    print('\n'.join(out))
    return 0


def _finalize(root, removed):
    """Seal an unsealed attempt whose supervisor is gone; it never ends as a pass.

    Caller holds the host lease and has confirmed that no labelled resource remains.
    """
    if sealed(root):
        return {'action': 'already_sealed'}
    try:
        record = controls.read(root / 'summary.json')
    except FileNotFoundError:
        return {'action': 'not_applicable', 'reason': 'no_attempt_record'}
    except (OSError, ValueError, controls.ControlError):
        return {'action': 'failed', 'reason': 'attempt_record_unreadable'}
    if not isinstance(record, dict) or record.get('document_type') != 'run_result' or record.get('schema') != 2:
        return {'action': 'not_applicable', 'reason': 'no_attempt_record'}
    if record.get('experiment_id') or record.get('trial_id'):
        # The experiment controller owns its attempts; experiment-resume reconciles them.
        return {'action': 'deferred', 'reason': 'experiment_attempt'}
    try:
        attempt = outcomes.Attempt.attach_unsealed(root, record)
        record = attempt.record
        record['controller_interruption'] = {
            'kind': 'controller_lost', 'scope': 'supervisor absent under the host lease; finalized by cleanup',
            'cleanup_confirmed': True, 'observations': removed, 'reconciled_at': controls.now()}
        record['infrastructure'].update(status='failed', reason='controller_lost')
        if record['termination']['reason'] in ('not_started', 'completed'):
            record['termination'].update(reason='process_error', trigger='controller_lost')
        if record['scoring']['status'] in ('not_started', 'running'):
            record['scoring'].update(status='error' if record['scoring']['status'] == 'running' else 'skipped',
                                     reason='controller_lost')
            record['task_result'].update(status='unknown', score=None, test_counts=None)
        if outcomes.status(record)[0] == 'PASS':
            return {'action': 'failed', 'reason': 'attempt_record_inconsistent'}
        result = attempt.finalize()
    except (OSError, ValueError, KeyError, TypeError, controls.ControlError):
        return {'action': 'failed', 'reason': 'attempt_finalization_failed'}
    return {'action': 'sealed', 'status': result['status'], 'exit_code': result['exit_code']}


def _remove(run_id, targets, report):
    """Containers first, then networks, each by the Docker ID that carried both labels."""
    for row in targets:
        command = ['rm', '-f', row['id']] if row['kind'] == 'container' else ['network', 'rm', row['id']]
        reply = _docker(command)
        entry = {'kind': row['kind'], 'name': row['name'], 'id': row['id']}
        if reply.returncode:
            report['failed'].append({**entry, 'error': diagnostics.first_line(reply.stderr)})
        else:
            report['removed'].append(entry)
    remaining = {'containers': _asked(['ps', '-aq', *_filters(run_id, True)]).split(),
                 'networks': _asked(['network', 'ls', '-q', *_filters(run_id, True)]).split()}
    report['remaining'] = remaining
    return not remaining['containers'] and not remaining['networks']


def _print(report, as_json):
    if as_json:
        print(json.dumps(report, indent=2))
        return
    dry = report['dry_run']
    out = ['=== RUN CLEANUP' + (' (dry run)' if dry else '') + ' ===',
           f"Run: {report['run_id']} ({report['run_dir']})"]
    for row in report['would_remove']:
        out.append(('Would remove ' if dry else 'Selected ') + _describe(row))
    if not report['would_remove']:
        out.append('No container or network carries both the managed label and this run id.')
    for row in report['unmanaged']:
        out.append('Left alone (not managed): ' + _describe(row))
    if dry:
        out.append('Nothing was removed. Repeat with --yes to remove.')
    else:
        for row in report['reconciled']:
            out.append(f"Removed by registry reconciliation: {row['kind']} {row['name']}")
        out.append(f"Removed {len(report['removed'])} by label, failed {len(report['failed'])}; "
                   f"absence {'confirmed' if report['cleanup_confirmed'] else 'NOT confirmed'}.")
        out.append('Run record: ' + report['finalization']['action']
                   + (f" ({report['finalization'].get('status') or report['finalization'].get('reason')})"
                      if len(report['finalization']) > 1 else ''))
        out.append('Receipt: ' + str(Path(report['run_dir']) / 'cleanup.json'))
    print('\n'.join(out))


def cmd_cleanup(args):
    run_id, root = find_run(args.run, args.results_dir)
    if root is None:
        raise CleanupError(f'No run directory for run {run_id} in {args.results_dir}', 'run-not-found',
                           'Pass --results-dir, or pass the run directory itself to --run.')
    lease = _lease_path(args.lock_file)
    other = sorted(path for path in recorded_leases(root) if Path(path) != lease.resolve())
    if other:
        raise CleanupError('This run was admitted under another host lease; cleanup under this one could not '
                           'tell whether its supervisor is still active.', 'cleanup-lease-mismatch',
                           'Repeat with --lock-file ' + other[0])
    report = {'schema': 1, 'document_type': 'run_cleanup', 'run_id': run_id, 'run_dir': str(root),
              'started_at': controls.now(), 'dry_run': not args.yes, 'status': 'RUNNING', 'exit_code': 2,
              'selection': {MANAGED: '1', RUN: run_id}, 'would_remove': [], 'unmanaged': [],
              'reconciled': [], 'removed': [], 'failed': [], 'remaining': None, 'cleanup_confirmed': False,
              'registry_reconciled': False, 'finalization': {'action': 'not_attempted'}}

    def select():
        rows = _resources(run_id)
        report['would_remove'] = [row for row in rows if row['managed']]
        report['unmanaged'] = [row for row in rows if not row['managed']]
        return rows

    if not args.yes:
        # No lease is taken and the registry is not reconciled: a dry run changes nothing.
        if lease_held(lease):
            busy = resources.AdmissionError('host-admission-busy')
            busy._lease_holder = resources.read_holder(lease)  # Named in the failure, as a refused admission is.
            raise busy
        try:
            select()
        except DockerUnavailable as exc:
            raise _blocked(exc) from None
        report.update(status='DRY_RUN', exit_code=0)
        _print(report, args.json)
        return 0
    try:
        before = select()  # what exists before the registry reconciles, for the receipt only
    except DockerUnavailable:
        before = []
    # Admission takes the lease without waiting and reconciles the registry before
    # anything else; a busy lease or an unsafe registry stops here with nothing removed.
    with resources.admission_lock(lease, 0):
        report['registry_reconciled'] = True
        try:
            try:
                present = {row['id'] for row in select()}
                report['reconciled'] = [{'kind': row['kind'], 'name': row['name'], 'id': row['id']}
                                        for row in before if row['id'] not in present]
                report['cleanup_confirmed'] = _remove(run_id, report['would_remove'], report)
            except DockerUnavailable as exc:
                report['docker_error'] = diagnostics.classify_docker_error(str(exc))
            if report['cleanup_confirmed']:
                report['finalization'] = _finalize(root, [
                    *({**row, 'removed_by': 'registry_reconciliation'} for row in report['reconciled']),
                    *({**row, 'removed_by': 'run_label'} for row in report['removed'])])
            complete = report['cleanup_confirmed'] and not report['failed'] and report['finalization']['action'] != 'failed'
            report.update(status='CLEANED' if complete else 'INCOMPLETE', exit_code=0 if complete else 2)
        except KeyboardInterrupt:
            report.update(status='INTERRUPTED', exit_code=130)
        report['finished_at'] = controls.now()
        controls.atomic(root / 'cleanup.json', report)
    _print(report, args.json)
    return report['exit_code']


def status_line(runroot):
    """One status line: how many labelled containers and networks of this run still exist."""
    run_id = run_identity(runroot)
    if run_id is None:
        return 'Labelled Docker Resources: unknown (run identity unavailable)'
    try:
        containers = len(labelled('container', run_id, timeout=STATUS_SECONDS))
        networks = len(labelled('network', run_id, timeout=STATUS_SECONDS))
    except DockerUnavailable:
        return 'Labelled Docker Resources: unknown (Docker cannot be asked)'
    return f'Labelled Docker Resources: {containers} container(s), {networks} network(s) still exist for run {run_id}'


def add_arguments(sub, default_lock, default_results=None):
    for name, help_text in (
        ('leftovers', 'List containers and networks that a finished or abandoned run left behind; read-only'),
        ('cleanup', 'Remove what one run left behind, under the host lease; without --yes it only reports')):
        parser = sub.add_parser(name, help=help_text)
        parser.add_argument('--run', required=name == 'cleanup',
                            help='Run id or run directory' + ('' if name == 'cleanup' else ' (default: every run)'))
        parser.add_argument('--results-dir', default=default_results,
                            help='Where run directories are looked up by run id')
        parser.add_argument('--lock-file', default=default_lock)
        parser.add_argument('--json', action='store_true', help='Print the report as JSON')
        if name == 'cleanup':
            parser.add_argument('--yes', action='store_true', help='Remove; without it nothing is changed')


def command(args):
    if args.results_dir is None:
        raise CleanupError('--results-dir is required', 'run-not-found')
    return cmd_leftovers(args) if args.op == 'leftovers' else cmd_cleanup(args)
