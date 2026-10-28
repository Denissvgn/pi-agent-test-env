"""Fresh, read-only native gates for an already validated legacy owner scope.

An observation is ephemeral operation state, never a receipt or purge credential.
Pure preparation and passive replay do not call this module's observation path.
"""
import copy
import errno
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time

import application_owner_cleanup as cleanup
import application_owner_legacy_protocol as protocol
import ownership_registry as ownership

COMMAND_SECONDS = 15
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_COMMANDS = 4 * 64 + 3


def _argv(argv):
    cleanup.require(type(argv) is list and all(type(item) is str for item in argv))
    if argv == ['docker', 'info', '--format', '{{.ID}}']:return
    if len(argv) == 6 and argv[:5] == ['docker', 'container', 'inspect', '--format', '{{.Id}}']:
        cleanup.require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', argv[-1]) is not None); return
    cleanup.require(len(argv) in (7, 9) and argv[:6] == ['docker', 'ps', '--all', '--quiet', '--no-trunc', '--filter'])
    filters = [argv[6]]
    if len(argv) == 9:cleanup.require(argv[7] == '--filter'); filters.append(argv[8])
    for item in filters:
        launch = 'label=' + ownership.LABEL + '='; registry = 'label=' + ownership.REGISTRY_LABEL + '='
        cleanup.require((item.startswith(launch) and cleanup.controls.valid_id(item[len(launch):]))
            or (item.startswith(registry) and re.fullmatch('[a-f0-9]{64}', item[len(registry):]) is not None))
    cleanup.require(len(filters) == len(set(filters)))
    if len(filters) == 2:
        cleanup.require(filters[0].startswith(launch) and filters[1].startswith(registry))


def docker(argv):
    """Run only closed metadata commands; bound time, both pipes and child wait."""
    import application_client
    _argv(argv)
    deadline = time.monotonic() + COMMAND_SECONDS
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=application_client._docker_environment(), close_fds=True)
    streams = {'stdout': [], 'stderr': []}; size = 0
    try:
        with selectors.DefaultSelector() as selected:
            for name in streams:
                stream = getattr(process, name); os.set_blocking(stream.fileno(), False)
                selected.register(stream, selectors.EVENT_READ, name)
            while selected.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:raise subprocess.TimeoutExpired(argv, COMMAND_SECONDS)
                events = selected.select(remaining)
                if not events:raise subprocess.TimeoutExpired(argv, COMMAND_SECONDS)
                for key, unused in events:
                    body = os.read(key.fileobj.fileno(), min(65536, MAX_OUTPUT_BYTES - size + 1))
                    if not body:selected.unregister(key.fileobj); continue
                    size += len(body); cleanup.require(size <= MAX_OUTPUT_BYTES, 'inventory_unbounded')
                    streams[key.data].append(body)
        remaining = deadline - time.monotonic()
        if remaining <= 0:raise subprocess.TimeoutExpired(argv, COMMAND_SECONDS)
        process.wait(timeout=remaining)
        return subprocess.CompletedProcess(argv, process.returncode,
            b''.join(streams['stdout']).decode('utf-8'), b''.join(streams['stderr']).decode('utf-8'))
    finally:
        try:
            if process.poll() is None:
                process.kill(); process.wait(timeout=5)
        finally:
            process.stdout.close(); process.stderr.close()


def _lease(registry):
    try:return cleanup.lease_identity(registry)
    except ownership.RegistryError:raise
    except (OSError, ValueError) as error:
        raise ownership.RegistryError('Original owner lease changed', condition='lease_changed', cause=error) from None


def _pids(plan):
    claims = [row['value'] for row in plan['claims'] if row['obligation'] == 'scoped_writers'
              and row['class'] in ('original', 'derived')]
    cleanup.require(len(claims) == 1 and claims[0]['wait_confirmed'] is True)
    controllers = [row['value'] for row in plan['claims'] if row['obligation'] == 'controller_execution'
                   and row['class'] in ('original', 'derived')]
    cleanup.require(len(controllers) == 1)
    # The bound supervisor can still write retained metadata, even though its
    # child's actual wait does not claim an individual OS wait for the supervisor.
    return sorted({*claims[0]['pids'], controllers[0]['parent_pid']})


def _processes(pids):
    for pid in pids:
        try:os.kill(pid, 0)
        except ProcessLookupError as error:
            cleanup.require(error.errno == errno.ESRCH, 'writer_observation_failed')
        except OSError as error:
            raise ownership.RegistryError('Owned writer identity is not quiescent',
                                          condition='writer_observation_failed', cause=error) from None
        else:cleanup.require(False, 'owner_writer_pending')


def _holders(records, related, plan):
    protected = plan['retained_roots'] + [row['path'] for row in plan['roots'] + plan['metadata']]
    aliases = {}
    def resolve(value):
        try:resolved = str(cleanup.path(value).resolve(strict=False))
        except (OSError, RuntimeError) as error:
            raise ownership.RegistryError('Owner holder scope is unknown', condition='owner_scope_unsupported', cause=error) from None
        aliases[value] = resolved; return Path(resolved)
    scopes = {resolve(value) for value in protected}
    selected = {row['launch_id'] for row in related}
    for row in records:
        if row['launch_id'] in selected or row['status'] == 'released':continue
        values = ([row['runroot']] if row.get('runroot') is not None else []) + [mount['source'] for mount in row['mounts']]
        if not values:
            cleanup.require(row.get('kind') == 'network', 'owner_scope_unsupported'); continue
        for value in values:
            candidate = resolve(value)
            cleanup.require(not any(candidate == target or candidate in target.parents or target in candidate.parents
                                    for target in scopes), 'owner_writer_pending')
    return aliases


def _call(registry, argv, counter):
    _argv(argv); counter[0] += 1; cleanup.require(counter[0] <= MAX_COMMANDS, 'inventory_unbounded')
    runner = registry.command
    if runner is ownership.docker or runner is cleanup._owner_docker:runner = docker
    with cleanup.diagnostics.operation('daemon_info' if argv[1] == 'info' else 'container_inspect'):
        reply = runner(argv)
    cleanup.require(type(reply.returncode) is int and type(reply.stdout) is str and type(reply.stderr) is str,
                    'writer_observation_failed')
    cleanup.require(len(reply.stdout.encode()) + len(reply.stderr.encode()) <= MAX_OUTPUT_BYTES, 'inventory_unbounded')
    return reply


def _daemon(registry, record, counter):
    reply = _call(registry, ['docker', 'info', '--format', '{{.ID}}'], counter)
    cleanup.require(reply.returncode == 0 and reply.stdout.strip() == record['daemon'] and not reply.stderr.strip(), 'daemon_changed')


def _resources(registry, record, related, plan, records, counter):
    physical = plan['physical']
    cleanup.require(sorted(row['launch_id'] for row in physical) == sorted(row['launch_id'] for row in related))
    ids = [row.get('container_id') for row in physical]
    cleanup.require(all(type(cid) is str and re.fullmatch('[a-f0-9]{64}', cid) and cid != '0' * 64 for cid in ids)
                    and len(set(ids)) == len(ids), 'owner_identity_required')
    _daemon(registry, record, counter)
    for row in physical:
        for target in (row['container_id'], row['container']):
            reply = _call(registry, ['docker', 'container', 'inspect', '--format', '{{.Id}}', target], counter)
            cleanup.require(cleanup._exact_absent(reply, target) and not reply.stdout.strip(), 'writer_absence_unconfirmed')
        launch = 'label=' + ownership.LABEL + '=' + row['launch_id']
        own = 'label=' + ownership.REGISTRY_LABEL + '=' + registry.registry_id
        for filters in (['--filter', launch], ['--filter', launch, '--filter', own]):
            reply = _call(registry, ['docker', 'ps', '--all', '--quiet', '--no-trunc'] + filters, counter)
            cleanup.require(reply.returncode == 0 and not reply.stdout.strip() and not reply.stderr.strip(), 'writer_absence_unconfirmed')
    reply = _call(registry, ['docker', 'ps', '--all', '--quiet', '--no-trunc', '--filter',
                            'label=' + ownership.REGISTRY_LABEL + '=' + registry.registry_id], counter)
    cleanup.require(reply.returncode == 0 and not reply.stderr.strip(), 'writer_absence_unconfirmed')
    listed = reply.stdout.splitlines()
    cleanup.require(len(listed) <= ownership.MAX_RECORDS and len(listed) == len(set(listed))
                    and all(re.fullmatch('[a-f0-9]{64}', cid) and cid != '0' * 64 for cid in listed), 'ownership_mismatch')
    by_cid = {}
    for row in records:
        if row.get('container_id') and row.get('kind', 'container') == 'container':
            by_cid.setdefault(row['container_id'], []).append(row)
    for cid in listed:
        rows = by_cid.get(cid, [])
        cleanup.require(len(rows) == 1 and rows[0]['status'] != 'released' and rows[0].get('daemon') == record['daemon'], 'ownership_mismatch')


def _records(records):
    return sorted(records, key=lambda row: row['launch_id'])


@cleanup.diagnostics.scoped('owner_legacy_scope', 'writer_observation_failed')
def observe(registry, request, *, reader=None, expected=None):
    """Recompute every predicate under the original lease; never consume a PASS."""
    request = copy.deepcopy(request)
    lease = _lease(registry); protocol.request_shape(request)
    reader = cleanup.Reader() if reader is None else reader
    held = {}
    def hold(value):
        name = str(value)
        if name in held:return cleanup.identity(os.fstat(held[name]))
        fd = cleanup.directory(cleanup.path(name)); held[name] = fd
        if name == str(registry.root):cleanup.require(not stat.S_IMODE(os.fstat(fd).st_mode) & 0o077, 'unsafe_path')
        return cleanup.identity(os.fstat(fd))
    def directories():
        result = {}
        for name, fd in held.items():
            named = cleanup.directory(cleanup.path(name))
            try:
                if name == str(registry.root):
                    cleanup.require(not stat.S_IMODE(os.fstat(named).st_mode) & 0o077, 'unsafe_path')
                result[name] = cleanup.identity(os.fstat(named))
                cleanup.require(result[name] == cleanup.identity(os.fstat(fd)), 'sensitive_identity_mismatch')
            finally:os.close(named)
        return result
    try:
        hold(registry.root)
        records = _records(registry.load())
        record, related, plan = protocol._plan(registry, request, reader, current=records)
        for name in plan['retained_roots']:hold(name)
        identities = directories(); aliases = _holders(records, related, plan)
        commitment = {'request': request, 'lease': lease, 'records': records, 'directories': identities,
                      'aliases': aliases, 'metadata': plan['metadata'], 'roots': plan['roots'], 'writer_pids': _pids(plan)}
        if expected is not None:cleanup.require(cleanup.canonical(commitment) == cleanup.canonical(expected['commitment']))
        _processes(_pids(plan)); counter = [0]
        _resources(registry, record, related, plan, records, counter)
        _daemon(registry, record, counter)
        cleanup.require(cleanup.canonical(_lease(registry)) == cleanup.canonical(lease), 'lease_changed')
        cleanup.require(directories() == identities, 'sensitive_identity_mismatch')
        current = _records(registry.load())
        cleanup.require(cleanup.canonical(current) == cleanup.canonical(records), 'cleanup_proof_invalid')
        unused, unused, repeated = protocol._plan(registry, request, reader, current=current)
        cleanup.require(repeated['metadata'] == plan['metadata'] and repeated['roots'] == plan['roots']
                        and repeated['retained_roots'] == plan['retained_roots'] and _pids(repeated) == _pids(plan))
        cleanup.require(_holders(current, related, repeated) == aliases, 'owner_scope_unsupported')
        cleanup.require(directories() == identities, 'sensitive_identity_mismatch')
        _processes(_pids(repeated))
        cleanup.require(cleanup.canonical(_lease(registry)) == cleanup.canonical(lease), 'lease_changed')
        return {'record': record, 'related': related, 'plan': plan, 'reader': reader, 'lease': lease,
                'commitment': copy.deepcopy(commitment), 'native_metadata_commands': counter[0]}
    finally:
        for fd in held.values():os.close(fd)
