"""Pure legacy launcher facts tied to original source, ledger and child receipts.

No witnesses or acceptance records are created. Unknown cwd/ancestry/waits remain
explicit. Original exits and historical intent domains are never regraded.
"""
from pathlib import Path
import os
import re

import application_owner_cleanup as cleanup
import application_owner_legacy as legacy
import application_owner_legacy_controller as controller

START = frozenset({'schema', 'ordinal', 'kind', 'pid', 'started_monotonic', 'started_wall'})
TERMINAL = frozenset({'schema', 'ordinal', 'pid', 'returncode', 'wait_confirmed',
                       'unknown_owned_child', 'failure_class'})
SIMPLE_LEDGER = frozenset({'schema', 'daemon', 'poisoned', 'launches'})
SIMPLE_ROW = frozenset({'launch_id', 'registry', 'generation', 'container', 'image',
                       'container_id', 'intent_sha256', 'pid', 'private_cleanup'})
ARTIFACT_LEDGER = frozenset({'schema', 'daemon', 'daemon_capacity', 'deadline', 'deadline_wall',
    'last_now', 'last_wall', 'launches', 'manifest_sha256', 'poisoned', 'started', 'started_wall'})
ARTIFACT_ROW = frozenset({'cell', 'cleanup_requests', 'container', 'container_id', 'generation',
    'image', 'intent_sha256', 'key', 'launch_id', 'launch_policy', 'physical', 'pid',
    'private_cleanup', 'registry', 'resources', 'role'})


def _require(value, condition='cleanup_proof_invalid'):
    legacy.require(value, condition)


def historical_intent(record):
    """Preserve the reviewed guard's typed qualification attachment exclusion."""
    excluded = {'status', 'container_id'}
    preworker = 'qualification_preworker_cleanup' in record
    service = ('qualification_service_cleanup' in record or 'qualification_role' in record
               or str(record.get('client_mode', '')).startswith('qualification-'))
    if preworker:
        _require(record.get('application_helper') is True and record.get('client_mode') == 'application-execution'
                 and 'qualification_role' not in record and 'qualification_service_cleanup' not in record)
        excluded |= {'qualification_service_cleanup', 'qualification_preworker_cleanup'}
    elif service:
        # This computes identity, not cleanup acceptance; the existing subtype
        # validator must still validate every specialized proof before eligibility.
        _require(record.get('application_helper') is True
                 and record.get('qualification_role') in ('fixture', 'scripted-inference')
                 and record.get('client_mode') == 'qualification-' + record['qualification_role'])
        excluded |= {'qualification_service_cleanup', 'qualification_preworker_cleanup'}
    elif record.get('application_helper') is True:cleanup.subject(record)
    return controller.historical_digest({k: v for k, v in record.items() if k not in excluded})


def _fact(result, launch_id, obligation, value, classification='derived', reason='incomplete_binding'):
    legacy._set_claim(result, obligation, value, classification=classification,
        component='launchers/' + launch_id, roles=['start', 'terminal', 'ledger', 'producer', 'emitter', 'inputs', 'source_binding'],
        rule_id='source_bound_launcher_v1', launch_id=launch_id, reason=reason)


def _pair(start, terminal, record, *, artifact, metadata=False):
    fields = START if 'parent_pid' not in start else START | {'parent_pid'}
    cleanup.exact(start, fields); cleanup.exact(terminal, TERMINAL)
    _require(type(start['schema']) is int and start['schema'] == 1
             and type(terminal['schema']) is int and terminal['schema'] == 1)
    _require(legacy.integer(start['ordinal'], 1, 4096) and type(terminal['ordinal']) is int
             and terminal['ordinal'] == start['ordinal'] and legacy.integer(start['pid'], 1, 2**31 - 1)
             and type(terminal['pid']) is int and terminal['pid'] == start['pid'])
    if artifact:
        allowed = ('diagnostic_container_cli', 'owned_docker_metadata_or_cleanup_cli') if metadata else ('diagnostic_container_cli',)
        _require(start['kind'] in allowed and 'parent_pid' not in start)
    else:_require(start['kind'] in ('helper_container_cli', 'diagnostic_container_cli'))
    for key in ('started_monotonic', 'started_wall'):controller._number(start[key])
    if 'parent_pid' in start:
        _require(type(start['parent_pid']) is int and start['parent_pid'] == record['owner_pid'])
    _require(type(terminal['wait_confirmed']) is bool and type(terminal['unknown_owned_child']) is bool
             and terminal['failure_class'] in (None, 'cancelled_or_failed'))
    _require(terminal['returncode'] is None or legacy.integer(terminal['returncode'], -255, 255))
    _require(not terminal['wait_confirmed'] or terminal['returncode'] is not None)
    return terminal['wait_confirmed'] and not terminal['unknown_owned_child']


def _row(ledger, record, start, *, artifact):
    cleanup.exact(ledger, ARTIFACT_LEDGER if artifact else SIMPLE_LEDGER)
    _require(type(ledger['schema']) is int and ledger['schema'] == 1
             and ledger['daemon'] == record['daemon'] and type(ledger['poisoned']) is bool)
    rows = ledger['launches']; _require(type(rows) is list and 0 <= len(rows) <= 1)
    ids = []
    for row in rows:
        cleanup.exact(row, ARTIFACT_ROW if artifact else SIMPLE_ROW)
        _require(cleanup.controls.valid_id(row['launch_id'])); ids.append(row['launch_id'])
    _require(len(ids) == len(set(ids)))
    selected = [r for r in rows if r['launch_id'] == record['launch_id']]
    if not selected:return None
    _require(len(selected) == 1); row = selected[0]
    for key in ('launch_id', 'registry', 'generation', 'container', 'image'):_require(row[key] == record[key])
    _require(type(row['pid']) is int and row['pid'] == start['pid'] and type(row['private_cleanup']) is bool)
    if artifact:
        _require(row['role'] == 'application-helper' and row['launch_policy'] == 'explicit_pull_never_owned_id_5s'
                 and type(row['cell']) is str and type(row['key']) is str
                 and type(row['cleanup_requests']) is list and type(row['resources']) is dict
                 and row['physical'] in ('absent', 'live', 'uncertain'))
    expected = historical_intent(record) if artifact else cleanup.subject(record)['intent_sha256']
    _require(row['intent_sha256'] == expected)
    cid = row['container_id']
    _require(type(cid) is str and re.fullmatch('[a-f0-9]{64}', cid) and cid != '0' * 64, 'owner_identity_required')
    _require(record.get('container_id') is None or record['container_id'] == cid, 'owner_identity_required')
    return row


def _direct_command(record):
    # Exact construction of the installed, source-identified direct-run family.
    argv = ['docker', 'run', '--name', record['container'], '--label',
        cleanup.ownership.LABEL + '=' + record['launch_id'], '--label',
        cleanup.ownership.REGISTRY_LABEL + '=' + record['registry']]
    for mount in record['mounts']:
        argv += ['--mount', 'type=bind,src=' + mount['source'] + ',dst=' + mount['target']
                 + (',readonly' if not mount['rw'] else '')]
    return argv + [record['image'], '/opt/pi-application/runtime/application_client_service.py']


def _artifact_command(record, manifest):
    root = Path(record['private_store'])
    base = ['docker', 'run', '--pull=never', '--interactive', '--name', record['container'], '--init',
        '--platform', 'linux/arm64', '--read-only', '--user', str(manifest['uid']) + ':' + str(manifest['gid']),
        '--cap-drop=ALL', '--security-opt=no-new-privileges=true', '--ipc=none', '--pids-limit', '128',
        '--memory', '512m', '--memory-swap', '512m', '--cpus', '1.0', '--network', 'none',
        '--entrypoint=python3', '--workdir=/pi-client/state', '--env', 'PYTHONDONTWRITEBYTECODE=1',
        '--env', 'PYTHONUNBUFFERED=1', '--env', 'HOME=/pi-client/state/private/home',
        '--env', 'TMPDIR=/pi-client/state/private/tmp']
    for leaf, target, readonly in (('code', '/opt/pi-application', True), ('evidence', '/pi-client/evidence', False),
                                    ('state', '/pi-client/state', False)):
        base += ['--mount', 'type=bind,src=' + str(root / leaf) + ',dst=' + target
                 + (',readonly' if readonly else '') + ',bind-recursive=disabled']
    base += [record['image'], '/opt/pi-application/runtime/application_client_service.py']
    _require(manifest['command'] == base)
    # The reviewed client inserts these labels before all original run options.
    # --pull=never already parses as --pull, so the guard adds no further option.
    labels = ['--label', cleanup.ownership.LABEL + '=' + record['launch_id'],
              '--label', cleanup.ownership.REGISTRY_LABEL + '=' + record['registry']]
    return base[:2] + labels + base[2:]


def _controller_confirmed(result, record):
    return any(c['obligation'] == 'controller_terminal' and c['class'] in ('original', 'derived')
               and c['value']['pid'] == record['owner_pid'] and c['value']['wait_confirmed'] is True for c in result['claims'])


def _artifact_children(result, components, evidence, record, reader):
    witness = components['root']['witness']
    if 'process_receipts' not in witness:return
    _require(type(witness.get('schema')) is int and witness['schema'] == 1
             and witness.get('document_type') == 'bounded_artifact_write_diagnostic_terminal')
    declarations = witness['process_receipts']
    _require(type(declarations) is list and 1 <= len(declarations) <= 64)
    original = evidence['launchers'][0]['originals']
    for key, role in (('inputs', 'inputs'), ('source_review', 'source_binding'), ('ledger', 'ledger')):
        controller._ref_equal(witness[key], original[role])
    _require(witness['qualification_id'] == record['binding']['qualification_id']
             and witness['container_id'] == result['physical'][0]['container_id']
             and witness['disposable_root'] == record['private_store'])
    params = controller._source_parameters(components['controller']['producer'], evidence['controller']['originals']['producer'])
    root = params['ROOT']; expected_names = set(); observations = []; container_pairs = []
    for ordinal, declaration in enumerate(declarations, 1):
        cleanup.exact(declaration, {'start', 'terminal'})
        for kind in ('start', 'terminal'):
            legacy.reference(declaration[kind]); name = 'process-%03d-%s.json' % (ordinal, kind)
            _require(declaration[kind]['path'] == str(root / name)); expected_names.add(name)
        start = reader.reference(declaration['start'], private=True)
        terminal = reader.reference(declaration['terminal'], private=True)
        confirmed = _pair(start, terminal, record, artifact=True, metadata=True)
        _require(start['ordinal'] == ordinal and start['pid'] != record['owner_pid'])
        if start['kind'] == 'diagnostic_container_cli':container_pairs.append(declaration)
        observations.append({'pid': start['pid'], 'parent_pid': record['owner_pid'], 'ordinal': ordinal,
            'kind': start['kind'], 'actual_exit': terminal['returncode'], 'wait_confirmed': confirmed,
            'originals': declaration})
    _require(container_pairs == [{'start': original['start'], 'terminal': original['terminal']}])
    # A shortened prefix cannot conceal later receipts left in the same retained
    # source-created namespace. Inspect names only, never private file payloads.
    fd = cleanup.directory(root)
    try:
        names = cleanup._bounded_names(fd, cleanup.MAX_ENTRIES)
        actual = {name for name in names if re.fullmatch(r'process-[0-9]+-(?:start|terminal)\.json', name)}
        _require(actual == expected_names)
        current = cleanup.directory(root)
        try:_require(cleanup.identity(os.fstat(fd)) == cleanup.identity(os.fstat(current)), 'unsafe_path')
        finally:os.close(current)
    finally:os.close(fd)
    _require(witness['all_owned_host_children_waited'] is True and all(o['wait_confirmed'] for o in observations))
    result['owned_processes'] = observations
    legacy._set_claim(result, 'scoped_writers', {'pids': sorted({record['owner_pid'], *(o['pid'] for o in observations)}),
        'wait_confirmed': True}, classification='derived', component='root', roles=['witness'],
        rule_id='source_bound_launcher_v1')


def validate_launchers(result, components, evidence, request, record, related, reader):
    family = legacy.SOURCE_FAMILIES.get(evidence['controller']['originals']['producer']['sha256'])
    if family is None:return
    artifact = family['binding_format'] == 'artifact_diagnostic_v1'
    for row_record, declaration, bodies in zip(related, evidence['launchers'], components['launchers']):
        launch_id = row_record['launch_id']
        # This rule handles ordinary helper launches only. It cannot retype a
        # worker or a specialized service/preworker proof into an ordinary helper.
        if row_record.get('application_helper') is not True or any(k in row_record for k in
                ('qualification_role', 'qualification_service_cleanup', 'qualification_preworker_cleanup')):continue
        if artifact:
            _require(row_record['schema'] == 1 and row_record['client_mode'] == 'application-execution')
        originals = declaration['originals']; control = evidence['controller']['originals']
        for role in ('producer', 'inputs', 'source_binding'):_require(originals[role] == control[role])
        if artifact:_require(originals['emitter'] == control['producer'])
        else:_require(originals['emitter']['sha256'] == family['emitter_sha256'])
        confirmed = _pair(bodies['start'], bodies['terminal'], row_record, artifact=artifact)
        selected = _row(bodies['ledger'], row_record, bodies['start'], artifact=artifact)
        if selected is None:continue
        # A returned PID/ledger match is necessary, but the source-bound owner
        # execution/terminal must also be established before deriving its child.
        if not _controller_confirmed(result, row_record):continue
        if artifact:
            params = controller._source_parameters(bodies['producer'], originals['producer'])
            manifest, unused = reader.read(params['manifest'], private=True)
            argv = _artifact_command(row_record, manifest); cwd = None
        else:
            argv = _direct_command(row_record); cwd = bodies['inputs']['cwd']
        legacy._argv(argv); cleanup.validate_launcher_arguments(argv, row_record)
        execution = {'launch_id': launch_id, 'pid': bodies['start']['pid'], 'parent_pid': row_record['owner_pid'],
                     'ordinal': bodies['start']['ordinal'], 'argv': argv, 'cwd': cwd}
        source_scoped=family.get('execution_rule')=='absolute_owned_host_paths_v1'
        if source_scoped:execution['cwd_rule']=family['execution_rule']
        _fact(result, launch_id, 'launcher_execution', execution, 'candidate' if cwd is None and not source_scoped else 'derived',
              'not_located' if cwd is None else 'incomplete_binding')
        terminal = {'launch_id': launch_id, 'pid': bodies['terminal']['pid'], 'ordinal': bodies['terminal']['ordinal'],
                    'actual_exit': bodies['terminal']['returncode'], 'wait_confirmed': bodies['terminal']['wait_confirmed']}
        _fact(result, launch_id, 'launcher_terminal', terminal, 'original' if confirmed else 'candidate')
        if not artifact and confirmed:
            owner_terminal = next(c['value'] for c in result['claims'] if c['obligation'] == 'controller_terminal')
            # This exact source family maps ordinary completion to 0/2; retain
            # actual signal exits without pretending they were normal returns.
            if owner_terminal['actual_exit'] >= 0:
                _require(owner_terminal['actual_exit'] == (0 if terminal['actual_exit'] == 0 else 2))
        subject = cleanup.subject(row_record)
        _fact(result, launch_id, 'helper_guard_identity', {'launch_id': launch_id,
            'container_id': selected['container_id'], 'intent_sha256': subject['intent_sha256']})
        result['physical'].append({**row_record, 'container_id': selected['container_id']})
        result['launchers'].append({**execution, 'actual_exit': terminal['actual_exit'], 'wait_confirmed': confirmed,
                                   'argv_basis': 'source_bound_post_guard', 'cwd_basis': 'not_located' if cwd is None else 'original_input'})
    if artifact and result['physical'] and _controller_confirmed(result, record):
        _artifact_children(result, components, evidence, record, reader)
