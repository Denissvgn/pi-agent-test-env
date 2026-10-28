"""Closed retained metadata and authority classification; never a secret scan.

Unknown files remain untouched and unsupported. An eligible metadata plan is
neither cleanup acceptance nor permission for native participant dispatch.
"""
import os
from pathlib import Path
import re
import stat

import application_owner_cleanup as cleanup
import application_owner_legacy as legacy
import application_owner_legacy_roots as roots
import application_owner_legacy_controller as controller

AUTHORITY_FIELDS = frozenset({'schema', 'document_type', 'registry', 'generation', 'launch_id',
                              'binding', 'issued_contexts', 'external_authority', 'producer'})
RESULT_FIELDS = frozenset({'schema', 'status', 'sealed', 'cleanup_confirmed', 'safe_to_continue', 'qualification_eligible'})


def _require(value, condition='owner_scope_unsupported'):
    legacy.require(value, condition)


def _fact(result, name, value):
    legacy._set_claim(result, name, value, classification='derived', component='namespace',
                      roles=['authority', 'producer', 'source_binding'], rule_id='retained_namespace_v1')


def _read(reader, path):
    return reader.read(path, private=True)


def _authority(components, evidence, record):
    value = components['namespace']['authority']; declaration = evidence['namespace']['originals']
    control = evidence['controller']['originals']
    _require(declaration['producer'] == control['producer'] and declaration['source_binding'] == control['source_binding'])
    cleanup.exact(value, AUTHORITY_FIELDS)
    _require(type(value['schema']) is int and value['schema'] == 1
             and value['document_type'] == 'source_bound_authority_observation')
    _require(all(value[k] == record[k] for k in ('registry', 'generation', 'launch_id'))
             and cleanup.canonical(value['binding']) == cleanup.canonical(record['binding'])
             and value['producer'] == control['producer'])
    _require(value['external_authority'] == 'none_issued' and value['issued_contexts'] == [])
    return {'state': 'none_issued', 'contexts': []}


def _stage_metadata(reader, root, record, identity):
    stages = root / 'stages'; descriptors = []; known = []
    try:fd = cleanup.directory(stages)
    except FileNotFoundError:return descriptors, known
    try:
        names = sorted(os.listdir(fd)); _require(len(names) <= 256, 'inventory_unbounded')
        for stage_id in names:
            _require(cleanup.controls.valid_id(stage_id))
            path = stages / stage_id / 'descriptor.json'; body, ref = _read(reader, path)
            _require(set(body) in (roots.DESCRIPTOR, roots.RETAINED_DESCRIPTOR))
            _require(type(body['schema']) is int and body['schema'] == 2 and body['stage_id'] == stage_id
                     and body['kind'] in ('agent', 'check', 'probe', 'preflight', 'boundary', 'browser'))
            _require(body['workspace'] == str(root / 'workspace') and body['workspace_identity'] == identity
                     and all(body[k] == record['binding'].get(k) for k in ('run_id', 'attempt_id')))
            _require(type(body['label']) is str and re.fullmatch('[A-Za-z0-9_-]{1,128}', body['label']))
            if 'document_type' in body:
                _require(body['document_type'] == 'stage' and body['control'] == str(root / 'controls' / stage_id)
                         and body['inbox'] == str(root / 'controls' / stage_id / 'inbox')
                         and body['outbox'] == str(root / 'controls' / stage_id / 'outbox'))
                if body['admission_lock_file'] is not None:cleanup.path(body['admission_lock_file'])
                _require(body['segment_id'] is None or cleanup.controls.valid_id(body['segment_id']))
                runtime = cleanup.path(body['runtime'])
                _require(runtime == root / 'children' / '.pi-lab' or root / 'children' / '.pi-lab' in runtime.parents)
                _require(type(body['container']) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', body['container']))
                paths = body['protected_paths']; _require(type(paths) is list and len(paths) <= cleanup.MAX_ENTRIES)
                for value in paths:
                    _require(type(value) is str and value and not Path(value).is_absolute() and '..' not in Path(value).parts
                             and not any(ord(c) < 32 or ord(c) == 127 for c in value))
                limits = body['original_limits']; ceilings = {**cleanup.controls.LIMIT_MAX, **cleanup.controls.NATIVE_LIMIT_MAX}
                _require(type(limits) is dict and set(limits) <= set(ceilings))
                _require(all(legacy.integer(value, 0 if key.startswith('reporting_reserve') else 1, ceilings[key])
                             for key, value in limits.items()))
            known.append(ref); descriptors.append((stage_id, body))
            state, ref = _read(reader, stages / stage_id / 'state.json'); known.append(ref)
            _require(set(state) in ({'schema', 'status', 'cleanup_confirmed'}, {'schema', 'status', 'cleanup_confirmed', 'revision'}))
            _require(type(state['schema']) is int and state['schema'] == 2
                     and state['status'] in ('prepared', 'pending', 'running', 'finalized', 'blocked')
                     and type(state['cleanup_confirmed']) is bool)
            if 'revision' in state:_require(legacy.integer(state['revision'], 0, 2**31-1))
            if body['kind'] != 'agent':continue
            credential, ref = _read(reader, stages / stage_id / 'application-credentials.json'); known.append(ref)
            _require(set(credential) in ({'schema', 'status', 'workspace'}, {'schema', 'status', 'workspace', 'references'}))
            _require(type(credential['schema']) is int and credential['schema'] == 1
                     and credential['status'] in ('cleanup_unconfirmed', 'removed', 'not_issued')
                     and credential['workspace'] in ('quarantined', 'discarded', 'clean')
                     and credential.get('references', []) == [])
            process, ref = _read(reader, root / body['label'] / 'process.json'); known.append(ref)
            _require(set(process) in ({'cleanup_confirmed'}, {'cleanup_confirmed', 'application_helper_cleanup'}))
            _require(type(process['cleanup_confirmed']) is bool)
            if 'application_helper_cleanup' in process:
                item = process['application_helper_cleanup']; cleanup.exact(item, {'status', 'safe_to_continue'})
                _require(item['status'] in ('cleanup_unconfirmed', 'removed') and type(item['safe_to_continue']) is bool)
    finally:os.close(fd)
    return descriptors, known


def _controls(root, descriptors):
    """None-issued profile permits known empty queues, not hidden contexts."""
    folder = root / 'controls'
    try:fd = cleanup.directory(folder)
    except FileNotFoundError:return set()
    allowed = {stage_id for stage_id, body in descriptors}
    recognized = {folder}
    try:
        stages = os.listdir(fd); _require(len(stages) <= 256, 'inventory_unbounded')
        for name in stages:
            _require(name in allowed)
            recognized.add(folder / name)
            child = cleanup.directory(folder / name)
            try:
                leaves = os.listdir(child); _require(len(leaves) <= 16, 'inventory_unbounded')
                for leaf in leaves:
                    _require(leaf in ('segments', 'inbox', 'outbox'))
                    recognized.add(folder / name / leaf)
                    queue = cleanup.directory(folder / name / leaf)
                    try:_require(not os.listdir(queue))
                    finally:os.close(queue)
            finally:os.close(child)
    finally:os.close(fd)
    return recognized


def _scan(reader, root, discard, known, *, counter=None, allowed_dirs=()):
    """FD-bound namespace inventory; inspect metadata only, never payloads."""
    known = {Path(ref['path']) for ref in known}; skipped = {Path(v['path']) for v in discard}
    count = [0] if counter is None else counter
    allowed_dirs = set(allowed_dirs)
    def walk(fd, path):
        names = sorted(os.listdir(fd)); count[0] += len(names)
        _require(count[0] <= cleanup.MAX_ENTRIES, 'inventory_unbounded')
        for name in names:
            target = path / name
            if target in skipped:continue
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            _require(info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o022, 'unsafe_path')
            if stat.S_ISDIR(info.st_mode):
                # Empty recognized queue directories are meaningful too.
                _require(target in allowed_dirs or any(target in item.parents for item in known | skipped | allowed_dirs))
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    _require(cleanup.identity(os.fstat(child)) == cleanup.identity(info), 'sensitive_identity_mismatch')
                    walk(child, target)
                    _require(cleanup.identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) == cleanup.identity(info), 'sensitive_identity_mismatch')
                finally:os.close(child)
            else:
                _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'unsafe_path')
                _require(target in known)
    fd = cleanup.directory(root)
    try:
        walk(fd, root)
        named = cleanup.directory(root)
        try:_require(cleanup.identity(os.fstat(fd)) == cleanup.identity(os.fstat(named)), 'sensitive_identity_mismatch')
        finally:os.close(named)
    finally:os.close(fd)


def _related(result, related, reader):
    # This family proves an ordinary direct helper, not an arbitrary collection.
    # No proof attachment or source PASS can turn a specialized subtype ordinary.
    for record in related:
        if 'qualification_preworker_cleanup' in record:
            cleanup.ownership.validate_qualification_preworker_cleanup(record,historical_replay=True,reader=reader)
        elif 'qualification_role' in record or 'qualification_service_cleanup' in record:
            cleanup.ownership.validate_qualification_service_cleanup(record,reader=reader)
        for obligation in ('launcher_execution', 'launcher_terminal', 'helper_guard_identity'):
            matches = [c for c in result['claims'] if c['obligation'] == obligation
                and c['class'] in ('original', 'derived') and c['value']['launch_id'] == record['launch_id']]
            if len(matches) != 1:return False
    return True


def _generic(result, components, evidence, request, record, related, reader):
    authority = _authority(components, evidence, record)
    root = cleanup.path(record['runroot']); _require(not request['extra_private_roots'])
    custody = next((c['value'] for c in result['claims'] if c['obligation'] == 'original_root_custody'
                    and c['class'] in ('original', 'derived')), None)
    if custody is None:return
    stages, known = _stage_metadata(reader, root, record, custody['identity'])
    ids = [stage_id for stage_id, body in stages]
    _require(request['stages'] == ids)
    _require((request['shape'] != 'agent' or any(body['kind'] == 'agent' for stage_id, body in stages))
             and (request['shape'] != 'helper_only' or not stages))
    controls = _controls(root, stages)
    target = root / 'result.json'
    try:body, ref = _read(reader, target)
    except FileNotFoundError:pass
    else:
        cleanup.exact(body, RESULT_FIELDS); known.append(ref)
        _require(type(body['schema']) is int and body['schema'] == 1 and body['status'] in ('PASS', 'FAIL', 'BLOCKED')
                 and all(type(body[k]) is bool for k in ('sealed', 'cleanup_confirmed', 'safe_to_continue', 'qualification_eligible')))
    # Previously read roles have their own closed validators. They count as
    # recognized evidence, not permission for an arbitrary uninspected runtime.
    known += reader.scope_references()
    _scan(reader, root, result['roots'], known, allowed_dirs=controls)
    _fact(result, 'stage_scope', ids); _fact(result, 'external_authority', authority)
    if _related(result, related, reader):
        _fact(result, 'related_closure', [cleanup._resource_subject(r) for r in related])
        controller_fact = next((c for c in result['claims'] if c['obligation'] == 'controller_terminal'
                                and c['class'] in ('original', 'derived')), None)
        if controller_fact is not None:
            pids = {controller_fact['value']['pid'], *(row['pid'] for row in result['launchers'])}
            _fact(result, 'scoped_writers', {'pids': sorted(pids), 'wait_confirmed': True})
    protected = reader.scope_references()
    _fact(result, 'protected_metadata', protected)
    _fact(result, 'retained_namespace', {'metadata': protected, 'roots': result['roots']})


def _empty(reader, path):
    parent = cleanup.directory(path.parent)
    try:
        info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        _require(stat.S_ISREG(info.st_mode) and info.st_size == 0, 'owner_scope_unsupported')
        body, ref = reader.read_bytes(path, private=True, maximum=0)
        _require(body == b'')
        return ref
    finally:os.close(parent)


def _probe(value, manifest):
    cleanup.exact(value, {'schema', 'scope', 'write_attempts', 'outcome', 'quarantined', 'process_uid', 'process_gid',
        'artifact_root_identity', 'declared_relative_path', 'body_bytes', 'events', 'events_dropped',
        'payloads_or_error_messages_retained', 'participants', 'inference_calls', 'credentials'})
    _require(type(value['schema']) is int and value['schema'] == 1 and value['scope'] == 'storage_primitive_only'
             and type(value['write_attempts']) is int and value['write_attempts'] == 1
             and value['outcome'] in ('write_returned', 'artifact_unavailable') and type(value['quarantined']) is bool
             and value['declared_relative_path'] == 'outputs/summary.md' and type(value['body_bytes']) is int and value['body_bytes'] == 74
             and type(value['process_uid']) is int and value['process_uid'] == manifest['uid']
             and type(value['process_gid']) is int and value['process_gid'] == manifest['gid']
             and value['payloads_or_error_messages_retained'] is False)
    for field in ('events_dropped', 'participants', 'inference_calls', 'credentials'):
        _require(type(value[field]) is int and value[field] == 0)
    def identity(meta):
        cleanup.exact(meta, {'device', 'inode', 'uid', 'gid', 'mode', 'nlink', 'size', 'kind'})
        _require(all(type(meta[k]) is int and meta[k] >= 0 for k in ('device', 'inode', 'uid', 'gid', 'mode', 'nlink', 'size'))
                 and meta['kind'] in ('directory', 'regular', 'other') and meta['mode'] <= 0o7777)
    identity(value['artifact_root_identity'])
    # These are container-side diagnostic observations, never host root custody.
    events = value['events']; _require(type(events) is list and 1 <= len(events) <= 512)
    for event in events:
        _require(type(event) is dict)
        error = {'error_class', 'errno'} if event.get('event') == 'exception' else set()
        if event.get('kind') == 'frozen_trace':
            cleanup.exact(event, {'kind', 'function', 'event', 'line'} | error)
            _require(event['function'] in ('_write', '_root', '_parent', '_entry', '_identity', '_regular')
                     and event['event'] in ('call', 'line', 'return', 'exception')
                     and legacy.integer(event['line'], 1, 400))
        else:
            extra = {'identity'} if event.get('operation') in ('stat', 'fstat') and event.get('event') == 'returned' else set()
            cleanup.exact(event, {'kind', 'operation', 'event'} | error | extra)
            _require(event['kind'] == 'syscall' and event['operation'] in ('dup', 'mkdir', 'fsync', 'open', 'close', 'fstat', 'stat', 'replace', 'unlink', 'fdopen')
                     and event['event'] in ('before', 'returned', 'exception'))
            if extra:identity(event['identity'])
        if error:_require(event['error_class'] in ('OSError', 'ValueError', 'other')
                          and (event['errno'] is None or type(event['errno']) is int))
    _require(any(e.get('kind') == 'frozen_trace' and e.get('function') == '_write' and e.get('event') == 'return' for e in events))


def _declared_path(source, reference, variable):
    values = controller.source_paths(source, reference)
    _require(values.get('HERE') == Path(reference['path']).parent and variable in values)
    return values[variable]


def _artifact(result, components, evidence, request, record, related, reader):
    original = evidence['controller']['originals']; declarations = evidence['namespace']['originals']
    _require(declarations == {'authority': original['inputs'], 'producer': original['producer'],
                              'source_binding': original['source_binding']} and not request['stages']
             and request['shape'] == 'helper_only' and not request['extra_private_roots'])
    inputs = components['namespace']['authority']
    _require(inputs['document_type'] == 'artifact_diagnostic_public_inputs'
             and inputs['credential_values_read'] is False and inputs['private_leaf_reads_or_hashes'] is False)
    params = controller._source_parameters(components['controller']['producer'], original['producer']); root = params['ROOT']
    _require(result['root_plan']['retained_root'] == str(root))
    witness = components['root']['witness']; manifest = reader.reference(witness['manifest'], private=True)
    _require(evidence['launchers'][0]['originals']['ledger']['path'] == str(root / 'launch-ledger' / 'ledger.json'))
    known = list(reader.scope_references())
    known.append(_empty(reader, root / 'controller.lock'))
    known.append(_empty(reader, Path(evidence['launchers'][0]['originals']['ledger']['path']).parent / 'ledger.lock'))
    probe = witness['probe_observation']
    _require(probe is not None); legacy.reference(probe)
    _require(probe['path'] == str(root / 'probe-observation.json'))
    observation = reader.reference(probe, private=True); _probe(observation, manifest); known.append(probe)
    _require(witness['primitive_outcome'] == observation['outcome'])
    claim_ref = witness['claim']; claim = reader.reference(claim_ref, private=True); known.append(claim_ref)
    claim_root = _declared_path(components['controller']['producer'], original['producer'], 'CLAIM')
    cleanup.exact(claim, {'schema', 'document_type', 'authorization', 'manifest_sha256', 'prior_attempts',
                          'prior_participants', 'qualification_id', 'root'})
    _require(type(claim['schema']) is int and claim['schema'] == 1
             and claim['document_type'] == 'qualification_one_artifact_diagnostic_claim'
             and claim['authorization'] == witness['authorization'] == manifest['authorization']
             and claim['manifest_sha256'] == controller.historical_digest(manifest)
             and claim['qualification_id'] == record['binding']['qualification_id'] and claim['root'] == str(root)
             and type(claim['prior_attempts']) is int and claim['prior_attempts'] == 193
             and type(claim['prior_participants']) is int and claim['prior_participants'] == 9)
    _require(claim_ref['path'] == str(claim_root / 'claim.json'))
    output = _declared_path(components['controller']['supervisor'], original['supervisor'], 'OUT')
    _require(Path(original['start']['path']).parent == output and Path(original['terminal']['path']).parent == output)
    intent, ref = _read(reader, output / 'intent.json'); known.append(ref)
    cleanup.exact(intent, {'schema', 'program', 'inputs', 'source_review', 'wrapper_pid', 'started',
                           'started_wall', 'deadline', 'overall_seconds_max', 'child_reap_reserve_seconds'})
    _require(type(intent['schema']) is int and intent['schema'] == 1 and intent['program'] == original['producer']
             and intent['inputs'] == original['inputs'] and intent['source_review'] == original['source_binding']
             and type(intent['wrapper_pid']) is int and intent['wrapper_pid'] == components['controller']['start']['wrapper_pid']
             and type(intent['overall_seconds_max']) is int and intent['overall_seconds_max'] == 90
             and type(intent['child_reap_reserve_seconds']) is int and intent['child_reap_reserve_seconds'] == 4)
    for key in ('started', 'started_wall', 'deadline'):controller._number(intent[key])
    stdout, ref = _read(reader, output / 'stdout.log'); known.append(ref)
    cleanup.exact(stdout, {'status', 'terminal', 'primitive_outcome', 'container_intents', 'participants'})
    _require(stdout['terminal'] == evidence['root']['originals']['witness'] and stdout['status'] == witness['status']
             and stdout['primitive_outcome'] == witness['primitive_outcome']
             and type(stdout['container_intents']) is int and stdout['container_intents'] == 1
             and type(stdout['participants']) is int and stdout['participants'] == 0)
    known.append(_empty(reader, output / 'stderr.log'))
    tool, ref = reader.read(output / 'root-tool-terminal.json'); known.append(ref)
    cleanup.exact(tool, {'schema', 'status', 'actual_tool_session', 'actual_terminal_chunk', 'actual_tool_exit',
        'supervisor_pid', 'supervisor_terminal_basis', 'individual_supervisor_OS_wait_recorded',
        'diagnostic_host_child_pid', 'diagnostic_host_child_wait_confirmed', 'command_verification'})
    # This later observer's relative locator is informational metadata, not a
    # proof Ref or a path to open. Original proof references remain absolute.
    locator = tool['command_verification']; cleanup.exact(locator, {'path', 'sha256'})
    text = locator['path']
    _require(type(text) is str and 0 < len(text) <= 4096 and str(Path(text)) == text
             and '..' not in Path(text).parts and not any(ord(c) < 32 or ord(c) == 127 for c in text)
             and Path(text).name == Path(original['terminal']['path']).name)
    _require(type(tool['schema']) is int and tool['schema'] == 1 and type(tool['actual_tool_exit']) is int
             and tool['status'] == 'PASS' and tool['actual_tool_exit'] == 0
             and legacy.integer(tool['actual_tool_session'], 0, 2**63-1)
             and type(tool['actual_terminal_chunk']) is str and re.fullmatch('[a-f0-9]{6}', tool['actual_terminal_chunk'])
             and tool['supervisor_terminal_basis'] == 'Root toolsessioncompletion0; individualsupervisorOSwaitnotrecorded'
             and type(tool['supervisor_pid']) is int and tool['supervisor_pid'] == intent['wrapper_pid']
             and type(tool['diagnostic_host_child_pid']) is int and tool['diagnostic_host_child_pid'] == record['owner_pid']
             and tool['diagnostic_host_child_wait_confirmed'] is True
             and tool['individual_supervisor_OS_wait_recorded'] is False
             and tool['command_verification']['sha256'] == original['terminal']['sha256'])
    # This later tool record is classified metadata; it cannot create a POSIX
    # wrapper wait that its own individual-wait field explicitly does not attest.
    count = [0]
    for retained in (root, output, Path(claim_ref['path']).parent):
        _scan(reader, retained, result['roots'], known, counter=count)
    _fact(result, 'stage_scope', [])
    _fact(result, 'external_authority', {'state': 'none_issued', 'contexts': []})
    # Related resource identity/terminal closure remains separate from cwd.
    if all(any(c['obligation'] == 'helper_guard_identity' and c['class'] in ('original', 'derived')
               and c['value']['launch_id'] == row['launch_id'] for c in result['claims']) for row in related):
        _fact(result, 'related_closure', [cleanup._resource_subject(row) for row in related])
    protected = reader.scope_references()
    _fact(result, 'protected_metadata', protected)
    _fact(result, 'retained_namespace', {'metadata': protected, 'roots': result['roots']})


def validate_namespace(result, components, evidence, request, record, related, reader):
    family = legacy.SOURCE_FAMILIES.get(evidence['controller']['originals']['producer']['sha256'])
    if family is None or 'root_plan' not in result:return
    if family['binding_format'] == 'supervised_source_v1':
        _generic(result, components, evidence, request, record, related, reader)
    elif family['binding_format'] == 'artifact_diagnostic_v1':
        _artifact(result, components, evidence, request, record, related, reader)
