"""Closed, bounded metadata validation for explicitly versioned legacy proofs.

This layer never observes processes or Docker, executes original source, writes
files or publishes acceptance. Source-specific facts require an installed rule;
unimplemented or unrecognized premises remain unresolved. A caller cannot add
rules, asserted facts or approval callbacks through evidence.
"""
import copy
import datetime
from pathlib import Path
import re

import application_owner_cleanup as cleanup
import registry_diagnostics as diagnostics

METHOD = 'legacy_derived_v1'
COHORT = 'application_owner_legacy_1'
VARIANTS = frozenset({'standard_workspace_v1', 'diagnostic_disposable_v1'})
REQUEST_FIELDS = frozenset({'schema', 'document_type', 'method', 'subject', 'shape', 'variant',
                            'cohort', 'evidence', 'stages', 'extra_private_roots'})
EVIDENCE_FIELDS = frozenset({'schema', 'document_type', 'produced_at', 'subject', 'variant', 'cohort',
                             'controller', 'launchers', 'root', 'namespace', 'unknowns'})
SUBJECT_FIELDS = frozenset({'registry', 'generation', 'launch_id', 'intent_sha256', 'container_id'})
COMPONENT_FIELDS = frozenset({'rule_id', 'rule_version', 'originals'})
ROLES = {
    'supervised_controller_v1': frozenset({'context', 'start', 'terminal', 'producer', 'supervisor',
                                          'source_binding', 'inputs'}),
    'source_bound_launcher_v1': frozenset({'start', 'terminal', 'ledger', 'producer', 'emitter',
                                          'source_binding', 'inputs'}),
    'standard_workspace_v1': frozenset({'witness'}),
    'diagnostic_disposable_v1': frozenset({'witness'}),
    'retained_namespace_v1': frozenset({'authority', 'producer', 'source_binding'}),
}
BYTE_ROLES = frozenset({'producer', 'supervisor', 'emitter'})
OBLIGATIONS = (
    'subject_identity', 'related_closure', 'controller_execution', 'controller_terminal',
    'launcher_execution', 'launcher_terminal', 'helper_guard_identity', 'original_root_custody',
    'mount_scope', 'stage_scope', 'retained_namespace', 'external_authority', 'protected_metadata',
    'scoped_writers',
)
REASONS = frozenset({'not_located', 'incomplete_binding', 'different_scope', 'unsupported_rule',
                     'contradiction', 'unclassified_namespace'})
PER_LAUNCH = frozenset({'launcher_execution', 'launcher_terminal', 'helper_guard_identity'})
CLAIM_CLASSES = frozenset({'original', 'derived', 'candidate', 'unknown', 'different_scope', 'contradiction'})

# Only reviewed installed identities and functions belong here. Neither catalog
# can be populated by a request, a locator, a source file or an external PASS.
SOURCE_FAMILIES = {}


def _controller(*args):
    from application_owner_legacy_controller import validate_controller
    return validate_controller(*args)


def _launchers(*args):
    from application_owner_legacy_launchers import validate_launchers
    return validate_launchers(*args)


_ADAPTERS = {'controller': _controller, 'launchers': _launchers}


def require(value, condition='cleanup_proof_invalid'):
    cleanup.require(value, condition)


def integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _set_claim(result, obligation, value, *, classification, component, roles,
               rule_id='supervised_controller_v1', launch_id=None, reason='incomplete_binding'):
    """Install one reviewed adapter output; input never supplies this function."""
    def same(claim):
        if claim['obligation'] != obligation:return False
        key = claim['value'].get('launch_id') if obligation in PER_LAUNCH and claim['value'] is not None else None
        return key == launch_id
    result['claims'] = [claim for claim in result['claims'] if not same(claim)]
    result['claims'].append({'obligation': obligation, 'class': classification, 'value': value,
        'provenance': [{'component': component, 'role': role} for role in sorted(set(roles))],
        'rule': {'id': rule_id, 'version': 1} if classification == 'derived' else None})
    result['unresolved'] = [item for item in result['unresolved']
                            if not (item['obligation'] == obligation and item['launch_id'] == launch_id)]
    if classification not in ('original', 'derived'):
        result['unresolved'].append({'obligation': obligation, 'launch_id': launch_id, 'reason': reason})


def reference(value):
    cleanup.exact(value, {'path', 'sha256'}); cleanup.path(value['path'])
    require(type(value['sha256']) is str and re.fullmatch('[a-f0-9]{64}', value['sha256']) is not None)


def timestamp(value):
    require(type(value) is str and len(value) <= 32
            and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z', value))
    try:datetime.datetime.fromisoformat(value[:-1] + '+00:00')
    except ValueError:require(False)


def _subject(value):
    cleanup.exact(value, SUBJECT_FIELDS)
    for key in ('registry', 'intent_sha256'):
        require(type(value[key]) is str and re.fullmatch('[a-f0-9]{64}', value[key]) is not None)
    for key in ('generation', 'launch_id'):require(cleanup.controls.valid_id(value[key]))
    cid = value['container_id']
    require(cid is None or type(cid) is str and re.fullmatch('[a-f0-9]{64}', cid) is not None and cid != '0' * 64)


def _record(record):
    require(type(record) is dict and type(record.get('schema')) is int and record['schema'] in (1, 2, 3))
    require(record.get('status') == 'released', 'owned_application_cleanup_required')
    require(record.get('kind', 'container') == 'container')
    for key in ('generation', 'launch_id'):require(cleanup.controls.valid_id(record.get(key)))
    require(type(record.get('registry')) is str and re.fullmatch('[a-f0-9]{64}', record['registry']) is not None)
    require(type(record.get('daemon')) is str and 0 < len(record['daemon']) <= 256)
    require(type(record.get('container')) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', record['container']))
    require(type(record.get('image')) is str and re.fullmatch('sha256:[a-f0-9]{64}', record['image']))
    cid = record.get('container_id')
    require(cid is None or type(cid) is str and re.fullmatch('[a-f0-9]{64}', cid) and cid != '0' * 64,
            'owner_identity_required')
    cleanup.path(record['runroot'])
    require(integer(record.get('owner_pid'), 1, 2**31 - 1))
    require(not record.get('inference_uncertain') and not record.get('gateway_state'))
    require(type(record.get('mounts')) is list and len(record['mounts']) <= 64)
    for mount in record['mounts']:
        cleanup.exact(mount, {'source', 'target', 'rw'})
        cleanup.path(mount['source']); cleanup.path(mount['target']); require(type(mount['rw']) is bool)
    # Registry schemas retain their pre-existing generation contract.
    if record['schema'] == 2:
        require(type(record.get('binding')) is dict and type(record['binding'].get('indexed_host_generation')) is int
                and record['binding']['indexed_host_generation'] == 2)
    if record['schema'] == 3:
        require(type(record.get('owner_cleanup_contract')) is int and record['owner_cleanup_contract'] == 1)
        cleanup.subject(record)
    else:require('owner_cleanup_contract' not in record)
    require(len(cleanup.canonical(record)) <= cleanup.MAX_BYTES, 'inventory_unbounded')


def _records(record, related):
    _record(record); expected = cleanup.subject(record)
    require(type(related) is list and 1 <= len(related) <= 64)
    ids = []
    for row in related:
        _record(row)
        require(all(row[key] == record[key] for key in ('runroot', 'registry', 'generation', 'daemon')))
        ids.append(row['launch_id'])
    require(len(set(ids)) == len(ids) and sum(cleanup.canonical(row) == cleanup.canonical(record) for row in related) == 1)
    return expected, sorted(related, key=lambda row: row['launch_id'])


def _request(value, expected):
    cleanup.exact(value, REQUEST_FIELDS); _subject(value['subject'])
    require(type(value['schema']) is int and value['schema'] == 2
            and value['document_type'] == 'application_owner_cleanup_request')
    require(value['method'] == METHOD and value['cohort'] == COHORT, 'owner_legacy_unsupported')
    require(type(value['variant']) is str and value['variant'] in VARIANTS, 'owner_scope_unsupported')
    require(value['shape'] in ('agent', 'helper_only', 'interrupted'))
    require(cleanup.canonical(value['subject']) == cleanup.canonical(expected))
    stages = value['stages']
    require(type(stages) is list and len(stages) <= 256 and all(cleanup.controls.valid_id(s) for s in stages))
    require(stages == sorted(set(stages)))
    if value['variant'] == 'diagnostic_disposable_v1':
        require(value['shape'] == 'helper_only' and not stages, 'owner_scope_unsupported')
    reference(value['evidence'])
    extras = value['extra_private_roots']
    require(type(extras) is list and len(extras) <= 8)
    for item in extras:
        cleanup.exact(item, {'path', 'origin'}); cleanup.path(item['path']); reference(item['origin'])
    require(len({item['path'] for item in extras}) == len(extras))


def _component(value, selected, reader, *, launcher=False, family=None, producer_hash=None):
    fields = COMPONENT_FIELDS | ({'launch_id'} if launcher else set())
    cleanup.exact(value, fields)
    require(type(value['rule_id']) is str and value['rule_id'] == selected
            and type(value['rule_version']) is int and value['rule_version'] == 1, 'owner_legacy_unsupported')
    cleanup.exact(value['originals'], ROLES[selected])
    bodies = {}
    public_sources = () if family is None else family.get('public_source_roles', ())
    metadata_parents = () if family is None else family.get('readable_metadata_parent_roles', ())
    require(type(public_sources) in (tuple, list) and set(public_sources) <= BYTE_ROLES | {'probe', 'prior_validator'}
            and type(metadata_parents) in (tuple, list) and set(metadata_parents) <= {'inputs', 'source_binding', 'authority'})
    for role in sorted(value['originals']):
        ref = value['originals'][role]; reference(ref)
        if role in BYTE_ROLES:
            public = role in public_sources
            if public:
                expected = producer_hash if role == 'producer' else family['supervisor_sha256'] if role == 'supervisor' else family.get('emitter_sha256', producer_hash)
                require(ref['sha256'] == expected)
            bodies[role] = reader.reference_bytes(ref, private=not public)
        else:
            bodies[role] = reader.reference(ref, private=True,
                                           private_parent=False if role in metadata_parents else None)
    return bodies


def _envelope(value, request, related, reader):
    cleanup.exact(value, EVIDENCE_FIELDS); _subject(value['subject'])
    require(type(value['schema']) is int and value['schema'] == 1
            and value['document_type'] == 'application_owner_legacy_evidence')
    timestamp(value['produced_at'])
    require(all(cleanup.canonical(value[k]) == cleanup.canonical(request[k])
                for k in ('subject', 'variant', 'cohort')))
    # Only an installed catalog identity can classify source readability. The
    # referenced bytes and every semantic premise are still verified afterward.
    cleanup.exact(value['controller'], COMPONENT_FIELDS)
    cleanup.exact(value['controller']['originals'], ROLES['supervised_controller_v1'])
    producer_ref = value['controller']['originals']['producer']; reference(producer_ref)
    family = SOURCE_FAMILIES.get(producer_ref['sha256'])
    require(family is None or type(family) is dict)
    if family is not None:
        from application_owner_legacy_controller import validate_descriptor
        validate_descriptor(family)
    options = {'family': family, 'producer_hash': producer_ref['sha256']}
    components = {'controller': _component(value['controller'], 'supervised_controller_v1', reader, **options)}
    launchers = value['launchers']
    require(type(launchers) is list and len(launchers) == len(related))
    require(all(type(v) is dict and cleanup.controls.valid_id(v.get('launch_id')) for v in launchers))
    require([v['launch_id'] for v in launchers] == [r['launch_id'] for r in related])
    components['launchers'] = [_component(v, 'source_bound_launcher_v1', reader, launcher=True, **options) for v in launchers]
    components['root'] = _component(value['root'], value['variant'], reader, **options)
    components['namespace'] = _component(value['namespace'], 'retained_namespace_v1', reader, **options)
    unknowns = value['unknowns']; require(type(unknowns) is list and len(unknowns) <= 32)
    keys = []
    for item in unknowns:
        cleanup.exact(item, {'obligation', 'reason'})
        require(type(item['obligation']) is str and item['obligation'] in OBLIGATIONS
                and type(item['reason']) is str and item['reason'] in REASONS)
        keys.append((item['obligation'], item['reason']))
    require(keys == sorted(set(keys)))
    for extra in request['extra_private_roots']:reader.reference(extra['origin'], private=True)
    return components


def _unknowns(related):
    result = []
    for obligation in OBLIGATIONS[1:]:
        rows = related if obligation in PER_LAUNCH else [None]
        for row in rows:
            if obligation == 'helper_guard_identity' and (row.get('application_helper') is not True
                    or any(k in row for k in ('qualification_role', 'qualification_preworker_cleanup', 'qualification_service_cleanup'))):
                continue
            result.append({'obligation': obligation, 'launch_id': None if row is None else row['launch_id'],
                           'reason': 'unsupported_rule'})
    return result


def _claim_shape(claim, evidence):
    cleanup.exact(claim, {'obligation', 'class', 'value', 'provenance', 'rule'})
    require(type(claim['obligation']) is str and claim['obligation'] in OBLIGATIONS
            and type(claim['class']) is str and claim['class'] in CLAIM_CLASSES)
    require(claim['class'] != 'contradiction')
    edges = claim['provenance']; require(type(edges) is list and len(edges) <= 128)
    keys = []
    for edge in edges:
        cleanup.exact(edge, {'component', 'role'})
        require(type(edge['component']) is str and type(edge['role']) is str)
        name = edge['component']
        if name.startswith('launchers/'):
            selected = [v for v in evidence['launchers'] if name == 'launchers/' + v['launch_id']]
            require(len(selected) == 1); component = selected[0]
        else:
            require(name in ('controller', 'root', 'namespace')); component = evidence[name]
        require(edge['role'] in component['originals'])
        keys.append((name, edge['role']))
    require(keys == sorted(set(keys)))
    if claim['class'] == 'derived':
        cleanup.exact(claim['rule'], {'id', 'version'})
        require(type(claim['rule']['id']) is str and claim['rule']['id'] in ROLES
                and type(claim['rule']['version']) is int and claim['rule']['version'] == 1 and edges)
    else:require(claim['rule'] is None)
    if claim['class'] in ('original', 'derived'):
        require(claim['value'] is not None)
        if claim['obligation'] not in ('subject_identity', 'related_closure'):require(edges)
    value = claim['value']
    if value is not None:
        expected_type = list if claim['obligation'] in ('related_closure', 'mount_scope', 'stage_scope', 'protected_metadata') else dict
        require(type(value) is expected_type)
        require(len(cleanup.canonical(value)) <= cleanup.MAX_BYTES, 'inventory_unbounded')
    if claim['obligation'] in PER_LAUNCH and claim['class'] in ('original', 'derived'):
        require(cleanup.controls.valid_id(value.get('launch_id')))


def _argv(value):
    require(type(value) is list and 1 <= len(value) <= 256)
    require(all(type(v) is str and 0 < len(v) <= 8192
                and not any(ord(c) < 32 or ord(c) == 127 for c in v) for v in value))


def _identity(value):
    require(type(value) is list and len(value) == 2 and type(value[0]) is int and value[0] >= 0
            and type(value[1]) is int and value[1] > 0)


def _known_refs(value, reader):
    require(type(value) is list and len(value) <= cleanup.MAX_REFERENCES)
    names = []
    for ref in value:
        reference(ref); require(reader.references.get(ref['path']) == ref); names.append(ref['path'])
    require(names == sorted(set(names)))


def _typed_value(claim, record, related, request, reader):
    value = claim['value']; obligation = claim['obligation']
    if obligation == 'subject_identity':require(value == cleanup.subject(record))
    elif obligation == 'related_closure':require(value == [cleanup._resource_subject(r) for r in related])
    elif obligation == 'controller_execution':
        cleanup.exact(value, {'pid', 'parent_pid', 'argv', 'cwd', 'launch_ids'})
        require(type(value['pid']) is int and value['pid'] == record['owner_pid']
                and integer(value['parent_pid'], 1, 2**31 - 1) and value['parent_pid'] != value['pid'])
        _argv(value['argv']); cleanup.path(value['cwd'])
        require(value['launch_ids'] == [r['launch_id'] for r in related])
    elif obligation in ('controller_terminal', 'launcher_terminal'):
        fields = {'pid', 'actual_exit', 'wait_confirmed'}
        if obligation == 'launcher_terminal':fields |= {'launch_id', 'ordinal'}
        cleanup.exact(value, fields)
        require(integer(value['pid'], 1, 2**31 - 1) and integer(value['actual_exit'], -255, 255)
                and value['wait_confirmed'] is True)
        if obligation == 'controller_terminal':require(value['pid'] == record['owner_pid'])
        else:require(integer(value['ordinal'], 1, 4096))
    elif obligation == 'launcher_execution':
        cleanup.exact(value, {'launch_id', 'pid', 'parent_pid', 'ordinal', 'argv', 'cwd'})
        row = next(r for r in related if r['launch_id'] == value['launch_id'])
        require(integer(value['pid'], 1, 2**31 - 1) and integer(value['parent_pid'], 1, 2**31 - 1)
                and value['parent_pid'] == row['owner_pid'] and value['parent_pid'] != value['pid']
                and integer(value['ordinal'], 1, 4096))
        _argv(value['argv']); cleanup.path(value['cwd'])
    elif obligation == 'helper_guard_identity':
        cleanup.exact(value, {'launch_id', 'container_id', 'intent_sha256'})
        row = next(r for r in related if r['launch_id'] == value['launch_id'])
        subject = cleanup.subject(row); cid = value['container_id']
        require(type(cid) is str and re.fullmatch('[a-f0-9]{64}', cid) and cid != '0' * 64
                and value['intent_sha256'] == subject['intent_sha256']
                and (subject['container_id'] is None or cid == subject['container_id']), 'owner_identity_required')
    elif obligation == 'original_root_custody':
        cleanup.exact(value, {'variant', 'path', 'identity', 'binding'})
        require(value['variant'] == request['variant']
                and cleanup.canonical(value['binding']) == cleanup.canonical(record['binding']))
        expected = str(Path(record['runroot']) / 'workspace') if request['variant'] == 'standard_workspace_v1' else record['private_store']
        require(value['path'] == expected, 'owner_scope_unsupported'); cleanup.path(value['path']); _identity(value['identity'])
    elif obligation == 'mount_scope':
        require(len(value) == 3 and len(record['mounts']) == 3)
        for mount in value:
            cleanup.exact(mount, {'source', 'target', 'rw'})
            cleanup.path(mount['source']); cleanup.path(mount['target']); require(type(mount['rw']) is bool)
        require(len({v['target'] for v in value}) == 3
                and sorted(value, key=lambda v: v['target']) == sorted(record['mounts'], key=lambda v: v['target']))
    elif obligation == 'stage_scope':require(value == request['stages'])
    elif obligation == 'retained_namespace':
        cleanup.exact(value, {'metadata', 'roots'}); _known_refs(value['metadata'], reader)
        require(type(value['roots']) is list and len(value['roots']) <= cleanup.MAX_ENTRIES)
        names = []
        for item in value['roots']:
            cleanup.exact(item, {'path', 'identity', 'state'}); cleanup.path(item['path']); names.append(item['path'])
            require(item['state'] in ('present', 'absent'))
            if item['state'] == 'present':_identity(item['identity'])
            else:require(item['identity'] is None)
        require(names == sorted(set(names)))
    elif obligation == 'external_authority':
        cleanup.exact(value, {'state', 'contexts'})
        require(value['state'] in ('none_issued', 'revoked')); _known_refs(value['contexts'], reader)
        require((value['state'] == 'none_issued') == (not value['contexts']))
    elif obligation == 'protected_metadata':_known_refs(value, reader)
    elif obligation == 'scoped_writers':
        cleanup.exact(value, {'pids', 'wait_confirmed'}); pids = value['pids']
        require(type(pids) is list and 1 <= len(pids) <= 128
                and all(integer(pid, 1, 2**31 - 1) for pid in pids)
                and pids == sorted(set(pids)) and value['wait_confirmed'] is True)


def _check_claims(result, evidence, record, related, request, reader):
    require(type(result['claims']) is list and len(result['claims']) <= 256)
    required = {('subject_identity', None), *((u['obligation'], u['launch_id']) for u in _unknowns(related))}
    confirmed = set(); seen = set()
    for claim in result['claims']:
        _claim_shape(claim, evidence)
        launch_id = claim['value'].get('launch_id') if claim['obligation'] in PER_LAUNCH and claim['value'] is not None else None
        key = (claim['obligation'], launch_id)
        require(key not in seen); seen.add(key)
        if claim['class'] not in ('original', 'derived'):
            require(any(token[0] == claim['obligation'] for token in required))
            if not any(u['obligation'] == key[0] and u['launch_id'] == key[1] for u in result['unresolved']):
                result['unresolved'].append({'obligation': key[0], 'launch_id': key[1], 'reason': 'incomplete_binding'})
            continue
        require(key in required)
        _typed_value(claim, record, related, request, reader); confirmed.add(key)
    require(type(result['unresolved']) is list and len(result['unresolved']) <= 256)
    for item in result['unresolved']:
        cleanup.exact(item, {'obligation', 'launch_id', 'reason'})
        require(item['obligation'] in OBLIGATIONS and item['reason'] in REASONS
                and (item['launch_id'] is None or cleanup.controls.valid_id(item['launch_id'])))
    for obligation, launch_id in sorted(required - confirmed, key=lambda key: (key[0], key[1] or '')):
        if not any(u['obligation'] == obligation and u['launch_id'] == launch_id for u in result['unresolved']):
            result['unresolved'].append({'obligation': obligation, 'launch_id': launch_id, 'reason': 'incomplete_binding'})


def _complete(result, reader):
    values = {(c['obligation'], c['value'].get('launch_id') if c['obligation'] in PER_LAUNCH else None): c['value']
              for c in result['claims'] if c['class'] in ('original', 'derived')}
    namespace = values['retained_namespace', None]
    require(cleanup.canonical(namespace['roots']) == cleanup.canonical(result['roots']))
    expected = reader.scope_references()
    require(namespace['metadata'] == expected and values['protected_metadata', None] == expected)
    root = values['original_root_custody', None]
    observed = [r for r in result['roots'] if r['path'] == root['path']]
    require(len(observed) == 1 and (observed[0]['state'] == 'absent' or observed[0]['identity'] == root['identity']),
            'sensitive_identity_mismatch')
    for ref in expected:
        target = Path(ref['path'])
        require(not any(target == Path(r['path']) or Path(r['path']) in target.parents for r in result['roots']), 'unsafe_path')
    owned_pids = {values['controller_execution', None]['pid']}
    for key, execution in values.items():
        if key[0] != 'launcher_execution':continue
        terminal = values['launcher_terminal', key[1]]
        require(terminal['pid'] == execution['pid'] and terminal['ordinal'] == execution['ordinal'])
        owned_pids.add(execution['pid'])
    require(owned_pids <= set(values['scoped_writers', None]['pids']))


def _analyze(request, record, related, reader):
    request, record, related = copy.deepcopy((request, record, related))
    expected, related = _records(record, related); _request(request, expected)
    evidence = reader.reference(request['evidence'], private=True)
    components = _envelope(evidence, request, related, reader)
    result = {'status': 'blocked', 'claims': [
        {'obligation': 'subject_identity', 'class': 'original', 'value': expected, 'provenance': [], 'rule': None},
        {'obligation': 'related_closure', 'class': 'candidate',
         'value': [cleanup._resource_subject(r) for r in related], 'provenance': [], 'rule': None}],
        'unresolved': _unknowns(related), 'metadata': [], 'roots': [], 'physical': [],
        'controller': None, 'launchers': []}
    # The static adapters will discharge only their own reviewed obligations.
    # Empty catalog entries and operator statements are deliberately insufficient.
    for component in ('controller', 'launchers', 'root', 'namespace'):
        adapter = _ADAPTERS.get(component)
        if adapter is not None:
            adapter(result, components, evidence, request, record, related, reader)
    for item in evidence['unknowns']:
        if not any(u['obligation'] == item['obligation'] and u['reason'] == item['reason'] for u in result['unresolved']):
            result['unresolved'].append({**item, 'launch_id': None})
    _check_claims(result, evidence, record, related, request, reader)
    result['metadata'] = reader.scope_references()
    # There is no eligible route until every installed adapter and all required
    # typed obligations have passed. Declared unknowns cannot be hidden.
    if not result['unresolved']:
        _complete(result, reader)
        result['status'] = 'eligible_for_native_checks'
    return result


@diagnostics.scoped('owner_legacy_validation', 'cleanup_proof_invalid')
def analyze(request, record, related, *, reader=None):
    """Validate the declared role graph, preserving unresolved semantic claims.

    Record arguments are the caller's privileged current-registry observation.
    The native operation must reread them under the original lease before effects.
    An analysis result is never an owner receipt or a dispatch credential.
    """
    reader = cleanup.Reader() if reader is None else reader
    with reader.custody_scope():
        return _analyze(request, record, related, reader)


def prepare(request, record, related, *, reader=None):
    result = analyze(request, record, related, reader=reader)
    require(result['status'] == 'eligible_for_native_checks' and not result['unresolved'], 'owner_legacy_incomplete')
    return result
