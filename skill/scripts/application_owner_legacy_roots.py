"""Original host root custody and exact discard topology, without file removal.

Current filesystem identity only checks a present root against its original
witness. It never creates historical custody, an agent invocation or admission.
"""
from pathlib import Path
import re

import application_owner_cleanup as cleanup
import application_owner_legacy as legacy
import application_owner_legacy_controller as controller

DESCRIPTOR = frozenset({'schema', 'stage_id', 'kind', 'label', 'workspace', 'workspace_identity', 'run_id', 'attempt_id'})
RETAINED_DESCRIPTOR = DESCRIPTOR | {'document_type', 'admission_lock_file', 'segment_id', 'control',
                                    'inbox', 'outbox', 'runtime', 'container', 'protected_paths', 'original_limits'}
MINIMAL_DIAGNOSTIC = frozenset({'schema', 'document_type', 'container_id', 'disposable_root',
                                'disposable_root_identity', 'disposable_root_removed'})
ARTIFACT_TERMINAL = frozenset({'schema', 'document_type', 'status', 'scope', 'authorization', 'claim',
    'cleanup_seconds', 'container_id', 'credentials', 'cumulative_container_intents', 'cumulative_participant_segments',
    'disposable_root', 'disposable_root_identity', 'disposable_root_removed', 'elapsed_seconds',
    'failure_before_positive_cleanup', 'finished', 'finished_wall', 'historical_failure_cause_established',
    'inference_calls', 'inputs', 'ledger', 'manifest', 'network', 'networks_created', 'new_container_intents',
    'new_participants', 'original_lease_held', 'physical_absence_confirmed', 'primitive_outcome', 'primitive_qualified',
    'prior_container_intents', 'private_cleanup_confirmed', 'probe_observation', 'process_receipts',
    'qualification_id', 'raw_ledger_preserved', 'registry_record', 'source_review', 'started', 'started_wall',
    'all_owned_host_children_waited'})


def _require(value, condition='cleanup_proof_invalid'):
    legacy.require(value, condition)


def _fact(result, obligation, value, classification='original', rule='standard_workspace_v1'):
    legacy._set_claim(result, obligation, value, classification=classification,
                      component='root', roles=['witness'], rule_id=rule)


def _mounts(record, expected):
    mounts = record['mounts']; _require(type(mounts) is list and len(mounts) == len(expected))
    remaining = dict(expected)
    for mount in mounts:
        cleanup.exact(mount, {'source', 'target', 'rw'})
        _require(type(mount['rw']) is bool and mount['target'] in remaining)
        _require((mount['source'], mount['rw']) == remaining.pop(mount['target']), 'owner_scope_unsupported')
    _require(not remaining)
    return mounts


def _standard(witness, reference, record, reader):
    root = cleanup.path(record['runroot']); private = cleanup.path(record['private_store'])
    _require(private.parent == root / 'application-helpers' and re.fullmatch('[a-f0-9]{32}', private.name),
             'owner_scope_unsupported')
    evidence = root / 'application-evidence' / record['container']
    mounts = _mounts(record, {'/opt/pi-application': (str(private / 'code'), False),
        '/pi-client/state': (str(private / 'state'), True), '/pi-client/evidence': (str(evidence), True)})
    identity = None
    if witness.get('document_type') == 'application_owned_snapshot':
        snapshot = cleanup._owned_snapshot(reader, reference, record)
        _require(cleanup.canonical(snapshot['binding']) == cleanup.canonical(record['binding']))
        identity = snapshot['workspace_identity']
    elif type(witness.get('schema')) is int and witness['schema'] == 2 and 'workspace_identity' in witness:
        _require(set(witness) in (DESCRIPTOR, RETAINED_DESCRIPTOR))
        _require(witness['kind'] in ('agent', 'check', 'probe', 'preflight', 'boundary', 'browser'))
        _require(cleanup.controls.valid_id(witness['stage_id']) and all(cleanup.controls.valid_id(record['binding'].get(k))
                                                                    for k in ('run_id', 'attempt_id')))
        _require(all(witness[k] == record['binding'][k] for k in ('run_id', 'attempt_id'))
                 and witness['workspace'] == str(root / 'workspace'), 'sensitive_identity_mismatch')
        _require(reference['path'] == str(root / 'stages' / witness['stage_id'] / 'descriptor.json'), 'owner_scope_unsupported')
        if 'document_type' in witness:_require(witness['document_type'] == 'stage')
        _require(type(witness['label']) is str and re.fullmatch('[A-Za-z0-9_-]{1,128}', witness['label']))
        identity = witness['workspace_identity']
    if identity is None:return None
    legacy._identity(identity)
    paths = [root / 'workspace', private, evidence, root / 'children' / '.pi-lab']
    return root / 'workspace', identity, paths, root, mounts, False


def _guard(result, record):
    facts = [c for c in result['claims'] if c['obligation'] == 'helper_guard_identity'
             and c['class'] in ('original', 'derived') and c['value']['launch_id'] == record['launch_id']]
    return facts[0]['value'] if len(facts) == 1 else None


def _diagnostic(witness, reference, components, evidence, record, result, reader):
    private = cleanup.path(record['private_store']); root = cleanup.path(record['runroot'])
    _require(private != root and root in private.parents and private.name == 'disposable', 'owner_scope_unsupported')
    mounts = _mounts(record, {'/opt/pi-application': (str(private / 'code'), False),
        '/pi-client/state': (str(private / 'state'), True), '/pi-client/evidence': (str(private / 'evidence'), True)})
    family = legacy.SOURCE_FAMILIES.get(evidence['controller']['originals']['producer']['sha256'])
    if family is None or _guard(result, record) is None:return None
    _require(type(witness.get('schema')) is int and witness['schema'] == 1)
    if witness.get('document_type') != 'bounded_artifact_write_diagnostic_terminal':return None
    if family['binding_format'] == 'artifact_diagnostic_v1':
        # Older partial/scoped observations do not become the complete original
        # terminal merely because they contain an inode or a PASS label.
        if set(witness) != ARTIFACT_TERMINAL:return None
        params = controller._source_parameters(components['controller']['producer'], evidence['controller']['originals']['producer'])
        _require(private == params['ROOT'] / 'disposable' and root == params['ROOT'].parent)
        _require(reference['path'] == str(params['ROOT'] / 'terminal.json'), 'owner_scope_unsupported')
        for key, expected in (('inputs', evidence['controller']['originals']['inputs']),
                              ('source_review', evidence['controller']['originals']['source_binding']),
                              ('ledger', evidence['launchers'][0]['originals']['ledger'])):
            controller._ref_equal(witness[key], expected)
        _require(witness['qualification_id'] == record['binding']['qualification_id'])
        legacy.reference(witness['manifest']); _require(witness['manifest']['path'] == str(params['manifest']))
        reader.reference(witness['manifest'], private=True)
        retained_root = params['ROOT']
    else:
        _require(family['binding_format'] == 'supervised_source_v1')
        cleanup.exact(witness, MINIMAL_DIAGNOSTIC); retained_root = private.parent
    _require(witness['disposable_root'] == str(private)
             and witness['container_id'] == _guard(result, record)['container_id'], 'sensitive_identity_mismatch')
    _require(type(witness['disposable_root_removed']) is bool)
    identity = witness['disposable_root_identity']; legacy._identity(identity)
    return private, identity, [private], retained_root, mounts, witness['disposable_root_removed']


def validate_root(result, components, evidence, request, record, related, reader):
    witness = components['root']['witness']; reference = evidence['root']['originals']['witness']
    variant = request['variant']
    if variant == 'standard_workspace_v1':
        planned = _standard(witness, reference, record, reader)
    else:
        planned = _diagnostic(witness, reference, components, evidence, record, result, reader)
    if planned is None:return
    original_path, original_identity, paths, retained, mounts, already_removed = planned
    observations = [cleanup._root_observation(p) for p in sorted(set(paths), key=str)]
    original = next(o for o in observations if o['path'] == str(original_path))
    if original['state'] == 'present':
        _require(not already_removed and original['identity'] == original_identity, 'sensitive_identity_mismatch')
    # Evidence, including the original custody document itself, must survive.
    for ref in reader.scope_references():
        target = Path(ref['path'])
        _require(not any(target == Path(o['path']) or Path(o['path']) in target.parents for o in observations), 'unsafe_path')
    _fact(result, 'original_root_custody', {'variant': variant, 'path': str(original_path),
        'identity': original_identity, 'binding': record['binding']}, rule=variant)
    _fact(result, 'mount_scope', mounts, 'derived', variant)
    result['roots'] = observations
    result['root_plan'] = {'variant': variant, 'retained_root': str(retained),
        'original_path': str(original_path), 'original_identity': original_identity,
        'original_removed': already_removed, 'discard_roots': observations}
