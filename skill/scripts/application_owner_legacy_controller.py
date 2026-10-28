"""Static adapters for retained controller records; original source is data only.

Recorded process outcomes, inferred context and unresolved lineage stay distinct.
These functions do not register source identities, observe PIDs, execute source,
write evidence, or grant cleanup/admission. Catalog activation is separate.
"""
import ast
import hashlib
import json
import math
from pathlib import Path

import application_owner_cleanup as cleanup
import application_owner_legacy as legacy

SUPERVISED_START = frozenset({'schema', 'pid', 'wrapper_pid', 'argv', 'started', 'started_wall'})
SUPERVISED_TERMINAL = frozenset({'schema', 'status', 'actual_exit', 'child_pid', 'wrapper_pid',
    'child_wait_confirmed', 'automatic_retries', 'container_or_private_actions_by_supervisor',
    'elapsed_seconds', 'program', 'inputs', 'source_review'})
SOURCE_BINDING = frozenset({'schema', 'program', 'source_dependencies', 'inputs', 'invoker',
                            'controller_context', 'role'})
SOURCE_REVIEW = frozenset({'schema', 'status', 'classification', 'controlled_validation', 'effect_scope',
    'inputs', 'limitations', 'pre_diagnostic_helper_review', 'probe', 'program', 'reviewed_guards',
    'supervisor', 'supports_one_shot_diagnostic', 'tests', 'unresolved_findings'})
MANIFEST_FIELDS = frozenset({'schema', 'document_type', 'authorization', 'cells', 'code_identity',
    'command', 'container_name', 'diagnostic', 'disposable_root', 'gid', 'images', 'inputs', 'limits',
    'planned_container_launches', 'qualification_id', 'source_review', 'uid'})
CONTEXT_BASE = frozenset({'argv', 'cwd', 'expected_exit', 'actual_exit', 'elapsed_seconds',
                         'invoker_sha256', 'scope'})


def _require(value, condition='cleanup_proof_invalid'):
    legacy.require(value, condition)


def validate_descriptor(family):
    """Check installed catalog data before it can classify a file's privacy."""
    _require(type(family) is dict and family.get('binding_format') in ('supervised_source_v1', 'artifact_diagnostic_v1'),
             'owner_legacy_unsupported')
    common = {'family_id', 'binding_format', 'supervisor_sha256', 'variants'}
    hashes = {'supervisor_sha256'}
    if family['binding_format'] == 'supervised_source_v1':hashes.add('emitter_sha256')
    else:hashes |= {'host_source_pins_sha256', 'runtime_source_pins_sha256', 'probe_sha256', 'prior_validator_sha256'}
    required = common | hashes; optional = {'public_source_roles', 'readable_metadata_parent_roles'}
    _require(required <= set(family) <= required | optional and family['family_id'] == family['binding_format'])
    for field in hashes:
        _require(type(family[field]) is str and len(family[field]) == 64
                 and all(c in '0123456789abcdef' for c in family[field]))
    variants = family['variants']
    _require(type(variants) in (tuple, list) and 1 <= len(variants) <= 2
             and all(type(v) is str and v in legacy.VARIANTS for v in variants)
             and len(set(variants)) == len(variants))
    if family['binding_format'] == 'artifact_diagnostic_v1':_require(set(variants) == {'diagnostic_disposable_v1'})
    for field, allowed in (('public_source_roles', legacy.BYTE_ROLES | {'probe', 'prior_validator'}),
                           ('readable_metadata_parent_roles', {'inputs', 'source_binding', 'authority'})):
        values = family.get(field, ())
        _require(type(values) in (tuple, list) and len(values) <= len(allowed)
                 and all(type(v) is str and v in allowed for v in values)
                 and len(values) == len(set(values)))


def _number(value):
    _require(type(value) in (int, float) and value >= 0)
    _require(value <= 2**63 - 1 if type(value) is int else math.isfinite(value))


def _ref_equal(value, expected):
    legacy.reference(value); _require(value == expected)


def historical_digest(value):
    """The reviewed producer used JSON's ASCII escaping, unlike the new envelope."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def _fact(result, obligation, value, roles, classification='derived', reason='incomplete_binding'):
    legacy._set_claim(result, obligation, value, classification=classification,
                      component='controller', roles=roles, reason=reason)


def _observations(result, bodies, record):
    """Keep useful recorded values without certifying a controller association."""
    terminal = bodies['terminal']; start = bodies['start']; context = bodies['context']
    actual = terminal.get('actual_exit'); observed = terminal; role = 'terminal'
    if not legacy.integer(actual, -255, 255):
        actual = context.get('actual_exit'); observed = context; role = 'context'
    if legacy.integer(actual, -255, 255):
        pid = observed.get('child_pid', observed.get('pid'))
        if not legacy.integer(pid, 1, 2**31 - 1):pid = None
        observed_wait = observed.get('child_wait_confirmed', observed.get('wait_completed', observed.get('wait_confirmed')))
        if type(observed_wait) is not bool:observed_wait = None
        classification = 'different_scope' if pid is not None and pid != record['owner_pid'] else 'candidate'
        _fact(result, 'controller_terminal', {'pid': pid, 'actual_exit': actual, 'wait_confirmed': observed_wait},
              [role], classification, 'different_scope' if classification == 'different_scope' else 'unsupported_rule')
    argv = start.get('argv', context.get('argv'))
    cwd = context.get('cwd')
    _fact(result, 'controller_execution', {'pid': start.get('pid', start.get('child_pid')),
        'parent_pid': start.get('wrapper_pid', start.get('parent_pid')), 'argv': argv,
        'cwd': cwd, 'launch_ids': None}, ['context', 'start'], 'candidate', 'unsupported_rule')


def _context(body):
    fields = set(body)
    variants = (CONTEXT_BASE | {'started_at'}, CONTEXT_BASE | {'schema', 'started_wall'})
    _require(fields in variants)
    if 'schema' in body:_require(type(body['schema']) is int and body['schema'] == 1)
    legacy._argv(body['argv']); cleanup.path(body['cwd'])
    _require(legacy.integer(body['actual_exit'], -255, 255) and legacy.integer(body['expected_exit'], -255, 255))
    _number(body['elapsed_seconds'])
    started = body.get('started_wall', body.get('started_at'))
    if type(started) is str:legacy.timestamp(started)
    else:_number(started)
    _require(type(body['scope']) is str and 0 < len(body['scope']) <= 512)
    _require(type(body['invoker_sha256']) is str and len(body['invoker_sha256']) == 64)
    return body


def _supervised(bodies, originals, family, record):
    start, terminal = bodies['start'], bodies['terminal']
    cleanup.exact(start, SUPERVISED_START); cleanup.exact(terminal, SUPERVISED_TERMINAL)
    _require(type(start['schema']) is int and start['schema'] == 1
             and type(terminal['schema']) is int and terminal['schema'] == 1)
    _require(legacy.integer(start['pid'], 1, 2**31 - 1) and start['pid'] == record['owner_pid']
             and type(terminal['child_pid']) is int and terminal['child_pid'] == start['pid'])
    _require(legacy.integer(start['wrapper_pid'], 1, 2**31 - 1) and start['wrapper_pid'] != start['pid']
             and type(terminal['wrapper_pid']) is int and terminal['wrapper_pid'] == start['wrapper_pid'])
    _number(start['started']); _number(start['started_wall']); _number(terminal['elapsed_seconds'])
    legacy._argv(start['argv'])
    _require(type(terminal['child_wait_confirmed']) is bool)
    _require(type(terminal['automatic_retries']) is int and terminal['automatic_retries'] == 0
             and type(terminal['container_or_private_actions_by_supervisor']) is int
             and terminal['container_or_private_actions_by_supervisor'] == 0)
    _require(terminal['status'] in ('PASS', 'FAIL', 'BLOCKED', 'INTERRUPTED'))
    if terminal['child_wait_confirmed']:_require(legacy.integer(terminal['actual_exit'], -255, 255))
    else:_require(terminal['actual_exit'] is None)
    for key, role in (('program', 'producer'), ('inputs', 'inputs'), ('source_review', 'source_binding')):
        _ref_equal(terminal[key], originals[role])
    _require(originals['supervisor']['sha256'] == family['supervisor_sha256']
             and hashlib.sha256(bodies['supervisor']).hexdigest() == family['supervisor_sha256'])
    return start, terminal


def _reference_family(bodies, components, evidence, originals, record, related):
    binding = bodies['source_binding']; inputs = bodies['inputs']; family = legacy.SOURCE_FAMILIES[originals['producer']['sha256']]
    cleanup.exact(binding, SOURCE_BINDING)
    _require(type(binding['schema']) is int and binding['schema'] == 1)
    for key, role in (('program', 'producer'), ('inputs', 'inputs'), ('invoker', 'supervisor'), ('controller_context', 'context')):
        _ref_equal(binding[key], originals[role])
    _require(type(binding['role']) is str and 0 < len(binding['role']) <= 128)
    _require(len(related) == 1, 'owner_legacy_unsupported')
    emitter = evidence['launchers'][0]['originals']['emitter']
    _require(binding['source_dependencies'] == [emitter]
             and emitter['sha256'] == family['emitter_sha256']
             and hashlib.sha256(components['launchers'][0]['emitter']).hexdigest() == family['emitter_sha256'])
    cleanup.exact(inputs, {'launch_id', 'registry', 'generation', 'container', 'image', 'mounts', 'cwd'})
    for key in ('launch_id', 'registry', 'generation', 'container', 'image', 'mounts'):
        _require(cleanup.canonical(inputs[key]) == cleanup.canonical(record[key]))
    cleanup.path(inputs['cwd'])
    expected = ['python3', originals['producer']['path'], originals['inputs']['path']]
    context = _context(bodies['context'])
    _require(context['argv'] == expected and context['invoker_sha256'] == family['supervisor_sha256'])
    return context, expected


def _source_parameters(source, producer):
    """Read constants from already catalog-matched source, without evaluating it."""
    tree = ast.parse(source, feature_version=(3, 10)); here = Path(producer['path']).parent
    values = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):continue
        name = node.targets[0].id
        if name in ('ROOT', 'INPUT_PATH', 'REVIEW_PATH'):
            value = node.value
            _require(isinstance(value, ast.BinOp) and isinstance(value.op, ast.Div)
                     and isinstance(value.right, ast.Constant) and type(value.right.value) is str)
            if isinstance(value.left, ast.Name) and value.left.id == 'HERE':parent = here
            else:
                _require(isinstance(value.left, ast.Attribute) and value.left.attr == 'parent'
                         and isinstance(value.left.value, ast.Name) and value.left.value.id == 'HERE')
                parent = here.parent
            leaf = value.right.value
            _require(leaf and not Path(leaf).is_absolute() and '..' not in Path(leaf).parts and str(Path(leaf)) == leaf)
            values[name] = cleanup.path(str(parent / leaf))
        elif name in ('AUTHORITY_ID', 'IMAGE'):
            _require(isinstance(node.value, ast.Constant) and type(node.value.value) is str)
            values[name] = node.value.value
    _require(set(values) == {'ROOT', 'INPUT_PATH', 'REVIEW_PATH', 'AUTHORITY_ID', 'IMAGE'})
    targets = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'publish'
                and len(node.args) == 2 and isinstance(node.args[1], ast.Name) and node.args[1].id == 'manifest'):continue
        target = node.args[0]
        _require(isinstance(target, ast.BinOp) and isinstance(target.op, ast.Div)
                 and isinstance(target.left, ast.Name) and target.left.id == 'ROOT'
                 and isinstance(target.right, ast.Constant) and type(target.right.value) is str)
        leaf = target.right.value
        _require(Path(leaf).name == leaf and leaf.endswith('.json'))
        targets.append(values['ROOT'] / leaf)
    _require(len(targets) == 1); values['manifest'] = targets[0]
    return values


def _artifact_family(bodies, components, evidence, originals, family, record, related, reader):
    review = bodies['source_binding']; inputs = bodies['inputs']
    cleanup.exact(review, SOURCE_REVIEW)
    _require(type(review['schema']) is int and review['schema'] == 1
             and review['status'] == 'PASS' and review['unresolved_findings'] == [])
    for key, role in (('program', 'producer'), ('supervisor', 'supervisor'), ('inputs', 'inputs')):
        _ref_equal(review[key], originals[role])
    _require(type(inputs['source_pins']) is dict and 1 <= len(inputs['source_pins']) <= 500
             and type(inputs['code_source_pins']) is dict and 1 <= len(inputs['code_source_pins']) <= 64)
    _require(historical_digest(inputs['source_pins']) == family['host_source_pins_sha256']
             and historical_digest(inputs['code_source_pins']) == family['runtime_source_pins_sha256'])
    _require(review['probe'] == inputs['probe'] and inputs['probe']['sha256'] == family['probe_sha256']
             and inputs['prior_validator']['sha256'] == family['prior_validator_sha256'])
    # The pinned loader verifies these execution bytes; no evidence-selected code
    # is imported here. Referenced bytes still use the complete shared budget.
    reader.reference_bytes(inputs['probe'], private='probe' not in family.get('public_source_roles', ()))
    reader.reference_bytes(inputs['prior_validator'], private='prior_validator' not in family.get('public_source_roles', ()))
    params = _source_parameters(bodies['producer'], originals['producer']); root = params['ROOT']
    _require(record['runroot'] == str(root.parent) and record['private_store'] == str(root / 'disposable')
             and record['image'] == params['IMAGE'] and len(related) == 1)
    _require(originals['inputs']['path'] == str(params['INPUT_PATH'])
             and originals['source_binding']['path'] == str(params['REVIEW_PATH']))
    manifest, unused = reader.read(params['manifest'], private=True); cleanup.exact(manifest, MANIFEST_FIELDS)
    _require(type(manifest['schema']) is int and manifest['schema'] == 1
             and manifest['document_type'] == 'credential_free_artifact_write_diagnostic'
             and manifest['disposable_root'] == record['private_store'] and manifest['container_name'] == record['container'])
    _require(type(manifest['planned_container_launches']) is int and manifest['planned_container_launches'] == 1
             and legacy.integer(manifest['uid'], 0, 2**32 - 1) and legacy.integer(manifest['gid'], 0, 2**32 - 1))
    marker = manifest['diagnostic']
    cleanup.exact(marker, {'kind', 'root', 'started', 'started_wall', 'deadline', 'deadline_wall'})
    _require(marker['root'] == str(root) and type(marker['kind']) is str and 0 < len(marker['kind']) <= 128)
    for key in ('started', 'started_wall', 'deadline', 'deadline_wall'):_number(marker[key])
    _require(marker['started'] <= marker['deadline'] and marker['started_wall'] <= marker['deadline_wall'])
    _ref_equal(manifest['inputs'], originals['inputs']); _ref_equal(manifest['source_review'], originals['source_binding'])
    _require(record['binding'] == {'artifact_diagnostic': params['AUTHORITY_ID'], 'qualification_id': manifest['qualification_id']}
             and cleanup.controls.valid_id(manifest['qualification_id']))
    expected_code = dict(inputs['code_source_pins']); expected_code['runtime/application_client_service.py'] = inputs['probe']['sha256']
    _require(manifest['code_identity'] == expected_code == record['code_identity'])
    ledger = components['launchers'][0]['ledger']
    _require(ledger['manifest_sha256'] == historical_digest(manifest) and ledger['daemon'] == record['daemon'])
    _require(type(ledger['launches']) is list and len(ledger['launches']) == 1
             and all(type(row) is dict for row in ledger['launches']))
    rows = [row for row in ledger['launches'] if row.get('launch_id') == record['launch_id']]
    _require(len(rows) == 1)
    for key in ('launch_id', 'registry', 'generation', 'container', 'image'):_require(rows[0][key] == record[key])
    _require(rows[0]['intent_sha256'] == historical_digest({k: v for k, v in record.items()
                                                        if k not in ('status', 'container_id')}))
    return params


def validate_controller(result, components, evidence, request, record, related, reader):
    bodies = components['controller']; originals = evidence['controller']['originals']
    _observations(result, bodies, record)
    family = legacy.SOURCE_FAMILIES.get(originals['producer']['sha256'])
    if family is None:return
    _require(type(family) is dict and request['variant'] in family['variants'], 'owner_legacy_unsupported')
    _require(hashlib.sha256(bodies['producer']).hexdigest() == originals['producer']['sha256'])
    format_id = family['binding_format']
    if format_id not in ('supervised_source_v1', 'artifact_diagnostic_v1'):return
    start, terminal = _supervised(bodies, originals, family, record)
    context = None
    if format_id == 'supervised_source_v1':
        context, expected = _reference_family(bodies, components, evidence, originals, record, related)
        _require(start['argv'] == expected)
    else:
        _artifact_family(bodies, components, evidence, originals, family, record, related, reader)
        argv = start['argv']
        _require(len(argv) == 11 and argv[1:4] == ['-B', originals['producer']['path'], '--inputs-sha256']
                 and argv[4] == originals['inputs']['sha256'] and argv[5] == '--review-sha256'
                 and argv[6] == originals['source_binding']['sha256'] and argv[7] == '--outer-deadline'
                 and argv[9] == '--outer-deadline-wall')
        _number(float(argv[8])); _number(float(argv[10]))
        # This original supervisor format omits cwd. Reusing its terminal as
        # context is honest partial evidence, not permission to invent a cwd.
        _require(originals['context'] == originals['terminal'], 'owner_legacy_incomplete')
    provenance = list(originals)
    if terminal['child_wait_confirmed']:
        if context is not None:_require(context['actual_exit'] == terminal['actual_exit'])
        _fact(result, 'controller_terminal', {'pid': start['pid'], 'actual_exit': terminal['actual_exit'],
                                            'wait_confirmed': True}, provenance, 'original')
    else:
        _fact(result, 'controller_terminal', {'pid': start['pid'], 'actual_exit': None,
                                            'wait_confirmed': False}, provenance, 'candidate')
    execution = {'pid': start['pid'], 'parent_pid': start['wrapper_pid'], 'argv': start['argv'],
                 'cwd': None if context is None else context['cwd'], 'launch_ids': [r['launch_id'] for r in related]}
    _fact(result, 'controller_execution', execution, provenance, 'candidate' if context is None else 'derived',
          'not_located' if context is None else 'incomplete_binding')
    if context is not None and terminal['child_wait_confirmed']:
        result['controller'] = {**execution, 'actual_exit': terminal['actual_exit'], 'wait_confirmed': True}
