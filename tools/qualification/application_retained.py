"""Explicit retained-nine/fresh-nineteen application qualification.

Retained evidence is an immutable input, never fresh controller state or a
launch-ledger carry.  Only the selected nineteen new cells can use the ordinary
qualification runner.  This module deliberately receives the qualification
module from its caller so that it cannot create a second orchestration runtime.
"""
import copy
import hashlib
import math
import os
from pathlib import Path
import re
import uuid


MODE = 'retained9_fresh19_v1'
FAILED_CELL = 'N02-0.87.1-commit-and-interruption-b'
HISTORICAL_USE = {'containers': 387, 'participants': 27}
LOCAL_PLAN = {'containers': 140, 'participants': 19}
CUMULATIVE_CEILING = {'containers': 527, 'participants': 46}
PHASES = (('N02', '0.87.1'), ('N02', '1.2.0'), ('N03', '0.87.1'),
          ('N03', '1.2.0'), ('N04', '0.87.1'), ('N04', '1.2.0'))
LIMITS = {'global_seconds': 14400, 'cleanup_reserve_seconds': 30,
          'container_launch_attempts': 140, 'live': 4, 'participant_segments': 19}
NEGATIVES = (('request-and-persona', 'a'), ('request-and-persona', 'b'),
             ('reporting-and-reserve', 'a'), ('reporting-and-reserve', 'b'),
             ('commit-and-interruption', 'a'), ('commit-and-interruption', 'b'))
RETAINED_IDS = tuple('N01-' + release + '-' + profile
                     for release in ('0.87.1', '1.2.0')
                     for profile in ('core', 'browser')) + tuple(
    'N02-0.87.1-' + case + '-' + variant for case, variant in NEGATIVES[:-1])
FRESH_IDS = (FAILED_CELL,) + tuple('N02-1.2.0-' + case + '-' + variant
                                  for case, variant in NEGATIVES) + tuple(
    group + '-' + release + '-' + str(repeat)
    for release in ('0.87.1', '1.2.0') for group in ('N03', 'N04')
    for repeat in range(1, 4))
SOURCE_CHANGES = {'tools/qualification/application_client.py',
                  'tools/qualification/application_launch.py',
                  'tools/qualification/application_operational_replay.py',
                  'tools/qualification/application_retained.py'}
LAUNCH_FIELDS = ('id', 'group', 'release', 'image_id', 'allowed_images',
                 'role_limits', 'container_launches_max', 'participant_segments_max')


class RetainedError(ValueError):
    def __init__(self):
        super().__init__('Retained qualification evidence or selection is unavailable')


def _require(condition):
    if not condition:
        raise RetainedError()


def _exact(value, fields):
    _require(type(value) is dict and set(value) == set(fields))


def _sha(value):
    _require(type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None)


def _uuid(value):
    try:
        _require(type(value) is str and str(uuid.UUID(value)) == value)
    except (ValueError, TypeError, AttributeError):
        raise RetainedError() from None


def _path(value):
    _require(type(value) is str and len(value) <= 4096 and '\0' not in value)
    path = Path(value)
    _require(path.is_absolute() and str(path) == value and '..' not in path.parts)
    return path


def _reference(value, expected=None):
    _exact(value, {'path', 'sha256'})
    path = _path(value['path'])
    _sha(value['sha256'])
    if expected is not None:
        _require(path == Path(expected))
    return path


def partition(cells):
    """Return the exact nine retained and nineteen new declared cells."""
    _require(type(cells) is list and len(cells) == 28)
    _require(all(type(row) is dict and type(row.get('id')) is str for row in cells))
    byid = {row['id']: row for row in cells}
    _require(len(byid) == 28 and set(byid) == set(RETAINED_IDS) | set(FRESH_IDS))
    retained = [copy.deepcopy(row) for row in cells if row['id'] in RETAINED_IDS]
    fresh = [copy.deepcopy(row) for row in cells if row['id'] in FRESH_IDS]
    _require(sum(row['container_launches_max'] for row in fresh) == 140
             and sum(row['participant_segments_max'] for row in fresh) == 19
             and sum(row['real_model'] is True for row in fresh) == 12)
    return retained, fresh


def validate_index(index, full_cells):
    """Validate role paths before reading any referenced evidence."""
    _exact(index, {'schema', 'document_type', 'prior_root', 'prior_manifest',
                   'prior_candidate', 'prior_state', 'prior_ledger', 'historical_use',
                   'excluded_failed_cell', 'cells'})
    _require(type(index['schema']) is int and index['schema'] == 1
             and index['document_type'] == 'application_retained_evidence_index'
             and index['historical_use'] == HISTORICAL_USE)
    root = _path(index['prior_root'])
    for name, leaf in (('prior_manifest', 'manifest.json'), ('prior_candidate', 'candidate.json'),
                       ('prior_state', 'state.json'), ('prior_ledger', 'launch-ledger/ledger.json')):
        _reference(index[name], root / leaf)
    _require(index['excluded_failed_cell'] == {'cell_id': FAILED_CELL,
              'disposition': 'NOT_RETAINED', 'reason': 'signal_provenance_not_established'})
    retained, _ = partition(full_cells)
    byid = {row['id']: row for row in retained}
    rows = index['cells']
    _require(type(rows) is list and len(rows) == 9
             and all(type(row) is dict and type(row.get('cell_id')) is str for row in rows))
    _require(len({row['cell_id'] for row in rows}) == 9
             and {row['cell_id'] for row in rows} == set(RETAINED_IDS))
    for row in rows:
        cell = byid[row['cell_id']]
        folder = root / 'cells' / cell['id']
        if cell['group'] == 'N01':
            _exact(row, {'cell_id', 'kind', 'admission'})
            _require(row['kind'] == 'admission')
            path = _reference(row['admission'])
            if cell['profile'] == 'core':
                _require(path == folder / 'runtime.json')
            else:
                _require(path.name == 'browser-admission.json' and path.parent.parent == folder)
                _require(re.fullmatch(r'browser-[a-f0-9]{32}', path.parent.name) is not None)
        else:
            _exact(row, {'cell_id', 'kind', 'run_id', 'attempt_id', 'attempt_intent',
                         'qualification', 'result', 'plan', 'oracle', 'journal', 'scripted',
                         'parent_receipt', 'fixture_terminal',
                         'services_cleanup', 'child_completion'})
            _require(row['kind'] == 'negative')
            _uuid(row['run_id']); _uuid(row['attempt_id'])
            experiment = root / ('scripted-' + cell['release'])
            _uuid(cell['trial_id'])
            paths = {'attempt_intent': experiment / 'attempts' / cell['trial_id'] /
                     ('0001-' + row['attempt_id'] + '.json'),
                     'qualification': folder / 'qualification.json',
                     'result': experiment / 'runs' / row['run_id'] / 'result.json',
                     'plan': experiment / 'runs' / row['run_id'] / 'plan.json',
                     'oracle': folder / 'oracle.json',
                     'journal': folder / 'fixture-journal/private/journal.json',
                     'parent_receipt': folder / 'fixture-journal/private/parent-receipt.json',
                     'fixture_terminal': folder / 'fixture-journal/private/terminal-receipt.json',
                     'scripted': folder / 'scripted-observations/private/scripted.json',
                     'services_cleanup': folder / 'services-cleanup.json',
                     'child_completion': folder / 'child-completion.json'}
            for name, path in paths.items():
                _reference(row[name], path)
    return copy.deepcopy(index)


def _read(q, reference, expected=None, maximum=4 * 1024 * 1024):
    path = _reference(reference, expected)
    body = q.preparation._read(path, maximum)
    _require(hashlib.sha256(body).hexdigest() == reference['sha256'])
    return q.c.loads(body, max_bytes=maximum)


def _exclusive(q, path, value):
    body = q.c.canonical(value)
    _require(len(body) <= 4 * 1024 * 1024)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(body); output.flush(); os.fsync(output.fileno())
    except BaseException:
        # Never replace/delete an incomplete immutable input after uncertainty.
        raise


def _compatibility(q, index, review, prior, manifest):
    _exact(review, {'schema', 'document_type', 'status', 'unresolved', 'index_sha256',
                    'prior_source_sha256', 'current_source_sha256', 'runner_sha256',
                    'runner_files_sha256', 'release_contracts_sha256',
                    'changed_qualification_files'})
    _require(type(review['schema']) is int and review['schema'] == 1
             and review['document_type'] == 'application_retained_compatibility_review'
             and review['status'] == 'PASS' and review['unresolved'] == [])
    _require(review['index_sha256'] == q.c.digest(index)
             and review['prior_source_sha256'] == prior['source']['sha256']
             and review['current_source_sha256'] == manifest['source']['sha256'])
    old, new = prior['source'], manifest['source']
    _require(q.c.digest(old['files']) == old['sha256']
             and q.c.digest(new['files']) == new['sha256']
             and q.c.digest(old['runner_files']) == old['runner'])
    for key in ('runner', 'runner_files', 'release_contracts'):
        _require(old[key] == new[key])
    _require(review['runner_sha256'] == new['runner']
             and review['runner_files_sha256'] == q.c.digest(new['runner_files'])
             and review['release_contracts_sha256'] == q.c.digest(new['release_contracts']))
    changed = sorted(name for name in set(old['files']) | set(new['files'])
                     if old['files'].get(name) != new['files'].get(name))
    _require(set(changed) <= SOURCE_CHANGES and review['changed_qualification_files'] == changed)
    for key in ('images', 'endpoint', 'endpoint_sha256', 'fixture_route', 'credential_references',
                'session', 'host_admission', 'negative_oracles', 'sensitive_negative_scope'):
        _require(prior[key] == manifest[key])


def _evidence(q, index, review, manifest):
    prior = _read(q, index['prior_manifest'])
    _require(type(prior['schema']) is int and prior['schema'] == 1 and prior['document_type'] == 'application_client_qualification'
             and prior['prepared_root'] == index['prior_root']
             and prior['planned_container_launches'] == 186
             and not set(prior) & {'predecessor', 'campaign_boundary', 'campaign_amendment',
                                   'retained_requalification'})
    _require(prior['qualification_id'] != manifest['qualification_id'])
    full = q.matrix(prior['images'])
    _require(len(prior['cells']) == len(full))
    for row, expected in zip(prior['cells'], full):
        _require({key: row.get(key) for key in expected} == expected
                 and not set(row) - set(expected) - {'trial_id', 'plan_sha256'})
    validate_index(index, prior['cells'])
    _compatibility(q, index, review, prior, manifest)
    candidate = _read(q, index['prior_candidate'])
    _exact(candidate, {'archive_sha256', 'runner_sha256', 'scope'})
    _sha(candidate['archive_sha256'])
    _require(candidate['runner_sha256'] == prior['source']['runner']
             and candidate['scope'] == 'extracted_candidate')
    state = _read(q, index['prior_state'])
    _require(state['phase'] == 'blocked'
             and set(state['cells']) == set(RETAINED_IDS) | {FAILED_CELL}
             and state['cells'][FAILED_CELL].get('status') == 'BLOCKED')
    if state['active_cell'] is not None:
        active = state['active_cell']; failed = state['cells'][FAILED_CELL]
        _exact(active, {'id', 'pid', 'run_id', 'attempt_id'})
        _require(active['id'] == FAILED_CELL
                 and all(active[key] == failed.get(key) for key in ('run_id', 'attempt_id'))
                 and (active['pid'] is None or type(active['pid']) is int and 0 < active['pid'] < 2**31))
        _uuid(active['run_id']); _uuid(active['attempt_id'])
    ledger = _read(q, index['prior_ledger'])
    _require(ledger['schema'] == 1 and type(ledger['launches']) is list
             and len(ledger['launches']) == 53
             and sum(row['role'] == 'participant' for row in ledger['launches']) == 6
             and all(row['physical'] == 'absent' for row in ledger['launches']))
    # The old ledger is immutable historical evidence.  Its original pure
    # validator has no clock/IO branch without a predecessor.  Do not call its
    # constructor, transaction or snapshot: those update old clocks and files.
    launch = q._launch_module()
    historical = object.__new__(launch.LaunchLedger)
    historical.manifest = launch.validate_manifest(q._launch_manifest(prior))
    historical.expected_daemon = historical.expected_capacity = None
    historical._carry = None
    launch.LaunchLedger._validate(historical, ledger)
    byid = {row['id']: row for row in prior['cells']}
    seen = set()
    scripted = {}
    for row in index['cells']:
        cell = byid[row['cell_id']]
        observed = state['cells'][cell['id']]
        _require(observed.get('status') == 'PASS' and observed.get('attempts') == 1)
        launches = [item for item in ledger['launches'] if item['cell'] == cell['id']]
        _require(launches and all(item['private_cleanup'] is True
                                 and item['role'] in cell['role_limits']
                                 and item['image'] in cell['allowed_images'] for item in launches))
        _require(all(sum(item['role'] == role for item in launches) <= count
                     for role, count in cell['role_limits'].items()))
        for item in launches:
            _sha(item['key']); _sha(item['intent_sha256']); _uuid(item['launch_id'])
            _require(item['key'] not in seen); seen.add(item['key'])
        if row['kind'] == 'admission':
            admission = _read(q, row['admission'])
            if cell['profile'] == 'core':
                q.lab.admit_image(admission, cell['release'])
                _require(admission['id'] == prior['images']['core-' + cell['release']]['id']
                         and admission['platform'] == 'linux/arm64')
            else:
                _require(q._browser_admitted(admission, cell))
            continue
        _require(observed.get('run_id') == row['run_id']
                 and observed.get('attempt_id') == row['attempt_id'])
        experiment = Path(index['prior_root']) / ('scripted-' + cell['release'])
        if cell['release'] not in scripted:
            metadata, mapping = q.experiments.verify(experiment, q.lab)
            _require(metadata['schema'] == 1
                     and metadata['runner_content_sha256'] == prior['source']['runner']
                     and metadata['release_contracts'] == prior['source']['release_contracts'])
            scripted[cell['release']] = (metadata, mapping)
        metadata, mapping = scripted[cell['release']]
        trials = [trial for trial in mapping['cells'] if trial['trial_id'] == cell['trial_id']]
        _require(len(trials) == 1 and trials[0]['case'] == cell['case']
                 and trials[0]['variant'] == cell['variant']
                 and trials[0]['plan_sha256'] == cell['plan_sha256'])
        intent = _read(q, row['attempt_intent'])
        originals = q.experiments.attempt_intents(experiment, trials[0])
        _require(len(originals) == 1 and originals[0] == intent)
        _require(intent['status'] == 'finalized' and intent['attempt_index'] == 1
                 and intent['retry_of_attempt_id'] is None
                 and intent['trial_id'] == cell['trial_id']
                 and intent['run_id'] == row['run_id'] and intent['attempt_id'] == row['attempt_id']
                 and intent['result'] == 'runs/' + row['run_id'] + '/result.json'
                 and intent['result_sha256'] == row['result']['sha256'])
        result = _read(q, row['result'])
        # Original sealed-result validator preserves all status/dimension/identity checks.
        checked = q.experiments.sealed_result(Path(index['prior_root']) /
                    ('scripted-' + cell['release']), intent)
        _require(result == checked)
        _require(result['run_id'] == row['run_id'] and result['attempt_id'] == row['attempt_id'])
        plan = _read(q, row['plan'])
        _require(plan['plan_sha256'] == cell['plan_sha256']
                 and q.c.digest({key: value for key, value in plan.items() if key != 'plan_sha256'}) == cell['plan_sha256']
                 and len(plan['stages']) == 1 and q._runtime_valid(result, plan['stages'][0]))
        oracle = _read(q, row['oracle']); journal = _read(q, row['journal'])
        parent = _read(q, row['parent_receipt']); terminal = _read(q, row['fixture_terminal'])
        oracle_module = q._module('retained_application_oracle', q.EXAMPLE / 'oracle.py')
        _require(oracle_module.stop_gate(parent) and oracle_module.fixture_stopped(terminal)
                 and parent['run']['result_sha256'] == row['result']['sha256']
                 and parent['fixture']['terminal_sha256'] == row['fixture_terminal']['sha256']
                 and terminal['journal']['sha256'] == row['journal']['sha256'])
        recomputed = oracle_module.evaluate(Path(row['result']['path']).parent,
                                            Path(row['journal']['path']).parent, parent)
        _require(oracle == recomputed)
        script = _read(q, row['scripted']); services = _read(q, row['services_cleanup'])
        completion = _read(q, row['child_completion'])
        _require(services.get('safe_to_continue') is True
                 and completion == {'schema': 1, 'run_id': row['run_id'],
                    'attempt_id': row['attempt_id'], 'result_sha256': row['result']['sha256'],
                    'cleanup_checked': True})
        verdict = q.negative_verdict(cell['scenario'], result, journal, oracle)
        script_ok = (script.get('case_id') == cell['case']
                     and script.get('model') == 'application-script-' + cell['variant']
                     and script.get('stopped') is True and script.get('unexpected_results') == 0
                     and script.get('tool_results') == q.SCRIPT_RESULTS[cell['scenario']]
                     and script.get('emitted_tool_calls') == q.SCRIPT_RESULTS[cell['scenario']]
                     and script.get('usage_accounting') == 'synthetic_fixed_16_16')
        verdict['checks']['scripted_result_sequence'] = script_ok
        verdict['status'] = 'PASS' if all(verdict['checks'].values()) else 'FAIL'
        qualification = _read(q, row['qualification'])
        _require(verdict['status'] == 'PASS' and qualification == {
            'cell_id': cell['id'], 'run_id': row['run_id'], 'attempt_id': row['attempt_id'],
            'result_sha256': row['result']['sha256'], 'real_model': False, **verdict})
    return prior, ledger


def effective_limits(manifest):
    marker = manifest.get('retained_requalification')
    validate_marker(marker)
    limits = dict(LIMITS)
    if 'schema' in manifest:
        limits['simultaneously_registered_live_container_intents'] = limits.pop('live')
        limits.update(automatic_retries=0, continuations=0)
    return limits


def validate_marker(marker):
    _exact(marker, {'schema', 'mode', 'retained_index', 'compatibility_review',
                    'historical_use', 'local_plan', 'cumulative_ceiling'})
    _require(type(marker['schema']) is int and marker['schema'] == 1 and marker['mode'] == MODE
             and marker['historical_use'] == HISTORICAL_USE and marker['local_plan'] == LOCAL_PLAN
             and marker['cumulative_ceiling'] == CUMULATIVE_CEILING)
    _reference(marker['retained_index']); _reference(marker['compatibility_review'])
    return copy.deepcopy(marker)


def launch_manifest(q, manifest):
    validate_marker(manifest['retained_requalification'])
    return {'qualification_id': manifest['qualification_id'], 'images': copy.deepcopy(manifest['images']),
            'cells': [{name: cell[name] for name in LAUNCH_FIELDS} for cell in manifest['cells']],
            'limits': dict(LIMITS), 'planned_container_launches': 140,
            'retained_requalification': copy.deepcopy(manifest['retained_requalification'])}


def prepare(q, root, *, retained_index, compatibility, freeze_kwargs):
    """Freeze ordinary inputs first; seal the new mode before candidate binding."""
    _require(type(freeze_kwargs) is dict
             and not set(freeze_kwargs) & {'predecessor', 'campaign_boundary', 'campaign_amendment', 'candidate_identity'})
    index = q.read(retained_index) if isinstance(retained_index, (str, Path)) else copy.deepcopy(retained_index)
    review = q.read(compatibility) if isinstance(compatibility, (str, Path)) else copy.deepcopy(compatibility)
    # Reject historical-root overlap and malformed role paths before the normal
    # freezer can create any input directory or file.
    _require(type(index) is dict and 'prior_root' in index and 'prior_manifest' in index)
    root = _path(str(Path(root).absolute())); oldroot = _path(index['prior_root'])
    _require(root != oldroot and root not in oldroot.parents and oldroot not in root.parents)
    prior = _read(q, index['prior_manifest'], oldroot / 'manifest.json')
    validate_index(index, prior['cells'])
    parent = q.preparation._directory(root.parent)
    os.close(parent)
    q.freeze(root, **freeze_kwargs)
    manifest = q.read(root / 'manifest.json')
    _, fresh = partition(manifest['cells'])
    _evidence(q, index, review, manifest)
    for name, value in (('retained-evidence-index.json', index), ('retained-compatibility-review.json', review)):
        _exclusive(q, root / name, value)
        manifest['files'][name] = q.sha(root / name)
    manifest['retained_requalification'] = {
        'schema': 1, 'mode': MODE,
        'retained_index': {'path': str(root / 'retained-evidence-index.json'), 'sha256': q.sha(root / 'retained-evidence-index.json')},
        'compatibility_review': {'path': str(root / 'retained-compatibility-review.json'), 'sha256': q.sha(root / 'retained-compatibility-review.json')},
        'historical_use': dict(HISTORICAL_USE), 'local_plan': dict(LOCAL_PLAN),
        'cumulative_ceiling': dict(CUMULATIVE_CEILING)}
    manifest['cells'] = fresh; manifest['planned_container_launches'] = 140
    manifest['limits'] = effective_limits(manifest)
    q.atomic(root / 'manifest.json', manifest)
    q.atomic(root / 'integrity.json', {'manifest_sha256': q.sha(root / 'manifest.json')})
    verify(q, root)
    return root


def _actual_state(q, root, manifest, state):
    """A fresh PASS row is usable only with its owning result/cleanup receipt."""
    byid = {cell['id']: cell for cell in manifest['cells']}
    for name, observed in state['cells'].items():
        cell = byid[name]
        _require(type(observed) is dict and observed.get('status') in ('started', 'PASS', 'FAIL', 'BLOCKED')
                 and type(observed.get('attempts')) is int and observed['attempts'] == 1)
        _uuid(observed.get('run_id')); _uuid(observed.get('attempt_id'))
        if observed['status'] not in ('PASS', 'FAIL'):
            continue
        folder = root / 'cells' / name
        run = (root / ('scripted-' + cell['release']) / 'runs' if cell['group'] == 'N02'
               else folder / 'runs') / observed['run_id']
        qualification = q.read(folder / 'qualification.json')
        body = q.preparation._read(run / 'result.json', 4 * 1024 * 1024)
        digest = hashlib.sha256(body).hexdigest(); result = q.c.loads(body, max_bytes=4 * 1024 * 1024)
        _require(qualification['cell_id'] == name and qualification['run_id'] == observed['run_id']
                 and qualification['attempt_id'] == observed['attempt_id']
                 and qualification['result_sha256'] == digest and qualification['status'] == observed['status']
                 and qualification['real_model'] is cell['real_model']
                 and result['run_id'] == observed['run_id'] and result['attempt_id'] == observed['attempt_id']
                 and result['sealed'] is True and observed['runner_status'] == result['status']
                 and type(result['exit_code']) is int
                 and type(observed['exit_code']) is int and observed['exit_code'] == result['exit_code']
                 and q.outcomes.status(result) == (result['status'], result['exit_code'])
                 and q.read(folder / 'child-completion.json') == {
                     'schema': 1, 'run_id': observed['run_id'], 'attempt_id': observed['attempt_id'],
                     'result_sha256': digest, 'cleanup_checked': True})
        if cell['group'] == 'N02':
            _require(qualification['status'] == 'PASS' and type(qualification.get('checks')) is dict
                     and qualification['checks'] and all(value is True for value in qualification['checks'].values()))
            if cell['scenario'] == 'sensitive-participant-interruption':
                _require(observed.get('interruption_sent') is True
                         and qualification['checks'].get('signal_sent') is True
                         and result['status'] == 'INTERRUPTED')


def verify(q, root, *, require_candidate=False):
    root = Path(root).absolute(); manifest = q.read(root / 'manifest.json'); state = q.read(root / 'state.json')
    _require(not set(manifest) & {'predecessor', 'campaign_boundary', 'campaign_amendment'})
    marker = validate_marker(manifest['retained_requalification'])
    _reference(marker['retained_index'], root / 'retained-evidence-index.json')
    _reference(marker['compatibility_review'], root / 'retained-compatibility-review.json')
    _require(q.read(root / 'integrity.json') == {'manifest_sha256': q.sha(root / 'manifest.json')}
             and type(manifest['schema']) is int and manifest['schema'] == 1 and manifest['document_type'] == 'application_client_qualification'
             and manifest['prepared_root'] == str(root) and manifest['source'] == q.source_identity()
             and manifest['limits'] == effective_limits(manifest)
             and all(type(value) is int for value in manifest['limits'].values())
             and type(manifest['planned_container_launches']) is int and manifest['planned_container_launches'] == 140)
    _require(manifest['negative_oracles'] == {'tool_results': q.SCRIPT_RESULTS,
             'reserve_counts': q.RESERVE_COUNTS, 'reserve_remaining': 6,
             'scope': 'expected negative failures are qualification assertions, never model task success'}
             and manifest['sensitive_negative_scope'] == q.SENSITIVE_SCOPE)
    _require(manifest['host_admission'] == {'lock_file': str(Path(q.lab.default_lock_file()).expanduser().absolute()),
                                         'wait_seconds': 30})
    _, expected = partition(q.matrix(manifest['images']))
    _require(len(manifest['cells']) == 19)
    for cell, original in zip(manifest['cells'], expected):
        _require({key: cell.get(key) for key in original} == original
                 and not set(cell) - set(original) - {'trial_id', 'plan_sha256'})
    q._launch_module().validate_manifest(launch_manifest(q, manifest))
    for path, digest in manifest['files'].items():
        q.c.relative(path, '/files'); _sha(digest)
        _require(q.sha(root / path) == digest)
    index = _read(q, marker['retained_index']); review = _read(q, marker['compatibility_review'])
    _evidence(q, index, review, manifest)
    _exact(state, {'schema', 'phase', 'active_cell', 'cells', 'started_at'})
    _require(type(state['schema']) is int and state['schema'] == 1
             and state['phase'] in ('frozen', 'admitting', 'images_admitted', 'collecting', 'blocked')
             and type(state['cells']) is dict and not set(state['cells']) - set(FRESH_IDS))
    if state['phase'] == 'frozen':
        _require(not state['cells'] and state['active_cell'] is None and state['started_at'] is None)
    else:
        _require(type(state['started_at']) in (int, float) and math.isfinite(state['started_at'])
                 and state['started_at'] > 0)
    _actual_state(q, root, manifest, state)
    if require_candidate:
        bound = q.read(root / 'candidate.json')
        _exact(bound, {'archive_sha256', 'runner_sha256', 'scope'}); _sha(bound['archive_sha256'])
        _require(bound['runner_sha256'] == manifest['source']['runner'] and bound['scope'] == 'extracted_candidate')
    return manifest, state


def admit(q, root):
    """Activate only the fresh ledger; retained infrastructure is never rerun."""
    root = Path(root).absolute()
    with q.controller(root):
        manifest, state = verify(q, root, require_candidate=True)
        _require(state['phase'] == 'frozen' and not state['cells'])
        q._endpoint(root / 'inputs/endpoint.json', manifest['session'])
        values = q._known_values(manifest); q._scan_frozen(root, manifest, values)
        state.update(started_at=q.time.time(), phase='admitting'); q.atomic(root / 'state.json', state)
        try:
            with q._deadline_signal(root):
                index = _read(q, manifest['retained_requalification']['retained_index'])
                old = _read(q, index['prior_ledger'])
                daemon, capacity = q._native()
                _require(daemon == old['daemon'] and capacity == old['daemon_capacity'])
                q._launch_module().LaunchLedger.create(root / 'launch-ledger', launch_manifest(q, manifest),
                                                     daemon_id=daemon, daemon_capacity=capacity)
            state['phase'] = 'images_admitted'; q.atomic(root / 'state.json', state)
        except BaseException:
            state['phase'] = 'blocked'; q.atomic(root / 'state.json', state); raise


def _scripted(q, root, manifest, selected, values):
    """Original primary reservation/seal/cleanup protocol for an exact subset."""
    exp = q.experiments; path = root / ('scripted-' + selected[0]['release'])
    with exp.controller_lock(path):
        metadata, mapping = exp.verify(path, q.lab)
        _require(metadata['schema'] == 1 and metadata['policies'] == {
            'primary_attempt': 'first', 'assistance': 'exclude', 'on_failure': 'continue', 'max_attempts': 1})
        work = []
        for cell in selected:
            rows = [row for row in mapping['cells'] if row['trial_id'] == cell['trial_id']]
            _require(len(rows) == 1 and rows[0]['case'] == cell['case'] and rows[0]['variant'] == cell['variant'])
            work.append(rows[0])
        _require(not any(exp.attempt_intents(path, row) for row in mapping['cells']))
        previous = exp.controller_state(path)
        _require(previous['status'] == 'prepared' and previous['active_attempt_id'] is None)
        private = q.application_experiments.admit_work(path, metadata, work, q.lab, manifest['session'])
        redactions = list(dict.fromkeys([*values, *private['redaction_values']]))
        exp.directory(path, 'runs'); exp.directory(path, 'logs')
        state = {'schema': 1, 'status': 'running', 'active_attempt_id': None, 'started_at': q.controls.now()}
        q.atomic(path / 'state.json', state); completed = 0
        try:
            for cell, trial in zip(selected, work):
                checked, remapping = exp.verify(path, q.lab)
                _require(checked == metadata and trial in remapping['cells'])
                intent, intent_path = exp.reserve_attempt(path, metadata, trial)
                state['active_attempt_id'] = intent['attempt_id']; q.atomic(path / 'state.json', state)
                args = exp.trial_args(path, metadata, trial, q.lab, manifest['session'])
                _require(Path(args.compiled_plan) == path / trial['compiled_plan'])
                with (path / 'logs' / (intent['attempt_id'] + '.txt')).open('w') as output, q.contextlib.redirect_stdout(output):
                    q._invoke_cell(root, manifest, cell, copy.deepcopy(intent['initial_record']), redactions)
                result = exp.sealed_result(path, intent)
                _require(result is not None)
                relative = 'runs/' + intent['run_id'] + '/result.json'
                intent.update(status='finalized', result=relative, result_sha256=q.sha(path / relative))
                q.atomic(intent_path, intent); completed += 1
                state['active_attempt_id'] = None; q.atomic(path / 'state.json', state)
                _require(exp.cleanup_known(path, intent, result))
                if result['status'] == 'INTERRUPTED':
                    # Only the last selected sensitive negative can end this way;
                    # _invoke_cell has already required the original signal oracle.
                    _require(cell['scenario'] == 'sensitive-participant-interruption' and completed == len(selected))
                    state['status'] = 'interrupted'; break
            else:
                state['status'] = 'completed'
        except BaseException:
            state['status'] = 'blocked'; q.atomic(path / 'state.json', state); raise
        q.atomic(path / 'state.json', state)
        _require(completed == len(selected))


def collect(q, root, *, group, release):
    root = Path(root).absolute(); _require((group, release) in PHASES)
    with q.controller(root), q._deadline_signal(root, reserve=False):
        manifest, state = verify(q, root, require_candidate=True)
        _require(state['phase'] in ('images_admitted', 'collecting') and state['active_cell'] is None)
        pending = next((phase for phase in PHASES if any(
            cell['id'] not in state['cells'] for cell in manifest['cells']
            if (cell['group'], cell['release']) == phase)), None)
        _require(pending == (group, release))
        selected = [cell for cell in manifest['cells'] if (cell['group'], cell['release']) == pending]
        _require(selected and all(cell['id'] not in state['cells'] for cell in selected))
        _require(all(state['cells'].get(cell['id'], {}).get('status') == 'PASS'
                     for cell in manifest['cells'] if cell['group'] == 'N02' and group != 'N02'))
        q._endpoint(root / 'inputs/endpoint.json', manifest['session'])
        values = q._known_values(manifest); q._scan_frozen(root, manifest, values)
        state['phase'] = 'collecting'; q.atomic(root / 'state.json', state)
        try:
            if group == 'N02':
                _scripted(q, root, manifest, selected, values)
            else:
                for cell in selected:
                    q._invoke_cell(root, manifest, cell, q.outcomes.initial(), values)
        except BaseException:
            state = q.read(root / 'state.json'); state['phase'] = 'blocked'
            q.atomic(root / 'state.json', state); raise
    return report(q, root)


def report(q, root):
    manifest, state = verify(q, root); rows = []
    for cell in q.matrix(manifest['images']):
        retained = cell['id'] in RETAINED_IDS
        observed = state['cells'].get(cell['id'], {}) if not retained else {}
        _require(type(observed) is dict and observed.get('status', 'NOT_RUN') in
                 ('started', 'PASS', 'FAIL', 'BLOCKED', 'NOT_RUN')
                 and observed.get('runner_status') in
                 (None, 'PASS', 'FAIL', 'BLOCKED', 'INTERRUPTED', 'ASSISTED', 'RECOVERED')
                 and type(observed.get('attempts', 0)) is int and observed.get('attempts', 0) in (0, 1))
        rows.append({'id': cell['id'], 'group': cell['group'], 'release': cell['release'],
                     'real_model': cell['real_model'], 'origin': 'retained' if retained else 'new',
                     'status': 'PASS' if retained else observed.get('status',
                         'BLOCKED' if state['phase'] == 'blocked' else 'NOT_RUN'),
                     'attempts_this_scope': 0 if retained else observed.get('attempts', 0),
                     'runner_status': None if retained else observed.get('runner_status'),
                     'scope': 'real_model' if cell['real_model'] else
                         'native_scripted_negative' if cell['group'] == 'N02' else 'infrastructure'})
    return {'schema': 1, 'qualification_id': manifest['qualification_id'],
            'document_type': 'application_retained_qualification_report',
            'status': 'PASS' if all(row['status'] == 'PASS' for row in rows) else 'NOT_READY',
            'cells': rows, 'retained_cells': 9, 'fresh_cells': 19,
            'planned_participant_segments': 24, 'scripted_cells': 12, 'real_model_cells': 12,
            'retained_evidence': copy.deepcopy(manifest['retained_requalification']),
            'historical_use': dict(HISTORICAL_USE), 'local_plan': dict(LOCAL_PLAN),
            'cumulative_ceiling': dict(CUMULATIVE_CEILING), 'limits': manifest['limits'],
            'excluded_failed_cell': {'id': FAILED_CELL, 'status': 'BLOCKED', 'retained': False},
            'sensitive_negative_scope': q.SENSITIVE_SCOPE}
