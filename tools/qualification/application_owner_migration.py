"""Bounded offline owner-evidence assessment; never a cleanup proof producer.

Legacy facts retain their original references and nonzero exit codes. This tool
does not publish an acceptance index, synthesize invocation/snapshot witnesses,
probe a PID/daemon, read credentials, or execute an adapter selected by input.
The CLI emits a closed nonsecret summary; the Python API retains private paths.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'skill/scripts'), str(ROOT / 'skill/runtime')]
import application_owner_cleanup as cleanup
import ownership_registry as ownership

KINDS = {'launch_ledger', 'launcher_start', 'launcher_terminal', 'controller_start',
         'controller_terminal', 'stage_descriptor', 'empty_root', 'identity_timing',
         'worker_custody', 'diagnostic_overlay', 'retained_predicate', 'guard_identity', 'native_request',
         'supervised_start', 'supervised_terminal', 'evidence_locations', 'controller_verification',
         'artifact_diagnostic_terminal'}
START_FIELDS = {'schema', 'ordinal', 'kind', 'pid', 'parent_pid', 'started_monotonic',
                'started_wall', 'handle_returned'}
TERMINAL_FIELDS = {'schema', 'ordinal', 'kind', 'pid', 'actual_exit', 'returncode',
                   'wait_confirmed', 'unknown_owned_child', 'failure_class'}
REMAINING = ['fresh_original_lease_and_record_check', 'fresh_writer_and_daemon_observations',
             'pending_overlapping_holder_check', 'exact_discard_authority', 'durable_cleanup_and_replay']


class AssessmentError(ValueError):
    def __init__(self, condition='assessment_input_invalid'):
        super().__init__(condition); self.condition = condition


def need(value, condition='assessment_input_invalid'):
    if not value:raise AssessmentError(condition)


def exact(value, fields):
    need(type(value) is dict and set(value) == set(fields))


def integer(value, minimum=0, maximum=2**63-1):
    return type(value) is int and minimum <= value <= maximum


def _capture(reader, reference, launch):
    exact(reference, {'path', 'sha256'})
    value, observed = reader.read(reference['path'], private=True); need(reference == observed); cleanup.canonical(value)
    exact(value, {'schema', 'document_type', 'captured_at', 'lease', 'original_reference',
                  'record', 'related_records', 'source', 'admission_authorized', 'cleanup_authorized'})
    need(type(value['schema']) is int and value['schema'] == 1
         and value['document_type'] == 'application_owner_migration_record_capture'
         and type(value['captured_at']) is str and 0 < len(value['captured_at']) <= 128
         and type(value['source']) is str and 0 < len(value['source']) <= 512
         and value['admission_authorized'] is False and value['cleanup_authorized'] is False)
    exact(value['lease'], {'device', 'inode'})
    need(integer(value['lease']['device']) and integer(value['lease']['inode'], 1))
    exact(value['original_reference'], {'path', 'sha256'})
    cleanup.path(value['original_reference']['path'])
    need(type(value['original_reference']['sha256']) is str
         and len(value['original_reference']['sha256']) == 64
         and all(c in '0123456789abcdef' for c in value['original_reference']['sha256']))
    record = value['record']; subject = cleanup.subject(record)
    need(subject['launch_id'] == launch and record.get('status') == 'released')
    cleanup.path(record['runroot']); need(integer(record.get('owner_pid'), 1, 2**31-1))
    related = value['related_records']; need(type(related) is list and 1 <= len(related) <= 64)
    ids = []
    for row in related:
        need(type(row) is dict and cleanup.controls.valid_id(row.get('launch_id'))
             and all(row.get(k) == record.get(k) for k in ('runroot', 'registry', 'generation', 'daemon'))
             and row.get('kind', 'container') == 'container')
        ids.append(row['launch_id'])
    need(len(ids) == len(set(ids)) and sum(row == record for row in related) == 1)
    return record, related, subject


def _supervised(starts, terminals, record):
    result = []
    for body, ref in terminals:
        need(type(body.get('schema')) is int and body['schema'] == 1
             and body.get('child_pid') == record['owner_pid']
             and integer(body.get('wrapper_pid'), 1, 2**31-1)
             and integer(body.get('actual_exit'), -255, 255))
        if 'document_type' in body:
            exact(body, {'schema', 'document_type', 'status', 'child_pid', 'wrapper_pid', 'wait_completed',
                'actual_exit', 'unknown_owned_child', 'elapsed_seconds', 'program_sha256', 'inputs_sha256',
                'authorization', 'window', 'credential_values_opened_by_supervisor',
                'helper_cleanup_or_keyfree_attested_by_supervisor', 'automatic_retry_performed'})
            need(body['document_type'] == 'future_helper_startup_diagnostic_command'
                 and body['wait_completed'] is True and body['unknown_owned_child'] is False
                 and body['credential_values_opened_by_supervisor'] is False
                 and body['helper_cleanup_or_keyfree_attested_by_supervisor'] is False
                 and body['automatic_retry_performed'] is False, 'legacy_wait_unconfirmed')
        else:
            exact(body, {'schema', 'status', 'actual_exit', 'child_pid', 'wrapper_pid', 'child_wait_confirmed',
                'automatic_retries', 'container_or_private_actions_by_supervisor', 'elapsed_seconds',
                'inputs', 'program', 'source_review'})
            need(body['child_wait_confirmed'] is True and type(body['automatic_retries']) is int
                 and body['automatic_retries'] == 0 and type(body['container_or_private_actions_by_supervisor']) is int
                 and body['container_or_private_actions_by_supervisor'] == 0, 'legacy_wait_unconfirmed')
        matches = [(start, reference) for start, reference in starts
                   if start.get('pid', start.get('child_pid')) == body['child_pid']
                   and start.get('wrapper_pid') == body['wrapper_pid']]
        need(len(matches) == 1, 'legacy_process_binding_mismatch')
        start, reference = matches[0]
        common = {'schema', 'wrapper_pid', 'argv'}
        need(set(start) in (common | {'pid', 'started', 'started_wall'},
                            common | {'child_pid', 'credential_values_opened_by_supervisor'}))
        need(type(start['schema']) is int and start['schema'] == 1 and type(start['argv']) is list
             and 1 <= len(start['argv']) <= 256 and all(type(a) is str and 0 < len(a) <= 8192
                 and not any(ord(c) < 32 or ord(c) == 127 for c in a) for a in start['argv']))
        if 'credential_values_opened_by_supervisor' in start:
            need(start['credential_values_opened_by_supervisor'] is False)
        result.append({'launch_id': None, 'pid': body['child_pid'], 'actual_exit': body['actual_exit'],
                       'wait_confirmed': True, 'argv_recorded': True, 'cwd_recorded': False,
                       'provenance': [reference, ref]})
    return result


def _ledger(body, reference, record, related, rows):
    need(type(body.get('schema')) is int and body['schema'] == 1
         and body.get('daemon') == record['daemon'] and type(body.get('launches')) is list
         and len(body['launches']) <= 8192)
    ids = []; by_id = {row['launch_id']: row for row in related}
    for row in body['launches']:
        need(type(row) is dict and cleanup.controls.valid_id(row.get('launch_id')))
        ids.append(row['launch_id'])
        if row['launch_id'] not in by_id:continue
        original = by_id[row['launch_id']]
        need(all(row.get(k) == original.get(k) for k in ('registry', 'generation', 'container', 'image')),
             'legacy_ledger_binding_mismatch')
        cid = row.get('container_id')
        need(cid is None or type(cid) is str and len(cid) == 64 and cid != '0' * 64
             and all(c in '0123456789abcdef' for c in cid), 'legacy_ledger_binding_mismatch')
        if original.get('container_id') is not None:
            need(cid == original['container_id'], 'legacy_ledger_binding_mismatch')
        excluded = {'status', 'container_id'}
        specialized = any(key in original for key in ('qualification_role', 'qualification_service_cleanup',
                                                       'qualification_preworker_cleanup'))
        if specialized:
            role = original.get('qualification_role')
            need(role in ('fixture', 'scripted-inference') and original.get('application_helper') is True
                 and original.get('client_mode') == 'qualification-' + role, 'unsupported_qualification_subtype')
            # The original qualification ledger excludes these later proof
            # attachments (application_launch._intent_identity). Ordinary
            # subjects retain their distinct full immutable-intent rule.
            excluded |= {'qualification_service_cleanup', 'qualification_preworker_cleanup'}
        immutable = {key: value for key, value in original.items() if key not in excluded}
        need(row.get('intent_sha256') == cleanup.digest(immutable), 'legacy_intent_binding_mismatch')
        pid = row.get('pid'); need(pid is None or integer(pid, 1, 2**31-1))
        fact = {'pid': pid, 'container_id': cid, 'reference': reference,
                'intent_rule': 'qualification_v1' if specialized else 'ordinary_v1'}
        if row['launch_id'] in rows:need(rows[row['launch_id']] == fact, 'legacy_ledger_binding_mismatch')
        rows[row['launch_id']] = fact
    need(len(ids) == len(set(ids)), 'duplicate_legacy_launch')


def _located_controllers(indices, verifications, record):
    result = []
    for body, reference in verifications:
        locations = []
        for index, index_ref in indices:
            need(type(index.get('schema_version')) is int and index['schema_version'] == 1
                 and type(index.get('cases')) is list and len(index['cases']) <= 32)
            matches = [case for case in index['cases'] if type(case) is dict
                       and case.get('launch_id') == record['launch_id']]
            need(len(matches) == 1, 'controller_location_mismatch')
            case = matches[0]; original = case.get('controller_terminal')
            need(type(original) is dict)
            if {key: original.get(key) for key in ('path', 'sha256')} == reference:
                locations.append((case, index_ref))
        need(len(locations) == 1, 'controller_location_mismatch')
        case, index_ref = locations[0]
        need(integer(body.get('actual_exit'), -255, 255)
             and type(case.get('controller_actual_exit')) is int
             and body['actual_exit'] == case['controller_actual_exit'], 'controller_exit_mismatch')
        if 'schema' in body:need(type(body['schema']) is int and body['schema'] == 1)
        if 'argv' in body:
            need(type(body['argv']) is list and 1 <= len(body['argv']) <= 256
                 and all(type(arg) is str and 0 < len(arg) <= 8192 for arg in body['argv']))
        if 'cwd' in body:cleanup.path(body['cwd'])
        # The index locates this record. It is not an original process witness,
        # PID binding, caller authorization or a completed custody graph.
        result.append({'actual_exit': body['actual_exit'], 'argv_recorded': 'argv' in body,
            'cwd_recorded': 'cwd' in body, 'owner_pid_binding': None,
            'association': 'owner_supplied_location_index', 'provenance': [index_ref, reference]})
    return result


def _process(body, terminal=False):
    fields = TERMINAL_FIELDS if terminal else START_FIELDS
    need(type(body) is dict and set(body) <= fields
         and type(body.get('schema')) is int and body['schema'] == 1
         and integer(body.get('pid'), 1, 2**31-1) and integer(body.get('ordinal'), 1, 8192))
    if terminal:
        need(('actual_exit' in body) != ('returncode' in body))
        code = body.get('actual_exit', body.get('returncode'))
        need(integer(code, -255, 255) and body.get('wait_confirmed') is True
             and body.get('unknown_owned_child') is False, 'legacy_wait_unconfirmed')
    else:
        need(type(body.get('kind')) is str and 0 < len(body['kind']) <= 128
             and (integer(body.get('parent_pid'), 1, 2**31-1)
                  or 'parent_pid' not in body and body['kind'] == 'diagnostic_container_cli'))


def _terminals(starts, terminals, record, ledgers, controller=False):
    result = []; seen = set()
    for body, ref in terminals:
        _process(body, True)
        matches = [(start, source) for start, source in starts if start['pid'] == body['pid']]
        need(len(matches) == 1, 'legacy_process_binding_mismatch')
        start, source = matches[0]
        need(body['ordinal'] == start['ordinal'] and body['pid'] not in seen
             and ('kind' not in body or body['kind'] == start['kind']), 'legacy_process_binding_mismatch')
        seen.add(body['pid']); provenance = [source, ref]
        if controller:
            need(body['pid'] == record['owner_pid'], 'legacy_process_binding_mismatch')
        else:
            need(start['kind'] in ('helper_container_cli', 'diagnostic_container_cli')
                 and ('parent_pid' not in start or start['parent_pid'] == record['owner_pid']),
                 'legacy_process_binding_mismatch')
            matches = [launch for launch, row in ledgers.items() if row['pid'] == body['pid']]
            need(len(matches) == 1, 'legacy_process_binding_mismatch')
            provenance.append(ledgers[matches[0]]['reference'])
        result.append({'launch_id': None if controller else matches[0],
                       'pid': body['pid'], 'actual_exit': body.get('actual_exit', body.get('returncode')),
                       'argv_recorded': False, 'cwd_recorded': False,
                       'parent_binding': 'recorded' if 'parent_pid' in start else 'not_recorded',
                       'wait_confirmed': True, 'provenance': provenance})
    return result


def _case(reader, case):
    exact(case, {'launch_id', 'capture', 'sources'}); need(cleanup.controls.valid_id(case['launch_id']))
    record, related, subject = _capture(reader, case['capture'], case['launch_id'])
    sources = case['sources']; need(type(sources) is list and len(sources) <= 64)
    by_kind = {kind: [] for kind in KINDS}; seen = set(); ledgers = {}; snapshots = []; stages = []; overlays = []; disposable = []
    for source in sources:
        exact(source, {'kind', 'reference'}); need(type(source['kind']) is str and source['kind'] in KINDS)
        key = cleanup.canonical(source); need(key not in seen); seen.add(key)
        body = reader.reference(source['reference']); cleanup.canonical(body)
        kind = source['kind']; ref = source['reference']
        by_kind[kind].append((body, ref))
        if kind == 'launch_ledger':_ledger(body, ref, record, related, ledgers)
        elif kind in ('launcher_start', 'controller_start'):_process(body)
        elif kind == 'stage_descriptor':
            need(type(body.get('schema')) is int and body['schema'] in (1, 2)
                 and cleanup.controls.valid_id(body.get('stage_id'))
                 and body.get('kind') in ('agent', 'check', 'probe', 'preflight', 'boundary', 'browser')
                 and body.get('workspace') == str(Path(record['runroot']) / 'workspace')
                 and all(body.get(k) == record['binding'][k] for k in ('run_id', 'attempt_id') if k in record['binding']))
            identity = body.get('workspace_identity')
            need(type(identity) is list and len(identity) == 2 and integer(identity[0]) and integer(identity[1], 1))
            snapshots.append((identity, ref)); stages.append(body)
        elif kind == 'identity_timing':
            need(body.get('schema') == 1 and type(body.get('schema')) is int
                 and body.get('document_type') == 'qualification_helper_identity_timing'
                 and type(body.get('identity')) is dict and body['identity'].get('launch_id') == record['launch_id'])
        elif kind == 'worker_custody':
            need(body.get('schema') == 1 and type(body.get('schema')) is int
                 and body.get('document_type') == 'interruption_diagnostic_parent_custody'
                 and body.get('worker_pid') == record['owner_pid'])
        elif kind == 'diagnostic_overlay':
            need(body.get('schema') == 1 and type(body.get('schema')) is int
                 and body.get('document_type') == 'qualification_failed_startup_diagnostic_known_cleanup'
                 and body.get('driver_status') == 'BLOCKED' and body.get('cleanup_accounting') == 'FAILED'
                 and body.get('native_success_attested') is False)
            release = reader.reference(body.get('metadata_release')); cleanup.canonical(release)
            need(type(release.get('schema')) is int and release['schema'] == 1
                 and release.get('document_type') == 'qualification_diagnostic_metadata_release'
                 and release.get('qualification_id') == body.get('qualification_id')
                 and release.get('container_id') == record.get('container_id')
                 and release.get('metadata_only_reporting') is True and release.get('raw_ledger_preserved') is True)
            original = reader.reference(release.get('original_helper_record'))
            need(cleanup.subject(original) == subject, 'diagnostic_subject_mismatch')
            overlays.append({'driver_status': 'BLOCKED', 'cleanup_accounting': 'FAILED',
                'native_success_attested': False,
                'provenance': [ref, body['metadata_release'], release['original_helper_record']]})
        elif kind == 'retained_predicate':
            need(type(body.get('schema')) is int and body['schema'] == 1
                 and body.get('document_type') == 'matrix20_retained_predicate_subject')
        elif kind == 'empty_root':
            need(type(body.get('schema')) is int and body['schema'] == 1
                 and type(body.get('path')) is str and integer(body.get('device')) and integer(body.get('inode'), 1))
            # An empty/current helper-directory observation is not original
            # snapshot custody, even when somebody labels its path workspace.
        elif kind == 'artifact_diagnostic_terminal':
            need(type(body.get('schema')) is int and body['schema'] == 1
                 and body.get('document_type') == 'bounded_artifact_write_diagnostic_terminal'
                 and record.get('container_id') is not None and body.get('container_id') == record['container_id'])
            root = cleanup.path(body.get('disposable_root')); identity = body.get('disposable_root_identity')
            need(root.is_relative_to(Path(record['runroot'])) and type(identity) is list and len(identity) == 2
                 and integer(identity[0]) and integer(identity[1], 1)
                 and {mount['source'] for mount in record['mounts']} == {str(root / name) for name in ('code', 'state', 'evidence')})
            disposable.append({'path': str(root), 'identity': identity, 'provenance': [ref],
                               'scope': 'diagnostic_disposable_root_not_workspace'})
    need(len({body['stage_id'] for body in stages}) == len(stages))
    need(not snapshots or all(pair[0] == snapshots[0][0] for pair in snapshots), 'snapshot_binding_mismatch')
    launchers = _terminals(by_kind['launcher_start'], by_kind['launcher_terminal'], record, ledgers)
    controllers = _terminals(by_kind['controller_start'], by_kind['controller_terminal'], record, ledgers, True)
    controllers += _supervised(by_kind['supervised_start'], by_kind['supervised_terminal'], record)
    controller_records = _located_controllers(by_kind['evidence_locations'], by_kind['controller_verification'], record)
    need(len({row['pid'] for row in controllers}) == len(controllers), 'duplicate_controller_terminal')
    guard_cid = None
    need(len(by_kind['guard_identity']) <= 1)
    for body, ref in by_kind['guard_identity']:
        need(record.get('container_id') is None)
        invocation = reader.reference(body.get('invocation'))
        cleanup.exact(invocation, cleanup.INVOCATION_FIELDS)
        need(invocation.get('document_type') == 'owned_process_invocation'
             and invocation.get('launch_ids') == [record['launch_id']]
             and all(invocation.get(k) == record[k] for k in ('registry', 'generation', 'runroot')))
        guard_cid = cleanup._guard_identity(reader, record, {'identity': ref, 'invocation': body['invocation']})['container_id']
    missing = ['original_controller_custody', 'complete_launcher_custody', 'recognized_retained_namespace']
    if not snapshots:
        missing.append('supported_legacy_disposable_scope_contract' if disposable else 'original_workspace_snapshot')
    if record.get('container_id') is None and guard_cid is None:missing.append('original_helper_guard_cid')
    native = 'not_supplied'; native_shape = None; need(len(by_kind['native_request']) <= 1)
    for body, unused in by_kind['native_request']:
        need(body.get('subject') == subject, 'native_request_subject_mismatch')
        class CapturedRegistry:
            def load(self):return related
        cleanup._prepare(CapturedRegistry(), body, replay=True, reader=reader)
        snapshot = reader.reference(body['snapshot'])
        need(not snapshots or all(identity == snapshot['workspace_identity'] for identity, unused in snapshots),
             'snapshot_binding_mismatch')
        if not snapshots:snapshots.append((snapshot['workspace_identity'], body['snapshot']))
        native_shape = body['shape']
        native = 'metadata_compatible'; missing = []
    work = ['original_evidence_collection'] if missing else ['authorized_live_recovery']
    if any(by_kind[k] for k in KINDS - {'native_request', 'guard_identity'}):work.append('legacy_format_adapter')
    if disposable:work.append('legacy_scope_adapter')
    specialized = sum(any(key in row for key in ('qualification_role', 'qualification_service_cleanup',
                       'qualification_preworker_cleanup')) for row in related)
    return {'launch_id': record['launch_id'], 'subject': subject, 'capture': case['capture'],
            'execution_shape': native_shape or ('interrupted' if record.get('container_id') is None else
                               'agent' if any(body['kind'] == 'agent' for body in stages) else 'unknown'),
            'primary_cid_recorded': record.get('container_id') is not None,
            'related_launches': len(related), 'related_launches_with_pid': len([v for v in ledgers.values() if v['pid'] is not None]),
            'related_qualification_records': specialized,
            'ledger_identity_candidates': [{'launch_id': launch, **fact} for launch, fact in sorted(ledgers.items())],
            'workspace_identity': snapshots[0][0] if snapshots else None,
            'snapshot_provenance': [ref for unused, ref in snapshots],
            'launcher_terminals': launchers, 'controller_terminals': controllers,
            'controller_verification_records': controller_records, 'disposable_root_facts': disposable,
            'diagnostic_overlays': overlays,
            'native_request': native, 'missing_facts': sorted(missing), 'required_work': work,
            'remaining_checks': list(REMAINING) + (['separate_qualification_proof_replay'] if specialized else []),
            'recovery_eligible': False,
            'source_count': len(sources), 'assessment_scope': 'supplied_retained_metadata_only'}


def assess(manifest_path):
    """Return a private evidence map. Inputs are read-only; no live proof is accepted."""
    try:
        need(Path(cleanup.__file__).resolve() == ROOT / 'skill/scripts/application_owner_cleanup.py', 'code_origin_mismatch')
        reader = cleanup.Reader(); manifest, reference = reader.read(manifest_path, private=True)
        cleanup.canonical(manifest)
        exact(manifest, {'schema', 'document_type', 'cases'})
        need(type(manifest['schema']) is int and manifest['schema'] == 1
             and manifest['document_type'] == 'application_owner_migration_audit_manifest'
             and type(manifest['cases']) is list and 1 <= len(manifest['cases']) <= 32)
        cases = []; seen = set()
        for case in manifest['cases']:
            row = _case(reader, case); need(row['launch_id'] not in seen); seen.add(row['launch_id']); cases.append(row)
        return {'schema': 1, 'document_type': 'application_owner_migration_assessment', 'status': 'ASSESSED',
                'manifest': reference, 'cases': cases, 'admission_authorized': False, 'cleanup_authorized': False,
                'native_actions': 0, 'proofs_published': 0, 'proof_graph_validated': False,
                'assessment_scope': 'supplied_retained_metadata_only',
                'missing_facts_scope': 'not_established_by_supplied_inputs',
                'references_read': len(reader.references), 'metadata_bytes_read': reader.bytes}
    except AssessmentError:raise
    except (ownership.RegistryError, OSError, ValueError, TypeError, KeyError, IndexError, AttributeError, RuntimeError):
        # Never serialize an exception containing a private path or payload.
        raise AssessmentError() from None


def public_summary(report):
    cases = []
    for row in report['cases']:
        public = {key: row[key] for key in ('launch_id', 'execution_shape', 'primary_cid_recorded',
                  'related_launches', 'related_qualification_records', 'native_request', 'missing_facts',
                  'required_work', 'recovery_eligible')}
        public.update(original_workspace_identity_recorded=row['workspace_identity'] is not None,
                      original_disposable_root_identity_recorded=bool(row['disposable_root_facts']),
                      controller_verification_exits=[value['actual_exit'] for value in row['controller_verification_records']],
                      controller_terminal_exits=[value['actual_exit'] for value in row['controller_terminals']],
                      launcher_terminal_exits=[value['actual_exit'] for value in row['launcher_terminals']])
        cases.append(public)
    return {'schema': 1, 'document_type': report['document_type'], 'status': report['status'],
            'admission_authorized': False, 'cleanup_authorized': False, 'native_actions': 0,
            'proofs_published': 0, 'proof_graph_validated': False,
            'assessment_scope': 'supplied_retained_metadata_only',
            'missing_facts_scope': 'not_established_by_supplied_inputs',
            'cases': cases}


def plan_retained(request_path,capture_reference):
    """Use the installed pure planner with one Reader; never accept owner proof."""
    import application_owner_legacy as legacy
    try:
        reader=cleanup.Reader()
        request,unused=reader.read(request_path,private=True)
        if isinstance(capture_reference,(str,Path)):
            unused,capture_reference=reader.read(capture_reference,private=True)
        record,related,subject=_capture(reader,capture_reference,request['subject']['launch_id'])
        result=legacy.analyze(request,record,related,reader=reader)
        return {'schema':1,'document_type':'application_owner_migration_plan','plan':result,
                'public':legacy.public_summary(result),'recovery_eligible':False,
                'admission_authorized':False,'cleanup_authorized':False,'native_actions':0,'proofs_published':0}
    except (ownership.RegistryError,OSError,ValueError,TypeError,KeyError,IndexError,AttributeError,RuntimeError):
        raise AssessmentError() from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    selector=parser.add_mutually_exclusive_group(required=True)
    selector.add_argument('--manifest',type=Path)
    selector.add_argument('--request',type=Path,help='Read-only structural planning with the installed legacy validator')
    parser.add_argument('--capture',type=Path,help='Private retained record capture required with --request')
    args = parser.parse_args(argv)
    if bool(args.request)!=bool(args.capture):parser.error('--request and --capture must be selected together')
    try:
        result=plan_retained(args.request,args.capture)['public'] if args.request else public_summary(assess(args.manifest))
        code=0
    except AssessmentError as error:result = {'status': 'BLOCKED', 'condition': error.condition,
        'admission_authorized': False, 'cleanup_authorized': False}; code = 2
    print(json.dumps(result, indent=2)); return code


if __name__ == '__main__':raise SystemExit(main())
