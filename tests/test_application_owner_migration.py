"""Offline legacy-owner assessments never create cleanup or admission authority."""
import copy
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'skill/scripts'), str(ROOT / 'tools/qualification')]
import application_owner_cleanup as cleanup


class MigrationAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.api = importlib.import_module('application_owner_migration')
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve(); self.root.chmod(0o700)
        self.run = self.root / 'run'; self.run.mkdir(mode=0o700)
        self.launch = str(uuid.uuid4()); generation = str(uuid.uuid4())
        self.record = {'schema': 1, 'application_helper': True, 'client_mode': 'application-execution',
            'launch_id': self.launch, 'generation': generation, 'registry': 'a' * 64,
            'status': 'released', 'container_id': 'b' * 64, 'container': 'pi-application-fixture',
            'image': 'sha256:' + 'c' * 64, 'daemon': 'fixture-daemon', 'owner_pid': 1234,
            'runroot': str(self.run), 'private_store': str(self.run / 'application-helpers' / ('d' * 32)),
            'mounts': [], 'binding': {}, 'code_identity': {'runtime/service.py': 'e' * 64}}
        self.sources = []; self.number = 0
        for target in ((subprocess, 'run'), (subprocess, 'Popen'), (os, 'kill')):
            patcher = mock.patch.object(*target, side_effect=AssertionError('Native action forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)

    def put(self, value, name=None):
        self.number += 1; path = self.root / (name or ('metadata-' + str(self.number) + '.json'))
        path.write_text(json.dumps(value)); path.chmod(0o600)
        return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}

    def add(self, kind, value):
        ref = self.put(value); self.sources.append({'kind': kind, 'reference': ref}); return ref

    def manifest(self, related=None):
        capture = self.put({'schema': 1, 'document_type': 'application_owner_migration_record_capture',
            'captured_at': '2026-10-28T00:00:00Z', 'lease': {'device': 1, 'inode': 2},
            'original_reference': {'path': str(self.root / 'original-record.json'), 'sha256': 'f' * 64},
            'record': self.record, 'related_records': related or [self.record],
            'source': 'Current capture, not historical process custody',
            'admission_authorized': False, 'cleanup_authorized': False})
        return self.put({'schema': 1, 'document_type': 'application_owner_migration_audit_manifest',
            'cases': [{'launch_id': self.launch, 'capture': capture, 'sources': self.sources}]})

    def ledger(self):
        r = self.record
        return {'schema': 1, 'daemon': r['daemon'], 'poisoned': True, 'launches': [
            {'launch_id': r['launch_id'], 'generation': r['generation'], 'registry': r['registry'],
             'container': r['container'], 'container_id': r.get('container_id'), 'image': r['image'],
             'intent_sha256': cleanup.subject(r)['intent_sha256'], 'pid': 5678, 'private_cleanup': False}]}

    def legacy_helper(self):
        self.add('launch_ledger', self.ledger())
        self.add('launcher_start', {'schema': 1, 'ordinal': 9, 'kind': 'helper_container_cli',
            'pid': 5678, 'parent_pid': 1234, 'started_monotonic': 1.0, 'started_wall': 2.0})
        self.add('launcher_terminal', {'schema': 1, 'ordinal': 9, 'pid': 5678, 'returncode': 137,
            'unknown_owned_child': False, 'wait_confirmed': True, 'failure_class': 'killed'})

    def native_request(self, selected=None):
        r = self.record if selected is None else selected
        workspace = self.run / 'workspace'; workspace.mkdir(mode=0o700, exist_ok=True)
        r['mounts'] = [
            {'source': r['private_store'] + '/code', 'target': '/opt/pi-application', 'rw': False},
            {'source': r['private_store'] + '/state', 'target': '/pi-client/state', 'rw': True},
            {'source': str(self.run / 'application-evidence' / r['container']), 'target': '/pi-client/evidence', 'rw': True}]
        def pair(pid, argv):
            invocation = self.put({'schema': 1, 'document_type': 'owned_process_invocation',
                'pid': pid, 'argv': argv, 'cwd': str(self.root), 'runroot': r['runroot'],
                'registry': r['registry'], 'generation': r['generation'], 'launch_ids': [r['launch_id']]})
            terminal = self.put({'schema': 1, 'document_type': 'owned_process_terminal',
                'pid': pid, 'argv': argv, 'cwd': str(self.root), 'invocation': invocation, 'actual_exit': 2})
            return {'invocation': invocation, 'terminal': terminal}
        argv = ['docker', 'run', '--name', r['container'], '--label',
            'org.pi-agent-test-env.launch=' + r['launch_id'], '--label',
            'org.pi-agent-test-env.registry=' + r['registry']]
        for mount in r['mounts']:
            argv += ['--mount', 'type=bind,src=' + mount['source'] + ',dst=' + mount['target']
                     + (',readonly' if not mount['rw'] else '')]
        argv += [r['image'], '/opt/pi-application/runtime/application_client_service.py']
        launcher = {'launch_id': r['launch_id'], **pair(5678, argv)}
        snapshot = self.put({'schema': 1, 'document_type': 'application_owned_snapshot',
            'registry': r['registry'], 'generation': r['generation'], 'runroot': r['runroot'],
            'binding': r['binding'], 'workspace': str(workspace),
            'workspace_identity': [workspace.stat().st_dev, workspace.stat().st_ino]})
        return {'schema': 1, 'document_type': 'application_owner_cleanup_request',
            'subject': cleanup.subject(r), 'shape': 'helper_only',
            'controller': pair(r['owner_pid'], ['python3', 'original-controller.py']),
            'launchers': [launcher], 'snapshot': snapshot, 'stages': [], 'extra_private_roots': []}

    def test_real_nonzero_legacy_terminal_is_preserved_as_partial_evidence(self):
        self.legacy_helper(); report = self.api.assess(self.manifest()['path']); row = report['cases'][0]
        self.assertEqual(row['launcher_terminals'][0]['actual_exit'], 137)
        self.assertEqual(len(row['launcher_terminals'][0]['provenance']), 3)
        self.assertFalse(row['recovery_eligible']); self.assertFalse(report['admission_authorized'])
        self.assertIn('original_workspace_snapshot', row['missing_facts'])
        self.assertIn('legacy_format_adapter', row['required_work'])
        self.assertFalse((self.root / 'original-record.json').exists())

    def test_unrelated_worker_terminal_cannot_supply_helper_identity_or_terminal(self):
        self.record.pop('container_id')
        self.add('controller_start', {'schema': 1, 'ordinal': 1, 'kind': 'worker', 'pid': 1234,
            'parent_pid': 1000, 'handle_returned': True})
        self.add('controller_terminal', {'schema': 1, 'ordinal': 1, 'kind': 'worker', 'pid': 1234,
            'actual_exit': 2, 'wait_confirmed': True, 'unknown_owned_child': False})
        self.add('identity_timing', {'schema': 1, 'document_type': 'qualification_helper_identity_timing',
            'identity': {'launch_id': self.launch}, 'identity_bind_outcome': 'not_observed', 'terminal': True})
        row = self.api.assess(self.manifest()['path'])['cases'][0]
        self.assertEqual(row['controller_terminals'][0]['actual_exit'], 2)
        self.assertEqual(row['launcher_terminals'], [])
        self.assertIn('original_helper_guard_cid', row['missing_facts'])
        self.assertIn('complete_launcher_custody', row['missing_facts'])

    def test_supervisor_child_wait_supplies_only_its_own_controller_exit(self):
        self.add('supervised_start', {'schema': 1, 'pid': 1234, 'wrapper_pid': 1000,
            'argv': ['python3', 'original.py'], 'started': 1.0, 'started_wall': 2.0})
        self.add('supervised_terminal', {'schema': 1, 'child_pid': 1234, 'wrapper_pid': 1000,
            'actual_exit': 2, 'child_wait_confirmed': True, 'automatic_retries': 0,
            'container_or_private_actions_by_supervisor': 0, 'elapsed_seconds': 3.0,
            'program': {}, 'inputs': {}, 'source_review': {}, 'status': 'PASS'})
        row = self.api.assess(self.manifest()['path'])['cases'][0]
        self.assertEqual(row['controller_terminals'][0]['actual_exit'], 2)
        self.assertEqual(row['launcher_terminals'], [])
        self.assertIn('original_controller_custody', row['missing_facts'])

    def indexed_controller(self, body):
        reference = self.add('controller_verification', body)
        self.add('evidence_locations', {'schema_version': 1, 'cases': [{'launch_id': self.launch,
            'controller_terminal': reference, 'controller_actual_exit': body['actual_exit'],
            'complete_4_7_owner_proof_graph_established': False}]})
        return reference

    def test_controller_index_preserves_actual_native_exit_without_inventing_pid(self):
        self.indexed_controller({'argv': ['python3', 'original.py'], 'cwd': str(self.root),
            'expected_exit': 2, 'actual_exit': 2, 'metadata_exit': 0})
        row = self.api.assess(self.manifest()['path'])['cases'][0]
        self.assertEqual(row['controller_verification_records'][0]['actual_exit'], 2)
        self.assertIsNone(row['controller_verification_records'][0]['owner_pid_binding'])
        self.assertEqual(row['controller_terminals'], [])
        self.assertIn('original_controller_custody', row['missing_facts'])

    def test_controller_verification_must_match_its_indexed_reference_and_exit(self):
        reference = self.indexed_controller({'argv': ['python3', 'original.py'], 'cwd': str(self.root), 'actual_exit': 2})
        body = json.loads(Path(reference['path']).read_text()); body['actual_exit'] = 0
        self.sources[0]['reference'] = self.put(body)
        with self.assertRaises(self.api.AssessmentError):self.api.assess(self.manifest()['path'])

    def test_disposable_root_identity_does_not_become_workspace_identity(self):
        disposable = self.run / 'diagnostic' / 'disposable'
        self.record['mounts'] = [{'source': str(disposable / name), 'target': '/' + name, 'rw': True}
                                 for name in ('code', 'state', 'evidence')]
        self.add('artifact_diagnostic_terminal', {'schema': 1,
            'document_type': 'bounded_artifact_write_diagnostic_terminal',
            'container_id': self.record['container_id'], 'disposable_root': str(disposable),
            'disposable_root_identity': [1, 765], 'disposable_root_removed': True})
        row = self.api.assess(self.manifest()['path'])['cases'][0]
        self.assertIsNone(row['workspace_identity'])
        self.assertEqual(row['disposable_root_facts'][0]['identity'], [1, 765])
        self.assertNotIn('original_workspace_snapshot', row['missing_facts'])
        self.assertIn('supported_legacy_disposable_scope_contract', row['missing_facts'])
        self.assertIn('legacy_scope_adapter', row['required_work'])

    def test_diagnostic_launcher_without_parent_receipt_retains_that_gap(self):
        self.add('launch_ledger', self.ledger())
        self.add('launcher_start', {'schema': 1, 'ordinal': 5, 'kind': 'diagnostic_container_cli',
            'pid': 5678, 'started_monotonic': 1.0, 'started_wall': 2.0})
        self.add('launcher_terminal', {'schema': 1, 'ordinal': 5, 'pid': 5678, 'returncode': 0,
            'wait_confirmed': True, 'unknown_owned_child': False, 'failure_class': None})
        row = self.api.assess(self.manifest()['path'])['cases'][0]
        self.assertEqual(row['launcher_terminals'][0]['actual_exit'], 0)
        self.assertEqual(row['launcher_terminals'][0]['parent_binding'], 'not_recorded')
        self.assertIn('complete_launcher_custody', row['missing_facts'])

    def test_unconfirmed_supervisor_wait_cannot_become_a_controller_terminal(self):
        self.add('supervised_start', {'schema': 1, 'child_pid': 1234, 'wrapper_pid': 1000,
            'argv': ['python3', 'original.py'], 'credential_values_opened_by_supervisor': False})
        self.add('supervised_terminal', {'schema': 1, 'document_type': 'unsupported_supervisor',
            'child_pid': 1234, 'wrapper_pid': 1000, 'actual_exit': 0, 'wait_completed': False})
        with self.assertRaises(self.api.AssessmentError):self.api.assess(self.manifest()['path'])

    def test_parent_and_ordinal_mismatch_do_not_join_unrelated_processes(self):
        self.legacy_helper()
        for field, value in (('parent_pid', 9999), ('ordinal', 8)):
            with self.subTest(field=field):
                original = self.sources[1]['reference']; body = json.loads(Path(original['path']).read_text())
                body[field] = value; self.sources[1]['reference'] = self.put(body)
                with self.assertRaises(self.api.AssessmentError):self.api.assess(self.manifest()['path'])
                self.sources[1]['reference'] = original

    def test_false_unknown_or_boolean_wait_data_never_becomes_a_terminal_fact(self):
        self.legacy_helper(); original = self.sources[2]['reference']
        for change in ({'wait_confirmed': False}, {'unknown_owned_child': True}, {'returncode': True}):
            with self.subTest(change=change):
                body = json.loads(Path(original['path']).read_text()); body.update(change)
                self.sources[2]['reference'] = self.put(body)
                with self.assertRaises(self.api.AssessmentError):self.api.assess(self.manifest()['path'])

    def test_wrong_ledger_identity_and_duplicate_rows_are_rejected(self):
        for change in ('cid', 'generation', 'duplicate'):
            self.sources = []; ledger = self.ledger()
            if change == 'cid':ledger['launches'][0]['container_id'] = '0' * 64
            elif change == 'generation':ledger['launches'][0]['generation'] = str(uuid.uuid4())
            else:ledger['launches'].append(copy.deepcopy(ledger['launches'][0]))
            self.add('launch_ledger', ledger)
            with self.subTest(change=change), self.assertRaises(self.api.AssessmentError):self.api.assess(self.manifest()['path'])

    def test_legacy_cid_candidate_does_not_rewrite_primary_or_replace_original_guard(self):
        self.record.pop('container_id'); ledger = self.ledger(); ledger['launches'][0]['container_id'] = 'b' * 64
        self.add('launch_ledger', ledger); manifest = self.manifest(); before = copy.deepcopy(self.record)
        row = self.api.assess(manifest['path'])['cases'][0]
        self.assertFalse(row['primary_cid_recorded'])
        self.assertEqual(row['ledger_identity_candidates'][0]['container_id'], 'b' * 64)
        self.assertIn('original_helper_guard_cid', row['missing_facts'])
        self.assertEqual(self.record, before); self.assertFalse(row['recovery_eligible'])

    def test_related_qualification_receipt_uses_its_original_intent_rule_without_retyping(self):
        related = {**self.record, 'launch_id': str(uuid.uuid4()), 'qualification_role': 'fixture',
            'client_mode': 'qualification-fixture'}
        ledger = self.ledger(); row = {**ledger['launches'][0], 'launch_id': related['launch_id'],
            'intent_sha256': cleanup.digest({k:v for k,v in related.items() if k not in ('status','container_id')})}
        ledger['launches'].append(row)
        related['qualification_service_cleanup'] = {'path': str(self.root / 'service-proof.json'), 'sha256': 'f' * 64}
        self.add('launch_ledger', ledger)
        result = self.api.assess(self.manifest([self.record, related])['path'])['cases'][0]
        self.assertEqual(result['related_qualification_records'], 1)
        self.assertFalse(result['recovery_eligible'])
        self.assertIn('separate_qualification_proof_replay', result['remaining_checks'])

    def test_private_helper_root_identity_cannot_substitute_for_workspace_snapshot(self):
        self.add('empty_root', {'schema': 1, 'path': self.record['private_store'], 'device': 1,
            'inode': 123, 'empty_before_bootstrap': True})
        row = self.api.assess(self.manifest()['path'])['cases'][0]
        self.assertIn('original_workspace_snapshot', row['missing_facts'])
        self.assertIsNone(row['workspace_identity'])

    def test_omitted_descriptors_do_not_establish_a_helper_only_execution_shape(self):
        row = self.api.assess(self.manifest()['path'])['cases'][0]
        self.assertEqual(row['execution_shape'], 'unknown')

    def test_unbound_empty_workspace_observation_is_not_original_snapshot_custody(self):
        self.add('empty_root', {'schema': 1, 'path': str(self.run / 'workspace'), 'device': 1, 'inode': 123})
        row = self.api.assess(self.manifest()['path'])['cases'][0]
        self.assertIn('original_workspace_snapshot', row['missing_facts'])

    def test_complete_native_metadata_is_only_a_candidate_for_authorized_recovery(self):
        request = self.native_request(); self.add('native_request', request)
        row = self.api.assess(self.manifest()['path'])['cases'][0]
        self.assertEqual(row['native_request'], 'metadata_compatible')
        self.assertEqual(row['missing_facts'], [])
        self.assertEqual(row['workspace_identity'], [self.run.joinpath('workspace').stat().st_dev,
                                                    self.run.joinpath('workspace').stat().st_ino])
        self.assertFalse(row['recovery_eligible']); self.assertTrue(row['remaining_checks'])

    def test_native_request_cannot_borrow_another_related_helpers_subject(self):
        sibling = {**self.record, 'launch_id': str(uuid.uuid4())}; request = self.native_request(sibling)
        self.add('native_request', request)
        with mock.patch.object(cleanup, '_prepare', return_value=None) as prepare:
            with self.assertRaises(self.api.AssessmentError):self.api.assess(self.manifest([self.record, sibling])['path'])
        prepare.assert_not_called()

    def test_matching_original_stage_descriptors_supply_snapshot_fact_with_provenance(self):
        self.add('stage_descriptor', {'schema': 2, 'kind': 'agent', 'stage_id': str(uuid.uuid4()),
            'workspace': str(self.run / 'workspace'), 'workspace_identity': [1, 321]})
        row = self.api.assess(self.manifest()['path'])['cases'][0]
        self.assertEqual(row['workspace_identity'], [1, 321]); self.assertEqual(row['execution_shape'], 'agent')
        self.assertNotIn('original_workspace_snapshot', row['missing_facts'])
        self.assertFalse(row['recovery_eligible'])

    def test_contradictory_stage_snapshots_or_bindings_are_rejected(self):
        for inode in (321, 322):
            self.add('stage_descriptor', {'schema': 2, 'kind': 'agent', 'stage_id': str(uuid.uuid4()),
                'workspace': str(self.run / 'workspace'), 'workspace_identity': [1, inode]})
        with self.assertRaises(self.api.AssessmentError):self.api.assess(self.manifest()['path'])

    def test_pass_overlay_is_not_accepted_custody_or_cleanup(self):
        self.add('retained_predicate', {'schema': 1, 'document_type': 'matrix20_retained_predicate_subject',
            'status': 'PASS_SCOPED_RETAINED', 'predicate': 'original_controller_and_owner_terminal_provenance'})
        report = self.api.assess(self.manifest()['path']); row = report['cases'][0]
        self.assertFalse(row['recovery_eligible']); self.assertFalse(report['cleanup_authorized'])
        self.assertIn('original_controller_custody', row['missing_facts'])

    def test_diagnostic_overlay_binds_through_original_record_not_missing_qualification_field(self):
        original = self.put({**self.record, 'status': 'quarantined'})
        release = self.put({'schema': 1, 'document_type': 'qualification_diagnostic_metadata_release',
            'qualification_id': 'fixture-qualification', 'container_id': self.record['container_id'],
            'original_helper_record': original, 'metadata_only_reporting': True, 'raw_ledger_preserved': True})
        self.add('diagnostic_overlay', {'schema': 1,
            'document_type': 'qualification_failed_startup_diagnostic_known_cleanup',
            'qualification_id': 'fixture-qualification', 'metadata_release': release,
            'driver_status': 'BLOCKED', 'cleanup_accounting': 'FAILED', 'native_success_attested': False})
        row = self.api.assess(self.manifest()['path'])['cases'][0]
        self.assertIn('original_controller_custody', row['missing_facts'])
        self.assertFalse(row['recovery_eligible'])
        self.assertEqual(len(row['diagnostic_overlays'][0]['provenance']), 3)

    def test_all_related_launchers_remain_a_requirement(self):
        self.legacy_helper(); sibling = {**self.record, 'application_helper': False, 'launch_id': str(uuid.uuid4())}
        row = self.api.assess(self.manifest([self.record, sibling])['path'])['cases'][0]
        self.assertEqual(row['related_launches'], 2)
        self.assertIn('complete_launcher_custody', row['missing_facts'])

    def test_unknown_fields_formats_and_duplicate_subjects_fail_closed(self):
        ref = self.manifest(); original = json.loads(Path(ref['path']).read_text())
        for mutation in ('field', 'format', 'duplicate'):
            body = copy.deepcopy(original)
            if mutation == 'field':body['accept_cleanup'] = True
            elif mutation == 'format':body['cases'][0]['sources'] = [{'kind': 'plugin', 'reference': ref}]
            else:body['cases'].append(copy.deepcopy(body['cases'][0]))
            with self.subTest(mutation=mutation), self.assertRaises(self.api.AssessmentError):self.api.assess(self.put(body)['path'])

    def test_tampered_linked_or_insecure_source_is_rejected(self):
        self.legacy_helper(); manifest = self.manifest(); path = Path(self.sources[0]['reference']['path'])
        original = path.read_bytes()
        path.write_bytes(original + b' ')
        with self.assertRaises(self.api.AssessmentError):self.api.assess(manifest['path'])
        path.write_bytes(original); path.chmod(0o666)
        with self.assertRaises(self.api.AssessmentError):self.api.assess(manifest['path'])
        path.chmod(0o600); target = path.with_suffix('.retained'); path.rename(target); path.symlink_to(target)
        with self.assertRaises(self.api.AssessmentError):self.api.assess(manifest['path'])

    def test_shared_reader_budget_is_not_reset_for_cases(self):
        manifest = self.manifest()
        with mock.patch.object(cleanup, 'MAX_REFERENCES', 1), self.assertRaises(self.api.AssessmentError):
            self.api.assess(manifest['path'])

    def test_public_report_has_no_paths_pids_payloads_or_claim_of_native_success(self):
        self.legacy_helper(); manifest = self.manifest(); before = {p:p.read_bytes() for p in self.root.rglob('*.json')}
        report = self.api.assess(manifest['path']); public = self.api.public_summary(report); text = json.dumps(public)
        self.assertNotIn(str(self.root), text)
        self.assertNotIn('pid', public['cases'][0]); self.assertNotIn('launcher_terminals', public['cases'][0])
        self.assertFalse(public['admission_authorized']); self.assertFalse(public['cleanup_authorized'])
        self.assertEqual({p:p.read_bytes() for p in self.root.rglob('*.json')}, before)
        self.assertEqual(report['native_actions'], 0)


if __name__ == '__main__':unittest.main()
