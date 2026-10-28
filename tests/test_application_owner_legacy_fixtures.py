"""Synthetic legacy source shapes and an independent fact oracle.

The catalog is test infrastructure, not a runtime request, acceptance receipt or
trusted adapter catalog. Its source-construction oracle is not supplied as an
original emitted-command witness. No real case data or native process is used.
"""
import hashlib
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
sys.path[:0] = [str(ROOT / 'skill/scripts'), str(ROOT / 'skill/runtime'),
                str(ROOT / 'tools/qualification')]
import application_owner_cleanup as cleanup
import application_owner_migration as migration


EMISSION_SOURCE = b'''def docker_command(intent):
    argv = ['docker', 'run', '--name', intent['container']]
    argv += ['--label', 'org.pi-agent-test-env.launch=' + intent['launch_id']]
    argv += ['--label', 'org.pi-agent-test-env.registry=' + intent['registry']]
    for mount in intent['mounts']:
        argv += ['--mount', 'type=bind,src=' + mount['source'] + ',dst=' + mount['target']
                 + (',readonly' if not mount['rw'] else '')]
    return argv + [intent['image'], '/opt/pi-application/runtime/application_client_service.py']
'''

CONTROLLER_SOURCE = b'''# Historical source fixture, never executed by the tests or a receipt reader.
import json
import subprocess
import sys
from emission_source import docker_command

if __name__ == '__main__':
    with open(sys.argv[1]) as stream:
        intent = json.load(stream)
    child = subprocess.Popen(docker_command(intent), cwd=intent['cwd'])
    actual_exit = child.wait()
    raise SystemExit(0 if actual_exit == 0 else 2)
'''

SUPERVISOR_SOURCE = b'''# Historical source fixture; data only.
import subprocess

def supervise(argv, cwd):
    child = subprocess.Popen(argv, cwd=cwd)
    return child.pid, child.wait()
'''


class LegacyFixture:
    """Create original-format synthetic inputs; keep expected facts out of them."""
    def __init__(self, parent, *, scope='standard_workspace', gap=None, exit_code=137,
                 registry_id=None, generation=None):
        if scope not in ('standard_workspace', 'diagnostic_disposable'):
            raise ValueError('Unknown synthetic scope')
        if gap not in (None, 'missing_helper_guard_cid', 'missing_workspace_identity',
                       'unrelated_worker_terminal', 'unconfirmed_wait', 'unknown_retained_namespace',
                       'orphan_controls', 'prepared_command_only', 'specialized_related_unvalidated',
                       'interrupted_worker_only'):
            raise ValueError('Unknown synthetic gap')
        self.root = Path(parent).resolve(); self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.originals = self.root / 'originals'; self.originals.mkdir(mode=0o700)
        self.run = self.root / 'retained'; self.run.mkdir(mode=0o700)
        self.scope = scope; self.gap = gap; self.sources = []; self.refs = {}
        worker_only = gap == 'interrupted_worker_only'
        self.launch_id = str(uuid.uuid4())
        generation = str(uuid.uuid4()) if generation is None else generation
        self.owner_pid = 2147483000; self.launcher_pid = 2147482999
        self.controller_exit = 2 if worker_only else 0 if exit_code == 0 else 2
        self.cid = 'b' * 64; self.stage_id = str(uuid.uuid4())
        if scope == 'standard_workspace':
            self.workspace = self.run / 'workspace'; self.workspace.mkdir(mode=0o700)
            self.private = self.run / 'application-helpers' / ('a' * 32)
            evidence = self.run / 'application-evidence' / 'pi-application-synthetic'
        else:
            self.workspace = None
            self.private = self.run / 'diagnostic' / 'disposable'
            evidence = self.private / 'evidence'
        for path in (self.private / 'code', self.private / 'state', evidence):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.record = {'schema': 1, 'launch_id': self.launch_id, 'registry': 'd' * 64 if registry_id is None else registry_id,
            'generation': generation, 'status': 'released', 'container': 'pi-application-synthetic',
            'container_id': self.cid, 'image': 'sha256:' + 'a' * 64,
            'application_helper': True, 'client_mode': 'application-execution',
            'daemon': 'synthetic-daemon', 'owner_pid': self.owner_pid,
            'runroot': str(self.run), 'private_store': str(self.private),
            'mounts': [{'source': str(self.private / 'code'), 'target': '/opt/pi-application', 'rw': False},
                       {'source': str(evidence), 'target': '/pi-client/evidence', 'rw': True},
                       {'source': str(self.private / 'state'), 'target': '/pi-client/state', 'rw': True}],
            'binding': {'run_id': str(uuid.uuid4()), 'attempt_id': str(uuid.uuid4())},
            'code_identity': {'runtime/application_client_service.py': 'e' * 64}}
        self.related = [self.record]
        if gap in ('missing_helper_guard_cid', 'interrupted_worker_only'):self.record.pop('container_id')
        self.put_raw('emission_source.py', EMISSION_SOURCE)
        program = self.put_raw('controller-driver.py', CONTROLLER_SOURCE)
        supervisor = self.put_raw('supervisor.py', SUPERVISOR_SOURCE)
        input_body = {key: self.record[key] for key in
            ('launch_id', 'registry', 'generation', 'container', 'image', 'mounts')}
        input_body['cwd'] = str(self.root)
        inputs = self.put('emission-inputs.json', input_body)
        self.emission_argv = self._oracle_command()
        controller_argv = ['python3', program['path'], inputs['path']]
        self.put('controller-context.json', {'argv': controller_argv, 'cwd': str(self.root),
            'expected_exit': self.controller_exit, 'actual_exit': self.controller_exit,
            'started_at': '2026-10-28T00:00:00Z',
            'elapsed_seconds': 1.0, 'invoker_sha256': supervisor['sha256'],
            'scope': 'Synthetic original-format controller context, not a new PID witness'})
        self.put('source-bindings.json', {'schema': 1, 'program': program,
            'source_dependencies': [self.refs['emission_source.py']], 'inputs': inputs,
            'invoker': supervisor,
            'controller_context': self.refs['controller-context.json'],
            'role': 'synthetic_execution_source_binding'})
        if not worker_only:
            self.add('supervised_start', 'controller-start.json', {'schema': 1, 'pid': self.owner_pid,
                'wrapper_pid': self.owner_pid - 1, 'argv': controller_argv,
                'started': 1.0, 'started_wall': 2.0})
            self.add('supervised_terminal', 'controller-verification.json', {'schema': 1, 'status': 'PASS',
                'actual_exit': self.controller_exit, 'child_pid': self.owner_pid, 'wrapper_pid': self.owner_pid - 1,
                'child_wait_confirmed': True, 'automatic_retries': 0,
                'container_or_private_actions_by_supervisor': 0, 'elapsed_seconds': 1.0,
                'program': program if gap != 'prepared_command_only' else {},
                'inputs': inputs if gap != 'prepared_command_only' else {},
                'source_review': self.refs['source-bindings.json'] if gap != 'prepared_command_only' else {}})
        start = {'schema': 1, 'ordinal': 9, 'kind': 'helper_container_cli',
                 'pid': self.launcher_pid, 'parent_pid': self.owner_pid,
                 'started_monotonic': 1.0, 'started_wall': 2.0}
        if scope == 'diagnostic_disposable':
            start['kind'] = 'diagnostic_container_cli'; start.pop('parent_pid')
        if worker_only:
            self.add('controller_start', 'worker-start.json', {'schema': 1, 'ordinal': 1,
                'kind': 'worker', 'pid': self.owner_pid, 'parent_pid': self.owner_pid - 1,
                'handle_returned': True})
            self.add('controller_terminal', 'worker-terminal.json', {'schema': 1, 'ordinal': 1,
                'kind': 'worker', 'pid': self.owner_pid, 'actual_exit': 2,
                'wait_confirmed': True, 'unknown_owned_child': False})
            self.add('identity_timing', 'identity-timing.json', {'schema': 1,
                'document_type': 'qualification_helper_identity_timing',
                'identity': {'launch_id': self.launch_id}, 'identity_bind_outcome': 'not_observed',
                'terminal': True})
        else:
            self.add('launcher_start', 'launcher-start.json', start)
            self.add('launcher_terminal', 'launcher-terminal.json', {'schema': 1, 'ordinal': 9,
                'pid': self.launcher_pid if gap != 'unrelated_worker_terminal' else self.owner_pid,
                'returncode': exit_code, 'wait_confirmed': gap != 'unconfirmed_wait',
                'unknown_owned_child': False, 'failure_class': None})
        ledger_rows = []
        if gap not in ('missing_helper_guard_cid', 'interrupted_worker_only'):
            ledger_rows.append({'launch_id': self.launch_id, 'registry': self.record['registry'],
                'generation': generation, 'container': self.record['container'],
                'image': self.record['image'], 'container_id': self.cid,
                'intent_sha256': cleanup.subject(self.record)['intent_sha256'],
                'pid': self.launcher_pid, 'private_cleanup': False})
        else:
            # A real-looking CID for another launch must never repair this helper.
            ledger_rows.append({'launch_id': str(uuid.uuid4()), 'registry': self.record['registry'],
                'generation': generation, 'container': 'pi-other-synthetic',
                'image': self.record['image'], 'container_id': 'c' * 64,
                'intent_sha256': 'f' * 64, 'pid': self.launcher_pid - 1, 'private_cleanup': False})
        self.add('launch_ledger', 'ledger.json', {'schema': 1, 'daemon': self.record['daemon'],
            'poisoned': True, 'launches': ledger_rows})
        self.original_identity = None
        if scope == 'standard_workspace' and gap != 'missing_workspace_identity':
            info = self.workspace.stat(); self.original_identity = [info.st_dev, info.st_ino]
            descriptor = self.put_retained('descriptor.json', self.run / 'stages' / self.stage_id / 'descriptor.json',
                {'schema': 2, 'stage_id': self.stage_id,
                'kind': 'agent', 'label': 'participant', 'workspace': str(self.workspace),
                'workspace_identity': self.original_identity, **self.record['binding']})
            self.sources.append({'kind': 'stage_descriptor', 'reference': descriptor})
            stage = self.run / 'stages' / self.stage_id
            self.put_retained('stage-state.json', stage / 'state.json',
                {'schema': 2, 'status': 'finalized', 'cleanup_confirmed': False})
            self.put_retained('stage-credentials.json', stage / 'application-credentials.json',
                {'schema': 1, 'status': 'cleanup_unconfirmed', 'workspace': 'quarantined', 'references': []})
            self.put_retained('process.json', self.run / 'participant' / 'process.json',
                {'cleanup_confirmed': False, 'application_helper_cleanup':
                 {'status': 'cleanup_unconfirmed', 'safe_to_continue': False}})
        elif scope == 'diagnostic_disposable':
            info = self.private.stat(); self.original_identity = [info.st_dev, info.st_ino]
            self.add('artifact_diagnostic_terminal', 'diagnostic-terminal.json', {'schema': 1,
                'document_type': 'bounded_artifact_write_diagnostic_terminal',
                'container_id': self.cid, 'disposable_root': str(self.private),
                'disposable_root_identity': self.original_identity, 'disposable_root_removed': False})
        self.put_retained('protected-result.json', self.run / 'result.json',
            {'schema': 1, 'status': 'FAIL', 'sealed': True,
            'cleanup_confirmed': False, 'safe_to_continue': False, 'qualification_eligible': False})
        if gap == 'unknown_retained_namespace':
            (self.run / 'unreviewed-runtime.log').write_text('synthetic retained payload\n')
        if gap == 'orphan_controls':
            context = self.run / 'controls' / str(uuid.uuid4()) / 'segments' / str(uuid.uuid4())
            context.mkdir(parents=True, mode=0o700)
            (context / 'application-context.json').write_text('{"fixture_only":true}\n')
        if gap == 'specialized_related_unvalidated':
            specialized = {**self.record, 'launch_id': str(uuid.uuid4()),
                'qualification_role': 'fixture', 'client_mode': 'qualification-fixture',
                'container': 'pi-service-synthetic', 'container_id': 'c' * 64}
            specialized['qualification_service_cleanup'] = self.put('unvalidated-service-proof.json',
                {'schema': 1, 'document_type': 'unvalidated_synthetic_service_reference'})
            self.related.append(specialized)
        self.capture = self.put('capture.json', {'schema': 1,
            'document_type': 'application_owner_migration_record_capture',
            'captured_at': '2026-10-28T00:00:00Z', 'lease': {'device': 1, 'inode': 2},
            'original_reference': self.put('primary-record.json', self.record),
            'record': self.record, 'related_records': self.related,
            'source': 'Synthetic current capture, never original process/snapshot custody',
            'admission_authorized': False, 'cleanup_authorized': False})
        self.manifest = self.put('audit-manifest.json', {'schema': 1,
            'document_type': 'application_owner_migration_audit_manifest',
            'cases': [{'launch_id': self.launch_id, 'capture': self.capture, 'sources': self.sources}]})
        obligations = []
        if gap == 'missing_helper_guard_cid':obligations.append('original_helper_guard_cid')
        if worker_only:obligations += ['original_helper_guard_cid', 'helper_launcher_custody']
        if gap == 'missing_workspace_identity':obligations.append('original_workspace_snapshot')
        if gap == 'unrelated_worker_terminal':obligations.append('helper_terminal_binding')
        if gap == 'unconfirmed_wait':obligations.append('actual_wait_confirmation')
        if gap == 'unknown_retained_namespace':obligations.append('retained_namespace_review')
        if gap == 'orphan_controls':obligations.append('original_control_descriptor')
        if gap == 'prepared_command_only':obligations.append('executed_emission_source_binding')
        if gap == 'specialized_related_unvalidated':obligations.append('specialized_receipt_replay')
        self.oracle = {'fixture_only': True, 'scope': scope, 'gap': gap,
            'semantic_reference': 'complete_selected_facts' if gap is None else 'faithful_missing_fact',
            'emission_argv': self.emission_argv, 'emission_cwd': str(self.root),
            'argv_claim_type': 'prospective_static_source_derivation_not_original_witness',
            'source_derivation_support': 'requires_reviewed_contract',
            'actual_helper_exit': None if worker_only else exit_code, 'original_identity': self.original_identity,
            'actual_controller_exit': self.controller_exit,
            'expected_unmet_obligations': obligations, 'runtime_acceptance_claimed': False,
            'real_participant_invocations': 0}

    def _oracle_command(self):
        r = self.record
        argv = ['docker', 'run', '--name', r['container'], '--label',
                'org.pi-agent-test-env.launch=' + r['launch_id'], '--label',
                'org.pi-agent-test-env.registry=' + r['registry']]
        for mount in r['mounts']:
            argv += ['--mount', 'type=bind,src=' + mount['source'] + ',dst=' + mount['target']
                     + (',readonly' if not mount['rw'] else '')]
        return argv + [r['image'], '/opt/pi-application/runtime/application_client_service.py']

    def put_raw(self, name, body):
        path = self.originals / name; path.write_bytes(body); path.chmod(0o600)
        ref = {'path': str(path), 'sha256': hashlib.sha256(body).hexdigest()}; self.refs[name] = ref
        return ref

    def put(self, name, value):
        return self.put_raw(name, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode())

    def put_retained(self, name, path, value):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        body = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
        path.write_bytes(body); path.chmod(0o600)
        ref = {'path': str(path), 'sha256': hashlib.sha256(body).hexdigest()}; self.refs[name] = ref
        return ref

    def add(self, kind, name, value):
        ref = self.put(name, value); self.sources.append({'kind': kind, 'reference': ref}); return ref


class LegacyFixtureCatalogTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        for obj, name in ((subprocess, 'run'), (subprocess, 'Popen'), (os, 'kill')):
            patcher = mock.patch.object(obj, name, side_effect=AssertionError('Native action forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)

    def build(self, name, **kw):return LegacyFixture(self.root / name, **kw)

    def test_complete_semantic_references_preserve_actual_legacy_omissions(self):
        for scope in ('standard_workspace', 'diagnostic_disposable'):
            fixture = self.build(scope, scope=scope)
            start = json.loads(Path(fixture.refs['launcher-start.json']['path']).read_text())
            self.assertNotIn('argv', start); self.assertNotIn('cwd', start)
            self.assertEqual('parent_pid' in start, scope == 'standard_workspace')
            self.assertEqual(fixture.oracle['semantic_reference'], 'complete_selected_facts')
            self.assertFalse(fixture.oracle['runtime_acceptance_claimed'])
            self.assertEqual(fixture.oracle['real_participant_invocations'], 0)

    def test_oracle_is_not_an_original_source_or_acceptance_document(self):
        fixture = self.build('oracle')
        before = {p:p.read_bytes() for p in fixture.originals.iterdir()}
        public = migration.public_summary(migration.assess(fixture.manifest['path']))
        self.assertFalse(public['admission_authorized']); self.assertFalse(public['cleanup_authorized'])
        self.assertFalse(public['proof_graph_validated'])
        self.assertNotIn('emission_argv', json.dumps(public))
        self.assertEqual(before, {p:p.read_bytes() for p in fixture.originals.iterdir()})

    def test_every_original_reference_is_hash_bound_and_outside_payloads(self):
        fixture = self.build('refs')
        payloads = [fixture.workspace, fixture.private]
        payloads += [Path(mount['source']) for mount in fixture.record['mounts']]
        for ref in fixture.refs.values():
            path = Path(ref['path']); self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), ref['sha256'])
            self.assertFalse(any(path == payload or path.is_relative_to(payload) for payload in payloads))
        self.assertTrue(Path(fixture.refs['descriptor.json']['path']).is_relative_to(fixture.run))
        self.assertEqual(Path(fixture.refs['protected-result.json']['path']), fixture.run / 'result.json')
        self.assertEqual(fixture.oracle['emission_argv'].count('--mount'), 3)
        self.assertEqual(fixture.oracle['emission_argv'].count('--label'), 2)

    def test_controller_context_and_source_dependencies_are_supplied_without_execution(self):
        fixture = self.build('context')
        context = json.loads(Path(fixture.refs['controller-context.json']['path']).read_text())
        binding = json.loads(Path(fixture.refs['source-bindings.json']['path']).read_text())
        self.assertEqual(context['cwd'], fixture.oracle['emission_cwd'])
        self.assertEqual(context['argv'][1], binding['program']['path'])
        self.assertEqual(binding['source_dependencies'], [fixture.refs['emission_source.py']])
        self.assertEqual(context['invoker_sha256'], binding['invoker']['sha256'])
        self.assertEqual(fixture.oracle['source_derivation_support'], 'requires_reviewed_contract')

    def test_prepared_command_without_original_execution_binding_is_a_gap(self):
        fixture = self.build('prepared-only', gap='prepared_command_only')
        outcome = json.loads(Path(fixture.refs['controller-verification.json']['path']).read_text())
        self.assertEqual(outcome['program'], {}); self.assertEqual(outcome['inputs'], {})
        self.assertTrue(Path(fixture.refs['emission_source.py']['path']).is_file())
        self.assertIn('executed_emission_source_binding', fixture.oracle['expected_unmet_obligations'])

    def test_specialized_related_subject_is_not_retyped_or_accepted_by_an_ordinary_fixture(self):
        fixture = self.build('specialized', gap='specialized_related_unvalidated')
        specialized = fixture.related[1]
        self.assertEqual(specialized['qualification_role'], 'fixture')
        self.assertEqual(specialized['client_mode'], 'qualification-fixture')
        self.assertIn('specialized_receipt_replay', fixture.oracle['expected_unmet_obligations'])
        row = migration.assess(fixture.manifest['path'])['cases'][0]
        self.assertEqual(row['related_qualification_records'], 1)
        self.assertFalse(row['recovery_eligible'])

    def test_unknown_fixture_variant_is_rejected_instead_of_creating_a_false_positive(self):
        with self.assertRaises(ValueError):self.build('unknown', gap='pretend_missing_fact')

    def test_missing_guard_keeps_other_cid_separate(self):
        fixture = self.build('guard', gap='missing_helper_guard_cid')
        self.assertNotIn('container_id', fixture.record)
        ledger = json.loads(Path(fixture.refs['ledger.json']['path']).read_text())
        self.assertTrue(ledger['launches'][0]['container_id'])
        self.assertNotEqual(ledger['launches'][0]['launch_id'], fixture.launch_id)
        self.assertIn('original_helper_guard_cid', fixture.oracle['expected_unmet_obligations'])

    def test_interrupted_worker_only_case_does_not_create_a_helper_terminal(self):
        fixture = self.build('worker-only', gap='interrupted_worker_only')
        self.assertNotIn('launcher-start.json', fixture.refs)
        self.assertNotIn('launcher-terminal.json', fixture.refs)
        self.assertIsNone(fixture.oracle['actual_helper_exit'])
        row = migration.assess(fixture.manifest['path'])['cases'][0]
        self.assertEqual(row['controller_terminals'][0]['actual_exit'], 2)
        self.assertEqual(row['launcher_terminals'], [])
        self.assertIn('original_helper_guard_cid', row['missing_facts'])

    def test_fresh_stat_does_not_fill_missing_original_workspace_identity(self):
        fixture = self.build('snapshot', gap='missing_workspace_identity')
        self.assertTrue(fixture.workspace.is_dir()); self.assertIsNone(fixture.original_identity)
        self.assertNotIn('descriptor.json', fixture.refs)
        self.assertIn('original_workspace_snapshot', fixture.oracle['expected_unmet_obligations'])

    def test_disposable_identity_stays_in_its_original_scope(self):
        fixture = self.build('disposable', scope='diagnostic_disposable')
        terminal = json.loads(Path(fixture.refs['diagnostic-terminal.json']['path']).read_text())
        self.assertEqual(terminal['disposable_root_identity'], fixture.original_identity)
        self.assertNotIn('workspace_identity', terminal); self.assertIsNone(fixture.workspace)
        row = migration.assess(fixture.manifest['path'])['cases'][0]
        self.assertTrue(row['disposable_root_facts']); self.assertIsNone(row['workspace_identity'])

    def test_nonzero_exit_and_protected_failure_are_not_regraded(self):
        fixture = self.build('failed', exit_code=137)
        row = migration.assess(fixture.manifest['path'])['cases'][0]
        self.assertEqual(row['launcher_terminals'][0]['actual_exit'], 137)
        original = json.loads(Path(fixture.refs['protected-result.json']['path']).read_text())
        self.assertEqual(original['status'], 'FAIL'); self.assertFalse(original['safe_to_continue'])
        self.assertFalse(original['qualification_eligible'])

    def test_controller_outcome_mapping_matches_the_bound_source_for_all_exit_classes(self):
        for code in (0, 137, -9):
            fixture = self.build('exit-' + str(code), exit_code=code)
            context = json.loads(Path(fixture.refs['controller-context.json']['path']).read_text())
            outcome = json.loads(Path(fixture.refs['controller-verification.json']['path']).read_text())
            expected = 0 if code == 0 else 2
            self.assertEqual(context['actual_exit'], expected)
            self.assertEqual(outcome['actual_exit'], expected)
            self.assertEqual(fixture.oracle['actual_controller_exit'], expected)
            result = json.loads(Path(fixture.refs['protected-result.json']['path']).read_text())
            self.assertEqual(result['status'], 'FAIL')

    def test_agent_metadata_does_not_claim_a_real_participant_or_clean_stage(self):
        fixture = self.build('prepared')
        stage = json.loads(Path(fixture.refs['stage-state.json']['path']).read_text())
        process = json.loads(Path(fixture.refs['process.json']['path']).read_text())
        self.assertFalse(stage['cleanup_confirmed']); self.assertFalse(process['cleanup_confirmed'])
        self.assertEqual(fixture.oracle['real_participant_invocations'], 0)
        orphan = self.build('orphan', gap='orphan_controls')
        descriptors = {orphan.stage_id}
        control_ids = {p.name for p in (orphan.run / 'controls').iterdir()}
        self.assertTrue(control_ids - descriptors)
        self.assertIn('original_control_descriptor', orphan.oracle['expected_unmet_obligations'])

    def test_wrong_actor_and_unknown_namespace_remain_explicit_gap_cases(self):
        worker = self.build('worker', gap='unrelated_worker_terminal')
        terminal = json.loads(Path(worker.refs['launcher-terminal.json']['path']).read_text())
        self.assertEqual(terminal['pid'], worker.owner_pid)
        self.assertNotEqual(terminal['pid'], worker.launcher_pid)
        with self.assertRaises(migration.AssessmentError):migration.assess(worker.manifest['path'])
        retained = self.build('namespace', gap='unknown_retained_namespace')
        self.assertTrue((retained.run / 'unreviewed-runtime.log').exists())
        self.assertIn('retained_namespace_review', retained.oracle['expected_unmet_obligations'])


if __name__ == '__main__':unittest.main()
