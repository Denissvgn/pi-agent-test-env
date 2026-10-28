"""Namespace and authority rejection must happen in pure analysis, before effects."""
import importlib
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest import mock
import uuid

from tests.test_application_owner_legacy_support import LegacyContractTests
from tests import test_application_owner_legacy_roots as root_fixtures
from tests import test_application_owner_legacy_controller as controller_fixtures
import application_owner_cleanup as cleanup

NAMESPACE_SOURCE = controller_fixtures.ARTIFACT_SOURCE + b"CLAIM = HERE.parent / 'claim-context'\n"
SUPERVISOR_SOURCE = b"from pathlib import Path\nHERE = Path(__file__).resolve().parent\nOUT = HERE.parent / 'supervisor-reports'\n"
NAMESPACE_SOURCE_SHA256 = '36258177a2a63a1a4214428b029f8c0ae6df4fea99176e0bda9996758b3d2976'
SUPERVISOR_SOURCE_SHA256 = '944b23e066f011bd2dfd2fb79a10dbd945b8c6e298b0c6be85b6f013c6da04d9'


def digest(value):
    return controller_fixtures.original_digest(value)


class LegacyNamespaceTests(LegacyContractTests):
    def artifact(self, name='artifact'):
        return root_fixtures.LegacyRootTests.artifact(self, name)

    def full_artifact(self):
        fixture = root_fixtures.LegacyRootTests.artifact_full(self)
        descriptor = dict(next(iter(fixture.family().values())))
        fixture.rewrite_bytes('controller-driver.py', NAMESPACE_SOURCE)
        fixture.rewrite_bytes('supervisor.py', SUPERVISOR_SOURCE)
        fixture.rewrite('emission-inputs.json', lambda body: body.update(document_type='artifact_diagnostic_public_inputs',
            credential_values_read=False, private_leaf_reads_or_hashes=False))
        # Move the original-format ledger into the producer-created namespace.
        root = fixture.private.parent
        old = dict(fixture.refs['ledger.json']); body = fixture.body('ledger.json')
        new = fixture.put_retained('ledger.json', root / 'launch-ledger' / 'ledger.json', body); fixture._rebind(old, new)
        output = fixture.root / 'supervisor-reports'; output.mkdir(mode=0o700)
        for name, leaf in (('controller-start.json', 'child-start.json'), ('controller-verification.json', 'verification.json')):
            old = dict(fixture.refs[name]); body = fixture.body(name)
            new = fixture.put_retained(name, output / leaf, body); fixture._rebind(old, new)
        argv = ['python3', '-B', fixture.refs['controller-driver.py']['path'], '--inputs-sha256',
            fixture.refs['emission-inputs.json']['sha256'], '--review-sha256', fixture.refs['source-bindings.json']['sha256'],
            '--outer-deadline', '90.0', '--outer-deadline-wall', '92.0']
        fixture.rewrite('controller-start.json', lambda body: body.update(argv=argv))
        fixture.rewrite('ledger.json', lambda body: body.update(manifest_sha256=digest(fixture.body('runtime-manifest.json'))))
        manifest = fixture.body('runtime-manifest.json')
        probe = {'schema':1,'scope':'storage_primitive_only','write_attempts':1,'outcome':'write_returned',
            'quarantined':False,'process_uid':manifest['uid'],'process_gid':manifest['gid'],
            'artifact_root_identity':{'device':1,'inode':2,'uid':0,'gid':0,'mode':448,'nlink':1,'size':0,'kind':'directory'},
            'declared_relative_path':'outputs/summary.md','body_bytes':74,
            'events':[{'kind':'frozen_trace','function':'_write','event':'return','line':1}],
            'events_dropped':0,'payloads_or_error_messages_retained':False,'participants':0,'inference_calls':0,'credentials':0}
        probe_ref = fixture.put_retained('probe-observation.json', root / 'probe-observation.json', probe)
        claim_ref = fixture.put_retained('claim.json', fixture.root / 'claim-context' / 'claim.json',
            {'schema':1,'document_type':'qualification_one_artifact_diagnostic_claim','authorization':manifest['authorization'],
             'manifest_sha256':digest(manifest),'qualification_id':fixture.record['binding']['qualification_id'],
             'root':str(root),'prior_attempts':193,'prior_participants':9})
        fixture.rewrite('diagnostic-terminal.json', lambda body: body.update(claim=claim_ref,probe_observation=probe_ref,
                                                                          primitive_outcome='write_returned'))
        for path in (root / 'controller.lock', root / 'launch-ledger' / 'ledger.lock', output / 'stderr.log'):
            path.write_bytes(b''); path.chmod(0o600)
        fixture.put_retained('supervisor-intent.json', output / 'intent.json',
            {'schema':1,'program':fixture.refs['controller-driver.py'],'inputs':fixture.refs['emission-inputs.json'],
             'source_review':fixture.refs['source-bindings.json'],'wrapper_pid':fixture.owner_pid-1,
             'started':1.0,'started_wall':2.0,'deadline':90.0,'overall_seconds_max':90,'child_reap_reserve_seconds':4})
        fixture.put_retained('supervisor-stdout.json', output / 'stdout.log',
            {'status':'PASS','terminal':fixture.refs['diagnostic-terminal.json'],'primitive_outcome':'write_returned',
             'container_intents':1,'participants':0})
        fixture.put_retained('tool-terminal.json', output / 'root-tool-terminal.json',
            {'schema':1,'status':'PASS','actual_tool_session':1,'actual_terminal_chunk':'abcdef',
             'actual_tool_exit':0,'supervisor_pid':fixture.owner_pid-1,
             'supervisor_terminal_basis':'Root toolsessioncompletion0; individualsupervisorOSwaitnotrecorded',
             'individual_supervisor_OS_wait_recorded':False,'diagnostic_host_child_pid':fixture.owner_pid,
             'diagnostic_host_child_wait_confirmed':True,'command_verification':{
                 'path':'verification.json','sha256':fixture.refs['controller-verification.json']['sha256']}})
        fixture.envelope['namespace']['originals']['authority'] = fixture.refs['emission-inputs.json']; fixture.flush_envelope()
        descriptor['supervisor_sha256'] = SUPERVISOR_SOURCE_SHA256
        fixture.family = lambda: {NAMESPACE_SOURCE_SHA256:dict(descriptor)}
        return fixture

    def rejects(self, fixture):
        with self.assertRaises(cleanup.ownership.RegistryError):self.exercise(fixture, analyze=True)

    def test_complete_standard_namespace_has_protected_metadata_and_no_authority(self):
        fixture = self.build(); result = self.exercise(fixture, analyze=True)
        self.assertEqual(result['status'], 'eligible_for_native_checks')
        self.assertEqual(result['unresolved'], [])
        self.assertEqual(self.claim(result, 'external_authority')['value'], {'state': 'none_issued', 'contexts': []})
        protected = self.claim(result, 'protected_metadata')['value']
        self.assertEqual(protected, result['metadata'])
        for name in ('descriptor.json', 'stage-state.json', 'stage-credentials.json', 'process.json', 'protected-result.json'):
            self.assertIn(fixture.refs[name], protected)
        self.assertEqual(fixture.body('protected-result.json')['status'], 'FAIL')

    def test_descriptor_set_counts_prepared_metadata_without_claiming_pi_invocation(self):
        fixture = self.build(); result = self.exercise(fixture, analyze=True)
        self.assertEqual(self.claim(result, 'stage_scope')['value'], [fixture.stage_id])
        self.assertFalse(any('participant_invocation' in c['obligation'] for c in result['claims']))

    def test_unknown_retained_raw_log_and_runtime_copy_are_not_key_free(self):
        for name in ('raw.log', 'runtime-copy.py'):
            with self.subTest(name=name):
                fixture = self.build(name); (fixture.run / name).write_text('synthetic unreviewed data')
                self.rejects(fixture)

    def test_orphan_controls_do_not_disappear_when_no_agent_is_registered(self):
        fixture = self.build(gap='orphan_controls'); self.rejects(fixture)

    def test_missing_process_or_credential_metadata_remains_unsupported(self):
        for name in ('process.json', 'stage-credentials.json'):
            with self.subTest(name=name):
                fixture = self.build(name); Path(fixture.refs[name]['path']).unlink(); self.rejects(fixture)

    def test_issued_or_unrevoked_external_authority_is_not_none_issued(self):
        fixture = self.build()
        fixture.rewrite('authority-observation.json', lambda body: body.update(external_authority='issued',
            issued_contexts=[{'id': str(uuid.uuid4()), 'revoked': False}]))
        self.rejects(fixture)

    def test_authority_subject_and_source_are_each_bound(self):
        for field, value in (('registry', '0' * 64), ('generation', str(uuid.uuid4())),
                             ('launch_id', str(uuid.uuid4())), ('producer', {'path': '/synthetic/other.py', 'sha256': '0' * 64})):
            with self.subTest(field=field):
                fixture = self.build(field); fixture.rewrite('authority-observation.json', lambda body: body.update({field: value}))
                self.rejects(fixture)

    def test_historical_pass_or_partial_canary_scan_cannot_certify_the_namespace(self):
        fixture = self.build(gap='unknown_retained_namespace')
        fixture.rewrite('authority-observation.json', lambda body: body.update(scan_passed=True, known_secret_count=1))
        self.rejects(fixture)

    def test_unknown_metadata_fields_cannot_hide_sensitive_payload(self):
        fixture = self.build()
        fixture.rewrite('stage-credentials.json', lambda body: body.update(unreviewed_payload='synthetic secret value'))
        self.rejects(fixture)

    def test_selected_stage_set_is_exact_not_a_caller_omission(self):
        fixture = self.build(); request = fixture.request(); request['stages'] = []
        with self.assertRaises(cleanup.ownership.RegistryError):self.exercise(fixture, request, analyze=True)

    def test_none_issued_cannot_hide_a_private_context_under_a_valid_stage(self):
        fixture = self.build(); segment = fixture.run / 'controls' / fixture.stage_id / 'segments' / str(uuid.uuid4())
        segment.mkdir(mode=0o700, parents=True)
        (segment / 'application-context.json').write_text('{"fixture_only":true}\n')
        self.rejects(fixture)

    def test_unknown_extra_private_root_is_never_authorized_by_shape(self):
        fixture = self.build(); request = fixture.request()
        request['extra_private_roots'] = [{'path': str(fixture.root / 'unrelated'), 'origin': fixture.refs['controller-context.json']}]
        with self.assertRaises(cleanup.ownership.RegistryError):self.exercise(fixture, request, analyze=True)

    def test_unknown_namespace_is_not_fixed_by_deleting_evidence(self):
        fixture = self.build(gap='unknown_retained_namespace'); before = fixture.bytes_snapshot()
        self.rejects(fixture); self.assertEqual(fixture.bytes_snapshot(), before)

    def test_original_failure_flags_are_not_regraded_by_structural_eligibility(self):
        fixture = self.build(); before = fixture.body('protected-result.json'); self.exercise(fixture, analyze=True)
        self.assertEqual(fixture.body('protected-result.json'), before)
        self.assertFalse(before['cleanup_confirmed']); self.assertFalse(before['qualification_eligible'])

    def test_actual_artifact_namespace_and_reports_leave_only_missing_cwd(self):
        fixture = self.full_artifact(); result = self.exercise(fixture, analyze=True)
        self.assertEqual(result['status'], 'blocked')
        self.assertEqual({u['obligation'] for u in result['unresolved']}, {'controller_execution','launcher_execution'})
        self.assertEqual(self.claim(result, 'external_authority')['value'], {'state':'none_issued','contexts':[]})

    def test_artifact_raw_log_cannot_be_classified_by_a_key_scan(self):
        fixture = self.full_artifact(); (fixture.private.parent / 'unknown-raw.log').write_text('synthetic payload')
        self.rejects(fixture)

    def test_artifact_nonempty_stderr_is_not_assumed_key_free(self):
        fixture = self.full_artifact(); (fixture.root / 'supervisor-reports' / 'stderr.log').write_text('unreviewed text')
        self.rejects(fixture)

    def test_container_probe_inode_never_becomes_host_root_identity(self):
        fixture = self.full_artifact(); result = self.exercise(fixture, analyze=True)
        self.assertEqual(self.claim(result, 'original_root_custody')['value']['identity'], fixture.original_identity)
        self.assertNotEqual(fixture.original_identity,[1,2])

    def test_unknown_empty_control_tree_is_not_an_artifact_namespace(self):
        fixture = self.full_artifact(); (fixture.private.parent / 'controls' / 'unrelated').mkdir(mode=0o700, parents=True)
        self.rejects(fixture)

    def test_structural_source_promises_do_not_follow_edited_fixture_code_automatically(self):
        self.assertEqual(hashlib.sha256(NAMESPACE_SOURCE).hexdigest(), NAMESPACE_SOURCE_SHA256)
        self.assertEqual(hashlib.sha256(SUPERVISOR_SOURCE).hexdigest(), SUPERVISOR_SOURCE_SHA256)

    def test_empty_queues_for_a_valid_stage_are_metadata_not_issued_authority(self):
        fixture = self.build()
        for name in ('segments','inbox','outbox'):
            (fixture.run / 'controls' / fixture.stage_id / name).mkdir(mode=0o700,parents=True)
        self.assertEqual(self.exercise(fixture,analyze=True)['status'],'eligible_for_native_checks')

    def test_later_observer_cannot_create_an_individual_wrapper_wait(self):
        fixture = self.full_artifact()
        fixture.rewrite('tool-terminal.json',lambda body:body.update(individual_supervisor_OS_wait_recorded=True))
        self.rejects(fixture)

    def test_probe_text_payload_cannot_be_added_to_key_free_metadata(self):
        fixture = self.full_artifact()
        fixture.rewrite('probe-observation.json',lambda body:body.update(error_message='unreviewed payload'))
        self.rejects(fixture)

    def test_namespace_root_replacement_cannot_hide_behind_held_directory_fd(self):
        api = importlib.import_module('application_owner_legacy_namespace')
        folder = self.root / 'observed'; folder.mkdir(mode=0o700)
        leaf = folder / 'metadata.json'; leaf.write_bytes(b'{"schema":1}'); leaf.chmod(0o600)
        known = [{'path':str(leaf),'sha256':hashlib.sha256(leaf.read_bytes()).hexdigest()}]
        identity = folder.stat(); original = os.listdir; changed = [False]
        def replace(fd):
            result = original(fd)
            info = os.fstat(fd)
            if (info.st_dev,info.st_ino)==(identity.st_dev,identity.st_ino) and not changed[0]:
                folder.rename(self.root / 'saved-observed'); folder.mkdir(mode=0o700); changed[0] = True
            return result
        with mock.patch.object(os,'listdir',side_effect=replace):
            with self.assertRaises(cleanup.ownership.RegistryError):api._scan(cleanup.Reader(),folder,[],known)
        self.assertTrue(changed[0])


class QualificationSharedReaderTests(unittest.TestCase):
    def test_service_receipt_keeps_typed_contract_and_shared_budget(self):
        from tests import test_ownership_registry as fixtures
        case = fixtures.QualificationServiceCleanupTests(); case.setUp(); self.addCleanup(case.doCleanups)
        reference = case.receipt(); reader = cleanup.Reader()
        result = cleanup.ownership.validate_qualification_service_cleanup(case.record, reader=reader)
        self.assertIn(reference['path'], reader.references)
        self.assertFalse(result['qualification_eligible']); case.command.assert_not_called()

    def test_service_original_small_limit_cannot_be_raised_by_shared_reader(self):
        from tests import test_ownership_registry as fixtures
        case = fixtures.QualificationServiceCleanupTests(); case.setUp(); self.addCleanup(case.doCleanups)
        reference = case.receipt(); target = Path(reference['path']); target.write_bytes(b' ' * 65537)
        with self.assertRaises(cleanup.ownership.RegistryError):
            cleanup.ownership.validate_qualification_service_cleanup(case.record, reader=cleanup.Reader())

    def test_preworker_graph_uses_one_reader_and_no_historical_pid_probe(self):
        from tests import test_ownership_registry as fixtures
        case = fixtures.QualificationPreworkerTests(); case.setUp(); self.addCleanup(case.doCleanups)
        with mock.patch.object(os, 'kill', side_effect=ProcessLookupError):reference = case.write()
        reader = cleanup.Reader()
        with mock.patch.object(os, 'kill', side_effect=AssertionError('Passive qualification replay probed PID')):
            result = cleanup.ownership.validate_qualification_preworker_cleanup(case.helper, historical_replay=True, reader=reader)
        self.assertIn(reference['path'], reader.references)
        self.assertIn(case.result_ref['path'], reader.references)
        self.assertIn(str(case.control / 'endpoint.json'), reader.references)
        self.assertFalse(result['stage']['worker_launch_attempted']); case.command.assert_not_called()

    def test_preworker_cannot_reset_budget_for_nested_service_receipts(self):
        from tests import test_ownership_registry as fixtures
        case = fixtures.QualificationPreworkerTests(); case.setUp(); self.addCleanup(case.doCleanups)
        with mock.patch.object(os, 'kill', side_effect=ProcessLookupError):case.write()
        with mock.patch.object(cleanup, 'MAX_REFERENCES', 1), mock.patch.object(os, 'kill', side_effect=AssertionError('No PID probes')):
            with self.assertRaises(cleanup.ownership.RegistryError):
                cleanup.ownership.validate_qualification_preworker_cleanup(case.helper, historical_replay=True, reader=cleanup.Reader())
