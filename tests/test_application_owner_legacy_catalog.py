"""Source qualification and scope decisions must not execute referenced code."""
import importlib
import contextlib
import io
import json
from unittest import mock

from tests.test_application_owner_legacy_support import LegacyContractTests
from tests import test_application_owner_legacy_namespace as namespace_fixtures
import application_owner_cleanup as cleanup


class SourcePathTests(LegacyContractTests):
    def test_repo_anchored_here_is_derived_from_original_source_not_copy_parent(self):
        api = importlib.import_module('application_owner_legacy_controller')
        original = self.root / 'project' / 'reports' / 'group' / 'design' / 'program.py'
        source = b"from pathlib import Path\nREPO=Path(__file__).resolve().parents[3]\nHERE=REPO/'reports/group/design'\nROOT=HERE.parent/'run'\n"
        values = api.source_paths(source, {'path':str(original),'sha256':'a'*64})
        self.assertEqual(values['HERE'], original.parent)
        self.assertEqual(values['ROOT'], original.parent.parent/'run')
        relocated = self.root / 'copied' / 'one' / 'two' / 'program.py'
        other = api.source_paths(source, {'path':str(relocated),'sha256':'a'*64})
        self.assertNotEqual(other['HERE'], relocated.parent)

    def test_arbitrary_path_expressions_are_rejected_without_evaluation(self):
        api = importlib.import_module('application_owner_legacy_controller')
        source = b"HERE=__import__('os').system('must never execute')\nROOT=HERE/'run'\n"
        with self.assertRaises(cleanup.ownership.RegistryError):
            api.source_paths(source, {'path':str(self.root/'source.py'),'sha256':'a'*64})

    def test_relative_traversal_is_not_a_source_path(self):
        api = importlib.import_module('application_owner_legacy_controller')
        source = b"from pathlib import Path\nHERE=Path(__file__).resolve().parent\nROOT=HERE/'../elsewhere'\n"
        with self.assertRaises(cleanup.ownership.RegistryError):
            api.source_paths(source, {'path':str(self.root/'source.py'),'sha256':'a'*64})

    def test_catalog_profiles_are_closed_and_independent(self):
        catalog = importlib.import_module('application_owner_legacy_catalog')
        controller = importlib.import_module('application_owner_legacy_controller')
        families = catalog.source_families()
        self.assertEqual(set(families), {catalog.ARTIFACT_PRODUCER})
        profile = families[catalog.ARTIFACT_PRODUCER]
        controller.validate_descriptor(profile)
        self.assertEqual(profile['variants'], ('diagnostic_disposable_v1',))
        profile['execution_rule'] = 'changed'
        self.assertEqual(catalog.source_families()[catalog.ARTIFACT_PRODUCER]['execution_rule'],
                         'absolute_owned_host_paths_v1')


class SourceScopedExecutionTests(LegacyContractTests):
    def artifact(self,name='artifact'):
        return namespace_fixtures.LegacyNamespaceTests.artifact(self,name)

    def fixture(self):
        return namespace_fixtures.LegacyNamespaceTests.full_artifact(self)

    def test_explicit_source_scope_rule_preserves_unknown_cwd_without_blocking_identity(self):
        fixture=self.fixture();api=importlib.import_module('application_owner_legacy')
        family=fixture.family();next(iter(family.values()))['execution_rule']='absolute_owned_host_paths_v1'
        with mock.patch.dict(api.SOURCE_FAMILIES,family,clear=True):
            result=api.analyze(fixture.request(),fixture.record,fixture.related,reader=cleanup.Reader())
        self.assertEqual(result['status'],'eligible_for_native_checks')
        for obligation in ('controller_execution','launcher_execution'):
            claim=self.claim(result,obligation)
            self.assertEqual(claim['class'],'derived');self.assertIsNone(claim['value']['cwd'])
            self.assertEqual(claim['value']['cwd_rule'],'absolute_owned_host_paths_v1')

    def test_scope_rule_does_not_replace_an_actual_wait(self):
        fixture=self.fixture();api=importlib.import_module('application_owner_legacy')
        family=fixture.family();next(iter(family.values()))['execution_rule']='absolute_owned_host_paths_v1'
        fixture.rewrite('launcher-terminal.json',lambda body:body.update(wait_confirmed=False,unknown_owned_child=True))
        with mock.patch.dict(api.SOURCE_FAMILIES,family,clear=True):
            with self.assertRaises(cleanup.ownership.RegistryError):
                api.prepare(fixture.request(),fixture.record,fixture.related,reader=cleanup.Reader())

    def test_input_cannot_select_the_execution_rule(self):
        fixture=self.fixture();fixture.envelope['execution_rule']='absolute_owned_host_paths_v1';fixture.flush_envelope()
        with self.assertRaises(cleanup.ownership.RegistryError):self.exercise(fixture,analyze=True)

    def test_missing_rule_keeps_unknown_cwd_unresolved(self):
        fixture=self.fixture();result=self.exercise(fixture,analyze=True)
        self.assertEqual(result['status'],'blocked')
        self.assertEqual({u['obligation'] for u in result['unresolved']},{'controller_execution','launcher_execution'})

    def test_unknown_rule_is_not_a_downgrade_to_original_context(self):
        fixture=self.fixture();api=importlib.import_module('application_owner_legacy')
        family=fixture.family();next(iter(family.values()))['execution_rule']='owner_supplied_rule'
        with mock.patch.dict(api.SOURCE_FAMILIES,family,clear=True):
            with self.assertRaises(cleanup.ownership.RegistryError):api.analyze(fixture.request(),fixture.record,fixture.related,reader=cleanup.Reader())

    def test_scope_rule_never_supplies_an_unrecorded_guard_cid(self):
        fixture=self.fixture();api=importlib.import_module('application_owner_legacy')
        family=fixture.family();next(iter(family.values()))['execution_rule']='absolute_owned_host_paths_v1'
        fixture.rewrite('ledger.json',lambda body:body['launches'][0].update(container_id='0'*64))
        with mock.patch.dict(api.SOURCE_FAMILIES,family,clear=True):
            with self.assertRaises(cleanup.ownership.RegistryError):api.analyze(fixture.request(),fixture.record,fixture.related,reader=cleanup.Reader())


class PlanningProjectionTests(LegacyContractTests):
    def test_public_projection_has_only_closed_metadata_counts_and_native_gates(self):
        fixture=self.build();api=importlib.import_module('application_owner_legacy')
        result=self.exercise(fixture,analyze=True);public=api.public_summary(result)
        self.assertEqual(public['status'],'eligible_for_native_checks')
        self.assertFalse(public['admission_authorized']);self.assertFalse(public['cleanup_completed'])
        text=json.dumps(public)
        for private in (str(fixture.root),fixture.launch_id,fixture.cid,str(fixture.owner_pid)):
            self.assertNotIn(private,text)
        self.assertIn('original_lease_and_current_records',public['remaining_native_checks'])

    def test_maintainer_planner_uses_same_pure_layer_without_turning_eligibility_into_authority(self):
        fixture=self.build();api=importlib.import_module('application_owner_legacy')
        assessor=importlib.import_module('application_owner_migration')
        request=fixture.put('new-request.json',fixture.request())
        with mock.patch.dict(api.SOURCE_FAMILIES,fixture.family(),clear=True):
            result=assessor.plan_retained(request['path'],fixture.capture)
        self.assertEqual(result['public']['status'],'eligible_for_native_checks')
        self.assertFalse(result['recovery_eligible']);self.assertFalse(result['cleanup_authorized'])
        self.assertEqual(result['native_actions'],0);self.assertEqual(result['proofs_published'],0)

    def test_planning_is_deterministic_and_cli_emits_only_the_public_projection(self):
        fixture=self.build();api=importlib.import_module('application_owner_legacy')
        assessor=importlib.import_module('application_owner_migration')
        request=fixture.put('new-request.json',fixture.request())
        before=fixture.bytes_snapshot()
        with mock.patch.dict(api.SOURCE_FAMILIES,fixture.family(),clear=True):
            first=assessor.plan_retained(request['path'],fixture.capture)
            second=assessor.plan_retained(request['path'],fixture.capture['path'])
            self.assertEqual(first,second)
            output=io.StringIO()
            with contextlib.redirect_stdout(output):
                code=assessor.main(['--request',request['path'],'--capture',fixture.capture['path']])
        self.assertEqual(code,0);self.assertEqual(json.loads(output.getvalue()),first['public'])
        self.assertEqual(fixture.bytes_snapshot(),before)

    def test_capture_subject_mismatch_is_blocked_without_private_error_details(self):
        fixture=self.build();other=self.build('other')
        assessor=importlib.import_module('application_owner_migration')
        request=fixture.put('new-request.json',fixture.request())
        output=io.StringIO()
        with contextlib.redirect_stdout(output):
            code=assessor.main(['--request',request['path'],'--capture',other.capture['path']])
        self.assertEqual(code,2)
        self.assertEqual(json.loads(output.getvalue()),{
            'status':'BLOCKED','condition':'assessment_input_invalid',
            'admission_authorized':False,'cleanup_authorized':False})
