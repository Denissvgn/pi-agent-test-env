"""Direct controller fact checks cannot pass merely because cleanup is blocked."""
import hashlib
import importlib
import json
from pathlib import Path
from unittest import mock

from tests.test_application_owner_legacy_support import LegacyContractTests
import application_owner_cleanup as cleanup

ARTIFACT_SOURCE = b'''# Structural source fixture only; never executed or registered in production.
from pathlib import Path
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent / 'retained/diagnostic'
INPUT_PATH = HERE / 'emission-inputs.json'
REVIEW_PATH = HERE / 'source-bindings.json'
AUTHORITY_ID = 'fixture-artifact'
IMAGE = 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
def retain(manifest):
    publish(ROOT / 'manifest.json', manifest)
'''
ARTIFACT_SOURCE_SHA256 = '3d46f7cf55e6e7db3178700a916c1b30c154f670211ad0dca251aabd3b77a5aa'


def original_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


class LegacyControllerTests(LegacyContractTests):
    def exercise(self, *args, **kwargs):
        # These are controller-component tests; later launcher/scope adapters
        # must not mask a controller predicate with an unrelated rejection.
        api = importlib.import_module('application_owner_legacy')
        with mock.patch.dict(api._ADAPTERS, {'controller': api._controller}, clear=True):
            return super().exercise(*args, **kwargs)

    def artifact(self, name='artifact'):
        """Model actual retained field sets, without importing an original program."""
        fixture = self.build(name, scope='diagnostic_disposable', exit_code=0)
        fixture.rewrite_bytes('controller-driver.py', ARTIFACT_SOURCE)
        probe = fixture.put_raw('probe.py', b'# inert probe fixture\n')
        prior = fixture.put_raw('prior.py', b'# inert prior validator fixture\n')
        host_pins = {'scripts/host.py': 'a' * 64}
        runtime_pins = {'runtime/application_client_service.py': 'e' * 64}
        qualification = fixture.record['binding']['run_id']
        fixture.record['binding'] = {'artifact_diagnostic': 'fixture-artifact', 'qualification_id': qualification}
        fixture.record['code_identity'] = {'runtime/application_client_service.py': probe['sha256']}
        def replace_inputs(body):
            body.clear(); body.update(source_pins=host_pins, code_source_pins=runtime_pins,
                                      probe=probe, prior_validator=prior)
        fixture.rewrite('emission-inputs.json', replace_inputs)
        def replace_review(body):
            body.clear(); body.update(schema=1, status='PASS', classification='structural_fixture',
                controlled_validation={}, effect_scope='fixture', inputs=fixture.refs['emission-inputs.json'],
                limitations=[], pre_diagnostic_helper_review={}, probe=probe, program=fixture.refs['controller-driver.py'],
                reviewed_guards=[], supervisor=fixture.refs['supervisor.py'], supports_one_shot_diagnostic=True,
                tests={}, unresolved_findings=[])
        fixture.rewrite('source-bindings.json', replace_review)
        argv = ['python3', '-B', fixture.refs['controller-driver.py']['path'], '--inputs-sha256',
            fixture.refs['emission-inputs.json']['sha256'], '--review-sha256',
            fixture.refs['source-bindings.json']['sha256'], '--outer-deadline', '90.0', '--outer-deadline-wall', '92.0']
        fixture.rewrite('controller-start.json', lambda body: body.update(argv=argv))
        root = fixture.private.parent; root.chmod(0o700)
        manifest = {'schema': 1, 'document_type': 'credential_free_artifact_write_diagnostic',
            'authorization': fixture.refs['authority-observation.json'], 'cells': [],
            'code_identity': fixture.record['code_identity'], 'command': fixture.emission_argv,
            'container_name': fixture.record['container'], 'diagnostic': {'root': str(root), 'kind': 'fixture',
                'started': 1.0, 'started_wall': 2.0, 'deadline': 90.0, 'deadline_wall': 92.0},
            'disposable_root': str(fixture.private), 'gid': 0, 'images': {},
            'inputs': fixture.refs['emission-inputs.json'], 'limits': {}, 'planned_container_launches': 1,
            'qualification_id': qualification, 'source_review': fixture.refs['source-bindings.json'], 'uid': 0}
        fixture.put_retained('runtime-manifest.json', root / 'manifest.json', manifest)
        def bind_ledger(body):
            body['manifest_sha256'] = original_digest(manifest)
            body['launches'][0]['intent_sha256'] = original_digest({k: v for k, v in fixture.record.items()
                                                                  if k not in ('status', 'container_id')})
        fixture.rewrite('ledger.json', bind_ledger)
        fixture.envelope['subject'] = cleanup.subject(fixture.record)
        fixture.envelope['controller']['originals']['context'] = fixture.refs['controller-verification.json']
        fixture.envelope['launchers'][0]['originals']['emitter'] = fixture.refs['controller-driver.py']
        fixture.flush_envelope()
        descriptor = {'family_id': 'artifact_diagnostic_v1', 'binding_format': 'artifact_diagnostic_v1',
            'supervisor_sha256': fixture.family()[next(iter(fixture.family()))]['supervisor_sha256'],
            'variants': ('diagnostic_disposable_v1',), 'host_source_pins_sha256': original_digest(host_pins),
            'runtime_source_pins_sha256': original_digest(runtime_pins), 'probe_sha256': probe['sha256'],
            'prior_validator_sha256': prior['sha256']}
        # A temporary catalog promise isolates metadata binding logic. This source
        # fixture is not the real producer and is never a production trust entry.
        fixed = ARTIFACT_SOURCE_SHA256
        fixture.family = lambda: {fixed: dict(descriptor)}
        return fixture

    def analysis_rejects(self, fixture):
        with self.assertRaises(cleanup.ownership.RegistryError):self.exercise(fixture, analyze=True)

    def test_complete_original_binding_reports_derived_execution_and_actual_wait(self):
        fixture = self.build(); result = self.exercise(fixture, analyze=True)
        execution = self.claim(result, 'controller_execution')
        terminal = self.claim(result, 'controller_terminal')
        self.assertEqual(execution['class'], 'derived'); self.assertEqual(terminal['class'], 'original')
        self.assertEqual(execution['value']['pid'], fixture.owner_pid)
        self.assertEqual(execution['value']['parent_pid'], fixture.owner_pid - 1)
        self.assertEqual(execution['value']['cwd'], str(fixture.root))
        self.assertEqual(terminal['value'], {'pid': fixture.owner_pid, 'actual_exit': 2, 'wait_confirmed': True})
        self.assertEqual(result['status'], 'blocked')
        self.assertTrue(result['unresolved'])

    def test_status_pass_never_changes_nonzero_actual_exit(self):
        fixture = self.build(exit_code=137); result = self.exercise(fixture, analyze=True)
        self.assertEqual(fixture.body('controller-verification.json')['status'], 'PASS')
        self.assertEqual(self.claim(result, 'controller_terminal')['value']['actual_exit'], 2)

    def test_controller_signal_exit_is_a_process_outcome_not_zero(self):
        fixture = self.build()
        fixture.rewrite('controller-context.json', lambda body: body.update(actual_exit=-9))
        fixture.rewrite('controller-verification.json', lambda body: body.update(actual_exit=-9))
        result = self.exercise(fixture, analyze=True)
        self.assertEqual(self.claim(result, 'controller_terminal')['value']['actual_exit'], -9)

    def test_each_pid_parent_argv_and_wait_binding_is_validated_in_analysis(self):
        changes = [('controller-start.json', 'pid', fixture_value) for fixture_value in (1, True)]
        changes += [('controller-verification.json', 'child_pid', 1),
                    ('controller-verification.json', 'wrapper_pid', 1),
                    ('controller-start.json', 'argv', ['python3', 'unrelated.py']),
                    ('controller-verification.json', 'automatic_retries', True)]
        for n, (name, key, value) in enumerate(changes):
            with self.subTest(name=name, key=key, value=value):
                fixture = self.build(str(n)); fixture.rewrite(name, lambda body: body.update({key: value}))
                self.analysis_rejects(fixture)

    def test_original_invoker_and_input_refs_must_match_the_recorded_execution(self):
        for key in ('program', 'inputs', 'invoker', 'controller_context'):
            with self.subTest(key=key):
                fixture = self.build(key)
                fixture.rewrite('source-bindings.json', lambda body: body.update({key: fixture.refs['authority-observation.json']}))
                self.analysis_rejects(fixture)

    def test_missing_emission_dependency_does_not_establish_controller_scope(self):
        fixture = self.build()
        fixture.rewrite('source-bindings.json', lambda body: body.update(source_dependencies=[]))
        self.analysis_rejects(fixture)

    def test_changed_input_cannot_rebind_an_unrelated_owned_launch(self):
        fixture = self.build()
        fixture.rewrite('emission-inputs.json', lambda body: body.update(container='unrelated-container'))
        self.analysis_rejects(fixture)

    def test_both_original_context_verification_shapes_are_supported(self):
        for shape in ('started_at', 'started_wall'):
            with self.subTest(shape=shape):
                fixture = self.build(shape)
                if shape == 'started_wall':
                    def change(body):
                        body.pop('started_at'); body.update(schema=1, started_wall=2.0)
                    fixture.rewrite('controller-context.json', change)
                result = self.exercise(fixture, analyze=True)
                self.assertEqual(self.claim(result, 'controller_execution')['class'], 'derived')

    def test_unknown_wait_preserves_argv_but_never_supplies_actual_terminal(self):
        fixture = self.build()
        fixture.rewrite('controller-verification.json', lambda body: body.update(child_wait_confirmed=False, actual_exit=None))
        result = self.exercise(fixture, analyze=True)
        self.assertEqual(self.claim(result, 'controller_execution')['class'], 'derived')
        terminal = self.claim(result, 'controller_terminal')
        self.assertEqual(terminal['class'], 'candidate'); self.assertIsNone(terminal['value']['actual_exit'])
        self.assertTrue(any(u['obligation'] == 'controller_terminal' for u in result['unresolved']))

    def test_terminal_without_original_cwd_does_not_create_execution_context(self):
        fixture = self.build()
        fixture.envelope['controller']['originals']['context'] = fixture.refs['controller-verification.json']
        fixture.flush_envelope(); result = self.exercise(fixture, analyze=True, known_family=False)
        self.assertEqual(self.claim(result, 'controller_terminal')['class'], 'candidate')
        execution = self.claim(result, 'controller_execution')
        self.assertEqual(execution['class'], 'candidate'); self.assertIsNone(execution['value']['cwd'])
        self.assertTrue(any(u['obligation'] == 'controller_execution' for u in result['unresolved']))

    def test_unknown_source_hash_keeps_original_records_as_candidates(self):
        fixture = self.build(); result = self.exercise(fixture, analyze=True, known_family=False)
        self.assertEqual(self.claim(result, 'controller_execution')['class'], 'candidate')
        terminal = self.claim(result, 'controller_terminal')
        self.assertEqual(terminal['class'], 'candidate'); self.assertEqual(terminal['value']['actual_exit'], 2)

    def test_rehashed_source_cannot_register_a_rule_from_its_own_description(self):
        fixture = self.build()
        fixture.rewrite_bytes('controller-driver.py', b'raise RuntimeError("source is data only")\n')
        result = self.exercise(fixture, analyze=True)
        self.assertEqual(self.claim(result, 'controller_execution')['class'], 'candidate')
        self.assertEqual(self.claim(result, 'controller_terminal')['class'], 'candidate')

    def test_context_exit_does_not_borrow_an_unrelated_terminal_pid(self):
        fixture = self.build()
        fixture.rewrite('controller-verification.json', lambda body: body.update(actual_exit=None, child_wait_confirmed=False))
        result = self.exercise(fixture, analyze=True, known_family=False)
        terminal = self.claim(result, 'controller_terminal')
        self.assertEqual(terminal['value']['actual_exit'], 2)
        self.assertIsNone(terminal['value']['pid']); self.assertIsNone(terminal['value']['wait_confirmed'])
        self.assertEqual(terminal['provenance'], [{'component': 'controller', 'role': 'context'}])

    def test_historical_manifest_hash_keeps_its_ascii_escaping(self):
        api = importlib.import_module('application_owner_legacy_controller')
        data = {'path': '/tmp/fixture-λ'}
        original = hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
        self.assertEqual(api.historical_digest(data), original)
        self.assertNotEqual(api.historical_digest(data), cleanup.digest(data))

    def test_extra_scope_or_approval_fields_are_not_source_binding_authority(self):
        fixture = self.build()
        fixture.rewrite('source-bindings.json', lambda body: body.update(owner_approved=True))
        self.analysis_rejects(fixture)

    def test_catalog_classifies_public_source_without_changing_metadata_privacy(self):
        fixture = self.build(); design = fixture.root / 'design'; design.mkdir(mode=0o755); design.chmod(0o755)
        names = ['controller-driver.py', 'supervisor.py', 'emission_source.py', 'emission-inputs.json', 'source-bindings.json']
        for name in names:
            old = dict(fixture.refs[name]); target = design / name
            Path(old['path']).rename(target)
            new = {'path': str(target), 'sha256': old['sha256']}; fixture.refs[name] = new; fixture._rebind(old, new)
        for name in names[:3]:Path(fixture.refs[name]['path']).chmod(0o644)
        argv = ['python3', fixture.refs['controller-driver.py']['path'], fixture.refs['emission-inputs.json']['path']]
        fixture.rewrite('controller-context.json', lambda body: body.update(argv=argv))
        fixture.rewrite('controller-start.json', lambda body: body.update(argv=argv))
        api = importlib.import_module('application_owner_legacy'); family = fixture.family()
        descriptor = next(iter(family.values()))
        descriptor.update(public_source_roles=('producer', 'supervisor', 'emitter'),
                          readable_metadata_parent_roles=('inputs', 'source_binding'))
        # Inputs cannot provide either policy. Only this test-owned catalog can.
        before = fixture.bytes_snapshot()
        with mock.patch.dict(api.SOURCE_FAMILIES, family, clear=True):
            result = api.analyze(fixture.request(), fixture.record, fixture.related, reader=cleanup.Reader())
            self.assertEqual(self.claim(result, 'controller_execution')['class'], 'derived')
            Path(fixture.refs['source-bindings.json']['path']).chmod(0o644)
            with self.assertRaises(cleanup.ownership.RegistryError):
                api.analyze(fixture.request(), fixture.record, fixture.related, reader=cleanup.Reader())
        self.assertEqual(fixture.bytes_snapshot(), before)

    def test_actual_supervisor_field_sets_keep_known_wait_and_unknown_cwd_separate(self):
        fixture = self.artifact(); result = self.exercise(fixture, analyze=True)
        terminal = self.claim(result, 'controller_terminal'); execution = self.claim(result, 'controller_execution')
        self.assertEqual(terminal['class'], 'original'); self.assertEqual(terminal['value']['actual_exit'], 0)
        self.assertEqual(execution['class'], 'candidate'); self.assertIsNone(execution['value']['cwd'])
        self.assertEqual(result['status'], 'blocked')

    def test_actual_manifest_ledger_instance_is_not_a_locator_only_association(self):
        fixture = self.artifact()
        fixture.rewrite('ledger.json', lambda body: body.update(manifest_sha256='0' * 64))
        self.analysis_rejects(fixture)

    def test_actual_source_pin_maps_are_immutable_catalog_premises(self):
        fixture = self.artifact()
        fixture.rewrite('emission-inputs.json', lambda body: body['source_pins'].update({'scripts/host.py': 'b' * 64}))
        self.analysis_rejects(fixture)

    def test_historical_unicode_intent_and_manifest_hashes_do_not_use_new_encoding(self):
        fixture = self.artifact('artifact-λ'); result = self.exercise(fixture, analyze=True)
        self.assertEqual(self.claim(result, 'controller_terminal')['class'], 'original')
        manifest = fixture.body('runtime-manifest.json')
        fixture.rewrite('ledger.json', lambda body: body.update(manifest_sha256=cleanup.digest(manifest)))
        self.analysis_rejects(fixture)

    def test_artifact_structural_source_identity_is_fixed(self):
        self.assertEqual(hashlib.sha256(ARTIFACT_SOURCE).hexdigest(), ARTIFACT_SOURCE_SHA256)

    def test_malformed_catalog_cannot_classify_source_privacy(self):
        fixture = self.build(); api = importlib.import_module('application_owner_legacy')
        family = fixture.family(); next(iter(family.values()))['readable_metadata_parent_roles'] = ['terminal']
        with mock.patch.dict(api.SOURCE_FAMILIES, family, clear=True):
            with self.assertRaises(cleanup.ownership.RegistryError):
                api.analyze(fixture.request(), fixture.record, fixture.related, reader=cleanup.Reader())

    def test_rehashed_manifest_cannot_claim_a_different_diagnostic_root(self):
        fixture = self.artifact()
        fixture.rewrite('runtime-manifest.json', lambda body: body['diagnostic'].update(root=str(fixture.root)))
        changed = fixture.body('runtime-manifest.json')
        fixture.rewrite('ledger.json', lambda body: body.update(manifest_sha256=original_digest(changed)))
        self.analysis_rejects(fixture)
