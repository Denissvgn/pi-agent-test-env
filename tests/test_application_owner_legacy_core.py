"""Pure graph checks must remain incomplete until semantic adapters discharge facts."""
import copy
import importlib
from pathlib import Path
from unittest import mock

from tests.test_application_owner_legacy_support import LegacyContractTests
import application_owner_cleanup as cleanup


class LegacyCoreTests(LegacyContractTests):
    def test_bound_role_graph_is_not_a_supported_semantic_proof(self):
        fixture = self.build(); result = self.exercise(fixture, analyze=True)
        self.assertEqual(result['status'], 'blocked')
        self.assertTrue(result['unresolved'])
        self.assertEqual([c['class'] for c in result['claims']], ['original', 'candidate'])
        self.assertEqual(result['roots'], [])

    def test_analysis_does_not_mutate_request_or_current_record_arguments(self):
        fixture = self.build(); request = fixture.request()
        before = copy.deepcopy((request, fixture.record, fixture.related))
        self.exercise(fixture, request, analyze=True)
        self.assertEqual(before, (request, fixture.record, fixture.related))

    def test_shared_reader_covers_source_bytes_and_nested_role_reuse(self):
        fixture = self.build(); api = importlib.import_module('application_owner_legacy')
        reader = cleanup.Reader()
        api.analyze(fixture.request(), fixture.record, fixture.related, reader=reader)
        self.assertIn(fixture.refs['controller-driver.py']['path'], reader.references)
        self.assertIn(fixture.refs['emission_source.py']['path'], reader.references)
        self.assertIn(fixture.refs['controller-context.json']['path'], reader.references)
        self.assertEqual(reader.bytes, sum(len(Path(path).read_bytes()) for path in reader.references))

    def test_aggregate_reference_budget_spans_all_components(self):
        fixture = self.build()
        with mock.patch.object(cleanup, 'MAX_REFERENCES', 3):self.reject(fixture)

    def test_unknown_timestamp_and_duplicate_unknowns_reject(self):
        for variant in ('timestamp', 'duplicate'):
            with self.subTest(variant=variant):
                fixture = self.build(variant)
                if variant == 'timestamp':fixture.envelope['produced_at'] = '2026-02-31T00:00:00Z'
                else:
                    item = {'obligation': 'scoped_writers', 'reason': 'not_located'}
                    fixture.envelope['unknowns'] = [item, dict(item)]
                fixture.flush_envelope(); self.reject(fixture)

    def test_declared_unknown_is_preserved_without_stating_global_nonexistence(self):
        fixture = self.build()
        fixture.envelope['unknowns'] = [{'obligation': 'scoped_writers', 'reason': 'not_located'}]
        fixture.flush_envelope(); result = self.exercise(fixture, analyze=True)
        self.assertIn({'obligation': 'scoped_writers', 'reason': 'not_located', 'launch_id': None}, result['unresolved'])
        self.assertNotEqual(result['status'], 'eligible_for_native_checks')

    def test_adapter_cannot_discharge_obligations_by_only_clearing_missing_list(self):
        fixture = self.build(); api = importlib.import_module('application_owner_legacy')
        def incomplete(result, *unused):result['unresolved'].clear()
        with mock.patch.dict(api._ADAPTERS, {'controller': incomplete}, clear=True):
            result = self.exercise(fixture, analyze=True)
        self.assertTrue(result['unresolved']); self.assertEqual(result['status'], 'blocked')

    def test_claim_cannot_fabricate_provenance_to_an_unrecognized_role(self):
        fixture = self.build(); api = importlib.import_module('application_owner_legacy')
        def forged(result, *unused):
            result['claims'].append({'obligation': 'controller_terminal', 'class': 'derived',
                'value': {'pid': fixture.owner_pid, 'actual_exit': 0, 'wait_confirmed': True},
                'provenance': [{'component': 'controller', 'role': 'owner_assertion'}],
                'rule': {'id': 'supervised_controller_v1', 'version': 1}})
        with mock.patch.dict(api._ADAPTERS, {'controller': forged}, clear=True):self.reject(fixture)

    def test_confirmed_claim_values_use_exact_types_and_closed_fields(self):
        fixture = self.build(); api = importlib.import_module('application_owner_legacy')
        def forged(result, *unused):
            result['claims'].append({'obligation': 'controller_terminal', 'class': 'derived',
                'value': {'pid': fixture.owner_pid, 'actual_exit': False, 'wait_confirmed': True},
                'provenance': [{'component': 'controller', 'role': 'terminal'}],
                'rule': {'id': 'supervised_controller_v1', 'version': 1}})
        with mock.patch.dict(api._ADAPTERS, {'controller': forged}, clear=True):self.reject(fixture)

    def test_primary_and_specialized_record_schemas_are_not_retyped(self):
        for schema in (True, 0, 4):
            with self.subTest(schema=schema):
                fixture = self.build(str(schema)); fixture.record['schema'] = schema
                self.reject(fixture)

    def test_conflicting_claim_cannot_be_hidden_beside_an_original_fact(self):
        fixture = self.build(); api = importlib.import_module('application_owner_legacy')
        def conflicting(result, *unused):
            result['claims'].append({'obligation': 'subject_identity', 'class': 'contradiction',
                'value': None, 'provenance': [], 'rule': None})
        with mock.patch.dict(api._ADAPTERS, {'controller': conflicting}, clear=True):self.reject(fixture)

    def test_prior_publication_reads_count_globally_without_circular_commitments(self):
        fixture = self.build(); api = importlib.import_module('application_owner_legacy')
        existing = fixture.put('existing-acceptance.json', {'schema': 2, 'document_type': 'synthetic_prior_index'})
        reader = cleanup.Reader(); reader.reference(existing, private=True)
        result = api.analyze(fixture.request(), fixture.record, fixture.related, reader=reader)
        self.assertIn(existing['path'], reader.references)
        self.assertNotIn(existing['path'], {ref['path'] for ref in result['metadata']})
        self.assertEqual(reader.bytes, sum(len(Path(path).read_bytes()) for path in reader.references))

    def test_repeated_validation_in_same_reader_has_same_original_metadata_scope(self):
        fixture = self.build(); api = importlib.import_module('application_owner_legacy')
        reader = cleanup.Reader()
        first = api.analyze(fixture.request(), fixture.record, fixture.related, reader=reader)
        charged = reader.bytes
        second = api.analyze(fixture.request(), fixture.record, fixture.related, reader=reader)
        self.assertEqual(first['metadata'], second['metadata']); self.assertEqual(reader.bytes, charged)

    def test_reader_scopes_include_reused_refs_without_resetting_outer_scope(self):
        fixture = self.build(); api = importlib.import_module('application_owner_legacy')
        reader = cleanup.Reader()
        with reader.custody_scope():
            reader.reference(fixture.refs['legacy-evidence.json'], private=True)
            result = api.analyze(fixture.request(), fixture.record, fixture.related, reader=reader)
            self.assertEqual(reader.scope_references(), result['metadata'])
        with self.assertRaises(cleanup.ownership.RegistryError):reader.scope_references()
