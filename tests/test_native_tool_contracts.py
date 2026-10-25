"""Pinned native schema regression oracles; no Pi/model/container invocation."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'skill/runtime'), str(ROOT / 'skill/scripts')]
import native_tool_contracts as native
import prompt_contract
import release_contracts
from tool_budgets import BudgetLedger

# Independently captured from exact source expressions evaluated with the
# SHA512-verified TypeBox1.3.27 distribution pinned by both upstream lockfiles.
SCHEMA_HASHES = {
    'read': '5fad0fa7493528bc4284f5c447781325f67099f5fc018206efdc461d33962e85',
    'write': '7e51d1de0f2ccb5fe8de82d51ee3a1d9065e3c4f7c53497ce12f283d6f2f5aa0',
    'edit': '394741d0cb4c9a6fe96d3275897405c8b13a1c7ff712426a942c10d484993fa1',
    'bash': '854beb37435894c8f97dcad8d4610c0ea1458b57a6a8d4bb5b0ea435cdaa5893',
    'grep': '1719e16b7adf706f60c917518c56a1aff9dfd765ed2041895287f0eee07dfa47',
    'find': 'de399f2b4b2fc8a8b3ab87c0f9dba39d882b9c2085153c23ee32fef53c48efba',
    'ls': 'e51884a69b5d7a6a7fe09eda2fe922a38dea8f315af2cc91120d52697f6ab035',
    'fixture_lookup': '3d82e992e0515b8da1130eb9547031ced3e1f4d31998ddd082ce39c03a3b02dc',
    'budget_status': 'd746974fa9afd5e951f76f9af38954b0ad7f436f2120dc974da65e5ee39f856f',
}
REGISTRY_HASHES = {'0.87.1': 'd130e44d0ea7fe9537dd16c8aa605836c121495a302c81ca3f802c36503f1abb',
                   '1.2.0': '23717f1683eef9c647139842fab51e426c0912ae32442dfd2165d825d3684df8'}


def digest(value):
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


class NativeToolContractTests(unittest.TestCase):
    def test_exact_source_schema_hashes_and_distinct_release_contracts(self):
        for release in ('0.87.1', '1.2.0'):
            with self.subTest(release=release):
                current = native.contract(release)
                self.assertEqual({name: digest(tool['parameters']) for name, tool in current['tools'].items()}, SCHEMA_HASHES)
                self.assertEqual(native.identity(release)['sha256'], REGISTRY_HASHES[release])
                self.assertEqual(set(native.identity(release)), {'id', 'revision', 'sha256'})
                self.assertEqual(current['upstream_commit'], release_contracts.contract(release)['upstream_commit'])
                self.assertFalse(current['native_qualified'])
                self.assertEqual(current['typebox']['version'], '1.3.27')
        self.assertNotEqual(native.identity('0.87.1'), native.identity('1.2.0'))

    def test_real_required_numeric_and_extra_field_semantics_are_not_normalized(self):
        for release in ('0.87.1', '1.2.0'):
            read = native.parameters(release, 'read')
            self.assertEqual(read['required'], ['path'])
            self.assertEqual(read['properties']['offset']['type'], 'number')
            self.assertEqual(read['properties']['limit']['type'], 'number')
            self.assertNotIn('additionalProperties', read)
            ls = native.parameters(release, 'ls')
            self.assertNotIn('required', ls); self.assertNotIn('additionalProperties', ls)
            edit = native.parameters(release, 'edit')
            self.assertEqual(edit['required'], ['path', 'edits'])
            self.assertEqual(edit['properties']['edits']['items']['required'], ['oldText', 'newText'])
            self.assertNotIn('additionalProperties', edit['properties']['edits']['items'])
            self.assertNotIn('minItems', edit['properties']['edits'])
            self.assertNotIn('oldText', edit['properties'])

    def test_only_edit_has_reviewed_pure_preparation_and_canonical_raw_policy(self):
        names = [*native.BUILTINS, 'fixture_lookup', 'budget_status']
        expected = {name: 'reviewed_pure' if name == 'edit' else 'none' for name in names}
        for release in ('0.87.1', '1.2.0'):
            self.assertEqual(native.prepare_arguments(release, names), expected)
            contract = native.contract(release)
            self.assertTrue(contract['public_parameters_observable'])
            self.assertFalse(contract['public_preparation_observable'])
            self.assertEqual(contract['raw_input_policy'], 'strict-unchanged-before-effects')
            self.assertIn('JSON.stringify', contract['runtime_schema_projection'])

    def test_selection_order_and_copy_isolation_preserve_registry_bytes(self):
        expected = native.identity('1.2.0')
        result = native.selected_tools('1.2.0', ['ls', 'edit', 'budget_status'])
        self.assertEqual([tool['name'] for tool in result], ['ls', 'edit', 'budget_status'])
        result[1]['parameters']['properties']['edits']['items']['required'].clear()
        changed = native.contract('1.2.0'); changed['source_pins'].clear(); changed['tools'].clear()
        self.assertEqual(native.identity('1.2.0'), expected)
        self.assertEqual(native.parameters('1.2.0', 'edit')['properties']['edits']['items']['required'], ['oldText', 'newText'])

    def test_unreviewed_release_names_tools_duplicates_and_powershell_are_inadmissible(self):
        for release in [None, True, '', 'latest', '1.2.1', '1.2.0+local', '^0.87.1']:
            with self.subTest(release=release), self.assertRaises(native.NativeToolError): native.contract(release)
        for names in [[], ['read', 'read'], ['powershell'], ['mcp__external'], ['browser'], 'read', [True]]:
            with self.subTest(names=names), self.assertRaises(native.NativeToolError): native.selected_tools('1.2.0', names)

    def test_observed_public_parameters_match_without_requiring_private_preparation_metadata(self):
        observed = native.selected_tools('1.2.0', ['read', 'edit', 'budget_status'])
        for tool in observed:
            tool['sourceInfo'] = {'source': 'builtin'}
            tool['promptGuidelines'] = []
            tool['exposure'] = 'direct'
        actual = native.validate_observed('1.2.0', ['read', 'edit', 'budget_status'], observed)
        self.assertEqual(actual['read'], native.parameters('1.2.0', 'read'))
        self.assertNotIn('prepareArguments', observed[1])

    def test_observed_missing_mutated_or_semantically_normalized_parameters_reject(self):
        base = native.selected_tools('1.2.0', ['read', 'ls', 'write', 'budget_status'])
        variants = []
        value = copy.deepcopy(base); value[0]['parameters']['properties']['offset']['type'] = 'integer'; variants.append(value)
        value = copy.deepcopy(base); value[0]['parameters']['additionalProperties'] = True; variants.append(value)
        value = copy.deepcopy(base); value[1]['parameters']['required'] = []; variants.append(value)
        value = copy.deepcopy(base); value[2]['parameters']['required'].reverse(); variants.append(value)
        value = copy.deepcopy(base); value[0]['parameters']['properties']['path']['description'] += '.'; variants.append(value)
        value = copy.deepcopy(base); del value[0]['parameters']; variants.append(value)
        variants.append(copy.deepcopy(base[:-1])); variants.append(copy.deepcopy(base + [base[0]]))
        for index, value in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(native.NativeToolError):
                native.validate_observed('1.2.0', ['read', 'ls', 'write', 'budget_status'], value)

    def test_only_explicit_reviewed_inactive_builtin_registrations_are_allowed(self):
        selected = ['read', 'budget_status']
        observed = native.selected_tools('1.2.0', selected)
        observed.append({'name': 'powershell', 'parameters': {'type': 'object'}})
        with self.assertRaises(native.NativeToolError): native.validate_observed('1.2.0', selected, observed)
        native.validate_observed('1.2.0', selected, observed, inactive_builtins=['powershell'])
        for unexpected in ['mcp__external', 'arbitrary_plugin', 'fixture_lookup']:
            value = copy.deepcopy(observed); value[-1]['name'] = unexpected
            with self.subTest(name=unexpected), self.assertRaises(native.NativeToolError):
                native.validate_observed('1.2.0', selected, value, inactive_builtins=['powershell'])
        with self.assertRaises(native.NativeToolError): native.validate_observed('1.2.0', selected, observed, inactive_builtins=['fixture_lookup'])
        with self.assertRaises(native.NativeToolError): native.selected_tools('1.2.0', ['powershell'])

    def test_fixture_and_status_declarations_match_shipped_contracts(self):
        fixture = native.parameters('1.2.0', 'fixture_lookup')
        self.assertEqual(fixture['properties']['key'], {'type': 'string', 'minLength': 1, 'maxLength': 64, 'pattern': '^[a-z0-9-]+$'})
        self.assertEqual(fixture['required'], ['key']); self.assertIs(fixture['additionalProperties'], False)
        actual = prompt_contract.tool_schemas({'tools': ['budget_status'], 'operations': [], 'browser_targets': []})
        self.assertEqual(native.selected_tools('1.2.0', ['budget_status']), actual)
        raw = (ROOT / 'skill/assets/profiles/fixture-lookup/fixture-lookup.mjs').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), native.contract('1.2.0')['local_schema_sources']['fixture_lookup']['sha256'])

    def test_validation_and_schema_selection_perform_no_io_or_discovery(self):
        observed = native.selected_tools('1.2.0', ['read', 'budget_status'])
        with mock.patch('builtins.open', side_effect=AssertionError('unreviewed file access')):
            native.selected_tools('1.2.0', ['read', 'budget_status'])
            native.prepare_arguments('1.2.0', ['read', 'budget_status'])
            native.validate_observed('1.2.0', ['read', 'budget_status'], observed)
        for value in [float('nan'), {'bad': float('inf')}, {'bad': b'not-json'}]:
            with self.assertRaises(native.NativeToolError): native.canonical(value)

    def test_actual_frozen_schemas_admit_native_shapes_and_reject_invalid_fixture_keys(self):
        for release in ('0.87.1', '1.2.0'):
            with self.subTest(release=release), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve(); root.chmod(0o700)
                binding = {key: str(uuid.uuid4()) for key in ('run_id', 'attempt_id', 'stage_id', 'session_id')}
                binding.update(plan_sha256='1' * 64, trial_id=None, pi_release=release)
                segment = str(uuid.uuid4()); scope = {**binding, 'segment_id': segment}
                names = [*native.BUILTINS, 'fixture_lookup', 'budget_status']
                ledger = BudgetLedger.create(root / 'budget.json', binding=binding,
                    limits={'max_tool_calls': 20, 'reporting_reserve_calls': 2, 'reporting_reserve_seconds': 5},
                    native_tools=native.selected_tools(release, names), prepare_arguments=native.prepare_arguments(release, names),
                    initial_segment_id=segment, deadline=100, profile='fixture-lookup', clock=lambda: 0)
                calls = [
                    {'id': 'read', 'name': 'read', 'arguments': {'path': 'file', 'offset': 1.5, 'extra': True}},
                    {'id': 'ls', 'name': 'ls', 'arguments': {}},
                    {'id': 'edit', 'name': 'edit', 'arguments': {'path': 'file', 'edits': [{'oldText': 'a', 'newText': 'b', 'extra': True}]}},
                    {'id': 'fixture-valid', 'name': 'fixture_lookup', 'arguments': {'key': 'lowercase-1'}},
                    {'id': 'fixture-invalid', 'name': 'fixture_lookup', 'arguments': {'key': 'UPPER_bad'}},
                    {'id': 'status-invalid', 'name': 'budget_status', 'arguments': {'extra': True}}]
                result = ledger.reserve_batch(scope, 'shapes', calls)
                self.assertEqual([row['admitted'] for row in result['calls']], [True, True, True, True, False, False])
                self.assertEqual(result['snapshot']['counts']['charged'], 6)


if __name__ == '__main__':
    unittest.main()
