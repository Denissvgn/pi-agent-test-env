"""A10 pure optional policy/extension/status oracles; no runtime qualification."""
from contextlib import ExitStack
import copy
import json
import math
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'skill/scripts'), str(ROOT / 'skill/runtime')]
import native_budget_controls as controls

TOOLS = ['bash', 'budget_status']
NATIVE = {'max_tool_calls': 8, 'reporting_reserve_calls': 2, 'reporting_reserve_seconds': 30}
LEGACY = {'max_total_tokens': 64000, 'timeout_seconds': 300, 'max_turns': 16}


def snapshot(*, charged=3, known=1, unknown=1, blocked=0, phase=None, accounting='available', maximum=8):
    phase = phase or ('business' if charged < maximum - 2 else 'reporting' if charged < maximum else 'exhausted')
    counts = {'attempted': charged + blocked, 'charged': charged, 'executed_known': known,
              'executed_unknown': unknown, 'grants_consumed': known + unknown, 'blocked': blocked,
              'worker_observed': 0, 'helper_verified': known,
              'executed': None if unknown else known}
    zero = {key: 0 for key in counts}
    remaining = maximum - charged
    return {'schema': 1, 'document_type': 'native_tool_budget_status', 'phase': phase,
            'accounting': accounting, 'limits': {**NATIVE, 'max_tool_calls': maximum},
            'counts': counts, 'per_tool': {'bash': copy.deepcopy(counts),
                                         'budget_status': copy.deepcopy(zero), '__unknown__': copy.deepcopy(zero)},
            'remaining_calls': remaining,
            'remaining_admissible_calls': remaining if accounting == 'available' and phase != 'exhausted' else 0,
            'business_calls_remaining': max(0, remaining - 2) if phase == 'business' else 0,
            'reporting_reserve_calls_remaining': min(remaining, 2), 'assisted': False}


class NativeBudgetControlTests(unittest.TestCase):
    def reject(self, function, *args, **kwargs):
        before = copy.deepcopy((args, kwargs))
        with self.assertRaises(controls.NativeBudgetControlError) as caught:
            function(*args, **kwargs)
        self.assertEqual((args, kwargs), before)
        self.assertTrue(caught.exception.pointer == '' or caught.exception.pointer.startswith('/'))
        self.assertIn(caught.exception.reason, ('contract_invalid', 'operation_not_granted'))
        return caught.exception

    def test_ac54_absent_native_fields_preserve_legacy_shape_order_and_bytes(self):
        for value in (LEGACY, {'timeout_seconds': 1, 'max_turns': 1, 'max_total_tokens': 1}):
            before = json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()
            result = controls.validate_budget(value)
            self.assertEqual(json.dumps(result, ensure_ascii=False, separators=(',', ':')).encode(), before)
            self.assertIsNot(result, value)
            self.assertIsNone(controls.native_limits(value))
            self.assertEqual(set(result), set(LEGACY))
        self.assertIsNone(controls.native_limits({}))

    def test_ac54_complete_native_tuple_is_explicit_copied_and_has_no_defaults(self):
        budget = {**LEGACY, **NATIVE}
        self.assertEqual(controls.validate_budget(budget), budget)
        self.assertEqual(controls.native_limits(budget), NATIVE)
        extracted = controls.native_limits(NATIVE, timeout_seconds=300)
        extracted['max_tool_calls'] = 9
        self.assertEqual(NATIVE['max_tool_calls'], 8)
        self.assertIsNone(controls.native_limits({'timeout_seconds': 300}))
        self.reject(controls.native_limits, LEGACY, required=True)
        self.reject(controls.native_limits, NATIVE)

    def test_ac54_every_partial_native_tuple_and_unknown_new_field_reject(self):
        fields = list(NATIVE)
        for mask in range(1, 7):
            partial = {key: NATIVE[key] for index, key in enumerate(fields) if mask & (1 << index)}
            self.reject(controls.native_limits, {**LEGACY, **partial})
            self.reject(controls.validate_budget, {**LEGACY, **partial})
        for key in ('max_tool_call', 'reporting_reserve_timeout', 'native_budget', 'unexpected'):
            self.reject(controls.native_limits, {**LEGACY, key: 1})
            self.reject(controls.validate_budget, {**LEGACY, key: 1})

    def test_ac54_native_fields_use_strict_integer_types_and_finite_bounds(self):
        invalid = {'max_tool_calls': [1, 0, 501, -1, True, 8.0, '8', None],
                   'reporting_reserve_calls': [0, 8, 21, -1, True, 2.0, '2', None],
                   'reporting_reserve_seconds': [0, 121, 300, True, 30.0, '30', None]}
        for name, values in invalid.items():
            for value in values:
                with self.subTest(name=name, value=value):
                    self.reject(controls.native_limits, {**LEGACY, **NATIVE, name: value})
        minimum = {'max_tool_calls': 2, 'reporting_reserve_calls': 1, 'reporting_reserve_seconds': 1}
        maximum = {'max_tool_calls': 500, 'reporting_reserve_calls': 20, 'reporting_reserve_seconds': 120}
        self.assertEqual(controls.native_limits(minimum, timeout_seconds=2), minimum)
        self.assertEqual(controls.native_limits(maximum, timeout_seconds=121), maximum)

    def test_ac54_timeout_constraint_does_not_round_floats_or_add_elapsed_defaults(self):
        policy = {**NATIVE, 'reporting_reserve_seconds': 120}
        self.assertEqual(controls.native_limits(policy, timeout_seconds=120.5), policy)
        for timeout in (120, 119.9, 0, -1, True, '300', float('inf'), float('nan'), 3601):
            with self.subTest(timeout=timeout):
                with self.assertRaises(controls.NativeBudgetControlError):
                    controls.native_limits(policy, timeout_seconds=timeout)
        self.reject(controls.native_limits, {**LEGACY, **NATIVE}, timeout_seconds=301)
        # A normal elapsed reporting threshold does not alter a valid original policy.
        self.assertEqual(controls.native_limits({**LEGACY, **NATIVE}), NATIVE)

    def test_ac54_complete_budget_preserves_predecessor_validation(self):
        for key, values in [('timeout_seconds', (True, 0, 3601, 300.0)),
                            ('max_turns', (True, 0, 101, '16')),
                            ('max_total_tokens', (True, 0, 10000001, 64000.0))]:
            for value in values:
                self.reject(controls.validate_budget, {**LEGACY, key: value})
        for key in LEGACY:
            value = dict(LEGACY); del value[key]
            self.reject(controls.validate_budget, value)

    def extension(self, value='+2', **kwargs):
        arguments = {'expected_revision': 4, 'current_revision': 4, 'phase': 'business', 'authorized': True}
        arguments.update(kwargs)
        return controls.propose_extension({**LEGACY, **NATIVE}, value, **arguments)

    def test_ac51_extensions_are_max_only_assistance_and_preserve_each_phase(self):
        for phase in ('business', 'reporting', 'exhausted'):
            proposal = self.extension(phase=phase)
            self.assertEqual(proposal['schema'], 1)
            self.assertEqual(proposal['document_type'], 'native_budget_extension_proposal')
            self.assertEqual(proposal['phase'], phase)
            self.assertTrue(proposal['assisted'])
            self.assertEqual(proposal['before'], NATIVE)
            self.assertEqual(proposal['limits'], {**NATIVE, 'max_tool_calls': 10})
            self.assertEqual((proposal['expected_revision'], proposal['next_revision']), (4, 5))
            self.assertNotIn('charged', proposal)
            self.assertNotIn('deadline', proposal)
        self.assertEqual(NATIVE['max_tool_calls'], 8)

    def test_ac51_extension_decimal_grammar_and_cumulative_ceiling(self):
        for value, expected in [('+1', 9), ('+100', 108), ('12', 12), (12, 12), ('500', 500)]:
            with self.subTest(value=value):
                self.assertEqual(self.extension(value)['limits']['max_tool_calls'], expected)
        first = self.extension('+2')
        second = controls.propose_extension(first['limits'], '+3', expected_revision=5,
                                            current_revision=5, phase='reporting', authorized=True,
                                            timeout_seconds=300)
        self.assertEqual(second['limits']['max_tool_calls'], 13)
        self.assertEqual(second['phase'], 'reporting')

    def test_ac51_extension_rejects_unauthorized_stale_malformed_reduced_and_oversize(self):
        for value in ('+0', '0', '-1', '++1', '+01', '01', '1.0', '1e2', ' 12', '12 ',
                      'NaN', '9999', '+500', 8, 7, 501, True, 9.0, None,
                      {'max_tool_calls': 10, 'reporting_reserve_calls': 1}):
            with self.subTest(value=value), self.assertRaises(controls.NativeBudgetControlError):
                self.extension(value)
        for kwargs in ({'authorized': False}, {'authorized': 1}, {'expected_revision': 3},
                       {'current_revision': True}, {'expected_revision': '4'},
                       {'current_revision': 10000, 'expected_revision': 10000}, {'phase': 'paused'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(controls.NativeBudgetControlError):
                self.extension(**kwargs)

    def test_ac52_projection_preserves_unknown_metrics_and_returns_independent_data(self):
        source = snapshot(); expected = copy.deepcopy(source)
        result = controls.public_snapshot(source, allowed_tools=TOOLS)
        self.assertEqual(result, expected)
        self.assertIsNone(result['counts']['executed'])
        self.assertEqual(result['counts']['executed_unknown'], 1)
        self.assertEqual(result['remaining_calls'], 5)
        result['counts']['charged'] = 0
        result['per_tool']['bash']['charged'] = 0
        self.assertEqual(source, expected)
        known = snapshot(known=2, unknown=0)
        self.assertEqual(controls.public_snapshot(known, allowed_tools=TOOLS)['counts']['executed'], 2)

    def test_ac52_all_remaining_and_phase_values_are_checked_against_authoritative_counts(self):
        for charged, phase in ((0, 'reporting'), (3, 'business'), (6, 'reporting'),
                               (8, 'exhausted'), (3, 'exhausted')):
            source = snapshot(charged=charged, known=0, unknown=0, phase=phase)
            self.assertEqual(controls.public_snapshot(source, allowed_tools=TOOLS), source)
            for name in ('remaining_calls', 'remaining_admissible_calls', 'business_calls_remaining',
                         'reporting_reserve_calls_remaining'):
                broken = copy.deepcopy(source); broken[name] += 1
                self.reject(controls.public_snapshot, broken, allowed_tools=TOOLS)
        source = snapshot(accounting='unavailable')
        self.assertEqual(controls.public_snapshot(source, allowed_tools=TOOLS)['remaining_admissible_calls'], 0)
        for source in (snapshot(charged=6, known=0, unknown=0, phase='business'),
                       snapshot(charged=8, known=0, unknown=0, phase='reporting')):
            self.reject(controls.public_snapshot, source, allowed_tools=TOOLS)

    def test_ac52_per_tool_totals_and_execution_source_counts_must_reconcile(self):
        for field in ('attempted', 'charged', 'executed_known', 'executed_unknown',
                      'grants_consumed', 'blocked', 'helper_verified', 'worker_observed'):
            broken = snapshot(); broken['per_tool']['bash'][field] += 1
            self.reject(controls.public_snapshot, broken, allowed_tools=TOOLS)
        for field, bad in [('attempted', 0), ('charged', 99), ('grants_consumed', 99),
                           ('executed_known', 99), ('executed_unknown', 0), ('executed', 0),
                           ('blocked', 99), ('helper_verified', 0)]:
            broken = snapshot(); broken['counts'][field] = bad
            self.reject(controls.public_snapshot, broken, allowed_tools=TOOLS)

    def test_ac52_schema_and_numeric_types_reject_coercion(self):
        for field, bad in [('schema', True), ('schema', 2), ('document_type', 'other'),
                           ('phase', 'automatic'), ('accounting', 'maybe'), ('assisted', 1)]:
            broken = snapshot(); broken[field] = bad
            self.reject(controls.public_snapshot, broken, allowed_tools=TOOLS)
        for field in ('attempted', 'charged', 'executed_known', 'executed_unknown', 'grants_consumed',
                      'blocked', 'worker_observed', 'helper_verified'):
            for bad in (True, -1, 1.0, '1', None, float('inf'), 1000001):
                broken = snapshot(); broken['counts'][field] = bad
                with self.assertRaises(controls.NativeBudgetControlError):
                    controls.public_snapshot(broken, allowed_tools=TOOLS)
        known = snapshot(known=1, unknown=0)
        for bad in (True, 1.0, None):
            broken = copy.deepcopy(known); broken['counts']['executed'] = bad
            self.reject(controls.public_snapshot, broken, allowed_tools=TOOLS)

    def test_ac52_unknown_keys_and_secret_named_tools_never_enter_projection_or_error(self):
        secret = 'CREDENTIAL_OR_ARGUMENT_CANARY'
        for target in ('top', 'limits', 'counts', 'per_tool', 'tool_counts'):
            broken = snapshot()
            node = broken if target == 'top' else broken['per_tool']['bash'] if target == 'tool_counts' else broken[target]
            node[secret] = secret
            error = self.reject(controls.public_snapshot, broken, allowed_tools=TOOLS)
            self.assertNotIn(secret, str(error))
            self.assertNotIn(secret, error.pointer)
        broken = snapshot(); broken['per_tool'][secret] = broken['per_tool'].pop('bash')
        error = self.reject(controls.public_snapshot, broken, allowed_tools=['budget_status', secret])
        self.assertNotIn(secret, str(error))
        for allowed in ([], ['bash'], ['budget_status', 'budget_status'], ['budget_status', 'arbitrary_extension']):
            self.reject(controls.public_snapshot, snapshot(), allowed_tools=allowed)

    def test_ac53_all_modes_use_identical_policy_status_and_explicit_versioned_wrapper(self):
        source = snapshot(); before = copy.deepcopy(source)
        for mode in ('standalone', 'serial', 'indexed', 'parallel'):
            result = controls.mode_view(source, mode=mode, allowed_tools=TOOLS)
            self.assertEqual(set(result), {'schema', 'document_type', 'mode', 'status'})
            self.assertEqual(result['schema'], 1)
            self.assertEqual(result['document_type'], 'native_tool_budget_view')
            self.assertEqual(result['mode'], mode)
            self.assertEqual(result['status'], source)
            self.assertIsNot(result['status'], source)
        self.assertEqual(source, before)
        for bad in ('automatic', 'legacy', '', None, True):
            self.reject(controls.mode_view, source, mode=bad, allowed_tools=TOOLS)

    def test_all_control_helpers_are_pure_and_do_not_resolve_ambient_authority(self):
        source = snapshot()
        with ExitStack() as stack:
            for target in ('builtins.open', 'io.open', 'os.open', 'subprocess.run',
                           'subprocess.Popen', 'socket.create_connection', 'socket.socket'):
                stack.enter_context(mock.patch(target, side_effect=AssertionError('unexpected I/O')))
            stack.enter_context(mock.patch.dict(os.environ, {'PI_APP_CANARY': 'PRIVATE_VALUE'}, clear=True))
            result = controls.validate_budget(LEGACY)
            self.assertIsNone(controls.native_limits(LEGACY))
            proposal = self.extension(phase='reporting')
            view = controls.mode_view(source, mode='indexed', allowed_tools=TOOLS)
        self.assertEqual(result, LEGACY)
        self.assertNotIn('PRIVATE_VALUE', json.dumps([proposal, view]))


if __name__ == '__main__':
    unittest.main()
