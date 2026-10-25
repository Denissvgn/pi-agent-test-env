"""Pure optional native-budget controls and safe cross-mode status views.

No defaults, credentials, helper RPC, deadlines, inference or file I/O live here.
The parent applies proposals through its separately authorized helper control
channel. Native fields remain absent from predecessor budget dictionaries.
"""
import copy
import math
import re

import application_contracts as c

LEGACY_LIMITS = {'timeout_seconds': 3600, 'max_turns': 100, 'max_total_tokens': 10000000}
NATIVE_FIELDS = frozenset({'max_tool_calls', 'reporting_reserve_calls', 'reporting_reserve_seconds'})
PHASES = ('business', 'reporting', 'exhausted')
MODES = ('standalone', 'serial', 'indexed', 'parallel')
SAFE_TOOLS = frozenset({'app_api', 'app_browser', 'artifact_read', 'artifact_write', 'report_write',
                        'budget_status', 'read', 'write', 'edit', 'bash', 'grep', 'find', 'ls', 'fixture_lookup'})
COUNTER_FIELDS = frozenset({'attempted', 'charged', 'executed_known', 'executed_unknown',
                            'grants_consumed', 'blocked', 'worker_observed', 'helper_verified', 'executed'})
SNAPSHOT_FIELDS = frozenset({'schema', 'document_type', 'phase', 'accounting', 'limits', 'counts',
                             'per_tool', 'remaining_calls', 'remaining_admissible_calls',
                             'business_calls_remaining', 'reporting_reserve_calls_remaining', 'assisted'})


class NativeBudgetControlError(c.ContractError):
    """Bounded static diagnostics; unknown keys/values never enter the message."""
    def __init__(self, pointer='', reason='contract_invalid'):
        super().__init__('Invalid native budget control', pointer, reason)


def _fail(pointer='', reason='contract_invalid'):
    raise NativeBudgetControlError(pointer, reason)


def _exact(value, expected, pointer):
    if type(value) is not dict or set(value) != set(expected):
        _fail(pointer)


def _integer(value, pointer, minimum=0, maximum=1000000):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(pointer)
    return value


def _policy(value, *, timeout_seconds=None, pointer=''):
    _exact(value, NATIVE_FIELDS, pointer)
    maximum = _integer(value['max_tool_calls'], pointer + '/max_tool_calls', 2, 500)
    _integer(value['reporting_reserve_calls'], pointer + '/reporting_reserve_calls', 1, min(20, maximum - 1))
    reserve_seconds = _integer(value['reporting_reserve_seconds'], pointer + '/reporting_reserve_seconds', 1, 120)
    if timeout_seconds is not None:
        if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
                or not 0 < timeout_seconds <= 3600 or reserve_seconds >= timeout_seconds):
            _fail(pointer + '/reporting_reserve_seconds')
    return copy.deepcopy(value)


def native_limits(mapping, *, timeout_seconds=None, required=False, pointer=''):
    """Extract an all-or-none native triple from a budget-field dictionary.

    The timeout constraint is the configured stage timeout, never remaining time.
    An explicit finite fractional constraint is accepted without rounding; native
    policy values themselves are always exact integers. Other legacy fields are
    left to validate_budget/the existing caller's validation.
    """
    if type(required) is not bool or type(mapping) is not dict or set(mapping) - (set(LEGACY_LIMITS) | NATIVE_FIELDS):
        _fail(pointer)
    present = NATIVE_FIELDS.intersection(mapping)
    if not present:
        if required:
            _fail(pointer)
        return None
    if present != NATIVE_FIELDS:
        _fail(pointer)
    configured = mapping.get('timeout_seconds')
    if timeout_seconds is not None and configured is not None and timeout_seconds != configured:
        _fail(pointer + '/timeout_seconds')
    bound = configured if timeout_seconds is None else timeout_seconds
    if bound is None:
        _fail(pointer + '/timeout_seconds')
    return _policy({key: mapping[key] for key in mapping if key in NATIVE_FIELDS},
                   timeout_seconds=bound, pointer=pointer)


def validate_budget(mapping):
    """Validate complete legacy limits plus an optional explicit native triple.

    Returns an independent copy in the original insertion order, with no added
    defaults or discriminator. Existing serialized legacy values retain bytes.
    """
    if type(mapping) is not dict or set(mapping) - (set(LEGACY_LIMITS) | NATIVE_FIELDS) or set(LEGACY_LIMITS) - set(mapping):
        _fail('/limits')
    for name, maximum in LEGACY_LIMITS.items():
        _integer(mapping[name], '/limits/' + name, 1, maximum)
    native_limits(mapping, pointer='/limits')
    return copy.deepcopy(mapping)


def propose_extension(mapping, value, *, expected_revision, current_revision, phase,
                      authorized=False, timeout_seconds=None):
    """Produce a parent-only max-call increase proposal; does not apply it.

    `value` is an integer ceiling or a canonical decimal CLI ceiling/+increment.
    Reserve fields and phase remain unchanged. The actual helper independently
    validates its scope, generation, accounting and monotonic state at commit.
    """
    if authorized is not True:
        _fail('/authorized', 'operation_not_granted')
    _integer(current_revision, '/current_revision', 0, 9999)
    _integer(expected_revision, '/expected_revision', 0, 9999)
    if expected_revision != current_revision or type(phase) is not str or phase not in PHASES:
        _fail('/expected_revision' if expected_revision != current_revision else '/phase')
    before = native_limits(mapping, timeout_seconds=timeout_seconds, required=True, pointer='/limits')
    if type(value) is int:
        maximum = value
    elif type(value) is str and re.fullmatch(r'\+?[1-9][0-9]{0,2}', value):
        number = int(value.lstrip('+'))
        maximum = before['max_tool_calls'] + number if value.startswith('+') else number
    else:
        _fail('/max_tool_calls')
    if not before['max_tool_calls'] < maximum <= 500:
        _fail('/max_tool_calls')
    after = copy.deepcopy(before); after['max_tool_calls'] = maximum
    return {'schema': 1, 'document_type': 'native_budget_extension_proposal',
            'expected_revision': current_revision, 'next_revision': current_revision + 1,
            'before': before, 'limits': after, 'phase': phase, 'assisted': True}


def _counters(value, pointer):
    _exact(value, COUNTER_FIELDS, pointer)
    for name in COUNTER_FIELDS - {'executed'}:
        _integer(value[name], pointer + '/' + name)
    attempted, charged, grants = value['attempted'], value['charged'], value['grants_consumed']
    known, unknown = value['executed_known'], value['executed_unknown']
    if not grants <= charged <= attempted or value['blocked'] > attempted or known + unknown != grants:
        _fail(pointer)
    if (value['worker_observed'] > known or value['helper_verified'] > known
            or not known <= value['worker_observed'] + value['helper_verified'] <= 2 * known):
        _fail(pointer)
    if unknown:
        if value['executed'] is not None:
            _fail(pointer + '/executed')
    elif type(value['executed']) is not int or value['executed'] != known:
        _fail(pointer + '/executed')


def public_snapshot(snapshot, *, allowed_tools):
    """Validate/project a trusted ledger view; reject hidden data rather than echo it.

    allowed_tools comes from the reviewed profile, never from received per_tool
    keys. No user-selected identifiers, routes, payloads or private digests occur
    in this public schema. Unknown execution remains null, never false zero.
    """
    _exact(snapshot, SNAPSHOT_FIELDS, '/native_budget')
    _integer(snapshot['schema'], '/native_budget/schema', 1, 1)
    if snapshot['document_type'] != 'native_tool_budget_status':
        _fail('/native_budget/document_type')
    if type(snapshot['phase']) is not str or snapshot['phase'] not in PHASES:
        _fail('/native_budget/phase')
    if type(snapshot['accounting']) is not str or snapshot['accounting'] not in ('available', 'unavailable'):
        _fail('/native_budget/accounting')
    if type(snapshot['assisted']) is not bool:
        _fail('/native_budget/assisted')
    limits = _policy(snapshot['limits'], pointer='/native_budget/limits')
    _counters(snapshot['counts'], '/native_budget/counts')
    counts = snapshot['counts']
    if counts['charged'] > limits['max_tool_calls']:
        _fail('/native_budget/counts/charged')
    if (type(allowed_tools) not in (tuple, list, set, frozenset)
            or not allowed_tools or any(type(name) is not str or name not in SAFE_TOOLS for name in allowed_tools)
            or len(set(allowed_tools)) != len(allowed_tools) or 'budget_status' not in allowed_tools):
        _fail('/native_budget/per_tool')
    expected_tools = set(allowed_tools) | {'__unknown__'}
    _exact(snapshot['per_tool'], expected_tools, '/native_budget/per_tool')
    for name in expected_tools:
        # The pointer deliberately contains no received dictionary key.
        _counters(snapshot['per_tool'][name], '/native_budget/per_tool')
    for name in COUNTER_FIELDS - {'executed'}:
        if sum(item[name] for item in snapshot['per_tool'].values()) != counts[name]:
            _fail('/native_budget/per_tool')
    phase, accounting = snapshot['phase'], snapshot['accounting']
    remaining = limits['max_tool_calls'] - counts['charged']
    if (phase == 'business' and counts['charged'] >= limits['max_tool_calls'] - limits['reporting_reserve_calls']
            or remaining == 0 and phase != 'exhausted'):
        _fail('/native_budget/phase')
    derived = {'remaining_calls': remaining,
               'remaining_admissible_calls': remaining if accounting == 'available' and phase != 'exhausted' else 0,
               'business_calls_remaining': max(0, remaining - limits['reporting_reserve_calls']) if phase == 'business' else 0,
               'reporting_reserve_calls_remaining': min(remaining, limits['reporting_reserve_calls'])}
    for name, expected in derived.items():
        if type(snapshot[name]) is not int or snapshot[name] != expected:
            _fail('/native_budget/' + name)
    return copy.deepcopy(snapshot)


def mode_view(snapshot, *, mode, allowed_tools):
    """Same policy/view for every execution mode; no mode-specific grant expansion."""
    if type(mode) is not str or mode not in MODES:
        _fail('/mode')
    return {'schema': 1, 'document_type': 'native_tool_budget_view', 'mode': mode,
            'status': public_snapshot(snapshot, allowed_tools=allowed_tools)}
