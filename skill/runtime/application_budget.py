"""Authenticated application budget routing with private credential screening.

The trusted parent supplies existing ledgers and exact prepared scopes. Stage
requests can spend/revoke their own finite authority, never initialize a ledger,
restore state, grow budgets or choose a file. Native protocol results stay within
the trusted adapter; only ledger public projections may reach the model.
"""
import copy
import secrets

import application_contracts as c
from tool_budgets import BudgetError, BudgetLedger, COUNTERS

MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_RESPONSE_BYTES = 256 * 1024
ACTIONS = ('reserve', 'consume', 'entry', 'complete', 'reconcile', 'checkpoint', 'status', 'poison')
PUBLIC_FIELDS = {'schema', 'document_type', 'phase', 'accounting', 'limits', 'counts',
                 'per_tool', 'remaining_calls', 'remaining_admissible_calls',
                 'business_calls_remaining', 'reporting_reserve_calls_remaining', 'assisted'}


def _token(value):
    return (type(value) is str and len(value) == 64
            and all(character in '0123456789abcdef' for character in value))


def _wire(value, maximum=MAX_REQUEST_BYTES):
    try:
        body = c.canonical(value)
        if len(body) > maximum:
            raise BudgetError()
        return body
    except (c.ContractError, ValueError, TypeError, RecursionError, OverflowError):
        raise BudgetError() from None


class BudgetRouter:
    """Fixed stage budget tokens, helper-owned redactor and parent-only effects."""
    def __init__(self, authority_service, bindings):
        self._authority = authority_service
        self._redactor = authority_service.redactor
        self._bindings = []
        try:
            if type(bindings) is not dict or not 1 <= len(bindings) <= 64:
                raise BudgetError('contract_invalid')
            application_tokens = [grant['token'] for grant in authority_service._grants]
            application_tokens.append(authority_service._control_token)
            for capability, entry in bindings.items():
                if (not _token(capability) or self._redactor.contains(capability.encode('ascii'))
                        or any(secrets.compare_digest(capability, other) for other in application_tokens)
                        or type(entry) is not dict or set(entry) != {'scope', 'ledger'}
                        or type(entry['ledger']) is not BudgetLedger):
                    raise BudgetError('contract_invalid')
                scope = copy.deepcopy(entry['scope'])
                raw_scope = _wire(scope)
                if (self._redactor.contains(raw_scope) or not self._active_scope(raw_scope)
                        or any(record['wire_scope'] == raw_scope for record in self._bindings)):
                    raise BudgetError('contract_invalid')
                ledger = entry['ledger']
                for key, value in ledger.binding.items():
                    if key == 'pi_release':
                        if value != authority_service.plan['runtime']['pi_release']:
                            raise BudgetError('contract_invalid')
                    elif scope.get(key) != value:
                        raise BudgetError('contract_invalid')
                stage = next(stage for stage in authority_service.plan['stages'] if stage['id'] == scope['stage_name'])
                self._bindings.append({'capability': capability, 'scope': scope,
                                       'wire_scope': raw_scope, 'ledger': ledger,
                                       'tools': set(stage['tools']) | {'__unknown__'}})
        except (AttributeError, KeyError, TypeError, ValueError):
            raise BudgetError('contract_invalid') from None

    def __repr__(self):
        return '<ApplicationBudgetRouter private capabilities and values withheld>'

    def _active_scope(self, wire_scope):
        # Application revocation closes the corresponding budget capability too.
        with self._authority._lock:
            return any(not grant['revoked'] and _wire(grant['scope']) == wire_scope
                       for grant in self._authority._grants)

    def _authenticated(self, bearer, scope):
        valid = _token(bearer)
        candidate = bearer if valid else '0' * 64
        selected = None
        for record in self._bindings:
            if secrets.compare_digest(candidate, record['capability']):
                selected = record
        if not valid or selected is None:
            raise BudgetError()
        raw_scope = _wire(scope)
        if raw_scope != selected['wire_scope'] or not self._active_scope(raw_scope):
            raise BudgetError()
        return selected

    def _effect_binding(self, scope):
        raw_scope = _wire(scope)
        selected = next((record for record in self._bindings if record['wire_scope'] == raw_scope), None)
        if selected is None or not self._active_scope(raw_scope):
            raise BudgetError()
        return selected

    def _poison(self, selected):
        # Neither rejected IDs, payloads, values nor their hashes enter this call.
        try:
            selected['ledger'].poison(copy.deepcopy(selected['scope']))
        except Exception:
            pass  # An unreadable/uncertain ledger already fails closed.
        raise BudgetError()

    def _screen(self, selected, raw_body, bearer=None):
        if (self._redactor.contains(raw_body)
                or type(bearer) is str and self._redactor.contains(bearer.encode('utf-8'))):
            self._poison(selected)

    def _public(self, selected, public):
        if type(public) is not dict or set(public) != PUBLIC_FIELDS:
            raise BudgetError()
        if (type(public['schema']) is not int or public['schema'] != 1
                or public['document_type'] != 'native_tool_budget_status'
                or public['phase'] not in ('business', 'reporting', 'exhausted')
                or public['accounting'] not in ('available', 'unavailable')
                or type(public['assisted']) is not bool):
            raise BudgetError()
        if type(public['limits']) is not dict or set(public['limits']) != {
                'max_tool_calls', 'reporting_reserve_calls', 'reporting_reserve_seconds'}:
            raise BudgetError()
        for value in public['limits'].values():
            if type(value) is not int or value < 1:
                raise BudgetError()
        for field in ('remaining_calls', 'remaining_admissible_calls', 'business_calls_remaining',
                      'reporting_reserve_calls_remaining'):
            if type(public[field]) is not int or public[field] < 0:
                raise BudgetError()
        def counters(value):
            if type(value) is not dict or set(value) != set(COUNTERS) | {'executed'}:
                raise BudgetError()
            for name, count in value.items():
                if name == 'executed' and count is None:
                    continue
                if type(count) is not int or count < 0:
                    raise BudgetError()
        counters(public['counts'])
        if type(public['per_tool']) is not dict or set(public['per_tool']) != selected['tools']:
            raise BudgetError()
        for value in public['per_tool'].values():
            counters(value)

    def _result(self, selected, action, result):
        # Do not let a future ledger change accidentally return private payloads.
        try:
            if action == 'reserve':
                if (type(result) is not dict or set(result) != {'schema', 'calls', 'snapshot'}
                        or type(result['schema']) is not int or result['schema'] != 1
                        or type(result['calls']) is not list or not 1 <= len(result['calls']) <= 500):
                    raise BudgetError()
                for row in result['calls']:
                    if type(row) is not dict or set(row) != {'id', 'name', 'admitted', 'reason'}:
                        raise BudgetError()
                public = result['snapshot']
            elif action == 'consume':
                if type(result) is not dict or set(result) != {'execution_nonce', 'snapshot'} or not _token(result['execution_nonce']):
                    raise BudgetError()
                public = result['snapshot']
            elif action == 'entry':
                if result is not True:
                    raise BudgetError()
                public = None
            else:
                public = result
            if public is not None:
                self._public(selected, public)
            raw_result = _wire(result, MAX_RESPONSE_BYTES)
        except Exception:
            self._poison(selected)
        self._screen(selected, raw_result)
        return copy.deepcopy(result)

    def request(self, bearer, body):
        """Return a native protocol result; the caller wraps no echoed request."""
        # Authentication selects an immutable scope before any ledger access. A
        # missing/foreign scope or capability never routes even a poison action.
        try:
            raw_body = _wire(body)
            raw_bearer = bearer.encode('utf-8') if type(bearer) is str else b''
            contains_secret = self._redactor.contains(raw_body) or self._redactor.contains(raw_bearer)
            if type(body) is not dict or 'scope' not in body:
                raise BudgetError()
            selected = self._authenticated(bearer, body['scope'])
            if contains_secret:
                self._poison(selected)
            if set(body) != {'schema', 'scope', 'action', 'payload'} or type(body['schema']) is not int or body['schema'] != 1:
                raise BudgetError()
            action = body['action']
            if type(action) is not str or action not in ACTIONS:
                raise BudgetError('operation_not_granted')
            result = selected['ledger'].rpc(copy.deepcopy(selected['scope']),
                                             {'action': action, 'payload': body['payload']})
            return self._result(selected, action, result)
        except BudgetError:
            raise
        except Exception:
            raise BudgetError() from None

    def verify_effect(self, grant, scope, native_call_id, tool_name, raw_input):
        """Private helper-only API action gate; no stage RPC exposes this method."""
        try:
            envelope = {'grant': grant, 'scope': scope, 'native_call_id': native_call_id,
                        'tool_name': tool_name, 'raw_input': raw_input}
            raw_envelope = _wire(envelope)
            selected = self._effect_binding(scope)
            self._screen(selected, raw_envelope)
            result = selected['ledger'].verify_effect(grant, copy.deepcopy(selected['scope']),
                                                       native_call_id, tool_name, raw_input)
            if result is not True:
                self._poison(selected)
            return True
        except BudgetError:
            raise
        except Exception:
            raise BudgetError() from None
