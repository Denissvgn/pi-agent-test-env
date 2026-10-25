"""Budget-only mode of the owned helper; no application or filesystem tool RPC.

The private parent bootstrap fixes all tools, scopes and limits. Stage capabilities
can only spend their ledger. Only the separate parent control capability can
extend a budget or explicitly authorize a continuation.
"""
import copy
import os
from pathlib import Path
import secrets
import stat
import threading
import time

import application_contracts as c
import application_credentials as credentials
from application_budget import BudgetRouter
from tool_budgets import BudgetError, BudgetLedger, BINDING_FIELDS


def token(value):
    if type(value) is not str or len(value) != 64 or any(ch not in '0123456789abcdef' for ch in value):
        raise BudgetError()
    return value


def private_root(value):
    path = Path(value)
    if not path.is_absolute():
        raise BudgetError()
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent); parent = child
        info = os.fstat(parent)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise BudgetError()
    finally:
        os.close(parent)
    return path


class BudgetOnlyService:
    def __init__(self, configuration, *, verify_code, clock=time.monotonic):
        c.exact(configuration, {'schema', 'document_type', 'mode', 'pi_release', 'control_token',
                                'code_identity', 'state_root', 'evidence_root', 'stage',
                                'redaction_values'}, '')
        c.choice(configuration['schema'], (1,), '/schema')
        c.choice(configuration['document_type'], ('native_budget_private_bootstrap',), '/document_type')
        c.choice(configuration['mode'], ('budget-only',), '/mode')
        c.choice(configuration['pi_release'], c.RELEASES, '/pi_release')
        verify_code(configuration['code_identity'])
        self._lock, self.clock = threading.RLock(), clock
        self._control_token = token(configuration['control_token'])
        self._state_root = private_root(configuration['state_root'])
        self._evidence_root = private_root(configuration['evidence_root'])
        if (self._state_root == self._evidence_root or self._state_root in self._evidence_root.parents
                or self._evidence_root in self._state_root.parents):
            raise BudgetError()
        c.array(configuration['redaction_values'], '/redaction_values', 1024)
        for value in configuration['redaction_values']:
            c.text(value, '/redaction_values', 16384)
        self.redactor = credentials.Redactor(configuration['redaction_values'])
        stage = configuration['stage']
        c.exact(stage, {'scope', 'authority_token', 'budget_token', 'limits', 'tools',
                        'prepare_arguments', 'profile', 'remaining_seconds'}, '/stage')
        scope = copy.deepcopy(stage['scope'])
        c.exact(scope, BINDING_FIELDS | {'segment_id', 'stage_name'}, '/stage/scope')
        c.slug(scope['stage_name'], '/stage/scope/stage_name')
        if scope['pi_release'] != configuration['pi_release']:
            raise BudgetError()
        # BudgetLedger validates all UUID/digest and schema fields before writing.
        if self.redactor.contains(c.canonical(scope)):
            raise BudgetError()
        self._authority_token, self._budget_token = token(stage['authority_token']), token(stage['budget_token'])
        if len({self._authority_token, self._budget_token, self._control_token}) != 3:
            raise BudgetError()
        if any(self.redactor.contains(value.encode()) for value in
               (self._authority_token, self._budget_token, self._control_token)):
            raise BudgetError()
        if self.redactor.contains(c.canonical({key: value for key, value in stage.items()
                                              if key not in ('authority_token', 'budget_token')})):
            raise BudgetError()
        c.choice(stage['profile'], ('builtin', 'fixture-lookup'), '/stage/profile')
        self._issued = {self._authority_token, self._budget_token, self._control_token}
        remaining = stage['remaining_seconds']
        if type(remaining) not in (int, float) or not 0 < remaining <= 3600:
            raise BudgetError()
        self._grants = [{'token': self._authority_token, 'scope': scope, 'revoked': False}]
        import native_tool_contracts
        names = [tool['name'] for tool in stage['tools']]
        if (stage['tools'] != native_tool_contracts.selected_tools(scope['pi_release'], names)
                or stage['prepare_arguments'] != native_tool_contracts.prepare_arguments(scope['pi_release'], names)):
            raise BudgetError('runtime_mismatch')
        self.plan = {'runtime': {'pi_release': scope['pi_release']},
                     'stages': [{'id': scope['stage_name'], 'tools': names}]}
        self.ledger = BudgetLedger.create(self._state_root / 'native-budget.json',
            binding={key: scope[key] for key in BINDING_FIELDS}, limits=stage['limits'],
            native_tools=stage['tools'], initial_segment_id=scope['segment_id'],
            deadline=clock() + remaining, profile=stage['profile'],
            prepare_arguments=stage['prepare_arguments'], clock=clock)
        self._router = self._new_router()
        self.mode = 'budget-only'

    def __repr__(self):
        return '<BudgetOnlyService private authority withheld>'

    def _new_router(self):
        return BudgetRouter(self, {self._budget_token: {'scope': self._grants[-1]['scope'], 'ledger': self.ledger}})

    def _parent(self, bearer):
        valid = type(bearer) is str and len(bearer) == 64 and all(ch in '0123456789abcdef' for ch in bearer)
        if not secrets.compare_digest(bearer if valid else '0' * 64, self._control_token) or not valid:
            raise BudgetError()

    def request(self, path, bearer, body):
        with self._lock:
            if path == '/budget':
                return {'ok': True, 'result': self._router.request(bearer, body)}
            if path == '/ipc':
                c.exact(body, {'schema', 'action', 'scope', 'operation_id'}, '')
                c.choice(body['schema'], (1,), '/schema')
                if (body['action'] != 'status' or body['operation_id'] is not None
                        or body['scope'] != self._grants[-1]['scope'] or self._grants[-1]['revoked']
                        or not secrets.compare_digest(token(bearer), self._authority_token)):
                    raise BudgetError()
                return {'schema': 1, 'ok': True, 'business_effects_enabled': False, 'native_budget_enabled': True}
            if path != '/control':
                raise BudgetError()
            self._parent(bearer)
            if type(body) is not dict or body.get('schema') != 1 or type(body.get('schema')) is not int:
                raise BudgetError()
            action = body.get('action')
            if action == 'revoke':
                c.exact(body, {'schema', 'action', 'capability'}, '')
                if not secrets.compare_digest(token(body['capability']), self._authority_token):
                    raise BudgetError()
                self._grants[-1]['revoked'] = True
                return {'schema': 1, 'ok': True, 'revoked': True}
            if self._grants[-1]['revoked']:
                raise BudgetError()
            if action == 'status':
                c.exact(body, {'schema', 'action'}, '')
                return {'schema': 1, 'ok': True, 'budget': self.ledger.snapshot()}
            if action == 'checkpoint':
                c.exact(body, {'schema', 'action'}, '')
                return {'schema': 1, 'ok': True, 'budget': self.ledger.checkpoint(self._grants[-1]['scope'])}
            if action == 'extend':
                c.exact(body, {'schema', 'action', 'max_tool_calls', 'remaining_seconds'}, '')
                remaining = body['remaining_seconds']
                if remaining is not None and (type(remaining) not in (int, float) or not 0 < remaining <= 3600):
                    raise BudgetError()
                result = self.ledger.extend(max_tool_calls=body['max_tool_calls'],
                                            deadline=None if remaining is None else self.clock() + remaining, authorized=True)
                return {'schema': 1, 'ok': True, 'budget': result}
            if action == 'continue':
                c.exact(body, {'schema', 'action', 'segment_id', 'authority_token', 'budget_token'}, '')
                authority, budget = token(body['authority_token']), token(body['budget_token'])
                if authority == budget or authority in self._issued or budget in self._issued:
                    raise BudgetError()
                if self.redactor.contains(c.canonical(body)):
                    raise BudgetError()
                self.ledger.add_segment(body['segment_id'])
                scope = copy.deepcopy(self._grants[-1]['scope']);scope['segment_id'] = body['segment_id']
                self._grants[-1]['revoked'] = True
                self._authority_token, self._budget_token = authority, budget
                self._issued.update((authority, budget))
                self._grants.append({'token': authority, 'scope': scope, 'revoked': False})
                self._router = self._new_router()
                return {'schema': 1, 'ok': True, 'budget': self.ledger.snapshot()}
            raise BudgetError('operation_not_granted')
