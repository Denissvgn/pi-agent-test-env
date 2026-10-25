"""Real in-process capability/redactor/ledger integration, without any network effects."""
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
sys.path[:0] = [str(ROOT / 'skill/scripts'), str(ROOT / 'skill/runtime')]
import application_budget
import application_client_service as service
import application_compiler as compiler
import application_contracts as c
from tool_budgets import BudgetError, BudgetLedger
import test_application_compiler as fixtures

KEY_A = 'synthetic-native-app-canary-123456'
KEY_B = 'synthetic-quoted"app\\canary-second-98765'


def encode(value):
    return json.dumps(value, ensure_ascii=True)[1:-1]


class ApplicationBudgetRouterTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='application-budget-router-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve(); self.root.chmod(0o700)
        evidence = self.root / 'evidence'; evidence.mkdir(mode=0o700)
        source = fixtures.two_stages()
        source['application']['credentials']['other'] = 'DIAGNOSTIC_BOB'
        operation = copy.deepcopy(source['application']['operations'][0])
        operation.update(id='identity-second', credential_alias='other')
        source['application']['operations'].append(operation)
        second = source['stages'][1]
        second.update(credential_aliases=['other'], operations=['identity-second'])
        second['participant']['actor_id'] = 'actor-bob'
        second['completion']['participant']['actor_id'] = 'actor-bob'
        second['completion']['publications'] = []; second['completion']['pagination'] = []
        source, inputs = fixtures.inputs(source)
        self.plan = compiler.compile_plan(source, **inputs)
        common = {'run_id': str(uuid.uuid4()), 'attempt_id': str(uuid.uuid4()), 'trial_id': None,
                  'plan_sha256': self.plan['plan_sha256'], 'authority_generation': str(uuid.uuid4())}
        self.scopes = []
        for stage in self.plan['stages']:
            self.scopes.append({**common, 'stage_id': str(uuid.uuid4()), 'segment_id': str(uuid.uuid4()),
                'session_id': str(uuid.uuid4()), 'stage_name': stage['id'], 'participant': stage['participant'],
                'operation_ids': stage['operations'], 'credential_aliases': stage['credential_aliases']})
        self.app_tokens = ['1' * 64, '2' * 64]
        config = {'schema': 1, 'document_type': 'application_client_private_bootstrap', 'mode': 'authority-only',
                  'plan': self.plan, 'authorities': {'participant': {'persona': KEY_A}, 'second': {'other': KEY_B}},
                  'capabilities': [{'token': token, 'scope': scope} for token, scope in zip(self.app_tokens, self.scopes)],
                  'control_token': '3' * 64, 'evidence_root': str(evidence),
                  'code_identity': {path: hashlib.sha256((ROOT / 'skill' / path).read_bytes()).hexdigest()
                                    for path in service.TRUSTED_CODE}}
        self.authority = service.CapabilityService(config)
        self.ledgers = []
        for scope, stage in zip(self.scopes, self.plan['stages']):
            bound = {key: scope[key] for key in ('plan_sha256', 'run_id', 'trial_id', 'attempt_id', 'stage_id', 'session_id')}
            bound['pi_release'] = self.plan['runtime']['pi_release']
            self.ledgers.append(BudgetLedger.create(self.root / (stage['id'] + '.json'), binding=bound,
                limits={key: stage['limits'][key] for key in ('max_tool_calls', 'reporting_reserve_calls', 'reporting_reserve_seconds')},
                native_tools=stage['tool_schemas'], initial_segment_id=scope['segment_id'], deadline=1300,
                completion=stage['completion'], clock=lambda: 1000, clock_domain='reviewed-local-test-clock'))
        self.budget_tokens = ['4' * 64, '5' * 64]
        self.bindings = {token: {'scope': scope, 'ledger': ledger}
                         for token, scope, ledger in zip(self.budget_tokens, self.scopes, self.ledgers)}
        self.router = application_budget.BudgetRouter(self.authority, self.bindings)

    def request(self, action, payload=None, index=0):
        return self.router.request(self.budget_tokens[index], {'schema': 1, 'scope': self.scopes[index],
            'action': action, 'payload': {} if payload is None else payload})

    def files(self):
        return {path.relative_to(self.root).as_posix(): path.read_bytes() for path in self.root.rglob('*') if path.is_file()}

    def assert_no_canary(self, extra=()):
        values = [KEY_A, KEY_B, encode(KEY_B), encode(encode(KEY_B)), *extra]
        needles = [value.encode() for value in values]
        needles += [hashlib.sha256(value.encode()).hexdigest().encode() for value in values]
        for name, body in self.files().items():
            for needle in needles: self.assertNotIn(needle, body, name)

    def call(self, identifier='call-safe'):
        return {'id': identifier, 'name': 'app_api', 'arguments': {'operation_id': 'identity',
                'path_params': {}, 'query': {}, 'body': None, 'cursor': None}}

    def test_actual_capability_redactor_and_ledger_prescan_native_identity_before_hashing(self):
        call = self.call(KEY_A)
        forbidden_hashes = [c.digest([self.scopes[0]['segment_id'], KEY_A]), c.digest(call['arguments'])]
        with mock.patch.object(self.ledgers[0], 'reserve_batch', wraps=self.ledgers[0].reserve_batch) as reserve:
            with self.assertRaises(BudgetError) as caught:
                self.request('reserve', {'batch_id': 'canary-batch', 'calls': [call], 'stop_reason': 'toolUse'})
            reserve.assert_not_called()
        self.assertEqual(str(caught.exception), 'accounting_unavailable')
        snapshot = self.ledgers[0].snapshot()
        self.assertEqual(snapshot['accounting'], 'unavailable'); self.assertEqual(snapshot['counts']['attempted'], 0)
        self.assertEqual(self.ledgers[1].snapshot()['accounting'], 'available')
        self.assert_no_canary(forbidden_hashes)

    def test_all_selected_application_keys_and_json_escape_layers_are_screened(self):
        # Other-stage values are still private helper authority and must not enter
        # this stage's ledger through nested/escaped raw arguments.
        for index, value in enumerate([KEY_B, encode(KEY_B), encode(encode(KEY_B))]):
            call = self.call('escaped-' + str(index)); call['arguments']['query'] = {'nested': [value]}
            with mock.patch.object(self.ledgers[0], 'reserve_batch', wraps=self.ledgers[0].reserve_batch) as reserve:
                with self.assertRaises(BudgetError):
                    self.request('reserve', {'batch_id': 'escaped-' + str(index), 'calls': [call], 'stop_reason': 'toolUse'})
                reserve.assert_not_called()
            self.assert_no_canary([c.digest(call['arguments'])])
        self.assertEqual(self.ledgers[0].snapshot()['accounting'], 'unavailable')

    def test_canary_in_unknown_envelope_field_or_batch_name_poison_without_echo(self):
        body = {'schema': 1, 'scope': self.scopes[0], 'action': 'reset', 'payload': {}, KEY_A: 'untrusted'}
        with self.assertRaises(BudgetError) as caught: self.router.request(self.budget_tokens[0], body)
        self.assertEqual(str(caught.exception), 'accounting_unavailable')
        self.assert_no_canary()
        self.assertEqual(self.ledgers[0].snapshot()['accounting'], 'unavailable')

    def test_batch_name_and_tool_name_cannot_store_a_secret_before_api_validation(self):
        for field in ['batch_id', 'tool_name']:
            call = self.call()
            batch = KEY_A if field == 'batch_id' else 'safe-batch'
            if field == 'tool_name': call['name'] = KEY_A
            with mock.patch.object(self.ledgers[0], 'reserve_batch', wraps=self.ledgers[0].reserve_batch) as reserve:
                with self.assertRaises(BudgetError):
                    self.request('reserve', {'batch_id': batch, 'calls': [call], 'stop_reason': 'toolUse'})
                reserve.assert_not_called()
            self.assert_no_canary([c.digest([self.scopes[0]['segment_id'], batch])])

    def test_private_effect_verification_screens_grant_id_name_and_arguments(self):
        for field in ['grant', 'native_call_id', 'tool_name', 'raw_input']:
            args = {'grant': '6' * 64, 'scope': self.scopes[0], 'native_call_id': 'safe-id',
                    'tool_name': 'app_api', 'raw_input': self.call()['arguments']}
            args[field] = {'nested': encode(KEY_B)} if field == 'raw_input' else KEY_A
            with self.subTest(field=field), mock.patch.object(self.ledgers[0], 'verify_effect', wraps=self.ledgers[0].verify_effect) as effect:
                with self.assertRaises(BudgetError): self.router.verify_effect(**args)
                effect.assert_not_called()
            self.assert_no_canary()
        self.assertEqual(self.ledgers[0].snapshot()['accounting'], 'unavailable')

    def test_wrong_caps_scopes_and_malformed_envelopes_never_route_any_ledger(self):
        baseline = self.files()
        valid = {'schema': 1, 'scope': self.scopes[0], 'action': 'status', 'payload': {}}
        changed_scope = {**self.scopes[0], 'segment_id': str(uuid.uuid4())}
        actor_scope = {**self.scopes[0], 'participant': {**self.scopes[0]['participant'], 'actor_id': 'wrong'}}
        cases = [('short', valid), ('é' * 64, valid), (self.app_tokens[0], valid),
                 (self.budget_tokens[1], valid), (self.budget_tokens[0], {**valid, 'scope': changed_scope}),
                 (self.budget_tokens[0], {**valid, 'scope': actor_scope}),
                 (self.budget_tokens[0], {k:v for k,v in valid.items() if k != 'scope'}),
                 (self.budget_tokens[0], {**valid, 'scope': None}),
                 (KEY_A, {**valid, 'payload': {'canary': KEY_A}})]
        for bearer, body in cases:
            with self.subTest(bearer_length=len(bearer)), self.assertRaises(BudgetError): self.router.request(bearer, body)
            self.assertEqual(self.files(), baseline)
        with self.assertRaises(BudgetError): self.router.verify_effect('0' * 64, changed_scope, KEY_A, 'app_api', {})
        self.assertEqual(self.files(), baseline)

    def test_invalid_padding_and_unicode_cannot_alias_a_valid_zero_budget_capability(self):
        mapping = {'0' * 64: self.bindings[self.budget_tokens[0]], self.budget_tokens[1]: self.bindings[self.budget_tokens[1]]}
        router = application_budget.BudgetRouter(self.authority, mapping)
        body = {'schema': 1, 'scope': self.scopes[0], 'action': 'status', 'payload': {}}
        baseline = self.files()
        for bearer in ['', None, True, 'short', 'é' * 64]:
            with self.assertRaises(BudgetError): router.request(bearer, body)
            self.assertEqual(self.files(), baseline)
        self.assertEqual(router.request('0' * 64, body)['accounting'], 'available')

    def test_authority_growth_rpc_actions_are_rejected_without_ledger_initialization(self):
        baseline = self.files()
        for action in ['create', 'open', 'restore', 'reset', 'extend', 'add_segment', 'effect']:
            with self.subTest(action=action), self.assertRaises(BudgetError): self.request(action)
            self.assertEqual(self.files(), baseline)

    def test_separate_budget_tokens_frozen_scopes_and_application_revocation(self):
        for capability in [self.app_tokens[0], self.authority._control_token, 'not-a-capability']:
            with self.assertRaises(BudgetError): application_budget.BudgetRouter(self.authority, {capability: self.bindings[self.budget_tokens[0]]})
        self.bindings[self.budget_tokens[0]]['scope']['participant']['actor_id'] = 'mutated-caller-copy'
        # Scopes stored by the fixture share references; use the helper's original
        # frozen scope to demonstrate the router does not read mutable bindings.
        original = copy.deepcopy(self.authority._grants[0]['scope'])
        result = self.router.request(self.budget_tokens[0], {'schema': 1, 'scope': original, 'action': 'status', 'payload': {}})
        self.assertEqual(result['accounting'], 'available')
        self.authority.request('/control', self.authority._control_token,
                               {'schema': 1, 'action': 'revoke', 'capability': self.app_tokens[0]})
        baseline = self.files()
        with self.assertRaises(BudgetError): self.router.request(self.budget_tokens[0], {'schema': 1, 'scope': original, 'action': 'status', 'payload': {}})
        self.assertEqual(self.files(), baseline)

    def test_normal_scoped_native_protocol_and_private_one_use_effect_gate(self):
        call = self.call(); reserved = self.request('reserve', {'batch_id': 'valid', 'calls': [call], 'stop_reason': 'toolUse'})
        self.assertTrue(reserved['calls'][0]['admitted'])
        payload = {'batch_id': 'valid', 'native_call_id': call['id'], 'tool_name': call['name'], 'raw_input': call['arguments']}
        consumed = self.request('consume', payload)
        nonce = consumed['execution_nonce']
        entry = {key:value for key,value in payload.items() if key != 'batch_id'}; entry['grant'] = nonce
        self.assertIs(self.request('entry', entry), True)
        self.assertIs(self.router.verify_effect(nonce, self.scopes[0], call['id'], call['name'], call['arguments']), True)
        self.request('complete', {'batch_id': 'valid', 'native_call_id': call['id'], 'tool_name': call['name'], 'is_error': False})
        status = self.request('reconcile', {'batch_id': 'valid'})
        self.assertEqual(status['counts']['charged'], 1); self.assertEqual(status['counts']['helper_verified'], 1)
        self.assertEqual(status['remaining_calls'], 31)
        public = c.canonical(self.request('status'))
        for private in [nonce.encode(), call['id'].encode(), c.digest(call['arguments']).encode(), self.budget_tokens[0].encode()]:
            self.assertNotIn(private, public)
        self.assert_no_canary(); self.assertNotIn(self.budget_tokens[0], repr(self.router))

    def test_unexpected_private_payload_in_protocol_response_is_never_returned(self):
        with mock.patch.object(self.ledgers[0], 'rpc', return_value={'private_payload': KEY_A}):
            with self.assertRaises(BudgetError) as caught: self.request('status')
        self.assertEqual(str(caught.exception), 'accounting_unavailable')
        self.assertEqual(self.ledgers[0].snapshot()['accounting'], 'unavailable')
        self.assert_no_canary()

    def test_nested_private_fields_cannot_masquerade_as_a_public_snapshot(self):
        public = self.ledgers[0].snapshot()
        public['counts']['arguments_sha256'] = c.digest({'private': KEY_A})
        with mock.patch.object(self.ledgers[0], 'rpc', return_value=public):
            with self.assertRaises(BudgetError): self.request('status')
        self.assertEqual(self.ledgers[0].snapshot()['accounting'], 'unavailable')
        self.assert_no_canary([public['counts']['arguments_sha256']])

    def test_constructor_rejects_missing_foreign_or_mutable_scope_bindings_without_writes(self):
        baseline = self.files()
        cases = [{}, {self.budget_tokens[0]: {'scope': {**self.scopes[0], 'stage_id': str(uuid.uuid4())}, 'ledger': self.ledgers[0]}},
                 {self.budget_tokens[0]: {'scope': self.scopes[0], 'ledger': self.ledgers[1]}},
                 {self.budget_tokens[0]: {'scope': self.scopes[0], 'ledger': 'choose-a-file'}}]
        for binding in cases:
            with self.assertRaises(BudgetError): application_budget.BudgetRouter(self.authority, binding)
            self.assertEqual(self.files(), baseline)


if __name__ == '__main__':
    unittest.main()
