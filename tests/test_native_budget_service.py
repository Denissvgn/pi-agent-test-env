"""Budget-only helper mode: real ledgers, fixed scopes, no application effects."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'skill/scripts'), str(ROOT / 'skill/runtime')]
import application_client_service as service
import application_contracts as c
import native_tool_contracts
from native_budget_service import BudgetOnlyService
from tool_budgets import BudgetError


class NativeBudgetServiceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve(); self.root.chmod(0o700)
        for name in ('state', 'evidence'):
            (self.root / name).mkdir(mode=0o700)
        self.clock = [100.0]
        self.scope = {key: str(uuid.uuid4()) for key in
                      ('run_id', 'attempt_id', 'stage_id', 'segment_id', 'session_id')}
        self.scope.update(trial_id=None, plan_sha256='b' * 64, pi_release='1.2.0', stage_name='implementer')
        self.config = {'schema': 1, 'document_type': 'native_budget_private_bootstrap', 'mode': 'budget-only',
            'pi_release': '1.2.0', 'control_token': '1' * 64,
            'code_identity': {p: hashlib.sha256((ROOT / 'skill' / p).read_bytes()).hexdigest()
                              for p in service.TRUSTED_CODE},
            'state_root': str(self.root / 'state'), 'evidence_root': str(self.root / 'evidence'),
            'redaction_values': ['private-credential-fixture-canary'],
            'stage': {'scope': self.scope, 'authority_token': '2' * 64, 'budget_token': '3' * 64,
                'limits': {'max_tool_calls': 6, 'reporting_reserve_calls': 2, 'reporting_reserve_seconds': 10},
                'tools': native_tool_contracts.selected_tools('1.2.0', ['read', 'budget_status']),
                'prepare_arguments': native_tool_contracts.prepare_arguments('1.2.0', ['read', 'budget_status']), 'profile': 'builtin',
                'remaining_seconds': 100}}

    def create(self):
        return BudgetOnlyService(self.config, verify_code=service.verify_code, clock=lambda: self.clock[0])

    def rpc(self, instance, action, payload=None, *, bearer='3' * 64, scope=None):
        return instance.request('/budget', bearer, {'schema': 1, 'scope': scope or self.scope,
                                                   'action': action, 'payload': payload or {}})['result']

    def batch(self, instance, count, *, batch='batch-1', start=0):
        return self.rpc(instance, 'reserve', {'batch_id': batch, 'calls': [
            {'id': 'call-' + str(i), 'name': 'read', 'arguments': {'path': 'x'}}
            for i in range(start, start + count)], 'stop_reason': 'toolUse'})

    def test_budget_only_has_no_application_or_arbitrary_file_route(self):
        instance = self.create()
        original = (self.root / 'state/native-budget.json').read_bytes()
        for path in ('/api', '/browser', '/artifact', '/report', '/proxy', '/ipc/../budget'):
            with self.subTest(path=path), self.assertRaises((BudgetError, c.ContractError)):
                instance.request(path, '3' * 64, {})
        self.assertEqual((self.root / 'state/native-budget.json').read_bytes(), original)

    def test_parent_control_and_stage_budget_capabilities_are_separate(self):
        instance = self.create()
        for bearer in ('2' * 64, '1' * 64, '0' * 64):
            with self.assertRaises(BudgetError): self.rpc(instance, 'status', bearer=bearer)
        with self.assertRaises(BudgetError):
            instance.request('/control', '3' * 64, {'schema': 1, 'action': 'status'})
        self.assertEqual(self.rpc(instance, 'status')['counts']['charged'], 0)
        self.assertFalse(instance.request('/ipc', '2' * 64, {'schema': 1, 'action': 'status',
            'scope': self.scope, 'operation_id': None})['business_effects_enabled'])

    def test_stage_cannot_extend_reset_or_create_ledger(self):
        instance = self.create()
        for action in ('extend', 'reset', 'restore', 'create', 'add_segment', 'effect'):
            with self.subTest(action=action), self.assertRaises(BudgetError):
                self.rpc(instance, action)
        self.assertEqual(self.rpc(instance, 'status')['counts']['charged'], 0)

    def test_reserve_boundary_and_parent_extension_never_reopen_business(self):
        instance = self.create()
        result = self.batch(instance, 5)
        self.assertEqual([row['admitted'] for row in result['calls']], [True] * 4 + [False])
        self.assertEqual(result['snapshot']['phase'], 'reporting')
        instance.request('/control', '1' * 64, {'schema': 1, 'action': 'extend',
            'max_tool_calls': 9, 'remaining_seconds': 110})
        status = self.rpc(instance, 'status')
        self.assertEqual(status['phase'], 'reporting')
        self.assertEqual(status['counts']['charged'], 4)
        self.assertTrue(status['assisted'])
        self.assertEqual(status['limits']['reporting_reserve_calls'], 2)

    def test_explicit_continuation_carries_counts_and_revokes_old_scope(self):
        instance = self.create()
        self.batch(instance, 1)
        self.rpc(instance, 'complete', {'batch_id': 'batch-1', 'native_call_id': 'call-0',
                                       'tool_name': 'read', 'is_error': True})
        self.rpc(instance, 'reconcile', {'batch_id': 'batch-1'})
        segment = str(uuid.uuid4())
        instance.request('/control', '1' * 64, {'schema': 1, 'action': 'continue',
            'segment_id': segment, 'authority_token': '4' * 64, 'budget_token': '5' * 64})
        with self.assertRaises(BudgetError): self.rpc(instance, 'status')
        scope = {**self.scope, 'segment_id': segment}
        status = self.rpc(instance, 'status', bearer='5' * 64, scope=scope)
        self.assertEqual(status['counts']['charged'], 1)
        self.assertEqual(status['phase'], 'business')
        instance.request('/control', '1' * 64, {'schema': 1, 'action': 'revoke', 'capability': '4' * 64})
        with self.assertRaises(BudgetError):
            self.rpc(instance, 'status', bearer='5' * 64, scope=scope)

    def test_max_calls_only_preserves_exact_private_deadline_counts_and_reporting_phase(self):
        instance=self.create();self.batch(instance,1)
        self.clock[0]=193.125
        before=self.rpc(instance,'status')
        deadline=c.loads((self.root/'state/native-budget.json').read_bytes())['deadline']
        self.assertEqual(before['phase'],'reporting')
        self.clock[0]+=.00123
        result=instance.request('/control','1'*64,{'schema':1,'action':'extend',
            'max_tool_calls':9,'remaining_seconds':None})['budget']
        self.assertEqual(c.loads((self.root/'state/native-budget.json').read_bytes())['deadline'],deadline)
        self.assertEqual(result['counts'],before['counts']);self.assertEqual(result['phase'],'reporting')
        self.assertTrue(result['assisted']);self.assertEqual(result['limits']['max_tool_calls'],9)
        # A separate explicitly authorized timeout increase changes the deadline.
        result=instance.request('/control','1'*64,{'schema':1,'action':'extend',
            'max_tool_calls':10,'remaining_seconds':100.5})['budget']
        self.assertEqual(c.loads((self.root/'state/native-budget.json').read_bytes())['deadline'],self.clock[0]+100.5)
        self.assertEqual(result['counts'],before['counts']);self.assertEqual(result['phase'],'reporting')

    def test_null_initial_remaining_is_rejected_before_any_ledger(self):
        self.config['stage']['remaining_seconds']=None
        with self.assertRaises((BudgetError,c.ContractError)):self.create()
        self.assertFalse((self.root/'state/native-budget.json').exists())

    def test_secret_metadata_is_poisoned_before_persistence(self):
        instance = self.create()
        canary = self.config['redaction_values'][0]
        with self.assertRaises(BudgetError):
            self.rpc(instance, 'reserve', {'batch_id': 'batch', 'calls': [
                {'id': canary, 'name': 'read', 'arguments': {'path': 'x'}}], 'stop_reason': 'toolUse'})
        raw = (self.root / 'state/native-budget.json').read_bytes()
        self.assertNotIn(canary.encode(), raw)
        self.assertNotIn(hashlib.sha256(canary.encode()).hexdigest().encode(), raw)
        self.assertEqual(instance.ledger.snapshot()['accounting'], 'unavailable')

    def test_wrong_code_or_scope_or_reserved_capability_rejects_before_ledger(self):
        for kind in ('code', 'scope', 'token', 'profile', 'secret-tool'):
            with self.subTest(kind=kind):
                config = copy.deepcopy(self.config)
                if kind == 'code': config['code_identity']['runtime/prompt_contract.py'] = '0' * 64
                if kind == 'scope': config['stage']['scope']['stage_id'] = 'not-a-uuid'
                if kind == 'token': config['stage']['budget_token'] = config['control_token']
                if kind == 'profile': config['stage']['profile'] = 'application-client'
                if kind == 'secret-tool': config['stage']['tools'][0]['description'] = config['redaction_values'][0]
                with self.assertRaises((BudgetError, c.ContractError, service.ServiceError)):
                    BudgetOnlyService(config, verify_code=service.verify_code, clock=lambda: self.clock[0])
                self.assertFalse((self.root / 'state/native-budget.json').exists())


if __name__ == '__main__': unittest.main()
