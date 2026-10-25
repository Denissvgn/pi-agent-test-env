"""A09 parent-ledger and real Node controlled-SDK checks; never live Pi evidence."""
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'skill/scripts'), str(ROOT / 'skill/runtime')]
import application_contracts as c
import prompt_contract
from tool_budgets import BudgetError, BudgetLedger

POSITIVE = json.loads((ROOT / 'tests/fixtures/application-contracts/positive.json').read_text())


def native_tools():
    stage = copy.deepcopy(POSITIVE['source']['stages'][0])
    stage['tools'] = ['app_api', 'artifact_read', 'artifact_write', 'report_write', 'budget_status']
    tools = prompt_contract.tool_schemas(stage)
    for name, properties in [('bash', {'command': {'type': 'string', 'maxLength': 4096}}),
                             ('fixture_lookup', {'amount': {'type': 'integer', 'minimum': 0, 'maximum': 100}})]:
        tools.append({'name': name, 'description': 'Controlled offline native tool.',
                      'parameters': {'type': 'object', 'properties': properties,
                                     'required': list(properties), 'additionalProperties': False}})
    return tools


def call(identifier, name='bash', arguments=None):
    return {'id': identifier, 'name': name,
            'arguments': {'command': 'true'} if arguments is None else arguments}


def binding():
    return {'run_id': str(uuid.uuid4()), 'trial_id': None, 'attempt_id': str(uuid.uuid4()),
            'stage_id': str(uuid.uuid4()), 'session_id': str(uuid.uuid4()),
            'plan_sha256': 'a' * 64, 'pi_release': '1.2.0'}


class LedgerFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pi-tool-budget-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve(); self.root.chmod(0o700)
        self.binding = binding(); self.segment = str(uuid.uuid4())
        self.scope = {**self.binding, 'segment_id': self.segment}
        self.now = 1000.0
        self.path = self.root / 'ledger.json'

    def ledger(self, maximum=6, reserve=2, profile='application-client', **overrides):
        options = {'binding': self.binding,
                   'limits': {'max_tool_calls': maximum, 'reporting_reserve_calls': reserve,
                              'reporting_reserve_seconds': 30},
                   'native_tools': native_tools(), 'initial_segment_id': self.segment,
                   'deadline': 1300.0, 'clock': lambda: self.now, 'clock_domain': 'controlled-test-boot',
                   'profile': profile,
                   'completion': POSITIVE['source']['stages'][0]['completion'] if profile == 'application-client' else None}
        options.update(overrides)
        return BudgetLedger.create(self.path, **options)

    def execute(self, ledger, batch, item, *, observe='helper', is_error=False):
        result = ledger.consume(self.scope, batch, item['id'], item['name'], item['arguments'])
        if observe == 'helper':
            self.assertIs(ledger.verify_effect(result['execution_nonce'], self.scope, item['id'], item['name'], item['arguments']), True)
        elif observe == 'worker':
            self.assertIs(ledger.observe_execution(result['execution_nonce'], self.scope, item['id'], item['name'], item['arguments']), True)
        ledger.complete(self.scope, batch, item['id'], item['name'], is_error)
        return result


class ToolBudgetTests(LedgerFixture):
    def test_ac44_exact_maximum_execution_grants_and_no_n_plus_one_effect(self):
        ledger = self.ledger(maximum=8)
        calls = [call('call_ABC:' + str(n), 'budget_status', {}) for n in range(8)]
        reserved = ledger.reserve_batch(self.scope, 'all', calls)
        self.assertTrue(all(row['admitted'] for row in reserved['calls']))
        for item in calls:
            self.execute(ledger, 'all', item)
        ledger.reconcile(self.scope, 'all')
        denied = ledger.reserve_batch(self.scope, 'next', [call('call_EXTRA', 'budget_status', {})])
        self.assertEqual(denied['calls'][0]['reason'], 'tool_budget_exhausted')
        with self.assertRaises(BudgetError):
            ledger.consume(self.scope, 'next', 'call_EXTRA', 'budget_status', {})
        ledger.complete(self.scope, 'next', 'call_EXTRA', 'budget_status', True)
        counts = ledger.reconcile(self.scope, 'next')['counts']
        self.assertEqual((counts['attempted'], counts['charged'], counts['executed'], counts['blocked']), (9, 8, 8, 1))

    def test_ac45_batch_reserves_all_members_in_order_before_any_execute(self):
        ledger = self.ledger()
        calls = [call('business-' + str(n)) for n in range(5)] + [call('report-1', 'budget_status', {})]
        result = ledger.reserve_batch(self.scope, 'mixed', calls)
        self.assertEqual([row['admitted'] for row in result['calls']], [True, True, True, True, False, True])
        self.assertEqual(result['snapshot']['counts']['charged'], 5)
        self.assertEqual(result['snapshot']['counts']['executed'], 0)
        self.assertEqual(result['snapshot']['phase'], 'reporting')
        for item, row in zip(calls, result['calls']):
            if row['admitted']:
                self.execute(ledger, 'mixed', item)
            else:
                ledger.complete(self.scope, 'mixed', item['id'], item['name'], True)
        self.assertEqual(ledger.reconcile(self.scope, 'mixed')['counts']['executed'], 5)

    def test_ac45_time_threshold_is_monotonic_and_extensions_do_not_reopen(self):
        ledger = self.ledger()
        self.now = 1270
        self.assertEqual(ledger.snapshot()['phase'], 'reporting')
        extended = ledger.extend(max_tool_calls=20, deadline=1500, authorized=True)
        self.assertEqual(extended['phase'], 'reporting')
        self.assertTrue(extended['assisted'])
        denied = ledger.reserve_batch(self.scope, 'late', [call('publish', 'app_api', {
            'operation_id': 'publish-summary', 'path_params': {}, 'query': {}, 'body': {}, 'cursor': None})])
        self.assertEqual(denied['calls'][0]['reason'], 'reporting_only')
        self.assertEqual(denied['snapshot']['counts']['charged'], 0)
        self.now = 1500
        self.assertEqual(ledger.snapshot()['phase'], 'exhausted')
        self.assertEqual(ledger.extend(max_tool_calls=30, deadline=1600, authorized=True)['phase'], 'exhausted')

    def test_ac46_invalid_and_unknown_native_calls_charge_available_business_only(self):
        ledger = self.ledger()
        calls = [call('invalid-1', 'fixture_lookup', {'amount': '7'}),
                 call('unknown-1', 'unregistered', {}),
                 call('invalid-2', 'fixture_lookup', {'amount': True}),
                 call('invalid-3', 'fixture_lookup', {'amount': -1}),
                 call('denied-1', 'unregistered', {}), call('denied-2', 'bash', {'command': 'true'}),
                 call('status-1', 'budget_status', {})]
        result = ledger.reserve_batch(self.scope, 'invalids', calls)
        self.assertEqual([row['reason'] for row in result['calls']],
                         ['request_invalid'] * 4 + ['reporting_only'] * 2 + [None])
        self.assertEqual(result['snapshot']['counts']['charged'], 5)
        self.assertEqual(result['snapshot']['remaining_calls'], 1)
        for item, row in zip(calls, result['calls']):
            if row['admitted']:
                self.execute(ledger, 'invalids', item)
            else:
                ledger.complete(self.scope, 'invalids', item['id'], item['name'], True)
        counts = ledger.reconcile(self.scope, 'invalids')['counts']
        self.assertEqual((counts['attempted'], counts['charged'], counts['blocked']), (7, 5, 6))
        retained = json.loads(self.path.read_text())
        self.assertEqual(sum(entry['charged'] for entry in retained['calls'].values()), 5)

    def test_ac46_repeated_business_denials_cannot_drain_reporting_reserve(self):
        ledger = self.ledger(); self.now = 1275
        calls = [call('denial-' + str(i)) for i in range(50)] + [call('status', 'budget_status', {})]
        result = ledger.reserve_batch(self.scope, 'reserve', calls)
        self.assertEqual(result['snapshot']['counts']['charged'], 1)
        self.assertTrue(result['calls'][-1]['admitted'])
        self.assertEqual(result['snapshot']['remaining_calls'], 5)

    def test_ac46_reconciled_denials_compact_without_forgetting_duplicate_ids(self):
        ledger = self.ledger(); self.now = 1275
        for batch in range(10):
            items = [call('denied-' + str(batch) + '-' + str(index)) for index in range(3)]
            result = ledger.reserve_batch(self.scope, 'batch-' + str(batch), items)
            self.assertTrue(all(row['reason'] == 'reporting_only' for row in result['calls']))
            for item in items:
                ledger.complete(self.scope, 'batch-' + str(batch), item['id'], item['name'], True)
            ledger.reconcile(self.scope, 'batch-' + str(batch))
        retained = json.loads(self.path.read_text())
        self.assertEqual(retained['calls'], {})
        self.assertEqual(len(retained['seen_calls']), 30)
        self.assertEqual(ledger.snapshot()['remaining_calls'], 6)
        self.assertEqual(ledger.snapshot()['counts']['charged'], 0)
        with self.assertRaises(BudgetError):
            ledger.reserve_batch(self.scope, 'duplicate-denial', [call('denied-0-0')])
        self.assertEqual(ledger.snapshot()['accounting'], 'unavailable')

    def test_ac47_all_result_events_reconcile_without_double_charges(self):
        ledger = self.ledger()
        calls = [call('builtin'), call('custom', 'fixture_lookup', {'amount': 5}),
                 call('failure', 'fixture_lookup', {'amount': 6})]
        ledger.reserve_batch(self.scope, 'results', calls)
        self.execute(ledger, 'results', calls[0], observe=None, is_error=True)
        self.execute(ledger, 'results', calls[1], observe='worker')
        self.execute(ledger, 'results', calls[2], is_error=True)
        result = ledger.reconcile(self.scope, 'results')
        self.assertEqual(result['counts']['charged'], 3)
        self.assertEqual(result['counts']['grants_consumed'], 3)
        self.assertEqual(result['counts']['executed_known'], 2)
        self.assertEqual(result['counts']['executed_unknown'], 1)
        self.assertIsNone(result['counts']['executed'])
        self.assertEqual(result['counts']['worker_observed'], 1)
        self.assertEqual(result['counts']['helper_verified'], 1)
        with self.assertRaises(BudgetError):
            ledger.complete(self.scope, 'results', 'custom', 'fixture_lookup', False)
        self.assertEqual(ledger.snapshot()['counts']['charged'], 3)
        self.assertEqual(ledger.snapshot()['accounting'], 'unavailable')

    def test_ac47_inflight_consumed_grants_are_unknown_until_observed(self):
        ledger = self.ledger(); item = call('inflight')
        ledger.reserve_batch(self.scope, 'inflight', [item])
        consumed = ledger.consume(self.scope, 'inflight', item['id'], item['name'], item['arguments'])
        self.assertIsNone(consumed['snapshot']['counts']['executed'])
        self.assertEqual(consumed['snapshot']['counts']['executed_unknown'], 1)
        ledger.observe_execution(consumed['execution_nonce'], self.scope, item['id'], item['name'], item['arguments'])
        self.assertEqual(ledger.snapshot()['counts']['executed'], 1)
        self.assertEqual(ledger.snapshot()['counts']['executed_unknown'], 0)

    def test_ac47_truncated_messages_charge_without_any_tool_hook(self):
        ledger = self.ledger()
        calls = [call('truncated_A'), call('truncated_B')]
        result = ledger.reserve_batch(self.scope, 'truncated', calls, stop_reason='length')
        self.assertTrue(all(row['reason'] == 'request_invalid' for row in result['calls']))
        for item in calls:
            ledger.complete(self.scope, 'truncated', item['id'], item['name'], True)
        snapshot = ledger.reconcile(self.scope, 'truncated')
        self.assertEqual(snapshot['counts']['charged'], 2)
        self.assertEqual(snapshot['counts']['grants_consumed'], 0)
        self.assertEqual(snapshot['counts']['executed'], 0)

    def test_ac48_reporting_allowlist_checks_exact_ids_arguments_and_report_contract(self):
        ledger = self.ledger(maximum=20); self.now = 1275
        valid_report = copy.deepcopy(POSITIVE['report'])
        wrong_report = copy.deepcopy(valid_report); wrong_report['contract_id'] = 'other-contract'
        calls = [call('write', 'write', {'path': 'outputs/summary.md', 'content': 'text'}),
                 call('edit', 'edit', {'path': 'outputs/summary.md'}),
                 call('bash', 'bash', {'command': 'true'}),
                 call('bad-id', 'artifact_write', {'artifact_id': 'undeclared', 'content': 'text'}),
                 call('path', 'artifact_write', {'artifact_id': 'summary', 'content': 'text', 'path': '../x'}),
                 call('oversize', 'artifact_write', {'artifact_id': 'summary', 'content': 'x' * 4097}),
                 call('wrong-report', 'report_write', {'report': wrong_report}),
                 call('read', 'artifact_read', {'artifact_id': 'summary'}),
                 call('artifact', 'artifact_write', {'artifact_id': 'summary', 'content': 'text'}),
                 call('report', 'report_write', {'report': valid_report})]
        result = ledger.reserve_batch(self.scope, 'reports', calls)
        self.assertEqual([row['admitted'] for row in result['calls']], [False] * 7 + [True] * 3)
        self.assertEqual(result['snapshot']['counts']['charged'], 3)

    def test_ac48_budgeted_legacy_reserve_allows_only_status(self):
        for profile in ('builtin', 'fixture-lookup'):
            self.path = self.root / (profile + '.json')
            ledger = self.ledger(profile=profile); self.now = 1275
            calls = [call('artifact', 'artifact_write', {'artifact_id': 'summary', 'content': 'text'}),
                     call('status', 'budget_status', {})]
            result = ledger.reserve_batch(self.scope, profile, calls)
            self.assertEqual([row['admitted'] for row in result['calls']], [False, True])
            self.now = 1000

    def test_ac49_parallel_consumption_and_effect_nonce_are_one_use(self):
        ledger = self.ledger(maximum=20)
        calls = [call('parallel-' + str(n)) for n in range(10)]
        ledger.reserve_batch(self.scope, 'parallel', calls)
        def execute(item):
            result = ledger.consume(self.scope, 'parallel', item['id'], item['name'], item['arguments'])
            ledger.verify_effect(result['execution_nonce'], self.scope, item['id'], item['name'], item['arguments'])
            ledger.complete(self.scope, 'parallel', item['id'], item['name'], False)
        with ThreadPoolExecutor(max_workers=10) as pool:
            list(pool.map(execute, calls))
        self.assertEqual(ledger.reconcile(self.scope, 'parallel')['counts']['executed'], 10)

    def test_ac49_replayed_effect_nonce_cannot_execute_again(self):
        ledger = self.ledger(); item = call('one-use')
        ledger.reserve_batch(self.scope, 'nonce', [item])
        grant = ledger.consume(self.scope, 'nonce', item['id'], item['name'], item['arguments'])['execution_nonce']
        self.assertTrue(ledger.verify_effect(grant, self.scope, item['id'], item['name'], item['arguments']))
        with self.assertRaises(BudgetError):
            ledger.verify_effect(grant, self.scope, item['id'], item['name'], item['arguments'])
        snapshot = ledger.snapshot()
        self.assertEqual(snapshot['counts']['charged'], 1)
        self.assertEqual(snapshot['counts']['helper_verified'], 1)
        self.assertEqual(snapshot['accounting'], 'unavailable')

    def test_ac49_concurrent_batches_cannot_interleave_unreconciled_reservations(self):
        ledger = self.ledger(maximum=20)
        def reserve(index):
            try:
                ledger.reserve_batch(self.scope, 'batch-' + str(index), [call('call-' + str(index))])
                return True
            except BudgetError:
                return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(reserve, range(2)))
        self.assertEqual(outcomes.count(True), 1)
        snapshot = ledger.snapshot()
        self.assertEqual(snapshot['counts']['charged'], 1)
        self.assertEqual(snapshot['counts']['attempted'], 2)
        self.assertEqual(snapshot['counts']['executed'], 0)
        self.assertEqual(snapshot['accounting'], 'unavailable')

    def test_ac49_duplicate_native_ids_missing_results_and_coercion_poison(self):
        scenarios = ('duplicate', 'coercion', 'missing_result', 'missing_identity', 'nested_scope')
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                self.path = self.root / (scenario + '.json'); ledger = self.ledger()
                item = call('Call_ABC:/[]!')
                if scenario == 'duplicate':
                    with self.assertRaises(BudgetError):
                        ledger.reserve_batch(self.scope, 'duplicate', [item, copy.deepcopy(item)])
                elif scenario == 'missing_identity':
                    broken = copy.deepcopy(item); del broken['id']
                    with self.assertRaises(BudgetError): ledger.reserve_batch(self.scope, 'missing', [broken])
                else:
                    ledger.reserve_batch(self.scope, scenario, [item])
                    with self.assertRaises(BudgetError):
                        if scenario == 'coercion': ledger.consume(self.scope, scenario, item['id'], 'bash', {'command': 'changed'})
                        elif scenario == 'missing_result': ledger.reconcile(self.scope, scenario)
                        else: ledger.consume({**self.scope, 'segment_id': str(uuid.uuid4())}, scenario, item['id'], 'bash', item['arguments'])
                self.assertEqual(ledger.snapshot()['accounting'], 'unavailable')

    def test_ac49_missing_corrupt_linked_and_uncertain_ledgers_cannot_reset(self):
        ledger = self.ledger()
        item = call('first'); ledger.reserve_batch(self.scope, 'first', [item])
        with mock.patch.object(ledger, '_persist', side_effect=OSError('controlled fsync failure')):
            with self.assertRaises(BudgetError): ledger.consume(self.scope, 'first', item['id'], 'bash', item['arguments'])
        self.assertTrue(ledger.pending_path.exists())
        with self.assertRaises(BudgetError):
            BudgetLedger.open(self.path, binding=self.binding, clock=lambda: self.now, clock_domain='controlled-test-boot')
        with self.assertRaises(BudgetError): self.ledger()
        for name in ('missing', 'corrupt', 'linked'):
            candidate = self.root / (name + '.json')
            if name == 'corrupt':
                candidate.write_text('{broken'); candidate.chmod(0o600)
                (self.root / (name + '.json.lock')).touch(mode=0o600)
            elif name == 'linked':
                candidate.symlink_to(self.path)
                (self.root / (name + '.json.lock')).touch(mode=0o600)
            with self.assertRaises(BudgetError):
                BudgetLedger.open(candidate, binding=self.binding, clock=lambda: self.now, clock_domain='controlled-test-boot')

    def test_continuation_preserves_totals_opaque_native_ids_and_clock_domain(self):
        ledger = self.ledger(); item = call('Call_ABC:/[]!')
        ledger.reserve_batch(self.scope, 'first', [item]); self.execute(ledger, 'first', item)
        ledger.reconcile(self.scope, 'first')
        restored = BudgetLedger.open(self.path, binding=self.binding, clock=lambda: self.now, clock_domain='controlled-test-boot')
        next_segment = str(uuid.uuid4()); restored.add_segment(next_segment)
        self.scope['segment_id'] = next_segment
        restored.reserve_batch(self.scope, 'first', [item])
        self.execute(restored, 'first', item)
        self.assertEqual(restored.reconcile(self.scope, 'first')['counts']['charged'], 2)
        with self.assertRaises(BudgetError):
            BudgetLedger.open(self.path, binding=self.binding, clock=lambda: self.now, clock_domain='different-boot')
        self.now -= 1
        with self.assertRaises(BudgetError): restored.snapshot()

    def test_persisted_totals_are_read_by_a_fresh_python_process_without_reset(self):
        ledger = self.ledger(clock=time.monotonic, deadline=time.monotonic() + 300)
        item = call('before-process')
        ledger.reserve_batch(self.scope, 'before-process', [item])
        self.execute(ledger, 'before-process', item)
        ledger.reconcile(self.scope, 'before-process')
        program = '''import sys,json
from tool_budgets import BudgetLedger
value=json.load(sys.stdin)
ledger=BudgetLedger.open(value['path'],binding=value['binding'],clock_domain='controlled-test-boot')
print(json.dumps(ledger.snapshot()))
'''
        result = subprocess.run([sys.executable, '-B', '-c', program],
                                input=json.dumps({'path': str(self.path), 'binding': self.binding}),
                                capture_output=True, text=True, timeout=5,
                                env={'PYTHONPATH': str(ROOT / 'skill/scripts'),
                                     'PATH': os.environ.get('PATH', '/usr/bin:/bin')})
        self.assertEqual(result.returncode, 0, result.stderr)
        snapshot = json.loads(result.stdout)
        self.assertEqual(snapshot['counts']['charged'], 1)
        self.assertEqual(snapshot['counts']['helper_verified'], 1)

    def test_untrusted_rpc_cannot_extend_restore_reset_or_add_segments(self):
        ledger = self.ledger()
        for action in ('extend', 'add_segment', 'restore', 'reset', 'create', 'effect'):
            with self.subTest(action=action), self.assertRaises(BudgetError):
                ledger.rpc(self.scope, {'action': action, 'payload': {}})
        with self.assertRaises(BudgetError): ledger.extend(max_tool_calls=20)
        self.assertEqual(ledger.snapshot()['limits']['max_tool_calls'], 6)

    def test_old_segment_cannot_request_more_authority_after_explicit_continuation(self):
        ledger = self.ledger()
        ledger.add_segment(str(uuid.uuid4()))
        with self.assertRaises(BudgetError):
            ledger.reserve_batch(self.scope, 'stale', [call('stale-call')])
        self.assertEqual(ledger.snapshot()['counts']['charged'], 0)
        self.assertEqual(ledger.snapshot()['accounting'], 'unavailable')

    def test_argument_payloads_capabilities_and_digests_never_enter_public_projection(self):
        ledger = self.ledger()
        secret = 'UNEXPECTED_SECRET_ARGUMENT_CANARY'
        item = call('native_PRIVATE', 'bash', {'command': secret})
        ledger.reserve_batch(self.scope, 'private', [item])
        admitted = self.execute(ledger, 'private', item)
        public = json.dumps(ledger.reconcile(self.scope, 'private'))
        for private in (secret, item['id'], admitted['execution_nonce'],
                        hashlib.sha256(c.canonical(item['arguments'])).hexdigest()):
            self.assertNotIn(private, public)
        self.assertNotIn(secret, self.path.read_text())

    def test_effectful_argument_preparation_is_rejected_before_ledger_creation(self):
        preparation = {tool['name']: 'none' for tool in native_tools()}
        preparation['bash'] = 'effectful'
        with self.assertRaises(BudgetError): self.ledger(prepare_arguments=preparation)
        self.assertFalse(self.path.exists())


NODE_SDK = r'''
import {createBudgetGuard} from './skill/runtime/tool-budget.mjs';
import fs from 'node:fs';
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const handlers = new Map(), tools = new Map(); let effects = 0, swallowed = 0, abortRequests=0;
const ctx={abort(){abortRequests++;}}; // Controlled SDK observation, never real Pi abort proof.
let checkpoints=0;
const pi = {on(name, handler) { handlers.set(name, handler); },
 registerTool(tool) { tools.set(tool.name, tool); },
 getActiveTools() { return input.context.allowed_tools; },
 getAllTools() {
  const result=JSON.parse(JSON.stringify(input.native_tools));
  if(input.scenario==='schema_change')result[0].parameters.additionalProperties=true;
  if(input.scenario==='typebox_metadata')Object.defineProperty(result[0].parameters,'~kind',{value:'Object',enumerable:false});
  return result;
 }};
async function request(action, payload) {
 if (input.scenario === 'unavailable' && action === 'reserve') throw new Error('private IPC failure');
 if(input.scenario==='context_failure' && action==='checkpoint' && ++checkpoints===2) throw new Error('private context failure');
 const response = await fetch(input.url, {method:'POST', headers:{'Authorization':'Bearer '+input.token,
   'Content-Type':'application/json'}, body:JSON.stringify({action,payload})});
 const value=await response.json(); if(!value.ok) throw new Error(value.reason); return value.result;
}
const guard=createBudgetGuard(pi,input.context,{request});
try {await handlers.get('before_agent_start')({},ctx);} catch(e) {
 if(input.scenario!=='schema_change')throw e;
 console.log(JSON.stringify({effects,swallowed,abortRequests,scope:'controlled-SDK-not-Pi',snapshot:guard.snapshot()}));process.exit(0);
}
try {await handlers.get('context')({},ctx);}catch(_){swallowed++;}
const calls=input.calls;
if(input.scenario==='nonfinite') calls[0].arguments.amount=Infinity;
if(input.scenario==='undefined') calls[0].arguments.amount=undefined;
if(input.scenario==='sparse') calls[0].arguments.amount=Array(2);
try { await handlers.get('message_end')({message:{role:'assistant',stopReason:'toolUse',content:calls.map(c=>({type:'toolCall',...c}))}},ctx); }
catch (_) { swallowed++; } // Exact reviewed Pi behavior: message_end handler errors are caught.
for(const call of calls) {
 let isError=false;
 if(input.scenario!=='missing_start') {
   try {await handlers.get('tool_execution_start')({toolCallId:call.id,toolName:call.name,args:call.arguments},ctx);}
   catch(_){swallowed++;}
 }
 const schemaInvalid=call.name==='fixture_lookup' && typeof call.arguments.amount!=='number';
 if(call.name==='unknown' || schemaInvalid) isError=true; // Native validation precedes tool_call.
 else {
   let raw=input.scenario==='coercion'?{amount:7}:call.arguments;
   if(input.scenario==='prototype_loss') {raw=JSON.parse(JSON.stringify(raw));delete raw.body.__proto__;}
   const event={toolCallId:call.id,toolName:call.name,input:raw};
   if(input.scenario==='nested') event.parentToolCallId='parent';
   const blocked=await handlers.get('tool_call')(event,ctx);
   if(blocked?.block) isError=true;
   else if(call.name==='budget_status') { await tools.get('budget_status').execute(call.id,raw); }
   else {
     const grant=guard.executionGrant(call.id,call.name,raw);
     await request('trusted_fixture_effect',{grant,native_call_id:call.id,tool_name:call.name,raw_input:raw}); effects++;
   }
 }
 try { await handlers.get('tool_execution_end')({toolCallId:call.id,toolName:call.name,isError},ctx); }
 catch (_) { swallowed++; }
}
try { await handlers.get('turn_end')({},ctx); } catch (_) { swallowed++; }
try { await handlers.get('agent_end')({},ctx); } catch (_) { swallowed++; }
console.log(JSON.stringify({effects,swallowed,abortRequests,scope:'controlled-SDK-not-Pi',snapshot:guard.snapshot()}));
'''


@unittest.skipUnless(shutil.which('node'), 'Node is required for actual controlled-SDK hook checks')
class NodeBudgetHookTests(LedgerFixture):
    def sdk(self, scenario, calls, maximum=6):
        ledger = self.ledger(maximum=maximum)
        capability = secrets.token_hex(32)
        scope = copy.deepcopy(self.scope)
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_POST(self):
                try:
                    if self.headers.get('Authorization') != 'Bearer ' + capability:
                        raise BudgetError()
                    body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                    if body['action'] == 'trusted_fixture_effect':
                        value = ledger.verify_effect(scope=scope, **body['payload'])
                    else:
                        value = ledger.rpc(scope, body)
                    result = {'ok': True, 'result': value}
                except (BudgetError, c.ContractError) as exc:
                    result = {'ok': False, 'reason': exc.reason}
                raw = json.dumps(result).encode()
                self.send_response(200); self.send_header('Content-Length', str(len(raw)))
                self.end_headers(); self.wfile.write(raw)
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            context = {'schema': 1, 'pi_release': '1.2.0', 'scope': scope,
                       'allowed_tools': [tool['name'] for tool in native_tools()],
                       'prepare_arguments': {tool['name']: 'none' for tool in native_tools()},
                       'extension_order_sha256': 'd' * 64,
                       'tool_schema_sha256': c.digest(sorted(native_tools(), key=lambda tool: tool['name'])),
                       'base_url': 'http://pi-application:8081/budget', 'capability': capability}
            payload = {'scenario': scenario, 'calls': calls, 'context': context,
                       'native_tools': native_tools(),
                       'url': 'http://127.0.0.1:' + str(server.server_port), 'token': capability}
            result = subprocess.run(['node', '--input-type=module', '-e', NODE_SDK], cwd=ROOT,
                                    input=json.dumps(payload), text=True, capture_output=True, timeout=15,
                                    env={'PATH': os.environ.get('PATH', '/usr/bin:/bin')})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn(capability, result.stdout + result.stderr)
            return json.loads(result.stdout), ledger
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)

    def test_changed_registered_schema_aborts_before_reserving_or_effects(self):
        result, ledger = self.sdk('schema_change', [call('valid')])
        self.assertEqual(result['effects'], 0)
        self.assertEqual(result['abortRequests'], 1)
        self.assertEqual(ledger.snapshot()['counts']['charged'], 0)
        self.assertEqual(ledger.snapshot()['accounting'], 'unavailable')

    def test_typebox_non_wire_metadata_does_not_change_native_schema_identity(self):
        result, ledger = self.sdk('typebox_metadata', [call('valid')])
        self.assertEqual(result['effects'], 1)
        self.assertEqual(result['abortRequests'], 0)
        self.assertEqual(ledger.snapshot()['counts']['charged'], 1)

    def test_ac44_ac47_real_node_hooks_reserve_invalid_unknown_and_multiple_calls(self):
        result, ledger = self.sdk('normal', [call('valid'), call('bad', 'fixture_lookup', {'amount': '7'}),
                                            call('missing', 'unknown', {}), call('status', 'budget_status', {})])
        self.assertEqual(result['scope'], 'controlled-SDK-not-Pi')
        self.assertEqual(result['effects'], 1)
        self.assertEqual(result['swallowed'], 0)
        self.assertEqual(result['abortRequests'], 0)
        snapshot = ledger.snapshot()
        self.assertEqual(snapshot['counts']['attempted'], 4)
        self.assertEqual(snapshot['counts']['charged'], 4)
        self.assertEqual(snapshot['counts']['executed_known'], 2)
        self.assertEqual(snapshot['counts']['helper_verified'], 1)
        self.assertEqual(snapshot['counts']['worker_observed'], 1)

    def test_ac44_real_node_seventh_call_is_denied_before_execute(self):
        result, ledger = self.sdk('normal', [call('status-' + str(i), 'budget_status', {}) for i in range(7)])
        self.assertEqual(result['effects'], 0)
        self.assertEqual(result['abortRequests'], 0)
        snapshot = ledger.snapshot()
        self.assertEqual((snapshot['counts']['attempted'], snapshot['counts']['charged'],
                          snapshot['counts']['grants_consumed'], snapshot['counts']['blocked']), (7, 6, 6, 1))
        self.assertEqual(snapshot['counts']['worker_observed'], 6)
        self.assertEqual(snapshot['phase'], 'exhausted')

    def test_ac45_ac46_real_node_denied_business_calls_preserve_report_slots(self):
        result, ledger = self.sdk('normal', [call('b' + str(i)) for i in range(6)] +
                                  [call('report1', 'budget_status', {}), call('report2', 'budget_status', {})])
        self.assertEqual(result['effects'], 4)
        counts = ledger.snapshot()['counts']
        self.assertEqual((counts['charged'], counts['blocked'], counts['executed_known']), (6, 2, 6))

    def test_ac48_real_node_reserve_rejects_wrong_artifact_id_before_effect(self):
        calls = [call('business-' + str(i)) for i in range(4)]
        calls += [call('wrong-artifact', 'artifact_write', {'artifact_id': 'other', 'content': 'text'}),
                  call('declared-artifact', 'artifact_write', {'artifact_id': 'summary', 'content': 'text'})]
        result, ledger = self.sdk('normal', calls)
        self.assertEqual(result['effects'], 5)
        self.assertEqual(result['abortRequests'], 0)
        self.assertEqual(ledger.snapshot()['counts']['charged'], 5)
        self.assertEqual(ledger.snapshot()['counts']['blocked'], 1)

    def test_ac49_real_node_coercion_nested_calls_and_swallowed_guard_errors_block(self):
        for scenario in ('coercion', 'nested', 'unavailable', 'missing_start', 'context_failure'):
            with self.subTest(scenario=scenario):
                self.path = self.root / (scenario + '.json')
                item = call('guarded', 'fixture_lookup', {'amount': 5})
                result, ledger = self.sdk(scenario, [item])
                self.assertEqual(result['effects'], 0)
                self.assertGreater(result['swallowed'], 0)
                self.assertEqual(result['abortRequests'], 1)
                self.assertEqual(ledger.snapshot()['accounting'], 'unavailable')

    def test_ac49_nonfinite_undefined_and_sparse_native_arguments_poison_before_effect(self):
        for scenario in ('nonfinite', 'undefined', 'sparse'):
            with self.subTest(scenario=scenario):
                self.path = self.root / (scenario + '.json')
                result, ledger = self.sdk(scenario, [call('unsafe', 'fixture_lookup', {'amount': 5})])
                self.assertEqual(result['effects'], 0)
                self.assertGreater(result['swallowed'], 0)
                self.assertEqual(result['abortRequests'], 1)
                self.assertEqual(ledger.snapshot()['accounting'], 'unavailable')

    def test_ac49_own_prototype_keys_and_nonbmp_order_are_preserved_and_matched(self):
        args = {'operation_id': 'identity', 'path_params': {}, 'query': {}, 'cursor': None,
                'body': {'__proto__': {'sentinel': True}, 'constructor': {'sentinel': True},
                         '\U00010000': 'non-BMP', '\ue000': 'BMP'}}
        result, ledger = self.sdk('normal', [call('prototype', 'app_api', args)])
        self.assertEqual(result['effects'], 1)
        self.assertEqual(ledger.snapshot()['accounting'], 'available')
        self.path = self.root / 'prototype-loss.json'
        result, ledger = self.sdk('prototype_loss', [call('prototype', 'app_api', args)])
        self.assertEqual(result['effects'], 0)
        self.assertEqual(ledger.snapshot()['accounting'], 'unavailable')


if __name__ == '__main__':
    unittest.main()
