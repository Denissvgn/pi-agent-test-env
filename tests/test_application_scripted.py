"""Scripted Chat Completions protocol and actual production helper result tests.

Local HTTP fixtures and in-process API/files/ledger only. No Pi, model, browser,
Docker, saved-endpoint change or native qualification is performed here.
"""
import copy
import hashlib
from http.client import HTTPConnection,RemoteDisconnected
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
spec=importlib.util.spec_from_file_location('application_scripted',ROOT/'tools/qualification/application_scripted.py')
script=importlib.util.module_from_spec(spec);spec.loader.exec_module(script)
import application_api
import application_client_service as service
import application_contracts as c
import application_files
import application_preparation as preparation
from tool_budgets import BudgetLedger
import test_authenticated_application_example as application_fixture

KEY='disposable-scripted-inference-key-138649725'


def config(case='reporting-and-reserve',model='application-script-a',lifetime=30):
    return {'schema':1,'document_type':'application_scripted_bootstrap','case_id':case,'model':model,'inference_key':KEY,'lifetime_seconds':lifetime}
def tool_messages(history,calls,results):
    history.append({'role':'assistant','content':None,'tool_calls':[{'id':call['id'],'type':'function','function':{'name':call['name'],'arguments':c.canonical(call['arguments']).decode()}} for call in calls]})
    history.extend({'role':'tool','tool_call_id':call['id'],'content':json.dumps(result) if type(result) is dict else result} for call,result in zip(calls,results))


class HelperFixture(unittest.TestCase):
    def setUp(self):
        self.fixture=application_fixture.AuthenticatedExampleTests(methodName='runTest');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups);self.fixture.build()
        f=self.fixture;f.client.close()
        source=c.loads((f.root/'compiled/source.json').read_bytes());source['application']['credentials']['bob']='APP_BOB'
        bob=copy.deepcopy(source['application']['operations'][0]);bob.update(id='identity-bob',credential_alias='bob');source['application']['operations'].append(bob)
        source['stages'][0]['operations'].append('identity-bob');source['stages'][0]['credential_aliases'].append('bob')
        source['stages'][0]['limits'].update(timeout_seconds=180,max_turns=8,max_total_tokens=16000,max_tool_calls=16,reporting_reserve_calls=6,reporting_reserve_seconds=30)
        (f.root/'inputs/source.json').write_bytes(c.canonical(source))
        result=preparation.compile_artifact(f.root/'inputs/source.json',f.root/'negative-compiled',f.root/'inputs/runtime.json',endpoint_path=f.root/'inputs/endpoint.json')
        f.plan=result['plan'];f.stage=f.plan['stages'][0];f.scope.update(plan_sha256=f.plan['plan_sha256'],operation_ids=f.stage['operations'],credential_aliases=f.stage['credential_aliases'])
        bootstrap={'schema':1,'document_type':'application_client_private_bootstrap','mode':'authority-only','plan':f.plan,
            'authorities':{f.stage['id']:{'persona':application_fixture.KEY_A,'bob':application_fixture.KEY_B}},
            'capabilities':[{'token':f.token,'scope':f.scope}],'control_token':secrets.token_hex(32),'evidence_root':str(f.evidence),
            'code_identity':{name:hashlib.sha256((ROOT/'skill'/name).read_bytes()).hexdigest() for name in service.TRUSTED_CODE}}
        f.authority=service.CapabilityService(bootstrap)
        binding={key:f.scope[key] for key in service.BINDING_FIELDS-{'segment_id'}};binding['pi_release']='1.2.0'
        self.ledger=BudgetLedger.create(f.root/'ledger.json',binding=binding,limits={'max_tool_calls':16,'reporting_reserve_calls':6,'reporting_reserve_seconds':30},
            native_tools=f.stage['tool_schemas'],initial_segment_id=f.scope['segment_id'],deadline=1300,clock=lambda:1000.0,clock_domain='controlled-script-test',completion=f.stage['completion'])
        def verify(grant,scope,call_id,name,raw):return self.ledger.verify_effect(grant,scope,call_id,name,raw)
        f.client=application_api.APIClient(f.authority,f.evidence,f.outputs,budget_verifier=verify)
        self.files=application_files.ApplicationFiles(f.authority,f.outputs,budget_verifier=verify);self.addCleanup(self.files.close)
        self.ordinal=0;self.snapshots=[]
    def execute(self,calls):
        f=self.fixture;self.ordinal+=1;batch='script-batch-'+str(self.ordinal)
        reserved=self.ledger.reserve_batch(f.scope,batch,calls);results=[]
        for call,row in zip(calls,reserved['calls']):
            if row['admitted']:
                nonce=self.ledger.consume(f.scope,batch,call['id'],call['name'],call['arguments'])['execution_nonce']
                if call['name']=='app_api':payload=f.client.execute(f.token,f.scope,call['id'],call['arguments'],nonce)
                elif call['name']=='budget_status':
                    self.ledger.observe_execution(nonce,f.scope,call['id'],call['name'],call['arguments']);payload=self.ledger.snapshot()
                else:payload=self.files.execute(f.token,f.scope,call['id'],call['name'],call['arguments'],nonce)
                # Exact current native profile result shape (text/details/isError).
                result={'content':[{'type':'text','text':json.dumps(payload)}],'details':payload,'isError':payload.get('ok') is False}
                is_error=payload.get('ok') is False
            else:result={'content':[{'type':'text','text':row['reason']}],'details':{},'isError':True};is_error=True
            results.append(result);self.ledger.complete(f.scope,batch,call['id'],call['name'],is_error)
        self.snapshots.append(self.ledger.reconcile(f.scope,batch));return results
    def machine(self,case,model):return script.ScriptMachine(case,model)
    def run_machine(self,machine):
        history=[{'role':'user','content':'A frozen synthetic case; prompt content never selects authority.'}];calls=[]
        for _ in range(8):
            decision=machine.respond(history,self.fixture.stage['tools']);calls.extend(decision['calls'])
            if decision['finished'] or decision['hold']:return decision,calls,history
            results=self.execute(decision['calls']);tool_messages(history,decision['calls'],results)
        self.fail('Script exceeded frozen eight responses')


class StateMachineTests(HelperFixture):
    def test_omitted_report_uses_actual_cursor_artifact_metadata_and_publication_receipt_then_settles(self):
        machine=self.machine('reporting-and-reserve','application-script-a');decision,calls,_=self.run_machine(machine)
        self.assertTrue(decision['finished']);self.assertEqual(machine.unexpected_results,0)
        self.assertEqual([call['name'] for call in calls],['app_api','app_api','app_api','artifact_write','app_api'])
        self.assertRegex(calls[2]['arguments']['cursor'],'^[a-f0-9]{64}$');self.assertNotEqual(calls[2]['arguments']['cursor'],'fixture-page-2')
        artifact=(self.fixture.outputs/'outputs/summary.md').read_bytes()
        self.assertEqual(calls[-1]['arguments']['body']['artifact_sha256'],hashlib.sha256(artifact).hexdigest())
        self.assertFalse((self.fixture.outputs/'outputs/completion.json').exists());self.assertEqual(len(self.fixture.server.journal['publications']),1)
        self.assertEqual(self.snapshots[-1]['counts']['attempted'],5)

    def test_invalid_typed_request_has_one_charged_denial_and_zero_application_requests(self):
        machine=self.machine('request-and-persona','application-script-a');decision,calls,_=self.run_machine(machine)
        self.assertTrue(decision['finished']);self.assertEqual(machine.unexpected_results,0);self.assertEqual(len(calls),1)
        self.assertEqual(self.fixture.server.journal['requests'],[])
        snapshot=self.snapshots[-1];self.assertEqual((snapshot['counts']['attempted'],snapshot['counts']['charged'],snapshot['counts']['blocked']),(1,1,1))

    def test_wrong_alias_actor_returns_actual_identity_mismatch_before_business(self):
        machine=self.machine('request-and-persona','application-script-b');_,calls,_=self.run_machine(machine)
        self.assertEqual(calls[0]['arguments']['operation_id'],'identity-bob');self.assertEqual(machine.unexpected_results,0)
        requests=self.fixture.server.journal['requests'];self.assertEqual(len(requests),1);self.assertEqual(requests[0]['actor_id'],'actor-bob')
        self.assertEqual(self.fixture.server.journal['pages'],[]);self.assertEqual(self.fixture.server.journal['publications'],[])

    def test_production_ledger_multi_call_batch_matches_frozen_reserve_counts_and_zero_batch_http(self):
        machine=self.machine('reporting-and-reserve','application-script-b');decision,calls,_=self.run_machine(machine)
        self.assertTrue(decision['finished']);self.assertEqual(machine.unexpected_results,0);self.assertEqual(len(calls),13)
        snapshot=self.snapshots[-1]
        for key in ('attempted','charged','blocked','grants_consumed','executed_known','executed_unknown','helper_verified','worker_observed'):
            self.assertEqual(snapshot['counts'][key],script.RESERVE_ORACLE[key],key)
        self.assertEqual(snapshot['phase'],'reporting');self.assertEqual(snapshot['remaining_calls'],6);self.assertEqual(snapshot['reporting_reserve_calls_remaining'],6)
        self.assertEqual(len(self.fixture.server.journal['requests']),1);self.assertEqual(self.fixture.server.journal['pages'],[])
        self.assertEqual(self.ledger.checkpoint(self.fixture.scope),snapshot)

    def test_actual_commit_response_loss_is_not_retried_and_partial_report_uses_only_returned_data(self):
        self.fixture.server.mode='timeout-after-commit'
        machine=self.machine('commit-and-interruption','application-script-a');decision,calls,_=self.run_machine(machine)
        self.assertTrue(decision['finished']);self.assertEqual(machine.unexpected_results,0)
        self.assertEqual([call['name'] for call in calls].count('report_write'),1)
        self.assertEqual(sum(call['name']=='app_api' and call['arguments']['operation_id']=='publish-summary' for call in calls),1)
        report=c.loads((self.fixture.outputs/'outputs/completion.json').read_bytes())
        self.assertEqual(report['publications'],[]);self.assertEqual(report['unresolved'],['publication_outcome_unknown'])
        self.assertEqual(report['artifacts'][0]['sha256'],machine.artifact['sha256']);self.assertEqual(report['pagination']['list-records'],machine.pages)
        self.assertEqual(len(self.fixture.server.journal['publications']),1)

    def test_interruption_sequence_requires_actual_identity_and_budget_result_before_hold(self):
        machine=self.machine('commit-and-interruption','application-script-b');decision,calls,_=self.run_machine(machine)
        self.assertTrue(decision['hold']);self.assertTrue(machine.identity_succeeded);self.assertEqual([call['name'] for call in calls],['app_api','budget_status'])
        self.assertEqual(len(self.fixture.server.journal['requests']),1)

    def test_http_hold_observation_follows_actual_tool_results_and_owned_stop_unblocks_request(self):
        server=script.ScriptedServer(config(case='commit-and-interruption',model='application-script-b'),self.fixture.root/'script-observations.json').start()
        history=[{'role':'user','content':'frozen synthetic scenario'}];held=[];requester=None
        tools=[{'type':'function','function':tool} for tool in self.fixture.stage['tool_schemas']]
        def request():
            conn=HTTPConnection('127.0.0.1',server.server.server_port,timeout=5)
            try:
                conn.request('POST','/v1/chat/completions',body=json.dumps({'model':'application-script-b','messages':history,'tools':tools,'stream':True,'max_tokens':8192}),headers={'Authorization':'Bearer '+KEY,'Content-Type':'application/json'})
                response=conn.getresponse();return response.status,response.read()
            finally:conn.close()
        try:
            for _ in range(2):
                status,raw=request();self.assertEqual(status,200);calls,finish,_=ProtocolTests.decode(self,raw)
                self.assertEqual(finish,'tool_calls');tool_messages(history,calls,self.execute(calls))
            def wait_for_response():
                try:held.append(request())
                except OSError:held.append('disconnected')
                except __import__('http.client',fromlist=['RemoteDisconnected']).RemoteDisconnected:held.append('disconnected')
            requester=threading.Thread(target=wait_for_response);requester.start();deadline=time.monotonic()+2
            while time.monotonic()<deadline:
                observations=json.loads((self.fixture.root/'script-observations.json').read_bytes())
                if observations['held']:break
                time.sleep(.01)
            self.assertEqual(observations['phase'],'holding_after_identity');self.assertTrue(observations['identity_succeeded'])
            self.assertEqual(observations['emitted_tool_calls'],2);self.assertEqual(len(self.fixture.server.journal['requests']),1)
        finally:
            server.stop()
            if requester:requester.join(timeout=2)
        self.assertFalse(requester.is_alive());self.assertEqual(held,['disconnected'])

    def test_missing_changed_unknown_or_replayed_tool_results_never_generate_successor_effects(self):
        for fault in ('missing','unknown','changed'):
            machine=self.machine('reporting-and-reserve','application-script-a');history=[{'role':'user','content':'ignored'}]
            first=machine.respond(history,self.fixture.stage['tools'])
            if fault=='missing':bad=history
            elif fault=='unknown':bad=history+[{'role':'tool','tool_call_id':'foreign','content':'{}'}]
            else:
                # Accept one actual production result, then mutate a prior result
                # while also supplying the successor's actual result.
                tool_messages(history,first['calls'],self.execute(first['calls']));second=machine.respond(history,self.fixture.stage['tools'])
                tool_messages(history,second['calls'],self.execute(second['calls']));bad=copy.deepcopy(history);bad[2]['content']='{"ok":false}'
            with self.subTest(fault=fault),self.assertRaises(script.ScriptError):machine.respond(bad,self.fixture.stage['tools'])


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(dir='/private/tmp');self.addCleanup(temporary.cleanup);self.root=Path(temporary.name).resolve();self.server=None
        self.addCleanup(self.cleanup)
    def cleanup(self):
        if self.server:self.server.stop()
    def start(self,**kwargs):
        self.server=script.ScriptedServer(config(**kwargs),self.root/'observations.json').start();return self.server
    def post(self,body,*,raw=None,key=KEY,headers=None):
        conn=HTTPConnection('127.0.0.1',self.server.server.server_port,timeout=3)
        try:
            payload=json.dumps(body).encode() if raw is None else raw
            conn.request('POST','/v1/chat/completions',body=payload,headers={'Authorization':'Bearer '+key,'Content-Type':'application/json',**(headers or {})})
            response=conn.getresponse();return response.status,response.read()
        finally:conn.close()
    def request(self,**extra):
        value={'model':'application-script-a','messages':[{'role':'user','content':'PRIVATE_PROMPT_CANARY'}],'stream':True,'max_tokens':8192,
            'tools':[{'type':'function','function':{'name':name,'parameters':{'type':'object'}}} for name in ('app_api','artifact_write','report_write','budget_status')]}
        value.update(extra);return value
    def decode(self,raw):
        calls={};finish=None;usage=None
        for frame in raw.split(b'\n\n'):
            if not frame:continue
            self.assertTrue(frame.startswith(b'data: '))
            if frame==b'data: [DONE]':continue
            value=json.loads(frame[6:]);choice=value['choices'][0];delta=choice['delta']
            for part in delta.get('tool_calls',[]):
                row=calls.setdefault(part['index'],{'id':None,'name':None,'arguments':''})
                if 'id' in part:row['id']=part['id']
                if 'name' in part['function']:row['name']=part['function']['name']
                row['arguments']+=part['function']['arguments']
            if choice['finish_reason'] is not None:finish=choice['finish_reason'];usage=value.get('usage')
        return [{'id':row['id'],'name':row['name'],'arguments':json.loads(row['arguments'])} for _,row in sorted(calls.items())],finish,usage

    def test_real_local_chat_sse_models_and_safe_scalar_observations(self):
        self.start(case='request-and-persona');status,raw=self.post(self.request())
        self.assertEqual(status,200);calls,finish,usage=self.decode(raw);self.assertEqual(finish,'tool_calls');self.assertEqual(len(calls),1)
        self.assertEqual(calls[0]['name'],'app_api');self.assertIn('unreviewed_header',calls[0]['arguments']);self.assertLessEqual(usage['completion_tokens'],8192)
        self.assertEqual(usage,{'prompt_tokens':16,'completion_tokens':16,'total_tokens':32})
        self.assertNotEqual(usage['completion_tokens'],len(c.canonical(calls)))
        request=self.request();tool_messages(request['messages'],calls,['Tool execution blocked: request_invalid'])
        status,raw=self.post(request);self.assertEqual(status,200);self.assertEqual(self.decode(raw)[1],'stop');self.assertTrue(raw.endswith(b'data: [DONE]\n\n'))
        conn=HTTPConnection('127.0.0.1',self.server.server.server_port)
        try:
            conn.request('GET','/v1/models',headers={'Authorization':'Bearer '+KEY});response=conn.getresponse();models=json.loads(response.read())
        finally:conn.close()
        self.assertEqual(models['data'][0]['context_window'],262144);self.assertEqual(models['data'][0]['max_tokens'],8192);self.assertFalse(models['data'][0]['reasoning'])
        self.server.stop();data=(self.root/'observations.json').read_bytes()
        for secret in (KEY,'PRIVATE_PROMPT_CANARY','unreviewed_header'):self.assertNotIn(secret.encode(),data);self.assertNotIn(hashlib.sha256(secret.encode()).hexdigest().encode(),data)
        self.assertTrue(json.loads(data)['stopped']);self.assertEqual(json.loads(data)['requests'],3)
        self.assertEqual(json.loads(data)['usage_accounting'],'synthetic_fixed_16_16')

    def test_sdk_store_false_envelope_streams_same_tool_and_usage(self):
        self.start(case='request-and-persona')
        status,raw=self.post(self.request(store=False));self.assertEqual(status,200)
        calls,finish,usage=self.decode(raw)
        self.assertEqual(finish,'tool_calls');self.assertEqual(len(calls),1);self.assertEqual(calls[0]['name'],'app_api')
        self.assertIn('unreviewed_header',calls[0]['arguments'])
        self.assertEqual(usage,script.WIRE_USAGE);self.assertEqual(self.server.data['responses'],1)
        self.assertEqual(self.server.data['rejections_by_stage'],dict.fromkeys(script.REJECTION_STAGES,0))
        self.assertIsNone(self.server.data['last_rejection_stage'])
        self.assertEqual(self.server.machine.results,{})  # No application operation was performed by the server.

    def test_store_nonfalse_values_refuse_before_any_scripted_tool(self):
        self.start(case='request-and-persona')
        variants=(True,0,1,0.0,None,'false',[],{})
        for value in variants:
            with self.subTest(value=value):
                status,raw=self.post(self.request(store=value));self.assertEqual(status,400)
                self.assertEqual(json.loads(raw),{'error':'scripted_request_rejected'})
        self.assertEqual(self.server.machine.sent,{});self.assertEqual(self.server.machine.results,{})
        self.assertEqual(self.server.data['responses'],0);self.assertEqual(self.server.data['emitted_tool_calls'],0)
        self.assertEqual(self.server.data['rejected'],len(variants))
        self.assertEqual(self.server.data['rejections_by_stage']['request_contract'],len(variants))

    def test_closed_rejection_stages_never_retain_canary_values_names_headers_or_errors(self):
        self.start(case='request-and-persona');canary='DO_NOT_RETAIN_EXCEPTION_CANARY_578392'
        headers={'X-PRIVATE_HEADER_CANARY':'DO_NOT_RETAIN_HEADER_VALUE_924687'}
        with mock.patch.object(script,'MAX_BODY',8):self.assertEqual(self.post(self.request(),headers=headers)[0],400)
        self.assertEqual(self.post(self.request(),raw=b'{"PRIVATE_FIELD_CANARY":"PRIVATE_VALUE_CANARY"',headers=headers)[0],400)
        self.assertEqual(self.post(self.request(**{'PRIVATE_UNKNOWN_FIELD_CANARY':'PRIVATE_ARGUMENT_CANARY'}),headers=headers)[0],400)
        with mock.patch.object(self.server.machine,'respond',side_effect=ValueError(canary)):
            self.assertEqual(self.post(self.request(store=False),headers=headers)[0],400)
        with mock.patch.object(script,'sse_frames',side_effect=ValueError(canary)):
            self.assertEqual(self.post(self.request(store=False),headers=headers)[0],400)
        self.server.stop();raw=(self.root/'observations.json').read_bytes();observed=json.loads(raw)
        self.assertEqual(observed['rejections_by_stage'],{'framing':1,'json':1,'request_contract':1,'scenario':1,'response_frames':1,'response_write':0})
        self.assertEqual(observed['last_rejection_stage'],'response_frames');self.assertEqual(observed['responses'],0)
        for value in (KEY,'PRIVATE_PROMPT_CANARY',canary,*headers.keys(),*headers.values(),'PRIVATE_FIELD_CANARY','PRIVATE_VALUE_CANARY','PRIVATE_UNKNOWN_FIELD_CANARY','PRIVATE_ARGUMENT_CANARY','unreviewed_header'):
            self.assertNotIn(value.encode(),raw);self.assertNotIn(hashlib.sha256(value.encode()).hexdigest().encode(),raw)

    def test_response_write_failure_retains_only_closed_stage(self):
        self.start(case='request-and-persona');canary='PRIVATE_SOCKET_EXCEPTION_CANARY'
        with mock.patch('socketserver._SocketWriter.write',side_effect=OSError(canary)):
            with self.assertRaises(RemoteDisconnected):self.post(self.request(store=False))
        self.server.stop();raw=(self.root/'observations.json').read_bytes();observed=json.loads(raw)
        self.assertEqual(observed['rejections_by_stage']['response_write'],1)
        self.assertEqual(observed['last_rejection_stage'],'response_write');self.assertEqual(observed['responses'],0)
        self.assertNotIn(canary.encode(),raw)

    def test_stage_diagnostics_obey_request_limit_and_reject_untrusted_labels(self):
        self.start();request=self.request(model='foreign-model')
        with mock.patch.object(script,'MAX_REQUESTS',3):
            for _ in range(3):self.assertEqual(self.post(request)[0],400)
            self.assertEqual(self.post(request)[0],429)
        self.assertEqual(self.server.data['requests'],3);self.assertEqual(self.server.data['rejected'],3)
        self.assertEqual(sum(self.server.data['rejections_by_stage'].values()),3);self.assertEqual(self.server.machine.sent,{})
        before=copy.deepcopy(self.server.data)
        with self.assertRaises(script.ScriptError):self.server._record_rejection('UNTRUSTED_STAGE_CANARY')
        self.assertEqual(self.server.data,before)

    def test_multi_tool_sse_frame_reassembly_is_exact_and_each_id_is_unique(self):
        machine=script.ScriptMachine('reporting-and-reserve','application-script-b');history=[{'role':'user','content':'ignored'}]
        first=machine.respond(history,script.ALLOWED_TOOLS)
        result={**script.PARTICIPANT,'ok':True,'receipt_id':'receipt-000001'};tool_messages(history,first['calls'],[result]);decision=machine.respond(history,script.ALLOWED_TOOLS)
        frames=script.sse_frames(machine.model,decision);calls,finish,_=self.decode(b''.join(frames))
        self.assertEqual(calls,decision['calls']);self.assertEqual(finish,'tool_calls');self.assertEqual(len({call['id'] for call in calls}),12)
        self.assertLessEqual(max(map(len,frames)),8192);self.assertLessEqual(sum(map(len,frames)),65536)
        oversized={'calls':[{'id':'call-large','name':'artifact_write','arguments':{'artifact_id':'summary','content':'x'*8192}}],'hold':False,'finished':False,'text':''}
        with self.assertRaises(script.ScriptError):script.sse_frames(machine.model,oversized)

    def test_plain_native_validation_failure_settles_invalid_case_without_inventing_sdk_reason(self):
        machine=script.ScriptMachine('request-and-persona','application-script-a');history=[{'role':'user','content':'frozen case'}]
        first=machine.respond(history,script.ALLOWED_TOOLS)
        # Both pinned SDK validators format this prefix/received-arguments block;
        # agent-loop catches Error.message before beforeToolCall and emits text.
        native_error=('Validation failed for tool "app_api":\n  - /unreviewed_header: Unexpected property\n\nReceived arguments:\n'
            +json.dumps(first['calls'][0]['arguments'],indent=2))
        self.assertNotIn('request_invalid',native_error)
        parsed=script.parse_tool_result(native_error);self.assertEqual(parsed,{'ok':False,'reason':'tool_failed'})
        tool_messages(history,first['calls'],[{'content':[{'type':'text','text':native_error}],'details':{},'isError':True}])
        final=machine.respond(history,script.ALLOWED_TOOLS)
        self.assertTrue(final['finished']);self.assertEqual(final['calls'],[]);self.assertEqual(machine.unexpected_results,0)
        self.assertEqual(next(iter(machine.results.values()))['reason'],'tool_failed')
        # Wrong-actor proof must still come from the actual identity adapter.
        wrong=script.ScriptMachine('request-and-persona','application-script-b');history=[{'role':'user','content':'frozen case'}]
        first=wrong.respond(history,script.ALLOWED_TOOLS);tool_messages(history,first['calls'],[native_error])
        self.assertTrue(wrong.respond(history,script.ALLOWED_TOOLS)['finished']);self.assertEqual(wrong.unexpected_results,1)

    def test_auth_model_reasoning_duplicate_json_and_token_bounds_reject_without_script_advancement(self):
        self.start();variants=[(self.request(model='foreign-model'),None,KEY),(self.request(reasoning_effort='high'),None,KEY),
            (self.request(max_tokens=8193),None,KEY),(self.request(),b'{"model":"application-script-a","model":"application-script-a"}',KEY),
            (self.request(),b'{"x":NaN}',KEY),(self.request(),None,'wrong-disposable-key'),
            (self.request(messages=[{'role':'user','content':'x'*(script.CONTEXT_WINDOW-script.MAX_TOKENS)}]),None,KEY)]
        for body,raw,key in variants:
            with self.subTest(body=body.get('model')):self.assertIn(self.post(body,raw=raw,key=key)[0],(400,401))
        self.assertEqual(self.server.machine.sent,{});self.assertEqual(self.server.data['tool_results'],0)

    def test_body_request_count_and_concurrency_caps_are_pre_state_machine(self):
        self.start()
        with mock.patch.object(script,'MAX_BODY',8):self.assertEqual(self.post(self.request())[0],400)
        with mock.patch.object(script,'MAX_REQUESTS',2):
            self.assertEqual(self.post(self.request(stream=False))[0],200)
            self.assertEqual(self.post(self.request())[0],429)
        self.assertEqual(self.server.machine.sent,{})
        connections=[]
        try:
            for _ in range(2):
                conn=socket.create_connection(('127.0.0.1',self.server.server.server_port),timeout=1);conn.sendall(b'GET /v1/models HTTP/1.1\r\nHost: fixture\r\nSlow: ');connections.append(conn)
            deadline=time.monotonic()+1
            while self.server.server.slots._value and time.monotonic()<deadline:time.sleep(.005)
            extra=socket.create_connection(('127.0.0.1',self.server.server.server_port),timeout=1)
            try:self.assertEqual(extra.recv(1),b'')
            finally:extra.close()
        finally:
            for conn in connections:conn.close()

    def test_bootstrap_closed_shape_private_files_and_finite_cli_lifetime(self):
        raw=config(lifetime=1);path=self.root/'private.json';path.write_bytes(c.canonical(raw));path.chmod(0o600)
        self.assertEqual(script.read_bootstrap(path),raw)
        for key,value in [('model','fallback'),('lifetime_seconds',901),('inference_key','short'),('schema',True),('unexpected','hidden')]:
            bad=copy.deepcopy(raw);bad[key]=value
            with self.subTest(key=key),self.assertRaises(script.ScriptError):script.bootstrap(bad)
        path.chmod(0o644)
        with self.assertRaises(script.ScriptError):script.read_bootstrap(path)
        path.chmod(0o600);obs=self.root/'cli-observations.json'
        argv=[sys.executable,str(ROOT/'tools/qualification/application_scripted.py'),'--private-bootstrap',str(path),'--observations',str(obs),'--host','127.0.0.1','--port','0']
        result=subprocess.run(argv,capture_output=True,text=True,timeout=8)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout,'');self.assertEqual(result.stderr,'')
        self.assertTrue(json.loads(obs.read_bytes())['stopped']);self.assertNotIn(KEY,' '.join(argv));self.assertNotIn(KEY,obs.read_text())

    def test_private_stdin_bootstrap_accepts_partial_chunks_but_has_absolute_read_deadline(self):
        raw=c.canonical(config())
        with mock.patch.object(script.select,'select',return_value=([0],[],[])),mock.patch.object(script.os,'read',side_effect=[raw[:5],raw[5:],b'']):
            self.assertEqual(script.read_bootstrap('-'),config())
        with mock.patch.object(script.select,'select',return_value=([],[],[])),mock.patch.object(script.os,'read',side_effect=AssertionError('No unbounded read')):
            with self.assertRaises(script.ScriptError):script.read_bootstrap('-')


if __name__=='__main__':unittest.main()
