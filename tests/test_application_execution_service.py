"""Actual localhost tool routing through capability, ledger and typed transports."""
import copy
import http.client
import json
from pathlib import Path
import sys
import threading
import unittest
import uuid
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_contracts as c
import application_client_service as base
from application_execution_service import ApplicationService
import test_application_client_api as fixtures


class ExecutionServiceTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.APITests(methodName='runTest');self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        f=self.fixture
        f.client.close();f.client=None
        root=f.root/'execution';root.mkdir(mode=0o700)
        for name in ('state','evidence'):(root/name).mkdir(mode=0o700)
        authority=copy.deepcopy(f.configuration);authority['evidence_root']=str(root/'evidence')
        self.configuration={'schema':1,'document_type':'application_execution_private_bootstrap',
            'mode':'application-execution','authority':authority,'state_root':str(root/'state'),
            'outputs_root':str(root/'evidence/outputs'),
            'budget_grants':[{'scope':f.scope,'token':'b'*64}], 'browser_admission':None,'sealed_inputs':[],
            'redaction_values':['other-trial-private-value-123456',f.bearer,'b'*64,authority['control_token']]}
        self.service=ApplicationService(self.configuration,clock=lambda:f.time)
        self.addCleanup(self.service.close)
        self.server=base.Server(('127.0.0.1',0),self.service)
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':0.01},daemon=True);self.thread.start()
        self.addCleanup(self.stop)
        self.ordinal=0

    def stop(self):
        self.server.shutdown();self.server.server_close();self.thread.join(2)

    def request(self,path,body,bearer=None):
        connection=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=5)
        try:
            connection.request('POST',path,c.canonical(body),{'Content-Type':'application/json',
                'Authorization':'Bearer '+(bearer or self.fixture.bearer)})
            response=connection.getresponse();return response.status,json.loads(response.read())
        finally:connection.close()

    def parent(self,action,**extra):
        return self.request('/control',{'schema':1,'action':action,**extra},self.fixture.configuration['control_token'])

    def rpc(self,action,payload=None,scope=None,bearer='b'*64):
        return self.request('/budget',{'schema':1,'scope':scope or self.fixture.scope,'action':action,
                                      'payload':payload or {}},bearer)

    def activate(self):
        status,result=self.parent('activate',capability=self.fixture.bearer,remaining_seconds=300)
        self.assertEqual(status,200,result)

    def tool(self,name,args,*,complete=True):
        self.ordinal+=1;native='actual-call-'+str(self.ordinal);batch='actual-batch-'+str(self.ordinal)
        status,result=self.rpc('reserve',{'batch_id':batch,'calls':[{'id':native,'name':name,'arguments':args}], 'stop_reason':'toolUse'})
        self.assertEqual(status,200,result)
        if not result['result']['calls'][0]['admitted']:
            row=result['result']['calls'][0]
            self.assertEqual(self.rpc('complete',{'batch_id':batch,'native_call_id':native,'tool_name':name,'is_error':True})[0],200)
            self.assertEqual(self.rpc('reconcile',{'batch_id':batch})[0],200)
            return False,row
        status,result=self.rpc('consume',{'batch_id':batch,'native_call_id':native,'tool_name':name,'raw_input':args})
        self.assertEqual(status,200,result);nonce=result['result']['execution_nonce']
        status,result=self.request('/tool',{'schema':1,'scope':self.fixture.scope,'native_call_id':native,
                                           'tool_name':name,'input':args,'budget_grant':nonce})
        if complete:
            self.assertEqual(self.rpc('complete',{'batch_id':batch,'native_call_id':native,'tool_name':name,'is_error':status!=200 or result.get('result',{}).get('ok') is False})[0],200)
            self.assertEqual(self.rpc('reconcile',{'batch_id':batch})[0],200)
        return status,result

    def identity(self):
        return {'operation_id':'identity','path_params':{},'query':{},'body':None,'cursor':None}

    def test_parent_activation_precedes_every_application_effect_and_budget_is_separate(self):
        f=self.fixture
        body={'schema':1,'scope':f.scope,'native_call_id':'before','tool_name':'app_api','input':self.identity(),'budget_grant':'c'*64}
        self.assertEqual(self.request('/tool',body)[0],403);self.assertEqual(f.requests,[])
        self.assertEqual(self.parent('activate',capability=f.bearer,remaining_seconds=300)[0],200)
        self.assertEqual(self.request('/control',{'schema':1,'action':'status'},'b'*64)[0],403)
        self.assertEqual(self.rpc('status',bearer=f.bearer)[0],403)
        status,result=self.tool('app_api',self.identity());self.assertEqual(status,200,result)
        self.assertTrue(result['result']['ok']);self.assertEqual(len(f.requests),1)
        snapshot=self.parent('status')[1]['budget'];self.assertEqual(snapshot['counts']['charged'],1)
        self.assertEqual(snapshot['counts']['helper_verified'],1)

    def test_exact_scope_and_one_use_effect_proof_reject_before_http(self):
        self.activate();f=self.fixture
        altered={**f.scope,'segment_id':str(uuid.uuid4())}
        self.assertEqual(self.rpc('status',scope=altered)[0],403)
        body={'schema':1,'scope':f.scope,'native_call_id':'forged','tool_name':'app_api','input':self.identity(),'budget_grant':'d'*64}
        status,result=self.request('/tool',body)
        self.assertEqual(status,200);self.assertFalse(result['result']['ok']);self.assertEqual(f.requests,[])
        self.assertEqual(self.request('/proxy',{})[0],403)

    def test_file_tools_use_parent_artifact_grants_and_finish_does_not_repair_report(self):
        self.activate();f=self.fixture
        status,result=self.tool('artifact_write',{'artifact_id':'summary','content':'All three records.'})
        self.assertEqual(status,200,result)
        status,result=self.tool('artifact_read',{'artifact_id':'summary'});self.assertEqual(status,200,result)
        self.assertIn('All three records.',json.dumps(result))
        self.assertEqual(self.parent('finish',writers_confirmed=False)[0],403)
        status,result=self.parent('finish',writers_confirmed=True);self.assertEqual(status,200,result)
        output=Path(self.configuration['outputs_root']);self.assertFalse((output/'outputs/completion.json').exists())
        self.assertEqual(self.rpc('status')[0],403)
        self.assertEqual(self.parent('activate',capability=f.bearer,remaining_seconds=300)[0],403)
        self.assertEqual(f.requests,[])

    def test_continuation_carries_count_and_invalidates_old_caps_without_new_application_request(self):
        self.activate();f=self.fixture
        self.tool('app_api',self.identity())
        scope={**f.scope,'segment_id':str(uuid.uuid4())}
        status,result=self.parent('continue',scope=scope,capability='c'*64,budget_token='d'*64)
        self.assertEqual(status,200,result);self.assertEqual(result['budget']['counts']['charged'],1)
        self.assertEqual(self.rpc('status')[0],403)
        self.assertEqual(self.rpc('status',scope=scope,bearer='d'*64)[0],200)
        self.assertEqual(len(f.requests),1)
        self.assertEqual(self.parent('continue',scope=scope,capability='e'*64,budget_token='f'*64)[0],403)

    def test_reporting_phase_denies_application_and_preserves_report_slots(self):
        self.activate();ledger=self.service._ledgers[self.fixture.scope['stage_id']]
        self.fixture.time+=271
        before=self.parent('status')[1]['budget'];self.assertEqual(before['phase'],'reporting')
        admitted,result=self.tool('app_api',self.identity());self.assertFalse(admitted)
        after=self.parent('status')[1]['budget'];self.assertEqual(after['counts']['charged'],0)
        self.assertEqual(after['reporting_reserve_calls_remaining'],before['reporting_reserve_calls_remaining'])
        self.assertEqual(self.fixture.requests,[])
        status,result=self.tool('artifact_write',{'artifact_id':'summary','content':'Final summary.'})
        self.assertEqual(status,200,result);self.assertEqual(self.parent('status')[1]['budget']['counts']['charged'],1)

    def test_failed_seal_revokes_old_effects_and_quarantines_successor_activation(self):
        self.activate();f=self.fixture
        output=Path(self.configuration['outputs_root'])/'outputs';output.mkdir(mode=0o700)
        (output/'summary.md').symlink_to(f.artifacts/'outputs/summary.md')
        self.assertEqual(self.parent('finish',writers_confirmed=True)[0],403)
        self.assertTrue(self.service._quarantined)
        self.assertEqual(self.rpc('status')[0],403)
        self.assertEqual(self.parent('activate',capability=f.bearer,remaining_seconds=300)[0],403)
        self.assertEqual(f.requests,[])

    def test_failed_continuation_close_revokes_old_capability_before_error(self):
        self.activate();scope={**self.fixture.scope,'segment_id':str(uuid.uuid4())}
        with mock.patch.object(self.service,'_close_stage_adapters',side_effect=OSError('controlled close failure')):
            self.assertEqual(self.parent('continue',scope=scope,capability='c'*64,budget_token='d'*64)[0],403)
        self.assertTrue(self.service._quarantined);self.assertEqual(self.rpc('status')[0],403)
        self.assertEqual(self.rpc('status',scope=scope,bearer='d'*64)[0],403)
        self.assertEqual(self.fixture.requests,[])

    def test_context_capability_input_cannot_enter_native_ledger_or_artifact(self):
        self.activate();secret=self.fixture.bearer
        status,result=self.rpc('reserve',{'batch_id':'secret-batch','calls':[{'id':'secret-call',
            'name':'artifact_write','arguments':{'artifact_id':'summary','content':secret}}], 'stop_reason':'toolUse'})
        self.assertEqual(status,403)
        self.assertEqual(self.parent('status')[1]['budget']['accounting'],'unavailable')
        for file in Path(self.configuration['state_root']).rglob('*.json'):
            self.assertNotIn(secret.encode(),file.read_bytes())
        self.assertEqual(self.fixture.requests,[])

    def test_call_only_extension_preserves_exact_helper_deadline(self):
        self.activate();f=self.fixture
        path=Path(self.configuration['state_root'])/(f.scope['stage_id']+'.json')
        before=json.loads(path.read_text());f.time+=0.02
        status,result=self.parent('extend',max_tool_calls=40,remaining_seconds=None)
        self.assertEqual(status,200,result);after=json.loads(path.read_text())
        self.assertEqual(after['deadline'],before['deadline'])
        self.assertEqual(after['counts'],before['counts'])
        self.assertEqual(result['budget']['limits']['max_tool_calls'],40)

    def test_parent_global_redaction_values_reject_before_persisting_or_effects(self):
        self.activate()
        status,result=self.rpc('reserve',{'batch_id':'foreign-value','calls':[{'id':'call-value',
            'name':'artifact_write','arguments':{'artifact_id':'summary','content':'other-trial-private-value-123456'}}],
            'stop_reason':'toolUse'})
        self.assertEqual(status,403)
        for path in Path(self.configuration['state_root']).rglob('*.json'):
            self.assertNotIn(b'other-trial-private-value-123456',path.read_bytes())
        self.assertEqual(self.fixture.requests,[])


if __name__=='__main__':unittest.main()
