"""Actual localhost example + reviewed typed client; synthetic participant reports.

No Pi/model/Docker/browser execution is claimed. The independent oracle reads
actual helper HTTP evidence and a stopped fixture journal under parent seals.
"""
import copy
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[1];HERE=ROOT/'skill/examples/authenticated-application'
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_api
import application_client_service as service
import application_contracts as c
import application_preparation as preparation
import secret_store


def load(name):
    spec=importlib.util.spec_from_file_location('authenticated_example_'+name,HERE/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

fixture_module=load('fixture');oracle=load('oracle');configure=load('configure');scorer=load('content_scorer')
KEY_A='disposable-example-alice-938475620'
KEY_B='disposable-example-bob-85948362710'


class AuthenticatedExampleTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(dir='/private/tmp');self.addCleanup(temporary.cleanup);self.root=Path(temporary.name).resolve()
        self.store=self.root/'store';secret_store.write_secret('APP_ALICE',KEY_A,self.store);secret_store.write_secret('APP_BOB',KEY_B,self.store)
        self.runroot=self.root/'run';self.runroot.mkdir(mode=0o700);self.outputs=self.runroot/'application-evidence/fixture/outputs';self.outputs.mkdir(parents=True,mode=0o700)
        self.evidence=self.runroot/'application-evidence/fixture/raw';self.evidence.mkdir(mode=0o700)
        self.server=None;self.client=None;self.grants={};self.results=[];self.parent=None
        self.addCleanup(self.cleanup)

    def cleanup(self):
        if self.client is not None:self.client.close();self.client=None
        if self.server is not None and not self.server.closed:self.server.stop()

    def build(self,*,persona='alice',mode='normal',readiness_id=None):
        self.server=fixture_module.FixtureServer.from_store(self.root/'journal',alice_reference='APP_ALICE',bob_reference='APP_BOB',secrets_dir=self.store,mode=mode,readiness_id=readiness_id).start()
        inputs=self.root/'inputs';inputs.mkdir();runtime={'id':'sha256:'+'a'*64,'platform':'linux/arm64','capabilities':{'pi':'1.2.0'}}
        (inputs/'runtime.json').write_bytes(c.canonical(runtime))
        source=configure.source_for(inputs/'runtime.json','http://fixture.invalid:'+str(self.server.server.server_port),['127.0.0.1'],'APP_'+persona.upper(),'api')
        if persona=='bob':
            for who in (source['stages'][0]['participant'],source['stages'][0]['completion']['participant']):who['actor_id']='actor-bob'
        for operation in source['application']['operations']:
            if operation['effect']=='publication':operation['max_request_seconds']=1
        (inputs/'source.json').write_bytes(c.canonical(source))
        for asset in ('content_scorer.py','expected.json'):(inputs/asset).write_bytes((HERE/asset).read_bytes())
        endpoint={'base_url':'http://explicit-model.invalid/v1','model':'explicit-fixture-model','api_key_env':'MODEL_REFERENCE','context_window':1000000,'max_tokens':4096}
        (inputs/'endpoint.json').write_bytes(c.canonical(endpoint))
        compiled=preparation.compile_artifact(inputs/'source.json',self.root/'compiled',inputs/'runtime.json',endpoint_path=inputs/'endpoint.json')
        self.plan=compiled['plan'];(self.runroot/'plan.json').write_bytes(c.canonical(self.plan));self.stage=self.plan['stages'][0]
        self.scope={key:str(uuid.uuid4()) for key in service.BINDING_FIELDS-{'plan_sha256','trial_id'}}
        self.scope.update(trial_id=None,plan_sha256=self.plan['plan_sha256'],stage_name=self.stage['id'],participant=self.stage['participant'],
            operation_ids=self.stage['operations'],credential_aliases=self.stage['credential_aliases'],authority_generation=str(uuid.uuid4()))
        self.token=secrets.token_hex(32);key=KEY_A if persona=='alice' else KEY_B
        bootstrap={'schema':1,'document_type':'application_client_private_bootstrap','mode':'authority-only','plan':self.plan,
            'authorities':{self.stage['id']:{'persona':key}},'capabilities':[{'token':self.token,'scope':self.scope}],
            'control_token':secrets.token_hex(32),'evidence_root':str(self.evidence),
            'code_identity':{name:hashlib.sha256((ROOT/'skill'/name).read_bytes()).hexdigest() for name in service.TRUSTED_CODE}}
        self.authority=service.CapabilityService(bootstrap)
        self.client=application_api.APIClient(self.authority,self.evidence,self.outputs,budget_verifier=self.verify_grant)
        return self

    def verify_grant(self,grant,scope,call_id,tool,raw):return self.grants.pop(grant,None)==(scope,call_id,tool,raw)
    def call(self,operation='identity',*,cursor=None,body=None):
        arguments={'operation_id':operation,'path_params':{},'query':{},'body':body,'cursor':cursor}
        call='example-call-'+uuid.uuid4().hex;grant=secrets.token_hex(32)
        self.grants[grant]=(copy.deepcopy(self.scope),call,'app_api',copy.deepcopy(arguments))
        result=self.client.execute(self.token,self.scope,call,arguments,grant);self.results.append((operation,result));return result
    def content(self):return fixture_module.EXPECTED['content']
    def artifact(self):
        path=self.outputs/'outputs';path.mkdir(exist_ok=True);(path/'summary.md').write_text(self.content())
        workspace=self.runroot/'workspace/outputs';workspace.mkdir(parents=True,exist_ok=True);(workspace/'summary.md').write_text(self.content())
    def business(self,*,missing_page=False):
        self.identity=self.call();self.assertTrue(self.identity['ok'],self.identity)
        self.first=self.call('list-records');self.assertTrue(self.first['ok'],self.first)
        self.second=None if missing_page else self.call('list-records',cursor=self.first['pagination']['cursor'])
        if self.second:self.assertTrue(self.second['ok'],self.second)
        self.artifact();self.publication=self.call('publish-summary',body={'target_id':'team-summary','artifact_id':'summary','artifact_sha256':hashlib.sha256(self.content().encode()).hexdigest()})
        return self.publication
    def write_report(self):
        pages=[self.first['receipt_id']]+([self.second['receipt_id']] if self.second else [])
        publications=[{'id':'summary-publication','receipt_id':self.publication['receipt_id']}] if self.publication.get('ok') else []
        self.report={'schema':1,'document_type':'application_completion_report','contract_id':'participant-report','participant':copy.deepcopy(self.stage['participant']),
            'artifacts':[{'id':'summary','path':'outputs/summary.md','sha256':hashlib.sha256(self.content().encode()).hexdigest(),'bytes':len(self.content().encode())}],
            'pagination':{'list-records':pages},'publications':publications,'unresolved':[]}
        (self.outputs/'outputs/completion.json').write_bytes(c.canonical(self.report))
    def retained_run(self,*,missing_receipt=False,dirty=False):
        index=self.client.receipt_index(self.scope)
        document=c.loads((self.evidence/index[self.identity['receipt_id']]['path']).read_bytes());binding=document['binding']
        if missing_receipt:index.pop(self.first['receipt_id'])
        context={'binding':binding,'authorized_segment_ids':[binding['segment_id']],'parent_receipts':index,
            'report_root':str(self.outputs),'evidence_root':str(self.evidence)}
        # Explicit synthetic participant fixture, not a Pi/native invocation.
        self.run={'schema':2,'document_type':'run_result','sealed':True,'status':'PASS','run_id':self.scope['run_id'],'attempt_id':self.scope['attempt_id'],
            'fixture_scope':'controlled in-process API helper; synthetic participant report',
            'agents':[{'name':self.stage['id'],'process':{'cleanup_confirmed':not dirty,
                'application_helper_cleanup':{'schema':1,'status':'removed','workspace':'clean','safe_to_continue':True},
                'application_credentials':{'schema':1,'status':'removed','workspace':'clean'},'application_completion_context':context}}]}
        (self.runroot/'result.json').write_bytes(c.canonical(self.run));self.client.close();self.client=None
        stopped=self.server.stop();self.terminal=stopped
        if not dirty:
            sealed=fixture_module.seal_parent_receipt(self.runroot,self.server.root,stopped['sha256'])
            self.parent=c.loads(Path(sealed['path']).read_bytes());self.parent_digest=sealed['sha256']
        return stopped
    def evaluate(self):return oracle.evaluate(self.runroot,self.server.root,self.parent)
    def inventory(self):return {str(path.relative_to(self.root)):path.read_bytes() for path in self.root.rglob('*') if path.is_file()}

    def test_actual_fixture_client_receipts_positive_and_independent_key_free_read_only_oracle(self):
        self.build();self.assertTrue(self.business()['ok']);self.write_report();self.retained_run()
        before=self.inventory()
        with mock.patch.object(socket,'socket',side_effect=AssertionError('Oracle has no network')),\
             mock.patch.object(subprocess,'Popen',side_effect=AssertionError('Oracle has no children')),\
             mock.patch.object(secret_store,'read_secret',side_effect=AssertionError('Oracle must remain key-free')):
            result=self.evaluate()
        self.assertEqual(result['status'],'PASS',result);self.assertEqual(before,self.inventory())
        self.assertEqual(scorer.score(self.runroot/'workspace')['task_status'],'pass')
        journal=c.loads((self.server.root/'journal.json').read_bytes())
        self.assertEqual(len(journal['requests']),4);self.assertEqual([row['page_index'] for row in journal['pages']],[1,2]);self.assertEqual(len(journal['publications']),1)
        for key in (KEY_A,KEY_B):
            for name,body in self.inventory().items():
                if name.startswith('journal/') or name.startswith('run/'):
                    self.assertNotIn(key.encode(),body,name);self.assertNotIn(hashlib.sha256(key.encode()).hexdigest().encode(),body,name)

    def test_wrong_persona_claimed_pass_fails_external_identity_evaluation(self):
        self.build(persona='bob');self.assertTrue(self.business()['ok']);self.write_report();self.retained_run()
        self.assertEqual(self.run['status'],'PASS');result=self.evaluate()
        self.assertEqual(result['status'],'FAIL');self.assertIn('participant_mismatch',result['diagnostics'])

    def test_nonce_readiness_preserves_full_authenticated_oracle_contract(self):
        nonce=str(uuid.uuid4());self.build(readiness_id=nonce)
        ready=c.loads((self.server.root/'readiness.json').read_bytes())
        self.assertEqual((ready['readiness_id'],ready['fixture_id'],ready['state']),
                         (nonce,self.server.journal['fixture_id'],'ready'))
        self.assertTrue(self.business()['ok']);self.write_report();self.retained_run()
        self.assertEqual(c.loads((self.server.root/'readiness.json').read_bytes())['state'],'stopped')
        before=self.inventory()
        with mock.patch.object(socket,'socket',side_effect=AssertionError('Oracle has no network')),\
             mock.patch.object(subprocess,'Popen',side_effect=AssertionError('Oracle has no children')),\
             mock.patch.object(secret_store,'read_secret',side_effect=AssertionError('Oracle must remain key-free')):
            result=self.evaluate()
        self.assertEqual(result['status'],'PASS',result);self.assertEqual(before,self.inventory())
        journal=c.loads((self.server.root/'journal.json').read_bytes())
        self.assertEqual(len(journal['requests']),4)
        self.assertEqual([row['page_index']for row in journal['pages']],[1,2])
        self.assertEqual(len(journal['publications']),1)

    def test_missing_second_page_fails_even_with_exact_content_and_single_publication(self):
        self.build();self.assertTrue(self.business(missing_page=True)['ok']);self.write_report();self.retained_run()
        self.assertEqual(scorer.score(self.runroot/'workspace')['task_status'],'pass')
        result=self.evaluate();self.assertEqual(result['status'],'FAIL');self.assertIn('pagination_incomplete',result['diagnostics'])

    def test_normally_claimed_pass_missing_report_is_distinct_from_commit_response_loss(self):
        self.build();self.assertTrue(self.business()['ok']);self.retained_run();result=self.evaluate()
        self.assertEqual(result['status'],'FAIL');self.assertIn('report_missing',result['diagnostics']);self.assertNotIn('publication_outcome_unknown',result['diagnostics'])
        self.assertFalse((self.outputs/'outputs/completion.json').exists())

    def test_missing_artifact_or_stale_report_hash_does_not_get_repaired(self):
        self.build();self.assertTrue(self.business()['ok']);self.write_report()
        self.report['artifacts'][0]['sha256']='0'*64;(self.outputs/'outputs/completion.json').write_bytes(c.canonical(self.report))
        (self.outputs/'outputs/summary.md').unlink();self.retained_run();before=self.inventory();result=self.evaluate()
        self.assertIn('artifact_missing',result['diagnostics']);self.assertIn('artifact_hash_mismatch',result['diagnostics']);self.assertEqual(before,self.inventory())

    def test_missing_parent_receipt_and_tampered_raw_evidence_fail_integrity(self):
        self.build();self.assertTrue(self.business()['ok']);self.write_report();self.retained_run(missing_receipt=True)
        result=self.evaluate();self.assertEqual(result['status'],'FAIL');self.assertIn('pagination_incomplete',result['diagnostics']);self.assertIn('receipt_missing',result['diagnostics'])
        first_reference=next(iter(self.run['agents'][0]['process']['application_completion_context']['parent_receipts'].values()))
        receipt=c.loads((self.evidence/first_reference['path']).read_bytes());evidence=self.evidence/receipt['evidence'][0]['path']
        evidence.write_bytes(evidence.read_bytes()+b'corrupted')
        result=self.evaluate();self.assertIn('receipt_integrity_failed',result['diagnostics'])

    def test_timeout_after_commit_is_unknown_once_and_never_retried(self):
        self.build(mode='timeout-after-commit');result=self.business();self.assertFalse(result['ok']);self.assertEqual(result['outcome'],'outcome_unknown')
        repeated=self.call('publish-summary',body={'target_id':'team-summary','artifact_id':'summary','artifact_sha256':hashlib.sha256(self.content().encode()).hexdigest()})
        self.assertFalse(repeated['ok']);self.write_report();self.retained_run();verdict=self.evaluate()
        journal=c.loads((self.server.root/'journal.json').read_bytes());self.assertEqual(len(journal['publications']),1)
        self.assertEqual(len([r for r in journal['requests'] if r['method']=='POST']),1)
        self.assertEqual(verdict['status'],'FAIL');self.assertIn('publication_outcome_unknown',verdict['diagnostics'])

    def test_unknown_writers_stop_oracle_before_any_expected_or_output_opens(self):
        for parent in (None,{}, {'schema':1,'document_type':'authenticated_application_parent_receipt','run':{},'fixture':{}}):
            with self.subTest(parent=parent),mock.patch.object(oracle.os,'open',side_effect=AssertionError('No read before trusted stopped-writer gate')):
                result=oracle.evaluate('/does-not-exist','/does-not-exist',parent)
            self.assertEqual(result['status'],'NOT_EVALUATED');self.assertEqual(result['diagnostics'],['writers_unconfirmed'])

    def test_parent_sealer_rejects_unknown_cleanup_and_stale_terminal_hash(self):
        self.build();self.business();self.write_report();stopped=self.retained_run(dirty=True)
        with self.assertRaises(ValueError):fixture_module.seal_parent_receipt(self.runroot,self.server.root,stopped['sha256'])
        self.run['agents'][0]['process']['cleanup_confirmed']=True;(self.runroot/'result.json').write_bytes(c.canonical(self.run))
        with self.assertRaises(ValueError):fixture_module.seal_parent_receipt(self.runroot,self.server.root,'0'*64)
        self.assertFalse((self.server.root/'parent-receipt.json').exists())

    def test_parent_sealed_result_sha_rejects_later_pass_claim_changes(self):
        self.build();self.business();self.write_report();self.retained_run();self.run['status']='OVERRIDDEN';(self.runroot/'result.json').write_bytes(c.canonical(self.run))
        result=self.evaluate();self.assertEqual(result['status'],'FAIL');self.assertIn('terminal_receipt_invalid',result['diagnostics'])

    def test_browser_html_exposes_only_explicit_typed_actions_without_credentials_or_expected_hash(self):
        body=fixture_module.summary_page().decode();self.assertIn('diagnostic-summary-v1',body)
        for testid in ('load-records','summary-editor','summary-hash','publish-summary'):self.assertIn('data-testid="'+testid+'"',body)
        self.assertNotIn(hashlib.sha256(self.content().encode()).hexdigest(),body);self.assertNotIn(KEY_A,body);self.assertNotIn(KEY_B,body)
        self.assertNotIn('<style',body);self.assertNotIn('style=',body);self.assertNotIn('crypto.',body)
        self.assertEqual(body.count("fetch("),2);self.assertEqual(body.count('onclick='),2)

    def test_anonymous_summary_shell_matches_credential_free_static_resource(self):
        self.build()
        connection=http.client.HTTPConnection('127.0.0.1',self.server.server.server_port,timeout=2)
        try:
            connection.request('GET','/summary')
            response=connection.getresponse();body=response.read()
            self.assertEqual(response.status,200)
            self.assertEqual(response.getheader('Content-Type'),'text/html')
            self.assertEqual(body,fixture_module.summary_page())
            self.assertIsNone(response.getheader('Set-Cookie'))
        finally:connection.close()
        for private in (KEY_A,KEY_B,self.content(),hashlib.sha256(self.content().encode()).hexdigest()):
            self.assertNotIn(private.encode(),body)
        for row in fixture_module.EXPECTED['records']:self.assertNotIn(row['id'].encode(),body)
        self.assertEqual(self.server.journal['pages'],[]);self.assertEqual(self.server.journal['publications'],[])
        self.assertEqual([(row['path'],row['actor_id'],row['status'])for row in self.server.journal['requests']],
                         [('/summary',None,200)])
        self.assertTrue(self.business()['ok']);self.write_report();self.retained_run()
        self.assertEqual(self.evaluate()['status'],'PASS')

    def test_static_shell_does_not_authenticate_identity_records_or_publication(self):
        self.build()
        publication=fixture_module.canonical({'target_id':fixture_module.EXPECTED['target_id'],
            'artifact_id':fixture_module.EXPECTED['artifact_id'],
            'artifact_sha256':hashlib.sha256(self.content().encode()).hexdigest(),'content':self.content()})
        requests=[('GET','/identity',None),('GET','/records',None),
            ('GET','/records?cursor='+fixture_module.PAGE_CURSOR,None),('POST','/publications',publication)]
        for method,path,body in requests:
            with self.subTest(method=method,path=path):
                connection=http.client.HTTPConnection('127.0.0.1',self.server.server.server_port,timeout=2)
                try:
                    connection.request(method,path,body=body,headers={'Content-Type':'application/json'})
                    response=connection.getresponse();raw=response.read()
                    self.assertEqual(response.status,401)
                    self.assertEqual(fixture_module.strict_json(raw),{'error':'request_rejected'})
                finally:connection.close()
        self.assertTrue(all(row['actor_id']is None for row in self.server.journal['requests']))
        self.assertEqual(self.server.journal['pages'],[]);self.assertEqual(self.server.journal['publications'],[])
        # The real typed API still needs and accepts its original actor credential.
        self.assertTrue(self.call()['ok'])

    def test_malformed_summary_requests_cannot_use_anonymous_static_exception(self):
        self.build()
        requests=[('GET','/summary?cursor=unexpected',None),('GET','/summary?',None),
            ('GET','/summary#unexpected',None),('GET','/summary/',None),
            ('GET','//summary',None),('GET','///summary',None),
            ('GET','/summary',b'{}'),('POST','/summary',b'{}')]
        for key in (None,KEY_A):
            for method,path,body in requests:
                with self.subTest(authenticated=key is not None,method=method,path=path):
                    connection=http.client.HTTPConnection('127.0.0.1',self.server.server.server_port,timeout=2)
                    headers={'X-Agent-API-Key':key}if key is not None else{}
                    try:
                        connection.request(method,path,body=body,headers=headers)
                        response=connection.getresponse();raw=response.read()
                        self.assertIn(response.status,(400,401,404))
                        self.assertEqual(fixture_module.strict_json(raw),{'error':'request_rejected'})
                        self.assertNotIn(b'diagnostic-summary-v1',raw)
                    finally:connection.close()
        self.assertEqual(self.server.journal['pages'],[]);self.assertEqual(self.server.journal['publications'],[])

    def test_fixture_concurrency_is_bounded_before_slow_header_body_admission(self):
        self.build();connections=[]
        try:
            for _ in range(8):
                connection=socket.create_connection(('127.0.0.1',self.server.server.server_port),timeout=1)
                connection.sendall(b'GET /identity HTTP/1.1\r\nHost: fixture\r\nX-Slow: ');connections.append(connection)
            deadline=time.monotonic()+1
            while self.server.server.slots._value and time.monotonic()<deadline:time.sleep(0.005)
            self.assertEqual(self.server.server.slots._value,0)
            extra=socket.create_connection(('127.0.0.1',self.server.server.server_port),timeout=1)
            try:self.assertEqual(extra.recv(1),b'')
            finally:extra.close()
            self.assertEqual(self.server.journal['requests'],[])
        finally:
            for connection in connections:connection.close()

    def test_fixture_request_cap_never_grows_journal_after_bound(self):
        self.build()
        with mock.patch.object(fixture_module,'MAX_REQUESTS',2):
            self.assertTrue(self.call()['ok']);self.assertTrue(self.call()['ok'])
            self.assertFalse(self.call('list-records')['ok']);self.assertFalse(self.call('list-records')['ok'])
        self.assertEqual(len(self.server.journal['requests']),2);self.assertEqual(self.server.journal['pages'],[])

    def test_distinct_explicit_reference_bootstrap_rejects_alias_or_shared_value(self):
        with self.assertRaises(ValueError):fixture_module.FixtureServer.from_store(self.root/'unpublished',alice_reference='APP_ALICE',bob_reference='APP_ALICE',secrets_dir=self.store)
        with self.assertRaises(ValueError):fixture_module.FixtureServer(self.root/'unpublished',{'alice':KEY_A,'bob':KEY_A})
        self.assertFalse((self.root/'unpublished').exists())

    def test_contradictory_stopped_journal_never_opens_run_outputs_or_evidence(self):
        self.build();self.business();self.write_report();self.retained_run()
        journal_path=self.server.root/'journal.json';journal=c.loads(journal_path.read_bytes());journal['closed']=False
        journal_path.write_bytes(c.canonical(journal));terminal_path=self.server.root/'terminal-receipt.json'
        terminal=c.loads(terminal_path.read_bytes());terminal['journal'].update(sha256=hashlib.sha256(journal_path.read_bytes()).hexdigest(),bytes=journal_path.stat().st_size)
        terminal_path.write_bytes(c.canonical(terminal));self.parent['fixture']['terminal_sha256']=hashlib.sha256(terminal_path.read_bytes()).hexdigest()
        actual=oracle.read;reads=[]
        def bounded_read(root,relative,*args):
            reads.append((str(root),relative))
            if str(root)==str(self.runroot) and relative!='result.json':raise AssertionError('Unknown fixture writers must stop before plan/output/evidence reads')
            return actual(root,relative,*args)
        with mock.patch.object(oracle,'read',side_effect=bounded_read):result=self.evaluate()
        self.assertEqual(result['status'],'NOT_EVALUATED');self.assertIn('writers_unconfirmed',result['diagnostics'])
        self.assertFalse(any(relative=='plan.json' for _,relative in reads))

    def test_hostile_receipt_index_keys_cannot_enter_public_oracle_assertions(self):
        self.build();self.business();self.write_report()
        index=self.client.receipt_index(self.scope);old=next(iter(index));self.client.receipt_index=mock.Mock(return_value={**index,'PRIVATE-CANARY-KEY':index[old]})
        self.retained_run();result=self.evaluate()
        self.assertEqual(result['status'],'FAIL');self.assertNotIn('PRIVATE-CANARY-KEY',json.dumps(result))

    def test_clean_cancelled_or_not_evaluated_runs_cannot_be_sealed_or_read_for_reports(self):
        self.build();self.business();self.write_report();stopped=self.retained_run(dirty=True)
        self.run['agents'][0]['process']['cleanup_confirmed']=True;base=copy.deepcopy(self.run)
        faults=[lambda r:r['agents'][0]['process'].update(cancelled=True),
            lambda r:r['agents'][0]['process'].update(exit_code=130),
            lambda r:r['agents'][0]['process'].update(termination_reason='cancelled'),
            lambda r:r['agents'][0]['process'].update(termination_reason='application_credential_cleanup'),
            lambda r:r['agents'][0]['process'].update(termination_reason='cleanup_error'),
            lambda r:r['agents'][0]['process'].update(application_completion={'status':'not_evaluated'}),
            lambda r:r.update(termination={'reason':'cancelled'}),
            lambda r:r['agents'][0]['process']['application_helper_cleanup'].update(schema=True),
            lambda r:r['agents'][0]['process']['application_credentials'].update(schema=True)]
        actual=oracle.read
        for number,fault in enumerate(faults):
            run=copy.deepcopy(base);fault(run);body=c.canonical(run);(self.runroot/'result.json').write_bytes(body)
            parent={'schema':1,'document_type':'authenticated_application_parent_receipt',
                'run':{'run_id':run['run_id'],'attempt_id':run['attempt_id'],'result_sha256':hashlib.sha256(body).hexdigest(),'writers_stopped':True,'cleanup_confirmed':True},
                'fixture':{'fixture_id':self.server.journal['fixture_id'],'terminal_sha256':stopped['sha256'],'writers_stopped':True,'cleanup_confirmed':True}}
            def stopped_read(root,relative,*args):
                if str(root)==str(self.runroot) and relative!='result.json':raise AssertionError('Cancelled run must not read plan/report/evidence')
                return actual(root,relative,*args)
            with self.subTest(fault=number):
                with self.assertRaises(ValueError):fixture_module.seal_parent_receipt(self.runroot,self.server.root,stopped['sha256'])
                with mock.patch.object(oracle,'read',side_effect=stopped_read):result=oracle.evaluate(self.runroot,self.server.root,parent)
                self.assertEqual(result['status'],'NOT_EVALUATED');self.assertFalse((self.server.root/'parent-receipt.json').exists())


if __name__=='__main__':unittest.main()
