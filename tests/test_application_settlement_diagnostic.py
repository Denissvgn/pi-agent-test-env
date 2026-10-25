"""Controlled diagnostic preparation and scripted protocol, no native execution."""
import ast
import copy
import hashlib
import html
import json
import shutil
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools/qualification'),str(ROOT/'tests')]
import application_settlement_diagnostic as diagnostic
import test_application_qualification as qualification


def endpoint():
    return {'base_url':'http://172.17.0.1:19081/v1','model':diagnostic.MODEL,'api_key_env':diagnostic.SCRIPT_KEY_REFERENCE,
      'context_window':262144,'max_tokens':8192,'input':['text'],'reasoning':{'enabled':False}}


def route():return {'origin':'http://172.17.0.1:19080','allowed_addresses':['172.17.0.1']}


def results(call,machine):
    name=call['name'];args=call['arguments']
    if name=='app_api':return {'ok':True,**diagnostic.PARTICIPANT,'receipt_id':'identity-receipt'}
    if name=='app_browser':
        if args['action']=='click':return {'ok':True,'operation_receipt_ids':['first-page-receipt']}
        if args['action']=='snapshot':
            page={'items':[{'id':'r1','text':'One & two'},{'id':'r2','text':'Actual returned text'}],
              'next_cursor':'a'*64,'snapshot_id':'controlled-snapshot'}
            dom={'url':route()['origin']+'/summary','page_identity':['diagnostic-summary-v1'],
              'html':'<pre data-testid="records">'+html.escape(json.dumps(page))+'</pre>',
              'form_state':[],'text_content':'NOT A SOURCE FOR THE SUMMARY','inner_text':'NOT A SOURCE FOR THE SUMMARY'}
            return {'ok':True,'dom':json.dumps(dom)}
        return {'ok':True}
    if name=='artifact_write':
        body=args['content'].encode();return {'ok':True,'artifact_id':'summary','bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
    return {'ok':True,'contract_id':'participant-report','bytes':128,'sha256':'b'*64}


def add(messages,call,result):
    messages.append({'role':'assistant','content':None,'tool_calls':[{'id':call['id'],'type':'function',
      'function':{'name':call['name'],'arguments':json.dumps(call['arguments'])}}]})
    messages.append({'role':'tool','tool_call_id':call['id'],'content':json.dumps(result)})


class SettlementDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='inert-settlement-preparation-');self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve()

    def test_seven_role_upper_bound_not_eight_and_preserved_poison_is_prerequisite(self):
        value=diagnostic.contract(endpoint(),route())
        self.assertEqual(sum(value['roles_upper_bounds'].values()),7);self.assertNotIn('scripted-inference',value['roles_upper_bounds'])
        self.assertEqual(value['inference']['kind'],'SCRIPTED_PARENT_HTTP');self.assertEqual(value['inference']['real_model_calls'],0)
        self.assertEqual(value['current_charged'],{'containers':501,'participants':42})
        self.assertEqual(value['cumulative_upper_bound'],{'containers':508,'participants':43})
        self.assertEqual(value['current_caps'],{'containers':537,'participants':47})
        self.assertEqual(value['prerequisites']['normal_lock_file'],diagnostic.NORMAL_LOCK)
        self.assertTrue(value['prerequisites']['preserve_poison_and_four_private_flags'])
        self.assertFalse(value['prerequisites']['override_or_alternate_registry_namespace'])
        self.assertFalse(value['native_dispatch_supported_by_this_module'])
        self.assertFalse(value['task_oracle']['all_seven_roles_required_to_launch'])

    def test_real_model_or_unscoped_inference_cannot_be_a_scripted_diagnostic(self):
        for field,value in (('model','bartowski/Altworld_Hemmingway-1-GGUF'),('api_key_env','PI_API_KEY'),
          ('base_url','http://192.168.1.21:8888/v1'),('base_url','http://127.0.0.1:19081/v1'),
          ('base_url','http://host.invalid:19081/v1'),('base_url','http://172.17.0.1:19081/v1?x=1'),
          ('base_url','http://name:secret@172.17.0.1:19081/v1'),('reasoning',{'enabled':True})):
            value_endpoint=endpoint();value_endpoint[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):diagnostic.endpoint(value_endpoint)

    def test_fixed_limits_reserve_and_synthetic_usage_are_explicit(self):
        value=diagnostic.contract(endpoint(),route())
        self.assertEqual(value['stage_limits'],{'timeout_seconds':180,'max_turns':8,'max_total_tokens':16000,
          'max_tool_calls':16,'reporting_reserve_calls':6,'reporting_reserve_seconds':30})
        self.assertEqual(value['max_primary_attempts'],1);self.assertEqual(value['max_assistant_responses_planned'],7)
        self.assertEqual(value['inference']['synthetic_usage'],{'prompt_tokens':16,'completion_tokens':16,'total_tokens':32})
        self.assertFalse(value['task_oracle']['native_qualification_credit']);self.assertFalse(value['activation_created'])

    def drive(self,mutate=None):
        machine=diagnostic.SettlementScript();messages=[{'role':'user','content':'Controlled script fixture; not model text.'}];calls=[];decisions=[]
        for turn in range(7):
            decision=machine.respond(messages,set(diagnostic.REQUIRED_TOOLS));decisions.append(decision)
            diagnostic.response_frames(decision)
            if decision['finished']:return machine,calls,decisions,messages
            self.assertEqual(len(decision['calls']),1);call=decision['calls'][0];calls.append(copy.deepcopy(call))
            result=results(call,machine)
            if mutate:result=mutate(call,result)
            add(messages,call,result)
        self.fail('Script did not settle within seven responses')

    def test_six_explicit_calls_use_actual_DOM_data_and_truthful_partial_report_once(self):
        machine,calls,decisions,_=self.drive()
        self.assertEqual([row['name']for row in calls],list(diagnostic.CALLS));self.assertEqual(len(decisions),7)
        self.assertEqual(machine.unexpected_results,0);self.assertTrue(machine.identity_succeeded)
        self.assertEqual(calls[2]['arguments'],{'action':'click','target_id':'records-button'})
        content=calls[4]['arguments']['content'];self.assertIn('One & two',content);self.assertIn('Actual returned text',content)
        self.assertNotIn('NOT A SOURCE',content);self.assertNotIn('r3',content)
        report=calls[5]['arguments']['report'];self.assertEqual(report['pagination'],{'list-records':['first-page-receipt']})
        self.assertEqual(report['unresolved'],[diagnostic.UNRESOLVED]);self.assertEqual(report['publications'],[])
        self.assertEqual(report['artifacts'][0]['sha256'],hashlib.sha256(content.encode()).hexdigest())
        self.assertFalse(any(call['arguments'].get('action')in('fill','select')for call in calls))
        with self.assertRaises(ValueError):machine.respond([{'role':'user','content':'retry'}],set(diagnostic.REQUIRED_TOOLS))

    def test_failed_browser_stops_without_artifact_or_report_repair(self):
        def failed(call,result):return {'ok':False,'reason':'evidence_unavailable'}if call['name']=='app_browser'else result
        machine,calls,decisions,_=self.drive(failed)
        self.assertEqual([c['name']for c in calls],['app_api','app_browser']);self.assertEqual(machine.unexpected_results,1)
        self.assertTrue(decisions[-1]['finished']);self.assertEqual(decisions[-1]['calls'],[])

    def test_wrong_returned_artifact_hash_stops_before_report(self):
        def bad_hash(call,result):
            if call['name']=='artifact_write':result['sha256']='0'*64
            return result
        machine,calls,_,_=self.drive(bad_hash)
        self.assertEqual(len(calls),5);self.assertEqual(machine.unexpected_results,1)
        self.assertNotIn('report_write',[c['name']for c in calls])

    def test_foreign_duplicate_changed_or_missing_tool_result_refused(self):
        machine=diagnostic.SettlementScript();messages=[{'role':'user','content':'fixture'}]
        call=machine.respond(messages,set(diagnostic.REQUIRED_TOOLS))['calls'][0]
        add(messages,call,results(call,machine));original=copy.deepcopy(messages)
        for fault in ('foreign','duplicate','missing'):
            changed=copy.deepcopy(original)
            if fault=='foreign':changed[-1]['tool_call_id']='foreign'
            elif fault=='duplicate':changed.append(copy.deepcopy(changed[-1]))
            else:changed.pop()
            clone=copy.deepcopy(machine)
            with self.subTest(fault=fault),self.assertRaises(ValueError):clone.respond(changed,set(diagnostic.REQUIRED_TOOLS))
        machine.respond(messages,set(diagnostic.REQUIRED_TOOLS));messages[-1]['content']=json.dumps({'ok':False})
        with self.assertRaises(ValueError):machine.respond(messages,set(diagnostic.REQUIRED_TOOLS))

    def test_script_rejects_extra_tool_catalog_and_forged_frame_call(self):
        machine=diagnostic.SettlementScript()
        with self.assertRaises(ValueError):machine.respond([{'role':'user','content':'x'}],set(diagnostic.REQUIRED_TOOLS)|{'bash'})
        forged={'calls':[{'id':'settlement-call-1','name':'bash','arguments':{}}],'hold':False,'finished':False,'text':''}
        with self.assertRaises(ValueError):diagnostic.response_frames(forged)

    def test_closed_failure_code_does_not_use_exception_text_or_duck_attributes(self):
        tree=ast.parse((ROOT/'skill/scripts/application_execution.py').read_bytes())
        declaration=next(n.value for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='SETTLEMENT_CODES'for t in n.targets))
        self.assertEqual(frozenset(ast.literal_eval(declaration.args[0])),diagnostic.SETTLEMENT_CODES)
        for code in diagnostic.SETTLEMENT_CODES:
            self.assertEqual(diagnostic.settlement_projection({'schema':1,'code':code}),{'schema':1,'code':code})
        class Duck:
            code='CONTEXT_PURGE_FAILED'
            def __str__(self):raise AssertionError('exception string used')
        for value in (Duck(),ValueError('CONTEXT_PURGE_FAILED SECRET'),{'schema':True,'code':'CONTEXT_PURGE_FAILED'},
          {'schema':1,'code':'SECRET_DYNAMIC'},{'schema':1,'code':'CONTEXT_PURGE_FAILED','path':'SECRET'}):
            self.assertEqual(diagnostic.settlement_projection(value),{'schema':1,'code':'UNKNOWN'})
        evidence=diagnostic.contract(endpoint(),route())['automatic_evidence_contract']
        self.assertEqual(evidence['parent_process_field'],'application_settlement_failure')
        self.assertTrue(evidence['parent_and_terminal_code_capture_included_in_future_grant'])
        self.assertFalse(evidence['new_private_read_request_after_failure_required'])

    def compiler_fixture(self):
        f=qualification.QualificationTests(methodName='runTest');f.setUp();self.addCleanup(f.doCleanups)
        for profile in ('core','browser'):
            p=f.paths[profile+'-0.87.1'];receipt=json.loads(p.read_text());image=receipt.get('image',receipt)
            image['id']=diagnostic.IMAGE_IDS[profile];p.write_bytes(diagnostic.canonical(receipt))
        ep=self.root/'scripted-endpoint.json';ep.write_bytes(diagnostic.canonical(endpoint()))
        return f,ep

    def test_genuine_original_compiler_keeps_check_and_seven_role_disabled_contract(self):
        f,ep=self.compiler_fixture();target=self.root/'prepared'
        with mock.patch.object(diagnostic.preparation.pi_lab,'endpoint_secret',side_effect=AssertionError('credential resolution')):
            doc=diagnostic.prepare(target,image_receipts={'core':f.paths['core-0.87.1'],'browser':f.paths['browser-0.87.1']},
              scripted_endpoint=ep,fixture_route=route(),credential_reference='CONTROLLED_ACTOR_REFERENCE')
        self.assertEqual(doc['status'],'DISABLED_PREPARED');self.assertFalse(doc['native_clock_created'])
        plan=json.loads((target/'compiled/plan.json').read_text());self.assertEqual(len(plan['checks']),1)
        self.assertEqual(plan['stages'][0]['limits'],diagnostic.LIMITS)
        self.assertEqual(plan['runtime']['image_id'],diagnostic.IMAGE_IDS['browser'])
        self.assertEqual(diagnostic.verify(target),doc)
        for name in ('clock.json','grant.json','launch-ledger','state.json','reservation-consumed.json'):
            self.assertFalse((target/name).exists())
        with self.assertRaises(ValueError):diagnostic.require_execution(target,grant={'status':'AUTHORIZED'})

    def test_prepare_refuses_wrong_release_or_image_without_runtime_probe(self):
        f,ep=self.compiler_fixture();receipt=json.loads(f.paths['browser-0.87.1'].read_text());receipt['image']['id']='sha256:'+'0'*64
        f.paths['browser-0.87.1'].write_bytes(diagnostic.canonical(receipt))
        with self.assertRaises(ValueError):diagnostic.prepare(self.root/'wrong',image_receipts={'core':f.paths['core-0.87.1'],'browser':f.paths['browser-0.87.1']},
          scripted_endpoint=ep,fixture_route=route(),credential_reference='CONTROLLED_ACTOR_REFERENCE')
        self.assertFalse((self.root/'wrong').exists())

    def prepared_fixture(self):
        f,ep=self.compiler_fixture();target=self.root/'prepared'
        diagnostic.prepare(target,image_receipts={'core':f.paths['core-0.87.1'],'browser':f.paths['browser-0.87.1']},
          scripted_endpoint=ep,fixture_route=route(),credential_reference='CONTROLLED_ACTOR_REFERENCE')
        return target

    def replace_owned_fixture(self,path,body):
        # Original publisher seals files read-only. A modeled coherent repack
        # replaces only this test's fresh owned leaf, retaining readonly mode.
        path=Path(path);path.unlink();path.write_bytes(body);path.chmod(0o444)

    def rehash_preparation(self,target):
        doc=json.loads((target/'PREPARATION.json').read_text())
        doc['files']={name:hashlib.sha256((target/name).read_bytes()).hexdigest()for name in doc['files']}
        doc['contract_sha256']=hashlib.sha256((target/'CONTRACT.json').read_bytes()).hexdigest()
        doc['compiled_plan_sha256']=json.loads((target/'compiled/plan.json').read_text())['plan_sha256']
        self.replace_owned_fixture(target/'PREPARATION.json',diagnostic.canonical(doc))

    def coherent_recompile(self,target,fault):
        scratch=self.root/('alternative-'+fault);scratch.mkdir()
        source=json.loads((target/'source.json').read_text());ep=endpoint()
        if fault=='prompt':source['stages'][0]['prompt']='Another otherwise valid controlled workflow.'
        if fault=='endpoint':ep['model']='unreviewed-other-controlled-model'
        (scratch/'source.json').write_bytes(diagnostic.canonical(source))
        (scratch/'endpoint.json').write_bytes(diagnostic.canonical(ep))
        for name in ('content_scorer.py','expected.json'):
            body=(target/name).read_bytes()
            if fault=='scorer'and name=='expected.json':
                value=json.loads(body);value['content']='A different coherently hashed expected answer.';body=diagnostic.canonical(value)
            (scratch/name).write_bytes(body)
        diagnostic.preparation.compile_artifact(scratch/'source.json',scratch/'compiled',target/'compiled/runtime-receipt.json',
          endpoint_path=scratch/'endpoint.json')
        shutil.rmtree(target/'compiled');shutil.copytree(scratch/'compiled',target/'compiled')
        self.replace_owned_fixture(target/'source.json',diagnostic.canonical(source));self.rehash_preparation(target)
        # The generic original compiler correctly accepts this different,
        # internally consistent application. Only this case verifier must refuse it.
        diagnostic.preparation.load_compiled(target/'compiled/plan.json',verify_runner=True)

    def test_coherent_alternate_source_inference_or_scorer_is_not_this_diagnostic(self):
        for fault in ('prompt','endpoint','scorer'):
            with self.subTest(fault=fault):
                case=self.root/('case-'+fault);case.mkdir();oldroot=self.root;self.root=case
                try:
                    target=self.prepared_fixture();self.coherent_recompile(target,fault)
                    with self.assertRaises(ValueError):diagnostic.verify(target)
                finally:self.root=oldroot

    def test_self_consistent_repacked_contract_cannot_change_roles_locks_or_partial_oracle(self):
        target=self.prepared_fixture();original=(target/'CONTRACT.json').read_bytes()
        changes=(('roles_upper_bounds','scorer',0),('prerequisites','normal_lock_file','/tmp/unrelated.lock'),
          ('task_oracle','partial_first_page_only',False),('resource_limits','containers',5),
          ('stage_limits','max_tool_calls',17),('prerequisites','original_ownership_gate','PROVEN_BY_CALLER'))
        for section,key,value in changes:
            altered=json.loads(original);altered[section][key]=value
            self.replace_owned_fixture(target/'CONTRACT.json',diagnostic.canonical(altered));self.rehash_preparation(target)
            with self.subTest(section=section,key=key),self.assertRaises(ValueError):diagnostic.verify(target)
        self.replace_owned_fixture(target/'CONTRACT.json',original);self.rehash_preparation(target);diagnostic.verify(target)

    def test_complete_file_membership_and_provider_identity_are_reasserted(self):
        target=self.prepared_fixture();path=target/'PREPARATION.json';original=json.loads(path.read_text())
        for fault in ('missing-file','provider'):
            doc=copy.deepcopy(original)
            if fault=='missing-file':del doc['files']['project/TASK.md']
            else:doc['script_module_sha256']='0'*64
            self.replace_owned_fixture(path,diagnostic.canonical(doc))
            with self.subTest(fault=fault),self.assertRaises(ValueError):diagnostic.verify(target)
        self.replace_owned_fixture(path,diagnostic.canonical(original));diagnostic.verify(target)

    def test_normal_ownership_gate_and_existing_scope_cannot_be_replaced_by_execution_flags(self):
        value=diagnostic.contract(endpoint(),route());before=copy.deepcopy(value)
        with self.assertRaises(ValueError):diagnostic.require_execution(root=diagnostic.PRESERVED_SCOPE,lock_file='/tmp/other',grant={})
        self.assertEqual(value,before);self.assertEqual(value['prerequisites']['original_ownership_gate'],'REQUIRED_UNRESOLVED')
        self.assertEqual(value['prerequisites']['fresh_specific_grant'],'REQUIRED_NOT_CREATED')


if __name__=='__main__':unittest.main(verbosity=2)
