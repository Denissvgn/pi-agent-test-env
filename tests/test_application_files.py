"""A07 typed artifact/report helper: real local files, no Docker/network/models."""
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import tempfile
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_files as files
import application_compiler as compiler
import application_contracts as c
import application_credentials
import application_client_service as service
import prompt_contract
import test_application_compiler as fixtures
from tool_budgets import BudgetLedger

KEY='disposable-artifact-private-key-123456789'


class Authority:
    def __init__(self,plan,scope,bearer):
        self.plan=plan;self.scope=copy.deepcopy(scope);self.bearer=bearer;self.revoked=False
        self.redactor=application_credentials.Redactor([KEY]);self.authorizations=0
    def authorize(self,bearer,scope):
        self.authorizations+=1
        if bearer!=self.bearer or scope!=self.scope or self.revoked:raise files.FileError('operation_not_granted')
        service.validate_scope(scope,self.plan)


class ApplicationFileTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/private/tmp');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.artifacts=self.root/'artifacts';self.artifacts.mkdir(mode=0o700)
        self.reports=self.root/'reports';self.reports.mkdir(mode=0o700)
        self.sealed=self.root/'sealed';self.sealed.mkdir(mode=0o700)
        self.source=copy.deepcopy(fixtures.POSITIVE['source'])
        self.source['stages'][0]['completion']['artifacts'].append({'id':'json-data','path':'outputs/data.json','media_type':'application/json','max_bytes':4096})
        self.client=None;self.grants={};self.verifications=[]
        self.addCleanup(lambda:self.client.close() if self.client else None)
        self.build()

    def build(self,source=None,stage_index=0,sealed_inputs=None,verifier=None):
        if self.client:self.client.close()
        source,kwargs=fixtures.inputs(source or self.source);self.plan=compiler.compile_plan(source,**kwargs)
        self.stage=self.plan['stages'][stage_index]
        self.scope={key:str(uuid.uuid4()) for key in service.BINDING_FIELDS-{'plan_sha256','trial_id'}}
        self.scope.update(trial_id=None,plan_sha256=self.plan['plan_sha256'],stage_name=self.stage['id'],participant=self.stage['participant'],
            operation_ids=self.stage['operations'],credential_aliases=self.stage['credential_aliases'],authority_generation=str(uuid.uuid4()))
        self.bearer=secrets.token_hex(32);self.authority=Authority(self.plan,self.scope,self.bearer)
        self.client=files.ApplicationFiles(self.authority,self.artifacts,self.reports,
            sealed_inputs=sealed_inputs,budget_verifier=verifier or self.verifier)

    def verifier(self,grant,scope,call_id,tool,arguments):
        self.verifications.append((grant,copy.deepcopy(scope),call_id,tool,copy.deepcopy(arguments)))
        return self.grants.pop(grant,None)==(scope,call_id,tool,arguments)

    def call(self,tool='artifact_write',arguments=None,call_id=None,grant=None,bearer=None,scope=None):
        arguments=arguments if arguments is not None else {'artifact_id':'summary','content':'# Exact artifact\n'}
        call_id=call_id or 'call_'+uuid.uuid4().hex
        grant=grant or secrets.token_hex(32)
        target=copy.deepcopy(scope if scope is not None else self.scope)
        self.grants[grant]=(target,call_id,tool,copy.deepcopy(arguments))
        return self.client.execute(bearer or self.bearer,target,call_id,tool,arguments,grant)

    def report(self):
        return {'schema':1,'document_type':'application_completion_report','contract_id':self.stage['completion']['id'],
                'participant':copy.deepcopy(self.stage['participant']),'artifacts':[],'pagination':{},'publications':[],'unresolved':[]}

    def test_write_and_read_exact_utf8_one_grant_per_operation(self):
        text='# Exact café\n';value=self.call(arguments={'artifact_id':'summary','content':text})
        body=text.encode();path=self.artifacts/'outputs/summary.md'
        self.assertTrue(value['ok']);self.assertEqual(path.read_bytes(),body)
        self.assertEqual(value['sha256'],hashlib.sha256(body).hexdigest());self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode),0o700)
        result=self.call('artifact_read',{'artifact_id':'summary'})
        self.assertEqual(result['content'],text);self.assertEqual(result['bytes'],len(body));self.assertEqual(len(self.verifications),2)

    def test_missing_budget_verifier_rejects_constructor_and_missing_grant_has_no_effect(self):
        with self.assertRaises(files.FileError):files.ApplicationFiles(self.authority,self.artifacts)
        value=self.client.execute(self.bearer,self.scope,'call_missing','artifact_write',{'artifact_id':'summary','content':'x'})
        self.assertEqual(value,{'ok':False,'reason':'accounting_unavailable'});self.assertFalse((self.artifacts/'outputs').exists())

    def test_unauthorized_bearer_or_scope_denies_before_verifier_and_files(self):
        scope=copy.deepcopy(self.scope);scope['participant']['actor_id']='foreign'
        for kwargs in ({'bearer':'f'*64},{'scope':scope}):
            with self.subTest(kwargs=kwargs):self.assertFalse(self.call(**kwargs)['ok'])
        self.assertEqual(self.verifications,[]);self.assertFalse((self.artifacts/'outputs').exists())

    def test_exact_input_ids_paths_and_types_reject_before_effect_proof(self):
        cases=[{'artifact_id':'../summary','content':'x'},{'artifact_id':'foreign','content':'x'},
               {'artifact_id':'summary','content':'x','path':'../outside'},{'artifact_id':'summary','content':123},
               {'artifact_id':True,'content':'x'},{'artifact_id':'summary','content':'x'*4097}]
        for arguments in cases:
            with self.subTest(arguments=arguments):self.assertFalse(self.call(arguments=arguments)['ok'])
        self.assertEqual(self.verifications,[]);self.assertFalse((self.artifacts/'outputs').exists())

    def test_strict_json_artifact_rejects_duplicate_nonfinite_and_bad_encoding(self):
        for content in ('{"x":1,"x":2}','{"x":NaN}','{"x":Infinity}','not-json','"\\u0000"','\ud800'):
            with self.subTest(content=repr(content)):self.assertFalse(self.call(arguments={'artifact_id':'json-data','content':content})['ok'])
        self.assertEqual(self.verifications,[]);self.assertFalse((self.artifacts/'outputs').exists())
        self.assertTrue(self.call(arguments={'artifact_id':'json-data','content':'{"x":1}'})['ok'])

    def test_known_secret_in_content_report_json_or_native_id_denies_without_persistence(self):
        encoded=''.join('\\u%04x'%ord(ch) for ch in KEY)
        cases=[('artifact_write',{'artifact_id':'summary','content':KEY},None),
               ('artifact_write',{'artifact_id':'json-data','content':'{"x":"'+encoded+'"}'},None),
               ('artifact_write',{'artifact_id':'summary','content':'safe'},KEY)]
        for tool,args,call_id in cases:self.assertFalse(self.call(tool,args,call_id=call_id)['ok'])
        report=self.report();report['unresolved']=[KEY]
        self.assertFalse(self.call('report_write',{'report':report})['ok'])
        self.assertEqual(self.verifications,[])
        for path in self.root.rglob('*'):
            if path.is_file():self.assertNotIn(KEY.encode(),path.read_bytes())

    def test_private_capability_corpus_rejects_literal_and_json_escaped_inputs_locally(self):
        capability='private-context-cap-\\"-123456789'
        self.client.close();self.client=files.ApplicationFiles(self.authority,self.artifacts,self.reports,
            budget_verifier=self.verifier,forbidden_values=[capability])
        escaped=json.dumps(capability)[1:-1]
        for content in (capability,escaped):
            self.assertFalse(self.call(arguments={'artifact_id':'summary','content':content})['ok'])
            report=self.report();report['unresolved']=[content]
            self.assertFalse(self.call('report_write',{'report':report})['ok'])
        self.assertEqual(self.verifications,[]);self.assertFalse((self.artifacts/'outputs').exists())
        self.assertFalse((self.reports/'outputs').exists())
        self.assertFalse(self.authority.redactor.contains(capability.encode()))

    def test_forbidden_corpus_is_strict_bounded_and_not_part_of_repr(self):
        for corpus in ([str(n) for n in range(257)],['x'*16385],[None],['']):
            with self.subTest(corpus_type=type(corpus)),self.assertRaises(ValueError):
                files.ApplicationFiles(self.authority,self.artifacts,budget_verifier=self.verifier,forbidden_values=corpus)
        self.assertNotIn(KEY,repr(self.client))

    def test_report_writes_exact_supplied_value_without_autofill_or_repair(self):
        report=self.report();before=copy.deepcopy(report)
        value=self.call('report_write',{'report':report})
        path=self.reports/self.stage['completion']['report_path']
        self.assertTrue(value['ok']);self.assertEqual(json.loads(path.read_bytes()),before);self.assertEqual(report,before)
        self.assertEqual(path.read_bytes(),c.canonical(report));self.assertEqual(json.loads(path.read_bytes())['artifacts'],[])
        self.assertFalse((self.artifacts/'outputs').exists())

    def test_report_identity_contract_membership_and_bounds_are_strict(self):
        for mutation in ('identity','contract','artifact','path','pagination','publication','size','extra'):
            report=self.report()
            if mutation=='identity':report['participant']['actor_id']='foreign'
            elif mutation=='contract':report['contract_id']='foreign'
            elif mutation in ('artifact','path'):
                report['artifacts']=[{'id':'foreign' if mutation=='artifact' else 'summary','path':'foreign.md','bytes':1,'sha256':'a'*64}]
            elif mutation=='pagination':report['pagination']={'foreign-operation':['receipt-1']}
            elif mutation=='publication':report['publications']=[{'id':'foreign','receipt_id':'receipt-1'}]
            elif mutation=='size':report['unresolved']=['x'*4096]*20
            else:report['private']=KEY
            with self.subTest(mutation=mutation):self.assertFalse(self.call('report_write',{'report':report})['ok'])
        self.assertFalse((self.reports/'outputs').exists());self.assertEqual(self.verifications,[])

    def test_same_native_id_and_grant_cannot_repeat_file_effect(self):
        args={'artifact_id':'summary','content':'first'};call='call_Exact-ID';grant='a'*64
        self.assertTrue(self.call(arguments=args,call_id=call,grant=grant)['ok'])
        self.assertFalse(self.call(arguments={'artifact_id':'summary','content':'second'},call_id=call,grant=grant)['ok'])
        self.assertEqual((self.artifacts/'outputs/summary.md').read_text(),'first');self.assertEqual(len(self.verifications),1)

    def test_revocation_after_budget_verification_prevents_effect(self):
        def revoke(*args):self.authority.revoked=True;return True
        self.client.budget_verifier=revoke
        self.assertFalse(self.call()['ok']);self.assertFalse((self.artifacts/'outputs').exists())

    def test_large_read_returns_truthful_metadata_and_no_partial_content(self):
        self.source['stages'][0]['completion']['artifacts'][0]['max_bytes']=262144;self.build()
        body='x'*9000;self.assertTrue(self.call(arguments={'artifact_id':'summary','content':body})['ok'])
        value=self.call('artifact_read',{'artifact_id':'summary'})
        self.assertEqual(value['reason'],'result_limit');self.assertEqual(value['bytes'],9000)
        self.assertEqual(value['sha256'],hashlib.sha256(body.encode()).hexdigest());self.assertNotIn('content',value)
        self.assertLessEqual(len(c.canonical(value)),8192)

    def test_symlink_hardlink_and_fifo_outputs_cannot_be_replaced(self):
        output=self.artifacts/'outputs';output.mkdir(mode=0o700);target=self.root/'external';target.write_text('untouched')
        path=output/'summary.md'
        for kind in ('symlink','hardlink','fifo'):
            self.client.quarantined=False
            if kind=='symlink':path.symlink_to(target)
            elif kind=='hardlink':os.link(target,path)
            else:os.mkfifo(path)
            value=self.call();self.assertFalse(value['ok']);self.assertEqual(target.read_text(),'untouched');path.unlink()

    def test_special_or_linked_artifacts_cannot_be_read(self):
        output=self.artifacts/'outputs';output.mkdir(mode=0o700);target=self.root/'external';target.write_text('outside')
        path=output/'summary.md'
        for kind in ('symlink','hardlink','fifo'):
            if kind=='symlink':path.symlink_to(target)
            elif kind=='hardlink':os.link(target,path)
            else:os.mkfifo(path)
            with self.subTest(kind=kind):self.assertFalse(self.call('artifact_read',{'artifact_id':'summary'})['ok'])
            path.unlink()

    def test_ancestor_replacement_during_commit_never_writes_through_new_symlink(self):
        self.assertTrue(self.call()['ok']);outside=self.root/'outside';outside.mkdir(mode=0o700)
        external=outside/'summary.md';external.write_text('untouched');original=files.os.replace
        def replace(source,destination,**kwargs):
            (self.artifacts/'outputs').rename(self.artifacts/'old-outputs')
            (self.artifacts/'outputs').symlink_to(outside,target_is_directory=True)
            return original(source,destination,**kwargs)
        with mock.patch.object(files.os,'replace',side_effect=replace):value=self.call(arguments={'artifact_id':'summary','content':'new'})
        self.assertFalse(value['ok']);self.assertTrue(self.client.quarantined);self.assertEqual(external.read_text(),'untouched')

    def test_root_permissions_and_generic_tool_names_fail_closed(self):
        public=self.root/'public';public.mkdir(mode=0o755)
        with self.assertRaises(ValueError):files.ApplicationFiles(self.authority,public,budget_verifier=self.verifier)
        for tool in ('read','write','bash','eval','unknown'):
            with self.subTest(tool=tool):self.assertFalse(self.call(tool,{'path':'/etc/passwd'})['ok'])
        self.assertEqual(self.verifications,[])

    def test_native_id_reuse_in_new_parent_authorized_segment_remains_exact(self):
        native='call_Exact.ABC-1';self.assertTrue(self.call(call_id=native)['ok'])
        self.scope['segment_id']=str(uuid.uuid4());self.authority.scope=copy.deepcopy(self.scope)
        self.assertTrue(self.call(arguments={'artifact_id':'summary','content':'new segment'},call_id=native)['ok'])
        self.assertEqual(self.verifications[0][2],native);self.assertEqual(self.verifications[1][2],native)

    def test_symlink_ancestor_and_replaced_root_fail_closed(self):
        outside=self.root/'outside';outside.mkdir(mode=0o700)
        (self.artifacts/'outputs').symlink_to(outside,target_is_directory=True)
        self.assertFalse(self.call()['ok']);self.assertFalse((outside/'summary.md').exists())
        (self.artifacts/'outputs').unlink();self.client.quarantined=False
        self.artifacts.rename(self.root/'old-artifacts');self.artifacts.mkdir(mode=0o700)
        self.assertFalse(self.call()['ok']);self.assertFalse((self.artifacts/'outputs').exists())

    def test_atomic_replace_failure_preserves_existing_bytes_and_blocks_future_effects(self):
        self.assertTrue(self.call(arguments={'artifact_id':'summary','content':'old'})['ok'])
        with mock.patch.object(files.os,'replace',side_effect=OSError('synthetic storage failure')):
            self.assertFalse(self.call(arguments={'artifact_id':'summary','content':'new'})['ok'])
        self.assertEqual((self.artifacts/'outputs/summary.md').read_text(),'old');self.assertTrue(self.client.quarantined)
        self.assertFalse(self.call()['ok']);self.assertEqual(list((self.artifacts/'outputs').glob('.artifact-*')),[])

    def test_directory_fsync_failure_after_replace_never_reports_success_or_retries(self):
        self.assertTrue(self.call()['ok']);original=files.os.fsync
        def fail(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):raise OSError('synthetic uncertain durability')
            return original(fd)
        with mock.patch.object(files.os,'fsync',side_effect=fail):value=self.call(arguments={'artifact_id':'summary','content':'committed-once'})
        self.assertFalse(value['ok']);self.assertTrue(self.client.quarantined)
        self.assertEqual((self.artifacts/'outputs/summary.md').read_text(),'committed-once')

    def predecessor(self):
        source=fixtures.two_stages();second=source['stages'][1];second['depends_on']=[source['stages'][0]['id']]
        second['operations']=[name for name in second['operations'] if name!='publish-summary'];second['completion']['publications']=[]
        second['completion']['artifacts'][0]['id']='second-summary'
        second['input_artifacts']=[{'stage_id':source['stages'][0]['id'],'artifact_id':'summary'}]
        path=self.sealed/'summary.md';path.write_bytes(b'sealed predecessor');path.chmod(0o400)
        entry={'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'bytes':path.stat().st_size,'media_type':'text/markdown'}
        self.build(source,1,{(source['stages'][0]['id'],'summary'):entry})
        return path,entry

    def test_parent_sealed_predecessor_read_is_hash_checked_and_never_writable(self):
        path,_=self.predecessor();value=self.call('artifact_read',{'artifact_id':'summary'})
        self.assertTrue(value['ok']);self.assertEqual(value['content'],'sealed predecessor')
        self.assertFalse(self.call(arguments={'artifact_id':'summary','content':'forged'})['ok'])
        self.assertEqual(path.read_bytes(),b'sealed predecessor')

    def test_tampered_linked_or_unsealed_predecessor_is_unavailable(self):
        path,entry=self.predecessor();path.chmod(0o600)
        self.assertFalse(self.call('artifact_read',{'artifact_id':'summary'})['ok'])
        path.write_bytes(b'tampered predecessor');path.chmod(0o400)
        self.assertFalse(self.call('artifact_read',{'artifact_id':'summary'})['ok'])
        path.unlink();path.symlink_to(self.root/'external')
        self.assertFalse(self.call('artifact_read',{'artifact_id':'summary'})['ok'])

    def test_real_budget_ledger_consumes_effect_once_without_double_charge(self):
        binding={key:self.scope[key] for key in ('plan_sha256','run_id','trial_id','attempt_id','stage_id','session_id')}
        binding['pi_release']=self.plan['runtime']['pi_release']
        ledgerroot=self.root/'ledger';ledgerroot.mkdir(mode=0o700)
        ledger=BudgetLedger.create(ledgerroot/'state.json',binding=binding,limits={'max_tool_calls':10,'reporting_reserve_calls':2,'reporting_reserve_seconds':10},
            native_tools=prompt_contract.tool_schemas(self.stage),initial_segment_id=self.scope['segment_id'],deadline=200,clock=lambda:100,
            completion=self.stage['completion'])
        args={'artifact_id':'summary','content':'ledger-authorized'};native='call_Ledger-1';batch='batch-1'
        ledger.reserve_batch(self.scope,batch,[{'id':native,'name':'artifact_write','arguments':args}])
        grant=ledger.consume(self.scope,batch,native,'artifact_write',args)['execution_nonce']
        self.client.budget_verifier=ledger.verify_effect
        result=self.client.execute(self.bearer,self.scope,native,'artifact_write',args,grant)
        self.assertTrue(result['ok']);snapshot=ledger.snapshot()
        self.assertEqual(snapshot['counts']['charged'],1);self.assertEqual(snapshot['counts']['executed_known'],1)
        self.assertFalse(self.client.execute(self.bearer,self.scope,native,'artifact_write',args,grant)['ok'])


if __name__=='__main__':unittest.main()
