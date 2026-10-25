"""A08 stopped-output finalization; actual files, no effects or report repair."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_completion as reporting
import application_compiler as compiler
import test_application_compiler as plans
import test_completion_contract as completion_fixtures


class CompletionReportingTests(unittest.TestCase):
    def setUp(self):
        self.fixture=completion_fixtures.CompletionTests(methodName='runTest');self.fixture.setUp();self.addCleanup(self.fixture.tearDown)
        f=self.fixture
        self.stage={'id':'participant','completion':copy.deepcopy(f.contract)}
        self.context={'binding':copy.deepcopy(f.binding),'authorized_segment_ids':[f.binding['segment_id']],
            'report_root':f.outputs,'evidence_root':f.evidence,'parent_receipts':copy.deepcopy(f.index)}
        self.process={'cleanup_confirmed':True,'application_helper_cleanup':{'schema':1,'status':'removed',
            'workspace':'clean','safe_to_continue':True},'evidence':{'agent_invocation_verified':True,'completion_verified':True},
            'task_result':{'status':'pass','score':1}}
        self.credentials={'schema':1,'status':'removed','workspace':'clean'}

    def result(self):return reporting.stage_result(self.stage,self.context,self.process,self.credentials)

    def test_complete_actual_files_project_safely_without_mutating_invocation_or_score(self):
        before=copy.deepcopy(self.process);files={str(p):p.read_bytes() for p in self.fixture.base.rglob('*') if p.is_file()}
        result=self.result();self.assertEqual(result['projection']['status'],'complete')
        self.assertEqual(result['result'],self.fixture.evaluate())
        public=reporting.run_projection([result['projection']])
        self.assertTrue(reporting.gate(public,required_stages=('participant',)))
        self.assertEqual(self.process,before)
        self.assertEqual(files,{str(p):p.read_bytes() for p in self.fixture.base.rglob('*') if p.is_file()})

    def test_normally_settled_and_task_passing_missing_report_fails_without_requests_or_repair(self):
        path=self.fixture.outputs/self.fixture.contract['report_path'];path.unlink()
        before=copy.deepcopy(self.process)
        with mock.patch('http.client.HTTPConnection.request',side_effect=AssertionError('Unexpected HTTP')) as requests,\
             mock.patch('subprocess.Popen',side_effect=AssertionError('Unexpected process')) as launch:
            result=self.result()
        requests.assert_not_called();launch.assert_not_called()
        self.assertEqual(result['projection']['status'],'incomplete')
        self.assertEqual(result['projection']['diagnostics'],[{'code':'report_missing','count':1}])
        self.assertFalse(reporting.gate(reporting.run_projection([result['projection']]),required_stages=('participant',)))
        self.assertFalse(path.exists());self.assertEqual(self.process,before)

    def test_unknown_writer_helper_or_credential_cleanup_never_reads_outputs(self):
        for field in ('writer','helper','credential','discarded','missing-helper'):
            with self.subTest(field=field):
                process=copy.deepcopy(self.process);credentials=copy.deepcopy(self.credentials)
                if field=='writer':process['cleanup_confirmed']=False
                elif field=='helper':process['application_helper_cleanup']['safe_to_continue']=False
                elif field=='credential':credentials['status']='cleanup_unconfirmed'
                elif field=='discarded':credentials['workspace']='discarded'
                else:process.pop('application_helper_cleanup')
                with mock.patch.object(reporting.completion_contract.os,'open',side_effect=AssertionError('Unexpected file read')):
                    result=reporting.stage_result(self.stage,self.context,process,credentials)
                self.assertEqual(result['projection']['status'],'not_evaluated');self.assertIsNone(result['result'])

    def test_cancelled_stage_with_clean_writers_and_helper_never_reads_report(self):
        faults=[{'cancelled':True},{'exit_code':130},{'termination_reason':'cancelled'},
            {'termination_reason':'application_credential_cleanup'},{'termination_reason':'cleanup_error'},
            {'cancelled':'hostile'},{'exit_code':'hostile'}]
        for fault in faults:
            with self.subTest(fault=fault),mock.patch.object(reporting.completion_contract.os,'open',side_effect=AssertionError('Unexpected file read')):
                result=reporting.stage_result(self.stage,self.context,{**self.process,**fault},self.credentials)
            self.assertEqual(result['projection']['status'],'not_evaluated');self.assertIsNone(result['result'])

    def test_public_projection_excludes_private_paths_identity_receipt_ids_and_values(self):
        self.fixture.report['participant']['actor_id']='hostile-private-actor';self.fixture.store_report()
        result=self.result();self.assertEqual(result['projection']['status'],'invalid')
        self.assertIn('pointer',result['result']['diagnostics'][0])
        public=json.dumps(reporting.run_projection([result['projection']]))
        for value in ('pointer','expected','observed','receipt_ids','hostile-private-actor',str(self.fixture.outputs),'actor_id'):
            self.assertNotIn(value,public)
        self.assertIn('participant_mismatch',public)

    def test_malformed_parent_context_and_hostile_evaluator_verdict_fail_closed(self):
        self.context['unexpected-private']='private-value'
        result=self.result();self.assertEqual(result['projection']['status'],'invalid')
        self.assertNotIn('private-value',json.dumps(result));self.context.pop('unexpected-private')
        bads=[{'status':'private-value'},{'schema':1,'document_type':'application_completion_result',
            'contract_id':self.fixture.contract['id'],'status':'complete','diagnostics':[{'code':'private-value'}],
            'diagnostics_truncated':False}]
        for bad in bads:
            with mock.patch.object(reporting.completion_contract,'evaluate',return_value=bad):result=self.result()
            self.assertFalse(reporting.gate(reporting.run_projection([result['projection']])))
            self.assertNotIn('private-value',json.dumps(result))

    def test_gate_is_strict_about_versions_unknown_fields_status_codes_counts_and_required_rows(self):
        public=reporting.run_projection([self.result()['projection']])
        mutations=[lambda v:v.update(schema=True),lambda v:v.update(extra='private'),
            lambda v:v['stages'][0].update(status='private'),lambda v:v['stages'][0].update(extra='private'),
            lambda v:v['stages'][0].update(diagnostics=[{'code':'private','count':1}]),
            lambda v:v['stages'][0].update(diagnostics=[{'code':'report_missing','count':True}]),
            lambda v:v['stages'].clear()]
        for mutate in mutations:
            changed=copy.deepcopy(public);mutate(changed);self.assertFalse(reporting.gate(changed))
        self.assertFalse(reporting.gate(public,required_stages=('participant','missing')))
        self.assertFalse(reporting.gate(None,required_stages=('participant',)))
        self.assertFalse(reporting.gate(public,required_stages=('participant','participant')))

    def test_legacy_none_stays_absent_and_gate_true(self):
        self.assertIsNone(reporting.run_projection(None));self.assertTrue(reporting.gate(None))

    def dependency_plan(self):
        source=plans.two_stages()
        source['stages'][1]['depends_on']=['participant']
        third=copy.deepcopy(source['stages'][1]);third.update(id='unrelated',depends_on=[])
        third['completion']['id']='third-report';third['completion']['report_path']='third/report.json'
        third['completion']['artifacts'][0]['path']='third/summary.md';source['stages'].append(third)
        src,kwargs=plans.inputs(source);return compiler.compile_plan(src,**kwargs)

    def completed(self,name='participant',**flags):
        value={'invocation_ok':True,'cleanup_ok':True,
            'completion':{'stage':name,'status':'complete','diagnostics':[],'diagnostics_truncated':False}}
        value.update(flags);return value

    def test_dependency_failure_blocks_descendants_and_stops_unrelated_stages(self):
        plan=self.dependency_plan()
        self.assertIsNone(reporting.dependency_status(plan,{},'participant'))
        good={'participant':self.completed()};self.assertIsNone(reporting.dependency_status(plan,good,'second'))
        for change in ({'invocation_ok':False},{'cleanup_ok':False},
                {'completion':reporting.blocked_stage('participant','prior_failure')},{'completion':{'status':'hostile'}}):
            prior={'participant':self.completed(**change)}
            self.assertEqual(reporting.dependency_status(plan,prior,'second'),'dependency_blocked')
            prior['second']=self.completed('second')
            self.assertEqual(reporting.dependency_status(plan,prior,'unrelated'),'prior_failure')

    def test_missing_prior_or_hostile_parent_flags_fail_closed(self):
        plan=self.dependency_plan()
        self.assertEqual(reporting.dependency_status(plan,{},'second'),'dependency_blocked')
        self.assertEqual(reporting.dependency_status(plan,{'participant':self.completed(invocation_ok='private')},'second'),'dependency_blocked')
        self.assertEqual(reporting.dependency_status(plan,{'foreign':{}},'second'),'prior_failure')
        self.assertEqual(reporting.dependency_status(plan,{},'foreign'),'prior_failure')
        with self.assertRaises(reporting.CompletionReportingError):reporting.blocked_stage('participant','private')


if __name__=='__main__':unittest.main()
