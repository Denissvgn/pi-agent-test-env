"""Outcome finalization keeps invocation/task/report dimensions independent."""
import copy
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_completion as completion
import outcomes
import test_completion_contract as fixtures


class CompletionOutcomeTests(unittest.TestCase):
    def record(self,status='complete'):
        record=outcomes.initial()
        record['infrastructure']['status']='ready';record['invocation']['status']='verified'
        record['termination']['reason']='completed';record['scoring']['status']='completed'
        record['task_result'].update(status='pass',score=1);record['protected_inputs']['status']='unchanged'
        record['application_execution']={'schema':1,'plan_sha256':'a'*64,'required_stages':['participant']}
        row={'stage':'participant','status':status,'diagnostics':[] if status=='complete' else [{'code':'report_missing','count':1}],
             'diagnostics_truncated':False}
        record['application_completion']=completion.run_projection([row])
        return record

    def test_normally_settled_task_pass_with_missing_report_is_fail_one(self):
        fixture=fixtures.CompletionTests(methodName='runTest');fixture.setUp();self.addCleanup(fixture.tearDown)
        (fixture.outputs/fixture.contract['report_path']).unlink()
        binding=fixture.binding
        context={'binding':binding,'authorized_segment_ids':[binding['segment_id']], 'report_root':fixture.outputs,
                 'evidence_root':fixture.evidence,'parent_receipts':fixture.index}
        process={'exit_code':0,'cleanup_confirmed':True,'termination_reason':'completed',
                 'application_helper_cleanup':{'schema':1,'status':'removed','workspace':'clean','safe_to_continue':True}}
        before={str(p):p.read_bytes() for p in fixture.base.rglob('*') if p.is_file()}
        result=completion.stage_result({'id':'participant','completion':fixture.contract},context,process,
                                      {'schema':1,'status':'removed','workspace':'clean'})
        record=self.record();record['application_completion']=completion.run_projection([result['projection']])
        self.assertEqual(outcomes.status(record),('FAIL',1))
        self.assertEqual(record['invocation']['status'],'verified');self.assertEqual(record['task_result']['score'],1)
        self.assertEqual(result['projection']['diagnostics'],[{'code':'report_missing','count':1}])
        self.assertEqual(before,{str(p):p.read_bytes() for p in fixture.base.rglob('*') if p.is_file()})
        self.assertFalse((fixture.outputs/fixture.contract['report_path']).exists())

    def test_complete_report_retains_existing_assistance_and_recovery_semantics(self):
        record=self.record();self.assertEqual(outcomes.status(record),('PASS',0))
        record['assistance']['status']='assisted';self.assertEqual(outcomes.status(record),('ASSISTED',1))
        record['invocation']['status']='recovered';self.assertEqual(outcomes.status(record),('RECOVERED',1))

    def test_missing_or_tampered_required_projection_never_becomes_legacy(self):
        for mutation in ('delete','extra','missingstage','wrongorder','hostile','invalidmarker'):
            with self.subTest(mutation=mutation):
                record=self.record()
                if mutation=='delete':del record['application_completion']
                elif mutation=='extra':record['application_completion']['raw']='secret payload'
                elif mutation=='missingstage':record['application_completion']['stages']=[]
                elif mutation=='wrongorder':record['application_execution']['required_stages']=['second','participant']
                elif mutation=='hostile':record['application_completion']['stages'][0]['status']={'private':'value'}
                else:record['application_execution']['schema']=True
                self.assertEqual(outcomes.status(record),('FAIL',1))

    def test_cancel_precedence_and_legacy_absence_are_preserved(self):
        record=self.record('incomplete');record['termination']['reason']='cancelled'
        self.assertEqual(outcomes.status(record),('INTERRUPTED',2))
        record=self.record();del record['application_execution'];del record['application_completion']
        self.assertEqual(outcomes.status(record),('PASS',0))


if __name__=='__main__':unittest.main()
