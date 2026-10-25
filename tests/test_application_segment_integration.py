"""Real run_stage/segments/app coordinator/service; synthetic Pi and Docker.

This proves parent orchestration and prompt/accounting checks, not native Pi,
model behavior, external application effects or runtime qualification.
"""
import contextlib
import copy
import io
import json
from pathlib import Path
import shutil
import sys
import time
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_contracts as c
import application_execution
from application_client import ClientError
import pi_lab as lab
import stage_control as controls
import test_application_execution as fixture
import test_controls
import test_results


class ApplicationSegmentTests(unittest.TestCase):
    def setUp(self):
        self.case=fixture.ApplicationCoordinatorTests();self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.run,self.workspace=self.case.run,self.case.workspace
        shutil.rmtree(self.run/'trusted-runtime');lab.trusted_runtime(self.run)
        self.args=test_controls.args(**vars(self.case.args))
        self.args.event_contract='settled';self.args.lock_file=str(self.case.fixture.root/'lease')
        self.continue_once=False;self.tamper_prompt=False;self.tasks=[];self.contexts=[];self.coordinators=[]
        self.original_class=application_execution.ApplicationCoordinator
        def coordinator(*args,**kwargs):
            value=self.original_class(*args,**kwargs);self.coordinators.append(value);return value
        patch=mock.patch.object(application_execution,'ApplicationCoordinator',side_effect=coordinator);patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(lab,'stream_run',side_effect=self.stream);patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(lab,'docker_info',return_value={'NCPU':32,'MemTotal':64*1024**3});patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(lab,'command',side_effect=AssertionError('Unmocked native command is forbidden in this fixture'));patch.start();self.addCleanup(patch.stop)

    def stream(self,argv,logs,timeout,name,secret='',stage=None,keep_budget=False,resume_budget=False,native_control=None,**kwargs):
        run,desc=stage;state=controls.read(run/'stages'/desc['stage_id']/'state.json');segment=state['segment_id']
        folder=Path(desc['control'])/'segments'/segment;task=controls.read(folder/'task.json');self.tasks.append(task)
        context=controls.read(folder/'application-context.json');self.contexts.append(context)
        self.assertEqual(native_control.reservation.state,'launching')
        if not resume_budget:controls.start_budget(run,desc,time.monotonic(),native_control=native_control)
        native_control.mark_running()
        helper=self.case.helpers[-1];ledger=helper.service._ledgers[desc['stage_id']];scope=context['scope']
        native='call-1';batch='synthetic-batch-'+str(len(self.tasks))
        ledger.reserve_batch(scope,batch,[{'id':native,'name':'budget_status','arguments':{}}])
        grant=ledger.consume(scope,batch,native,'budget_status',{})['execution_nonce']
        ledger.verify_effect(grant,scope,native,'budget_status',{});ledger.complete(scope,batch,native,'budget_status',False);ledger.reconcile(scope,batch)
        trace=test_results.SegmentTests().trace(task['session_id'],model='fixture-model')
        def transform(value):
            if type(value) is dict:
                for key,item in list(value.items()):
                    if key in ('name','toolName') and item=='read':value[key]='budget_status'
                    elif key in ('arguments','args'):value[key]={}
                    else:transform(item)
            elif type(value) is list:
                for item in value:transform(item)
        transform(trace)
        if self.args.observed_pi_version=='1.2.0':
            for event in trace:
                if event.get('type')=='agent_settled':event['aborted']=False
        profile=controls.read(folder/'profile-context.json')
        receipt={key:profile[key] for key in ('run_id','attempt_id','stage_id','segment_id','profile_sha256')}
        receipt.update(active_tools=profile['allowed_tools'],registered_tools=profile['allowed_tools'],
                       assets_sha256={asset['target']:asset['sha256'] for asset in profile['profile']['assets']})
        trace.insert(1,{'type':'entry_appended','entry':{'customType':'pi_lab_profile','data':receipt}})
        logs.mkdir(parents=True);(logs/'stdout.jsonl').write_text(''.join(json.dumps(event)+'\n' for event in trace));(logs/'stderr.log').write_text('')
        runtime=Path(next(value.split('src=',1)[1].split(',dst=',1)[0] for value in argv if 'dst=/pi-state,' in value))
        (runtime/'sessions/session.jsonl').write_text(json.dumps(trace[0])+'\n')
        continuation=task.get('application_continuation');prompt=continuation['message'] if continuation else task['prompt']
        (runtime/'effective-prompt.txt').write_text('tampered' if self.tamper_prompt else prompt)
        (runtime/'application-prompt.json').write_bytes(c.canonical({'schema':1,
            'frozen_effective_prompt_sha256':task['application_execution']['effective_prompt_sha256'],
            'sent_prompt_sha256':__import__('hashlib').sha256(prompt.encode()).hexdigest(),
            'continuation':{key:continuation[key] for key in ('command_id','continues_segment_id','sha256')} if continuation else None}))
        if self.continue_once and len(self.tasks)==1:
            with contextlib.redirect_stdout(io.StringIO()):
                lab.cmd_steer(test_controls.args(run=str(run),stage=desc['stage_id'],message='Explicit parent direction',interrupt=False))
        result={'exit_code':0,'cleanup_confirmed':True,'started':True,'termination_reason':'completed'}
        lab.save(logs/'process.json',result);return result

    def execute(self):
        return lab.run_stage(self.args,self.case.plan['runtime']['image_id'],self.run,self.workspace,
            'agent-1-'+self.case.stage['id'],['agent'],task=self.case.task,endpoint={'model':'fixture-model'},
            secret=fixture.client_fixture.INFERENCE_KEY,timeout=self.case.stage['limits']['timeout_seconds'])

    def test_normal_settlement_missing_report_is_independently_incomplete_and_never_continues(self):
        result=self.execute()
        self.assertEqual(result['exit_code'],0,result)
        self.assertTrue(result['evidence']['agent_invocation_verified'],result['evidence'])
        self.assertEqual(len(self.tasks),1);self.assertEqual(result['native_tool_budget']['counts']['charged'],1)
        self.assertEqual(result['application_completion']['status'],'incomplete',result['application_completion'])
        self.assertTrue(result['application_helper_cleanup']['safe_to_continue'])
        self.assertEqual(set(result['application_completion_context']),{'binding','authorized_segment_ids','report_root','evidence_root','parent_receipts'})
        self.assertFalse(list(self.run.glob('controls/*/segments/*/application-context.json')))
        self.assertEqual(result['application_credentials']['status'],'removed')

    def test_explicit_cli_continuation_keeps_one_ledger_new_caps_and_original_frozen_prompt(self):
        self.continue_once=True;result=self.execute()
        self.assertTrue(result['evidence']['completion_verified'],result['evidence'])
        self.assertEqual(len(self.tasks),2);self.assertEqual(len(self.case.helpers),1)
        self.assertEqual(self.tasks[0]['prompt'],self.case.stage['effective_prompt'])
        self.assertEqual(self.tasks[1]['prompt'],self.tasks[0]['prompt'])
        self.assertEqual(self.tasks[1]['application_continuation']['message'],'Explicit parent direction')
        self.assertNotEqual(self.contexts[0]['capability'],self.contexts[1]['capability'])
        self.assertEqual(self.contexts[0]['scope']['session_id'],self.contexts[1]['scope']['session_id'])
        self.assertEqual(result['native_tool_budget']['counts']['charged'],2)
        self.assertEqual(len(result['application_completion_context']['authorized_segment_ids']),2)

    def test_worker_prompt_observation_mismatch_invalidates_invocation(self):
        self.tamper_prompt=True;result=self.execute()
        self.assertFalse(result['evidence']['completion_verified'])
        self.assertTrue(any('prompt observation' in error for segment in result['segments'] for error in segment['evidence']['errors']))

    def failed_helper(self,*,known=True,corrupt=None,failure=None):
        failure=failure if failure is not None else ClientError('evidence_unavailable')
        def start(authority,**kwargs):
            helper=fixture.HelperFixture(authority,**kwargs);self.case.helpers.append(helper)
            receipt=helper.cleanup(writers_absent=known)
            if corrupt is not None:corrupt(receipt)
            failure.application_helper_cleanup=receipt
            failure.application_helper_startup={'schema':1,'phase':'service_readiness','reason':'evidence_unavailable','diagnostic':None}
            failure.application_helper_launch_attempted=True
            raise failure
        self.case.start.side_effect=start
        return failure

    def parent_result(self):return controls.read(self.run/('agent-1-'+self.case.stage['id'])/'process.json')

    def test_failed_start_positive_actual_cleanup_does_not_invent_worker_or_evaluate_report(self):
        failure=self.failed_helper()
        with mock.patch('completion_contract.evaluate',side_effect=AssertionError('No report reads without participant')) as evaluator:
            with self.assertRaises(application_execution.ApplicationExecutionError) as caught:self.execute()
        self.assertIs(caught.exception.__cause__,failure);evaluator.assert_not_called()
        result=self.parent_result();self.assertEqual(result['document_type'],'application_preworker_failure')
        self.assertIsNone(result['exit_code']);self.assertIs(result['started'],False);self.assertIs(result['worker_launch_attempted'],False)
        self.assertTrue(result['cleanup_confirmed']);self.assertEqual(result['application_credentials']['status'],'removed')
        self.assertEqual(result['application_completion']['status'],'not_evaluated');self.assertIsNone(result['application_completion_result'])
        self.assertIsNone(result['native_tool_budget']);self.assertEqual(result['native_tool_budget_error'],'accounting_unavailable')
        self.assertEqual(result['application_helper_startup']['reason'],'evidence_unavailable')
        proof=result['application_preworker_cleanup'];self.assertFalse(proof['completion_eligible']);self.assertEqual(proof['accounting'],'unavailable')
        self.assertEqual(proof['binding']['stage_id'],next(self.run.glob('stages/*/application-credentials.json')).parent.name)
        self.assertEqual(self.tasks,[]);self.assertEqual(len(self.case.helpers),1)
        lab.stream_run.assert_not_called()
        self.assertEqual(self.case.helpers[0].requests,[])
        self.assertNotIn('evidence',result);self.assertNotIn('segments',result)

    def test_unknown_helper_cleanup_keeps_original_start_failure_and_credential_gate_closed(self):
        failure=self.failed_helper(known=False)
        with mock.patch('completion_contract.evaluate',side_effect=AssertionError('No report reads')) as evaluator:
            with self.assertRaises(application_execution.ApplicationExecutionError) as caught:self.execute()
        self.assertIs(caught.exception.__cause__,failure);evaluator.assert_not_called();self.assertEqual(self.tasks,[])
        lab.stream_run.assert_not_called()
        result=self.parent_result();self.assertFalse(result['cleanup_confirmed'])
        self.assertNotIn('application_preworker_cleanup',result)
        self.assertEqual(result['application_credentials']['status'],'cleanup_unconfirmed')
        self.assertEqual(result['application_completion']['status'],'not_evaluated')

    def test_malformed_positive_helper_receipt_does_not_authorize_sensitive_cleanup(self):
        self.failed_helper(corrupt=lambda receipt:receipt.update(schema=True))
        with self.assertRaises(application_execution.ApplicationExecutionError):self.execute()
        result=self.parent_result();self.assertFalse(result['cleanup_confirmed']);self.assertNotIn('application_preworker_cleanup',result)
        self.assertEqual(result['application_credentials']['status'],'cleanup_unconfirmed')

    def test_malformed_optional_evidence_fields_cannot_enter_positive_preworker_record(self):
        self.failed_helper(corrupt=lambda receipt:receipt.update(evidence={'unexpected':'payload-not-published'},evidence_root=False))
        with self.assertRaises(application_execution.ApplicationExecutionError):self.execute()
        result=self.parent_result();self.assertFalse(result['cleanup_confirmed']);self.assertNotIn('application_preworker_cleanup',result)
        self.assertNotIn('payload-not-published',c.canonical(result).decode())
        self.assertEqual(result['application_credentials']['status'],'cleanup_unconfirmed')

    def test_external_optional_evidence_path_cannot_authorize_preworker_cleanup(self):
        self.failed_helper(corrupt=lambda receipt:receipt.update(evidence='retained',evidence_root='/unowned/evidence'))
        with self.assertRaises(application_execution.ApplicationExecutionError):self.execute()
        result=self.parent_result();self.assertFalse(result['cleanup_confirmed']);self.assertNotIn('application_preworker_cleanup',result)

    def test_quarantined_nonnull_evidence_contradiction_cannot_authorize_preworker_cleanup(self):
        self.failed_helper(corrupt=lambda receipt:receipt.update(evidence='quarantined',
            evidence_root=str(self.run/'application-evidence'/('pi-application-'+'a'*16))))
        with self.assertRaises(application_execution.ApplicationExecutionError):self.execute()
        result=self.parent_result();self.assertFalse(result['cleanup_confirmed']);self.assertNotIn('application_preworker_cleanup',result)

    def test_worker_dispatch_attempt_cannot_be_reclassified_as_preworker_absence(self):
        with mock.patch.object(lab,'stream_run',side_effect=ValueError('Controlled dispatch failure')):
            with self.assertRaises(ValueError):self.execute()
        result=self.parent_result();self.assertNotIn('application_preworker_cleanup',result)
        self.assertFalse(result['cleanup_confirmed']);self.assertEqual(result['application_credentials']['status'],'cleanup_unconfirmed')

    def test_activation_failure_keeps_cleanup_positive_without_finish_or_budget_claim(self):
        failure=ValueError('private-startup-message-must-not-be-published')
        with mock.patch.object(application_execution,'helper_control',side_effect=failure),mock.patch('completion_contract.evaluate') as evaluator:
            with self.assertRaises(application_execution.ApplicationExecutionError) as caught:self.execute()
        self.assertIs(caught.exception.__cause__,failure);evaluator.assert_not_called()
        result=self.parent_result();self.assertTrue(result['cleanup_confirmed'])
        self.assertIsNone(result['native_tool_budget']);self.assertIsNone(result['application_completion_context'])
        self.assertEqual(result['application_completion']['status'],'not_evaluated')
        self.assertEqual(result['application_credentials']['status'],'removed')
        self.assertNotIn('private-startup-message',c.canonical(result).decode());self.assertEqual(self.tasks,[])
        lab.stream_run.assert_not_called()
        self.assertEqual(self.case.helpers[0].requests,[])

    def test_settled_worker_cannot_later_supply_preworker_proof(self):
        self.execute();co=self.coordinators[0]
        self.assertIsNone(co.preworker_failure(worker_launch_attempted=False,
            segment_id=self.contexts[0]['scope']['segment_id'],session_id=self.contexts[0]['scope']['session_id']))

    def test_cancel_before_worker_preserves_cancel_and_clean_sensitive_cleanup_without_report_reads(self):
        failure=self.failed_helper(failure=KeyboardInterrupt())
        with mock.patch('completion_contract.evaluate',side_effect=AssertionError('Cancelled report read')) as evaluator:
            with self.assertRaises(KeyboardInterrupt) as caught:self.execute()
        self.assertIs(caught.exception,failure);evaluator.assert_not_called();lab.stream_run.assert_not_called()
        result=self.parent_result();self.assertTrue(result['cancelled']);self.assertEqual(result['termination_reason'],'cancelled')
        self.assertIsNone(result['exit_code']);self.assertTrue(result['cleanup_confirmed'])
        self.assertEqual(result['application_credentials']['status'],'removed');self.assertEqual(result['application_completion']['status'],'not_evaluated')


if __name__=='__main__':unittest.main()
