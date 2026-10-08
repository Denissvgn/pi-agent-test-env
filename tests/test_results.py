"""Offline attempt/scoring/recovery failures; synthetic Docker/Pi fixtures only."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT=(Path(__file__).resolve().parents[1] / 'skill')
sys.path.insert(0,str(ROOT/'scripts'))
import pi_lab as lab
import outcomes


def fixture(top):
    project=top/'project';project.mkdir();(project/'code.py').write_text('pass')
    plan=top/'plan.json';lab.save(plan,{'schema':1,'agents':[{'name':'dev','prompt':'Synthetic task','require_tools':[]}],'checks':[{'name':'oracle','argv':['true']}]})
    a=lab.parser().parse_args(['run','--project',str(project),'--plan',str(plan),'--endpoint',str(top/'endpoint.json'),'--results-dir',str(top/'results'),'--lock-file',str(top/'lease'),'--platform','linux/arm64','--memory','1g','--cpus','1'])
    return a


def mocked_suite(stack, stage=None):
    endpoint={'base_url':'http://example.invalid/v1','model':'fixture-model','api_key_env':'PI_API_KEY','context_window':8192,'max_tokens':1024}
    stack.enter_context(mock.patch.object(lab,'load_endpoint',return_value=endpoint))
    stack.enter_context(mock.patch.object(lab,'endpoint_secret',return_value='synthetic-key'))
    stack.enter_context(mock.patch.object(lab,'require_host',return_value={}))
    stack.enter_context(mock.patch.object(lab,'probe_image',return_value={'id':'fixture','reference':'fixture'}))
    def fake(argv,logdir,timeout,name,secret='',stage=None,**kw):
        logdir.mkdir(parents=True,exist_ok=True);(logdir/'stdout.jsonl').write_text('');(logdir/'stderr.log').write_text('')
        return {'exit_code':0,'cleanup_confirmed':True}
    stack.enter_context(mock.patch.object(lab,'stream_run',side_effect=stage or fake))
    stack.enter_context(mock.patch.object(lab,'analyze',return_value={'agent_invocation_verified':True,'errors':[],'final_text':'synthetic'}))
    stack.enter_context(mock.patch.object(lab.segments,'aggregate',return_value={'agent_invocation_verified':True,'completion_verified':True,'invocation_status':'verified','errors':[],'final_text':'synthetic'}))
    stack.enter_context(contextlib.redirect_stdout(io.StringIO()))


class AttemptTests(unittest.TestCase):
    def test_prerequisite_failures_have_initial_and_final_records(self):
        for name in ('load_endpoint','endpoint_secret','require_host','probe_image'):
            with self.subTest(prerequisite=name),tempfile.TemporaryDirectory() as td,contextlib.ExitStack() as stack:
                top=Path(td);a=fixture(top);mocked_suite(stack)
                def fail(*args,**kw):
                    initial=lab.controls.read((top/'results/latest').resolve()/'summary.json')
                    self.assertEqual(initial['status'],'RUNNING')
                    self.assertEqual(initial['invocation']['status'],'not_started')
                    raise lab.LabError('synthetic-key private endpoint', 'missing-secret' if name=='endpoint_secret' else 'fixture-prerequisite')
                stack.enter_context(mock.patch.object(lab,name,side_effect=fail))
                self.assertEqual(lab.run_suite(a),2)
                result=lab.controls.read((top/'results/latest').resolve()/'result.json')
                self.assertEqual(result['status'],'BLOCKED');self.assertTrue(result['sealed'])
                self.assertIsNone(result['workspace']);self.assertIsNone(result['task_result']['score'])
                self.assertNotIn('synthetic-key',json.dumps(result))

    def test_invalid_plan_setup_and_interruption_are_finalized(self):
        for fault in ('plan','setup','cancel'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as td,contextlib.ExitStack() as stack:
                top=Path(td);a=fixture(top);mocked_suite(stack)
                if fault=='plan':Path(a.plan).write_text('{invalid')
                elif fault=='setup':
                    plan=json.loads(Path(a.plan).read_text());plan['setup']=[{'name':'prepare','argv':['false']}];lab.save(Path(a.plan),plan)
                    stack.enter_context(mock.patch.object(lab,'run_stage',side_effect=lambda *arg,**kw:{'exit_code':1 if arg[4].startswith('setup') else 0,'cleanup_confirmed':True}))
                else:stack.enter_context(mock.patch.object(lab,'run_stage',side_effect=KeyboardInterrupt))
                self.assertEqual(lab.run_suite(a),2)
                result=lab.controls.read((top/'results/latest').resolve()/'result.json')
                self.assertEqual(result['status'],'INTERRUPTED' if fault=='cancel' else 'BLOCKED')
                self.assertEqual(result['scoring']['status'],'skipped');self.assertIsNone(result['task_result']['score'])

    def test_unsafe_and_unwritable_output_emit_sanitized_record_without_fallback_writes(self):
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);a=fixture(top);a.results_dir=str(top/'project/evidence')
            error=io.StringIO()
            with contextlib.redirect_stderr(error),mock.patch.object(lab,'load_endpoint') as endpoint:
                self.assertEqual(lab.run_suite(a),2)
            record=json.loads(error.getvalue());self.assertTrue(record['attempt_id'])
            self.assertEqual(record['persistence'],'unavailable');endpoint.assert_not_called()
            self.assertFalse((top/'project/evidence').exists())
            a.results_dir=str(top/'results');error=io.StringIO()
            with mock.patch.object(outcomes.os,'mkdir',side_effect=PermissionError),contextlib.redirect_stderr(error):
                self.assertEqual(lab.run_suite(a),2)
            self.assertEqual(json.loads(error.getvalue())['infrastructure']['reason'],'evidence_destination_unavailable')

    def test_finalization_is_one_way_even_after_memory_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            a=fixture(Path(td));attempt=outcomes.Attempt(a);attempt.fail(lab.LabError('fixture','missing-secret'))
            first=attempt.finalize()
            attempt.record.update(status='PASS');attempt.record['infrastructure']['status']='ready'
            self.assertEqual(attempt.finalize(),first)
            self.assertEqual(lab.controls.read(attempt.root/'result.json'),first)

    def test_timeout_and_cleanup_keep_distinct_cause_dimensions(self):
        with tempfile.TemporaryDirectory() as td:
            attempt=outcomes.Attempt(fixture(Path(td)));attempt.record['infrastructure']['status']='ready';attempt.record['invocation']['status']='invalid'
            attempt.cause('timeout',124);attempt.cause('cleanup_error')
            result=attempt.finalize()
            self.assertEqual(result['status'],'FAIL');self.assertEqual(result['termination']['trigger'],'timeout')
            self.assertEqual(result['termination']['process_exit_code'],124)


class ProtocolTests(unittest.TestCase):
    def analyze(self,events,**kw):
        from evidence import analyze
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'events';path.write_text(''.join(json.dumps(e)+'\n' for e in events))
            return analyze(path,'example/model',[],0,**kw)

    def examples(self,index=0):
        return json.loads((ROOT/'references/pi-0.87.1.examples.json').read_text())['event_examples'][index]['records']

    def test_invalid_order_and_tools_reject(self):
        import copy
        base=self.examples()
        for fault in ('message_end','early_settle','missing_settle','late_work','overlap','duplicate_tool','unpaired_tool','pending_retry','tool_result_shape'):
            with self.subTest(fault=fault):
                ev=copy.deepcopy(base)
                if fault=='message_end':ev=[e for e in ev if e['type']!='message_start']
                elif fault=='early_settle':ev.insert(1,{'type':'agent_settled'})
                elif fault=='missing_settle':ev.pop()
                elif fault=='late_work':ev.append({'type':'turn_start'})
                elif fault=='overlap':ev.insert(3,{'type':'agent_start'})
                elif fault=='duplicate_tool':ev.insert(10,next(e for e in ev if e['type']=='tool_execution_end'))
                elif fault=='unpaired_tool':next(e for e in ev if e['type']=='tool_execution_end')['toolCallId']='forged'
                elif fault=='pending_retry':ev[-2]['willRetry']=True
                else:next(e['message'] for e in ev if e['type']=='message_end' and e['message']['role']=='toolResult')['toolCallId']=[]
                self.assertFalse(self.analyze(ev)['agent_invocation_verified'])

    def test_clean_multiturn_and_authorized_retry_have_distinct_attribution(self):
        clean=self.analyze(self.examples());self.assertTrue(clean['agent_invocation_verified']);self.assertTrue(clean['protocol_valid'])
        retry=self.analyze(self.examples(1),allow_retries=True)
        self.assertTrue(retry['protocol_valid']);self.assertTrue(retry['completion_verified'])
        self.assertEqual(retry['invocation_status'],'recovered');self.assertFalse(retry['agent_invocation_verified'])
        self.assertEqual(retry['unsuccessful_messages'],['error'])
        self.assertFalse(self.analyze(self.examples(1))['completion_verified'])

    def test_metadata_does_not_forge_completion_and_custom_observations_are_allowed(self):
        ev=self.examples();ev.append({'type':'session_info_changed','name':'display'})
        self.assertTrue(self.analyze(ev)['agent_invocation_verified'])
        custom={'role':'custom','customType':'note','content':'metadata'}
        ev=self.examples();ev[-1:-1]=[{'type':'message_start','message':custom},{'type':'message_end','message':custom}]
        self.assertTrue(self.analyze(ev)['agent_invocation_verified'])
        ev=self.examples();ev.append({'type':'queue_update','steering':['pending'],'followUp':[]})
        self.assertFalse(self.analyze(ev)['agent_invocation_verified'])

    def test_legacy_is_explicit_and_cannot_weaken_pinned_release(self):
        ev=self.examples()[:-1]
        self.assertTrue(self.analyze(ev,completion_contract='process-exit')['agent_invocation_verified'])
        self.assertFalse(self.analyze(ev,completion_contract='process-exit',release='0.87.1')['agent_invocation_verified'])
        self.assertFalse(self.analyze(ev)['agent_invocation_verified'])


class ScorerTests(unittest.TestCase):
    def contract(self,top):
        import scoring
        source=top/'score.py';source.write_text('print("fixture")')
        return scoring.validate({'schema':1,'id':'fixture','version':'1','assets':[{'source':str(source),'target':'score.py'}],
            'score_domain':{'min':0,'max':1,'direction':'higher','pass_threshold':1},
            'required_assertions':['oracle'],'zero_test_policy':'fail','all_skipped_policy':'fail'},top)

    def data(self):
        return {'schema':1,'scorer_id':'fixture','scorer_version':'1','run_id':'run','attempt_id':'attempt',
                'task_status':'pass','score':1,'test_counts':{'discovered':1,'passed':1,'failed':0,'skipped':0},
                'assertions':[{'id':'oracle','passed':True}]}

    def test_valid_failed_partial_zero_and_skipped_results(self):
        import scoring
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);contract=self.contract(top);receipt=scoring.freeze(contract,top/'frozen')
            for mode in ('pass','fail','partial','zero','skipped'):
                data=self.data();declared=dict(contract)
                if mode=='fail':data.update(task_status='fail',score=0);data['assertions'][0]['passed']=False
                elif mode=='partial':declared['allow_partial']=True;data.update(task_status='partial',assertions=[])
                elif mode in ('zero','skipped'):
                    data['test_counts']={'discovered':0 if mode=='zero' else 1,'passed':0,'failed':0,'skipped':0 if mode=='zero' else 1};data['task_status']='fail'
                result=scoring.evaluate(declared,receipt,{'exit_code':0,'cleanup_confirmed':True},json.dumps(data),'run','attempt')
                self.assertEqual(result['status'],'completed',result);self.assertEqual(result['task_status'],data['task_status'])

    def test_malformed_missing_wrong_identity_domain_and_nonzero_are_errors(self):
        import scoring
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);contract=self.contract(top);receipt=scoring.freeze(contract,top/'frozen')
            for fault in ('missing','malformed','identity','domain','nan','assertions','nonzero'):
                data=self.data();code=0
                if fault=='identity':data['scorer_id']='unreviewed'
                elif fault=='domain':data['score']=2
                elif fault=='nan':data['score']=float('nan')
                elif fault=='assertions':data['assertions']=[]
                elif fault=='nonzero':code=1
                text='' if fault=='missing' else ('invalid' if fault=='malformed' else json.dumps(data))
                result=scoring.evaluate(contract,receipt,{'exit_code':code,'cleanup_confirmed':True},text,'run','attempt')
                self.assertEqual(result['status'],'error');self.assertIsNone(result['score'])

    def test_frozen_assets_are_independent_and_mutation_attempts_fail(self):
        import scoring
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);contract=self.contract(top);receipt=scoring.freeze(contract,top/'frozen')
            (top/'score.py').write_text('agent changed source')
            self.assertTrue(scoring.assets_unchanged(receipt))
            (top/'frozen/score.py').chmod(0o644);(top/'frozen/score.py').write_text('corrupted')
            result=scoring.evaluate(contract,receipt,{'exit_code':0,'cleanup_confirmed':True},json.dumps(self.data()),'run','attempt')
            self.assertEqual(result['reason'],'scorer_assets_changed')
            from test_controls import args
            argv=lab.docker_args(args(),'fixture',top/'subject',top/'controls',top/'state','n','none',key=False)
            self.assertIn('PI_LAB_API_KEY=',argv)

    def test_real_scorer_subprocess_and_command_only_unknown_metrics(self):
        import scoring,subprocess
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);contract=self.contract(top);data=self.data()
            (top/'score.py').write_text('import json\nprint('+repr(json.dumps(data))+')\n')
            receipt=scoring.freeze(contract,top/'frozen')
            process=subprocess.run([sys.executable,str(top/'frozen/score.py')],capture_output=True,text=True,timeout=5,env={'PATH':os.environ['PATH']})
            result=scoring.evaluate(contract,receipt,{'exit_code':process.returncode,'cleanup_confirmed':True},process.stdout,'run','attempt')
            self.assertEqual(result['task_status'],'pass')
            result=scoring.evaluate(None,None,{'exit_code':0,'cleanup_confirmed':True},'unstructured stdout','run','attempt')
            self.assertEqual(result['task_status'],'pass');self.assertIsNone(result['score']);self.assertIsNone(result['test_counts'])

    def test_narrow_readonly_mount_and_key_free_scorer_execution(self):
        from test_controls import args
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);subject=top/'subject';subject.mkdir();run=top/'run';run.mkdir();assets=top/'assets';assets.mkdir()
            with mock.patch.object(lab,'stream_run',return_value={'exit_code':0,'cleanup_confirmed':True}) as stream:
                lab.run_stage(args(),'fixture',run,subject,'score',['check'],task={'argv':['true'],'timeout_seconds':5},access='ro',network='none',scorer_assets={'root':str(assets)})
            argv=stream.call_args.args[0]
            self.assertIn(f'type=bind,src={assets},dst=/opt/pi-scorer,readonly,bind-recursive=disabled',argv)
            self.assertIn('PI_LAB_API_KEY=',argv);self.assertIn('none',argv)


class SegmentTests(unittest.TestCase):
    def trace(self,session,abort=False,model='fixture-model'):
        from test_lab import events,final_event
        ev=events();ev[0]['id']=session
        for event in ev:
            for msg in [event.get('message'),*event.get('messages',[])]:
                if isinstance(msg,dict) and msg.get('role')=='assistant':msg['model']=model
        final_event(ev)['message']['usage']={'totalTokens':5}
        if abort:final_event(ev)['message']['stopReason']='aborted'
        return ev

    def run_chain(self,top,fault=None,multiple=False):
        from test_controls import args
        import time
        run=top/'run';run.mkdir();workspace=top/'subject';workspace.mkdir()
        a=args(event_contract='settled',lock_file=str(top/'lease'))
        task={'name':'dev','prompt':'fixture','tools':['read'],'require_tools':['read'],'max_turns':10,'max_total_tokens':1000,'timeout_seconds':5}
        endpoint={'model':'fixture-model'};calls=[]
        def fake(argv,logs,timeout,name,secret='',stage=None,keep_budget=False,resume_budget=False,**kw):
            desc=stage[1];state=lab.controls.resolve(run,desc['stage_id'])[1];segment_id=state['segment_id']
            control=Path(desc['control'])/'segments'/segment_id
            data=lab.controls.read(control/'task.json');calls.append(data)
            if not resume_budget:lab.controls.start_budget(run,desc,time.monotonic(),.1)
            else:lab.controls.publish_budget(run,desc,lab.controls.read(lab.controls.budget_path(run,desc)))
            logs.mkdir(parents=True)
            trace=self.trace(data['session_id'],abort=len(calls)==1,model='wrong' if fault=='model' and len(calls)>1 else 'fixture-model')
            if fault=='session' and len(calls)>1:trace[0]['id']='unrelated'
            (logs/'stdout.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in trace));(logs/'stderr.log').write_text('')
            runtime=next(x.split('src=',1)[1].split(',dst=',1)[0] for x in argv if 'dst=/pi-state,' in x)
            sessions=Path(runtime)/'sessions';sessions.mkdir(exist_ok=True)
            if fault!='missing_session':(sessions/'session.jsonl').write_text(json.dumps(trace[0])+'\n')
            result={'exit_code':130 if len(calls)==1 else 0,'cleanup_confirmed':True,'started':True}
            if len(calls)==1:
                for index in range(2 if multiple else 1):
                    lab.cmd_steer(args(run=str(run),stage=desc['stage_id'],message='continue '+str(index),interrupt=True))
                directives=lab.segments.pending(run,desc,segment_id,set())
                if fault=='forged_ack':
                    folder=Path(desc['outbox'])/'acks';folder.mkdir(exist_ok=True)
                    lab.save(folder/(directives[0]['id']+'.json'),{**directives[0],'status':'applied'})
                if fault not in ('unrequested','forged_ack'):result['interrupts_applied']=[d['id'] for d in directives]
                lab.cmd_extend_budget(args(run=str(run),stage=desc['stage_id'],turns=None,tokens=None,timeout='+2'))
                lab.controls.process_budget_requests(run,desc)
            return result
        with mock.patch.object(lab,'stream_run',side_effect=fake):
            result=lab.run_stage(a,'fixture',run,workspace,'agent',['agent'],task=task,endpoint=endpoint)
        return result,calls,run

    def test_authorized_recovery_uses_exact_session_and_cumulative_budgets(self):
        with tempfile.TemporaryDirectory() as td:
            result,calls,run=self.run_chain(Path(td))
            self.assertEqual(result['evidence']['invocation_status'],'recovered',result['evidence'])
            self.assertFalse(result['evidence']['agent_invocation_verified'])
            self.assertEqual(len(result['segments']),2)
            first,last=result['segments'];self.assertEqual(last['continues_segment_id'],first['segment_id'])
            self.assertEqual(last['session_id'],first['session_id']);self.assertTrue(last['session_sha256'])
            self.assertEqual(calls[1]['prior_turns'],2);self.assertEqual(calls[1]['prior_reported_tokens'],5)
            budget=lab.controls.read(run/'stages'/first['stage_id']/'budget.json')
            self.assertEqual(budget['revision'],1);self.assertEqual(budget['effective_limits']['timeout_seconds'],7)
            self.assertEqual(budget['deadline_host_monotonic']-budget['started_host_monotonic'],7)
            self.assertEqual(first['evidence']['unsuccessful_messages'],['aborted'])

    def test_unrequested_abort_wrong_model_and_unrelated_session_cannot_recover(self):
        for fault in ('unrequested','forged_ack','model','session','missing_session'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as td:
                result,_,_=self.run_chain(Path(td),fault=fault)
                self.assertFalse(result['evidence']['completion_verified'])

    def test_multiple_directives_are_preserved_and_consumed_once(self):
        with tempfile.TemporaryDirectory() as td:
            result,calls,run=self.run_chain(Path(td),multiple=True)
            self.assertEqual(len(calls),3);self.assertEqual(len(result['segments']),3)
            self.assertEqual(len({s['command_id'] for s in result['segments'][1:]}),2)
            self.assertTrue(result['evidence']['completion_verified'],result['evidence'])

    def test_exact_session_snapshot_rejects_aliases_and_unrelated_context(self):
        import segments
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);runtime=top/'state';runtime.mkdir();(runtime/'sessions').mkdir();sentinel=top/'sentinel';sentinel.write_text('safe')
            (runtime/'sessions/a.jsonl').symlink_to(sentinel)
            with self.assertRaises((OSError,ValueError,lab.controls.ControlError)):segments.freeze_session(runtime,'id','/workspace','m',top/'snapshot')
            self.assertEqual(sentinel.read_text(),'safe')

    def test_parent_interrupt_receipt_is_real_process_control_not_child_ack(self):
        import threading,time
        from test_controls import args,prepare
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);run,desc=prepare(top,limits={'max_turns':10,'timeout_seconds':3,'max_total_tokens':1000});result={}
            code='import signal,time,sys; signal.signal(signal.SIGUSR1,lambda s,f:sys.exit(130)); time.sleep(5)'
            thread=threading.Thread(target=lambda:result.update(lab.stream_run([sys.executable,'-c',code],top/'logs',3,'surrogate',stage=(run,desc))))
            thread.start();time.sleep(.25)
            lab.cmd_steer(args(run=str(run),stage=desc['stage_id'],message='interrupt',interrupt=True))
            thread.join(timeout=4)
            self.assertFalse(thread.is_alive());self.assertEqual(result['termination_reason'],'interrupted')
            self.assertEqual(len(result['interrupts_applied']),1);self.assertTrue(result['cleanup_confirmed'])

    def test_explicit_cancellation_never_starts_a_successor(self):
        from test_controls import args
        import time
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);run=top/'run';run.mkdir();workspace=top/'subject';workspace.mkdir();calls=[]
            a=args(event_contract='settled',lock_file=str(top/'lease'))
            task={'name':'dev','prompt':'fixture','tools':['read'],'require_tools':['read'],'max_turns':10,'max_total_tokens':1000,'timeout_seconds':3}
            def cancel(argv,logs,timeout,name,secret='',stage=None,**kw):
                calls.append(1);desc=stage[1];lab.controls.start_budget(run,desc,time.monotonic())
                logs.mkdir(parents=True);lab.save(logs/'process.json',{'exit_code':130,'started':True,'cancelled':True,'cleanup_confirmed':True})
                lab.cmd_steer(args(run=str(run),stage=desc['stage_id'],message='queued',interrupt=True))
                raise KeyboardInterrupt
            with mock.patch.object(lab,'stream_run',side_effect=cancel):
                with self.assertRaises(KeyboardInterrupt):lab.run_stage(a,'fixture',run,workspace,'agent',['agent'],task=task,endpoint={'model':'fixture-model'})
            self.assertEqual(len(calls),1)
            self.assertEqual(lab.controls.read(run/'agent/process.json')['segments'][0]['process']['cancelled'],True)


class FailureScoringTests(unittest.TestCase):
    def scenario(self,top,failure='timeout',cleanup=True,cancel_at=None,post_cancel=False):
        import scoring
        a=fixture(top);a.score_after_cancel=post_cancel
        source=top/'scorer.py';source.write_text('print("reviewed fixture")')
        contract={'schema':1,'id':'artifact','version':'1','assets':[{'source':str(source),'target':'score.py'}],
                  'score_domain':{'min':0,'max':1,'direction':'higher','pass_threshold':1},'required_assertions':['answer'],
                  'zero_test_policy':'fail','all_skipped_policy':'fail'}
        plan=json.loads(Path(a.plan).read_text());plan['agents'].append({'name':'dependent','prompt':'must not run'})
        plan['checks']=[{'name':'one','argv':['true'],'scorer':contract},{'name':'two','argv':['true'],'scorer':contract}]
        lab.save(Path(a.plan),plan);calls=[]
        def fake_stage(args,image,run,workspace,label,operation,**kw):
            calls.append(label);folder=run/label;folder.mkdir()
            if label.startswith('agent'):
                (workspace/'answer.txt').write_text('42')
                if failure=='missing_workspace':
                    import shutil
                    shutil.rmtree(workspace)
                if cancel_at=='agent':
                    from test_controls import prepare
                    # Parent-owned interrupted stage receipt, using the same attempt identity.
                    import uuid
                    stage_id=str(uuid.uuid4());control=run/'controls'/stage_id;control.mkdir(parents=True);lab.control_channels(control,os.getuid())
                    state=lab.state_dir(run/'children',stage_id,os.getuid())
                    desc=lab.controls.create(run,workspace,label,'agent',kw['task'],control,state,stage_id,'fixture')
                    lab.controls.transition(run,desc,'running')
                    lab.save(folder/'process.json',{'exit_code':130,'started':True,'cancelled':True,'cleanup_confirmed':True})
                    raise KeyboardInterrupt
                return {'exit_code':124 if failure in ('timeout','token_limit') else 1 if failure=='nonzero' else 0,
                        'termination_reason':failure if failure in ('timeout','token_limit') else ('process_error' if failure=='nonzero' else 'completed'),
                        'cleanup_confirmed':cleanup}
            if label.startswith('check'):
                if cancel_at=='scorer':raise KeyboardInterrupt
                identity=lab.controls.read(run/'identity.json')
                data={'schema':1,'scorer_id':'artifact','scorer_version':'1','run_id':identity['run_id'],'attempt_id':identity['attempt_id'],
                      'task_status':'pass','score':1,'test_counts':None,'assertions':[{'id':'answer','passed':True}]}
                (folder/'stdout.jsonl').write_text('invalid' if failure=='scorer_error' and label.endswith('one') else json.dumps(data))
                self.assertEqual((workspace/'answer.txt').read_text(),'42')
                return {'exit_code':0,'cleanup_confirmed':True}
            return {'exit_code':0,'cleanup_confirmed':True}
        with contextlib.ExitStack() as stack:
            mocked_suite(stack)
            stack.enter_context(mock.patch.object(lab,'run_stage',side_effect=fake_stage))
            stack.enter_context(mock.patch.object(lab,'analyze',return_value={'agent_invocation_verified':False,'completion_verified':False,'invocation_status':'invalid','errors':['synthetic failure'],'final_text':''}))
            code=lab.run_suite(a)
        return code,lab.controls.read((top/'results/latest').resolve()/'result.json'),calls

    def test_timeout_token_nonzero_and_invalid_evidence_still_receive_scores(self):
        for failure in ('timeout','token_limit','nonzero','invalid'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as td:
                code,result,calls=self.scenario(Path(td),failure)
                self.assertEqual(code,1);self.assertEqual(result['status'],'FAIL')
                self.assertEqual(result['invocation']['status'],'invalid')
                self.assertEqual(result['scoring']['status'],'completed');self.assertEqual(result['task_result']['status'],'pass')
                self.assertEqual([r['score'] for r in result['scoring']['results']],[1,1])
                self.assertNotIn('agent-2-dependent',calls)

    def test_unknown_cleanup_skips_all_scorers_and_workspace_inspection(self):
        with tempfile.TemporaryDirectory() as td:
            code,result,calls=self.scenario(Path(td),cleanup=False)
            self.assertEqual(code,1);self.assertEqual(result['scoring']['reason'],'cleanup_unconfirmed')
            self.assertFalse(any(c.startswith('check') for c in calls))
            self.assertEqual(result['protected_inputs']['status'],'unknown');self.assertIsNone(result['task_result']['score'])

    def test_all_scorer_results_retained_after_one_error(self):
        with tempfile.TemporaryDirectory() as td:
            _,result,calls=self.scenario(Path(td),'scorer_error')
            self.assertEqual([r['status'] for r in result['scoring']['results']],['error','completed'])
            self.assertEqual(len(result['checks']),2);self.assertEqual(result['scoring']['status'],'error')

    def test_cancellation_policy_and_active_scorer_cancellation_are_distinct(self):
        for when,authorised in [('agent',False),('agent',True),('scorer',False)]:
            with self.subTest(when=when,authorised=authorised),tempfile.TemporaryDirectory() as td:
                code,result,calls=self.scenario(Path(td),cancel_at=when,post_cancel=authorised)
                self.assertEqual(code,2);self.assertEqual(result['status'],'INTERRUPTED')
                if when=='agent' and authorised:self.assertEqual(result['scoring']['status'],'completed')
                else:self.assertEqual(result['scoring']['status'],'cancelled' if when=='scorer' else 'skipped')
                if when=='agent' and not authorised:self.assertFalse(any(c.startswith('check') for c in calls))

    def test_missing_workspace_is_explicitly_unscorable(self):
        with tempfile.TemporaryDirectory() as td:
            _,result,calls=self.scenario(Path(td),'missing_workspace')
            self.assertEqual(result['scoring']['status'],'skipped')
            self.assertEqual(result['scoring']['reason'],'workspace_missing')
            self.assertIsNone(result['task_result']['score'])
            self.assertFalse(any(c.startswith('check') for c in calls))


class CapabilityTests(unittest.TestCase):
    def test_access_network_and_writable_locations_follow_effective_configuration(self):
        sys.path.insert(0,str(ROOT/'runtime'));import worker
        for access,network in [('ro','none'),('rw','bridge')]:
            env={'PI_LAB_STAGE_ACCESS':access,'PI_LAB_NETWORK_MODE':network,'PI_LAB_ROOT_READONLY':'1',
                 'PI_LAB_RUNTIME_PATH':'/pi-state','TMPDIR':'/pi-state/tmp','PI_OFFLINE':'1','CONTAINER_ARCH':'linux/arm64'}
            with self.subTest(access=access,network=network),mock.patch.dict(os.environ,env,clear=True):
                facts=worker.capability_facts({'tools':['read','bash']},'/workspace/service')
                self.assertEqual(facts['workspace']['access'],access)
                self.assertEqual('/workspace' in facts['writable_locations'],access=='rw')
                self.assertIn('/pi-state',facts['writable_locations']);self.assertIn('/opt/pi-control/outbox',facts['writable_locations'])
                self.assertEqual(facts['network']['mode'],network);self.assertTrue(facts['pi_startup_network_disabled'])
                self.assertEqual(facts['network']['external_routing'],'disabled' if network=='none' else 'unverified')
                self.assertEqual(facts['pi_tools'],['read','bash'])
                self.assertEqual(facts['temporary_directory'],'/pi-state/tmp')
                self.assertIn('not a shell parser',facts['bash_guard'])

    def test_unknown_facts_and_startup_offline_are_not_fabricated(self):
        import worker
        with mock.patch.dict(os.environ,{},clear=True),mock.patch.object(worker.shutil,'which',return_value=None),mock.patch.object(worker,'chromium_path',side_effect=RuntimeError):
            facts=worker.capability_facts({},'/workspace')
            self.assertEqual(facts['workspace']['access'],'unknown');self.assertEqual(facts['network']['mode'],'unknown')
            self.assertIsNone(facts['configured_root_read_only']);self.assertEqual(facts['writable_locations'],[])
            self.assertFalse(facts['pi_startup_network_disabled']);self.assertEqual(facts['available_commands'],[])

    def test_docker_env_and_setup_next_actions_match_public_contract(self):
        from test_controls import args
        import lab_env
        argv=lab.docker_args(args(),'fixture',Path('/tmp/subject'),Path('/tmp/control'),Path('/tmp/state'),'n','none','ro')
        self.assertIn('PI_LAB_STAGE_ACCESS=ro',argv);self.assertIn('PI_LAB_NETWORK_MODE=none',argv)
        self.assertIn('PI_LAB_ROOT_READONLY=1',argv)
        with mock.patch.object(lab_env,'resolve_session',return_value='fixture'),mock.patch.object(lab_env,'load_saved',return_value=None):
            report=lab_env.evaluate('fixture',check=False)
        self.assertIn('base URL only',report['next']);self.assertIn('PI_API_KEY',report['next'])
        self.assertNotIn('key variable,',report['next'])

    def test_protected_hashing_records_ancestor_links_without_reading_external_files(self):
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);workspace=top/'subject';workspace.mkdir();outside=top/'outside';outside.mkdir()
            (outside/'oracle.py').write_text('host data');(workspace/'tests').symlink_to(outside)
            hashes=lab.protected_hashes(workspace,['tests/oracle.py'])
            self.assertEqual(hashes['tests/oracle.py']['linked_component'],'tests')
            self.assertNotIn('host data',json.dumps(hashes))
