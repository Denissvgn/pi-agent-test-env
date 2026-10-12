"""Application experiment tests. Protocol/process fixtures never qualify a live model."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT=(Path(__file__).resolve().parents[1] / 'skill')
sys.path.insert(0,str(ROOT/'scripts'))
import experiments
import pi_lab as lab


class ExperimentFixture(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        (self.root/'project').mkdir();(self.root/'project/app.py').write_text('value=0\n')
        (self.root/'scorer.py').write_text('print("synthetic schema fixture only")\n')
        self.endpoint={'base_url':'http://example.invalid/v1','model':'fixture-model','api_key_env':'TEST_KEY','context_window':32768,'max_tokens':1024}
        self.write('endpoint.json',self.endpoint);self.write('resources.json',{'schema':1,'runtime':{'cpus':1,'memory':'128m','pids_limit':64,'jobs':1}})
        self.plan={'schema':1,'agents':[{'name':'dev','prompt':'Read app.py, implement the requested change.','tools':['read','write'],'require_tools':['read']}],
                   'checks':[{'name':'score','argv':['python3','/opt/pi-scorer/scorer.py'],'scorer':{'schema':1,'id':'fixture','version':'1',
                              'assets':[{'source':'scorer.py','target':'scorer.py'}],'score_domain':{'min':0,'max':1,'direction':'higher','pass_threshold':1},
                              'required_assertions':['value'],'zero_test_policy':'fail','all_skipped_policy':'fail'}}]}
        self.write('plan.json',self.plan)
        self.definition={'schema':1,'name':'fixture','baseline':'baseline','repetitions':2,
            'cases':[{'name':'case','project':'project','plan':'plan.json'}],
            'variants':[{'name':'baseline'},{'name':'candidate','prompt_suffix':'Check edge cases before editing.'}],
            'budgets':{'timeout_seconds':4,'max_turns':3,'max_total_tokens':10000},
            'execution':{'image':'sha256:'+'a'*64,'platform':'linux/arm64','resources':'resources.json'},
            'policies':{'primary_attempt':'first','assistance':'exclude','on_failure':'continue','max_attempts':2}}
        self.write('experiment.json',self.definition)

    def write(self,name,value):
        p=self.root/name;p.write_text(json.dumps(value,indent=2));return p

    def validate(self,value=None):
        if value is not None:self.write('experiment.json',value)
        return experiments.validate(self.root/'experiment.json',lab,self.root/'endpoint.json')

    def prepare(self,name='prepared'):
        return experiments.prepare(self.root/'experiment.json',self.root/name,lab,self.root/'endpoint.json')


class DefinitionTests(ExperimentFixture):
    def test_browser_policy_identity_is_frozen_and_reaches_trial_dispatch(self):
        import browser_security
        self.definition['execution'].update(profile='browser',browser_sandbox_policy='chromium-userns')
        self.write('experiment.json',self.definition)
        self.prepare()
        metadata,matrix=experiments.verify(self.root/'prepared',lab)
        self.assertEqual(metadata['execution']['browser_security']['sha256'],browser_security.SHA256)
        args=experiments.trial_args(self.root/'prepared',metadata,matrix['cells'][0],lab,None)
        self.assertEqual(args.profile,'browser');self.assertEqual(args.browser_sandbox_policy,'chromium-userns')
        self.definition['execution']['profile']='core'
        with self.assertRaises(ValueError):self.validate(self.definition)

    def test_missing_duplicates_baseline_unsupported_and_invalid_bounds_reject(self):
        invalid=[]
        for field in self.definition:
            value=copy.deepcopy(self.definition);value.pop(field);invalid.append(value)
        for field,value in [('repetitions',True),('repetitions',0),('repetitions',11),('schema',True),('baseline','absent'),('integration',{})]:
            item=copy.deepcopy(self.definition);item[field]=value;invalid.append(item)
        for field in ('cases','variants'):
            value=copy.deepcopy(self.definition);value[field].append(copy.deepcopy(value[field][0]));invalid.append(value)
        for field in self.definition['budgets']:
            value=copy.deepcopy(self.definition);value['budgets'][field]=0;invalid.append(value)
        for value in invalid:
            with self.subTest(value=value),self.assertRaises((experiments.ExperimentError,lab.LabError)):self.validate(value)

    def test_input_scorer_policy_and_variant_override_validation(self):
        for field,value in [('project','missing'),('plan','missing'),('project',None)]:
            item=copy.deepcopy(self.definition);item['cases'][0][field]=value
            with self.subTest(field=field),self.assertRaises((ValueError,OSError)):self.validate(item)
        item=copy.deepcopy(self.definition);item['variants'][1]['plan']='other.json'
        with self.assertRaises(ValueError):self.validate(item)
        item=copy.deepcopy(self.definition);item['policies']['primary_attempt']='best'
        with self.assertRaises(ValueError):self.validate(item)
        self.write('experiment.json',self.definition)
        bad=copy.deepcopy(self.plan);bad['checks'][0]['scorer']['score_domain']['max']=0
        self.write('plan.json',bad)
        with self.assertRaises(ValueError):self.validate()
        bad=copy.deepcopy(self.plan);bad['checks'][0].pop('scorer');self.write('plan.json',bad)
        with self.assertRaises(ValueError):self.validate()

    def test_materializes_entire_stable_uuid_matrix_and_frozen_key_free_inputs(self):
        receipt=self.prepare();self.assertEqual(receipt['planned'],4)
        metadata,matrix=experiments.verify(self.root/'prepared',lab)
        self.assertEqual(len({x['trial_id'] for x in matrix['cells']}),4)
        self.assertTrue(all(x['initial_status']=='planned' for x in matrix['cells']))
        self.assertTrue(all(x['configuration_digest'] for x in matrix['cells']))
        self.assertEqual(matrix,experiments.verify(self.root/'prepared',lab)[1])
        for cell in matrix['cells']:
            self.assertTrue((self.root/'prepared'/cell['source']/'app.py').is_file())
            planpath=self.root/'prepared'/cell['plan'];plan=lab.validate_plan(json.loads(planpath.read_text()),planpath.parent)
            self.assertEqual(plan['agents'][0]['timeout_seconds'],4)
            self.assertTrue(Path(plan['checks'][0]['scorer']['assets'][0]['source']).is_file())
        digests={x['variant']:x['configuration_digest'] for x in matrix['cells']}
        self.assertNotEqual(digests['baseline'],digests['candidate'])
        self.assertEqual(metadata['profile'],'builtin-only')
        self.assertFalse((self.root/'prepared'/'runs').exists())

    def test_frozen_tampering_destination_reuse_and_project_alias_reject(self):
        self.prepare()
        with self.assertRaisesRegex(ValueError,'already exists'):self.prepare()
        with self.assertRaisesRegex(ValueError,'outside'):experiments.prepare(self.root/'experiment.json',self.root/'project'/'evidence',lab,self.root/'endpoint.json')
        (self.root/'alias').symlink_to(self.root/'project',target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'outside'):experiments.prepare(self.root/'experiment.json',self.root/'alias'/'evidence',lab,self.root/'endpoint.json')
        (self.root/'prepared/inputs/sources/case/app.py').write_text('changed')
        with self.assertRaisesRegex(ValueError,'changed'):experiments.verify(self.root/'prepared',lab)

    def test_scorer_change_between_validation_and_freezing_rejects(self):
        original=experiments.scoring.freeze
        def changing(contract,root):
            (self.root/'scorer.py').write_text('changed oracle')
            return original(contract,root)
        with mock.patch.object(experiments.scoring,'freeze',side_effect=changing),self.assertRaisesRegex(ValueError,'Scorer changed'):self.prepare()
        self.assertFalse((self.root/'prepared').exists())

    def test_source_change_during_freezing_rejects_without_executable_matrix(self):
        original=lab.snapshot
        def changing(*args,**kwargs):
            result=original(*args,**kwargs);(self.root/'project/app.py').write_text('changed');return result
        with mock.patch.object(lab,'snapshot',side_effect=changing),self.assertRaisesRegex(ValueError,'Source changed'):self.prepare()
        self.assertFalse((self.root/'prepared').exists())

import contextlib
import subprocess
import outcomes


class ControlledFixture(ExperimentFixture):
    def controlled_runner(self,observations,failures=None,change_original=False):
        """Real admission, attempt persistence/snapshot and short Python children; synthetic Pi/scorer dimensions."""
        failures=failures or {}
        def run(args,initial_record):
            args.lock_file=str(self.root/'fixture-core.lock')
            def body(a,attempt,smoke):
                record=attempt.record;index=len(observations)
                cell=next(x for x in experiments.verify(self.root/'prepared',lab)[1]['cells'] if x['trial_id']==record['trial_id'])
                intents=experiments.attempt_intents(self.root/'prepared',cell)
                self.assertEqual(intents[-1]['attempt_id'],record['attempt_id'])
                self.assertTrue((attempt.root/'summary.json').exists())
                workspace=attempt.root/'workspace';lab.snapshot(Path(a.project),workspace,[],10)
                record['workspace']=str(workspace);record['fixture_origin']='synthetic controller fixture, not live Pi'
                observations.append({'trial_id':record['trial_id'],'workspace':str(workspace),'initial':(workspace/'app.py').read_text()})
                if change_original and index==0:(self.root/'project/app.py').write_text('value=999\n')
                kind=failures.get(index)
                if kind=='setup':
                    record['infrastructure']['phase']='setup';raise lab.LabError('Synthetic setup failure','fixture_setup')
                # The real stream_run uses explicit cwd in the Python script instead of a host cwd option.
                result=lab.stream_run([sys.executable,'-c',"from pathlib import Path; p=Path(__import__('sys').argv[1]); assert p.read_text()=='value=0\\n'; p.write_text('value=1\\n')",str(workspace/'app.py')],attempt.root/'fixture-stage-one',2,'fixture-one')
                result2=lab.stream_run([sys.executable,'-c',"from pathlib import Path; assert Path(__import__('sys').argv[1]).read_text()=='value=1\\n'",str(workspace/'app.py')],attempt.root/'fixture-stage-two',2,'fixture-two')
                self.assertEqual(result['exit_code'],0);self.assertEqual(result2['exit_code'],0)
                record['agents']=[{'name':'synthetic-two-stage','process':result2}]
                record['infrastructure'].update(status='ready',phase='agents')
                record['invocation'].update(status='invalid' if kind=='invocation' else 'verified',attempted_stages=2)
                record['termination'].update(reason='completed',process_exit_code=0)
                record['protected_inputs']['status']='unchanged'
                record['scoring'].update(status='error' if kind=='scorer' else 'completed')
                record['task_result'].update(status='unknown' if kind=='scorer' else 'pass',score=None if kind=='scorer' else 1)
                if kind=='cleanup':record['termination']['reason']='cleanup_error';record['agents'][0]['process']['cleanup_confirmed']=False
            with mock.patch.object(lab,'_execute_suite',side_effect=body):return lab.run_suite(args,initial_record=initial_record)
        return run


class ExecutionTests(ControlledFixture):
    def test_trials_reset_and_stage_sharing_reuse_existing_runner_records(self):
        self.prepare();observations=[]
        result=experiments.execute(self.root/'prepared',lab,runner=self.controlled_runner(observations,change_original=True))
        self.assertEqual(result['status'],'completed');self.assertEqual(len(observations),4)
        self.assertEqual(len({x['workspace'] for x in observations}),4)
        self.assertTrue(all(x['initial']=='value=0\n' for x in observations))
        metadata,matrix=experiments.verify(self.root/'prepared',lab)
        for cell in matrix['cells']:
            intent=experiments.attempt_intents(self.root/'prepared',cell)[0]
            record=experiments.sealed_result(self.root/'prepared',intent)
            self.assertEqual(record['experiment_id'],metadata['experiment_id']);self.assertEqual(record['trial_id'],cell['trial_id'])
            self.assertEqual(record['attempt_index'],1);self.assertIsNone(record['retry_of_attempt_id'])
        with self.assertRaisesRegex(ValueError,'silently repeat'):experiments.execute(self.root/'prepared',lab,runner=self.controlled_runner([]))

    def test_first_middle_failures_retain_and_execute_later_planned_cells(self):
        self.definition['repetitions']=3;self.write('experiment.json',self.definition);self.prepare();observations=[]
        result=experiments.execute(self.root/'prepared',lab,runner=self.controlled_runner(observations,{0:'setup',2:'invocation',3:'scorer'}))
        self.assertEqual(result['planned'],6);self.assertEqual(result['completed_this_call'],6)
        matrix=experiments.verify(self.root/'prepared',lab)[1]
        statuses=[experiments.sealed_result(self.root/'prepared',experiments.attempt_intents(self.root/'prepared',cell)[0])['status'] for cell in matrix['cells']]
        self.assertEqual(statuses,['BLOCKED','PASS','FAIL','FAIL','PASS','PASS'])

    def test_stop_and_unknown_cleanup_keep_unexecuted_cells(self):
        for on_failure,kind,status in [('stop','invocation','halted'),('continue','cleanup','blocked')]:
            self.definition['policies']['on_failure']=on_failure;self.write('experiment.json',self.definition)
            name='prepared';self.prepare(name);observations=[]
            result=experiments.execute(self.root/name,lab,runner=self.controlled_runner(observations,{0:kind}))
            self.assertEqual(result['status'],status);self.assertEqual(len(observations),1)
            matrix=experiments.verify(self.root/name,lab)[1]
            self.assertEqual(len(matrix['cells']),4)
            self.assertEqual(sum(bool(experiments.attempt_intents(self.root/name,c)) for c in matrix['cells']),1)
            import shutil;shutil.rmtree(self.root/name)

    def test_linked_destination_is_rejected_before_host_lease_write(self):
        (self.root/'unrelated').mkdir();(self.root/'alias').symlink_to(self.root/'unrelated')
        with self.assertRaises(ValueError):experiments.execute(self.root/'alias',lab,runner=lambda *a,**k:None)
        self.assertFalse((self.root/'unrelated/controller.lock').exists())

    def test_changed_confirmed_environment_rejects_before_any_trial(self):
        with mock.patch.object(experiments.lab_env,'endpoint_path',return_value=self.root/'endpoint.json'):
            experiments.prepare(self.root/'experiment.json',self.root/'prepared',lab)
        changed={**self.endpoint,'model':'other-model'};self.write('changed.json',changed)
        with mock.patch.object(experiments.platform,'machine',return_value='arm64'),mock.patch.object(experiments.lab_env,'require_ready',return_value=self.root/'changed.json'),mock.patch.object(lab,'run_suite') as run:
            with self.assertRaisesRegex(ValueError,'differs from frozen'):experiments.execute(self.root/'prepared',lab,session='synthetic-session')
            run.assert_not_called()
        matrix=experiments.verify(self.root/'prepared',lab)[1]
        self.assertTrue(all(not experiments.attempt_intents(self.root/'prepared',cell) for cell in matrix['cells']))

import signal
import time


class ResumeTests(ControlledFixture):
    def test_hard_kill_resume_and_explicit_retry_preserve_original_attempts(self):
        self.prepare()
        script=self.root/'crash-controller.py'
        script.write_text('''import sys,time,json
from pathlib import Path
from unittest import mock
sys.path.insert(0,sys.argv[1]);sys.path.insert(0,sys.argv[2])
from test_experiments import ExecutionTests
import experiments,pi_lab as lab
case=ExecutionTests();case.root=Path(sys.argv[3]);observations=[]
base=case.controlled_runner(observations)
def runner(args,initial_record):
 if len(observations)!=1:return base(args,initial_record)
 args.lock_file=str(case.root/'fixture-core.lock')
 def sleeping(args,attempt,smoke):
  workspace=attempt.root/'workspace';lab.snapshot(Path(args.project),workspace,[],10)
  attempt.record['fixture_origin']='synthetic controller crash, no Docker/Pi'
  attempt.record['workspace']=str(workspace)
  attempt.record['infrastructure'].update(status='ready',phase='agents')
  attempt.record['invocation'].update(status='invalid',attempted_stages=1)
  attempt.persist();(case.root/'crash-ready').write_text(attempt.record['attempt_id'])
  time.sleep(30)
 with mock.patch.object(lab,'_execute_suite',side_effect=sleeping):return lab.run_suite(args,initial_record=initial_record)
experiments.execute(case.root/'prepared',lab,runner=runner)
''')
        with (self.root/'controller-log').open('w') as output:
            process=subprocess.Popen([sys.executable,str(script),str(Path(__file__).resolve().parent),str(ROOT/'scripts'),str(self.root)],stdout=output,stderr=output)
            self.addCleanup(lambda:process.kill() if process.poll() is None else None)
            deadline=time.monotonic()+8
            while not (self.root/'crash-ready').exists() and process.poll() is None and time.monotonic()<deadline:time.sleep(0.02)
            self.assertTrue((self.root/'crash-ready').exists(),(self.root/'controller-log').read_text())
            with self.assertRaisesRegex(ValueError,'Another controller'):experiments.execute(self.root/'prepared',lab,resume=True,runner=self.controlled_runner([]))
            process.kill();process.wait(timeout=5)
        matrix=experiments.verify(self.root/'prepared',lab)[1]
        first_intent=experiments.attempt_intents(self.root/'prepared',matrix['cells'][0])[0]
        first_path=self.root/'prepared/runs'/first_intent['run_id']/'result.json';first_bytes=first_path.read_bytes()
        observations=[]
        with mock.patch.object(lab,'default_lock_file',return_value=str(self.root/'fixture-core.lock')):
            result=experiments.execute(self.root/'prepared',lab,resume=True,runner=self.controlled_runner(observations))
        self.assertEqual(result['completed_this_call'],2);self.assertEqual(first_path.read_bytes(),first_bytes)
        second=experiments.attempt_intents(self.root/'prepared',matrix['cells'][1])[0]
        failed=experiments.sealed_result(self.root/'prepared',second)
        self.assertEqual(failed['status'],'FAIL');self.assertEqual(failed['termination']['trigger'],'controller_lost')
        self.assertIsNone(failed['task_result']['score']);self.assertTrue(failed['controller_interruption']['cleanup_confirmed'])
        second_path=self.root/'prepared/runs'/second['run_id']/'result.json';old_bytes=second_path.read_bytes()
        observations=[]
        experiments.execute(self.root/'prepared',lab,resume=True,retry_trial=matrix['cells'][1]['trial_id'],runner=self.controlled_runner(observations))
        self.assertEqual(len(observations),1);self.assertEqual(second_path.read_bytes(),old_bytes)
        attempts=experiments.attempt_intents(self.root/'prepared',matrix['cells'][1])
        self.assertEqual(len(attempts),2);self.assertEqual(attempts[1]['retry_of_attempt_id'],attempts[0]['attempt_id'])
        self.assertNotEqual(attempts[1]['run_id'],attempts[0]['run_id']);self.assertEqual(experiments.sealed_result(self.root/'prepared',attempts[1])['status'],'PASS')
        rows=experiments.ledger_rows(self.root/'prepared',lab);self.assertEqual(rows[1]['primary_attempt_id'],attempts[0]['attempt_id'])
        a=experiments.export_ledger(self.root/'prepared',lab);b=experiments.export_ledger(self.root/'prepared',lab)
        self.assertEqual(a,b);self.assertEqual(len((self.root/'prepared/trials.jsonl').read_text().splitlines()),4)
        with self.assertRaisesRegex(ValueError,'Retry requires'):experiments.execute(self.root/'prepared',lab,resume=True,retry_trial=matrix['cells'][1]['trial_id'],runner=self.controlled_runner([]))
        final=experiments.execute(self.root/'prepared',lab,resume=True,runner=self.controlled_runner([]))
        self.assertEqual(final['completed_this_call'],0)

    def test_incomplete_final_write_is_preserved_and_pending_work_resumes(self):
        self.prepare();metadata,matrix=experiments.verify(self.root/'prepared',lab);cell=matrix['cells'][0]
        intent,path=experiments.reserve_attempt(self.root/'prepared',metadata,cell)
        args=experiments.trial_args(self.root/'prepared',metadata,cell,lab,None)
        attempt=outcomes.Attempt(args,intent['initial_record']);attempt.record['probe_receipt_contract']=1;attempt.persist()
        (attempt.root/'result.json').write_text('{"interrupted":')
        with mock.patch.object(lab,'default_lock_file',return_value=str(self.root/'fixture-core.lock')):
            result=experiments.execute(self.root/'prepared',lab,resume=True,runner=self.controlled_runner([]))
        self.assertEqual(result['completed_this_call'],3)
        record=experiments.sealed_result(self.root/'prepared',experiments.attempt_intents(self.root/'prepared',cell)[0])
        archived=self.root/'prepared'/record['controller_interruption']['incomplete_result']['path']
        self.assertEqual(archived.read_text(),'{"interrupted":');self.assertIsNone(record['task_result']['score'])
        (self.root/'prepared/inputs/endpoints/baseline.json').chmod(0o600)
        (self.root/'prepared/inputs/endpoints/baseline.json').write_text('{}')
        with self.assertRaisesRegex(ValueError,'changed'):experiments.execute(self.root/'prepared',lab,resume=True,runner=self.controlled_runner([]))

    def test_docker_cleanup_requires_matched_parent_control_mount_and_image(self):
        self.prepare();metadata,matrix=experiments.verify(self.root/'prepared',lab);cell=matrix['cells'][0]
        intent,_=experiments.reserve_attempt(self.root/'prepared',metadata,cell)
        args=experiments.trial_args(self.root/'prepared',metadata,cell,lab,None);attempt=outcomes.Attempt(args,intent['initial_record'])
        import uuid
        stage=str(uuid.uuid4());folder=attempt.root/'stages'/stage;folder.mkdir(parents=True)
        control=attempt.root/'controls'/stage;control.mkdir(parents=True)
        desc={'run_id':intent['run_id'],'attempt_id':intent['attempt_id'],'stage_id':stage,'control':str(control),'container':'pi-lab-123456789abc'}
        lab.save(folder/'descriptor.json',desc);lab.save(folder/'state.json',{'status':'running','cleanup_confirmed':False})
        wrong=mock.Mock(return_value=type('Reply',(),{'returncode':0,'stdout':'[]\nwrong-image\n','stderr':''})())
        with mock.patch.object(lab,'default_lock_file',return_value=str(self.root/'fixture-core.lock')),mock.patch.object(lab,'command',wrong):
            with self.assertRaisesRegex(ValueError,'ownership'):experiments.cleanup_owned(self.root/'prepared',intent,metadata,lab)
        self.assertEqual(wrong.call_count,1)
        replies=[type('Reply',(),{'returncode':0,'stdout':json.dumps([{'Destination':'/opt/pi-control','Source':str(control),'RW':False}])+'\n'+metadata['execution']['image']+'\n','stderr':''})(),
                 type('Reply',(),{'returncode':0,'stdout':'removed','stderr':''})(),type('Reply',(),{'returncode':1,'stdout':'','stderr':'No such container'})()]
        with mock.patch.object(lab,'default_lock_file',return_value=str(self.root/'fixture-core.lock')),mock.patch.object(lab,'command',side_effect=replies) as command:
            observation=experiments.cleanup_owned(self.root/'prepared',intent,metadata,lab)
        self.assertEqual(observation[0]['cleanup'],'matched_removed_and_absent')
        self.assertEqual(command.call_args_list[1].args[0],['docker','rm','--force',desc['container']])

    def test_missing_primary_or_changed_sealed_result_rejects_resume(self):
        self.prepare();experiments.execute(self.root/'prepared',lab,runner=self.controlled_runner([]))
        cell=experiments.verify(self.root/'prepared',lab)[1]['cells'][0]
        intent=experiments.attempt_intents(self.root/'prepared',cell)[0]
        path=self.root/'prepared/runs'/intent['run_id']/'result.json'
        original=path.read_bytes();value=json.loads(original);value['task_result']['score']=0.5;path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError,'changed'):experiments.execute(self.root/'prepared',lab,resume=True,runner=self.controlled_runner([]))
        path.write_text('{')
        with self.assertRaisesRegex(ValueError,'corrupted'):experiments.execute(self.root/'prepared',lab,resume=True,runner=self.controlled_runner([]))
        path.unlink()
        with self.assertRaisesRegex(ValueError,'missing'):experiments.execute(self.root/'prepared',lab,resume=True,runner=self.controlled_runner([]))
        path.write_bytes(original)
        parent=self.root/'prepared/attempts'/cell['trial_id'];p=next(parent.glob('*.json'));bad=json.loads(p.read_text());bad['attempt_index']=2;bad['retry_of_attempt_id']='missing-primary';p.write_text(json.dumps(bad))
        with self.assertRaisesRegex(ValueError,'Missing primary'):experiments.execute(self.root/'prepared',lab,resume=True,runner=self.controlled_runner([]))

    def test_known_cancel_before_runner_creation_is_not_rewritten_as_crash(self):
        self.prepare();metadata,matrix=experiments.verify(self.root/'prepared',lab);cell=matrix['cells'][0]
        intent,_=experiments.reserve_attempt(self.root/'prepared',metadata,cell)
        lab.save(self.root/'prepared/state.json',{'schema':1,'status':'interrupted','active_attempt_id':intent['attempt_id'],'interruption_kind':'explicit_controller_cancel'})
        with mock.patch.object(lab,'default_lock_file',return_value=str(self.root/'fixture-core.lock')):
            experiments.execute(self.root/'prepared',lab,resume=True,runner=self.controlled_runner([]))
        record=experiments.sealed_result(self.root/'prepared',experiments.attempt_intents(self.root/'prepared',cell)[0])
        self.assertEqual(record['status'],'INTERRUPTED');self.assertEqual(record['termination']['reason'],'cancelled')
        self.assertEqual(record['controller_interruption']['kind'],'explicit_controller_cancel')
        self.assertEqual(record['scoring']['reason'],'user_cancelled');self.assertIsNone(record['task_result']['score'])

    def test_changed_runner_rejects_resume_before_reconciliation(self):
        self.prepare()
        original=experiments.provenance.execution
        def changed(*args,**kwargs):
            result=original(*args,**kwargs);result['runner_content_sha256']='changed';return result
        with mock.patch.object(experiments.provenance,'execution',side_effect=changed),self.assertRaisesRegex(ValueError,'Runner content changed'):
            experiments.execute(self.root/'prepared',lab,resume=True,runner=self.controlled_runner([]))

    def test_report_covers_all_planned_cells_and_is_byte_deterministic(self):
        self.prepare()
        args=lab.parser().parse_args(['experiment-report','--experiment',str(self.root/'prepared')])
        import io
        with contextlib.redirect_stdout(io.StringIO()):experiments.command(args,lab)
        original=(self.root/'prepared/comparison.json').read_bytes();markdown=(self.root/'prepared/comparison.md').read_bytes()
        report=json.loads(original);self.assertEqual(report['counts_totals']['planned'],4);self.assertEqual(report['counts_totals']['started'],0)
        self.assertEqual(report['counts_totals']['unscorable'],4)
        with contextlib.redirect_stdout(io.StringIO()):experiments.command(args,lab)
        self.assertEqual((self.root/'prepared/comparison.json').read_bytes(),original)
        self.assertEqual((self.root/'prepared/comparison.md').read_bytes(),markdown)


class ProbePersistenceTests(ExperimentFixture):
    def test_probe_identity_is_durable_before_launch_and_cleanup_survives_interrupt(self):
        import uuid
        args=lab.parser().parse_args(['run','--platform','linux/arm64'])
        args._attempt_root=self.root/'probe-owner';args._attempt_root.mkdir()
        args._attempt_identity={'run_id':str(uuid.uuid4()),'attempt_id':str(uuid.uuid4())}
        def interrupted(argv,logs,timeout,name):
            receipt=experiments.read_json(next((args._attempt_root/'image-probes').glob('*.json')))
            self.assertEqual(receipt['container'],name);self.assertEqual(receipt['run_id'],args._attempt_identity['run_id']);self.assertIsNone(receipt['process'])
            logs.mkdir();lab.save(logs/'process.json',{'exit_code':130,'cleanup_confirmed':True})
            raise KeyboardInterrupt
        with mock.patch.object(lab.Path,'home',return_value=self.root),mock.patch.object(lab,'image_info',return_value={'id':'sha256:'+'a'*64}),mock.patch.object(lab,'docker_args',return_value=['synthetic-probe']),mock.patch.object(lab,'stream_run',side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):lab.probe_image(args,'fixture')
        receipt=experiments.read_json(next((args._attempt_root/'image-probes').glob('*.json')))
        self.assertTrue(receipt['process']['cleanup_confirmed']);self.assertEqual(receipt['process']['exit_code'],130)
