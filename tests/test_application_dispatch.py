"""Actual compiled preparation/snapshot/outcomes with mocked execution boundaries.

No Docker, helper, Pi, model, network or scorer process is executed. Report
absence is diagnosed by the real independent completion evaluator on real files.
"""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_completion as completion
import application_contracts as c
import application_dispatch as dispatch
import application_runtime_contracts
import application_preparation
import lab_env
import native_budget_controls
import outcomes
import pi_lab as lab
import secret_store
import test_application_preparation as preparation_fixture

APP_KEY='disposable-dispatch-application-key-123456'
MODEL_KEY='disposable-dispatch-inference-key-123456'


class DispatchTests(unittest.TestCase):
    def setUp(self):
        fixture=preparation_fixture.PreparationTests(methodName='runTest');fixture.setUp()
        self.addCleanup(fixture.doCleanups);self.fixture=fixture;self.root=fixture.root
        self.project=self.root/'project';self.project.mkdir();(self.project/'original.txt').write_text('unchanged original\n')
        self.store=self.root/'store'
        self.reference=next(iter(fixture.source['application']['credentials'].values()))
        secret_store.write_secret(self.reference,APP_KEY,self.store)
        secret_store.write_secret(fixture.endpoint['api_key_env'],MODEL_KEY,self.store)
        self.calls=[];self.tasks=[];self.score_calls=0;self.compiled=None
        self.omit_segments=False;self.recovered=False;self.cancelled=False;self.complete=False
        self.authority_inputs=[];self.produced_outputs={}
        self.stack=mock.patch.multiple(lab_env,evaluate=mock.Mock(return_value={'state':'ready'}),
            load_saved=mock.Mock(side_effect=lambda:(lab.normalize_endpoint(self.fixture.endpoint),{})))
        self.stack.start();self.addCleanup(self.stack.stop)
        self.host=mock.patch.object(lab,'require_host',side_effect=self.require_host).start()
        self.addCleanup(mock.patch.stopall)
        self.probe=mock.patch.object(lab,'probe_image',side_effect=lambda args,image:copy.deepcopy(self.fixture.runtime)).start()
        mock.patch.object(lab,'run_stage',side_effect=self.stage).start()
        self.score=mock.patch.object(lab,'score_artifacts',side_effect=self.score_boundary).start()
        self.legacy_validation=mock.patch.object(lab,'validate_plan',side_effect=AssertionError('Compiled IR must bypass legacy normalization')).start()

    def build(self):
        self.compiled=self.fixture.compile()
        return self.compiled

    def attempt(self):
        if self.compiled is None:self.build()
        args=lab.parser().parse_args(['run','--project',str(self.project),'--results-dir',str(self.root/'runs'),
            '--lock-file',str(self.root/'lease'),'--secrets-dir',str(self.store),'--session','fixture'])
        args.compiled_plan=str(Path(self.compiled['root'])/'plan.json');args._explicit_options=()
        return args,outcomes.Attempt(args)

    def require_host(self,args):
        args.native_platform='linux/arm64'
        args.resource_report={'effective':copy.deepcopy(args._application_plan['runtime']['resources'])}
        return {'native_platform':'linux/arm64','scope':'mocked host admission'}

    def stage(self,args,image,run,workspace,label,operation,**kwargs):
        self.calls.append((label,operation))
        if operation[0]!='agent':return {'exit_code':0,'cleanup_confirmed':True}
        stageid=args._application_execution['stage_id'];stage=next(row for row in args._application_plan['stages'] if row['id']==stageid)
        self.authority_inputs.append((stageid,copy.deepcopy(args._application_execution['authority']._sealed_inputs)))
        task=copy.deepcopy(kwargs['task']);self.tasks.append((task,copy.deepcopy(kwargs)))
        self.assertEqual(task['prompt'],stage['effective_prompt'])
        self.assertEqual(task['tools'],stage['tools']);self.assertEqual(task['tool_schemas'],stage['tool_schemas'])
        self.assertEqual(task['application_execution']['profile_binding'],stage['profile_binding'])
        self.assertEqual(task['application_execution']['plan_sha256'],args._application_plan['plan_sha256'])
        self.assertEqual(task['application_execution']['stage_id'],stageid)
        self.assertEqual(task['application_execution']['effective_prompt_sha256'],hashlib.sha256(task['prompt'].encode()).hexdigest())
        self.assertEqual(task['application_execution']['tool_schema_sha256'],c.digest(sorted(stage['tool_schemas'],key=lambda row:row['name'])))
        self.assertNotIn('application_context',task,'coordinator must issue the private segment context later')
        self.assertNotIn('native_budget_context',task)
        self.assertEqual((kwargs['access'],args.platform,args.profile),('ro','linux/arm64',args._application_plan['runtime']['container_profile']))
        self.assertEqual(image,args._application_plan['runtime']['image_id'])
        self.assertEqual(args._resource_request,args._application_plan['runtime']['resources'])
        outputs=run/('stopped-outputs-'+stageid);outputs.mkdir(mode=0o700)
        evidence_root=run/('private-evidence-'+stageid);evidence_root.mkdir(mode=0o700)
        binding={key:str(uuid.uuid4()) for key in ('run_id','attempt_id','stage_id','segment_id','session_id')}
        binding.update(run_id=outcomes_record(run)['run_id'],attempt_id=outcomes_record(run)['attempt_id'],trial_id=None,
            plan_sha256=args._application_plan['plan_sha256'],profile_sha256=stage['profile_binding']['sha256'],
            pi_release=args.observed_pi_version,release_contract_sha256=application_runtime_contracts.identity(args.observed_pi_version)['sha256'],
            report_contract_sha256=c.digest(stage['completion']))
        context={'binding':binding,'authorized_segment_ids':[binding['segment_id']],
            'report_root':str(outputs),'evidence_root':str(evidence_root),'parent_receipts':{}}
        counts={name:0 for name in native_budget_controls.COUNTER_FIELDS}
        maximum=stage['limits']['max_tool_calls'];reserve=stage['limits']['reporting_reserve_calls']
        budget={'schema':1,'document_type':'native_tool_budget_status','phase':'business','accounting':'available',
            'limits':{key:stage['limits'][key] for key in native_budget_controls.NATIVE_FIELDS},'counts':counts,
            'per_tool':{name:copy.deepcopy(counts) for name in [*stage['tools'],'__unknown__']},
            'remaining_calls':maximum,'remaining_admissible_calls':maximum,'business_calls_remaining':maximum-reserve,
            'reporting_reserve_calls_remaining':reserve,'assisted':False}
        process={'exit_code':0,'cleanup_confirmed':True,'termination_reason':'completed',
            'application_helper_cleanup':{'schema':1,'status':'removed','workspace':'clean','safe_to_continue':True},
            'application_credentials':{'schema':1,'status':'removed','workspace':'clean'},
            'application_completion_context':context,'native_tool_manifest':{'schema':1,'tools':stage['tools']},
            'native_tool_budget':budget,'evidence':{'agent_invocation_verified':True,'completion_verified':True,
                'invocation_status':'verified','errors':[],'final_text':'controlled participant settled'},
            'segments':[{'evidence':{'agent_profile':{'loading':'observed'}}}]}
        if self.omit_segments:process['segments']=[]
        if self.recovered:process['evidence'].update(agent_invocation_verified=False,invocation_status='recovered')
        if self.cancelled:
            process.update(cancelled=True,exit_code=130,termination_reason='cancelled')
            report=outputs/stage['completion']['report_path'];report.parent.mkdir(parents=True)
            report.write_text('Cancelled unreviewed report: never read or copy this output.\n')
        if self.complete:self.complete_journal(stage,context)
        process['application_completion']=completion.stage_result(stage,context,process,process['application_credentials'])['projection']
        expected='not_evaluated' if self.cancelled else 'complete' if self.complete else 'incomplete'
        self.assertEqual(process['application_completion']['status'],expected,process['application_completion'])
        if not self.cancelled and not self.complete:self.assertIn({'code':'report_missing','count':1},process['application_completion']['diagnostics'])
        return process

    def complete_journal(self,stage,context):
        """Synthetic stored application journal, independently checked from bytes.

        The receipt/evidence template is an explicit fixture, not an HTTP/Pi
        observation. Real stage_result validates its bound hashes and report.
        """
        template=c.loads((ROOT/'tests/fixtures/application-contracts/completion.json').read_bytes())
        identity=copy.deepcopy(template['receipts'][0])
        identity['binding']=copy.deepcopy(context['binding']);identity['participant']=copy.deepcopy(stage['participant'])
        evidence_root=Path(context['evidence_root']);outputs=Path(context['report_root'])
        for evidence in identity['evidence']:
            body=template['stored_evidence'][evidence['path']].encode()
            if evidence['kind']=='response':self.assertEqual(c.loads(body),stage['participant'])
            path=evidence_root/evidence['path'];path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            path.write_bytes(body)
            evidence.update(sha256=hashlib.sha256(body).hexdigest(),bytes=len(body))
        c.validate_receipt(identity)
        path=evidence_root/'receipts/identity.json';path.parent.mkdir(mode=0o700)
        body=c.canonical(identity);path.write_bytes(body)
        context['parent_receipts'][identity['receipt_id']]={'path':'receipts/identity.json','sha256':hashlib.sha256(body).hexdigest()}
        report=copy.deepcopy(template['report'])
        report.update(contract_id=stage['completion']['id'],participant=copy.deepcopy(stage['participant']),
                      artifacts=[],pagination={},publications=[],unresolved=[])
        for artifact in stage['completion']['artifacts']:
            body=('# Controlled sealed artifact '+stage['id']+'/'+artifact['id']+'\n').encode()
            path=outputs/artifact['path'];path.parent.mkdir(parents=True,exist_ok=True,mode=0o700);path.write_bytes(body)
            self.produced_outputs[(stage['id'],artifact['id'])]=body
            report['artifacts'].append({'id':artifact['id'],'path':artifact['path'],
                'sha256':hashlib.sha256(body).hexdigest(),'bytes':len(body)})
        c.validate_report(report)
        path=outputs/stage['completion']['report_path'];path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        path.write_bytes(c.canonical(report))

    def complete_two_stage_source(self,with_input=False):
        self.complete=True
        self.fixture.source['application']['operations']=[operation for operation in self.fixture.source['application']['operations']
                                                         if operation['effect']=='identity']
        first=self.fixture.source['stages'][0];first['operations']=['identity']
        first['completion'].update(pagination=[],publications=[])
        extra=copy.deepcopy(first['completion']['artifacts'][0]);extra.update(id='unconsumed-note',path='outputs/unconsumed.md')
        first['completion']['artifacts'].append(extra)
        second=copy.deepcopy(first);second.update(id='reviewer',depends_on=[first['id']],input_artifacts=[])
        second['completion'].update(id='review-report',report_path='review/completion.json')
        second['completion']['artifacts']=[{**copy.deepcopy(first['completion']['artifacts'][0]),
                                           'id':'review-output','path':'review/summary.md'}]
        if with_input:second['input_artifacts']=[{'stage_id':first['id'],'artifact_id':first['completion']['artifacts'][0]['id']}]
        self.fixture.source['stages'].append(second)
        self.fixture.write('source.json',self.fixture.source)

    def score_boundary(self,args,attempt,plan,image,workspace,receipts,**kwargs):
        self.score_calls+=1
        self.assertTrue(receipts,'actual frozen independent scorer assets must reach the scoring boundary')
        self.assertEqual((Path(workspace)/'original.txt').read_text(),'unchanged original\n')
        attempt.record['scoring'].update(status='completed',reason=None)
        attempt.record['task_result'].update(status='pass',score=1)
        attempt.record['protected_inputs'].update(status='unchanged')

    def run_dispatch(self,args=None,attempt=None):
        if args is None:args,attempt=self.attempt()
        dispatch.prepare(args,attempt,lab);dispatch.execute(args,attempt,lab)
        return attempt.finalize(),args,attempt

    def test_verified_settlement_passing_task_missing_report_is_fail_without_repair_or_continuation(self):
        record,args,attempt=self.run_dispatch()
        self.assertEqual((record['status'],record['exit_code']),('FAIL',1))
        self.assertEqual(record['invocation']['status'],'verified')
        self.assertEqual((record['scoring']['status'],record['task_result']['status']),('completed','pass'))
        self.assertIn({'code':'report_missing','count':1},record['application_completion']['stages'][0]['diagnostics'])
        self.assertEqual(len(self.tasks),1);self.assertEqual(self.score_calls,1)
        self.assertEqual([operation[0] for _,operation in self.calls],['boundary','preflight','agent'])
        self.assertFalse(list(attempt.root.rglob('completion.json')))
        self.assertEqual((self.project/'original.txt').read_text(),'unchanged original\n')
        self.legacy_validation.assert_not_called()
        self.assertNotIn(APP_KEY,json.dumps(record));self.assertNotIn(MODEL_KEY,json.dumps(record))

    def check_long_stage(self, length):
        self.complete_two_stage_source()
        self.fixture.source['stages'] = self.fixture.source['stages'][:1]
        name = 's' * length
        self.fixture.source['stages'][0]['id'] = name
        self.fixture.write('source.json', self.fixture.source)
        record, _, _ = self.run_dispatch()
        self.assertEqual(record['status'], 'PASS', record)
        self.assertEqual(len(self.tasks), 1)
        self.assertEqual(self.score_calls, 1)
        self.assertEqual(record['native_tool_budgets']['stages'][0]['stage'], name)

    def test_52_character_compiled_stage_reaches_scoring_and_finalization(self):
        self.check_long_stage(52)

    def test_64_character_compiled_stage_reaches_scoring_and_finalization(self):
        self.check_long_stage(64)

    def test_report_failure_blocks_dependent_and_unrelated_successors_without_second_business_stage(self):
        original=self.fixture.source['stages'][0]
        for name,dependencies in [('dependent',[original['id']]),('unrelated',[])]:
            stage=copy.deepcopy(original);stage['id']=name;stage['depends_on']=dependencies
            stage['completion']['id']=name+'-report';stage['completion']['report_path']=name+'/completion.json'
            stage['completion']['artifacts'][0]['path']=name+'/summary.md'
            self.fixture.source['stages'].append(stage)
        self.fixture.write('source.json',self.fixture.source)
        record,_,_=self.run_dispatch()
        self.assertEqual(len(self.tasks),1)
        stages={stage['stage']:stage['status'] for stage in record['application_completion']['stages']}
        self.assertEqual(stages,{'participant':'incomplete','dependent':'dependency_blocked','unrelated':'prior_failure'})
        self.assertEqual(record['status'],'FAIL')

    def test_missing_or_colliding_application_credential_rejects_before_host_and_probe(self):
        for fault in ('missing','collision'):
            with self.subTest(fault=fault):
                if self.compiled is None:self.build()
                args,attempt=self.attempt()
                path=self.store/self.reference
                if fault=='missing':path.unlink()
                else:secret_store.write_secret(self.reference,MODEL_KEY,self.store)
                with self.assertRaises(ValueError):dispatch.prepare(args,attempt,lab)
                self.host.assert_not_called();self.probe.assert_not_called();self.assertEqual(self.calls,[])
                secret_store.write_secret(self.reference,APP_KEY,self.store)

    def test_rotated_credential_between_prepare_and_execute_rejects_before_host(self):
        args,attempt=self.attempt();dispatch.prepare(args,attempt,lab)
        secret_store.write_secret(self.reference,'rotated-disposable-application-key-98765',self.store)
        with self.assertRaises(ValueError):dispatch.execute(args,attempt,lab)
        self.host.assert_not_called();self.probe.assert_not_called();self.assertEqual(self.calls,[])

    def test_compiled_tamper_and_explicit_runtime_override_reject_zero_execution_effects(self):
        self.build();args,attempt=self.attempt();args._explicit_options={'--image'}
        with self.assertRaises(ValueError):dispatch.prepare(args,attempt,lab)
        args,attempt=self.attempt();plan=Path(args.compiled_plan);plan.chmod(0o600);plan.write_bytes(plan.read_bytes()+b' ')
        with self.assertRaises(ValueError):dispatch.prepare(args,attempt,lab)
        self.host.assert_not_called();self.probe.assert_not_called();self.assertEqual(self.calls,[])

    def test_user_group_and_host_gateway_overrides_are_not_compiled_runtime_inputs(self):
        self.build()
        for flag,field,value in [('--uid','uid',0),('--gid','gid',0),('--host-gateway','host_gateway',True)]:
            args,attempt=self.attempt();args._explicit_options={flag};setattr(args,field,value)
            with self.subTest(flag=flag),self.assertRaises(ValueError):dispatch.prepare(args,attempt,lab)
        self.host.assert_not_called();self.probe.assert_not_called();self.assertEqual(self.calls,[])

    def test_empty_segment_list_cannot_claim_observed_profile_loading(self):
        self.omit_segments=True
        record,_,_=self.run_dispatch()
        self.assertEqual(record['agent_profile']['loading'],'unverified')
        self.assertEqual(record['status'],'FAIL')

    def test_explicit_recovery_status_survives_independent_report_failure(self):
        self.recovered=True
        record,_,_=self.run_dispatch()
        self.assertEqual(record['invocation']['status'],'recovered')
        self.assertEqual((record['status'],record['exit_code']),('FAIL',1))
        self.assertEqual(record['application_completion']['stages'][0]['status'],'incomplete')

    def test_attempt_frozen_copy_runs_after_original_inputs_and_artifact_disappear(self):
        args,attempt=self.attempt();dispatch.prepare(args,attempt,lab)
        shutil.rmtree(self.fixture.inputs);shutil.rmtree(self.compiled['root'])
        self.assertTrue((attempt.root/'compiled/plan.json').is_file())
        dispatch.execute(args,attempt,lab);record=attempt.finalize()
        self.assertEqual(record['invocation']['status'],'verified');self.assertEqual(record['status'],'FAIL')
        self.assertEqual(len(self.tasks),1)

    def test_runtime_copy_must_match_prepared_runner_before_keys_or_probes(self):
        args,attempt=self.attempt();freeze=lab.trusted_runtime
        def changed(root):
            runtime=freeze(root)
            target=runtime/'worker.py';target.chmod(0o600)
            target.write_bytes(target.read_bytes()+b'\n# changed frozen runtime\n')
            return runtime
        with mock.patch.object(lab,'trusted_runtime',side_effect=changed), \
             mock.patch.object(lab,'endpoint_secret',side_effect=AssertionError('No keys after runtime mismatch')) as keys:
            with self.assertRaisesRegex(ValueError,'Frozen runtime'):dispatch.prepare(args,attempt,lab)
        keys.assert_not_called();self.host.assert_not_called();self.probe.assert_not_called()
        lab_env.evaluate.assert_not_called();self.assertEqual(self.calls,[])

    def test_cancelled_clean_process_never_reads_report_or_copies_stopped_outputs(self):
        self.cancelled=True
        with mock.patch.object(dispatch,'_copy_outputs',side_effect=AssertionError('Cancelled outputs must never be copied')) as copy_outputs, \
             mock.patch.object(completion.completion_contract,'evaluate',side_effect=AssertionError('Cancelled report must never be read')) as report_reader:
            record,args,attempt=self.run_dispatch()
        copy_outputs.assert_not_called();report_reader.assert_not_called()
        self.assertEqual(record['application_completion']['stages'][0]['status'],'not_evaluated')
        self.assertEqual(record['application_completion']['stages'][0]['diagnostics'],[{'code':'stage_not_evaluated','count':1}])
        self.assertEqual((record['status'],record['exit_code']),('INTERRUPTED',2))
        self.assertFalse((attempt.root/'workspace'/self.fixture.source['stages'][0]['completion']['report_path']).exists())
        self.assertEqual(len(self.tasks),1)

    def test_known_application_key_in_original_project_rejects_before_copy_host_and_probe(self):
        args,attempt=self.attempt()
        (self.project/'.env').write_text('PRIVATE_TEST_KEY='+APP_KEY+'\n')
        original={str(path.relative_to(self.project)):path.read_bytes() for path in self.project.rglob('*') if path.is_file()}
        with mock.patch.object(lab,'snapshot',side_effect=AssertionError('Sensitive source must never be copied')) as snapshot:
            with self.assertRaises(ValueError):dispatch.prepare(args,attempt,lab)
        snapshot.assert_not_called();self.host.assert_not_called();self.probe.assert_not_called()
        self.assertEqual(self.calls,[])
        self.assertFalse((attempt.root/'workspace').exists())
        self.assertEqual({str(path.relative_to(self.project)):path.read_bytes() for path in self.project.rglob('*') if path.is_file()},original)

    def test_independently_valid_artifact_swap_during_copy_cannot_replace_first_selection(self):
        first=self.build();args,attempt=self.attempt()
        self.fixture.source['name']='independently-valid-replacement'
        self.fixture.write('source.json',self.fixture.source)
        second=self.fixture.compile('replacement')
        self.assertNotEqual(first['plan']['plan_sha256'],second['plan']['plan_sha256'])
        self.assertEqual(set(first['manifest']['files']),set(second['manifest']['files']))
        self.assertEqual(application_preparation.load_compiled(Path(second['root'])/'plan.json',verify_runner=True)['plan'],second['plan'])
        source=Path(first['root']);replacement=Path(second['root']);retired=self.root/'retired-first-selection'
        real_read=dispatch.agent_profiles.read_asset;swapped=[]
        def replace_on_first_copy(path,*arguments,**kwargs):
            if not swapped and Path(path).is_relative_to(source):
                source.rename(retired);shutil.copytree(replacement,source);swapped.append(True)
            return real_read(path,*arguments,**kwargs)
        with mock.patch.object(dispatch.agent_profiles,'read_asset',side_effect=replace_on_first_copy), \
             mock.patch.object(lab,'endpoint_secret',side_effect=AssertionError('No key resolution after swapped selection')) as key_resolver:
            with self.assertRaises(ValueError):dispatch.prepare(args,attempt,lab)
        self.assertEqual(swapped,[True]);key_resolver.assert_not_called()
        lab_env.evaluate.assert_not_called();self.host.assert_not_called();self.probe.assert_not_called()
        self.assertEqual(self.calls,[])
        self.assertEqual(application_preparation.load_compiled(source/'plan.json')['plan'],second['plan'])
        self.assertEqual(application_preparation.load_compiled(retired/'plan.json')['plan'],first['plan'])

    def test_complete_stages_without_input_grants_do_not_cache_unconsumed_outputs_as_helper_inputs(self):
        self.complete_two_stage_source()
        record,args,attempt=self.run_dispatch()
        self.assertEqual((record['status'],record['exit_code']),('PASS',0))
        self.assertEqual(len(self.tasks),2)
        self.assertEqual([row['status'] for row in record['application_completion']['stages']],['complete','complete'])
        self.assertEqual(self.authority_inputs,[('participant',[]),('reviewer',[])])
        for stage in args._application_plan['stages']:
            for artifact in stage['completion']['artifacts']:
                self.assertEqual((attempt.root/'workspace'/artifact['path']).read_bytes(),self.produced_outputs[(stage['id'],artifact['id'])])
        self.assertEqual(self.score_calls,1)

    def test_declared_predecessor_input_preserves_exact_sealed_bytes_without_extra_scorer_outputs(self):
        self.complete_two_stage_source(with_input=True)
        record,args,attempt=self.run_dispatch()
        self.assertEqual((record['status'],record['exit_code']),('PASS',0))
        self.assertEqual(len(self.tasks),2)
        self.assertEqual([row['status'] for row in record['application_completion']['stages']],['complete','complete'])
        self.assertEqual(self.authority_inputs[0],('participant',[]))
        name,inputs=self.authority_inputs[1];self.assertEqual(name,'reviewer')
        self.assertEqual(len(inputs),1)
        body=self.produced_outputs[('participant','summary')]
        self.assertEqual(inputs,[{'stage_id':'participant','artifact_id':'summary','content':body.decode(),
            'sha256':hashlib.sha256(body).hexdigest(),'bytes':len(body),'media_type':'text/markdown'}])
        self.assertEqual((attempt.root/'workspace/outputs/unconsumed.md').read_bytes(),self.produced_outputs[('participant','unconsumed-note')])
        self.assertEqual(self.score_calls,1)


def outcomes_record(run):return c.loads((Path(run)/'identity.json').read_bytes())


if __name__=='__main__':unittest.main()
