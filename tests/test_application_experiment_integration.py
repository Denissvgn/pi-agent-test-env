"""Shared experiment -> actual compiled dispatcher; mocked host/participant/scorer.

No Docker, helper, Pi, model, browser, network or scorer process is executed.
Stored completion journals are explicit fixtures checked by the real evaluator.
"""
import copy
import contextlib
import hashlib
import json
import os
from pathlib import Path
import sys
import io
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_contracts as c
import application_experiments
import application_preparation
import agent_profiles
import comparisons
import experiments
import outcomes
import pi_lab as lab
import provenance
import resources
import test_application_dispatch as dispatch_fixture
import test_application_experiments as experiment_fixture
import test_native_budget_controls as budget_fixture
import native_budget_controls


class ApplicationExperimentIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.engine=dispatch_fixture.DispatchTests(methodName='runTest');self.engine.setUp();self.addCleanup(self.engine.doCleanups)
        self.fixture=self.engine.fixture;self.root=self.engine.root
        self.engine.complete_two_stage_source(with_input=True)
        self.fixture.source['runtime']['inference_owner']='experiment_variant';self.fixture.write('source.json',self.fixture.source)
        policy=copy.deepcopy(resources.DEFAULTS);policy['runtime'].update(cpus=1,memory='1g',pids_limit=64,jobs=1)
        self.fixture.write('resources.json',policy)
        self.definition={'schema':1,'document_type':'application_experiment_source','name':'dispatch-integration','baseline':'baseline','repetitions':1,
            'cases':[{'name':name,'project':str(self.engine.project),'plan':'source.json','runtime_receipt':'runtime.json'} for name in ('first','second')],
            'variants':[{'name':'baseline','endpoint':'endpoint.json'},{'name':'candidate','endpoint':'endpoint.json','prompt_suffix':'EXPLICIT_SUFFIX'}],
            'budgets':copy.deepcopy(self.fixture.source['stages'][0]['limits']),
            'execution':{'image':self.fixture.runtime['id'],'platform':'linux/arm64','resources':'resources.json'},
            'policies':{'primary_attempt':'first','assistance':'exclude','on_failure':'continue','max_attempts':2}}
        self.path=self.fixture.write('experiment.json',self.definition);self.prepared=self.root/'prepared'
        patch=mock.patch.dict(os.environ,{'PI_LAB_SECRETS_DIR':str(self.engine.store)});patch.start();self.addCleanup(patch.stop)
        mock.patch.object(resources,'admission_lock',side_effect=lambda *args,**kwargs:contextlib.nullcontext()).start()
        mock.patch.object(lab,'admission_lock',side_effect=lambda *args,**kwargs:contextlib.nullcontext()).start()
        # Experiment's preliminary image admission precedes dispatcher.prepare.
        def host(args):
            if not hasattr(args,'_application_plan'):args._application_plan=application_preparation.load_compiled(args.compiled_plan)['plan']
            return self.engine.require_host(args)
        self.engine.host.side_effect=host
        self.engine.score.side_effect=self.score
        self.observed=[];original=lab.run_stage.side_effect
        def participant(*args,**kwargs):
            process=original(*args,**kwargs)
            if args[5][0]=='agent':
                task=kwargs['task'];process['segments'][0]['evidence']['agent_profile']['use']='observed'
                self.observed.append((args[0]._application_plan['plan_sha256'],copy.deepcopy(task),copy.deepcopy(args[0]._resource_request)))
            return process
        lab.run_stage.side_effect=participant
        self.legacy=mock.patch.object(agent_profiles,'apply',side_effect=AssertionError('No legacy plan profile application')).start()
        self.addCleanup(mock.patch.stopall)

    def score(self,args,attempt,plan,image,workspace,receipts,**kwargs):
        self.engine.score_boundary(args,attempt,plan,image,workspace,receipts,**kwargs)
        contract=plan['checks'][0]['scorer'];hashes={asset['target']:asset['sha256'] for asset in contract['assets']}
        attempt.record['scoring']['results']=[{'schema':1,'status':'completed','scorer_id':contract['id'],'scorer_version':contract['version'],
            'scorer_sha256':hashlib.sha256(json.dumps(hashes,sort_keys=True).encode()).hexdigest(),'score_domain':contract['score_domain'],
            'score':1,'task_status':'pass'}]

    def prepare(self):
        selected=experiments.validate(self.path,lab)
        self.assertEqual(selected['document_type'],'application_experiment_source')
        experiments.prepare(self.path,self.prepared,lab,session='fixture')
        return experiments.verify(self.prepared,lab)

    def inventory(self,path):return {str(file.relative_to(path)):file.read_bytes() for file in path.rglob('*') if file.is_file()}

    def test_shared_serial_execute_preserves_final_variant_ir_and_readonly_eligible_comparison(self):
        before=self.inventory(self.fixture.inputs);project=self.inventory(self.engine.project)
        metadata,matrix=self.prepare();frozen=self.inventory(self.prepared/'inputs')
        result=experiments.execute(self.prepared,lab,session='fixture')
        self.assertEqual((result['status'],result['completed_this_call']),('completed',4))
        rows=experiments.ledger_rows(self.prepared,lab);self.assertEqual(len(rows),4)
        self.assertEqual(len(self.observed),8)
        for row in rows:
            plan=application_preparation.load_compiled(self.prepared/row['compiled_plan'])['plan']
            result=row['attempts'][0]['result'];self.assertEqual(result['status'],'PASS',result.get('error'))
            self.assertEqual(result['provenance']['plan_sha256'],plan['plan_sha256'])
            tasks=[task for digest,task,policy in self.observed if digest==plan['plan_sha256']]
            self.assertTrue(all(policy==plan['runtime']['resources'] for digest,task,policy in self.observed if digest==plan['plan_sha256']))
            for stage in plan['stages']:
                task=next(task for task in tasks if task['name']==stage['id'])
                self.assertEqual(task['prompt'],stage['effective_prompt']);self.assertEqual(task['tool_schemas'],stage['tool_schemas'])
                self.assertEqual(task['prompt'].count('EXPLICIT_SUFFIX'),int(row['variant']=='candidate'))
                self.assertEqual({key:task[key] for key in stage['limits']},stage['limits'])
            self.assertTrue(all(stage['status']=='complete' for stage in result['application_completion']['stages']))
        expected=comparisons.expected_contracts(self.prepared,metadata,rows,lab)
        snapshot=self.inventory(self.prepared)
        report=comparisons.comparison(metadata,rows,expected)
        self.assertEqual(report['counts_totals']['eligible'],4,report)
        self.assertEqual(report['counts_totals']['successful'],4,report)
        self.assertEqual(report['counts_totals']['planned'],4)
        self.assertEqual(self.inventory(self.prepared),snapshot)
        self.assertEqual(self.inventory(self.prepared/'inputs'),frozen)
        self.assertEqual(self.inventory(self.fixture.inputs),before);self.assertEqual(self.inventory(self.engine.project),project)
        self.engine.legacy_validation.assert_not_called();self.legacy.assert_not_called()
        no_work=experiments.execute(self.prepared,lab,session='fixture',resume=True)
        self.assertEqual(no_work['completed_this_call'],0);self.assertEqual(len(self.observed),8)
        with self.assertRaises(experiments.ExperimentError):experiments.execute(self.prepared,lab,session='fixture')

    def test_normally_settled_passing_task_missing_report_fails_and_resume_retry_keeps_primary(self):
        self.engine.complete=False;metadata,matrix=self.prepare();frozen=self.inventory(self.prepared/'inputs')
        experiments.execute(self.prepared,lab,session='fixture');rows=experiments.ledger_rows(self.prepared,lab)
        self.assertEqual(len(self.observed),4,'only first stage of each case/variant may run')
        primaries={row['trial_id']:row['primary_attempt_id'] for row in rows}
        for row in rows:
            record=row['attempts'][0]['result'];self.assertEqual(record['status'],'FAIL')
            self.assertTrue(record['agents'][0]['process']['evidence']['completion_verified'])
            self.assertEqual(record['task_result']['status'],'pass')
            self.assertEqual(record['application_completion']['stages'][0]['status'],'incomplete')
            self.assertEqual(record['application_completion']['stages'][1]['status'],'dependency_blocked')
        self.engine.complete=True
        experiments.execute(self.prepared,lab,session='fixture',resume=True,retry_trial=rows[0]['trial_id'])
        retried=experiments.ledger_rows(self.prepared,lab)
        self.assertEqual({row['trial_id']:row['primary_attempt_id'] for row in retried},primaries)
        selected=next(row for row in retried if row['trial_id']==rows[0]['trial_id'])
        self.assertEqual([item['result']['status'] for item in selected['attempts']],['FAIL','PASS'])
        report=comparisons.comparison(metadata,retried,comparisons.expected_contracts(self.prepared,metadata,retried,lab))
        self.assertEqual((report['counts_totals']['planned'],report['counts_totals']['successful'],report['counts_totals']['retries']),(4,0,1))
        self.assertEqual(self.inventory(self.prepared/'inputs'),frozen)
        primary=self.prepared/selected['attempts'][0]['result_path'];body=primary.read_bytes();primary.write_bytes(body+b' ')
        callcount=len(self.observed)
        with self.assertRaises(experiments.ExperimentError):experiments.execute(self.prepared,lab,session='fixture',resume=True)
        self.assertEqual(primary.read_bytes(),body+b' ','resume must retain corrupt primary evidence rather than replace it')
        self.assertEqual(len(self.observed),callcount);primary.write_bytes(body)

    def test_single_normally_settled_stage_is_invocation_verified_but_missing_report_fails(self):
        self.engine.complete=False;self.fixture.source['stages']=self.fixture.source['stages'][:1]
        self.fixture.write('source.json',self.fixture.source)
        self.definition['cases']=self.definition['cases'][:1]
        self.fixture.write('experiment.json',self.definition);self.prepare()
        experiments.execute(self.prepared,lab,session='fixture')
        record=experiments.ledger_rows(self.prepared,lab)[0]['attempts'][0]['result']
        self.assertEqual((record['status'],record['invocation']['status'],record['task_result']['status']),('FAIL','verified','pass'))
        self.assertEqual(len(self.observed),2);self.assertEqual(self.engine.score_calls,2)
        self.assertIn({'code':'report_missing','count':1},record['application_completion']['stages'][0]['diagnostics'])

    def test_frozen_variant_cannot_run_without_exact_parent_trial_context(self):
        metadata,matrix=self.prepare();args=experiments.trial_args(self.prepared,metadata,matrix['cells'][0],lab,'fixture')
        del args._application_variant_context
        with contextlib.redirect_stdout(io.StringIO()):result=lab.run_suite(args)
        self.assertEqual(result,2);self.assertEqual(self.observed,[]);self.engine.host.assert_not_called()


class IndexedApplicationPublicIntegrationTests(unittest.TestCase):
    def test_actual_indexed_frozen_ir_drives_safe_export_of_retained_parent_counts(self):
        case=experiment_fixture.ApplicationExperimentTests(methodName='runTest');case.setUp();self.addCleanup(case.doCleanups)
        catalog=case.indexed();root=case.root/'indexed'
        experiments.validate(case.write(),lab,catalog=catalog)
        experiments.prepare(case.path,root,lab,session='fixture-session',catalog=catalog)
        metadata,matrix=experiments.verify(root,lab)
        canary='private-control-capability-canary-928374'
        for cell in matrix['cells']:
            plan=application_preparation.load_compiled(root/cell['compiled_plan'])['plan'];stage=plan['stages'][0]
            intent,_=experiments.reserve_attempt(root,metadata,cell)
            args=experiments.trial_args(root,metadata,cell,lab,'fixture-session');attempt=outcomes.Attempt(args,copy.deepcopy(intent['initial_record']))
            budget=budget_fixture.snapshot(maximum=stage['limits']['max_tool_calls'])
            budget['limits']={key:stage['limits'][key] for key in native_budget_controls.NATIVE_FIELDS}
            reserve=stage['limits']['reporting_reserve_calls'];remaining=budget['remaining_calls']
            budget['business_calls_remaining']=max(0,remaining-reserve);budget['reporting_reserve_calls_remaining']=min(remaining,reserve)
            charged=budget['per_tool'].pop('bash');zero=copy.deepcopy(budget['per_tool']['budget_status'])
            budget['per_tool']={name:copy.deepcopy(zero) for name in [*stage['tools'],'__unknown__']};budget['per_tool']['app_api']=charged
            attempt.record['fixture_origin']='controlled stored accounting; no invocation'
            attempt.record['infrastructure'].update(status='failed',phase='admission',reason=canary)
            attempt.record['agents']=[{'name':stage['id'],'process':{'cleanup_confirmed':True,
                'native_tool_manifest':{'schema':1,'tools':stage['tools']},'native_tool_budget':budget,
                'raw_control':canary,'events':{'tool_calls':999999}}}]
            attempt.finalize()
        rows=experiments.ledger_rows(root,lab);before=case.inventory(root)
        expected=comparisons.expected_contracts(root,metadata,rows,lab)
        comparison=comparisons.comparison(metadata,rows,expected)
        self.assertEqual(comparison['counts_totals']['planned'],2)
        self.assertEqual(comparison['counts_totals']['eligible'],0)
        self.assertEqual(case.inventory(root),before,'comparison must not write prepared or attempt evidence')
        exported=experiments.export_ledger(root,lab,public=True)
        body=Path(exported['path']).read_text();public=[json.loads(line) for line in body.splitlines()]
        for row in public:
            attempt=row['attempts'][0];stage=attempt['native_tool_budgets']['stages'][0]
            self.assertEqual(stage['stage'],1);self.assertEqual(stage['budget']['counts']['charged'],3)
            self.assertIsNone(stage['budget']['counts']['executed'])
            self.assertEqual(attempt['application_completion']['stages'][0]['status'],'not_evaluated')
            self.assertEqual(attempt['application_completion']['stages'][0]['stage'],1)
        for private in (canary,experiment_fixture.APP_KEY,'raw_control','"tool_calls":','999999',
                        'participant','configuration_sha256','authority_id'):
            self.assertNotIn(private,body)
        self.assertEqual({key:value for key,value in case.inventory(root).items() if key!='public-trials.jsonl'},before)


if __name__=='__main__':unittest.main()
