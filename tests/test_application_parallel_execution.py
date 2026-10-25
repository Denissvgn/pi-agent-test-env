"""Actual frozen application experiments with controlled host/gateway/engine.

No worker/helper container, Pi/model request or browser process is executed.
The collector fixture exercises parent actor/resource admission and bootstrap.
"""
import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_experiments as artifacts
import application_parallel_execution as controller
import application_contracts as c
import experiments
from inference_catalog import Catalog
import indexed_contract
import ownership_registry
import outcomes
from parallel_allocator import LIVE
from parallel_dispatch import Peer
import parallel_contract
import pi_lab as lab
import resources
import secret_store
import stage_control as controls
import test_application_preparation as preparation_fixtures
from test_indexed_contract import config
from test_parallel_contract import selected

APP_KEY='application-parallel-disposable-app-123456'
MODEL_KEY='application-parallel-disposable-model-123456'


class ParallelApplicationTests(unittest.TestCase):
    def setUp(self):
        fixture=preparation_fixtures.PreparationTests(methodName='runTest');fixture.setUp();self.addCleanup(fixture.doCleanups)
        self.fixture=fixture;self.root=fixture.root;self.store=self.root/'store'
        self.project=self.root/'project';self.project.mkdir();(self.project/'original.txt').write_text('untouched original\n')
        self.store_patch=mock.patch.object(secret_store,'default_store',return_value=self.store);self.store_patch.start();self.addCleanup(self.store_patch.stop)
        secret_store.write_secret('DIAGNOSTIC_ALICE',APP_KEY,self.store);secret_store.write_secret('MODEL_REFERENCE',MODEL_KEY,self.store)
        fixture.source['runtime']['inference_owner']='experiment_variant'
        second=copy.deepcopy(fixture.source['stages'][0]);second.update(id='second',depends_on=['participant'])
        second['completion']['id']='second-report';second['completion']['report_path']='second/report.json';second['completion']['artifacts'][0]['path']='second/summary.md'
        fixture.source['stages'].append(second);fixture.write('source.json',fixture.source)
        self.policy=resources.validate_policy({'runtime':{'cpus':1,'memory':'128m','pids_limit':64,'jobs':1},
            'build':{'cpus':1,'memory':'128m','max_parallelism':1,'timeout_seconds':60}})
        fixture.write('policy.json',self.policy)
        contract=selected();contract['gateway'].update(queue_wait_seconds=1,request_timeout_seconds=30)
        contract['native_budget']=indexed_contract.native_helper_contract()
        contract['aggregate']={'cpu_millis':4250,'memory_mib':1408,'pids_limit':448}
        self.definition={'schema':2,'document_type':'application_experiment_source','name':'controlled-parallel',
            'baseline':'baseline','repetitions':1,'budgets':copy.deepcopy(fixture.source['stages'][0]['limits']),
            'execution':{'image':fixture.source['runtime']['image_id'],'platform':'linux/arm64','resources':'policy.json'},
            'policies':{'primary_attempt':'first','assistance':'exclude','on_failure':'continue','max_attempts':2},
            'cases':[{'name':'case','project':str(self.project),'plan':'source.json','runtime_receipt':'runtime.json'}],
            'variants':[{'name':'baseline','endpoint':'endpoint.json'},{'name':'candidate','endpoint':'endpoint.json'}],
            'concurrency':contract}
        self.events=[];self.records=[];self.captures=[];self.mutate_effective=False;self.revoke_model=False
        self.registry=ownership_registry.Registry(self.root/'registry',command=mock.Mock())
        self.registry.daemon='controlled-daemon';self.registry.close=mock.Mock()
        self.catalog=None

    def prepare(self,indexed=False):
        if indexed:
            self.definition.update(schema=3,mode='parallel')
            self.definition['concurrency'].update(scheduler=indexed_contract.SCHEDULER,host_generation=2)
            self.definition['indexed_execution']={'contract':indexed_contract.EXECUTION,'host_generation':2,'max_workers':2,
                'aggregate':copy.deepcopy(self.definition['concurrency']['aggregate']),
                'gateway':copy.deepcopy(self.definition['concurrency']['gateway']),
                'native_budget':indexed_contract.native_helper_contract()}
            self.catalog=Catalog(lab.normalize_endpoint,self.root/'catalog',self.store)
            for name in ('model-a','model-b'):
                configuration=config();configuration['endpoint'].update(model=name,context_window=1000000,max_tokens=4096)
                configuration['credential']={'source':'store','name':'MODEL_REFERENCE'}
                configuration['request_limits']={'queue_wait_seconds':1,'request_timeout_seconds':30}
                self.catalog.register(name,configuration);self.catalog.confirm(name,'fixture')
            self.definition['variants']=[{'name':'baseline','inference_env':'model-a'},{'name':'candidate','inference_env':'model-b'}]
        self.fixture.write('experiment.json',self.definition)
        artifacts.prepare(self.fixture.inputs/'experiment.json',self.root/'prepared',lab,session='fixture',catalog=self.catalog)
        self.exp=self.root/'prepared';self.metadata,self.matrix=artifacts.verify(self.exp,lab)

    @contextmanager
    def lease(self,*args):
        self.events.append('lease')
        token=ownership_registry.CURRENT.set(self.registry)
        try:yield self.registry
        finally:ownership_registry.CURRENT.reset(token)

    def host(self,args):
        self.events.append('host');args.native_platform='linux/arm64'
        resources.configure(args,{'NCPU':32,'MemTotal':64*1024**3})
        if self.mutate_effective:args.resource_report['effective']['runtime']['cpus']=.5
        return {'scope':'controlled host boundary'}

    def probe(self,args,image):
        self.events.append('probe')
        self.assertIsNotNone(getattr(self.registry,'_native_budget_cohort',None))
        self.assertIsNotNone(self.registry._native_budget_cohort.pool)
        return {'id':image,'platform':'linux/arm64','capabilities':{'pi':self.fixture.source['runtime']['pi_release']}}

    @contextmanager
    def broker(self,unused_lab,args,root,registry,pool,worker,configuration,*rest):
        self.events.append('broker');self.broker_config=copy.deepcopy(configuration)
        def trial(intent):return {'token':next(token for token,owner in configuration['tokens'].items() if owner==intent['trial_id'])}
        inference={'worker_resources':worker,'trial':trial,'base_url':'http://pi-inference:8080/v1',
            'host_base_url':'http://127.0.0.1:1/v1','admit':lambda:None,
            'activate':lambda values:self.events.append(('activate',len(list(values))))}
        yield inference,lambda intent:'pi-trial-fixture',lambda network:self.events.append(('network-cleanup',network))

    def collect(self,root,metadata,matrix,work,unused_lab,registry,pool,session,inference,factory,cleanup):
        self.events.append('collect');self.work=list(work);self.pool=pool
        self.assertEqual(inference['credentials'],{})
        cohort=registry._native_budget_cohort
        for cell in work:pool.request(cell['trial_id'],{'credential_authorities':inference['authorities'][cell['trial_id']]},inference['worker_resources'],30)
        pool.dispatch()
        stages=[row for row in pool.records.values() if row.kind=='stage' and row.state in LIVE]
        self.assertEqual(len(stages),1,'Same application actor must serialize even with two trial slots')
        cell=next(cell for cell in work if cell['trial_id']==stages[0].identity)
        previous=experiments.attempt_intents(root,cell)
        intent,_=experiments.reserve_attempt(root,metadata,cell,len(previous)+1,previous[-1]['attempt_id'] if previous else None)
        row=stages[0];row.binding.update(generation=registry.generation,
            **{key:intent[key] for key in ('run_id','attempt_id','trial_id')},workspace=str(Path(root)/'runs'/intent['run_id']/'workspace'))
        bootstrap={'experiment':str(root),'intent':intent,'network':factory(intent),'capability':row.capability,
            'inference':inference['trial'](intent),'credentials':{}}
        if inference.get('indexed'):bootstrap['indexed']=inference['indexed'](cell,intent)
        peer=Peer(bootstrap,registry,pool,row,metadata,Path(root)/'runs'/intent['run_id'])
        self.assertEqual(bootstrap['application'],{'schema':1,'plan_sha256':cell['plan_sha256'],'participant_keys_withheld':True})
        self.captures.append(copy.deepcopy(bootstrap))
        for secret in (APP_KEY,MODEL_KEY):self.assertNotIn(secret,json.dumps(bootstrap))
        self.assertEqual(pool.buddies[cell['trial_id']].resources,self.definition['concurrency']['native_budget']['resources'])
        held=pool.used();self.assertGreaterEqual(held['memory_mib'],self.definition['concurrency']['native_budget']['resources']['memory_mib'])
        if inference.get('stage_admission'):
            before=len(self.events)
            with self.assertRaises(ValueError):inference['stage_admission'](cell['trial_id'],'second')
            self.assertEqual(len(self.events),before,'Wrong model stage cannot activate a delegate token')
            other=next(item for item in work if item['trial_id']!=cell['trial_id'])
            other_tokens=cohort._trial_values[other['trial_id']]
            self.assertFalse(set(other_tokens)&set(cohort._private_values(cell['trial_id'])))
            self.assertEqual(len(bootstrap['indexed']['tokens']),2)
            if self.revoke_model:
                binding=bootstrap['indexed']['bindings'][bootstrap['indexed']['first_stage']]
                self.catalog.revoke(binding['id'],binding['revision']);before=len(self.events)
                with self.assertRaises(ValueError):inference['stage_admission'](cell['trial_id'],bootstrap['indexed']['first_stage'])
                self.assertEqual(len(self.events),before,'Revoked model cannot activate a token')
        return {'schema':2,'status':'completed','planned':len(matrix['cells']),'completed_this_call':len(work),'exit_code':0,
            'fixture_origin':'controlled collection boundary; no worker/helper/model execution'}

    @contextmanager
    def boundaries(self):
        with mock.patch.object(controller.experiments,'verify',side_effect=artifacts.verify),\
             mock.patch.object(controller.experiments,'trial_args',side_effect=artifacts.trial_args),\
             mock.patch.object(controller.resources,'admission_lock',side_effect=self.lease),\
             mock.patch.object(lab,'require_host',side_effect=self.host) as host,\
             mock.patch.object(lab,'docker_info',return_value={'NCPU':32,'MemTotal':64*1024**3}),\
             mock.patch.object(lab,'probe_image',side_effect=self.probe) as probe,\
             mock.patch.object(controller.inference_broker,'owner',side_effect=self.broker),\
             mock.patch.object(controller.parallel_engine,'collect',side_effect=self.collect) as collect,\
             mock.patch.object(controller.platform,'machine',return_value='arm64'):
            yield host,probe,collect

    def test_legacy_actual_frozen_artifact_reaches_parent_cohort_without_key_bootstrap(self):
        self.prepare()
        with self.boundaries():result=controller.execute(self.exp,lab,'fixture')
        self.assertEqual(result['schema'],2);self.assertEqual(self.broker_config['upstream_key'],MODEL_KEY)
        self.assertTrue(self.broker_config['active_tokens_file'])
        self.assertLess(self.events.index('host'),self.events.index('probe'))
        self.assertEqual((self.project/'original.txt').read_text(),'untouched original\n')

    def test_indexed_actual_frozen_routes_private_pools_and_stage_gate(self):
        self.prepare(indexed=True)
        with self.boundaries():result=controller.execute(self.exp,lab,'fixture')
        self.assertEqual(result['schema'],3);self.assertTrue(self.broker_config['active_tokens_file'])
        self.assertEqual(len(self.broker_config['tokens']),400)
        self.assertEqual(len(self.broker_config['routes']),2)

    def test_shared_experiment_entry_dispatches_actual_parallel_application_controller(self):
        self.prepare()
        with self.boundaries():result=experiments.execute(self.exp,lab,session='fixture')
        self.assertEqual(result['schema'],2)
        self.assertEqual(result['fixture_origin'],'controlled collection boundary; no worker/helper/model execution')
        self.assertEqual(self.events.count('collect'),1)

    def test_shared_experiment_entry_rejects_serial_runner_or_cleanup_bypass(self):
        self.prepare()
        for kwargs in ({'runner':mock.Mock()},{'cleanup':mock.Mock()}):
            with self.subTest(option=next(iter(kwargs))),self.boundaries() as (host,probe,collect):
                with self.assertRaises(ValueError):experiments.execute(self.exp,lab,session='fixture',**kwargs)
                host.assert_not_called();probe.assert_not_called();collect.assert_not_called()
        self.assertEqual(self.events,[])

    def test_missing_application_credential_rejects_before_host_lease_probe_or_collection(self):
        self.prepare();(self.store/'DIAGNOSTIC_ALICE').unlink()
        with self.boundaries() as (host,probe,collect):
            with self.assertRaises(ValueError):controller.execute(self.exp,lab,'fixture')
        self.assertNotIn('lease',self.events);host.assert_not_called();probe.assert_not_called();collect.assert_not_called()

    def test_resource_clamping_rejects_without_probe_or_dispatch(self):
        self.prepare();self.mutate_effective=True
        with self.boundaries() as (_,probe,collect):
            with self.assertRaises(ValueError):controller.execute(self.exp,lab,'fixture')
        probe.assert_not_called();collect.assert_not_called()

    def test_mismatched_reviewed_helper_class_cannot_reach_host_or_probe(self):
        self.prepare();private=artifacts.admit_work(self.exp,self.metadata,self.matrix['cells'],lab,'fixture')
        metadata=copy.deepcopy(self.metadata)
        metadata['concurrency']['native_budget']['resources']=copy.deepcopy(parallel_contract.NATIVE_BROWSER_HELPER_RESOURCES)
        with self.boundaries() as (host,probe,collect),\
             mock.patch.object(controller.experiments,'verify',return_value=(metadata,self.matrix)),\
             mock.patch.object(controller.application_experiments,'admit_work',return_value=private):
            with self.assertRaises(ValueError):controller.execute(self.exp,lab,'fixture')
        host.assert_not_called();probe.assert_not_called();collect.assert_not_called()

    def test_indexed_revocation_after_initial_bootstrap_cannot_activate_another_request(self):
        self.prepare(indexed=True);self.revoke_model=True
        with self.boundaries():controller.execute(self.exp,lab,'fixture')

    def test_released_helper_without_private_cleanup_proof_cannot_trigger_generic_recovery(self):
        self.prepare();intent={'run_id':'controlled-run'};run=self.exp/'runs'/intent['run_id']
        private=run/'application-helpers'/'owned';private.mkdir(parents=True);(private/'preserve').write_text('retain unknown authority')
        with mock.patch.object(self.registry,'load',return_value=[{'application_helper':True,'runroot':str(run),'status':'released'}]),\
             mock.patch.object(controller.parallel_execution,'registry_cleanup',return_value=mock.Mock(side_effect=AssertionError('No generic purge'))):
            callback=controller._recovery(self.registry,self.metadata)
            with self.assertRaises(ValueError):callback(self.exp,intent,self.metadata,lab)
        self.assertEqual((private/'preserve').read_text(),'retain unknown authority')

    def test_unknown_old_application_helper_never_enters_generic_cleanup(self):
        self.prepare()
        with self.boundaries() as (host,probe,collect),mock.patch.object(self.registry,'load',return_value=[{'application_helper':True,'status':'quarantined'}]),\
             mock.patch.object(self.registry,'reconcile',side_effect=AssertionError('No generic helper cleanup')):
            with self.assertRaises(ValueError):controller.execute(self.exp,lab,'fixture',resume=True)
        host.assert_not_called();probe.assert_not_called();collect.assert_not_called()

    def test_source_identity_rejects_before_private_credentials_or_host(self):
        self.prepare()
        with self.boundaries(),mock.patch.object(controller.provenance,'execution',return_value={'runner_content_sha256':'0'*64}),\
             mock.patch.object(controller.application_experiments,'admit_work',side_effect=AssertionError('No credential work')) as admit:
            with self.assertRaises(ValueError):controller.execute(self.exp,lab,'fixture')
        admit.assert_not_called();self.assertEqual(self.events,[])

    def primary(self):
        cell=self.matrix['cells'][0];intent,path=experiments.reserve_attempt(self.exp,self.metadata,cell)
        record=copy.deepcopy(intent['initial_record']);record.update(schema=2,document_type='run_result',sealed=True,status='FAIL',
            fixture_origin='synthetic stopped primary for retry identity test')
        record['termination']['reason']='completed';record['status'],record['exit_code']=outcomes.status(record)
        run=self.exp/'runs'/intent['run_id'];run.mkdir(parents=True)
        controls.atomic(run/'result.json',record)
        return cell,intent,(run/'result.json').read_bytes()

    def test_explicit_retry_preserves_primary_and_existing_attempt_requires_resume(self):
        self.prepare();cell,intent,original=self.primary()
        with self.boundaries() as (host,probe,collect):
            with self.assertRaises(ValueError):controller.execute(self.exp,lab,'fixture',retry_trial=cell['trial_id'])
        host.assert_not_called();probe.assert_not_called();collect.assert_not_called()
        with self.boundaries():controller.execute(self.exp,lab,'fixture',resume=True,retry_trial=cell['trial_id'])
        self.assertEqual((self.exp/'runs'/intent['run_id']/'result.json').read_bytes(),original)
        attempts=experiments.attempt_intents(self.exp,cell)
        self.assertEqual(len(attempts),2);self.assertEqual(attempts[1]['retry_of_attempt_id'],intent['attempt_id'])

    def test_resume_reconciles_pre_dispatch_only_attempts_without_new_business(self):
        self.prepare();intents=[]
        for cell in self.matrix['cells']:intents.append(experiments.reserve_attempt(self.exp,self.metadata,cell)[0])
        with self.boundaries() as (host,probe,collect):result=controller.execute(self.exp,lab,'fixture',resume=True)
        self.assertEqual(result['completed_this_call'],0);host.assert_not_called();probe.assert_not_called();collect.assert_not_called()
        for intent in intents:
            record=experiments.sealed_result(self.exp,intent)
            self.assertEqual(record['controller_interruption']['kind'],'controller_lost')
            self.assertEqual(record['invocation']['attempted_stages'],0)


if __name__=='__main__':unittest.main()
