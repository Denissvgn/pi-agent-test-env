"""A10 indexed native helper admission; no Docker, models or stored catalog export."""
import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import indexed_contract as contract
import indexed_execution as indexed
import indexed_experiments
import inference_broker
import ownership_registry
from parallel_allocator import Allocator
import parallel_contract
import resources
import stage_control as controls
from test_indexed_experiments import IndexedSetup
import test_inference_broker as broker_fixture


def fresh():return str(uuid.uuid4())


class IndexedNativeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/private/tmp');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.run=self.root/'run';self.run.mkdir();(self.run/'workspace').mkdir()
        self.policy=copy.deepcopy(resources.DEFAULTS)
        self.policy['runtime']={'cpus':1,'memory':'1024m','pids_limit':256,'jobs':1}
        self.args=SimpleNamespace(platform='linux/arm64',native_platform='linux/arm64',
            resource_report={'requested':self.policy,'effective':self.policy})
        self.lab=mock.Mock();self.lab.requested_policy.return_value=self.policy
        self.lab.docker_info.return_value={'NCPU':16,'MemTotal':32*1024**3}

    def capacity(self,**kwargs):return indexed.capacity(self.args,self.lab,**kwargs)

    def test_absent_optin_retains_exact_legacy_shape_and_digest(self):
        value,worker=self.capacity()
        before=json.dumps(value,sort_keys=True,separators=(',',':')).encode();digest=contract.digest(value)
        checked=contract.helper_contract(value)
        self.assertEqual(json.dumps(checked,sort_keys=True,separators=(',',':')).encode(),before)
        self.assertEqual(contract.digest(checked),digest);self.assertNotIn('native_budget',checked)
        self.assertEqual(value['aggregate'],{'cpu_millis':1250,'memory_mib':1152,'pids_limit':320})

    def test_new_named_indexed_contract_derives_explicit_helper_weight(self):
        value,worker=self.capacity(native=True)
        self.assertEqual(value['native_budget'],contract.native_helper_contract())
        self.assertEqual(value['aggregate'],{'cpu_millis':2250,'memory_mib':1664,'pids_limit':448})
        self.assertEqual(contract.helper_contract(value),value)

    def test_frozen_legacy_contract_cannot_grow_or_enable_helper(self):
        value,_=self.capacity();before=copy.deepcopy(value);self.lab.reset_mock()
        with self.assertRaises(contract.IndexedError):self.capacity(contract_value=value,native=True)
        self.assertEqual(value,before);self.lab.require_host.assert_not_called();self.lab.docker_info.assert_not_called()

    def test_insufficient_frozen_helper_weight_rejects_before_docker_probe(self):
        value,_=self.capacity();value['native_budget']=contract.native_helper_contract();before=copy.deepcopy(value)
        self.lab.reset_mock()
        with self.assertRaises(contract.IndexedError):self.capacity(contract_value=value,native=True)
        self.assertEqual(value,before);self.lab.require_host.assert_not_called();self.lab.docker_info.assert_not_called()

    def test_parallel_admission_reserves_two_helpers_and_gateway(self):
        with mock.patch.object(parallel_contract,'admit_capacity',wraps=parallel_contract.admit_capacity) as admitted:
            value,worker=self.capacity(workers=2,native=True)
        self.assertEqual(value['aggregate'],{'cpu_millis':4250,'memory_mib':3200,'pids_limit':832})
        self.assertEqual(admitted.call_count,1)
        self.assertEqual(admitted.call_args.args[0]['native_budget'],contract.native_helper_contract())

    def test_native_footprint_is_fixed_and_unknown_fields_reject(self):
        good,_=self.capacity(native=True)
        for change in ('cpu','extra','boolean'):
            bad=copy.deepcopy(good)
            if change=='cpu':bad['native_budget']['resources']['cpu_millis']=999
            elif change=='extra':bad['native_budget']['extra']='forbidden'
            else:bad['native_budget']['helpers_per_trial']=True
            with self.subTest(change=change),self.assertRaises(contract.IndexedError):contract.helper_contract(bad)

    def support(self):
        value,worker=self.capacity(native=True)
        run,attempt=fresh(),fresh()
        pool=Allocator(value['aggregate']);row=pool.request('indexed-worker',{'run_id':run,'attempt_id':attempt,
            'generation':'generation','trial_id':None,'workspace':str(self.run/'workspace')},worker,30)
        pool.dispatch();pool.consume(row.identity,row.capability,row.binding,row.resources)
        records=[]
        registry=SimpleNamespace(generation='generation',registry_id='registry',daemon='daemon',load=lambda:records)
        network={'kind':'network','container':'admitted-network','generation':'generation','registry':'registry',
                 'daemon':'daemon','status':'intent'};records.append(network)
        session=indexed.Session(None,{'agent':{}},'fixture',{}, {'agent':['synthetic-delegate']},{},['synthetic-original'],value)
        session._native_owner={'pool':pool,'reservation':row,'registry':registry,'network':network['container'],
                              'runroot':self.run,'run_id':run,'attempt_id':attempt,'trial_id':None,'resources':copy.deepcopy(worker)}
        stage=fresh();desc={'kind':'agent','run_id':session._native_owner['run_id'],'attempt_id':session._native_owner['attempt_id'],
            'stage_id':stage,'workspace':str(self.run/'workspace')}
        path=self.run/'stages'/stage;path.mkdir(parents=True);controls.atomic(path/'descriptor.json',desc)
        token=ownership_registry.CURRENT.set(registry);self.addCleanup(ownership_registry.CURRENT.reset,token)
        return session,registry,records,desc,row

    def test_stage_support_binds_exact_owner_and_keeps_held_reservation(self):
        session,registry,_,desc,row=self.support()
        result=session.bind_native_stage(desc)
        self.assertEqual(set(result),{'pool','reservation','registry','network_record'})
        self.assertIs(result['reservation'],row);self.assertIs(result['registry'],registry)
        self.assertEqual(row.state,'launching')
        for key in ('run_id','attempt_id','stage_id','workspace'):self.assertEqual(row.binding[key],desc[key])
        self.assertEqual(row.binding['generation'],'generation');self.assertIsNone(row.binding['trial_id'])

    def test_stale_lease_foreign_descriptor_or_network_prevents_support(self):
        for mutation in ('lease','run','network','reservation'):
            with self.subTest(mutation=mutation):
                session,registry,records,desc,row=self.support()
                if mutation=='lease':ownership_registry.CURRENT.set(SimpleNamespace())
                elif mutation=='run':desc['run_id']=fresh()
                elif mutation=='network':records[0]['generation']='stale'
                else:row.binding['attempt_id']=fresh()
                with self.assertRaises(contract.IndexedError):session.bind_native_stage(desc)
                self.assertIsNone(session.native_budget_support)

    def test_stage_support_cannot_reopen_same_stage_with_a_fresh_ledger(self):
        session,_,_,desc,_=self.support();session.bind_native_stage(desc)
        with self.assertRaises(contract.IndexedError):session.bind_native_stage(desc)

    def test_live_helper_or_retained_capability_prevents_new_stage_support(self):
        for mutation in ('live','absent-sensitive','capability'):
            with self.subTest(mutation=mutation):
                session,registry,records,desc,_=self.support()
                if mutation=='capability':
                    path=self.run/'controls'/fresh()/'segments'/fresh();path.mkdir(parents=True)
                    (path/'native-budget-context.json').write_text('synthetic-capability')
                else:records.append({'runroot':str(self.run),'status':'running' if mutation=='live' else 'absent','application_helper':True})
                with self.assertRaises(contract.IndexedError):session.bind_native_stage(desc)
                self.assertIsNone(session.native_budget_support)
                shutil.rmtree(self.run/'controls',ignore_errors=True)

    def test_clean_released_helper_is_eligible_but_unremoved_sensitive_receipt_is_not(self):
        session,registry,records,desc,_=self.support()
        records.append({'runroot':str(self.run),'status':'released','application_helper':True})
        session.bind_native_stage(desc)
        controls.atomic(self.run/'stages'/desc['stage_id']/'application-credentials.json',{'status':'quarantined'})
        with self.assertRaises(contract.IndexedError):session.bind_native_stage(desc)

    def test_parent_redaction_list_is_bounded_and_never_publicly_echoed(self):
        self.assertEqual(indexed.bounded_redaction(['synthetic-private','synthetic-private']),['synthetic-private'])
        for values in ([str(n) for n in range(1025)],['x'*16385],['x'*16384+str(i) for i in range(129)]):
            with self.assertRaises(contract.IndexedError) as caught:indexed.bounded_redaction(values)
            self.assertLess(len(str(caught.exception)),200)

    def test_frozen_indexed_plan_requires_optin_during_offline_compile(self):
        fixture=IndexedSetup();fixture.setUp();self.addCleanup(fixture.doCleanups)
        fixture.plan['agents'][0].update(max_tool_calls=8,reporting_reserve_calls=2,reporting_reserve_seconds=10,timeout_seconds=600)
        fixture.write('plan.json',fixture.plan)
        with self.assertRaises(contract.IndexedError):indexed_experiments.validate(fixture.root/'experiment.json',__import__('pi_lab'),fixture.catalog)
        self.assertFalse((fixture.root/'prepared').exists())
        fixture.definition['indexed_execution']['native_budget']=contract.native_helper_contract()
        fixture.write('experiment.json',fixture.definition)
        normalized=indexed_experiments.validate(fixture.root/'experiment.json',__import__('pi_lab'),fixture.catalog)
        self.assertIn('native_budget',normalized['indexed_execution'])

    def test_experiment_budget_override_also_requires_frozen_helper_optin(self):
        fixture=IndexedSetup();fixture.setUp();self.addCleanup(fixture.doCleanups)
        fixture.definition['budgets'].update(max_tool_calls=8,reporting_reserve_calls=2,reporting_reserve_seconds=10)
        fixture.write('experiment.json',fixture.definition)
        with self.assertRaises(contract.IndexedError):indexed_experiments.validate(fixture.root/'experiment.json',__import__('pi_lab'),fixture.catalog)

    def test_serial_unknown_helper_quarantines_before_network_cleanup_or_pool_release(self):
        self.serial_cleanup_unknown()

    def test_serial_released_helper_with_renamed_context_cleanup_failure_retains_network(self):
        self.serial_cleanup_unknown(private_failure=True)

    def serial_cleanup_unknown(self,private_failure=False):
        value,_=self.capacity(native=True)
        task={'name':'agent','timeout_seconds':600,'max_tool_calls':8,'reporting_reserve_calls':2,'reporting_reserve_seconds':10}
        plan={'agents':[task]};planpath=self.root/'plan.json';controls.atomic(planpath,plan)
        binding={'incarnation':fresh(),'fingerprint':'f'*64,'authority_id':'fixture-authority',
            'configuration':{'endpoint':{},'request_limits':{'queue_wait_seconds':1,'request_timeout_seconds':30}}}
        args=copy.copy(self.args)
        args.__dict__.update(op='run',uid=os.getuid(),gid=os.getgid(),network='bridge',project=str(self.root/'project'),
            endpoint=None,in_place=False,plan=str(planpath),agent_profile=None,session='fixture',
            _indexed_bindings={'agent':binding},_indexed_contract=value,image='sha256:'+'a'*64)
        attempt=SimpleNamespace(root=self.run,record={'run_id':fresh(),'attempt_id':fresh()})
        records=[];registry=SimpleNamespace(binding={},generation='gen',registry_id='registry',daemon='daemon',load=lambda:records)
        events=[];captured={}
        @contextmanager
        def broker(lab,args,root,registry,pool,*rest):
            captured['pool']=pool
            records.append({'kind':'network','container':'owned-network','generation':'gen','registry':'registry','daemon':'daemon','status':'intent'})
            inference={'base_url':'http://pi-inference:8080/v1','host_base_url':'http://127.0.0.1:1/v1',
                       'activate':lambda values:events.append('activate'),'admit':lambda:None}
            try:yield inference,lambda intent:'owned-network',lambda name:events.append('network-cleanup')
            finally:events.append(('broker-finally',getattr(pool,'dependent_cleanup_confirmed',True)))
        lab=mock.Mock();lab.ROOT=ROOT/'skill';lab.validate_plan.return_value=plan
        with mock.patch.object(indexed,'Catalog'),mock.patch.object(indexed,'resolve',return_value=({'entry':binding},{'entry':'synthetic-original'},{})),\
             mock.patch.object(indexed,'capacity',return_value=(value,{'cpu_millis':1000,'memory_mib':1024,'pids_limit':256})),\
             mock.patch.object(indexed.inference_broker,'owner',broker):
            with self.assertRaises(contract.IndexedError):
                with indexed.admission(lab,args,attempt,registry):
                    if private_failure:
                        records.append({'runroot':str(self.run),'status':'released','application_helper':True})
                        stage=fresh();label='agent-1-agent'
                        (self.run/'stages'/stage).mkdir(parents=True);(self.run/label).mkdir()
                        controls.atomic(self.run/'stages'/stage/'descriptor.json',{'stage_id':stage,'label':label,
                            'original_limits':{'max_tool_calls':8,'reporting_reserve_calls':2,'reporting_reserve_seconds':10}})
                        controls.atomic(self.run/label/'process.json',{'cleanup_confirmed':False,
                            'native_tool_budget_error':'cleanup_unconfirmed'})
                        renamed=self.run/'controls'/stage/'segments'/fresh()/'renamed-private-context.json'
                        renamed.parent.mkdir(parents=True);controls.atomic(renamed,{'capability':'synthetic-private'})
                    else:records.append({'runroot':str(self.run),'status':'running','application_helper':True})
        self.assertNotIn('network-cleanup',events)
        self.assertIn(('broker-finally',False),events)
        self.assertEqual(captured['pool'].records['indexed-worker'].state,'quarantined')
        self.assertTrue(captured['pool'].closed)

    def test_frozen_indexed_parallel_attaches_native_cohort_before_probe(self):
        import experiments,indexed_parallel,parallel_native_budget,pi_lab
        from test_parallel_contract import selected
        fixture=IndexedSetup();fixture.setUp();self.addCleanup(fixture.doCleanups)
        fixture.definition['budgets'].update(max_tool_calls=8,reporting_reserve_calls=2,reporting_reserve_seconds=10)
        concurrency=selected();concurrency.update(scheduler=contract.SCHEDULER,host_generation=2)
        concurrency['gateway']['queue_wait_seconds']=180
        concurrency['aggregate']['cpu_millis']=4250
        concurrency['native_budget']=contract.native_helper_contract()
        fixture.definition.update(mode='parallel',concurrency=concurrency)
        helper=fixture.definition['indexed_execution'];helper.update(max_workers=2,native_budget=contract.native_helper_contract(),
            aggregate=copy.deepcopy(concurrency['aggregate']),gateway=copy.deepcopy(concurrency['gateway']))
        fixture.write('experiment.json',fixture.definition)
        destination=fixture.root/'native-prepared'
        indexed_experiments.prepare(fixture.root/'experiment.json',destination,pi_lab,'fixture',fixture.catalog)
        registry=SimpleNamespace(binding={},generation='gen',load=lambda:[],daemon='fixture-daemon')
        @contextmanager
        def lease(*args,**kwargs):yield registry
        class ProbeBoundary(Exception):pass
        with mock.patch.object(indexed_parallel.resources,'admission_lock',lease),\
             mock.patch.object(indexed_parallel.indexed_execution,'capacity',return_value=(helper,{'cpu_millis':1000,'memory_mib':128,'pids_limit':64})),\
             mock.patch.object(pi_lab,'probe_image',side_effect=ProbeBoundary) as probe:
            with self.assertRaises(ProbeBoundary):indexed_parallel.execute(destination,pi_lab,'fixture')
        self.assertEqual(probe.call_count,1)
        cohort=registry._native_budget_cohort
        self.assertIsInstance(cohort.pool,parallel_native_budget.NativeAllocator)
        self.assertEqual(cohort.pool.native_trials,cohort.native_trials)
        self.assertEqual(len(cohort.native_trials),4)


class BrokerQuarantineTests(unittest.TestCase):
    def setUp(self):
        self.fixture=broker_fixture.BrokerTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)

    def test_native_unknown_dependent_retains_private_gateway_and_networks(self):
        fixture=self.fixture
        def network(name):
            record={'kind':'network','container':name,'status':'intent','launch_id':fresh()};fixture.records.append(record);return record
        fixture.registry.registry_id='fixture-registry'
        fixture.registry.network_intent=network
        fixture.registry.remove_network=mock.Mock()
        with mock.patch.object(inference_broker,'urlopen',fixture.health):
            with self.assertRaises(parallel_contract.ParallelError):
                with fixture.owner() as (inference,factory,cleanup):
                    owned=factory({'trial_id':'fixture-trial'})
                    fixture.pool.dependent_cleanup_confirmed=False
        private=Path(fixture.records[0]['private_store']);self.addCleanup(shutil.rmtree,private)
        self.assertTrue(private.exists());self.assertEqual(fixture.records[0]['status'],'quarantined')
        self.assertEqual(fixture.pool.records['gateway'].state,'quarantined')
        self.assertFalse(any(call[:3]==['docker','rm','--force'] for call in fixture.calls))
        fixture.registry.remove_network.assert_not_called()
        self.assertEqual(fixture.records[1]['container'],owned)
        self.assertEqual(fixture.records[1]['status'],'intent')
        self.assertEqual(json.loads((fixture.control/'active-tokens.json').read_text())['tokens'],[])
        with self.assertRaises(contract.IndexedError):inference['admit']()

    def test_legacy_absent_flag_keeps_successful_cleanup_behavior(self):
        fixture=self.fixture
        with mock.patch.object(inference_broker,'urlopen',fixture.health):
            with fixture.owner():pass
        self.assertEqual(fixture.records[0]['status'],'released')
        self.assertFalse(Path(fixture.records[0]['private_store']).exists())


if __name__=='__main__':unittest.main()
