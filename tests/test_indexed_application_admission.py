"""A11 exact application IR/catalog admission; real catalog, mocked host/broker."""
import argparse
import copy
from contextlib import contextmanager
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_contracts as c
import application_compiler as compiler
import indexed_contract as contract
import indexed_execution as indexed
from inference_catalog import Catalog
import parallel_contract
import pi_lab as lab
import resources
import stage_control as controls
import test_application_compiler as fixtures
import test_application_client_authority as authorities
import test_application_preparation as preparation_fixtures
import application_dispatch
from test_indexed_contract import config


class IndexedApplicationTests(authorities.BaseFixture):
    def setUp(self):
        super().setUp()
        self.catalog=Catalog(lab.normalize_endpoint,self.root/'catalog',self.store)
        configuration=config();configuration.update(credential={'source':'none'},
            request_limits={'queue_wait_seconds':1,'request_timeout_seconds':30})
        configuration['endpoint']['model']='fixture-é-model'
        self.catalog.register('reviewed',configuration);self.catalog.confirm('reviewed','fixture')
        self.entry=self.catalog.freeze('reviewed','fixture')
        source,kwargs=fixtures.inputs()
        for name in kwargs['inference_bindings']:
            kwargs['inference_bindings'][name].update(kind='indexed',
                configuration_sha256=c.digest(self.entry['configuration']),
                context_window=self.entry['configuration']['endpoint']['context_window'],
                max_tokens=self.entry['configuration']['endpoint']['max_tokens'],input_modalities=['text'],
                selection={'owner':source['runtime']['inference_owner'],'id':'reviewed'})
        self.plan=compiler.compile_plan(source,**kwargs)
        policy=self.plan['runtime']['resources'];runtime=self.plan['runtime']
        self.args=argparse.Namespace(_indexed_application=True,_application_plan=copy.deepcopy(self.plan),
            _indexed_bindings={'participant':copy.deepcopy(self.entry)},_indexed_contract=None,
            op='run',uid=os.getuid(),gid=os.getgid(),network='bridge',endpoint=None,in_place=False,
            project=str(self.project),session='fixture',catalog_dir=str(self.catalog.root),secrets_dir=str(self.store),
            plan=str(self.root/'must-not-read-plan.json'),agent_profile=str(self.root/'must-not-read-profile.json'),
            image=runtime['image_id'],platform=runtime['platform'],profile=runtime['container_profile'],
            browser_sandbox_policy=runtime['browser_sandbox_policy'] or 'docker-default',native_platform='linux/arm64',
            resource_report={'requested':copy.deepcopy(policy),'effective':copy.deepcopy(policy)})
        self.worker=parallel_contract.worker_weight(policy)
        self.helper={'contract':contract.EXECUTION,'host_generation':2,'max_workers':1,
            'aggregate':{key:self.worker[key]+extra for key,extra in zip(self.worker,(1250,640,192))},
            'gateway':{'resources':{'cpu_millis':250,'memory_mib':128,'pids_limit':64},
                'max_inflight':1,'max_pending':4,'queue_wait_seconds':180,'request_timeout_seconds':180},
            'native_budget':contract.native_helper_contract()}
        self.parent_lab=mock.Mock(wraps=lab);self.parent_lab.ROOT=lab.ROOT
        self.parent_lab.requested_policy.return_value=copy.deepcopy(policy)
        self.records=[];self.registry=SimpleNamespace(binding={},generation='generation',registry_id='registry',
            daemon='daemon',load=lambda:self.records)
        self.attempt=SimpleNamespace(root=self.runroot,record={'run_id':str(uuid.uuid4()),'attempt_id':str(uuid.uuid4())})
        self.events=[]

    @contextmanager
    def broker(self,unused_lab,args,root,registry,pool,*rest):
        self.pool=pool
        self.records.append({'kind':'network','container':'owned-network','generation':registry.generation,
            'registry':registry.registry_id,'daemon':registry.daemon,'status':'intent'})
        inference={'base_url':'http://pi-inference:8080/v1','host_base_url':'http://127.0.0.1:1/v1',
            'activate':lambda values:self.events.append(('activate',len(list(values)))),'admit':lambda:None}
        try:yield inference,lambda intent:'owned-network',lambda name:self.events.append(('cleanup',name))
        finally:self.events.append(('finally',getattr(pool,'dependent_cleanup_confirmed',True)))

    @contextmanager
    def admitted(self):
        with mock.patch.object(indexed,'capacity',return_value=(self.helper,self.worker)),\
             mock.patch.object(indexed.inference_broker,'owner',self.broker),\
             mock.patch.object(self.parent_lab,'validate_plan',side_effect=AssertionError('No legacy translation')):
            with indexed.admission(self.parent_lab,self.args,self.attempt,self.registry) as context:yield context

    def test_internal_admission_view_preserves_ir_and_both_canonical_identities(self):
        before=copy.deepcopy(self.args._application_plan)
        view,names=indexed.application_admission_view(self.args,self.parent_lab,self.args._indexed_bindings)
        self.assertEqual(names,['participant']);self.assertEqual(view['application_plan'],before)
        self.assertEqual(view['agents'][0]['application_secrets'],{'PI_APP_ALIAS_0':'DIAGNOSTIC_ALICE'})
        self.assertEqual(view['agents'][0]['tools'],before['stages'][0]['tools'])
        self.assertEqual(self.args._application_plan,before)
        self.assertNotEqual(c.digest(self.entry['configuration']),self.entry['fingerprint'])
        self.assertEqual(contract.digest(self.entry['configuration']),self.entry['fingerprint'])

    def test_runtime_or_binding_mismatches_reject_before_host_or_broker(self):
        faults=[lambda a:setattr(a,'image','sha256:'+'e'*64),lambda a:setattr(a,'profile','browser'),
            lambda a:setattr(a,'platform','linux/amd64'),
            lambda a:a._indexed_bindings.clear(),
            lambda a:a._indexed_bindings.update(extra=copy.deepcopy(self.entry)),
            lambda a:a._indexed_bindings['participant']['configuration']['credential'].update(name='PRIVATE_REF'),
            lambda a:a._application_plan['stages'][0]['inference_binding'].update(kind='legacy'),
            lambda a:a._application_plan['stages'][0]['inference_binding']['selection'].update(id='wrong'),
            lambda a:a._application_plan['stages'][0]['inference_binding'].update(configuration_sha256=self.entry['fingerprint'])]
        for number,fault in enumerate(faults):
            with self.subTest(fault=number):
                args=copy.deepcopy(self.args);fault(args)
                args._application_plan['plan_sha256']=c.digest({k:v for k,v in args._application_plan.items() if k!='plan_sha256'})
                with self.assertRaises(contract.IndexedError):indexed.application_admission_view(args,self.parent_lab,args._indexed_bindings)
        self.parent_lab.require_host.assert_not_called();self.parent_lab.probe_image.assert_not_called()

    def test_equal_memory_bytes_are_accepted_but_other_resource_changes_reject(self):
        policy=copy.deepcopy(self.plan['runtime']['resources'])
        for section in ('runtime','build'):
            policy[section]['memory']=str(resources.memory_bytes(policy[section]['memory'])//1024**2)+'m'
        self.parent_lab.requested_policy.return_value=policy
        indexed.application_admission_view(self.args,self.parent_lab,self.args._indexed_bindings)
        policy['runtime']['jobs']+=1
        with self.assertRaises(contract.IndexedError):indexed.application_admission_view(self.args,self.parent_lab,self.args._indexed_bindings)

    def test_actual_catalog_confirmation_reaches_broker_without_legacy_plan_read(self):
        with self.admitted() as context:
            self.assertEqual(context.current,'participant');self.assertEqual(context.binding,self.entry)
            self.assertEqual(context.credentials['participant'],{'PI_APP_ALIAS_0':authorities.KEY_A})
            self.assertEqual(context.endpoint()['model'],self.entry['configuration']['endpoint']['model'])
            self.assertNotIn(authorities.KEY_A,str(context.endpoint()))
            self.assertEqual(self.args._application_plan,self.plan)
        self.assertIn(('cleanup','owned-network'),self.events);self.assertIn(('finally',True),self.events)
        self.assertEqual(self.args.network,'bridge');self.assertIsNone(self.args._indexed_session)

    def test_catalog_revocation_still_rejects_before_capacity_and_gateway(self):
        self.catalog.revoke('reviewed',self.entry['revision'])
        with mock.patch.object(indexed,'capacity',side_effect=AssertionError('No host work')) as capacity,\
             mock.patch.object(indexed.inference_broker,'owner',side_effect=AssertionError('No broker')) as broker:
            with self.assertRaises(contract.IndexedError):
                with indexed.admission(self.parent_lab,self.args,self.attempt,self.registry):pass
        capacity.assert_not_called();broker.assert_not_called()

    def test_literal_application_authority_still_rejects_before_host_work(self):
        source,kwargs=fixtures.inputs();source['stages'][0]['prompt']+=' '+authorities.KEY_A
        kwargs['inference_bindings']['participant']=copy.deepcopy(self.plan['stages'][0]['inference_binding'])
        self.args._application_plan=compiler.compile_plan(source,**kwargs)
        with mock.patch.object(indexed,'capacity',side_effect=AssertionError('No host work')) as capacity:
            with self.assertRaises(ValueError):
                with indexed.admission(self.parent_lab,self.args,self.attempt,self.registry):pass
        capacity.assert_not_called()

    def test_revocation_during_explicit_continuation_prevents_token_activation(self):
        with self.admitted() as context:
            count=len(self.events);self.catalog.revoke('reviewed',self.entry['revision'])
            with self.assertRaises(contract.IndexedError):context.continuation(renew=True)
            self.assertEqual(len(self.events),count)

    def test_partial_application_optin_cannot_fall_back_to_legacy_dispatch(self):
        for fault in ('flag','plan','bindings','hostile-bindings'):
            with self.subTest(fault=fault):
                args=copy.deepcopy(self.args)
                if fault=='flag':args._indexed_application=False
                elif fault=='plan':args._application_plan=None
                elif fault=='bindings':args._indexed_bindings=None
                else:args._indexed_bindings='hostile'
                with mock.patch.object(self.parent_lab,'validate_plan',side_effect=AssertionError('No legacy plan read')):
                    with self.assertRaises(contract.IndexedError):
                        with indexed.admission(self.parent_lab,args,self.attempt,self.registry):pass

    def browser_args(self):
        source,kwargs=fixtures.inputs(fixtures.browser_source())
        kwargs['inference_bindings']['participant']=copy.deepcopy(self.plan['stages'][0]['inference_binding'])
        self.args._application_plan=compiler.compile_plan(source,**kwargs)
        self.args.profile='browser';self.args.browser_sandbox_policy='chromium-userns'
        return self.args

    def test_browser_ir_derives_exact_helper_class_only_for_new_standalone_contract(self):
        self.browser_args()
        with mock.patch.object(self.parent_lab,'require_host'),\
             mock.patch.object(self.parent_lab,'docker_info',return_value={'NCPU':32,'MemTotal':64*1024**3}),\
             mock.patch.object(indexed.inference_broker,'owner',self.broker):
            with indexed.admission(self.parent_lab,self.args,self.attempt,self.registry) as context:
                selected=context.contract['native_budget']['resources']
                self.assertEqual(selected,{'cpu_millis':2000,'memory_mib':2048,'pids_limit':512})
                self.assertEqual(context.contract['aggregate'],{key:self.worker[key]+selected[key]+context.contract['gateway']['resources'][key] for key in self.worker})
                self.assertEqual(list(self.pool.records),['indexed-worker'])
                self.assertEqual(self.pool.records['indexed-worker'].resources,self.worker)

    def test_frozen_api_helper_cannot_silently_resize_to_browser_class(self):
        self.browser_args();self.args._indexed_contract=copy.deepcopy(self.helper);before=copy.deepcopy(self.helper)
        with mock.patch.object(indexed.inference_broker,'owner',side_effect=AssertionError('No broker')):
            with self.assertRaises(contract.IndexedError):
                with indexed.admission(self.parent_lab,self.args,self.attempt,self.registry):pass
        self.assertEqual(self.args._indexed_contract,before);self.parent_lab.require_host.assert_not_called()

    def test_only_two_reviewed_helper_resource_classes_are_accepted(self):
        from application_client import API_RESOURCES,BROWSER_RESOURCES
        self.assertEqual(contract.native_helper_contract()['resources'],API_RESOURCES)
        self.assertEqual(contract.native_helper_contract(BROWSER_RESOURCES)['resources'],BROWSER_RESOURCES)
        for changed in ({**BROWSER_RESOURCES,'memory_mib':1024},{**API_RESOURCES,'extra':1},
                {**API_RESOURCES,'pids_limit':True}):
            with self.assertRaises(contract.IndexedError):contract.native_helper_contract(changed)

    def test_actual_dispatch_prepare_core_policy_and_nondefault_resources_admit_same_ir(self):
        fixture=preparation_fixtures.PreparationTests(methodName='runTest');fixture.setUp();self.addCleanup(fixture.doCleanups)
        configuration=config();configuration.update(credential={'source':'none'},
            request_limits={'queue_wait_seconds':1,'request_timeout_seconds':30})
        configuration['endpoint'].update(context_window=1000000,max_tokens=4096)
        self.catalog.register('dispatch-reviewed',configuration);self.catalog.confirm('dispatch-reviewed','fixture')
        fixture.source['runtime']['resources']['runtime']={'cpus':2,'memory':'2048m','pids_limit':256,'jobs':2}
        fixture.write('source.json',fixture.source)
        compiled=fixture.compile(inference_env_id='dispatch-reviewed',catalog_root=self.catalog.root)
        args=lab.parser().parse_args(['run','--project',str(self.project),'--secrets-dir',str(self.store),
            '--catalog-dir',str(self.catalog.root),'--session','fixture'])
        args.compiled_plan=str(Path(compiled['root'])/'plan.json');args._explicit_options=()
        root=self.root/'prepared-dispatch-attempt';root.mkdir(mode=0o700)
        attempt=SimpleNamespace(root=root,record={},persist=mock.Mock())
        with mock.patch.object(lab,'probe_image',side_effect=AssertionError('No probe')) as probe:
            application_dispatch.prepare(args,attempt,lab)
            self.assertEqual(args.browser_sandbox_policy,'docker-default')
            view,names=indexed.application_admission_view(args,lab,args._indexed_bindings)
        probe.assert_not_called();self.assertEqual(names,['participant'])
        self.assertEqual(view['application_plan'],compiled['plan'])
        with mock.patch.object(lab,'require_host') as host,\
             mock.patch.object(lab,'docker_info',return_value={'NCPU':32,'MemTotal':64*1024**3}):
            args.native_platform='linux/arm64';args.resource_report={'requested':args._resource_request,'effective':args._resource_request}
            selected,worker=indexed.capacity(args,lab,native=True)
        self.assertEqual(worker,{'cpu_millis':2000,'memory_mib':2048,'pids_limit':256})
        self.assertEqual(selected['aggregate']['cpu_millis'],3250)


if __name__=='__main__':unittest.main()
