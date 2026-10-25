"""Parent application cohort: actual IR/authority/service, mocked owned boundary.

No Docker, model, browser, network or Pi process is executed.
"""
import copy
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import agent_profiles
import application_contracts as c
import application_execution
import ownership_registry
import parallel_application as app
import parallel_contract
import resources
import secret_store
import stage_control as controls
import test_application_preparation as preparation_fixture
import test_application_execution as helper_fixture
import test_application_client_authority as private_fixture
import test_application_compiler as compiler_fixture
import application_preparation


def fresh():return str(uuid.uuid4())


class ParallelApplicationTests(unittest.TestCase):
    def setUp(self):
        self.fixture=preparation_fixture.PreparationTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        if getattr(self,'source_factory',None):self.fixture.source=self.source_factory();self.fixture.write('source.json',self.fixture.source)
        self.root=self.fixture.root
        if getattr(self,'corpus_canary',None):
            asset=self.fixture.source['checks'][0]['scorer']['assets'][0]['source']
            (self.fixture.inputs/asset).write_bytes(b'# '+self.corpus_canary.encode()+b'\n')
        if getattr(self,'variant_mode',False):
            self.fixture.source['runtime']['inference_owner']='experiment_variant';self.fixture.write('source.json',self.fixture.source)
            endpoint=app.application_preparation.pi_lab.normalize_endpoint(self.fixture.endpoint)
            compiled=application_preparation.compile_variant_artifact(self.fixture.spec,self.root/'compiled',self.fixture.runtime_path,
                variant_id='candidate',bindings={stage['id']:{'kind':'legacy','endpoint':endpoint} for stage in self.fixture.source['stages']})
        else:compiled=self.fixture.compile()
        self.plan=compiled['plan'];self.compiled=Path(compiled['root'])
        self.project=self.root/'project';self.project.mkdir(mode=0o700);(self.project/'original.txt').write_text('original')
        self.store=self.root/'store'
        secret_store.write_secret('DIAGNOSTIC_ALICE',private_fixture.KEY_A,self.store)
        secret_store.write_secret('DIAGNOSTIC_BOB',private_fixture.KEY_B,self.store)
        self.trial=fresh();self.cell={'trial_id':self.trial,'plan':'compiled/plan.json','compiled_plan':'compiled/plan.json',
            'plan_sha256':self.plan['plan_sha256'],'source':'project'}
        self.matrix={'cells':[self.cell]};runtime=self.plan['runtime'];worker=parallel_contract.worker_weight(runtime['resources'])
        if getattr(self,'variant_mode',False):self.cell['variant']='candidate'
        native=parallel_contract.NATIVE_HELPER_RESOURCES;aggregate={key:2*(worker[key]+native[key])+{'cpu_millis':250,'memory_mib':128,'pids_limit':64}[key] for key in worker}
        self.metadata={'execution':{'image':runtime['image_id'],'platform':'linux/arm64','profile':runtime['container_profile'],
            'resources':runtime['resources']},'concurrency':{'native_budget':{'schema':1,'helpers_per_trial':1,'resources':native}}}
        if getattr(self,'fixed_resources',False):
            del self.metadata['execution']['resources'];controls.atomic(self.root/'inputs/resources.json',runtime['resources'])
        inference=c.loads((self.compiled/'inference.json').read_bytes())
        if inference['kind']=='variant':inference=inference['stages'][self.plan['stages'][0]['id']]
        self.entries={self.trial:{'plan':self.plan,'endpoint':inference['configuration'],'inference_key':private_fixture.INFERENCE_KEY,
            'store':self.store,'project':self.project,'browser_admission':None,
            'inference_authorities':{stage['inference_binding']['configuration_sha256']:{'reference':inference['configuration']['api_key_env'],
                'value':private_fixture.INFERENCE_KEY} for stage in self.plan['stages']}}}
        policy=runtime['resources'];self.args=SimpleNamespace(platform='linux/arm64',native_platform='linux/arm64',
            profile=runtime['container_profile'],observed_pi_version=runtime['pi_release'],in_place=False,
            resource_report={'effective':copy.deepcopy(policy)},**policy['runtime'])
        self.registry=SimpleNamespace(generation='generation',registry_id='registry',daemon='daemon',records=[])
        self.registry.load=lambda:list(self.registry.records)
        token=ownership_registry.CURRENT.set(self.registry);self.addCleanup(ownership_registry.CURRENT.reset,token)
        self.lab=mock.Mock();self.helpers=[]
        def start(authority,**kwargs):
            authority.revalidate();authority.preflight_bootstrap();slot=kwargs['allocator']
            class HelperAllocator:
                @property
                def records(self):return slot.records
                def request(self,identity,binding,resources,wait_seconds,kind='stage'):
                    self_case.assertEqual(kind,'helper')
                    return slot.request(identity,{'generation':self_case.registry.generation,
                        'credential_authorities':authority.launch_spec()['actors'],'plan_sha256':authority.plan['plan_sha256']},resources,wait_seconds,kind)
                def __getattr__(self,name):return getattr(slot,name)
            self_case=self;kwargs['allocator']=HelperAllocator()
            helper=helper_fixture.HelperFixture(authority,**kwargs);self.helpers.append(helper);return helper
        patch=mock.patch.object(application_execution.OwnedHelper,'start',side_effect=start);self.start=patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(application_execution,'helper_control',side_effect=lambda helper,body:helper.control(body));patch.start();self.addCleanup(patch.stop)
        self.addCleanup(lambda:[helper.service.close() for helper in self.helpers])
        self.cohort=app.ApplicationCohort(self.root,self.metadata,self.matrix,[self.cell],self.lab,self.args,self.registry,
            authorities_by_trial=self.entries,redaction_values=[private_fixture.INFERENCE_KEY,*getattr(self,'extra_global',[])],per_trial_redaction={self.trial:['delegated-token-123456']})
        self.pool=self.cohort.allocator(aggregate);self.cohort.attach(self.pool);self.cohort.admit_release(runtime['pi_release'])
        self.runid,self.attempt=fresh(),fresh();self.run=self.root/'runs'/self.runid;self.run.mkdir(parents=True,mode=0o700)
        (self.run/'workspace').mkdir(mode=0o700);controls.atomic(self.run/'plan.json',self.plan)
        controls.atomic(self.run/'identity.json',{'run_id':self.runid,'attempt_id':self.attempt})
        import pi_lab
        pi_lab.trusted_runtime(self.run);agent_profiles.freeze(self.cohort.profiles[self.trial],self.run/'agent-profile')
        binding={'generation':self.registry.generation,'run_id':self.runid,'attempt_id':self.attempt,'trial_id':self.trial,
            'workspace':str(self.run/'workspace'),'credential_authorities':self.cohort.authorities(self.trial)}
        reservation=self.pool.request(self.trial,binding,worker,30);self.pool.dispatch()
        self.pool.consume(reservation.identity,reservation.capability,reservation.binding,reservation.resources);self.pool.running(reservation.identity)
        self.registry.records.append({'kind':'network','container':'owned-application-network','registry':'registry','generation':'generation',
            'daemon':'daemon','status':'running'})
        bootstrap={'intent':{'run_id':self.runid,'attempt_id':self.attempt,'trial_id':self.trial},'network':'owned-application-network',
            'credentials':{},'capability':reservation.capability,'inference':{'token':'delegated-token-123456'}}
        self.peer=SimpleNamespace(bootstrap=bootstrap,allocator=self.pool,reservation=reservation,registry=self.registry,runroot=self.run,
            active=None,records=[])
        self.adapter=self.cohort.bind(self.peer);self.peer.native_budget=self.adapter

    def begin(self):
        stage=self.plan['stages'][0];stageid,segment,session=fresh(),fresh(),fresh()
        folder=self.run/'controls'/stageid/'segments'/segment;folder.mkdir(parents=True,mode=0o700)
        desc={'run_id':self.runid,'attempt_id':self.attempt,'stage_id':stageid,'kind':'agent',
            'workspace':str(self.run/'workspace'),'control':str(self.run/'controls'/stageid),'label':'agent-1-'+stage['id']}
        parent=self.run/'stages'/stageid;parent.mkdir(parents=True);controls.atomic(parent/'descriptor.json',desc)
        controls.atomic(parent/'state.json',{'status':'running','cleanup_confirmed':False})
        binding={'run_id':self.runid,'attempt_id':self.attempt,'trial_id':self.trial,'stage_id':stageid,'segment_id':segment,
            'session_id':session,'plan_sha256':self.plan['plan_sha256']}
        reply=self.adapter.begin(stage['id'],binding)
        task={**self.adapter.coordinator.task,'session_id':session,'pi_release':self.cohort.release,
            'allowed_tools':stage['tools'],'release_contract':app.release_contracts.identity(self.cohort.release),
            'application_context':'/opt/pi-control/segments/'+segment+'/application-context.json',
            'agent_profile_context':'/opt/pi-control/segments/'+segment+'/profile-context.json'}
        controls.atomic(folder/'task.json',task,0o644)
        argv=['docker','run','/opt/pi-lab/worker.py','agent','--task','/opt/pi-control/segments/'+segment+'/task.json']
        return binding,desc,reply,task,argv

    def finalized(self,binding,desc,reply):
        self.adapter.checkpoint(binding['stage_id']);closed=self.adapter.close(binding['stage_id'])
        controls.atomic(self.run/'stages'/binding['stage_id']/'state.json',{'status':'finalized','cleanup_confirmed':True})
        controls.atomic(self.run/'stages'/binding['stage_id']/'application-credentials.json',{'schema':1,'status':'removed','workspace':'clean'})
        target=self.run/desc['label'];target.mkdir()
        controls.atomic(target/'process.json',{'cleanup_confirmed':True,'exit_code':0,'termination_reason':'completed',
            'application_helper_cleanup':closed['cleanup'],'evidence':{'completion_verified':True}})
        return closed

    def test_parent_stage_grant_reuses_exact_buddy_and_worker_and_never_bootstraps_keys(self):
        original_worker=self.peer.reservation;binding,desc,reply,task,argv=self.begin()
        self.assertEqual(set(reply),{'context','network','binding','budget'})
        self.assertEqual(len(self.pool.records),2);self.assertIs(self.adapter.coordinator.reservation,original_worker)
        self.assertEqual(self.pool.buddies[self.trial].resources,parallel_contract.NATIVE_HELPER_RESOURCES)
        self.adapter.validate_agent_launch(argv,{key:binding[key] for key in ('stage_id','segment_id')})
        self.assertTrue(self.adapter.coordinator._running)
        body=json.dumps(reply)+json.dumps(self.peer.bootstrap)
        for key in (private_fixture.KEY_A,private_fixture.KEY_B,private_fixture.INFERENCE_KEY):self.assertNotIn(key,body)
        self.assertNotIn(self.adapter.coordinator.authority._control_token,body)

    def test_held_slot_rejects_actor_binding_and_resource_expansion(self):
        slot=self.adapter.slot;expected={'generation':'generation','credential_authorities':slot.actors,'plan_sha256':self.plan['plan_sha256']}
        for mutation in ('actors','weight'):
            binding=copy.deepcopy(expected);weight=copy.deepcopy(self.cohort.resource_class)
            if mutation=='actors':binding['credential_authorities']=[]
            else:weight['memory_mib']+=1
            with self.subTest(mutation=mutation),self.assertRaises(parallel_contract.ParallelError):slot.request('foreign',binding,weight,30,'helper')
        self.assertEqual(len(self.pool.records),2);self.start.assert_not_called()

    def test_worker_authorities_serialize_reference_names_and_exact_participant_tuple(self):
        tags=self.cohort.authorities(self.trial)
        for reference in self.plan['application']['credentials'].values():self.assertIn(reference,tags)
        for stage in self.plan['stages']:self.assertIn('application-actor:'+c.digest(stage['participant']),tags)
        for key in (private_fixture.KEY_A,private_fixture.KEY_B,private_fixture.INFERENCE_KEY):self.assertNotIn(key,json.dumps(tags))

    def test_each_parent_authority_pins_the_exact_compiled_runner_inventory(self):
        inventory=application_preparation.load_compiled(self.compiled/'plan.json')['manifest']['runner']['files']
        self.assertEqual(self.cohort.runner_files[self.trial],inventory)
        self.assertEqual(self.cohort.admissions[self.trial]._runner_files,inventory)
        self.assertEqual(c.digest(inventory),self.plan['input_hashes']['runner'])
        self.begin();self.assertEqual(self.adapter.coordinator.authority._runner_files,inventory)
        self.assertIsNot(self.adapter.coordinator.authority._runner_files,self.cohort.runner_files[self.trial])

    def test_raw_keys_or_wrong_withheld_marker_in_bootstrap_are_denied(self):
        for mutation in ('key','marker'):
            peer=copy.copy(self.peer);peer.bootstrap=copy.deepcopy(self.peer.bootstrap)
            if mutation=='key':peer.bootstrap['credentials']={'stage':{'PI_APP_KEY':private_fixture.KEY_A}}
            else:peer.bootstrap['application']['participant_keys_withheld']=False
            existing=self.cohort.peers.pop(self.trial)
            with self.subTest(mutation=mutation),self.assertRaises(parallel_contract.ParallelError):self.cohort.bind(peer)
            self.cohort.peers[self.trial]=existing

    def test_task_or_context_tampering_is_rejected_before_parent_launch(self):
        binding,desc,reply,task,argv=self.begin();task['prompt']='unreviewed'
        folder=Path(desc['control'])/'segments'/binding['segment_id'];controls.atomic(folder/'task.json',task)
        with self.assertRaises(parallel_contract.ParallelError):self.adapter.validate_agent_launch(argv,{key:binding[key] for key in ('stage_id','segment_id')})
        self.assertTrue(self.pool.closed);self.assertFalse(self.pool.dependent_cleanup_confirmed)
        with self.assertRaises(parallel_contract.ParallelError):self.adapter.finalize()
        self.assertEqual(self.helpers[0].record['status'],'released')
        self.assertFalse(self.helpers[0].private_root.exists())

    def test_checkpoint_requires_parent_observed_participant_absence(self):
        binding,_,_,_,_=self.begin();self.peer.active={'status':'running'}
        with self.assertRaises(parallel_contract.ParallelError):self.adapter.checkpoint(binding['stage_id'])
        self.assertFalse(self.pool.dependent_cleanup_confirmed)

    def test_incomplete_report_does_not_become_uncertain_physical_cleanup_at_finalize(self):
        binding,desc,reply,task,argv=self.begin();self.adapter.validate_agent_launch(argv,{key:binding[key] for key in ('stage_id','segment_id')})
        closed=self.finalized(binding,desc,reply)
        self.assertEqual(set(closed),{'budget','cleanup','completion_context'})
        self.assertTrue(closed['cleanup']['safe_to_continue']);self.assertEqual(self.pool.buddies[self.trial].state,'reserved')
        self.assertTrue(self.adapter.finalize());self.assertEqual(self.pool.buddies[self.trial].state,'released')
        self.assertTrue(getattr(self.pool,'dependent_cleanup_confirmed',True));self.assertEqual(self.peer.reservation.state,'running')

    def test_missing_finalized_credential_proof_quarantines_before_network_release(self):
        binding,desc,reply,_,_=self.begin();self.finalized(binding,desc,reply)
        controls.atomic(self.run/'stages'/binding['stage_id']/'application-credentials.json',{'schema':1,'status':'quarantined','workspace':'quarantined'})
        with self.assertRaises(parallel_contract.ParallelError):self.adapter.finalize()
        self.assertFalse(self.pool.dependent_cleanup_confirmed);self.assertEqual(self.registry.records[0]['status'],'running')

    def test_uniform_helper_class_and_authority_plan_mismatch_deny_before_owned_start(self):
        for mutation in ('helper','plan'):
            metadata=copy.deepcopy(self.metadata);entries=copy.deepcopy(self.entries)
            if mutation=='helper':metadata['concurrency']['native_budget']['resources']=parallel_contract.NATIVE_BROWSER_HELPER_RESOURCES
            else:entries[self.trial]['plan']['plan_sha256']='f'*64
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):app.ApplicationCohort(self.root,metadata,self.matrix,[self.cell],self.lab,self.args,self.registry,
                authorities_by_trial=entries,redaction_values=[private_fixture.INFERENCE_KEY],per_trial_redaction={})
        self.start.assert_not_called()

    def test_stage_reopen_and_foreign_trial_binding_never_start_second_helper(self):
        binding,desc,reply,_,_=self.begin();self.finalized(binding,desc,reply)
        with self.assertRaises(parallel_contract.ParallelError):self.adapter.begin(self.plan['stages'][0]['id'],binding)
        self.assertEqual(len(self.helpers),1)

    def test_model_activation_is_bound_to_frozen_stage_and_stopped_segment(self):
        name=self.plan['stages'][0]['id']
        peer=self.cohort.peers.pop(self.trial)
        try:
            self.assertTrue(self.cohort.admit_inference_stage(self.trial,name))
            with self.assertRaises(parallel_contract.ParallelError):self.cohort.admit_inference_stage(self.trial,name,True)
            with self.assertRaises(parallel_contract.ParallelError):self.cohort.admit_inference_stage(self.trial,'foreign')
        finally:self.cohort.peers[self.trial]=peer
        self.assertTrue(self.cohort.admit_inference_stage(self.trial,name))
        with self.assertRaises(parallel_contract.ParallelError):self.cohort.admit_inference_stage(self.trial,'foreign')
        binding,_,_,_,_=self.begin()
        with self.assertRaises(parallel_contract.ParallelError):self.cohort.admit_inference_stage(self.trial,name,True)
        self.adapter.checkpoint(binding['stage_id'])
        self.assertTrue(self.cohort.admit_inference_stage(self.trial,name,True))
        with self.assertRaises(parallel_contract.ParallelError):self.cohort.admit_inference_stage(self.trial,name,True)

    def test_explicit_continuation_keeps_parent_ledger_and_validates_exact_message(self):
        binding,desc,_,task,argv=self.begin();self.adapter.validate_agent_launch(argv,{key:binding[key] for key in ('stage_id','segment_id')})
        self.adapter.checkpoint(binding['stage_id']);co=self.adapter.coordinator
        command=helper_fixture.ApplicationCoordinatorTests.command(SimpleNamespace(run=self.run,desc=desc),co,'steer',message='Explicit retained parent message')
        nextid=fresh();folder=Path(desc['control'])/'segments'/nextid;folder.mkdir(mode=0o700)
        reply=self.adapter.continuation(binding['stage_id'],command['id'],nextid)
        self.assertEqual(len(self.helpers),1);self.assertEqual(reply['budget']['counts']['charged'],0)
        task['application_context']='/opt/pi-control/segments/'+nextid+'/application-context.json'
        task['agent_profile_context']='/opt/pi-control/segments/'+nextid+'/profile-context.json'
        task['application_continuation']=copy.deepcopy(self.adapter.continuation_proof)
        task['resume_session']='/opt/pi-control/segments/'+nextid+'/session.jsonl'
        controls.atomic(folder/'task.json',task,0o644);nextargv=[*argv[:-1],'/opt/pi-control/segments/'+nextid+'/task.json']
        scope={'stage_id':binding['stage_id'],'segment_id':nextid}
        self.adapter.validate_agent_launch(nextargv,scope)
        task['application_continuation']['message']='Unapproved replacement';controls.atomic(folder/'task.json',task,0o644)
        with self.assertRaises(parallel_contract.ParallelError):self.adapter.validate_agent_launch(nextargv,scope)


class ArtifactAdmissionTests(unittest.TestCase):
    def test_actual_variant_and_fixed_resource_file_are_admitted(self):
        case=ParallelApplicationTests();case.variant_mode=True;case.fixed_resources=True
        try:
            case.setUp();binding,_,reply,_,_=case.begin()
            self.assertEqual(reply['binding'],binding);self.assertNotIn('resources',case.metadata['execution'])
            self.assertEqual(case.plan['stages'][0]['inference_binding']['selection']['owner'],'experiment_variant')
        finally:case.doCleanups()

    def test_global_cross_trial_key_in_frozen_scorer_asset_blocks_before_helper(self):
        case=ParallelApplicationTests();case.corpus_canary='other-trial-application-authority-928341'
        case.extra_global=[case.corpus_canary]
        try:
            with self.assertRaises(parallel_contract.ParallelError):case.setUp()
            case.start.assert_not_called()
        finally:case.doCleanups()


class PredecessorGateTests(unittest.TestCase):
    def setUp(self):
        def source():
            value=compiler_fixture.two_stages();second=value['stages'][1]
            second['depends_on']=[value['stages'][0]['id']]
            second['operations']=[name for name in second['operations'] if name!='publish-summary']
            second['completion']['publications']=[];second['completion']['artifacts'][0]['id']='second-summary'
            second['input_artifacts']=[{'stage_id':value['stages'][0]['id'],'artifact_id':'summary'}]
            return value
        self.case=ParallelApplicationTests();self.case.source_factory=source;self.case.setUp();self.addCleanup(self.case.doCleanups)

    def successor(self):
        case=self.case;stage=case.plan['stages'][1];sid,segment,session=fresh(),fresh(),fresh()
        folder=case.run/'controls'/sid/'segments'/segment;folder.mkdir(mode=0o700,parents=True)
        desc={'run_id':case.runid,'attempt_id':case.attempt,'stage_id':sid,'kind':'agent','workspace':str(case.run/'workspace'),
            'control':str(case.run/'controls'/sid),'label':'agent-2-'+stage['id']}
        path=case.run/'stages'/sid;path.mkdir(parents=True);controls.atomic(path/'descriptor.json',desc)
        controls.atomic(path/'state.json',{'status':'running','cleanup_confirmed':False})
        binding={'run_id':case.runid,'attempt_id':case.attempt,'trial_id':case.trial,'stage_id':sid,'segment_id':segment,
            'session_id':session,'plan_sha256':case.plan['plan_sha256']}
        return stage,binding

    def test_child_complete_flag_cannot_override_independent_missing_report(self):
        case=self.case;binding,desc,reply,_,_=case.begin();case.finalized(binding,desc,reply)
        path=case.run/desc['label']/'process.json';record=c.loads(path.read_bytes())
        record['application_completion']={'status':'complete'};controls.atomic(path,record)
        stage,nextbinding=self.successor()
        with self.assertRaises(parallel_contract.ParallelError):case.adapter.begin(stage['id'],nextbinding)
        self.assertEqual(len(case.helpers),1);self.assertTrue(case.pool.closed)
        self.assertTrue(getattr(case.pool,'dependent_cleanup_confirmed',True))
        self.assertTrue(case.adapter.finalize())

    def test_clean_parent_oracle_boundary_seals_bytes_into_next_authority(self):
        case=self.case;binding,desc,reply,_,_=case.begin();closed=case.finalized(binding,desc,reply)
        stage=case.plan['stages'][0];body=b'# independently checked fixture bytes\n'
        root=Path(closed['completion_context']['report_root']);artifact=stage['completion']['artifacts'][0]
        target=root/artifact['path'];target.parent.mkdir(mode=0o700,parents=True,exist_ok=True);target.write_bytes(body)
        report={'schema':1,'document_type':'application_completion_report','contract_id':stage['completion']['id'],
            'participant':stage['participant'],'artifacts':[{'id':artifact['id'],'path':artifact['path'],'bytes':len(body),
                'sha256':__import__('hashlib').sha256(body).hexdigest()}],'pagination':{},'publications':[],'unresolved':[]}
        (root/stage['completion']['report_path']).write_bytes(c.canonical(report))
        successor,binding2=self.successor()
        # The positive ownership oracle is deliberately controlled here; the
        # preceding test invokes the real A03 evaluator and rejects a child lie.
        with mock.patch.object(app.application_completion,'stage_result',return_value={'projection':{'stage':stage['id'],'status':'complete'}}):
            case.adapter.begin(successor['id'],binding2)
        self.assertEqual(len(case.helpers),2);self.assertEqual(case.adapter.sealed[(stage['id'],artifact['id'])],body)
        self.assertEqual(case.adapter.coordinator.authority._sealed_inputs[0]['content'],body.decode())
        self.assertEqual(len(case.pool.records),2);self.assertEqual(case.peer.reservation.state,'running')


if __name__=='__main__':unittest.main()
