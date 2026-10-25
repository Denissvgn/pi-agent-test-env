"""A10 frozen-topology/private-Peer fixtures; all Docker/helper effects mocked."""
import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile
import time
import types
import unittest
from unittest import mock
from unittest.mock import Mock
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_contracts as c
from application_client import Grant
import experiments
import native_budget_controls
import ownership_registry
import parallel_contract
from parallel_contract import ParallelError
from parallel_dispatch import Peer,RemoteAdmission
import parallel_native_budget as native
import parallel_execution
import inference_broker
import inference_gateway
import pi_lab as lab
import resources
import stage_control as controls
from test_experiments import ExperimentFixture
from test_parallel_contract import selected

FOOTPRINT={'cpu_millis':1000,'memory_mib':512,'pids_limit':128}


def topology():
    return {'schema':1,'helpers_per_trial':1,'resources':dict(FOOTPRINT)}


class TopologyTests(unittest.TestCase):
    def test_explicit_browser_buddy_uses_reviewed_footprint_and_reuses_exact_slot(self):
        footprint=parallel_contract.NATIVE_BROWSER_HELPER_RESOURCES
        pool=native.NativeAllocator({'cpu_millis':8000,'memory_mib':8192,'pids_limit':2048},
            native_trials={'a'},generation='owner',helper_resources=footprint)
        pool.request('a',{}, {'cpu_millis':1000,'memory_mib':128,'pids_limit':64},30);pool.dispatch()
        buddy=pool.buddies['a'];self.assertEqual(buddy.resources,footprint)
        view=native._HeldHelperSlot(pool,'a','a'*64)
        binding={'generation':'owner','credential_authorities':[],'plan_sha256':'a'*64}
        with self.assertRaises(ParallelError):view.request('wrong-size',binding,FOOTPRINT,30)
        self.assertIs(view.request('owned-browser',binding,footprint,30),buddy)
        self.assertEqual(len(pool.records),2)

    def test_native_nonindexed_gateway_uses_monitored_revocation_file_and_legacy_does_not(self):
        for opted in (False,True):
            with self.subTest(native=opted),tempfile.TemporaryDirectory(dir='/private/tmp') as directory:
                path=Path(directory)/'active-tokens.json';captured={};revision=0
                @contextmanager
                def owner(lab,args,root,registry,pool,weight,config,*unused):
                    nonlocal revision
                    captured.update(copy.deepcopy(config))
                    if config.get('active_tokens_file'):captured['active_tokens_file']=str(path)
                    controls.atomic(path,{'revision':0,'tokens':[]})
                    def activate(values):
                        nonlocal revision
                        revision+=1;controls.atomic(path,{'revision':revision,'tokens':list(values)})
                    inference={'trial':lambda intent:{'token':next(token for token,trial in config['tokens'].items() if trial==intent['trial_id'])},
                        'activate':activate,'admit':lambda:None}
                    yield inference,lambda intent:None,lambda network:None
                registry=types.SimpleNamespace()
                if opted:registry._native_budget_cohort=types.SimpleNamespace(add_redaction_values=Mock())
                work=[{'trial_id':'one','endpoint':'endpoint.json'},{'trial_id':'two','endpoint':'endpoint.json'}]
                metadata={'execution':{'image':'frozen-image'},'concurrency':{'gateway':{}}}
                with mock.patch.object(inference_broker,'owner',owner):
                    with parallel_execution.gateway_owner(Mock(),Mock(),Path(directory),metadata,work,registry,Mock(),{},'synthetic-original') as result:
                        inference=result[0]
                        self.assertEqual('active_tokens_file' in captured,opted)
                        if not opted:
                            self.assertNotIn('stage_release',inference);continue
                        first=inference['trial']({'trial_id':'one'})['token']
                        second=inference['trial']({'trial_id':'two'})['token']
                        # Exercise the actual gateway authorization method and
                        # secure activation file, with no HTTP/model or Docker.
                        handler=inference_gateway.handler(captured,inference_gateway.Gate({}))
                        request=types.SimpleNamespace(headers={'Authorization':'Bearer '+first})
                        self.assertEqual(handler.authorized(request),first)
                        inference['stage_release']('one')
                        self.assertIsNone(handler.authorized(request))
                        request.headers={'Authorization':'Bearer '+second}
                        self.assertEqual(handler.authorized(request),second)
                        revision+=1;controls.atomic(path,{'revision':revision,'tokens':[]})
                        self.assertIsNone(handler.authorized(request))

    def test_absent_legacy_contract_bytes_and_capacity_view_are_unchanged(self):
        source=selected(); before=json.dumps(source,separators=(',',':')).encode()
        self.assertEqual(json.dumps(parallel_contract.validate(source),separators=(',',':')).encode(),before)
        self.assertIsNone(parallel_contract.native_helper(source))
        policy=resources.validate_policy({'runtime':{'cpus':1,'memory':'1536m','pids_limit':512,'jobs':1}})
        view=parallel_contract.admit_capacity(source,policy,{'NCPU':16,'MemTotal':16*1024**3})
        self.assertEqual(set(view),{'worker','gateway','aggregate','host_generation'})

    def test_explicit_native_footprint_requires_room_without_autogrowing_aggregate(self):
        source=selected(); source['native_budget']=topology(); before=copy.deepcopy(source)
        policy=resources.validate_policy({'runtime':{'cpus':1,'memory':'128m','pids_limit':64,'jobs':1}})
        with self.assertRaises(ParallelError):parallel_contract.admit_capacity(source,policy,{'NCPU':16,'MemTotal':8*1024**3})
        self.assertEqual(source,before)
        source['aggregate']={'cpu_millis':4250,'memory_mib':1408,'pids_limit':448}
        view=parallel_contract.admit_capacity(source,policy,{'NCPU':16,'MemTotal':8*1024**3})
        self.assertEqual(view['native_budget'],FOOTPRINT)
        for field,value in [('schema',True),('helpers_per_trial',2),('resources',{**FOOTPRINT,'cpu_millis':500})]:
            bad=copy.deepcopy(source);bad['native_budget'][field]=value
            with self.assertRaises(ParallelError):parallel_contract.validate(bad)
        bad=copy.deepcopy(source);bad['native_budget']['extra']='never admitted'
        with self.assertRaises(ParallelError):parallel_contract.validate(bad)

    def test_fifo_buddies_precede_workers_and_no_third_helper_steals_a_live_slot(self):
        pool=native.NativeAllocator({'cpu_millis':16000,'memory_mib':8192,'pids_limit':4096},
            native_trials={'a','b','c','d'},generation='owner',max_pending=4)
        worker={'cpu_millis':1000,'memory_mib':128,'pids_limit':64}
        for name in ('a','b','c','d'):pool.request(name,{'generation':'owner'},worker,30)
        pool.dispatch()
        self.assertEqual([item for item in pool.queue],['c-native-budget','c','d-native-budget','d'])
        self.assertEqual(sum(item.kind=='stage' and item.state=='reserved' for item in pool.records.values()),2)
        self.assertEqual(sum(item.kind=='helper' and item.state=='reserved' for item in pool.records.values()),2)
        self.assertEqual(pool.records['a-native-budget'].state,'reserved')
        # Held allocator view reuses the same slot for a later stage, with no
        # younger queued worker blocking helper admission and no new reservation.
        view=native._HeldHelperSlot(pool,'a','a'*64)
        binding={'generation':'owner','credential_authorities':[],'plan_sha256':'a'*64}
        first=view.request('physical-helper-1',binding,FOOTPRINT,30)
        view.consume(first.identity,first.capability,first.binding,first.resources);view.running(first.identity)
        used=pool.used();view.release(first.identity,True,True)
        self.assertEqual(pool.used(),used)
        second=view.request('physical-helper-2',binding,FOOTPRINT,30)
        self.assertIs(first,second);self.assertEqual(len(pool.records),8)
        view.consume(second.identity,second.capability,second.binding,second.resources);view.running(second.identity)
        view.release(second.identity,True,True);view.finalize()
        pool.release('a',True,True);pool.dispatch()
        self.assertEqual(pool.records['c'].state,'reserved')

    def test_unknown_helper_cleanup_quarantines_weight_and_stops_dispatch(self):
        pool=native.NativeAllocator({'cpu_millis':3000,'memory_mib':1024,'pids_limit':512},
            native_trials={'a'},generation='owner')
        pool.request('a',{'generation':'owner'},{'cpu_millis':1000,'memory_mib':128,'pids_limit':64},30)
        pool.dispatch();view=native._HeldHelperSlot(pool,'a','a'*64)
        row=view.request('helper',{'generation':'owner','credential_authorities':[],'plan_sha256':'a'*64},FOOTPRINT,30)
        view.consume(row.identity,row.capability,row.binding,row.resources);view.running(row.identity)
        before=pool.used();self.assertFalse(view.release(row.identity,False,False))
        self.assertTrue(pool.closed);self.assertEqual(row.state,'quarantined');self.assertEqual(pool.used(),before)


def empty_snapshot(authority):
    fields=('attempted','charged','executed_known','executed_unknown','grants_consumed','blocked',
            'worker_observed','helper_verified','executed')
    counters={name:0 for name in fields};maximum=authority.limits['max_tool_calls']
    return {'schema':1,'document_type':'native_tool_budget_status','phase':'business','accounting':'available',
        'limits':dict(authority.limits),'counts':dict(counters),
        'per_tool':{name:dict(counters) for name in [*[tool['name'] for tool in authority.tools],'__unknown__']},
        'remaining_calls':maximum,'remaining_admissible_calls':maximum,
        'business_calls_remaining':maximum-authority.limits['reporting_reserve_calls'],
        'reporting_reserve_calls_remaining':authority.limits['reporting_reserve_calls'],'assisted':False}


class SimulatedHelper:
    def __init__(self,authority,*,lab,args,registry,allocator,participant_resources,participant_reservation,borrowed_network):
        self.authority=authority;self.view=allocator;self.events=[];self.receipt=None
        self.borrowed_network=borrowed_network;self.participant_reservation=participant_reservation
        self.row=allocator.request('synthetic-helper',{'generation':registry.generation,'credential_authorities':[],
            'plan_sha256':authority.plan_sha256},FOOTPRINT,30,'helper')
        allocator.consume(self.row.identity,self.row.capability,self.row.binding,self.row.resources);allocator.running(self.row.identity)
        authority._launched=True;self.budget=empty_snapshot(authority)
    def native_budget_status(self):return copy.deepcopy(self.budget)
    def checkpoint_native_budget(self):self.events.append('checkpoint');return self.native_budget_status()
    def extend_native_budget(self,*,max_tool_calls,remaining_seconds):
        self.events.append(('extend',max_tool_calls,remaining_seconds));self.budget['limits']['max_tool_calls']=max_tool_calls
        remaining=max_tool_calls-self.budget['counts']['charged'];self.budget['remaining_calls']=remaining
        self.budget['remaining_admissible_calls']=remaining if self.budget['phase']!='exhausted' else 0
        self.budget['business_calls_remaining']=max(0,remaining-self.budget['limits']['reporting_reserve_calls']) if self.budget['phase']=='business' else 0
        self.budget['reporting_reserve_calls_remaining']=min(remaining,self.budget['limits']['reporting_reserve_calls'])
        self.budget['assisted']=True;return self.native_budget_status()
    def continue_native_budget(self,segment_id,extension_order_sha256):
        self.events.append('continue');old=self.authority._grants[-1]
        self.authority._revoked.add(old.capability)
        grant=Grant({**old.scope,'segment_id':segment_id},secrets.token_hex(32));self.authority._grants.append(grant)
        self.authority._grant_digests[grant.capability]=c.digest(grant.scope)
        self.authority._budget_tokens[segment_id]=secrets.token_hex(32)
        return self.authority.budget_context(grant,extension_order_sha256)
    def revoke(self,grant):self.events.append('revoke');self.authority._revoked.add(grant.capability)
    def cleanup(self,*,writers_absent):
        if writers_absent is not True:raise ParallelError('Synthetic writer uncertainty')
        self.events.append('cleanup');self.view.release(self.row.identity,True,True)
        self.receipt={'schema':1,'status':'removed','workspace':'clean','safe_to_continue':True};return self.receipt
    def require_clean(self):
        if self.receipt is None:raise ParallelError('Synthetic cleanup unconfirmed')
        return True


class NativePeerTests(ExperimentFixture):
    def setUp(self):
        super().setUp();self.root=self.root.resolve()
        self.definition.update(schema=2,concurrency=selected());self.definition['concurrency']['native_budget']=topology()
        self.definition['concurrency']['aggregate']={'cpu_millis':4250,'memory_mib':1536,'pids_limit':512}
        self.definition['budgets']={'timeout_seconds':300,'max_turns':3,'max_total_tokens':10000,
            'max_tool_calls':6,'reporting_reserve_calls':2,'reporting_reserve_seconds':30}
        self.write('experiment.json',self.definition);self.prepare()
        self.exp=self.root/'prepared';self.metadata,self.matrix=experiments.verify(self.exp,lab);self.cell=self.matrix['cells'][0]
        self.registry=ownership_registry.Registry(self.root/'registry',command=mock.Mock())
        self.registry.daemon='controlled-daemon'
        self.args=experiments.trial_args(self.exp,self.metadata,self.cell,lab,None);self.args.native_platform='linux/arm64'
        self.helpers=[]
        def factory(*args,**kwargs):
            item=SimulatedHelper(*args,**kwargs);self.helpers.append(item);return item
        self.cohort=native.NativeCohort(self.exp,self.metadata,self.matrix,self.matrix['cells'],lab,self.args,self.registry,
            redaction_values=['synthetic-upstream-secret-123456'],helper_factory=factory)
        self.pool=self.cohort.allocator(self.metadata['concurrency']['aggregate'],2,16)
        self.cohort.attach(self.pool);self.cohort.admit_release('1.2.0')
        self.res=self.pool.request(self.cell['trial_id'],{'credential_authorities':[]},
            {'cpu_millis':1000,'memory_mib':128,'pids_limit':64},30);self.pool.dispatch()
        self.intent,_=experiments.reserve_attempt(self.exp,self.metadata,self.cell)
        self.run=self.exp/'runs'/self.intent['run_id'];self.run.mkdir(parents=True,mode=0o700)
        controls.atomic(self.run/'identity.json',{'schema':2,'run_id':self.intent['run_id'],'attempt_id':self.intent['attempt_id']})
        lab.snapshot(self.exp/self.cell['source'],self.run/'workspace',[],10)
        lab.trusted_runtime(self.run)
        self.res.binding={'generation':self.registry.generation,**{key:self.intent[key] for key in ('run_id','attempt_id','trial_id')},
            'workspace':str(self.run/'workspace'),'credential_authorities':[]}
        self.net=self.registry.network_intent('controlled-trial-network')
        bootstrap={'experiment':str(self.exp),'intent':self.intent,'network':self.net['container'],
            'inference':{'token':'synthetic-delegate-token-123456'},'credentials':{},'capability':self.res.capability}
        self.peer=Peer(bootstrap,self.registry,self.pool,self.res,self.metadata,self.run)
        self.peer.handle({'op':'enter','capability':self.res.capability})
        self.stage_id=str(uuid.uuid4());self.segment_id=str(uuid.uuid4())
        self.binding={**{key:self.intent[key] for key in ('run_id','attempt_id','trial_id')},
            'stage_id':self.stage_id,'segment_id':self.segment_id,'session_id':str(uuid.uuid4()),'plan_sha256':self.cell['plan_sha256']}
        self.control=self.run/'controls'/self.stage_id;self.control.mkdir(parents=True)
        (self.control/'inbox').mkdir();(self.control/'outbox').mkdir()
        task=self.cohort.plans[self.cell['trial_id']]['agents'][0]
        self.desc=controls.create(self.run,self.run/'workspace','agent-1-dev','agent',task,self.control,self.run/'state',
            self.stage_id,'controlled-worker')
        self.state=controls.transition(self.run,self.desc,'running',segment_id=self.segment_id)

    def begin(self):
        return self.peer.handle({'op':'native-budget-begin','stage_name':'dev','binding':self.binding})

    def test_legacy_budget_only_cohort_rejects_browser_helper_class_before_any_launch(self):
        metadata=copy.deepcopy(self.metadata)
        metadata['concurrency']['native_budget']['resources']=copy.deepcopy(parallel_contract.NATIVE_BROWSER_HELPER_RESOURCES)
        with self.assertRaises(ParallelError):native.NativeCohort(self.exp,metadata,self.matrix,self.matrix['cells'],lab,self.args,self.registry)
        self.assertEqual(self.helpers,[])

    def command(self,kind,payload,*,accepted=True,requested=True):
        state={**self.state,'segment_id':self.binding['segment_id']}
        record=controls.command_record(self.desc,state,kind,payload)
        # CLI requested data has a different digest from normalized acceptance.
        if requested:controls.audit(self.run,{**record,'payload_digest':'f'*64},'requested')
        if accepted:controls.audit(self.run,record,'accepted')
        folder=(self.run/'stages'/self.stage_id/'budget-requests' if kind=='extend_budget'
                else self.control/'inbox'/'directives')
        folder.mkdir(parents=True,exist_ok=True);controls.atomic(folder/(record['id']+'.json'),record)
        return record

    def test_parent_begin_sources_frozen_policy_and_reuses_verified_network_and_worker(self):
        before=len(self.pool.records);reply=self.begin()
        self.assertEqual(len(self.pool.records),before)
        self.assertIs(self.helpers[0].participant_reservation,self.res)
        self.assertEqual(self.helpers[0].borrowed_network,self.net)
        self.assertEqual(reply['network'],self.net['container']);self.assertEqual(reply['binding'],self.binding)
        self.assertEqual(reply['context']['scope']['stage_name'],'dev')
        self.assertEqual(reply['budget']['limits']['max_tool_calls'],6)
        self.assertNotIn('synthetic-upstream-secret-123456',json.dumps(reply))
        self.assertNotIn('synthetic-delegate-token-123456',json.dumps(reply))
        self.assertEqual(self.pool.records[self.cell['trial_id']+'-native-budget'].state,'running')

    def test_child_cannot_select_unfrozen_stage_runtime_limits_or_native_context(self):
        with self.assertRaises(ParallelError):self.peer.handle({'op':'native-budget-begin','stage_name':'dev','binding':self.binding,'limits':{'max_tool_calls':500}})
        foreign={**self.binding,'trial_id':str(uuid.uuid4())}
        with self.assertRaises(ParallelError):self.peer.handle({'op':'native-budget-begin','stage_name':'dev','binding':foreign})
        self.assertEqual(self.helpers,[]);self.assertTrue(self.pool.closed)

    def test_checkpoint_and_close_wait_for_confirmed_active_worker_absence(self):
        self.begin();helper=self.helpers[0]
        self.assertEqual(self.peer.handle({'op':'native-budget-checkpoint','stage_id':self.stage_id})['budget']['counts']['charged'],0)
        self.peer.active={'status':'running'}
        with self.assertRaises(ParallelError):self.peer.handle({'op':'native-budget-close','stage_id':self.stage_id})
        self.assertNotIn('cleanup',helper.events);self.assertTrue(self.pool.closed)
        self.assertEqual(helper.row.state,'quarantined')

    def test_clean_close_holds_same_buddy_until_parent_trial_finalization(self):
        self.begin();helper=self.helpers[0]
        reply=self.peer.handle({'op':'native-budget-close','stage_id':self.stage_id})
        self.assertTrue(reply['cleanup']['safe_to_continue']);self.assertEqual(helper.events,['revoke','cleanup'])
        self.assertEqual(helper.row.state,'reserved');self.assertNotEqual(self.res.state,'released')
        self.assertTrue(self.peer.finalize_native_budget());self.assertEqual(helper.row.state,'released')
        self.assertTrue(getattr(self.pool,'dependent_cleanup_confirmed',True))
        self.assertEqual(self.registry.load()[0]['status'],'intent') # Borrowed network was not removed.

    def test_extension_requires_retained_parent_request_acceptance_and_exact_payload(self):
        self.begin()
        budget={'schema':2,'revision':0,'started_host_monotonic':time.monotonic(),'effective_limits':{**self.definition['budgets']}}
        controls.atomic(self.run/'stages'/self.stage_id/'budget.json',budget)
        record=self.command('extend_budget',{'expected_budget_revision':0,'limits':{**self.definition['budgets'],'max_tool_calls':8}})
        reply=self.peer.handle({'op':'native-budget-extend','stage_id':self.stage_id,'command_id':record['id'],
            'max_tool_calls':8,'remaining_seconds':299.5})
        self.assertEqual(reply['budget']['limits']['max_tool_calls'],8)
        self.assertTrue(reply['budget']['assisted']);self.assertEqual(reply['budget']['phase'],'business')
        self.assertIsNone(self.helpers[0].events[-1][2])
        with self.assertRaises(ParallelError):self.peer.handle({'op':'native-budget-extend','stage_id':self.stage_id,
            'command_id':record['id'],'max_tool_calls':8,'remaining_seconds':299.5})

    def test_parent_approved_timeout_increase_sends_positive_remaining(self):
        self.begin()
        controls.atomic(self.run/'stages'/self.stage_id/'budget.json',{'schema':2,'revision':0,
            'started_host_monotonic':time.monotonic(),'effective_limits':{**self.definition['budgets']}})
        record=self.command('extend_budget',{'expected_budget_revision':0,
            'limits':{**self.definition['budgets'],'max_tool_calls':8,'timeout_seconds':330}})
        self.peer.handle({'op':'native-budget-extend','stage_id':self.stage_id,'command_id':record['id'],
            'max_tool_calls':8,'remaining_seconds':329.5})
        self.assertIsInstance(self.helpers[0].events[-1][2],float)
        self.assertGreater(self.helpers[0].events[-1][2],300)

    def test_missing_parent_authorization_cannot_grow_helper(self):
        self.begin();helper=self.helpers[0]
        record=self.command('extend_budget',{'expected_budget_revision':0,'limits':{**self.definition['budgets'],'max_tool_calls':8}},accepted=False)
        with self.assertRaises(ParallelError):self.peer.handle({'op':'native-budget-extend','stage_id':self.stage_id,
            'command_id':record['id'],'max_tool_calls':8,'remaining_seconds':299})
        self.assertFalse(any(type(event) is tuple and event[0]=='extend' for event in helper.events))
        self.assertTrue(self.pool.closed);self.assertNotIn('cleanup',helper.events)

    def test_explicit_continuation_carries_counters_and_rechecks_frozen_guard_bytes(self):
        initial=self.begin();record=self.command('steer',{'message':'Explicit reviewed continuation.','interrupt':False})
        new_segment=str(uuid.uuid4())
        reply=self.peer.handle({'op':'native-budget-continue','stage_id':self.stage_id,'command_id':record['id'],'segment_id':new_segment})
        self.assertEqual(reply['budget'],initial['budget']);self.assertEqual(reply['binding']['segment_id'],new_segment)
        self.assertEqual(reply['context']['scope']['session_id'],initial['context']['scope']['session_id'])
        self.assertNotEqual(reply['context']['capability'],initial['context']['capability'])
        self.assertEqual(len(self.helpers),1)

    def test_guard_content_changed_before_begin_rejects_before_helper_effects(self):
        runtime=self.run/'trusted-runtime';(runtime/'tool-budget.mjs').unlink()
        with self.assertRaises(ParallelError):self.begin()
        self.assertEqual(self.helpers,[]);self.assertTrue(self.pool.closed)

    def test_agent_launch_requires_exact_owner_only_context_even_if_child_supplies_path(self):
        reply=self.begin();segment=self.control/'segments'/self.segment_id;segment.mkdir(parents=True)
        path=segment/'budget-context.json';controls.atomic(path,reply['context'],0o400)
        task=copy.deepcopy(self.cohort.plans[self.cell['trial_id']]['agents'][0])
        task['native_budget_context']='/opt/pi-control/segments/'+self.segment_id+'/budget-context.json'
        controls.atomic(segment/'task.json',task,0o644)
        argv=lab.docker_args(self.args,self.metadata['execution']['image'],self.run/'workspace',self.control,
            self.run/'state','controlled-worker',self.net['container'],helpers=self.run/'trusted-runtime')
        argv+=['agent','--task','/opt/pi-control/segments/'+self.segment_id+'/task.json']
        self.peer.native_budget.validate_agent_launch(argv,{'stage_id':self.stage_id,'segment_id':self.segment_id})
        path.chmod(0o644)
        with self.assertRaises(ParallelError):self.peer.native_budget.validate_agent_launch(argv,{'stage_id':self.stage_id,'segment_id':self.segment_id})

    def test_failed_accounting_still_cleans_known_helper_after_writer_absence(self):
        self.begin();helper=self.helpers[0]
        with self.assertRaises(ParallelError):self.peer.native_budget._error()
        self.assertNotIn('cleanup',helper.events)
        with self.assertRaises(ParallelError):self.peer.finalize_native_budget()
        self.assertIn('cleanup',helper.events)
        self.assertTrue(self.peer.native_budget.finalized)
        self.assertEqual(helper.row.state,'released');self.assertTrue(self.pool.closed)
        self.assertTrue(getattr(self.pool,'dependent_cleanup_confirmed',True))

    def test_unknown_helper_cleanup_retains_dependent_gateway_and_network(self):
        self.begin();helper=self.helpers[0]
        with mock.patch.object(helper,'cleanup',side_effect=ParallelError('Synthetic cleanup uncertainty')):
            with self.assertRaises(ParallelError):self.peer.finalize_native_budget()
        self.assertFalse(self.pool.dependent_cleanup_confirmed)
        self.assertTrue(self.pool.closed);self.assertEqual(helper.row.state,'quarantined')
        self.assertEqual(self.registry.load()[0]['status'],'intent')

    def worker_record(self):
        return {'container':'synthetic-worker','image':'sha256:'+'b'*64,'launch_id':'launch',
            'registry':self.registry.registry_id,'status':'running',
            'mounts':[{'source':str(self.run/'workspace'),'target':'/workspace','rw':True}]}

    def test_crashed_controller_worker_cleanup_removes_only_inspected_immutable_id(self):
        record=self.worker_record();self.peer.active=record
        observed={'Id':'a'*64,'Image':record['image'],
            'Config':{'Labels':{ownership_registry.LABEL:record['launch_id'],ownership_registry.REGISTRY_LABEL:record['registry']}},
            'Mounts':[{'Source':record['mounts'][0]['source'],'Destination':'/workspace','RW':True}]}
        self.registry.command.side_effect=[types.SimpleNamespace(returncode=0,stdout=self.registry.daemon),
            types.SimpleNamespace(returncode=0,stdout=json.dumps([observed])),types.SimpleNamespace(returncode=0,stdout='')]
        with mock.patch.object(self.registry,'confirm_absent',return_value=True):
            self.assertTrue(native.stop_owned_worker(self.peer))
        self.assertIsNone(self.peer.active)
        self.assertEqual(self.registry.command.call_args_list[-1].args[0],['docker','rm','--force','a'*64])

    def test_foreign_worker_is_never_removed_and_live_helper_is_not_purged(self):
        self.begin();helper=self.helpers[0];record=self.worker_record();self.peer.active=record
        self.registry.command.side_effect=[types.SimpleNamespace(returncode=0,stdout=self.registry.daemon),
            types.SimpleNamespace(returncode=0,stdout=json.dumps([{'Id':'a'*64,'Image':'foreign'}]))]
        with mock.patch.object(self.registry,'write'):
            with self.assertRaises(ParallelError):self.peer.finalize_native_budget(stop_worker=True)
        self.assertEqual(len(self.registry.command.call_args_list),2)
        self.assertEqual(record['status'],'quarantined');self.assertEqual(helper.row.state,'quarantined')
        self.assertTrue(self.pool.closed);self.assertNotIn('cleanup',helper.events)
        self.assertFalse(self.pool.dependent_cleanup_confirmed)

    def test_malformed_worker_ownership_quarantines_before_cleanup(self):
        self.begin();helper=self.helpers[0];record=self.worker_record();self.peer.active=record
        self.registry.command.side_effect=[types.SimpleNamespace(returncode=0,stdout=self.registry.daemon),
            types.SimpleNamespace(returncode=0,stdout='[]')]
        with mock.patch.object(self.registry,'write'):
            with self.assertRaises(ParallelError):self.peer.finalize_native_budget(stop_worker=True)
        self.assertEqual(record['status'],'quarantined');self.assertTrue(self.pool.closed)
        self.assertFalse(self.pool.dependent_cleanup_confirmed)
        self.assertNotIn('cleanup',helper.events)

    def test_tampered_accepted_extension_payload_has_no_helper_effect(self):
        self.begin();helper=self.helpers[0]
        record=self.command('extend_budget',{'expected_budget_revision':0,'limits':{**self.definition['budgets'],'max_tool_calls':8}})
        record['limits']['max_tool_calls']=9
        controls.atomic(self.run/'stages'/self.stage_id/'budget-requests'/(record['id']+'.json'),record)
        with self.assertRaises(ParallelError):self.peer.handle({'op':'native-budget-extend','stage_id':self.stage_id,
            'command_id':record['id'],'max_tool_calls':9,'remaining_seconds':299})
        self.assertFalse(any(type(event) is tuple and event[0]=='extend' for event in helper.events))


if __name__=='__main__':unittest.main()
