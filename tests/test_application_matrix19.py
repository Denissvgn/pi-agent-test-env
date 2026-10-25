"""Synthetic origin19 carry and original-ledger guards; no live/private calls."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock
import uuid

R=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(R/'tests'),str(R/'skill/scripts'),str(R/'skill/runtime'),str(R/'tools/qualification')]
import application_matrix19 as current
import application_launch as launch
from test_application_matrix18 import fixture as older_fixture

def fresh():return str(uuid.uuid4())
def reference(name):return {'path':str(current.CAMPAIGN/name),'sha256':'e'*64}

def authorization():
    return {'schema':1,'document_type':'qualification_matrix19_amendment','authorization_id':current.AUTHORIZATION_ID,'matrix_origin':19,'human_authorization':'Synthetic matrix19 only','authorization_clock':current.CLOCK_REFERENCE,'recorded_wall':current.STARTED_WALL,'original_boundary':current.BOUNDARY_REFERENCE,'basis':current.BASIS_REFERENCES,
      **{'prior_'+k:current.BASIS_REFERENCES[k]for k in ('manifest','state','ledger')},'current_carry_metadata':reference('meta.json'),'current_carry_metadata_review':reference('meta-review.json'),
      'prior_cumulative_container_launches':275,'prior_cumulative_participant_segments':15,'prior_native_rows':504,'prior_matrix_origins':18,'planned_new_container_launches':186,'planned_new_participant_segments':24,'container_cap':461,'participant_cap':39,'maximum_matrix_origins':19,'maximum_live_containers':4,'maximum_active_trials':1,'maximum_inference_slots':1,'global_seconds':14400,'cleanup_reserve_seconds':30,'automatic_retries':0,'continuations':0,'auxiliary_container_launches':0,'platform':'linux/arm64','started_monotonic':current.STARTED_MONOTONIC,'started_wall':current.STARTED_WALL,'deadline_monotonic':current.DEADLINE_MONOTONIC,'deadline_wall':current.DEADLINE_WALL}

def clock_grant():
    return {'schema':1,'document_type':'matrix19_authorization_clock','human_authorization':authorization()['human_authorization'],'matrix_origin':19,'container_cap':461,'participant_cap':39,'prior_container_intents':275,'prior_participant_intents':15,'active_trials_max':1,'inference_slots_max':1,'live_containers_max':4,'max_seconds':14400,'automatic_retry_allowed':False,'prior_evidence_must_remain_immutable':True,'platform':'linux/arm64',**{k:authorization()[k]for k in ('started_monotonic','started_wall','deadline_monotonic','deadline_wall')}}

class Authorization(unittest.TestCase):
    def setUp(self):
        self.auth=authorization();self.ref={'path':str(current.AUTHORIZATION_PATH),'sha256':'a'*64};self.clock=clock_grant()
        self.patches=[mock.patch.object(current,'AUTHORIZATION_SHA256','a'*64),mock.patch.object(current,'_reference',side_effect=lambda r:copy.deepcopy(self.auth if r==self.ref else self.clock))]
        for p in self.patches:p.start();self.addCleanup(p.stop)
    def test_exact_461_39_and_one_new_origin_router(self):
        self.assertEqual(current.effective_limits(self.ref),{**launch.LIMITS,'container_launch_attempts':461,'participant_segments':39})
        self.assertIs(launch.amendment_module(self.ref),current);self.assertEqual(launch.maximum_origins(self.ref),19)
    def test_old_cap_wrong_origin_retry_or_budget_expansion_denied(self):
        for key,bad in [('container_cap',432),('participant_cap',37),('matrix_origin',20),('maximum_matrix_origins',20),('cleanup_reserve_seconds',31),('automatic_retries',1),('auxiliary_container_launches',1),('maximum_live_containers',5),('maximum_inference_slots',2),('platform','linux/amd64'),('planned_new_container_launches',185)]:
            old=self.auth[key];self.auth[key]=bad
            with self.subTest(key=key),self.assertRaises(launch.LaunchError):current.effective_limits(self.ref)
            self.auth[key]=old
    def test_bool_integer_unknown_field_and_wrong_clock_refuse(self):
        self.auth['schema']=True
        with self.assertRaises(launch.LaunchError):current.effective_limits(self.ref)
        self.auth['schema']=1;self.auth['extra']=0
        with self.assertRaises(launch.LaunchError):current.effective_limits(self.ref)
        del self.auth['extra'];self.clock['deadline_wall']+=1
        with self.assertRaises(launch.LaunchError):current.effective_limits(self.ref)
    def test_unbound_or_wrong_authority_refuses_before_reader(self):
        with mock.patch.object(current,'AUTHORIZATION_SHA256',None),mock.patch.object(current,'_reference')as read,self.assertRaises(launch.LaunchError):current.effective_limits(self.ref)
        read.assert_not_called()
        with self.assertRaises(launch.LaunchError):launch.maximum_origins({'path':str(current.AUTHORIZATION_PATH),'sha256':'b'*64})

def native_fixture():
    full,policy,_,_,prior=older_fixture();full=copy.deepcopy(full);policy=copy.deepcopy(policy);prior=copy.deepcopy(prior)
    policy['campaign_amendment']=current.PRIOR_AMENDMENT_REFERENCE;policy['limits']={**launch.LIMITS,'container_launch_attempts':432,'participant_segments':37}
    full.update(copy.deepcopy(policy),prepared_root=str(current.PRIOR_ROOT))
    prior.update(attempts=246,participant_segments=13,planned_cells=476,qualification_id=fresh(),started=current.historical.STARTED_MONOTONIC,deadline=current.historical.DEADLINE_MONOTONIC,started_wall=current.historical.STARTED_WALL,deadline_wall=current.historical.DEADLINE_WALL,
      prior_rows=[{'status':'NOT_RUN'}for _ in range(476)],lineage=[{'qualification_id':fresh(),'root':'/synthetic/'+str(i)}for i in range(17)],fixture_startup_diagnostic={'fixture':'KEEP'},image_recovery={'attempts':12,'qualified_images':full['images']})
    state={'schema':1,'phase':'blocked','started_at':current.historical.STARTED_WALL,'cells':{},'active_cell':None};rows=[]
    for index,cell in enumerate(full['cells'][:7]):
        item={'status':'PASS','attempts':1,'evidence_level':'native_infrastructure'}if index<4 else{'status':'PASS'if index<6 else'BLOCKED','attempts':1,'run_id':fresh(),'attempt_id':fresh()}
        if 4<=index<6:item.update(runner_status='FAIL',exit_code=1,interruption_sent=False)
        if index==6:item['private_cleanup']='unconfirmed';state['active_cell']={'id':cell['id'],'pid':83845,'run_id':item['run_id'],'attempt_id':item['attempt_id']}
        state['cells'][cell['id']]=item
        roles=cell['role_limits']if index<6 else{key:value for key,value in cell['role_limits'].items()if key not in ('participant','scorer')}
        for role in roles:
            launchid=fresh();registry='a'*64
            rows.append({'key':launch._digest({'registry':registry,'launch_id':launchid}),'cell':cell['id'],'role':role,'registry':registry,'generation':fresh(),'launch_id':launchid,'container':'pi-lab-'+uuid.uuid4().hex,'image':cell['image_id'],'resources':launch._role_weight(policy,cell,role),'physical':'absent','private_cleanup':not(index==6 and role in('probe','boundary','preflight')),'pid':1000+len(rows),'container_id':hashlib.sha256(launchid.encode()).hexdigest(),'intent_sha256':'c'*64,'cleanup_requests':[],'launch_policy':'explicit_pull_never_owned_id_5s'})
    ledger={'schema':1,'manifest_sha256':launch._digest(policy),'daemon':prior['daemon'],'daemon_capacity':prior['daemon_capacity'],'started':prior['started'],'deadline':prior['deadline'],'started_wall':prior['started_wall'],'deadline_wall':prior['deadline_wall'],'last_now':prior['started']+1,'last_wall':prior['started_wall']+1,'poisoned':True,'launches':rows,'carry':{'descriptor_sha256':launch._digest(full['predecessor']),**{k:prior[k]for k in ('attempts','participant_segments','qualification_id','planned_cells')}}}
    return full,policy,state,ledger,prior

class NativeCarry(unittest.TestCase):
    def setUp(self):
        self.full,self.policy,self.state,self.ledger,self.prior=native_fixture();self.objects={current.BASIS_REFERENCES[k]['path']:v for k,v in [('manifest',self.full),('state',self.state),('ledger',self.ledger)]}
        for p in [mock.patch.object(current,'_reference',side_effect=lambda ref:copy.deepcopy(self.objects[ref['path']])),mock.patch.object(current.historical,'validate_amendment',side_effect=lambda *a,**kw:copy.deepcopy(self.prior)),mock.patch.object(current.historical,'_launch_policy',return_value=self.policy),mock.patch.object(launch,'_successor_claim')]:p.start();self.addCleanup(p.stop)
    def call(self):return current._native_prior(self.full['predecessor'],clock=lambda:current.STARTED_MONOTONIC+1,wall=lambda:current.STARTED_WALL+1)
    def test_original_ledger_28rows_poison_and_3false_are_preserved(self):
        before=copy.deepcopy((self.state,self.ledger));full,state,ledger,carry=self.call()
        self.assertEqual((carry['attempts'],carry['participant_segments'],carry['planned_cells'],len(carry['lineage'])),(274,15,504,18))
        self.assertEqual(len([c for c in full['cells']if c['group']=='N02']),12);self.assertEqual((self.state,self.ledger),before)
        for key in ('startup_diagnostic','artifact_write_diagnostic','fixture_startup_diagnostic','image_recovery'):self.assertEqual(carry[key],self.prior[key])
    def test_raw_poison_repair_or_private_flag_repair_refuses(self):
        self.ledger['poisoned']=False
        with self.assertRaises(launch.LaunchError):self.call()
        self.ledger['poisoned']=True;next(r for r in self.ledger['launches']if not r['private_cleanup'])['private_cleanup']=True
        with self.assertRaises(launch.LaunchError):self.call()
    def test_original_central_counter_and_resource_mutations_refuse(self):
        for edit in ('carry','resource','physical','container'):
            saved=copy.deepcopy(self.ledger)
            if edit=='carry':self.ledger['carry']['participant_segments']=14
            elif edit=='resource':self.ledger['launches'][0]['resources']['memory_mib']+=1
            elif edit=='physical':self.ledger['launches'][0]['physical']='started'
            else:self.ledger['launches'][0]['container_id']=None
            with self.subTest(edit=edit),self.assertRaises(launch.LaunchError):self.call()
            self.ledger.clear();self.ledger.update(saved)
    def test_later_case_or_changed_stale_state_refuses_without_PID_probe(self):
        with mock.patch.object(os,'kill',side_effect=AssertionError('PID probe')):
            self.call();self.state['active_cell']['id']=self.full['cells'][5]['id']
            with self.assertRaises(launch.LaunchError):self.call()
        self.state['active_cell']['id']=self.full['cells'][6]['id'];self.state['cells'][self.full['cells'][7]['id']]={'status':'PASS','attempts':1}
        with self.assertRaises(launch.LaunchError):self.call()

class CarryComposition(unittest.TestCase):
    def setUp(self):
        _,_,_,_,self.prior=native_fixture();self.prior.update(attempts=274,participant_segments=15,planned_cells=504,lineage=[{'qualification_id':fresh()}for _ in range(18)])
        self.diag={'attempts':1,'participant_segments':0,'native_rows':0,'root':str(current.DIAGNOSTIC_ROOT),'qualification_id':fresh(),'terminal':current.BASIS_REFERENCES['diagnostic_terminal']}
        self.auth=authorization();self.ref={'path':str(current.AUTHORIZATION_PATH),'sha256':'a'*64}
        for p in [mock.patch.object(current,'_authorization',return_value=self.auth),mock.patch.object(current,'_native_prior',return_value=({}, {}, {'daemon':'synthetic'},self.prior)),mock.patch.object(current,'_current_cleanup',return_value=({},{})),mock.patch.object(current,'_closed_helper',side_effect=lambda p:(copy.deepcopy(self.diag),{},{},{})),mock.patch.object(current,'_fresh_carry_metadata'),mock.patch.object(current,'effective_limits',return_value={**launch.LIMITS,'container_launch_attempts':461,'participant_segments':39})]:p.start();self.addCleanup(p.stop)
    def call(self,mono=None,wall=None,window=True):return current.validate_amendment(self.ref,{},clock=lambda:current.STARTED_MONOTONIC+1 if mono is None else mono,wall=lambda:current.STARTED_WALL+1 if wall is None else wall,window=window)
    def test_exact_275_15_504_18_then_186_24_fit_461_39(self):
        result=self.call();self.assertEqual((result['attempts'],result['participant_segments'],result['planned_cells'],len(result['lineage'])),(275,15,504,18));self.assertEqual(result['helper_startup_diagnostic'],self.diag)
        for key in ('startup_diagnostic','artifact_write_diagnostic','fixture_startup_diagnostic','image_recovery'):self.assertEqual(result[key],self.prior[key])
    def test_diagnostic_wrong_int_bool_or_rows_never_increment(self):
        for key,bad in [('attempts',2),('attempts',True),('participant_segments',1),('native_rows',1)]:
            old=self.diag[key];self.diag[key]=bad
            with self.subTest(key=key,bad=bad),self.assertRaises(launch.LaunchError):self.call()
            self.diag[key]=old
        self.assertEqual(self.prior['attempts'],274)
    def test_wrong_final_24_projection_and_expired_new_window_refuse(self):
        self.auth['planned_new_participant_segments']=23
        with self.assertRaises(launch.LaunchError):self.call()
        self.auth['planned_new_participant_segments']=24
        with self.assertRaises(launch.LaunchError):self.call(wall=current.DEADLINE_WALL)
        self.assertEqual(self.call(current.DEADLINE_MONOTONIC+1,current.DEADLINE_WALL+1,False)['attempts'],275)

def helper_fixture():
    full,_,_,_,prior=native_fixture();prior.update(attempts=274,participant_segments=15,planned_cells=504,lineage=[{'qualification_id':fresh()}for _ in range(18)])
    authref=reference('d04-auth.json');windowref=reference('d04-window.json');image=full['images']['core-0.87.1']['id'];cell={'id':'D04-synthetic','group':'D04','release':'0.87.1','image_id':image,'allowed_images':[image],'role_limits':{'application-helper':1},'container_launches_max':1,'participant_segments_max':0}
    manifest={'schema':1,'document_type':'helper_startup_diagnostic','qualification_id':fresh(),'authorization':authref,'window':windowref,'images':{'core-0.87.1':{'id':image,'platform':'linux/arm64','capabilities':{'pi':'0.87.1'}}},'cells':[cell],'limits':{**launch.LIMITS,'container_launch_attempts':275,'participant_segments':15},'planned_container_launches':1,'diagnostic':{'kind':'helper-startup','root':str(current.DIAGNOSTIC_ROOT)}}
    uid=fresh();registry='a'*64;row={'key':launch._digest({'registry':registry,'launch_id':uid}),'cell':cell['id'],'role':'application-helper','registry':registry,'generation':fresh(),'launch_id':uid,'container':'pi-application-synthetic','image':image,'resources':{'cpu_millis':1000,'memory_mib':512,'pids_limit':128},'physical':'absent','private_cleanup':True,'pid':4321,'container_id':'f'*64,'intent_sha256':'c'*64,'cleanup_requests':[],'launch_policy':'explicit_pull_never_owned_id_5s'}
    start=current.STARTED_MONOTONIC-2000;wall=current.STARTED_WALL-2000
    ledger={'schema':1,'manifest_sha256':launch._digest(manifest),'daemon':prior['daemon'],'daemon_capacity':prior['daemon_capacity'],'started':start,'deadline':start+14400,'started_wall':wall,'deadline_wall':wall+14400,'last_now':start+1,'last_wall':wall+1,'poisoned':False,'launches':[row]}
    files={k:'8'*64 for k in ('private/diagnostic-startup-phases.jsonl','private/raw/.owner.lock','private/raw/state.json')}
    terminal={'schema':1,'document_type':'helper_startup_diagnostic_terminal','status':'PASS','manifest':current.BASIS_REFERENCES['diagnostic_manifest'],'ledger':current.BASIS_REFERENCES['diagnostic_ledger'],'authorization':authref,'window':windowref,'new_container_intents':1,'cumulative_container_intents':275,'participant_segments':15,'new_participants':0,'inference_calls':0,'business_calls':0,'real_credentials':0,**{k:True for k in ('helper_startup_ready','physical_absence_confirmed','private_cleanup_confirmed','all_writers_stopped','dummy_store_removed','diagnostic_evidence_available')},'automatic_retry_performed':False,'matrix_triggered':False,'fixture_identity_seconds':5,'helper_ready_seconds':10,'elapsed_seconds':15.4,'cleanup_seconds':6.2,'classified_evidence_hashes':files,'process_receipts':[]}
    review={'status':'PASS','unresolved_findings':[],'supports_actual_helper_diagnostic':True,'supports_confirmed_cleanup':True,**{k:current.BASIS_REFERENCES['diagnostic_'+k]for k in ('terminal','manifest','ledger','command')},'authorization':authref,'window':windowref,'post_registry':current.BASIS_REFERENCES['diagnostic_post_registry'],'confirmed_cleanup':{'all6706_prior_record_hashes_unchanged':True,'new_kind_delta':{'container':1,'network':1}},'key_free_scope':{'new_diagnostic_files':3,'classified_hashes':files}}
    command={'status':'PASS','actual_exit':0,'wait_completed':True,'unknown_owned_child':False,'elapsed_seconds':16.}
    objects={current.BASIS_REFERENCES['diagnostic_'+k]['path']:v for k,v in [('manifest',manifest),('ledger',ledger),('terminal',terminal),('review',review),('command',command),('post_registry',{'status':'PASS','whole_host_records':6708,'status_counts':{'released':6708}})]}
    objects[authref['path']]={'status':'AUTHORIZED','diagnostic_kind':'application_execution_helper_startup','maximum_diagnostic_launches':1}
    objects[windowref['path']]={'authorization':authref,'started_monotonic':start,'deadline_monotonic':start+14400,'started_wall':wall,'deadline_wall':wall+14400}
    claim={'schema':1,'authorization':authref,'qualification_id':manifest['qualification_id'],'manifest':current.BASIS_REFERENCES['diagnostic_manifest'],'root':str(current.DIAGNOSTIC_ROOT),'maximum_launches':1}
    for path in (current.DIAGNOSTIC_ROOT.parent/'future-diagnostic-claim/claim.json',current.DIAGNOSTIC_ROOT/'claim.json'):objects[str(path)]=claim
    for index in range(1,30):
        a,b=reference('start-%02d.json'%index),reference('end-%02d.json'%index);terminal['process_receipts'].append({'start':a,'terminal':b});pid=4321 if index==10 else 6000+index
        objects[a['path']]={'schema':1,'ordinal':index,'pid':pid,'kind':'helper_container_cli'if index==10 else'owned_metadata_or_service_cli'}
        objects[b['path']]={'schema':1,'ordinal':index,'pid':pid,'wait_confirmed':True,'unknown_owned_child':False,'returncode':137 if index==10 else 0}
    return prior,objects,terminal,ledger,review

class ClosedHelper(unittest.TestCase):
    def setUp(self):
        self.prior,self.objects,self.terminal,self.ledger,self.review=helper_fixture();p=mock.patch.object(current,'_reference',side_effect=lambda ref:copy.deepcopy(self.objects[ref['path']]));p.start();self.addCleanup(p.stop)
    def call(self):return current._closed_helper(self.prior)[0]
    def test_original_central_ledger_and_29_positive_waits_validate_one_helper(self):
        result=self.call();self.assertEqual((result['attempts'],result['participant_segments'],result['native_rows']),(1,0,0));self.assertTrue(result['all_writers_stopped'])
    def test_missing_wait_wrong_returned_pid_and_unknown_child_refuse(self):
        ref=self.terminal['process_receipts'][9]['terminal'];doc=self.objects[ref['path']]
        for key,bad in [('wait_confirmed',False),('pid',5555),('unknown_owned_child',True)]:
            old=doc[key];doc[key]=bad
            with self.subTest(key=key),self.assertRaises(launch.LaunchError):self.call()
            doc[key]=old
    def test_cleanup_poison_or_unbound_cid_never_charges(self):
        for key,bad in [('poisoned',True),('private_cleanup',False),('container_id',None)]:
            doc=self.ledger if key=='poisoned'else self.ledger['launches'][0];old=doc[key];doc[key]=bad
            with self.subTest(key=key),self.assertRaises(launch.LaunchError):self.call()
            doc[key]=old
    def test_extra_diagnostic_native_call_budget_or_false_readiness_refuses(self):
        for key,bad in [('new_container_intents',2),('new_container_intents',True),('new_participants',1),('inference_calls',1),('business_calls',1),('helper_startup_ready',False),('cleanup_seconds',31),('elapsed_seconds',117)]:
            old=self.terminal[key];self.terminal[key]=bad
            with self.subTest(key=key),self.assertRaises(launch.LaunchError):self.call()
            self.terminal[key]=old
    def test_permanent_claim_and_typed_review_subject_must_match(self):
        path=str(current.DIAGNOSTIC_ROOT/'claim.json');self.objects[path]={**self.objects[path],'maximum_launches':2}
        with self.assertRaises(launch.LaunchError):self.call()
        self.objects[path]['maximum_launches']=1;self.review['terminal']={**self.review['terminal'],'sha256':'0'*64}
        with self.assertRaises(launch.LaunchError):self.call()

class FreshTaskRecords(unittest.TestCase):
    def setUp(self):
        self.root=Path('/synthetic/registry');self.auth=authorization();self.objects={};self.records={};self.copied=[]
        def add(record):
            digest=launch._digest(record);ref={'path':str(current.CAMPAIGN/(record['launch_id']+'.json')),'sha256':digest};self.objects[ref['path']]=record;self.records[str(self.root/(record['launch_id']+'.json'))]=(record,digest);self.copied.append(ref);return ref
        self.cleanup={'registry_records':[add({'launch_id':fresh(),'daemon':'synthetic-daemon','status':'released'})for _ in range(213)]}
        self.helper={'launch_id':fresh(),'daemon':'synthetic-daemon','status':'released','registry':'a'*64,'generation':fresh(),'container':'pi-application-synthetic','image':'sha256:'+'b'*64,'container_id':'c'*64,'application_helper':True,'client_mode':'application-execution'}
        add(self.helper);self.network={'launch_id':fresh(),'daemon':'synthetic-daemon','status':'released','kind':'network','container':self.helper['container']+'-network','registry':self.helper['registry'],'generation':self.helper['generation']};add(self.network)
        row={**self.helper,'intent_sha256':launch._intent_identity(self.helper)};self.objects[current.BASIS_REFERENCES['diagnostic_ledger']['path']]={'launches':[row]}
        self.terminal={'classified_evidence_hashes':{k:'f'*64 for k in ('private/diagnostic-startup-phases.jsonl','private/raw/.owner.lock','private/raw/state.json')}}
        self.master={'target':'/synthetic/master/store'};self.absences=['/synthetic/dummy','/synthetic/helper','/synthetic/master/store','/synthetic/master']
        self.review={'confirmed_cleanup':{'exact_two_new_released_record_paths':[str(self.root/(r['launch_id']+'.json'))for r in (self.helper,self.network)],'fresh_Root_stat_absences':self.absences[:2]}}
        pins={path:digest for path,(_,digest)in self.records.items()};pins[str(self.root/'unrelated.json')]='d'*64
        names={'.','private','private/raw','private/outputs',*self.terminal['classified_evidence_hashes']}
        self.meta={'status':'PASS','original_lease_held':True,'Registry_constructor_or_reconcile_called':False,'Registry_mutations':0,'PID_probes':0,'Docker_or_model_actions':0,'retained_payload_opens_or_hashes':0,'credential_values_opened':False,'all_whole_host_records_released':True,'new_authorization_clock':current.CLOCK_REFERENCE,'prior_post_registry':current.BASIS_REFERENCES['diagnostic_post_registry'],'d04_classification_terminal':current.BASIS_REFERENCES['diagnostic_terminal'],'task_records_215':self.copied,'record_sha256':pins,'d04_retained_tree':{'path':str(current.DIAGNOSTIC_ROOT/'run/application-evidence'/self.helper['container']),'nodes':{n:{'kind':'regular'if n in self.terminal['classified_evidence_hashes']else'directory','mode':0o600 if n in self.terminal['classified_evidence_hashes']else 0o700}for n in names}},'d04_classified_evidence_hashes':self.terminal['classified_evidence_hashes'],'known_absences':[{'path':p,'absent':True}for p in self.absences]}
        self.post={'record_sha256':copy.deepcopy(pins)};self.objects[self.auth['current_carry_metadata']['path']]=self.meta;self.objects[self.auth['current_carry_metadata_review']['path']]={'status':'PASS','unresolved_findings':[],'supports_current_carry_metadata':True,'current_carry_metadata':self.auth['current_carry_metadata']}
        def bound(path,digest):
            record,actual=self.records[path]
            if actual!=digest:raise launch.LaunchError('synthetic_stale_body')
            return copy.deepcopy(record)
        for p in [mock.patch.object(current,'_reference',side_effect=lambda ref:copy.deepcopy(self.objects[ref['path']])),mock.patch.object(current,'_relative_reference',side_effect=lambda ref:copy.deepcopy(self.objects[ref['path']])),mock.patch.object(current.historical,'_registry_root',return_value=self.root),mock.patch.object(launch,'_bound_json',side_effect=bound),mock.patch.object(current,'_metadata_tree'),mock.patch.object(current.registry_api,'_qualification_absent',return_value=True)]:p.start();self.addCleanup(p.stop)
    def call(self):return current._fresh_carry_metadata(self.auth,self.cleanup,self.master,self.terminal,self.review,self.post,'synthetic-daemon')
    def test_exact_215_subset_accepts_unrelated_wholehost_members(self):
        self.call();self.assertEqual(len(self.copied),215);self.assertEqual(len(self.meta['record_sha256']),216)
    def test_changed_full_body_or_missing_task_refuses(self):
        path=next(iter(self.records));record,digest=self.records[path];self.records[path]=(record,'0'*64)
        with self.assertRaises(launch.LaunchError):self.call()
        self.records[path]=(record,digest);self.copied.pop()
        with self.assertRaises(launch.LaunchError):self.call()
    def test_changed_helper_cid_or_network_generation_refuses(self):
        for record,key in [(self.helper,'container_id'),(self.network,'generation'),(self.network,'container')]:
            old=record[key];record[key]='0'*64 if key=='container_id'else fresh()
            with self.subTest(key=key),self.assertRaises(launch.LaunchError):self.call()
            record[key]=old
    def test_extra_owner_leaf_or_unconfirmed_absence_refuses(self):
        nodes=self.meta['d04_retained_tree']['nodes'];nodes['private/unclassified']={'kind':'regular','mode':0o600}
        with self.assertRaises(launch.LaunchError):self.call()
        del nodes['private/unclassified'];self.meta['known_absences'][0]['absent']=False
        with self.assertRaises(launch.LaunchError):self.call()

def metadata(path):
    i=path.lstat();return {'device':i.st_dev,'inode':i.st_ino,'uid':i.st_uid,'mode':stat.S_IMODE(i.st_mode),'nlink':i.st_nlink,'size':i.st_size,'mtime_ns':i.st_mtime_ns,'ctime_ns':i.st_ctime_ns,'kind':'directory'if stat.S_ISDIR(i.st_mode)else'regular'}

class MetadataFence(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
        (self.root/'private').mkdir(mode=0o700);(self.root/'private/raw').mkdir(mode=0o700);(self.root/'private/outputs').mkdir(mode=0o700)
        for name in ('private/diagnostic-startup-phases.jsonl','private/raw/.owner.lock','private/raw/state.json'):(self.root/name).write_bytes(b'SYNTHETIC');(self.root/name).chmod(0o600)
        self.nodes={'.':metadata(self.root),**{str(p.relative_to(self.root)):metadata(p)for p in self.root.rglob('*')}}
    def call(self):current._metadata_tree(str(self.root),self.nodes,self.root)
    def test_exact_seven_nodes_three_files_never_opens_payload(self):
        original=os.open
        def directory_only(path,flags,*args,**kw):self.assertTrue(flags&os.O_DIRECTORY);return original(path,flags,*args,**kw)
        with mock.patch.object(os,'open',side_effect=directory_only):self.call()
        self.assertEqual(len(self.nodes),7)
    def test_extra_file_or_directory_refuses_without_open(self):
        for kind in ('file','directory'):
            p=self.root/'private/unknown'
            if kind=='file':p.write_bytes(b'CANARY');p.chmod(0o600)
            else:p.mkdir(mode=0o700)
            with self.subTest(kind=kind),self.assertRaises(launch.LaunchError):self.call()
            p.unlink()if kind=='file'else p.rmdir()
            # Parent directory metadata was deliberately changed; restore the
            # synthetic baseline before exercising the independent next case.
            self.nodes={'.':metadata(self.root),**{str(q.relative_to(self.root)):metadata(q)for q in self.root.rglob('*')}}
    def test_directory_reopen_identity_drift_refuses_before_listing(self):
        original=os.fstat;listed=[]
        def changed(fd):
            info=original(fd)
            if stat.S_ISDIR(info.st_mode):return mock.Mock(st_dev=info.st_dev,st_ino=info.st_ino+1)
            return info
        # _dir has its own fstat mode check, so drift only after it returned.
        original_dir=launch._dir
        def directory(path,*args,**kwargs):
            fd=original_dir(path,*args,**kwargs)
            if Path(path)==self.root:
                patch=mock.patch.object(os,'fstat',side_effect=changed);patch.start();self.addCleanup(patch.stop)
            return fd
        with mock.patch.object(launch,'_dir',side_effect=directory),mock.patch.object(os,'listdir',side_effect=lambda fd:listed.append(fd)):
            with self.assertRaises(launch.LaunchError):self.call()
        self.assertEqual(listed,[])
    def test_inode_replacement_and_symlink_refuse(self):
        p=self.root/'private/raw/state.json';p.unlink();p.write_bytes(b'SYNTHETIC');p.chmod(0o600)
        with self.assertRaises(launch.LaunchError):self.call()
        p.unlink();p.symlink_to(self.root/'private/raw/.owner.lock')
        with self.assertRaises(launch.LaunchError):self.call()

class ClaimDeadline(unittest.TestCase):
    def test_forward_wall_jump_after_blocking_lock_prevents_claim_writes(self):
        clock=[current.STARTED_MONOTONIC+1,current.STARTED_WALL+1];opened=[]
        def file(fd,name,flags):opened.append(name);return 12
        def flock(fd,operation):clock[1]=current.DEADLINE_WALL
        with mock.patch.object(launch,'_dir',return_value=10),mock.patch.object(launch,'_file',side_effect=file),mock.patch.object(os,'open',return_value=11),mock.patch.object(os,'close'),mock.patch.object(os,'mkdir'),mock.patch.object(os,'fsync'),mock.patch.object(os,'fstat',return_value=mock.Mock(st_uid=os.getuid(),st_mode=stat.S_IFDIR|0o700)),mock.patch.object(current.fcntl,'flock',side_effect=flock),mock.patch.object(launch,'_read')as read:
            with self.assertRaises(launch.LaunchError):current._fence({}, {'qualification_id':fresh()},create=True,clock=lambda:clock[0],wall=lambda:clock[1])
        self.assertEqual(len(opened),1);self.assertTrue(opened[0].endswith('.lock'));read.assert_not_called()

if __name__=='__main__':unittest.main()
