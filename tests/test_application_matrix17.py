"""Synthetic matrix17 pre-diagnostic guards; no reports/host/private dependency."""
import copy,hashlib,json,os,sys,tempfile,unittest,uuid,subprocess
from pathlib import Path
from unittest import mock
R=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(R/'skill/scripts'),str(R/'skill/runtime'),str(R/'tools/qualification')]
import application_matrix17 as current
import application_launch as launch

def authority():
 return {'schema':1,'document_type':'bounded_artifact_write_diagnostic_authorization','authorization_id':'af28ea56-e17f-4f6a-aaba-1421fc581ed5','human_authorization':'SYNTHETIC matrix17 diagnostic and380/33',
  'recorded_wall':current.STARTED_WALL,'window_authorization':copy.deepcopy(current.WINDOW_AUTHORIZATION),'started_wall':current.STARTED_WALL,'started_monotonic':current.STARTED_MONOTONIC,'deadline_wall':current.DEADLINE_WALL,'deadline_monotonic':current.DEADLINE_MONOTONIC,
  'prior_cumulative_container_launches':193,'prior_cumulative_participant_segments':9,'container_cap':380,'participant_cap':33,'maximum_diagnostic_launches':1,'diagnostic_participants':0,'inference_calls':0,'credentials':0,'live_cap':1,'trial_cap':1,'platform':'linux/arm64','overall_seconds':90,'work_seconds_max':60,'cleanup_seconds':30,'automatic_retries':0,'continuations':0,
  **{k:{'path':'/synthetic/'+k+'.json','sha256':'a'*64}for k in ('proposal','prior_cleanup','prior_boundary_review','prior_final_audit','prior_actual_publication_review')},'original_boundary':copy.deepcopy(current.BOUNDARY_REFERENCE),'no_existing_evidence_mounts':True,'original_lease_required':True,'matrix17_requires_diagnostic_terminal_cleanup':True}
def window(value):
 return {'document_type':'qualification_window_authorization','window_seconds':14400,'authorization':value['human_authorization'],'original_deadline_wall':current.prior_amendment.DEADLINE_WALL,'prior_campaign_modified':False,'new_native_admission_requires_positive_owned_cleanup':True,
  **{k:value[k]for k in ('started_wall','started_monotonic','deadline_wall','deadline_monotonic','container_cap','participant_cap','platform','automatic_retries','continuations')},'cumulative_container_launches':193,'cumulative_participant_segments':9,'live_cap':4,'trial_cap':1,'inference_slot_cap':1}
def fixture():
 image='sha256:'+'1'*64;qid=str(uuid.uuid4());cells=[]
 for i in range(4):
  roles={'probe':1}if i%2==0 else{'probe':1,'browser-check':1}
  cells.append({'id':'N01-fixture-'+str(i),'group':'N01','release':'0.87.1','image_id':image,'allowed_images':[image],'role_limits':roles,'container_launches_max':sum(roles.values()),'participant_segments_max':0})
 for i in range(24):
  roles={k:1 for k in ('fixture','probe','boundary','preflight','application-helper','participant','scorer')}
  if i<12:roles['scripted-inference']=1
  cells.append({'id':'cell-'+str(i),'group':'N02'if i<12 else'N03'if i<18 else'N04','release':'0.87.1','image_id':image,'allowed_images':[image],'role_limits':roles,'container_launches_max':sum(roles.values()),'participant_segments_max':1})
 images={p+'-'+v:{'id':image if p=='core'else'sha256:'+'2'*64,'platform':'linux/arm64','capabilities':{'pi':v}}for p in ('core','browser')for v in ('0.87.1','1.2.0')}
 base={'synthetic_only':True};policy={'qualification_id':qid,'images':images,'cells':cells,'limits':{**launch.LIMITS,'container_launch_attempts':349,'participant_segments':30},'planned_container_launches':186,'predecessor':base,'campaign_boundary':current.BOUNDARY_REFERENCE,'campaign_amendment':current.PRIOR_AMENDMENT_REFERENCE}
 full={**copy.deepcopy(policy),'schema':1,'document_type':'application_client_qualification','prepared_root':str(current.PRIOR_ROOT),'secrets_dir':'/synthetic/master/store'}
 prior={'attempts':163,'participant_segments':6,'qualification_id':str(uuid.uuid4()),'planned_cells':420,'started':100.,'deadline':14500.,'started_wall':1000.,'deadline_wall':15400.,'daemon':'synthetic-daemon','daemon_capacity':{'cpu_millis':18000,'memory_mib':8192},'lineage':[{'qualification_id':str(uuid.uuid4()),'root':'/synthetic/'+str(i)}for i in range(15)],'prior_rows':[{'status':'NOT_RUN'}for _ in range(420)],'startup_diagnostic':{'historical':'KEEP EXACT'},'original_window':{'historical':'UNCHANGED'},'previous_window':{'historical':'UNCHANGED'},'campaign_boundary':current.BOUNDARY_REFERENCE,'base_attempts':51,'auxiliary_attempts':3}
 state={'schema':1,'phase':'blocked','active_cell':None,'cells':{},'started_at':1000.};rows=[]
 for i,cell in enumerate(cells[:7]):
  if i<4:state['cells'][cell['id']]={'status':'PASS','attempts':1,'evidence_level':'native_infrastructure'}
  else:state['cells'][cell['id']]={'status':'FAIL'if i==6 else'PASS','attempts':1,'run_id':str(uuid.uuid4()),'attempt_id':str(uuid.uuid4()),'runner_status':'FAIL','exit_code':1,'interruption_sent':False}
  for role in cell['role_limits']:
   uid=str(uuid.uuid4());registry='a'*64
   rows.append({'key':launch._digest({'registry':registry,'launch_id':uid}),'cell':cell['id'],'role':role,'registry':registry,'generation':str(uuid.uuid4()),'launch_id':uid,'container':'pi-lab-'+uuid.uuid4().hex,'image':image,'resources':launch._role_weight(policy,cell,role),'physical':'absent','private_cleanup':True,'pid':200+len(rows),'intent_sha256':'c'*64,'container_id':hashlib.sha256(uid.encode()).hexdigest(),'cleanup_requests':[],'launch_policy':'explicit_pull_never_owned_id_5s'})
 ledger={'schema':1,'manifest_sha256':launch._digest(policy),'daemon':'synthetic-daemon','daemon_capacity':prior['daemon_capacity'],'started':100.,'deadline':14500.,'started_wall':1000.,'deadline_wall':15400.,'last_now':101.,'last_wall':1001.,'poisoned':False,'launches':rows,'carry':{'descriptor_sha256':launch._digest(base),**{k:prior[k]for k in ('attempts','participant_segments','qualification_id','planned_cells')}}}
 return full,policy,state,ledger,prior

class Authority(unittest.TestCase):
 def setUp(self):
  self.value=authority();self.window=window(self.value)
  patch=mock.patch.object(current,'_reference',side_effect=lambda ref:copy.deepcopy(self.window if ref==current.WINDOW_AUTHORIZATION else self.value));patch.start();self.addCleanup(patch.stop)
 def test_exact_pre_diagnostic_authority(self):self.assertEqual(current._diagnostic_authorization(current.DIAGNOSTIC_AUTHORIZATION)['maximum_diagnostic_launches'],1)
 def test_changed_reference_denied(self):
  with self.assertRaises(launch.LaunchError):current._diagnostic_authorization({**current.DIAGNOSTIC_AUTHORIZATION,'sha256':'0'*64})
 def test_no_cap_role_inference_key_retry_or_time_expansion(self):
  for key,value in [('container_cap',381),('participant_cap',34),('maximum_diagnostic_launches',2),('diagnostic_participants',1),('credentials',1),('inference_calls',1),('live_cap',2),('platform','linux/amd64'),('cleanup_seconds',31),('work_seconds_max',61),('overall_seconds',91),('automatic_retries',1),('continuations',1)]:
   original=self.value[key];self.value[key]=value
   with self.subTest(key=key),self.assertRaises(launch.LaunchError):current._diagnostic_authorization(current.DIAGNOSTIC_AUTHORIZATION)
   self.value[key]=original
 def test_bool_not_integer_or_extra_field(self):
  self.value['maximum_diagnostic_launches']=True
  with self.assertRaises(launch.LaunchError):current._diagnostic_authorization(current.DIAGNOSTIC_AUTHORIZATION)
  self.value['maximum_diagnostic_launches']=1;self.value['retry_allowed']=False
  with self.assertRaises(launch.LaunchError):current._diagnostic_authorization(current.DIAGNOSTIC_AUTHORIZATION)
 def test_old_window_and_widened_slot_denied(self):
  for key,bad in [('deadline_wall',current.DEADLINE_WALL+1),('inference_slot_cap',2),('cumulative_container_launches',194),('prior_campaign_modified',True)]:
   original=self.window[key];self.window[key]=bad
   with self.subTest(key=key),self.assertRaises(launch.LaunchError):current._diagnostic_authorization(current.DIAGNOSTIC_AUTHORIZATION)
   self.window[key]=original
 def test_null_final_reference_refuses_before_read(self):
  with mock.patch.object(current,'_reference')as read,self.assertRaises(launch.LaunchError):current.effective_limits({'path':str(current.AUTHORIZATION_PATH),'sha256':None})
  read.assert_not_called()

class PriorProjection(unittest.TestCase):
 def setUp(self):
  self.full,self.policy,self.state,self.ledger,self.prior=fixture();self.value=authority();self.window=window(self.value)
  self.objects={current.DIAGNOSTIC_AUTHORIZATION['path']:self.value,current.WINDOW_AUTHORIZATION['path']:self.window,**{current.PRIOR_REFERENCES[k]['path']:v for k,v in [('manifest',self.full),('state',self.state),('ledger',self.ledger)]}}
  for patch in [mock.patch.object(current,'_reference',side_effect=lambda ref:copy.deepcopy(self.objects[ref['path']])),mock.patch.object(current.prior_amendment,'validate_amendment',return_value=self.prior),mock.patch.object(current.prior_amendment,'_launch_policy',return_value=self.policy),mock.patch.object(current,'_cleanup'),mock.patch.object(launch,'_successor_claim')]:patch.start();self.addCleanup(patch.stop)
 def call(self,mono=None,wall=None,window=True):return current.validate_prior_for_diagnostic(current.DIAGNOSTIC_AUTHORIZATION,self.full['predecessor'],clock=lambda:current.STARTED_MONOTONIC+1 if mono is None else mono,wall=lambda:current.STARTED_WALL+1 if wall is None else wall,window=window)
 def test_original_central_ledger_validated_and193_not194(self):
  value=self.call();self.assertEqual((value['attempts'],value['participant_segments'],value['planned_cells'],len(value['lineage'])),(193,9,448,16));self.assertEqual(value['startup_diagnostic'],self.prior['startup_diagnostic']);self.assertEqual(value['original_window'],self.prior['original_window']);self.assertEqual(value['previous_window'],self.prior['previous_window']);self.assertEqual(value['prior_rows'][-22]['status'],'FAIL');self.assertEqual(value['effective_limits']['participant_segments'],33);self.assertEqual(self.prior['attempts'],163)
 def test_expired_current_window_denies_but_historical_projection_allowed(self):
  for mono,wall in [(current.DEADLINE_MONOTONIC,current.STARTED_WALL+1),(current.STARTED_MONOTONIC+1,current.DEADLINE_WALL)]:
   with self.assertRaises(launch.LaunchError):self.call(mono,wall)
  self.assertEqual(self.call(current.DEADLINE_MONOTONIC+1,current.DEADLINE_WALL+1,False)['attempts'],193)
 def test_global_fail_not_repaired_or_later_cell_accepted(self):
  self.state['cells']['cell-2']['status']='PASS'
  with self.assertRaises(launch.LaunchError):self.call()
 def test_active_owner_not_invented_as_terminal(self):
  self.state['active_cell']={'pid':123}
  with self.assertRaises(launch.LaunchError):self.call()
 def test_poison_or_private_false_never_repaired(self):
  self.ledger['poisoned']=True
  with self.assertRaises(launch.LaunchError):self.call()
  self.ledger['poisoned']=False;self.ledger['launches'][0]['private_cleanup']=False
  with self.assertRaises(launch.LaunchError):self.call()
 def test_original_ledger_row_policy_denial_is_preserved(self):
  self.ledger['launches'][0]['resources']['memory_mib']+=1
  with self.assertRaises(launch.LaunchError):self.call()

class PublicClosure(unittest.TestCase):
 def setUp(self):
  self.full,self.policy,self.state,self.ledger,self.prior=fixture();self.value=authority();self.objects={};self.records={}
  def add(value,name):
   ref={'path':'/synthetic/'+name+'.json','sha256':launch._digest(value)};self.objects[ref['path']]=value;return ref
  self.add=add;oldids=[hashlib.sha256(('old'+str(i)).encode()).hexdigest()for i in range(163)];oldrefs=[]
  for i in range(92):
   uid=str(uuid.uuid4());record={'launch_id':uid,'status':'released','daemon':'synthetic-daemon'};self.records[uid]=record;oldrefs.append(add(record,'old-'+uid))
  records=list(oldrefs)
  for row in self.ledger['launches']:
   record={k:row[k]for k in ('launch_id','registry','generation','image','container')};record.update(status='released',container_id=row['container_id'],daemon='synthetic-daemon',kind='container',runroot=None);self.records[row['launch_id']]=record;row['intent_sha256']=launch._intent_identity(record);records.append(add(record,'row-'+row['launch_id']))
  networks=[]
  for row in self.ledger['launches']:
   if row['role']!='application-helper':continue
   uid=str(uuid.uuid4());record={'launch_id':uid,'registry':row['registry'],'generation':row['generation'],'daemon':'synthetic-daemon','container':row['container']+'-network','kind':'network','status':'released','runroot':None};self.records[uid]=record;networks.append(uid);records.append(add(record,'network-'+uid))
  oldref=add({'all_owned_container_ids':oldids,'current_registry_records':oldrefs},'old-cleanup');self.objects[current.PRIOR_AMENDMENT_REFERENCE['path']]={'prior_cleanup':oldref}
  qid=self.full['qualification_id'];actors=[];terminal_ref=add({'status':'PASS'},'terminal-proof');source_ref={'path':'/synthetic/source.py','sha256':'d'*64}
  for i in range(61):
   row=self.ledger['launches'][i]if i<30 else None;pid=row['pid']if row else 3000+i;ctx={'qualification_id':qid,'cell_id':row['cell']if row else None,'run_id':None,'attempt_id':None,'stage_id':None,'launch_id':row['launch_id']if row else None,'role':row['role']if row else'metadata','parent_context':{},'pid':pid};actors.append({'actor_id':launch._digest(ctx),'pid':pid,'context':ctx,'terminal_proofs':[terminal_ref],'source_proofs':[source_ref]})
  chains=[]
  for i,selected in enumerate((actors[:59],actors[59:])):
   ids=sorted(a['actor_id']for a in selected);pids=sorted({a['pid']for a in selected});chain={'status':'PASS','document_type':'qualification_owned_actor_terminal_chain','positive_terminal_chain':True,'no_unconfirmed_owned_children':True,'actors':selected,'covered_actor_ids':ids,'covered_pids':pids,'terminal_proofs':[terminal_ref],'source_proofs':[source_ref]};chainref=add(chain,'chain'+str(i));reviewref=add({'status':'PASS','unresolved_findings':[],'actor_chain':chainref,'supports_global_actor_terminal_chain':True,'covered_actor_ids':ids,'covered_pids':pids},'chain-review'+str(i));chains.append({'chain':chainref,'review':reviewref})
  actorids=sorted(a['actor_id']for a in actors);byid={a['actor_id']:a for a in actors};ids=oldids+[row['container_id']for row in self.ledger['launches']]
  hashes={'/synthetic/tree'+str(i):{'file'+str(j):'e'*64 for j in range(4 if i<7 else 3)}for i in range(9)}
  terminal={'status':'PASS','qualification_id':qid,'current_ledger':current.PRIOR_REFERENCES['ledger'],'current_state':current.PRIOR_REFERENCES['state'],'known_current_contextual_actor_count':61,'actor_chains':chains,'current_actor_ids':actorids,'current_actors':[byid[k]for k in actorids],'all_owned_container_ids':ids,'current_registry_records':records,'network_launch_ids':networks,'retained_evidence_file_sha256':hashes,**{k:True for k in ('all_native_writers_absent','all_service_writers_stopped','all_helper_writers_stopped','all_qualification_controllers_stopped','all_issued_capabilities_revoked','owned_networks_removed','all_container_ids_absent','raw_preserved','all_root_readers_stopped','retained_evidence_key_free')}}
  terminalref=add(terminal,'hygiene');hreview=add({'status':'PASS','unresolved_findings':[],'actor_terminal_evidence_reviewed':True,'terminal_hygiene':terminalref},'hygiene-review')
  screenref=add({'status':'PASS','key_free_status':'KEY_FREE','credential_match_count':0,'all_selected_bytes_keyfree_before_first_hash':True,'credential_values_or_fingerprints_retained':False,'file_sha256':hashes},'screen');screenreview=add({'status':'PASS','unresolved_findings':[],'supports_retained_evidence_key_free':True,'screen_proof':screenref},'screen-review')
  masterref=add({'status':'removed','target':self.full['secrets_dir'],'store_removed':True,'temporary_parent_removed':True,'values_opened':False,'value_hashes_computed':False,'operator_original_store_selected':False,'removed_references':['PI_API_KEY','QUAL_APPLICATION_ALICE','QUAL_APPLICATION_BOB','QUAL_APPLICATION_SCRIPTED']},'master');masterreview=add({'status':'PASS','unresolved_findings':[],'supports_master_cleanup':True,'actual_all_metadata_actors_closed':True,'all_master_metadata_actors_closed':True,'master_cleanup':masterref},'master-review')
  inputsref=add({'inventory':add({},'inventory'),'descriptor':add({'secrets_dir':self.full['secrets_dir']},'descriptor')},'inputs')
  postref=add({'status':'PASS','classified_tree_counts':{'files':34,'bytes':24067,'trees':9},'master_store_and_parent_absent':True,'fixed_inputs':inputsref,'master_removed':masterref,**{k:True for k in ('source352_unchanged','current_public_history_unchanged','raw_five_pairs_unchanged','all125_Registry_bodies_unchanged')}},'post');postreview=add({'status':'PASS','unresolved_findings':[],'supports_post_master_preservation':True,'preservation_proof':postref},'post-review')
  release=add({'status':'ACKNOWLEDGED','shared_lease_priority_released':True,'testing_and_heartbeat_remain_paused':True},'release')
  cleanup={'status':'PASS','qualification_id':qid,'cumulative_container_launches':193,'participant_segments':9,'scripted_participant_segments':9,'real_model_participant_segments':0,'live_owned_containers':0,'known_current_credential_runtime_context_count':61,'post_cutoff_metadata_actor_context_count':18,'raw_current_counts':{'PASS':6,'FAIL':1,'NOT_RUN':21},'chronological_native_rows':448,'chronological_native_counts':{'PASS':55,'FAIL':1,'BLOCKED':15,'NOT_RUN':377},'terminal_hygiene':terminalref,'terminal_hygiene_review':hreview,'known_current_credential_runtime_actor_ids':actorids,'all_owned_container_ids':ids,'current_registry_records':records,'retained_evidence_screen':screenref,'retained_evidence_screen_review':screenreview,'post_master_preservation':postref,'post_master_preservation_review':postreview,'retained_evidence_file_sha256':hashes,'master_cleanup':masterref,'master_cleanup_review':masterreview,'coordination_release_acknowledgment':release,
   **{k:True for k in ('physical_absence_confirmed','private_cleanup_confirmed','master016_copy_removed','safe_for_final_handoff','current_registry_records_released','retained_evidence_key_free','retained_evidence_bytes_unchanged','raw_poison_and_flags_unchanged','product_private_cleanup_all30_true')},**{k:False for k in ('safe_to_continue','continued_execution_authorized','qualification_eligible','original_operator_store_touched','historical_numeric_PID_probes','credential_values_or_hashes_retained','master_cleanup_values_opened','master_cleanup_value_hashes_computed','manual_private_purge_performed','manual_registry_release_performed','raw_ledger_poisoned')}}
  self.cleanup=cleanup;self.value['prior_cleanup']=add(cleanup,'cleanup');self.value['prior_boundary_review']=add({'status':'PASS','unresolved_findings':[],'final_cleanup':self.value['prior_cleanup'],'actor_terminal_evidence_reviewed':True},'boundary');self.value['prior_final_audit']=add({'status':'PASS'},'audit');self.value['prior_actual_publication_review']=add({'status':'PASS','unresolved_findings':[]},'publication')
  self.records=copy.deepcopy(self.records)
  for patch in [mock.patch.object(current,'_reference',side_effect=lambda ref:copy.deepcopy(self.objects[ref['path']])),mock.patch.object(current,'_relative_reference',side_effect=lambda ref:copy.deepcopy(self.objects[ref['path']])),mock.patch.object(current,'_bytes_reference',return_value=b'FAKE'),mock.patch.object(launch,'_bound_json',side_effect=lambda path,digest:copy.deepcopy(self.records[Path(path).stem])),mock.patch.object(current,'_retained_metadata'),mock.patch.object(current.registry_api,'_qualification_absent',return_value=True)]:patch.start();self.addCleanup(patch.stop)
 def call(self):current._cleanup(self.value,self.full,self.ledger)
 def test_synthetic_graph_with_mocked_live_bodies_no_private_reads(self):self.call()
 def test_live_record_body_drift_denied(self):
  next(iter(self.records.values()))['cleanup_unknown']=True
  with self.assertRaises(launch.LaunchError):self.call()
 def test_changed_nonnull_container_identity_denied(self):
  self.records[self.ledger['launches'][0]['launch_id']]['container_id']='f'*64
  with self.assertRaises(launch.LaunchError):self.call()
 def test_master_removed_required(self):
  self.cleanup['master016_copy_removed']=False
  with self.assertRaises(launch.LaunchError):self.call()
 def test_current_context_count_never_old85(self):
  self.cleanup['known_current_credential_runtime_context_count']=85
  with self.assertRaises(launch.LaunchError):self.call()
 def test_raw_unpoisoned_preserved(self):
  self.cleanup['raw_ledger_poisoned']=True
  with self.assertRaises(launch.LaunchError):self.call()


def matrix_authority(diag):
 return {'schema':1,'document_type':'qualification_matrix_requalification_authorization','authorization_id':'c444f1b7-9924-4ac8-b4f2-645ac717021b','human_authorization':diag['human_authorization'],'recorded_wall':current.STARTED_WALL+1,
  'final_root':str(current.FINAL_ROOT),'maximum_matrix_origins':17,'prior_matrix_origins':16,'cumulative_container_launches':193,'cumulative_participant_segments':9,'previous_container_cap':349,'container_cap':380,'previous_participant_cap':30,'participant_cap':33,'live_cap':4,'trial_cap':1,'inference_slot_cap':1,'platform':'linux/arm64','automatic_retries':0,'continuations':0,'planned_new_container_launches':186,'planned_new_participant_segments':24,'diagnostic_container_launches':1,
  'window_authorization':copy.deepcopy(current.WINDOW_AUTHORIZATION),'started_wall':current.STARTED_WALL,'started_monotonic':current.STARTED_MONOTONIC,'deadline_wall':current.DEADLINE_WALL,'deadline_monotonic':current.DEADLINE_MONOTONIC,'prior_amendment':copy.deepcopy(current.PRIOR_AMENDMENT_REFERENCE),'original_boundary':copy.deepcopy(current.BOUNDARY_REFERENCE),
  **{'prior_'+k:copy.deepcopy(v)for k,v in current.PRIOR_REFERENCES.items()},**{k:copy.deepcopy(diag[k])for k in ('prior_cleanup','prior_boundary_review','prior_final_audit','prior_actual_publication_review')},'prior_independent_review':{'path':'/synthetic/final-independent.json','sha256':'a'*64},
  'diagnostic_authorization':copy.deepcopy(current.DIAGNOSTIC_AUTHORIZATION),'diagnostic_terminal':{'path':str(current.CAMPAIGN/'artifact-diagnostic-001/terminal.json'),'sha256':'e'*64},'diagnostic_ledger':{'path':str(current.CAMPAIGN/'artifact-diagnostic-001/launch-ledger/ledger.json'),'sha256':'f'*64},'diagnostic_independent_review':{'path':str(current.CAMPAIGN/'artifact-diagnostic-actual-independent-review/review.json'),'sha256':'d'*64},'diagnostic_validator':{'path':str(current.DIAGNOSTIC_VALIDATOR_PATH),'sha256':'c'*64},
  'original_evidence_modified':False,'historical_windows_modified':False,'additional_auxiliary_launches_authorized':0,'additional_startup_diagnostic_authorized':False,'eighteenth_origin_authorized':False}

class FinalMatrix(unittest.TestCase):
 def setUp(self):
  from types import SimpleNamespace
  self.diag=authority();self.window=window(self.diag);self.value=matrix_authority(self.diag);self.reference={'path':str(current.AUTHORIZATION_PATH),'sha256':'b'*64};self.now=current.STARTED_MONOTONIC+10;self.wall=current.STARTED_WALL+10
  self.prior={'attempts':193,'participant_segments':9,'planned_cells':448,'lineage':[{'qualification_id':str(uuid.uuid4())}for _ in range(16)],'prior_rows':[{'status':'NOT_RUN'}for _ in range(448)],'qualification_id':str(uuid.uuid4()),'startup_diagnostic':{'historical':'PRESERVED'},'previous_window':{'historical':'PRESERVED'}}
  self.closed={'attempts':1,'participant_segments':0,'native_rows':0,'root':str(current.CAMPAIGN/'artifact-diagnostic-001'),'container_id':'9'*64,'physical_absence_confirmed':True,'private_cleanup_confirmed':True,'all_writers_stopped':True,'manifest':{'path':str(current.CAMPAIGN/'artifact-diagnostic-001/manifest.json'),'sha256':'8'*64},**{k:copy.deepcopy(self.value[v])for k,v in [('terminal','diagnostic_terminal'),('ledger','diagnostic_ledger'),('independent_review','diagnostic_independent_review')]}}
  def reference(ref):
   if ref==self.reference:return copy.deepcopy(self.value)
   if ref==current.DIAGNOSTIC_AUTHORIZATION:return copy.deepcopy(self.diag)
   if ref==current.WINDOW_AUTHORIZATION:return copy.deepcopy(self.window)
   if ref==self.value['prior_independent_review']:return {'status':'PASS','unresolved_findings':[],'supports_ac80':True}
   raise AssertionError('unexpected synthetic reference')
  self.validator=mock.Mock(side_effect=lambda *a,**k:copy.deepcopy(self.closed))
  for patch in [mock.patch.object(current,'AUTHORIZATION_SHA256','b'*64),mock.patch.object(current,'AUTHORIZATION_ID',self.value['authorization_id']),mock.patch.object(current,'DIAGNOSTIC_VALIDATOR_SHA256','c'*64),mock.patch.object(current,'_reference',side_effect=reference),mock.patch.object(current,'validate_prior_for_diagnostic',side_effect=lambda *a,**k:copy.deepcopy(self.prior)),mock.patch.object(current,'_diagnostic_validator',return_value=SimpleNamespace(validate_closed_diagnostic=self.validator))]:patch.start();self.addCleanup(patch.stop)
 def call(self):return current.validate_amendment(self.reference,{'synthetic_only':True},clock=lambda:self.now,wall=lambda:self.wall)
 def test_actual_one_closed_diagnostic_adds_exactly_one_no_row_or_origin(self):
  value=self.call();self.assertEqual((value['attempts'],value['participant_segments'],value['planned_cells'],len(value['lineage'])),(194,9,448,16));self.assertEqual(value['startup_diagnostic'],self.prior['startup_diagnostic']);self.assertEqual(value['previous_window'],self.prior['previous_window']);self.assertEqual(len(value['prior_rows']),448);self.assertEqual(self.prior['attempts'],193);self.assertEqual(value['artifact_write_diagnostic'],self.closed)
 def test_missing_actual_terminal_never_counts_authority_as_execution(self):
  self.validator.side_effect=launch.LaunchError('missing_terminal')
  with self.assertRaises(launch.LaunchError):self.call()
  self.assertEqual(self.prior['attempts'],193)
 def test_bool_or_extra_launch_participant_native_row_counts_deny(self):
  for key,bad in [('attempts',True),('attempts',2),('participant_segments',1),('native_rows',1)]:
   original=self.closed[key];self.closed[key]=bad
   with self.subTest(key=key,bad=bad),self.assertRaises(launch.LaunchError):self.call()
   self.closed[key]=original
 def test_unconfirmed_physical_private_or_writer_cleanup_denies(self):
  for key in ('physical_absence_confirmed','private_cleanup_confirmed','all_writers_stopped'):
   self.closed[key]=False
   with self.subTest(key=key),self.assertRaises(launch.LaunchError):self.call()
   self.closed[key]=True
 def test_ref_mismatch_cannot_replace_actual_diagnostic(self):
  for key in ('terminal','ledger','independent_review'):
   original=self.closed[key];self.closed[key]={**original,'sha256':'0'*64}
   with self.subTest(key=key),self.assertRaises(launch.LaunchError):self.call()
   self.closed[key]=original
 def test_caps_origin_primary24_and_extra_authority_fields_deny(self):
  for key,bad in [('container_cap',381),('participant_cap',34),('maximum_matrix_origins',18),('planned_new_participant_segments',25),('diagnostic_container_launches',0),('eighteenth_origin_authorized',True)]:
   original=self.value[key];self.value[key]=bad
   with self.subTest(key=key),self.assertRaises(launch.LaunchError):self.call()
   self.value[key]=original
 def test_window_expiry_during_closure_validation_denies(self):
  def expired(*a,**k):self.wall=current.DEADLINE_WALL;return copy.deepcopy(self.closed)
  self.validator.side_effect=expired
  with self.assertRaises(launch.LaunchError):self.call()
 def test_exact_validator_source_ref_is_required(self):
  self.value['diagnostic_validator']['sha256']='0'*64
  with self.assertRaises(launch.LaunchError):self.call()


class QualifierProjection(unittest.TestCase):
 def setUp(self):
  from test_application_matrix16 import QualifierProjectionTests
  self.f=QualifierProjectionTests(methodName='runTest');self.f.setUp();self.addCleanup(self.f.doCleanups);self.q=self.f.q;self.harness=self.f.harness
  self.reference={'path':str(current.AUTHORIZATION_PATH),'sha256':'b'*64};self.carry=copy.deepcopy(self.f.carry)
  self.carry.update(attempts=194,participant_segments=9,planned_cells=448,campaign_amendment=self.reference,effective_limits={**launch.LIMITS,'container_launch_attempts':380,'participant_segments':33})
  self.carry['qualification_id']=str(uuid.uuid4());self.carry['lineage'].append({'root':'/synthetic/matrix16','qualification_id':self.carry['qualification_id']})
  self.diagref={'path':str(self.f.carry_fixture.e.root/'diagnostic-manifest.json'),'sha256':'7'*64};self.diagqid=str(uuid.uuid4());self.carry['artifact_write_diagnostic']={'manifest':self.diagref,'attempts':1,'participant_segments':0,'native_rows':0}
  self.clock=current.STARTED_MONOTONIC+10;self.wall=current.STARTED_WALL+10
  for name,value in [('AUTHORIZATION_ID','c444f1b7-9924-4ac8-b4f2-645ac717021b'),('AUTHORIZATION_SHA256','b'*64),('PRIOR_ROOT',self.f.carry_fixture.e.root/'matrix16-prior'),('BINDING_ROOT',self.f.carry_fixture.e.root/'matrix17-binding'),('FINAL_ROOT',self.q.output),('_authorization',lambda ref:matrix_authority(authority())if ref==self.reference else current.require(False)),('validate_amendment',lambda *a,**k:copy.deepcopy(self.carry))]:
   patch=mock.patch.object(current,name,value);patch.start();self.addCleanup(patch.stop)
  original=current._reference
  def reference(ref):
   if ref==self.diagref:return {'qualification_id':self.diagqid}
   path=Path(ref['path'])
   if path in (self.q.output/'manifest.json',self.q.output/'candidate.json'):
    body=path.read_bytes()
    if hashlib.sha256(body).hexdigest()!=ref['sha256']:raise launch.LaunchError('fixture_drift')
    return json.loads(body)
   return original(ref)
  patch=mock.patch.object(current,'_reference',side_effect=reference);patch.start();self.addCleanup(patch.stop)
  original_effective=launch._effective_carry
  def clocks(manifest,**kwargs):
   if manifest.get('campaign_amendment')==self.reference:kwargs.update(clock=lambda:self.clock,wall=lambda:self.wall)
   return original_effective(manifest,**kwargs)
  patch=mock.patch.object(launch,'_effective_carry',side_effect=clocks);patch.start();self.addCleanup(patch.stop)
 def freeze(self):self.q.freeze(predecessor=self.f.carry_fixture.e.base,campaign_boundary=current.BOUNDARY_REFERENCE,campaign_amendment=self.reference)
 def candidate(self,full):return {'archive_sha256':'e'*64,'runner_sha256':full['source']['runner'],'scope':'extracted_candidate'}
 def test_real_qualifier_freeze_verify_candidate_permanent_bind1949(self):
  self.freeze();full,state=self.harness.verify(self.q.output);self.assertEqual((full['limits']['container_launch_attempts'],full['limits']['participant_segments']),(380,33));self.assertEqual(sum(c['participant_segments_max']for c in full['cells']),24)
  projection=self.harness._launch_manifest(full);launch.validate_manifest(projection);self.harness.bind_candidate(self.q.output,self.candidate(full));self.harness.verify(self.q.output,require_candidate=True)
  refs=[{'path':str(self.q.output/name),'sha256':hashlib.sha256((self.q.output/name).read_bytes()).hexdigest()}for name in ('manifest.json','candidate.json')]
  current.finalize_candidate(self.reference,*refs,clock=lambda:self.clock,wall=lambda:self.wall);current.bind_final(self.q.output/'launch-ledger',projection,self.carry,create=True);current.bind_final(self.q.output/'launch-ledger',projection,self.carry)
  binding=json.loads((current.BINDING_ROOT/'launch-binding.json').read_bytes());self.assertEqual((binding['cumulative_attempts'],binding['participant_segments']),(194,9));self.assertFalse((self.q.output/'launch-ledger').exists())
 def test_wrong32_projection_denies_before_candidate_or_claim(self):
  self.freeze();full,_=self.harness.verify(self.q.output);original=self.harness._launch_manifest
  def wrong(value):p=original(value);p['limits']['participant_segments']=32;return p
  with mock.patch.object(self.harness,'_launch_manifest',side_effect=wrong),self.assertRaises(launch.LaunchError):self.harness.bind_candidate(self.q.output,self.candidate(full))
  self.assertFalse((self.q.output/'candidate.json').exists());self.assertFalse(current.BINDING_ROOT.exists())
 def test_duplicate_diagnostic_qualification_id_denies_before_claim(self):
  self.freeze();full,_=self.harness.verify(self.q.output);self.harness.bind_candidate(self.q.output,self.candidate(full));self.diagqid=full['qualification_id']
  refs=[{'path':str(self.q.output/name),'sha256':hashlib.sha256((self.q.output/name).read_bytes()).hexdigest()}for name in ('manifest.json','candidate.json')]
  with self.assertRaises(launch.LaunchError):current.finalize_candidate(self.reference,*refs,clock=lambda:self.clock,wall=lambda:self.wall)
  self.assertFalse(current.BINDING_ROOT.exists())
 def test_new_matrix_never_expands_primary_participants_to33(self):
  self.freeze();full,_=self.harness.verify(self.q.output);projection=self.harness._launch_manifest(full);next(c for c in projection['cells']if c['participant_segments_max'])['participant_segments_max']=25
  with self.assertRaises(launch.LaunchError):launch.validate_manifest(projection)

class Router(unittest.TestCase):
 def test_exact17_selector_and_legacy8_preserved(self):
  reference={'path':str(current.AUTHORIZATION_PATH),'sha256':current.AUTHORIZATION_SHA256}
  with mock.patch.object(current,'effective_limits',return_value={**launch.LIMITS,'container_launch_attempts':380,'participant_segments':33})as validated:
   self.assertIs(launch.amendment_module(reference),current);self.assertEqual(launch.maximum_origins(reference),17)
  self.assertEqual(validated.call_count,2);self.assertEqual(launch.maximum_origins(),8)
 def test_prior16_selector_unchanged(self):
  with mock.patch.object(current.prior_amendment,'effective_limits',return_value={**launch.LIMITS,'container_launch_attempts':349,'participant_segments':30}):self.assertEqual(launch.maximum_origins(current.PRIOR_AMENDMENT_REFERENCE),16)
 def test_alias_extra_or_changed_hash_denied(self):
  reference={'path':str(current.AUTHORIZATION_PATH),'sha256':current.AUTHORIZATION_SHA256}
  for bad in ({**reference,'sha256':'0'*64},{**reference,'path':reference['path']+'/../alias.json'},{**reference,'retry':False}):
   with self.subTest(reference=bad),self.assertRaises(launch.LaunchError):launch.amendment_module(bad)

class LibraryAdapter(unittest.TestCase):
 CODE=b"LAUNCH=None\nOWNERSHIP=None\nCLIENT=None\ndef validate_closed_diagnostic(*a,**k):\n global CLIENT\n if LAUNCH is None or OWNERSHIP is None:\n  import application_client\n  CLIENT=application_client\n return sorted(CLIENT.TRUSTED_CODE)\n"
 def setUp(self):
  self.inputs={'path':str(current.CAMPAIGN/'artifact-diagnostic-design/inputs-final-002.json'),'sha256':'a'*64};self.value={'diagnostic_terminal':{'path':'/synthetic/terminal.json','sha256':'b'*64}};self.pins={'scripts/fake.py':'c'*64,'runtime/fake.mjs':'d'*64}
 def test_current_predicates_and_fixed_historical_keyset_skip_bad_client_import(self):
  from types import SimpleNamespace
  with mock.patch.object(current,'_bytes_reference',return_value=self.CODE)as source,mock.patch.object(current,'_reference',return_value={'inputs':self.inputs}),mock.patch.object(current,'_relative_reference',return_value={'code_source_pins':self.pins}),mock.patch.dict(sys.modules,{'application_client':SimpleNamespace()}):
   library=current._diagnostic_validator(self.value);self.assertIs(library.LAUNCH,launch);self.assertIs(library.OWNERSHIP,current.registry_api);self.assertEqual(library.validate_closed_diagnostic(),sorted(self.pins))
  self.assertEqual(source.call_args.args[0],{'path':str(current.DIAGNOSTIC_VALIDATOR_PATH),'sha256':current.DIAGNOSTIC_VALIDATOR_SHA256})
 def test_unsafe_historical_code_key_refuses_without_current_code_reads(self):
  with mock.patch.object(current,'_bytes_reference',return_value=self.CODE),mock.patch.object(current,'_reference',return_value={'inputs':self.inputs}),mock.patch.object(current,'_relative_reference',return_value={'code_source_pins':{'../escape.py':'c'*64}}),self.assertRaises(launch.LaunchError):current._diagnostic_validator(self.value)
 def test_fresh_creator_tools_first_order_never_imports_maintainer_client(self):
  code="import sys;from pathlib import Path;from types import SimpleNamespace;root=Path(%r);sys.path[:0]=[str(root/'tools/qualification'),str(root/'skill/scripts'),str(root/'skill/runtime')];import application_matrix17 as m;m._bytes_reference=lambda ref:%r;m._reference=lambda ref:{'inputs':{'path':str(m.CAMPAIGN/'artifact-diagnostic-design/inputs-final-002.json'),'sha256':'a'*64}};m._relative_reference=lambda ref:{'code_source_pins':{'scripts/fake.py':'c'*64,'runtime/fake.mjs':'d'*64}};sys.modules['application_client']=SimpleNamespace();library=m._diagnostic_validator({'diagnostic_terminal':{'path':'/synthetic/terminal.json','sha256':'b'*64}});assert library.LAUNCH is m.launch;assert library.OWNERSHIP is m.registry_api;assert library.validate_closed_diagnostic()==['runtime/fake.mjs','scripts/fake.py'];print('PASS fixed library adapter')"%(str(R),self.CODE)
  result=subprocess.run([sys.executable,'-B','-c',code],capture_output=True,text=True,timeout=10)
  self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout.strip(),'PASS fixed library adapter')

class RetainedMetadata(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve();self.root.chmod(0o700);roots=[]
  for i in range(9):
   root=self.root/('tree'+str(i));root.mkdir(mode=0o700);(root/'a').mkdir(mode=0o700)
   if i<7:(root/'b').mkdir(mode=0o700)
   roots.append(root)
  for i in range(34):p=roots[i%9]/'a'/('f'+str(i));p.write_bytes(b'FAKE');p.chmod(0o600)
  trees=[];self.hashes={}
  for root in roots:
   def meta(path):
    st=path.stat();return {'device':st.st_dev,'inode':st.st_ino,'uid':st.st_uid,'mode':st.st_mode&0o777,'nlink':st.st_nlink,'size':st.st_size,'mtime_ns':st.st_mtime_ns,'ctime_ns':st.st_ctime_ns,'kind':'directory'if path.is_dir()else'regular'}
   trees.append({'path':str(root),'state':'present','metadata':meta(root),'nodes':[{'relative':str(p.relative_to(root)),**meta(p)}for p in root.rglob('*')]})
   self.hashes[str(root)]={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()for p in root.rglob('*')if p.is_file()}
  self.inventory={'cells':[{'retained_roots':trees[i:i+3]}for i in range(0,9,3)]};self.roots=roots
  patch=mock.patch.object(current,'PRIOR_ROOT',self.root);patch.start();self.addCleanup(patch.stop)
 def call(self):current._retained_metadata(self.inventory,self.hashes)
 def test_exact_metadata_opens_directories_only_never_payload(self):
  original=os.open;flags=[]
  def opened(name,mode,*args,**kwargs):flags.append(mode);return original(name,mode,*args,**kwargs)
  with mock.patch.object(current.os,'open',side_effect=opened):self.call()
  self.assertTrue(flags);self.assertTrue(all(mode&os.O_DIRECTORY for mode in flags))
 def test_unknown_entry_refuses_no_payload_read(self):
  (self.roots[0]/'a/UNSEEN').write_bytes(b'NO_READ')
  with mock.patch.object(current.os,'read')as read,self.assertRaises(launch.LaunchError):self.call()
  read.assert_not_called()
 def test_known_symlink_refuses(self):
  p=next((self.roots[0]/'a').iterdir());p.unlink();p.symlink_to('/unused')
  with self.assertRaises(launch.LaunchError):self.call()
 def test_missing_declared_hash_leaf_denied(self):
  self.hashes[str(self.roots[0])].pop(next(iter(self.hashes[str(self.roots[0])])))
  with self.assertRaises(launch.LaunchError):self.call()


if __name__=='__main__':unittest.main()
