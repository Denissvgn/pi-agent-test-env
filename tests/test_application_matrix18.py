"""Synthetic matrix18 replay, fresh metadata and exactly-one diagnostic guards."""
import copy,hashlib,json,os,stat,sys,tempfile,unittest,uuid
from pathlib import Path
from unittest import mock
R=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(R/'tests'),str(R/'skill/scripts'),str(R/'skill/runtime'),str(R/'tools/qualification')]
import application_matrix18 as current
import application_launch as launch
from test_application_matrix17 import fixture as old_fixture


def common():
 return {'schema':1,'human_authorization':'Synthetic bounded diagnostic then matrix18','window_authorization':current.WINDOW_AUTHORIZATION,
  'recorded_wall':current.STARTED_WALL,'started_monotonic':current.STARTED_MONOTONIC,'started_wall':current.STARTED_WALL,'deadline_monotonic':current.DEADLINE_MONOTONIC,'deadline_wall':current.DEADLINE_WALL,
  'prior_cumulative_container_launches':233,'prior_cumulative_participant_segments':13,'container_cap':432,'participant_cap':37,'automatic_retries':0,'continuations':0,'platform':'linux/arm64',
  'original_boundary':current.BOUNDARY_REFERENCE,**{key:current.BASIS_REFERENCES[basis]for key,basis in [('prior_cleanup','cleanup'),('prior_boundary_review','boundary_review'),('prior_source029_handoff','source029_handoff')]}}


def diagnostic_authority():
 return {**common(),'prior_cumulative_container_launches':245,'document_type':'bounded_fixture_startup_diagnostic_authorization','authorization_id':str(uuid.uuid4()),'maximum_diagnostic_launches':1,'diagnostic_participants':0,'inference_calls':0,'live_cap':1,'trial_cap':1,
  'original_lease_required':True,'matrix18_requires_diagnostic_terminal_cleanup':True,'overall_seconds':120,'work_seconds_max':90,'cleanup_seconds':30,'fixture_cpu_millis':250,'fixture_memory_mib':128,'fixture_pids':64,'fixture_host_port':57570,'real_credentials':0,'dummy_application_keys':2,'fixture_image':'sha256:'+'1'*64,'image_recovery_authorization':current.IMAGE_RECOVERY_AUTHORIZATION}


def grant():
 return {'schema':1,'document_type':'qualification_window_authorization','authorization_text':common()['human_authorization'],
  **{k:common()[k]for k in ('started_monotonic','started_wall','deadline_monotonic','deadline_wall')},
  'maximum_container_launches':420,'maximum_participant_segments':37,'carry_container_launches':233,'carry_participant_segments':13,'maximum_live_containers':4,'maximum_active_trials':1,'maximum_inference_slots':1,'diagnostic_containers':1,'diagnostic_participants':0,'diagnostic_required_before_matrix':True,'automatic_retries':0,'continuations':0}


def fixture():
 full,policy,_,_,_=old_fixture();policy['limits']={**launch.LIMITS,'container_launch_attempts':380,'participant_segments':33};policy['campaign_amendment']=current.PRIOR_AMENDMENT_REFERENCE
 full.update(copy.deepcopy(policy),prepared_root=str(current.PRIOR_ROOT));state={'schema':1,'phase':'blocked','started_at':current.historical.STARTED_WALL,'active_cell':None,'cells':{}}
 rows=[];registry='a'*64
 for index,cell in enumerate(full['cells'][:9]):
  item={'status':'PASS','attempts':1,'evidence_level':'native_infrastructure'}if index<4 else{'status':'BLOCKED'if index==8 else'PASS','attempts':1,'run_id':str(uuid.uuid4()),'attempt_id':str(uuid.uuid4())}
  if 4<=index<8:item.update(runner_status='FAIL',exit_code=1,interruption_sent=False)
  if index==8:item['private_cleanup']='unconfirmed';state['active_cell']={'id':cell['id'],'pid':10000,'run_id':item['run_id'],'attempt_id':item['attempt_id']}
  state['cells'][cell['id']]=item
  for role in (cell['role_limits']if index<8 else['fixture']):
   uid=str(uuid.uuid4());rows.append({'key':launch._digest({'registry':registry,'launch_id':uid}),'cell':cell['id'],'role':role,'registry':registry,'generation':str(uuid.uuid4()),'launch_id':uid,'container':'pi-lab-'+uuid.uuid4().hex,'image':'sha256:'+'1'*64,'resources':launch._role_weight(policy,cell,role),'physical':'absent','private_cleanup':True,'pid':200+len(rows),'intent_sha256':'c'*64,'container_id':hashlib.sha256(uid.encode()).hexdigest(),'cleanup_requests':[],'launch_policy':'explicit_pull_never_owned_id_5s'})
 prior={'attempts':194,'participant_segments':9,'qualification_id':str(uuid.uuid4()),'planned_cells':448,'started':current.historical.STARTED_MONOTONIC,'deadline':current.historical.DEADLINE_MONOTONIC,'started_wall':current.historical.STARTED_WALL,'deadline_wall':current.historical.DEADLINE_WALL,
  'daemon':'synthetic-daemon','daemon_capacity':{'cpu_millis':18000,'memory_mib':8192},'lineage':[{'qualification_id':str(uuid.uuid4()),'root':'/synthetic/'+str(i)}for i in range(16)],'prior_rows':[{'status':'NOT_RUN'}for _ in range(448)],'startup_diagnostic':{'old_failed':'PRESERVED'},'artifact_write_diagnostic':{'old_artifact':'PRESERVED'},'original_window':{'old1':True},'previous_window':{'old2':True},'_historical_native_ids':[]}
 ledger={'schema':1,'manifest_sha256':launch._digest(policy),'daemon':prior['daemon'],'daemon_capacity':prior['daemon_capacity'],'started':prior['started'],'deadline':prior['deadline'],'started_wall':prior['started_wall'],'deadline_wall':prior['deadline_wall'],'last_now':prior['started']+1,'last_wall':prior['started_wall']+1,'poisoned':False,'launches':rows,'carry':{'descriptor_sha256':launch._digest(full['predecessor']),**{k:prior[k]for k in ('attempts','participant_segments','qualification_id','planned_cells')}}}
 return full,policy,state,ledger,prior


class Authority(unittest.TestCase):
 def setUp(self):
  self.auth=diagnostic_authority();self.ref={'path':current.DIAGNOSTIC_AUTHORIZATION['path'],'sha256':'d'*64};self.grant=grant()
  self.objects={self.ref['path']:self.auth,current.WINDOW_AUTHORIZATION['path']:self.grant,current.PRIOR_REFERENCES['manifest']['path']:{'images':{'core-0.87.1':{'id':self.auth['fixture_image']}}}}
  for p in [mock.patch.object(current,'_image_recovery_authorization',return_value={'recorded_wall':current.STARTED_WALL}),mock.patch.object(current,'DIAGNOSTIC_AUTHORIZATION',self.ref),mock.patch.object(current,'_reference',side_effect=lambda r:copy.deepcopy(self.objects[r['path']]))]:p.start();self.addCleanup(p.stop)
 def test_exact_one_fixture_no_inference_or_participant(self):self.assertEqual(current._diagnostic_authorization(self.ref)['maximum_diagnostic_launches'],1)
 def test_role_cap_clock_retry_and_platform_expansions_refuse(self):
  for key,bad in [('maximum_diagnostic_launches',2),('diagnostic_participants',1),('inference_calls',1),('container_cap',433),('participant_cap',38),('live_cap',2),('platform','linux/amd64'),('automatic_retries',1),('cleanup_seconds',31),('real_credentials',1),('dummy_application_keys',3),('deadline_wall',current.DEADLINE_WALL+1)]:
   original=self.auth[key];self.auth[key]=bad
   with self.subTest(key=key),self.assertRaises(launch.LaunchError):current._diagnostic_authorization(self.ref)
   self.auth[key]=original
 def test_unknown_field_and_bool_integer_refuse(self):
  self.auth['maximum_diagnostic_launches']=True
  with self.assertRaises(launch.LaunchError):current._diagnostic_authorization(self.ref)
  self.auth['maximum_diagnostic_launches']=1;self.auth['retry']=False
  with self.assertRaises(launch.LaunchError):current._diagnostic_authorization(self.ref)
 def test_changed_grant_or_old_window_refuse(self):
  self.grant['maximum_inference_slots']=2
  with self.assertRaises(launch.LaunchError):current._diagnostic_authorization(self.ref)
 def test_unbound_full_authority_refuses_before_read(self):
  with mock.patch.object(current,'_reference')as read,self.assertRaises(launch.LaunchError):current.effective_limits({'path':str(current.AUTHORIZATION_PATH),'sha256':None})
  read.assert_not_called()


class PriorProjection(unittest.TestCase):
 def setUp(self):
  self.full,self.policy,self.state,self.ledger,self.prior=fixture()
  self.objects={current.PRIOR_REFERENCES[k]['path']:v for k,v in [('manifest',self.full),('state',self.state),('ledger',self.ledger)]}
  for p in [mock.patch.object(current,'_image_recovery_authorization',return_value={'recorded_wall':current.STARTED_WALL}),mock.patch.object(current,'_reference',side_effect=lambda r:copy.deepcopy(self.objects[r['path']])),mock.patch.object(current,'_replay_prior',side_effect=lambda *args:copy.deepcopy(self.prior)),mock.patch.object(current.historical,'_launch_policy',return_value=self.policy),mock.patch.object(current,'_cleanup'),mock.patch.object(launch,'_successor_claim')]:p.start();self.addCleanup(p.stop)
 def call(self,mono=None,wall=None,window=True):return current.validate_prior_for_image_recovery({},self.full['predecessor'],clock=lambda:current.STARTED_MONOTONIC+1 if mono is None else mono,wall=lambda:current.STARTED_WALL+1 if wall is None else wall,window=window)
 def test_real_central_validation_233_13_476_17_and_both_diagnostics_preserved(self):
  out=self.call();self.assertEqual((out['attempts'],out['participant_segments'],out['planned_cells'],len(out['lineage'])),(233,13,476,17))
  for k in ('startup_diagnostic','artifact_write_diagnostic','original_window','previous_window'):self.assertEqual(out[k],self.prior[k])
  self.assertEqual(out['effective_limits']['participant_segments'],37);self.assertEqual(self.state['cells'][self.full['cells'][8]['id']]['private_cleanup'],'unconfirmed')
 def test_expired_new_window_refuses_historical_false_preserves_rows(self):
  for mono,wall in [(current.DEADLINE_MONOTONIC,current.STARTED_WALL+1),(current.STARTED_MONOTONIC+1,current.DEADLINE_WALL)]:
   with self.assertRaises(launch.LaunchError):self.call(mono,wall)
  self.assertEqual(self.call(current.DEADLINE_MONOTONIC+1,current.DEADLINE_WALL+1,False)['attempts'],233)
 def test_poison_private_false_and_wrong_resources_not_repaired(self):
  for edit in ('poison','private','resource'):
   original=copy.deepcopy(self.ledger)
   if edit=='poison':self.ledger['poisoned']=True
   elif edit=='private':self.ledger['launches'][0]['private_cleanup']=False
   else:self.ledger['launches'][0]['resources']['memory_mib']+=1
   with self.subTest(edit=edit),self.assertRaises(launch.LaunchError):self.call()
   self.ledger.clear();self.ledger.update(original)
 def test_stale_state_retained_but_wrong_cell_or_private_claim_refused(self):
  item=self.state['cells'][self.full['cells'][8]['id']];item['private_cleanup']='confirmed'
  with self.assertRaises(launch.LaunchError):self.call()
  item['private_cleanup']='unconfirmed';self.state['active_cell']['id']=self.full['cells'][7]['id']
  with self.assertRaises(launch.LaunchError):self.call()
 def test_later_cell_or_fifth_pass_refused(self):
  self.state['cells'][self.full['cells'][8]['id']]['status']='PASS'
  with self.assertRaises(launch.LaunchError):self.call()
 def test_inherited_participant_cap_is_9_before_current4(self):
  self.ledger['carry']['participant_segments']=10
  with self.assertRaises(launch.LaunchError):self.call()


def metadata(path):
 i=path.lstat();return {'device':i.st_dev,'inode':i.st_ino,'uid':i.st_uid,'mode':stat.S_IMODE(i.st_mode),'nlink':i.st_nlink,'size':i.st_size,'mtime_ns':i.st_mtime_ns,'ctime_ns':i.st_ctime_ns,'kind':'directory'if stat.S_ISDIR(i.st_mode)else'regular'}


class RetainedMetadata(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve();self.root.chmod(0o700);trees=[];self.hashes={}
  for n in range(13):
   root=self.root/str(n);root.mkdir(mode=0o700)
   for x in range(3 if n<8 else 2):(root/('d'+str(x))).mkdir(mode=0o700)
   self.hashes[str(root)]={}
   for x in range(6 if n<5 else 5):
    p=root/('file'+str(x));p.write_bytes(b'SYNTHETIC');p.chmod(0o600);self.hashes[str(root)][p.name]=hashlib.sha256(b'SYNTHETIC').hexdigest()
   trees.append({'path':str(root),'state':'present','metadata':metadata(root),'nodes':[{'relative':str(p.relative_to(root)),**metadata(p)}for p in root.rglob('*')]})
  trees.append({'path':str(self.root/'absent'),'state':'absent'});self.inventory={'cells':[{'retained_roots':trees}]}
  p=mock.patch.object(current,'PRIOR_ROOT',self.root);p.start();self.addCleanup(p.stop)
 def call(self):current._retained_metadata(self.inventory,self.hashes)
 def test_exact_13_trees_117_nodes_70_files_without_opening_payload(self):
  original=os.open
  def dirs_only(path,flags,*args,**kwargs):
   self.assertTrue(flags&os.O_DIRECTORY,'A payload open was attempted');return original(path,flags,*args,**kwargs)
  with mock.patch.object(os,'open',side_effect=dirs_only):self.call()
 def test_added_unknown_file_is_refused_without_open(self):
  p=self.root/'0'/'unknown';p.write_bytes(b'CANARY');p.chmod(0o600)
  with self.assertRaises(launch.LaunchError):self.call()
 def test_added_unknown_directory_refused(self):
  (self.root/'0'/'unknown').mkdir(mode=0o700)
  with self.assertRaises(launch.LaunchError):self.call()
 def test_known_leaf_inode_replacement_refused(self):
  p=self.root/'0'/'file0';p.unlink();p.write_bytes(b'SYNTHETIC');p.chmod(0o600)
  with self.assertRaises(launch.LaunchError):self.call()
 def test_known_absence_became_present_refused(self):
  (self.root/'absent').mkdir(mode=0o700)
  with self.assertRaises((launch.LaunchError,current.registry_api.RegistryError)):self.call()


class DiagnosticGate(unittest.TestCase):
 def setUp(self):
  self.ref={'path':str(current.AUTHORIZATION_PATH),'sha256':'a'*64};self.prior={'attempts':245,'participant_segments':13,'planned_cells':476,'lineage':[{}]*17,'startup_diagnostic':{'first':'KEEP'},'artifact_write_diagnostic':{'second':'KEEP'}}
  def r(name):return {'path':str(current.CAMPAIGN/'startup-diagnostic-001'/name),'sha256':'d'*64}
  self.binding={k:r(name)for k,name in [('manifest','manifest.json'),('ledger','launch-ledger/ledger.json'),('terminal','terminal.json')]};self.binding['independent_review']={'path':str(current.CAMPAIGN/'startup-diagnostic-actual-independent-review/review.json'),'sha256':'e'*64}
  self.diag={**self.binding,'attempts':1,'participant_segments':0,'native_rows':0,'root':str(current.CAMPAIGN/'startup-diagnostic-001'),'container_id':'f'*64,**{k:True for k in ('physical_absence_confirmed','private_cleanup_confirmed','all_writers_stopped','fixture_startup_ready','strict_nonce_and_initial_journal','stopped_terminal_confirmed','evidence_key_free')}}
  self.value={'planned_new_container_launches':186,'planned_new_participant_segments':24}
  for p in [mock.patch.object(current,'_authorization',return_value=self.value),mock.patch.object(current,'validate_prior_for_diagnostic',return_value=self.prior),mock.patch.object(current,'_diagnostic_binding',return_value=self.binding),mock.patch.object(current,'_diagnostic_validator',return_value=mock.Mock(validate_closed_diagnostic=lambda *a,**k:copy.deepcopy(self.diag))),mock.patch.object(current,'effective_limits',return_value={**launch.LIMITS,'container_launch_attempts':432,'participant_segments':37})]:p.start();self.addCleanup(p.stop)
 def call(self):return current.validate_amendment(self.ref,{},clock=lambda:current.STARTED_MONOTONIC+1,wall=lambda:current.STARTED_WALL+1)
 def test_exact_closed_one_adds1_with_zero_native_rows_and_preserves_both_old(self):
  out=self.call();self.assertEqual(out['attempts'],246);self.assertEqual(out['participant_segments'],13);self.assertEqual(out['planned_cells'],476)
  for k in ('startup_diagnostic','artifact_write_diagnostic'):self.assertEqual(out[k],self.prior[k])
  self.assertEqual(out['fixture_startup_diagnostic'],self.diag)
 def test_missing_binding_no_increment(self):
  with mock.patch.object(current,'_diagnostic_binding',side_effect=launch.LaunchError('not_bound')),self.assertRaises(launch.LaunchError):self.call()
  self.assertEqual(self.prior['attempts'],245)
 def test_failed_nonce_cleanup_extra_attempt_or_native_row_refuses(self):
  for k,v in [('fixture_startup_ready',False),('strict_nonce_and_initial_journal',False),('stopped_terminal_confirmed',False),('evidence_key_free',False),('private_cleanup_confirmed',False),('all_writers_stopped',False),('attempts',2),('attempts',True),('native_rows',1),('participant_segments',1)]:
   old=self.diag[k];self.diag[k]=v
   with self.subTest(k=k,v=v),self.assertRaises(launch.LaunchError):self.call()
   self.diag[k]=old
 def test_terminal_or_review_substitution_denied(self):
  self.diag['terminal']={**self.diag['terminal'],'sha256':'0'*64}
  with self.assertRaises(launch.LaunchError):self.call()
 def test_wrong_24_participant_projection_denied(self):
  self.value['planned_new_participant_segments']=23
  with self.assertRaises(launch.LaunchError):self.call()



class ReleasedRecordBodies(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve();self.root.chmod(0o700);self.retained=self.root/'retained';self.live=self.root/'live'
  self.retained.mkdir(mode=0o700);self.live.mkdir(mode=0o700);self.refs=[]
  for i in range(169):
   uid=str(uuid.uuid4());body=launch._json({'launch_id':uid,'daemon':'synthetic-daemon','status':'released','qualification_service_cleanup':{'receipt':'unchanged'},'qualification_preworker_cleanup':None})
   for folder in (self.retained,self.live):
    p=folder/(uid+'.json');p.write_bytes(body);p.chmod(0o600)
   self.refs.append({'path':str(self.retained/(uid+'.json')),'sha256':hashlib.sha256(body).hexdigest()})
  for p in [mock.patch.object(current,'_registry_root',return_value=self.live),mock.patch.object(current,'_relative_reference',side_effect=lambda r:launch._bound_json(r['path'],r['sha256']))]:p.start();self.addCleanup(p.stop)
 def test_all169_current_full_bodies_fresh_sha_bound(self):
  records,digests=current._released_records(self.refs,'synthetic-daemon');self.assertEqual(len(records),169);self.assertEqual(len(digests),169)
 def test_excluded_cleanup_pointer_drift_refuses_without_ledger_or_resource_effect(self):
  p=self.live/Path(self.refs[0]['path']).name;d=json.loads(p.read_bytes());d['qualification_service_cleanup']={'receipt':'changed'};p.write_bytes(launch._json(d))
  with self.assertRaises(launch.LaunchError):current._released_records(self.refs,'synthetic-daemon')
 def test_missing_record_and_duplicate_record_refuse(self):
  p=self.live/Path(self.refs[0]['path']).name;p.unlink()
  with self.assertRaises((launch.LaunchError,OSError)):current._released_records(self.refs,'synthetic-daemon')
  refs=self.refs[1:]+[self.refs[1]]
  with self.assertRaises(launch.LaunchError):current._released_records(refs,'synthetic-daemon')


class PublicReplay(unittest.TestCase):
 def setUp(self):
  self.objects={};self.full,self.policy,self.state,self.ledger,_=fixture();self.base=self.full['predecessor'];self.lineage=[];self.rows=[]
  def add(path,value):
   self.objects[str(path)]=value;return {'path':str(path),'sha256':launch._digest(value)}
  self.add=add
  for i in range(16):
   root=current.REPO/'reports/application-agent-enhancements/A15'/('synthetic-'+str(i));qid=str(uuid.uuid4());cells=[{'id':'c'+str(n)}for n in range(28)]
   full={'qualification_id':qid,'prepared_root':str(root),'cells':cells}
   if i:full['predecessor']=self.base if i>=7 else{'schema':1,**{k:self.lineage[-1][k]for k in ('root','manifest_sha256','state_sha256','ledger_sha256')},'cleanup_receipts':[]}
   state={'cells':{}};rows=[{'container_id':hashlib.sha256((str(i)+'-'+str(n)).encode()).hexdigest(),'role':'participant'if i<9 and n==0 else'fixture'}for n in range(12 if i<13 else 11)]
   ledger={'daemon':self.ledger['daemon'],'daemon_capacity':self.ledger['daemon_capacity'],'launches':rows}
   refs={k:add(root/name,value)for k,name,value in [('manifest','manifest.json',full),('state','state.json',state),('ledger','launch-ledger/ledger.json',ledger)]}
   self.lineage.append({'root':str(root),'qualification_id':qid,**{k+'_sha256':v['sha256']for k,v in refs.items()}});self.rows+=current._rows(full,state)
  self.ledger['carry']['qualification_id']=self.lineage[-1]['qualification_id']
  snap={'reference':current.PRIOR_AMENDMENT_REFERENCE,'attempts':194,'participant_segments':9,'planned_cells':448,'lineage':self.lineage,'prior_rows':self.rows,'started_wall':current.historical.STARTED_WALL,'deadline_wall':current.historical.DEADLINE_WALL,'original_window':{'old':'IMMUTABLE'}}
  add(current.BASIS_REFERENCES['report']['path'],{'qualification_id':self.full['qualification_id'],'campaign_amendment':snap});self.snapshot=snap
  window={'started_monotonic':1.,'deadline_monotonic':14401.,'started_wall':100.,'deadline_wall':14500.};add(current.BASIS_REFERENCES['window2']['path'],window)
  binding=add('/synthetic/boundary-binding.json',{'authorization':current.BASIS_REFERENCES['window2']});aux=add('/synthetic/aux.json',{'launches':[{'cleanup':None}for _ in range(3)]});recovery=add('/synthetic/recovery.json',{'document_type':'qualification_known_auxiliary_cleanup'})
  add(current.BOUNDARY_REFERENCE['path'],{'binding':binding,'ledger':aux,'recovery':recovery})
  oldledger=add('/synthetic/old-startup-ledger.json',{'launches':[{'role':'application-helper'}]});add(current.BASIS_REFERENCES['old_startup']['path'],{'document_type':'qualification_failed_startup_diagnostic_known_cleanup','driver_status':'BLOCKED','cleanup_accounting':'FAILED','raw_ledger_preserved':True,'native_success_attested':False,'ledger':oldledger,'manifest':{'path':'/synthetic/old-startup/manifest.json','sha256':'a'*64}})
  add(current.BASIS_REFERENCES['old_startup_review']['path'],{'status':'PASS','unresolved_findings':[],'known_cleanup':current.BASIS_REFERENCES['old_startup']})
  dledger=add('/synthetic/artifact/ledger.json',{'launches':[{'container_id':'f'*64}]});dmanifest={'path':'/synthetic/artifact/manifest.json','sha256':'b'*64}
  dterminal=add('/synthetic/artifact/terminal.json',{'status':'PASS','new_container_intents':1,'new_participants':0,'inference_calls':0,'credentials':0,'container_id':'f'*64,'manifest':dmanifest,'ledger':dledger,**{k:True for k in ('all_owned_host_children_waited','physical_absence_confirmed','private_cleanup_confirmed','disposable_root_removed')}})
  dreview=add('/synthetic/artifact/review.json',{'status':'PASS','unresolved_findings':[],'supports_diagnostic_cleanup':True,'terminal':dterminal,'manifest':dmanifest,'ledger':dledger})
  add(current.PRIOR_AMENDMENT_REFERENCE['path'],{'diagnostic_terminal':dterminal,'diagnostic_ledger':dledger,'diagnostic_independent_review':dreview})
  p=mock.patch.object(current,'_reference',side_effect=lambda r:copy.deepcopy(self.objects[r['path']]));p.start();self.addCleanup(p.stop)
 def call(self):return current._replay_prior(self.full,self.ledger,self.base)
 def test_public16_origin194_9_carry_preserves_both_diagnostic_identities(self):
  p=self.call();self.assertEqual((p['attempts'],p['participant_segments'],len(p['prior_rows']),len(p['lineage'])),(194,9,448,16));self.assertEqual(len(p['_historical_native_ids']),189)
  self.assertEqual(p['startup_diagnostic']['outcome'],'startup_failed');self.assertEqual(p['artifact_write_diagnostic']['attempts'],1)
 def test_report_prior_row_status_mutation_refused(self):
  self.snapshot['prior_rows']=copy.deepcopy(self.rows);self.snapshot['prior_rows'][0]['status']='PASS'
  with self.assertRaises(launch.LaunchError):self.call()
 def test_duplicate_lineage_or_container_refused(self):
  self.snapshot['lineage'][1]=copy.deepcopy(self.snapshot['lineage'][0])
  with self.assertRaises(launch.LaunchError):self.call()
 def test_native_ledger_participant_count_mutation_refused(self):
  first=self.objects[str(Path(self.lineage[0]['root'])/'launch-ledger/ledger.json')];first['launches'][0]['role']='fixture'
  with self.assertRaises(launch.LaunchError):self.call()
 def test_historical_diagnostic_cleanup_failure_not_promoted(self):
  self.objects[current.BASIS_REFERENCES['old_startup']['path']]['native_success_attested']=True
  with self.assertRaises(launch.LaunchError):self.call()



class RecoveryBridge(unittest.TestCase):
 def setUp(self):
  self.prior={'attempts':233,'participant_segments':13,'planned_cells':476,'lineage':[{}]*17,'startup_diagnostic':{'first':'KEEP'},'artifact_write_diagnostic':{'second':'KEEP'}}
  self.descriptor={'attempts':12,'participant_segments':0,'native_rows':0,'root':str(current.CAMPAIGN/'image-recovery-002'),'qualified_images':{'core-0.87.1':{'id':'sha256:'+'1'*64}}}
  for p in [mock.patch.object(current,'_diagnostic_authorization',return_value={'fixture_image':'sha256:'+'1'*64}),mock.patch.object(current,'validate_prior_for_image_recovery',return_value=self.prior),mock.patch.object(current,'_closed_recovery',side_effect=lambda *a,**k:copy.deepcopy(self.descriptor))]:p.start();self.addCleanup(p.stop)
 def call(self):return current.validate_prior_for_diagnostic({}, {},clock=lambda:current.STARTED_MONOTONIC+1,wall=lambda:current.STARTED_WALL+1)
 def test_only_positive_closed12_recovery_yields245_without_native_rows(self):
  out=self.call();self.assertEqual((out['attempts'],out['participant_segments'],out['planned_cells'],len(out['lineage'])),(245,13,476,17))
  for k in ('startup_diagnostic','artifact_write_diagnostic'):self.assertEqual(out[k],self.prior[k])
  self.assertEqual(out['image_recovery'],self.descriptor);self.assertEqual(self.prior['attempts'],233)
 def test_authorization_alone_or_failed_recovery_never_increments(self):
  with mock.patch.object(current,'_closed_recovery',side_effect=launch.LaunchError('no_actual_recovery')),self.assertRaises(launch.LaunchError):self.call()
  self.assertEqual(self.prior['attempts'],233)
 def test_changed_prior_count_does_not_grant_extra12(self):
  self.prior['attempts']=234
  with self.assertRaises(launch.LaunchError):self.call()



class QualifiedImages(unittest.TestCase):
 def setUp(self):
  self.images={name:{'id':'sha256:'+str(i+1)*64,'platform':'linux/arm64','capabilities':{'pi':name.split('-',1)[1]}}for i,name in enumerate(('core-0.87.1','browser-0.87.1','core-1.2.0','browser-1.2.0'))}
 def test_exact_four_distinct_arm64_images(self):self.assertEqual(current._qualified_images(self.images),self.images)
 def test_duplicate_id_wrong_platform_or_version_refuse(self):
  for field,value in [('id',self.images['browser-0.87.1']['id']),('platform','linux/amd64'),('capabilities',{'pi':'other'})]:
   original=copy.deepcopy(self.images['core-0.87.1']);self.images['core-0.87.1'][field]=value
   with self.subTest(field=field),self.assertRaises(launch.LaunchError):current._qualified_images(self.images)
   self.images['core-0.87.1']=original



class QualifierProjection(unittest.TestCase):
 def setUp(self):
  from test_application_matrix16 import QualifierProjectionTests
  self.f=QualifierProjectionTests(methodName='runTest');self.f.setUp();self.addCleanup(self.f.doCleanups);self.q=self.f.q;self.harness=self.f.harness
  self.reference={'path':str(current.AUTHORIZATION_PATH),'sha256':'b'*64};self.carry=copy.deepcopy(self.f.carry)
  self.carry.update(attempts=246,participant_segments=13,planned_cells=476,campaign_amendment=self.reference,effective_limits={**launch.LIMITS,'container_launch_attempts':432,'participant_segments':37})
  for origin in (16,17):self.carry['lineage'].append({'root':'/synthetic/matrix'+str(origin),'qualification_id':str(uuid.uuid4())})
  self.carry['qualification_id']=self.carry['lineage'][-1]['qualification_id'];self.diagqid=str(uuid.uuid4());self.diagref={'path':str(self.f.carry_fixture.e.root/'startup-diagnostic-manifest.json'),'sha256':'7'*64}
  self.carry['fixture_startup_diagnostic']={'manifest':self.diagref,'attempts':1,'participant_segments':0,'native_rows':0}
  self.clock=current.STARTED_MONOTONIC+10;self.wall=current.STARTED_WALL+10
  for name,value in [('AUTHORIZATION_ID','f94be22e-5461-4f18-8068-0ba86a6257e1'),('AUTHORIZATION_SHA256','b'*64),('PRIOR_ROOT',self.f.carry_fixture.e.root/'matrix17-prior'),('BINDING_ROOT',self.f.carry_fixture.e.root/'matrix18-binding'),('FINAL_ROOT',self.q.output),('_authorization',lambda ref:{}if ref==self.reference else current.require(False)),('validate_amendment',lambda *a,**k:copy.deepcopy(self.carry))]:
   patch=mock.patch.object(current,name,value);patch.start();self.addCleanup(patch.stop)
  original=current._reference
  def reference(ref):
   if ref==self.diagref:return {'qualification_id':self.diagqid}
   path=Path(ref['path'])
   if path in (self.q.output/'manifest.json',self.q.output/'candidate.json'):
    body=path.read_bytes()
    if hashlib.sha256(body).hexdigest()!=ref['sha256']:raise launch.LaunchError('synthetic_drift')
    return json.loads(body)
   return original(ref)
  patch=mock.patch.object(current,'_reference',side_effect=reference);patch.start();self.addCleanup(patch.stop)
  original_effective=launch._effective_carry
  def clocks(manifest,**kwargs):
   if manifest.get('campaign_amendment')==self.reference:kwargs.update(clock=lambda:self.clock,wall=lambda:self.wall)
   return original_effective(manifest,**kwargs)
  patch=mock.patch.object(launch,'_effective_carry',side_effect=clocks);patch.start();self.addCleanup(patch.stop)
 def freeze(self):
  self.q.freeze(predecessor=self.f.carry_fixture.e.base,campaign_boundary=current.BOUNDARY_REFERENCE,campaign_amendment=self.reference)
  full=json.loads((self.q.output/'manifest.json').read_bytes());self.carry['image_recovery']={'qualified_images':copy.deepcopy(full['images'])}
 def candidate(self,full):return {'archive_sha256':'e'*64,'runner_sha256':full['source']['runner'],'scope':'extracted_candidate'}
 def test_real_freeze_verify_candidate_permanent_bind43237_with_prior24613(self):
  self.freeze();full,state=self.harness.verify(self.q.output);self.assertEqual((full['limits']['container_launch_attempts'],full['limits']['participant_segments']),(432,37));self.assertEqual(sum(c['participant_segments_max']for c in full['cells']),24)
  projection=self.harness._launch_manifest(full);launch.validate_manifest(projection);self.harness.bind_candidate(self.q.output,self.candidate(full));self.harness.verify(self.q.output,require_candidate=True)
  refs=[{'path':str(self.q.output/name),'sha256':hashlib.sha256((self.q.output/name).read_bytes()).hexdigest()}for name in ('manifest.json','candidate.json')]
  current.finalize_candidate(self.reference,*refs,clock=lambda:self.clock,wall=lambda:self.wall);current.bind_final(self.q.output/'launch-ledger',projection,self.carry,create=True);current.bind_final(self.q.output/'launch-ledger',projection,self.carry)
  binding=json.loads((current.BINDING_ROOT/'launch-binding.json').read_bytes());self.assertEqual((binding['cumulative_attempts'],binding['participant_segments']),(246,13));self.assertFalse((self.q.output/'launch-ledger').exists())
 def test_wrong36_projection_refuses_before_candidate_or_claim(self):
  self.freeze();full,_=self.harness.verify(self.q.output);original=self.harness._launch_manifest
  def wrong(value):result=original(value);result['limits']['participant_segments']=36;return result
  with mock.patch.object(self.harness,'_launch_manifest',side_effect=wrong),self.assertRaises(launch.LaunchError):self.harness.bind_candidate(self.q.output,self.candidate(full))
  self.assertFalse((self.q.output/'candidate.json').exists());self.assertFalse(current.BINDING_ROOT.exists())
 def test_recovered_image_map_drift_refuses_before_permanent_claim(self):
  self.freeze();full,_=self.harness.verify(self.q.output);self.harness.bind_candidate(self.q.output,self.candidate(full));self.carry['image_recovery']['qualified_images']['core-0.87.1']['id']='sha256:'+'f'*64
  refs=[{'path':str(self.q.output/name),'sha256':hashlib.sha256((self.q.output/name).read_bytes()).hexdigest()}for name in ('manifest.json','candidate.json')]
  with self.assertRaises(launch.LaunchError):current.finalize_candidate(self.reference,*refs,clock=lambda:self.clock,wall=lambda:self.wall)
  self.assertFalse(current.BINDING_ROOT.exists())
 def test_exact18_route_and_primary24_legacy8_unchanged(self):
  self.assertIs(launch.amendment_module(self.reference),current);self.assertEqual(launch.maximum_origins(self.reference),18);self.assertEqual(launch.maximum_origins(),8)
  self.freeze();full,_=self.harness.verify(self.q.output);projection=self.harness._launch_manifest(full);next(c for c in projection['cells']if c['participant_segments_max'])['participant_segments_max']=25
  with self.assertRaises(launch.LaunchError):launch.validate_manifest(projection)

if __name__=='__main__':unittest.main()
