"""One explicit matrix18 origin after a separately closed fixture startup diagnostic.

Historical carry is replayed from SHA-pinned public ledger/report bytes. Retained
KEY_FREE evidence is checked by exact FD metadata/name sets; its payload is never
opened by this adapter. Historical diagnostics remain distinct from the new one.
"""
import copy
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import time
import types
import application_launch as launch
import application_campaign as campaign
import application_matrix17 as historical
import ownership_registry as registry_api

REPO=Path(__file__).resolve().parents[2]
CAMPAIGN=REPO/'reports/application-agent-enhancements/A15/campaign-012'
AUTHORIZATION_PATH=CAMPAIGN/'matrix-018-authorization-003.json'
AUTHORIZATION_SHA256='67b10dc6abc60f2ba72adadba21c5d47530881a6bec83dffeebaf2bcdf91b9d4'
AUTHORIZATION_ID='8f5ce6bf-a8a9-4c2b-84cc-c277af207548'
DIAGNOSTIC_AUTHORIZATION={'path':str(CAMPAIGN/'startup-diagnostic-authorization.json'),'sha256':'55adccd59d3d8e49bc4bf5118a8e2eba258644c78550a9c19b66e44af075835e'}
DIAGNOSTIC_VALIDATOR_PATH=CAMPAIGN/'startup-diagnostic-design/diagnostic_002.py'
DIAGNOSTIC_VALIDATOR_SHA256='b85fcf87f9731c2448555111b1e3be4c0a0563808e6ead6afa0e0dc165c22425'
DIAGNOSTIC_BINDING_PATH=CAMPAIGN/'startup-diagnostic-binding.json'
IMAGE_RECOVERY_AUTHORIZATION={'path':str(CAMPAIGN/'image-recovery-authorization.json'),'sha256':'8145535688c2303655cb8a0468f5c40adfc72348c5b08ddf96de99e15b01ab0b'}
IMAGE_RECOVERY_VALIDATOR_PATH=CAMPAIGN/'image-recovery-design/recover_002.py'
IMAGE_RECOVERY_VALIDATOR_SHA256='1838864005c48f2e8d411783e3e54de98d274eb1f9dcd43a0a51e03225570d72'
IMAGE_RECOVERY_BINDING_PATH=CAMPAIGN/'image-recovery-binding.json'
WINDOW_AUTHORIZATION={'path':str(CAMPAIGN/'user-authorization.json'),'sha256':'6adf4d6a7090d24b1876549c8b6c6396ec311f7148c1034a7cfaccd5604c2210'}
PRIOR_ROOT=REPO/'reports/application-agent-enhancements/A15/attempt-017/qualification'
FINAL_ROOT=REPO/'reports/application-agent-enhancements/A15/attempt-018/qualification'
BINDING_ROOT=CAMPAIGN/'matrix-018-successor'
PRIOR_AMENDMENT_REFERENCE={'path':str(historical.AUTHORIZATION_PATH),'sha256':historical.AUTHORIZATION_SHA256}
BOUNDARY_REFERENCE=copy.deepcopy(historical.BOUNDARY_REFERENCE)
STARTED_MONOTONIC=686925.524116416
STARTED_WALL=1792411092.976367
DEADLINE_MONOTONIC=701325.524116416
DEADLINE_WALL=1792425492.976367
BASIS_REFERENCES={'report': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-017/commands/report/stdout.log', 'sha256': 'b5cb69617523ca55c07618cf65eca2632830cf96ef35da4e784c937c209a4cc7'}, 'manifest': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-017/qualification/manifest.json', 'sha256': '7a6e5f3c694ae7d193ecded560c59a6b63db4ca5ffec75ba18fb5a84fa7dd603'}, 'state': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-017/qualification/state.json', 'sha256': 'd6fee3863bcd6af59223ddb428fb4d12b93f96ad54620424bec5cc6025fdfff1'}, 'ledger': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-017/qualification/launch-ledger/ledger.json', 'sha256': '1c270bd356e8495fe204ab2e6bb118f1f49aef240b75e4fa197e00507e042ee7'}, 'cleanup': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-017/final-cleanup.json', 'sha256': '3078c5fd93bc2a7bfcbeca7b850b6b56b76e2207d07dac89a9d9b42036190006'}, 'boundary_review': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-017/final-cleanup-independent-review/review.json', 'sha256': '809a1126b1d8d02087467a2081e192c156fe2891eae42d635d09f83cb3527d63'}, 'source029_handoff': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A16/attempt-015/final-audit-actual-independent-review/review.json', 'sha256': 'ce4eeba7ea45a385be3ca4688eb3995c3943a0699e36c268ead1c2fe49f8e80c'}, 'window2': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/campaign-window-002-authorization.json', 'sha256': '96eb796121279a8b42de0f7dc765155aa9a663b00bb1fa6e5db080fbb0547c9f'}, 'old_startup': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/campaign-004/diagnostic-known-cleanup-001/known-cleanup.json', 'sha256': '6514efb3e98b5a2c6885396c458666aa22937c64a782c524045a405e987ac8ee'}, 'old_startup_review': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/campaign-004/diagnostic-known-cleanup-001/independent-review.json', 'sha256': '4b1a62b21d462ec06f6cdc9237a8c24024e9082a103a13fc4248c706046e3761'}}
PRIOR_REFERENCES={k:BASIS_REFERENCES[k]for k in ("manifest","state","ledger")}
_reference=historical._reference
_relative_reference=historical._relative_reference
_same_reference=historical._same_reference
_bytes_reference=historical._bytes_reference


def require(value):
 if not value:raise launch.LaunchError('qualification_matrix18_invalid')


def _clock(clock,wall,window):
 now,wallnow=launch._number(clock()),launch._number(wall())
 require(now>=STARTED_MONOTONIC and wallnow>=STARTED_WALL)
 if window:require(now<DEADLINE_MONOTONIC-30 and wallnow<DEADLINE_WALL-30)
 return now,wallnow


def _window(value):
 require(value['window_authorization']==WINDOW_AUTHORIZATION)
 grant=_reference(WINDOW_AUTHORIZATION)
 expected={'schema':1,'document_type':'qualification_window_authorization','started_monotonic':STARTED_MONOTONIC,'started_wall':STARTED_WALL,
  'deadline_monotonic':DEADLINE_MONOTONIC,'deadline_wall':DEADLINE_WALL,'maximum_container_launches':420,'maximum_participant_segments':37,
  'carry_container_launches':233,'carry_participant_segments':13,'maximum_live_containers':4,'maximum_active_trials':1,'maximum_inference_slots':1,
  'diagnostic_containers':1,'diagnostic_participants':0,'diagnostic_required_before_matrix':True,'automatic_retries':0,'continuations':0}
 for k,v in expected.items():require(type(grant[k])is type(v)and grant[k]==v)
 require(value['human_authorization']==grant['authorization_text']and DEADLINE_MONOTONIC-STARTED_MONOTONIC==DEADLINE_WALL-STARTED_WALL==14400)
 return grant


def _image_recovery_authorization(reference):
 require(reference==IMAGE_RECOVERY_AUTHORIZATION);value=_reference(reference)
 fixed={'schema':1,'document_type':'qualification_image_recovery_authorization','maximum_container_launches':432,'maximum_participant_segments':37,
  'maximum_recovery_container_launches':12,'carry_containers':233,'carry_participants':13,'maximum_live_containers':4,'maximum_trials':1,'maximum_inference_slots':1,
  'deadline_wall':DEADLINE_WALL,'deadline_monotonic':DEADLINE_MONOTONIC,'window_extended':False,'automatic_retries':0,'continuations':0,'platform':'linux/arm64',
  'model_requests_in_recovery':0,'original_credentials_in_builds':False}
 for k,v in fixed.items():require(type(value[k])is type(v)and value[k]==v)
 require(_same_reference(value['original_window'],WINDOW_AUTHORIZATION))
 plan=_relative_reference(value['recovery_plan']);require(plan['schema']==1)
 return value


def _diagnostic_authorization(reference):
 require(type(DIAGNOSTIC_AUTHORIZATION['sha256'])is str and reference==DIAGNOSTIC_AUTHORIZATION)
 value=_reference(reference)
 fixed={'schema':1,'document_type':'bounded_fixture_startup_diagnostic_authorization','prior_cumulative_container_launches':245,
  'prior_cumulative_participant_segments':13,'container_cap':432,'participant_cap':37,'maximum_diagnostic_launches':1,'diagnostic_participants':0,
  'inference_calls':0,'live_cap':1,'trial_cap':1,'platform':'linux/arm64','automatic_retries':0,'continuations':0,'original_lease_required':True,
  'matrix18_requires_diagnostic_terminal_cleanup':True,'started_monotonic':STARTED_MONOTONIC,'started_wall':STARTED_WALL,
  'deadline_monotonic':DEADLINE_MONOTONIC,'deadline_wall':DEADLINE_WALL,'overall_seconds':120,'work_seconds_max':90,'cleanup_seconds':30,
  'fixture_cpu_millis':250,'fixture_memory_mib':128,'fixture_pids':64,'fixture_host_port':57570,'real_credentials':0,'dummy_application_keys':2}
 launch._exact(value,set(fixed)|{'authorization_id','human_authorization','window_authorization','recorded_wall','original_boundary','prior_cleanup','prior_boundary_review','prior_source029_handoff','fixture_image','image_recovery_authorization'})
 for k,v in fixed.items():require(type(value[k])is type(v)and value[k]==v)
 launch._uuid(value['authorization_id']);require(value['original_boundary']==BOUNDARY_REFERENCE)
 for k,b in [('prior_cleanup','cleanup'),('prior_boundary_review','boundary_review'),('prior_source029_handoff','source029_handoff')]:require(value[k]==BASIS_REFERENCES[b])
 require(value['image_recovery_authorization']==IMAGE_RECOVERY_AUTHORIZATION)
 require(type(value['fixture_image'])is str and value['fixture_image'].startswith('sha256:'));launch._sha(value['fixture_image'][7:])
 _image_recovery_authorization(IMAGE_RECOVERY_AUTHORIZATION)
 require(STARTED_WALL<=launch._number(value['recorded_wall'])<DEADLINE_WALL)
 _window(value);return value


def _rows(full,state):
 return [{'qualification_id':full['qualification_id'],'cell':c['id'],'status':state['cells'].get(c['id'],{}).get('status','NOT_RUN'),'attempts':state['cells'].get(c['id'],{}).get('attempts',0)}for c in full['cells']]


def _replay_prior(full,ledger,base):
 """Replay public sixteen-origin rows, retaining the reviewed historical overlays."""
 report=_reference(BASIS_REFERENCES['report']);snapshot=report['campaign_amendment']
 require(report['qualification_id']==full['qualification_id']and snapshot['reference']==PRIOR_AMENDMENT_REFERENCE
  and(snapshot['attempts'],snapshot['participant_segments'],snapshot['planned_cells'],len(snapshot['lineage']))==(194,9,448,16))
 lineage=snapshot['lineage'];rows=[];ids=set();participants=0;capacities=[];roots=set();qids=set()
 for index,entry in enumerate(lineage):
  launch._exact(entry,{'root','qualification_id','manifest_sha256','state_sha256','ledger_sha256'})
  root=launch._canonical_root(entry['root']);require(root.is_relative_to(REPO/'reports/application-agent-enhancements/A15')and str(root)not in roots and entry['qualification_id']not in qids)
  roots.add(str(root));qids.add(entry['qualification_id'])
  docs={k:_reference({'path':str(root/p),'sha256':entry[k+'_sha256']})for k,p in [('manifest','manifest.json'),('state','state.json'),('ledger','launch-ledger/ledger.json')]}
  f,s,l=(docs[k]for k in ('manifest','state','ledger'));require(f['qualification_id']==entry['qualification_id']and f['prepared_root']==str(root)and len(f['cells'])==28 and l['daemon']==ledger['daemon'])
  if index==0:require(f.get('predecessor')is None)
  elif index<7:
   predecessor=f['predecessor'];previous=lineage[index-1]
   require(all(predecessor[k]==previous[k]for k in ('root','manifest_sha256','state_sha256','ledger_sha256')))
   for proof in predecessor['cleanup_receipts']:_reference(proof)
  else:require(f['predecessor']==base)
  rows+=_rows(f,s);capacities.append(l['daemon_capacity'])
  for r in l['launches']:
   require(r['container_id']is not None and r['container_id']not in ids);launch._sha(r['container_id']);ids.add(r['container_id']);participants+=r['role']=='participant'
 require(rows==snapshot['prior_rows']and len(ids)==189 and participants==9 and lineage[-1]['qualification_id']==ledger['carry']['qualification_id'])
 boundary=_reference(BOUNDARY_REFERENCE);binding=_reference(boundary['binding']);oldwindow=_reference(BASIS_REFERENCES['window2'])
 require(binding['authorization']==BASIS_REFERENCES['window2'])
 # The pinned cleanup overlay preserves the auxiliary uncertain raw row unchanged.
 auxiliary=_reference(boundary['ledger']);recovery=_reference(boundary['recovery']);require(len(auxiliary['launches'])==3 and recovery['document_type']=='qualification_known_auxiliary_cleanup')
 for row in auxiliary['launches']:
  if row['cleanup'] is not None:_reference(row['cleanup'])
 old=_reference(BASIS_REFERENCES['old_startup']);review=_reference(BASIS_REFERENCES['old_startup_review'])
 require(old['document_type']=='qualification_failed_startup_diagnostic_known_cleanup'and old['driver_status']=='BLOCKED'and old['cleanup_accounting']=='FAILED'
  and old['raw_ledger_preserved']is True and old['native_success_attested']is False and review['status']=='PASS'and review['unresolved_findings']==[]and _same_reference(review['known_cleanup'],BASIS_REFERENCES['old_startup']))
 oldledger=_reference(old['ledger']);require(len(oldledger['launches'])==1 and oldledger['launches'][0]['role']=='application-helper')
 startup={'reference':copy.deepcopy(BASIS_REFERENCES['old_startup']),'attempts':1,'participant_segments':0,'native_rows':0,'root':str(Path(old['manifest']['path']).parent),'outcome':'startup_failed','driver_status':'BLOCKED','cleanup_accounting':'FAILED','native_success_attested':False}
 auth=_reference(PRIOR_AMENDMENT_REFERENCE);terminal=_reference(auth['diagnostic_terminal']);dledger=_reference(auth['diagnostic_ledger']);dreview=_reference(auth['diagnostic_independent_review'])
 require(terminal['status']=='PASS'and terminal['new_container_intents']==1 and terminal['new_participants']==terminal['inference_calls']==terminal['credentials']==0
  and all(terminal[k]is True for k in ('all_owned_host_children_waited','physical_absence_confirmed','private_cleanup_confirmed','disposable_root_removed'))
  and dreview['status']=='PASS'and dreview['unresolved_findings']==[]and dreview['supports_diagnostic_cleanup']is True and dreview['terminal']==auth['diagnostic_terminal']and dreview['ledger']==auth['diagnostic_ledger']and dreview['manifest']==terminal['manifest']
  and len(dledger['launches'])==1 and dledger['launches'][0]['container_id']==terminal['container_id']and terminal['ledger']==auth['diagnostic_ledger'])
 artifact={k:copy.deepcopy(auth['diagnostic_'+k])for k in ('terminal','ledger','independent_review')}
 artifact.update(attempts=1,participant_segments=0,native_rows=0,root=str(Path(terminal['manifest']['path']).parent),manifest=terminal['manifest'],container_id=terminal['container_id'],physical_absence_confirmed=True,private_cleanup_confirmed=True,all_writers_stopped=True)
 capacity={k:min(c[k]for c in capacities+[ledger['daemon_capacity']])for k in ('cpu_millis','memory_mib')}
 return {'attempts':194,'participant_segments':9,'qualification_id':lineage[-1]['qualification_id'],'planned_cells':448,
  **{k:lineage[-1][k]for k in ('manifest_sha256','state_sha256','ledger_sha256')},'lineage':copy.deepcopy(lineage),'prior_rows':rows,
  'started':historical.STARTED_MONOTONIC,'deadline':historical.DEADLINE_MONOTONIC,'started_wall':snapshot['started_wall'],'deadline_wall':snapshot['deadline_wall'],
  'daemon':ledger['daemon'],'daemon_capacity':capacity,'original_window':copy.deepcopy(snapshot['original_window']),
  'previous_window':{'started':oldwindow['started_monotonic'],'deadline':oldwindow['deadline_monotonic'],'started_wall':oldwindow['started_wall'],'deadline_wall':oldwindow['deadline_wall']},
  'campaign_boundary':copy.deepcopy(BOUNDARY_REFERENCE),'campaign_amendment':copy.deepcopy(PRIOR_AMENDMENT_REFERENCE),'base_attempts':51,'auxiliary_attempts':3,
  'startup_diagnostic':startup,'artifact_write_diagnostic':artifact,'effective_limits':{**launch.LIMITS,'container_launch_attempts':380,'participant_segments':33},'_historical_native_ids':sorted(ids)}


def _contextual_actors(terminal,cleanup):
 actors={};require(type(terminal['actor_chains'])is list and len(terminal['actor_chains'])==2)
 for item in terminal['actor_chains']:
  launch._exact(item,{'chain','review'});chain=_relative_reference(item['chain']);review=_relative_reference(item['review'])
  require(chain['status']=='PASS'and chain['document_type']=='qualification_owned_actor_terminal_chain'and chain['positive_terminal_chain']is True
   and chain['no_unconfirmed_owned_children']is True and review['status']=='PASS'and review['unresolved_findings']==[]
   and _same_reference(review['actor_chain'],item['chain'])and review['supports_global_actor_terminal_chain']is True)
  current=chain['actors'];require(type(current)is list and current and len(current)==len(chain['covered_actor_ids']))
  for actor in current:
   context=actor['context'];pid=actor['pid'];identifier=actor['actor_id'];launch._sha(identifier)
   launch._exact(context,{'qualification_id','cell_id','run_id','attempt_id','stage_id','launch_id','role','parent_context','pid'})
   require(type(pid)is int and pid>1 and type(context['pid'])is int and context['pid']==pid and type(context['parent_context'])is dict
    and context['qualification_id']==terminal['qualification_id']and launch._digest(context)==identifier and identifier not in actors
    and actor['terminal_proofs']and actor['source_proofs'])
   actors[identifier]=actor
  require(sorted(a['actor_id']for a in current)==chain['covered_actor_ids']==review['covered_actor_ids']
   and sorted({a['pid']for a in current})==chain['covered_pids']==review['covered_pids'])
  for actor in current:
   for ref in actor['terminal_proofs']:_bytes_reference(ref)
   for ref in actor['source_proofs']:_bytes_reference(ref)
  for proof in chain['terminal_proofs']:_relative_reference(proof)
  for proof in chain['source_proofs']:_bytes_reference(proof)
 require(len(actors)==84 and sorted(actors)==terminal['current_actor_ids']==cleanup['known_current_actor_ids']
  and terminal['current_actors']==[actors[k]for k in sorted(actors)])
 return actors


def _retained_metadata(inventory,hashes):
 """Fresh known-name/inode metadata only; no opening or hashing70 payloads."""
 roots={};files=nodes_count=0
 for cell in inventory['cells']:
  for tree in cell['retained_roots']:
   root=launch._canonical_root(tree['path']);require(root.is_relative_to(PRIOR_ROOT)and str(root)not in roots)
   if tree['state']=='absent':
    require(registry_api._qualification_absent(str(root)));continue
   require(tree['state']=='present')
   nodes={'.':tree['metadata'],**{n['relative']:n for n in tree['nodes']}};require(len(nodes)==1+len(tree['nodes']))
   require(set(hashes[str(root)])=={name for name,node in nodes.items()if node['kind']=='regular'})
   for name,expected in nodes.items():
    require(name=='.'or(not Path(name).is_absolute()and '..'not in Path(name).parts))
    path=root if name=='.'else root/name;fd=launch._dir(path.parent,False)
    try:info=os.stat(path.name,dir_fd=fd,follow_symlinks=False)
    finally:os.close(fd)
    kind='directory'if stat.S_ISDIR(info.st_mode)else'regular'if stat.S_ISREG(info.st_mode)else'forbidden'
    require(kind==expected['kind']and info.st_uid==os.getuid()and stat.S_IMODE(info.st_mode)==expected['mode']
     and all(getattr(info,attr)==expected[key]for attr,key in [('st_dev','device'),('st_ino','inode'),('st_nlink','nlink'),('st_size','size'),('st_mtime_ns','mtime_ns'),('st_ctime_ns','ctime_ns')]))
    if kind=='directory':
     fd=launch._dir(path)
     try:require(set(os.listdir(fd))=={Path(n).name for n in nodes if n!='.'and str(Path(n).parent)==('.'if name=='.'else name)})
     finally:os.close(fd)
     require(expected['mode']==0o700)
    else:require(kind=='regular'and expected['mode']==0o600 and expected['nlink']==1);files+=1
    nodes_count+=1
   roots[str(root)]=nodes
 require(len(roots)==13 and set(roots)==set(hashes)and nodes_count==117 and files==70)



def _metadata_support(reference,count,qid):
 support=_relative_reference(reference)
 require(support['status']=='PASS'and support['metadata_context_count']==count and support['credential_runtime_context_cutoff']==84
  and support['individual_wrapper_OS_wait_invented']is False and support['numeric_PID_probe_performed']is False)
 actors=support['actors'];require(len(actors)==count and len({a['actor_id']for a in actors})==count)
 for actor in actors:
  context=actor['context'];require(context['qualification_id']==qid and type(actor['pid'])is int and actor['pid']>1 and type(context['pid'])is int and context['pid']==actor['pid']and launch._digest(context)==actor['actor_id'])
  require(actor['terminal_proofs'])
  for ref in actor['terminal_proofs']:_bytes_reference(ref)
  for ref in actor.get('source_proofs',[]):_bytes_reference(ref)
 require(sorted(a['actor_id']for a in actors)==support['covered_actor_ids']and sorted({a['pid']for a in actors})==support['covered_pids'])
 return {a['actor_id']for a in actors}


def _registry_root():
 return Path.home()/'.local/state/pi-agentic-development/operation.lock.registry'


def _released_records(records,daemon):
 require(type(records)is list and len(records)==169)
 pinned={};digests={};registry=_registry_root()
 for ref in records:
  record=_relative_reference(ref);key=record['launch_id'];launch._uuid(key)
  require(key not in pinned and record['status']=='released'and record['daemon']==daemon)
  require(launch._bound_json(str(registry/(key+'.json')),ref['sha256'])==record)
  pinned[key]=record;digests[key]=ref['sha256']
 return pinned,digests


def _cleanup(full,state,ledger,prior):
 cleanup=_reference(BASIS_REFERENCES['cleanup']);review=_reference(BASIS_REFERENCES['boundary_review']);handoff=_reference(BASIS_REFERENCES['source029_handoff'])
 require(review['status']==handoff['status']==cleanup['status']=='PASS'and review['unresolved_findings']==handoff['unresolved_findings']==[]
  and review['supports_final_handoff']is True and _same_reference(review['final_cleanup'],BASIS_REFERENCES['cleanup'])and handoff['supports_final_offline_handoff']is True
  and handoff['current_source_archive_sha256']=='7c6e3590b0a4a1222dd50b8cb23ee0ba7e001ef48123ed33f62794637cb0a10a'
  and handoff['current_runner_sha256']=='ad2f7eb69a47017643a02c22a44727d653fe61b2f0703f06f011b09e9b6bdd62'
  and handoff['current_Source029_native_qualification']=='NOT_RUN')
 require(cleanup['qualification_id']==full['qualification_id']and cleanup['cumulative_container_launches']==233 and cleanup['participant_segments']==13
  and cleanup['scripted_participant_segments']==13 and cleanup['real_model_participant_segments']==0 and cleanup['live_owned_containers']==0
  and cleanup['known_current_context_count']==84 and cleanup['post_cutoff_master_metadata_contexts']==18 and cleanup['post_cutoff_preservation_metadata_contexts']==4
  and cleanup['total_contextual_terminal_support']==106 and cleanup['raw_current_counts']=={'PASS':8,'BLOCKED':1,'NOT_RUN':19}
  and cleanup['chronological_native_rows']==476 and cleanup['chronological_native_counts']=={'PASS':63,'FAIL':1,'BLOCKED':16,'NOT_RUN':396})
 for k in ('physical_absence_confirmed','private_cleanup_confirmed','master017_copy_removed','safe_for_final_handoff','current_registry_records_released',
  'retained_evidence_key_free','retained_evidence_bytes_unchanged','raw_poison_and_flags_unchanged','product_private_cleanup_all39_true','raw_ledger_all39_private_true_preserved',
  'raw_fifth_cell_private_cleanup_unconfirmed_preserved','outer_bootstrap_removed','all5_outer_bootstrap_ancestors_absent'):require(cleanup[k]is True)
 for k in ('safe_to_continue','continued_execution_authorized','qualification_eligible','native_qualification_success_attested','original_operator_store_modified',
  'original_operator_store_selected_for_cleanup','historical_numeric_PID_probes','credential_values_or_hashes_retained','master_cleanup_values_opened','master_cleanup_value_hashes_computed',
  'manual_container_removal_performed','manual_registry_release_performed','raw_ledger_poisoned'):require(cleanup[k]is False)
 require(cleanup['pending_actual_refs']==[]and cleanup['raw_active_cell_retained']==state['active_cell'])
 terminal=_relative_reference(cleanup['terminal_hygiene']);treview=_relative_reference(cleanup['terminal_hygiene_review'])
 require(terminal['status']==treview['status']=='PASS'and treview['unresolved_findings']==[]and treview['actor_terminal_evidence_reviewed']is True
  and _same_reference(treview['terminal_hygiene'],cleanup['terminal_hygiene'])and _same_reference(terminal['current_ledger'],PRIOR_REFERENCES['ledger'])
  and _same_reference(terminal['current_state'],PRIOR_REFERENCES['state'])and terminal['known_current_context_count']==84)
 for k in ('all_native_writers_absent','all_service_writers_stopped','all_helper_writers_stopped','all_qualification_controllers_stopped','all_issued_capabilities_revoked',
  'all_root_readers_stopped','all_container_ids_absent','owned_networks_removed','raw_preserved','retained_evidence_key_free'):require(terminal[k]is True)
 actors=_contextual_actors(terminal,cleanup)
 for row in ledger['launches']:
  require(len([a for a in actors.values()if a['context']['qualification_id']==full['qualification_id']and a['context']['cell_id']==row['cell']and a['context']['launch_id']==row['launch_id']and a['context']['role']==row['role']and a['pid']==row['pid']])==1)
 mid=_metadata_support(cleanup['master_metadata_terminal_support'],18,full['qualification_id']);postids=_metadata_support(cleanup['post_preservation_terminal_support'],4,full['qualification_id'])
 require(not(set(actors)&mid or set(actors)&postids or mid&postids))
 old=_relative_reference(terminal['prior_cleanup']);artifact=prior['artifact_write_diagnostic']
 ids=cleanup['all_owned_container_ids'];require(type(ids)is list and len(ids)==len(set(ids))==233 and ids==terminal['all_owned_container_ids']
  and len(old['all_owned_container_ids'])==193 and set(ids)==set(old['all_owned_container_ids'])|{artifact['container_id']}|{r['container_id']for r in ledger['launches']}
  and set(prior['_historical_native_ids']).issubset(old['all_owned_container_ids']))
 records=cleanup['current_registry_records'];require(records==terminal['current_registry_records']and len(records)==169)
 pinned,digests=_released_records(records,ledger['daemon'])
 oldrefs={_relative_reference(ref)['launch_id']:ref['sha256']for ref in old['current_registry_records']}
 dterminal=_reference(artifact['terminal']);drecord=_relative_reference(dterminal['registry_record']);networks=terminal['network_launch_ids']
 require(len(oldrefs)==125 and len(networks)==len(set(networks))==4 and set(pinned)==set(oldrefs)|{drecord['launch_id']}|{r['launch_id']for r in ledger['launches']}|set(networks)
  and all(digests[k]==v for k,v in oldrefs.items())and digests[drecord['launch_id']]==dterminal['registry_record']['sha256'])
 for row in ledger['launches']:
  record=pinned[row['launch_id']];require(launch._intent_identity(record)==row['intent_sha256']and all(record[k]==row[k]for k in ('launch_id','registry','generation','image','container'))and record.get('container_id')in(None,row['container_id']))
 helpers=[pinned[r['launch_id']]for r in ledger['launches']if r['role']=='application-helper'];require(len(helpers)==4)
 for helper in helpers:
  matches=[pinned[k]for k in networks if pinned[k]['container']==helper['container']+'-network'];require(len(matches)==1)
  network=matches[0];require(network['kind']=='network'and all(network[k]==helper[k]for k in ('registry','generation','daemon')))
 screen=_relative_reference(cleanup['retained_evidence_screen']);sreview=_relative_reference(cleanup['retained_evidence_screen_review'])
 post=_relative_reference(cleanup['post_master_preservation']);preview=_relative_reference(cleanup['post_master_preservation_review'])
 require(screen['status']==sreview['status']==post['status']==preview['status']=='PASS'and screen['key_free_status']=='KEY_FREE'
  and screen['credential_match_count']==0 and screen['all_selected_bytes_keyfree_before_first_hash']is True and screen['credential_values_or_fingerprints_retained']is False
  and sreview['unresolved_findings']==[]and sreview['supports_retained_evidence_key_free']is True and _same_reference(sreview['screen'],cleanup['retained_evidence_screen'])
  and post['classified_tree_counts']=={'files':70,'bytes':53890,'trees':13}and post['master_store_and_parent_absent']is True and post['all5_outer_bootstrap_ancestors_absent']is True
  and all(post[k]is True for k in ('source363_unchanged','current_public_history_unchanged','raw_current_frozen_pairs_unchanged','all169_Registry_bodies_unchanged'))
  and preview['unresolved_findings']==[]and preview['supports_post_master_preservation']is True and _same_reference(preview['post_master_preservation'],cleanup['post_master_preservation']))
 inputs=_relative_reference(post['fixed_inputs']);inventory=_relative_reference(inputs['inventory']);owners=_relative_reference(inputs['owner_inventory']);hashes=cleanup['retained_evidence_file_sha256']
 require(hashes==screen['file_sha256']==terminal['retained_evidence_file_sha256']and sum(map(len,hashes.values()))==70)
 _retained_metadata(inventory,hashes)
 absent=[tree['path']for cell in inventory['cells']for tree in cell['retained_roots']if tree['state']=='absent']
 require(len(owners['targets'])==4 and all(t['state']=='absent'for t in owners['targets']))
 absent+=[target['path']for target in owners['targets']]
 require(len(absent)==len(set(absent))==5 and sorted(absent)==sorted(cleanup['retained_evidence_absences'])and all(registry_api._qualification_absent(str(path))for path in absent))
 master=_relative_reference(cleanup['master_cleanup']);mreview=_relative_reference(cleanup['master_cleanup_review'])
 require(master['status']=='removed'and master['target']==full['secrets_dir']and master['store_removed']is True and master['temporary_parent_removed']is True
  and master['values_opened']is False and master['value_hashes_computed']is False and master['operator_original_store_selected']is False
  and mreview['status']=='PASS'and mreview['unresolved_findings']==[]and mreview['supports_master_cleanup']is True and _same_reference(mreview['master_cleanup'],cleanup['master_cleanup'])
  and _same_reference(post['master_removed'],cleanup['master_cleanup'])and set(master['removed_references'])=={'PI_API_KEY','QUAL_APPLICATION_ALICE','QUAL_APPLICATION_BOB','QUAL_APPLICATION_SCRIPTED'})
 require(registry_api._qualification_absent(master['target'])and registry_api._qualification_absent(str(Path(master['target']).parent)))
 bootstrap=_relative_reference(cleanup['outer_bootstrap_cleanup']);breview=_relative_reference(cleanup['outer_bootstrap_cleanup_review'])
 require(bootstrap['status']==breview['status']=='PASS'and bootstrap['removed']is True and bootstrap['credential_contents_opened']is False and bootstrap['credential_hashes_computed']is False)
 outer=[]
 for cell in inventory['cells']:
  for item in cell['artifact_and_workspace_metadata']:
   path=item['path']
   if Path(path).name.startswith('pi-qualification-cell-'):outer.append(path)
 require(len(outer)==len(set(outer))==5 and bootstrap['root']in outer and all(registry_api._qualification_absent(str(path))for path in outer))
 release=_relative_reference(cleanup['coordination_release_acknowledgment']);require(release['status']=='ACKNOWLEDGED'and release['shared_lease_priority_released']is True and release['testing_and_heartbeat_remain_paused']is True)
 return cleanup


def validate_prior_for_image_recovery(reference,base_predecessor,*,clock=time.monotonic,wall=time.time,window=True):
 """Actual233/13, not234 by authority alone; no private payload reads."""
 authority=_image_recovery_authorization(reference);now,wallnow=_clock(clock,wall,window);require(wallnow>=authority['recorded_wall'])
 full,state,ledger=(_reference(PRIOR_REFERENCES[k])for k in ('manifest','state','ledger'))
 require(full['prepared_root']==str(PRIOR_ROOT)and full['document_type']=='application_client_qualification'and full['predecessor']==base_predecessor
  and full['campaign_boundary']==BOUNDARY_REFERENCE and full['campaign_amendment']==PRIOR_AMENDMENT_REFERENCE)
 prior=_replay_prior(full,ledger,base_predecessor)
 verifier=object.__new__(launch.LaunchLedger);verifier.root=PRIOR_ROOT/'launch-ledger';verifier.manifest=historical._launch_policy(full,PRIOR_AMENDMENT_REFERENCE)
 verifier.expected_daemon=verifier.expected_capacity=verifier._carry=None;verifier._prevalidated_carry=prior;verifier._validate(ledger)
 require(ledger['poisoned']is False and len(ledger['launches'])==39 and now>=ledger['last_now']and wallnow>=ledger['last_wall'])
 launch._exact(state,{'schema','phase','active_cell','cells','started_at'});require(type(state['schema'])is int and state['schema']==1 and state['phase']=='blocked'and state['started_at']==historical.STARTED_WALL and len(state['cells'])==9)
 ordered=[c for c in full['cells']if c['group']=='N02']
 for cell in full['cells']:
  item=state['cells'].get(cell['id'])
  if cell['group']=='N01':require(item=={'status':'PASS','attempts':1,'evidence_level':'native_infrastructure'})
  elif cell in ordered[:4]:
   launch._exact(item,{'status','attempts','run_id','attempt_id','runner_status','exit_code','interruption_sent'})
   require(item['status']=='PASS'and type(item['attempts'])is int and item['attempts']==1 and item['runner_status']=='FAIL'and type(item['exit_code'])is int and item['exit_code']==1 and item['interruption_sent']is False)
   for k in ('run_id','attempt_id'):launch._uuid(item[k])
  elif cell==ordered[4]:
   launch._exact(item,{'status','attempts','run_id','attempt_id','private_cleanup'});require(item['status']=='BLOCKED'and type(item['attempts'])is int and item['attempts']==1 and item['private_cleanup']=='unconfirmed')
   for k in ('run_id','attempt_id'):launch._uuid(item[k])
  else:require(item is None)
 active=state['active_cell'];launch._exact(active,{'id','pid','run_id','attempt_id'});require(all(active[k]==state['cells'][ordered[4]['id']][k]for k in ('run_id','attempt_id'))and type(active)is dict and active['id']==ordered[4]['id']and type(active['pid'])is int and active['pid']>1)
 rows=ledger['launches'];require(all(r['physical']=='absent'and r['private_cleanup']is True and r['container_id']is not None for r in rows)
  and len({r['container_id']for r in rows})==39 and sum(r['role']=='participant'for r in rows)==4)
 _cleanup(full,state,ledger,prior)
 oldrows=_rows(full,state);require(len(oldrows)==28 and full['qualification_id']not in {e['qualification_id']for e in prior['lineage']})
 hashes={k:PRIOR_REFERENCES[k.removesuffix('_sha256')]['sha256']for k in ('manifest_sha256','state_sha256','ledger_sha256')}
 prior={k:v for k,v in prior.items()if not k.startswith('_')}
 return {**prior,'attempts':233,'participant_segments':13,'qualification_id':full['qualification_id'],'planned_cells':476,**hashes,
  'started':STARTED_MONOTONIC,'deadline':DEADLINE_MONOTONIC,'started_wall':STARTED_WALL,'deadline_wall':DEADLINE_WALL,
  'lineage':prior['lineage']+[{'root':str(PRIOR_ROOT),'qualification_id':full['qualification_id'],**hashes}],'prior_rows':prior['prior_rows']+oldrows,
  'campaign_amendment':copy.deepcopy(reference),'effective_limits':{**launch.LIMITS,'container_launch_attempts':432,'participant_segments':37}}


def _qualified_images(images):
 launch._exact(images,{'core-0.87.1','browser-0.87.1','core-1.2.0','browser-1.2.0'})
 ids=set()
 for name,image in images.items():
  launch._exact(image,{'id','platform','capabilities'})
  require(type(image['id'])is str and image['id'].startswith('sha256:'));launch._sha(image['id'][7:])
  require(image['platform']=='linux/arm64'and type(image['capabilities'])is dict and image['capabilities'].get('pi')==name.split('-',1)[1])
  ids.add(image['id'])
 require(len(ids)==4)
 return images


def _closed_recovery(prior,base_predecessor,*,clock,wall,window):
 require(type(IMAGE_RECOVERY_VALIDATOR_SHA256)is str)
 binding=launch._bound_json(str(IMAGE_RECOVERY_BINDING_PATH),None)
 launch._exact(binding,{'schema','document_type','authorization','validator','verification','ledger','independent_review'})
 require(type(binding['schema'])is int and binding['schema']==1 and binding['document_type']=='qualification_image_recovery_binding'and binding['authorization']==IMAGE_RECOVERY_AUTHORIZATION
  and binding['validator']=={'path':str(IMAGE_RECOVERY_VALIDATOR_PATH),'sha256':IMAGE_RECOVERY_VALIDATOR_SHA256})
 for k,name in [('verification','image-recovery-002/verification.json'),('ledger','image-recovery-002/ledger.json'),('independent_review','image-recovery-independent-review-002/review.json')]:
  launch._exact(binding[k],{'path','sha256'});launch._sha(binding[k]['sha256']);require(binding[k]['path']==str(CAMPAIGN/name))
 body=_bytes_reference(binding['validator']);module=types.ModuleType('bound_image_recovery_validator');module.__file__=str(IMAGE_RECOVERY_VALIDATOR_PATH)
 exec(compile(body,str(IMAGE_RECOVERY_VALIDATOR_PATH),'exec'),module.__dict__)
 require(callable(module.validate_closed_recovery))
 descriptor=module.validate_closed_recovery(IMAGE_RECOVERY_AUTHORIZATION,base_predecessor,prior,clock=clock,wall=wall,window=window)
 for k,n in [('attempts',12),('participant_segments',0),('native_rows',0)]:require(type(descriptor[k])is int and descriptor[k]==n)
 require(descriptor['root']==str(CAMPAIGN/'image-recovery-002'));_qualified_images(descriptor['qualified_images'])
 for k in ('physical_absence_confirmed','all_writers_stopped'):require(descriptor[k]is True)
 for k in ('verification','ledger','independent_review'):require(descriptor[k]==binding[k])
 records=descriptor['records'];require(type(records)is list and len(records)==12)
 ids=set();registry=Path.home()/'.local/state/pi-agentic-development/operation.lock.registry'
 for ref in records:
  record=_relative_reference(ref);key=record['launch_id'];launch._uuid(key);require(key not in ids and record['status']=='released'and record['daemon']==prior['daemon'])
  require(launch._bound_json(str(registry/(key+'.json')),ref['sha256'])==record);ids.add(key)
 return descriptor


def validate_prior_for_diagnostic(reference,base_predecessor,*,clock=time.monotonic,wall=time.time,window=True):
 authority=_diagnostic_authorization(reference)
 prior=validate_prior_for_image_recovery(IMAGE_RECOVERY_AUTHORIZATION,base_predecessor,clock=clock,wall=wall,window=window)
 require((prior['attempts'],prior['participant_segments'],prior['planned_cells'],len(prior['lineage']))==(233,13,476,17))
 recovery=_closed_recovery(prior,base_predecessor,clock=clock,wall=wall,window=window);_clock(clock,wall,window)
 require(authority['fixture_image']==recovery['qualified_images']['core-0.87.1']['id'])
 return {**prior,'attempts':245,'image_recovery':copy.deepcopy(recovery),'campaign_amendment':copy.deepcopy(reference)}


def _authorization(reference):
 require(type(AUTHORIZATION_SHA256)is str and type(AUTHORIZATION_ID)is str and type(DIAGNOSTIC_VALIDATOR_SHA256)is str and type(IMAGE_RECOVERY_VALIDATOR_SHA256)is str)
 launch._sha(AUTHORIZATION_SHA256);launch._sha(DIAGNOSTIC_VALIDATOR_SHA256);launch._uuid(AUTHORIZATION_ID)
 require(reference=={'path':str(AUTHORIZATION_PATH),'sha256':AUTHORIZATION_SHA256});value=_reference(reference)
 fixed={'schema':1,'document_type':'qualification_matrix_requalification_authorization','authorization_id':AUTHORIZATION_ID,
  'final_root':str(FINAL_ROOT),'maximum_matrix_origins':18,'prior_matrix_origins':17,'prior_cumulative_container_launches':233,'prior_cumulative_participant_segments':13,
  'container_cap':432,'participant_cap':37,'live_cap':4,'trial_cap':1,'inference_slot_cap':1,'platform':'linux/arm64','automatic_retries':0,'continuations':0,
  'planned_new_container_launches':186,'planned_new_participant_segments':24,'diagnostic_container_launches':1,'image_recovery_container_launches':12,'additional_auxiliary_launches_authorized':0,
  'nineteenth_origin_authorized':False,'original_evidence_modified':False,'historical_windows_modified':False,
  'started_monotonic':STARTED_MONOTONIC,'started_wall':STARTED_WALL,'deadline_monotonic':DEADLINE_MONOTONIC,'deadline_wall':DEADLINE_WALL,
  'diagnostic_binding_path':str(DIAGNOSTIC_BINDING_PATH)}
 launch._exact(value,set(fixed)|{'human_authorization','window_authorization','recorded_wall','original_boundary','prior_cleanup','prior_boundary_review','prior_source029_handoff','prior_manifest','prior_state','prior_ledger','diagnostic_authorization','diagnostic_validator','image_recovery_authorization','image_recovery_validator'})
 for k,v in fixed.items():require(type(value[k])is type(v)and value[k]==v)
 require(value['image_recovery_validator']=={'path':str(IMAGE_RECOVERY_VALIDATOR_PATH),'sha256':IMAGE_RECOVERY_VALIDATOR_SHA256}and value['image_recovery_authorization']==IMAGE_RECOVERY_AUTHORIZATION and value['diagnostic_authorization']==DIAGNOSTIC_AUTHORIZATION and value['diagnostic_validator']=={'path':str(DIAGNOSTIC_VALIDATOR_PATH),'sha256':DIAGNOSTIC_VALIDATOR_SHA256}
  and value['original_boundary']==BOUNDARY_REFERENCE and STARTED_WALL<=launch._number(value['recorded_wall'])<DEADLINE_WALL)
 for k,b in [('prior_cleanup','cleanup'),('prior_boundary_review','boundary_review'),('prior_source029_handoff','source029_handoff')]:require(value[k]==BASIS_REFERENCES[b])
 for key,ref in PRIOR_REFERENCES.items():require(value['prior_'+key]==ref)
 _window(value);_diagnostic_authorization(DIAGNOSTIC_AUTHORIZATION);return value


def effective_limits(reference):
 _authorization(reference);return {**launch.LIMITS,'container_launch_attempts':432,'participant_segments':37}


def _diagnostic_validator():
 require(type(DIAGNOSTIC_VALIDATOR_SHA256)is str)
 body=_bytes_reference({'path':str(DIAGNOSTIC_VALIDATOR_PATH),'sha256':DIAGNOSTIC_VALIDATOR_SHA256})
 module=types.ModuleType('bound_fixture_startup_diagnostic_validator');module.__file__=str(DIAGNOSTIC_VALIDATOR_PATH)
 exec(compile(body,str(DIAGNOSTIC_VALIDATOR_PATH),'exec'),module.__dict__)
 require(callable(module.validate_closed_diagnostic));return module


def _diagnostic_binding(reference,value):
 # The fixed file is installed exclusively only after actual PASS. Its refs are
 # authenticated by the fixed validator, not trusted as an unsigned increment.
 binding=launch._bound_json(str(DIAGNOSTIC_BINDING_PATH),None)
 launch._exact(binding,{'schema','document_type','authorization','diagnostic_authorization','diagnostic_validator','manifest','ledger','terminal','independent_review'})
 require(type(binding['schema'])is int and binding['schema']==1 and binding['document_type']=='qualification_startup_diagnostic_binding'
  and binding['authorization']==reference and binding['diagnostic_authorization']==DIAGNOSTIC_AUTHORIZATION and binding['diagnostic_validator']==value['diagnostic_validator'])
 for key,name in [('manifest','manifest.json'),('ledger','launch-ledger/ledger.json'),('terminal','terminal.json')]:
  ref=binding[key];launch._exact(ref,{'path','sha256'});launch._sha(ref['sha256']);require(ref['path']==str(CAMPAIGN/'startup-diagnostic-001'/name))
 ref=binding['independent_review'];launch._exact(ref,{'path','sha256'});launch._sha(ref['sha256']);require(ref['path']==str(CAMPAIGN/'startup-diagnostic-actual-independent-review/review.json'))
 return binding


def validate_amendment(reference,base_predecessor,*,clock=time.monotonic,wall=time.time,window=True):
 value=_authorization(reference);prior=validate_prior_for_diagnostic(DIAGNOSTIC_AUTHORIZATION,base_predecessor,clock=clock,wall=wall,window=window)
 require((prior['attempts'],prior['participant_segments'],prior['planned_cells'],len(prior['lineage']))==(245,13,476,17))
 binding=_diagnostic_binding(reference,value)
 diagnostic=_diagnostic_validator().validate_closed_diagnostic(DIAGNOSTIC_AUTHORIZATION,base_predecessor,prior,clock=clock,wall=wall,window=window)
 for key,wanted in [('attempts',1),('participant_segments',0),('native_rows',0)]:require(type(diagnostic[key])is int and diagnostic[key]==wanted)
 require(diagnostic['root']==str(CAMPAIGN/'startup-diagnostic-001'));launch._sha(diagnostic['container_id'])
 for key in ('physical_absence_confirmed','private_cleanup_confirmed','all_writers_stopped','fixture_startup_ready','strict_nonce_and_initial_journal','stopped_terminal_confirmed','evidence_key_free'):require(diagnostic[key]is True)
 for key in ('manifest','ledger','terminal','independent_review'):require(diagnostic[key]==binding[key])
 _clock(clock,wall,window)
 require(prior['attempts']+diagnostic['attempts']+value['planned_new_container_launches']==432 and prior['participant_segments']+value['planned_new_participant_segments']==37)
 return {**prior,'attempts':246,'campaign_amendment':copy.deepcopy(reference),'fixture_startup_diagnostic':copy.deepcopy(diagnostic),'effective_limits':effective_limits(reference)}


def _folder():
    parent=launch._dir(BINDING_ROOT.parent,False)
    try:
        try:os.mkdir(BINDING_ROOT.name,0o700,dir_fd=parent);os.fsync(parent)
        except FileExistsError:pass
    finally:os.close(parent)
    fd=launch._dir(BINDING_ROOT);os.close(fd)


def _fence(reference,carry,*,create=False):
    parent=launch._dir(PRIOR_ROOT.parent,False);folder=lock=None
    try:
        if create:
            try:os.mkdir('campaign-successor-claims',0o700,dir_fd=parent);os.fsync(parent)
            except FileExistsError:pass
        folder=os.open('campaign-successor-claims',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        info=os.fstat(folder);require(info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700)
        name=launch._digest({'root':str(PRIOR_ROOT),'qualification_id':carry['qualification_id']});auth='amendment-'+AUTHORIZATION_ID
        lock=launch._file(folder,name+'.lock',os.O_RDWR|(os.O_CREAT|os.O_EXCL if create else 0));fcntl.flock(lock,fcntl.LOCK_EX)
        expected={'schema':1,'document_type':'qualification_matrix_amendment_claim','amendment':reference,'prior_root':str(PRIOR_ROOT),
            'prior_qualification_id':carry['qualification_id'],'final_root':str(FINAL_ROOT)}
        if create:
            os.fsync(lock);os.fsync(folder)
            fd=launch._file(folder,auth+'.lock',os.O_RDWR|os.O_CREAT|os.O_EXCL);os.fsync(fd);os.close(fd);os.fsync(folder)
            for filename in (name+'.json',auth+'.json'):
                fd=launch._file(folder,filename,os.O_WRONLY|os.O_CREAT|os.O_EXCL)
                with os.fdopen(fd,'wb') as stream:stream.write(launch._json(expected));stream.flush();os.fsync(stream.fileno())
                os.fsync(folder)
        fd=launch._file(folder,auth+'.lock',os.O_RDWR);os.close(fd)
        require(launch._read(folder,name+'.json')==expected and launch._read(folder,auth+'.json')==expected)
    finally:
        if lock is not None:os.close(lock)
        if folder is not None:os.close(folder)
        os.close(parent)


def _launch_policy(full,reference):
    require(full.get('schema')==1 and type(full['schema']) is int and full.get('document_type')=='application_client_qualification'
        and full.get('prepared_root')==str(FINAL_ROOT) and full.get('campaign_amendment')==reference and full.get('campaign_boundary')==BOUNDARY_REFERENCE)
    expected={key:value for key,value in effective_limits(reference).items() if key!='live'}
    expected.update(simultaneously_registered_live_container_intents=4,automatic_retries=0,continuations=0)
    require(launch._json(full['limits'])==launch._json(expected))
    fields=('id','group','release','image_id','allowed_images','role_limits','container_launches_max','participant_segments_max')
    return launch.validate_manifest({'qualification_id':full['qualification_id'],'images':full['images'],'cells':[{key:cell[key] for key in fields} for cell in full['cells']],
        'limits':effective_limits(reference),'planned_container_launches':full['planned_container_launches'],'predecessor':full['predecessor'],
        'campaign_boundary':full['campaign_boundary'],'campaign_amendment':reference})


def finalize_candidate(reference,full_manifest_reference,candidate_reference,*,clock=time.monotonic,wall=time.time):
    full=_reference(full_manifest_reference);candidate=_reference(candidate_reference)
    require(full_manifest_reference['path']==str(FINAL_ROOT/'manifest.json') and candidate_reference['path']==str(FINAL_ROOT/'candidate.json'))
    policy=_launch_policy(full,reference);carry=validate_amendment(reference,full['predecessor'],clock=clock,wall=wall)
    require(full['images']==carry['image_recovery']['qualified_images'])
    require(full['qualification_id'] not in {entry['qualification_id'] for entry in carry['lineage']}and full['qualification_id']!=_reference(carry['fixture_startup_diagnostic']['manifest'])['qualification_id'])
    launch._exact(candidate,{'archive_sha256','runner_sha256','scope'});launch._sha(candidate['archive_sha256']);launch._sha(candidate['runner_sha256'])
    require(candidate['scope']=='extracted_candidate' and candidate['runner_sha256']==full['source']['runner'])
    _folder();_fence(reference,carry,create=True)
    return campaign.exclusive(BINDING_ROOT/'candidate-binding.json',{'schema':1,'amendment':reference,'qualification_id':full['qualification_id'],
        'full_manifest':full_manifest_reference,'candidate':candidate_reference,'launch_manifest_sha256':launch._digest(policy)})


def bind_final(root,manifest,carry,*,create=False):
    require(launch._canonical_root(str(root))==FINAL_ROOT/'launch-ledger' and len(carry['lineage'])==17 and carry['attempts']==246
        and carry['participant_segments']==13 and carry['campaign_amendment']==manifest['campaign_amendment'])
    reference=manifest['campaign_amendment'];_fence(reference,carry)
    binding=campaign.read(BINDING_ROOT/'candidate-binding.json');launch._exact(binding,{'schema','amendment','qualification_id','full_manifest','candidate','launch_manifest_sha256'})
    full=_reference(binding['full_manifest']);candidate=_reference(binding['candidate']);require(full['images']==carry['image_recovery']['qualified_images'])
    require(type(binding['schema']) is int and binding['schema']==1 and binding['amendment']==reference and binding['qualification_id']==manifest['qualification_id']
        and binding['full_manifest']['path']==str(FINAL_ROOT/'manifest.json') and binding['candidate']['path']==str(FINAL_ROOT/'candidate.json')
        and candidate['scope']=='extracted_candidate' and candidate['runner_sha256']==full['source']['runner']
        and binding['launch_manifest_sha256']==launch._digest(manifest) and launch._json(_launch_policy(full,reference))==launch._json(manifest))
    expected={'schema':1,'document_type':'qualification_matrix_amendment_launch_binding','amendment':reference,'qualification_id':manifest['qualification_id'],
        'manifest_sha256':launch._digest(manifest),'ledger_root':str(root),'cumulative_attempts':246,'participant_segments':13,
        'candidate_binding':campaign.ref(BINDING_ROOT/'candidate-binding.json')}
    if create:campaign.exclusive(BINDING_ROOT/'launch-binding.json',expected)
    require(campaign.read(BINDING_ROOT/'launch-binding.json')==expected)
