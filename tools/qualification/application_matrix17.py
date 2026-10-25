"""Explicit matrix17 authority with one separately charged artifact diagnostic.

The pre-diagnostic helper admits only the one fixed diagnostic authority. Final
matrix admission remains unbound until its actual diagnostic terminal is pinned.
No process, key resolution, private payload read or old raw repair is performed
by this module's new matrix016 closure validation. The unchanged earlier
validator retains its narrowly authorized five historically classified leaves.
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
import application_matrix16 as prior_amendment
import ownership_registry as registry_api

REPO=Path(__file__).resolve().parents[2]
CAMPAIGN=REPO/'reports/application-agent-enhancements/A15/campaign-011'
AUTHORIZATION_PATH=CAMPAIGN/'matrix-017-authorization.json'
AUTHORIZATION_SHA256='7d9fa918409e49249f674404144c1b308eebedede591a508b9e4a4f6148e9fcf'
AUTHORIZATION_ID='bc8f8aef-2110-4204-854e-28476caa7a9a'
DIAGNOSTIC_VALIDATOR_PATH=CAMPAIGN/'artifact-diagnostic-design/diagnostic.py'
DIAGNOSTIC_VALIDATOR_SHA256='a5e36e9b679780819372bd2ec9b65e1737d6acbe6339582bd9c38021116ecf30'
DIAGNOSTIC_AUTHORIZATION={'path':str(CAMPAIGN/'artifact-diagnostic-authorization.json'),'sha256':'1235cbe5bb0cd35b57e74089abdd7613da548ce47e560f2df243720697db10a1'}
WINDOW_AUTHORIZATION={'path':str(REPO/'reports/application-agent-enhancements/A15/campaign-window-009-authorization.json'),'sha256':'74f42a408103e0479b0897703feefd9064f100fb54deed8471903a8960444309'}
PRIOR_ROOT=REPO/'reports/application-agent-enhancements/A15/attempt-016/qualification'
FINAL_ROOT=REPO/'reports/application-agent-enhancements/A15/attempt-017/qualification'
BINDING_ROOT=CAMPAIGN/'matrix-017-successor'
PRIOR_AMENDMENT_REFERENCE={'path':str(prior_amendment.AUTHORIZATION_PATH),'sha256':prior_amendment.AUTHORIZATION_SHA256}
BOUNDARY_REFERENCE=copy.deepcopy(prior_amendment.BOUNDARY_REFERENCE)
STARTED_WALL=1792394708.337437
STARTED_MONOTONIC=670540.983177208
DEADLINE_WALL=1792409108.337437
DEADLINE_MONOTONIC=684940.983177208
PRIOR_REFERENCES={
 'manifest':{'path':str(PRIOR_ROOT/'manifest.json'),'sha256':'cebfc444132a31f9355e49f9875080b22f20e8621e5e863d60518e9e3b971bda'},
 'state':{'path':str(PRIOR_ROOT/'state.json'),'sha256':'009c3cc9cd19cb1f52f01f895e8e788cd64964bf29c1858d349ce2e788ccca34'},
 'ledger':{'path':str(PRIOR_ROOT/'launch-ledger/ledger.json'),'sha256':'ec99410c10c714cc5954719ff505141dad55b0a416ef99e6ce8f8f71311e24ff'}}
_reference=prior_amendment._reference
_relative_reference=prior_amendment._relative_reference
_same_reference=prior_amendment._same_reference


def require(value):
 if not value:raise launch.LaunchError('qualification_matrix17_invalid')


def _bytes_reference(reference):
 launch._exact(reference,{'path','sha256'});launch._sha(reference['sha256'])
 path=Path(reference['path']);path=path if path.is_absolute()else REPO/path
 require(path.is_relative_to(REPO/'reports/application-agent-enhancements')and '..'not in path.parts)
 parent=launch._dir(path.parent,False)
 try:
  fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
  with os.fdopen(fd,'rb')as stream:
   first=os.fstat(stream.fileno());require(stat.S_ISREG(first.st_mode)and first.st_uid==os.getuid()and first.st_nlink==1 and not stat.S_IMODE(first.st_mode)&0o022 and first.st_size<=launch.MAX_BYTES)
   body=stream.read(launch.MAX_BYTES+1);last=os.fstat(stream.fileno());named=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
  identity=lambda v:(v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
  require(identity(first)==identity(last)==identity(named)and len(body)==first.st_size and hashlib.sha256(body).hexdigest()==reference['sha256']);return body
 finally:os.close(parent)


def _window(value):
 require(value['window_authorization']==WINDOW_AUTHORIZATION)
 window=_reference(WINDOW_AUTHORIZATION)
 expected={'document_type':'qualification_window_authorization','window_seconds':14400,'original_deadline_wall':prior_amendment.DEADLINE_WALL,
  'started_wall':STARTED_WALL,'started_monotonic':STARTED_MONOTONIC,'deadline_wall':DEADLINE_WALL,'deadline_monotonic':DEADLINE_MONOTONIC,
  'cumulative_container_launches':193,'cumulative_participant_segments':9,'container_cap':380,'participant_cap':33,'live_cap':4,'trial_cap':1,
  'inference_slot_cap':1,'platform':'linux/arm64','automatic_retries':0,'continuations':0,'prior_campaign_modified':False,'new_native_admission_requires_positive_owned_cleanup':True}
 for key,wanted in expected.items():require(type(window[key])is type(wanted)and window[key]==wanted)
 require(window['authorization']==value['human_authorization']and DEADLINE_WALL==STARTED_WALL+14400 and DEADLINE_MONOTONIC==STARTED_MONOTONIC+14400)
 return window


def _diagnostic_authorization(reference):
 require(reference==DIAGNOSTIC_AUTHORIZATION);value=_reference(reference)
 fixed={'schema':1,'document_type':'bounded_artifact_write_diagnostic_authorization','authorization_id':'af28ea56-e17f-4f6a-aaba-1421fc581ed5',
  'recorded_wall':STARTED_WALL,'started_wall':STARTED_WALL,'started_monotonic':STARTED_MONOTONIC,'deadline_wall':DEADLINE_WALL,'deadline_monotonic':DEADLINE_MONOTONIC,
  'prior_cumulative_container_launches':193,'prior_cumulative_participant_segments':9,'container_cap':380,'participant_cap':33,'maximum_diagnostic_launches':1,
  'diagnostic_participants':0,'inference_calls':0,'credentials':0,'live_cap':1,'trial_cap':1,'platform':'linux/arm64','overall_seconds':90,'work_seconds_max':60,'cleanup_seconds':30,
  'automatic_retries':0,'continuations':0,'no_existing_evidence_mounts':True,'original_lease_required':True,'matrix17_requires_diagnostic_terminal_cleanup':True}
 launch._exact(value,set(fixed)|{'human_authorization','window_authorization','proposal','prior_cleanup','prior_boundary_review','prior_final_audit','prior_actual_publication_review','original_boundary'})
 for key,wanted in fixed.items():require(type(value[key])is type(wanted)and value[key]==wanted)
 require(type(value['human_authorization'])is str and 1<=len(value['human_authorization'])<=4096 and value['original_boundary']==BOUNDARY_REFERENCE)
 _window(value);return value


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
  for proof in chain['terminal_proofs']:_relative_reference(proof)
  for proof in chain['source_proofs']:_bytes_reference(proof)
 require(len(actors)==61 and sorted(actors)==terminal['current_actor_ids']==cleanup['known_current_credential_runtime_actor_ids']
  and terminal['current_actors']==[actors[k]for k in sorted(actors)])
 return actors


def _retained_metadata(inventory,hashes):
 """Fresh known-name/inode metadata only; no opening or hashing34 payloads."""
 roots={};files=nodes_count=0
 for cell in inventory['cells']:
  for tree in cell['retained_roots']:
   root=launch._canonical_root(tree['path']);require(root.is_relative_to(PRIOR_ROOT)and tree['state']=='present'and str(root)not in roots)
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
 require(len(roots)==9 and set(roots)==set(hashes)and nodes_count==59 and files==34)


def _cleanup(value,full,ledger):
 cleanup=_reference(value['prior_cleanup']);boundary=_reference(value['prior_boundary_review']);audit=_reference(value['prior_final_audit']);publication=_reference(value['prior_actual_publication_review'])
 require(cleanup['status']==boundary['status']==audit['status']==publication['status']=='PASS'and boundary['unresolved_findings']==publication['unresolved_findings']==[]
  and _same_reference(boundary['final_cleanup'],value['prior_cleanup'])and boundary['actor_terminal_evidence_reviewed']is True
  and cleanup['qualification_id']==full['qualification_id']and cleanup['cumulative_container_launches']==193 and cleanup['participant_segments']==9
  and cleanup['scripted_participant_segments']==9 and cleanup['real_model_participant_segments']==0 and cleanup['live_owned_containers']==0
  and cleanup['known_current_credential_runtime_context_count']==61 and cleanup['post_cutoff_metadata_actor_context_count']==18
  and cleanup['raw_current_counts']=={'PASS':6,'FAIL':1,'NOT_RUN':21}and cleanup['chronological_native_rows']==448
  and cleanup['chronological_native_counts']=={'PASS':55,'FAIL':1,'BLOCKED':15,'NOT_RUN':377})
 for key in ('physical_absence_confirmed','private_cleanup_confirmed','master016_copy_removed','safe_for_final_handoff','current_registry_records_released','retained_evidence_key_free','retained_evidence_bytes_unchanged','raw_poison_and_flags_unchanged','product_private_cleanup_all30_true'):require(cleanup[key]is True)
 for key in ('safe_to_continue','continued_execution_authorized','qualification_eligible','original_operator_store_touched','historical_numeric_PID_probes','credential_values_or_hashes_retained','master_cleanup_values_opened','master_cleanup_value_hashes_computed','manual_private_purge_performed','manual_registry_release_performed','raw_ledger_poisoned'):require(cleanup[key]is False)
 terminal=_relative_reference(cleanup['terminal_hygiene']);review=_relative_reference(cleanup['terminal_hygiene_review'])
 require(terminal['status']==review['status']=='PASS'and review['unresolved_findings']==[]and review['actor_terminal_evidence_reviewed']is True
  and _same_reference(review['terminal_hygiene'],cleanup['terminal_hygiene'])and _same_reference(terminal['current_ledger'],PRIOR_REFERENCES['ledger'])
  and _same_reference(terminal['current_state'],PRIOR_REFERENCES['state'])and terminal['known_current_contextual_actor_count']==61)
 for key in ('all_native_writers_absent','all_service_writers_stopped','all_helper_writers_stopped','all_qualification_controllers_stopped','all_issued_capabilities_revoked','owned_networks_removed','all_container_ids_absent','raw_preserved','all_root_readers_stopped','retained_evidence_key_free'):require(terminal[key]is True)
 actors=_contextual_actors(terminal,cleanup)
 for row in ledger['launches']:require(len([a for a in actors.values()if a['context']['qualification_id']==full['qualification_id']and a['context']['cell_id']==row['cell']and a['context']['launch_id']==row['launch_id']and a['context']['role']==row['role']and a['pid']==row['pid']])==1)
 old=_reference(_reference(PRIOR_AMENDMENT_REFERENCE)['prior_cleanup'])
 ids=cleanup['all_owned_container_ids'];require(type(ids)is list and len(ids)==len(set(ids))==193 and ids==terminal['all_owned_container_ids']and set(ids)==set(old['all_owned_container_ids'])|{row['container_id']for row in ledger['launches']})
 records=cleanup['current_registry_records'];require(records==terminal['current_registry_records']and len(records)==125)
 pinned={};pinned_digests={};registry=Path.home()/'.local/state/pi-agentic-development/operation.lock.registry'
 for reference in records:
  record=_relative_reference(reference);key=record['launch_id'];launch._uuid(key);require(key not in pinned and record['status']=='released'and record['daemon']==ledger['daemon'])
  current=launch._bound_json(str(registry/(key+'.json')),reference['sha256']);require(current==record);pinned[key]=record;pinned_digests[key]=reference['sha256']
 old_records={_relative_reference(ref)['launch_id']:ref['sha256']for ref in old['current_registry_records']}
 require(len(old_records)==92 and set(pinned)==set(old_records)|{r['launch_id']for r in ledger['launches']}|set(terminal['network_launch_ids']))
 require(all(pinned_digests[key]==digest for key,digest in old_records.items()))
 for row in ledger['launches']:
  record=pinned[row['launch_id']];require(launch._intent_identity(record)==row['intent_sha256']and all(record[k]==row[k]for k in ('launch_id','registry','generation','image','container'))and record.get('container_id')in(None,row['container_id']))
 helpers=[pinned[row['launch_id']]for row in ledger['launches']if row['role']=='application-helper'];networks=terminal['network_launch_ids'];require(len(helpers)==len(networks)==len(set(networks))==3)
 for helper in helpers:
  matching=[pinned[k]for k in networks if pinned[k]['container']==helper['container']+'-network'];require(len(matching)==1)
  network=matching[0];require(network['kind']=='network'and all(network[k]==helper[k]for k in ('registry','generation','daemon')))
 screen=_relative_reference(cleanup['retained_evidence_screen']);screen_review=_relative_reference(cleanup['retained_evidence_screen_review']);post=_relative_reference(cleanup['post_master_preservation']);post_review=_relative_reference(cleanup['post_master_preservation_review'])
 require(screen['status']==screen_review['status']==post['status']==post_review['status']=='PASS'and screen['key_free_status']=='KEY_FREE'
  and screen['credential_match_count']==0 and screen['all_selected_bytes_keyfree_before_first_hash']is True and screen['credential_values_or_fingerprints_retained']is False
  and screen_review['unresolved_findings']==[]and screen_review['supports_retained_evidence_key_free']is True and _same_reference(screen_review['screen_proof'],cleanup['retained_evidence_screen'])
  and post['classified_tree_counts']=={'files':34,'bytes':24067,'trees':9}and post['master_store_and_parent_absent']is True
  and all(post[k]is True for k in ('source352_unchanged','current_public_history_unchanged','raw_five_pairs_unchanged','all125_Registry_bodies_unchanged'))
  and post_review['unresolved_findings']==[]and post_review['supports_post_master_preservation']is True and _same_reference(post_review['preservation_proof'],cleanup['post_master_preservation']))
 inputs=_relative_reference(post['fixed_inputs']);inventory=_relative_reference(inputs['inventory']);hashes=cleanup['retained_evidence_file_sha256']
 require(hashes==screen['file_sha256']==terminal['retained_evidence_file_sha256']and sum(map(len,hashes.values()))==34)
 _retained_metadata(inventory,hashes)
 descriptor=_relative_reference(inputs['descriptor']);master=_relative_reference(cleanup['master_cleanup']);master_review=_relative_reference(cleanup['master_cleanup_review'])
 require(master['status']=='removed'and master['target']==full['secrets_dir']==descriptor['secrets_dir']and master['store_removed']is True and master['temporary_parent_removed']is True and master['values_opened']is False
  and master['value_hashes_computed']is False and master['operator_original_store_selected']is False and master_review['status']=='PASS'and master_review['unresolved_findings']==[]
  and master_review['supports_master_cleanup']is True and master_review['actual_all_metadata_actors_closed']is True and master_review['all_master_metadata_actors_closed']is True
  and _same_reference(master_review['master_cleanup'],cleanup['master_cleanup'])and _same_reference(post['master_removed'],cleanup['master_cleanup'])
  and set(master['removed_references'])=={'PI_API_KEY','QUAL_APPLICATION_ALICE','QUAL_APPLICATION_BOB','QUAL_APPLICATION_SCRIPTED'})
 require(registry_api._qualification_absent(master['target'])and registry_api._qualification_absent(str(Path(master['target']).parent)))
 release=_relative_reference(cleanup['coordination_release_acknowledgment']);require(release['status']=='ACKNOWLEDGED'and release['shared_lease_priority_released']is True and release['testing_and_heartbeat_remain_paused']is True)


def validate_prior_for_diagnostic(reference,base_predecessor,*,clock=time.monotonic,wall=time.time,window=True):
 """Fresh193/9 carry for exactlyone authorized diagnostic, never194 by fiat."""
 value=_diagnostic_authorization(reference)
 prior=prior_amendment.validate_amendment(PRIOR_AMENDMENT_REFERENCE,base_predecessor,clock=clock,wall=wall,window=False)
 require((prior['attempts'],prior['participant_segments'],prior['planned_cells'],len(prior['lineage']))==(163,6,420,15))
 now,wallnow=launch._number(clock()),launch._number(wall());require(now>=STARTED_MONOTONIC and wallnow>=STARTED_WALL)
 if window:require(now<DEADLINE_MONOTONIC-30 and wallnow<DEADLINE_WALL-30)
 full,state,ledger=(_reference(PRIOR_REFERENCES[key])for key in ('manifest','state','ledger'))
 require(full['prepared_root']==str(PRIOR_ROOT)and full['document_type']=='application_client_qualification'and full['predecessor']==base_predecessor
  and full['campaign_boundary']==BOUNDARY_REFERENCE and full['campaign_amendment']==PRIOR_AMENDMENT_REFERENCE)
 verifier=object.__new__(launch.LaunchLedger);verifier.root=PRIOR_ROOT/'launch-ledger';verifier.manifest=prior_amendment._launch_policy(full,PRIOR_AMENDMENT_REFERENCE)
 verifier.expected_daemon=verifier.expected_capacity=verifier._carry=None;verifier._prevalidated_carry=prior;verifier._validate(ledger)
 require(ledger['poisoned']is False and len(ledger['launches'])==30 and now>=ledger['last_now']and wallnow>=ledger['last_wall'])
 launch._exact(state,{'schema','phase','active_cell','cells','started_at'});require(type(state['schema'])is int and state['schema']==1 and state['phase']=='blocked'and state['active_cell']is None and state['started_at']==prior['started_wall']and len(state['cells'])==7)
 ordered=[c for c in full['cells']if c['group']=='N02']
 for cell in full['cells']:
  item=state['cells'].get(cell['id'])
  if cell['group']=='N01':require(item=={'status':'PASS','attempts':1,'evidence_level':'native_infrastructure'})
  elif cell in ordered[:3]:
   launch._exact(item,{'status','attempts','run_id','attempt_id','runner_status','exit_code','interruption_sent'})
   require(item['status']==('FAIL'if cell==ordered[2]else'PASS')and type(item['attempts'])is int and item['attempts']==1 and item['runner_status']=='FAIL'and type(item['exit_code'])is int and item['exit_code']==1 and item['interruption_sent']is False)
   for key in ('run_id','attempt_id'):launch._uuid(item[key])
  else:require(item is None)
 rows=ledger['launches'];require(all(r['physical']=='absent'and r['private_cleanup']is True and r['container_id']is not None for r in rows)and len({r['container_id']for r in rows})==30 and sum(r['role']=='participant'for r in rows)==3)
 _cleanup(value,full,ledger)
 old_rows=[{'qualification_id':full['qualification_id'],'cell':cell['id'],'status':state['cells'].get(cell['id'],{}).get('status','NOT_RUN'),'attempts':state['cells'].get(cell['id'],{}).get('attempts',0)}for cell in full['cells']]
 require(len(old_rows)==28 and full['qualification_id']not in {r['qualification_id']for r in prior['lineage']})
 hashes={key:PRIOR_REFERENCES[key.removesuffix('_sha256')]['sha256']for key in ('manifest_sha256','state_sha256','ledger_sha256')}
 return {**prior,'attempts':193,'participant_segments':9,'qualification_id':full['qualification_id'],'planned_cells':448,**hashes,
  'started':STARTED_MONOTONIC,'started_wall':STARTED_WALL,'deadline':DEADLINE_MONOTONIC,'deadline_wall':DEADLINE_WALL,
  'lineage':prior['lineage']+[{'root':str(PRIOR_ROOT),'qualification_id':full['qualification_id'],**hashes}],
  'prior_rows':prior['prior_rows']+old_rows,'campaign_amendment':copy.deepcopy(reference),'effective_limits':{**launch.LIMITS,'container_launch_attempts':380,'participant_segments':33}}


def _authorization(reference):
 require(type(AUTHORIZATION_SHA256)is str and type(AUTHORIZATION_ID)is str and type(DIAGNOSTIC_VALIDATOR_SHA256)is str)
 launch._sha(AUTHORIZATION_SHA256);launch._sha(DIAGNOSTIC_VALIDATOR_SHA256);launch._uuid(AUTHORIZATION_ID)
 require(reference=={'path':str(AUTHORIZATION_PATH),'sha256':AUTHORIZATION_SHA256});value=_reference(reference)
 fixed={'schema':1,'document_type':'qualification_matrix_requalification_authorization','authorization_id':AUTHORIZATION_ID,
  'final_root':str(FINAL_ROOT),'maximum_matrix_origins':17,'prior_matrix_origins':16,'cumulative_container_launches':193,'cumulative_participant_segments':9,
  'previous_container_cap':349,'container_cap':380,'previous_participant_cap':30,'participant_cap':33,'live_cap':4,'trial_cap':1,'inference_slot_cap':1,'platform':'linux/arm64',
  'automatic_retries':0,'continuations':0,'planned_new_container_launches':186,'planned_new_participant_segments':24,'diagnostic_container_launches':1,
  'started_wall':STARTED_WALL,'started_monotonic':STARTED_MONOTONIC,'deadline_wall':DEADLINE_WALL,'deadline_monotonic':DEADLINE_MONOTONIC,
  'original_evidence_modified':False,'historical_windows_modified':False,'additional_auxiliary_launches_authorized':0,'additional_startup_diagnostic_authorized':False,'eighteenth_origin_authorized':False}
 launch._exact(value,set(fixed)|{'human_authorization','recorded_wall','window_authorization','prior_amendment','original_boundary','prior_manifest','prior_state','prior_ledger',
  'prior_cleanup','prior_independent_review','prior_boundary_review','prior_final_audit','prior_actual_publication_review','diagnostic_authorization','diagnostic_terminal','diagnostic_independent_review','diagnostic_ledger','diagnostic_validator'})
 for key,wanted in fixed.items():require(type(value[key])is type(wanted)and value[key]==wanted)
 recorded=launch._number(value['recorded_wall']);require(STARTED_WALL<=recorded<DEADLINE_WALL and type(value['human_authorization'])is str and 1<=len(value['human_authorization'])<=4096)
 require(value['diagnostic_validator']=={'path':str(DIAGNOSTIC_VALIDATOR_PATH),'sha256':DIAGNOSTIC_VALIDATOR_SHA256})
 require(value['prior_amendment']==PRIOR_AMENDMENT_REFERENCE and value['original_boundary']==BOUNDARY_REFERENCE and value['diagnostic_authorization']==DIAGNOSTIC_AUTHORIZATION)
 _window(value);diagnostic=_diagnostic_authorization(DIAGNOSTIC_AUTHORIZATION)
 for key in ('prior_cleanup','prior_boundary_review','prior_final_audit','prior_actual_publication_review'):require(value[key]==diagnostic[key])
 for key,ref in PRIOR_REFERENCES.items():require(value['prior_'+key]==ref)
 for key in ('diagnostic_terminal','diagnostic_independent_review','diagnostic_ledger'):
  launch._exact(value[key],{'path','sha256'});launch._sha(value[key]['sha256']);path=launch._canonical_root(value[key]['path'])
  require(path.is_relative_to(CAMPAIGN))
 independent=_reference(value['prior_independent_review']);require(independent['status']=='PASS'and independent['unresolved_findings']==[]and independent['supports_ac80']is True)
 return value


def effective_limits(reference):
 _authorization(reference);return {**launch.LIMITS,'container_launch_attempts':380,'participant_segments':33}


def _diagnostic_validator(value):
 require(type(DIAGNOSTIC_VALIDATOR_SHA256)is str);launch._sha(DIAGNOSTIC_VALIDATOR_SHA256)
 body=_bytes_reference({'path':str(DIAGNOSTIC_VALIDATOR_PATH),'sha256':DIAGNOSTIC_VALIDATOR_SHA256})
 module=types.ModuleType('bound_artifact_diagnostic_validator');module.__file__=str(DIAGNOSTIC_VALIDATOR_PATH)
 exec(compile(body,str(DIAGNOSTIC_VALIDATOR_PATH),'exec'),module.__dict__)
 require(callable(module.validate_closed_diagnostic))
 # The historical library needs only the fixed codebundle keyset from CLIENT.
 # Never let creator tools-first sys.path resolve the maintainer client here,
 # and never reinstall the historical101 current-source map after later edits.
 terminal=_reference(value['diagnostic_terminal']);inputs_ref=terminal['inputs']
 require(inputs_ref['path']==str(CAMPAIGN/'artifact-diagnostic-design/inputs-final-002.json'))
 inputs=_relative_reference(inputs_ref);pins=inputs['code_source_pins']
 require(type(pins)is dict and 1<=len(pins)<=128)
 for name,digest in pins.items():
  require(type(name)is str and not Path(name).is_absolute()and '..'not in Path(name).parts and Path(name).suffix in ('.py','.mjs'));launch._sha(digest)
 module.LAUNCH=launch;module.OWNERSHIP=registry_api;module.CLIENT=types.SimpleNamespace(TRUSTED_CODE=tuple(sorted(pins)))
 return module


def validate_amendment(reference,base_predecessor,*,clock=time.monotonic,wall=time.time,window=True):
 value=_authorization(reference)
 prior=validate_prior_for_diagnostic(DIAGNOSTIC_AUTHORIZATION,base_predecessor,clock=clock,wall=wall,window=window)
 require((prior['attempts'],prior['participant_segments'],prior['planned_cells'],len(prior['lineage']))==(193,9,448,16))
 diagnostic=_diagnostic_validator(value).validate_closed_diagnostic(DIAGNOSTIC_AUTHORIZATION,base_predecessor,prior,clock=clock,wall=wall,window=window)
 for key,expected in (('attempts',1),('participant_segments',0),('native_rows',0)):require(type(diagnostic[key])is int and diagnostic[key]==expected)
 require(diagnostic['root']==str(CAMPAIGN/'artifact-diagnostic-001'))
 launch._sha(diagnostic['container_id'])
 for key in ('physical_absence_confirmed','private_cleanup_confirmed','all_writers_stopped'):require(diagnostic[key]is True)
 for key,authority_key in (('terminal','diagnostic_terminal'),('ledger','diagnostic_ledger'),('independent_review','diagnostic_independent_review')):require(diagnostic[key]==value[authority_key])
 launch._exact(diagnostic['manifest'],{'path','sha256'});launch._sha(diagnostic['manifest']['sha256']);require(diagnostic['manifest']['path']==str(CAMPAIGN/'artifact-diagnostic-001/manifest.json'))
 now,wallnow=launch._number(clock()),launch._number(wall());require(now>=STARTED_MONOTONIC and wallnow>=value['recorded_wall'])
 if window:require(now<DEADLINE_MONOTONIC-30 and wallnow<DEADLINE_WALL-30)
 require(prior['attempts']+diagnostic['attempts']+value['planned_new_container_launches']==380 and prior['participant_segments']+value['planned_new_participant_segments']==33)
 return {**prior,'attempts':194,'campaign_amendment':copy.deepcopy(reference),'artifact_write_diagnostic':copy.deepcopy(diagnostic),'effective_limits':effective_limits(reference)}


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
    require(full['qualification_id'] not in {entry['qualification_id'] for entry in carry['lineage']}and full['qualification_id']!=_reference(carry['artifact_write_diagnostic']['manifest'])['qualification_id'])
    launch._exact(candidate,{'archive_sha256','runner_sha256','scope'});launch._sha(candidate['archive_sha256']);launch._sha(candidate['runner_sha256'])
    require(candidate['scope']=='extracted_candidate' and candidate['runner_sha256']==full['source']['runner'])
    _folder();_fence(reference,carry,create=True)
    return campaign.exclusive(BINDING_ROOT/'candidate-binding.json',{'schema':1,'amendment':reference,'qualification_id':full['qualification_id'],
        'full_manifest':full_manifest_reference,'candidate':candidate_reference,'launch_manifest_sha256':launch._digest(policy)})


def bind_final(root,manifest,carry,*,create=False):
    require(launch._canonical_root(str(root))==FINAL_ROOT/'launch-ledger' and len(carry['lineage'])==16 and carry['attempts']==194
        and carry['participant_segments']==9 and carry['campaign_amendment']==manifest['campaign_amendment'])
    reference=manifest['campaign_amendment'];_fence(reference,carry)
    binding=campaign.read(BINDING_ROOT/'candidate-binding.json');launch._exact(binding,{'schema','amendment','qualification_id','full_manifest','candidate','launch_manifest_sha256'})
    full=_reference(binding['full_manifest']);candidate=_reference(binding['candidate'])
    require(type(binding['schema']) is int and binding['schema']==1 and binding['amendment']==reference and binding['qualification_id']==manifest['qualification_id']
        and binding['full_manifest']['path']==str(FINAL_ROOT/'manifest.json') and binding['candidate']['path']==str(FINAL_ROOT/'candidate.json')
        and candidate['scope']=='extracted_candidate' and candidate['runner_sha256']==full['source']['runner']
        and binding['launch_manifest_sha256']==launch._digest(manifest) and launch._json(_launch_policy(full,reference))==launch._json(manifest))
    expected={'schema':1,'document_type':'qualification_matrix_amendment_launch_binding','amendment':reference,'qualification_id':manifest['qualification_id'],
        'manifest_sha256':launch._digest(manifest),'ledger_root':str(root),'cumulative_attempts':194,'participant_segments':9,
        'candidate_binding':campaign.ref(BINDING_ROOT/'candidate-binding.json')}
    if create:campaign.exclusive(BINDING_ROOT/'launch-binding.json',expected)
    require(campaign.read(BINDING_ROOT/'launch-binding.json')==expected)
