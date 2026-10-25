"""One explicitly authorized origin19 after sealed matrix18 and closed D04.

Fresh historical replay and original Ledger validation are retained. Private
payloads are never opened or hashed here; only exact known metadata/entry sets
and fresh task Registry bodies are observed. D04 adds no native row or origin.
"""
import copy
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import time
import application_launch as launch
import application_campaign as campaign
import application_matrix18 as historical
import ownership_registry as registry_api

REPO=Path(__file__).resolve().parents[2]
CAMPAIGN=REPO/'reports/application-agent-enhancements/A15/campaign-013'
AUTHORIZATION_PATH=CAMPAIGN/'matrix-019-authorization.json'
AUTHORIZATION_SHA256='07422f13dcb5f983e44e8d88dc374730fcddcf900d3b4d1def210ef0ba2b5142'
AUTHORIZATION_ID='ad5988fd-4c95-45a3-bcbc-e7ec1b609f52'
CLOCK_REFERENCE={'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/campaign-013/authorization-clock.json', 'sha256': '726a0d5b6d0ae5774c12cf57a5af2806ff96553afc7839c083bb89021245a606'}
BASIS_REFERENCES={'manifest': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-018/qualification/manifest.json', 'sha256': '9062fc6bfecdaf4a391d56239f172a6ec4394300493b9d82ee6f0647f702a0c2'}, 'state': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-018/qualification/state.json', 'sha256': 'c4123bfa4f658d598af36badb459be2ecb49442a928ee09dd0bc8b32e18fc5fa'}, 'ledger': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-018/qualification/launch-ledger/ledger.json', 'sha256': '32d3a3699480f37b96133e949c1e7e8ba32e1e1e06af5216cccd2f0effd58cf0'}, 'candidate': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-018/qualification/candidate.json', 'sha256': '23f7918d54eac0009eb8d1c6f185e1f3c3572abed5930f539a17e2627e7060d3'}, 'cleanup': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-018/final-cleanup.json', 'sha256': '7658e4ec3fc89d6dbafa6e5a6e5fabd938e406632ca964e5b4fb85114bf2faed'}, 'cleanup_review': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-018/final-cleanup-independent-review/review.json', 'sha256': '1bb29b29838af13c184d370390a0a7b485be089bb71cb028f66bbeea5d5cc5a1'}, 'post': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-018/post-master-preservation-001/verification.json', 'sha256': '467c3a5d3a5d1aad94ed3a83be6a30a762c271d863c95a76d9108bf5e5c216fa'}, 'post_review': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-018/post-master-preservation-actual-independent-review/review.json', 'sha256': '183efa3e65f9d9482c42dc47032baaa994a1574083e25499d88335062c4fffc8'}, 'diagnostic_manifest': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-018/helper-startup-diagnostic-authorized-001/future-execution-001/manifest.json', 'sha256': 'a647f2680d5e59562987e99fa92e4d81f75f5c1f62e0282bfcc50d99d42ed758'}, 'diagnostic_ledger': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-018/helper-startup-diagnostic-authorized-001/future-execution-001/launch-ledger/ledger.json', 'sha256': '6232507341e04b18794c28d8f935203239cc5e1cae0c7c58dd0550be73f5bc53'}, 'diagnostic_terminal': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-018/helper-startup-diagnostic-authorized-001/future-execution-001/terminal.json', 'sha256': 'be0d0792a5784f0ec05609353f77aa446ff67796af61f0164a45e17d81481810'}, 'diagnostic_review': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-018/helper-startup-diagnostic-authorized-001/actual-diagnostic-independent-review.json', 'sha256': '1ff385df003102baac429970dfc840ac439f9100ea4eb02581a4524e68b95db2'}, 'diagnostic_command': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-018/helper-startup-diagnostic-authorized-001/future-execution-command-001/verification.json', 'sha256': '789fc13fa9f0b85a9b3f5914ae85a9854ac72dabe59be62dea81d2cb06dce305'}, 'diagnostic_post_registry': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-018/helper-startup-diagnostic-authorized-001/host-baseline-post-001/verification.json', 'sha256': 'd2b5e8b8c2e7eed5a288f27973ff287967c42c653f6ae5a57abd0865d24df7b0'}, 'source030_handoff': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A16/attempt-017/final-independent-review/R2-actual-publication-review.json', 'sha256': '526f28354ed9d920a7cae3cf5784ef0aaea12861ef6219920bb194ca5ea37da6'}}
PRIOR_ROOT=REPO/'reports/application-agent-enhancements/A15/attempt-018/qualification'
FINAL_ROOT=REPO/'reports/application-agent-enhancements/A15/attempt-019/qualification'
DIAGNOSTIC_ROOT=PRIOR_ROOT.parent/'helper-startup-diagnostic-authorized-001/future-execution-001'
BINDING_ROOT=CAMPAIGN/'matrix-019-successor'
BOUNDARY_REFERENCE=copy.deepcopy(historical.BOUNDARY_REFERENCE)
PRIOR_AMENDMENT_REFERENCE={'path':str(historical.AUTHORIZATION_PATH),'sha256':historical.AUTHORIZATION_SHA256}
STARTED_MONOTONIC=706421.978244583
STARTED_WALL=1792430589.542186
DEADLINE_MONOTONIC=720821.978244583
DEADLINE_WALL=1792444989.542186
PRODUCTION_RUNNER='ad2f7eb69a47017643a02c22a44727d653fe61b2f0703f06f011b09e9b6bdd62'
_reference=historical._reference
_relative_reference=historical._relative_reference
_bytes_reference=historical._bytes_reference
_same_reference=historical._same_reference

def require(value):
    if not value:raise launch.LaunchError('qualification_matrix19_invalid')

def _clock(clock,wall,window=True):
    now,wallnow=launch._number(clock()),launch._number(wall())
    require(now>=STARTED_MONOTONIC and wallnow>=STARTED_WALL)
    if window:require(now<DEADLINE_MONOTONIC-30 and wallnow<DEADLINE_WALL-30)
    return now,wallnow

def _authorization(reference):
    require(type(AUTHORIZATION_SHA256)is str and reference=={'path':str(AUTHORIZATION_PATH),'sha256':AUTHORIZATION_SHA256})
    value=_reference(reference);clock=_reference(CLOCK_REFERENCE)
    fixed={'schema':1,'document_type':'qualification_matrix19_amendment','authorization_id':AUTHORIZATION_ID,'matrix_origin':19,
      'prior_cumulative_container_launches':275,'prior_cumulative_participant_segments':15,'prior_native_rows':504,'prior_matrix_origins':18,
      'planned_new_container_launches':186,'planned_new_participant_segments':24,'container_cap':461,'participant_cap':39,
      'maximum_matrix_origins':19,'maximum_live_containers':4,'maximum_active_trials':1,'maximum_inference_slots':1,
      'global_seconds':14400,'cleanup_reserve_seconds':30,'automatic_retries':0,'continuations':0,'auxiliary_container_launches':0,
      'platform':'linux/arm64','started_monotonic':STARTED_MONOTONIC,'started_wall':STARTED_WALL,'deadline_monotonic':DEADLINE_MONOTONIC,'deadline_wall':DEADLINE_WALL}
    launch._exact(value,set(fixed)|{'human_authorization','authorization_clock','recorded_wall','original_boundary','basis','prior_manifest','prior_state','prior_ledger','current_carry_metadata','current_carry_metadata_review'})
    for key,wanted in fixed.items():require(type(value[key])is type(wanted)and value[key]==wanted)
    require(value['authorization_clock']==CLOCK_REFERENCE and value['original_boundary']==BOUNDARY_REFERENCE and value['basis']==BASIS_REFERENCES)
    for key in ('manifest','state','ledger'):require(value['prior_'+key]==BASIS_REFERENCES[key])
    require(clock['schema']==1 and clock['document_type']=='matrix19_authorization_clock' and clock['human_authorization']==value['human_authorization'])
    for key in ('started_monotonic','started_wall','deadline_monotonic','deadline_wall'):require(type(clock[key])in(int,float)and clock[key]==fixed[key])
    for key,wanted in [('matrix_origin',19),('container_cap',461),('participant_cap',39),('prior_container_intents',275),('prior_participant_intents',15),('active_trials_max',1),('inference_slots_max',1),('live_containers_max',4),('max_seconds',14400)]:require(type(clock[key])is int and clock[key]==wanted)
    require(clock['automatic_retry_allowed']is False and clock['prior_evidence_must_remain_immutable']is True and clock['platform']=='linux/arm64')
    require(STARTED_WALL<=launch._number(value['recorded_wall'])<DEADLINE_WALL)
    require(DEADLINE_MONOTONIC-STARTED_MONOTONIC==DEADLINE_WALL-STARTED_WALL==14400)
    return value

def effective_limits(reference):
    value=_authorization(reference)
    return {**launch.LIMITS,'container_launch_attempts':value['container_cap'],'participant_segments':value['participant_cap']}

def _native_prior(base,*,clock,wall):
    """Original eighteen-origin policy:246 prior +28 actual native launches."""
    full,state,ledger=(_reference(BASIS_REFERENCES[key])for key in ('manifest','state','ledger'))
    require(full['prepared_root']==str(PRIOR_ROOT)and full['predecessor']==base and full['campaign_amendment']==PRIOR_AMENDMENT_REFERENCE and full['campaign_boundary']==BOUNDARY_REFERENCE)
    prior=historical.validate_amendment(PRIOR_AMENDMENT_REFERENCE,base,clock=clock,wall=wall,window=False)
    require((prior['attempts'],prior['participant_segments'],prior['planned_cells'],len(prior['lineage']))==(246,13,476,17))
    verifier=object.__new__(launch.LaunchLedger);verifier.root=PRIOR_ROOT/'launch-ledger';verifier.manifest=historical._launch_policy(full,PRIOR_AMENDMENT_REFERENCE)
    verifier.expected_daemon=verifier.expected_capacity=verifier._carry=None;verifier._prevalidated_carry=prior;verifier._validate(ledger)
    launch._exact(state,{'schema','phase','active_cell','cells','started_at'})
    require(type(state['schema'])is int and state['schema']==1 and state['phase']=='blocked' and state['started_at']==historical.STARTED_WALL and len(state['cells'])==7)
    ordered=[c for c in full['cells']if c['group']=='N02'];require(len(full['cells'])==28 and len(ordered)==12)
    for cell in full['cells']:
        item=state['cells'].get(cell['id'])
        if cell['group']=='N01':require(item=={'status':'PASS','attempts':1,'evidence_level':'native_infrastructure'})
        elif cell in ordered[:2]:
            launch._exact(item,{'status','attempts','run_id','attempt_id','runner_status','exit_code','interruption_sent'})
            require(item['status']=='PASS'and type(item['attempts'])is int and item['attempts']==1 and item['runner_status']=='FAIL'and type(item['exit_code'])is int and item['exit_code']==1 and item['interruption_sent']is False)
            for key in ('run_id','attempt_id'):launch._uuid(item[key])
        elif cell==ordered[2]:
            launch._exact(item,{'status','attempts','run_id','attempt_id','private_cleanup'})
            require(item['status']=='BLOCKED'and type(item['attempts'])is int and item['attempts']==1 and item['private_cleanup']=='unconfirmed')
            for key in ('run_id','attempt_id'):launch._uuid(item[key])
        else:require(item is None)
    active=state['active_cell'];launch._exact(active,{'id','pid','run_id','attempt_id'})
    require(type(active['pid'])is int and active['pid']>1 and active['id']==ordered[2]['id']and all(active[k]==state['cells'][ordered[2]['id']][k]for k in ('run_id','attempt_id')))
    rows=ledger['launches'];require(type(ledger['poisoned'])is bool and ledger['poisoned']is True and len(rows)==28 and sum(r['role']=='participant'for r in rows)==2)
    require(all(r['physical']=='absent'and r['container_id']is not None for r in rows)and len({r['container_id']for r in rows})==28)
    false=[r for r in rows if not r['private_cleanup']]
    require(len(false)==3 and {r['role']for r in false}=={'probe','boundary','preflight'}and all(r['cell']==active['id']for r in false))
    require(full['qualification_id']not in {entry['qualification_id']for entry in prior['lineage']})
    hashes={key+'_sha256':BASIS_REFERENCES[key]['sha256']for key in ('manifest','state','ledger')}
    result={**{k:v for k,v in prior.items()if not k.startswith('_')},'attempts':274,'participant_segments':15,'qualification_id':full['qualification_id'],'planned_cells':504,
      **hashes,'lineage':prior['lineage']+[{'root':str(PRIOR_ROOT),'qualification_id':full['qualification_id'],**hashes}],
      'prior_rows':prior['prior_rows']+historical._rows(full,state),'daemon':ledger['daemon'],
      'daemon_capacity':{k:min(prior['daemon_capacity'][k],ledger['daemon_capacity'][k])for k in ('cpu_millis','memory_mib')}}
    require(len(result['prior_rows'])==504 and len(result['lineage'])==18)
    return full,state,ledger,result

def _metadata_tree(root,nodes,scope):
    """FD-relative named metadata/entry sets only; never open a payload leaf."""
    root=launch._canonical_root(root);require(root.is_relative_to(scope)and type(nodes)is dict and '.'in nodes and 1<=len(nodes)<=512)
    for name,expected in nodes.items():
        require(type(name)is str and(name=='.'or(not Path(name).is_absolute()and '..'not in Path(name).parts and str(Path(name))==name)))
        path=root if name=='.'else root/name;fd=launch._dir(path.parent,False)
        try:info=os.stat(path.name,dir_fd=fd,follow_symlinks=False)
        finally:os.close(fd)
        kind='directory'if stat.S_ISDIR(info.st_mode)else'regular'if stat.S_ISREG(info.st_mode)else'forbidden'
        require(kind==expected['kind']and info.st_uid==expected['uid']==os.getuid()and stat.S_IMODE(info.st_mode)==expected['mode']and not expected['mode']&0o022
          and all(getattr(info,attr)==expected[key]for attr,key in [('st_dev','device'),('st_ino','inode'),('st_nlink','nlink'),('st_size','size'),('st_mtime_ns','mtime_ns'),('st_ctime_ns','ctime_ns')]))
        if kind=='directory':
            require(expected['mode']in(0o700,0o755));fd=launch._dir(path,False)
            try:
                opened=os.fstat(fd);require((opened.st_dev,opened.st_ino)==(info.st_dev,info.st_ino))
                require(set(os.listdir(fd))=={Path(n).name for n in nodes if n!='.'and str(Path(n).parent)==('.'if name=='.'else name)})
            finally:os.close(fd)
        else:require(kind=='regular'and expected['mode']in(0o400,0o444,0o600,0o644)and expected['nlink']==1)

def _current_metadata(cleanup):
    base=_reference(cleanup['current_retained_evidence_screen']);extra=_reference(cleanup['supplemental_context_screen'])
    require(base['status']==extra['status']=='PASS'and base['key_free_status']==extra['key_free_status']=='KEY_FREE'and base['credential_match_count']==extra['credential_match_count']==0)
    require(base['all_selected_bytes_keyfree_before_first_hash']is True and extra['all_selected_bytes_keyfree_before_first_hash']is True)
    inventory=_reference(base['inventory']);supplement=_reference(extra['metadata_inventory']);trees=[];absent=[]
    for cell in inventory['cells']:
        for tree in cell['retained_roots']+cell['owner_private_leaves']+cell['startup_diagnostic_leaves']:
            if tree['state']=='absent':absent.append(tree['path']);continue
            require(tree['state']=='present');nodes={'.':tree['metadata'],**{n['relative']:n for n in tree.get('nodes',[])}}
            require(len(nodes)==1+len(tree.get('nodes',[])));trees.append((tree['path'],nodes))
        absent.extend(t['path']for t in cell['sensitive_roots'])
    for tree in supplement['targets']:
        if tree['state']=='absent':absent.append(tree['path']);continue
        require(tree['state']=='present');nodes={'.':tree['metadata'],**{n['relative']:n for n in tree['nodes']}}
        require(len(nodes)==1+len(tree['nodes']));trees.append((tree['path'],nodes))
    require(len(trees)==15 and sum(n['kind']=='regular'for _,nodes in trees for n in nodes.values())==27)
    require(len({path for path,_ in trees})==15)
    for path,nodes in trees:_metadata_tree(path,nodes,PRIOR_ROOT)
    require(len(set(absent))==13 and all(registry_api._qualification_absent(str(path))for path in absent))
    return base,extra

def _actors(cleanup):
    seen=set()
    for pair in cleanup['actor_chains']:
        chain=_reference(pair['chain']);review=_reference(pair['review'])
        require(chain['status']==review['status']=='PASS'and review['unresolved_findings']==[]and chain['positive_terminal_chain']is True and chain['no_unconfirmed_owned_children']is True
          and review['supports_global_actor_terminal_chain']is True and review['actor_chain']==pair['chain'])
        require(chain['covered_actor_ids']==review['covered_actor_ids']and chain['covered_pids']==review['covered_pids'])
        current=[]
        for actor in chain['actors']:
            context=actor['context'];identifier=actor['actor_id'];launch._sha(identifier)
            require(type(actor['pid'])is int and actor['pid']>1 and type(context['pid'])is int and context['pid']==actor['pid']and identifier==launch._digest(context)and identifier not in seen)
            seen.add(identifier);current.append(identifier)
            for key in ('terminal_proofs','source_proofs'):
                require(type(actor[key])is list and actor[key])
                for reference in actor[key]:_bytes_reference(reference)
        require(sorted(current)==chain['covered_actor_ids'])
    require(len(seen)==67)
    support=_reference(cleanup['master_metadata_terminal_contexts'])
    require(support['status']=='PASS'and support['positive_terminal_chain']is True and support['no_unconfirmed_owned_children']is True and support['covered_actor_count']==24 and support['credential_or_owned_bootstrap_cutoff_contexts']==67 and support['numeric_PID_probe_or_signal_performed']is False)
    current=[]
    for actor in [*support['actors'],*cleanup['post_master_preservation_contexts']]:
        context=actor['context'];identifier=actor['actor_id'];launch._sha(identifier)
        require(type(actor['pid'])is int and actor['pid']>1 and type(context['pid'])is int and context['pid']==actor['pid']and context['qualification_id']==cleanup['qualification_id']and identifier==launch._digest(context)and identifier not in seen)
        seen.add(identifier);current.append(identifier);require(actor['terminal_proofs'])
        for ref in actor['terminal_proofs']:_bytes_reference(ref)
        for ref in actor.get('source_proofs',[]):_bytes_reference(ref)
    require(len(support['actors'])==24 and len(cleanup['post_master_preservation_contexts'])==2 and len(seen)==93 and sorted(current[:24])==support['covered_actor_ids'])

def _current_cleanup(full,state,ledger):
    cleanup=_reference(BASIS_REFERENCES['cleanup']);review=_reference(BASIS_REFERENCES['cleanup_review']);handoff=_reference(BASIS_REFERENCES['source030_handoff'])
    require(cleanup['status']==review['status']==handoff['status']=='PASS'and review['unresolved_findings']==handoff['unresolved_findings']==[]and review['supports_final_handoff']is True and review['final_cleanup']==BASIS_REFERENCES['cleanup'])
    require(cleanup['qualification_id']==full['qualification_id']and cleanup['raw_ledger']==BASIS_REFERENCES['ledger']and cleanup['raw_state']==BASIS_REFERENCES['state'])
    require(cleanup['cumulative_container_launches']==274 and cleanup['participant_segments']==15 and cleanup['real_model_participant_segments']==0 and cleanup['raw_current_counts']=={'PASS':6,'BLOCKED':1,'NOT_RUN':21})
    for key in ('all213_registry_records_released','all_known_private_roots_closed','master018_copy_removed','all_known_owned_contexts_terminal','safe_for_final_handoff','raw_poisoned_true_preserved','raw_private_cleanup_false_preserved'):require(cleanup[key]is True)
    require(cleanup['raw_active_cell_preserved']==state['active_cell']and cleanup['raw_private_cleanup_false_count']==3 and cleanup['known_context_count']==93)
    _actors(cleanup);_current_metadata(cleanup)
    post=_reference(BASIS_REFERENCES['post']);peer=_reference(BASIS_REFERENCES['post_review'])
    require(cleanup['post_master_preservation']==BASIS_REFERENCES['post']and cleanup['post_master_preservation_review']==BASIS_REFERENCES['post_review']and post['status']==peer['status']=='PASS'
      and peer['unresolved_findings']==[]and peer['supports_post_master_preservation']is True and peer['post_master_preservation']==BASIS_REFERENCES['post']and post['master_store_and_parent_absent']is True)
    for key in ('source367_unchanged','current_public_history_unchanged','raw_current_frozen_copies_unchanged','campaign213_Registry_final_bodies_stable','raw_ledger_flags_unchanged','all_inventory_sensitive_roots_absent'):require(post[key]is True)
    master=_reference(cleanup['master_cleanup']);mreview=_reference(cleanup['master_cleanup_review'])
    require(master['document_type']=='active_qualification_master_cleanup'and master['status']=='removed'and master['store_removed']is True and master['temporary_parent_removed']is True
      and master['values_opened']is False and master['value_hashes_computed']is False and master['operator_original_store_selected']is False
      and mreview['status']=='PASS'and mreview['unresolved_findings']==[]and mreview['supports_master_cleanup']is True and mreview['master_cleanup']==cleanup['master_cleanup'])
    require(registry_api._qualification_absent(master['target'])and registry_api._qualification_absent(str(Path(master['target']).parent)))
    return cleanup,master

def _closed_helper(prior):
    terminal,manifest,ledger,review=(_reference(BASIS_REFERENCES['diagnostic_'+key])for key in ('terminal','manifest','ledger','review'))
    require(review['status']=='PASS'and review['unresolved_findings']==[]and review['supports_actual_helper_diagnostic']is True and review['supports_confirmed_cleanup']is True)
    for key in ('terminal','manifest','ledger'):require(review[key]==BASIS_REFERENCES['diagnostic_'+key])
    require(terminal['status']=='PASS'and terminal['document_type']=='helper_startup_diagnostic_terminal'and terminal['manifest']==BASIS_REFERENCES['diagnostic_manifest']and terminal['ledger']==BASIS_REFERENCES['diagnostic_ledger'])
    for key,wanted in [('new_container_intents',1),('cumulative_container_intents',275),('participant_segments',15),('new_participants',0),('inference_calls',0),('business_calls',0),('real_credentials',0)]:require(type(terminal[key])is int and terminal[key]==wanted)
    for key in ('helper_startup_ready','physical_absence_confirmed','private_cleanup_confirmed','all_writers_stopped','dummy_store_removed','diagnostic_evidence_available'):require(terminal[key]is True)
    require(terminal['automatic_retry_performed']is False and terminal['matrix_triggered']is False and terminal['fixture_identity_seconds']==5 and terminal['helper_ready_seconds']==10)
    require(0<launch._number(terminal['elapsed_seconds'])<=116 and 0<=launch._number(terminal['cleanup_seconds'])<=30)
    launch._exact(manifest,{'schema','document_type','qualification_id','authorization','window','images','cells','limits','planned_container_launches','diagnostic'})
    launch._uuid(manifest['qualification_id']);require(manifest['qualification_id']not in {entry['qualification_id']for entry in prior['lineage']})
    require(type(manifest['schema'])is int and manifest['schema']==1 and manifest['document_type']=='helper_startup_diagnostic'and type(manifest['planned_container_launches'])is int and manifest['planned_container_launches']==1 and manifest['diagnostic']['kind']=='helper-startup'and manifest['diagnostic']['root']==str(DIAGNOSTIC_ROOT)
      and manifest['limits']=={**launch.LIMITS,'container_launch_attempts':275,'participant_segments':15})
    require(len(manifest['cells'])==1 and manifest['cells'][0]['role_limits']=={'application-helper':1}and type(manifest['cells'][0]['role_limits']['application-helper'])is int and manifest['cells'][0]['group']=='D04'and type(manifest['cells'][0]['participant_segments_max'])is int and manifest['cells'][0]['participant_segments_max']==0)
    image=prior['image_recovery']['qualified_images']['core-0.87.1']['id'];require(set(manifest['images'])=={'core-0.87.1'}and manifest['images']['core-0.87.1']=={'id':image,'platform':'linux/arm64','capabilities':{'pi':'0.87.1'}}and manifest['cells'][0]['image_id']==image and manifest['cells'][0]['allowed_images']==[image])
    require(manifest['authorization']==review['authorization']==terminal['authorization']and manifest['window']==review['window']==terminal['window'])
    claim={'schema':1,'authorization':manifest['authorization'],'qualification_id':manifest['qualification_id'],'manifest':BASIS_REFERENCES['diagnostic_manifest'],'root':str(DIAGNOSTIC_ROOT),'maximum_launches':1}
    claim_sha=hashlib.sha256(launch._json(claim)+b'\n').hexdigest()
    for path in (DIAGNOSTIC_ROOT.parent/'future-diagnostic-claim/claim.json',DIAGNOSTIC_ROOT/'claim.json'):
        require(_reference({'path':str(path),'sha256':claim_sha})==claim)
    window=_reference(manifest['window']);auth=_reference(manifest['authorization'])
    require(window['authorization']==manifest['authorization']and auth['status']=='AUTHORIZED'and 'proposal_only'not in auth and auth['diagnostic_kind']=='application_execution_helper_startup'and auth['maximum_diagnostic_launches']==1)
    require(all(ledger[k]==window[v]for k,v in [('started','started_monotonic'),('deadline','deadline_monotonic'),('started_wall','started_wall'),('deadline_wall','deadline_wall')]))
    verifier=object.__new__(launch.LaunchLedger);verifier.manifest=manifest;verifier.root=DIAGNOSTIC_ROOT/'launch-ledger';verifier.expected_daemon=prior['daemon'];verifier.expected_capacity=None;verifier._carry=prior
    verifier._validate(ledger)
    require(ledger['poisoned']is False and len(ledger['launches'])==1)
    row=ledger['launches'][0];require(row['role']=='application-helper'and row['physical']=='absent'and row['private_cleanup']is True and row['container_id']is not None)
    command=_reference(BASIS_REFERENCES['diagnostic_command']);require(review['command']==BASIS_REFERENCES['diagnostic_command']and command['status']=='PASS'and type(command['actual_exit'])is int and command['actual_exit']==0 and command['wait_completed']is True and command['unknown_owned_child']is False and 0<launch._number(command['elapsed_seconds'])<=120)
    require(type(terminal['process_receipts'])is list and len(terminal['process_receipts'])==29)
    helper=[]
    for index,pair in enumerate(terminal['process_receipts'],1):
        start=_reference(pair['start']);end=_reference(pair['terminal'])
        require(start['ordinal']==end['ordinal']==index and type(start['pid'])is int and start['pid']>1 and end['pid']==start['pid']and end['wait_confirmed']is True and end['unknown_owned_child']is False and type(end['returncode'])is int)
        if start['kind']=='helper_container_cli':helper.append(start['pid'])
    require(helper==[row['pid']])
    post=_reference(BASIS_REFERENCES['diagnostic_post_registry']);require(review['post_registry']==BASIS_REFERENCES['diagnostic_post_registry']and post['status']=='PASS'and post['whole_host_records']==6708 and post['status_counts']=={'released':6708})
    require(review['confirmed_cleanup']['all6706_prior_record_hashes_unchanged']is True and review['confirmed_cleanup']['new_kind_delta']=={'container':1,'network':1})
    require(review['key_free_scope']['new_diagnostic_files']==3 and review['key_free_scope']['classified_hashes']==terminal['classified_evidence_hashes'])
    require(set(terminal['classified_evidence_hashes'])=={'private/diagnostic-startup-phases.jsonl','private/raw/.owner.lock','private/raw/state.json'})
    for digest in terminal['classified_evidence_hashes'].values():launch._sha(digest)
    return {'attempts':1,'participant_segments':0,'native_rows':0,'root':str(DIAGNOSTIC_ROOT),'manifest':BASIS_REFERENCES['diagnostic_manifest'],'ledger':BASIS_REFERENCES['diagnostic_ledger'],'terminal':BASIS_REFERENCES['diagnostic_terminal'],'independent_review':BASIS_REFERENCES['diagnostic_review'],'container_id':row['container_id'],'qualification_id':manifest['qualification_id'],'physical_absence_confirmed':True,'private_cleanup_confirmed':True,'all_writers_stopped':True,'helper_startup_ready':True,'evidence_key_free':True},terminal,review,post

def _fresh_carry_metadata(value,cleanup,master,terminal,dreview,post,daemon):
    metadata=_reference(value['current_carry_metadata']);review=_reference(value['current_carry_metadata_review'])
    require(metadata['status']==review['status']=='PASS'and review['unresolved_findings']==[]and review['supports_current_carry_metadata']is True and review['current_carry_metadata']==value['current_carry_metadata'])
    require(metadata['original_lease_held']is True and metadata['Registry_constructor_or_reconcile_called']is False and metadata['Registry_mutations']==metadata['PID_probes']==metadata['Docker_or_model_actions']==metadata['retained_payload_opens_or_hashes']==0 and metadata['credential_values_opened']is False and metadata['all_whole_host_records_released']is True)
    require(metadata['new_authorization_clock']==CLOCK_REFERENCE and metadata['prior_post_registry']==BASIS_REFERENCES['diagnostic_post_registry']and metadata['d04_classification_terminal']==BASIS_REFERENCES['diagnostic_terminal'])
    records=metadata['task_records_215'];require(type(records)is list and len(records)==215)
    old={_reference(ref)['launch_id']:ref['sha256']for ref in cleanup['registry_records']};require(len(old)==213)
    current={};global_root=historical._registry_root()
    for ref in records:
        record=_relative_reference(ref);key=record['launch_id'];launch._uuid(key)
        require(key not in current and record['status']=='released'and record['daemon']==daemon)
        require(launch._bound_json(str(global_root/(key+'.json')),ref['sha256'])==record)
        require(metadata['record_sha256'][str(global_root/(key+'.json'))]==ref['sha256']);current[key]=(record,ref['sha256'])
    require(all(current.get(key,(None,None))[1]==digest for key,digest in old.items()))
    new={str(global_root/(key+'.json')):record for key,(record,_)in current.items()if key not in old}
    require(set(new)==set(dreview['confirmed_cleanup']['exact_two_new_released_record_paths'])and {r.get('kind','container')for r in new.values()}=={'container','network'})
    require(all(current[key][1]==post['record_sha256'][str(global_root/(key+'.json'))]for key in current))
    helper=next(record for record in new.values()if record.get('kind','container')=='container');row=_reference(BASIS_REFERENCES['diagnostic_ledger'])['launches'][0]
    require(all(helper[key]==row[key]for key in ('registry','generation','launch_id','container','image','container_id'))and helper.get('application_helper')is True and helper.get('client_mode')=='application-execution'and launch._intent_identity(helper)==row['intent_sha256'])
    network=next(record for record in new.values()if record.get('kind')=='network');require(network['registry']==helper['registry']and network['generation']==helper['generation']and network['daemon']==helper['daemon']and network['container']==helper['container']+'-network')
    tree=metadata['d04_retained_tree'];expected_root=DIAGNOSTIC_ROOT/'run/application-evidence'/next(r['container']for r in new.values()if r.get('kind','container')=='container')
    require(tree['path']==str(expected_root)and set(tree['nodes'])=={'.','private','private/raw','private/outputs',*terminal['classified_evidence_hashes']}and metadata['d04_classified_evidence_hashes']==terminal['classified_evidence_hashes'])
    require(all(n['mode']==(0o700 if n['kind']=='directory'else 0o600)for n in tree['nodes'].values()))
    _metadata_tree(tree['path'],tree['nodes'],DIAGNOSTIC_ROOT)
    wanted=set(dreview['confirmed_cleanup']['fresh_Root_stat_absences'])|{master['target'],str(Path(master['target']).parent)}
    require({v['path']for v in metadata['known_absences']}==wanted and all(v['absent']is True and registry_api._qualification_absent(v['path'])for v in metadata['known_absences']))

def validate_amendment(reference,base_predecessor,*,clock=time.monotonic,wall=time.time,window=True):
    value=_authorization(reference);_clock(clock,wall,window)
    full,state,ledger,prior=_native_prior(base_predecessor,clock=clock,wall=wall)
    cleanup,master=_current_cleanup(full,state,ledger)
    diagnostic,terminal,review,post=_closed_helper(prior)
    for key,wanted in [('attempts',1),('participant_segments',0),('native_rows',0)]:require(type(diagnostic[key])is int and diagnostic[key]==wanted)
    _fresh_carry_metadata(value,cleanup,master,terminal,review,post,ledger['daemon'])
    _clock(clock,wall,window)
    require(prior['attempts']+1+value['planned_new_container_launches']==461 and prior['participant_segments']+value['planned_new_participant_segments']==39)
    return {**prior,'attempts':275,'helper_startup_diagnostic':diagnostic,'previous_window':{k:prior[k]for k in ('started','deadline','started_wall','deadline_wall')},
      'started':STARTED_MONOTONIC,'deadline':DEADLINE_MONOTONIC,'started_wall':STARTED_WALL,'deadline_wall':DEADLINE_WALL,'campaign_amendment':copy.deepcopy(reference),'effective_limits':effective_limits(reference)}

def _folder(*,clock=time.monotonic,wall=time.time):
    _clock(clock,wall);parent=launch._dir(BINDING_ROOT.parent,False)
    try:
        try:_clock(clock,wall);os.mkdir(BINDING_ROOT.name,0o700,dir_fd=parent);os.fsync(parent)
        except FileExistsError:pass
    finally:os.close(parent)
    fd=launch._dir(BINDING_ROOT);os.close(fd)

def _fence(reference,carry,*,create=False,clock=time.monotonic,wall=time.time):
    parent=launch._dir(PRIOR_ROOT.parent,False);folder=lock=None
    def action():
        if create:_clock(clock,wall)
    try:
        if create:
            try:action();os.mkdir('campaign-successor-claims',0o700,dir_fd=parent);action();os.fsync(parent)
            except FileExistsError:pass
        folder=os.open('campaign-successor-claims',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        info=os.fstat(folder);require(info.st_uid==os.getuid()and stat.S_IMODE(info.st_mode)==0o700)
        name=launch._digest({'root':str(PRIOR_ROOT),'qualification_id':carry['qualification_id']});auth='amendment-'+AUTHORIZATION_ID
        action();lock=launch._file(folder,name+'.lock',os.O_RDWR|(os.O_CREAT|os.O_EXCL if create else 0));fcntl.flock(lock,fcntl.LOCK_EX);action()
        expected={'schema':1,'document_type':'qualification_matrix_amendment_claim','amendment':reference,'prior_root':str(PRIOR_ROOT),'prior_qualification_id':carry['qualification_id'],'final_root':str(FINAL_ROOT)}
        if create:
            action();os.fsync(lock);action();os.fsync(folder)
            action();fd=launch._file(folder,auth+'.lock',os.O_RDWR|os.O_CREAT|os.O_EXCL)
            try:action();os.fsync(fd)
            finally:os.close(fd)
            action();os.fsync(folder)
            for filename in (name+'.json',auth+'.json'):
                action();fd=launch._file(folder,filename,os.O_WRONLY|os.O_CREAT|os.O_EXCL)
                with os.fdopen(fd,'wb')as stream:action();stream.write(launch._json(expected));stream.flush();action();os.fsync(stream.fileno())
                action();os.fsync(folder)
        fd=launch._file(folder,auth+'.lock',os.O_RDWR);os.close(fd)
        require(launch._read(folder,name+'.json')==expected and launch._read(folder,auth+'.json')==expected)
    finally:
        if lock is not None:os.close(lock)
        if folder is not None:os.close(folder)
        os.close(parent)

def _launch_policy(full,reference):
    require(type(full.get('schema'))is int and full['schema']==1 and full.get('document_type')=='application_client_qualification'and full.get('prepared_root')==str(FINAL_ROOT)
      and full.get('campaign_amendment')==reference and full.get('campaign_boundary')==BOUNDARY_REFERENCE and full['source']['runner']==PRODUCTION_RUNNER)
    expected={k:v for k,v in effective_limits(reference).items()if k!='live'};expected.update(simultaneously_registered_live_container_intents=4,automatic_retries=0,continuations=0)
    require(launch._json(full['limits'])==launch._json(expected))
    fields=('id','group','release','image_id','allowed_images','role_limits','container_launches_max','participant_segments_max')
    return launch.validate_manifest({'qualification_id':full['qualification_id'],'images':full['images'],'cells':[{k:c[k]for k in fields}for c in full['cells']],
      'limits':effective_limits(reference),'planned_container_launches':full['planned_container_launches'],'predecessor':full['predecessor'],'campaign_boundary':full['campaign_boundary'],'campaign_amendment':reference})

def finalize_candidate(reference,full_manifest_reference,candidate_reference,*,clock=time.monotonic,wall=time.time):
    _clock(clock,wall);full=_reference(full_manifest_reference);candidate=_reference(candidate_reference)
    require(full_manifest_reference['path']==str(FINAL_ROOT/'manifest.json')and candidate_reference['path']==str(FINAL_ROOT/'candidate.json'))
    policy=_launch_policy(full,reference);carry=validate_amendment(reference,full['predecessor'],clock=clock,wall=wall)
    require(full['images']==carry['image_recovery']['qualified_images']and full['qualification_id']not in {e['qualification_id']for e in carry['lineage']}|{carry['helper_startup_diagnostic']['qualification_id']})
    launch._exact(candidate,{'archive_sha256','runner_sha256','scope'});launch._sha(candidate['archive_sha256']);launch._sha(candidate['runner_sha256'])
    require(candidate['scope']=='extracted_candidate'and candidate['runner_sha256']==full['source']['runner']==PRODUCTION_RUNNER)
    _folder(clock=clock,wall=wall);_fence(reference,carry,create=True,clock=clock,wall=wall);_clock(clock,wall)
    return campaign.exclusive(BINDING_ROOT/'candidate-binding.json',{'schema':1,'amendment':reference,'qualification_id':full['qualification_id'],'full_manifest':full_manifest_reference,'candidate':candidate_reference,'launch_manifest_sha256':launch._digest(policy)})

def bind_final(root,manifest,carry,*,create=False):
    require(launch._canonical_root(str(root))==FINAL_ROOT/'launch-ledger'and len(carry['lineage'])==18 and carry['attempts']==275 and carry['participant_segments']==15 and carry['planned_cells']==504
      and carry['campaign_amendment']==manifest['campaign_amendment']and manifest['qualification_id']not in {carry['helper_startup_diagnostic']['qualification_id']}|{e['qualification_id']for e in carry['lineage']})
    reference=manifest['campaign_amendment'];_fence(reference,carry)
    binding=campaign.read(BINDING_ROOT/'candidate-binding.json');launch._exact(binding,{'schema','amendment','qualification_id','full_manifest','candidate','launch_manifest_sha256'})
    full=_reference(binding['full_manifest']);candidate=_reference(binding['candidate']);require(full['images']==carry['image_recovery']['qualified_images'])
    require(type(binding['schema'])is int and binding['schema']==1 and binding['amendment']==reference and binding['qualification_id']==manifest['qualification_id']and binding['full_manifest']['path']==str(FINAL_ROOT/'manifest.json')and binding['candidate']['path']==str(FINAL_ROOT/'candidate.json')
      and candidate['scope']=='extracted_candidate'and candidate['runner_sha256']==full['source']['runner']==PRODUCTION_RUNNER and binding['launch_manifest_sha256']==launch._digest(manifest)and launch._json(_launch_policy(full,reference))==launch._json(manifest))
    expected={'schema':1,'document_type':'qualification_matrix_amendment_launch_binding','amendment':reference,'qualification_id':manifest['qualification_id'],'manifest_sha256':launch._digest(manifest),'ledger_root':str(root),'cumulative_attempts':275,'participant_segments':15,'candidate_binding':campaign.ref(BINDING_ROOT/'candidate-binding.json')}
    if create:_clock(time.monotonic,time.time);campaign.exclusive(BINDING_ROOT/'launch-binding.json',expected)
    require(campaign.read(BINDING_ROOT/'launch-binding.json')==expected)

