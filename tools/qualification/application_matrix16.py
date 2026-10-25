"""One explicitly authorized sixteenth matrix after preserved blocked matrix015.

This maintainer validator reads public custody evidence and reserves one durable
successor origin. It never launches a process, resolves a key, repairs old raw
accounting, or grants any additional diagnostic or seventeenth origin.
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
import application_matrix15 as prior_amendment
import ownership_registry as registry_api

REPO = Path(__file__).resolve().parents[2]
AUTHORIZATION_PATH = REPO/'reports/application-agent-enhancements/A15/campaign-010/matrix-016-authorization.json'
AUTHORIZATION_SHA256 = '77d461392127ee7bc434750438341d8fa21148bad54f7cc5af3ee2b2284fb057'
AUTHORIZATION_ID = '358e19b0-16d8-4a87-bd0a-df2f88dba017'
WINDOW_AUTHORIZATION = {'path':str(REPO/'reports/application-agent-enhancements/A15/campaign-window-008-authorization.json'),
    'sha256':'6d229c1cbf591b14c26f5a9d73936de185fe6751737dcd0ca36792720c740e4a'}
PRIOR_ROOT = REPO/'reports/application-agent-enhancements/A15/attempt-015/qualification'
FINAL_ROOT = REPO/'reports/application-agent-enhancements/A15/attempt-016/qualification'
BINDING_ROOT = AUTHORIZATION_PATH.parent/'matrix-016-successor'
PRIOR_AMENDMENT_REFERENCE = {'path':str(prior_amendment.AUTHORIZATION_PATH),'sha256':prior_amendment.AUTHORIZATION_SHA256}
BOUNDARY_REFERENCE = copy.deepcopy(prior_amendment.BOUNDARY_REFERENCE)
STARTED_WALL = 1792356572.352897
STARTED_MONOTONIC = 636980.227786125
DEADLINE_WALL = 1792370972.352897
DEADLINE_MONOTONIC = 651380.227786125
_reference = prior_amendment._reference
_relative_reference = prior_amendment._relative_reference


def require(value):
    if not value:
        raise launch.LaunchError('qualification_matrix16_invalid')


def _authorization(reference):
    require(reference == {'path':str(AUTHORIZATION_PATH),'sha256':AUTHORIZATION_SHA256})
    value = _reference(reference)
    fixed = {'schema':1,'document_type':'qualification_matrix_requalification_authorization','authorization_id':AUTHORIZATION_ID,
        'final_root':str(FINAL_ROOT),'maximum_matrix_origins':16,'prior_matrix_origins':15,'cumulative_container_launches':163,
        'cumulative_participant_segments':6,'previous_container_cap':305,'container_cap':349,'participant_cap':30,'previous_participant_cap':26,'live_cap':4,
        'trial_cap':1,'inference_slot_cap':1,'platform':'linux/arm64','automatic_retries':0,'continuations':0,
        'planned_new_container_launches':186,'planned_new_participant_segments':24,'started_wall':STARTED_WALL,
        'started_monotonic':STARTED_MONOTONIC,'deadline_wall':DEADLINE_WALL,'deadline_monotonic':DEADLINE_MONOTONIC,
        'original_evidence_modified':False,'historical_windows_modified':False,'additional_auxiliary_launches_authorized':0,
        'additional_startup_diagnostic_authorized':False,'seventeenth_origin_authorized':False}
    launch._exact(value,set(fixed)|{'human_authorization','recorded_wall','window_authorization','prior_amendment','original_boundary',
        'prior_manifest','prior_state','prior_ledger','prior_cleanup','prior_independent_review','prior_boundary_review'})
    for key, expected in fixed.items():
        require(type(value[key]) is type(expected) and value[key] == expected)
    for key in ('started_wall','started_monotonic','deadline_wall','deadline_monotonic','recorded_wall'):
        launch._number(value[key])
    require(DEADLINE_WALL == STARTED_WALL+14400 and DEADLINE_MONOTONIC == STARTED_MONOTONIC+14400
        and STARTED_WALL <= value['recorded_wall'] < DEADLINE_WALL)
    require(type(value['human_authorization']) is str and 1 <= len(value['human_authorization']) <= 4096
        and value['window_authorization'] == WINDOW_AUTHORIZATION and value['prior_amendment'] == PRIOR_AMENDMENT_REFERENCE
        and value['original_boundary'] == BOUNDARY_REFERENCE)
    window = _reference(value['window_authorization'])
    require(window['document_type'] == 'qualification_window_authorization' and window['window_seconds'] == 14400
        and window['authorization'] == value['human_authorization'] and window['original_deadline_wall'] == prior_amendment.DEADLINE_WALL
        and window['prior_campaign_modified'] is False and window['new_native_admission_requires_positive_owned_cleanup'] is True)
    for key in ('started_wall','started_monotonic','deadline_wall','deadline_monotonic','cumulative_container_launches',
        'cumulative_participant_segments','container_cap','participant_cap','live_cap','trial_cap','inference_slot_cap','platform','automatic_retries','continuations'):
        require(type(window[key]) is type(value[key]) and window[key] == value[key])
    for key, relative in (('prior_manifest','manifest.json'),('prior_state','state.json'),('prior_ledger','launch-ledger/ledger.json')):
        launch._exact(value[key],{'path','sha256'})
        require(value[key]['path'] == str(PRIOR_ROOT/relative))
        launch._sha(value[key]['sha256'])
    return value


def effective_limits(reference):
    _authorization(reference)
    return {**launch.LIMITS,'container_launch_attempts':349,'participant_segments':30}



def _same_reference(left, right):
    for reference in (left,right):
        launch._exact(reference,{'path','sha256'});launch._sha(reference['sha256'])
    def path(reference):
        value=Path(reference['path'])
        return launch._canonical_root(str(value if value.is_absolute() else REPO/value))
    return left['sha256']==right['sha256'] and path(left)==path(right)


def _retained_tree(root, metadata, hashes):
    """Fence exact known names before opening any previously key-free leaf."""
    root=launch._canonical_root(root);require(root.is_relative_to(PRIOR_ROOT))
    require(type(metadata) is dict and type(hashes) is dict and set(metadata)=={'.'}|set(hashes)|{
        str(Path(name).parent) for name in hashes if str(Path(name).parent)!='.'}|({'outputs'} if 'outputs' in metadata else set()))
    for name,expected in metadata.items():
        require(name=='.' or (not Path(name).is_absolute() and '..' not in Path(name).parts))
        if expected['kind']!='dir':continue
        path=root/name;fd=launch._dir(path)
        try:
            info=os.fstat(fd);require((info.st_dev,info.st_ino)==(expected['device'],expected['inode'])
                and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==expected['mode']==0o700)
            wanted={str(Path(p).relative_to(name)) if name!='.' else p for p in metadata if p!='.' and (name=='.' or Path(p).parent==Path(name))}
            if name=='.':wanted={p.split('/')[0] for p in wanted}
            require(set(os.listdir(fd))==wanted)
        finally:os.close(fd)
    for name,digest in hashes.items():
        launch._sha(digest);expected=metadata[name];path=root/name;fd=launch._dir(path.parent)
        try:
            leaf=launch._file(fd,path.name,os.O_RDONLY)
            try:
                before=os.fstat(leaf);data=os.read(leaf,launch.MAX_BYTES+1);after=os.fstat(leaf);named=os.stat(path.name,dir_fd=fd,follow_symlinks=False)
                identity=lambda st:(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
                require(expected['kind']=='file' and before.st_uid==os.getuid() and before.st_nlink==1
                    and (before.st_dev,before.st_ino,before.st_size,stat.S_IMODE(before.st_mode))==(expected['device'],expected['inode'],expected['size'],expected['mode'])
                    and expected['mode']==0o600 and identity(before)==identity(after)==identity(named)
                    and len(data)<=launch.MAX_BYTES and hashlib.sha256(data).hexdigest()==digest)
            finally:os.close(leaf)
        finally:os.close(fd)


def _terminal_actors(pids,actors):
    """Bind each historical actor to its own positive terminal evidence."""
    require(type(pids) is list and len(pids)==len(set(pids))==85 and type(actors) is list and len(actors)==85
        and {r['pid'] for r in actors}==set(pids))
    for pid in pids:launch._integer(pid,1,2**31-1)
    proofs={}
    for row in actors:
        require(row['basis']=='reviewed_owner_terminal_chain')
        reference=row['evidence'];key=reference['path']
        if key not in proofs:
            proof=_reference(reference);covered=proof['covered_pids']
            require(proof['status']=='PASS' and proof['positive_terminal_chain'] is True and proof['no_unconfirmed_owned_children'] is True
                and type(covered) is list and len(covered)==len(set(covered)) and set(covered)<=set(pids))
            for pid in covered:launch._integer(pid,1,2**31-1)
            proofs[key]=(reference,proof)
        require(proofs[key][0]==reference and row['pid'] in proofs[key][1]['covered_pids'])


def _cleanup(value,full,ledger):
    """Actual015 preworker closure, not the earlier started-worker014 schema."""
    cleanup=_reference(value['prior_cleanup']);review=_reference(value['prior_independent_review']);boundary=_reference(value['prior_boundary_review'])
    require(cleanup['status']==review['status']==boundary['status']=='PASS' and review['unresolved_findings']==boundary['unresolved_findings']==[]
        and review['supports_ac80'] is True and _same_reference(boundary['final_cleanup'],value['prior_cleanup'])
        and cleanup['qualification_id']==full['qualification_id'] and cleanup['cumulative_container_launches']==163 and cleanup['participant_segments']==6
        and cleanup['scripted_participant_segments']==6 and cleanup['real_model_participant_segments']==0 and cleanup['live_owned_containers']==0
        and cleanup['enforced_live_ceiling']==4 and cleanup['current_registry_records_released']==92 and cleanup['known_credential_runtime_actor_count']==85
        and cleanup['raw_product_private_false_rows_preserved']==3 and cleanup['chronological_native_rows']==420
        and cleanup['raw_current_counts']=={'PASS':8,'BLOCKED':1,'NOT_RUN':19}
        and cleanup['chronological_native_counts']=={'PASS':49,'BLOCKED':15,'NOT_RUN':356})
    for key in ('physical_absence_confirmed','private_cleanup_confirmed','master015_copy_removed','safe_for_final_handoff',
        'retained_evidence_key_free','retained_evidence_bytes_unchanged','private_scan_values_RAM_only','raw_poison_and_flags_unchanged'):require(cleanup[key] is True)
    for key in ('safe_to_continue','continued_execution_authorized','qualification_eligible','original_operator_store_touched',
        'historical_numeric_PID_probes','credential_values_or_hashes_retained','master_cleanup_values_opened','master_cleanup_value_hashes_computed'):require(cleanup[key] is False)
    verified=boundary['verified']
    require(verified['containers']==163 and verified['participants']==6 and verified['released_records']==92
        and verified['credential_native_terminal_actors']==85 and verified['bootstrap_paths_freshly_absent']==8
        and verified['native_rows']==420 and verified['previously_keyfree_files_preserved']==5
        and verified['master_store_parent_removal_reviewed'] is True and verified['raw_poison_and3false_preserved'] is True)
    terminal=_relative_reference(cleanup['terminal_hygiene']);terminal_review=_relative_reference(cleanup['terminal_hygiene_review'])
    manual=_relative_reference(cleanup['private_cleanup']);private_review=_relative_reference(cleanup['private_cleanup_review'])
    require(terminal['status']==terminal_review['status']==manual['status']==private_review['status']=='PASS'
        and terminal_review['unresolved_findings']==private_review['unresolved_findings']==[]
        and _same_reference(terminal_review['terminal_hygiene'],cleanup['terminal_hygiene'])
        and _same_reference(private_review['private_cleanup'],cleanup['private_cleanup'])
        and _same_reference(terminal['private_proof'],cleanup['private_cleanup'])
        and _same_reference(terminal['current_ledger'],value['prior_ledger']) and _same_reference(terminal['current_state'],value['prior_state']))
    for proof in (terminal,manual):
        require(proof['cumulative_container_launches']==163 and proof['participant_segments']==6 and proof['master015_cleanup_pending'] is True
            and proof['original_lease_held'] is True and proof['controller_lock_held'] is True)
    for key in ('all_native_writers_absent','all_service_writers_stopped','all_helper_writers_stopped','all_qualification_controllers_stopped',
        'all_issued_capabilities_revoked','owned_networks_removed','all_container_ids_absent','raw_preserved','all_root_readers_stopped','retained_evidence_key_free','lock_inodes_unchanged'):require(terminal[key] is True)
    for key in ('private_cleanup_confirmed','all163_ids_absent','all92_registry_records_released','already_released89_records_unchanged',
        'retained_evidence_key_free','retained_evidence_bytes_unchanged','retained_evidence_keyfree_before_evidence_hashing',
        'retained_evidence_schema_validated_inside_scanner','credential_values_readonly_RAM','all4_values_RAM_matched_and_scanned',
        'raw_history_unchanged','raw_poison_and_flags_unchanged','positive_preworker_helper_cleanup_preserved','all4_metadata_child_waits_confirmed'):require(manual[key] is True)
    require(manual['registry_release_count']==3 and manual['retained_evidence_credential_match_count']==0 and manual['credential_values_or_hashes_retained'] is False
        and manual['raw_product_private_false_rows_preserved']==3 and manual['elapsed_scope']=='program_entry_to_final_proof'
        and 0<=launch._number(manual['elapsed_seconds'])<=30 and manual['qualification_eligible'] is False and manual['safe_to_continue'] is False)
    ids=cleanup['all_owned_container_ids'];require(type(ids) is list and len(ids)==len(set(ids))==163
        and ids==manual['all_owned_container_ids']==terminal['all_owned_container_ids'] and {r['container_id'] for r in ledger['launches']}<=set(ids))
    for identifier in ids:launch._sha(identifier)
    roots,absent=cleanup['selected_private_roots_removed'],cleanup['already_removed_private_roots_verified']
    require(type(roots) is list and len(roots)==len(set(roots))==3 and type(absent) is list and len(absent)==len(set(absent))==5
        and not set(roots)&set(absent) and roots==manual['selected_private_roots_removed']==terminal['removed_private_roots']
        and absent==manual['already_removed_private_roots_verified']==terminal['already_removed_private_roots'])
    for path in roots+absent:require(registry_api._qualification_absent(str(launch._canonical_root(path))))
    pids=terminal['host_pids'];require(type(pids) is list and len(pids)==len(set(pids))==85 and pids==cleanup['known_credential_runtime_actor_ids'])
    for pid in pids:launch._integer(pid,1,2**31-1)
    actors=terminal['host_actor_evidence'];require(len(actors)==85 and {r['pid'] for r in actors}==set(pids)
        and actors==cleanup['actor_terminal_evidence'])
    _terminal_actors(pids,actors)
    events=manual['metadata_child_terminals'];require(len(events)==4 and len({r['pid'] for r in events})==4)
    for index,event in enumerate(events):
        require(event['sequence']==index+1 and event['wait_completed'] is True and event['actual_exit']==(0 if index%2==0 else 1)
            and event['disposition']=='reaped' and event['action_deadline_expired'] is False and event['pid'] in pids)
    command=_relative_reference(cleanup['master_cleanup_command']);observed=command['custody_before_action']
    require(command['status']=='PASS' and type(command['actual_exit']) is int and command['actual_exit']==0
        and command['credential_values_opened'] is False and command['native_launches']==0 and command['automatic_retry_performed'] is False
        and observed['status']=='PASS' and observed['target']==full['secrets_dir'] and observed['cumulative_container_launches']==163
        and observed['participant_segments']==6 and observed['all_known_container_ids_freshly_absent'] is True
        and observed['actual_container_id_count']==163 and observed['private_store_readers']==0
        and observed['historical_numeric_pid_checks_performed'] is False and observed['original_lease_held'] is True and observed['controller_lock_held'] is True
        and _same_reference(observed['terminal_resource_hygiene'],cleanup['terminal_hygiene']))
    refs=observed['current_registry_records'];retained=terminal['current_registry_records'];registry_root=Path.home()/'.local/state/pi-agentic-development/operation.lock.registry'
    require(type(refs) is list and len(refs)==len({r['path'] for r in refs})==92 and len(retained)==92)
    retained_by_id={}
    for ref in retained:
        record=_relative_reference(ref);require(record['status']=='released' and record['launch_id'] not in retained_by_id);retained_by_id[record['launch_id']]=ref['sha256']
    require(retained_by_id=={Path(r['path']).stem:r['sha256'] for r in refs})
    pinned={}
    for ref in refs:
        launch._exact(ref,{'path','sha256'});launch._sha(ref['sha256']);path=Path(ref['path']);require(path.parent==registry_root);launch._uuid(path.stem)
        record=launch._bound_json(ref['path'],ref['sha256']);require(record['status']=='released' and record['launch_id']==path.stem and record['daemon']==ledger['daemon']);pinned[path.stem]=record
    require({r['launch_id'] for r in ledger['launches']}<=set(pinned))
    helpers=[]
    for row in ledger['launches']:
        record=pinned[row['launch_id']];require(launch._intent_identity(record)==row['intent_sha256']
            and all(record[k]==row[k] for k in ('launch_id','registry','generation','image','container')) and record.get('container_id') in (None,row['container_id']))
        if row['role']=='application-helper':helpers.append(record)
    networks=terminal['network_launch_ids'];require(len(networks)==len(set(networks))==5 and len(helpers)==5)
    for helper in helpers:
        matching=[pinned[k] for k in networks if pinned[k]['container']==helper['container']+'-network'];require(len(matching)==1)
        network=matching[0];require(network['kind']=='network' and all(network[k]==helper[k] for k in ('registry','generation','daemon')) and network['runroot'] in (None,helper['runroot']))
    source_review=_relative_reference(private_review['source_review']);require(source_review['status']=='PASS' and source_review['unresolved_findings']==[])
    inputs=_reference(source_review['design_inputs']);require(inputs['master_excluded']==full['secrets_dir'] and inputs['credential_or_bootstrap_values_opened_or_hashed'] is False)
    evidence=cleanup['retained_evidence_file_sha256'];require(len(evidence)==3 and sum(len(v) for v in evidence.values())==5
        and evidence==manual['retained_evidence_file_sha256']==private_review['retained_private_file_sha256']==terminal['retained_evidence'])
    metadata=inputs['retained_private_metadata'];require(set(metadata)==set(evidence))
    for root,hashes in evidence.items():_retained_tree(root,metadata[root],hashes)
    master=_relative_reference(cleanup['master_cleanup']);master_review=_relative_reference(cleanup['master_cleanup_review'])
    require(master['status']=='removed' and master['target']==full['secrets_dir'] and master['store_removed'] is True and master['temporary_parent_removed'] is True
        and master['operator_original_store_selected'] is False and master['values_opened'] is False and master['value_hashes_computed'] is False
        and set(master['removed_references'])=={'PI_API_KEY','QUAL_APPLICATION_ALICE','QUAL_APPLICATION_BOB','QUAL_APPLICATION_SCRIPTED'}
        and master_review['status']=='PASS' and master_review['unresolved_findings']==[] and master_review['master_store_and_parent_freshly_absent'] is True
        and master_review['all92_current_Registry_bodies_released_unchanged'] is True and master_review['known85_credential_native_actor_terminal_scope_preserved'] is True
        and _same_reference(master_review['master_cleanup'],cleanup['master_cleanup']) and master_review['positive_child_wait_exit']==0)
    custody=_reference(master['independent_review']);require(custody['status']=='PASS' and custody['unresolved_findings']==[])
    for key in ('authorization','observation'):require(master[key]==custody[key]);_reference(master[key])
    supervision=_relative_reference(cleanup['master_cleanup_supervision']);require(supervision['status']=='PASS' and supervision['actual_exit']==0 and supervision['wait_completed'] is True)
    require(registry_api._qualification_absent(master['target']) and registry_api._qualification_absent(str(Path(master['target']).parent)))



def validate_amendment(reference, base_predecessor, *, clock=time.monotonic, wall=time.time, window=True):
    value=_authorization(reference)
    prior=prior_amendment.validate_amendment(value['prior_amendment'],base_predecessor,clock=clock,wall=wall,window=False)
    require((prior['attempts'],prior['participant_segments'],prior['planned_cells'],len(prior['lineage']))==(119,2,392,14))
    now,wallnow=launch._number(clock()),launch._number(wall())
    require(now>=STARTED_MONOTONIC and wallnow>=STARTED_WALL and wallnow>=value['recorded_wall'])
    if window:require(now<DEADLINE_MONOTONIC-30 and wallnow<DEADLINE_WALL-30)
    full,state,ledger=(_reference(value['prior_'+key]) for key in ('manifest','state','ledger'))
    require(full['prepared_root']==str(PRIOR_ROOT) and full['document_type']=='application_client_qualification'
        and full['predecessor']==base_predecessor and full['campaign_boundary']==BOUNDARY_REFERENCE and full['campaign_amendment']==PRIOR_AMENDMENT_REFERENCE)
    verifier=object.__new__(launch.LaunchLedger);verifier.root=PRIOR_ROOT/'launch-ledger'
    verifier.manifest=prior_amendment._launch_policy(full,PRIOR_AMENDMENT_REFERENCE)
    verifier.expected_daemon=verifier.expected_capacity=verifier._carry=None;verifier._prevalidated_carry=prior;verifier._validate(ledger)
    require(ledger['poisoned'] is True and len(ledger['launches'])==44 and now>=ledger['last_now'] and wallnow>=ledger['last_wall'])
    rows=ledger['launches'];cells=full['cells'];ordered=[c for c in cells if c['group']=='N02'];active=state['active_cell']
    launch._exact(state,{'schema','phase','active_cell','cells','started_at'});launch._exact(active,{'id','pid','run_id','attempt_id'})
    launch._integer(active['pid'],1,2**31-1)
    for key in ('run_id','attempt_id'):launch._uuid(active[key])
    require(type(state['schema']) is int and state['schema']==1 and state['phase']=='blocked' and state['started_at']==prior['started_wall']
        and active['id']==ordered[4]['id'] and len(state['cells'])==9)
    for cell in cells:
        item=state['cells'].get(cell['id'])
        if cell['group']=='N01':require(item=={'status':'PASS','attempts':1,'evidence_level':'native_infrastructure'})
        elif cell in ordered[:4]:
            launch._exact(item,{'status','attempts','run_id','attempt_id','runner_status','exit_code','interruption_sent'})
            require(item['status']=='PASS' and type(item['attempts']) is int and item['attempts']==1 and item['runner_status']=='FAIL'
                and type(item['exit_code']) is int and item['exit_code']==1 and item['interruption_sent'] is False)
            for key in ('run_id','attempt_id'):launch._uuid(item[key])
        elif cell['id']==active['id']:require(item=={'status':'BLOCKED','attempts':1,'run_id':active['run_id'],'attempt_id':active['attempt_id'],'private_cleanup':'unconfirmed'})
        else:require(item is None)
    require(all(r['physical']=='absent' and r['private_cleanup'] is True for r in rows[:38])
        and [r['role'] for r in rows[38:]]==['fixture','scripted-inference','probe','boundary','preflight','application-helper']
        and all(r['cell']==active['id'] and r['physical']=='absent' and r['private_cleanup'] is (r['role'] not in ('probe','boundary','preflight')) for r in rows[38:])
        and sum(r['role']=='participant' for r in rows)==4 and len({r['container_id'] for r in rows})==44 and all(r['container_id'] is not None for r in rows))
    _cleanup(value,full,ledger)
    old_rows=[{'qualification_id':full['qualification_id'],'cell':cell['id'],'status':state['cells'].get(cell['id'],{}).get('status','NOT_RUN'),
        'attempts':state['cells'].get(cell['id'],{}).get('attempts',0)} for cell in cells]
    require(len(old_rows)==28 and full['qualification_id'] not in {r['qualification_id'] for r in prior['lineage']})
    hashes={key:value['prior_'+key.removesuffix('_sha256')]['sha256'] for key in ('manifest_sha256','state_sha256','ledger_sha256')}
    return {**prior,'attempts':163,'participant_segments':6,'qualification_id':full['qualification_id'],'planned_cells':420,**hashes,
        'started':STARTED_MONOTONIC,'started_wall':STARTED_WALL,'deadline':DEADLINE_MONOTONIC,'deadline_wall':DEADLINE_WALL,
        'lineage':prior['lineage']+[{'root':str(PRIOR_ROOT),'qualification_id':full['qualification_id'],**hashes}],
        'prior_rows':prior['prior_rows']+old_rows,'campaign_amendment':copy.deepcopy(reference),'effective_limits':effective_limits(reference)}

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
    require(full['qualification_id'] not in {entry['qualification_id'] for entry in carry['lineage']})
    launch._exact(candidate,{'archive_sha256','runner_sha256','scope'});launch._sha(candidate['archive_sha256']);launch._sha(candidate['runner_sha256'])
    require(candidate['scope']=='extracted_candidate' and candidate['runner_sha256']==full['source']['runner'])
    _folder();_fence(reference,carry,create=True)
    return campaign.exclusive(BINDING_ROOT/'candidate-binding.json',{'schema':1,'amendment':reference,'qualification_id':full['qualification_id'],
        'full_manifest':full_manifest_reference,'candidate':candidate_reference,'launch_manifest_sha256':launch._digest(policy)})


def bind_final(root,manifest,carry,*,create=False):
    require(launch._canonical_root(str(root))==FINAL_ROOT/'launch-ledger' and len(carry['lineage'])==15 and carry['attempts']==163
        and carry['participant_segments']==6 and carry['campaign_amendment']==manifest['campaign_amendment'])
    reference=manifest['campaign_amendment'];_fence(reference,carry)
    binding=campaign.read(BINDING_ROOT/'candidate-binding.json');launch._exact(binding,{'schema','amendment','qualification_id','full_manifest','candidate','launch_manifest_sha256'})
    full=_reference(binding['full_manifest']);candidate=_reference(binding['candidate'])
    require(type(binding['schema']) is int and binding['schema']==1 and binding['amendment']==reference and binding['qualification_id']==manifest['qualification_id']
        and binding['full_manifest']['path']==str(FINAL_ROOT/'manifest.json') and binding['candidate']['path']==str(FINAL_ROOT/'candidate.json')
        and candidate['scope']=='extracted_candidate' and candidate['runner_sha256']==full['source']['runner']
        and binding['launch_manifest_sha256']==launch._digest(manifest) and launch._json(_launch_policy(full,reference))==launch._json(manifest))
    expected={'schema':1,'document_type':'qualification_matrix_amendment_launch_binding','amendment':reference,'qualification_id':manifest['qualification_id'],
        'manifest_sha256':launch._digest(manifest),'ledger_root':str(root),'cumulative_attempts':163,'participant_segments':6,
        'candidate_binding':campaign.ref(BINDING_ROOT/'candidate-binding.json')}
    if create:campaign.exclusive(BINDING_ROOT/'launch-binding.json',expected)
    require(campaign.read(BINDING_ROOT/'launch-binding.json')==expected)
