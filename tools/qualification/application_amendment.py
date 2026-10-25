"""One explicit ninth-matrix amendment; historical limits remain unchanged.

The pinned human authorization changes only the final root and cumulative
container ceiling. It grants no auxiliary launch, retry, new window or tenth
origin. This maintainer module reads retained custody proofs, never Docker,
credential values or mutable historical ledgers.
"""
import copy
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import time

import application_launch as launch
import application_campaign as campaign

REPO=Path(__file__).resolve().parents[2]
AUTHORIZATION_PATH=REPO/'reports/application-agent-enhancements/A15/campaign-002/matrix-009-authorization.json'
AUTHORIZATION_SHA256='5c8576c3672968d5b429b52a4bfb26039b9eab2394f87d1e6d73f5f611807b92'
AUTHORIZATION_ID='e8a970b1-3e9e-4a52-a292-d0fdca25537e'
PRIOR_ROOT=REPO/'reports/application-agent-enhancements/A15/attempt-008/qualification'
FINAL_ROOT=REPO/'reports/application-agent-enhancements/A15/attempt-009/qualification'
BINDING_ROOT=AUTHORIZATION_PATH.parent/'matrix-009-amendment'
BOUNDARY_REFERENCE={'path':str(campaign.AUXILIARY_ROOT/'boundary.json'),'sha256':'a5512d47f9b4428144b5a47205cb999c69b0f9c893dc5c03ac19acddfcfb1f3b'}
DEADLINE_WALL=1792283647.187074
DEADLINE_MONOTONIC=564055.688387708


def require(value):
    if not value:raise launch.LaunchError('qualification_matrix_amendment_invalid')


def _reference(value):
    """Pinned public historical metadata may be0644; it is never made private."""
    launch._exact(value,{'path','sha256'});launch._sha(value['sha256']);path=launch._canonical_root(value['path'])
    parent=launch._dir(path.parent,False);fd=None
    try:
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==os.getuid() and before.st_nlink==1
            and not stat.S_IMODE(before.st_mode)&0o022 and before.st_size<=launch.MAX_BYTES)
        with os.fdopen(fd,'rb') as stream:
            fd=None;body=stream.read(launch.MAX_BYTES+1);after=os.fstat(stream.fileno())
        named=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        identity=lambda st:(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
        require(identity(before)==identity(after)==identity(named) and len(body)<=launch.MAX_BYTES and hashlib.sha256(body).hexdigest()==value['sha256'])
        def pairs(items):
            result={}
            for key,item in items:require(key not in result);result[key]=item
            return result
        def finite_float(raw):
            number=float(raw);require(math.isfinite(number));return number
        return json.loads(body,object_pairs_hook=pairs,parse_float=finite_float,parse_constant=lambda _:require(False))
    finally:
        if fd is not None:os.close(fd)
        os.close(parent)


def _authorization(reference):
    require(reference=={'path':str(AUTHORIZATION_PATH),'sha256':AUTHORIZATION_SHA256})
    value=_reference(reference)
    launch._exact(value,{'schema','document_type','authorization_id','human_authorization','recorded_wall','final_root',
        'maximum_matrix_origins','prior_matrix_origins','cumulative_container_launches','cumulative_participant_segments',
        'previous_container_cap','container_cap','participant_cap','live_cap','trial_cap','inference_slot_cap','platform',
        'automatic_retries','continuations','planned_new_container_launches','planned_new_participant_segments','window_authorization',
        'deadline_wall','deadline_monotonic','original_boundary','prior_manifest','prior_state','prior_ledger','prior_cleanup',
        'prior_terminal_proof','prior_independent_review','original_evidence_modified','window_reset','additional_auxiliary_launches_authorized'})
    fixed={'schema':1,'document_type':'qualification_matrix_amendment_authorization','authorization_id':AUTHORIZATION_ID,
        'final_root':str(FINAL_ROOT),'maximum_matrix_origins':9,'prior_matrix_origins':8,'cumulative_container_launches':55,
        'cumulative_participant_segments':0,'previous_container_cap':240,'container_cap':241,'participant_cap':24,'live_cap':4,
        'trial_cap':1,'inference_slot_cap':1,'platform':'linux/arm64','automatic_retries':0,'continuations':0,
        'planned_new_container_launches':186,'planned_new_participant_segments':24,'deadline_wall':DEADLINE_WALL,
        'deadline_monotonic':DEADLINE_MONOTONIC,'original_evidence_modified':False,'window_reset':False,'additional_auxiliary_launches_authorized':0}
    for key,expected in fixed.items():require(type(value[key]) is type(expected) and value[key]==expected)
    require(type(value['human_authorization']) is str and 1<=len(value['human_authorization'])<=4096)
    launch._number(value['recorded_wall']);require(value['recorded_wall']<DEADLINE_WALL)
    require(value['window_authorization']=={'path':str(campaign.AUTHORIZATION_PATH),'sha256':campaign.AUTHORIZATION_SHA256}
        and value['original_boundary']==BOUNDARY_REFERENCE)
    for key,relative in (('prior_manifest','manifest.json'),('prior_state','state.json'),('prior_ledger','launch-ledger/ledger.json')):
        launch._exact(value[key],{'path','sha256'});require(value[key]['path']==str(PRIOR_ROOT/relative));launch._sha(value[key]['sha256'])
    return value


def effective_limits(reference):
    _authorization(reference)
    return {**launch.LIMITS,'container_launch_attempts':241}


def _relative_reference(value):
    """Some historical final receipts retain repository-relative public refs."""
    launch._exact(value,{'path','sha256'});path=value['path']
    require(type(path) is str and '..' not in Path(path).parts)
    if not Path(path).is_absolute():path=str(REPO/path)
    return _reference({'path':path,'sha256':value['sha256']})


def validate_amendment(reference,base_predecessor,*,clock=time.monotonic,wall=time.time,window=True):
    value=_authorization(reference)
    prior=campaign.validate_boundary(value['original_boundary'],base_predecessor,clock=clock,wall=wall,window=window)
    require(prior['attempts']==54 and prior['participant_segments']==0 and prior['planned_cells']==196 and len(prior['lineage'])==7
        and prior['deadline_wall']==DEADLINE_WALL and prior['deadline']==DEADLINE_MONOTONIC)
    now,wallnow=launch._number(clock()),launch._number(wall());require(wallnow>=value['recorded_wall'])
    full=_reference(value['prior_manifest']);state=_reference(value['prior_state']);ledger=_reference(value['prior_ledger'])
    require(full['prepared_root']==str(PRIOR_ROOT) and full['document_type']=='application_client_qualification'
        and full['predecessor']==base_predecessor and full['campaign_boundary']==value['original_boundary'] and 'campaign_amendment' not in full)
    policy=campaign._launch_policy(full)
    verifier=object.__new__(launch.LaunchLedger);verifier.root=PRIOR_ROOT/'launch-ledger';verifier.manifest=policy
    verifier.expected_daemon=None;verifier.expected_capacity=None;verifier._carry=None;verifier._prevalidated_carry=prior
    verifier._validate(ledger)
    require(ledger['poisoned'] is True and len(ledger['launches'])==1 and now>=ledger['last_now'] and wallnow>=ledger['last_wall'])
    row=ledger['launches'][0];first=full['cells'][0]
    require(first['group']=='N01' and row['role']=='probe' and row['cell']==first['id'] and row['physical']=='absent'
        and row['private_cleanup'] is False and row['container_id'] is not None)
    launch._exact(state,{'schema','phase','active_cell','cells','started_at'})
    require(type(state['schema']) is int and state['schema']==1 and state['phase']=='blocked' and state['active_cell'] is None
        and set(state['cells'])=={first['id']} and state['cells'][first['id']]['status']=='BLOCKED'
        and type(state['cells'][first['id']]['attempts']) is int and state['cells'][first['id']]['attempts']==1)
    cleanup=_reference(value['prior_cleanup']);terminal=_reference(value['prior_terminal_proof']);review=_reference(value['prior_independent_review'])
    require(cleanup['status']=='PASS' and cleanup['qualification_id']==full['qualification_id'] and cleanup['safe_to_continue'] is False
        and cleanup['safe_for_final_handoff'] is True and cleanup['cumulative_container_launches']==55 and cleanup['participant_segments']==0
        and cleanup['live_owned_containers']==0 and cleanup['enforced_live_ceiling']==4 and cleanup['continued_execution_authorized'] is False)
    for key in ('physical_absence_confirmed','private_cleanup_confirmed','all_issued_validating_processes_gone','all_master_copy_readers_stopped',
                'master006_copy_removed','raw_poison_and_matrix_preserved'):require(cleanup[key] is True)
    require(cleanup['original_operator_store_touched'] is False and _relative_reference(cleanup['terminal_observation'])==terminal)
    master=_relative_reference(cleanup['master_cleanup']);custody=_relative_reference(cleanup['independent_actual_custody'])
    require(master['status']=='removed' and master['store_removed'] is True and master['temporary_parent_removed'] is True
        and master['operator_original_store_selected'] is False and master['values_opened'] is False and master['value_hashes_computed'] is False
        and custody['status']=='PASS' and custody['unresolved_findings']==[] and review['status']=='PASS' and review['unresolved_findings']==[])
    require(terminal['status']=='PASS' and terminal['qualification_id']==full['qualification_id'] and terminal['cumulative_container_launches']==55
        and terminal['cumulative_participant_segments']==0 and terminal['current_launches']==1 and terminal['historical_launches']==51
        and terminal['auxiliary_launches']==3 and terminal['all_owned_ids_absent'] is True and terminal['live_owned_containers']==0
        and terminal['daemon_id']==ledger['daemon'] and terminal['current_registry_status']=='released' and terminal['raw_ledger_poison_preserved'] is True
        and terminal['raw_ledger_private_cleanup_flag_preserved'] is False and terminal['ledger']==value['prior_ledger'] and terminal['state']==value['prior_state']
        and terminal['boundary']==value['original_boundary'])
    ids=terminal['all_owned_container_ids'];require(type(ids) is list and len(ids)==55 and len(set(ids))==55 and row['container_id'] in ids)
    for identifier in ids:launch._sha(identifier)
    released=_reference(terminal['released_record']);original=_reference(terminal['original_record'])
    require(released['status']=='released' and original['status']=='absent' and launch._intent_identity(original)==row['intent_sha256']
        and launch._intent_identity(released)==row['intent_sha256'] and released['launch_id']==row['launch_id']
        and released['generation']==row['generation'] and released['registry']==row['registry'] and released['daemon']==ledger['daemon'])
    rows=[{'qualification_id':full['qualification_id'],'cell':cell['id'],'status':'BLOCKED' if index==0 else 'NOT_RUN','attempts':1 if index==0 else 0}
          for index,cell in enumerate(full['cells'])]
    require(len(rows)==28 and full['qualification_id'] not in {entry['qualification_id'] for entry in prior['lineage']})
    return {**prior,'attempts':55,'qualification_id':full['qualification_id'],'planned_cells':224,
        **{key:value['prior_'+key.removesuffix('_sha256')]['sha256'] for key in ('manifest_sha256','state_sha256','ledger_sha256')},
        'lineage':prior['lineage']+[{'root':str(PRIOR_ROOT),'qualification_id':full['qualification_id'],
            **{key:value['prior_'+key.removesuffix('_sha256')]['sha256'] for key in ('manifest_sha256','state_sha256','ledger_sha256')}}],
        'prior_rows':prior['prior_rows']+rows,'campaign_amendment':copy.deepcopy(reference),'effective_limits':effective_limits(reference)}


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
    require(launch._canonical_root(str(root))==FINAL_ROOT/'launch-ledger' and len(carry['lineage'])==8 and carry['attempts']==55
        and carry['participant_segments']==0 and carry['campaign_amendment']==manifest['campaign_amendment'])
    reference=manifest['campaign_amendment'];_fence(reference,carry)
    binding=campaign.read(BINDING_ROOT/'candidate-binding.json');launch._exact(binding,{'schema','amendment','qualification_id','full_manifest','candidate','launch_manifest_sha256'})
    full=_reference(binding['full_manifest']);candidate=_reference(binding['candidate'])
    require(type(binding['schema']) is int and binding['schema']==1 and binding['amendment']==reference and binding['qualification_id']==manifest['qualification_id']
        and binding['full_manifest']['path']==str(FINAL_ROOT/'manifest.json') and binding['candidate']['path']==str(FINAL_ROOT/'candidate.json')
        and candidate['scope']=='extracted_candidate' and candidate['runner_sha256']==full['source']['runner']
        and binding['launch_manifest_sha256']==launch._digest(manifest) and launch._json(_launch_policy(full,reference))==launch._json(manifest))
    expected={'schema':1,'document_type':'qualification_matrix_amendment_launch_binding','amendment':reference,'qualification_id':manifest['qualification_id'],
        'manifest_sha256':launch._digest(manifest),'ledger_root':str(root),'cumulative_attempts':55,'participant_segments':0,
        'candidate_binding':campaign.ref(BINDING_ROOT/'candidate-binding.json')}
    if create:campaign.exclusive(BINDING_ROOT/'launch-binding.json',expected)
    require(campaign.read(BINDING_ROOT/'launch-binding.json')==expected)
