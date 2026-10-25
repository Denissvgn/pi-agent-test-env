"""One separately authorized tenth matrix with immutable ninth-matrix custody.

This source-only validator never resets historical ledgers, dispatches a
container, reads credential values, or grants an eleventh matrix. Its pinned
execution authority must include a separately authorized four-hour window.
"""
import copy
import fcntl
import os
from pathlib import Path
import stat
import time

import application_launch as launch
import application_campaign as campaign
import application_amendment as prior_amendment

REPO=Path(__file__).resolve().parents[2]
AUTHORIZATION_PATH=REPO/'reports/application-agent-enhancements/A15/campaign-003/matrix-010-execution-authorization.json'
# Exact combined authority records separate human matrix and window grants.
AUTHORIZATION_SHA256='b548df9507118531a8e6901d3cad065c7c1347ffb63c0b52ba8a4cfec0f4d406'
AUTHORIZATION_ID='42f69b66-9201-4d94-b0d2-b2658aa0d88e'
MATRIX_AUTHORIZATION={'path':str(REPO/'reports/application-agent-enhancements/A15/campaign-003/matrix-010-authorization.json'),'sha256':'82e3bd93e6ff4e52f451bd0295f28afc449b869d198f758d2ebb25266e731ce3'}
WINDOW_AUTHORIZATION={'path':str(REPO/'reports/application-agent-enhancements/A15/campaign-window-003-authorization.json'),'sha256':'41cc6139ee6797993184d8607b39de38b1d9c01b8de4c42f2ab768d838911434'}
PRIOR_ROOT=REPO/'reports/application-agent-enhancements/A15/attempt-009/qualification'
FINAL_ROOT=REPO/'reports/application-agent-enhancements/A15/attempt-010/qualification'
BINDING_ROOT=AUTHORIZATION_PATH.parent/'matrix-010-successor'
BOUNDARY_REFERENCE=copy.deepcopy(prior_amendment.BOUNDARY_REFERENCE)
PRIOR_AMENDMENT_REFERENCE={'path':str(prior_amendment.AUTHORIZATION_PATH),'sha256':prior_amendment.AUTHORIZATION_SHA256}
STARTED_WALL=1792309648.4343522
STARTED_MONOTONIC=590056.609015083
DEADLINE_WALL=1792324048.4343522
DEADLINE_MONOTONIC=604456.609015083


def require(value):
    if not value:raise launch.LaunchError('qualification_matrix_successor_invalid')


_reference=prior_amendment._reference
_relative_reference=prior_amendment._relative_reference


def _authorization(reference):
    require(reference=={'path':str(AUTHORIZATION_PATH),'sha256':AUTHORIZATION_SHA256})
    value=_reference(reference)
    fields={'schema','document_type','authorization_id','human_authorization','recorded_wall','final_root',
        'maximum_matrix_origins','prior_matrix_origins','cumulative_container_launches','cumulative_participant_segments',
        'previous_container_cap','container_cap','participant_cap','live_cap','trial_cap','inference_slot_cap','platform',
        'automatic_retries','continuations','planned_new_container_launches','planned_new_participant_segments',
        'matrix_authorization','window_authorization','started_wall','started_monotonic','deadline_wall','deadline_monotonic',
        'prior_amendment','original_boundary','prior_manifest','prior_state','prior_ledger','prior_cleanup',
        'prior_independent_review','prior_terminal_proof','prior_boundary_review','original_evidence_modified','window_reset','additional_auxiliary_launches_authorized'}
    launch._exact(value,fields)
    fixed={'schema':1,'document_type':'qualification_matrix_successor_authorization','authorization_id':AUTHORIZATION_ID,
        'final_root':str(FINAL_ROOT),'maximum_matrix_origins':10,'prior_matrix_origins':9,'cumulative_container_launches':63,
        'cumulative_participant_segments':0,'previous_container_cap':241,'container_cap':249,'participant_cap':24,'live_cap':4,
        'trial_cap':1,'inference_slot_cap':1,'platform':'linux/arm64','automatic_retries':0,'continuations':0,
        'planned_new_container_launches':186,'planned_new_participant_segments':24,'started_wall':STARTED_WALL,
        'started_monotonic':STARTED_MONOTONIC,'deadline_wall':DEADLINE_WALL,'deadline_monotonic':DEADLINE_MONOTONIC,
        'original_evidence_modified':False,'window_reset':False,'additional_auxiliary_launches_authorized':0}
    for key,expected in fixed.items():require(type(value[key]) is type(expected) and value[key]==expected)
    for key in ('started_wall','started_monotonic','deadline_wall','deadline_monotonic','recorded_wall'):launch._number(value[key])
    require(DEADLINE_WALL==STARTED_WALL+14400 and DEADLINE_MONOTONIC==STARTED_MONOTONIC+14400
        and STARTED_WALL<=value['recorded_wall']<DEADLINE_WALL and STARTED_WALL>=prior_amendment.DEADLINE_WALL)
    require(type(value['human_authorization']) is str and 1<=len(value['human_authorization'])<=4096)
    require(value['matrix_authorization']==MATRIX_AUTHORIZATION and value['window_authorization']==WINDOW_AUTHORIZATION
        and value['prior_amendment']==PRIOR_AMENDMENT_REFERENCE and value['original_boundary']==BOUNDARY_REFERENCE)
    matrix=_reference(value['matrix_authorization']);window=_reference(value['window_authorization'])
    # Their complete bytes are separately pinned, including the human quote.
    launch._number(matrix['recorded_wall']);require(matrix['recorded_wall']<=STARTED_WALL)
    require(matrix['container_cap']==249 and matrix['maximum_matrix_origins']==10 and matrix['prior_matrix_origins']==9
        and matrix['cumulative_container_launches']==63 and matrix['cumulative_participant_segments']==0)
    require(window['document_type']=='qualification_window_authorization' and window['window_seconds']==14400
        and window['original_deadline_wall']==prior_amendment.DEADLINE_WALL
        and window['cumulative_container_launches']==63 and window['cumulative_participant_segments']==0
        and window['container_cap']==249 and window['participant_cap']==24 and window['live_cap']==4
        and window['trial_cap']==1 and window['inference_slot_cap']==1 and window['platform']=='linux/arm64'
        and type(window['automatic_retries']) is int and window['automatic_retries']==0
        and type(window['continuations']) is int and window['continuations']==0
        and window['prior_campaign_modified'] is False and window['new_native_admission_requires_positive_owned_cleanup'] is True
        and window['started_wall']==STARTED_WALL and window['started_monotonic']==STARTED_MONOTONIC
        and window['deadline_wall']==DEADLINE_WALL and window['deadline_monotonic']==DEADLINE_MONOTONIC)
    require(type(matrix['human_authorization']) is str and 1<=len(matrix['human_authorization'])<=4096
        and type(window['authorization']) is str and 1<=len(window['authorization'])<=4096)
    for key in ('prior_amendment','original_boundary','prior_manifest','prior_state','prior_ledger','prior_cleanup','prior_independent_review'):
        require(value[key]==matrix[key])
    require(matrix['final_root']==str(FINAL_ROOT) and matrix['native_window_authorized'] is False
        and matrix['requires_separate_window_authorization'] is True and matrix['original_evidence_modified'] is False
        and type(matrix['additional_auxiliary_launches_authorized']) is int and matrix['additional_auxiliary_launches_authorized']==0)
    for key,relative in (('prior_manifest','manifest.json'),('prior_state','state.json'),('prior_ledger','launch-ledger/ledger.json')):
        launch._exact(value[key],{'path','sha256'});require(value[key]['path']==str(PRIOR_ROOT/relative));launch._sha(value[key]['sha256'])
    return value


def effective_limits(reference):
    _authorization(reference)
    return {**launch.LIMITS,'container_launch_attempts':249}


def validate_amendment(reference,base_predecessor,*,clock=time.monotonic,wall=time.time,window=True):
    value=_authorization(reference)
    prior=prior_amendment.validate_amendment(value['prior_amendment'],base_predecessor,clock=clock,wall=wall,window=False)
    require(prior['attempts']==55 and prior['participant_segments']==0 and prior['planned_cells']==224 and len(prior['lineage'])==8)
    now,wallnow=launch._number(clock()),launch._number(wall())
    require(now>=STARTED_MONOTONIC and wallnow>=STARTED_WALL)
    if window:require(now<DEADLINE_MONOTONIC-30 and wallnow<DEADLINE_WALL-30)
    full=_reference(value['prior_manifest']);state=_reference(value['prior_state']);ledger=_reference(value['prior_ledger'])
    require(full['prepared_root']==str(PRIOR_ROOT) and full['document_type']=='application_client_qualification'
        and full['predecessor']==base_predecessor and full['campaign_boundary']==BOUNDARY_REFERENCE and full['campaign_amendment']==PRIOR_AMENDMENT_REFERENCE)
    policy=prior_amendment._launch_policy(full,PRIOR_AMENDMENT_REFERENCE)
    verifier=object.__new__(launch.LaunchLedger);verifier.root=PRIOR_ROOT/'launch-ledger';verifier.manifest=policy
    verifier.expected_daemon=None;verifier.expected_capacity=None;verifier._carry=None;verifier._prevalidated_carry=prior;verifier._validate(ledger)
    require(ledger['poisoned'] is True and len(ledger['launches'])==8 and now>=ledger['last_now'] and wallnow>=ledger['last_wall'])
    rows=ledger['launches'];cells=full['cells'];active=state['active_cell'];first_negative=next(c for c in cells if c['group']=='N02')
    launch._exact(state,{'schema','phase','active_cell','cells','started_at'})
    require(type(state['schema']) is int and state['schema']==1 and state['phase']=='blocked' and state['started_at']==prior['started_wall'])
    launch._exact(active,{'id','pid','run_id','attempt_id'});launch._integer(active['pid'],1,2**31-1)
    for key in ('run_id','attempt_id'):launch._uuid(active[key])
    require(active['id']==first_negative['id'] and len(state['cells'])==5)
    for cell in cells:
        item=state['cells'].get(cell['id'])
        if cell['group']=='N01':require(item=={'status':'PASS','attempts':1,'evidence_level':'native_infrastructure'})
        elif cell['id']==active['id']:
            require(item=={'status':'BLOCKED','attempts':1,'run_id':active['run_id'],'attempt_id':active['attempt_id'],'private_cleanup':'unconfirmed'})
        else:require(item is None)
    require({role:sum(r['role']==role for r in rows) for role in ('probe','browser-check','fixture','scripted-inference')}==
        {'probe':4,'browser-check':2,'fixture':1,'scripted-inference':1})
    ids=[r['container_id'] for r in rows];require(None not in ids and len(set(ids))==8)
    for identifier in ids:launch._sha(identifier)
    ordinary=[r for r in rows if r['role'] in ('probe','browser-check')]
    services=[r for r in rows if r['role'] in ('fixture','scripted-inference')]
    require(all(r['physical']=='absent' and r['private_cleanup'] is True for r in ordinary)
        and all(r['private_cleanup'] is False and r['cell']==active['id'] for r in services)
        and next(r for r in services if r['role']=='fixture')['physical']=='uncertain'
        and next(r for r in services if r['role']=='scripted-inference')['physical']=='absent')
    cleanup=_reference(value['prior_cleanup']);review=_reference(value['prior_independent_review'])
    boundary_review=_reference(value['prior_boundary_review'])
    require(boundary_review['status']=='PASS' and boundary_review['unresolved_findings']==[])
    require(cleanup['status']=='PASS' and cleanup['qualification_id']==full['qualification_id'] and cleanup['safe_to_continue'] is False
        and cleanup['safe_for_final_handoff'] is True and cleanup['continued_execution_authorized'] is False
        and cleanup['cumulative_container_launches']==63 and cleanup['participant_segments']==0 and cleanup['live_owned_containers']==0
        and cleanup['enforced_live_ceiling']==4 and cleanup['original_operator_store_touched'] is False
        and review['status']=='PASS' and review['unresolved_findings']==[])
    for key in ('physical_absence_confirmed','private_cleanup_confirmed','master009_copy_removed','raw_history_poison_and_pending_flags_preserved'):require(cleanup[key] is True)
    terminal=_relative_reference(cleanup['service_and_parent_cleanup']);master=_relative_reference(cleanup['master_cleanup'])
    custody=_relative_reference(cleanup['independent_actual_custody'])
    require(_reference(value['prior_terminal_proof'])==terminal)
    require(terminal['status']=='PASS' and terminal['cumulative_container_launches']==63 and terminal['participant_segments']==0
        and terminal['all63_ids_absent'] is True and terminal['parent_envelope_removed'] is True and terminal['service_private_roots_removed'] is True
        and terminal['all4_values_RAM_matched_and_scanned'] is True and terminal['raw_history_unchanged'] is True
        and terminal['raw_poison_unchanged'] is True and terminal['raw_private_flags_unchanged'] is True
        and terminal['controller_lock_held'] is True and terminal['original_lease_held'] is True
        and terminal['safe_to_continue'] is False and terminal['original_operator_store_touched'] is False)
    allids=terminal['all_owned_container_ids'];require(type(allids) is list and len(allids)==63 and len(set(allids))==63 and set(ids)<=set(allids))
    for identifier in allids:launch._sha(identifier)
    require(active['pid'] in terminal['writer_pids_absent'])
    parent=_reference(terminal['parent_terminal'])
    require(parent['actual_exit']==2 and type(parent['actual_exit']) is int and parent['cwd']==str(REPO)
        and parent['argv']==['python3','tools/qualification/application_client.py','collect','--root',str(PRIOR_ROOT),'--group','N02','--release','0.87.1'])
    receipts=[_reference(ref) for ref in terminal['service_cleanup_receipts']];require(len(receipts)==2)
    require({r['launch_id'] for r in receipts}=={r['launch_id'] for r in services})
    for receipt in receipts:
        row=next(row for row in services if row['launch_id']==receipt['launch_id'])
        require(receipt['document_type']=='qualification_service_cleanup' and receipt['physical_absence_confirmed'] is True
            and receipt['private_bootstrap_removed'] is True and receipt['qualification_eligible'] is False and receipt['terminal_available'] is False
            and receipt['intent_sha256']==row['intent_sha256'] and receipt['container_id']==row['container_id']
            and all(receipt[k]==row[k] for k in ('launch_id','registry','generation','image','container','role','cell'))
            and receipt['daemon']==ledger['daemon'])
    require(master['status']=='removed' and master['store_removed'] is True and master['temporary_parent_removed'] is True
        and master['operator_original_store_selected'] is False and master['values_opened'] is False and master['value_hashes_computed'] is False
        and set(master['removed_references'])=={'PI_API_KEY','QUAL_APPLICATION_ALICE','QUAL_APPLICATION_BOB','QUAL_APPLICATION_SCRIPTED'}
        and custody['status']=='PASS' and custody['unresolved_findings']==[] and _relative_reference(master['independent_review'])==custody)
    for key in ('authorization','observation'):
        require(master[key]==custody[key]);_reference(master[key])
    require(master['program_sha256']==custody['program_sha256'])
    prior_rows=[{'qualification_id':full['qualification_id'],'cell':cell['id'],'status':state['cells'].get(cell['id'],{}).get('status','NOT_RUN'),
        'attempts':state['cells'].get(cell['id'],{}).get('attempts',0)} for cell in cells]
    require(len(prior_rows)==28 and full['qualification_id'] not in {entry['qualification_id'] for entry in prior['lineage']})
    return {**prior,'attempts':63,'participant_segments':0,'qualification_id':full['qualification_id'],'planned_cells':252,
        'started':STARTED_MONOTONIC,'deadline':DEADLINE_MONOTONIC,'started_wall':STARTED_WALL,'deadline_wall':DEADLINE_WALL,
        'previous_window':{key:prior[key] for key in ('started','deadline','started_wall','deadline_wall')},
        **{key:value['prior_'+key.removesuffix('_sha256')]['sha256'] for key in ('manifest_sha256','state_sha256','ledger_sha256')},
        'lineage':prior['lineage']+[{'root':str(PRIOR_ROOT),'qualification_id':full['qualification_id'],
            **{key:value['prior_'+key.removesuffix('_sha256')]['sha256'] for key in ('manifest_sha256','state_sha256','ledger_sha256')}}],
        'prior_rows':prior['prior_rows']+prior_rows,'campaign_amendment':copy.deepcopy(reference),'effective_limits':effective_limits(reference)}

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
    require(launch._canonical_root(str(root))==FINAL_ROOT/'launch-ledger' and len(carry['lineage'])==9 and carry['attempts']==63
        and carry['participant_segments']==0 and carry['campaign_amendment']==manifest['campaign_amendment'])
    reference=manifest['campaign_amendment'];_fence(reference,carry)
    binding=campaign.read(BINDING_ROOT/'candidate-binding.json');launch._exact(binding,{'schema','amendment','qualification_id','full_manifest','candidate','launch_manifest_sha256'})
    full=_reference(binding['full_manifest']);candidate=_reference(binding['candidate'])
    require(type(binding['schema']) is int and binding['schema']==1 and binding['amendment']==reference and binding['qualification_id']==manifest['qualification_id']
        and binding['full_manifest']['path']==str(FINAL_ROOT/'manifest.json') and binding['candidate']['path']==str(FINAL_ROOT/'candidate.json')
        and candidate['scope']=='extracted_candidate' and candidate['runner_sha256']==full['source']['runner']
        and binding['launch_manifest_sha256']==launch._digest(manifest) and launch._json(_launch_policy(full,reference))==launch._json(manifest))
    expected={'schema':1,'document_type':'qualification_matrix_amendment_launch_binding','amendment':reference,'qualification_id':manifest['qualification_id'],
        'manifest_sha256':launch._digest(manifest),'ledger_root':str(root),'cumulative_attempts':63,'participant_segments':0,
        'candidate_binding':campaign.ref(BINDING_ROOT/'candidate-binding.json')}
    if create:campaign.exclusive(BINDING_ROOT/'launch-binding.json',expected)
    require(campaign.read(BINDING_ROOT/'launch-binding.json')==expected)
