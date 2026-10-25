"""One explicit startup diagnostic and an eleventh matrix, no implicit retry.

This maintainer-only module validates immutable authority and retained custody.
It dispatches no process/container and reads no credential values. The one
synthetic diagnostic is charged centrally and adds no native participant row.
"""
import copy
import fcntl
import os
from pathlib import Path
import stat
import time
import uuid

import application_launch as launch
import application_campaign as campaign
import application_amendment as original_amendment
import application_successor as prior_successor
import ownership_registry as registry_api

REPO=Path(__file__).resolve().parents[2]
AUTHORIZATION_PATH=REPO/'reports/application-agent-enhancements/A15/campaign-004/diagnostic-and-matrix-011-authorization.json'
AUTHORIZATION_SHA256='e656b42a94f76729e2f055b341b50d975bb338baa5219085c49b0faeed9a4320'
AUTHORIZATION_ID='e8bb8dd3-19c3-45fd-8200-5b628695a0a5'
PRIOR_ROOT=REPO/'reports/application-agent-enhancements/A15/attempt-010/qualification'
FINAL_ROOT=REPO/'reports/application-agent-enhancements/A15/attempt-011/qualification'
DIAGNOSTIC_ROOT=AUTHORIZATION_PATH.parent/'startup-diagnostic-001'
DIAGNOSTIC_CELL='D01-0.87.1-application-startup'
BINDING_ROOT=AUTHORIZATION_PATH.parent/'matrix-011-successor'
DIAGNOSTIC_BINDING_ROOT=AUTHORIZATION_PATH.parent/'startup-diagnostic-claim'
BOUNDARY_REFERENCE=copy.deepcopy(prior_successor.BOUNDARY_REFERENCE)
PRIOR_AUTHORITY={'path':str(prior_successor.AUTHORIZATION_PATH),'sha256':prior_successor.AUTHORIZATION_SHA256}
WINDOW_AUTHORITY=copy.deepcopy(prior_successor.WINDOW_AUTHORIZATION)
DIAGNOSTIC_IMAGE='sha256:47856fc949cc114980b4befa37bf6ae17711e84b56be2fb5370fe66e1d216102'
_reference=original_amendment._reference
_relative_reference=original_amendment._relative_reference


def require(value):
    if not value:raise launch.LaunchError('qualification_followup_invalid')


def _authorization(reference):
    require(reference=={'path':str(AUTHORIZATION_PATH),'sha256':AUTHORIZATION_SHA256})
    value=_reference(reference)
    launch._exact(value,{'schema','document_type','authorization_id','human_authorization','recorded_wall','prior_matrix_origins','maximum_matrix_origins',
        'cumulative_container_launches','cumulative_participant_segments','previous_container_cap','container_cap','diagnostic_max_container_launches',
        'diagnostic_max_participant_segments','diagnostic_max_seconds','diagnostic_cleanup_seconds','diagnostic_root','final_root','planned_matrix_container_ceiling',
        'planned_matrix_participant_segments','participant_cap','live_cap','trial_cap','inference_slot_cap','platform','automatic_retries','continuations',
        'additional_auxiliary_launches_authorized','twelfth_origin_authorized','window_authorization','deadline_wall','deadline_monotonic',
        'prior_execution_authorization','original_boundary','prior_manifest','prior_state','prior_ledger','prior_cleanup','prior_independent_review',
        'prior_boundary_review','original_evidence_modified','window_reset','diagnostic_uses_real_inference_or_application_credentials'})
    fixed={'schema':1,'document_type':'qualification_diagnostic_and_matrix_authorization','authorization_id':AUTHORIZATION_ID,'prior_matrix_origins':10,
        'maximum_matrix_origins':11,'cumulative_container_launches':75,'cumulative_participant_segments':0,'previous_container_cap':249,'container_cap':262,
        'diagnostic_max_container_launches':1,'diagnostic_max_participant_segments':0,'diagnostic_max_seconds':120,'diagnostic_cleanup_seconds':30,
        'diagnostic_root':str(DIAGNOSTIC_ROOT),'final_root':str(FINAL_ROOT),'planned_matrix_container_ceiling':186,'planned_matrix_participant_segments':24,
        'participant_cap':24,'live_cap':4,'trial_cap':1,'inference_slot_cap':1,'platform':'linux/arm64','automatic_retries':0,'continuations':0,
        'additional_auxiliary_launches_authorized':0,'twelfth_origin_authorized':False,'deadline_wall':prior_successor.DEADLINE_WALL,
        'deadline_monotonic':prior_successor.DEADLINE_MONOTONIC,'original_evidence_modified':False,'window_reset':False,
        'diagnostic_uses_real_inference_or_application_credentials':False}
    for key,expected in fixed.items():require(type(value[key]) is type(expected) and value[key]==expected)
    launch._number(value['recorded_wall']);require(prior_successor.STARTED_WALL<=value['recorded_wall']<value['deadline_wall'])
    require(type(value['human_authorization']) is str and 1<=len(value['human_authorization'])<=4096 and value['window_authorization']==WINDOW_AUTHORITY
        and value['prior_execution_authorization']==PRIOR_AUTHORITY and value['original_boundary']==BOUNDARY_REFERENCE)
    window=_reference(value['window_authorization']);require(window['deadline_wall']==value['deadline_wall'] and window['deadline_monotonic']==value['deadline_monotonic'])
    for key,relative in (('prior_manifest','manifest.json'),('prior_state','state.json'),('prior_ledger','launch-ledger/ledger.json')):
        require(value[key]['path']==str(PRIOR_ROOT/relative));launch._sha(value[key]['sha256'])
    return value


def effective_limits(reference):
    _authorization(reference)
    return {**launch.LIMITS,'container_launch_attempts':262}


def _current_carry(reference,base_predecessor,*,clock=time.monotonic,wall=time.time,window=True):
    value=_authorization(reference)
    prior=prior_successor.validate_amendment(value['prior_execution_authorization'],base_predecessor,clock=clock,wall=wall,window=False)
    require((prior['attempts'],prior['participant_segments'],prior['planned_cells'],len(prior['lineage']))==(63,0,252,9))
    now,wallnow=launch._number(clock()),launch._number(wall());require(wallnow>=value['recorded_wall'])
    if window:require(now<value['deadline_monotonic']-30 and wallnow<value['deadline_wall']-30)
    full=_reference(value['prior_manifest']);state=_reference(value['prior_state']);ledger=_reference(value['prior_ledger'])
    require(full['prepared_root']==str(PRIOR_ROOT) and full['document_type']=='application_client_qualification' and full['predecessor']==base_predecessor
        and full['campaign_amendment']==PRIOR_AUTHORITY and full['campaign_boundary']==BOUNDARY_REFERENCE)
    policy=prior_successor._launch_policy(full,PRIOR_AUTHORITY)
    verifier=object.__new__(launch.LaunchLedger);verifier.root=PRIOR_ROOT/'launch-ledger';verifier.manifest=policy;verifier.expected_daemon=None
    verifier.expected_capacity=None;verifier._carry=None;verifier._prevalidated_carry=prior;verifier._validate(ledger)
    require(ledger['poisoned'] is True and len(ledger['launches'])==12 and now>=ledger['last_now'] and wallnow>=ledger['last_wall'])
    require(sum(row['physical']!='absent' for row in ledger['launches'])==2 and sum(not row['private_cleanup'] for row in ledger['launches'])==6
        and not any(row['role']=='participant' for row in ledger['launches']))
    require(state['phase']=='blocked' and len(state['cells'])==5 and state['active_cell']['id']==next(c['id'] for c in full['cells'] if c['group']=='N02'))
    cleanup=_reference(value['prior_cleanup']);review=_reference(value['prior_independent_review']);boundary_review=_reference(value['prior_boundary_review'])
    require(cleanup['status']=='PASS' and cleanup['qualification_id']==full['qualification_id'] and cleanup['cumulative_container_launches']==75
        and cleanup['participant_segments']==0 and cleanup['live_owned_containers']==0 and cleanup['enforced_live_ceiling']==4
        and cleanup['safe_to_continue'] is False and cleanup['safe_for_final_handoff'] is True and cleanup['continued_execution_authorized'] is False
        and cleanup['original_operator_store_touched'] is False)
    for key in ('physical_absence_confirmed','private_cleanup_confirmed','master010_copy_removed','raw_history_poison_and_pending_flags_preserved','raw_product_cleanup_unconfirmed_preserved'):require(cleanup[key] is True)
    require(review['status']=='PASS' and review['unresolved_findings']==[] and boundary_review['status']=='PASS' and boundary_review['unresolved_findings']==[]
        and boundary_review['cumulative_container_launches']==75 and boundary_review['participant_segments']==0 and boundary_review['registry_cleanup_verified'] is True)
    manual=_relative_reference(cleanup['service_helper_runtime_parent_cleanup']);physical=_relative_reference(cleanup['physical_cleanup'])
    require(manual['status']=='PASS' and manual['cumulative_container_launches']==75 and manual['participant_segments']==0 and manual['live_owned_containers']==0
        and manual['all75_ids_absent'] is True and manual['qualification_eligible'] is False and manual['safe_to_continue'] is False
        and manual['raw_history_unchanged'] is True and manual['raw_poison_and_flags_unchanged'] is True and manual['raw_product_cleanup_unconfirmed_preserved'] is True
        and physical['status']=='PASS' and physical['all75_ids_absent'] is True and physical['raw_history_unchanged'] is True)
    for key in ('physical_absence_confirmed','private_cleanup_confirmed','parent_envelope_removed','service_private_roots_removed','application_helper_private_removed','runtime_private_roots_removed','all4_values_RAM_matched_and_scanned'):require(manual[key] is True)
    ids=manual['all_owned_container_ids'];require(type(ids) is list and len(ids)==len(set(ids))==75 and physical['all_owned_container_ids']==ids)
    for identifier in ids:launch._sha(identifier)
    require({row['container_id'] for row in ledger['launches']}<=set(ids))
    master=_relative_reference(cleanup['master_cleanup']);custody=_relative_reference(cleanup['independent_actual_custody'])
    require(master['status']=='removed' and master['store_removed'] is True and master['temporary_parent_removed'] is True
        and master['operator_original_store_selected'] is False and master['values_opened'] is False and master['value_hashes_computed'] is False
        and set(master['removed_references'])=={'PI_API_KEY','QUAL_APPLICATION_ALICE','QUAL_APPLICATION_BOB','QUAL_APPLICATION_SCRIPTED'}
        and custody['status']=='PASS' and custody['unresolved_findings']==[] and _relative_reference(master['independent_review'])==custody)
    for key in ('authorization','observation'):require(master[key]==custody[key]);_reference(master[key])
    require(master['program_sha256']==custody['program_sha256'])
    require(registry_api._qualification_absent(master['target']) and registry_api._qualification_absent(str(Path(master['target']).parent)))
    records=boundary_review['registry_records'];require(type(records) is list and len(records)==75 and len({r['path'] for r in records})==75)
    for bound in records:
        record=_reference(bound);require(record['status']=='released' and record['daemon']==ledger['daemon'])
    rows=[{'qualification_id':full['qualification_id'],'cell':cell['id'],'status':state['cells'].get(cell['id'],{}).get('status','NOT_RUN'),
        'attempts':state['cells'].get(cell['id'],{}).get('attempts',0)} for cell in full['cells']]
    require(len(rows)==28 and full['qualification_id'] not in {entry['qualification_id'] for entry in prior['lineage']})
    return {**prior,'attempts':75,'participant_segments':0,'qualification_id':full['qualification_id'],'planned_cells':280,
        **{key:value['prior_'+key.removesuffix('_sha256')]['sha256'] for key in ('manifest_sha256','state_sha256','ledger_sha256')},
        'lineage':prior['lineage']+[{'root':str(PRIOR_ROOT),'qualification_id':full['qualification_id'],
            **{key:value['prior_'+key.removesuffix('_sha256')]['sha256'] for key in ('manifest_sha256','state_sha256','ledger_sha256')}}],
        'prior_rows':prior['prior_rows']+rows,'campaign_amendment':copy.deepcopy(reference),'effective_limits':effective_limits(reference)}


def validate_diagnostic_manifest(value):
    launch._exact(value,{'qualification_id','images','cells','limits','planned_container_launches','predecessor','campaign_boundary','campaign_amendment','diagnostic'})
    _authorization(value['campaign_amendment']);launch._predecessor_shape(value['predecessor']);launch._uuid(value['qualification_id'])
    marker=value['diagnostic'];launch._exact(marker,{'kind','root','started','started_wall','deadline','deadline_wall'})
    for key in ('started','started_wall','deadline','deadline_wall'):launch._number(marker[key])
    require(marker['kind']=='application-startup' and marker['root']==str(DIAGNOSTIC_ROOT) and marker['deadline']==marker['started']+120
        and marker['deadline_wall']==marker['started_wall']+120 and marker['started']>=prior_successor.STARTED_MONOTONIC
        and marker['started_wall']>=_authorization(value['campaign_amendment'])['recorded_wall']
        and marker['deadline']<=prior_successor.DEADLINE_MONOTONIC and marker['deadline_wall']<=prior_successor.DEADLINE_WALL)
    require(value['campaign_boundary']==BOUNDARY_REFERENCE
        and value['limits']==effective_limits(value['campaign_amendment']) and type(value['planned_container_launches']) is int and value['planned_container_launches']==1)
    launch._exact(value['images'],{'core-0.87.1'});image=value['images']['core-0.87.1'];launch._exact(image,{'id','platform','capabilities'})
    require(image['id']==DIAGNOSTIC_IMAGE and image['platform']=='linux/arm64' and type(image['capabilities']) is dict and image['capabilities'].get('pi')=='0.87.1')
    expected={'id':DIAGNOSTIC_CELL,'group':'D01','release':'0.87.1','image_id':DIAGNOSTIC_IMAGE,'allowed_images':[DIAGNOSTIC_IMAGE],
        'role_limits':{'application-helper':1},'container_launches_max':1,'participant_segments_max':0}
    require(launch._json(value['cells'])==launch._json([expected]))
    require(all(type(value['limits'][key]) is int for key in launch.LIMITS))
    return copy.deepcopy(value)


def build_diagnostic_manifest(reference,image,base_predecessor,*,clock=time.monotonic,wall=time.time):
    """Return the final dispatch representation; this performs no writes/claims."""
    started,started_wall=launch._number(clock()),launch._number(wall())
    value={'qualification_id':str(uuid.uuid4()),'images':{'core-0.87.1':copy.deepcopy(image)},
        'cells':[{'id':DIAGNOSTIC_CELL,'group':'D01','release':'0.87.1','image_id':DIAGNOSTIC_IMAGE,'allowed_images':[DIAGNOSTIC_IMAGE],
            'role_limits':{'application-helper':1},'container_launches_max':1,'participant_segments_max':0}],
        'limits':effective_limits(reference),'planned_container_launches':1,'predecessor':copy.deepcopy(base_predecessor),
        'campaign_boundary':copy.deepcopy(BOUNDARY_REFERENCE),'campaign_amendment':copy.deepcopy(reference),
        'diagnostic':{'kind':'application-startup','root':str(DIAGNOSTIC_ROOT),'started':started,'started_wall':started_wall,
            'deadline':started+120,'deadline_wall':started_wall+120}}
    return validate_diagnostic_manifest(value)


def validate_diagnostic(reference,base_predecessor,*,clock=time.monotonic,wall=time.time,window=True):
    return _current_carry(reference,base_predecessor,clock=clock,wall=wall,window=window)


def bind_diagnostic(root,manifest,carry,*,create=False):
    validate_diagnostic_manifest(manifest)
    require(launch._canonical_root(str(root))==DIAGNOSTIC_ROOT/'launch-ledger' and carry['attempts']==75 and len(carry['lineage'])==10
        and carry['participant_segments']==0 and carry['campaign_amendment']==manifest['campaign_amendment'])
    manifest_reference=campaign.ref(DIAGNOSTIC_ROOT/'manifest.json');require(_reference(manifest_reference)==manifest)
    expected={'schema':1,'document_type':'qualification_startup_diagnostic_claim','authorization':manifest['campaign_amendment'],
        'qualification_id':manifest['qualification_id'],'manifest_sha256':launch._digest(manifest),'manifest_file':manifest_reference,'ledger_root':str(root),'prior_attempts':75,'participant_segments':0}
    parent=launch._dir(DIAGNOSTIC_BINDING_ROOT.parent,False)
    try:
        if create:
            os.mkdir(DIAGNOSTIC_BINDING_ROOT.name,0o700,dir_fd=parent);os.fsync(parent)
            folder=launch._dir(DIAGNOSTIC_BINDING_ROOT)
            try:
                fd=launch._file(folder,'claim.lock',os.O_RDWR|os.O_CREAT|os.O_EXCL);os.fsync(fd);os.close(fd);os.fsync(folder)
            finally:os.close(folder)
            campaign.exclusive(DIAGNOSTIC_BINDING_ROOT/'claim.json',expected)
        folder=launch._dir(DIAGNOSTIC_BINDING_ROOT)
        try:fd=launch._file(folder,'claim.lock',os.O_RDONLY);os.close(fd)
        finally:os.close(folder)
        require(campaign.read(DIAGNOSTIC_BINDING_ROOT/'claim.json')==expected)
    finally:os.close(parent)


def validate_amendment(reference,base_predecessor,*,clock=time.monotonic,wall=time.time,window=True):
    # Only a positively absent original terminal can select the separately
    # reviewed failed-diagnostic custody path. Malformed existing terminals
    # remain authoritative failures and never fall back to another result.
    if registry_api._qualification_absent(str(DIAGNOSTIC_ROOT/'terminal.json')):
        import application_diagnostic_cleanup
        return application_diagnostic_cleanup.validate_known_cleanup(reference,base_predecessor,clock=clock,wall=wall,window=window)
    carry=_current_carry(reference,base_predecessor,clock=clock,wall=wall,window=window)
    terminal_reference=campaign.ref(DIAGNOSTIC_ROOT/'terminal.json');terminal=_reference(terminal_reference)
    launch._exact(terminal,{'schema','document_type','authorization','qualification_id','manifest','ledger','registry_record','container_id','diagnostic_outcome','process_exit_code','process_exit_code_available','network_removed','network_record',
        'participant_segments','inference_calls','application_requests','real_credentials_used','physical_absence_confirmed','private_cleanup_confirmed','all_writers_absent',
        'private_roots_removed','started_wall','finished_wall','elapsed_seconds','cleanup_elapsed_seconds','original_lease_held','raw_ledger_preserved'})
    require(type(terminal['schema']) is int and terminal['schema']==1 and terminal['document_type']=='qualification_startup_diagnostic_terminal'
        and terminal['authorization']==reference and terminal['diagnostic_outcome'] in ('ready','startup_failed'))
    for key in ('participant_segments','inference_calls','application_requests'):require(type(terminal[key]) is int and terminal[key]==0)
    require(terminal['real_credentials_used'] is False)
    for key in ('physical_absence_confirmed','private_cleanup_confirmed','all_writers_absent','original_lease_held','raw_ledger_preserved'):require(terminal[key] is True)
    for key in ('started_wall','finished_wall','elapsed_seconds','cleanup_elapsed_seconds'):launch._number(terminal[key])
    require(0<terminal['elapsed_seconds']<=120 and 0<=terminal['cleanup_elapsed_seconds']<=30
        and terminal['finished_wall']>=terminal['started_wall'] and abs(terminal['finished_wall']-terminal['started_wall']-terminal['elapsed_seconds'])<1
        and terminal['started_wall']>=_authorization(reference)['recorded_wall'] and terminal['finished_wall']<=wall()
        and terminal['finished_wall']<carry['deadline_wall'])
    require(type(terminal['process_exit_code_available']) is bool and terminal['network_removed'] is True)
    if terminal['process_exit_code_available']:launch._integer(terminal['process_exit_code'],0,255)
    else:require(terminal['process_exit_code'] is None)
    launch._sha(terminal['container_id'])
    require(terminal['manifest']['path']==str(DIAGNOSTIC_ROOT/'manifest.json') and terminal['ledger']['path']==str(DIAGNOSTIC_ROOT/'launch-ledger/ledger.json'))
    manifest=_reference(terminal['manifest']);validate_diagnostic_manifest(manifest);require(manifest['campaign_amendment']==reference and manifest['predecessor']==base_predecessor
        and manifest['qualification_id']==terminal['qualification_id'] and terminal['started_wall']==manifest['diagnostic']['started_wall']
        and terminal['finished_wall']<=manifest['diagnostic']['deadline_wall'])
    ledger=_reference(terminal['ledger']);verifier=object.__new__(launch.LaunchLedger);verifier.root=DIAGNOSTIC_ROOT/'launch-ledger';verifier.manifest=manifest
    verifier.expected_daemon=None;verifier.expected_capacity=None;verifier._carry=None;verifier._prevalidated_carry=carry;verifier._validate(ledger)
    require(len(ledger['launches'])==1 and ledger['launches'][0]['role']=='application-helper' and ledger['launches'][0]['cell']==DIAGNOSTIC_CELL)
    row=ledger['launches'][0];record=_reference(terminal['registry_record'])
    require(row['container_id']==terminal['container_id'] and record['container_id']==terminal['container_id'] and record['status']=='released'
        and launch._intent_identity(record)==row['intent_sha256'] and record['daemon']==carry['daemon'] and record['application_helper'] is True
        and record['client_mode']=='application-execution' and all(record[k]==row[k] for k in ('launch_id','registry','generation','image','container')))
    # status/revoke are owner control IPC. application_requests counts outbound
    # business API/browser effects only; diagnostic activation remains forbidden.
    if terminal['network_record'] is not None:
        network=_reference(terminal['network_record'])
        require(network['kind']=='network' and network['status']=='released' and network['daemon']==carry['daemon']
            and network['registry']==record['registry'] and network['generation']==record['generation']
            and network['runroot'] in (None,record['runroot']) and network['container']==record['container']+'-network')
    private=terminal['private_roots_removed'];require(type(private) is list and 1<=len(private)<=16 and len({r['path'] for r in private})==len(private))
    for item in private:
        launch._exact(item,{'path','device','inode','removed'});path=launch._canonical_root(item['path']);launch._integer(item['device'],0,2**64-1);launch._integer(item['inode'],1,2**64-1)
        require(item['removed'] is True and DIAGNOSTIC_ROOT in path.parents and registry_api._qualification_absent(str(path)))
    require(record['private_store'] in {r['path'] for r in private})
    return {**carry,'attempts':76,'startup_diagnostic':{'reference':terminal_reference,'attempts':1,'participant_segments':0,'native_rows':0,'root':str(DIAGNOSTIC_ROOT)}}


class DiagnosticLedger(launch.LaunchLedger):
    """The same durable central reserve/dispatch/cleanup transactions."""

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
    require(launch._canonical_root(str(root))==FINAL_ROOT/'launch-ledger' and len(carry['lineage'])==10 and carry['attempts']==76
        and carry['participant_segments']==0 and carry['campaign_amendment']==manifest['campaign_amendment'])
    reference=manifest['campaign_amendment'];_fence(reference,carry)
    binding=campaign.read(BINDING_ROOT/'candidate-binding.json');launch._exact(binding,{'schema','amendment','qualification_id','full_manifest','candidate','launch_manifest_sha256'})
    full=_reference(binding['full_manifest']);candidate=_reference(binding['candidate'])
    require(type(binding['schema']) is int and binding['schema']==1 and binding['amendment']==reference and binding['qualification_id']==manifest['qualification_id']
        and binding['full_manifest']['path']==str(FINAL_ROOT/'manifest.json') and binding['candidate']['path']==str(FINAL_ROOT/'candidate.json')
        and candidate['scope']=='extracted_candidate' and candidate['runner_sha256']==full['source']['runner']
        and binding['launch_manifest_sha256']==launch._digest(manifest) and launch._json(_launch_policy(full,reference))==launch._json(manifest))
    expected={'schema':1,'document_type':'qualification_matrix_amendment_launch_binding','amendment':reference,'qualification_id':manifest['qualification_id'],
        'manifest_sha256':launch._digest(manifest),'ledger_root':str(root),'cumulative_attempts':76,'participant_segments':0,
        'candidate_binding':campaign.ref(BINDING_ROOT/'candidate-binding.json')}
    if create:campaign.exclusive(BINDING_ROOT/'launch-binding.json',expected)
    require(campaign.read(BINDING_ROOT/'launch-binding.json')==expected)
