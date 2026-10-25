"""One explicitly authorized twelfth matrix after preserved blocked matrix011.

This maintainer validator reads public custody evidence and reserves one durable
successor origin. It never launches a process, resolves a key, repairs old raw
accounting, or grants any additional diagnostic or thirteenth origin.
"""
import copy
import fcntl
import os
from pathlib import Path
import stat
import time

import application_launch as launch
import application_campaign as campaign
import application_followup as prior_amendment
import ownership_registry as registry_api

REPO = Path(__file__).resolve().parents[2]
AUTHORIZATION_PATH = REPO/'reports/application-agent-enhancements/A15/campaign-005/matrix-012-authorization.json'
AUTHORIZATION_SHA256 = '7d6c3a9579a14829d5b76888bd83a503294ad8e47a20f17e2a8c323d70f913c8'
AUTHORIZATION_ID = '051bdc12-45f8-4900-b32a-5b359136e756'
WINDOW_AUTHORIZATION = {'path':str(REPO/'reports/application-agent-enhancements/A15/campaign-window-004-authorization.json'),
    'sha256':'fe89d4d42344b84c519196c8d466aae47df92410109e5cb1fdcce04e90f716c7'}
PRIOR_ROOT = REPO/'reports/application-agent-enhancements/A15/attempt-011/qualification'
FINAL_ROOT = REPO/'reports/application-agent-enhancements/A15/attempt-012/qualification'
BINDING_ROOT = AUTHORIZATION_PATH.parent/'matrix-012-successor'
PRIOR_AMENDMENT_REFERENCE = {'path':str(prior_amendment.AUTHORIZATION_PATH),'sha256':prior_amendment.AUTHORIZATION_SHA256}
BOUNDARY_REFERENCE = copy.deepcopy(prior_amendment.BOUNDARY_REFERENCE)
STARTED_WALL = 1792322178.1072938
STARTED_MONOTONIC = 602586.187410833
DEADLINE_WALL = 1792336578.1072938
DEADLINE_MONOTONIC = 616986.187410833
_reference = prior_amendment._reference
_relative_reference = prior_amendment._relative_reference


def require(value):
    if not value:
        raise launch.LaunchError('qualification_requalification_invalid')


def _authorization(reference):
    require(reference == {'path':str(AUTHORIZATION_PATH),'sha256':AUTHORIZATION_SHA256})
    value = _reference(reference)
    fixed = {'schema':1,'document_type':'qualification_matrix_requalification_authorization','authorization_id':AUTHORIZATION_ID,
        'final_root':str(FINAL_ROOT),'maximum_matrix_origins':12,'prior_matrix_origins':11,'cumulative_container_launches':79,
        'cumulative_participant_segments':0,'previous_container_cap':262,'container_cap':265,'participant_cap':24,'live_cap':4,
        'trial_cap':1,'inference_slot_cap':1,'platform':'linux/arm64','automatic_retries':0,'continuations':0,
        'planned_new_container_launches':186,'planned_new_participant_segments':24,'started_wall':STARTED_WALL,
        'started_monotonic':STARTED_MONOTONIC,'deadline_wall':DEADLINE_WALL,'deadline_monotonic':DEADLINE_MONOTONIC,
        'original_evidence_modified':False,'historical_windows_modified':False,'additional_auxiliary_launches_authorized':0,
        'additional_startup_diagnostic_authorized':False,'thirteenth_origin_authorized':False}
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
        and window['authorization'] == value['human_authorization'] and window['original_deadline_wall'] == prior_amendment.prior_successor.DEADLINE_WALL
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
    return {**launch.LIMITS,'container_launch_attempts':265}


def _cleanup(value, full, ledger):
    cleanup = _reference(value['prior_cleanup'])
    review = _reference(value['prior_independent_review'])
    boundary = _reference(value['prior_boundary_review'])
    require(cleanup['status'] == 'PASS' and cleanup['qualification_id'] == full['qualification_id']
        and cleanup['cumulative_container_launches'] == 79 and cleanup['participant_segments'] == 0
        and cleanup['live_owned_containers'] == 0 and cleanup['enforced_live_ceiling'] == 4
        and cleanup['safe_to_continue'] is False and cleanup['continued_execution_authorized'] is False
        and cleanup['safe_for_final_handoff'] is True and cleanup['qualification_eligible'] is False
        and cleanup['original_operator_store_touched'] is False and cleanup['raw_ledger_rewritten'] is False
        and cleanup['raw_product_private_cleanup_false_rows'] == 2 and cleanup['planned_rows'] == 308)
    for key in ('physical_absence_confirmed','private_cleanup_confirmed','master011_copy_removed','temporary_parent_absence_confirmed',
        'all79_ids_absent','raw_history_poison_and_pending_flags_preserved','raw_product_cleanup_unconfirmed_preserved'):
        require(cleanup[key] is True)
    require(review['status'] == boundary['status'] == 'PASS' and review['unresolved_findings'] == boundary['unresolved_findings'] == []
        and boundary['final_cleanup'] == value['prior_cleanup'] and boundary['registry_cleanup_verified'] is True
        and boundary['all79_physical_absence_proof_verified'] is True and boundary['raw_current_ledger_preserved'] is True
        and boundary['raw_historical_ledgers_preserved'] is True and boundary['raw_private_cleanup_false_rows_preserved'] == 2
        and boundary['cumulative_container_launches'] == 79 and boundary['participant_segments'] == 0 and boundary['live_owned_containers'] == 0)
    physical = _relative_reference(cleanup['physical_and_ownership_closure'])
    physical_review = _relative_reference(cleanup['independent_physical_ownership_review'])
    require(physical['status'] == physical_review['status'] == 'PASS' and physical_review['unresolved_findings'] == []
        and physical['qualification_id'] == full['qualification_id'] and physical['manifest'] == value['prior_manifest']
        and physical['ledger'] == value['prior_ledger'] and physical['state'] == value['prior_state']
        and physical['cumulative_container_launches'] == 79 and physical['participant_segments'] == 0 and physical['live_owned_containers'] == 0
        and physical['resource_mutations'] == 0 and physical['raw_product_private_cleanup_false_rows_preserved'] == 2)
    for key in ('all79_ids_absent','original_lease_held','controller_lock_held','lock_inodes_unchanged','all_native_writers_absent',
        'all_service_writers_stopped','all_helper_writers_stopped','all_qualification_controllers_stopped','all_issued_capabilities_revoked',
        'raw_history_unchanged','raw_poison_preserved','physical_absence_confirmed','private_cleanup_confirmed'):
        require(physical[key] is True)
    ids = cleanup['all_owned_container_ids']
    require(type(ids) is list and len(ids) == len(set(ids)) == 79 and physical['all_owned_container_ids'] == ids)
    for identifier in ids:
        launch._sha(identifier)
    require({row['container_id'] for row in ledger['launches']} <= set(ids))
    records = physical['after_records']
    require(type(records) is list and len(records) == 3 and len({r['path'] for r in records}) == 3)
    released = {}
    for bound in records:
        record = _relative_reference(bound)
        released[record['launch_id']] = (record,bound)
    require(len(released) == 3)
    registry_root = Path.home()/'.local/state/pi-agentic-development/operation.lock.registry'
    for row in ledger['launches']:
        record, bound = released[row['launch_id']]
        require(record['status'] == 'released' and record['daemon'] == ledger['daemon']
            and launch._intent_identity(record) == row['intent_sha256']
            and all(record[k] == row[k] for k in ('launch_id','registry','generation','image','container')))
        # Legacy Registry entries omit container_id. The immutable raw ledger and
        # exact all79 absence proof retain it; never synthesize a new entry field.
        require(launch._bound_json(str(registry_root/(row['launch_id']+'.json')),bound['sha256']) == record)
    master = _relative_reference(cleanup['master_cleanup'])
    custody = _relative_reference(cleanup['independent_actual_custody'])
    require(master['status'] == 'removed' and master['store_removed'] is True and master['temporary_parent_removed'] is True
        and master['operator_original_store_selected'] is False and master['values_opened'] is False and master['value_hashes_computed'] is False
        and set(master['removed_references']) == {'PI_API_KEY','QUAL_APPLICATION_ALICE','QUAL_APPLICATION_BOB','QUAL_APPLICATION_SCRIPTED'}
        and master['target'] == full['secrets_dir'] and custody['target'] == master['target']
        and custody['status'] == 'PASS' and custody['unresolved_findings'] == [] and _relative_reference(master['independent_review']) == custody)
    for key in ('authorization','observation'):
        require(master[key] == custody[key])
        _reference(master[key])
    require(master['program_sha256'] == custody['program_sha256']
        and registry_api._qualification_absent(master['target']) and registry_api._qualification_absent(str(Path(master['target']).parent)))


def validate_amendment(reference, base_predecessor, *, clock=time.monotonic, wall=time.time, window=True):
    value = _authorization(reference)
    prior = prior_amendment.validate_amendment(value['prior_amendment'],base_predecessor,clock=clock,wall=wall,window=False)
    require((prior['attempts'],prior['participant_segments'],prior['planned_cells'],len(prior['lineage'])) == (76,0,280,10))
    now, wallnow = launch._number(clock()), launch._number(wall())
    require(now >= STARTED_MONOTONIC and wallnow >= STARTED_WALL and wallnow >= value['recorded_wall'])
    if window:
        require(now < DEADLINE_MONOTONIC-30 and wallnow < DEADLINE_WALL-30)
    full, state, ledger = (_reference(value['prior_'+key]) for key in ('manifest','state','ledger'))
    require(full['prepared_root'] == str(PRIOR_ROOT) and full['document_type'] == 'application_client_qualification'
        and full['predecessor'] == base_predecessor and full['campaign_boundary'] == BOUNDARY_REFERENCE
        and full['campaign_amendment'] == PRIOR_AMENDMENT_REFERENCE)
    policy = prior_amendment._launch_policy(full,PRIOR_AMENDMENT_REFERENCE)
    verifier = object.__new__(launch.LaunchLedger)
    verifier.root, verifier.manifest = PRIOR_ROOT/'launch-ledger', policy
    verifier.expected_daemon = verifier.expected_capacity = verifier._carry = None
    verifier._prevalidated_carry = prior
    verifier._validate(ledger)
    require(ledger['poisoned'] is True and len(ledger['launches']) == 3 and now >= ledger['last_now'] and wallnow >= ledger['last_wall'])
    require([r['role'] for r in ledger['launches']] == ['probe','probe','browser-check']
        and all(r['physical'] == 'absent' for r in ledger['launches'])
        and [r['private_cleanup'] for r in ledger['launches']] == [True,False,False])
    launch._exact(state,{'schema','phase','active_cell','cells','started_at'})
    require(type(state['schema']) is int and state['schema'] == 1 and state['phase'] == 'blocked' and state['active_cell'] is None
        and state['started_at'] == prior['started_wall'] and state['cells'] == {
            'N01-0.87.1-core':{'status':'PASS','attempts':1,'evidence_level':'native_infrastructure'},
            'N01-0.87.1-browser':{'status':'BLOCKED','attempts':1,'reason':'infrastructure_qualification_failed'}})
    _cleanup(value,full,ledger)
    rows = [{'qualification_id':full['qualification_id'],'cell':cell['id'],'status':state['cells'].get(cell['id'],{}).get('status','NOT_RUN'),
        'attempts':state['cells'].get(cell['id'],{}).get('attempts',0)} for cell in full['cells']]
    require(len(rows) == 28 and full['qualification_id'] not in {item['qualification_id'] for item in prior['lineage']})
    hashes = {key:value['prior_'+key.removesuffix('_sha256')]['sha256'] for key in ('manifest_sha256','state_sha256','ledger_sha256')}
    return {**prior,'attempts':79,'participant_segments':0,'qualification_id':full['qualification_id'],'planned_cells':308,**hashes,
        'started':STARTED_MONOTONIC,'started_wall':STARTED_WALL,'deadline':DEADLINE_MONOTONIC,'deadline_wall':DEADLINE_WALL,
        'lineage':prior['lineage']+[{'root':str(PRIOR_ROOT),'qualification_id':full['qualification_id'],**hashes}],
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
    require(launch._canonical_root(str(root))==FINAL_ROOT/'launch-ledger' and len(carry['lineage'])==11 and carry['attempts']==79
        and carry['participant_segments']==0 and carry['campaign_amendment']==manifest['campaign_amendment'])
    reference=manifest['campaign_amendment'];_fence(reference,carry)
    binding=campaign.read(BINDING_ROOT/'candidate-binding.json');launch._exact(binding,{'schema','amendment','qualification_id','full_manifest','candidate','launch_manifest_sha256'})
    full=_reference(binding['full_manifest']);candidate=_reference(binding['candidate'])
    require(type(binding['schema']) is int and binding['schema']==1 and binding['amendment']==reference and binding['qualification_id']==manifest['qualification_id']
        and binding['full_manifest']['path']==str(FINAL_ROOT/'manifest.json') and binding['candidate']['path']==str(FINAL_ROOT/'candidate.json')
        and candidate['scope']=='extracted_candidate' and candidate['runner_sha256']==full['source']['runner']
        and binding['launch_manifest_sha256']==launch._digest(manifest) and launch._json(_launch_policy(full,reference))==launch._json(manifest))
    expected={'schema':1,'document_type':'qualification_matrix_amendment_launch_binding','amendment':reference,'qualification_id':manifest['qualification_id'],
        'manifest_sha256':launch._digest(manifest),'ledger_root':str(root),'cumulative_attempts':79,'participant_segments':0,
        'candidate_binding':campaign.ref(BINDING_ROOT/'candidate-binding.json')}
    if create:campaign.exclusive(BINDING_ROOT/'launch-binding.json',expected)
    require(campaign.read(BINDING_ROOT/'launch-binding.json')==expected)
