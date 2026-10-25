"""One explicitly authorized thirteenth matrix after preserved blocked matrix012.

This maintainer validator reads public custody evidence and reserves one durable
successor origin. It never launches a process, resolves a key, repairs old raw
accounting, or grants any additional diagnostic or fourteenth origin.
"""
import copy
import fcntl
import os
from pathlib import Path
import stat
import time

import application_launch as launch
import application_campaign as campaign
import application_requalification as prior_amendment
import ownership_registry as registry_api

REPO = Path(__file__).resolve().parents[2]
AUTHORIZATION_PATH = REPO/'reports/application-agent-enhancements/A15/campaign-006/matrix-013-authorization.json'
AUTHORIZATION_SHA256 = 'c3f2d3add282f0b6fd4238f816725dd24d82a0f5080a852e15703965f2f44d2d'
AUTHORIZATION_ID = '5fbce9c5-b706-443a-ba65-7eee83e09855'
WINDOW_AUTHORIZATION = {'path':str(REPO/'reports/application-agent-enhancements/A15/campaign-window-005-authorization.json'),
    'sha256':'4ce553cc85690362d6a47ac3826660fc6c6b97e1cfd3087d250e9727bdadfb6f'}
PRIOR_ROOT = REPO/'reports/application-agent-enhancements/A15/attempt-012/qualification'
FINAL_ROOT = REPO/'reports/application-agent-enhancements/A15/attempt-013/qualification'
BINDING_ROOT = AUTHORIZATION_PATH.parent/'matrix-013-successor'
PRIOR_AMENDMENT_REFERENCE = {'path':str(prior_amendment.AUTHORIZATION_PATH),'sha256':prior_amendment.AUTHORIZATION_SHA256}
BOUNDARY_REFERENCE = copy.deepcopy(prior_amendment.BOUNDARY_REFERENCE)
STARTED_WALL = 1792327421.30397
STARTED_MONOTONIC = 607829.374229125
DEADLINE_WALL = 1792341821.30397
DEADLINE_MONOTONIC = 622229.374229125
_reference = prior_amendment._reference
_relative_reference = prior_amendment._relative_reference


def require(value):
    if not value:
        raise launch.LaunchError('qualification_matrix13_invalid')


def _authorization(reference):
    require(reference == {'path':str(AUTHORIZATION_PATH),'sha256':AUTHORIZATION_SHA256})
    value = _reference(reference)
    fixed = {'schema':1,'document_type':'qualification_matrix_requalification_authorization','authorization_id':AUTHORIZATION_ID,
        'final_root':str(FINAL_ROOT),'maximum_matrix_origins':13,'prior_matrix_origins':12,'cumulative_container_launches':91,
        'cumulative_participant_segments':0,'previous_container_cap':265,'container_cap':277,'participant_cap':24,'live_cap':4,
        'trial_cap':1,'inference_slot_cap':1,'platform':'linux/arm64','automatic_retries':0,'continuations':0,
        'planned_new_container_launches':186,'planned_new_participant_segments':24,'started_wall':STARTED_WALL,
        'started_monotonic':STARTED_MONOTONIC,'deadline_wall':DEADLINE_WALL,'deadline_monotonic':DEADLINE_MONOTONIC,
        'original_evidence_modified':False,'historical_windows_modified':False,'additional_auxiliary_launches_authorized':0,
        'additional_startup_diagnostic_authorized':False,'fourteenth_origin_authorized':False}
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
    return {**launch.LIMITS,'container_launch_attempts':277}


def _cleanup(value, full, ledger):
    cleanup = _reference(value['prior_cleanup'])
    review = _reference(value['prior_independent_review'])
    boundary = _reference(value['prior_boundary_review'])
    require(cleanup['status'] == 'PASS' and cleanup['qualification_id'] == full['qualification_id']
        and cleanup['cumulative_container_launches'] == 91 and cleanup['participant_segments'] == 0
        and cleanup['live_owned_containers'] == 0 and cleanup['enforced_live_ceiling'] == 4
        and cleanup['safe_to_continue'] is False and cleanup['continued_execution_authorized'] is False
        and cleanup['safe_for_final_handoff'] is True and cleanup['qualification_eligible'] is False
        and cleanup['original_operator_store_touched'] is False and cleanup['raw_ledger_rewritten'] is False
        and cleanup['raw_product_private_cleanup_false_rows'] == 6 and cleanup['planned_rows'] == 336)
    for key in ('physical_absence_confirmed','private_cleanup_confirmed','master012_copy_removed','all91_ids_absent',
        'parent_envelope_removed','service_private_roots_removed','application_helper_private_removed','runtime_private_roots_removed',
        'all4_values_RAM_matched_and_scanned','owned_application_network_removed_and_released',
        'raw_history_poison_and_pending_flags_preserved','raw_product_cleanup_unconfirmed_preserved'):
        require(cleanup[key] is True)
    require(cleanup['raw_ledger']['sha256'] == value['prior_ledger']['sha256'] and _relative_reference(cleanup['raw_ledger']) == ledger
        and review['status'] == boundary['status'] == 'PASS'
        and review['unresolved_findings'] == boundary['unresolved_findings'] == [] and boundary['final_cleanup'] == value['prior_cleanup']
        and boundary['cumulative_container_launches'] == 91 and boundary['participant_segments'] == 0)
    for key in ('actual_master_parent_store_absent','all8_private_roots_absent','all13_current_matrix_registry_records_released_unchanged',
        'all91_immutable_container_absence_retained','raw_manifest_state_candidate_integrity_ledger_preserved','raw_poison_true_and_six_private_false_preserved'):
        require(boundary[key] is True)
    physical = _relative_reference(cleanup['physical_cleanup'])
    manual = _relative_reference(cleanup['service_helper_runtime_parent_cleanup'])
    private_review = _relative_reference(cleanup['independent_private_review'])
    require(physical['status'] == manual['status'] == private_review['status'] == 'PASS' and private_review['unresolved_findings'] == []
        and private_review['actual_private_proof']['sha256'] == cleanup['service_helper_runtime_parent_cleanup']['sha256']
        and _relative_reference(private_review['actual_private_proof']) == manual
        and physical['qualification_id'] == full['qualification_id'] and physical['raw_state_sha256'] == value['prior_state']['sha256']
        and physical['raw_ledger_sha256'] == value['prior_ledger']['sha256'] and manual['live_owned_containers'] == 0)
    for proof in (physical,manual):
        require(proof['cumulative_container_launches'] == 91 and proof['participant_segments'] == 0
            and proof['all91_ids_absent'] is True and proof['original_lease_held'] is True and proof['controller_lock_held'] is True
            and proof['raw_history_unchanged'] is True)
    for key in ('physical_absence_confirmed','private_cleanup_confirmed','parent_envelope_removed','service_private_roots_removed',
        'application_helper_private_removed','runtime_private_roots_removed','all4_values_RAM_matched_and_scanned',
        'raw_poison_and_flags_unchanged','raw_product_cleanup_unconfirmed_preserved'):
        require(manual[key] is True)
    ids = cleanup['all_owned_container_ids']
    require(type(ids) is list and len(ids) == len(set(ids)) == 91
        and manual['all_owned_container_ids'] == physical['all_owned_container_ids'] == ids)
    for identifier in ids:launch._sha(identifier)
    require({row['container_id'] for row in ledger['launches']} <= set(ids))
    custody = _relative_reference(manual['manual_owner_custody'])
    require(custody['status'] == 'PASS' and custody['qualification_id'] == full['qualification_id']
        and custody['cumulative_container_launches'] == 91 and custody['participant_segments'] == 0
        and custody['all_owned_container_ids'] == ids and custody['raw_product_and_history_unchanged'] is True
        and custody['sealed_product_cleanup_status'] == 'cleanup_unconfirmed' and custody['report_repaired'] is False)
    roots = custody['private_roots_removed']
    require(type(roots) is list and len(roots) == len(set(roots)) == 8)
    for path in roots:require(registry_api._qualification_absent(str(launch._canonical_root(path))))
    registry_root = Path.home()/'.local/state/pi-agentic-development/operation.lock.registry'
    command = _relative_reference(cleanup['master_cleanup_command'])
    require(command['status'] == 'PASS' and type(command['actual_exit']) is int and command['actual_exit'] == 0
        and command['native_launches'] == 0 and command['credential_values_opened'] is False and command['automatic_retry_performed'] is False)
    observed = command['custody_before_action']
    require(observed['status'] == 'PASS' and observed['target'] == full['secrets_dir']
        and observed['cumulative_container_launches'] == 91 and observed['participant_segments'] == 0
        and observed['original_lease_held'] is True and observed['controller_lock_held'] is True
        and observed['all91_absence_reused_from_retained_leased_hygiene'] is True)
    references = observed['current_registry_records']
    require(type(references) is list and len(references) == 13 and len({r['path'] for r in references}) == 13)
    expected_paths = {str(registry_root/(row['launch_id']+'.json')) for row in ledger['launches']}
    expected_paths.add(str(registry_root/(physical['network_record_released']+'.json')))
    require({r['path'] for r in references} == expected_paths)
    pinned = {}
    for bound in references:
        launch._exact(bound,{'path','sha256'});launch._sha(bound['sha256']);pinned[bound['path']] = bound['sha256']
    helper = None
    for row in ledger['launches']:
        path = str(registry_root/(row['launch_id']+'.json'))
        record = launch._bound_json(path,pinned[path])
        require(record['status'] == 'released' and record['daemon'] == ledger['daemon']
            and launch._intent_identity(record) == row['intent_sha256']
            and all(record[k] == row[k] for k in ('launch_id','registry','generation','image','container'))
            and record.get('container_id') in (None,row['container_id']))
        if row['role'] == 'application-helper':helper = record
    require(helper is not None and helper['application_helper'] is True and helper['client_mode'] == 'application-execution'
        and helper['private_store'] in roots and helper['container_id'] == ledger['launches'][-1]['container_id'])
    network_path = str(registry_root/(physical['network_record_released']+'.json'))
    network = launch._bound_json(network_path,pinned[network_path])
    require(physical['network_cleanup_confirmed'] is True and network['kind'] == 'network' and network['status'] == 'released'
        and network['daemon'] == ledger['daemon'] and network['registry'] == helper['registry'] and network['generation'] == helper['generation']
        and network['container'] == helper['container']+'-network' and network['runroot'] in (None,helper['runroot']))
    receipts = [_reference(bound) for bound in manual['service_cleanup_receipts']]
    services = [row for row in ledger['launches'] if row['role'] in ('fixture','scripted-inference')]
    require(len(receipts) == 2 and {r['launch_id'] for r in receipts} == {r['launch_id'] for r in services})
    for receipt in receipts:
        row = next(row for row in services if row['launch_id'] == receipt['launch_id'])
        require(receipt['document_type'] == 'qualification_service_cleanup' and receipt['physical_absence_confirmed'] is True
            and receipt['private_bootstrap_removed'] is True and receipt['daemon'] == ledger['daemon']
            and all(receipt[k] == row[k] for k in ('launch_id','registry','generation','image','container','container_id','intent_sha256','role','cell')))
    master = _relative_reference(cleanup['master_cleanup'])
    master_custody = _relative_reference(cleanup['independent_actual_custody'])
    require(master['status'] == 'removed' and master['store_removed'] is True and master['temporary_parent_removed'] is True
        and master['operator_original_store_selected'] is False and master['values_opened'] is False and master['value_hashes_computed'] is False
        and set(master['removed_references']) == {'PI_API_KEY','QUAL_APPLICATION_ALICE','QUAL_APPLICATION_BOB','QUAL_APPLICATION_SCRIPTED'}
        and master['target'] == full['secrets_dir'] and master_custody['target'] == master['target']
        and master_custody['status'] == 'PASS' and master_custody['unresolved_findings'] == []
        and _relative_reference(master['independent_review']) == master_custody)
    for key in ('authorization','observation'):
        require(master[key] == master_custody[key]);_reference(master[key])
    require(master['program_sha256'] == master_custody['program_sha256']
        and registry_api._qualification_absent(master['target']) and registry_api._qualification_absent(str(Path(master['target']).parent)))


def validate_amendment(reference, base_predecessor, *, clock=time.monotonic, wall=time.time, window=True):
    value = _authorization(reference)
    prior = prior_amendment.validate_amendment(value['prior_amendment'],base_predecessor,clock=clock,wall=wall,window=False)
    require((prior['attempts'],prior['participant_segments'],prior['planned_cells'],len(prior['lineage'])) == (79,0,308,11))
    now, wallnow = launch._number(clock()), launch._number(wall())
    require(now >= STARTED_MONOTONIC and wallnow >= STARTED_WALL and wallnow >= value['recorded_wall'])
    if window:require(now < DEADLINE_MONOTONIC-30 and wallnow < DEADLINE_WALL-30)
    full, state, ledger = (_reference(value['prior_'+key]) for key in ('manifest','state','ledger'))
    require(full['prepared_root'] == str(PRIOR_ROOT) and full['document_type'] == 'application_client_qualification'
        and full['predecessor'] == base_predecessor and full['campaign_boundary'] == BOUNDARY_REFERENCE
        and full['campaign_amendment'] == PRIOR_AMENDMENT_REFERENCE)
    verifier = object.__new__(launch.LaunchLedger);verifier.root = PRIOR_ROOT/'launch-ledger'
    verifier.manifest = prior_amendment._launch_policy(full,PRIOR_AMENDMENT_REFERENCE)
    verifier.expected_daemon = verifier.expected_capacity = verifier._carry = None;verifier._prevalidated_carry = prior
    verifier._validate(ledger)
    require(ledger['poisoned'] is True and len(ledger['launches']) == 12 and now >= ledger['last_now'] and wallnow >= ledger['last_wall'])
    rows = ledger['launches'];cells = full['cells'];first = next(c for c in cells if c['group'] == 'N02');active = state['active_cell']
    launch._exact(state,{'schema','phase','active_cell','cells','started_at'});launch._exact(active,{'id','pid','run_id','attempt_id'})
    launch._integer(active['pid'],1,2**31-1)
    for key in ('run_id','attempt_id'):launch._uuid(active[key])
    require(type(state['schema']) is int and state['schema'] == 1 and state['phase'] == 'blocked'
        and state['started_at'] == prior['started_wall'] and active['id'] == first['id'] and len(state['cells']) == 5)
    for cell in cells:
        item = state['cells'].get(cell['id'])
        if cell['group'] == 'N01':require(item == {'status':'PASS','attempts':1,'evidence_level':'native_infrastructure'})
        elif cell['id'] == active['id']:require(item == {'status':'BLOCKED','attempts':1,'run_id':active['run_id'],'attempt_id':active['attempt_id'],'private_cleanup':'unconfirmed'})
        else:require(item is None)
    require(all(r['physical'] == 'absent' and r['private_cleanup'] is True for r in rows[:6])
        and all(r['cell'] == active['id'] and r['private_cleanup'] is False for r in rows[6:])
        and [r['role'] for r in rows[6:]] == ['fixture','scripted-inference','probe','boundary','preflight','application-helper']
        and [r['physical'] for r in rows[6:]] == ['uncertain','absent','absent','absent','absent','uncertain'])
    require(len({r['container_id'] for r in rows}) == 12 and None not in {r['container_id'] for r in rows})
    _cleanup(value,full,ledger)
    old_rows = [{'qualification_id':full['qualification_id'],'cell':cell['id'],'status':state['cells'].get(cell['id'],{}).get('status','NOT_RUN'),
        'attempts':state['cells'].get(cell['id'],{}).get('attempts',0)} for cell in cells]
    require(len(old_rows) == 28 and full['qualification_id'] not in {entry['qualification_id'] for entry in prior['lineage']})
    hashes = {key:value['prior_'+key.removesuffix('_sha256')]['sha256'] for key in ('manifest_sha256','state_sha256','ledger_sha256')}
    return {**prior,'attempts':91,'participant_segments':0,'qualification_id':full['qualification_id'],'planned_cells':336,**hashes,
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
    require(launch._canonical_root(str(root))==FINAL_ROOT/'launch-ledger' and len(carry['lineage'])==12 and carry['attempts']==91
        and carry['participant_segments']==0 and carry['campaign_amendment']==manifest['campaign_amendment'])
    reference=manifest['campaign_amendment'];_fence(reference,carry)
    binding=campaign.read(BINDING_ROOT/'candidate-binding.json');launch._exact(binding,{'schema','amendment','qualification_id','full_manifest','candidate','launch_manifest_sha256'})
    full=_reference(binding['full_manifest']);candidate=_reference(binding['candidate'])
    require(type(binding['schema']) is int and binding['schema']==1 and binding['amendment']==reference and binding['qualification_id']==manifest['qualification_id']
        and binding['full_manifest']['path']==str(FINAL_ROOT/'manifest.json') and binding['candidate']['path']==str(FINAL_ROOT/'candidate.json')
        and candidate['scope']=='extracted_candidate' and candidate['runner_sha256']==full['source']['runner']
        and binding['launch_manifest_sha256']==launch._digest(manifest) and launch._json(_launch_policy(full,reference))==launch._json(manifest))
    expected={'schema':1,'document_type':'qualification_matrix_amendment_launch_binding','amendment':reference,'qualification_id':manifest['qualification_id'],
        'manifest_sha256':launch._digest(manifest),'ledger_root':str(root),'cumulative_attempts':91,'participant_segments':0,
        'candidate_binding':campaign.ref(BINDING_ROOT/'candidate-binding.json')}
    if create:campaign.exclusive(BINDING_ROOT/'launch-binding.json',expected)
    require(campaign.read(BINDING_ROOT/'launch-binding.json')==expected)
