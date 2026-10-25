"""One explicitly authorized fourteenth matrix after preserved blocked matrix013.

This maintainer validator reads public custody evidence and reserves one durable
successor origin. It never launches a process, resolves a key, repairs old raw
accounting, or grants any additional diagnostic or fifteenth origin.
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
import application_matrix13 as prior_amendment
import ownership_registry as registry_api

REPO = Path(__file__).resolve().parents[2]
AUTHORIZATION_PATH = REPO/'reports/application-agent-enhancements/A15/campaign-008/matrix-014-authorization.json'
AUTHORIZATION_SHA256 = '4849dd9eaab0b987d2f1390b7043b72766b62c247003fb512d0a18bbb03bad3d'
AUTHORIZATION_ID = 'de2cde66-cbc1-4e9a-87c5-a0ca9c3e79d3'
WINDOW_AUTHORIZATION = {'path':str(REPO/'reports/application-agent-enhancements/A15/campaign-window-006-authorization.json'),
    'sha256':'60cd1a7fd2b1a2975e7fe3b357f6ebae5610e80a46c8d288d2d7600a27c04b27'}
PRIOR_ROOT = REPO/'reports/application-agent-enhancements/A15/attempt-013/qualification'
FINAL_ROOT = REPO/'reports/application-agent-enhancements/A15/attempt-014/qualification-002'
BINDING_ROOT = AUTHORIZATION_PATH.parent/'matrix-014-successor'
PRIOR_AMENDMENT_REFERENCE = {'path':str(prior_amendment.AUTHORIZATION_PATH),'sha256':prior_amendment.AUTHORIZATION_SHA256}
BOUNDARY_REFERENCE = copy.deepcopy(prior_amendment.BOUNDARY_REFERENCE)
STARTED_WALL = 1792336564.132689
STARTED_MONOTONIC = 616972.105809541
DEADLINE_WALL = 1792350964.132689
DEADLINE_MONOTONIC = 631372.105809541
_reference = prior_amendment._reference
_relative_reference = prior_amendment._relative_reference


def require(value):
    if not value:
        raise launch.LaunchError('qualification_matrix14_invalid')


def _authorization(reference):
    require(reference == {'path':str(AUTHORIZATION_PATH),'sha256':AUTHORIZATION_SHA256})
    value = _reference(reference)
    fixed = {'schema':1,'document_type':'qualification_matrix_requalification_authorization','authorization_id':AUTHORIZATION_ID,
        'final_root':str(FINAL_ROOT),'maximum_matrix_origins':14,'prior_matrix_origins':13,'cumulative_container_launches':105,
        'cumulative_participant_segments':1,'previous_container_cap':277,'container_cap':291,'participant_cap':25,'previous_participant_cap':24,'live_cap':4,
        'trial_cap':1,'inference_slot_cap':1,'platform':'linux/arm64','automatic_retries':0,'continuations':0,
        'planned_new_container_launches':186,'planned_new_participant_segments':24,'started_wall':STARTED_WALL,
        'started_monotonic':STARTED_MONOTONIC,'deadline_wall':DEADLINE_WALL,'deadline_monotonic':DEADLINE_MONOTONIC,
        'original_evidence_modified':False,'historical_windows_modified':False,'additional_auxiliary_launches_authorized':0,
        'additional_startup_diagnostic_authorized':False,'fifteenth_origin_authorized':False}
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
    return {**launch.LIMITS,'container_launch_attempts':291,'participant_segments':25}


def _cleanup(value, full, ledger):
    cleanup = _reference(value['prior_cleanup'])
    review = _reference(value['prior_independent_review'])
    boundary = _reference(value['prior_boundary_review'])
    require(cleanup['status'] == 'PASS' and cleanup['qualification_id'] == full['qualification_id']
        and cleanup['cumulative_container_launches'] == 105 and cleanup['participant_segments'] == 1
        and cleanup['live_owned_containers'] == 0 and cleanup['enforced_live_ceiling'] == 4
        and cleanup['safe_to_continue'] is False and cleanup['continued_execution_authorized'] is False
        and cleanup['safe_for_final_handoff'] is True and cleanup['qualification_eligible'] is False
        and cleanup['original_operator_store_touched'] is False and cleanup['raw_ledger_rewritten'] is False
        and cleanup['raw_product_private_cleanup_false_rows'] == 7 and cleanup['planned_rows'] == 364)
    for key in ('physical_absence_confirmed','private_cleanup_confirmed','master013_copy_removed','all105_ids_absent',
        'parent_envelope_removed','service_private_roots_removed','application_helper_private_removed','runtime_private_roots_removed',
        'all4_values_RAM_matched_and_scanned','owned_application_network_removed_and_released','retained_evidence_key_free',
        'retained_evidence_bytes_unchanged','raw_history_poison_and_pending_flags_preserved','raw_product_cleanup_unconfirmed_preserved'):
        require(cleanup[key] is True)
    require(cleanup['raw_ledger']['sha256'] == value['prior_ledger']['sha256'] and _relative_reference(cleanup['raw_ledger']) == ledger
        and review['status'] == boundary['status'] == 'PASS' and review['unresolved_findings'] == boundary['unresolved_findings'] == []
        and boundary['final_cleanup'] == value['prior_cleanup']
        and boundary['native_counters'] == {'containers':105,'participants':1,'raw_rows':364,'PASS':37,'BLOCKED':13,'NOT_RUN':314})
    for key in ('actual_master_parent_store_and_four_leaves_removed','five_selected_and_three_prior_credential_roots_absent',
        'retained_two_automatic_rawfiles_and178sealed_pins_unchanged','all28_current_registry_bodies_still_released_and_pinned',
        'all105_immutable_ids_positive_retained_absence','raw_five_pairs_poison_and_seven_privatefalse_unchanged'):
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
        require(proof['cumulative_container_launches'] == 105 and proof['participant_segments'] == 1
            and proof['all105_ids_absent'] is True and proof['original_lease_held'] is True and proof['controller_lock_held'] is True
            and proof['raw_history_unchanged'] is True)
    for key in ('physical_absence_confirmed','private_cleanup_confirmed','parent_envelope_removed','service_private_roots_removed',
        'remaining_runtime_private_roots_removed','all4_values_RAM_matched_and_scanned','raw_poison_and_flags_unchanged',
        'positive_participant_helper_cleanup_preserved','retained_evidence_key_free','retained_evidence_bytes_unchanged'):
        require(manual[key] is True)
    require(manual['retained_evidence_credential_match_count'] == 0 and manual['credential_values_or_hashes_retained'] is False
        and manual['raw_product_private_false_rows_preserved'] == 7
        and manual['retained_evidence_files_preserved'] == ['raw/.owner.lock','raw/state.json'])
    ids = cleanup['all_owned_container_ids']
    require(type(ids) is list and len(ids) == len(set(ids)) == 105
        and manual['all_owned_container_ids'] == physical['all_owned_container_ids'] == ids)
    for identifier in ids:launch._sha(identifier)
    require({row['container_id'] for row in ledger['launches']} <= set(ids))
    custody = _relative_reference(manual['manual_owner_custody'])
    require(custody['status'] == 'PASS' and custody['qualification_id'] == full['qualification_id']
        and custody['cumulative_container_launches'] == 105 and custody['participant_segments'] == 1
        and custody['all_owned_container_ids'] == ids and custody['raw_product_and_history_unchanged'] is True
        and custody['report_repaired'] is False and custody['positive_participant_cleanup_preserved'] is True
        and custody['positive_helper_cleanup_preserved'] is True)
    roots, absent = custody['private_roots_removed'], custody['already_removed_private_roots_verified']
    require(type(roots) is list and len(roots) == len(set(roots)) == 5 and type(absent) is list and len(absent) == len(set(absent)) == 3
        and not set(roots)&set(absent) and roots == manual['selected_private_roots_removed'] == cleanup['selected_private_roots_removed']
        and absent == manual['already_removed_private_roots_verified'] == cleanup['already_removed_private_roots_verified'])
    for path in roots+absent:require(registry_api._qualification_absent(str(launch._canonical_root(path))))
    registry_root = Path.home()/'.local/state/pi-agentic-development/operation.lock.registry'
    command = _relative_reference(cleanup['master_cleanup_command'])
    require(command['status'] == 'PASS' and type(command['actual_exit']) is int and command['actual_exit'] == 0
        and command['native_launches'] == 0 and command['credential_values_opened'] is False and command['automatic_retry_performed'] is False)
    observed = command['custody_before_action']
    require(observed['status'] == 'PASS' and observed['target'] == full['secrets_dir']
        and observed['cumulative_container_launches'] == 105 and observed['participant_segments'] == 1
        and observed['original_lease_held'] is True and observed['controller_lock_held'] is True
        and observed['all_known_container_ids_freshly_absent'] is True and observed['actual_container_id_count'] == 105)
    references = observed['current_registry_records']
    require(type(references) is list and len(references) == 28 and len({r['path'] for r in references}) == 28)
    expected_paths = {str(registry_root/(row['launch_id']+'.json')) for row in ledger['launches']}
    network_path = str(registry_root/(physical['network_record_released']+'.json'))
    expected_paths.add(network_path)
    require(expected_paths <= {r['path'] for r in references})
    pinned = {}
    for bound in references:
        launch._exact(bound,{'path','sha256'});launch._sha(bound['sha256'])
        path = Path(bound['path']);require(path.parent == registry_root);launch._uuid(path.stem)
        record = launch._bound_json(bound['path'],bound['sha256'])
        require(record['status'] == 'released' and record['daemon'] == ledger['daemon'])
        pinned[bound['path']] = record
    helper = None
    for row in ledger['launches']:
        record = pinned[str(registry_root/(row['launch_id']+'.json'))]
        require(launch._intent_identity(record) == row['intent_sha256']
            and all(record[k] == row[k] for k in ('launch_id','registry','generation','image','container'))
            and record.get('container_id') in (None,row['container_id']))
        if row['role'] == 'application-helper':helper = record
    require(helper is not None and helper['application_helper'] is True and helper['client_mode'] == 'application-execution'
        and helper['private_store'] in absent and helper['container_id'] == next(r['container_id'] for r in ledger['launches'] if r['role']=='application-helper'))
    network = pinned[network_path]
    require(physical['network_cleanup_confirmed'] is True and network['kind'] == 'network'
        and network['registry'] == helper['registry'] and network['generation'] == helper['generation']
        and network['container'] == helper['container']+'-network' and network['runroot'] in (None,helper['runroot']))
    receipts = [_reference(bound) for bound in manual['service_cleanup_receipts']]
    services = [row for row in ledger['launches'] if row['role'] in ('fixture','scripted-inference')]
    require(len(receipts) == 2 and {r['launch_id'] for r in receipts} == {r['launch_id'] for r in services})
    for receipt in receipts:
        row = next(row for row in services if row['launch_id'] == receipt['launch_id'])
        require(receipt['document_type'] == 'qualification_service_cleanup' and receipt['physical_absence_confirmed'] is True
            and receipt['private_bootstrap_removed'] is True and receipt['daemon'] == ledger['daemon']
            and all(receipt[k] == row[k] for k in ('launch_id','registry','generation','image','container','container_id','intent_sha256','role','cell')))
    # The two automatic evidence files were deliberately retained, never purged.
    source_review = _relative_reference(private_review['source_input_review'])
    require(source_review['status'] == 'PASS' and source_review['unresolved_findings'] == [])
    inputs = _reference({'path':str(PRIOR_ROOT.parent/'manual-cleanup-design/design-inputs-002.json'),'sha256':source_review['design_inputs_sha256']})
    evidence = {p:h for p,h in inputs['history_pins'].items() if '/application-evidence/' in p}
    require(len(evidence) == 2 and {str(Path(p).relative_to(Path(p).parents[1])) for p in evidence} == {'raw/.owner.lock','raw/state.json'})
    for path, digest in evidence.items():
        launch._sha(digest);canonical = launch._canonical_root(str(REPO/path))
        require(canonical.is_relative_to(PRIOR_ROOT) and 'application-evidence' in canonical.parts)
        fd = launch._dir(canonical.parent)
        try:
            leaf = launch._file(fd,canonical.name,os.O_RDONLY)
            try:
                before = os.fstat(leaf);data = os.read(leaf,launch.MAX_BYTES+1);after = os.fstat(leaf)
                named = os.stat(canonical.name,dir_fd=fd,follow_symlinks=False)
                identity = lambda st:(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
                require(identity(before)==identity(after)==identity(named) and len(data)<=launch.MAX_BYTES and hashlib.sha256(data).hexdigest()==digest)
            finally:os.close(leaf)
        finally:os.close(fd)
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
    require((prior['attempts'],prior['participant_segments'],prior['planned_cells'],len(prior['lineage'])) == (91,0,336,12))
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
    require(ledger['poisoned'] is True and len(ledger['launches']) == 14 and now >= ledger['last_now'] and wallnow >= ledger['last_wall'])
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
        and all(r['cell'] == active['id'] and r['private_cleanup'] is (r['role']=='application-helper') for r in rows[6:])
        and [r['role'] for r in rows[6:]] == ['fixture','scripted-inference','probe','boundary','preflight','application-helper','participant','scorer']
        and [r['physical'] for r in rows[6:]] == ['uncertain','absent','absent','absent','absent','absent','absent','absent'])
    require(len({r['container_id'] for r in rows}) == 14 and None not in {r['container_id'] for r in rows})
    _cleanup(value,full,ledger)
    old_rows = [{'qualification_id':full['qualification_id'],'cell':cell['id'],'status':state['cells'].get(cell['id'],{}).get('status','NOT_RUN'),
        'attempts':state['cells'].get(cell['id'],{}).get('attempts',0)} for cell in cells]
    require(len(old_rows) == 28 and full['qualification_id'] not in {entry['qualification_id'] for entry in prior['lineage']})
    hashes = {key:value['prior_'+key.removesuffix('_sha256')]['sha256'] for key in ('manifest_sha256','state_sha256','ledger_sha256')}
    return {**prior,'attempts':105,'participant_segments':1,'qualification_id':full['qualification_id'],'planned_cells':364,**hashes,
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
    require(launch._canonical_root(str(root))==FINAL_ROOT/'launch-ledger' and len(carry['lineage'])==13 and carry['attempts']==105
        and carry['participant_segments']==1 and carry['campaign_amendment']==manifest['campaign_amendment'])
    reference=manifest['campaign_amendment'];_fence(reference,carry)
    binding=campaign.read(BINDING_ROOT/'candidate-binding.json');launch._exact(binding,{'schema','amendment','qualification_id','full_manifest','candidate','launch_manifest_sha256'})
    full=_reference(binding['full_manifest']);candidate=_reference(binding['candidate'])
    require(type(binding['schema']) is int and binding['schema']==1 and binding['amendment']==reference and binding['qualification_id']==manifest['qualification_id']
        and binding['full_manifest']['path']==str(FINAL_ROOT/'manifest.json') and binding['candidate']['path']==str(FINAL_ROOT/'candidate.json')
        and candidate['scope']=='extracted_candidate' and candidate['runner_sha256']==full['source']['runner']
        and binding['launch_manifest_sha256']==launch._digest(manifest) and launch._json(_launch_policy(full,reference))==launch._json(manifest))
    expected={'schema':1,'document_type':'qualification_matrix_amendment_launch_binding','amendment':reference,'qualification_id':manifest['qualification_id'],
        'manifest_sha256':launch._digest(manifest),'ledger_root':str(root),'cumulative_attempts':105,'participant_segments':1,
        'candidate_binding':campaign.ref(BINDING_ROOT/'candidate-binding.json')}
    if create:campaign.exclusive(BINDING_ROOT/'launch-binding.json',expected)
    require(campaign.read(BINDING_ROOT/'launch-binding.json')==expected)
