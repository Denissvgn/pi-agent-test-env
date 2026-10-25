"""Pure, finite-copy origin19 scoped checker compatibility. No host/runtime IO.

This verifies actual C14 public metadata checks, not an executed legacy cleanup
validator. Unknown old POSIX wait/RAM/census stay unknown; native eligibility is
always separate. Missing required copied evidence refuses.
"""
import copy
import hashlib
import json
from pathlib import Path

NAMES = ('original_controller_and_owner_terminal_provenance',
         'original_guest_and_owned_sensitive_file_cleanup')
KIND = 'reviewed_scoped_source_checks'
class ScopedCoverageError(ValueError):pass

def need(v):
    if not v:raise ScopedCoverageError('origin19_scoped_coverage_unconfirmed')

def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,ensure_ascii=False,
    separators=(',',':'),allow_nan=False).encode()).hexdigest()

METHOD = {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/campaign-014/interruption-authority-design/prepare_public_freeze.py', 'sha256': '2e17b5d26a9b8299e4311c08b14ad2e237c5a7bae48976971903b2b29d504bcf', 'callable': 'main'}
SUBJECTS = {'manifest': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-019/qualification/manifest.json', 'sha256': 'd34552ccf61024e53be188ef7e6028f98a8edc98bc7c1121bbf76f6e15dd6bd5'}, 'state': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-019/qualification/state.json', 'sha256': '7f1b563334acd5b4d8c0f055441e1db6fe2ef320eeef0f605d2e323491fcf325'}, 'ledger': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-019/qualification/launch-ledger/ledger.json', 'sha256': 'c25b2a1f751e401d5f454faaae9b8e9ca37591ce4bdb99a22c6bc738f0d1ed71'}}
DOCS = {'prior_cleanup': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-019/final-cleanup.json', 'sha256': '65a0008c8c005955949c5ab2d11e452ecb8d1e8c57376b02fc2ce56f5b2c10b7'}, 'prior_cleanup_review': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-019/final-cleanup-independent-review/review.json', 'sha256': '362d24548a9a5f6b7eaf0a0064b955ffa3bd3194b98bed16d1b084e379fdabc7'}, 'prior_file_hygiene_review': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-019/final-task-file-hygiene-independent-review-001/review.json', 'sha256': 'c18dbe08493e0e45e602efb591a93a4a72b26533d1ba00a9dd7f6030c4321bf9'}, 'handoff': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A16/attempt-018/handoff.json', 'sha256': '15c733c2f03f5aaf3db8810b452c2d706059407fd2a3d793924c654148eb8fb8'}, 'R2': {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A16/attempt-018/final-audit-independent-review-001/review.json', 'sha256': 'da14faf8c5f030d0fe76a53ba911e0f5c88c5fb45112cae2e54b4970e62dc4b1'}}
BASELINE = {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/campaign-014/interruption-authority-design/baseline-001/verification.json', 'sha256': 'b434a55448e6192253d70df25715ac68333c25bdd2376132d7b12329e843880b'}
ACTUAL_REVIEW = {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-027/predicate-facts-001/origin19-actual-scoped-checker-review-001.json', 'sha256': 'b8868524ac5b725765dc0b0520600e0945e9de0c7488859167be04a372a64f0e'}
CAPABILITY = {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/attempt-019/host-file-writer-capability-002.json', 'sha256': '1036a787143bda5991866a7edf14b0d5f06ec756ce03f223782a4615066443ed'}
CAPABILITY_REVIEW = {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/campaign-013/owner-terminal-chain-design/host-file-writer-capability-independent-review-001.json', 'sha256': '89da714c86c98ce40bd277cad99ac69a44f0507c1a487a74afe86476edeb625f'}
OWNER = {'path': '/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/campaign-013/owner-terminal-chain-design/source-protocol-independent-assessment-001.json', 'sha256': '2e70bc7ec4d64998345d08a755b4e2b3ad163f2ca58ee64eb367231ef829f3fb'}

def source_checks(docs):
    cleanup=docs['prior_cleanup']
    need(cleanup['status']=='PASS'and cleanup['cumulative_container_launches']==328 and cleanup['participant_segments']==21 and cleanup['real_model_participant_segments']==0 and cleanup['all274_task_records_released']is True and cleanup['master019_copy_removed']is True and cleanup['all_known_owned_file_contexts_closed']is True and cleanup['global_actor_terminal_status']=='PENDING'and cleanup['individual_unknown_hostclient_wait_or_reap_confirmed']is False and cleanup['all_credential_memory_erased_claimed']is False and cleanup['census_complete']is False)
    need(docs['handoff']['status']=='NOT_READY'and docs['handoff']['cumulative_container_intents']==328 and docs['R2']['status']=='PASS'and docs['R2']['unresolved_findings']==[]and docs['R2']['supports_actual_final_publication']is True and docs['prior_cleanup_review']['status']=='PASS'and docs['prior_file_hygiene_review']['status']=='PASS')


def evaluate(closure,event,predicate):
    need(closure is not None and type(event)is dict and type(event.get('origin'))is int
        and event['origin']==19 and predicate in NAMES)
    need(all(event.get(k)==v for k,v in SUBJECTS.items()))
    seen={}
    def get(ref,kind='operational-projection'):
        value=closure.get(ref,kind)
        if kind=='operational-projection':seen[(ref['path'],ref['sha256'])]=copy.deepcopy(ref)
        return value
    receipt=get(BASELINE);review=get(ACTUAL_REVIEW)
    need(receipt['document_type']=='qualification_public_source_and_historical_preservation_baseline'
        and receipt['status']=='PASS' and receipt['program']==METHOD_SOURCE
        and receipt['counter_baseline']=={'container_intents':328,'scripted_participant_intents':21,'real_model_participants':0})
    need(review['document_type']=='independent_origin19_actual_scoped_main_result_review'
        and review['status']=='PASS' and review['unresolved_findings']==[]
        and review['supports_actual_scoped_original19_file_checker_result'] is True
        and review['supports_binding_actual_scoped_main_without_rename'] is True
        and review['actual_scoped_method']['source']==METHOD_SOURCE
        and review['actual_scoped_method']['callable']=='main'
        and review['actual_scoped_method']['published_check_receipt']==BASELINE
        and review['original19_subject_refs']==SUBJECTS
        and review['supports_original19_legacy_own_cleanup_validator_execution'] is False
        and review['supports_original19_all_controller_POSIX_waits'] is False
        and review['supports_original19_global_RAM_or_census_clearance'] is False
        and review['supports_native_or_old_scope_resume'] is False)
    for k,ref in SUBJECTS.items():need(receipt['public_references']['raw_'+k+'.json']==ref)
    for k,ref in DOCS.items():need(receipt['public_references'][k]==ref)
    docs={k:get(ref)for k,ref in DOCS.items()};source_checks(docs)
    cleanup=docs['prior_cleanup']
    need(cleanup['document_type']=='qualification_scoped_final_file_cleanup'
        and cleanup['scope']=='task_scoped_file_hygiene_with_trusted_platform_readcache'
        and cleanup['all_known_private_roots_closed'] is True and cleanup['private_store_readers']==0
        and cleanup['raw_poison_private_flags_and_stale_active_preserved'] is True
        and cleanup['safe_to_continue'] is False and cleanup['qualification_eligible'] is False)
    ledger=get(SUBJECTS['ledger'],'ledger');state=get(SUBJECTS['state'],'state')
    full=get(SUBJECTS['manifest'],'manifest');rows=ledger['launches']
    need(full['prepared_root']==str(Path(SUBJECTS['manifest']['path']).parent)
        and len(rows)==53 and len({r['launch_id']for r in rows})==53
        and ledger['poisoned'] is True and sum(r['private_cleanup'] is False for r in rows)==4
        and ledger['carry']['attempts']==275 and ledger['carry']['participant_segments']==15
        and state['phase']=='blocked')
    ids=cleanup['all_owned_container_ids']
    need(type(ids)is list and len(ids)==len(set(ids))
        and all(r['physical']=='absent' and r['container_id'] is not None and r['container_id']in ids for r in rows))
    # Exact source-reviewed fixed-client exclusion, not an old OS wait claim.
    pending=[r for r in rows if r['pid'] is None]
    need(len(pending)==1 and pending[0]['container_id'] is not None)
    row=pending[0];cap=get(CAPABILITY);peer=get(CAPABILITY_REVIEW)
    need(cap['status']=='PASS' and cap['launch_id']==row['launch_id']
        and cap['immutable_container_id_from_ledger']==row['container_id']
        and cap['fixed_builtin_docker_run'] is True
        and cap['host_file_output_or_envfile_options_present'] is False
        and cap['close_fds_default_true'] is True
        and cap['pass_fds_or_shell_or_executable_override_in_source'] is False
        and cap['inherited_environment_may_have_credentials'] is True
        and cap['individual_hostclient_wait_or_reap_attested'] is False
        and cap['hostclient_terminal_confirmed'] is False)
    need(peer['status']=='PASS' and peer['unresolved_findings']==[]
        and peer['supports_host_file_writer_capability_analysis'] is True
        and peer['supports_selected_file_writer_scope_input'] is True
        and peer['host_file_writer_capability']==CAPABILITY)
    need(peer['source_owner_assessment']==OWNER)
    owner=get(OWNER)
    need(owner['status']=='PASS' and owner['unresolved_findings']==[]
        and owner['source_owner_terminal_chain_reviewed'] is True
        and owner['unresolved_inner_hostclient']['launch_id']==row['launch_id']
        and owner['unresolved_inner_hostclient']['individual_wait_or_reap_confirmed'] is False
        and owner['unresolved_inner_hostclient']['hostclient_terminal_confirmed'] is False)
    for doc in (cleanup,):
        need(doc['global_actor_terminal_status']=='PENDING'
            and doc['individual_unknown_hostclient_wait_or_reap_confirmed'] is False
            and doc['all_credential_memory_erased_claimed'] is False and doc['census_complete'] is False)
    need(receipt['prior_global_actor_status']=='PENDING'
        and receipt['prior_inner_client_reap_or_memory_clearance_claimed'] is False
        and receipt['prior_census_complete'] is False and receipt['prior_raw_ledger_poisoned'] is True
        and receipt['prior_raw_private_cleanup_false_count']==4
        and receipt['prior_scoped_task_records_released']==274)
    return {'evidence_kind':KIND,'actual_method':copy.deepcopy(METHOD),
        'scoped_check_receipt':copy.deepcopy(BASELINE),'scoped_check_review':copy.deepcopy(ACTUAL_REVIEW),
        'coverage_state':'SUPPORTED_AT_EXISTING_SCOPED_FILE_BOUNDARY',
        'legacy_original_cleanup_execution_claimed':False,
        'evidence':[seen[k]for k in sorted(seen)]}

METHOD_SOURCE={k:METHOD[k]for k in ('path','sha256')}

METHOD_OBJECT = {**METHOD,'evidence_kind':KIND,'check_receipt':BASELINE,
    'check_review':ACTUAL_REVIEW,'scope':'origin19_task_scoped_FILE_and_owner_provenance',
    'legacy_original_cleanup_execution_claimed':False}

def validate(closure,event,predicate,proof):
    need(proof.get('original_validator')==METHOD_OBJECT)
    result=evaluate(closure,event,predicate)
    # Preserve the existing evidence[] carrier; every supplied ref still must
    # be classified. All exact required named facts must be present, never
    # replaced by a governing name or generic support boolean.
    actual=proof.get('evidence');need(type(actual)is list and actual)
    seen=set()
    for ref in actual:
        closure.get(ref,'operational-projection');seen.add((ref['path'],ref['sha256']))
    need({(r['path'],r['sha256'])for r in result['evidence']} <= seen)
    return result
