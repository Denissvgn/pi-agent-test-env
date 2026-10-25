"""Explicit source-scoped prior22 support and six new browser trials.

This mode never relabels old runs or relaxes retained9/fresh19 runner equality.
A separately reviewed capture attester supplies immutable historical snapshot
identities; original predicates and scans are explicitly reused, never rerun. Dispatch requires a new bound530/46 authorization.
"""
import copy
import hashlib
import math
import os
from pathlib import Path
import re

import application_retained as retained

MODE='source_scoped_retained22_fresh6_browser_v1'
HISTORICAL_USE={'containers':488,'participants':40}
LOCAL_PLAN={'containers':42,'participants':6}
CUMULATIVE_CEILING={'containers':530,'participants':46}
LIMITS={**retained.LIMITS,'container_launch_attempts':42,'participant_segments':6}
FRESH_IDS=tuple('N04-'+release+'-'+str(i)for release in('0.87.1','1.2.0')for i in range(1,4))
PRIOR_IDS=tuple(x for x in retained.RETAINED_IDS)+tuple('N02-0.87.1-commit-and-interruption-b'for _ in range(1))+tuple(
 'N02-1.2.0-'+case+'-'+variant for case,variant in retained.NEGATIVES)+tuple(
 'N03-'+release+'-'+str(i)for release in('0.87.1','1.2.0')for i in range(1,4))
PHASES=(('N04','0.87.1'),('N04','1.2.0'))
SOURCE044_ARCHIVE='133c10fce97f3250d277b6810113eb72fc66b631919d3fad209932945912d02d'
SOURCE044_RUNNER='bf6b89aa7b66b786201bf186703430dda63cfd9a7fcf1304d0a37d00e4d12f2d'
CURRENT_RUNNER='77763ad0c3089970e9f8bae81b826085b7e2922dc599b07bdbf0fd9c70b6e530'
OLD_SERVICE='b8d78a4f6c126186ff397fef6d641fe5d3989d22dc1df602cad14a0322bd95c9'
CURRENT_SERVICE='0086c65bc4c3930bc5f25f7cde8a6de477967fb902ed4a126e6e7d99f280047b'
OLD_SDK='38504cb22eb985f1bfa3568085d31109ec4edb889680c314ce2fd6e7db35a1a5'
CURRENT_SDK='ddc151b3eb782041bbe57f61a4bda6291e9a4d43694ec1c292723047c79da3f7'
HISTORY_VERIFIER_SHA='99d0be0cae7572566e6cd4ffbebaacc276317fbaae45d745fda9f7deb119daac'
HISTORY_PRODUCER_BASENAME='build_prior_history_capture_attestation_003.py'
HISTORY_ATTESTATION_PATH=Path('/home/piqual/a15-clean-060/prior-history-capture-attestation.json')
HISTORY_STAGE=Path('/home/piqual/a15-clean-059')
HISTORY_VALIDATION_SCOPE={'original_validations':'REUSED_REVIEWED_CLOSED_CAPTURES','known_value_scans':'REUSED_REVIEWED_CLOSED_CAPTURES',
 'original_predicates_reexecuted':False,'known_value_scans_reexecuted':False,
 'transitive_raw_bodies_exported':False,'current_original_files_census':False}
SOURCE_CHANGES=frozenset(('tools/qualification/application_client.py','tools/qualification/application_launch.py',
 'tools/qualification/application_operational_replay.py','tools/qualification/application_sdk_admission.py',
 'tools/qualification/application_browser_followup.py'))
SEMANTIC_FIELDS=('images','endpoint','endpoint_sha256','fixture_route','credential_references','session',
                 'host_admission','negative_oracles','sensitive_negative_scope')
INDEX_FIELDS={'schema','document_type','prior_root','prior_manifest','prior_candidate','prior_state','prior_ledger',
 'legacy_index','legacy_compatibility','owned_cleanup','owned_cleanup_review','historical_verification',
 'historical_use','excluded_failed_browser','cells'}
ATTESTATION_FIELDS={'schema','document_type','status','verifier','source_archive_sha256','prior_root',
 'prior_manifest','prior_candidate','prior_state','prior_ledger','legacy_index','legacy_compatibility',
 'owned_cleanup','owned_cleanup_review','historical_use','cells','immutable_roles','effects',
 'validation_scope','reviewed_captures','independent_reviews'}
CERTIFICATE_FIELDS={'schema','document_type','status','unresolved','index_sha256','historical_verification_sha256',
 'old_source','new_source','production_delta','changed_qualification_files','semantic_inputs_sha256',
 'owned_cleanup_sha256','owned_cleanup_review_sha256'}
LAUNCH_FIELDS=retained.LAUNCH_FIELDS
_require=retained._require
_exact=retained._exact
_read=retained._read
def _path(value):
    path=retained._path(value)
    _require(not any(ord(ch)<32 or ord(ch)==127 for ch in value))
    return path


def _reference(value,expected=None):
    path=retained._reference(value,expected);_path(value['path']);return path


def partition(cells):
    _require(type(cells)is list and len(cells)==28)
    _require(len({row['id']for row in cells})==28)
    old=[copy.deepcopy(row)for row in cells if row['id']in PRIOR_IDS]
    fresh=[copy.deepcopy(row)for row in cells if row['id']in FRESH_IDS]
    _require(len(old)==22 and len(fresh)==6 and len(PRIOR_IDS)==22)
    _require(tuple(row['id']for row in fresh)==FRESH_IDS)
    _require(sum(row['container_launches_max']for row in fresh)==42
             and sum(row['participant_segments_max']for row in fresh)==6)
    for row in fresh:
        _require(row['group']=='N04'and row['profile']=='browser'and row['real_model']is True
                 and type(row['max_attempts'])is int and row['max_attempts']==1
                 and row['role_limits']==dict.fromkeys(('fixture','probe','boundary','preflight','application-helper','participant','scorer'),1)
                 and all(type(v)is int and v==1 for v in row['role_limits'].values()))
    return old,fresh


def validate_marker(value):
    _exact(value,{'schema','mode','evidence_index','compatibility_review','historical_use','local_plan','cumulative_ceiling','authorization_required'})
    _require(type(value['schema'])is int and value['schema']==1 and value['mode']==MODE
             and value['authorization_required']is True)
    for key,expected in(('historical_use',HISTORICAL_USE),('local_plan',LOCAL_PLAN),('cumulative_ceiling',CUMULATIVE_CEILING)):
        _exact(value[key],expected);_require(value[key]==expected and all(type(v)is int for v in value[key].values()))
    _reference(value['evidence_index']);_reference(value['compatibility_review'])
    return copy.deepcopy(value)


def effective_limits(manifest):
    _require(not set(manifest)&{'predecessor','campaign_boundary','campaign_amendment','retained_requalification','diagnostic'})
    validate_marker(manifest['browser_followup'])
    limits=dict(LIMITS)
    if 'schema'in manifest:
        limits['simultaneously_registered_live_container_intents']=limits.pop('live')
        limits.update(automatic_retries=0,continuations=0)
    return limits


def launch_manifest(q,manifest):
    validate_marker(manifest['browser_followup'])
    return {'qualification_id':manifest['qualification_id'],'images':copy.deepcopy(manifest['images']),
      'cells':[{k:copy.deepcopy(cell[k])for k in LAUNCH_FIELDS}for cell in manifest['cells']],
      'limits':dict(LIMITS),'planned_container_launches':42,
      'browser_followup':copy.deepcopy(manifest['browser_followup'])}


def _source_compatibility(q,review,index,prior):
    _exact(review,CERTIFICATE_FIELDS)
    _require(type(review['schema'])is int and review['schema']==1
      and review['document_type']=='application_browser_followup_compatibility_review'
      and review['status']=='PASS'and review['unresolved']==[]and review['index_sha256']==q.c.digest(index))
    old,new=review['old_source'],review['new_source']
    _require(old==prior['source']and new==q.source_identity())
    _require(q.c.digest(old['runner_files'])==old['runner']==SOURCE044_RUNNER
             and q.c.digest(new['runner_files'])==new['runner']==CURRENT_RUNNER
             and q.c.digest(old['files'])==old['sha256']and q.c.digest(new['files'])==new['sha256'])
    _require(old['release_contracts']==new['release_contracts']and set(old['runner_files'])==set(new['runner_files']))
    changed={key for key in old['runner_files']if old['runner_files'][key]!=new['runner_files'][key]}
    _require(changed=={'runtime/application_client_service.py'}
      and old['runner_files']['runtime/application_client_service.py']==OLD_SERVICE
      and new['runner_files']['runtime/application_client_service.py']==CURRENT_SERVICE)
    _require(review['production_delta']=={'path':'runtime/application_client_service.py','before':OLD_SERVICE,'after':CURRENT_SERVICE})
    changed=sorted(key for key in set(old['files'])|set(new['files'])if old['files'].get(key)!=new['files'].get(key))
    _require(set(changed)<=SOURCE_CHANGES and review['changed_qualification_files']==changed
      and old['files']['tools/qualification/application_sdk_admission.py']==OLD_SDK
      and new['files']['tools/qualification/application_sdk_admission.py']==CURRENT_SDK)
    _require(review['semantic_inputs_sha256']==q.c.digest({k:prior[k]for k in SEMANTIC_FIELDS}))
    _require(review['historical_verification_sha256']==index['historical_verification']['sha256']
      and review['owned_cleanup_sha256']==index['owned_cleanup']['sha256']
      and review['owned_cleanup_review_sha256']==index['owned_cleanup_review']['sha256'])


def _cell_paths(row,cell,root):
    _exact(row,{'cell_id','source_origin','kind','run_id','attempt_id','original_status','roles'})
    _require(row['cell_id']==cell['id']and row['original_status']=='PASS')
    folder=root/'cells'/cell['id'];roles=row['roles']
    if cell['group']=='N01':
        _require(row['kind']=='admission'and row['run_id']is None and row['attempt_id']is None)
        _exact(roles,{'admission'});path=_reference(roles['admission'])
        _require(path==folder/'runtime.json'if cell['profile']=='core'else
            path.name=='browser-admission.json'and path.parent.parent==folder and re.fullmatch(r'browser-[a-f0-9]{32}',path.parent.name)is not None)
        return
    retained._uuid(row['run_id']);retained._uuid(row['attempt_id'])
    run=(root/('scripted-'+cell['release'])/'runs'if cell['group']=='N02'else folder/'runs')/row['run_id']
    paths={'qualification':folder/'qualification.json','result':run/'result.json','plan':run/'plan.json',
      'oracle':folder/'oracle.json','journal':folder/'fixture-journal/private/journal.json',
      'fixture_terminal':folder/'fixture-journal/private/terminal-receipt.json',
      'services_cleanup':folder/'services-cleanup.json','child_completion':folder/'child-completion.json'}
    sensitive=cell.get('scenario')=='sensitive-participant-interruption'
    if not sensitive:paths['parent_receipt']=folder/'fixture-journal/private/parent-receipt.json'
    if cell['group']=='N02':
        _require(row['kind']=='negative');retained._uuid(cell['trial_id'])
        paths.update(attempt_intent=root/('scripted-'+cell['release'])/'attempts'/cell['trial_id']/('0001-'+row['attempt_id']+'.json'),
                     scripted=folder/'scripted-observations/private/scripted.json')
        if sensitive:
            descriptor=_reference(roles['stage_descriptor']);retained._uuid(descriptor.parent.name)
            _require(descriptor.name=='descriptor.json'and descriptor.parent.parent==run/'stages');paths['stage_descriptor']=descriptor
    else:_require(row['kind']=='api'and cell['group']=='N03')
    _exact(roles,paths)
    for name,path in paths.items():_reference(roles[name],path)


def _immutable_roles(references,root,legacy_root,outside,passed_runs):
    """Classify the complete finite metadata set before reading any role body."""
    _require(type(references)is list and len(references)<=2048)
    seen=set();classified=[]
    for reference in references:
        path=_reference(reference);_require(reference['path']not in seen);seen.add(reference['path'])
        _require(path.is_relative_to(root)or path.is_relative_to(legacy_root)or path in outside)
        _require(not set(path.parts)&{'workspace','workspaces','controls','application-helpers','application-startup','secrets','private-store','.config','private-dispatch'}
                 and path.name not in {'files.json','initial.json','application-context.json','application-credentials.json','private-envelope.json'})
        for namespace,selected in((root,set(PRIOR_IDS)-set(retained.RETAINED_IDS)),(legacy_root,set(retained.RETAINED_IDS))):
            if path.is_relative_to(namespace/'cells'):
                relative=path.relative_to(namespace/'cells')
                _require(len(relative.parts)>=2 and relative.parts[0]in selected)
        if 'runs'in path.parts:_require(any(path.is_relative_to(run)for run in passed_runs))
        _require(not path.is_relative_to(root/'cells'/'N04-0.87.1-1')
             and not path.is_relative_to(legacy_root/'cells'/retained.FAILED_CELL))
        classified.append((reference,path))
    return classified,seen


def _validate_attestation(attestation,index):
    _exact(attestation,ATTESTATION_FIELDS)
    retained._sha(HISTORY_VERIFIER_SHA);_reference(attestation['verifier'])
    _require(attestation['schema']==1 and type(attestation['schema'])is int
      and attestation['document_type']=='source044_browser_followup_reviewed_capture_attestation'
      and attestation['status']=='PASS_22_REVIEWED_HISTORICAL_SNAPSHOTS'and attestation['source_archive_sha256']==SOURCE044_ARCHIVE
      and attestation['verifier']['sha256']==HISTORY_VERIFIER_SHA and attestation['historical_use']==HISTORICAL_USE)
    _require(_path(attestation['verifier']['path']).name==HISTORY_PRODUCER_BASENAME
      and attestation['validation_scope']==HISTORY_VALIDATION_SCOPE
      and all(type(attestation['validation_scope'][key])is bool for key in
         ('original_predicates_reexecuted','known_value_scans_reexecuted','transitive_raw_bodies_exported','current_original_files_census')))
    for key,count in(('reviewed_captures',5),('independent_reviews',None)):
        refs=attestation[key]
        _require(type(refs)is list and (len(refs)==count if count is not None else 1<=len(refs)<=16))
        for ref in refs:_reference(ref)
        _require(len({ref['path']for ref in refs})==len(refs))
    for key in('prior_root','prior_manifest','prior_candidate','prior_state','prior_ledger','legacy_index','legacy_compatibility','owned_cleanup','owned_cleanup_review'):
        _require(attestation[key]==index[key])
    _exact(attestation['effects'],{'record_writes','SDK_contexts','Docker_calls','network_calls','model_calls','credential_resolution'})
    _require(all(type(v)is int and v==0 for v in attestation['effects'].values()))
    return attestation


def _evidence(q,index,review):
    _exact(index,INDEX_FIELDS)
    _require(type(index['schema'])is int and index['schema']==1 and index['document_type']=='application_browser_followup_evidence_index'
      and index['historical_use']==HISTORICAL_USE and all(type(v)is int for v in index['historical_use'].values()))
    root=_path(index['prior_root'])
    for key,leaf in(('prior_manifest','manifest.json'),('prior_candidate','candidate.json'),('prior_state','state.json'),
       ('prior_ledger','launch-ledger/ledger.json'),('legacy_index','retained-evidence-index.json'),('legacy_compatibility','retained-compatibility-review.json')):
        _reference(index[key],root/leaf)
    _require(index['excluded_failed_browser']=={'cell_id':'N04-0.87.1-1','disposition':'NOT_RETAINED','reason':'browser_startup_unqualified_no_participant'})
    attestation_path=_reference(index['historical_verification'])
    _require(attestation_path==HISTORY_ATTESTATION_PATH)
    stage=HISTORY_STAGE
    _reference(index['owned_cleanup'],stage/'owned-browser-cleanup-001/result.json')
    _reference(index['owned_cleanup_review'],stage/'prior044-browser-owned-cleanup-review-002.json')
    rows=index['cells'];_require(type(rows)is list and len(rows)==22)
    known_roles={'admission','attempt_intent','qualification','result','plan','oracle','journal','parent_receipt',
                 'fixture_terminal','scripted','services_cleanup','child_completion','stage_descriptor'}
    for row in rows:
        _exact(row,{'cell_id','source_origin','kind','run_id','attempt_id','original_status','roles'})
        _require(row['cell_id']in PRIOR_IDS and row['source_origin']in('source042','source044')
          and row['kind']in('admission','negative','api')and row['original_status']=='PASS'
          and type(row['roles'])is dict and set(row['roles'])<=known_roles)
        for reference in row['roles'].values():_reference(reference)
        for field in('run_id','attempt_id'):
            if row[field]is not None:retained._uuid(row[field])
    _require(len({r['cell_id']for r in rows})==22)
    prior=_read(q,index['prior_manifest']);_source_compatibility(q,review,index,prior)
    _require(prior['prepared_root']==str(root)and prior['planned_container_launches']==140)
    retained.validate_marker(prior['retained_requalification'])
    _require(prior['retained_requalification']['retained_index']==index['legacy_index']
             and prior['retained_requalification']['compatibility_review']==index['legacy_compatibility'])
    candidate=_read(q,index['prior_candidate'])
    _require(candidate=={'archive_sha256':SOURCE044_ARCHIVE,'runner_sha256':SOURCE044_RUNNER,'scope':'extracted_candidate'})
    legacy=_read(q,index['legacy_index']);legacy_root=_path(legacy['prior_root'])
    original=_read(q,legacy['prior_manifest']);full=q.matrix(prior['images']);byid={c['id']:c for c in full}
    retained.validate_index(legacy,original['cells'])
    state=_read(q,index['prior_state']);ledger=_read(q,index['prior_ledger'])
    new_prior=set(PRIOR_IDS)-set(retained.RETAINED_IDS);failed='N04-0.87.1-1'
    _require(state['phase']=='blocked'and set(state['cells'])==new_prior|{failed}
      and all(state['cells'][name].get('status')=='PASS'and state['cells'][name].get('attempts')==1 for name in new_prior)
      and state['cells'][failed].get('status')=='BLOCKED')
    _require(ledger['poisoned']is True and len(ledger['launches'])==101
      and all(row['physical']=='absent'for row in ledger['launches']))
    pending=[row for row in ledger['launches']if row['private_cleanup']is False]
    _require(len(pending)==3 and {r['role']for r in pending}=={'probe','boundary','preflight'}and all(r['cell']==failed for r in pending))
    cleanup=_read(q,index['owned_cleanup']);peer=_read(q,index['owned_cleanup_review'])
    _require(cleanup['status']=='PASS_ORIGINAL_OWNED059_CLOSURE'and cleanup['phase']=='COMPLETE'
      and cleanup['original_reconcile_CURRENT_normalclose_completed']is True and cleanup['record_preimages_preserved_in_guest']==174
      and cleanup['ordinary_records_released']==3 and cleanup['private_dispatch_purged']is True
      and cleanup['ledger_state_controller_STOP_poison_and_clock_repaired']is False
      and cleanup['new_containers_participants_model_calls']==0)
    _require(peer['status']=='PASS'and peer['findings']==[]and peer['subjects']['guest_result']['sha256']==index['owned_cleanup']['sha256']
      and peer['actual_closed_facts']['cumulative_containers']==488 and peer['actual_closed_facts']['cumulative_participants']==40
      and peer['actual_closed_facts']['source_attested_canonical_inventory']==174)
    attestation=_validate_attestation(_read(q,index['historical_verification']),index)
    rows=index['cells'];_require(type(rows)is list and len(rows)==22 and rows==attestation['cells']
      and {r['cell_id']for r in rows}==set(PRIOR_IDS))
    refs={};passed_runs=[]
    legacy_rows={r['cell_id']:r for r in legacy['cells']}
    for row in rows:
        old=row['cell_id']in retained.RETAINED_IDS
        _require(row['source_origin']==('source042'if old else'source044'))
        source_cell=next(c for c in original['cells']if c['id']==row['cell_id'])if old else next(c for c in prior['cells']if c['id']==row['cell_id'])
        _cell_paths(row,source_cell,legacy_root if old else root)
        if old:
            original_row=legacy_rows[row['cell_id']]
            _require(row['kind']==original_row['kind']and row['run_id']==original_row.get('run_id')and row['attempt_id']==original_row.get('attempt_id')
                and row['roles']=={k:v for k,v in original_row.items()if k not in {'cell_id','kind','run_id','attempt_id'}})
        else:
            observed=state['cells'][row['cell_id']]
            _require(row['run_id']==observed['run_id']and row['attempt_id']==observed['attempt_id'])
        if row['kind']!='admission':passed_runs.append(Path(row['roles']['result']['path']).parent)
        for reference in row['roles'].values():_read(q,reference);refs[reference['path']]=reference['sha256']
    attestation_path=_reference(index['historical_verification'])
    _require(attestation_path==HISTORY_ATTESTATION_PATH)
    stage=HISTORY_STAGE
    _reference(index['owned_cleanup'],stage/'owned-browser-cleanup-001/result.json')
    _reference(index['owned_cleanup_review'],stage/'prior044-browser-owned-cleanup-review-002.json')
    # Host producer/capture/review refs are commitments only, never guest read targets.
    outside={stage/('fresh-evidence-'+phase)/name for phase in('N02-0.87.1','N02-1.2.0','N03-0.87.1','N03-1.2.0')for name in('assessment.json','result.json')}
    outside|={stage/'retained-capture-001'/name for name in('retained-index.json','result.json')}
    outside|={stage/'owned-browser-cleanup-001/result.json',stage/'prior044-browser-owned-cleanup-review-002.json',
              stage/'prior044-browser-history-inputs-002.json'}
    classified,seen=_immutable_roles(attestation['immutable_roles'],root,legacy_root,outside,passed_runs)
    _require(set(refs)<=seen)
    for reference,path in classified:
        body=q.preparation._read(path,4*1024*1024);_require(hashlib.sha256(body).hexdigest()==reference['sha256'])
        _require(reference['path']not in refs or refs[reference['path']]==reference['sha256'])
    _require(set(refs)<=seen)
    return prior,ledger,rows


def prepare(q,root,*,evidence_index,compatibility,freeze_kwargs):
    index=q.read(evidence_index)if isinstance(evidence_index,(str,Path))else copy.deepcopy(evidence_index)
    review=q.read(compatibility)if isinstance(compatibility,(str,Path))else copy.deepcopy(compatibility)
    _require(type(freeze_kwargs)is dict and not set(freeze_kwargs)&{'predecessor','campaign_boundary','campaign_amendment','candidate_identity'})
    _require(type(index)is dict and 'prior_root'in index)
    root=_path(str(Path(root).absolute()));old=_path(index['prior_root'])
    _require(root!=old and root not in old.parents and old not in root.parents)
    prior,_,_=_evidence(q,index,review)
    legacy_root=_path(_read(q,index['legacy_index'])['prior_root'])
    _require(root!=legacy_root and root not in legacy_root.parents and legacy_root not in root.parents)
    fd=q.preparation._directory(root.parent);os.close(fd)
    q.freeze(root,**freeze_kwargs);manifest=q.read(root/'manifest.json')
    _require(all(prior[k]==manifest[k]for k in SEMANTIC_FIELDS))
    _,fresh=partition(manifest['cells'])
    for name,value in(('browser-followup-index.json',index),('browser-followup-compatibility.json',review)):
        retained._exclusive(q,root/name,value);manifest['files'][name]=q.sha(root/name)
    manifest['browser_followup']={'schema':1,'mode':MODE,
      'evidence_index':{'path':str(root/'browser-followup-index.json'),'sha256':q.sha(root/'browser-followup-index.json')},
      'compatibility_review':{'path':str(root/'browser-followup-compatibility.json'),'sha256':q.sha(root/'browser-followup-compatibility.json')},
      'historical_use':dict(HISTORICAL_USE),'local_plan':dict(LOCAL_PLAN),'cumulative_ceiling':dict(CUMULATIVE_CEILING),'authorization_required':True}
    manifest['cells']=fresh;manifest['planned_container_launches']=42;manifest['limits']=effective_limits(manifest)
    q.atomic(root/'manifest.json',manifest);q.atomic(root/'integrity.json',{'manifest_sha256':q.sha(root/'manifest.json')})
    verify(q,root);return root


def verify(q,root,*,require_candidate=False):
    root=Path(root).absolute();manifest=q.read(root/'manifest.json');state=q.read(root/'state.json')
    marker=validate_marker(manifest['browser_followup'])
    _reference(marker['evidence_index'],root/'browser-followup-index.json');_reference(marker['compatibility_review'],root/'browser-followup-compatibility.json')
    _require(not set(manifest)&{'retained_requalification','predecessor','campaign_boundary','campaign_amendment'}
      and manifest['schema']==1 and type(manifest['schema'])is int and manifest['document_type']=='application_client_qualification'
      and manifest['prepared_root']==str(root)and manifest['source']==q.source_identity()
      and manifest['limits']==effective_limits(manifest)and all(type(v)is int for v in manifest['limits'].values())
      and manifest['planned_container_launches']==42 and type(manifest['planned_container_launches'])is int
      and q.read(root/'integrity.json')=={'manifest_sha256':q.sha(root/'manifest.json')})
    _,fresh=partition(q.matrix(manifest['images']));_require(len(manifest['cells'])==6)
    compiled={}
    for cell,expected in zip(manifest['cells'],fresh):
        _require(q.c.canonical({k:cell.get(k)for k in expected})==q.c.canonical(expected)and set(cell)==set(expected)|{'plan_sha256'})
        retained._sha(cell['plan_sha256'])
        if cell['release']not in compiled:
            compiled[cell['release']]=q.preparation.load_compiled(root/'inputs'/('browser-'+cell['release'])/'compiled/plan.json',verify_runner=True)['plan']
        plan=compiled[cell['release']]
        _require(plan['plan_sha256']==cell['plan_sha256']and plan['runtime']['image_id']==cell['image_id']
                 and plan['runtime']['pi_release']==cell['release']and plan['runtime']['platform']=='linux/arm64')
    q._launch_module().validate_manifest(launch_manifest(q,manifest))
    for path,digest in manifest['files'].items():q.c.relative(path,'/files');_require(q.sha(root/path)==digest)
    prior,_,_=_evidence(q,_read(q,marker['evidence_index']),_read(q,marker['compatibility_review']))
    _require(all(prior[k]==manifest[k]for k in SEMANTIC_FIELDS))
    _exact(state,{'schema','phase','active_cell','cells','started_at'})
    _require(type(state['schema'])is int and state['schema']==1 and state['phase']in('frozen','admitting','images_admitted','collecting','blocked')
      and type(state['cells'])is dict and not set(state['cells'])-set(FRESH_IDS))
    if state['phase']=='frozen':_require(not state['cells']and state['active_cell']is None and state['started_at']is None)
    else:_require(type(state['started_at'])in(int,float)and math.isfinite(state['started_at'])and state['started_at']>0)
    retained._actual_state(q,root,manifest,state)
    if require_candidate:
        candidate=q.read(root/'candidate.json');_exact(candidate,{'archive_sha256','runner_sha256','scope'})
        retained._sha(candidate['archive_sha256']);_require(candidate['runner_sha256']==CURRENT_RUNNER and candidate['scope']=='extracted_candidate')
    return manifest,state


def _activation(q,root,manifest):
    grant_path=root/'native-authorization.json';review_path=root/'independent-native-input-review.json'
    grant=q.read(grant_path);peer=q.read(review_path)
    _exact(grant,{'schema','document_type','status','authorization_id','manifest','candidate','evidence_index','compatibility_review',
       'historical_use','local_plan','cumulative_caps','native_window_seconds','live_limits','automatic_retries','publication_authorized'})
    retained._uuid(grant['authorization_id']);marker=manifest['browser_followup']
    manifest_ref={'path':str(root/'manifest.json'),'sha256':q.sha(root/'manifest.json')}
    candidate_ref={'path':str(root/'candidate.json'),'sha256':q.sha(root/'candidate.json')}
    _require(q.c.canonical(grant)==q.c.canonical({'schema':1,'document_type':'application_browser_followup_native_authorization','status':'AUTHORIZED',
      'authorization_id':grant['authorization_id'],'manifest':manifest_ref,'candidate':candidate_ref,
      'evidence_index':marker['evidence_index'],'compatibility_review':marker['compatibility_review'],
      'historical_use':HISTORICAL_USE,'local_plan':LOCAL_PLAN,'cumulative_caps':CUMULATIVE_CEILING,'native_window_seconds':14400,
      'live_limits':{'containers':4,'active_trials':1,'inference_slots':1},'automatic_retries':0,'publication_authorized':False}))
    _require(q.c.canonical(peer)==q.c.canonical({'schema':1,'status':'PASS','grant':{'path':str(grant_path),'sha256':q.sha(grant_path)},
      'manifest':manifest_ref,'candidate':candidate_ref,'supports_exact_browser_followup_authority':True,'unresolved_findings':[]}))


def require_dispatch(q,root,manifest):
    return _activation(q,Path(root).absolute(),manifest)


def admit(q,root):
    root=Path(root).absolute();manifest,_=verify(q,root,require_candidate=True);_activation(q,root,manifest)
    with q.controller(root):
        manifest,state=verify(q,root,require_candidate=True);_activation(q,root,manifest)
        _require(state['phase']=='frozen'and not state['cells'])
        q._endpoint(root/'inputs/endpoint.json',manifest['session']);values=q._known_values(manifest);q._scan_frozen(root,manifest,values)
        state.update(started_at=q.time.time(),phase='admitting');q.atomic(root/'state.json',state)
        try:
            with q._deadline_signal(root):
                _,old,_=_evidence(q,_read(q,manifest['browser_followup']['evidence_index']),_read(q,manifest['browser_followup']['compatibility_review']))
                daemon,capacity=q._native();_require(daemon==old['daemon']and capacity==old['daemon_capacity'])
                q._launch_module().LaunchLedger.create(root/'launch-ledger',launch_manifest(q,manifest),daemon_id=daemon,daemon_capacity=capacity)
            state['phase']='images_admitted';q.atomic(root/'state.json',state)
        except BaseException:
            state['phase']='blocked';q.atomic(root/'state.json',state);raise


def collect(q,root,*,group,release):
    root=Path(root).absolute();_require((group,release)in PHASES)
    manifest,_=verify(q,root,require_candidate=True);_activation(q,root,manifest)
    with q.controller(root),q._deadline_signal(root,reserve=False):
        manifest,state=verify(q,root,require_candidate=True);_activation(q,root,manifest)
        _require(state['phase']in('images_admitted','collecting')and state['active_cell']is None)
        pending=next((p for p in PHASES if any(c['id']not in state['cells']for c in manifest['cells']if(c['group'],c['release'])==p)),None)
        _require(pending==(group,release))
        selected=[c for c in manifest['cells']if(c['group'],c['release'])==pending]
        _require(len(selected)==3 and all(c['id']not in state['cells']for c in selected))
        q._endpoint(root/'inputs/endpoint.json',manifest['session']);values=q._known_values(manifest);q._scan_frozen(root,manifest,values)
        state['phase']='collecting';q.atomic(root/'state.json',state)
        try:
            for cell in selected:q._invoke_cell(root,manifest,cell,q.outcomes.initial(),values)
        except BaseException:
            state=q.read(root/'state.json');state['phase']='blocked';q.atomic(root/'state.json',state);raise
    return report(q,root)


def report(q,root):
    manifest,state=verify(q,root);rows=[]
    for cell in manifest['cells']:
        observed=state['cells'].get(cell['id'],{})
        _require(type(observed)is dict and observed.get('status','NOT_RUN')in('started','PASS','FAIL','BLOCKED','NOT_RUN')
          and observed.get('runner_status')in(None,'PASS','FAIL','BLOCKED','INTERRUPTED','ASSISTED','RECOVERED')
          and type(observed.get('attempts',0))is int and observed.get('attempts',0)in(0,1))
        rows.append({'id':cell['id'],'group':'N04','release':cell['release'],'real_model':True,
          'origin':'new_browser_scope','status':observed.get('status','BLOCKED'if state['phase']=='blocked'else'NOT_RUN'),
          'attempts_this_scope':observed.get('attempts',0),'runner_status':observed.get('runner_status'),'scope':'real_model'})
    marker=manifest['browser_followup']
    return {'schema':1,'document_type':'application_browser_followup_qualification_report','qualification_id':manifest['qualification_id'],
      'status':'PASS'if all(r['status']=='PASS'for r in rows)else'NOT_READY','cells':rows,'fresh_cells':6,
      'prior_source_scoped_passes':22,'prior_evidence':{'index':marker['evidence_index'],'compatibility_review':marker['compatibility_review']},
      'historical_use':dict(HISTORICAL_USE),'local_plan':dict(LOCAL_PLAN),'cumulative_ceiling':dict(CUMULATIVE_CEILING),
      'limits':manifest['limits'],'same_source_full28_execution_claimed':False,'prior_failed_browser_retained':False}
