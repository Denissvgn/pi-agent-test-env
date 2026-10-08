"""Independent schema-1 scorer contracts, frozen assets and truthful results."""
import hashlib
import json
import math
import os
from pathlib import Path,PurePosixPath
import stat

class ScorerError(ValueError):pass


def finite(value):return type(value) in (int,float) and math.isfinite(value)


def validate(value,base):
    allowed={'schema','id','version','assets','score_domain','required_assertions','allow_partial',
             'zero_test_policy','all_skipped_policy','test_counts_required'}
    if not isinstance(value,dict) or set(value)-allowed or value.get('schema')!=1:raise ScorerError('Scorer schema 1 required')
    out=dict(value)
    for key in ('id','version'):
        if not isinstance(out.get(key),str) or not out[key].strip() or len(out[key])>100:raise ScorerError('Scorer identity required')
    domain=out.get('score_domain',{})
    if not isinstance(domain,dict) or set(domain)!= {'min','max','direction','pass_threshold'} or not all(finite(domain[k]) for k in ('min','max','pass_threshold')) or not domain['min']<domain['max'] or not domain['min']<=domain['pass_threshold']<=domain['max'] or domain['direction'] not in ('higher','lower'):
        raise ScorerError('Finite score domain/direction/threshold required')
    required=out.get('required_assertions')
    if not isinstance(required,list) or not required or len(required)>100 or not all(isinstance(x,str) and x for x in required) or len(set(required))!=len(required):raise ScorerError('Unique approved assertions required')
    for key in ('zero_test_policy','all_skipped_policy'):
        if out.get(key) not in ('fail','allow'):raise ScorerError('Explicit zero/all-skipped policy required')
    for key in ('allow_partial','test_counts_required'):
        out.setdefault(key,False)
        if type(out[key]) is not bool:raise ScorerError('Scorer policy must be boolean')
    assets=out.get('assets')
    if not isinstance(assets,list) or not 1<=len(assets)<=32:raise ScorerError('Declare 1..32 reviewed scorer assets')
    normalized=[];seen=set()
    for asset in assets:
        if not isinstance(asset,dict) or set(asset)!= {'source','target'}:raise ScorerError('Scorer asset source/target required')
        if not all(isinstance(asset[k],str) and asset[k] and '\0' not in asset[k] for k in ('source','target')):raise ScorerError('Asset paths must be strings')
        p=PurePosixPath(asset['target'])
        if p.is_absolute() or not p.parts or '..' in p.parts or '\\' in asset['target'] or '\0' in asset['target'] or p.as_posix() in seen:raise ScorerError('Invalid scorer asset target')
        if any(p.as_posix().startswith(x+'/') or x.startswith(p.as_posix()+'/') for x in seen):raise ScorerError('Conflicting asset targets')
        seen.add(p.as_posix());normalized.append({'source':str((base/asset['source']).absolute()),'target':p.as_posix()})
    out['assets']=normalized
    return out


def freeze(contract,root):
    root.mkdir()
    hashes={};total=0
    for asset in contract['assets']:
        fd=os.open(asset['source'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as f:
            info=os.fstat(f.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise ScorerError('Scorer sources must be regular non-linked files')
            content=f.read(16*1024*1024+1)
        total+=len(content)
        if total>16*1024*1024:raise ScorerError('Scorer assets exceed 16 MiB')
        dest=root/asset['target'];dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(content);dest.chmod(0o444)
        hashes[asset['target']]=hashlib.sha256(content).hexdigest()
    digest=hashlib.sha256(json.dumps(hashes,sort_keys=True).encode()).hexdigest()
    return {'assets':hashes,'sha256':digest,'root':str(root)}


def assets_unchanged(receipt):
    root=Path(receipt['root'])
    actual={p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file() and not p.is_symlink()}
    return actual==receipt['assets'] and not any(p.is_symlink() for p in root.rglob('*'))


def evaluate(contract,receipt,process,stdout,run_id,attempt_id):
    result={'schema':1,'scorer_id':contract['id'] if contract else 'command-only',
            'scorer_version':contract['version'] if contract else '1','scorer_sha256':receipt['sha256'] if receipt else None,
            'score_domain':contract['score_domain'] if contract else None,
            'status':'error','reason':None,'task_status':'unknown','score':None,'test_counts':None,'assertions':None}
    if process.get('cleanup_confirmed') is not True:result['reason']='cleanup_unconfirmed';return result
    if not contract:
        if process.get('timed_out') or process.get('cleanup_confirmed') is False:result['reason']='command_infrastructure_error';return result
        result.update(status='completed',task_status='pass' if process['exit_code']==0 else 'fail')
        return result
    try:
        if not assets_unchanged(receipt):raise ScorerError('scorer_assets_changed')
        if process['exit_code']!=0:raise ScorerError('scorer_nonzero_exit')
        if not stdout.strip():raise ScorerError('scorer_output_missing')
        data=json.loads(stdout)
        keys={'schema','scorer_id','scorer_version','run_id','attempt_id','task_status','score','test_counts','assertions'}
        if not isinstance(data,dict) or set(data)!=keys or data['schema']!=1 or data['scorer_id']!=contract['id'] or data['scorer_version']!=contract['version'] or data['run_id']!=run_id or data['attempt_id']!=attempt_id:raise ScorerError('scorer_identity_or_schema')
        score=data['score'];domain=contract['score_domain']
        if not finite(score) or not domain['min']<=score<=domain['max']:raise ScorerError('score_out_of_domain')
        assertions=data['assertions']
        if not isinstance(assertions,list):raise ScorerError('assertions_missing')
        ids=[]
        for assertion in assertions:
            if not isinstance(assertion,dict) or set(assertion)-{'id','passed','skipped'} or not isinstance(assertion.get('id'),str) or type(assertion.get('passed')) is not bool or type(assertion.get('skipped',False)) is not bool:raise ScorerError('assertion_shape')
            ids.append(assertion['id'])
        if len(set(ids))!=len(ids) or set(ids)-set(contract['required_assertions']):raise ScorerError('assertion_identity')
        partial=set(ids)!=set(contract['required_assertions'])
        if partial and not contract['allow_partial']:raise ScorerError('assertions_incomplete')
        counts=data['test_counts']
        forced_fail=False
        if counts is None:
            if contract['test_counts_required']:raise ScorerError('test_counts_missing')
        else:
            if not isinstance(counts,dict) or set(counts)!= {'discovered','passed','failed','skipped'} or any(type(v) is not int or v<0 for v in counts.values()) or counts['discovered']!=counts['passed']+counts['failed']+counts['skipped']:raise ScorerError('test_counts_invalid')
            forced_fail=counts['failed']>0 or (counts['discovered']==0 and contract['zero_test_policy']=='fail') or (counts['discovered']>0 and counts['skipped']==counts['discovered'] and contract['all_skipped_policy']=='fail')
        threshold=score>=domain['pass_threshold'] if domain['direction']=='higher' else score<=domain['pass_threshold']
        passes=threshold and not forced_fail and all(a['passed'] and not a.get('skipped',False) for a in assertions)
        expected='partial' if partial else ('pass' if passes else 'fail')
        if data['task_status']!=expected:raise ScorerError('inconsistent_task_status')
        result.update(status='completed',task_status=expected,score=score,test_counts=counts,assertions=assertions)
    except (OSError,ValueError,TypeError,KeyError) as exc:
        result['reason']=str(exc) if isinstance(exc,ScorerError) else 'malformed_scorer_output'
    return result


def aggregate(results):
    if not results:return {'status':'not_started','reason':'no_scorer_results'}, {'status':'unknown','score':None,'test_counts':None}
    state='cancelled' if any(r['status']=='cancelled' for r in results) else ('error' if any(r['status']=='error' for r in results) else ('skipped' if any(r['status']=='skipped' for r in results) else 'completed'))
    task='unknown' if state!='completed' else ('fail' if any(r['task_status']=='fail' for r in results) else ('partial' if any(r['task_status']=='partial' for r in results) else 'pass'))
    return {'status':state,'reason':'scorer_error' if state=='error' else None,'results':results}, {'status':task,'score':results[0]['score'] if len(results)==1 and state=='completed' else None,'test_counts':results[0]['test_counts'] if len(results)==1 and state=='completed' else None}
