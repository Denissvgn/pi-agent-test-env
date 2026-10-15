"""Parent-owned Pi segment chains. Never infer recovery authority from child acks."""
import copy
import provenance
import agent_profiles
import release_contracts
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import uuid

import stage_control as controls
from evidence import analyze
from usage_contract import combine, summarize


def activate(runroot,desc,segment_id,logs):
    with controls.lock(runroot,desc['stage_id']):
        path=Path(runroot)/'stages'/desc['stage_id']/'state.json';state=controls.read(path)
        if state['status']!='running':raise controls.ControlError('Segment requires running stage')
        state.update(segment_id=segment_id,logs=str(logs),revision=state['revision']+1)
        controls.atomic(path,state)
    return state


def pending(runroot,desc,segment_id,consumed):
    targets=segment_id if isinstance(segment_id,set) else {segment_id}
    accepted={e['id'] for e in controls.history(runroot) if e['status']=='accepted' and e['stage_id']==desc['stage_id']}
    values=[]
    for path in (Path(desc['inbox'])/'directives').glob('*.json'):
        data=controls.read(path)
        if (data.get('kind')=='steer' and data.get('id') in accepted and data['id'] not in consumed
            and data.get('segment_id') in targets and data.get('run_id')==desc['run_id']):values.append(data)
    return sorted(values,key=lambda d:(d['created_at'],d['id']))


def freeze_session(runtime,session_id,cwd,model,target):
    root=os.open(runtime,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    folder=None;matches=[]
    try:
        folder=os.open('sessions',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root)
        with os.scandir(folder) as entries:
            for index,entry in enumerate(entries):
                if index>=128:raise controls.ControlError('Too many session candidates')
                if not entry.name.endswith('.jsonl'):continue
                fd=os.open(entry.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=folder)
                with os.fdopen(fd,'rb') as stream:
                    info=os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise controls.ControlError('Unsafe session file')
                    body=stream.read(32*1024*1024+1)
                if len(body)>32*1024*1024:raise controls.ControlError('Session exceeds limit')
                records=[json.loads(line) for line in body.split(b'\n') if line.strip()]
                if not all(isinstance(r,dict) for r in records):raise controls.ControlError('Malformed session records')
                if not records or records[0].get('id')!=session_id:continue
                header=records[0]
                if header.get('type')!='session' or header.get('version')!=3 or header.get('cwd')!=cwd:raise controls.ControlError('Unrelated session header')
                for record in records[1:]:
                    msg=record.get('message',{})
                    if isinstance(msg,dict) and msg.get('role')=='assistant' and (msg.get('provider')!='local-lab' or msg.get('model')!=model):raise controls.ControlError('Session model identity mismatch')
                    if record.get('type')=='model_change' and (record.get('provider')!='local-lab' or record.get('modelId')!=model):raise controls.ControlError('Session model switch rejected')
                matches.append(body)
        if len(matches)!=1:raise controls.ControlError('Missing/ambiguous exact session')
        target.write_bytes(matches[0]);target.chmod(0o644)
        return hashlib.sha256(matches[0]).hexdigest()
    finally:
        if folder is not None:os.close(folder)
        os.close(root)


def aggregate(records,model,required_tools,authorized_ids,execution_identity=None):
    errors=[];success={};recovered=False
    if not records:return {'agent_invocation_verified':False,'completion_verified':False,'invocation_status':'invalid','errors':['No segments'],'final_text':''}
    session=records[0]['session_id'];seen=set()
    for index,record in enumerate(records):
        ev=record['evidence'];segment_id=record['segment_id']
        if segment_id in seen or record['ordinal']!=index+1:errors.append('Duplicate/out-of-order segment')
        seen.add(segment_id)
        if execution_identity is not None and record.get('execution_identity') != execution_identity:
            errors.append('Segment release/image/contract identity differs from admitted execution')
        if record['session_id']!=session or ev.get('session_id')!=session:errors.append('Unrelated session continuation')
        if ev.get('identity_conflict') or (index==len(records)-1 and not ev.get('identity_verified')):errors.append('Segment model/provider identity invalid')
        if index:
            if record.get('continues_segment_id')!=records[index-1]['segment_id'] or record.get('command_id') not in authorized_ids or not record.get('session_sha256'):errors.append('Unauthorised/unlinked continuation')
        if not ev.get('agent_invocation_verified'):
            if index==len(records)-1:errors.append('Final segment did not complete cleanly')
            else:
                successor=records[index+1]
                allowed=successor.get('command_id') in record['process'].get('interrupts_applied',[]) and successor.get('command_id') in authorized_ids
                benign=all(any(label in text for label in ('pending at process exit','Pending tool','Final settlement')) or (ev.get('truncated_tail') and text.startswith('Malformed JSONL record ') and sum(e.startswith('Malformed JSONL') for e in ev['protocol_errors'])==1) for text in ev.get('protocol_errors',[]))
                allowed_abort_policy = {
                    'No successful final assistant/process completion',
                    'Unsuccessful assistant messages retained',
                    'Pi settled with aborted work; no clean completion',
                }
                benign = benign and all(text in allowed_abort_policy for text in ev.get('policy_errors', []))
                benign = benign and not (ev.get('agent_profile') or {}).get('errors', [])
                if not allowed or not benign:errors.append('Original abort/invalid trace not authorised for recovery')
                recovered=True
        for name,count in ev.get('successful_tools',{}).items():success[name]=success.get(name,0)+count
        if not record['process'].get('cleanup_confirmed'):errors.append('Segment cleanup unconfirmed')
    for tool in required_tools:
        if not success.get(tool):errors.append('Required successful tool missing: '+tool)
    final=records[-1]['evidence']
    complete=not errors
    return {'schema':2,'agent_invocation_verified':complete and not recovered,
            'completion_verified':complete,'invocation_status':'recovered' if complete and recovered else ('verified' if complete else 'invalid'),
            'errors':errors,'successful_tools':success,'final_text':final.get('final_text',''),
            'session_id':session,'segments':[r['segment_id'] for r in records]}



def classify_worker_limit(process,evidence,prior_turns=0,prior_tokens=0):
    """Classify exit 124 using retained trace counts and parent-approved caps, never a heartbeat."""
    if process.get('exit_code')!=124 or process.get('termination_reason')!='process_error':return process
    limits=process.get('effective_limits',{})
    observed_turns=prior_turns+evidence.get('events',{}).get('turn_start',0)
    observed_tokens=prior_tokens+evidence.get('usage',{}).get('categories',{}).get('total',{}).get('known_sum',0)
    reason=None
    if type(limits.get('max_turns')) is int and observed_turns>limits['max_turns']:reason='turn_limit'
    elif type(limits.get('max_total_tokens')) is int and observed_tokens>limits['max_total_tokens']:reason='token_limit'
    if reason:
        process.update(supervisor_termination_reason=process['termination_reason'],termination_reason=reason,
                       termination_origin='parent comparison of retained trace counts to approved effective caps',
                       observed_budget_counts={'turns':observed_turns,'known_reported_tokens':observed_tokens})
    return process

def execute(lab,args,image,runroot,workspace,label,task,endpoint,secret,desc,access,network,timeout,helpers,application_secrets=None,redaction_secrets=()):
    application_secrets = application_secrets or {}
    release = getattr(args, 'observed_pi_version', None)
    selected = release_contracts.identity(release)
    release_contracts.validate_binding(getattr(args, 'release_contract', selected), release)
    execution_identity = {'image_id': image, 'release_contract': selected}
    if getattr(args,'_indexed_binding',None):execution_identity['inference_binding']=copy.deepcopy(args._indexed_binding)
    root=runroot/label;root.mkdir(parents=True,exist_ok=True)
    parent_records=runroot/'stages'/desc['stage_id']/'segments';parent_records.mkdir()
    session_id=str(uuid.uuid4());records=[];consumed=set();turns=0;tokens=0;known=True
    stage_started=time.monotonic()
    directive=None;session_body=None
    cwd='/workspace'+('' if task.get('cwd','.')=='.' else '/'+task['cwd'])
    try:
        for ordinal in range(1,101):
            if getattr(args,'_indexed_session',None):secret=args._indexed_session.continuation(renew=ordinal>1)
            segment_id=str(uuid.uuid4());logs=root/'segments'/segment_id
            control=Path(desc['control'])/'segments'/segment_id;control.mkdir(parents=True)
            state=activate(runroot,desc,segment_id,logs)
            runtime=lab.state_dir(runroot/'children',segment_id,args.uid)
            segment_task=copy.deepcopy(task)
            segment_task.update(session_id=session_id,prior_turns=turns,prior_reported_tokens=tokens,prior_usage_known=known,
                                pi_release=getattr(args,'observed_pi_version',None),allowed_tools=task['tools'])
            segment_task['release_contract'] = release_contracts.identity(segment_task['pi_release'])
            if directive:
                if records[-1].get('execution_identity') != execution_identity:
                    raise controls.ControlError('Cannot continue across Pi release/image/contract identities')
                segment_task['prompt']=directive['message'];segment_task['resume_session']='/opt/pi-control/segments/'+segment_id+'/session.jsonl'
                digest=freeze_session(records[-1]['runtime'],session_id,cwd,endpoint['model'],control/'session.jsonl')
                consumed.add(directive['id'])
            else:digest=None
            receipt=getattr(args,'frozen_agent_profile',None)
            profile=agent_profiles.staged(receipt) if receipt else agent_profiles.builtin()
            context={'schema':1,'profile':profile,'profile_sha256':agent_profiles.identity(profile),
                     'run_id':desc['run_id'],'attempt_id':desc['attempt_id'],'stage_id':desc['stage_id'],'segment_id':segment_id,
                     'allowed_tools':sorted(set(segment_task['tools']))}
            controls.atomic(control/'profile-context.json',context,0o644)
            segment_task['agent_profile_context']='/opt/pi-control/segments/'+segment_id+'/profile-context.json'
            controls.atomic(control/'task.json',segment_task,0o644)
            controls.atomic(control/'stage.json',{**desc,'segment_id':segment_id,'stage_revision':state['revision']},0o644)
            argv=lab.docker_args(args,image,workspace,Path(desc['control']),runtime,desc['container'],network,access,bool(secret),helpers=helpers)
            for variable in application_secrets:
                argv[-2:-2] = ['--env', variable]
            if receipt and profile['kind']!='builtin':argv[-2:-2]=['--mount',f"type=bind,src={receipt['root']},dst=/opt/pi-profile,readonly,bind-recursive=disabled"]
            argv[-2:-2]=['--env',f'PI_LAB_STAGE_CONTEXT=/opt/pi-control/segments/{segment_id}/stage.json']
            meta={'schema':2,'segment_id':segment_id,'ordinal':ordinal,'stage_id':desc['stage_id'],
                  'execution_identity':copy.deepcopy(execution_identity),
                  'run_id':desc['run_id'],'attempt_id':desc['attempt_id'],'session_id':session_id,
                  'runtime':str(runtime),'logs':str(logs),'started_at':controls.now(),
                  'continues_segment_id':records[-1]['segment_id'] if records else None,
                  'command_id':directive['id'] if directive else None,
                  'intervention_id':directive['intervention_id'] if directive else None,'session_sha256':digest}
            controls.atomic(parent_records/(segment_id+'.json'),meta)
            if directive:controls.audit(runroot,directive,'applied',action='continuation_launch',successor_segment_id=segment_id,session_sha256=digest)
            try:
                result=lab.stream_run(argv+['agent','--task',f'/opt/pi-control/segments/{segment_id}/task.json'],logs,timeout,desc['container'],secret,
                                  stage=(runroot,desc),keep_budget=True,resume_budget=bool(records),application_secrets=application_secrets,redaction_secrets=redaction_secrets)
            except KeyboardInterrupt:
                result=controls.read(logs/'process.json') if (logs/'process.json').exists() else {'exit_code':130,'cancelled':True,'cleanup_confirmed':False}
                meta.update(process=result,finished_at=controls.now())
                controls.atomic(parent_records/(segment_id+'.json'),meta)
                lab.save(root/'process.json',{**result,'segments':records+[meta]})
                raise
            if getattr(args,'_indexed_session',None) and result.get('cleanup_confirmed') is True:args._indexed_session.release_segment()
            ev=lab.analyze(logs/'stdout.jsonl',endpoint['model'],[],result['exit_code'],args.event_contract,release=getattr(args,'observed_pi_version',None),allowed_tools=task['tools'])
            if receipt:agent_profiles.staged(receipt)
            observation=agent_profiles.observed(logs/'stdout.jsonl',{**context,'asset_root':receipt['root']}) if receipt else {'loading':'unverified','errors':[]}
            ev['agent_profile']=observation
            if observation['errors']:
                profile_errors = ['Agent profile violation: ' + text for text in observation['errors']]
                ev.setdefault('policy_errors', []).extend(profile_errors)
                ev['errors'] += profile_errors
                ev.update(agent_invocation_verified=False,completion_verified=False,invocation_status='invalid')
            classify_worker_limit(result,ev,turns,tokens)
            lab.save(logs/'process.json',result)
            effective=provenance.collect_emitted(runtime,logs,secret,[*application_secrets.values(), *redaction_secrets]) if result.get('cleanup_confirmed') is True else {'status':'cleanup_unconfirmed'}
            meta.update(process=result,evidence=ev,finished_at=controls.now(),provenance={'task_sha256':provenance.digest(segment_task),'emitted':effective})
            controls.atomic(parent_records/(segment_id+'.json'),meta);records.append(meta)
            turns+=ev.get('events',{}).get('turn_start',0)
            reported=ev.get('provider_reported_total_tokens')
            if reported is None:known=False
            tokens+=ev.get('usage',{}).get('categories',{}).get('total',{}).get('known_sum',reported or 0)
            if result.get('cancelled') or result.get('exit_code')==130 and not result.get('interrupts_applied') or not result.get('cleanup_confirmed') or result.get('timed_out') or result.get('log_limit_exceeded'):break
            directives=pending(runroot,desc,{r['segment_id'] for r in records},consumed)
            if not directives:break
            # One directive per successor. Older pending directives remain retained;
            # remaining accepted messages are consumed in subsequent successors.
            directive=directives[0]
            if not ev.get('agent_invocation_verified') and directive['id'] not in result.get('interrupts_applied',[]):break
            budget=controls.read(controls.budget_path(runroot,desc))
            if time.monotonic()>=budget['deadline_host_monotonic'] or turns>=budget['effective_limits']['max_turns'] or tokens>=budget['effective_limits']['max_total_tokens']:break
        accepted={e['id'] for e in controls.history(runroot) if e['status']=='accepted'}
        evidence=aggregate(records,endpoint['model'],task['require_tools'],accepted,execution_identity)
        result=dict(records[-1]['process']) if records else {'exit_code':2,'cleanup_confirmed':False}
        result.update(segments=records,evidence=evidence,stage_turns=turns,
                      usage=combine([r['evidence'].get('usage',summarize([])) for r in records]),
                      timing={'stage_end_to_end_seconds':round(time.monotonic()-stage_started,3),'inference_seconds':None,'scope':'whole stage including orchestration, tools and cleanup'},
                      stage_reported_tokens=tokens if known else None,reported_tokens_counted=tokens)
        if evidence['completion_verified']:result['termination_reason']='completed'
        lab.save(root/'process.json',result);lab.save(root/'evidence.json',evidence)
        return result
    except (OSError,ValueError,controls.ControlError) as exc:
        # A failed launch still has a supervisor cleanup receipt. Never use the
        # preceding segment's cleanup status for a failed successor launch.
        current = controls.read(logs/'process.json') if 'logs' in locals() and (logs/'process.json').exists() else None
        if not records:
            if current is not None:lab.save(root/'process.json', current)
            raise
        result={**(current or records[-1]['process']),'segments':records,'recovery_error':type(exc).__name__,
                'evidence':{'agent_invocation_verified':False,'completion_verified':False,
                            'invocation_status':'invalid','errors':['Continuation preparation failed'],'final_text':''}}
        lab.save(root/'process.json',result)
        return result
    finally:
        if controls.budget_path(runroot,desc).exists():controls.process_budget_requests(runroot,desc,closing=True)
