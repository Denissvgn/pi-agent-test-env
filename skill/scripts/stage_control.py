"""Parent-owned schema-2 stage routing. Child observations never select paths."""
from contextlib import contextmanager
import contextvars
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import uuid
import registry_diagnostics

SCHEMA = 2
LIMIT_MAX = {'timeout_seconds':3600, 'max_turns':100, 'max_total_tokens':10000000}
NATIVE_LIMIT_MAX = {'max_tool_calls':500, 'reporting_reserve_calls':20, 'reporting_reserve_seconds':120}

class ControlError(RuntimeError):
    pass


class LockBusy(ControlError):
    """A bounded control-plane lock stayed held, for example by a stopped helper."""
    reason = 'control_lock_busy'


# A supervisor must keep enforcing its deadline even when a steer, extend-budget
# or patch process is stopped while it holds a control-plane lock. Inside
# bounded_locks() every control lock is tried without blocking and retried for
# at most this long; then LockBusy is raised and the caller skips the work.
LOCK_WAIT_SECONDS = 2
_LOCK_RETRY_SECONDS = 0.02
_lock_wait = contextvars.ContextVar('control_lock_wait', default=None)
# (resolved run root, descriptor) of the intervention history held by history_lock().
_history_held = contextvars.ContextVar('control_history_held', default=None)


@contextmanager
def bounded_locks(seconds=LOCK_WAIT_SECONDS):
    token = _lock_wait.set(seconds)
    try:
        yield
    finally:
        _lock_wait.reset(token)


def _flock(fd, operation):
    wait = _lock_wait.get()
    if wait is None:
        fcntl.flock(fd, operation)
        return
    deadline = time.monotonic() + wait
    while True:
        try:
            fcntl.flock(fd, operation | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            pass
        if time.monotonic() >= deadline:
            raise LockBusy('control_lock_busy')
        time.sleep(_LOCK_RETRY_SECONDS)

def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()

def atomic(path, value, mode=0o600):
    path = Path(path)
    if path.is_symlink():
        raise ControlError('Symlinked parent record rejected')
    temp = path.with_name('.' + path.name + '-' + uuid.uuid4().hex)
    try:
        with registry_diagnostics.operation('temporary_create', mutating=True):
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, 'w') as f:
            with registry_diagnostics.operation('file_write', mutating=True):
                json.dump(value, f, ensure_ascii=False, indent=2); f.write('\n'); f.flush()
            with registry_diagnostics.operation('file_fsync', mutating=True):
                os.fsync(f.fileno())
        with registry_diagnostics.operation('atomic_replace', mutating=True):
            os.replace(temp, path)
    finally:
        with registry_diagnostics.operation('temporary_cleanup', mutating=True):
            temp.unlink(missing_ok=True)

@registry_diagnostics.observed('record_read')
def read(path):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd) as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise ControlError('Record is not a regular file')
        data = f.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ControlError('Record exceeds limit')
    return json.loads(data)

def valid_id(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except ValueError:
        return False

@contextmanager
def lock(runroot, stage_id=None):
    path = Path(runroot) / (('stages/' + stage_id + '/lock') if stage_id else 'control.lock')
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode) or os.fstat(fd).st_nlink != 1:
            raise ControlError('Unsafe control lock')
        _flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)

def create(runroot, workspace, label, operation, task, control, state, stage_id, container, admission_path=None):
    runroot = Path(runroot).resolve()
    workspace, control, state = map(lambda p: Path(p).resolve(), (workspace,control,state))
    if any(p==workspace or workspace in p.parents for p in (runroot,control,state)):
        raise ControlError('Parent sources must remain outside the workspace')
    root = runroot / 'stages'; root.mkdir(exist_ok=True)
    identity_path = runroot / 'identity.json'
    with lock(runroot):
        if not identity_path.exists():
            atomic(identity_path, {'schema':2, 'run_id':str(uuid.uuid4()), 'attempt_id':str(uuid.uuid4())})
        identity = read(identity_path)
        folder = root / stage_id; folder.mkdir()
        plan = read(runroot / 'plan.json') if (runroot / 'plan.json').exists() else {}
        st = os.stat(workspace, follow_symlinks=False)
        if not stat.S_ISDIR(st.st_mode): raise ControlError('Workspace must be a real directory')
        desc = {'document_type':'stage', 'schema':2, **identity, 'stage_id':stage_id,
                'admission_lock_file':str(Path(admission_path).resolve()) if admission_path else None,
                'segment_id':None, 'label':label, 'kind':operation, 'workspace':str(workspace),
                'workspace_identity':[st.st_dev,st.st_ino], 'control':str(control),
                'inbox':str(control/'inbox'), 'outbox':str(control/'outbox'), 'runtime':str(state),
                'container':container, 'protected_paths':plan.get('protected_paths',[]),
                'original_limits':{k:task[k] for k in (*LIMIT_MAX, *NATIVE_LIMIT_MAX) if task and k in task}}
        atomic(folder/'descriptor.json', desc)
        atomic(folder/'state.json', {'schema':2, 'status':'pending', 'revision':0, 'cleanup_confirmed':False})
    return desc

def resolve(runroot, target=None):
    runroot = Path(runroot).resolve()
    if target is None:
        active = read(runroot/'active_stage.json')
        target = active.get('stage_id')
    if not valid_id(target):
        matches=[]
        for path in (runroot/'stages').glob('*/descriptor.json'):
            d=read(path)
            if d.get('label')==target: matches.append(d['stage_id'])
        if len(matches)!=1: raise ControlError('Wrong/ambiguous stage target or unsupported legacy control record')
        target=matches[0]
    d=read(runroot/'stages'/target/'descriptor.json')
    if d.get('schema')!=2 or d.get('stage_id')!=target:
        raise ControlError('Unsupported or wrong stage descriptor')
    control=runroot/'controls'/target
    if d['control']!=str(control) or d['inbox']!=str(control/'inbox') or d['outbox']!=str(control/'outbox'):
        raise ControlError('Stage paths do not match parent-owned sources')
    state=read(runroot/'stages'/target/'state.json')
    return d,state

def transition(runroot, desc, status, **fields):
    with lock(runroot,desc['stage_id']):
        path=Path(runroot)/'stages'/desc['stage_id']/'state.json'; previous=read(path)
        allowed={'pending':{'running','stopped'}, 'running':{'stopping'}, 'stopping':{'stopped'}, 'stopped':{'finalized'}}
        if status not in allowed.get(previous['status'],set()): raise ControlError('Invalid lifecycle transition')
        updated={**previous,**fields,'status':status,'revision':previous['revision']+1,'updated_at':now()}
        atomic(path,updated)
        atomic(Path(runroot)/'active_stage.json',{'schema':2,'stage_id':desc['stage_id'],'label':desc['label']})
    return updated

def command_record(desc,state,kind,payload,context=None):
    context=context or {}
    return {'schema':2,'id':context.get('id',str(uuid.uuid4())),
            'intervention_id':context.get('intervention_id',str(uuid.uuid4())),
            'payload_digest':hashlib.sha256(json.dumps(payload,sort_keys=True).encode()).hexdigest(),
            'run_id':desc['run_id'],'attempt_id':desc['attempt_id'],
            'stage_id':desc['stage_id'],'segment_id':state.get('segment_id',desc['segment_id']), 'kind':kind,
            'expected_stage_revision':state['revision'],'created_at':now(),**payload}

def check_mutable(desc,state,expected=None,allow_pending=False):
    statuses={'pending'} if allow_pending else {'running'}
    if state['status'] not in statuses: raise ControlError('Stage is not eligible for mutation')
    if expected is not None and expected!=state['revision']: raise ControlError('Stale stage revision')
    if desc['kind']!='agent': raise ControlError('Execution controls require an agent stage')

def observations(desc):
    out={}
    for name in ('heartbeat','steer_ack','hotfix_ack','limits_ack'):
        try:
            value=read(Path(desc['outbox'])/(name+'.json'))
            if isinstance(value,dict) and value.get('schema')==2 and value.get('stage_id')==desc['stage_id']:
                out[name]=value
        except (OSError,ValueError,ControlError): pass
    return out


def budget_path(runroot,desc):
    return Path(runroot)/'stages'/desc['stage_id']/'budget.json'


def start_budget(runroot,desc,start,cleanup_grace=0,native_control=None):
    """Called by the active supervisor, using its own clock origin only."""
    with lock(runroot,desc['stage_id']):
        limits=desc['original_limits']
        for key,value in limits.items():
            if type(value) is not int or not 0<value<={**LIMIT_MAX, **NATIVE_LIMIT_MAX}[key]:raise ControlError('Invalid original limit')
        if set(limits) & set(NATIVE_LIMIT_MAX):
            import native_budget_controls
            native_budget_controls.validate_budget(limits)
            if native_control is None:raise ControlError('Native budget has no live parent control')
        budget={'schema':2,'revision':0,'original_limits':limits,'effective_limits':dict(limits),
                'started_host_monotonic':start,'deadline_host_monotonic':start+limits['timeout_seconds'],
                'cleanup_grace_seconds':cleanup_grace,'phase':'active'}
        if native_control is not None:
            budget['native_tool_budget']=native_control.status(force=True)
        atomic(budget_path(runroot,desc),budget)
        publish_budget(runroot,desc,budget)
    return budget


def publish_budget(runroot,desc,budget,command_id=None):
    import time
    state=read(Path(runroot)/'stages'/desc['stage_id']/'state.json')
    view=command_record(desc,state,'extend_budget',{
        **budget['effective_limits'],'budget_revision':budget['revision'],
        'remaining_seconds':max(0,budget['deadline_host_monotonic']-time.monotonic())})
    if command_id:view['id']=command_id
    atomic(Path(desc['inbox'])/'limits.json',view,0o644)


def process_budget_requests(runroot,desc,closing=False,native_control=None):
    import time
    with lock(runroot,desc['stage_id']):
        budget=read(budget_path(runroot,desc));state=read(Path(runroot)/'stages'/desc['stage_id']/'state.json')
        if budget.get('native_budget_error'):
            raise ControlError('Native budget update unconfirmed; further authority is blocked')
        requests=Path(runroot)/'stages'/desc['stage_id']/'budget-requests'
        responses=requests.parent/'budget-updates';responses.mkdir(exist_ok=True)
        pending=[]
        for path in requests.glob('*.json'):
            try:
                request=read(path)
                if not isinstance(request,dict):raise ControlError('Budget request is not an object')
            except (OSError,ValueError,ControlError) as exc:
                _reject_unreadable(requests,responses,desc,path,exc)
                continue
            created=request.get('created_at')
            pending.append((created if isinstance(created,str) else '',path.name,path,request))
        for _created,_name,path,request in sorted(pending,key=lambda item:item[:2]):
            if (responses/path.name).exists():
                previous=read(responses/path.name)
                if 'max_tool_calls' in budget['original_limits'] and previous.get('status') == 'applying':
                    budget['native_budget_error']='accounting_unavailable'
                    atomic(budget_path(runroot,desc),budget)
                    atomic(responses/path.name,{**previous,'status':'rejected',
                        'reason':'native_budget_update_unconfirmed','helper_applied':'unknown'})
                    raise ControlError('Interrupted native budget update; no retry permitted')
                continue
            reason=None
            try:
                if request.get('schema')!=2 or request.get('kind')!='extend_budget' or request.get('id')!=path.stem:
                    raise ControlError('Malformed budget command')
                check_mutable(desc,state,request['expected_stage_revision'])
                if closing or budget['phase']!='active' or time.monotonic()>=budget['deadline_host_monotonic']:
                    raise ControlError('Budget update is late or supervisor stopped')
                if request['expected_budget_revision']!=budget['revision']:raise ControlError('Stale budget revision')
                if any(request.get(k)!=desc.get(k) for k in ('stage_id','run_id','attempt_id')):
                    raise ControlError('Wrong budget target')
                values=request['limits']
                if set(values)!=set(budget['effective_limits']):raise ControlError('Incomplete limits')
                if any(type(v) is not int or not 0<v<={**LIMIT_MAX, **NATIVE_LIMIT_MAX}[k] or v<budget['effective_limits'][k] for k,v in values.items()):
                    raise ControlError('Invalid or reduced budget')
                if set(values) & set(NATIVE_LIMIT_MAX):
                    import native_budget_controls
                    native_budget_controls.validate_budget(values)
                    if (native_control is None or any(values[key] != budget['effective_limits'][key]
                            for key in ('reporting_reserve_calls', 'reporting_reserve_seconds'))):
                        raise ControlError('Native budget requires live control and unchanged reserves')
                if values==budget['effective_limits']:raise ControlError('Ineffective update')
            except (ControlError,KeyError,TypeError) as exc:reason=str(exc)
            response={'schema':2,'id':request.get('id'),'stage_id':desc['stage_id'],
                      'status':'rejected' if reason else 'applied','reason':reason,
                      'before':dict(budget['effective_limits']),'updated_at':now()}
            # The history lock is taken before the first event and held until the
            # response and its last event exist. A busy history (LockBusy under
            # bounded_locks) therefore leaves this request untouched and it is
            # processed whole on a later pass: never an applied response whose
            # applied event a retry would skip.
            native=False
            with history_lock(runroot):
                if not reason and not requested(runroot,request):reason='Missing parent intervention request'
                response['reason']=reason;response['status']='rejected' if reason else 'applied'
                if reason:
                    if request.get('intervention_id'):audit(runroot,request,'rejected',reason_code='budget_rejected')
                    atomic(responses/path.name,response)
                    continue
                audit(runroot,request,'accepted',before=response['before'],after=request['limits'])
                native=bool(set(values) & set(NATIVE_LIMIT_MAX))
                if native:
                    # Only a retained, explicitly requested parent command may
                    # grow helper authority. Failure is uncertain: stop the
                    # supervisor instead of applying/retrying a local-only cap.
                    atomic(responses/path.name,{**response,'status':'applying','helper_applied':'unverified'})
                else:
                    _commit_budget_update(runroot,desc,budget,request,values,response,responses/path.name)
            if native:
                # The helper extension is answered by a process that reads this
                # history itself (the parallel engine), so it runs unlocked.
                try:
                    budget['native_tool_budget']=native_control.extend(
                        command_id=request['id'], max_tool_calls=values['max_tool_calls'],
                        remaining_seconds=max(0,budget['started_host_monotonic']+values['timeout_seconds']-time.monotonic()))
                except Exception:
                    _native_unconfirmed(runroot,desc,budget,response,responses/path.name)
                try:
                    with history_lock(runroot):
                        _commit_budget_update(runroot,desc,budget,request,values,response,responses/path.name)
                except LockBusy:
                    # The host record of an applied extension cannot be completed:
                    # the existing fail-closed outcome of an unconfirmed update.
                    _native_unconfirmed(runroot,desc,budget,response,responses/path.name)
        if closing:
            budget['phase']='stopped';atomic(budget_path(runroot,desc),budget)
        if native_control is not None:
            budget['native_tool_budget']=native_control.status(force=closing)
            atomic(budget_path(runroot,desc),budget)
    return budget


def _commit_budget_update(runroot,desc,budget,request,values,response,target):
    """Apply an accepted request: budget, view, response, then its applied event.

    Called under the stage lock and history_lock(), so the published applied
    response and its applied event exist together or not at all.
    """
    budget['effective_limits']=values;budget['revision']+=1
    budget['deadline_host_monotonic']=budget['started_host_monotonic']+values['timeout_seconds']
    atomic(budget_path(runroot,desc),budget)
    publish_budget(runroot,desc,budget,request['id'])
    response.update(budget_revision=budget['revision'],after=dict(values),host_applied=True,
                    worker_applied='unverified')
    atomic(target,response)
    audit(runroot,request,'applied',before=response['before'],after=values,budget_revision=budget['revision'],host_applied=True)


def _native_unconfirmed(runroot,desc,budget,response,target):
    budget['native_budget_error']='accounting_unavailable'
    atomic(budget_path(runroot,desc),budget)
    atomic(target,{**response,'status':'rejected',
        'reason':'native_budget_update_unconfirmed','helper_applied':'unknown'})
    raise ControlError('Native budget update unconfirmed; no retry permitted') from None


def _reject_unreadable(requests,responses,desc,path,exc):
    """Move an unreadable request aside with its reason; the stage carries on."""
    rejected=requests/'rejected';rejected.mkdir(exist_ok=True)
    reason='Unreadable budget request: '+type(exc).__name__
    os.replace(path,rejected/path.name)
    record={'schema':2,'id':path.stem,'stage_id':desc['stage_id'],'status':'rejected',
            'reason':reason,'updated_at':now()}
    atomic(rejected/(path.stem+'.reason.json'),record)
    if not (responses/path.name).exists():atomic(responses/path.name,record)


def settle_budget_without_lock(runroot,desc,closing=False,native_control=None):
    """Fallback when the stage lock stays busy: process no request, only settle.

    The supervisor is the only writer of budget.json (control commands only
    read it), so it may close the budget without the stage lock. A request that
    is still queued stays unanswered; a closed budget refuses it as late.
    """
    budget=read(budget_path(runroot,desc))
    if closing:budget['phase']='stopped'
    if native_control is not None:budget['native_tool_budget']=native_control.status(force=closing)
    if closing or native_control is not None:atomic(budget_path(runroot,desc),budget)
    return budget


def _history_fd(fd):
    os.lseek(fd,0,os.SEEK_SET)
    chunks=[];remaining=16*1024*1024+1
    while remaining:
        chunk=os.read(fd,min(65536,remaining))
        if not chunk:break
        chunks.append(chunk);remaining-=len(chunk)
    data=b''.join(chunks)
    if len(data)>16*1024*1024:raise ControlError('Intervention history limit exceeded')
    return [json.loads(line) for line in data.splitlines() if line.strip()]


def _held_history(runroot):
    held=_history_held.get()
    return held[1] if held is not None and held[0]==str(Path(runroot).resolve()) else None


@contextmanager
def history_lock(runroot):
    """Hold the intervention history exclusively across a multi-event commit.

    audit() and history() in this context use the held descriptor, so a commit
    that must append several events (accepted, then applied) takes the lock
    once, before it publishes anything. Under bounded_locks() a busy history
    raises LockBusy here, while nothing of the commit exists yet. Nesting is
    reentrant. The lock is per open file, so it is never held across a call
    that another process answers by reading the history itself.
    """
    key=str(Path(runroot).resolve())
    held=_history_held.get()
    if held is not None and held[0]==key:
        yield
        return
    fd=os.open(Path(runroot)/'interventions.jsonl',os.O_RDWR|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode) or os.fstat(fd).st_nlink!=1:raise ControlError('Unsafe intervention history')
        _flock(fd,fcntl.LOCK_EX)
        token=_history_held.set((key,fd))
        try:
            yield
        finally:
            _history_held.reset(token)
    finally:
        os.close(fd)


def history(runroot):
    held=_held_history(runroot)
    if held is not None:return _history_fd(held)
    path=Path(runroot)/'interventions.jsonl'
    if not path.exists():return []
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):raise ControlError('Unsafe intervention history')
        _flock(fd,fcntl.LOCK_SH)
        return _history_fd(fd)
    finally:os.close(fd)


def audit(runroot,context,status,**details):
    """Append and fsync parent events. Only sanitized identifiers/hashes/numbers."""
    held=_held_history(runroot)
    if held is not None:return _append_event(held,runroot,context,status,details)
    path=Path(runroot)/'interventions.jsonl'
    fd=os.open(path,os.O_RDWR|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode) or os.fstat(fd).st_nlink!=1:raise ControlError('Unsafe intervention history')
        _flock(fd,fcntl.LOCK_EX)
        return _append_event(fd,runroot,context,status,details)
    finally:os.close(fd)


def _append_event(fd,runroot,context,status,details):
    """Append one event on an exclusively locked history descriptor."""
    records=_history_fd(fd)
    if len(records)>=10000:raise ControlError('Intervention event limit exceeded')
    event={k:context.get(k) for k in ('intervention_id','id','run_id','attempt_id','stage_id','segment_id','kind','payload_digest','expected_stage_revision','expected_budget_revision')}
    event.update(schema=2,sequence=len(records)+1,status=status,timestamp=now(),
                 authorization_source='parent_cli',**details)
    encoded=(json.dumps(event,ensure_ascii=False)+'\n').encode()
    view=memoryview(encoded)
    while view:
        written=os.write(fd,view)
        if written<=0:raise ControlError('Intervention append failed')
        view=view[written:]
    os.fsync(fd)
    directory_fd=os.open(Path(runroot),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(directory_fd)
    finally:os.close(directory_fd)
    return event


def requested(runroot,record):
    return any(e['status']=='requested' and all(e.get(k)==record.get(k) for k in
               ('id','intervention_id','stage_id','run_id','attempt_id')) for e in history(runroot))


def assistance(runroot):
    ids=list(dict.fromkeys(e['intervention_id'] for e in history(runroot) if e['status']=='accepted'))
    return {'status':'assisted' if ids else 'autonomous','intervention_ids':ids}


def capture_observations(runroot,desc):
    """Only link observations to existing parent acceptance; never authorize from them."""
    records=history(runroot)
    accepted={e['id']:e for e in records if e['status']=='accepted' and e['stage_id']==desc['stage_id']}
    observed={e.get('observation_digest') for e in records if e['status']=='observed'}
    if not accepted:return
    outbox=os.open(desc['outbox'],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    sources=[]
    try:
        try:
            acks=os.open('acks',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=outbox)
        except OSError:acks=None
        if acks is not None:
            with os.scandir(acks) as entries:
                for index,entry in enumerate(entries):
                    if index>=128:break
                    if entry.name.endswith('.json') and entry.name[:-5] in accepted:
                        sources.append((acks,entry.name))
        sources.append((outbox,'limits_ack.json'))
        for parent,name in sources:
            fd=None
            try:
                fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
                if not stat.S_ISREG(os.fstat(fd).st_mode):continue
                data=json.loads(os.read(fd,65536))
                if not isinstance(data,dict):continue
                context=accepted.get(data.get('id'))
                if not context or data.get('schema')!=2 or any(data.get(k)!=context.get(k) for k in ('stage_id','run_id','attempt_id','segment_id')):continue
                if data.get('expected_stage_revision')!=context.get('expected_stage_revision'):continue
                if context['kind']=='extend_budget' and data.get('budget_revision')!=context.get('expected_budget_revision',-1)+1:continue
                response={'child_status':data.get('status') if data.get('status') in ('active','observed','applied','rejected') else 'unknown'}
                revision=data.get('budget_revision')
                if type(revision) is int and 0<=revision<=10000:response['child_budget_revision']=revision
                digest=hashlib.sha256(json.dumps([data['id'],response],sort_keys=True).encode()).hexdigest()
                if digest not in observed:
                    audit(runroot,context,'observed',observation_digest=digest,trusted=False,**response);observed.add(digest)
            except (OSError,ValueError,TypeError):pass
            finally:
                if fd is not None:os.close(fd)
    finally:
        if acks is not None:os.close(acks)
        os.close(outbox)
