"""One explicitly authorized native helper startup diagnostic, never a Pi run.

Use only after source/extracted gates and independent review. The exact q10 IR
and runtime remain unchanged. All credentials are freshly generated disposable
values. The only IPC is OwnedHelper.start's disabled-business status and optional
revocation. No activation, participant, inference, business request or retry is
implemented. Actual execution belongs to the approving coordinator.
"""
import argparse
import contextlib
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import sys
import time
from types import SimpleNamespace
import uuid

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'skill/scripts'),str(REPO/'skill/runtime'),str(REPO/'tools/qualification')]
import application_client as client
import application_contracts as contracts
import application_credentials as credentials
from application_execution_authority import ReviewedAuthority
import application_followup as followup
import application_launch as launch
import ownership_registry as ownership
from parallel_allocator import Allocator
import pi_lab as lab

ROOT=followup.DIAGNOSTIC_ROOT
PRIOR=followup.PRIOR_ROOT
PLAN='inputs/api-0.87.1/compiled/plan.json'
INPUT_MANIFEST='inputs/api-0.87.1/compiled/input-manifest.json'
TASK='inputs/api-0.87.1/project/TASK.md'


class DiagnosticError(ValueError):pass


def require(value):
    if not value:raise DiagnosticError('startup_diagnostic_unconfirmed')


def read(path):
    return followup._reference({'path':str(Path(path).absolute()),'sha256':digest(path)})


def digest(path):
    path=Path(path);parent=launch._dir(path.parent,False)
    try:
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno());require(stat.S_ISREG(before.st_mode) and before.st_uid==os.getuid() and before.st_nlink==1
                and not stat.S_IMODE(before.st_mode)&0o022 and before.st_size<=64*1024*1024)
            body=stream.read(64*1024*1024+1);after=os.fstat(stream.fileno());named=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        require(len(body)<=64*1024*1024 and identity(before)==identity(after)==identity(named));return hashlib.sha256(body).hexdigest()
    finally:os.close(parent)


def reference(path):return {'path':str(Path(path).absolute()),'sha256':digest(path)}


def publish(path,value):
    path=Path(path);parent=launch._dir(path.parent)
    try:
        fd=launch._file(parent,path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL)
        with os.fdopen(fd,'wb') as stream:stream.write(launch._json(value));stream.flush();os.fsync(stream.fileno())
        os.fsync(parent)
    finally:os.close(parent)


def inventory():
    """Complete gate scope, without following source aliases or cache files."""
    result={}
    for base in ('skill','tests','tools'):
        root=REPO/base;fd=launch._dir(root,False);os.close(fd)
        for parent,directories,files in os.walk(root,followlinks=False):
            directories[:]=sorted(name for name in directories if name!='__pycache__')
            for name in directories:require(not (Path(parent)/name).is_symlink())
            for name in sorted(files):
                if name.endswith('.pyc'):continue
                path=Path(parent)/name;require(not path.is_symlink())
                result[str(path.relative_to(REPO))]=digest(path)
    return result


def source_gate(path):
    value=read(path);launch._exact(value,{'schema','status','source_gate','extracted_gate','extracted_result','independent_review'})
    require(type(value['schema']) is int and value['schema']==1 and value['status']=='PASS')
    source=followup._reference(value['source_gate']);extracted=followup._reference(value['extracted_gate']);result=followup._reference(value['extracted_result']);review=followup._reference(value['independent_review'])
    for gate in (source,extracted):
        require(type(gate['actual_exit']) is int and gate['actual_exit']==0 and type(gate['expected_exit']) is int and gate['expected_exit']==0
            and gate['source_stable'] is True and gate['source_before']==gate['source_after'])
    require(source['source_after']==extracted['source_after'] and review['status']=='PASS' and review['unresolved_findings']==[])
    require(review['source_gate']==value['source_gate'] and review['extracted_gate']==value['extracted_gate']
        and review['extracted_result']==value['extracted_result'] and review['source_files']==source['source_after'])
    require(type(source['tests_run']) is int and source['tests_run']>0 and type(source['tests_skipped']) is int and source['tests_skipped']==0
        and result['status']=='pass' and result['tests_run']==source['tests_run'] and type(result['tests_run']) is int
        and type(result['tests_skipped']) is int and result['tests_skipped']==0 and type(result['unit_tests']['exit_code']) is int and result['unit_tests']['exit_code']==0
        and result['source_unchanged'] is True and result['archives_unchanged'] is True
        and result['extracted_inventory_before']==result['extracted_inventory_after'])
    files=source['source_after'];require(files==inventory());required={'tools/qualification/application_startup_diagnostic.py','tools/qualification/application_followup.py','tools/qualification/application_launch.py'}
    require(type(files) is dict and required<=set(files) and any(p.startswith('skill/runtime/') for p in files))
    archived=result['extracted_inventory_after']
    # Match the existing source-archive publication boundary: internal release
    # hardening tools remain in the complete source gate but never ship.
    excluded={name for name in files if name.startswith('tools/release-hardening/')}
    require(set(files)-set(archived)==excluded
        and not any(name=='tools/release-hardening' or name.startswith('tools/release-hardening/') for name in archived))
    for name,sha in files.items():
        require(type(name) is str and not Path(name).is_absolute() and '..' not in Path(name).parts and str(Path(name))==name)
        require(digest(REPO/name)==sha)
        if name not in excluded:require(archived[name]['sha256']==sha)
    return reference(path)


def public_inputs(authority):
    old=followup._reference(authority['prior_manifest']);require(old['prepared_root']==str(PRIOR))
    result={}
    for relative in (PLAN,INPUT_MANIFEST,TASK,'inputs/endpoint.json'):
        path=PRIOR/relative;require(digest(path)==old['files'][relative]);result[relative]=reference(path)
    plan=read(PRIOR/PLAN);manifest=read(PRIOR/INPUT_MANIFEST);endpoint=read(PRIOR/'inputs/endpoint.json')
    contracts.validate_ir(plan)
    require(plan['runtime']['pi_release']=='0.87.1' and plan['runtime']['container_profile']=='core'
        and plan['runtime']['image_id']==followup.DIAGNOSTIC_IMAGE and manifest['plan_sha256']==plan['plan_sha256']
        and manifest['runner']['sha256']==plan['input_hashes']['runner'])
    for name,sha in manifest['runner']['files'].items():require(digest(REPO/'skill'/name)==sha)
    return plan,manifest,endpoint,result


class Budget:
    def __init__(self,started,started_wall):
        self.started,self.started_wall=started,started_wall;self.deadline=started+120;self.cleanup_deadline=None;self.cleanup_started=None;self.on_cleanup=None;self.locks=[]
    def fence(self):
        for fd,path in self.locks:
            held=os.fstat(fd);named=os.stat(path,follow_symlinks=False)
            require(stat.S_ISREG(held.st_mode) and held.st_uid==os.getuid() and held.st_nlink==1 and not stat.S_IMODE(held.st_mode)&0o077
                and (held.st_dev,held.st_ino)==(named.st_dev,named.st_ino))
    def remaining(self):
        self.fence();deadline=self.cleanup_deadline if self.cleanup_deadline is not None else self.started+90
        left=min(deadline,self.deadline,followup.prior_successor.DEADLINE_MONOTONIC)-time.monotonic()
        left=min(left,followup.prior_successor.DEADLINE_WALL-time.time());require(left>0);return left
    def cleanup(self):
        if self.cleanup_started is None:
            self.cleanup_started=time.monotonic();self.cleanup_deadline=min(self.deadline,self.cleanup_started+30)
            if self.on_cleanup is not None:self.on_cleanup()


@contextlib.contextmanager
def original_lease(budget,runroot):
    path=Path(lab.default_lock_file());require(path==Path.home()/'.local/state/pi-agentic-development/operation.lock')
    parent=launch._dir(path.parent,False)
    try:fd=os.open(path.name,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
    finally:os.close(parent)
    token=None;controller=None
    try:
        budget.locks.append((fd,path));budget.fence();wait_end=min(time.monotonic()+30,budget.started+90)
        while True:
            budget.remaining()
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);break
            except BlockingIOError:require(time.monotonic()<wait_end);time.sleep(.025)
        controller_path=ROOT/'controller.lock';parent=launch._dir(ROOT)
        try:controller=launch._file(parent,'controller.lock',os.O_RDWR|os.O_CREAT|os.O_EXCL)
        finally:os.close(parent)
        fcntl.flock(controller,fcntl.LOCK_EX|fcntl.LOCK_NB);budget.locks.append((controller,controller_path));budget.fence()
        registry=ownership.Registry(Path(str(path)+'.registry'))
        # A diagnostic owns no authority to reconcile another run's resources.
        require(all(record['status']=='released' for record in registry.load()))
        registry.lease_fd=fd;registry.runroot=runroot
        token=ownership.CURRENT.set(registry);yield registry
    finally:
        if token is not None:ownership.CURRENT.reset(token)
        budget.locks=[]
        if controller is not None:os.close(controller)
        os.close(fd)


class DiagnosticLab:
    """The normal lab interface with time bounds and mutation-attempt receipts."""
    def __init__(self,budget):
        self.budget=budget;self.original=lab.command;self.removals=set();self.events=[]
    def command(self,argv,timeout=30,required=True):
        self.budget.remaining();require(type(argv) is list and all(type(v) is str for v in argv) and argv[:1]==['docker'])
        allowed=(argv[1:2] in (['info'],['port']) or argv[1:3] in (['image','inspect'],['container','inspect'],['network','inspect'],['network','create'],['network','rm']) or argv[1:2]==['rm'])
        require(allowed)
        mutation=argv[1:2]==['rm'] or argv[1:3]==['network','rm']
        if mutation:
            key=('network' if argv[1]=='network' else 'container',argv[-1]);require(key not in self.removals);self.removals.add(key)
        started=time.monotonic()
        try:return self.original(argv,timeout=min(timeout,self.budget.remaining()),required=required)
        finally:self.events.append({'operation':' '.join(argv[1:3]) if argv[1] in ('image','container','network') else argv[1],'elapsed_seconds':time.monotonic()-started})
    def observe_command(self,argv,timeout=15):return self.command(argv,timeout=timeout,required=False)
    def image_info(self,image,platform):return lab.image_info(image,platform)


def private_identity(path):
    fd=launch._dir(path)
    try:info=os.fstat(fd);return {'path':str(path),'device':info.st_dev,'inode':info.st_ino}
    finally:os.close(fd)


def purge_private(path,identity,budget):
    """Only owned, bounded private trees; every deletion is relative to held FDs."""
    budget.remaining();parent=launch._dir(path.parent,False);directory=None;count=[0]
    def clear(fd):
        names=os.listdir(fd);require(len(names)<=32)
        for name in names:
            budget.remaining();count[0]+=1;require(count[0]<=128)
            st=os.stat(name,dir_fd=fd,follow_symlinks=False);require(st.st_uid==os.getuid())
            if stat.S_ISDIR(st.st_mode):
                require(stat.S_IMODE(st.st_mode)==0o700);child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                try:
                    held=os.fstat(child);require((held.st_dev,held.st_ino)==(st.st_dev,st.st_ino));clear(child);budget.remaining()
                    named=os.stat(name,dir_fd=fd,follow_symlinks=False);require((named.st_dev,named.st_ino)==(st.st_dev,st.st_ino));os.rmdir(name,dir_fd=fd)
                finally:os.close(child)
            else:
                require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and stat.S_IMODE(st.st_mode) in (0o400,0o600));os.unlink(name,dir_fd=fd)
            os.fsync(fd)
    try:
        directory=os.open(path.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);held=os.fstat(directory)
        require((held.st_dev,held.st_ino)==(identity['device'],identity['inode']) and held.st_uid==os.getuid() and stat.S_IMODE(held.st_mode)==0o700)
        clear(directory);budget.remaining();named=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        require((named.st_dev,named.st_ino)==(held.st_dev,held.st_ino));os.rmdir(path.name,dir_fd=parent);os.fsync(parent)
    finally:
        if directory is not None:os.close(directory)
        os.close(parent)


def owned_container(record,observed):
    require(type(observed) is dict and observed['Id']==record['container_id'] and observed['Image']==record['image'])
    labels=observed.get('Config',{}).get('Labels') or {};require(labels.get(ownership.LABEL)==record['launch_id'] and labels.get(ownership.REGISTRY_LABEL)==record['registry'])
    actual=observed.get('Mounts',[]);require(len(actual)==len(record['mounts']) and all(any(m.get('Source')==e['source'] and m.get('Destination')==e['target'] and m.get('RW') is e['rw'] for m in actual) for e in record['mounts']))
    h=observed['HostConfig'];require(h.get('ReadonlyRootfs') is True and h.get('NanoCpus')==1000000000 and h.get('Memory')==536870912 and h.get('MemorySwap')==536870912 and h.get('PidsLimit')==128)
    require(observed['Config'].get('User')==str(os.getuid())+':'+str(os.getgid()))


def pid_absent(pid):
    try:os.kill(pid,0)
    except ProcessLookupError:return True
    except OSError:return False
    return False


def wait_writer_absent(pid,budget):
    """Reap only the exact direct child issued by the guard, without a Popen ref."""
    require(type(pid) is int and 1<=pid<2**31)
    deadline=time.monotonic()+min(3,budget.remaining())
    while True:
        budget.remaining()
        try:
            observed,status=os.waitpid(pid,os.WNOHANG)
        except ChildProcessError:
            return pid_absent(pid),None
        except OSError:
            return False,None
        if observed==pid:
            code=os.waitstatus_to_exitcode(status)
            return pid_absent(pid),code if code>=0 else None
        if pid_absent(pid):return True,None
        if time.monotonic()>=deadline:return False,None
        time.sleep(.025)


def cleanup_native(registry,ledger,proxy,identities,private,runroot,authority,grant,helper,budget):
    budget.cleanup();budget.remaining();snapshot=ledger.snapshot();require(len(snapshot['launches'])==1);row=snapshot['launches'][0]
    require(row['role']=='application-helper' and row['container_id'] is not None)
    records=[r for r in registry.load() if r['generation']==registry.generation]
    matches=[r for r in records if r.get('application_helper') is True];require(len(matches)==1)
    record=matches[0];require(launch._intent_identity(record)==row['intent_sha256'] and record.get('container_id') in (None,row['container_id']))
    record['container_id']=row['container_id'];identifier=row['container_id'];exit_code=None
    # Bind the guard's already-observed immutable ID to the authoritative record
    # before patched Registry cleanup compares local/current custody.
    registry.write(record)
    reply=proxy.command(['docker','container','inspect',identifier],required=False)
    if reply.returncode==0:
        data=json.loads(reply.stdout);require(type(data) is list and len(data)==1);owned_container(record,data[0])
        state=data[0]['State']
        if state.get('Running') is False and type(state.get('ExitCode')) is int:exit_code=state['ExitCode']
        # Prior unknown mutation attempts cannot authorize a cleanup retry.
        require(not row['cleanup_requests'] or not any(r['operation']=='rm' for r in row['cleanup_requests']))
        if helper is not None:
            try:helper.revoke(grant)
            except (client.ClientError,OSError):pass
        proxy.command(['docker','rm','--force',identifier])
    else:require(launch.LaunchGuard._absent(reply,identifier))
    if helper is not None:
        helper._reap_owned_process()
        if type(helper.process.returncode) is int and helper.process.returncode>=0:exit_code=helper.process.returncode
    if type(row['pid']) is int:
        writer_absent,reaped_exit=wait_writer_absent(row['pid'],budget);require(writer_absent)
        if reaped_exit is not None:exit_code=reaped_exit
    require(registry.confirm_absent(record) is True)
    redactor=credentials.Redactor([*authority._inference_values,*(v for aliases in authority._values.values() for v in aliases.values()),grant.capability,authority._control_token,*authority._budget_tokens.values()])
    # All private roots are deleted before public scans and Registry release.
    candidates=[private]
    candidates.extend(Path(r['private_store']) for r in matches)
    candidates.extend(p/'private' for p in (runroot/'application-evidence').glob('*') if p.is_dir() and not p.is_symlink())
    removed=[]
    for path in candidates:
        require(ROOT in path.parents and str(path) in identities)
        ident=identities[str(path)]
        if not ownership._qualification_absent(str(path)):purge_private(path,ident,budget)
        require(ownership._qualification_absent(str(path)));removed.append({**ident,'removed':True})
    require(credentials.workspace_inspected_clean(runroot,redactor))
    networks=[r for r in records if r.get('kind')=='network'];require(len(networks)<=1)
    network_reference=None
    if networks:
        network=networks[0];require(network['container']==record['container']+'-network' and network['daemon']==record['daemon'])
        if network['status']!='released':registry.remove_network(network);registry.release(network,True)
        network_reference=reference(registry.root/(network['launch_id']+'.json'))
    authority._revoked.update(g.capability for g in authority._grants)
    registry.release(record,True);ledger.assert_cell_released(followup.DIAGNOSTIC_CELL)
    return record,network_reference,removed,exit_code


def execute(args):
    gate=source_gate(args.source_gate);authority_ref=read(args.authority_ref);authorization=followup._authorization(authority_ref)
    base=read(args.base_predecessor);image_receipt=read(args.image_receipt)
    require(image_receipt['id']==followup.DIAGNOSTIC_IMAGE and image_receipt['platform']=='linux/arm64')
    plan,input_manifest,endpoint,inputs=public_inputs(authorization)
    started,started_wall=time.monotonic(),time.time();budget=Budget(started,started_wall)
    require(not ROOT.exists() and not ROOT.is_symlink());parent=launch._dir(ROOT.parent)
    try:os.mkdir(ROOT.name,0o700,dir_fd=parent);os.fsync(parent)
    finally:os.close(parent)
    manifest=followup.build_diagnostic_manifest(authority_ref,{k:image_receipt[k] for k in ('id','platform','capabilities')},base,clock=lambda:started,wall=lambda:started_wall)
    publish(ROOT/'manifest.json',manifest);publish(ROOT/'inputs.json',{'schema':1,'source_gate':gate,'authority':authority_ref,'q10_inputs':inputs,'image_receipt':reference(args.image_receipt),'runner_sha256':input_manifest['runner']['sha256']})
    private=ROOT/'private';private.mkdir(mode=0o700);store=private/'fake-store';store.mkdir(mode=0o700)
    project=ROOT/'project';project.mkdir(mode=0o700);runroot=ROOT/'run';runroot.mkdir(mode=0o700);workspace=runroot/'workspace';workspace.mkdir(mode=0o700)
    task=(PRIOR/TASK).read_bytes();(project/'TASK.md').write_bytes(task);(workspace/'TASK.md').write_bytes(task)
    for name in set(plan['application']['credentials'].values()):
        require(re.fullmatch('[A-Z][A-Z0-9_]*',name) is not None);fd=os.open(store/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f:f.write('FAKE_DIAGNOSTIC_'+secrets.token_hex(32))
    fake_inference='FAKE_INFERENCE_'+secrets.token_hex(32)
    authority=ReviewedAuthority(plan,endpoint,fake_inference,store,project,runroot,runner_files=input_manifest['runner']['files'])
    binding={key:str(uuid.uuid4()) for key in ('run_id','attempt_id','stage_id','segment_id','session_id')};binding.update(trial_id=None,plan_sha256=plan['plan_sha256'])
    grant=authority.grant(plan['stages'][0]['id'],binding);identities={str(private):private_identity(private)}
    original_private=client._private_root;original_cleanup=client.OwnedHelper.cleanup;original_reap=client.OwnedHelper._reap_owned_process;original_command=lab.command;proxy=DiagnosticLab(budget);guard=None;helper=None;outcome='startup_failed';failure=None;timings_flushed=False
    def observe_private(path):
        result=original_private(path);require(ROOT in result.parents);identities.setdefault(str(result),private_identity(result));return result
    def observe_cleanup(helper,*args,**kwargs):
        budget.cleanup()
        return original_cleanup(helper,*args,**kwargs)
    def observe_reap(helper,*args,**kwargs):
        budget.remaining();result=original_reap(helper,*args,**kwargs);budget.remaining();return result
    previous=signal.getsignal(signal.SIGALRM);timer=signal.getitimer(signal.ITIMER_REAL);require(not any(timer))
    def alarm(unused_signum,unused_frame):raise DiagnosticError('startup_diagnostic_deadline')
    signal.signal(signal.SIGALRM,alarm);signal.setitimer(signal.ITIMER_REAL,max(.001,budget.deadline-time.monotonic()))
    budget.on_cleanup=lambda:signal.setitimer(signal.ITIMER_REAL,max(.001,budget.cleanup_deadline-time.monotonic()))
    try:
        with original_lease(budget,runroot) as registry:
            registry.binding={k:binding[k] for k in ('run_id','attempt_id')}
            registry.command=lambda argv:proxy.command(argv,required=False)
            lab.command=proxy.command;client._private_root=observe_private;client.OwnedHelper.cleanup=observe_cleanup;client.OwnedHelper._reap_owned_process=observe_reap
            daemon=proxy.command(['docker','info','--format','{{json .}}']);data=json.loads(daemon.stdout)
            require(data['ID']=='3f2581a9-2d2e-46ae-aa44-b5477f9302b2' and data['OSType']=='linux' and lab.norm_arch(data['Architecture'])=='arm64')
            capacity={'cpu_millis':int(data['NCPU'])*1000,'memory_mib':int(data['MemTotal'])//1048576};registry.bind_daemon(data['ID'])
            ledger=followup.DiagnosticLedger.create(ROOT/'launch-ledger',manifest,daemon_id=data['ID'],daemon_capacity=capacity)
            require(capacity['cpu_millis']//2>=2000 and capacity['memory_mib']//2>=1536)
            allocator=Allocator({'cpu_millis':2000,'memory_mib':1536,'pids_limit':384})
            native=SimpleNamespace(platform='linux/arm64',native_platform='linux/arm64',uid=os.getuid(),gid=os.getgid())
            with launch.instrument(ledger,followup.DIAGNOSTIC_CELL,registry_getter=lambda:registry,command=proxy.command,observe_command=proxy.observe_command) as guard:
                try:
                    helper=client.OwnedHelper.start(authority,lab=proxy,args=native,registry=registry,allocator=allocator,
                        participant_resources={'cpu_millis':1000,'memory_mib':1024,'pids_limit':256})
                    outcome='ready'
                except Exception as error:
                    failure=getattr(error,'application_helper_startup',None)
                    if failure is not None:failure=client.validate_startup_failure(failure,runroot=runroot)
                finally:
                    record,network_reference,removed,exit_code=cleanup_native(registry,ledger,proxy,identities,private,runroot,authority,grant,helper,budget)
                    for reservation in allocator.records.values():
                        if reservation.state=='queued':allocator.cancel_queued(reservation.identity)
                        elif reservation.state in ('reserved','launching','running','stopping','quarantined'):allocator.release(reservation.identity,True,True)
            require(not any(allocator.used().values()))
            # The guard's observer owns its timing buffer. Flush only after all
            # native cleanup and instrumentation context exit, before final pin.
            timings=guard.flush_timings(ROOT,kind='startup_diagnostic');timings_flushed=True
            snapshot=ledger.snapshot();require(snapshot['attempts']==76 and snapshot['participant_segments']==0 and snapshot['live']==0 and snapshot['private_cleanup_pending']==0)
            budget.remaining();finished=time.time()
            terminal={'schema':1,'document_type':'qualification_startup_diagnostic_terminal','authorization':authority_ref,'qualification_id':manifest['qualification_id'],
                'manifest':reference(ROOT/'manifest.json'),'ledger':reference(ROOT/'launch-ledger/ledger.json'),'registry_record':reference(registry.root/(record['launch_id']+'.json')),
                'container_id':record['container_id'],'diagnostic_outcome':outcome,'process_exit_code':exit_code,'process_exit_code_available':exit_code is not None,
                'network_removed':True,'network_record':network_reference,'participant_segments':0,'inference_calls':0,'application_requests':0,'real_credentials_used':False,
                'physical_absence_confirmed':True,'private_cleanup_confirmed':True,'all_writers_absent':True,'private_roots_removed':removed,
                'started_wall':started_wall,'finished_wall':finished,'elapsed_seconds':finished-started_wall,'cleanup_elapsed_seconds':max(0,time.monotonic()-budget.cleanup_started),
                'original_lease_held':True,'raw_ledger_preserved':True}
            publish(ROOT/'terminal.json',terminal);publish(ROOT/'diagnostic.json',{'schema':1,'outcome':outcome,'startup_failure':failure,'timings':timings,'commands':proxy.events,
                'business_activation_called':False,'new_container_launches':1,'participant_segments':0,'fake_credentials_only':True})
            print(json.dumps({'status':'PASS','diagnostic_outcome':outcome,'container_launches':1,'participant_segments':0,'terminal':reference(ROOT/'terminal.json')}))
            return 0
    except BaseException:
        if guard is not None and not timings_flushed:
            try:guard.flush_timings(ROOT,kind='startup_diagnostic')
            except Exception:pass
        if ROOT.is_dir() and not (ROOT/'failure.json').exists():
            publish(ROOT/'failure.json',{'schema':1,'status':'BLOCKED','qualification_eligible':False,'continuation_authorized':False,'diagnostic_outcome':outcome,'raw_evidence_preserved':True})
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)
        client._private_root=original_private;client.OwnedHelper.cleanup=original_cleanup;client.OwnedHelper._reap_owned_process=original_reap;lab.command=original_command


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('authority-ref','base-predecessor','image-receipt','source-gate'):parser.add_argument('--'+name,required=True)
    args=parser.parse_args()
    try:return execute(args)
    except Exception:
        print(json.dumps({'status':'BLOCKED','reason':'startup_diagnostic_unconfirmed'}));return 2


if __name__=='__main__':raise SystemExit(main())
