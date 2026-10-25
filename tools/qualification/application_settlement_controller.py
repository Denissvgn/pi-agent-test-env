"""One fail-closed, explicitly authorized controlled settlement attempt.

New local bookkeeping is never clearance of the original host Registry. The
unchanged original lease/reconciliation must admit before any role or server.
"""
import argparse
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import pwd
import re
import select
import signal
import stat
import subprocess
import sys
import time
import uuid

import application_settlement_diagnostic as diagnostic

MODE='application_settlement_controlled_diagnostic_v1'
ROOT=Path('/home/piqual/a15-settlement-diagnostic-048')
PREPARED_ROOT=Path('/home/piqual/a15-settlement-prepared-048')
CELL='SETTLEMENT-0.87.1-1'
NORMAL_LOCK=Path(diagnostic.NORMAL_LOCK)
DAEMON={'id':'28700317-fa19-4e5e-b3e3-82b42f3c63c2','cpu_millis':7000,'memory_mib':7921}
LIMITS={'global_seconds':900,'cleanup_reserve_seconds':30,'container_launch_attempts':7,'live':4,'participant_segments':1}
DOCKER_SELECTORS=('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_CONFIG','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH','DOCKER_API_VERSION')
INPUT_SECONDS=5
MARKER_FIELDS={'schema','mode','clock','preparation','candidate','historical_use','local_plan','cumulative_upper_bound','caps'}
ACTIVATION_FIELDS={'root','grant','input_review','clock','preparation','candidate','admission','nonce','controller_sha256'}
GRANT_FIELDS={'schema','document_type','status','authorization_id','qualification_id','run_id','attempt_id','root',
 'cell_id','preparation','candidate','execution','controller','service','historical_use','local_plan','caps',
 'live_limits','automatic_retries','native_qualification_credit','controlled_environment_consent','ownership_input','ownership_read_scope'}
PEER_FIELDS={'schema','status','grant','clock','manifest','preparation','candidate','execution','controller','service',
 'supports_exact_controlled_settlement','ownership_input','unresolved'}


class ControllerError(ValueError):
    def __init__(self):super().__init__('Controlled settlement execution refused')


def need(value):
    if not value:raise ControllerError()


def _valid_key(value):
    return type(value)is str and 16<=len(value)<=4096 and value.isascii()and all(32<ord(char)<127 for char in value)


def canonical(value):return diagnostic.canonical(value)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def exact(value,keys):need(type(value)is dict and set(value)==set(keys))
def identity(value):need(type(value)is str and str(uuid.UUID(value))==value)
def number(value):need(type(value)in(int,float)and math.isfinite(value));return value
def reference(value):
    exact(value,{'path','sha256'});path=Path(value['path'])
    need(type(value['path'])is str and path.is_absolute()and str(path)==value['path']and '..'not in path.parts)
    need(type(value['sha256'])is str and re.fullmatch('[a-f0-9]{64}',value['sha256'])is not None)
    return path


def directory(path):
    path=Path(path);need(path.is_absolute()and '..'not in path.parts)
    parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);os.close(parent);parent=child
            need(os.fstat(parent).st_uid in(0,os.getuid()))
        return parent
    except BaseException:os.close(parent);raise


def signature(value):return(value.st_dev,value.st_ino,value.st_uid,value.st_mode,value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)


def read(path,maximum=4*1024*1024,*,custody=None):
    """One bounded nofollow read, with held/named regular-file header checks."""
    path=Path(path);parent=directory(path.parent);fd=None;kept=False
    try:
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode)and before.st_uid==os.getuid()and before.st_nlink==1
          and not stat.S_IMODE(before.st_mode)&0o002 and 0<before.st_size<=maximum)
        raw=bytearray()
        while len(raw)<before.st_size:
            chunk=os.read(fd,min(65536,before.st_size-len(raw)));need(bool(chunk));raw.extend(chunk)
        need(signature(before)==signature(os.fstat(fd))==signature(os.stat(path.name,dir_fd=parent,follow_symlinks=False)))
        if custody is not None:custody.append((path,parent,fd,signature(before)));kept=True
        return bytes(raw)
    finally:
        if not kept:
            if fd is not None:os.close(fd)
            os.close(parent)


def decoded(raw):
    def pairs(rows):
        out={}
        for key,value in rows:need(key not in out);out[key]=value
        return out
    def floating(value):out=float(value);number(out);return out
    def integer(value):need(len(value.lstrip('-'))<=4300);return int(value)
    value=json.loads(raw,object_pairs_hook=pairs,parse_float=floating,parse_int=integer,
        parse_constant=lambda _:(_ for _ in ()).throw(ControllerError()))
    queue=[(value,0)];nodes=0
    while queue:
        child,depth=queue.pop();nodes+=1;need(nodes<=32768 and depth<=32)
        if type(child)is dict:
            need(len(child)<=1024)
            for key,item in child.items():need(type(key)is str and len(key)<=256);queue.append((item,depth+1))
        elif type(child)is list:need(len(child)<=4096);queue.extend((item,depth+1)for item in child)
        elif type(child)is str:need(len(child)<=262144)
    return value


def bound_reference(value,maximum=4*1024*1024):
    raw=read(reference(value),maximum);need(sha(raw)==value['sha256']);return decoded(raw)


def write(path,value):
    raw=canonical(value);need(len(raw)<=1024*1024)
    flags=os.O_WRONLY|os.O_NOFOLLOW|os.O_CREAT|os.O_EXCL
    fd=os.open(path,flags,0o600)
    with os.fdopen(fd,'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())


def validate_clock(value):
    exact(value,{'schema','authorization_id','started','deadline','started_wall','deadline_wall'})
    need(type(value['schema'])is int and value['schema']==1);identity(value['authorization_id'])
    for key in ('started','deadline','started_wall','deadline_wall'):number(value[key])
    need(value['deadline']==value['started']+900 and value['deadline_wall']==value['started_wall']+900)
    return copy.deepcopy(value)


def effective_limits(value=None):
    if value is not None:validate_marker(value['settlement_diagnostic'])
    return dict(LIMITS)


def validate_marker(value):
    exact(value,MARKER_FIELDS);need(type(value['schema'])is int and value['schema']==1 and value['mode']==MODE)
    exact(value['clock'],{'started','deadline','started_wall','deadline_wall'})
    clock={'schema':1,'authorization_id':'00000000-0000-4000-8000-000000000001',**value['clock']};validate_clock(clock)
    for name in ('preparation','candidate'):reference(value[name])
    for key,expected in (('historical_use',diagnostic.CURRENT_USE),('local_plan',diagnostic.PLAN_MAX),
                         ('cumulative_upper_bound',diagnostic.POST_MAX),('caps',diagnostic.CAPS)):
        need(canonical(value[key])==canonical(expected))
    return copy.deepcopy(value)


def launch_manifest(qualification_id,clock,preparation,candidate):
    identity(qualification_id);clock=validate_clock(clock)
    images={profile+'-0.87.1':{'id':image,'platform':'linux/arm64','capabilities':{'pi':'0.87.1'}}for profile,image in diagnostic.IMAGE_IDS.items()}
    cell={'id':CELL,'group':'N04','release':'0.87.1','image_id':diagnostic.IMAGE_IDS['browser'],
      'allowed_images':[diagnostic.IMAGE_IDS['browser'],diagnostic.IMAGE_IDS['core']],
      'role_limits':dict.fromkeys(diagnostic.ROLES,1),'container_launches_max':7,'participant_segments_max':1}
    return {'qualification_id':qualification_id,'images':images,'cells':[cell],'limits':dict(LIMITS),'planned_container_launches':7,
      'settlement_diagnostic':{'schema':1,'mode':MODE,'clock':{key:clock[key]for key in ('started','deadline','started_wall','deadline_wall')},
        'preparation':copy.deepcopy(preparation),'candidate':copy.deepcopy(candidate),'historical_use':dict(diagnostic.CURRENT_USE),
        'local_plan':dict(diagnostic.PLAN_MAX),'cumulative_upper_bound':dict(diagnostic.POST_MAX),'caps':dict(diagnostic.CAPS)}}


def validate_launch_manifest(value):
    exact(value,{'qualification_id','images','cells','limits','planned_container_launches','settlement_diagnostic'})
    marker=validate_marker(value['settlement_diagnostic']);identity(value['qualification_id'])
    clock={'schema':1,'authorization_id':'00000000-0000-4000-8000-000000000001',**marker['clock']}
    need(canonical(value)==canonical(launch_manifest(value['qualification_id'],clock,marker['preparation'],marker['candidate'])))
    return copy.deepcopy(value)


def _sdk():
    path=Path(__file__).with_name('application_client.py')
    spec=importlib.util.spec_from_file_location('settlement_original_sdk',path);module=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=module;spec.loader.exec_module(module);return module


def _ownership_checker():
    path=Path(__file__).with_name('application_settlement_checks.py')
    spec=importlib.util.spec_from_file_location('settlement_fixed_ownership_check',path);module=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=module;spec.loader.exec_module(module);return module


def load_activation(activation,q):
    exact(activation,ACTIVATION_FIELDS);need(activation['root']==str(ROOT));identity(activation['nonce'])
    for key,name in (('grant','native-authorization.json'),('clock','clock.json'),('input_review','independent-input-review.json'),('candidate','candidate.json'),('admission','service-admission.json')):
        need(reference(activation[key])==ROOT/name)
    need(reference(activation['preparation'])==PREPARED_ROOT/'PREPARATION.json')
    need(activation['controller_sha256']==sha(read(Path(__file__),1024*1024)))
    grant=bound_reference(activation['grant']);clock=validate_clock(bound_reference(activation['clock']));peer=bound_reference(activation['input_review'])
    exact(grant,GRANT_FIELDS);exact(peer,PEER_FIELDS)
    need(type(grant['schema'])is int and grant['schema']==1 and grant['document_type']=='controlled_settlement_native_authorization'
      and grant['status']=='AUTHORIZED_CONTROLLED_DIAGNOSTIC_ONLY'and grant['root']==str(ROOT)and grant['cell_id']==CELL)
    for key in ('authorization_id','qualification_id','run_id','attempt_id'):identity(grant[key])
    need(clock['authorization_id']==grant['authorization_id'])
    for key,expected in (('historical_use',diagnostic.CURRENT_USE),('local_plan',diagnostic.PLAN_MAX),('caps',diagnostic.CAPS),('live_limits',diagnostic.LIVE)):
        need(canonical(grant[key])==canonical(expected))
    need(type(grant['automatic_retries'])is int and grant['automatic_retries']==0 and grant['native_qualification_credit']is False)
    need(peer['schema']==1 and type(peer['schema'])is int and peer['status']=='PASS'
      and peer['supports_exact_controlled_settlement']is True and peer['unresolved']==[])
    for key in ('grant','clock','preparation','candidate'):need(peer[key]==activation[key])
    for key in ('preparation','candidate'):need(grant[key]==activation[key])
    for key in ('controller','service','execution'):need(peer[key]==grant[key])
    need(reference(grant['execution'])==ROOT/'execution.json')
    need(peer['ownership_input']==grant['ownership_input']and reference(grant['ownership_input'])==ROOT/'ownership-input.json')
    need(canonical(grant['ownership_read_scope'])==canonical({'record_body_passes_max':6,'record_body_bytes_each_max':1048576,
      'seconds_max':120,'proof_reference_follows':0,'Docker_PID_queries':0,'record_writes':0}))
    _ownership_checker().validate_ownership_input(bound_reference(grant['ownership_input']))
    need(reference(grant['controller'])==Path(__file__).absolute()and grant['controller']['sha256']==activation['controller_sha256'])
    service=Path(__file__).with_name('application_settlement_service.py').absolute()
    need(reference(grant['service'])==service and sha(read(service,1024*1024))==grant['service']['sha256'])
    need(reference(peer['manifest'])==ROOT/'manifest.json');manifest=validate_launch_manifest(bound_reference(peer['manifest']))
    need(manifest['qualification_id']==grant['qualification_id']and manifest['settlement_diagnostic']['clock']=={key:clock[key]for key in ('started','deadline','started_wall','deadline_wall')})
    need(manifest['settlement_diagnostic']['preparation']==activation['preparation']and manifest['settlement_diagnostic']['candidate']==activation['candidate'])
    candidate=bound_reference(activation['candidate']);exact(candidate,{'archive_sha256','runner_sha256','scope'})
    for key in ('archive_sha256','runner_sha256'):need(type(candidate[key])is str and re.fullmatch('[a-f0-9]{64}',candidate[key])is not None)
    need(candidate['scope']=='extracted_candidate'and candidate['runner_sha256']==q.source_identity()['runner'])
    document=diagnostic.verify(PREPARED_ROOT)
    need(sha(read(PREPARED_ROOT/'PREPARATION.json'))==activation['preparation']['sha256'])
    configuration=bound_reference(grant['execution']);exact(configuration,{'session','secrets_dir','credential_references','fixture_route','source','daemon'})
    need(type(configuration['session'])is str and 1<=len(configuration['session'])<=64 and configuration['source']==q.source_identity()and configuration['daemon']==DAEMON)
    q._route(configuration['fixture_route']);need(configuration['fixture_route']['origin']=='http://172.17.0.1:18080')
    q.c.exact(configuration['credential_references'],{'alice','bob','scripted_inference'},'')
    need(configuration['credential_references']['alice']==diagnostic.preparation._json(PREPARED_ROOT/'CONTRACT.json')['actor_credential_reference'])
    for value in configuration['credential_references'].values():q.secret_store.check_name(value)
    need(configuration['credential_references']['scripted_inference']==diagnostic.SCRIPT_KEY_REFERENCE)
    store=Path(configuration['secrets_dir']);need(store.is_absolute()and '..'not in store.parts and store!=ROOT and ROOT not in store.parents and store not in ROOT.parents)
    endpoint=q.lab.normalize_endpoint(diagnostic.preparation._json(PREPARED_ROOT/'CONTRACT.json')['inference']['configuration'])
    need(canonical(grant['controlled_environment_consent'])==canonical({'endpoint':endpoint,'config_dir':str(ROOT/'controlled-config'),
      'session':configuration['session'],'new_confirmation_only':True,'default_state_namespace_unchanged':True}))
    return grant,clock,manifest,configuration,document


def prepare_session(q,configuration):
    """Ordinary saved-environment gate, new confirmation only, no health request."""
    config=ROOT/'controlled-config';config.mkdir(mode=0o700)
    endpoint=q.lab.normalize_endpoint(diagnostic.preparation._json(PREPARED_ROOT/'CONTRACT.json')['inference']['configuration'])
    os.environ['PI_LAB_CONFIG_DIR']=str(config)
    metadata=q.lab_env.save_environment(endpoint,name='controlled-settlement-diagnostic')
    q.lab_env.confirm_session_once(configuration['session'],metadata['fingerprint'])
    need(q.lab_env.evaluate(configuration['session'],check=False,store=configuration['secrets_dir']).get('state')=='ready')


def _host_identity(q):
    need(not any(name in os.environ for name in DOCKER_SELECTORS))
    user=pwd.getpwuid(os.getuid())
    need(os.getuid()==1000 and user.pw_name=='piqual'and user.pw_dir==os.environ.get('HOME')=='/home/piqual'
      and os.uname().machine=='aarch64'and Path(q.lab.default_lock_file()).absolute()==NORMAL_LOCK
      and 'PI_LAB_STATE_DIR'not in os.environ)
    info=ROOT.lstat();need(stat.S_ISDIR(info.st_mode)and info.st_uid==os.getuid()and stat.S_IMODE(info.st_mode)==0o700)


def remaining(clock):
    need(time.monotonic()>=clock['started']and time.time()>=clock['started_wall'])
    left=min(clock['deadline']-time.monotonic(),clock['deadline_wall']-time.time());need(left>0);return left


def verify_service_admission(activation,*,control_fd,parent_pid):
    """Verify only the source-owned permit created after original reconciliation."""
    q=_sdk();grant,clock,_,_,_=load_activation(activation,q);need(remaining(clock)>0)
    need(type(control_fd)is int and control_fd>=3 and type(parent_pid)is int and parent_pid==os.getppid())
    stored=bound_reference(activation['admission']);exact(stored,{'schema','permit','lease_identity','control_pipe_identity','parent_pid','registry_id','generation','daemon_id'})
    need(stored['schema']==1 and type(stored['schema'])is int and stored['parent_pid']==parent_pid and stored['daemon_id']==DAEMON['id'])
    actual=os.fstat(control_fd)
    need(stat.S_ISFIFO(actual.st_mode)and actual.st_uid==os.getuid()
      and [actual.st_dev,actual.st_ino,actual.st_uid,stat.S_IMODE(actual.st_mode)]==stored['control_pipe_identity'])
    permit={'schema':1,'authorization_id':grant['authorization_id'],'nonce':activation['nonce'],
      'deadline_wall':clock['deadline_wall'],'deadline_monotonic':clock['deadline'],'normal_lock_file':str(NORMAL_LOCK),
      'registry_root':str(NORMAL_LOCK)+'.registry','parent_registry_admission_attested':True,
      'grant_sha256':activation['grant']['sha256'],'input_review_sha256':activation['input_review']['sha256'],
      'clock_sha256':activation['clock']['sha256'],'preparation_sha256':activation['preparation']['sha256'],
      'candidate_sha256':activation['candidate']['sha256']}
    need(canonical(stored['permit'])==canonical(permit))
    deadline=min(time.monotonic()+5,clock['deadline']);frame=bytearray()
    while b'\n'not in frame:
        need(len(frame)<4096 and time.monotonic()<deadline)
        ready,_,_=select.select([control_fd],[],[],max(.001,deadline-time.monotonic()))
        need(bool(ready));chunk=os.read(control_fd,4096-len(frame));need(bool(chunk));frame.extend(chunk)
    need(decoded(bytes(frame))=={'schema':1,'status':'PARENT_ORIGINAL_ADMISSION_ATTESTED','nonce':activation['nonce']})
    return permit


class ServiceProcess:
    """One returned owned process, one private stdin frame, bounded stop/reap."""
    def __init__(self,original_popen,activation,registry,clock,key):
        self.child=None;self.closed=False;self.cleanup_attempted=False;self.constructor_uncertain=False;self.clock=clock;self.activation=activation;self.registry=registry;self.key=key;self.popen=original_popen
        self.control_read,self.control_write=os.pipe()
        self.control_identity=os.fstat(self.control_read)
    def start(self):
        need(self.child is None and _valid_key(self.key))
        lifetime=int(min(900,remaining(self.clock)));need(lifetime>30)
        argv=[sys.executable,'-B',str(Path(__file__).with_name('application_settlement_service.py')),'serve',
          '--control-fd',str(self.control_read),'--parent-pid',str(os.getpid())]
        env={k:os.environ[k]for k in ('HOME','USER','LOGNAME','PATH','LANG','LC_ALL')if k in os.environ}
        self.constructor_uncertain=True
        self.child=self.popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
          pass_fds=(self.control_read,),close_fds=True,start_new_session=True,env=env)
        self.constructor_uncertain=False
        os.close(self.control_read);self.control_read=None
        barrier=canonical({'schema':1,'status':'PARENT_ORIGINAL_ADMISSION_ATTESTED','nonce':self.activation['nonce']})+b'\n'
        need(os.write(self.control_write,barrier)==len(barrier))
        capsule={'schema':1,'model':diagnostic.MODEL,'endpoint':'http://172.17.0.1:19081/v1',
          'lifetime_seconds':lifetime,'inference_key':self.key,'activation':self.activation}
        raw=canonical(capsule)+b'\n';need(len(raw)<=65536);self.child.stdin.write(raw);self.child.stdin.flush();self.child.stdin.close()
        deadline=min(time.monotonic()+5,self.clock['deadline']);frame=bytearray()
        while b'\n'not in frame:
            need(len(frame)<4096 and time.monotonic()<deadline)
            ready,_,_=select.select([self.child.stdout],[],[],max(.001,deadline-time.monotonic()))
            need(bool(ready));chunk=os.read(self.child.stdout.fileno(),4096-len(frame));need(bool(chunk));frame.extend(chunk)
        need(decoded(bytes(frame))=={'schema':1,'status':'SERVICE_READY','phase':'LISTENING'}and self.child.poll()is None)
        return self
    def close(self):
        if self.cleanup_attempted:need(self.closed);return
        self.cleanup_attempted=True
        child=self.child
        try:
            need(child is not None or not self.constructor_uncertain)
            if child is not None:
                if child.poll()is None:child.terminate()
                try:child.wait(timeout=max(.001,min(5,self.clock['deadline']-time.monotonic(),self.clock['deadline_wall']-time.time())))
                except subprocess.TimeoutExpired:child.kill();child.wait(timeout=1)
                need(child.returncode==0)
                raw=child.stdout.read(65537);need(len(raw)<=65536)
                spec=importlib.util.spec_from_file_location('settlement_owned_service',Path(__file__).with_name('application_settlement_service.py'))
                service=importlib.util.module_from_spec(spec);spec.loader.exec_module(service)
                terminal=service.validate_terminal(decoded(raw));need(terminal['status']=='SERVICE_STOPPED')
        except BaseException:
            # A logical-clock/deadline error must not abandon a returned handle.
            # Reaping uses only the remaining original kernel/clock budget.
            if child is not None and child.poll()is None:
                try:
                    child.kill();kernel=signal.getitimer(signal.ITIMER_REAL)[0]
                    child.wait(timeout=max(.001,min(1,kernel,self.clock['deadline']-time.monotonic(),self.clock['deadline_wall']-time.time())))
                except BaseException:pass
            raise
        finally:
            primary=sys.exc_info()[1];closing_error=None
            if child is not None:
                for stream in (child.stdin,child.stdout,child.stderr):
                    if stream is not None:
                        try:stream.close()
                        except BaseException as error:
                            if closing_error is None:closing_error=error
            for name in ('control_read','control_write'):
                fd=getattr(self,name)
                if fd is not None:
                    try:os.close(fd)
                    except BaseException as error:
                        if closing_error is None:closing_error=error
                    finally:setattr(self,name,None)
            self.key=''
            if primary is None and closing_error is not None:raise closing_error
        self.closed=True


def evidence_projection(root,initial):
    """Fixed eight ordinary metadata roles; no raw body/reference export."""
    root=Path(root);runroot=root/'cells'/CELL/'runs'/initial['run_id'];folder=root/'cells'/CELL
    roles={'result':runroot/'result.json','process':runroot/'agent-1-participant/process.json','child':folder/'child-completion.json',
      'services':folder/'services-cleanup.json','ledger':root/'launch-ledger/ledger.json','state':root/'state.json'}
    values={};bodies={};used=0;attempts=0;held=[]
    try:
        for role,path in roles.items():
            attempts+=1
            try:raw=read(path,65536 if role=='child'else 4*1024*1024,custody=held)
            except FileNotFoundError:
                if role!='result':continue
                attempts+=1
                try:raw=read(runroot/'summary.json',custody=held)
                except FileNotFoundError:continue
                role='summary'
            used+=len(raw);need(used<=32*1024*1024);value=decoded(raw);need(type(value)is dict);values[role]=value;bodies[role]=raw
        for path,parent,fd,before in held:
            need(before==signature(os.fstat(fd))==signature(os.stat(path.name,dir_fd=parent,follow_symlinks=False)))
            current=directory(path.parent)
            try:need((os.fstat(current).st_dev,os.fstat(current).st_ino)==(os.fstat(parent).st_dev,os.fstat(parent).st_ino))
            finally:os.close(current)
    finally:
        for _,parent,fd,_ in reversed(held):os.close(fd);os.close(parent)
    record=values.get('result',values.get('summary',{}));process=values.get('process',record.get('last_process',{}))
    if record:need(type(record.get('schema'))is int and record['schema']==2 and record.get('document_type')=='run_result'
      and record.get('run_id')==initial['run_id']and record.get('attempt_id')==initial['attempt_id']
      and record.get('trial_id')is None and record.get('experiment_id')is None)
    if 'result'in values:need(record.get('sealed')is True)
    if 'child'in values:
        child=values['child'];exact(child,{'schema','run_id','attempt_id','result_sha256','cleanup_checked'})
        need(type(child['schema'])is int and child['schema']==1 and child['run_id']==initial['run_id']and child['attempt_id']==initial['attempt_id'])
        if 'result'in bodies:need(child['result_sha256']==sha(bodies['result'])and child['cleanup_checked']is True)
    code=diagnostic.settlement_projection(process.get('application_settlement_failure'))if type(process)is dict else {'schema':1,'code':'UNKNOWN'}
    return {'schema':1,'application_settlement_failure':code,'metadata_roles_present':sorted(values),'metadata_body_passes':len(values),
      'metadata_static_path_attempts':attempts,'metadata_bytes':used,'sealed_result_present':record.get('sealed')is True and 'result'in values,
      'native_qualification_credit':False,'raw_bodies_values_hashes_paths_or_exception_text_exported':False}


def execute(activation,*,inference_key,_entry_deadline=None):
    """Native entry; absent exact future authorization refuses before bookkeeping."""
    start=time.monotonic();wall=time.time();outer=signal.getitimer(signal.ITIMER_REAL)[0]
    need(signal.SIGALRM not in signal.sigpending())
    if _entry_deadline is None:need(outer==0)
    else:
        need(type(_entry_deadline)is tuple and len(_entry_deadline)==2 and outer>0)
        for value in _entry_deadline:number(value)
    hard_m=min(start+900,_entry_deadline[0],start+outer)if _entry_deadline else start+900
    hard_w=min(wall+900,_entry_deadline[1],wall+outer)if _entry_deadline else wall+900
    cleanup_m=cleanup_w=None;cleanup_reap=False
    def cleanup_expired(*_):
        nonlocal cleanup_reap
        cleanup_reap=True;signal.signal(signal.SIGALRM,lambda *_:os._exit(124))
        signal.setitimer(signal.ITIMER_REAL,max(.001,min(6,cleanup_m-time.monotonic(),cleanup_w-time.time())))
        raise TimeoutError('CONTROLLED_DIAGNOSTIC_CLEANUP_DEADLINE')
    def begin_cleanup(*,from_alarm=False):
        nonlocal cleanup_m,cleanup_w
        mono,wallnow=time.monotonic(),time.time();kernel=signal.getitimer(signal.ITIMER_REAL)[0]
        if cleanup_m is None:
            duration=min(30,hard_m-mono,hard_w-wallnow)
            if kernel>0 and not from_alarm:duration=min(duration,kernel)
            cleanup_m,cleanup_w=mono+max(0,duration),wallnow+max(0,duration)
        left=min(cleanup_m-mono,cleanup_w-wallnow,hard_m-mono,hard_w-wallnow)
        cap=left if cleanup_reap else left-6
        if kernel>0:cap=min(cap,kernel)
        signal.signal(signal.SIGALRM,(lambda *_:os._exit(124))if cleanup_reap else cleanup_expired)
        signal.setitimer(signal.ITIMER_REAL,max(.001,cap))
    def expire(*_):
        begin_cleanup(from_alarm=True)
        raise TimeoutError('CONTROLLED_DIAGNOSTIC_DEADLINE')
    original_signal=signal.signal(signal.SIGALRM,expire)
    signal.setitimer(signal.ITIMER_REAL,max(.001,min(hard_m-start,hard_w-wall)))
    q=None;primary=None;services=[];backends=[];lease_closed=False;ledger=None;initial=None;projection=None;status='BLOCKED_NO_RETRY';code=None
    original_lease=None;original_popen=subprocess.Popen;previous_config=os.environ.get('PI_LAB_CONFIG_DIR');config_changed=False
    try:
        need(_valid_key(inference_key));exact(activation,ACTIVATION_FIELDS)
        need(reference(activation['grant'])==ROOT/'native-authorization.json')
        bound_reference(activation['grant'])
        q=_sdk();original_lease=q.lab.admission_lock
        grant,clock,manifest,configuration,document=load_activation(activation,q)
        hard_m=min(hard_m,clock['deadline']);hard_w=min(hard_w,clock['deadline_wall']);need(remaining(clock)>60)
        signal.setitimer(signal.ITIMER_REAL,max(.001,min(hard_m-time.monotonic(),hard_w-time.time())-30))
        _host_identity(q)
        need(original_lease is q.resources.admission_lock)
        write(ROOT/'attempt-intent.json',{'schema':1,'attempts':1,'qualification_credit':False})
        config_changed=True;prepare_session(q,configuration)
        initial=q.outcomes.initial();initial.update(run_id=grant['run_id'],attempt_id=grant['attempt_id'])
        folder=ROOT/'cells'/CELL;folder.mkdir(mode=0o700,parents=True)
        state={'schema':1,'phase':'started','active_cell':{'id':CELL,'pid':os.getpid(),'run_id':initial['run_id'],'attempt_id':initial['attempt_id']},
          'cells':{CELL:{'status':'started','attempts':1,'run_id':initial['run_id'],'attempt_id':initial['attempt_id']}},'started_at':clock['started_wall']}
        write(ROOT/'state.json',state)
        ledger=q._launch_module().LaunchLedger.create(ROOT/'launch-ledger',manifest,daemon_id=DAEMON['id'],
          daemon_capacity={k:DAEMON[k]for k in ('cpu_millis','memory_mib')})
        args=q.lab.parser().parse_args(['run','--compiled-plan',str(PREPARED_ROOT/'compiled/plan.json'),'--project',str(PREPARED_ROOT/'project'),
          '--results-dir',str(folder/'runs'),'--session',configuration['session'],'--secrets-dir',configuration['secrets_dir'],
          '--lock-file',str(NORMAL_LOCK),'--lock-wait-seconds','30']);args._explicit_options=();args._application_parent_values=[inference_key];args._indexed_redaction_keys=[]
        cell={**manifest['cells'][0],'profile':'browser','real_model':False,'max_attempts':1}
        runtime_manifest={**manifest,'session':configuration['session'],'secrets_dir':configuration['secrets_dir'],
          'credential_references':configuration['credential_references'],'fixture_route':configuration['fixture_route']}
        with q._launch_module().instrument(ledger,CELL)as guard:
            def factory(registry):
                need(q.ownership_registry.CURRENT.get()is registry and registry.lease_fd>=3)
                need(remaining(clock)>60)
                registry.command=lambda argv:q.lab.command(argv,timeout=15,required=False)
                daemon,capacity=q._native();need(daemon==DAEMON['id']and capacity=={k:DAEMON[k]for k in ('cpu_millis','memory_mib')})
                registry.bind_daemon(daemon);q._aggregate(capacity,True,False)
                lease=os.fstat(registry.lease_fd)
                permit={'schema':1,'authorization_id':grant['authorization_id'],'nonce':activation['nonce'],'deadline_wall':clock['deadline_wall'],
                  'deadline_monotonic':clock['deadline'],'normal_lock_file':str(NORMAL_LOCK),'registry_root':str(NORMAL_LOCK)+'.registry',
                  'parent_registry_admission_attested':True,'grant_sha256':activation['grant']['sha256'],'input_review_sha256':activation['input_review']['sha256'],
                  'clock_sha256':activation['clock']['sha256'],'preparation_sha256':activation['preparation']['sha256'],'candidate_sha256':activation['candidate']['sha256']}
                named=os.stat(NORMAL_LOCK,follow_symlinks=False)
                stamp=lambda value:[value.st_dev,value.st_ino,value.st_uid,stat.S_IMODE(value.st_mode),value.st_nlink]
                need(stat.S_ISREG(lease.st_mode)and lease.st_uid==os.getuid()and stat.S_IMODE(lease.st_mode)==0o600
                  and lease.st_nlink==1 and stamp(lease)==stamp(named))
                backend=ServiceProcess(original_popen,activation,registry,clock,inference_key);backends.append(backend);pipe=backend.control_identity
                admission={'schema':1,'permit':permit,'lease_identity':stamp(lease),
                  'control_pipe_identity':[pipe.st_dev,pipe.st_ino,pipe.st_uid,stat.S_IMODE(pipe.st_mode)],
                  'parent_pid':os.getpid(),'registry_id':registry.registry_id,'generation':registry.generation,'daemon_id':daemon}
                raw=canonical(admission);service_activation=copy.deepcopy(activation);service_activation['admission']['sha256']=sha(raw)
                write(ROOT/'service-admission.json',admission)
                backend.activation=service_activation
                values=[inference_key,*[q.credentials.read(configuration['credential_references'][name],configuration['secrets_dir'])for name in ('alice','bob')]]
                owned=q.OwnedServices(ROOT,runtime_manifest,cell,args,registry,guard,values)
                class Owned:
                    def start(self):owned.start();backend.start();return self
                    def close(self):
                        begin_cleanup()
                        failure=None
                        try:backend.close()
                        except BaseException as error:failure=error
                        try:owned.close()
                        except BaseException:
                            if failure is None:raise
                        if failure is not None:raise failure
                value=Owned();services.append(value);return value
            @contextlib.contextmanager
            def lease(path,wait):
                nonlocal lease_closed
                need(Path(path).absolute()==NORMAL_LOCK and type(wait)is int and wait==30)
                @contextlib.contextmanager
                def original(lock_path,lock_wait):
                    descriptor=bound_reference(grant['ownership_input']);checker=_ownership_checker()
                    def denial_only(**kwargs):
                        need(checker.deny_unsafe_original_ownership(descriptor,**kwargs)is None)
                    with q.resources.admission_lock(lock_path,lock_wait,before_registry=denial_only)as registry:yield registry
                with q.actual_lease(args,factory,original=original)as registry:yield registry
                lease_closed=True
            q.lab.admission_lock=lease
            class NoRawOutput(io.TextIOBase):
                def __init__(self):self.count=0
                def write(self,value):self.count+=len(value.encode());need(self.count<=32*1024*1024);return len(value)
            previous=os.environ.get(diagnostic.SCRIPT_KEY_REFERENCE);os.environ[diagnostic.SCRIPT_KEY_REFERENCE]=inference_key
            try:
                with contextlib.redirect_stdout(NoRawOutput()):code=q.lab.run_suite(args,initial_record=copy.deepcopy(initial))
            finally:
                if previous is None:os.environ.pop(diagnostic.SCRIPT_KEY_REFERENCE,None)
                else:os.environ[diagnostic.SCRIPT_KEY_REFERENCE]=previous
                q.lab.admission_lock=original_lease
            guard.assert_cell_released()
            snapshot=ledger.snapshot();rows=snapshot['launches'];required=set(diagnostic.ROLES)-{'scorer'}
            need(required<={row['role']for row in rows}<=set(diagnostic.ROLES)
              and len(rows) in(6,7)and all(row['cell']==CELL and row['physical']=='absent'and row['private_cleanup']is True for row in rows))
            record=q.read(folder/'runs'/initial['run_id']/'result.json');stage=diagnostic.preparation.load_compiled(PREPARED_ROOT/'compiled/plan.json')['plan']['stages'][0]
            completion=record.get('application_completion',{}).get('stages',[{}])[0]
            need(lease_closed and q._runtime_valid(record,stage)and completion.get('status')=='incomplete'and record.get('status')=='FAIL')
            status='SETTLEMENT_CONFIRMED_TASK_INCOMPLETE_NO_QUALIFICATION_CREDIT'
    except BaseException as error:
        primary=error
        if ledger is not None:
            try:ledger.poison_scope(CELL)
            except BaseException:pass
    finally:
        if q is not None and original_lease is not None:q.lab.admission_lock=original_lease
        if config_changed:
            if previous_config is None:os.environ.pop('PI_LAB_CONFIG_DIR',None)
            else:os.environ['PI_LAB_CONFIG_DIR']=previous_config
        # Cleanup keeps the original endpoint, never resets a new budget.
        begin_cleanup()
        for backend in reversed(backends):
            try:backend.close()
            except BaseException as error:
                status='BLOCKED_NO_RETRY'
                if primary is None:primary=error
        terminal={'schema':1,'status':status,'original_registry_normal_close':lease_closed,'native_qualification_credit':False,
          'application_settlement_failure':{'schema':1,'code':'UNKNOWN'},'original_primary_exception_preserved':primary is not None}
        if initial is not None:
            try:
                projection=evidence_projection(ROOT,initial);terminal['application_settlement_failure']=projection['application_settlement_failure']
                terminal['evidence']=projection
            except BaseException:
                terminal['status']='BLOCKED_NO_RETRY';terminal['automatic_evidence_complete']=False
                if primary is None:primary=ControllerError()
            if primary is None and min(hard_m-time.monotonic(),hard_w-time.time(),cleanup_m-time.monotonic(),cleanup_w-time.time())<=0:
                primary=ControllerError();terminal['status']='BLOCKED_NO_RETRY'
            try:write(ROOT/'phase-terminal.json',terminal)
            except BaseException:
                if primary is None:primary=ControllerError()
        if primary is None and min(hard_m-time.monotonic(),hard_w-time.time(),cleanup_m-time.monotonic(),cleanup_w-time.time())<=0:
            primary=ControllerError();terminal['status']='BLOCKED_NO_RETRY'
        if _entry_deadline is None:
            signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,original_signal)
        else:
            kernel=signal.getitimer(signal.ITIMER_REAL)[0];signal.signal(signal.SIGALRM,original_signal)
            signal.setitimer(signal.ITIMER_REAL,max(.001,min(kernel,hard_m-time.monotonic(),hard_w-time.time(),cleanup_m-time.monotonic(),cleanup_w-time.time())))
    if primary is not None:raise primary
    return terminal


def _private_frame(stream,clock,deadline):
    remaining(clock);end=min(time.monotonic()+INPUT_SECONDS,clock['deadline'],deadline[0])
    wallend=min(time.time()+INPUT_SECONDS,clock['deadline_wall'],deadline[1]);raw=bytearray();fd=stream.fileno()
    while True:
        left=min(end-time.monotonic(),wallend-time.time());need(left>0 and len(raw)<=65536)
        ready,_,_=select.select([fd],[],[],left);need(bool(ready))
        chunk=os.read(fd,min(4096,65537-len(raw)))
        if not chunk:break
        raw.extend(chunk)
    need(len(raw)<=65536);value=decoded(bytes(raw));exact(value,{'inference_key'});need(_valid_key(value['inference_key']))
    return value


def main(argv=None):
    need(signal.getitimer(signal.ITIMER_REAL)[0]==0 and signal.SIGALRM not in signal.sigpending())
    mono,wall=time.monotonic(),time.time();deadline=(mono+900,wall+900)
    previous=signal.signal(signal.SIGALRM,lambda *_:os._exit(124));signal.setitimer(signal.ITIMER_REAL,900)
    try:
        parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--activation',required=True);args=parser.parse_args(argv)
        need(Path(args.activation)==ROOT/'activation.json')
        activation=decoded(read(Path(args.activation),65536));exact(activation,ACTIVATION_FIELDS)
        need(reference(activation['clock'])==ROOT/'clock.json')
        clock=validate_clock(bound_reference(activation['clock']));remaining(clock)
        deadline=(min(deadline[0],clock['deadline']),min(deadline[1],clock['deadline_wall']))
        kernel=signal.getitimer(signal.ITIMER_REAL)[0]
        signal.setitimer(signal.ITIMER_REAL,max(.001,min(kernel,deadline[0]-time.monotonic(),deadline[1]-time.time())))
        frame=_private_frame(sys.stdin.buffer,clock,deadline);result=execute(activation,inference_key=frame['inference_key'],_entry_deadline=deadline)
        print(json.dumps(result));return 0
    except SystemExit:raise
    except BaseException:
        print(json.dumps({'schema':1,'status':'DISABLED_OR_BLOCKED_NO_RETRY','raw_exception_exported':False}));return 2
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)


if __name__=='__main__':raise SystemExit(main())
