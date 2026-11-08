"""Policy-gated private sessions. No default stores, command proxy or retries."""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import PurePosixPath
import selectors
import stat
import sys
import threading
import time

from . import collect, policy, runtime, source, state, wire, worker
from . import secret_registration_contract as contract
from . import secret_registration_primitive, secret_registration_posix as native
_SESSION_LOCK=globals().get('_SESSION_LOCK',threading.Lock())


class Result:
    __slots__=('_accepted','_code','_data','_facts','_patterns','_maximum')
    def __init__(self, accepted, code, data, facts, patterns, maximum):
        self._accepted=bool(accepted);self._code=code;self._data=wire.PrivateData(data)
        self._facts=wire.PrivateData(facts);self._patterns=patterns;self._maximum=maximum
    def private(self):return self._data.get()
    @property
    def accepted(self):return self._accepted
    @property
    def code(self):return self._code
    def facts(self):return self._facts.get()
    def public_wire(self):return wire.public_status(self.code,self.accepted)
    def public_json(self,value):
        wire.require(self._patterns is not None,10)
        body=wire.encode(value,self._maximum);wire.require(not self._patterns.contains(body),10)
        return body
    def bytes(self):
        data=self.private();wire.require(type(data)is dict and type(data.get('bytes_base64'))is str,7)
        try:return base64.b64decode(data['bytes_base64'],validate=True)
        except ValueError:raise wire.SDKError(7)from None
    def __repr__(self):return '<sdk>'


class Client:
    def __init__(self):
        package=sys.modules.get('operation_sdk')
        wire.require(package is not None and hasattr(package,'__sdk_root__')and hasattr(package,'__sdk_files__'),4)
        wire.require(getattr(sys.modules[__name__].__loader__,'__sdk_verified__',False),4)
        self._root=package.__sdk_root__;self._files=dict(package.__sdk_files__);self._sizes=dict(package.__sdk_sizes__)
    @property
    def root(self):return self._root
    @property
    def files(self):return dict(self._files)
    def __repr__(self):return '<sdk>'
    def prepare(self,value,request_metadata,*,trusted_policy_sha256):
        admitted=policy.compile_admission(value,request_metadata,trusted_policy_sha256=trusted_policy_sha256,
                                           now_ns=time.monotonic_ns())
        p=admitted.policy();wire.require(p['deployment']['consumer_root']==self.root
            and p['deployment']['consumer_files']==self.files,4)
        wire.require(all(p['deployment']['provider_sizes']['scripts/operation_sdk/'+name]==size
                         for name,size in self._sizes.items()),4)
        runtime.platform_check();runtime.cgroup_limits(p['limits'])
        wire.require(_SESSION_LOCK.acquire(blocking=False),12)
        session=None
        try:
            record=state.reserve(admitted,time.monotonic_ns());session=Session(admitted,record)
            session._session_lock=True;session.start();return session
        except BaseException as error:
            if session is not None:session.close();record.fail()
            else:_SESSION_LOCK.release()
            if isinstance(error,wire.SDKError):raise
            raise wire.SDKError(4)from None


class Session:
    def __init__(self,admitted,record):
        self._admitted,self._record=admitted,record;self._session_lock=False
        self._owned={};self._process=None;self._store=self._coord=None;self._closed=False
        self._known=True;self._patterns=None;self._collection={};self._delivery={}
        self._input_transferred=False;self._received=False;self._ready=None;self._references=[]
        self._verification=None
    @property
    def admitted(self):return self._admitted
    @property
    def phase(self):return self._record.phase
    @property
    def p(self):return self._admitted.policy()
    @property
    def limits(self):return self._admitted.policy()['limits']
    @property
    def deadline(self):return self._admitted.request()['expires_ns']/1000000000
    def __repr__(self):return '<sdk>'
    def __enter__(self):return self
    def __exit__(self,*args):
        if not self.close():raise wire.SDKError(6)from None
    def _take(self,fd,role):self._owned[fd]=role;return fd
    def _close(self,fd):
        wire.require(fd in self._owned,6);del self._owned[fd]
        try:native.close(fd)
        except BaseException:self._known=False;raise wire.SDKError(6)from None
    def _pipe(self,role):
        pair=os.pipe2(os.O_CLOEXEC)
        for fd in pair:self._take(fd,role)
        return pair
    def _authority(self):
        if self._coord is not None:self._coord.verify()
        if self._store is not None:self._store.verify()
    def start(self):
        deployment=self.p['deployment'];scope=self.p['scope']
        self._verification=source.ReadBudget(self.limits['max_source_bytes']//2,self.limits['max_source_files'],
            initial_bytes=self.admitted.forecast()['parent_bootstrap_verification_bytes'],initial_files=len(policy.CONSUMER_FILES)+1)
        source.verify_tree(deployment['provider_root'],deployment['provider_files'],self.limits)
        if scope['coordination']is not None:
            self._coord=collect.Coordination(scope['coordination']['path'],scope['coordination']['identity'])
            self._store=source.Namespace(scope['store']['path'],scope['store']['identity'],private=True)
        control_r,self._control=self._pipe('control');private_r,self._private=self._pipe('private')
        self._report,report_w=self._pipe('report');self._stdout,stdout_w=self._pipe('stdout');self._stderr,stderr_w=self._pipe('stderr')
        store_fd=self._store.fd if self._store else-1;coord_fd=self._coord.fd if self._coord else-1
        passed=[control_r,private_r,report_w]+([store_fd,coord_fd]if self._store else[])
        command=[deployment['python_path'],'-I','-S','-B',self.p['deployment']['consumer_root']+'/worker.py',
            self.admitted.policy_sha256,str(control_r),str(private_r),str(report_w),str(store_fd),str(coord_fd),'0']
        self._process=runtime.OwnedProcess.launch(command,passed,stdout_w,stderr_w)
        for fd in(control_r,private_r,report_w,stdout_w,stderr_w):self._close(fd)
        wire.write_frame(self._control,wire.encode({'policy':self.p,'request':self.admitted.request()},self.limits['max_control_bytes']),self.deadline)
        ready=wire.decode(self._receive(self.limits['max_control_bytes'],False),self.limits['max_control_bytes'])
        self._verify_ready(ready);self._ready=ready;self._record.ready(self.admitted.context_sha256)
    def _receive(self,maximum,eof):
        frame=wire.Frame(maximum);selector=selectors.DefaultSelector();closed=set()
        try:
            for fd,role in((self._report,'report'),(self._stdout,'stdout'),(self._stderr,'stderr')):
                if fd in self._owned:os.set_blocking(fd,False);selector.register(fd,selectors.EVENT_READ,role)
            while True:
                wire.require(time.monotonic()<self.deadline,9)
                events=selector.select(max(0,self.deadline-time.monotonic()));wire.require(events,9)
                for key,_ in events:
                    try:body=os.read(key.fd,65536)
                    except BlockingIOError:continue
                    except OSError:raise wire.SDKError(6)from None
                    if not body:
                        selector.unregister(key.fd);closed.add(key.data)
                        if key.data=='report'and not eof:return frame.finish()
                    elif key.data!='report':raise wire.SDKError(8)
                    else:
                        frame.feed(body)
                        if frame.complete and not eof:return frame.finish()
                if eof and closed=={'report','stdout','stderr'}:return frame.finish()
        finally:selector.close()
    def _verify_ready(self,value):
        deployment=self.p['deployment']
        wire.require(type(value)is dict and set(value)=={'schema','kind','context_sha256','operation','pid','runtime',
            'limits','sdk_files','sdk_sources','provider_sources','operational_approval'},4)
        wire.require(type(value['schema'])is int and value['schema']==1 and value['kind']=='ready'
            and value['context_sha256']==self.admitted.context_sha256 and value['operation']==self.admitted.operation
            and value['operational_approval']is False,4)
        observed=self._process.observe(deployment,self.limits,budget=self._verification)
        wire.require(type(value['pid'])is int and value['pid']==observed['pid'],4)
        current_limits=runtime.cgroup_limits(self.limits);claimed=value['limits']
        wire.require(type(claimed)is dict and set(claimed)==set(current_limits)
            and all(type(item)is int for item in claimed.values())and claimed==current_limits,4)
        measured=value['runtime']
        wire.require(measured['modules']==deployment['runtime_modules']and measured['files']==deployment['runtime_files']
            and measured['sizes']==deployment['runtime_sizes']
            and measured['mapped_files']==sorted(deployment['mapped_files'])
            and measured['python_sha256']==deployment['python_sha256']and measured['approval']is False,4)
        wire.require(value['sdk_files']==deployment['consumer_files'],4)
        names=set()
        for row in value['sdk_sources']:
            path=row['path'];wire.require(type(path)is str and path.startswith(deployment['consumer_root']+'/'),4)
            name=path[len(deployment['consumer_root'])+1:]
            wire.require(name in deployment['consumer_files']and row['sha256']==deployment['consumer_files'][name]
                and row['code_filename']==path and row['spec_origin']==(None if name=='__init__.py'else path)
                and name not in names,4);names.add(name)
        wire.require(names==set(deployment['consumer_files']),4)
        provider_names=set()
        for row in value['provider_sources']:
            name=row['name'];wire.require(name in deployment['modules']and name not in provider_names,4)
            path=deployment['provider_root']+'/'+deployment['modules'][name]
            wire.require(row['path']==row['code_filename']==row['spec_origin']==path
                and row['sha256']==deployment['provider_files'][deployment['modules'][name]]
                and row['loader_kind']=='verified_source',4);provider_names.add(name)
        wire.require(provider_names==set(deployment['modules']),4)
        self._authority()
    def _input(self,fd):
        selected=self.p['input']
        if selected is None:wire.require(fd is None,7);return None
        wire.require(type(fd)is int and fd>=0 and fd not in self._owned,7)
        info=os.fstat(fd)
        wire.require(source.identity(info)==tuple(selected['identity'])and info.st_uid==os.geteuid(),4)
        if selected['kind']=='pipe':
            wire.require(stat.S_ISFIFO(info.st_mode)and fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY,4)
        else:
            needed=fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL
            wire.require(stat.S_ISREG(info.st_mode)and info.st_nlink==0 and stat.S_IMODE(info.st_mode)==0o600
                and info.st_size<=selected['maximum_bytes']+4 and os.lseek(fd,0,os.SEEK_CUR)==0
                and fcntl.fcntl(fd,fcntl.F_GET_SEALS)&needed==needed,4)
        self._take(fd,'private_source');self._input_transferred=True
        try:
            body=(wire.read_frame(fd,selected['maximum_bytes'],self.deadline,eof=True)if selected['kind']=='pipe'
                  else wire.read_memory_frame(fd,selected['maximum_bytes'],self.deadline))
        finally:self._close(fd)
        if self.admitted.operation=='redact_bytes_v1':return{'bytes_base64':base64.b64encode(body).decode('ascii')}
        return wire.decode(body,selected['maximum_bytes'])
    def execute(self,private_fd=None):
        wire.require(not self._closed,12)
        # A bad or repeated call spends the capability before source metadata.
        self._record.claim(time.monotonic_ns());native_result=None
        try:
            self._authority();self._process.observe(self.p['deployment'],self.limits,budget=self._verification)
            current=int(runtime.kernel_bytes('/sys/fs/cgroup/memory.current').strip())
            wire.require(current+self.admitted.forecast()['additional_memory_bytes']<=self.limits['max_memory_bytes'],5)
            payload=self._input(private_fd)
            rows=[]
            if self.p['scope']['references']:
                values=collect.references(self._store,self.p['scope']['references'],self.limits['max_ref_bytes'],
                    self.limits['max_read_bytes'],progress=self._collection);rows=values.private()
            else:self._collection={'attempted':0,'complete':0,'coverage':True}
            self._references=wire.PrivateData(rows).get()
            patterns=[row['value']for row in rows]
            if self.admitted.operation=='secret_register_create_only_v1':
                wire.require(type(payload)is dict and set(payload)=={'value'},7)
                size=contract.validate_value(payload['value'],self.p['scope']['value_contract'])
                wire.require(size<=self.limits['max_secret_bytes'],5);patterns.append(payload['value'])
            self._patterns=collect.Patterns(patterns,self.limits)
            self._authority()
            wire.write_frame(self._control,wire.encode({'schema':1,'kind':'go','context_sha256':self.admitted.context_sha256},
                self.limits['max_control_bytes']),self.deadline);self._close(self._control)
            body=wire.encode({'schema':1,'context_sha256':self.admitted.context_sha256,'payload':payload,'references':rows},
                             self.limits['max_payload_bytes'])
            wire.write_frame(self._private,body,self.deadline,progress=self._delivery);self._close(self._private);self._record.sent()
            message=wire.decode(self._receive(self.limits['max_result_bytes'],True),self.limits['max_result_bytes'])
            code=self._process.wait(max(0.01,self.deadline-time.monotonic()));wire.require(type(code)is int and code==0,9)
            self._record.received();self._validate(message,payload)
            native_result=message['native'];accepted=message['status']=='ok'
            self._authority()
            if accepted and self.admitted.operation=='secret_register_create_only_v1':self._receiver_native(message,payload)
            wire.require(self._cleanup_transport(),6)
            if accepted:self._record.accept(time.monotonic_ns())
            else:self._record.fail()
            return Result(accepted,message['code'],message['data'],self._facts(message['facts'],native_result),self._patterns,self.limits['max_result_bytes'])
        except BaseException as error:
            self._record.fail();known=self._cleanup_transport()
            code=error.code if isinstance(error,wire.SDKError)else 7
            return Result(False,code,None,self._facts({'effect':'unknown'if self._delivery else'none','handler_calls':None},native_result),
                          self._patterns,self.limits['max_result_bytes'])
    def _validate(self,message,payload):
        wire.require(type(message)is dict and set(message)=={'schema','kind','context_sha256','operation','status','code',
            'data','native','final_identity','facts'}and type(message['schema'])is int and message['schema']==1
            and message['kind']=='result'and message['context_sha256']==self.admitted.context_sha256
            and message['operation']==self.admitted.operation and message['status']in('ok','refused','unknown')
            and type(message['code'])is int and 0<=message['code']<=255,7)
        facts=message['facts'];operation=self.admitted.operation
        wire.require(type(facts)is dict and set(facts)=={'handler_calls','reference_bindings_checked','source_conserved','effect'}
            and type(facts['handler_calls'])is int and facts['handler_calls']in(0,1)
            and type(facts['reference_bindings_checked'])is int and 0<=facts['reference_bindings_checked']<=len(self._references)
            and type(facts['source_conserved'])is bool and facts['effect']in('none','created','unknown'),7)
        if operation!='secret_register_create_only_v1':
            wire.require(message['native']is None and message['final_identity']is None and facts['effect']=='none',7)
        if message['status']=='ok':
            wire.require(message['code']==0 and facts['source_conserved']is True and facts['handler_calls']==1
                and facts['reference_bindings_checked']==len(self._references),7)
            if self.admitted.operation.startswith('plan_'):
                data=message['data'];wire.require(type(data)is dict and set(data)=={'normalized_plan','plan_sha256','digest_domain',
                    'validation_only','profile_validated','project_contract_checked','scorer_frozen','dependencies_read'}
                    and type(data['normalized_plan'])is dict and data['digest_domain']=='normalized_plan_utf8_v1'
                    and data['validation_only']is True and data['scorer_frozen']is False
                    and type(data['dependencies_read'])is int and 0<=data['dependencies_read']<=self.limits['max_read_refs'],7)
                legacy=operation in('plan_validate_legacy_v1','plan_check_project_v1')
                wire.require(data['profile_validated']is legacy
                    and data['project_contract_checked']is(operation=='plan_check_project_v1'),7)
                if not legacy:
                    wire.require(wire.encode(data['normalized_plan'],self.limits['max_payload_bytes'])
                        ==wire.encode(payload['plan'],self.limits['max_payload_bytes'])and data['dependencies_read']==0,7)
                digest=hashlib.sha256(json.dumps(data['normalized_plan'],sort_keys=True,separators=(',',':'),
                    ensure_ascii=False,allow_nan=False).encode()).hexdigest();wire.require(data['plan_sha256']==digest,7)
            elif self.admitted.operation=='redact_bytes_v1':
                data=message['data'];wire.require(type(data)is dict and set(data)=={'bytes_base64','known_patterns_checked'}
                    and data['known_patterns_checked']is True,7)
                original=self._decode_bytes(payload['bytes_base64'],self.p['input']['maximum_bytes'])
                output=self._decode_bytes(data['bytes_base64'],10*len(original))
                wire.require(output==self._patterns.replace(original),7)
                wire.require(not self._patterns.contains(output),10)
            elif operation=='credentials_collect_v1':
                aliases={row['alias']:row['value']for row in self._references if row['role']=='application'}
                inference=[row['value']for row in self._references if row['role']=='inference']
                wire.require(len(inference)==1 and message['data']=={'stage_id':self.p['stage_id'],
                    'participant_id':self.p['participant_id'],'aliases':aliases,'inference_value':inference[0]},7)
            elif operation=='resource_read_v1':
                data=message['data'];resource=self.p['scope']['resource']
                wire.require(type(data)is dict and set(data)=={'bytes_base64','resource_sha256'},7)
                output=self._decode_bytes(data['bytes_base64'],resource['maximum_bytes'])
                expected=self.p['deployment']['resources'][resource['path']]
                wire.require(data['resource_sha256']==expected==hashlib.sha256(output).hexdigest(),4)
            elif operation=='secret_register_create_only_v1':
                wire.require(message['data']is None and facts['effect']=='created',7)
            else:raise wire.SDKError(2)
        else:wire.require(message['code']!=0 and message['data']is None,7)
    @staticmethod
    def _decode_bytes(value,maximum):
        wire.require(type(value)is str and len(value)<=4*((maximum+2)//3),5)
        try:output=base64.b64decode(value,validate=True)
        except ValueError:raise wire.SDKError(7)from None
        wire.require(len(output)<=maximum and base64.b64encode(output).decode('ascii')==value,7)
        return output
    def _receiver_native(self,message,payload):
        native_result=message['native'];wire.require(type(native_result)is dict and set(native_result)=={'observation','owned_fd_tokens'},7)
        depth=len(PurePosixPath(self.p['scope']['store']['path']).parts)-1
        expected=('store_duplicate',*(f'ancestor:{i}'for i in range(depth)),'value')
        wire.require(tuple(native_result['owned_fd_tokens'])==expected,7)
        observation=native_result['observation']
        checked=contract.validate_worker(observation,expected_operation_id=self.admitted.request()['operation_id'],
            expected_context_sha256=self.admitted.context_sha256,expected_value_contract=self.p['scope']['value_contract'],
            expected_value_utf8_bytes=len(payload['value'].encode()),owned_fd_tokens=expected,
            max_mutating_calls=self.limits['max_mutating_calls'],max_owned_fds=self.limits['max_owned_fds'])
        wire.require(checked.ack_ready and observation['outcome']=='created',7)
        info=self._store.stat(self.p['scope']['write_reference'])
        current=[info.st_dev,info.st_ino,info.st_uid,stat.S_IMODE(info.st_mode),info.st_nlink,info.st_size]
        wire.require(current==message['final_identity']and stat.S_ISREG(info.st_mode),4)
        # Independent of the worker report: exact owner, private mode, one link, value size.
        wire.require(info.st_uid==os.geteuid()and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1
            and info.st_size==len(payload['value'].encode('utf-8')),4)
        self._store.absent('.'+self.p['scope']['write_reference']+'.'+self.admitted.request()['operation_id']+'.pending')
        self._authority()
    def _facts(self,facts,native_result):
        return {'worker':facts,'native':native_result,'collection':dict(self._collection),'delivery':dict(self._delivery),
            'input_transferred':self._input_transferred,'authority_retained':self._coord is not None and not self._closed,
            'child_exit_code':self._process.process.returncode if self._process is not None and self._process.reaped else None,
            'child_reaped':self._process.reaped if self._process is not None else False,
            'managed_transport_cleanup_known':self._known,'phase':self._record.phase,
            'parent_verification_reserved_bytes':self._verification.reserved if self._verification is not None else None,
            'historical_or_workflow_admission':False}
    def _cleanup_transport(self):
        if self._process is not None:self._known &= self._process.close()
        for fd in tuple(self._owned):
            try:self._close(fd)
            except wire.SDKError:self._known=False
        return self._known
    def close(self):
        if self._closed:return self._known
        self._closed=True
        if self._record.phase!='accepted':self._record.fail()
        self._cleanup_transport()
        if self._store is not None:self._known &= self._store.close()
        if self._coord is not None:self._known &= self._coord.close()
        if self._session_lock:self._session_lock=False;_SESSION_LOCK.release()
        return self._known
