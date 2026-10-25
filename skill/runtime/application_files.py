"""Typed, budgeted application artifacts and model-authored completion reports.

Only frozen IDs select paths. Predecessor reads use a parent supplied sealed
mapping; neither paths nor generic filesystem operations are public tools.
"""
import copy
import hashlib
import os
from pathlib import PurePosixPath
import stat
import threading
import uuid

import application_contracts as c
import application_credentials
from application_evidence import EvidenceError,open_directory,read_file

MAX_RESULT_BYTES=8192
MAX_ARTIFACT_BYTES=256*1024
MAX_REPORT_BYTES=64*1024
TOOLS=frozenset({'artifact_read','artifact_write','report_write'})
REASONS=frozenset({'request_invalid','operation_not_granted','accounting_unavailable',
                   'artifact_unavailable','result_limit','authority_changed','reporting_only','tool_budget_exhausted'})
DIAGNOSTIC_PHASES=frozenset({'authorize','input_validation','root_state','plan_identity','tool_grant',
    'report_encode','artifact_input','budget_verify','effect_authorize','artifact_read','storage_write','result',
    'root_reopen','parent_create_open','leaf_inspect','temporary_open_write','temporary_flush_fsync',
    'pre_replace_fence','rename_parent_fsync','post_replace_fence','temporary_cleanup','parent_close'})
DIAGNOSTIC_CLASSES=frozenset({'FileError','EvidenceError','OSError','ValueError','other'})


def validate_file_diagnostic(value):
    """Closed private metadata, never a participant result or an authority."""
    fields={'schema','document_type','phase','error_class','errno','roots_present',
            'quarantine_before','storage_entered','storage_returned'}
    if (type(value) is not dict or set(value)!=fields or type(value['schema']) is not int or value['schema']!=1
            or value['document_type']!='application_file_failure_diagnostic' or value['phase'] not in DIAGNOSTIC_PHASES
            or value['error_class'] not in DIAGNOSTIC_CLASSES
            or not (value['errno'] is None or type(value['errno']) is int and 0<=value['errno']<=65535)
            or any(type(value[key]) is not bool for key in ('roots_present','quarantine_before','storage_entered','storage_returned'))):
        raise FileError('request_invalid')
    if len(c.canonical(value))>1024:raise FileError('request_invalid')
    return copy.deepcopy(value)


class FileError(ValueError):
    def __init__(self,reason='request_invalid'):
        self.reason=reason if type(reason) is str and reason in REASONS else 'request_invalid'
        super().__init__(self.reason)


def _identity(fd):
    info=os.fstat(fd);return info.st_dev,info.st_ino


def _regular(info):
    if info.st_uid!=os.getuid() or not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:
        raise FileError('artifact_unavailable')


def _parent(root,path,create=False):
    c.relative(path,'/path')
    fd=os.dup(root)
    try:
        parts=path.split('/')
        for name in parts[:-1]:
            if create:
                try:os.mkdir(name,0o700,dir_fd=fd);os.fsync(fd)
                except FileExistsError:pass
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
            os.close(fd);fd=child
            info=os.fstat(fd)
            if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077:
                raise FileError('artifact_unavailable')
        return fd,parts[-1]
    except BaseException:
        os.close(fd);raise


def _entry(parent,leaf):
    try:
        info=os.stat(leaf,dir_fd=parent,follow_symlinks=False);_regular(info)
        return tuple(getattr(info,key) for key in ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
    except FileNotFoundError:return None


class ApplicationFiles:
    def __repr__(self):return '<ApplicationFiles private authority and paths withheld>'

    def __init__(self,authority_service,artifact_root,report_root=None,*,sealed_inputs=None,budget_verifier=None,forbidden_values=()):
        if not callable(budget_verifier):raise FileError('accounting_unavailable')
        if type(forbidden_values) not in (list,tuple) or len(forbidden_values)>256:raise FileError('request_invalid')
        for value in forbidden_values:c.text(value,'/forbidden_values',16384)
        self._forbidden=application_credentials.Redactor(forbidden_values)
        self.authority=authority_service;self.budget_verifier=budget_verifier
        self.plan=c.validate_ir(authority_service.plan);self._plan_sha=c.digest(self.plan)
        self._stages={stage['id']:stage for stage in self.plan['stages']}
        self._roots={};self._sealed={};self._calls=set();self._lock=threading.RLock();self.quarantined=False
        self._file_diagnostic=None;self._diagnostic_context=None;self._diagnostic_control=None
        try:
            artifact_path=os.fspath(artifact_root);report_path=artifact_path if report_root is None else os.fspath(report_root)
            a,r=PurePosixPath(artifact_path),PurePosixPath(report_path)
            if a!=r and (a in r.parents or r in a.parents):raise FileError('artifact_unavailable')
            for kind,path in (('artifact',artifact_path),('report',report_path)):
                fd=open_directory(path,private=True);self._roots[kind]=(path,fd,_identity(fd))
            if a!=r and self._roots['artifact'][2]==self._roots['report'][2]:raise FileError('artifact_unavailable')
            mapping={} if sealed_inputs is None else sealed_inputs
            if type(mapping) is not dict or len(mapping)>512:raise FileError('request_invalid')
            declarations={(stage['id'],item['id']):item for stage in self.plan['stages'] for item in stage['completion']['artifacts']}
            grants={(item['stage_id'],item['artifact_id']) for stage in self.plan['stages'] for item in stage['input_artifacts']}
            for key,value in mapping.items():
                if type(key) is not tuple or len(key)!=2 or key not in declarations or key not in grants:raise FileError('operation_not_granted')
                c.exact(value,{'path','sha256','bytes','media_type'},'/sealed_inputs')
                declared=declarations[key];path=value['path']
                c.text(path,'/sealed_inputs/path',4096);c.sha256(value['sha256'],'/sealed_inputs/sha256')
                c.integer(value['bytes'],'/sealed_inputs/bytes',0,declared['max_bytes'])
                if value['media_type']!=declared['media_type']:raise FileError('request_invalid')
                absolute=PurePosixPath(path)
                if not path.startswith('/') or str(absolute)!=path or '..' in absolute.parts:raise FileError('request_invalid')
                if any(root==absolute or root in absolute.parents or absolute in root.parents for root in (a,r)):
                    raise FileError('operation_not_granted')
                if self._secret(c.canonical(value)):raise FileError('request_invalid')
                self._sealed[key]=copy.deepcopy(value)
        except BaseException:
            self.close();raise

    def close(self):
        with getattr(self,'_lock',threading.RLock()):
            for _,fd,_ in self._roots.values():os.close(fd)
            self._roots={}

    @property
    def file_diagnostic(self):
        return copy.deepcopy(getattr(self,'_file_diagnostic',None))

    def _diagnostic_step(self,action):
        try:
            if action=='begin':
                self._diagnostic_control=None
                self._diagnostic_context={'roots_present':bool(self._roots),'quarantine_before':bool(self.quarantined),
                                          'storage_entered':False,'storage_returned':False}
            elif self._diagnostic_context is not None:self._diagnostic_context[action]=True
        except (KeyboardInterrupt,SystemExit,GeneratorExit,TimeoutError) as error:
            self._diagnostic_control=error;raise
        except Exception:pass

    def _remember_file_failure(self,phase,error,*,storage_entered=False):
        # Telemetry is best-effort RAM only. It cannot alter an operation's
        # result, grow authority, or overwrite the first useful failure with a
        # later quarantine refusal. Never inspect paths, arguments or messages.
        try:
            if getattr(self,'_file_diagnostic',None) is not None:return
            context=getattr(self,'_diagnostic_context',None) or {
                'roots_present':bool(self._roots),'quarantine_before':bool(self.quarantined),
                'storage_entered':storage_entered,'storage_returned':False}
            kind=('FileError' if isinstance(error,FileError) else 'EvidenceError' if isinstance(error,EvidenceError)
                  else 'OSError' if isinstance(error,OSError) else 'ValueError' if isinstance(error,ValueError) else 'other')
            number=error.errno if isinstance(error,OSError) else None
            value={'schema':1,'document_type':'application_file_failure_diagnostic','phase':phase,'error_class':kind,
                'errno':number if type(number) is int and 0<=number<=65535 else None,**context}
            self._file_diagnostic=validate_file_diagnostic(value)
        except (KeyboardInterrupt,SystemExit,GeneratorExit,TimeoutError) as error:
            self._diagnostic_control=error;raise
        except Exception:pass

    def _root(self,kind):
        path,fd,identity=self._roots[kind]
        probe=open_directory(path,private=True)
        try:
            if _identity(probe)!=identity or _identity(fd)!=identity:raise FileError('artifact_unavailable')
        finally:os.close(probe)
        return fd

    def _secret(self,body):
        return self.authority.redactor.contains(body) or self._forbidden.contains(body)

    def _text(self,body,media_type,maximum):
        if len(body)>maximum:raise FileError('request_invalid')
        text=body.decode('utf8')
        if self._secret(body):raise FileError('request_invalid')
        if media_type=='application/json':
            parsed=c.loads(body,max_bytes=maximum)
            if self._secret(c.canonical(parsed)):raise FileError('request_invalid')
        return text

    def _report(self,stage,arguments):
        c.exact(arguments,{'report'},'')
        report=c.validate_report(arguments['report']);completion=stage['completion']
        if report['contract_id']!=completion['id'] or report['participant']!=completion['participant']:
            raise FileError('operation_not_granted')
        declarations={item['id']:item for item in completion['artifacts']}
        for item in report['artifacts']:
            declared=declarations.get(item['id'])
            if declared is None or item['path']!=declared['path'] or item['bytes']>declared['max_bytes']:
                raise FileError('operation_not_granted')
        if set(report['pagination'])-{item['operation_id'] for item in completion['pagination']}:
            raise FileError('operation_not_granted')
        if {item['id'] for item in report['publications']}-{item['id'] for item in completion['publications']}:
            raise FileError('operation_not_granted')
        body=c.canonical(report)
        if len(body)>MAX_REPORT_BYTES or self._secret(body):raise FileError('request_invalid')
        return completion['report_path'],body,{'contract_id':completion['id']}

    def _write(self,kind,path,body):
        parent=None;temporary='.artifact-'+uuid.uuid4().hex
        phase='root_reopen'
        try:
            root=self._root(kind);phase='parent_create_open';parent,leaf=_parent(root,path,True)
            phase='leaf_inspect'
            original=_entry(parent,leaf)
            phase='temporary_open_write'
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
            with os.fdopen(fd,'wb') as stream:
                stream.write(body);phase='temporary_flush_fsync';stream.flush();os.fsync(stream.fileno());created=_identity(stream.fileno())
            phase='pre_replace_fence'
            fresh,_=_parent(self._root(kind),path)
            try:
                if _identity(fresh)!=_identity(parent) or _entry(parent,leaf)!=original:raise FileError('artifact_unavailable')
            finally:os.close(fresh)
            phase='rename_parent_fsync';os.replace(temporary,leaf,src_dir_fd=parent,dst_dir_fd=parent);os.fsync(parent)
            phase='post_replace_fence'
            fresh,_=_parent(self._root(kind),path)
            try:
                after=os.stat(leaf,dir_fd=fresh,follow_symlinks=False);_regular(after)
                if _identity(fresh)!=_identity(parent) or (after.st_dev,after.st_ino)!=created:raise FileError('artifact_unavailable')
            finally:os.close(fresh)
        except (OSError,ValueError) as error:
            self.quarantined=True
            self._remember_file_failure(phase,error,storage_entered=True)
            raise FileError('artifact_unavailable') from None
        finally:
            if parent is not None:
                try:
                    phase='temporary_cleanup'
                    try:os.unlink(temporary,dir_fd=parent)
                    except FileNotFoundError:pass
                    phase='parent_close';os.close(parent)
                except (OSError,ValueError) as error:
                    self._remember_file_failure(phase,error,storage_entered=True)
                    raise

    def _read(self,stage,artifact_id):
        own=next((item for item in stage['completion']['artifacts'] if item['id']==artifact_id),None)
        if own is not None:
            root=self._root('artifact');parent,leaf=_parent(root,own['path'])
            try:body=read_file(parent,leaf,own['max_bytes'])
            finally:os.close(parent)
            media=own['media_type'];maximum=own['max_bytes']
            self._root('artifact')
        else:
            granted=next((item for item in stage['input_artifacts'] if item['artifact_id']==artifact_id),None)
            if granted is None:raise FileError('operation_not_granted')
            sealed=self._sealed.get((granted['stage_id'],artifact_id))
            if sealed is None:raise FileError('artifact_unavailable')
            path=PurePosixPath(sealed['path']);root=open_directory(str(path.parent),private=True)
            try:
                info=os.stat(path.name,dir_fd=root,follow_symlinks=False);_regular(info)
                if stat.S_IMODE(info.st_mode)&0o222:raise FileError('artifact_unavailable')
                body=read_file(root,path.name,sealed['bytes'])
                after=os.stat(path.name,dir_fd=root,follow_symlinks=False)
                if any(getattr(info,key)!=getattr(after,key) for key in
                       ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')):
                    raise FileError('artifact_unavailable')
            finally:os.close(root)
            media=sealed['media_type'];maximum=MAX_ARTIFACT_BYTES
        content=self._text(body,media,maximum)
        if own is None and (len(body)!=sealed['bytes'] or hashlib.sha256(body).hexdigest()!=sealed['sha256']):
            raise FileError('artifact_unavailable')
        metadata={'artifact_id':artifact_id,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
        result={'ok':True,**metadata,'media_type':media,'content':content}
        return result if len(c.canonical(result))<=MAX_RESULT_BYTES else {'ok':False,'reason':'result_limit',**metadata,'limit_bytes':MAX_RESULT_BYTES}

    def execute(self,bearer,scope,native_call_id,tool_name,input,budget_grant=None):
        with self._lock:
            self._diagnostic_step('begin')
            phase='authorize'
            try:
                scope=copy.deepcopy(scope);arguments=copy.deepcopy(input)
                self.authority.authorize(bearer,scope)
                phase='input_validation'
                c.native_id(native_call_id,'/native_call_id');c.safe_json(arguments)
                if (self._secret(native_call_id.encode('ascii'))
                    or self._secret(c.canonical(arguments))):raise FileError('request_invalid')
                phase='root_state'
                if not self._roots or self.quarantined:raise FileError('artifact_unavailable')
                phase='plan_identity'
                if c.digest(self.authority.plan)!=self._plan_sha:raise FileError('authority_changed')
                phase='tool_grant'
                stage=self._stages.get(scope.get('stage_name'))
                if stage is None or tool_name not in TOOLS or tool_name not in stage['tools']:raise FileError('operation_not_granted')
                if tool_name=='report_write':
                    phase='report_encode';path,body,metadata=self._report(stage,arguments);kind='report'
                else:
                    phase='artifact_input'
                    c.exact(arguments,{'artifact_id','content'} if tool_name=='artifact_write' else {'artifact_id'},'')
                    c.slug(arguments['artifact_id'],'/artifact_id');artifact_id=arguments['artifact_id']
                    own=next((item for item in stage['completion']['artifacts'] if item['id']==artifact_id),None)
                    incoming=next((item for item in stage['input_artifacts'] if item['artifact_id']==artifact_id),None)
                    if own is None and (incoming is None or tool_name=='artifact_write'):raise FileError('operation_not_granted')
                    if tool_name=='artifact_write':
                        if type(arguments['content']) is not str:raise FileError('request_invalid')
                        body=arguments['content'].encode('utf8');self._text(body,own['media_type'],own['max_bytes'])
                        path=own['path'];kind='artifact';metadata={'artifact_id':artifact_id}
                key=(scope['stage_id'],scope['segment_id'],native_call_id)
                if key in self._calls:raise FileError('operation_not_granted')
                phase='budget_verify'
                if budget_grant is None or self.budget_verifier(budget_grant,scope,native_call_id,tool_name,copy.deepcopy(arguments)) is not True:
                    raise FileError('accounting_unavailable')
                self._calls.add(key)
                phase='effect_authorize'
                self.authority.authorize(bearer,scope)
                if tool_name=='artifact_read':
                    phase='artifact_read';return self._read(stage,artifact_id)
                phase='storage_write';self._diagnostic_step('storage_entered')
                self._write(kind,path,body)
                self._diagnostic_step('storage_returned');phase='result'
                return {'ok':True,**metadata,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
            except (OSError,EvidenceError) as error:
                if error is self._diagnostic_control:
                    self._diagnostic_control=None;raise
                self._remember_file_failure(phase,error)
                return {'ok':False,'reason':'artifact_unavailable'}
            except Exception as error:
                reason=getattr(error,'reason',None)
                if reason=='artifact_unavailable':self._remember_file_failure(phase,error)
                return {'ok':False,'reason':reason if type(reason) is str and reason in REASONS else 'request_invalid'}
