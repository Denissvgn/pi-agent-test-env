"""Same-user durable launch registry; call only while holding the host lease.

PID/heartbeat are observations, never ownership or writer-stop evidence.
"""
import contextvars
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import threading
import uuid

import stage_control as controls
import registry_diagnostics as diagnostics
from registry_diagnostics import RegistryError, RegistryCapacityError

CURRENT=contextvars.ContextVar('pi_owned_admission',default=None)
SCHEMA=1
LABEL='org.pi-agent-test-env.launch'
REGISTRY_LABEL='org.pi-agent-test-env.registry'
MAX_RECORDS=8192
MAX_TRANSIENT_RECORDS=32


@diagnostics.scoped('registry_initialization')
def private_directory(path, *, create=True):
    path=Path(path).absolute()
    # No lexical alias may select another registry. Parent directories can be
    # shared (e.g. /tmp), but the registry itself is always owner-only.
    if path.is_symlink():raise RegistryError('Registry path aliases another location', condition='unsafe_path')
    path=path.parent.resolve()/path.name
    if create:
        with diagnostics.operation('directory_create', mutating=not path.exists()):
            path.mkdir(mode=0o700,parents=True,exist_ok=True)
    st=path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)&0o077:
        raise RegistryError('Registry directory is not owner-only', condition='unsafe_path')
    return path


@diagnostics.observed('record_read')
def read_private(path,decode=True):
    # A concurrent atomic replace can unlink the inode after open but before
    # fstat. Retry only that verified replacement, never an insecure named file.
    for unused in range(3):
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as f:
            st=os.fstat(f.fileno())
            if st.st_nlink==0:
                current=os.stat(path,follow_symlinks=False)
                if (st.st_dev,st.st_ino)!=(current.st_dev,current.st_ino):continue
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)&0o077 or st.st_size>1024*1024:
                raise RegistryError('Registry record is insecure or unbounded', condition='unsafe_record')
            return json.load(f) if decode else None
    raise RegistryError('Registry record changed during bounded observation', condition='unsafe_record')


def docker(argv):
    return subprocess.run(argv,text=True,capture_output=True,timeout=15)


def absent(reply):
    return reply.returncode!=0 and ('No such container' in reply.stderr or 'No such object' in reply.stderr)


def network_absent(reply,name):
    """Recognize only bounded Docker missing-network replies for the requested name."""
    if reply.returncode==0:return False
    escaped=re.escape(name)
    patterns=(r'(?:Error response from daemon: )?network '+escaped+r' not found',
              r'(?:Error(?: response from daemon)?: )?No such network(?::? '+escaped+r')')
    return any(re.fullmatch(pattern,reply.stderr.strip()) is not None for pattern in patterns)


def _qualification_canonical(value):
    return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8')


def _qualification_path(value):
    if (type(value) is not str or len(value)>4096 or value=='/' or not value.startswith('/') or value.startswith('//')
            or any(ord(ch)<32 or ord(ch)==127 for ch in value) or '..' in Path(value).parts or str(Path(value))!=value):
        raise RegistryError('Unsafe qualification cleanup path', condition='unsafe_path')
    return Path(value)


@diagnostics.observed('proof_read')
def _qualification_directory(path):
    path=_qualification_path(str(path));fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child
        return fd
    except BaseException:
        os.close(fd);raise


@diagnostics.observed('proof_read')
def _qualification_absent(path):
    path=_qualification_path(path);fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            try:child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            except FileNotFoundError:return True
            os.close(fd);fd=child
        try:os.stat(path.name,dir_fd=fd,follow_symlinks=False)
        except FileNotFoundError:return True
        return False
    finally:os.close(fd)


def _qualification_service(record):
    if (type(record) is not dict or record.get('application_helper') is not True
            or record.get('qualification_role') not in ('fixture','scripted-inference')
            or record.get('client_mode')!='qualification-'+record['qualification_role']
            or record.get('kind','container')!='container' or record.get('status') not in ('intent','running','absent','released','quarantined')):
        raise RegistryError('Invalid qualification service cleanup subtype')
    for key in ('launch_id','generation'):
        if not controls.valid_id(record.get(key)):raise RegistryError('Invalid qualification service cleanup identity')
    for key,pattern in (('registry',r'[a-f0-9]{64}'),('container_id',r'[a-f0-9]{64}'),('image',r'sha256:[a-f0-9]{64}'),
                        ('container',r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}'),('qualification_cell',r'[A-Za-z0-9][A-Za-z0-9.-]{0,127}')):
        if type(record.get(key)) is not str or re.fullmatch(pattern,record[key]) is None:
            raise RegistryError('Invalid qualification service cleanup identity')
    if type(record.get('daemon')) is not str or not 1<=len(record['daemon'])<=256 or type(record.get('binding')) is not dict:
        raise RegistryError('Invalid qualification service cleanup binding')
    _qualification_path(record.get('runroot'))
    mounts=record.get('mounts')
    if type(mounts) is not list or not 1<=len(mounts)<=16:raise RegistryError('Invalid qualification service cleanup mounts')
    targets=set();private=None
    for mount in mounts:
        if type(mount) is not dict or set(mount)!={'source','target','rw'} or type(mount['rw']) is not bool:
            raise RegistryError('Invalid qualification service cleanup mounts')
        _qualification_path(mount['source']);_qualification_path(mount['target'])
        if mount['target'] in targets:raise RegistryError('Invalid qualification service cleanup mounts')
        targets.add(mount['target'])
        if mount['target']=='/private':
            if mount['rw']:raise RegistryError('Invalid qualification service private mount')
            private=mount['source']
    if private is None:raise RegistryError('Missing qualification service private mount')
    immutable={key:value for key,value in record.items() if key not in ('status','container_id','qualification_service_cleanup','qualification_preworker_cleanup')}
    identity={key:record[key] for key in ('launch_id','registry','generation','daemon','container','container_id','image','runroot','binding','client_mode','mounts')}
    identity.update(role=record['qualification_role'],cell=record['qualification_cell'],
        intent_sha256=hashlib.sha256(_qualification_canonical(immutable)).hexdigest())
    if len(_qualification_canonical(identity))>49152:raise RegistryError('Unbounded qualification cleanup identity')
    return identity,private


def observe_qualification_private(record):
    """Observe the exact owner-private role mount by FD before an owned purge."""
    # The immutable container ID is acquired after dispatch, while this observation
    # is needed before dispatch. Validate the same shape with a temporary ID only.
    if type(record) is not dict:raise RegistryError('Invalid qualification service record')
    candidate={**record,'container_id':record.get('container_id') or '0'*64}
    unused,source=_qualification_service(candidate);fd=None
    try:
        fd=_qualification_directory(source);info=os.fstat(fd)
        if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077:
            raise RegistryError('Qualification private mount is not owner-only')
        return {'source':source,'device':info.st_dev,'inode':info.st_ino}
    except (OSError,ValueError) as exc:raise RegistryError('Qualification private mount cannot be observed', cause=exc) from None
    finally:
        if fd is not None:os.close(fd)


def _qualification_cleanup_payload(record,value):
    identity,source=_qualification_service(record)
    fields=set(identity)|{'schema','document_type','private_mount','physical_absence_confirmed','private_bootstrap_removed',
        'terminal_available','startup_readied','qualification_eligible'}
    if type(value) is not dict or set(value)!=fields or type(value['schema']) is not int or value['schema']!=1 or value['document_type']!='qualification_service_cleanup':
        raise RegistryError('Invalid qualification service cleanup proof')
    if any(_qualification_canonical(value[key])!=_qualification_canonical(expected) for key,expected in identity.items()):raise RegistryError('Qualification cleanup ownership changed', condition='ownership_mismatch')
    private=value['private_mount']
    if (type(private) is not dict or set(private)!={'source','device','inode'} or private['source']!=source
            or type(private['device']) is not int or not 0<=private['device']<2**64
            or type(private['inode']) is not int or not 1<=private['inode']<2**64):
        raise RegistryError('Invalid qualification private FD proof')
    if (value['physical_absence_confirmed'] is not True or value['private_bootstrap_removed'] is not True
            or any(type(value[key]) is not bool for key in ('terminal_available','startup_readied','qualification_eligible'))
            or value['qualification_eligible']!=(value['terminal_available'] and value['startup_readied'])
            or not _qualification_absent(source)):
        raise RegistryError('Qualification service cleanup remains uncertain', condition='cleanup_proof_invalid')
    return value


@diagnostics.scoped('qualification_service_cleanup', 'cleanup_proof_invalid')
@diagnostics.observed('proof_read')
def validate_qualification_service_cleanup(record,reference=None,*,reader=None):
    """Read a closed owner receipt; never infer service cleanup from agent files."""
    fd=parent=None
    try:
        if type(record) is not dict:raise RegistryError('Invalid qualification service record')
        if record.get('status') not in ('absent','released'):raise RegistryError('Qualification service is not absent')
        reference=record.get('qualification_service_cleanup') if reference is None else reference
        if reader is not None:
            value=_qualification_reference(reference,private=True,reader=reader,limit=65536)
            return _qualification_cleanup_payload(record,value)
        if (type(reference) is not dict or set(reference)!={'path','sha256'} or type(reference['sha256']) is not str
                or re.fullmatch(r'[a-f0-9]{64}',reference['sha256']) is None):raise RegistryError('Missing qualification cleanup reference')
        path=_qualification_path(reference['path']);parent=_qualification_directory(path.parent);info=os.fstat(parent)
        if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077:raise RegistryError('Qualification cleanup directory is not owner-only')
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1
                or stat.S_IMODE(info.st_mode)&0o077 or info.st_size>65536):raise RegistryError('Insecure qualification cleanup receipt')
        with os.fdopen(fd,'rb') as stream:
            fd=None;body=stream.read(65537)
        if len(body)>65536 or hashlib.sha256(body).hexdigest()!=reference['sha256']:raise RegistryError('Qualification cleanup receipt changed')
        def pairs(items):
            result={}
            for key,value in items:
                if key in result:raise RegistryError('Duplicate qualification cleanup field')
                result[key]=value
            return result
        value=json.loads(body,object_pairs_hook=pairs,parse_constant=lambda unused:(_ for _ in ()).throw(RegistryError('Invalid qualification cleanup number')))
        return _qualification_cleanup_payload(record,value)
    except (OSError,ValueError,TypeError,KeyError) as exc:raise RegistryError('Qualification service cleanup cannot be established', cause=exc) from None
    finally:
        if fd is not None:os.close(fd)
        if parent is not None:os.close(parent)


def write_qualification_service_cleanup(record,path,*,private_identity,physical_absence_confirmed,private_bootstrap_removed,terminal_available,startup_readied):
    """Publish a new known-clean owner receipt after physical absence and FD purge.

    This records the trusted owner's observations, not a Docker observation by
    this writer. Missing fixture terminal evidence never becomes oracle eligibility.
    """
    parent=fd=None
    try:
        if type(record) is not dict:raise RegistryError('Invalid qualification service record')
        if record.get('status')!='absent':raise RegistryError('Qualification service is not absent')
        identity,unused=_qualification_service(record)
        value={**identity,'schema':1,'document_type':'qualification_service_cleanup','private_mount':private_identity,
            'physical_absence_confirmed':physical_absence_confirmed,'private_bootstrap_removed':private_bootstrap_removed,
            'terminal_available':terminal_available,'startup_readied':startup_readied,
            'qualification_eligible':terminal_available is True and startup_readied is True}
        _qualification_cleanup_payload(record,value);body=_qualification_canonical(value)
        path=_qualification_path(str(path));parent=_qualification_directory(path.parent);info=os.fstat(parent)
        if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077:raise RegistryError('Qualification cleanup directory is not owner-only')
        fd=os.open(path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        with os.fdopen(fd,'wb') as stream:
            fd=None;stream.write(body);stream.flush();os.fsync(stream.fileno())
        os.fsync(parent)
        reference={'path':str(path),'sha256':hashlib.sha256(body).hexdigest()}
        validate_qualification_service_cleanup(record,reference)
        return reference
    except (OSError,ValueError,TypeError,KeyError) as exc:raise RegistryError('Qualification service cleanup receipt cannot be published', cause=exc) from None
    finally:
        if fd is not None:os.close(fd)
        if parent is not None:os.close(parent)


@diagnostics.observed('proof_read')
def _qualification_reference(reference,private=False,*,_current=False,reader=None,limit=None):
    if (type(reference) is not dict or set(reference)!={'path','sha256'} or type(reference['sha256']) is not str
            or re.fullmatch(r'[a-f0-9]{64}',reference['sha256']) is None) and not (_current and type(reference) is dict and set(reference)=={'path','sha256'} and reference['sha256'] is None):raise RegistryError('Invalid qualification evidence reference')
    maximum=262144 if private else 4194304
    if limit is not None:
        if type(limit) is not int or not 0<=limit<=maximum:raise RegistryError('Invalid qualification evidence bound')
        maximum=limit
    if reader is not None:
        path=_qualification_path(reference['path'])
        body,observed=reader.read_bytes(path,private=private,maximum=maximum)
        if len(body)>maximum or reference['sha256'] is not None and observed!=reference:
            raise RegistryError('Qualification evidence changed or exceeds its original bound')
        value,unused=reader.read(path,private=private)
        return value
    path=_qualification_path(reference['path']);parent=_qualification_directory(path.parent);fd=None
    try:
        info=os.fstat(parent)
        if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&(0o077 if private else 0o022):raise RegistryError('Unsafe qualification evidence directory')
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        with os.fdopen(fd,'rb') as stream:
            fd=None;info=os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1
                    or stat.S_IMODE(info.st_mode)&(0o077 if private else 0o022) or info.st_size>maximum):raise RegistryError('Unsafe qualification evidence file')
            body=stream.read(maximum+1)
        if len(body)>maximum or reference['sha256'] is not None and hashlib.sha256(body).hexdigest()!=reference['sha256']:raise RegistryError('Qualification evidence changed')
        def pairs(items):
            result={}
            for key,value in items:
                if key in result:raise RegistryError('Duplicate qualification evidence field')
                result[key]=value
            return result
        value=json.loads(body,object_pairs_hook=pairs,parse_constant=lambda unused:(_ for _ in ()).throw(RegistryError('Invalid qualification evidence number')))
        if type(value) is not dict:raise RegistryError('Invalid qualification evidence object')
        return value
    finally:
        if fd is not None:os.close(fd)
        os.close(parent)


def _preworker_identity(record):
    if (type(record) is not dict or record.get('application_helper') is not True or record.get('client_mode')!='application-execution'
            or record.get('status') not in ('absent','released') or 'qualification_role' in record or 'qualification_service_cleanup' in record):
        raise RegistryError('Invalid qualification preworker subtype')
    for key in ('launch_id','generation'):
        if not controls.valid_id(record.get(key)):raise RegistryError('Invalid qualification preworker identity')
    for key,pattern in (('registry',r'[a-f0-9]{64}'),('container_id',r'[a-f0-9]{64}'),('image',r'sha256:[a-f0-9]{64}')):
        if type(record.get(key)) is not str or re.fullmatch(pattern,record[key]) is None:raise RegistryError('Invalid qualification preworker identity')
    root=_qualification_path(record.get('runroot'));private=_qualification_path(record.get('private_store'))
    if private.parent!=root/'application-helpers' or re.fullmatch('[a-f0-9]{32}',private.name) is None:raise RegistryError('Invalid qualification preworker private root')
    if type(record.get('daemon')) is not str or not record['daemon'] or type(record.get('binding')) is not dict:raise RegistryError('Invalid qualification preworker binding')
    if type(record.get('container')) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}',record['container']) is None:raise RegistryError('Invalid qualification preworker container')
    code=record.get('code_identity')
    if type(code) is not dict or not 1<=len(code)<=64 or any(type(v) is not str or re.fullmatch('[a-f0-9]{64}',v) is None for v in code.values()):raise RegistryError('Invalid qualification preworker code identity')
    expected={'/opt/pi-application':(str(private/'code'),False),'/pi-client/state':(str(private/'state'),True),
              '/pi-client/evidence':(str(root/'application-evidence'/record['container']),True)}
    mounts=record.get('mounts')
    if type(mounts) is not list or len(mounts)!=3:raise RegistryError('Invalid qualification preworker mounts')
    for mount in mounts:
        if type(mount) is not dict or set(mount)!={'source','target','rw'} or type(mount['rw']) is not bool or mount['target'] not in expected:
            raise RegistryError('Invalid qualification preworker mounts')
        if (mount['source'],mount['rw'])!=expected.pop(mount['target']):raise RegistryError('Invalid qualification preworker mounts')
    immutable={k:v for k,v in record.items() if k not in ('status','container_id','qualification_service_cleanup','qualification_preworker_cleanup')}
    fields=('launch_id','registry','generation','daemon','container','container_id','image','runroot','binding','mounts','private_store','code_identity','client_mode')
    return {**{k:record[k] for k in fields},'intent_sha256':hashlib.sha256(_qualification_canonical(immutable)).hexdigest()}


def _preworker_exact(value,fields):
    if type(value) is not dict or set(value)!=set(fields):raise RegistryError('Invalid qualification preworker proof')


def _preworker_fd(value,*,removed=False):
    fields={'path','device','inode'}|({'removed'} if removed else set());_preworker_exact(value,fields)
    _qualification_path(value['path'])
    if (type(value['device']) is not int or not 0<=value['device']<2**64 or type(value['inode']) is not int or not 1<=value['inode']<2**64
            or removed and (value['removed'] is not True or not _qualification_absent(value['path']))):raise RegistryError('Invalid qualification preworker FD evidence')


def _preworker_control(value,descriptor,segment,*,reader=None):
    _preworker_exact(value,{'path','device','inode','retained_files','directories','private_contexts_absent','all_parent_authorities_scanned'})
    _preworker_fd({k:value[k] for k in ('path','device','inode')})
    if value['path']!=descriptor['control'] or value['private_contexts_absent'] is not True or value['all_parent_authorities_scanned'] is not True:
        raise RegistryError('Qualification preworker context cleanup uncertain')
    fd=_qualification_directory(value['path'])
    try:
        st=os.fstat(fd)
        if st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)&0o022 or (st.st_dev,st.st_ino)!=(value['device'],value['inode']):raise RegistryError('Qualification preworker control identity changed')
        files={};directories=[]
        def inventory(folder,prefix=''):
            names=os.listdir(folder)
            if len(names)>16:raise RegistryError('Unbounded qualification preworker controls')
            for name in names:
                relative=prefix+name;info=os.stat(name,dir_fd=folder,follow_symlinks=False)
                if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o022:raise RegistryError('Unsafe qualification preworker controls')
                if stat.S_ISDIR(info.st_mode):
                    if relative not in ('inbox','outbox','segments','segments/'+segment):raise RegistryError('Unexpected qualification preworker control directory')
                    directories.append(relative);child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=folder)
                    try:inventory(child,relative+'/')
                    finally:os.close(child)
                else:
                    if relative not in ('task.json','endpoint.json','stage.json') or not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>4194304:
                        raise RegistryError('Unexpected qualification preworker control file')
                    if reader is not None:
                        body,unused=reader.read_bytes(Path(value['path'])/relative)
                    else:
                        filefd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=folder)
                        with os.fdopen(filefd,'rb') as stream:body=stream.read(4194305)
                    if len(body)>4194304:raise RegistryError('Unbounded qualification preworker controls')
                    files[relative]={'path':relative,'sha256':hashlib.sha256(body).hexdigest(),'bytes':len(body)}
        inventory(fd)
        if type(value['retained_files']) is not list:raise RegistryError('Invalid retained qualification metadata')
        for item in value['retained_files']:
            _preworker_exact(item,{'path','sha256','bytes'})
            if type(item['bytes']) is not int or not 0<=item['bytes']<=4194304:raise RegistryError('Invalid retained qualification metadata size')
        if set(files)!={'task.json','endpoint.json','stage.json'} or type(value['retained_files']) is not list or value['retained_files']!=[files[k] for k in sorted(files)]:raise RegistryError('Qualification preworker retained inputs changed')
        if type(value['directories']) is not list or value['directories']!=sorted(directories) or 'segments/'+segment not in directories:raise RegistryError('Qualification preworker contexts changed')
        if reader is not None:
            named=_qualification_directory(value['path'])
            try:
                if (os.fstat(named).st_dev,os.fstat(named).st_ino)!=(st.st_dev,st.st_ino):raise RegistryError('Qualification preworker control directory changed')
            finally:os.close(named)
    finally:os.close(fd)


def _preworker_payload(record,value,*,historical_replay=False,reader=None):
    if type(historical_replay) is not bool or historical_replay and record.get('status')!='released':
        raise RegistryError('Historical qualification cleanup requires a released record')
    identity=_preworker_identity(record)
    _preworker_exact(value,set(identity)|{'schema','document_type','qualification','controller','stage','private_cleanup','launches','service_receipts'})
    if type(value['schema']) is not int or value['schema']!=1 or value['document_type']!='qualification_preworker_cleanup':raise RegistryError('Invalid qualification preworker receipt')
    if any(_qualification_canonical(value[k])!=_qualification_canonical(v) for k,v in identity.items()):raise RegistryError('Qualification preworker ownership changed')
    qualification=value['qualification'];_preworker_exact(qualification,{'lineage','cumulative_attempts','participant_segments'})
    lineage=qualification['lineage']
    if type(lineage) is not list or len(lineage)!=2 or type(qualification['cumulative_attempts']) is not int or qualification['cumulative_attempts']!=19 or type(qualification['participant_segments']) is not int or qualification['participant_segments']!=0:
        raise RegistryError('Invalid qualification preworker campaign scope')
    allrows=[];roots=set();previous=None;leaf=None
    for index,entry in enumerate(lineage):
        _preworker_exact(entry,{'root','manifest','state','ledger'});root=_qualification_path(entry['root'])
        if str(root) in roots:raise RegistryError('Cyclic qualification preworker lineage')
        roots.add(str(root))
        for key,relative in (('manifest','manifest.json'),('state','state.json'),('ledger','launch-ledger/ledger.json')):
            if entry[key].get('path')!=str(root/relative):raise RegistryError('Qualification preworker evidence rerooted')
        manifest=_qualification_reference(entry['manifest'],reader=reader);state=_qualification_reference(entry['state'],reader=reader);ledger=_qualification_reference(entry['ledger'],reader=reader)
        if (manifest.get('document_type')!='application_client_qualification' or manifest.get('prepared_root')!=str(root) or len(manifest.get('cells',[]))!=28
                or state.get('phase')!='blocked' or ledger.get('poisoned') is not True or type(ledger.get('launches')) is not list
                or len(ledger['launches'])!=(7 if index==0 else 12)):raise RegistryError('Invalid qualification preworker frozen campaign')
        if previous is None:
            if 'predecessor' in manifest or 'carry' in ledger:raise RegistryError('Invalid qualification preworker first campaign')
        else:
            predecessor=manifest.get('predecessor',{})
            if (predecessor.get('root')!=previous['root'] or any(predecessor.get(k+'_sha256')!=previous[k]['sha256'] for k in ('manifest','state','ledger'))
                    or ledger.get('carry',{}).get('attempts')!=7 or ledger['carry'].get('participant_segments')!=0
                    or any(ledger.get(k)!=leaf[2].get(k) for k in ('started','deadline','started_wall','deadline_wall'))):raise RegistryError('Qualification preworker lineage reset')
        if any(row.get('physical')!='absent' or row.get('role')=='participant' or type(row.get('container_id')) is not str or re.fullmatch('[a-f0-9]{64}',row['container_id']) is None for row in ledger['launches']):raise RegistryError('Qualification preworker writer absence uncertain')
        allrows.extend(ledger['launches']);previous=entry;leaf=(manifest,state,ledger)
    manifest,state,ledger=leaf;active=state['active_cell'];stage=value['stage']
    _preworker_exact(stage,{'descriptor','state','process','result','stage_id','segment_id','worker_launch_attempted','application_context_issued'})
    if stage['worker_launch_attempted'] is not False or stage['application_context_issued'] is not False or not controls.valid_id(stage['stage_id']) or not controls.valid_id(stage['segment_id']):raise RegistryError('Qualification preworker launch absence uncertain')
    runroot=Path(record['runroot']);expected={'descriptor':runroot/'stages'/stage['stage_id']/'descriptor.json','state':runroot/'stages'/stage['stage_id']/'state.json','result':runroot/'result.json'}
    for key,path in expected.items():
        if stage[key].get('path')!=str(path):raise RegistryError('Qualification preworker stage rerooted')
    descriptor=_qualification_reference(stage['descriptor'],reader=reader);stage_state=_qualification_reference(stage['state'],reader=reader);result=_qualification_reference(stage['result'],reader=reader)
    if stage['process'].get('path')!=str(runroot/descriptor.get('label','')/'process.json'):raise RegistryError('Qualification preworker process rerooted')
    process=_qualification_reference(stage['process'],reader=reader)
    if (descriptor.get('kind')!='agent' or descriptor.get('stage_id')!=stage['stage_id'] or descriptor.get('label')!='agent-1-participant'
            or stage_state.get('status')!='finalized' or stage_state.get('cleanup_confirmed') is not False or stage_state.get('segment_id')!=stage['segment_id']
            or result.get('sealed') is not True or result.get('status')!='FAIL' or result.get('agents')!=[] or result.get('invocation')!={'status':'invalid','attempted_stages':1}
            or descriptor.get('control')!=str(runroot/'controls'/stage['stage_id']) or descriptor.get('workspace')!=str(runroot/'workspace')
            or result.get('infrastructure',{}).get('phase')!='agents' or result.get('infrastructure',{}).get('reason')!='ApplicationExecutionError'
            or process.get('cleanup_confirmed') is not False or process.get('termination_reason')!='application_credential_cleanup'
            or any(result.get(k)!=active.get(k) or descriptor.get(k)!=active.get(k) or record['binding'].get(k)!=active.get(k) for k in ('run_id','attempt_id'))):raise RegistryError('Qualification preworker original failure changed')
    controller=value['controller'];_preworker_exact(controller,{'pid','parent_terminal','original_invocation','pid_absence_observed','provenance'})
    if controller['pid']!=active['pid'] or type(controller['pid']) is not int or controller['pid_absence_observed'] is not True or controller['provenance']!='terminal_parent_and_pid_absence':raise RegistryError('Qualification preworker controller uncertain')
    terminal=_qualification_reference(controller['parent_terminal'],reader=reader);invocation=_qualification_reference(controller['original_invocation'],reader=reader);argv=invocation.get('argv')
    if (type(terminal.get('actual_exit')) is not int or terminal['actual_exit']!=2 or type(argv) is not list or len(argv)!=9
            or argv[2:8]!=['_cell-run','--root',lineage[-1]['root'],'--cell-id',active['id'],'--private-envelope']
            or terminal.get('argv')!=['python3','tools/qualification/application_client.py','collect','--root',lineage[-1]['root'],'--group','N02','--release','0.87.1']
            or terminal.get('cwd')!=invocation.get('cwd') or invocation.get('classification')!='native_scripted_protocol'):
        raise RegistryError('Qualification preworker parent termination uncertain')
    # A released record already committed this exact cleanup proof after live
    # validation. Its historical absence observation does not expire when the
    # numeric PID is reused. Initial publication and release still check it live.
    if not historical_replay:
        try:os.kill(controller['pid'],0)
        except ProcessLookupError:pass
        except PermissionError as exc:raise RegistryError('Qualification preworker controller absence uncertain',cause=exc) from None
        else:raise RegistryError('Qualification preworker controller remains present')
    private=value['private_cleanup'];_preworker_exact(private,{'helper','parent_bootstrap','control','workspace'})
    _preworker_exact(private['helper'],{'source','provenance','removed','container_id_provenance'})
    if private['helper']!={'source':record['private_store'],'provenance':'prior_owned_cleanup','removed':True,'container_id_provenance':'original_guard_ledger'} or private['helper']['removed'] is not True or not _qualification_absent(record['private_store']):raise RegistryError('Qualification preworker helper cleanup uncertain')
    _preworker_fd(private['parent_bootstrap'],removed=True)
    if str(Path(argv[-1]).parent)!=private['parent_bootstrap']['path'] or Path(argv[-1]).name!='initial.json' or not Path(private['parent_bootstrap']['path']).name.startswith('pi-qualification-cell-'):raise RegistryError('Qualification preworker parent authority rerooted')
    _preworker_control(private['control'],descriptor,stage['segment_id'],reader=reader)
    workspace=private['workspace'];_preworker_exact(workspace,{'path','device','inode','status','provenance','all_parent_authorities_scanned'})
    _preworker_fd({k:workspace[k] for k in ('path','device','inode')})
    if (workspace['path']!=descriptor['workspace'] or [workspace['device'],workspace['inode']]!=descriptor.get('workspace_identity')
            or workspace['status']!='discarded' or workspace['provenance']!='original_descriptor' or workspace['all_parent_authorities_scanned'] is not True
            or not _qualification_absent(workspace['path'])):raise RegistryError('Qualification preworker workspace cleanup uncertain')
    rows=value['launches']
    if type(rows) is not list or len(rows)!=19 or len({r.get('launch_id') for r in rows})!=19:raise RegistryError('Qualification preworker launch history changed')
    rows={r['launch_id']:r for r in rows};service_refs=value['service_receipts']
    if type(service_refs) is not list or len(service_refs)!=3:raise RegistryError('Qualification preworker service proof missing')
    used=[];helper_rows=[];registry_root=Path(descriptor['admission_lock_file']+'.registry')
    for row in allrows:
        proof=rows.get(row['launch_id']);_preworker_exact(proof,{'registry','generation','launch_id','container_id','physical_absence_confirmed','private_cleanup_confirmed'})
        if (any(proof[k]!=row[k] for k in ('registry','generation','launch_id','container_id')) or proof['physical_absence_confirmed'] is not True or proof['private_cleanup_confirmed'] is not True):raise RegistryError('Qualification preworker launch cleanup uncertain')
        current=_qualification_reference({'path':str(registry_root/(row['launch_id']+'.json')),'sha256':None},_current=True,reader=reader)
        immutable={k:v for k,v in current.items() if k not in ('status','container_id','qualification_service_cleanup','qualification_preworker_cleanup')}
        if (current.get('status') not in ('absent','released') or current.get('container_id') not in (None,row['container_id']) or current.get('daemon')!=ledger['daemon']
                or hashlib.sha256(_qualification_canonical(immutable)).hexdigest()!=row['intent_sha256']):raise RegistryError('Qualification preworker current ownership changed')
        if row['role'] in ('fixture','scripted-inference'):
            reference=current.get('qualification_service_cleanup')
            if reference not in service_refs:raise RegistryError('Qualification preworker service cleanup missing')
            validate_qualification_service_cleanup(current,reference,reader=reader);used.append(reference)
        elif row['role']=='application-helper':
            helper_rows.append(row)
            if row['launch_id']!=record['launch_id'] or row['private_cleanup'] is not True or row['container_id']!=record['container_id'] or row['cell']!=active['id']:raise RegistryError('Qualification preworker helper history changed')
        elif row.get('private_cleanup') is not True and (row['cell']!=active['id'] or row['role'] not in ('probe','boundary','preflight')):
            raise RegistryError('Qualification preworker unrelated cleanup uncertain')
    if len(helper_rows)!=1 or len(used)!=3 or any(r not in used for r in service_refs):raise RegistryError('Qualification preworker proof scope changed')
    return value


@diagnostics.scoped('qualification_preworker_cleanup', 'cleanup_proof_invalid')
@diagnostics.observed('proof_read')
def validate_qualification_preworker_cleanup(record,reference=None,*,historical_replay=False,reader=None):
    """Validate the full owner proof; replay only a released, attached receipt.

    Historical replay avoids probing a reusable PID. It still verifies the
    original absence/terminal proof and every frozen ownership/cleanup predicate.
    It is not a metadata-only operation: referenced evidence is still validated.
    """
    try:
        reference=record.get('qualification_preworker_cleanup') if reference is None else reference
        if (type(historical_replay) is not bool or historical_replay and
                (record.get('status')!='released' or reference!=record.get('qualification_preworker_cleanup'))):
            raise RegistryError('Historical qualification cleanup requires the attached released receipt')
        return _preworker_payload(record,_qualification_reference(reference,private=True,reader=reader),historical_replay=historical_replay,reader=reader)
    except (OSError,ValueError,TypeError,KeyError,AttributeError,IndexError) as exc:raise RegistryError('Qualification preworker cleanup cannot be established', cause=exc) from None


def write_qualification_preworker_cleanup(record,path,*,proof):
    """Record separately observed owner cleanup; never rewrite historical stages."""
    parent=fd=None
    try:
        _preworker_exact(proof,{'qualification','controller','stage','private_cleanup','launches','service_receipts'})
        value={**_preworker_identity(record),'schema':1,'document_type':'qualification_preworker_cleanup',**proof}
        _preworker_payload(record,value);body=_qualification_canonical(value)
        if len(body)>262144:raise RegistryError('Unbounded qualification preworker receipt')
        path=_qualification_path(str(path));parent=_qualification_directory(path.parent);info=os.fstat(parent)
        if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077:raise RegistryError('Unsafe qualification preworker receipt directory')
        fd=os.open(path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        with os.fdopen(fd,'wb') as stream:fd=None;stream.write(body);stream.flush();os.fsync(stream.fileno())
        os.fsync(parent);reference={'path':str(path),'sha256':hashlib.sha256(body).hexdigest()}
        validate_qualification_preworker_cleanup(record,reference);return reference
    except (OSError,ValueError,TypeError,KeyError,AttributeError,IndexError) as exc:raise RegistryError('Qualification preworker cleanup receipt cannot be published', cause=exc) from None
    finally:
        if fd is not None:os.close(fd)
        if parent is not None:os.close(parent)


@diagnostics.scoped('application_cleanup', 'application_cleanup_pending')
def _application_stage_pending(path):
    """Bounded no-follow observation before generic recovery has any effects."""
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts:raise RegistryError('Unsafe application recovery root')
    root=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    def child(parent,name):
        try:return os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        except FileNotFoundError:return None
    def names(fd):
        values=os.listdir(fd)
        if len(values)>256:raise RegistryError('Application cleanup inventory is unbounded')
        return values
    @diagnostics.observed('proof_read')
    def read(parent,name,private=False):
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        with os.fdopen(fd,'rb') as stream:
            st=os.fstat(stream.fileno())
            if (not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_nlink!=1
                    or st.st_size>4*1024*1024 or stat.S_IMODE(st.st_mode)&(0o077 if private else 0o022)):
                raise RegistryError('Unsafe application cleanup proof')
            body=stream.read(4*1024*1024+1)
            if len(body)>4*1024*1024:raise RegistryError('Unbounded application cleanup proof')
            value=json.loads(body)
            if type(value) is not dict:raise RegistryError('Invalid application cleanup proof')
            return value
    try:
        for part in path.parts[1:]:
            nextfd=child(root,part)
            if nextfd is None:return True
            os.close(root);root=nextfd
        info=os.fstat(root)
        if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o022:raise RegistryError('Unsafe application recovery root')
        stages=child(root,'stages')
        agents=0
        if stages is not None:
            try:
                for name in names(stages):
                    folder=child(stages,name)
                    if folder is None:continue
                    try:
                        desc=read(folder,'descriptor.json')
                        if desc.get('stage_id')!=name:raise RegistryError('Application stage identity changed')
                        if desc.get('kind')!='agent':continue
                        agents+=1
                        receipt=read(folder,'application-credentials.json',True)
                        if (type(receipt) is not dict or type(receipt.get('schema')) is not int or receipt['schema']!=1 or receipt.get('status')!='removed'
                                or receipt.get('workspace') not in ('clean','discarded')):return True
                        state=read(folder,'state.json')
                        if state.get('status')!='finalized' or state.get('cleanup_confirmed') is not True:return True
                        label=desc.get('label')
                        if type(label) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',label):return True
                        output=child(root,label)
                        if output is None:return True
                        try:process=read(output,'process.json')
                        finally:os.close(output)
                        cleanup=process.get('application_helper_cleanup',process.get('native_tool_budget_cleanup',{}))
                        if (process.get('cleanup_confirmed') is not True or type(cleanup) is not dict
                                or cleanup.get('status')!='removed' or cleanup.get('workspace') not in ('clean','discarded')
                                or cleanup.get('safe_to_continue') is not True
                                or process.get('application_credentials')!= {k:v for k,v in receipt.items() if k!='references'}):return True
                    finally:os.close(folder)
            finally:os.close(stages)
        if not agents:return True
        control=child(root,'controls')
        if control is None:return False
        try:
            for name in names(control):
                stage=child(control,name)
                if stage is None:continue
                try:
                    segments=child(stage,'segments')
                    if segments is None:continue
                    try:
                        for name in names(segments):
                            segment=child(segments,name)
                            if segment is None:continue
                            try:
                                for leaf in ('application-context.json','native-budget-context.json'):
                                    try:os.stat(leaf,dir_fd=segment,follow_symlinks=False)
                                    except FileNotFoundError:continue
                                    return True
                            finally:os.close(segment)
                    finally:os.close(segments)
                finally:os.close(stage)
        finally:os.close(control)
        return False
    except (OSError,ValueError) as exc:raise RegistryError('Application sensitive cleanup cannot be established', cause=exc) from None
    finally:os.close(root)


class Registry:
    @diagnostics.scoped('registry_initialization')
    def __init__(self,path,command=docker,recover_sensitive=None,*,create=True):
        self.root=private_directory(path,create=create);self.command=command
        self.generation=str(uuid.uuid4());self.registry_id=hashlib.sha256(str(self.root).encode()).hexdigest()
        self.recover_sensitive=recover_sensitive;self.runroot=None;self.binding={};self.daemon=None
        self._write_lock=threading.RLock()

    def _paths(self,observe=False):
        paths=[];transient=0
        with diagnostics.operation('inventory_read'), os.scandir(self.root) as entries:
            for entry in entries:
                path=self.root/entry.name
                if observe and re.fullmatch(r'\.[a-f0-9-]{36}\.json-[a-f0-9]{32}',path.name):
                    # An observation sees only committed records. Admission remains
                    # strict: an abandoned temporary entry still blocks dispatch.
                    try:read_private(path,decode=False)
                    except FileNotFoundError:pass # atomic replace consumed this temporary name
                    transient+=1
                    if transient>MAX_TRANSIENT_RECORDS:raise RegistryError('Registry transient inventory exceeds its bounded limit', condition='inventory_unbounded')
                    continue
                if not re.fullmatch(r'[a-f0-9-]{36}\.json',path.name):raise RegistryError('Unknown registry entry', condition='unexpected_entry')
                paths.append(path)
                if len(paths)>MAX_RECORDS:raise RegistryCapacityError('Registry committed inventory exceeds its bounded limit')
        return paths

    @diagnostics.scoped('inventory')
    def load(self,observe=False):
        records=[]
        for path in self._paths(observe):
            record=read_private(path)
            if (not isinstance(record,dict) or type(record.get('schema')) is not int or record.get('schema') not in (1,2,3)
                or not controls.valid_id(record.get('launch_id')) or path.stem!=record['launch_id']
                or record.get('registry')!=self.registry_id or not controls.valid_id(record.get('generation'))
                or record.get('status') not in ('intent','running','absent','released','quarantined')
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}',record.get('container',''))
                or (record.get('kind','container')!='network' and not re.fullmatch(r'sha256:[a-f0-9]{64}',record.get('image','')))
                or record.get('kind','container') not in ('container','network','builder')
                or not isinstance(record.get('mounts'),list)):
                raise RegistryError('Malformed launch registry', condition='malformed_record')
            if record['schema']==3:
                if (record.get('application_helper') is not True or type(record.get('owner_cleanup_contract')) is not int
                        or record['owner_cleanup_contract']!=1
                        or record.get('client_mode') not in ('application-execution','authority-only','budget-only')
                        or any(k in record for k in ('qualification_role','qualification_service_cleanup','qualification_preworker_cleanup'))):
                    raise RegistryError('Invalid application ownership contract', condition='malformed_record')
            elif 'owner_cleanup_contract' in record:
                raise RegistryError('Application ownership requires its versioned record format', condition='malformed_record')
            if record['schema']==2 and (not isinstance(record.get('binding'),dict) or type(record['binding'].get('indexed_host_generation')) is not int or record['binding']['indexed_host_generation']!=2):raise RegistryError('Invalid indexed registry generation', condition='malformed_record')
            if any(not isinstance(m,dict) or set(m)!={'source','target','rw'} or not isinstance(m['source'],str) or not Path(m['source']).is_absolute() or not isinstance(m['target'],str) or not m['target'].startswith('/') or type(m['rw']) is not bool for m in record['mounts']):
                raise RegistryError('Malformed ownership mount bindings', condition='malformed_record')
            records.append(record)
        return records

    def require_capacity(self,additional):
        if type(additional) is not int or not 0<=additional<=MAX_RECORDS:
            raise RegistryCapacityError('Invalid registry reservation')
        count=len(self.load())
        if count+additional>MAX_RECORDS:raise RegistryCapacityError('Insufficient registry headroom before dispatch')
        return {'retained_records':count,'new_records_ceiling':additional,'committed_records_limit':MAX_RECORDS}

    @diagnostics.scoped('registry_write', inherit=True)
    def write(self,record):
        if not controls.valid_id(record.get('launch_id')):raise RegistryError('Invalid launch identity')
        if len((json.dumps(record,ensure_ascii=False,indent=2)+'\n').encode())>1024*1024:
            raise RegistryError('Registry record exceeds its bounded limit')
        with self._write_lock:
            path=self.root/(record['launch_id']+'.json')
            try:read_private(path,decode=False)
            except FileNotFoundError:
                if len(self._paths(observe=True))>=MAX_RECORDS:raise RegistryCapacityError('Registry capacity exhausted before intent creation')
            controls.atomic(path,record)
            with diagnostics.operation('directory_open'):
                fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:
                with diagnostics.operation('directory_fsync', mutating=True):os.fsync(fd)
            finally:os.close(fd)

    @diagnostics.scoped('application_cleanup')
    def validate_history(self, records, *, quarantine=False):
        """Shared predicates; only reconciliation may quarantine pending helpers."""
        pending=[r for r in records if r['status']!='released']
        application=[record for record in pending if record.get('application_helper') is True]
        if application:
            if quarantine:
                for record in application:
                    record['status']='quarantined';self.write(record)
            raise RegistryError('Application helper requires owned sensitive cleanup; generic recovery is prohibited',
                                condition='owned_application_cleanup_required')
        def qualification(record):
            return (str(record.get('client_mode','')).startswith('qualification-')
                or 'qualification_role' in record or 'qualification_service_cleanup' in record)
        for record in records:
            if record.get('application_helper') is True and 'qualification_preworker_cleanup' in record:
                validate_qualification_preworker_cleanup(record,historical_replay=record.get('status')=='released')
            elif record.get('application_helper') is True and qualification(record):
                validate_qualification_service_cleanup(record)
            elif record.get('application_helper') is True:
                # Explicitly selected owner proof is checked even for all-released
                # history; malformed new evidence never falls back to legacy.
                import application_owner_cleanup
                accepted = application_owner_cleanup.validate_accepted(self, record)
                if application_owner_cleanup.requires_proof(self, record) and not accepted:
                    raise RegistryError('Current helper cleanup proof was not finalized', condition='application_cleanup_pending')
        if not pending:return []
        for record in records:
            if record.get('application_helper') is not True or qualification(record) or 'qualification_preworker_cleanup' in record:continue
            import application_owner_cleanup
            if application_owner_cleanup.validate_accepted(self, record):continue
            if record.get('runroot') is None or _application_stage_pending(record['runroot']):
                raise RegistryError('Application contexts or credential cleanup remain pending; generic recovery is prohibited',
                                    condition='application_cleanup_pending')
        return pending

    @diagnostics.scoped('reconciliation')
    def reconcile(self):
        records=self.load()
        pending=self.validate_history(records,quarantine=True)
        if not pending:return []
        with diagnostics.phase('daemon_observation'):
            if any(r.get('daemon') for r in pending):
                with diagnostics.operation('daemon_info'):
                    observed=self.command(['docker','info','--format','{{.ID}}'])
                if observed.returncode:
                    raise RegistryError('Daemon identity cannot be observed',condition='daemon_unavailable')
                if any(r.get('daemon')!=observed.stdout.strip() for r in pending):
                    raise RegistryError('Daemon identity changed',condition='daemon_changed')
        # An owner died: recover every writer before touching sensitive files.
        for record in pending:
            with diagnostics.phase('inference_termination'):
                if record.get('inference_uncertain'):
                    raise RegistryError('Upstream request termination remains uncertain',condition='inference_uncertain')
                if record.get('gateway_state') and record.get('gateway_ready'):
                    import time
                    deadline=time.monotonic()+35
                    while True:
                        value=read_private(record['gateway_state'])
                        if value.get('launch_id')!=record['launch_id'] or value.get('uncertain'):
                            raise RegistryError('Gateway inference termination uncertain',condition='inference_uncertain')
                        if value.get('inflight')==0 and value.get('pending')==0:break
                        if time.monotonic()>=deadline:
                            raise RegistryError('Gateway still owns an upstream request',condition='gateway_pending')
                        time.sleep(.1)
            if record.get('kind')=='network':continue
            with diagnostics.phase('writer_inspection'):
                with diagnostics.operation('container_inspect'):
                    reply=self.command(['docker','container','inspect',record['container']])
                if not absent(reply):
                    if reply.returncode:
                        raise RegistryError('Writer absence cannot be established',condition='writer_observation_failed')
                    try:data=json.loads(reply.stdout)[0]
                    except (ValueError,KeyError,IndexError) as exc:
                        raise RegistryError('Invalid writer inspection',condition='writer_observation_failed',cause=exc) from None
                    labels=data.get('Config',{}).get('Labels') or {}
                    mounts=data.get('Mounts') or []
                    expected={LABEL:record['launch_id'],REGISTRY_LABEL:self.registry_id}
                    label_match=all(labels.get(k)==v for k,v in expected.items())
                    if record.get('kind')=='builder':label_match=bool(record.get('container_id')) and data.get('Id')==record['container_id']
                    if (data.get('Image')!=record['image'] or not label_match
                        or any(not any(m.get('Source')==e['source'] and m.get('Destination')==e['target'] and m.get('RW')==e['rw'] for m in mounts) for e in record['mounts'])):
                        record['status']='quarantined';self.write(record)
                        raise RegistryError('Container ownership does not match persisted intent',condition='ownership_mismatch')
                    with diagnostics.phase('writer_termination'):
                        with diagnostics.operation('container_remove',mutating=True):
                            removed=self.command(['docker','rm','--force',record['container']])
                        if removed.returncode:
                            raise RegistryError('Owned writer cleanup failed',condition='writer_cleanup_failed')
                        with diagnostics.operation('container_inspect'):
                            reply=self.command(['docker','container','inspect',record['container']])
                        if not absent(reply):
                            raise RegistryError('Owned writer absence is unconfirmed',condition='writer_absence_unconfirmed')
            with diagnostics.phase('persist_absent'):
                record['status']='absent';self.write(record)
        for record in pending:
            if record.get('kind')=='network':self.remove_network(record)
        # Every selected proof remains mandatory after writer/status changes,
        # even when the recovered writer belongs to a different retained run.
        self.validate_history(self.load(),quarantine=False)
        with diagnostics.phase('sensitive_recovery'):
            for runroot in {r.get('runroot') for r in pending if r.get('runroot')}:
                path=Path(runroot)
                try:canonical=path.resolve(strict=False)
                except (OSError,RuntimeError) as exc:
                    raise RegistryError('Sensitive recovery scope is unknown',condition='owner_scope_unsupported',cause=exc) from None
                if not path.is_absolute() or path.is_symlink() or str(path)!=runroot or path!=canonical:
                    raise RegistryError('Unsafe sensitive recovery root',condition='unsafe_path')
                import application_owner_cleanup
                owners=[r for r in records if r.get('runroot')==runroot and r.get('application_helper') is True
                        and not str(r.get('client_mode','')).startswith('qualification-')
                        and not any(k in r for k in ('qualification_role','qualification_service_cleanup','qualification_preworker_cleanup'))]
                if any(application_owner_cleanup.validate_accepted(self, r) for r in owners):
                    # Owner proof already establishes sensitive cleanup while
                    # preserving original failed accounting. Revalidate after
                    # writer/status transitions; legacy repair would rewrite it.
                    self.validate_history(self.load(),quarantine=False)
                    continue
                if self.recover_sensitive is None:
                    import application_credentials
                    application_credentials.recover(path)
                else:self.recover_sensitive(path)
        for record in pending:
            with diagnostics.phase('private_store_cleanup'):
                if record.get('private_store'):
                    import shutil
                    path=Path(record['private_store'])
                    if path.is_symlink() or path.parent.resolve()!=Path(__import__('tempfile').gettempdir()).resolve() or not path.name.startswith('pi-parallel-gateway-'):
                        raise RegistryError('Unsafe gateway private-store cleanup path',condition='unsafe_path')
                    if path.exists():
                        with diagnostics.operation('purge',mutating=True):shutil.rmtree(path)
            with diagnostics.phase('persist_release'):
                record['status']='released';self.write(record)
        # A successful return cannot hide proof loss during final publication.
        self.validate_history(self.load(),quarantine=False)
        return pending

    def intent(self,argv,name,binding=None,runroot=None):
        if argv[:2]!=['docker','run'] or '--name' not in argv or argv[argv.index('--name')+1]!=name:
            raise RegistryError('Unrecognized owned launch')
        # Worker argv uses a pinned image immediately before the absolute helper.
        indices=[i for i,x in enumerate(argv) if x=='/opt/pi-lab/worker.py']
        if len(indices)!=1:raise RegistryError('Unrecognized immutable worker image')
        image=argv[indices[0]-1]
        if not re.fullmatch(r'sha256:[a-f0-9]{64}',image):raise RegistryError('Registry needs an immutable image')
        mounts=[]
        for i,value in enumerate(argv):
            if value!='--mount':continue
            parts=argv[i+1].split(',');options=dict(p.split('=',1) for p in parts if '=' in p)
            if options.get('type')!='bind':raise RegistryError('Unreviewed launch mount')
            mounts.append({'source':str(Path(options['src']).resolve()),'target':options['dst'],'rw':'readonly' not in parts})
        record={'schema':SCHEMA,'launch_id':str(uuid.uuid4()),'generation':self.generation,
                'registry':self.registry_id,'status':'intent','container':name,'image':image,'mounts':mounts,
                'binding':{**self.binding,**(binding or {})},'runroot':str(runroot or self.runroot) if runroot or self.runroot else None,
                'created_at':controls.now(),'owner_pid':os.getpid(),'daemon':self.daemon}
        if record['binding'].get('indexed_host_generation')==2:record['schema']=2
        self.write(record) # fsync precedes the Docker CLI launch.
        labelled=argv[:2]+['--label',LABEL+'='+record['launch_id'],'--label',REGISTRY_LABEL+'='+self.registry_id]+argv[2:]
        return record,labelled

    def confirm_absent(self,record):
        target=record['container']
        if record.get('application_helper') is True:
            target=record.get('container_id')
            if type(target) is not str or re.fullmatch(r'[a-f0-9]{64}',target) is None:
                record['status']='quarantined';self.write(record);return False
        reply=self.command(['docker','container','inspect',target])
        confirmed=(reply.returncode!=0 and re.fullmatch(r'(?:(?:Error response from daemon|Error): )?No such (?:container|object):? '+re.escape(target),reply.stderr.strip()) is not None
                   if record.get('application_helper') is True else absent(reply))
        record['status']='absent' if confirmed else 'quarantined';self.write(record)
        return confirmed

    @diagnostics.scoped('persist_release')
    def release(self,record,sensitive_clean):
        if record['status']!='absent' or sensitive_clean is not True:
            record['status']='quarantined';self.write(record);raise RegistryError('Sensitive or physical cleanup remains uncertain', condition='sensitive_cleanup_pending')
        if record.get('application_helper') is True and 'qualification_preworker_cleanup' in record:
            try:validate_qualification_preworker_cleanup(record)
            except RegistryError:
                record['status']='quarantined';self.write(record);raise
        if (record.get('application_helper') is True and (str(record.get('client_mode','')).startswith('qualification-')
                or 'qualification_role' in record or 'qualification_service_cleanup' in record)):
            try:validate_qualification_service_cleanup(record)
            except RegistryError:
                record['status']='quarantined';self.write(record);raise
        record['status']='released';self.write(record)

    @diagnostics.scoped('terminal_close')
    def close(self):
        import application_owner_cleanup
        application_owner_cleanup.finalize_current(self)
        current=[r for r in self.load() if r['generation']==self.generation and r['status']!='released']
        for root in {r['runroot'] for r in current if r['runroot']}:
            for receipt in (Path(root)/'stages').glob('*/application-credentials.json'):
                if controls.read(receipt).get('status')!='removed':
                    raise RegistryError('Sensitive state has not been purged', condition='sensitive_cleanup_pending')
        for record in current:self.release(record,True)

    def check_cancel(self):
        pass

    def bind_daemon(self,value):
        if not isinstance(value,str) or not value or len(value)>256:raise RegistryError('Observed daemon identity missing')
        if self.daemon is not None and self.daemon!=value:raise RegistryError('Daemon changed within admission')
        self.daemon=value

    def network_intent(self,name):
        record={'schema':SCHEMA,'launch_id':str(uuid.uuid4()),'generation':self.generation,'registry':self.registry_id,
                'kind':'network','status':'intent','container':name,'image':None,'mounts':[],
                'daemon':self.daemon,'runroot':None,'created_at':controls.now()}
        self.write(record);return record

    @diagnostics.scoped('network_cleanup')
    def remove_network(self,record):
        with diagnostics.operation('network_inspect'):
            reply=self.command(['docker','network','inspect',record['container']])
        if reply.returncode:
            if not network_absent(reply,record['container']):raise RegistryError('Owned network absence uncertain', condition='network_cleanup_failed')
        else:
            data=json.loads(reply.stdout)[0];labels=data.get('Labels') or {}
            if labels.get(LABEL)!=record['launch_id'] or labels.get(REGISTRY_LABEL)!=self.registry_id or data.get('Driver')!='bridge' or data.get('Containers'):
                raise RegistryError('Network ownership or quiescence does not match', condition='ownership_mismatch')
            with diagnostics.operation('network_remove',mutating=True):
                removed=self.command(['docker','network','rm',record['container']])
            if removed.returncode:raise RegistryError('Owned network cleanup failed',condition='network_cleanup_failed')
            with diagnostics.operation('network_inspect'):
                absent=self.command(['docker','network','inspect',record['container']])
            if not network_absent(absent,record['container']):raise RegistryError('Owned network absence uncertain', condition='network_cleanup_failed')
        record['status']='absent';self.write(record)

    def builder_intent(self,name,image):
        record={'schema':SCHEMA,'launch_id':str(uuid.uuid4()),'generation':self.generation,'registry':self.registry_id,
                'kind':'builder','status':'intent','container':'buildx_buildkit_'+name+'0','image':image,'mounts':[],
                'daemon':self.daemon,'runroot':None,'created_at':controls.now()}
        self.write(record);return record
