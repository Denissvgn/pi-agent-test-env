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
import uuid

import stage_control as controls

CURRENT=contextvars.ContextVar('pi_owned_admission',default=None)
SCHEMA=1
LABEL='org.pi-agent-test-env.launch'
REGISTRY_LABEL='org.pi-agent-test-env.registry'


class RegistryError(ValueError):
    reason='host-registry-unsafe'


def private_directory(path):
    path=Path(path).absolute()
    # No lexical alias may select another registry. Parent directories can be
    # shared (e.g. /tmp), but the registry itself is always owner-only.
    if path.is_symlink():raise RegistryError('Registry path aliases another location')
    path=path.parent.resolve()/path.name
    path.mkdir(mode=0o700,parents=True,exist_ok=True)
    st=path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)&0o077:
        raise RegistryError('Registry directory is not owner-only')
    return path


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
                raise RegistryError('Registry record is insecure or unbounded')
            return json.load(f) if decode else None
    raise RegistryError('Registry record changed during bounded observation')


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


class Registry:
    def __init__(self,path,command=docker,recover_sensitive=None):
        self.root=private_directory(path);self.command=command
        self.generation=str(uuid.uuid4());self.registry_id=hashlib.sha256(str(self.root).encode()).hexdigest()
        self.recover_sensitive=recover_sensitive;self.runroot=None;self.binding={};self.daemon=None

    def load(self,observe=False):
        records=[]
        paths=list(self.root.iterdir())
        if len(paths)>4096:raise RegistryError('Registry inventory exceeds its bounded limit')
        for path in paths:
            if observe and re.fullmatch(r'\.[a-f0-9-]{36}\.json-[a-f0-9]{32}',path.name):
                # An observation sees only committed records. Admission remains
                # strict: an abandoned temporary entry still blocks dispatch.
                try:read_private(path,decode=False)
                except FileNotFoundError:pass # atomic replace consumed this temporary name
                continue
            if not re.fullmatch(r'[a-f0-9-]{36}\.json',path.name):raise RegistryError('Unknown registry entry')
            record=read_private(path)
            if (not isinstance(record,dict) or type(record.get('schema')) is not int or record.get('schema') not in (1,2)
                or not controls.valid_id(record.get('launch_id')) or path.stem!=record['launch_id']
                or record.get('registry')!=self.registry_id or not controls.valid_id(record.get('generation'))
                or record.get('status') not in ('intent','running','absent','released','quarantined')
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}',record.get('container',''))
                or (record.get('kind','container')!='network' and not re.fullmatch(r'sha256:[a-f0-9]{64}',record.get('image','')))
                or record.get('kind','container') not in ('container','network','builder')
                or not isinstance(record.get('mounts'),list)):
                raise RegistryError('Malformed launch registry')
            if record['schema']==2 and (not isinstance(record.get('binding'),dict) or type(record['binding'].get('indexed_host_generation')) is not int or record['binding']['indexed_host_generation']!=2):raise RegistryError('Invalid indexed registry generation')
            if any(not isinstance(m,dict) or set(m)!={'source','target','rw'} or not isinstance(m['source'],str) or not Path(m['source']).is_absolute() or not isinstance(m['target'],str) or not m['target'].startswith('/') or type(m['rw']) is not bool for m in record['mounts']):
                raise RegistryError('Malformed ownership mount bindings')
            records.append(record)
        return records

    def write(self,record):
        controls.atomic(self.root/(record['launch_id']+'.json'),record)
        fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)

    def reconcile(self):
        pending=[r for r in self.load() if r['status']!='released']
        if not pending:return []
        if any(r.get('daemon') for r in pending):
            observed=self.command(['docker','info','--format','{{.ID}}'])
            if observed.returncode or any(r.get('daemon')!=observed.stdout.strip() for r in pending):
                raise RegistryError('Daemon identity changed or cannot be observed')
        # An owner died: recover every writer before touching sensitive files.
        for record in pending:
            if record.get('inference_uncertain'):raise RegistryError('Upstream request termination remains uncertain')
            if record.get('gateway_state') and record.get('gateway_ready'):
                import time
                deadline=time.monotonic()+35
                while True:
                    value=read_private(record['gateway_state'])
                    if value.get('launch_id')!=record['launch_id'] or value.get('uncertain'):raise RegistryError('Gateway inference termination uncertain')
                    if value.get('inflight')==0 and value.get('pending')==0:break
                    if time.monotonic()>=deadline:raise RegistryError('Gateway still owns an upstream request')
                    time.sleep(.1)
            if record.get('kind')=='network':continue
            reply=self.command(['docker','container','inspect',record['container']])
            if not absent(reply):
                if reply.returncode:raise RegistryError('Writer absence cannot be established')
                try:data=json.loads(reply.stdout)[0]
                except (ValueError,KeyError,IndexError):raise RegistryError('Invalid writer inspection') from None
                labels=data.get('Config',{}).get('Labels') or {}
                mounts=data.get('Mounts') or []
                expected={LABEL:record['launch_id'],REGISTRY_LABEL:self.registry_id}
                label_match=all(labels.get(k)==v for k,v in expected.items())
                if record.get('kind')=='builder':label_match=bool(record.get('container_id')) and data.get('Id')==record['container_id']
                if (data.get('Image')!=record['image'] or not label_match
                    or any(not any(m.get('Source')==e['source'] and m.get('Destination')==e['target'] and m.get('RW')==e['rw'] for m in mounts) for e in record['mounts'])):
                    record['status']='quarantined';self.write(record)
                    raise RegistryError('Container ownership does not match persisted intent')
                removed=self.command(['docker','rm','--force',record['container']])
                if removed.returncode:raise RegistryError('Owned writer cleanup failed')
                if not absent(self.command(['docker','container','inspect',record['container']])):
                    raise RegistryError('Owned writer absence is unconfirmed')
            record['status']='absent';self.write(record)
        for record in pending:
            if record.get('kind')=='network':self.remove_network(record)
        for runroot in {r.get('runroot') for r in pending if r.get('runroot')}:
            path=Path(runroot)
            if not path.is_absolute() or path.is_symlink():raise RegistryError('Unsafe sensitive recovery root')
            if self.recover_sensitive is None:
                import application_credentials
                application_credentials.recover(path)
            else:self.recover_sensitive(path)
        for record in pending:
            if record.get('private_store'):
                import shutil
                path=Path(record['private_store'])
                if path.is_symlink() or path.parent.resolve()!=Path(__import__('tempfile').gettempdir()).resolve() or not path.name.startswith('pi-parallel-gateway-'):
                    raise RegistryError('Unsafe gateway private-store cleanup path')
                if path.exists():shutil.rmtree(path)
            record['status']='released';self.write(record)
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
        reply=self.command(['docker','container','inspect',record['container']])
        confirmed=absent(reply)
        record['status']='absent' if confirmed else 'quarantined';self.write(record)
        return confirmed

    def release(self,record,sensitive_clean):
        if record['status']!='absent' or sensitive_clean is not True:
            record['status']='quarantined';self.write(record);raise RegistryError('Sensitive or physical cleanup remains uncertain')
        record['status']='released';self.write(record)

    def close(self):
        current=[r for r in self.load() if r['generation']==self.generation and r['status']!='released']
        for root in {r['runroot'] for r in current if r['runroot']}:
            for receipt in (Path(root)/'stages').glob('*/application-credentials.json'):
                if controls.read(receipt).get('status')!='removed':
                    raise RegistryError('Sensitive state has not been purged')
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

    def remove_network(self,record):
        reply=self.command(['docker','network','inspect',record['container']])
        if reply.returncode:
            if not network_absent(reply,record['container']):raise RegistryError('Owned network absence uncertain')
        else:
            data=json.loads(reply.stdout)[0];labels=data.get('Labels') or {}
            if labels.get(LABEL)!=record['launch_id'] or labels.get(REGISTRY_LABEL)!=self.registry_id or data.get('Driver')!='bridge' or data.get('Containers'):
                raise RegistryError('Network ownership or quiescence does not match')
            removed=self.command(['docker','network','rm',record['container']])
            if removed.returncode:raise RegistryError('Owned network cleanup failed')
            absent=self.command(['docker','network','inspect',record['container']])
            if not network_absent(absent,record['container']):raise RegistryError('Owned network absence uncertain')
        record['status']='absent';self.write(record)

    def builder_intent(self,name,image):
        record={'schema':SCHEMA,'launch_id':str(uuid.uuid4()),'generation':self.generation,'registry':self.registry_id,
                'kind':'builder','status':'intent','container':'buildx_buildkit_'+name+'0','image':image,'mounts':[],
                'daemon':self.daemon,'runroot':None,'created_at':controls.now()}
        self.write(record);return record
