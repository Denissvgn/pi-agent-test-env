"""Owner-private inference catalog and source-specific, offline authorization.

No method here contacts a provider, runs a child, or prints credential material.
"""
import contextlib
import copy
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
import uuid

import indexed_contract as contract
from indexed_contract import IndexedError
import lab_env
import ownership_registry
import secret_store


def default_root():
    return Path(os.environ.get('PI_LAB_CATALOG_DIR') or lab_env.config_dir().parent/'inference-catalog').expanduser()


def secure_directory(path):
    path=Path(path).expanduser().absolute()
    if path.is_symlink():raise IndexedError('catalog-insecure')
    path=path.parent.resolve()/path.name
    path.mkdir(mode=0o700,parents=True,exist_ok=True)
    st=path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)&0o077:
        raise IndexedError('catalog-insecure')
    return path


def read(path,default=None):
    try:return ownership_registry.read_private(path)
    except FileNotFoundError:return copy.deepcopy(default)
    except (OSError,ValueError,TypeError,RecursionError):raise IndexedError('catalog-insecure') from None


def atomic(path,value):
    raw=json.dumps(value,sort_keys=True,ensure_ascii=True,separators=(',',':')).encode()
    if len(raw)>contract.MAX_BYTES:raise IndexedError()
    if path.exists() or path.is_symlink():read(path)
    temporary=path.with_name('.'+path.name+'-'+uuid.uuid4().hex)
    try:
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
        os.replace(temporary,path)
        fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if temporary.exists():temporary.unlink()


class Catalog:
    def __init__(self,normalize,root=None,store=None):
        self.normalize=normalize;self.root=secure_directory(root or default_root())
        self.store=(Path(store) if store is not None else secret_store.default_store()).expanduser().absolute()

    @contextlib.contextmanager
    def locked(self):
        secure_directory(self.root)
        allowed={'catalog.json','approvals.json','authority.json','catalog.lock'}
        path=self.root/'catalog.lock'
        fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
        try:
            st=os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)&0o077:
                raise IndexedError('catalog-insecure')
            deadline=time.monotonic()+15
            while True:
                try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);break
                except BlockingIOError:
                    if time.monotonic()>=deadline:raise IndexedError('catalog-insecure')
                    time.sleep(.01)
            # A live writer may own a temporary file until replacement completes.
            # Inspect inventory only after acquiring its lock.
            for candidate in self.root.iterdir():
                if candidate.name not in allowed:raise IndexedError('catalog-insecure')
            # Check committed sensitive files even when this operation only lists.
            for name in allowed-{'catalog.lock'}:
                if (self.root/name).exists() or (self.root/name).is_symlink():read(self.root/name)
            yield
        except OSError:raise IndexedError('catalog-insecure') from None
        finally:fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)

    def _load(self):
        value=read(self.root/'catalog.json',{'schema':1,'revision':1,'default_id':None,'entries':[],'tombstones':[]})
        try:return contract.catalog(value,self.normalize)
        except (ValueError,TypeError,KeyError,RecursionError):raise IndexedError() from None

    def _selected(self,document,identifier):
        contract.identifier(identifier)
        found=next((e for e in document['entries'] if e['id']==identifier),None)
        if found is None:raise IndexedError('environment-not-found')
        return found

    def outside(self,*forbidden):
        for location in (self.root,self.store.resolve()):
            for boundary in forbidden:
                if boundary is None:continue
                boundary=Path(boundary).resolve()
                if location==boundary or boundary in location.parents or location in boundary.parents:
                    raise IndexedError('catalog-insecure')

    def availability(self,config):
        source=config['credential']
        if source['source']=='none':return 'not_required'
        if source['source']=='env':return 'present' if source['name'] in os.environ else 'missing'
        path=secret_store.secret_path(source['name'],self.store)
        try:
            parent=self.store.lstat()
            if not stat.S_ISDIR(parent.st_mode) or self.store.is_symlink() or parent.st_uid!=os.getuid() or stat.S_IMODE(parent.st_mode)&0o077:return 'insecure'
            st=path.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)&0o077:return 'insecure'
            return 'present'
        except FileNotFoundError:return 'missing'
        except OSError:return 'unknown'

    def list(self):
        with self.locked():
            document=self._load()
            return {'schema':1,'catalog_revision':document['revision'],'default_id':document['default_id'],
                'entries':[{'index':i+1,'id':e['id'],'revision':e['revision'],'api':contract.API,
                    'adapter_contract':contract.ADAPTER,'credential_availability':self.availability(e['configuration']),
                    'capabilities':{'adapter':'reviewed','tool_use':'not_qualified','image_input':'not_qualified','deployment_capacity':'unknown'}}
                    for i,e in enumerate(document['entries'])],'offline':True}

    def select(self,identifier=None,index=None,revision=None):
        with self.locked():
            document=self._load()
            if identifier is not None and index is not None:raise IndexedError('selection-conflict')
            if index is not None:
                if type(index) is not int or not 1<=index<=len(document['entries']) or revision!=document['revision']:
                    raise IndexedError('environment-index-stale')
                identifier=document['entries'][index-1]['id']
            if identifier is None:raise IndexedError('selection-conflict')
            return copy.deepcopy(self._selected(document,identifier))

    def inspect(self,identifier,private=False):
        entry=self.select(identifier);value={'id':entry['id'],'revision':entry['revision'],'api':contract.API,
            'adapter_contract':contract.ADAPTER,'credential_availability':self.availability(entry['configuration']),'offline':True}
        if private:value.update(incarnation=entry['incarnation'],configuration=entry['configuration'],fingerprint=entry['fingerprint'],private=True)
        return value

    def register(self,identifier,config,expected_revision=None,default=False):
        identifier=contract.identifier(identifier);normalized=contract.configuration(config,self.normalize)
        if expected_revision is not None:contract.integer(expected_revision)
        with self.locked():
            document=self._load();old=next((e for e in document['entries'] if e['id']==identifier),None)
            if old is not None:
                if expected_revision!=old['revision']:raise IndexedError('environment-configuration-changed')
                incarnation=old['incarnation'];revision=old['revision']+1
            else:
                if expected_revision is not None:raise IndexedError('environment-not-found')
                incarnation=str(uuid.uuid4());revision=1
            e={'id':identifier,'incarnation':incarnation,'revision':revision,'configuration':normalized,'fingerprint':contract.digest(normalized)}
            if old is not None:document['entries'][document['entries'].index(old)]=e
            else:document['entries'].append(e)
            if default:document['default_id']=identifier
            document['revision']+=1;contract.catalog(document,self.normalize);atomic(self.root/'catalog.json',document)
            return {'id':identifier,'revision':revision,'catalog_revision':document['revision'],'offline':True}

    def revoke(self,identifier,expected_revision):
        contract.integer(expected_revision)
        with self.locked():
            document=self._load();entry=self._selected(document,identifier)
            if expected_revision!=entry['revision']:raise IndexedError('environment-configuration-changed')
            document['entries'].remove(entry);document['tombstones'].append({k:entry[k] for k in ('id','incarnation','revision')})
            if document['default_id']==identifier:document['default_id']=None
            document['revision']+=1;contract.catalog(document,self.normalize);atomic(self.root/'catalog.json',document)
            return {'id':identifier,'revoked':True,'offline':True}

    def _secret(self,config):
        source=config['credential']
        if source['source']=='none':return ''
        try:
            if source['source']=='store':
                st=self.store.lstat()
                if not stat.S_ISDIR(st.st_mode) or self.store.is_symlink() or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)&0o077:
                    raise IndexedError('credential-unavailable')
                fd=os.open(secret_store.secret_path(source['name'],self.store),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                with os.fdopen(fd,'rb') as f:
                    st=os.fstat(f.fileno())
                    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)&0o077 or st.st_size>secret_store.MAX_LEN*4:
                        raise IndexedError('credential-unavailable')
                    value=f.read(secret_store.MAX_LEN*4+1).decode('utf-8')
            else:value=os.environ.get(source['name'],'')
            if not value:raise IndexedError('credential-unavailable')
            return secret_store.clean_value(value)
        except (secret_store.SecretError,OSError,UnicodeError):raise IndexedError('credential-unavailable') from None

    def _authority_key(self,create=False):
        path=self.root/'authority.json';record=read(path)
        if record is None:
            if not create:raise IndexedError('environment-unconfirmed')
            record={'schema':1,'key':secrets.token_hex(32)};atomic(path,record)
        if not isinstance(record,dict) or set(record)!= {'schema','key'} or record['schema']!=1 or not isinstance(record['key'],str) or not re.fullmatch(r'[a-f0-9]{64}',record['key']):raise IndexedError('catalog-insecure')
        return bytes.fromhex(record['key'])

    def _approvals(self):
        record=read(self.root/'approvals.json',{'schema':1,'sessions':{}})
        if not isinstance(record,dict) or set(record)!= {'schema','sessions'} or type(record['schema']) is not int or record['schema']!=1 or not isinstance(record['sessions'],dict) or len(record['sessions'])>128:raise IndexedError('catalog-insecure')
        for session,bindings in record['sessions'].items():
            if not isinstance(session,str) or not lab_env.SESSION_RE.fullmatch(session) or not isinstance(bindings,dict) or len(bindings)>32:raise IndexedError('catalog-insecure')
            for incarnation,value in bindings.items():
                contract.identity(incarnation);contract.fields(value,('fingerprint','authority_id','tag','confirmed_at'))
                contract.identity(value['authority_id']);contract.integer(value['confirmed_at'])
                if any(not isinstance(value[k],str) or not re.fullmatch(r'[a-f0-9]{64}',value[k]) for k in ('fingerprint','tag')):raise IndexedError('catalog-insecure')
        return record

    def _tag(self,entry,value,key):
        source=entry['configuration']['credential']
        body=json.dumps({'source':source,'location':str(self.store.resolve()) if source['source']=='store' else None,'value':value},sort_keys=True).encode()
        return hmac.new(key,body,hashlib.sha256).hexdigest()

    def confirm(self,identifier,session):
        session=lab_env.resolve_session(session)
        with self.locked():
            e=self._selected(self._load(),identifier);secret=self._secret(e['configuration']);contract.secret_free(e,[secret]);record=self._approvals()
            bindings=record['sessions'].setdefault(session,{})
            existing=bindings.get(e['incarnation']);tag=self._tag(e,secret,self._authority_key(create=True))
            if (not existing or existing.get('fingerprint')!=e['fingerprint'] or existing.get('tag')!=tag):
                bindings[e['incarnation']]={'fingerprint':e['fingerprint'],'authority_id':str(uuid.uuid4()),'tag':tag,'confirmed_at':int(time.time())}
            else:
                existing['confirmed_at']=int(time.time())
            atomic(self.root/'approvals.json',record)
            return {'id':identifier,'confirmed':True,'offline':True}

    def _admit(self,entry,session):
        current=next((e for e in self._load()['entries'] if e['incarnation']==entry['incarnation']),None)
        if current is None:raise IndexedError('environment-revoked')
        if current['fingerprint']!=entry['fingerprint']:raise IndexedError('environment-configuration-changed')
        approval=self._approvals()['sessions'].get(lab_env.resolve_session(session),{}).get(entry['incarnation'])
        if approval is None:raise IndexedError('environment-unconfirmed')
        if time.time()-approval['confirmed_at']>lab_env.SESSION_TTL_SECONDS:raise IndexedError('environment-unconfirmed')
        if approval.get('fingerprint')!=entry['fingerprint']:raise IndexedError('environment-configuration-changed')
        secret=self._secret(current['configuration'])
        contract.secret_free(current,[secret])
        if not hmac.compare_digest(approval.get('tag',''),self._tag(current,secret,self._authority_key())):
            raise IndexedError('inference-authority-changed')
        return secret,approval['authority_id']

    def freeze(self,identifier,session):
        with self.locked():
            e=self._selected(self._load(),identifier);unused,authority=self._admit(e,session)
            return {**e,'authority_id':authority}

    def admit(self,binding,session):
        selected=copy.deepcopy(binding);authority=selected.pop('authority_id',None)
        contract.entry(selected,self.normalize);contract.identity(authority)
        with self.locked():
            secret,current=self._admit(selected,session)
            if current!=authority:raise IndexedError('inference-authority-changed')
            return secret

    def status(self,identifier,session):
        try:self.freeze(identifier,session);return {'id':identifier,'state':'ready','offline':True,'health':'not_checked'}
        except IndexedError as exc:return {'id':identifier,'state':'blocked','offline':True,**exc.public()}


def command(args):
    import pi_lab
    try:
        catalog=Catalog(pi_lab.normalize_endpoint,getattr(args,'catalog_dir',None),getattr(args,'secrets_dir',None))
        op=args.env_op;identifier=getattr(args,'id',None)
        if op=='list':value=catalog.list()
        elif op=='inspect':
            selected=catalog.select(identifier,getattr(args,'index',None),getattr(args,'catalog_revision',None))
            value=catalog.inspect(selected['id'],getattr(args,'private',False))
        elif op in ('register','update'):
            path=Path(args.config)
            if path.is_symlink() or not path.is_file() or path.stat().st_size>contract.MAX_BYTES:raise IndexedError()
            value=catalog.register(identifier,json.loads(path.read_text()),getattr(args,'expected_revision',None),getattr(args,'default',False))
        elif op in ('delete','revoke'):value=catalog.revoke(identifier,args.expected_revision)
        elif op=='confirm':value=catalog.confirm(identifier,args.session)
        elif op=='status':value=catalog.status(identifier,args.session)
        elif op=='check':
            import indexed_broker
            value=indexed_broker.health(args,catalog)
        else:raise IndexedError()
        print(json.dumps(value,indent=2));return 0 if value.get('state')!='blocked' else 2
    except (IndexedError,OSError,ValueError,TypeError,ImportError) as exc:
        error=exc if isinstance(exc,IndexedError) else IndexedError()
        print(json.dumps({'state':'blocked',**error.public()}));return 2
