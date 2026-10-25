"""Inert-only proposal controls. Root is the sole test executor.

All owner/reference/control fixtures are built synthetically in each disposable directory. Every opened
operational file is generated in TemporaryDirectory. No original .local record,
protected proof, SDK result/log/control, PID, Docker or lease is accessed.
Custody tests deliberately replace ONLY proof-header hooks with inert assertions;
they do not establish original SDK semantic validation or native qualification.
"""
import ast
import contextvars
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock
import uuid

HERE=Path(__file__).parent
SOURCE=next((parent/'tools/qualification/application_sdk_admission.py' for parent in HERE.parents if (parent/'tools/qualification/application_sdk_admission.py').is_file()),HERE/'application_sdk_admission-007.py')
SOURCE_BYTES=SOURCE.read_bytes()

PURE_AUTHORITY_SOURCE_SHA256 = {
    'skill/scripts/application_contracts.py':'e88d6d7ad0d6bd63ae2a86205bba025c20cc7a658861e78883c7840b3eae2e38',
    'skill/scripts/application_credentials.py':'3e35239aefbfee5433bb208a0928ed668a6b7daa5daca999b2feac4306b0ec11',
    'skill/scripts/parallel_application.py':'1f839d838d806d59ab3c040485a522ea4df63db5cc7f29a477244451719398b2',
    'skill/scripts/application_client.py':'3d949abdbc90b3943c1525ab4225e4fc708d4de24747ff1af8fdb2c5b4992cf8',
    'skill/scripts/native_budget_client.py':'7dece396f84b5bf4273507d0633e5683dec4d942a06f0c0b60c74c62df413577',
}


# Exact Source039 _profile method fixture; normalized AST is pinned below.
# This source string is portable in extracted archives and reads no reports.
SOURCE039_PROFILE_CODE = "def _profile(self, value):\n    if value.get('application_helper') is not True:\n        require(value['launch_id'] not in self.profiles, 'known_owner_subtype_changed')\n        return 'ordinary'\n    subtype = 'preworker' if 'qualification_preworker_cleanup' in value else 'service' if str(value.get('client_mode', '')).startswith('qualification-') or 'qualification_role' in value or 'qualification_service_cleanup' in value else 'ordinary_helper'\n    if subtype in ('service', 'preworker'):\n        profile = self.profiles.get(value['launch_id'])\n        field = 'qualification_' + ('preworker' if subtype == 'preworker' else 'service') + '_cleanup'\n        require(profile is not None and profile['subtype'] == subtype and (value.get(field) == profile['reference']), 'unknown_qualification_reference')\n        if subtype == 'service':\n            require([m for m in value['mounts'] if m['target'] == '/private'] == [{'source': profile['private_mount_source'], 'target': '/private', 'rw': False}], 'service_private_scope_changed')\n    else:\n        require(value['launch_id'] not in self.profiles, 'known_owner_subtype_changed')\n    return subtype\n"
SOURCE039_PROFILE_AST_SHA256 = '5a67f5a259cbeb3e59420753ad0ced7aafae382f4d0d62a8b7bb4951ab2a2780'

# Exact Source040 reporting method; portable old-type/args comparator only.
SOURCE040_PROFILE_CODE = "def _profile(self, value):\n    if value.get('application_helper') is not True:\n        require(value['launch_id'] not in self.profiles, 'known_owner_subtype_changed')\n        return 'ordinary'\n    subtype = 'preworker' if 'qualification_preworker_cleanup' in value else 'service' if str(value.get('client_mode', '')).startswith('qualification-') or 'qualification_role' in value or 'qualification_service_cleanup' in value else 'ordinary_helper'\n    if subtype in ('service', 'preworker'):\n        profile = self.profiles.get(value['launch_id'])\n        field = 'qualification_' + ('preworker' if subtype == 'preworker' else 'service') + '_cleanup'\n        if profile is None:\n            if value['launch_id'] in self.policy['selected_task_records']:\n                require(False, 'qualification_owner_missing_selected')\n            require(False, 'qualification_owner_missing_outside_selected')\n        require(profile['subtype'] == subtype, 'qualification_owner_subtype_mismatch')\n        require(field in value, 'qualification_cleanup_reference_missing')\n        require(value[field]['path'] == profile['reference']['path'], 'qualification_cleanup_path_mismatch')\n        require(value[field]['sha256'] == profile['reference']['sha256'], 'qualification_cleanup_digest_mismatch')\n        if subtype == 'service':\n            require([m for m in value['mounts'] if m['target'] == '/private'] == [{'source': profile['private_mount_source'], 'target': '/private', 'rw': False}], 'service_private_scope_changed')\n    else:\n        require(value['launch_id'] not in self.profiles, 'known_owner_subtype_changed')\n    return subtype\n"
SOURCE040_PROFILE_AST_SHA256 = '947e8d7d0d92d67a1ce5ec6150f281c61c5c06323777fc43d1b43ceee54dadb8'

# Exact Source041 caller fixture; no report/source preimage is read at test runtime.
SOURCE041_CALL_CODE = "def __call__(self, *, lease_fd, lock_path, registry_root):\n    require(not self._called, 'preflight_already_used')\n    self._called = True\n    require(Path(lock_path) == self.lock_path and Path(registry_root) == self.registry_root and (type(lease_fd) is int), 'callback_not_original_context')\n    self._begin()\n    lease_identity = self._lease(lease_fd)\n    fd = self._directory(self.registry_root)\n    total = self._initial_bytes\n    signatures = {}\n    kinds = {}\n    owners = set()\n    try:\n        ri = self._registry(fd)\n        namespace_signature = signature(ri)\n        require(ri.st_uid == os.getuid() and stat.S_IMODE(ri.st_mode) == 448, 'registry_not_owner_only')\n        names = self._names(fd)\n        for key, expected in sorted(self.expected.items()):\n            self._lease(lease_fd)\n            self._registry(fd)\n            maximum = min(1048576, 33554432 - total)\n            require(maximum > 0, 'aggregate_metadata_limit')\n            leaf = os.open(key + '.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)\n            with os.fdopen(leaf, 'rb', buffering=0) as stream:\n                info = os.fstat(stream.fileno())\n                require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and (stat.S_IMODE(info.st_mode) == 384) and (info.st_nlink == 1) and (0 <= info.st_size <= maximum), 'metadata_leaf_not_classified')\n                self._fence()\n                body = stream.read(info.st_size)\n                after = os.fstat(stream.fileno())\n            named = os.stat(key + '.json', dir_fd=fd, follow_symlinks=False)\n            require(signature(info) == signature(after) == signature(named) and len(body) == info.st_size, 'metadata_changed')\n            total += len(body)\n            self._registry(fd)\n            value = decode(body)\n            self._shape(value, key)\n            require(digest(value) == expected, 'canonical_record_changed')\n            kind = self._profile(value)\n            kinds[kind] = kinds.get(kind, 0) + 1\n            if kind in ('service', 'preworker'):\n                owners.add(key)\n            signatures[key] = signature(info)\n        require(owners == set(self.profiles), 'qualification_owner_set_changed')\n        proof_snapshots, proof_bytes = self._proof_headers()\n        self._final_records(fd, signatures)\n        self._proof_conservation(proof_snapshots)\n        require(self._names(fd) == names, 'registry_namespace_changed')\n        require(signature(self._registry(fd)) == namespace_signature, 'registry_directory_drift')\n        require(8192 - len(names) >= 210, 'insufficient_original_registry_headroom')\n        self._lease(lease_fd)\n        self._registry(fd)\n        self._fence()\n        self._snapshots = signatures\n        self._proof_snapshots = proof_snapshots\n        self.witness = {'schema': 1, 'document_type': 'original_lease_sdk_preflight_witness', 'lease_fd': lease_fd, 'lease_device': lease_identity[0], 'lease_inode': lease_identity[1], 'registry_root': str(self.registry_root), 'registry_device': ri.st_dev, 'registry_inode': ri.st_ino, 'namespace_sha256': digest(names), 'canonical_map_sha256': digest(self.expected), 'selected281_sha256': digest({k: self.expected[k] for k in sorted(self.policy['selected_task_records'])}), 'readset_seal': digest(self.closure), 'records': len(names), 'record_bytes': total, 'subtype_counts': kinds, 'headroom': 8192 - len(names), 'proof_header_bytes_with_multiplicity': proof_bytes, 'original_reconcile_claimed': False, 'native_eligibility_claimed': False}\n    finally:\n        os.close(fd)\n"
SOURCE041_CALL_AST_SHA256 = 'ac06cc4aa6f6aac8405da23451c1aeb9b48f8847940a5c12cf5555e2b0558a57'


def authority_pure_call(function,*args,**kwargs):
    # The only bodies supplied below are exact selected public pure APIs and
    # the pure SDK shape check. No store resolution or producer constructor runs.
    with mock.patch('os.open',side_effect=forbidden),mock.patch('os.stat',side_effect=forbidden), \
         mock.patch('os.lstat',side_effect=forbidden),mock.patch('os.kill',side_effect=forbidden), \
         mock.patch('subprocess.Popen',side_effect=forbidden),mock.patch('socket.socket',side_effect=forbidden), \
         mock.patch.object(M,'digest',side_effect=forbidden):
        return function(*args,**kwargs)


def pure_authority_subset(relative,*,functions=(),classes=(),methods=None,bindings=None):
    assert relative in PURE_AUTHORITY_SOURCE_SHA256
    source=next(parent/relative for parent in HERE.parents if (parent/relative).is_file())
    body=source.read_bytes();assert hashlib.sha256(body).hexdigest()==PURE_AUTHORITY_SOURCE_SHA256[relative]
    nodes=[];found=set();methods=methods or {}
    for node in ast.parse(body,filename=str(source)).body:
        if isinstance(node,ast.FunctionDef) and node.name in functions:
            nodes.append(copy.deepcopy(node));found.add(node.name)
        elif isinstance(node,ast.ClassDef) and node.name in classes:
            nodes.append(copy.deepcopy(node));found.add(node.name)
        elif isinstance(node,ast.ClassDef) and node.name in methods:
            # Keep exact method ASTs while omitting effectful constructors and
            # unrelated methods. These three source classes have no bases.
            assert not node.bases and not node.keywords and not node.decorator_list
            selected=copy.deepcopy(node);selected.body=[copy.deepcopy(item)for item in node.body
                if isinstance(item,ast.FunctionDef)and item.name in methods[node.name]]
            assert {item.name for item in selected.body}==set(methods[node.name])
            nodes.append(selected);found.add(node.name)
    assert found==set(functions)|set(classes)|set(methods)
    subject=types.ModuleType('_pure_authority_public_fixture');subject.__file__=str(source)
    subject.__dict__.update(copy=copy,hashlib=hashlib,json=json,math=math,re=re)
    subject.__dict__.update(bindings or {})
    authority_pure_call(exec,compile(ast.Module(body=nodes,type_ignores=[]),str(source),'exec'),subject.__dict__)
    return subject

def forbidden(*args,**kwargs):
    raise AssertionError('inert_entry_effect_forbidden')

# These controls are in place BEFORE executing the subject's module body.
M=types.ModuleType('sdk_admission_inert_subject');M.__file__=str(SOURCE)
with mock.patch('os.open',side_effect=forbidden),mock.patch('os.kill',side_effect=forbidden), \
     mock.patch('subprocess.Popen',side_effect=forbidden),mock.patch('socket.socket',side_effect=forbidden):
    exec(compile(SOURCE_BYTES,str(SOURCE),'exec'),M.__dict__)

def source039_profile_comparator():
    tree=ast.parse(SOURCE039_PROFILE_CODE)
    assert len(tree.body)==1 and isinstance(tree.body[0],ast.FunctionDef)
    assert hashlib.sha256(ast.dump(tree.body[0],include_attributes=False).encode()).hexdigest()==SOURCE039_PROFILE_AST_SHA256
    subject={'require':M.require}
    authority_pure_call(exec,compile(tree,'<frozen-source039-profile>','exec'),subject)
    return subject['_profile']


def source040_profile_comparator():
    tree=ast.parse(SOURCE040_PROFILE_CODE)
    assert len(tree.body)==1 and isinstance(tree.body[0],ast.FunctionDef)
    assert hashlib.sha256(ast.dump(tree.body[0],include_attributes=False).encode()).hexdigest()==SOURCE040_PROFILE_AST_SHA256
    subject={'require':M.require}
    authority_pure_call(exec,compile(tree,'<frozen-source040-profile>','exec'),subject)
    return subject['_profile']


def source041_call_comparator():
    tree=ast.parse(SOURCE041_CALL_CODE)
    assert len(tree.body)==1 and isinstance(tree.body[0],ast.FunctionDef)
    assert hashlib.sha256(ast.dump(tree.body[0],include_attributes=False).encode()).hexdigest()==SOURCE041_CALL_AST_SHA256
    subject={name:getattr(M,name)for name in ('require','Path','os','stat','signature','decode','digest')}
    authority_pure_call(exec,compile(tree,'<frozen-source041-call>','exec'),subject)
    return subject['__call__']


def synthetic_template(base):
    evidence=base/'synthetic-proof-headers';evidence.mkdir(mode=0o700)
    def ref(path,body=b'{}'):
        path.parent.mkdir(parents=True,exist_ok=True);path.parent.chmod(0o700);path.write_bytes(body);path.chmod(0o600)
        return {'path':str(path),'sha256':hashlib.sha256(body).hexdigest()}
    preworker=str(uuid.uuid4());owners={};service_ids=[]
    for index in range(55):
        key=str(uuid.uuid4());service_ids.append(key)
        owners[key]={'subtype':'service','reference':ref(evidence/'services'/(key+'.json')),
            'private_mount_source':str(base/'absent-service-private'/key)}
    ownerref=ref(evidence/'preworker.json');owners[preworker]={'subtype':'preworker','reference':ownerref}
    control=evidence/'control';control.mkdir(mode=0o700)
    segment=str(uuid.uuid4());directories=['inbox','segments','segments/'+segment]
    for relative in directories:(control/relative).mkdir(parents=True,exist_ok=True,mode=0o700)
    retained=[]
    for name,size in (('endpoint.json',236),('stage.json',1883),('task.json',15368)):
        item=ref(control/name,b' '*size);retained.append({**item,'path':name,'bytes':size})
    ci=control.stat()
    lineage=[]
    for index in range(2):
        root=evidence/('lineage-'+str(index));lineage.append({'root':str(root),
            'manifest':ref(root/'manifest.json'),'state':ref(root/'state.json'),
            'ledger':ref(root/'launch-ledger/ledger.json')})
    projection={'schema':1,'source_reference':ownerref,'owner':{'launch_id':preworker},
        'qualification':{'lineage':lineage},'stage':{k:ref(evidence/'stage'/(k+'.json'))for k in ('descriptor','state','process','result')},
        'controller':{k:ref(evidence/'controller'/(k+'.json'))for k in ('parent_terminal','original_invocation')},
        'private_cleanup':{'helper':{'source':str(base/'absent-helper')},
            'parent_bootstrap':{'path':str(base/'absent-bootstrap')},'workspace':{'path':str(base/'absent-workspace')},
            'control':{'path':str(control),'device':ci.st_dev,'inode':ci.st_ino,'directories':directories,
                'retained_files':retained}},'launches':[{'launch_id':k}for k in service_ids[:19]],
        'service_receipts':[owners[k]['reference']for k in service_ids[:3]]}
    return {'schema':1,'document_type':'qualification_sdk_admission_policy',
        'lock_path':str(base/'unbound.lock'),'registry_root':str(base/'unbound.lock.registry'),
        'expected_canonical_records':{},'selected_task_records':[],'base_qualification_owners':copy.deepcopy(owners),
        'qualification_owners':copy.deepcopy(owners),'preworker_projection':projection,
        'limits':{'seconds':120,'per_record_bytes':1048576,'aggregate_record_bytes':33554432,
            'maximum_committed_records':8192,'minimum_headroom':210},
        'proof_limits':{'base_unique_files':71,'maximum_unique_files':127,'aggregate_maximum_bytes':67108864},
        'activation':None,'admission_budget':None,'current_scope':None}


class InertAdmission(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='sdk-admission-inert-')
        self.addCleanup(self.tmp.cleanup);self.repo=Path(self.tmp.name).resolve()
        self.lock=self.repo/'operation.lock';self.lock.write_bytes(b'original-header\n');self.lock.chmod(0o600)
        self.rroot=Path(str(self.lock)+'.registry');self.rroot.mkdir(mode=0o700)
        self.lfd=os.open(self.lock,os.O_RDWR);self.addCleanup(os.close,self.lfd)
        self.root=self.repo/'reports'/'c16';self.root.mkdir(parents=True,mode=0o700)
        self.ledgerroot=self.root/'launch-ledger';self.ledgerroot.mkdir(mode=0o700)
        self.registry_id=hashlib.sha256(str(self.rroot).encode()).hexdigest()
        self.generation=str(uuid.uuid4());self.image='sha256:'+'a'*64;self.daemon='synthetic-daemon'
        self.template=synthetic_template(self.repo)
        for name,value in (('KNOWN_OWNERS_DIGEST',M.digest(self.template['base_qualification_owners'])),
                           ('KNOWN_PREWORKER_DIGEST',M.digest(self.template['preworker_projection'])),
                           ('PREWORKER_ID',self.template['preworker_projection']['owner']['launch_id'])):
            patch=mock.patch.object(M,name,value);patch.start();self.addCleanup(patch.stop)
        self.rows={};ids=set(self.template['qualification_owners'])|set(self.template['preworker_projection']['launches'][i]['launch_id']for i in range(19))
        while len(ids)<281:ids.add(str(uuid.uuid4()))
        for key in sorted(ids):
            value=self.record(key)
            profile=self.template['qualification_owners'].get(key)
            if profile:
                value['application_helper']=True
                value['qualification_'+profile['subtype']+'_cleanup']=copy.deepcopy(profile['reference'])
                if profile['subtype']=='service':
                    value.update(client_mode='qualification-fixture',qualification_role='fixture',qualification_cell='synthetic')
                    value['mounts']=[{'source':profile['private_mount_source'],'target':'/private','rw':False}]
                else:value['client_mode']='application-execution'
            self.rows[key]=value;self.write_record(value)
        self.policy=copy.deepcopy(self.template);self.policy['lock_path']=str(self.lock);self.policy['registry_root']=str(self.rroot)
        self.policy['expected_canonical_records']={k:M.digest(v)for k,v in self.rows.items()}
        self.policy['selected_task_records']=sorted(self.rows)
        now=time.monotonic();wall=time.time();li=os.fstat(self.lfd);ri=self.rroot.stat()
        self.policy['activation']={'lease_device':li.st_dev,'lease_inode':li.st_ino,
            'registry_device':ri.st_dev,'registry_inode':ri.st_ino,'global_deadline_monotonic':now+1000,
            'global_deadline_wall':wall+1000,'proof_read_authority':M.digest(M.derive_read_closure(
                self.policy['qualification_owners'],self.policy['preworker_projection']))}
        self.policy['admission_budget']={'started_monotonic':now,'started_wall':wall,
            'deadline_monotonic':now+120,'deadline_wall':wall+120}
        self.pred={'schema':1,'root':'/synthetic-old','manifest_sha256':'b'*64,'ledger_sha256':'c'*64,
            'state_sha256':'d'*64,'cleanup_receipts':[]}
        cell={'id':'N01-core','release':'0.87.1','group':'N01','image_id':self.image,
            'allowed_images':[self.image],'role_limits':{'probe':2,'application-helper':1,'fixture':1}}
        self.manifest={'qualification_id':str(uuid.uuid4()),'predecessor':self.pred,
            'images':{'browser-0.87.1':{'id':'sha256:'+'b'*64}},'cells':[cell],
            'limits':{'container_launch_attempts':520,'participant_segments':45}}
        carry={'descriptor_sha256':M.digest(self.pred),'attempts':334,'participant_segments':21,
            'qualification_id':str(uuid.uuid4()),'planned_cells':532}
        self.policy['current_scope']={'scope_root':str(self.root),'ledger_root':str(self.ledgerroot),
            'manifest_sha256':M.digest(self.manifest),'repository_root':str(self.repo),
            'maximum_container_records':210,'maximum_network_records':24,'expected_carry':carry}
        self.ledger={'schema':1,'manifest_sha256':M.digest(self.manifest),'daemon':self.daemon,
            'daemon_capacity':{'cpu_millis':18000,'memory_mib':7931},'started':now-5,'deadline':now-5+14400,
            'started_wall':wall-5,'deadline_wall':wall-5+14400,'last_now':now,'last_wall':wall,
            'poisoned':False,'launches':[],'carry':carry}
        self.write_json(self.ledgerroot/'ledger.json',self.ledger)
        self.effect_guards=[mock.patch('os.kill',side_effect=forbidden),mock.patch('subprocess.Popen',side_effect=forbidden),
            mock.patch('socket.socket',side_effect=forbidden)]
        for patch in self.effect_guards:patch.start();self.addCleanup(patch.stop)

    def record(self,key=None):
        return {'schema':1,'launch_id':key or str(uuid.uuid4()),'generation':self.generation,
            'registry':self.registry_id,'status':'released','container':'synthetic-'+(key or uuid.uuid4().hex)[:8],
            'image':self.image,'mounts':[],'daemon':self.daemon,'runroot':str(self.root),'binding':{}}

    def session_record(self,key=None):
        value=self.record(key)
        value['binding']={'generation':self.generation,'credential_authorities':['application-actor:'+'a'*64],
            'plan_sha256':'b'*64,'run_id':str(uuid.uuid4()),'trial_id':None,
            'attempt_id':str(uuid.uuid4()),'stage_id':str(uuid.uuid4()),'session_id':str(uuid.uuid4())}
        return value

    def parallel_record(self,key=None):
        value=self.record(key);run_id=str(uuid.uuid4());value['runroot']=str(self.root/'runs'/run_id)
        value['binding']={'generation':self.generation,'trial_id':str(uuid.uuid4()),'image':value['image'],
            'release_contracts':copy.deepcopy(M.PARALLEL_RELEASE_CONTRACTS),'daemon':self.daemon,
            'credential_authorities':['application-actor:'+'a'*64],
            'run_id':run_id,'attempt_id':str(uuid.uuid4()),'workspace':str(Path(value['runroot'])/'workspace')}
        return value

    def auxiliary_record(self,case,key=None):
        value=self.record(key)
        value.update(image=M.AUXILIARY_IMAGE,created_at=1792520000.25,owner_pid=123,diagnostic=True,
            runroot=str(self.repo/'reports/application-agent-enhancements/A15/campaign-002/auxiliary/cases'/str(case)),
            binding={'authorization_id':M.AUXILIARY_AUTHORIZATION_ID,'case_id':case,
                     'auxiliary_binding_sha256':M.AUXILIARY_BINDING_SHA256})
        return value

    def assert_shape_denied(self,value):
        gate=M.AdmissionGate(self.policy)
        with mock.patch.object(M,'digest',side_effect=forbidden), \
             mock.patch.object(gate,'_proof_headers',side_effect=forbidden), \
             mock.patch.object(M.os,'open',side_effect=forbidden), \
             mock.patch.object(M.os,'stat',side_effect=forbidden), \
             mock.patch.object(M.os,'lstat',side_effect=forbidden),self.assertRaises(M.AdmissionDenied):
            gate._shape(value,value['launch_id'])

    def write_json(self,path,value):
        path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(M.canonical(value));path.chmod(0o600)

    def write_record(self,value):self.write_json(self.rroot/(value['launch_id']+'.json'),value)

    def call(self,gate):gate(lease_fd=self.lfd,lock_path=self.lock,registry_root=self.rroot)

    def inert_headers(self):
        # Explicitly limited to custody/orchestration. Real proof semantics NOT_RUN.
        return mock.patch.object(M.AdmissionGate,'_proof_headers',return_value=({},0))

    def inert_conservation(self):return mock.patch.object(M.AdmissionGate,'_proof_conservation',return_value=None)

    def extend(self):
        return M.extend_current_scope_policy(self.policy,lease_fd=self.lfd,lock_path=self.lock,
            registry_root=self.rroot,manifest=self.manifest,ledger_root=self.ledgerroot,scope_root=self.root)

    def add_own(self,role='probe',kind='container',helper=None,*,binding=None):
        value=self.record();key=value['launch_id']
        if binding is not None:value['binding']=copy.deepcopy(binding)
        if role=='application-helper':value.update(application_helper=True,client_mode='application-execution')
        if role=='fixture':
            private=self.repo/'disposable-private'/key;observations=self.root/'cells'/'N01-core'/'observations'
            value.update(application_helper=True,qualification_role='fixture',qualification_cell='N01-core',client_mode='qualification-fixture')
            value['mounts']=[{'source':str(self.repo/'skill'),'target':'/opt/pi-skill','rw':False},
                {'source':str(self.repo/'tools/qualification'),'target':'/qualification','rw':False},
                {'source':str(private),'target':'/private','rw':False},
                {'source':str(observations),'target':'/observations','rw':True}]
        if kind=='network':
            value.update(kind='network',container=helper['container']+'-network',image=None,mounts=[],runroot=None)
            value.pop('binding')
        else:
            value['container_id']='f'*64
            row={'key':M.digest({'registry':self.registry_id,'launch_id':key}),'cell':'N01-core','role':role,
                'registry':self.registry_id,'generation':self.generation,'launch_id':key,'container':value['container'],
                'image':self.image,'resources':M._role_weight(self.manifest,self.manifest['cells'][0],role),
                'physical':'absent','private_cleanup':True,'pid':None,'intent_sha256':M._intent_identity(value),
                'container_id':'f'*64,'cleanup_requests':[],'launch_policy':'explicit_pull_never_owned_id_5s'}
            self.ledger['launches'].append(row);self.write_json(self.ledgerroot/'ledger.json',self.ledger)
            if role=='fixture':
                path=self.root/'cells'/'N01-core'/'service-cleanup-receipts'/(key+'.json')
                proof={k:value[k]for k in ('launch_id','registry','generation','daemon','container','container_id','image','runroot','binding','client_mode','mounts')}
                proof.update(schema=1,document_type='qualification_service_cleanup',role='fixture',cell='N01-core',
                    intent_sha256=M._intent_identity(value),private_mount={'source':str(private),'device':0,'inode':1},
                    physical_absence_confirmed=True,private_bootstrap_removed=True,terminal_available=False,
                    startup_readied=False,qualification_eligible=False)
                # Match the original typed service writer's owner-only parent.
                # Only this generated disposable fixture is changed.
                path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.parent.chmod(0o700)
                self.write_json(path,proof);value['qualification_service_cleanup']={'path':str(path),
                    'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
        mirror={'schema':1,'launch_id':key,'kind':kind,'intent_sha256':M._intent_identity(value),
            'before_original_Registry_write':True,'registry':self.registry_id,'generation':self.generation,
            'daemon':self.daemon,'runroot':value['runroot'],'qualification_id':self.manifest['qualification_id'],
            'source_scope_root':str(self.root)}
        # The source producer's required order: durable mirror before record.
        self.write_json(self.root/('intent-'+key+'.json'),mirror);self.write_record(value);return value

    def test_default_unbound_constructor_is_zero_io(self):
        with mock.patch('os.open',side_effect=forbidden),self.assertRaises(M.AdmissionDenied):M.AdmissionGate(self.template)

    def test_bound_constructor_is_pure(self):
        with mock.patch('os.open',side_effect=forbidden),mock.patch('os.stat',side_effect=forbidden):M.AdmissionGate(self.policy)

    def test_fixed_closure_has_55_service_one_preworker_71_files_19_current_refs(self):
        gate=M.AdmissionGate(self.policy);self.assertEqual(len(gate.reads),71)
        self.assertEqual(len(gate.closure['current_registry_ids']),19)
        self.assertEqual(sum(v['subtype']=='service'for v in gate.profiles.values()),55)

    def test_all_71_disposable_proof_headers_are_checked_without_proof_bytes(self):
        gate=M.AdmissionGate(self.policy);original=M.os.open
        def guard(path,*args,**kwargs):
            # The only file-content opens belong to generated Registry rows;
            # every evidence/control leaf is stat-only in the callback.
            if isinstance(path,str) and path.endswith('.json') and not path[:-5] in self.rows:
                raise AssertionError('proof_content_opened')
            return original(path,*args,**kwargs)
        with mock.patch.object(M.os,'open',side_effect=guard):self.call(gate)
        self.assertEqual(len(gate._proof_snapshots),71)


    def test_nonprivate_0644_leaves_and_0755_parents_and_control_tree_are_accepted(self):
        gate=M.AdmissionGate(self.policy)
        for text,row in gate.reads.items():
            if row['role'] not in ('typed_service_owner_metadata','typed_preworker_owner_metadata'):
                path=Path(text);path.chmod(0o644);path.parent.chmod(0o755)
        control=gate.closure['control_tree'];root=Path(control['path']);root.chmod(0o755)
        for relative in control['directories']:(root/relative).chmod(0o755)
        self.call(gate);self.assertEqual(len(gate._proof_snapshots),71)

    def test_private_preworker_owner_0644_is_refused(self):
        gate=M.AdmissionGate(self.policy)
        path=Path(next(text for text,row in gate.reads.items()if row['role']=='typed_preworker_owner_metadata'))
        path.chmod(0o644)
        with self.assertRaises(M.AdmissionDenied):self.call(gate)

    def test_private_service_parent_0755_is_refused(self):
        gate=M.AdmissionGate(self.policy)
        path=Path(next(text for text,row in gate.reads.items()if row['role']=='typed_service_owner_metadata'))
        path.parent.chmod(0o755)
        with self.assertRaises(M.AdmissionDenied):self.call(gate)

    def test_nonprivate_writable_0626_leaf_is_refused(self):
        gate=M.AdmissionGate(self.policy)
        path=Path(next(text for text,row in gate.reads.items()if row['role']=='exact_historical_SDK_process'))
        path.chmod(0o626)
        with self.assertRaises(M.AdmissionDenied):self.call(gate)

    def test_nonprivate_writable_0777_parent_is_refused(self):
        gate=M.AdmissionGate(self.policy)
        path=Path(next(text for text,row in gate.reads.items()if row['role']=='closed_controller_parent_terminal'))
        path.parent.chmod(0o777)
        with self.assertRaises(M.AdmissionDenied):self.call(gate)

    def test_reappeared_classified_private_path_denies_without_purge(self):
        gate=M.AdmissionGate(self.policy);path=Path(gate.closure['absent_paths'][0]);path.mkdir(parents=True)
        with self.assertRaises(M.AdmissionDenied):self.call(gate)
        self.assertTrue(path.exists())

    def test_unclassified_control_leaf_is_never_opened(self):
        gate=M.AdmissionGate(self.policy);control=Path(gate.closure['control_tree']['path'])
        (control/'unknown').write_bytes(b'not-read')
        with self.assertRaises(M.AdmissionDenied):self.call(gate)

    def test_proof_header_size_limit_denies_before_constructor(self):
        gate=M.AdmissionGate(self.policy);path=Path(next(r['path']for r in gate.reads.values()if r['role']=='typed_service_owner_metadata'))
        path.write_bytes(b'x'*65537)
        with self.assertRaises(M.AdmissionDenied):self.call(gate)

    def test_child_ref_tamper_is_denied_before_io(self):
        self.policy['preworker_projection']['stage']['result']['sha256']='0'*64
        with mock.patch('os.open',side_effect=forbidden),self.assertRaises(M.AdmissionDenied):M.AdmissionGate(self.policy)

    def test_arbitrary_owner_classification_is_not_accepted(self):
        self.policy['base_qualification_owners'][next(iter(self.policy['base_qualification_owners']))]['reference']['sha256']='0'*64
        with self.assertRaises(M.AdmissionDenied):M.AdmissionGate(self.policy)

    def test_generic_COMPLETE_does_not_bind_exact_read_authority(self):
        self.policy['activation']['proof_read_authority']='COMPLETE'
        with self.assertRaises(M.AdmissionDenied):M.AdmissionGate(self.policy)

    def test_reporting_reserve_is_required_on_both_clocks(self):
        for clock in ('monotonic','wall'):
            p=copy.deepcopy(self.policy);p['activation']['global_deadline_'+clock]=p['admission_budget']['deadline_'+clock]+29
            with self.assertRaises(M.AdmissionDenied):M.AdmissionGate(p)

    def test_expired_budget_does_not_open_anything(self):
        gate=M.AdmissionGate(self.policy)
        with mock.patch.object(M.time,'monotonic',return_value=self.policy['admission_budget']['deadline_monotonic']+1), \
             mock.patch('os.open',side_effect=forbidden),self.assertRaises(M.AdmissionDenied):self.call(gate)

    def test_positive_281_metadata_readonly_custody(self):
        before=self.lock.read_bytes()
        with self.inert_headers(),self.inert_conservation():
            gate=M.AdmissionGate(self.policy);self.call(gate)
        self.assertEqual(gate.witness['records'],281);self.assertEqual(self.lock.read_bytes(),before)
        self.assertFalse(gate.witness['original_reconcile_claimed']);self.assertFalse(gate.witness['native_eligibility_claimed'])

    def test_failed_callback_cannot_be_reused(self):
        gate=M.AdmissionGate(self.policy)
        for unused in range(2):
            with self.assertRaises(M.AdmissionDenied):gate(lease_fd=self.lfd,lock_path='/wrong',registry_root=self.rroot)

    def test_pending_record_denies_before_canonical_hash(self):
        key=sorted(self.rows)[0];self.rows[key]['status']='intent';self.write_record(self.rows[key]);gate=M.AdmissionGate(self.policy)
        with mock.patch.object(M,'digest',side_effect=forbidden),self.assertRaises(M.AdmissionDenied):self.call(gate)

    def test_unknown_record_field_denies_before_canonical_hash(self):
        key=sorted(self.rows)[0];self.rows[key]['payload']='unknown';self.write_record(self.rows[key]);gate=M.AdmissionGate(self.policy)
        with mock.patch.object(M,'digest',side_effect=forbidden),self.assertRaises(M.AdmissionDenied):self.call(gate)


    def test_source_initial_ordinary_trial_id_None_is_accepted(self):
        key=next(k for k in sorted(self.rows)if k not in self.policy['qualification_owners'])
        self.rows[key]['binding']['trial_id']=None;self.write_record(self.rows[key])
        self.policy['expected_canonical_records'][key]=M.digest(self.rows[key])
        with self.inert_headers(),self.inert_conservation():self.call(M.AdmissionGate(self.policy))

    def test_source_budget_only_session_binding_is_pure_and_accepted(self):
        value=self.session_record();gate=M.AdmissionGate(self.policy)
        with mock.patch.object(M.os,'open',side_effect=forbidden), \
             mock.patch.object(M.os,'stat',side_effect=forbidden),mock.patch.object(M.os,'lstat',side_effect=forbidden), \
             mock.patch.object(M,'digest',side_effect=forbidden):
            gate._shape(value,value['launch_id'])

    def test_session_id_requires_canonical_uuid(self):
        for item in (None,True,1,'7BED0000-0000-0000-0000-000000000001',
                     '7bed0000000000000000000000000001','f'*36,'invalid\nidentity'):
            with self.subTest(item=item):
                value=self.session_record();value['binding']['session_id']=item;self.assert_shape_denied(value)

    def test_source_parallel_binding_and_only_declared_overlays_are_accepted(self):
        for overlay in ({},{'stage_id':str(uuid.uuid4()),'segment_id':str(uuid.uuid4())},
                        {'stage_id':str(uuid.uuid4()),'indexed_host_generation':2}):
            with self.subTest(overlay=overlay):
                value=self.parallel_record();value['binding'].update(overlay)
                if 'indexed_host_generation' in overlay:value['schema']=2
                gate=M.AdmissionGate(self.policy)
                with mock.patch.object(M.os,'open',side_effect=forbidden),mock.patch.object(M,'digest',side_effect=forbidden):
                    gate._shape(value,value['launch_id'])

    def test_parallel_binding_requires_every_source_field(self):
        for field in M.PARALLEL_BINDING_REQUIRED:
            with self.subTest(field=field):
                value=self.parallel_record();del value['binding'][field];self.assert_shape_denied(value)

    def test_parallel_unknown_or_ordinary_mixture_is_denied(self):
        for field,item in (('payload','unknown'),('plan_sha256','a'*64),('session_id',str(uuid.uuid4())),
                           ('environment_incarnation','unknown'),('configuration',{}),('authority_id','unknown'),('adapter','unknown')):
            with self.subTest(field=field):
                value=self.parallel_record();value['binding'][field]=item;self.assert_shape_denied(value)

    def test_parallel_nested_release_contracts_are_closed_and_hash_bound(self):
        mutations=[lambda c:c.pop('1.2.0'),lambda c:c.update({'other':{}}),
            lambda c:c['0.87.1'].pop('id'),lambda c:c['0.87.1'].update(payload='unknown'),
            lambda c:c['0.87.1'].update(release='1.2.0'),lambda c:c['0.87.1'].update(id='other'),
            lambda c:c['0.87.1'].update(revision=True),lambda c:c['0.87.1'].update(revision=1.0),
            lambda c:c['0.87.1'].update(sha256='0'*64),lambda c:c['0.87.1'].update(sha256='malformed')]
        for index,mutate in enumerate(mutations):
            with self.subTest(index=index):
                value=self.parallel_record();mutate(value['binding']['release_contracts']);self.assert_shape_denied(value)
        value=self.parallel_record();value['binding']['release_contracts']=[];self.assert_shape_denied(value)

    def test_parallel_record_and_workspace_identities_are_cross_bound(self):
        for field,item in (('generation',str(uuid.uuid4())),('image','sha256:'+'c'*64),('daemon','other-daemon'),
                           ('workspace',str(self.root/'foreign-workspace')),('run_id',str(uuid.uuid4()))):
            with self.subTest(field=field):
                value=self.parallel_record();value['binding'][field]=item;self.assert_shape_denied(value)
        for item in (None,str(self.root/'runs'/'..'/'foreign'),str(self.root/'other'/str(uuid.uuid4()))):
            with self.subTest(runroot=item):
                value=self.parallel_record();value['runroot']=item;self.assert_shape_denied(value)

    def test_parallel_workspace_is_a_bounded_path_without_path_io(self):
        value=self.parallel_record();run_id=value['binding']['run_id']
        runroot=self.repo/('long-'+'a'*240)/('long-'+'b'*240)/'runs'/run_id
        value['runroot']=str(runroot);value['binding']['workspace']=str(runroot/'workspace')
        self.assertGreater(len(value['binding']['workspace']),256)
        self.assertLessEqual(len(value['binding']['workspace']),4096)
        gate=M.AdmissionGate(self.policy)
        with mock.patch.object(M.os,'open',side_effect=forbidden), \
             mock.patch.object(M.os,'stat',side_effect=forbidden),mock.patch.object(M.os,'lstat',side_effect=forbidden), \
             mock.patch.object(M,'digest',side_effect=forbidden):
            gate._shape(value,value['launch_id'])
        for workspace in ('relative/workspace',str(runroot/'..'/'workspace'),'//foreign/workspace'):
            with self.subTest(workspace=workspace):
                bad=copy.deepcopy(value);bad['binding']['workspace']=workspace;self.assert_shape_denied(bad)
        bad=copy.deepcopy(value);runroot=self.repo/('too-long-'+'a'*4100)/'runs'/run_id
        bad['runroot']=str(runroot);bad['binding']['workspace']=str(runroot/'workspace')
        self.assertGreater(len(bad['binding']['workspace']),4096);self.assert_shape_denied(bad)

    def test_parallel_uuid_authority_and_indexed_types_are_strict(self):
        for field in ('run_id','attempt_id','trial_id','stage_id','segment_id'):
            with self.subTest(field=field):
                value=self.parallel_record();value['binding'][field]=None;self.assert_shape_denied(value)
        for field,item in (('credential_authorities',['unclassified']),('credential_authorities',True),
                           ('indexed_host_generation',True),('indexed_host_generation',1)):
            with self.subTest(field=field,item=item):
                value=self.parallel_record();value['binding'][field]=item;self.assert_shape_denied(value)
        value=self.parallel_record();value['schema']=2;self.assert_shape_denied(value)

    def test_parallel_release_literals_equal_original_runtime_snapshot(self):
        source=next(parent/'skill/runtime/release_contracts.py' for parent in HERE.parents
                    if (parent/'skill/runtime/release_contracts.py').is_file())
        # This public, pure source is executed in an isolated namespace only;
        # the SDK itself acquires no new import or IO dependency.
        subject=types.ModuleType('sdk_admission_release_fixture');body=source.read_bytes()
        with mock.patch('os.open',side_effect=forbidden),mock.patch('os.kill',side_effect=forbidden), \
             mock.patch('subprocess.Popen',side_effect=forbidden),mock.patch('socket.socket',side_effect=forbidden):
            exec(compile(body,str(source),'exec'),subject.__dict__)
            self.assertEqual(M.PARALLEL_RELEASE_CONTRACTS,subject.snapshot())

    def test_auxiliary_constants_equal_fixed_source_producer(self):
        source=next(parent/'tools/qualification/application_campaign.py' for parent in HERE.parents
                    if (parent/'tools/qualification/application_campaign.py').is_file())
        assignments={node.targets[0].id:node.value for node in ast.parse(source.read_bytes()).body
            if isinstance(node,ast.Assign) and isinstance(node.targets[0],ast.Name)}
        self.assertEqual(M.AUXILIARY_AUTHORIZATION_ID,ast.literal_eval(assignments['AUTHORIZATION_ID']))
        self.assertEqual(M.AUXILIARY_IMAGE,ast.literal_eval(assignments['IMAGE']))
        self.assertEqual(M.AUXILIARY_BINDING_SHA256,
            ast.literal_eval(assignments['KNOWN_AUXILIARY_INCIDENT'])['binding_sha256'])

    def test_fixed_auxiliary_three_case_binding_is_pure_and_accepted(self):
        gate=M.AdmissionGate(self.policy)
        for case in (1,2,3):
            with self.subTest(case=case):
                value=self.auxiliary_record(case)
                with mock.patch.object(M.os,'open',side_effect=forbidden),mock.patch.object(M,'digest',side_effect=forbidden):
                    gate._shape(value,value['launch_id'])

    def test_auxiliary_binding_is_exact_and_incident_bound(self):
        for field,item in (('authorization_id',str(uuid.uuid4())),('case_id',True),('case_id',0),('case_id',4),
                           ('auxiliary_binding_sha256','0'*64),('auxiliary_binding_sha256','malformed')):
            with self.subTest(field=field,item=item):
                value=self.auxiliary_record(1);value['binding'][field]=item;self.assert_shape_denied(value)
        for field in M.AUXILIARY_BINDING_KEYS:
            with self.subTest(missing=field):
                value=self.auxiliary_record(1);del value['binding'][field];self.assert_shape_denied(value)
        value=self.auxiliary_record(1);value['binding']['payload']='unknown';self.assert_shape_denied(value)

    def test_auxiliary_diagnostic_timestamp_and_root_are_conditional(self):
        for field,item in (('diagnostic',False),('diagnostic',1),('created_at',True),('created_at','timestamp'),
                           ('created_at',float('inf')),('created_at',float('nan')),('image',self.image),
                           ('schema',2),('schema',True),('runroot',str(self.root))):
            with self.subTest(field=field,item=item):
                value=self.auxiliary_record(1);value[field]=item;self.assert_shape_denied(value)
        value=self.auxiliary_record(1);value['runroot']=str(Path(value['runroot']).parent/'2');self.assert_shape_denied(value)

    def test_auxiliary_rejects_unproduced_top_level_decorations(self):
        for field,item in (('kind','container'),('application_helper',False),('gateway_ready',False),
                           ('private_store',str(self.root/'not-read')),('code_identity',{}),
                           ('qualification_service_cleanup',{}),('payload','unknown')):
            with self.subTest(field=field):
                value=self.auxiliary_record(1);value[field]=item;self.assert_shape_denied(value)
        for field in ('owner_pid','created_at','diagnostic'):
            with self.subTest(missing=field):
                value=self.auxiliary_record(1);del value[field];self.assert_shape_denied(value)

    def test_generic_top_level_diagnostic_or_numeric_timestamp_still_denies(self):
        for factory in (self.record,self.parallel_record):
            for field,item in (('diagnostic',True),('diagnostic',False),('created_at',1792520000.25)):
                with self.subTest(factory=factory.__name__,field=field,item=item):
                    value=factory();value[field]=item;self.assert_shape_denied(value)

    def test_mixed_source_binding_forms_pass_original_metadata_custody(self):
        keys=[k for k in sorted(self.rows) if k not in self.policy['qualification_owners']]
        values=[self.session_record(keys[0]),self.parallel_record(keys[1])]
        indexed=self.parallel_record(keys[2]);indexed['schema']=2
        indexed['binding'].update(indexed_host_generation=2,stage_id=str(uuid.uuid4()),segment_id=str(uuid.uuid4()))
        values.append(indexed)
        values.extend(self.auxiliary_record(case,keys[case+2]) for case in (1,2,3))
        for value in values:
            self.rows[value['launch_id']]=value;self.write_record(value)
            self.policy['expected_canonical_records'][value['launch_id']]=M.digest(value)
        before=self.lock.read_bytes()
        # Only proof-header/semantic conservation hooks are inert in this
        # existing custody fixture; this is not a real SDK proof-graph claim.
        with self.inert_headers(),self.inert_conservation():
            gate=M.AdmissionGate(self.policy);self.call(gate)
        self.assertEqual(gate.witness['records'],281);self.assertEqual(self.lock.read_bytes(),before)

    def test_malformed_new_variant_denies_before_target_hash_or_proof_read(self):
        key=sorted(self.rows)[0]
        values=[self.session_record(key),self.parallel_record(key),self.auxiliary_record(1,key)]
        values[0]['binding']['session_id']=None
        values[1]['binding']['release_contracts']['0.87.1']['sha256']='0'*64
        values[2]['binding']['case_id']=True
        for value in values:
            with self.subTest(binding=value['binding']):
                self.write_record(value);gate=M.AdmissionGate(self.policy)
                with self.deny_target_hash(key),mock.patch.object(gate,'_proof_headers',side_effect=forbidden), \
                     self.assertRaises(M.AdmissionDenied):self.call(gate)

    def test_extended_ordinary_trial_id_None_is_accepted(self):
        value=self.add_own(binding={'trial_id':None});result=self.extend()
        with self.inert_headers(),self.inert_conservation():self.call(M.AdmissionGate(result))
        self.assertIn(value['launch_id'],result['expected_canonical_records'])

    def deny_target_hash(self,key):
        original=M.digest
        def guarded(value):
            if type(value) is dict and value.get('launch_id')==key:
                raise AssertionError('unclassified_target_was_hashed')
            return original(value)
        return mock.patch.object(M,'digest',side_effect=guarded)

    def test_None_other_binding_field_is_rejected_before_canonical_hash(self):
        key=next(k for k in sorted(self.rows)if k not in self.policy['qualification_owners'])
        self.rows[key]['binding']['attempt_id']=None;self.write_record(self.rows[key]);gate=M.AdmissionGate(self.policy)
        with self.deny_target_hash(key),self.assertRaises(M.AdmissionDenied):self.call(gate)


    def test_released_ordinary_gateway_metadata_is_accepted_without_following_state(self):
        key=next(k for k in sorted(self.rows)if k not in self.policy['qualification_owners'])
        state=self.repo/'never-open-gateway-state.json';state.write_bytes(b'inert-state-canary')
        self.rows[key].update(gateway_state=str(state),gateway_ready=True,inference_uncertain=False)
        self.write_record(self.rows[key]);self.policy['expected_canonical_records'][key]=M.digest(self.rows[key]);gate=M.AdmissionGate(self.policy)
        original=M.os.open
        def guard(path,*args,**kwargs):
            if path in (str(state),state.name):raise AssertionError('gateway_state_followed')
            return original(path,*args,**kwargs)
        with self.inert_headers(),self.inert_conservation(),mock.patch.object(M.os,'open',side_effect=guard):self.call(gate)

    def test_gateway_nonboolean_flags_denied_before_target_hash(self):
        key=next(k for k in sorted(self.rows)if k not in self.policy['qualification_owners'])
        for field,value in (('gateway_ready',1),('inference_uncertain',0)):
            with self.subTest(field=field):
                row=copy.deepcopy(self.rows[key]);row[field]=value;self.write_record(row);gate=M.AdmissionGate(self.policy)
                with self.deny_target_hash(key),self.assertRaises(M.AdmissionDenied):self.call(gate)

    def test_released_inference_uncertain_true_denied_before_target_hash(self):
        key=next(k for k in sorted(self.rows)if k not in self.policy['qualification_owners'])
        self.rows[key]['inference_uncertain']=True;self.write_record(self.rows[key]);gate=M.AdmissionGate(self.policy)
        with self.deny_target_hash(key),self.assertRaises(M.AdmissionDenied):self.call(gate)

    def test_unknown_binding_field_denies_before_canonical_hash(self):
        key=sorted(self.rows)[0];self.rows[key]['binding']['payload']='unknown';self.write_record(self.rows[key]);gate=M.AdmissionGate(self.policy)
        with mock.patch.object(M,'digest',side_effect=forbidden),self.assertRaises(M.AdmissionDenied):self.call(gate)

    def test_unknown_namespace_is_refused_without_opening_its_body(self):
        bad=self.rroot/'unknown.json';bad.write_bytes(b'never-open');gate=M.AdmissionGate(self.policy)
        original=M.os.open
        def guard(path,*a,**kw):
            self.assertNotEqual(path,'unknown.json');return original(path,*a,**kw)
        with mock.patch.object(M.os,'open',side_effect=guard),self.assertRaises(M.AdmissionDenied):self.call(gate)

    def test_symlink_record_refused(self):
        key=sorted(self.rows)[0];path=self.rroot/(key+'.json');path.unlink();path.symlink_to(self.repo/'never-read')
        with self.assertRaises(OSError):self.call(M.AdmissionGate(self.policy))

    def test_wrong_lease_inode_refused(self):
        gate=M.AdmissionGate(self.policy);self.lock.rename(self.repo/'old.lock');self.lock.write_bytes(b'new');self.lock.chmod(0o600)
        with self.assertRaises(M.AdmissionDenied):self.call(gate)

    def test_registry_rename_during_first_decode_denies_before_next_leaf(self):
        gate=M.AdmissionGate(self.policy);old=M.decode;calls=[]
        def changed(body):
            value=old(body);calls.append(1)
            if len(calls)==1:self.rroot.rename(self.repo/'old.registry');self.rroot.mkdir(mode=0o700)
            return value
        with mock.patch.object(M,'decode',side_effect=changed),self.assertRaises(M.AdmissionDenied):self.call(gate)
        self.assertEqual(len(calls),1)

    def test_earlier_record_drift_caught_before_constructor(self):
        gate=M.AdmissionGate(self.policy);old=M.decode;calls=[];first=sorted(self.rows)[0]
        def changed(body):
            value=old(body);calls.append(1)
            if len(calls)==2:
                changed_value=copy.deepcopy(self.rows[first]);changed_value['status']='intent';self.write_record(changed_value)
            return value
        with self.inert_headers(),self.inert_conservation(),mock.patch.object(M,'decode',side_effect=changed),self.assertRaises(M.AdmissionDenied):self.call(gate)

    def test_after_yield_uses_actual_CURRENT(self):
        with self.inert_headers(),self.inert_conservation():
            gate=M.AdmissionGate(self.policy);self.call(gate)
            current=contextvars.ContextVar('inert_registry',default=None);registry=types.SimpleNamespace(root=self.rroot,lease_fd=self.lfd)
            with mock.patch.dict(sys.modules,{'ownership_registry':types.SimpleNamespace(CURRENT=current)}):
                with self.assertRaises(M.AdmissionDenied):gate.assert_after_yield(registry)
                token=current.set(registry)
                try:gate.assert_after_yield(registry)
                finally:current.reset(token)

    def test_two_leases_add_completed_probe_preserving_baseline_and_shared_budget(self):
        before=copy.deepcopy(self.policy['expected_canonical_records'])
        with self.inert_headers(),self.inert_conservation():
            first=self.extend();gate=M.AdmissionGate(first);self.call(gate)
            self.assertEqual(gate.witness['records'],281)
            own=self.add_own();second=self.extend();again=M.AdmissionGate(second);self.call(again)
        self.assertEqual(len(second['expected_canonical_records']),282)
        self.assertTrue(all(second['expected_canonical_records'][k]==v for k,v in before.items()))
        self.assertEqual(second['admission_budget'],self.policy['admission_budget'])
        self.assertIn(own['launch_id'],again.expected)

    def test_exact_own_helper_network_is_accepted_after_completed_helper(self):
        helper=self.add_own('application-helper');network=self.add_own(kind='network',helper=helper)
        result=self.extend();self.assertIn(network['launch_id'],result['expected_canonical_records'])

    def test_next_lease_extends_only_exact_source_generated_typed_service_receipt(self):
        with self.inert_headers(),self.inert_conservation():
            first=self.extend();gate=M.AdmissionGate(first);self.call(gate)
            service=self.add_own('fixture');result=self.extend();again=M.AdmissionGate(result);self.call(again)
        self.assertEqual(len(again.profiles),57);self.assertEqual(len(again.reads),72)
        self.assertEqual(again.profiles[service['launch_id']]['reference'],service['qualification_service_cleanup'])
        self.assertEqual(result['admission_budget'],self.policy['admission_budget'])


    def test_service_nullable_record_CID_denied_before_service_proof_body(self):
        service=self.add_own('fixture');key=service['launch_id'];service['container_id']=None;self.write_record(service)
        original=M.AdmissionGate._read_exact
        def guard(gate,fd,name,maximum,lease_fd,registry_fd=None):
            if name==key+'.json' and registry_fd is None:
                raise AssertionError('service_proof_opened_before_real_CID')
            return original(gate,fd,name,maximum,lease_fd,registry_fd)
        with mock.patch.object(M.AdmissionGate,'_read_exact',new=guard),self.assertRaises(M.AdmissionDenied):self.extend()

    def test_service_receipt_outside_current_cell_is_refused_without_read(self):
        service=self.add_own('fixture');service['qualification_service_cleanup']['path']=str(self.repo/'unapproved-proof.json')
        self.write_record(service)
        with self.assertRaises(M.AdmissionDenied):self.extend()

    def test_service_unknown_proof_field_is_refused_before_hash(self):
        service=self.add_own('fixture');path=Path(service['qualification_service_cleanup']['path'])
        proof=json.loads(path.read_text());proof['payload']='unknown';self.write_json(path,proof)
        with self.assertRaises(M.AdmissionDenied):self.extend()

    def test_unmirrored_global_new_row_denied_before_body_read(self):
        value=self.record();self.write_record(value)
        with self.assertRaises(M.AdmissionDenied):self.extend()

    def test_pending_own_row_denied(self):
        value=self.add_own();value['status']='quarantined';self.write_record(value)
        with self.assertRaises(M.AdmissionDenied):self.extend()

    def test_private_false_or_poisoned_own_ledger_denies(self):
        self.add_own();self.ledger['launches'][0]['private_cleanup']=False;self.write_json(self.ledgerroot/'ledger.json',self.ledger)
        with self.assertRaises(M.AdmissionDenied):self.extend()
        self.ledger['launches'][0]['private_cleanup']=True;self.ledger['poisoned']=True;self.write_json(self.ledgerroot/'ledger.json',self.ledger)
        with self.assertRaises(M.AdmissionDenied):self.extend()

    def test_foreign_network_generation_denied(self):
        helper=self.add_own('application-helper');network=self.add_own(kind='network',helper=helper)
        network['generation']=str(uuid.uuid4());self.write_record(network)
        with self.assertRaises(M.AdmissionDenied):self.extend()

    def test_current_resource_drift_denied(self):
        self.add_own();self.ledger['launches'][0]['resources']['memory_mib']+=1;self.write_json(self.ledgerroot/'ledger.json',self.ledger)
        with self.assertRaises(M.AdmissionDenied):self.extend()

    def test_serialized_extension_assertion_has_no_source_ticket(self):
        self.add_own();derived=self.extend();plain=json.loads(json.dumps(derived))
        with self.assertRaises(M.AdmissionDenied):M.AdmissionGate(plain)

    def test_full_role_set_and_unknown_class_have_no_generic_policy_override(self):
        altered=copy.deepcopy(self.policy);altered['preworker_projection']['controller']['pid']=1
        altered['allowed_evidence_classes']=['anything'];altered['status']='COMPLETE'
        with self.assertRaises(M.AdmissionDenied):M.AdmissionGate(altered)

    def test_public_application_authority_producer_matches_mixed_parallel_metadata(self):
        contracts=pure_authority_subset('skill/scripts/application_contracts.py',
            classes=('ContractError',),functions=('fail','escape','exact','text','participant','safe_json','canonical','digest'))
        credentials=pure_authority_subset('skill/scripts/application_credentials.py',
            classes=('CredentialError',),functions=('validate',))
        declared={'PI_APP_ALIAS_'+str(i):'STORE_ACTOR_'+str(i)for i in range(8)}
        references=authority_pure_call(credentials.validate,declared)
        participants=[{'application_id':'synthetic-app','tenant_id':'synthetic-tenant',
            'actor_id':'actor-'+str(i),'role':'writer'}for i in range(8)]
        for participant in participants:authority_pure_call(contracts.participant,participant,'/participant')
        producer=pure_authority_subset('skill/scripts/parallel_application.py',
            methods={'ApplicationCohort':('authorities',)},bindings={'c':contracts})
        cohort=object.__new__(producer.ApplicationCohort)
        cohort.plans={'trial':{'application':{'credentials':{'alias-'+str(i):name
            for i,name in enumerate(references.values())}},'stages':[{'participant':p}for p in participants]}}
        cohort._values=['synthetic-private-value-not-a-reference']
        tags=authority_pure_call(cohort.authorities,'trial')
        self.assertEqual(len(tags),16);self.assertEqual(tags,sorted(set(tags)))
        self.assertEqual(set(references.values()),{tag for tag in tags if not tag.startswith('application-actor:')})
        self.assertNotIn(cohort._values[0],json.dumps(tags))
        value=self.parallel_record();value['binding']['credential_authorities']=tags
        gate=M.AdmissionGate(self.policy);authority_pure_call(gate._shape,value,value['launch_id'])

    def test_public_helper_producers_remain_actor_only_and_budget_empty(self):
        contracts=pure_authority_subset('skill/scripts/application_contracts.py',
            classes=('ContractError',),functions=('fail','escape','text','safe_json','canonical','digest'))
        application=pure_authority_subset('skill/scripts/application_client.py',
            methods={'Authority':('launch_spec',)},bindings={'c':contracts})
        owner=object.__new__(application.Authority)
        owner._plan={'runtime':{},'plan_sha256':'a'*64,'application':{'browser_targets':[]},
            'stages':[{'participant':{'application_id':'synthetic-app','tenant_id':'tenant',
                'actor_id':'actor-'+str(i),'role':'writer'}}for i in range(8)]}
        actors=authority_pure_call(owner.launch_spec)['actors'];self.assertEqual(len(actors),8)
        native=pure_authority_subset('skill/scripts/native_budget_client.py',
            methods={'NativeBudgetAuthority':('launch_spec',)})
        budget=object.__new__(native.NativeBudgetAuthority);budget.runtime={};budget.plan_sha256='a'*64
        empty=authority_pure_call(budget.launch_spec)['actors'];self.assertEqual(empty,[])
        for tags in (actors,empty):
            value=self.record();value['application_helper']=True
            value['binding']={'generation':self.generation,'plan_sha256':'a'*64,'credential_authorities':tags}
            gate=M.AdmissionGate(self.policy);authority_pure_call(gate._shape,value,value['launch_id'])

    def test_original_credential_validator_supports_bounded_legacy_reference_names(self):
        credentials=pure_authority_subset('skill/scripts/application_credentials.py',
            classes=('CredentialError',),functions=('validate',))
        names=[]
        for agent in range(8):
            declared={'PI_APP_ALIAS_'+str(i):'ACTOR_'+str(agent)+'_'+str(i)for i in range(8)}
            names.extend(authority_pure_call(credentials.validate,declared).values())
        self.assertEqual(len(set(names)),64)
        for name in ('A','_','A'*64):
            self.assertEqual(authority_pure_call(credentials.validate,{'PI_APP_ALIAS':name})['PI_APP_ALIAS'],name)
        for name in ('A'*65,'lower','9START','A/B','A-B','A\nB','ÁCTOR'):
            with self.subTest(name=name),self.assertRaises(credentials.CredentialError):
                authority_pure_call(credentials.validate,{'PI_APP_ALIAS':name})
        value=self.parallel_record();value['binding']['credential_authorities']=sorted(set(names))
        gate=M.AdmissionGate(self.policy);authority_pure_call(gate._shape,value,value['launch_id'])

    def test_parallel_named_authorities_accept_only_declared_worker_role_forms(self):
        actor='application-actor:'+'a'*64
        for flags in ({},{'kind':'container'},{'application_helper':False},
                      {'kind':'container','application_helper':False,'schema':2}):
            for tags in ([],['STORE_ACTOR'],['STORE_ACTOR',actor]):
                with self.subTest(flags=flags,tags=tags):
                    value=self.parallel_record();value.update(flags)
                    if value['schema']==2:value['binding'].update(indexed_host_generation=2,
                        stage_id=str(uuid.uuid4()),segment_id=str(uuid.uuid4()))
                    value['binding']['credential_authorities']=tags
                    gate=M.AdmissionGate(self.policy);authority_pure_call(gate._shape,value,value['launch_id'])

    def test_named_authority_grammar_and_list_types_reject_before_shape_io(self):
        invalid=[None,True,3,{},[],['NESTED'],'A'*65,'lower','9START',' A','A ',
            'A\tB','A\nB','A\0B','ÁCTOR','A/B',r'A\B','A-B','env:ACTOR',
            'application-actor:'+'A'*64,'application-actor:'+'a'*63,'opaque-synthetic-secret-value']
        for item in invalid:
            with self.subTest(item=item):
                value=self.parallel_record();value['binding']['credential_authorities']=[item]
                gate=M.AdmissionGate(self.policy)
                with self.assertRaisesRegex(M.AdmissionDenied,'^authority_reference_shape$'):
                    authority_pure_call(gate._shape,value,value['launch_id'])
        for tags in (None,True,1,{},'STORE_ACTOR',('STORE_ACTOR',)):
            with self.subTest(list_type=type(tags).__name__):
                value=self.parallel_record();value['binding']['credential_authorities']=tags
                gate=M.AdmissionGate(self.policy)
                with self.assertRaisesRegex(M.AdmissionDenied,'^authority_reference_shape$'):
                    authority_pure_call(gate._shape,value,value['launch_id'])

    def test_store_names_do_not_activate_for_ordinary_helper_network_or_builder(self):
        for factory in (self.record,self.session_record):
            value=factory();value['binding']['credential_authorities']=['STORE_ACTOR']
            gate=M.AdmissionGate(self.policy)
            with self.assertRaisesRegex(M.AdmissionDenied,'^authority_reference_shape$'):
                authority_pure_call(gate._shape,value,value['launch_id'])
        for flags in ({'application_helper':True},{'application_helper':0},{'application_helper':None},
                      {'kind':'network'},{'kind':'builder'}):
            with self.subTest(flags=flags):
                value=self.parallel_record();value.update(flags);value['binding']['credential_authorities']=['STORE_ACTOR']
                gate=M.AdmissionGate(self.policy)
                # All other parallel fields are valid: the intended authority
                # predicate, not an unrelated malformed field, must refuse.
                with self.assertRaisesRegex(M.AdmissionDenied,'^authority_reference_shape$'):
                    authority_pure_call(gate._shape,value,value['launch_id'])

    def test_authority_cap_order_duplicates_and_actor_compatibility_are_unchanged(self):
        actor='application-actor:'+'a'*64
        for tags in (['Z_REF','A_REF','Z_REF',actor],['DUPLICATE']*128,[actor]*128,[],['A','_','A'*64]):
            with self.subTest(count=len(tags)):
                value=self.parallel_record();value['binding']['credential_authorities']=copy.deepcopy(tags)
                before=copy.deepcopy(value);gate=M.AdmissionGate(self.policy)
                authority_pure_call(gate._shape,value,value['launch_id']);self.assertEqual(value,before)
        value=self.parallel_record();value['binding']['credential_authorities']=['DUPLICATE']*129
        gate=M.AdmissionGate(self.policy)
        with self.assertRaisesRegex(M.AdmissionDenied,'^authority_reference_shape$'):
            authority_pure_call(gate._shape,value,value['launch_id'])

    def test_named_authority_requires_complete_cross_bound_parallel_before_allowance(self):
        for field in M.PARALLEL_BINDING_REQUIRED:
            with self.subTest(missing=field):
                value=self.parallel_record();value['binding']['credential_authorities']=['STORE_ACTOR']
                del value['binding'][field];self.assert_shape_denied(value)
        for field,item in (('generation',str(uuid.uuid4())),('image','sha256:'+'f'*64),('daemon','foreign'),
                           ('workspace',str(self.root/'foreign')),('trial_id',None)):
            with self.subTest(field=field):
                value=self.parallel_record();value['binding']['credential_authorities']=['STORE_ACTOR']
                value['binding'][field]=item;self.assert_shape_denied(value)
        value=self.parallel_record();value['binding']['credential_authorities']=['STORE_ACTOR']
        value['binding']['release_contracts']['0.87.1']['sha256']='0'*64;self.assert_shape_denied(value)
        value=self.parallel_record();value['binding']['credential_authorities']=['STORE_ACTOR']
        value['binding']['plan_sha256']='a'*64;self.assert_shape_denied(value)

    def test_named_authority_custody_and_role_denial_precede_target_hash_and_proofs(self):
        key=next(k for k in sorted(self.rows)if k not in self.policy['qualification_owners'])
        value=self.parallel_record(key);value['binding']['credential_authorities']=['STORE_ACTOR','application-actor:'+'a'*64]
        self.write_record(value);self.policy['expected_canonical_records'][key]=M.digest(value)
        with self.inert_headers(),self.inert_conservation():
            gate=M.AdmissionGate(self.policy);self.call(gate)
        self.assertEqual(gate.witness['records'],281)
        key=sorted(self.rows)[0]
        for flags in ({'application_helper':True},{'kind':'network'},{'kind':'builder'}):
            with self.subTest(flags=flags):
                value=self.parallel_record(key);value.update(flags);value['binding']['credential_authorities']=['STORE_ACTOR']
                self.write_record(value);gate=M.AdmissionGate(self.policy)
                with self.deny_target_hash(key),mock.patch.object(gate,'_proof_headers',side_effect=forbidden), \
                     self.assertRaisesRegex(M.AdmissionDenied,'^authority_reference_shape$'):
                    self.call(gate)

    def test_source039_profile_fixture_is_exact_and_portable(self):
        old=source039_profile_comparator()
        self.assertEqual(old.__name__,'_profile')
        self.assertEqual(SOURCE039_PROFILE_AST_SHA256,'5a67f5a259cbeb3e59420753ad0ced7aafae382f4d0d62a8b7bb4951ab2a2780')
        self.assertNotIn('read_bytes',SOURCE039_PROFILE_CODE)
        self.assertNotIn('source039-preservation',SOURCE039_PROFILE_CODE)

    def test_profile_old_and_new_acceptance_match_closed_source_truth_table(self):
        old=source039_profile_comparator();gate=M.AdmissionGate(self.policy)
        service=next(k for k,v in self.policy['qualification_owners'].items()if v['subtype']=='service')
        preworker=next(k for k,v in self.policy['qualification_owners'].items()if v['subtype']=='preworker')
        cases=[copy.deepcopy(self.rows[k])for k in self.policy['qualification_owners']]
        cases.append(self.record())
        for mode in ('authority-only','application-execution','budget-only'):
            value=self.record();value.update(application_helper=True,client_mode=mode);cases.append(value)
        gateway=self.record();gateway.update(gateway_state=str(self.repo/'unread-gateway-state'),
            gateway_ready=True,inference_uncertain=False,private_store=str(self.repo/'unread-gateway-private'));cases.append(gateway)
        unknown=self.record();unknown.update(application_helper=True,client_mode='qualification-fixture');cases.append(unknown)
        selected=next(k for k in self.rows if k not in self.policy['qualification_owners'])
        value=self.record(selected);value.update(application_helper=True,client_mode='qualification-fixture');cases.append(value)
        for field,item in (('path',str(self.repo/'other-proof.json')),('sha256','0'*64)):
            value=copy.deepcopy(self.rows[service]);value['qualification_service_cleanup'][field]=item;cases.append(value)
        value=copy.deepcopy(self.rows[service]);value.pop('qualification_service_cleanup');cases.append(value)
        value=copy.deepcopy(self.rows[service]);value['qualification_preworker_cleanup']=copy.deepcopy(
            self.rows[preworker]['qualification_preworker_cleanup']);cases.append(value)
        value=copy.deepcopy(self.rows[preworker]);value.pop('qualification_preworker_cleanup');cases.append(value)
        value=copy.deepcopy(self.rows[service]);value['mounts'][0]['source']=str(self.repo/'other-private');cases.append(value)
        for index,value in enumerate(cases):
            with self.subTest(index=index):
                authority_pure_call(gate._shape,value,value['launch_id'])
                outcomes=[]
                for check in (lambda:old(gate,value),lambda:gate._profile(value)):
                    try:outcomes.append(('accepted',authority_pure_call(check)))
                    except M.AdmissionDenied:outcomes.append(('denied',None))
                self.assertEqual(outcomes[0],outcomes[1])

    def test_profile_all_six_closed_denials_and_path_first_priority(self):
        gate=M.AdmissionGate(self.policy)
        service=next(k for k,v in self.policy['qualification_owners'].items()if v['subtype']=='service')
        preworker=next(k for k,v in self.policy['qualification_owners'].items()if v['subtype']=='preworker')
        selected=next(k for k in self.rows if k not in self.policy['qualification_owners'])
        inside=self.record(selected);inside.update(application_helper=True,client_mode='qualification-fixture')
        outside=self.record();outside.update(application_helper=True,client_mode='qualification-fixture')
        subtype=copy.deepcopy(self.rows[service]);subtype['qualification_preworker_cleanup']=copy.deepcopy(
            self.rows[preworker]['qualification_preworker_cleanup'])
        absent=copy.deepcopy(self.rows[service]);absent.pop('qualification_service_cleanup')
        path=copy.deepcopy(self.rows[service]);path['qualification_service_cleanup']['path']=str(self.repo/'different-proof.json')
        digest=copy.deepcopy(self.rows[service]);digest['qualification_service_cleanup']['sha256']='0'*64
        both=copy.deepcopy(path);both['qualification_service_cleanup']['sha256']='0'*64
        cases=[(inside,'qualification_owner_missing_selected'),(outside,'qualification_owner_missing_outside_selected'),
            (subtype,'qualification_owner_subtype_mismatch'),(absent,'qualification_cleanup_reference_missing'),
            (path,'qualification_cleanup_path_mismatch'),(digest,'qualification_cleanup_digest_mismatch'),
            (both,'qualification_cleanup_path_mismatch')]
        for value,code in cases:
            with self.subTest(code=code):
                authority_pure_call(gate._shape,value,value['launch_id'])
                with self.assertRaisesRegex(M.AdmissionDenied,'^'+code+'$'):
                    authority_pure_call(gate._profile,value)

    def test_known_owner_outside_selected_keeps_profile_and_unknown_selected_does_not(self):
        service=next(k for k,v in self.policy['qualification_owners'].items()if v['subtype']=='service')
        extra=self.record();policy=copy.deepcopy(self.policy)
        policy['expected_canonical_records'][extra['launch_id']]=M.digest(extra)
        policy['selected_task_records']=[k for k in policy['selected_task_records']if k!=service]+[extra['launch_id']]
        gate=M.AdmissionGate(policy);self.assertNotIn(service,policy['selected_task_records'])
        self.assertEqual(authority_pure_call(gate._profile,self.rows[service]),'service')
        ordinary=copy.deepcopy(extra)
        self.assertEqual(authority_pure_call(gate._profile,ordinary),'ordinary')
        ordinary.update(application_helper=True,client_mode='qualification-fixture')
        with self.assertRaisesRegex(M.AdmissionDenied,'^qualification_owner_missing_selected$'):
            authority_pure_call(gate._profile,ordinary)

    def test_preworker_presence_priority_and_existing_ordinary_owner_denials_remain(self):
        gate=M.AdmissionGate(self.policy)
        preworker=next(k for k,v in self.policy['qualification_owners'].items()if v['subtype']=='preworker')
        service=next(k for k,v in self.policy['qualification_owners'].items()if v['subtype']=='service')
        value=copy.deepcopy(self.rows[preworker]);value.pop('qualification_preworker_cleanup')
        authority_pure_call(gate._shape,value,value['launch_id'])
        with self.assertRaisesRegex(M.AdmissionDenied,'^known_owner_subtype_changed$'):
            authority_pure_call(gate._profile,value)
        value['qualification_service_cleanup']=copy.deepcopy(self.rows[service]['qualification_service_cleanup'])
        authority_pure_call(gate._shape,value,value['launch_id'])
        with self.assertRaisesRegex(M.AdmissionDenied,'^qualification_owner_subtype_mismatch$'):
            authority_pure_call(gate._profile,value)
        value=copy.deepcopy(self.rows[service]);value['application_helper']=False
        with self.assertRaisesRegex(M.AdmissionDenied,'^known_owner_subtype_changed$'):
            authority_pure_call(gate._profile,value)

    def test_profile_reference_missing_means_field_not_evidence_file(self):
        service=next(k for k,v in self.policy['qualification_owners'].items()if v['subtype']=='service')
        value=copy.deepcopy(self.rows[service]);path=Path(value['qualification_service_cleanup']['path'])
        raw=path.read_bytes();path.unlink()
        try:
            gate=M.AdmissionGate(self.policy)
            self.assertEqual(authority_pure_call(gate._profile,value),'service')
            value.pop('qualification_service_cleanup')
            with self.assertRaisesRegex(M.AdmissionDenied,'^qualification_cleanup_reference_missing$'):
                authority_pure_call(gate._profile,value)
        finally:path.write_bytes(raw);path.chmod(0o600)

    def test_profile_denial_follows_canonical_match_and_precedes_proof_reads(self):
        key=next(k for k in sorted(self.rows)if k not in self.policy['qualification_owners'])
        value=self.record(key);value.update(application_helper=True,client_mode='qualification-fixture')
        self.write_record(value)
        for match in (False,True):
            with self.subTest(canonical_match=match):
                policy=copy.deepcopy(self.policy)
                if match:policy['expected_canonical_records'][key]=M.digest(value)
                gate=M.AdmissionGate(policy);events=[];original_digest=M.digest;original_profile=gate._profile
                def watched_digest(item):
                    if type(item)is dict and item.get('launch_id')==key:events.append('canonical_hash')
                    return original_digest(item)
                def watched_profile(item):
                    if item['launch_id']==key:events.append('profile')
                    return original_profile(item)
                code='qualification_owner_missing_selected'if match else'canonical_record_changed'
                with mock.patch.object(M,'digest',side_effect=watched_digest), \
                     mock.patch.object(gate,'_profile',side_effect=watched_profile), \
                     mock.patch.object(gate,'_proof_headers',side_effect=forbidden), \
                     self.assertRaisesRegex(M.AdmissionDenied,'^'+code+'$'):
                    self.call(gate)
                self.assertEqual(events,['canonical_hash','profile']if match else['canonical_hash'])

    def test_malformed_reference_shape_stays_before_profile_and_catalog_is_153(self):
        key=sorted(self.rows)[0]
        for reference in (None,{},'unclassified',{'path':'relative','sha256':'a'*64},
                          {'path':str(self.repo/'unread'),'sha256':'a'*64,'extra':True}):
            with self.subTest(reference=reference):
                value=self.record(key);value.update(application_helper=True,client_mode='qualification-fixture',
                    qualification_service_cleanup=reference)
                self.write_record(value);gate=M.AdmissionGate(self.policy)
                with self.deny_target_hash(key),mock.patch.object(gate,'_profile',side_effect=forbidden), \
                     mock.patch.object(gate,'_proof_headers',side_effect=forbidden),self.assertRaises(M.AdmissionDenied):
                    self.call(gate)
        codes=set()
        for node in ast.walk(ast.parse(SOURCE_BYTES)):
            if isinstance(node,ast.Call)and isinstance(node.func,ast.Name):
                item=node.args[1]if node.func.id=='require'and len(node.args)>1 else node.args[0]if node.func.id=='AdmissionDenied'and node.args else None
                if isinstance(item,ast.Constant)and type(item.value)is str:codes.add(item.value)
        self.assertEqual(len(codes),153);self.assertNotIn('unknown_qualification_reference',codes)
        self.assertTrue({'qualification_owner_missing_selected','qualification_owner_missing_outside_selected',
            'qualification_owner_subtype_mismatch','qualification_cleanup_reference_missing',
            'qualification_cleanup_path_mismatch','qualification_cleanup_digest_mismatch'}<=codes)

    def marker_record(self,mask,key=None):
        value=self.record(key);value['application_helper']=True
        value['client_mode']='qualification-fixture'if mask&1 else'application-execution'
        if mask&2:value['qualification_role']='fixture'
        for bit,field,subtype in ((4,'qualification_service_cleanup','service'),
                                  (8,'qualification_preworker_cleanup','preworker')):
            if mask&bit:
                owner=next(k for k,v in self.policy['qualification_owners'].items()if v['subtype']==subtype)
                value[field]=copy.deepcopy(self.rows[owner][field])
        return value

    def test_source040_profile_fixture_is_exact_and_portable(self):
        old=source040_profile_comparator()
        self.assertEqual(old.__name__,'_profile')
        self.assertEqual(SOURCE040_PROFILE_AST_SHA256,'947e8d7d0d92d67a1ce5ec6150f281c61c5c06323777fc43d1b43ceee54dadb8')
        self.assertNotIn('read_bytes',SOURCE040_PROFILE_CODE)
        self.assertNotIn('source040-preservation',SOURCE040_PROFILE_CODE)

    def test_all_missing_owner_marker_masks_preserve_source040_type_args_and_denial(self):
        old=source040_profile_comparator();gate=M.AdmissionGate(self.policy)
        selected=next(k for k in self.rows if k not in self.policy['qualification_owners'])
        for mask in range(1,16):
            for inside in (False,True):
                with self.subTest(mask=mask,inside_selected=inside):
                    value=self.marker_record(mask,selected if inside else None)
                    authority_pure_call(gate._shape,value,value['launch_id'])
                    with self.assertRaises(M.AdmissionDenied)as prior:
                        authority_pure_call(old,gate,value)
                    with self.assertRaises(M.AdmissionDenied)as current:
                        authority_pure_call(gate._profile,value)
                    code='qualification_owner_missing_selected'if inside else'qualification_owner_missing_outside_selected'
                    self.assertIs(type(current.exception),M.AdmissionDenied)
                    self.assertIs(type(prior.exception),M.AdmissionDenied)
                    self.assertEqual(current.exception.args,prior.exception.args)
                    self.assertEqual(current.exception.args,(code,))
                    markers=current.exception.qualification_profile_markers
                    self.assertIs(type(markers),tuple);self.assertEqual(len(markers),2)
                    self.assertIs(type(markers[0]),str);self.assertIs(type(markers[1]),int)
                    self.assertEqual(markers,('preworker'if mask&8 else'service',mask))
                    self.assertEqual(current.exception.__dict__,{'qualification_profile_markers':markers})
                    self.assertFalse(hasattr(prior.exception,'qualification_profile_markers'))

    def test_missing_owner_marker_priority_and_field_presence_do_not_attribute_a_producer(self):
        gate=M.AdmissionGate(self.policy)
        for mask in (2,4,8,12,13,14,15):
            with self.subTest(mask=mask):
                value=self.marker_record(mask)
                if mask&1:value['client_mode']='qualification-unrecognized-public-shape'
                if mask&2:value['qualification_role']='unrecognized-role'
                for field in ('qualification_service_cleanup','qualification_preworker_cleanup'):
                    if field in value:
                        value[field]={'path':str(self.repo/('unopened-'+field)), 'sha256':'e'*64}
                authority_pure_call(gate._shape,value,value['launch_id'])
                with self.assertRaises(M.AdmissionDenied)as caught:
                    authority_pure_call(gate._profile,value)
                self.assertEqual(caught.exception.qualification_profile_markers,
                    ('preworker'if mask&8 else'service',mask))
                self.assertEqual(set(caught.exception.__dict__),{'qualification_profile_markers'})

    def test_marker_attribute_is_absent_on_all_other_profile_denials_and_accepted_rows(self):
        old=source040_profile_comparator();gate=M.AdmissionGate(self.policy)
        service=next(k for k,v in self.policy['qualification_owners'].items()if v['subtype']=='service')
        preworker=next(k for k,v in self.policy['qualification_owners'].items()if v['subtype']=='preworker')
        accepted=[self.record(),copy.deepcopy(self.rows[service]),copy.deepcopy(self.rows[preworker])]
        for mode in ('authority-only','application-execution','budget-only'):
            value=self.record();value.update(application_helper=True,client_mode=mode);accepted.append(value)
        for value in accepted:
            authority_pure_call(gate._shape,value,value['launch_id'])
            self.assertEqual(authority_pure_call(old,gate,value),authority_pure_call(gate._profile,value))
        denied=[]
        value=copy.deepcopy(self.rows[service]);value['application_helper']=False;denied.append(value)
        value=copy.deepcopy(self.rows[service]);value['qualification_preworker_cleanup']=copy.deepcopy(
            self.rows[preworker]['qualification_preworker_cleanup']);denied.append(value)
        value=copy.deepcopy(self.rows[service]);value.pop('qualification_service_cleanup');denied.append(value)
        for field,item in (('path',str(self.repo/'different-unopened-proof')),('sha256','f'*64)):
            value=copy.deepcopy(self.rows[service]);value['qualification_service_cleanup'][field]=item;denied.append(value)
        value=copy.deepcopy(self.rows[service]);value['mounts'][0]['source']=str(self.repo/'different-private');denied.append(value)
        value=copy.deepcopy(self.rows[preworker]);value.pop('qualification_preworker_cleanup');denied.append(value)
        for value in denied:
            authority_pure_call(gate._shape,value,value['launch_id'])
            with self.assertRaises(M.AdmissionDenied)as prior:
                authority_pure_call(old,gate,value)
            with self.assertRaises(M.AdmissionDenied)as current:
                authority_pure_call(gate._profile,value)
            self.assertEqual(current.exception.args,prior.exception.args)
            self.assertFalse(hasattr(current.exception,'qualification_profile_markers'))

    def test_marker_derivation_adds_no_io_hash_or_record_reference(self):
        gate=M.AdmissionGate(self.policy);value=self.marker_record(15)
        value['client_mode']='qualification-INERT_SENTINEL'
        value['qualification_role']='INERT_SENTINEL_ROLE'
        value['qualification_service_cleanup']['path']=str(self.repo/'INERT_SENTINEL_SERVICE')
        value['qualification_preworker_cleanup']['path']=str(self.repo/'INERT_SENTINEL_PREWORKER')
        with mock.patch('builtins.open',side_effect=forbidden), \
             mock.patch.object(Path,'resolve',side_effect=forbidden), \
             mock.patch.object(Path,'read_bytes',side_effect=forbidden), \
             mock.patch.object(Path,'read_text',side_effect=forbidden):
            authority_pure_call(gate._shape,value,value['launch_id'])
            with self.assertRaises(M.AdmissionDenied)as caught:
                authority_pure_call(gate._profile,value)
        self.assertEqual(caught.exception.__dict__,{'qualification_profile_markers':('preworker',15)})
        wire=json.dumps(caught.exception.__dict__,sort_keys=True)
        for text in ('INERT_SENTINEL',value['launch_id'],str(self.repo),'sha256','qualification_service_cleanup'):
            self.assertNotIn(text,wire)
        value.clear()
        self.assertEqual(caught.exception.qualification_profile_markers,('preworker',15))

    def test_marker_denial_retains_shape_canonical_profile_and_proof_order(self):
        key=next(k for k in sorted(self.rows)if k not in self.policy['qualification_owners'])
        for phase in ('shape','canonical','profile'):
            with self.subTest(phase=phase):
                value=self.marker_record(15,key)
                if phase=='shape':value['qualification_service_cleanup']['extra']=True
                self.write_record(value);policy=copy.deepcopy(self.policy)
                if phase=='profile':policy['expected_canonical_records'][key]=M.digest(value)
                gate=M.AdmissionGate(policy);events=[]
                original_shape=gate._shape;original_digest=M.digest;original_profile=gate._profile
                def watched_shape(item,identifier):
                    if identifier==key:events.append('shape')
                    return original_shape(item,identifier)
                def watched_digest(item):
                    if type(item)is dict and item.get('launch_id')==key:events.append('canonical')
                    return original_digest(item)
                def watched_profile(item):
                    if item['launch_id']==key:events.append('profile')
                    return original_profile(item)
                with mock.patch.object(gate,'_shape',side_effect=watched_shape), \
                     mock.patch.object(M,'digest',side_effect=watched_digest), \
                     mock.patch.object(gate,'_profile',side_effect=watched_profile), \
                     mock.patch.object(gate,'_proof_headers',side_effect=forbidden), \
                     self.assertRaises(M.AdmissionDenied)as caught:
                    self.call(gate)
                self.assertEqual(events,{'shape':['shape'],'canonical':['shape','canonical'],
                    'profile':['shape','canonical','profile']}[phase])
                if phase=='profile':
                    self.assertEqual(caught.exception.args,('qualification_owner_missing_selected',))
                    self.assertEqual(caught.exception.qualification_profile_markers,('preworker',15))
                else:self.assertFalse(hasattr(caught.exception,'qualification_profile_markers'))

    def test_marker_evidence_is_not_shared_with_later_independent_exceptions(self):
        gate=M.AdmissionGate(self.policy);value=self.marker_record(1)
        with self.assertRaises(M.AdmissionDenied)as first:
            authority_pure_call(gate._profile,value)
        value=self.marker_record(8)
        with self.assertRaises(M.AdmissionDenied)as second:
            authority_pure_call(gate._profile,value)
        self.assertIsNot(first.exception,second.exception)
        self.assertEqual(first.exception.qualification_profile_markers,('service',1))
        self.assertEqual(second.exception.qualification_profile_markers,('preworker',8))
        fresh=M.AdmissionDenied('qualification_cleanup_path_mismatch')
        self.assertEqual(fresh.args,('qualification_cleanup_path_mismatch',))
        self.assertFalse(hasattr(fresh,'qualification_profile_markers'))

    def test_source041_call_fixture_is_exact_and_portable(self):
        old=source041_call_comparator()
        self.assertEqual(old.__name__,'__call__')
        self.assertEqual(SOURCE041_CALL_AST_SHA256,'ac06cc4aa6f6aac8405da23451c1aeb9b48f8847940a5c12cf5555e2b0558a57')
        self.assertNotIn('read_bytes',SOURCE041_CALL_CODE)
        self.assertNotIn('source041-preservation',SOURCE041_CALL_CODE)

    def test_public_selector_first_last_and_middle_follow_sorted_public_map(self):
        first='00000000-0000-0000-0000-000000000000'
        last='ffffffff-ffff-ffff-ffff-ffffffffffff'
        middle='88888888-8888-4888-8888-888888888888'
        for target,position in ((first,'first'),(last,'last'),(middle,'middle')):
            with self.subTest(position=position):
                policy=copy.deepcopy(self.policy);extra={target:self.marker_record(7,target)}
                if position=='middle':extra.update({first:self.record(first),last:self.record(last)})
                self.assertTrue(set(extra).isdisjoint(self.rows))
                try:
                    for key,value in extra.items():
                        self.write_record(value);policy['expected_canonical_records'][key]=M.digest(value)
                    # Deliberately reverse insertion order; only sorted keys govern.
                    policy['expected_canonical_records']=dict(reversed(list(policy['expected_canonical_records'].items())))
                    keys=sorted(policy['expected_canonical_records']);ordinal=keys.index(target)
                    if position=='first':self.assertEqual(ordinal,0)
                    elif position=='last':self.assertEqual(ordinal,len(keys)-1)
                    else:self.assertTrue(0<ordinal<len(keys)-1)
                    gate=M.AdmissionGate(policy)
                    with mock.patch.object(gate,'_proof_headers',side_effect=forbidden), \
                         self.assertRaises(M.AdmissionDenied)as caught:
                        self.call(gate)
                    self.assertEqual(caught.exception.args,('qualification_owner_missing_outside_selected',))
                    self.assertEqual(caught.exception.qualification_profile_markers,('service',7))
                    self.assertEqual(caught.exception.qualification_baseline_selector,
                        (ordinal,len(keys),M.digest(policy['expected_canonical_records'])))
                finally:
                    for key in extra:(self.rroot/(key+'.json')).unlink()

    def test_public_selector_rethrows_same_error_without_catch_clock_or_later_work(self):
        key='00000000-0000-0000-0000-000000000000';value=self.marker_record(7,key)
        self.write_record(value);policy=copy.deepcopy(self.policy)
        policy['expected_canonical_records'][key]=M.digest(value);gate=M.AdmissionGate(policy)
        error=M.AdmissionDenied('qualification_owner_missing_outside_selected')
        error.qualification_profile_markers=('service',7);events=[];in_handler={'value':False}
        original_digest=M.digest;original_fence=gate._fence
        original_mono=M.time.monotonic;original_wall=M.time.time
        def failed_profile(item):
            self.assertEqual(item['launch_id'],key);events.append('profile')
            in_handler['value']=True;raise error
        def watched_digest(item):
            if item is gate.expected:events.append('public_map_hash')
            return original_digest(item)
        def fenced():
            if in_handler['value']:forbidden()
            return original_fence()
        def mono():
            if in_handler['value']:forbidden()
            return original_mono()
        def wall():
            if in_handler['value']:forbidden()
            return original_wall()
        with mock.patch.object(gate,'_profile',side_effect=failed_profile), \
             mock.patch.object(M,'digest',side_effect=watched_digest), \
             mock.patch.object(gate,'_fence',side_effect=fenced), \
             mock.patch.object(M.time,'monotonic',side_effect=mono), \
             mock.patch.object(M.time,'time',side_effect=wall), \
             mock.patch.object(gate,'_proof_headers',side_effect=forbidden), \
             self.assertRaises(M.AdmissionDenied)as caught:
            self.call(gate)
        self.assertIs(caught.exception,error);self.assertIs(type(error),M.AdmissionDenied)
        self.assertEqual(error.args,('qualification_owner_missing_outside_selected',))
        self.assertEqual(events,['profile','public_map_hash'])
        self.assertEqual(error.qualification_baseline_selector,(0,len(gate.expected),M.digest(gate.expected)))

    def test_public_selector_rejects_other_errors_and_opaque_or_malformed_markers(self):
        class ChildDenied(M.AdmissionDenied):pass
        class Text(str):pass
        class Number(int):pass
        class Opaque:
            def __eq__(self,other):forbidden()
            def __str__(self):forbidden()
            def __repr__(self):forbidden()
        class OpaqueDict(dict):
            def get(self,*args):forbidden()
        code='qualification_owner_missing_outside_selected';errors=[]
        for args in ((),(code,'extra'),(Opaque(),),(Text(code),),
                     ('qualification_owner_missing_selected',),('qualification_cleanup_path_mismatch',)):
            error=M.AdmissionDenied(*args);error.qualification_profile_markers=('service',7);errors.append(error)
        error=ChildDenied(code);error.qualification_profile_markers=('service',7);errors.append(error)
        errors.append(M.AdmissionDenied(code))
        for markers in (None,[],{},Opaque(),('service',),('service',7,'extra'),
                        (Text('service'),7),('service',Number(7)),('service',True),('service',7.0),
                        ('preworker',7),('preworker',8),('service',1),('service',3),('service',8)):
            error=M.AdmissionDenied(code);error.qualification_profile_markers=markers;errors.append(error)
        error=M.AdmissionDenied(code);error.__dict__=OpaqueDict(qualification_profile_markers=('service',7));errors.append(error)
        key='00000000-0000-0000-0000-000000000000';value=self.marker_record(7,key)
        self.write_record(value);policy=copy.deepcopy(self.policy);policy['expected_canonical_records'][key]=M.digest(value)
        for index,error in enumerate(errors):
            with self.subTest(index=index):
                gate=M.AdmissionGate(policy);original_digest=M.digest
                def no_public_hash(item):
                    if item is gate.expected:forbidden()
                    return original_digest(item)
                with mock.patch.object(gate,'_profile',side_effect=error), \
                     mock.patch.object(M,'digest',side_effect=no_public_hash), \
                     mock.patch.object(gate,'_proof_headers',side_effect=forbidden), \
                     self.assertRaises(M.AdmissionDenied)as caught:
                    self.call(gate)
                self.assertIs(caught.exception,error)
                self.assertNotIn('qualification_baseline_selector',error.__dict__)

    def test_public_selector_requires_caller_shape_hash_and_outside_denial(self):
        key='00000000-0000-0000-0000-000000000000';direct=self.marker_record(7,key)
        gate=M.AdmissionGate(self.policy)
        with self.assertRaises(M.AdmissionDenied)as caught:
            authority_pure_call(gate._profile,direct)
        self.assertEqual(caught.exception.qualification_profile_markers,('service',7))
        self.assertFalse(hasattr(caught.exception,'qualification_baseline_selector'))
        for phase in ('shape','canonical'):
            with self.subTest(phase=phase):
                value=self.marker_record(7,key);policy=copy.deepcopy(self.policy)
                policy['expected_canonical_records'][key]=M.digest(value)
                if phase=='shape':value['qualification_service_cleanup']['extra']=True
                else:value['qualification_role']='different-synthetic-role'
                self.write_record(value);gate=M.AdmissionGate(policy);original_digest=M.digest
                def no_public_hash(item):
                    if item is gate.expected:forbidden()
                    return original_digest(item)
                with mock.patch.object(gate,'_profile',side_effect=forbidden), \
                     mock.patch.object(M,'digest',side_effect=no_public_hash), \
                     mock.patch.object(gate,'_proof_headers',side_effect=forbidden), \
                     self.assertRaises(M.AdmissionDenied)as caught:
                    self.call(gate)
                self.assertFalse(hasattr(caught.exception,'qualification_baseline_selector'))
        (self.rroot/(key+'.json')).unlink()
        key=next(k for k in self.rows if k not in self.policy['qualification_owners'])
        value=self.marker_record(7,key);self.write_record(value);policy=copy.deepcopy(self.policy)
        policy['expected_canonical_records'][key]=M.digest(value);gate=M.AdmissionGate(policy)
        with mock.patch.object(gate,'_proof_headers',side_effect=forbidden), \
             self.assertRaises(M.AdmissionDenied)as caught:
            self.call(gate)
        self.assertEqual(caught.exception.args,('qualification_owner_missing_selected',))
        self.assertFalse(hasattr(caught.exception,'qualification_baseline_selector'))

    def test_public_selector_accepted_path_matches_portable_source041_caller(self):
        previous=source041_call_comparator();old_gate=M.AdmissionGate(self.policy);new_gate=M.AdmissionGate(self.policy)
        # These existing hooks expressly limit this to custody/orchestration;
        # original semantic proof validation is NOT claimed by this test.
        with self.inert_headers(),self.inert_conservation():
            previous(old_gate,lease_fd=self.lfd,lock_path=self.lock,registry_root=self.rroot)
            self.call(new_gate)
        self.assertEqual(old_gate.witness,new_gate.witness)
        self.assertNotIn('qualification_baseline_selector',new_gate.witness)

    def test_public_selector_hashes_only_bounded_public_map_and_retains_no_record(self):
        key='00000000-0000-0000-0000-000000000000';value=self.marker_record(7,key)
        value['client_mode']='qualification-INERT_SELECTOR_SENTINEL'
        value['qualification_role']='INERT_SELECTOR_SENTINEL_ROLE'
        value['qualification_service_cleanup']['path']=str(self.repo/'INERT_SELECTOR_SENTINEL_REF')
        self.write_record(value);policy=copy.deepcopy(self.policy);policy['expected_canonical_records'][key]=M.digest(value)
        gate=M.AdmissionGate(policy);in_handler={'value':False};hashes=[]
        original_profile=gate._profile;original_digest=M.digest
        original_open=M.os.open;original_stat=M.os.stat;original_lstat=M.os.lstat
        def profile(item):
            try:return original_profile(item)
            finally:
                if item['launch_id']==key:in_handler['value']=True
        def public_hash(item):
            if item is gate.expected:
                self.assertTrue(in_handler['value']);hashes.append('public_expected_map')
                self.assertLessEqual(len(item),8192)
                self.assertTrue(all(M.identifier(k)and M.sha(v)for k,v in item.items()))
                self.assertLessEqual(len(M.canonical(item)),106*len(item)+1)
            return original_digest(item)
        def opened(*args,**kwargs):
            if in_handler['value']:forbidden()
            return original_open(*args,**kwargs)
        def stated(*args,**kwargs):
            if in_handler['value']:forbidden()
            return original_stat(*args,**kwargs)
        def lstated(*args,**kwargs):
            if in_handler['value']:forbidden()
            return original_lstat(*args,**kwargs)
        with mock.patch.object(gate,'_profile',side_effect=profile), \
             mock.patch.object(M,'digest',side_effect=public_hash), \
             mock.patch.object(M.os,'open',side_effect=opened), \
             mock.patch.object(M.os,'stat',side_effect=stated), \
             mock.patch.object(M.os,'lstat',side_effect=lstated), \
             mock.patch.object(Path,'resolve',side_effect=forbidden), \
             mock.patch('builtins.open',side_effect=forbidden), \
             mock.patch.object(gate,'_proof_headers',side_effect=forbidden), \
             self.assertRaises(M.AdmissionDenied)as caught:
            self.call(gate)
        self.assertEqual(hashes,['public_expected_map'])
        selector=caught.exception.qualification_baseline_selector
        self.assertIs(type(selector),tuple);self.assertEqual(len(selector),3)
        self.assertIs(type(selector[0]),int);self.assertIs(type(selector[1]),int);self.assertIs(type(selector[2]),str)
        self.assertEqual(selector,(0,len(gate.expected),M.digest(gate.expected)))
        self.assertEqual(set(caught.exception.__dict__),{'qualification_profile_markers','qualification_baseline_selector'})
        serialized=json.dumps(caught.exception.__dict__,sort_keys=True)
        for text in ('INERT_SELECTOR_SENTINEL',key,str(self.repo),'qualification_service_cleanup'):
            self.assertNotIn(text,serialized)
        value.clear();self.assertEqual(caught.exception.qualification_baseline_selector,selector)


if __name__=='__main__':
    previous=signal.signal(signal.SIGALRM,lambda *_:os._exit(124));signal.alarm(30)
    try:unittest.main(verbosity=2)
    finally:signal.alarm(0);signal.signal(signal.SIGALRM,previous)
