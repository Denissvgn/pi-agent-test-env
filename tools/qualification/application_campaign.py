"""One explicitly authorized maintainer window; auxiliary attempts never reset caps.

This is a fixed diagnostic accounting boundary, not a participant API. The
trusted parent owns the original operation lease, child lifecycle and dummy
stdin. No real credential store, inference, Pi or application request is used.
"""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import uuid

import application_launch as launch

REPO=Path(__file__).resolve().parents[2]
AUTHORIZATION_PATH=REPO/'reports/application-agent-enhancements/A15/campaign-window-002-authorization.json'
AUTHORIZATION_SHA256='96eb796121279a8b42de0f7dc765155aa9a663b00bb1fa6e5db080fbb0547c9f'
AUTHORIZATION_ID='ae0a11fc-e188-46a4-b6e7-a50b7918f734'
BASE_PREDECESSOR_REFERENCE={'path':str(REPO/'reports/application-agent-enhancements/preparation/qualification-design/resumption-008/base-predecessor-007.json'),
    'sha256':'c7a406524cdd55f476995aa1cc63ef2e809fd7d3506c536e70a66af10d40a375'}
AUXILIARY_ROOT=REPO/'reports/application-agent-enhancements/A15/campaign-002/auxiliary'
FINAL_ROOT=REPO/'reports/application-agent-enhancements/A15/attempt-008/qualification'
KNOWN_AUXILIARY_INCIDENT={
    'binding_sha256':'710f5674ab772db745e1a0dfa8f17d82fe4d734ac494db421a4afd070c360665',
    'ledger_sha256':'3de4dc47474b8e56a78753fd3bb3e189eb766ae1199950a35903b93377819f78',
    'dispatch_sha256':'084fe8742b5c9e9864ba7824d980089e7304367f9c5bfe4935e16e961d85d259',
    'recipe_sha256':'1c21ec2f53cbf73d7c3764b4d92a53e29364163160bce323951f62da0d069fa1',
    'intent_marker_sha256':'d9df5a92536119561a28d6d73fe80edc9099b6057c96f458766b95f7573e6c6e',
    'source_record_sha256':'e7d428215aaf3816d03cfb6da25a161282989b3a0292f6940ac9713b0e6130ee',
    'launch_id':'6eee9c4d-6414-4c4f-90b8-d517cb4862a2',
    'registry':'40e5a29c1ae9625ec57101d2a98159a29b1606b8ea557d85865429baf9d306dd',
    'generation':'725c75d3-0baf-4d9f-8954-5f487f541df2',
    'intent_sha256':'c34b689164c21aa4943af70035a66b8c7915d4ec74e329820737d7a2b4e56455',
    'container_id':'a23a0684f378c05519d55feaa632a2744058ebb440558b72bcb06ab66c87e21e',
    'owner_pid':16192,'docker_cli_pid':16276,
    'controller_sha256':'c093e7e63353b63c25e256ea5fa9bf9acca1efa97868403cf09442dcc61c47bf',
    'command_sha256':'203ba2d9033230b9051e386e8c956680243197ba29c50dd27f66922d5fec5534',
    'failure_sha256':'2e85f779c9e14b9719e115b5484b97e6d88b7209aad20ef93c36d94670c97c9e',
}
IMAGE='sha256:47856fc949cc114980b4befa37bf6ae17711e84b56be2fb5370fe66e1d216102'
RESOURCES={'cpu_millis':1000,'memory_mib':512,'pids_limit':128}
INPUT_FILES={'guest.py','service_wrapper.py','diagnostic_instrumentation.py','parent_control.py','plan.json','binding.json'}
CODE_FILES={'runtime/application_client_service.py','runtime/prompt_contract.py','scripts/application_contracts.py','scripts/application_documents.py',
    'scripts/resources.py','scripts/application_credentials.py','scripts/secret_store.py','scripts/stage_control.py','runtime/native_budget_service.py',
    'runtime/application_budget.py','scripts/tool_budgets.py','runtime/native_tool_contracts.py','runtime/release_contracts.py','runtime/application_execution_service.py',
    'runtime/application_api.py','runtime/application_browser.py','runtime/application-browser-cdp.mjs','runtime/application_runtime_contracts.py',
    'scripts/application_evidence.py','runtime/application_files.py'}
APPROVED_CODE_REVISIONS=({'runtime/application_client_service.py': 'b8d78a4f6c126186ff397fef6d641fe5d3989d22dc1df602cad14a0322bd95c9', 'runtime/prompt_contract.py': 'b9ee3219ca69b5070bede3d8043bf56d3328a0d967eca3d7826ac3125f8c4a2a', 'scripts/application_contracts.py': 'e88d6d7ad0d6bd63ae2a86205bba025c20cc7a658861e78883c7840b3eae2e38', 'scripts/application_documents.py': '744bfd44c270df608ac4241fb45dac30d849b37a16a1cf9b85b1942119204eb7', 'scripts/resources.py': '6da033dc55290c666efa61cc759dee0a0ef2e5c0091d855346c116c5f41cfb40', 'scripts/application_credentials.py': '3e35239aefbfee5433bb208a0928ed668a6b7daa5daca999b2feac4306b0ec11', 'scripts/secret_store.py': '62ed60b44d1cc24955a4d0481a833aea493c98e2d709a3cc66496f28d9d94add', 'scripts/stage_control.py': '63754ea74e3d1f551f42f1c6b35d139c1f483b8fea4e416dff0cdd8e2020f12c', 'runtime/native_budget_service.py': 'a0027475d59ac4898ce83205695fe3bd8ec839222a05c3246fb2d15ee665bd32', 'runtime/application_budget.py': '724156cd427fa4e03181e894848984e91a33e4f79dc0fe06fa6e0f5619674f48', 'scripts/tool_budgets.py': 'ec70e195d5546c55c4a40f276bf5e6976ccfcd401ca6a91e7f8e3837890d36be', 'runtime/native_tool_contracts.py': '74e3973b85effe605dd402f5ea3deaf237bd4eba8bfb195a5995c8f8590cc372', 'runtime/release_contracts.py': '5633815c7f17fff542a15f0f42b0f591f4b749a897932f6e6686f7821d69ea0f', 'runtime/application_execution_service.py': 'c0fcab1189ea997997d65eba6123a047f954a26b3e9e050d3e37e8b7ddf930a2', 'runtime/application_api.py': '7a2abeb910c03683b7718f539f198408be9cc3dcef52ad15d0c9bc83e52aa417', 'runtime/application_browser.py': '3e851d3cb78c5c6f42730b80b2704029e1771230081ec09c64096d5d3aeaceef', 'runtime/application-browser-cdp.mjs': '4de80d59e4854241a10ca3be152abc803d9cd8e00cf2425b1cc8ea15c87db2fe', 'runtime/application_runtime_contracts.py': '88308f5db6ee60d49c6027f3c88e099c6c6287bf793f2bc57060730f26da5636', 'scripts/application_evidence.py': '6ebc35b295848ee7fe2d8db9e0bc7fd834ff42f1aef7debf9b2ee21f3b046d88', 'runtime/application_files.py': 'cada70f275cf119955f863aa157f1467ec93e222500bfb8f27de36463835a782'},)
APPROVED_INPUT_REVISIONS=({'guest.py': '45f7b93252e9be82fa0ac201ff52095308a94c40ec5c487ba827714834ec7aa0', 'service_wrapper.py': '18dab15aa19a0f5ef9db4d67caa03eb5283b755d47186260bd946fcb79ff1398', 'diagnostic_instrumentation.py': 'c0e61f0383d8072b41ba9dd123acc3bca0da7d2ce3bb1523a3005f8d84af4579', 'parent_control.py': 'a42f378d640b9b4d118f53ecde096e28e0de48c941b8dcca787ee03349c68932', 'plan.json': 'e8cbcb7cc9e56e55113c8bd1dbb60f95b670204d114308b438cf93ea8598db09', 'binding.json': 'b955594f9708c46ba667acd7339c00efd651b89006055b78282fb3d66a66ae0e'}, {'guest.py': '3e2285680f8f89654b80c9b6f11cf5c8919ebba207721e3986efc205bef4653b', 'service_wrapper.py': '18dab15aa19a0f5ef9db4d67caa03eb5283b755d47186260bd946fcb79ff1398', 'diagnostic_instrumentation.py': 'c0e61f0383d8072b41ba9dd123acc3bca0da7d2ce3bb1523a3005f8d84af4579', 'parent_control.py': 'a42f378d640b9b4d118f53ecde096e28e0de48c941b8dcca787ee03349c68932', 'plan.json': 'e8cbcb7cc9e56e55113c8bd1dbb60f95b670204d114308b438cf93ea8598db09', 'binding.json': 'b955594f9708c46ba667acd7339c00efd651b89006055b78282fb3d66a66ae0e'})
TARGETS=(('code','/opt/pi-application',False),('inputs','/diagnostic-inputs',False),('state','/pi-client/state',True),('evidence','/pi-client/evidence',True))
APPROVED_PUBLISHED_INPUT_REVISIONS=({'guest.py': '72f3c678fc6b2dd600b6b57939ca5670695d97e3ce9b5d2b01b954eea6f69d51', 'service_wrapper.py': '095af773734b644e3de87e773b9f37fd67a7694dd0be3bbe48214322cfee8fa1', 'diagnostic_instrumentation.py': 'c0e61f0383d8072b41ba9dd123acc3bca0da7d2ce3bb1523a3005f8d84af4579', 'parent_control.py': 'a42f378d640b9b4d118f53ecde096e28e0de48c941b8dcca787ee03349c68932', 'plan.json': 'e8cbcb7cc9e56e55113c8bd1dbb60f95b670204d114308b438cf93ea8598db09', 'binding.json': 'b955594f9708c46ba667acd7339c00efd651b89006055b78282fb3d66a66ae0e'},)


def deny():raise launch.LaunchError('qualification_campaign_boundary_invalid')
def require(condition):
    if not condition:deny()
def exact(value,fields):launch._exact(value,set(fields))
def digest(value):return launch._digest(value)
def read(path,sha=None):return launch._bound_json(path,sha)
def ref(path):
    path=Path(path);folder=launch._dir(path.parent,False)
    try:
        fd=launch._file(folder,path.name,os.O_RDONLY)
        with os.fdopen(fd,'rb') as stream:body=stream.read(launch.MAX_BYTES+1)
        require(len(body)<=launch.MAX_BYTES);return {'path':str(path),'sha256':hashlib.sha256(body).hexdigest()}
    finally:os.close(folder)

def reference(value):
    exact(value,{'path','sha256'});launch._sha(value['sha256']);launch._canonical_root(value['path']);return read(value['path'],value['sha256'])

def exclusive(path,value):
    path=Path(path);folder=launch._dir(path.parent,False)
    try:
        fd=launch._file(folder,path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL)
        with os.fdopen(fd,'wb') as stream:stream.write(launch._json(value));stream.flush();os.fsync(stream.fileno())
        os.fsync(folder)
    finally:os.close(folder)
    return ref(path)


def authorization(reference_value,base,clock,wall,*,window=True):
    require(reference_value=={'path':str(AUTHORIZATION_PATH),'sha256':AUTHORIZATION_SHA256})
    value=reference(reference_value)
    exact(value,{'schema','document_type','authorization_id','authorization','original_deadline_wall','started_wall','started_monotonic','deadline_wall','deadline_monotonic',
        'window_seconds','cumulative_container_launches','cumulative_participant_segments','container_cap','participant_cap','live_cap','trial_cap','inference_slot_cap',
        'platform','automatic_retries','continuations','prior_campaign_modified','new_native_admission_requires_positive_owned_cleanup','created_utc','deadline_utc','deadline_madrid'})
    fixed={'schema':1,'document_type':'qualification_window_authorization','authorization_id':AUTHORIZATION_ID,'window_seconds':14400,'cumulative_container_launches':51,
        'cumulative_participant_segments':0,'container_cap':240,'participant_cap':24,'live_cap':4,'trial_cap':1,'inference_slot_cap':1,'platform':'linux/arm64',
        'automatic_retries':0,'continuations':0,'prior_campaign_modified':False,'new_native_admission_requires_positive_owned_cleanup':True}
    for key,expected in fixed.items():require(type(value[key]) is type(expected) and value[key]==expected)
    require(value['original_deadline_wall']==base['deadline_wall'] and value['deadline_wall']==value['started_wall']+14400
        and value['deadline_monotonic']==value['started_monotonic']+14400)
    now,wallnow=launch._number(clock()),launch._number(wall())
    require(now>=value['started_monotonic'] and wallnow>=value['started_wall'])
    if window:require(now<value['deadline_monotonic']-30 and wallnow<value['deadline_wall']-30)
    return value


def base_carry(predecessor,clock,wall):
    require(launch._json(predecessor)==launch._json(reference(BASE_PREDECESSOR_REFERENCE)))
    base=launch.validate_predecessor(predecessor,clock=clock,wall=wall,_launch_window=False)
    require(base['attempts']==51 and base['participant_segments']==0 and base['planned_cells']==196 and len(base['lineage'])==7)
    require(len(predecessor['cleanup_receipts'])==1 and reference(predecessor['cleanup_receipts'][0]).get('document_type')=='qualification_known_preworker_cleanup')
    return base


def _claim_names(base_predecessor,base):
    root=launch._canonical_root(base_predecessor['root'])
    return root.parent/'campaign-successor-claims',digest({'root':str(root),'qualification_id':base['qualification_id']})


def _fence(binding,base,*,create=False):
    folder_path,name=_claim_names(binding['base_predecessor'],base);parent=launch._dir(folder_path.parent,False);folder=lock=None
    try:
        if create:
            try:os.mkdir(folder_path.name,0o700,dir_fd=parent);os.fsync(parent)
            except FileExistsError:pass
        folder=os.open(folder_path.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        require(stat.S_IMODE(os.fstat(folder).st_mode)==0o700 and os.fstat(folder).st_uid==os.getuid())
        # Use exactly the legacy predecessor slot. Its EXCL lock prevents even
        # old non-boundary launch code from creating a competing eighth root.
        lock=launch._file(folder,name+'.lock',os.O_RDWR|(os.O_CREAT|os.O_EXCL if create else 0));os.fsync(lock);os.fsync(folder)
        fcntl.flock(lock,fcntl.LOCK_EX)
        expected={'schema':1,'document_type':'qualification_campaign_boundary_fence','binding_sha256':digest(binding),'auxiliary_root':binding['root'],
            'final_root':binding['final_root'],'authorization':binding['authorization'],'base_predecessor':binding['base_predecessor']}
        auth_name='authorization-'+AUTHORIZATION_ID
        if create:
            # Both claims are permanent. A crash at any intermediate point
            # leaves a closed slot, never permission to create another window.
            auth_lock=launch._file(folder,auth_name+'.lock',os.O_RDWR|os.O_CREAT|os.O_EXCL);os.fsync(auth_lock);os.close(auth_lock);os.fsync(folder)
            for filename in (name+'.json',auth_name+'.json'):
                fd=launch._file(folder,filename,os.O_WRONLY|os.O_CREAT|os.O_EXCL)
                with os.fdopen(fd,'wb') as stream:stream.write(launch._json(expected));stream.flush();os.fsync(stream.fileno())
                os.fsync(folder)
        auth_lock=launch._file(folder,auth_name+'.lock',os.O_RDWR);os.close(auth_lock)
        require(launch._read(folder,name+'.json')==expected and launch._read(folder,auth_name+'.json')==expected)
        return expected
    finally:
        if lock is not None:os.close(lock)
        if folder is not None:os.close(folder)
        os.close(parent)


def _binding(value,clock,wall,*,window=False):
    exact(value,{'schema','document_type','root','final_root','base_predecessor','authorization','daemon','daemon_capacity','base_identity'})
    require(type(value['schema']) is int and value['schema']==1 and value['document_type']=='qualification_auxiliary_campaign'
        and value['root']==str(AUXILIARY_ROOT) and value['final_root']==str(FINAL_ROOT))
    launch._canonical_root(value['root']);launch._canonical_root(value['final_root'])
    base=base_carry(value['base_predecessor'],clock,wall)
    require(value['daemon']==base['daemon'] and value['daemon_capacity']==base['daemon_capacity'])
    expected={key:base[key] for key in ('attempts','participant_segments','planned_cells','qualification_id','started','deadline','started_wall','deadline_wall','lineage')}
    require(launch._json(value['base_identity'])==launch._json(expected));auth=authorization(value['authorization'],base,clock,wall,window=window)
    return base,auth


def _lease(fd,binding):
    manifest=read(Path(binding['base_predecessor']['root'])/'manifest.json',binding['base_predecessor']['manifest_sha256'])
    path=Path(manifest['host_admission']['lock_file']);require(manifest['host_admission']['wait_seconds']==30)
    info=os.fstat(fd);named=os.stat(path,follow_symlinks=False)
    require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1 and not stat.S_IMODE(info.st_mode)&0o077
        and (info.st_dev,info.st_ino)==(named.st_dev,named.st_ino))
    # This must be the caller's actual open-file-description lock, not an
    # unrelated holder of another descriptor for the same inode.
    try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:deny()
    other=os.open(path,os.O_RDWR|os.O_NOFOLLOW)
    try:
        try:fcntl.flock(other,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return
        else:fcntl.flock(other,fcntl.LOCK_UN);deny()
    finally:os.close(other)


def _tree(folder,expected):
    folder=Path(folder);fd=launch._dir(folder,False);found={};total=0
    try:
        require(os.fstat(fd).st_uid==os.getuid() and not stat.S_IMODE(os.fstat(fd).st_mode)&0o077)
        def walk(directory,prefix=''):
            nonlocal total
            names=os.listdir(directory);require(len(names)<=64)
            for name in names:
                info=os.stat(name,dir_fd=directory,follow_symlinks=False);relative=prefix+name
                require(info.st_uid==os.getuid() and not stat.S_IMODE(info.st_mode)&0o022)
                if stat.S_ISDIR(info.st_mode):
                    require(relative in ('scripts','runtime'));child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
                    try:walk(child,relative+'/')
                    finally:os.close(child)
                else:
                    require(relative in expected and stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=2*1024*1024)
                    leaf=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
                    try:
                        before=os.fstat(leaf);body=os.read(leaf,2*1024*1024+1);after=os.fstat(leaf);named=os.stat(name,dir_fd=directory,follow_symlinks=False)
                        identity=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
                        require(identity(before)==identity(after)==identity(named) and len(body)<=2*1024*1024)
                    finally:os.close(leaf)
                    total+=len(body);require(total<=16*1024*1024);found[relative]=hashlib.sha256(body).hexdigest()
        walk(fd);require(set(found)==set(expected));return found
    finally:os.close(fd)


def _recipe(binding,value,*,verify_files=True):
    require(type(value) is dict and type(value.get('schema')) is int and value['schema'] in (1,2))
    fields={'schema','case_id','program_sha256','code_files','input_files','image_id','platform','uid','resources','timeout_seconds','mounts','writable_identities'}
    exact(value,fields|({'private_children','transport'} if value['schema']==2 else set()))
    launch._integer(value['case_id'],1,3);case=Path(binding['root'])/'cases'/str(value['case_id'])
    require(((value['schema']==1 and value['case_id'] in (1,2)) or (value['schema']==2 and value['case_id']==3))
        and value['image_id']==IMAGE and value['platform']=='linux/arm64' and value['uid']=='501:20'
        and launch._json(value['resources'])==launch._json(RESOURCES) and type(value['timeout_seconds']) is int and value['timeout_seconds']==60)
    mounts=[{'source':str(case/name),'target':target,'rw':rw} for name,target,rw in TARGETS]
    require(launch._json(value['mounts'])==launch._json(mounts));exact(value['code_files'],CODE_FILES);exact(value['input_files'],INPUT_FILES)
    for checksum in [*value['code_files'].values(),*value['input_files'].values()]:launch._sha(checksum)
    revisions=APPROVED_PUBLISHED_INPUT_REVISIONS if value['schema']==2 else APPROVED_INPUT_REVISIONS
    require(value['program_sha256']==value['input_files']['guest.py'] and value['input_files'] in revisions and value['code_files'] in APPROVED_CODE_REVISIONS)
    if verify_files:require(_tree(case/'code',CODE_FILES)==value['code_files'] and _tree(case/'inputs',INPUT_FILES)==value['input_files'])
    exact(value['writable_identities'],{'state','evidence'})
    for name in ('state','evidence'):
        identity=value['writable_identities'][name];exact(identity,{'device','inode'})
        for v in identity.values():launch._integer(v,1,2**63-1)
    if value['schema']==2:
        require(value['transport']=='host-loopback-published');exact(value['private_children'],{'state','evidence'})
        for identity in value['private_children'].values():
            exact(identity,{'device','inode'})
            for v in identity.values():launch._integer(v,1,2**63-1)
    return value


def _writable_roots(binding,recipe):
    """Repeat original FD/UID/mode/inventory proof immediately before effects."""
    case=Path(binding['root'])/'cases'/str(recipe['case_id'])
    for name in ('state','evidence'):
        folder=launch._dir(case/name,False);child=None
        try:
            info=os.fstat(folder);require(info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700
                and recipe['writable_identities'][name]=={'device':info.st_dev,'inode':info.st_ino})
            if recipe['schema']==1:require(not os.listdir(folder))
            else:
                require(os.listdir(folder)==['private'])
                child=os.open('private',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=folder);info=os.fstat(child)
                require(info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700 and not os.listdir(child)
                    and recipe['private_children'][name]=={'device':info.st_dev,'inode':info.st_ino})
        finally:
            if child is not None:os.close(child)
            os.close(folder)


def build_argv(record,recipe):
    require(record.get('application_helper') is not True and record.get('diagnostic') is True and record['image']==recipe['image_id'] and launch._json(record['mounts'])==launch._json(recipe['mounts']))
    args=['docker','run','--interactive','--name',record['container'],'--label',launch.LABEL+'='+record['launch_id'],'--label',launch.REGISTRY_LABEL+'='+record['registry'],
        '--init','--platform','linux/arm64','--pull=never','--network','bridge' if recipe['schema']==2 else 'none','--ipc','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges=true',
        '--cpus','1','--memory','512m','--memory-swap','512m','--pids-limit','128','--user','501:20','--entrypoint=python3','--workdir=/pi-client/state',
        '--env','PYTHONDONTWRITEBYTECODE=1','--env','PYTHONUNBUFFERED=1','--env','HOME=/pi-client/state/home','--env','TMPDIR=/pi-client/state/tmp']
    if recipe['schema']==2:args+=['--publish','127.0.0.1::8081']
    for mount in recipe['mounts']:
        args+=['--mount','type=bind,src='+mount['source']+',dst='+mount['target']+(',readonly' if not mount['rw'] else '')+',bind-recursive=disabled']
    return args+[IMAGE,'-I','-B','/diagnostic-inputs/guest.py']


class AuxiliaryCampaign:
    def __init__(self,root,*,clock=time.monotonic,wall=time.time):
        self.root=launch._canonical_root(str(root));self.clock,self.wall=clock,wall
        self.binding=read(self.root/'binding.json');self.base,self.auth=_binding(self.binding,clock,wall);_fence(self.binding,self.base)
    @classmethod
    def create(cls,root,*,base_predecessor,authorization_ref,final_root,clock=time.monotonic,wall=time.time):
        root=launch._canonical_root(str(root));require(root==AUXILIARY_ROOT and launch._canonical_root(str(final_root))==FINAL_ROOT)
        base=base_carry(base_predecessor,clock,wall);authorization(authorization_ref,base,clock,wall)
        binding={'schema':1,'document_type':'qualification_auxiliary_campaign','root':str(root),'final_root':str(final_root),
            'base_predecessor':copy.deepcopy(base_predecessor),'authorization':copy.deepcopy(authorization_ref),'daemon':base['daemon'],'daemon_capacity':base['daemon_capacity'],
            'base_identity':{key:base[key] for key in ('attempts','participant_segments','planned_cells','qualification_id','started','deadline','started_wall','deadline_wall','lineage')}}
        _fence(binding,base,create=True)
        parent=launch._dir(root.parent,False)
        try:os.mkdir(root.name,0o700,dir_fd=parent);os.fsync(parent)
        finally:os.close(parent)
        exclusive(root/'binding.json',binding);exclusive(root/'ledger.json',{'schema':1,'binding_sha256':digest(binding),'poisoned':False,'sealed':False,'last_now':clock(),'last_wall':wall(),'launches':[]})
        folder=launch._dir(root,False)
        try:
            fd=launch._file(folder,'ledger.lock',os.O_RDWR|os.O_CREAT|os.O_EXCL);os.fsync(fd);os.close(fd);os.mkdir('cases',0o700,dir_fd=folder);os.fsync(folder)
        finally:os.close(folder)
        return cls(root,clock=clock,wall=wall)
    def _validate(self,state):
        exact(state,{'schema','binding_sha256','poisoned','sealed','last_now','last_wall','launches'})
        require(type(state['schema']) is int and state['schema']==1 and state['binding_sha256']==digest(self.binding) and type(state['poisoned']) is bool and type(state['sealed']) is bool)
        launch._number(state['last_now']);launch._number(state['last_wall']);rows=state['launches'];require(type(rows) is list and len(rows)<=3)
        keys=set()
        for index,row in enumerate(rows,1):
            exact(row,{'case_id','recipe','launch_id','registry','generation','intent_sha256','container_id','physical','private_cleanup','pid','cleanup'})
            require(row['case_id']==index and type(row['case_id']) is int and row['physical'] in ('pending','started','absent','uncertain') and type(row['private_cleanup']) is bool)
            launch._uuid(row['launch_id']);launch._uuid(row['generation']);launch._sha(row['registry']);launch._sha(row['intent_sha256'])
            require(row['launch_id'] not in keys);keys.add(row['launch_id'])
            require(row['recipe']['path']==str(self.root/'cases'/str(index)/'recipe.json'))
            require(_recipe(self.binding,reference(row['recipe']))['case_id']==index)
            if row['container_id'] is not None:launch._sha(row['container_id'])
            if row['pid'] is not None:launch._integer(row['pid'],1,2**31-1)
            require(not row['private_cleanup'] or row['physical']=='absent')
            if row['private_cleanup']:
                require(row['cleanup'] is not None);_cleanup(self.binding,row,row['cleanup'])
            else:require(row['cleanup'] is None)
        require(sum(row['physical']!='absent' for row in rows)<=1 and len(rows)+51+186<=240)
    def _transaction(self,fn,*,active=False):
        folder=launch._dir(self.root,False);lock=None
        try:
            lock=launch._file(folder,'ledger.lock',os.O_RDWR);fcntl.flock(lock,fcntl.LOCK_EX)
            require(launch._json(launch._read(folder,'binding.json'))==launch._json(self.binding));_fence(self.binding,self.base)
            state=launch._read(folder,'ledger.json');self._validate(state)
            require(not state['sealed'])
            now,wall=launch._number(self.clock()),launch._number(self.wall())
            if now<state['last_now'] or wall<state['last_wall']:
                state['poisoned']=True;launch._write(folder,'ledger.json',state);deny()
            state['last_now'],state['last_wall']=now,wall
            if active:
                require(not state['sealed'] and not state['poisoned']);authorization(self.binding['authorization'],self.base,self.clock,self.wall)
            try:result=fn(state)
            except BaseException:
                launch._write(folder,'ledger.json',state);raise
            self._validate(state);launch._write(folder,'ledger.json',state);return copy.deepcopy(result)
        finally:
            if lock is not None:os.close(lock)
            os.close(folder)
    def snapshot(self):
        state=read(self.root/'ledger.json');self._validate(state);return copy.deepcopy(state)
    def freeze_recipe(self,case_id,recipe,*,lease_fd):
        _lease(lease_fd,self.binding);launch._integer(case_id,1,3);require(recipe['case_id']==case_id);_recipe(self.binding,recipe)
        case=self.root/'cases'/str(case_id);_writable_roots(self.binding,recipe)
        def apply(state):
            require(len(state['launches'])==case_id-1 and all(r['private_cleanup'] for r in state['launches']))
            return exclusive(case/'recipe.json',recipe)
        return self._transaction(apply,active=True)
    def create_intent(self,case_id,registry,*,lease_fd,name):
        _lease(lease_fd,self.binding);launch._integer(case_id,1,3);launch._slug(name);require(len(name)<=99)
        recipe_ref=ref(self.root/'cases'/str(case_id)/'recipe.json');recipe=_recipe(self.binding,reference(recipe_ref));require(recipe['case_id']==case_id);_writable_roots(self.binding,recipe)
        require(registry.daemon==self.binding['daemon']);registry.require_capacity(1)
        record={'schema':1,'launch_id':str(uuid.uuid4()),'generation':registry.generation,'registry':registry.registry_id,'status':'intent','container':name,'image':IMAGE,
            'mounts':recipe['mounts'],'binding':{'authorization_id':AUTHORIZATION_ID,'case_id':case_id,'auxiliary_binding_sha256':digest(self.binding)},
            'runroot':str(self.root/'cases'/str(case_id)),'created_at':self.wall(),'owner_pid':os.getpid(),'daemon':self.binding['daemon'],'diagnostic':True}
        # The ordinary record is truthful: this runner has dummy authorities
        # only, no application credential store and no participant stage.
        def apply(state):
            require(len(state['launches'])==case_id-1 and all(r['private_cleanup'] for r in state['launches']))
            exclusive(self.root/'cases'/str(case_id)/'intent.json',{'schema':1,'launch_id':record['launch_id'],'registry':record['registry'],
                'generation':record['generation'],'intent_sha256':launch._intent_identity(record)})
            registry.write(record);return record,build_argv(record,recipe)
        return self._transaction(apply,active=True)
    def reserve(self,case_id,record,argv,daemon,*,lease_fd):
        _lease(lease_fd,self.binding);launch._integer(case_id,1,3)
        recipe_ref=ref(self.root/'cases'/str(case_id)/'recipe.json');recipe=_recipe(self.binding,reference(recipe_ref));require(recipe['case_id']==case_id);_writable_roots(self.binding,recipe)
        require(read(self.root/'cases'/str(case_id)/'intent.json')=={'schema':1,'launch_id':record['launch_id'],'registry':record['registry'],
            'generation':record['generation'],'intent_sha256':launch._intent_identity(record)})
        require(argv==build_argv(record,recipe) and record.get('status')=='intent' and record['daemon']==self.binding['daemon'] and record['runroot']==str(self.root/'cases'/str(case_id)))
        registry_root=Path(read(Path(self.binding['base_predecessor']['root'])/'manifest.json')['host_admission']['lock_file']+'.registry')
        require(launch._json(read(registry_root/(record['launch_id']+'.json')))==launch._json(record))
        exact(daemon,{'id','cpu_millis','memory_mib','image_id','architecture','os'})
        for key in ('cpu_millis','memory_mib'):launch._integer(daemon[key],1,10**12)
        require(daemon['image_id']==IMAGE and daemon['architecture']=='arm64' and daemon['os']=='linux'
            and daemon['id']==self.binding['daemon'] and min(daemon['cpu_millis'],self.base['daemon_capacity']['cpu_millis'])>=2000
            and min(daemon['memory_mib'],self.base['daemon_capacity']['memory_mib'])>=1024)
        def apply(state):
            require(len(state['launches'])==case_id-1 and case_id<=3 and all(r['physical']=='absent' and r['private_cleanup'] for r in state['launches']))
            state['launches'].append({'case_id':case_id,'recipe':recipe_ref,'launch_id':record['launch_id'],'registry':record['registry'],'generation':record['generation'],
                'intent_sha256':launch._intent_identity(record),'container_id':None,'physical':'pending','private_cleanup':False,'pid':None,'cleanup':None})
            return record['launch_id']
        return self._transaction(apply,active=True)
    def note(self,key,*,pid=None,container_id=None,physical=None,poison=False):
        def apply(state):
            rows=[r for r in state['launches'] if r['launch_id']==key];require(len(rows)==1 and not state['sealed']);row=rows[0]
            if pid is not None:launch._integer(pid,1,2**31-1);require(row['pid'] in (None,pid));row['pid']=pid
            if container_id is not None:launch._sha(container_id);require(row['container_id'] in (None,container_id));row['container_id']=container_id
            if physical is not None:
                require(physical in ('started','absent','uncertain') and row['physical']!='absent');row['physical']=physical
            state['poisoned']=state['poisoned'] or poison or physical=='uncertain'
        return self._transaction(apply)
    def dispatch(self,case_id,record,argv,daemon,*,lease_fd,popen):
        """One parent-supplied executor; durable charge strictly precedes it."""
        key=self.reserve(case_id,record,argv,daemon,lease_fd=lease_fd)
        try:
            process=popen(argv);self.note(key,pid=process.pid,physical='started');return key,process
        except BaseException:
            self.note(key,physical='uncertain',poison=True);raise
    def confirm_cleanup(self,key,receipt,*,lease_fd):
        _lease(lease_fd,self.binding)
        def apply(state):
            rows=[r for r in state['launches'] if r['launch_id']==key];require(len(rows)==1 and not state['sealed']);row=rows[0]
            value=_cleanup(self.binding,row,receipt);row['physical']='absent';row['private_cleanup']=True;row['cleanup']=copy.deepcopy(receipt);return value
        return self._transaction(apply)
    def seal(self,path,*,lease_fd):
        _lease(lease_fd,self.binding)
        def apply(state):
            require(not state['sealed'] and not state['poisoned'] and all(r['physical']=='absent' and r['private_cleanup'] and r['cleanup'] is not None for r in state['launches']))
            for row in state['launches']:_cleanup(self.binding,row,row['cleanup'])
            cases=launch._dir(self.root/'cases',False)
            try:
                names=os.listdir(cases);require(set(names)<=set(('1','2','3')))
                for name in names:
                    case=self.root/'cases'/name
                    marker=case/'intent.json'
                    if marker.exists() or marker.is_symlink():
                        value=read(marker);require(any(row['case_id']==int(name) and row['launch_id']==value['launch_id'] for row in state['launches']))
            finally:os.close(cases)
            state['sealed']=True
        self._transaction(apply,active=True)
        value={'schema':1,'document_type':'qualification_campaign_boundary','binding':ref(self.root/'binding.json'),'ledger':ref(self.root/'ledger.json')}
        return exclusive(path,value)


def _cleanup(binding,row,receipt):
    value=reference(receipt);exact(value,{'schema','document_type','authorization_id','binding_sha256','case_id','launch_id','registry','generation','container_id','intent_sha256','daemon',
        'physical_absence_confirmed','private_cleanup_confirmed','writable_roots','terminal'})
    require(type(value['schema']) is int and value['schema']==1 and value['document_type']=='qualification_auxiliary_cleanup' and value['authorization_id']==AUTHORIZATION_ID
        and value['binding_sha256']==digest(binding) and value['daemon']==binding['daemon'] and value['physical_absence_confirmed'] is True and value['private_cleanup_confirmed'] is True
        and all(value[k]==row[k] for k in ('case_id','launch_id','registry','generation','container_id','intent_sha256')) and row['container_id'] is not None)
    recipe=_recipe(binding,reference(row['recipe']));exact(value['writable_roots'],{'state','evidence'})
    for name in ('state','evidence'):
        root=value['writable_roots'][name];exact(root,{'path','device','inode','removed'})
        require(launch._json(root)==launch._json({'path':str(Path(binding['root'])/'cases'/str(row['case_id'])/name),**recipe['writable_identities'][name],'removed':True}))
        import ownership_registry
        require(ownership_registry._qualification_absent(root['path']))
    terminal=reference(value['terminal']);exact(terminal,{'schema','launch_id','container_id','exit_code','exit_code_source','timed_out','writers_stopped'})
    require(type(terminal['schema']) is int and terminal['schema']==1 and terminal['launch_id']==row['launch_id'] and terminal['container_id']==row['container_id']
        and type(terminal['exit_code']) is int and -127<=terminal['exit_code']<=255 and terminal['exit_code_source'] in ('docker_cli_returncode','container_state_exit_code')
        and (terminal['exit_code_source']=='docker_cli_returncode' or terminal['exit_code']>=0) and type(terminal['timed_out']) is bool and terminal['writers_stopped'] is True)
    manifest=read(Path(binding['base_predecessor']['root'])/'manifest.json');registry_root=Path(manifest['host_admission']['lock_file']+'.registry');record=read(registry_root/(row['launch_id']+'.json'))
    require(record.get('status')=='released' and record.get('container_id')==row['container_id'] and launch._intent_identity(record)==row['intent_sha256'] and record.get('daemon')==binding['daemon']
        and all(record.get(key)==row[key] for key in ('launch_id','registry','generation')) and record.get('diagnostic') is True
        and record.get('application_helper') is not True and record.get('image')==IMAGE and record.get('mounts')==recipe['mounts'])
    return value


def _raw_reference(value):
    exact(value,{'path','sha256'});launch._sha(value['sha256']);path=launch._canonical_root(value['path']);folder=launch._dir(path.parent,False)
    try:
        fd=launch._file(folder,path.name,os.O_RDONLY)
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno());body=stream.read(launch.MAX_BYTES+1);after=os.fstat(stream.fileno());named=os.stat(path.name,dir_fd=folder,follow_symlinks=False)
            identity=lambda info:(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
            require(len(body)<=launch.MAX_BYTES and identity(before)==identity(after)==identity(named) and hashlib.sha256(body).hexdigest()==value['sha256'])
        return body
    finally:os.close(folder)


def _known_auxiliary_cleanup(recovery_reference,*,clock=time.monotonic,wall=time.time,window=False):
    """One source-pinned stopped diagnostic, never a generic ledger repair."""
    value=reference(recovery_reference);exact(value,{'schema','document_type','binding','ledger','dispatch','source_record','quarantine_record','observation','controller','cleanup'})
    require(type(value['schema']) is int and value['schema']==1 and value['document_type']=='qualification_known_auxiliary_cleanup')
    known=KNOWN_AUXILIARY_INCIDENT;case=AUXILIARY_ROOT/'cases/3'
    for key,path in (('binding',AUXILIARY_ROOT/'binding.json'),('ledger',AUXILIARY_ROOT/'ledger.json'),('dispatch',case/'dispatch.json')):
        require(value[key]=={'path':str(path),'sha256':known[key+'_sha256']})
    binding=reference(value['binding']);base,auth=_binding(binding,clock,wall,window=window);_fence(binding,base)
    ledger=reference(value['ledger']);owner=object.__new__(AuxiliaryCampaign);owner.root=AUXILIARY_ROOT;owner.binding=binding;owner.base=base;owner.auth=auth;owner._validate(ledger)
    require(ledger['poisoned'] is True and ledger['sealed'] is False and len(ledger['launches'])==3
        and clock()>=ledger['last_now'] and wall()>=ledger['last_wall'])
    for row in ledger['launches'][:2]:require(row['physical']=='absent' and row['private_cleanup'] is True and row['cleanup'] is not None);_cleanup(binding,row,row['cleanup'])
    row=ledger['launches'][2]
    require(row['case_id']==3 and all(row[key]==known[key] for key in ('launch_id','registry','generation','intent_sha256'))
        and row['pid']==known['docker_cli_pid'] and row['container_id'] is None and row['physical']=='uncertain' and row['private_cleanup'] is False and row['cleanup'] is None
        and row['recipe']=={'path':str(case/'recipe.json'),'sha256':known['recipe_sha256']})
    marker=reference({'path':str(case/'intent.json'),'sha256':known['intent_marker_sha256']})
    require(launch._json(marker)==launch._json({'schema':1,**{key:row[key] for key in ('launch_id','registry','generation','intent_sha256')}}))
    require(value['source_record']['sha256']==known['source_record_sha256']);source=reference(value['source_record']);quarantined=reference(value['quarantine_record'])
    require(source.get('status')=='intent' and source.get('container_id') is None and source.get('owner_pid')==known['owner_pid']
        and source.get('diagnostic') is True and source.get('application_helper') is not True and source.get('runroot')==str(case)
        and source.get('daemon')==binding['daemon'] and all(source.get(key)==row[key] for key in ('launch_id','registry','generation'))
        and launch._intent_identity(source)==row['intent_sha256'] and launch._json(quarantined)==launch._json({**source,'status':'quarantined'}))
    recipe=_recipe(binding,reference(row['recipe']));require(recipe['schema']==2 and recipe['transport']=='host-loopback-published')
    dispatch=reference(value['dispatch']);exact(dispatch,{'schema','argv','classification','daemon'})
    require(type(dispatch['schema']) is int and dispatch['schema']==1 and dispatch['argv']==build_argv(source,recipe)
        and dispatch['classification']=='dummy host control component; no Pi/model/application actions')
    exact(dispatch['daemon'],{'id','cpu_millis','memory_mib','image_id','architecture','os'})
    require(dispatch['daemon']['id']==binding['daemon'] and dispatch['daemon']['image_id']==IMAGE and dispatch['daemon']['architecture']=='arm64' and dispatch['daemon']['os']=='linux')
    for key in ('cpu_millis','memory_mib'):launch._integer(dispatch['daemon'][key],1,10**12)
    registry_root=Path(read(Path(binding['base_predecessor']['root'])/'manifest.json')['host_admission']['lock_file']+'.registry')
    current=read(registry_root/(row['launch_id']+'.json'));expected_current={**source,'status':'released','container_id':known['container_id']}
    require(launch._json(current)==launch._json(expected_current))
    observation=reference(value['observation']);exact(observation,{'schema','document_type','launch_id','container_id','daemon','image_id','user','workdir','labels','host_config','mounts','state','physical_absence_confirmed','bound_observation'})
    expected_host={'ReadonlyRootfs':True,'NetworkMode':'bridge','IpcMode':'none','NanoCpus':1000000000,'Memory':536870912,'MemorySwap':536870912,
        'PidsLimit':128,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges=true'],'PortBindings':{'8081/tcp':[{'HostIp':'127.0.0.1','HostPort':''}]}}
    require(type(observation['schema']) is int and observation['schema']==1 and observation['document_type']=='qualification_auxiliary_recovery_observation'
        and observation['launch_id']==known['launch_id'] and observation['container_id']==known['container_id'] and observation['daemon']==binding['daemon']
        and observation['image_id']==IMAGE and observation['user']=='501:20' and observation['workdir']=='/pi-client/state'
        and observation['labels']=={launch.LABEL:row['launch_id'],launch.REGISTRY_LABEL:row['registry']}
        and launch._json(observation['host_config'])==launch._json(expected_host)
        and launch._json(observation['mounts'])==launch._json(sorted(recipe['mounts'],key=lambda item:item['target']))
        and launch._json(observation['state'])==launch._json({'status':'exited','running':False,'exit_code':2}) and observation['physical_absence_confirmed'] is True)
    bound=reference(observation['bound_observation'])
    require(launch._json(bound)==launch._json({'schema':1,'container_id':known['container_id'],'launch_id':known['launch_id'],'daemon':binding['daemon'],
        'verified_stopped_identity_user_resources_mounts_labels':True,'late_binding':True,'source_registry_sha256':known['source_record_sha256'],
        'source_ledger_sha256':known['ledger_sha256'],'no_bootstrap_or_control_request_sent':True}))
    controller=reference(value['controller']);exact(controller,{'schema','document_type','owner_pid','docker_cli_pid','owner_pid_absent','docker_cli_pid_absent',
        'configuration_bootstrap_sent','control_rpc_attempted','command_verification','controller_failure','reviewed_controller'})
    for key in ('owner_pid','docker_cli_pid'):launch._integer(controller[key],1,2**31-1)
    require(type(controller['schema']) is int and controller['schema']==1 and controller['document_type']=='qualification_auxiliary_recovery_controller'
        and controller['owner_pid']==known['owner_pid'] and controller['docker_cli_pid']==known['docker_cli_pid']
        and controller['owner_pid_absent'] is True and controller['docker_cli_pid_absent'] is True and controller['configuration_bootstrap_sent'] is False and controller['control_rpc_attempted'] is False)
    for pid in (known['owner_pid'],known['docker_cli_pid']):
        try:os.kill(pid,0)
        except ProcessLookupError:pass
        except PermissionError:deny()
        else:deny()
    for key,sha_key in (('command_verification','command_sha256'),('controller_failure','failure_sha256'),('reviewed_controller','controller_sha256')):
        require(controller[key]['sha256']==known[sha_key]);_raw_reference(controller[key])
    command=reference(controller['command_verification'])
    require(type(command.get('actual_exit')) is int and command['actual_exit']==1 and command.get('outer_timeout') is False
        and command.get('program_before')==known['controller_sha256'] and command.get('program_after')==known['controller_sha256']
        and command.get('logs',{}).get('stderr.log')==known['failure_sha256'])
    effective=copy.deepcopy(row);effective.update(container_id=known['container_id'],physical='absent',private_cleanup=True,cleanup=value['cleanup'])
    cleanup=_cleanup(binding,effective,value['cleanup']);terminal=reference(cleanup['terminal'])
    require(terminal['exit_code_source']=='container_state_exit_code' and terminal['exit_code']==2 and terminal['timed_out'] is False)
    return value,binding,ledger,base,auth


def validate_known_auxiliary_cleanup(recovery_reference,*,clock=time.monotonic,wall=time.time):
    return _known_auxiliary_cleanup(recovery_reference,clock=clock,wall=wall)[0]


def seal_known_cleanup(root,path,*,recovery_ref,lease_fd,clock=time.monotonic,wall=time.time):
    require(launch._canonical_root(str(root))==AUXILIARY_ROOT and launch._canonical_root(str(path))==AUXILIARY_ROOT/'boundary.json')
    value,binding,ledger,base,auth=_known_auxiliary_cleanup(recovery_ref,clock=clock,wall=wall,window=True);_lease(lease_fd,binding)
    # No transaction, note, poison clear or synthetic sealed ledger is written.
    result=exclusive(path,{'schema':1,'document_type':'qualification_campaign_boundary','binding':value['binding'],'ledger':value['ledger'],'recovery':recovery_ref})
    validate_boundary(result,binding['base_predecessor'],clock=clock,wall=wall);return result


def validate_boundary(reference_value,base_predecessor,*,clock=time.monotonic,wall=time.time,window=True):
    value=reference(reference_value);exact(value,{'schema','document_type','binding','ledger'}|({'recovery'} if 'recovery' in value else set()))
    require(type(value['schema']) is int and value['schema']==1 and value['document_type']=='qualification_campaign_boundary')
    binding=reference(value['binding']);base,auth=_binding(binding,clock,wall,window=window);require(launch._json(binding['base_predecessor'])==launch._json(base_predecessor));_fence(binding,base)
    require(value['binding']['path']==str(Path(binding['root'])/'binding.json') and value['ledger']['path']==str(Path(binding['root'])/'ledger.json'))
    ledger=reference(value['ledger']);campaign=object.__new__(AuxiliaryCampaign);campaign.root=Path(binding['root']);campaign.binding=binding;campaign.base=base;campaign.auth=auth
    campaign._validate(ledger)
    if 'recovery' in value:
        require(reference_value['path']==str(AUXILIARY_ROOT/'boundary.json'))
        recovered,_,_,_,_=_known_auxiliary_cleanup(value['recovery'],clock=clock,wall=wall,window=window)
        require(value['binding']==recovered['binding'] and value['ledger']==recovered['ledger'])
    else:require(ledger['sealed'] is True and ledger['poisoned'] is False)
    require(clock()>=ledger['last_now'] and wall()>=ledger['last_wall'])
    if 'recovery' not in value:
        for row in ledger['launches']:require(row['physical']=='absent' and row['private_cleanup'] is True and row['cleanup'] is not None);_cleanup(binding,row,row['cleanup'])
    result={**base,'attempts':base['attempts']+len(ledger['launches']),'started':auth['started_monotonic'],'deadline':auth['deadline_monotonic'],
        'started_wall':auth['started_wall'],'deadline_wall':auth['deadline_wall'],'campaign_boundary':copy.deepcopy(reference_value),
        'original_window':{key:base[key] for key in ('started','deadline','started_wall','deadline_wall')},'base_attempts':51,'auxiliary_attempts':len(ledger['launches'])}
    if 'recovery' in value:result['known_auxiliary_cleanup']=copy.deepcopy(value['recovery'])
    return result


def _launch_policy(full):
    fields=('id','group','release','image_id','allowed_images','role_limits','container_launches_max','participant_segments_max')
    expected_limits={key:value for key,value in launch.LIMITS.items() if key!='live'}
    expected_limits.update(simultaneously_registered_live_container_intents=4,automatic_retries=0,continuations=0)
    require(launch._json(full['limits'])==launch._json(expected_limits))
    return launch.validate_manifest({'qualification_id':full['qualification_id'],'images':full['images'],
        'cells':[{key:cell[key] for key in fields} for cell in full['cells']],'limits':dict(launch.LIMITS),
        'planned_container_launches':full['planned_container_launches'],'predecessor':full['predecessor'],'campaign_boundary':full['campaign_boundary']})


def bind_final(root,manifest,carry,*,create=False):
    value=reference(manifest['campaign_boundary']);binding=reference(value['binding']);base=base_carry(binding['base_predecessor'],time.monotonic,time.time)
    _fence(binding,base);require(Path(root)==Path(binding['final_root'])/'launch-ledger' and manifest['predecessor']==binding['base_predecessor'] and carry.get('campaign_boundary')==manifest['campaign_boundary'])
    candidate_binding=read(Path(binding['root'])/'candidate-binding.json')
    exact(candidate_binding,{'schema','boundary','qualification_id','full_manifest','candidate','launch_manifest_sha256'})
    require(type(candidate_binding['schema']) is int and candidate_binding['schema']==1 and candidate_binding['boundary']==manifest['campaign_boundary']
        and candidate_binding['qualification_id']==manifest['qualification_id'])
    full=reference(candidate_binding['full_manifest']);candidate=reference(candidate_binding['candidate'])
    require(full['qualification_id']==manifest['qualification_id'] and full['campaign_boundary']==manifest['campaign_boundary']
        and candidate['runner_sha256']==full['source']['runner'] and candidate_binding['launch_manifest_sha256']==digest(manifest)
        and launch._json(_launch_policy(full))==launch._json(manifest))
    expected={'schema':1,'document_type':'qualification_boundary_final_binding','boundary':manifest['campaign_boundary'],'qualification_id':manifest['qualification_id'],
        'manifest_sha256':digest(manifest),'ledger_root':str(Path(root)),'base_attempts':51,'auxiliary_attempts':carry['auxiliary_attempts'],'cumulative_attempts':carry['attempts'],
        'candidate_binding':ref(Path(binding['root'])/'candidate-binding.json')}
    path=Path(binding['root'])/'final-binding.json'
    if create:exclusive(path,expected)
    require(read(path)==expected)


def finalize_candidate(boundary_reference,full_manifest_reference,candidate_reference,*,clock=time.monotonic,wall=time.time):
    boundary=reference(boundary_reference);binding=reference(boundary['binding'])
    validate_boundary(boundary_reference,binding['base_predecessor'],clock=clock,wall=wall)
    require(full_manifest_reference['path']==str(FINAL_ROOT/'manifest.json') and candidate_reference['path']==str(FINAL_ROOT/'candidate.json'))
    full=reference(full_manifest_reference);candidate=reference(candidate_reference);launch._uuid(full['qualification_id'])
    exact(candidate,{'archive_sha256','runner_sha256','scope'});launch._sha(candidate['archive_sha256']);launch._sha(candidate['runner_sha256'])
    require(full.get('document_type')=='application_client_qualification' and full.get('prepared_root')==str(FINAL_ROOT)
        and launch._json(full.get('predecessor'))==launch._json(binding['base_predecessor']) and full.get('campaign_boundary')==boundary_reference
        and candidate['scope']=='extracted_candidate' and candidate['runner_sha256']==full['source']['runner'])
    policy=_launch_policy(full)
    return exclusive(Path(binding['root'])/'candidate-binding.json',{'schema':1,'boundary':boundary_reference,'qualification_id':full['qualification_id'],
        'full_manifest':full_manifest_reference,'candidate':candidate_reference,'launch_manifest_sha256':digest(policy)})
