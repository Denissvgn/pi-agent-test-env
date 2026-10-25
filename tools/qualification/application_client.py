#!/usr/bin/env python3
"""Fixed native application qualification; scripted protocol is not model evidence.

Maintainer-only orchestration. Runtime sources remain unchanged. Every native
cell is an immutable one-attempt declaration and uses the real runner/lease.
"""
import argparse
import contextlib
import copy
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit
import uuid
from types import SimpleNamespace

HERE=Path(__file__).resolve().parent;REPO=HERE.parents[1];SKILL=REPO/'skill'
sys.path[:0]=[str(SKILL/'scripts'),str(SKILL/'runtime'),str(HERE)]
import application_contracts as c
import application_credentials as credentials
import application_experiments
import application_preparation as preparation
import application_timing as timing
from application_evidence import open_directory,read_file
import experiments
import lab_env
import native_budget_controls
import outcomes
import ownership_registry
import pi_lab as lab
import provenance
import release_contracts
import resources
import secret_store
import stage_control as controls

EXAMPLE=SKILL/'examples/authenticated-application'
RELEASES=('0.87.1','1.2.0')
LIMITS={'global_seconds':14400,'cleanup_reserve_seconds':30,'container_launch_attempts':240,
        'simultaneously_registered_live_container_intents':4,'participant_segments':24,'automatic_retries':0,'continuations':0}
NEGATIVE_LIMITS={'timeout_seconds':180,'max_turns':8,'max_total_tokens':16000,'max_tool_calls':16,
                 'reporting_reserve_calls':6,'reporting_reserve_seconds':30}
NEGATIVES=(('request-and-persona','a','invalid-typed-request'),('request-and-persona','b','wrong-actor'),
    ('reporting-and-reserve','a','omitted-report'),('reporting-and-reserve','b','multi-call-reserve-boundary'),
    ('commit-and-interruption','a','publication-response-loss'),('commit-and-interruption','b','sensitive-participant-interruption'))
ROLES={'fixture':1,'probe':1,'boundary':1,'preflight':1,'application-helper':1,'participant':1,'scorer':1}
ADMISSION_WAIT_SECONDS=30
SCRIPT_RESULTS={'invalid-typed-request':1,'wrong-actor':1,'omitted-report':5,'multi-call-reserve-boundary':13,
    'publication-response-loss':6,'sensitive-participant-interruption':2}
RESERVE_COUNTS={'attempted':13,'charged':10,'blocked':3,'grants_consumed':10,'executed_known':10,'executed_unknown':0,'helper_verified':10,'worker_observed':0}
SENSITIVE_SCOPE='participant interruption followed by known sensitive cleanup; cleanup-operation interruption and unknown-cleanup recovery unqualified'


class QualificationError(ValueError):
    def __init__(self,message='Qualification input, ownership or evidence is unavailable'):super().__init__(message)


class ServiceProcessUnconfirmed(QualificationError):
    """An exact spawned Docker CLI has no confirmed bounded reap."""
    def __init__(self,pid=None):
        super().__init__()
        self.pid=pid if type(pid) is int and 0<pid<2**31 else None


class ServiceReaderUnconfirmed(ServiceProcessUnconfirmed):
    """The owned log CLI could not be reaped inside its original budget."""


def _module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def _retained_call(operation,*args,**kwargs):
    """Fixed maintainer adapter; dispatch never imports an input-selected module."""
    import application_retained
    return getattr(application_retained,operation)(SimpleNamespace(**globals()),*args,**kwargs)


def prepare_requalification(root,*,retained_index,compatibility,**freeze_kwargs):
    return _retained_call('prepare',root,retained_index=retained_index,
                          compatibility=compatibility,freeze_kwargs=freeze_kwargs)



def _browser_followup_call(operation,*args,**kwargs):
    """Fixed new-mode adapter; never imports a caller-selected module."""
    import application_browser_followup
    return getattr(application_browser_followup,operation)(SimpleNamespace(**globals()),*args,**kwargs)


def prepare_browser_followup(root,*,evidence_index,compatibility,**freeze_kwargs):
    return _browser_followup_call('prepare',root,evidence_index=evidence_index,
                                 compatibility=compatibility,freeze_kwargs=freeze_kwargs)


def _browser_fixture_followup_call(operation,*args,**kwargs):
    """Fixed fixture-successor adapter; input never selects executable code."""
    import application_browser_fixture_followup
    return getattr(application_browser_fixture_followup,operation)(SimpleNamespace(**globals()),*args,**kwargs)


def prepare_browser_fixture_followup(root,*,evidence_index,compatibility,**freeze_kwargs):
    return _browser_fixture_followup_call('prepare',root,evidence_index=evidence_index,
                                         compatibility=compatibility,freeze_kwargs=freeze_kwargs)


def read(path,maximum=4*1024*1024):return preparation._json(path,maximum)
def sha(path):return hashlib.sha256(preparation._read(path,64*1024*1024)).hexdigest()
def atomic(path,value):controls.atomic(path,value,0o600)


def _private_identity(path):
    fd=preparation._directory(path)
    try:
        info=os.fstat(fd)
        if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077:raise QualificationError()
        return info.st_dev,info.st_ino
    finally:os.close(fd)


def _readiness_remaining(deadline):
    left=deadline-time.monotonic()
    if left<=0:
        error=QualificationError('Service readiness deadline exceeded')
        error.readiness_deadline=True
        raise error
    return left


def _purge_private(path,identity):
    """Only an originally owned directory; all removal stays FD-relative."""
    path=Path(path);parent=preparation._directory(path.parent);fd=None
    def clear(directory):
        names=os.listdir(directory)
        if len(names)>16:raise QualificationError()
        for name in names:
            info=os.stat(name,dir_fd=directory,follow_symlinks=False)
            if info.st_uid!=os.getuid():raise QualificationError()
            if stat.S_ISDIR(info.st_mode):
                child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
                try:
                    clear(child);now=os.stat(name,dir_fd=directory,follow_symlinks=False)
                    if (now.st_dev,now.st_ino)!=(info.st_dev,info.st_ino):raise QualificationError()
                    os.rmdir(name,dir_fd=directory)
                finally:os.close(child)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink==1:os.unlink(name,dir_fd=directory)
            else:raise QualificationError()
        os.fsync(directory)
    try:
        fd=os.open(path.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);before=os.fstat(fd)
        if (before.st_dev,before.st_ino)!=identity:raise QualificationError('Private directory identity changed')
        clear(fd);now=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        if (now.st_dev,now.st_ino)!=identity:raise QualificationError()
        os.rmdir(path.name,dir_fd=parent);os.fsync(parent)
    finally:
        if fd is not None:os.close(fd)
        os.close(parent)

def matrix(images):
    cells=[]
    for release in RELEASES:
        for profile in ('core','browser'):
            roles={'probe':1,**({'browser-check':1} if profile=='browser' else {})}
            cells.append({'id':f'N01-{release}-{profile}','group':'N01','release':release,'profile':profile,
                'image_id':images[profile+'-'+release]['id'],'allowed_images':[images[profile+'-'+release]['id']],
                'role_limits':roles,'container_launches_max':sum(roles.values()),'participant_segments_max':0,'max_attempts':1,'real_model':False})
        for case,variant,scenario in NEGATIVES:
            roles={**ROLES,'scripted-inference':1}
            cells.append({'id':f'N02-{release}-{case}-{variant}','group':'N02','release':release,'profile':'core','case':case,'variant':variant,
                'scenario':scenario,'image_id':images['core-'+release]['id'],'allowed_images':[images['core-'+release]['id']],
                'role_limits':roles,'container_launches_max':8,'participant_segments_max':1,'max_attempts':1,'real_model':False,'service_lifetime_seconds':900})
        for group,profile in (('N03','core'),('N04','browser')):
            for repeat in range(1,4):
                cells.append({'id':f'{group}-{release}-{repeat}','group':group,'release':release,'profile':profile,'repetition':repeat,
                    'image_id':images[profile+'-'+release]['id'],'allowed_images':list(dict.fromkeys([images[profile+'-'+release]['id'],images['core-'+release]['id']])),
                    'role_limits':dict(ROLES),'container_launches_max':7,'participant_segments_max':1,'max_attempts':1,'real_model':True,'service_lifetime_seconds':900})
    return cells


def source_identity():
    runner=provenance.execution({}, {},SKILL)
    paths=[path for path in HERE.glob('application_*.py') if path.is_file()]
    paths+= [path for path in EXAMPLE.rglob('*') if path.is_file() and '__pycache__' not in path.parts]
    files={str(path.relative_to(REPO)):sha(path) for path in sorted(paths)}
    if not {'application_launch.py','application_scripted.py'}<={path.name for path in paths}:raise QualificationError('Qualification modules are incomplete')
    return {'runner':runner['runner_content_sha256'],'runner_files':runner['runner_files'],'release_contracts':release_contracts.snapshot(),
        'files':files,'sha256':provenance.digest(files)}


def _endpoint(path,session):
    selected=lab.normalize_endpoint(read(path));saved=lab_env.load_saved()
    if (lab_env.evaluate(session,check=False).get('state')!='ready' or saved is None
            or lab.normalize_endpoint(saved[0])!=selected):raise QualificationError('Confirmed saved environment must match the explicit real endpoint')
    return selected


def _route(value):
    c.exact(value,{'origin','allowed_addresses','fixture_port','scripted_base_url','scripted_host_base_url','scripted_port','publish_host'},'/route')
    for key in ('fixture_port','scripted_port'):c.integer(value[key],'/route/'+key,1024,65535)
    if value['fixture_port']==value['scripted_port']:raise QualificationError()
    origin=urlsplit(value['origin'])
    if origin.scheme!='http' or origin.port!=value['fixture_port']:raise QualificationError()
    for key in ('scripted_base_url','scripted_host_base_url'):
        parsed=urlsplit(value[key])
        if (parsed.scheme!='http' or not parsed.hostname or parsed.username is not None or parsed.password is not None
                or parsed.port!=value['scripted_port'] or parsed.path!='/v1' or parsed.query or parsed.fragment):raise QualificationError()
    if urlsplit(value['scripted_host_base_url']).hostname!='127.0.0.1':raise QualificationError()
    ipaddress.ip_address(value['publish_host'])
    return copy.deepcopy(value)


def _effective_limits(manifest):
    if 'browser_fixture_followup' in manifest:
        import application_browser_fixture_followup
        return application_browser_fixture_followup.effective_limits(manifest)
    if 'browser_followup' in manifest:
        import application_browser_followup
        return application_browser_followup.effective_limits(manifest)
    if 'retained_requalification' in manifest:
        import application_retained
        return application_retained.effective_limits(manifest)
    value=dict(LIMITS)
    if 'campaign_amendment' in manifest:
        effective=_launch_module().effective_limits(manifest)
        for key in ('container_launch_attempts','participant_segments'):value[key]=effective[key]
    return value


def freeze(root,*,session,approved_endpoint_path,image_receipts,fixture_route,credential_references,secrets_dir,candidate_identity=None,predecessor=None,campaign_boundary=None,campaign_amendment=None):
    root=Path(root).absolute()
    if root.exists() or root.is_symlink():raise QualificationError('Use a fresh qualification root')
    if campaign_boundary is not None and predecessor is None:raise QualificationError('Campaign boundary requires its original predecessor')
    if campaign_amendment is not None:
        amendment=_launch_module().amendment_module(campaign_amendment)
        if campaign_boundary is None or predecessor is None or root!=amendment.FINAL_ROOT:
            raise QualificationError('Matrix amendment requires its exact authorized successor root and original boundary')
    carry_manifest={'predecessor':predecessor}
    if campaign_boundary is not None:carry_manifest['campaign_boundary']=campaign_boundary
    if campaign_amendment is not None:carry_manifest['campaign_amendment']=campaign_amendment
    carried=(_launch_module()._effective_carry(carry_manifest) if campaign_boundary is not None
        else _launch_module().validate_predecessor(predecessor)) if predecessor is not None else None
    if predecessor is not None and (root==Path(predecessor['root']) or root in Path(predecessor['root']).parents or Path(predecessor['root']) in root.parents):
        raise QualificationError('Successor qualification must have a distinct disjoint root')
    expected={profile+'-'+release for profile in ('core','browser') for release in RELEASES}
    if type(image_receipts) is not dict or set(image_receipts)!=expected:raise QualificationError('All four immutable native image receipts are required')
    c.exact(credential_references,{'alice','bob','scripted_inference'},'/references')
    for reference in credential_references.values():secret_store.check_name(reference)
    if len(set(credential_references.values()))!=3:raise QualificationError()
    store=Path(secrets_dir).expanduser().absolute()
    if (root==store or root in store.parents or store in root.parents or REPO==store or REPO in store.parents
            or REPO.resolve()==store.resolve() or REPO.resolve() in store.resolve().parents):
        raise QualificationError('Private store must remain outside package, project and qualification evidence')
    endpoint=_endpoint(approved_endpoint_path,session);route=_route(fixture_route);configure=_module('qualification_example_configure',EXAMPLE/'configure.py')
    source=source_identity();root.mkdir(mode=0o700,parents=True)
    try:
        inputs=root/'inputs';inputs.mkdir(mode=0o700);(root/'cells').mkdir(mode=0o700)
        atomic(inputs/'endpoint.json',endpoint);images={};receipts={}
        for key,path in image_receipts.items():
            profile,release=key.rsplit('-',1);receipt=read(path)
            example=configure.source_for(path,route['origin'],route['allowed_addresses'],credential_references['alice'],'browser' if profile=='browser' else 'api')
            if example['runtime']['pi_release']!=release:raise QualificationError('Runtime receipt release differs from its fixed image slot')
            normalized=preparation._runtime(example,receipt);images[key]=normalized['image'];receipts[key]=receipt
            atomic(inputs/(key+'.json'),receipt)
        for release in RELEASES:
            runtime_path=inputs/('core-'+release+'.json');case_inputs=inputs/('scripted-'+release);case_inputs.mkdir()
            cases=[]
            for name in dict.fromkeys(case for case,_,_ in NEGATIVES):
                folder=case_inputs/name;folder.mkdir();source_plan=configure.source_for(runtime_path,route['origin'],route['allowed_addresses'],credential_references['alice'],'api')
                source_plan['runtime']['inference_owner']='experiment_variant';source_plan['stages'][0]['limits']=dict(NEGATIVE_LIMITS)
                source_plan['stages'][0]['prompt']+='\nQualification case '+name+'. Follow the explicit scripted native calls only.'
                if name=='request-and-persona':
                    source_plan['application']['credentials']['bob']=credential_references['bob'];identity=copy.deepcopy(source_plan['application']['operations'][0])
                    identity.update(id='identity-bob',credential_alias='bob');source_plan['application']['operations'].append(identity)
                    source_plan['stages'][0]['credential_aliases'].append('bob');source_plan['stages'][0]['operations'].append('identity-bob')
                atomic(folder/'source.json',source_plan)
                for asset in ('content_scorer.py','expected.json'):shutil.copyfile(EXAMPLE/asset,folder/asset)
                project=folder/'project';project.mkdir();shutil.copyfile(EXAMPLE/'project/TASK.md',project/'TASK.md')
                cases.append({'name':name,'project':str(project),'plan':str(folder/'source.json'),'runtime_receipt':str(runtime_path)})
            for variant in ('a','b'):
                atomic(case_inputs/('endpoint-'+variant+'.json'),{'base_url':route['scripted_base_url'],'host_base_url':route['scripted_host_base_url'],
                    'model':'application-script-'+variant,'api_key_env':credential_references['scripted_inference'],'context_window':262144,'max_tokens':8192})
            policy=configure.source_for(runtime_path,route['origin'],route['allowed_addresses'],credential_references['alice'],'api')['runtime']['resources']
            atomic(case_inputs/'resources.json',policy)
            definition={'schema':1,'document_type':'application_experiment_source','name':'application-scripted-'+release.replace('.','-'),'baseline':'a','repetitions':1,'cases':cases,
                'variants':[{'name':variant,'endpoint':str(case_inputs/('endpoint-'+variant+'.json')),'prompt_suffix':'QUALIFICATION_SCRIPT_VARIANT_'+variant.upper()} for variant in ('a','b')],
                'budgets':dict(NEGATIVE_LIMITS),'execution':{'image':images['core-'+release]['id'],'platform':'linux/arm64','resources':str(case_inputs/'resources.json')},
                'policies':{'primary_attempt':'first','assistance':'exclude','on_failure':'continue','max_attempts':1}}
            atomic(case_inputs/'definition.json',definition)
            experiments.prepare(case_inputs/'definition.json',root/('scripted-'+release),lab,session=session,secrets_dir=store)
            for profile,variant in (('core','api'),('browser','browser')):
                configure.configure(runtime_receipt=inputs/(profile+'-'+release+'.json'),origin=route['origin'],allowed_addresses=route['allowed_addresses'],
                    credential_reference=credential_references['alice'],variant=variant,output_dir=inputs/(variant+'-'+release),endpoint=inputs/'endpoint.json')
        cells=matrix(images)
        if len({image['id'] for image in images.values()})!=4:raise QualificationError('Four distinct observed image identities required')
        for cell in cells:
            if cell['group']=='N02':
                metadata,mapping=experiments.verify(root/('scripted-'+cell['release']),lab)
                trial=next(row for row in mapping['cells'] if row['case']==cell['case'] and row['variant']==cell['variant'])
                cell['trial_id']=trial['trial_id'];cell['plan_sha256']=trial['plan_sha256']
            elif cell['participant_segments_max']:
                path=inputs/(('browser' if cell['group']=='N04' else 'api')+'-'+cell['release'])/'compiled/plan.json'
                cell['plan_sha256']=preparation.load_compiled(path)['plan']['plan_sha256']
        inventory={str(path.relative_to(root)):sha(path) for path in root.rglob('*') if path.is_file()
            and not (path.parent.name.startswith('scripted-') and path.name=='state.json')}
        manifest={'schema':1,'document_type':'application_client_qualification','qualification_id':str(uuid.uuid4()),'created_at':controls.now(),
            'prepared_root':str(root),'session':session,'endpoint':endpoint,'endpoint_sha256':provenance.digest(endpoint),'images':images,
            'image_receipts':{key:'inputs/'+key+'.json' for key in images},'fixture_route':route,'credential_references':dict(credential_references),
            'host_admission':{'lock_file':str(Path(lab.default_lock_file()).expanduser().absolute()),'wait_seconds':ADMISSION_WAIT_SECONDS},
            'secrets_dir':str(store),'source':source,'cells':cells,'limits':_effective_limits(carry_manifest),'planned_container_launches':186,'files':inventory,
            'negative_oracles':{'tool_results':dict(SCRIPT_RESULTS),'reserve_counts':dict(RESERVE_COUNTS),'reserve_remaining':6,
                'scope':'expected negative failures are qualification assertions, never model task success'},
            'sensitive_negative_scope':SENSITIVE_SCOPE}
        if predecessor is not None:manifest['predecessor']=copy.deepcopy(predecessor)
        if campaign_boundary is not None:manifest['campaign_boundary']=copy.deepcopy(campaign_boundary)
        if campaign_amendment is not None:manifest['campaign_amendment']=copy.deepcopy(campaign_amendment)
        atomic(root/'manifest.json',manifest);atomic(root/'integrity.json',{'manifest_sha256':sha(root/'manifest.json')})
        atomic(root/'state.json',{'schema':1,'phase':'frozen','active_cell':None,'cells':{},'started_at':carried['started_wall'] if carried else None})
        if candidate_identity is not None:bind_candidate(root,candidate_identity)
        return root
    except BaseException:
        # This root was exclusively created here; do not delete an ancestor or
        # a replacement. Failed setup remains private evidence for inspection.
        atomic(root/'freeze-failed.json',{'schema':1,'status':'BLOCKED','reason':'freeze_failed'});raise


def bind_candidate(root,identity):
    root=Path(root);verify(root,require_candidate=False)
    c.exact(identity,{'archive_sha256','runner_sha256','scope'},'/candidate');c.sha256(identity['archive_sha256'],'/candidate');c.sha256(identity['runner_sha256'],'/candidate')
    if identity['scope']!='extracted_candidate' or identity['runner_sha256']!=read(root/'manifest.json')['source']['runner']:raise QualificationError()
    if (root/'candidate.json').exists():raise QualificationError('Candidate binding is immutable')
    atomic(root/'candidate.json',identity)


def verify(root,*,require_candidate=False):
    root=Path(root).absolute();manifest=read(root/'manifest.json');state=read(root/'state.json')
    if 'browser_fixture_followup' in manifest:
        return _browser_fixture_followup_call('verify',root,require_candidate=require_candidate)
    if 'browser_followup' in manifest:
        return _browser_followup_call('verify',root,require_candidate=require_candidate)
    if 'retained_requalification' in manifest:
        return _retained_call('verify',root,require_candidate=require_candidate)
    if 'campaign_amendment' in manifest:
        amendment=_launch_module().amendment_module(manifest['campaign_amendment'])
        if root!=amendment.FINAL_ROOT:raise QualificationError('Matrix amendment root changed')
    if (read(root/'integrity.json')!={'manifest_sha256':sha(root/'manifest.json')} or manifest['prepared_root']!=str(root)
            or manifest['limits']!=_effective_limits(manifest) or manifest['source']!=source_identity() or manifest['planned_container_launches']!=186):raise QualificationError('Frozen source/matrix/limits changed')
    if manifest['negative_oracles']!={'tool_results':SCRIPT_RESULTS,'reserve_counts':RESERVE_COUNTS,'reserve_remaining':6,
        'scope':'expected negative failures are qualification assertions, never model task success'}:raise QualificationError('Frozen negative oracle changed')
    c.exact(manifest['host_admission'],{'lock_file','wait_seconds'},'/host_admission')
    if (manifest['host_admission']['wait_seconds']!=ADMISSION_WAIT_SECONDS or type(manifest['host_admission']['wait_seconds']) is not int
            or manifest['host_admission']['lock_file']!=str(Path(lab.default_lock_file()).expanduser().absolute())):
        raise QualificationError('Shared host admission policy changed')
    base=matrix(manifest['images'])
    if len(manifest['cells'])!=len(base):raise QualificationError()
    for cell,expected in zip(manifest['cells'],base):
        if {key:cell.get(key) for key in expected}!=expected or set(cell)-set(expected)-{'trial_id','plan_sha256'}:raise QualificationError()
    _launch_module().validate_manifest(_launch_manifest(manifest))
    if 'predecessor' in manifest:
        carried=(_launch_module()._effective_carry(manifest,_launch_window=False) if 'campaign_boundary' in manifest
            else _launch_module().validate_predecessor(manifest['predecessor'],_launch_window=False))
        if 'campaign_boundary' in manifest and state.get('started_at')!=carried['started_wall']:raise QualificationError('Frozen campaign clock changed')
    for path,digest in manifest['files'].items():
        c.relative(path,'/files')
        if sha(root/path)!=digest:raise QualificationError('Frozen application input changed')
    if require_candidate:
        bound=read(root/'candidate.json');c.exact(bound,{'archive_sha256','runner_sha256','scope'},'/candidate')
        if bound['runner_sha256']!=manifest['source']['runner'] or bound['scope']!='extracted_candidate':raise QualificationError()
        c.sha256(bound['archive_sha256'],'/candidate')
    return manifest,state


@contextlib.contextmanager
def controller(root):
    path=Path(root)/'controller.lock';fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise QualificationError('Qualification controller is already active') from None
        yield
    finally:os.close(fd)


def _remaining(root):
    state=read(Path(root)/'state.json');started=state.get('started_at')
    remaining=LIMITS['global_seconds'] if type(started) not in (int,float) else LIMITS['global_seconds']-(time.time()-started)
    path=Path(root)/'manifest.json'
    if path.exists():
        manifest=read(path)
        if 'predecessor' in manifest:
            carried=(_launch_module()._effective_carry(manifest,_launch_window=False) if 'campaign_boundary' in manifest
                else _launch_module().validate_predecessor(manifest['predecessor'],_launch_window=False))
            remaining=min(remaining,carried['deadline_wall']-time.time())
    return remaining


@contextlib.contextmanager
def _deadline_signal(root,*,reserve=True):
    """Interrupt only this owning process; never extend the global deadline."""
    delay=_remaining(root)-(30 if reserve else 0)
    if delay<=0 or threading.current_thread() is not threading.main_thread():raise QualificationError('Global qualification deadline unavailable')
    timer=threading.Timer(delay,lambda:os.kill(os.getpid(),signal.SIGINT));timer.daemon=True;timer.start()
    try:yield
    finally:timer.cancel()


def _known_values(manifest):
    refs=manifest['credential_references'];store=manifest['secrets_dir'];values=[]
    values.extend(credentials.read(refs[name],store) for name in ('alice','bob'))
    for name in [refs['scripted_inference'],manifest['endpoint']['api_key_env']]:
        value=secret_store.resolve_secret(name,store)[0]
        if not value:raise QualificationError('Required private authority is unavailable')
        values.append(value)
    if any(not value.isascii() or not 16<=len(value)<=4096 or any(ord(ch)<=32 or ord(ch)==127 for ch in value) for value in values[:3]):
        raise QualificationError('Disposable fixture/script authority is not a bounded HTTP credential')
    if values[0]==values[1] or values[2]==values[3] or any(value in values[2:] for value in values[:2]):raise QualificationError('Application and inference authority collision')
    return list(dict.fromkeys(values))


def _scan_frozen(root,manifest,values):
    redactor=credentials.Redactor(values)
    if redactor.contains(c.canonical(manifest)):raise QualificationError('Known private authority appears in frozen qualification metadata')
    for path in manifest['files']:
        if redactor.contains(preparation._read(Path(root)/path,64*1024*1024)):raise QualificationError('Known private authority appears in frozen inputs')


def _native():
    value=json.loads(lab.command(['docker','info','--format','{{json .}}'],timeout=15).stdout)
    if value.get('OSType')!='linux' or lab.norm_arch(value.get('Architecture',''))!='arm64':raise QualificationError('Native ARM64 Docker daemon required')
    daemon=lab.command(['docker','info','--format','{{.ID}}'],timeout=15).stdout.strip()
    if not daemon:raise QualificationError()
    return daemon,{'cpu_millis':int(value['NCPU']*1000),'memory_mib':int(value['MemTotal'])//(1024**2)}


def _aggregate(capacity,browser,scripted):
    helper={'cpu_millis':2000 if browser else 1000,'memory_mib':2048 if browser else 512,'pids_limit':512 if browser else 128}
    wanted={'cpu_millis':helper['cpu_millis']+1000+250*(1+int(scripted)),
        'memory_mib':helper['memory_mib']+1024+128*(1+int(scripted)),'pids_limit':helper['pids_limit']+256+64*(1+int(scripted))}
    available={'cpu_millis':capacity['cpu_millis']//2,'memory_mib':capacity['memory_mib']//2,'pids_limit':4096}
    if any(wanted[key]>available[key] for key in wanted):raise QualificationError('Complete qualification topology exceeds host allocation')
    return wanted


def _launch_module():
    import application_launch
    return application_launch


def _mounted_as_declared(record,observed):
    expected=record.get('mounts');actual=observed.get('Mounts')
    return (type(expected) is list and type(actual) is list and len(expected)==len(actual)
        and all(any(item.get('Type')=='bind' and item.get('Source')==wanted['source']
            and item.get('Destination')==wanted['target'] and item.get('RW') is wanted['rw'] for item in actual) for wanted in expected))


def _reap_service_process(process,deadline,*,reader=False,primary=None):
    """Dispose only this returned CLI within the caller's existing deadline.

    Signal/wait cancellation cannot erase custody. A confirmed reap preserves
    the primary exception; otherwise only the exact known PID escapes.
    """
    interrupted=None;reaped=False
    def attempt(function,*args,**kwargs):
        nonlocal interrupted
        try:return True,function(*args,**kwargs)
        except BaseException as error:
            if primary is None and interrupted is None and not isinstance(error,(OSError,subprocess.SubprocessError)):
                interrupted=error
            return False,None
    def confirmed(code):
        nonlocal reaped
        if type(code) is not int:return False
        reaped=True
        if interrupted is not None:raise interrupted
        return True
    try:
        ok,code=attempt(process.poll)
        if ok and confirmed(code):return
        if reader:
            attempt(process.terminate)
            ok,code=attempt(process.wait,timeout=max(0,(deadline-time.monotonic())/2))
            if ok and confirmed(code):return
        attempt(process.kill)
        if reader:ok,code=attempt(process.wait,timeout=max(0,deadline-time.monotonic()))
        else:
            ok,_=attempt(process.communicate,timeout=max(0,deadline-time.monotonic()))
            valid,code=attempt(lambda:process.returncode);ok=ok and valid
        if ok and confirmed(code):return
    finally:
        # Also cover cancellation between the bounded signal/wait operations.
        if not reaped:
            error_type=ServiceReaderUnconfirmed if reader else ServiceProcessUnconfirmed
            raise error_type(getattr(process,'pid',None)) from None


def _bounded_service_logs(container,*,maximum=32768,seconds=3,popen=None,deadline=None):
    """Bound both Docker CLI pipes; terminating this reader never stops a service."""
    deadline=min(time.monotonic()+seconds,deadline) if deadline is not None else time.monotonic()+seconds
    if deadline<=time.monotonic():raise QualificationError()
    process=(popen or subprocess.Popen)(['docker','logs','--tail','20',container],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    parts={'stdout':bytearray(),'stderr':bytearray()};complete=True
    try:
        with selectors.DefaultSelector() as selector:
            for name,stream in (('stdout',process.stdout),('stderr',process.stderr)):
                os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
            while selector.get_map():
                remaining=deadline-time.monotonic()-min(.5,seconds/2)
                if remaining<=0:complete=False;break
                for key,_ in selector.select(remaining):
                    body=os.read(key.fileobj.fileno(),min(4096,maximum-sum(map(len,parts.values()))+1))
                    if not body:selector.unregister(key.fileobj);continue
                    parts[key.data].extend(body)
                    if sum(map(len,parts.values()))>maximum:complete=False;break
                if not complete:break
        if complete:
            remaining=deadline-time.monotonic()
            if remaining<=0:complete=False
            else:process.wait(timeout=remaining)
    except (OSError,subprocess.SubprocessError):complete=False
    finally:
        primary=sys.exc_info()[1];closing_error=None
        for stream in (process.stdout,process.stderr):
            try:stream.close()
            except BaseException as error:
                if closing_error is None and not isinstance(error,OSError):closing_error=error
        _reap_service_process(process,deadline,reader=True,primary=primary or closing_error)
        if primary is None and closing_error is not None:raise closing_error
        if deadline<=time.monotonic():complete=False
    return {'complete':complete,'stdout':bytes(parts['stdout']) if complete else b'',
        'stderr':bytes(parts['stderr']) if complete else b''}


class OwnedServices:
    """Only the exact fixed fixture/script container roles; actual registry custody."""
    def __init__(self,root,manifest,cell,args,registry,guard,values):
        self.root,self.manifest,self.cell=Path(root),manifest,cell;self.args,self.registry,self.guard=args,registry,guard
        self.redactor=credentials.Redactor(values);self.items=[];self.private=None;self.safe=False
        self.service_states={};self.private_identities={};self.unconfirmed_cli=[]
        self.folder=self.root/'cells'/cell['id'];self.folder.mkdir(mode=0o700,parents=True,exist_ok=True)
    def start(self):
        self.private=Path(tempfile.mkdtemp(prefix='pi-application-qualification-')).resolve();os.chmod(self.private,0o700)
        self.private_identity=_private_identity(self.private)
        fixture_private=self.private/'fixture';fixture_private.mkdir(mode=0o700)
        store=fixture_private/'store';store.mkdir(mode=0o700);refs=self.manifest['credential_references']
        for name in (refs['alice'],refs['bob']):secret_store.write_secret(name,credentials.read(name,self.manifest['secrets_dir']),store)
        journal_mount=self.folder/'fixture-journal';journal_mount.mkdir(mode=0o700)
        self.journal=journal_mount/'private';self.journal.mkdir(mode=0o700)
        self._start('fixture',journal_mount,['/opt/pi-skill/examples/authenticated-application/fixture.py','--journal-dir','/observations/private',
            '--secrets-dir','/private/store','--alice-reference',refs['alice'],'--bob-reference',refs['bob'],'--host','0.0.0.0','--port','8080',
            '--mode','timeout-after-commit' if self.cell.get('scenario')=='publication-response-loss' else 'normal','--timeout-seconds','900'],
            self.manifest['fixture_route']['fixture_port'],fixture_private)
        if self.cell['group']=='N02':
            observations=self.folder/'scripted-observations';observations.mkdir(mode=0o700)
            (observations/'private').mkdir(mode=0o700)
            scripted_private=self.private/'scripted';scripted_private.mkdir(mode=0o700)
            bootstrap_private=scripted_private/'bootstrap';bootstrap_private.mkdir(mode=0o700)
            atomic(bootstrap_private/'config.json',{'schema':1,'document_type':'application_scripted_bootstrap','case_id':self.cell['case'],
                'model':'application-script-'+self.cell['variant'],'inference_key':secret_store.resolve_secret(refs['scripted_inference'],self.manifest['secrets_dir'])[0],'lifetime_seconds':900})
            self._start('scripted-inference',observations,['/qualification/application_scripted.py','--private-bootstrap','/private/bootstrap/config.json',
                '--observations','/observations/private/scripted.json','--host','0.0.0.0','--port','8080'],self.manifest['fixture_route']['scripted_port'],scripted_private)
        return self
    def _start(self,role,observations,command,port,private):
        readiness={}
        if role=='fixture':
            if '--readiness-id' in command:raise QualificationError('Fixture readiness identity already supplied')
            wrapper=open_directory(Path(observations).absolute(),private=True);child=None
            try:
                outer=os.fstat(wrapper)
                if stat.S_IMODE(outer.st_mode)!=0o700:raise QualificationError('Fixture readiness directory unavailable')
                child=os.open('private',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=wrapper)
                inner=os.fstat(child)
                if inner.st_uid!=os.getuid() or stat.S_IMODE(inner.st_mode)!=0o700 or os.listdir(child):raise QualificationError('Fresh fixture readiness directory required')
                readiness={'readiness_id':str(uuid.uuid4()),'readiness_root_identity':(inner.st_dev,inner.st_ino),
                    'readiness_wrapper_identity':(outer.st_dev,outer.st_ino)}
                command=[*command,'--readiness-id',readiness['readiness_id']]
            finally:
                if child is not None:os.close(child)
                os.close(wrapper)
        image=self.manifest['images']['core-'+self.cell['release']]['id'];name='pi-app-qualification-'+uuid.uuid4().hex[:16]
        argv=['docker','run','--detach','--pull=never','--name',name,'--platform','linux/arm64','--read-only','--cap-drop=ALL',
            '--security-opt=no-new-privileges=true','--ipc=none','--cpus','0.25','--memory','128m','--memory-swap','128m','--pids-limit','64',
            '--user',str(os.getuid())+':'+str(os.getgid()),'--network','bridge','--publish',self.manifest['fixture_route']['publish_host']+':'+str(port)+':8080',
            '--env','PYTHONDONTWRITEBYTECODE=1','--env','PYTHONUNBUFFERED=1','--mount','type=bind,src='+str(SKILL)+',dst=/opt/pi-skill,readonly,bind-recursive=disabled',
            '--mount','type=bind,src='+str(HERE)+',dst=/qualification,readonly,bind-recursive=disabled','--mount','type=bind,src='+str(private)+',dst=/private,readonly,bind-recursive=disabled',
            '--mount','type=bind,src='+str(observations)+',dst=/observations,bind-recursive=disabled','--entrypoint','python3',image,*command]
        record,argv=self.guard.external_service_intent(self.registry,argv,role,self.args._attempt_root)
        self.items.append((record,name));self.service_states[record['launch_id']]={'role':role,'ready':False,'observations':Path(observations),**readiness}
        self.private_identities[record['launch_id']]=ownership_registry.observe_qualification_private(record)
        try:self._await_ready(record,name,role,observations,argv,image)
        except BaseException as error:
            # Closed passive metadata is retained in the existing terminal
            # receipt; diagnostic collection never replaces this primary error.
            try:
                state=self.service_states[record['launch_id']]
                phase=state.get('startup_phase')
                phase=phase if phase in ('container_launch','container_observation','readiness_custody','readiness_signal','readiness_wait') else 'unobserved'
                failure={'role':role,'phase':phase,'readiness_deadline_expired':getattr(error,'readiness_deadline',None) is True}
                detail=timing.extract_service_diagnostic(error)
                if detail is not None:failure['service_deadline']=detail
                if getattr(self,'startup_failure',None) is None:self.startup_failure=failure
            except BaseException:pass
            try:self._diagnose(record,name,'startup_failed')
            except Exception:pass
            raise

    def _fixture_ready(self,record,observations,deadline):
        """Read only the fresh fixture's bounded nonce-bound startup receipt.

        The initial journal exists before bind and is not a readiness signal.
        Both files and their owned directory names stay fenced through the read.
        """
        wrapper=child=None;leaves=[]
        try:
            _readiness_remaining(deadline)
            state=self.service_states[record['launch_id']]
            if state['role']!='fixture' or Path(observations)!=state['observations'] or not controls.valid_id(state['readiness_id']):raise QualificationError('Fixture readiness unavailable')
            wrapper=open_directory(Path(observations).absolute(),private=True);outer=os.fstat(wrapper)
            if stat.S_IMODE(outer.st_mode)!=0o700 or (outer.st_dev,outer.st_ino)!=state['readiness_wrapper_identity']:raise QualificationError('Fixture readiness unavailable')
            _readiness_remaining(deadline)
            child=os.open('private',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=wrapper)
            def fence():
                _readiness_remaining(deadline)
                opened=os.fstat(child);named=os.stat('private',dir_fd=wrapper,follow_symlinks=False)
                if (not stat.S_ISDIR(named.st_mode) or named.st_uid!=os.getuid() or stat.S_IMODE(named.st_mode)!=0o700
                        or (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino)
                        or (opened.st_dev,opened.st_ino)!=state['readiness_root_identity']):raise QualificationError('Fixture readiness unavailable')
                current=open_directory(Path(observations).absolute(),private=True)
                try:
                    info=os.fstat(current)
                    if stat.S_IMODE(info.st_mode)!=0o700 or (info.st_dev,info.st_ino)!=(outer.st_dev,outer.st_ino):raise QualificationError('Fixture readiness unavailable')
                finally:os.close(current)
                _readiness_remaining(deadline)
            identity=lambda info:tuple(getattr(info,key)for key in ('st_dev','st_ino','st_uid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
            def selected(name,maximum,*,allow_missing=False):
                fence()
                try:fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=child)
                except FileNotFoundError:
                    if allow_missing:fence();return None,None
                    raise
                leaves.append(fd)
                before=os.fstat(fd)
                if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or stat.S_IMODE(before.st_mode)!=0o600
                        or before.st_nlink!=1 or before.st_size>maximum):raise QualificationError('Fixture readiness unavailable')
                chunks=[];size=0
                while size<=maximum:
                    _readiness_remaining(deadline);part=os.read(fd,min(65536,maximum+1-size))
                    if not part:break
                    chunks.append(part);size+=len(part)
                body=b''.join(chunks);after=os.fstat(fd);named=os.stat(name,dir_fd=child,follow_symlinks=False)
                if len(body)!=before.st_size or identity(before)!=identity(after) or identity(before)!=identity(named):raise QualificationError('Fixture readiness unavailable')
                fence();return c.loads(body,max_bytes=maximum),before
            ready,ready_info=selected('readiness.json',4096,allow_missing=True)
            if ready_info is None:return False
            c.exact(ready,{'schema','document_type','fixture_id','readiness_id','state','port'},'')
            if (type(ready['schema']) is not int or ready['schema']!=1 or ready['document_type']!='application_fixture_readiness'
                    or not controls.valid_id(ready['fixture_id']) or ready['readiness_id']!=state['readiness_id']
                    or ready['state']!='ready' or type(ready['port']) is not int or ready['port']!=8080):raise QualificationError('Fixture readiness unavailable')
            journal,journal_info=selected('journal.json',262144)
            c.exact(journal,{'schema','document_type','fixture_id','application_id','tenant_id','requests','pages','publications','closed'},'')
            if (type(journal['schema']) is not int or journal['schema']!=1 or journal['document_type']!='application_fixture_journal'
                    or journal['fixture_id']!=ready['fixture_id'] or journal['application_id']!='diagnostic-app' or journal['tenant_id']!='team-1'
                    or journal['closed'] is not False or any(journal[key]!=[] for key in ('requests','pages','publications'))):raise QualificationError('Fixture readiness unavailable')
            fence()
            for name,info in (('readiness.json',ready_info),('journal.json',journal_info)):
                _readiness_remaining(deadline)
                if identity(os.stat(name,dir_fd=child,follow_symlinks=False))!=identity(info):raise QualificationError('Fixture readiness unavailable')
            _readiness_remaining(deadline);return True
        except QualificationError:raise
        except (OSError,ValueError,TypeError,KeyError,AttributeError):raise QualificationError('Fixture readiness unavailable') from None
        finally:
            for fd in reversed(leaves):os.close(fd)
            if child is not None:os.close(child)
            if wrapper is not None:os.close(wrapper)
    def _observation(self,record,name,seconds=3):
        inspection=lab.command(['docker','container','inspect',name],timeout=max(.01,min(3,seconds)),required=False)
        if inspection.returncode!=0:raise QualificationError('Service container observation unavailable')
        observed=json.loads(inspection.stdout)[0];labels=observed.get('Config',{}).get('Labels',{})
        if (record.get('container_id') is not None and observed['Id']!=record['container_id'] or observed['Image']!=record['image']
                or labels.get(ownership_registry.LABEL)!=record['launch_id'] or labels.get(ownership_registry.REGISTRY_LABEL)!=self.registry.registry_id
                or not _mounted_as_declared(record,observed)):
            raise QualificationError('Foreign service container observed; no inspection or deletion authorized')
        return observed
    def _remember_unconfirmed(self,error):
        # Sticky process disposition only, never checked application authority.
        rows=getattr(self,'unconfirmed_cli',[])
        row={'pid':error.pid,'pid_available':error.pid is not None,'reaped':False}
        if row not in rows:rows.append(row)
        self.unconfirmed_cli=rows
    def _process_barrier(self):
        rows=getattr(self,'unconfirmed_cli',[])
        if rows:raise ServiceProcessUnconfirmed(rows[0]['pid'])
    def _logs(self,container,seconds=3,record=None,deadline=None):
        self._process_barrier()
        deadline=min(time.monotonic()+max(0,min(3,seconds)),deadline) if deadline is not None else time.monotonic()+max(0,min(3,seconds))
        popen=None
        if record is not None and getattr(self,'guard',None) is not None:
            popen=lambda argv,**kwargs:self.guard.service_process(record,'logs',deadline,**kwargs)
        try:captured=_bounded_service_logs(container,seconds=max(0,min(3,seconds)),popen=popen,deadline=deadline)
        except ServiceProcessUnconfirmed as error:
            self._remember_unconfirmed(error);raise
        if not captured['complete'] or any(self.redactor.contains(captured[key]) for key in ('stdout','stderr')):
            return {'available':False,'stdout':'','stderr':''}
        return {'available':True,**{key:captured[key].decode('utf-8',errors='replace') for key in ('stdout','stderr')}}
    def _diagnose(self,record,name,phase,deadline=None):
        self._process_barrier()
        deadline=min(time.monotonic()+3,deadline) if deadline is not None else time.monotonic()+3
        if deadline<=time.monotonic():raise QualificationError()
        observed=self._observation(record,name,deadline-time.monotonic());state=observed.get('State',{})
        if deadline<=time.monotonic():raise QualificationError()
        logs=self._logs(observed['Id'],deadline-time.monotonic(),record,deadline)
        status=state.get('Status');exit_code=state.get('ExitCode')
        atomic(self.folder/('service-diagnostic-'+record['launch_id']+'-'+phase+'.json'),{'schema':1,'role':self.service_states[record['launch_id']]['role'],
            'phase':phase,'running':state.get('Running') is True,'status':status if status in ('created','running','paused','restarting','removing','exited','dead') else 'unavailable',
            'exit_code':exit_code if type(exit_code) is int and 0<=exit_code<=255 else None,'oom_killed':state.get('OOMKilled') is True,
            'startup_readied':self.service_states[record['launch_id']]['ready'],'logs':logs})
    def _await_ready(self,record,name,role,observations,argv,image):
        state=self.service_states[record['launch_id']];state['startup_phase']='container_launch'
        lab.command(argv,timeout=20)
        deadline=time.monotonic()+15
        while True:
            _readiness_remaining(deadline);state['startup_phase']='container_observation'
            inspected=self._observation(record,name,deadline-time.monotonic())
            if role=='fixture':
                # The former logs guard supplied this fresh daemon/Registry/
                # captured-CID fence. A readiness file cannot replace custody.
                state['startup_phase']='readiness_custody'
                identifier=self.guard.service_readiness_check(record,inspected,deadline)
                if identifier!=inspected['Id']:raise QualificationError('Fixture readiness ownership unavailable')
                _readiness_remaining(deadline)
            # Keep immutable custody even when the owned service exits before
            # readiness, so cleanup never infers absence from a reusable name.
            record['container_id']=inspected['Id'];self.registry.write(record)
            actual=inspected['HostConfig']
            if (inspected['Image']!=image or actual.get('NanoCpus')!=250000000 or actual.get('Memory')!=134217728
                    or actual.get('MemorySwap')!=134217728 or actual.get('PidsLimit')!=64):raise QualificationError('Service resource/image observation mismatch')
            if inspected.get('State',{}).get('Running') is not True:
                raise QualificationError('Owned service exited before readiness')
            record['status']='running';self.registry.write(record)
            _readiness_remaining(deadline);state['startup_phase']='readiness_signal'
            if role=='scripted-inference':
                path=observations/'private/scripted.json'
                if path.exists():
                    ready=read(path)
                    if (ready.get('phase')=='ready' and ready.get('case_id')==self.cell['case']
                            and ready.get('model')=='application-script-'+self.cell['variant'] and ready.get('stopped') is False):break
            else:
                if self._fixture_ready(record,observations,deadline):break
            _readiness_remaining(deadline);state['startup_phase']='readiness_wait'
            time.sleep(.1)
        _readiness_remaining(deadline)
        self.service_states[record['launch_id']]['ready']=True
    def _service_command(self,record,operation,deadline,seconds):
        self._process_barrier()
        # Leave one second inside the same deadline to reap only this Docker CLI.
        process=self.guard.service_process(record,operation,deadline,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            remaining=min(seconds,deadline-time.monotonic()-1)
            if remaining<=0:raise subprocess.TimeoutExpired(operation,0)
            output,error=process.communicate(timeout=remaining)
            if deadline<=time.monotonic():raise QualificationError()
            return subprocess.CompletedProcess(operation,process.returncode,output,error)
        except BaseException as primary:
            try:_reap_service_process(process,deadline,primary=primary)
            except ServiceProcessUnconfirmed as error:
                self._remember_unconfirmed(error);raise
            # Confirmed reap preserves the exact primary timeout/cancellation.
            raise

    def close(self):
        deadline=time.monotonic()+max(0,min(30,_remaining(self.root)))
        with self.guard.service_cleanup(self.registry,deadline):
            return self._close(deadline)

    def _close(self,deadline):
        unconfirmed=list(getattr(self,'unconfirmed_cli',[]));errors=[True] if unconfirmed else [];physical=not unconfirmed
        def remaining():
            value=deadline-time.monotonic()
            if value<=0:raise QualificationError()
            return value
        for record,name in (() if unconfirmed else reversed(self.items)):
            try:
                left=deadline-time.monotonic()
                if left<=0:raise QualificationError()
                inspection=lab.command(['docker','container','inspect',name],timeout=min(3,left),required=False)
                if inspection.returncode==0:
                    observed=json.loads(inspection.stdout)[0];labels=observed.get('Config',{}).get('Labels',{})
                    if (record.get('container_id') is not None and observed['Id']!=record['container_id'] or observed['Image']!=record['image']
                            or labels.get(ownership_registry.LABEL)!=record['launch_id'] or labels.get(ownership_registry.REGISTRY_LABEL)!=self.registry.registry_id
                            or not _mounted_as_declared(record,observed)):
                        raise QualificationError('Foreign service container observed; no deletion authorized')
                    record['container_id']=observed['Id'];self.registry.write(record)
                    try:self._diagnose(record,name,'before_removal',deadline=deadline)
                    except ServiceReaderUnconfirmed:raise
                    except Exception:pass
                    self._service_command(record,'stop',deadline,18)
                    self._service_command(record,'rm',deadline,5)
                remaining()
                if self.registry.confirm_absent(record) is not True:raise QualificationError('Service physical absence unknown')
                remaining()
            except ServiceProcessUnconfirmed as error:
                self._remember_unconfirmed(error);unconfirmed=list(self.unconfirmed_cli)
                errors.append(True);physical=False;break
            except Exception:errors.append(True);physical=False
        terminal=self.journal/'terminal-receipt.json' if hasattr(self,'journal') else None
        try:
            receipt=read(terminal,16384) if terminal is not None else None
            terminal_available=(type(receipt) is dict and receipt.get('schema')==1
                and receipt.get('document_type')=='application_fixture_terminal_receipt'
                and receipt.get('process')=={'exit_code':0,'cleanup_confirmed':True,'writers_stopped':True})
        except (OSError,ValueError,TypeError):terminal_available=False
        if not errors:
            try:
                remaining()
                if self.private is not None:
                    _purge_private(self.private,self.private_identity);self.private=None
                receipts=self.folder/'service-cleanup-receipts'
                if self.items:receipts.mkdir(mode=0o700,exist_ok=True)
                for record,_ in self.items:
                    remaining()
                    state=self.service_states[record['launch_id']]
                    record['qualification_service_cleanup']=ownership_registry.write_qualification_service_cleanup(record,receipts/(record['launch_id']+'.json'),
                        private_identity=self.private_identities[record['launch_id']],physical_absence_confirmed=True,private_bootstrap_removed=True,
                        terminal_available=terminal_available,startup_readied=state['ready'])
                    remaining()
                    self.registry.write(record);remaining();self.registry.release(record,True)
                    remaining()
                self.safe=True
            except Exception:errors.append(True)
        result={'schema':1,'safe_to_continue':self.safe,'physical_absence_confirmed':physical,
            'private_bootstrap_removed':self.private is None,'terminal_available':terminal_available,
            'qualification_eligible':self.safe and terminal_available and all(value['ready'] for value in self.service_states.values()),
            'unconfirmed_owned_cli':unconfirmed}
        if getattr(self,'startup_failure',None) is not None:result['startup_failure']=copy.deepcopy(self.startup_failure)
        atomic(self.folder/'services-cleanup.json',result)
        if errors:raise QualificationError('Owned service cleanup is unconfirmed')
        return terminal


class _ControlledCancellation:
    """Child-owned identity for the one frozen sensitive-interruption cell.

    This is not a caller-supplied cleanup boolean. Parent-owned handoff, stage,
    process and service receipts must still bind the actual lease and Registry.
    """
    def __init__(self,root,manifest,cell,initial,values):
        self.root=Path(root);self.manifest=manifest;self.cell=cell;self.initial=initial
        self.values=values

    def known_clean(self,args,registry,services):
        try:
            cell,initial=self.cell,self.initial
            if (cell.get('group')!='N02' or cell.get('scenario')!='sensitive-participant-interruption'
                    or cell.get('real_model') is not False or type(services) is not OwnedServices
                    or services.registry is not registry or services.root!=self.root
                    or services.cell!=cell or services.safe is not True
                    or ownership_registry.CURRENT.get() is not registry):return False
            runroot=Path(args._attempt_root)
            if (runroot!=Path(_cell_args(self.root,self.manifest,cell).results_dir)/initial['run_id']
                    or Path(registry.runroot)!=runroot
                    or args._attempt_identity!={key:initial[key] for key in ('run_id','attempt_id')}
                    or any(registry.binding.get(key)!=initial[key] for key in ('run_id','attempt_id'))):return False
            active=read(self.root/'state.json')
            if (active.get('active_cell')!={'id':cell['id'],'pid':os.getpid(),
                    'run_id':initial['run_id'],'attempt_id':initial['attempt_id']}
                    or active.get('cells',{}).get(cell['id'])!={'status':'started','attempts':1,
                        'run_id':initial['run_id'],'attempt_id':initial['attempt_id']}):return False
            marker_path=self.root/'cells'/cell['id']/'participant-handoff.json'
            marker=_handoff_read(marker_path)
            if type(marker) is not dict:return False
            desc,state=controls.resolve(runroot,marker.get('stage_id'))
            binding={key:initial[key] for key in ('run_id','attempt_id')}
            binding.update(stage_id=desc['stage_id'],segment_id=state.get('segment_id'))
            if (marker!=_handoff_marker_value(self.manifest,cell,initial,desc,binding,os.getpid())
                    or desc.get('workspace')!=str(runroot/'workspace')
                    or desc.get('admission_lock_file')!=str(Path(args.lock_file).absolute())
                    or state.get('status')!='finalized' or state.get('exit_code')!=130
                    or state.get('cleanup_confirmed') is not True):return False
            process=read(runroot/'agent-1-participant/process.json',2*1024*1024)
            if (type(process) is not dict or any(type(process.get(key)) is not dict for key in
                    ('application_helper_cleanup','application_credentials','native_tool_budget','application_completion'))):return False
            helper=process.get('application_helper_cleanup',{})
            credential=process.get('application_credentials',{})
            if (type(process.get('exit_code')) is not int or process['exit_code']!=130
                    or process.get('cancelled') is not True or process.get('timed_out') is not False
                    or process.get('cleanup_confirmed') is not True
                    or helper.get('status')!='removed' or helper.get('workspace')!='clean'
                    or helper.get('safe_to_continue') is not True
                    or credential.get('status')!='removed'
                    or credential.get('workspace') not in ('clean','discarded')
                    or process.get('native_tool_budget',{}).get('accounting')!='available'
                    or process.get('application_completion',{}).get('status')!='not_evaluated'):return False
            receipt=read(runroot/'stages'/desc['stage_id']/'application-credentials.json',16384)
            if any(receipt.get(key)!=credential.get(key) for key in ('status','workspace')):return False
            closed=read(services.folder/'services-cleanup.json',65536)
            if (closed.get('safe_to_continue') is not True
                    or closed.get('physical_absence_confirmed') is not True
                    or closed.get('private_bootstrap_removed') is not True
                    or closed.get('unconfirmed_owned_cli')!=[]):return False
            snapshot=services.guard.ledger.snapshot()
            rows=[row for row in snapshot['launches'] if row['cell']==cell['id']]
            workers={'probe','boundary','preflight','participant'}
            if (snapshot['poisoned'] or sum(row['role']=='participant' for row in rows)!=1
                    or {row['role'] for row in rows if not row['private_cleanup']}-workers
                    or any(row['registry']!=registry.registry_id or row['generation']!=registry.generation
                        or row['physical']!='absent' or row['container_id'] is None for row in rows)):return False
            _cleanup_material(runroot,self.values)
            return _handoff_read(marker_path)==marker
        except (KeyboardInterrupt,SystemExit,GeneratorExit,TimeoutError):raise
        except (OSError,ValueError,KeyError,TypeError,AttributeError,IndexError):return False


@contextlib.contextmanager
def actual_lease(args,services_factory,*,original=None,_cancellation=None):
    """Enter original flock exactly once; yield its actual Registry unchanged."""
    original=original or resources.admission_lock
    deferred=None
    with original(args.lock_file,args.lock_wait_seconds) as registry:
        if ownership_registry.CURRENT.get() is not registry:raise QualificationError('Actual host registry custody missing')
        registry.runroot=Path(args._attempt_root);registry.binding=copy.deepcopy(args._attempt_identity)
        services=services_factory(registry)
        try:services.start();yield registry
        except KeyboardInterrupt as error:
            # Only the frozen, identity-bound controlled cancellation may let
            # original Registry.close run. Unknown cleanup retains old behavior.
            closed=False
            try:services.close();closed=True
            except BaseException:pass
            if (type(error) is KeyboardInterrupt and closed
                    and type(_cancellation) is _ControlledCancellation
                    and _cancellation.known_clean(args,registry,services)):
                deferred=error
            else:raise
        except BaseException:
            # close retains its own bounded receipt; never replace the primary
            # startup/participant failure with an exception from finalization.
            try:services.close()
            except BaseException:pass
            raise
        else:services.close()
    # A failed original lease close is propagated instead; it cannot become a
    # successful cancellation. The known-clean path preserves the same object.
    if deferred is not None:raise deferred


def negative_verdict(scenario,record,journal,oracle,*,interruption_sent=False,participant_launches=None,stage_metadata=None):
    """Closed assertions; never classify a deliberate failure as task success."""
    agents=record.get('agents',[]);process=agents[0].get('process',{}) if len(agents)==1 else {}
    completion=record.get('application_completion',{}).get('stages',[{}])[0]
    interrupted=scenario=='sensitive-participant-interruption'
    if interrupted and agents==[] and type(record.get('last_process')) is dict:
        process=record['last_process'];completion=process.get('application_completion',{})
    diagnostics={row.get('code') for row in completion.get('diagnostics',[])};requests=journal.get('requests',[]);posts=[r for r in requests if r.get('method')=='POST']
    budget=process.get('native_tool_budget',{});counts=budget.get('counts',{});known=process.get('cleanup_confirmed') is True
    known=known and process.get('application_helper_cleanup',{}).get('safe_to_continue') is True and process.get('application_credentials',{}).get('status')=='removed'
    checks={'one_agent':len(agents)==1 or interrupted and agents==[] and type(record.get('last_process')) is dict,
        'cleanup_known':known,'no_success_claim':record.get('status')!='PASS'}
    if scenario=='invalid-typed-request':checks.update(no_http=not requests,failed=record.get('status')=='FAIL',
        one_attempt=counts.get('attempted')==1,charged=counts.get('charged')==1,blocked=counts.get('blocked')==1)
    elif scenario=='wrong-actor':checks.update(no_business=all(r.get('path')=='/identity' for r in requests),bob_observed=any(r.get('actor_id')=='actor-bob' for r in requests),participant=completion.get('status')=='invalid' and 'participant_mismatch' in diagnostics)
    elif scenario=='omitted-report':checks.update(settled=record.get('invocation',{}).get('status')=='verified',content_pass=record.get('task_result',{}).get('status')=='pass',report_missing='report_missing' in diagnostics,one_commit=len(posts)==len(journal.get('publications',[]))==1)
    elif scenario=='multi-call-reserve-boundary':checks.update(only_identity=all(r.get('path')=='/identity' for r in requests),phase=budget.get('phase')=='reporting',
        exact_counts=all(type(counts.get(key)) is int and counts[key]==value for key,value in RESERVE_COUNTS.items()),reserve=budget.get('reporting_reserve_calls_remaining')==6)
    elif scenario=='publication-response-loss':checks.update(one_commit=len(posts)==len(journal.get('publications',[]))==1,unknown='publication_outcome_unknown' in diagnostics,oracle_unknown='publication_outcome_unknown' in oracle.get('diagnostics',[]))
    elif scenario=='sensitive-participant-interruption':
        metadata_ok=(type(stage_metadata) is list and len(stage_metadata)==1 and stage_metadata[0].get('kind')=='agent'
            and stage_metadata[0].get('run_id')==record.get('run_id') and stage_metadata[0].get('attempt_id')==record.get('attempt_id')
            and controls.valid_id(stage_metadata[0].get('stage_id')) and stage_metadata[0].get('label')=='agent-1-participant')
        checks.update(signal_sent=interruption_sent,interrupted=record.get('status')=='INTERRUPTED',not_evaluated=completion.get('status')=='not_evaluated',
            oracle_not_evaluated=oracle.get('status')=='NOT_EVALUATED',no_publication=not posts,
            attempted_one=record.get('invocation',{}).get('attempted_stages')==1,launched_one=type(participant_launches) is int and participant_launches==1,stage_metadata=metadata_ok)
    else:raise QualificationError('Unknown frozen negative oracle')
    return {'schema':1,'scope':'scripted negative qualification; not model task success','status':'PASS' if all(checks.values()) else 'FAIL','checks':checks}


def _launch_manifest(manifest):
    if 'browser_fixture_followup' in manifest:
        return _browser_fixture_followup_call('launch_manifest',manifest)
    if 'browser_followup' in manifest:
        return _browser_followup_call('launch_manifest',manifest)
    if 'retained_requalification' in manifest:
        return _retained_call('launch_manifest',manifest)
    limits=_effective_limits(manifest)
    fields=('id','group','release','image_id','allowed_images','role_limits','container_launches_max','participant_segments_max')
    value={'qualification_id':manifest['qualification_id'],'images':manifest['images'],
        'cells':[{key:cell[key] for key in fields} for cell in manifest['cells']],
        'limits':{'global_seconds':14400,'cleanup_reserve_seconds':30,'container_launch_attempts':limits['container_launch_attempts'],'live':4,'participant_segments':limits['participant_segments']},
        'planned_container_launches':186}
    if 'predecessor' in manifest:value['predecessor']=copy.deepcopy(manifest['predecessor'])
    if 'campaign_boundary' in manifest:value['campaign_boundary']=copy.deepcopy(manifest['campaign_boundary'])
    if 'campaign_amendment' in manifest:value['campaign_amendment']=copy.deepcopy(manifest['campaign_amendment'])
    return value


def _ledger(root,manifest,*,create=False):
    module=_launch_module();daemon,capacity=_native();kwargs={'daemon_id':daemon,'daemon_capacity':capacity}
    return module.LaunchLedger.create(Path(root)/'launch-ledger',_launch_manifest(manifest),**kwargs) if create else module.LaunchLedger(Path(root)/'launch-ledger',_launch_manifest(manifest),**kwargs)


def _cell_update(root,cell_id,**fields):
    state=read(Path(root)/'state.json');state['cells'].setdefault(cell_id,{}).update(fields);atomic(Path(root)/'state.json',state)


def _browser_admitted(value,cell):
    """The normal browser PASS alone does not establish native WebGL."""
    try:
        image=value['image'];lab.admit_image(image,cell['release'])
        observations=value['observations'];dom=[row for row in observations if 'browser_dom_ok' in row]
        sandbox=[row['browser_sandbox'] for row in observations if 'browser_sandbox' in row]
        return (value['status']=='PASS' and image['id']==cell['image_id'] and image['platform']=='linux/arm64'
            and value['host']['native_platform']==value['host']['selected_platform']=='linux/arm64'
            and value['browser_security']['policy']=='chromium-userns' and value['process']['exit_code']==0
            and type(value['process']['exit_code']) is int and value['process']['cleanup_confirmed'] is True
            and len(dom)==1 and dom[0].get('browser_dom_ok') is True and dom[0].get('webgl_ok') is True
            and dom[0].get('no_browser_sandbox') is False and dom[0].get('software_webgl') is False
            and len(sandbox)==1 and sandbox[0].get('namespace_and_seccomp_verified') is True
            and not any(row.get('no_browser_sandbox') is True or row.get('software_webgl') is True for row in observations))
    except (ValueError,TypeError,KeyError,AttributeError):return False


def admit_images(root):
    root=Path(root).absolute()
    selected,_=verify(root,require_candidate=True)
    if 'browser_fixture_followup' in selected:
        return _browser_fixture_followup_call('admit',root)
    if 'browser_followup' in selected:
        return _browser_followup_call('admit',root)
    if 'retained_requalification' in selected:
        return _retained_call('admit',root)
    with controller(root):
        manifest,state=verify(root,require_candidate=True)
        if state['phase']!='frozen' or state['cells']:raise QualificationError('Image admission cannot repeat')
        _endpoint(root/'inputs/endpoint.json',manifest['session'])
        values=_known_values(manifest);_scan_frozen(root,manifest,values)
        state.update(started_at=state['started_at'] if 'predecessor' in manifest else time.time(),phase='admitting');atomic(root/'state.json',state)
        cell=None
        try:
            ledger=_ledger(root,manifest,create=True);module=_launch_module()
            for cell in [row for row in manifest['cells'] if row['group']=='N01']:
                if _remaining(root)<=30:raise QualificationError('Global cleanup reserve reached')
                _cell_update(root,cell['id'],status='started',attempts=1)
                folder=root/'cells'/cell['id'];folder.mkdir(mode=0o700)
                args=lab.parser().parse_args(['browser-check' if cell['profile']=='browser' else 'run','--image',cell['image_id'],
                    '--platform','linux/arm64','--profile',cell['profile'],'--results-dir',str(folder),
                    '--lock-file',manifest['host_admission']['lock_file'],'--lock-wait-seconds',str(ADMISSION_WAIT_SECONDS),
                    '--cpus','2' if cell['profile']=='browser' else '1','--memory','2g' if cell['profile']=='browser' else '1g',
                    '--pids-limit','512' if cell['profile']=='browser' else '256','--jobs','1'])
                if cell['profile']=='browser':args.browser_sandbox_policy='chromium-userns'
                resources.requested_policy(args)
                with module.instrument(ledger,cell['id']) as guard,_deadline_signal(root):
                    admission=resources.admission_lock
                    if 'campaign_amendment' in manifest:
                        amendment=module.amendment_module(manifest['campaign_amendment'])
                        if getattr(amendment,'__name__','')=='application_matrix20':
                            admission=amendment.admission_factory(admission,manifest)
                    with admission(args.lock_file,args.lock_wait_seconds) as registry:
                        registry.runroot=folder;registry.command=lambda argv:lab.command(argv,timeout=15,required=False)
                        if cell['id']==manifest['cells'][0]['id']:registry.require_capacity(210)
                        if cell['profile']=='core':
                            lab.require_host(args);image=lab.probe_image(args,cell['image_id']);lab.admit_image(image,cell['release'])
                            if image['id']!=cell['image_id']:raise QualificationError()
                            atomic(folder/'runtime.json',image)
                        else:
                            if lab.browser_check(args):raise QualificationError('Browser sandbox admission failed')
                            reports=list(folder.glob('browser-*/browser-admission.json'))
                            if len(reports)!=1:raise QualificationError()
                            value=read(reports[0])
                            if not _browser_admitted(value,cell):raise QualificationError('Native DOM/WebGL/sandbox admission incomplete')
                    guard.assert_cell_released()
                _cell_update(root,cell['id'],status='PASS',evidence_level='native_infrastructure')
            state=read(root/'state.json');state['phase']='images_admitted';atomic(root/'state.json',state)
        except BaseException:
            if cell is not None and read(root/'state.json')['cells'].get(cell['id'],{}).get('status')=='started':
                _cell_update(root,cell['id'],status='BLOCKED',reason='infrastructure_qualification_failed')
            state=read(root/'state.json');state['phase']='blocked';atomic(root/'state.json',state);raise


def _real_args(root,manifest,cell):
    configured=Path(root)/'inputs'/(('browser' if cell['group']=='N04' else 'api')+'-'+cell['release'])
    args=lab.parser().parse_args(['run','--compiled-plan',str(configured/'compiled/plan.json'),'--project',str(configured/'project'),
        '--results-dir',str(Path(root)/'cells'/cell['id']/'runs'),'--session',manifest['session'],'--secrets-dir',manifest['secrets_dir'],
        '--lock-file',manifest['host_admission']['lock_file'],'--lock-wait-seconds',str(ADMISSION_WAIT_SECONDS)])
    args._explicit_options=();return args


def _cell_args(root,manifest,cell):
    if cell['group']!='N02':return _real_args(root,manifest,cell)
    experiment=Path(root)/('scripted-'+cell['release']);metadata,mapping=experiments.verify(experiment,lab)
    trial=next(row for row in mapping['cells'] if row['trial_id']==cell['trial_id'])
    args=experiments.trial_args(experiment,metadata,trial,lab,manifest['session'])
    args.lock_file=manifest['host_admission']['lock_file'];args.lock_wait_seconds=ADMISSION_WAIT_SECONDS
    return args


def _cleanup_material(runroot,values):
    if not credentials.workspace_inspected_clean(Path(runroot),credentials.Redactor(values)):raise QualificationError('Known private material retained in run evidence')
    if any((Path(runroot)/'controls').glob('*/segments/*/application-context.json')):raise QualificationError('Private application context remains')
    for path in (Path(runroot)/'stages').glob('*/application-credentials.json'):
        if read(path).get('status')!='removed':raise QualificationError('Credential cleanup remains uncertain')


def _scan_cell(folder,runroot,values):
    """Never follow the runner's parent-owned latest convenience alias."""
    redactor=credentials.Redactor(values);folder,runroot=Path(folder),Path(runroot)
    _cleanup_material(runroot,values)
    for path in folder.iterdir():
        if path==runroot.parent:
            if path.is_symlink() or {item.name for item in path.iterdir()}-{runroot.name,'latest'}:raise QualificationError('Unexpected run evidence alias')
            latest=path/'latest'
            if latest.exists() or latest.is_symlink():
                if not latest.is_symlink() or Path(os.readlink(latest))!=runroot:raise QualificationError('Unexpected latest alias')
            continue
        if path.is_symlink():raise QualificationError('Linked cell evidence')
        if path.is_dir():
            if not credentials.workspace_inspected_clean(path,redactor):raise QualificationError('Private material retained in cell evidence')
        elif redactor.contains(preparation._read(path,64*1024*1024)):raise QualificationError('Private material retained in cell evidence')


def _runtime_valid(record,stage):
    agents=record.get('agents',[])
    if (record.get('infrastructure',{}).get('status')!='ready' or record.get('invocation',{}).get('status')!='verified'
            or record.get('assistance',{}).get('status')!='autonomous' or len(agents)!=1):return False
    process=agents[0].get('process',{})
    try:
        if process.get('native_tool_manifest')!={'schema':1,'tools':stage['tools']}:return False
        budget=native_budget_controls.public_snapshot(process.get('native_tool_budget'),allowed_tools=stage['tools'])
        if budget['limits']!={key:stage['limits'][key] for key in native_budget_controls.NATIVE_FIELDS}:return False
    except (ValueError,TypeError,KeyError):return False
    return (process.get('cleanup_confirmed') is True and process.get('application_helper_cleanup',{}).get('safe_to_continue') is True
        and process.get('application_credentials',{}).get('status')=='removed' and 'native_tool_budget_error' not in process
        and process.get('native_tool_budget',{}).get('accounting')=='available'
        and type(process.get('segments')) is list and len(process['segments'])==1
        and process.get('evidence',{}).get('completion_verified') is True)


def browser_dom_audit(runroot,stage,context):
    """Bound three successful network actions to protected native DOM captures."""
    projection={'schema':1,'status':'FAIL','actions_verified':0,'dom_captures_verified':0,'capture_sha256':[],
            'diagnostics':['browser_audit_invalid']};directory=private_parent=None
    try:
        runroot=Path(runroot).absolute();evidence=Path(context['evidence_root'])
        if (not evidence.is_absolute() or str(evidence)!=context['evidence_root'] or evidence.name!='raw' or evidence.parent.name!='private'
                or evidence.parent.parent.parent!=runroot/'application-evidence'
                or not re.fullmatch('pi-application-[a-f0-9]{16}',evidence.parent.parent.name)):raise QualificationError()
        index=context['parent_receipts'];binding=context['binding']
        if type(index) is not dict or not 1<=len(index)<=500:raise QualificationError()
        private_parent=open_directory(str(evidence.parent),private=True)
        directory=open_directory(str(evidence),private=True);receipts=[];paths=set();total=0
        for identifier,reference in index.items():
            c.slug(identifier,'');c.exact(reference,{'path','sha256'},'');c.relative(reference['path'],'');c.sha256(reference['sha256'],'')
            if not reference['path'].startswith('receipts/') or reference['path'] in paths:raise QualificationError()
            paths.add(reference['path']);body=read_file(directory,reference['path'],65536);total+=len(body)
            if total>33554432 or hashlib.sha256(body).hexdigest()!=reference['sha256']:raise QualificationError()
            receipt=c.validate_receipt(c.loads(body))
            if receipt['receipt_id']!=identifier or receipt['binding']!=binding or receipt['participant']!=stage['participant']:raise QualificationError()
            if receipt['outcome']=='succeeded' and receipt['operation_id'] in ('list-records','publish-summary'):receipts.append(receipt)
        if sorted(row['operation_id'] for row in receipts)!=['list-records','list-records','publish-summary']:raise QualificationError()
        seen=set();hashes=[];targets={row['id']:row for row in stage['_resolved_browser_targets']}
        for receipt in receipts:
            action_id=receipt['action_id'];c.slug(action_id,'')
            if receipt['transport']!='browser' or action_id in seen:raise QualificationError()
            seen.add(action_id);audit=c.loads(read_file(directory,'browser-actions/'+action_id+'/receipt.json',65536))
            c.exact(audit,{'schema','document_type','action_id','native_call_id','binding','participant','target_id','page_identity','action',
                'operation_receipt_ids','resource_receipt_ids','captures','ok','outcome','reason','denied_requests','elapsed_seconds','classification','diagnostic'},'')
            if (type(audit['schema']) is not int or audit['schema']!=1 or audit['document_type']!='application_browser_action_receipt'
                    or audit['classification']!='native_chromium_cdp' or audit['ok'] is not True or audit['outcome']!='succeeded'
                    or audit['reason'] is not None or type(audit['denied_requests']) is not int or audit['denied_requests']!=0
                    or audit['binding']!=binding or audit['participant']!=stage['participant'] or audit['action_id']!=action_id
                    or audit['native_call_id']!=receipt['native_call_id'] or audit['operation_receipt_ids']!=[receipt['receipt_id']]
                    or audit['action']!='click' or audit['diagnostic'] is not None):raise QualificationError()
            c.slug(audit['target_id'],'');c.slug(audit['page_identity'],'');c.array(audit['resource_receipt_ids'],'',16)
            for resource in audit['resource_receipt_ids']:c.slug(resource,'')
            if (audit['target_id'] not in targets or receipt['operation_id'] not in targets[audit['target_id']]['allowed_operation_ids']
                    or audit['page_identity']!=targets[audit['target_id']]['page_identity']):raise QualificationError()
            captures=c.array(audit['captures'],'',2,2)
            if {row.get('kind') for row in captures}!={'dom_before','dom_after'}:raise QualificationError()
            for capture in captures:
                c.exact(capture,{'kind','path','media_type','bytes','sha256'},'');c.sha256(capture['sha256'],'');c.integer(capture['bytes'],'',0,262144)
                if capture['media_type']!='application/json' or capture['path']!='browser-actions/'+action_id+'/'+capture['kind']+'.txt':raise QualificationError()
                body=read_file(directory,capture['path'],262144)
                if len(body)!=capture['bytes'] or hashlib.sha256(body).hexdigest()!=capture['sha256']:raise QualificationError()
                dom=c.loads(body);c.exact(dom,{'url','page_identity','html','form_state','text_content','inner_text'},'')
                for key in ('url','html','text_content','inner_text'):c.text(dom[key],'',262144,empty=True)
                if dom['page_identity']!=[audit['page_identity']] or dom['url']!=targets[audit['target_id']]['url']:raise QualificationError()
                for field in c.array(dom['form_state'],'',500):
                    c.exact(field,{'tag','test_id','type','value','checked'},'')
                    for key in ('tag','type','value'):c.text(field[key],'',262144,empty=True)
                    if field['test_id'] is not None:c.text(field['test_id'],'',128,empty=True)
                    if type(field['checked']) is not bool:raise QualificationError()
                hashes.append(capture['sha256'])
        return {'schema':1,'status':'PASS','actions_verified':3,'dom_captures_verified':6,'capture_sha256':sorted(hashes),'diagnostics':[]}
    except (OSError,ValueError,KeyError,TypeError,AttributeError):return projection
    finally:
        if directory is not None:os.close(directory)
        if private_parent is not None:os.close(private_parent)


def _evaluate(root,manifest,cell,runroot,*,interruption_sent=False):
    folder=Path(root)/'cells'/cell['id'];journal=folder/'fixture-journal/private';record=read(Path(runroot)/'result.json')
    services=read(folder/'services-cleanup.json')
    if services.get('safe_to_continue') is not True:raise QualificationError('Fixture physical/private cleanup unavailable')
    fixture=_module('qualification_fixture_sealer',EXAMPLE/'fixture.py');oracle_module=_module('qualification_external_oracle',EXAMPLE/'oracle.py')
    if cell.get('scenario')=='sensitive-participant-interruption':
        oracle=oracle_module.evaluate(Path(runroot),journal,None)
    else:
        sealed=fixture.seal_parent_receipt(runroot,journal,sha(journal/'terminal-receipt.json'))
        parent=read(sealed['path']);oracle=oracle_module.evaluate(Path(runroot),journal,parent)
    atomic(folder/'oracle.json',oracle)
    if cell['group']=='N02':
        launched=None;metadata=None
        if cell['scenario']=='sensitive-participant-interruption':
            ledger=_launch_module().LaunchLedger(Path(root)/'launch-ledger',_launch_manifest(manifest))
            launched=sum(row['cell']==cell['id'] and row['role']=='participant' for row in ledger.snapshot()['launches'])
            metadata=[read(path) for path in (Path(runroot)/'stages').glob('*/descriptor.json') if read(path).get('kind')=='agent']
        verdict=negative_verdict(cell['scenario'],record,read(journal/'journal.json'),oracle,interruption_sent=interruption_sent,
            participant_launches=launched,stage_metadata=metadata)
        observations=read(folder/'scripted-observations/private/scripted.json')
        script_ok=(observations.get('case_id')==cell['case'] and observations.get('model')=='application-script-'+cell['variant']
            and observations.get('stopped') is True and observations.get('unexpected_results')==0
            and observations.get('tool_results')==SCRIPT_RESULTS[cell['scenario']]
            and observations.get('emitted_tool_calls')==SCRIPT_RESULTS[cell['scenario']]
            and observations.get('usage_accounting')=='synthetic_fixed_16_16')
        verdict['checks']['scripted_result_sequence']=script_ok
        verdict['status']='PASS' if all(verdict['checks'].values()) else 'FAIL'
    else:
        dom=None
        if cell['group']=='N04':
            plan=preparation.load_compiled(_cell_args(root,manifest,cell).compiled_plan)['plan'];stage=copy.deepcopy(plan['stages'][0])
            stage['_resolved_browser_targets']=[target for target in plan['application']['browser_targets'] if target['id'] in stage['browser_targets']]
            dom=browser_dom_audit(runroot,stage,record['agents'][0]['process']['application_completion_context'])
            atomic(folder/'browser-dom-audit.json',dom)
        verdict={'schema':1,'status':'PASS' if oracle['status']=='PASS' and record['status']=='PASS' and (dom is None or dom['status']=='PASS') else 'FAIL',
            'scope':'native_real_model','runner_status':record['status'],'oracle_status':oracle['status']}
    atomic(folder/'qualification.json',{'cell_id':cell['id'],'run_id':record['run_id'],'attempt_id':record['attempt_id'],
        'result_sha256':sha(Path(runroot)/'result.json'),'real_model':cell['real_model'],**verdict})
    return verdict


def _handoff_marker_value(manifest,cell,initial,desc,binding,owner_pid):
    """Closed public metadata; no argv, environment, output or credential data."""
    if (cell.get('group')!='N02' or cell.get('scenario')!='sensitive-participant-interruption'
            or cell.get('real_model') is not False or desc.get('kind')!='agent'
            or desc.get('label')!='agent-1-participant'
            or any(desc.get(k)!=initial[k] or binding.get(k)!=initial[k] for k in ('run_id','attempt_id'))
            or binding.get('stage_id')!=desc.get('stage_id')
            or type(owner_pid)is not int or owner_pid<=1):
        raise QualificationError('Participant handoff metadata unavailable')
    value={'schema':1,'document_type':'qualification_participant_handle_handoff',
        'qualification_id':manifest['qualification_id'],'cell_id':cell['id'],
        'run_id':initial['run_id'],'attempt_id':initial['attempt_id'],'stage_id':desc['stage_id'],
        'segment_id':binding.get('segment_id'),'owner_pid':owner_pid,'state':'caller_owns_process_handle'}
    if any(not controls.valid_id(value[k])for k in ('qualification_id','run_id','attempt_id','stage_id','segment_id')):
        raise QualificationError('Participant handoff metadata unavailable')
    return value


def _handoff_read(path):
    """One <=4KiB regular owned0600/nlink1 marker, stable FD and named inode."""
    path=Path(path);parent=preparation._directory(path.parent)
    try:
        try:fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        except FileNotFoundError:return None
        with os.fdopen(fd,'rb')as stream:
            before=os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_nlink!=1
                    or stat.S_IMODE(before.st_mode)!=0o600 or before.st_size>4096):
                raise QualificationError('Participant handoff metadata unavailable')
            body=stream.read(4097);after=os.fstat(stream.fileno());named=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
            identity=lambda v:(v.st_dev,v.st_ino,v.st_size,v.st_mode,v.st_nlink,v.st_mtime_ns,v.st_ctime_ns)
            if len(body)!=before.st_size or identity(before)!=identity(after) or identity(before)!=identity(named):
                raise QualificationError('Participant handoff metadata unavailable')
        return c.loads(body,max_bytes=4096)
    finally:os.close(parent)


@contextlib.contextmanager
def _participant_handle_handoff(root,manifest,cell,initial):
    """Qualification-child-only hook; installed runtime bytes remain unchanged."""
    if cell.get('scenario')!='sensitive-participant-interruption':
        yield;return
    if cell.get('group')!='N02' or cell.get('real_model')is not False:
        raise QualificationError('Participant handoff scope unavailable')
    import application_execution
    coordinator_type=application_execution.ApplicationCoordinator
    original=coordinator_type.mark_running;published=[False]
    marker=Path(root)/'cells'/cell['id']/'participant-handoff.json'
    def mark_running(coordinator):
        result=original(coordinator)
        if type(coordinator)is not coordinator_type or published[0]:
            raise QualificationError('Participant handoff scope unavailable')
        value=_handoff_marker_value(manifest,cell,initial,coordinator.desc,coordinator.binding,os.getpid())
        try:marker.lstat()
        except FileNotFoundError:pass
        else:raise QualificationError('Participant handoff marker already exists')
        # Single source-owned stage/segment; refuse existing stale markers. The
        # existing atomic helper publishes only complete JSON with mode0600.
        atomic(marker,value)
        folder=preparation._directory(marker.parent)
        try:os.fsync(folder)
        finally:os.close(folder)
        published[0]=True
        return result
    try:
        coordinator_type.mark_running=mark_running
        yield
    finally:coordinator_type.mark_running=original


def _participant_handle_ready(root,manifest,cell,initial,owner_pid):
    marker=Path(root)/'cells'/cell['id']/'participant-handoff.json';value=_handoff_read(marker)
    if value is None:return False
    fields={'schema','document_type','qualification_id','cell_id','run_id','attempt_id','stage_id','segment_id','owner_pid','state'}
    c.exact(value,fields,'/participant-handoff')
    if (type(value['schema'])is not int or value['schema']!=1
            or value['document_type']!='qualification_participant_handle_handoff'
            or value['state']!='caller_owns_process_handle'
            or type(value['owner_pid'])is not int or value['owner_pid']!=owner_pid
            or value['qualification_id']!=manifest['qualification_id'] or value['cell_id']!=cell['id']
            or any(value[k]!=initial[k]for k in ('run_id','attempt_id'))
            or any(not controls.valid_id(value[k])for k in ('qualification_id','run_id','attempt_id','stage_id','segment_id'))):
        raise QualificationError('Participant handoff metadata unavailable')
    runroot=Path(_cell_args(root,manifest,cell).results_dir)/initial['run_id']
    active=read(runroot/'active_stage.json',4096)
    desc=read(runroot/'stages'/value['stage_id']/'descriptor.json',16384)
    state=read(runroot/'stages'/value['stage_id']/'state.json',16384)
    if (active!={'schema':2,'stage_id':value['stage_id'],'label':'agent-1-participant'}
            or desc.get('schema')!=2 or desc.get('kind')!='agent' or desc.get('label')!='agent-1-participant'
            or desc.get('stage_id')!=value['stage_id'] or any(desc.get(k)!=initial[k]for k in ('run_id','attempt_id'))
            or desc.get('workspace')!=str(runroot/'workspace') or desc.get('control')!=str(runroot/'controls'/value['stage_id'])
            or state.get('status')!='running' or state.get('segment_id')!=value['segment_id']):
        raise QualificationError('Participant handoff metadata unavailable')
    # Refuse replacement while parent bound the exact live stage/segment.
    if _handoff_read(marker)!=value:raise QualificationError('Participant handoff metadata changed')
    return True


def _child(root,cell_id,envelope_path):
    """Internal entry: only the parent-reserved current PID can spend this cell."""
    root=Path(root).absolute();manifest,state=verify(root,require_candidate=True);cell=next(row for row in manifest['cells'] if row['id']==cell_id)
    if 'browser_fixture_followup' in manifest:_browser_fixture_followup_call('require_dispatch',root,manifest)
    if 'browser_followup' in manifest:_browser_followup_call('require_dispatch',root,manifest)
    envelope_path=Path(envelope_path).absolute();info=envelope_path.lstat()
    if info.st_uid!=os.getuid() or info.st_nlink!=1 or info.st_mode&0o077:raise QualificationError('Private child envelope unavailable')
    envelope=read(envelope_path,2*1024*1024);c.exact(envelope,{'initial_record','redaction_values'},'/child')
    deadline=time.monotonic()+5
    while True:
        state=read(root/'state.json');active=state.get('active_cell')
        if type(active) is dict and active.get('id')==cell_id and active.get('pid')==os.getpid():break
        if time.monotonic()>=deadline:raise QualificationError('Child not owned by current qualification controller')
        time.sleep(.02)
    initial=envelope['initial_record']
    if initial['run_id']!=active['run_id'] or initial['attempt_id']!=active['attempt_id']:raise QualificationError()
    if state['cells'].get(cell_id,{}).get('status')!='started' or state['cells'][cell_id].get('attempts')!=1:raise QualificationError()
    args=_cell_args(root,manifest,cell);args._application_parent_values=envelope['redaction_values']
    args._indexed_redaction_keys=[]
    if cell['group']=='N02':
        intents=experiments.attempt_intents(root/('scripted-'+cell['release']),next(row for row in experiments.verify(root/('scripted-'+cell['release']),lab)[1]['cells'] if row['trial_id']==cell['trial_id']))
        if len(intents)!=1 or intents[0]['initial_record']!=initial:raise QualificationError('Prepared primary identity changed')
    _endpoint(root/'inputs/endpoint.json',manifest['session']);module=_launch_module();ledger=_ledger(root,manifest)
    original=lab.admission_lock;services=[]
    if 'campaign_amendment' in manifest:
        amendment=module.amendment_module(manifest['campaign_amendment'])
        if getattr(amendment,'__name__','')=='application_matrix20':
            original=amendment.admission_factory(original,manifest)
    with module.instrument(ledger,cell_id) as guard,_deadline_signal(root):
        def lease(path,wait):
            if path!=args.lock_file or wait!=args.lock_wait_seconds:raise QualificationError('Unexpected lease selector')
            def factory(registry):
                registry.command=lambda argv:lab.command(argv,timeout=15,required=False);daemon,capacity=_native();registry.bind_daemon(daemon)
                _aggregate(capacity,cell['profile']=='browser',cell['group']=='N02')
                value=OwnedServices(root,manifest,cell,args,registry,guard,envelope['redaction_values']);services.append(value);return value
            cancellation=(_ControlledCancellation(root,manifest,cell,initial,envelope['redaction_values'])
                if cell.get('scenario')=='sensitive-participant-interruption' else None)
            return actual_lease(args,factory,original=original,_cancellation=cancellation)
        lab.admission_lock=lease
        try:
            with _participant_handle_handoff(root,manifest,cell,initial):
                code=lab.run_suite(args,initial_record=copy.deepcopy(initial))
        finally:
            lab.admission_lock=original
            guard.flush_timings(root/'cells'/cell_id)
        guard.assert_cell_released()
    runroot=Path(args.results_dir)/initial['run_id'];_cleanup_material(runroot,envelope['redaction_values'])
    atomic(root/'cells'/cell_id/'child-completion.json',{'schema':1,'run_id':initial['run_id'],'attempt_id':initial['attempt_id'],
        'result_sha256':sha(runroot/'result.json'),'cleanup_checked':True})
    return code


def _invoke_cell(root,manifest,cell,initial,values):
    root=Path(root);state=read(root/'state.json')
    if cell['id'] in state['cells'] or state['active_cell'] is not None or _remaining(root)<=30:raise QualificationError('Cell cannot repeat or overlap')
    folder=root/'cells'/cell['id'];folder.mkdir(parents=True,mode=0o700,exist_ok=True)
    private=Path(tempfile.mkdtemp(prefix='pi-qualification-cell-')).resolve();private_identity=_private_identity(private);envelope=private/'initial.json'
    atomic(envelope,{'initial_record':initial,'redaction_values':values});envelope.chmod(0o400)
    argv=[sys.executable,str(Path(__file__).resolve()),'_cell-run','--root',str(root),'--cell-id',cell['id'],'--private-envelope',str(envelope)]
    state['cells'][cell['id']]={'status':'started','attempts':1,'run_id':initial['run_id'],'attempt_id':initial['attempt_id']}
    state['active_cell']={'id':cell['id'],'pid':None,'run_id':initial['run_id'],'attempt_id':initial['attempt_id']};atomic(root/'state.json',state)
    atomic(folder/'invocation.json',{'argv':argv,'cwd':str(REPO),'classification':'native_real_model' if cell['real_model'] else 'native_scripted_protocol'})
    interruption_sent=False;process=None
    try:
        with (folder/'stdout.log').open('w') as out,(folder/'stderr.log').open('w') as err:
            process=subprocess.Popen(argv,cwd=REPO,stdout=out,stderr=err,start_new_session=True,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
            state=read(root/'state.json');state['active_cell']['pid']=process.pid;atomic(root/'state.json',state)
            while process.poll() is None:
                if cell.get('scenario')=='sensitive-participant-interruption' and not interruption_sent:
                    path=folder/'scripted-observations/private/scripted.json'
                    if path.exists():
                        observed=read(path)
                        if (observed.get('held') is True and observed.get('identity_succeeded') is True
                                and observed.get('phase')=='holding_after_identity'
                                and _participant_handle_ready(root,manifest,cell,initial,process.pid)):
                            process.send_signal(signal.SIGINT);interruption_sent=True
                if _remaining(root)<=30:
                    process.send_signal(signal.SIGINT)
                    try:process.wait(timeout=max(.1,_remaining(root)))
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=1)
                    raise QualificationError('Global deadline reached; no later cell admitted')
                time.sleep(.05)
        args=_cell_args(root,manifest,cell);runroot=Path(args.results_dir)/initial['run_id']
        if not (runroot/'result.json').exists():raise QualificationError('Child produced no sealed result')
        result=read(runroot/'result.json')
        if any(result.get(key)!=initial.get(key) for key in ('run_id','attempt_id','trial_id')) or result.get('sealed') is not True:raise QualificationError()
        completed=read(folder/'child-completion.json')
        if completed!={'schema':1,'run_id':initial['run_id'],'attempt_id':initial['attempt_id'],'result_sha256':sha(runroot/'result.json'),'cleanup_checked':True}:
            raise QualificationError('Owning child cleanup receipt unavailable')
        if type(result.get('exit_code')) is not int or process.returncode!=result['exit_code']:raise QualificationError('Child ended outside its sealed outcome')
        _scan_cell(folder,runroot,values)
        stage=preparation.load_compiled(args.compiled_plan,verify_runner=True)['plan']['stages'][0]
        if cell.get('scenario')!='sensitive-participant-interruption' and not _runtime_valid(result,stage):raise QualificationError('Runtime invocation/accounting qualification failed')
        verdict=_evaluate(root,manifest,cell,runroot,interruption_sent=interruption_sent)
        _cell_update(root,cell['id'],status=verdict['status'],runner_status=result['status'],exit_code=process.returncode,interruption_sent=interruption_sent)
        state=read(root/'state.json');state['active_cell']=None;atomic(root/'state.json',state)
        _purge_private(private,private_identity)
        if cell['group']=='N02' and verdict['status']!='PASS':raise QualificationError('Frozen scripted oracle failed; later cells are blocked')
        return result
    except BaseException:
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:process.wait(timeout=max(.1,min(30,_remaining(root))))
            except subprocess.TimeoutExpired:
                process.kill();process.wait(timeout=1)
        # Do not delete private bootstrap or release admission on unknown writers.
        current=read(root/'state.json')['cells'][cell['id']]
        if current.get('status') not in ('PASS','FAIL'):_cell_update(root,cell['id'],status='BLOCKED',private_cleanup='unconfirmed')
        raise


def collect(root,*,group,release):
    root=Path(root).absolute()
    selected,_=verify(root,require_candidate=True)
    if 'browser_fixture_followup' in selected:
        return _browser_fixture_followup_call('collect',root,group=group,release=release)
    if 'browser_followup' in selected:
        return _browser_followup_call('collect',root,group=group,release=release)
    if 'retained_requalification' in selected:
        return _retained_call('collect',root,group=group,release=release)
    if group not in ('N02','N03','N04') or release not in RELEASES:raise QualificationError()
    with controller(root),_deadline_signal(root,reserve=False):
        manifest,state=verify(root,require_candidate=True)
        if state['phase'] not in ('images_admitted','collecting') or state['active_cell'] is not None:raise QualificationError('Image admission or cleanup unavailable')
        _endpoint(root/'inputs/endpoint.json',manifest['session']);values=_known_values(manifest);_scan_frozen(root,manifest,values)
        if not all(state['cells'].get(row['id'],{}).get('status')=='PASS' for row in manifest['cells'] if row['group']=='N01'):raise QualificationError()
        selected=[row for row in manifest['cells'] if row['group']==group and row['release']==release]
        prerequisites=('N02',) if group in ('N03','N04') else ()
        if any(state['cells'].get(row['id'],{}).get('status')!='PASS' for row in manifest['cells'] if row['group'] in prerequisites):
            raise QualificationError('Earlier native qualification gate is incomplete')
        if any(row['id'] in state['cells'] for row in selected):raise QualificationError('Group already attempted; automatic retry is forbidden')
        state['phase']='collecting';atomic(root/'state.json',state)
        try:
            if group=='N02':
                path=root/('scripted-'+release);metadata,mapping=experiments.verify(path,lab)
                private=application_experiments.admit_work(path,metadata,mapping['cells'],lab,manifest['session'])
                values=list(dict.fromkeys([*values,*private['redaction_values']]))
                def runner(args,initial_record=None):
                    cell=next(row for row in selected if row['trial_id']==initial_record['trial_id'])
                    result=_invoke_cell(root,manifest,cell,initial_record,values);return result['exit_code']
                result=experiments.execute(path,lab,session=manifest['session'],runner=runner)
                if result['completed_this_call']!=6:raise QualificationError('Planned scripted cells were not all retained')
            else:
                for cell in selected:_invoke_cell(root,manifest,cell,outcomes.initial(),values)
        except BaseException:
            state=read(root/'state.json');state['phase']='blocked';atomic(root/'state.json',state);raise
    return report(root)


def report(root):
    manifest,state=verify(root,require_candidate=False)
    if 'browser_fixture_followup' in manifest:
        return _browser_fixture_followup_call('report',root)
    if 'browser_followup' in manifest:
        return _browser_followup_call('report',root)
    if 'retained_requalification' in manifest:
        return _retained_call('report',root)
    rows=[]
    for cell in manifest['cells']:
        observed=state['cells'].get(cell['id'],{})
        if (type(observed) is not dict or observed.get('status','NOT_RUN') not in ('started','PASS','FAIL','BLOCKED','NOT_RUN')
                or observed.get('runner_status') not in (None,'PASS','FAIL','BLOCKED','INTERRUPTED','ASSISTED','RECOVERED')
                or type(observed.get('attempts',0)) is not int or observed.get('attempts',0) not in (0,1)):raise QualificationError('Invalid qualification report state')
        rows.append({'id':cell['id'],'group':cell['group'],'release':cell['release'],'real_model':cell['real_model'],
            'status':observed.get('status','BLOCKED' if state['phase']=='blocked' else 'NOT_RUN'),'attempts':observed.get('attempts',0),
            'runner_status':observed.get('runner_status'),'scope':'real_model' if cell['real_model'] else 'native_scripted_negative' if cell['group']=='N02' else 'infrastructure'})
    value={'schema':1,'qualification_id':manifest['qualification_id'],'status':'PASS' if all(row['status']=='PASS' for row in rows) else 'NOT_READY',
        'planned_participant_segments':24,'scripted_cells':12,'real_model_cells':12,'cells':rows,'limits':manifest['limits'],
        'sensitive_negative_scope':SENSITIVE_SCOPE}
    if 'campaign_amendment' in manifest:
        amendment=_launch_module().amendment_module(manifest['campaign_amendment'])
        if getattr(amendment,'__name__','')=='application_matrix20':
            value.update(amendment.historical_report(manifest['campaign_amendment'],manifest['predecessor']))
            return value
    if 'predecessor' in manifest:
        carried=_launch_module().validate_predecessor(manifest['predecessor'],_launch_window=False)
        value['predecessor']={key:carried[key] for key in ('qualification_id','attempts','participant_segments','deadline_wall','planned_cells','prior_rows')}
        if 'campaign_boundary' in manifest:
            effective=_launch_module()._effective_carry(manifest,_launch_window=False)
            if 'campaign_amendment' in manifest:
                import application_campaign
                effective=application_campaign.validate_boundary(manifest['campaign_boundary'],manifest['predecessor'],window=False)
            value['campaign_boundary']={'reference':copy.deepcopy(manifest['campaign_boundary']),
                **{key:effective[key] for key in ('base_attempts','auxiliary_attempts','attempts','participant_segments','started_wall','deadline_wall','original_window')}}
        if 'campaign_amendment' in manifest:
            effective=_launch_module()._effective_carry(manifest,_launch_window=False)
            value['campaign_amendment']={'reference':copy.deepcopy(manifest['campaign_amendment']),
                **{key:copy.deepcopy(effective[key]) for key in ('attempts','participant_segments','planned_cells','prior_rows','lineage','started_wall','deadline_wall','original_window')},
                'container_launch_attempts':manifest['limits']['container_launch_attempts']}
    return value


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    freeze_cmd=sub.add_parser('freeze');freeze_cmd.add_argument('--root',required=True);freeze_cmd.add_argument('--session',required=True)
    freeze_cmd.add_argument('--endpoint',required=True);freeze_cmd.add_argument('--image-receipts',required=True);freeze_cmd.add_argument('--fixture-route',required=True)
    freeze_cmd.add_argument('--credential-references',required=True);freeze_cmd.add_argument('--secrets-dir',required=True)
    freeze_cmd.add_argument('--predecessor')
    freeze_cmd.add_argument('--campaign-boundary')
    freeze_cmd.add_argument('--campaign-amendment')
    retained_cmd=sub.add_parser('prepare-requalification')
    for name in ('root','session','endpoint','image-receipts','fixture-route','credential-references','secrets-dir','retained-index','compatibility'):
        retained_cmd.add_argument('--'+name,required=True)
    browser_cmd=sub.add_parser('prepare-browser-followup')
    for name in ('root','session','endpoint','image-receipts','fixture-route','credential-references','secrets-dir','evidence-index','compatibility'):
        browser_cmd.add_argument('--'+name,required=True)
    fixture_browser_cmd=sub.add_parser('prepare-browser-fixture-followup')
    for name in ('root','session','endpoint','image-receipts','fixture-route','credential-references','secrets-dir','evidence-index','compatibility'):
        fixture_browser_cmd.add_argument('--'+name,required=True)
    for name in ('verify','admit','report'):
        command=sub.add_parser(name);command.add_argument('--root',required=True)
    bound=sub.add_parser('bind-candidate');bound.add_argument('--root',required=True);bound.add_argument('--identity',required=True)
    command=sub.add_parser('collect');command.add_argument('--root',required=True);command.add_argument('--group',choices=['N02','N03','N04'],required=True);command.add_argument('--release',choices=RELEASES,required=True)
    child=sub.add_parser('_cell-run');child.add_argument('--root',required=True);child.add_argument('--cell-id',required=True);child.add_argument('--private-envelope',required=True)
    args=parser.parse_args(argv)
    try:
        if args.command=='prepare-browser-fixture-followup':
            result={'root':str(prepare_browser_fixture_followup(args.root,evidence_index=args.evidence_index,compatibility=args.compatibility,
                session=args.session,approved_endpoint_path=args.endpoint,image_receipts=read(args.image_receipts),
                fixture_route=read(args.fixture_route),credential_references=read(args.credential_references),secrets_dir=args.secrets_dir))}
        elif args.command=='prepare-browser-followup':
            result={'root':str(prepare_browser_followup(args.root,evidence_index=args.evidence_index,compatibility=args.compatibility,
                session=args.session,approved_endpoint_path=args.endpoint,image_receipts=read(args.image_receipts),
                fixture_route=read(args.fixture_route),credential_references=read(args.credential_references),secrets_dir=args.secrets_dir))}
        elif args.command=='prepare-requalification':
            result={'root':str(prepare_requalification(args.root,retained_index=args.retained_index,compatibility=args.compatibility,
                session=args.session,approved_endpoint_path=args.endpoint,image_receipts=read(args.image_receipts),
                fixture_route=read(args.fixture_route),credential_references=read(args.credential_references),secrets_dir=args.secrets_dir))}
        elif args.command=='freeze':result={'root':str(freeze(args.root,session=args.session,approved_endpoint_path=args.endpoint,image_receipts=read(args.image_receipts),fixture_route=read(args.fixture_route),credential_references=read(args.credential_references),secrets_dir=args.secrets_dir,predecessor=read(args.predecessor) if args.predecessor else None,campaign_boundary=read(args.campaign_boundary) if args.campaign_boundary else None,**({'campaign_amendment':read(args.campaign_amendment)} if args.campaign_amendment else {})))}
        elif args.command=='bind-candidate':bind_candidate(args.root,read(args.identity));result={'candidate_bound':True}
        elif args.command=='verify':verify(args.root,require_candidate=True);result={'status':'verified_no_execution'}
        elif args.command=='admit':admit_images(args.root);result=report(args.root)
        elif args.command=='collect':result=collect(args.root,group=args.group,release=args.release)
        elif args.command=='report':result=report(args.root)
        else:return _child(args.root,args.cell_id,args.private_envelope)
        print(json.dumps(result,indent=2));return 0
    except (OSError,ValueError,KeyError,TypeError,StopIteration) as exc:
        failure={'status':'BLOCKED','reason':'qualification_inputs_or_ownership_unavailable'}
        # Only the closed parent catalog is diagnostic authority. Exception
        # text may contain credentials or arbitrary child output.
        if type(exc) is resources.AdmissionError:
            failure['admission']=resources.admission_diagnostic(exc)
        print(json.dumps(failure),file=sys.stderr);return 2


if __name__=='__main__':raise SystemExit(main())
