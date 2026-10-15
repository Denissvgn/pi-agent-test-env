#!/usr/bin/env python3
"""Freeze bounded parallel ARM64 qualification; never retry a failed collection.

Maintainer only: infrastructure precedes real-model lanes. Secrets and raw
observations remain outside published source, in owner-only disposable stores.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[1]
SKILL=REPO/'skill'
sys.path[:0]=[str(SKILL/'scripts'),str(SKILL/'runtime'),str(HERE)]
import agent_profiles
import application_credentials
import experiments
import fixtures
import ownership_registry
import parallel_contract
from parallel_allocator import Allocator
from parallel_dispatch import Peer
import pi_lab as lab
import pi_release
import provenance
import release_contracts
import resources
import secret_store
import stage_control as controls

WORKER={'schema':1,'runtime':{'cpus':1,'memory':'1536m','pids_limit':512,'jobs':1},
        'host_budget':{'cpu_fraction':.5,'memory_fraction':.5}}
CONCURRENCY={'scheduler':'parallel-trials-v1','host_generation':1,'registry_aware_cohort':True,
    'max_trials':2,'max_stages':2,'max_pending':16,'queue_wait_seconds':3600,'collection_timeout_seconds':14400,
    'aggregate':{'cpu_millis':2500,'memory_mib':3328,'pids_limit':1152},
    'gateway':{'resources':{'cpu_millis':250,'memory_mib':128,'pids_limit':64},
               'max_inflight':1,'max_pending':4,'queue_wait_seconds':180,'request_timeout_seconds':180}}
POSITIVE=('coding','lookup','credentials','browser')
FAULTS=('abort','timeout','recovery','crash','discovery','boundary','contamination','provider-fatal')


def matrix():
    rows=[]
    for release in release_contracts.RELEASES:
        for kind in POSITIVE:
            cells=12 if kind=='credentials' else 6
            stages=3 if kind=='credentials' else 2 if kind=='coding' else 1
            rows.append({'id':'positive-'+release+'-'+kind,'release':release,'kind':kind,
                         'real_model':True,'repetitions':3,'cells':cells,'segments_ceiling':cells*stages})
        for kind in FAULTS:
            rows.append({'id':'fault-'+release+'-'+kind,'release':release,'kind':kind,
                         'real_model':False,'repetitions':1,'cells':4,'segments_ceiling':8 if kind=='recovery' else 4})
    return rows


def command(argv,timeout=30,required=True):return pi_release.command(argv,timeout,required)


def token_budget(value):
    if type(value) is not int or value not in (64000,128000):
        raise ValueError('Select a reviewed qualification token ceiling: 64000 or 128000')
    return value


def freeze(root,images_file,endpoint_file,session=None,coding_max_total_tokens=64000,other_positive_max_total_tokens=64000):
    coding_max_total_tokens=token_budget(coding_max_total_tokens)
    other_positive_max_total_tokens=token_budget(other_positive_max_total_tokens)
    root=Path(root).resolve()
    if root.exists():raise ValueError('Fresh qualification directory required')
    selected=json.loads(Path(images_file).read_text());images={}
    for release in release_contracts.RELEASES:
        for profile in ('core','browser'):
            name=profile+'-'+release;image=selected[name]['id']
            images[name]={'id':pi_release.native(image),'platform':'linux/arm64'}
    host=pi_release.native();endpoint=lab.load_endpoint(Path(endpoint_file))
    parallel_contract.admit_capacity(CONCURRENCY,resources.validate_policy(WORKER),host)
    root.mkdir(mode=0o700,parents=True)
    controls.atomic(root/'endpoint.json',endpoint)
    controls.atomic(root/'worker.json',WORKER)
    rows=matrix();manifest={'schema':1,'qualification_id':str(uuid.uuid4()),'source':pi_release.source_identity(),
       'images':images,'endpoint_sha256':provenance.digest({k:v for k,v in endpoint.items() if k!='api_key_env'}),
       'model_deployment_limits':'unknown; existing deployment retained','host':host,'session':session,
       'worker_resources':WORKER,'concurrency':CONCURRENCY,
       'inference_preflight':parallel_contract.preflight_limits(CONCURRENCY),
       'coding_max_total_tokens':coding_max_total_tokens,
       'other_positive_max_total_tokens':other_positive_max_total_tokens,
       'authority_resources':{'cpu_millis':250,'memory_mib':128,'pids_limit':64},
       'batches':rows,'planned_cells':sum(r['cells'] for r in rows),'segments_ceiling':sum(r['segments_ceiling'] for r in rows),
       'docker_launches_ceiling':900,'infrastructure_seconds_ceiling':1200,'collection_seconds_ceiling':14400,
       'cleanup_seconds_ceiling':240,'automatic_retries':0,
       'scope':'Disposable actor and scripted fault fixtures; real model lanes separate; no WorkChord acceptance'}
    controls.atomic(root/'manifest.json',manifest,0o444)
    controls.atomic(root/'integrity.json',{'manifest_sha256':hashlib.sha256((root/'manifest.json').read_bytes()).hexdigest(),
        'worker_sha256':hashlib.sha256((root/'worker.json').read_bytes()).hexdigest()})
    controls.atomic(root/'state.json',{'phase':'frozen','batches':[],'attempted_batches':[],'native_pi_segments':0})
    return {'qualification':str(root),'planned_cells':manifest['planned_cells'],'segments_ceiling':manifest['segments_ceiling'],
            'coding_max_total_tokens':coding_max_total_tokens,'other_positive_max_total_tokens':other_positive_max_total_tokens}


def verify(root):
    root=Path(root).resolve();manifest=experiments.read_json(root/'manifest.json')
    if hashlib.sha256((root/'manifest.json').read_bytes()).hexdigest()!=experiments.read_json(root/'integrity.json')['manifest_sha256']:
        raise ValueError('Qualification manifest changed')
    if manifest['source']!=pi_release.source_identity():raise ValueError('Qualification source/fixtures changed; fresh intent required')
    if hashlib.sha256((root/'worker.json').read_bytes()).hexdigest()!=experiments.read_json(root/'integrity.json').get('worker_sha256'):
        raise ValueError('Frozen worker policy bytes changed before admission')
    if manifest['worker_resources']!=WORKER or experiments.read_json(root/'worker.json')!=manifest['worker_resources']:
        raise ValueError('Frozen worker policy changed before admission')
    if manifest.get('inference_preflight')!=parallel_contract.preflight_limits(CONCURRENCY):
        raise ValueError('Frozen inference preflight limits changed before admission')
    token_budget(manifest.get('coding_max_total_tokens'))
    token_budget(manifest.get('other_positive_max_total_tokens'))
    if manifest['batches']!=matrix():raise ValueError('Fixed batch matrix changed')
    if manifest['endpoint_sha256']!=provenance.digest({k:v for k,v in lab.load_endpoint(root/'endpoint.json').items() if k!='api_key_env'}):
        raise ValueError('Frozen endpoint changed')
    return root,manifest,experiments.read_json(root/'state.json')


def invoke(root,label,argv,timeout,env=None,control=None):
    folder=root/'commands'/label;folder.mkdir(parents=True,exist_ok=False)
    controls.atomic(folder/'intent.json',{'argv':argv,'timeout_seconds':timeout,'native_platform':'linux/arm64'})
    start=time.monotonic();observed={}
    with (folder/'stdout.json').open('w') as stdout,(folder/'stderr.log').open('w') as stderr:
        process=subprocess.Popen([sys.executable,str(SKILL/'scripts/pi_lab.py'),*argv],stdout=stdout,stderr=stderr,env=env)
        try:
            while process.poll() is None:
                if time.monotonic()-start>=timeout:raise TimeoutError('Frozen invocation deadline exceeded')
                if control:control(process,observed)
                time.sleep(.05)
        except BaseException:
            process.send_signal(signal.SIGINT)
            try:process.wait(timeout=240)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
            raise
    value={'exit_code':process.returncode,'elapsed_seconds':round(time.monotonic()-start,3),'observation':observed}
    controls.atomic(folder/'result.json',value)
    return value


def absence(name,network=False):
    reply=command(['docker','network' if network else 'container','inspect',name],required=False)
    confirmed=ownership_registry.network_absent(reply,name) if network else ownership_registry.absent(reply)
    if not confirmed:raise RuntimeError('Owned absence unconfirmed')


def registry_records():
    path=Path(lab.default_lock_file()+'.registry')
    return ownership_registry.Registry(path).load(observe=True) if path.exists() else []


def enforce_launch_ceiling(root,manifest):
    before=set(experiments.read_json(root/'registry-baseline.json')['launch_ids'])
    fresh=[r for r in registry_records() if r['launch_id'] not in before and r.get('kind')!='network']
    # Two separately budgeted disposable authority containers (infrastructure and collection).
    if len(fresh)+2>manifest['docker_launches_ceiling']:raise RuntimeError('Frozen Docker launch ceiling exceeded')
    return fresh


def image_arguments(root,manifest,name):
    profile,release=name.rsplit('-',1)
    return ['ensure-image','--image',manifest['images'][name]['id'],'--policy','reuse','--profile',profile,'--pi-version',release,
            '--platform','linux/arm64','--resources',str(Path(root)/'worker.json'),
            '--receipt',str(Path(root)/(name+'.json')),
            *(['--browser-sandbox-policy','chromium-userns'] if profile=='browser' else [])]


def infrastructure(root):
    root,manifest,state=verify(root)
    if state['phase']!='frozen':raise ValueError('Infrastructure qualification cannot repeat')
    controls.atomic(root/'registry-baseline.json',{'launch_ids':[r['launch_id'] for r in registry_records()]})
    if not isinstance(manifest.get('session'),str) or not manifest['session']:raise ValueError('Confirmed existing session required for image admission')
    import lab_env
    confirmed=lab.load_endpoint(lab_env.require_ready(manifest['session']))
    if provenance.digest({k:v for k,v in confirmed.items() if k!='api_key_env'})!=manifest['endpoint_sha256']:
        raise ValueError('Confirmed saved environment differs from frozen selection')
    state['phase']='infrastructure';controls.atomic(root/'state.json',state);start=time.monotonic()
    try:
        for name,entry in manifest['images'].items():
            profile,release=name.rsplit('-',1)
            result=invoke(root,'image-'+name,image_arguments(root,manifest,name),180)
            if result['exit_code']:raise RuntimeError('Image admission failed')
            receipt=experiments.read_json(root/(name+'.json'));lab.admit_image(receipt,release);pi_release.native(receipt['id'])
        # Primitive sandbox checks prove physical overlap/FIFO/cancellation before Pi.
        infrastructure_gateway(root,manifest)
        infrastructure_overlap(root,manifest)
        infrastructure_cancel(root,manifest)
        infrastructure_owner_loss(root,manifest)
        for release in release_contracts.RELEASES:
            result=invoke(root,'dom-'+release,['browser-check','--image',manifest['images']['browser-'+release]['id'],
                '--profile','browser','--platform','linux/arm64','--browser-sandbox-policy','chromium-userns',
                '--resources',str(root/'worker.json'),'--results-dir',str(root/'dom')],240)
            if result['exit_code']:raise RuntimeError('Sandboxed DOM gate failed')
        if time.monotonic()-start>manifest['infrastructure_seconds_ceiling']:raise TimeoutError('Infrastructure ceiling exceeded')
        enforce_launch_ceiling(root,manifest)
        state['phase']='infrastructure_qualified'
    except BaseException as exc:state.update(phase='blocked',reason=type(exc).__name__);raise
    finally:controls.atomic(root/'state.json',state)


def infrastructure_overlap(root,manifest):
    image=manifest['images']['core-0.87.1']['id'];args=lab.parser().parse_args(['run','--image',image,'--platform','linux/arm64','--resources',str(root/'worker.json')])
    observations=[];owned=[]
    with resources.admission_lock(args.lock_file) as registry:
        registry.command=lambda argv:command(argv,required=False);lab.require_host(args)
        pool=Allocator(CONCURRENCY['aggregate']);weight=parallel_contract.worker_weight(resources.validate_policy(WORKER))
        launches=[]
        try:
            for ordinal in range(3):
                trial=str(uuid.uuid4());reservation=pool.request(trial,{'generation':registry.generation,'trial_id':trial},weight,30)
                run=root/'infrastructure'/trial;run.mkdir(parents=True)
                workspace=run/'workspace';control=run/'control';workspace.mkdir();control.mkdir();lab.control_channels(control,args.uid)
                helper=lab.trusted_runtime(run);runtime=lab.state_dir(run/'state',str(uuid.uuid4()),args.uid)
                source="import os,time,json;from pathlib import Path;assert os.getuid()!=0;assert not Path('/var/run/docker.sock').exists();assert not any(k.startswith('PI_APP_') for k in os.environ);print(json.dumps({'fixture':'native sandbox','pid':os.getpid(),'uid':os.getuid()}),flush=True);time.sleep(2)"
                controls.atomic(control/'task.json',{'argv':['python3','-c',source],'cwd':'.'})
                name='pi-lab-'+uuid.uuid4().hex[:12];peer=Peer({'network':'none','experiment':str(root)},registry,pool,reservation,
                    {'execution':{'image':image,'platform':'linux/arm64'}},run)
                launches.append((reservation,peer,lab.docker_args(args,image,workspace,control,runtime,name,'none',helpers=helper)+['check'],name,run))
            grants=pool.dispatch()
            if len(grants)!=2 or launches[2][0].state!='queued':raise RuntimeError('FIFO third-worker gate failed')
            active=[]
            for reservation,peer,argv,name,run in launches[:2]:
                peer.handle({'op':'enter','capability':reservation.capability});reply=peer.handle({'op':'launch','argv':argv,'name':name})
                lab.image_info(image,'linux/arm64')
                out=(run/'stdout.log').open('w');err=(run/'stderr.log').open('w');process=subprocess.Popen(reply['argv'],stdout=out,stderr=err)
                active.append((process,out,err,peer,reservation));owned.append(reply['record'])
            deadline=time.monotonic()+10
            while True:
                data=[]
                for record in owned:
                    reply=command(['docker','container','inspect',record['container']],required=False)
                    if reply.returncode==0:data.append(json.loads(reply.stdout)[0])
                if len(data)==2 and all(d['State']['Running'] for d in data):break
                if time.monotonic()>=deadline:raise RuntimeError('Native two-container overlap not observed')
                time.sleep(.02)
            for data in data:
                h=data['HostConfig']
                if h['NanoCpus']!=10**9 or h['Memory']!=1536*1024**2 or h['MemorySwap']!=h['Memory'] or h['PidsLimit']!=512:
                    raise RuntimeError('Physical worker limits do not match reservations')
            observations.append({'two_running':True,'third':'queued','reserved':pool.used()})
            for process,out,err,peer,reservation in active:
                process.wait(timeout=10);out.close();err.close()
                if process.returncode:raise RuntimeError('Native sandbox primitive failed')
                command(['docker','rm','--force',peer.active['container']]);peer.handle({'op':'absent','launch_id':peer.active['launch_id']})
                pool.release(reservation.identity,True,True)
                for record in peer.records:registry.release(record,True)
            if pool.dispatch()!=[launches[2][0]]:raise RuntimeError('Queued third worker did not become eligible')
            reservation,peer,argv,name,run=launches[2]
            peer.handle({'op':'enter','capability':reservation.capability});reply=peer.handle({'op':'launch','argv':argv,'name':name});owned.append(reply['record'])
            lab.image_info(image,'linux/arm64')
            result=command(reply['argv'],timeout=10)
            if result.returncode:raise RuntimeError('Queued sandbox primitive failed')
            command(['docker','rm','--force',name]);peer.handle({'op':'absent','launch_id':peer.active['launch_id']})
            pool.release(reservation.identity,True,True)
            for record in peer.records:registry.release(record,True)
        finally:
            for record in owned:
                command(['docker','rm','--force',record['container']],required=False)
                if not registry.confirm_absent(record):raise RuntimeError('Primitive cleanup uncertain')
                registry.release(record,True)
    controls.atomic(root/'infrastructure-overlap.json',{'passed':True,'observations':observations,'owned_containers':len(owned),
                  'cleanup_confirmed':True,'pi_invocations':0,'scripted_model_invocations':0})


class AuthorityOwner:
    def __init__(self,root,image,endpoint,read_model_key=True):
        self.root=root;self.image=pi_release.native(image);self.endpoint=endpoint
        self.private=Path(tempfile.mkdtemp(prefix='pi-parallel-authority-')).resolve()
        self.control=self.private/'control';self.control.mkdir(mode=0o700)
        self.store=self.private/'store';self.store.mkdir(mode=0o700)
        self.output=root/'authority';self.output.mkdir()
        self.name='pi-parallel-authority-'+uuid.uuid4().hex[:12]
        self.inference=secrets.token_hex(32);self.observer=secrets.token_hex(32);self.issued=[]
        secret_store.write_secret('QUALIFICATION_INFERENCE',self.inference,self.store)
        if read_model_key:
            key,_=secret_store.resolve_secret(endpoint['api_key_env'])
            if not key:raise ValueError('Retained model credential is unavailable')
            secret_store.write_secret(endpoint['api_key_env'],key,self.store)
        self.config={'mode':'discovery','dispatch_enabled':True,'inference_key':self.inference,'observer_key':self.observer,'actors':[]}
        self.write()
    def write(self):controls.atomic(self.control/'config.json',self.config)
    def start(self):
        argv=['docker','run','--detach','--name',self.name,'--platform','linux/arm64','--label','org.pi-parallel-qualification.owned=1',
              '--read-only','--user',str(os.getuid())+':'+str(os.getgid()),'--cap-drop=ALL','--security-opt=no-new-privileges=true',
              '--ipc=none','--cpus','.25','--memory','128m','--memory-swap','128m','--pids-limit','64','--network','bridge',
              '--publish','127.0.0.1::8080','--env','PYTHONDONTWRITEBYTECODE=1','--entrypoint','python3',
              '--mount',f'type=bind,src={self.control},dst=/private,readonly',
              '--mount',f'type=bind,src={self.output},dst=/observations',
              '--mount',f'type=bind,src={HERE},dst=/qualification,readonly',self.image,
              '/qualification/parallel_service.py','--config','/private/config.json','--output','/observations/observations.json']
        controls.atomic(self.root/'authority-intent.json',{'argv':argv,'image':self.image,'cpu_millis':250,'memory_mib':128,'pids_limit':64})
        command(argv);data=json.loads(command(['docker','container','inspect',self.name]).stdout)[0]
        h=data['HostConfig']
        if h['NanoCpus']!=250*10**6 or h['Memory']!=128*1024**2 or h['MemorySwap']!=h['Memory'] or h['PidsLimit']!=64:
            raise RuntimeError('Authority limits not applied')
        port=data['NetworkSettings']['Ports']['8080/tcp'][0]
        if port['HostIp']!='127.0.0.1':raise RuntimeError('Authority route not loopback-only')
        self.host='http://127.0.0.1:'+port['HostPort'];self.child='http://host.docker.internal:'+port['HostPort']
        deadline=time.monotonic()+20
        while True:
            try:self.snapshot();break
            except OSError:
                if time.monotonic()>=deadline:raise RuntimeError('Authority readiness deadline exceeded') from None
                time.sleep(.1)
    def actors(self,case,nonce):
        refs={}
        for role in ('A','B'):
            ref='PQUAL_'+case.upper()+'_'+role;value='PQ_'+role+'_quoted"slash\\é_'+secrets.token_hex(24)
            secret_store.write_secret(ref,value,self.store);self.issued.append(value);refs[role]=ref
            self.config['actors'].append({'key':value,'role':role,'case':case,'nonce':nonce})
        self.write();return refs
    def snapshot(self):
        request=urllib.request.Request(self.host+'/observer',headers={'X-Qualification-Observer':self.observer})
        with urllib.request.urlopen(request,timeout=3) as reply:return json.load(reply)
    def close(self):
        command(['docker','rm','--force',self.name],required=False);absence(self.name)
        shutil.rmtree(self.private)
        controls.atomic(self.root/'authority-cleanup.json',{'confirmed_absent':True,'private_store_removed':True,
              'application_actors':'disposable fixture only','original_model_store_unchanged':True})


def definition(root,batch,manifest,authority,transform=None,prepare_callback=None):
    folder=root/'batches'/batch['id'];folder.mkdir(parents=True)
    kind=batch['kind'];release=batch['release'];endpoint=copy.deepcopy(authority.endpoint)
    if not batch['real_model']:
        endpoint={'base_url':authority.child+'/v1','host_base_url':authority.host+'/v1','model':'qualification-diagnostic',
                  'api_key_env':'QUALIFICATION_INFERENCE','context_window':32768,'max_tokens':1024,'reasoning':False}
    controls.atomic(folder/'endpoint.json',endpoint)
    cases=[];count=2 if kind=='credentials' or not batch['real_model'] else 1
    authority.config.update(mode=kind,dispatch_enabled=batch['real_model'],boundary_release=kind!='boundary');authority.config['actors']=[];authority.write()
    for index in range(count):
        name='case'+str(index);nonce=uuid.uuid4().hex;fixture=folder/name
        refs=authority.actors(name,nonce) if kind=='credentials' or kind in ('abort','timeout','recovery','crash','contamination','provider-fatal') else None
        if kind=='coding':
            fixture.mkdir();project=fixture/'project';shutil.copytree(SKILL/'examples/python-project',project)
            plan=experiments.read_json(SKILL/'assets/python-feature.plan.json')
            # This example's checks are command-only; freeze the packaged independent oracle as a scorer.
            check=plan['checks'][0];oracle=fixture/'scorer.py'
            oracle.write_text("import json,os,sys,unittest\nsys.path.insert(0,os.getcwd())\nsuite=unittest.defaultTestLoader.discover('tests');count=suite.countTestCases();r=unittest.TextTestRunner(stream=sys.stderr).run(suite)\nassert count>0 and r.testsRun==count and r.wasSuccessful() and len(r.skipped)<count\nprint(json.dumps({'schema':1,'scorer_id':'parallel-slug','scorer_version':'1','run_id':os.environ['PI_LAB_RUN_ID'],'attempt_id':os.environ['PI_LAB_ATTEMPT_ID'],'task_status':'pass','score':1,'test_counts':{'discovered':count,'passed':count-len(r.skipped),'failed':0,'skipped':len(r.skipped)},'assertions':[{'id':'acceptance','passed':True}]}))\n")
            check.update(argv=['python3','/opt/pi-scorer/scorer.py'],scorer={'schema':1,'id':'parallel-slug','version':'1',
                         'assets':[{'source':str(oracle),'target':'scorer.py'}],
                         'score_domain':{'min':0,'max':1,'direction':'higher','pass_threshold':1},
                         'required_assertions':['acceptance'],'zero_test_policy':'fail','all_skipped_policy':'fail'})
            planpath=fixture/'plan.json';controls.atomic(planpath,plan)
        elif kind=='lookup':
            fixture.mkdir();project=fixture/'project';shutil.copytree(SKILL/'examples/integration-baseline/project',project)
            plan=experiments.read_json(SKILL/'examples/integration-baseline/lookup.plan.json')
            for asset in plan['checks'][0]['scorer']['assets']:asset['source']=str(SKILL/'examples/integration-baseline'/asset['source'])
            planpath=fixture/'plan.json';controls.atomic(planpath,plan)
        else:
            project,planpath=fixtures.prepare(fixture,kind,nonce,child_service=authority.child,references=refs)
            if kind=='credentials':
                client=project/'client.py';text=client.read_text().replace("headers={'X-Agent-Key':key", "headers={'X-Trial-ID':json.loads(Path(os.environ['PI_LAB_STAGE_CONTEXT']).read_text())['run_id'],'X-Agent-Key':key")
                client.write_text(text)
            if kind=='crash':
                rule=experiments.read_json(fixture/'expected.json');rule['kind']='recovery';controls.atomic(fixture/'expected.json',rule)
        cases.append({'name':name,'project':str(project),'plan':str(planpath)})
    concurrency=copy.deepcopy(CONCURRENCY);budget=dict(fixtures.CORE_BUDGET)
    if batch['real_model']:
        budget['max_total_tokens']=token_budget(manifest.get('other_positive_max_total_tokens',64000))
    if batch['real_model'] and kind=='coding':
        budget['max_total_tokens']=token_budget(manifest.get('coding_max_total_tokens',64000))
    if not batch['real_model']:
        budget={'timeout_seconds':60,'max_turns':20,'max_total_tokens':16000}
        concurrency['gateway'].update(queue_wait_seconds=10,request_timeout_seconds=30)
    variants=[{'name':'baseline'},{'name':'candidate','prompt_suffix':'Verify the declared task using the permitted tools.'}]
    if kind=='lookup':
        profile='profile.json' if release=='0.87.1' else 'profile.pi-1.2.0.json'
        variants[1]['agent_profile']=str(SKILL/'assets/profiles/fixture-lookup'/profile)
    execution={'image':manifest['images'][('browser-' if kind=='browser' else 'core-')+release]['id'],
               'platform':'linux/arm64','resources':str(root/'worker.json'),'network':'bridge'}
    if kind=='browser':execution.update(profile='browser',browser_sandbox_policy='chromium-userns')
    stop=kind in ('abort','timeout','boundary','contamination','provider-fatal')
    value={'schema':2,'name':batch['id'].replace('.','-'),'baseline':'baseline','repetitions':batch['repetitions'],
           'cases':cases,'variants':variants,'budgets':budget,'execution':execution,'concurrency':concurrency,
           'policies':{'primary_attempt':'first','assistance':'exclude','on_failure':'stop' if stop else 'continue','max_attempts':1}}
    if transform:value=transform(value,folder)
    controls.atomic(folder/'definition.json',value)
    prepared=(prepare_callback(folder) if prepare_callback else experiments.prepare(folder/'definition.json',folder/'experiment',lab,folder/'endpoint.json'))
    if prepared['planned']!=batch['cells']:raise RuntimeError('Prepared matrix differs from fixed cell count')
    return folder,Path(prepared['experiment'])


def live_agents(exp):
    found=[]
    for path in (exp/'runs').glob('*/stages/*/descriptor.json'):
        desc=experiments.read_json(path)
        if desc.get('kind')!='agent':continue
        reply=command(['docker','container','inspect',desc['container']],required=False)
        if reply.returncode:continue
        data=json.loads(reply.stdout)[0]
        if data.get('State',{}).get('Running'):found.append((path.parents[2],desc,data))
    return found


def canonical_runs(directory):
    """Retained attempts only; a validated latest alias is not another attempt."""
    directory=Path(directory)
    if directory.is_symlink() or directory.parent.is_symlink():raise RuntimeError('Linked run inventory')
    if not directory.exists():return []
    runs=[]
    for path in directory.iterdir():
        if path.name=='latest' and path.is_symlink():
            target=path.resolve(strict=True)
            if target.parent!=directory.resolve() or not controls.valid_id(target.name) or not target.is_dir():raise RuntimeError('Invalid latest run alias')
            continue
        if path.is_symlink() or not path.is_dir() or not controls.valid_id(path.name):raise RuntimeError('Invalid canonical run directory')
        runs.append(path)
    return sorted(runs)


def count_segments(exp):
    exp=Path(exp)
    if exp.is_symlink() or exp.parent.is_symlink():raise RuntimeError('Linked experiment inventory')
    count=0
    for run in canonical_runs(exp/'runs'):
        stages=run/'stages'
        if stages.is_symlink():raise RuntimeError('Linked stage inventory')
        if not stages.exists():continue
        for stage in stages.iterdir():
            if stage.is_symlink() or not stage.is_dir() or not controls.valid_id(stage.name):raise RuntimeError('Invalid canonical stage directory')
            segments=stage/'segments'
            if segments.is_symlink():raise RuntimeError('Linked segment inventory')
            if not segments.exists():continue
            for path in segments.iterdir():
                if path.is_symlink() or not path.is_file() or path.suffix!='.json' or not controls.valid_id(path.stem):raise RuntimeError('Invalid canonical segment file')
                count+=1
    return count


def validate_fault(exp,kind,rows,invocation,batch):
    exp=Path(exp);attempted=[row for row in rows if row['attempts']]
    if len(rows)!=batch['cells'] or any(len(row['attempts'])!=1 for row in attempted):
        raise RuntimeError('Fault accounting lost planned cells or introduced retries')
    records=[row['attempts'][0]['result'] for row in attempted]
    full=kind in ('recovery','crash','discovery','boundary')
    if len(attempted)!=(4 if full else 2):raise RuntimeError('Fault attempted/pending denominator differs from frozen policy')
    if not all(row['attempts'] for row in rows[:2]):raise RuntimeError('Both first active trials were not retained')
    codes={'PASS':0,'FAIL':1,'INTERRUPTED':2,'RECOVERED':1,'BLOCKED':2}
    if any(r['exit_code']!=codes.get(r['status']) for r in records):raise RuntimeError('Fault sealed status/exit mismatch')
    observed=invocation.get('observation',{})
    def physical(record):
        receipts=[]
        run=exp/'runs'/record['run_id']
        for path in (run/'stages').glob('*/segments/*.json'):
            segment=experiments.read_json(path);receipt=experiments.read_json(Path(segment['logs'])/'process.json')
            if receipt.get('cleanup_confirmed') is not True:raise RuntimeError('Fault writer absence not confirmed')
            receipts.append((segment,receipt))
        if not receipts:raise RuntimeError('Fault has no actual Pi segment')
        return receipts
    by_run={r['run_id']:physical(r) for r in records}
    if kind=='abort':
        if invocation['exit_code']!=2 or observed.get('cancelled') is not True or any(r['status']!='INTERRUPTED' or r['termination']['reason']!='cancelled' or r['scoring']['status'] not in ('skipped','cancelled') for r in records):
            raise RuntimeError('Fault lacks controlled parent cancellation with suppressed scoring')
        if any(p.get('cancelled') is not True or p.get('termination_reason')!='cancelled' for receipts in by_run.values() for meta,p in receipts):
            raise RuntimeError('Abort did not actually stop both Pi processes')
    elif kind=='timeout':
        if invocation['exit_code']!=1 or any(r['status'] not in ('FAIL','INTERRUPTED') for r in records):raise RuntimeError('Timeout policy/exit mismatch')
        timed=[r for r in records if r['status']=='FAIL']
        if not timed or any(r['termination']['reason']!='timeout' or not all(p.get('timed_out') is True and p.get('exit_code')==124 and p.get('termination_reason')=='timeout' for meta,p in by_run[r['run_id']]) for r in timed):
            raise RuntimeError('Timeout qualification cannot accept an unrelated FAIL')
    elif kind=='provider-fatal':
        if invocation['exit_code']!=1 or not observed.get('barrier_released_after_overlap'):raise RuntimeError('Fatal provider lacks controlled release')
        failed=[r for r in records if r['status']=='FAIL']
        if not failed or any(r['status'] not in ('FAIL','INTERRUPTED') for r in records):raise RuntimeError('Fatal provider policy mismatch')
        for record in failed:
            messages=[cause for meta,p in by_run[record['run_id']] for cause in meta.get('evidence',{}).get('unsuccessful_messages',[])]
            if 'error' not in messages or record['termination']['reason'] in ('timeout','cleanup_error','cancelled'):
                raise RuntimeError('Fatal provider qualification cannot accept an unrelated FAIL')
    elif kind=='contamination':
        if invocation['exit_code']!=2 or any(r['status'] not in ('FAIL','INTERRUPTED') for r in records):raise RuntimeError('Contamination policy mismatch')
        discarded=[r for r in records if r['status']=='FAIL']
        if not discarded:raise RuntimeError('No actual contamination was observed')
        for record in discarded:
            row=next(row for row in rows if row['trial_id']==record['trial_id'])
            pi_release.validate_contamination_execution(exp/'runs'/record['run_id'],exp/row['source'],record)
    elif kind=='recovery':
        if invocation['exit_code']!=0 or len(observed.get('steers',{}))!=2 or [r['status'] for r in records]!=['RECOVERED','RECOVERED','PASS','PASS']:
            raise RuntimeError('Recovery lacks two assisted primaries and two fresh pending trials')
        for record in records[:2]:
            run=exp/'runs'/record['run_id'];receipts=by_run[record['run_id']]
            if len(receipts)!=2 or record['invocation']['status']!='recovered':raise RuntimeError('Recovery lacks exact-session successor')
            first,second=receipts[0][0],receipts[1][0]
            # Sort UUID records by explicit segment ordinal, never filesystem order.
            first,second=sorted((first,second),key=lambda m:m['ordinal'])
            if second.get('continues_segment_id')!=first['segment_id'] or second['session_id']!=first['session_id'] or second['execution_identity']!=first['execution_identity'] or not second.get('session_sha256'):
                raise RuntimeError('Recovery crossed session/image/release identity')
            if not any(e.get('status')=='applied' and e.get('action')=='interrupt_signal' for e in controls.history(run)):
                raise RuntimeError('Recovery lacks independently applied interrupt')
    elif kind=='crash':
        if invocation['exit_code']!=-signal.SIGKILL or not observed.get('owner_killed') or invocation.get('resume',{}).get('exit_code')!=0 or [r['status'] for r in records]!=['FAIL','FAIL','PASS','PASS']:
            raise RuntimeError('Owner-loss/reconciliation denominator or controller exit mismatch')
        for record in records[:2]:
            if record.get('controller_interruption',{}).get('kind')!='controller_lost' or record['termination'].get('trigger')!='controller_lost':
                raise RuntimeError('Crash was confused with user cancellation or unrelated failure')
    else:
        if invocation['exit_code']!=0 or any(r['status']!='PASS' for r in records):raise RuntimeError('Namespace/discovery lane failed')
        if kind=='boundary' and (not observed.get('protected_before') or len(observed['protected_before'])!=2 or observed.get('protected_after')!=observed['protected_before']):
            raise RuntimeError('Boundary protection evidence missing')
    expected_segments=6 if kind=='recovery' else 4 if full else 2
    if sum(len(v) for v in by_run.values())!=expected_segments:raise RuntimeError('Fault segment/attempt accounting mismatch')


def validate_positive(exp,metadata,rows,invocation,batch):
    exp=Path(exp);kind=batch['kind'];records=[a['result'] for row in rows for a in row['attempts']]
    import comparisons
    if invocation['exit_code']!=0 or len(records)!=batch['cells'] or any(r['status']!='PASS' or r['exit_code']!=0 for r in records):
        raise RuntimeError('Positive lane/controller failed acceptance')
    expected=comparisons.expected_contracts(exp,metadata,rows,lab)
    stages=3 if kind=='credentials' else 2 if kind=='coding' else 1
    for row in rows:
        record=row['attempts'][0]['result'];run=exp/'runs'/record['run_id']
        if len(record['agents'])!=stages or len(list((run/'stages').glob('*/segments/*.json')))!=stages:
            raise RuntimeError('Positive lane lacks exact native stage/segment evidence')
        if not comparisons.assessment(record,expected[row['trial_id']],row['configuration_digest'])['successful']:
            raise RuntimeError('Positive lane lacks attributable protected independent acceptance')


def run_batch(root,batch,manifest,authority,collection_deadline=None,definition_builder=None,session=None):
    folder,exp=(definition_builder or definition)(root,batch,manifest,authority);kind=batch['kind'];overlaps=[]
    before=len(authority.snapshot()['effects']);steers={};started=time.monotonic();crashed=False
    env=pi_release.checker_env({'PI_LAB_SECRETS_DIR':str(authority.store)})
    def remaining(maximum):
        value=maximum if collection_deadline is None else min(maximum,collection_deadline-time.monotonic())
        if value<=0:raise TimeoutError('Frozen whole collection deadline reached')
        return value
    def protected(desc):
        reply=command(['docker','exec',desc['container'],'python3','-c',
            "import hashlib,json;from pathlib import Path;print(json.dumps({p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in ['/etc/hostname','/opt/pi-control/task.json']}))"],timeout=10)
        return json.loads(reply.stdout)
    def control(process,observed):
        nonlocal crashed
        enforce_launch_ceiling(root,manifest)
        active=live_agents(exp)
        if len(active)>=2:
            identities=[d['stage_id'] for run,d,data in active]
            for run,desc,data in active:
                h=data['HostConfig']
                if h['NanoCpus']!=10**9 or h['Memory']!=1536*1024**2 or h['MemorySwap']!=h['Memory'] or h['PidsLimit']!=512:
                    raise RuntimeError('Overlapping worker violated native limits')
            if not overlaps:overlaps.append({'stage_ids':identities,'two_running':True,'image':manifest['images'][('browser-' if kind=='browser' else 'core-')+batch['release']]['id']})
            if kind=='boundary' and 'protected_before' not in observed:
                observed['protected_before']={d['stage_id']:protected(d) for run,d,data in active}
            if kind=='boundary' and not authority.config['boundary_release'] and any(r.get('completed_tools',0)>=7 for r in authority.snapshot()['requests']):
                observed['protected_after']={d['stage_id']:protected(d) for run,d,data in active if d['stage_id'] in observed.get('protected_before',{})}
                if observed['protected_after']!=observed['protected_before']:raise RuntimeError('Protected container/control bytes changed')
                authority.config['boundary_release']=True;authority.write()
            if not batch['real_model'] and not authority.config['dispatch_enabled']:
                authority.config['dispatch_enabled']=True;authority.write();observed['barrier_released_after_overlap']=True
        if batch['real_model'] or kind not in ('abort','recovery','crash'):return
        held=[]
        for run,desc,data in active:
            # Independently observe a real child bash process, not a model prose claim.
            reply=command(['docker','exec',desc['container'],'python3','-c',
              "import os;from pathlib import Path;print(sum(b'time.sleep(180)' in p.read_bytes() for p in Path('/proc').glob('[0-9]*/cmdline') if p.parent.name!=str(os.getpid()) and p.exists()))"],required=False)
            if reply.returncode==0 and reply.stdout.strip().isdigit() and int(reply.stdout.strip())>=1:held.append((run,desc))
        if len(held)<2:return
        if kind=='abort' and not observed.get('cancelled'):
            observed['cancelled']=True;process.send_signal(signal.SIGINT)
        if kind=='crash' and not crashed:
            observed['owner_killed']=True;crashed=True;process.kill()
            authority.config['mode']='crash-finish';authority.write()
        if kind=='recovery' and not steers:
            authority.config['mode']='recovery-finish';authority.write()
            for run,desc in held:
                reply=command([sys.executable,str(SKILL/'scripts/pi_lab.py'),'steer','--run',str(run),'--stage',desc['stage_id'],
                               '--message','Finish this exact-session recovery task.','--interrupt'])
                steers[desc['stage_id']]=json.loads(reply.stdout)
            observed['steers']=steers
    result=invoke(root,batch['id'],['experiment-run','--experiment',str(exp),*(['--session',session] if session else [])],remaining(3600),env,control)
    if kind=='crash':
        # Child controllers retain custody while stopping; never bypass their lease.
        deadline=time.monotonic()+60
        while True:
            try:
                with resources.admission_lock(lab.default_lock_file()):break
            except resources.AdmissionError as exc:
                if exc.reason!='host-admission-busy' or time.monotonic()>=deadline:raise
                time.sleep(.1)
        originals={p:p.read_bytes() for p in (exp/'runs').glob('*/result.json')}
        result['resume']=invoke(root,batch['id']+'-resume',['experiment-resume','--experiment',str(exp),*(['--session',session] if session else [])],remaining(240),env)
        if any(p.read_bytes()!=body for p,body in originals.items()):raise RuntimeError('Resume rewrote a sealed primary')
    metadata,matrix=experiments.verify(exp,lab);rows=experiments.ledger_rows(exp,lab)
    records=[a['result'] for row in rows for a in row['attempts']]
    if not overlaps:raise RuntimeError('No real two-agent overlap observed')
    if not records or any(r is None for r in records):raise RuntimeError('Attempt not sealed')
    if batch['real_model']:validate_positive(exp,metadata,rows,result,batch)
    if not batch['real_model']:validate_fault(exp,kind,rows,result,batch)
    if kind=='credentials':
        effects=authority.snapshot()['effects'][before:]
        for record in records:
            actual=[e for e in effects if e['run_id']==record['run_id']]
            if sorted(e['role'] for e in actual)!=['A','B']:raise RuntimeError('Independent application effects oracle failed')
    for record in records:
        run=Path(record['run_dir'])
        if list((run/'stages').glob('*/application-credentials.json')):pi_release.sensitive_clean(run,authority.issued)
        for path in (run/'stages').glob('*/segments/*.json'):
            segment=experiments.read_json(path);receipt=experiments.read_json(Path(segment['logs'])/'process.json')
            if receipt.get('cleanup_confirmed') is not True:raise RuntimeError('Physical Pi segment absence unconfirmed')
    count=count_segments(exp)
    if count>batch['segments_ceiling']:raise RuntimeError('Frozen batch Pi-segment ceiling exceeded')
    experiments.export_ledger(exp,lab)
    controls.atomic(folder/'overlap.json',{'observations':overlaps,'source_frozen_before_dispatch':True})
    return {'id':batch['id'],'passed':True,'real_model':batch['real_model'],'planned':batch['cells'],
            'attempted':len(records),'segments':count,'statuses':[r['status'] for r in records],
            'two_pi_containers_observed':True,'elapsed_seconds':round(time.monotonic()-started,3)}


def collect(root):
    root,manifest,state=verify(root)
    if state['phase']!='infrastructure_qualified':raise ValueError('Infrastructure gate required; failed/running collection cannot repeat')
    state['phase']='collecting';start=time.monotonic();controls.atomic(root/'state.json',state)
    endpoint=lab.load_endpoint(root/'endpoint.json');authority=AuthorityOwner(root,manifest['images']['core-0.87.1']['id'],endpoint)
    try:
        authority.start()
        for batch in manifest['batches']:
            if time.monotonic()-start>=manifest['collection_seconds_ceiling']:raise TimeoutError('Whole collection ceiling reached')
            state['active_batch']=batch['id'];state['attempted_batches'].append(batch['id']);controls.atomic(root/'state.json',state)
            result=run_batch(root,batch,manifest,authority,start+manifest['collection_seconds_ceiling']);state['batches'].append(result);state['active_batch']=None
            state['native_pi_segments']+=result['segments']
            if state['native_pi_segments']>manifest['segments_ceiling']:raise RuntimeError('Global Pi-segment ceiling exceeded')
            controls.atomic(root/'state.json',state)
            print(json.dumps({'batch':batch['id'],'passed':True,'completed':len(state['batches']),'planned':len(manifest['batches']),
                              'native_pi_segments':state['native_pi_segments']}),flush=True)
        if [r['id'] for r in state['batches']]!=[r['id'] for r in manifest['batches']]:raise RuntimeError('Fixed matrix incomplete')
        state['phase']='qualified'
    except BaseException as exc:
        state.update(phase='blocked',reason=type(exc).__name__,remaining_not_run=[r['id'] for r in manifest['batches'] if r['id'] not in state['attempted_batches']]);raise
    finally:
        try:
            with resources.admission_lock(lab.default_lock_file(),min(240,manifest['cleanup_seconds_ceiling'])):pass
            fresh=enforce_launch_ceiling(root,manifest)
            for record in fresh:
                absence(record['container'])
            before=set(experiments.read_json(root/'registry-baseline.json')['launch_ids'])
            networks=[r for r in registry_records() if r['launch_id'] not in before and r.get('kind')=='network']
            for record in networks:absence(record['container'],network=True)
            if any(Path(r['private_store']).exists() for r in fresh if r.get('private_store')):raise RuntimeError('Gateway private store retained')
            controls.atomic(root/'owned-cleanup.json',{'owned_containers':len(fresh),'all_confirmed_absent':True,
                'owned_networks':len(networks),'all_networks_confirmed_absent':True,'gateway_private_stores_removed':True})
        except BaseException as exc:state.update(phase='blocked',cleanup_error=type(exc).__name__)
        try:authority.close()
        except BaseException as exc:state.update(phase='blocked',cleanup_error=type(exc).__name__)
        redactor=application_credentials.Redactor(authority.issued)
        state['known_application_key_matches']=sum(redactor.contains(p.read_bytes()) for p in root.rglob('*') if p.is_file() and not p.is_symlink())
        if state['known_application_key_matches']:state.update(phase='blocked',reason='sensitive evidence retained')
        state['native_pi_segments']=sum(count_segments(p) for p in (root/'batches').glob('*/experiment'))
        controls.atomic(root/'state.json',state)
    if state['phase']!='qualified':raise RuntimeError('Qualification or owned cleanup incomplete')


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='operation',required=True)
    freeze_parser=sub.add_parser('freeze');freeze_parser.add_argument('--root',required=True);freeze_parser.add_argument('--images',required=True);freeze_parser.add_argument('--endpoint',required=True);freeze_parser.add_argument('--session',required=True)
    freeze_parser.add_argument('--coding-max-total-tokens',type=int,choices=(64000,128000),default=64000)
    freeze_parser.add_argument('--other-positive-max-total-tokens',type=int,choices=(64000,128000),default=64000)
    for name in ('infrastructure','collect'):
        item=sub.add_parser(name);item.add_argument('--root',required=True)
    args=parser.parse_args()
    if args.operation=='freeze':print(json.dumps(freeze(args.root,args.images,args.endpoint,args.session,args.coding_max_total_tokens,args.other_positive_max_total_tokens),indent=2))
    elif args.operation=='infrastructure':infrastructure(args.root)
    else:collect(args.root)



# Infrastructure owner-loss helper is invoked only from the frozen infrastructure
# gate. It launches key-free sandbox checks under the same real host lease.
def infrastructure_owner(root,image):
    args=lab.parser().parse_args(['run','--image',image,'--platform','linux/arm64','--resources',str(root/'worker.json')])
    owned=[]
    with resources.admission_lock(args.lock_file) as registry:
        registry.command=lambda argv:command(argv,required=False);lab.require_host(args)
        pool=Allocator(CONCURRENCY['aggregate']);weight=parallel_contract.worker_weight(resources.validate_policy(WORKER))
        for index in range(2):
            trial=str(uuid.uuid4());reservation=pool.request(trial,{'generation':registry.generation},weight,30);pool.dispatch()
            folder=root/'owner-loss'/trial;folder.mkdir(parents=True);workspace=folder/'workspace';control=folder/'control'
            workspace.mkdir();control.mkdir();lab.control_channels(control,args.uid)
            runtime=lab.state_dir(folder/'state',str(uuid.uuid4()),args.uid);helper=lab.trusted_runtime(folder)
            controls.atomic(control/'task.json',{'argv':['python3','-c','import time;time.sleep(180)'],'cwd':'.'})
            name='pi-lab-'+uuid.uuid4().hex[:12]
            peer=Peer({'network':'none','experiment':str(root)},registry,pool,reservation,{'execution':{'image':image,'platform':'linux/arm64'}},folder)
            peer.handle({'op':'enter','capability':reservation.capability})
            argv=lab.docker_args(args,image,workspace,control,runtime,name,'none',helpers=helper)
            # Registry recognizes the worker helper regardless of detached CLI mode.
            argv=argv[:2]+['--detach']+argv[2:]+['check']
            record,argv=registry.intent(argv,name,{'generation':registry.generation},folder)
            lab.image_info(image,'linux/arm64');command(argv);owned.append(record)
        controls.atomic(root/'owner-loss-ready.json',{'containers':[r['container'] for r in owned]})
        time.sleep(180)


def infrastructure_owner_loss(root,manifest):
    image=manifest['images']['core-0.87.1']['id']
    with (root/'owner-loss-owner.log').open('w') as output:
        # Keep the frozen helper in this source file; no generated code gets promoted.
        source="import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);import parallel;parallel.infrastructure_owner(Path(sys.argv[2]),sys.argv[3])"
        process=subprocess.Popen([sys.executable,'-c',source,str(HERE),str(root),image],stdout=output,stderr=output)
        try:
            deadline=time.monotonic()+30
            while not (root/'owner-loss-ready.json').exists():
                if process.poll() is not None or time.monotonic()>=deadline:raise RuntimeError('Infrastructure owner did not launch both writers')
                time.sleep(.05)
            ready=experiments.read_json(root/'owner-loss-ready.json')
            with_busy=False
            try:
                with resources.admission_lock(lab.default_lock_file()):pass
            except resources.AdmissionError as exc:with_busy=exc.reason=='host-admission-busy'
            if not with_busy:raise RuntimeError('Native old owner did not hold the shared lease')
            process.kill();process.wait(timeout=5)
            # A fresh serial registry-aware client must reconcile the two writers.
            with resources.admission_lock(lab.default_lock_file()):
                for name in ready['containers']:absence(name)
            controls.atomic(root/'infrastructure-owner-loss.json',{'passed':True,'old_lease_busy':True,
                'owner_killed':True,'new_serial_admission_reconciled':True,'owned_containers':2,'confirmed_absent':True,'pi_invocations':0})
        finally:
            if process.poll() is None:process.kill();process.wait(timeout=5)
            with resources.admission_lock(lab.default_lock_file()):pass


def infrastructure_cancel(root,manifest):
    image=manifest['images']['core-0.87.1']['id'];args=lab.parser().parse_args(['run','--image',image,'--platform','linux/arm64','--resources',str(root/'worker.json')])
    records=[];processes=[]
    with resources.admission_lock(args.lock_file) as registry:
        registry.command=lambda argv:command(argv,required=False);lab.require_host(args)
        try:
            for index in range(2):
                folder=root/'infrastructure-cancel'/str(index);folder.mkdir(parents=True)
                workspace=folder/'workspace';control=folder/'control';workspace.mkdir();control.mkdir();lab.control_channels(control,args.uid)
                runtime=lab.state_dir(folder/'state',str(uuid.uuid4()),args.uid);helper=lab.trusted_runtime(folder)
                code='import sys,time;time.sleep(2);sys.exit(7)' if index==0 else 'import time;time.sleep(180)'
                controls.atomic(control/'task.json',{'argv':['python3','-c',code],'cwd':'.'})
                name='pi-lab-'+uuid.uuid4().hex[:12];argv=lab.docker_args(args,image,workspace,control,runtime,name,'none',helpers=helper)+['check']
                record,argv=registry.intent(argv,name,runroot=folder);records.append(record);lab.image_info(image,'linux/arm64')
                output=(folder/'output.log').open('w');processes.append((subprocess.Popen(argv,stdout=output,stderr=output),output))
            first=processes[0][0];first.wait(timeout=15)
            if first.returncode!=7:raise RuntimeError('Infrastructure deliberate failure not observed')
            processes[1][0].send_signal(signal.SIGINT);processes[1][0].wait(timeout=15)
            if processes[1][0].returncode==0:raise RuntimeError('Infrastructure cancellation lost')
        finally:
            for record in records:
                command(['docker','rm','--force',record['container']],required=False)
                if not registry.confirm_absent(record):raise RuntimeError('Cancellation writer absence uncertain')
                registry.release(record,True)
            for process,output in processes:
                if process.poll() is None:process.kill();process.wait(timeout=5)
                output.close()
    controls.atomic(root/'infrastructure-cancel.json',{'passed':True,'failure_exit':7,'cancel_exit':processes[1][0].returncode,
              'owned_containers':2,'cleanup_confirmed':True,'pi_invocations':0})


def infrastructure_gateway(root,manifest):
    from parallel_execution import gateway_owner
    folder=root/'infrastructure-gateway';folder.mkdir()
    endpoint={'base_url':'http://example.invalid/v1','model':'qualification-diagnostic','api_key_env':'QUALIFICATION_INFERENCE',
              'context_window':32768,'max_tokens':1024,'reasoning':False}
    authority=AuthorityOwner(folder,manifest['images']['core-0.87.1']['id'],endpoint,read_model_key=False)
    try:
        authority.start();endpoint.update(base_url=authority.child+'/v1',host_base_url=authority.host+'/v1')
        controls.atomic(folder/'endpoint.json',endpoint)
        args=lab.parser().parse_args(['run','--image',manifest['images']['core-0.87.1']['id'],'--platform','linux/arm64','--resources',str(root/'worker.json')])
        with resources.admission_lock(args.lock_file) as registry:
            registry.command=lambda argv:command(argv,required=False);lab.require_host(args)
            pool=Allocator(CONCURRENCY['aggregate']);trial=str(uuid.uuid4());work=[{'trial_id':trial,'endpoint':'endpoint.json'}]
            metadata={'concurrency':CONCURRENCY,'execution':{'image':args.image,'platform':'linux/arm64'}}
            with gateway_owner(lab,args,folder,metadata,work,registry,pool,parallel_contract.worker_weight(resources.validate_policy(WORKER)),authority.inference) as (routing,network_factory,network_cleanup):
                namespace=network_factory({'trial_id':trial});route=routing['trial']({'trial_id':trial})
                run=folder/'client';run.mkdir();workspace=run/'workspace';workspace.mkdir()
                target={**endpoint,'base_url':route['base_url'],'host_base_url':route['host_base_url']}
                result=lab.run_stage(args,args.image,run,workspace,'preflight',['preflight','--chat'],endpoint=target,
                                     secret=route['token'],network=namespace,timeout=90)
                if result['exit_code'] or not result['cleanup_confirmed']:raise RuntimeError('Native gateway/token/upstream route gate failed')
                network_cleanup(namespace)
        receipt=experiments.read_json(folder/'gateway-receipt.json')
        if receipt['observed'].get('observed_max_inflight')!=1 or receipt['observed'].get('uncertain') is not False:
            raise RuntimeError('Native one-slot inference accounting gate failed')
        controls.atomic(folder/'qualification.json',{'passed':True,'model_source':'scripted','pi_invocations':0,
            'native_gateway_limits_verified':True,'opaque_token_forwarding_verified':True,'cleanup_confirmed':True})
    finally:authority.close()


if __name__=='__main__':main()
