"""Explicit schema-2 admission. Serial entry points remain unchanged."""
import copy
import contextlib
import hashlib
import json
from pathlib import Path
import platform
import secrets
import shutil
import tempfile
import time
from urllib.request import urlopen
import uuid

import agent_profiles
import application_credentials
import experiments
import lab_env
import ownership_registry
import parallel_contract
from parallel_allocator import Allocator
import parallel_engine
import provenance
import release_contracts
import resources
import secret_store
import stage_control as controls


def app_admission(root,work,lab,args,endpoint,upstream_key):
    assigned={};authorities={};values={}
    for cell in work:
        planpath=root/cell['plan'];profile=agent_profiles.load(root/cell['agent_profile'])
        plan=lab.validate_plan(experiments.read_json(planpath),planpath.parent,profile)
        found=application_credentials.resolve(plan,endpoint,upstream_key,
                getattr(args,'secrets_dir',None) or secret_store.default_store(),root/cell['source'],root/'runs',False,
                forbidden_roots=[lab.ROOT,root])
        assigned[cell['trial_id']]=found
        refs={reference for stage in plan['agents'] for reference in stage.get('application_secrets',{}).values()}
        authorities[cell['trial_id']]=sorted(refs)
        for task in plan['agents']:
            for variable,ref in task.get('application_secrets',{}).items():
                value=found[task['name']][variable]
                if value in values and values[value]!=ref:raise parallel_contract.ParallelError('Different actor references share an authority')
                values[value]=ref
    return assigned,authorities


@contextlib.contextmanager
def gateway_owner(lab,args,root,metadata,work,registry,pool,worker_resources,upstream_key):
    contract=metadata['concurrency'];helper=contract['gateway']['resources']
    item=pool.request('gateway',{'generation':registry.generation},helper,30,'helper');pool.dispatch()
    pool.consume(item.identity,item.capability,item.binding,item.resources)
    directory=Path(tempfile.mkdtemp(prefix='pi-parallel-gateway-')).resolve();name='pi-lab-gateway-'+uuid.uuid4().hex[:12]
    record=None;networks={};tokens={c['trial_id']:secrets.token_hex(32) for c in work}
    try:
        config=copy.deepcopy(args);config.cpus=helper['cpu_millis']/1000;config.memory=str(helper['memory_mib'])+'m';config.pids_limit=helper['pids_limit'];config.jobs=1
        config.profile='core';config.browser_sandbox_policy='docker-default';config.frozen_browser_security=None
        workspace=directory/'workspace';control=directory/'control';workspace.mkdir();control.mkdir()
        lab.control_channels(control,config.uid);state=lab.state_dir(directory/'state',str(uuid.uuid4()),config.uid)
        endpoint=lab.load_endpoint(root/work[0]['endpoint'])
        gateway_config={'endpoint':endpoint,'upstream_key':upstream_key,
                'tokens':{token:trial for trial,token in tokens.items()},'limits':contract['gateway']}
        controls.atomic(control/'inference.json',gateway_config)
        image=lab.image_info(metadata['execution']['image'],metadata['execution']['platform'])['id']
        argv=lab.docker_args(config,image,workspace,control,state,name,'bridge',helpers=lab.RUNTIME)
        argv=argv[:2]+['--detach','--publish','127.0.0.1::8080','--sysctl','net.ipv4.ip_forward=0']+argv[2:]+['gateway','--config','/opt/pi-control/inference.json']
        record,argv=registry.intent(argv,name)
        record['gateway_state']=str(control/'outbox/gateway-state.json');record['private_store']=str(directory);registry.write(record)
        gateway_config['launch_id']=record['launch_id'];controls.atomic(control/'inference.json',gateway_config)
        lab.command(argv,timeout=30);pool.running('gateway')
        observed=json.loads(lab.command(['docker','container','inspect',name]).stdout)[0]
        actual=observed['HostConfig']
        if actual.get('NanoCpus')!=helper['cpu_millis']*10**6 or actual.get('Memory')!=helper['memory_mib']*1024**2 or actual.get('MemorySwap')!=actual['Memory'] or actual.get('PidsLimit')!=helper['pids_limit']:
            raise parallel_contract.ParallelError('Gateway Docker limits do not match reservation')
        port=observed['NetworkSettings']['Ports']['8080/tcp'][0]
        if port['HostIp']!='127.0.0.1':raise parallel_contract.ParallelError('Gateway host route is not loopback-only')
        host='http://127.0.0.1:'+port['HostPort']
        deadline=time.monotonic()+20
        while True:
            try:
                with urlopen(host+'/health',timeout=1) as reply:
                    if json.load(reply).get('status')=='ready':break
            except OSError:
                if time.monotonic()>=deadline:raise parallel_contract.ParallelError('Gateway readiness deadline exceeded') from None
                time.sleep(.1)
        record['gateway_ready']=True;registry.write(record)
        def network_factory(intent):
            name='pi-trial-'+uuid.uuid4().hex[:16];owned=registry.network_intent(name);networks[name]=owned
            lab.command(['docker','network','create','--driver','bridge','--label',ownership_registry.LABEL+'='+owned['launch_id'],
                         '--label',ownership_registry.REGISTRY_LABEL+'='+registry.registry_id,name])
            lab.command(['docker','network','connect','--alias','pi-inference',name,record['container']])
            return name
        def cleanup_network(name):
            lab.command(['docker','network','disconnect',name,record['container']],required=False)
            registry.remove_network(networks[name]);registry.release(networks[name],True);del networks[name]
        inference={'worker_resources':worker_resources,'trial':lambda intent:{'base_url':'http://pi-inference:8080/v1',
                        'host_base_url':host+'/v1','token':tokens[intent['trial_id']]}}
        yield inference,network_factory,cleanup_network
    finally:
        # Confirm gateway absence before deleting its upstream secret and tokens.
        if record is not None:
            drain_deadline=time.monotonic()+contract['gateway']['request_timeout_seconds']+5
            uncertain=False
            recovered=next((r for r in registry.load() if r['launch_id']==record['launch_id'] and r['status']=='released'),None)
            while recovered is None:
                try:
                    observation=ownership_registry.read_private(record['gateway_state'])
                    if observation.get('launch_id')!=record['launch_id']:raise ValueError('Gateway observation owner mismatch')
                    if observation.get('uncertain') is True:uncertain=True;break
                    if observation.get('inflight')==0 and observation.get('pending')==0:break
                except (OSError,ValueError):
                    if record.get('gateway_ready') is not True:break
                if time.monotonic()>=drain_deadline:uncertain=True;break
                time.sleep(.1)
            try:
                observed=ownership_registry.read_private(record['gateway_state'])
                controls.atomic(root/'gateway-receipt.json',{'schema':1,'scheduler':contract['scheduler'],
                    'contract_sha256':provenance.digest(contract),'limits':contract['gateway'],
                    'observed':observed,'scope':'Cooperating requests; no server-wide capacity or inference-time claim'})
            except (OSError,ValueError):pass
            if uncertain:
                record['inference_uncertain']=True;registry.write(record)
            lab.command(['docker','rm','--force',record['container']],required=False)
            physical=registry.confirm_absent(record)
            if not physical:pool.release('gateway',False,False);raise parallel_contract.ParallelError('Gateway absence unconfirmed; private state retained')
            for network in networks.values():registry.remove_network(network);registry.release(network,True)
            shutil.rmtree(directory)
            if uncertain:
                record['status']='quarantined';registry.write(record);pool.release('gateway',True,False)
                raise parallel_contract.ParallelError('Upstream request termination uncertain; no new inference admission')
            registry.release(record,True);pool.release('gateway',True,True)
        else:
            shutil.rmtree(directory);pool.release('gateway',True,True)


def execute(root,lab,session=None,resume=False,retry_trial=None):
    root=Path(root).resolve()
    with experiments.controller_lock(root):
        metadata,matrix=experiments.verify(root,lab);previous=experiments.controller_state(root)
        if metadata['schema']!=2:raise parallel_contract.ParallelError('Explicit schema-2 experiment required')
        if metadata['runner_content_sha256']!=provenance.execution({}, {},lab.ROOT)['runner_content_sha256'] or metadata['release_contracts']!=release_contracts.snapshot() or metadata['prepared_root']!=str(root):
            raise parallel_contract.ParallelError('Frozen source/release/execution identity changed')
        if any(experiments.attempt_intents(root,c) for c in matrix['cells']) and not resume:
            raise parallel_contract.ParallelError('Existing attempts require explicit resume')
        args=experiments.trial_args(root,metadata,matrix['cells'][0],lab,session)
        if metadata['execution']['platform']!='linux/'+lab.norm_arch(platform.machine()):raise parallel_contract.ParallelError('Parallel execution requires native architecture')
        for cell in matrix['cells']:
            if cell['endpoint_origin']=='saved_environment':
                approved=lab.load_endpoint(lab_env.require_ready(session))
                if lab_env.fingerprint_of(approved)!=lab_env.fingerprint_of(lab.load_endpoint(root/cell['endpoint'])):
                    raise parallel_contract.ParallelError('Confirmed model environment differs from frozen inputs')
        with resources.admission_lock(args.lock_file,args.lock_wait_seconds) as registry:
            registry.command=lambda argv:lab.command(argv,timeout=15,required=False)
            lab.require_host(args)
            capacity=parallel_contract.admit_capacity(metadata['concurrency'],resources.requested_policy(args),lab.docker_info())
            if args.resource_report['effective']['runtime']!=args.resource_report['requested']['runtime']:
                raise parallel_contract.ParallelError('Frozen parallel workers cannot be clamped')
            if resume:
                def cleanup_abandoned(exp,intent,unused_metadata,unused_lab):
                    run=Path(exp)/'runs'/intent['run_id'];records=registry.load();proof=[]
                    descriptors=list((run/'stages').glob('*/descriptor.json'))+list((run/'image-probes').glob('*.json'))
                    for path in descriptors:
                        desc=experiments.read_json(path)
                        matches=[r for r in records if r.get('container')==desc.get('container') and r.get('runroot')==str(run) and r.get('image')==metadata['execution']['image'] and r['status']=='released']
                        if not matches:raise parallel_contract.ParallelError('Abandoned writer has no independently reconciled registry ownership')
                        proof.append({'container':desc['container'],'cleanup':'registry_matched_removed_and_absent','launch_id':matches[-1]['launch_id']})
                    application_credentials.recover(run)
                    return proof
                experiments.reconcile(root,metadata,matrix,lab,cleanup=cleanup_abandoned)
            halted=experiments.stop_from_history(root,metadata,matrix,previous)
            work=[] if halted else [c for c in matrix['cells'] if not experiments.attempt_intents(root,c)]
            if retry_trial:
                cell=next((c for c in matrix['cells'] if c['trial_id']==retry_trial),None)
                if cell is None:raise parallel_contract.ParallelError('Retry trial not in frozen matrix')
                attempts=experiments.attempt_intents(root,cell)
                if not attempts or len(attempts)>=metadata['policies']['max_attempts'] or experiments.sealed_result(root,attempts[-1])['status']=='PASS':
                    raise parallel_contract.ParallelError('Retry requires failed primary and remaining frozen attempts')
                work.insert(0,cell)
            if not work:return {'schema':2,'status':'halted' if halted else 'completed','planned':len(matrix['cells']),'completed_this_call':0,'exit_code':1 if halted else 0}
            endpoint=lab.load_endpoint(root/work[0]['endpoint']);upstream_key=lab.endpoint_secret(endpoint,args)
            credentials,authorities=app_admission(root,work,lab,args,endpoint,upstream_key)
            pool=Allocator(capacity['aggregate'],metadata['concurrency']['max_stages'],metadata['concurrency']['max_pending'])
            probe=pool.request('admission-probe',{'generation':registry.generation},capacity['worker'],30);pool.dispatch();pool.consume(probe.identity,probe.capability,probe.binding,probe.resources)
            image=lab.probe_image(args,metadata['execution']['image']);selected=lab.admit_image(image)
            if selected!=metadata['release_contracts'].get(selected['release']):raise parallel_contract.ParallelError('Observed release differs from frozen contract')
            pool.release(probe.identity,True,True);registry.close()
            for cell in work:
                agent_profiles.admit(agent_profiles.load(root/cell['agent_profile']),selected['release'])
                lab.pi_contract.model_configuration(lab.load_endpoint(root/cell['endpoint']),selected['release'])
            controls.atomic(root/'admission.json',{'schema':2,'image':image['id'],'release_contract':selected,'capacity':capacity,
                'scheduler':metadata['concurrency']['scheduler'],'scope':'Native image/resource admission only; not model qualification'})
            with gateway_owner(lab,args,root,metadata,work,registry,pool,capacity['worker'],upstream_key) as (inference,factory,cleanup):
                inference.update(credentials=credentials,authorities=authorities)
                result=parallel_engine.collect(root,metadata,matrix,work,lab,registry,pool,session,inference,factory,cleanup)
                if halted and result['status']=='completed':
                    current=experiments.controller_state(root);current['status']='halted';controls.atomic(root/'state.json',current)
                    result.update(status='halted',exit_code=1)
                return result
