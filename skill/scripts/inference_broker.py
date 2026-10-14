"""Shared bounded broker ownership. No caller receives an upstream credential."""
import contextlib
import copy
import json
from pathlib import Path
import shutil
import tempfile
import time
from urllib.request import urlopen
import uuid

import ownership_registry
import parallel_contract
import provenance
import stage_control as controls

@contextlib.contextmanager
def owner(lab,args,root,registry,pool,worker_resources,gateway_config,image_reference,limits,contract=None):
    contract=contract or {'gateway':limits,'scheduler':'indexed-inference-v1'};helper=limits['resources']
    item=pool.request('gateway',{'generation':registry.generation},helper,30,'helper');pool.dispatch()
    pool.consume(item.identity,item.capability,item.binding,item.resources)
    directory=Path(tempfile.mkdtemp(prefix='pi-parallel-gateway-')).resolve();name='pi-lab-gateway-'+uuid.uuid4().hex[:12]
    record=None;networks={};tokens=gateway_config['tokens']
    try:
        config=copy.deepcopy(args);config.cpus=helper['cpu_millis']/1000;config.memory=str(helper['memory_mib'])+'m';config.pids_limit=helper['pids_limit'];config.jobs=1
        config.profile='core';config.browser_sandbox_policy='docker-default';config.frozen_browser_security=None
        workspace=directory/'workspace';control=directory/'control';workspace.mkdir();control.mkdir()
        lab.control_channels(control,config.uid);state=lab.state_dir(directory/'state',str(uuid.uuid4()),config.uid)
        gateway_config=copy.deepcopy(gateway_config)
        gateway_config['limits']=limits
        if gateway_config.get('active_tokens_file'):
            gateway_config['active_tokens_file']='/opt/pi-control/active-tokens.json'
            controls.atomic(control/'active-tokens.json',{'tokens':[]})
        controls.atomic(control/'inference.json',gateway_config)
        image=lab.image_info(image_reference,args.platform)['id']
        argv=lab.docker_args(config,image,workspace,control,state,name,'bridge',helpers=lab.RUNTIME)
        argv=argv[:2]+['--detach','--publish','127.0.0.1::8080','--sysctl','net.ipv4.ip_forward=0']+argv[2:]+['gateway','--config','/opt/pi-control/inference.json']
        record,argv=registry.intent(argv,name,runroot=root)
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
                        'host_base_url':host+'/v1','token':next(token for token,binding in tokens.items() if binding==intent['trial_id'])}}
        inference['host_base_url']=host+'/v1';inference['base_url']='http://pi-inference:8080/v1'
        def admit():
            from indexed_contract import IndexedError
            try:observation=ownership_registry.read_private(record['gateway_state'])
            except (OSError,ValueError):raise IndexedError('inference-quarantined') from None
            if observation.get('launch_id')!=record['launch_id'] or observation.get('uncertain') is not False:raise IndexedError('inference-quarantined')
        inference['admit']=admit
        inference['activate']=lambda tokens:controls.atomic(control/'active-tokens.json',{'tokens':list(tokens)})
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
