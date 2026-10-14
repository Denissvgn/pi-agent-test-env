"""Explicit indexed suite admission; upstream credentials stay in the broker."""
import contextlib
import copy
import math
import os
from pathlib import Path
import secrets

import application_credentials
import indexed_contract as contract
from indexed_contract import IndexedError
from inference_catalog import Catalog
import inference_broker
from parallel_allocator import Allocator
import parallel_contract
import secret_store
import stage_control as controls


def capacity(args,lab,workers=1,contract_value=None):
    policy=lab.requested_policy(args);lab.require_host(args);daemon=lab.docker_info()
    if args.platform!=args.native_platform:raise IndexedError('selection-conflict')
    if args.resource_report['effective']['runtime']!=args.resource_report['requested']['runtime']:raise IndexedError('selection-conflict')
    worker=parallel_contract.worker_weight(policy)
    if contract_value is None:
        helper={'cpu_millis':250,'memory_mib':128,'pids_limit':64}
        value={'contract':contract.EXECUTION,'host_generation':2,'max_workers':workers,
            'aggregate':{k:workers*worker[k]+helper[k] for k in worker},
            'gateway':{'resources':helper,'max_inflight':1,'max_pending':4,'queue_wait_seconds':180,'request_timeout_seconds':180}}
    else:value=contract.helper_contract(contract_value)
    if value['max_workers']!=workers:raise IndexedError('selection-conflict')
    aggregate=value['aggregate'];helper=value['gateway']['resources'];budget=policy['host_budget']
    if (aggregate['cpu_millis']>math.floor(daemon['NCPU']*budget['cpu_fraction']*1000)
        or aggregate['memory_mib']>math.floor(daemon['MemTotal']*budget['memory_fraction']/(1024**2))
        or any(workers*worker[k]+helper[k]>aggregate[k] for k in aggregate)):
        raise IndexedError('selection-conflict')
    return value,worker


class Session:
    def __init__(self,catalog,bindings,session,inference,tokens,credentials,original_keys,contract_value):
        self.catalog=catalog;self.bindings=bindings;self.session=session
        self.inference=inference;self.tokens=tokens;self.credentials=credentials;self.original_keys=original_keys
        self.contract=contract_value;self.current=next(iter(bindings));self.token=tokens[self.current][0];self.ordinals={name:0 for name in bindings}
    @property
    def binding(self):return self.bindings[self.current]
    @property
    def original(self):return self.binding['configuration']['endpoint']
    @property
    def redaction(self):return [*self.original_keys,*[token for pool in self.tokens.values() for token in pool],*[v for assigned in self.credentials.values() for v in assigned.values()]]
    def endpoint(self):
        return {**self.original,'base_url':self.inference['base_url'],'host_base_url':self.inference['host_base_url'],'api_key_env':'PI_INDEXED_INFERENCE'}
    def stage(self,name,args):
        if name not in self.tokens:raise IndexedError('selection-conflict')
        if self.inference.get('admit'):self.inference['admit']()
        self.catalog.admit(self.bindings[name],self.session);self.current=name
        self.token=self.tokens[name][0];self.inference['activate']([self.token])
        args._indexed_binding={'environment_incarnation':self.binding['incarnation'],'configuration':self.binding['fingerprint'],
            'authority_id':self.binding['authority_id'],'adapter':contract.ADAPTER}
        return self.endpoint(),self.token
    def continuation(self,renew=False):
        if self.inference.get('admit'):self.inference['admit']()
        self.catalog.admit(self.binding,self.session)
        if renew:self.ordinals[self.current]+=1
        if self.ordinals[self.current]>=len(self.tokens[self.current]):raise IndexedError('selection-conflict')
        self.token=self.tokens[self.current][self.ordinals[self.current]]
        self.inference['activate']([self.token]);return self.token
    def release_segment(self):self.inference['activate']([])


def resolve(catalog,bindings,session,plan,project,runroot,lab):
    selected={b['incarnation']:b for b in bindings.values()}
    if len(selected)>contract.MAX_SELECTED:raise IndexedError()
    keys={name:catalog.admit(binding,session) for name,binding in selected.items()};credentials={}
    contract.secret_free(list(selected.values()),keys.values())
    if plan and project:
        for name,binding in selected.items():
            credentials=application_credentials.resolve(plan,binding['configuration']['endpoint'],keys[name],catalog.store,
                Path(project),runroot,False,forbidden_roots=[lab.ROOT])
    return selected,keys,credentials


@contextlib.contextmanager
def admission(lab,args,attempt,registry,smoke=False):
    if getattr(args,'in_place',False) or getattr(args,'endpoint',None) is not None or args.network!='bridge' or args.uid!=os.getuid() or args.gid!=os.getgid():
        raise IndexedError('selection-conflict')
    catalog=Catalog(lab.normalize_endpoint,getattr(args,'catalog_dir',None),getattr(args,'secrets_dir',None))
    project=getattr(args,'project',None)
    catalog.outside(lab.ROOT,project,attempt.root)
    frozen=getattr(args,'_indexed_bindings',None)
    binding=next(iter(frozen.values())) if frozen else None
    if args.op in ('preflight','doctor','env'):names=['preflight'];plan=None
    elif smoke:names=['smoke-agent'];plan=None
    else:
        import agent_profiles
        profile=agent_profiles.load(args.agent_profile) if getattr(args,'agent_profile',None) else agent_profiles.builtin()
        planpath=Path(args.plan);plan=lab.validate_plan(controls.read(planpath),planpath.parent,profile,external_bindings=bool(frozen))
        names=[t['name'] for t in plan['agents']]
    if frozen and set(frozen)!=set(names):raise IndexedError('selection-conflict')
    if plan and plan.get('schema')==2 and plan['inference_bindings']!='external':
        if frozen or not getattr(args,'_indexed_plan_selection',False):raise IndexedError('selection-conflict')
        bindings={name:catalog.freeze(identifier,args.session) for name,identifier in plan['inference_bindings'].items()}
    elif frozen:bindings=frozen
    else:
        binding=catalog.freeze(getattr(args,'inference_env',None),args.session);bindings={name:binding for name in names}
    registry.binding={**registry.binding,'indexed_host_generation':2}
    selected_entries,keys,credentials=resolve(catalog,bindings,args.session,plan,project,attempt.root,lab)
    additional=getattr(args,'_indexed_redaction_keys',[])
    all_keys=[*keys.values(),*additional]
    contract.secret_free(list(bindings.values()),all_keys)
    if any(value in all_keys for assigned in credentials.values() for value in assigned.values()):raise application_credentials.CredentialError('Application credentials match a selected inference authority')
    contract_value,worker=capacity(args,lab,contract_value=getattr(args,'_indexed_contract',None))
    maximum={'queue_wait_seconds':max(e['configuration']['request_limits']['queue_wait_seconds'] for e in selected_entries.values()),
             'request_timeout_seconds':max(e['configuration']['request_limits']['request_timeout_seconds'] for e in selected_entries.values())}
    if getattr(args,'_indexed_contract',None):
        if any(maximum[k]>contract_value['gateway'][k] for k in maximum):raise IndexedError('selection-conflict')
    else:contract_value['gateway'].update(maximum)
    if plan and any(sum(bindings[t['name']]['configuration']['request_limits'].values())>=t['timeout_seconds'] for t in plan['agents']):raise IndexedError('selection-conflict')
    controls.atomic(attempt.root/'inference-bindings.json',bindings)
    controls.atomic(attempt.root/'indexed-contract.json',contract_value)
    pool=Allocator(contract_value['aggregate']);token_prefix=secrets.token_hex(16);tokens={name:[token_prefix+secrets.token_hex(16) for _ in range(100)] for name in names}
    reservation=pool.request('indexed-worker',{'run_id':attempt.record['run_id']},worker,30)
    pool.dispatch();pool.consume(reservation.identity,reservation.capability,reservation.binding,reservation.resources)
    routes={name:{'endpoint':e['configuration']['endpoint'],'upstream_key':keys[name],
                  'limits':e['configuration']['request_limits']} for name,e in selected_entries.items()}
    config={'routes':routes,'tokens':{token:{'route':bindings[name]['incarnation']} for name,pool_tokens in tokens.items() for token in pool_tokens},'active_tokens_file':True,'token_prefix':token_prefix,'redaction_keys':additional}
    old_network=args.network
    with inference_broker.owner(lab,args,attempt.root,registry,pool,worker,config,args.image,contract_value['gateway']) as (inference,factory,cleanup):
        network=factory({'trial_id':attempt.record['run_id']})
        args.network=network;args.host_gateway=True
        local={'base_url':'http://pi-inference:8080/v1','host_base_url':inference['host_base_url'],'activate':inference['activate'],'admit':inference['admit']}
        context=Session(catalog,bindings,args.session,local,tokens,credentials,all_keys,contract_value)
        args._indexed_session=context;context.stage(names[0],args)
        try:yield context
        finally:
            inference['activate']([]);cleanup(network);args.network=old_network;args._indexed_session=None
            records=[r for r in registry.load() if r.get('runroot')==str(attempt.root) and not r.get('gateway_state') and r.get('kind')!='network']
            physical=all(r['status'] in ('absent','released') for r in records)
            sensitive=all(controls.read(path).get('status')=='removed' for path in (attempt.root/'stages').glob('*/application-credentials.json'))
            if not pool.release('indexed-worker',physical,sensitive):raise IndexedError('inference-quarantined')
