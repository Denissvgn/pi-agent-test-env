"""Explicit indexed suite admission; upstream credentials stay in the broker."""
import contextlib
import copy
import math
import os
from pathlib import Path
import secrets
import json

import application_credentials
import indexed_contract as contract
from indexed_contract import IndexedError
from inference_catalog import Catalog
import inference_broker
from parallel_allocator import Allocator
import parallel_contract
import ownership_registry
import native_budget_controls
import application_contracts as application_contract
import resources
import secret_store
import stage_control as controls


def native_required(plan):
    required=False
    for task in (plan or {}).get('agents',[]):
        if native_budget_controls.NATIVE_FIELDS.intersection(task):
            native_budget_controls.native_limits({key:task[key] for key in native_budget_controls.NATIVE_FIELDS if key in task},
                                                timeout_seconds=task['timeout_seconds'],required=True)
            required=True
    return required


def bounded_redaction(values):
    if type(values) not in (list,tuple) or len(values)>1024 or any(type(value) is not str or len(value.encode())>16384 for value in values):
        raise IndexedError('selection-conflict')
    values=list(dict.fromkeys(value for value in values if value))
    if len(json.dumps(values,ensure_ascii=False).encode())>2*1024*1024:raise IndexedError('selection-conflict')
    return values


def _requested_policy(args,lab):
    if getattr(args,'_indexed_application',False) is True and getattr(args,'_resource_request',None) is not None:
        return resources.validate_policy(copy.deepcopy(args._resource_request))
    return lab.requested_policy(args)


def capacity(args,lab,workers=1,contract_value=None,*,native=False,concurrency=None,native_resources=None):
    if type(native) is not bool:raise IndexedError('selection-conflict')
    if native_resources is not None and not native:raise IndexedError('selection-conflict')
    expected_native=contract.native_helper_contract(native_resources)['resources'] if native else None
    if contract_value is not None:
        frozen=contract.helper_contract(contract_value)
        if native and 'native_budget' not in frozen:raise IndexedError('selection-conflict')
    policy=_requested_policy(args,lab)
    worker=parallel_contract.worker_weight(policy)
    if contract_value is None:
        helper={'cpu_millis':250,'memory_mib':128,'pids_limit':64}
        value={'contract':contract.EXECUTION,'host_generation':2,'max_workers':workers,
            'aggregate':{k:workers*worker[k]+helper[k] for k in worker},
            'gateway':{'resources':helper,'max_inflight':1,'max_pending':4,'queue_wait_seconds':180,'request_timeout_seconds':180}}
        if native:
            value['native_budget']=contract.native_helper_contract(expected_native)
            for key in worker:value['aggregate'][key]+=workers*value['native_budget']['resources'][key]
    else:value=frozen
    if value['max_workers']!=workers:raise IndexedError('selection-conflict')
    aggregate=value['aggregate'];helper=value['gateway']['resources'];budget=policy['host_budget']
    native_weight=parallel_contract.native_helper(value)
    if native and native_weight!=expected_native:raise IndexedError('selection-conflict')
    if native_weight is not None and args.platform!='linux/arm64':raise IndexedError('selection-conflict')
    if any(workers*(worker[k]+(native_weight[k] if native_weight else 0))+helper[k]>aggregate[k] for k in aggregate):
        raise IndexedError('selection-conflict')
    lab.require_host(args);daemon=lab.docker_info()
    if args.platform!=args.native_platform:raise IndexedError('selection-conflict')
    if args.resource_report['effective']['runtime']!=args.resource_report['requested']['runtime']:raise IndexedError('selection-conflict')
    if (aggregate['cpu_millis']>math.floor(daemon['NCPU']*budget['cpu_fraction']*1000)
        or aggregate['memory_mib']>math.floor(daemon['MemTotal']*budget['memory_fraction']/(1024**2))
        or any(workers*(worker[k]+(native_weight[k] if native_weight else 0))+helper[k]>aggregate[k] for k in aggregate)):
        raise IndexedError('selection-conflict')
    if workers==2:
        selected=contract.parallel(concurrency) if concurrency is not None else {
            'scheduler':contract.SCHEDULER,'host_generation':2,'registry_aware_cohort':True,
            'max_trials':2,'max_stages':2,'max_pending':16,'queue_wait_seconds':3600,
            'collection_timeout_seconds':14400,'aggregate':aggregate,'gateway':value['gateway']}
        if concurrency is None and native_weight is not None:selected['native_budget']=value['native_budget']
        if any(selected.get(key)!=value.get(key) for key in ('aggregate','gateway','native_budget')):raise IndexedError('selection-conflict')
        converted={**selected,'scheduler':parallel_contract.VERSION,'host_generation':1}
        try:parallel_contract.admit_capacity(converted,policy,daemon)
        except ValueError:raise IndexedError('selection-conflict') from None
    return value,worker


class Session:
    def __init__(self,catalog,bindings,session,inference,tokens,credentials,original_keys,contract_value):
        self.catalog=catalog;self.bindings=bindings;self.session=session
        self.inference=inference;self.tokens=tokens;self.credentials=credentials;self.original_keys=original_keys
        self.contract=contract_value;self.current=next(iter(bindings));self.token=tokens[self.current][0];self.ordinals={name:0 for name in bindings}
        self.native_budget_support=None;self._native_owner=None
        self._native_stage=None
        self._native_used=set()
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

    def bind_native_stage(self,desc):
        """Lend the held worker only under its current host lease and clean history."""
        owner=self._native_owner
        if owner is None or parallel_contract.native_helper(self.contract) is None:raise IndexedError('selection-conflict')
        registry=owner['registry'];row=owner['reservation'];pool=owner['pool'];root=owner['runroot']
        self.native_budget_support=None
        if (ownership_registry.CURRENT.get() is not registry or pool.closed
            or pool.records.get(row.identity) is not row or row.state not in ('launching','running')
            or row.resources!=owner['resources'] or row.binding.get('generation')!=registry.generation
            or any(key not in row.binding or row.binding[key]!=owner[key] for key in ('run_id','attempt_id','trial_id'))
            or row.binding.get('workspace')!=str(root/'workspace')
            or row.binding.get('stage_id')!=self._native_stage
            or any(desc.get(key)!=owner[key] for key in ('run_id','attempt_id'))
            or not controls.valid_id(desc.get('stage_id')) or desc.get('kind')!='agent'
            or desc.get('stage_id') in self._native_used
            or desc.get('workspace')!=str(root/'workspace')
            or controls.read(root/'stages'/desc['stage_id']/'descriptor.json')!=desc):
            raise IndexedError('selection-conflict')
        physical,sensitive=dependent_cleanup(registry,root,pending_native_stage=desc['stage_id'])
        if not physical or not sensitive:raise IndexedError('inference-quarantined')
        network=registered_network(registry,owner['network'])
        row.binding={**row.binding,'generation':registry.generation,'run_id':owner['run_id'],
            'attempt_id':owner['attempt_id'],'trial_id':owner['trial_id'],'stage_id':desc['stage_id'],'workspace':str(root/'workspace')}
        self.native_budget_support={'pool':pool,'reservation':row,'registry':registry,'network_record':network}
        self._native_stage=desc['stage_id']
        self._native_used.add(desc['stage_id'])
        return self.native_budget_support


def registered_network(registry,name):
    found=[row for row in registry.load() if row.get('kind')=='network' and row.get('container')==name
        and row.get('generation')==registry.generation and row.get('registry')==registry.registry_id
        and row.get('daemon')==registry.daemon and row.get('status') in ('intent','running')]
    if len(found)!=1:raise IndexedError('inference-quarantined')
    return copy.deepcopy(found[0])


def dependent_cleanup(registry,root,*,pending_native_stage=None):
    """Parent records only; child acknowledgments cannot release the footprint."""
    records=[row for row in registry.load() if row.get('runroot')==str(root)
             and not row.get('gateway_state') and row.get('kind')!='network']
    physical=all(row.get('status') in ('absent','released') for row in records)
    sensitive=all(not row.get('application_helper') or row.get('status')=='released' for row in records)
    sensitive=sensitive and all(controls.read(path).get('status')=='removed'
        for path in (Path(root)/'stages').glob('*/application-credentials.json'))
    # Successful coordinator cleanup removes these parent capability files.
    # A surviving file or replaced path keeps the shared footprint quarantined.
    sensitive=sensitive and not any((Path(root)/'controls').glob('*/segments/*/native-budget-context.json'))
    for descriptor in (Path(root)/'stages').glob('*/descriptor.json'):
        desc=controls.read(descriptor)
        if (desc.get('stage_id')==pending_native_stage
                or not native_budget_controls.NATIVE_FIELDS.intersection(desc.get('original_limits',{}))):continue
        # An exact filename glob cannot prove that a private capability was
        # purged: inode/path replacement or rename can hide the expected name.
        # Require the retained stage-level cleanup result from its coordinator.
        label=desc.get('label')
        if type(label) is not str or label in ('','.','..') or Path(label).name!=label:
            sensitive=False;continue
        try:process=controls.read(Path(root)/label/'process.json')
        except (OSError,ValueError):sensitive=False;continue
        receipt=process.get('native_tool_budget_cleanup')
        if (process.get('cleanup_confirmed') is not True or process.get('native_tool_budget_error') is not None
                or type(receipt) is not dict or receipt.get('safe_to_continue') is not True):sensitive=False
    return physical,sensitive


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


def application_admission_view(args,lab,frozen):
    """Pure exact IR/catalog binding admission; never a dispatch translation."""
    try:
        if getattr(args,'_indexed_application',None) is not True or type(frozen) is not dict:
            raise IndexedError('selection-conflict')
        final=application_contract.validate_ir(args._application_plan)
        runtime=final['runtime'];names=[stage['id'] for stage in final['stages']]
        if set(frozen)!=set(names):raise IndexedError('selection-conflict')
        from application_execution import _same_policy
        if (args.image!=runtime['image_id'] or args.platform!=runtime['platform']
                or args.profile!=runtime['container_profile']
                or getattr(args,'browser_sandbox_policy',None)!=(runtime['browser_sandbox_policy'] or 'docker-default')
                or not _same_policy(_requested_policy(args,lab),runtime['resources'])):
            raise IndexedError('selection-conflict')
        agents=[]
        for stage in final['stages']:
            binding=copy.deepcopy(frozen[stage['id']]);authority=binding.pop('authority_id',None)
            contract.identity(authority);entry=contract.entry(binding,lab.normalize_endpoint)
            selected=stage['inference_binding'];configuration=entry['configuration'];endpoint=configuration['endpoint']
            if runtime['inference_owner']=='experiment_variant':
                import application_variants
                context=getattr(args,'_application_variant_context',None)
                if type(context) is not dict or 'variant_id' not in context:raise IndexedError('selection-conflict')
                expected_selection=application_variants.variant_selection(context['variant_id'],'indexed',entry)
            else:expected_selection={'owner':'compiler_input','id':entry['id']}
            if (selected['kind']!='indexed' or selected['selection']['owner']!=runtime['inference_owner']
                    or selected['selection']!=expected_selection
                    or selected['configuration_sha256']!=application_contract.digest(configuration)
                    or selected['context_window']!=endpoint['context_window']
                    or selected['max_tokens']!=endpoint['max_tokens']
                    or selected['input_modalities']!=endpoint.get('input',['text'])):
                raise IndexedError('selection-conflict')
            agents.append({'name':stage['id'],'tools':list(stage['tools']),**copy.deepcopy(stage['limits']),
                'application_secrets':{'PI_APP_ALIAS_'+str(number):final['application']['credentials'][alias]
                    for number,alias in enumerate(stage['credential_aliases'])}})
        # resolve() screens the entire final IR for literal authorities as well
        # as resolving only stage-assigned references from this internal view.
        return {'agents':agents,'application_plan':final},names
    except (ValueError,TypeError,KeyError,AttributeError):
        raise IndexedError('selection-conflict') from None


@contextlib.contextmanager
def admission(lab,args,attempt,registry,smoke=False):
    if getattr(args,'in_place',False) or getattr(args,'endpoint',None) is not None or args.network!='bridge' or args.uid!=os.getuid() or args.gid!=os.getgid():
        raise IndexedError('selection-conflict')
    catalog=Catalog(lab.normalize_endpoint,getattr(args,'catalog_dir',None),getattr(args,'secrets_dir',None))
    project=getattr(args,'project',None)
    catalog.outside(lab.ROOT,project,attempt.root)
    frozen=getattr(args,'_indexed_bindings',None)
    application=getattr(args,'_indexed_application',False)
    if application is not False or getattr(args,'_application_plan',None) is not None:
        if application is not True or smoke or args.op in ('preflight','doctor','env'):
            raise IndexedError('selection-conflict')
        plan,names=application_admission_view(args,lab,frozen)
        frozen=copy.deepcopy(frozen)
    elif args.op in ('preflight','doctor','env'):names=['preflight'];plan=None
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
    budgeted=native_required(plan)
    extra={}
    if application:
        from application_client import API_RESOURCES,BROWSER_RESOURCES
        extra['native_resources']=BROWSER_RESOURCES if plan['application_plan']['application']['browser_targets'] else API_RESOURCES
    contract_value,worker=capacity(args,lab,contract_value=getattr(args,'_indexed_contract',None),native=budgeted,**extra)
    maximum={'queue_wait_seconds':max(e['configuration']['request_limits']['queue_wait_seconds'] for e in selected_entries.values()),
             'request_timeout_seconds':max(e['configuration']['request_limits']['request_timeout_seconds'] for e in selected_entries.values())}
    if getattr(args,'_indexed_contract',None):
        if any(maximum[k]>contract_value['gateway'][k] for k in maximum):raise IndexedError('selection-conflict')
    else:contract_value['gateway'].update(maximum)
    if plan and any(sum(bindings[t['name']]['configuration']['request_limits'].values())>=t['timeout_seconds'] for t in plan['agents']):raise IndexedError('selection-conflict')
    controls.atomic(attempt.root/'inference-bindings.json',bindings)
    controls.atomic(attempt.root/'indexed-contract.json',contract_value)
    pool=Allocator(contract_value['aggregate']);token_prefix=secrets.token_hex(16);tokens={name:[token_prefix+secrets.token_hex(16) for _ in range(100)] for name in names}
    if budgeted:bounded_redaction([*all_keys,*[token for values in tokens.values() for token in values],
                                  *[value for assignment in credentials.values() for value in assignment.values()]])
    worker_binding={'run_id':attempt.record['run_id']}
    if budgeted:worker_binding.update(generation=registry.generation,attempt_id=attempt.record['attempt_id'],
        trial_id=attempt.record.get('trial_id'),workspace=str(Path(attempt.root)/'workspace'))
    reservation=pool.request('indexed-worker',worker_binding,worker,30)
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
        if budgeted:
            registered_network(registry,network)
            context._native_owner={'pool':pool,'reservation':reservation,'registry':registry,'network':network,
                'runroot':Path(attempt.root),'run_id':attempt.record['run_id'],'attempt_id':attempt.record['attempt_id'],
                'trial_id':attempt.record.get('trial_id'),'resources':copy.deepcopy(worker)}
            pool.dependent_cleanup_confirmed=False
        args._indexed_session=context
        try:
            context.stage(names[0],args)
            yield context
        finally:
            try:
                inference['activate']([])
                physical,sensitive=dependent_cleanup(registry,attempt.root)
                if budgeted:pool.dependent_cleanup_confirmed=physical and sensitive
                if not pool.release('indexed-worker',physical,sensitive):raise IndexedError('inference-quarantined')
                cleanup(network)
            except BaseException:
                if budgeted:
                    pool.dependent_cleanup_confirmed=False
                    if reservation.state in ('reserved','launching','running','stopping'):
                        pool.release('indexed-worker',False,False)
                raise
            finally:
                args.network=old_network;args._indexed_session=None;context.native_budget_support=None
