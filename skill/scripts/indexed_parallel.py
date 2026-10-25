"""Generation-2 indexed controllers; all authority checks stay in the parent."""
import copy
from pathlib import Path
import secrets

import application_credentials
import experiments
import indexed_contract as contract
from indexed_contract import IndexedError
import indexed_execution
import indexed_experiments
from inference_catalog import Catalog
import inference_broker
import parallel_engine
from parallel_allocator import Allocator
import provenance
import release_contracts
import resources
import parallel_contract
import parallel_native_budget
import stage_control as controls


class RemoteSession:
    def __init__(self,remote,bootstrap):
        self.remote=remote;self.bootstrap=bootstrap;data=bootstrap['indexed']
        self.bindings=data['bindings'];self.current=data['first_stage'];self.credentials=bootstrap['credentials']
        self.contract=data['contract'];self.token=data['tokens'][self.current]
        self.tokens=data['tokens'];self.redaction=list(self.tokens.values())
    @property
    def binding(self):return self.bindings[self.current]
    @property
    def original(self):return self.binding['configuration']['endpoint']
    def endpoint(self):
        return {**self.original,'base_url':self.bootstrap['inference']['base_url'],'host_base_url':self.bootstrap['inference']['host_base_url'],'api_key_env':'PI_INDEXED_INFERENCE'}
    def stage(self,name,args):
        reply=self.remote.call('indexed-stage',name=name);self.current=name;self.token=reply['token']
        self.redaction.append(self.token)
        args._indexed_binding=reply['identity'];return self.endpoint(),self.token
    def continuation(self,renew=False):
        reply=self.remote.call('indexed-stage',name=self.current,renew=renew);self.token=reply['token']
        self.redaction.append(self.token);return self.token
    def release_segment(self):self.remote.call('indexed-release',cleanup=True)


def execute(root,lab,session=None,resume=False,retry_trial=None):
    root=Path(root).resolve()
    with experiments.controller_lock(root):
        metadata,matrix=experiments.verify(root,lab);previous=experiments.controller_state(root)
        if metadata.get('mode')!='parallel':raise IndexedError('selection-conflict')
        if (metadata['runner_content_sha256']!=provenance.execution({}, {},lab.ROOT)['runner_content_sha256']
            or metadata['prepared_root']!=str(root.resolve()) or metadata['release_contracts']!=release_contracts.snapshot()):raise IndexedError('environment-configuration-changed')
        args=experiments.trial_args(root,metadata,matrix['cells'][0],lab,session);args._indexed_bindings=None
        with resources.admission_lock(args.lock_file,args.lock_wait_seconds) as registry:
            registry.command=lambda argv:lab.command(argv,timeout=15,required=False)
            registry.binding={'indexed_host_generation':2}
            if resume:
                import parallel_execution
                experiments.reconcile(root,metadata,matrix,lab,cleanup=parallel_execution.registry_cleanup(registry,metadata))
            if any(experiments.attempt_intents(root,c) for c in matrix['cells']) and not resume:raise IndexedError('selection-conflict')
            halted=experiments.stop_from_history(root,metadata,matrix,previous)
            work=[] if halted else [c for c in matrix['cells'] if not experiments.attempt_intents(root,c)]
            if retry_trial:
                cell=next((c for c in matrix['cells'] if c['trial_id']==retry_trial),None)
                if cell is None:raise IndexedError('selection-conflict')
                attempts=experiments.attempt_intents(root,cell)
                if not attempts or len(attempts)>=metadata['policies']['max_attempts'] or experiments.sealed_result(root,attempts[-1])['status']=='PASS':raise IndexedError('selection-conflict')
                work.insert(0,cell)
            if not work:return {'schema':3,'status':'halted' if halted else 'completed','exit_code':1 if halted else 0,'completed_this_call':0,'planned':len(matrix['cells'])}
            catalog=Catalog(lab.normalize_endpoint,metadata['catalog_root'],metadata['credential_store'])
            catalog.outside(lab.ROOT,root,*[root/c['source'] for c in work])
            bindings={c['trial_id']:experiments.read_json(root/c['inference_bindings']) for c in work}
            first_stages={c['trial_id']:experiments.read_json(root/c['plan'])['agents'][0]['name'] for c in work}
            entries={b['incarnation']:b for stages in bindings.values() for b in stages.values()}
            keys={i:catalog.admit(b,session) for i,b in entries.items()};assigned={};authorities={}
            contract.secret_free(list(entries.values()),keys.values())
            actor_values={}
            budgeted=False
            for cell in work:
                plan=indexed_experiments.frozen_plan(root,cell,lab)
                budgeted=indexed_execution.native_required(plan) or budgeted
                indexed_experiments.check_deadlines(plan,bindings[cell['trial_id']],metadata['indexed_execution'])
                unused,unused_keys,assigned[cell['trial_id']]=indexed_execution.resolve(catalog,bindings[cell['trial_id']],session,plan,root/cell['source'],root/'runs',lab)
                authorities[cell['trial_id']]=sorted({v for t in plan['agents'] for v in t.get('application_secrets',{}).values()})
                for task in plan['agents']:
                    for variable,ref in task.get('application_secrets',{}).items():
                        value=assigned[cell['trial_id']][task['name']][variable]
                        if value in actor_values and actor_values[value]!=ref:raise IndexedError('selection-conflict')
                        actor_values[value]=ref
                for i,b in entries.items():application_credentials.resolve(plan,b['configuration']['endpoint'],keys[i],catalog.store,root/cell['source'],root/'runs',False,forbidden_roots=[lab.ROOT,root])
                redactor=application_credentials.Redactor([*keys.values(),*actor_values])
                if redactor.contains(__import__('json').dumps(plan).encode()) or not application_credentials.workspace_inspected_clean(root/cell['source'],redactor):raise IndexedError('selection-conflict')
            if any(metadata['concurrency'].get(key)!=metadata['indexed_execution'].get(key)
                   for key in ('aggregate','gateway','native_budget')):raise IndexedError('selection-conflict')
            helper,worker=indexed_execution.capacity(args,lab,2,metadata['indexed_execution'],
                native=budgeted,concurrency=metadata['concurrency'])
            for i,b in entries.items():
                if any(b['configuration']['request_limits'][k]>helper['gateway'][k] for k in b['configuration']['request_limits']):raise IndexedError()
            per_trial={trial:[value for assigned_stage in assigned[trial].values() for value in assigned_stage.values()] for trial in assigned}
            cohort=parallel_native_budget.NativeCohort(root,metadata,matrix,work,lab,args,registry,
                redaction_values=list(keys.values()),per_trial_redaction=per_trial)
            cohort.native_trials.intersection_update(cell['trial_id'] for cell in work)
            pool=cohort.allocator(helper['aggregate'],metadata['concurrency']['max_stages'],metadata['concurrency']['max_pending'])
            cohort.attach(pool)
            probe=pool.request('admission-probe',{'generation':registry.generation},worker,30);pool.dispatch()
            pool.consume(probe.identity,probe.capability,probe.binding,probe.resources)
            image=lab.probe_image(args,metadata['execution']['image']);selected=lab.admit_image(image)
            if selected!=metadata['release_contracts'].get(selected['release']):raise IndexedError('environment-configuration-changed')
            cohort.admit_release(selected['release'])
            pool.release(probe.identity,True,True);registry.close()
            import agent_profiles
            for cell in work:
                agent_profiles.admit(agent_profiles.load(root/cell['agent_profile']),selected['release'])
            for entry in entries.values():lab.pi_contract.model_configuration(entry['configuration']['endpoint'],selected['release'])
            token_prefix=secrets.token_hex(16)
            tokens={trial:{name:[token_prefix+secrets.token_hex(16) for _ in range(100)] for name in stages} for trial,stages in bindings.items()}
            for trial,stages in tokens.items():
                values=[token for pool_tokens in stages.values() for token in pool_tokens]
                indexed_execution.bounded_redaction([*keys.values(),*per_trial[trial],*values])
                cohort.add_redaction_values(values,trial)
            routes={i:{'endpoint':b['configuration']['endpoint'],'upstream_key':keys[i],'limits':b['configuration']['request_limits']} for i,b in entries.items()}
            config={'routes':routes,'tokens':{token:{'route':bindings[trial][name]['incarnation']} for trial,stages in tokens.items() for name,pool_tokens in stages.items() for token in pool_tokens},'active_tokens_file':True,'token_prefix':token_prefix}
            active={};ordinals={(trial,name):0 for trial,stages in bindings.items() for name in stages}
            with inference_broker.owner(lab,args,root,registry,pool,worker,config,metadata['execution']['image'],helper['gateway']) as (inference,factory,cleanup):
                def stage(trial,name,renew=False):
                    if name not in bindings[trial]:raise IndexedError('selection-conflict')
                    inference['admit']()
                    binding=bindings[trial][name];catalog.admit(binding,session)
                    if type(renew) is not bool:raise IndexedError('selection-conflict')
                    if renew:ordinals[trial,name]+=1
                    if ordinals[trial,name]>=len(tokens[trial][name]):raise IndexedError('selection-conflict')
                    active[trial]=tokens[trial][name][ordinals[trial,name]];inference['activate'](active.values())
                    return {'token':active[trial],'identity':{'environment_incarnation':binding['incarnation'],'configuration':binding['fingerprint'],'authority_id':binding['authority_id'],'adapter':contract.ADAPTER}}
                def release(trial):active.pop(trial,None);inference['activate'](active.values())
                def bootstrap(cell,intent):
                    trial=cell['trial_id']
                    return {'first_stage':first_stages[trial],'bindings':bindings[trial],'tokens':{name:pool_tokens[0] for name,pool_tokens in tokens[trial].items()},'contract':helper}
                def first(intent):
                    trial=intent['trial_id'];name=first_stages[trial];stage(trial,name)
                    return {'base_url':inference['base_url'],'host_base_url':inference['host_base_url'],'token':tokens[trial][name][0]}
                private={'worker_resources':worker,'trial':first,'credentials':assigned,'authorities':authorities,
                    'admit':inference['admit'],'indexed':bootstrap,'stage_admission':stage,'stage_release':release,
                    'secret_variable_names':[b['configuration']['credential'].get('name') for b in entries.values() if b['configuration']['credential'].get('name')]}
                inference['control_deadline']=__import__('time').monotonic()+metadata['concurrency']['collection_timeout_seconds']
                result=parallel_engine.collect(root,metadata,matrix,work,lab,registry,pool,session,private,factory,cleanup)
                if halted and result['status']=='completed':
                    state=experiments.controller_state(root);state['status']='halted';controls.atomic(root/'state.json',state)
                    result.update(status='halted',exit_code=1)
                return result
