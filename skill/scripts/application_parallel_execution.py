"""Frozen two-trial application collection with parent-only private authority.

This controller admits all selected credentials before host work, then delegates
only bounded trial execution to the existing engine. It never resumes a report,
recreates an uncertain helper, or puts original authority in child bootstrap.
"""
import copy
import os
from pathlib import Path
import platform
import secrets
import time

import application_experiments
import application_execution
import application_preparation
import experiments
from inference_catalog import Catalog
import inference_broker
import indexed_contract
import indexed_execution
import parallel_contract
from parallel_contract import ParallelError
import parallel_engine
import parallel_execution
from parallel_application import ApplicationCohort
from parallel_native_budget import _read_owned
import provenance
import release_contracts
import resources
import stage_control as controls


def _pending_helpers(registry):
    if any(row.get('application_helper') is True and row.get('status')!='released' for row in registry.load()):
        raise ParallelError('Existing application helper cleanup requires independent confirmation')


def _recovery(registry,metadata):
    ordinary=parallel_execution.registry_cleanup(registry,metadata)
    def cleanup(root,intent,unused_metadata,lab):
        run=Path(root)/'runs'/intent['run_id'];records=registry.load()
        # A vanished child cannot attest helper/context purge. No generic
        # recreation or private-store purge is used to make it look confirmed.
        if (any(row.get('application_helper') is True and row.get('runroot')==str(run) for row in records)
                or any((run/'controls').glob('*/segments/*/application-context.json'))
                or any((run/'application-helpers').glob('*'))):
            raise ParallelError('Application attempt needs independent helper cleanup evidence')
        return ordinary(root,intent,unused_metadata,lab)
    return cleanup


def _work(root,metadata,matrix,previous,resume,retry_trial,*,before_reconcile=False):
    if any(experiments.attempt_intents(root,cell) for cell in matrix['cells']) and not resume:
        raise ParallelError('Existing application attempts require explicit resume')
    # Explicit resume reconciles unfinished parent results before interpreting
    # history. Pre-admit prospective work without treating partial JSON as a
    # sealed result or bypassing the final stop/retry checks after reconciliation.
    halted=False if before_reconcile else experiments.stop_from_history(root,metadata,matrix,previous)
    work=[] if halted else [cell for cell in matrix['cells'] if not experiments.attempt_intents(root,cell)]
    if retry_trial is not None:
        cell=next((cell for cell in matrix['cells'] if cell['trial_id']==retry_trial),None)
        if cell is None:raise ParallelError('Retry is outside the frozen application matrix')
        attempts=experiments.attempt_intents(root,cell)
        prior=experiments.sealed_result(root,attempts[-1]) if attempts and not before_reconcile else None
        if (not attempts or len(attempts)>=metadata['policies']['max_attempts']
                or prior is None and not (resume and before_reconcile)
                or prior is not None and prior['status']=='PASS'):raise ParallelError('Explicit retry requires a failed sealed primary and remaining bound')
        work.insert(0,cell)
    return work,halted


def _capacity(contract,policy,daemon,schema):
    selected=copy.deepcopy(contract)
    if schema==3:
        selected=indexed_contract.parallel(selected)
        selected.update(scheduler=parallel_contract.VERSION,host_generation=1)
    return parallel_contract.admit_capacity(selected,policy,daemon)


def _bounded(values):
    return indexed_execution.bounded_redaction(list(dict.fromkeys(value for value in values if value)))


def _legacy(root,work,specs):
    endpoints=[]
    for cell in work:
        plan=specs[cell['trial_id']]['plan'];records=_read_owned((root/cell['compiled_plan']).parent/'inference.json')['stages']
        if set(records)!={stage['id'] for stage in plan['stages']}:raise ParallelError('Incomplete frozen application inference mapping')
        for stage in plan['stages']:
            record=records[stage['id']]
            if record['kind']!='legacy':raise ParallelError('Mixed application inference owners')
            endpoints.append(record['configuration'])
    first=specs[work[0]['trial_id']]
    if any(endpoint!=first['endpoint'] for endpoint in endpoints):raise ParallelError('Legacy parallel application variants require one frozen upstream')
    if any(spec['inference_key']!=first['inference_key'] for spec in specs.values()):raise ParallelError('Legacy parallel original authorities differ')
    return first['inference_key']


def _indexed_inputs(root,metadata,work,specs,lab,session,corpus):
    catalog=Catalog(lab.normalize_endpoint,metadata['catalog_root'],metadata['credential_store'])
    catalog.outside(lab.ROOT,root,*[root/cell['source'] for cell in work])
    bindings={};entries={};keys={};first={};names={};refs=set()
    for cell in work:
        trial=cell['trial_id'];plan=specs[trial]['plan'];names[trial]=[stage['id'] for stage in plan['stages']]
        stages=_read_owned(root/cell['inference_bindings'])
        if set(stages)!=set(names[trial]):raise ParallelError('Frozen indexed stage map changed')
        bindings[trial]=stages;first[trial]=names[trial][0]
        for stage in plan['stages']:
            binding=stages[stage['id']];identity=binding['incarnation']
            if identity in entries and entries[identity]!=binding:raise ParallelError('Conflicting indexed incarnation in application matrix')
            entries[identity]=binding;value=catalog.admit(binding,session)
            expected=specs[trial]['inference_authorities'][stage['inference_binding']['configuration_sha256']]['value']
            if not secrets.compare_digest(value.encode(),expected.encode()):raise ParallelError('Indexed application authority changed before admission')
            keys[identity]=value
            limits=binding['configuration']['request_limits']
            if any(limits[key]>metadata['indexed_execution']['gateway'][key] for key in limits):raise ParallelError('Indexed route exceeds frozen gateway deadline')
            reference=binding['configuration']['credential'].get('name')
            if reference:refs.add(reference)
    indexed_contract.secret_free(list(entries.values()),keys.values())
    prefix=secrets.token_hex(16)
    tokens={trial:{stage:[prefix+secrets.token_hex(16) for _ in range(100)] for stage in ordered} for trial,ordered in names.items()}
    for trial,stages in tokens.items():_bounded([*corpus,*[token for pool in stages.values() for token in pool]])
    return catalog,bindings,entries,keys,first,tokens,prefix,refs


def _collect_indexed(root,metadata,matrix,work,lab,registry,pool,session,cohort,worker,prepared,authorities,refs):
    catalog,bindings,entries,keys,first,tokens,prefix,inference_refs=prepared
    for trial,stages in tokens.items():cohort.add_redaction_values([token for values in stages.values() for token in values],trial)
    routes={identity:{'endpoint':binding['configuration']['endpoint'],'upstream_key':keys[identity],
        'limits':binding['configuration']['request_limits']} for identity,binding in entries.items()}
    config={'routes':routes,'tokens':{token:{'route':bindings[trial][stage]['incarnation']} for trial,stages in tokens.items()
        for stage,values in stages.items() for token in values},'active_tokens_file':True,'token_prefix':prefix}
    active={};ordinals={(trial,stage):0 for trial,stages in bindings.items() for stage in stages}
    with inference_broker.owner(lab,cohort.args,root,registry,pool,worker,config,metadata['execution']['image'],
            metadata['indexed_execution']['gateway'],metadata['concurrency']) as (inference,factory,cleanup):
        def stage(trial,name,renew=False):
            if type(renew) is not bool or trial not in bindings or name not in bindings[trial]:raise ParallelError('Unknown indexed application stage')
            cohort.admit_inference_stage(trial,name,renew)
            inference['admit']();binding=bindings[trial][name];catalog.admit(binding,session)
            if renew:ordinals[trial,name]+=1
            if ordinals[trial,name]>=len(tokens[trial][name]):raise ParallelError('Indexed continuation token bound reached')
            active[trial]=tokens[trial][name][ordinals[trial,name]];inference['activate'](active.values())
            return {'token':active[trial],'identity':{'environment_incarnation':binding['incarnation'],
                'configuration':binding['fingerprint'],'authority_id':binding['authority_id'],'adapter':indexed_contract.ADAPTER}}
        def release(trial):active.pop(trial,None);inference['activate'](active.values())
        def bootstrap(cell,intent):
            trial=cell['trial_id']
            return {'first_stage':first[trial],'bindings':bindings[trial],
                'tokens':{name:values[0] for name,values in tokens[trial].items()},'contract':metadata['indexed_execution']}
        def initial(intent):
            trial=intent['trial_id'];selected=stage(trial,first[trial])
            return {'base_url':inference['base_url'],'host_base_url':inference['host_base_url'],'token':selected['token']}
        inference['control_deadline']=time.monotonic()+metadata['concurrency']['collection_timeout_seconds']
        private={'worker_resources':worker,'trial':initial,'credentials':{},'authorities':authorities,
            'admit':inference['admit'],'indexed':bootstrap,'stage_admission':stage,'stage_release':release,
            'secret_variable_names':sorted(refs|inference_refs)}
        return parallel_engine.collect(root,metadata,matrix,work,lab,registry,pool,session,private,factory,cleanup)


def execute(root,lab,session=None,resume=False,retry_trial=None):
    if type(resume) is not bool:raise ParallelError('Application resume must be explicit')
    root=Path(root).absolute()
    descriptor=application_preparation._directory(root);os.close(descriptor)
    with experiments.controller_lock(root):
        metadata,matrix=experiments.verify(root,lab);schema=metadata.get('schema')
        if (metadata.get('document_type')!='application_experiment' or type(schema) is not int or schema not in (2,3)
                or schema==2 and metadata.get('mode','parallel')!='parallel'
                or schema==3 and metadata.get('mode')!='parallel'):raise ParallelError('Explicit parallel application experiment required')
        if (metadata['runner_content_sha256']!=provenance.execution({}, {},lab.ROOT)['runner_content_sha256']
                or metadata['release_contracts']!=release_contracts.snapshot() or metadata['prepared_root']!=str(root)):
            raise ParallelError('Frozen application source/runtime identity changed')
        previous=experiments.controller_state(root)
        # Repeated cells require explicit resume even before opening host leases.
        if any(experiments.attempt_intents(root,cell) for cell in matrix['cells']) and not resume:
            raise ParallelError('Existing application attempts require explicit resume')
        work,halted=_work(root,metadata,matrix,previous,resume,retry_trial,before_reconcile=resume)
        if not work and not resume:return {'schema':schema,'status':'halted' if halted else 'completed','planned':len(matrix['cells']),'completed_this_call':0,'exit_code':1 if halted else 0}
        if any(cell.get('compiled_plan')!=cell.get('plan') for cell in work):raise ParallelError('Application dispatch must use exact final IR artifact')
        private=application_experiments.admit_work(root,metadata,work,lab,session)
        if type(private) is not dict or set(private)!={'authorities_by_trial','keys','redaction_values'}:raise ParallelError('Private application admission unavailable')
        specs=private['authorities_by_trial'];corpus=_bounded(private['redaction_values'])
        if set(specs)!={cell['trial_id'] for cell in work}:raise ParallelError('Incomplete private application admission')
        args=experiments.trial_args(root,metadata,(work or matrix['cells'])[0],lab,session)
        policy=resources.validate_policy(_read_owned(root/'inputs/resources.json'))
        args.image=metadata['execution']['image'];args.platform=metadata['execution']['platform'];args.profile=metadata['execution']['profile']
        args.browser_sandbox_policy=metadata['execution']['browser_sandbox_policy'];args.network='bridge';args._resource_request=copy.deepcopy(policy)
        args.uid,args.gid=os.getuid(),os.getgid()
        if args.uid==0 or args.platform!='linux/arm64' or lab.norm_arch(platform.machine())!='arm64':
            raise ParallelError('Application collection requires an unprivileged native ARM64 owner')
        refs={reference for spec in specs.values() for reference in spec['plan']['application']['credentials'].values()}
        prepared=None
        if schema==3 and work:
            if any(metadata['concurrency'].get(key)!=metadata['indexed_execution'].get(key) for key in ('aggregate','gateway','native_budget')):
                raise ParallelError('Application indexed helper/concurrency contracts differ')
            prepared=_indexed_inputs(root,metadata,work,specs,lab,session,corpus)
        elif work:
            key=_legacy(root,work,specs)
            refs.update(spec['endpoint']['api_key_env'] for spec in specs.values())
            nonce=next(format(number,'064x') for number in range(1025) if format(number,'064x') not in corpus)
            _bounded([*corpus,nonce])  # One same-size delegated token per trial.
        with resources.admission_lock(args.lock_file,args.lock_wait_seconds) as registry:
            registry.command=lambda argv:lab.command(argv,timeout=15,required=False)
            if schema==3:registry.binding={**registry.binding,'indexed_host_generation':2}
            _pending_helpers(registry)
            if resume:
                experiments.reconcile(root,metadata,matrix,lab,cleanup=_recovery(registry,metadata))
                work,halted=_work(root,metadata,matrix,experiments.controller_state(root),True,retry_trial)
                if not work:return {'schema':schema,'status':'halted' if halted else 'completed','planned':len(matrix['cells']),'completed_this_call':0,'exit_code':1 if halted else 0}
                if set(cell['trial_id'] for cell in work)!=set(specs):raise ParallelError('Reconciled work changed; explicit fresh admission required')
            cohort=ApplicationCohort(root,metadata,matrix,work,lab,args,registry,authorities_by_trial=specs,
                redaction_values=corpus,per_trial_redaction={trial:[] for trial in specs})
            lab.require_host(args)
            if not application_execution._same_policy(args.resource_report['effective'],policy):raise ParallelError('Frozen application resources cannot be clamped')
            capacity=_capacity(metadata['concurrency'],policy,lab.docker_info(),schema)
            pool=cohort.allocator(capacity['aggregate'],metadata['concurrency']['max_stages'],metadata['concurrency']['max_pending']);cohort.attach(pool)
            if prepared is not None:
                for trial,stages in prepared[5].items():cohort.add_redaction_values([token for values in stages.values() for token in values],trial)
            probe=pool.request('admission-probe',{'generation':registry.generation},capacity['worker'],30)
            pool.dispatch();pool.consume(probe.identity,probe.capability,probe.binding,probe.resources)
            image=lab.probe_image(args,args.image);selected=lab.admit_image(image)
            if (image['id']!=args.image or image['platform']!='linux/arm64'
                    or selected!=metadata['release_contracts'].get(selected['release'])):raise ParallelError('Observed application runtime differs')
            cohort.admit_release(selected['release']);args.observed_pi_version=selected['release'];args.release_contract=selected
            pool.release(probe.identity,True,True);registry.close()
            for trial,spec in specs.items():
                for stage in spec['plan']['stages']:
                    if schema==3:configuration=prepared[1][trial][stage['id']]['configuration']['endpoint']
                    else:configuration=spec['endpoint']
                    lab.pi_contract.model_configuration(configuration,selected['release'])
            authorities={trial:cohort.authorities(trial) for trial in specs}
            controls.atomic(root/'admission.json',{'schema':schema,'image':image['id'],'release_contract':selected,'capacity':capacity,
                'scheduler':metadata['concurrency']['scheduler'],'scope':'Native resource/image admission; model and browser qualification remain separate'})
            if schema==3:
                result=_collect_indexed(root,metadata,matrix,work,lab,registry,pool,session,cohort,capacity['worker'],prepared,authorities,refs)
            else:
                with parallel_execution.gateway_owner(lab,args,root,metadata,work,registry,pool,capacity['worker'],key) as (inference,factory,cleanup):
                    inference.update(credentials={},authorities=authorities,secret_variable_names=sorted(refs))
                    result=parallel_engine.collect(root,metadata,matrix,work,lab,registry,pool,session,inference,factory,cleanup)
            result['schema']=schema
            if halted and result['status']=='completed':
                state=experiments.controller_state(root);state['status']='halted';controls.atomic(root/'state.json',state)
                result.update(status='halted',exit_code=1)
            return result
