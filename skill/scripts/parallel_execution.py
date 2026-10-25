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
    import inference_broker
    tokens={secrets.token_hex(32):cell['trial_id'] for cell in work}
    config={'endpoint':lab.load_endpoint(root/work[0]['endpoint']),'upstream_key':upstream_key,'tokens':tokens}
    cohort=getattr(registry,'_native_budget_cohort',None)
    if cohort is not None:config['active_tokens_file']=True
    with inference_broker.owner(lab,args,root,registry,pool,worker_resources,config,
                                metadata['execution']['image'],metadata['concurrency']['gateway'],metadata['concurrency']) as result:
        if cohort is not None:
            cohort.add_redaction_values([upstream_key])
            for token,trial in tokens.items():cohort.add_redaction_values([token],trial)
            inference=result[0];original=inference['trial'];active={}
            def trial(intent):
                inference['admit']()
                selected=original(intent);active[intent['trial_id']]=selected['token']
                inference['activate'](active.values())
                return selected
            def release(trial_id):
                active.pop(trial_id,None);inference['activate'](active.values())
            inference['trial']=trial;inference['stage_release']=release
        yield result


def registry_cleanup(registry,metadata):
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
    return cleanup_abandoned


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
            import parallel_native_budget
            cohort=parallel_native_budget.NativeCohort(root,metadata,matrix,matrix['cells'],lab,args,registry)
            lab.require_host(args)
            capacity=parallel_contract.admit_capacity(metadata['concurrency'],resources.requested_policy(args),lab.docker_info())
            if args.resource_report['effective']['runtime']!=args.resource_report['requested']['runtime']:
                raise parallel_contract.ParallelError('Frozen parallel workers cannot be clamped')
            if resume:
                experiments.reconcile(root,metadata,matrix,lab,cleanup=registry_cleanup(registry,metadata))
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
            # Cohort reads only frozen inputs. Restrict queue pairing to cells
            # that this invocation can actually launch (including explicitretry).
            cohort.native_trials.intersection_update(cell['trial_id'] for cell in work)
            pool=cohort.allocator(capacity['aggregate'],metadata['concurrency']['max_stages'],metadata['concurrency']['max_pending'])
            cohort.attach(pool);cohort.add_redaction_values([upstream_key])
            probe=pool.request('admission-probe',{'generation':registry.generation},capacity['worker'],30);pool.dispatch();pool.consume(probe.identity,probe.capability,probe.binding,probe.resources)
            image=lab.probe_image(args,metadata['execution']['image']);selected=lab.admit_image(image)
            if selected!=metadata['release_contracts'].get(selected['release']):raise parallel_contract.ParallelError('Observed release differs from frozen contract')
            cohort.admit_release(selected['release'])
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
