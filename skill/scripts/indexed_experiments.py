"""Schema-3 input compilation. Legacy schemas never gain indexed fields."""
import copy
import json
from pathlib import Path
import tempfile

import indexed_contract as contract
from indexed_contract import IndexedError
from inference_catalog import Catalog
import stage_control as controls

PARALLEL_ENABLED=True
STAGE_MAPS_ENABLED=True


def frozen_plan(root,cell,lab):
    """Validate effective frozen tools with the exact selected child profile."""
    import agent_profiles,experiments
    root=Path(root);path=root/cell['plan'];profile=agent_profiles.load(root/cell['agent_profile'])
    return lab.validate_plan(experiments.read_json(path),path.parent,profile,external_bindings=True)


def check_deadlines(plan,bindings,helper):
    for task in plan['agents']:
        limits=bindings[task['name']]['configuration']['request_limits']
        if sum(limits.values())>=task['timeout_seconds'] or any(limits[k]>helper['gateway'][k] for k in limits):
            raise IndexedError('selection-conflict')


def cell_digest(root,metadata,cell,bindings):
    import provenance
    return provenance.digest({'schema':3,'source':metadata['source_receipts'][cell['case']],
        'scorer':cell['scorer_identity'],'plan':cell['plan_sha256'],'bindings':bindings,
        'execution':metadata['execution'],'indexed_execution':metadata['indexed_execution'],
        'concurrency':metadata.get('concurrency'),'policies':metadata['policies'],'budgets':cell['budgets'],
        'agent_profile':cell['agent_profile_sha256'],'runner':metadata['runner_content_sha256'],
        'resources':controls.read(Path(root)/'inputs/resources.json'),
        'environment':controls.read(Path(root)/'inputs/environment.json') if (Path(root)/'inputs/environment.json').exists() else None})


def compile_input(path,lab,catalog=None,session=None,freeze=False):
    import experiments
    path=Path(path).absolute();base=path.parent;raw=experiments.read_json(path)
    required=('schema','name','baseline','repetitions','cases','variants','budgets','execution','policies','mode','indexed_execution')
    contract.fields(raw,required,('concurrency',))
    if type(raw['schema']) is not int or raw['schema']!=3 or raw['mode'] not in ('serial','parallel'):raise IndexedError()
    if raw['mode']=='parallel' and not PARALLEL_ENABLED:raise IndexedError('selection-conflict')
    if raw['mode']=='serial' and 'concurrency' in raw:raise IndexedError('selection-conflict')
    if raw['mode']=='parallel':contract.parallel(raw.get('concurrency'))
    helper=contract.helper_contract(raw['indexed_execution'])
    if helper['max_workers']!=(2 if raw['mode']=='parallel' else 1):raise IndexedError('selection-conflict')
    catalog=catalog or Catalog(lab.normalize_endpoint)
    transformed={k:copy.deepcopy(raw[k]) for k in required if k not in ('mode','indexed_execution')};transformed['schema']=1
    execution=transformed['execution']
    for field in ('resources','environment'):
        if execution.get(field):execution[field]=str((base/execution[field]).absolute())
    cases={};external_cases=set()
    for case in transformed['cases']:
        experiments.label(case['name'])
        for field in ('project','plan'):case[field]=str((base/case[field]).absolute())
        catalog.outside(lab.ROOT,case['project'])
        planpath=Path(case['plan']);plan=lab.validate_plan(experiments.read_json(planpath),planpath.parent,external_bindings=True)
        if plan.get('schema')==2:
            if plan['inference_bindings']!='external':raise IndexedError('selection-conflict')
            external_cases.add(case['name'])
        cases[case['name']]=[t['name'] for t in plan['agents']]
    bindings={};selected={};endpoint_files=[]
    with tempfile.TemporaryDirectory(prefix='pi-indexed-input-') as temporary:
        for number,case in enumerate(transformed['cases']):
            planpath=Path(case['plan']);plan=lab.validate_plan(experiments.read_json(planpath),planpath.parent,external_bindings=True)
            if case['name'] in external_cases:
                plan.pop('inference_bindings');plan['schema']=1
                # Materialize normalized inline prompts and absolute scorer assets.
                private_plan=Path(temporary)/('plan-'+str(number)+'.json');controls.atomic(private_plan,plan)
                case['plan']=str(private_plan)
        for number,variant in enumerate(transformed['variants']):
            experiments.label(variant['name'])
            contract.fields(variant,('name',),('inference_env','inference_bindings','prompt_suffix','agent_profile'))
            if ('inference_env' in variant)==('inference_bindings' in variant):raise IndexedError('selection-conflict')
            if 'inference_env' in variant:
                profile=contract.identifier(variant.pop('inference_env'));mapping={case:{name:profile for name in names} for case,names in cases.items()}
            else:
                if not STAGE_MAPS_ENABLED:raise IndexedError('selection-conflict')
                mapping=contract.case_maps(variant.pop('inference_bindings'),cases)
            resolved={}
            for case,stages in mapping.items():
                resolved[case]={}
                for stage,profile in stages.items():
                    if profile not in selected:selected[profile]=catalog.freeze(profile,session) if freeze else catalog.select(profile)
                    if len(selected)>contract.MAX_SELECTED:raise IndexedError()
                    resolved[case][stage]=selected[profile]
            bindings[variant['name']]=resolved
            first_case=next(iter(cases));first=resolved[first_case][cases[first_case][0]]
            endpoint=Path(temporary)/('endpoint-'+str(number)+'.json');endpoint_files.append((endpoint,first['configuration']['endpoint']))
            variant['endpoint']=str(endpoint)
            if variant.get('agent_profile'):variant['agent_profile']=str((base/variant['agent_profile']).absolute())
        if freeze:
            keys=[catalog.admit(binding,session) for binding in selected.values()]
            contract.secret_free(list(selected.values()),keys)
            import application_credentials
            plans=[lab.validate_plan(experiments.read_json(case['plan']),Path(case['plan']).parent) for case in transformed['cases']]
            contract.secret_free([transformed,plans],keys)
            all_values=list(keys)
            actor_authorities={}
            for case,plan in zip(transformed['cases'],plans):
                assigned={}
                for binding,key in zip(selected.values(),keys):
                    assigned=application_credentials.resolve(plan,binding['configuration']['endpoint'],key,catalog.store,case['project'],None,False,forbidden_roots=[lab.ROOT])
                for task in plan['agents']:
                    for variable,reference in task.get('application_secrets',{}).items():
                        value=assigned[task['name']][variable]
                        if value in actor_authorities and actor_authorities[value]!=reference:raise application_credentials.CredentialError('Distinct application references share an authority')
                        actor_authorities[value]=reference;all_values.append(value)
            redactor=application_credentials.Redactor(all_values)
            for case in transformed['cases']:
                if not application_credentials.workspace_inspected_clean(Path(case['project']),redactor):raise IndexedError('inference-input-unsafe')
        for endpoint,configuration in endpoint_files:controls.atomic(endpoint,configuration)
        definition=Path(temporary)/'definition.json';controls.atomic(definition,transformed)
        normalized=experiments.validate(definition,lab)
        if normalized['execution']['network']!='bridge':raise IndexedError('selection-conflict')
        for case in normalized['cases']:
            for variant in normalized['variants']:check_deadlines(case['plan'],bindings[variant['name']][case['name']],helper)
        if freeze:
            yield definition,normalized,bindings,helper,catalog
        else:
            normalized.update(schema=3,mode=raw['mode'],indexed_execution=helper,indexed_bindings=bindings)
            yield normalized


def validate(path,lab,catalog=None):
    generator=compile_input(path,lab,catalog)
    try:return next(generator)
    finally:generator.close()


def prepare(path,destination,lab,session,catalog=None):
    import experiments,provenance
    destination=Path(destination).absolute()
    if destination.exists() or destination.is_symlink():raise IndexedError('selection-conflict')
    destination=destination.resolve()
    catalog=catalog or Catalog(lab.normalize_endpoint)
    catalog.outside(lab.ROOT,destination)
    generator=compile_input(path,lab,catalog,session,True)
    try:
        file,definition,bindings,helper,catalog=next(generator)
        raw=experiments.read_json(path)
        result=experiments.prepare(file,destination,lab)
        folder=destination/'inputs/inference-bindings';folder.mkdir()
        matrix=experiments.read_json(destination/'matrix.json');metadata=experiments.read_json(destination/'experiment.json')
        metadata.update(schema=3,mode=raw['mode'],indexed_execution=helper,catalog_root=str(catalog.root),credential_store=str(catalog.store))
        if raw['mode']=='parallel':metadata['concurrency']=contract.parallel(raw['concurrency'])
        rewritten=set()
        for cell in matrix['cells']:
            planpath=destination/cell['plan']
            if cell['plan'] not in rewritten:
                plan=experiments.read_json(planpath);plan.update(schema=2,inference_bindings='external')
                controls.atomic(planpath,plan,0o444);rewritten.add(cell['plan'])
            import agent_profiles
            profile=agent_profiles.load(destination/cell['agent_profile'])
            cell['plan_sha256']=provenance.digest(lab.validate_plan(experiments.read_json(planpath),planpath.parent,profile,external_bindings=True))
            relative='inputs/inference-bindings/'+cell['trial_id']+'.json'
            controls.atomic(destination/relative,bindings[cell['variant']][cell['case']],0o444)
            selected=bindings[cell['variant']][cell['case']]
            first_name=experiments.read_json(planpath)['agents'][0]['name']
            endpoint_relative='inputs/endpoints/'+cell['trial_id']+'.json'
            controls.atomic(destination/endpoint_relative,selected[first_name]['configuration']['endpoint'],0o444)
            cell.update(inference_bindings=relative,endpoint=endpoint_relative,endpoint_origin='indexed_catalog')
            cell['configuration_digest']=cell_digest(destination,metadata,cell,selected)
        matrix['schema']=3;metadata.update(schema=3,mode=raw['mode'],indexed_execution=helper,catalog_root=str(catalog.root),credential_store=str(catalog.store))
        if raw['mode']=='parallel':
            metadata['concurrency']=contract.parallel(raw['concurrency'])
            if metadata['concurrency']['aggregate']!=helper['aggregate'] or metadata['concurrency']['gateway']!=helper['gateway']:raise IndexedError('selection-conflict')
            order={v['name']:i for i,v in enumerate(definition['variants'])};case_order={c['name']:i for i,c in enumerate(definition['cases'])}
            matrix['cells'].sort(key=lambda c:(c['repetition'],order[c['variant']],case_order[c['case']]))
            controls.atomic(destination/'state.json',{'schema':2,'status':'prepared','active_attempts':{}})
        controls.atomic(destination/'inputs/indexed-contract.json',helper,0o444)
        controls.atomic(destination/'matrix.json',matrix,0o444);controls.atomic(destination/'experiment.json',metadata,0o444)
        hashes={'inputs/'+name:value for name,value in lab.tree_hashes(destination/'inputs',include_ignored=True).items()}
        for name in ('experiment.json','matrix.json'):hashes[name]=lab.tree_hashes(destination/name,include_ignored=True)['.']
        controls.atomic(destination/'integrity.json',{'schema':1,'files':hashes,'fingerprint':provenance.digest(hashes)},0o444)
        return {**result,'schema':3,'mode':raw['mode']}
    finally:generator.close()


def admit_work(root,metadata,cells,lab,session):
    import experiments,application_credentials
    root=Path(root);catalog=Catalog(lab.normalize_endpoint,metadata['catalog_root'],metadata['credential_store'])
    catalog.outside(lab.ROOT,root,*[root/c['source'] for c in cells])
    selected={}
    for cell in cells:
        for binding in experiments.read_json(root/cell['inference_bindings']).values():
            selected[binding['incarnation']]=binding
    if len(selected)>contract.MAX_SELECTED:raise IndexedError()
    keys={name:catalog.admit(binding,session) for name,binding in selected.items()}
    contract.secret_free(list(selected.values()),keys.values())
    for cell in cells:
        plan=frozen_plan(root,cell,lab)
        check_deadlines(plan,experiments.read_json(root/cell['inference_bindings']),metadata['indexed_execution'])
        for name,binding in selected.items():
            application_credentials.resolve(plan,binding['configuration']['endpoint'],keys[name],catalog.store,
                root/cell['source'],root/'runs',False,forbidden_roots=[lab.ROOT,root])
    return {'bindings':selected,'keys':list(keys.values())}
