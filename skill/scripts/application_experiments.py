"""Explicit compiled application experiment artifacts and private admission.

Preparation never probes or dispatches. Legacy endpoint choices are frozen
explicitly; live admission resolves their original references without substituting
a saved endpoint. Indexed preparation additionally confirms/scans before copying.
"""
import copy
import hashlib
import os
from pathlib import Path
import stat
import tempfile
import types
import uuid

import agent_profiles
import application_compiler
import application_contracts as c
import application_credentials as credentials
import application_preparation as preparation
import browser_security
import indexed_contract
from inference_catalog import Catalog
import lab_env
import native_budget_controls
import parallel_contract
import provenance
import release_contracts
import resources
import secret_store
import stage_control as controls
from application_client import API_RESOURCES,BROWSER_RESOURCES
from application_execution_authority import ReviewedAuthority

SOURCE_TYPE='application_experiment_source'
EXPERIMENT_TYPE='application_experiment'
COMMON={'schema','document_type','name','baseline','repetitions','cases','variants','budgets','execution','policies'}
CELL_FIELDS={'trial_id','case_id','variant_id','case','variant','repetition','source','plan','compiled_plan',
    'plan_sha256','endpoint','endpoint_origin','scorer_identity','agent_profile','agent_profile_id',
    'agent_profile_sha256','profile_explicit','budgets','initial_status','configuration_digest'}


class ApplicationExperimentError(ValueError):
    def __init__(self):super().__init__('Invalid or unavailable compiled application experiment')


def recognizes(path):
    value=preparation._json(path,4*1024*1024)
    return type(value) is dict and value.get('document_type')==SOURCE_TYPE


def _input(base,value,directory=False):
    c.text(value,'/input',4096)
    path=Path(value).expanduser()
    if not path.is_absolute():c.relative(value,'/input');path=base/path
    path=preparation._path(path)
    if directory:
        fd=preparation._directory(path);os.close(fd)
        if path in (Path('/'),Path.home()):raise ApplicationExperimentError()
    return path


def _budget(value):
    c.exact(value,set(native_budget_controls.LEGACY_LIMITS)|set(native_budget_controls.NATIVE_FIELDS),'/budgets')
    return native_budget_controls.validate_budget(value)


def _runtime(execution):
    return {'image_id':execution['image'],'platform':execution['platform'],
            'container_profile':execution['profile'],
            'browser_sandbox_policy':'chromium-userns' if execution['profile']=='browser' else None}


def _execution(value):
    value=copy.deepcopy(value)
    required={'image','platform','resources'};optional={'network','profile','browser_sandbox_policy'}
    if type(value) is not dict or not required<=set(value) or set(value)-required-optional:raise ApplicationExperimentError()
    c.text(value['resources'],'/execution/resources',4096)
    c.text(value['image'],'/execution/image',80)
    if not value['image'].startswith('sha256:'):raise ApplicationExperimentError()
    c.sha256(value['image'][7:],'/execution/image');c.choice(value['platform'],('linux/arm64',),'/execution/platform')
    value.setdefault('network','bridge');value.setdefault('profile','core');value.setdefault('browser_sandbox_policy','docker-default')
    c.choice(value['network'],('bridge',),'/execution/network');c.choice(value['profile'],('core','browser'),'/execution/profile')
    expected='chromium-userns' if value['profile']=='browser' else 'docker-default'
    c.choice(value['browser_sandbox_policy'],(expected,),'/execution/browser_sandbox_policy')
    if expected=='chromium-userns':value['browser_security']=browser_security.selection('browser',expected,'linux/arm64')
    return value


def _shape(raw):
    schema=raw.get('schema') if type(raw) is dict else None;c.choice(schema,(1,2,3),'/schema')
    fields=set(COMMON)
    if schema==2:fields.add('concurrency')
    if schema==3:
        fields|={'mode','indexed_execution'};c.choice(raw.get('mode'),('serial','parallel'),'/mode')
        if raw['mode']=='parallel':fields.add('concurrency')
    c.exact(raw,fields,'');c.choice(raw['document_type'],(SOURCE_TYPE,),'/document_type')
    c.slug(raw['name'],'/name');c.slug(raw['baseline'],'/baseline');c.integer(raw['repetitions'],'/repetitions',1,10)
    _budget(raw['budgets']);_execution(raw['execution'])
    policies=raw['policies'];c.exact(policies,{'primary_attempt','assistance','on_failure','max_attempts'},'/policies')
    for key,value in [('primary_attempt','first'),('assistance','exclude')]:c.choice(policies[key],(value,),'/policies/'+key)
    c.choice(policies['on_failure'],('continue','stop'),'/policies/on_failure');c.integer(policies['max_attempts'],'/policies/max_attempts',1,3)
    cases=[];variants=[]
    for item in c.array(raw['cases'],'/cases',8,1):
        fields={'name','project','plan','runtime_receipt'}|({'budgets'} if type(item) is dict and 'budgets' in item else set())
        c.exact(item,fields,'/cases');cases.append(c.slug(item['name'],'/cases/name'))
        for key in ('project','plan','runtime_receipt'):c.text(item[key],'/cases/'+key,4096)
        if 'budgets' in item:_budget(item['budgets'])
    for item in c.array(raw['variants'],'/variants',8,2):
        if type(item) is not dict:raise ApplicationExperimentError()
        selector='endpoint' if schema<3 else 'inference_env' if 'inference_env' in item else 'inference_bindings'
        c.exact(item,{'name',selector}|({'prompt_suffix'} if 'prompt_suffix' in item else set()),'/variants')
        variants.append(c.slug(item['name'],'/variants/name'));c.text(item.get('prompt_suffix',''),'/variants/prompt_suffix',8192,empty=True)
        if schema<3:c.text(item['endpoint'],'/variants/endpoint',4096)
        elif selector=='inference_env':indexed_contract.identifier(item[selector])
        elif type(item[selector]) is not dict or set(item[selector])!=set(cases):raise ApplicationExperimentError()
    if len(cases)!=len(set(cases)) or len(variants)!=len(set(variants)) or raw['baseline'] not in variants or len(cases)*len(variants)*raw['repetitions']>64:raise ApplicationExperimentError()
    return schema


def _helper(plan):return dict(BROWSER_RESOURCES if plan['application']['browser_targets'] else API_RESOURCES)


def _contracts(definition,plans):
    schema=definition['schema'];parallel=schema==2 or schema==3 and definition['mode']=='parallel'
    policy=definition['execution']['resources'];helper_weights={tuple(sorted(_helper(plan).items())) for plan in plans}
    if parallel and len(helper_weights)!=1:raise ApplicationExperimentError()
    concurrency=definition.get('concurrency');indexed=definition.get('indexed_execution')
    if schema==2:concurrency=parallel_contract.validate(concurrency)
    elif schema==3:
        indexed=indexed_contract.helper_contract(indexed)
        if indexed['max_workers']!=(2 if parallel else 1):raise ApplicationExperimentError()
        if parallel:
            concurrency=indexed_contract.parallel(concurrency)
            if any(concurrency[key]!=indexed[key] for key in ('aggregate','gateway','native_budget')):raise ApplicationExperimentError()
    selected=indexed if schema==3 else concurrency
    if selected is not None:
        weight=parallel_contract.worker_weight(policy);gateway=selected['gateway']['resources'];workers=2 if parallel else 1
        for helper_tuple in helper_weights:
            helper=dict(helper_tuple)
            if parallel_contract.native_helper(selected)!=helper:raise ApplicationExperimentError()
            if any(workers*(weight[key]+helper[key])+gateway[key]>selected['aggregate'][key] for key in weight):
                raise ApplicationExperimentError()
        if selected['gateway']['queue_wait_seconds']+selected['gateway']['request_timeout_seconds']>=min(
                stage['limits']['timeout_seconds'] for plan in plans for stage in plan['stages']):raise ApplicationExperimentError()
    if parallel and len(plans)*definition['repetitions']>concurrency['max_pending']:raise ApplicationExperimentError()
    return parallel


def _pair_plan(case,variant,execution,bindings,runner):
    files={};profiles,assets,instructions=preparation._profile_inputs(case['source'],files)
    size=sum(map(len,assets.values()))
    for check in case['source']['checks']:
        for asset in check.get('scorer',{}).get('assets',[]):
            body=preparation._read(Path(case['plan_path']).parent/asset['source'],16*1024*1024)
            if asset['source'] in assets and assets[asset['source']]!=body:raise ApplicationExperimentError()
            if asset['source'] not in assets:size+=len(body)
            if size>preparation.MAX_TOTAL:raise ApplicationExperimentError()
            assets[asset['source']]=body
    record=preparation._variant_record(variant['name'],bindings,_runtime(execution),execution['resources'],case['budgets'],variant['prompt_suffix'])
    prepared=preparation._variant_build(case['source'],record,profiles,assets,instructions,runner)
    observation=preparation._runtime(prepared['source'],preparation._json(case['runtime_receipt']))
    inference=preparation._variant_inference(record,prepared)
    for selected in inference['stages'].values():preparation._credential_scope(prepared['source'],selected)
    plan=application_compiler.compile_plan(prepared['source'],**prepared['compiler_kwargs'])
    return {'case':case['name'],'variant':variant['name'],'plan':plan,'bindings':copy.deepcopy(bindings),
            'runtime_observation':observation,'budgets':copy.deepcopy(case['budgets']),'prompt_suffix':variant['prompt_suffix'],
            'asset_bytes':list(assets.values())}


def validate(path,lab,endpoint_path=None,catalog=None,*,secrets_dir=None):
    try:
        if endpoint_path is not None:raise ApplicationExperimentError()
        path=preparation._path(path);raw=preparation._json(path,4*1024*1024);base=path.parent
        schema=_shape(raw);default=_budget(raw['budgets']);execution=_execution(raw['execution'])
        execution['resources']=resources.validate_policy(preparation._json(_input(base,execution['resources'])))
        policies=copy.deepcopy(raw['policies'])
        cases=[];seen=set()
        for item in c.array(raw['cases'],'/cases',8,1):
            fields={'name','project','plan','runtime_receipt'}|({'budgets'} if type(item) is dict and 'budgets' in item else set())
            c.exact(item,fields,'/cases');name=c.slug(item['name'],'/cases/name')
            if name in seen:raise ApplicationExperimentError()
            seen.add(name);project=_input(base,item['project'],True);plan_path=_input(base,item['plan'])
            source=c.validate_source(preparation._json(plan_path))
            if source['runtime']['inference_owner']!='experiment_variant':raise ApplicationExperimentError()
            if len(source['checks'])!=1 or 'scorer' not in source['checks'][0]:raise ApplicationExperimentError()
            if not credentials.workspace_inspected_clean(project,credentials.Redactor([])):raise ApplicationExperimentError()
            cases.append({'name':name,'project':str(project),'plan_path':str(plan_path),'source':source,
                'runtime_receipt':str(_input(base,item['runtime_receipt'])),'budgets':_budget(item.get('budgets',default))})
        variants=[];seen=set();maps={case['name']:[stage['id'] for stage in case['source']['stages']] for case in cases}
        selected={};catalog=(catalog or Catalog(lab.normalize_endpoint)) if schema==3 else None
        if catalog is not None:catalog.outside(lab.ROOT,*[case['project'] for case in cases])
        for item in c.array(raw['variants'],'/variants',8,2):
            name=c.slug(item.get('name') if type(item) is dict else None,'/variants/name')
            if name in seen:raise ApplicationExperimentError()
            seen.add(name);suffix=item.get('prompt_suffix','');c.text(suffix,'/variants/prompt_suffix',8192,empty=True)
            variant={'name':name,'prompt_suffix':suffix,'bindings':{}}
            if schema<3:
                c.exact(item,{'name','endpoint'}|({'prompt_suffix'} if 'prompt_suffix' in item else set()),'/variants')
                raw_endpoint=preparation._json(_input(base,item['endpoint']));preparation._no_templates(raw_endpoint)
                endpoint=lab.normalize_endpoint(raw_endpoint)
                for case in cases:variant['bindings'][case['name']]={stage:{'kind':'legacy','endpoint':copy.deepcopy(endpoint)} for stage in maps[case['name']]}
            else:
                selector='inference_env' if 'inference_env' in item else 'inference_bindings'
                c.exact(item,{'name',selector}|({'prompt_suffix'} if 'prompt_suffix' in item else set()),'/variants')
                mapping=({case:{stage:indexed_contract.identifier(item[selector]) for stage in names} for case,names in maps.items()}
                    if selector=='inference_env' else indexed_contract.case_maps(item[selector],maps))
                for case,names in mapping.items():
                    variant['bindings'][case]={}
                    for stage,identifier in names.items():
                        if identifier not in selected:selected[identifier]=catalog.select(identifier)
                        if len(selected)>indexed_contract.MAX_SELECTED:raise ApplicationExperimentError()
                        variant['bindings'][case][stage]={'kind':'indexed','entry':copy.deepcopy(selected[identifier])}
            variants.append(variant)
        if raw['baseline'] not in seen or len(cases)*len(variants)*raw['repetitions']>64:raise ApplicationExperimentError()
        definition={'schema':schema,'document_type':SOURCE_TYPE,'name':raw['name'],'baseline':raw['baseline'],
            'repetitions':raw['repetitions'],'cases':cases,'variants':variants,'execution':execution,'policies':policies,'raw':raw}
        for key in ('mode','indexed_execution','concurrency'):
            if key in raw:definition[key]=copy.deepcopy(raw[key])
        runner=preparation._runner();pairs=[];asset_bytes=0
        for case in cases:
            for variant in variants:
                pair=_pair_plan(case,variant,execution,variant['bindings'][case['name']],runner)
                asset_bytes+=sum(map(len,pair['asset_bytes']))
                if asset_bytes>preparation.MAX_TOTAL:raise ApplicationExperimentError()
                pairs.append(pair)
        if len({plan['plan']['runtime']['pi_release'] for plan in pairs})!=1:raise ApplicationExperimentError()
        parallel=_contracts(definition,[pair['plan'] for pair in pairs])
        if schema==2 and any(variant['bindings']!=variants[0]['bindings'] for variant in variants):raise ApplicationExperimentError()
        if schema==3:
            for pair in pairs:
                for stage in pair['plan']['stages']:
                    limits=pair['bindings'][stage['id']]['entry']['configuration']['request_limits']
                    if sum(limits.values())>=stage['limits']['timeout_seconds'] or any(limits[key]>raw['indexed_execution']['gateway'][key] for key in limits):raise ApplicationExperimentError()
            definition.update(catalog_root=str(catalog.root),credential_store=str(catalog.store))
        else:definition['credential_store']=str(Path(secrets_dir or secret_store.default_store()).expanduser().absolute())
        store=Path(definition['credential_store'])
        if schema==3 and secrets_dir is not None and Path(secrets_dir).expanduser().resolve()!=store.resolve():raise ApplicationExperimentError()
        for forbidden in [lab.ROOT,*[Path(case['project']) for case in cases]]:
            if store==forbidden or forbidden in store.parents or store.resolve()==forbidden.resolve() or forbidden.resolve() in store.resolve().parents:
                raise ApplicationExperimentError()
        definition.update(pairs=pairs,runner=runner,parallel=parallel)
        return definition
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError,lab.LabError,lab_env.EnvError):raise ApplicationExperimentError() from None


def _private_admit(rows,root,store,lab,session,catalog=None):
    lab_env.resolve_session(session);keys=[];specs={};apps=[];app_references=set();inference_references=set();app_owners={}
    for row in rows:
        plan=row['plan'];authorities={};endpoints={};values={}
        for stage in plan['stages']:
            binding=row['bindings'][stage['id']]
            if binding['kind']=='indexed':
                entry=binding['entry'];configuration=entry['configuration'];endpoint=configuration['endpoint']
                key=catalog.admit(entry,session);reference=configuration['credential'].get('name')
            else:
                endpoint=binding['endpoint'];reference=endpoint['api_key_env']
                key=lab.endpoint_secret(endpoint,types.SimpleNamespace(secrets_dir=str(store),session=session,prompt_secret=False))
            digest=stage['inference_binding']['configuration_sha256'];value={'reference':reference,'value':key}
            if digest in authorities and authorities[digest]!=value:raise ApplicationExperimentError()
            authorities[digest]=value;endpoints[stage['id']]=copy.deepcopy(endpoint);values[stage['id']]=key;keys.append(key)
            if reference is not None:inference_references.add(reference)
        first=plan['stages'][0]['id'];project=Path(row['project'])
        authority=ReviewedAuthority(plan,endpoints[first],values[first],store,project,Path(root)/'runs'/str(uuid.uuid4()),
            browser_admission=row['runtime_observation']['browser_admission'],inference_authorities=authorities,forbidden_roots=(root,lab.ROOT))
        for stage in plan['stages']:
            for alias,value in authority._values[stage['id']].items():
                reference=plan['application']['credentials'][alias];app_references.add(reference);apps.append(value)
                if value in app_owners and app_owners[value]!=reference:raise ApplicationExperimentError()
                app_owners[value]=reference
        specs[row['trial_id']]={'plan':copy.deepcopy(plan),'endpoint':endpoints[first],'inference_key':values[first],
            'store':str(store),'project':str(project),'inference_authorities':authorities,
            'browser_admission':copy.deepcopy(row['runtime_observation']['browser_admission'])}
    if app_references&inference_references or any(value and value in apps for value in keys):raise ApplicationExperimentError()
    corpus=list(dict.fromkeys(value for value in [*keys,*apps] if value));redactor=credentials.Redactor(corpus)
    for row in rows:
        if redactor.contains(c.canonical({'plan':row['plan'],'bindings':row['bindings']})) or not credentials.workspace_inspected_clean(row['project'],redactor):raise ApplicationExperimentError()
        if any(redactor.contains(body) for body in row.get('asset_bytes',())):raise ApplicationExperimentError()
        if row.get('compiled_root') is not None and not credentials.workspace_inspected_clean(row['compiled_root'],redactor):raise ApplicationExperimentError()
    return {'authorities_by_trial':specs,'keys':list(dict.fromkeys(value for value in keys if value)),'redaction_values':corpus}


def _pair_path(experiment_id,case,variant):
    import json
    identity=uuid.uuid5(uuid.UUID(experiment_id),'plan:'+json.dumps([case,variant],ensure_ascii=False,separators=(',',':')))
    return 'inputs/application/'+str(identity)


def _cell_digest(metadata,cell,compiled):
    return provenance.digest({'schema':metadata['schema'],'source':metadata['source_receipts'][cell['case']],
        'plan':compiled['plan']['plan_sha256'],'manifest':compiled['manifest']['manifest_sha256'],
        'scorer':cell['scorer_identity'],'execution':metadata['execution'],'budgets':cell['budgets'],
        'indexed_execution':metadata.get('indexed_execution'),'concurrency':metadata.get('concurrency'),
        'policies':metadata['policies'],'runner':metadata['runner_content_sha256']})


def _read_tree(root):
    result={};total=0;directories=0
    for base,dirs,files in os.walk(root,followlinks=False):
        directories+=len(dirs)
        if directories>preparation.MAX_FILES*8:raise ApplicationExperimentError()
        for name in dirs:fd=preparation._directory(Path(base)/name);os.close(fd)
        for name in files:
            path=Path(base)/name;relative=str(path.relative_to(root));c.relative(relative,'/files')
            body=preparation._read(path,preparation.MAX_TOTAL);total+=len(body)
            if len(result)>=preparation.MAX_FILES or total>preparation.MAX_TOTAL:raise ApplicationExperimentError()
            result[relative]=body
    return result


def prepare(path,destination,lab,endpoint_path=None,session=None,catalog=None,*,secrets_dir=None):
    try:
        definition=validate(path,lab,endpoint_path,catalog,secrets_dir=secrets_dir);root=preparation._path(destination)
        store=Path(definition['credential_store'])
        if store==root or root in store.parents or store.resolve()==root.resolve() or root.resolve() in store.resolve().parents:
            raise ApplicationExperimentError()
        if root==lab.ROOT or lab.ROOT in root.parents:raise ApplicationExperimentError()
        for case in definition['cases']:
            project=Path(case['project'])
            if root==project or project in root.parents:raise ApplicationExperimentError()
        experiment_id=str(uuid.uuid4());pairs=copy.deepcopy(definition['pairs']);private={'redaction_values':[]}
        if definition['schema']==3:
            catalog=catalog or Catalog(lab.normalize_endpoint,definition['catalog_root'],definition['credential_store'])
            catalog.outside(lab.ROOT,root,*[case['project'] for case in definition['cases']]);frozen={}
            for pair in pairs:
                for wrapper in pair['bindings'].values():
                    entry=wrapper['entry'];name=entry['id']
                    if name not in frozen:frozen[name]=catalog.freeze(name,session)
                    if {key:value for key,value in frozen[name].items() if key!='authority_id'}!=entry:raise ApplicationExperimentError()
                    wrapper['entry']=copy.deepcopy(frozen[name])
            rows=[{**pair,'trial_id':str(uuid.uuid4()),'project':next(case['project'] for case in definition['cases'] if case['name']==pair['case'])} for pair in pairs]
            private=_private_admit(rows,root,definition['credential_store'],lab,session,catalog)
            if credentials.Redactor(private['redaction_values']).contains(c.canonical(definition['raw'])):raise ApplicationExperimentError()
        files={};receipts={};compiled_by_pair={}
        with tempfile.TemporaryDirectory(prefix='pi-application-experiment-') as temporary:
            scratch=Path(temporary).resolve()
            for case in definition['cases']:
                project=Path(case['project']);before=lab.tree_hashes(project);target=scratch/('source-'+case['name'])
                copied=lab.snapshot(project,target,[],64)
                if before!=lab.tree_hashes(project) or before!=lab.tree_hashes(target):raise ApplicationExperimentError()
                if not credentials.workspace_inspected_clean(target,credentials.Redactor(private['redaction_values'])):raise ApplicationExperimentError()
                entries=_read_tree(target)
                for relative,body in entries.items():preparation._add(files,'inputs/sources/'+case['name']+'/'+relative,body)
                snapshot={name:'0444:'+hashlib.sha256(body).hexdigest() for name,body in entries.items()}
                receipts[case['name']]={'source_sha256':provenance.digest(before),'snapshot_sha256':provenance.digest(snapshot),'copy':copied}
            for number,pair in enumerate(pairs):
                case=next(value for value in definition['cases'] if value['name']==pair['case'])
                compiled=preparation.compile_variant_artifact(case['plan_path'],scratch/('pair-'+str(number)),case['runtime_receipt'],
                    variant_id=pair['variant'],bindings=pair['bindings'],runtime=_runtime(definition['execution']),
                    resources=definition['execution']['resources'],budgets=case['budgets'],prompt_suffix=pair['prompt_suffix'])
                if compiled['plan']!=pair['plan'] or compiled['manifest']['runner']!=definition['runner']:raise ApplicationExperimentError()
                relative=_pair_path(experiment_id,pair['case'],pair['variant'])
                for name,body in _read_tree(Path(compiled['root'])).items():preparation._add(files,relative+'/'+name,body)
                compiled_by_pair[(pair['case'],pair['variant'])]=(relative,compiled,pair)
        execution={key:value for key,value in definition['execution'].items() if key!='resources'}
        metadata={'schema':definition['schema'],'document_type':EXPERIMENT_TYPE,'experiment_id':experiment_id,
            'name':definition['name'],'baseline':definition['baseline'],'repetitions':definition['repetitions'],
            'policies':definition['policies'],'execution':execution,'profile':'application-client','created_at':controls.now(),
            'source_receipts':receipts,'runner_content_sha256':definition['runner']['sha256'],'prepared_root':str(root),
            'release_contracts':release_contracts.snapshot(),'cases':[case['name'] for case in definition['cases']],
            'variants':[variant['name'] for variant in definition['variants']],
            'application_definition_sha256':c.digest(definition['raw']),'credential_store':definition['credential_store'],
            'source_admission':'indexed_confirmed_and_scanned' if definition['schema']==3 else 'legacy_offline_unverified_until_admit_work'}
        for key in ('mode','indexed_execution','concurrency','catalog_root'):
            if key in definition:metadata[key]=copy.deepcopy(definition[key])
        cells=[];namespace=uuid.UUID(experiment_id)
        for case in definition['cases']:
            for variant in definition['variants']:
                relative,compiled,pair=compiled_by_pair[(case['name'],variant['name'])];plan=compiled['plan']
                first=plan['stages'][0];endpoint=pair['bindings'][first['id']]
                endpoint=endpoint['entry']['configuration']['endpoint'] if definition['schema']==3 else endpoint['endpoint']
                for repetition in range(definition['repetitions']):
                    case_id=str(uuid.uuid5(namespace,'case:'+case['name']));variant_id=str(uuid.uuid5(namespace,'variant:'+variant['name']))
                    trial_id=str(uuid.uuid5(namespace,case_id+':'+variant_id+':'+str(repetition)))
                    endpoint_path='inputs/endpoints/'+trial_id+'.json';preparation._add(files,endpoint_path,c.canonical(endpoint))
                    cell={'trial_id':trial_id,'case_id':case_id,'variant_id':variant_id,'case':case['name'],'variant':variant['name'],
                        'repetition':repetition,'source':'inputs/sources/'+case['name'],'plan':relative+'/plan.json',
                        'compiled_plan':relative+'/plan.json','plan_sha256':plan['plan_sha256'],'endpoint':endpoint_path,
                        'endpoint_origin':'indexed_catalog' if definition['schema']==3 else 'explicit',
                        'scorer_identity':c.digest(plan['checks']),'agent_profile':relative+'/profiles/'+first['id']+'/profile.json',
                        'agent_profile_id':'application-client','agent_profile_sha256':first['profile_binding']['sha256'],
                        'profile_explicit':True,'budgets':case['budgets'],'initial_status':'planned'}
                    if definition['schema']==3:
                        binding_path='inputs/inference-bindings/'+trial_id+'.json'
                        preparation._add(files,binding_path,c.canonical({stage:wrapper['entry'] for stage,wrapper in pair['bindings'].items()}))
                        cell['inference_bindings']=binding_path
                    cell['configuration_digest']=_cell_digest(metadata,cell,compiled);cells.append(cell)
        if definition['parallel']:
            cases={name:number for number,name in enumerate(metadata['cases'])};variants={name:number for number,name in enumerate(metadata['variants'])}
            cells.sort(key=lambda cell:(cell['repetition'],variants[cell['variant']],cases[cell['case']]))
        for name,value in [('inputs/resources.json',definition['execution']['resources']),('inputs/application-definition.json',definition['raw'])]:
            preparation._add(files,name,c.canonical(value))
        if 'concurrency' in metadata:preparation._add(files,'inputs/concurrency.json',c.canonical(metadata['concurrency']))
        if metadata['schema']==3:preparation._add(files,'inputs/indexed-contract.json',c.canonical(metadata['indexed_execution']))
        matrix={'schema':metadata['schema'],'document_type':'trial_matrix','experiment_id':experiment_id,'cells':cells}
        preparation._add(files,'experiment.json',c.canonical(metadata));preparation._add(files,'matrix.json',c.canonical(matrix))
        hashes={name:'0444:'+hashlib.sha256(body).hexdigest() for name,body in files.items()}
        integrity={'schema':1,'files':hashes,'fingerprint':provenance.digest(hashes)}
        preparation._add(files,'integrity.json',c.canonical(integrity))
        state={'schema':2 if definition['parallel'] else 1,'status':'prepared'}
        state.update(active_attempts={}) if definition['parallel'] else state.update(active_attempt_id=None)
        preparation._add(files,'state.json',c.canonical(state))
        if credentials.Redactor(private['redaction_values']).contains(b'\n'.join(files.values())):raise ApplicationExperimentError()
        directories=tuple('inputs/sources/'+case['name'] for case in definition['cases'])
        with tempfile.TemporaryDirectory(prefix='pi-application-experiment-verify-') as temporary:
            view=Path(temporary).resolve()/'view'
            preparation._publish(view,files,directories=directories)
            verify(view,lab)
        preparation._publish(root,files,directories=directories)
        return {'experiment':str(root),'experiment_id':experiment_id,'planned':len(cells),
                'fingerprint':integrity['fingerprint'],'schema':metadata['schema'],**({'mode':metadata['mode']} if 'mode' in metadata else {})}
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError,lab.LabError,lab_env.EnvError):raise ApplicationExperimentError() from None


def verify(root,lab):
    try:
        root=preparation._path(root);fd=preparation._directory(root);os.close(fd)
        integrity=preparation._json(root/'integrity.json',4*1024*1024)
        c.exact(integrity,{'schema','files','fingerprint'},'/integrity');c.choice(integrity['schema'],(1,),'/integrity/schema')
        if type(integrity['files']) is not dict or not 1<=len(integrity['files'])<=preparation.MAX_FILES or provenance.digest(integrity['files'])!=integrity['fingerprint']:raise ApplicationExperimentError()
        total=0
        for path,expected in integrity['files'].items():
            c.relative(path,'/integrity/files');body=preparation._read(root/path,preparation.MAX_TOTAL);total+=len(body)
            if total>preparation.MAX_TOTAL or expected!='0444:'+hashlib.sha256(body).hexdigest() or stat.S_IMODE((root/path).lstat().st_mode)!=0o444:raise ApplicationExperimentError()
        actual={'inputs/'+name for name in _read_tree(root/'inputs')}
        if actual!={name for name in integrity['files'] if name.startswith('inputs/')}:raise ApplicationExperimentError()
        metadata=preparation._json(root/'experiment.json');matrix=preparation._json(root/'matrix.json')
        schema=metadata.get('schema') if type(metadata) is dict else None;c.choice(schema,(1,2,3),'/schema')
        fields={'schema','document_type','experiment_id','name','baseline','repetitions','policies','execution','profile',
            'created_at','source_receipts','runner_content_sha256','prepared_root','release_contracts','cases','variants',
            'application_definition_sha256','credential_store','source_admission'}
        if schema==2:fields.add('concurrency')
        if schema==3:
            fields|={'mode','indexed_execution','catalog_root'}
            if metadata.get('mode')=='parallel':fields.add('concurrency')
        c.exact(metadata,fields,'/experiment');c.exact(matrix,{'schema','document_type','experiment_id','cells'},'/matrix')
        if metadata['document_type']!=EXPERIMENT_TYPE or matrix['document_type']!='trial_matrix' or matrix['schema']!=schema or type(matrix['schema']) is not int or metadata['profile']!='application-client':raise ApplicationExperimentError()
        for key in ('runner_content_sha256','application_definition_sha256'):c.sha256(metadata[key],'/experiment/'+key)
        for key in ('prepared_root','credential_store','created_at'):c.text(metadata[key],'/experiment/'+key,4096)
        if schema==3:c.text(metadata['catalog_root'],'/experiment/catalog_root',4096)
        expected_admission='indexed_confirmed_and_scanned' if schema==3 else 'legacy_offline_unverified_until_admit_work'
        if metadata['source_admission']!=expected_admission:raise ApplicationExperimentError()
        namespace=uuid.UUID(metadata['experiment_id'])
        if str(namespace)!=metadata['experiment_id'] or matrix['experiment_id']!=metadata['experiment_id']:raise ApplicationExperimentError()
        raw=preparation._json(root/'inputs/application-definition.json')
        if _shape(raw)!=schema or c.digest(raw)!=metadata['application_definition_sha256']:raise ApplicationExperimentError()
        if metadata['cases']!=[case['name'] for case in raw['cases']] or metadata['variants']!=[variant['name'] for variant in raw['variants']]:raise ApplicationExperimentError()
        if any(metadata[key]!=raw[key] for key in ('name','baseline','repetitions','policies')):raise ApplicationExperimentError()
        expected_execution=_execution(raw['execution']);expected_execution.pop('resources')
        if metadata['execution']!=expected_execution:raise ApplicationExperimentError()
        if type(metadata['source_receipts']) is not dict or set(metadata['source_receipts'])!=set(metadata['cases']):raise ApplicationExperimentError()
        for receipt in metadata['source_receipts'].values():
            c.exact(receipt,{'source_sha256','snapshot_sha256','copy'},'/source_receipts')
            for key in ('source_sha256','snapshot_sha256'):c.sha256(receipt[key],'/source_receipts/'+key)
            c.exact(receipt['copy'],{'copied_bytes','skipped'},'/source_receipts/copy')
            c.integer(receipt['copy']['copied_bytes'],'/source_receipts/copy/copied_bytes',0,preparation.MAX_TOTAL)
            c.array(receipt['copy']['skipped'],'/source_receipts/copy/skipped',10000)
        c.exact(metadata['release_contracts'],set(release_contracts.RELEASES),'/release_contracts')
        for release,binding in metadata['release_contracts'].items():
            c.exact(binding,{'release','id','revision','sha256'},'/release_contracts/'+release)
            c.choice(binding['release'],(release,),'/release_contracts/release');c.text(binding['id'],'/release_contracts/id',128)
            c.integer(binding['revision'],'/release_contracts/revision',1,1000000);c.sha256(binding['sha256'],'/release_contracts/sha256')
        allowed={'experiment.json','matrix.json','inputs/resources.json','inputs/application-definition.json'}
        for key,path in [('concurrency','inputs/concurrency.json'),('indexed_execution','inputs/indexed-contract.json')]:
            if key in metadata:
                if metadata[key]!=raw[key] or preparation._json(root/path)!=metadata[key]:raise ApplicationExperimentError()
                allowed.add(path)
        if schema==3 and metadata['mode']!=raw['mode']:raise ApplicationExperimentError()
        policy=resources.validate_policy(preparation._json(root/'inputs/resources.json'));compiled_cache={};plans=[];seen=set();source_hashes={};stage_maps={};legacy_upstreams=set()
        for cell in c.array(matrix['cells'],'/matrix/cells',64,1):
            c.exact(cell,CELL_FIELDS|({'inference_bindings'} if schema==3 else set()),'/matrix/cell')
            if cell['initial_status']!='planned' or cell['endpoint_origin']!=('indexed_catalog' if schema==3 else 'explicit'):raise ApplicationExperimentError()
            case=next(row for row in raw['cases'] if row['name']==cell['case']);variant=next(row for row in raw['variants'] if row['name']==cell['variant'])
            relative=_pair_path(metadata['experiment_id'],cell['case'],cell['variant']);plan_path=relative+'/plan.json'
            if cell['compiled_plan']!=plan_path or cell['plan']!=plan_path or cell['source']!='inputs/sources/'+cell['case']:raise ApplicationExperimentError()
            expected_case=str(uuid.uuid5(namespace,'case:'+cell['case']));expected_variant=str(uuid.uuid5(namespace,'variant:'+cell['variant']))
            expected_trial=str(uuid.uuid5(namespace,expected_case+':'+expected_variant+':'+str(cell['repetition'])))
            if cell['case_id']!=expected_case or cell['variant_id']!=expected_variant or cell['trial_id']!=expected_trial or expected_trial in seen or type(cell['repetition']) is not int or not 0<=cell['repetition']<metadata['repetitions']:raise ApplicationExperimentError()
            seen.add(expected_trial)
            if plan_path not in compiled_cache:
                compiled_cache[plan_path]=preparation.load_compiled(root/plan_path);plans.append(compiled_cache[plan_path]['plan'])
                allowed.update(relative+'/'+name for name in _read_tree(root/relative))
            compiled=compiled_cache[plan_path];plan=compiled['plan'];first=plan['stages'][0]
            if compiled['manifest']['document_type']!='application_variant_input_manifest' or plan['runtime']['inference_owner']!='experiment_variant' or cell['plan_sha256']!=plan['plan_sha256'] or plan['input_hashes']['runner']!=metadata['runner_content_sha256']:raise ApplicationExperimentError()
            record=preparation._json(root/relative/'variant.json');source=preparation._json(root/relative/'source.json')
            stage_maps[cell['case']]=[stage['id'] for stage in source['stages']]
            if cell['case'] in source_hashes and source_hashes[cell['case']]!=c.digest(source):raise ApplicationExperimentError()
            source_hashes[cell['case']]=c.digest(source)
            budgets=_budget(case.get('budgets',raw['budgets']))
            if record['variant_id']!=cell['variant'] or record['runtime']!=_runtime(metadata['execution']) or record['resources']!=policy or record['budgets']!=budgets or record['prompt_suffix']!=variant.get('prompt_suffix','') or cell['budgets']!=budgets:raise ApplicationExperimentError()
            if cell['agent_profile']!=relative+'/profiles/'+first['id']+'/profile.json' or cell['agent_profile_sha256']!=first['profile_binding']['sha256'] or cell['agent_profile_id']!='application-client' or cell['profile_explicit'] is not True:raise ApplicationExperimentError()
            inference=preparation._json(root/relative/'inference.json');selected=inference['stages'][first['id']]
            endpoint=selected['configuration']['endpoint'] if metadata['schema']==3 else selected['configuration']
            if cell['endpoint']!='inputs/endpoints/'+cell['trial_id']+'.json' or preparation._json(root/cell['endpoint'])!=endpoint:raise ApplicationExperimentError()
            allowed.add(cell['endpoint'])
            if metadata['schema']==3:
                if cell['inference_bindings']!='inputs/inference-bindings/'+cell['trial_id']+'.json':raise ApplicationExperimentError()
                bindings=preparation._json(root/cell['inference_bindings'])
                allowed.add(cell['inference_bindings'])
                if bindings!={stage:wrapper['entry'] for stage,wrapper in record['bindings'].items()}:raise ApplicationExperimentError()
                mapping=({stage:variant['inference_env'] for stage in stage_maps[cell['case']]} if 'inference_env' in variant
                    else indexed_contract.case_maps(variant['inference_bindings'],{name:stage_maps.get(name,list(variant['inference_bindings'][name])) for name in metadata['cases']})[cell['case']])
                for stage,entry in bindings.items():
                    value=copy.deepcopy(entry);indexed_contract.identity(value.pop('authority_id'));indexed_contract.entry(value,lab.normalize_endpoint)
                    if value['id']!=mapping[stage]:raise ApplicationExperimentError()
            elif any(wrapper['kind']!='legacy' for wrapper in record['bindings'].values()):raise ApplicationExperimentError()
            if schema==2:
                legacy_upstreams.update(c.digest(wrapper['endpoint']) for wrapper in record['bindings'].values())
                if len(legacy_upstreams)!=1:raise ApplicationExperimentError()
            if cell['scorer_identity']!=c.digest(plan['checks']) or cell['configuration_digest']!=_cell_digest(metadata,cell,compiled):raise ApplicationExperimentError()
            fd=preparation._directory(root/cell['source']);os.close(fd)
            snapshot=lab.tree_hashes(root/cell['source'],include_ignored=True)
            allowed.update(cell['source']+'/'+name for name in snapshot)
            if metadata['source_receipts'][cell['case']]['snapshot_sha256']!=provenance.digest(snapshot):raise ApplicationExperimentError()
        if len(seen)!=len(raw['cases'])*len(raw['variants'])*raw['repetitions']:raise ApplicationExperimentError()
        expected_order=[(case,variant,repetition) for case in metadata['cases'] for variant in metadata['variants'] for repetition in range(metadata['repetitions'])]
        if schema==2 or schema==3 and metadata['mode']=='parallel':
            expected_order=[(case,variant,repetition) for repetition in range(metadata['repetitions']) for variant in metadata['variants'] for case in metadata['cases']]
        if [(cell['case'],cell['variant'],cell['repetition']) for cell in matrix['cells']]!=expected_order:raise ApplicationExperimentError()
        if schema==3:
            for variant in raw['variants']:
                if 'inference_bindings' in variant:indexed_contract.case_maps(variant['inference_bindings'],stage_maps)
        if set(integrity['files'])!=allowed:raise ApplicationExperimentError()
        expected_dirs={'inputs'}
        for name in allowed:
            if name.startswith('inputs/'):
                expected_dirs.update(str(parent) for parent in Path(name).parents if str(parent)!='.')
        for name in metadata['cases']:expected_dirs.update({'inputs/sources','inputs/sources/'+name})
        actual_dirs=set()
        for base,dirs,_ in os.walk(root/'inputs',followlinks=False):actual_dirs.update(str((Path(base)/name).relative_to(root)) for name in dirs)
        if actual_dirs|{'inputs'}!=expected_dirs:raise ApplicationExperimentError()
        definition={'schema':metadata['schema'],'execution':{**metadata['execution'],'resources':policy},'repetitions':metadata['repetitions']}
        for key in ('mode','concurrency','indexed_execution'):
            if key in metadata:definition[key]=metadata[key]
        _contracts(definition,plans)
        return metadata,matrix
    except (OSError,ValueError,KeyError,TypeError,AttributeError,StopIteration,RecursionError,lab.LabError):raise ApplicationExperimentError() from None


def trial_args(root,metadata,cell,lab,session):
    root=Path(root)
    args=lab.parser().parse_args(['run','--compiled-plan',str(root/cell['compiled_plan']),
        '--project',str(root/cell['source']),'--results-dir',str(root/'runs')])
    args.session=session;args._experiment_root=str(root);args.secrets_dir=metadata['credential_store']
    for name in ('image','platform','profile','browser_sandbox_policy','network'):setattr(args,name,metadata['execution'][name])
    args._resource_request=resources.validate_policy(preparation._json(root/'inputs/resources.json'));args._explicit_options=()
    args._application_variant_context={'experiment_root':str(root),'experiment_id':metadata['experiment_id'],
        'trial_id':cell['trial_id'],'variant_id':cell['variant'],'configuration_digest':cell['configuration_digest']}
    if metadata['schema']==3:
        args.catalog_dir=metadata['catalog_root'];args._indexed_bindings=preparation._json(root/cell['inference_bindings'])
        args._indexed_contract=metadata['indexed_execution']
    return args


def admit_work(root,metadata,work,lab,session):
    try:
        checked,matrix=verify(root,lab)
        if checked!=metadata:raise ApplicationExperimentError()
        byid={cell['trial_id']:cell for cell in matrix['cells']};rows=[];catalog=None
        if metadata['schema']==3:
            catalog=Catalog(lab.normalize_endpoint,metadata['catalog_root'],metadata['credential_store'])
            catalog.outside(lab.ROOT,root)
        c.array(work,'/work',64);selected_trials=set()
        for cell in work:
            if cell!=byid.get(cell.get('trial_id')):raise ApplicationExperimentError()
            if cell['trial_id'] in selected_trials:raise ApplicationExperimentError()
            selected_trials.add(cell['trial_id'])
            compiled=preparation.load_compiled(Path(root)/cell['compiled_plan'],verify_runner=True)
            artifact=Path(compiled['root']);variant=preparation._json(artifact/'variant.json')
            rows.append({'trial_id':cell['trial_id'],'plan':compiled['plan'],'bindings':variant['bindings'],
                'project':str(Path(root)/cell['source']),'compiled_root':str(artifact),
                'runtime_observation':preparation._json(artifact/'runtime-receipt.json')})
        result=_private_admit(rows,root,metadata['credential_store'],lab,session,catalog)
        redactor=credentials.Redactor(result['redaction_values'])
        if any(redactor.contains(body) for body in _read_tree(Path(root)/'inputs').values()):raise ApplicationExperimentError()
        return result
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError,lab.LabError,lab_env.EnvError):raise ApplicationExperimentError() from None
