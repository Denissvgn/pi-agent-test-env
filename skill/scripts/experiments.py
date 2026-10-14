"""Versioned application experiments: immutable matrix and parent-held inputs."""
from __future__ import annotations
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import uuid

import lab_env
import agent_profiles
import provenance
import browser_security
import resources
import scoring
import stage_control as controls
import release_contracts
import parallel_contract

class ExperimentError(ValueError):pass


def object_fields(value,allowed,required=()):
    if not isinstance(value,dict) or set(value)-set(allowed) or not set(required)<=set(value):
        raise ExperimentError('Missing/unsupported experiment fields: '+', '.join(required))


def read_json(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as handle:
        info=os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>4*1024*1024:raise ExperimentError('Expected bounded non-linked JSON file')
        return json.load(handle)


def label(value):
    if not isinstance(value,str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}',value):raise ExperimentError('Experiment labels must be lowercase slugs')
    return value



def input_path(base,value):
    if not isinstance(value,str) or not value or '\0' in value:raise ExperimentError('Input path must be a nonempty string')
    return base/value

def budget(value):
    fields={'timeout_seconds':3600,'max_turns':100,'max_total_tokens':10000000}
    object_fields(value,fields,fields)
    if any(type(value[k]) is not int or not 0<value[k]<=cap for k,cap in fields.items()):raise ExperimentError('Finite positive stage budgets required')
    return dict(value)


def scorer_identity(plan):
    identities=[]
    for check in plan['checks']:
        if not check.get('scorer'):raise ExperimentError('Experiments require structured independent scorers, not command-only scores')
        contract=copy.deepcopy(check['scorer'])
        assets=[]
        for asset in contract['assets']:
            path=Path(asset['source']);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd,'rb') as f:
                info=os.fstat(f.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>16*1024*1024:raise ExperimentError('Unsafe scorer asset')
                body=f.read()
            assets.append({'target':asset['target'],'sha256':hashlib.sha256(body).hexdigest()})
        contract['assets']=assets
        identities.append({'contract':contract,'argv':check['argv'],'cwd':check['cwd'],'network':check['network']})
    # Multiple structured checks remain diagnostic; numeric comparison needs a single score.
    if len(identities)!=1:raise ExperimentError('Application MVP requires one structured scorer per case')
    return identities


def validate(path,lab,endpoint_path=None,catalog=None):
    path=Path(path).absolute();value=read_json(path);base=path.parent
    if value.get('schema')==3:
        if endpoint_path is not None:raise ExperimentError('Indexed experiment cannot accept an endpoint override')
        import indexed_experiments
        return indexed_experiments.validate(path,lab,catalog)
    required=('schema','name','baseline','repetitions','cases','variants','budgets','execution','policies')
    if type(value.get('schema')) is not int or value['schema'] not in (1,2):raise ExperimentError('Experiment schema 1 or 2 required')
    fields=required+('concurrency',) if value['schema']==2 else required
    object_fields(value,fields,fields)
    concurrency=parallel_contract.validate(value['concurrency']) if value['schema']==2 else None
    label(value['name']);label(value['baseline'])
    if type(value['repetitions']) is not int or not 1<=value['repetitions']<=10:raise ExperimentError('repetitions must be 1..10')
    default_budget=budget(value['budgets'])
    execution=copy.deepcopy(value['execution'])
    object_fields(execution,('image','platform','resources','environment','network','profile','browser_sandbox_policy'),('image','platform','resources'))
    if execution.get('profile', 'core') not in ('core', 'browser'):
        raise ExperimentError('Invalid runtime profile')
    if execution.get('browser_sandbox_policy', 'docker-default') != 'docker-default':
        execution['browser_security'] = browser_security.selection(execution.get('profile','core'), execution['browser_sandbox_policy'], execution['platform'])
    if not isinstance(execution['image'],str) or not re.fullmatch(r'sha256:[a-f0-9]{64}',execution['image']):raise ExperimentError('Explicit immutable image ID required; qualify a trusted image first')
    if execution['platform'] not in ('linux/arm64','linux/amd64'):raise ExperimentError('Explicit supported native platform required')
    execution['resources']=resources.validate_policy(read_json(input_path(base,execution['resources'])))
    if execution.get('environment'):execution['environment']=lab.load_environment(input_path(base,execution['environment']))
    execution.setdefault('network','bridge')
    if not isinstance(execution['network'],str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',execution['network']):raise ExperimentError('Invalid Docker network name')
    policies=copy.deepcopy(value['policies'])
    object_fields(policies,('primary_attempt','assistance','on_failure','max_attempts'),('primary_attempt','assistance','on_failure','max_attempts'))
    if policies['primary_attempt']!='first' or policies['assistance']!='exclude' or policies['on_failure'] not in ('continue','stop') or type(policies['max_attempts']) is not int or not 1<=policies['max_attempts']<=3:
        raise ExperimentError('Supported policies: first primary, exclude assistance, continue/stop failures, 1..3 attempts')
    if not isinstance(value['cases'],list) or not 1<=len(value['cases'])<=8 or not isinstance(value['variants'],list) or not 2<=len(value['variants'])<=8:raise ExperimentError('Require 1..8 cases and 2..8 variants')
    if len(value['cases'])*len(value['variants'])*value['repetitions']>64:raise ExperimentError('At most 64 planned cells')
    if concurrency is not None and len(value['cases'])*len(value['variants'])*value['repetitions']>concurrency['max_pending']:
        raise ExperimentError('Frozen pending queue must cover the planned matrix')
    cases=[];seen=set()
    for case in value['cases']:
        object_fields(case,('name','project','plan','budgets'),('name','project','plan'))
        name=label(case['name'])
        if name in seen:raise ExperimentError('Duplicate case label')
        seen.add(name);project=input_path(base,case['project']).resolve()
        if not project.is_dir() or project in (Path('/'),Path.home()):raise ExperimentError('Missing/unsafe project')
        planpath=input_path(base,case['plan']);plan=lab.validate_plan(read_json(planpath),planpath.parent)
        limits=budget(case.get('budgets',default_budget))
        for agent in plan['agents']:agent.update(limits)
        for section in ('setup','checks'):
            for stage in plan[section]:
                if stage['network']!='none':raise ExperimentError('Application MVP setup/scorers require network none')
                stage['timeout_seconds']=min(stage['timeout_seconds'],limits['timeout_seconds'])
        lab.check_project_contract(project,plan)
        cases.append({'name':name,'project':str(project),'plan':plan,'budgets':limits,'scorer':scorer_identity(plan)})
    variants=[];seen=set()
    for variant in value['variants']:
        object_fields(variant,('name','endpoint','prompt_suffix','agent_profile'),('name',))
        name=label(variant['name'])
        if name in seen:raise ExperimentError('Duplicate variant label')
        seen.add(name)
        selected=input_path(base,variant['endpoint']) if variant.get('endpoint') else Path(endpoint_path or lab_env.endpoint_path())
        endpoint=lab.load_endpoint(selected)
        suffix=variant.get('prompt_suffix','')
        if not isinstance(suffix,str) or len(suffix.encode())>8192:raise ExperimentError('Variant prompt_suffix must be at most 8 KiB')
        profile=agent_profiles.load(input_path(base,variant['agent_profile'])) if variant.get('agent_profile') else agent_profiles.builtin()
        variants.append({'name':name,'endpoint':endpoint,'prompt_suffix':suffix,'agent_profile':profile,'profile_explicit':bool(variant.get('agent_profile')),
                         'endpoint_origin':'explicit' if variant.get('endpoint') or endpoint_path else 'saved_environment'})
    if value['baseline'] not in seen:raise ExperimentError('Declared baseline is absent')
    result={'schema':value['schema'],'name':value['name'],'baseline':value['baseline'],'repetitions':value['repetitions'],
            'cases':cases,'variants':variants,'execution':execution,'policies':policies}
    if concurrency is not None:
        if concurrency['gateway']['queue_wait_seconds']+concurrency['gateway']['request_timeout_seconds']>=min(case['budgets']['timeout_seconds'] for case in cases):
            raise ExperimentError('Inference queue and request deadline must fit every Pi stage budget')
        if any(v['endpoint']!=variants[0]['endpoint'] for v in variants):
            raise ExperimentError('Parallel trials require one exact unchanged upstream endpoint')
        if execution['network']!='bridge':raise ExperimentError('Parallel mode requires dedicated trial bridge networks')
        result['concurrency']=concurrency
    # Variants change only endpoint and prompt; scorer/case/budgets are shared by construction.
    return result


def plan_path_map(experiment_id,pairs):
    namespace=uuid.UUID(experiment_id);paths={};owners={}
    for pair in pairs:
        pair=tuple(pair)
        if pair in paths:continue # Repetitions deliberately share one pair plan.
        name='plan:'+json.dumps(list(pair),ensure_ascii=False,separators=(',',':'))
        destination='inputs/plans/'+str(uuid.uuid5(namespace,name))+'.json'
        if destination in owners:raise ExperimentError('Frozen plan UUID destination collision')
        owners[destination]=pair;paths[pair]=destination
    return paths


def prepare(path,destination,lab,endpoint_path=None,session=None,catalog=None):
    if read_json(path).get('schema')==3:
        if endpoint_path is not None:raise ExperimentError('Indexed experiment cannot accept an endpoint override')
        import indexed_experiments
        return indexed_experiments.prepare(path,destination,lab,session,catalog)
    definition=validate(path,lab,endpoint_path)
    lexical=Path(destination).expanduser().absolute();root=lexical.resolve()
    for case in definition['cases']:
        project=Path(case['project'])
        if root==project or project in root.parents or lexical==project or project in lexical.parents:raise ExperimentError('Experiment evidence must be outside every project')
    if root.exists():raise ExperimentError('Experiment destination already exists; never replace it')
    runner_sha=provenance.execution({}, {},lab.ROOT)['runner_content_sha256']
    frozen_contracts = release_contracts.snapshot()
    experiment_id=str(uuid.uuid4());cells=[]
    plan_paths=plan_path_map(experiment_id,[(case['name'],variant['name'])
        for case in definition['cases'] for variant in definition['variants']])
    root.parent.mkdir(parents=True,exist_ok=True)
    temp=Path(tempfile.mkdtemp(prefix='.experiment-prepare-',dir=root.parent))
    try:
        inputs=temp/'inputs';inputs.mkdir()
        source_receipts={}
        for case in definition['cases']:
            name=case['name'];source=Path(case['project']);frozen=inputs/'sources'/name
            frozen.parent.mkdir(parents=True,exist_ok=True)
            before=lab.tree_hashes(source)
            copied=lab.snapshot(source,frozen,[],256)
            if before!=lab.tree_hashes(source):raise ExperimentError('Source changed during freezing')
            source_receipts[name]={'source_sha256':provenance.digest(before),'snapshot_sha256':provenance.digest(lab.tree_hashes(frozen)),'copy':copied}
            for variant in definition['variants']:
                plan=agent_profiles.apply(case['plan'],variant['agent_profile'])
                for agent in plan['agents']:
                    if variant['prompt_suffix']:agent['prompt']+='\n\nDeclared variant instruction:\n'+variant['prompt_suffix']
                for index,check in enumerate(plan['checks']):
                    contract=check['scorer'];scorerroot=inputs/'scorers'/name/str(index)
                    if not scorerroot.exists():
                        scorerroot.parent.mkdir(parents=True,exist_ok=True);receipt=scoring.freeze(contract,scorerroot)
                        expected={x['target']:x['sha256'] for x in case['scorer'][index]['contract']['assets']}
                        if receipt['assets']!=expected:raise ExperimentError('Scorer changed during freezing')
                    for asset in contract['assets']:asset['source']=str(Path('../scorers')/name/str(index)/asset['target'])
                plans=inputs/'plans';plans.mkdir(exist_ok=True)
                controls.atomic(temp/plan_paths[(name,variant['name'])],plan,0o444)
        endpoints=inputs/'endpoints';endpoints.mkdir()
        for variant in definition['variants']:
            controls.atomic(endpoints/(variant['name']+'.json'),variant['endpoint'],0o444)
            directory=inputs/'profiles'/variant['name'];directory.parent.mkdir(exist_ok=True)
            agent_profiles.freeze(variant['agent_profile'],directory)
        if definition['schema']==2:controls.atomic(inputs/'concurrency.json',definition['concurrency'],0o444)
        controls.atomic(inputs/'resources.json',definition['execution']['resources'],0o444)
        if definition['execution'].get('environment'):controls.atomic(inputs/'environment.json',definition['execution']['environment'],0o444)
        for case in definition['cases']:
            for variant in definition['variants']:
                for repetition in range(definition['repetitions']):
                    namespace=uuid.UUID(experiment_id)
                    case_id=str(uuid.uuid5(namespace,'case:'+case['name']));variant_id=str(uuid.uuid5(namespace,'variant:'+variant['name']))
                    trial_id=str(uuid.uuid5(namespace,case_id+':'+variant_id+':'+str(repetition)))
                    configuration={'source':source_receipts[case['name']], 'scorer':case['scorer'],
                                   'endpoint':{k:v for k,v in variant['endpoint'].items() if k!='api_key_env'},
                                   'plan':read_json(temp/plan_paths[(case['name'],variant['name'])]),
                                   'execution':definition['execution'],'budgets':case['budgets'],'profile_sha256':agent_profiles.identity(variant['agent_profile']),'runner_content_sha256':runner_sha}
                    if definition['schema']==2:configuration['concurrency']=definition['concurrency']
                    cells.append({'trial_id':trial_id,'case_id':case_id,'variant_id':variant_id,'case':case['name'],'variant':variant['name'],
                                  'repetition':repetition,'configuration_digest':provenance.digest(configuration),
                                  'source':'inputs/sources/'+case['name'],'plan':plan_paths[(case['name'],variant['name'])],
                                  'endpoint':'inputs/endpoints/'+variant['name']+'.json','endpoint_origin':variant['endpoint_origin'],
                                  'scorer_identity':provenance.digest(case['scorer']),'agent_profile':'inputs/profiles/'+variant['name']+'/profile.json',
                                  'agent_profile_id':variant['agent_profile']['id'],'agent_profile_sha256':agent_profiles.identity(variant['agent_profile']),
                                  'profile_explicit':variant['profile_explicit'],'budgets':case['budgets'],'initial_status':'planned',
                                  'plan_sha256':provenance.digest(lab.validate_plan(read_json(temp/plan_paths[(case['name'],variant['name'])]),(root/plan_paths[(case['name'],variant['name'])]).parent,variant['agent_profile']))})
        if definition['schema']==2:
            case_order={c['name']:i for i,c in enumerate(definition['cases'])};variant_order={v['name']:i for i,v in enumerate(definition['variants'])}
            cells.sort(key=lambda c:(c['repetition'],variant_order[c['variant']],case_order[c['case']]))
        metadata={'schema':definition['schema'],'document_type':'experiment','experiment_id':experiment_id,'name':definition['name'],
                  'baseline':definition['baseline'],'repetitions':definition['repetitions'],'policies':definition['policies'],
                  'execution':{k:v for k,v in definition['execution'].items() if k not in ('resources','environment')},
                  'profile':'explicit-agent-profiles' if any(v['profile_explicit'] for v in definition['variants']) else 'builtin-only','created_at':controls.now(),'source_receipts':source_receipts,'runner_content_sha256':runner_sha,'prepared_root':str(root),
                  'release_contracts':frozen_contracts}
        if definition['schema']==2:metadata['concurrency']=definition['concurrency']
        controls.atomic(temp/'experiment.json',metadata,0o444)
        controls.atomic(temp/'matrix.json',{'schema':definition['schema'],'document_type':'trial_matrix','experiment_id':experiment_id,'cells':cells},0o444)
        hashes=lab.tree_hashes(inputs,include_ignored=True)
        hashes={str(Path('inputs')/k):v for k,v in hashes.items()}
        for name in ('experiment.json','matrix.json'):hashes[name]=lab.tree_hashes(temp/name,include_ignored=True)['.']
        controls.atomic(temp/'integrity.json',{'schema':1,'files':hashes,'fingerprint':provenance.digest(hashes)},0o444)
        state={'schema':definition['schema'],'status':'prepared'}
        state.update(active_attempts={}) if definition['schema']==2 else state.update(active_attempt_id=None)
        controls.atomic(temp/'state.json',state)
        # All planned cells and frozen inputs exist before the directory becomes executable.
        temp.rename(root)
    finally:
        if temp.exists():shutil.rmtree(temp)
    return {'experiment':str(root),'experiment_id':experiment_id,'planned':len(cells),'fingerprint':provenance.digest(hashes)}


def verify_plan_ownership(root,metadata,matrix,manifest,lab):
    pairs=[(label(cell['case']),label(cell['variant'])) for cell in matrix['cells']]
    expected=plan_path_map(metadata['experiment_id'],pairs)
    by_pair={};owners={}
    for cell,pair in zip(matrix['cells'],pairs):
        path=cell.get('plan')
        if not isinstance(path,str):raise ExperimentError('Missing frozen plan path')
        try:lab.safe_relative(path)
        except lab.LabError as exc:raise ExperimentError('Escaping frozen plan path') from exc
        legacy='inputs/plans/'+pair[0]+'--'+pair[1]+'.json'
        if path not in (expected[pair],legacy):raise ExperimentError('Frozen plan path does not belong to its case/variant pair')
        if path in owners and owners[path]!=pair:raise ExperimentError('Cross-pair frozen plan alias rejected')
        if pair in by_pair and by_pair[pair]!=path:raise ExperimentError('Inconsistent repetition plan paths')
        owners[path]=pair;by_pair[pair]=path
        if path not in manifest['files'] or not (root/path).is_file():raise ExperimentError('Missing frozen plan: '+path)
    normalized={}
    for cell,pair in zip(matrix['cells'],pairs):
        profile_path=cell.get('agent_profile')
        if profile_path is None:
            profile=agent_profiles.builtin() # Unambiguous older built-in archives.
        else:
            try:lab.safe_relative(profile_path)
            except (lab.LabError,TypeError) as exc:raise ExperimentError('Unsafe frozen profile path') from exc
            if profile_path not in manifest['files']:raise ExperimentError('Missing frozen agent profile')
            profile=agent_profiles.load(root/profile_path)
        key=(cell['plan'],agent_profiles.identity(profile))
        if key not in normalized:
            # Normalized scorer paths retain the original prepared root for
            # portable archive inspection. Execution still rejects moved roots.
            base=(Path(metadata['prepared_root'])/cell['plan']).parent
            plan=read_json(root/cell['plan'])
            if (not isinstance(plan,dict) or not isinstance(plan.get('agents'),list)
                or any(not isinstance(agent,dict) or 'prompt_file' in agent for agent in plan['agents'])):
                raise ExperimentError('Frozen plans require inline agent prompts')
            normalized[key]=provenance.digest(lab.validate_plan(plan,base,profile,external_bindings=metadata['schema']==3))
        if normalized[key]!=cell.get('plan_sha256'):raise ExperimentError('Frozen normalized plan hash mismatch')


def verify(root,lab):
    root=Path(root).absolute()
    if root.is_symlink() or not root.is_dir():raise ExperimentError('Expected parent-held experiment directory')
    manifest=read_json(root/'integrity.json')
    if provenance.digest(manifest['files'])!=manifest['fingerprint']:raise ExperimentError('Invalid experiment integrity fingerprint')
    for name,expected in manifest['files'].items():
        lab.safe_relative(name)
        current=root
        for part in Path(name).parts:
            current=current/part
            if current.is_symlink():raise ExperimentError('Frozen input link rejected')
        if lab.tree_hashes(current,include_ignored=True).get('.')!=expected:raise ExperimentError('Frozen experiment inputs changed: '+name)
    expected={name for name in manifest['files'] if name.startswith('inputs/')}
    actual={'inputs/'+name for name in lab.tree_hashes(root/'inputs',include_ignored=True)}
    if expected!=actual:raise ExperimentError('Frozen input set changed')
    metadata=read_json(root/'experiment.json');matrix=read_json(root/'matrix.json')
    if type(metadata.get('schema')) is not int or metadata['schema'] not in (1,2,3) or matrix.get('schema')!=metadata['schema']:
        raise ExperimentError('Unsupported experiment/matrix schema')
    if metadata['schema']==2:
        contract=parallel_contract.validate(metadata.get('concurrency'))
        if 'inputs/concurrency.json' not in manifest['files'] or read_json(root/'inputs/concurrency.json')!=contract:
            raise ExperimentError('Frozen concurrency contract mismatch')
    elif 'concurrency' in metadata and not (metadata['schema']==3 and metadata.get('mode')=='parallel'):
        raise ExperimentError('Serial experiment cannot acquire parallel mode')
    if metadata['schema']==3:
        import indexed_contract
        selected=indexed_contract.helper_contract(metadata.get('indexed_execution'))
        if metadata.get('mode')=='parallel':indexed_contract.parallel(metadata.get('concurrency'))
        if read_json(root/'inputs/indexed-contract.json')!=selected:raise ExperimentError('Indexed contract changed')
        for cell in matrix['cells']:
            bindingpath=cell.get('inference_bindings')
            if bindingpath not in manifest['files']:raise ExperimentError('Missing frozen inference bindings')
            bindings=read_json(root/bindingpath)
            plan=read_json(root/cell['plan']);names=[a['name'] for a in plan['agents']]
            if not isinstance(bindings,dict) or set(bindings)!=set(names):raise ExperimentError('Ambiguous stage bindings')
            for binding in bindings.values():
                selected_binding=copy.deepcopy(binding);authority=selected_binding.pop('authority_id',None)
                indexed_contract.identity(authority);indexed_contract.entry(selected_binding,lab.normalize_endpoint)
            import indexed_experiments
            if cell['configuration_digest']!=indexed_experiments.cell_digest(root,metadata,cell,bindings):raise ExperimentError('Indexed configuration identity mismatch')
            first=bindings[plan['agents'][0]['name']]['configuration']['endpoint']
            if read_json(root/cell['endpoint'])!=first:raise ExperimentError('Indexed first-stage endpoint mismatch')
    if metadata['experiment_id']!=matrix['experiment_id']:raise ExperimentError('Matrix identity mismatch')
    verify_plan_ownership(root,metadata,matrix,manifest,lab)
    return metadata,matrix


def add_parser(sub):
    run=sub.add_parser('experiment-run',help='Execute the frozen serial or explicitly selected two-trial matrix')
    run.add_argument('--experiment',required=True);run.add_argument('--session')
    resume=sub.add_parser('experiment-resume',help='Reconcile abandoned attempts; run pending cells and only explicitly selected fresh retries')
    resume.add_argument('--experiment',required=True);resume.add_argument('--session');resume.add_argument('--retry-trial',help='Explicit trial UUID; first attempt remains primary')
    export=sub.add_parser('experiment-export',help='Write deterministic complete planned-cell JSONL inside the experiment')
    export.add_argument('--experiment',required=True)
    export.add_argument('--public',action='store_true',help='Indexed-only allowlisted opaque export; excludes private inventory')
    report=sub.add_parser('experiment-report',help='Write complete JSONL and primary/cohort JSON/Markdown comparisons')
    report.add_argument('--experiment',required=True)
    for name in ('validate-experiment','experiment-prepare'):
        p=sub.add_parser(name,help='Validate schema-1 serial or schema-2 parallel application inputs' if name=='validate-experiment' else 'Freeze all inputs and persist the complete trial matrix')
        p.add_argument('--definition',required=True);p.add_argument('--endpoint',help='Explicit common endpoint; otherwise saved environment, offline validation only')
        p.add_argument('--catalog-dir');p.add_argument('--secrets-dir')
        if name=='experiment-prepare':
            p.add_argument('--experiment-dir',required=True);p.add_argument('--session')


def command(args,lab):
    if args.op in ('experiment-run','experiment-resume'):
        result=execute(args.experiment,lab,args.session,resume=args.op=='experiment-resume',retry_trial=getattr(args,'retry_trial',None));print(json.dumps(result,indent=2));return result['exit_code']
    if args.op=='experiment-report':
        import comparisons
        root=Path(args.experiment);rows=ledger_rows(root,lab);metadata=read_json(root/'experiment.json')
        report=comparisons.comparison(metadata,rows,comparisons.expected_contracts(root,metadata,rows,lab))
        export_ledger(root,lab);controls.atomic(root/'comparison.json',report)
        atomic_bytes(root/'comparison.md',comparisons.markdown(report).encode())
        print(json.dumps({'comparison':str(root/'comparison.json'),'markdown':str(root/'comparison.md'),'trials':str(root/'trials.jsonl')}));return 0
    if args.op=='experiment-export':
        print(json.dumps(export_ledger(args.experiment,lab,public=getattr(args,'public',False)),indent=2));return 0
    if args.op=='validate-experiment':
        catalog=None
        if read_json(args.definition).get('schema')==3:
            from inference_catalog import Catalog
            catalog=Catalog(lab.normalize_endpoint,args.catalog_dir,args.secrets_dir)
        definition=validate(args.definition,lab,args.endpoint,catalog)
        print(json.dumps({'valid':True,'planned':len(definition['cases'])*len(definition['variants'])*definition['repetitions'],'profile':'builtin-only'}))
    else:
        catalog=None
        if read_json(args.definition).get('schema')==3:
            from inference_catalog import Catalog
            catalog=Catalog(lab.normalize_endpoint,args.catalog_dir,args.secrets_dir)
        print(json.dumps(prepare(args.definition,args.experiment_dir,lab,args.endpoint,getattr(args,'session',None),catalog),indent=2))
    return 0

# One controller per experiment, independent of the global per-runtime admission lock.
import contextlib
import fcntl
import platform
import outcomes


@contextlib.contextmanager
def controller_lock(root):
    fd=os.open(Path(root)/'controller.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise ExperimentError('Unsafe experiment controller lease')
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise ExperimentError('Another controller owns this experiment') from None
        yield
    finally:
        os.close(fd)


def directory(root,name):
    current=Path(root)
    for part in Path(name).parts:
        if part in ('.','..') or Path(name).is_absolute():raise ExperimentError('Unsafe experiment record path')
        current=current/part
        if current.is_symlink():raise ExperimentError('Linked experiment record directory rejected')
        current.mkdir(exist_ok=True)
        if not current.is_dir():raise ExperimentError('Expected experiment record directory')
    return current


def attempt_intents(root,cell):
    folder=Path(root)/'attempts'/cell['trial_id']
    if not folder.exists():return []
    if folder.is_symlink():raise ExperimentError('Linked attempt directory')
    intents=[read_json(p) for p in sorted(folder.glob('*.json'))]
    if len({i['attempt_index'] for i in intents})!=len(intents):raise ExperimentError('Duplicate attempt index')
    for intent in intents:
        if intent['trial_id']!=cell['trial_id'] or not controls.valid_id(intent['attempt_id']) or not controls.valid_id(intent['run_id']):raise ExperimentError('Invalid attempt identity')
    intents=sorted(intents,key=lambda x:x['attempt_index'])
    if [i['attempt_index'] for i in intents]!=list(range(1,len(intents)+1)) or len(intents)>3:raise ExperimentError('Missing primary/gapped attempt indices')
    experiment_id=read_json(Path(root)/'experiment.json')['experiment_id']
    for index,intent in enumerate(intents):
        if intent['experiment_id']!=experiment_id or intent['configuration_digest']!=cell['configuration_digest'] or intent['retry_of_attempt_id']!=(intents[index-1]['attempt_id'] if index else None):raise ExperimentError('Attempt chain/configuration mismatch')
    return intents


def reserve_attempt(root,metadata,cell,index=1,previous=None):
    record=outcomes.initial()
    record.update(experiment_id=metadata['experiment_id'],trial_id=cell['trial_id'],case_id=cell['case_id'],variant_id=cell['variant_id'],
                  repetition=cell['repetition'],configuration_digest=cell['configuration_digest'],attempt_index=index,retry_of_attempt_id=previous)
    intent={k:record[k] for k in ('experiment_id','trial_id','run_id','attempt_id','attempt_index','retry_of_attempt_id','configuration_digest')}
    intent.update(schema=1,document_type='attempt_intent',initial_record=record,created_at=controls.now(),status='reserved')
    folder=directory(root,'attempts/'+cell['trial_id']);path=folder/(f'{index:04d}-'+record['attempt_id']+'.json')
    controls.atomic(path,intent)
    parent=os.open(folder,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(parent) # Reservation is durable before runtime admission.
    finally:os.close(parent)
    return intent,path


def trial_args(root,metadata,cell,lab,session):
    root=Path(root)
    argv=['run','--project',str(root/cell['source']),'--plan',str(root/cell['plan']),
          '--endpoint',str(root/cell['endpoint']),'--agent-profile',str(root/cell['agent_profile']),'--results-dir',str(root/'runs'),
          '--image',metadata['execution']['image'],'--platform',metadata['execution']['platform'],
          '--resources',str(root/'inputs/resources.json'),'--network',metadata['execution']['network']]
    argv += ['--profile', metadata['execution'].get('profile', 'core'), '--browser-sandbox-policy', metadata['execution'].get('browser_sandbox_policy', 'docker-default')]
    if (root/'inputs/environment.json').exists():argv+=['--environment',str(root/'inputs/environment.json')]
    args=lab.parser().parse_args(argv);args.session=session
    args._experiment_root = str(root)
    if metadata['schema']==3:
        args.endpoint=None;args.catalog_dir=metadata['catalog_root'];args.secrets_dir=metadata['credential_store']
        args._indexed_bindings=read_json(root/cell['inference_bindings']);args.inference_env=next(iter(args._indexed_bindings.values()))['id']
        args._indexed_contract=metadata['indexed_execution']
    # Core run_suite still acquires the same global admission lease for every trial.
    return args


def sealed_result(root,intent):
    path=Path(root)/'runs'/intent['run_id']/'result.json'
    if not path.exists():
        if intent.get('result_sha256') or intent.get('status')=='finalized':raise ExperimentError('Sealed attempt result missing')
        return None
    value=read_json(path)
    if not isinstance(value,dict):raise ExperimentError('Malformed sealed attempt result')
    if intent.get('result_sha256') and hashlib.sha256(path.read_bytes()).hexdigest()!=intent['result_sha256']:raise ExperimentError('Sealed attempt result changed')
    for field in ('experiment_id','trial_id','attempt_id','run_id','attempt_index','retry_of_attempt_id','configuration_digest'):
        if value.get(field)!=intent[field]:raise ExperimentError('Sealed result identity/configuration mismatch')
    if value.get('document_type')!='run_result' or value.get('schema')!=2 or value.get('sealed') is not True:raise ExperimentError('Incomplete/unsupported sealed attempt result')
    if not isinstance(value.get('status'),str) or value['status'] not in {'PASS','FAIL','BLOCKED','INTERRUPTED','ASSISTED','RECOVERED'}:raise ExperimentError('Invalid sealed attempt outcome')
    dimensions={'infrastructure':{'not_started','ready','failed'},
        'invocation':{'not_started','invalid','verified','recovered'},
        'scoring':{'not_started','running','completed','skipped','error','cancelled'},
        'task_result':{'unknown','pass','fail','partial'},
        'protected_inputs':{'unknown','unchanged','changed'},'assistance':{'autonomous','assisted'}}
    for section,allowed in dimensions.items():
        dimension=value.get(section)
        if (not isinstance(dimension,dict) or not isinstance(dimension.get('status'),str)
            or dimension['status'] not in allowed):raise ExperimentError('Malformed sealed attempt dimension: '+section)
    if (not isinstance(value['infrastructure'].get('phase'),str)
        or not isinstance(value.get('termination'),dict)
        or not isinstance(value['termination'].get('reason'),str)):
        raise ExperimentError('Malformed sealed attempt termination/infrastructure')
    try:
        derived=outcomes.status(value)
        rows=value['agents']+value['checks']
        valid_rows=isinstance(value['agents'],list) and isinstance(value['checks'],list) and all(
            isinstance(row,dict) and isinstance(row.get('process'),dict) for row in rows)
    except (KeyError,TypeError):raise ExperimentError('Malformed sealed attempt result') from None
    if not valid_rows or type(value.get('exit_code')) is not int or derived!=(value['status'],value['exit_code']):raise ExperimentError('Inconsistent sealed attempt outcome')
    return value


def cleanup_known(root,intent,result):
    recovery=Path(root)/'runs'/intent['run_id']/'cleanup-recovery.json'
    if recovery.exists():
        proof=read_json(recovery)
        if proof.get('run_id')==intent['run_id'] and proof.get('attempt_id')==intent['attempt_id'] and proof.get('cleanup_confirmed') is True:return True
    if result['termination']['reason']=='cleanup_error':return False
    if result.get('infrastructure',{}).get('phase')=='image' and result['infrastructure']['status']=='failed':return False
    run=Path(root)/'runs'/intent['run_id']
    for path in (run/'image-probes').glob('*.json'):
        if (read_json(path).get('process') or {}).get('cleanup_confirmed') is not True:return False
    for path in (run/'stages').glob('*/state.json'):
        state=read_json(path)
        if state.get('status')!='finalized' or state.get('cleanup_confirmed') is not True:return False
    return all(row.get('process',{}).get('cleanup_confirmed') is True for row in result['agents']+result['checks'])


def controller_state(root):
    try:value=read_json(Path(root)/'state.json')
    except (ValueError,OSError) as exc:raise ExperimentError('Missing/malformed experiment controller state') from exc
    if (not isinstance(value,dict) or type(value.get('schema')) is not int or value['schema'] not in (1,2)
        or not isinstance(value.get('status'),str) or value['status'] not in {'prepared','running','blocked','interrupted','completed','halted'}
        or (value['schema']==1 and ('active_attempt_id' not in value or value['active_attempt_id'] is not None and not controls.valid_id(value['active_attempt_id'])))
        or (value['schema']==2 and (not isinstance(value.get('active_attempts'),dict) or any(not controls.valid_id(k) or not isinstance(v,dict) or not controls.valid_id(v.get('trial_id')) or not controls.valid_id(v.get('run_id')) for k,v in value['active_attempts'].items())))
        or value.get('interruption_kind') not in (None,'explicit_controller_cancel')):
        raise ExperimentError('Malformed experiment controller state')
    return value


def stop_from_history(root,metadata,matrix,previous_state):
    """Reconciled sealed history, never a mutable view, controls permanent halt."""
    nonpass=False
    for cell in matrix['cells']:
        for intent in attempt_intents(root,cell):
            result=sealed_result(root,intent)
            if result is None:raise ExperimentError('Attempt result unavailable after reconciliation')
            if not cleanup_known(root,intent,result):raise ExperimentError('Attempt cleanup unconfirmed; no new reservation admitted')
            nonpass=nonpass or result['status']!='PASS'
    stop=metadata['policies']['on_failure']=='stop'
    if previous_state['status']=='halted' and (not stop or not nonpass):
        raise ExperimentError('Inconsistent halted controller state: no supporting stop-policy failure history')
    return stop and nonpass


def execute(root,lab,session=None,runner=None,resume=False,retry_trial=None,cleanup=None):
    root=Path(root).absolute()
    verify(root,lab) # Reject linked/invalid destinations before writing a controller lease.
    root=root.resolve()
    metadata=read_json(root/'experiment.json')
    if metadata['schema']==3 and metadata.get('mode')=='parallel':
        if runner is not None or cleanup is not None:raise ExperimentError('Indexed parallel does not accept a runtime bypass')
        import indexed_parallel
        return indexed_parallel.execute(root,lab,session,resume,retry_trial)
    if read_json(root/'experiment.json')['schema']==2:
        if runner is not None or cleanup is not None:raise ExperimentError('Parallel executor does not accept a serial runner or cleanup bypass')
        import parallel_execution
        return parallel_execution.execute(root,lab,session,resume,retry_trial)
    with controller_lock(root):
        metadata,matrix=verify(root,lab)
        existing=any(attempt_intents(root,cell) for cell in matrix['cells'])
        if existing and not resume:raise ExperimentError('Existing experiment attempts: execution will not silently repeat them; use experiment-resume')
        if metadata.get('runner_content_sha256')!=provenance.execution({}, {},lab.ROOT)['runner_content_sha256']:raise ExperimentError('Runner content changed; prepare a new experiment')
        if metadata.get('release_contracts') != release_contracts.snapshot():
            raise ExperimentError('Frozen Pi release contracts are missing or changed; prepare a new experiment')
        if metadata.get('prepared_root')!=str(root):raise ExperimentError('Experiment execution directory moved; prepare a new experiment')
        previous_state=controller_state(root)
        if resume:reconcile(root,metadata,matrix,lab,cleanup)
        halted=stop_from_history(root,metadata,matrix,previous_state)
        pending=[cell for cell in matrix['cells'] if not attempt_intents(root,cell)]
        selected=None
        if retry_trial:
            selected=next((cell for cell in matrix['cells'] if cell['trial_id']==retry_trial),None)
            if selected is None:raise ExperimentError('Retry trial UUID is not in the intended matrix')
            intents=attempt_intents(root,selected)
            if not intents or len(intents)>=metadata['policies']['max_attempts'] or sealed_result(root,intents[-1])['status']=='PASS':raise ExperimentError('Retry requires a failed/interrupted cell and remaining predeclared attempts')
        work=([selected] if selected else [])+([] if halted else pending)
        indexed_authorities=None
        if runner is None:
            if metadata['schema']==3:
                import indexed_experiments
                indexed_authorities=indexed_experiments.admit_work(root,metadata,work,lab,session)
            if metadata['execution']['platform']!='linux/'+lab.norm_arch(platform.machine()):raise ExperimentError('Experiment platform must be native; no emulation fallback')
            for cell in work:
                if cell['endpoint_origin']=='saved_environment':
                    approved=lab.load_endpoint(lab_env.require_ready(session))
                    frozen=lab.load_endpoint(root/cell['endpoint'])
                    if lab_env.fingerprint_of(approved)!=lab_env.fingerprint_of(frozen):raise ExperimentError('Confirmed saved environment differs from frozen configuration; prepare a new experiment')
            if work:
                admission_args = trial_args(root, metadata, work[0], lab, session)
                with resources.admission_lock(admission_args.lock_file, admission_args.lock_wait_seconds):
                    lab.require_host(admission_args)
                    image = lab.probe_image(admission_args, metadata['execution']['image'])
                    selected = lab.admit_image(image)
                    if selected != metadata['release_contracts'].get(selected['release']):
                        raise ExperimentError('Observed Pi contract differs from the frozen release registry')
                    for cell in work:
                        profile = agent_profiles.load(root / cell['agent_profile'])
                        agent_profiles.admit(profile, selected['release'])
                        lab.pi_contract.model_configuration(lab.load_endpoint(root / cell['endpoint']), selected['release'])
                # Admission is complete before any trial attempt can be reserved.
                controls.atomic(root/'admission.json', {
                    'schema': 1, 'image': image['id'], 'release_contract': selected,
                    'scope': 'Observed image/release admission; not a participant or model qualification'})
            runner=lab.run_suite
        directory(root,'runs');directory(root,'logs')
        state={'schema':1,'status':'running','active_attempt_id':None,'started_at':controls.now()}
        controls.atomic(root/'state.json',state)
        completed=0;exit_code=0
        try:
            for cell in work:
                verify(root,lab)
                previous=attempt_intents(root,cell)
                intent,path=reserve_attempt(root,metadata,cell,len(previous)+1,previous[-1]['attempt_id'] if previous else None)
                state['active_attempt_id']=intent['attempt_id'];controls.atomic(root/'state.json',state)
                args=trial_args(root,metadata,cell,lab,session)
                if indexed_authorities:args._indexed_redaction_keys=indexed_authorities['keys']
                with (root/'logs'/(intent['attempt_id']+'.txt')).open('w') as output,contextlib.redirect_stdout(output):
                    runner(args,initial_record=copy.deepcopy(intent['initial_record']))
                result=sealed_result(root,intent)
                if result is None:raise ExperimentError('Attempt result unavailable; later cells retained, no new runtime admitted')
                relative='runs/'+intent['run_id']+'/result.json'
                intent.update(status='finalized',result=relative,result_sha256=hashlib.sha256((root/relative).read_bytes()).hexdigest())
                controls.atomic(path,intent);completed+=1;state['active_attempt_id']=None;controls.atomic(root/'state.json',state)
                if not cleanup_known(root,intent,result):state['status']='blocked';exit_code=2;break
                if result['status']=='INTERRUPTED':state['status']='interrupted';exit_code=2;break
                if result['status']!='PASS' and metadata['policies']['on_failure']=='stop':state['status']='halted';exit_code=1;break
            else:state['status']='halted' if halted else 'completed'
            if halted and state['status']=='halted':exit_code=1
        except KeyboardInterrupt:
            state['status']='interrupted';state['interruption_kind']='explicit_controller_cancel';exit_code=2
        except Exception:
            state['status']='blocked';controls.atomic(root/'state.json',state)
            raise
        controls.atomic(root/'state.json',state)
        return {'schema':1,'experiment_id':metadata['experiment_id'],'status':state['status'],'planned':len(matrix['cells']),
                'completed_this_call':completed,'exit_code':exit_code}


def cleanup_owned(root,intent,metadata,lab):
    """Stop only independently matched parent-registered containers, under the host admission lease."""
    run=Path(root)/'runs'/intent['run_id'];owned=[]
    for path in (run/'stages').glob('*/descriptor.json'):
        desc=read_json(path)
        if desc.get('run_id')!=intent['run_id'] or desc.get('attempt_id')!=intent['attempt_id'] or desc.get('stage_id')!=path.parent.name or not controls.valid_id(desc['stage_id']):raise ExperimentError('Invalid abandoned stage identity')
        expected=run/'controls'/desc['stage_id']
        if Path(desc['control']).resolve()!=expected.resolve():raise ExperimentError('Invalid abandoned stage control source')
        state=read_json(path.parent/'state.json')
        owned.append({'container':desc['container'],'control':str(expected.resolve()),'image':metadata['execution']['image'],
                      'already_clean':state.get('status')=='finalized' and state.get('cleanup_confirmed') is True})
    for path in (run/'image-probes').glob('*.json'):
        desc=read_json(path)
        if any(desc.get(k)!=intent[k] for k in ('run_id','attempt_id')) or desc.get('image')!=metadata['execution']['image']:raise ExperimentError('Invalid abandoned probe identity')
        owned.append({'container':desc['container'],'control':desc['control'],'image':desc['image'],
                      'already_clean':(desc.get('process') or {}).get('cleanup_confirmed') is True})
    if not owned and run.exists():
        progress=read_json(run/'summary.json') if (run/'summary.json').exists() else intent['initial_record']
        if progress.get('probe_receipt_contract')!=1:raise ExperimentError('Unregistered legacy runtime ownership cannot be proven; no cleanup or new trial admitted')
    observations=[]
    with resources.admission_lock(lab.default_lock_file(),0):
        for item in owned:
            name=item['container']
            if not re.fullmatch(r'pi-lab-(?:probe-)?[a-f0-9]{10,12}',name):raise ExperimentError('Unsafe abandoned container name')
            if item['already_clean']:observations.append({'container':name,'cleanup':'previously_confirmed'});continue
            result=lab.command(['docker','container','inspect',name,'--format','{{json .Mounts}}\n{{.Image}}'],timeout=10,required=False)
            if result.returncode:
                if 'No such container' not in result.stderr:raise ExperimentError('Cannot independently inspect abandoned writer; pending cells retained')
                observations.append({'container':name,'cleanup':'confirmed_absent'});continue
            lines=result.stdout.splitlines();mounts=json.loads(lines[0])
            if len(lines)!=2 or lines[1]!=item['image'] or not any(m.get('Destination')=='/opt/pi-control' and m.get('Source')==item['control'] and m.get('RW') is False for m in mounts):raise ExperimentError('Abandoned container ownership did not match; refusing to remove it')
            removed=lab.command(['docker','rm','--force',name],timeout=30,required=False)
            if removed.returncode:raise ExperimentError('Abandoned writer cleanup failed; pending cells retained')
            absent=lab.command(['docker','container','inspect',name],timeout=10,required=False)
            if absent.returncode==0 or 'No such container' not in absent.stderr:raise ExperimentError('Abandoned writer absence unconfirmed')
            observations.append({'container':name,'cleanup':'matched_removed_and_absent'})
        # Keep sensitive filesystem cleanup under the same host writer lease.
        import application_credentials
        application_credentials.recover(run)
    return observations


def reconcile(root,metadata,matrix,lab,cleanup=None):
    cleanup=cleanup or cleanup_owned
    controller_state=read_json(Path(root)/'state.json')
    for cell in matrix['cells']:
        for intent in attempt_intents(root,cell):
            run=Path(root)/'runs'/intent['run_id'];path=Path(root)/'attempts'/cell['trial_id']/(f"{intent['attempt_index']:04d}-"+intent['attempt_id']+'.json')
            incomplete=None
            try:result=sealed_result(root,intent)
            except json.JSONDecodeError:
                if intent.get('result_sha256') or intent.get('status')=='finalized':raise ExperimentError('Sealed attempt result corrupted; original attempt will not be replaced') from None
                bad=run/'result.json';archive=run/('interrupted-result-'+str(uuid.uuid4())+'.json')
                os.rename(bad,archive);incomplete={'path':str(archive.relative_to(root)),'sha256':hashlib.sha256(archive.read_bytes()).hexdigest()};result=None
            if result is not None:
                if not cleanup_known(root,intent,result):
                    observations=cleanup(root,intent,metadata,lab)
                    controls.atomic(run/'cleanup-recovery.json',{'schema':1,'run_id':intent['run_id'],'attempt_id':intent['attempt_id'],
                        'cleanup_confirmed':True,'observations':observations,'observed_at':controls.now()})
            else:
                observations=cleanup(root,intent,metadata,lab)
                if (run/'summary.json').exists():
                    try:record=read_json(run/'summary.json')
                    except json.JSONDecodeError:record=copy.deepcopy(intent['initial_record'])
                    if any(record.get(k)!=intent[k] for k in ('run_id','attempt_id','experiment_id','trial_id','configuration_digest')):raise ExperimentError('Abandoned progress identity mismatch')
                    attempt=outcomes.Attempt.attach_unsealed(run,record)
                else:
                    args=trial_args(root,metadata,cell,lab,None)
                    if run.exists():
                        record=copy.deepcopy(intent['initial_record']);attempt=outcomes.Attempt.attach_unsealed(run,record)
                    else:attempt=outcomes.Attempt(args,copy.deepcopy(intent['initial_record']))
                record=attempt.record
                explicit_cancel=controller_state.get('interruption_kind')=='explicit_controller_cancel' and (controller_state.get('active_attempt_id')==intent['attempt_id'] or intent['attempt_id'] in controller_state.get('active_attempts',{}))
                record['controller_interruption']={'kind':'explicit_controller_cancel' if explicit_cancel else 'controller_lost',
                    'cleanup_confirmed':True,'observations':observations,'reconciled_at':controls.now(),'incomplete_result':incomplete}
                if explicit_cancel:
                    attempt.cancel()
                    if record['scoring']['status']!='completed':record['task_result'].update(status='unknown',score=None,test_counts=None)
                else:
                    if record['termination']['reason'] in ('not_started','completed'):record['termination'].update(reason='process_error',trigger='controller_lost')
                    if record['scoring']['status'] in ('not_started','running'):
                        record['scoring'].update(status='error' if record['scoring']['status']=='running' else 'skipped',reason='controller_lost')
                        record['task_result'].update(status='unknown',score=None,test_counts=None)
                result=attempt.finalize()
                controls.atomic(run/'cleanup-recovery.json',{'schema':1,'run_id':intent['run_id'],'attempt_id':intent['attempt_id'],
                    'cleanup_confirmed':True,'observations':observations,'observed_at':controls.now()})
            intent.update(status='finalized',result='runs/'+intent['run_id']+'/result.json',result_sha256=hashlib.sha256((run/'result.json').read_bytes()).hexdigest())
            controls.atomic(path,intent)


def ledger_rows(root,lab):
    metadata,matrix=verify(root,lab);rows=[]
    for cell in matrix['cells']:
        intents=attempt_intents(root,cell)
        rows.append({'schema':1,'document_type':'trial_record','experiment_id':metadata['experiment_id'],**cell,
                     'primary_attempt_id':intents[0]['attempt_id'] if intents else None,
                     'attempts':[{'attempt_id':intent['attempt_id'],'attempt_index':intent['attempt_index'],'retry_of_attempt_id':intent['retry_of_attempt_id'],
                                  'status':intent['status'],'result_path':'runs/'+intent['run_id']+'/result.json',
                                  'evidence_path':'runs/'+intent['run_id']+'/result.json' if (Path(root)/'runs'/intent['run_id']/'result.json').exists() else 'attempts/'+cell['trial_id']+'/'+f"{intent['attempt_index']:04d}-"+intent['attempt_id']+'.json',
                                  'result':sealed_result(root,intent)} for intent in intents]})
    return rows


def atomic_bytes(path,body):
    path=Path(path)
    if path.is_symlink():raise ExperimentError('Linked export destination rejected')
    temp=path.with_name('.'+path.name+'-'+str(uuid.uuid4()))
    try:
        fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as f:f.write(body);f.flush();os.fsync(f.fileno())
        os.replace(temp,path)
        parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(parent)
        finally:os.close(parent)
    finally:temp.unlink(missing_ok=True)


def export_ledger(root,lab,public=False):
    root=Path(root);rows=ledger_rows(root,lab)
    if public:
        if read_json(root/'experiment.json')['schema']!=3:raise ExperimentError('Public indexed export requires schema 3')
        import indexed_reporting
        rows=indexed_reporting.public_rows(rows,lambda row:read_json(root/row['inference_bindings']),lambda row:[task['name'] for task in read_json(root/row['plan'])['agents']])
    body=''.join(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n' for row in rows).encode()
    path=root/('public-trials.jsonl' if public else 'trials.jsonl')
    atomic_bytes(path,body)
    return {'path':str(path),'cells':len(rows),'sha256':hashlib.sha256(body).hexdigest()}
