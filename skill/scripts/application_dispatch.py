"""Dispatch frozen application IR with separate invocation, task and report gates."""
import copy
import hashlib
import os
from pathlib import Path
import shutil

import agent_profiles
import application_contracts as c
import application_completion as completion
import application_credentials as credentials
import application_preparation as preparation
from application_client import Authority
from application_execution_authority import ReviewedAuthority
import application_execution
from application_evidence import open_directory, read_file, _parent
import lab_env
import native_budget_reporting
import provenance
import scoring
import secret_store
import stage_control as controls


def _variant_cell(args,attempt,selected,lab):
    context=getattr(args,'_application_variant_context',None)
    variant=selected['manifest']['document_type']=='application_variant_input_manifest'
    if not variant:
        if context is not None:raise ValueError('Standalone artifact cannot acquire variant ownership')
        return None
    c.exact(context,{'experiment_root','experiment_id','trial_id','variant_id','configuration_digest'},'/variant_context')
    import experiments
    root=Path(context['experiment_root']).absolute();metadata,matrix=experiments.verify(root,lab)
    cell=next((cell for cell in matrix['cells'] if cell['trial_id']==context['trial_id']),None)
    if (metadata.get('document_type')!='application_experiment' or cell is None
            or metadata['experiment_id']!=context['experiment_id'] or cell['variant']!=context['variant_id']
            or cell['configuration_digest']!=context['configuration_digest']
            or cell['plan_sha256']!=selected['plan']['plan_sha256']
            or attempt.record.get('trial_id')!=cell['trial_id']
            or Path(args.compiled_plan).absolute()!=root/cell['compiled_plan']):
        raise ValueError('Frozen variant does not belong to this trial')
    return root,metadata,cell


def prepare(args,attempt,lab):
    if not args.project or args.in_place or args.plan or args.endpoint or args.agent_profile or args.inference_env:
        raise ValueError('Compiled application execution requires an isolated project and no competing selectors')
    forbidden={'--image','--profile','--platform','--browser-sandbox-policy','--environment','--resources',
        '--memory','--cpus','--pids-limit','--jobs','--network','--allow-browser-no-sandbox','--software-webgl',
        '--allow-setup-network','--allow-check-network','--score-after-cancel','--uid','--gid','--host-gateway'}
    if forbidden & set(getattr(args,'_explicit_options',())):
        raise ValueError('Compiled runtime and policy overrides are not permitted')
    selected=preparation.load_compiled(args.compiled_plan,verify_runner=True)
    owner=_variant_cell(args,attempt,selected,lab)
    root=Path(selected['root']);frozen=attempt.root/'compiled';frozen.mkdir(mode=0o700)
    manifest=selected['manifest']
    for relative in [*manifest['files'],'input-manifest.json']:
        body=agent_profiles.read_asset(root/relative,32*1024*1024)
        if relative in manifest['files'] and hashlib.sha256(body).hexdigest()!=manifest['files'][relative]:
            raise ValueError('Prepared source changed while freezing')
        target=frozen/relative;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        with target.open('xb') as output:output.write(body)
        target.chmod(0o400)
    copied=preparation.load_compiled(frozen/'plan.json',verify_runner=True)
    if copied['plan']!=selected['plan'] or copied['manifest']!=manifest:
        raise ValueError('Prepared selection changed while freezing')
    selected=copied;plan=selected['plan'];runtime=plan['runtime'];args._compiled_application=selected
    frozen_runtime=lab.trusted_runtime(attempt.root)
    expected_runtime={path[len('runtime/'):]:digest for path,digest in manifest['runner']['files'].items() if path.startswith('runtime/')}
    actual_runtime={path.relative_to(frozen_runtime).as_posix():hashlib.sha256(agent_profiles.read_asset(path)).hexdigest()
                    for path in frozen_runtime.rglob('*') if path.is_file()}
    if actual_runtime!=expected_runtime:raise ValueError('Frozen runtime differs from compiled runner')
    args.image=runtime['image_id'];args.platform=runtime['platform'];args.profile=runtime['container_profile']
    args.browser_sandbox_policy=runtime['browser_sandbox_policy'] or 'docker-default'
    args._resource_request=copy.deepcopy(runtime['resources'])
    remote=getattr(args,'_parallel_session',None)
    if remote is not None:
        from parallel_dispatch import RemoteAdmission
        if type(remote) is not RemoteAdmission:raise ValueError('Unknown application admission owner')
        marker=remote.bootstrap.get('application')
        c.exact(marker,{'schema','plan_sha256','participant_keys_withheld'},'/application_admission')
        if type(marker['schema']) is not int or marker['schema']!=1 or marker['plan_sha256']!=plan['plan_sha256'] or marker['participant_keys_withheld'] is not True:
            raise ValueError('Parent application admission unavailable')
        if owner is None:raise ValueError('Remote application execution requires a frozen trial')
        args.network=remote.bootstrap['network']
    else:args.network='bridge'
    args.event_contract='settled';args.allow_browser_no_sandbox=False;args.software_webgl=False
    args._application_plan=copy.deepcopy(plan)
    names=[stage['id'] for stage in plan['stages']]
    attempt.record['application_execution']={'schema':1,'plan_sha256':plan['plan_sha256'],'required_stages':names}
    attempt.record['application_completion']=completion.run_projection([completion.blocked_stage(name,'prior_failure') for name in names])
    controls.atomic(attempt.root/'plan.json',plan)
    inference=c.loads(agent_profiles.read_asset(frozen/'inference.json'));args._application_inference=inference
    selections=inference['stages'] if inference['kind']=='variant' else {name:inference for name in names}
    if set(selections)!=set(names) or len({entry['kind'] for entry in selections.values()})!=1:
        raise ValueError('Ambiguous application inference owner')
    indexed=next(iter(selections.values()))['kind']=='indexed'
    endpoints={};keys={}
    if indexed:
        bindings=getattr(args,'_indexed_bindings',None)
        if remote is None:
            from inference_catalog import Catalog
            catalog=Catalog(lab.normalize_endpoint,args.catalog_dir,args.secrets_dir)
            catalog.outside(lab.ROOT,args.project,attempt.root)
            resolved={}
            for name in names:
                bound=copy.deepcopy(bindings[name]) if bindings is not None else catalog.freeze(selections[name]['catalog_entry']['id'],args.session)
                if {k:v for k,v in bound.items() if k!='authority_id'}!=selections[name]['catalog_entry']:
                    raise ValueError('Frozen indexed inference selection changed')
                resolved[name]=bound;keys[name]=catalog.admit(bound,args.session)
            args._indexed_bindings=resolved;args._indexed_plan_selection=True
        else:
            session=getattr(args,'_indexed_session',None)
            if session is None:raise ValueError('Parent indexed inference admission unavailable')
            args._indexed_bindings=copy.deepcopy(session.bindings);args._indexed_plan_selection=False
            for name in names:
                if {k:v for k,v in session.bindings[name].items() if k!='authority_id'}!=selections[name]['catalog_entry']:
                    raise ValueError('Parent indexed binding differs from frozen variant')
        args._indexed_application=True
        endpoints={name:copy.deepcopy(selections[name]['configuration']['endpoint']) for name in names}
    else:
        endpoints={name:copy.deepcopy(selections[name]['configuration']) for name in names}
        if owner is None:
            report=lab_env.evaluate(args.session,check=False,store=args.secrets_dir);saved=lab_env.load_saved()
            if report['state']!='ready' or saved is None or any(lab.normalize_endpoint(saved[0])!=endpoint for endpoint in endpoints.values()):
                raise ValueError('Frozen inference configuration requires its confirmed session')
        else:lab_env.resolve_session(args.session)
        if remote is None:keys={name:lab.endpoint_secret(endpoint,args) for name,endpoint in endpoints.items()}
    args._application_endpoints=endpoints;args._application_keys=keys
    args._application_endpoint=endpoints[names[0]];args._application_key=keys.get(names[0],'')
    if remote is not None:
        args._application_authority=None
        args._application_values=[remote.bootstrap['inference']['token'],*getattr(getattr(args,'_indexed_session',None),'redaction',[])]
    else:
        project=lab.checked_path(Path(args.project));lab.secret_store_outside(project,args)
        authorities={stage['inference_binding']['configuration_sha256']:{'reference':endpoints[stage['id']]['api_key_env'],'value':keys[stage['id']]} for stage in plan['stages']}
        authority=Authority(plan,args._application_endpoint,args._application_key,args.secrets_dir or secret_store.default_store(),project,attempt.root,
            inference_authorities=authorities)
        args._application_authority=authority;args._application_authorities=authorities
        args._application_values=list(dict.fromkeys(value for value in [*keys.values(),
            *(v for values in authority._values.values() for v in values.values()),
            *getattr(args,'_application_parent_values',())] if value))
        redactor=credentials.Redactor(args._application_values)
        if (redactor.contains(c.canonical(manifest)) or not credentials.workspace_inspected_clean(project,redactor)
                or not credentials.workspace_inspected_clean(frozen,redactor)):
            raise ValueError('Credential-bearing or uninspectable prepared inputs rejected')
    attempt.persist()


def _reserved_outputs(workspace,plan):
    for stage in plan['stages']:
        for relative in [stage['completion']['report_path'],*[a['path'] for a in stage['completion']['artifacts']]]:
            current=workspace
            for part in Path(relative).parts:
                current=current/part
                if current.is_symlink() or current.exists() and not current.is_dir():
                    raise ValueError('Declared output collides with original project input')
            if current.exists():raise ValueError('Declared output already exists')


def _copy_outputs(workspace,stage,context,values):
    """Parent-only publication into the stopped snapshot, never original project."""
    source=open_directory(context['report_root']);target=open_directory(workspace)
    redactor=credentials.Redactor(values);contents={}
    try:
        rows=[(a['path'],a['max_bytes'],a['id']) for a in stage['completion']['artifacts']]
        rows.append((stage['completion']['report_path'],65536,None))
        for relative,maximum,artifact_id in rows:
            try:body=read_file(source,relative,maximum)
            except FileNotFoundError:continue
            if redactor.contains(body):raise ValueError('Sensitive output rejected')
            parent,leaf=_parent(target,relative,create=True)
            try:
                fd=os.open(leaf,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
                with os.fdopen(fd,'wb') as output:output.write(body);output.flush();os.fsync(output.fileno())
                os.fsync(parent)
            finally:os.close(parent)
            if artifact_id is not None:contents[artifact_id]=body
        return contents
    finally:os.close(source);os.close(target)


def execute(args,attempt,lab):
    selected=args._compiled_application;plan=selected['plan'];manifest=selected['manifest'];root=Path(selected['root'])
    summary=attempt.record;runroot=attempt.root;project=lab.checked_path(Path(args.project))
    admission=args._application_authority;remote=getattr(args,'_parallel_session',None)
    if admission is not None:admission.revalidate()
    workspace=runroot/'workspace';summary['workspace']=str(workspace)
    lab.snapshot(project,workspace,args.exclude,args.max_project_mb)
    try:
        if admission is not None:admission.ensure_snapshot_clean()
        _reserved_outputs(workspace,plan)
    except ValueError:
        if not credentials.workspace_inspected_clean(workspace,credentials.Redactor(args._application_values)):
            shutil.rmtree(workspace)
        raise
    summary['infrastructure']['phase']='host';summary['host']=lab.require_host(args)
    if not application_execution._same_policy(args.resource_report['effective'],plan['runtime']['resources']):
        raise ValueError('Host capacity cannot preserve the frozen resource policy')
    args.frozen_browser_security=lab.browser_security.freeze(args,runroot/'browser-security')
    summary['browser_security']=copy.deepcopy(args.frozen_browser_security)
    image=lab.probe_image(args,args.image);summary['image']=image
    args.release_contract=lab.admit_image(image,plan['runtime']['pi_release']);args.observed_pi_version=args.release_contract['release']
    if image['id']!=plan['runtime']['image_id'] or image['platform']!=plan['runtime']['platform']:
        raise ValueError('Observed runtime differs from compiled runtime')
    summary['release_contract']=args.release_contract
    observation=c.loads(agent_profiles.read_asset(root/'runtime-receipt.json'))
    browser_admission=observation['browser_admission']
    profile=agent_profiles.load(root/'profiles'/plan['stages'][0]['id']/'profile.json')
    agent_profiles.admit(profile,args.observed_pi_version)
    args.frozen_agent_profile=agent_profiles.freeze(profile,runroot/'agent-profile')
    summary['agent_profile']={'id':profile['id'],'kind':profile['kind'],'sha256':agent_profiles.identity(profile),'loading':'unverified'}
    before=lab.tree_hashes(workspace);lab.save(runroot/'files-before.json',before)
    protected=list(before);lab.save(runroot/'protected-before.json',lab.protected_hashes(workspace,protected))
    summary['provenance']={'plan_sha256':plan['plan_sha256'],'input_manifest_sha256':manifest['manifest_sha256'],
        'runner_content_sha256':manifest['runner']['sha256'],'snapshot_sha256':provenance.digest(before),
        'configuration_sha256':provenance.digest({k:v for k,v in args._application_endpoint.items() if k!='api_key_env'}),
        'agent_profile':{'id':profile['id'],'sha256':agent_profiles.identity(profile),
                         'assets':{a['target']:a['sha256'] for a in profile['assets']}}}
    lab.trusted_runtime(runroot)
    checks=[];receipts={}
    for index,original in enumerate(plan['checks']):
        check={**copy.deepcopy(original),'name':original['id']};checks.append(check)
        if 'scorer' in check:
            contract=copy.deepcopy(check['scorer'])
            assets=[row for row in manifest['scorer_assets'] if row['check_id']==original['id']]
            contract['assets']=[{'source':str(root/row['path']),'target':row['target']} for row in assets]
            parent=runroot/'scorers';parent.mkdir(exist_ok=True)
            receipts[index]=scoring.freeze(contract,parent/str(index));lab.save(parent/(str(index)+'.json'),receipts[index])
    values=args._application_values
    boundary=lab.run_stage(args,image['id'],runroot,workspace,'boundary',['boundary'],network='none',redaction_secrets=values)
    attempt.process(boundary)
    if boundary['exit_code'] or boundary.get('cleanup_confirmed') is not True:raise ValueError('Application boundary admission failed')
    indexed=getattr(args,'_indexed_session',None)
    if indexed:
        summary['inference_admission']={'contract_sha256':provenance.digest(indexed.contract),
            'bindings_sha256':provenance.digest(indexed.bindings),'max_inflight':1,
            'upstream_keys_excluded':True,'scope':'parent-selected frozen indexed bindings'}
    elif remote:
        import experiments
        metadata=experiments.read_json(Path(args._experiment_root)/'experiment.json')
        summary['inference_admission']={'contract_sha256':provenance.digest(metadata['concurrency']),
                                       'max_inflight':1,'scope':'parent-owned frozen inference gateway'}
    endpoint=indexed.endpoint() if indexed else remote.endpoint(args._application_endpoint) if remote else args._application_endpoint
    key=lab.endpoint_secret(endpoint,args) if indexed or remote else args._application_key
    preflight=lab.run_stage(args,image['id'],runroot,workspace,'preflight',['preflight'],endpoint=endpoint,secret=key,timeout=150,redaction_secrets=values)
    attempt.process(preflight)
    if preflight['exit_code'] or preflight.get('cleanup_confirmed') is not True:raise ValueError('Application inference admission failed')
    summary['infrastructure'].update(status='ready',phase='agents')
    completed={};projections={};sealed_inputs={};any_failed=False;any_recovered=False
    incoming={(item['stage_id'],item['artifact_id']) for stage in plan['stages'] for item in stage['input_artifacts']}
    names=[stage['id'] for stage in plan['stages']]
    for index,stage in enumerate(plan['stages']):
        blocked=completion.dependency_status(plan,completed,stage['id'])
        if blocked:
            projection=completion.blocked_stage(stage['id'],blocked);projections[stage['id']]=projection
            completed[stage['id']]={'invocation_ok':False,'cleanup_ok':False,'completion':projection}
            continue
        if admission is not None:admission.revalidate()
        if indexed:
            endpoint,key=indexed.stage(stage['id'],args)
        elif remote:endpoint,key=remote.endpoint(args._application_endpoints[stage['id']]),lab.endpoint_secret(endpoint,args)
        else:endpoint,key=args._application_endpoints[stage['id']],args._application_keys[stage['id']]
        for value in [key,*getattr(indexed,'redaction',[])]:
            if value and value not in values:values.append(value)
        original=args._application_endpoints[stage['id']]
        authority=(None if remote else ReviewedAuthority(plan,original,args._application_keys[stage['id']],
            args.secrets_dir or secret_store.default_store(),project,runroot,browser_admission=browser_admission,
            sealed_inputs=sealed_inputs,inference_authorities=args._application_authorities,redaction_values=values,
            runner_files=manifest['runner']['files']))
        task={'name':stage['id'],'prompt':stage['effective_prompt'],'tools':stage['tools'],'tool_schemas':stage['tool_schemas'],
              'require_tools':[],'cwd':'.','access':'ro',**stage['limits']}
        actual_profile=agent_profiles.staged(args.frozen_agent_profile)
        extension=application_execution.extension_order_sha256(stage,actual_profile,runtime_root=runroot/'trusted-runtime')
        task['application_execution']={'schema':1,'plan_sha256':plan['plan_sha256'],'stage_id':stage['id'],
            'effective_prompt_sha256':hashlib.sha256(stage['effective_prompt'].encode()).hexdigest(),
            'tool_schema_sha256':c.digest(sorted(stage['tool_schemas'],key=lambda value:value['name'])),
            'profile_binding':stage['profile_binding'],'extension_order_sha256':extension}
        def retain_values(additional):
            for value in additional:
                if value and value not in values:values.append(value)
        args._application_execution={'plan':plan,'stage_id':stage['id'],'authority':authority,'redaction_sink':retain_values}
        label='agent-'+str(index+1)+'-'+stage['id'];summary['invocation']['attempted_stages']+=1
        summary['invocation']['status']='invalid';attempt.persist()
        result=lab.run_stage(args,image['id'],runroot,workspace,label,['agent'],task=task,endpoint=endpoint,secret=key,
                             access='ro',timeout=stage['limits']['timeout_seconds']+30,redaction_secrets=values)
        evidence=result.get('evidence',{});verified=evidence.get('completion_verified') is True
        any_recovered=any_recovered or evidence.get('invocation_status')=='recovered'
        attempt.process(result)
        projection=result['application_completion'];projections[stage['id']]=projection
        clean=result.get('cleanup_confirmed') is True and result.get('application_helper_cleanup',{}).get('safe_to_continue') is True
        completed[stage['id']]={'invocation_ok':verified,'cleanup_ok':clean,'completion':projection}
        summary['agents'].append({'name':stage['id'],'logs':label,'process':result,
            'invocation_verified':evidence.get('agent_invocation_verified') is True,'errors':evidence.get('errors',[]),
            **({'inference_binding':copy.deepcopy(args._indexed_binding)} if indexed else {})})
        summary['agent_profile'].setdefault('observed_stages',[]).append({'name':stage['id'],
            'segments':[{'segment_id':segment.get('segment_id'),**segment['evidence'].get('agent_profile',{})}
                        for segment in result.get('segments',[])]})
        if clean and projection['status']!='not_evaluated':
            contents=_copy_outputs(workspace,stage,result['application_completion_context'],values)
            sealed_inputs.update({(stage['id'],artifact_id):body for artifact_id,body in contents.items()
                                  if (stage['id'],artifact_id) in incoming})
        any_failed=any_failed or not verified
        summary['application_completion']=completion.run_projection([projections.get(name,completion.blocked_stage(name,'prior_failure')) for name in names])
        summary['native_tool_budgets']=native_budget_reporting.record_projection(summary,stage_names=names,required_stages=names)
        attempt.persist()
    summary['application_completion']=completion.run_projection([projections[name] for name in names])
    summary['native_tool_budgets']=native_budget_reporting.record_projection(summary,stage_names=names,required_stages=names)
    summary['invocation']['status']=('invalid' if any_failed or len(summary['agents'])!=len(names)
                                     else 'recovered' if any_recovered else 'verified')
    if summary['termination']['reason']=='not_started':summary['termination']['reason']='completed'
    summary['agent_profile']['loading']='observed' if summary['agents'] and all(row['process'].get('segments') for row in summary['agents']) and all(
        segment['evidence'].get('agent_profile',{}).get('loading')=='observed'
        for row in summary['agents'] for segment in row['process'].get('segments',[])) else 'unverified'
    # Scoring is independent of report completeness, after all writers stop.
    score_view={'checks':checks,'protected_paths':protected}
    lab.score_artifacts(args,attempt,score_view,image,workspace,receipts,redaction_secrets=values)
    summary['infrastructure']['phase']='finished';attempt.persist()
