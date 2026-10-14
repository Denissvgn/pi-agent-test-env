#!/usr/bin/env python3
"""Frozen indexed ARM64 campaign: offline intent, infrastructure, A, cleanup, B.

No native action occurs during freeze. Collection is a separate explicit command;
failed or begun campaigns cannot repeat. All operator data is private and keys
live solely in a disposable owner-only namespace outside projects/evidence.
"""
import argparse,copy,hashlib,json,os,secrets,shutil,sys,tempfile,time,uuid
from pathlib import Path
HERE=Path(__file__).resolve().parent;REPO=HERE.parents[1];SKILL=REPO/'skill'
sys.path[:0]=[str(SKILL/'scripts'),str(SKILL/'runtime'),str(HERE)]
import application_credentials,experiments,fixtures,indexed_contract,indexed_experiments
import inference_catalog,parallel as predecessor,pi_lab as lab,pi_release,provenance
import release_contracts,resources,secret_store,stage_control as controls

WORKER=predecessor.WORKER
CONCURRENCY={**copy.deepcopy(predecessor.CONCURRENCY),'scheduler':'parallel-trials-v2','host_generation':2}


def matrix():
    rows=[]
    for release in release_contracts.RELEASES:
        for lane,cells,stages in (('indexed-single',6,1),('indexed-serial',6,1),('legacy-saved',3,1),('legacy-explicit',3,1),('legacy-serial',6,1),('legacy-parallel',6,1),('standalone-roles',6,2),('serial-roles',6,2)):
            rows.append({'id':'a-'+release+'-'+lane,'collection':'A','release':release,'lane':lane,'kind':'coding' if stages==2 else 'smoke',
                'cells':cells,'segments_ceiling':cells*stages,'real_model':True,'repetitions':3})
    for release in release_contracts.RELEASES:
        for lane,kind,cells,stages in (('coding','coding',6,2),('lookup-builtin','lookup',6,1),('lookup-fixture','lookup',6,1),('credentials','credentials',12,3),('browser','browser',6,1)):
            rows.append({'id':'b-'+release+'-'+lane,'collection':'B','release':release,'lane':lane,'kind':kind,
                'cells':cells,'segments_ceiling':cells*stages,'real_model':True,'repetitions':3})
        for kind in predecessor.FAULTS:
            rows.append({'id':'b-'+release+'-'+kind,'collection':'B','release':release,'lane':kind,'kind':kind,
                'cells':4,'segments_ceiling':8 if kind=='recovery' else 4,'real_model':False,'repetitions':1})
    return rows


def launch_derivation(rows=None):
    """Count every potential started cell, continuation, helper and preflight.

    Per trial: image probe + boundary + initial preflight + scorer;
    browser adds a browser gate. Every additional role has a preflight. Fault
    continuations are counted from the full segment ceiling, including halted
    cells that normally stay pending. Serial indexed trials own one helper/network;
    parallel batches share a helper and have a parent image-admission probe.
    """
    infrastructure={'image_admission':4,'dom_image_probes':2,'dom_workers':2,'overlap_fifo_workers':3,'cancel_workers':2,'owner_loss_workers':2,'routing_authority':1,'routing_broker':1}
    totals={'infrastructure':{'containers':sum(infrastructure.values()),'networks':0},'A':{'containers':1,'networks':0},'B':{'containers':1,'networks':0}}
    details=[]
    for row in rows or matrix():
        if row['lane']=='admission':details.append({'id':row['id'],'containers':0,'networks':0});continue
        stages=3 if row['kind']=='credentials' else 2 if row['kind']=='coding' else 1
        parallel=row['collection']=='B' or row['lane']=='legacy-parallel'
        indexed=row['lane'] not in ('legacy-saved','legacy-explicit','legacy-serial','legacy-parallel')
        # Discovery/boundary explicitly add one setup stage per cell.
        setup=1 if row['kind'] in ('discovery','boundary') else 0
        containers=row['cells']*(4+setup+(stages-1)+(1 if row['kind']=='browser' else 0))+row['segments_ceiling']
        if parallel:containers+=2 # parent image probe and one broker
        elif indexed:containers+=row['cells']
        if row['kind']=='crash':containers+=2 # independently admitted resume probe/broker
        networks=row['cells'] if indexed or parallel else 0
        totals[row['collection']]['containers']+=containers;totals[row['collection']]['networks']+=networks
        details.append({'id':row['id'],'containers':containers,'networks':networks,'broker_mode':'shared-multiroute' if parallel else 'immutable-per-trial' if indexed else 'legacy-direct'})
    for phase in ('infrastructure','A','B'):totals[phase]['segments']=0 if phase=='infrastructure' else sum(r['segments_ceiling'] for r in rows or matrix() if r['collection']==phase)
    totals['whole']={k:sum(v[k] for v in totals.values()) for k in ('containers','networks','segments')}
    if totals['whole']['containers']>1600 or totals['whole']['networks']>256:raise ValueError('Planning hard launch ceiling exceeded')
    return {**totals,'infrastructure_paths':infrastructure,'batches':details}


def store_inventory(path):
    result={}
    for file in Path(path).glob('*'):
        info=file.lstat()
        result[file.name]={name:getattr(info,'st_'+name) for name in ('mode','uid','gid','size','mtime_ns','ctime_ns','nlink','dev','ino')}
    return result


def original_inventory(manifest):return store_inventory(manifest['original_store_path'])


def positive_usage(record):
    total=record.get('measurement',{}).get('usage',{}).get('categories',{}).get('total',{}).get('reported')
    if type(total) is not int or total<=0:raise RuntimeError('Required provider usage is missing or placeholder')
    for agent in record.get('agents',[]):
        process=agent['process'];tokens=process.get('stage_reported_tokens');turns=process.get('stage_turns')
        if type(tokens) is not int or not 0<tokens<=128000 or type(turns) is not int or not 0<turns<=12:raise RuntimeError('Frozen positive stage token/turn limits unverified')


def freeze(root,profiles_file,images_file,session):
    root=Path(root).resolve()
    if root.exists():raise ValueError('Fresh qualification root required')
    raw=experiments.read_json(profiles_file);indexed_contract.fields(raw,('a','b','scope','deployment_limits'))
    configurations={name:indexed_contract.configuration(raw[name],lab.normalize_endpoint) for name in ('a','b')}
    if configurations['a']['credential'].get('name')==configurations['b']['credential'].get('name') and configurations['a']['credential']!=configurations['b']['credential']:
        raise indexed_contract.IndexedError('selection-conflict')
    images=experiments.read_json(images_file)
    selected={}
    for release in release_contracts.RELEASES:
        for kind in ('core','browser'):
            name=kind+'-'+release;entry=images[name]
            if entry.get('platform')!='linux/arm64' or not isinstance(entry.get('id'),str) or not __import__('re').fullmatch('sha256:[a-f0-9]{64}',entry['id']):raise ValueError('Recorded native ARM64 image identity required')
            selected[name]={'id':entry['id'],'platform':'linux/arm64'}
    rows=matrix();identity=str(uuid.uuid4());root.mkdir(mode=0o700,parents=True)
    private=Path(tempfile.mkdtemp(prefix='pi-indexed-qualification-')).resolve();store=private/'store';store.mkdir(mode=0o700)
    catalog=inference_catalog.Catalog(lab.normalize_endpoint,private/'catalog',store)
    original=inference_catalog.Catalog(lab.normalize_endpoint,private/'source-catalog')
    try:
        bindings={}
        for name,configuration in configurations.items():
            source=configuration['credential'];key=original._secret(configuration)
            if source['source']=='none':raise ValueError('Native credential-profile campaign requires explicit real sources')
            secret_store.write_secret(source['name'],key,store)
            canonical={**configuration,'endpoint':{k:v for k,v in configuration['endpoint'].items() if k!='api_key_env'},'credential':{'source':'store','name':source['name']}}
            catalog.register(name,canonical);catalog.confirm(name,session);bindings[name]=catalog.freeze(name,session)
        manifest={'schema':1,'qualification_id':identity,'source':pi_release.source_identity(),'images':selected,'session':session,
            'private_root':str(private),'catalog':str(catalog.root),'store':str(store),'profiles':bindings,
            'scope':raw['scope'],'deployment_limits':raw['deployment_limits'],'worker_resources':WORKER,'concurrency':CONCURRENCY,
            'batches':rows,'planned_cells':220,'segments_ceiling':312,'expected_segments':292,'expected_real_segments':240,'expected_scripted_segments':52,
            'launch_derivation':launch_derivation(rows),'docker_launches_ceiling':launch_derivation(rows)['whole']['containers'],
            'infrastructure_seconds_ceiling':1200,'infrastructure_active_seconds':960,'A_seconds':10800,'B_seconds':14400,
            'cleanup_seconds_ceiling':240,'whole_seconds':26880,'automatic_retries':0,
            'standalone_invocation_seconds':1800,'batch_invocation_seconds':3600,'resume_invocation_seconds':240,
            'live_health_http_ceiling':8,'scripted_direct_http_ceiling':64,'coding_max_total_tokens':128000,'other_positive_max_total_tokens':128000,
            'original_store_path':str(secret_store.default_store()),
            'original_store_inventory':store_inventory(secret_store.default_store()),
            'cell_oracles':[{'id':str(uuid.uuid5(uuid.UUID(identity),row['id']+':'+str(i))),'batch':row['id'],'ordinal':i,'expected':'positive' if row['real_model'] else 'negative','status':'planned'} for row in rows for i in range(row['cells'])]}
        controls.atomic(root/'worker.json',WORKER,0o444);controls.atomic(root/'manifest.json',manifest,0o444)
        controls.atomic(root/'integrity.json',{'manifest_sha256':hashlib.sha256((root/'manifest.json').read_bytes()).hexdigest(),'worker_sha256':hashlib.sha256((root/'worker.json').read_bytes()).hexdigest()})
        controls.atomic(root/'state.json',{'phase':'frozen','attempted_batches':[],'batches':[],'segments':0,'remaining_not_run':[r['id'] for r in rows]})
        return {'qualification':str(root),'planned_cells':220,'segments_ceiling':312,'launches':manifest['launch_derivation']['whole'],'source':manifest['source']['runner'],'scope':raw['scope']}
    except BaseException:
        shutil.rmtree(private);raise


def verify(root):
    root=Path(root).resolve();manifest=experiments.read_json(root/'manifest.json');integrity=experiments.read_json(root/'integrity.json')
    if integrity['manifest_sha256']!=hashlib.sha256((root/'manifest.json').read_bytes()).hexdigest() or integrity['worker_sha256']!=hashlib.sha256((root/'worker.json').read_bytes()).hexdigest():raise ValueError('Frozen intent changed')
    if manifest['source']!=pi_release.source_identity() or manifest['batches']!=matrix() or manifest['launch_derivation']!=launch_derivation():raise ValueError('Frozen source or matrix changed')
    if original_inventory(manifest)!=manifest['original_store_inventory']:raise ValueError('Operator credential store changed')
    if manifest['worker_resources']!=WORKER or manifest['concurrency']!=CONCURRENCY:raise ValueError('Frozen limits changed')
    return root,manifest,experiments.read_json(root/'state.json')


def helper(workers,scripted=False):
    value={'contract':indexed_contract.EXECUTION,'host_generation':2,'max_workers':workers,'aggregate':CONCURRENCY['aggregate'],'gateway':copy.deepcopy(CONCURRENCY['gateway'])}
    if scripted:value['gateway'].update(queue_wait_seconds=10,request_timeout_seconds=30)
    return value


def builder(root,batch,manifest,authority):
    lane=batch['lane'];parallel=batch['collection']=='B' or lane=='legacy-parallel'
    indexed=lane not in ('legacy-saved','legacy-explicit','legacy-serial','legacy-parallel')
    catalog=inference_catalog.Catalog(lab.normalize_endpoint,manifest['catalog'],manifest['store'])
    if not batch['real_model']:
        endpoint={'base_url':authority.child+'/v1','host_base_url':authority.host+'/v1','model':'qualification-diagnostic','context_window':32768,'max_tokens':1024,'reasoning':False}
        for name in ('fault-a','fault-b'):
            key=authority.inference if name=='fault-a' else authority.second_inference
            secret_store.write_secret(name.upper().replace('-','_'),key,catalog.store)
            configuration={'api':indexed_contract.API,'adapter_contract':indexed_contract.ADAPTER,'endpoint':endpoint,'credential':{'source':'store','name':name.upper().replace('-','_')},'capacity_group':'scripted-shared','request_limits':{'queue_wait_seconds':10,'request_timeout_seconds':30}}
            old=next((e for e in catalog.list()['entries'] if e['id']==name),None)
            catalog.register(name,configuration,old['revision'] if old else None);catalog.confirm(name,manifest['session'])
    ids=('a','b') if batch['real_model'] else ('fault-a','fault-b')
    def transform(value,folder):
        value['budgets'].update(timeout_seconds=600,max_turns=12,max_total_tokens=128000) if batch['real_model'] else None
        value['schema']=3 if indexed else 2 if parallel else 1
        if indexed:
            value.update(mode='parallel' if parallel else 'serial',indexed_execution=helper(2 if parallel else 1,not batch['real_model']))
            if parallel:value['concurrency'].update(scheduler=indexed_contract.SCHEDULER,host_generation=2)
            else:value.pop('concurrency')
        elif not parallel:value.pop('concurrency')
        if lane=='lookup-builtin':
            for variant in value['variants']:variant.pop('agent_profile',None)
        elif lane=='lookup-fixture':
            profile=value['variants'][1]['agent_profile']
            for variant in value['variants']:variant['agent_profile']=profile
        for number,variant in enumerate(value['variants']):
            variant.pop('prompt_suffix',None)
            chosen=ids[number]
            if indexed:
                maps={}
                for case in value['cases']:
                    plan=experiments.read_json(case['plan']);names=[t['name'] for t in plan['agents']]
                    mapping={name:ids[(number+i)%2] for i,name in enumerate(names)} if len(names)>1 else {names[0]:chosen}
                    maps[case['name']]=mapping
                    if len(names)>1:plan.update(schema=2,inference_bindings='external');controls.atomic(Path(case['plan']),plan)
                if len(next(iter(maps.values())))>1:variant['inference_bindings']=maps
                else:variant['inference_env']=chosen
            else:
                chosen='a' if lane in ('legacy-saved','legacy-serial','legacy-parallel') else 'b'
                endpoint=catalog.select(chosen)['configuration']['endpoint'];path=folder/('legacy-'+str(number)+'.json');controls.atomic(path,endpoint);variant['endpoint']=str(path)
        if batch['cells']==3:value['variants']=value['variants'][:1]
        return value
    direct=lane in ('indexed-single','legacy-saved','legacy-explicit','standalone-roles')
    def prepared(folder):
        if direct:
            target=folder/'standalone';target.mkdir()
            controls.atomic(target/'definition.json',experiments.read_json(folder/'definition.json'),0o444)
            return {'planned':batch['cells'],'experiment':str(target)}
        return experiments.prepare(folder/'definition.json',folder/'experiment',lab,session=manifest['session'],catalog=catalog) if indexed else experiments.prepare(folder/'definition.json',folder/'experiment',lab)
    return predecessor.definition(root,batch,manifest,authority,transform,prepared)


def run_standalone(root,batch,manifest,authority,deadline):
    folder,frozen=builder(root,batch,manifest,authority);definition=experiments.read_json(frozen/'definition.json')
    catalog=inference_catalog.Catalog(lab.normalize_endpoint,manifest['catalog'],manifest['store']);results=[]
    import lab_env
    for variant in definition['variants']:
        for repetition in range(3):
            if time.monotonic()>=deadline:raise TimeoutError('Collection A deadline')
            case=definition['cases'][0];plan=lab.validate_plan(experiments.read_json(case['plan']),Path(case['plan']).parent,external_bindings=True)
            for task in plan['agents']:task.update(definition['budgets'])
            inline=copy.deepcopy(plan)
            if batch['lane']=='standalone-roles':inline.update(schema=2,inference_bindings=variant['inference_bindings'][case['name']])
            label=batch['id']+'-'+variant['name']+'-'+str(repetition)
            planpath=folder/(label+'.plan.json');controls.atomic(planpath,inline,0o444)
            argv=['run','--image',definition['execution']['image'],'--platform','linux/arm64','--resources',str(root/'worker.json'),
                '--project',case['project'],'--plan',str(planpath),'--results-dir',str(folder/'standalone-runs'/label/'runs'),
                '--secrets-dir',manifest['store'],'--session',manifest['session']]
            if batch['lane']=='indexed-single':argv+=['--inference-env',variant['inference_env'],'--catalog-dir',manifest['catalog']]
            elif batch['lane']=='standalone-roles':argv+=['--catalog-dir',manifest['catalog']]
            elif batch['lane']=='legacy-explicit':argv+=['--endpoint',variant['endpoint']]
            else:
                # Only the disposable legacy namespace is mutated. Preserve the
                # operator default and prove indexed catalog mutations cannot reroute it.
                endpoint=catalog.select('a')['configuration']['endpoint'];lab_env.save_environment(endpoint)
                lab_env.confirm_session(manifest['session'],lab_env.fingerprint_of(endpoint))
            invoked=predecessor.invoke(root,label,argv,min(1800,deadline-time.monotonic()),qualification_environment(root,manifest,'A'))
            run,result=pi_release.run_result(folder/'standalone-runs'/label)
            if invoked['exit_code']!=0 or result['status']!='PASS' or result.get('invocation',{}).get('status')!='verified':raise RuntimeError('Standalone positive invocation failed')
            if result['protected_inputs']['status']!='unchanged' or result['task_result']['status']!='pass':raise RuntimeError('Standalone independent oracle failed')
            positive_usage(result)
            count=len(list((run/'stages').glob('*/segments/*.json')))
            expected=2 if batch['lane']=='standalone-roles' else 1
            if count!=expected or len(result['agents'])!=expected:raise RuntimeError('Standalone segment accounting mismatch')
            for number,agent in enumerate(result['agents']):
                if batch['lane'].startswith(('indexed','standalone')):
                    name=inline['agents'][number]['name'];identifier=variant.get('inference_env') or inline['inference_bindings'][name]
                    binding=catalog.freeze(identifier,manifest['session'])
                    import indexed_reporting
                    if agent.get('inference_binding')!=indexed_reporting.identity(binding):raise RuntimeError('Standalone binding mismatch')
            if list((run/'stages').glob('*/application-credentials.json')):pi_release.sensitive_clean(run,authority.issued)
            results.append({'status':result['status'],'segments':count,'run':str(run)})
    if len(results)!=batch['cells']:raise RuntimeError('Standalone fixed matrix incomplete')
    return {'id':batch['id'],'passed':True,'real_model':True,'planned':batch['cells'],'attempted':len(results),'segments':sum(x['segments'] for x in results),'statuses':[x['status'] for x in results]}


def qualification_environment(root,manifest,phase):
    private=Path(manifest['private_root']);env=pi_release.checker_env({'PI_LAB_CONFIG_DIR':str(private/'legacy-config'),
        'PI_LAB_STATE_DIR':str(private/'legacy-state'),'PI_LAB_SECRETS_DIR':manifest['store'],'PI_LAB_CATALOG_DIR':manifest['catalog'],
        'PI_INDEXED_QUALIFICATION_ROOT':str(root),'PI_INDEXED_QUALIFICATION_PHASE':phase})
    env['PATH']=str(private/'bin')+os.pathsep+os.environ['PATH']
    return env


def enter_phase(root,manifest,phase,seconds,first=False):
    now=time.monotonic();path=root/'budget.json'
    if first:
        real=shutil.which('docker')
        if not real:raise ValueError('Docker CLI unavailable')
        value={'whole_deadline':now+manifest['whole_seconds'],'docker':real,'counts':{p:{'containers':0,'networks':0,'segments':0} for p in ('infrastructure','A','B')}}
        private=Path(manifest['private_root']);(private/'bin').mkdir()
        shim=private/'bin/docker';shim.write_text('#!'+sys.executable+'\nimport sys\nsys.path.insert(0,'+repr(str(HERE))+')\nimport indexed_budget\nsys.exit(indexed_budget.main())\n');shim.chmod(0o700)
    else:value=experiments.read_json(path)
    value.update(cleanup=False,phase=phase,phase_deadline=min(now+seconds,value['whole_deadline']))
    controls.atomic(path,value)
    os.environ.update(qualification_environment(root,manifest,phase))


def verify_cleanup(root,manifest,authority):
    started=time.monotonic()
    with resources.admission_lock(lab.default_lock_file(),min(120,manifest['cleanup_seconds_ceiling'])) as registry:
        registry.command=lambda argv:predecessor.command(argv,required=False)
        registry.close()
    records=predecessor.registry_records();baseline=set(experiments.read_json(root/'registry-baseline.json')['launch_ids'])
    owned=[r for r in records if r['launch_id'] not in baseline]
    for record in owned:
        predecessor.absence(record['container'],record.get('kind')=='network')
        if record.get('private_store') and Path(record['private_store']).exists():raise RuntimeError('Broker private store retained')
    if authority is not None:authority.close()
    if time.monotonic()-started>manifest['cleanup_seconds_ceiling']:raise TimeoutError('Cleanup ceiling')
    return {'confirmed_absent':True,'registered_resources':len(owned),'broker_private_stores_removed':True}


def admission_oracles(root,batch,manifest):
    """Real parent admission negatives with a Docker-command trap; zero Pi."""
    import unittest.mock as mock
    folder=root/'batches'/batch['id'];folder.mkdir(parents=True)
    catalog=inference_catalog.Catalog(lab.normalize_endpoint,manifest['catalog'],manifest['store'])
    config=copy.deepcopy(manifest['profiles']['a']['configuration']);config['endpoint'].pop('api_key_env')
    source=Path(manifest['private_root'])/'negative-store';source.mkdir(exist_ok=True,mode=0o700)
    negative=inference_catalog.Catalog(lab.normalize_endpoint,Path(manifest['private_root'])/('negative-'+batch['release']),source)
    config['credential']={'source':'store','name':'SYNTHETIC_NEGATIVE'};secret_store.write_secret('SYNTHETIC_NEGATIVE','synthetic-negative-one',source)
    negative.register('selected',config);negative.confirm('selected',manifest['session']);binding=negative.freeze('selected',manifest['session'])
    results=[]
    def reject(name,call,reason):
        with mock.patch.object(lab,'command',side_effect=AssertionError('No Docker/network dispatch permitted')):
            try:call()
            except indexed_contract.IndexedError as exc:
                if exc.reason!=reason:raise RuntimeError('Wrong negative admission reason')
                results.append({'oracle':name,'passed':True,'reason':exc.reason,'pi_segments':0})
            else:raise RuntimeError('Negative fixture was admitted')
    reject('unknown-profile',lambda:negative.freeze('missing',manifest['session']),'environment-not-found')
    reject('stale-index',lambda:negative.select(index=1,revision=0),'environment-index-stale')
    unsupported=copy.deepcopy(config);unsupported['api']='unreviewed-api'
    reject('unsupported-adapter',lambda:negative.register('other',unsupported),'unsupported-api-adapter')
    reject('partial-map',lambda:indexed_contract.stage_map({'implementer':'selected'},['implementer','reviewer']),'selection-conflict')
    secret_store.write_secret('SYNTHETIC_NEGATIVE','synthetic-negative-two',source)
    reject('rotation',lambda:negative.admit(binding,manifest['session']),'inference-authority-changed')
    negative.revoke('selected',1)
    reject('revocation',lambda:negative.admit(binding,manifest['session']),'environment-revoked')
    controls.atomic(folder/'oracles.json',results)
    return {'id':batch['id'],'passed':True,'planned':6,'attempted':6,'segments':0,'real_model':False}


def authority_owner(root,manifest):
    owner=predecessor.AuthorityOwner(root,manifest['images']['core-0.87.1']['id'],manifest['profiles']['a']['configuration']['endpoint'],read_model_key=False)
    owner.store=Path(manifest['store']);owner.second_inference=secrets.token_hex(32)
    owner.config['inference_keys']=[owner.inference,owner.second_inference];owner.write()
    original_close=owner.close;closed=False
    def close():
        nonlocal closed
        if not closed:original_close();closed=True
    owner.close=close
    return owner


def infrastructure_routes(root,manifest):
    """A real ARM64 helper, two controlled URL paths and one global slot."""
    import http.client,threading
    import inference_broker
    from parallel_allocator import Allocator
    folder=root/'routing-gate';folder.mkdir();authority=authority_owner(folder,manifest)
    prefix=secrets.token_hex(16);tokens=[prefix+secrets.token_hex(16) for _ in range(2)]
    authority.config.update(routing_fixture=True,route_keys={'route-a':authority.inference,'route-b':authority.second_inference},opaque_tokens=tokens);authority.write()
    try:
        authority.start()
        args=lab.parser().parse_args(['run','--image',manifest['images']['core-0.87.1']['id'],'--platform','linux/arm64','--resources',str(root/'worker.json')])
        routes={name:{'endpoint':{'base_url':authority.child+'/'+name+'/v1','host_base_url':authority.host+'/'+name+'/v1','model':'qualification-diagnostic','max_tokens':1024},
            'upstream_key':authority.config['route_keys'][name],'limits':{'queue_wait_seconds':10,'request_timeout_seconds':30}} for name in ('route-a','route-b')}
        config={'routes':routes,'tokens':{token:{'route':name} for token,name in zip(tokens,routes)},'token_prefix':prefix,'active_tokens_file':True}
        observed=[];calls=0;http_observations=[];http_lock=threading.Lock()
        with resources.admission_lock(lab.default_lock_file()) as registry:
            registry.command=lambda argv:predecessor.command(argv,required=False);registry.binding={'indexed_host_generation':2};lab.require_host(args)
            pool=Allocator(CONCURRENCY['aggregate']);weight=__import__('parallel_contract').worker_weight(resources.validate_policy(WORKER))
            try:
                with inference_broker.owner(lab,args,folder,registry,pool,weight,config,args.image,helper(2,True)['gateway']) as (broker,factory,cleanup):
                    budget=experiments.read_json(root/'budget.json');broker['control_deadline']=min(budget['phase_deadline'],budget['whole_deadline'])
                    broker['activate'](tokens)
                    route=__import__('urllib.parse',fromlist=['urlsplit']).urlsplit(broker['host_base_url'])
                    def request(token,method='POST',extra=None):
                        nonlocal calls
                        with http_lock:
                            if calls>=64:raise RuntimeError('Direct scripted HTTP ceiling')
                            calls+=1;ordinal=calls
                        connection=http.client.HTTPConnection(route.hostname,route.port,timeout=45)
                        body=json.dumps({'model':'qualification-diagnostic','messages':[],'max_tokens':16,**(extra or {})}) if method=='POST' else None
                        connection.request(method,'/v1/models' if method=='GET' else '/v1/chat/completions',body,{'Authorization':'Bearer '+token})
                        response=connection.getresponse();status=response.status
                        observation={'ordinal':ordinal,'method':method,'status':status,'completion':'reading','request_fields':sorted(extra or {})}
                        with http_lock:
                            http_observations.append(observation);controls.atomic(folder/'http-observations.json',http_observations)
                        try:
                            raw=response.read();headers=str(response.getheaders());observation['completion']='http_complete'
                        except (OSError,http.client.HTTPException):
                            observation['completion']='framing_or_transport_error';raise
                        finally:
                            connection.close()
                            with http_lock:controls.atomic(folder/'http-observations.json',http_observations)
                        redactor=application_credentials.Redactor([authority.inference,authority.second_inference,*tokens])
                        if redactor.contains(raw) or redactor.contains(headers.encode()):raise RuntimeError('Response boundary leaked a held key/token')
                        return status,json.loads(raw)
                    concurrent=[];errors=[]
                    barrier=threading.Barrier(2)
                    def simultaneous(token):
                        try:barrier.wait(timeout=2);concurrent.append(request(token))
                        except BaseException as exc:errors.append(type(exc).__name__)
                    threads=[threading.Thread(target=simultaneous,args=(token,)) for token in tokens]
                    for thread in threads:thread.start()
                    for thread in threads:thread.join(45)
                    if errors or any(t.is_alive() for t in threads) or len(concurrent)!=2 or any(status!=200 for status,value in concurrent):raise RuntimeError('Concurrent route admission failed')
                    for number,token in enumerate(tokens):
                        for method in ('GET','POST'):
                            status,value=request(token,method)
                            if status!=200 or method=='POST' and value['reply']!=list(routes)[number]:raise RuntimeError('Wrong token-bound route')
                    for token in tokens:
                        for extra in ({'model':'foreign'},{'route':'route-b'},{'api_key':'synthetic-override'},{'base_url':'http://foreign.invalid/v1'}):
                            if request(token,extra=extra)[0]!=400:raise RuntimeError('Spoofed request admitted')
                    broker['activate']([tokens[1]])
                    if request(tokens[0])[0]!=401:raise RuntimeError('Revoked stage capability admitted')
                    observed=authority.snapshot().get('route_observations',[])
                    if len(observed)!=6 or not all(row['key_matched'] for row in observed):raise RuntimeError('Controlled route observer mismatch')
                    if {r['route'] for r in observed}!={'route-a','route-b'}:raise RuntimeError('Both controlled routes were not observed')
                    broker['activate'](tokens)
                    # Select the malformed fixture in this controlled request;
                    # another host file replacement is not a delivery barrier.
                    from parallel_service import TRUNCATION_MESSAGES
                    try:request(tokens[0],extra={'messages':TRUNCATION_MESSAGES})
                    except (ValueError,http.client.HTTPException):
                        if http_observations[-1]['status']!=200:raise RuntimeError('Truncation fixture was rejected before forwarding')
                    else:
                        if http_observations[-1]['status']!=200:raise RuntimeError('Truncation fixture was rejected before forwarding')
                        raise RuntimeError('Incomplete response did not fail')
                    for token in tokens:
                        if request(token)[0]!=429:raise RuntimeError('Uncertainty did not quarantine every route')
                    broker['activate']([])
            except __import__('parallel_contract').ParallelError:
                uncertain=[r for r in registry.load() if r.get('runroot')==str(folder) and r.get('inference_uncertain') and r['status']=='quarantined']
                if len(uncertain)!=1:raise
                # These are controlled routes on this exact disposable authority;
                # stopping that owned upstream proves its requests are terminated.
                authority.close()
                for record in uncertain:
                    if not registry.confirm_absent(record):raise RuntimeError('Quarantined fixture helper remains')
                    registry.release(record,True)
                controls.atomic(folder/'controlled-quarantine-cleanup.json',{'scripted_upstream_confirmed_absent':True,'gateway_confirmed_absent':True,'only_controlled_fixture_routes':True,'real_model_requests':0})
        receipt=experiments.read_json(folder/'gateway-receipt.json')
        if receipt['observed']['observed_max_inflight']!=1 or receipt['observed']['observed_max_pending']<1 or receipt['observed']['uncertain'] is not True:raise RuntimeError('One-slot broker observation failed')
        controls.atomic(folder/'qualification.json',{'passed':True,'direct_scripted_http':calls,'pi_segments':0,'route_observations':observed,
            'limits_applied':True,'all_key_and_header_redaction':True,'revoked_token_rejected':True,'all_routes_quarantined_on_incomplete_response':True})
    finally:authority.close()


def infrastructure_old_client(root):
    import legacy_registry_v1
    with resources.admission_lock(lab.default_lock_file()) as registry:
        registry.command=lambda argv:predecessor.command(argv,required=False)
        if not any(r['schema']==2 for r in registry.load()):raise RuntimeError('No generation-2 registry witness')
        old=legacy_registry_v1.Registry(registry.root,command=lambda argv:(_ for _ in ()).throw(AssertionError('Predecessor must reject before Docker')))
        try:old.load()
        except legacy_registry_v1.RegistryError:
            controls.atomic(root/'older-client-negative.json',{'passed':True,'new_registry_rejected_before_dispatch':True,'pi_segments':0,'predecessor_contract':'released generation-1 reader'})
        else:raise RuntimeError('Unqualified older host reader accepted indexed generation')


def begin_cleanup(root,manifest):
    value=experiments.read_json(root/'budget.json');value.update(cleanup=True,phase_deadline=min(time.monotonic()+240,value['whole_deadline']))
    controls.atomic(root/'budget.json',value)


def live_health(root,manifest):
    """Four separately counted finite requests, under the global writer lease."""
    import http.client,threading
    from urllib.parse import urlsplit
    import inference_gateway
    observations=[]
    catalog=inference_catalog.Catalog(lab.normalize_endpoint,manifest['catalog'],manifest['store'])
    with resources.admission_lock(lab.default_lock_file()) as registry:
        registry.command=lambda argv:predecessor.command(argv,required=False)
        for name,binding in manifest['profiles'].items():
            endpoint=binding['configuration']['endpoint'];key=catalog.admit(binding,manifest['session']);route=urlsplit(endpoint['host_base_url'])
            for method in ('GET','POST'):
                deadline=min(time.monotonic()+15,experiments.read_json(root/'budget.json')['phase_deadline'])
                cls=http.client.HTTPSConnection if route.scheme=='https' else http.client.HTTPConnection
                connection=cls(route.hostname,route.port,timeout=max(.01,deadline-time.monotonic()));connection.response_class=inference_gateway.StrictResponse
                connection._create_connection=lambda address,timeout,source_address:inference_gateway.deadline_connection(address,deadline,source_address)
                expired=threading.Event()
                def cancel():
                    expired.set()
                    if connection.sock is not None:
                        try:connection.sock.shutdown(2)
                        except OSError:pass
                timer=threading.Timer(max(.01,deadline-time.monotonic()),cancel);timer.daemon=True;timer.start()
                try:
                    body={'model':endpoint['model'],'messages':[{'role':'user','content':'Reply with OK.'}],endpoint.get('compat',{}).get('maxTokensField','max_tokens'):16,'stream':False} if method=='POST' else None
                    connection.connect();sock=connection.sock
                    connection.request(method,route.path.rstrip('/')+('/models' if method=='GET' else '/chat/completions'),body=json.dumps(body) if body else None,
                        headers={'Authorization':'Bearer '+key,'Content-Type':'application/json','Accept-Encoding':'identity'})
                    response=connection.getresponse();raw=b''.join(inference_gateway.response_chunks(response,sock,deadline,2*1024*1024))
                    result=json.loads(raw)
                    if expired.is_set() or time.monotonic()>=deadline or response.status!=200:raise RuntimeError('Approved bounded health request failed')
                    if method=='GET' and endpoint['model'] not in [m.get('id') for m in result.get('data',[])]:raise RuntimeError('Exact real model unavailable')
                    if method=='POST' and not result.get('choices'):raise RuntimeError('Tiny health reply missing')
                    observations.append({'profile':name,'method':method,'passed':True,'deadline_seconds':15,'reply_cap':16 if body else None})
                finally:timer.cancel();timer.join();connection.close()
    if len(observations)>8:raise RuntimeError('Live health allowance')
    controls.atomic(root/'live-health.json',{'requests':observations,'count':len(observations),'pi_segments':0})


def infrastructure(root):
    root,manifest,state=verify(root)
    if state['phase']!='frozen':raise ValueError('Infrastructure cannot repeat')
    state['phase']='infrastructure';controls.atomic(root/'state.json',state)
    enter_phase(root,manifest,'infrastructure',960,first=True)
    controls.atomic(root/'registry-baseline.json',{'launch_ids':[r['launch_id'] for r in predecessor.registry_records()]})
    import lab_env
    endpoint=manifest['profiles']['a']['configuration']['endpoint']
    lab_env.save_environment(endpoint);lab_env.confirm_session(manifest['session'],lab_env.fingerprint_of(endpoint))
    try:
        host=pi_release.native()
        __import__('parallel_contract').admit_capacity(predecessor.CONCURRENCY,resources.validate_policy(WORKER),host)
        for name in manifest['images']:
            image=pi_release.native(manifest['images'][name]['id'])
            remaining=experiments.read_json(root/'budget.json')['phase_deadline']-time.monotonic()
            result=predecessor.invoke(root,'image-'+name,predecessor.image_arguments(root,manifest,name),min(180,remaining),qualification_environment(root,manifest,'infrastructure'))
            if result['exit_code']:raise RuntimeError('Exact ARM64 image admission failed')
            lab.admit_image(experiments.read_json(root/(name+'.json')),name.rsplit('-',1)[1])
        live_health(root,manifest)
        infrastructure_routes(root,manifest)
        infrastructure_old_client(root)
        predecessor.infrastructure_overlap(root,manifest);predecessor.infrastructure_cancel(root,manifest);predecessor.infrastructure_owner_loss(root,manifest)
        for release in release_contracts.RELEASES:
            result=predecessor.invoke(root,'dom-'+release,['browser-check','--image',manifest['images']['browser-'+release]['id'],'--profile','browser',
                '--platform','linux/arm64','--browser-sandbox-policy','chromium-userns','--resources',str(root/'worker.json'),'--results-dir',str(root/'dom')],
                min(240,experiments.read_json(root/'budget.json')['phase_deadline']-time.monotonic()),qualification_environment(root,manifest,'infrastructure'))
            if result['exit_code']:raise RuntimeError('Sandboxed DOM admission failed')
        state['phase']='infrastructure_qualified'
    except BaseException as exc:state.update(phase='blocked',reason=type(exc).__name__);raise
    finally:
        begin_cleanup(root,manifest)
        try:state['infrastructure_cleanup']=verify_cleanup(root,manifest,None)
        except BaseException as exc:state.update(phase='blocked',cleanup_error=type(exc).__name__)
        controls.atomic(root/'state.json',state)
    if state['phase']!='infrastructure_qualified':raise RuntimeError('Infrastructure cleanup incomplete')


def collect_phase(root,collection):
    root,manifest,state=verify(root);expected='infrastructure_qualified' if collection=='A' else 'A_qualified'
    if state['phase']!=expected:raise ValueError('Fixed order or no-retry gate')
    enter_phase(root,manifest,collection,manifest[collection+'_seconds']);deadline=experiments.read_json(root/'budget.json')['phase_deadline']
    folder=root/('authority-'+collection);folder.mkdir();authority=authority_owner(folder,manifest)
    state['phase']=collection+'_collecting';state.setdefault('cell_outcomes',[]);controls.atomic(root/'state.json',state)
    try:
        authority.start()
        for batch in [r for r in manifest['batches'] if r['collection']==collection]:
            verify(root);state['active_batch']=batch['id'];state['attempted_batches'].append(batch['id']);controls.atomic(root/'state.json',state)
            if batch['lane'] in ('indexed-single','legacy-saved','legacy-explicit','standalone-roles'):
                result=run_standalone(root,batch,manifest,authority,deadline)
            elif collection=='A':
                batchfolder,exp=builder(root,batch,manifest,authority)
                invocation=predecessor.invoke(root,batch['id'],['experiment-run','--experiment',str(exp),'--session',manifest['session']],min(3600,deadline-time.monotonic()),qualification_environment(root,manifest,collection))
                metadata,matrix=experiments.verify(exp,lab);rows=experiments.ledger_rows(exp,lab)
                predecessor.validate_positive(exp,metadata,rows,invocation,batch)
                result={'id':batch['id'],'passed':True,'real_model':True,'planned':batch['cells'],'attempted':batch['cells'],'segments':predecessor.count_segments(exp)}
            else:
                result=predecessor.run_batch(root,batch,manifest,authority,deadline,definition_builder=builder,session=manifest['session'])
            if batch['real_model'] and batch['lane'] not in ('indexed-single','legacy-saved','legacy-explicit','standalone-roles'):
                exp=root/'batches'/batch['id']/'experiment'
                for row in experiments.ledger_rows(exp,lab):positive_usage(row['attempts'][0]['result'])
            if result['segments']>batch['segments_ceiling']:raise RuntimeError('Batch segment ceiling')
            for oracle in [o for o in manifest['cell_oracles'] if o['batch']==batch['id']]:
                state['cell_outcomes'].append({**oracle,'status':'oracle_passed','real_model':batch['real_model']})
            state['batches'].append(result);state['segments']+=result['segments'];state['active_batch']=None
            state['remaining_not_run'].remove(batch['id']);controls.atomic(root/'state.json',state)
            print(json.dumps({'collection':collection,'batch':batch['id'],'passed':True,'segments':state['segments']}),flush=True)
        if collection=='B':
            for release in release_contracts.RELEASES:
                admission_oracles(root,{'id':'admission-'+release,'release':release},manifest)
        state['phase']=collection+'_qualified'
    except BaseException as exc:state.update(phase='blocked',reason=type(exc).__name__);raise
    finally:
        begin_cleanup(root,manifest)
        try:state[collection+'_cleanup']=verify_cleanup(root,manifest,authority)
        except BaseException as exc:state.update(phase='blocked',cleanup_error=type(exc).__name__)
        redactor=application_credentials.Redactor([*authority.issued,authority.inference,authority.second_inference,*[inference_catalog.Catalog(lab.normalize_endpoint,manifest['catalog'],manifest['store']).admit(b,manifest['session']) for b in manifest['profiles'].values()]])
        if any(redactor.contains(p.read_bytes()) for p in root.rglob('*') if p.is_file() and not p.is_symlink()):state.update(phase='blocked',privacy_error=True)
        counter=experiments.read_json(root/'budget.json');state['observed_segments']=sum(counts.get('segments',0) for counts in counter['counts'].values())
        state['unrun_oracles']=[{**o,'status':'not_run_blocked'} for o in manifest['cell_oracles'] if o['id'] not in {c['id'] for c in state.get('cell_outcomes',[])} and o['batch'] not in state['attempted_batches']]
        if state['phase']=='blocked' and state.get('active_batch'):state['failed_batch_oracles']=[{**o,'status':'failed_or_partial','evidence':'batches/'+o['batch']} for o in manifest['cell_oracles'] if o['batch']==state['active_batch']]
        controls.atomic(root/'state.json',state)
    if state['phase']!=collection+'_qualified':raise RuntimeError('Subcollection cleanup incomplete')


def inspection_targets(root,manifest):
    targets=[]
    for batch in manifest['batches']:
        if batch['kind']!='coding':continue
        folder=Path(root)/'batches'/batch['id']
        candidates=list((folder/'experiment/runs').glob('*/result.json'))+list((folder/'standalone-runs').glob('*/runs/*/result.json'))
        for path in candidates:
            record=experiments.read_json(path);workspace=Path(record['workspace']);reviewer=record['agents'][1]
            target=workspace/'slug.py';final=path.parent/reviewer['logs']/'final.txt'
            if not target.is_file() or not final.is_file() or record['protected_inputs']['status']!='unchanged':raise RuntimeError('Coding inspection artifacts missing')
            targets.append({'run_id':record['run_id'],'implementation':str(target),'reviewer':str(final),
                'implementation_sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'reviewer_sha256':hashlib.sha256(final.read_bytes()).hexdigest()})
    if len(targets)!=36 or len({row['run_id'] for row in targets})!=36:raise RuntimeError('Expected 36 independent coding/reviewer inspections')
    return targets


def finish(root,inspection):
    root,manifest,state=verify(root)
    if state['phase']!='B_qualified' or state['remaining_not_run']:raise ValueError('Complete A/B qualification required')
    targets=inspection_targets(root,manifest);reviews=experiments.read_json(inspection)
    if not isinstance(reviews,list) or len(reviews)!=36:raise RuntimeError('All coding pipelines require independent inspection')
    expected={row['run_id']:row for row in targets}
    for review in reviews:
        target=expected.pop(review.get('run_id'),None)
        if target is None or review.get('reviewed') is not True or any(review.get(k)!=target[k] for k in ('implementation_sha256','reviewer_sha256')):raise RuntimeError('Coding inspection identity mismatch')
    if expected:raise RuntimeError('Coding inspection incomplete')
    if time.monotonic()>=experiments.read_json(root/'budget.json')['whole_deadline']:raise TimeoutError('Whole qualification deadline')
    if state['segments']!=state.get('observed_segments'):raise RuntimeError('Budget counter and retained segments differ')
    if state['segments']!=manifest['expected_segments'] or state['segments']>manifest['segments_ceiling']:raise RuntimeError('Expected real/scripted segment accounting not established')
    catalog=inference_catalog.Catalog(lab.normalize_endpoint,manifest['catalog'],manifest['store'])
    keys=[catalog.admit(binding,manifest['session']) for binding in manifest['profiles'].values()]
    # Scan only retained evidence; private authority/store is outside it.
    redactor=application_credentials.Redactor(keys)
    matches=[str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() and not p.is_symlink() and redactor.contains(p.read_bytes())]
    if matches:raise RuntimeError('Known inference authority found in retained evidence')
    inventory=original_inventory(manifest)
    if inventory!=manifest['original_store_inventory']:raise RuntimeError('Operator credential store changed')
    shutil.rmtree(manifest['private_root']);state.update(phase='qualified',private_namespace_removed=True,known_key_matches=0)
    controls.atomic(root/'state.json',state)
    return {'phase':'qualified','cells':220,'segments':state['segments'],'scope':manifest['scope']}


def main():
    parser=argparse.ArgumentParser(description=__doc__);commands=parser.add_subparsers(dest='op',required=True)
    freeze_parser=commands.add_parser('freeze');freeze_parser.add_argument('--root',required=True);freeze_parser.add_argument('--profiles',required=True);freeze_parser.add_argument('--images',required=True);freeze_parser.add_argument('--session',required=True)
    run=commands.add_parser('run');run.add_argument('--root',required=True);run.add_argument('--approval',required=True)
    inspect=commands.add_parser('inspect');inspect.add_argument('--root',required=True)
    final=commands.add_parser('finish');final.add_argument('--root',required=True);final.add_argument('--inspection',required=True)
    args=parser.parse_args()
    if args.op=='freeze':value=freeze(args.root,args.profiles,args.images,args.session)
    elif args.op=='finish':value=finish(args.root,args.inspection)
    elif args.op=='inspect':
        root,manifest,state=verify(args.root);value={'phase':state['phase'],'cells':manifest['planned_cells'],'segments_ceiling':manifest['segments_ceiling'],'launches':manifest['launch_derivation']['whole'],'scope':manifest['scope']}
    else:
        root,manifest,state=verify(args.root);approval=experiments.read_json(args.approval)
        if approval.get('approved_manifest_sha256')!=hashlib.sha256((root/'manifest.json').read_bytes()).hexdigest() or approval.get('older_clients_quiesced') is not True:raise ValueError('Exact frozen approval and quiescence required')
        try:
            infrastructure(root);collect_phase(root,'A');collect_phase(root,'B')
            targets=inspection_targets(root,manifest);controls.atomic(root/'coding-inspection-targets.json',targets)
            value={'phase':'B_qualified','requires_independent_coding_inspection':True,'targets':str(root/'coding-inspection-targets.json')}
        except BaseException:
            # A failed campaign retains its immutable ledger. Remove disposable
            # authorities only after registry-matched physical cleanup succeeds.
            root,manifest,state=verify(root)
            if state.get('cleanup_error') is None and Path(manifest['private_root']).exists():shutil.rmtree(manifest['private_root']);state['private_namespace_removed']=True
            controls.atomic(root/'state.json',state);raise
    print(json.dumps(value,indent=2))

if __name__=='__main__':main()
