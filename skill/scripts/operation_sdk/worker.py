"""Fixed isolated operation worker. CLI run/doctor/owner actions do not exist."""
import hashlib
import json
import os
import select
import sys
import time
import types
_STAGE='bootstrap'


def _initial(fd):
    deadline = time.monotonic() + 10
    def take(size):
        result = bytearray()
        while len(result) < size:
            if time.monotonic() >= deadline or not select.select([fd], [], [], max(0, deadline-time.monotonic()))[0]:
                raise ValueError('bootstrap')
            body = os.read(fd, min(65536, size-len(result)))
            if not body: raise ValueError('bootstrap')
            result.extend(body)
        return bytes(result)
    size = int.from_bytes(take(4), 'big')
    if size > 1048576: raise ValueError('bootstrap')
    body = take(size)
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result: raise ValueError('bootstrap')
            result[key] = value
        return result
    text = body.decode('utf-8'); depth = 0; quoted = escaped = False
    for char in text:
        if quoted:
            if escaped: escaped = False
            elif char == '\\': escaped = True
            elif char == '"': quoted = False
        elif char == '"': quoted = True
        elif char in '[{':
            depth += 1
            if depth > 64: raise ValueError('bootstrap')
        elif char in ']}': depth -= 1
    return json.loads(text, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('bootstrap')))


def _bootstrap():
    if len(sys.argv) != 8: raise ValueError('bootstrap')
    expected, control, private, report, store, coordination, probe = sys.argv[1:]
    control, private, report, store, coordination = map(int, (control, private, report, store, coordination))
    initial = _initial(control); value = initial['policy']
    body = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()
    if hashlib.sha256(body).hexdigest() != expected: raise ValueError('bootstrap')
    root = value['deployment']['consumer_root']; files = value['deployment']['consumer_files']
    path = root + '/__init__.py'; fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if info.st_size > 1048576 or not os.fstatvfs(fd).f_flag & os.ST_RDONLY: raise ValueError('bootstrap')
        content = b''
        while len(content) < info.st_size:
            chunk = os.read(fd, min(65536, info.st_size-len(content)))
            if not chunk: raise ValueError('bootstrap')
            content += chunk
    finally: os.close(fd)
    if hashlib.sha256(content).hexdigest() != files['__init__.py']: raise ValueError('bootstrap')
    if 'operation_sdk' in sys.modules: raise ValueError('bootstrap')
    package = types.ModuleType('operation_sdk'); package.__file__ = path; package.__path__ = [root]
    sys.modules['operation_sdk'] = package
    exec(compile(content, path, 'exec', dont_inherit=True), package.__dict__)
    package.load_verified(root, files)
    from operation_sdk.worker import serve
    serve(initial, expected, control, private, report, store, coordination, probe == '1')


def _audit(deployment, dependencies):
    """Constrain reviewed code, not a hostile Python/native-code sandbox."""
    allowed = {deployment['provider_root']+'/'+name for name in deployment['resources']}
    protected = {row['path'] for row in dependencies}
    active = {'private': False}
    def check(event, args):
        from operation_sdk.wire import SDKError
        if event in ('subprocess.Popen', 'os.system', 'os.fork', 'os.posix_spawn', 'os.exec') or event.startswith('socket.'):
            raise SDKError(2)
        if event == 'open':
            path, mode, flags = args
            if isinstance(path, int): return
            if type(path) is not str: raise SDKError(2)
            if (type(flags) is int and flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND)):
                raise SDKError(2)
            if path in allowed or active['private'] and path in protected: return
            # The immutable runtime image is an independently trusted platform;
            # its complete observed closure is checked before private action.
            if path.startswith(('/usr/local/lib/python3.12/', '/usr/lib/', '/lib/')): return
            if path.startswith('/sys/fs/cgroup/') or path in ('/proc/self/maps', '/proc/self/cgroup'): return
            raise SDKError(2)
    sys.addaudithook(check)
    return active


def _payload(value, admitted):
    from operation_sdk import wire, policy, secret_registration_contract as contract
    p = admitted.policy(); refs = p['scope']['references']
    wire.require(type(value) is dict and set(value) == {'schema','context_sha256','payload','references'}
        and type(value['schema']) is int and value['schema'] == 1
        and value['context_sha256'] == admitted.context_sha256, 7)
    rows = value['references']; wire.require(type(rows) is list and len(rows) == len(refs), 7)
    for actual, expected in zip(rows, refs):
        wire.require(type(actual) is dict and set(actual) == set(expected) | {'value'}
            and policy.canonical({key:actual[key] for key in expected}) == policy.canonical(expected), 7)
        try: contract.validate_value(actual['value'], expected['value_contract'])
        except contract.TraceError: raise wire.SDKError(7) from None
    return value['payload'], rows


def _plan_dimensions(value, limits, *, typed=False):
    from operation_sdk.wire import require
    require(type(value) is dict and type(value.get('schema')) is int and value['schema'] in (1,2), 7)
    agents='stages'if typed else'agents'
    for field, maximum in ((agents, limits['max_plan_agents']), ('checks', limits['max_plan_checks']), ('setup', limits['max_plan_setup'])):
        require(type(value.get(field,[])) is list and len(value.get(field,[])) <= maximum, 5)
    for task in value.get(agents,[]):
        require(type(task) is dict, 7)
        for key in('prompt','effective_prompt')if typed else('prompt',):
            if key in task:require(type(task[key])is str and len(task[key].encode('utf-8'))<=limits['max_prompt_bytes'],5)
    count = 0
    for task in value.get('checks',[]):
        if type(task) is dict and 'scorer' in task:
            scorer=task['scorer']; require(type(scorer)is dict and type(scorer.get('assets'))is list,7)
            count += len(scorer['assets'])
    require(count <= limits['max_scorer_assets'], 5)


def _legacy(provider, admitted, value, patterns):
    from pathlib import PurePosixPath, Path
    from operation_sdk import source, wire
    p=admitted.policy(); scope=p['scope']; limits=p['limits']; base=PurePosixPath(scope['base'])
    allowed={p['deployment']['provider_root']+'/'+name:{'sha256':pin,
        'maximum_bytes':limits['max_dependency_file_bytes'],'readonly':True}
        for name,pin in p['deployment']['resources'].items()}
    allowed.update({row['path']:{'sha256':row['sha256'],'maximum_bytes':min(row['maximum_bytes'],
        limits['max_prompt_bytes'])if row['role']=='prompt'else row['maximum_bytes'],'readonly':True}
             for row in scope['dependencies']})
    reader=source.ApprovedReader(allowed,max_file_bytes=limits['max_dependency_file_bytes'],
        max_total_bytes=limits['max_dependency_bytes'],max_files=limits['max_read_refs'])
    def dependency(path, maximum):
        result=reader.read(str(path),maximum)
        wire.require(not patterns.contains(result),7)
        return result
    def relative(name):
        wire.require(type(name)is str and not name.startswith('/') and '\\'not in name
            and str(PurePosixPath(name))==name and '..'not in PurePosixPath(name).parts,7)
        return str(base/name)
    _plan_dimensions(value,limits)
    for task in value.get('agents',[]):
        if 'prompt_file'in task:wire.require(relative(task['prompt_file'])in allowed,2)
    for task in value.get('checks',[]):
        if 'scorer'in task:
            scorer_bytes=0
            for asset in task['scorer']['assets']:
                selected=relative(asset['source']);wire.require(selected in allowed,2)
                scorer_bytes+=len(dependency(selected,limits['max_dependency_file_bytes']))
                wire.require(scorer_bytes<=16777216,5)
    profiles=provider.module('agent_profiles')
    profile=profiles.builtin() if scope['profile']is None else profiles.load(scope['profile'],reader=dependency)
    lab=provider.module('pi_lab')
    normalized=lab.validate_plan(value,Path(str(base)),agent_profile=profile,
        external_bindings=scope['external_bindings'],dependency_reader=dependency)
    _plan_dimensions(normalized,limits)
    checked=False
    if admitted.operation=='plan_check_project_v1':
        metadata={row['path']:row for row in scope['metadata']}
        def observe(path,kind):
            selected=str(PurePosixPath(str(path)));wire.require(selected in metadata,2)
            grant=metadata[selected];wire.require(kind in('exists','directory')
                and(kind!='directory'or grant['kind']=='directory'),2)
            parent=source.Namespace(str(PurePosixPath(selected).parent),private=False)
            try:
                wire.require(os.fstatvfs(parent.fd).f_flag&os.ST_RDONLY,4)
                info=parent.stat(PurePosixPath(selected).name)
                import stat
                wire.require(source.identity(info)==tuple(grant['identity'])
                    and(stat.S_ISDIR(info.st_mode)if grant['kind']=='directory'else stat.S_ISREG(info.st_mode)),4)
                return stat.S_ISDIR(info.st_mode) if kind=='directory'else stat.S_ISREG(info.st_mode)or stat.S_ISDIR(info.st_mode)
            finally:wire.require(parent.close(),6)
        lab.check_project_contract(Path(str(base)),normalized,metadata_reader=observe);checked=True
    return normalized,{'profile_validated':True,'project_contract_checked':checked,
                       'scorer_frozen':False,'dependencies_read':reader.count}


def _execute(provider, admitted, payload, rows, store_fd):
    import base64
    from operation_sdk import wire, policy, collect, secret_registration_contract as contract
    from operation_sdk import secret_registration_primitive as primitive
    p=admitted.policy(); op=admitted.operation; scope=p['scope']; limits=p['limits']
    patterns=collect.Patterns([row['value']for row in rows],limits)
    wire.require(type(payload)is dict or payload is None,7)
    if op in ('plan_validate_source_v1','plan_validate_ir_v1','plan_validate_legacy_v1','plan_check_project_v1'):
        wire.require(type(payload)is dict and set(payload)=={'plan'},7); value=payload['plan']
        wire.require(not patterns.contains(wire.encode(value,limits['max_payload_bytes'])),7)
        if op in ('plan_validate_legacy_v1','plan_check_project_v1'):
            normalized,checks=_legacy(provider,admitted,value,patterns)
        else:
            wire.require(type(value)is dict and type(value.get('schema'))is int and value['schema']==1,7)
            _plan_dimensions(value,limits,typed=True)
            api=provider.module('application_contracts')
            normalized=(api.validate_source if op=='plan_validate_source_v1'else api.validate_ir)(value)
            checks={'profile_validated':False,'project_contract_checked':False,'scorer_frozen':False,'dependencies_read':0}
        digest=hashlib.sha256(json.dumps(normalized,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
        return {'normalized_plan':normalized,'plan_sha256':digest,'digest_domain':'normalized_plan_utf8_v1',
                'validation_only':True,**checks},None,None
    if op=='redact_bytes_v1':
        wire.require(type(payload)is dict and set(payload)=={'bytes_base64'}and type(payload['bytes_base64'])is str,7)
        wire.require(len(payload['bytes_base64'])<=4*((p['input']['maximum_bytes']+2)//3),5)
        body=base64.b64decode(payload['bytes_base64'],validate=True)
        wire.require(len(body)<=p['input']['maximum_bytes'],5)
        api=provider.module('application_credentials'); result=api.Redactor([row['value']for row in rows]).bytes(body)
        wire.require(type(result)is bytes and not patterns.contains(result),10)
        return {'bytes_base64':base64.b64encode(result).decode('ascii'),'known_patterns_checked':True},None,None
    if op=='credentials_collect_v1':
        wire.require(payload=={} and len(rows)==len(scope['references']),7)
        applications={row['alias']:row['value']for row in rows if row['role']=='application'}
        inference=[row['value']for row in rows if row['role']=='inference'];wire.require(len(inference)==1,7)
        wire.require(len(set(applications.values()))==len(applications)and inference[0]not in applications.values(),7)
        return {'stage_id':p['stage_id'],'participant_id':p['participant_id'],'aliases':applications,
                'inference_value':inference[0]},None,None
    if op=='secret_register_create_only_v1':
        wire.require(type(payload)is dict and set(payload)=={'value'},7)
        try:size=contract.validate_value(payload['value'],scope['value_contract'])
        except contract.TraceError:raise wire.SDKError(7)from None
        wire.require(size<=limits['max_secret_bytes']and payload['value']not in[row['value']for row in rows],7)
        result=primitive.register_create_only(store_path=scope['store']['path'],store_fd=store_fd,
            expected_identity=scope['store']['identity'],reference=scope['write_reference'],
            operation_id=admitted.request()['operation_id'],context_sha256=admitted.context_sha256,
            value=payload['value'],value_contract=scope['value_contract'],
            limits=primitive.RegistrationLimits(limits['max_mutating_calls'],limits['max_owned_fds'],min(limits['max_result_bytes'],1048576)))
        native=result.to_wire()
        return None,{'observation':native,'owned_fd_tokens':list(result.owned_fd_tokens)},list(result.final_identity)if result.final_identity is not None else None
    if op=='resource_read_v1':
        wire.require(payload is None,7);resource=scope['resource'];path=p['deployment']['provider_root']+'/'+resource['path']
        from operation_sdk.source import ApprovedReader
        reader=ApprovedReader({path:{'sha256':p['deployment']['resources'][resource['path']],
            'maximum_bytes':resource['maximum_bytes'],'readonly':True}},max_file_bytes=resource['maximum_bytes'],
            max_total_bytes=resource['maximum_bytes'],max_files=1)
        body=reader.read(path,resource['maximum_bytes'])
        return {'bytes_base64':base64.b64encode(body).decode('ascii'),'resource_sha256':p['deployment']['resources'][resource['path']]},None,None
    raise wire.SDKError(2)


def serve(initial, expected, control_fd, private_fd, report_fd, store_fd, coordination_fd, probe):
    global _STAGE
    _STAGE='compile_policy'
    import importlib
    from operation_sdk import policy, runtime, source, state, wire, secret_registration_posix as native
    import base64
    import encodings.ascii
    import encodings.idna
    code=1; operation=None; native_result=None; final=None; dispatched=False
    compiler=policy.compile_discovery if probe else policy.compile_admission
    admitted=compiler(initial['policy'],initial['request'],trusted_policy_sha256=expected,now_ns=time.monotonic_ns())
    p=admitted.policy();limits=p['limits'];deadline=admitted.request()['expires_ns']/1000000000
    _STAGE='kernel_limits';measured=runtime.worker_limits(limits)
    if probe:wire.require(p['input']is None and p['scope']['store']is None and not p['scope']['references'],2)
    elif p['scope']['store']is not None:
        import stat
        info=os.fstat(store_fd);coord=os.fstat(coordination_fd)
        wire.require(source.identity(info)==tuple(p['scope']['store']['identity'])and stat.S_ISDIR(info.st_mode)
            and source.identity(coord)==tuple(p['scope']['coordination']['identity'])and stat.S_ISREG(coord.st_mode),11)
    verification=source.ReadBudget(limits['max_source_bytes']//2,limits['max_source_files'],
        initial_bytes=admitted.forecast()['bootstrap_verification_bytes'],initial_files=len(policy.CONSUMER_FILES)+2)
    _STAGE='provider_inventory';provider=source.Provider(p['deployment'],limits,budget=verification);provider.install()
    audit=_audit(p['deployment'],p['scope']['dependencies'])
    try:
        _STAGE='provider_preload';provider.preload()
        _STAGE='runtime_capture'
        runtime_state=runtime.capture(p['deployment'],limits,set(provider.modules),discovery=probe,budget=verification)
        verification.require_remaining(sum(row['bytes']for row in provider.loaded.values())+runtime_state['observed_source_bytes'],
                                       len(provider.loaded)+runtime_state['observed_source_files'])
        package=sys.modules['operation_sdk']
        ready={'schema':1,'kind':'probe'if probe else'ready','context_sha256':admitted.context_sha256,
            'operation':admitted.operation,'pid':os.getpid(),'runtime':runtime_state,'limits':measured,
            'sdk_files':dict(package.__sdk_files__),'sdk_sources':list(package.__sdk_observations__),
            'provider_sources':list(provider.loaded.values()),'operational_approval':False}
        _STAGE='ready_frame';wire.write_frame(report_fd,wire.encode(ready,limits['max_control_bytes']),deadline)
        if probe:return
        operation=state.reserve(admitted,time.monotonic_ns());operation.ready(admitted.context_sha256)
        go=wire.decode(wire.read_frame(control_fd,limits['max_control_bytes'],deadline,eof=True),limits['max_control_bytes'])
        wire.require(go=={'schema':1,'kind':'go','context_sha256':admitted.context_sha256}and type(go['schema'])is int,7)
        operation.claim(time.monotonic_ns())
        private=wire.decode(wire.read_frame(private_fd,limits['max_payload_bytes'],deadline,eof=True),limits['max_payload_bytes'])
        payload,rows=_payload(private,admitted);audit['private']=True
        dispatched=True
        data,native_result,final=_execute(provider,admitted,payload,rows,store_fd)
        provider.conserve();after=runtime.capture(p['deployment'],limits,set(provider.modules),budget=verification)
        wire.require(after['modules']==runtime_state['modules']and after['files']==runtime_state['files'],4)
        ok=native_result is None or native_result['observation']['ack_ready']is True
        terminal={'schema':1,'kind':'result','context_sha256':admitted.context_sha256,'operation':admitted.operation,
            'status':'ok'if ok else'unknown','code':0 if ok else 8,'data':data,'native':native_result,
            'final_identity':final,'facts':{'handler_calls':1,'reference_bindings_checked':len(rows),
                'source_conserved':True,'effect':'created'if native_result and ok else'none'if native_result is None else'unknown'}}
        code=0
    except BaseException as error:
        code=error.code if isinstance(error,wire.SDKError)else 7
        terminal={'schema':1,'kind':'result','context_sha256':admitted.context_sha256,'operation':admitted.operation,
            'status':'unknown'if dispatched and admitted.operation=='secret_register_create_only_v1'else'refused',
            'code':code,'data':None,'native':native_result,'final_identity':final,
            'facts':{'handler_calls':int(dispatched),'reference_bindings_checked':0,'source_conserved':False,
                'effect':'unknown'if dispatched and admitted.operation=='secret_register_create_only_v1'else'none'}}
        if probe:terminal['probe_diagnostic']={'stage':_STAGE,'detail':getattr(runtime,'_DIAGNOSTIC',None)}
    finally:
        provider.close()
    wire.write_frame(report_fd,wire.encode(terminal,limits['max_result_bytes']),deadline)
    for fd in (control_fd,private_fd):native.close(fd)
    # The final endpoint close is not predicted in the frame being emitted.
    native.close(report_fd)


if __name__=='__main__':
    try:_bootstrap()
    except BaseException as error:
        if len(sys.argv)==8 and sys.argv[-1]=='1':
            # Environment probes select no private source/store and execute no
            # handler. Fixed stage/code diagnostics contain no exception body.
            module=sys.modules.get('operation_sdk.worker')
            stage=getattr(module,'_STAGE','bootstrap')
            code=getattr(error,'code',1)
            if type(code)is not int:code=1
            os.write(2,json.dumps({'probe_stage':stage,'code':code}).encode())
        os._exit(71)
