"""Parent-owned lifecycle for one exact compiled application stage.

The coordinator grants no workflow discovery, child control, automatic recovery,
or report repair. Explicit continuation keeps the same live helper and ledger.
"""
import copy
import hashlib
import http.client
import math
import os
from pathlib import Path
import re
import secrets
import socket
import threading
import time

import agent_profiles
import application_contracts as c
import application_credentials as credentials
import application_runtime_contracts as runtime_contracts
from application_evidence import open_directory,read_file
from application_client import OwnedHelper,Grant,_binding,API_RESOURCES,BROWSER_RESOURCES
from application_execution_authority import ReviewedAuthority
from native_budget_execution import Coordinator as NativeCoordinator,_private_context,_purge_context
import native_budget_controls as budgets
import ownership_registry
from parallel_allocator import Allocator,LIVE
import prompt_contract
import resources
import stage_control as controls


SETTLEMENT_CODES=frozenset(('UNKNOWN','WRITERS_UNCONFIRMED','FINISH_ALREADY_ATTEMPTED',
    'FINISH_RPC_FAILED','FINISH_DIAGNOSTIC_FAILED','FINISH_BUDGET_INVALID','RECEIPT_INDEX_INVALID',
    'RECEIPT_REDACTION_REJECTED','COMPLETION_BINDING_INVALID','REDACTION_STATE_FAILED',
    'HELPER_CLEANUP_FAILED','STARTUP_CLEANUP_UNCONFIRMED','FINISH_UNCONFIRMED',
    'HELPER_RECEIPT_INVALID','CONTEXT_UNCONFIRMED','CONTEXT_PURGE_FAILED'))


def _settlement_code(value):
    return value if type(value) is str and value in SETTLEMENT_CODES else 'UNKNOWN'


class ApplicationExecutionError(ValueError):
    def __init__(self,settlement_code=None):
        super().__init__('Application execution ownership or accounting unavailable')
        self._settlement_code=_settlement_code(settlement_code)


_APPLICATION_EXECUTION_ERROR_TYPE=ApplicationExecutionError


def settlement_failure_recorded(coordinator):
    """Distinguish an unknown recorded failure from a normal successful close."""
    return type(coordinator) is _APPLICATION_COORDINATOR_TYPE and '_settlement_failure_code' in vars(coordinator)


def settlement_diagnostic(error=None,coordinator=None):
    """Closed metadata only; never inspect exception arguments or arbitrary objects."""
    code='UNKNOWN'
    if settlement_failure_recorded(coordinator):
        return {'schema':1,'code':_settlement_code(vars(coordinator)['_settlement_failure_code'])}
    if type(error) is _APPLICATION_EXECUTION_ERROR_TYPE:
        code=_settlement_code(vars(error).get('_settlement_code'))
    return {'schema':1,'code':code}


def _remember_settlement(coordinator,code,error=None):
    """Keep the first observed settlement failure through secondary cleanup errors."""
    state=vars(coordinator)
    if '_settlement_failure_code' not in state:
        state['_settlement_failure_code']=_settlement_code(code)
    if type(error) is _APPLICATION_EXECUTION_ERROR_TYPE:
        error._settlement_code=_settlement_code(state['_settlement_failure_code'])


def _known_clean_helper(receipt,runroot):
    required={'schema','status','workspace','safe_to_continue'}
    known=(type(receipt) is dict and required<=set(receipt) and not set(receipt)-required-{'evidence','evidence_root'}
        and type(receipt['schema']) is int and receipt['schema']==1 and receipt['status']=='removed'
        and receipt['workspace']=='clean' and receipt['safe_to_continue'] is True)
    if not known:return False
    optional=set(receipt)&{'evidence','evidence_root'}
    if not optional:return True  # Compact controlled helper implementations.
    if optional!={'evidence','evidence_root'} or receipt['evidence'] not in ('retained','quarantined'):return False
    root=receipt['evidence_root']
    if root is None:return receipt['evidence']=='quarantined'
    if receipt['evidence']!='retained' or type(root) is not str or len(root)>4096:return False
    path=Path(root)
    return (path.is_absolute() and str(path)==root and path.parent==Path(runroot).absolute()/'application-evidence'
        and re.fullmatch(r'pi-application-[a-f0-9]{16}',path.name) is not None)


def _same_policy(left,right):
    left,right=resources.validate_policy(left),resources.validate_policy(right)
    for value in (left,right):
        for section in ('runtime','build'):value[section]['memory']=resources.memory_bytes(value[section]['memory'])
    return left==right


def helper_control(helper,body):
    """One bounded parent-only loopback POST, hard deadline, never retried."""
    if type(helper.host_port) is not int or not 1<=helper.host_port<=65535:raise ApplicationExecutionError()
    wire=c.canonical(body)
    if len(wire)>256*1024:raise ApplicationExecutionError()
    expired=threading.Event();sockets=[]
    class Connection(http.client.HTTPConnection):
        def connect(self):
            super().connect();sockets.append(self.sock)
            if expired.is_set():self.sock.close();raise ApplicationExecutionError()
    connection=Connection('127.0.0.1',helper.host_port,timeout=5)
    def expire():
        expired.set()
        for sock in sockets:
            try:sock.shutdown(socket.SHUT_RDWR)
            except OSError:pass
        connection.close()
    timer=threading.Timer(5,expire);timer.daemon=True;timer.start()
    try:
        connection.request('POST','/control',wire,{'Authorization':'Bearer '+helper.authority._control_token,'Content-Type':'application/json'})
        response=connection.getresponse();raw=response.read(256*1024+1)
        if expired.is_set() or response.status!=200 or len(raw)>256*1024:raise ApplicationExecutionError()
        value=c.loads(raw,max_bytes=256*1024)
        if type(value) is not dict or type(value.get('schema')) is not int or value['schema']!=1 or value.get('ok') is not True:
            raise ApplicationExecutionError()
        return value
    except (OSError,http.client.HTTPException,ValueError,KeyError,TypeError):raise ApplicationExecutionError() from None
    finally:timer.cancel();connection.close()


def extension_order_sha256(stage,profile,*,runtime_root):
    release=stage['profile_binding']['pi_release'];root=Path(runtime_root)
    if profile['kind']!='application-client':raise ApplicationExecutionError()
    binding={'id':'application-client','pi_release':release,'sha256':agent_profiles.identity(profile),
             'assets':{asset['target']:asset['sha256'] for asset in profile['assets']}}
    if binding!=stage['profile_binding']:raise ApplicationExecutionError()
    paths=runtime_contracts.APPLICATION_EXTENSION_PATHS;hashes={}
    for path in paths:
        if path.startswith('/opt/pi-lab/'):
            body=agent_profiles.read_asset(root/Path(path).name)
        else:
            selected=[asset for asset in profile['assets'] if asset['target']==Path(path).name]
            if len(selected)!=1:raise ApplicationExecutionError()
            body=agent_profiles.read_asset(selected[0]['source'])
            if hashlib.sha256(body).hexdigest()!=selected[0]['sha256']:raise ApplicationExecutionError()
        hashes[path]=hashlib.sha256(body).hexdigest()
    for asset in profile['assets']:
        if hashlib.sha256(agent_profiles.read_asset(asset['source'])).hexdigest()!=asset['sha256']:raise ApplicationExecutionError()
    return runtime_contracts.extension_identity(release,binding,c.digest(sorted(stage['tool_schemas'],key=lambda value:value['name'])),hashes)['sha256']


def verify_emitted(stage,segment_task,emitted):
    """Check parent-retained worker observations; this is not effect authority."""
    try:
        frozen=stage['effective_prompt'];frozen_sha=hashlib.sha256(frozen.encode()).hexdigest()
        if segment_task.get('prompt')!=frozen or segment_task['application_execution']['effective_prompt_sha256']!=frozen_sha:
            raise ApplicationExecutionError()
        continuation=segment_task.get('application_continuation');proof_continuation=None;expected=frozen
        if continuation is not None:
            c.exact(continuation,{'schema','command_id','continues_segment_id','message','sha256'},'/continuation')
            if type(continuation['schema']) is not int or continuation['schema']!=1:raise ApplicationExecutionError()
            if not controls.valid_id(continuation['command_id']) or not controls.valid_id(continuation['continues_segment_id']):raise ApplicationExecutionError()
            c.text(continuation['message'],'/continuation/message',16384);c.sha256(continuation['sha256'],'/continuation/sha256')
            expected=continuation['message']
            if hashlib.sha256(expected.encode()).hexdigest()!=continuation['sha256']:raise ApplicationExecutionError()
            context=segment_task.get('application_context','').split('/')
            if len(context)!=6 or context[:4]!=['','opt','pi-control','segments'] or not controls.valid_id(context[4]) or context[5]!='application-context.json':
                raise ApplicationExecutionError()
            if segment_task.get('resume_session')!='/opt/pi-control/segments/'+context[4]+'/session.jsonl':raise ApplicationExecutionError()
            proof_continuation={key:continuation[key] for key in ('command_id','continues_segment_id','sha256')}
        elif segment_task.get('resume_session') is not None:raise ApplicationExecutionError()
        observations={}
        for name,maximum in (('effective-prompt.txt',131072),('application-prompt.json',4096)):
            reference=emitted[name];c.exact(reference,{'sha256','path','origin'},'/emitted')
            c.sha256(reference['sha256'],'/emitted/sha256');c.text(reference['path'],'/emitted/path',4096)
            path=Path(reference['path'])
            if reference['origin']!='worker_reported' or not path.is_absolute() or str(path)!=reference['path'] or '..' in path.parts:
                raise ApplicationExecutionError()
            root=open_directory(str(path.parent))
            try:body=read_file(root,path.name,maximum)
            finally:os.close(root)
            if hashlib.sha256(body).hexdigest()!=reference['sha256']:raise ApplicationExecutionError()
            observations[name]=body
        if observations['effective-prompt.txt']!=expected.encode():raise ApplicationExecutionError()
        expected_proof={'schema':1,'frozen_effective_prompt_sha256':frozen_sha,
            'sent_prompt_sha256':hashlib.sha256(expected.encode()).hexdigest(),'continuation':proof_continuation}
        if c.canonical(c.loads(observations['application-prompt.json'],max_bytes=4096))!=c.canonical(expected_proof):
            raise ApplicationExecutionError()
        return True
    except (OSError,ValueError,KeyError,TypeError,AttributeError):raise ApplicationExecutionError() from None


class ApplicationCoordinator(NativeCoordinator):
    def __repr__(self):return '<ApplicationCoordinator private capabilities withheld>'

    def __init__(self,lab,args,image,runroot,workspace,desc,task,profile,redaction_values):
        self.lab,self.args,self.image=lab,args,image
        self.runroot,self.workspace=Path(runroot).absolute(),Path(workspace).absolute()
        self.desc,self.task,self.profile=copy.deepcopy(desc),copy.deepcopy(task),copy.deepcopy(profile)
        spec=getattr(args,'_application_execution',None)
        if type(spec) is not dict or not {'plan','stage_id','authority'}<=set(spec) or set(spec)-{'plan','stage_id','authority','external_support','redaction_sink'}:
            raise ApplicationExecutionError()
        self.plan=c.validate_ir(spec['plan']);self.authority=spec['authority']
        if type(self.authority) is not ReviewedAuthority or self.authority.plan!=self.plan:raise ApplicationExecutionError()
        self.stage=next((stage for stage in self.plan['stages'] if stage['id']==spec['stage_id']),None)
        if self.stage is None:raise ApplicationExecutionError()
        self.release=self.plan['runtime']['pi_release'];self.plan_sha256=self.plan['plan_sha256']
        self.allowed_tools=list(self.stage['tools']);self._maximum=self.stage['limits']['max_tool_calls']
        self._support=(spec['external_support'] if 'external_support' in spec else
                       getattr(getattr(args,'_indexed_session',None),'native_budget_support',None))
        if self._support is not None and (type(self._support) is not dict or set(self._support)!={'pool','reservation','registry','network_record'}):
            raise ApplicationExecutionError()
        self._sink=spec.get('redaction_sink')
        if self._sink is not None and not callable(self._sink):raise ApplicationExecutionError()
        self.registry=ownership_registry.CURRENT.get();self.remote=None
        if self.registry is None or getattr(args,'_parallel_session',None) is not None:raise ApplicationExecutionError()
        if (getattr(args,'in_place',False) or args.platform!='linux/arm64' or getattr(args,'native_platform',None)!='linux/arm64'
                or image!=self.plan['runtime']['image_id'] or args.platform!=self.plan['runtime']['platform']
                or getattr(args,'observed_pi_version',None)!=self.release or args.profile!=self.plan['runtime']['container_profile']
                or not _same_policy(args.resource_report['effective'],self.plan['runtime']['resources'])):raise ApplicationExecutionError()
        runtime=self.plan['runtime']['resources']['runtime']
        if (type(getattr(args,'cpus',None)) not in (int,float) or args.cpus!=runtime['cpus']
                or resources.memory_bytes(args.memory)!=resources.memory_bytes(runtime['memory'])
                or type(args.pids_limit) is not int or args.pids_limit!=runtime['pids_limit']
                or type(args.jobs) is not int or args.jobs!=runtime['jobs']):raise ApplicationExecutionError()
        if (self.workspace!=self.runroot/'workspace' or self.workspace.is_symlink() or not self.workspace.is_dir()
                or self.authority.runroot!=self.runroot or self.authority.project!=Path(args.project).resolve()
                or self.authority._grants or self.authority._launched):raise ApplicationExecutionError()
        if (controls.read(self.runroot/'plan.json')!=self.plan
                or controls.read(self.runroot/'stages'/desc['stage_id']/'descriptor.json')!=desc
                or any(controls.read(self.runroot/'identity.json').get(key)!=desc.get(key) for key in ('run_id','attempt_id'))
                or desc.get('kind')!='agent' or desc.get('workspace')!=str(self.workspace)
                or Path(desc.get('control','')).absolute()!=self.runroot/'controls'/desc['stage_id']):raise ApplicationExecutionError()
        self.extension_sha256=extension_order_sha256(self.stage,profile,runtime_root=self.runroot/'trusted-runtime')
        marker={'schema':1,'plan_sha256':self.plan_sha256,'stage_id':self.stage['id'],
            'effective_prompt_sha256':hashlib.sha256(self.stage['effective_prompt'].encode()).hexdigest(),
            'tool_schema_sha256':c.digest(sorted(self.stage['tool_schemas'],key=lambda value:value['name'])),
            'profile_binding':copy.deepcopy(self.stage['profile_binding']),'extension_order_sha256':self.extension_sha256}
        if (c.canonical(task.get('application_execution'))!=c.canonical(marker) or task.get('name')!=self.stage['id'] or task.get('prompt')!=self.stage['effective_prompt']
                or c.canonical(task.get('tools'))!=c.canonical(self.stage['tools']) or c.canonical(task.get('tool_schemas'))!=c.canonical(self.stage['tool_schemas'])
                or task.get('cwd')!='.' or task.get('require_tools')!=[] or any(type(task.get(key)) is not int or task[key]!=value for key,value in self.stage['limits'].items())
                or desc.get('label')!='agent-'+str(self.plan['stages'].index(self.stage)+1)+'-'+self.stage['id']):raise ApplicationExecutionError()
        receipt=getattr(args,'frozen_agent_profile',None)
        if receipt is None or agent_profiles.staged(receipt)!=profile:raise ApplicationExecutionError()
        if getattr(args,'_indexed_session',None) is not None and self._support is None:raise ApplicationExecutionError()
        if type(redaction_values) not in (tuple,list) or len(redaction_values)>1024:raise ApplicationExecutionError()
        for value in redaction_values:c.text(value,'/redaction_values',16384,empty=True)
        self._values=list(dict.fromkeys(value for value in redaction_values if value))
        self.helper=self.pool=self.reservation=None;self.external=False;self.failed=False;self.closed=False
        self.binding=self.context=None;self._cached=self._cached_at=None
        self._paths=[];self._used=set();self._segments=[];self._settled=True;self._running=False
        self._helper_attempted=False;self._uncertain_context=False;self._finish_attempted=False;self._completion=None
        self._startup_cleanup=None;self._startup_failure=None;self._helper_launch_attempted=None;self._preworker_binding=None
        self._worker_ever_started=False
        self.trial_id=(self._support['reservation'].binding.get('trial_id') if self._support is not None else self.registry.binding.get('trial_id'))
        self.authority.revalidate();self.redaction_values()

    def _error(self):
        self.failed=True
        raise ApplicationExecutionError()

    def redaction_values(self):
        def strings(value):
            if type(value) is str:return [value] if value else []
            if type(value) is dict:return [item for nested in value.values() for item in strings(nested)]
            if type(value) in (list,tuple):return [item for nested in value for item in strings(nested)]
            return []
        values=[*self._values,*strings(self.authority._values),*strings(self.authority._inference_values),self.authority._control_token,
                *(grant.capability for grant in self.authority._grants),*self.authority._budget_tokens.values()]
        if self.helper is not None:values.extend(item.capability for item in self.helper.reservations if item.capability)
        if self.reservation is not None and self.reservation.capability:values.append(self.reservation.capability)
        self._values=list(dict.fromkeys(value for value in values if value))
        if self._sink is not None:self._sink(list(self._values))
        return list(self._values)

    def _rpc(self,action,**fields):
        reply=helper_control(self.helper,{'schema':1,'action':action,**fields})
        expected={'schema','ok','budget','receipts'} if action=='finish' else {'schema','ok','budget'}
        if action=='finish' and type(reply) is dict and 'file_diagnostic' in reply:expected.add('file_diagnostic')
        c.exact(reply,expected,'/control')
        if action=='finish' and 'file_diagnostic' in reply:
            # No diagnostic is authority or completion evidence. Invalid optional
            # metadata is unknown and cannot fail an otherwise valid finish.
            reply=copy.deepcopy(reply)
            try:
                from application_files import validate_file_diagnostic
                reply['file_diagnostic']=validate_file_diagnostic(reply['file_diagnostic'])
            except (KeyboardInterrupt,SystemExit,GeneratorExit,TimeoutError):raise
            except Exception:reply.pop('file_diagnostic',None)
        return reply

    def _retain_file_diagnostic(self,reply):
        try:
            if 'file_diagnostic' not in reply:return
            from application_files import validate_file_diagnostic
            value=validate_file_diagnostic(reply['file_diagnostic'])
            path=self.runroot/'stages'/self.desc['stage_id']/'application-file-diagnostic.json'
            controls.atomic(path,value,0o600)
        except (KeyboardInterrupt,SystemExit,GeneratorExit,TimeoutError):raise
        except Exception:pass  # Ordinary owner metadata failure stays unknown.

    def _remaining(self):
        path=self.runroot/'stages'/self.desc['stage_id']/'budget.json'
        if path.exists():
            budget=controls.read(path);remaining=budget['deadline_host_monotonic']-time.monotonic()
        elif self.binding is None:remaining=self.task['timeout_seconds']
        else:self._error()
        if type(remaining) not in (int,float) or not math.isfinite(remaining) or not 0<remaining<=3600:self._error()
        return min(remaining,self.task['timeout_seconds'])

    def _start(self,binding):
        runtime=self.plan['runtime']['resources']['runtime'];weight={'cpu_millis':round(runtime['cpus']*1000),
            'memory_mib':resources.memory_bytes(runtime['memory'])//1024**2,'pids_limit':runtime['pids_limit']}
        footprint=BROWSER_RESOURCES if self.authority.launch_spec()['browser'] else API_RESOURCES
        borrowed=None
        if self._support is not None:
            if type(self._support) is not dict or set(self._support)!={'pool','reservation','registry','network_record'}:self._error()
            self.pool,self.reservation=self._support['pool'],self._support['reservation'];self.external=True
            borrowed=self._support['network_record'];row=self.reservation
            if (self._support['registry'] is not self.registry or self.pool.records.get(row.identity) is not row or row.kind!='stage'
                    or row.state not in ('reserved','launching','running') or row.resources!=weight
                    or row.binding.get('generation')!=self.registry.generation or self.args.network!=borrowed.get('container')
                    or any(row.binding.get(key)!=binding[key] for key in ('run_id','attempt_id','trial_id'))
                    or row.binding.get('workspace')!=str(self.workspace)
                    or (binding['trial_id'] is None or 'stage_id' in row.binding) and row.binding.get('stage_id')!=binding['stage_id']):self._error()
        else:
            if self.args.network!='bridge':self._error()
            daemon=self.lab.docker_info()
            if type(daemon.get('NCPU')) is not int or daemon['NCPU']<1 or type(daemon.get('MemTotal')) is not int or daemon['MemTotal']<1:self._error()
            capacity={'cpu_millis':math.floor(daemon['NCPU']*.5*1000),'memory_mib':math.floor(daemon['MemTotal']*.5/1024**2),
                      'pids_limit':weight['pids_limit']+footprint['pids_limit']}
            if any(weight[key]+footprint[key]>capacity[key] for key in capacity):self._error()
            self.pool=Allocator(capacity)
        self.authority.ensure_snapshot_clean();grant=self.authority.grant(self.stage['id'],binding);self.redaction_values()
        self._helper_attempted=True;self._before_records=set(self.pool.records)
        try:
            self.helper=OwnedHelper.start(self.authority,lab=self.lab,args=self.args,registry=self.registry,allocator=self.pool,
                participant_resources=weight,participant_reservation=self.reservation,borrowed_network=borrowed)
        except BaseException as exc:
            self._startup_cleanup=copy.deepcopy(getattr(exc,'application_helper_cleanup',None))
            self._helper_launch_attempted=getattr(exc,'application_helper_launch_attempted',None)
            try:
                from application_client import validate_startup_failure
                self._startup_failure=validate_startup_failure(getattr(exc,'application_helper_startup',None),runroot=self.runroot)
            except (OSError,ValueError,TypeError,AttributeError):self._startup_failure=None
            raise
        self.reservation=self.helper.participant_reservation;self.redaction_values()
        context=self.authority.application_context(grant,self.extension_sha256)
        snapshot=self._rpc('activate',capability=grant.capability,remaining_seconds=self._remaining())['budget']
        return context,(borrowed['container'] if borrowed else self.helper.network_record['container']),snapshot

    def _verify_context(self,context,binding):
        grant=self.authority._grants[-1]
        c.exact(context,{'schema','scope','capability','base_url','tool_schemas','budget_context'},'/context')
        budget=context['budget_context'];c.exact(budget,{'schema','pi_release','scope','allowed_tools','prepare_arguments',
            'extension_order_sha256','tool_schema_sha256','base_url','capability'},'/context/budget_context')
        expected_budget={'schema':1,'pi_release':self.release,'scope':grant.scope,'allowed_tools':self.allowed_tools,
            'prepare_arguments':{name:'none' for name in self.allowed_tools},'extension_order_sha256':self.extension_sha256,
            'tool_schema_sha256':c.digest(sorted(self.stage['tool_schemas'],key=lambda value:value['name'])),
            'base_url':'http://pi-application:8081/budget','capability':self.authority._budget_tokens[grant.capability]}
        if (type(context['schema']) is not int or context['schema']!=1 or context['scope']!=grant.scope
                or context['capability']!=grant.capability or context['base_url']!='http://pi-application:8081/tool'
                or c.canonical(context['tool_schemas'])!=c.canonical(self.stage['tool_schemas']) or c.canonical(budget)!=c.canonical(expected_budget)):self._error()
        if context!=self.authority.application_context(grant,self.extension_sha256) or any(grant.scope.get(key)!=value for key,value in binding.items()):self._error()
        self.redaction_values();return copy.deepcopy(context)

    def begin_segment(self,segment_id,session_id,control,directive=None):
        if self.failed or self.closed or not self._settled or not controls.valid_id(segment_id) or not controls.valid_id(session_id):self._error()
        binding={'run_id':self.desc['run_id'],'trial_id':self.trial_id,'attempt_id':self.desc['attempt_id'],'stage_id':self.desc['stage_id'],
                 'segment_id':segment_id,'session_id':session_id,'plan_sha256':self.plan_sha256}
        self._preworker_binding=copy.deepcopy(binding)
        _binding(binding,self.plan_sha256);folder=Path(self.desc['control'])/'segments'/segment_id
        if Path(control).absolute()!=folder.absolute() or segment_id in self._used:self._error()
        try:
            self.authority.revalidate()
            if controls.read(self.runroot/'plan.json')!=self.plan or agent_profiles.staged(self.args.frozen_agent_profile)!=self.profile:self._error()
            if extension_order_sha256(self.stage,self.profile,runtime_root=self.runroot/'trusted-runtime')!=self.extension_sha256:self._error()
            if self.binding is None:
                if directive is not None:self._error()
                context,network,snapshot=self._start(binding)
            else:
                if session_id!=self.binding['session_id'] or type(directive) is not dict:self._error()
                if credentials.Redactor(self.redaction_values()).contains(c.canonical(directive)):self._error()
                record,target,intent=self._command(directive.get('id'),'steer')
                if record!=directive:self._error()
                before=self.status(force=True)
                if before['accounting']!='available':self._error()
                old=self.authority._grants[-1];scope={**copy.deepcopy(old.scope),'segment_id':segment_id}
                capability,budget_token=secrets.token_hex(32),secrets.token_hex(32)
                known=set(self.redaction_values())
                if capability==budget_token or capability in known or budget_token in known:self._error()
                self._values.extend((capability,budget_token));self.redaction_values()
                snapshot=self._rpc('continue',scope=scope,capability=capability,budget_token=budget_token)['budget']
                if snapshot['limits']!=before['limits'] or snapshot['counts']!=before['counts']:self._error()
                grant=Grant(scope,capability);self.authority._revoked.add(old.capability);self.authority._grants.append(grant)
                self.authority._budget_tokens[capability]=budget_token
                self.authority._grant_digests[capability]=c.digest({'scope':scope,'budget_token':budget_token})
                context=self.authority.application_context(grant,self.extension_sha256);network=self._network
                controls.atomic(target,{**intent,'status':'applied','budget':snapshot})
            self.context=self._verify_context(context,binding);self.binding,self._network=binding,network
            if type(network) is not str or not network or len(network)>128:self._error()
            self._snapshot(snapshot);self._uncertain_context=True
            path=folder/'application-context.json';identity=_private_context(path,self.context);self._paths.append((path,identity));self._uncertain_context=False
            self._used.add(segment_id);self._segments.append(copy.deepcopy(self.authority._grants[-1].scope))
            if not self.external:
                row=self.reservation;self.pool.consume(row.identity,row.capability,row.binding,row.resources)
            self._settled=False;self._running=False
            return {'context_path':'/opt/pi-control/segments/'+segment_id+'/application-context.json','network':network}
        except (OSError,ValueError,KeyError,TypeError) as exc:
            self.failed=True
            raise ApplicationExecutionError() from exc

    def status(self,force=False):
        self._active()
        if type(force) is not bool:self._error()
        if not force and self._cached_at is not None and 0<=time.monotonic()-self._cached_at<5:return copy.deepcopy(self._cached)
        try:return self._snapshot(self._rpc('status')['budget'])
        except (OSError,ValueError,KeyError,TypeError):self._error()

    def mark_running(self):
        self._worker_ever_started=True
        return super().mark_running()

    def extend(self,command_id,max_tool_calls,remaining_seconds):
        try:
            record,target,intent=self._command(command_id,'extend_budget');before=self.status(force=True)
            budget=controls.read(self.runroot/'stages'/self.desc['stage_id']/'budget.json');limits=record['limits']
            if (record.get('expected_budget_revision')!=budget['revision'] or type(record.get('expected_budget_revision')) is not int
                    or limits.get('max_tool_calls')!=max_tool_calls or type(max_tool_calls) is not int or not self._maximum<=max_tool_calls<=500
                    or any(limits.get(key)!=before['limits'][key] for key in ('reporting_reserve_calls','reporting_reserve_seconds'))
                    or type(remaining_seconds) not in (int,float) or not math.isfinite(remaining_seconds) or not 0<remaining_seconds<=limits['timeout_seconds']):self._error()
            remaining=budget['started_host_monotonic']+limits['timeout_seconds']-time.monotonic()
            if not math.isfinite(remaining) or not 0<remaining<=3600:self._error()
            old_timeout=budget['effective_limits']['timeout_seconds']
            if type(old_timeout) is not int or type(limits['timeout_seconds']) is not int or limits['timeout_seconds']<old_timeout:self._error()
            duration=remaining if limits['timeout_seconds']>old_timeout else None
            value=self._snapshot(self._rpc('extend',max_tool_calls=max_tool_calls,remaining_seconds=duration)['budget'],maximum=max_tool_calls)
            controls.atomic(target,{**intent,'status':'applied','budget':value});return value
        except (OSError,ValueError,KeyError,TypeError):self._error()

    def after_segment(self,writers_confirmed):
        self._active()
        if writers_confirmed is not True or self._settled:self._error()
        try:
            value=self._snapshot(self._rpc('checkpoint')['budget'])
            if not credentials.workspace_inspected_clean(self.workspace,credentials.Redactor(self.redaction_values())):self._error()
            if not self.external:
                if self.reservation.state not in ('launching','running'):self._error()
                self.reservation.state='reserved';self.reservation.capability=secrets.token_hex(32)
            self._settled=True;self._running=False;self.redaction_values();return value
        except (OSError,ValueError,KeyError,TypeError):self._error()

    @property
    def completion_context(self):return copy.deepcopy(self._completion)

    def _completion_binding(self,scope):
        return {**{key:scope[key] for key in ('run_id','trial_id','attempt_id','stage_id','segment_id','session_id','plan_sha256')},
            'profile_sha256':self.stage['profile_binding']['sha256'],'release_contract_sha256':runtime_contracts.identity(self.release)['sha256'],
            'report_contract_sha256':c.digest(self.stage['completion']),'pi_release':self.release}

    def close(self,writers_confirmed):
        if self.closed:return copy.deepcopy(self._cleanup)
        safe=writers_confirmed is True
        if not safe:_remember_settlement(self,'WRITERS_UNCONFIRMED')
        diagnostic_control=None
        preworker=self.binding is None and not self._segments and not self._running
        finished=self.helper is None or preworker;receipt=None
        if self.helper is not None and safe and self.binding is not None:
            settlement_phase='FINISH_ALREADY_ATTEMPTED'
            try:
                if self._finish_attempted:self._error()
                self._finish_attempted=True;settlement_phase='FINISH_RPC_FAILED'
                reply=self._rpc('finish',writers_confirmed=True)
                settlement_phase='FINISH_DIAGNOSTIC_FAILED'
                self._retain_file_diagnostic(reply)
                settlement_phase='FINISH_BUDGET_INVALID';snapshot=self._snapshot(reply['budget'])
                settlement_phase='RECEIPT_INDEX_INVALID';index=reply['receipts']
                if type(index) is not dict or len(index)>500:self._error()
                for key,value in index.items():
                    c.slug(key,'/receipts');c.exact(value,{'path','sha256'},'/receipts');c.relative(value['path'],'/receipts/path');c.sha256(value['sha256'],'/receipts/sha256')
                    if not value['path'].startswith('receipts/'):self._error()
                settlement_phase='RECEIPT_REDACTION_REJECTED'
                if credentials.Redactor(self.redaction_values()).contains(c.canonical(index)):self._error()
                settlement_phase='COMPLETION_BINDING_INVALID'
                scope=self.authority._grants[-1].scope
                self._completion={'binding':self._completion_binding(scope),'parent_receipts':copy.deepcopy(index),
                    'evidence_root':str(getattr(self.helper,'evidence_data_root',self.helper.evidence_root)/'raw'),
                    'report_root':str(getattr(self.helper,'evidence_data_root',self.helper.evidence_root)/'outputs'),
                    'authorized_segment_ids':[item['segment_id'] for item in self._segments]}
                self.authority._revoked.add(self.authority._grants[-1].capability);finished=snapshot['accounting']=='available'
            except (KeyboardInterrupt,SystemExit,GeneratorExit,TimeoutError) as error:
                _remember_settlement(self,settlement_phase,error)
                diagnostic_control=error;self.failed=True;finished=False
            except (OSError,ValueError,KeyError,TypeError) as error:
                _remember_settlement(self,settlement_phase,error)
                self.failed=True;finished=False
        settlement_phase='REDACTION_STATE_FAILED'
        try:
            self.redaction_values()
            if self.helper is not None:
                settlement_phase='HELPER_CLEANUP_FAILED';receipt=self.helper.cleanup(writers_absent=safe)
            else:
                settlement_phase='STARTUP_CLEANUP_UNCONFIRMED'
                if self._helper_attempted:
                    pending=[row for key,row in self.pool.records.items() if key not in self._before_records and row.state in LIVE]
                    unresolved=[row for row in self.registry.load() if row.get('application_helper') is True and row.get('client_mode')=='application-execution'
                        and row.get('runroot')==str(self.runroot) and row.get('status') not in ('absent','released')]
                    if pending or unresolved:finished=False
                receipt=(copy.deepcopy(self._startup_cleanup) if self._helper_attempted else
                         {'schema':1,'status':'removed','safe_to_continue':safe})
                if type(receipt) is not dict:finished=False;receipt={}
            settlement_phase='WRITERS_UNCONFIRMED'
            if not safe:self._error()
            settlement_phase='FINISH_UNCONFIRMED'
            if not finished:self._error()
            settlement_phase='HELPER_RECEIPT_INVALID'
            if not _known_clean_helper(receipt,self.runroot):self._error()
            settlement_phase='CONTEXT_UNCONFIRMED'
            if self._uncertain_context:self._error()
            settlement_phase='CONTEXT_PURGE_FAILED'
            for path,identity in self._paths:_purge_context(path,identity)
            settlement_phase='UNKNOWN'
            self.closed=True;self._cleanup={**receipt,'budget':copy.deepcopy(self._cached)};return copy.deepcopy(self._cleanup)
        except (OSError,ValueError,KeyError,TypeError) as error:
            _remember_settlement(self,settlement_phase,error)
            if self.pool is not None:self.pool.dependent_cleanup_confirmed=False;self.pool.stop()
            try:self._error()
            except ApplicationExecutionError as failure:
                _remember_settlement(self,settlement_phase,failure)
                raise
        except BaseException:
            _remember_settlement(self,settlement_phase)
            raise
        finally:
            if diagnostic_control is not None:
                # A diagnostic must not swallow cancellation/deadline or permit
                # a later business action. Owned helper cleanup was attempted.
                self.failed=True
                raise diagnostic_control

    def preworker_failure(self,*,worker_launch_attempted,segment_id,session_id):
        """Parent-only proof of cleanup, never a worker process/settlement result."""
        if (worker_launch_attempted is not False or not self.closed or self._running or self._worker_ever_started or self._uncertain_context
                or self._preworker_binding is None or self._preworker_binding['segment_id']!=segment_id
                or self._preworker_binding['session_id']!=session_id):return None
        cleanup={key:value for key,value in self._cleanup.items() if key!='budget'}
        if not _known_clean_helper(cleanup,self.runroot):return None
        if credentials.Redactor(self.redaction_values()).contains(c.canonical(cleanup)):return None
        launch=self._helper_launch_attempted if self.helper is None else True
        if type(launch) is not bool:return None
        proof={'schema':1,'binding':copy.deepcopy(self._preworker_binding),'worker_launch_attempted':False,
            'helper_launch_attempted':launch,'writers_absent':True,'physical_cleanup_confirmed':True,
            'private_cleanup_confirmed':True,'accounting':'unavailable','completion_eligible':False}
        return {'schema':1,'document_type':'application_preworker_failure','started':False,'worker_launch_attempted':False,
            'exit_code':None,'termination_reason':'application_startup_failed','cleanup_confirmed':True,
            'application_preworker_cleanup':proof,'application_helper_cleanup':cleanup,
            'application_helper_startup':copy.deepcopy(self._startup_failure),
            'native_tool_budget_error':'accounting_unavailable'}


_APPLICATION_COORDINATOR_TYPE=ApplicationCoordinator


def prepare(lab,args,image,runroot,workspace,desc,task,profile,redaction_values):
    if getattr(args,'_application_execution',None) is None:
        if 'application_execution' in task:raise ApplicationExecutionError()
        return None
    return ApplicationCoordinator(lab,args,image,runroot,workspace,desc,task,profile,redaction_values)
