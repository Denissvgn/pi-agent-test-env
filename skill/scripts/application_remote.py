"""Credential-free child adapter to a parent-owned application coordinator.

The parent owns effects, budget/control authority, context creation and purge.
This adapter verifies shared frozen bytes and scopes; it never launches helpers,
reads credential stores, creates control intents or repairs/continues a report.
"""
import copy
import hashlib
import math
import os
from pathlib import Path
import re
import stat
import time

import agent_profiles
import application_contracts as c
import application_credentials as credentials
from application_client import _binding
from application_client_service import validate_scope
from application_evidence import open_directory
from application_execution import ApplicationExecutionError,extension_order_sha256,_same_policy
import application_runtime_contracts as runtime_contracts
from native_budget_execution import Coordinator as NativeCoordinator
import ownership_registry
from parallel_dispatch import RemoteAdmission
import resources
import stage_control as controls


def _owned_json(path,*,context=False):
    path=Path(path).absolute();parent=open_directory(str(path.parent),private=context)
    try:
        identity=os.fstat(parent);fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno());maximum=65536 if context else 4*1024*1024
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=os.getuid()
                    or stat.S_IMODE(before.st_mode)&0o077 or context and stat.S_IMODE(before.st_mode)!=0o400
                    or before.st_size>maximum):raise ApplicationExecutionError()
            body=stream.read(maximum+1);after=os.fstat(stream.fileno())
            if len(body)>maximum or any(getattr(before,k)!=getattr(after,k) for k in
                    ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode','st_nlink')):raise ApplicationExecutionError()
            return c.loads(body,max_bytes=maximum),(identity.st_dev,identity.st_ino)
    finally:os.close(parent)


class RemoteApplicationCoordinator(NativeCoordinator):
    def __repr__(self):return '<RemoteApplicationCoordinator parent authority withheld>'

    def __init__(self,lab,args,image,runroot,workspace,desc,task,profile,redaction_values):
        self.failed=False;self.closed=False;self.binding=None
        try:
            self.lab,self.args,self.image=lab,args,image
            self.runroot,self.workspace=Path(runroot).absolute(),Path(workspace).absolute()
            self.desc,self.task,self.profile=copy.deepcopy(desc),copy.deepcopy(task),copy.deepcopy(profile)
            self.remote=getattr(args,'_parallel_session',None)
            if type(self.remote) is not RemoteAdmission or ownership_registry.CURRENT.get() is not self.remote:raise ApplicationExecutionError()
            self._channel_alive()
            bootstrap=self.remote.bootstrap;marker=bootstrap.get('application');spec=getattr(args,'_application_execution',None)
            if (type(marker) is not dict or set(marker)!={'schema','plan_sha256','participant_keys_withheld'}
                    or type(marker['schema']) is not int or marker['schema']!=1 or marker['participant_keys_withheld'] is not True
                    or bootstrap.get('credentials',{})!={} or any(key in bootstrap for key in
                        ('application_values','application_key','control_token','authority','store'))):raise ApplicationExecutionError()
            if (type(spec) is not dict or not {'plan','stage_id','authority'}<=set(spec)
                    or set(spec)-{'plan','stage_id','authority','redaction_sink'} or spec['authority'] is not None):raise ApplicationExecutionError()
            self.plan=c.validate_ir(spec['plan']);self.plan_sha256=self.plan['plan_sha256']
            if marker['plan_sha256']!=self.plan_sha256:raise ApplicationExecutionError()
            self.stage=next((s for s in self.plan['stages'] if s['id']==spec['stage_id']),None)
            if self.stage is None:raise ApplicationExecutionError()
            self.release=self.plan['runtime']['pi_release'];runtime=self.plan['runtime']['resources']['runtime']
            if (getattr(args,'in_place',False) or args.platform!='linux/arm64' or getattr(args,'native_platform',None)!='linux/arm64'
                    or image!=self.plan['runtime']['image_id'] or args.profile!=self.plan['runtime']['container_profile']
                    or getattr(args,'observed_pi_version',None)!=self.release
                    or args.browser_sandbox_policy!=(self.plan['runtime']['browser_sandbox_policy'] or 'docker-default')
                    or not _same_policy(args.resource_report['effective'],self.plan['runtime']['resources'])
                    or type(args.cpus) not in (int,float) or args.cpus!=runtime['cpus']
                    or resources.memory_bytes(args.memory)!=resources.memory_bytes(runtime['memory'])
                    or type(args.pids_limit) is not int or args.pids_limit!=runtime['pids_limit']
                    or type(args.jobs) is not int or args.jobs!=runtime['jobs']):raise ApplicationExecutionError()
            intent=bootstrap['intent'];self.trial_id=intent['trial_id']
            if (not controls.valid_id(self.trial_id) or self.runroot!=Path(bootstrap['experiment']).absolute()/'runs'/intent['run_id']
                    or self.workspace!=self.runroot/'workspace' or self.workspace.is_symlink() or not self.workspace.is_dir()
                    or any(desc.get(k)!=intent[k] for k in ('run_id','attempt_id'))
                    or desc.get('kind')!='agent' or desc.get('workspace')!=str(self.workspace)
                    or not controls.valid_id(desc.get('stage_id'))
                    or Path(desc.get('control','')).absolute()!=self.runroot/'controls'/desc['stage_id']):raise ApplicationExecutionError()
            if (_owned_json(self.runroot/'plan.json')[0]!=self.plan
                    or _owned_json(self.runroot/'stages'/desc['stage_id']/'descriptor.json')[0]!=desc
                    or any(_owned_json(self.runroot/'identity.json')[0].get(k)!=intent[k] for k in ('run_id','attempt_id'))):raise ApplicationExecutionError()
            receipt=getattr(args,'frozen_agent_profile',None)
            if receipt is None or agent_profiles.staged(receipt)!=profile:raise ApplicationExecutionError()
            self.extension_sha256=extension_order_sha256(self.stage,profile,runtime_root=self.runroot/'trusted-runtime')
            expected={'schema':1,'plan_sha256':self.plan_sha256,'stage_id':self.stage['id'],
                'effective_prompt_sha256':hashlib.sha256(self.stage['effective_prompt'].encode()).hexdigest(),
                'tool_schema_sha256':c.digest(sorted(self.stage['tool_schemas'],key=lambda row:row['name'])),
                'profile_binding':self.stage['profile_binding'],'extension_order_sha256':self.extension_sha256}
            fields={'name','prompt','tools','tool_schemas','require_tools','cwd','access','application_execution',*self.stage['limits']}
            if (set(task)!=fields or task['application_execution']!=expected or task['name']!=self.stage['id']
                    or task['prompt']!=self.stage['effective_prompt'] or task['tools']!=self.stage['tools']
                    or task['tool_schemas']!=self.stage['tool_schemas'] or task['require_tools']!=[] or task['cwd']!='.' or task['access']!='ro'
                    or any(type(task[k]) is not int or task[k]!=v for k,v in self.stage['limits'].items())
                    or desc.get('label')!='agent-'+str(self.plan['stages'].index(self.stage)+1)+'-'+self.stage['id']):raise ApplicationExecutionError()
            self.allowed_tools=list(self.stage['tools']);self._maximum=self.stage['limits']['max_tool_calls']
            self._sink=spec.get('redaction_sink')
            if self._sink is not None and not callable(self._sink):raise ApplicationExecutionError()
            if type(redaction_values) not in (list,tuple):raise ApplicationExecutionError()
            self._values=list(redaction_values)
            self._values.extend(value for value in (bootstrap.get('capability'),bootstrap.get('inference',{}).get('token')) if value)
            self._values.extend(bootstrap.get('indexed',{}).get('tokens',{}).values())
            self.context=None;self._cached=self._cached_at=None;self._paths=[];self._used=set();self._segments=[]
            self._commands=set();self._settled=True;self._running=False;self._remote_started=False;self._close_attempted=False;self._completion=None
            self.redaction_values()
        except (OSError,ValueError,KeyError,TypeError,AttributeError):self._error()

    def _error(self):
        self.failed=True
        raise ApplicationExecutionError() from None

    def _channel_alive(self):
        if self.remote.owner_lost or self.remote.cancelled:self._error()

    def redaction_values(self):
        try:
            values=list(dict.fromkeys(value for value in self._values if value))
            if len(values)>1024:raise ApplicationExecutionError()
            for value in values:c.text(value,'/redaction_values',16384)
            self._values=values
            if self._sink is not None:self._sink(list(values))
            return list(values)
        except Exception:self._error()

    def _caps(self,context):
        if type(context) is dict:
            for value in (context.get('capability'),context.get('budget_context',{}).get('capability') if type(context.get('budget_context')) is dict else None):
                if type(value) is str and re.fullmatch('[a-f0-9]{64}',value):self._values.append(value)
        self.redaction_values()

    def _verify_context(self,context,binding,known):
        self._caps(context)
        c.exact(context,{'schema','scope','capability','base_url','tool_schemas','budget_context'},'/context')
        scope=context['scope'];validate_scope(scope,self.plan)
        budget=context['budget_context'];c.exact(budget,{'schema','pi_release','scope','allowed_tools','prepare_arguments',
            'extension_order_sha256','tool_schema_sha256','base_url','capability'},'/budget_context')
        for value in (context['capability'],budget['capability']):c.sha256(value,'/capability')
        if (context['capability']==budget['capability'] or context['capability'] in known or budget['capability'] in known
                or type(context['schema']) is not int or context['schema']!=1 or any(scope.get(k)!=v for k,v in binding.items())
                or scope['stage_name']!=self.stage['id'] or context['base_url']!='http://pi-application:8081/tool'
                or context['tool_schemas']!=self.stage['tool_schemas']):self._error()
        expected={'schema':1,'pi_release':self.release,'scope':scope,'allowed_tools':self.allowed_tools,
            'prepare_arguments':{name:'none' for name in self.allowed_tools},'extension_order_sha256':self.extension_sha256,
            'tool_schema_sha256':c.digest(sorted(self.stage['tool_schemas'],key=lambda row:row['name'])),
            'base_url':'http://pi-application:8081/budget','capability':budget['capability']}
        if c.canonical(budget)!=c.canonical(expected):self._error()
        if self.context is not None and {k:v for k,v in scope.items() if k!='segment_id'}!={k:v for k,v in self.context['scope'].items() if k!='segment_id'}:self._error()
        return copy.deepcopy(context)

    def begin_segment(self,segment_id,session_id,control,directive=None):
        self._channel_alive()
        if self.failed or self.closed or not self._settled or not controls.valid_id(segment_id) or not controls.valid_id(session_id):self._error()
        binding={'run_id':self.desc['run_id'],'attempt_id':self.desc['attempt_id'],'trial_id':self.trial_id,
            'stage_id':self.desc['stage_id'],'segment_id':segment_id,'session_id':session_id,'plan_sha256':self.plan_sha256}
        folder=Path(self.desc['control'])/'segments'/segment_id
        if Path(control).absolute()!=folder or segment_id in self._used:self._error()
        try:
            _binding(binding,self.plan_sha256)
            if (_owned_json(self.runroot/'plan.json')[0]!=self.plan or agent_profiles.staged(self.args.frozen_agent_profile)!=self.profile
                    or extension_order_sha256(self.stage,self.profile,runtime_root=self.runroot/'trusted-runtime')!=self.extension_sha256):self._error()
            known=set(self.redaction_values())
            if self.binding is None:
                if directive is not None:self._error()
                self._remote_started=True;reply=self.remote.native_budget_begin(self.stage['id'],binding)
            else:
                if session_id!=self.binding['session_id'] or type(directive) is not dict or directive.get('kind')!='steer':self._error()
                command=directive.get('id')
                if (not controls.valid_id(command) or command in self._commands or len(c.canonical(directive))>65536
                        or any(directive.get(k)!=self.binding[k] for k in ('run_id','attempt_id','stage_id','segment_id'))
                        or credentials.Redactor(self.redaction_values()).contains(c.canonical(directive))):self._error()
                before=self.status(force=True)
                if before['accounting']!='available':self._error()
                self._commands.add(command);reply=self.remote.native_budget_continue(self.binding['stage_id'],command,segment_id)
                if reply['budget']['limits']!=before['limits'] or reply['budget']['counts']!=before['counts']:self._error()
            c.exact(reply,{'context','network','binding','budget'},'/reply')
            self._caps(reply['context'])
            c.text(reply['network'],'/network',128)
            if reply['binding']!=binding or reply['network']!=self.remote.bootstrap['network']:self._error()
            context=self._verify_context(reply['context'],binding,known)
            path=folder/'application-context.json';stored,parent=_owned_json(path,context=True)
            if c.canonical(stored)!=c.canonical(context):self._error()
            if self._snapshot(reply['budget'])['accounting']!='available':self._error()
            self.context,self.binding,self._network=context,binding,reply['network']
            self._paths.append((path,parent));self._segments.append(segment_id);self._used.add(segment_id)
            self._settled=False;self._running=False
            return {'context_path':'/opt/pi-control/segments/'+segment_id+'/application-context.json','network':self._network}
        except KeyboardInterrupt:self.failed=True;raise
        except (OSError,ValueError,KeyError,TypeError,AttributeError,EOFError):self._error()

    def mark_running(self):
        self._active();self._channel_alive()
        if self._settled or self._running:self._error()
        self._running=True

    def status(self,force=False):
        self._active();self._channel_alive()
        if type(force) is not bool:self._error()
        if not force and self._cached_at is not None and 0<=time.monotonic()-self._cached_at<5:return copy.deepcopy(self._cached)
        try:return self._snapshot(self.remote.native_budget_status(self.binding['stage_id']))
        except KeyboardInterrupt:self.failed=True;raise
        except (OSError,ValueError,KeyError,TypeError,EOFError):self._error()

    def extend(self,command_id,max_tool_calls,remaining_seconds):
        self._active();self._channel_alive()
        try:
            if (not controls.valid_id(command_id) or command_id in self._commands or type(max_tool_calls) is not int
                    or not self._maximum<=max_tool_calls<=500 or type(remaining_seconds) not in (int,float)
                    or not math.isfinite(remaining_seconds) or not 0<remaining_seconds<=3600):self._error()
            self._commands.add(command_id)
            return self._snapshot(self.remote.native_budget_extend(self.binding['stage_id'],command_id,max_tool_calls,remaining_seconds),maximum=max_tool_calls)
        except KeyboardInterrupt:self.failed=True;raise
        except (OSError,ValueError,KeyError,TypeError,EOFError):self._error()

    def after_segment(self,writers_confirmed):
        self._active();self._channel_alive()
        if writers_confirmed is not True or self._settled or not self._running:self._error()
        try:
            result=self._snapshot(self.remote.native_budget_checkpoint(self.binding['stage_id']))
            if result['accounting']!='available' or not credentials.workspace_inspected_clean(self.workspace,credentials.Redactor(self.redaction_values())):self._error()
            self._settled=True;self._running=False;return result
        except KeyboardInterrupt:self.failed=True;raise
        except (OSError,ValueError,KeyError,TypeError,EOFError):self._error()

    @property
    def completion_context(self):return copy.deepcopy(self._completion)

    def _completion_context(self,value):
        c.exact(value,{'binding','authorized_segment_ids','report_root','evidence_root','parent_receipts'},'/completion_context')
        expected={**self.binding,'profile_sha256':self.stage['profile_binding']['sha256'],
            'release_contract_sha256':runtime_contracts.identity(self.release)['sha256'],
            'report_contract_sha256':c.digest(self.stage['completion']),'pi_release':self.release}
        if value['binding']!=expected or value['authorized_segment_ids']!=self._segments:self._error()
        report,evidence=Path(value['report_root']),Path(value['evidence_root'])
        if (str(report)!=value['report_root'] or str(evidence)!=value['evidence_root'] or report.name!='outputs' or evidence.name!='raw'
                or report.parent!=evidence.parent or report.parent.name!='private'
                or report.parent.parent.parent!=self.runroot/'application-evidence'
                or not re.fullmatch('pi-application-[a-f0-9]{16}',report.parent.parent.name)):self._error()
        for path in (report.parent,report,evidence):fd=open_directory(str(path),private=True);os.close(fd)
        index=value['parent_receipts']
        if type(index) is not dict or len(index)>500:self._error()
        paths=set()
        for identifier,reference in index.items():
            c.slug(identifier,'/receipt');c.exact(reference,{'path','sha256'},'/receipt')
            c.relative(reference['path'],'/receipt/path');c.sha256(reference['sha256'],'/receipt/sha256')
            if not reference['path'].startswith('receipts/') or reference['path'] in paths:self._error()
            paths.add(reference['path'])
        if len(c.canonical(value))>256*1024 or credentials.Redactor(self.redaction_values()).contains(c.canonical(value)):self._error()
        return copy.deepcopy(value)

    def close(self,writers_confirmed):
        if self.closed:return copy.deepcopy(self._cleanup)
        if writers_confirmed is not True or self._close_attempted:self._error()
        self._close_attempted=True
        try:
            if not self._remote_started:
                self.closed=True;self._cleanup={'schema':1,'status':'removed','workspace':'clean','safe_to_continue':True};return copy.deepcopy(self._cleanup)
            reply=self.remote.native_budget_close(self.desc['stage_id'])
            c.exact(reply,{'budget','cleanup','completion_context'},'/close')
            cleanup=reply['cleanup']
            if (type(cleanup) is not dict or type(cleanup.get('schema')) is not int or cleanup.get('schema')!=1
                    or cleanup.get('status')!='removed' or cleanup.get('workspace')!='clean' or cleanup.get('safe_to_continue') is not True):self._error()
            self._snapshot(reply['budget'])
            if self.binding is None:self._error()
            context=self._completion_context(reply['completion_context'])
            for path,identity in self._paths:
                parent=open_directory(str(path.parent),private=True)
                try:
                    observed=os.fstat(parent)
                    if (observed.st_dev,observed.st_ino)!=identity:self._error()
                    try:os.stat(path.name,dir_fd=parent,follow_symlinks=False)
                    except FileNotFoundError:pass
                    else:self._error()
                finally:os.close(parent)
            if self.failed or reply['budget']['accounting']!='available':self._error()
            self._completion=context;self._cleanup=copy.deepcopy(cleanup);self._cleanup['budget']=copy.deepcopy(self._cached)
            self.closed=True;return copy.deepcopy(self._cleanup)
        except KeyboardInterrupt:self.failed=True;raise
        except (OSError,ValueError,KeyError,TypeError,AttributeError,EOFError):self._error()
