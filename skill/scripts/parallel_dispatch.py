"""Private inherited host channel for process-isolated trial controllers.

No socket, host lease descriptor or grant is passed to a Pi container.
"""
import contextlib
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import time

import ownership_registry
from parallel_contract import ParallelError

MAX_FRAME=512*1024


class Channel:
    def __init__(self,sock):self.sock=sock;self.pending=b''
    def send(self,value):
        body=json.dumps(value,separators=(',',':')).encode()+b'\n'
        if len(body)>MAX_FRAME:raise ParallelError('Private admission frame exceeds bound')
        self.sock.sendall(body)
    def receive(self,timeout=15):
        deadline=time.monotonic()+timeout
        while b'\n' not in self.pending:
            if len(self.pending)>MAX_FRAME:raise ParallelError('Private admission frame exceeds bound')
            remaining=deadline-time.monotonic()
            if remaining<=0 or not select.select([self.sock],[],[],remaining)[0]:raise ParallelError('Private admission channel deadline exceeded')
            data=self.sock.recv(65536)
            if not data:raise EOFError('Owning admission controller is gone')
            self.pending+=data
        body,self.pending=self.pending.split(b'\n',1)
        if len(body)>MAX_FRAME:raise ParallelError('Private admission frame exceeds bound')
        value=json.loads(body)
        if not isinstance(value,dict):raise ParallelError('Invalid private admission frame')
        return value
    def ready(self):return b'\n' in self.pending or bool(select.select([self.sock],[],[],0)[0])


class RemoteAdmission:
    def __init__(self,channel,bootstrap,command):
        self.channel=channel;self.bootstrap=bootstrap;self.command=command
        self.runroot=None;self.binding={};self.cancelled=False;self.owner_lost=False
    def call(self,operation,cleanup=False,**payload):
        try:
            self.channel.send({'op':operation,**payload})
            bounded_native = operation in ('native-budget-begin', 'native-budget-close')
            deadline = time.monotonic()+60 if bounded_native else None
            reply=self.channel.receive(max(0,deadline-time.monotonic())) if bounded_native else self.channel.receive()
            while reply.get('op')=='cancel':
                self.cancelled=True
                if not cleanup:raise KeyboardInterrupt
                reply=self.channel.receive(max(0,deadline-time.monotonic())) if bounded_native else self.channel.receive()
        except (EOFError,BrokenPipeError,ConnectionResetError):
            self.owner_lost=True
            if not cleanup:raise KeyboardInterrupt from None
            raise ParallelError('Owner lost during private cleanup confirmation') from None
        if reply.get('op')!='ok':
            import indexed_contract
            if reply.get('reason') in indexed_contract.REASONS:raise indexed_contract.IndexedError(reply['reason'])
            raise ParallelError('Private admission grant rejected')
        return reply
    @contextlib.contextmanager
    def admission(self,args,attempt):
        expected=self.bootstrap['intent']
        if any(attempt.record.get(k)!=expected[k] for k in ('run_id','attempt_id','trial_id')) or args.in_place:
            raise ParallelError('Private grant belongs to another attempt or mutable original')
        self.call('enter',capability=self.bootstrap['capability'])
        token=ownership_registry.CURRENT.set(self)
        try:yield self
        finally:ownership_registry.CURRENT.reset(token)
    def intent(self,argv,name,binding=None,runroot=None):
        reply=self.call('launch',argv=argv,name=name,binding=binding or {})
        return reply['record'],reply['argv']
    def confirm_absent(self,record):
        try:return self.call('absent',cleanup=True,launch_id=record['launch_id'])['confirmed']
        except ParallelError:
            # Still under inherited host lease custody. Independent absence is
            # useful to this partial result; the next owner rechecks the registry.
            return ownership_registry.absent(self.command(['docker','container','inspect',record['container']]))
    def check_cancel(self):
        if self.cancelled or self.owner_lost:raise KeyboardInterrupt
        if self.channel.ready():
            try:message=self.channel.receive(.1)
            except EOFError:self.owner_lost=True;raise KeyboardInterrupt from None
            if message.get('op')!='cancel':raise ParallelError('Unexpected admission channel message')
            self.cancelled=True;raise KeyboardInterrupt
    def bind_daemon(self,value):self.call('daemon',value=value)
    def endpoint(self,original):
        route=self.bootstrap.get('inference')
        if not route:raise ParallelError('Frozen inference gateway has not been admitted')
        return {**original,'base_url':route['base_url'],'host_base_url':route['host_base_url'],'api_key_env':'PI_PARALLEL_INFERENCE'}
    def native_budget_begin(self,stage_name,binding):
        reply=self.call('native-budget-begin',stage_name=stage_name,binding=binding)
        return {key:reply[key] for key in ('context','network','binding','budget')}
    def native_budget_status(self,stage_id):
        return self.call('native-budget-status',stage_id=stage_id)['budget']
    def native_budget_checkpoint(self,stage_id):
        return self.call('native-budget-checkpoint',stage_id=stage_id)['budget']
    def native_budget_extend(self,stage_id,command_id,max_tool_calls,remaining_seconds):
        return self.call('native-budget-extend',stage_id=stage_id,command_id=command_id,
            max_tool_calls=max_tool_calls,remaining_seconds=remaining_seconds)['budget']
    def native_budget_continue(self,stage_id,command_id,segment_id):
        reply=self.call('native-budget-continue',stage_id=stage_id,command_id=command_id,segment_id=segment_id)
        return {key:reply[key] for key in ('context','network','binding','budget')}
    def native_budget_close(self,stage_id):
        reply=self.call('native-budget-close',cleanup=True,stage_id=stage_id)
        result={key:reply[key] for key in ('budget','cleanup')}
        if 'completion_context' in reply:result['completion_context']=reply['completion_context']
        return result


def worker_environment(bootstrap):
    names=set(bootstrap.get('secret_variable_names',[]))
    env={k:v for k,v in os.environ.items() if k not in names and not k.startswith('PI_APP_') and not k.endswith(('API_KEY','ACCESS_TOKEN','AUTH_TOKEN','PASSWORD','SECRET'))}
    env['PYTHONDONTWRITEBYTECODE']='1'
    return env


def launch_worker(bootstrap,logfile,lease_fd):
    parent,child=socket.socketpair()
    channel=Channel(parent);env=worker_environment(bootstrap)
    try:
        process=subprocess.Popen([sys.executable,str(Path(__file__).with_name('parallel_worker.py')),str(child.fileno()),str(lease_fd)],
                                 pass_fds=(child.fileno(),lease_fd),env=env,stdout=logfile,stderr=logfile)
        channel.send({'op':'bootstrap',**bootstrap})
    except BaseException:
        parent.close();raise
    finally:child.close()
    return process,channel


class Peer:
    """Parent-issued fixed trial reservation with at most one physical writer."""
    def __init__(self,bootstrap,registry,allocator,reservation,metadata,runroot):
        self.bootstrap=bootstrap;self.registry=registry;self.allocator=allocator;self.reservation=reservation
        self.metadata=metadata;self.runroot=Path(runroot).resolve();self.entered=False;self.active=None;self.records=[]
        cohort=getattr(registry,'_native_budget_cohort',None)
        self.native_budget=cohort.bind(self) if cohort is not None else None
    def handle(self,message):
        operation=message.get('op')
        if operation=='enter':
            if self.entered:raise ParallelError('Private trial grant already consumed')
            self.allocator.consume(self.reservation.identity,message.get('capability',''),self.reservation.binding,self.reservation.resources)
            self.entered=True;return {'op':'ok'}
        if not self.entered:raise ParallelError('Trial has no consumed admission grant')
        if isinstance(operation,str) and operation.startswith('native-budget-'):
            if self.native_budget is None:raise ParallelError('No frozen native helper grant')
            actions={
                'native-budget-begin':({'op','stage_name','binding'},lambda:self.native_budget.begin(message['stage_name'],message['binding'])),
                'native-budget-status':({'op','stage_id'},lambda:{'budget':self.native_budget.status(message['stage_id'])}),
                'native-budget-checkpoint':({'op','stage_id'},lambda:{'budget':self.native_budget.checkpoint(message['stage_id'])}),
                'native-budget-extend':({'op','stage_id','command_id','max_tool_calls','remaining_seconds'},lambda:{'budget':self.native_budget.extend(message['stage_id'],message['command_id'],message['max_tool_calls'],message['remaining_seconds'])}),
                'native-budget-continue':({'op','stage_id','command_id','segment_id'},lambda:self.native_budget.continuation(message['stage_id'],message['command_id'],message['segment_id'])),
                'native-budget-close':({'op','stage_id'},lambda:self.native_budget.close(message['stage_id'])),
            }
            if operation not in actions or set(message)!=actions[operation][0]:raise ParallelError('Unsupported native helper operation')
            return {'op':'ok',**actions[operation][1]()}
        if operation=='indexed-stage':
            if not hasattr(self,'indexed_stage') or set(message) not in ({'op','name'},{'op','name','renew'}):raise ParallelError('No indexed stage grant')
            return {'op':'ok',**self.indexed_stage(message['name'],message.get('renew',False))}
        if operation=='indexed-release':
            if not hasattr(self,'indexed_release') or set(message)!={'op'}:raise ParallelError('No indexed release grant')
            self.indexed_release();return {'op':'ok'}
        if operation=='daemon':
            if message.get('value')!=self.registry.daemon:raise ParallelError('Worker daemon differs from frozen grant')
            return {'op':'ok'}
        if operation=='launch':
            if self.allocator.closed or self.active is not None:raise ParallelError('Dispatch stopped or worker already owns a live container')
            argv=message.get('argv');self.validate_launch(argv)
            supplied=message.get('binding',{})
            if not isinstance(supplied,dict) or set(supplied)-{'stage_id','segment_id'}:raise ParallelError('Launch cannot enlarge its frozen identity binding')
            if self.native_budget is not None:self.native_budget.validate_agent_launch(argv,supplied)
            binding={**self.reservation.binding,**supplied}
            record,argv=self.registry.intent(argv,message['name'],binding,self.runroot)
            self.active=record;self.records.append(record)
            if self.reservation.state=='launching':self.allocator.running(self.reservation.identity)
            return {'op':'ok','record':record,'argv':argv}
        if operation=='absent':
            if self.active is None or message.get('launch_id')!=self.active['launch_id']:
                raise ParallelError('Cleanup does not match the active launch')
            confirmed=self.registry.confirm_absent(self.active)
            if confirmed:self.active=None
            else:self.allocator.release(self.reservation.identity,False,False)
            return {'op':'ok','confirmed':confirmed}
        raise ParallelError('Unknown private admission operation')

    def finalize_native_budget(self,stop_worker=False):
        cohort=getattr(self.registry,'_native_budget_cohort',None)
        if stop_worker and self.active is not None and (self.native_budget is not None or cohort is not None):
            from parallel_native_budget import stop_owned_worker
            stop_owned_worker(self)
        if self.native_budget is None:return True
        return self.native_budget.finalize()

    def validate_launch(self,argv):
        import resources
        if not isinstance(argv,list) or any(not isinstance(x,str) for x in argv) or argv[:2]!=['docker','run']:
            raise ParallelError('Invalid private launch argv')
        def option(name):
            if argv.count(name)!=1:raise ParallelError('Missing or duplicate frozen launch option')
            return argv[argv.index(name)+1]
        resource=self.reservation.resources
        if (option('--platform')!=self.metadata['execution']['platform'] or float(option('--cpus'))*1000!=resource['cpu_millis']
            or resources.memory_bytes(option('--memory'))!=resource['memory_mib']*1024**2
            or option('--memory-swap')!=option('--memory') or int(option('--pids-limit'))!=resource['pids_limit']
            or option('--network') not in ('none',self.bootstrap['network'])
            or '--read-only' not in argv or '--cap-drop=ALL' not in argv or '--security-opt=no-new-privileges=true' not in argv
            or '--ipc=none' not in argv or option('--user')!=str(os.getuid())+':'+str(os.getgid()) or os.getuid()==0):
            raise ParallelError('Launch exceeds or relaxes the frozen grant')
        allowed={'--name','--init','--platform','--read-only','--user','--cap-drop=ALL','--security-opt=no-new-privileges=true',
                 '--ipc=none','--security-opt','--pids-limit','--memory','--memory-swap','--cpus','--network','--workdir=/workspace','--entrypoint=python3',
                 '--mount','--env','--add-host','--label=org.pi-agent-test-env.managed=1','--label=org.pi-agentic-development.managed=1'}
        helper=argv.index('/opt/pi-lab/worker.py')
        if '--security-opt' in argv:
            import browser_security
            if self.metadata['execution'].get('browser_sandbox_policy')!='chromium-userns' or argv.count('--security-opt')!=1:
                raise ParallelError('Unselected browser policy in private launch')
            value=option('--security-opt');path=self.runroot/'browser-security/seccomp.json'
            if value!='seccomp='+str(path) or browser_security.verify(path)!=path:
                raise ParallelError('Browser policy differs from the pinned trial receipt')
        for value in argv[2:helper-1]:
            if value.startswith('--') and value not in allowed:
                if not value.startswith('--security-opt=seccomp=') or self.metadata['execution'].get('browser_sandbox_policy')!='chromium-userns':
                    raise ParallelError('Unsupported Docker option in private grant')
        if argv[helper-1]!=self.metadata['execution']['image']:raise ParallelError('Launch image changed')
        for index,value in enumerate(argv[:helper]):
            if value=='--mount':
                parts=argv[index+1].split(',');options=dict(p.split('=',1) for p in parts if '=' in p)
                path=Path(options.get('src','')).resolve()
                if options.get('type')!='bind' or options.get('bind-recursive')!='disabled':
                    raise ParallelError('Unsupported private mount policy')
                if 'readonly' not in parts and options.get('dst') not in ('/workspace','/pi-state','/opt/pi-control/outbox'):
                    raise ParallelError('Grant does not permit writable parent mounts')
                if self.runroot not in path.parents and path!=self.runroot:
                    # Only the frozen nonsecret agent profile may be shared RO.
                    profile=Path(self.bootstrap['experiment'])/'inputs/profiles'
                    if 'readonly' not in parts or profile.resolve() not in path.parents:
                        raise ParallelError('Launch mount escapes its private trial')
            if value=='--env' and argv[index+1].startswith('PI_APP_') and '=' in argv[index+1]:
                raise ParallelError('Application values must not enter Docker argv')


def private_credentials(plan,assigned):
    expected={task['name']:set(task['application_secrets']) for task in plan['agents'] if task.get('application_secrets')}
    if not isinstance(assigned,dict) or set(assigned)!=set(expected):raise ParallelError('Private credential stages do not match the frozen plan')
    for stage,names in expected.items():
        if not isinstance(assigned[stage],dict) or set(assigned[stage])!=names or any(not isinstance(v,str) or len(v)<16 for v in assigned[stage].values()):
            raise ParallelError('Private credential variables do not match the frozen assignment')
    return {stage:dict(values) for stage,values in assigned.items()}
