"""ENV-ADMISSION-002 analysis: synthetic Docker, real disposable lease/filesystem.

Never reads or mutates the operator's registry, credentials, endpoint, or Docker.
The original downstream failure is NOT replayed. No diagnostic digest is guessed.
"""
import argparse
import collections
import contextlib
import copy
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from unittest import mock

REPO = Path('/Users/bramen/Projects/pi-agentic-development')
sys.path[:0] = [str(REPO/'skill/scripts'), str(REPO/'tests')]
import ownership_registry as reg
import resources
import application_credentials as credentials
import pi_lab as lab
import stage_control as controls
from test_results import fixture, mocked_suite

OUT = Path(__file__).resolve().parent
IMAGE = 'sha256:' + 'a'*64
DAEMON = 'synthetic-daemon'
original_init = reg.Registry.__init__
results = []

class DockerFixture:
    def __init__(self): self.calls = []; self.fault = None
    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        if argv == ['docker', 'info', '--format', '{{.ID}}']:
            return argparse.Namespace(returncode=0, stdout=(DAEMON if self.fault != 'daemon' else 'changed-daemon'), stderr='')
        if argv[:3] == ['docker', 'container', 'inspect']:
            error = 'Cannot contact synthetic daemon' if self.fault == 'inspection' else 'Error response from daemon: No such container: ' + argv[-1]
            return argparse.Namespace(returncode=1, stdout='[]\n', stderr=error+'\n')
        raise AssertionError('Unexpected synthetic Docker command: '+str(argv))

@contextlib.contextmanager
def mocked_external(docker):
    def init(self, path, command=None, recover_sensitive=None):
        original_init(self, path, command=docker, recover_sensitive=recover_sensitive)
    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.object(reg.Registry, '__init__', init))
        for target in ('subprocess.run', 'subprocess.Popen', 'socket.socket', 'os.system', 'os.kill'):
            stack.enter_context(mock.patch(target, side_effect=AssertionError('External effect forbidden')))
        yield

def counts(owner): return dict(collections.Counter(row['status'] for row in owner.load()))
def owned(owner, run, name):
    argv=['docker','run','--name',name,'--mount',f'type=bind,src={run}/workspace,dst=/workspace', IMAGE, '/opt/pi-lab/worker.py', 'preflight']
    row, unused=owner.intent(argv,name,runroot=run)
    assert owner.confirm_absent(row)
    return row

def leave_pending(lease, run):
    run.mkdir(parents=True,exist_ok=True)
    try:
        with resources.admission_lock(lease) as owner:
            owner.bind_daemon(DAEMON)
            for i in range(3):owned(owner,run,'pi-synthetic-'+str(i))
            raise lab.LabError('Synthetic predecessor preflight failure')
    except lab.LabError:pass
    return owner

def diagnostic(exc):
    stream=io.StringIO()
    with contextlib.redirect_stderr(stream):assert lab.cli_failure(exc)==2
    return json.loads(stream.getvalue())

def check(name, call):
    started=time.monotonic()
    value=call()
    results.append({'case':name,'status':'passed','elapsed_seconds':round(time.monotonic()-started,3),**value})
    print(name+': passed',flush=True)

def lifecycle():
    with tempfile.TemporaryDirectory(prefix='env-admission-lifecycle-') as temp:
        root=Path(temp).resolve();docker=DockerFixture()
        with mocked_external(docker),contextlib.ExitStack() as stack:
            args=fixture(root);mocked_suite(stack)
            stack.enter_context(mock.patch.object(lab,'command',side_effect=docker))
            def host(args):reg.CURRENT.get().bind_daemon(DAEMON);return {'synthetic':True}
            def probe(args,image):
                owner=reg.CURRENT.get();owned(owner,owner.runroot,'pi-synthetic-probe')
                return {'id':IMAGE,'reference':IMAGE,'capabilities':{'pi':'0.87.1'}}
            def stream(argv,logdir,timeout,name,secret='',**kwargs):
                owner=reg.CURRENT.get();row,labelled=owner.intent(argv,name)
                assert owner.confirm_absent(row)
                logdir.mkdir(parents=True,exist_ok=True)
                failed=argv[-1]=='preflight'
                value={'exit_code':2 if failed else 0,'started':True,'cleanup_confirmed':True,'ownership_launch_id':row['launch_id'],'termination_reason':'process_error' if failed else 'completed'}
                (logdir/'stdout.jsonl').write_text('')
                (logdir/'stderr.log').write_text('PI_LAB_ERROR: Cannot reach API from the Pi container: [Errno 111] Connection refused\n' if failed else '')
                controls.atomic(logdir/'process.json',value)
                return value
            stack.enter_context(mock.patch.object(lab,'require_host',side_effect=host))
            stack.enter_context(mock.patch.object(lab,'probe_image',side_effect=probe))
            stack.enter_context(mock.patch.object(lab,'stream_run',side_effect=stream))
            assert lab.run_suite(args)==2
            run=(root/'results/latest').resolve();result=run/'result.json';before=result.read_bytes()
            sealed=json.loads(before)
            assert sealed['status']=='BLOCKED' and sealed['invocation']=={'status':'not_started','attempted_stages':0} and not sealed['agents']
            observer=reg.Registry(Path(args.lock_file+'.registry'))
            assert counts(observer)=={'absent':3}
            with resources.admission_lock(args.lock_file) as owner:assert counts(owner)=={'released':3}
            assert result.read_bytes()==before
            return {'before_recovery':{'absent':3},'after_recovery':counts(owner),'original_result_unchanged':True,'predecessor_status':sealed['status'],'invocation':sealed['invocation'],'native_docker_calls':0}

def history_guard():
    with tempfile.TemporaryDirectory(prefix='env-admission-history-') as temp:
        root=Path(temp).resolve();docker=DockerFixture();lease=root/'lease';old=root/'old-proof-unavailable'
        with mocked_external(docker):
            with resources.admission_lock(lease) as owner:
                row=owned(owner,old,'pi-synthetic-historical')
                row.update(application_helper=True,client_mode='application-execution',container_id='b'*64)
                owner.write(row);owner.release(row,True)
            with resources.admission_lock(lease):pass
            owner=leave_pending(lease,root/'run');docker.calls.clear()
            try:
                with resources.admission_lock(lease):raise AssertionError('Should block')
            except resources.AdmissionError as exc:
                assert str(exc)=='Application contexts or credential cleanup remain pending; generic recovery is prohibited'
                public=diagnostic(exc)
            assert not docker.calls
            assert counts(owner)=={'released':1,'absent':3}
            return {'only_released_admitted':True,'mixed_history_denied':True,'synthetic_underlying_condition':'older generic application helper lacks required retained cleanup proof','public':public,'docker_observations_before_denial':0,'counts':counts(owner)}

def failure(fault):
    with tempfile.TemporaryDirectory(prefix='env-admission-fault-') as temp:
        root=Path(temp).resolve();docker=DockerFixture();lease=root/'lease';run=root/'run'
        with mocked_external(docker):
            owner=leave_pending(lease,run)
            with contextlib.ExitStack() as stack:
                if fault in ('daemon','inspection'):docker.fault=fault
                elif fault in ('valid_sensitive_cleanup','invalid_sensitive_cleanup'):
                    sid=str(uuid.uuid4());stage=run/'stages'/sid;stage.mkdir(parents=True)
                    controls.atomic(stage/'application-credentials.json',{'schema':1,'status':'pending'})
                    controls.atomic(stage/'descriptor.json',{'stage_id':sid if fault=='valid_sensitive_cleanup' else str(uuid.uuid4())})
                    (run/'workspace').mkdir();(run/'workspace/file.txt').write_text('synthetic sensitive workspace')
                elif fault=='atomic_open':
                    real=os.open
                    def failing(path,*args,**kwargs):
                        if Path(path).parent==owner.root and Path(path).name.startswith('.'):raise PermissionError(errno.EACCES,'synthetic access denial')
                        return real(path,*args,**kwargs)
                    stack.enter_context(mock.patch.object(os,'open',side_effect=failing))
                elif fault=='atomic_replace':
                    real=os.replace
                    def failing(src,dst,*args,**kwargs):
                        if Path(dst).parent==owner.root:raise OSError(errno.EROFS,'synthetic read-only destination')
                        return real(src,dst,*args,**kwargs)
                    stack.enter_context(mock.patch.object(os,'replace',side_effect=failing))
                elif fault in ('file_fsync','directory_fsync'):
                    real=os.fsync
                    def failing(fd):
                        directory=stat.S_ISDIR(os.fstat(fd).st_mode)
                        if directory==(fault=='directory_fsync'):raise OSError(errno.EIO,'synthetic fsync failure')
                        return real(fd)
                    stack.enter_context(mock.patch.object(os,'fsync',side_effect=failing))
                elif fault=='release_write':
                    real=reg.Registry.write
                    def failing(self,row):
                        if row['status']=='released':raise OSError(errno.ENOSPC,'synthetic release-write failure')
                        return real(self,row)
                    stack.enter_context(mock.patch.object(reg.Registry,'write',failing))
                entered=False;public=None
                try:
                    with resources.admission_lock(lease):entered=True
                except resources.AdmissionError as exc:public=diagnostic(exc)
                if fault=='valid_sensitive_cleanup':
                    assert entered and counts(owner)=={'released':3}
                    assert controls.read(stage/'application-credentials.json')['status']=='removed'
                    assert not (run/'workspace').exists()
                else:
                    assert not entered and public['infrastructure']['reason']=='host-registry-unsafe'
                    assert counts(owner)=={'absent':3}
                    assert not list(owner.root.glob('.*'))
                return {'entered_body':entered,'counts':counts(owner),'public':public,'injected_fault':fault}

def large_history(total):
    with tempfile.TemporaryDirectory(prefix='env-admission-scale-') as temp:
        root=Path(temp).resolve();docker=DockerFixture();lease=root/'lease'
        with mocked_external(docker):
            owner=leave_pending(lease,root/'run')
            # Fixture materialization only: no live records or native ownership claims.
            with lease.open('a+') as handle:
                resources.fcntl.flock(handle.fileno(),resources.fcntl.LOCK_EX)
                prototype=owner.load()[0];retained={}
                for i in range(total-3):
                    row={**prototype,'launch_id':str(uuid.uuid4()),'container':'pi-synthetic-history-'+str(i),'status':'released','runroot':None}
                    path=owner.root/(row['launch_id']+'.json')
                    controls.atomic(path,row);retained[path.name]=hashlib.sha256(path.read_bytes()).hexdigest()
                fd=os.open(owner.root,os.O_RDONLY|os.O_DIRECTORY)
                try:os.fsync(fd)
                finally:os.close(fd)
                resources.fcntl.flock(handle.fileno(),resources.fcntl.LOCK_UN)
            docker.calls.clear();capacity_denied=False
            with resources.admission_lock(lease) as recovered:
                assert counts(recovered)=={'released':total}
                for name,digest in retained.items():assert hashlib.sha256((recovered.root/name).read_bytes()).hexdigest()==digest
                if total==reg.MAX_RECORDS:
                    try:recovered.network_intent('pi-synthetic-over-capacity')
                    except reg.RegistryCapacityError:capacity_denied=True
                    assert capacity_denied
            return {'total':total,'counts':counts(recovered),'unrelated_records_byte_preserved':len(retained),'synthetic_docker_observations':len(docker.calls),'new_intent_at_capacity_denied':capacity_denied}

if __name__=='__main__':
    check('failed_run_preflight_then_safe_next_admission',lifecycle)
    check('released_generic_helper_cross_history_guard',history_guard)
    for name in ('daemon','inspection','atomic_open','atomic_replace','file_fsync','directory_fsync','release_write','invalid_sensitive_cleanup','valid_sensitive_cleanup'):
        check(name,lambda name=name:failure(name))
    for count in (6777,8192):check('mixed_history_'+str(count),lambda count=count:large_history(count))
    report={'scope':'Synthetic Docker observations; real temporary files, exclusive flock, atomic replacement and fsync. No live registry, Docker, endpoints, credentials, or participants. Not a reproduction of the original failure.','python':sys.version,'platform':platform.platform(),'machine':platform.machine(),'cases':results}
    (OUT/'results.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'cases_passed':len(results),'results':str(OUT/'results.json')}))
