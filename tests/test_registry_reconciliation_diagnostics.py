"""Registry admission regressions: synthetic Docker, real disposable lease/filesystem.

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
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO/'skill/scripts'), str(REPO/'tests')]
import ownership_registry as reg
import resources
import application_credentials as credentials
import pi_lab as lab
import stage_control as controls
import registry_diagnostics as diagnostics
from test_results import fixture, mocked_suite

IMAGE = 'sha256:' + 'a'*64
DAEMON = 'synthetic-daemon'
original_init = reg.Registry.__init__

class DockerFixture:
    def __init__(self): self.calls = []; self.fault = None; self.daemon = DAEMON
    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        if argv == ['docker', 'info', '--format', '{{.ID}}']:
            return argparse.Namespace(returncode=0, stdout=(self.daemon if self.fault != 'daemon' else 'changed-daemon'), stderr='')
        if argv[:3] == ['docker', 'container', 'inspect']:
            error = 'Cannot contact synthetic daemon' if self.fault == 'inspection' else 'Error response from daemon: No such container: ' + argv[-1]
            return argparse.Namespace(returncode=1, stdout='[]\n', stderr=error+'\n')
        raise AssertionError('Unexpected synthetic Docker command: '+str(argv))

@contextlib.contextmanager
def mocked_external(docker):
    def init(self, path, command=None, recover_sensitive=None, **kwargs):
        original_init(self, path, command=docker, recover_sensitive=recover_sensitive, **kwargs)
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
                elif fault=='file_write':
                    stack.enter_context(mock.patch.object(json,'dump',side_effect=OSError(errno.ENOSPC,'synthetic file-write failure')))
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

class ReconciliationDiagnosticsTests(unittest.TestCase):
    def test_failed_preflight_lifecycle_preserves_original_sealed_result(self):
        value=lifecycle()
        self.assertEqual(value['before_recovery'],{'absent':3})
        self.assertEqual(value['after_recovery'],{'released':3})
        self.assertTrue(value['original_result_unchanged'])

    def test_historical_generic_helper_is_a_distinct_pre_docker_denial(self):
        value=history_guard();context=value['public']['infrastructure']['registry_diagnostic']
        self.assertEqual((context['phase'],context['condition']),('application_cleanup','application_cleanup_pending'))
        self.assertEqual(context['effects'],'none_observed')

    def test_persistence_faults_report_exact_operation_and_partial_effects(self):
        expected={
            'atomic_open':('temporary_create','permission_denied'),
            'file_write':('file_write','storage_exhausted'),
            'file_fsync':('file_fsync','io_error'),
            'atomic_replace':('atomic_replace','read_only'),
            'directory_fsync':('directory_fsync','io_error'),
        }
        for fault,(operation,error) in expected.items():
            with self.subTest(fault=fault):
                context=failure(fault)['public']['infrastructure']['registry_diagnostic']
                self.assertEqual(context,{'schema':1,'phase':'persist_absent',
                    'condition':'filesystem_operation_failed','operation':operation,
                    'os_error':error,'effects':'may_have_occurred'})

    def test_daemon_writer_and_sensitive_gates_remain_distinct(self):
        for fault,phase,condition in (
            ('daemon','daemon_observation','daemon_changed'),
            ('inspection','writer_inspection','writer_observation_failed'),
            ('release_write','persist_release','filesystem_operation_failed'),
            ('invalid_sensitive_cleanup','sensitive_recovery','sensitive_identity_mismatch')):
            with self.subTest(fault=fault):
                context=failure(fault)['public']['infrastructure']['registry_diagnostic']
                self.assertEqual((context['phase'],context['condition']),(phase,condition))
        self.assertEqual(failure('valid_sensitive_cleanup')['counts'],{'released':3})

    def test_large_mixed_history_preserves_unrelated_bytes_and_capacity(self):
        for total in (6777,reg.MAX_RECORDS):
            with self.subTest(total=total):
                value=large_history(total)
                self.assertEqual(value['unrelated_records_byte_preserved'],total-3)
                self.assertEqual(value['counts'],{'released':total})

    def test_partial_release_is_reported_and_revalidated_on_next_admission(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();docker=DockerFixture();lease=root/'lease'
            with mocked_external(docker):
                owner=leave_pending(lease,root/'run');real=reg.Registry.write;released=[]
                def fail_second(self,row):
                    if row['status']=='released':
                        released.append(row['launch_id'])
                        if len(released)==2:raise OSError(errno.ENOSPC,'private-token release failed')
                    return real(self,row)
                with mock.patch.object(reg.Registry,'write',fail_second):
                    with self.assertRaises(resources.AdmissionError) as caught:
                        with resources.admission_lock(lease):self.fail('admitted partial release')
                context=resources.admission_diagnostic(caught.exception)['registry_diagnostic']
                self.assertEqual(context['phase'],'persist_release')
                self.assertEqual(context['effects'],'may_have_occurred')
                self.assertEqual(counts(owner),{'released':1,'absent':2})
                docker.calls.clear()
                with resources.admission_lock(lease):pass
                self.assertEqual(counts(owner),{'released':3})
                self.assertEqual(len([a for a in docker.calls if a[:3]==['docker','container','inspect']]),2)

    def test_interrupted_sensitive_purge_rechecks_receipt_before_release(self):
        import shutil
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();docker=DockerFixture();lease=root/'lease';run=root/'run'
            with mocked_external(docker):
                owner=leave_pending(lease,run);sid=str(uuid.uuid4());stage=run/'stages'/sid;stage.mkdir(parents=True)
                controls.atomic(stage/'application-credentials.json',{'schema':1,'status':'pending'})
                controls.atomic(stage/'descriptor.json',{'stage_id':sid})
                workspace=run/'workspace';workspace.mkdir();(workspace/'value').write_text('synthetic sensitive data')
                real=shutil.rmtree
                def interrupted(path,*args,**kwargs):
                    real(path,*args,**kwargs)
                    if Path(path)==workspace:raise KeyboardInterrupt
                with mock.patch.object(shutil,'rmtree',side_effect=interrupted):
                    with self.assertRaises(KeyboardInterrupt):
                        with resources.admission_lock(lease):self.fail('interrupted cleanup admitted')
                self.assertEqual(controls.read(stage/'application-credentials.json')['status'],'pending')
                self.assertEqual(counts(owner),{'absent':3})
                with resources.admission_lock(lease):pass
                self.assertEqual(controls.read(stage/'application-credentials.json')['status'],'removed')
                self.assertEqual(counts(owner),{'released':3})

    def test_complete_generic_historical_helper_proof_allows_mixed_recovery(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();docker=DockerFixture();lease=root/'lease';old=root/'historical'
            with mocked_external(docker):
                with resources.admission_lock(lease) as owner:
                    row=owned(owner,old,'pi-historical-complete')
                    row.update(application_helper=True,client_mode='application-execution',container_id='b'*64)
                    owner.write(row);owner.release(row,True)
                sid=str(uuid.uuid4());stage=old/'stages'/sid;stage.mkdir(parents=True)
                receipt={'schema':1,'status':'removed','workspace':'clean'}
                controls.atomic(stage/'descriptor.json',{'stage_id':sid,'kind':'agent','label':'agent-1'})
                controls.atomic(stage/'application-credentials.json',receipt)
                controls.atomic(stage/'state.json',{'status':'finalized','cleanup_confirmed':True})
                (old/'agent-1').mkdir()
                controls.atomic(old/'agent-1/process.json',{'cleanup_confirmed':True,'application_credentials':receipt,
                    'application_helper_cleanup':{'status':'removed','workspace':'clean','safe_to_continue':True}})
                before={p:p.read_bytes() for p in old.rglob('*') if p.is_file()}
                owner=leave_pending(lease,root/'run')
                with resources.admission_lock(lease):pass
                self.assertEqual(counts(owner),{'released':4})
                self.assertTrue(all(p.read_bytes()==body for p,body in before.items()))

    def test_interruption_after_absent_commit_leaves_recoverable_state_and_free_lease(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();docker=DockerFixture();lease=root/'lease'
            with mocked_external(docker):
                owner=leave_pending(lease,root/'run');real=reg.Registry.write
                def interrupted(self,row):
                    real(self,row)
                    raise KeyboardInterrupt
                with mock.patch.object(reg.Registry,'write',interrupted):
                    with self.assertRaises(KeyboardInterrupt):
                        with resources.admission_lock(lease):self.fail('admitted interrupted owner')
                self.assertIsNone(reg.CURRENT.get())
                with resources.admission_lock(lease):pass
                self.assertEqual(counts(owner),{'released':3})

    def test_untrusted_context_and_exception_subclasses_cannot_publish_fields(self):
        canary='https://private.invalid/?key=canary-sensitive'
        plain=ValueError(canary);plain.registry_diagnostic={'phase':canary}
        plain._registry_observation=(object(),diagnostics._Snapshot(canary,canary,canary,canary,canary))
        self.assertIsNone(resources.admission_diagnostic(plain))
        class Forged(reg.RegistryError):pass
        self.assertIsNone(resources.admission_diagnostic(Forged(canary)))
        error=resources.AdmissionError('host-registry-unsafe',canary)
        error._registry_diagnostic={'phase':canary}
        self.assertNotIn('registry_diagnostic',resources.admission_diagnostic(error))
        with self.assertRaises(reg.RegistryError) as caught:
            with diagnostics.phase('writer_inspection'):
                with diagnostics.operation('container_inspect'):
                    raise subprocess.TimeoutExpired([canary],1,output=canary,stderr=canary)
        rendered=json.dumps(diagnostic(caught.exception))
        self.assertNotIn(canary,rendered)
        self.assertEqual(json.loads(rendered)['infrastructure']['registry_diagnostic']['condition'],'command_timeout')

    def test_capacity_condition_survives_translation_into_a_phase(self):
        error=reg.RegistryCapacityError('private capacity detail')
        with self.assertRaises(reg.RegistryCapacityError) as caught:
            with diagnostics.phase('inventory'):raise error
        context=resources.admission_diagnostic(caught.exception)['registry_diagnostic']
        self.assertEqual((context['phase'],context['condition']),('inventory','capacity_exceeded'))

    def test_cli_failure_before_output_directory_and_sealed_outcome_share_context(self):
        import outcomes
        for release in ('0.87.1','1.2.0'):
            with self.subTest(release=release),tempfile.TemporaryDirectory() as temp:
                root=Path(temp).resolve();docker=DockerFixture();lease=root/'lease'
                with mocked_external(docker):
                    owner=leave_pending(lease,root/'run');docker.fault='daemon'
                    argv=['preflight','--endpoint',str(root/'must-not-read.json'),'--lock-file',str(lease),
                          '--results-dir',str(root/'preflight-output'),'--platform','linux/arm64']
                    with self.assertRaises(resources.AdmissionError) as caught:lab.main(argv)
                    public=diagnostic(caught.exception)
                    self.assertFalse((root/'preflight-output').exists())
                    args=fixture(root);args.observed_pi_version=release
                    output=io.StringIO()
                    with mock.patch.object(lab,'_execute_suite') as dispatch,contextlib.redirect_stdout(output):
                        self.assertEqual(lab.run_suite(args),2)
                    dispatch.assert_not_called();sealed=json.loads(output.getvalue())
                    self.assertEqual(sealed['infrastructure']['registry_diagnostic'],public['infrastructure']['registry_diagnostic'])
                    self.assertEqual(sealed['invocation'],{'status':'not_started','attempted_stages':0})
                    self.assertEqual(sealed['infrastructure']['phase'],'admission')

    def test_constructor_inventory_and_close_failures_keep_safe_phase(self):
        for fault,phase in (('constructor','registry_initialization'),('inventory','inventory'),('close','terminal_close')):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as temp:
                lease=Path(temp).resolve()/'lease';docker=DockerFixture()
                with mocked_external(docker),contextlib.ExitStack() as stack:
                    if fault=='constructor':
                        stack.enter_context(mock.patch.object(reg,'private_directory',side_effect=PermissionError(errno.EACCES,'sensitive path')))
                    elif fault=='inventory':
                        folder=Path(str(lease)+'.registry');folder.mkdir(mode=0o700);(folder/'unknown').write_text('private')
                    else:stack.enter_context(mock.patch.object(reg.Registry,'close',side_effect=controls.ControlError('private control')))
                    with self.assertRaises(resources.AdmissionError) as caught:
                        with resources.admission_lock(lease):pass
                    value=diagnostic(caught.exception)
                    self.assertEqual(value['infrastructure']['registry_diagnostic']['phase'],phase)
                    self.assertNotIn('sensitive path',json.dumps(value))
                    self.assertNotIn('private control',json.dumps(value))


class HistoricalDiagnosticTests(unittest.TestCase):
    def setUp(self):
        import test_ownership_registry
        self.docker=DockerFixture();external=mocked_external(self.docker);external.__enter__()
        self.addCleanup(external.__exit__,None,None,None)
        patcher=mock.patch.object(os,'kill',side_effect=ProcessLookupError)
        self.pid=patcher.start();self.addCleanup(patcher.stop)
        self.owner=test_ownership_registry.QualificationPreworkerTests()
        self.owner.setUp();self.addCleanup(self.owner.doCleanups);self.owner.write()
        self.registry=self.owner.registry;self.docker.daemon=self.owner.fixture.daemon
        self.lease=self.owner.root/'operation.lock'
        self.pid.reset_mock();self.pid.side_effect=AssertionError('Released historical PID was reused')

    def test_near_capacity_mixed_qualification_history_under_real_lease(self):
        root=self.owner.root;run=root/'ordinary-run';run.mkdir()
        try:
            with resources.admission_lock(self.lease) as owner:
                owner.bind_daemon(self.docker.daemon)
                for i in range(3):owned(owner,run,'pi-mixed-'+str(i))
                raise lab.LabError('synthetic predecessor failed')
        except lab.LabError:pass
        with self.lease.open('r') as handle:
            resources.fcntl.flock(handle.fileno(),resources.fcntl.LOCK_EX)
            existing=owner.load();prototype=next(r for r in existing if r['status']=='absent')
            for i in range(reg.MAX_RECORDS-len(existing)):
                row={**prototype,'launch_id':str(uuid.uuid4()),'container':'pi-historical-fill-'+str(i),'status':'released','runroot':None}
                controls.atomic(owner.root/(row['launch_id']+'.json'),row)
            resources.fcntl.flock(handle.fileno(),resources.fcntl.LOCK_UN)
        originals={p:p.read_bytes() for p in root.rglob('*') if p.is_file() and p!=self.lease
                   and not (p.parent==owner.root and json.loads(p.read_bytes())['status']=='absent')}
        self.docker.calls.clear()
        with resources.admission_lock(self.lease) as recovered:
            self.assertEqual(counts(recovered),{'released':reg.MAX_RECORDS})
        self.assertTrue(all(p.read_bytes()==body for p,body in originals.items()))
        self.assertEqual(len(self.docker.calls),4);self.pid.assert_not_called()

    def test_historical_proof_tamper_and_io_failure_remain_distinct_and_nonsecret(self):
        receipt=Path(self.owner.helper['qualification_preworker_cleanup']['path'])
        original=receipt.read_bytes()
        for fault in ('tamper','permission'):
            with self.subTest(fault=fault),contextlib.ExitStack() as stack:
                if fault=='tamper':receipt.write_bytes(original+b' ')
                else:
                    real=os.open
                    def denied(path,*args,**kwargs):
                        if str(path)==receipt.name:raise PermissionError(errno.EACCES,'private-proof-path')
                        return real(path,*args,**kwargs)
                    stack.enter_context(mock.patch.object(os,'open',side_effect=denied))
                with self.assertRaises(resources.AdmissionError) as caught:
                    with resources.admission_lock(self.lease):self.fail('invalid proof admitted')
                value=diagnostic(caught.exception);context=value['infrastructure']['registry_diagnostic']
                self.assertEqual(context['phase'],'qualification_preworker_cleanup')
                self.assertEqual(context['operation'],'proof_read')
                self.assertEqual(context['os_error'],'permission_denied' if fault=='permission' else 'none')
                self.assertEqual(context['effects'],'none_observed')
                self.assertNotIn('private-proof-path',json.dumps(value))
            receipt.write_bytes(original)
        self.assertEqual(self.docker.calls,[]);self.pid.assert_not_called()

    def test_effects_remain_monotonic_after_error_then_quarantine(self):
        receipt=Path(self.owner.helper['qualification_preworker_cleanup']['path'])
        receipt.write_bytes(receipt.read_bytes()+b' ')
        row=copy.deepcopy(self.owner.helper);row['status']='absent';self.registry.write(row)
        with self.assertRaises(reg.RegistryError) as caught:self.registry.release(row,True)
        context=diagnostics.diagnostic(caught.exception)
        self.assertEqual(context['phase'],'qualification_preworker_cleanup')
        self.assertEqual(context['effects'],'may_have_occurred')
        self.assertEqual(row['status'],'quarantined')


if __name__=='__main__':unittest.main()
