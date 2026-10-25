"""External cleanup with real temp custody and fake Docker/controlled clocks.

No container, Pi, model, private credential or global Registry is used.
"""
import copy
import hashlib
import importlib.util
import json
import fcntl
import time as realtime
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/qualification'),str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import test_application_launch as fixtures
import application_launch as launch
import ownership_registry
import application_credentials as credentials
spec=importlib.util.spec_from_file_location('service_cleanup_qualification',ROOT/'tools/qualification/application_client.py')
qualifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(qualifier)

class FakeProcess:
    def __init__(self,backend,argv,reply,delay,**kwargs):
        self.backend,self.args,self.reply,self.delay=backend,list(argv),reply,delay
        self.pid=9000+len(backend.commands);self.returncode=None if delay else reply.returncode;self.spent=False
        self.stdout=self.stderr=None
        if argv[1:2]==['logs']:
            first,second=os.pipe();os.close(second);self.stdout=os.fdopen(first,'rb')
            first,second=os.pipe();os.close(second);self.stderr=os.fdopen(first,'rb')
    def __enter__(self):return self
    def __exit__(self,*unused):
        for stream in (self.stdout,self.stderr):
            if stream is not None and not stream.closed:stream.close()
    def communicate(self,input=None,timeout=None):
        if not self.spent:
            self.spent=True
            if timeout is not None and self.delay>timeout:
                self.backend.advance(timeout);raise subprocess.TimeoutExpired(self.args,timeout)
            self.backend.advance(self.delay)
            if self.returncode is None:self.returncode=self.reply.returncode
        return self.reply.stdout,self.reply.stderr
    def poll(self):return self.returncode
    def wait(self,timeout=None):return self.returncode
    def kill(self):self.returncode=-9
    def terminate(self):self.returncode=-15

class FakeDocker:
    def __init__(self,fixture,stop_seconds):
        self.fixture=fixture;self.stop_seconds=stop_seconds;self.commands=[];self.objects={}
    def advance(self,seconds):self.fixture.now[0]+=seconds;self.fixture.wall[0]+=seconds
    def popen(self,argv,*args,**kwargs):
        assert argv[0]=='docker','No actual process delegate is available'
        self.commands.append(list(argv));values=argv[1:];delay=0.;code=0;output='';error=''
        if values[:1]==['info']:
            output=json.dumps({'ID':'fixture-daemon','NCPU':64,'MemTotal':65536*1048576,'Architecture':'arm64','OSType':'linux'})
        elif values[:2]==['image','inspect']:
            output=json.dumps([{'Id':argv[-1],'Architecture':'arm64','Os':'linux'}])
        elif values[:1]==['run']:
            parsed=launch._options(argv);name=parsed[1]['--name'][0]
            record=next(r for r in self.fixture.registry.load() if r['container']==name)
            observed=fixtures.observation(record)
            for mount in observed['Mounts']:mount['Type']='bind'
            observed['State']={'Running':True,'Status':'running','ExitCode':0,'OOMKilled':False}
            self.objects[name]=self.objects[observed['Id']]=observed
        elif values[:2]==['container','inspect']:
            observed=self.objects.get(argv[-1]);code=0 if observed else 1
            output=json.dumps([observed] if observed else [])
            error='' if observed else 'No such container: '+argv[-1]
        elif values[:1]==['logs']:
            assert argv[-1] in self.objects
        elif values[:1]==['stop']:
            observed=self.objects[argv[-1]];observed['State'].update(Running=False,Status='exited')
            output=argv[-1];delay=self.stop_seconds
        elif values[:1]==['rm']:
            observed=self.objects[argv[-1]]
            self.objects={key:value for key,value in self.objects.items() if value is not observed};output=argv[-1]
        else:raise AssertionError('Unplanned fake Docker command')
        return FakeProcess(self,argv,subprocess.CompletedProcess(argv,code,output,error),delay,**kwargs)

class ServiceCleanupTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.LaunchTests(methodName='runTest');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.backend=FakeDocker(self.fixture,0)
        self.guard=launch.LaunchGuard(self.fixture.ledger,'cell-a',lambda:self.fixture.registry,self.backend.popen,
            None)
        self.proxy=SimpleNamespace(monotonic=lambda:self.fixture.now[0],time=lambda:self.fixture.wall[0],sleep=self.backend.advance)
        self.clock=mock.patch.object(launch,'time',self.proxy);self.clock.start();self.addCleanup(self.clock.stop)
        self.client_clock=mock.patch.object(qualifier,'time',self.proxy);self.client_clock.start();self.addCleanup(self.client_clock.stop)
        self.real_popen=subprocess.Popen
        self.native=mock.patch.object(subprocess,'Popen',self.guard.popen);self.native.start();self.addCleanup(self.native.stop)
        # LaunchGuard's captured delegate is always FakeDocker.
        self.registry=self.fixture.registry;self.registry.command=lambda argv:qualifier.lab.command(argv,required=False)
        self.fixture.root.joinpath('state.json').write_text(json.dumps({'started_at':self.fixture.wall[0]}))
        self.private=tempfile.TemporaryDirectory();self.addCleanup(self.private.cleanup)
        parent=Path(self.private.name).resolve();parent.chmod(0o700)
        self.owner=object.__new__(qualifier.OwnedServices)
        self.owner.root=self.fixture.root;self.owner.manifest={};self.owner.cell={'id':'cell-a'}
        self.owner.registry=self.registry;self.owner.guard=self.guard;self.owner.folder=self.fixture.root/'cells/cell-a'
        self.owner.items=[];self.owner.service_states={};self.owner.private_identities={}
        self.owner.redactor=credentials.Redactor(['FAKE_DISPOSABLE_VALUE_382']);self.owner.private=parent
        self.owner.private_identity=qualifier._private_identity(parent);self.owner.safe=False
        for role in ('fixture','scripted-inference'):
            source=parent/role;source.mkdir(mode=0o700);(source/'initial.json').write_bytes(b'{}');(source/'initial.json').chmod(0o400)
            argv=self.fixture.service_argv(role)
            for index,value in enumerate(argv):
                if value.startswith('type=bind,src=') and ',dst=/private,' in value:
                    argv[index]='type=bind,src='+str(source)+',dst=/private,bind-recursive=disabled,readonly'
            record,argv=self.guard.external_service_intent(self.registry,argv,role,self.fixture.root/'fake-run')
            self.guard.popen(argv)
            row=next(r for r in self.fixture.ledger.snapshot()['launches'] if r['launch_id']==record['launch_id'])
            record.update(container_id=row['container_id'],status='running');self.registry.write(record)
            self.owner.items.append((record,record['container']));self.owner.service_states[record['launch_id']]={'role':role,'ready':True}
            self.owner.private_identities[record['launch_id']]=ownership_registry.observe_qualification_private(record)
        self.owner.journal=self.owner.folder/'fixture/private';self.owner.journal.mkdir(mode=0o700,parents=True)
        self.record=self.owner.items[-1][0];self.backend.commands.clear()
        self.validations=0;self.transactions=0
        original=self.fixture.ledger._validate;transaction=self.fixture.ledger._transaction
        self.validation_hook=lambda state:None
        def validate(state):
            self.validations+=1;original(state);self.validation_hook(state)
        def transact(*args,**kwargs):self.transactions+=1;return transaction(*args,**kwargs)
        self.patches=[mock.patch.object(self.fixture.ledger,'_validate',validate),mock.patch.object(self.fixture.ledger,'_transaction',transact)]
        for patch in self.patches:patch.start();self.addCleanup(patch.stop)
    def raw(self):return json.loads((self.fixture.ledger.root/'ledger.json').read_bytes())
    def effects(self):return [a for a in self.backend.commands if a[1] in ('stop','rm')]
    def process(self,operation='stop',deadline=None):
        return self.guard.service_process(self.record,operation,self.fixture.now[0]+30 if deadline is None else deadline)
    def test_two_services_complete_with_twenty_validations_not_sixtyfour(self):
        original_confirm=ownership_registry.Registry.confirm_absent;original_release=ownership_registry.Registry.release
        def confirm(registry,record):return self.fixture.ledger.application_lifecycle(self.guard,registry,record,original_confirm)
        def release(registry,record,clean):return self.fixture.ledger.application_lifecycle(self.guard,registry,record,original_release,release=True,sensitive_clean=clean)
        self.validation_hook=lambda state:self.backend.advance(.6)
        self.backend.stop_seconds=8;started=self.fixture.now[0]
        with mock.patch.object(ownership_registry.Registry,'confirm_absent',confirm),mock.patch.object(ownership_registry.Registry,'release',release):
            self.owner.close()
        self.assertTrue(self.owner.safe);self.assertEqual(self.validations,20);self.assertEqual(self.transactions,10)
        self.assertAlmostEqual(self.fixture.now[0]-started,28)
        self.assertEqual([a[1] for a in self.effects()],['stop','rm','stop','rm'])
        self.assertTrue(all(r['private_cleanup'] for r in self.raw()['launches']))
    def test_one_fresh_transaction_and_durable_audit_before_exactly_once_delegate(self):
        captured=self.guard.original_popen
        def delegate(argv,**kwargs):
            if argv[1] not in ('stop','rm'):return captured(argv,**kwargs)
            state=self.raw();row=state['launches'][-1]
            self.assertEqual(row['cleanup_requests'],[{'operation':'stop','requested_target':'immutable_id','effective_target':'immutable_id'}])
            return captured(argv,**kwargs)
        self.guard.original_popen=delegate;self.process()
        self.assertEqual(self.transactions,1);self.assertEqual(self.validations,2);self.assertEqual(len(self.effects()),1)
    def test_second_command_revalidates_current_registry_without_cache(self):
        self.process();self.record['image']='sha256:'+'f'*64;self.registry.write(self.record)
        with self.assertRaises(launch.LaunchError):self.process('rm')
        self.assertEqual(len(self.effects()),1);self.assertTrue(self.raw()['poisoned'])
    def test_registry_drift_during_postvalidation_denies_before_effect(self):
        def drift(state):
            if self.validations==2:
                changed=copy.deepcopy(self.record);changed['status']='quarantined';self.registry.write(changed)
        self.validation_hook=drift
        with self.assertRaises(launch.LaunchError):self.process()
        self.assertFalse(self.effects());self.assertTrue(self.raw()['poisoned'])
    def test_fsync_failure_has_zero_native_effect(self):
        with mock.patch.object(launch,'_write',side_effect=OSError('controlled durability failure')):
            with self.assertRaises(launch.LaunchError):self.process()
        self.assertFalse(self.effects())
    def test_inspection_exception_identity_and_durable_poison_same_transaction(self):
        original=TimeoutError('CANARY must never be serialized');observe=self.guard._observe
        def fail(argv,timeout=15):
            if argv[1:3]==['container','inspect']:raise original
            return observe(argv,timeout)
        with mock.patch.object(self.guard,'_observe',side_effect=fail):
            with self.assertRaises(TimeoutError) as caught:self.process()
        self.assertIs(caught.exception,original);self.assertEqual(self.transactions,1)
        self.assertTrue(self.raw()['poisoned']);self.assertEqual(self.raw()['launches'][-1]['physical'],'uncertain')
        self.assertNotIn('CANARY',(self.fixture.ledger.root/'ledger.json').read_text());self.assertFalse(self.effects())
    def test_daemon_exception_identity_and_durable_poison(self):
        original=OSError('controlled read error')
        with mock.patch.object(self.guard,'_daemon',side_effect=original):
            with self.assertRaises(OSError) as caught:self.process()
        self.assertIs(caught.exception,original);self.assertTrue(self.raw()['poisoned']);self.assertFalse(self.effects())
    def test_delegate_exception_preserved_once_with_durable_uncertainty(self):
        original=RuntimeError('controlled delegate failure');captured=self.guard.original_popen
        def invoke(argv,**kwargs):
            if argv[1]=='stop':raise original
            return captured(argv,**kwargs)
        delegate=mock.Mock(side_effect=invoke);self.guard.original_popen=delegate
        with self.assertRaises(RuntimeError) as caught:self.process()
        self.assertIs(caught.exception,original);self.assertEqual(sum(call.args[0][1]=='stop' for call in delegate.call_args_list),1)
        self.assertTrue(self.raw()['poisoned']);self.assertEqual(len(self.raw()['launches'][-1]['cleanup_requests']),1)
    def test_expiry_during_postvalidation_never_delegates_or_resets_deadline(self):
        self.validation_hook=lambda state:self.backend.advance(2)
        with self.assertRaises(launch.LaunchError):self.process(deadline=self.fixture.now[0]+3)
        self.assertFalse(self.effects());self.assertTrue(self.raw()['poisoned'])
    def test_regressed_clock_after_fsync_denies_before_effect(self):
        def regress(state):
            if self.validations==2:self.fixture.wall[0]-=1
        self.validation_hook=regress
        with self.assertRaises(launch.LaunchError):self.process()
        self.assertFalse(self.effects());self.assertTrue(self.raw()['poisoned'])
    def test_wrong_role_never_uses_external_delegate(self):
        self.record['qualification_role']='participant';self.registry.write(self.record)
        with self.assertRaises(launch.LaunchError):self.process()
        self.assertFalse(self.effects())
    def test_unknown_absence_refuses_mutation(self):
        observe=self.guard._observe
        def unknown(argv,timeout=15):
            return subprocess.CompletedProcess(argv,1,'','transport failure') if argv[1:3]==['container','inspect'] else observe(argv,timeout)
        with mock.patch.object(self.guard,'_observe',side_effect=unknown):
            with self.assertRaises(launch.LaunchError):self.process()
        self.assertFalse(self.effects());self.assertTrue(self.raw()['poisoned'])
    def test_id_mount_label_and_daemon_changes_refuse(self):
        observed=self.backend.objects[self.record['container_id']]
        for kind in ('id','mount','label','image','daemon'):
            with self.subTest(kind=kind):
                saved=copy.deepcopy(observed);daemon=self.registry.daemon
                if kind=='id':observed['Id']='f'*64
                elif kind=='mount':observed['Mounts'][0]['RW']=True
                elif kind=='label':observed['Config']['Labels'][launch.LABEL]='foreign'
                elif kind=='image':observed['Image']='sha256:'+'f'*64
                else:self.registry.daemon='foreign'
                with self.assertRaises(launch.LaunchError):self.process()
                self.assertFalse(self.effects());observed.clear();observed.update(saved);self.registry.daemon=daemon
    def test_logs_deadline_includes_guard_not_only_pipe_read(self):
        self.validation_hook=lambda state:self.backend.advance(2)
        with self.assertRaises(launch.LaunchError):self.owner._logs(self.record['container_id'],3,self.record)
        self.assertFalse([a for a in self.backend.commands if a[1]=='logs'])
    def test_cleanup_deadline_exhaustion_prevents_later_mutations(self):
        self.validation_hook=lambda state:self.backend.advance(4)
        with self.assertRaises(qualifier.QualificationError):self.owner.close()
        self.assertFalse(self.owner.safe)
        self.assertTrue(self.fixture.now[0]<=140)
        self.assertEqual([a[1] for a in self.effects()],['stop','rm'])
        self.assertTrue(all(a[-1]==self.record['container_id'] for a in self.effects()))
    def test_command_timeout_uses_remaining_budget_after_guard(self):
        self.validation_hook=lambda state:self.backend.advance(1)
        self.backend.stop_seconds=9;deadline=self.fixture.now[0]+6
        with self.assertRaises(subprocess.TimeoutExpired):self.owner._service_command(self.record,'stop',deadline,18)
        self.assertAlmostEqual(self.fixture.now[0],deadline-1)
    def test_replaced_root_lock_or_durable_bytes_refuse_before_delegate(self):
        for mode in ('root','lock','bytes'):
            with self.subTest(mode=mode):
                original=launch._write;replacement=[]
                def replace(root,name,state):
                    original(root,name,state)
                    if replacement:return
                    replacement.append(True)
                    if mode=='root':
                        moved=self.fixture.ledger.root.with_name('old-launches');self.fixture.ledger.root.rename(moved)
                        self.fixture.ledger.root.mkdir(mode=0o700)
                        for item in moved.iterdir():
                            target=self.fixture.ledger.root/item.name;target.write_bytes(item.read_bytes());target.chmod(0o600)
                    elif mode=='lock':
                        path=self.fixture.ledger.root/'ledger.lock';path.unlink();path.write_bytes(b'');path.chmod(0o600)
                    else:
                        path=self.fixture.ledger.root/'ledger.json';changed=json.loads(path.read_bytes());changed['poisoned']=True
                        path.write_text(json.dumps(changed));path.chmod(0o600)
                with mock.patch.object(launch,'_write',side_effect=replace),self.assertRaises(launch.LaunchError):self.process()
                self.assertFalse(self.effects())
                # Restore only disposable test custody for the next subcase.
                if mode=='root':
                    import shutil
                    shutil.rmtree(self.fixture.ledger.root);self.fixture.ledger.root.with_name('old-launches').rename(self.fixture.ledger.root)
                elif mode=='bytes':
                    state=self.raw();state['poisoned']=False
                    (self.fixture.ledger.root/'ledger.json').write_text(json.dumps(state))
    def test_caller_cannot_override_fixed_docker_semantics(self):
        for kwargs in ({'shell':True},{'executable':'other'},{'env':{'DOCKER_HOST':'foreign'}},{'cwd':'/'}):
            with self.subTest(kwargs=tuple(kwargs)),self.assertRaises(launch.LaunchError):
                self.guard.service_process(self.record,'stop',self.fixture.now[0]+30,**kwargs)
        self.assertFalse(self.effects())
    def test_real_contender_cannot_acquire_lock_during_delegate_but_can_after(self):
        original=self.guard.original_popen;observed=[]
        def contender():
            read,write=os.pipe();child=os.fork()
            if child==0:
                os.close(read);fd=os.open(self.fixture.ledger.root/'ledger.lock',os.O_RDWR)
                try:
                    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);os.write(write,b'acquired')
                except BlockingIOError:os.write(write,b'blocked')
                finally:os.close(fd);os.close(write);os._exit(0)
            os.close(write)
            try:return os.read(read,16)
            finally:os.close(read);self.assertEqual(os.waitpid(child,0)[1],0)
        def delegate(argv,**kwargs):
            if argv[1]=='stop':observed.append(contender())
            return original(argv,**kwargs)
        self.guard.original_popen=delegate;self.process()
        self.assertEqual(observed,[b'blocked']);self.assertEqual(contender(),b'acquired')
    def test_actual_second_process_flock_blocks_dispatch_until_release(self):
        read,write=os.pipe();child=os.fork()
        if child==0:
            os.close(read)
            fd=os.open(self.fixture.ledger.root/'ledger.lock',os.O_RDWR)
            fcntl.flock(fd,fcntl.LOCK_EX);os.write(write,b'1');os.close(write)
            realtime.sleep(.15);os.close(fd);os._exit(0)
        os.close(write)
        try:
            self.assertEqual(os.read(read,1),b'1');started=realtime.monotonic()
            self.process();elapsed=realtime.monotonic()-started
            self.assertGreaterEqual(elapsed,.10);self.assertEqual(len(self.effects()),1)
        finally:os.close(read);self.assertEqual(os.waitpid(child,0)[1],0)
    def test_unreaped_owned_log_reader_prevents_safe_cleanup_and_further_effects(self):
        def diagnostic(record,*args,**kwargs):
            if record['qualification_role']=='scripted-inference':raise qualifier.ServiceReaderUnconfirmed()
        with mock.patch.object(self.owner,'_diagnose',side_effect=diagnostic),self.assertRaises(qualifier.QualificationError):self.owner.close()
        self.assertFalse(self.owner.safe);self.assertFalse(self.effects())
    def test_log_reader_timeout_disposal_is_bounded_and_reported_unconfirmed(self):
        first,second=os.pipe();os.close(second);output=os.fdopen(first,'rb')
        first,second=os.pipe();os.close(second);error=os.fdopen(first,'rb')
        child=SimpleNamespace(stdout=output,stderr=error,poll=lambda:None,terminate=mock.Mock(),kill=mock.Mock(),wait=mock.Mock(side_effect=subprocess.TimeoutExpired('fixed-reader',0)))
        with self.assertRaises(qualifier.ServiceReaderUnconfirmed):qualifier._bounded_service_logs('fixed-id',seconds=1,popen=lambda *a,**kw:child)
        child.terminate.assert_called_once();child.kill.assert_called_once()
        self.assertTrue(output.closed and error.closed)
        self.assertTrue(all(0<=call.kwargs['timeout']<=1 for call in child.wait.call_args_list))
    def test_log_signal_race_still_requires_bounded_confirmed_wait(self):
        first,second=os.pipe();os.close(second);output=os.fdopen(first,'rb')
        first,second=os.pipe();os.close(second);error=os.fdopen(first,'rb')
        child=SimpleNamespace(stdout=output,stderr=error,poll=lambda:None,terminate=mock.Mock(side_effect=ProcessLookupError()),kill=mock.Mock(),wait=mock.Mock(side_effect=[subprocess.TimeoutExpired('fixed',0),0]))
        captured=qualifier._bounded_service_logs('fixed-id',seconds=1,popen=lambda *a,**kw:child)
        self.assertFalse(captured['complete']);child.terminate.assert_called_once();child.kill.assert_not_called()
        self.assertEqual(child.wait.call_count,2)
    def test_all_log_signal_wait_errors_block_private_purge_and_registry_release(self):
        first,second=os.pipe();os.close(second);output=os.fdopen(first,'rb')
        first,second=os.pipe();os.close(second);error=os.fdopen(first,'rb')
        child=SimpleNamespace(pid=876545,stdout=output,stderr=error,poll=mock.Mock(side_effect=OSError('fixed')),terminate=mock.Mock(side_effect=OSError('fixed')),kill=mock.Mock(side_effect=OSError('fixed')),wait=mock.Mock(side_effect=subprocess.TimeoutExpired('fixed',0)))
        original=self.guard.service_process
        def process(record,operation,deadline,**kwargs):
            return child if operation=='logs' else original(record,operation,deadline,**kwargs)
        with mock.patch.object(self.guard,'service_process',side_effect=process),mock.patch.object(qualifier,'_purge_private') as purge,mock.patch.object(self.registry,'release') as release:
            with self.assertRaises(qualifier.QualificationError):self.owner.close()
        purge.assert_not_called();release.assert_not_called();self.assertFalse(self.effects());self.assertFalse(self.owner.safe)
        child.terminate.assert_called_once();child.kill.assert_called_once()
        self.assertEqual(qualifier.read(self.owner.folder/'services-cleanup.json')['unconfirmed_owned_cli'],[{'pid':876545,'pid_available':True,'reaped':False}])
    def test_command_unconfirmed_reap_stops_other_service_and_retains_exact_pid(self):
        timeout=subprocess.TimeoutExpired('CANARY_NOT_RETAINED',1)
        child=SimpleNamespace(pid=876543,returncode=None,poll=mock.Mock(side_effect=OSError('CANARY_NOT_RETAINED')),kill=mock.Mock(side_effect=ProcessLookupError()),communicate=mock.Mock(side_effect=timeout))
        original=self.guard.service_process
        def process(record,operation,deadline,**kwargs):
            return child if operation=='stop' else original(record,operation,deadline,**kwargs)
        with mock.patch.object(self.guard,'service_process',side_effect=process),mock.patch.object(qualifier,'_purge_private') as purge,mock.patch.object(self.registry,'release') as release:
            with self.assertRaises(qualifier.QualificationError):self.owner.close()
        purge.assert_not_called();release.assert_not_called();self.assertFalse(self.effects())
        receipt=qualifier.read(self.owner.folder/'services-cleanup.json')
        self.assertEqual(receipt['unconfirmed_owned_cli'],[{'pid':876543,'pid_available':True,'reaped':False}])
        self.assertNotIn('CANARY',(self.owner.folder/'services-cleanup.json').read_text());child.kill.assert_called_once()
        self.assertEqual(child.communicate.call_count,2)
        self.assertTrue(all(0<=call.kwargs['timeout']<=30 for call in child.communicate.call_args_list))
    def test_command_kill_race_with_confirmed_reap_preserves_primary_identity(self):
        primary=subprocess.TimeoutExpired('fixed',1)
        child=SimpleNamespace(pid=876544,returncode=None,poll=lambda:None,kill=mock.Mock(side_effect=ProcessLookupError()))
        def communicate(**kwargs):
            if not hasattr(child,'first'):child.first=True;raise primary
            child.returncode=0;return '',''
        child.communicate=mock.Mock(side_effect=communicate)
        with mock.patch.object(self.guard,'service_process',return_value=child),self.assertRaises(subprocess.TimeoutExpired) as caught:
            self.owner._service_command(self.record,'stop',self.fixture.now[0]+5,1)
        self.assertIs(caught.exception,primary);child.kill.assert_called_once();self.assertEqual(child.communicate.call_count,2)
    def test_actual_disposable_host_cli_is_reaped_after_timeout(self):
        child=self.real_popen([sys.executable,'-B','-c','import time; time.sleep(30)'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            started=realtime.monotonic()
            with mock.patch.object(self.guard,'service_process',return_value=child),self.assertRaises(subprocess.TimeoutExpired):
                self.owner._service_command(self.record,'stop',self.fixture.now[0]+5,.1)
            self.assertIsNotNone(child.returncode);self.assertIsNotNone(child.poll())
            self.assertLess(realtime.monotonic()-started,3)
        finally:
            if child.poll() is None:child.kill();child.wait(timeout=2)
    def broken_log_child(self,pid):
        first,second=os.pipe();os.close(second);output=os.fdopen(first,'rb')
        first,second=os.pipe();os.close(second);error=os.fdopen(first,'rb')
        return SimpleNamespace(pid=pid,stdout=output,stderr=error,poll=lambda:None,terminate=lambda:None,kill=lambda:None,wait=mock.Mock(side_effect=subprocess.TimeoutExpired('fixed',0)))
    def test_standalone_startup_diagnostic_unknown_reader_is_sticky_through_close(self):
        child=self.broken_log_child(876546)
        with mock.patch.object(self.guard,'service_process',return_value=child) as process:
            with self.assertRaises(qualifier.ServiceReaderUnconfirmed):self.owner._diagnose(self.record,self.record['container'],'startup_failed')
            self.assertEqual(process.call_count,1)
            with mock.patch.object(qualifier,'_purge_private') as purge,mock.patch.object(self.registry,'release') as release:
                with self.assertRaises(qualifier.QualificationError):self.owner.close()
            self.assertEqual(process.call_count,1);purge.assert_not_called();release.assert_not_called()
        self.assertFalse(self.effects());self.assertFalse(self.owner.safe)
        self.assertEqual(qualifier.read(self.owner.folder/'services-cleanup.json')['unconfirmed_owned_cli'],[{'pid':876546,'pid_available':True,'reaped':False}])
    def test_startup_readiness_unknown_reader_does_not_start_another_diagnostic(self):
        child=self.broken_log_child(876547)
        self.owner.args=SimpleNamespace(_attempt_root=self.fixture.root/'fake-run')
        self.owner.manifest={'images':self.fixture.policy['images'],'fixture_route':{'publish_host':'127.0.0.1'}};self.owner.cell['release']='0.87.1'
        observations=self.owner.folder/'fresh-start';observations.mkdir(mode=0o700)
        (observations/'private').mkdir(mode=0o700)
        def ready(*args):self.owner._logs(self.record['container_id'],3,self.record)
        with mock.patch.object(self.guard,'external_service_intent',return_value=(self.record,['fixed-not-dispatched'])),mock.patch.object(self.guard,'service_process',return_value=child) as process,mock.patch.object(self.owner,'_await_ready',side_effect=ready),mock.patch.object(self.owner,'_observation') as observation:
            with self.assertRaises(qualifier.ServiceReaderUnconfirmed):self.owner._start('fixture',observations,['fixed'],8080,Path(self.record['mounts'][2]['source']))
            observation.assert_not_called();self.assertEqual(process.call_count,1)
            with self.assertRaises(qualifier.QualificationError):self.owner.close()
            self.assertEqual(process.call_count,1)
        self.assertFalse(self.effects());self.assertFalse(self.owner.safe)
        self.assertEqual(qualifier.read(self.owner.folder/'services-cleanup.json')['unconfirmed_owned_cli'],[{'pid':876547,'pid_available':True,'reaped':False}])
    def test_command_cancellation_during_disposal_keeps_sticky_unknown_pid(self):
        primary=KeyboardInterrupt('CANARY_PRIMARY')
        child=SimpleNamespace(pid=876548,returncode=None,poll=mock.Mock(side_effect=KeyboardInterrupt('CANARY_POLL')),kill=mock.Mock(side_effect=qualifier.QualificationError()),communicate=mock.Mock(side_effect=[primary,qualifier.QualificationError()]))
        with mock.patch.object(self.guard,'service_process',return_value=child),mock.patch.object(self.owner,'_diagnose'),mock.patch.object(qualifier,'_purge_private') as purge,mock.patch.object(self.registry,'release') as release:
            with self.assertRaises(qualifier.QualificationError):self.owner.close()
        purge.assert_not_called();release.assert_not_called();self.assertFalse(self.effects())
        receipt=qualifier.read(self.owner.folder/'services-cleanup.json')
        self.assertEqual(receipt['unconfirmed_owned_cli'],[{'pid':876548,'pid_available':True,'reaped':False}])
        self.assertNotIn('CANARY',(self.owner.folder/'services-cleanup.json').read_text())
    def test_command_confirmed_disposal_preserves_primary_cancellation(self):
        primary=KeyboardInterrupt('fixed-primary');child=SimpleNamespace(pid=876549,returncode=None,poll=mock.Mock(side_effect=qualifier.QualificationError()),kill=mock.Mock(side_effect=KeyboardInterrupt('fixed-cleanup')))
        def communicate(**kwargs):
            if not hasattr(child,'first'):child.first=True;raise primary
            child.returncode=-9;return '',''
        child.communicate=communicate
        with mock.patch.object(self.guard,'service_process',return_value=child),self.assertRaises(KeyboardInterrupt) as caught:
            self.owner._service_command(self.record,'stop',self.fixture.now[0]+5,1)
        self.assertIs(caught.exception,primary);self.assertFalse(getattr(self.owner,'unconfirmed_cli',[]))
    def test_log_cancellations_at_each_disposal_stage_require_reap_or_sticky_pid(self):
        for stage in ('poll','terminate','wait','kill'):
            for confirmed in (False,True):
                with self.subTest(stage=stage,confirmed=confirmed):
                    child=self.broken_log_child(876550);primary=KeyboardInterrupt('CANARY_CANCEL')
                    child.poll=mock.Mock(side_effect=primary if stage=='poll' else [None])
                    child.terminate=mock.Mock(side_effect=primary if stage=='terminate' else None)
                    child.kill=mock.Mock(side_effect=primary if stage=='kill' else None)
                    calls=[subprocess.TimeoutExpired('fixed',0)]
                    calls.append(primary if stage=='wait' else subprocess.TimeoutExpired('fixed',0) if stage=='kill' or not confirmed else 0)
                    if len(calls)==2 and (stage in ('wait','kill') or not confirmed):calls.append(0 if confirmed else qualifier.QualificationError())
                    child.wait=mock.Mock(side_effect=calls)
                    self.owner.unconfirmed_cli=[]
                    with mock.patch.object(self.guard,'service_process',return_value=child):
                        if confirmed:
                            with self.assertRaises(KeyboardInterrupt) as caught:self.owner._logs(self.record['container_id'],3,self.record)
                            self.assertIs(caught.exception,primary);self.assertFalse(self.owner.unconfirmed_cli)
                        else:
                            with self.assertRaises(qualifier.ServiceReaderUnconfirmed):self.owner._logs(self.record['container_id'],3,self.record)
                            self.assertEqual(self.owner.unconfirmed_cli,[{'pid':876550,'pid_available':True,'reaped':False}])
    def test_log_primary_cancellation_is_preserved_after_confirmed_reap(self):
        child=self.broken_log_child(876551);primary=KeyboardInterrupt('fixed-primary')
        child.wait=mock.Mock(side_effect=[primary,0]);child.terminate=mock.Mock(side_effect=qualifier.QualificationError())
        with mock.patch.object(self.guard,'service_process',return_value=child),self.assertRaises(KeyboardInterrupt) as caught:
            self.owner._logs(self.record['container_id'],3,self.record)
        self.assertIs(caught.exception,primary);self.assertFalse(getattr(self.owner,'unconfirmed_cli',[]))
    def test_deadline_exception_between_disposal_operations_retains_sticky_pid(self):
        child=SimpleNamespace(pid=876552,returncode=None,poll=lambda:None,kill=mock.Mock(),communicate=mock.Mock(side_effect=subprocess.TimeoutExpired('fixed',0)))
        clock=SimpleNamespace(monotonic=mock.Mock(side_effect=qualifier.QualificationError()))
        with mock.patch.object(self.guard,'service_process',return_value=child),mock.patch.object(qualifier,'time',clock),self.assertRaises(qualifier.ServiceProcessUnconfirmed):
            self.owner._service_command(self.record,'stop',105,1)
        self.assertEqual(self.owner.unconfirmed_cli,[{'pid':876552,'pid_available':True,'reaped':False}])
    def test_active_cleanup_scope_clamps_a_longer_command_deadline(self):
        self.validation_hook=lambda state:self.backend.advance(1)
        with self.guard.service_cleanup(self.registry,self.fixture.now[0]+1.5):
            with self.assertRaises(launch.LaunchError):self.process(deadline=self.fixture.now[0]+30)
        self.assertFalse(self.effects())
    def test_no_registry_release_after_cleanup_receipt_crosses_deadline(self):
        original=ownership_registry.write_qualification_service_cleanup
        def delayed(*args,**kwargs):
            result=original(*args,**kwargs);self.backend.advance(31);return result
        with mock.patch.object(ownership_registry,'write_qualification_service_cleanup',side_effect=delayed),mock.patch.object(self.registry,'release') as released:
            with self.assertRaises(qualifier.QualificationError):self.owner.close()
        released.assert_not_called();self.assertFalse(self.owner.safe)
    def test_no_safe_closure_after_private_purge_crosses_fixed_deadline(self):
        original=qualifier._purge_private
        def slow(path,identity):original(path,identity);self.backend.advance(31)
        with mock.patch.object(qualifier,'_purge_private',side_effect=slow),self.assertRaises(qualifier.QualificationError):self.owner.close()
        self.assertFalse(self.owner.safe);self.assertFalse(any(row['private_cleanup'] for row in self.raw()['launches']))
    def test_external_scope_restores_registry_command_after_failure(self):
        original=self.registry.command
        with self.assertRaises(ValueError):
            with self.guard.service_cleanup(self.registry,self.fixture.now[0]+30):raise ValueError('controlled')
        self.assertIs(self.registry.command,original);self.assertIsNone(self.guard._service_cleanup_deadline)

if __name__=='__main__':unittest.main()
