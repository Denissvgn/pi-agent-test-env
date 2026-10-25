"""Real durable ledgers/flock with inert launch delegates; no Docker/Pi/model.

These regressions exercise pre-effect durability and current custody, including
real independent host processes. Prior campaign fixtures remain synthetic.
"""
import copy
import fcntl
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools/qualification'),str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_launch as launch
import ownership_registry
import test_application_launch as fixtures


def _competitor(root,policy,record,weight,capacity,events,release,label,clock):
    """No effect beyond an event sentinel; actual flock is not mocked away."""
    try:
        events.put((label,'attempting'))
        ledger=launch.LaunchLedger(root,policy,clock=lambda:clock.value,wall=lambda:1000.0)
        def delegate(key):
            events.put((label,'delegate'))
            if label=='A' and not release.wait(5):raise RuntimeError('test_release_missing')
            return 'inert-process'
        ledger.application_dispatch('cell-a',record,weight,{'id':'fixture-daemon',**capacity},delegate)
        events.put((label,'returned'))
    except BaseException as error:events.put((label,'error',getattr(error,'reason',type(error).__name__)))


class BatchedLaunchTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
        self.policy=fixtures.manifest();self.now=[100.0];self.wallnow=[1000.0];self.clock=lambda:self.now[0];self.wall=lambda:self.wallnow[0]
        self.capacity={'cpu_millis':64000,'memory_mib':65536};self.daemon={'id':'fixture-daemon',**self.capacity}
        self.ledger=launch.LaunchLedger.create(self.root/'ledger',self.policy,daemon_id='fixture-daemon',daemon_capacity=self.capacity,clock=self.clock,wall=self.wall)
        self.registry=ownership_registry.Registry(self.root/'registry');self.registry.bind_daemon('fixture-daemon')
        self.weight={'cpu_millis':1000,'memory_mib':512,'pids_limit':128};self.record=self.newrecord();self.registry.write(self.record)
        self.guard=launch.LaunchGuard(self.ledger,'cell-a',lambda:self.registry,lambda *a,**kw:None,lambda argv:None)
    def newrecord(self):
        return {'schema':1,'launch_id':str(uuid.uuid4()),'registry':self.registry.registry_id,'generation':self.registry.generation,'status':'intent',
            'container':'inert-'+uuid.uuid4().hex,'image':self.policy['images']['core-0.87.1']['id'],'mounts':[],
            'binding':{},'daemon':'fixture-daemon','runroot':str(self.root/'run'),'owner_pid':os.getpid(),'application_helper':True,'client_mode':'application-execution','private_store':str(self.root/'private')}
    def raw(self):return json.loads((self.ledger.root/'ledger.json').read_text())
    def dispatch(self,delegate=None,**kwargs):return self.ledger.application_dispatch('cell-a',self.record,self.weight,self.daemon,delegate or (lambda key:object()),**kwargs)
    def observed(self,record=None):
        record=record or self.record
        return {'Id':'c'*64,'Image':record['image'],'Config':{'Labels':{launch.LABEL:record['launch_id'],launch.REGISTRY_LABEL:record['registry']}},
            'Mounts':[{'Source':m['source'],'Destination':m['target'],'RW':m['rw']} for m in record['mounts']]}
    def started(self):
        key,process=self.dispatch();self.ledger.application_started(key,123);return key,process
    def test_success_has_three_fresh_transactions_and_durable_pending_before_delegate(self):
        process=object();events=[];original_validate=self.ledger._validate
        def validate(state):events.append('validate');return original_validate(state)
        def delegate(key):
            raw=self.raw();self.assertEqual(len(raw['launches']),1);self.assertEqual(raw['launches'][0]['key'],key);self.assertEqual(raw['launches'][0]['physical'],'pending')
            events.append('delegate');return process
        with mock.patch.object(self.ledger,'_validate',side_effect=validate),mock.patch.object(self.ledger,'_transaction',wraps=self.ledger._transaction) as transactions:
            key,returned=self.dispatch(delegate);self.assertIs(returned,process)
            remaining=self.ledger.application_started(key,123);identifier=self.ledger.application_identity(self.guard,self.registry,self.record,self.observed())
            self.assertEqual(transactions.call_count,3)
        self.assertGreaterEqual(events.count('validate'),6);self.assertGreater(events.index('delegate'),0)
        self.assertEqual(identifier,'c'*64);self.assertEqual(remaining,14400);self.assertEqual(self.raw()['launches'][0]['pid'],123)
    def contention(self,prior_live=0,late=False):
        for _ in range(prior_live):
            record=self.newrecord();record['application_helper']=False
            key=self.ledger.reserve('cell-a','probe',record,{'cpu_millis':1000,'memory_mib':1024,'pids_limit':256},self.daemon)
            self.ledger.note(key,physical='started',pid=456)
        context=multiprocessing.get_context('spawn');events=context.Queue();release=context.Event();clock=context.Value('d',100.0)
        records=[self.record,self.newrecord()];children=[]
        try:
            a=context.Process(target=_competitor,args=(self.ledger.root,self.policy,records[0],self.weight,self.capacity,events,release,'A',clock));a.start();children.append(a)
            seen=[]
            until=time.monotonic()+8
            while ('A','delegate') not in seen:
                self.assertLess(time.monotonic(),until);seen.append(events.get(timeout=5))
            b=context.Process(target=_competitor,args=(self.ledger.root,self.policy,records[1],self.weight,self.capacity,events,release,'B',clock));b.start();children.append(b)
            while ('B','attempting') not in seen:seen.append(events.get(timeout=5))
            fd=os.open(self.ledger.root/'ledger.lock',os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally:os.close(fd)
            self.assertNotIn(('B','delegate'),seen)
            if late:clock.value=14500.0
            release.set()
            for child in children:child.join(8);self.assertFalse(child.is_alive());self.assertEqual(child.exitcode,0)
            while ('A','returned') not in seen or not any(event[:2]==('B','error') for event in seen):seen.append(events.get(timeout=2))
            self.assertIn(('A','returned'),seen);self.assertNotIn(('B','delegate'),seen)
            error=next(event[2] for event in seen if event[:2]==('B','error'))
            self.assertEqual(error,'qualification_deadline' if late else 'qualification_live_limit' if prior_live==3 else 'qualification_role_limit')
            self.assertEqual(len(self.raw()['launches']),prior_live+1)
        finally:
            release.set()
            for child in children:
                if child.is_alive():child.terminate()
                child.join(3)
            events.close();events.join_thread()
    def test_two_process_role_contention_holds_real_lock_through_delegate(self):self.contention()
    def test_two_process_live_slot_contention_cannot_hide_an_uncharged_effect(self):self.contention(prior_live=3)
    def test_expired_competitor_after_real_lock_wait_never_delegates(self):self.contention(late=True)
    def test_fsync_failure_before_publication_has_zero_effects(self):
        delegate=mock.Mock();original=launch.os.fsync
        def fsync(fd):
            if not __import__('stat').S_ISDIR(os.fstat(fd).st_mode):raise OSError('inert_file_fsync_failure')
            return original(fd)
        with mock.patch.object(launch.os,'fsync',side_effect=fsync),self.assertRaises((OSError,launch.LaunchError)):self.dispatch(delegate)
        delegate.assert_not_called();self.assertEqual(self.raw()['launches'],[])
    def test_directory_fsync_failure_after_rename_keeps_one_pending_and_no_effect(self):
        delegate=mock.Mock();original=launch.os.fsync
        def fsync(fd):
            if __import__('stat').S_ISDIR(os.fstat(fd).st_mode):raise OSError('inert_directory_fsync_failure')
            return original(fd)
        with mock.patch.object(launch.os,'fsync',side_effect=fsync),self.assertRaises((OSError,launch.LaunchError)):self.dispatch(delegate)
        delegate.assert_not_called();rows=self.raw()['launches'];self.assertEqual(len(rows),1);self.assertIn(rows[0]['physical'],('pending','uncertain'));self.assertFalse(rows[0]['private_cleanup'])
    def test_clock_crosses_dispatch_deadline_during_durable_write_no_effect(self):
        delegate=mock.Mock();original=launch._write
        def write(*args):original(*args);self.now[0]=14470.0
        with mock.patch.object(launch,'_write',side_effect=write),self.assertRaises(launch.LaunchError):self.dispatch(delegate)
        delegate.assert_not_called();self.assertEqual(len(self.raw()['launches']),1)
    def test_regressed_clock_before_reservation_poisoned_zero_effect(self):
        delegate=mock.Mock();self.now[0]=99
        with self.assertRaises(launch.LaunchError):self.dispatch(delegate)
        delegate.assert_not_called();self.assertTrue(self.raw()['poisoned']);self.assertEqual(self.raw()['launches'],[])
    def test_nonfinite_or_regressed_clock_at_effect_barrier_never_delegates(self):
        # Fresh disposable ledger per boundary; no state rollback in this test.
        for value in (99.0,float('inf'),float('nan')):
            ledger=launch.LaunchLedger.create(self.root/('clock-'+uuid.uuid4().hex),self.policy,daemon_id='fixture-daemon',daemon_capacity=self.capacity,clock=self.clock,wall=self.wall)
            self.now[0]=100.0;delegate=mock.Mock();original=launch._write
            def write(*args):original(*args);self.now[0]=value
            with mock.patch.object(launch,'_write',side_effect=write),self.assertRaises(launch.LaunchError):ledger.application_dispatch('cell-a',self.record,self.weight,self.daemon,delegate)
            delegate.assert_not_called();self.now[0]=100.0
    def test_delegate_exception_identity_single_charge_and_no_hidden_retry(self):
        failure=RuntimeError('inert_delegate_failure');delegate=mock.Mock(side_effect=failure)
        with self.assertRaises(RuntimeError) as caught:self.dispatch(delegate)
        self.assertIs(caught.exception,failure);self.assertEqual(delegate.call_count,1)
        rows=self.raw()['launches'];self.assertEqual(len(rows),1);self.assertTrue(self.raw()['poisoned']);self.assertEqual(rows[0]['physical'],'uncertain')
        with self.assertRaises(launch.LaunchError):self.dispatch(delegate)
        self.assertEqual(delegate.call_count,1)
    def test_baseexception_identity_is_not_replaced_or_retried(self):
        class Cancelled(BaseException):pass
        failure=Cancelled();delegate=mock.Mock(side_effect=failure)
        with self.assertRaises(Cancelled) as caught:self.dispatch(delegate)
        self.assertIs(caught.exception,failure);self.assertEqual(delegate.call_count,1);self.assertEqual(len(self.raw()['launches']),1);self.assertTrue(self.raw()['poisoned'])
    def test_invalid_returned_pid_cannot_create_a_successful_started_state(self):
        key,_=self.dispatch()
        with self.assertRaises(launch.LaunchError):self.ledger.application_started(key,True)
        row=self.raw()['launches'][0];self.assertIsNone(row['pid']);self.assertEqual(len(self.raw()['launches']),1)
    def test_replaced_named_lock_before_effect_refuses_without_delegate(self):
        original=launch._write;delegate=mock.Mock()
        def write(*args):
            original(*args);path=self.ledger.root/'ledger.lock';path.rename(self.ledger.root/'old-lock');path.write_bytes(b'');path.chmod(0o600)
        with mock.patch.object(launch,'_write',side_effect=write),self.assertRaises(launch.LaunchError):self.dispatch(delegate)
        delegate.assert_not_called();self.assertEqual(len(self.raw()['launches']),1)
    def test_pre_effect_image_resource_and_daemon_refusals_leave_zero_delegates(self):
        delegate=mock.Mock()
        for record,weight,daemon in (({**self.record,'image':'sha256:'+'f'*64},self.weight,self.daemon),(self.record,{**self.weight,'memory_mib':1024},self.daemon),(self.record,self.weight,{**self.daemon,'id':'foreign'})):
            with self.assertRaises(launch.LaunchError):self.ledger.application_dispatch('cell-a',record,weight,daemon,delegate)
        delegate.assert_not_called();self.assertEqual(self.raw()['launches'],[])
    def test_current_registry_drift_after_observation_is_not_cached(self):
        key,_=self.started();original=copy.deepcopy(self.record)
        for field,value in (('image','sha256:'+'f'*64),('generation',str(uuid.uuid4())),('registry','f'*64),('owner_pid',999)):
            changed={**original,field:value};self.registry.write(changed)
            with self.subTest(field=field),self.assertRaises(launch.LaunchError):self.ledger.application_identity(self.guard,self.registry,original,self.observed(original))
            self.registry.write(original)
        self.assertIsNone(self.raw()['launches'][0]['container_id'])
    def test_observed_id_image_labels_extra_mount_and_mount_rw_refused(self):
        directory=self.root/'mount';directory.mkdir(mode=0o700);self.record['mounts']=[{'source':str(directory),'target':'/private','rw':False}];self.registry.write(self.record);self.started();original=self.observed()
        changes=(lambda x:x.update(Id='bad'),lambda x:x.update(Image='sha256:'+'f'*64),lambda x:x['Config']['Labels'].update({launch.LABEL:str(uuid.uuid4())}),
            lambda x:x['Config']['Labels'].update({launch.REGISTRY_LABEL:'f'*64}),lambda x:x['Mounts'].append(dict(x['Mounts'][0])),lambda x:x['Mounts'][0].update(RW=True),
            lambda x:x['Mounts'][0].update(Source=str(self.root/'foreign')),lambda x:x['Mounts'][0].update(Destination='/foreign'))
        for mutate in changes:
            observed=copy.deepcopy(original);mutate(observed)
            with self.assertRaises(launch.LaunchError):self.ledger.application_identity(self.guard,self.registry,self.record,observed)
        self.assertIsNone(self.raw()['launches'][0]['container_id'])
    def test_existing_immutable_cid_cannot_be_overwritten(self):
        self.started();self.ledger.application_identity(self.guard,self.registry,self.record,self.observed())
        with self.assertRaises(launch.LaunchError):self.ledger.application_identity(self.guard,self.registry,self.record,{**self.observed(),'Id':'d'*64})
        self.assertEqual(self.raw()['launches'][0]['container_id'],'c'*64)
    def test_cid_fsync_failure_does_not_report_success_or_allow_private_handoff(self):
        self.started();original=launch.os.fsync
        def fsync(fd):
            if not __import__('stat').S_ISDIR(os.fstat(fd).st_mode):raise OSError('inert_cid_fsync_failure')
            return original(fd)
        with mock.patch.object(launch.os,'fsync',side_effect=fsync),self.assertRaises((OSError,launch.LaunchError)):self.ledger.application_identity(self.guard,self.registry,self.record,self.observed())
        self.assertIsNone(self.raw()['launches'][0]['container_id'])
    def test_each_boundary_reads_fresh_current_state_without_validation_cache(self):
        key,_=self.dispatch();path=self.ledger.root/'ledger.json';raw=self.raw();raw['poisoned']=True;path.write_bytes(launch._json(raw))
        # Start may record an already-issued child, but the poison is monotonic.
        self.ledger.application_started(key,123);self.assertTrue(self.raw()['poisoned'])
        replacement={**self.record,'created_after_first_transaction':True};self.registry.write(replacement)
        with self.assertRaises(launch.LaunchError):self.ledger.application_identity(self.guard,self.registry,self.record,self.observed())
    def helper_argv(self):
        return ['docker','run','--name',self.record['container'],'--platform','linux/arm64','--cpus','1','--memory','512m','--memory-swap','512m','--pids-limit','128',
            '--label',launch.LABEL+'='+self.record['launch_id'],'--label',launch.REGISTRY_LABEL+'='+self.registry.registry_id,'--entrypoint=python3',
            self.record['image'],'/opt/pi-application/runtime/application_client_service.py']
    def helper_command(self,argv):
        if argv[1]=='info':return subprocess.CompletedProcess(argv,0,json.dumps({'ID':'fixture-daemon','NCPU':64,'MemTotal':65536*1048576,'Architecture':'arm64','OSType':'linux'}),'')
        if argv[1:3]==['image','inspect']:return subprocess.CompletedProcess(argv,0,json.dumps([{'Id':self.record['image'],'Architecture':'arm64','Os':'linux'}]),'')
        if argv[1:3]==['container','inspect']:return subprocess.CompletedProcess(argv,0,json.dumps([self.observed()]),'')
        raise AssertionError('unplanned inert observer command')
    def test_full_guard_application_helper_routes_through_one_held_scope(self):
        process=fixtures.Process(123);delegate=mock.Mock(return_value=process)
        guard=launch.LaunchGuard(self.ledger,'cell-a',lambda:self.registry,delegate,self.helper_command)
        with mock.patch.object(self.ledger,'_transaction',wraps=self.ledger._transaction) as transactions:
            returned=guard.popen(self.helper_argv());self.assertIs(returned,process);self.assertEqual(transactions.call_count,0)
        delegate.assert_called_once();self.assertEqual(self.raw()['launches'][0]['container_id'],'c'*64)
    def test_full_guard_late_observed_commit_keeps_original_capture_deadline(self):
        elapsed=[0.0];process=fixtures.Process(123);delegate=mock.Mock(return_value=process)
        def command(argv):
            if argv[1:3]==['container','inspect']:elapsed[0]=5.0
            return self.helper_command(argv)
        guard=launch.LaunchGuard(self.ledger,'cell-a',lambda:self.registry,delegate,command)
        with mock.patch.object(launch.time,'monotonic',side_effect=lambda:elapsed[0]),self.assertRaises(launch.LaunchError) as caught:guard.popen(self.helper_argv())
        self.assertEqual(caught.exception.reason,'qualification_container_id_unconfirmed');delegate.assert_called_once()
        raw=self.raw();self.assertTrue(raw['poisoned']);self.assertEqual(raw['launches'][0]['physical'],'uncertain');self.assertEqual(raw['launches'][0]['container_id'],'c'*64)
    def test_full_guard_refuses_changed_current_registry_before_delegate(self):
        delegate=mock.Mock(return_value=fixtures.Process(123));argv=self.helper_argv();original=copy.deepcopy(self.record)
        guard=launch.LaunchGuard(self.ledger,'cell-a',lambda:self.registry,delegate,self.helper_command)
        for field,value in (('image','sha256:'+'f'*64),('generation',str(uuid.uuid4())),('registry','f'*64),('owner_pid',os.getpid()+1)):
            self.registry.write({**original,field:value})
            with self.subTest(field=field),self.assertRaises(launch.LaunchError):guard.popen(argv)
            self.registry.write(original)
        delegate.assert_not_called();self.assertEqual(self.raw()['launches'],[])
    def test_full_guard_cid_durability_failure_never_returns_to_bootstrap(self):
        delegate=mock.Mock(return_value=fixtures.Process(123));guard=launch.LaunchGuard(self.ledger,'cell-a',lambda:self.registry,delegate,self.helper_command)
        failure=OSError('inert_identity_commit_failure')
        with mock.patch.object(guard,'_capture_held',side_effect=failure),self.assertRaises(OSError) as caught:guard.popen(self.helper_argv())
        self.assertIs(caught.exception,failure);delegate.assert_called_once();self.assertTrue(self.raw()['poisoned']);self.assertIsNone(self.raw()['launches'][0]['container_id'])
    def test_composed_followup_cap262_final_helper_then_denies263(self):
        import test_application_followup as followupfixtures
        fixture=followupfixtures.FollowupTests(methodName='runTest');fixture.setUp();self.addCleanup(fixture.doCleanups);fixture.finish();policy=fixture.full()
        ledger=launch.LaunchLedger.create(fixture.final/'launch-ledger',policy,daemon_id='fixture-daemon',daemon_capacity=fixture.carry['daemon_capacity'],clock=fixture.clock,wall=fixture.wall)
        target=policy['cells'][-1]
        for cell in policy['cells']:
            for role,count in cell['role_limits'].items():
                for _ in range(count):
                    if cell['id']==target['id'] and role=='application-helper':continue
                    image=policy['images']['core-'+cell['release']]['id'] if role in launch.EXTERNAL else cell['image_id'];record=fixture.record(image)
                    key=ledger.reserve(cell['id'],role,record,launch._role_weight(policy,cell,role),fixture.daemon);ledger.note(key,physical='absent',private_cleanup=True)
        self.assertEqual(ledger.snapshot()['attempts'],261)
        record=fixture.record(target['image_id']);weight=launch._role_weight(policy,target,'application-helper');delegate=mock.Mock(return_value='inert-process')
        key,process=ledger.application_dispatch(target['id'],record,weight,fixture.daemon,delegate);self.assertEqual(process,'inert-process');self.assertEqual(ledger.snapshot()['attempts'],262)
        with self.assertRaises(launch.LaunchError) as caught:ledger.application_dispatch(target['id'],fixture.record(target['image_id']),weight,fixture.daemon,delegate)
        self.assertEqual(caught.exception.reason,'qualification_launch_limit');self.assertEqual(delegate.call_count,1)
    def physical_command(self,argv):
        if argv[1]=='info':return self.helper_command(argv)
        if argv[1:3]==['container','inspect']:return subprocess.CompletedProcess(argv,1,'[]','Error: No such container: '+argv[-1])
        raise AssertionError('unplanned lifecycle observer')
    def lifecycle_ready(self,status='intent'):
        self.started();self.ledger.application_identity(self.guard,self.registry,self.record,self.observed())
        self.record.update(container_id='c'*64,status=status);self.registry.write(self.record)
        self.registry.command=self.physical_command
        return launch.LaunchGuard(self.ledger,'cell-a',lambda:self.registry,lambda *a,**kw:None,self.physical_command)
    def test_normal_confirm_and_release_each_one_transaction_one_original_call(self):
        guard=self.lifecycle_ready();confirm=mock.Mock(wraps=ownership_registry.Registry.confirm_absent);release=mock.Mock(wraps=ownership_registry.Registry.release)
        with mock.patch.object(self.ledger,'_transaction',wraps=self.ledger._transaction) as transactions:
            self.assertTrue(self.ledger.application_lifecycle(guard,self.registry,self.record,confirm));self.assertEqual(transactions.call_count,1)
        confirm.assert_called_once_with(self.registry,self.record);self.assertEqual(self.record['status'],'absent');self.assertFalse(self.raw()['launches'][0]['private_cleanup'])
        with mock.patch.object(self.ledger,'_transaction',wraps=self.ledger._transaction) as transactions:
            self.ledger.application_lifecycle(guard,self.registry,self.record,release,release=True,sensitive_clean=True);self.assertEqual(transactions.call_count,1)
        release.assert_called_once_with(self.registry,self.record,True);self.assertEqual(self.record['status'],'released');self.assertTrue(self.raw()['launches'][0]['private_cleanup'])
    def test_lifecycle_unknown_absence_after_original_preserves_false_and_poison(self):
        guard=self.lifecycle_ready()
        def original(registry,record):record['status']='quarantined';registry.write(record);return False
        original=mock.Mock(side_effect=original)
        self.assertFalse(self.ledger.application_lifecycle(guard,self.registry,self.record,original));original.assert_called_once()
        raw=self.raw();self.assertTrue(raw['poisoned']);self.assertEqual(raw['launches'][0]['physical'],'uncertain');self.assertFalse(raw['launches'][0]['private_cleanup'])
    def test_lifecycle_sensitive_false_preserves_original_registry_error_identity(self):
        guard=self.lifecycle_ready('absent');failure=ownership_registry.RegistryError('inert_sensitive_refusal');original=mock.Mock(side_effect=failure)
        with self.assertRaises(ownership_registry.RegistryError) as caught:self.ledger.application_lifecycle(guard,self.registry,self.record,original,release=True,sensitive_clean=False)
        self.assertIs(caught.exception,failure);original.assert_called_once_with(self.registry,self.record,False);self.assertTrue(self.raw()['poisoned']);self.assertFalse(self.raw()['launches'][0]['private_cleanup'])
    def test_lifecycle_after_daemon_drift_denies_and_does_not_mark_private_clean(self):
        guard=self.lifecycle_ready('absent');after=[False]
        def command(argv):
            if argv[1]=='info' and after[0]:return subprocess.CompletedProcess(argv,0,json.dumps({'ID':'foreign','NCPU':64,'MemTotal':65536*1048576,'Architecture':'arm64','OSType':'linux'}),'')
            return self.physical_command(argv)
        guard.command=command
        def original(registry,record,sensitive):record['status']='released';registry.write(record);after[0]=True
        original=mock.Mock(side_effect=original)
        with self.assertRaises(launch.LaunchError):self.ledger.application_lifecycle(guard,self.registry,self.record,original,release=True,sensitive_clean=True)
        original.assert_called_once();self.assertTrue(self.raw()['poisoned']);self.assertFalse(self.raw()['launches'][0]['private_cleanup'])
    def test_lifecycle_before_unknown_id_refuses_without_original_call(self):
        self.started();original=mock.Mock();guard=launch.LaunchGuard(self.ledger,'cell-a',lambda:self.registry,lambda *a,**kw:None,self.physical_command)
        with self.assertRaises(launch.LaunchError):self.ledger.application_lifecycle(guard,self.registry,self.record,original)
        original.assert_not_called();self.assertTrue(self.raw()['poisoned']);self.assertFalse(self.raw()['launches'][0]['private_cleanup'])
    def test_lifecycle_after_current_registry_or_absence_change_is_rechecked(self):
        guard=self.lifecycle_ready('absent')
        def original(registry,record,sensitive):record.update(status='released',image='sha256:'+'f'*64);registry.write(record)
        original=mock.Mock(side_effect=original)
        with self.assertRaises(launch.LaunchError):self.ledger.application_lifecycle(guard,self.registry,self.record,original,release=True,sensitive_clean=True)
        original.assert_called_once();self.assertTrue(self.raw()['poisoned']);self.assertFalse(self.raw()['launches'][0]['private_cleanup'])
    def test_full_guard_registry_change_during_pending_fsync_is_rechecked_before_effect(self):
        delegate=mock.Mock(return_value=fixtures.Process(123));guard=launch.LaunchGuard(self.ledger,'cell-a',lambda:self.registry,delegate,self.helper_command)
        original=launch._write;changed=[False]
        def write(*args):
            original(*args)
            if not changed[0]:changed[0]=True;self.registry.write({**self.record,'owner_pid':os.getpid()+1})
        with mock.patch.object(launch,'_write',side_effect=write),self.assertRaises(launch.LaunchError):guard.popen(self.helper_argv())
        delegate.assert_not_called();self.assertEqual(len(self.raw()['launches']),1);self.assertTrue(self.raw()['poisoned'])
    def test_guard_primary_delegate_error_survives_failed_accounting_note(self):
        primary=RuntimeError('inert_primary_delegate_failure');secondary=RuntimeError('inert_accounting_failure');delegate=mock.Mock(side_effect=primary)
        guard=launch.LaunchGuard(self.ledger,'cell-a',lambda:self.registry,delegate,self.helper_command)
        with mock.patch.object(self.ledger,'note',side_effect=secondary),self.assertRaises(RuntimeError) as caught:guard.popen(self.helper_argv())
        self.assertIs(caught.exception,primary);delegate.assert_called_once();self.assertEqual(len(self.raw()['launches']),1);self.assertFalse(self.raw()['launches'][0]['private_cleanup'])
    def test_old_caps_roles_and_non_application_reserve_route_remain_unchanged(self):
        self.assertEqual(launch.LIMITS,{'global_seconds':14400,'cleanup_reserve_seconds':30,'container_launch_attempts':240,'live':4,'participant_segments':24})
        record=self.newrecord();key=self.ledger.reserve('cell-a','probe',record,{'cpu_millis':1000,'memory_mib':1024,'pids_limit':256},self.daemon)
        self.ledger.dispatch_ready(key);self.assertEqual(self.raw()['launches'][0]['role'],'probe')
        with self.assertRaises(launch.LaunchError):launch._hard_admission(attempts=240,live=0,segments=0,participant=False,now=100,deadline=14500)


class AllPlannedRoleBatchTests(unittest.TestCase):
    """Actual guard routes for worker, browser admission and external services."""
    roles=('probe','browser-check','fixture')
    def environment(self,role):
        env=BatchedLaunchTests(methodName='runTest');env.setUp();self.addCleanup(env.doCleanups)
        if role=='browser-check':
            env.policy=copy.deepcopy(env.policy);cell=env.policy['cells'][0];cell.update(group='N01',image_id=env.policy['images']['browser-0.87.1']['id'])
            env.ledger=launch.LaunchLedger.create(env.root/'browser-ledger',env.policy,daemon_id='fixture-daemon',daemon_capacity=env.capacity,clock=env.clock,wall=env.wall)
        cell=env.policy['cells'][0];weight=launch._role_weight(env.policy,cell,role);record=env.newrecord();record['image']=cell['image_id']
        record['application_helper']=False;record.pop('client_mode');record.pop('private_store');mounts=[]
        if role=='fixture':
            temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);env.service_private=Path(temp.name).resolve()
            observation=env.root/'cells/cell-a/fixture';observation.mkdir(mode=0o700,parents=True)
            record.update(application_helper=True,client_mode='qualification-fixture',qualification_role='fixture',qualification_cell='cell-a',
                binding={'run_id':str(uuid.uuid4()),'attempt_id':str(uuid.uuid4())})
            record['mounts']=[{'source':str(source),'target':target,'rw':rw} for source,target,rw in ((ROOT/'skill','/opt/pi-skill',False),(ROOT/'tools/qualification','/qualification',False),(env.service_private,'/private',False),(observation,'/observations',True))]
            for item in record['mounts']:mounts.extend(['--mount','type=bind,src='+item['source']+',dst='+item['target']+',bind-recursive=disabled'+('' if item['rw'] else ',readonly')])
            command=[launch.EXTERNAL['fixture']]
        else:command=['/opt/pi-lab/worker.py','probe' if role=='probe' else 'browser']
        env.record=record;env.registry.write(record);env.weight=weight;env.absent=False;env.effect_calls=[]
        env.argv=['docker','run','--name',record['container'],'--platform','linux/arm64','--cpus',str(weight['cpu_millis']/1000),'--memory',str(weight['memory_mib'])+'m',
            '--memory-swap',str(weight['memory_mib'])+'m','--pids-limit',str(weight['pids_limit']),'--label',launch.LABEL+'='+record['launch_id'],
            '--label',launch.REGISTRY_LABEL+'='+env.registry.registry_id,'--entrypoint=python3',*mounts,record['image'],*command]
        def command(argv):
            if argv[1]=='info':return subprocess.CompletedProcess(argv,0,json.dumps({'ID':'fixture-daemon','NCPU':64,'MemTotal':65536*1048576,'Architecture':'arm64','OSType':'linux'}),'')
            if argv[1:3]==['image','inspect']:return subprocess.CompletedProcess(argv,0,json.dumps([{'Id':record['image'],'Architecture':'arm64','Os':'linux'}]),'')
            if argv[1:3]==['container','inspect']:
                if env.absent:return subprocess.CompletedProcess(argv,1,'[]','Error: No such container: '+argv[-1])
                return subprocess.CompletedProcess(argv,0,json.dumps([env.observed()]),'')
            raise AssertionError('unplanned mocked role observer')
        env.command=command;env.registry.command=command;env.process=fixtures.Process(123);env.delegate=mock.Mock(return_value=env.process)
        env.guard=launch.LaunchGuard(env.ledger,'cell-a',lambda:env.registry,env.delegate,command)
        return env
    def test_worker_browser_and_fixture_each_use_three_critical_transactions(self):
        for role in self.roles:
            with self.subTest(role=role):
                e=self.environment(role)
                with mock.patch.object(e.ledger,'_transaction',wraps=e.ledger._transaction) as tx:actual=e.guard.popen(e.argv);self.assertEqual(tx.call_count,3)
                self.assertIs(actual,e.process);e.delegate.assert_called_once();row=e.raw()['launches'][0]
                self.assertEqual(row['role'],role);self.assertEqual(row['resources'],e.weight);self.assertEqual(row['container_id'],'c'*64);self.assertEqual(row['pid'],123)
        self.assertEqual(self.environment('browser-check').weight,{'cpu_millis':2000,'memory_mib':2048,'pids_limit':512})
        self.assertEqual(self.environment('fixture').weight,{'cpu_millis':250,'memory_mib':128,'pids_limit':64})
    def test_all_roles_confirm_release_and_direct_absence_are_one_transaction_each(self):
        for role in self.roles:
            with self.subTest(role=role):
                e=self.environment(role);e.guard.popen(e.argv);e.record['container_id']='c'*64;e.registry.write(e.record);e.absent=True
                with launch.instrument(e.ledger,'cell-a',registry_getter=lambda:e.registry,original_popen=e.delegate,command=e.command) as guard:
                    with mock.patch.object(e.ledger,'_transaction',wraps=e.ledger._transaction) as tx:self.assertTrue(e.registry.confirm_absent(e.record));self.assertEqual(tx.call_count,1)
                    self.assertFalse(e.raw()['launches'][0]['private_cleanup'])
                    with mock.patch.object(e.ledger,'_transaction',wraps=e.ledger._transaction) as tx:self.assertIsNone(guard.confirm_physical(e.registry,e.record));self.assertEqual(tx.call_count,1)
                    if role=='fixture':
                        identity=ownership_registry.observe_qualification_private(e.record);e.service_private.rmdir()
                        e.record['qualification_service_cleanup']=ownership_registry.write_qualification_service_cleanup(e.record,e.root/'service-cleanup.json',private_identity=identity,
                            physical_absence_confirmed=True,private_bootstrap_removed=True,terminal_available=False,startup_readied=False)
                        e.registry.write(e.record)
                    with mock.patch.object(e.ledger,'_transaction',wraps=e.ledger._transaction) as tx:e.registry.release(e.record,True);self.assertEqual(tx.call_count,1)
                self.assertEqual(e.record['status'],'released');self.assertTrue(e.raw()['launches'][0]['private_cleanup'])
    def test_all_roles_reject_wrong_resources_before_any_effect(self):
        for role in self.roles:
            with self.subTest(role=role):
                e=self.environment(role);argv=list(e.argv);argv[argv.index('--pids-limit')+1]=str(e.weight['pids_limit']+1)
                with self.assertRaises(launch.LaunchError):e.guard.popen(argv)
                e.delegate.assert_not_called();self.assertEqual(e.raw()['launches'],[])
    def test_all_roles_reject_current_image_owner_label_and_command_class_drift(self):
        for role in self.roles:
            for kind in ('image','owner','label','class'):
                with self.subTest(role=role,kind=kind):
                    e=self.environment(role);argv=list(e.argv)
                    if kind=='image':e.registry.write({**e.record,'image':'sha256:'+'f'*64})
                    elif kind=='owner':e.registry.write({**e.record,'owner_pid':os.getpid()+1})
                    elif kind=='label':argv[argv.index(launch.LABEL+'='+e.record['launch_id'])]=launch.LABEL+'='+str(uuid.uuid4())
                    else:argv[argv.index(e.record['image'])+1]='/unapproved/command.py'
                    with self.assertRaises((OSError,launch.LaunchError)):e.guard.popen(argv)
                    e.delegate.assert_not_called();self.assertEqual(e.raw()['launches'],[])
    def test_fixture_mount_mismatch_is_refused_before_effect(self):
        e=self.environment('fixture');argv=list(e.argv);i=argv.index('--mount')+1;argv[i]=argv[i].replace('dst=/opt/pi-skill','dst=/unexpected')
        with self.assertRaises(launch.LaunchError):e.guard.popen(argv)
        e.delegate.assert_not_called();self.assertEqual(e.raw()['launches'],[])
    def test_all_roles_delegate_error_keeps_exact_exception_and_one_charged_intent(self):
        for role in self.roles:
            with self.subTest(role=role):
                e=self.environment(role);failure=RuntimeError('inert_role_delegate_failure');e.delegate.side_effect=failure
                with self.assertRaises(RuntimeError) as caught:e.guard.popen(e.argv)
                self.assertIs(caught.exception,failure);e.delegate.assert_called_once();self.assertEqual(len(e.raw()['launches']),1)
                self.assertTrue(e.raw()['poisoned']);self.assertEqual(e.raw()['launches'][0]['physical'],'uncertain')
    def test_all_roles_file_durability_failure_blocks_delegate(self):
        for role in self.roles:
            with self.subTest(role=role):
                e=self.environment(role);original=launch.os.fsync
                def fsync(fd):
                    if not __import__('stat').S_ISDIR(os.fstat(fd).st_mode):raise OSError('inert_role_durability_failure')
                    return original(fd)
                with mock.patch.object(launch.os,'fsync',side_effect=fsync),self.assertRaises((OSError,launch.LaunchError)):e.guard.popen(e.argv)
                e.delegate.assert_not_called();self.assertEqual(e.raw()['launches'],[])
    def test_all_roles_post_fsync_deadline_crossing_is_not_reset(self):
        for role in self.roles:
            with self.subTest(role=role):
                e=self.environment(role);original=launch._write
                def write(*args):original(*args);e.now[0]=14470.0
                with mock.patch.object(launch,'_write',side_effect=write),self.assertRaises(launch.LaunchError):e.guard.popen(e.argv)
                e.delegate.assert_not_called();self.assertEqual(len(e.raw()['launches']),1)
    def test_all_roles_original_capture_timeout_still_refuses_late_identity(self):
        for role in self.roles:
            with self.subTest(role=role):
                e=self.environment(role);elapsed=[0.0];original=e.command
                def command(argv):
                    if argv[1:3]==['container','inspect']:elapsed[0]=5.0
                    return original(argv)
                e.guard.command=command
                with mock.patch.object(launch.time,'monotonic',side_effect=lambda:elapsed[0]),self.assertRaises(launch.LaunchError):e.guard.popen(e.argv)
                e.delegate.assert_called_once();self.assertTrue(e.raw()['poisoned']);self.assertEqual(e.raw()['launches'][0]['physical'],'uncertain')
    def test_all_roles_identity_mismatch_retains_one_charge_without_success(self):
        for role in self.roles:
            with self.subTest(role=role):
                e=self.environment(role);original=e.command
                def command(argv):
                    if argv[1:3]==['container','inspect']:
                        observed=e.observed();observed['Config']['Labels'][launch.LABEL]=str(uuid.uuid4());return subprocess.CompletedProcess(argv,0,json.dumps([observed]),'')
                    return original(argv)
                e.guard.command=command
                with self.assertRaises(launch.LaunchError):e.guard.popen(e.argv)
                e.delegate.assert_called_once();self.assertEqual(len(e.raw()['launches']),1);self.assertTrue(e.raw()['poisoned'])
    def test_all_roles_sensitive_cleanup_refusal_preserves_poison_and_private_pending(self):
        for role in self.roles:
            with self.subTest(role=role):
                e=self.environment(role);e.guard.popen(e.argv);e.record.update(container_id='c'*64,status='absent');e.registry.write(e.record);e.absent=True
                original=mock.Mock(wraps=ownership_registry.Registry.release)
                with self.assertRaises(ownership_registry.RegistryError):e.ledger.application_lifecycle(e.guard,e.registry,e.record,original,release=True,sensitive_clean=False)
                original.assert_called_once_with(e.registry,e.record,False);self.assertTrue(e.raw()['poisoned']);self.assertFalse(e.raw()['launches'][0]['private_cleanup'])
    def test_all_roles_unknown_confirmation_retains_false_result_and_uncertainty(self):
        for role in self.roles:
            with self.subTest(role=role):
                e=self.environment(role);e.guard.popen(e.argv);e.record['container_id']='c'*64;e.registry.write(e.record);e.absent=True
                def original(registry,record):record['status']='quarantined';registry.write(record);return False
                original=mock.Mock(side_effect=original)
                self.assertFalse(e.ledger.application_lifecycle(e.guard,e.registry,e.record,original));original.assert_called_once_with(e.registry,e.record)
                row=e.raw()['launches'][0];self.assertEqual(row['physical'],'uncertain');self.assertTrue(e.raw()['poisoned']);self.assertFalse(row['private_cleanup'])
    def test_all_roles_poison_is_refused_before_any_docker_metadata(self):
        for role in self.roles:
            with self.subTest(role=role):
                e=self.environment(role);state=e.raw();state['poisoned']=True;(e.ledger.root/'ledger.json').write_bytes(launch._json(state))
                observer=mock.Mock(side_effect=AssertionError('poison_must_refuse_before_metadata'));e.guard.command=observer
                with self.assertRaises(launch.LaunchError) as caught:e.guard.popen(e.argv)
                self.assertEqual(caught.exception.reason,'qualification_accounting_unavailable');observer.assert_not_called();e.delegate.assert_not_called()
    def test_early_refusal_rejects_nonbool_flag_and_insecure_metadata_without_observer(self):
        for bad in (0,1,None,'false'):
            with self.subTest(flag=bad):
                e=self.environment('probe');state=e.raw();state['poisoned']=bad;(e.ledger.root/'ledger.json').write_bytes(launch._json(state));observer=mock.Mock();e.guard.command=observer
                with self.assertRaises(launch.LaunchError):e.guard.popen(e.argv)
                observer.assert_not_called();e.delegate.assert_not_called()
        e=self.environment('probe');(e.ledger.root/'ledger.json').chmod(0o666);observer=mock.Mock();e.guard.command=observer
        with self.assertRaises(launch.LaunchError):e.guard.popen(e.argv)
        observer.assert_not_called();e.delegate.assert_not_called()
    def test_early_refusal_rejects_replaced_ledger_root_identity(self):
        e=self.environment('probe');old=e.ledger.root;old.rename(e.root/'original-ledger');old.mkdir(mode=0o700);observer=mock.Mock();e.guard.command=observer
        with self.assertRaises(launch.LaunchError):e.guard.popen(e.argv)
        observer.assert_not_called();e.delegate.assert_not_called()
    def test_false_flag_is_not_admission_and_never_caches_full_validation(self):
        e=self.environment('probe');self.assertIsNone(e.ledger.refuse_poisoned());state=e.raw();state['manifest_sha256']='f'*64
        (e.ledger.root/'ledger.json').write_bytes(launch._json(state));observer=mock.Mock(wraps=e.command);e.guard.command=observer
        with self.assertRaises(launch.LaunchError):e.guard.popen(e.argv)
        e.delegate.assert_not_called();self.assertGreater(observer.call_count,0);self.assertEqual(e.raw()['launches'],[])
    def test_untracked_record_preserves_original_passthrough_result_and_one_call(self):
        e=self.environment('probe');untracked=e.newrecord();result=object();original=mock.Mock(return_value=result)
        with mock.patch.object(e.ledger,'_transaction',wraps=e.ledger._transaction) as tx:
            self.assertIs(e.ledger.application_lifecycle(e.guard,e.registry,untracked,original),result);self.assertEqual(tx.call_count,1)
        original.assert_called_once_with(e.registry,untracked);self.assertEqual(e.raw()['launches'],[])




class HeldStartupTests(unittest.TestCase):
    def setUp(self):
        self.e=BatchedLaunchTests(methodName='runTest');self.e.setUp();self.addCleanup(self.e.doCleanups)
    def startup(self,delegate=None,capture=None,before_delegate=None):
        e=self.e
        def observe(state,process,remaining):
            self.assertEqual(e.raw()['launches'][0]['pid'],process.pid)
            key=e.guard._owned_key_state(state,e.record,e.registry)
            self.assertIsNotNone(key)
            row=next(r for r in state['launches'] if r['key']==key)
            return e.guard._verify_owned_observation(e.record,row,e.observed()),time.monotonic()+5
        return e.ledger.application_startup('cell-a',e.record,e.weight,e.daemon,delegate or (lambda key:fixtures.Process(123)),capture or observe,before_delegate=before_delegate)
    def test_durable_pending_pid_cid_and_three_live_full_validations(self):
        e=self.e;valid=e.ledger._validate;events=[]
        def validate(state):events.append('full');return valid(state)
        def delegate(key):
            raw=e.raw();self.assertEqual(raw['launches'][0]['physical'],'pending');self.assertIsNone(raw['launches'][0]['pid'])
            events.append('delegate');return fixtures.Process(123)
        with mock.patch.object(e.ledger,'_validate',side_effect=validate):self.startup(delegate)
        self.assertEqual(events,['full','full','delegate','full']);row=e.raw()['launches'][0]
        self.assertEqual((row['pid'],row['container_id'],row['physical']),(123,'c'*64,'started'))
        self.assertFalse(hasattr(e.ledger,'_prevalidated_carry'))
    def test_each_checkpoint_write_failure_prevents_readiness_without_retry(self):
        for failed_checkpoint in (1,2,3):
            e=BatchedLaunchTests(methodName='runTest');e.setUp();self.addCleanup(e.doCleanups)
            old=self.e;self.e=e;original=launch._write;calls=[0];failure=OSError('inert_checkpoint');delegate=mock.Mock(return_value=fixtures.Process(123))
            def write(*args):
                calls[0]+=1
                if calls[0]==failed_checkpoint:raise failure
                return original(*args)
            with mock.patch.object(launch,'_write',side_effect=write),self.assertRaises(OSError) as caught:self.startup(delegate)
            self.assertIs(caught.exception,failure);self.assertEqual(delegate.call_count,0 if failed_checkpoint==1 else 1)
            rows=e.raw()['launches'];self.assertLessEqual(len(rows),1)
            if rows:self.assertTrue(e.raw()['poisoned']);self.assertFalse(rows[0]['private_cleanup'])
            self.e=old
    def test_delegate_exception_and_cancellation_identity_survive_local_accounting(self):
        class Cancelled(BaseException):pass
        for failure in (RuntimeError('inert_delegate'),Cancelled()):
            e=BatchedLaunchTests(methodName='runTest');e.setUp();self.addCleanup(e.doCleanups);old=self.e;self.e=e
            delegate=mock.Mock(side_effect=failure)
            with self.assertRaises(type(failure)) as caught:self.startup(delegate)
            self.assertIs(caught.exception,failure);delegate.assert_called_once();self.assertTrue(e.raw()['poisoned'])
            self.e=old
    def test_post_capture_full_validation_failure_preserves_durable_pid_and_cid(self):
        e=self.e;original=e.ledger._validate;calls=[0];failure=RuntimeError('inert_changed_history')
        def validate(state):
            calls[0]+=1
            if calls[0]==3:raise failure
            return original(state)
        with mock.patch.object(e.ledger,'_validate',side_effect=validate),self.assertRaises(RuntimeError) as caught:self.startup()
        self.assertIs(caught.exception,failure);row=e.raw()['launches'][0]
        self.assertEqual((row['pid'],row['container_id']),(123,'c'*64));self.assertTrue(e.raw()['poisoned']);self.assertEqual(row['physical'],'uncertain')
    def test_regressed_clock_pre_effect_has_zero_delegate_calls(self):
        e=self.e;e.now[0]=99;delegate=mock.Mock()
        with self.assertRaises(launch.LaunchError):self.startup(delegate)
        delegate.assert_not_called();self.assertTrue(e.raw()['poisoned']);self.assertEqual(e.raw()['launches'],[])
    def test_late_post_capture_keeps_five_second_refusal_and_durable_cid(self):
        def capture(state,process,remaining):return 'c'*64,time.monotonic()-1
        with self.assertRaises(launch.LaunchError) as caught:self.startup(capture=capture)
        self.assertEqual(caught.exception.reason,'qualification_container_id_unconfirmed')
        self.assertEqual(self.e.raw()['launches'][0]['container_id'],'c'*64);self.assertTrue(self.e.raw()['poisoned'])
    def test_second_call_does_not_reuse_scoped_full_validation(self):
        e=self.e;original=e.ledger._validate;calls=[]
        def validate(state):calls.append(1);return original(state)
        with mock.patch.object(e.ledger,'_validate',side_effect=validate):
            self.startup()
            with self.assertRaises(launch.LaunchError):self.startup()
        self.assertEqual(len(calls),4);self.assertFalse(hasattr(e.ledger,'_prevalidated_carry'))
    def test_real_second_process_is_blocked_through_pid_and_cid_capture(self):
        # POSIX fork inherits this inert candidate module for draft execution;
        # the test creates no Docker process and never alters the held source.
        e=self.e;context=multiprocessing.get_context('fork');events=context.Queue();release=context.Event()
        def first():
            ledger=launch.LaunchLedger(e.ledger.root,e.policy,clock=e.clock,wall=e.wall)
            def capture(state,process,remaining):
                events.put(('A','pid_durable',json.loads((e.ledger.root/'ledger.json').read_text())['launches'][0]['pid']))
                if not release.wait(5):raise RuntimeError('inert_release_missing')
                return 'c'*64,time.monotonic()+5
            ledger.application_startup('cell-a',e.record,e.weight,e.daemon,lambda key:fixtures.Process(123),capture)
            events.put(('A','ready'))
        def second():
            events.put(('B','attempting'))
            ledger=launch.LaunchLedger(e.ledger.root,e.policy,clock=e.clock,wall=e.wall)
            try:ledger.application_dispatch('cell-a',e.newrecord(),e.weight,e.daemon,lambda key:events.put(('B','effect')))
            except launch.LaunchError as error:events.put(('B','denied',error.reason))
        children=[]
        try:
            a=context.Process(target=first);a.start();children.append(a);self.assertEqual(events.get(timeout=5),('A','pid_durable',123))
            b=context.Process(target=second);b.start();children.append(b);self.assertEqual(events.get(timeout=5),('B','attempting'))
            fd=os.open(e.ledger.root/'ledger.lock',os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally:os.close(fd)
            release.set();observed=[events.get(timeout=5),events.get(timeout=5)]
            self.assertIn(('A','ready'),observed);self.assertIn(('B','denied','qualification_role_limit'),observed)
            for child in children:child.join(5);self.assertFalse(child.is_alive());self.assertEqual(child.exitcode,0)
            self.assertEqual(len(e.raw()['launches']),1);self.assertEqual(e.raw()['launches'][0]['container_id'],'c'*64)
        finally:
            release.set()
            for child in children:
                if child.is_alive():child.terminate()
                child.join(3)
            events.close();events.join_thread()
    def campaign_scope(self):
        e=self.e;descriptor={'schema':1,'root':str(e.root/'old'),'manifest_sha256':'1'*64,'state_sha256':'2'*64,'ledger_sha256':'3'*64,
            'cleanup_receipts':[{'path':str(e.root/'old-cleanup.json'),'sha256':'4'*64}]}
        e.ledger.manifest['predecessor']=descriptor
        carry={'attempts':0,'participant_segments':0,'qualification_id':str(uuid.uuid4()),'planned_cells':28,'prior_rows':[],
            **{k:e.raw()[k] for k in ('started','deadline','started_wall','deadline_wall')},'daemon_capacity':e.capacity}
        raw=e.raw();raw['manifest_sha256']=launch._digest(e.ledger.manifest)
        raw['carry']={'descriptor_sha256':launch._digest(descriptor),**{k:carry[k] for k in ('attempts','participant_segments','qualification_id','planned_cells')}}
        folder=launch._dir(e.ledger.root)
        try:launch._write(folder,'ledger.json',raw)
        finally:os.close(folder)
        return carry
    def test_campaign_scope_rereads_carry_three_times_and_local_states_never_recurse(self):
        e=self.e;carry=self.campaign_scope()
        with mock.patch.object(launch,'_effective_carry',side_effect=lambda *a,**kw:copy.deepcopy(carry)) as fresh,mock.patch.object(launch,'_successor_claim'):
            self.startup()
        self.assertEqual(fresh.call_count,3);self.assertFalse(hasattr(e.ledger,'_prevalidated_carry'))
    def test_authority_drift_in_before_delegate_has_zero_effects_and_charged_poison(self):
        e=self.e;carry=self.campaign_scope();authority=e.root/'retained-authority.json';authority.write_text('original')
        expected=hashlib.sha256(authority.read_bytes()).hexdigest();delegate=mock.Mock()
        def fresh(*args,**kwargs):
            if hashlib.sha256(authority.read_bytes()).hexdigest()!=expected:raise launch.LaunchError('qualification_contract_invalid')
            return copy.deepcopy(carry)
        def drift():authority.write_text('changed after durable pending and Registry callback')
        with mock.patch.object(launch,'_effective_carry',side_effect=fresh) as observed,mock.patch.object(launch,'_successor_claim'),self.assertRaises(launch.LaunchError):
            self.startup(delegate,before_delegate=drift)
        self.assertEqual(observed.call_count,2);delegate.assert_not_called()
        raw=e.raw();self.assertEqual(len(raw['launches']),1);self.assertTrue(raw['poisoned']);self.assertIsNone(raw['launches'][0]['pid'])
    def test_real_file_fsync_failure_prevents_helper_delegate(self):
        original=launch.os.fsync;delegate=mock.Mock()
        def fsync(fd):
            if not __import__('stat').S_ISDIR(os.fstat(fd).st_mode):raise OSError('inert_actual_file_fsync')
            return original(fd)
        with mock.patch.object(launch.os,'fsync',side_effect=fsync),self.assertRaises(OSError):self.startup(delegate)
        delegate.assert_not_called();self.assertEqual(self.e.raw()['launches'],[])
    def test_real_directory_fsync_failure_charges_one_helper_without_delegate(self):
        original=launch.os.fsync;delegate=mock.Mock()
        def fsync(fd):
            if __import__('stat').S_ISDIR(os.fstat(fd).st_mode):raise OSError('inert_actual_directory_fsync')
            return original(fd)
        with mock.patch.object(launch.os,'fsync',side_effect=fsync),self.assertRaises(OSError):self.startup(delegate)
        delegate.assert_not_called();self.assertEqual(len(self.e.raw()['launches']),1);self.assertFalse(self.e.raw()['launches'][0]['private_cleanup'])

if __name__=='__main__':unittest.main()
