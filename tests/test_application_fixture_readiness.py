"""Offline owner-private fixture readiness: inert Docker and disposable stores.

Localhost FixtureServer threads are the only live service; no Docker, Pi, model,
external endpoint, original operation lease, global Registry or real keys.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/qualification'),str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import test_application_service_cleanup as inert
import secret_store

qualifier=inert.qualifier
fixture_path=ROOT/'skill/examples/authenticated-application/fixture.py'
spec=importlib.util.spec_from_file_location('readiness_example_fixture',fixture_path)
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
FAKE_A='readiness-disposable-alice-185730945'
FAKE_B='readiness-disposable-bob-670492183'
REFUSALS=(qualifier.QualificationError,ValueError,OSError)


class FixtureReadinessPublicationTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.store=self.root/'FAKE-store'
        secret_store.write_secret('TEST_ALICE',FAKE_A,self.store);secret_store.write_secret('TEST_BOB',FAKE_B,self.store)
        self.nonce=str(uuid.uuid4());self.server=None
        self.addCleanup(self.close_server)

    def close_server(self):
        if self.server is not None and not self.server.closed:self.server.stop()

    def build(self,nonce=True):
        self.server=fixture.FixtureServer.from_store(self.root/'journal',alice_reference='TEST_ALICE',bob_reference='TEST_BOB',secrets_dir=self.store,readiness_id=self.nonce if nonce else None,host='127.0.0.1',port=0)
        return self.server

    def test_private_ready_receipt_only_after_thread_start_and_stopped_before_terminal(self):
        server=self.build();path=server.root/'readiness.json';self.assertFalse(path.exists());events=[]
        write=server._write;start=threading.Thread.start
        def started(thread,*args,**kwargs):
            self.assertFalse(path.exists());events.append('thread_start');return start(thread,*args,**kwargs)
        def written(name,value):
            if name=='readiness.json':
                self.assertTrue(server.thread.is_alive()or value['state']=='stopped');events.append(value['state'])
            if name=='terminal-receipt.json':events.append('terminal')
            return write(name,value)
        with mock.patch.object(threading.Thread,'start',new=started),mock.patch.object(server,'_write',side_effect=written):
            server.start();ready=json.loads(path.read_bytes())
            self.assertEqual(ready,{'schema':1,'document_type':'application_fixture_readiness','fixture_id':server.journal['fixture_id'],'readiness_id':self.nonce,'state':'ready','port':server.server.server_port})
            info=path.lstat();self.assertEqual(stat.S_IMODE(info.st_mode),0o600);self.assertEqual(info.st_nlink,1)
            self.assertNotIn(FAKE_A,path.read_text());self.assertNotIn(FAKE_B,path.read_text())
            server.stop()
        self.assertEqual(events,['thread_start','ready','stopped','terminal'])
        self.assertEqual(json.loads(path.read_bytes())['state'],'stopped');self.assertFalse(server.thread.is_alive())
        self.assertEqual(server.server.fileno(),-1)

    def test_legacy_optional_nonce_does_not_publish_readiness(self):
        server=self.build(nonce=False);server.start();self.assertFalse((server.root/'readiness.json').exists());server.stop()
        self.assertFalse((server.root/'readiness.json').exists())

    def test_non_uuid_readiness_id_refuses_bootstrap(self):
        with self.assertRaises(ValueError):fixture.FixtureServer(self.root/'invalid',{'alice':FAKE_A,'bob':FAKE_B},readiness_id='not-a-uuid')

    def test_failed_ready_publication_closes_thread_and_socket_preserves_primary(self):
        server=self.build();original=server._write;primary=OSError('FAKE_ready_write_failed')
        def write(name,value):
            if name=='readiness.json'and value['state']=='ready':raise primary
            return original(name,value)
        with mock.patch.object(server,'_write',side_effect=write),self.assertRaises(OSError)as caught:server.start()
        self.assertIs(caught.exception,primary);self.assertFalse(server.thread.is_alive());self.assertEqual(server.server.fileno(),-1);self.assertTrue(server.closed);self.assertEqual(server._keys,{})


    def test_stopped_readiness_write_failure_closes_resources_without_terminal_success(self):
        server=self.build();server.start();write=server._write;primary=OSError('FAKE_stopped_write_failed')
        def changed(name,value):
            if name=='readiness.json'and value['state']=='stopped':raise primary
            return write(name,value)
        with mock.patch.object(server,'_write',side_effect=changed),self.assertRaises(OSError)as caught:server.stop()
        self.assertIs(caught.exception,primary);self.assertTrue(server.closed);self.assertFalse(server.thread.is_alive());self.assertEqual(server.server.fileno(),-1);self.assertEqual(server._keys,{})
        self.assertFalse((server.root/'terminal-receipt.json').exists())
        with self.assertRaises(OSError):os.fstat(server._directory)


class FixtureReadinessConsumerTests(unittest.TestCase):
    def setUp(self):
        self.case=inert.ServiceCleanupTests(methodName='runTest');self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.owner=self.case.owner;self.record=self.owner.items[0][0]
        self.observations=self.owner.folder/'new-fixture-observations';self.observations.mkdir(mode=0o700);self.private=self.observations/'private';self.private.mkdir(mode=0o700)
        info=self.private.stat();self.nonce=str(uuid.uuid4());self.fixture_id=str(uuid.uuid4())
        state=self.owner.service_states[self.record['launch_id']]
        wrapper=self.observations.stat();state.update(observations=self.observations,readiness_id=self.nonce,readiness_root_identity=(info.st_dev,info.st_ino),readiness_wrapper_identity=(wrapper.st_dev,wrapper.st_ino))
        self.ready={'schema':1,'document_type':'application_fixture_readiness','fixture_id':self.fixture_id,'readiness_id':self.nonce,'state':'ready','port':8080}
        self.journal={'schema':1,'document_type':'application_fixture_journal','fixture_id':self.fixture_id,'application_id':'diagnostic-app','tenant_id':'team-1','requests':[],'pages':[],'publications':[],'closed':False}
        self.write_receipts()

    def put(self,name,value):
        path=self.private/name
        if path.exists():path.chmod(0o600)
        path.write_bytes((json.dumps(value,allow_nan=False)+'\n').encode());path.chmod(0o600);return path

    def write_receipts(self):self.put('readiness.json',self.ready);self.put('journal.json',self.journal)
    def read_ready(self,deadline=None):return self.owner._fixture_ready(self.record,self.observations,self.case.fixture.now[0]+15 if deadline is None else deadline)

    def test_exact_owner_receipt_and_initial_journal_ready(self):self.assertTrue(self.read_ready())

    def test_only_missing_readiness_is_pending(self):
        (self.private/'readiness.json').unlink();self.assertFalse(self.read_ready())

    def test_missing_journal_with_present_readiness_refuses(self):
        (self.private/'journal.json').unlink()
        with self.assertRaises(REFUSALS):self.read_ready()

    def test_bad_ready_schema_nonce_state_id_or_port_fail_closed(self):
        changes=[{'schema':True},{'schema':2},{'readiness_id':str(uuid.uuid4())},{'fixture_id':'invalid'},{'state':'stopped'},{'state':'starting'},{'port':8081},{'port':True},{'unexpected':'value'}]
        for change in changes:
            with self.subTest(change=change):
                self.put('readiness.json',{**self.ready,**change})
                with self.assertRaises(REFUSALS):self.read_ready()
        self.put('readiness.json',self.ready)

    def test_non_initial_wrong_fixture_or_closed_journal_refuses(self):
        changes=[{'fixture_id':str(uuid.uuid4())},{'schema':True},{'closed':True},{'requests':[{}]},{'pages':[{}]},{'publications':[{}]},{'application_id':'other'},{'tenant_id':'other'},{'unexpected':1}]
        for change in changes:
            with self.subTest(change=change):
                self.put('journal.json',{**self.journal,**change})
                with self.assertRaises(REFUSALS):self.read_ready()

    def test_duplicate_nonfinite_and_malformed_json_refuse(self):
        for name in ('readiness.json','journal.json'):
            for body in (b'{"schema":1,"schema":1}',b'{"value":NaN}',b'{"value":Infinity}',b'{malformed'):
                with self.subTest(name=name,body=body):
                    self.write_receipts();(self.private/name).write_bytes(body)
                    with self.assertRaises(REFUSALS):self.read_ready()

    def test_bounded_ready_and_journal_files_refuse_oversize(self):
        for name,maximum in (('readiness.json',4096),('journal.json',262144)):
            with self.subTest(name=name):
                self.write_receipts();(self.private/name).write_bytes(b' '*(maximum+1))
                with self.assertRaises(REFUSALS):self.read_ready()

    def test_both_leaf_modes_must_be_exact_0600(self):
        for name in ('readiness.json','journal.json'):
            for mode in (0o400,0o644):
                with self.subTest(name=name,mode=mode):
                    self.write_receipts();(self.private/name).chmod(mode)
                    with self.assertRaises(REFUSALS):self.read_ready()

    def test_leaf_symlink_never_followed(self):
        for name in ('readiness.json','journal.json'):
            with self.subTest(name=name):
                self.write_receipts();leaf=self.private/name;target=self.observations/(name+'.external');target.write_bytes(leaf.read_bytes());target.chmod(0o600);leaf.unlink();leaf.symlink_to(target)
                with self.assertRaises(REFUSALS):self.read_ready()
                leaf.unlink()

    def test_leaf_hardlinks_refuse(self):
        for name in ('readiness.json','journal.json'):
            with self.subTest(name=name):
                self.write_receipts();alias=self.observations/(name+'.hardlink');os.link(self.private/name,alias)
                try:
                    with self.assertRaises(REFUSALS):self.read_ready()
                finally:alias.unlink()

    def test_private_directory_replacement_and_symlink_refuse(self):
        original=self.private.with_name('private-original');self.private.rename(original);self.private.mkdir(mode=0o700);self.write_receipts()
        with self.assertRaises(REFUSALS):self.read_ready()
        for leaf in self.private.iterdir():leaf.unlink()
        self.private.rmdir();self.private.symlink_to(original,target_is_directory=True)
        with self.assertRaises(REFUSALS):self.read_ready()

    def test_private_directory_mode_change_refuses(self):
        self.private.chmod(0o755)
        with self.assertRaises(REFUSALS):self.read_ready()

    def test_observation_wrapper_mode_change_refuses(self):
        self.observations.chmod(0o755)
        with self.assertRaises(REFUSALS):self.read_ready()

    def test_wrong_leaf_uid_refuses(self):
        leaf_inode=(self.private/'readiness.json').stat().st_ino;original=os.fstat
        def changed(fd):
            info=original(fd)
            if info.st_ino!=leaf_inode:return info
            values={name:getattr(info,name)for name in dir(info)if name.startswith('st_')};values['st_uid']=os.getuid()+1;return SimpleNamespace(**values)
        with mock.patch.object(qualifier.os,'fstat',side_effect=changed),self.assertRaises(REFUSALS):self.read_ready()

    def test_expired_receipt_deadline_refuses(self):
        with self.assertRaises(REFUSALS):self.read_ready(self.case.fixture.now[0])

    def test_receipt_becomes_late_during_read_refuses(self):
        deadline=self.case.fixture.now[0]+1;original=os.read;calls=[]
        def late(fd,count):
            body=original(fd,count);calls.append(fd);self.case.backend.advance(2);return body
        with mock.patch.object(qualifier.os,'read',side_effect=late),self.assertRaises(REFUSALS):self.read_ready(deadline)
        self.assertTrue(calls)

    def test_leaf_changes_while_reading_refuses(self):
        original=os.read;leaf=self.private/'readiness.json';changed=[]
        def drift(fd,count):
            body=original(fd,count)
            if not changed:changed.append(True);leaf.write_bytes(json.dumps(self.ready).encode()+b'  ');leaf.chmod(0o600)
            return body
        with mock.patch.object(qualifier.os,'read',side_effect=drift),self.assertRaises(REFUSALS):self.read_ready()
        self.assertTrue(changed)

    def test_wrapper_replacement_during_read_refuses(self):
        original=os.read;replaced=[];old=self.observations.with_name('old-wrapper')
        def drift(fd,count):
            body=original(fd,count)
            if not replaced:
                replaced.append(True);self.observations.rename(old);self.observations.mkdir(mode=0o700);self.private.mkdir(mode=0o700);self.write_receipts()
            return body
        with mock.patch.object(qualifier.os,'read',side_effect=drift),self.assertRaises(REFUSALS):self.read_ready()
        self.assertTrue(replaced)

    def await_ready(self):
        self.owner.manifest={'images':self.case.fixture.policy['images'],'fixture_route':{'publish_host':'127.0.0.1'}};self.owner.cell.update(release='0.87.1',group='N02')
        observed=self.case.backend.objects[self.record['container']]
        observed['HostConfig']={'NanoCpus':250000000,'Memory':134217728,'MemorySwap':134217728,'PidsLimit':64}
        original=qualifier.lab.command
        def command(argv,**kwargs):
            if argv==['FAKE_ALREADY_STARTED']:return subprocess.CompletedProcess(argv,0,'','')
            return original(argv,**kwargs)
        with mock.patch.object(qualifier.lab,'command',side_effect=command):return self.owner._await_ready(self.record,self.record['container'],'fixture',self.observations,['FAKE_ALREADY_STARTED'],self.record['image'])

    def test_slow_fresh_history_blocks_old_logs_but_ready_receipt_uses_no_logs(self):
        self.case.validation_hook=lambda state:self.case.backend.advance(2)
        with self.assertRaises(inert.launch.LaunchError)as caught:self.owner._logs(self.record['container_id'],3,self.record)
        self.assertEqual(caught.exception.reason,'qualification_deadline');self.assertEqual(self.case.validations,2)
        self.assertFalse([a for a in self.case.backend.commands if a[1]=='logs'])
        with mock.patch.object(self.owner,'_logs',side_effect=AssertionError('Readiness must not depend on3s diagnostic logs'))as logs:self.await_ready()
        logs.assert_not_called();self.assertTrue(self.owner.service_states[self.record['launch_id']]['ready'])

    def test_valid_receipt_cannot_bypass_fresh_Docker_resource_checks(self):
        self.owner.manifest={'images':self.case.fixture.policy['images'],'fixture_route':{'publish_host':'127.0.0.1'}};self.owner.cell.update(release='0.87.1',group='N02')
        observed=self.case.backend.objects[self.record['container_id']];observed['HostConfig']={'NanoCpus':250000000,'Memory':1,'MemorySwap':134217728,'PidsLimit':64}
        original=qualifier.lab.command
        def command(argv,**kwargs):return subprocess.CompletedProcess(argv,0,'','')if argv==['FAKE_ALREADY_STARTED']else original(argv,**kwargs)
        with mock.patch.object(qualifier.lab,'command',side_effect=command),mock.patch.object(self.owner,'_fixture_ready',wraps=self.owner._fixture_ready)as receipt,self.assertRaises(qualifier.QualificationError):self.owner._await_ready(self.record,self.record['container'],'fixture',self.observations,['FAKE_ALREADY_STARTED'],self.record['image'])
        receipt.assert_not_called()

    def test_null_registry_cid_cannot_adopt_foreign_cid_over_captured_ledger_identity(self):
        captured=self.record['container_id'];row=next(row for row in self.case.raw()['launches']if row['launch_id']==self.record['launch_id'])
        self.assertEqual(row['container_id'],captured)
        self.record['container_id']=None;self.case.registry.write(self.record)
        self.case.backend.objects[self.record['container']]['Id']='f'*64
        with mock.patch.object(self.owner,'_fixture_ready',wraps=self.owner._fixture_ready)as receipt,mock.patch.object(self.case.registry,'write',wraps=self.case.registry.write)as write,self.assertRaises(inert.launch.LaunchError):
            self.await_ready()
        receipt.assert_not_called();write.assert_not_called();self.assertIsNone(self.record['container_id'])
        self.assertEqual(next(row for row in self.case.raw()['launches']if row['launch_id']==self.record['launch_id'])['container_id'],captured)

    def test_valid_receipt_cannot_bypass_changed_daemon(self):
        delegate=self.case.guard.original_popen
        def foreign_daemon(argv,**kwargs):
            child=delegate(argv,**kwargs)
            if argv[1:2]==['info']:
                body=json.loads(child.reply.stdout);body['ID']='foreign-daemon';child.reply.stdout=json.dumps(body)
            return child
        self.case.guard.original_popen=foreign_daemon
        with mock.patch.object(self.owner,'_fixture_ready',wraps=self.owner._fixture_ready)as receipt,mock.patch.object(self.case.registry,'write',wraps=self.case.registry.write)as write,self.assertRaises(inert.launch.LaunchError)as caught:
            self.await_ready()
        self.assertEqual(caught.exception.reason,'qualification_daemon_changed');receipt.assert_not_called();write.assert_not_called()

    def test_registry_drift_during_final_readiness_validation_refuses_before_acceptance(self):
        def drift(state):
            if self.case.validations==2:
                changed=copy.deepcopy(self.record);changed['status']='quarantined';self.case.registry.write(changed)
        self.case.validation_hook=drift
        with mock.patch.object(self.owner,'_fixture_ready',wraps=self.owner._fixture_ready)as receipt,self.assertRaises(inert.launch.LaunchError):self.await_ready()
        self.assertEqual(self.case.validations,2);receipt.assert_not_called()
        self.assertEqual(next(row for row in self.case.registry.load()if row['launch_id']==self.record['launch_id'])['status'],'quarantined')

    def test_fresh_history_uses_15s_ready_budget_and_expiry_never_accepts_receipt(self):
        state=self.owner.service_states[self.record['launch_id']];state['ready']=False
        self.case.validation_hook=lambda ledger:self.case.backend.advance(2)
        started=self.case.fixture.now[0]
        with mock.patch.object(self.owner,'_logs',side_effect=AssertionError('No logs readiness delegate'))as logs,mock.patch.object(self.owner,'_fixture_ready',wraps=self.owner._fixture_ready)as receipt:self.await_ready()
        self.assertEqual(self.case.validations,2);self.assertEqual(self.case.transactions,1);self.assertAlmostEqual(self.case.fixture.now[0]-started,4)
        logs.assert_not_called();receipt.assert_called_once();self.assertTrue(state['ready'])
        self.case.validations=0;self.case.transactions=0;state['ready']=False
        self.case.validation_hook=lambda ledger:self.case.backend.advance(8)
        with mock.patch.object(self.owner,'_logs',side_effect=AssertionError('No logs readiness delegate'))as logs,mock.patch.object(self.owner,'_fixture_ready',wraps=self.owner._fixture_ready)as receipt,mock.patch.object(self.case.registry,'write',wraps=self.case.registry.write)as write,self.assertRaises(inert.launch.LaunchError)as caught:self.await_ready()
        self.assertEqual(caught.exception.reason,'qualification_deadline');self.assertEqual(self.case.validations,2)
        logs.assert_not_called();receipt.assert_not_called();write.assert_not_called();self.assertFalse(state['ready'])

    def test_absent_receipt_remains_inside_original15s_readiness_bound(self):
        (self.private/'readiness.json').unlink();started=self.case.fixture.now[0]
        with mock.patch.object(self.owner,'_logs',side_effect=AssertionError('No logs readiness fallback')),self.assertRaises(qualifier.QualificationError):self.await_ready()
        self.assertGreaterEqual(self.case.fixture.now[0]-started,15);self.assertLess(self.case.fixture.now[0]-started,15.2)

    def test_start_binds_fresh_private_identity_and_nonce_before_intent(self):
        observations=self.owner.folder/'fresh-start';private=observations/'private';private.mkdir(mode=0o700,parents=True);observations.chmod(0o700);info=private.stat()
        self.owner.manifest={'images':self.case.fixture.policy['images'],'fixture_route':{'publish_host':'127.0.0.1'}};self.owner.cell.update(release='0.87.1',group='N02');self.owner.args=SimpleNamespace(_attempt_root=self.case.fixture.root/'fake-run')
        captured=[]
        def intent(registry,argv,role,runroot):
            self.assertEqual(list(private.iterdir()),[]);captured.append(argv);return self.record,argv
        with mock.patch.object(self.owner.guard,'external_service_intent',side_effect=intent),mock.patch.object(self.owner,'_await_ready'):self.owner._start('fixture',observations,['FAKE_FIXED_FIXTURE'],8080,Path(self.record['mounts'][2]['source']))
        state=self.owner.service_states[self.record['launch_id']];wrapper=observations.stat();self.assertEqual(state['readiness_wrapper_identity'],(wrapper.st_dev,wrapper.st_ino));self.assertEqual(state['readiness_root_identity'],(info.st_dev,info.st_ino));self.assertEqual(str(uuid.UUID(state['readiness_id'])),state['readiness_id'])
        argv=captured[0];self.assertEqual(argv.count('--readiness-id'),1);self.assertEqual(argv[argv.index('--readiness-id')+1],state['readiness_id'])

    def test_start_refuses_nonempty_readiness_root_before_intent(self):
        observations=self.owner.folder/'stale-start';private=observations/'private';private.mkdir(mode=0o700,parents=True);observations.chmod(0o700);(private/'stale.json').write_bytes(b'{}')
        self.owner.manifest={'images':self.case.fixture.policy['images'],'fixture_route':{'publish_host':'127.0.0.1'}};self.owner.cell.update(release='0.87.1',group='N02');self.owner.args=SimpleNamespace(_attempt_root=self.case.fixture.root/'fake-run')
        with mock.patch.object(self.owner.guard,'external_service_intent')as intent,self.assertRaises(REFUSALS):self.owner._start('fixture',observations,['FAKE_FIXED_FIXTURE'],8080,Path(self.record['mounts'][2]['source']))
        intent.assert_not_called()


if __name__=='__main__':unittest.main()
