"""Readiness publication by the shipped example fixture over local loopback."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'skill/scripts'))
import secret_store

fixture_path=ROOT/'skill/examples/authenticated-application/fixture.py'
spec=importlib.util.spec_from_file_location('readiness_example_fixture',fixture_path)
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
FAKE_A='readiness-disposable-alice-185730945'
FAKE_B='readiness-disposable-bob-670492183'


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
