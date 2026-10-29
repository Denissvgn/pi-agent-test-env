"""Durable publication ordering and no-overwrite faults in synthetic histories."""
import importlib
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import unittest
import uuid
from unittest import mock

from tests import test_application_owner_legacy_lifecycle as lifecycle
import application_owner_cleanup as cleanup
import ownership_registry as ownership


class LegacyPublicationTests(unittest.TestCase):
    def setUp(self):
        self.f=lifecycle.LegacyLifecycleTests('test_complete_publication_preserves_primary_and_failed_metadata')
        self.f.setUp();self.addCleanup(self.f.doCleanups)

    def test_intent_anchor_and_selection_are_synced_before_first_purge(self):
        synced=set();seen=[];original_sync=os.fsync;original_purge=cleanup._purge
        output=self.f.root/'recovery'
        def fsync(fd):
            result=original_sync(fd);info=os.fstat(fd);synced.add((info.st_dev,info.st_ino));return result
        def purge(observation,**kwargs):
            if not seen:
                seen.append(True)
                paths=[output/'intent.json',cleanup._anchor(self.f.owner,self.f.fixture.record),
                       cleanup._selection(self.f.owner,self.f.fixture.record)]
                for target in paths:
                    self.assertTrue(target.exists());info=target.stat()
                    self.assertIn((info.st_dev,info.st_ino),synced)
                    parent=target.parent.stat();self.assertIn((parent.st_dev,parent.st_ino),synced)
                    self.assertEqual(stat.S_IMODE(info.st_mode),0o600)
                self.assertEqual(json.loads(paths[0].read_bytes())['status'],'RUNNING')
                self.assertFalse((output/'terminal.json').exists())
                self.assertFalse(cleanup._index(self.f.owner,self.f.fixture.record).exists())
            return original_purge(observation,**kwargs)
        with mock.patch.object(os,'fsync',side_effect=fsync),mock.patch.object(cleanup,'_purge',side_effect=purge):
            result=self.f.recover()
        self.assertTrue(seen);self.assertTrue(result['cleanup_completed']);self.assertTrue(self.f.replay(self.f.fresh()))

    def test_selected_graph_cannot_be_retried_or_overwritten(self):
        self.f.recover();paths=[cleanup._anchor(self.f.owner,self.f.fixture.record),
            cleanup._selection(self.f.owner,self.f.fixture.record),cleanup._index(self.f.owner,self.f.fixture.record),
            self.f.root/'recovery'/'intent.json',self.f.root/'recovery'/'terminal.json']
        before={str(path):path.read_bytes() for path in paths}
        with self.assertRaises(ownership.RegistryError):self.f.recover(self.f.root/'retry')
        self.assertFalse((self.f.root/'retry').exists())
        self.assertEqual({str(path):path.read_bytes() for path in paths},before)

    def test_index_failure_records_separate_failure_without_rewriting_terminal(self):
        with mock.patch.object(cleanup,'_publish_index',side_effect=OSError('synthetic index failure')):
            with self.assertRaises((ownership.RegistryError,OSError)):self.f.recover()
        terminal=json.loads((self.f.root/'recovery'/'terminal.json').read_bytes())
        failure=json.loads((self.f.root/'recovery'/'failure.json').read_bytes())
        self.assertEqual(terminal['status'],'CLEANED');self.assertTrue(terminal['cleanup_completed'])
        self.assertEqual(failure['status'],'BLOCKED');self.assertFalse(failure['cleanup_completed'])
        self.assertEqual(failure['intent'],terminal['intent']);self.assertFalse(failure['admission_authorized'])
        self.assertEqual(set(failure['diagnostic']),{'schema','phase','condition','operation','os_error','effects'})

    def test_unknown_anchor_entry_is_retained_and_blocks_before_removal(self):
        anchor=cleanup._anchor(self.f.owner,self.f.fixture.record).parent;anchor.mkdir(mode=0o700)
        sentinel=anchor/'foreign.txt';sentinel.write_text('retain');sentinel.chmod(0o600)
        with self.assertRaises(ownership.RegistryError):self.f.recover()
        self.assertTrue(self.f.fixture.workspace.exists());self.assertEqual(sentinel.read_text(),'retain')

    def test_publication_capacity_is_reserved_before_payload_effects(self):
        legacy=importlib.import_module('application_owner_legacy')
        with mock.patch.dict(legacy.SOURCE_FAMILIES,self.f.fixture.family(),clear=True):
            prepared=cleanup._prepare(self.f.owner,self.f.fixture.request())
        original_refs=len(prepared[2].references)
        with mock.patch.object(cleanup,'MAX_REFERENCES',original_refs+3):
            with self.assertRaises(ownership.RegistryError):self.f.recover()
        self.assertTrue(self.f.fixture.workspace.exists());self.assertTrue(self.f.fixture.private.exists())
        self.assertFalse((self.f.root/'recovery'/'terminal.json').exists())

    def test_output_cannot_be_nested_in_owner_proof_or_anchor_store(self):
        for parent in (cleanup.store_path(self.f.owner),cleanup._anchor(self.f.owner,self.f.fixture.record).parent):
            parent.mkdir(mode=0o700,exist_ok=True);target=parent/'new-output'
            with self.subTest(parent=parent.name):
                with self.assertRaises(ownership.RegistryError):self.f.recover(target)
                self.assertFalse(target.exists());self.assertTrue(self.f.fixture.workspace.exists())

    def test_anchor_inventory_keeps_the_existing_registry_entry_ceiling(self):
        anchor=cleanup._anchor(self.f.owner,self.f.fixture.record).parent;anchor.mkdir(mode=0o700)
        for unused in range(2):
            path=anchor/(str(uuid.uuid4())+'.json');path.write_text('{}');path.chmod(0o600)
        with mock.patch.object(ownership,'MAX_RECORDS',1):
            with self.assertRaises(ownership.RegistryError):self.f.recover()
        self.assertEqual(len(list(anchor.iterdir())),2);self.assertTrue(self.f.fixture.workspace.exists())

    def test_publication_change_at_first_purge_checkpoint_blocks_before_data(self):
        original=cleanup._purge;changed=[]
        def purge(observation,**kwargs):
            if not changed:
                changed.append(True);cleanup._anchor(self.f.owner,self.f.fixture.record).write_text('{}')
            return original(observation,**kwargs)
        with mock.patch.object(cleanup,'_purge',side_effect=purge):
            with self.assertRaises(ownership.RegistryError):self.f.recover()
        self.assertTrue(changed);self.assertTrue(self.f.fixture.workspace.exists());self.assertTrue(self.f.fixture.private.exists())
        self.assertFalse((self.f.root/'recovery'/'terminal.json').exists())

    def test_successful_new_method_cli_prints_no_private_subject_or_runner_hash(self):
        request=self.f.root/'request.json';request.write_bytes(cleanup.canonical(self.f.fixture.request()));request.chmod(0o600)
        actual_registry=ownership.Registry
        def factory(path,**kwargs):return actual_registry(path,command=self.f.command,create=False)
        args=argparse.Namespace(op='application-owner-recover',lock_file=str(self.f.lease),lock_wait_seconds=0,
            request=str(request),output_dir=str(self.f.root/'cli-output'),discard_workspace=True)
        legacy=importlib.import_module('application_owner_legacy');output=io.StringIO()
        with mock.patch.dict(legacy.SOURCE_FAMILIES,self.f.fixture.family(),clear=True),mock.patch.object(ownership,'Registry',side_effect=factory),contextlib.redirect_stdout(output):
            code=cleanup.command(args)
        self.assertEqual(code,0);result=json.loads(output.getvalue());self.assertEqual(result['status'],'CLEANED')
        self.assertNotIn('subject',result);self.assertNotIn('runner_content_sha256',result)
        for value in (str(self.f.root),self.f.fixture.launch_id,self.f.fixture.cid):self.assertNotIn(value,output.getvalue())

    def test_index_replacement_after_write_is_not_this_attempts_confirmed_publication(self):
        original=cleanup._publish_index
        def publish(registry,record,reference,**kwargs):
            result=original(registry,record,reference,**kwargs)
            target=cleanup._index(registry,record);body=target.read_bytes()
            target.rename(self.f.root/'saved-index');target.write_bytes(body);target.chmod(0o600)
            return result
        with mock.patch.object(cleanup,'_publish_index',side_effect=publish):
            with self.assertRaises(ownership.RegistryError):self.f.recover()
        self.assertEqual(json.loads((self.f.root/'recovery'/'terminal.json').read_bytes())['status'],'CLEANED')
