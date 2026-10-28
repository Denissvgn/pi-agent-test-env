"""Passive legacy proof and recovery conservation across disposable histories."""
import contextlib
import copy
import hashlib
import importlib
import json
import os
import shutil
from pathlib import Path
import unittest
import uuid
from unittest import mock

from tests import test_application_owner_legacy_lifecycle as lifecycle
import application_owner_cleanup as cleanup
import ownership_registry as ownership


class LegacyRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.f=lifecycle.LegacyLifecycleTests('test_complete_publication_preserves_primary_and_failed_metadata')
        self.f.setUp();self.addCleanup(self.f.doCleanups)

    @contextlib.contextmanager
    def selected(self,owner=None):
        owner=self.f.owner if owner is None else owner
        legacy=importlib.import_module('application_owner_legacy')
        with mock.patch.dict(legacy.SOURCE_FAMILIES,self.f.fixture.family(),clear=True),self.f.held(owner):
            yield owner

    def worker(self,runroot):
        row={'schema':1,'launch_id':str(uuid.uuid4()),'generation':str(uuid.uuid4()),'registry':self.f.owner.registry_id,
            'status':'running','container':'pi-unrelated-worker','image':'sha256:'+'e'*64,'container_id':'f'*64,
            'daemon':'synthetic-daemon','mounts':[],'runroot':str(runroot)}
        self.f.owner.write(row);return row

    def rewritten(self,path,value):
        path.write_bytes(cleanup.canonical(value));path.chmod(0o600)
        return {'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}

    def rewrite_related(self,related):
        index_path=cleanup._index(self.f.owner,self.f.fixture.record);index=json.loads(index_path.read_bytes())
        terminal_path=Path(index['receipt']['path']);terminal=json.loads(terminal_path.read_bytes())
        intent_path=Path(terminal['intent']['path']);intent=json.loads(intent_path.read_bytes())
        intent['related_subjects']=related;terminal['related_subjects']=related
        reference=self.rewritten(intent_path,intent);terminal['intent']=reference
        anchor_path=cleanup._anchor(self.f.owner,self.f.fixture.record);anchor=json.loads(anchor_path.read_bytes());anchor['intent']=reference
        self.rewritten(anchor_path,anchor);index['receipt']=self.rewritten(terminal_path,terminal);self.rewritten(index_path,index)

    def test_all_released_restart_validation_is_passive_and_preserves_failed_bytes(self):
        self.f.recover();before=self.f.protected();fresh=self.f.fresh();self.f.calls.clear()
        with self.selected(fresh),mock.patch.object(os,'kill',side_effect=AssertionError('Historical PID probe')):
            self.assertEqual(fresh.validate_history(fresh.load()),[])
            self.assertTrue(cleanup.validate_accepted(fresh,self.f.fixture.record))
        self.assertEqual(self.f.calls,[]);self.assertEqual(self.f.protected(),before)

    def test_lost_proof_after_unrelated_writer_transition_denies_before_raw_repair(self):
        self.f.recover();other=self.f.root/'other';other.mkdir(mode=0o700)
        worker=self.worker(other);before=self.f.protected();repair=mock.Mock();self.f.owner.recover_sensitive=repair
        original=self.f.owner.write
        def write(row):
            original(row)
            if row['launch_id']==worker['launch_id'] and row['status']=='absent':
                cleanup._index(self.f.owner,self.f.fixture.record).unlink(missing_ok=True)
        with self.selected(),mock.patch.object(self.f.owner,'write',side_effect=write):
            with self.assertRaises(ownership.RegistryError):self.f.owner.reconcile()
        repair.assert_not_called();self.assertEqual(self.f.protected(),before)

    def test_lost_proof_at_final_release_cannot_return_reconciled(self):
        self.f.recover();other=self.f.root/'other';other.mkdir(mode=0o700);worker=self.worker(other)
        before=self.f.protected();self.f.owner.recover_sensitive=mock.Mock();original=self.f.owner.write
        def write(row):
            original(row)
            if row['launch_id']==worker['launch_id'] and row['status']=='released':
                cleanup._index(self.f.owner,self.f.fixture.record).unlink(missing_ok=True)
        with self.selected(),mock.patch.object(self.f.owner,'write',side_effect=write):
            with self.assertRaises(ownership.RegistryError):self.f.owner.reconcile()
        self.assertEqual(self.f.protected(),before)

    def test_noncanonical_or_parent_aliased_run_cannot_repair_a_proven_history(self):
        self.f.recover();before=self.f.protected();repair=mock.Mock();self.f.owner.recover_sensitive=repair
        self.worker(str(self.f.fixture.run)+'/')
        with self.selected():
            with self.assertRaises(ownership.RegistryError):self.f.owner.reconcile()
        repair.assert_not_called();self.assertEqual(self.f.protected(),before)

    def test_parent_symlink_cannot_hide_proven_run_from_conservation(self):
        self.f.recover();before=self.f.protected();repair=mock.Mock();self.f.owner.recover_sensitive=repair
        alias=self.f.root/'alias';alias.symlink_to(self.f.fixture.run.parent,target_is_directory=True)
        self.worker(alias/self.f.fixture.run.name)
        with self.selected():
            with self.assertRaises(ownership.RegistryError):self.f.owner.reconcile()
        repair.assert_not_called();self.assertEqual(self.f.protected(),before)

    def test_ordinary_unproven_disjoint_recovery_still_runs(self):
        self.f.recover();other=self.f.root/'other';other.mkdir(mode=0o700);row=self.worker(other)
        before=self.f.protected();repair=mock.Mock();self.f.owner.recover_sensitive=repair
        with self.selected():self.f.owner.reconcile()
        repair.assert_called_once_with(other)
        self.assertEqual(next(r for r in self.f.owner.load() if r['launch_id']==row['launch_id'])['status'],'released')
        self.assertEqual(self.f.protected(),before)

    def test_coherently_rehashed_missing_duplicate_or_extra_related_subjects_deny(self):
        self.f.recover();original=[cleanup._resource_subject(self.f.fixture.record)]
        cases=[[],original+original,original+[{'launch_id':str(uuid.uuid4()),'identity':'a'*64}]]
        for subjects in cases:
            with self.subTest(count=len(subjects)):
                self.rewrite_related(subjects)
                with self.assertRaises(ownership.RegistryError):self.f.replay(self.f.fresh())
        self.rewrite_related(original);self.assertTrue(self.f.replay(self.f.fresh()))

    def test_other_subject_cannot_borrow_an_index_even_for_released_records(self):
        self.f.recover();other=copy.deepcopy(self.f.fixture.record);other['launch_id']=str(uuid.uuid4())
        other['runroot']=str(self.f.root/'other');self.f.owner.write(other)
        index=json.loads(cleanup._index(self.f.owner,self.f.fixture.record).read_bytes())
        self.rewritten(cleanup._index(self.f.owner,other),index)
        with self.selected():
            with self.assertRaises(ownership.RegistryError):cleanup.validate_accepted(self.f.owner,other)

    def test_observed_incomplete_anchor_stays_selected_after_later_namespace_loss(self):
        self.f.recover();fresh=self.f.fresh()
        cleanup._index(fresh,self.f.fixture.record).unlink()
        with self.selected(fresh):
            with self.assertRaises(ownership.RegistryError):cleanup.validate_accepted(fresh,self.f.fixture.record)
        shutil.rmtree(cleanup.store_path(fresh));cleanup._anchor(fresh,self.f.fixture.record).unlink()
        with self.selected(fresh):
            with self.assertRaises(ownership.RegistryError):cleanup.validate_accepted(fresh,self.f.fixture.record)
            with self.assertRaises(ownership.RegistryError):
                cleanup._retained_selection(fresh,self.f.fixture.record,cleanup.Reader())

    def test_same_consumer_rejects_replaced_anchor_directory_with_identical_bytes(self):
        self.f.recover();fresh=self.f.fresh();self.assertTrue(self.f.replay(fresh))
        anchor=cleanup._anchor(fresh,self.f.fixture.record).parent;saved=self.f.root/'saved-anchors'
        anchor.rename(saved);shutil.copytree(saved,anchor)
        with self.assertRaises(ownership.RegistryError):self.f.replay(fresh)

    def test_refused_new_recovery_also_remembers_existing_selection(self):
        self.f.recover();self.f.owner=self.f.fresh()
        with self.assertRaises(ownership.RegistryError):self.f.recover(self.f.root/'retry')
        shutil.rmtree(cleanup.store_path(self.f.owner));cleanup._anchor(self.f.owner,self.f.fixture.record).unlink()
        with self.selected():
            with self.assertRaises(ownership.RegistryError):
                cleanup._retained_selection(self.f.owner,self.f.fixture.record,cleanup.Reader())

    def test_selection_without_index_or_anchor_is_remembered_before_denial(self):
        self.f.recover();fresh=self.f.fresh()
        cleanup._index(fresh,self.f.fixture.record).unlink();cleanup._anchor(fresh,self.f.fixture.record).unlink()
        with self.selected(fresh):
            with self.assertRaises(ownership.RegistryError):cleanup.validate_accepted(fresh,self.f.fixture.record)
        shutil.rmtree(cleanup.store_path(fresh))
        with self.selected(fresh):
            with self.assertRaises(ownership.RegistryError):
                cleanup._retained_selection(fresh,self.f.fixture.record,cleanup.Reader())
