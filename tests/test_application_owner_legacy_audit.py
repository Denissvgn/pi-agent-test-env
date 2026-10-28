"""Whole-path audit regressions; operational state is always disposable."""
import importlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import shutil
from unittest import mock

from tests import test_application_owner_legacy_discard as discard_fixtures
from tests import test_application_owner_legacy_dispatch as dispatch_fixtures
from tests import test_application_owner_legacy_lifecycle as lifecycle_fixtures
import application_owner_cleanup as cleanup


class LegacyAuditTests(unittest.TestCase):
    def test_nested_ancestor_permission_change_blocks_before_unlink(self):
        case=discard_fixtures.LegacyDiscardTests('test_complete_discard_preserves_every_original_and_primary_byte')
        case.setUp();self.addCleanup(case.doCleanups);case.diagnostic()
        payload=case.f.fixture.private/'code'/'payload.bin';payload.write_text('retain')
        original_stat=os.stat;original_purge=cleanup._purge;changed=[]
        def stat(name,*args,**kwargs):
            result=original_stat(name,*args,**kwargs)
            if str(name)=='payload.bin' and kwargs.get('dir_fd') is not None and not changed:
                changed.append(True);payload.parent.chmod(0o777)
            return result
        def purge(observation,**kwargs):
            with mock.patch.object(os,'stat',side_effect=stat):return original_purge(observation,**kwargs)
        try:
            with case.bound() as operation:
                with mock.patch.object(cleanup,'_purge',side_effect=purge):
                    with self.assertRaises(cleanup.ownership.RegistryError):operation.purge()
                self.assertEqual(operation.effects,'none_observed')
            self.assertTrue(changed);self.assertEqual(payload.read_text(),'retain')
        finally:payload.parent.chmod(0o700)

    def test_namespace_entry_limit_is_enforced_without_unbounded_listdir(self):
        namespace=importlib.import_module('application_owner_legacy_namespace')
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve()
            for name in ('a','b','c'):(root/name).write_text('synthetic')
            with mock.patch.object(cleanup,'MAX_ENTRIES',2),mock.patch.object(os,'listdir',side_effect=AssertionError('Unbounded listdir')):
                with self.assertRaises(cleanup.ownership.RegistryError) as caught:
                    namespace._scan(cleanup.Reader(),root,[],[])
            self.assertEqual(cleanup.diagnostics.diagnostic(caught.exception)['condition'],'inventory_unbounded')

    def test_receipt_cannot_recreate_a_root_the_original_terminal_already_removed(self):
        case=dispatch_fixtures.LegacyDispatchTests('test_complete_new_method_graph_replays_without_native_actions')
        case.setUp();self.addCleanup(case.doCleanups)
        from tests.test_application_owner_legacy_support import AcceptanceFixture
        case.fixture=AcceptanceFixture(case.root/'diagnostic',scope='diagnostic_disposable',
            registry_id=case.owner.registry_id,generation=case.owner.generation)
        case.fixture.rewrite('diagnostic-terminal.json',lambda body:body.update(disposable_root_removed=True))
        shutil.rmtree(case.fixture.private);case.owner.write(case.fixture.record)
        legacy=importlib.import_module('application_owner_legacy')
        with mock.patch.dict(legacy.SOURCE_FAMILIES,case.fixture.family(),clear=True):
            terminal=case.graph();self.assertTrue(case.replay())
            for row in terminal['roots']:
                row.update(state='present',identity=case.fixture.original_identity)
            intent_path=Path(terminal['intent']['path']);intent=json.loads(intent_path.read_bytes());intent['roots']=terminal['roots']
            reference=case.put(intent_path,intent);terminal['intent']=reference
            anchor=json.loads(case.anchor_path.read_bytes());anchor['intent']=reference;case.put(case.anchor_path,anchor)
            case.rewrite_receipt(terminal)
            with self.assertRaises(cleanup.ownership.RegistryError):case.replay()

    def test_registry_namespace_stays_bound_after_discard_descriptors_close(self):
        case=lifecycle_fixtures.LegacyLifecycleTests('test_complete_publication_preserves_primary_and_failed_metadata')
        case.setUp();self.addCleanup(case.doCleanups)
        discard=importlib.import_module('application_owner_legacy_discard');original=discard._BoundCleanup.close;changed=[]
        def close(operation):
            original(operation)
            if operation.cleanup_completed and not changed:
                changed.append(True);root=case.owner.root;saved=case.root/'saved-registry'
                root.rename(saved);shutil.copytree(saved,root)
        with mock.patch.object(discard._BoundCleanup,'close',new=close):
            with self.assertRaises(cleanup.ownership.RegistryError):case.recover()
        self.assertTrue(changed);self.assertFalse((case.root/'recovery'/'terminal.json').exists())
