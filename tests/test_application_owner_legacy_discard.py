"""Descriptor cleanup faults operate only on explicitly disposable test roots."""
import contextlib
import errno
import importlib
import os
from pathlib import Path
import shutil
import unittest
from unittest import mock

from tests import test_application_owner_legacy_native as native_fixtures
import application_owner_cleanup as cleanup
import ownership_registry as ownership


class LegacyDiscardTests(unittest.TestCase):
    def setUp(self):
        self.f=native_fixtures.LegacyNativeTests('test_complete_observation_preserves_records_inputs_and_private_files')
        self.f.setUp();self.addCleanup(self.f.doCleanups)

    @contextlib.contextmanager
    def bound(self,*,reader=None,discard_workspace=True):
        module=importlib.import_module('application_owner_legacy_discard')
        legacy=importlib.import_module('application_owner_legacy')
        with mock.patch.dict(legacy.SOURCE_FAMILIES,self.f.fixture.family(),clear=True),self.f.held():
            with module._BoundCleanup(self.f.owner,self.f.fixture.request(),
                    discard_workspace=discard_workspace,reader=reader) as operation:
                yield operation

    def protected(self):
        refs=list(self.f.fixture.refs.values())
        primary=self.f.owner.root/(self.f.fixture.launch_id+'.json')
        return {str(path):path.read_bytes() for path in [primary,*[Path(ref['path']) for ref in refs]]}

    def diagnostic(self):
        self.f.fixture=self.f.build('diagnostic',scope='diagnostic_disposable')
        self.f.owner.write(self.f.fixture.record)

    def test_complete_discard_preserves_every_original_and_primary_byte(self):
        before=self.protected()
        with self.bound() as operation:
            original_roots=operation.observation['plan']['roots']
            result=operation.purge()
            self.assertTrue(result['cleanup_completed']);self.assertEqual(result['effects'],'may_have_occurred')
            self.assertTrue(all(not Path(row['path']).exists() for row in original_roots))
            self.assertTrue(any(row['identity'] is not None for row in original_roots))
            self.assertFalse(cleanup.validate_accepted(self.f.owner,self.f.fixture.record))
        self.assertEqual(self.protected(),before)
        self.assertFalse(cleanup.store_path(self.f.owner).exists())

    def test_exact_explicit_discard_authority_required_before_observation(self):
        for flag in (False,1,None):
            with self.subTest(flag=flag):
                with self.assertRaises(ownership.RegistryError):
                    with self.bound(discard_workspace=flag):pass
        self.assertEqual(self.f.calls,[]);self.assertTrue(self.f.fixture.private.exists())

    def test_input_read_before_custody_scope_cannot_be_discarded(self):
        request=self.f.fixture.workspace/'owner-request.json'
        request.write_bytes(cleanup.canonical(self.f.fixture.request()));request.chmod(0o600)
        reader=cleanup.Reader();reader.read(request,private=True)
        with self.assertRaises(ownership.RegistryError):
            with self.bound(reader=reader):pass
        self.assertTrue(request.exists());self.assertTrue(self.f.fixture.private.exists())

    def test_unknown_issued_authority_remains_blocked_without_removal(self):
        self.f.fixture.rewrite('authority-observation.json',lambda body:body.update(external_authority='issued'))
        with self.assertRaises(ownership.RegistryError):
            with self.bound():pass
        self.assertTrue(self.f.fixture.private.exists())

    def test_root_replacement_does_not_delete_saved_or_foreign_data(self):
        payload=self.f.fixture.private/'retain.bin';payload.write_bytes(b'synthetic owned bytes')
        with self.bound() as operation:
            saved=self.f.root/'saved-private';self.f.fixture.private.rename(saved)
            self.f.fixture.private.mkdir(mode=0o700)
            sentinel=self.f.fixture.private/'foreign.txt';sentinel.write_text('retain')
            with self.assertRaises(ownership.RegistryError):operation.purge()
            self.assertEqual(operation.effects,'none_observed')
        self.assertEqual((saved/'retain.bin').read_bytes(),b'synthetic owned bytes')
        self.assertEqual(sentinel.read_text(),'retain')

    def test_replaced_named_parent_does_not_redirect_held_descriptor(self):
        payload=self.f.fixture.workspace/'retain.bin';payload.write_bytes(b'synthetic owned bytes')
        with self.bound() as operation:
            saved=self.f.root/'saved-run';self.f.fixture.run.rename(saved)
            self.f.fixture.run.mkdir(mode=0o700)
            sentinel=self.f.fixture.run/'foreign.txt';sentinel.write_text('retain')
            with self.assertRaises(ownership.RegistryError):operation.purge()
            self.assertEqual(operation.effects,'none_observed')
        self.assertEqual((saved/'workspace'/'retain.bin').read_bytes(),b'synthetic owned bytes')
        self.assertEqual(sentinel.read_text(),'retain')

    def test_recreated_initially_absent_root_blocks_before_any_other_root(self):
        shutil.rmtree(self.f.fixture.workspace)
        with self.bound() as operation:
            self.f.fixture.workspace.mkdir(mode=0o700)
            sentinel=self.f.fixture.workspace/'new.txt';sentinel.write_text('retain')
            with self.assertRaises(ownership.RegistryError):operation.purge()
            self.assertEqual(operation.effects,'none_observed')
        self.assertTrue(self.f.fixture.private.exists());self.assertEqual(sentinel.read_text(),'retain')

    def test_symlinks_hardlinks_and_special_nodes_fail_preflight_before_purge(self):
        outside=self.f.root/'outside';outside.write_text('retain')
        target=self.f.fixture.private/'unsafe'
        for shape in ('symlink','hardlink','fifo'):
            with self.subTest(shape=shape):
                if shape=='symlink':target.symlink_to(outside)
                elif shape=='hardlink':os.link(outside,target)
                else:os.mkfifo(target)
                try:
                    with self.assertRaises(ownership.RegistryError):
                        with self.bound():pass
                    self.assertTrue(self.f.fixture.workspace.exists());self.assertEqual(outside.read_text(),'retain')
                finally:target.unlink()

    def test_entry_ceiling_applies_before_first_mutation(self):
        for i in range(3):(self.f.fixture.private/('payload-'+str(i))).write_text('synthetic')
        with mock.patch.object(cleanup,'MAX_ENTRIES',2):
            with self.assertRaises(ownership.RegistryError):
                with self.bound():pass
        self.assertTrue(self.f.fixture.workspace.exists());self.assertTrue(self.f.fixture.private.exists())

    def test_payload_bytes_are_never_opened_or_hashed(self):
        payload=self.f.fixture.private/'payload.bin';payload.write_bytes(b'synthetic disposable bytes')
        original=os.open
        def opened(name,flags,*args,**kwargs):
            if Path(str(name)).name=='payload.bin' and not flags & os.O_DIRECTORY:
                raise AssertionError('Payload content was opened')
            return original(name,flags,*args,**kwargs)
        with mock.patch.object(os,'open',side_effect=opened),self.bound() as operation:operation.purge()
        self.assertFalse(payload.exists())

    def test_changed_protected_input_after_binding_blocks_before_removal(self):
        with self.bound() as operation:
            target=Path(self.f.fixture.refs['protected-result.json']['path']);target.write_text('{}')
            with self.assertRaises(ownership.RegistryError):operation.purge()
            self.assertEqual(operation.effects,'none_observed')
        self.assertTrue(self.f.fixture.private.exists())

    def test_failure_after_unlink_reports_possible_effects_and_no_completion(self):
        self.diagnostic();payload=self.f.fixture.private/'code'/'payload.bin';payload.write_text('synthetic')
        original=os.unlink;removed=[]
        def unlink(name,*args,**kwargs):
            result=original(name,*args,**kwargs)
            if str(name)=='payload.bin' and not removed:
                removed.append(True);raise OSError(errno.EIO,'synthetic failure after deletion')
            return result
        with self.bound() as operation:
            with mock.patch.object(os,'unlink',side_effect=unlink):
                with self.assertRaises((ownership.RegistryError,OSError)):operation.purge()
            self.assertEqual(operation.effects,'may_have_occurred');self.assertFalse(operation.cleanup_completed)
        self.assertTrue(removed);self.assertFalse(payload.exists())
        self.assertFalse(cleanup._index(self.f.owner,self.f.fixture.record).exists())

    def test_payload_changes_after_preflight_are_denied(self):
        payload=self.f.fixture.private/'payload.bin';payload.write_bytes(b'old')
        with self.bound() as operation:
            payload.write_bytes(b'changed')
            with self.assertRaises(ownership.RegistryError):operation.purge()
            self.assertEqual(operation.effects,'none_observed')
        self.assertEqual(payload.read_bytes(),b'changed')

    def test_nested_directory_swap_after_stat_cannot_redirect_unlink(self):
        self.diagnostic();payload=self.f.fixture.private/'code'/'payload.bin';payload.write_text('owned')
        saved=self.f.root/'saved-code';changed=[];original_stat=os.stat;original_purge=cleanup._purge
        def observed(name,*args,**kwargs):
            value=original_stat(name,*args,**kwargs)
            if str(name)=='payload.bin' and kwargs.get('dir_fd') is not None and not changed:
                changed.append(True);payload.parent.rename(saved);payload.parent.mkdir(mode=0o700)
                payload.write_text('foreign')
            return value
        def purge(observation,**kwargs):
            with mock.patch.object(os,'stat',side_effect=observed):return original_purge(observation,**kwargs)
        with self.bound() as operation:
            with mock.patch.object(cleanup,'_purge',side_effect=purge):
                with self.assertRaises(ownership.RegistryError):operation.purge()
            self.assertEqual(operation.effects,'none_observed')
        self.assertEqual(payload.read_text(),'foreign');self.assertEqual((saved/'payload.bin').read_text(),'owned')

    def test_file_replacement_after_stat_is_not_deleted(self):
        self.diagnostic();payload=self.f.fixture.private/'code'/'payload.bin';payload.write_text('owned')
        saved=self.f.root/'saved-file';changed=[];original_stat=os.stat;original_purge=cleanup._purge
        def observed(name,*args,**kwargs):
            value=original_stat(name,*args,**kwargs)
            if str(name)=='payload.bin' and kwargs.get('dir_fd') is not None and not changed:
                changed.append(True);payload.rename(saved);payload.write_text('foreign')
            return value
        def purge(observation,**kwargs):
            with mock.patch.object(os,'stat',side_effect=observed):return original_purge(observation,**kwargs)
        with self.bound() as operation:
            with mock.patch.object(cleanup,'_purge',side_effect=purge):
                with self.assertRaises(ownership.RegistryError):operation.purge()
            self.assertEqual(operation.effects,'none_observed')
        self.assertEqual(payload.read_text(),'foreign');self.assertEqual(saved.read_text(),'owned')

    def test_mid_purge_protected_change_blocks_without_restoring_failure_history(self):
        self.diagnostic();payload=self.f.fixture.private/'code'/'payload.bin';payload.write_text('owned')
        target=Path(self.f.fixture.refs['protected-result.json']['path']);original=os.unlink;changed=[]
        def unlink(name,*args,**kwargs):
            value=original(name,*args,**kwargs)
            if str(name)=='payload.bin' and not changed:
                changed.append(True);target.write_text('{"external-change":true}')
            return value
        with self.bound() as operation:
            with mock.patch.object(os,'unlink',side_effect=unlink):
                with self.assertRaises(ownership.RegistryError):operation.purge()
            self.assertFalse(operation.cleanup_completed);self.assertEqual(operation.effects,'may_have_occurred')
        self.assertEqual(target.read_text(),'{"external-change":true}')
        self.assertFalse(cleanup._index(self.f.owner,self.f.fixture.record).exists())

    def test_already_absent_roots_keep_original_custody_without_mutation(self):
        self.diagnostic();shutil.rmtree(self.f.fixture.private)
        with self.bound() as operation:
            original=next(row['value']['identity'] for row in operation.observation['plan']['claims']
                          if row['obligation']=='original_root_custody')
            result=operation.purge()
            self.assertTrue(result['cleanup_completed']);self.assertEqual(result['effects'],'none_observed')
            self.assertEqual(original,self.f.fixture.original_identity)

    def test_fsync_failure_after_removal_never_reports_completion(self):
        self.diagnostic();original=os.fsync;failed=[]
        def fsync(fd):
            if not failed:failed.append(True);raise OSError(errno.EIO,'synthetic fsync failure')
            return original(fd)
        with self.bound() as operation:
            with mock.patch.object(os,'fsync',side_effect=fsync):
                with self.assertRaises((ownership.RegistryError,OSError)):operation.purge()
            self.assertFalse(operation.cleanup_completed);self.assertEqual(operation.effects,'may_have_occurred')
        self.assertTrue(failed);self.assertFalse(self.f.fixture.private.exists())

    def test_close_failure_still_attempts_every_owned_fd_and_keeps_lease_open(self):
        with self.bound() as operation:
            fds=[fd for root in operation.roots for fd in (root.fd,root.parent) if fd is not None]
            fds.extend(fd for fd,identity in operation.held.values());target=fds[0];failed=[];original=os.close
            def close(fd):
                value=original(fd)
                if fd==target and not failed:failed.append(True);raise OSError(errno.EIO,'synthetic close failure')
                return value
            with mock.patch.object(os,'close',side_effect=close):
                with self.assertRaises(OSError):operation.close()
            for fd in fds:
                with self.assertRaises(OSError):os.fstat(fd)
            os.fstat(self.f.owner.lease_fd)
        self.assertTrue(self.f.fixture.private.exists())

    def test_close_error_does_not_replace_an_original_interruption(self):
        target=[];failed=[];original=os.close
        def close(fd):
            value=original(fd)
            if target and fd==target[0] and not failed:
                failed.append(True);raise OSError(errno.EIO,'synthetic secondary close error')
            return value
        with mock.patch.object(os,'close',side_effect=close):
            with self.assertRaises(KeyboardInterrupt):
                with self.bound() as operation:
                    target.append(next(root.fd for root in operation.roots if root.fd is not None))
                    raise KeyboardInterrupt()
        self.assertTrue(failed);self.assertTrue(self.f.fixture.private.exists())

    def test_purge_is_one_shot_and_does_not_auto_adopt_absent_roots(self):
        with self.bound() as operation:
            operation.purge();calls=len(self.f.calls)
            with self.assertRaises(ownership.RegistryError):operation.purge()
            self.assertEqual(len(self.f.calls),calls)

    def test_diagnostic_removes_only_disposable_child_and_keeps_campaign_parent(self):
        from tests import test_application_owner_legacy_namespace as shapes
        self.f.fixture=shapes.LegacyNamespaceTests.full_artifact(self.f)
        self.f.owner.write(self.f.fixture.record)
        sibling=Path(self.f.fixture.record['runroot'])/'unrelated';sibling.mkdir(mode=0o700)
        sentinel=sibling/'retained.txt';sentinel.write_text('retain')
        module=importlib.import_module('application_owner_legacy_discard')
        legacy=importlib.import_module('application_owner_legacy');family=self.f.fixture.family()
        next(iter(family.values()))['execution_rule']='absolute_owned_host_paths_v1'
        with mock.patch.dict(legacy.SOURCE_FAMILIES,family,clear=True),self.f.held():
            with module._BoundCleanup(self.f.owner,self.f.fixture.request(),discard_workspace=True) as operation:
                operation.purge()
        self.assertTrue(sentinel.exists());self.assertTrue(Path(self.f.fixture.record['runroot']).exists())
