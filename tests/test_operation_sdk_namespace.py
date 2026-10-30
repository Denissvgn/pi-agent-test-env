"""Fresh native namespaces only; no live registry or user credential store."""
import errno
import os
from pathlib import Path
import tempfile
from unittest import TestCase, mock

from tests.test_operation_sdk_policy import policy
from operation_sdk import collect, source
from operation_sdk.wire import SDKError


class SDKNamespaceTests(TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='sdk-namespace-'); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve(); self.store = self.root / 'store'; self.store.mkdir(mode=0o700)
        self.coordination = self.root / 'coordination'; self.coordination.write_bytes(b''); self.coordination.chmod(0o600)

    def identity(self, path):
        info = path.stat(); return [info.st_dev, info.st_ino]

    def reference(self, name='APP_FAKE', value=b'fixture-only-value-0123456789abcdef', role='application'):
        leaf = self.store / name; leaf.write_bytes(value); leaf.chmod(0o600); info = leaf.stat()
        return dict(reference=name, alias='PI_APP_KEY' if role == 'application' else None, role=role,
                    identity=[info.st_dev, info.st_ino], size=info.st_size,
                    mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns)

    def test_exact_private_reference_has_stable_version_without_discovery(self):
        expected = self.reference()
        namespace = source.Namespace(str(self.store), self.identity(self.store), private=True)
        try:
            with (mock.patch('os.listdir', side_effect=AssertionError('namespace discovery')),
                  mock.patch('os.scandir', side_effect=AssertionError('namespace discovery'))):
                body = namespace.read_private('APP_FAKE', expected, 16384)
            self.assertEqual(body, b'fixture-only-value-0123456789abcdef')
        finally: self.assertTrue(namespace.close())

    def test_bad_mode_link_or_changed_version_is_rejected_without_repair(self):
        expected = self.reference()
        namespace = source.Namespace(str(self.store), self.identity(self.store), private=True)
        try:
            (self.store / 'APP_FAKE').chmod(0o644)
            with self.assertRaises(SDKError): namespace.read_private('APP_FAKE', expected, 16384)
            self.assertEqual((self.store / 'APP_FAKE').stat().st_mode & 0o777, 0o644)
            (self.store / 'APP_FAKE').chmod(0o600)
            os.link(self.store / 'APP_FAKE', self.store / 'alias')
            with self.assertRaises(SDKError): namespace.read_private('APP_FAKE', expected, 16384)
        finally: namespace.close()

    def test_named_namespace_replacement_never_reopens_the_replacement(self):
        expected = self.reference(); namespace = source.Namespace(str(self.store), self.identity(self.store), private=True)
        self.store.rename(self.root / 'detached'); self.store.mkdir(mode=0o700)
        try:
            with self.assertRaises(SDKError): namespace.read_private('APP_FAKE', expected, 16384)
            self.assertEqual(list(self.store.iterdir()), [])
        finally: namespace.close()

    def test_public_reader_rejects_unapproved_path_before_lookup(self):
        reader = source.ApprovedReader({}, max_file_bytes=4096, max_total_bytes=4096, max_files=8)
        with mock.patch.object(source, 'Namespace', side_effect=AssertionError('unapproved lookup')):
            with self.assertRaises(SDKError): reader.read('/not-approved', 4096)

    def test_inventory_uses_held_directory_descriptors_and_never_path_scandir(self):
        (self.store/'APP_FAKE').write_bytes(b'fixture')
        real_scandir=os.scandir
        def anchored(fd):
            self.assertIs(type(fd),int)
            return real_scandir(fd)
        with (mock.patch.object(source.os,'scandir',side_effect=anchored),
              mock.patch.object(source.os,'statvfs',return_value=mock.Mock(f_flag=os.ST_RDONLY)),
              mock.patch.object(source.os,'fstatvfs',return_value=mock.Mock(f_flag=os.ST_RDONLY))):
            source.verify_tree(str(self.store),{'APP_FAKE':'a'*64},{'max_source_files':8})

    def test_inventory_rejects_unknown_entry_before_metadata_lookup(self):
        (self.store/'UNKNOWN').write_bytes(b'not-approved')
        real_stat=os.stat
        def scoped(name,*args,**kwargs):
            if name=='UNKNOWN' or str(name).endswith('/UNKNOWN'):
                raise AssertionError('unapproved metadata lookup')
            return real_stat(name,*args,**kwargs)
        real_lstat=os.lstat
        def scoped_lstat(name,*args,**kwargs):
            if str(name).endswith('/UNKNOWN'):raise AssertionError('unapproved metadata lookup')
            return real_lstat(name,*args,**kwargs)
        with (mock.patch.object(source.os,'stat',side_effect=scoped),
              mock.patch.object(source.os,'lstat',side_effect=scoped_lstat),
              mock.patch.object(source.os,'statvfs',return_value=mock.Mock(f_flag=os.ST_RDONLY)),
              mock.patch.object(source.os,'fstatvfs',return_value=mock.Mock(f_flag=os.ST_RDONLY))):
            with self.assertRaises(SDKError):source.verify_tree(str(self.store),{}, {'max_source_files':8})

    def test_inventory_stops_enumerating_at_the_first_unapproved_name(self):
        import types
        class Cursor:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def __iter__(self):
                yield types.SimpleNamespace(name='UNKNOWN')
                raise AssertionError('unbounded enumeration after refusal')
        with (mock.patch.object(source.os,'scandir',return_value=Cursor()),
              mock.patch.object(source.os,'fstatvfs',return_value=mock.Mock(f_flag=os.ST_RDONLY))):
            with self.assertRaises(SDKError):source.verify_tree(str(self.store),{}, {'max_source_files':8})

    def test_zero_read_count_is_supported_and_denies_before_namespace_lookup(self):
        reader=source.ApprovedReader({'/approved/file':{'sha256':'a'*64,'maximum_bytes':1,'readonly':True}},
                                    max_file_bytes=1,max_total_bytes=1,max_files=0)
        with mock.patch.object(source,'Namespace',side_effect=AssertionError('zero-count lookup')):
            with self.assertRaises(SDKError):reader.read('/approved/file',1)

    def test_absence_is_never_inferred_from_permission_or_namespace_failure(self):
        namespace=source.Namespace(str(self.store),self.identity(self.store),private=True)
        try:
            self.assertTrue(namespace.absent('MISSING'))
            with mock.patch.object(source.os,'stat',side_effect=PermissionError):
                with self.assertRaises(SDKError):namespace.absent('MISSING')
        finally:namespace.close()

    def test_approved_source_hash_and_size_are_checked_without_payload_readback_permissions(self):
        import hashlib
        file = self.root / 'artifact.txt'; file.write_bytes(b'nonsecret artifact')
        reader = source.ApprovedReader({str(file): {'sha256': hashlib.sha256(file.read_bytes()).hexdigest(),
            'maximum_bytes': 4096, 'readonly': False}}, max_file_bytes=4096, max_total_bytes=4096, max_files=8)
        self.assertEqual(reader.read(str(file), 4096), b'nonsecret artifact')
        file.write_bytes(b'changed artifact')
        with self.assertRaises(SDKError): reader.read(str(file), 4096)

    def test_unknown_native_close_is_not_retried_and_other_owned_descriptors_close(self):
        namespace = source.Namespace(str(self.store), self.identity(self.store), private=True)
        real_close = source.native.close; calls = []
        def ambiguous(fd):
            calls.append(fd); real_close(fd)
            if len(calls) == 1: raise OSError(errno.EINTR, 'lost native return')
        with mock.patch.object(source.native, 'close', side_effect=ambiguous):
            self.assertFalse(namespace.close())
            self.assertFalse(namespace.close())
        self.assertEqual(len(calls), len(set(calls)))

    def test_existing_exact_coordination_is_locked_and_never_created_replaced_or_unlocked_by_a_borrower(self):
        import fcntl
        lease = collect.Coordination(str(self.coordination), self.identity(self.coordination))
        try:
            lease.verify(); other = os.open(self.coordination, os.O_RDONLY)
            try:
                with self.assertRaises(BlockingIOError): fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally: os.close(other)
            duplicate = os.dup(lease.fd); os.close(duplicate)
            lease.verify()  # Closing a borrow does not unlock the parent's description.
        finally: self.assertTrue(lease.close())
        self.assertEqual(self.coordination.read_bytes(), b'')
        missing = self.root / 'missing'
        with self.assertRaises(SDKError): collect.Coordination(str(missing), [17, 23])
        self.assertFalse(missing.exists())

    def test_exact_reference_collector_preserves_every_binding_and_separates_inference(self):
        app = self.reference(); inference = self.reference('INFERENCE_FAKE', b'different-inference-value-0123456789', 'inference')
        namespace = source.Namespace(str(self.store), self.identity(self.store), private=True)
        try:
            values = collect.references(namespace, [app, inference], 16384, 32768)
            self.assertEqual([x['reference'] for x in values], ['APP_FAKE', 'INFERENCE_FAKE'])
            self.assertNotIn('fixture', repr(values))
            self.assertEqual(values.private()[0]['value'], 'fixture-only-value-0123456789abcdef')
        finally: namespace.close()

    def test_duplicate_application_and_inference_value_fails_without_omitting_a_reference(self):
        app = self.reference(); inference = self.reference('INFERENCE_FAKE', b'fixture-only-value-0123456789abcdef', 'inference')
        namespace = source.Namespace(str(self.store), self.identity(self.store), private=True)
        try:
            with self.assertRaises(SDKError): collect.references(namespace, [app, inference], 16384, 32768)
        finally: namespace.close()

    def test_zero_byte_grant_never_attempts_a_positive_payload_read(self):
        (self.store / 'EMPTY').write_bytes(b'')
        namespace = source.Namespace(str(self.store), self.identity(self.store), private=True)
        real_read = os.read
        try:
            with mock.patch.object(source.os, 'read', wraps=real_read) as reads:
                self.assertEqual(namespace.read_file('EMPTY', 0), b'')
            self.assertTrue(all(call.args[1] == 0 for call in reads.call_args_list))
        finally: namespace.close()

    def test_grants_are_snapshotted_and_failed_hash_reads_still_spend_byte_budget(self):
        import hashlib
        path = self.root / 'artifact.txt'; path.write_bytes(b'bounded-public-data')
        grant = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'maximum_bytes': 4096, 'readonly': False}
        reader = source.ApprovedReader({str(path): grant}, max_file_bytes=4096, max_total_bytes=4096, max_files=8)
        grant['sha256'] = 'b' * 64
        self.assertEqual(reader.read(str(path), 4096), b'bounded-public-data')
        bad = source.ApprovedReader({str(path): {'sha256': 'b' * 64, 'maximum_bytes': 4096, 'readonly': False}},
                                    max_file_bytes=4096, max_total_bytes=path.stat().st_size, max_files=8)
        with self.assertRaises(SDKError): bad.read(str(path), 4096)
        with mock.patch.object(source.os, 'read', side_effect=AssertionError('spent source budget')):
            with self.assertRaises(SDKError): bad.read(str(path), 4096)
