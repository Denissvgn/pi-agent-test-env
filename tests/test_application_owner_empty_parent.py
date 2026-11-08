"""Reuse the freshly checked zero-byte parent within one existing call only."""
import importlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / 'skill/scripts'
sys.path.insert(0, str(SCRIPTS))
import application_owner_cleanup as cleanup
namespace = importlib.import_module('application_owner_legacy_namespace')


class EmptyParentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.parent = self.root / 'metadata'; self.parent.mkdir(mode=0o700)
        self.path = self.parent / 'empty.bin'; self.path.touch(mode=0o600)

    def test_fresh_parent_is_supplied_and_closed_after_single_call(self):
        reader = cleanup.Reader(); original = reader.read_bytes; passed = []
        def observed(path, **kwargs):
            fd = kwargs['parent_fd']; passed.append(fd)
            self.assertEqual(cleanup.identity(os.fstat(fd)), cleanup.identity(self.parent.stat()))
            self.assertEqual(kwargs['maximum'], 0)
            return original(path, **kwargs)
        with mock.patch.object(reader, 'read_bytes', side_effect=observed):reference = namespace._empty(reader, self.path)
        self.assertEqual(reference['path'], str(self.path)); self.assertEqual(len(passed), 1)
        with self.assertRaises(OSError):os.fstat(passed[0])
        self.assertEqual(reader.bytes, 0)

    def test_nonempty_role_still_refuses_before_any_payload_read(self):
        self.path.write_bytes(b'unreviewed payload')
        with mock.patch.object(os, 'read', side_effect=AssertionError('Payload consulted')):
            with self.assertRaises(cleanup.ownership.RegistryError) as caught:
                namespace._empty(cleanup.Reader(), self.path)
        self.assertEqual(cleanup.diagnostics.diagnostic(caught.exception)['condition'], 'owner_scope_unsupported')

    def test_already_symlinked_parent_is_denied_before_reader_entry(self):
        original = self.root / 'moved'; self.parent.rename(original)
        self.parent.symlink_to(original, target_is_directory=True)
        reader = cleanup.Reader()
        with mock.patch.object(reader, 'read_bytes', side_effect=AssertionError('Reader entered')):
            with self.assertRaises(OSError):namespace._empty(reader, self.path)
        self.parent.unlink()

    def test_current_replaced_parent_is_freshly_selected_without_a_retained_handle(self):
        first = namespace._empty(cleanup.Reader(), self.path)
        original = self.root / 'moved'; self.parent.rename(original)
        self.parent.mkdir(mode=0o700); self.path.write_bytes(b'payload'); self.path.chmod(0o600)
        with self.assertRaises(cleanup.ownership.RegistryError):namespace._empty(cleanup.Reader(), self.path)
        self.assertEqual(first['path'], str(self.path))

    def test_zero_byte_capture_never_reads_growth_inserted_after_precheck(self):
        actual = os.fstat; changed = []
        def observe(fd):
            info = actual(fd)
            if info.st_size == 0 and os.path.isfile(self.path) and not changed:
                # Only the leaf descriptor, not a directory descriptor.
                import stat
                if stat.S_ISREG(info.st_mode):changed.append(True); self.path.write_bytes(b'payload')
            return info
        with (mock.patch.object(os, 'fstat', side_effect=observe),
              mock.patch.object(os, 'read', side_effect=AssertionError('Payload consulted'))):
            with self.assertRaises(cleanup.ownership.RegistryError):namespace._empty(cleanup.Reader(), self.path)
        self.assertEqual(changed, [True])

    def test_native_cost_control_keeps_two_full_named_walks_under_FD16(self):
        program = '''
import importlib,json,resource,sys,tempfile
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import application_owner_cleanup as cleanup
namespace=importlib.import_module('application_owner_legacy_namespace')
soft,hard=resource.getrlimit(resource.RLIMIT_NOFILE);hard=16 if hard==resource.RLIM_INFINITY else min(hard,16)
resource.setrlimit(resource.RLIMIT_NOFILE,(min(16,hard),hard))
with tempfile.TemporaryDirectory() as text:
 root=Path(text).resolve();parent=root/'metadata';parent.mkdir(mode=0o700);path=parent/'empty';path.touch(mode=0o600)
 count=[0]
 def hook(event,args):
  if event=='open':count[0]+=1
 sys.addaudithook(hook)
 namespace._empty(cleanup.Reader(),path)
 depth=len(parent.parts)-1
 assert count[0]==2*depth+3,(count[0],depth)
 print(json.dumps({'open_events':count[0],'depth':depth}))
'''
        result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', program, str(SCRIPTS)],
                                capture_output=True, text=True, env={}, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
