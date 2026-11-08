"""Fresh bounded reads and real audit-event counts in disposable fixtures."""
import contextlib
import errno
import json
import mmap
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / 'skill' / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import application_owner_cleanup as cleanup
import ownership_registry as ownership
import registry_maintenance as maintenance


class OwnerReadIOTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.path = self.root / 'record.json'
        self.path.write_bytes(b'{"tag":"aaaaaaaa"}'); self.path.chmod(0o600)

    def mapped_change(self, observe):
        fd = os.open(self.path, os.O_RDWR)
        try:
            with mmap.mmap(fd, 0, access=mmap.ACCESS_WRITE) as mapping:
                offset = mapping.find(b'aaaaaaaa')
                mapping[offset:offset + 8] = b'aaaaaaaa'
                observe()
                mapping[offset:offset + 8] = b'bbbbbbbb'
                yield_mapping = mapping[offset:offset + 8]
                self.assertEqual(yield_mapping, b'bbbbbbbb')
                return ownership.read_private(self.path)
        finally:os.close(fd)

    def test_registry_rereads_shared_mapping_bytes(self):
        self.assertEqual(self.mapped_change(lambda: self.assertEqual(
            ownership.read_private(self.path), {'tag': 'aaaaaaaa'})), {'tag': 'bbbbbbbb'})

    def test_mapped_valid_and_invalid_registry_changes_are_freshly_validated(self):
        for invalid in (False, True):
            with self.subTest(invalid=invalid):
                lease = self.root / ('lease-invalid' if invalid else 'lease-valid')
                lease.touch(mode=0o600)
                owner = ownership.Registry(Path(str(lease) + '.registry'), command=mock.Mock())
                row = dict(schema=1, registry=owner.registry_id, generation=owner.generation,
                           launch_id=str(uuid.uuid4()), status='released', container='synthetic',
                           image='sha256:' + 'a' * 64, mounts=[], runroot=[])
                owner.write(row); target = owner.root / (row['launch_id'] + '.json')
                needle = b'"schema": 1' if invalid else b'"status": "released"'
                replacement = b'"schema": 9' if invalid else b'"status": "absent"  '
                self.assertEqual(len(needle), len(replacement))
                fd = os.open(target, os.O_RDWR)
                try:
                    with mmap.mmap(fd, 0, access=mmap.ACCESS_WRITE) as mapping:
                        offset = mapping.find(needle); self.assertGreaterEqual(offset, 0)
                        mapping[offset:offset + len(needle)] = needle
                        with maintenance.existing_lease(lease):
                            self.assertEqual(owner.load(), [row])
                            mapping[offset:offset + len(needle)] = replacement
                            if invalid:
                                with self.assertRaises(ownership.RegistryError):owner.load()
                            else:
                                current = owner.load()[0]
                                self.assertEqual(current['status'], 'absent')
                                self.assertEqual(current['runroot'], [])
                finally:os.close(fd)
                owner.command.assert_not_called()

    def test_proof_reader_rejects_changed_mapping_even_when_stat_can_stay_equal(self):
        reader = cleanup.Reader()
        fd = os.open(self.path, os.O_RDWR)
        try:
            with mmap.mmap(fd, 0, access=mmap.ACCESS_WRITE) as mapping:
                offset = mapping.find(b'aaaaaaaa'); mapping[offset:offset + 8] = b'aaaaaaaa'
                reader.read(self.path, private=True)
                mapping[offset:offset + 8] = b'bbbbbbbb'
                with self.assertRaises(ownership.RegistryError):reader.read(self.path, private=True)
                fresh, unused = cleanup.Reader().read(self.path, private=True)
                self.assertEqual(fresh, {'tag': 'bbbbbbbb'})
        finally:os.close(fd)

    def test_short_descriptor_reads_are_joined_without_truncation(self):
        actual = os.read
        with mock.patch.object(os, 'read', side_effect=lambda fd, maximum: actual(fd, min(3, maximum))):
            self.assertEqual(ownership.read_private(self.path), {'tag': 'aaaaaaaa'})
            value, unused = cleanup.Reader().read(self.path, private=True)
            self.assertEqual(value, {'tag': 'aaaaaaaa'})

    def test_existing_binary_json_encodings_are_preserved(self):
        for encoding in ('utf-8', 'utf-16', 'utf-32'):
            with self.subTest(encoding=encoding):
                self.path.write_bytes('{"tag":"synthetic"}'.encode(encoding))
                self.assertEqual(ownership.read_private(self.path), {'tag': 'synthetic'})

    def test_empty_zero_limit_proof_and_stricter_repeat_stay_bounded(self):
        self.path.write_bytes(b''); reader = cleanup.Reader()
        body, unused = reader.read_bytes(self.path, private=True, maximum=0)
        self.assertEqual(body, b''); self.assertEqual(reader.bytes, 0)
        self.path.write_bytes(b'x')
        with self.assertRaises(ownership.RegistryError):reader.read_bytes(self.path, private=True, maximum=100)
        self.assertEqual(reader.maximums[str(self.path)], 0)

    def test_io_and_json_failures_close_original_descriptor(self):
        for proof in (False, True):
            for failure in ('io', 'json'):
                with self.subTest(proof=proof, failure=failure):
                    self.path.write_bytes(b'not-json' if failure == 'json' else b'{}')
                    actual_open = os.open; opened = []
                    def tracked(path, flags, *args, **kwargs):
                        fd = actual_open(path, flags, *args, **kwargs)
                        opened.append(fd); return fd
                    with mock.patch.object(os, 'open', side_effect=tracked):
                        with mock.patch.object(os, 'read', side_effect=OSError(errno.EIO, 'synthetic')) if failure == 'io' else contextlib.nullcontext():
                            with self.assertRaises((OSError, ValueError, ownership.RegistryError)):
                                (cleanup.Reader().read(self.path, private=True) if proof else ownership.read_private(self.path))
                    for fd in set(opened):
                        with self.assertRaises(OSError):os.fstat(fd)

    def test_registry_growth_during_read_cannot_allocate_an_unbounded_body(self):
        actual = os.read; requested = []; grown = []
        def grow(fd, maximum):
            if not grown:
                grown.append(True); self.path.write_bytes(b' ' * (2 * 1024 * 1024))
            body = actual(fd, maximum); requested.append(len(body)); return body
        with mock.patch.object(os, 'read', side_effect=grow):
            with self.assertRaises(ownership.RegistryError):ownership.read_private(self.path)
        self.assertEqual(sum(requested), 1024 * 1024 + 1)

    def test_native_read_stage_keeps_all_directory_opens_without_wrapper_events(self):
        # A separate interpreter owns this real audit hook. Startup is excluded;
        # this is a synthetic read-stage count, never production budget-fit proof.
        program = '''
import json,os,sys,tempfile
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import ownership_registry as ownership
import application_owner_cleanup as cleanup
with tempfile.TemporaryDirectory() as text:
 root=Path(text).resolve(); path=root/'record.json'
 path.write_text('{"tag":"synthetic"}');path.chmod(0o600)
 count=[0]
 def hook(event,args):
  if event=='open':count[0]+=1
 sys.addaudithook(hook)
 ownership.read_private(path);record_count=count[0];count[0]=0
 cleanup.Reader().read(path,private=True);proof_count=count[0]
 print(json.dumps({'record':record_count,'proof':proof_count,'depth':len(path.parent.parts)-1}))
'''
        result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', program, str(SCRIPTS)],
                                capture_output=True, text=True, env={}, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        counts = json.loads(result.stdout)
        self.assertEqual(counts['record'], 1)
        self.assertEqual(counts['proof'], 2 * counts['depth'] + 3)
