"""Red-first persistence/fresh-consumer faults in disposable synthetic registries."""
import contextlib
import argparse
import errno
import importlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from tests.test_application_owner_legacy_support import AcceptanceFixture
import application_owner_cleanup as cleanup
import registry_maintenance as maintenance
import ownership_registry as ownership


class LegacyLifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve(); self.calls = []
        self.lease = self.root / 'lease'; self.lease.write_text('original lease\n'); self.lease.chmod(0o600)
        self.owner = ownership.Registry(Path(str(self.lease) + '.registry'), command=self.command)
        self.owner.bind_daemon('synthetic-daemon')
        self.fixture = AcceptanceFixture(self.root / 'case', registry_id=self.owner.registry_id,
                                         generation=self.owner.generation)
        self.owner.write(self.fixture.record)
        for name in ('run', 'Popen'):
            patch = mock.patch.object(subprocess, name, side_effect=AssertionError('No real native process allowed'))
            patch.start(); self.addCleanup(patch.stop)
        patch = mock.patch.object(os, 'kill', side_effect=ProcessLookupError(errno.ESRCH, 'synthetic absent PID'))
        patch.start(); self.addCleanup(patch.stop)

    @staticmethod
    def reply(code, out='', err=''):
        return type('Reply', (), {'returncode': code, 'stdout': out, 'stderr': err})()

    def command(self, argv):
        self.calls.append(list(argv))
        if argv == ['docker', 'info', '--format', '{{.ID}}']:return self.reply(0, 'synthetic-daemon\n')
        if argv[:3] == ['docker', 'container', 'inspect']:
            return self.reply(1, '' if '--format' in argv else '[]\n', 'Error response from daemon: No such container: ' + argv[-1])
        if argv[:2] == ['docker', 'ps']:return self.reply(0)
        raise AssertionError('Unapproved/effectful native call: ' + repr(argv))

    def fresh(self):
        return ownership.Registry(self.owner.root, command=self.command, create=False)

    @contextlib.contextmanager
    def held(self, owner=None):
        owner = self.owner if owner is None else owner
        with maintenance.existing_lease(self.lease) as (fd, identity, selected):
            owner.lease_fd = fd
            yield owner

    def recover(self, output=None):
        api = importlib.import_module('application_owner_legacy')
        with mock.patch.dict(api.SOURCE_FAMILIES, self.fixture.family(), clear=True):
            with self.held():
                return cleanup.recover(self.owner, self.fixture.request(), output or self.root / 'recovery',
                                       discard_workspace=True)

    def replay(self, owner=None):
        api = importlib.import_module('application_owner_legacy')
        with mock.patch.dict(api.SOURCE_FAMILIES, self.fixture.family(), clear=True):
            with self.held(owner):
                return cleanup.validate_accepted(self.owner if owner is None else owner, self.fixture.record)

    def protected(self):
        return {ref['path']: Path(ref['path']).read_bytes() for name, ref in self.fixture.refs.items()
                if Path(ref['path']).is_relative_to(self.fixture.run)}

    def test_complete_publication_preserves_primary_and_failed_metadata(self):
        original = (self.owner.root / (self.fixture.launch_id + '.json')).read_bytes(); before = self.protected()
        result = self.recover()
        self.assertEqual(result['status'], 'CLEANED'); self.assertTrue(result['cleanup_completed'])
        self.assertFalse(result['admission_authorized']); self.assertFalse(result['original_outcome_regraded'])
        self.assertEqual((self.owner.root / (self.fixture.launch_id + '.json')).read_bytes(), original)
        self.assertEqual(self.protected(), before)
        self.assertTrue(self.replay(self.fresh()))
        api = importlib.import_module('application_owner_legacy'); fresh = self.fresh()
        with mock.patch.dict(api.SOURCE_FAMILIES, self.fixture.family(), clear=True):
            with self.held(fresh):self.assertEqual(fresh.validate_history(fresh.load()), [])

    def test_replay_is_passive_with_fresh_registry_and_no_old_pid_probes(self):
        self.recover(); owner = self.fresh(); self.calls.clear()
        with mock.patch.object(os, 'kill', side_effect=AssertionError('Passive replay probed old PID')):
            self.assertTrue(self.replay(owner))
        self.assertEqual(self.calls, [])

    def test_each_selected_record_loss_denies_all_released_history_after_restart(self):
        self.recover()
        index = cleanup._index(self.owner, self.fixture.record)
        document = json.loads(index.read_bytes()); terminal = Path(document['receipt']['path'])
        receipt = json.loads(terminal.read_bytes())
        anchor_dir = self.owner.root.with_name(self.owner.root.name + '.owner-selected')
        paths = [index, cleanup._selection(self.owner, self.fixture.record), terminal,
                 Path(receipt['intent']['path']), anchor_dir / (self.fixture.launch_id + '.json')]
        for target in paths:
            with self.subTest(target=target.name):
                saved = target.with_suffix('.saved'); target.rename(saved)
                try:
                    fresh = self.fresh()
                    with self.assertRaises(ownership.RegistryError):self.replay(fresh)
                    with self.assertRaises(ownership.RegistryError):
                        with self.held(fresh):fresh.validate_history(fresh.load())
                finally:saved.rename(target)

    def test_whole_store_loss_does_not_erase_independent_selection(self):
        self.recover(); shutil.rmtree(cleanup.store_path(self.owner))
        fresh = self.fresh()
        with self.assertRaises(ownership.RegistryError):self.replay(fresh)
        with self.assertRaises(ownership.RegistryError):
            with self.held(fresh):fresh.validate_history(fresh.load())

    def test_partial_purge_intent_without_terminal_never_becomes_accepted(self):
        purge = cleanup._purge; count = [0]
        def interrupted(observation, **kwargs):
            purge(observation, **kwargs)
            if observation['state'] == 'present':
                count[0] += 1
                raise KeyboardInterrupt()
        with mock.patch.object(cleanup, '_purge', side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):self.recover()
        self.assertEqual(count[0], 1)
        # Missing best-effort failure is a valid hard-kill durable image.
        for target in (self.root / 'recovery').glob('failure.json'):target.unlink()
        with self.assertRaises(ownership.RegistryError):self.replay(self.fresh())

    def test_replaced_scope_is_not_deleted_via_held_authority_for_old_inode(self):
        original = cleanup._purge; replaced = [False]; sentinel = [None]
        def replace(observation, **kwargs):
            if observation['state'] == 'present' and not replaced[0]:
                target = Path(observation['path']); target.rename(self.root / 'saved-scope')
                target.mkdir(mode=0o700); sentinel[0] = target / 'sentinel'; sentinel[0].write_text('keep')
                replaced[0] = True
            return original(observation, **kwargs)
        with mock.patch.object(cleanup, '_purge', side_effect=replace):
            with self.assertRaises(ownership.RegistryError):self.recover()
        self.assertTrue(replaced[0]); self.assertEqual(sentinel[0].read_text(), 'keep')

    def test_replaced_output_parent_cannot_redirect_receipt_writes(self):
        bucket = self.root / 'output-parent'; bucket.mkdir(mode=0o700); output = bucket / 'receipt'
        original = os.fsync; replaced = [False]
        def replace(fd):
            if output.exists() and not replaced[0]:
                bucket.rename(self.root / 'saved-parent'); bucket.mkdir(mode=0o700); replaced[0] = True
            return original(fd)
        with mock.patch.object(os, 'fsync', side_effect=replace):
            with self.assertRaises((ownership.RegistryError, OSError)):self.recover(output)
        self.assertTrue(replaced[0]); self.assertEqual(list(bucket.iterdir()), [])

    def test_terminal_is_not_rewritten_after_index_publication_failure(self):
        # The common publisher remains the compatibility dispatch seam.
        with mock.patch.object(cleanup, '_publish_index', side_effect=OSError('synthetic I/O error')):
            with self.assertRaises((ownership.RegistryError, OSError)):self.recover()
        terminal = self.root / 'recovery' / 'terminal.json'
        self.assertTrue(terminal.is_file())
        value = json.loads(terminal.read_bytes())
        self.assertEqual(value['status'], 'CLEANED'); self.assertTrue(value['cleanup_completed'])
        with self.assertRaises(ownership.RegistryError):self.replay(self.fresh())

    def test_replaced_selected_store_cannot_redirect_later_publication(self):
        store = cleanup.store_path(self.owner)
        selection = cleanup._selection(self.owner, self.fixture.record)
        original = os.fsync; replaced = [False]
        def replace(fd):
            if selection.exists() and not replaced[0]:
                store.rename(self.root / 'saved-store'); store.mkdir(mode=0o700); replaced[0] = True
            return original(fd)
        with mock.patch.object(os, 'fsync', side_effect=replace):
            with self.assertRaises((ownership.RegistryError, OSError)):self.recover()
        self.assertTrue(replaced[0]); self.assertEqual(list(store.iterdir()), [])

    def test_close_error_after_index_creation_remains_inconclusive(self):
        output = self.root / 'recovery'; index = cleanup._index(self.owner, self.fixture.record)
        original = os.close; failed = [False]
        def fail(fd):
            info = os.fstat(fd)
            target = output.stat() if output.exists() else None
            matches = target is not None and (info.st_dev, info.st_ino) == (target.st_dev, target.st_ino)
            if matches and index.exists() and not failed[0]:
                failed[0] = True; original(fd)
                raise OSError('synthetic directory close failure')
            return original(fd)
        with mock.patch.object(os, 'close', side_effect=fail):
            with self.assertRaises((ownership.RegistryError, OSError)):self.recover()
        self.assertTrue(failed[0])
        terminal = json.loads((output / 'terminal.json').read_bytes())
        self.assertEqual(terminal['status'], 'CLEANED')

    def test_unknown_selected_version_does_not_fall_back_to_old_methods(self):
        self.recover(); index = cleanup._index(self.owner, self.fixture.record)
        value = json.loads(index.read_bytes()); value['schema'] = 999
        index.write_text(json.dumps(value))
        with self.assertRaises(ownership.RegistryError):self.replay(self.fresh())

    def test_malformed_private_input_never_appears_in_public_cli_result(self):
        sentinel = 'SYNTHETIC_PRIVATE_VALUE_MUST_NOT_APPEAR'
        request = self.root / 'malformed.json'
        request.write_text('{"schema":2,"private":"' + sentinel + '" invalid}')
        request.chmod(0o600)
        args = argparse.Namespace(op='application-owner-recover', lock_file=str(self.lease),
            lock_wait_seconds=0, request=str(request), output_dir=str(self.root / 'recovery'),
            discard_workspace=True)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):code = cleanup.command(args)
        result = stdout.getvalue()
        self.assertNotEqual(code, 0); self.assertNotIn(sentinel, result)
        self.assertNotIn(str(request), result); self.assertNotIn(str(self.lease), result)
        self.assertFalse(json.loads(result)['admission_authorized'])

    def test_every_fsync_boundary_has_truthful_failure_or_complete_passive_proof(self):
        # Count the real protocol's barriers; do not assume a fixed ordering count.
        original = os.fsync; barriers = [0]
        def count(fd):barriers[0] += 1; return original(fd)
        with mock.patch.object(os, 'fsync', side_effect=count):self.recover()
        self.assertGreaterEqual(barriers[0], 8)
        for ordinal in range(1, barriers[0] + 1):
            with self.subTest(ordinal=ordinal):
                # Each failure gets an independent original lease/registry/run.
                case = LegacyLifecycleTests('test_complete_publication_preserves_primary_and_failed_metadata')
                case.setUp()
                try:
                    seen = [0]; before = case.protected()
                    def fail(fd):
                        seen[0] += 1
                        if seen[0] == ordinal:raise OSError('synthetic fsync failure')
                        return original(fd)
                    with mock.patch.object(os, 'fsync', side_effect=fail):
                        with self.assertRaises((ownership.RegistryError, OSError)):case.recover()
                    self.assertEqual(case.protected(), before)
                    try:accepted = case.replay(case.fresh())
                    except ownership.RegistryError:accepted = False
                    if accepted:
                        # A later successful passive inspection may confirm a
                        # logically complete graph after inconclusive fsync.
                        self.assertFalse(case.fixture.workspace.exists())
                        self.assertFalse(case.fixture.private.exists())
                finally:case.doCleanups()
