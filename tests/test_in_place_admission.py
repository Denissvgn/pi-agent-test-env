"""Full mounted-tree admission through _execute_suite; no Docker/Pi/model calls."""
import contextlib
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = (Path(__file__).resolve().parents[1] / 'skill')
sys.path.insert(0, str(ROOT / 'scripts'))
import pi_lab as lab
import outcomes


class StageBoundaryReached(Exception):
    pass


class InPlaceAdmissionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pi-admission-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.project = self.root / 'project'
        self.project.mkdir()
        (self.project / 'app.py').write_text('value = 0\n')
        self.sentinel = self.root / 'outside.txt'
        self.sentinel.write_bytes(b'outside remains unchanged\n')
        self.expected_sentinel = self.sentinel.read_bytes()
        self.outside = self.root / 'outside-directory'
        self.outside.mkdir()
        (self.outside / 'secret').write_text('outside directory data')
        self.endpoint = self.root / 'endpoint.json'
        self.endpoint.write_text(json.dumps({
            'base_url': 'http://fixture.invalid/v1', 'model': 'synthetic',
            'api_key_env': 'FIXTURE_KEY', 'context_window': 4096, 'max_tokens': 64}))
        self.plan = self.root / 'plan.json'
        self.plan.write_text(json.dumps({'schema': 1,
            'agents': [{'prompt': 'Synthetic boundary fixture.', 'tools': ['read'], 'require_tools': ['read']}],
            'checks': [{'argv': ['true']}], 'protected_paths': []}))

    def execute_until_boundary(self, *, in_place=True, excludes=(), inspection=None):
        argv = ['run', '--project', str(self.project), '--plan', str(self.plan),
                '--endpoint', str(self.endpoint), '--results-dir', str(self.root / 'runs')]
        if in_place:
            argv.append('--in-place')
        for name in excludes:
            argv += ['--exclude', name]
        args = lab.parser().parse_args(argv)
        attempt = outcomes.Attempt(args)
        with contextlib.ExitStack() as stack:
            # Only host/image/secret/launch boundaries are replaced. Admission,
            # plan checks, inventory, snapshots and attempt persistence are real.
            host = stack.enter_context(patch.object(lab, 'require_host', return_value={}))
            probe = stack.enter_context(patch.object(lab, 'probe_image', return_value={
                'id': 'sha256:' + 'a' * 64, 'capabilities': {'pi': '0.87.1'}}))
            secret = stack.enter_context(patch.object(lab, 'endpoint_secret', return_value=''))
            stage = stack.enter_context(patch.object(lab, 'run_stage', side_effect=StageBoundaryReached))
            if inspection is not None:
                stack.enter_context(inspection)
            error = None
            try:
                lab._execute_suite(args, attempt)
            except (lab.LabError, StageBoundaryReached) as exc:
                error = exc
            # Image-only host probes precede project admission and are allowed.
            host.assert_called_once()
            probe.assert_called_once()
            secret.assert_called_once()
        self.assertEqual(self.sentinel.read_bytes(), self.expected_sentinel)
        self.assertEqual((self.outside / 'secret').read_text(), 'outside directory data')
        return error, stage, attempt

    def assert_rejected(self, **kwargs):
        error, stage, attempt = self.execute_until_boundary(**kwargs)
        self.assertIsInstance(error, lab.LabError)
        stage.assert_not_called()
        self.assertEqual(attempt.record['invocation']['attempted_stages'], 0)
        return error

    def test_hardlinks_in_every_excluded_directory_and_nested_variants(self):
        for excluded in sorted(lab.EXCLUDES):
            for nested in (False, True):
                with self.subTest(excluded=excluded, nested=nested):
                    folder = self.project / ('nested' if nested else '.') / excluded / 'deep'
                    folder.mkdir(parents=True)
                    alias = folder / 'shared'
                    os.link(self.sentinel, alias)
                    try:
                        self.assert_rejected()
                    finally:
                        alias.unlink()

    def test_file_directory_and_dangling_symlinks_in_every_excluded_name(self):
        for excluded in sorted(lab.EXCLUDES):
            for kind, target in [('file', self.sentinel), ('directory', self.outside),
                                 ('dangling', self.root / 'missing')]:
                with self.subTest(excluded=excluded, kind=kind):
                    # Use the excluded name itself: os.walk previously removed
                    # directory symlinks before examining their metadata.
                    alias = self.project / excluded
                    alias.symlink_to(target, target_is_directory=kind == 'directory')
                    try:
                        self.assert_rejected()
                    finally:
                        alias.unlink()

    def test_nested_symlinks_and_ordinary_hardlinks_reject_without_following(self):
        folder = self.project / 'nested/.git/deep'
        folder.mkdir(parents=True)
        for target in (self.sentinel, self.outside, self.root / 'absent', self.project):
            with self.subTest(target=target):
                alias = folder / 'alias'
                alias.symlink_to(target)
                try:
                    self.assert_rejected()
                finally:
                    alias.unlink()
        ordinary = self.project / 'ordinary-hardlink'
        os.link(self.sentinel, ordinary)
        self.assert_rejected()

    def test_directory_symlink_target_is_never_enumerated(self):
        (self.project / '.git').symlink_to(self.outside, target_is_directory=True)
        outside_inode = self.outside.stat().st_ino
        original = os.scandir

        def forbid_target(path):
            info = os.fstat(path) if isinstance(path, int) else os.stat(path)
            self.assertNotEqual(info.st_ino, outside_inode, 'Admission followed an excluded directory link')
            return original(path)

        error = self.assert_rejected(inspection=patch.object(lab.os, 'scandir', side_effect=forbid_target))
        self.assertEqual(error.reason, 'in-place-linked-entry')

    def test_user_exclusions_and_secret_names_do_not_hide_hazards(self):
        for name in ('user-omission', '.env', '.env.private', 'credential.pem', 'id_ed25519'):
            with self.subTest(name=name):
                folder = self.project / name / 'deep'
                folder.mkdir(parents=True)
                alias = folder / 'shared'
                os.link(self.sentinel, alias)
                try:
                    self.assert_rejected(excludes=('user-*', '*'))
                finally:
                    alias.unlink()

    def test_lstat_errors_and_disappearing_entries_block(self):
        folder = self.project / '.git/deep'
        folder.mkdir(parents=True)
        victim = folder / 'entry'
        victim.write_text('safe')
        original = os.lstat
        for failure in (PermissionError(errno.EACCES, 'injected inspection denial'),
                        FileNotFoundError(errno.ENOENT, 'injected disappearance')):
            def failing(path, *args, **kwargs):
                if Path(path).name == 'entry':
                    raise failure
                return original(path, *args, **kwargs)
            with self.subTest(error=type(failure).__name__):
                error = self.assert_rejected(inspection=patch.object(lab.os, 'lstat', side_effect=failing))
                self.assertEqual(error.reason, 'in-place-inspection-error')
                self.assertIn('.git/deep/entry', str(error))

    def test_scandir_error_blocks_even_for_an_excluded_directory(self):
        folder = self.project / '.aws/deep'
        folder.mkdir(parents=True)
        inode = folder.stat().st_ino
        original = os.scandir

        def failing(path):
            info = os.fstat(path) if isinstance(path, int) else os.stat(path)
            if info.st_ino == inode:
                raise PermissionError(errno.EACCES, 'injected enumeration denial')
            return original(path)

        error = self.assert_rejected(inspection=patch.object(lab.os, 'scandir', side_effect=failing))
        self.assertEqual(error.reason, 'in-place-inspection-error')
        self.assertIn('.aws/deep', str(error))

    def test_iteration_failure_after_an_entry_blocks_and_closes_directory_descriptors(self):
        folder = self.project / '.aws/deep'
        folder.mkdir(parents=True)
        (folder / 'regular').write_text('safe')
        inode = folder.stat().st_ino
        original_scandir, original_open, original_close = os.scandir, os.open, os.close
        active = set()

        def opening(*args, **kwargs):
            fd = original_open(*args, **kwargs)
            if args[1] & os.O_DIRECTORY:
                active.add(fd)
            return fd

        def closing(fd):
            original_close(fd)
            active.discard(fd)

        @contextlib.contextmanager
        def enumeration(path):
            info = os.fstat(path) if isinstance(path, int) else os.stat(path)
            with original_scandir(path) as entries:
                if info.st_ino == inode:
                    def broken():
                        yield next(entries)
                        raise PermissionError(errno.EACCES, 'injected partial enumeration failure')
                    yield broken()
                else:
                    yield entries

        with patch.object(lab.os, 'open', side_effect=opening), patch.object(lab.os, 'close', side_effect=closing):
            error = self.assert_rejected(inspection=patch.object(lab.os, 'scandir', side_effect=enumeration))
            self.assertFalse(active, 'Admission leaked directory descriptors after enumeration failed')
        self.assertEqual(error.reason, 'in-place-inspection-error')
        self.assertIn('.aws/deep', str(error))

    def test_unopenable_directory_blocks_before_any_writable_stage(self):
        (self.project / '.git/deep').mkdir(parents=True)
        original = os.open

        def failing(path, flags, *args, **kwargs):
            if Path(path).name == 'deep' and flags & os.O_DIRECTORY:
                raise PermissionError(errno.EACCES, 'injected directory-open denial')
            return original(path, flags, *args, **kwargs)

        error = self.assert_rejected(inspection=patch.object(lab.os, 'open', side_effect=failing))
        self.assertEqual(error.reason, 'in-place-inspection-error')
        self.assertIn('.git/deep', str(error))

    def test_safe_complete_tree_accepts_directory_link_counts_and_preserves_inventory(self):
        for excluded in sorted(lab.EXCLUDES):
            folder = self.project / excluded / 'nested/deep'
            folder.mkdir(parents=True)
            (folder / 'regular').write_text('safe excluded file')
        (self.project / '.env').write_text('synthetic private content')
        self.assertGreater((self.project / '.git').stat().st_nlink, 1)
        before = lab.tree_hashes(self.project)
        error, stage, attempt = self.execute_until_boundary(excludes=('*',))
        self.assertIsInstance(error, StageBoundaryReached)
        stage.assert_called_once()
        self.assertEqual(stage.call_args.args[3], self.project)
        self.assertEqual(stage.call_args.args[4:6], ('boundary', ['boundary']))
        self.assertEqual(stage.call_args.kwargs.get('access', 'rw'), 'rw')
        self.assertEqual(attempt.record['workspace_mode'], 'IN_PLACE_ORIGINAL_FILES')
        self.assertEqual(before, json.loads((attempt.root / 'files-before.json').read_text()))
        self.assertNotIn('.git/nested/deep/regular', before)
        self.assertEqual(lab.tree_hashes(self.project), before)

    def test_default_snapshot_materializes_hardlinks_and_preserves_omissions(self):
        linked = self.project / 'hardlinked.txt'
        os.link(self.sentinel, linked)
        for excluded in sorted(lab.EXCLUDES):
            folder = self.project / excluded
            folder.mkdir()
            os.link(self.sentinel, folder / 'hidden-hardlink')
        (self.project / '.env').write_text('synthetic private content')
        (self.project / 'key.pem').write_text('synthetic key-shaped content')
        (self.project / 'ignored.custom').write_text('user excluded')
        (self.project / 'outside-link').symlink_to(self.sentinel)
        error, stage, attempt = self.execute_until_boundary(in_place=False, excludes=('*.custom',))
        self.assertIsInstance(error, StageBoundaryReached)
        stage.assert_called_once()
        workspace = stage.call_args.args[3]
        self.assertNotEqual(workspace, self.project)
        self.assertEqual(attempt.record['workspace_mode'], 'isolated-copy')
        copied = workspace / 'hardlinked.txt'
        self.assertEqual(copied.stat().st_nlink, 1)
        self.assertNotEqual((copied.stat().st_dev, copied.stat().st_ino),
                            (linked.stat().st_dev, linked.stat().st_ino))
        self.assertEqual({p.name for p in workspace.iterdir()}, {'app.py', 'hardlinked.txt'})
        # A real key-free local subprocess writes the copy; host aliases retain
        # their original bytes. This is not a Docker/Pi/model qualification.
        result = subprocess.run([sys.executable, '-c',
            'from pathlib import Path; import sys; Path(sys.argv[1]).write_text("changed copy")',
            str(copied)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(copied.read_text(), 'changed copy')
        self.assertEqual(linked.read_bytes(), self.expected_sentinel)
        self.assertEqual(self.sentinel.read_bytes(), self.expected_sentinel)
        self.assertEqual((self.project / 'app.py').read_text(), 'value = 0\n')


if __name__ == '__main__':
    unittest.main()
