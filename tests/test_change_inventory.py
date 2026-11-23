"""The change record of a run: every shape of change, with synthetic fixtures only."""
import contextlib
import io
import json
import os
from pathlib import Path
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1] / 'skill'
sys.path.insert(0, str(ROOT / 'scripts'))
import pi_lab as lab
import outcomes
from test_results import fixture, mocked_suite

AS_ROOT = hasattr(os, 'geteuid') and os.geteuid() == 0


def seed_project(project):
    (project / 'sub').mkdir()
    (project / 'sub' / 'inner.txt').write_text('inner')
    for name, mode in (('tool.sh', 0o644), ('gone.txt', 0o644), ('edit.txt', 0o644), ('plain.txt', 0o644)):
        (project / name).write_text(name)
        os.chmod(project / name, mode)


def observe(mutate, checks=None, **options):
    """Run the suite with a mocked agent stage that applies `mutate` to the workspace."""
    with tempfile.TemporaryDirectory() as td, contextlib.ExitStack() as stack:
        top = Path(td)
        a = fixture(top)
        seed_project(top / 'project')
        if checks:
            plan = json.loads(Path(a.plan).read_text())
            plan['checks'] = checks
            lab.save(Path(a.plan), plan)
        stages = []

        def fake_stage(args, image, run, workspace, label, operation, **kw):
            stages.append(label)
            (run / label).mkdir()
            if label.startswith('agent'):
                mutate(workspace)
            return {'exit_code': 0, 'cleanup_confirmed': True}
        mocked_suite(stack)
        stack.enter_context(mock.patch.object(lab, 'run_stage', side_effect=fake_stage))
        stderr = io.StringIO()
        stack.enter_context(contextlib.redirect_stderr(stderr))
        code = lab.run_suite(a)
        run = (top / 'results' / 'latest').resolve()
        read = lambda name: lab.controls.read(run / name) if (run / name).exists() else None
        return {'code': code, 'result': read('result.json'), 'summary': read('summary.json'),
                'changes': read('changes.json'), 'stderr': stderr.getvalue(), 'stages': stages}


def add(ws):
    (ws / 'new.txt').write_text('new')


def modify(ws):
    (ws / 'edit.txt').write_text('edited')


def delete(ws):
    (ws / 'gone.txt').unlink()


def mode_only(ws):
    os.chmod(ws / 'tool.sh', 0o755)


def dir_to_file(ws):
    shutil.rmtree(ws / 'sub')
    (ws / 'sub').write_text('now a file')


def file_to_dir(ws):
    (ws / 'plain.txt').unlink()
    (ws / 'plain.txt').mkdir()
    (ws / 'plain.txt' / 'x').write_text('x')


def file_to_link(ws):
    (ws / 'edit.txt').unlink()
    os.symlink('tool.sh', ws / 'edit.txt')


def link_to_file(ws):
    file_to_link(ws)
    (ws / 'edit.txt').unlink()
    (ws / 'edit.txt').write_text('back')


def under_node_modules(ws):
    (ws / 'node_modules' / 'pkg').mkdir(parents=True)
    (ws / 'node_modules' / 'pkg' / 'index.js').write_text('x')


def npmrc(ws):
    (ws / '.npmrc').write_text('synthetic')


def fifo(ws):
    os.mkfifo(ws / 'pipe')


def mode_zero(ws):
    (ws / 'locked.txt').write_text('synthetic')
    os.chmod(ws / 'locked.txt', 0)


def secret_names(ws):
    (ws / 'api.key').write_text('synthetic')
    (ws / '.env.local').write_text('synthetic')


NO_COUNTS = dict.fromkeys(('added', 'modified', 'deleted', 'mode_only', 'type_changed', 'links'), 0)

# name, mutation, changed paths, non-zero counts, omitted (path, rule, kind)
SHAPES = [
    ('added', add, ['new.txt'], {'added': 1}, []),
    ('modified', modify, ['edit.txt'], {'modified': 1}, []),
    ('deleted', delete, ['gone.txt'], {'deleted': 1}, []),
    ('mode only', mode_only, ['tool.sh'], {'mode_only': 1}, []),
    ('directory to file', dir_to_file, ['sub', 'sub/inner.txt'], {'type_changed': 1, 'deleted': 1}, []),
    ('file to directory', file_to_dir, ['plain.txt', 'plain.txt/x'], {'type_changed': 1, 'added': 1}, []),
    ('file to link', file_to_link, ['edit.txt'], {'type_changed': 1, 'links': 1}, []),
    ('link to file', link_to_file, ['edit.txt'], {'modified': 1}, []),
    ('new file under node_modules', under_node_modules, [], {},
     [('node_modules', 'excluded-name:node_modules', 'directory')]),
    ('new .npmrc', npmrc, [], {}, [('.npmrc', 'excluded-name:.npmrc', 'file')]),
    ('fifo', fifo, [], {}, [('pipe', 'special-file', 'fifo')]),
    ('mode 000', mode_zero, [], {}, [('locked.txt', 'unreadable:PermissionError', 'file')]),
    ('names that match a secret pattern', secret_names, ['.env.local', 'api.key'], {'added': 2}, []),
]


class ShapesOfChange(unittest.TestCase):
    def test_every_shape_leaves_the_verdict_to_the_checks(self):
        for name, mutate, paths, counts, omitted in SHAPES:
            with self.subTest(shape=name):
                if name == 'mode 000' and AS_ROOT:
                    self.skipTest('root can read a file with mode 000')
                out = observe(mutate)
                self.assertEqual((out['code'], out['result']['status']), (0, 'PASS'))
                self.assertIn('check-1-oracle', out['stages'])
                self.assertEqual(sorted(out['changes']), paths)
                record = {'schema': 1, **NO_COUNTS, **counts,
                          'omitted': [{'path': p, 'rule': r, 'kind': k} for p, r, k in omitted]}
                self.assertEqual(out['summary']['changes'], record)
                self.assertEqual(out['result']['changes'], record)
                entries = len(out['changes'])
                self.assertEqual(sum(record[k] for k in ('added', 'modified', 'deleted', 'mode_only', 'type_changed')), entries)
                first = out['stderr'].splitlines()[-1]
                self.assertTrue(first.startswith('Changes: ' + ' '.join(f'{k}={record[k]}' for k in NO_COUNTS)))
                if omitted:
                    self.assertIn(f'omitted {len(omitted)}: {omitted[0][0]} ({omitted[0][1]})', first)
                else:
                    self.assertNotIn('omitted', first)

    def test_changes_json_keeps_its_shape(self):
        out = observe(modify)
        entry = out['changes']['edit.txt']
        self.assertEqual(set(entry), {'before', 'after'})
        self.assertRegex(entry['before'], r'^0644:[0-9a-f]{64}$')
        self.assertRegex(entry['after'], r'^0644:[0-9a-f]{64}$')

    def test_a_run_that_stopped_before_the_workspace_has_no_change_record(self):
        self.assertIsNone(outcomes.initial()['changes'])

    def test_a_check_whose_directory_was_replaced_fails_and_the_others_run(self):
        checks = [{'name': 'inside', 'argv': ['true'], 'cwd': 'sub'}, {'name': 'outside', 'argv': ['true']}]
        out = observe(dir_to_file, checks=checks)
        self.assertEqual((out['code'], out['result']['status']), (1, 'FAIL'))
        self.assertNotIn('check-1-inside', out['stages'])
        self.assertIn('check-2-outside', out['stages'])
        first, second = out['result']['checks']
        self.assertEqual((first['scorer']['status'], first['scorer']['reason']), ('error', 'check-target-missing'))
        self.assertTrue(first['process']['cleanup_confirmed'])
        self.assertEqual((second['scorer']['status'], second['scorer']['task_status']), ('completed', 'pass'))
        verdict = outcomes.verdict(out['result'])
        self.assertEqual((verdict['outcome'], verdict['attribution'], verdict['reason']),
                         ('check_failed', 'model', 'check-target-missing'))
        self.assertEqual(out['summary']['scoring']['status'], 'error')

    def test_a_check_in_an_intact_directory_still_runs(self):
        out = observe(add, checks=[{'name': 'inside', 'argv': ['true'], 'cwd': 'sub'}])
        self.assertEqual((out['code'], out['result']['status']), (0, 'PASS'))
        self.assertIn('check-1-inside', out['stages'])

    def test_checks_start_when_a_file_cannot_be_copied_for_scoring(self):
        real = shutil.copy2

        def copy(source, target, *args, **kw):
            if Path(source).name == 'locked.txt':
                raise PermissionError(13, 'Permission denied', str(source))
            return real(source, target, *args, **kw)
        with mock.patch.object(lab.shutil, 'copy2', side_effect=copy):
            out = observe(lambda ws: (ws / 'locked.txt').write_text('synthetic'))
        self.assertEqual((out['code'], out['result']['status']), (0, 'PASS'))
        self.assertIn('check-1-oracle', out['stages'])

    def test_the_project_copy_still_refuses_a_file_it_cannot_read(self):
        real = shutil.copy2

        def copy(source, target, *args, **kw):
            if Path(source).name == 'locked.txt':
                raise PermissionError(13, 'Permission denied', str(source))
            return real(source, target, *args, **kw)
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / 'source'
            source.mkdir()
            (source / 'locked.txt').write_text('synthetic')
            with mock.patch.object(lab.shutil, 'copy2', side_effect=copy), self.assertRaises(PermissionError):
                lab.snapshot(source, Path(td) / 'copy', [], 10)
            with mock.patch.object(lab.shutil, 'copy2', side_effect=copy):
                result = lab.snapshot(source, Path(td) / 'scored', [], 10, score_copy=True)
            self.assertEqual(result['skipped'], ['locked.txt [unreadable]'])


# Recorded from tree_hashes at the v4.11.0 tag for the tree that build_tree makes.
TAG_DIGESTS = {
    'a.txt': '0644:b6a98d9ce9a2d9149288fa3df42d377c3e42737afdcdaf714e33c0a100b51060',
    'link-a': 'symlink:a.txt',
    'run.sh': '0755:a8076d3d28d21e02012b20eaf7dbf75409a6277134439025f282e368e3305abf',
    'src/b.py': '0600:cc42155088fca5730758db72b2a5bca33112a941dfaa2d43098ec422ce4ea213',
    'src/dangling': 'symlink:missing-target',
    'src/deep/c.bin': '0640:10fc3c51a152e90e5b90319b601d92ccf37290ef53c35ff92507687d8a911a08',
    'zero.txt': '0644:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
}


def build_tree(root):
    """Regular files, links, a nested directory and an empty directory with fixed modes."""
    (root / 'src' / 'deep').mkdir(parents=True)
    (root / 'empty').mkdir()
    files = {'a.txt': (b'alpha\n', 0o644), 'run.sh': (b'#!/bin/sh\n', 0o755),
             'src/b.py': (b'print(1)\n', 0o600), 'src/deep/c.bin': (bytes(range(256)) * 8, 0o640),
             'zero.txt': (b'', 0o644)}
    for name, (data, mode) in files.items():
        (root / name).write_bytes(data)
        os.chmod(root / name, mode)
    os.symlink('a.txt', root / 'link-a')
    os.symlink('missing-target', root / 'src' / 'dangling')


class TreeHashes(unittest.TestCase):
    def test_values_for_regular_files_and_links_match_the_tag(self):
        with tempfile.TemporaryDirectory() as td:
            build_tree(Path(td))
            self.assertEqual(lab.tree_hashes(Path(td)), TAG_DIGESTS)
            self.assertEqual(lab.tree_hashes(Path(td), include_ignored=True), TAG_DIGESTS)
            collected = []
            self.assertEqual(lab.tree_hashes(Path(td), omitted=collected), TAG_DIGESTS)
            self.assertEqual(collected, [])

    def test_collecting_leaves_every_hash_as_it_was(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            build_tree(root)
            (root / 'node_modules').mkdir()
            (root / 'node_modules' / 'x.js').write_text('x')
            (root / '.npmrc').write_text('x')
            os.mkfifo(root / 'pipe')
            self.assertEqual(lab.tree_hashes(root, omitted=[]), lab.tree_hashes(root))
            self.assertEqual(lab.tree_hashes(root, include_ignored=True, omitted=[]),
                             lab.tree_hashes(root, include_ignored=True))

    def test_only_the_topmost_excluded_path_is_listed_and_links_are_not_followed(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as outside:
            root = Path(td)
            (Path(outside) / 'deep').mkdir()
            (Path(outside) / 'deep' / 'file.txt').write_text('outside')
            (root / 'node_modules' / 'a' / 'b').mkdir(parents=True)
            (root / 'node_modules' / 'a' / 'b' / '.npmrc').write_text('x')
            (root / 'src').mkdir()
            (root / 'src' / '.venv').mkdir()
            (root / 'src' / '.venv' / 'lib.py').write_text('x')
            os.symlink(outside, root / '.aws')
            collected = []
            hashes = lab.tree_hashes(root, omitted=collected)
            self.assertEqual(hashes, {})
            self.assertEqual(sorted((r['path'], r['rule'], r['kind']) for r in collected),
                             [('.aws', 'excluded-name:.aws', 'symlink'),
                              ('node_modules', 'excluded-name:node_modules', 'directory'),
                              ('src/.venv', 'excluded-name:.venv', 'directory')])

    def test_an_unreadable_file_is_listed_and_does_not_raise(self):
        real = pathlib.Path.open

        def opener(self, *args, **kw):
            if self.name == 'locked.txt':
                raise PermissionError(13, 'Permission denied', str(self))
            return real(self, *args, **kw)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'locked.txt').write_text('x')
            (root / 'fine.txt').write_text('y')
            with mock.patch.object(pathlib.Path, 'open', opener):
                collected = []
                self.assertEqual(sorted(lab.tree_hashes(root, omitted=collected)), ['fine.txt'])
                self.assertEqual(collected, [{'path': 'locked.txt', 'rule': 'unreadable:PermissionError', 'kind': 'file'}])
                with self.assertRaises(PermissionError):
                    lab.tree_hashes(root)

    @unittest.skipIf(AS_ROOT, 'root can list a directory with mode 000')
    def test_an_unlistable_directory_is_listed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'closed').mkdir()
            (root / 'closed' / 'f.txt').write_text('x')
            os.chmod(root / 'closed', 0)
            try:
                collected = []
                self.assertEqual(lab.tree_hashes(root, omitted=collected), {})
            finally:
                os.chmod(root / 'closed', 0o700)
            self.assertEqual(collected, [{'path': 'closed', 'rule': 'unreadable:PermissionError', 'kind': 'directory'}])


class ChangeRecord(unittest.TestCase):
    def test_the_list_is_capped_with_a_total(self):
        rows = [{'path': f'p{i:04d}', 'rule': 'special-file', 'kind': 'fifo'} for i in range(501)]
        record = lab.change_record({}, {}, [], list(reversed(rows)), Path('.'), False, 0)
        self.assertEqual(len(record['omitted']), lab.OMITTED_LIMIT)
        self.assertEqual(record['omitted_total'], 501)
        self.assertEqual(record['omitted'][0]['path'], 'p0000')
        exact = lab.change_record({}, {}, [], rows[:500], Path('.'), False, 0)
        self.assertNotIn('omitted_total', exact)
        self.assertTrue(lab.change_line(record).endswith('omitted 501: p0000 (special-file), p0001 (special-file), '
                                                          'p0002 (special-file)'))

    def test_an_excluded_path_that_existed_is_listed_in_place_only_when_modified_after_the_start(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'node_modules').mkdir()
            (root / '.venv').mkdir()
            started = 2_000_000_000 * 10 ** 9
            os.utime(root / 'node_modules', ns=(started - 10 ** 9, started - 10 ** 9))
            os.utime(root / '.venv', ns=(started + 10 ** 9, started + 10 ** 9))
            known = [{'path': 'node_modules', 'rule': 'excluded-name:node_modules', 'kind': 'directory'},
                     {'path': '.venv', 'rule': 'excluded-name:.venv', 'kind': 'directory'}]
            fresh = {'path': '.npmrc', 'rule': 'excluded-name:.npmrc', 'kind': 'file'}
            in_place = lab.change_record({}, {}, known, known + [fresh], root, True, started)
            self.assertEqual([row['path'] for row in in_place['omitted']], ['.npmrc', '.venv'])
            copied = lab.change_record({}, {}, known, known + [fresh], root, False, started)
            self.assertEqual([row['path'] for row in copied['omitted']], ['.npmrc'])


if __name__ == '__main__':
    unittest.main()
