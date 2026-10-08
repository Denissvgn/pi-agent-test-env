"""Installer preservation and actual extracted-content contracts."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str((Path(__file__).resolve().parents[1] / 'skill') / 'scripts'))
import export_skill as exporter


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        (self.source / 'SKILL.md').write_text('skill')
        (self.source / 'skill.json').write_text('{"name": "pi-agent-test-env", "version": "3.0.0"}')
        self.project = self.root / 'project'
        self.project.mkdir()

    def destination(self, harness='codex'):
        dest = self.project / f'{exporter.HARNESS_PATHS[harness]}/pi-agent-test-env'
        dest.parent.mkdir(parents=True, exist_ok=True)
        return dest

    def test_clean_and_idempotent(self):
        self.assertEqual([x['status'] for x in exporter.install_harness(self.source, self.project, 'all')], ['created', 'created', 'created', 'already-correct'])
        self.assertEqual([x['status'] for x in exporter.install_harness(self.source, self.project, 'all')], ['already-correct'] * 4)

    def test_preserves_directory_file_unrelated_and_broken_links(self):
        dest = self.destination()
        for kind in ('directory', 'file', 'link', 'broken'):
            with self.subTest(kind=kind):
                if kind == 'directory':
                    dest.mkdir()
                    (dest / 'keep').write_text('old')
                elif kind == 'file':
                    dest.write_text('old')
                else:
                    dest.symlink_to(self.root / ('source' if kind == 'link' else 'absent'))
                    if kind == 'link':
                        other = self.root / 'other'
                        other.mkdir()
                        dest.unlink()
                        dest.symlink_to(other)
                before = dest.lstat()
                self.assertEqual(exporter.install_harness(self.source, self.project, 'codex')[0]['status'], 'conflict')
                self.assertEqual(dest.lstat().st_ino, before.st_ino)
                if kind == 'directory':
                    self.assertEqual((dest / 'keep').read_text(), 'old')
                    (dest / 'keep').unlink()
                    dest.rmdir()
                else:
                    dest.unlink()

    def test_relative_correct_link(self):
        self.destination().symlink_to('../../../source')
        self.assertEqual(exporter.install_harness(self.source, self.project, 'codex')[0]['status'], 'already-correct')

    def test_claude_conflict_does_not_create_command(self):
        self.destination('claude').mkdir()
        results = exporter.install_harness(self.source, self.project, 'claude')
        self.assertEqual([x['status'] for x in results], ['conflict', 'failed'])
        self.assertFalse((self.project / '.claude/commands').exists())

    def test_command_conflict_preserves_contents(self):
        dest = self.project / '.claude/commands/pi-agent-test-env.md'
        dest.parent.mkdir(parents=True)
        dest.write_text('unrelated')
        results = exporter.install_harness(self.source, self.project, 'claude')
        self.assertEqual([x['status'] for x in results], ['created', 'conflict'])
        self.assertEqual(dest.read_text(), 'unrelated')

    def test_permission_failure_is_explicit(self):
        with patch.object(exporter.os, 'symlink', side_effect=PermissionError('denied')):
            results = exporter.install_harness(self.source, self.project, 'claude')
        self.assertEqual([x['status'] for x in results], ['failed', 'failed'])
        self.assertIn('denied', results[0]['reason'])
        self.assertFalse((self.project / '.claude/commands').exists())

    def test_parent_link_cannot_redirect_install(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (self.project / '.agents').symlink_to(outside)
        self.assertEqual(exporter.install_harness(self.source, self.project, 'codex')[0]['status'], 'failed')
        self.assertEqual(list(outside.iterdir()), [])

    def test_cli_exits_nonzero_on_conflict(self):
        self.destination().mkdir()
        with patch.object(sys, 'argv', ['export_skill.py', '--output-dir', str(self.root), '--target-dir', str(self.project), '--install', 'codex']), patch.object(exporter, 'ROOT', self.source), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(exporter.main(), 1)
        self.assertIn('"status": "conflict"', output.getvalue())


class ArchiveTests(unittest.TestCase):
    def test_all_archives_extract_exact_package_and_manifest(self):
        import hashlib
        import zipfile
        source = (Path(__file__).resolve().parents[1] / 'skill')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for filename, prefix in exporter.archive_specs(source).items():
                archive = exporter.build_zip(source, root / filename, prefix, claude_command=filename.endswith('-claude.zip'))
                with zipfile.ZipFile(archive) as zipped:
                    dest = root / filename.removesuffix('.zip')
                    zipped.extractall(dest)
                package = dest / prefix
                self.assertTrue((package / 'SKILL.md').is_file())
                for file in exporter.file_list(source):
                    relative = file.relative_to(source)
                    self.assertEqual((package / relative).read_bytes(), file.read_bytes(), str(relative))
                for line in (package / 'MANIFEST.sha256').read_text().splitlines():
                    digest, relative = line.split('  ', 1)
                    self.assertEqual(hashlib.sha256((package / relative).read_bytes()).hexdigest(), digest, relative)
                if filename.endswith('-claude.zip'):
                    self.assertEqual((dest / '.claude/commands/pi-agent-test-env.md').read_text(), exporter.CLAUDE_COMMAND)

    def test_sources_reject_links_and_ignore_macos_junk(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / '.DS_Store').write_text('junk')
            self.assertEqual(exporter.file_list(root), [])
            (root / 'link').symlink_to('/etc/hosts')
            with self.assertRaises(ValueError):
                exporter.file_list(root)


class ExportDestinationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pi-export-destination-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def package(self, name):
        source = self.root / name / 'pi-agent-test-env'
        (source / 'scripts').mkdir(parents=True)
        shutil.copyfile(Path(exporter.__file__), source / 'scripts/export_skill.py')
        (source / 'SKILL.md').write_text('Temporary distribution fixture; no model invocation.\n')
        (source / 'skill.json').write_text('{"name":"pi-agent-test-env","version":"4.0.1"}\n')
        (source / 'MANIFEST.sha256').write_bytes(b'original manifest sentinel\n')
        (source / 'asset.txt').write_bytes(b'package resource\n')
        return source

    def inventory(self, root):
        result = {}
        for path in sorted(root.rglob('*')):
            relative = path.relative_to(root).as_posix()
            if path.is_symlink(): result[relative] = ('link', path.readlink().as_posix())
            elif path.is_file(): result[relative] = ('file', path.read_bytes())
            else: result[relative] = ('directory',)
        return result

    def cli(self, source, *arguments, cwd=None):
        argv = [sys.executable, str(source / 'scripts/export_skill.py'), *map(str, arguments)]
        result = subprocess.run(argv, cwd=cwd or self.root, capture_output=True, text=True, timeout=20)
        print(json.dumps({'evidence': 'real disposable exporter subprocess; no model/Docker',
                         'command': argv, 'cwd': str(cwd or self.root), 'exit_code': result.returncode}))
        return result

    def assert_rejected_cli(self, source, output, *, cwd=None):
        target = source.parent / 'install-target'
        target.mkdir()
        # Preserve previously generated ZIP-shaped files and unrelated content.
        existing = source / 'old-generated.zip'
        existing.write_bytes(b'existing generated archive sentinel')
        before = self.inventory(source.parent)
        result = self.cli(source, '--output-dir', output, '--install', 'all', '--target-dir', target, cwd=cwd)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn('outside the skill package', result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(before, self.inventory(source.parent))
        self.assertEqual(existing.read_bytes(), b'existing generated archive sentinel')
        self.assertEqual(list(target.iterdir()), [])

    def test_cli_root_existing_new_descendants_and_relative_aliases_reject_atomically(self):
        for kind in ('root', 'existing', 'new', 'relative'):
            with self.subTest(kind=kind):
                source = self.package(kind)
                if kind == 'root': output = source
                elif kind == 'existing':
                    output = source / 'dist'; output.mkdir(); (output / 'keep').write_text('original')
                elif kind == 'new': output = source / 'new/nested/dist'
                else: output = Path('pi-agent-test-env/scripts/../dist')
                self.assert_rejected_cli(source, output, cwd=source.parent)

    def test_cli_destination_and_ancestor_symlinks_resolve_inside_source(self):
        for kind in ('destination', 'ancestor'):
            with self.subTest(kind=kind):
                source = self.package(kind)
                if kind == 'destination':
                    inside = source / 'dist'; inside.mkdir()
                    output = source.parent / 'linked-output'; output.symlink_to(inside, target_is_directory=True)
                else:
                    alias = source.parent / 'linked-parent'; alias.symlink_to(source, target_is_directory=True)
                    output = alias / 'new/nested/dist'
                self.assert_rejected_cli(source, output)

    def test_case_aliases_use_filesystem_identity_without_rejecting_distinct_siblings(self):
        for kind in ('root', 'new-descendant'):
            with self.subTest(kind=kind):
                source = self.package('case-alias-' + kind)
                alias = source.with_name(source.name.upper())
                output = alias if kind == 'root' else alias / 'new/dist'
                if alias.exists() and alias.samefile(source):
                    # APFS realpath preserves requested casing even when both
                    # spellings name the same directory. Check actual identity.
                    self.assert_rejected_cli(source, output)
                    with self.assertRaises(ValueError):
                        exporter.build_universal_zip(source, output / 'result.zip')
                else:
                    # On case-sensitive hosts the other spelling is a supported
                    # sibling, not a source alias; do not implement case folding.
                    result = self.cli(source, '--output-dir', output)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assert_exact_archives(source, output)

    def test_main_rejects_before_manifest_mkdir_zip_or_install_calls(self):
        source = self.package('side-effects')
        with patch.object(exporter, 'ROOT', source), \
             patch.object(sys, 'argv', ['export_skill.py', '--output-dir', str(source / 'absent'), '--install', 'all']), \
             patch.object(exporter, 'update_manifest') as manifest, \
             patch.object(exporter.Path, 'mkdir') as mkdir, \
             patch.object(exporter, 'build_zip') as build, \
             patch.object(exporter, 'install_harness') as install, \
             contextlib.redirect_stderr(io.StringIO()) as errors, contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(SystemExit) as rejected: exporter.main()
            self.assertEqual(rejected.exception.code, 2)
            manifest.assert_not_called(); mkdir.assert_not_called(); build.assert_not_called(); install.assert_not_called()
        self.assertEqual(output.getvalue(), '')
        self.assertIn('outside the skill package', errors.getvalue())

    def test_library_and_wrappers_reject_before_opening_or_truncating_destinations(self):
        builders = [exporter.build_universal_zip, exporter.build_claude_zip, exporter.build_codex_zip,
                    lambda source, dest: exporter.build_zip(source, dest, exporter.SKILL_NAME)]
        for index, builder in enumerate(builders):
            for kind in ('root', 'existing', 'new', 'relative', 'symlink-ancestor', 'symlink-leaf'):
                with self.subTest(builder=index, kind=kind):
                    source = self.package(f'library-{index}-{kind}')
                    archive = source / 'existing.zip'; archive.write_bytes(b'preserve archive')
                    if kind == 'root': dest = source
                    elif kind == 'existing': dest = archive
                    elif kind == 'new': dest = source / 'absent/result.zip'
                    elif kind == 'relative': dest = source / 'scripts/../relative.zip'
                    elif kind == 'symlink-ancestor':
                        alias = source.parent / 'alias'; alias.symlink_to(source, target_is_directory=True)
                        dest = alias / 'result.zip'
                    else:
                        dest = source.parent / 'linked.zip'; dest.symlink_to(archive)
                    before = self.inventory(source.parent)
                    with patch.object(exporter.zipfile, 'ZipFile', wraps=zipfile.ZipFile) as opening:
                        with self.assertRaises(ValueError): builder(source, dest)
                        opening.assert_not_called()
                    self.assertEqual(before, self.inventory(source.parent))

    def assert_exact_archives(self, source, output):
        files = {p.relative_to(source).as_posix(): p.read_bytes() for p in exporter.file_list(source)}
        for filename, prefix in exporter.archive_specs(source).items():
            with zipfile.ZipFile(output / filename) as archive:
                members = archive.namelist()
                expected = {prefix + '/' + name for name in files}
                if filename.endswith('-claude.zip'): expected.add('.claude/commands/pi-agent-test-env.md')
                self.assertEqual(len(members), len(set(members)))
                self.assertEqual(set(members), expected)
                self.assertFalse(any(name.endswith('.zip') for name in members))
                for name, body in files.items(): self.assertEqual(archive.read(prefix + '/' + name), body)
                manifest = archive.read(prefix + '/MANIFEST.sha256').decode()
                covered = set()
                for line in manifest.splitlines():
                    digest, name = line.split('  ', 1); covered.add(name)
                    self.assertEqual(digest, hashlib.sha256(archive.read(prefix + '/' + name)).hexdigest())
                self.assertEqual(covered, set(files) - {'MANIFEST.sha256'})
                if filename.endswith('-claude.zip'):
                    self.assertEqual(archive.read('.claude/commands/pi-agent-test-env.md').decode(), exporter.CLAUDE_COMMAND)

    def test_repeated_positive_exports_in_source_and_all_installed_layouts(self):
        layouts = {'source': 'pi-agent-test-env', 'universal': 'pi-agent-test-env',
                   'codex': '.agents/skills/pi-agent-test-env', 'claude': '.claude/skills/pi-agent-test-env',
                   'antigravity': 'pi-agent-test-env'}
        for layout, relative in layouts.items():
            for destination in ('default', 'parent', 'sibling'):
                with self.subTest(layout=layout, destination=destination):
                    template = self.package(f'template-{layout}-{destination}')
                    source = self.root / f'layout-{layout}-{destination}' / relative
                    source.parent.mkdir(parents=True); shutil.copytree(template, source)
                    output = source.parent if destination != 'sibling' else source.parent / 'pi-agent-test-env-output'
                    args = [] if destination == 'default' else ['--output-dir', output]
                    for _ in range(2):
                        result = self.cli(source, *args)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assert_exact_archives(source, output)

    def test_supported_export_install_and_installed_relative_cli_preserve_conflicts(self):
        source = self.package('install')
        target = source.parent / 'project'; target.mkdir()
        output = source.parent / 'outputs'
        result = self.cli(source, '--output-dir', output, '--install', 'all', '--target-dir', target)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_exact_archives(source, output)
        for harness in ('codex', 'claude', 'antigravity'):
            installed = target / exporter.HARNESS_PATHS[harness] / exporter.SKILL_NAME
            result = self.cli(installed, '--output-dir', output)
            self.assertEqual(result.returncode, 0, result.stderr)
        command = target / '.claude/commands/pi-agent-test-env.md'
        command.write_text('user-owned command conflict')
        result = self.cli(source, '--output-dir', output, '--install', 'all', '--target-dir', target)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(command.read_text(), 'user-owned command conflict')
