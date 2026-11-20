"""Release tooling: changelog assembly, version bumps and manifest-only export.

Every test that writes runs against a temporary copy of the repository's skill
package and documentation, never against the working tree. The real repository is
only read, by the `--check` runs. Versions are read from each temporary copy, so the
tests keep working after a real bump or after a real changelog assembly.
"""
import errno
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from unittest import mock
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / 'tools'
sys.dont_write_bytecode = True  # importing tools in-process must not leave __pycache__ in the repository
sys.path.insert(0, str(TOOLS))
import release_files  # noqa: E402  (tools/release_files.py)

ENV = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}
IGNORED = shutil.ignore_patterns('__pycache__', '*.pyc', '.DS_Store')


def run(script: str, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(ROOT / script), *args], cwd=cwd or ROOT,
                          env=ENV, capture_output=True, text=True, timeout=120)


def run_path(script: Path, *args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(script), *args], cwd=cwd,
                          env=ENV, capture_output=True, text=True, timeout=120)


def load_tool(name: str):
    """Import tools/<name>.py in this process, so a test can inject I/O failures."""
    spec = importlib.util.spec_from_file_location(name, TOOLS / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def snapshot(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob('*') if p.is_file()}


def temporary_files(root: Path) -> list[str]:
    return sorted(p.relative_to(root).as_posix() for p in root.rglob('*.tmp'))


def source_version_in(root: Path) -> str:
    """The live package version of this copy, read from skill/skill.json."""
    text = (root / 'skill/skill.json').read_text(encoding='utf-8')
    return re.search(r'^  "version": "(\d+\.\d+\.\d+)",', text, re.MULTILINE).group(1)


def next_patch(version: str) -> str:
    major, minor, patch = (int(part) for part in version.split('.'))
    return f'{major}.{minor}.{patch + 1}'


def top_entry_offset(changelog: str) -> int:
    return re.search(r'^## ', changelog, re.MULTILINE).start()


class TemporaryProject(unittest.TestCase):
    """A disposable copy of the files the tools read: skill/, README.md and changes/.

    `version` is the live version of the copy, `target` is the next patch version
    that is not yet in it, and `drift` is a third version used to make the places
    disagree. None of them is written into a test as a literal.
    """

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name) / 'project'
        self.root.mkdir()
        shutil.copytree(ROOT / 'skill', self.root / 'skill', ignore=IGNORED)
        shutil.copy(ROOT / 'README.md', self.root / 'README.md')
        (self.root / 'changes').mkdir()
        shutil.copy(ROOT / 'changes' / 'README.md', self.root / 'changes' / 'README.md')
        self.version = source_version_in(self.root)
        self.target = next_patch(self.version)
        self.drift = next_patch(self.target)

    def write_fragment(self, name: str, text: str) -> Path:
        path = self.root / 'changes' / name
        path.write_text(text, encoding='utf-8')
        return path


class ChangelogAssemblyTests(TemporaryProject):

    def setUp(self):
        super().setUp()
        self.top_version = re.search(r'^## (\d+\.\d+\.\d+)', self.changelog(), re.MULTILINE).group(1)

    def assemble(self, version: str) -> subprocess.CompletedProcess:
        return run('tools/assemble_changelog.py', '--root', str(self.root), '--version', version)

    def check(self) -> subprocess.CompletedProcess:
        return run('tools/assemble_changelog.py', '--root', str(self.root), '--check')

    def changelog(self) -> str:
        return (self.root / 'skill/CHANGELOG.md').read_text(encoding='utf-8')

    def test_three_fragments_of_different_kinds_form_the_entry_above_existing_entries(self):
        before = self.changelog()
        top = top_entry_offset(before)
        self.write_fragment('a-added.md', 'kind: added\nAdds one thing.\n')
        self.write_fragment('b-fixed.md', 'kind: fixed\nFixes a thing.\n')
        self.write_fragment('c-upgrade.md', 'kind: upgrade-note\nRun the new command once.\n')

        result = self.assemble(self.target)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        expected_entry = (f'## {self.target}\n\n'
                          f'### Upgrading from {self.top_version}\n\n- Run the new command once.\n\n'
                          '### Added\n\n- Adds one thing.\n\n'
                          '### Fixed\n\n- Fixes a thing.\n\n')
        self.assertEqual(self.changelog(), before[:top] + expected_entry + before[top:])
        for name in ('a-added.md', 'b-fixed.md', 'c-upgrade.md'):
            self.assertFalse((self.root / 'changes' / name).exists(), name)
        self.assertTrue((self.root / 'changes/README.md').is_file())

    def test_multiline_fragment_text_is_indented_under_its_bullet(self):
        before = self.changelog()
        self.write_fragment('wide.md', 'kind: changed\nFirst line.\nSecond line.\n')

        self.assertEqual(self.assemble(self.target).returncode, 0)

        self.assertIn('### Changed\n\n- First line.\n  Second line.\n\n', self.changelog())
        self.assertTrue(self.changelog().endswith(before[top_entry_offset(before):]))

    def test_insertion_into_a_crlf_changelog_keeps_every_existing_byte_and_uses_crlf(self):
        path = self.root / 'skill/CHANGELOG.md'
        original = path.read_bytes().replace(b'\n', b'\r\n')
        path.write_bytes(original)
        top = re.search(rb'^## ', original, re.MULTILINE).start()
        self.write_fragment('a-added.md', 'kind: added\nAdds one thing.\n')

        result = self.assemble(self.target)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        after = path.read_bytes()
        self.assertEqual(after[:top], original[:top])
        self.assertTrue(after.endswith(original[top:]))
        entry = after[top:len(after) - len(original[top:])]
        self.assertIn(f'## {self.target}\r\n'.encode(), entry)
        self.assertEqual(entry.count(b'\n'), entry.count(b'\r\n'))

    def test_fenced_example_with_a_hash_comment_is_accepted_and_kept_in_its_bullet(self):
        self.write_fragment('example.md', 'kind: added\nShows the call:\n\n'
                                         '```python\n# Read the version from skill.json.\nversion = 1\n```\n')

        result = self.check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        self.assertEqual(self.assemble(self.target).returncode, 0)
        self.assertIn('- Shows the call:\n\n  ```python\n  # Read the version from skill.json.\n',
                      self.changelog())

    def test_ordinary_markdown_in_the_text_is_kept_as_written(self):
        self.write_fragment('markdown.md', 'kind: changed\nUse **bold** and `x # y` here.\n'
                                           '- first item\n- second item\n')

        self.assertEqual(self.check().returncode, 0)

        self.assertEqual(self.assemble(self.target).returncode, 0)
        self.assertIn('### Changed\n\n- Use **bold** and `x # y` here.\n'
                      '  - first item\n  - second item\n\n', self.changelog())

    def test_a_symbolic_link_named_like_a_fragment_is_refused_without_being_followed(self):
        outside = self.root.parent / 'outside.md'
        outside.write_text('kind: added\nLinked text.\n', encoding='utf-8')
        link = self.root / 'changes' / 'linked.md'
        os.symlink(outside, link)
        before = snapshot(self.root)

        result = self.check()

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('linked.md', result.stdout)
        self.assertEqual(self.assemble(self.target).returncode, 1)
        self.assertTrue(link.is_symlink())
        self.assertEqual(snapshot(self.root), before)

    def test_short_and_unusual_fragment_names_are_accepted(self):
        self.write_fragment('x.md', 'kind: added\nA short one.\n')
        self.write_fragment('Fix Two.md', 'kind: fixed\nAn unusual name.\n')

        result = self.check()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('2 changelog fragment(s) valid', result.stdout)

    def test_a_non_markdown_file_in_changes_is_named(self):
        self.write_fragment('notes.txt', 'kind: added\nNot a fragment.\n')

        result = self.check()

        self.assertEqual(result.returncode, 1)
        self.assertIn('notes.txt', result.stdout)

    def test_a_fifo_named_like_a_fragment_is_refused_without_being_read(self):
        os.mkfifo(self.root / 'changes' / 'pipe.md')

        result = self.check()

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('pipe.md', result.stdout)

    def test_a_directory_named_like_a_fragment_is_refused(self):
        (self.root / 'changes' / 'folder.md').mkdir()

        result = self.check()

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('folder.md', result.stdout)

    def test_check_names_a_malformed_fragment_and_writes_nothing(self):
        self.write_fragment('bad-kind.md', 'kind: bogus\nSome text.\n')
        before = snapshot(self.root)

        result = self.check()

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('bad-kind.md', result.stdout)
        self.assertEqual(snapshot(self.root), before)

    def test_fragment_without_a_kind_line_is_named(self):
        self.write_fragment('no-kind.md', 'Some text with no kind line.\n')

        result = self.check()

        self.assertEqual(result.returncode, 1)
        self.assertIn('no-kind.md', result.stdout)

    def test_fragment_with_no_text_is_named(self):
        self.write_fragment('empty.md', 'kind: fixed\n\n')

        result = self.check()

        self.assertEqual(result.returncode, 1)
        self.assertIn('empty.md', result.stdout)

    def test_check_passes_and_writes_nothing_for_valid_fragments(self):
        self.write_fragment('ok.md', 'kind: removed\nRemoves a flag.\n')
        before = snapshot(self.root)

        result = self.check()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(snapshot(self.root), before)

    def test_assembly_refuses_a_malformed_fragment_and_keeps_every_file(self):
        self.write_fragment('good.md', 'kind: added\nGood text.\n')
        self.write_fragment('bad.md', 'kind: nope\nText.\n')
        before = snapshot(self.root)

        result = self.assemble(self.target)

        self.assertEqual(result.returncode, 1)
        self.assertIn('bad.md', result.stdout)
        self.assertEqual(snapshot(self.root), before)

    def test_assembly_refuses_a_version_that_already_has_an_entry(self):
        self.write_fragment('x.md', 'kind: added\nText.\n')
        before = snapshot(self.root)

        result = self.assemble(self.top_version)

        self.assertEqual(result.returncode, 1)
        self.assertEqual(snapshot(self.root), before)

    def test_assembly_refuses_with_no_fragments(self):
        before = snapshot(self.root)

        result = self.assemble(self.target)

        self.assertEqual(result.returncode, 1)
        self.assertEqual(snapshot(self.root), before)


class ChangelogFailureTests(TemporaryProject):
    """Assembly is all-or-nothing: an unlink failure restores every fragment and the changelog."""

    def setUp(self):
        super().setUp()
        self.module = load_tool('assemble_changelog')
        self.write_fragment('a-added.md', 'kind: added\nAdds one thing.\n')
        self.write_fragment('b-fixed.md', 'kind: fixed\nFixes a thing.\n')
        self.victim = self.root / 'changes' / 'b-fixed.md'

    def failing_unlink(self, on_first_success=None):
        """Patch os.unlink so the second fragment fails; optionally run a callback after the first succeeds."""
        real_unlink = os.unlink
        pending = [on_first_success]

        def unlink(path, *args, **kwargs):
            if Path(path) == self.victim:
                raise OSError(errno.EIO, 'simulated unlink failure')
            real_unlink(path, *args, **kwargs)
            if pending[0] is not None:
                callback, pending[0] = pending[0], None
                callback()
        return mock.patch('os.unlink', side_effect=unlink)

    def test_unlink_failure_on_the_second_fragment_restores_everything_and_retry_finishes(self):
        before = snapshot(self.root)

        with self.failing_unlink():
            with self.assertRaises(OSError) as raised:
                self.module.assemble(self.root, self.target)

        self.assertIn('simulated unlink failure', str(raised.exception))
        self.assertEqual(snapshot(self.root), before)
        self.assertEqual(temporary_files(self.root), [])

        retry = run('tools/assemble_changelog.py', '--root', str(self.root), '--version', self.target)

        self.assertEqual(retry.returncode, 0, retry.stdout + retry.stderr)
        self.assertIn(f'## {self.target}\n', (self.root / 'skill/CHANGELOG.md').read_text(encoding='utf-8'))
        self.assertEqual(sorted(p.name for p in (self.root / 'changes').iterdir()), ['README.md'])

    def test_a_fragment_arriving_during_a_failed_run_is_kept(self):
        late = self.root / 'changes' / 'late-arrival.md'
        late_text = b'kind: changed\nArrives mid-run.\n'
        before = snapshot(self.root)

        with self.failing_unlink(on_first_success=lambda: late.write_bytes(late_text)):
            with self.assertRaises(OSError):
                self.module.assemble(self.root, self.target)

        self.assertEqual(snapshot(self.root), {**before, 'changes/late-arrival.md': late_text})

        retry = run('tools/assemble_changelog.py', '--root', str(self.root), '--version', self.target)

        self.assertEqual(retry.returncode, 0, retry.stdout + retry.stderr)
        self.assertIn('Arrives mid-run.', (self.root / 'skill/CHANGELOG.md').read_text(encoding='utf-8'))
        self.assertFalse(late.exists())


class VersionBumpTests(TemporaryProject):

    def bump(self, version: str) -> subprocess.CompletedProcess:
        return run('tools/bump_version.py', version, '--root', str(self.root))

    def check(self) -> subprocess.CompletedProcess:
        return run('tools/bump_version.py', '--check', '--root', str(self.root))

    def test_check_passes_on_the_repository(self):
        result = run('tools/bump_version.py', '--check')

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('version check passed', result.stdout)

    def test_check_fails_when_one_place_is_edited(self):
        path = self.root / 'skill/README.md'
        text = path.read_bytes().decode('utf-8')
        edited = text.replace(f'# Pi Agent Test Environment {self.version}',
                              f'# Pi Agent Test Environment {self.drift}', 1)
        self.assertNotEqual(edited, text)
        path.write_bytes(edited.encode('utf-8'))

        result = self.check()

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('skill/README.md:1:', result.stdout)

    def test_bump_changes_every_listed_place_and_nothing_else(self):
        original = snapshot(self.root)

        result = self.bump(self.target)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        after = snapshot(self.root)
        changed_lines = 0
        for name, data in original.items():
            if after[name] == data:
                continue
            old, new = data.decode('utf-8').splitlines(), after[name].decode('utf-8').splitlines()
            self.assertEqual(len(old), len(new), name)
            changed_lines += sum(1 for a, b in zip(old, new) if a != b)
        self.assertEqual(changed_lines, 12)

        self.assertEqual(self.check().returncode, 0)
        target = self.target
        self.assertIn(f'"version": "{target}"', after['skill/skill.json'].decode('utf-8'))
        readme = after['README.md'].decode('utf-8')
        self.assertIn(f'version-{target}-blue', readme)
        self.assertIn(f'Version {target} is a stable release', readme)
        self.assertIn(f'# Pi Agent Test Environment {target}', after['skill/README.md'].decode('utf-8'))
        skill = after['skill/SKILL.md'].decode('utf-8')
        self.assertIn(f'Package version: {target}. Instructions are in English.', skill)
        self.assertIn(f'Version {target} is stable for the capabilities', skill)
        harnesses = after['skill/references/HARNESSES.md'].decode('utf-8')
        self.assertIn(f'The package version is {target}.', harnesses)
        self.assertIn(f'| `pi-agent-test-env-{target}.zip`', harnesses)
        self.assertIn(f'remain experimental in {target}.',
                      after['skill/references/OWNER-CLEANUP-COMPATIBILITY.md'].decode('utf-8'))
        qualification = after['skill/QUALIFICATION.md'].decode('utf-8')
        self.assertIn(f'Version {target} is a stable release.', qualification)
        self.assertIn(f'| Scope | Status for {target} |', qualification)

    def test_bump_keeps_dated_evidence_at_its_recorded_version(self):
        self.bump(self.target)

        inference = (self.root / 'skill/references/INFERENCE-ENVIRONMENTS.md').read_text(encoding='utf-8')
        qualification = (self.root / 'skill/QUALIFICATION.md').read_text(encoding='utf-8')
        readme = (self.root / 'README.md').read_text(encoding='utf-8')
        self.assertIn('For 4.11.0 the indexed executor passed its frozen native ARM64 campaign', inference)
        self.assertIn('## Stable 4.11.0 release campaign', qualification)
        self.assertIn('the release qualified for 4.11.0;', readme)

    def test_bump_keeps_crlf_line_endings(self):
        path = self.root / 'skill/skill.json'
        path.write_bytes(path.read_bytes().replace(b'\n', b'\r\n'))

        result = self.bump(self.target)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        after = path.read_bytes()
        self.assertIn(f'"version": "{self.target}",\r\n'.encode(), after)
        self.assertEqual(after.count(b'\n'), after.count(b'\r\n'))
        self.assertEqual(self.check().returncode, 0)

    def test_bump_refuses_when_the_places_disagree_and_writes_nothing(self):
        path = self.root / 'skill/SKILL.md'
        text = path.read_bytes().decode('utf-8')
        edited = text.replace(f'Version {self.version} is stable', f'Version {self.drift} is stable', 1)
        self.assertNotEqual(edited, text)
        path.write_bytes(edited.encode('utf-8'))
        before = snapshot(self.root)

        result = self.bump(self.target)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('skill/SKILL.md', result.stdout)
        self.assertEqual(snapshot(self.root), before)

    def test_bump_rejects_a_malformed_version_and_writes_nothing(self):
        before = snapshot(self.root)

        result = self.bump('4.11')

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(snapshot(self.root), before)


class VersionBumpFailureTests(TemporaryProject):
    """A bump is all-or-nothing: an I/O failure part-way restores every file and leaves no temporary file."""

    def setUp(self):
        super().setUp()
        self.module = load_tool('bump_version')
        self.readme = self.root / 'README.md'
        self.skill_json = self.root / 'skill/skill.json'
        # Bump writes skill/skill.json first and README.md second.
        os.chmod(self.skill_json, 0o600)
        os.chmod(self.readme, 0o640)

    def failing_replace(self, victim: Path):
        real_replace = os.replace

        def replace(source, target, *args, **kwargs):
            if Path(target) == victim:
                raise OSError(errno.EIO, 'simulated write failure')
            return real_replace(source, target, *args, **kwargs)
        return mock.patch('os.replace', side_effect=replace)

    def test_second_file_write_failure_restores_the_first_and_retry_succeeds(self):
        before = snapshot(self.root)

        with self.failing_replace(self.readme):
            with self.assertRaises(OSError) as raised:
                self.module.bump(self.root, self.target)

        self.assertIn('simulated write failure', str(raised.exception))
        self.assertEqual(snapshot(self.root), before)
        self.assertEqual(temporary_files(self.root), [])
        self.assertEqual(stat.S_IMODE(self.skill_json.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.readme.stat().st_mode), 0o640)

        retry = run('tools/bump_version.py', self.target, '--root', str(self.root))

        self.assertEqual(retry.returncode, 0, retry.stdout + retry.stderr)
        self.assertEqual(run('tools/bump_version.py', '--check', '--root', str(self.root)).returncode, 0)
        self.assertIn(f'"version": "{self.target}"', self.skill_json.read_text(encoding='utf-8'))
        self.assertEqual(stat.S_IMODE(self.skill_json.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.readme.stat().st_mode), 0o640)

    def test_staging_failure_on_the_second_file_changes_nothing(self):
        before = snapshot(self.root)
        real_stage = release_files.stage_bytes
        calls = []

        def stage(path, data, mode):
            calls.append(path.name)
            if len(calls) == 2:
                raise OSError(errno.ENOSPC, 'simulated disk full')
            return real_stage(path, data, mode)

        with mock.patch.object(release_files, 'stage_bytes', side_effect=stage):
            with self.assertRaises(OSError) as raised:
                self.module.bump(self.root, self.target)

        self.assertIn('simulated disk full', str(raised.exception))
        self.assertEqual(snapshot(self.root), before)
        self.assertEqual(temporary_files(self.root), [])

        retry = run('tools/bump_version.py', self.target, '--root', str(self.root))

        self.assertEqual(retry.returncode, 0, retry.stdout + retry.stderr)
        self.assertEqual(run('tools/bump_version.py', '--check', '--root', str(self.root)).returncode, 0)

    def test_a_restore_that_also_fails_is_reported_by_name(self):
        real_replace = os.replace
        state = {'failed': False}

        def replace(source, target, *args, **kwargs):
            target = Path(target)
            if target == self.readme:
                state['failed'] = True
                raise OSError(errno.EIO, 'simulated write failure')
            if state['failed'] and target == self.skill_json:
                raise OSError(errno.EIO, 'simulated restore failure')
            return real_replace(source, target, *args, **kwargs)

        with mock.patch('os.replace', side_effect=replace):
            with self.assertRaises(release_files.RollbackError) as raised:
                self.module.bump(self.root, self.target)

        self.assertIn('skill.json: simulated restore failure', str(raised.exception))
        self.assertEqual(temporary_files(self.root), [])


class ManifestOnlyExportTests(TemporaryProject):

    def test_manifest_only_changes_only_the_manifest_and_writes_no_archive(self):
        skill_md = self.root / 'skill/SKILL.md'
        skill_md.write_bytes(skill_md.read_bytes() + b'\nA note for the manifest test.\n')
        before = snapshot(self.root)
        script = self.root / 'skill/scripts/export_skill.py'

        result = run_path(script, '--manifest-only', cwd=self.root)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        after = snapshot(self.root)
        self.assertEqual(sorted(after), sorted(before))
        changed = sorted(name for name in before if before[name] != after[name])
        self.assertEqual(changed, ['skill/MANIFEST.sha256'])
        self.assertEqual(list(self.root.rglob('*.zip')), [])
        digest = hashlib.sha256(after['skill/SKILL.md']).hexdigest()
        self.assertIn(f'{digest}  SKILL.md\n', after['skill/MANIFEST.sha256'].decode('utf-8'))

    def test_manifest_only_cannot_be_combined_with_install(self):
        script = self.root / 'skill/scripts/export_skill.py'
        before = snapshot(self.root)

        result = run_path(script, '--manifest-only', '--install', 'claude', cwd=self.root)

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(snapshot(self.root), before)


if __name__ == '__main__':
    unittest.main()
