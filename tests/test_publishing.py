"""Published-content boundaries and safe verifier rejection behavior."""
import hashlib
import os
from pathlib import Path
import stat
import shutil
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPOSITORY/'tools'))
import build_release
import check_package
import verify_release


class PublishingTests(unittest.TestCase):
    def test_owner_reader_runtime_is_required_even_with_regenerated_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            source=Path(temporary)/'skill';shutil.copytree(REPOSITORY/'skill',source)
            (source/'scripts/application_owner_legacy_publication.py').unlink()
            check_package.export_skill.update_manifest(source)
            with self.assertRaisesRegex(ValueError,'required'):
                check_package.check(source)

    def test_operation_sdk_runtime_is_required_even_with_regenerated_manifest(self):
        for name in ('scripts/operation_sdk/worker.py', 'references/OPERATION-SDK.md'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                source=Path(temporary)/'skill';shutil.copytree(REPOSITORY/'skill',source)
                (source/name).unlink()
                check_package.export_skill.update_manifest(source)
                with self.assertRaisesRegex(ValueError,'required'):
                    check_package.check(source)

    def copied_repository(self, root):
        repository=root/'source'
        for path in build_release.source_files(REPOSITORY):
            target=repository/path.relative_to(REPOSITORY);target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,target)
        return repository

    def set_changelog_entry(self, repository, heading):
        path=repository/'skill/CHANGELOG.md';lines=path.read_text().splitlines(True)
        index=next(i for i,line in enumerate(lines) if line.startswith('## '))
        lines[index]='## '+heading+'\n';path.write_text(''.join(lines))

    def test_release_build_requires_the_changelog_to_name_the_package_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();repository=self.copied_repository(root)
            version=check_package.export_skill.package_metadata(repository/'skill')['version']
            self.set_changelog_entry(repository,'Unreleased')
            before=(repository/'skill/MANIFEST.sha256').read_bytes()
            with self.assertRaisesRegex(ValueError,'CHANGELOG top entry'):
                build_release.build(root/'refused',repository)
            self.assertFalse((root/'refused').exists())
            self.assertEqual((repository/'skill/MANIFEST.sha256').read_bytes(),before)
            self.assertFalse(build_release.build(root/'candidate',repository,candidate=True)['publishable'])
            self.set_changelog_entry(repository,version+' (release)')
            self.assertTrue(build_release.build(root/'release',repository)['publishable'])

    def test_archives_are_byte_reproducible_regardless_of_file_times(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();repository=self.copied_repository(root)
            build_release.build(root/'first',repository,candidate=True)
            for path in repository.rglob('*'):
                if path.is_file():os.utime(path,(1_000_000_000,1_000_000_000))
            build_release.build(root/'second',repository,candidate=True)
            self.assertEqual((root/'first/SHA256SUMS').read_bytes(),(root/'second/SHA256SUMS').read_bytes())
            with zipfile.ZipFile(root/'first/pi-agent-test-env-claude.zip') as archive:
                command=archive.getinfo('.claude/commands/pi-agent-test-env.md')
                self.assertEqual(stat.S_IMODE(command.external_attr>>16),0o600)
                self.assertEqual(stat.S_IFMT(command.external_attr>>16),stat.S_IFREG)

    def test_archive_mode_follows_the_git_owner_executable_rule(self):
        canonical=check_package.export_skill.archive_mode
        for local,expected in ((0o600,0o644),(0o400,0o644),(0o640,0o644),(0o644,0o644),(0o664,0o644),(0o666,0o644),
                               (0o700,0o755),(0o500,0o755),(0o744,0o755),(0o755,0o755),(0o775,0o755)):
            with self.subTest(local=oct(local)):self.assertEqual(canonical(stat.S_IFREG|local),expected)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();script=root/'tool.py';script.write_text('#!/usr/bin/env python3\n');script.chmod(0o700)
            with zipfile.ZipFile(root/'out.zip','w') as archive:check_package.export_skill.write_entry(archive,script,'tool.py')
            with zipfile.ZipFile(root/'out.zip') as archive:
                self.assertEqual(stat.S_IMODE(archive.getinfo('tool.py').external_attr>>16),0o755)

    def test_archives_are_byte_reproducible_regardless_of_local_file_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();repository=self.copied_repository(root)
            build_release.build(root/'first',repository,candidate=True)
            # A private checkout mode on a source fixture once changed the published
            # source archive; package and tool files drift the same way.
            for name,mode in (('tests/fixtures/application-contracts/historical-browser-source-identities.json',0o600),
                              ('skill/references/PROJECTS.md',0o640),('tools/check_examples.py',0o664)):
                (repository/name).chmod(mode)
            build_release.build(root/'second',repository,candidate=True)
            self.assertEqual((root/'first/SHA256SUMS').read_bytes(),(root/'second/SHA256SUMS').read_bytes())
            for path in sorted((root/'second').glob('*.zip')):
                with zipfile.ZipFile(path) as archive:
                    modes={i.filename:stat.S_IMODE(i.external_attr>>16) for i in archive.infolist()}
                command=modes.pop('.claude/commands/pi-agent-test-env.md',None)
                self.assertEqual(set(modes.values()),{0o644},path.name)
                self.assertEqual(command,0o600 if path.name.endswith('-claude.zip') else None)
            # The verifier expects the same canonical modes from the drifted checkout.
            def passing(argv,cwd,timeout=180):
                tests='-m' in argv
                return {'command':argv,'cwd':str(cwd),'exit_code':0,'stdout':'','stderr':'\nRan 2 tests in 0.001s\n\nOK\n' if tests else ''}
            with mock.patch.object(verify_release,'run',side_effect=passing):
                result=verify_release.verify(root/'second',root/'audit.json',repository)
            self.assertEqual(result['status'],'pass');self.assertEqual(len(result['layouts']),5)

    def test_source_allowlist_retains_tests_and_runtime_plans_without_internal_history(self):
        paths={p.relative_to(REPOSITORY).as_posix() for p in build_release.source_files(REPOSITORY)}
        self.assertIn('tests/test_publishing.py',paths)
        self.assertIn('tests/fixtures/application-contracts/positive.json',paths)
        self.assertIn('tests/fixtures/application-contracts/completion.json',paths)
        self.assertIn('tests/fixtures/application-contracts/native-tools.json',paths)
        self.assertIn('tests/fixtures/application-contracts/legacy-baseline.json',paths)
        self.assertIn('skill/assets/python-feature.plan.json',paths)
        self.assertIn('skill/examples/python-project/tests/test_slug.py',paths)
        self.assertIn('tools/validation/vendor/agentskills-source.tar.gz',paths)
        self.assertIn('tools/pi_release_intake.py',paths)
        self.assertFalse(any(p.split('/')[0] in {'reports','plans','dist','development'} for p in paths))
        self.assertFalse(any(p.startswith('tools/release-hardening/') for p in paths))
        self.assertFalse(any(p.startswith('skill/tests/') for p in paths))
        self.assertNotIn('BACKLOG.md',paths);self.assertNotIn('RELEASE_BACKLOG.md',paths)

    def test_validation_allowlist_excludes_unregistered_reports_and_build_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();repository=root/'source'
            for path in build_release.source_files(REPOSITORY):
                target=repository/path.relative_to(REPOSITORY);target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,target)
            extra=repository/'tools/validation/generated/reports.json';extra.parent.mkdir();extra.write_text('private development history')
            (extra.parent/'previous.zip').write_bytes(b'previous artifact')
            paths=build_release.source_files(repository)
            self.assertFalse(any('generated' in p.parts for p in paths))
            unreviewed = repository/'tests/fixtures/application-contracts/private-response.json'
            unreviewed.parent.mkdir(parents=True, exist_ok=True)
            unreviewed.write_text('unregistered fixture output')
            self.assertNotIn(unreviewed, build_release.source_files(repository))
            before=(repository/'skill/MANIFEST.sha256').read_bytes()
            with self.assertRaisesRegex(ValueError,'outside'):
                build_release.build(repository/'tools/validation/new-release',repository)
            self.assertEqual((repository/'skill/MANIFEST.sha256').read_bytes(),before)
            self.assertFalse((repository/'tools/validation/new-release').exists())

    def test_case_alias_report_cannot_bypass_input_guard(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();repository=root/'repository';source=repository/'skill';source.mkdir(parents=True)
            archives=root/'archives';archives.mkdir()
            aliases=[source.with_name('SkIlL'),archives.with_name('ArChIvEs')]
            if not all(p.exists() for p in aliases):self.skipTest('Case-sensitive filesystem has no native path alias')
            for alias in aliases:
                report=alias/'audit.json'
                with self.subTest(path=report),self.assertRaisesRegex(ValueError,'outside inputs'):
                    verify_release.verify(archives,report,repository)
                self.assertFalse(report.exists())

    def test_failed_verification_subprocess_retains_complete_diagnostics(self):
        with self.assertRaises(verify_release.VerificationCommandError) as caught:
            verify_release.run([sys.executable,'-c',"import sys; print('diagnostic'*500); sys.exit(1)"],REPOSITORY)
        self.assertEqual(caught.exception.row['exit_code'],1)
        self.assertGreater(len(caught.exception.row['stdout']),3000)

    def test_verification_timeout_retains_partial_stdout_and_stderr(self):
        code="import sys,time; print('partial stdout',flush=True); print('partial stderr',file=sys.stderr,flush=True); time.sleep(5)"
        with self.assertRaises(verify_release.VerificationCommandError) as caught:
            verify_release.run([sys.executable,'-u','-c',code],REPOSITORY,timeout=1.0)
        row=caught.exception.row
        self.assertEqual(row['exit_code'],124);self.assertTrue(row['timed_out'])
        self.assertEqual(row['timeout_seconds'],1.0)
        self.assertIn('partial stdout',row['stdout']);self.assertIn('partial stderr',row['stderr'])

    def test_verification_test_budget_is_bounded_before_input_access(self):
        for budget in (True,0,59,1801,1.5,'900'):
            with self.subTest(budget=budget),mock.patch.object(Path,'resolve',side_effect=AssertionError('input accessed')):
                with self.assertRaisesRegex(ValueError,'60..1800'):
                    verify_release.verify(Path('unopened'),Path('unwritten'),test_timeout_seconds=budget)

    def test_build_rejects_contained_output_before_manifest_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();source=root/'skill';source.mkdir()
            sentinel=source/'MANIFEST.sha256';sentinel.write_bytes(b'original')
            output=source/'generated'
            with self.assertRaisesRegex(ValueError,'outside'):
                build_release.build(output,repository=root)
            self.assertEqual(sentinel.read_bytes(),b'original');self.assertFalse(output.exists())

    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();(root/'skill').mkdir();output=root/'release';output.mkdir();keep=output/'keep';keep.write_text('original')
            with self.assertRaisesRegex(ValueError,'fresh output'):
                build_release.build(output,repository=root)
            self.assertEqual(keep.read_text(),'original')

    def test_report_inside_inputs_rejects_without_any_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();report=root/'audit.json'
            with self.assertRaisesRegex(ValueError,'outside inputs'):
                verify_release.verify(root,report,repository=REPOSITORY)
            self.assertFalse(report.exists());self.assertEqual(list(root.iterdir()),[])

    def test_archive_duplicate_escape_and_link_entries_reject(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve()
            for name,mode in [('../escape',stat.S_IFREG|0o644),('/absolute',stat.S_IFREG|0o644),
                              ('C:/drive',stat.S_IFREG|0o644),('a\\b',stat.S_IFREG|0o644),('link',stat.S_IFLNK|0o777)]:
                path=root/'unsafe.zip'
                with zipfile.ZipFile(path,'w') as archive:
                    info=zipfile.ZipInfo(name);info.external_attr=mode<<16;archive.writestr(info,'unsafe')
                with zipfile.ZipFile(path) as archive,self.subTest(name=name),self.assertRaises(ValueError):
                    verify_release.safe_members(archive)

    def test_wrong_archive_size_rejects_before_extraction(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();path=root/'oversize.zip';output=root/'extracted'
            with zipfile.ZipFile(path,'w') as archive:archive.writestr('entry',b'longer')
            expected={'entry':{'sha256':hashlib.sha256(b'longer').hexdigest(),'mode':0o600,'bytes':1}}
            with self.assertRaisesRegex(ValueError,'size'):
                verify_release.extract(path,output,expected)
            self.assertFalse(output.exists())


if __name__=='__main__':unittest.main()
