"""Published-content boundaries and safe verifier rejection behavior."""
import hashlib
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
