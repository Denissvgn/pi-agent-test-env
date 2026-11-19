"""Checks for CI-facing package and Markdown validation."""
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import check_links
import docker_ci


class CiToolsTests(unittest.TestCase):
    def test_stale_manifest_option(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'skill'
            shutil.copytree(ROOT / 'skill', source)
            with (source / 'MANIFEST.sha256').open('a') as stream:
                stream.write('0' * 64 + '  stale\n')
            command = [sys.executable, str(ROOT / 'tools/check_package.py'), '--source', str(source)]
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual(subprocess.run(command + ['--no-manifest'], capture_output=True).returncode, 0)

    def test_links_and_github_heading_anchors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / 'target.md'
            target.write_text('# Hello, World!\n\n## Repeat\n## Repeat\n')
            source = root / 'source.md'
            source.write_text('[one](target.md#hello-world) [two](target.md#repeat-1)\n')
            self.assertEqual(check_links.check(root, [source, target]), [])
            source.write_text('[broken](target.md#missing)\n')
            self.assertIn('missing anchor', check_links.check(root, [source])[0])

    @unittest.skipUnless((ROOT / '.git').exists(), 'requires a Git checkout')
    def test_tracked_markdown_links(self):
        self.assertEqual(subprocess.run([sys.executable, str(ROOT / 'tools/check_links.py')], cwd=ROOT).returncode, 0)

    @unittest.skipUnless((ROOT / '.github/workflows/ci.yml').exists(), 'workflow is not in source archives')
    def test_workflow_actions_are_pinned_and_permissions_read_only(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        actions = re.findall(r'^\s*-?\s*uses:\s*(\S+)', workflow, re.M)
        self.assertTrue(actions)
        self.assertTrue(all(re.fullmatch(r'[^@]+@[0-9a-f]{40}', action) for action in actions))
        self.assertRegex(workflow, r'(?m)^permissions:\n  contents: read\n')

    def test_report_records_python_base_digest(self):
        identity = {'Os': 'linux', 'Architecture': 'arm64', 'Id': 'sha256:image',
                    'Config': {'Labels': {'ci.python-image-reference': 'python@sha256:' + 'a' * 64}}}
        result_row = {'exit_code': 0, 'stdout': 'Python 3.14.0\nv24.0.0', 'stderr': '', 'command': [], 'seconds': 0}
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(docker_ci, 'docker', return_value=json.dumps([identity])), \
             mock.patch.object(docker_ci, 'stage', side_effect=lambda destination: destination.mkdir() or destination), \
             mock.patch.object(docker_ci, 'container', return_value=result_row.copy()):
            report = Path(temporary) / 'report.json'
            result = docker_ci.run('image', report, platform='linux/arm64')
            self.assertEqual(result['python_image_digest'], 'sha256:' + 'a' * 64)
            self.assertEqual(json.loads(report.read_text())['python_image_digest'], 'sha256:' + 'a' * 64)


if __name__ == '__main__':
    unittest.main()
