import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest import mock

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
SCRIPTS = ROOT / 'skill' / 'scripts'
for _path in (str(SCRIPTS), str(TESTS)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import command_modules
import pi_lab


def run_main(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        try:
            code = pi_lab.main(argv)
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue()


class VersionTests(unittest.TestCase):
    def test_version_matches_skill_json(self):
        expected = json.loads((ROOT / 'skill' / 'skill.json').read_text(encoding='utf-8'))['version']
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        done = subprocess.run([sys.executable, str(SCRIPTS / 'pi_lab.py'), '--version'],
                              capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout, f'pi-agent-test-env {expected}\n')


class RegistrationTests(unittest.TestCase):
    def test_sample_module_is_listed_parsed_and_returns_exit_code(self):
        with mock.patch.object(command_modules, 'COMMAND_MODULES', ('test_sample_command_module',)):
            code, help_text = run_main(['--help'])
            self.assertEqual(code, 0)
            self.assertIn('sample-greet', help_text)
            code, output = run_main(['sample-greet', '--name', 'pi', '--exit-code', '7'])
            self.assertEqual(code, 7)
            self.assertEqual(output, 'hello pi\n')
            code, output = run_main(['sample-greet'])
            self.assertEqual(code, 0)
            self.assertEqual(output, 'hello world\n')

    def test_unregistered_sample_is_absent(self):
        _, help_text = run_main(['--help'])
        self.assertNotIn('sample-greet', help_text)

    def test_unimportable_module_stops_with_its_name(self):
        with mock.patch.object(command_modules, 'COMMAND_MODULES', ('no_such_command_module',)):
            with self.assertRaises(SystemExit) as caught:
                pi_lab.parser()
        self.assertIn('no_such_command_module', str(caught.exception))

    def test_module_without_register_stops_with_its_name(self):
        bare = types.ModuleType('bare_command_module')
        with mock.patch.dict(sys.modules, {'bare_command_module': bare}):
            with mock.patch.object(command_modules, 'COMMAND_MODULES', ('bare_command_module',)):
                with self.assertRaises(SystemExit) as caught:
                    pi_lab.parser()
        self.assertIn('bare_command_module', str(caught.exception))

    def test_registered_names_are_sorted_and_importable(self):
        names = list(command_modules.COMMAND_MODULES)
        self.assertEqual(names, sorted(names))
        pi_lab.parser()


if __name__ == '__main__':
    unittest.main()
