"""Command-module seam and --version; local subprocesses only, no Docker, model or network."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

SKILL = Path(__file__).resolve().parents[1] / 'skill'
FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'command_modules'
sys.path.insert(0, str(SKILL / 'scripts'))
import command_modules
import pi_lab as lab


def run_main(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = lab.main(argv)
        except SystemExit as exit_:
            code = exit_.code
    return code, out.getvalue(), err.getvalue()


class VersionTests(unittest.TestCase):
    def test_version_matches_skill_json(self):
        version = json.loads((SKILL / 'skill.json').read_text(encoding='utf-8'))['version']
        result = subprocess.run([sys.executable, str(SKILL / 'scripts' / 'pi_lab.py'), '--version'],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f'pi-agent-test-env {version}\n')
        self.assertEqual(result.stderr, '')

    def test_version_is_listed_in_help(self):
        self.assertIn('--version', lab.parser().format_help())


class CommandModuleTests(unittest.TestCase):
    def setUp(self):
        for patch in (mock.patch.object(sys, 'path', [str(FIXTURES), *sys.path]),
                      mock.patch.dict(sys.modules)):
            patch.start()
            self.addCleanup(patch.stop)

    def register(self, *names):
        patch = mock.patch.object(command_modules, 'COMMAND_MODULES', names)
        patch.start()
        self.addCleanup(patch.stop)

    def test_registered_command_is_listed_by_help(self):
        self.register('sample_command')
        self.assertIn('sample-echo', lab.parser().format_help())
        code, out, _ = run_main(['--help'])
        self.assertEqual(code, 0)
        self.assertIn('sample-echo', out)

    def test_registered_command_parses_its_own_options(self):
        self.register('sample_command')
        args = lab.parser().parse_args(['sample-echo', '--text', 'hello', '--code', '3'])
        self.assertEqual((args.op, args.text, args.code), ('sample-echo', 'hello', 3))
        self.assertTrue(callable(args.handler))
        code, _, err = run_main(['sample-echo', '--code', 'not-a-number'])
        self.assertEqual(code, 2)
        self.assertIn('--code', err)

    def test_registered_command_returns_its_handler_exit_code(self):
        self.register('sample_command')
        code, out, _ = run_main(['sample-echo', '--text', 'hello', '--code', '7'])
        self.assertEqual(code, 7)
        self.assertEqual(out, 'sample:hello\n')
        code, out, _ = run_main(['sample-echo', '--text', 'ok'])
        self.assertEqual(code, 0)
        self.assertEqual(out, 'sample:ok\n')

    def test_command_is_absent_when_module_is_not_listed(self):
        self.register()
        self.assertNotIn('sample-echo', lab.parser().format_help())
        self.assertEqual(run_main(['sample-echo'])[0], 2)

    def test_built_in_commands_have_no_handler(self):
        self.register('sample_command')
        self.assertFalse(hasattr(lab.parser().parse_args(['validate-agent-profile', '--agent-profile', 'x']), 'handler'))

    def test_module_that_cannot_be_imported_stops_the_program_with_its_name(self):
        for name in ('module_that_does_not_exist', 'broken_command'):
            with self.subTest(name=name):
                self.register('sample_command', name)
                with self.assertRaises(SystemExit) as caught:
                    lab.parser()
                self.assertIn(name, str(caught.exception.code))
                code, _, err = run_main(['--help'])
                self.assertIn(name, str(code) + err)
                self.assertNotEqual(code, 0)

    def test_module_without_register_stops_the_program_with_its_name(self):
        self.register('no_register_command')
        with self.assertRaises(SystemExit) as caught:
            lab.parser()
        self.assertIn('no_register_command', str(caught.exception.code))
        self.assertIn('register', str(caught.exception.code))


class ModuleListTests(unittest.TestCase):
    def test_names_are_alphabetical_unique_and_one_per_line(self):
        names = list(command_modules.COMMAND_MODULES)
        self.assertEqual(names, sorted(set(names)))
        source = (SKILL / 'scripts' / 'command_modules.py').read_text(encoding='utf-8')
        lines = source.split('COMMAND_MODULES = (', 1)[1].split(')', 1)[0].strip().splitlines()
        self.assertEqual(len([line for line in lines if line.strip()]), len(names))

    def test_listed_modules_import_and_register(self):
        for name in command_modules.COMMAND_MODULES:
            with self.subTest(name=name):
                self.assertTrue(callable(getattr(__import__(name), 'register', None)))

    def test_module_registry_is_not_copied_into_the_application_helper(self):
        import application_client_service as service
        self.assertFalse([name for name in service.TRUSTED_CODE if 'command_modules' in name])


if __name__ == '__main__':
    unittest.main()
