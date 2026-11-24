import contextlib
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

TESTS = Path(__file__).resolve().parent
SCRIPTS = TESTS.parent / 'skill' / 'scripts'
FIXTURES = TESTS / 'fixtures' / 'init-plan'
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import init_plan
import pi_lab

PYTHON_CHECK = ['python3', '/opt/pi-lab/verify-unittest.py', '--start-dir', 'tests']


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = pi_lab.cli(['init-plan', *argv])
    return code, out.getvalue(), err.getvalue()


class InitPlanTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.temp = Path(temp.name)
        self.output = self.temp / 'plan.json'

    def copy(self, kind):
        target = self.temp / kind
        shutil.copytree(FIXTURES / kind, target)
        return target

    def generate(self, project, *extra, task='Implement the behavior.'):
        code, out, err = run('--project', str(project), '--task', task, '--output', str(self.output), *extra)
        self.assertEqual(code, 0, err)
        plan = json.loads(self.output.read_text())
        base = project if isinstance(project, Path) else Path(project)
        self.assertEqual(pi_lab.validate_plan(plan, base)['schema'], 1)
        return plan, out

    def checks(self, plan):
        return [check['argv'] for check in plan['checks']]

    def test_each_kind_gets_its_default_check_and_protected_paths(self):
        cases = {
            'python': (PYTHON_CHECK, ['tests', 'spec']),
            'node': (['node', '--test'], ['test']),
            'go': (['go', 'test', './...'], []),
            'rust': (['cargo', 'test', '--offline'], []),
        }
        for kind, (argv, protected) in cases.items():
            with self.subTest(kind=kind):
                self.output.unlink(missing_ok=True)
                plan, out = self.generate(FIXTURES / kind)
                self.assertEqual(self.checks(plan), [argv])
                self.assertEqual(plan['protected_paths'], protected)
                self.assertEqual(plan['required_paths'], protected)
                self.assertEqual(plan['setup'], [])
                self.assertEqual(plan['checks'][0]['network'], 'none')
                self.assertIn(f'a {kind} project', out)
                self.assertIn('1 check(s)', out)
                self.assertIn('dependency manifest', out)
                self.assertIn('network is off', out)

    def test_generic_project_with_check_has_no_setup_note(self):
        plan, out = self.generate(FIXTURES / 'generic', '--check', 'sh run-tests')
        self.assertEqual(self.checks(plan), [['sh', 'run-tests']])
        self.assertEqual(plan['protected_paths'], [])
        self.assertIn('a generic project', out)
        self.assertNotIn('dependency manifest', out)

    def test_agents_follow_the_python_template(self):
        template = json.loads((SCRIPTS.parent / 'assets' / 'python-feature.plan.json').read_text())
        roles = {agent['name']: agent for agent in template['agents']}
        plan, _ = self.generate(FIXTURES / 'python', task='Make slug lowercase words.')
        self.assertEqual([agent['name'] for agent in plan['agents']], ['implementer', 'reviewer'])
        for agent in plan['agents']:
            for field in init_plan.AGENT_FIELDS:
                self.assertEqual(agent[field], roles[agent['name']][field], field)
        self.assertEqual(plan['agents'][0]['access'], 'rw')
        self.assertEqual(plan['agents'][1]['access'], 'ro')
        prompt = plan['agents'][0]['prompt']
        self.assertIn('Make slug lowercase words.', prompt)
        self.assertIn('Do not change these protected paths: tests, spec.', prompt)
        self.assertIn('python3 /opt/pi-lab/verify-unittest.py --start-dir tests', prompt)

    def test_no_reviewer_leaves_only_the_implementer(self):
        plan, _ = self.generate(FIXTURES / 'node', '--no-reviewer')
        self.assertEqual([agent['name'] for agent in plan['agents']], ['implementer'])

    def test_protect_option_and_inside_task_file_are_protected(self):
        project = self.copy('node')
        (project / 'task.md').write_text('Make normalize trim input.\n')
        code, _, err = run('--project', str(project), '--task-file', str(project / 'task.md'),
                           '--protect', './package.json', '--protect', 'test', '--output', str(self.output))
        self.assertEqual(code, 0, err)
        plan = json.loads(self.output.read_text())
        self.assertEqual(plan['protected_paths'], ['test', 'package.json', 'task.md'])
        self.assertIn('Make normalize trim input.', plan['agents'][0]['prompt'])
        pi_lab.validate_plan(plan, project)

    def test_task_file_outside_the_project_is_not_a_protected_path(self):
        task = self.temp / 'task.md'
        task.write_text('Outside task.\n')
        code, _, err = run('--project', str(FIXTURES / 'go'), '--task-file', str(task),
                           '--output', str(self.output))
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(self.output.read_text())['protected_paths'], [])

    def test_protect_must_exist_and_stay_inside_the_project(self):
        for value in ('missing.txt', '../escape', '/etc'):
            with self.subTest(value=value):
                code, _, err = run('--project', str(FIXTURES / 'go'), '--task', 'x', '--protect', value,
                                   '--output', str(self.output))
                self.assertEqual(code, 2, err)
                self.assertFalse(self.output.exists())

    def test_marker_and_python_files_select_python(self):
        project = self.temp / 'bare'
        (project / 'tests').mkdir(parents=True)
        (project / 'tests' / 'test_a.py').write_text('')
        (project / 'package.json').write_text('{}')
        self.assertEqual(init_plan.detect_kind(project), 'python')
        (project / 'tests' / 'test_a.py').unlink()
        self.assertEqual(init_plan.detect_kind(project), 'node')
        (project / 'package.json').unlink()
        self.assertEqual(init_plan.detect_kind(project), 'generic')
        (project / 'go.mod').write_text('module m\n')
        (project / 'Cargo.toml').write_text('')
        self.assertEqual(init_plan.detect_kind(project), 'go')
        (project / 'requirements.txt').write_text('')
        self.assertEqual(init_plan.detect_kind(project), 'python')

    def test_python_without_tests_directory_needs_a_check(self):
        project = self.temp / 'py'
        project.mkdir()
        (project / 'requirements.txt').write_text('')
        code, _, err = run('--project', str(project), '--task', 'x', '--output', str(self.output))
        self.assertEqual(code, 2)
        self.assertIn('--check', err)
        self.assertFalse(self.output.exists())

    def test_generic_project_without_check_exits_2_and_names_the_option(self):
        code, out, err = run('--project', str(FIXTURES / 'generic'), '--task', 'x', '--output', str(self.output))
        self.assertEqual(code, 2)
        self.assertIn('--check', err)
        self.assertEqual(out, '')
        self.assertFalse(self.output.exists())

    def test_existing_output_is_refused_and_left_unchanged(self):
        self.output.write_text('keep me')
        code, _, err = run('--project', str(FIXTURES / 'go'), '--task', 'x', '--output', str(self.output))
        self.assertEqual(code, 2)
        self.assertIn('already exists', err)
        self.assertEqual(self.output.read_text(), 'keep me')

    def test_existing_symlink_output_is_refused(self):
        target = self.temp / 'target.json'
        self.output.symlink_to(target)
        code, _, _ = run('--project', str(FIXTURES / 'go'), '--task', 'x', '--output', str(self.output))
        self.assertEqual(code, 2)
        self.assertFalse(target.exists())

    def test_default_output_is_pi_plan_json_in_the_working_directory(self):
        import os
        previous = Path.cwd()
        os.chdir(self.temp)
        self.addCleanup(os.chdir, previous)
        code, _, err = run('--project', str(FIXTURES / 'go'), '--task', 'x')
        self.assertEqual(code, 0, err)
        self.assertTrue((self.temp / 'pi-plan.json').is_file())
        code, _, _ = run('--project', str(FIXTURES / 'go'), '--task', 'x')
        self.assertEqual(code, 2)

    def test_check_is_split_into_arguments(self):
        plan, _ = self.generate(FIXTURES / 'generic', '--check', 'pytest -q tests/unit')
        self.assertEqual(self.checks(plan), [['pytest', '-q', 'tests/unit']])
        self.assertEqual(init_plan.split_check('run "a b" \'c|d\' e\\ f'), ['run', 'a b', 'c|d', 'e f'])

    def test_repeated_checks_replace_the_default_and_are_counted(self):
        plan, out = self.generate(FIXTURES / 'python', '--check', 'pytest -q', '--check', 'ruff check .')
        self.assertEqual(self.checks(plan), [['pytest', '-q'], ['ruff', 'check', '.']])
        self.assertEqual([check['name'] for check in plan['checks']], ['check-1', 'check-2'])
        self.assertIn('2 check(s)', out)

    def test_shell_operators_are_refused(self):
        for text in ('pytest | tee log', 'pytest > out.txt', 'pytest 2>&1', 'make && make test',
                     'make; make test', 'pytest < in', 'echo $(date)', 'echo `date`', '(cd x)',
                     'make "$(date)"', 'make\nmake test', 'pytest &'):
            with self.subTest(text=text):
                code, _, err = run('--project', str(FIXTURES / 'generic'), '--task', 'x',
                                   '--check', text, '--output', str(self.output))
                self.assertEqual(code, 2, err)
                self.assertIn('shell', err)
                self.assertFalse(self.output.exists())

    def test_quoted_operators_and_malformed_checks(self):
        self.assertEqual(init_plan.split_check("grep -c 'a|b' f"), ['grep', '-c', 'a|b', 'f'])
        self.assertEqual(init_plan.split_check('echo "a > b"'), ['echo', 'a > b'])
        for text in ('', '   ', 'pytest "unterminated', 'DEBUG=1 pytest'):
            with self.subTest(text=text):
                with self.assertRaises(pi_lab.LabError):
                    init_plan.split_check(text)

    def test_task_must_not_be_empty_and_project_must_exist(self):
        code, _, _ = run('--project', str(FIXTURES / 'go'), '--task', '  ', '--output', str(self.output))
        self.assertEqual(code, 2)
        code, _, _ = run('--project', str(self.temp / 'absent'), '--task', 'x', '--output', str(self.output))
        self.assertEqual(code, 2)
        self.assertFalse(self.output.exists())

    def test_task_and_task_file_are_mutually_exclusive_and_one_is_required(self):
        for extra in ((), ('--task', 'a', '--task-file', 'b')):
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    pi_lab.main(['init-plan', '--project', str(FIXTURES / 'go'), *extra])
                self.assertEqual(caught.exception.code, 2)

    def test_command_is_listed_in_help(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaises(SystemExit):
                pi_lab.main(['--help'])
        self.assertIn('init-plan', out.getvalue())


if __name__ == '__main__':
    unittest.main()
