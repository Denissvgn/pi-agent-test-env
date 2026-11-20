"""CLI failure diagnostics with isolated host inputs and synthetic transports."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tests.test_results import fixture, lab, mocked_suite


class CliFailureTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        env = mock.patch.dict(os.environ, {
            'HOME': str(self.root), 'PI_LAB_CONFIG_DIR': str(self.root / 'config'),
            'PI_LAB_SECRETS_DIR': str(self.root / 'secrets'),
        }, clear=True)
        env.start()
        self.addCleanup(env.stop)

    def test_command_line_inputs(self):
        args = fixture(self.root)
        valid = Path(args.plan)
        bad_name = self.root / 'name.json'
        plan = json.loads(valid.read_text())
        plan['agents'][0]['name'] = 5
        lab.save(bad_name, plan)
        array = self.root / 'array.json'
        array.write_text('[]')
        undecodable = self.root / 'encoding.json'
        undecodable.write_bytes(b'\xff')
        link = self.root / 'link.json'
        link.symlink_to(valid)
        endpoint = {'base_url': 'https://example.invalid/v1', 'api_key_env': 'TEST_ENDPOINT_KEY',
                    'model': 'fixture-model', 'max_tokens': 1024, 'context_window': 8192}
        lab.lab_env.save_environment(endpoint)
        os.environ['TEST_ENDPOINT_KEY'] = 'synthetic-model-list-key'
        rows = [
            (['run', '--plan', str(array)], 'Plan must be a JSON object'),
            (['validate-plan', '--plan', str(bad_name)], 'Agent names must be unique lowercase slugs'),
            (['run', '--plan', str(link)], 'Plan path is a symlink'),
            (['validate-plan', '--plan', str(link)], 'Plan path is a symlink'),
            (['run', '--plan', str(undecodable)], 'Plan file must be UTF-8'),
            (['validate-plan', '--plan', str(undecodable)], 'Plan file must be UTF-8'),
            (['env', 'check', '--no-chat'], '/models must return a JSON object with a data array'),
            (['doctor', '--endpoint', str(lab.lab_env.endpoint_path())],
             '/models must return a JSON object with a data array'),
        ]
        # Only model-list rows substitute the HTTP transport. Every row runs the executable.
        offline_models = ('import io, runpy, sys\n'
                          'from unittest.mock import patch\n'
                          'script = sys.argv.pop(1)\n'
                          'with patch("urllib.request.OpenerDirector.open", return_value=io.BytesIO(b"[]")):\n'
                          '    runpy.run_path(script, run_name="__main__")\n')
        for argv, message in rows:
            with self.subTest(command=argv[0], message=message):
                bootstrap = ['-c', offline_models] if argv[0] in ('env', 'doctor') else []
                result = subprocess.run(
                    [sys.executable, '-B', *bootstrap, lab.__file__, *argv], cwd=self.root,
                    env={**os.environ, 'PATH': '', 'PYTHONPATH': str(Path(lab.__file__).parent)},
                    capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 2, result.stderr)
                lines = result.stderr.splitlines()
                self.assertEqual(len(lines), 2, lines)
                self.assertRegex(lines[0], r'^BLOCKED \[LabError\] phase=\w+: ')
                self.assertIn(message, lines[0])
                self.assertTrue(lines[1].startswith('Remedy: '))
                self.assertNotIn('Traceback', result.stderr)

    def test_executable_exit_and_debug_traceback(self):
        # Inject an unexpected failure at a command boundary in a fresh interpreter.
        launch = ('import sys, runpy\n'
                  'from unittest.mock import patch\n'
                  'script = sys.argv.pop(1)\n'
                  'with patch("agent_profiles.load", side_effect=TypeError("unexpected fixture failure")):\n'
                  '    runpy.run_path(script, run_name="__main__")\n')
        for debug in ('0', '1'):
            with self.subTest(debug=debug):
                result = subprocess.run(
                    [sys.executable, '-B', '-c', launch, lab.__file__, 'validate-agent-profile',
                     '--agent-profile', 'unused'], cwd=self.root, capture_output=True, text=True,
                    env={**os.environ, 'PYTHONPATH': str(Path(lab.__file__).parent), 'PI_LAB_DEBUG': debug},
                    timeout=15)
                self.assertEqual(result.returncode, 70, result.stderr)
                self.assertEqual(result.stderr.splitlines()[0], 'INTERNAL [TypeError]: unexpected fixture failure')
                self.assertEqual('Traceback (most recent call last)' in result.stderr, debug == '1')

    def test_run_blockers_keep_the_sentence_out_of_the_result(self):
        for phase, sentence in [
            ('setup', 'Setup command failed: setup-1-install'),
            ('plan', 'Project copy exceeds 1 MiB; add --exclude or stage a smaller checkout'),
        ]:
            with self.subTest(phase=phase), contextlib.ExitStack() as stack:
                top = self.root / phase
                top.mkdir()
                args = fixture(top)
                mocked_suite(stack)
                if phase == 'setup':
                    plan = json.loads(Path(args.plan).read_text())
                    plan['setup'] = [{'name': 'install', 'argv': ['false']}]
                    lab.save(Path(args.plan), plan)
                    def stage(args, image, root, workspace, label, operation, **kwargs):
                        return {'exit_code': int(label == 'setup-1-install'), 'cleanup_confirmed': True}
                    stack.enter_context(mock.patch.object(lab, 'run_stage', side_effect=stage))
                else:
                    args.max_project_mb = 1
                    with (Path(args.project) / 'large').open('wb') as source:
                        source.truncate(1024 * 1024 + 1)
                errors = stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
                self.assertEqual(lab.run_suite(args), 2)
                self.assertIn(f'BLOCKED [LabError] phase={phase}: {sentence}', errors.getvalue().splitlines())
                record = (top / 'results/latest/result.json').read_text()
                self.assertNotIn(sentence, record)
                self.assertEqual(json.loads(record)['infrastructure'], {
                    'status': 'failed', 'phase': phase, 'reason': 'LabError',
                    'error_digest': hashlib.sha256(sentence.encode()).hexdigest(),
                })

    def test_resolved_values_and_routes_are_redacted_including_debug_output(self):
        inference = 'synthetic-inference-placeholder'
        application = 'synthetic-application-placeholder'
        endpoint = 'https://example.invalid/private-route'
        sentence = f'Preparation stopped for {inference} and {application} at {endpoint}'
        args = fixture(self.root)
        args.secrets_dir = str(self.root / 'secrets')
        lab.secret_store.write_secret('TEST_APPLICATION', application, args.secrets_dir)
        os.environ.update(PI_API_KEY=inference, PI_LAB_DEBUG='1')
        plan = json.loads(Path(args.plan).read_text())
        plan['agents'][0]['application_secrets'] = {'PI_APP_FIXTURE': 'TEST_APPLICATION'}
        lab.save(Path(args.plan), plan)
        endpoint_secret = lab.endpoint_secret
        for exc, code in [(lab.LabError(sentence, remedy='Check ' + application), 2), (TypeError(sentence), 70)]:
            with self.subTest(error=type(exc).__name__), contextlib.ExitStack() as stack:
                mocked_suite(stack)
                stack.enter_context(mock.patch.object(lab, 'endpoint_secret', endpoint_secret))
                stack.enter_context(mock.patch.object(lab, 'require_host', side_effect=exc))
                errors = stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
                self.assertEqual(lab.run_suite(args), code)
                text = errors.getvalue()
                self.assertIn('Preparation stopped for <REDACTED> and <REDACTED> at <REDACTED>', text)
                if code == 2:
                    self.assertIn('Remedy: Check <REDACTED>', text.splitlines())
                self.assertIn('Traceback (most recent call last)', text)
                record = (self.root / 'results/latest/result.json').read_text()
                for value in (inference, application, endpoint):
                    self.assertNotIn(value, text)
                    self.assertNotIn(value, record)
                self.assertNotIn(sentence, record)
                self.assertEqual(json.loads(record)['infrastructure']['reason'], type(exc).__name__)

    def test_unexpected_error_after_invocation_exits_70(self):
        args = fixture(self.root)

        def interrupted_stage(args, attempt, smoke):
            self.assertTrue(smoke)
            attempt.record['infrastructure'].update(status='ready', phase='agents')
            attempt.record['invocation'].update(status='invalid', attempted_stages=1)
            raise RuntimeError('Unexpected stage error')

        with mock.patch.object(lab, '_execute_suite', side_effect=interrupted_stage), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(lab.run_suite(args, smoke=True), 70)
        self.assertEqual(errors.getvalue().splitlines(), ['INTERNAL [RuntimeError]: Unexpected stage error'])
        record = json.loads((self.root / 'results/latest/result.json').read_text())
        self.assertTrue(record['sealed'])
        self.assertEqual(record['verdict']['outcome'], 'infrastructure_fault')
        self.assertNotIn('Unexpected stage error', json.dumps(record))

    def test_untrusted_reason_and_remedy_do_not_set_the_diagnostic(self):
        error = UnicodeDecodeError('utf-8', b'\xff', 0, 1, 'invalid start byte')
        error.remedy = 'untrusted remedy'
        with contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(lab.cli_failure(error), 2)
        self.assertTrue(errors.getvalue().startswith('BLOCKED [UnicodeDecodeError]'))
        self.assertNotIn(error.remedy, errors.getvalue())
        unexpected = RuntimeError('fixture')
        unexpected.reason = unexpected.remedy = 'untrusted attribute'
        attempt = lab.outcomes.Attempt(fixture(self.root))
        attempt.fail(unexpected)
        self.assertEqual(attempt.record['infrastructure']['reason'], 'RuntimeError')
        self.assertNotIn('remedy', attempt.record['infrastructure'])


if __name__ == '__main__':
    unittest.main()
