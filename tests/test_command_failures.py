"""Command diagnostics with local plan files and synthetic host responses."""
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


# Exercise the CLI in a child process with both HTTP transports replaced.
MODEL_FIXTURE = """
import io, sys
from unittest.mock import patch
import pi_lab as lab

endpoint = {'model': 'fixture', 'api_key_env': 'TEST_KEY', 'base_url': 'https://example.invalid/v1'}
with patch.object(lab, 'docker_info', side_effect=lab.LabError('offline')), \\
     patch.object(lab, 'load_endpoint', return_value=endpoint), \\
     patch.object(lab.lab_env, 'load_saved', return_value=(endpoint, {})), \\
     patch.object(lab.lab_env, 'http_json', return_value=[]), \\
     patch('urllib.request.build_opener') as opener:
    opener.return_value.open.return_value = io.BytesIO(b'[]')
    sys.exit(lab.cli())
"""


class CommandFailureTests(unittest.TestCase):
    def test_cli_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = fixture(root)
            plan = Path(args.plan)
            numeric = json.loads(plan.read_text())
            numeric['agents'][0]['name'] = 5
            (root / 'numeric').write_text(json.dumps(numeric))
            (root / 'array').write_text('[]')
            (root / 'link').symlink_to(plan)
            (root / 'encoding').write_bytes(b'\xff')
            scripts = Path(lab.__file__).parent
            env = {**os.environ, 'PYTHONPATH': str(scripts), 'TEST_KEY': 'synthetic-inference',
                   'PI_LAB_DEBUG': '0', 'PI_LAB_SECRETS_DIR': str(root / 'secrets')}
            direct = [sys.executable, str(scripts / 'pi_lab.py')]
            models = [sys.executable, '-c', MODEL_FIXTURE]
            internal = [sys.executable, '-c',
                        "import sys, pi_lab; from unittest.mock import patch\n"
                        "with patch.object(pi_lab, 'parser', side_effect=RuntimeError('internal fixture')):\n"
                        "    sys.exit(pi_lab.cli())"]
            shape = 'BLOCKED [ValueError]: /models must return a JSON object with a data array'
            link = 'BLOCKED [LabError]: Plan path is a symlink; pass the regular plan file'
            rows = [
                ('plan array', direct + ['run', '--plan', str(root / 'array')], 2,
                 'BLOCKED [LabError]: Plan must be a JSON object'),
                ('numeric name', direct + ['validate-plan', '--plan', str(root / 'numeric')], 2,
                 'BLOCKED [LabError]: Agent names must be unique lowercase slugs'),
                ('health listing', models + ['env', 'check', '--no-chat'], 2, shape),
                ('doctor listing', models + ['doctor', '--endpoint', str(root / 'endpoint')], 2, shape),
                ('linked run plan', direct + ['run', '--plan', str(root / 'link')], 2, link),
                ('linked validation plan', direct + ['validate-plan', '--plan', str(root / 'link')], 2, link),
                ('plan encoding', direct + ['run', '--plan', str(root / 'encoding')], 2,
                 "BLOCKED [UnicodeDecodeError]: 'utf-8' codec can't decode byte 0xff in position 0: invalid start byte"),
                ('internal error', internal, 70, 'INTERNAL [RuntimeError]: internal fixture'),
            ]
            for name, command, code, message in rows:
                with self.subTest(name=name):
                    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=15)
                    self.assertEqual(result.returncode, code, result.stderr)
                    self.assertEqual(result.stderr.splitlines(), [message])
            debug = subprocess.run(internal, env={**env, 'PI_LAB_DEBUG': '1'},
                                   capture_output=True, text=True, timeout=15)
            self.assertEqual(debug.returncode, 70)
            self.assertIn('Traceback (most recent call last):', debug.stderr)

    def suite_fixture(self, root, stack):
        args = fixture(root)
        args.secrets_dir = str(root / 'secrets')
        mocked_suite(stack)
        # Start with a private attempt directory. Exercise the real one-way result seal.
        record = lab.outcomes.initial()
        evidence = root / 'attempt'
        evidence.mkdir()
        lab.save(evidence / 'identity.json', {key: record[key] for key in ('run_id', 'attempt_id')})
        attempt = lab.outcomes.Attempt.attach_unsealed(evidence, record)
        stack.enter_context(mock.patch.object(lab.outcomes, 'Attempt', return_value=attempt))
        stack.enter_context(mock.patch.object(lab, '_suite_admission', return_value=contextlib.nullcontext()))
        errors = stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
        return args, evidence / 'result.json', errors

    def test_setup_and_copy_failures_show_phase_and_keep_digest(self):
        for phase, message in [
            ('setup', 'Setup command failed: setup-1-install'),
            ('plan', 'Project copy exceeds 1 MiB; add --exclude or stage a smaller checkout'),
        ]:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
                args, result, errors = self.suite_fixture(Path(directory), stack)
                if phase == 'setup':
                    plan = json.loads(Path(args.plan).read_text())
                    plan['setup'] = [{'name': 'install', 'argv': ['false']}]
                    lab.save(Path(args.plan), plan)
                    def stage(*args, **kwargs):
                        return {'exit_code': int(args[4].startswith('setup')), 'cleanup_confirmed': True}
                    stack.enter_context(mock.patch.object(lab, 'run_stage', side_effect=stage))
                else:
                    args.max_project_mb = 1
                    with (Path(args.project) / 'large').open('wb') as handle:
                        handle.truncate(1024 * 1024 + 1)
                self.assertEqual(lab.run_suite(args), 2)
                self.assertIn(f'BLOCKED [LabError] phase={phase}: {message}', errors.getvalue().splitlines())
                self.assertNotIn(message, result.read_text())
                self.assertEqual(json.loads(result.read_text())['infrastructure'],
                                 {'status': 'failed', 'phase': phase, 'reason': 'LabError',
                                  'error_digest': hashlib.sha256(message.encode()).hexdigest()})

    def test_known_keys_are_redacted_from_message_remedy_and_debug_traceback(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            args, result, errors = self.suite_fixture(Path(directory), stack)
            key = 'synthetic-application-secret'
            lab.secret_store.write_secret('APP_FIXTURE', key, args.secrets_dir)
            plan = json.loads(Path(args.plan).read_text())
            plan['agents'][0]['application_secrets'] = {'PI_APP_FIXTURE': 'APP_FIXTURE'}
            lab.save(Path(args.plan), plan)
            detail = 'Access to https://example.invalid/path failed with synthetic-key and ' + key
            failure = lab.LabError(detail, remedy='Replace ' + key)
            stack.enter_context(mock.patch.dict(os.environ, {'PI_LAB_DEBUG': '1'}))
            stack.enter_context(mock.patch.object(lab, 'require_host', side_effect=failure))
            self.assertEqual(lab.run_suite(args), 2)
            output = errors.getvalue()
            self.assertIn('Access to <REDACTED> failed with <REDACTED> and <REDACTED>', output)
            self.assertIn('Remedy: Replace <REDACTED>', output)
            self.assertIn('Traceback (most recent call last):', output)
            for value in (key, 'synthetic-key', 'example.invalid/path'):
                self.assertNotIn(value, output)
                self.assertNotIn(value, result.read_text())

    def test_internal_run_failure_seals_without_trusting_exception_attributes(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            args, result, errors = self.suite_fixture(Path(directory), stack)
            failure = RuntimeError('first line\nsecond line')
            failure.reason = failure.remedy = 'untrusted'
            stack.enter_context(mock.patch.object(lab, 'require_host', side_effect=failure))
            self.assertEqual(lab.run_suite(args), 70)
            self.assertEqual(errors.getvalue().splitlines(), ['INTERNAL [RuntimeError]: first line second line'])
            saved = json.loads(result.read_text())
            self.assertTrue(saved['sealed'])
            self.assertEqual(saved['infrastructure']['reason'], 'RuntimeError')
            self.assertNotIn('untrusted', result.read_text())


if __name__ == '__main__':
    unittest.main()
