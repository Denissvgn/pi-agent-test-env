"""Unit tests for secret_store, diagnostics, and doctor/secrets commands in pi_lab."""
from __future__ import annotations
import argparse
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = (Path(__file__).resolve().parents[1] / 'skill')
sys.path.insert(0, str(ROOT / 'scripts'))

import diagnostics
import pi_lab as lab
import secret_store


class SecretStoreTests(unittest.TestCase):
    def test_check_name_valid_and_invalid(self):
        self.assertEqual(secret_store.check_name('UNSLOTH_API_KEY'), 'UNSLOTH_API_KEY')
        self.assertEqual(secret_store.check_name('A_1'), 'A_1')
        for bad in ('my-key', '123_KEY', 'FOO BAR', '', 'key', 'KEY$'):
            with self.subTest(bad=bad), self.assertRaises(secret_store.SecretError):
                secret_store.check_name(bad)

    def test_clean_value_validation(self):
        self.assertEqual(secret_store.clean_value('  secret-token-123\n'), 'secret-token-123')
        with self.assertRaises(secret_store.SecretError):
            secret_store.clean_value('')
        with self.assertRaises(secret_store.SecretError):
            secret_store.clean_value('   \t\n ')
        with self.assertRaises(secret_store.SecretError):
            secret_store.clean_value('x' * (secret_store.MAX_LEN + 1))
        with self.assertRaises(secret_store.SecretError):
            secret_store.clean_value('has space')
        with self.assertRaises(secret_store.SecretError):
            secret_store.clean_value('has\nnewline')

    def test_fingerprint(self):
        fp = secret_store.fingerprint('my-secret-value')
        self.assertTrue(fp.startswith('sha256:'))
        self.assertEqual(len(fp), 17)  # 'sha256:' (7) + 10 chars = 17
        self.assertEqual(fp, secret_store.fingerprint('my-secret-value'))
        self.assertNotEqual(fp, secret_store.fingerprint('other-value'))

    def test_write_and_read_secret(self):
        with tempfile.TemporaryDirectory() as td:
            store = Path(td) / 'secrets'
            written = secret_store.write_secret('TEST_KEY', 'super-secret-123', store)
            self.assertTrue(written.exists())
            # Directory should be 0700
            dir_mode = stat.S_IMODE(store.stat().st_mode)
            self.assertEqual(dir_mode, 0o700)
            # File should be 0600
            file_mode = stat.S_IMODE(written.stat().st_mode)
            self.assertEqual(file_mode, 0o600)
            # Read secret
            val = secret_store.read_secret('TEST_KEY', store)
            self.assertEqual(val, 'super-secret-123')

    def test_read_secret_nonexistent_returns_empty(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(secret_store.read_secret('NONEXISTENT', td), '')

    def test_read_secret_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            store = Path(td)
            real_file = store / 'real'
            real_file.write_text('token', encoding='utf-8')
            sym_file = store / 'TEST_KEY'
            sym_file.symlink_to(real_file)
            with self.assertRaises(secret_store.SecretError):
                secret_store.read_secret('TEST_KEY', store)

    def test_read_secret_rejects_insecure_permissions(self):
        with tempfile.TemporaryDirectory() as td:
            store = Path(td)
            sec_file = store / 'TEST_KEY'
            sec_file.write_text('token', encoding='utf-8')
            sec_file.chmod(0o644)
            with self.assertRaises(secret_store.SecretError):
                secret_store.read_secret('TEST_KEY', store)

    def test_delete_secret(self):
        with tempfile.TemporaryDirectory() as td:
            store = Path(td)
            secret_store.write_secret('TEST_KEY', 'val', store)
            self.assertTrue(secret_store.delete_secret('TEST_KEY', store))
            self.assertFalse(secret_store.delete_secret('TEST_KEY', store))

    def test_resolve_secret_precedence(self):
        with tempfile.TemporaryDirectory() as td:
            store = Path(td)
            secret_store.write_secret('MY_KEY', 'store-val', store)
            # Both env and store exist: env wins
            with mock.patch.dict(os.environ, {'MY_KEY': 'env-val'}):
                val, src = secret_store.resolve_secret('MY_KEY', store)
                self.assertEqual(val, 'env-val')
                self.assertEqual(src, 'env')

            # Only store exists
            with mock.patch.dict(os.environ, {}, clear=True):
                val, src = secret_store.resolve_secret('MY_KEY', store)
                self.assertEqual(val, 'store-val')
                self.assertEqual(src, 'store')

            # Neither exists
            with mock.patch.dict(os.environ, {}, clear=True):
                val, src = secret_store.resolve_secret('OTHER_KEY', store)
                self.assertEqual(val, '')
                self.assertEqual(src, '')

    def test_status_output_structure_and_no_leak(self):
        with tempfile.TemporaryDirectory() as td:
            store = Path(td)
            secret_store.write_secret('TARGET_KEY', 'unrevealed-key-content', store)
            st = secret_store.status('TARGET_KEY', store)
            self.assertEqual(st['name'], 'TARGET_KEY')
            self.assertTrue(st['store_present'])
            self.assertTrue(st['store_ok'])
            self.assertEqual(st['active_source'], 'store')
            self.assertTrue(st['fingerprint'].startswith('sha256:'))
            # Ensure raw secret string is not in status
            self.assertNotIn('unrevealed-key-content', json.dumps(st))

    def test_prompt_secret(self):
        with mock.patch('secret_store.has_terminal', return_value=True), \
             mock.patch('getpass.getpass', side_effect=['secret123', 'secret123']):
            val = secret_store.prompt_secret('TEST_KEY')
            self.assertEqual(val, 'secret123')

        # Mismatch raises
        with mock.patch('secret_store.has_terminal', return_value=True), \
             mock.patch('getpass.getpass', side_effect=['secret123', 'mismatch']):
            with self.assertRaises(secret_store.SecretError):
                secret_store.prompt_secret('TEST_KEY')

        # No terminal raises
        with mock.patch('secret_store.has_terminal', return_value=False):
            with self.assertRaises(secret_store.SecretError):
                secret_store.prompt_secret('TEST_KEY')

    def test_read_stdin_secret(self):
        with mock.patch('sys.stdin.isatty', return_value=True):
            with self.assertRaises(secret_store.SecretError):
                secret_store.read_stdin_secret()

        with mock.patch('sys.stdin.isatty', return_value=False), \
             mock.patch('sys.stdin.read', return_value='piped-secret-key\n'):
            val = secret_store.read_stdin_secret()
            self.assertEqual(val, 'piped-secret-key')


class DiagnosticsTests(unittest.TestCase):
    def test_classify_docker_error(self):
        self.assertEqual(diagnostics.classify_docker_error('permission denied while connecting to Docker'),
                         'docker-permission-denied')
        self.assertEqual(diagnostics.classify_docker_error('Operation not permitted'),
                         'docker-permission-denied')
        self.assertEqual(diagnostics.classify_docker_error('Access is denied'),
                         'docker-permission-denied')
        self.assertEqual(diagnostics.classify_docker_error('context "test" not found'),
                         'docker-context-invalid')
        self.assertEqual(diagnostics.classify_docker_error('Cannot connect to the Docker daemon at unix:///var/run/docker.sock'),
                         'docker-daemon-unavailable')
        self.assertEqual(diagnostics.classify_docker_error('connection refused'),
                         'docker-daemon-unavailable')
        self.assertEqual(diagnostics.classify_docker_error('some unexpected docker engine failure'),
                         'docker-error')

    def test_remedy_formatting(self):
        text = diagnostics.remedy('missing-secret', name='CUSTOM_KEY')
        self.assertIn('CUSTOM_KEY', text)
        self.assertIn('secrets set', text)

        img_text = diagnostics.remedy('image-missing', image='my-test-image:v1')
        self.assertIn('my-test-image:v1', img_text)

        unknown = diagnostics.remedy('unknown-reason')
        self.assertIn('docker info', unknown)

    def test_first_line(self):
        multiline = '\n\n  first actionable line  \nsecond line'
        self.assertEqual(diagnostics.first_line(multiline), 'first actionable line')
        self.assertEqual(diagnostics.first_line(''), '')


class PiLabDoctorAndSecretsCommandTests(unittest.TestCase):
    def test_cmd_secrets_set_from_file_and_clear(self):
        with tempfile.TemporaryDirectory() as td:
            store = Path(td) / 'secrets'
            keyfile = Path(td) / 'my.key'
            keyfile.write_text('unsloth-secret-token', encoding='utf-8')

            args_set = argparse.Namespace(secrets_op='set', name='UNSLOTH_API_KEY',
                                          from_file=str(keyfile), stdin=False, secrets_dir=str(store))
            code = lab.cmd_secrets(args_set)
            self.assertEqual(code, 0)
            self.assertEqual(secret_store.read_secret('UNSLOTH_API_KEY', store), 'unsloth-secret-token')

            # status
            args_status = argparse.Namespace(secrets_op='status', names=['UNSLOTH_API_KEY'],
                                             endpoint=None, secrets_dir=str(store))
            buf = io.StringIO()
            with mock.patch('sys.stdout', buf):
                code = lab.cmd_secrets(args_status)
            self.assertEqual(code, 0)
            parsed = json.loads(buf.getvalue())
            self.assertEqual(parsed[0]['active_source'], 'store')

            # clear
            args_clear = argparse.Namespace(secrets_op='clear', name='UNSLOTH_API_KEY', secrets_dir=str(store))
            code = lab.cmd_secrets(args_clear)
            self.assertEqual(code, 0)
            self.assertEqual(secret_store.read_secret('UNSLOTH_API_KEY', store), '')

    def test_cmd_doctor_reports_missing_secret_with_exit_code(self):
        with tempfile.TemporaryDirectory() as td:
            store = Path(td) / 'secrets'
            ep_file = Path(td) / 'endpoint.json'
            ep_file.write_text(json.dumps({
                'base_url': 'http://localhost:8000/v1',
                'model': 'test-model',
                'context_window': 8192,
                'max_tokens': 2048,
                'api_key_env': 'UNSLOTH_API_KEY'
            }))
            args = argparse.Namespace(
                image='pi-agent-tests:core',
                endpoint=str(ep_file),
                secrets_dir=str(store),
                skip_network=True,
                project=None,
                probe_image=False,
                lock_file=str(Path(td) / 'lock'),
                lock_wait_seconds=5
            )

            mock_docker_info = {'ServerVersion': '27.0.0', 'OSType': 'linux', 'Architecture': 'aarch64'}
            def mock_cmd(argv, **kwargs):
                if argv[:3] == ['docker', 'context', 'show']:
                    return argparse.Namespace(returncode=0, stdout='desktop-linux\n')
                if argv[:3] == ['docker', 'context', 'inspect']:
                    return argparse.Namespace(returncode=0, stdout=json.dumps([{'Endpoints': {'docker': {'Host': 'unix:///var/run/docker.sock'}}}]))
                if argv[:3] == ['docker', 'image', 'inspect']:
                    return argparse.Namespace(returncode=0, stdout='arm64\n')
                return argparse.Namespace(returncode=0, stdout='')

            with mock.patch.object(lab, 'docker_info', return_value=mock_docker_info), \
                 mock.patch.object(lab, 'command', side_effect=mock_cmd), \
                 mock.patch.dict(os.environ, {}, clear=True):
                buf = io.StringIO()
                with mock.patch('sys.stdout', buf):
                    code = lab.cmd_doctor(args)
                self.assertEqual(code, lab.EXIT_NEEDS_SECRET)
                report = json.loads(buf.getvalue())
                self.assertEqual(report['status'], 'BLOCKED')
                key_check = next(c for c in report['checks'] if c['check'] == 'endpoint-key')
                self.assertEqual(key_check['status'], 'fail')
                self.assertEqual(key_check['reason'], 'missing-secret')
                self.assertIn('secrets set', key_check['remedy'])

    def test_cmd_secrets_defaults_to_pi_api_key(self):
        with tempfile.TemporaryDirectory() as td:
            store = Path(td) / 'secrets'
            # 1. status without endpoint or explicit names defaults to PI_API_KEY
            p = lab.parser()
            args = p.parse_args(['secrets', 'status', '--secrets-dir', str(store)])
            buf = io.StringIO()
            with mock.patch('sys.stdout', buf):
                code = lab.cmd_secrets(args)
            self.assertEqual(code, lab.EXIT_NEEDS_SECRET)
            report = json.loads(buf.getvalue())
            self.assertEqual(len(report), 1)
            self.assertEqual(report[0]['name'], 'PI_API_KEY')
            self.assertEqual(report[0]['active_source'], 'missing')

            # 2. set without positional arg defaults to PI_API_KEY
            key_file = Path(td) / 'key.txt'
            key_file.write_text('secret-val-123\n')
            args_set = p.parse_args(['secrets', 'set', '--from-file', str(key_file), '--secrets-dir', str(store)])
            self.assertEqual(args_set.name, 'PI_API_KEY')
            code_set = lab.cmd_secrets(args_set)
            self.assertEqual(code_set, 0)
            self.assertTrue((store / 'PI_API_KEY').exists())

            # 3. status now reports store present
            buf = io.StringIO()
            with mock.patch('sys.stdout', buf):
                code = lab.cmd_secrets(args)
            self.assertEqual(code, 0)
            report = json.loads(buf.getvalue())
            self.assertEqual(report[0]['active_source'], 'store')

            # 4. clear without positional arg defaults to PI_API_KEY
            args_clear = p.parse_args(['secrets', 'clear', '--secrets-dir', str(store)])
            self.assertEqual(args_clear.name, 'PI_API_KEY')
            code_clear = lab.cmd_secrets(args_clear)
            self.assertEqual(code_clear, 0)
            self.assertFalse((store / 'PI_API_KEY').exists())


    def test_control_channels_creates_inbox_and_outbox(self):
        with tempfile.TemporaryDirectory() as td:
            ctrl = Path(td) / 'stage-ctrl'
            inbox, outbox = lab.control_channels(ctrl)
            self.assertTrue(inbox.is_dir())
            self.assertTrue(outbox.is_dir())
            self.assertEqual(inbox.name, 'inbox')
            self.assertEqual(outbox.name, 'outbox')

    def test_control_channels_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            ctrl = Path(td) / 'stage-ctrl'
            ctrl.mkdir()
            fake = Path(td) / 'fake'
            fake.mkdir()
            (ctrl / 'inbox').symlink_to(fake)
            with self.assertRaises(lab.LabError):
                lab.control_channels(ctrl)

    def test_worker_rejects_unversioned_controls(self):
        sys.path.insert(0,str(ROOT/'runtime'));import worker
        with tempfile.TemporaryDirectory() as td:
            inbox=Path(td)/'inbox';inbox.mkdir();outbox=Path(td)/'outbox';outbox.mkdir()
            (inbox/'limits.json').write_text(json.dumps({'max_turns':99}))
            self.assertFalse(worker.sync_dynamic_limits(inbox, {'max_turns':10}))
            (inbox/'steer.json').write_text(json.dumps({'id':'legacy','message':'x'}))
            self.assertIsNone(worker.check_steering(inbox,outbox))

    def test_export_packages_and_install_harness(self):
        import export_skill
        import zipfile

        with tempfile.TemporaryDirectory() as td:
            target_proj = Path(td) / 'my-project'
            target_proj.mkdir()
            export_dir = Path(td) / 'exports'
            export_dir.mkdir()

            # Test universal zip
            u_zip = export_skill.build_universal_zip(ROOT, export_dir / 'univ.zip')
            self.assertTrue(u_zip.exists())
            with zipfile.ZipFile(u_zip) as zf:
                names = zf.namelist()
                self.assertIn('pi-agent-test-env/SKILL.md', names)
                self.assertIn('pi-agent-test-env/skill.json', names)

            # Test Claude Code zip
            claude_zip = export_skill.build_claude_zip(ROOT, export_dir / 'claude.zip')
            self.assertTrue(claude_zip.exists())
            with zipfile.ZipFile(claude_zip) as zf:
                names = zf.namelist()
                self.assertIn('.claude/skills/pi-agent-test-env/SKILL.md', names)
                self.assertIn('.claude/commands/pi-agent-test-env.md', names)

            # Test Codex zip
            codex_zip = export_skill.build_codex_zip(ROOT, export_dir / 'codex.zip')
            self.assertTrue(codex_zip.exists())
            with zipfile.ZipFile(codex_zip) as zf:
                names = zf.namelist()
                self.assertIn('.agents/skills/pi-agent-test-env/SKILL.md', names)
                self.assertIn('.agents/skills/pi-agent-test-env/CODEX.md', names)

            # Test install into local harness directories
            msgs = export_skill.install_harness(ROOT, target_proj, 'all')
            self.assertTrue(len(msgs) >= 2)
            self.assertTrue((target_proj / '.claude/commands/pi-agent-test-env.md').exists())


if __name__ == '__main__':
    unittest.main()
