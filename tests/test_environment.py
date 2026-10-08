"""Tests for the saved environment, per-session confirmation, discovery, and the run gate."""
from __future__ import annotations
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

ROOT = (Path(__file__).resolve().parents[1] / 'skill')
sys.path.insert(0, str(ROOT / 'scripts'))

import lab_env
import pi_lab as lab

MODELS = {'data': [
    {'id': 'alpha', 'owned_by': 'me', 'meta': {'n_ctx_train': 40960, 'n_params': 7_000_000_000}},
    {'id': 'beta', 'max_model_len': 8192},
]}


class FakeServer:
    """Minimal OpenAI-compatible server. `state` lets a test break it mid-way."""
    def __init__(self, require_key='secret-key'):
        outer = self
        self.require_key = require_key
        self.models = MODELS

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _authorized(self):
                return not outer.require_key or self.headers.get('Authorization') == f'Bearer {outer.require_key}'

            def do_GET(self):
                if not self._authorized():
                    return self._send(401, {'error': 'no'})
                if self.path == '/v1/models':
                    return self._send(200, outer.models)
                if self.path == '/props':
                    return self._send(200, {'default_generation_settings': {'n_ctx': 16384}})
                self._send(404, {})

            def do_POST(self):
                self.rfile.read(int(self.headers.get('Content-Length', 0)))
                if not self._authorized():
                    return self._send(401, {})
                self._send(200, {'choices': [{'message': {'content': 'OK'}}]})

        self.httpd = HTTPServer(('127.0.0.1', 0), Handler)
        self.url = f'http://127.0.0.1:{self.httpd.server_port}/v1'
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        if getattr(self, 'closed', False):
            return
        self.closed = True
        self.httpd.shutdown()
        self.httpd.server_close()


class EnvTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        patcher = mock.patch.dict(os.environ, {
            'PI_LAB_CONFIG_DIR': str(base / 'config'), 'PI_LAB_STATE_DIR': str(base / 'state'),
            'PI_LAB_SECRETS_DIR': str(base / 'secrets'), 'TEST_LAB_KEY': 'secret-key'})
        patcher.start()
        os.environ.pop('PI_LAB_SESSION', None)
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)
        self.server = FakeServer()
        self.addCleanup(self.server.close)

    def env(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = lab.main(['env', *argv])
        text = out.getvalue().strip()
        try:
            return code, json.loads(text)
        except ValueError:
            return code, text

    def save(self, session='s1', **extra):
        args = ['save', '--base-url', self.server.url, '--model', 'alpha', '--api-key-env', 'TEST_LAB_KEY',
                '--context-window', '16384', '--max-tokens', '2048', '--session', session]
        return self.env(*args, *extra.get('more', []))


class SessionGateTests(EnvTestCase):
    def test_no_environment_state(self):
        code, report = self.env('status', '--session', 's1')
        self.assertEqual((code, report['state']), (lab_env.EXIT_NO_ENV, 'no-environment'))

    def test_session_required(self):
        code, report = self.env('status')
        self.assertNotEqual(code, 0)
        self.assertEqual(report['reason'], 'missing-session')

    def test_save_confirms_current_session_only(self):
        code, saved = self.save('s1')
        self.assertEqual(code, 0, saved)
        self.assertEqual(self.env('status', '--session', 's1')[1]['state'], 'ready')
        code, other = self.env('status', '--session', 'brand-new')
        self.assertEqual((code, other['state']), (lab_env.EXIT_NEEDS_CONFIRM, 'needs-confirmation'))
        self.assertEqual(other['environment']['model'], 'alpha')

    def test_confirm_makes_new_session_ready(self):
        self.save('s1')
        self.assertEqual(self.env('confirm', '--session', 's2')[0], 0)
        self.assertEqual(self.env('status', '--session', 's2')[1]['state'], 'ready')

    def test_changed_environment_invalidates_confirmation(self):
        self.save('s1')
        self.env('save', '--base-url', self.server.url, '--model', 'beta', '--api-key-env', 'TEST_LAB_KEY',
                 '--context-window', '4096', '--max-tokens', '512')  # no --session: nothing confirmed
        code, report = self.env('status', '--session', 's1')
        self.assertEqual(report['state'], 'needs-confirmation')

    def test_broken_when_model_disappears_then_recovers(self):
        self.save('s1')
        self.server.models = {'data': [{'id': 'other'}]}
        code, report = self.env('status', '--session', 's1')
        self.assertEqual((code, report['state'], report['reason']), (lab_env.EXIT_BROKEN, 'broken', 'model-not-found'))
        self.server.models = MODELS
        self.assertEqual(self.env('status', '--session', 's1')[1]['state'], 'ready')

    def test_broken_when_key_missing_or_wrong(self):
        self.save('s1')
        with mock.patch.dict(os.environ, {'TEST_LAB_KEY': 'wrong'}):
            self.assertEqual(self.env('status', '--session', 's1')[1]['reason'], 'endpoint-auth-failed')
        del os.environ['TEST_LAB_KEY']
        self.assertEqual(self.env('status', '--session', 's1')[1]['reason'], 'missing-secret')

    def test_broken_when_server_down(self):
        self.save('s1')
        self.server.close()
        self.assertEqual(self.env('status', '--session', 's1')[1]['reason'], 'endpoint-unreachable')

    def test_corrupt_saved_file_reported(self):
        self.save('s1')
        lab_env.endpoint_path().write_text('{not json')
        code, report = self.env('status', '--session', 's1')
        self.assertEqual((report['state'], report['reason']), ('broken', 'environment-corrupt'))

    def test_clear(self):
        self.save('s1')
        self.assertTrue(self.env('clear', '--session', 's1')[1]['cleared'])
        self.assertEqual(self.env('status', '--session', 's1')[1]['state'], 'no-environment')

    def test_new_session_ids_unique_and_valid(self):
        ids = {self.env('new-session')[1] for _ in range(5)}
        self.assertEqual(len(ids), 5)
        self.assertTrue(all(lab_env.SESSION_RE.fullmatch(i) for i in ids))

    def test_invalid_session_rejected(self):
        self.assertEqual(self.env('status', '--session', '../evil')[1]['reason'], 'invalid-session')

    def test_old_sessions_purged(self):
        lab_env.confirm_session('old', 'x')
        path = lab_env.session_path('old')
        os.utime(path, (1, 1))
        lab_env.confirm_session('fresh', 'x')
        self.assertFalse(path.exists())


class DiscoveryAndSaveTests(EnvTestCase):
    def test_discover_lists_models_with_parameters(self):
        code, report = self.env('discover', '--base-url', self.server.url, '--api-key-env', 'TEST_LAB_KEY')
        self.assertEqual(code, 0, report)
        by_id = {m['id']: m for m in report['models']}
        self.assertIsNone(by_id['alpha']['context_window_hint'])
        self.assertEqual(by_id['alpha']['context']['training_maxima'][0]['value'],40960)
        self.assertEqual(by_id['alpha']['meta']['n_params'], 7_000_000_000)
        self.assertEqual(by_id['beta']['context_hint_source'], 'max_model_len')
        self.assertNotIn('server_loaded_context',report)
        self.assertEqual(by_id['alpha']['context']['props_association'],'unknown_model')
        self.assertNotIn('secret-key', json.dumps(report))

    def test_save_distinct_host_route_then_normal_gate(self):
        code,report=self.env('save','--base-url','http://docker-model:8080/v1','--host-base-url',self.server.url,
                             '--model','beta','--api-key-env','TEST_LAB_KEY','--context-window','8192',
                             '--max-tokens','1024','--session','paired')
        self.assertEqual(code,0,report)
        self.assertEqual(self.env('status','--session','paired')[1]['state'],'ready')
        saved,meta=lab_env.load_saved();saved['host_base_url']='http://changed.invalid/v1'
        lab_env.save_environment(saved)
        self.assertEqual(self.env('status','--session','paired')[1]['state'],'needs-confirmation')

    def test_discover_without_key_on_open_server(self):
        self.server.require_key = ''
        del os.environ['TEST_LAB_KEY']
        code, report = self.env('discover', '--base-url', self.server.url, '--api-key-env', 'TEST_LAB_KEY')
        self.assertEqual(code, 0)
        self.assertIn('not-required', report['auth'])

    def test_discover_auth_failure_has_reason(self):
        del os.environ['TEST_LAB_KEY']
        code, report = self.env('discover', '--base-url', self.server.url, '--api-key-env', 'TEST_LAB_KEY')
        self.assertEqual(report['reason'], 'endpoint-auth-failed')

    def test_base_url_defaults_to_v1_and_rejects_bad_input(self):
        self.assertEqual(lab_env.normalize_base_url('http://h:1/'), 'http://h:1/v1')
        for bad in ('ftp://h/v1', 'http://u:p@h/v1', 'http://h/api', 'nonsense'):
            with self.subTest(bad=bad), self.assertRaises(lab_env.EnvError):
                lab_env.normalize_base_url(bad)

    def test_save_rejects_invalid_values_without_writing(self):
        code, report = self.env('save', '--base-url', self.server.url, '--model', 'alpha',
                                '--api-key-env', 'TEST_LAB_KEY', '--context-window', '100', '--max-tokens', '200')
        self.assertEqual(report['reason'], 'invalid-endpoint')
        self.assertFalse(lab_env.endpoint_path().exists())

    def test_save_refuses_unlisted_model(self):
        code, report = self.env('save', '--base-url', self.server.url, '--model', 'ghost',
                                '--api-key-env', 'TEST_LAB_KEY', '--context-window', '4096', '--max-tokens', '512')
        self.assertEqual(report['reason'], 'model-not-found')
        self.assertFalse(lab_env.endpoint_path().exists())

    def test_no_auth_stores_dummy_key_and_no_secret_in_files(self):
        self.server.require_key = ''
        del os.environ['TEST_LAB_KEY']
        code, report = self.env('save', '--base-url', self.server.url, '--model', 'alpha',
                                '--api-key-env', 'PI_API_KEY', '--context-window', '4096', '--max-tokens', '512',
                                '--no-auth', '--session', 's1')
        self.assertEqual(code, 0, report)
        self.assertEqual(self.env('status', '--session', 's1')[1]['state'], 'ready')
        saved = lab_env.endpoint_path().read_text() + lab_env.meta_path().read_text()
        self.assertNotIn(lab_env.DUMMY_KEY, saved)

    def test_saved_file_is_runner_compatible_and_private(self):
        self.save('s1')
        endpoint = lab.load_endpoint(lab_env.endpoint_path())
        self.assertEqual(endpoint['model'], 'alpha')
        self.assertEqual(oct(lab_env.endpoint_path().stat().st_mode & 0o777), '0o600')
        self.assertNotIn('secret-key', lab_env.endpoint_path().read_text())


class RunGateTests(EnvTestCase):
    def args(self, **kw):
        base = dict(endpoint=None, session=None, secrets_dir=None)
        base.update(kw)
        return mock.Mock(**base)

    def test_explicit_endpoint_bypasses_gate(self):
        path = ROOT / 'assets/endpoint.example.json'
        self.assertEqual(lab.resolve_endpoint_path(self.args(endpoint=str(path))), path.resolve())

    def test_gate_blocks_each_state_with_reason(self):
        with self.assertRaises(lab.LabError) as ctx:
            lab.resolve_endpoint_path(self.args(session='s1'))
        self.assertEqual(ctx.exception.reason, 'environment-no-environment')
        self.save('s1')
        with self.assertRaises(lab.LabError) as ctx:
            lab.resolve_endpoint_path(self.args(session='fresh'))
        self.assertEqual(ctx.exception.reason, 'environment-needs-confirmation')
        with self.assertRaises(lab.LabError) as ctx:
            lab.resolve_endpoint_path(self.args())
        self.assertEqual(ctx.exception.reason, 'environment-needs-session')

    def test_gate_passes_when_ready(self):
        self.save('s1')
        self.assertEqual(lab.resolve_endpoint_path(self.args(session='s1')), lab_env.endpoint_path())

    def test_gate_blocks_broken(self):
        self.save('s1')
        self.server.models = {'data': []}
        with self.assertRaises(lab.LabError) as ctx:
            lab.resolve_endpoint_path(self.args(session='s1'))
        self.assertEqual(ctx.exception.reason, 'environment-broken')

    def test_preflight_requires_no_endpoint_flag(self):
        parsed = lab.parser().parse_args(['preflight', '--session', 's1'])
        self.assertIsNone(parsed.endpoint)


if __name__ == '__main__':
    unittest.main()
