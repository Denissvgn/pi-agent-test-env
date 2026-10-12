"""Credential regression tests: real local clients, synthetic Docker/Pi boundaries."""
import argparse
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1] / 'skill'
sys.path.insert(0, str(ROOT / 'scripts'))
import application_credentials as credentials
import pi_lab as lab
import secret_store
from test_results import fixture, mocked_suite

KEY_A = 'synthetic-persona-a-123456789'
KEY_B = 'synthetic-persona-b-987654321'
DECLARATION = {'PI_APP_WORKCHORD_API_KEY': 'WORKCHORD_A'}
ENDPOINT = {'api_key_env': 'PI_API_KEY'}


def plan():
    return {'schema': 1, 'agents': [
        {'name': 'a', 'prompt': 'Use the authorized application API.', 'application_secrets': DECLARATION},
        {'name': 'b', 'prompt': 'Use the authorized application API.', 'application_secrets': {'PI_APP_WORKCHORD_API_KEY': 'WORKCHORD_B'}},
        {'name': 'unassigned', 'prompt': 'Read the output.'}],
        'setup': [{'name': 'setup', 'argv': ['true']}],
        'checks': [{'name': 'independent', 'argv': ['true']}]}


class AdmissionTests(unittest.TestCase):
    def test_snapshot_scan_exceptions_discard_owned_copy_before_dispatch(self):
        for error in (OSError('unreadable entry'),RecursionError('inspection depth')):
            with self.subTest(error=type(error).__name__),tempfile.TemporaryDirectory() as td,contextlib.ExitStack() as stack:
                top=Path(td);args=fixture(top);lab.save(Path(args.plan),plan());args.secrets_dir=str(top/'secrets')
                secret_store.write_secret('WORKCHORD_A',KEY_A,args.secrets_dir)
                secret_store.write_secret('WORKCHORD_B',KEY_B,args.secrets_dir)
                mocked_suite(stack)
                stack.enter_context(mock.patch.object(credentials,'workspace_clean',side_effect=error))
                dispatch=stack.enter_context(mock.patch.object(lab,'run_stage'))
                self.assertEqual(lab.run_suite(args),2)
                dispatch.assert_not_called()
                root=(top/'results/latest').resolve()
                self.assertFalse((root/'workspace').exists())
                self.assertTrue((top/'project/code.py').exists())
                self.assertEqual(lab.controls.read(root/'result.json')['infrastructure']['reason'],'application-credentials')

    def test_images_cannot_supply_ambient_application_variables(self):
        image = [{'Os': 'linux', 'Architecture': 'arm64', 'Id': 'sha256:synthetic', 'Config': {'Env': ['PI_APP_PERSONA=synthetic-baked-value']}}]
        with mock.patch.object(lab, 'command', return_value=argparse.Namespace(stdout=json.dumps(image))), self.assertRaises(lab.LabError):
            lab.image_info('synthetic-image', 'linux/arm64')

    def test_schema_is_agent_only_and_references_only(self):
        normalized = lab.validate_plan(plan(), ROOT)
        self.assertEqual(normalized['agents'][0]['application_secrets'], DECLARATION)
        self.assertNotIn('application_secrets', normalized['agents'][2])
        for value in ({}, [], {'PATH': 'WORKCHORD_A'}, {'PI_LAB_API_KEY': 'WORKCHORD_A'},
                      {'PI_APP_KEY': '/tmp/key'}, {'PI_APP_KEY': KEY_A}, {'PI_APP_KEY': {'value': KEY_A}}):
            with self.subTest(value=value), self.assertRaises(lab.LabError):
                p = plan(); p['agents'][0]['application_secrets'] = value
                lab.validate_plan(p, ROOT)
        for section in ('setup', 'checks'):
            p = plan(); p[section][0]['application_secrets'] = DECLARATION
            with self.assertRaises(lab.LabError):
                lab.validate_plan(p, ROOT)

    def test_missing_reference_blocks_before_docker_even_when_exported(self):
        with tempfile.TemporaryDirectory() as td, contextlib.ExitStack() as stack:
            top = Path(td); args = fixture(top); lab.save(Path(args.plan), plan())
            args.secrets_dir = str(top / 'secrets'); (top / 'secrets').mkdir(mode=0o700)
            mocked_suite(stack)
            stack.enter_context(mock.patch.dict(os.environ, {'WORKCHORD_A': KEY_A, 'WORKCHORD_B': KEY_B}))
            host = stack.enter_context(mock.patch.object(lab, 'require_host'))
            probe = stack.enter_context(mock.patch.object(lab, 'probe_image'))
            stage = stack.enter_context(mock.patch.object(lab, 'run_stage'))
            self.assertEqual(lab.run_suite(args), 2)
            host.assert_not_called(); probe.assert_not_called(); stage.assert_not_called()
            result = lab.controls.read((top / 'results/latest').resolve() / 'result.json')
            self.assertEqual(result['infrastructure']['reason'], 'application-credentials')

    def test_secure_resolution_and_no_inference_or_persona_fallback(self):
        with tempfile.TemporaryDirectory() as td:
            top = Path(td); store = top / 'secrets'
            a = secret_store.write_secret('WORKCHORD_A', KEY_A, store)
            b = secret_store.write_secret('WORKCHORD_B', KEY_B, store)
            def resolve(p=None, **kw):
                return credentials.resolve(p or plan(), ENDPOINT, 'inference-only-123456', store, top / 'project', top / 'run', **kw)
            self.assertEqual(resolve(), {'a': {'PI_APP_WORKCHORD_API_KEY': KEY_A}, 'b': {'PI_APP_WORKCHORD_API_KEY': KEY_B}})
            for kind in ('missing', 'mode', 'directory-mode', 'symlink', 'hardlink', 'short', 'same-key', 'inference-value', 'inference-reference', 'literal-prompt', 'in-place', 'contained-store'):
                with self.subTest(kind=kind), contextlib.ExitStack() as stack:
                    p = plan()
                    if kind == 'missing': b.unlink()
                    elif kind == 'mode': b.chmod(0o644)
                    elif kind == 'directory-mode': store.chmod(0o755)
                    elif kind == 'symlink': b.unlink(); b.symlink_to(a)
                    elif kind == 'hardlink': b.unlink(); os.link(a, b)
                    elif kind == 'short': b.write_text('short')
                    elif kind == 'same-key': b.write_text(KEY_A)
                    elif kind == 'inference-value': b.write_text('inference-only-123456')
                    elif kind == 'inference-reference': p['agents'][1]['application_secrets']['PI_APP_WORKCHORD_API_KEY'] = 'PI_API_KEY'
                    elif kind == 'literal-prompt': p['agents'][1]['prompt'] += KEY_B
                    with self.assertRaises(credentials.CredentialError):
                        if kind == 'contained-store': credentials.resolve(p, ENDPOINT, '', store, store.parent, top / 'run')
                        else: resolve(p, in_place=kind == 'in-place')
                store.chmod(0o700); b.unlink(missing_ok=True)
                secret_store.write_secret('WORKCHORD_B', KEY_B, store)


class TransportTests(unittest.TestCase):
    def test_plain_and_json_escaped_values_across_reads_and_both_pipes(self):
        key = 'synthetic-quoted-"\\-é-123456789'
        code = "import os,json,sys,time; k=os.environ['PI_APP_KEY']; os.write(1,k[:20].encode()); time.sleep(.02); os.write(1,(k[20:]+'\\n').encode()); print(json.dumps({'key':k})); print(json.dumps({'key':k},ensure_ascii=False),file=sys.stderr); sys.stderr.write(k)"
        with tempfile.TemporaryDirectory() as td, mock.patch.dict(os.environ, {'PI_APP_AMBIENT': KEY_B}):
            root = Path(td)
            result = lab.stream_run([sys.executable, '-c', code], root, 5, 'credential-local-test', application_secrets={'PI_APP_KEY': key})
            self.assertEqual(result['exit_code'], 0)
            redactor = credentials.Redactor([key])
            for path in root.iterdir():
                self.assertFalse(redactor.contains(path.read_bytes()), path.name)
            self.assertIn('<REDACTED>', (root / 'stdout.jsonl').read_text())
            for line in (root / 'stdout.jsonl').read_text().splitlines()[1:]:
                self.assertEqual(json.loads(line)['key'], '<REDACTED>')
            empty = root / 'empty'
            result = lab.stream_run([sys.executable, '-c', "import os; assert not any(k.startswith('PI_APP_') for k in os.environ)"], empty, 5, 'credential-empty-test')
            self.assertEqual(result['exit_code'], 0)

    def test_docker_diagnostics_are_redacted(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(lab.subprocess, 'Popen', side_effect=OSError(KEY_A)), mock.patch.object(lab, 'command', return_value=argparse.Namespace(returncode=1, stdout='', stderr=KEY_A)):
            root = Path(td)
            with self.assertRaises(OSError):
                lab.stream_run(['docker', 'run', '--env', 'PI_APP_KEY', 'image'], root, 5, 'synthetic', application_secrets={'PI_APP_KEY': KEY_A})
            self.assertNotIn(KEY_A, (root / 'process.json').read_text())
            self.assertNotIn(KEY_A, (root / 'command.json').read_text())


class LifecycleTests(unittest.TestCase):
    def run_campaign(self, top, fault=None, base_url=None):
        args = fixture(top); p = plan()
        for t in p['agents']: t['require_tools'] = []
        lab.save(Path(args.plan), p); args.secrets_dir = str(top / 'secrets')
        secret_store.write_secret('WORKCHORD_A', KEY_A, args.secrets_dir)
        secret_store.write_secret('WORKCHORD_B', KEY_B, args.secrets_dir)
        calls = []; real_stream = lab.stream_run
        def stream(argv, logs, timeout, name, secret='', stage=None, **kw):
            supplied = kw.get('application_secrets') or {}
            calls.append((argv, dict(supplied)))
            if supplied:
                # A real subprocess uses the admitted credential through built-in urllib.
                mounts = [argv[i+1] for i, part in enumerate(argv[:-1]) if part == '--mount']
                runtime = Path(next(m.split('src=')[1].split(',dst=')[0] for m in mounts if 'dst=/pi-state' in m))
                source = "import os,sys,json; from pathlib import Path; k=os.environ['PI_APP_WORKCHORD_API_KEY']; assert len([n for n in os.environ if n.startswith('PI_APP_')])==1; print(k); sys.stderr.write(k); Path(sys.argv[1]).write_text(k)"
                if base_url:
                    source += "; import urllib.request; base=sys.argv[2]; ack=urllib.request.Request(base+'/api/agent/team-setup/onboarding/acknowledge',data=b'{\"handoff\":\"current\"}',headers={'X-Agent-API-Key':k,'Content-Type':'application/json'}); urllib.request.urlopen(ack).read(); req=urllib.request.Request(base+'/api/agent/effects',headers={'X-Agent-API-Key':k}); print(urllib.request.urlopen(req).read().decode())"
                client = [sys.executable, '-c', source, str(runtime / 'sessions/raw.jsonl')]
                if base_url: client.append(base_url)
                if fault == 'copy': (Path(stage[1]['workspace']) / 'copied-token.txt').write_text(next(iter(supplied.values())))
                if fault == 'other-persona-copy': (Path(stage[1]['workspace']) / 'copied-token.txt').write_text(KEY_B)
                if fault == 'cancel':
                    lab.save(logs / 'process.json', {'exit_code': 130, 'cancelled': True, 'cleanup_confirmed': True})
                    (runtime / 'sessions/raw.jsonl').write_text(next(iter(supplied.values())))
                    raise KeyboardInterrupt
                if fault == 'timeout': client = [sys.executable, '-c', source + '; import time; time.sleep(10)', str(runtime / 'sessions/raw.jsonl')]; timeout = .1
                if fault == 'uncertain':
                    (runtime / 'sessions/raw.jsonl').write_text(next(iter(supplied.values())))
                    return {'exit_code': 2, 'cleanup_confirmed': False}
                if fault == 'startup':
                    (runtime / 'sessions/raw.jsonl').write_text(next(iter(supplied.values())))
                    with mock.patch.object(lab.subprocess, 'Popen', side_effect=OSError('synthetic launch failure')):
                        return real_stream(client, logs, timeout, 'credential-local-client', secret, application_secrets=supplied)
                return real_stream(client, logs, timeout, 'credential-local-client', secret, application_secrets=supplied, redaction_secrets=kw.get('redaction_secrets', ()))
            return real_stream([sys.executable, '-c', "import os; assert not any(n.startswith('PI_APP_') for n in os.environ)"], logs, 5, 'credential-key-free', redaction_secrets=kw.get('redaction_secrets', ()))
        with contextlib.ExitStack() as stack:
            mocked_suite(stack, stage=stream)
            def aggregate(records, *args):
                complete = all(row['process'].get('exit_code') == 0 and row['process'].get('cleanup_confirmed') for row in records)
                return {'agent_invocation_verified': complete, 'completion_verified': complete,
                        'invocation_status': 'verified' if complete else 'invalid', 'errors': [], 'final_text': 'Synthetic Pi boundary'}
            stack.enter_context(mock.patch.object(lab.segments, 'aggregate', side_effect=aggregate))
            code = lab.run_suite(args)
        return code, (top / 'results/latest').resolve(), calls

    def test_two_personas_unassigned_setup_checks_and_sensitive_cleanup(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.dict(os.environ, {'PI_APP_AMBIENT': 'unassigned-ambient-123456'}):
            code, run, calls = self.run_campaign(Path(td))
            self.assertEqual(code, 0)
            self.assertEqual([v for _, v in calls if v], [{'PI_APP_WORKCHORD_API_KEY': KEY_A}, {'PI_APP_WORKCHORD_API_KEY': KEY_B}])
            for argv, supplied in calls:
                self.assertNotIn(KEY_A, str(argv)); self.assertNotIn(KEY_B, str(argv))
                if supplied: self.assertIn('PI_APP_WORKCHORD_API_KEY', argv)
            redactor = credentials.Redactor([KEY_A, KEY_B])
            for path in run.rglob('*'):
                if path.is_file(): self.assertFalse(redactor.contains(path.read_bytes()), str(path))
            receipts = list((run / 'stages').glob('*/application-credentials.json'))
            self.assertEqual(len(receipts), 2)
            for path in receipts:
                self.assertEqual(lab.controls.read(path)['status'], 'removed')
                self.assertEqual(lab.controls.read(path)['workspace'], 'clean')

    def test_copy_cancel_timeout_and_uncertain_cleanup_fail_closed(self):
        for fault in ('copy', 'other-persona-copy', 'cancel', 'timeout', 'uncertain', 'startup'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as td:
                code, run, calls = self.run_campaign(Path(td), fault)
                self.assertNotEqual(code, 0)
                self.assertEqual(len([values for _, values in calls if values]), 1)
                result = lab.controls.read(run / 'result.json')
                if fault != 'timeout':
                    self.assertNotEqual(result['scoring']['status'], 'completed')
                else:
                    # Eligible stopped artifacts may be scored diagnostically, key-free.
                    self.assertEqual(result['invocation']['status'], 'invalid')
                receipt = lab.controls.read(next((run / 'stages').glob('*/application-credentials.json')))
                self.assertEqual(receipt['status'], 'cleanup_unconfirmed' if fault == 'uncertain' else 'removed')
                if fault in ('copy', 'other-persona-copy'): self.assertFalse((run / 'workspace').exists())
                if fault == 'uncertain':
                    self.assertTrue(list((run / 'children').rglob('raw.jsonl')))
                    # Recovery is called only after independent container ownership/absence checks.
                    credentials.recover(run)
                    self.assertFalse(list((run / 'children').rglob('raw.jsonl')))
                    self.assertFalse((run / 'workspace').exists())
                else: self.assertFalse(list((run / 'children').rglob('raw.jsonl')))

    def test_literal_contamination_crosses_scan_chunks_and_links_do_not_touch_host(self):
        with tempfile.TemporaryDirectory() as td:
            top = Path(td); workspace = top / 'workspace'; workspace.mkdir()
            key = ('x' * 20000) + 'credential-tail-123456'
            file = workspace / 'payload'; file.write_bytes(b'a' * 65530 + key.encode())
            self.assertFalse(credentials.workspace_clean(workspace, credentials.Redactor([key])))
            # The longest JSON-escaped credential may exceed the old fixed overlap.
            file.write_bytes(b'a' * 50000 + json.dumps('😀' * 4096)[1:-1].encode())
            self.assertFalse(credentials.workspace_clean(workspace, credentials.Redactor(['😀' * 4096])))
            file.unlink(); sentinel = top / 'host'; sentinel.write_text(KEY_A)
            (workspace / 'alias').symlink_to(sentinel)
            self.assertFalse(credentials.workspace_clean(workspace, credentials.Redactor([KEY_A])))
            self.assertEqual(sentinel.read_text(), KEY_A)


class AuthenticationTests(unittest.TestCase):
    run_campaign = LifecycleTests.run_campaign
    def test_onboarding_and_authenticated_effects_are_recorded_by_the_service(self):
        observed = []; active = set(); identities = {KEY_A: 'persona-a', KEY_B: 'persona-b'}
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_POST(self):
                persona = identities.get(self.headers.get('X-Agent-API-Key'))
                body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
                valid = persona and self.path == '/api/agent/team-setup/onboarding/acknowledge' and body == {'handoff': 'current'}
                if valid: active.add(persona); observed.append(('acknowledge', persona))
                self.send_response(200 if valid else 403); self.end_headers(); self.wfile.write(b'{}')
            def do_GET(self):
                persona = identities.get(self.headers.get('X-Agent-API-Key'))
                valid = persona in active and self.path == '/api/agent/effects'
                if valid: observed.append(('effect', persona))
                self.send_response(200 if valid else 403); self.end_headers()
                self.wfile.write(json.dumps({'identity': persona if valid else None}).encode())
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                code, run, _ = self.run_campaign(Path(td), base_url=f'http://127.0.0.1:{server.server_port}')
                self.assertEqual(code, 0)
                self.assertEqual(observed, [('acknowledge', 'persona-a'), ('effect', 'persona-a'), ('acknowledge', 'persona-b'), ('effect', 'persona-b')])
        finally:
            server.shutdown(); server.server_close(); thread.join()


if __name__ == '__main__':
    unittest.main()
