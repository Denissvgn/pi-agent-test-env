"""UNIT tests only. Synthetic protocol fixtures are NOT real-agent acceptance evidence."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = (Path(__file__).resolve().parents[1] / 'skill')
sys.path.insert(0, str(ROOT / 'scripts'))
import pi_lab as lab
from evidence import analyze


def task():
    return {'schema': 1, 'agents': [{'name': 'dev', 'prompt': 'Read the spec.',
             'tools': ['read'], 'require_tools': ['read']}],
            'checks': [{'argv': ['python3', '-V']}], 'protected_paths': ['tests']}


def events():
    import copy
    data=json.loads((ROOT/'references/pi-0.87.1.examples.json').read_text())
    ev=copy.deepcopy(data['event_examples'][0]['records'])
    for event in ev:
        for msg in [event.get('message'),*event.get('messages',[])]:
            if isinstance(msg,dict) and msg.get('role')=='assistant':msg['model']='test-model'
        if event['type']=='message_end' and event['message']['role']=='assistant' and event['message']['stopReason']=='stop':
            event['message']['usage']={'totalTokens':42};event['message']['responseId']='fixture-response'
    return ev


def final_event(ev):
    return next(e for e in reversed(ev) if e['type']=='message_end' and e.get('message',{}).get('role')=='assistant')


def tool_end(ev):
    return next(e for e in ev if e['type']=='tool_execution_end')


class EvidenceTests(unittest.TestCase):
    def run_events(self, ev=None, exit_code=0, required=None):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'events.jsonl'
            p.write_text(''.join(json.dumps(x) + '\n' for x in (events() if ev is None else ev)))
            return analyze(p, 'test-model', ['read'] if required is None else required, exit_code)

    def test_complete_protocol_fixture(self):
        r = self.run_events()
        self.assertTrue(r['agent_invocation_verified'])
        self.assertIsNone(r['provider_reported_total_tokens'])
        self.assertEqual(r['usage']['categories']['total']['known_sum'],42)
        self.assertEqual(r['usage']['categories']['total']['missing_messages'],1)

    def test_prose_does_not_pass(self):
        self.assertFalse(self.run_events([{'type': 'text', 'text': 'All tests passed'}])['agent_invocation_verified'])

    def test_wrong_model(self):
        ev = events(); final_event(ev)['message']['model'] = 'fallback-model'
        self.assertFalse(self.run_events(ev)['agent_invocation_verified'])

    def test_wrong_provider(self):
        ev = events(); final_event(ev)['message']['provider'] = 'cloud'
        self.assertFalse(self.run_events(ev)['agent_invocation_verified'])

    def test_missing_tool(self):
        self.assertFalse(self.run_events(required=['write'])['agent_invocation_verified'])

    def test_failed_tool(self):
        ev = events(); tool_end(ev)['isError'] = True
        self.assertFalse(self.run_events(ev)['agent_invocation_verified'])

    def test_exit_status(self):
        self.assertFalse(self.run_events(exit_code=124)['agent_invocation_verified'])

    def test_missing_settled(self):
        self.assertFalse(self.run_events(events()[:-1])['agent_invocation_verified'])

    def test_length_not_success(self):
        ev = events(); final_event(ev)['message']['stopReason'] = 'length'
        self.assertFalse(self.run_events(ev)['agent_invocation_verified'])

    def test_zero_usage_is_reported_not_invented(self):
        ev = events(); final_event(ev)['message']['usage'] = {'totalTokens': 0}
        result = self.run_events(ev)
        self.assertFalse(result['usage_reported'])
        self.assertTrue(result['agent_invocation_verified'])

    def test_unpaired_tool(self):
        ev = events(); tool_end(ev)['toolCallId'] = 'other'
        self.assertFalse(self.run_events(ev)['agent_invocation_verified'])

    def test_invalid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'bad'; p.write_text('not json\n')
            self.assertFalse(analyze(p, 'm', [], 0)['agent_invocation_verified'])

    def test_unicode_separator_is_not_record_break(self):
        ev = events(); final_event(ev)['message']['content'][0]['text'] = 'a\u2028b'
        self.assertTrue(self.run_events(ev)['agent_invocation_verified'])


class PlanTests(unittest.TestCase):
    def test_valid(self):
        p = lab.validate_plan(task(), ROOT)
        self.assertEqual(p['agents'][0]['max_turns'], 24)

    def test_requires_independent_checks(self):
        t = task(); t['checks'] = []
        with self.assertRaises(lab.LabError): lab.validate_plan(t, ROOT)

    def test_rejects_unknown_fields(self):
        t = task(); t['mock_llm'] = True
        with self.assertRaises(lab.LabError): lab.validate_plan(t, ROOT)

    def test_rejects_traversal(self):
        for value in ('../secret', '/etc', '.pi-lab/expected', 'a/../../etc'):
            with self.assertRaises(lab.LabError): lab.safe_relative(value)

    def test_rejects_unknown_tools(self):
        t = task(); t['agents'][0]['tools'] = ['docker']
        with self.assertRaises(lab.LabError): lab.validate_plan(t, ROOT)

    def test_requires_successful_tool_in_allowlist(self):
        t = task(); t['agents'][0]['require_tools'] = ['bash']
        with self.assertRaises(lab.LabError): lab.validate_plan(t, ROOT)

    def test_check_not_shell_string(self):
        t = task(); t['checks'][0]['argv'] = 'echo passed'
        with self.assertRaises(lab.LabError): lab.validate_plan(t, ROOT)

    def test_timeout_is_bounded(self):
        t = task(); t['agents'][0]['timeout_seconds'] = 0
        with self.assertRaises(lab.LabError): lab.validate_plan(t, ROOT)

    def test_duplicate_names(self):
        t = task(); t['agents'] *= 2
        with self.assertRaises(lab.LabError): lab.validate_plan(t, ROOT)

    def test_bundled_plans(self):
        for f in (ROOT / 'assets').glob('*.plan.json'):
            lab.validate_plan(json.loads(f.read_text()), f.parent)


class FilesystemTests(unittest.TestCase):
    def test_snapshot_skips_secrets_links_and_node_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / 'src'; dst = Path(tmp) / 'dst'; src.mkdir()
            (src / 'main.py').write_text('print(1)')
            (src / '.env').write_text('SECRET')
            (src / 'node_modules').mkdir(); (src / 'node_modules/a').write_text('native mac file')
            (src / 'link').symlink_to(src / 'main.py')
            result = lab.snapshot(src, dst, [], 1)
            self.assertTrue((dst / 'main.py').exists())
            self.assertFalse((dst / '.env').exists())
            self.assertFalse((dst / 'node_modules').exists())
            self.assertFalse((dst / 'link').exists())
            self.assertNotEqual((dst / 'main.py').stat().st_ino, (src / 'main.py').stat().st_ino)
            self.assertGreater(len(result['skipped']), 0)

    def test_snapshot_size_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / 'src'; src.mkdir(); (src / 'big').write_bytes(b'x' * (1024 * 1024 + 1))
            with self.assertRaises(lab.LabError): lab.snapshot(src, Path(tmp) / 'dst', [], 1)

    def test_runtime_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            w = Path(tmp) / 'w'; w.mkdir(); (w / '.pi-lab').symlink_to('/tmp')
            with self.assertRaises(lab.LabError): lab.state_dir(w, 'agent')

    def test_protected_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            w = Path(tmp); (w / 'tests').mkdir(); (w / 'tests/test.py').write_text('assert False')
            before = lab.protected_hashes(w, ['tests'])
            (w / 'tests/test.py').write_text('assert True')
            self.assertNotEqual(before, lab.protected_hashes(w, ['tests']))

    def test_paths_with_spaces_work(self):
        self.assertIn('a b', str(lab.checked_path(Path('/tmp/a b'))))

    def test_mount_delimiter_rejected(self):
        with self.assertRaises(lab.LabError): lab.checked_path(Path('/tmp/a,b'))

    def test_docker_hardening_and_key_not_in_argv(self):
        a = argparse.Namespace(platform='linux/arm64', uid=501, gid=20, memory='6g', cpus=4,
             allow_browser_no_sandbox=False, software_webgl=False)
        argv = lab.docker_args(a, 'sha256:id', Path('/x/project'), Path('/x/control'),
                              Path('/x/project/.pi-lab/dev'), 'pi-lab-x', 'bridge', 'rw', True)
        text = ' '.join(argv)
        for flag in ['--read-only', '--cap-drop=ALL', 'no-new-privileges', '--ipc=none', '--init', 'bind-recursive=disabled']:
            self.assertIn(flag, text)
        for bad in ['--privileged', 'SYS_ADMIN', '/var/run/docker.sock', '--gpus']:
            self.assertNotIn(bad, text)
        self.assertIn('PI_LAB_API_KEY', argv)
        self.assertIn('CHROME_NO_SANDBOX=0', argv)

    def test_readonly_reviewer_gets_only_runtime_rw_submount(self):
        a = argparse.Namespace(platform='linux/arm64', uid=501, gid=20, memory='6g', cpus=4,
             allow_browser_no_sandbox=False, software_webgl=False)
        argv = lab.docker_args(a, 'id', Path('/x/w'), Path('/x/c'), Path('/x/w/.pi-lab/review'),
                              'n', 'none', 'ro', False)
        self.assertIn('type=bind,src=/x/w,dst=/workspace,bind-recursive=disabled,readonly', argv)
        self.assertIn('type=bind,src=/x/w/.pi-lab/review,dst=/pi-state,bind-recursive=disabled', argv)


class EndpointTests(unittest.TestCase):
    def load(self, updates=None):
        c = {'base_url': 'http://model-server:8000/v1', 'model': 'test-model', 'api_key_env': 'LOCAL_KEY', 'context_window': 32768, 'max_tokens': 4096}; c.update(updates or {})
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'e'; p.write_text(json.dumps(c)); return lab.load_endpoint(p)
    def test_valid(self): self.assertEqual(self.load()['context_window'], 32768)
    def test_no_key_in_url(self):
        with self.assertRaises(lab.LabError): self.load({'base_url': 'http://user:password@host/v1'})
    def test_context_budget(self):
        with self.assertRaises(lab.LabError): self.load({'max_tokens': 262144})
    def test_no_arbitrary_api(self):
        with self.assertRaises(lab.LabError): self.load({'base_url': 'file:///tmp/v1'})
    def test_key_is_environment_name(self):
        with self.assertRaises(lab.LabError): self.load({'api_key_env': 'sk-my-secret'})
    def test_reasoning_bool_and_dict(self):
        self.assertTrue(self.load({'reasoning': True})['reasoning'])
        self.assertFalse(self.load({'reasoning': False})['reasoning'])
        dict_val = {'enabled': True, 'level': 'low', 'budget_tokens': 1024}
        self.assertEqual(self.load({'reasoning': dict_val})['reasoning'], dict_val)
        with self.assertRaises(lab.LabError):
            self.load({'reasoning': {'level': 'invalid'}})
        with self.assertRaises(lab.LabError):
            self.load({'reasoning': {'budget_tokens': 999999999}})
        with self.assertRaises(lab.LabError):
            self.load({'reasoning': 'invalid_string'})


class ImageTests(unittest.TestCase):
    def test_arch_normalization(self):
        self.assertEqual(lab.norm_arch('aarch64'), 'arm64')
        self.assertEqual(lab.norm_arch('x86_64'), 'amd64')
    def image(self, updates=None):
        d = {'Id': 'sha256:fixture', 'Os': 'linux', 'Architecture': 'arm64', 'Config': {}}
        d.update(updates or {})
        return mock.patch.object(lab, 'command', return_value=argparse.Namespace(stdout=json.dumps([d])))
    def test_wrong_arch_rejected(self):
        with self.image():
            with self.assertRaises(lab.LabError): lab.image_info('fixture', 'linux/amd64')
    def test_implicit_volume_rejected(self):
        with self.image({'Config': {'Volumes': {'/extra': {}}}}):
            with self.assertRaises(lab.LabError): lab.image_info('fixture', 'linux/arm64')
    def test_baked_key_rejected(self):
        with self.image({'Config': {'Env': ['OPENAI_API_KEY=secret']}}):
            with self.assertRaises(lab.LabError): lab.image_info('fixture', 'linux/arm64')
    def test_valid_image_id(self):
        with self.image(): self.assertEqual(lab.image_info('fixture', 'linux/arm64')['id'], 'sha256:fixture')



class SupervisorTests(unittest.TestCase):
    def test_drain_and_redact_both_streams(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(lab, 'command', return_value=argparse.Namespace(returncode=1, stderr='No such container', stdout='')):
                cmd = [sys.executable, '-c',
                       'import os,sys; k=os.environ["PI_LAB_API_KEY"]; print(k); print(k,file=sys.stderr)']
                result = lab.stream_run(cmd, Path(tmp), 5, 'unit-test-not-docker', secret='unit-test-key')
            self.assertEqual(result['exit_code'], 0)
            self.assertNotIn('unit-test-key', (Path(tmp) / 'stdout.jsonl').read_text())
            self.assertNotIn('unit-test-key', (Path(tmp) / 'stderr.log').read_text())
            self.assertIn('<REDACTED>', (Path(tmp) / 'stdout.jsonl').read_text())

    def test_log_limit_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(lab, 'command', return_value=argparse.Namespace(returncode=1, stderr='No such container', stdout='')):
                result = lab.stream_run([sys.executable, '-c', 'print("x"*100000)'],
                                        Path(tmp), 5, 'unit-test-not-docker', max_bytes=100)
            self.assertNotEqual(result['exit_code'], 0)
            self.assertTrue(result['log_limit_exceeded'])
            self.assertEqual(result['termination_reason'],'log_limit')

    def test_protected_bytecode_is_not_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            w = Path(tmp); (w / 'tests').mkdir()
            before = lab.protected_hashes(w, ['tests'])
            (w / 'tests/__pycache__').mkdir(); (w / 'tests/__pycache__/fake.pyc').write_bytes(b'bad')
            self.assertNotEqual(before, lab.protected_hashes(w, ['tests']))


class ImagePolicyTests(unittest.TestCase):
    def args(self, policy='auto'):
        return lab.parser().parse_args(['ensure-image', '--policy', policy,
                                       '--reuse', 'pi-workspace:chromium', '--uid', '1000'])
    def test_reuse_existing_target_without_build(self):
        with mock.patch.object(lab, 'require_host', return_value={}), \
             mock.patch.object(lab, 'probe_image', return_value={'id': 'sha256:unit', 'capabilities': {'pi': '0.87.1'}}), \
             mock.patch.object(lab.subprocess, 'run') as build:
            self.assertEqual(lab.ensure_image(self.args())['action'], 'reused')
            build.assert_not_called()

    def test_reuse_candidate_and_alias(self):
        with mock.patch.object(lab, 'require_host', return_value={}), \
             mock.patch.object(lab, 'probe_image', side_effect=[lab.LabError('missing'), {'id':'sha256:unit','capabilities':{'pi':'0.87.1'}}]), \
             mock.patch.object(lab, 'command') as cmd:
            r = lab.ensure_image(self.args())
            self.assertEqual(r['action'], 'reused')
            cmd.assert_called_once_with(['docker', 'image', 'tag', 'sha256:unit', 'pi-agent-tests:core'])

    def test_reuse_policy_never_builds(self):
        with mock.patch.object(lab, 'require_host', return_value={}), \
             mock.patch.object(lab, 'probe_image', side_effect=lab.LabError('missing')), \
             mock.patch.object(lab.subprocess, 'run') as build:
            with self.assertRaises(lab.LabError): lab.ensure_image(self.args('reuse'))
            build.assert_not_called()

    def test_build_policy_uses_dedicated_context(self):
        a = self.args('build')
        a.platform = 'linux/arm64'
        a.pi_version = '0.87.1'  # A synthetic fixture, not a release claim.
        with mock.patch.object(lab, 'require_host', return_value={}), \
             mock.patch.object(lab, 'probe_image', return_value={'id':'sha256:unit','capabilities':{'pi':'0.87.1'}}), \
             mock.patch.object(lab, 'limited_build', return_value={'argv': ['fixture']}) as build:
            r = lab.ensure_image(a)
            self.assertEqual(r['action'], 'built')
            self.assertEqual(build.call_args.args[1], ROOT / 'docker/Dockerfile')
            self.assertEqual(build.call_args.args[2], ROOT / 'docker')
            self.assertEqual(r['requested_pi_version'], '0.87.1')

    def test_missing_build_pin_does_not_build(self):
        with mock.patch.object(lab, 'require_host', return_value={}), \
             mock.patch.object(lab, 'limited_build') as build:
            with self.assertRaises(lab.LabError):
                lab.ensure_image(self.args('build'))
            build.assert_not_called()


class LiveControlAndArchitectureTests(unittest.TestCase):
    def test_docker_args_includes_live_mount_and_arch_env(self):
        a = argparse.Namespace(platform='linux/arm64', native_platform='linux/arm64', uid=501, gid=20,
                               memory='6g', cpus=4, allow_browser_no_sandbox=False, software_webgl=False)
        argv = lab.docker_args(a, 'sha256:id', Path('/x/project'), Path('/x/control'),
                               Path('/x/project/.pi-lab/dev'), 'pi-lab-x', 'bridge', 'rw', True)
        text = ' '.join(argv)
        self.assertIn('dst=/opt/pi-control/outbox', text)
        self.assertIn('HOST_ARCH=linux/arm64', text)
        self.assertIn('CONTAINER_ARCH=linux/arm64', text)

    def test_require_host_auto_detects_amd64(self):
        a = argparse.Namespace(platform=None, uid=501, gid=20, memory=None, cpus=None, pids_limit=None, jobs=None)
        info = {'OSType': 'linux', 'Architecture': 'x86_64', 'ServerVersion': '27.0.0', 'NCPU': 8, 'MemTotal': 16 * 1024 * 1024 * 1024}
        with mock.patch('shutil.which', return_value='/usr/bin/docker'), \
             mock.patch.object(lab, 'command', side_effect=[
                 argparse.Namespace(stdout=json.dumps(info)),
                 argparse.Namespace(stdout='default\n'),
                 argparse.Namespace(stdout=json.dumps([{'Endpoints': {'docker': {'Host': 'unix:///var/run/docker.sock'}}}]))
             ]):
            host = lab.require_host(a)
            self.assertEqual(a.platform, 'linux/amd64')
            self.assertEqual(host['native_platform'], 'linux/amd64')
            self.assertEqual(host['selected_platform'], 'linux/amd64')

    def test_legacy_controls_are_inspectable_but_not_mutable(self):
        with tempfile.TemporaryDirectory() as td:
            runroot = Path(td)
            lab.save(runroot / 'active_stage.json', {'label':'dev','status':'running'})
            lab.save(runroot / 'summary.json', {'status':'RUNNING'})
            a = argparse.Namespace(run=str(runroot), results_dir=td, stage=None,
                                   turns='+5', timeout=None, tokens=None, message='hello', interrupt=False)
            self.assertEqual(lab.cmd_status(a), 0)
            with self.assertRaises(lab.LabError): lab.cmd_extend_budget(a)
            with self.assertRaises(lab.LabError): lab.cmd_steer(a)
            with self.assertRaises(lab.LabError): lab.cmd_patch_session(a)


class WorkspaceBoundaryConfinementTests(unittest.TestCase):
    def test_workspace_boundary_extension_exists(self):
        ext_path = ROOT / 'runtime' / 'workspace-boundary.mjs'
        self.assertTrue(ext_path.exists())
        content = ext_path.read_text(encoding='utf-8')
        self.assertIn('isWithinWorkspace', content)
        self.assertIn('tool_call', content)

    def test_workspace_boundary_node_evaluation(self):
        ext_path = ROOT / 'runtime' / 'workspace-boundary.mjs'
        script = f"""
import {{ isWithinWorkspace }} from '{ext_path.as_uri()}';
import assert from 'node:assert';

assert.strictEqual(isWithinWorkspace('src/index.js', '/workspace', '/workspace'), true);
assert.strictEqual(isWithinWorkspace('/workspace/SPEC-V4.md', '/workspace', '/workspace'), true);
assert.strictEqual(isWithinWorkspace('/workspace/.pi-lab/tmp/file.txt', '/workspace', '/workspace'), true);
assert.strictEqual(isWithinWorkspace('../escape.txt', '/workspace', '/workspace'), false);
assert.strictEqual(isWithinWorkspace('/tmp/outside.txt', '/workspace', '/workspace'), false);
assert.strictEqual(isWithinWorkspace('/opt/pi-control/live/heartbeat.json', '/workspace', '/workspace'), false);
assert.strictEqual(isWithinWorkspace('/etc/passwd', '/workspace', '/workspace'), false);
assert.strictEqual(isWithinWorkspace('/workspace/../../etc/passwd', '/workspace', '/workspace'), false);
console.log('NODE_PATH_ASSERTIONS_OK');
"""
        proc = subprocess.run(['node', '--input-type=module', '-e', script], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, f"Node assertions failed: {proc.stderr}")
        self.assertIn('NODE_PATH_ASSERTIONS_OK', proc.stdout)

    def test_workspace_boundary_tool_call_handler(self):
        ext_path = ROOT / 'runtime' / 'workspace-boundary.mjs'
        script = f"""
import registerBoundary from '{ext_path.as_uri()}';
import assert from 'node:assert';

const handlers = [];
const mockPi = {{
  on(event, handler) {{
    if (event === 'tool_call') handlers.push(handler);
  }}
}};
registerBoundary(mockPi);
assert.strictEqual(handlers.length, 1);
const handler = handlers[0];

// Allowed writes
assert.strictEqual(handler({{ toolName: 'write', input: {{ path: 'SPEC-V4.md' }} }}, {{ cwd: '/workspace' }}), undefined);
assert.strictEqual(handler({{ toolName: 'edit', input: {{ path: 'snake-three.html' }} }}, {{ cwd: '/workspace' }}), undefined);

// Disallowed writes
const blocked1 = handler({{ toolName: 'write', input: {{ path: '/tmp/outside.txt' }} }}, {{ cwd: '/workspace' }});
assert.strictEqual(blocked1?.block, true);
assert.match(blocked1?.reason, /Security violation/);

const blocked2 = handler({{ toolName: 'write', input: {{ path: '../../outside.txt' }} }}, {{ cwd: '/workspace' }});
assert.strictEqual(blocked2?.block, true);

const blocked3 = handler({{ toolName: 'edit', input: {{ path: '/opt/pi-control/task.json' }} }}, {{ cwd: '/workspace' }});
assert.strictEqual(blocked3?.block, true);

// Disallowed bash modifying outside /workspace
const blockedBash = handler({{ toolName: 'bash', input: {{ command: 'echo hack > /opt/pi-control/tamper' }} }}, {{ cwd: '/workspace' }});
assert.strictEqual(blockedBash?.block, true);

// Disallowed writes and edits targeting .pi-runtime/inbox
const blockedInboxWrite = handler({{ toolName: 'write', input: {{ path: '.pi-runtime/inbox/limits.json' }} }}, {{ cwd: '/workspace' }});
assert.strictEqual(blockedInboxWrite?.block, true);
assert.match(blockedInboxWrite?.reason, /protected control inbox/);

const blockedInboxEdit = handler({{ toolName: 'edit', input: {{ path: '/workspace/.pi-runtime/inbox/steer.json' }} }}, {{ cwd: '/workspace' }});
assert.strictEqual(blockedInboxEdit?.block, true);

const blockedInboxBash = handler({{ toolName: 'bash', input: {{ command: 'echo hack > /workspace/.pi-runtime/inbox/limits.json' }} }}, {{ cwd: '/workspace' }});
assert.strictEqual(blockedInboxBash?.block, true);

console.log('NODE_TOOL_CALL_ASSERTIONS_OK');
"""
        proc = subprocess.run(['node', '--input-type=module', '-e', script], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, f"Tool call assertions failed: {proc.stderr}")
        self.assertIn('NODE_TOOL_CALL_ASSERTIONS_OK', proc.stdout)

    def test_worker_boundary_probe_checks_outside_dirs(self):
        worker_path = ROOT / 'runtime' / 'worker.py'
        code = worker_path.read_text(encoding='utf-8')
        self.assertIn('sampled_outside_write_denied', code)
        self.assertNotIn('workspace_boundary_enforced', code)
        self.assertIn('/opt/pi-lab/workspace-boundary.mjs', code)
        self.assertIn('isWithinWorkspace', code)



if __name__ == '__main__':
    unittest.main()
