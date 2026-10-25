"""Compiled worker admission/prompt checks; inference Popen is never executed."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'skill/scripts'), str(ROOT / 'skill/runtime')]
import agent_profiles
import application_runtime_contracts as contracts
import prompt_contract
import release_contracts
import worker


class InferenceBoundary(RuntimeError): pass


class ApplicationWorkerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.profile_root = self.root / 'profile'
        self.runtime_root = self.root / 'runtime'; self.runtime_root.mkdir()
        for name in ('workspace-boundary.mjs', 'profile-monitor.mjs', 'tool-budget.mjs'):
            shutil.copyfile(ROOT / 'skill/runtime' / name, self.runtime_root / name)
        self.stack = mock.patch.multiple(worker, APPLICATION_PROFILE_ROOT=self.profile_root, APPLICATION_RUNTIME_ROOT=self.runtime_root)
        self.stack.start(); self.addCleanup(self.stack.stop)

    def fixture(self, release='1.2.0'):
        if self.profile_root.exists(): shutil.rmtree(self.profile_root)
        receipt = agent_profiles.freeze(agent_profiles.application(release), self.profile_root)
        profile = agent_profiles.staged(receipt)
        binding = {'id': 'application-client', 'pi_release': release, 'sha256': agent_profiles.identity(profile),
                   'assets': {asset['target']: asset['sha256'] for asset in profile['assets']}}
        tools = ['artifact_read', 'report_write', 'budget_status']
        definitions = prompt_contract.tool_schemas({'tools': tools, 'operations': [], 'browser_targets': []})
        schema_sha = worker._application_digest(sorted(definitions, key=lambda item: item['name']))
        scope = {key: str(uuid.uuid4()) for key in ('run_id', 'attempt_id', 'stage_id', 'segment_id', 'session_id', 'authority_generation')}
        scope.update(trial_id=None, plan_sha256='a' * 64, stage_name='participant',
            participant={'application_id': 'fixture', 'tenant_id': 'team', 'actor_id': 'actor', 'role': 'participant'},
            operation_ids=[], credential_aliases=['persona'])
        extension = worker.application_extension_identity(release, binding, schema_sha)['sha256']
        private = {'schema': 1, 'scope': scope, 'capability': 'b' * 64, 'base_url': 'http://pi-application:8081/tool',
            'tool_schemas': definitions, 'budget_context': {'schema': 1, 'pi_release': release, 'scope': scope,
                'allowed_tools': tools, 'prepare_arguments': {name: 'none' for name in tools},
                'extension_order_sha256': extension, 'tool_schema_sha256': schema_sha,
                'base_url': 'http://pi-application:8081/budget', 'capability': 'c' * 64}}
        profile_context = {'schema': 1, 'profile': profile, 'profile_sha256': binding['sha256'],
            **{key: scope[key] for key in ('run_id', 'attempt_id', 'stage_id', 'segment_id')}, 'allowed_tools': sorted(tools)}
        private_path = self.root / 'application-context.json'
        if private_path.exists(): private_path.chmod(0o600)
        private_path.write_text(json.dumps(private)); private_path.chmod(0o400)
        public_path = self.root / 'profile-context.json'; public_path.write_text(json.dumps(profile_context))
        prompt = 'FROZEN π prompt\nWhitespace and final newline stay exact.\n'
        task = {'name': 'participant', 'prompt': prompt, 'tools': tools, 'tool_schemas': definitions,
            'pi_release': release, 'release_contract': release_contracts.identity(release),
            'application_context': str(private_path), 'agent_profile_context': str(public_path),
            'session_id': scope['session_id'], 'timeout_seconds': 30, 'max_turns': 5, 'max_total_tokens': 1000,
            'max_tool_calls': 8, 'reporting_reserve_calls': 2, 'reporting_reserve_seconds': 5,
            'application_execution': {'schema': 1, 'plan_sha256': scope['plan_sha256'], 'stage_id': 'participant',
                'effective_prompt_sha256': hashlib.sha256(prompt.encode()).hexdigest(), 'tool_schema_sha256': schema_sha,
                'profile_binding': binding, 'extension_order_sha256': extension}}
        return task, profile_context, private

    def write_private(self, task, value):
        path = Path(task['application_context']); path.chmod(0o600)
        path.write_text(json.dumps(value)); path.chmod(0o400)

    def test_shared_extension_identity_binds_exact_order_release_profile_schema_and_actual_bytes(self):
        task, context, private = self.fixture()
        marker = task['application_execution']
        files = {path: hashlib.sha256(((self.profile_root if '/pi-profile/' in path else self.runtime_root) / Path(path).name).read_bytes()).hexdigest()
                 for path in contracts.APPLICATION_EXTENSION_PATHS}
        parent = contracts.extension_identity('1.2.0', marker['profile_binding'], marker['tool_schema_sha256'], files)
        self.assertEqual(parent['sha256'], marker['extension_order_sha256'])
        self.assertEqual(worker.validate_application_execution(task, context, '1.2.0'), private)
        changed = dict(files); changed['/opt/pi-lab/tool-budget.mjs'] = '0' * 64
        self.assertNotEqual(contracts.extension_identity('1.2.0', marker['profile_binding'], marker['tool_schema_sha256'], changed), parent)
        with self.assertRaises(ValueError): contracts.extension_identity('1.2.0', marker['profile_binding'], marker['tool_schema_sha256'], {})
        (self.runtime_root / 'profile-monitor.mjs').write_text('changed loadout')
        with self.assertRaisesRegex(ValueError, '^Invalid compiled application execution$'):
            worker.validate_application_execution(task, context, '1.2.0')

    def test_numeric_leading_stage_slug_matches_final_ir_contract(self):
        task,context,private=self.fixture()
        task['name']='1-participant';task['application_execution']['stage_id']='1-participant'
        private['scope']['stage_name']='1-participant'
        private['budget_context']['scope']['stage_name']='1-participant'
        self.write_private(task,private)
        self.assertEqual(worker.validate_application_execution(task,context,'1.2.0'),private)

    def test_frozen_prompt_reaches_inference_exactly_without_any_worker_augmentation(self):
        for release in ('0.87.1', '1.2.0'):
            with self.subTest(release=release):
                task, context, private = self.fixture(release)
                home = self.root / release / 'agent'
                inbox = self.root / release / 'inbox'; inbox.mkdir(parents=True)
                outbox = self.root / release / 'outbox'; outbox.mkdir()
                captured = {}
                def boundary(argv, **kwargs):
                    captured['argv'] = argv
                    self.assertEqual((home.parent / 'effective-prompt.txt').read_bytes(), task['prompt'].encode())
                    self.assertEqual(os.environ['PI_LAB_APPLICATION_CONTEXT'], task['application_context'])
                    self.assertNotIn('PI_LAB_TOOL_BUDGET_CONTEXT', os.environ)
                    raise InferenceBoundary()
                with mock.patch.dict(os.environ, {'PI_CODING_AGENT_DIR': str(home), 'PI_LAB_TOOL_BUDGET_CONTEXT': 'ambient'}), \
                     mock.patch.object(worker, 'execute', return_value=release), \
                     mock.patch.object(worker, 'select_cwd', return_value='/workspace'), \
                     mock.patch.object(worker, 'control_dirs', return_value=(inbox, outbox)), \
                     mock.patch.object(worker, 'get_capabilities_manifest', side_effect=AssertionError('No prompt prefix allowed')), \
                     mock.patch.object(worker.subprocess, 'Popen', side_effect=boundary) as popen:
                    with self.assertRaises(InferenceBoundary):
                        worker.agent({'base_url': 'http://fixture.invalid/v1', 'model': 'fixture-model',
                            'api_key_env': 'PI_LAB_API_KEY', 'context_window': 32768, 'max_tokens': 1024}, task)
                self.assertEqual(popen.call_count, 1)
                argv = captured['argv']
                extensions = [argv[index + 1] for index, value in enumerate(argv) if value == '-e']
                self.assertEqual(extensions, ['/opt/pi-lab/workspace-boundary.mjs', '/opt/pi-lab/profile-monitor.mjs',
                                             '/opt/pi-profile/application-client.mjs'])
                self.assertEqual(argv[argv.index('--tools') + 1], ','.join(task['tools']))
                self.assertEqual('--no-mcp' in argv, release == '1.2.0')
                for flag in ('--no-extensions', '--no-skills', '--no-context-files', '--no-prompt-templates'):
                    self.assertIn(flag, argv)
                serialized = json.dumps(argv) + (home.parent / 'effective-configuration.json').read_text()
                self.assertNotIn('b' * 64, serialized); self.assertNotIn('c' * 64, serialized)

    def test_malformed_prompt_schema_profile_scope_and_guard_context_reject_before_configuration(self):
        for kind in ('prompt', 'schema', 'profile', 'plan', 'scope', 'private-mode', 'asset', 'extension', 'extra-marker', 'resume'):
            with self.subTest(kind=kind):
                task, context, private = self.fixture()
                if kind == 'prompt': task['prompt'] += 'changed'
                elif kind == 'schema': task['tool_schemas'][0]['description'] = 'changed'
                elif kind == 'profile': context['profile']['components'][0]['pi_release'] = '0.87.1'
                elif kind == 'plan': private['scope']['plan_sha256'] = 'f' * 64
                elif kind == 'scope': private['budget_context']['scope'] = {**private['scope'], 'operation_ids': ['foreign']}
                elif kind == 'asset':
                    asset = self.profile_root / 'application-client.mjs'; asset.chmod(0o600); asset.write_text('changed')
                elif kind == 'extension': private['budget_context']['extension_order_sha256'] = '0' * 64
                elif kind == 'extra-marker': task['application_execution']['unknown'] = True
                elif kind == 'resume': task['resume_session'] = '/untrusted/session.jsonl'
                Path(task['agent_profile_context']).write_text(json.dumps(context))
                self.write_private(task, private)
                if kind == 'private-mode': Path(task['application_context']).chmod(0o444)
                with mock.patch.object(worker, 'execute', return_value='1.2.0'), \
                     mock.patch.object(worker, 'model_configuration') as model, \
                     mock.patch.object(worker, 'select_cwd') as cwd, \
                     mock.patch.object(worker.subprocess, 'Popen') as popen:
                    with self.assertRaisesRegex(ValueError, '^Invalid compiled application execution$') as caught:
                        worker.agent({}, task)
                model.assert_not_called(); cwd.assert_not_called(); popen.assert_not_called()
                self.assertNotIn('b' * 64, str(caught.exception))

    def test_app_requires_explicit_native_tuple_and_refuses_legacy_native_context(self):
        for kind in ('partial', 'legacy-context', 'missing-marker'):
            task, context, private = self.fixture()
            if kind == 'partial': del task['reporting_reserve_calls']
            elif kind == 'legacy-context': task['native_budget_context'] = '/legacy/context.json'
            else: del task['application_execution']
            with mock.patch.object(worker, 'execute') as version, mock.patch.object(worker.subprocess, 'Popen') as popen:
                with self.assertRaises(ValueError): worker.agent({}, task)
            version.assert_not_called(); popen.assert_not_called()

    def test_linked_or_hardlinked_private_context_cannot_admit(self):
        task, context, private = self.fixture()
        original = Path(task['application_context']); link = self.root / 'linked-context.json'; link.symlink_to(original)
        task['application_context'] = str(link)
        with self.assertRaises(ValueError): worker.validate_application_execution(task, context, '1.2.0')
        link.unlink(); os.link(original, link)
        task['application_context'] = str(original)
        with self.assertRaises(ValueError): worker.validate_application_execution(task, context, '1.2.0')

    def continuation(self, task, private):
        message = 'Explicitly authorized correction. Preserve the frozen report contract.\n'
        task['resume_session'] = '/opt/pi-control/segments/' + private['scope']['segment_id'] + '/session.jsonl'
        task.update(prior_turns=1, prior_reported_tokens=5)
        task['application_continuation'] = {'schema': 1, 'command_id': str(uuid.uuid4()),
            'continues_segment_id': str(uuid.uuid4()), 'message': message,
            'sha256': hashlib.sha256(message.encode()).hexdigest()}
        return message

    def test_explicit_bound_continuation_sends_directive_and_preserves_frozen_initial_prompt_hash(self):
        task, context, private = self.fixture()
        frozen = task['prompt']; directive = self.continuation(task, private)
        self.assertEqual(worker.validate_application_execution(task, context, '1.2.0'), private)
        home = self.root / 'continued' / 'agent'
        inbox = self.root / 'continued' / 'inbox'; inbox.mkdir(parents=True)
        outbox = self.root / 'continued' / 'outbox'; outbox.mkdir()
        session = json.dumps({'type': 'session', 'version': 3, 'id': private['scope']['session_id'], 'cwd': '/workspace'}).encode() + b'\n'
        read = worker._application_read
        def admitted_read(path, maximum, private=False):
            if path == task['resume_session']: return session
            return read(path, maximum, private)
        def boundary(argv, **kwargs):
            self.assertEqual((home.parent / 'effective-prompt.txt').read_bytes(), directive.encode())
            self.assertEqual(task['prompt'], frozen)
            self.assertEqual(Path(argv[argv.index('--session') + 1]).read_bytes(), session)
            proof = json.loads((home.parent / 'application-prompt.json').read_text())
            self.assertEqual(proof['frozen_effective_prompt_sha256'], hashlib.sha256(frozen.encode()).hexdigest())
            self.assertEqual(proof['sent_prompt_sha256'], hashlib.sha256(directive.encode()).hexdigest())
            self.assertEqual(proof['continuation'], {key: task['application_continuation'][key]
                                                    for key in ('command_id', 'continues_segment_id', 'sha256')})
            self.assertNotIn('b' * 64, json.dumps(proof)); self.assertNotIn('c' * 64, json.dumps(proof))
            raise InferenceBoundary()
        with mock.patch.dict(os.environ, {'PI_CODING_AGENT_DIR': str(home)}), \
             mock.patch.object(worker, 'execute', return_value='1.2.0'), \
             mock.patch.object(worker, 'select_cwd', return_value='/workspace'), \
             mock.patch.object(worker, 'control_dirs', return_value=(inbox, outbox)), \
             mock.patch.object(worker, '_application_read', side_effect=admitted_read), \
             mock.patch.object(worker.subprocess, 'Popen', side_effect=boundary) as popen:
            with self.assertRaises(InferenceBoundary):
                worker.agent({'base_url': 'http://fixture.invalid/v1', 'model': 'fixture-model',
                    'api_key_env': 'PI_LAB_API_KEY', 'context_window': 32768, 'max_tokens': 1024}, task)
        self.assertEqual(popen.call_count, 1)

    def test_continuation_requires_exact_current_path_digest_identifiers_and_prior_caps(self):
        for kind in ('initial-object', 'wrong-path', 'hash', 'command', 'previous', 'oversize', 'prior-turns', 'prior-tokens'):
            with self.subTest(kind=kind):
                task, context, private = self.fixture(); self.continuation(task, private)
                if kind == 'initial-object': del task['resume_session']
                elif kind == 'wrong-path': task['resume_session'] = '/opt/pi-control/foreign/session.jsonl'
                elif kind == 'hash': task['application_continuation']['sha256'] = '0' * 64
                elif kind == 'command': task['application_continuation']['command_id'] = 'unrequested'
                elif kind == 'previous': task['application_continuation']['continues_segment_id'] = private['scope']['segment_id']
                elif kind == 'oversize': task['application_continuation']['message'] = 'x' * 16385
                elif kind == 'prior-turns': task['prior_turns'] = True
                else: task['prior_reported_tokens'] = task['max_total_tokens'] + 1
                with self.assertRaisesRegex(ValueError, '^Invalid compiled application execution$'):
                    worker.validate_application_execution(task, context, '1.2.0')


if __name__ == '__main__': unittest.main()
