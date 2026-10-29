"""Disposable owner-proof histories; Docker and process observations are synthetic."""
import contextlib
import copy
import hashlib
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import uuid
import errno
import subprocess
import argparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skill/scripts'))
import ownership_registry as registry
import registry_maintenance as maintenance
import registry_diagnostics as diagnostics
import stage_control as controls


class OwnerCleanupTests(unittest.TestCase):
    def setUp(self):
        self.api = importlib.import_module('application_owner_cleanup')
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.lease = self.root / 'lease'; self.lease.write_text('original lease\n'); self.lease.chmod(0o600)
        self.run = self.root / 'run'; self.run.mkdir(mode=0o700)
        self.workspace = self.run / 'workspace'; self.workspace.mkdir(mode=0o700)
        (self.workspace / 'private.txt').write_text('synthetic private fixture')
        self.calls = []
        def command(argv):
            self.calls.append(argv)
            if argv == ['docker', 'info', '--format', '{{.ID}}']:
                return self.reply(0, 'fixture-daemon\n')
            if argv[:3] == ['docker', 'container', 'inspect']:
                return self.reply(1, '[]\n', 'Error response from daemon: No such container: ' + argv[-1])
            if argv[:2] == ['docker', 'ps']:
                return self.reply(0, '')
            if argv[:3] == ['docker', 'network', 'inspect']:
                return self.reply(1, '', 'Error response from daemon: network ' + argv[-1] + ' not found')
            raise AssertionError('Unexpected or effectful Docker operation: ' + repr(argv))
        self.owner = registry.Registry(Path(str(self.lease) + '.registry'), command=command)
        self.owner.bind_daemon('fixture-daemon')
        self.name = 'pi-application-fixture'
        self.private = self.run / 'application-helpers' / ('a' * 32)
        self.helper = {'schema': 1, 'registry': self.owner.registry_id, 'generation': self.owner.generation,
                       'launch_id': str(uuid.uuid4()), 'status': 'released', 'container': self.name,
                       'image': 'sha256:' + 'a' * 64, 'container_id': 'b' * 64,
                       'mounts': [{'source': str(self.private / 'code'), 'target': '/opt/pi-application', 'rw': False},
                                  {'source': str(self.private / 'state'), 'target': '/pi-client/state', 'rw': True},
                                  {'source': str(self.run / 'application-evidence' / self.name), 'target': '/pi-client/evidence', 'rw': True}],
                       'application_helper': True, 'client_mode': 'application-execution',
                       'private_store': str(self.private), 'runroot': str(self.run), 'owner_pid': 2147483000,
                       'daemon': 'fixture-daemon', 'binding': {'run_id': str(uuid.uuid4()), 'attempt_id': str(uuid.uuid4())},
                       'code_identity': {'runtime/application_client_service.py': 'c' * 64}}
        self.owner.write(self.helper)
        self.evidence = self.root / 'evidence'; self.evidence.mkdir(mode=0o700)
        self.put(self.run / 'result.json', {'sealed': True, 'status': 'FAIL', 'cleanup_confirmed': False})
        self.pid = mock.patch.object(os, 'kill', side_effect=ProcessLookupError)
        self.kill = self.pid.start(); self.addCleanup(self.pid.stop)
        for name in ('run', 'Popen'):
            patcher = mock.patch.object(subprocess, name, side_effect=AssertionError('External process forbidden in owner fixtures'))
            patcher.start(); self.addCleanup(patcher.stop)

    @staticmethod
    def reply(code, body='', error=''):
        return type('Reply', (), {'returncode': code, 'stdout': body, 'stderr': error})()

    def put(self, path, body):
        path.parent.mkdir(parents=True, exist_ok=True)
        controls.atomic(path, body)
        return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}

    def launch_arguments(self):
        argv = ['docker', 'run', '--name', self.name, '--label', registry.LABEL + '=' + self.helper['launch_id'],
                '--label', registry.REGISTRY_LABEL + '=' + self.owner.registry_id]
        for mount in self.helper['mounts']:
            argv += ['--mount', 'type=bind,src=' + mount['source'] + ',dst=' + mount['target'] + (',readonly' if not mount['rw'] else '')]
        return argv + [self.helper['image'], '/opt/pi-application/runtime/application_client_service.py', '--port', '8081']

    def request(self, shape='agent'):
        original_cid = self.helper.get('container_id')
        if shape == 'interrupted':
            self.helper.pop('container_id', None); self.owner.write(self.helper)
        stages = []
        if shape != 'helper_only':
            stage_id = str(uuid.uuid4()); stage = self.run / 'stages' / stage_id
            info = self.workspace.stat()
            self.put(stage / 'descriptor.json', {'schema': 2, 'kind': 'agent', 'stage_id': stage_id,
                'label': 'agent-1-participant', 'workspace': str(self.workspace),
                'workspace_identity': [info.st_dev, info.st_ino], **self.helper['binding']})
            self.put(stage / 'state.json', {'schema': 2, 'status': 'finalized', 'cleanup_confirmed': False})
            self.put(stage / 'application-credentials.json', {'schema': 1, 'status': 'cleanup_unconfirmed', 'workspace': 'quarantined'})
            self.put(self.run / 'agent-1-participant' / 'process.json', {'cleanup_confirmed': False})
            context = self.run / 'controls' / stage_id / 'segments' / str(uuid.uuid4())
            self.put(context / 'application-context.json', {'private': 'synthetic'})
            stages.append(stage_id)
        info = self.workspace.stat()
        snapshot = self.put(self.evidence / 'snapshot.json', {'schema': 1, 'document_type': 'application_owned_snapshot',
            'registry': self.helper['registry'], 'generation': self.helper['generation'],
            'runroot': str(self.run), 'binding': self.helper['binding'], 'workspace': str(self.workspace),
            'workspace_identity': [info.st_dev, info.st_ino]})
        argv = ['python3', 'owner-controller.py', '--project', 'fixture']
        invocation = self.put(self.evidence / 'controller-invocation.json', {'schema': 1,
            'document_type': 'owned_process_invocation', 'pid': self.helper['owner_pid'], 'argv': argv,
            'cwd': str(self.root), 'runroot': str(self.run), 'registry': self.helper['registry'],
            'generation': self.helper['generation'], 'launch_ids': [self.helper['launch_id']]})
        terminal = self.put(self.evidence / 'controller-terminal.json', {'schema': 1,
            'document_type': 'owned_process_terminal', 'invocation': invocation, 'pid': self.helper['owner_pid'],
            'argv': argv, 'cwd': str(self.root), 'actual_exit': 2})
        launch_argv = ['docker', 'run', '--name', self.name,
            '--label', registry.LABEL + '=' + self.helper['launch_id'],
            '--label', registry.REGISTRY_LABEL + '=' + self.owner.registry_id,
        ]
        for mount in self.helper['mounts']:
            launch_argv += ['--mount', 'type=bind,src=' + mount['source'] + ',dst=' + mount['target'] + (',readonly' if not mount['rw'] else '')]
        launch_argv += [self.helper['image'], '/opt/pi-application/runtime/application_client_service.py', '--port', '8081']
        launch_invocation = self.put(self.evidence / 'launcher-invocation.json', {'schema': 1,
            'document_type': 'owned_process_invocation', 'pid': 2147482999, 'argv': launch_argv,
            'cwd': str(self.root), 'runroot': str(self.run), 'registry': self.helper['registry'],
            'generation': self.helper['generation'], 'launch_ids': [self.helper['launch_id']]})
        launch_terminal = self.put(self.evidence / 'launcher-terminal.json', {'schema': 1,
            'document_type': 'owned_process_terminal', 'invocation': launch_invocation, 'pid': 2147482999,
            'argv': launch_argv, 'cwd': str(self.root), 'actual_exit': 1})
        launcher = {'launch_id': self.helper['launch_id'], 'invocation': launch_invocation, 'terminal': launch_terminal}
        if shape == 'interrupted':
            guard = {k: self.helper[k] for k in ('registry', 'generation', 'launch_id', 'daemon', 'container', 'image', 'mounts')}
            guard.update(schema=1, document_type='owned_container_identity', container_id=original_cid,
                         intent_sha256=self.api.subject(self.helper)['intent_sha256'], invocation=launch_invocation)
            launcher['identity'] = self.put(self.evidence / 'original-guard-identity.json', guard)
        return {'schema': 1, 'document_type': 'application_owner_cleanup_request',
            'subject': self.api.subject(self.helper), 'shape': shape,
            'controller': {'invocation': invocation, 'terminal': terminal},
            'launchers': [launcher],
            'snapshot': snapshot, 'stages': stages, 'extra_private_roots': []}

    @contextlib.contextmanager
    def held(self):
        with maintenance.existing_lease(self.lease) as (fd, identity, path):
            self.owner.lease_fd = fd
            yield

    def recover(self, request, name='recovery'):
        with self.held():
            return self.api.recover(self.owner, request, self.root / name, discard_workspace=True)

    def metadata(self):
        return {p: p.read_bytes() for p in self.run.rglob('*.json')
                if 'controls' not in p.parts and 'children' not in p.parts}

    def test_independent_new_method_anchor_prohibits_old_recovery_downgrade(self):
        request = self.request()
        anchor = self.owner.root.with_name(self.owner.root.name + '.owner-selected') / (self.helper['launch_id'] + '.json')
        anchor.parent.mkdir(mode=0o700)
        self.put(anchor, {'schema': 1, 'document_type': 'application_owner_cleanup_anchor',
            'subject': self.api.subject(self.helper), 'method': 'legacy_derived_v1', 'cohort': 'application_owner_legacy_1',
            'intent': {'path': str(self.root / 'lost-intent.json'), 'sha256': 'a' * 64}})
        with self.assertRaises(registry.RegistryError):self.recover(request)
        self.assertTrue(self.workspace.exists()); self.assertFalse((self.root / 'recovery').exists())
        self.assertEqual(self.calls, [])

    def test_new_method_selection_prohibits_old_recovery_before_native_observation(self):
        request = self.request()
        store = self.api.store_path(self.owner); store.mkdir(mode=0o700)
        selection = self.api._selection(self.owner, self.helper); selection.parent.mkdir(mode=0o700)
        self.put(selection, {'schema': 2, 'document_type': 'application_owner_cleanup_selection',
            'subject': self.api.subject(self.helper), 'method': 'legacy_derived_v1', 'cohort': 'application_owner_legacy_1'})
        with self.assertRaises(registry.RegistryError):self.recover(request)
        self.assertTrue(self.workspace.exists()); self.assertFalse((self.root / 'recovery').exists())
        self.assertEqual(self.calls, [])

    def test_failed_stage_proof_preserves_raw_failure_and_reconciles_only_dependent_resources(self):
        request = self.request(); before = self.metadata(); record = self.owner.root / (self.helper['launch_id'] + '.json')
        original = record.read_bytes(); report = self.recover(request)
        self.assertEqual(report['status'], 'CLEANED'); self.assertFalse(report['admission_authorized'])
        self.assertFalse(self.workspace.exists()); self.assertEqual(self.metadata(), before)
        self.assertEqual(record.read_bytes(), original)
        self.owner.network_intent(self.name + '-network')
        with self.held():self.owner.reconcile()
        self.assertEqual({r['status'] for r in self.owner.load()}, {'released'})

    def test_helper_only_proof_never_fabricates_agent_metadata(self):
        request = self.request('helper_only'); self.recover(request)
        self.assertFalse((self.run / 'stages').exists())
        with self.held():self.assertTrue(self.api.validate_accepted(self.owner, self.helper))

    def test_missing_record_cid_uses_original_guard_identity_without_rewriting_record(self):
        request = self.request('interrupted'); original = copy.deepcopy(self.helper)
        self.recover(request)
        self.assertEqual(self.owner.load()[0], original)
        self.assertTrue(any(a[:2] == ['docker', 'ps'] for a in self.calls))
        self.assertIn(['docker', 'container', 'inspect', 'b' * 64], self.calls)
        self.assertNotIn(['docker', 'container', 'inspect', self.helper['container']], self.calls)

    def test_no_cid_name_absence_without_terminal_never_releases(self):
        request = self.request('interrupted'); request['launchers'] = []
        with self.assertRaises(registry.RegistryError):self.recover(request)
        self.assertTrue(self.workspace.exists()); self.assertEqual(self.calls, [])

    def test_pass_boolean_or_wrong_subject_cannot_be_owner_proof(self):
        request = self.request()
        for change in ({'status': 'PASS'}, {'subject': {**request['subject'], 'intent_sha256': '0' * 64}}):
            candidate = {**request, **change}
            with self.subTest(change=change), self.assertRaises(registry.RegistryError):self.recover(candidate)
        self.assertTrue(self.workspace.exists()); self.assertEqual(self.calls, [])

    def test_helper_only_with_undisclosed_stage_is_rejected(self):
        request = self.request(); request.update(shape='helper_only', stages=[])
        with self.assertRaises(registry.RegistryError):self.recover(request)
        self.assertEqual(self.calls, []); self.assertTrue(self.workspace.exists())

    def test_explicit_tampered_proof_blocks_even_all_released_without_fallback(self):
        request = self.request(); self.recover(request)
        receipt = self.root / 'recovery/recovery.json'; receipt.write_bytes(receipt.read_bytes() + b' ')
        with self.held(), self.assertRaises(registry.RegistryError):self.owner.validate_history(self.owner.load())

    def test_replay_does_not_recheck_reused_historical_pid(self):
        request = self.request(); self.recover(request)
        self.kill.reset_mock(); self.kill.side_effect = AssertionError('Historical PID must not be probed')
        self.calls.clear()
        with self.held():self.assertTrue(self.api.validate_accepted(self.owner, self.helper))
        self.kill.assert_not_called(); self.assertEqual(self.calls, [])

    def test_recreated_private_context_or_workspace_invalidates_receipt(self):
        request = self.request(); self.recover(request)
        self.workspace.mkdir(); (self.workspace / 'foreign').write_text('preserve')
        with self.held(), self.assertRaises(registry.RegistryError):self.api.validate_accepted(self.owner, self.helper)
        self.assertEqual((self.workspace / 'foreign').read_text(), 'preserve')

    def test_sibling_record_cannot_borrow_receipt(self):
        request = self.request(); self.recover(request)
        sibling = {**self.helper, 'launch_id': str(uuid.uuid4())}; self.owner.write(sibling)
        self.owner.network_intent('pending-network')
        with self.held(), self.assertRaises(registry.RegistryError):self.owner.validate_history(self.owner.load())

    def test_original_metadata_change_invalidates_rehashed_historical_evidence(self):
        request = self.request(); self.recover(request)
        self.put(self.run / 'result.json', {'sealed': True, 'status': 'PASS'})
        with self.held(), self.assertRaises(registry.RegistryError):self.api.validate_accepted(self.owner, self.helper)

    def test_unresolved_inference_or_live_controller_denies_before_effects(self):
        request = self.request(); self.kill.side_effect = None
        with self.assertRaises(registry.RegistryError):self.recover(request)
        self.assertTrue(self.workspace.exists()); self.assertEqual(self.calls, [])

    def test_missing_discard_authorization_is_read_only(self):
        request = self.request()
        with self.held(), self.assertRaises(registry.RegistryError):
            self.api.recover(self.owner, request, self.root / 'recovery')
        self.assertTrue(self.workspace.exists()); self.assertEqual(self.calls, [])

    def test_receipt_cannot_redirect_cleanup_to_symlink_or_unrelated_root(self):
        request = self.request(); other = self.root / 'other'; other.mkdir(); (other / 'keep').write_text('retain')
        self.workspace.rename(self.run / 'retained-workspace'); self.workspace.symlink_to(other, target_is_directory=True)
        with self.assertRaises(registry.RegistryError):self.recover(request)
        self.assertEqual((other / 'keep').read_text(), 'retain')

    def test_inspection_lists_all_shapes_without_docker_or_mutation(self):
        self.request('helper_only')
        before = self.metadata()
        with self.held():report = self.api.inspect_helpers(self.owner, self.owner.load())
        self.assertEqual(report[0]['launch_id'], self.helper['launch_id'])
        self.assertEqual(report[0]['condition'], 'owner_proof_required')
        self.assertEqual(self.metadata(), before); self.assertEqual(self.calls, [])

    def test_pending_application_helpers_still_require_their_original_owned_cleanup(self):
        request = self.request(); self.helper['status'] = 'quarantined'; self.owner.write(self.helper)
        with self.assertRaises(registry.RegistryError):self.recover(request)
        self.assertTrue(self.workspace.exists()); self.assertEqual(self.calls, [])

    def test_current_daemon_or_owned_label_uncertainty_denies_cleanup(self):
        request = self.request(); real = self.owner.command
        def wrong(argv):
            if argv[:2] == ['docker', 'ps']:return self.reply(0, 'd' * 64)
            return real(argv)
        self.owner.command = wrong
        with self.assertRaises(registry.RegistryError):self.recover(request)
        self.assertTrue(self.workspace.exists())

    def test_launcher_host_file_options_are_not_terminal_writer_proof(self):
        request = self.request('interrupted'); item = request['launchers'][0]
        invocation = json.loads(Path(item['invocation']['path']).read_text())
        invocation['argv'][2:2] = ['--cidfile=' + str(self.root / 'foreign')]
        item['invocation'] = self.put(Path(item['invocation']['path']), invocation)
        terminal = json.loads(Path(item['terminal']['path']).read_text())
        terminal.update(argv=invocation['argv'], invocation=item['invocation'])
        item['terminal'] = self.put(Path(item['terminal']['path']), terminal)
        with self.assertRaises(registry.RegistryError):self.recover(request)
        self.assertEqual(self.calls, []); self.assertTrue(self.workspace.exists())

    def test_unknown_external_private_scope_requires_a_reviewed_adapter(self):
        request = self.request(); request['extra_private_roots'] = [{'path': str(self.root / 'foreign')}]
        with self.assertRaises(registry.RegistryError):self.recover(request)
        self.assertEqual(self.calls, []); self.assertTrue(self.workspace.exists())

    def test_initial_receipt_failure_has_no_cleanup_effects(self):
        request = self.request()
        with mock.patch.object(maintenance._Receipt, 'publish', side_effect=OSError(errno.ENOSPC, 'private-canary')):
            with self.assertRaises(registry.RegistryError):self.recover(request)
        self.assertTrue(self.workspace.exists()); self.assertFalse(self.api._index(self.owner, self.helper).exists())

    def test_interrupted_purge_retains_a_terminal_receipt_without_index(self):
        request = self.request(); original = self.api._purge
        def interrupted(observation):
            original(observation)
            if observation['state'] == 'present':raise KeyboardInterrupt
        with mock.patch.object(self.api, '_purge', side_effect=interrupted), self.assertRaises(KeyboardInterrupt):self.recover(request)
        receipt = json.loads((self.root / 'recovery/recovery.json').read_text())
        self.assertEqual(receipt['status'], 'INTERRUPTED'); self.assertEqual(receipt['effects'], 'may_have_occurred')
        self.assertFalse(self.api._index(self.owner, self.helper).exists())

    def test_index_failure_never_turns_partial_publication_into_proof(self):
        request = self.request()
        with mock.patch.object(self.api, '_publish_index', side_effect=OSError(errno.EIO, 'private-canary')):
            with self.assertRaises(registry.RegistryError):self.recover(request)
        self.assertFalse(self.workspace.exists())
        self.assertEqual(json.loads((self.root / 'recovery/recovery.json').read_text())['status'], 'BLOCKED')
        with self.held(), self.assertRaises(registry.RegistryError):self.api.validate_accepted(self.owner, self.helper)

    def test_workspace_replacement_between_observation_and_purge_preserves_foreign_files(self):
        request = self.request(); original = self.api._purge
        def replaced(observation):
            if observation['path'] == str(self.workspace):
                self.workspace.rename(self.run / 'original-workspace'); self.workspace.mkdir()
                (self.workspace / 'foreign').write_text('retain')
            return original(observation)
        with mock.patch.object(self.api, '_purge', side_effect=replaced), self.assertRaises(registry.RegistryError):self.recover(request)
        self.assertEqual((self.workspace / 'foreign').read_text(), 'retain')

    def test_index_links_and_insecure_store_never_fall_back(self):
        request = self.request(); self.recover(request)
        index = self.api._index(self.owner, self.helper); body = index.read_bytes()
        for kind in ('mode', 'symlink', 'dangling', 'hardlink', 'store'):
            with self.subTest(kind=kind):
                if os.path.lexists(index):index.unlink()
                index.write_bytes(body); index.chmod(0o600)
                if kind == 'mode':index.chmod(0o644)
                if kind in ('symlink', 'dangling'):
                    index.unlink(); index.symlink_to(self.root / ('recovery/recovery.json' if kind == 'symlink' else 'missing'))
                if kind == 'hardlink':os.link(index, self.root / 'extra-index-link')
                if kind == 'store':index.parent.chmod(0o755)
                with self.held(), self.assertRaises((registry.RegistryError, OSError)):
                    self.owner.validate_history(self.owner.load())
                index.parent.chmod(0o700)

    def test_cli_inspection_is_offline_and_does_not_create_missing_state(self):
        import io
        import pi_lab
        self.request('helper_only'); output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = pi_lab.main(['application-owner-inspect', '--lock-file', str(self.lease)])
        self.assertEqual(code, 0); self.assertEqual(self.calls, [])
        self.assertEqual(json.loads(output.getvalue())['helpers'][0]['condition'], 'owner_proof_required')
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = pi_lab.main(['application-owner-inspect', '--lock-file', str(self.root / 'missing-lease')])
        self.assertEqual(code, 2); self.assertFalse((self.root / 'missing-lease').exists())

    def test_cli_failure_never_prints_evidence_paths_or_exception_canaries(self):
        import io
        import pi_lab
        request = self.request(); ref = self.put(self.evidence / 'request.json', request)
        output = io.StringIO()
        with mock.patch.object(self.api, '_writers_absent', side_effect=OSError(errno.EIO, 'secret-canary')):
            with contextlib.redirect_stdout(output):
                code = pi_lab.main(['application-owner-recover', '--lock-file', str(self.lease), '--request', ref['path'],
                                    '--output-dir', str(self.root / 'output'), '--discard-workspace'])
        self.assertEqual(code, 2); self.assertNotIn('secret-canary', output.getvalue())
        self.assertNotIn(str(self.evidence), output.getvalue()); self.assertTrue(self.workspace.exists())

    def runtime_cleanup(self):
        import application_client
        helper = object.__new__(application_client.OwnedHelper)
        helper.registry = self.owner; helper.record = self.helper
        self.helper['schema'] = 3
        self.helper['owner_cleanup_contract'] = 1
        self.helper['owner_pid'] = os.getpid()
        self.helper.pop('container_id'); self.helper['status'] = 'intent'; self.owner.write(self.helper)
        helper._owner_custody = self.api.begin_custody(helper, self.launch_arguments())
        self.api.custody_event(helper, 'launch_attempted')
        helper.process = argparse.Namespace(pid=2147482999, returncode=0)
        self.api.custody_launched(helper)
        helper.container_id = 'b' * 64; self.api.custody_identity(helper, helper.container_id)
        self.helper['container_id'] = 'b' * 64; self.owner.write(self.helper)
        self.api.custody_event(helper, 'container_bound'); self.api.custody_event(helper, 'bootstrap_sent')
        helper.cleanup_receipt = {'status': 'removed', 'workspace': 'clean', 'safe_to_continue': True}
        self.helper['status'] = 'released'; self.owner.write(self.helper)
        self.api.custody_event(helper, 'helper_cleanup')
        return helper

    def test_normal_helper_only_finalization_emits_replayable_proof(self):
        before = self.metadata()
        with self.held():
            self.runtime_cleanup(); self.owner.close()
            self.assertTrue(self.api.validate_accepted(self.owner, self.helper))
        self.assertEqual(self.metadata(), before); self.assertEqual(self.calls, [])
        self.assertTrue(self.workspace.exists())

    def test_unfinalized_current_custody_blocks_even_all_released(self):
        with self.held():
            self.runtime_cleanup()
            with self.assertRaises(registry.RegistryError):self.owner.validate_history(self.owner.load())

    def test_normal_proof_revalidates_retained_workspace_inventory(self):
        with self.held():
            self.runtime_cleanup(); self.owner.close()
            (self.workspace / 'private.txt').write_text('changed')
            with self.assertRaises(registry.RegistryError):self.api.validate_accepted(self.owner, self.helper)

    def test_failed_agent_metadata_cannot_become_normal_success_proof(self):
        self.request()
        with self.held():
            self.runtime_cleanup()
            with self.assertRaises(registry.RegistryError):self.owner.close()
        self.assertFalse(self.api._index(self.owner, self.helper).exists())

    def test_deleted_selected_index_does_not_restore_all_released_shortcut(self):
        request = self.request(); self.recover(request)
        self.api._index(self.owner, self.helper).unlink()
        with self.held(), self.assertRaises(registry.RegistryError):self.owner.validate_history(self.owner.load())

    def test_deleted_current_custody_still_requires_proof_from_original_intent_marker(self):
        with self.held():
            self.runtime_cleanup(); self.api._custody_path(self.owner, self.helper).unlink()
            with self.assertRaises(registry.RegistryError):self.owner.validate_history(self.owner.load())

    def test_bound_external_envelope_must_be_declared_and_already_absent(self):
        request = self.request(); invocation = json.loads(Path(request['controller']['invocation']['path']).read_text())
        parent = self.root / 'pi-qualification-cell-fixture'
        invocation['argv'] += ['--private-envelope', str(parent / 'initial.json')]
        request['controller']['invocation'] = self.put(Path(request['controller']['invocation']['path']), invocation)
        terminal = json.loads(Path(request['controller']['terminal']['path']).read_text())
        terminal.update(invocation=request['controller']['invocation'], argv=invocation['argv'])
        request['controller']['terminal'] = self.put(Path(request['controller']['terminal']['path']), terminal)
        with self.assertRaises(registry.RegistryError):self.recover(request)
        request['extra_private_roots'] = [{'path': str(parent), 'origin': request['controller']['invocation']}]
        parent.mkdir(); (parent / 'initial.json').write_text('retain synthetic authority')
        with self.assertRaises(registry.RegistryError):self.recover(request)
        self.assertTrue((parent / 'initial.json').exists()); self.assertEqual(self.calls, [])
        (parent / 'initial.json').unlink(); parent.rmdir()
        self.recover(request)
        with self.held():self.assertTrue(self.api.validate_accepted(self.owner, self.helper))

    def test_private_receipt_directory_mode_change_blocks_replay(self):
        request = self.request(); self.recover(request)
        (self.root / 'recovery').chmod(0o755)
        with self.held(), self.assertRaises(registry.RegistryError):self.api.validate_accepted(self.owner, self.helper)

    def test_proof_publication_effects_are_reported_even_when_private_roots_are_absent(self):
        request = self.request('helper_only')
        (self.workspace / 'private.txt').unlink(); self.workspace.rmdir()
        report = self.recover(request)
        self.assertEqual(report['effects'], 'may_have_occurred')

    def test_original_stage_binding_mismatch_denies_before_docker(self):
        request = self.request(); target = self.run / 'stages' / request['stages'][0] / 'descriptor.json'
        descriptor = json.loads(target.read_text()); descriptor['attempt_id'] = str(uuid.uuid4()); self.put(target, descriptor)
        with self.assertRaises(registry.RegistryError):self.recover(request)
        self.assertTrue(self.workspace.exists()); self.assertEqual(self.calls, [])

    def test_custody_directory_chain_is_synced_before_dispatch(self):
        synced = []; real = os.fsync
        def observed(fd):
            info = os.fstat(fd); synced.append((info.st_dev, info.st_ino)); return real(fd)
        with self.held(), mock.patch.object(os, 'fsync', side_effect=observed):self.runtime_cleanup()
        for target in (self.api.store_path(self.owner), self.api.store_path(self.owner) / 'custody',
                       self.api._custody_path(self.owner, self.helper).parent):
            info = target.stat(); self.assertIn((info.st_dev, info.st_ino), synced)

    def test_orphan_context_without_stage_descriptor_is_not_cleared_by_helper_only_proof(self):
        request = self.request('helper_only')
        context = self.run / 'controls' / str(uuid.uuid4()) / 'segments' / str(uuid.uuid4()) / 'application-context.json'
        self.put(context, {'private': 'synthetic orphan authority'})
        with self.assertRaises(registry.RegistryError):self.recover(request)
        self.assertTrue(context.exists()); self.assertTrue(self.workspace.exists()); self.assertEqual(self.calls, [])

    def test_uninspected_retained_file_requires_an_owner_adapter_without_deleting_history(self):
        request = self.request('helper_only'); raw = self.run / 'uninspected-private.log'
        raw.write_text('synthetic private fixture')
        with self.assertRaises(registry.RegistryError):self.recover(request)
        self.assertTrue(self.workspace.exists()); self.assertEqual(raw.read_text(), 'synthetic private fixture')
        self.assertEqual(self.calls, [])

    def test_known_nonagent_control_scope_is_cleaned_without_fabricating_an_agent(self):
        request = self.request('helper_only'); stage = str(uuid.uuid4())
        self.put(self.run / 'stages' / stage / 'descriptor.json',
                 {'stage_id': stage, 'kind': 'preflight', **self.helper['binding']})
        context = self.run / 'controls' / stage
        self.put(context / 'segments' / str(uuid.uuid4()) / 'application-context.json', {'private': 'synthetic'})
        self.put(context / 'inbox' / 'command.json', {'private': 'synthetic'})
        self.put(context / 'outbox' / 'response.json', {'private': 'synthetic'})
        self.recover(request)
        self.assertFalse((context / 'segments').exists()); self.assertFalse((context / 'inbox').exists())
        self.assertFalse((context / 'outbox').exists())
        self.assertEqual(json.loads((self.run / 'stages' / stage / 'descriptor.json').read_text())['kind'], 'preflight')
        with self.held():self.assertTrue(self.api.validate_accepted(self.owner, self.helper))

    def test_normal_runtime_binds_other_retained_run_files(self):
        raw = self.run / 'retained-redacted.log'; raw.write_text('synthetic public log')
        with self.held():
            self.runtime_cleanup(); self.owner.close()
            raw.write_text('changed')
            with self.assertRaises(registry.RegistryError):self.api.validate_accepted(self.owner, self.helper)

    def test_original_budget_metadata_is_preserved_and_bound(self):
        request = self.request(); target = self.run / 'stages' / request['stages'][0] / 'budget.json'
        self.put(target, {'schema': 1, 'status': 'closed', 'remaining': 0}); original = target.read_bytes()
        self.recover(request); self.assertEqual(target.read_bytes(), original)
        self.put(target, {'schema': 1, 'status': 'open', 'remaining': 1})
        with self.held(), self.assertRaises(registry.RegistryError):self.api.validate_accepted(self.owner, self.helper)

    def test_regular_proof_store_replacement_never_receives_an_index(self):
        request = self.request('helper_only'); original = self.api._publish_index
        def replaced(owner, record, reference):
            store = self.api.store_path(owner); store.rename(self.root / 'original-proof-store')
            store.mkdir(mode=0o700); (store / 'foreign.txt').write_text('retain')
            return original(owner, record, reference)
        with mock.patch.object(self.api, '_publish_index', side_effect=replaced), self.assertRaises(registry.RegistryError):
            self.recover(request)
        self.assertEqual(sorted(p.name for p in self.api.store_path(self.owner).iterdir()), ['foreign.txt'])

    def test_custody_creation_after_store_swap_cannot_write_into_foreign_directory(self):
        original = self.api._store; replaced = []
        def swap(owner):
            fd = original(owner)
            if not replaced:
                replaced.append(True); store = self.api.store_path(owner); store.rename(self.root / 'original-proof-store')
                store.mkdir(mode=0o700); (store / 'custody').mkdir(mode=0o700); (store / 'foreign.txt').write_text('retain')
            return fd
        with self.held(), mock.patch.object(self.api, '_store', side_effect=swap), self.assertRaises(registry.RegistryError):
            self.runtime_cleanup()
        self.assertEqual(list((self.api.store_path(self.owner) / 'custody').iterdir()), [])

    def test_selected_directory_swap_cannot_redirect_selection_publication(self):
        request = self.request('helper_only'); original = self.api.Reader.read; swapped = []
        def read(reader, value, *args, **kwargs):
            try:return original(reader, value, *args, **kwargs)
            except FileNotFoundError:
                if str(value) == str(self.api._selection(self.owner, self.helper)) and not swapped:
                    swapped.append(True); selected = self.api.store_path(self.owner) / 'selected'
                    selected.rename(self.root / 'original-selected'); selected.mkdir(mode=0o700)
                    (selected / 'foreign.txt').write_text('retain')
                raise
        with mock.patch.object(self.api.Reader, 'read', new=read), self.assertRaises(registry.RegistryError):self.recover(request)
        self.assertEqual(sorted(p.name for p in (self.api.store_path(self.owner) / 'selected').iterdir()), ['foreign.txt'])

    def test_owner_docker_observation_does_not_inherit_exported_application_or_inference_keys(self):
        with mock.patch.dict(os.environ, {'PI_API_KEY': 'synthetic-inference-value', 'PI_APP_TEST': 'synthetic-application-value',
                                        'DOCKER_HOST': 'unix:///synthetic/daemon.sock'}):
            with mock.patch.object(subprocess, 'run', return_value=self.reply(0, 'fixture-daemon')) as run:
                self.api._owner_docker(['docker', 'info', '--format', '{{.ID}}'])
        environment = run.call_args.kwargs['env']
        self.assertNotIn('PI_API_KEY', environment); self.assertNotIn('PI_APP_TEST', environment)
        self.assertEqual(environment['DOCKER_HOST'], 'unix:///synthetic/daemon.sock')
        self.assertEqual(run.call_args.kwargs['timeout'], 15)

    def test_lost_bound_store_is_not_automatically_recreated_during_publication(self):
        request = self.request('helper_only'); original = self.api._publish_index
        def removed(owner, record, reference):
            self.api.store_path(owner).rename(self.root / 'original-proof-store')
            return original(owner, record, reference)
        with mock.patch.object(self.api, '_publish_index', side_effect=removed), self.assertRaises(registry.RegistryError):
            self.recover(request)
        self.assertFalse(self.api.store_path(self.owner).exists())

    def test_no_cid_terminal_and_name_absence_without_original_guard_stays_blocked(self):
        request = self.request('interrupted'); request['launchers'][0].pop('identity')
        with self.assertRaises(registry.RegistryError):self.recover(request)
        self.assertEqual(self.calls, []); self.assertTrue(self.workspace.exists())

    def test_original_guard_identity_cannot_be_fabricated_or_borrowed(self):
        request = self.request('interrupted'); launcher = request['launchers'][0]
        guard = json.loads(Path(launcher['identity']['path']).read_text())
        for field, value in (('container_id', '0' * 64), ('container_id', True), ('launch_id', str(uuid.uuid4())),
                             ('intent_sha256', '0' * 64), ('invocation', request['controller']['invocation'])):
            candidate = copy.deepcopy(request); modified = {**guard, field: value}
            candidate['launchers'][0]['identity'] = self.put(self.evidence / 'changed-guard.json', modified)
            with self.subTest(field=field, value=value), self.assertRaises(registry.RegistryError):self.recover(candidate)
        self.assertEqual(self.calls, []); self.assertTrue(self.workspace.exists())

    def test_launcher_environment_cannot_add_an_unreviewed_authority(self):
        request = self.request('helper_only'); launcher = request['launchers'][0]
        invocation = json.loads(Path(launcher['invocation']['path']).read_text())
        invocation['argv'][2:2] = ['--env', 'PI_API_KEY=synthetic-private-authority']
        launcher['invocation'] = self.put(Path(launcher['invocation']['path']), invocation)
        terminal = json.loads(Path(launcher['terminal']['path']).read_text())
        terminal.update(argv=invocation['argv'], invocation=launcher['invocation'])
        launcher['terminal'] = self.put(Path(launcher['terminal']['path']), terminal)
        with self.assertRaises(registry.RegistryError):self.recover(request)
        self.assertTrue(self.workspace.exists()); self.assertEqual(self.calls, [])

    def test_new_record_format_requires_the_real_ordinary_owner_contract(self):
        for change in ({'schema': 3}, {'schema': 3, 'owner_cleanup_contract': True},
                       {'schema': 1, 'owner_cleanup_contract': 1},
                       {'schema': 3, 'owner_cleanup_contract': 1, 'qualification_role': 'fixture'}):
            row = {**self.helper, **change}; self.owner.write(row)
            with self.subTest(change=change), self.assertRaises(registry.RegistryError):self.owner.load()
        self.owner.write(self.helper)


class RuntimeCustodyProcessTests(unittest.TestCase):
    def test_real_host_helper_records_cid_before_private_bootstrap_under_temporary_lease(self):
        import argparse
        import application_client as client
        from parallel_allocator import Allocator
        import test_application_client_authority as fixtures
        api = importlib.import_module('application_owner_cleanup')
        fixture = fixtures.BaseFixture(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        lease = fixture.root / 'lease'; lease.write_text('retained lease\n'); lease.chmod(0o600)
        boundary = fixtures.DockerBoundary()
        owner = registry.Registry(Path(str(lease) + '.registry'), command=boundary.command)
        owner.bind_daemon('fixture-daemon'); boundary.records = owner.load
        authority, unused = fixture.authority()
        pool = Allocator({'cpu_millis': 4000, 'memory_mib': 8192, 'pids_limit': 1024})
        args = argparse.Namespace(platform='linux/arm64', native_platform='linux/arm64', uid=os.getuid(), gid=os.getgid())
        ready, send = client._ready, client._send_bootstrap
        def observed_ready(process, deadline=10):
            value = ready(process, deadline); boundary.port = value['port']; return value
        def observed_send(process, payload, timeout=10):
            row = next(r for r in owner.load() if r.get('application_helper'))
            body = json.loads(api._custody_path(owner, row).read_text())
            self.assertEqual(row['container_id'], 'f' * 64)
            self.assertEqual(body['events'], ['intent', 'launch_attempted', 'container_bound'])
            guard = json.loads(Path(body['guard']['path']).read_text())
            self.assertEqual(guard['container_id'], 'f' * 64); self.assertEqual(guard['invocation'], body['launcher'])
            self.assertIsNone(body['terminal'])
            return send(process, payload, timeout)
        original_write = owner.write
        def guarded_write(row):
            if row.get('application_helper') is True and row.get('container_id') == 'f' * 64 and row['status'] == 'intent':
                guard = api._custody_path(owner, row).parent / 'container-identity/recovery.json'
                self.assertEqual(json.loads(guard.read_text())['container_id'], 'f' * 64)
            return original_write(row)
        with maintenance.existing_lease(lease) as (fd, unused, selected):
            owner.lease_fd = fd
            with mock.patch.object(client, '_ready', side_effect=observed_ready), \
                 mock.patch.object(client, '_send_bootstrap', side_effect=observed_send), \
                 mock.patch.object(owner, 'write', side_effect=guarded_write):
                helper = client.OwnedHelper.start(authority, lab=boundary, args=args, registry=owner,
                    allocator=pool, participant_resources={'cpu_millis': 1000, 'memory_mib': 2048, 'pids_limit': 256},
                    popen=boundary.popen)
            self.addCleanup(lambda: helper.cleanup(writers_absent=True))
            cleanup = helper.cleanup(writers_absent=True); self.assertEqual(cleanup['status'], 'removed')
            self.assertEqual(helper.record['schema'], 3); self.assertEqual(helper.record['owner_cleanup_contract'], 1)
            custody = json.loads(api._custody_path(owner, helper.record).read_text())
            terminal = json.loads(Path(custody['terminal']['path']).read_text())
            self.assertEqual(terminal['pid'], boundary.process.pid)
            self.assertEqual(terminal['actual_exit'], boundary.process.returncode)
            owner.close(); self.assertTrue(api.validate_accepted(owner, helper.record))
            for proof in api.store_path(owner).rglob('*.json'):
                body = proof.read_text()
                for value in (fixtures.KEY_A, fixtures.KEY_B, fixtures.INFERENCE_KEY):self.assertNotIn(value, body)
        self.assertFalse(any(isinstance(item, list) and item[:2] == ['docker', 'run'] for item in boundary.events))


if __name__ == '__main__':
    unittest.main()
