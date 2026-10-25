"""Closed timing metadata and real identity-method clock composition offline.

No Docker, model, real credential, global lease or actual campaign is used.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'skill/scripts'), str(ROOT / 'skill/runtime'),
               str(ROOT / 'tools/qualification')]
import application_timing as timing


class RecorderTests(unittest.TestCase):
    def test_complete_trace_pairs_durations_and_never_attests_success(self):
        now = [1000.]
        rec = timing.Recorder(clock=lambda: now[0])
        for event in timing.EVENTS[:-1]:
            if event == 'identity_bind_enter':
                self.assertTrue(rec.observe_deadline(1005.))
            self.assertTrue(rec.emit(event, status='returned' if event.endswith('return') else 'observed'))
            now[0] += .1
        value = rec.record_metadata()
        self.assertEqual(len(value['events']), 11)
        self.assertAlmostEqual(value['durations']['guard_prelaunch_seconds'], .4)
        self.assertAlmostEqual(value['durations']['guard_callback_seconds'], .8)
        self.assertAlmostEqual(value['identity_bind_remaining_seconds_at_entry'], 4.1)
        self.assertFalse(value['identity_deadline_already_expired_at_entry'])
        self.assertFalse(value['native_success_attested'])
        self.assertFalse(value['deadline_changed'])
        self.assertEqual(value['extra_dispatches'], 0)
        self.assertEqual((value['runtime_identity_seconds'], value['guard_capture_seconds']), (5, 5))

    def test_missing_measurements_are_null_not_fabricated_zero(self):
        rec = timing.Recorder(clock=lambda: 10.)
        self.assertTrue(rec.emit('guard_enter'))
        value = rec.record_metadata()
        self.assertTrue(all(x is None for x in value['durations'].values()))
        self.assertIsNone(value['runtime_deadline_monotonic'])
        self.assertIsNone(value['identity_deadline_already_expired_at_entry'])
        self.assertEqual(value['identity_bind_outcome'], 'not_observed')

    def test_closed_event_status_and_order_deny_private_payloads(self):
        for event, status in [('private-capability-canary', 'observed'),
                              ('guard_enter', 'private-exception-canary')]:
            rec = timing.Recorder(clock=lambda: 100.)
            self.assertFalse(rec.emit(event, status=status))
            text = json.dumps(rec.record_metadata())
            self.assertNotIn('canary', text)
            self.assertEqual(rec.record_metadata()['status'], 'timing_unavailable')
        rec = timing.Recorder(clock=lambda: 100.)
        rec.emit('delegate_enter')
        self.assertFalse(rec.emit('guard_enter'))
        self.assertEqual(len(rec.record_metadata()['events']), 1)

    def test_duplicate_and_terminal_observation_cannot_reopen_recorder(self):
        rec = timing.Recorder(clock=lambda: 100.)
        rec.emit('guard_enter')
        self.assertFalse(rec.emit('guard_enter'))
        rec.terminal()
        self.assertFalse(rec.emit('delegate_enter'))
        self.assertEqual(len(rec.record_metadata()['events']), 1)
        self.assertIsNone(rec.record_metadata()['durations']['guard_prelaunch_seconds'])

    def test_finite_ordered_clocks_and_deadlines_required(self):
        for value in [True, -1, float('nan'), float('inf'), 'private-clock-canary', 10**1000]:
            rec = timing.Recorder(clock=lambda: value)
            self.assertFalse(rec.emit('guard_enter'))
            self.assertNotIn('canary', json.dumps(rec.record_metadata()))
        rec = timing.Recorder(clock=iter([100., 99.]).__next__)
        self.assertTrue(rec.emit('guard_enter'))
        self.assertFalse(rec.emit('delegate_enter'))
        for value in [None, True, 0, -1, float('nan'), float('inf'), 'private-deadline-canary']:
            rec = timing.Recorder()
            self.assertFalse(rec.observe_deadline(value))
            self.assertIsNone(rec.record_metadata()['runtime_deadline_monotonic'])
        rec = timing.Recorder()
        self.assertTrue(rec.observe_deadline(100.))
        self.assertFalse(rec.observe_deadline(101.))

    def test_clock_ordinary_failure_is_unavailable_but_cancel_propagates(self):
        rec = timing.Recorder(clock=mock.Mock(side_effect=RuntimeError('private-error-canary')))
        self.assertFalse(rec.emit('guard_enter'))
        self.assertNotIn('canary', json.dumps(rec.record_metadata()))
        rec = timing.Recorder(clock=mock.Mock(side_effect=KeyboardInterrupt))
        with self.assertRaises(KeyboardInterrupt):
            rec.emit('guard_enter')

    def test_at_most_twelve_events_and_metadata_copy_is_detached(self):
        rec = timing.Recorder(clock=lambda: 100.)
        for event in timing.EVENTS:
            self.assertTrue(rec.emit(event))
        self.assertFalse(rec.emit('guard_enter'))
        value = rec.record_metadata()
        self.assertEqual(len(value['events']), 12)
        self.assertLess(len(json.dumps(value).encode()), timing.MAX_BYTES)
        value['events'][0]['event'] = 'private-mutated-canary'
        self.assertEqual(rec.record_metadata()['events'][0]['event'], 'guard_enter')


class BindingTests(unittest.TestCase):
    def test_original_arguments_result_and_exception_identity_once(self):
        calls = []
        result = object()
        class Helper:
            def _bind_container_identity(self, *args, **kwargs):
                calls.append((args, kwargs))
                return result
        original = Helper._bind_container_identity
        rec = timing.Recorder(clock=lambda: 100.)
        helper = Helper()
        with timing.observe_identity_binding(Helper, lambda value: rec if value is helper else None):
            self.assertIs(helper._bind_container_identity(deadline=105.), result)
        self.assertEqual(calls, [((), {'deadline': 105.})])
        self.assertIs(Helper._bind_container_identity, original)
        self.assertEqual(rec.record_metadata()['identity_bind_outcome'], 'returned')

    def test_original_failure_or_cancel_is_not_replaced_by_recorder_failure(self):
        for error in [ValueError('primary'), KeyboardInterrupt(), SystemExit(2)]:
            calls = []
            class Helper:
                def _bind_container_identity(self, deadline):
                    calls.append(deadline)
                    raise error
            original = Helper._bind_container_identity
            rec = timing.Recorder(clock=lambda: 100.)
            original_emit = rec.emit
            def emit(event, **kwargs):
                if event == 'identity_bind_return':
                    raise KeyboardInterrupt('secondary-private-canary')
                return original_emit(event, **kwargs)
            with mock.patch.object(rec, 'emit', side_effect=emit):
                with self.assertRaises(BaseException) as caught:
                    with timing.observe_identity_binding(Helper, lambda _: rec):
                        Helper()._bind_container_identity(105.)
            self.assertIs(caught.exception, error)
            self.assertEqual(calls, [105.])
            self.assertIs(Helper._bind_container_identity, original)

    def test_recorder_or_provider_ordinary_failure_still_calls_original_once(self):
        for provider_failure in [False, True]:
            calls = []
            class Helper:
                def _bind_container_identity(self, deadline):
                    calls.append(deadline)
                    return 'original'
            rec = timing.Recorder()
            provider = mock.Mock(side_effect=RuntimeError()) if provider_failure else lambda _: rec
            with mock.patch.object(rec, 'emit', side_effect=RuntimeError('private-canary')):
                with timing.observe_identity_binding(Helper, provider):
                    self.assertEqual(Helper()._bind_container_identity(105.), 'original')
            self.assertEqual(calls, [105.])

    def test_unselected_helper_and_nested_context_restore(self):
        class Parent:
            def _bind_container_identity(self, deadline):
                return deadline
        class Child(Parent):
            pass
        original = Parent._bind_container_identity
        with timing.observe_identity_binding(Child, lambda _: None):
            with self.assertRaises(timing.TimingContextError):
                with timing.observe_identity_binding(Child, lambda _: None):
                    self.fail('nested instrumentation entered')
            self.assertEqual(Child()._bind_container_identity(12), 12)
        self.assertNotIn('_bind_container_identity', Child.__dict__)
        self.assertIs(Child._bind_container_identity, original)

    def test_real_identity_method_zero_vs_six_second_callback_budget_unchanged(self):
        import application_client as client
        for advance in [0., 6.]:
            now = [1000.]
            rec = timing.Recorder(clock=lambda: now[0])
            helper = object.__new__(client.OwnedHelper)
            helper._check_daemon = mock.Mock()
            helper._command = mock.Mock(return_value=types.SimpleNamespace(returncode=0, stdout='[{}]', stderr=''))
            helper._verify_observation = mock.Mock(return_value='f' * 64)
            helper.name = 'controlled-helper'
            helper.registry = mock.Mock()
            helper.record = {}
            helper.container_id = None
            helper.process = types.SimpleNamespace(poll=lambda: None)
            deadline = now[0] + 5
            rec.emit('guard_enter')
            rec.emit('delegate_enter')
            now[0] += advance
            rec.emit('delegate_return')
            rec.emit('guard_return')
            with mock.patch.object(client, 'time', types.SimpleNamespace(monotonic=lambda: now[0], sleep=lambda _: None)):
                with timing.observe_identity_binding(client.OwnedHelper, lambda value: rec if value is helper else None):
                    if advance:
                        with self.assertRaises(client.ClientError) as caught:
                            helper._bind_container_identity(deadline)
                        self.assertEqual(caught.exception.reason, 'cleanup_unconfirmed')
                        helper._command.assert_not_called()
                        self.assertIsNone(helper.container_id)
                    else:
                        helper._bind_container_identity(deadline)
                        self.assertEqual(helper.container_id, 'f' * 64)
            value = rec.record_metadata()
            self.assertEqual(value['runtime_deadline_monotonic'], 1005.)
            self.assertEqual(value['identity_deadline_already_expired_at_entry'], bool(advance))
            self.assertEqual(value['identity_bind_outcome'], 'raised' if advance else 'returned')

    def test_original_capture_five_second_exhaustion_remains_poisoned(self):
        import test_application_launch as fixtures
        fixture = fixtures.LaunchTests(methodName='test_capture_exhausted_daemon_deadline_starts_no_inspection_and_poison_blocks_retry')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.test_capture_exhausted_daemon_deadline_starts_no_inspection_and_poison_blocks_retry()


class FlushTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.reports = self.root / 'reports'
        self.reports.mkdir(mode=0o700)
        self.folder = self.reports / 'controlled-cell'
        self.folder.mkdir(mode=0o700)
        self.sources = {}
        for name in timing.SOURCE_PATHS:
            path = self.root / (name + '.py')
            path.write_text('public controlled source\n')
            self.sources[name] = path
        diagnostic = self.root / 'startup-diagnostic.py'
        diagnostic.write_text('public distinct diagnostic source\n')
        self.orchestrators = {'qualification': self.sources['orchestrator'],
                              'startup_diagnostic': diagnostic}
        self.patches = [mock.patch.object(timing, 'REPORTS', self.reports),
                        mock.patch.object(timing, 'SOURCE_PATHS', self.sources),
                        mock.patch.object(timing, 'ORCHESTRATOR_PATHS', self.orchestrators)]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in self.sources.items()}
        self.hashes['orchestrator'] = hashlib.sha256(diagnostic.read_bytes()).hexdigest()
        self.identity = {'kind': 'startup_diagnostic', 'scope_id': str(uuid.uuid4()),
                         'cell_id': 'startup-diagnostic-001', 'launch_id': str(uuid.uuid4())}
        self.rec = timing.Recorder(clock=lambda: 1000.)
        self.rec.emit('guard_enter')

    def flush(self, **kwargs):
        return timing.flush_terminal(kwargs.pop('directory', self.folder), kwargs.pop('recorder', self.rec),
            identity=kwargs.pop('identity', self.identity), source_hashes=kwargs.pop('source_hashes', self.hashes))

    def test_only_terminal_fixed_exclusive_private_leaf_and_no_overwrite(self):
        self.assertFalse(self.flush()['written'])
        self.assertEqual(list(self.folder.iterdir()), [])
        self.rec.terminal()
        value = self.flush()
        self.assertTrue(value['written'])
        path = Path(value['path'])
        self.assertEqual(path.name, 'identity-timing-' + self.identity['launch_id'] + '.json')
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        before = path.read_bytes()
        self.assertEqual(hashlib.sha256(before).hexdigest(), value['sha256'])
        self.assertFalse(self.flush()['written'])
        self.assertEqual(path.read_bytes(), before)
        self.assertLessEqual(len(before), timing.MAX_BYTES)

    def test_unavailable_trace_writes_only_fixed_reason_not_private_input(self):
        self.rec.emit('private-key-canary')
        self.rec.terminal()
        value = self.flush()
        self.assertTrue(value['written'])
        self.assertEqual(value['status'], 'timing_unavailable')
        body = Path(value['path']).read_text()
        self.assertNotIn('canary', body)
        self.assertIsNone(json.loads(body)['durations']['guard_prelaunch_seconds'])

    def test_source_hashes_are_actual_fixed_source_not_arbitrary_private_strings(self):
        self.rec.terminal()
        self.assertFalse(self.flush(source_hashes={**self.hashes, 'guard': 'a' * 64})['written'])
        self.sources['guard'].write_text('changed public source\n')
        self.assertFalse(self.flush()['written'])
        self.assertEqual(list(self.folder.iterdir()), [])

    def test_scope_selects_exact_diagnostic_or_qualification_orchestrator(self):
        diagnostic = timing.source_hashes(kind='startup_diagnostic')
        qualified = timing.source_hashes(kind='qualification')
        self.assertEqual(diagnostic, self.hashes)
        self.assertNotEqual(diagnostic['orchestrator'], qualified['orchestrator'])
        self.assertEqual(qualified['orchestrator'], hashlib.sha256(self.sources['orchestrator'].read_bytes()).hexdigest())
        self.assertIsNone(timing.source_hashes(kind='arbitrary-private-path'))
        self.rec.terminal()
        self.assertFalse(self.flush(source_hashes=qualified)['written'])
        value = self.flush()
        self.assertTrue(value['written'])
        self.assertEqual(json.loads(Path(value['path']).read_bytes())['source_hashes'], diagnostic)

    def test_public_or_symlink_parent_and_existing_symlink_leaf_refuse(self):
        self.rec.terminal()
        self.folder.chmod(0o755)
        self.assertFalse(self.flush()['written'])
        self.folder.chmod(0o700)
        alias = self.reports / 'linked'
        alias.symlink_to(self.folder, target_is_directory=True)
        self.assertFalse(self.flush(directory=alias)['written'])
        target = self.root / 'unrelated'
        target.write_bytes(b'unchanged')
        leaf = self.folder / ('identity-timing-' + self.identity['launch_id'] + '.json')
        leaf.symlink_to(target)
        self.assertFalse(self.flush()['written'])
        self.assertEqual(target.read_bytes(), b'unchanged')

    def test_paths_outside_reports_and_noncanonical_or_extra_identity_refuse(self):
        self.rec.terminal()
        for directory in [self.root, str(self.folder) + '/./', self.folder / '..' / 'controlled-cell']:
            self.assertFalse(self.flush(directory=directory)['written'])
        for identity in [{**self.identity, 'arguments': 'private-canary'},
                         {**self.identity, 'launch_id': '../private-canary'},
                         {**self.identity, 'kind': 'private-canary'}]:
            self.assertFalse(self.flush(identity=identity)['written'])
        self.assertEqual(list(self.folder.iterdir()), [])

    def test_unknown_write_error_retains_partial_leaf_and_returns_unavailable(self):
        self.rec.terminal()
        with mock.patch.object(timing.os, 'write', side_effect=OSError('private-canary')):
            value = self.flush()
        self.assertFalse(value['written'])
        self.assertNotIn('canary', json.dumps(value))
        leaves = list(self.folder.iterdir())
        self.assertEqual(len(leaves), 1)
        self.assertEqual(leaves[0].read_bytes(), b'')
        self.assertFalse(self.flush()['written'])

    def test_parent_replacement_during_flush_cannot_write_into_replacement(self):
        self.rec.terminal()
        moved = self.reports / 'moved-owned-directory'
        original = timing.os.write
        def write(fd, body):
            self.folder.rename(moved)
            self.folder.mkdir(mode=0o700)
            return original(fd, body)
        with mock.patch.object(timing.os, 'write', side_effect=write):
            result = self.flush()
        self.assertFalse(result['written'])
        self.assertEqual(list(self.folder.iterdir()), [])
        self.assertEqual(len(list(moved.iterdir())), 1)

    def test_descriptor_close_errors_do_not_escape_flush_or_replace_existing_leaf(self):
        self.rec.terminal()
        real = timing.os.close
        def close(fd):
            real(fd)
            raise OSError('private-close-canary')
        with mock.patch.object(timing.os, 'close', side_effect=close):
            result = self.flush()
        self.assertTrue(result['written'])
        self.assertNotIn('canary', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
