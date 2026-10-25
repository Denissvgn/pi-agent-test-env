"""Guard/identity recorder composition with durable fake registries only.

No Docker, Pi, model, endpoint, host operation lease or actual private store.
"""
import gc
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest import mock
import uuid
import weakref

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'skill/scripts'), str(ROOT/'skill/runtime'), str(ROOT/'tools/qualification')]
import application_client as runtime
import application_launch as launch
import application_timing as timing
import ownership_registry
import test_application_launch as fixtures


class TimingIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.LaunchTests(methodName='test_scoped_global_run_and_captured_helper_delegate_are_counted_once_and_preserved')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.f = self.fixture

    def intent(self):
        argv = self.f.argv()
        argv[-2:] = ['/opt/pi-application/runtime/application_client_service.py', '--port']
        for option, value in (('--memory', '512m'), ('--memory-swap', '512m'), ('--pids-limit', '128')):
            argv[argv.index(option)+1] = value
        return runtime._intent(self.f.registry, argv, argv[argv.index('--name')+1], self.f.image,
                               self.f.root/'private/helper', {}, {}, 'application-execution')

    def instrument(self):
        return launch.instrument(self.f.ledger, 'cell-a', registry_getter=lambda: self.f.registry,
                                 original_popen=self.f.executor, command=self.f.command)

    def test_helper_delegate_once_original_deadline_and_no_critical_path_flush(self):
        record, argv = self.intent()
        calls = []
        sentinel = object()
        def bind(helper, deadline):
            calls.append((helper, deadline))
            return sentinel
        def start(cls, *, popen=self.f.executor):
            process = popen(argv, stdin=subprocess.PIPE, start_new_session=True)
            helper = object.__new__(cls)
            helper.record = dict(record)
            self.assertIs(helper._bind_container_identity(1005.0), sentinel)
            return helper, process
        with mock.patch.object(runtime.OwnedHelper, '_bind_container_identity', bind), \
             mock.patch.object(runtime.OwnedHelper, 'start', classmethod(start)), \
             mock.patch.object(timing, 'flush_terminal') as flush:
            with self.instrument() as guard:
                helper, process = runtime.OwnedHelper.start()
                self.assertEqual(calls, [(helper, 1005.0)])
                self.assertEqual(len(self.f.effects), 1)
                self.assertEqual(self.f.ledger.snapshot()['attempts'], 1)
                self.assertTrue(self.f.effects[0][2]['start_new_session'])
                recorder = guard.recorder_for_helper(helper)
                self.assertIs(recorder, guard._timings[record['launch_id']])
                self.assertEqual(recorder.record_metadata()['runtime_deadline_monotonic'], 1005.0)
                self.assertFalse(recorder.record_metadata()['terminal'])
                self.assertEqual(recorder.record_metadata()['identity_bind_outcome'], 'returned')
                flush.assert_not_called()
            flush.assert_not_called()

    def test_timeout_aware_observations_preserve_original_capture_slice(self):
        calls=[]
        guard=launch.LaunchGuard(self.f.ledger,'cell-a',lambda:self.f.registry,
            self.f.executor,self.f.command,lambda argv,timeout:(calls.append((argv,timeout)),self.f.command(argv))[1])
        guard._observe(['docker','info'],.125)
        self.assertEqual(calls,[(['docker','info'],.125)])

    def test_recorders_select_registered_helper_identity_and_ignore_other_helpers(self):
        record, argv = self.intent()
        guard = self.f.guard()
        guard.popen(argv)
        selected = types.SimpleNamespace(record=dict(record))
        self.assertIs(guard.recorder_for_helper(selected), guard._timings[record['launch_id']])
        for helper in (types.SimpleNamespace(record={**record, 'launch_id': str(uuid.uuid4())}),
                       types.SimpleNamespace(record=None), types.SimpleNamespace(record=[]), object()):
            self.assertIsNone(guard.recorder_for_helper(helper))
        self.assertEqual(len(guard._timings), 1)

    def test_guard_does_not_hold_completed_popen_object_for_timing(self):
        _, argv = self.intent()
        guard = self.f.guard()
        process = guard.popen(argv)
        observed = weakref.ref(process)
        del process
        gc.collect()
        self.assertIsNone(observed())
        self.assertTrue(all(type(recorder) is timing.Recorder for recorder in guard._timings.values()))
        self.assertEqual(self.f.ledger.snapshot()['attempts'], 1)

    def test_helper_original_error_or_cancel_preserved_hooks_restored_and_scope_poisoned(self):
        for original_error in (ValueError('controlled-primary'), KeyboardInterrupt(), SystemExit(2)):
            with self.subTest(kind=type(original_error).__name__):
                # Each failing scope has its own durable inert ledger/registry.
                if self.f.ledger.snapshot()['attempts']:
                    self.f.doCleanups()
                    self.f.setUp()
                record, argv = self.intent()
                def bind(helper, deadline):
                    self.assertEqual(deadline, 1005.0)
                    raise original_error
                def start(cls, *, popen=self.f.executor):
                    popen(argv)
                    helper = object.__new__(cls)
                    helper.record = dict(record)
                    return helper._bind_container_identity(1005.0)
                popen_before = subprocess.Popen
                confirm_before = ownership_registry.Registry.confirm_absent
                release_before = ownership_registry.Registry.release
                with mock.patch.object(runtime.OwnedHelper, '_bind_container_identity', bind), \
                     mock.patch.object(runtime.OwnedHelper, 'start', classmethod(start)):
                    start_before = runtime.OwnedHelper.__dict__['start']
                    with self.assertRaises(BaseException) as caught:
                        with self.instrument() as guard:
                            runtime.OwnedHelper.start()
                    self.assertIs(caught.exception, original_error)
                    self.assertIs(runtime.OwnedHelper._bind_container_identity, bind)
                    self.assertIs(runtime.OwnedHelper.__dict__['start'], start_before)
                    self.assertIs(subprocess.Popen, popen_before)
                    self.assertIs(ownership_registry.Registry.confirm_absent, confirm_before)
                    self.assertIs(ownership_registry.Registry.release, release_before)
                self.assertTrue(self.f.ledger.snapshot()['poisoned'])
                self.assertEqual(len(self.f.effects), 1)
                self.assertEqual(guard._timings[record['launch_id']].record_metadata()['identity_bind_outcome'], 'raised')
                self.assertTrue(launch._PATCH_LOCK.acquire(blocking=False))
                launch._PATCH_LOCK.release()

    def test_explicit_terminal_flush_is_deferred_and_scope_identity_bound(self):
        record, argv = self.intent()
        guard = self.f.guard()
        guard.popen(argv)
        recorder = guard._timings[record['launch_id']]
        self.assertFalse(recorder.record_metadata()['terminal'])
        hashes = {'guard': 'a'*64, 'runtime': 'b'*64, 'orchestrator': 'c'*64}
        with mock.patch.object(timing, 'source_hashes', return_value=hashes) as source, \
             mock.patch.object(timing, 'flush_terminal', return_value={'status': 'recorded', 'written': True}) as flush:
            directory = self.f.root/'terminal-evidence'
            value = guard.flush_timings(directory, kind='startup_diagnostic')
        self.assertTrue(recorder.record_metadata()['terminal'])
        source.assert_called_once_with(kind='startup_diagnostic')
        flush.assert_called_once_with(directory, recorder, identity={'kind':'startup_diagnostic',
            'scope_id':self.f.policy['qualification_id'], 'cell_id':'cell-a', 'launch_id':record['launch_id']}, source_hashes=hashes)
        self.assertEqual(value, [{'status':'recorded', 'written':True}])
        self.assertEqual(self.f.ledger.snapshot()['attempts'], 1)

    def test_delegate_error_keeps_original_exception_and_uncertain_charged_slot(self):
        record, argv = self.intent()
        primary = OSError('controlled-delegate-failure')
        guard = self.f.guard()
        guard.original_popen = mock.Mock(side_effect=primary)
        with self.assertRaises(OSError) as caught:
            guard.popen(argv)
        self.assertIs(caught.exception, primary)
        guard.original_popen.assert_called_once()
        snapshot = self.f.ledger.snapshot()
        self.assertEqual((snapshot['attempts'], snapshot['live']), (1, 1))
        self.assertTrue(snapshot['poisoned'])
        metadata = guard._timings[record['launch_id']].record_metadata()
        self.assertEqual(metadata['events'][-1], {'event':'guard_failed', 'status':'raised',
            'monotonic':metadata['events'][-1]['monotonic']})
        self.assertFalse(metadata['terminal'])
        self.assertFalse(metadata['native_success_attested'])

    def test_worker_dispatch_stays_uninstrumented_and_identical(self):
        _, argv = self.f.intent('probe')
        guard = self.f.guard()
        process = guard.popen(argv)
        self.assertEqual(process.pid, 101)
        self.assertEqual(guard._timings, {})
        self.assertIs(self.f.effects[0][0], argv)
        self.assertEqual(self.f.ledger.snapshot()['attempts'], 1)


if __name__ == '__main__':
    unittest.main()
