"""Real local flock/signal boundaries; no Docker, endpoint, keys or participant."""
import contextlib
import fcntl
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'skill/scripts'))
import ownership_registry
import resources


class QueuedAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.handler = signal.getsignal(signal.SIGALRM)
        self.timer = signal.getitimer(signal.ITIMER_REAL)
        self.mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        self.assertEqual(self.timer, (0.0, 0.0))
        self.assertNotIn(signal.SIGALRM, self.mask)
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name)/'lease'
        self.children = []

    def tearDown(self):
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, self.handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, self.mask)
        for child in self.children:
            if child.poll() is None:
                child.terminate()
            child.communicate(timeout=3)
        self.temporary.cleanup()

    def holder(self, duration=3):
        code = ('import fcntl,sys,time\n'
                'with open(sys.argv[1],"a+") as h:\n'
                ' fcntl.flock(h,fcntl.LOCK_EX)\n'
                ' print("held",flush=True)\n'
                ' time.sleep(float(sys.argv[2]))\n')
        child = subprocess.Popen([sys.executable, '-I', '-B', '-c', code,
                                  str(self.path), str(duration)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.children.append(child)
        self.assertEqual(child.stdout.readline(), 'held\n')
        return child

    def assert_restored(self, handler):
        self.assertIs(signal.getsignal(signal.SIGALRM), handler)
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), self.mask)

    def test_kernel_queue_acquires_once_same_fd_and_registry_custody(self):
        child = self.holder(.12)
        original = resources.fcntl.flock
        calls = []
        def observed(fd, operation):
            calls.append((fd, operation))
            return original(fd, operation)
        with mock.patch.object(resources.fcntl, 'flock', side_effect=observed):
            with resources.admission_lock(self.path, .8) as registry:
                self.assertIs(ownership_registry.CURRENT.get(), registry)
                self.assertEqual(registry.lease_fd, calls[0][0])
                with self.assertRaises(BlockingIOError), self.path.open('a+') as other:
                    original(other, fcntl.LOCK_EX|fcntl.LOCK_NB)
        self.assertIsNone(ownership_registry.CURRENT.get())
        self.assertEqual([operation for _, operation in calls], [fcntl.LOCK_EX, fcntl.LOCK_UN])
        self.assertEqual(child.wait(timeout=1), 0)
        self.assert_restored(self.handler)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0, 0))

    def test_timeout_closes_fd_without_later_acquisition(self):
        child = self.holder(.2)
        started = time.monotonic()
        with self.assertRaises(resources.AdmissionError) as caught:
            with resources.admission_lock(self.path, .05):
                self.fail('expired waiter entered')
        self.assertEqual(caught.exception.reason, 'host-admission-busy')
        self.assertLess(time.monotonic()-started, .18)
        child.wait(timeout=1)
        with resources.admission_lock(self.path):
            pass
        self.assert_restored(self.handler)

    def test_earlier_outer_error_propagates_same_instance(self):
        self.holder()
        for error in (RuntimeError('outer'), OSError('outer'), KeyboardInterrupt()):
            with self.subTest(kind=type(error).__name__):
                def outer(_signum, _frame):
                    raise error
                signal.signal(signal.SIGALRM, outer)
                signal.setitimer(signal.ITIMER_REAL, .03)
                with self.assertRaises(type(error)) as caught:
                    with resources.admission_lock(self.path, .3):
                        self.fail('outer expired')
                self.assertIs(caught.exception, error)
                self.assert_restored(outer)
                self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0, 0))

    def test_later_outer_deadline_not_reset_by_inner_timeout(self):
        self.holder()
        events = []
        def outer(_signum, _frame):
            events.append(time.monotonic())
        signal.signal(signal.SIGALRM, outer)
        started = time.monotonic()
        signal.setitimer(signal.ITIMER_REAL, .18)
        with self.assertRaises(resources.AdmissionError):
            with resources.admission_lock(self.path, .05):
                self.fail('busy')
        remaining, interval = signal.getitimer(signal.ITIMER_REAL)
        self.assertGreater(remaining, .05)
        self.assertLess(remaining, .16)
        self.assertEqual(interval, 0)
        self.assert_restored(outer)
        time.sleep(.2)
        self.assertEqual(len(events), 1)
        self.assertLess(events[0]-started, .23)

    def test_success_preserves_outer_timer_inside_body(self):
        self.holder(.05)
        events = []
        def outer(_signum, _frame):
            events.append(time.monotonic())
        signal.signal(signal.SIGALRM, outer)
        started = time.monotonic()
        signal.setitimer(signal.ITIMER_REAL, .17)
        with resources.admission_lock(self.path, .5):
            self.assert_restored(outer)
            time.sleep(.2)
            self.assertEqual(len(events), 1)
            self.assertLess(events[0]-started, .22)

    def test_returning_earlier_outer_callback_fires_once(self):
        self.holder()
        events = []
        def outer(_signum, _frame):
            events.append(True)
        signal.signal(signal.SIGALRM, outer)
        signal.setitimer(signal.ITIMER_REAL, .025)
        with self.assertRaises(resources.AdmissionError) as caught:
            with resources.admission_lock(self.path, .08):
                self.fail('busy')
        self.assertEqual(caught.exception.reason, 'host-admission-busy')
        self.assertEqual(events, [True])
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0, 0))
        self.assert_restored(outer)

    def test_acquisition_restore_race_delivers_outer_before_body(self):
        error = RuntimeError('outer restore')
        def outer(_signum, _frame):
            raise error
        signal.signal(signal.SIGALRM, outer)
        original = resources.fcntl.flock
        def delayed(fd, operation):
            original(fd, operation)
            if operation == fcntl.LOCK_EX:
                signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
                time.sleep(.04)
        signal.setitimer(signal.ITIMER_REAL, .02)
        with mock.patch.object(resources.fcntl, 'flock', side_effect=delayed):
            with self.assertRaises(RuntimeError) as caught:
                with resources.admission_lock(self.path, .4):
                    self.fail('expired outer entered body')
        self.assertIs(caught.exception, error)
        self.assert_restored(outer)
        with resources.admission_lock(self.path):
            pass

    def test_sigint_interrupt_preserves_outer_and_does_not_acquire_later(self):
        child = self.holder(.15)
        def outer(_signum, _frame):
            self.fail('later outer should not fire')
        signal.signal(signal.SIGALRM, outer)
        signal.setitimer(signal.ITIMER_REAL, .8)
        interrupt = threading.Timer(.03, lambda: os.kill(os.getpid(), signal.SIGINT))
        interrupt.start()
        try:
            with self.assertRaises(KeyboardInterrupt):
                with resources.admission_lock(self.path, .5):
                    self.fail('interrupted waiter entered')
        finally:
            interrupt.cancel(); interrupt.join()
        self.assert_restored(outer)
        self.assertGreater(signal.getitimer(signal.ITIMER_REAL)[0], .5)
        signal.setitimer(signal.ITIMER_REAL, 0)
        child.wait(timeout=1)
        with resources.admission_lock(self.path):
            pass

    def test_unsafe_contexts_never_call_blocking_flock(self):
        def outer(_signum, _frame):
            pass
        for kind in ('periodic', 'ignored', 'blocked', 'interrupt_blocked', 'pending', 'thread'):
            with self.subTest(kind=kind):
                signal.signal(signal.SIGALRM, outer)
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.pthread_sigmask(signal.SIG_SETMASK, self.mask)
                stack = contextlib.ExitStack()
                if kind == 'periodic': signal.setitimer(signal.ITIMER_REAL, 5, 1)
                if kind == 'ignored':
                    signal.signal(signal.SIGALRM, signal.SIG_IGN)
                    signal.setitimer(signal.ITIMER_REAL, 5)
                if kind == 'blocked': signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
                if kind == 'interrupt_blocked': signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
                if kind == 'pending': stack.enter_context(mock.patch.object(signal, 'sigpending', return_value={signal.SIGALRM}))
                if kind == 'thread': stack.enter_context(mock.patch.object(resources.threading, 'current_thread', return_value=object()))
                with stack, mock.patch.object(resources.fcntl, 'flock') as flock:
                    with self.assertRaises(resources.AdmissionError) as caught:
                        with resources.admission_lock(self.path, .1):
                            self.fail('unsafe context entered')
                    self.assertEqual(caught.exception.reason, 'admission-lock-unavailable')
                    flock.assert_not_called()
                signal.setitimer(signal.ITIMER_REAL, 0)
        signal.pthread_sigmask(signal.SIG_SETMASK, self.mask)

    def test_interrupt_at_restore_entry_still_restores_timer_handler_and_fd(self):
        self.interrupted_mask_boundary(2)

    def test_interrupt_at_install_entry_restores_original_mask_and_timer(self):
        self.interrupted_mask_boundary(1)

    def interrupted_mask_boundary(self, fail_at):
        def outer(_signum, _frame):
            self.fail('later outer should not fire')
        signal.signal(signal.SIGALRM, outer)
        signal.setitimer(signal.ITIMER_REAL, .8)
        original = signal.pthread_sigmask
        blocks = []
        error = KeyboardInterrupt()
        def interrupt_once(operation, mask):
            result = original(operation, mask)
            if operation == signal.SIG_BLOCK and signal.SIGALRM in mask:
                blocks.append(True)
                if len(blocks) == fail_at:
                    raise error
            return result
        with mock.patch.object(signal, 'pthread_sigmask', side_effect=interrupt_once):
            with self.assertRaises(KeyboardInterrupt) as caught:
                with resources.admission_lock(self.path, .3):
                    self.fail('interrupted restoration entered body')
        self.assertIs(caught.exception, error)
        self.assert_restored(outer)
        self.assertGreater(signal.getitimer(signal.ITIMER_REAL)[0], .5)
        signal.setitimer(signal.ITIMER_REAL, 0)
        with resources.admission_lock(self.path):
            pass

    def test_zero_wait_never_touches_alarm_or_blocking_flock(self):
        child = self.holder()
        with mock.patch.object(signal, 'setitimer', side_effect=AssertionError('timer touched')):
            with self.assertRaises(resources.AdmissionError) as caught:
                with resources.admission_lock(self.path):
                    self.fail('busy')
        self.assertEqual(caught.exception.reason, 'host-admission-busy')
        child.terminate(); child.wait(timeout=1)


if __name__ == '__main__':
    unittest.main()
