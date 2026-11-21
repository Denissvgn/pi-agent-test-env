#!/usr/bin/env python3
"""Bounded, synthetic measurements for the release verifier's host."""
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
PHASES = ('interpreter', 'filesystem', 'scheduling', 'raw_bind', 'reverse_lookup', 'resolver_control', 'http_sync', 'http_threaded',
          'scripted', 'alarm', 'lock_timer')


class MeasurementFailure(Exception):
    def __init__(self, records):
        self.records = records


def child(phase):
    import fcntl
    from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
    import signal
    import socket
    import tempfile
    import threading

    records = []
    def measure(name, action):
        start = time.monotonic()
        try:
            action()
        except Exception as exc:
            outcome = 'permission_denied' if isinstance(exc, PermissionError) else 'timeout' if isinstance(exc, TimeoutError) else 'error'
            records.append({'phase': name, 'outcome': outcome, 'elapsed_ms': round((time.monotonic()-start)*1000, 3)})
            raise MeasurementFailure(records) from None
        records.append({'phase': name, 'outcome': 'ok', 'elapsed_ms': round((time.monotonic()-start)*1000, 3)})

    if phase == 'interpreter':
        measure(phase, lambda: None)
    elif phase == 'filesystem':
        with tempfile.TemporaryDirectory() as directory:
            def sync():
                with open(Path(directory)/'fixture', 'wb') as stream:
                    stream.write(b'synthetic'); stream.flush(); os.fsync(stream.fileno())
            measure('filesystem_sync', sync)
    elif phase == 'scheduling':
        event = threading.Event()
        def schedule():
            thread = threading.Thread(target=event.set)
            thread.start(); thread.join()
        measure('thread_schedule', schedule)
    elif phase == 'raw_bind':
        def bind():
            with socket.socket() as sock: sock.bind(('127.0.0.1', 0))
        measure(phase, bind)
    elif phase == 'reverse_lookup':
        measure(phase, lambda: socket.gethostbyaddr('127.0.0.1'))
    elif phase == 'resolver_control':
        # A synthetic resolver delay provides a known comparison with process,
        # filesystem and thread scheduling overhead; it performs no lookup.
        measure(phase, lambda: time.sleep(.05))
    elif phase in ('http_sync', 'http_threaded'):
        cls = HTTPServer if phase == 'http_sync' else ThreadingHTTPServer
        def server():
            instance = cls(('127.0.0.1', 0), BaseHTTPRequestHandler)
            instance.server_close()
        measure(phase, server)
    elif phase == 'scripted':
        sys.path.insert(0, str(ROOT / 'tools/qualification'))
        import application_scripted as script
        config = {'schema': 1, 'document_type': 'application_scripted_bootstrap',
                  'case_id': 'reporting-and-reserve', 'model': 'application-script-a',
                  'inference_key': 'synthetic-scripted-inference-key-123456789', 'lifetime_seconds': 30}
        with tempfile.TemporaryDirectory() as directory:
            holder = []
            measure('scripted_construct', lambda: holder.append(script.ScriptedServer(config, Path(directory).resolve()/'observations.json')))
            instance = holder[0]
            try:
                measure('scripted_sync', instance._note)
                measure('scripted_start', instance.start)
            finally:
                measure('scripted_stop', instance.stop)
    elif phase == 'alarm':
        previous = signal.getsignal(signal.SIGALRM)
        fired = threading.Event()
        signal.signal(signal.SIGALRM, lambda *_: fired.set())
        try:
            signal.setitimer(signal.ITIMER_REAL, .05)
            measure('alarm_delivery', lambda: fired.wait(.5) or (_ for _ in ()).throw(TimeoutError()))
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
    elif phase == 'lock_timer':
        sys.path.insert(0, str(ROOT / 'skill/scripts'))
        import resources
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'lease'
            with path.open('w') as held:
                fcntl.flock(held, fcntl.LOCK_EX)
                previous = signal.getsignal(signal.SIGALRM)
                fired = []
                signal.signal(signal.SIGALRM, lambda *_: fired.append(time.monotonic()))
                started = time.monotonic()
                deadline = started + .18
                records.append({'phase': 'requested_outer_deadline', 'outcome': 'ok', 'elapsed_ms': 180.0})
                signal.setitimer(signal.ITIMER_REAL, .18)
                try:
                    def acquire():
                        try:
                            with resources.admission_lock(path, .05): pass
                        except resources.AdmissionError: return
                        raise RuntimeError()
                    measure('lock_timeout', acquire)
                    remaining, interval = signal.getitimer(signal.ITIMER_REAL)
                    records.append({'phase': 'restored_deadline_offset', 'outcome': 'ok' if remaining > 0 and interval == 0 else 'error',
                                    'elapsed_ms': round((time.monotonic()+remaining-deadline)*1000, 3)})
                    measure('outer_callback', lambda: time.sleep(.25))
                    records.append({'phase': 'callback_from_requested_deadline', 'outcome': 'ok' if len(fired) == 1 else 'error',
                                    'elapsed_ms': round(((fired[0] if fired else time.monotonic())-deadline)*1000, 3)})
                finally:
                    def cleanup():
                        signal.setitimer(signal.ITIMER_REAL, 0)
                        signal.signal(signal.SIGALRM, previous)
                        fcntl.flock(held, fcntl.LOCK_UN)
                        if signal.getsignal(signal.SIGALRM) != previous or signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
                            raise RuntimeError()
                    measure('lock_cleanup', cleanup)
            def verify_closed():
                if not held.closed: raise RuntimeError()
                with path.open('w') as probe:
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(probe, fcntl.LOCK_UN)
            measure('lock_fd_cleanup', verify_closed)
    return records


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--child':
        started = time.monotonic()
        try:
            print(json.dumps(child(sys.argv[2])))
        except MeasurementFailure as exc:
            print(json.dumps(exc.records))
        except Exception:
            print(json.dumps([{'phase': sys.argv[2], 'outcome': 'error', 'elapsed_ms': round((time.monotonic()-started)*1000, 3)}]))
        return
    measurements = []
    for phase in PHASES:
        started = time.monotonic()
        try:
            command = [sys.executable, '-B', '-c', 'pass'] if phase == 'interpreter' else [sys.executable, '-B', __file__, '--child', phase]
            result = subprocess.run(command,
                                    capture_output=True, text=True, timeout=5, check=False)
            elapsed = round((time.monotonic()-started)*1000, 3)
            measurements.append({'phase': phase+'_process', 'outcome': 'ok' if result.returncode == 0 else 'error', 'elapsed_ms': elapsed})
            if phase == 'interpreter':
                continue
            try:
                measurements.extend(json.loads(result.stdout))
            except (ValueError, TypeError):
                measurements.append({'phase': phase, 'outcome': 'invalid_output', 'elapsed_ms': elapsed})
        except subprocess.TimeoutExpired:
            measurements.append({'phase': phase, 'outcome': 'timeout', 'elapsed_ms': round((time.monotonic()-started)*1000, 3)})
    output = {'platform': {'python': platform.python_version(), 'os': platform.system(),
                           'os_version': platform.release(), 'architecture': platform.machine()},
              'measurements': measurements}
    Path(sys.argv[1]).write_text(json.dumps(output, indent=2)+'\n', encoding='utf-8')


if __name__ == '__main__':
    main()
