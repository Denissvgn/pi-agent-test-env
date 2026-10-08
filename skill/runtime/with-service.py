#!/usr/bin/env python3
"""Run a test-only application service, wait for readiness, run tests, and clean up.

Trusted command input only. No Docker socket, host shell, or background server reuse.
"""
import argparse
import json
import os
import signal
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, build_opener


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--start-json', required=True, help='Service argv as a JSON array')
    parser.add_argument('--ready-url', required=True, help='HTTP(S) loopback readiness URL')
    parser.add_argument('--ready-timeout', type=float, default=45)
    parser.add_argument('--test-timeout', type=float, default=300)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    start = json.loads(args.start_json)
    tests = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not isinstance(start, list) or not start or not all(isinstance(x, str) and x and '\x00' not in x for x in start) or not tests:
        parser.error('Provide service argv as an array and test argv after --')
    url = urlsplit(args.ready_url)
    if url.scheme not in ('http', 'https') or url.hostname not in ('localhost', '127.0.0.1', '::1') or url.username or url.password:
        parser.error('readiness must target HTTP(S) loopback, without URL credentials')
    if not (0 < args.ready_timeout <= 600 and 0 < args.test_timeout <= 3600):
        parser.error('Bound readiness to 1..600s and tests to 1..3600s')
    env = dict(os.environ)
    env['TEST_BASE_URL'] = f'{url.scheme}://{url.netloc}'
    client = build_opener(ProxyHandler({}))
    service = subprocess.Popen(start, stdout=sys.stderr, stderr=sys.stderr, start_new_session=True, env=env)
    tester = None
    try:
        deadline = time.monotonic() + args.ready_timeout
        while True:
            if service.poll() is not None:
                raise RuntimeError(f'Service exited before readiness: {service.returncode}')
            try:
                with client.open(args.ready_url, timeout=1) as response:
                    if 200 <= response.status < 300:
                        break
            except (HTTPError, URLError, TimeoutError, OSError):
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError('Service did not become ready before the deadline')
            time.sleep(0.1)
        tester = subprocess.Popen(tests, env=env, start_new_session=True)
        deadline = time.monotonic() + args.test_timeout
        while tester.poll() is None:
            if service.poll() is not None:
                raise RuntimeError(f'Service exited while tests were running: {service.returncode}')
            if time.monotonic() >= deadline:
                raise RuntimeError('Test command exceeded its timeout')
            time.sleep(0.1)
        return tester.returncode
    finally:
        for process in (tester, service):
            if process is None:
                continue
            # Kill surviving members even if the leader already exited.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError) as exc:
        print(f'SERVICE_CHECK_FAILED: {exc}', file=sys.stderr)
        sys.exit(2)
