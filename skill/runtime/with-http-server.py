#!/usr/bin/env python3
"""Serve static test files on loopback while a trusted test command runs."""
import argparse
import functools
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import os
import subprocess
import threading

p = argparse.ArgumentParser()
p.add_argument('--port', type=int, default=4173)
p.add_argument('--root', default='/workspace')
p.add_argument('command', nargs=argparse.REMAINDER)
a = p.parse_args()
cmd = a.command[1:] if a.command[:1] == ['--'] else a.command
if not cmd:
    p.error('A test command is required after --')
handler = functools.partial(SimpleHTTPRequestHandler, directory=a.root)
server = ThreadingHTTPServer(('127.0.0.1', a.port), handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
env = dict(os.environ)
env['TEST_BASE_URL'] = f'http://127.0.0.1:{server.server_port}'
try:
    result = subprocess.run(cmd, env=env, check=False)
finally:
    server.shutdown()
    server.server_close()
raise SystemExit(result.returncode)
