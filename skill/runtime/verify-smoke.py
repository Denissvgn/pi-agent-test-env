#!/usr/bin/env python3
"""Trusted verifier: run in a NEW container, with no API key and no network."""
import json
from pathlib import Path

expected = json.loads(Path('/opt/pi-control/challenge.json').read_text())
proof = Path('/workspace/agent-proof.json')
if proof.is_symlink() or not proof.is_file():
    raise SystemExit('FAIL: agent-proof.json must be a regular file, not a symlink')
actual = json.loads(proof.read_text())
assert actual == {'nonce': expected['nonce'], 'sum': expected['a'] + expected['b']}, actual
print('INDEPENDENT_SMOKE_VERIFICATION_OK')
