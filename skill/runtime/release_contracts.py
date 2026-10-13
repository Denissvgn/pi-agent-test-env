"""Exact reviewed Pi execution contracts, shared by the host and worker.

Source review admits an interface; live qualification remains separate evidence.
Callers receive copies so task or receipt mutation cannot change the registry.
"""
import copy
import hashlib
import json

COMMON_FLAGS = (
    '--mode', '--provider', '--model', '--tools', '--session-dir', '--session',
    '--session-id', '--no-extensions', '--no-skills', '--no-context-files',
    '--no-prompt-templates', '--no-themes', '--no-approve', '--offline',
)
RELEASES = ('0.87.1', '1.2.0')
_COMMITS = {
    '0.87.1': 'f07218c4d4bbc12bef056a7058c3dd49dfe41abe',
    '1.2.0': '06a466935536f8c9bcacb2d5efc0fc021be1bdff',
}


def contract(release):
    if not isinstance(release, str) or release not in RELEASES:
        raise ValueError(
            f'Selected Pi {release or "unknown"} is unsupported: an exact reviewed '
            'release contract (0.87.1 or 1.2.0) is required. No version/model substitution.')
    return {
        'release': release, 'id': 'pi-json-direct-' + release, 'revision': 1,
        'upstream_commit': _COMMITS[release], 'session_version': 3,
        'completion': 'settled',
        'settlement_aborted': 'required_boolean' if release == '1.2.0' else 'not_declared',
        'required_flags': list(COMMON_FLAGS) + (['--no-mcp'] if release == '1.2.0' else []),
        'extra_cli_flags': ['--no-mcp'] if release == '1.2.0' else [],
        'reasoning_levels': ['off', 'minimal', 'low', 'medium', 'high'],
        'numeric_reasoning_budgets': False, 'sampling': True,
        'fixture_component': {'id': 'fixture-lookup', 'kind': 'pi-extension',
                              'version': '1', 'pi_release': release,
                              'entrypoint': 'fixture-lookup.mjs'},
    }


def identity(release):
    value = contract(release)
    body = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    return {key: value[key] for key in ('release', 'id', 'revision')} | {
        'sha256': hashlib.sha256(body).hexdigest()}


def observed(value):
    """Pi --version emits an exact version, not a substring or release range."""
    if not isinstance(value, str):
        raise ValueError('Missing observed Pi version')
    release = value.strip()
    contract(release)
    return release


def image_identity(image, expected=None):
    release = observed(image.get('capabilities', {}).get('pi'))
    if expected is not None and release != contract(expected)['release']:
        raise ValueError(f'Observed Pi {release} differs from explicitly selected Pi {expected}')
    return identity(release)


def validate_binding(value, release):
    if (not isinstance(value, dict) or set(value) != {'release', 'id', 'revision', 'sha256'}
            or type(value.get('revision')) is not int
            or any(not isinstance(value.get(key), str) for key in ('release', 'id', 'sha256'))
            or value != identity(release)):
        raise ValueError('Pi release-contract identity mismatch; no cross-release continuation')
    return copy.deepcopy(value)


def snapshot():
    return {release: identity(release) for release in RELEASES}
