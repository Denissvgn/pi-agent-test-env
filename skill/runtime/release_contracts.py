"""Exact reviewed Pi execution contracts, shared by the host and worker.

Each reviewed release is one complete entry in the registry below. Adding a
release means appending an entry that states every field in ENTRY_FIELDS:
nothing is inherited from an earlier release, and check_registry() refuses an
incomplete, malformed or out-of-order table when this module loads. Predecessor
entries are immutable; tests freeze the contract identities that receipts bind.

Source review admits an interface; live qualification remains separate evidence.
Callers receive copies so task or receipt mutation cannot change the registry.
"""
import copy
import hashlib
import json
import re

COMMON_FLAGS = (
    '--mode', '--provider', '--model', '--tools', '--session-dir', '--session',
    '--session-id', '--no-extensions', '--no-skills', '--no-context-files',
    '--no-prompt-templates', '--no-themes', '--no-approve', '--offline',
)
# Every field each entry states. extra_cli_flags are required beyond
# COMMON_FLAGS; transient_retries marks the opt-in endpoint retries as reviewed;
# early_session_file records that Pi can write the session file at the first
# user message, before any assistant output; fixture_profile names the
# fixture-lookup declaration for the release. The *_sources maps pin upstream
# files by SHA-256 at upstream_commit for native_tool_contracts and
# application_runtime_contracts.
ENTRY_FIELDS = {
    'upstream_commit': str, 'revision': int, 'session_version': int, 'settlement_aborted': str,
    'extra_cli_flags': tuple, 'reasoning_levels': tuple, 'numeric_reasoning_budgets': bool,
    'sampling': bool, 'transient_retries': bool, 'early_session_file': bool, 'fixture_profile': str,
    'typebox': dict, 'native_tool_sources': dict, 'application_runtime_sources': dict,
}
SETTLEMENT_SHAPES = ('not_declared', 'required_boolean')

# The reviewed releases, oldest first. Append new releases; never edit a
# predecessor entry, because receipts bind the identities derived from it.
_REVIEWED = {
    '0.87.1': {
        'upstream_commit': 'f07218c4d4bbc12bef056a7058c3dd49dfe41abe',
        'revision': 1,
        'session_version': 3,
        'settlement_aborted': 'not_declared',
        'extra_cli_flags': (),
        'reasoning_levels': ('off', 'minimal', 'low', 'medium', 'high'),
        'numeric_reasoning_budgets': False,
        'sampling': True,
        'transient_retries': False,
        'early_session_file': False,
        'fixture_profile': 'profile.json',
        'typebox': {'version': '1.3.27',
                    'integrity': 'sha512-zu+jc1pcy4UiNThxikUr36f0Rybk9PEeCg/NE6adeWr/SKsdNO4EzZHYRDlv2YCVAfj3Odq3dESSo/jNyoBXzA=='},
        'native_tool_sources': {
            'packages/coding-agent/src/core/tools/read.ts':
                '297d26092979651091f44de8862a6fd55aaf59e7252f8fb8dd3d7cb3f9771518',
            'packages/coding-agent/src/core/tools/write.ts':
                '2ee0a438c24cf83fefd733e349d55a21aa5b633c18934b2c80759fcf14b6f297',
            'packages/coding-agent/src/core/tools/edit.ts':
                '31a368c14cf5437ecac157765660001b16063302d9bd746303d6d1b1dcb5625d',
            'packages/coding-agent/src/core/tools/bash.ts':
                '3f43b6d80b460bd38334975bee2726b5438ee6e54bf52abdb6fc54400aad28d2',
            'packages/coding-agent/src/core/tools/grep.ts':
                '88be3d00217d1a1caf8a9e7bb2b8d2e6d96edfa4b790c2cf76c746ab36b8841b',
            'packages/coding-agent/src/core/tools/find.ts':
                'b06bcae6821a0e9fda1b63be613a7ce28eb0e66e1d01d16564e59e83f9ce10ea',
            'packages/coding-agent/src/core/tools/ls.ts':
                '3d0a5457e4f5b9e9967c44608b76b060374d047e80d6871ecec4459b612cb6a3',
            'packages/coding-agent/src/core/tools/tool-definition-wrapper.ts':
                '98c04e593457dfefdc4160fa84c4e16f1a693adad21672bdf1fbfa4912ef2f8b',
            'packages/coding-agent/src/core/agent-session.ts':
                'e5c020bced4ada5c5e116cbd160f66e111016fc717ae30d79994a45527e7f3d7',
            'packages/coding-agent/package.json':
                '627631b613ba4ca29eba8df793f5280fd20b19f01d73826e9ffda14c15def5dc',
            'package-lock.json':
                '95dbf4d7aa54eebf235edccd6926efac42fbf4e1c6a92c625c9ac706a8b367f7',
            'packages/coding-agent/src/core/tools/index.ts':
                '3c66ea1e03530fb85436ee639f35add8bf72718ac6e76b738a1f41be58a2b472',
            'packages/coding-agent/src/core/sdk.ts':
                'b419cd7aa1515d5f85d68d210daa0d79360a1e8eabe456e96b97857bec0498de',
            'packages/coding-agent/src/cli/args.ts':
                '94d1490f9c0f66ae40482c8fec9a37ab541f92eb813ae859af66ed776da44315',
            'packages/coding-agent/src/main.ts':
                'd5f38460ed5ff89a8822a56bb40d279c08fe00b4d1d501e83cce0faf0b99addd',
            'packages/coding-agent/src/core/tools/truncate.ts':
                '104e61ea602c7f7894097b2771dad8c68de75c5a10ea6222e615c4ad144451c7',
        },
        'application_runtime_sources': {
            'packages/agent/src/agent-loop.ts':
                'c3d99a5b0f24d1e7fde41cbeb2cd7a2f3559aa3e9c1df975abef21d7e0ecd189',
            'packages/agent/src/agent.ts':
                'fad42fdcea126f8b47f01876431def6f866ad72260b1e95d1a10e3acb0b6ddeb',
            'packages/agent/src/types.ts':
                'bc8db50886cdf164c55d636f2755da22b2bf12d9172b1fb7383f37c2fe439fe7',
            'packages/ai/src/utils/validation.ts':
                '460786b57dead200e411b9afec916a5049c96ebcff4da082096456ac06d44fb7',
            'packages/coding-agent/src/core/agent-session.ts':
                'e5c020bced4ada5c5e116cbd160f66e111016fc717ae30d79994a45527e7f3d7',
            'packages/coding-agent/src/core/extensions/runner.ts':
                'bf68eaf27a3e54f1cfc0982554e0598c050fd9a06c8e8b7d6cd2d8e3d8d5990c',
            'packages/coding-agent/src/core/extensions/types.ts':
                '601261b3deee1d61f85c930efed2767d66fe6c8d9637e19f4f53135b5fecf4d1',
        },
    },
    '1.2.0': {
        'upstream_commit': '06a466935536f8c9bcacb2d5efc0fc021be1bdff',
        'revision': 1,
        'session_version': 3,
        'settlement_aborted': 'required_boolean',
        'extra_cli_flags': ('--no-mcp',),
        'reasoning_levels': ('off', 'minimal', 'low', 'medium', 'high'),
        'numeric_reasoning_budgets': False,
        'sampling': True,
        'transient_retries': True,
        'early_session_file': True,
        'fixture_profile': 'profile.pi-1.2.0.json',
        'typebox': {'version': '1.3.27',
                    'integrity': 'sha512-zu+jc1pcy4UiNThxikUr36f0Rybk9PEeCg/NE6adeWr/SKsdNO4EzZHYRDlv2YCVAfj3Odq3dESSo/jNyoBXzA=='},
        'native_tool_sources': {
            'packages/coding-agent/src/core/tools/read.ts':
                'c3c64f7105599455d3066568074796e2ddb143cb210da4981b0eb632aa3d2811',
            'packages/coding-agent/src/core/tools/write.ts':
                '2ee0a438c24cf83fefd733e349d55a21aa5b633c18934b2c80759fcf14b6f297',
            'packages/coding-agent/src/core/tools/edit.ts':
                '31a368c14cf5437ecac157765660001b16063302d9bd746303d6d1b1dcb5625d',
            'packages/coding-agent/src/core/tools/bash.ts':
                'de2b54d4f4bfbb844ce6d8077f63d715f7d8e80079dd9689b561e45b6679c81b',
            'packages/coding-agent/src/core/tools/grep.ts':
                '88be3d00217d1a1caf8a9e7bb2b8d2e6d96edfa4b790c2cf76c746ab36b8841b',
            'packages/coding-agent/src/core/tools/find.ts':
                'b06bcae6821a0e9fda1b63be613a7ce28eb0e66e1d01d16564e59e83f9ce10ea',
            'packages/coding-agent/src/core/tools/ls.ts':
                '3d0a5457e4f5b9e9967c44608b76b060374d047e80d6871ecec4459b612cb6a3',
            'packages/coding-agent/src/core/tools/tool-definition-wrapper.ts':
                'bae3cdd9f2aa21fb168ef42a47584f3b19536c0815ec14d94389af530eef9358',
            'packages/coding-agent/src/core/agent-session.ts':
                'e2bbf746779fbed5a8c36f023842bf271252d1fd6f17f5a32f70a0d1c63f0b65',
            'packages/coding-agent/package.json':
                'd4231a02b6a2ccb357a8e9e420fab9c217490137ade958d4a45a12e169daad0c',
            'package-lock.json':
                'ba5e0b40c10cb67baf8b43c6c64c91fe5b5853c6acdd08674aae60f938479fac',
            'packages/coding-agent/src/core/tools/index.ts':
                '3c66ea1e03530fb85436ee639f35add8bf72718ac6e76b738a1f41be58a2b472',
            'packages/coding-agent/src/core/sdk.ts':
                '61f398403c7510bec849583b2c46272df11ac5aa8d2e24b4ded97a108dd55b28',
            'packages/coding-agent/src/cli/args.ts':
                'ef7b54f02939d2ebc8ec2defcf4c2d9be90fe979c2c74675d970a4dd14aadad3',
            'packages/coding-agent/src/main.ts':
                '7179a903b492b3c9ab42c093029e3dab0d7627981082aa787f1d66ab2b5c7f9d',
            'packages/coding-agent/src/core/tools/truncate.ts':
                '8e4507c3ed7ca7548cf7c2d7f77d07f2ae63a38b756789cbb44e9062db6c8762',
        },
        'application_runtime_sources': {
            'packages/agent/src/agent-loop.ts':
                '28a2b03e34a7e32f004aa851e54d3b5be9dad71c392205614cbc9abdf3a9020a',
            'packages/agent/src/agent.ts':
                '7024a3145a6ebc951a0f030164adb1dfb12d33d6e0dbbac15ef0efda49c87457',
            'packages/agent/src/types.ts':
                '2e116ef60fdaca4e26be5a1ace8d8b47f545d648d365de60b8c9f9d1ba629ee4',
            'packages/ai/src/utils/validation.ts':
                '460786b57dead200e411b9afec916a5049c96ebcff4da082096456ac06d44fb7',
            'packages/coding-agent/src/core/agent-session.ts':
                'e2bbf746779fbed5a8c36f023842bf271252d1fd6f17f5a32f70a0d1c63f0b65',
            'packages/coding-agent/src/core/extensions/runner.ts':
                '3cd6d1ad18e8e4c7adf722aed9291bc64f06e3a7d461755c21e3cba4819f4e5e',
            'packages/coding-agent/src/core/extensions/types.ts':
                'cb54c7a4fedb3473bb995694bbc1f2988c144fb0b802bfd1b656816bc25d0f25',
        },
    },
}


def _version(text):
    match = (re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', text)
             if isinstance(text, str) else None)
    if match is None:
        raise ValueError(f'Reviewed release {text!r} is not an exact X.Y.Z version')
    return tuple(int(part) for part in match.groups())


def check_registry(table):
    """Refuse an incomplete, malformed or unordered release table; return its releases."""
    if type(table) is not dict or not table:
        raise ValueError('The reviewed release registry must be a non-empty table')
    versions = [_version(release) for release in table]
    if versions != sorted(set(versions)):
        raise ValueError('Reviewed releases must be distinct and in ascending version order')
    for release, value in table.items():
        def refuse(field, rule):
            raise ValueError(f'Reviewed Pi {release} entry: {field} {rule}')
        if type(value) is not dict or set(value) != set(ENTRY_FIELDS):
            refuse('fields', 'must be exactly ' + ', '.join(ENTRY_FIELDS))
        for field, kind in ENTRY_FIELDS.items():
            if type(value[field]) is not kind:
                refuse(field, 'must be ' + kind.__name__)
        if not re.fullmatch('[0-9a-f]{40}', value['upstream_commit']):
            refuse('upstream_commit', 'must be a full commit SHA')
        if value['revision'] < 1 or value['session_version'] < 1:
            refuse('revision and session_version', 'must be positive')
        if value['settlement_aborted'] not in SETTLEMENT_SHAPES:
            refuse('settlement_aborted', 'must be one of ' + ', '.join(SETTLEMENT_SHAPES))
        flags, levels = value['extra_cli_flags'], value['reasoning_levels']
        if len(set(flags)) != len(flags) or any(type(flag) is not str or flag in COMMON_FLAGS
                                                or not re.fullmatch('--[a-z][a-z0-9-]*', flag) for flag in flags):
            refuse('extra_cli_flags', 'must be distinct flags beyond COMMON_FLAGS')
        if not levels or len(set(levels)) != len(levels) or any(type(level) is not str for level in levels):
            refuse('reasoning_levels', 'must be distinct level names')
        if not re.fullmatch(r'profile(\.pi-[0-9]+\.[0-9]+\.[0-9]+)?\.json', value['fixture_profile']):
            refuse('fixture_profile', 'must name a fixture-lookup profile declaration')
        if (set(value['typebox']) != {'version', 'integrity'}
                or any(type(text) is not str or not text for text in value['typebox'].values())):
            refuse('typebox', 'must state version and integrity')
        for field in ('native_tool_sources', 'application_runtime_sources'):
            pins = value[field]
            if not pins or any(type(path) is not str or type(digest) is not str
                               or not re.fullmatch(r'[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*', path)
                               or '..' in path.split('/') or not re.fullmatch('[0-9a-f]{64}', digest)
                               for path, digest in pins.items()):
                refuse(field, 'must map relative upstream paths to SHA-256 digests')
    return tuple(table)


RELEASES = check_registry(_REVIEWED)


def describe(releases=None):
    """Reviewed releases as text, such as '0.87.1 or 1.2.0'."""
    names = list(RELEASES if releases is None else releases)
    return names[0] if len(names) == 1 else ', '.join(names[:-1]) + ' or ' + names[-1]


def _selected(release):
    if not isinstance(release, str) or release not in _REVIEWED:
        raise ValueError(
            f'Selected Pi {release or "unknown"} is unsupported: an exact reviewed '
            f'release contract ({describe()}) is required. No version/model substitution.')
    return _REVIEWED[release]


def entry(release):
    """A copy of one reviewed release's complete registry entry."""
    return copy.deepcopy(_selected(release))


def contract(release):
    selected = _selected(release)
    extra = list(selected['extra_cli_flags'])
    return {
        'release': release, 'id': 'pi-json-direct-' + release, 'revision': selected['revision'],
        'upstream_commit': selected['upstream_commit'], 'session_version': selected['session_version'],
        'completion': 'settled', 'settlement_aborted': selected['settlement_aborted'],
        'required_flags': list(COMMON_FLAGS) + extra, 'extra_cli_flags': extra,
        'reasoning_levels': list(selected['reasoning_levels']),
        'numeric_reasoning_budgets': selected['numeric_reasoning_budgets'], 'sampling': selected['sampling'],
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
