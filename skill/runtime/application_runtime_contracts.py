"""Separate application/compiler identities; predecessor release contracts are immutable.

Source-reviewed callback support is not runtime qualification or dispatch authority.
"""
import copy
import hashlib
import json
import re
import release_contracts

SOURCE_PINS = {'0.87.1': {'packages/agent/src/agent-loop.ts': 'c3d99a5b0f24d1e7fde41cbeb2cd7a2f3559aa3e9c1df975abef21d7e0ecd189',
            'packages/agent/src/agent.ts': 'fad42fdcea126f8b47f01876431def6f866ad72260b1e95d1a10e3acb0b6ddeb',
            'packages/agent/src/types.ts': 'bc8db50886cdf164c55d636f2755da22b2bf12d9172b1fb7383f37c2fe439fe7',
            'packages/ai/src/utils/validation.ts': '460786b57dead200e411b9afec916a5049c96ebcff4da082096456ac06d44fb7',
            'packages/coding-agent/src/core/agent-session.ts': 'e5c020bced4ada5c5e116cbd160f66e111016fc717ae30d79994a45527e7f3d7',
            'packages/coding-agent/src/core/extensions/runner.ts': 'bf68eaf27a3e54f1cfc0982554e0598c050fd9a06c8e8b7d6cd2d8e3d8d5990c',
            'packages/coding-agent/src/core/extensions/types.ts': '601261b3deee1d61f85c930efed2767d66fe6c8d9637e19f4f53135b5fecf4d1'},
 '1.2.0': {'packages/agent/src/agent-loop.ts': '28a2b03e34a7e32f004aa851e54d3b5be9dad71c392205614cbc9abdf3a9020a',
           'packages/agent/src/agent.ts': '7024a3145a6ebc951a0f030164adb1dfb12d33d6e0dbbac15ef0efda49c87457',
           'packages/agent/src/types.ts': '2e116ef60fdaca4e26be5a1ace8d8b47f545d648d365de60b8c9f9d1ba629ee4',
           'packages/ai/src/utils/validation.ts': '460786b57dead200e411b9afec916a5049c96ebcff4da082096456ac06d44fb7',
           'packages/coding-agent/src/core/agent-session.ts': 'e2bbf746779fbed5a8c36f023842bf271252d1fd6f17f5a32f70a0d1c63f0b65',
           'packages/coding-agent/src/core/extensions/runner.ts': '3cd6d1ad18e8e4c7adf722aed9291bc64f06e3a7d461755c21e3cba4819f4e5e',
           'packages/coding-agent/src/core/extensions/types.ts': 'cb54c7a4fedb3473bb995694bbc1f2988c144fb0b802bfd1b656816bc25d0f25'}}


def compiler_contract():
    return {'id': 'application-plan-v1', 'revision': 1,
            'source': 'application_plan_source', 'execution': 'application_execution_plan',
            'schema': 1, 'json': 'strict-finite-no-coercion',
            'canonicalization': 'utf8-sorted-keys-preserved-arrays',
            'stage_failure_policy': 'stop-remaining-stages',
            'max_stages': 8, 'max_checks': 20, 'max_prompt_bytes': 131072}


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def compiler_identity():
    value = compiler_contract()
    return {'id': value['id'], 'revision': value['revision'], 'sha256': _digest(value)}


def contract(release):
    selected = release_contracts.contract(release)
    return {'schema': 1, 'id': 'application-client-direct-' + release, 'revision': 1,
            'release': release, 'upstream_commit': selected['upstream_commit'],
            'legacy_release_identity': release_contracts.identity(release),
            'compiler': compiler_identity(),
            'native_adapter': 'assistant-batch-reservation-plus-native-effect-gate-v1',
            'declaration_boundary': 'awaited-extension-message_end',
            'effect_boundary': 'tool_call-and-helper-one-use-grant',
            'argument_policy': 'strict-raw-before-native-coercion',
            'prepare_arguments': 'absent-or-reviewed-pure',
            'nested_tools': False,
            'source_pins': copy.deepcopy(SOURCE_PINS[release])}


def identity(release):
    value = contract(release)
    return {key: value[key] for key in ('id', 'revision', 'release')} | {'sha256': _digest(value)}


def profile_component(release):
    """Exact separate reviewed extension component; legacy identities stay fixed."""
    release_contracts.contract(release)
    return {'id': 'application-client', 'kind': 'pi-extension', 'version': '1',
            'pi_release': release, 'entrypoint': 'application-client.mjs'}


APPLICATION_EXTENSION_PATHS = ('/opt/pi-lab/workspace-boundary.mjs',
    '/opt/pi-lab/profile-monitor.mjs', '/opt/pi-profile/application-client.mjs',
    '/opt/pi-lab/tool-budget.mjs')


def extension_identity(release, profile_binding, tool_schema_sha256, file_sha256):
    """Pure identity of ordered app extensions, including the imported guard.

    SHA-256 uses sorted compact JSON (ensure_ascii=True), as _digest above.
    Callers hash actual admitted bytes at each exact APPLICATION_EXTENSION_PATHS
    path. The initializer imports the last guard; it is not loaded a second time.
    """
    selected = identity(release)
    valid = lambda value: type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None
    if (type(profile_binding) is not dict or set(profile_binding) != {'id','pi_release','sha256','assets'}
            or profile_binding['id'] != 'application-client' or profile_binding['pi_release'] != release
            or not valid(profile_binding['sha256']) or type(profile_binding['assets']) is not dict
            or set(profile_binding['assets']) != {'application-client.mjs','instructions.md'}
            or not all(valid(value) for value in profile_binding['assets'].values())
            or not valid(tool_schema_sha256) or type(file_sha256) is not dict
            or set(file_sha256) != set(APPLICATION_EXTENSION_PATHS)
            or not all(valid(value) for value in file_sha256.values())):
        raise ValueError('Invalid application extension identity')
    value = {'schema':1,'id':'application-extension-order-v1','revision':1,
             'release_contract':selected,'profile_binding':copy.deepcopy(profile_binding),
             'tool_schema_sha256':tool_schema_sha256,
             'ordered_extensions':[{'path':path,'sha256':file_sha256[path]} for path in APPLICATION_EXTENSION_PATHS]}
    return {'id':value['id'],'revision':value['revision'],'release':release,'sha256':_digest(value)}
