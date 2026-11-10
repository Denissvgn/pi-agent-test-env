"""Separate application/compiler identities; predecessor release contracts are immutable.

Source-reviewed callback support is not runtime qualification or dispatch authority.
"""
import copy
import hashlib
import json
import re
import release_contracts

# Each release's upstream source pins live in the release_contracts registry.
SOURCE_PINS = {release: release_contracts.entry(release)['application_runtime_sources']
               for release in release_contracts.RELEASES}


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
