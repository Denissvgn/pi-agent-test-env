"""Pure closed SDK admission. An externally trusted digest is a required input.

This compiler observes no filesystem, process, private value or authority. Its
output permits only the selected source mechanics to proceed to native gates.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import PurePosixPath
import re
import uuid


OPERATIONS = frozenset(('plan_validate_source_v1', 'plan_validate_ir_v1', 'plan_validate_legacy_v1', 'plan_check_project_v1',
                        'redact_bytes_v1', 'credentials_collect_v1', 'secret_register_create_only_v1',
                        'resource_read_v1'))
CONSUMER_FILES = frozenset(('__init__.py', 'policy.py', 'wire.py', 'client.py', 'worker.py',
                           'source.py', 'collect.py', 'runtime.py', 'state.py', 'secret_registration_contract.py',
                           'secret_registration_primitive.py', 'secret_registration_posix.py'))
LIMITS = dict(max_control_bytes=(512, 1048576), max_payload_bytes=(0, 16777216),
    max_result_bytes=(512, 33554432), failure_reserve_bytes=(512, 65536), max_read_refs=(0, 128),
    max_ref_bytes=(16, 16384), max_read_bytes=(0, 2097152), max_pattern_count=(0, 4096),
    max_pattern_bytes=(0, 8388608), max_regex_bytes=(0, 16777216), max_owned_fds=(8, 48),
    max_mutating_calls=(1, 4096), max_runtime_millis=(100, 60000),
    max_memory_bytes=(67108864, 536870912), max_pids=(2, 128), max_cpu_millis=(1000, 60000), max_cpu_millicores=(1, 1000),
    max_source_files=(1, 4096), max_source_file_bytes=(1, 67108864), max_source_bytes=(1, 134217728),
    max_runtime_modules=(1, 512), max_native_libraries=(1, 64),
    max_dependency_file_bytes=(0, 16777216), max_dependency_bytes=(0, 67108864),
    max_secret_bytes=(1, 16384), max_plan_agents=(1, 8), max_plan_checks=(1, 20),
    max_plan_setup=(0, 20), max_prompt_bytes=(1, 131072), max_scorer_assets=(0, 640))
PRIVATE_OPERATIONS = frozenset(('redact_bytes_v1', 'credentials_collect_v1', 'secret_register_create_only_v1'))


class PolicyError(ValueError):
    """A fixed reason; never interpolate a private path, value or parser body."""


def require(value, reason='policy_invalid'):
    if not value:
        raise PolicyError(reason)


def exact(value, fields):
    require(type(value) is dict and len(value) == len(fields) and set(value) == set(fields))


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                          allow_nan=False).encode('ascii')
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
        raise PolicyError('policy_invalid') from None


def primitives(value, depth=0, count=None):
    if count is None: count = [0, 0]
    count[0] += 1
    require(depth <= 64 and count[0] <= 100000)
    if type(value) is dict:
        require(len(value) <= 8192 and all(type(k) is str for k in value))
        for key, child in value.items():
            primitives(key, depth + 1, count); primitives(child, depth + 1, count)
    elif type(value) is list:
        require(len(value) <= 8192)
        for child in value: primitives(child, depth + 1, count)
    elif type(value) is str:
        require(len(value) <= 4096)
        try: count[1] += len(value.encode('utf-8'))
        except UnicodeError: raise PolicyError('policy_invalid') from None
    else:
        require(value is None or type(value) in (bool, int))
        if type(value) is int: require(abs(value) <= 2**64)
    require(count[1] <= 1048576)


def sha(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None and value != '0' * 64)
    return value


def identifier(value):
    require(type(value) is str and len(value) == 36)
    try: require(str(uuid.UUID(value)) == value)
    except (ValueError, AttributeError): raise PolicyError('policy_invalid') from None
    return value


def path(value, absolute=True):
    require(type(value) is str and 0 < len(value) <= 4096
            and not any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value))
    result = PurePosixPath(value)
    require('\\' not in value and result.is_absolute() == absolute and not value.startswith('//')
            and str(result) == value and '..' not in result.parts and value not in ('.', '/') and len(result.parts) <= 33)
    return result


def integer(value, low, high):
    require(type(value) is int and low <= value <= high)
    return value


def identity(value):
    require(type(value) is list and len(value) == 2)
    for number in value: integer(number, 1, 2**64 - 1)


def inventory(value, absolute=False, maximum=4096):
    require(type(value) is dict and 1 <= len(value) <= maximum)
    for name, pin in value.items():
        path(name, absolute)
        require('__pycache__' not in PurePosixPath(name).parts and not name.endswith(('.pyc', '.pyo')))
        sha(pin)


def _deployment(value, limits):
    exact(value, ('profile', 'provider_root', 'provider_files', 'provider_sizes', 'provider_inventory_sha256', 'modules', 'resources',
                  'consumer_root', 'consumer_files', 'python_path', 'python_sha256', 'runtime_files',
                  'runtime_modules', 'runtime_sizes', 'mapped_files'))
    require(value['profile'] == 'linux_arm64_cpython_3_12_13')
    provider = path(value['provider_root']); consumer = path(value['consumer_root'])
    require(consumer == provider / 'scripts' / 'operation_sdk')
    inventory(value['provider_files'], maximum=limits['max_source_files'])
    for filename in value['provider_files']:path(str(provider/filename))
    exact(value['provider_sizes'],value['provider_files'])
    for size in value['provider_sizes'].values():integer(size,0,limits['max_source_file_bytes'])
    sha(value['provider_inventory_sha256'])
    require(hashlib.sha256(canonical(value['provider_files'])).hexdigest() == value['provider_inventory_sha256'])
    exact(value['consumer_files'], CONSUMER_FILES)
    for name, pin in value['consumer_files'].items():
        sha(pin); require(value['provider_files'].get('scripts/operation_sdk/' + name) == pin)
    modules = value['modules']
    require(type(modules) is dict and len(modules) <= 128)
    for name, filename in modules.items():
        require(type(name) is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,127}', name) is not None
                and name != 'operation_sdk')
        path(filename, False)
        require(filename in value['provider_files'] and filename in ('scripts/' + name + '.py', 'runtime/' + name + '.py'))
        path(str(provider / filename))
    require(len(set(modules.values())) == len(modules))
    resources = value['resources']; require(type(resources) is dict and len(resources) <= limits['max_source_files'])
    for name, pin in resources.items():
        path(name, False); sha(pin)
        require(name.startswith(('assets/', 'references/')) and value['provider_files'].get(name) == pin)
    path(value['python_path']); require(value['python_path'] == '/usr/local/bin/python3.12'); sha(value['python_sha256'])
    inventory(value['runtime_files'], True, limits['max_source_files'])
    exact(value['runtime_sizes'],value['runtime_files'])
    for size in value['runtime_sizes'].values():integer(size,0,limits['max_source_file_bytes'])
    require(value['runtime_files'].get(value['python_path']) == value['python_sha256'])
    for filename in value['runtime_files']:
        require(filename == value['python_path'] or filename.startswith(('/usr/local/lib/python3.12/', '/usr/local/lib/', '/usr/lib/', '/lib/')))
    require(type(value['runtime_modules']) is dict and 1 <= len(value['runtime_modules']) <= limits['max_runtime_modules'])
    for name, record in value['runtime_modules'].items():
        require(type(name) is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_.]{0,255}', name) is not None)
        if type(record)is dict and record.get('kind')=='export_alias':
            exact(record,('kind','path','spec_name','owner'))
            require(name in('typing.io','typing.re')and record['path']is None and record['spec_name']is None
                    and record['owner']=='typing'and 'typing'in value['runtime_modules'])
            continue
        exact(record, ('kind', 'path', 'spec_name'))
        require(type(record['spec_name']) is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_.]{0,255}', record['spec_name']) is not None)
        if record['kind'] in ('built-in', 'frozen'): require(record['path'] is None)
        else:
            require(record['kind'] == 'file'); path(record['path']); require(record['path'] in value['runtime_files'])
    require(type(value['mapped_files']) is list and 1 <= len(value['mapped_files']) <= limits['max_native_libraries'])
    for filename in value['mapped_files']:
        path(filename); require(filename in value['runtime_files'])
    require(len(set(value['mapped_files'])) == len(value['mapped_files']))


def _scope(value, operation, deployment, limits):
    exact(value, ('base', 'profile', 'resource', 'dependencies', 'metadata', 'external_bindings',
                  'store', 'coordination', 'references', 'write_reference', 'value_contract'))
    require(type(value['external_bindings']) is bool)
    deps = value['dependencies']
    require(type(deps) is list and len(deps) <= limits['max_read_refs'])
    names = set(); total = 0
    resources={str(PurePosixPath(deployment['provider_root'])/name):pin
               for name,pin in deployment['resources'].items()}
    for item in deps:
        exact(item, ('path', 'sha256', 'maximum_bytes', 'role')); path(item['path']); sha(item['sha256'])
        require(item['role'] in ('prompt', 'profile', 'profile_asset', 'scorer') and item['path'] not in names)
        require(item['path']not in resources or item['sha256']==resources[item['path']], 'dependency_resource_hash')
        total += integer(item['maximum_bytes'], 0, limits['max_dependency_file_bytes']); names.add(item['path'])
    require(total <= limits['max_dependency_bytes'])
    if operation in ('plan_validate_legacy_v1', 'plan_check_project_v1'):
        path(value['base'])
        if value['profile'] is not None:
            path(value['profile']); require(any(d['path'] == value['profile'] and d['role'] == 'profile' for d in deps))
    else:
        require(value['base'] is None and value['profile'] is None and not deps and not value['external_bindings'])
    metadata = value['metadata']; require(type(metadata) is list and len(metadata) <= limits['max_read_refs'])
    if operation == 'plan_check_project_v1':
        require(metadata)
        seen = set()
        for item in metadata:
            exact(item, ('path', 'identity', 'kind')); selected = path(item['path']); identity(item['identity'])
            require(selected == path(value['base']) or path(value['base']) in selected.parents)
            require(item['kind'] in ('file', 'directory') and item['path'] not in seen); seen.add(item['path'])
    else: require(not metadata)
    if operation == 'resource_read_v1':
        resource = value['resource']; exact(resource, ('path', 'maximum_bytes')); path(resource['path'], False)
        require(resource['path'].startswith(('assets/', 'references/'))
                and resource['path'] in deployment['resources'])
        integer(resource['maximum_bytes'], 1, limits['max_result_bytes'])
    else:
        require(value['resource'] is None)
    store, coordination = value['store'], value['coordination']
    references = value['references']
    require(type(references) is list and len(references) <= limits['max_read_refs'])
    if operation == 'resource_read_v1': require(not references)
    if operation in PRIVATE_OPERATIONS or references:
        exact(store, ('path', 'identity')); store_path = path(store['path']); identity(store['identity'])
        exact(coordination, ('path', 'identity')); coord_path = path(coordination['path']); identity(coordination['identity'])
        provider = path(deployment['provider_root'])
        require(store_path != provider and provider not in store_path.parents and store_path not in provider.parents)
        require(coord_path != provider and provider not in coord_path.parents and coord_path != store_path)
        require(not str(store_path).startswith(('/usr/', '/lib/')) and not str(coord_path).startswith(('/usr/', '/lib/')))
    else:
        require(store is None and coordination is None)
        store_path = coord_path = None
    refs = set(); aliases = set(); inference = applications = 0
    for item in references:
        exact(item, ('reference', 'alias', 'role', 'value_contract', 'identity', 'size', 'mtime_ns', 'ctime_ns'))
        name = item['reference']
        require(type(name) is str and re.fullmatch('[A-Z_][A-Z0-9_]{0,63}', name) is not None and name not in refs)
        require(item['role'] in ('application', 'inference', 'redaction')); identity(item['identity'])
        require(item['value_contract'] in ('normalized_secret_1', 'application_credential_1'))
        if item['role'] == 'application': require(item['value_contract'] == 'application_credential_1')
        integer(item['size'], 16 if item['value_contract'] == 'application_credential_1' else 1, limits['max_ref_bytes'])
        integer(item['mtime_ns'], 0, 2**63 - 1); integer(item['ctime_ns'], 0, 2**63 - 1)
        if item['role'] == 'inference':
            require(item['alias'] is None); inference += 1
        elif item['role'] == 'application':
            alias = item['alias']; require(type(alias) is str and re.fullmatch('PI_APP_[A-Z][A-Z0-9_]{0,56}', alias) is not None
                                         and alias not in aliases)
            aliases.add(alias); applications += 1
        else: require(item['alias'] is None)
        refs.add(name); require(store_path / name != coord_path)
    require(inference <= 1 and applications <= 8 and sum(i['size'] for i in references) <= limits['max_read_bytes'])
    if operation in ('credentials_collect_v1', 'redact_bytes_v1'): require(references)
    if operation == 'credentials_collect_v1': require(applications and inference == 1 and len(references) == applications + inference)
    if operation == 'secret_register_create_only_v1':
        ref = value['write_reference']
        require(type(ref) is str and re.fullmatch('[A-Z_][A-Z0-9_]{0,63}', ref) is not None
                and ref not in refs and store_path / ref != coord_path)
        require(value['value_contract'] in ('normalized_secret_1', 'application_credential_1'))
        if value['value_contract'] == 'application_credential_1': require(inference == 1)
    else:
        require(value['write_reference'] is None and value['value_contract'] is None)


def _forecast(value):
    """Complete conservative admission before any namespace or private lookup."""
    scope, limits, deployment = value['scope'], value['limits'], value['deployment']
    source = value['input']; input_bound = source['maximum_bytes'] if source is not None else 0
    keys = sum(ref['size'] for ref in scope['references'])
    payload_bound = ((input_bound + 2) // 3 * 4 if value['operation'] == 'redact_bytes_v1' else 6 * input_bound)
    payload_bound += 6 * keys + 4096 + 512 * len(scope['references'])
    require(payload_bound <= limits['max_payload_bytes'], 'payload_forecast')
    require(4 * len(canonical(deployment)) + 16384 <= limits['max_control_bytes'], 'control_forecast')
    sdk_bytes=sum(deployment['provider_sizes']['scripts/operation_sdk/'+name]for name in CONSUMER_FILES)
    bootstrap_bytes=sdk_bytes+deployment['provider_sizes']['scripts/operation_sdk/__init__.py']+deployment['provider_sizes']['scripts/operation_sdk/worker.py']
    module_bytes=sum(deployment['provider_sizes'][name]for name in deployment['modules'].values())
    require(bootstrap_bytes+2*module_bytes+2*sum(deployment['runtime_sizes'].values())<=limits['max_source_bytes']//2,'verification_forecast')
    require(len(CONSUMER_FILES)+2+2*len(deployment['modules'])+2*len(deployment['runtime_files'])
            <=limits['max_source_files'],'verification_file_forecast')
    store_depth = len(PurePosixPath(scope['store']['path']).parts) if scope['store'] else 0
    coord_depth = len(PurePosixPath(scope['coordination']['path']).parts) if scope['coordination'] else 0
    deepest = max([len(PurePosixPath(deployment['consumer_root']).parts) + 1]
                  + [len(PurePosixPath(d['path']).parts) for d in scope['dependencies']]
                  + [len((PurePosixPath(deployment['provider_root'])/name).parts)for name in deployment['provider_files']]
                  + [len(PurePosixPath(name).parts)for name in deployment['runtime_files']])
    require(max(12 + store_depth + coord_depth, 9 + deepest, 10 + store_depth) <= limits['max_owned_fds'], 'fd_forecast')
    result_bound = 6 * input_bound + 16384 + limits['failure_reserve_bytes']
    pattern_bytes = regex_bytes = 0
    protected_bytes=keys+(limits['max_secret_bytes']if value['operation']=='secret_register_create_only_v1'else 0)
    protected_count=len(scope['references'])+int(value['operation']=='secret_register_create_only_v1')
    if protected_count:
        # collect.Patterns keeps at most 2**k strings at escape layer k (15 in all).
        # One json.dumps layer maps each allowed character to at most three bytes per
        # input byte: '"' and '\\' become 2 bytes, a 2-byte character becomes \uXXXX
        # and an astral character a 12-byte surrogate pair. Values exclude control
        # characters and json.dumps never emits them, so this holds at every layer:
        # sum(2**k * 3**k for k in 0..3) = 259 bytes per protected byte.
        patterns = 15 * protected_count; pattern_bytes = 259 * protected_bytes
        regex_bytes = 2 * pattern_bytes + 3 * patterns
        require(patterns <= limits['max_pattern_count'] and pattern_bytes <= limits['max_pattern_bytes']
                and regex_bytes <= limits['max_regex_bytes'], 'pattern_forecast')
    if value['operation'] == 'redact_bytes_v1':
        minimum = min(ref['size'] for ref in scope['references'])
        replaced = input_bound + (input_bound // minimum) * max(0, 10 - minimum)
        result_bound = 4 * ((replaced + 2) // 3) + 16384 + limits['failure_reserve_bytes']
    elif value['operation'] in ('plan_validate_legacy_v1', 'plan_check_project_v1'):
        result_bound += 6 * limits['max_plan_agents'] * limits['max_prompt_bytes']
        result_bound += 3 * len(scope['base'].encode()) * limits['max_scorer_assets']
        result_bound += 2048 * (limits['max_plan_agents'] + limits['max_plan_checks'] + limits['max_plan_setup'])
    elif value['operation'] == 'secret_register_create_only_v1':
        calls=limits['max_secret_bytes']+store_depth+7
        require(calls <= limits['max_mutating_calls'], 'call_forecast')
        require(calls*256+8192<=1048576,'native_report_forecast')
        result_bound = calls * 256 + 16384 + limits['failure_reserve_bytes']
    elif value['operation'] == 'resource_read_v1':
        result_bound = 4 * ((scope['resource']['maximum_bytes'] + 2) // 3) + 16384 + limits['failure_reserve_bytes']
    require(result_bound <= limits['max_result_bytes'], 'result_forecast')
    additional_memory = 16 * (pattern_bytes + regex_bytes) + 3 * result_bound + 4 * payload_bound
    require(134217728 + additional_memory <= limits['max_memory_bytes'], 'memory_forecast')
    return {'private_frame_bytes': payload_bound, 'result_frame_bytes': result_bound,
            'additional_memory_bytes': additional_memory, 'pattern_bytes': pattern_bytes,
            'regex_bytes': regex_bytes,'bootstrap_verification_bytes':bootstrap_bytes,
            'parent_bootstrap_verification_bytes':sdk_bytes+deployment['provider_sizes']['scripts/operation_sdk/__init__.py']}


@dataclass(frozen=True, repr=False)
class Admission:
    policy_sha256: str
    context_sha256: str
    operation: str
    _policy: bytes
    _request: bytes
    _forecast: bytes
    operational_approval: bool = False

    def policy(self): return json.loads(self._policy)
    def request(self): return json.loads(self._request)
    def forecast(self): return json.loads(self._forecast)
    def __repr__(self): return '<sdk>'


def _compile(value, request, *, trusted_policy_sha256, now_ns, discovery=False):
    """Pure snapshot compilation; matching a supplied digest is not authority."""
    sha(trusted_policy_sha256); primitives(value); primitives(request)
    body = canonical(value); require(len(body) <= 1048576)
    require(hashlib.sha256(body).hexdigest() == trusted_policy_sha256, 'policy_digest')
    value = json.loads(body); request = json.loads(canonical(request))
    exact(value, ('schema', 'document_type', 'policy_id', 'actor_id', 'participant_id', 'stage_id',
                  'operation', 'deployment', 'input', 'scope', 'limits'))
    require(type(value['schema']) is int and value['schema'] == 1 and value['document_type'] == 'operation_sdk_policy')
    identifier(value['policy_id']); identifier(value['actor_id'])
    for name in ('participant_id', 'stage_id'):
        require(type(value[name]) is str and re.fullmatch('[A-Za-z0-9._:-]{1,128}', value[name]) is not None)
    operation = value['operation']; require(type(operation) is str and
        (operation=='environment_probe_v1'if discovery else operation in OPERATIONS))
    limits = value['limits']; exact(limits, LIMITS)
    for name, bounds in LIMITS.items(): integer(limits[name], *bounds)
    require(limits['max_cpu_millis']%1000==0, 'cpu_budget_unrepresentable')
    require(limits['failure_reserve_bytes'] < limits['max_result_bytes'])
    _deployment(value['deployment'], limits); _scope(value['scope'], operation, value['deployment'], limits)
    if operation in ('resource_read_v1','credentials_collect_v1','secret_register_create_only_v1'):
        require(not value['deployment']['modules'],'unexpected_provider_import')
    source = value['input']
    if operation in ('resource_read_v1','environment_probe_v1'): require(source is None)
    else:
        exact(source, ('source_id', 'kind', 'identity', 'maximum_bytes')); identifier(source['source_id']); identity(source['identity'])
        require(source['kind'] in ('pipe', 'sealed_memfd') and limits['max_payload_bytes'] > 0)
        integer(source['maximum_bytes'], 1, limits['max_payload_bytes'])
    forecast = _forecast(value)
    exact(request, ('schema', 'document_type', 'operation', 'policy_sha256', 'actor_id', 'participant_id', 'stage_id', 'operation_id',
                    'request_id', 'worker_id', 'channel_id', 'source_id', 'created_ns', 'expires_ns'))
    require(type(request['schema']) is int and request['schema'] == 1 and request['document_type'] == 'operation_sdk_request')
    require(request['operation'] == operation and request['policy_sha256'] == trusted_policy_sha256
            and request['actor_id'] == value['actor_id']
            and request['participant_id'] == value['participant_id'] and request['stage_id'] == value['stage_id']
            and request['source_id'] == (source['source_id'] if source else None), 'request_binding')
    for field in ('operation_id', 'request_id', 'worker_id', 'channel_id'): identifier(request[field])
    integer(now_ns, 0, 2**63 - 1); integer(request['created_ns'], 0, 2**63 - 1); integer(request['expires_ns'], 1, 2**63 - 1)
    require(request['created_ns'] <= now_ns < request['expires_ns']
            <= request['created_ns'] + limits['max_runtime_millis'] * 1000000, 'request_expired')
    request_body = canonical(request)
    require(len(body) + len(request_body) + 4096 <= limits['max_control_bytes'], 'control_forecast')
    context = hashlib.sha256(canonical({'domain': 'operation_sdk_context_1',
        'policy_sha256': trusted_policy_sha256, 'request': request})).hexdigest()
    return Admission(trusted_policy_sha256, context, operation, body, request_body, canonical(forecast))


def compile_admission(value,request,*,trusted_policy_sha256,now_ns):
    return _compile(value,request,trusted_policy_sha256=trusted_policy_sha256,now_ns=now_ns)


def compile_discovery(value,request,*,trusted_policy_sha256,now_ns):
    """Qualification-only public-source observation; never a handler grant."""
    return _compile(value,request,trusted_policy_sha256=trusted_policy_sha256,now_ns=now_ns,discovery=True)
