"""Pure consumer policy compilation, independent of provider code and evidence.

The trusted digest must come from the consumer's separately approved policy.
Parsing a policy or matching that digest does not itself establish approval.
This module performs no filesystem, provider import, history or native operation.
"""
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import PurePosixPath
import re

CONTRACT = 'application_owner_legacy_reader_1'
METHOD = 'legacy_derived_v1'
COHORT = 'application_owner_legacy_1'
SCOPE = 'owned_host_files_only'
FILE_BYTES = 4194304
MAX_REFERENCES = 128
MAX_POLICY_BYTES = 4 * 1024 * 1024
ROLES = frozenset(('anchor', 'index', 'selection', 'intent', 'terminal', 'request',
                   'evidence', 'source', 'original_metadata', 'empty_metadata', 'related_proof'))
CONSUMER_FILES = frozenset(('application_owner_consumer_policy.py',
                           'application_owner_consumer.py', 'application_owner_consumer_worker.py'))


class PolicyError(ValueError):
    """Closed policy denial; never include input paths or exception bodies."""


def require(value):
    if not value:raise PolicyError('extension_required')


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=False, allow_nan=False).encode('utf-8')
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
        raise PolicyError('extension_required') from None


def primitives(value, depth=0, count=None):
    """Reject coercible Python objects before taking the immutable JSON snapshot."""
    if count is None:count = [0, 0]
    count[0] += 1
    require(depth <= 32 and count[0] <= 100000)
    if type(value) is dict:
        require(all(type(key) is str for key in value))
        for key in value:
            require(len(key) <= 4096)
            try:count[1] += len(key.encode('utf-8'))
            except UnicodeError:raise PolicyError('extension_required') from None
        for item in value.values():primitives(item, depth + 1, count)
    elif type(value) is list:
        for item in value:primitives(item, depth + 1, count)
    else:
        require(value is None or type(value) in (str, int, bool, float))
        if type(value) is str:
            require(len(value) <= 4096)
            try:count[1] += len(value.encode('utf-8'))
            except UnicodeError:raise PolicyError('extension_required') from None
        if type(value) is int:require(abs(value) <= 2**64)
        if type(value) is float:require(math.isfinite(value))
    require(count[1] <= MAX_POLICY_BYTES)


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def sha(value):
    return type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None and value != '0' * 64


def exact(value, fields):
    require(type(value) is dict and set(value) == set(fields))


def absolute(value):
    require(type(value) is str and 1 < len(value) <= 4096 and value.startswith('/')
            and not value.startswith('//') and str(PurePosixPath(value)) == value
            and '..' not in PurePosixPath(value).parts
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))
    return PurePosixPath(value)


def relative(value):
    require(type(value) is str and 0 < len(value) <= 4096
            and not value.startswith('/') and str(PurePosixPath(value)) == value
            and '..' not in PurePosixPath(value).parts and value != '.'
            and '__pycache__' not in PurePosixPath(value).parts and not value.endswith(('.pyc', '.pyo'))
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def identifier(value):
    return type(value) is str and re.fullmatch(
        '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', value) is not None


def ordered_paths(values, maximum):
    require(type(values) is list and len(values) <= maximum)
    for value in values:absolute(value)
    require(values == sorted(set(values)))


@dataclass(frozen=True)
class FileGrant:
    path: str
    sha256: object
    maximum_bytes: int
    private: bool
    private_parent: bool
    roles: tuple


@dataclass(frozen=True)
class CompiledPolicy:
    policy_sha256: str
    _body: bytes
    files: tuple

    def to_wire(self):
        """Return independent data, not a mutable view of the approval."""
        return json.loads(self._body)

    def file_grant(self, path):
        absolute(path)
        for grant in self.files:
            if grant.path == path:return grant
        raise PolicyError('extension_required')


def compile_policy(policy, *, trusted_policy_sha256, selection):
    """Fail closed before IO, using a digest from trusted consumer configuration."""
    require(sha(trusted_policy_sha256))
    primitives(policy); primitives(selection)
    body = canonical(policy)
    require(len(body) <= MAX_POLICY_BYTES and hashlib.sha256(body).hexdigest() == trusted_policy_sha256)
    # Snapshot primitive JSON before inspecting anything. Caller mutation cannot
    # alter a compiled read grant, provider identity or execution binding later.
    policy = json.loads(body)
    exact(policy, ('schema', 'document_type', 'capabilities', 'binding', 'subject', 'provider',
                   'consumer', 'lease', 'read_scope'))
    require(type(policy['schema']) is int and policy['schema'] == 1
            and policy['document_type'] == 'application_owner_consumer_policy')
    require(policy['capabilities'] in (['origins'], ['origins', 'replay']))
    binding = policy['binding']
    exact(binding, ('contract_id', 'contract_version', 'method', 'cohort', 'variant', 'scope'))
    require(binding['contract_id'] == CONTRACT and type(binding['contract_version']) is int
            and binding['contract_version'] == 1 and binding['method'] == METHOD
            and binding['cohort'] == COHORT and binding['scope'] == SCOPE
            and binding['variant'] in ('standard_workspace_v1', 'diagnostic_disposable_v1'))
    subject = policy['subject']
    provider = policy['provider']; exact(provider, ('root', 'files', 'inventory_sha256'))
    provider_root = absolute(provider['root']); inventory = provider['files']
    require(type(inventory) is dict and 4 <= len(inventory) <= 4096)
    for name, value in inventory.items():relative(name); require(sha(value))
    require({'SKILL.md', 'MANIFEST.sha256', 'scripts/application_owner_cleanup.py',
             'assets/application-owner-reader-v1.json'} <= set(inventory)
            and sha(provider['inventory_sha256']) and digest(inventory) == provider['inventory_sha256'])
    consumer = policy['consumer']; exact(consumer, ('files', 'python_sha256', 'python_version'))
    exact(consumer['files'], CONSUMER_FILES)
    require(all(sha(value) for value in consumer['files'].values()) and sha(consumer['python_sha256']))
    version = consumer['python_version']
    require(type(version) is list and len(version) == 3
            and all(integer(value, 0, 999) for value in version)
            and version[0] == 3 and version[1] >= 10)
    if policy['capabilities'] == ['origins']:
        require(subject is None and policy['lease'] is None and policy['read_scope'] is None)
        _selection(selection, binding, subject, provider)
        return CompiledPolicy(trusted_policy_sha256, body, ())
    exact(subject, ('registry', 'generation', 'launch_id', 'intent_sha256', 'container_id'))
    require(all(sha(subject[field]) for field in ('registry', 'intent_sha256', 'container_id'))
            and all(identifier(subject[field]) for field in ('generation', 'launch_id')))
    lease = policy['lease']; exact(lease, ('path', 'identity')); lease_path = absolute(lease['path'])
    identity = lease['identity']
    require(type(identity) is list and len(identity) == 2
            and integer(identity[0], 0, 2**64 - 1) and integer(identity[1], 1, 2**64 - 1))
    scope = policy['read_scope']
    exact(scope, ('registry', 'store', 'anchor', 'files', 'registry_records', 'directories', 'absent_paths'))
    registry = str(lease_path) + '.registry'
    require(scope['registry'] == registry and scope['store'] == registry + '.owner-proofs'
            and scope['anchor'] == registry + '.owner-selected'
            and subject['registry'] == hashlib.sha256(registry.encode()).hexdigest())
    ordered_paths(scope['directories'], 4096)
    require({registry, scope['store'], scope['store'] + '/selected', scope['anchor']}
            <= set(scope['directories']))
    ordered_paths(scope['absent_paths'], 16)
    for text in scope['absent_paths']:
        root = absolute(text)
        for target in (provider_root, lease_path, absolute(registry), absolute(scope['store']), absolute(scope['anchor'])):
            require(root != target and root not in target.parents)
    records = scope['registry_records']
    require(type(records) is list and len(records) <= 8192)
    record_paths = []
    for row in records:
        exact(row, ('path', 'sha256')); path = absolute(row['path'])
        require(str(path.parent) == registry and path.suffix == '.json'
                and identifier(path.stem) and sha(row['sha256']))
        record_paths.append(row['path'])
    require(record_paths == sorted(set(record_paths)))
    rows = scope['files']; require(type(rows) is list and 3 <= len(rows) <= 512)
    merged = {}; declarations = []
    for row in rows:
        exact(row, ('path', 'role', 'sha256', 'maximum_bytes', 'private', 'private_parent'))
        name = row['path']; absolute(name); role = row['role']
        require(type(role) is str and role in ROLES and (row['sha256'] is None or sha(row['sha256']))
                and integer(row['maximum_bytes'], 0, FILE_BYTES)
                and type(row['private']) is bool and type(row['private_parent']) is bool)
        require(role == 'source' or row['private'])
        require(role not in ('anchor', 'index', 'selection', 'intent', 'terminal', 'request', 'evidence')
                or row['private_parent'])
        require(role != 'empty_metadata' or row['maximum_bytes'] == 0)
        for text in scope['absent_paths']:
            root = absolute(text); target = absolute(name)
            require(root != target and root not in target.parents)
        declarations.append((name, role))
        previous = merged.get(name)
        if previous:
            require(previous.sha256 == row['sha256'])
            merged[name] = FileGrant(name, previous.sha256, min(previous.maximum_bytes, row['maximum_bytes']),
                previous.private or row['private'], previous.private_parent or row['private_parent'],
                tuple(sorted((*previous.roles, role))))
        else:
            merged[name] = FileGrant(name, row['sha256'], row['maximum_bytes'], row['private'],
                                    row['private_parent'], (role,))
    require(declarations == sorted(set(declarations)) and len(merged) <= MAX_REFERENCES)
    launch = subject['launch_id'] + '.json'
    for name, role in ((scope['anchor'] + '/' + launch, 'anchor'),
                       (scope['store'] + '/' + launch, 'index'),
                       (scope['store'] + '/selected/' + launch, 'selection')):
        require(name in merged and role in merged[name].roles)
    _selection(selection, binding, subject, provider)
    return CompiledPolicy(trusted_policy_sha256, body, tuple(merged[name] for name in sorted(merged)))


def _selection(selection, binding, subject, provider):
    exact(selection, ('binding', 'subject', 'provider_inventory_sha256'))
    require(canonical(selection['binding']) == canonical(binding)
            and canonical(selection['subject']) == canonical(subject)
            and selection['provider_inventory_sha256'] == provider['inventory_sha256'])
