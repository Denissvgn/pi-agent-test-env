"""Consumer-owned isolated proof replay; no provider import in this interpreter.

Use a separately approved policy/digest and the complete three-file consumer
artifact. Private origin observations are returned to the caller, not printed.
This is not an application admission or operational authorization interface.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import selectors
import stat
import subprocess
import sys
import threading
import time

if __package__:
    from . import application_owner_consumer_policy as policy
else:
    import application_owner_consumer_policy as policy

MAX_OUTPUT_BYTES = 512 * 1024
TIMEOUT_SECONDS = 30
MEMORY_FIELDS = ('_owner_anchor_identity', '_owner_proof_store_identity', '_owner_selected_identity')
RESULT_FIELDS = frozenset(('schema', 'document_type', 'decision', 'condition', 'phase', 'admission_authorized',
                           'provider_imported', 'history_read', 'origins', 'memory'))
_MEMORY_NAME = '_pi_application_owner_consumer_memory_v1'
_process_memory = getattr(sys, _MEMORY_NAME, None)
if _process_memory is None:
    _process_memory = {'schema':1,'states':{},'lock':threading.Lock()}
    setattr(sys, _MEMORY_NAME, _process_memory)
policy.require(type(_process_memory) is dict and set(_process_memory)=={'schema','states','lock'}
               and type(_process_memory['schema']) is int and _process_memory['schema']==1
               and type(_process_memory['states']) is dict
               and type(_process_memory['lock']) is type(threading.Lock()))
_MEMORY = _process_memory['states']
_MEMORY_LOCK = _process_memory['lock']


class ConsumerError(ValueError):
    pass


def require(value):
    if not value:raise ConsumerError('invalid_proof')


def signature(info):
    return [getattr(info, field) for field in ('st_dev', 'st_ino', 'st_uid', 'st_mode',
            'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')]


def directory(path):
    path = Path(str(policy.absolute(str(path))))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        return fd
    except BaseException:
        os.close(fd); raise


def stable_read(path, *, maximum=8 * 1024 * 1024, private=False, private_parent=False):
    path = Path(str(policy.absolute(str(path)))); parent = directory(path.parent)
    try:
        parent_info = os.fstat(parent)
        require(parent_info.st_uid in (0, os.getuid())
                and not stat.S_IMODE(parent_info.st_mode) & (0o077 if private_parent else 0o022))
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and before.st_uid in ((os.getuid(),) if private else (0, os.getuid()))
                    and not stat.S_IMODE(before.st_mode) & (0o077 if private else 0o022)
                    and before.st_size <= maximum)
            body = stream.read(0 if maximum == 0 else maximum + 1)
            require(len(body) == before.st_size and signature(before) == signature(os.fstat(stream.fileno()))
                    == signature(os.stat(path.name, dir_fd=parent, follow_symlinks=False)))
        named_parent = directory(path.parent)
        try:require(signature(os.fstat(parent)) == signature(os.fstat(named_parent)))
        finally:os.close(named_parent)
        return body, signature(before)
    finally:os.close(parent)


def provider_inventory(approved):
    """Hash the complete bounded layout without following a file/directory alias."""
    value = approved.to_wire()['provider']; root = Path(value['root']); files = {}; identities = {}; total = 0
    prefixes={str(parent) for name in value['files'] for parent in Path(name).parents if str(parent)!='.'}
    pending = [root]; directories = 0
    while pending:
        path = pending.pop(); fd = directory(path)
        try:
            before = os.fstat(fd)
            require(before.st_uid in (0, os.getuid()) and not stat.S_IMODE(before.st_mode) & 0o022)
            identities[str(path)] = signature(before)
            with os.scandir(fd) as entries:
                for entry in entries:
                    info = entry.stat(follow_symlinks=False); child = path / entry.name
                    relative=str(child.relative_to(root))
                    if stat.S_ISDIR(info.st_mode):
                        require(relative in prefixes)
                        directories += 1; require(directories <= 4096); pending.append(child)
                    else:
                        require(stat.S_ISREG(info.st_mode) and len(files) < 4096)
                        require(relative in value['files'])
                        body, observed = stable_read(child)
                        total += len(body); require(total <= 128 * 1024 * 1024)
                        files[str(child.relative_to(root))] = hashlib.sha256(body).hexdigest()
                        identities[str(child)] = observed
            require(signature(before) == signature(os.fstat(fd)))
        finally:os.close(fd)
        named = directory(path)
        try:require(signature(os.fstat(named)) == identities[str(path)])
        finally:os.close(named)
    require(files == value['files'] and policy.digest(files) == value['inventory_sha256'])
    return identities


def decode(body):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result); result[key] = value
        return result
    try:
        def number(text):
            value = float(text); require(math.isfinite(value)); return value
        return json.loads(body, object_pairs_hook=pairs,
            parse_float=number, parse_constant=lambda unused: require(False))
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise ConsumerError('invalid_proof') from None


def exchange(argv, body):
    """Bound request writing, combined output and elapsed time for our own worker."""
    require(len(body) <= policy.MAX_POLICY_BYTES + 16384)
    env = {'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1', 'LC_ALL': 'C',
           'HOME': '/nonexistent-owner-consumer-home'}
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=env, cwd='/', start_new_session=True)
    output = {process.stdout: bytearray(), process.stderr: bytearray()}
    deadline = time.monotonic() + TIMEOUT_SECONDS; offset = 0; received = 0
    try:
        with selectors.DefaultSelector() as events:
            for stream in (process.stdin, process.stdout, process.stderr):os.set_blocking(stream.fileno(), False)
            events.register(process.stdin, selectors.EVENT_WRITE)
            for stream in output:events.register(stream, selectors.EVENT_READ)
            while events.get_map():
                remaining = deadline - time.monotonic(); require(remaining > 0)
                for key, unused in events.select(min(remaining, 0.1)):
                    stream = key.fileobj
                    if stream is process.stdin:
                        try:offset += os.write(stream.fileno(), body[offset:offset + 16384])
                        except BrokenPipeError:offset = len(body)
                        if offset == len(body):events.unregister(stream); stream.close()
                    else:
                        chunk = os.read(stream.fileno(), 16384)
                        if not chunk:events.unregister(stream); stream.close(); continue
                        received += len(chunk); require(received <= MAX_OUTPUT_BYTES)
                        output[stream].extend(chunk)
            code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        return code, bytes(output[process.stdout]), bytes(output[process.stderr])
    finally:
        if process.poll() is None:process.kill(); process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            if not stream.closed:stream.close()


def empty_memory():
    return {'selected': False, 'indeterminate': False, 'namespaces': {field: None for field in MEMORY_FIELDS}}


def result(decision='extension_required', condition='extension_required'):
    return {'schema': 1, 'document_type': 'application_owner_consumer_result',
            'decision': decision, 'condition': condition, 'phase': 'policy', 'admission_authorized': False,
            'provider_imported': False, 'history_read': False, 'origins': None, 'memory': empty_memory()}


def validate_result(value, approved, mode):
    require(type(value) is dict and set(value) == RESULT_FIELDS and type(value['schema']) is int
            and value['schema'] == 1 and value['document_type'] == 'application_owner_consumer_result'
            and value['decision'] in ('proof_accepted', 'not_selected', 'invalid_proof', 'extension_required')
            and value['condition'] in ('extension_required', 'provider_readonly_required', 'invalid_proof', 'origins_observed', 'replayed')
            and value['phase'] in ('policy', 'bootstrap', 'inventory', 'provider_import', 'resource_identity', 'replay', 'inventory_recheck', 'complete')
            and value['admission_authorized'] is False
            and all(value[key] is None or type(value[key]) is bool for key in ('provider_imported', 'history_read')))
    memory = value['memory']
    require(type(memory) is dict and set(memory) == {'selected', 'indeterminate', 'namespaces'}
            and type(memory['indeterminate']) is bool
            and type(memory['selected']) is bool and type(memory['namespaces']) is dict
            and set(memory['namespaces']) == set(MEMORY_FIELDS))
    for identity in memory['namespaces'].values():
        require(identity is None or (type(identity) is list and len(identity) == 2
                and all(policy.integer(n, 0, 2**64 - 1) for n in identity)))
    if value['provider_imported']:
        origins = value['origins']; provider = approved.to_wire()['provider']
        require(type(origins) is dict and set(origins) == {'modules', 'resources', 'inventory_sha256', 'identity_sha256', 'provider_readonly'}
                and origins['provider_readonly'] is True and policy.sha(origins['identity_sha256'])
                and origins['inventory_sha256'] == provider['inventory_sha256']
                and type(origins['modules']) is list and 1 <= len(origins['modules']) <= 4096
                and type(origins['resources']) is list and len(origins['resources']) <= 128)
        names = []
        for row in origins['modules']:
            require(type(row) is dict and set(row) == {'name', 'path', 'sha256'})
            path = policy.absolute(row['path']); root = policy.absolute(provider['root'])
            require(root in path.parents and str(path.relative_to(root)) in provider['files']
                    and provider['files'][str(path.relative_to(root))] == row['sha256']
                    and type(row['name']) is str)
            names.append(row['name'])
        require(names == sorted(set(names)) and 'application_owner_cleanup' in names)
        for row in origins['resources']:
            require(type(row) is dict and set(row) == {'path', 'sha256'})
            path = policy.absolute(row['path']); root = policy.absolute(provider['root'])
            require(root in path.parents and provider['files'].get(str(path.relative_to(root))) == row['sha256'])
    else:
        require(value['origins'] is None)
        if value['provider_imported'] is False:require(value['history_read'] is False)
        else:require(value['decision'] == 'invalid_proof')
    if value['history_read'] is None:require(value['decision'] == 'invalid_proof')
    require(not value['history_read'] or (mode == 'replay' and value['provider_imported']))
    if value['decision'] in ('proof_accepted', 'not_selected'):
        require(value['history_read'] and value['condition'] == 'replayed')
    if value['condition'] == 'origins_observed':
        require(mode == 'origins' and value['provider_imported'] and value['decision'] == 'extension_required')


class Consumer:
    """Keep selected-state memory across fresh provider processes in this consumer."""
    def __init__(self, value, *, trusted_policy_sha256, selection):
        self.approved = policy.compile_policy(value, trusted_policy_sha256=trusted_policy_sha256, selection=selection)
        self.selection = decode(policy.canonical(selection)); frozen = self.approved.to_wire()
        if 'replay' not in frozen['capabilities']:
            self._state={'memory':empty_memory(),'lock':threading.RLock(),'expected_lease':None}
            return
        key = policy.digest({'lease_path':frozen['lease']['path'],'subject':frozen['subject']})
        with _MEMORY_LOCK:
            if key not in _MEMORY:
                policy.require(len(_MEMORY) < 8192)
                _MEMORY[key] = {'memory':empty_memory(),'lock':threading.RLock(),
                                'expected_lease':frozen['lease']['identity']}
            self._state = _MEMORY[key]
            policy.require(self._state['expected_lease'] == frozen['lease']['identity'])

    @property
    def memory(self):
        return decode(policy.canonical(self._state['memory']))

    def evaluate(self, mode='origins'):
        with self._state['lock']:return self._evaluate(mode)

    def _evaluate(self, mode):
        if mode not in self.approved.to_wire()['capabilities']:
            denied=result();denied['memory']=self.memory;return denied
        if mode == 'replay' and self.memory['indeterminate']:
            observed=result('invalid_proof','invalid_proof');observed['memory']=self.memory
            return observed
        try:
            verify_consumer(self.approved); root = Path(__file__).resolve().parent
        except (ConsumerError, OSError, policy.PolicyError):
            denied=result();denied['memory']=self.memory;return denied
        try:
            packet = {'policy': self.approved.to_wire(), 'trusted_policy_sha256': self.approved.policy_sha256,
                      'selection': self.selection, 'mode': mode, 'memory': self.memory}
            code, stdout, stderr = exchange([sys.executable, '-I', '-S', '-B',
                str(root/'application_owner_consumer_worker.py')], policy.canonical(packet))
            require(code == 0 and not stderr)
            observed = decode(stdout); validate_result(observed, self.approved, mode)
            if self.memory['selected']:require(observed['memory']['selected'])
            for key, identity in self.memory['namespaces'].items():
                if identity is not None:require(observed['memory']['namespaces'][key] == identity)
            require(not self.memory['indeterminate'] or observed['memory']['indeterminate'])
            self._state['memory'] = decode(policy.canonical(observed['memory']))
            return observed
        except (ConsumerError, OSError, policy.PolicyError, subprocess.SubprocessError):
            # Uncertainty blocks fallback without inventing an observed selection.
            self._state['memory']['indeterminate'] = True
            observed = result('invalid_proof', 'invalid_proof'); observed['memory'] = self.memory
            observed.update(phase='bootstrap', provider_imported=None, history_read=None)
            return observed


def verify_consumer(approved):
    expected = approved.to_wire()['consumer']; root = Path(__file__).resolve().parent
    for name, sha in expected['files'].items():
        body, unused = stable_read(root/name); require(hashlib.sha256(body).hexdigest() == sha)
    body, unused = stable_read(Path(sys.executable).resolve(), maximum=128*1024*1024)
    require(hashlib.sha256(body).hexdigest() == expected['python_sha256']
            and list(sys.version_info[:3]) == expected['python_version'])


def evaluate(value, *, trusted_policy_sha256, selection, mode='origins'):
    try:consumer = Consumer(value, trusted_policy_sha256=trusted_policy_sha256, selection=selection)
    except policy.PolicyError:return result()
    return consumer.evaluate(mode)
