"""Prepare and explicitly authorize bounded read-only settlement prerequisites.

Preparation is offline. Runtime observations need their own exact grant/review;
neither ownership declarations nor Docker bridge metadata clear SDK admission.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import pwd
import re
import selectors
import signal
import stat
import subprocess
import time

LOCK = '/home/piqual/.local/state/pi-agent-test-env/operation.lock'
REGISTRY = LOCK + '.registry'
PRESERVED_ROOT = '/home/piqual/a15-qualification-062'
OUTPUT_BASE = '/home/piqual/a15-settlement-checks-048'
CELL = 'N04-0.87.1-1'
ROLES = frozenset(('fixture', 'probe', 'boundary', 'preflight', 'application-helper', 'participant'))
DAEMON = '28700317-fa19-4e5e-b3e3-82b42f3c63c2'
KINDS = ('ownership', 'bridge')
LIMITS = {'work_seconds': 120, 'lifecycle_seconds': 126, 'lock_wait_seconds': 30,
          'target_records_max': 6, 'record_bytes_max': 1048576, 'target_bytes_max': 6291456,
          'docker_queries_max': 2, 'docker_query_seconds': 15}
STATES = frozenset(('intent', 'running', 'absent', 'released', 'quarantined'))


class CheckError(ValueError):
    def __init__(self):
        super().__init__('Bounded settlement check refused')


def need(value):
    if not value:
        raise CheckError()


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw, maximum=1048576):
    need(type(raw) is bytes and len(raw) <= maximum)
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value)
            value[key] = item
        return value
    def floating(text):
        value = float(text)
        need(math.isfinite(value))
        return value
    def integer(text):
        need(len(text.lstrip('-')) <= 4300)
        return int(text)
    def invalid(_):
        raise CheckError()
    value = json.loads(raw, object_pairs_hook=pairs, parse_float=floating, parse_int=integer, parse_constant=invalid)
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        need(count <= 32768 and depth <= 24)
        if type(item) is dict:
            need(len(item) <= 512 and all(type(key) is str and len(key) <= 256 for key in item))
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            need(len(item) <= 4096)
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            need(len(item) <= 262144)
        else:
            need(item is None or type(item) in (bool, int, float))
    return value


def identifier(value):
    need(type(value) is str and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', value) is not None)


def digest(value):
    need(type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None)


def validate_selection(value):
    need(type(value) is dict and set(value) == {'schema', 'document_type', 'normal_lock', 'registry_root',
        'preserved_scope', 'source_snapshot_sha256', 'records'})
    need(type(value['schema']) is int and value['schema'] == 1
         and value['document_type'] == 'settlement_preserved_owner_selection'
         and value['normal_lock'] == LOCK and value['registry_root'] == REGISTRY
         and value['preserved_scope'] == PRESERVED_ROOT)
    digest(value['source_snapshot_sha256'])
    rows = value['records']
    need(type(rows) is list and len(rows) == 6 and {row.get('role') for row in rows if type(row) is dict} == ROLES)
    seen = set()
    for row in rows:
        need(type(row) is dict and set(row) == {'role', 'path', 'registry', 'generation', 'launch_id',
                                              'intent_sha256', 'image', 'container_id'})
        identifier(row['launch_id']); identifier(row['generation']); digest(row['registry']); digest(row['intent_sha256'])
        digest(row['container_id'])
        need(row['launch_id'] not in seen and row['path'] == REGISTRY + '/' + row['launch_id'] + '.json'
             and row['registry'] == sha(REGISTRY.encode())
             and type(row['image']) is str and re.fullmatch('sha256:[a-f0-9]{64}', row['image']) is not None)
        seen.add(row['launch_id'])
    return value


def selection_from_snapshot(raw, expected_sha):
    digest(expected_sha); need(sha(raw) == expected_sha)
    snapshot = decode(raw)
    need(type(snapshot) is dict and snapshot.get('poisoned') is True
         and type(snapshot.get('launches')) is list and len(snapshot['launches']) == 6)
    rows = []
    for row in snapshot['launches']:
        need(type(row) is dict and row.get('cell') == CELL and row.get('physical') == 'absent'
             and type(row.get('private_cleanup')) is bool)
        rows.append({key: row[key] for key in ('role', 'registry', 'generation', 'launch_id', 'intent_sha256', 'image', 'container_id')})
        rows[-1]['path'] = REGISTRY + '/' + row['launch_id'] + '.json'
    return validate_selection({'schema': 1, 'document_type': 'settlement_preserved_owner_selection',
        'normal_lock': LOCK, 'registry_root': REGISTRY, 'preserved_scope': PRESERVED_ROOT,
        'source_snapshot_sha256': expected_sha, 'records': rows})


def save(path, value):
    raw = wire(value)
    need(len(raw) <= 131072)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def preparation(kind, selection=None):
    need(kind in KINDS)
    if kind == 'ownership':
        validate_selection(selection)
    else:
        need(selection is None)
    return {'schema': 1, 'document_type': 'bounded_settlement_check_preparation', 'kind': kind,
        'status': 'DISABLED_REQUIRES_SPECIFIC_GRANT_AND_REVIEW', 'selection': selection, 'limits': dict(LIMITS),
        'normal_lock': LOCK, 'expected_daemon': DAEMON, 'network': 'bridge', 'gateway': '172.17.0.1',
        'output': OUTPUT_BASE + '/' + kind + '/run-001',
        'docker_selector_policy': 'NORMAL_GUEST_DEFAULT_NO_OVERRIDES',
        'caps': {'containers': 537, 'participants': 47}, 'declared_current_use': {'containers': 501, 'participants': 42},
        'new_containers_participants_model_business_calls': 0, 'original_record_writes': 0,
        'normal_SDK_admission_still_required': True, 'clearance_or_dispatch_authority': False}


def verify_preparation(value):
    need(type(value) is dict and type(value.get('schema')) is int
         and value == preparation(value.get('kind'), value.get('selection')))
    need(all(type(value['limits'][key]) is int for key in LIMITS)
         and all(type(item) is int for item in value['caps'].values())
         and all(type(item) is int for item in value['declared_current_use'].values())
         and type(value['new_containers_participants_model_business_calls']) is int
         and type(value['original_record_writes']) is int
         and value['normal_SDK_admission_still_required'] is True and value['clearance_or_dispatch_authority'] is False)
    return value


def directory(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            need(os.fstat(fd).st_uid in (0, os.getuid()))
        return fd
    except BaseException:
        os.close(fd); raise


def signature(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class Reader:
    def __init__(self):
        self.attempts = self.bytes = 0
        self.held = []
        self.deadline_check = lambda: None
    def read(self, path, maximum, *, target=True):
        self.deadline_check()
        if target:
            self.attempts += 1
            need(self.attempts <= 6)
        parent = directory(Path(path).parent); fd = None
        try:
            parent_info = os.fstat(parent)
            need(parent_info.st_uid == os.getuid() and stat.S_IMODE(parent_info.st_mode) == 0o700)
            fd = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1
                 and stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= maximum)
            raw = bytearray()
            while len(raw) < before.st_size:
                self.deadline_check()
                chunk = os.read(fd, min(65536, before.st_size - len(raw))); need(bool(chunk)); raw.extend(chunk)
                if target:
                    self.bytes += len(chunk); need(self.bytes <= LIMITS['target_bytes_max'])
            need(signature(before) == signature(os.fstat(fd)) == signature(os.stat(Path(path).name, dir_fd=parent, follow_symlinks=False)))
            self.held.append((Path(path), parent, fd, signature(before)))
            return bytes(raw)
        except BaseException:
            if fd is not None: os.close(fd)
            os.close(parent); raise
    def fence(self):
        self.deadline_check()
        for path, parent, fd, before in self.held:
            need(before == signature(os.fstat(fd)) == signature(os.stat(path.name, dir_fd=parent, follow_symlinks=False)))
            current = directory(path.parent)
            try:
                info = os.fstat(current)
                need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700
                     and (info.st_dev, info.st_ino) == (os.fstat(parent).st_dev, os.fstat(parent).st_ino))
            finally: os.close(current)
    def close(self):
        failed = False
        for _, parent, fd, _ in reversed(self.held):
            for handle in (fd, parent):
                try: os.close(handle)
                except OSError: failed = True
        self.held = []
        need(not failed)


def owner_projection(record, selected):
    need(type(record) is dict and type(record.get('schema')) is int and record['schema'] in (1, 2))
    ordinary_worker = (selected['role'] in ('probe', 'boundary', 'preflight', 'participant')
        and (record.get('application_helper') is None or record.get('application_helper') is False)
        and 'qualification_role' not in record and 'qualification_service_cleanup' not in record
        and 'qualification_preworker_cleanup' not in record
        and not str(record.get('client_mode', '')).startswith('qualification-'))
    cid_matches = record.get('container_id') == selected['container_id']
    # Ordinary Registry.intent stores launch identity independently of the
    # ledger's observed CID. Service/helper records retain the exact-CID rule.
    need(cid_matches or (ordinary_worker and record.get('container_id') is None))
    need(record.get('launch_id') == selected['launch_id'] and record.get('registry') == selected['registry']
         and record.get('generation') == selected['generation'] and record.get('image') == selected['image']
         and record.get('status') in STATES)
    immutable = {key: value for key, value in record.items() if key not in
                 ('status', 'container_id', 'qualification_service_cleanup', 'qualification_preworker_cleanup')}
    return {'role': selected['role'], 'declared_status': record['status'],
        'intent_binding_matches': sha(wire(immutable)) == selected['intent_sha256'],
        'sensitive_helper_declared': record.get('application_helper') is True,
        'service_proof_declared': 'qualification_service_cleanup' in record,
        'preworker_proof_declared': 'qualification_preworker_cleanup' in record,
        'physical_or_private_absence_verified': False, 'normal_registry_release_verified': False}


def validate_ownership_input(value):
    value = verify_preparation(value)
    need(value['kind'] == 'ownership')
    return value


def deny_unsafe_original_ownership(descriptor, *, lease_fd, lock_path, registry_root):
    """Denial-only original before_registry hook, never reconciliation/clearance.

    The controller must bind permission for these exact six reads before entry.
    This function neither acquires another flock nor constructs a Registry.
    A return only allows the unchanged original reconciliation to proceed.
    """
    descriptor = validate_ownership_input(descriptor)
    need(type(lease_fd) is int and lease_fd >= 0 and str(Path(lock_path).absolute()) == LOCK
         and str(Path(registry_root).absolute()) == REGISTRY)
    parent = directory(Path(LOCK).parent)
    reader = Reader()
    try:
        held = os.fstat(lease_fd); named = os.stat(Path(LOCK).name, dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISREG(held.st_mode) and held.st_uid == os.getuid() and held.st_nlink == 1
             and stat.S_IMODE(held.st_mode) == 0o600 and signature(held) == signature(named))
        start, wall = time.monotonic(), time.time()
        timer, interval = signal.getitimer(signal.ITIMER_REAL)
        need(not interval and math.isfinite(timer) and (timer == 0 or timer > 30))
        end = start + min(120., timer - 30 if timer else 120.)
        def within():
            need(start <= time.monotonic() < end and wall <= time.time() < wall + 120)
        reader.deadline_check = within
        for selected in descriptor['selection']['records']:
            record = decode(reader.read(selected['path'], 1048576))
            projected = owner_projection(record, selected)
            need(projected['declared_status'] == 'released' and projected['intent_binding_matches'] is True)
        reader.fence()
        need(signature(held) == signature(os.fstat(lease_fd)) == signature(os.stat(Path(LOCK).name, dir_fd=parent, follow_symlinks=False)))
    finally:
        try: reader.close()
        finally: os.close(parent)


@contextlib.contextmanager
def readonly_original_lock(deadline):
    parent = directory(Path(LOCK).parent); fd = None
    try:
        fd = os.open(Path(LOCK).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        held = os.fstat(fd)
        need(stat.S_ISREG(held.st_mode) and held.st_uid == os.getuid() and held.st_nlink == 1 and stat.S_IMODE(held.st_mode) == 0o600)
        until = min(deadline, time.monotonic() + 30)
        while True:
            try: fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB); break
            except BlockingIOError:
                need(time.monotonic() < until); time.sleep(min(.05, max(0, until - time.monotonic())))
        need(signature(held) == signature(os.stat(Path(LOCK).name, dir_fd=parent, follow_symlinks=False)))
        yield
        need(signature(held) == signature(os.fstat(fd)) == signature(os.stat(Path(LOCK).name, dir_fd=parent, follow_symlinks=False)))
    finally:
        if fd is not None: os.close(fd)
        os.close(parent)


def ownership_observation(selection, reader, deadline):
    validate_selection(selection); rows = []
    with readonly_original_lock(deadline):
        for selected in selection['records']:
            need(time.monotonic() < deadline)
            rows.append(owner_projection(decode(reader.read(selected['path'], 1048576)), selected))
        reader.fence()
    return {'kind': 'ownership', 'records': rows, 'status': 'SELECTED_RECORD_DECLARATIONS_OBSERVED',
        'normal_SDK_admission_still_required': True, 'ownership_clearance': False,
        'private_flags_cleared': False, 'references_followed': False}


def bridge_projection(info, networks):
    need(type(info) is dict and info.get('ID') == DAEMON and info.get('OSType') == 'linux'
         and info.get('Architecture') in ('arm64', 'aarch64'))
    need(type(networks) is list and len(networks) == 1)
    network = networks[0]
    need(type(network) is dict and network.get('Name') == 'bridge' and network.get('Driver') == 'bridge'
         and network.get('Scope') == 'local' and type(network.get('IPAM')) is dict)
    configs = network['IPAM'].get('Config')
    need(type(configs) is list and len(configs) == 1 and type(configs[0]) is dict)
    import ipaddress
    subnet = ipaddress.ip_network(configs[0].get('Subnet'), strict=True)
    need(subnet.version == 4 and subnet.is_private and configs[0].get('Gateway') == '172.17.0.1'
         and ipaddress.ip_address('172.17.0.1') in subnet)
    return {'kind': 'bridge', 'status': 'DEFAULT_BRIDGE_CONFIGURATION_MATCHES', 'daemon_matches': True,
        'linux_arm64': True, 'gateway_matches': True, 'private_subnet': True,
        'server_listener_exposure': 'NOT_OBSERVED', 'container_reachability': 'NOT_OBSERVED',
        'ownership_clearance': False, 'dispatch_ready': False}


def bridge_observation(deadline, costs, *, wall_deadline=None):
    values = []
    for argv in (['docker', 'info', '--format', '{{json .}}'], ['docker', 'network', 'inspect', 'bridge']):
        need(time.monotonic() < deadline and (wall_deadline is None or time.time() < wall_deadline))
        costs['docker_queries'] += 1; need(costs['docker_queries'] <= 2)
        process = None
        selector = None
        buffers = [bytearray(), bytearray()]
        costs['constructor_uncertain'] = True
        try:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            costs['constructor_uncertain'] = False
            selector = selectors.DefaultSelector()
            for index, stream in enumerate((process.stdout, process.stderr)):
                os.set_blocking(stream.fileno(), False); selector.register(stream, selectors.EVENT_READ, index)
            until = min(deadline, time.monotonic() + 15)
            while selector.get_map():
                need(time.monotonic() < until and (wall_deadline is None or time.time() < wall_deadline))
                for key, _ in selector.select(min(.1, max(0, until - time.monotonic()))):
                    block = os.read(key.fd, 65536)
                    if not block: selector.unregister(key.fileobj); continue
                    buffers[key.data].extend(block)
                    need(sum(map(len, buffers)) <= 1048576)
            process.wait(timeout=max(.001, until - time.monotonic()))
            raw, error = map(bytes, buffers)
            need(process.returncode == 0 and len(raw) + len(error) <= 1048576)
            values.append(decode(raw))
        finally:
            if selector is not None: selector.close()
            if process is not None:
                if process.poll() is None: os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=5)
                process.stdout.close(); process.stderr.close()
                costs['returned_handles'] += 1
                need(process.returncode is not None and process.stdout.closed and process.stderr.closed)
    return bridge_projection(*values)


def authorize(prepared_raw, grant_raw, review_raw):
    prepared = verify_preparation(decode(prepared_raw, 65536)); grant = decode(grant_raw, 16384); review = decode(review_raw, 16384)
    need(type(grant) is dict and set(grant) == {'schema', 'document_type', 'status', 'authorization_id', 'kind',
        'preparation_sha256', 'source_sha256', 'issued_wall', 'deadline_wall', 'max_attempts', 'effects'})
    need(type(grant['schema']) is int and grant['schema'] == 1 and grant['document_type'] == 'bounded_settlement_check_grant'
         and grant['status'] == 'AUTHORIZED_CHECK_ONLY' and grant['kind'] == prepared['kind']
         and grant['preparation_sha256'] == sha(prepared_raw) and grant['source_sha256'] == sha(Path(__file__).read_bytes())
         and type(grant['max_attempts']) is int and grant['max_attempts'] == 1)
    identifier(grant['authorization_id'])
    for key in ('issued_wall', 'deadline_wall'): need(type(grant[key]) in (int, float) and math.isfinite(grant[key]))
    need(0 < grant['deadline_wall'] - grant['issued_wall'] <= 900 and grant['issued_wall'] <= time.time() < grant['deadline_wall'])
    effects = {'containers': 0, 'participants': 0, 'model_business_calls': 0, 'record_writes': 0,
               'docker_queries': 2 if prepared['kind'] == 'bridge' else 0}
    need(grant['effects'] == effects and all(type(grant['effects'][key]) is int for key in effects))
    need(type(review) is dict and type(review.get('schema')) is int and review.get('supports_check_only') is True
         and review == {'schema': 1, 'document_type': 'independent_bounded_settlement_check_review', 'status': 'PASS',
        'grant_sha256': sha(grant_raw), 'preparation_sha256': sha(prepared_raw), 'source_sha256': grant['source_sha256'],
        'supports_check_only': True, 'unresolved': []})
    return prepared, grant


def _run_check(prepared_path, grant_path, review_path, output, reader, *, started, started_wall, hard_deadlines):
    prepared_path, grant_path, review_path = map(lambda value: Path(value).absolute(), (prepared_path, grant_path, review_path))
    need(prepared_path in {Path(OUTPUT_BASE) / kind / 'PREPARATION.json' for kind in KINDS}
         and grant_path == prepared_path.parent / 'grant.json' and review_path == prepared_path.parent / 'review.json')
    costs = {'docker_queries': 0, 'returned_handles': 0, 'constructor_uncertain': False}; data = None; ok = False
    try:
        raw = reader.read(prepared_path, 65536, target=False)
        grant_raw = reader.read(grant_path, 16384, target=False); review_raw = reader.read(review_path, 16384, target=False)
        prepared, grant = authorize(raw, grant_raw, review_raw)
        need(prepared['kind'] == prepared_path.parent.name)
        user = pwd.getpwuid(os.getuid())
        need(os.getuid() == 1000 and user.pw_name == 'piqual' and user.pw_dir == os.environ.get('HOME') == '/home/piqual'
             and os.uname().machine == 'aarch64')
        need(not any(os.environ.get(name) for name in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG',
             'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'DOCKER_API_VERSION')))
    except BaseException:
        reader.close(); raise
    start, wall = started, started_wall
    hard_deadlines[0] = min(hard_deadlines[0], start + grant['deadline_wall'] - wall)
    hard_deadlines[1] = min(hard_deadlines[1], grant['deadline_wall'])
    hard = hard_deadlines[0]
    end = min(start + 120, hard - 6)
    need(start <= time.monotonic() < end and wall <= time.time() < hard_deadlines[1] - 6)
    reader.deadline_check = lambda: need(start <= time.monotonic() < end and wall <= time.time() < min(wall + 120, hard_deadlines[1] - 6))
    signal.setitimer(signal.ITIMER_REAL, max(.001, min(end - time.monotonic(), hard_deadlines[1] - time.time() - 6)))
    output = Path(output).absolute()
    try:
        need(str(output) == prepared['output'] and not output.exists() and not output.is_symlink())
        parent = directory(output.parent)
        try:
            info = os.fstat(parent); need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
            os.mkdir(output.name, 0o700, dir_fd=parent)
        finally: os.close(parent)
        save(output / 'intent.json', {'schema': 1, 'action': prepared['kind'], 'authorization_id': grant['authorization_id'], 'max_attempts': 1})
    except BaseException:
        reader.close(); signal.setitimer(signal.ITIMER_REAL, 0); raise
    try:
        if prepared['kind'] == 'ownership':
            data = ownership_observation(prepared['selection'], reader, end)
        else:
            with readonly_original_lock(end):
                data = bridge_observation(end, costs, wall_deadline=grant['deadline_wall'] - 6)
        reader.fence(); ok = True
    except BaseException:
        ok = False
    finally:
        try: reader.close()
        except OSError: ok = False
        result = {'schema': 1, 'status': 'OBSERVATION_COMPLETE' if ok else 'CHECK_INCOMPLETE', 'kind': prepared['kind'],
            'projection': data, 'record_attempts': reader.attempts, 'record_bytes': reader.bytes, 'costs': costs,
            'elapsed_seconds': time.monotonic() - start, 'normal_SDK_admission_still_required': True,
            'clearance_or_dispatch_authority': False, 'original_or_record_writes': 0,
            'raw_bodies_values_hashes_exception_text_exported': False, 'no_automatic_retry': True}
        save(output / 'result.json', result); signal.setitimer(signal.ITIMER_REAL, 0)
    return result


def run_check(prepared_path, grant_path, review_path, output):
    # Standalone check entries cannot borrow or reset another owner's deadline.
    timer = signal.getitimer(signal.ITIMER_REAL)
    need(timer == (0., 0.) and signal.SIGALRM not in signal.sigpending())
    previous_handler = signal.getsignal(signal.SIGALRM)
    started, wall = time.monotonic(), time.time()
    hard_deadlines = [started + 126, wall + 126]
    def expired(*_):
        signal.signal(signal.SIGALRM, lambda *_: os._exit(124))
        signal.setitimer(signal.ITIMER_REAL, max(.001, min(hard_deadlines[0] - time.monotonic(), hard_deadlines[1] - time.time())))
        raise TimeoutError('BOUNDED_CHECK_DEADLINE')
    reader = Reader()
    reader.deadline_check = lambda: need(started <= time.monotonic() < started + 120 and wall <= time.time() < wall + 120)
    try:
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, 120)
        return _run_check(prepared_path, grant_path, review_path, output, reader,
                          started=started, started_wall=wall, hard_deadlines=hard_deadlines)
    finally:
        try: reader.close()
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_handler)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__); commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('prepare'); p.add_argument('--kind', choices=KINDS, required=True); p.add_argument('--output', required=True)
    p.add_argument('--snapshot'); p.add_argument('--snapshot-sha256')
    p = commands.add_parser('check')
    for name in ('prepared', 'grant', 'review', 'output'): p.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'prepare':
            selected = None
            if args.kind == 'ownership':
                need(args.snapshot is not None and args.snapshot_sha256 is not None)
                selected = selection_from_snapshot(Path(args.snapshot).read_bytes(), args.snapshot_sha256)
            else: need(args.snapshot is None and args.snapshot_sha256 is None)
            save(Path(args.output), preparation(args.kind, selected)); status = 'DISABLED_PREPARED'
        else:
            status = run_check(args.prepared, args.grant, args.review, args.output)['status']
        print(json.dumps({'status': status, 'clearance_or_dispatch_authority': False})); return 0 if status in ('DISABLED_PREPARED', 'OBSERVATION_COMPLETE') else 2
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        print(json.dumps({'status': 'DISABLED_OR_REFUSED', 'raw_exception_exported': False})); return 2


if __name__ == '__main__':
    raise SystemExit(main())
