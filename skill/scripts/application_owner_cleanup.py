"""Scoped parent-file cleanup with separately retained owner custody evidence.

This module never dispatches an agent, model, application request or container.
Terminal witnesses are parent-owned records, not child reports or PASS labels.
Unknown historical evidence formats require an owner-side adapter; they are not
guessed from exception strings, PID absence or qualification classifications.
"""
import hashlib
import contextlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import uuid

import ownership_registry as ownership
import registry_diagnostics as diagnostics
import stage_control as controls

MAX_BYTES = 4 * 1024 * 1024
MAX_REFERENCES = 128
MAX_AGGREGATE_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 4096
REQUEST_FIELDS = {'schema', 'document_type', 'subject', 'shape', 'controller', 'launchers',
                  'snapshot', 'stages', 'extra_private_roots'}
INVOCATION_FIELDS = {'schema', 'document_type', 'pid', 'argv', 'cwd', 'runroot',
                     'registry', 'generation', 'launch_ids'}
TERMINAL_FIELDS = {'schema', 'document_type', 'invocation', 'pid', 'argv', 'cwd', 'actual_exit'}
CUSTODY_FIELDS = {'schema', 'document_type', 'subject', 'lease', 'workspace', 'events', 'cleanup',
                  'writers_absent', 'recorded_at', 'directory_identity', 'launcher_argv', 'launcher',
                  'guard', 'terminal', 'snapshot'}


def require(value, condition='cleanup_proof_invalid'):
    if not value:
        raise ownership.RegistryError('Application owner cleanup proof is incomplete or changed', condition=condition)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def exact(value, fields):
    require(type(value) is dict and set(value) == set(fields))


def path(value):
    require(type(value) is str and 0 < len(value) <= 4096 and value.startswith('/')
            and not value.startswith('//') and str(Path(value)) == value and value != '/'
            and '..' not in Path(value).parts and not any(ord(c) < 32 or ord(c) == 127 for c in value), 'unsafe_path')
    return Path(value)


@diagnostics.observed('directory_open')
def directory(value):
    value = path(str(value)); fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in value.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        info = os.fstat(fd)
        require(info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o022, 'unsafe_path')
        return fd
    except BaseException:
        os.close(fd); raise


def identity(info):
    return [info.st_dev, info.st_ino]


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result); result[key] = value
    return result


class Reader:
    def __init__(self):
        self.references = {}; self.bytes = 0; self.private_paths = set(); self.private_parent_paths = set(); self._scopes = []
        self.maximums = {}

    @contextlib.contextmanager
    def custody_scope(self):
        """Track consulted evidence without resetting the shared graph budget."""
        selected = set(); self._scopes.append(selected)
        try:yield
        finally:require(self._scopes.pop() is selected)

    def scope_references(self):
        require(bool(self._scopes))
        return [self.references[name] for name in sorted(self._scopes[-1])]

    @diagnostics.observed('proof_read')
    def read_bytes(self, value, *, private=False, parent_fd=None, private_parent=None, maximum=None):
        """Read one stable file; JSON and source bytes share custody and limits."""
        value = path(str(value))
        limit = MAX_BYTES if maximum is None else maximum
        require(type(limit) is int and 0 <= limit <= MAX_BYTES, 'inventory_unbounded')
        limit = min(limit, self.maximums.get(str(value), limit)); self.maximums[str(value)] = limit
        require(type(private) is bool and (private_parent is None or type(private_parent) is bool))
        requested_parent = private if private_parent is None else private_parent
        if private:self.private_paths.add(str(value))
        if requested_parent:self.private_parent_paths.add(str(value))
        private = str(value) in self.private_paths
        private_parent = str(value) in self.private_parent_paths
        require(parent_fd is None or type(parent_fd) is int)
        parent = directory(value.parent) if parent_fd is None else os.dup(parent_fd)
        try:
            require(not stat.S_IMODE(os.fstat(parent).st_mode) & (0o077 if private_parent else 0o022), 'unsafe_path')
            fd = os.open(value.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            with os.fdopen(fd, 'rb') as stream:
                before = os.fstat(stream.fileno())
                require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1
                        and not stat.S_IMODE(before.st_mode) & (0o077 if private else 0o022)
                        and before.st_size <= limit, 'unsafe_record')
                if str(value) not in self.references:
                    require(len(self.references) < MAX_REFERENCES
                            and self.bytes + before.st_size <= MAX_AGGREGATE_BYTES, 'inventory_unbounded')
                body = stream.read(limit + 1); after = os.fstat(stream.fileno())
                named = os.stat(value.name, dir_fd=parent, follow_symlinks=False)
                signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)
                require(signature(before) == signature(after) == signature(named) and len(body) == before.st_size)
            held = os.fstat(parent)
            require(held.st_uid == os.getuid() and not stat.S_IMODE(held.st_mode) & (0o077 if private_parent else 0o022),
                    'unsafe_path')
            current_parent = directory(value.parent)
            try:require(identity(os.fstat(current_parent)) == identity(held), 'unsafe_path')
            finally:os.close(current_parent)
            ref = {'path': str(value), 'sha256': hashlib.sha256(body).hexdigest()}
            if str(value) not in self.references:
                self.bytes += len(body)
                require(len(self.references) < MAX_REFERENCES and self.bytes <= MAX_AGGREGATE_BYTES, 'inventory_unbounded')
            else:require(self.references[str(value)] == ref)
            self.references[str(value)] = ref
            for scope in self._scopes:scope.add(str(value))
            return body, ref
        finally:os.close(parent)

    @diagnostics.observed('proof_read')
    def read(self, value, *, private=False, parent_fd=None, private_parent=None):
        body, ref = self.read_bytes(value, private=private, parent_fd=parent_fd, private_parent=private_parent)
        def number(value):
            result = float(value); require(math.isfinite(result), 'malformed_record')
            return result
        try:
            result = json.loads(body, object_pairs_hook=pairs, parse_float=number,
                                parse_constant=lambda unused: require(False, 'malformed_record'))
        except ownership.RegistryError:raise
        except (ValueError, UnicodeError, RecursionError, OverflowError):
            require(False, 'malformed_record')
        require(type(result) is dict)
        return result, ref

    def reference(self, ref, *, private=False, private_parent=None):
        exact(ref, {'path', 'sha256'})
        require(type(ref['sha256']) is str and re.fullmatch('[a-f0-9]{64}', ref['sha256']) is not None)
        options = {'private': private}
        if private_parent is not None:options['private_parent'] = private_parent
        result, observed = self.read(ref['path'], **options); require(observed == ref)
        return result

    def reference_bytes(self, ref, *, private=False, private_parent=None):
        exact(ref, {'path', 'sha256'})
        require(type(ref['sha256']) is str and re.fullmatch('[a-f0-9]{64}', ref['sha256']) is not None)
        result, observed = self.read_bytes(ref['path'], private=private, private_parent=private_parent); require(observed == ref)
        return result


def subject(record):
    require(type(record) is dict and record.get('application_helper') is True
            and 'qualification_preworker_cleanup' not in record
            and 'qualification_service_cleanup' not in record and 'qualification_role' not in record
            and record.get('client_mode') in ('application-execution', 'authority-only', 'budget-only'))
    for field in ('generation', 'launch_id'):require(controls.valid_id(record.get(field)))
    require(type(record.get('registry')) is str and re.fullmatch('[a-f0-9]{64}', record['registry']) is not None)
    cid = record.get('container_id')
    require(cid is None or type(cid) is str and re.fullmatch('[a-f0-9]{64}', cid) is not None and cid != '0' * 64)
    code = record.get('code_identity')
    require(type(code) is dict and 1 <= len(code) <= 64 and all(type(k) is str and 0 < len(k) <= 256
            and not Path(k).is_absolute() and '..' not in Path(k).parts and type(v) is str
            and re.fullmatch('[a-f0-9]{64}', v) is not None for k, v in code.items()))
    require(type(record.get('binding')) is dict)
    immutable = {k: v for k, v in record.items() if k not in ('status', 'container_id')}
    return {'registry': record['registry'], 'generation': record['generation'], 'launch_id': record['launch_id'],
            'intent_sha256': digest(immutable), 'container_id': cid}


def store_path(registry):
    return registry.root.with_name(registry.root.name + '.owner-proofs')


def lease_identity(registry):
    import registry_maintenance as maintenance
    require(registry.root.name.endswith('.registry'), 'unsafe_path')
    lease = registry.root.with_name(registry.root.name[:-9])
    fd = getattr(registry, 'lease_fd', None)
    require(type(fd) is int, 'lease_changed')
    observed = maintenance._check_lock(fd, lease)
    require(registry.root == lease.parent.resolve() / (lease.name + '.registry'), 'lease_changed')
    return observed


def validate_launcher_arguments(argv, record):
    """Validate original or source-derived argv without making a witness."""
    require(argv[:2] == ['docker', 'run'] and argv.count('--name') == 1
            and argv[argv.index('--name') + 1] == record['container']
            and record['image'] in argv)
    labels = [argv[i + 1] for i, arg in enumerate(argv[:-1]) if arg == '--label']
    require(sorted(labels) == sorted([ownership.LABEL + '=' + record['launch_id'],
                                     ownership.REGISTRY_LABEL + '=' + record['registry']]))
    image_at = argv.index(record['image']); require(argv.count(record['image']) == 1 and image_at + 1 < len(argv)
                                                   and argv[image_at + 1] in (
                                                       '/opt/pi-application/runtime/application_client_service.py',
                                                       '/opt/pi-lab/worker.py'))
    switches = {'--pull=never', '--interactive', '--init', '--read-only', '--cap-drop=ALL',
                '--security-opt=no-new-privileges=true', '--ipc=none', '--entrypoint=python3',
                '--workdir=/pi-client/state'}
    valued = {'--name', '--label', '--mount', '--platform', '--user', '--security-opt', '--pids-limit',
              '--memory', '--memory-swap', '--cpus', '--network', '--network-alias', '--publish',
              '--workdir', '--env', '--tmpfs', '--ulimit', '--add-host'}
    position = 2
    while position < image_at:
        option = argv[position]
        if option in switches:position += 1; continue
        require(option in valued and position + 1 < image_at)
        value = argv[position + 1]
        if option == '--platform':require(value == 'linux/arm64')
        if option == '--network':require(value not in ('host', 'container'))
        if option == '--env' and record.get('application_helper') is True:
            require(value in ('PYTHONDONTWRITEBYTECODE=1', 'PYTHONUNBUFFERED=1',
                              'HOME=/pi-client/state/private/home', 'TMPDIR=/pi-client/state/private/tmp'))
        position += 2
    mounts = []
    for i, option in enumerate(argv[:-1]):
        if option != '--mount':continue
        parts = argv[i + 1].split(','); fields = dict(p.split('=', 1) for p in parts if '=' in p)
        require(fields.get('type') == 'bind' and set(fields) <= {'type', 'src', 'dst', 'bind-recursive'})
        mounts.append({'source': fields.get('src'), 'target': fields.get('dst'), 'rw': 'readonly' not in parts})
    require(mounts == record['mounts'])


def _terminal(reader, witnesses, record, launch_ids, *, replay=False, launcher=False):
    exact(witnesses, {'invocation', 'terminal'})
    invocation = reader.reference(witnesses['invocation']); terminal = reader.reference(witnesses['terminal'])
    exact(invocation, INVOCATION_FIELDS); exact(terminal, TERMINAL_FIELDS)
    require(type(invocation['schema']) is int and invocation['schema'] == 1
            and invocation['document_type'] == 'owned_process_invocation'
            and type(terminal['schema']) is int and terminal['schema'] == 1
            and terminal['document_type'] == 'owned_process_terminal')
    require(type(invocation['pid']) is int and 1 <= invocation['pid'] < 2**31
            and type(terminal['actual_exit']) is int and -255 <= terminal['actual_exit'] <= 255)
    argv = invocation['argv']
    require(type(argv) is list and 1 <= len(argv) <= 256 and all(type(a) is str and 0 < len(a) <= 8192
            and not any(ord(c) < 32 or ord(c) == 127 for c in a) for a in argv))
    path(invocation['cwd'])
    require(invocation['runroot'] == record['runroot'] and invocation['registry'] == record['registry']
            and invocation['generation'] == record['generation'] and invocation['launch_ids'] == sorted(launch_ids)
            and terminal['invocation'] == witnesses['invocation']
            and all(type(terminal[k]) is type(invocation[k]) and terminal[k] == invocation[k] for k in ('pid', 'argv', 'cwd')))
    if not launcher:require(invocation['pid'] == record.get('owner_pid'))
    else:validate_launcher_arguments(argv, record)
    if not replay:
        try:os.kill(invocation['pid'], 0)
        except ProcessLookupError:pass
        except OSError as exc:raise ownership.RegistryError('Owner process termination cannot be observed', cause=exc) from None
        else:require(False, 'owner_writer_pending')
    return invocation


def _stages(reader, root):
    stages = root / 'stages'; result = []; metadata = []
    try:fd = directory(stages)
    except FileNotFoundError:return result, metadata
    try:
        names = sorted(os.listdir(fd)); require(len(names) <= 256, 'inventory_unbounded')
        for name in names:
            require(controls.valid_id(name))
            desc, ref = reader.read(stages / name / 'descriptor.json'); metadata.append(ref)
            require(desc.get('stage_id') == name)
            require(desc.get('kind') in ('agent', 'check', 'probe', 'preflight', 'boundary', 'browser'), 'owner_scope_unsupported')
            if desc.get('kind') != 'agent':
                for target in (stages / name / 'state.json', stages / name / 'budget.json'):
                    try:body, ref = reader.read(target)
                    except FileNotFoundError:continue
                    metadata.append(ref)
                continue
            label = desc.get('label'); require(type(label) is str and re.fullmatch('[A-Za-z0-9_-]{1,128}', label) is not None)
            for target in (stages / name / 'state.json', stages / name / 'application-credentials.json', root / label / 'process.json'):
                body, ref = reader.read(target); metadata.append(ref)
            try:body, ref = reader.read(stages / name / 'budget.json')
            except FileNotFoundError:pass
            else:metadata.append(ref)
            result.append((name, desc))
    finally:os.close(fd)
    return result, metadata


def _root_scope(root, stages, record, snapshot, extra):
    require(type(extra) is list and len(extra) <= 8)
    roots = [root / 'workspace', path(record['private_store']), root / 'application-evidence' / record['container'],
             root / 'children' / '.pi-lab']
    require(roots[1].parent == root / 'application-helpers' and re.fullmatch('[a-f0-9]{32}', roots[1].name) is not None)
    expected = {'/opt/pi-application': (str(roots[1] / 'code'), False),
                '/pi-client/state': (str(roots[1] / 'state'), True),
                '/pi-client/evidence': (str(roots[2]), True)}
    require(type(record['mounts']) is list and len(record['mounts']) == 3)
    for mount in record['mounts']:
        exact(mount, {'source', 'target', 'rw'})
        require(type(mount['rw']) is bool and mount['target'] in expected
                and (mount['source'], mount['rw']) == expected.pop(mount['target']))
    for stage_id, desc in stages:
        require(desc.get('workspace') == str(root / 'workspace') and desc.get('workspace_identity') == snapshot['workspace_identity'])
        require(all(desc.get(k) == record['binding'][k] for k in ('run_id', 'attempt_id') if k in record['binding']))
        # Segment state has UUID identities; all are within this exact owned child root.
        segments = root / 'controls' / stage_id / 'segments'
        try:fd = directory(segments)
        except FileNotFoundError:continue
        try:
            names = os.listdir(fd); require(len(names) <= 256, 'inventory_unbounded')
            for name in names:
                require(controls.valid_id(name))
        finally:os.close(fd)
    return sorted(set(roots), key=str)


def _control_scope(reader, root, metadata, record):
    """An empty agent list must not conceal an unexplained control tree."""
    stage_ids = sorted({Path(ref['path']).parent.name for ref in metadata
                        if Path(ref['path']).name == 'descriptor.json'
                        and Path(ref['path']).parent.parent == root / 'stages'})
    roots = [root / 'controls' / stage / name for stage in stage_ids for name in ('segments', 'inbox', 'outbox')]
    try:fd = directory(root / 'controls')
    except FileNotFoundError:return roots
    try:
        names = sorted(os.listdir(fd)); require(len(names) <= 256, 'inventory_unbounded')
        for stage in names:
            require(stage in stage_ids, 'owner_scope_unsupported')
            descriptor = reader.reference(next(ref for ref in metadata if ref['path'] == str(root / 'stages' / stage / 'descriptor.json')))
            require(all(descriptor.get(k) == record['binding'][k] for k in ('run_id', 'attempt_id') if k in record['binding']),
                    'sensitive_identity_mismatch')
            child = directory(root / 'controls' / stage)
            try:
                leaves = sorted(os.listdir(child)); require(len(leaves) <= 256, 'inventory_unbounded')
                for leaf in leaves:
                    if leaf in ('segments', 'inbox', 'outbox'):continue
                    require(leaf in ('task.json', 'endpoint.json', 'stage.json', 'challenge.json'), 'owner_scope_unsupported')
                    body, ref = reader.read(root / 'controls' / stage / leaf); metadata.append(ref)
            finally:os.close(child)
    finally:os.close(fd)
    return roots


def _retained_namespace(reader, root, metadata, discarded):
    """Failed histories need a complete recognized retained namespace.

    Uninspected raw logs/runtime copies are not silently called key-free. Their
    owner must supply a reviewed historical adapter instead of deleting history.
    """
    known = {path(ref['path']) for ref in [*metadata, *reader.references.values()]}
    skip = [path(item['path']) for item in discarded if path(item['path']).is_relative_to(root)]
    count = [0]
    def walk(fd, folder):
        names = sorted(os.listdir(fd)); count[0] += len(names)
        require(count[0] <= MAX_ENTRIES, 'inventory_unbounded')
        for name in names:
            target = folder / name
            if target in skip:continue
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            require(info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o022, 'unsafe_path')
            if stat.S_ISDIR(info.st_mode):
                require(any(target in p.parents for p in [*known, *skip]), 'owner_scope_unsupported')
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    require(identity(os.fstat(child)) == identity(info), 'sensitive_identity_mismatch')
                    walk(child, target)
                    require(identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) == identity(info), 'sensitive_identity_mismatch')
                finally:os.close(child)
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'unsafe_path')
                lock = target == root / 'control.lock' or target.name == 'lock' and target.parent.parent == root / 'stages'
                require(target in known or lock and info.st_size == 0, 'owner_scope_unsupported')
                if target not in known:
                    metadata.append({'path': str(target), 'sha256': hashlib.sha256(b'').hexdigest()})
    fd = directory(root)
    try:walk(fd, root)
    finally:os.close(fd)


def _parent_scopes(invocation, reference, extra):
    """Recognize the existing private-envelope binding, without deleting it."""
    argv = invocation['argv']; expected = []
    require(not any(a.split('=', 1)[0] in ('--application-context', '--native-budget-context') for a in argv),
            'owner_scope_unsupported')
    envelopes = [i for i, arg in enumerate(argv) if arg == '--private-envelope' or arg.startswith('--private-envelope=')]
    if envelopes:
        require(len(envelopes) == 1)
        position = envelopes[0]
        if argv[position] == '--private-envelope':
            require(position + 1 < len(argv)); value = argv[position + 1]
        else:value = argv[position].split('=', 1)[1]
        envelope = path(value)
        require(envelope.name == 'initial.json' and envelope.parent.name.startswith('pi-qualification-cell-'), 'owner_scope_unsupported')
        expected = [{'path': str(envelope.parent), 'origin': reference}]
    require(extra == expected, 'owner_scope_unsupported')
    scopes = [_root_observation(item['path']) for item in expected]
    require(all(item['state'] == 'absent' for item in scopes), 'owner_scope_unsupported')
    return scopes


def _root_observation(value):
    value = path(str(value))
    if ownership._qualification_absent(str(value)):
        return {'path': str(value), 'identity': None, 'state': 'absent'}
    fd = directory(value)
    try:return {'path': str(value), 'identity': identity(os.fstat(fd)), 'state': 'present'}
    finally:os.close(fd)


def _guard_identity(reader, record, launcher):
    """Use a retained real CID; terminal/name absence is not a create barrier."""
    require('identity' in launcher, 'owner_identity_required')
    guard = reader.reference(launcher['identity'])
    fields = {'registry', 'generation', 'launch_id', 'daemon', 'container', 'image', 'mounts'}
    exact(guard, fields | {'schema', 'document_type', 'container_id', 'intent_sha256', 'invocation'})
    require(type(guard['schema']) is int and guard['schema'] == 1
            and guard['document_type'] == 'owned_container_identity'
            and all(canonical(guard[k]) == canonical(record[k]) for k in fields)
            and guard['intent_sha256'] == subject(record)['intent_sha256']
            and guard['invocation'] == launcher['invocation'], 'owner_identity_required')
    cid = guard['container_id']
    require(type(cid) is str and re.fullmatch('[a-f0-9]{64}', cid) is not None and cid != '0' * 64,
            'owner_identity_required')
    return {**record, 'container_id': cid}


def _owned_snapshot(reader, reference, record):
    snapshot = reader.reference(reference)
    exact(snapshot, {'schema', 'document_type', 'registry', 'generation', 'runroot', 'binding', 'workspace', 'workspace_identity'})
    require(type(snapshot['schema']) is int and snapshot['schema'] == 1 and snapshot['document_type'] == 'application_owned_snapshot'
            and all(snapshot[k] == record[k] for k in ('registry', 'generation', 'runroot', 'binding'))
            and snapshot['workspace'] == str(path(record['runroot']) / 'workspace')
            and type(snapshot['workspace_identity']) is list and len(snapshot['workspace_identity']) == 2
            and all(type(x) is int and x >= 0 for x in snapshot['workspace_identity']) and snapshot['workspace_identity'][1] > 0)
    return snapshot


def _request_method(request):
    require(type(request) is dict and type(request.get('schema')) is int)
    if request['schema'] == 1:
        exact(request, REQUEST_FIELDS)
        return 'retained_terminals'
    require(request['schema'] == 2, 'owner_legacy_unsupported')
    import application_owner_legacy_protocol as legacy_protocol
    legacy_protocol.request_shape(request)
    return 'legacy_derived_v1'


def _prepare(registry, request, *, replay=False, reader=None):
    if _request_method(request) == 'legacy_derived_v1':
        import application_owner_legacy_protocol as legacy_protocol
        return legacy_protocol.prepare(registry, request, reader=reader)
    return _prepare_retained(registry, request, replay=replay, reader=reader)


def _prepare_retained(registry, request, *, replay=False, reader=None):
    exact(request, REQUEST_FIELDS)
    exact(request['subject'], {'registry', 'generation', 'launch_id', 'intent_sha256', 'container_id'})
    require(type(request['schema']) is int and request['schema'] == 1
            and request['document_type'] == 'application_owner_cleanup_request'
            and request['shape'] in ('agent', 'helper_only', 'interrupted'))
    current = registry.load(); matches = [r for r in current if r['launch_id'] == request.get('subject', {}).get('launch_id')]
    require(len(matches) == 1); record = matches[0]; require(subject(record) == request['subject'])
    require(record['status'] == 'released', 'owned_application_cleanup_required')
    root = path(record['runroot']); root_fd = directory(root); os.close(root_fd)
    # A proof cannot spill to another run or borrow another generation's custody.
    related = sorted((r for r in current if r.get('runroot') == str(root)), key=lambda r: r['launch_id'])
    require(all(r['generation'] == record['generation'] and r['registry'] == record['registry']
                and r.get('daemon') == record['daemon'] and not r.get('inference_uncertain')
                and not r.get('gateway_state') and r.get('kind', 'container') == 'container' for r in related))
    require(len(related) <= 64 and type(record.get('daemon')) is str and bool(record['daemon']))
    ids = sorted(r['launch_id'] for r in related)
    reader = Reader() if reader is None else reader
    controller = _terminal(reader, request['controller'], record, ids, replay=replay)
    parent_scopes = _parent_scopes(controller, request['controller']['invocation'], request['extra_private_roots'])
    require(type(request['launchers']) is list and len(request['launchers']) == len(ids))
    launchers = {}
    for item in request['launchers']:
        require(type(item) is dict and set(item) in ({'launch_id', 'invocation', 'terminal'},
                                                   {'launch_id', 'invocation', 'terminal', 'identity'}))
        require(item['launch_id'] not in launchers)
        launchers[item['launch_id']] = item
    require(sorted(launchers) == ids)
    physical = []
    for row in related:
        item = launchers[row['launch_id']]
        _terminal(reader, {k: item[k] for k in ('invocation', 'terminal')}, row,
                  [row['launch_id']], replay=replay, launcher=True)
        if row.get('application_helper') is True and row.get('container_id') is None:
            physical.append(_guard_identity(reader, row, item))
        else:
            require('identity' not in item)
            physical.append(row)
    snapshot = _owned_snapshot(reader, request['snapshot'], record)
    stages, metadata = _stages(reader, root)
    require(type(request['stages']) is list and request['stages'] == [s[0] for s in stages])
    require((request['shape'] != 'helper_only' or not stages)
            and (request['shape'] != 'agent' or bool(stages))
            and (request['shape'] != 'interrupted' or record.get('container_id') is None))
    for target in ('identity.json', 'result.json', 'plan.json'):
        try:body, ref = reader.read(root / target)
        except FileNotFoundError:continue
        metadata.append(ref)
    scopes = _root_scope(root, stages, record, snapshot, request['extra_private_roots'])
    scopes += _control_scope(reader, root, metadata, record)
    roots = [_root_observation(p) for p in sorted(set(scopes), key=str)] + parent_scopes
    workspace = next(r for r in roots if r['path'] == str(root / 'workspace'))
    if workspace['state'] == 'present':require(workspace['identity'] == snapshot['workspace_identity'], 'sensitive_identity_mismatch')
    _retained_namespace(reader, root, metadata, roots)
    # Custody evidence must remain parent-owned and outside discarded scopes.
    for ref in reader.references.values():
        target = path(ref['path'])
        require(not any(target == Path(r['path']) or Path(r['path']) in target.parents for r in roots), 'unsafe_path')
    return record, related, reader, metadata, roots, physical


def _exact_absent(reply, target):
    return reply.returncode != 0 and re.fullmatch(
        r'(?:(?:Error response from daemon|Error): )?No such (?:container|object):? ' + re.escape(target), reply.stderr.strip()) is not None


def _writers_absent(registry, records):
    with diagnostics.operation('daemon_info'):
        reply = registry.command(['docker', 'info', '--format', '{{.ID}}'])
    require(reply.returncode == 0 and all(r['daemon'] == reply.stdout.strip() for r in records), 'daemon_changed')
    for row in records:
        cid = row.get('container_id'); require(cid is None or type(cid) is str and re.fullmatch('[a-f0-9]{64}', cid) is not None)
        target = cid or row['container']
        with diagnostics.operation('container_inspect'):
            observed = registry.command(['docker', 'container', 'inspect', target])
        require(_exact_absent(observed, target), 'writer_absence_unconfirmed')
        # Includes the no-CID case: an absent name cannot hide a renamed owned
        # container. Completed launcher witnesses separately exclude late create.
        with diagnostics.operation('container_inspect'):
            labelled = registry.command(['docker', 'ps', '--all', '--quiet', '--no-trunc', '--filter',
                'label=' + ownership.LABEL + '=' + row['launch_id'], '--filter',
                'label=' + ownership.REGISTRY_LABEL + '=' + registry.registry_id])
        require(labelled.returncode == 0 and labelled.stdout.strip() == '', 'writer_absence_unconfirmed')
    with diagnostics.operation('daemon_info'):
        final = registry.command(['docker', 'info', '--format', '{{.ID}}'])
    require(final.returncode == 0 and all(r['daemon'] == final.stdout.strip() for r in records), 'daemon_changed')


def _purge_names(fd, count):
    """Bound directory enumeration before retaining names in memory."""
    names = []; scan = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
    try:
        with os.scandir(scan) as entries:
            for entry in entries:
                count[0] += 1; require(count[0] <= MAX_ENTRIES, 'inventory_unbounded')
                names.append(entry.name)
    finally:os.close(scan)
    return sorted(names)


def _purge_signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _purge(observation, *, parent_fd=None, root_fd=None, checkpoint=None):
    if observation['state'] == 'absent':
        require(ownership._qualification_absent(observation['path']), 'sensitive_identity_mismatch'); return
    value = path(observation['path']); parent = directory(value.parent) if parent_fd is None else os.dup(parent_fd)
    count = [0]; chain = []
    def verify(parts, info, mutating=False):
        named = directory(value.parent)
        try:require(identity(os.fstat(named)) == identity(os.fstat(parent)), 'sensitive_identity_mismatch')
        finally:os.close(named)
        require(identity(os.stat(value.name, dir_fd=parent, follow_symlinks=False)) == observation['identity'], 'sensitive_identity_mismatch')
        for ancestor, name, child, expected in chain:
            require(identity(os.fstat(child)) == expected
                    and identity(os.stat(name, dir_fd=ancestor, follow_symlinks=False)) == expected, 'sensitive_identity_mismatch')
        if checkpoint is not None:checkpoint(parts, info, mutating)
    def empty(fd, prefix=()):
        names = _purge_names(fd, count)
        for name in names:
            parts = prefix + (name,)
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            require(info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o022, 'unsafe_path')
            require(info.st_dev == observation['identity'][0], 'sensitive_identity_mismatch')
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    require(identity(os.fstat(child)) == identity(info), 'sensitive_identity_mismatch')
                    chain.append((fd, name, child, identity(info))); verify(parts, info)
                    empty(child, parts)
                    require(identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) == identity(info), 'sensitive_identity_mismatch')
                    verify(parts, os.fstat(child), True)
                    with diagnostics.operation('purge', mutating=True):os.rmdir(name, dir_fd=fd)
                finally:
                    if chain and chain[-1][2] == child:chain.pop()
                    os.close(child)
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'unsafe_path')
                verify(parts, info)
                current = os.stat(name, dir_fd=fd, follow_symlinks=False)
                require(_purge_signature(current) == _purge_signature(info), 'sensitive_identity_mismatch')
                verify(parts, current, True)
                with diagnostics.operation('purge', mutating=True):os.unlink(name, dir_fd=fd)
    try:
        child = os.open(value.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent) if root_fd is None else os.dup(root_fd)
        try:
            require(identity(os.fstat(child)) == observation['identity'], 'sensitive_identity_mismatch')
            verify((), os.fstat(child))
            empty(child)
            require(identity(os.stat(value.name, dir_fd=parent, follow_symlinks=False)) == observation['identity'], 'sensitive_identity_mismatch')
            verify((), os.fstat(child), True)
            with diagnostics.operation('purge', mutating=True):os.rmdir(value.name, dir_fd=parent)
            with diagnostics.operation('directory_fsync', mutating=True):os.fsync(parent)
        finally:os.close(child)
    finally:os.close(parent)


def _index(registry, record):
    return store_path(registry) / (record['launch_id'] + '.json')


def _selection(registry, record):
    return store_path(registry) / 'selected' / (record['launch_id'] + '.json')


def _anchor(registry, record):
    return registry.root.with_name(registry.root.name + '.owner-selected') / (record['launch_id'] + '.json')


def _read_anchor(registry, record, reader):
    target = _anchor(registry, record)
    try:parent = directory(target.parent)
    except FileNotFoundError:
        require(getattr(registry, '_owner_anchor_identity', None) is None, 'unsafe_path')
        require(not os.path.lexists(target))
        return None
    try:
        require(not stat.S_IMODE(os.fstat(parent).st_mode) & 0o077, 'unsafe_path')
        _bind_directory(registry, '_owner_anchor_identity', parent)
        try:os.stat(target.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:value = None
        else:
            _remember_legacy_selection(registry, record)
            value, unused = reader.read(target, private=True, parent_fd=parent)
        named = directory(target.parent)
        try:require(identity(os.fstat(named)) == identity(os.fstat(parent)), 'unsafe_path')
        finally:os.close(named)
        return value
    finally:os.close(parent)


def _retained_selection(registry, record, reader):
    """A selected new method cannot be retried through the old native path."""
    require(record['launch_id'] not in getattr(registry, '_owner_legacy_selected_ids', set()), 'owner_proof_publication_incomplete')
    require(_read_anchor(registry, record, reader) is None, 'owner_proof_publication_incomplete')
    try:fd = directory(store_path(registry))
    except FileNotFoundError:
        require(getattr(registry, '_owner_proof_store_identity', None) is None, 'unsafe_path')
        return
    parent = None
    try:
        require(not stat.S_IMODE(os.fstat(fd).st_mode) & 0o077, 'unsafe_path')
        _bind_directory(registry, '_owner_proof_store_identity', fd)
        try:parent = _descendant(fd, ('selected',))
        except FileNotFoundError:
            require(getattr(registry, '_owner_selected_identity', None) is None, 'unsafe_path')
            return
        _bind_directory(registry, '_owner_selected_identity', parent)
        try:selection, unused = reader.read(_selection(registry, record), private=True, parent_fd=parent)
        except FileNotFoundError:require(not os.path.lexists(_selection(registry, record)))
        else:
            expected = {'schema': 1, 'document_type': 'application_owner_cleanup_selection', 'subject': subject(record)}
            require(canonical(selection) == canonical(expected), 'owner_proof_publication_incomplete')
        named = directory(_selection(registry, record).parent)
        try:require(identity(os.fstat(named)) == identity(os.fstat(parent)), 'unsafe_path')
        finally:os.close(named)
    finally:
        if parent is not None:os.close(parent)
        os.close(fd)


def _remember_selection(registry, record):
    selected = getattr(registry, '_owner_proof_selected_ids', None)
    if selected is None:
        selected = set(); registry._owner_proof_selected_ids = selected
    selected.add(record['launch_id'])


def _remember_legacy_selection(registry, record):
    _remember_selection(registry, record)
    selected = getattr(registry, '_owner_legacy_selected_ids', None)
    if selected is None:
        selected = set(); registry._owner_legacy_selected_ids = selected
    selected.add(record['launch_id'])


def _remember_document_selection(registry, record, value):
    if value.get('schema') == 2 or value.get('method') == 'legacy_derived_v1' or value.get('cohort') == 'application_owner_legacy_1':
        _remember_legacy_selection(registry, record)
    else:_remember_selection(registry, record)


def _mark_selected(registry, record):
    fd = _store(registry)
    parent = None
    try:
        try:
            with diagnostics.operation('directory_create', mutating=True):os.mkdir('selected', 0o700, dir_fd=fd)
        except FileExistsError:pass
        with diagnostics.operation('directory_fsync', mutating=True):os.fsync(fd)
        parent = _descendant(fd, ('selected',))
        _bind_directory(registry, '_owner_selected_identity', parent)
        target = _selection(registry, record)
        expected = {'schema': 1, 'document_type': 'application_owner_cleanup_selection', 'subject': subject(record)}
        try:previous, unused = Reader().read(target, private=True, parent_fd=parent)
        except FileNotFoundError:
            with diagnostics.operation('temporary_create', mutating=True):
                output = os.open(target.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            with os.fdopen(output, 'wb') as stream:
                with diagnostics.operation('file_write', mutating=True):stream.write(canonical(expected)); stream.flush()
                with diagnostics.operation('file_fsync', mutating=True):os.fsync(stream.fileno())
            with diagnostics.operation('directory_fsync', mutating=True):os.fsync(parent)
        else:require(previous == expected)
        named = directory(target.parent)
        try:require(identity(os.fstat(named)) == identity(os.fstat(parent)), 'unsafe_path')
        finally:os.close(named)
        _remember_selection(registry, record)
    finally:
        if parent is not None:os.close(parent)
        os.close(fd)


def _bind_directory(registry, name, fd):
    observed = identity(os.fstat(fd)); previous = getattr(registry, name, None)
    require(previous is None or previous == observed, 'unsafe_path')
    setattr(registry, name, observed)


@diagnostics.observed('directory_open')
def _descendant(parent, names):
    fd = os.dup(parent)
    try:
        for name in names:
            require(type(name) is str and name not in ('.', '..') and '/' not in name, 'unsafe_path')
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            require(info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o077, 'unsafe_path')
        return fd
    except BaseException:os.close(fd); raise


def _store(registry):
    lease_identity(registry)
    root = store_path(registry)
    try:fd = directory(root)
    except FileNotFoundError:
        require(getattr(registry, '_owner_proof_store_identity', None) is None, 'unsafe_path')
        parent = directory(root.parent)
        try:
            with diagnostics.operation('directory_create', mutating=True):os.mkdir(root.name, 0o700, dir_fd=parent)
            with diagnostics.operation('directory_fsync', mutating=True):os.fsync(parent)
        finally:os.close(parent)
        fd = directory(root)
    try:
        require(not stat.S_IMODE(os.fstat(fd).st_mode) & 0o077, 'unsafe_path')
        _bind_directory(registry, '_owner_proof_store_identity', fd)
    except BaseException:os.close(fd); raise
    return fd


def _publish_index(registry, record, reference, *, method=None, cohort=None):
    require((method is None and cohort is None) or
            (method == 'legacy_derived_v1' and cohort == 'application_owner_legacy_1'), 'owner_legacy_unsupported')
    root = store_path(registry)
    fd = _store(registry)
    try:
        require(not stat.S_IMODE(os.fstat(fd).st_mode) & 0o077, 'unsafe_path')
        value = {'schema': 2 if method else 1, 'document_type': 'application_owner_cleanup_index', 'subject': subject(record), 'receipt': reference}
        if method:value.update(method=method, cohort=cohort)
        with diagnostics.operation('temporary_create', mutating=True):
            output = os.open(record['launch_id'] + '.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        with os.fdopen(output, 'wb') as stream:
            with diagnostics.operation('file_write', mutating=True):stream.write(canonical(value)); stream.flush()
            with diagnostics.operation('file_fsync', mutating=True):os.fsync(stream.fileno())
            signature = _purge_signature(os.fstat(stream.fileno()))
        with diagnostics.operation('directory_fsync', mutating=True):os.fsync(fd)
        named = directory(root)
        try:require(identity(os.fstat(named)) == identity(os.fstat(fd)), 'unsafe_path')
        finally:os.close(named)
        require(_purge_signature(os.stat(record['launch_id'] + '.json', dir_fd=fd, follow_symlinks=False)) == signature, 'unsafe_record')
        if method:
            return {'reference': {'path': str(root / (record['launch_id'] + '.json')), 'sha256': digest(value)},
                    'signature': signature}
    finally:os.close(fd)


@diagnostics.scoped('application_cleanup', 'cleanup_proof_invalid')
def validate_accepted(registry, record):
    reader = Reader()
    anchor = _read_anchor(registry, record, reader)
    try:index, unused = reader.read(_index(registry, record), private=True)
    except FileNotFoundError:
        require(anchor is None, 'owner_proof_publication_incomplete')
        require(record['launch_id'] not in getattr(registry, '_owner_proof_selected_ids', set()))
        if getattr(registry, '_owner_proof_store_identity', None) is not None:
            bound = directory(store_path(registry))
            try:_bind_directory(registry, '_owner_proof_store_identity', bound)
            finally:os.close(bound)
        require(not os.path.lexists(_index(registry, record)))
        try:selection, unused = reader.read(_selection(registry, record), private=True)
        except FileNotFoundError:
            require(not os.path.lexists(_selection(registry, record)))
        else:
            _remember_document_selection(registry, record, selection)
            require(False)
        return False
    _remember_document_selection(registry, record, index)
    require(subject(record)['registry'] == registry.registry_id)
    store = directory(store_path(registry))
    try:
        require(not stat.S_IMODE(os.fstat(store).st_mode) & 0o077, 'unsafe_path')
        _bind_directory(registry, '_owner_proof_store_identity', store)
    finally:os.close(store)
    require(type(index) is dict)
    if type(index.get('schema')) is int and index['schema'] == 2:
        _remember_legacy_selection(registry, record)
        import application_owner_legacy_protocol as legacy_protocol
        return legacy_protocol.validate_accepted(registry, record, index, anchor, reader)
    require(anchor is None, 'owner_proof_publication_incomplete')
    exact(index, {'schema', 'document_type', 'subject', 'receipt'})
    require(type(index['schema']) is int and index['schema'] == 1
            and index['document_type'] == 'application_owner_cleanup_index' and index['subject'] == subject(record))
    selection, unused = reader.read(_selection(registry, record), private=True)
    require(selection == {'schema': 1, 'document_type': 'application_owner_cleanup_selection', 'subject': subject(record)})
    exact(index['receipt'], {'path', 'sha256'})
    receipt, reference = reader.read(index['receipt']['path'], private=True)
    require(reference == index['receipt'])
    base_fields = {'schema', 'document_type', 'method', 'status', 'cleanup_completed', 'subject', 'lease',
                   'admission_authorized', 'original_outcome_regraded', 'scope', 'global_actor_census',
                   'credential_memory_erasure', 'runner_content_sha256'}
    if receipt.get('method') == 'runtime_finalization':exact(receipt, base_fields | {'basis'})
    else:exact(receipt, base_fields | {'invocation_id', 'started_at', 'finished_at', 'request', 'metadata', 'roots',
                                     'related_subjects', 'new_containers', 'participant_stages', 'model_requests', 'effects'})
    require(receipt.get('document_type') == 'application_owner_cleanup_receipt' and receipt.get('status') == 'CLEANED'
            and type(receipt['schema']) is int and receipt['schema'] == 1
            and receipt.get('cleanup_completed') is True and receipt.get('subject') == subject(record)
            and canonical(receipt.get('lease')) == canonical(lease_identity(registry)) and receipt.get('admission_authorized') is False
            and receipt['original_outcome_regraded'] is False and receipt['scope'] == 'owned_host_files_only'
            and type(receipt['runner_content_sha256']) is str and re.fullmatch('[a-f0-9]{64}', receipt['runner_content_sha256']) is not None
            and receipt['global_actor_census'] == 'not_attested' and receipt['credential_memory_erasure'] == 'not_attested')
    if receipt.get('method') == 'runtime_finalization':
        _validate_runtime(registry, record, receipt, reader=reader)
        return True
    require(receipt.get('method') == 'retained_terminals')
    original, related, observed, metadata, roots, physical = _prepare(registry, receipt['request'], replay=True, reader=reader)
    require(metadata == receipt['metadata'] and all(r['state'] == 'absent' for r in roots))
    require([r['path'] for r in roots] == [r['path'] for r in receipt['roots']])
    require(_canonical_subjects(receipt['related_subjects']) == [_resource_subject(r) for r in related])
    return True


def _resource_subject(record):
    return {'launch_id': record['launch_id'], 'identity': digest({k: v for k, v in record.items() if k != 'status'})}


def _no_foreign_holders(registry, record, related, reader, roots):
    """Do not discard a namespace still held by another registered owner.

    Historical replay remains passive: ordinary reconciliation must be able to
    stop later pending writers before authorizing fresh dispatch.
    """
    related_ids = {item['launch_id'] for item in related}
    protected_values = [record['runroot'], *[item['path'] for item in roots],
                        *[ref['path'] for ref in reader.references.values()]]
    def resolved(value):
        try:return path(value).resolve(strict=False)
        except (OSError, RuntimeError) as exc:
            raise ownership.RegistryError('Registered holder scope cannot be established',
                                          condition='owner_scope_unsupported', cause=exc) from None
    protected = {resolved(value) for value in protected_values}
    for other in registry.load():
        if other['launch_id'] in related_ids or other['status'] == 'released':continue
        values = [other['runroot']] if other.get('runroot') is not None else []
        values.extend(mount['source'] for mount in other['mounts'])
        for value in values:
            candidate = resolved(value)
            require(not any(candidate == target or candidate in target.parents or target in candidate.parents
                            for target in protected), 'owner_writer_pending')


def _canonical_subjects(value):
    require(type(value) is list and len(value) <= 64)
    for item in value:
        exact(item, {'launch_id', 'identity'})
        require(controls.valid_id(item['launch_id']) and type(item['identity']) is str
                and re.fullmatch('[a-f0-9]{64}', item['identity']) is not None)
    require(len({item['launch_id'] for item in value}) == len(value))
    return sorted(value, key=lambda item: item['launch_id'])


@diagnostics.scoped('application_cleanup', 'cleanup_proof_invalid')
def recover(registry, request, output_dir, *, discard_workspace=False, reader=None):
    import registry_maintenance as maintenance
    require(discard_workspace is True, 'owner_discard_required')
    if _request_method(request) == 'legacy_derived_v1':
        import application_owner_legacy_publication as legacy_publication
        return legacy_publication.recover(registry, request, output_dir, discard_workspace=discard_workspace, reader=reader)
    lease = lease_identity(registry)
    record, related, reader, metadata, roots, physical = _prepare(registry, request, reader=reader)
    require(not os.path.lexists(_index(registry, record)))
    _retained_selection(registry, record, reader)
    runner = maintenance._runner_identity()
    _no_foreign_holders(registry, record, related, reader, roots)
    _writers_absent(registry, physical)
    receipt = maintenance._new_receipt_directory(output_dir, registry.root.with_name(registry.root.name[:-9]), registry, registry.load())
    report = {'schema': 1, 'document_type': 'application_owner_cleanup_receipt', 'invocation_id': str(uuid.uuid4()),
              'started_at': controls.now(), 'status': 'RUNNING', 'cleanup_completed': False,
              'admission_authorized': False, 'original_outcome_regraded': False,
              'method': 'retained_terminals', 'scope': 'owned_host_files_only',
              'global_actor_census': 'not_attested', 'credential_memory_erasure': 'not_attested',
              'subject': subject(record), 'lease': lease, 'request': request, 'metadata': metadata, 'roots': roots,
              'runner_content_sha256': runner,
              'related_subjects': [_resource_subject(r) for r in related],
              'new_containers': 0, 'participant_stages': 0, 'model_requests': 0, 'effects': 'may_have_occurred'}
    try:
        with diagnostics.operation('directory_fsync', mutating=True):os.fsync(receipt.parent)
        receipt.publish(report)
        try:
            _mark_selected(registry, record)
            for observation in roots:
                if observation['state'] == 'present':report['effects'] = 'may_have_occurred'
                _purge(observation)
            # Re-read the original evidence before committing acceptance.
            repeated = _prepare(registry, request, replay=True, reader=reader)
            require(repeated[3] == metadata and all(r['state'] == 'absent' for r in repeated[4]))
            _no_foreign_holders(registry, repeated[0], repeated[1], reader, repeated[4])
            report.update(status='CLEANED', cleanup_completed=True, finished_at=controls.now())
            receipt.publish(report)
            reference = {'path': str(receipt.path / 'recovery.json')}
            # _Receipt uses indented JSON; reference its exact published bytes.
            reference['sha256'] = hashlib.sha256((json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode()).hexdigest()
            _publish_index(registry, record, reference)
            require(validate_accepted(registry, record))
            report['receipt_persistence'] = 'confirmed'
            return report
        except BaseException as exc:
            report.update(status='INTERRUPTED' if isinstance(exc, KeyboardInterrupt) else 'BLOCKED',
                          cleanup_completed=False, finished_at=controls.now())
            report['registry_diagnostic'] = diagnostics.diagnostic(exc)
            try:receipt.publish(report)
            except BaseException:pass
            raise
    finally:receipt.close()


class _Custody:
    """An in-process write ticket; never reconstructed from a supplied report."""
    def __init__(self, receipt, body, registry):
        self.path = receipt.path
        self.parent_identity = receipt.parent_identity
        self.identity = receipt.identity
        self.previous = receipt.previous
        self.body = body
        self.registry = registry

    def update(self, **fields):
        import registry_maintenance as maintenance
        bound = _store(self.registry); os.close(bound)
        receipt = maintenance._Receipt(self.path, directory(self.path.parent))
        try:
            receipt.parent_identity = self.parent_identity
            receipt.fd = directory(self.path); receipt.identity = self.identity; receipt.previous = self.previous
            body = {**self.body, **fields}; receipt.publish(body)
            self.body = body; self.previous = receipt.previous
        finally:receipt.close()

    def witness(self, name, body):
        import registry_maintenance as maintenance
        require(name in ('snapshot', 'launcher-invocation', 'container-identity', 'launcher-terminal'))
        bound = _store(self.registry); os.close(bound)
        parent = directory(self.path)
        try:
            require(identity(os.fstat(parent)) == list(self.identity), 'unsafe_path')
            receipt = maintenance._Receipt.create(self.path / name, parent_fd=parent)
        finally:os.close(parent)
        try:
            with diagnostics.operation('directory_fsync', mutating=True):os.fsync(receipt.parent)
            receipt.publish(body)
            return {'path': str(receipt.path / 'recovery.json'), 'sha256': receipt.previous[1]}
        finally:receipt.close()


def _custody_path(registry, record):
    return store_path(registry) / 'custody' / record['launch_id'] / 'recovery.json'


@diagnostics.scoped('application_cleanup', 'cleanup_proof_invalid')
def begin_custody(helper, argv):
    """Called by the genuine host helper before Popen and private bootstrap."""
    import registry_maintenance as maintenance
    import application_client
    require(type(helper) is application_client.OwnedHelper)
    registry = helper.registry
    if type(registry) is not ownership.Registry or not hasattr(registry, 'lease_fd'):
        return None  # Synthetic/provider objects do not mint production proof.
    lease = lease_identity(registry); record = helper.record; root = path(record['runroot'])
    require(record['status'] == 'intent' and record['generation'] == registry.generation
            and record.get('owner_pid') == os.getpid() and record in registry.load())
    require(type(argv) is list and all(type(value) is str for value in argv))
    workspace = _root_observation(root / 'workspace'); require(workspace['state'] == 'present')
    fd = _store(registry)
    custody_parent = None
    try:
        try:os.mkdir('custody', 0o700, dir_fd=fd)
        except FileExistsError:pass
        with diagnostics.operation('directory_fsync', mutating=True):os.fsync(fd)
        custody_parent = _descendant(fd, ('custody',))
        _bind_directory(registry, '_owner_custody_identity', custody_parent)
        receipt = maintenance._Receipt.create(_custody_path(registry, record).parent, parent_fd=custody_parent)
    finally:
        if custody_parent is not None:os.close(custody_parent)
        os.close(fd)
    try:
        with diagnostics.operation('directory_fsync', mutating=True):os.fsync(receipt.parent)
        body = {'schema': 1, 'document_type': 'application_helper_custody', 'subject': subject(record),
                'lease': lease, 'workspace': workspace, 'events': ['intent'], 'cleanup': None,
                'writers_absent': False, 'recorded_at': controls.now(), 'directory_identity': list(receipt.identity),
                'launcher_argv': list(argv), 'launcher': None, 'guard': None, 'terminal': None, 'snapshot': None}
        receipt.publish(body)
        ticket = _Custody(receipt, body, registry)
        snapshot = {'schema': 1, 'document_type': 'application_owned_snapshot',
                    **{k: record[k] for k in ('registry', 'generation', 'runroot', 'binding')},
                    'workspace': workspace['path'], 'workspace_identity': workspace['identity']}
        reference = ticket.witness('snapshot', snapshot); ticket.update(snapshot=reference)
        return ticket
    finally:receipt.close()


def custody_event(helper, event):
    ticket = getattr(helper, '_owner_custody', None)
    if ticket is None:return
    require(type(ticket) is _Custody and event in ('launch_attempted', 'container_bound', 'bootstrap_sent', 'helper_cleanup'))
    events = ticket.body['events']; require(event not in events)
    if event == 'container_bound':require('launch_attempted' in events and helper.record.get('container_id') is not None and ticket.body['guard'] is not None)
    if event == 'bootstrap_sent':require('container_bound' in events)
    fields = {'subject': subject(helper.record), 'events': [*events, event]}
    if event == 'helper_cleanup':
        fields.update(cleanup=helper.cleanup_receipt, writers_absent=helper.cleanup_receipt.get('status') == 'removed')
        process = getattr(helper, 'process', None)
        if ticket.body['launcher'] is not None and process is not None and type(process.returncode) is int:
            invocation = Reader().reference(ticket.body['launcher'])
            terminal = {'schema': 1, 'document_type': 'owned_process_terminal', 'invocation': ticket.body['launcher'],
                        **{k: invocation[k] for k in ('pid', 'argv', 'cwd')}, 'actual_exit': process.returncode}
            fields['terminal'] = ticket.witness('launcher-terminal', terminal)
    ticket.update(**fields)


def custody_launched(helper):
    ticket = getattr(helper, '_owner_custody', None)
    if ticket is None:return
    require(type(ticket) is _Custody and ticket.body['launcher'] is None and 'launch_attempted' in ticket.body['events'])
    require(type(helper.process.pid) is int and 1 <= helper.process.pid < 2**31)
    record = helper.record
    body = {'schema': 1, 'document_type': 'owned_process_invocation', 'pid': helper.process.pid,
            'argv': ticket.body['launcher_argv'], 'cwd': os.getcwd(),
            **{k: record[k] for k in ('runroot', 'registry', 'generation')}, 'launch_ids': [record['launch_id']]}
    ticket.update(launcher=ticket.witness('launcher-invocation', body))


def custody_identity(helper, cid):
    ticket = getattr(helper, '_owner_custody', None)
    if ticket is None:return
    require(type(ticket) is _Custody and ticket.body['guard'] is None and ticket.body['launcher'] is not None)
    require(type(cid) is str and re.fullmatch('[a-f0-9]{64}', cid) is not None and cid != '0' * 64
            and helper.container_id == cid)
    record = helper.record
    guard = {'schema': 1, 'document_type': 'owned_container_identity', 'container_id': cid,
             **{k: record[k] for k in ('registry', 'generation', 'launch_id', 'daemon', 'container', 'image', 'mounts')},
             'intent_sha256': subject(record)['intent_sha256'], 'invocation': ticket.body['launcher']}
    ticket.update(guard=ticket.witness('container-identity', guard))


def _runtime_basis(registry, record, *, reader=None):
    reader = Reader() if reader is None else reader
    custody, ref = reader.read(_custody_path(registry, record), private=True)
    exact(custody, CUSTODY_FIELDS)
    require(type(custody['schema']) is int and custody['schema'] == 1 and custody['document_type'] == 'application_helper_custody'
            and custody['subject'] == subject(record) and custody['lease'] == lease_identity(registry)
            and custody['events'] in (['intent', 'launch_attempted', 'container_bound', 'bootstrap_sent', 'helper_cleanup'],
                                      ['intent', 'launch_attempted', 'container_bound', 'helper_cleanup'])
            and custody['writers_absent'] is True and type(custody['cleanup']) is dict
            and custody['cleanup'].get('status') == 'removed'
            and custody['cleanup'].get('workspace') in ('clean', 'discarded'))
    parent = directory(_custody_path(registry, record).parent)
    try:require(canonical(custody['directory_identity']) == canonical(identity(os.fstat(parent))), 'unsafe_path')
    finally:os.close(parent)
    snapshot = _owned_snapshot(reader, custody['snapshot'], record)
    require(snapshot['workspace_identity'] == custody['workspace']['identity'])
    _terminal(reader, {'invocation': custody['launcher'], 'terminal': custody['terminal']},
              record, [record['launch_id']], replay=True, launcher=True)
    bound = _guard_identity(reader, record, {'identity': custody['guard'], 'invocation': custody['launcher']})
    require(bound['container_id'] == record.get('container_id'), 'owner_identity_required')
    root = path(record['runroot']); stages, metadata = _stages(reader, root)
    if stages:
        # This is the exact original complete stage gate; the runtime path does
        # not turn failed writer/credential accounting into a successful run.
        require(not ownership._application_stage_pending(root), 'application_cleanup_pending')
    else:
        require(custody['cleanup'].get('safe_to_continue') is True, 'application_cleanup_pending')
        # No stage must also mean no undocumented context tree.
        require(ownership._qualification_absent(str(root / 'controls')), 'application_cleanup_pending')
    require(ownership._qualification_absent(record['private_store']), 'application_cleanup_pending')
    workspace = _root_observation(root / 'workspace')
    require(workspace['state'] == 'present' and workspace['identity'] == custody['workspace']['identity'], 'sensitive_identity_mismatch')
    evidence = root / 'application-evidence' / record['container']
    observation = _root_observation(evidence)
    if observation['state'] == 'present':
        require(custody['cleanup'].get('evidence') == 'retained' and custody['cleanup'].get('evidence_root') == str(evidence))
    evidence_inventory = _inventory(evidence) if observation['state'] == 'present' else []
    for target in ('identity.json', 'result.json', 'plan.json'):
        try:body, item = reader.read(root / target)
        except FileNotFoundError:continue
        metadata.append(item)
    return {'custody': ref, 'metadata': metadata, 'stages': [s[0] for s in stages], 'workspace': workspace,
            'workspace_inventory': _inventory(root / 'workspace'),
            'evidence': observation, 'evidence_inventory': evidence_inventory,
            'retained_inventory': _inventory(root, exclude=(root / 'workspace', evidence)),
            'custody_directory_identity': custody['directory_identity']}


def _inventory(root, *, exclude=()):
    """Bound a retained clean snapshot without following links or special files."""
    result = []; budget = [0]; total = [0]
    def walk(fd, prefix=''):
        names = sorted(os.listdir(fd)); budget[0] += len(names)
        require(budget[0] <= MAX_ENTRIES, 'inventory_unbounded')
        for name in names:
            relative = prefix + name
            if any(root / relative == p for p in exclude):continue
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            require(info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o022, 'unsafe_path')
            require(info.st_dev == root_device, 'sensitive_identity_mismatch')
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    require(identity(os.fstat(child)) == identity(info), 'sensitive_identity_mismatch')
                    result.append({'path': relative, 'directory': True}); walk(child, relative + '/')
                    require(identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) == identity(info), 'sensitive_identity_mismatch')
                finally:os.close(child)
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 16 * 1024 * 1024, 'unsafe_path')
                total[0] += info.st_size; require(total[0] <= 256 * 1024 * 1024, 'inventory_unbounded')
                leaf = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                with os.fdopen(leaf, 'rb') as stream:
                    require(identity(os.fstat(stream.fileno())) == identity(info), 'sensitive_identity_mismatch')
                    body = stream.read(16 * 1024 * 1024 + 1); after = os.fstat(stream.fileno())
                    require(len(body) == info.st_size and (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                            == (info.st_size, info.st_mtime_ns, info.st_ctime_ns), 'sensitive_identity_mismatch')
                require(identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) == identity(info), 'sensitive_identity_mismatch')
                result.append({'path': relative, 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()})
    fd = directory(root)
    try:
        root_device = os.fstat(fd).st_dev
        walk(fd)
    finally:os.close(fd)
    return result


def _validate_runtime(registry, record, receipt, *, reader=None):
    require(record['status'] == 'released')
    basis = _runtime_basis(registry, record, reader=reader)
    require(basis == receipt['basis'])


@diagnostics.scoped('application_cleanup', 'cleanup_proof_invalid')
def finalize_current(registry):
    """Publish normal proof only after final stage metadata is complete."""
    import registry_maintenance as maintenance
    for record in registry.load():
        if record['generation'] != registry.generation or record.get('application_helper') is not True:continue
        if not os.path.lexists(_custody_path(registry, record)):continue
        if validate_accepted(registry, record):continue
        require(record['status'] == 'released', 'owned_application_cleanup_required')
        basis = _runtime_basis(registry, record)
        output = _custody_path(registry, record).parent / 'finalized'
        store = _store(registry)
        parent = None
        try:
            parent = _descendant(store, ('custody', record['launch_id']))
            require(identity(os.fstat(parent)) == basis['custody_directory_identity'], 'unsafe_path')
            receipt = maintenance._Receipt.create(output, parent_fd=parent)
        finally:
            if parent is not None:os.close(parent)
            os.close(store)
        try:
            with diagnostics.operation('directory_fsync', mutating=True):os.fsync(receipt.parent)
            report = {'schema': 1, 'document_type': 'application_owner_cleanup_receipt',
                      'method': 'runtime_finalization', 'status': 'CLEANED', 'cleanup_completed': True,
                      'subject': subject(record), 'lease': lease_identity(registry), 'basis': basis,
                      'admission_authorized': False, 'original_outcome_regraded': False,
                      'scope': 'owned_host_files_only', 'global_actor_census': 'not_attested',
                      'credential_memory_erasure': 'not_attested', 'runner_content_sha256': maintenance._runner_identity()}
            receipt.publish(report)
            _mark_selected(registry, record)
            reference = {'path': str(receipt.path / 'recovery.json'), 'sha256': hashlib.sha256(
                (json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode()).hexdigest()}
            _publish_index(registry, record, reference)
            require(validate_accepted(registry, record))
        finally:receipt.close()


def requires_proof(registry, record):
    if 'owner_cleanup_contract' in record:
        require(type(record['owner_cleanup_contract']) is int and record['owner_cleanup_contract'] == 1)
        return True
    return os.path.lexists(_custody_path(registry, record))


def add_arguments(sub, default_lock):
    for name in ('application-owner-inspect', 'application-owner-recover'):
        parser = sub.add_parser(name, help='Inspect or clean exact historical application ownership without dispatch')
        parser.add_argument('--lock-file', default=default_lock)
        parser.add_argument('--lock-wait-seconds', type=float, default=0)
        if name == 'application-owner-recover':
            parser.add_argument('--request', required=True, help='Owner-only typed custody request with original terminal references')
            parser.add_argument('--output-dir', required=True, help='New private receipt directory outside retained execution paths')
            parser.add_argument('--discard-workspace', action='store_true', help='Authorize discard of the exact proven-owned disposable private scope')


def _owner_docker(argv):
    # Retained ownership observation must not propagate unrelated exported
    # inference/application keys into a new Docker CLI process.
    import application_client
    return subprocess.run(argv, text=True, capture_output=True, timeout=15,
                          env=application_client._docker_environment())


def command(args):
    import registry_maintenance as maintenance
    report = {'schema': 1, 'document_type': 'application_owner_operation', 'status': 'RUNNING',
              'exit_code': 2, 'admission_authorized': False, 'new_containers': 0, 'participant_stages': 0, 'model_requests': 0}
    try:
        with maintenance.existing_lease(args.lock_file, args.lock_wait_seconds) as (fd, lease, selected):
            registry = ownership.Registry(Path(str(selected) + '.registry'), command=_owner_docker, create=False); registry.lease_fd = fd
            if args.op == 'application-owner-inspect':
                report.update(status='OBSERVED', exit_code=0, helpers=inspect_helpers(registry, registry.load()))
            else:
                reader = Reader()
                request, unused = reader.read(args.request, private=True)
                result = recover(registry, request, args.output_dir, discard_workspace=args.discard_workspace, reader=reader)
                # Full paths/terminal witnesses stay in the owner-only receipt.
                report.update(status=result['status'], exit_code=0,
                              receipt_persistence=result['receipt_persistence'], effects=result['effects'])
                if result['method'] != 'legacy_derived_v1':
                    report.update(subject=result['subject'], runner_content_sha256=result['runner_content_sha256'])
    except KeyboardInterrupt:
        report.update(status='INTERRUPTED', exit_code=130)
    except Exception as exc:
        maintenance._failure(report, exc)
    print(json.dumps(report, indent=2))
    return report['exit_code']


def inspect_helpers(registry, records):
    observations = []
    for record in records:
        if record.get('application_helper') is not True:continue
        if ('qualification_role' in record or 'qualification_service_cleanup' in record
                or 'qualification_preworker_cleanup' in record):continue
        shape = 'unknown'
        try:
            stages, unused = _stages(Reader(), path(record['runroot']))
            shape = 'interrupted' if record.get('container_id') is None else 'agent' if stages else 'helper_only'
            accepted = validate_accepted(registry, record)
            pending = False if accepted else ownership._application_stage_pending(record['runroot'])
            condition = 'owner_proof_required' if pending else 'cleanup_observed'
        except (ownership.RegistryError, OSError, ValueError):condition = 'cleanup_proof_invalid'
        observations.append({'launch_id': record['launch_id'], 'condition': condition,
                             'execution_shape': shape,
                             'container_id_recorded': record.get('container_id') is not None})
    return observations
