"""Fixed fresh-process worker for an independently approved consumer policy.

Never invoke directly with an encountered receipt as policy. The Python runtime
and consumer bootstrap are trusted deployment inputs. The audit guard constrains
reviewed Python provider code; it is not a sandbox for a malicious provider.
"""
import builtins
import collections
import dataclasses
import hashlib
import importlib.abc
import importlib.machinery
import importlib.util
import json
import math
import os
from pathlib import Path
import stat
import sys
import types


def bootstrap():
    if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):
        raise ValueError('invalid_proof')
    body = sys.stdin.buffer.read(4 * 1024 * 1024 + 16385)
    if len(body) > 4 * 1024 * 1024 + 16384:raise ValueError('invalid_proof')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:raise ValueError('invalid_proof')
            result[key] = value
        return result
    packet = json.loads(body, object_pairs_hook=pairs,
        parse_constant=lambda unused: (_ for _ in ()).throw(ValueError('invalid_proof')))
    if type(packet) is not dict or set(packet) != {'policy', 'trusted_policy_sha256', 'selection', 'mode', 'memory'}:
        raise ValueError('invalid_proof')
    root = Path(__file__).resolve().parent
    names = ('application_owner_consumer.py', 'application_owner_consumer_policy.py', 'application_owner_consumer_worker.py')
    expected = packet['policy']['consumer']['files']
    if type(expected) is not dict or set(expected) != set(names):raise ValueError('invalid_proof')
    def source(name):
        parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            with os.fdopen(fd,'rb') as stream:
                before=os.fstat(stream.fileno())
                signature=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
                if (not stat.S_ISREG(before.st_mode) or before.st_uid not in (0,os.getuid())
                        or before.st_nlink!=1 or stat.S_IMODE(before.st_mode)&0o022 or before.st_size>4194304):
                    raise ValueError('invalid_proof')
                data=stream.read(4194305)
                if not signature(before)==signature(os.fstat(stream.fileno()))==signature(os.stat(name,dir_fd=parent,follow_symlinks=False)):
                    raise ValueError('invalid_proof')
            if hashlib.sha256(data).hexdigest()!=expected[name]:raise ValueError('invalid_proof')
            return data,signature(before)
        finally:os.close(parent)
    sources={name:source(name) for name in names}
    # Compile precisely the verified source bytes. Never add the artifact folder
    # to sys.path: -B alone still permits encountered pyc/sibling imports.
    for name in ('application_owner_consumer_policy','application_owner_consumer'):
        if name in sys.modules:raise ValueError('invalid_proof')
        filename=str(root/(name+'.py'));module=types.ModuleType(name)
        module.__file__=filename;module.__package__=''
        module.__spec__=importlib.machinery.ModuleSpec(name,loader=None,origin=filename)
        sys.modules[name]=module
        exec(compile(sources[name+'.py'][0],filename,'exec',dont_inherit=True),module.__dict__)
    consumer=sys.modules['application_owner_consumer']
    approved = consumer.policy.compile_policy(packet['policy'],
        trusted_policy_sha256=packet['trusted_policy_sha256'], selection=packet['selection'])
    consumer.require(packet['mode'] in approved.to_wire()['capabilities'])
    check = consumer.result(); check['memory'] = packet['memory']
    consumer.validate_result(check, approved, packet['mode'])
    for name in names:
        if source(name)!=sources[name]:raise ValueError('invalid_proof')
    consumer.verify_consumer(approved)
    return consumer, approved, packet


class Guard:
    """Bound reviewed provider IO; no write, native/PID or unapproved file read."""
    def __init__(self, consumer, approved, *, allow_history=False):
        self.consumer = consumer; self.approved = approved; self.value = approved.to_wire()
        self.provider = Path(self.value['provider']['root'])
        self.files = {str(self.provider/name) for name in self.value['provider']['files']}
        if allow_history:
            self.files.update(row.path for row in approved.files)
            self.files.update(row['path'] for row in self.value['read_scope']['registry_records'])
            self.files.add(self.value['lease']['path'])
        self.runtime = Path(os.__file__).resolve().parent
        self.consumer_root = Path(__file__).resolve().parent
        self.runtime_paths = tuple(Path(text) for text in sys.path if text.startswith('/')
            and (Path(sys.base_prefix) == Path(text) or Path(sys.base_prefix) in Path(text).parents))
        self.fd_paths = {}; self.pending = []; self.original_open = os.open
        self.original_dup = os.dup; self.original_close = os.close
        self.original_stat = os.stat; self.original_lstat = os.lstat
        self.directories = set(self.value['read_scope']['directories']) if allow_history else set()
        self.absent_paths = set(self.value['read_scope']['absent_paths']) if allow_history else set()
        # dataclasses generates functions from already-reviewed class definitions.
        # Permit only its captured generator code objects, never arbitrary
        # '<string>' execution or a function selected by historical evidence.
        self.generated_callers = {collections.namedtuple.__code__}
        create = getattr(dataclasses, '_create_fn', None)
        if create is not None:self.generated_callers.add(create.__code__)
        builder = getattr(dataclasses, '_FuncBuilder', None)
        if builder is not None:self.generated_callers.add(builder.add_fns_to_class.__code__)
        self.ancestors = {'/'}
        for text in self.files | self.directories | self.absent_paths:
            self.ancestors.update(str(p) for p in Path(text).parents)

    def code_path(self, path):
        return (path == self.provider or self.provider in path.parents or path == self.runtime
                or self.runtime in path.parents or any(path == root or root in path.parents for root in self.runtime_paths))

    def path(self, value, dir_fd=None):
        if type(value) is int:
            self.consumer.require(value in self.fd_paths)
            text, identity = self.fd_paths[value]
            self.consumer.require(self.consumer.signature(os.fstat(value))[:5] == identity)
            return Path(text)
        text = os.fsdecode(value)
        if not Path(text).is_absolute():
            base = self.path(dir_fd) if dir_fd is not None else Path.cwd()
            text = str(base/text)
        if text == '/':return Path('/')  # Traversal FD only; no root listing/file-read grant.
        return Path(str(self.consumer.policy.absolute(text)))

    def allowed(self, path, directory=False):
        if self.code_path(path):return
        if path.parent == self.consumer_root and path.name in self.consumer.policy.CONSUMER_FILES:return
        self.consumer.require(str(path) in (self.ancestors | self.directories if directory else self.files))

    def metadata(self, path):
        if self.code_path(path):return
        if path.parent == self.consumer_root and path.name in self.consumer.policy.CONSUMER_FILES:return
        self.consumer.require(str(path) in self.ancestors | self.directories | self.files | self.absent_paths)

    def audit(self, event, args):
        if (event in ('subprocess.Popen', 'os.system', 'os.posix_spawn', 'os.fork', 'os.forkpty',
                      'os.exec', 'os.kill', 'os.killpg', 'socket.__new__', 'socket.connect', 'socket.bind')
                or event.startswith(('os.spawn', 'shutil.'))
                or event in ('os.remove', 'os.rmdir', 'os.rename', 'os.mkdir', 'os.chmod', 'os.chown',
                             'os.truncate', 'os.link', 'os.symlink', 'os.utime', 'os.chdir')):
            self.consumer.require(False)
        if event == 'open':
            value, mode, flags = args
            self.consumer.require(not (type(mode) is str and any(c in mode for c in 'wax+'))
                and not (type(flags) is int and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)))
            path = self.pending[-1] if self.pending else self.path(value)
            self.allowed(path, directory=type(flags) is int and bool(flags & os.O_DIRECTORY))
        elif event in ('os.scandir', 'os.listdir'):
            path = self.path(args[0])
            self.consumer.require(self.code_path(path) or str(path) in self.directories)
        elif event == 'exec':
            filename = args[0].co_filename
            # Historical Python source is data, not executable provider code.
            trusted_file = filename.startswith('/') and (self.code_path(Path(filename))
                or Path(filename).parent == self.consumer_root)
            generated = filename == '<string>' and sys._getframe(1).f_code in self.generated_callers
            self.consumer.require(trusted_file or generated)

    def install(self):
        def opened(path, flags, mode=0o777, *, dir_fd=None):
            full = self.path(path, dir_fd); self.allowed(full, directory=bool(flags & os.O_DIRECTORY))
            self.pending.append(full)
            try:fd = self.original_open(path, flags, mode, dir_fd=dir_fd)
            finally:self.pending.pop()
            self.fd_paths[fd] = (str(full), self.consumer.signature(os.fstat(fd))[:5])
            return fd
        def duplicated(fd):
            path = self.path(fd); new = self.original_dup(fd)
            self.fd_paths[new] = (str(path), self.consumer.signature(os.fstat(new))[:5]); return new
        def closed(fd):
            self.fd_paths.pop(fd, None); return self.original_close(fd)
        def stated(path, *, dir_fd=None, follow_symlinks=True):
            self.metadata(self.path(path, dir_fd))
            return self.original_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
        def lstated(path, *, dir_fd=None):
            self.metadata(self.path(path, dir_fd))
            return self.original_lstat(path, dir_fd=dir_fd)
        os.open = opened; os.dup = duplicated; os.close = closed
        os.stat = stated; os.lstat = lstated
        sys.addaudithook(self.audit)


class ProviderFinder(importlib.abc.MetaPathFinder):
    def __init__(self, consumer, approved):
        self.consumer = consumer; self.value = approved.to_wire()['provider']; self.loads = {}
        self.modules = {}
        for name in self.value['files']:
            path = Path(name)
            if path.parent.as_posix() in ('scripts', 'runtime') and path.suffix == '.py':
                consumer.require(path.stem not in self.modules)
                self.modules[path.stem] = str(Path(self.value['root'])/name)
        consumer.require(not set(self.modules) & set(sys.modules))

    def find_spec(self, fullname, path=None, target=None):
        if fullname not in self.modules:return None
        owner = self; filename = self.modules[fullname]
        class Loader(importlib.machinery.SourceFileLoader):
            def get_code(self, name):
                body, signature = owner.consumer.stable_read(filename)
                sha = hashlib.sha256(body).hexdigest()
                relative = str(Path(filename).relative_to(owner.value['root']))
                owner.consumer.require(owner.value['files'][relative] == sha)
                owner.loads[name] = {'name': name, 'path': filename, 'sha256': sha}
                # Always compile approved source bytes; never read encountered pyc.
                return compile(body, filename, 'exec', dont_inherit=True)
        return importlib.util.spec_from_file_location(fullname, filename, loader=Loader(fullname, filename))

    def observed(self):
        for name, row in self.loads.items():
            module = sys.modules.get(name)
            self.consumer.require(module is not None and module.__file__ == row['path']
                and module.__spec__.origin == row['path'])
        return [self.loads[name] for name in sorted(self.loads)]


def scoped_reader(consumer, approved, cleanup):
    base = cleanup.Reader; value = approved.to_wire(); expected_variant = value['binding']['variant']
    documents = {'application_owner_cleanup_'+kind:role for kind,role in
        (('anchor','anchor'),('index','index'),('selection','selection'),('intent','intent'),
         ('receipt','terminal'),('request','request'))}
    documents['application_owner_legacy_evidence']='evidence'
    document_roles=set(documents.values())
    class Reader(base):
        def read_bytes(self, path, **options):
            try:grant = approved.file_grant(str(path))
            except consumer.policy.PolicyError:raise cleanup.ownership.RegistryError('Unapproved proof read') from None
            if grant.sha256 is None:
                parent = cleanup.directory(Path(path).parent)
                try:
                    cleanup.require(not stat.S_IMODE(os.fstat(parent).st_mode) & (0o077 if grant.private_parent else 0o022))
                    os.stat(Path(path).name, dir_fd=parent, follow_symlinks=False)
                finally:os.close(parent)
                raise cleanup.ownership.RegistryError('Unexpected selected file')
            limit = options.get('maximum', cleanup.MAX_BYTES)
            if limit is None:limit = cleanup.MAX_BYTES
            options.update(maximum=min(limit, grant.maximum_bytes),
                           private=options.get('private', False) or grant.private,
                           private_parent=options.get('private_parent', options.get('private', False)) or grant.private_parent)
            body, ref = super().read_bytes(path, **options)
            cleanup.require(ref['sha256'] == grant.sha256)
            return body, ref
        def read(self, path, **options):
            body, ref = super().read(path, **options); grant = approved.file_grant(str(path))
            actual_role=documents.get(body.get('document_type'))
            if actual_role is not None:cleanup.require(actual_role in grant.roles)
            for role in grant.roles:
                if role in document_roles:cleanup.require(actual_role == role)
            for role in grant.roles:
                version = {'anchor': 1, 'index': 2, 'selection': 2, 'intent': 1, 'terminal': 2,
                           'request': 2, 'evidence': 1}.get(role)
                if version is not None:
                    cleanup.require(type(body.get('schema')) is int and body['schema'] == version)
                    cleanup.require(body.get('cohort') == consumer.policy.COHORT)
                    if role != 'evidence':cleanup.require(body.get('method') == consumer.policy.METHOD)
                    if role in ('intent', 'terminal', 'request', 'evidence'):
                        cleanup.require(body.get('variant') == expected_variant)
            return body, ref
    return Reader


def replay(consumer, approved, packet, output):
    import application_owner_cleanup as cleanup
    import ownership_registry as ownership
    import registry_maintenance as maintenance
    value = approved.to_wire(); scope = value['read_scope']
    expected = {row['path']: row['sha256'] for row in scope['registry_records']}
    def private(path, decode=True):
        name = str(path); consumer.require(name in expected)
        output['history_read'] = True
        body, unused = consumer.stable_read(path, maximum=1024*1024, private=True, private_parent=True)
        consumer.require(hashlib.sha256(body).hexdigest() == expected[name])
        return consumer.decode(body) if decode else None
    def forbidden(*args, **kwargs):raise consumer.ConsumerError('invalid_proof')
    ownership.read_private = private
    cleanup.Reader = scoped_reader(consumer, approved, cleanup)
    with maintenance.existing_lease(value['lease']['path']) as (fd, identity, unused):
        consumer.require([identity['device'], identity['inode']] == value['lease']['identity'])
        registry = ownership.Registry(Path(scope['registry']), command=forbidden, create=False)
        registry.lease_fd = fd
        for name, remembered in packet['memory']['namespaces'].items():
            if remembered is not None:setattr(registry, name, remembered)
        if packet['memory']['selected']:
            registry._owner_proof_selected_ids = {value['subject']['launch_id']}
            registry._owner_legacy_selected_ids = {value['subject']['launch_id']}
        try:
            consumer.require({str(p) for p in registry._paths()} == set(expected))
            records = registry.load(); selected = [r for r in records if r['launch_id'] == value['subject']['launch_id']]
            consumer.require(len(selected) == 1 and cleanup.subject(selected[0]) == value['subject'])
            registry.generation = selected[0]['generation']; registry.daemon = selected[0]['daemon']
            accepted = cleanup.validate_accepted(registry, selected[0])
            consumer.require(type(accepted) is bool)
            output.update(decision='proof_accepted' if accepted else 'not_selected', condition='replayed')
        finally:
            output['memory']['selected'] = packet['memory']['selected'] or bool(getattr(registry, '_owner_proof_selected_ids', set()))
            for name in consumer.MEMORY_FIELDS:
                output['memory']['namespaces'][name] = getattr(registry, name, packet['memory']['namespaces'][name])


def run(consumer, approved, packet):
    output = consumer.result('invalid_proof', 'invalid_proof'); output['memory'] = packet['memory']
    output['phase'] = 'inventory'
    provider = approved.to_wire()['provider']; root = Path(provider['root'])
    if not os.statvfs(root).f_flag & os.ST_RDONLY:
        output['condition'] = 'provider_readonly_required'; return output
    before = consumer.provider_inventory(approved)
    finder = ProviderFinder(consumer, approved)
    Guard(consumer, approved, allow_history=packet['mode'] == 'replay').install(); sys.meta_path.insert(0, finder)
    try:
        output.update(phase='provider_import', provider_imported=None)
        import application_owner_cleanup
        output['phase'] = 'resource_identity'
        descriptor = root/'assets/application-owner-reader-v1.json'
        body, unused = consumer.stable_read(descriptor)
        contract = consumer.decode(body)
        consumer.require(contract['contract_id'] == consumer.policy.CONTRACT and contract['contract_version'] == 1)
        output['origins'] = {'modules': finder.observed(), 'resources': [{'path': str(descriptor),
            'sha256': hashlib.sha256(body).hexdigest()}], 'inventory_sha256': provider['inventory_sha256'],
            'identity_sha256': consumer.policy.digest(before), 'provider_readonly': True}
        output['provider_imported'] = True
        if packet['mode'] == 'replay':
            output['phase'] = 'replay'; replay(consumer, approved, packet, output)
        else:output.update(decision='extension_required', condition='origins_observed')
    except Exception:
        output.update(decision='invalid_proof', condition='invalid_proof')
    finally:
        consumer.require(consumer.provider_inventory(approved) == before)
        if output['provider_imported']:output['origins']['modules'] = finder.observed()
    if output['decision'] != 'invalid_proof':output['phase'] = 'complete'
    return output


if __name__ == '__main__':
    try:
        consumer, approved, packet = bootstrap()
        observed = run(consumer, approved, packet)
        consumer.validate_result(observed, approved, packet['mode'])
        sys.stdout.buffer.write(consumer.policy.canonical(observed))
    except Exception:
        # No traceback, encountered path, PID, CID, argv or exception text escapes.
        sys.stdout.buffer.write(b'{"invalid_worker_result":true}')
