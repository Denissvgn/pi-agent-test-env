"""Explicit no-follow native namespaces and approved, bounded source reads."""
import hashlib
import importlib.abc
import importlib.util
import os
from pathlib import PurePosixPath
import stat
import sys
from types import MappingProxyType

from . import policy
from . import secret_registration_posix as native
from .wire import SDKError, require


def header(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def identity(info): return info.st_dev, info.st_ino


def directory_header(info): return info.st_dev, info.st_ino, info.st_uid, info.st_mode


class Namespace:
    """Owned held/named directory chain; this class supplies no authority."""
    def __init__(self, path, expected_identity=None, *, private):
        try: selected = policy.path(path)
        except policy.PolicyError: raise SDKError(1) from None
        require(len(selected.parts) <= 33, 5)
        self.path, self.private = str(selected), private
        self._fds = []; self._chain = []; self._closed = False; self._close_known = True
        try:
            parent = None
            for index, name in enumerate(selected.parts):
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
                fd = native.open_file(name, flags) if parent is None else native.open_file(name, flags, dir_fd=parent)
                self._fds.append(fd)
                info = os.fstat(fd); mode = stat.S_IMODE(info.st_mode)
                require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.geteuid())
                        and (not mode & 0o022 or info.st_uid == 0 and mode & stat.S_ISVTX), 4)
                self._chain.append((fd, parent, name, directory_header(info)))
                parent = fd
            self.fd = parent
            info = os.fstat(self.fd)
            if private: require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, 4)
            if expected_identity is not None: require(identity(info) == tuple(expected_identity), 4)
            self.verify()
        except BaseException as error:
            if not self.close(): raise SDKError(6) from None
            if isinstance(error, SDKError): raise
            raise SDKError(4) from None

    def __repr__(self): return '<sdk>'

    def verify(self):
        require(not self._closed, 4)
        try:
            for fd, parent, name, expected in self._chain:
                current = os.fstat(fd)
                named = os.stat(name, follow_symlinks=False) if parent is None else os.stat(name, dir_fd=parent, follow_symlinks=False)
                require(directory_header(current) == expected == directory_header(named), 4)
        except OSError: raise SDKError(4) from None

    def stat(self, name):
        require(type(name) is str and PurePosixPath(name).name == name and name not in ('.', '..')
                and '/' not in name and '\0' not in name, 1)
        self.verify()
        try: return os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        except OSError: raise SDKError(4) from None

    def absent(self, name):
        require(type(name)is str and PurePosixPath(name).name==name and name not in('.', '..')
                and '/'not in name and '\0'not in name,1)
        self.verify()
        try:os.stat(name,dir_fd=self.fd,follow_symlinks=False)
        except FileNotFoundError:
            self.verify();return True
        except OSError:raise SDKError(4)from None
        raise SDKError(4)

    def read_file(self, name, maximum, *, private=False, expected=None, expected_sha=None, expected_size=None, readonly=False, reserve=None):
        require(type(maximum) is int and 0 <= maximum <= 67108864, 5)
        require(type(name) is str and PurePosixPath(name).name == name and name not in ('.', '..')
                and '/' not in name and '\0' not in name, 1)
        self.verify(); fd = None; result = None; close_known = True
        try:
            if readonly: require(os.fstatvfs(self.fd).f_flag & os.ST_RDONLY, 4)
            fd = native.open_file(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.fd)
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum, 4)
            if expected_size is not None:require(before.st_size==expected_size,4)
            if private: require(before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o600, 4)
            if expected is not None:
                require(identity(before) == tuple(expected['identity']) and before.st_size == expected['size']
                        and before.st_mtime_ns == expected['mtime_ns'] and before.st_ctime_ns == expected['ctime_ns'], 4)
            if reserve is not None: reserve(before.st_size)
            body = bytearray()
            while len(body) < before.st_size:
                chunk = os.read(fd, min(65536, before.st_size - len(body)))
                require(bool(chunk), 4)
                body.extend(chunk); require(len(body) <= before.st_size, 5)
            require(header(before) == header(os.fstat(fd)) == header(os.stat(name, dir_fd=self.fd, follow_symlinks=False)), 4)
            self.verify(); result = bytes(body)
            if expected_sha is not None: require(hashlib.sha256(result).hexdigest() == expected_sha, 4)
        except SDKError: raise
        except (OSError, UnicodeError): raise SDKError(6) from None
        finally:
            if fd is not None:
                closing = fd; fd = None
                try: native.close(closing)
                except BaseException: close_known = False
            if not close_known: raise SDKError(6) from None
        return result

    def read_private(self, reference, expected, maximum):
        require(self.private, 2)
        return self.read_file(reference, maximum, private=True, expected=expected)

    def close(self):
        if self._closed: return self._close_known
        self._closed = True
        while self._fds:
            fd = self._fds.pop()
            try: native.close(fd)
            except BaseException: self._close_known = False
        return self._close_known


class ReadBudget:
    """Shared reservation across pre/post verification; failures never refund."""
    def __init__(self,maximum_bytes,maximum_files,*,initial_bytes=0,initial_files=0):
        require(type(maximum_bytes)is int and type(maximum_files)is int and maximum_files>=0
                and type(initial_bytes)is int and 0<=initial_bytes<=maximum_bytes
                and type(initial_files)is int and 0<=initial_files<=maximum_files,5)
        self.maximum=maximum_bytes;self.maximum_files=maximum_files;self.reserved=initial_bytes;self.count=initial_files
    def attempt(self):
        require(self.count<self.maximum_files,5);self.count+=1
    def reserve(self,size):
        require(type(size)is int and size>=0 and self.reserved+size<=self.maximum,5);self.reserved+=size
    def require_remaining(self,size,count):
        require(self.reserved+size<=self.maximum and self.count+count<=self.maximum_files,5)


class ApprovedReader:
    def __init__(self, allowed, *, max_file_bytes, max_total_bytes, max_files, budget=None):
        self._allowed = MappingProxyType({name: MappingProxyType(dict(grant)) for name, grant in allowed.items()})
        self.maximum_file, self.maximum_total, self.maximum_count = max_file_bytes, max_total_bytes, max_files
        self.total = self.count = self.reserved = 0; self.observations = []
        self.budget=budget if budget is not None else ReadBudget(max_total_bytes,max_files)

    @property
    def allowed(self): return self._allowed

    def _reserve(self, size):
        require(self.reserved + size <= self.maximum_total, 5)
        self.budget.reserve(size)
        self.reserved += size  # A failed/partial read never refunds admission.

    def read(self, path, maximum):
        selected = str(path)
        require(selected in self.allowed, 2)  # No lookup precedes exact scope membership.
        try: parsed = policy.path(selected)
        except policy.PolicyError: raise SDKError(1) from None
        grant = self.allowed[selected]
        # Provider callers request fixed ceilings (prompt/profile sizes). The narrower
        # grant and admitted file cap bind the read; read_file refuses, never truncates,
        # a larger file, so clamping cannot return partial bytes.
        require(type(maximum) is int and maximum >= 0, 5)
        bound = min(maximum, grant['maximum_bytes'], self.maximum_file)
        require(self.count < self.maximum_count, 5)
        self.budget.attempt()
        self.count += 1
        namespace = Namespace(str(parsed.parent), private=False)
        try:
            body = namespace.read_file(parsed.name, bound, expected_sha=grant['sha256'],
                                       expected_size=grant.get('size'),readonly=grant['readonly'], reserve=self._reserve)
        finally:
            require(namespace.close(), 6)
        self.total += len(body)
        self.observations.append({'path': selected, 'sha256': grant['sha256'], 'bytes': len(body)})
        return body


def verify_tree(root, files, limits):
    """Exact read-only artifact inventory; no private roots are traversed."""
    try: selected = policy.path(root)
    except policy.PolicyError: raise SDKError(1) from None
    expected_dirs = {'.'}
    for name in files:
        try: relative = policy.path(name, False)
        except policy.PolicyError: raise SDKError(1) from None
        expected_dirs.update(str(parent) for parent in relative.parents)
    seen = set(); directories = set(); count = 0
    def walk(fd, relative):
        nonlocal count
        count += 1; require(count <= limits['max_source_files'] * 2 + 64, 5)
        before=os.fstat(fd);require(stat.S_ISDIR(before.st_mode)and os.fstatvfs(fd).f_flag&os.ST_RDONLY,4)
        key=str(relative);require(key in expected_dirs,4);directories.add(key)
        names=[];unique=set()
        with os.scandir(fd)as entries:
            for entry in entries:
                name=entry.name;key=str(relative/name)
                require(key in files or key in expected_dirs,4)
                require(name not in unique and len(names)<len(files)+len(expected_dirs),5)
                unique.add(name);names.append(name)
        names.sort()
        for name in names:
            child=relative/name;key=str(child)
            require(key in files or key in expected_dirs,4)
            info=os.stat(name,dir_fd=fd,follow_symlinks=False)
            if key in expected_dirs:
                require(stat.S_ISDIR(info.st_mode),4)
                owned=native.open_file(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                try:
                    require(header(info)==header(os.fstat(owned)),4);walk(owned,child)
                    require(header(info)==header(os.fstat(owned))==header(os.stat(name,dir_fd=fd,follow_symlinks=False)),4)
                finally:
                    try:native.close(owned)
                    except BaseException:raise SDKError(6)from None
            else:
                require(stat.S_ISREG(info.st_mode)and info.st_nlink==1,4);seen.add(key)
        require(header(before)==header(os.fstat(fd)),4)
    namespace=Namespace(str(selected),private=False)
    try:
        walk(namespace.fd,PurePosixPath('.'));namespace.verify()
    except OSError:raise SDKError(4)from None
    finally:require(namespace.close(),6)
    require(seen == set(files) and directories == expected_dirs, 4)


class Provider:
    """Fixed verified-source importer and separately approved resource reader."""
    def __init__(self, deployment, limits, *, budget=None):
        self.deployment, self.limits = deployment, limits
        self.root = deployment['provider_root']; self.modules = dict(deployment['modules'])
        self.loaded = {}; self._finder = None
        verify_tree(self.root, deployment['provider_files'], limits)
        require(not set(self.modules) & set(sys.modules), 4)
        allowed = {self.root + '/' + relative: {'sha256': deployment['provider_files'][relative],
            'maximum_bytes': deployment['provider_sizes'][relative], 'size':deployment['provider_sizes'][relative], 'readonly': True}
            for relative in self.modules.values()}
        self.reader = ApprovedReader(allowed, max_file_bytes=limits['max_source_file_bytes'],
            max_total_bytes=limits['max_source_bytes'] // 2, max_files=limits['max_source_files'],budget=budget)
        self.all_names = {PurePosixPath(name).stem for name in deployment['provider_files']
                          if name.endswith('.py') and PurePosixPath(name).parent in (PurePosixPath('scripts'), PurePosixPath('runtime'))}

    def install(self):
        owner = self
        class Loader(importlib.abc.Loader):
            def __init__(self, name): self.name = name
            def create_module(self, spec): return None
            def exec_module(self, module):
                filename = owner.root + '/' + owner.modules[self.name]
                body = owner.reader.read(filename, owner.limits['max_source_file_bytes'])
                module.__file__ = filename
                code = compile(body, filename, 'exec', dont_inherit=True)
                exec(code, module.__dict__)
                owner.loaded[self.name] = {'name': self.name, 'path': filename,
                    'sha256': hashlib.sha256(body).hexdigest(), 'code_filename': code.co_filename,
                    'spec_origin': getattr(module.__spec__, 'origin', None), 'loader_kind': 'verified_source','bytes':len(body)}
        class Finder(importlib.abc.MetaPathFinder):
            def find_spec(self, name, path=None, target=None):
                if name in owner.modules:
                    return importlib.util.spec_from_loader(name, Loader(name), origin=owner.root + '/' + owner.modules[name])
                if name in owner.all_names: raise SDKError(4)
                return None
        self._finder = Finder(); sys.meta_path.insert(0, self._finder)

    def preload(self):
        import importlib
        for name in sorted(self.modules): importlib.import_module(name)

    def module(self, name):
        require(name in self.modules and name in self.loaded, 4)
        return sys.modules[name]

    def conserve(self):
        verify_tree(self.root, self.deployment['provider_files'], self.limits)
        for name, observation in self.loaded.items():
            body = self.reader.read(observation['path'], self.limits['max_source_file_bytes'])
            require(hashlib.sha256(body).hexdigest() == observation['sha256'], 4)
        return True

    def close(self):
        if self._finder in sys.meta_path: sys.meta_path.remove(self._finder)
