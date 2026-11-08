"""Policy-gated operation SDK. Trust the consumer bootstrap independently first.

No provider, private source or operation is selected by importing this package.
"""
SDK_VERSION = 1


def load_verified(root, expected_files):
    """Load checked SDK source without sibling bytecode.

    The caller must trust this bootstrap independently before invoking it.
    expected_files comes from separately approved configuration, not discovery.
    This creates a client, never an operation approval or a worker.
    """
    import hashlib
    import importlib.abc
    import importlib.machinery
    import importlib.util
    import os
    from pathlib import PurePosixPath
    import stat
    import sys

    names = frozenset(('__init__.py', 'policy.py', 'wire.py', 'client.py', 'worker.py',
        'source.py', 'collect.py', 'runtime.py', 'state.py', 'secret_registration_contract.py',
        'secret_registration_primitive.py', 'secret_registration_posix.py'))
    def check(condition):
        if not condition: raise ValueError('sdk_bootstrap')
    check(type(root) is str and str(PurePosixPath(root)) == root and root.startswith('/')
          and '..' not in PurePosixPath(root).parts and not root.startswith('//')
          and __name__ == 'operation_sdk' and len(PurePosixPath(root).parts) <= 33
          and not any(ord(c) < 32 or ord(c) == 127 for c in root))
    check(type(expected_files) is dict and set(expected_files) == names)
    check(not any(name.startswith(__name__ + '.') for name in sys.modules))
    bodies = {}
    parent = None
    try:
        for part in PurePosixPath(root).parts:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            **({} if parent is None else {'dir_fd': parent}))
            if parent is not None: os.close(parent)
            parent = child
        check(os.fstatvfs(parent).f_flag & os.ST_RDONLY)
        for name in sorted(names):
            pin = expected_files[name]
            check(type(pin) is str and len(pin) == 64 and all(c in '0123456789abcdef' for c in pin))
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            try:
                info = os.fstat(fd); check(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 1048576)
                chunks = []; size = 0
                while size < info.st_size:
                    body = os.read(fd, min(65536, info.st_size - size)); check(bool(body))
                    size += len(body); chunks.append(body)
                body = b''.join(chunks); after = os.fstat(fd)
                named = os.stat(name, dir_fd=parent, follow_symlinks=False)
                signature = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
                check(signature(info) == signature(after) == signature(named)
                      and hashlib.sha256(body).hexdigest() == pin)
                bodies[name[:-3]] = body
            finally: os.close(fd)
    finally:
        if parent is not None: os.close(parent)

    package = sys.modules[__name__]
    package.__path__ = [root]
    package.__sdk_files__ = dict(expected_files)
    package.__sdk_sizes__ = {name+'.py':len(body)for name,body in bodies.items()}
    package.__sdk_root__ = root
    package.__sdk_observations__ = [{'name': __name__, 'path': root + '/__init__.py',
        'sha256': hashlib.sha256(bodies['__init__']).hexdigest(),
        'code_filename': load_verified.__code__.co_filename,
        'spec_origin': getattr(getattr(package, '__spec__', None), 'origin', None),
        'loader_kind': 'trusted_bootstrap'}]
    class Loader(importlib.abc.Loader):
        __sdk_verified__ = True
        def __init__(self, name): self.name = name
        def create_module(self, spec): return None
        def exec_module(self, module):
            stem = self.name.rsplit('.', 1)[-1]
            filename = root + '/' + stem + '.py'
            module.__file__ = filename
            code = compile(bodies[stem], filename, 'exec', dont_inherit=True)
            exec(code, module.__dict__)
            package.__sdk_observations__.append({'name': self.name, 'path': filename,
                'sha256': hashlib.sha256(bodies[stem]).hexdigest(), 'code_filename': code.co_filename,
                'spec_origin': getattr(module.__spec__, 'origin', None), 'loader_kind': 'verified_source'})
    class Finder(importlib.abc.MetaPathFinder):
        def find_spec(self, name, path=None, target=None):
            if not name.startswith(__name__ + '.'): return None
            stem = name[len(__name__) + 1:]
            check('.' not in stem and stem in bodies)
            return importlib.util.spec_from_loader(name, Loader(name), origin=root + '/' + stem + '.py')
    sys.meta_path.insert(0, Finder())
    import importlib
    return importlib.import_module(__name__ + '.client').Client()
