"""Internal descriptor-bound discard primitive; no CLI dispatch or publication.

The owner publisher must persist its intent and selection before invoking purge.
An in-memory operation is never an accepted cleanup proof or an adoption route.
"""
import copy
import os
from pathlib import Path
import stat

import application_owner_cleanup as cleanup
import application_owner_legacy_native as native
import application_owner_legacy_protocol as protocol


def _overlap(left, right):
    return left == right or left in right.parents or right in left.parents


def _node(info, device):
    cleanup.require(info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o022, 'unsafe_path')
    cleanup.require(info.st_dev == device, 'sensitive_identity_mismatch')
    if stat.S_ISDIR(info.st_mode):return True, (info.st_dev, info.st_ino, info.st_mode, info.st_uid)
    cleanup.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'unsafe_path')
    return False, cleanup._purge_signature(info)


class _Root:
    def __init__(self, observation):
        self.observation = copy.deepcopy(observation); self.path = cleanup.path(observation['path'])
        self.parent = None; self.fd = None; self.removed = False; self.missing = None
        try:
            ancestor = self.path.parent; tail = [self.path.name]
            while True:
                try:self.parent = cleanup.directory(ancestor); break
                except FileNotFoundError:
                    cleanup.require(observation['state'] == 'absent' and ancestor != Path('/'), 'sensitive_identity_mismatch')
                    tail.insert(0, ancestor.name); ancestor = ancestor.parent
            self.parent_path = ancestor; self.parent_identity = cleanup.identity(os.fstat(self.parent))
            if observation['state'] == 'present':
                cleanup.require(ancestor == self.path.parent)
                self.fd = os.open(self.path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.parent)
                cleanup.require(cleanup.identity(os.fstat(self.fd)) == observation['identity'], 'sensitive_identity_mismatch')
            else:self.missing = tail[0]
            self.verify(); self.inventory = self.scan() if self.fd is not None else {}
        except BaseException:
            try:self.close()
            except BaseException:pass
            raise

    def verify(self):
        named = cleanup.directory(self.parent_path)
        try:cleanup.require(cleanup.identity(os.fstat(named)) == self.parent_identity
                            == cleanup.identity(os.fstat(self.parent)), 'sensitive_identity_mismatch')
        finally:os.close(named)
        if self.fd is None or self.removed:
            name = self.missing if self.fd is None else self.path.name
            try:os.stat(name, dir_fd=self.parent, follow_symlinks=False)
            except FileNotFoundError:return
            cleanup.require(False, 'sensitive_identity_mismatch')
        held = os.fstat(self.fd); named = os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False)
        cleanup.require(cleanup.identity(held) == cleanup.identity(named) == self.observation['identity'], 'sensitive_identity_mismatch')
        _node(held, self.observation['identity'][0]); _node(named, self.observation['identity'][0])

    def scan(self):
        self.verify(); result = {}; count = [0]; device = self.observation['identity'][0]
        def walk(fd, prefix):
            before = os.fstat(fd); result[prefix] = _node(before, device)
            for name in cleanup._purge_names(fd, count):
                info = os.stat(name, dir_fd=fd, follow_symlinks=False); parts = prefix + (name,)
                result[parts] = _node(info, device)
                if result[parts][0]:
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        cleanup.require(cleanup._purge_signature(os.fstat(child)) == cleanup._purge_signature(info), 'sensitive_identity_mismatch')
                        walk(child, parts)
                        cleanup.require(cleanup.identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) == cleanup.identity(info), 'sensitive_identity_mismatch')
                    finally:os.close(child)
            cleanup.require(cleanup._purge_signature(os.fstat(fd)) == cleanup._purge_signature(before), 'sensitive_identity_mismatch')
        walk(self.fd, ()); self.verify(); return result

    def close(self):
        errors = []
        for name in ('fd', 'parent'):
            fd = getattr(self, name); setattr(self, name, None)
            if fd is not None:
                try:os.close(fd)
                except OSError as error:errors.append(error)
        if errors:raise errors[0]


class _BoundCleanup:
    """Private one-shot primitive; obtain authority only from complete originals."""
    @cleanup.diagnostics.scoped('owner_legacy_scope', 'cleanup_proof_invalid')
    def __init__(self, registry, request, *, discard_workspace=False, reader=None):
        self.registry = registry; self.request = copy.deepcopy(request)
        self.reader = cleanup.Reader() if reader is None else reader
        self.roots = []; self.held = {}; self.protected = {}; self.effects = 'none_observed'
        self.cleanup_completed = False; self.attempted = False; self.closed = False
        try:
            cleanup.require(discard_workspace is True, 'owner_discard_required')
            native._lease(registry)
            unused, unused, plan = protocol._plan(registry, self.request, self.reader)
            self.paths = [cleanup.path(row['path']) for row in plan['roots']]
            cleanup.require(all(not _overlap(left, right) for i, left in enumerate(self.paths) for right in self.paths[i+1:]), 'owner_scope_unsupported')
            self._protect()
            self.observation = native.observe(registry, self.request, reader=self.reader)
            cleanup.require(self.observation['plan']['roots'] == plan['roots'] and self.observation['plan']['metadata'] == plan['metadata'])
            for name, identity in self.observation['commitment']['directories'].items():
                fd = cleanup.directory(cleanup.path(name)); self.held[name] = (fd, identity)
                cleanup.require(cleanup.identity(os.fstat(fd)) == identity, 'sensitive_identity_mismatch')
            for row in plan['roots']:self.roots.append(_Root(row))
            self._verify(); self._protect()
        except BaseException:
            try:self.close()
            except BaseException:pass
            raise

    def _protect(self):
        for name, ref in list(self.reader.references.items()):
            target = cleanup.path(name)
            cleanup.require(not any(target == root or root in target.parents for root in self.paths), 'unsafe_path')
            if name in self.protected:cleanup.require(self.protected[name] == ref)
            else:self.protected[name] = copy.deepcopy(ref)
        for name, ref in self.protected.items():
            unused, observed = self.reader.read_bytes(name, private=name in self.reader.private_paths,
                private_parent=name in self.reader.private_parent_paths)
            cleanup.require(observed == ref)

    def _verify(self):
        cleanup.require(not self.closed, 'cleanup_proof_invalid')
        for name, (fd, expected) in self.held.items():
            named = cleanup.directory(cleanup.path(name))
            try:cleanup.require(cleanup.identity(os.fstat(named)) == cleanup.identity(os.fstat(fd)) == expected, 'sensitive_identity_mismatch')
            finally:os.close(named)
        for root in self.roots:root.verify()

    @cleanup.diagnostics.scoped('owner_legacy_scope', 'cleanup_proof_invalid')
    def purge(self):
        cleanup.require(not self.attempted and not self.closed); self.attempted = True
        self._verify(); self._protect()
        native.observe(self.registry, self.request, reader=self.reader, expected=self.observation)
        self._verify(); self._protect()
        for root in self.roots:
            if root.fd is not None:cleanup.require(root.scan() == root.inventory, 'sensitive_identity_mismatch')
        for root in self.roots:
            if root.fd is None:continue
            def checkpoint(parts, info, mutating):
                self._verify()
                cleanup.require(parts in root.inventory and _node(info, root.observation['identity'][0]) == root.inventory[parts], 'sensitive_identity_mismatch')
                if mutating:self.effects = 'may_have_occurred'
            cleanup._purge(root.observation, parent_fd=root.parent, root_fd=root.fd, checkpoint=checkpoint)
            root.removed = True
            self._verify(); self._protect()
        self._verify(); self._protect()
        post = native.observe(self.registry, self.request, reader=self.reader)
        expected = copy.deepcopy(self.observation['commitment'])
        expected['roots'] = [{'path': row['path'], 'state': 'absent', 'identity': None} for row in expected['roots']]
        cleanup.require(cleanup.canonical(post['commitment']) == cleanup.canonical(expected))
        self._verify(); self._protect(); self.cleanup_completed = True
        return {'cleanup_completed': True, 'effects': self.effects, 'admission_authorized': False,
                'original_outcome_regraded': False, 'new_containers': 0, 'participant_stages': 0, 'model_requests': 0,
                'roots': copy.deepcopy(self.observation['plan']['roots']), 'post': post}

    def __enter__(self):return self

    def __exit__(self, kind, error, traceback):
        try:self.close()
        except BaseException:
            if error is None:raise

    def close(self):
        if self.closed:return
        self.closed = True; errors = []
        for root in self.roots:
            try:root.close()
            except OSError as error:errors.append(error)
        for fd, unused in self.held.values():
            try:os.close(fd)
            except OSError as error:errors.append(error)
        self.held.clear()
        if errors:
            self.cleanup_completed = False
            raise errors[0]
