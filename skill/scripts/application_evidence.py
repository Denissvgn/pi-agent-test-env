"""Private durable evidence/state storage for one owned application helper.

Only generated helper-relative names are written. No credential values, secret
digests or consistency tags belong in this store. The owner supplies redacted
capture bytes; an incomplete unsanitizable capture must be marked unavailable.
"""
import fcntl
import hashlib
import os
from pathlib import PurePosixPath
import stat
import uuid

import application_contracts as c


class EvidenceError(ValueError):
    def __init__(self, reason='evidence_unavailable'):
        self.reason = reason
        super().__init__(reason)


def open_directory(path, private=False):
    raw = os.fspath(path)
    if type(raw) is not str or not raw.startswith('/') or str(PurePosixPath(raw)) != raw:
        raise EvidenceError()
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in PurePosixPath(raw).parts[1:]:
            if part in ('.', '..'):
                raise EvidenceError()
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or (private and stat.S_IMODE(info.st_mode) & 0o077):
            raise EvidenceError()
        return fd
    except BaseException:
        os.close(fd)
        raise


def _parent(root, path, create=False):
    c.relative(path, '')
    fd = os.dup(root)
    try:
        parts = path.split('/')
        for part in parts[:-1]:
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                    os.fsync(fd)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
                raise EvidenceError()
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise


def read_file(root, path, maximum):
    parent, leaf = _parent(root, path)
    fd = None
    try:
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        if (before.st_uid != os.getuid() or not stat.S_ISREG(before.st_mode) or
                before.st_nlink != 1 or before.st_size > maximum):
            raise EvidenceError()
        chunks, left = [], maximum + 1
        while left:
            chunk = os.read(fd, min(65536, left))
            if not chunk:
                break
            chunks.append(chunk)
            left -= len(chunk)
        body = b''.join(chunks)
        after = os.fstat(fd)
        if len(body) > maximum or any(getattr(before, k) != getattr(after, k) for k in
                ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink', 'st_mode')):
            raise EvidenceError()
        return body
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


class EvidenceStore:
    """One lifetime file lock, atomic fsynced state and no-follow capture writes."""
    def __init__(self, root, limits):
        self.root = self.lock = None
        try:
            self.root = open_directory(root, private=True)
            self.lock = os.open('.owner.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                                0o600, dir_fd=self.root)
            info = os.fstat(self.lock)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise EvidenceError()
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.limits = dict(limits)
            try:
                self.state = c.loads(read_file(self.root, 'state.json', 8388608), max_bytes=8388608)
                c.exact(self.state, {'schema', 'next_sequence', 'stages', 'receipts', 'pending',
                                     'identities', 'writes', 'chains', 'cursors', 'calls', 'blocked', 'generations', 'operation_usage', 'browser_actions', 'state_sha256'}, '')
                c.sha256(self.state['state_sha256'], '/state_sha256')
                if self.state['state_sha256'] != c.digest({key: value for key, value in self.state.items() if key != 'state_sha256'}):
                    raise EvidenceError()
                c.choice(self.state['schema'], (1,), '/schema')
                c.integer(self.state['next_sequence'], '/next_sequence', 1, 501)
                for field in set(self.state) - {'schema', 'next_sequence', 'state_sha256'}:
                    if type(self.state[field]) is not dict or len(self.state[field]) > 4000:
                        raise EvidenceError()
            except FileNotFoundError:
                if set(os.listdir(self.root)) - {'.owner.lock'}:
                    raise EvidenceError()
                self.state = {'schema': 1, 'next_sequence': 1, **{key: {} for key in
                    ('stages', 'receipts', 'pending', 'identities', 'writes', 'chains', 'cursors', 'calls', 'blocked', 'generations', 'operation_usage', 'browser_actions')}}
                self.save()
            # A crash with an unsealed intent cannot grant a fresh business action.
            for pending in self.state['pending'].values():
                self.state['blocked'][pending['stage_id']] = 'evidence_unavailable'
            for action in self.state['browser_actions'].values():
                self.state['blocked'][action['stage_id']] = 'browser_action_unsealed'
            # Immutable consumed write grants are the recovery fence. Even a
            # successful projection cannot authorize business continuation in a
            # recreated helper: its final state replace/fsync may be uncertain.
            for write in self.state['writes'].values():
                c.exact(write, {'stage_id', 'operation_instance_id', 'receipt_id'}, '')
                for field, value in write.items():
                    c.slug(value, '/' + field)
                self.state['blocked'][write['stage_id']] = 'prior_write_requires_fresh_preparation'
            self.save()
        except Exception:
            self.close()
            raise EvidenceError() from None

    def close(self):
        for name in ('lock', 'root'):
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)

    def put(self, path, body, replace=False):
        parent = fd = None
        temporary = '.new-' + uuid.uuid4().hex
        try:
            parent, leaf = _parent(self.root, path, create=True)
            if not replace:
                fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            else:
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            view = memoryview(body)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise EvidenceError()
                view = view[count:]
            os.fsync(fd)
            os.close(fd)
            fd = None
            if replace:
                os.replace(temporary, leaf, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        except Exception:
            raise EvidenceError() from None
        finally:
            if fd is not None:
                os.close(fd)
            if parent is not None:
                os.close(parent)

    def save(self):
        self.state['state_sha256'] = c.digest({key: value for key, value in self.state.items() if key != 'state_sha256'})
        body = c.canonical(self.state)
        if len(body) > 8388608:
            raise EvidenceError()
        self.put('state.json', body, replace=True)

    def reserve(self, stage_id, worst_bytes, reservation=None):
        stage = self.state['stages'].setdefault(stage_id, {'receipts': 0, 'bytes': 0})
        reserved = sum(action['remaining'] for action in self.state['browser_actions'].values())
        if (self.state['next_sequence'] > self.limits['max_receipts'] or stage['receipts'] >= self.limits['max_receipts']):
            raise EvidenceError('evidence_limit')
        if reservation is None:
            if sum(item['bytes'] for item in self.state['stages'].values()) + len(c.canonical(self.state)) + reserved + worst_bytes > self.limits['max_evidence_bytes']:
                raise EvidenceError('evidence_limit')
        else:
            action = self.state['browser_actions'].get(reservation)
            if action is None or action['stage_id'] != stage_id or action['remaining'] < worst_bytes:
                raise EvidenceError('evidence_limit')
            action['remaining'] -= worst_bytes
        sequence = self.state['next_sequence']
        self.state['next_sequence'] += 1
        stage['receipts'] += 1
        self.save()
        return sequence

    def index(self, stage_id, *, allowed_segment_ids):
        return {key: {'path': value['path'], 'sha256': value['sha256']}
                for key, value in self.state['receipts'].items() if value['stage_id'] == stage_id
                and value['segment_id'] in allowed_segment_ids}

    def seal(self, stage_id, receipt, request, response=None, response_redactions=()):
        prefix = 'evidence/' + receipt['receipt_id']
        captures = [('request', request, ['authentication_value'])]
        if response is not None:
            captures.append(('response', response, list(response_redactions)))
        receipt['evidence'] = []
        size = 0
        for kind, body, redactions in captures:
            path = prefix + '/' + kind + '.txt'
            self.put(path, body)
            size += len(body)
            receipt['evidence'].append({'kind': kind, 'path': path, 'sha256': hashlib.sha256(body).hexdigest(),
                                         'bytes': len(body), 'redactions': redactions})
        c.validate_receipt(receipt)
        body = c.canonical(receipt)
        path = 'receipts/' + receipt['receipt_id'] + '.json'
        self.put(path, body)
        size += len(body)
        self.state['receipts'][receipt['receipt_id']] = {'path': path, 'sha256': hashlib.sha256(body).hexdigest(),
            'stage_id': stage_id, 'segment_id': receipt['binding']['segment_id']}
        self.state['stages'][stage_id]['bytes'] += size
        self.state['pending'].pop(receipt['receipt_id'], None)
        self.save()
        return receipt['receipt_id']
