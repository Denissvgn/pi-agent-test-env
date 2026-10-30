"""Exact references and existing coordination; no creation, discovery or default."""
import fcntl
import os
import json
import re
from pathlib import PurePosixPath
import stat

from . import secret_registration_contract as contract
from . import secret_registration_posix as native
from .source import Namespace, header, identity
from .wire import SDKError, require
from .wire import PrivateData


class Coordination:
    def __init__(self, path, expected_identity):
        selected = PurePosixPath(path); self._parent = None; self.fd = None
        self._closed = False; self._known = True; self._locked = False; self._name = selected.name
        try:
            self._parent = Namespace(str(selected.parent), private=True)
            self.fd = native.open_file(selected.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                       dir_fd=self._parent.fd)
            info = os.fstat(self.fd)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                    and stat.S_IMODE(info.st_mode) == 0o600 and identity(info) == tuple(expected_identity), 11)
            self._header = header(info)
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._locked = True; self.verify()
        except BaseException as error:
            if not self.close(): raise SDKError(6) from None
            if isinstance(error, SDKError): raise
            raise SDKError(11) from None

    def __repr__(self): return '<sdk>'

    def verify(self):
        require(self._locked and not self._closed, 11)
        self._parent.verify()
        try: require(header(os.fstat(self.fd)) == self._header == header(self._parent.stat(self._name)), 11)
        except OSError: raise SDKError(11) from None

    def close(self):
        if self._closed: return self._known
        self._closed = True; self._locked = False
        if self.fd is not None:
            fd = self.fd; self.fd = None
            # Never LOCK_UN a shared open-file description. Parent closes only
            # after child cleanup/receiver checks; a child borrow is not owned.
            try: native.close(fd)
            except BaseException: self._known = False
        if self._parent is not None: self._known &= self._parent.close()
        return self._known


class Values:
    def __init__(self, rows): self._data = PrivateData(rows)
    def private(self): return self._data.get()
    def __iter__(self): return iter(self.private())
    def __repr__(self): return '<sdk>'


def references(namespace, declarations, maximum_file, maximum_total, *, progress=None):
    require(type(declarations) is list and len(declarations) <= 128, 5)
    rows = []; total = 0; application_values = set(); inference = None
    if progress is not None: progress.update(attempted=0, complete=0, coverage=False)
    for item in declarations:
        require(total + item['size'] <= maximum_total, 5)
        if progress is not None: progress['attempted'] += 1
        body = namespace.read_private(item['reference'], item, maximum_file)
        total += len(body)
        try:
            value = body.decode('utf-8')
            contract.validate_value(value, item.get('value_contract', 'application_credential_1'))
        except (UnicodeError, contract.TraceError): raise SDKError(7) from None
        if item['role'] == 'inference':
            require(inference is None, 7); inference = value
        elif item['role'] == 'application':
            require(value not in application_values, 7); application_values.add(value)
        rows.append({**item, 'value': value})
        if progress is not None: progress['complete'] += 1
    require(inference is None or inference not in application_values, 7)
    if progress is not None: progress['coverage'] = True
    return Values(rows)


class Patterns:
    """Exact UTF-8 values and three declared JSON-string escape layers."""
    def __init__(self, values, limits):
        patterns=set(); total=0
        for value in values:
            try: contract.validate_value(value, 'normalized_secret_1')
            except contract.TraceError: raise SDKError(7) from None
            current={value}
            for layer in range(4):
                for text in current:
                    body=text.encode('utf-8')
                    if body not in patterns:
                        require(len(patterns)<limits['max_pattern_count']and total+len(body)<=limits['max_pattern_bytes'],5)
                        patterns.add(body);total+=len(body)
                if layer<3:
                    current={json.dumps(text,ensure_ascii=ascii_only)[1:-1]
                             for text in current for ascii_only in (True,False)}
        quoted=[re.escape(p)for p in sorted(patterns,key=lambda p:(-len(p),p))]
        require(sum(map(len,quoted))+max(0,len(quoted)-1)<=limits['max_regex_bytes'],5)
        self._regex=re.compile(b'|'.join(quoted))if quoted else None
    def contains(self, body):return bool(self._regex and self._regex.search(body))
    def replace(self,body):return self._regex.sub(b'<REDACTED>',body)if self._regex else body
    def __repr__(self):return '<sdk>'
