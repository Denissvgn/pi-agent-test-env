"""Bounded process-local tombstones. These transitions are not OS observations."""
import threading
from .wire import SDKError, require

_LOCK = globals().get('_LOCK', threading.Lock())
_RECORDS = globals().get('_RECORDS', {})
_OPERATIONS = globals().get('_OPERATIONS', set())
_SOURCES = globals().get('_SOURCES', set())


class SessionState:
    def __init__(self, request_id): self._id = request_id
    def __repr__(self): return '<sdk>'
    @property
    def phase(self):
        with _LOCK: return _RECORDS[self._id]['phase']
    def _transition(self, before, after):
        with _LOCK:
            row = _RECORDS[self._id]; require(row['phase'] == before, 12); row['phase'] = after
    def ready(self, context):
        with _LOCK:
            row = _RECORDS[self._id]
            require(row['phase'] == 'reserved' and row['context'] == context, 4)
            row['phase'] = 'ready'
    def claim(self, now_ns):
        with _LOCK:
            row = _RECORDS[self._id]
            require(row['phase'] == 'ready', 12)
            row['phase'] = 'spent'  # Even an expired/failed claim is not reusable.
            require(type(now_ns) is int and row['created'] <= now_ns < row['expires'], 3)
            row['phase'] = 'claimed'
    def sent(self): self._transition('claimed', 'sent')
    def received(self): self._transition('sent', 'received')
    def accept(self,now_ns):
        with _LOCK:
            row=_RECORDS[self._id];require(row['phase']=='received',12)
            row['phase']='spent'
            require(type(now_ns)is int and row['created']<=now_ns<row['expires'],3)
            row['phase']='accepted'
    def fail(self):
        with _LOCK:
            row = _RECORDS[self._id]
            if row['phase'] != 'accepted': row['phase'] = 'failed'


def reserve(admission, now_ns):
    request = admission.request()
    require(type(now_ns) is int and request['created_ns'] <= now_ns < request['expires_ns'], 3)
    with _LOCK:
        require(len(_RECORDS) < 4096, 5)
        require(request['request_id'] not in _RECORDS and request['operation_id'] not in _OPERATIONS
                and (request['source_id'] is None or request['source_id'] not in _SOURCES), 12)
        _RECORDS[request['request_id']] = dict(phase='reserved', context=admission.context_sha256,
            created=request['created_ns'], expires=request['expires_ns'])
        _OPERATIONS.add(request['operation_id'])
        if request['source_id'] is not None: _SOURCES.add(request['source_id'])
    return SessionState(request['request_id'])
