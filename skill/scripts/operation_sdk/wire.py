"""Bounded private documents/frames. No logging, environment or file lookup."""
import json
import math
import os
import selectors
import time

MAX_BYTES = 33554432
MAX_DEPTH = 64
MAX_NODES = 65536


class SDKError(ValueError):
    """Numeric nonsecret status; exception formatting never contains input."""
    def __init__(self, code=1):
        self.code = code if type(code) is int and 0 <= code <= 255 else 1
        super().__init__()
    def __str__(self): return '<sdk>'
    def __repr__(self): return '<sdk>'


def require(condition, code=1):
    if not condition: raise SDKError(code)


def _limit(maximum):
    require(type(maximum) is int and 0 <= maximum <= MAX_BYTES, 5)


def _walk(value, depth=0, count=None):
    if count is None: count = [0, 0]
    count[0] += 1
    require(depth <= MAX_DEPTH and count[0] <= MAX_NODES, 5)
    if type(value) is dict:
        require(len(value) <= MAX_NODES and all(type(key) is str for key in value))
        for key, child in value.items(): _walk(key, depth + 1, count); _walk(child, depth + 1, count)
    elif type(value) is list:
        require(len(value) <= MAX_NODES, 5)
        for child in value: _walk(child, depth + 1, count)
    elif type(value) is str:
        require(len(value) <= MAX_BYTES, 5)
        try: count[1] += len(value.encode('utf-8'))
        except UnicodeError: raise SDKError(7) from None
    elif type(value) is int: require(-2**63 <= value <= 2**64, 5)
    elif type(value) is float: require(math.isfinite(value), 7)
    else: require(value is None or type(value) is bool, 7)
    require(count[1] <= MAX_BYTES, 5)


def encode(value, maximum):
    _limit(maximum); _walk(value)
    encoder = json.JSONEncoder(sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
    chunks = []; length = 0
    try:
        for text in encoder.iterencode(value):
            chunk = text.encode('ascii'); length += len(chunk)
            require(length <= maximum, 5); chunks.append(chunk)
        return b''.join(chunks)
    except SDKError: raise
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise SDKError(7) from None


def _pairs(pairs):
    value = {}
    for key, child in pairs:
        require(key not in value, 7); value[key] = child
    return value


def _integer(raw):
    require(len(raw.lstrip('-')) <= 20, 5)
    result = int(raw); require(-2**63 <= result <= 2**64, 5)
    return result


def _constant(_): raise SDKError(7)


def decode(body, maximum):
    _limit(maximum); require(type(body) is bytes and len(body) <= maximum, 5)
    try:
        text = body.decode('utf-8'); depth = 0; quoted = escaped = False
        for char in text:
            if quoted:
                if escaped: escaped = False
                elif char == '\\': escaped = True
                elif char == '"': quoted = False
            elif char == '"': quoted = True
            elif char in '[{':
                depth += 1; require(depth <= MAX_DEPTH, 5)
            elif char in ']}':
                depth -= 1; require(depth >= 0, 7)
        value = json.loads(text, object_pairs_hook=_pairs, parse_int=_integer, parse_constant=_constant)
        _walk(value)
        return value
    except SDKError: raise
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError): raise SDKError(7) from None


class Frame:
    def __init__(self, maximum):
        _limit(maximum); self.maximum = maximum
        self._header = bytearray(); self._body = bytearray(); self.expected = None
        self._failed = False; self._finished = False
    @property
    def buffered_bytes(self): return len(self._body)
    @property
    def complete(self): return self.expected is not None and len(self._body) == self.expected
    def feed(self, body):
        require(not self._failed and not self._finished, 9)
        try: self._feed(body)
        except BaseException:
            self._failed = True
            raise
    def _feed(self, body):
        require(type(body) is bytes)
        if self.complete:
            require(not body, 7); return
        if len(self._header) < 4:
            count = min(4 - len(self._header), len(body)); self._header.extend(body[:count]); body = body[count:]
            if len(self._header) == 4:
                self.expected = int.from_bytes(self._header, 'big'); require(self.expected <= self.maximum, 5)
        if self.expected is not None:
            require(len(self._body) + len(body) <= self.expected, 7); self._body.extend(body)
    def finish(self):
        require(not self._failed and not self._finished, 9)
        if not self.complete:
            self._failed = True
            raise SDKError(9)
        self._finished = True
        return bytes(self._body)


def read_frame(fd, maximum, deadline, *, eof=False):
    frame = Frame(maximum)
    os.set_blocking(fd, False)
    selector = selectors.DefaultSelector()
    try:
        selector.register(fd, selectors.EVENT_READ)
        while True:
            require(time.monotonic() < deadline, 9)
            require(selector.select(max(0, deadline - time.monotonic())), 9)
            try: chunk = os.read(fd, 65536)
            except BlockingIOError: continue
            except OSError: raise SDKError(6) from None
            if not chunk: return frame.finish()
            frame.feed(chunk)
            if frame.complete and not eof: return frame.finish()
    finally: selector.close()


def write_frame(fd, body, deadline, *, progress=None):
    require(type(body) is bytes and len(body) <= MAX_BYTES, 5)
    body = len(body).to_bytes(4, 'big') + body; offset = 0
    if progress is not None: progress.update(confirmed_bytes=0, positive_calls=0, unknown=False)
    os.set_blocking(fd, False); selector = selectors.DefaultSelector()
    try:
        selector.register(fd, selectors.EVENT_WRITE)
        while offset < len(body):
            require(time.monotonic() < deadline, 9)
            require(selector.select(max(0, deadline - time.monotonic())), 9)
            try: count = os.write(fd, body[offset:offset + 4096])
            except BlockingIOError: continue
            except OSError:
                if progress is not None: progress['unknown'] = True
                raise SDKError(6) from None
            require(type(count) is int and 0 < count <= len(body) - offset, 6); offset += count
            if progress is not None:
                progress['confirmed_bytes'] = offset; progress['positive_calls'] += 1
        return offset
    finally: selector.close()


def public_status(code, accepted):
    require(type(code) is int and 0 <= code <= 255 and type(accepted) is bool)
    # Every byte is C0. Strict normalized UTF-8 secrets contain no C0 byte,
    # including one-character generic values. Text/base64 wrappers need their
    # own full-envelope check and are deliberately not emitted here.
    body = bytes((1, 3, 4, 11, 1, code >> 4, code & 15, int(accepted)))
    return len(body).to_bytes(4, 'big') + body


def decode_status(packet):
    require(type(packet) is bytes and len(packet) == 12 and packet[:4] == b'\0\0\0\x08'
            and packet[4:9] == bytes((1, 3, 4, 11, 1))
            and packet[9] <= 15 and packet[10] <= 15 and packet[11] in (0, 1), 7)
    return packet[9] * 16 + packet[10], bool(packet[11])


class PrivateData:
    def __init__(self, value): self._body = encode(value, MAX_BYTES)
    def get(self): return decode(self._body, MAX_BYTES)
    def __str__(self): return '<sdk>'
    def __repr__(self): return '<sdk>'


def read_memory_frame(fd, maximum, deadline):
    """Only a caller-verified sealed memfd; ordinary files are unsupported."""
    frame=Frame(maximum)
    while True:
        require(time.monotonic()<deadline,9)
        try:chunk=os.read(fd,65536)
        except OSError:raise SDKError(6)from None
        if not chunk:return frame.finish()
        frame.feed(chunk)
