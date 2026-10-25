"""One explicitly granted typed API operation per native call, without retries.

This adapter is private helper code. It connects only to the first frozen IP,
with the reviewed origin's TLS name, and exposes neither an HTTP proxy nor keys.
"""
import copy
from datetime import datetime, timezone
import hashlib
import html
from html.parser import HTMLParser
import ipaddress
import json
import os
from pathlib import PurePosixPath
import re
import secrets
import socket
import ssl
import threading
import time
from urllib.parse import quote, unquote, urlsplit
import uuid

import application_contracts as c
import application_credentials
import application_runtime_contracts
from application_evidence import EvidenceError, EvidenceStore, open_directory, read_file

SAFE_REASONS = {'request_invalid', 'operation_not_granted', 'identity_unverified', 'cursor_invalid',
                'pagination_limit', 'evidence_limit', 'evidence_unavailable', 'authority_changed',
                'accounting_unavailable', 'reporting_only', 'tool_budget_exhausted', 'runtime_mismatch', 'participant_mismatch'}


class APIError(ValueError):
    def __init__(self, reason='request_invalid'):
        self.reason = reason
        super().__init__(reason)


class WireError(ValueError):
    def __init__(self, status=None, reason='response_unavailable'):
        self.status, self.reason = status, reason


class _BrowserAction:
    """Private in-process authority; never an IPC input or serializable grant."""
    def __init__(self, owner, bearer, scope, native_id, raw_action, target, action_id, sequence, deadline):
        self.owner, self.bearer = owner, bearer
        self.scope, self.raw_action, self.target = copy.deepcopy(scope), copy.deepcopy(raw_action), copy.deepcopy(target)
        self.native_id, self.action_id, self.sequence, self.deadline = native_id, action_id, sequence, deadline
        self.requests, self.writes, self.operations, self.resources = 0, 0, set(), set()
        self.transmitted_writes = 0
        self.closed, self.effect_started, self.response = False, False, None
        self.receipt_ids, self.resource_ids = [], []

    def __repr__(self):
        return '<private browser action authority>'


def _now():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def _scalar(value):
    return ('true' if value else 'false') if type(value) is bool else str(value)


def _request_target(operation, arguments, upstream=None):
    path = operation['path_template']
    for key, value in arguments['path_params'].items():
        raw = str(value)
        if raw in ('.', '..') or any(char in raw for char in '/\\%?#') or any(ord(char) < 32 or ord(char) == 127 for char in raw):
            raise APIError()
        path = path.replace('{' + key + '}', quote(raw, safe=''))
    path = quote(path, safe="/%-._~!$&'()*+,;=:@")
    if len(path.encode()) > 4096:
        raise APIError()
    query = copy.deepcopy(arguments['query'])
    if upstream is not None:
        reserved = operation['pagination']['request_cursor']
        if reserved['location'] != 'query':
            raise APIError()
        query[reserved['name']] = upstream
    encoded = '&'.join(quote(key, safe='') + '=' + quote(_scalar(value), safe='') for key, value in sorted(query.items()))
    target = path + ('?' + encoded if encoded else '')
    if len(target.encode()) > 8192:
        raise APIError()
    return path, target


def _projection(value, paths):
    result = {}
    for pointer in paths:
        parts = [part.replace('~1', '/').replace('~0', '~') for part in pointer[1:].split('/')]
        source = value
        try:
            for part in parts:
                source = source[int(part)] if type(source) is list else source[part]
        except (KeyError, IndexError, TypeError, ValueError):
            continue
        current, original = result, value
        for index, part in enumerate(parts):
            key = int(part) if type(original) is list else part
            if type(current) is list:
                while len(current) <= key:
                    current.append(None)
            if index == len(parts) - 1:
                current[key] = copy.deepcopy(source)
                break
            original = original[key]
            if type(current) is dict:
                if key not in current:
                    current[key] = [] if type(original) is list else {}
            elif current[key] is None:
                current[key] = [] if type(original) is list else {}
            current = current[key]
    return result


def _request_preview(operation, target, origin, body, authenticated=True):
    return (operation['method'] + ' ' + target + ' HTTP/1.1\r\nHost: ' + urlsplit(origin['url']).netloc +
            ('\r\nX-Agent-API-Key: [REDACTED]' if authenticated else '') + '\r\nContent-Type: application/json\r\nContent-Length: ' +
            str(len(body)) + '\r\nConnection: close\r\n\r\n').encode() + body


def _redacted_response(raw, redactor):
    head, separator, body = raw.partition(b'\r\n\r\n')
    lines = head.split(b'\r\n')
    redactions = []
    safe = []
    for line in lines:
        name, colon, value = line.partition(b':')
        lower = name.lower()
        if colon and (lower in (b'authorization', b'proxy-authorization', b'cookie', b'set-cookie', b'x-agent-api-key')
                      or b'token' in lower or b'api-key' in lower):
            safe.append(name + b': [REDACTED]')
            if 'authentication_value' not in redactions:
                redactions.append('authentication_value')
        else:
            safe.append(line)
    sanitized = b'\r\n'.join(safe) + separator + body
    if redactor.contains(sanitized) and 'authentication_value' not in redactions:
        redactions.append('authentication_value')
    sanitized = redactor.bytes(sanitized)
    try:
        current = sanitized.decode('utf-8')
        def check_decoded(value):
            if redactor.contains(value.encode('utf-8')):
                raise APIError('evidence_unavailable')
            return value
        for _ in range(3):
            decoded = check_decoded(html.unescape(current))
            decoded = check_decoded(re.sub(r'\\u([a-fA-F0-9]{4})', lambda match: chr(int(match[1], 16)), decoded))
            decoded = check_decoded(re.sub(r'\\x([a-fA-F0-9]{2})', lambda match: chr(int(match[1], 16)), decoded))
            decoded = check_decoded(unquote(decoded, encoding='utf-8', errors='strict'))
            def css_character(match):
                point = int(match[1], 16)
                return chr(point) if 0 < point <= 0x10ffff and not 0xd800 <= point <= 0xdfff else '\ufffd'
            decoded = check_decoded(re.sub(r'\\([a-fA-F0-9]{1,6})(?:[ \t\r\n\f])?', css_character, decoded))
            decoded = check_decoded(re.sub(r'\\(?:\r\n|[\r\n\f])', '', decoded))
            decoded = check_decoded(re.sub(r'\\([^0-9a-fA-F\r\n\f])', r'\1', decoded))
            class TextProjection(HTMLParser):
                def __init__(self):
                    super().__init__(convert_charrefs=True); self.parts = []
                def handle_data(self, data):
                    self.parts.append(data)
            projection = TextProjection(); projection.feed(decoded); projection.close()
            if redactor.contains(''.join(projection.parts).encode('utf-8')):
                raise APIError('evidence_unavailable')
            if decoded == current:
                break
            current = decoded
    except UnicodeError:
        raise APIError('evidence_unavailable') from None
    return sanitized, redactions


def _exchange(origin, target, operation, body, key, before_send, mark_sent):
    parsed = urlsplit(origin['url'])
    if parsed.scheme != 'https' and not origin['diagnostic_fixture']:
        raise APIError()
    address = ipaddress.ip_address(origin['allowed_addresses'][0])
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    connection = socket.socket(family, socket.SOCK_STREAM)
    holder, timed_out = [connection], threading.Event()
    deadline = time.monotonic() + operation['max_request_seconds']
    def expire():
        timed_out.set()
        try:
            holder[0].shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        holder[0].close()
    timer = threading.Timer(operation['max_request_seconds'], expire)
    timer.daemon = True
    timer.start()
    status = None
    try:
        connection.settimeout(max(0.001, deadline - time.monotonic()))
        connection.connect((str(address), port))
        if parsed.scheme == 'https':
            connection = ssl.create_default_context().wrap_socket(connection, server_hostname=parsed.hostname,
                                                                 do_handshake_on_connect=False)
            holder[0] = connection
            connection.settimeout(max(0.001, deadline - time.monotonic()))
            connection.do_handshake()
        request = (operation['method'] + ' ' + target + ' HTTP/1.1\r\nHost: ' + parsed.netloc +
                   ('\r\nX-Agent-API-Key: ' + key if key is not None else '') + '\r\nContent-Type: application/json\r\nContent-Length: ' +
                   str(len(body)) + '\r\nConnection: close\r\n\r\n').encode('ascii') + body
        before_send()
        mark_sent()
        connection.sendall(request)
        maximum = operation['pagination']['max_response_bytes'] if operation['pagination'] else 1048576
        reader = connection.makefile('rb', buffering=0)
        try:
            line = reader.readline(8193)
            if len(line) > 8192 or not re.fullmatch(rb'HTTP/1\.[01] [1-5][0-9]{2} [^\r\n]*\r\n', line):
                raise WireError(reason='response_protocol_invalid')
            status = int(line[9:12])
            if status < 200:
                raise WireError(status, 'response_protocol_invalid')
            raw, headers = bytearray(line), {}
            for count in range(101):
                line = reader.readline(8193)
                if not line or len(line) > 8192 or not line.endswith(b'\r\n') or len(raw) + len(line) > min(65536, maximum):
                    raise WireError(status, 'response_protocol_invalid')
                raw.extend(line)
                if line == b'\r\n':
                    break
                if count == 100:
                    raise WireError(status, 'response_protocol_invalid')
                name, separator, value = line[:-2].partition(b':')
                if not separator or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
                    raise WireError(status, 'response_protocol_invalid')
                key_name = name.decode('ascii').lower()
                headers.setdefault(key_name, []).append(value.strip())
            # No implicit decompression or transfer decoding. Incomplete or
            # unsupported captures stay unavailable, rather than leaking chunks.
            if 'transfer-encoding' in headers or 'content-encoding' in headers:
                raise WireError(status, 'response_protocol_invalid')
            lengths = headers.get('content-length', [])
            if len(lengths) > 1 or (lengths and not re.fullmatch(rb'[0-9]{1,10}', lengths[0])):
                raise WireError(status, 'response_protocol_invalid')
            length = int(lengths[0]) if lengths else None
            if length is not None and length > maximum - len(raw):
                raise WireError(status, 'response_oversize')
            content = bytearray()
            while length is None or len(content) < length:
                left = min(65536, (length - len(content)) if length is not None else maximum - len(raw) + 1)
                if left <= 0:
                    raise WireError(status, 'response_oversize')
                chunk = reader.read(left)
                if not chunk:
                    if length is not None and len(content) != length:
                        raise WireError(status)
                    break
                content.extend(chunk)
                raw.extend(chunk)
                if len(raw) > maximum:
                    raise WireError(status, 'response_oversize')
            if timed_out.is_set():
                raise WireError(status)
            media = headers.get('content-type', [])
            if 200 <= status <= 299 and (len(media) != 1 or media[0].split(b';', 1)[0].strip().lower() != operation['response_media_type'].encode()):
                raise WireError(status, 'response_media_invalid')
            return status, bytes(content), bytes(raw)
        finally:
            reader.close()
    except (OSError, ValueError) as exc:
        if isinstance(exc, (APIError, EvidenceError, WireError)):
            raise
        raise WireError(status) from None
    finally:
        timer.cancel()
        holder[0].close()


class APIClient:
    def __init__(self, authority_service, evidence_root, artifact_root, *, clock=time.monotonic, budget_verifier=None):
        self.authority = authority_service
        self.plan = c.validate_ir(authority_service.plan)
        self.clock, self.budget_verifier = clock, budget_verifier
        self._lock = threading.RLock()
        self.evidence = EvidenceStore(evidence_root, self.plan['application']['limits'])
        self.artifacts = None
        try:
            self.artifacts = open_directory(artifact_root)
            evidence_path, artifacts_path = PurePosixPath(os.fspath(evidence_root)), PurePosixPath(os.fspath(artifact_root))
            if (evidence_path == artifacts_path or evidence_path in artifacts_path.parents or artifacts_path in evidence_path.parents
                    or (os.fstat(self.artifacts).st_dev, os.fstat(self.artifacts).st_ino) ==
                       (os.fstat(self.evidence.root).st_dev, os.fstat(self.evidence.root).st_ino)):
                raise EvidenceError()
            self._operations = {op['id']: op for op in self.plan['application']['operations']}
            self._stages = {stage['id']: stage for stage in self.plan['stages']}
            self._browser_actions = {}
            self.quarantined = bool(self.evidence.state['blocked'])
        except Exception:
            self.close()
            raise

    def close(self):
        if self.artifacts is not None:
            os.close(self.artifacts)
            self.artifacts = None
        self.evidence.close()

    def receipt_index(self, scope, *, allowed_segment_ids=None):
        selected = [scope['segment_id']] if allowed_segment_ids is None else allowed_segment_ids
        c.array(selected, '/allowed_segment_ids', 64, 1)
        for index, segment in enumerate(selected):
            try:
                if type(segment) is not str or str(uuid.UUID(segment)) != segment:
                    raise ValueError()
            except ValueError:
                raise APIError('request_invalid') from None
        if len(set(selected)) != len(selected):
            raise APIError('request_invalid')
        return self.evidence.index(scope['stage_id'], allowed_segment_ids=selected)

    def _binding(self, scope, stage):
        value = {key: scope[key] for key in ('run_id', 'trial_id', 'attempt_id', 'stage_id', 'segment_id', 'session_id', 'plan_sha256')}
        value.update(profile_sha256=stage['profile_binding']['sha256'],
                     release_contract_sha256=application_runtime_contracts.identity(self.plan['runtime']['pi_release'])['sha256'],
                     report_contract_sha256=c.digest(stage['completion']), pi_release=self.plan['runtime']['pi_release'])
        return value

    def _identity_key(self, scope, alias):
        return c.digest({'plan': scope['plan_sha256'], 'attempt': scope['attempt_id'], 'stage': scope['stage_id'],
                         'participant': scope['participant'], 'generation': scope['authority_generation'], 'alias': alias})

    def _usage(self, scope, operation):
        key = c.digest({'attempt': scope['attempt_id'], 'stage': scope['stage_id'], 'operation': operation['id']})
        return self.evidence.state['operation_usage'].setdefault(key,
            {'started': self.clock(), 'requests': 0, 'items': 0, 'bytes': 0})

    def _audit_rejection(self, scope, native_call_id, reason):
        ordinal = self.evidence.reserve(scope['stage_id'], 4096)
        audit_id = 'rejection-' + str(ordinal).zfill(6)
        body = c.canonical({'schema': 1, 'document_type': 'application_request_rejection',
            'audit_id': audit_id, 'binding': self._binding(scope, self._stages[scope['stage_name']]),
            'native_call_id': native_call_id, 'reason': reason, 'application_requests': 0})
        self.evidence.put('rejections/' + audit_id + '.json', body)
        self.evidence.state['stages'][scope['stage_id']]['bytes'] += len(body)
        self.evidence.save()
        return audit_id

    def _bounded(self, result, maximum=8192):
        result = self.authority.redactor.value(result)
        if len(c.canonical(result)) <= maximum:
            return result
        return {'ok': False, 'reason': 'evidence_unavailable', 'detail': 'projection_limit',
                'limit_bytes': maximum, 'receipt_id': result.get('receipt_id')}

    def execute(self, bearer, scope, native_call_id, input, budget_grant=None):
        with self._lock:
            return self._execute(bearer, scope, native_call_id, input, budget_grant)

    def begin_browser_action(self, bearer, scope, native_call_id, raw_action, budget_grant):
        with self._lock:
            self.authority.authorize(bearer, scope)
            c.native_id(native_call_id, '/native_call_id')
            c.safe_json(raw_action)
            if self.authority.redactor.contains(native_call_id.encode()) or self.authority.redactor.contains(c.canonical(raw_action)):
                raise APIError('request_invalid')
            action = raw_action.get('action') if type(raw_action) is dict else None
            c.choice(action, ('navigate', 'snapshot', 'screenshot', 'click', 'fill', 'select'), '/action')
            extra = {'value'} if action == 'fill' else {'option_id'} if action == 'select' else set()
            c.exact(raw_action, {'action', 'target_id'} | extra, '')
            stage = self._stages[scope['stage_name']]
            if self.plan['runtime']['container_profile'] != 'browser' or self.plan['runtime']['browser_sandbox_policy'] != 'chromium-userns':
                raise APIError('runtime_mismatch')
            if raw_action['target_id'] not in stage['browser_targets'] or self._browser_actions or self.quarantined:
                raise APIError('operation_not_granted')
            target = next(target for target in self.plan['application']['browser_targets'] if target['id'] == raw_action['target_id'])
            if action not in target['actions']:
                raise APIError('operation_not_granted')
            if (any(resource['media_type'] not in ('text/html', 'text/css', 'application/javascript') for resource in target['static_resources'])
                    or any(self._operations[op]['response_media_type'] not in ('application/json', 'text/html', 'text/css', 'application/javascript')
                           for op in target['allowed_operation_ids'])):
                raise APIError('evidence_unavailable')
            model_input = {key: raw_action[key] for key in extra}
            c.validate_value(model_input, target['input_schema'])
            if action == 'fill':
                c.text(raw_action['value'], '/value', 32768, empty=True)
            if action == 'select':
                choices = target['input_schema']['properties'].get('option_id', {}).get('enum', [])
                if raw_action['option_id'] not in choices:
                    raise APIError('request_invalid')
            identity = self.evidence.state['identities'].get(self._identity_key(scope, target['credential_alias']))
            if identity is None or identity == 'denied':
                raise APIError('identity_unverified')
            generation = self.evidence.state['generations'].get(scope['stage_id'])
            if generation != scope['authority_generation']:
                raise APIError('authority_changed')
            if budget_grant is None or self.budget_verifier is None or self.budget_verifier(budget_grant, scope, native_call_id, 'app_browser', raw_action) is not True:
                raise APIError('accounting_unavailable')
            call_key = c.digest({'attempt': scope['attempt_id'], 'stage': scope['stage_id'], 'segment': scope['segment_id'], 'call': native_call_id})
            if call_key in self.evidence.state['calls']:
                raise APIError('operation_not_granted')
            operations = [self._operations[op_id] for op_id in target['allowed_operation_ids']]
            if any(op['credential_alias'] != target['credential_alias'] for op in operations):
                raise APIError('credential_scope_invalid')
            bounds = [(op['pagination']['max_response_bytes'] if op['pagination'] else 1048576) + 393216 for op in operations]
            bounds += [resource['max_bytes'] + 131072 for resource in target['static_resources']]
            worst = sum(sorted(bounds, reverse=True)[:16]) + 524288 + 65536 + (2097152 if action == 'screenshot' else 0)
            ordinal = self.evidence.reserve(scope['stage_id'], worst)
            action_id = 'action-' + str(ordinal).zfill(6)
            self.evidence.state['calls'][call_key] = True
            self.evidence.state['browser_actions'][action_id] = {'stage_id': scope['stage_id'], 'remaining': worst}
            self.evidence.save()
            handle = _BrowserAction(self, bearer, scope, native_call_id, raw_action, target, action_id,
                                   self.evidence.state['stages'][scope['stage_id']]['receipts'], time.monotonic() + 15)
            self._browser_actions[action_id] = handle
            return handle

    def _browser_handle(self, handle):
        if (type(handle) is not _BrowserAction or handle.owner is not self or
                self._browser_actions.get(handle.action_id) is not handle or handle.closed or
                time.monotonic() >= handle.deadline or self.quarantined):
            raise APIError('operation_not_granted')
        self.authority.authorize(handle.bearer, handle.scope)
        return handle

    def execute_browser(self, handle, operation_id, typed_input):
        """Private bridge-only transport; the action proof was consumed once."""
        with self._lock:
            self._browser_handle(handle)
            if (operation_id not in handle.target['allowed_operation_ids'] or operation_id in handle.operations or
                    handle.requests >= 16 or typed_input.get('operation_id') != operation_id):
                raise APIError('operation_not_granted')
            operation = self._operations[operation_id]
            if operation['response_media_type'] not in ('application/json', 'text/html', 'text/css', 'application/javascript'):
                raise APIError('evidence_unavailable')
            if operation['effect'] in ('mutation', 'publication'):
                if not handle.effect_started or handle.writes:
                    raise APIError('operation_not_granted')
                handle.writes += 1
            handle.requests += 1
            handle.operations.add(operation_id)
            handle.response = None
            result = self._execute(handle.bearer, handle.scope, handle.native_id, typed_input, None, browser_handle=handle)
            if result.get('receipt_id'):
                handle.receipt_ids.append(result['receipt_id'])
            return result, handle.response

    def execute_browser_resource(self, handle, resource):
        """Exact unauthenticated static GET; never an operation receipt/proxy."""
        with self._lock:
            self._browser_handle(handle)
            if (resource not in handle.target['static_resources'] or handle.requests >= 16 or
                    resource['media_type'] not in ('text/html', 'text/css', 'application/javascript')):
                raise APIError('operation_not_granted')
            resource_key = c.digest(resource)
            if resource_key in handle.resources:
                raise APIError('operation_not_granted')
            handle.resources.add(resource_key)
            handle.requests += 1
            ordinal = self.evidence.reserve(handle.scope['stage_id'], resource['max_bytes'] + 131072,
                                            reservation=handle.action_id)
            resource_id = 'resource-' + str(ordinal).zfill(6)
            origin = self.plan['application']['origins'][resource['origin']]
            operation = {'method': 'GET', 'pagination': {'max_response_bytes': resource['max_bytes']},
                         'max_request_seconds': max(0.001, min(15, handle.deadline - time.monotonic())),
                         'response_media_type': resource['media_type']}
            request = _request_preview(operation, resource['path'], origin, b'', authenticated=False)
            status, outcome, reason = None, 'rejected', None
            response, redactions, visible = None, [], None
            record = {'schema': 1, 'document_type': 'application_browser_resource_receipt', 'resource_id': resource_id,
                'binding': self._binding(handle.scope, self._stages[handle.scope['stage_name']]),
                'participant': handle.scope['participant'], 'native_call_id': handle.native_id,
                'action_id': handle.action_id, 'resource': copy.deepcopy(resource), 'started_at': _now()}
            intent = c.canonical({'record': record, 'request_capture': request.decode()})
            self.evidence.put('intents/' + resource_id + '.json', intent)
            self.evidence.state['stages'][handle.scope['stage_id']]['bytes'] += len(intent)
            self.evidence.save()
            sent = False
            def mark():
                nonlocal sent
                sent = True
            try:
                status, body, raw = _exchange(origin, resource['path'], operation, b'', None,
                    lambda: self._browser_handle(handle), mark)
                response, redactions = _redacted_response(raw, self.authority.redactor)
                if 200 <= status <= 299:
                    visible = self.authority.redactor.bytes(body.decode('utf-8').encode('utf-8'))
                    outcome = 'succeeded'
                else:
                    outcome, reason = 'failed', 'http_failure'
            except WireError as exc:
                status, reason = exc.status, exc.reason
                outcome = 'failed' if sent else 'rejected'
                if sent:
                    response, redactions = b'[UNAVAILABLE: incomplete or unsupported response capture]\n', ['capture_unavailable']
            except Exception:
                outcome, reason = 'failed' if sent else 'rejected', 'request_invalid'
                if sent and response is None:
                    response, redactions = b'[UNAVAILABLE: response sanitization not proven]\n', ['capture_unavailable']
            record.update(ended_at=_now(), outcome=outcome, reason=reason, http_status=status, evidence=[])
            size = 0
            try:
                for kind, body, omitted in [('request', request, []), ('response', response, redactions)]:
                    if body is None:
                        continue
                    path = 'browser-resources/' + resource_id + '/' + kind + '.txt'
                    self.evidence.put(path, body)
                    size += len(body)
                    record['evidence'].append({'kind': kind, 'path': path, 'sha256': hashlib.sha256(body).hexdigest(),
                                               'bytes': len(body), 'redactions': omitted})
                data = c.canonical(record)
                self.evidence.put('browser-resources/' + resource_id + '/receipt.json', data)
                self.evidence.state['stages'][handle.scope['stage_id']]['bytes'] += size + len(data)
                self.evidence.save()
                handle.resource_ids.append(resource_id)
            except Exception:
                self.quarantined = True
                raise APIError('evidence_unavailable') from None
            return {'ok': outcome == 'succeeded', 'status': status, 'media_type': resource['media_type'],
                    'body': visible, 'resource_id': resource_id, 'reason': reason}

    def finish_browser_action(self, handle, audit, captures):
        """Seal bounded private action evidence and retire its live authority."""
        with self._lock:
            if type(handle) is not _BrowserAction or self._browser_actions.get(handle.action_id) is not handle or handle.closed:
                raise APIError('operation_not_granted')
            row = self.evidence.state['browser_actions'][handle.action_id]
            size = 0
            references = []
            try:
                for kind, body, media_type in captures:
                    limit = 2097152 if media_type == 'image/png' else 262144
                    if len(body) > limit:
                        raise EvidenceError('evidence_limit')
                    if self.authority.redactor.contains(body):
                        raise EvidenceError()
                    path = 'browser-actions/' + handle.action_id + '/' + kind + ('.png' if media_type == 'image/png' else '.txt')
                    self.evidence.put(path, body)
                    references.append({'kind': kind, 'path': path, 'media_type': media_type,
                        'sha256': hashlib.sha256(body).hexdigest(), 'bytes': len(body)})
                    size += len(body)
                audit = {**audit, 'schema': 1, 'document_type': 'application_browser_action_receipt',
                    'action_id': handle.action_id, 'native_call_id': handle.native_id,
                    'binding': self._binding(handle.scope, self._stages[handle.scope['stage_name']]),
                    'participant': handle.scope['participant'], 'target_id': handle.target['id'],
                    'page_identity': handle.target['page_identity'], 'action': handle.raw_action['action'],
                    'operation_receipt_ids': handle.receipt_ids, 'resource_receipt_ids': handle.resource_ids, 'captures': references}
                data = self.authority.redactor.bytes(c.canonical(audit))
                size += len(data)
                if size > row['remaining']:
                    raise EvidenceError('evidence_limit')
                self.evidence.put('browser-actions/' + handle.action_id + '/receipt.json', data)
                self.evidence.state['stages'][handle.scope['stage_id']]['bytes'] += size
                self.evidence.state['browser_actions'].pop(handle.action_id)
                self.evidence.save()
            except Exception:
                self.quarantined = True
                raise APIError('evidence_unavailable') from None
            finally:
                handle.closed = True
                self._browser_actions.pop(handle.action_id, None)
            return references

    def _execute(self, bearer, scope, native_call_id, arguments, budget_grant, browser_handle=None):
        receipt = operation = stage = None
        request_capture = b''
        raw_response = None
        response_redactions = []
        sent, status, value, page_result, chain = False, None, None, None, None
        outcome, reason = 'rejected', None
        admitted = False
        try:
            self.authority.authorize(bearer, scope)
            c.native_id(native_call_id, '/native_call_id')
            if self.authority.redactor.contains(native_call_id.encode('ascii')):
                raise APIError('request_invalid')
            c.safe_json(arguments)
            if self.authority.redactor.contains(c.canonical(arguments)):
                raise APIError('request_invalid')
            if self.quarantined or self.evidence.state['blocked'].get(scope['stage_id']):
                raise APIError('evidence_unavailable')
            if browser_handle is None:
                if self._browser_actions:
                    raise APIError('operation_not_granted')
                if budget_grant is None or self.budget_verifier is None:
                    raise APIError('accounting_unavailable')
                if self.budget_verifier(budget_grant, scope, native_call_id, 'app_api', arguments) is not True:
                    raise APIError('accounting_unavailable')
            else:
                self._browser_handle(browser_handle)
            admitted = True
            call_key = c.digest({'attempt': scope['attempt_id'], 'stage': scope['stage_id'],
                                 'segment': scope['segment_id'], 'call': native_call_id})
            if browser_handle is None and call_key in self.evidence.state['calls']:
                raise APIError('operation_not_granted')
            self.evidence.state['calls'][call_key] = True
            self.evidence.save()
            c.exact(arguments, {'operation_id', 'path_params', 'query', 'body', 'cursor'}, '')
            c.slug(arguments['operation_id'], '/operation_id')
            self.authority.authorize(bearer, scope, arguments['operation_id'])
            operation = self._operations[arguments['operation_id']]
            stage = self._stages[scope['stage_name']]
            if browser_handle is None and operation['transport'] != 'api':
                raise APIError('operation_not_granted')
            generation = self.evidence.state['generations'].get(scope['stage_id'])
            if generation is not None and generation != scope['authority_generation']:
                raise APIError('authority_changed')
            self.evidence.state['generations'][scope['stage_id']] = scope['authority_generation']
            # Reserve before validating effects, so denied known operations also
            # receive a bounded durable receipt whenever evidence is available.
            maximum = operation['pagination']['max_response_bytes'] if operation['pagination'] else 1048576
            ordinal = self.evidence.reserve(scope['stage_id'], maximum + 393216,
                reservation=browser_handle.action_id if browser_handle is not None else None)
            receipt = {'schema': 1, 'document_type': 'application_operation_receipt',
                       'receipt_id': 'receipt-' + str(ordinal).zfill(6), 'operation_instance_id': None,
                       'native_call_id': native_call_id, 'transport': 'browser' if browser_handle is not None else 'api',
                       'action_id': browser_handle.action_id if browser_handle is not None else None,
                       'sequence': self.evidence.state['stages'][scope['stage_id']]['receipts'],
                       'binding': self._binding(scope, stage), 'participant': copy.deepcopy(scope['participant']),
                       'operation_id': operation['id'], 'effect': operation['effect'],
                       'request': {'method': operation['method'], 'origin_id': operation['origin'],
                                   'path': operation['path_template'], 'credential_alias': operation['credential_alias']},
                       'evidence': [], 'started_at': _now(), 'ended_at': None, 'outcome': None,
                       'reason': None, 'http_status': None, 'pagination': None, 'publication': None}
            for field, schema in [('path_params', 'path_params_schema'), ('query', 'query_schema'), ('body', 'body_schema')]:
                c.validate_value(arguments[field], operation[schema], '/' + field)
            alias = operation['credential_alias']
            identity_key = self._identity_key(scope, alias)
            identity = self.evidence.state['identities'].get(identity_key)
            if identity == 'denied' or (operation['effect'] != 'identity' and identity is None):
                raise APIError('identity_unverified')
            write_key = c.digest({'attempt': scope['attempt_id'], 'stage': scope['stage_id'], 'operation': operation['id']})
            if operation['effect'] in ('mutation', 'publication') and write_key in self.evidence.state['writes']:
                raise APIError('operation_not_granted')
            upstream, chain = self._cursor(scope, operation, arguments)
            path, target = _request_target(operation, arguments, upstream)
            receipt['request']['path'] = path
            wire_body = copy.deepcopy(arguments['body'])
            publication_keys = []
            artifact = None
            if operation['effect'] == 'publication':
                publication = operation['publication']
                declared = next(a for a in stage['completion']['artifacts'] if a['id'] == publication['artifact_id'])
                try:
                    artifact = read_file(self.artifacts, declared['path'], declared['max_bytes'])
                    content = artifact.decode('utf-8')
                except (OSError, EvidenceError, UnicodeError):
                    raise APIError('request_invalid') from None
                if declared['media_type'] == 'application/json':
                    c.loads(artifact, max_bytes=declared['max_bytes'])
                if self.authority.redactor.contains(artifact):
                    raise APIError('request_invalid')
                if (wire_body.get('artifact_id') != publication['artifact_id'] or
                        wire_body.get('target_id') != publication['target_id'] or
                        wire_body.get('artifact_sha256') != hashlib.sha256(artifact).hexdigest()):
                    raise APIError('request_invalid')
                publication_keys = [c.digest({'attempt': scope['attempt_id'], 'stage': scope['stage_id'], 'publication': publication['id']}),
                    c.digest({'attempt': scope['attempt_id'], 'stage': scope['stage_id'], 'target': publication['target_id'],
                              'artifact': publication['artifact_id'], 'sha256': wire_body['artifact_sha256']})]
                if any(key in self.evidence.state['writes'] for key in publication_keys):
                    raise APIError('operation_not_granted')
                wire_body['content'] = content
            c.validate_value(wire_body, operation['wire_body_schema'], '/wire_body')
            body = b'' if wire_body is None else c.canonical(wire_body)
            if len(body) > 65536:
                raise APIError('request_invalid')
            origin = self.plan['application']['origins'][operation['origin']]
            key = self.authority.private_authority(bearer, scope, operation['id'])
            preview = _request_preview(operation, target, origin, body)
            request_capture = self.authority.redactor.bytes(preview)
            transport_operation = copy.deepcopy(operation)
            if browser_handle is not None:
                transport_operation['max_request_seconds'] = min(operation['max_request_seconds'], max(0.001, browser_handle.deadline - time.monotonic()))
            allowance = None
            if operation['pagination']:
                usage = self._usage(scope, operation)
                allowance = min(operation['pagination']['max_response_bytes'], operation['pagination']['max_total_bytes'] - usage['bytes'] - len(preview))
                if allowance < 1:
                    raise APIError('pagination_limit')
                usage['requests'] += 1
                usage['bytes'] += allowance + len(preview)
                transport_operation['pagination']['max_response_bytes'] = allowance
            if artifact is not None:
                self.evidence.put('snapshots/' + receipt['receipt_id'] + '.txt', artifact)
                self.evidence.state['stages'][scope['stage_id']]['bytes'] += len(artifact)
            intent = {'schema': 1, 'receipt': receipt, 'request_capture': request_capture.decode('utf-8')}
            intent_body = c.canonical(intent)
            self.evidence.put('intents/' + receipt['receipt_id'] + '.json', intent_body)
            self.evidence.state['stages'][scope['stage_id']]['bytes'] += len(intent_body)
            self.evidence.state['pending'][receipt['receipt_id']] = {'stage_id': scope['stage_id'], 'operation_id': operation['id']}
            self.evidence.save()
            def consume():
                self.authority.authorize(bearer, scope, operation['id'])
                receipt['operation_instance_id'] = 'operation-' + str(uuid.uuid4())
                if operation['effect'] in ('mutation', 'publication'):
                    write = {'stage_id': scope['stage_id'], 'operation_instance_id': receipt['operation_instance_id'],
                             'receipt_id': receipt['receipt_id']}
                    self.evidence.state['writes'][write_key] = write
                    for publication_key in publication_keys:
                        self.evidence.state['writes'][publication_key] = write
                self.evidence.save()
            def mark():
                nonlocal sent
                sent = True
                if browser_handle is not None and operation['effect'] in ('mutation', 'publication'):
                    browser_handle.transmitted_writes += 1
            status, response_body, raw = _exchange(origin, target, transport_operation, body, key, consume, mark)
            if allowance is not None:
                self._usage(scope, operation)['bytes'] -= allowance - len(raw)
            raw_response, response_redactions = _redacted_response(raw, self.authority.redactor)
            if not 200 <= status <= 299:
                outcome, reason = 'failed', 'http_failure'
            else:
                if operation['response_schema'] is None and browser_handle is not None:
                    value = response_body.decode('utf-8')
                else:
                    value = c.loads(response_body, max_bytes=1048576)
                    c.validate_value(value, operation['response_schema'], '/response')
                if operation['effect'] == 'identity':
                    if value != scope['participant']:
                        raise APIError('participant_mismatch')
                    self.evidence.state['identities'][identity_key] = receipt['receipt_id']
                    self.evidence.save()
                if operation['effect'] == 'publication':
                    pub = operation['publication']
                    expected = {'actor_id': scope['participant']['actor_id'], 'target_id': pub['target_id'],
                                'artifact_sha256': wire_body['artifact_sha256'], 'state': 'published'}
                    if any(value.get(k) != v for k, v in expected.items()) or type(value.get('publication_id')) is not str or not value['publication_id'].strip():
                        raise APIError('request_invalid')
                    receipt['publication'] = {key: pub[key] for key in ('id', 'artifact_id', 'target_id')}
                    receipt['publication'].update(publication_id=value['publication_id'], artifact_sha256=wire_body['artifact_sha256'], state='published')
                if operation['pagination']:
                    page_result = self._page(scope, operation, arguments, value, chain, receipt, len(raw) + len(preview))
                if browser_handle is not None:
                    visible = self.authority.redactor.value(value)
                    if operation['pagination']:
                        visible = application_credentials.Redactor(self.evidence.state['chains'][chain]['tokens']).value(visible)
                        visible[operation['pagination']['cursor_field']] = page_result['cursor']
                    browser_handle.response = {'status': status, 'media_type': operation['response_media_type'],
                        'body': visible.encode('utf-8') if type(visible) is str else c.canonical(visible)}
                outcome = 'succeeded'
        except WireError as exc:
            status = exc.status
            reason = exc.reason
            outcome = 'outcome_unknown' if sent and operation['effect'] in ('mutation', 'publication') else 'failed' if sent else 'rejected'
            raw_response = b'[UNAVAILABLE: incomplete or unsupported response capture]\n' if sent else None
            response_redactions = ['capture_unavailable'] if sent else []
        except Exception as exc:
            reason = getattr(exc, 'reason', None)
            reason = reason if reason in SAFE_REASONS else 'request_invalid'
            outcome = 'outcome_unknown' if sent and operation['effect'] in ('mutation', 'publication') else 'failed' if sent else 'rejected'
            if sent and raw_response is None:
                raw_response = b'[UNAVAILABLE: response sanitization not proven]\n'
                response_redactions = ['capture_unavailable']
            if isinstance(exc, EvidenceError) or isinstance(exc, OSError):
                self.quarantined = True
                reason = 'evidence_unavailable'
        if receipt is None:
            result = {'ok': False, 'reason': reason or 'request_invalid'}
            if admitted:
                try:
                    result['audit_id'] = self._audit_rejection(scope, native_call_id, result['reason'])
                except Exception:
                    self.quarantined = True
                    result['reason'] = 'evidence_unavailable'
            return self._bounded(result)
        try:
            if operation['effect'] == 'identity' and outcome != 'succeeded' and sent:
                self.evidence.state['identities'][self._identity_key(scope, operation['credential_alias'])] = 'denied'
            if outcome == 'outcome_unknown':
                self.quarantined = True
                self.evidence.state['blocked'][scope['stage_id']] = 'outcome_unknown'
            if not sent:
                receipt['operation_instance_id'] = None
            receipt.update(ended_at=_now(), outcome=outcome, reason=None if outcome == 'succeeded' else reason or 'request_invalid', http_status=status)
            if outcome != 'succeeded':
                receipt['pagination'] = receipt['publication'] = None
            self.evidence.seal(scope['stage_id'], receipt, request_capture, raw_response, response_redactions)
        except Exception:
            self.quarantined = True
            if sent and operation['effect'] in ('mutation', 'publication'):
                outcome = 'outcome_unknown'
                self.evidence.state['blocked'][scope['stage_id']] = 'evidence_unavailable'
                try:
                    self.evidence.save()
                except Exception:
                    pass
            return self._bounded({'ok': False, 'reason': 'evidence_unavailable', 'outcome': outcome})
        if outcome != 'succeeded':
            return self._bounded({'ok': False, 'reason': receipt['reason'], 'outcome': outcome, 'receipt_id': receipt['receipt_id']})
        projected = _projection(value, operation['result_fields'])
        if operation['pagination']:
            projected.pop(operation['pagination']['cursor_field'], None)
            tokens = self.evidence.state['chains'][chain]['tokens']
            projected = application_credentials.Redactor(tokens).value(projected)
        projected.update(ok=True, receipt_id=receipt['receipt_id'])
        if page_result is not None:
            projected['pagination'] = page_result
        return self._bounded(projected, operation['max_result_bytes'])

    def _cursor(self, scope, operation, arguments):
        pagination = operation['pagination']
        cursor = arguments['cursor']
        if pagination is None:
            if cursor is not None:
                raise APIError('cursor_invalid')
            return None, None
        cursor_scope = {key: value for key, value in scope.items() if key != 'segment_id'}
        query_binding = c.digest({'scope': cursor_scope, 'operation_id': operation['id'], 'path_params': arguments['path_params'],
                                  'query': arguments['query'], 'body': arguments['body']})
        usage = self._usage(scope, operation)
        if cursor is None:
            if (usage['requests'] >= pagination['max_pages'] or usage['items'] >= pagination['max_items'] or
                    usage['bytes'] >= pagination['max_total_bytes'] or self.clock() - usage['started'] >= pagination['timeout_seconds']):
                raise APIError('pagination_limit')
            chain_id = 'chain-' + uuid.uuid4().hex
            self.evidence.state['chains'][chain_id] = {'binding': query_binding, 'started': self.clock(),
                'pages': 0, 'items': 0, 'bytes': 0, 'snapshot': None, 'last_receipt': None, 'tokens': [], 'terminated': False}
            return None, chain_id
        if type(cursor) is not str or not re.fullmatch('[a-f0-9]{64}', cursor):
            raise APIError('cursor_invalid')
        record = self.evidence.state['cursors'].get(cursor)
        if record is None or record['used'] or record['binding'] != query_binding:
            raise APIError('cursor_invalid')
        chain = self.evidence.state['chains'][record['chain']]
        if chain['terminated'] or self.clock() - chain['started'] >= pagination['timeout_seconds']:
            raise APIError('cursor_invalid')
        if (usage['requests'] >= pagination['max_pages'] or usage['items'] >= pagination['max_items'] or
                usage['bytes'] >= pagination['max_total_bytes'] or self.clock() - usage['started'] >= pagination['timeout_seconds']):
            raise APIError('pagination_limit')
        record['used'] = True
        self.evidence.save()
        return record['upstream'], record['chain']

    def _page(self, scope, operation, arguments, value, chain_id, receipt, raw_bytes):
        pagination = operation['pagination']
        chain = self.evidence.state['chains'][chain_id]
        items = len(value[pagination['items_field']])
        usage = self._usage(scope, operation)
        usage['items'] += items
        upstream, snapshot = value[pagination['cursor_field']], value[pagination['snapshot_field']]
        if (chain['snapshot'] is not None and snapshot != chain['snapshot']) or usage['items'] > pagination['max_items']:
            chain['terminated'] = True
            self.evidence.save()
            raise APIError('pagination_limit')
        if upstream is not None:
            c.text(upstream, '/cursor', 4096)
            if self.authority.redactor.contains(upstream.encode()) or '://' in upstream or upstream.startswith('//'):
                raise APIError('cursor_invalid')
        chain['pages'] += 1
        chain['items'] += items
        chain['bytes'] += raw_bytes
        chain['snapshot'] = snapshot
        state, reason = ('exhausted', None) if upstream is None else ('more', None)
        if upstream is not None:
            _, next_target = _request_target(operation, arguments, upstream)
            next_request_bytes = len(_request_preview(operation, next_target,
                self.plan['application']['origins'][operation['origin']], b''))
            for reached, code in ((upstream in chain['tokens'], 'cursor_cycle'),
                                  (usage['requests'] >= pagination['max_pages'], 'page_limit'),
                                  (usage['items'] >= pagination['max_items'], 'item_limit'),
                                  (usage['bytes'] + next_request_bytes + 1 > pagination['max_total_bytes'], 'byte_limit'),
                                  (self.clock() - usage['started'] >= pagination['timeout_seconds'], 'time_limit')):
                if reached:
                    state, reason = 'truncated', code
                    break
        cursor = None
        if upstream is not None:
            chain['tokens'].append(upstream)
        if state == 'more':
            cursor = secrets.token_hex(32)
            self.evidence.state['cursors'][cursor] = {'chain': chain_id, 'binding': chain['binding'], 'upstream': upstream, 'used': False}
        else:
            chain['terminated'] = True
        receipt['pagination'] = {'chain_id': chain_id, 'snapshot_id': snapshot, 'page': chain['pages'],
            'items': items, 'total_items': chain['items'], 'state': state, 'reason': reason,
            'predecessor_receipt_id': chain['last_receipt']}
        chain['last_receipt'] = receipt['receipt_id']
        self.evidence.save()
        return {'state': state, 'cursor': cursor, 'page': chain['pages'], 'total_items': chain['items'], 'reason': reason}
