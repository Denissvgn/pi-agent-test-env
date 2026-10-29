"""Typed one-action browser controller; credentials stay in trusted transport.

The native bridge uses a CDP pipe and a deny-only browser proxy. Every permitted
HTTP request is independently executed by the helper and fulfilled with sanitized
text. Controlled bridge tests do not qualify real Chromium interception.
"""
import base64
import copy
import hashlib
import os
from pathlib import Path
import re
import select
import signal
import struct
import subprocess
import sys
import time
from urllib.parse import parse_qsl, unquote, urlsplit

import application_contracts as c
from application_api import APIError, _request_target
from application_evidence import read_file

CSP = "default-src 'none'; script-src 'unsafe-inline' *; style-src 'unsafe-inline' *; connect-src *; frame-src *; img-src 'none'; media-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'"
TEXT_MEDIA = {'application/json', 'text/html', 'text/css', 'application/javascript'}


class BrowserError(ValueError):
    def __init__(self, reason='request_invalid'):
        self.reason = reason
        super().__init__(reason)


def unsupported_browser_assets(plan, stage_name):
    """Pure source/IR admission predicate for the current text-only capability."""
    stage = next(stage for stage in plan['stages'] if stage['id'] == stage_name)
    operations = {operation['id']: operation for operation in plan['application']['operations']}
    unsupported = []
    for target in plan['application']['browser_targets']:
        if target['id'] not in stage['browser_targets']:
            continue
        for operation_id in target['allowed_operation_ids']:
            if operations[operation_id]['response_media_type'] not in TEXT_MEDIA:
                unsupported.append({'target_id': target['id'], 'kind': 'operation', 'id': operation_id})
        for index, resource in enumerate(target['static_resources']):
            if resource['media_type'] not in TEXT_MEDIA - {'application/json'}:
                unsupported.append({'target_id': target['id'], 'kind': 'static_resource', 'index': index})
    return unsupported


class CDPPipeBridge:
    classification = 'native_chromium_cdp'

    def __init__(self):
        if sys.platform != 'linux' or os.uname().machine not in ('aarch64', 'arm64') or os.getuid() == 0:
            raise BrowserError('runtime_mismatch')
        if os.environ.get('CHROME_NO_SANDBOX') == '1' or os.environ.get('CHROME_SOFTWARE_WEBGL') == '1':
            raise BrowserError('runtime_mismatch')
        env = {name: os.environ[name] for name in ('PATH', 'HOME', 'TMPDIR', 'CHROME_BIN', 'PUPPETEER_EXECUTABLE_PATH') if name in os.environ}
        self.process = subprocess.Popen(['node', str(Path(__file__).with_name('application-browser-cdp.mjs'))],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
            start_new_session=True, bufsize=0)
        self.buffer, self.stderr_bytes = bytearray(), 0
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            os.set_blocking(stream.fileno(), False)
        try:
            deadline = time.monotonic() + 15
            self.send({'kind': 'configure', 'schema': 1, 'platform': 'linux/arm64', 'browser_sandbox_policy': 'chromium-userns'}, deadline)
            self.ready = self.receive(deadline)
            if self.ready.get('kind') != 'ready' or self.ready.get('platform') != 'linux/arm64' or self.ready.get('protocol_version') != '1.3':
                raise BrowserError('runtime_mismatch')
        except Exception:
            self.close()
            raise BrowserError('runtime_mismatch') from None

    def send(self, value, deadline):
        body = memoryview(c.canonical(value) + b'\n')
        if len(body) > 2097152:
            raise BrowserError('evidence_limit')
        while body:
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([], [self.process.stdin], [], left)[1]:
                raise BrowserError('evidence_unavailable')
            try:
                count = os.write(self.process.stdin.fileno(), body)
            except BlockingIOError:
                continue
            if count <= 0:
                raise BrowserError('evidence_unavailable')
            body = body[count:]

    def receive(self, deadline):
        while True:
            boundary = self.buffer.find(b'\n')
            if boundary >= 0:
                raw = bytes(self.buffer[:boundary]); del self.buffer[:boundary + 1]
                value = c.loads(raw, max_bytes=8388608)
                if type(value) is not dict or value.get('kind') == 'fatal':
                    raise BrowserError('evidence_unavailable')
                return value
            left = deadline - time.monotonic()
            if left <= 0:
                raise BrowserError('evidence_unavailable')
            readable = select.select([self.process.stdout, self.process.stderr], [], [], left)[0]
            if not readable:
                raise BrowserError('evidence_unavailable')
            for stream in readable:
                chunk = os.read(stream.fileno(), 65536)
                if not chunk:
                    raise BrowserError('evidence_unavailable')
                if stream is self.process.stderr:
                    self.stderr_bytes += len(chunk)
                    if self.stderr_bytes > 65536:
                        raise BrowserError('evidence_limit')
                else:
                    self.buffer.extend(chunk)
                    if len(self.buffer) > 8388608:
                        raise BrowserError('evidence_limit')

    def close(self):
        process = getattr(self, 'process', None)
        if process is None:
            return
        if process.poll() is None:
            try:
                self.send({'kind': 'close'}, time.monotonic() + 1)
                process.wait(timeout=2)
            except Exception:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=2)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


def _admission(plan, receipt):
    try:
        if (receipt['schema'] != 1 or receipt['document_type'] != 'browser_admission' or receipt['status'] != 'PASS'
                or receipt['image']['id'] != plan['runtime']['image_id'] or receipt['image']['platform'] != 'linux/arm64'
                or receipt['host']['native_platform'] != 'linux/arm64' or receipt['host']['selected_platform'] != 'linux/arm64'
                or receipt['browser_security']['policy'] != 'chromium-userns' or receipt['process']['exit_code'] != 0
                or receipt['process']['cleanup_confirmed'] is not True
                or not any(row.get('browser_sandbox', {}).get('namespace_and_seccomp_verified') is True for row in receipt['observations'])
                or any(row.get('no_browser_sandbox') is True or row.get('software_webgl') is True for row in receipt['observations'])):
            raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise BrowserError('runtime_mismatch') from None


def _decode_scalar(value, schema):
    if schema['type'] == 'integer':
        if not re.fullmatch(r'-?(0|[1-9][0-9]*)', value) or str(int(value)) != value:
            raise BrowserError()
        return int(value)
    if schema['type'] == 'boolean':
        if value not in ('true', 'false'):
            raise BrowserError()
        return value == 'true'
    return value


class BrowserClient:
    def __init__(self, api_client, admission, *, bridge_factory=None):
        self.api = api_client
        if api_client.plan['runtime']['container_profile'] != 'browser' or api_client.plan['runtime']['browser_sandbox_policy'] != 'chromium-userns':
            raise BrowserError('runtime_mismatch')
        _admission(api_client.plan, admission)
        if any(unsupported_browser_assets(api_client.plan, stage['id']) for stage in api_client.plan['stages']):
            raise BrowserError('evidence_unavailable')
        self.bridge = (bridge_factory or CDPPipeBridge)()
        self.classification = self.bridge.classification
        if bridge_factory is None:
            expected = re.search(r'\d+\.\d+\.\d+\.\d+', admission['image']['capabilities']['chromium'])
            observed = re.search(r'\d+\.\d+\.\d+\.\d+', self.bridge.ready.get('browser', ''))
            if expected is None or observed is None or expected.group() != observed.group():
                self.bridge.close()
                raise BrowserError('runtime_mismatch')

    def close(self):
        self.bridge.close()

    def _template(self, handle, template):
        if type(template) is dict:
            return {key: self._template(handle, value) for key, value in template.items()}
        if type(template) is list:
            return [self._template(handle, value) for value in template]
        if type(template) is str and template.startswith('${'):
            if template in ('${input.value}', '${input.option_id}'):
                key = template[8:-1]
                if key not in handle.raw_action:
                    raise BrowserError()
                return handle.raw_action[key]
            match = re.fullmatch(r'\$\{artifact\.([a-z0-9-]+)\.sha256\}', template)
            if match is None:
                raise BrowserError()
            stage = self.api._stages[handle.scope['stage_name']]
            artifact = next((a for a in stage['completion']['artifacts'] if a['id'] == match[1]), None)
            if artifact is None:
                raise BrowserError('operation_not_granted')
            body = read_file(self.api.artifacts, artifact['path'], artifact['max_bytes'])
            if self.api.authority.redactor.contains(body):
                raise BrowserError()
            return hashlib.sha256(body).hexdigest()
        return template

    def _operation_input(self, handle, operation, message):
        parsed = urlsplit(message['url'])
        origin = self.api.plan['application']['origins'][operation['origin']]['url']
        if parsed.scheme + '://' + parsed.netloc != origin or parsed.fragment or parsed.username is not None:
            return None
        if message['method'] != operation['method']:
            return None
        pattern = re.escape(operation['path_template'])
        pattern = re.sub(r'\\\{([a-z][a-z0-9_]*)\\\}', lambda match: '(?P<' + match[1] + '>[^/]+)', pattern)
        matched = re.fullmatch(pattern, parsed.path)
        if matched is None:
            return None
        params = {key: _decode_scalar(unquote(value, encoding='utf-8', errors='strict'), operation['path_params_schema']['properties'][key])
                  for key, value in matched.groupdict().items()}
        pairs = (parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True,
                           encoding='utf-8', errors='strict', max_num_fields=65)
                 if parsed.query else [])
        if len({key for key, _ in pairs}) != len(pairs):
            raise BrowserError()
        query, cursor = {}, None
        reserved = operation['pagination']['request_cursor']['name'] if operation['pagination'] else None
        for key, value in pairs:
            if key == reserved:
                cursor = value
            else:
                schema = operation['query_schema']['properties'].get(key)
                if schema is None:
                    return None
                query[key] = _decode_scalar(value, schema)
        body = None if message['post_data'] is None else c.loads(message['post_data'], max_bytes=65536)
        args = {'operation_id': operation['id'], 'path_params': params, 'query': query, 'body': body, 'cursor': cursor}
        path, _ = _request_target(operation, args)
        if path != parsed.path:
            raise BrowserError()
        for field, schema in [('path_params', 'path_params_schema'), ('query', 'query_schema'), ('body', 'body_schema')]:
            c.validate_value(args[field], operation[schema])
        if operation['effect'] in ('mutation', 'publication'):
            if handle.raw_action['action'] not in ('click', 'fill', 'select') or not handle.effect_started:
                raise BrowserError('operation_not_granted')
            if handle.target['request_body_template'] is None or body != self._template(handle, handle.target['request_body_template']):
                raise BrowserError()
        return args

    def _request(self, handle, message):
        c.exact(message, {'kind', 'request_id', 'action_id', 'url', 'method', 'headers', 'post_data', 'resource_type', 'redirected'}, '')
        if (message['action_id'] != handle.action_id or message['redirected'] is not False or
                message['resource_type'] in ('Image', 'Font', 'Media') or self.api.authority.redactor.contains(c.canonical(message))):
            raise BrowserError('operation_not_granted')
        c.text(message['url'], '/url', 8192)
        c.text(message['method'], '/method', 8)
        if type(message['headers']) is not dict:
            raise BrowserError()
        if any(name.lower() in ('authorization', 'proxy-authorization', 'cookie', 'x-agent-api-key') for name in message['headers']):
            raise BrowserError()
        matches = []
        for operation_id in handle.target['allowed_operation_ids']:
            operation = self.api._operations[operation_id]
            try:
                arguments = self._operation_input(handle, operation, message)
            except (c.ContractError, BrowserError, ValueError):
                continue
            if arguments is not None:
                matches.append((operation_id, arguments))
        if len(matches) > 1:
            raise BrowserError('operation_not_granted')
        if matches:
            result, response = self.api.execute_browser(handle, *matches[0])
            return response if result.get('ok') is True else None
        parsed = urlsplit(message['url'])
        if message['method'] != 'GET' or parsed.query or parsed.fragment or message['post_data'] is not None:
            raise BrowserError('operation_not_granted')
        for resource in handle.target['static_resources']:
            origin = self.api.plan['application']['origins'][resource['origin']]['url']
            if message['url'] == origin + resource['path']:
                result = self.api.execute_browser_resource(handle, resource)
                return result if result['ok'] else None
        raise BrowserError('operation_not_granted')

    def execute(self, bearer, scope, native_call_id, input, budget_grant=None):
        handle = None
        captures, denied, result = [], [], None
        diagnostic = None
        sensitive_dom = False
        started = time.monotonic()
        try:
            handle = self.api.begin_browser_action(bearer, scope, native_call_id, input, budget_grant)
            command = {'kind': 'action', 'action_id': handle.action_id, 'action': input['action'],
                'target': {key: handle.target[key] for key in ('url', 'page_identity', 'locator', 'allowed_operation_ids')}}
            for key in ('value', 'option_id'):
                if key in input:
                    command[key] = input[key]
            self.bridge.send(command, handle.deadline)
            intercepted = 0
            while True:
                message = self.bridge.receive(handle.deadline)
                if message.get('action_id') != handle.action_id:
                    raise BrowserError('operation_not_granted')
                if message.get('kind') == 'effect_boundary':
                    if input['action'] not in ('click', 'fill', 'select') or handle.effect_started:
                        raise BrowserError('operation_not_granted')
                    handle.effect_started = True
                    self.bridge.send({'kind': 'effect_ack', 'action_id': handle.action_id}, handle.deadline)
                    continue
                if message.get('kind') == 'request':
                    intercepted += 1
                    response = None
                    try:
                        if intercepted > 16:
                            raise BrowserError('evidence_limit')
                        response = self._request(handle, message)
                        if response is None:
                            denied.append('request_failed')
                    except Exception:
                        denied.append('request_denied')
                    answer = {'kind': 'response', 'action_id': handle.action_id, 'request_id': message['request_id'],
                        'ok': response is not None, 'abort': self.api.quarantined}
                    if response is not None:
                        headers = [{'name': 'Content-Type', 'value': response['media_type'] + '; charset=utf-8'},
                                   {'name': 'Cache-Control', 'value': 'no-store'}, {'name': 'X-Content-Type-Options', 'value': 'nosniff'}]
                        if response['media_type'] == 'text/html':
                            headers.append({'name': 'Content-Security-Policy', 'value': CSP})
                        answer.update(status=response['status'], headers=headers, body_base64=base64.b64encode(response['body']).decode('ascii'))
                    self.bridge.send(answer, handle.deadline)
                    continue
                if message.get('kind') != 'result':
                    raise BrowserError()
                if message.get('diagnostic') is not None:
                    diagnostic = message['diagnostic']
                    c.exact(diagnostic, {'code','phase','loading_count','pending_count','dom_ready','network_seen',
                                        'frame_started','frame_completed','network_finished','unmatched_finished'}, '/diagnostic')
                    c.choice(diagnostic['code'], ('readiness_limit','readiness_unavailable','navigation_unready','dom_limit',
                        'page_identity_mismatch','unsupported_opaque_capture','screenshot_limit','locator_not_unique',
                        'element_outside_viewport','unsupported_input','unsupported_option','action_deadline','bridge_action_failed'), '/diagnostic/code')
                    c.choice(diagnostic['phase'], ('prepare','perform','readiness','after_capture','screenshot'), '/diagnostic/phase')
                    for key in ('loading_count','pending_count','network_finished','unmatched_finished'):
                        c.integer(diagnostic[key], '/diagnostic/' + key, maximum=1000)
                    for key in ('dom_ready','network_seen','frame_started','frame_completed'):
                        c.choice(diagnostic[key], (True,False), '/diagnostic/' + key)
                for key in ('dom_before', 'dom_after'):
                    if message.get(key) is None:
                        continue
                    c.text(message[key], '/' + key, 262144, empty=True)
                    raw_dom = message[key].encode('utf-8')
                    this_sensitive = self.api.authority.redactor.contains(raw_dom)
                    sensitive_dom = sensitive_dom or this_sensitive
                    body = (c.canonical({'schema':1,'document_type':'application_dom_capture_unavailable',
                                         'reason':'credential_sensitive'}) if this_sensitive
                            else self.api.authority.redactor.bytes(raw_dom))
                    captures.append((key, body, 'application/json'))
                if message.get('ok') is not True or len(captures) != 2:
                    raise BrowserError('evidence_unavailable')
                screenshot = message.get('screenshot')
                if input['action'] == 'screenshot':
                    if type(screenshot) is not str or message.get('opaque') is not False or sensitive_dom:
                        raise BrowserError('evidence_unavailable')
                    png = base64.b64decode(screenshot, validate=True)
                    if len(png) > 2097152 or png[:8] != b'\x89PNG\r\n\x1a\n' or len(png) < 24:
                        raise BrowserError('evidence_limit')
                    width, height = struct.unpack('!II', png[16:24])
                    if not (1 <= width <= 1280 and 1 <= height <= 960):
                        raise BrowserError('evidence_limit')
                    captures.append(('screenshot', png, 'image/png'))
                elif screenshot is not None:
                    raise BrowserError()
                c.array(message.get('denied', []), '/denied', 16)
                denied += ['bridge_request_denied'] * len(message.get('denied', []))
                result = {'ok': not self.api.quarantined and not denied, 'action_id': handle.action_id,
                          'operation_receipt_ids': handle.receipt_ids, 'resource_receipt_ids': handle.resource_ids}
                if denied:
                    result['reason'] = 'operation_not_granted'
                if input['action'] == 'snapshot':
                    result['dom'] = captures[-1][1].decode('utf-8')
                    if sensitive_dom: result['capture_unavailable'] = True
                break
        except Exception as exc:
            result = {'ok': False, 'reason': getattr(exc, 'reason', 'evidence_unavailable')}
            if handle is not None:
                if handle.transmitted_writes:
                    self.api.quarantined = True
                    self.api.evidence.state['blocked'][scope['stage_id']] = 'browser_action_outcome_unknown'
                    result['outcome'] = 'outcome_unknown'
                try:
                    self.bridge.close()
                except Exception:
                    self.api.quarantined = True
        if handle is not None and result.get('ok') is not True:
            if handle.transmitted_writes:
                self.api.quarantined = True
                self.api.evidence.state['blocked'][scope['stage_id']] = 'browser_action_outcome_unknown'
                result['outcome'] = 'outcome_unknown'
            try:
                self.bridge.close()
            except Exception:
                self.api.quarantined = True
        if handle is not None:
            try:
                references = self.api.finish_browser_action(handle, {'ok': result['ok'],
                    'outcome': result.get('outcome', 'succeeded' if result['ok'] else 'failed'),
                    'reason': result.get('reason'), 'denied_requests': len(denied),
                    'elapsed_seconds': round(time.monotonic() - started, 6), 'classification': self.classification,
                    'diagnostic': diagnostic}, captures)
                result['action_id'] = handle.action_id
                result['captures'] = [{'kind': row['kind'], 'sha256': row['sha256'], 'bytes': row['bytes']} for row in references]
            except Exception:
                result = {'ok': False, 'reason': 'evidence_unavailable', 'outcome': 'outcome_unknown' if handle.transmitted_writes else 'failed'}
        return self.api._bounded(result)
