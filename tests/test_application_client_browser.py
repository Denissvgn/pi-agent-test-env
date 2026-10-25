"""Controlled bridge protocol tests; these are NOT real-browser qualification.

The native harness entrypoint requires an already-owned Linux ARM64 browser
container and a parent-reviewed admission receipt. It never launches Docker.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import unittest
from unittest.mock import Mock, patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'skill/scripts'), str(ROOT / 'skill/runtime')]
import application_browser as browser
import application_api
import application_contracts as c
import test_application_client_api as api_fixtures

PNG = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=')


class ControlledBridge:
    classification = 'controlled_bridge_protocol_only'
    def __init__(self):
        self.commands, self.answers, self.events, self.script, self.closed = [], [], [], [], False
        self.dom_override = None
        self.ready = {'kind': 'ready', 'browser': 'controlled fixture'}
    def send(self, message, deadline):
        if message['kind'] == 'action':
            self.commands.append(message)
            self.events = []
            for event in self.script:
                self.events.append({**copy.deepcopy(event), 'action_id': message['action_id']})
            html = '<html><head><meta name="pi-application-page" content="diagnostic-summary-v1"></head><body>Reviewed text</body></html>'
            html = self.dom_override or html
            html = json.dumps({'url': message['target']['url'], 'page_identity': [message['target']['page_identity']],
                               'html': html, 'form_state': []})
            self.events.append({'kind': 'result', 'action_id': message['action_id'], 'ok': True,
                'dom_before': html, 'dom_after': html,
                'screenshot': base64.b64encode(PNG).decode() if message['action'] == 'screenshot' else None,
                'opaque': False, 'denied': []})
        elif message['kind'] == 'response':
            self.answers.append(message)
            if message.get('abort'):
                self.events = [{'kind': 'result', 'action_id': message['action_id'], 'ok': False,
                                'reason': 'browser_action_failed', 'denied': []}]
    def receive(self, deadline):
        return self.events.pop(0)
    def close(self):
        self.closed = True


class ControlledBrowserTests(unittest.TestCase):
    def setUp(self):
        self.fixture = api_fixtures.APITests(methodName='runTest')
        self.fixture.setUp()
        fixture = self.fixture
        fixture.client.close(); fixture.client = None
        fixture.source['runtime'].update(container_profile='browser', browser_sandbox_policy='chromium-userns')
        fixture.source['application']['limits']['max_evidence_bytes'] = 33554432
        empty = {'type': 'object', 'properties': {}, 'required': [], 'additionalProperties': False}
        target = {'id': 'summary-page', 'page_identity': 'diagnostic-summary-v1',
            'url': fixture.source['application']['origins']['fixture']['url'] + '/summary',
            'locator': '[data-testid="publish-summary"]',
            'actions': ['navigate', 'snapshot', 'screenshot', 'click'], 'credential_alias': 'persona',
            'allowed_operation_ids': ['list-records', 'publish-summary'], 'static_resources': [],
            'request_body_template': {'target_id': 'team-summary', 'artifact_id': 'summary', 'artifact_sha256': '${artifact.summary.sha256}'},
            'input_schema': empty}
        fixture.source['application']['browser_targets'] = [target]
        fixture.source['stages'][0]['browser_targets'] = [target['id']]
        fixture.build()
        self.bridge = ControlledBridge()
        self.admission = {'schema': 1, 'document_type': 'browser_admission', 'status': 'PASS',
            'image': {'id': fixture.plan['runtime']['image_id'], 'platform': 'linux/arm64'},
            'host': {'native_platform': 'linux/arm64', 'selected_platform': 'linux/arm64'},
            'browser_security': {'policy': 'chromium-userns'},
            'process': {'exit_code': 0, 'cleanup_confirmed': True},
            'observations': [{'browser_sandbox': {'namespace_and_seccomp_verified': True}}]}
        self.controller = browser.BrowserClient(fixture.client, self.admission, bridge_factory=lambda: self.bridge)

    def tearDown(self):
        self.controller.close()
        self.fixture.tearDown()

    def call(self, action='snapshot', **fields):
        fixture = self.fixture
        raw = {'action': action, 'target_id': 'summary-page', **fields}
        native_id, grant = 'browser_call_' + uuid.uuid4().hex, uuid.uuid4().hex * 2
        fixture.grants[grant] = (copy.deepcopy(fixture.scope), native_id, 'app_browser', copy.deepcopy(raw))
        return self.controller.execute(fixture.bearer, fixture.scope, native_id, raw, grant)

    def request(self, operation='list-records', body=None, **changes):
        path = '/records' if operation == 'list-records' else '/publications'
        message = {'kind': 'request', 'request_id': 'request-1',
            'url': self.fixture.source['application']['origins']['fixture']['url'] + path,
            'method': 'GET' if operation == 'list-records' else 'POST', 'headers': {},
            'post_data': None if body is None else json.dumps(body), 'resource_type': 'Fetch', 'redirected': False}
        return {**message, **changes}

    def test_each_snapshot_and_screenshot_sends_only_one_declared_bridge_command(self):
        self.fixture.call()
        for action in ('snapshot', 'screenshot', 'navigate'):
            result = self.call(action)
            self.assertTrue(result['ok'], result)
            self.assertEqual(self.bridge.commands[-1]['action'], action)
        self.assertEqual(len(self.bridge.commands), 3)
        self.assertEqual(len(self.fixture.requests), 1)
        self.assertEqual(self.fixture.effects, [])

    def test_browser_requires_explicit_identity_before_bridge_action(self):
        result = self.call('navigate')
        self.assertFalse(result['ok'])
        self.assertEqual(result['reason'], 'identity_unverified')
        self.assertEqual(self.bridge.commands, [])
        self.assertEqual(self.fixture.requests, [])

    def test_snapshot_and_navigation_never_unlock_listed_mutation(self):
        self.fixture.call()
        for action in ('snapshot', 'screenshot', 'navigate'):
            self.bridge.script = [self.request('publish-summary', self.fixture.publication_body())]
            result = self.call(action)
            self.assertFalse(result['ok'])
            self.assertEqual(self.fixture.effects, [])
        self.assertEqual(len(self.fixture.requests), 1)

    def test_matching_explicit_click_permits_one_write_and_denies_second(self):
        self.fixture.call()
        first = self.request('publish-summary', self.fixture.publication_body())
        self.bridge.script = [{'kind': 'effect_boundary'}, first, {**first, 'request_id': 'request-2'}]
        result = self.call('click')
        self.assertFalse(result['ok'])
        self.assertEqual(len(self.fixture.effects), 1)
        self.assertEqual(len(self.fixture.requests), 2)
        self.assertEqual([answer['ok'] for answer in self.bridge.answers], [True, False])

    def test_template_mismatch_headers_foreign_url_and_redirect_are_denied_before_http(self):
        self.fixture.call()
        base = self.request('publish-summary', self.fixture.publication_body())
        bad_body = self.fixture.publication_body(); bad_body['target_id'] = 'different'
        for request in [self.request('publish-summary', bad_body), {**base, 'headers': {'Authorization': 'admin'}},
                        {**base, 'url': 'http://foreign.invalid/publications'}, {**base, 'redirected': True}]:
            self.bridge.script = [{'kind': 'effect_boundary'}, request]
            self.assertFalse(self.call('click')['ok'])
        self.assertEqual(len(self.fixture.requests), 1)
        self.assertEqual(self.fixture.effects, [])

    def test_ambiguous_write_aborts_bridge_and_prevents_every_follow_up_effect(self):
        self.fixture.call(); self.fixture.mode = 'disconnect'
        first = self.request('publish-summary', self.fixture.publication_body())
        self.bridge.script = [{'kind': 'effect_boundary'}, first, {**first, 'request_id': 'request-2'}]
        result = self.call('click')
        self.assertEqual(result['outcome'], 'outcome_unknown')
        self.assertTrue(self.bridge.closed)
        self.assertTrue(self.fixture.client.quarantined)
        self.assertEqual(len(self.fixture.effects), 1)
        self.assertFalse(self.call('click')['ok'])
        self.assertEqual(len(self.fixture.effects), 1)

    def test_private_action_handles_are_required_not_serialized_or_forged(self):
        self.fixture.call()
        with self.assertRaises(Exception):
            self.fixture.client.execute_browser({'action_id': 'forged'}, 'list-records', {})
        self.assertEqual(len(self.fixture.requests), 1)

    def test_one_budget_action_proof_covers_distinct_network_operations(self):
        self.fixture.call()
        self.bridge.script = [{'kind': 'effect_boundary'}, self.request('list-records'), self.request('publish-summary', self.fixture.publication_body(), request_id='request-2')]
        result = self.call('click')
        self.assertTrue(result['ok'], result)
        self.assertEqual(len(self.fixture.requests), 3)
        receipts = [self.fixture.read_receipt(receipt_id) for receipt_id in result['operation_receipt_ids']]
        self.assertEqual({row['transport'] for row in receipts}, {'browser'})
        self.assertEqual(len({row['native_call_id'] for row in receipts}), 1)
        self.assertEqual(len({row['action_id'] for row in receipts}), 1)
        self.assertEqual(len({row['operation_id'] for row in receipts}), 2)

    def test_browser_receives_helper_cursor_and_reserved_query_maps_only_stored_token(self):
        self.fixture.call()
        self.bridge.script = [self.request('list-records')]
        first = self.call('click')
        self.assertTrue(first['ok'])
        body = json.loads(base64.b64decode(self.bridge.answers[-1]['body_base64']))
        helper_cursor = body['next_cursor']
        self.assertRegex(helper_cursor, '^[0-9a-f]{64}$')
        self.assertNotIn('upstream-page-2', json.dumps(body))
        request = self.request('list-records')
        request['url'] += '?cursor=' + helper_cursor
        self.bridge.script = [request]
        second = self.call('click')
        self.assertTrue(second['ok'], second)
        self.assertTrue(self.fixture.requests[-1]['path'].endswith('cursor=upstream-page-2'))
        body = json.loads(base64.b64decode(self.bridge.answers[-1]['body_base64']))
        self.assertIsNone(body['next_cursor'])
        receipt = self.fixture.read_receipt(second['operation_receipt_ids'][0])
        self.assertEqual(receipt['pagination']['state'], 'exhausted')
        self.assertEqual(receipt['pagination']['predecessor_receipt_id'], first['operation_receipt_ids'][0])

    def test_scope_and_input_errors_have_no_bridge_or_http_effect(self):
        for raw in [{'action': 'evaluate', 'target_id': 'summary-page', 'script': 'x'},
                    {'action': 'click', 'target_id': 'other'}, {'action': 'click', 'target_id': 'summary-page', 'url': 'http://foreign'}]:
            result = self.controller.execute(self.fixture.bearer, self.fixture.scope, 'native_id', raw, '0' * 64)
            self.assertFalse(result['ok'])
        self.assertEqual(self.bridge.commands, [])
        self.assertEqual(self.fixture.requests, [])

    def test_sandbox_or_unsupported_media_failure_happens_before_bridge_creation(self):
        factory = Mock()
        broken = copy.deepcopy(self.admission); broken['browser_security']['policy'] = 'docker-default'
        with self.assertRaises(browser.BrowserError):
            browser.BrowserClient(self.fixture.client, broken, bridge_factory=factory)
        factory.assert_not_called()
        target = self.fixture.client.plan['application']['browser_targets'][0]
        target['static_resources'].append({'method': 'GET', 'origin': 'fixture', 'path': '/secret.png', 'media_type': 'image/png', 'max_bytes': 100})
        self.assertTrue(browser.unsupported_browser_assets(self.fixture.client.plan, 'participant'))
        with self.assertRaises(browser.BrowserError):
            browser.BrowserClient(self.fixture.client, self.admission, bridge_factory=factory)
        factory.assert_not_called()
        self.assertEqual(self.fixture.requests, [])

    def test_worst_case_capacity_is_reserved_before_bridge_action(self):
        self.fixture.call()
        with patch.object(self.fixture.client.evidence, 'reserve', side_effect=browser.APIError('evidence_limit')):
            result = self.call('click')
        self.assertFalse(result['ok'])
        self.assertEqual(self.bridge.commands, [])
        self.assertEqual(len(self.fixture.requests), 1)

    def test_live_dom_with_known_credential_is_redacted_and_screenshot_unavailable(self):
        self.fixture.call()
        self.bridge.dom_override = '<html><body>' + api_fixtures.KEY_A + '</body></html>'
        snapshot = self.call('snapshot')
        self.assertTrue(snapshot['ok'])
        self.assertNotIn(api_fixtures.KEY_A, json.dumps(snapshot))
        screenshot = self.call('screenshot')
        self.assertFalse(screenshot['ok'])
        self.assertFalse(any(capture['kind'] == 'screenshot' for capture in screenshot.get('captures', [])))
        for path in self.fixture.evidence.rglob('*'):
            if path.is_file():
                self.assertFalse(self.fixture.authority.redactor.contains(path.read_bytes()))

    def test_encoded_credential_response_is_unavailable_instead_of_decoded_in_browser(self):
        key = api_fixtures.KEY_A
        bodies = [''.join('&#' + str(ord(character)) + ';' for character in key),
                  ''.join('\\u' + format(ord(character), '04x') for character in key)]
        for body in bodies:
            raw = b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n' + body.encode()
            with self.assertRaises(application_api.APIError) as error:
                application_api._redacted_response(raw, self.fixture.authority.redactor)
            self.assertEqual(error.exception.reason, 'evidence_unavailable')

    def test_fill_and_select_bind_one_exact_input_and_declared_option(self):
        self.controller.close()
        self.fixture.client.close(); self.fixture.client = None
        common = copy.deepcopy(self.fixture.source['application']['browser_targets'][0])
        fill = dict(common, id='title-input', locator='[data-testid="title-input"]', actions=['fill'], allowed_operation_ids=[], request_body_template=None,
            input_schema={'type':'object','properties':{'value':{'type':'string','maxLength':16}},'required':['value'],'additionalProperties':False})
        select = dict(common, id='label-select', locator='[data-testid="label-select"]', actions=['select'], allowed_operation_ids=[], request_body_template=None,
            input_schema={'type':'object','properties':{'option_id':{'type':'string','enum':['one','two']}},'required':['option_id'],'additionalProperties':False})
        self.fixture.source['application']['browser_targets'] += [fill, select]
        self.fixture.source['stages'][0]['browser_targets'] += ['title-input', 'label-select']
        self.fixture.build(); self.fixture.call()
        self.bridge = ControlledBridge()
        self.controller = browser.BrowserClient(self.fixture.client, self.admission, bridge_factory=lambda:self.bridge)
        for raw in [{'action':'fill','target_id':'title-input','value':'Reviewed'},
                    {'action':'select','target_id':'label-select','option_id':'two'}]:
            native, grant='native-' + uuid.uuid4().hex, uuid.uuid4().hex*2
            self.fixture.grants[grant]=(copy.deepcopy(self.fixture.scope),native,'app_browser',copy.deepcopy(raw))
            self.assertTrue(self.controller.execute(self.fixture.bearer,self.fixture.scope,native,raw,grant)['ok'])
        self.assertEqual([command['action'] for command in self.bridge.commands],['fill','select'])
        raw={'action':'select','target_id':'label-select','option_id':'three'}
        self.assertFalse(self.controller.execute(self.fixture.bearer,self.fixture.scope,'bad-option',raw,'0'*64)['ok'])
        self.assertEqual(len(self.bridge.commands),2)
        self.assertEqual(len(self.fixture.requests),1)

    def test_native_bridge_fails_closed_on_mac_instead_of_using_host_chrome(self):
        with patch.object(browser.sys, 'platform', 'darwin'), patch.object(browser.subprocess, 'Popen') as launch:
            with self.assertRaises(browser.BrowserError):
                browser.CDPPipeBridge()
        launch.assert_not_called()

    def test_renderer_checkpoint_settles_when_headless_animation_frames_are_suspended(self):
        module=(ROOT/'skill/runtime/application-browser-cdp.mjs').as_uri()
        script="""import vm from 'node:vm';
import {RENDERER_CHECKPOINT} from MODULE;
let frames=0;
const realm={Promise,setTimeout,requestAnimationFrame:()=>{frames++;}};
const value=await vm.runInNewContext(RENDERER_CHECKPOINT,realm,{timeout:1000});
if(value!==true||frames!==0)throw Error('checkpoint depends on suspended compositor');
console.log('renderer task checkpoint passed with suspended RAF');
""".replace('MODULE',json.dumps(module))
        result=subprocess.run(['node','--input-type=module','-e',script],stdin=subprocess.DEVNULL,
                              capture_output=True,text=True,timeout=3)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('checkpoint passed',result.stdout)


def native_harness(admission_path, output_dir, case='positive'):
    """Run in an already-owned native browser container; never starts Docker."""
    output = Path(output_dir)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    admission = c.loads(Path(admission_path).read_bytes(), max_bytes=2097152)
    fixture = api_fixtures.APITests(methodName='runTest')
    controller, foreign, foreign_thread, phase = None, None, None, 'prepare'
    observations, forbidden_requests = [], []
    result = {'schema': 1, 'document_type': 'application_browser_native_fixture', 'case': case,
              'classification': 'real Chromium/CDP + controlled localhost application; no Pi/model',
              'status': 'FAIL', 'browser_actions': [], 'pi_invocations': 0}
    try:
        temporary_root = os.environ.get('TMPDIR')
        if not temporary_root or not Path(temporary_root).is_absolute() or not os.access(temporary_root, os.W_OK):
            raise browser.BrowserError('runtime_mismatch')
        fixture.temporary_root = temporary_root
        fixture.setUp()
        fixture.client.close(); fixture.client = None
        fixture.source['runtime'].update(image_id=admission['image']['id'], container_profile='browser', browser_sandbox_policy='chromium-userns')
        fixture.source['application']['limits']['max_evidence_bytes'] = 33554432
        class Forbidden(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self): forbidden_requests.append(self.path); self.send_response(204); self.end_headers()
            do_POST = do_GET
        foreign = ThreadingHTTPServer(('127.0.0.1', 0), Forbidden)
        foreign.daemon_threads = True
        foreign_thread = threading.Thread(target=foreign.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        foreign_thread.start()
        payload = fixture.publication_body()
        page = '''<!doctype html><html><head><meta charset="utf-8"><meta name="pi-application-page" content="diagnostic-summary-v1">
<link rel="icon" href="data:,"><title>Reviewed browser fixture</title></head><body>
<h1>Application records</h1><p id="key-echo">KEY_ECHO</p><input data-testid="title-input" value="">
<select data-testid="label-select"><option value="one">One</option><option value="two">Two</option></select>
<button data-testid="load-records">Read one page</button><button data-testid="publish-summary">Publish</button>
<button data-testid="escape">Attempt unsupported network</button><div id="records"></div><div id="publication"></div>
<script>let cursor=null;const payload=PAYLOAD;
document.querySelector('[data-testid="load-records"]').onclick=async()=>{const response=await fetch('/records'+(cursor?'?cursor='+encodeURIComponent(cursor):''));const value=await response.json();cursor=value.next_cursor;document.getElementById('records').textContent+=value.items.map(x=>x.id+':'+x.text).join(',');};
document.querySelector('[data-testid="publish-summary"]').onclick=async()=>{const response=await fetch('/publications',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const value=await response.json();document.getElementById('publication').textContent=value.state;};
document.querySelector('[data-testid="escape"]').onclick=()=>{const foreign='FOREIGN';try{window.open(foreign+'/popup');}catch{}try{new Worker(foreign+'/worker.js');}catch{}try{new WebSocket(foreign.replace('http:','ws:')+'/socket');}catch{}const frame=document.createElement('iframe');frame.src=foreign+'/frame';document.body.appendChild(frame);fetch(foreign+'/background',{method:'POST',body:'denied'}).catch(()=>{});};
</script></body></html>'''.replace('KEY_ECHO', api_fixtures.KEY_A).replace('PAYLOAD', json.dumps(payload)).replace('FOREIGN', 'http://127.0.0.1:' + str(foreign.server_port))
        if case == 'double-write':
            page = page.replace("const response=await fetch('/publications',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});",
                "const request=()=>fetch('/publications',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const responses=await Promise.all([request(),request()]);const response=responses[0];")
        elif case == 'capture-denial':
            # No author CSS or light-DOM opaque element can trigger the simple
            # document.querySelector check. Only the pierced CDP tree sees this
            # script-created closed author shadow root and its real canvas.
            page = page.replace('</body>', '''<div id="closed-capture-host"></div><script>
const hiddenRoot=document.getElementById('closed-capture-host').attachShadow({mode:'closed'});
const hiddenCanvas=document.createElement('canvas');hiddenCanvas.width=16;hiddenCanvas.height=16;
hiddenCanvas.getContext('2d').fillRect(0,0,16,16);hiddenRoot.appendChild(hiddenCanvas);
</script></body>''')
        original_handler = fixture.server.RequestHandlerClass
        class NativeHandler(original_handler):
            def dispatch(self):
                if self.path == '/summary':
                    fixture.requests.append({'method': self.command, 'path': self.path,
                        'key': self.headers.get('X-Agent-API-Key'), 'body': b'', 'host': self.headers.get('Host')})
                    body = page.encode()
                    self.send_response(200); self.send_header('Content-Type', 'text/html'); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
                else:
                    super().dispatch()
            do_GET = dispatch
            do_POST = dispatch
        fixture.server.RequestHandlerClass = NativeHandler
        origin = fixture.source['application']['origins']['fixture']['url']
        empty = {'type': 'object', 'properties': {}, 'required': [], 'additionalProperties': False}
        common = {'page_identity': 'diagnostic-summary-v1', 'url': origin + '/summary', 'credential_alias': 'persona',
                  'static_resources': [], 'request_body_template': None, 'input_schema': empty}
        targets = [dict(common, id='summary-page', locator=None, actions=['navigate', 'snapshot', 'screenshot'], allowed_operation_ids=[],
                        static_resources=[{'method': 'GET', 'origin': 'fixture', 'path': '/summary', 'media_type': 'text/html', 'max_bytes': 16384}]),
                   dict(common, id='records-button', locator='[data-testid="load-records"]', actions=['click'], allowed_operation_ids=['list-records']),
                   dict(common, id='publish-button', locator='[data-testid="publish-summary"]', actions=['click'], allowed_operation_ids=['publish-summary'],
                        request_body_template={'target_id':'team-summary','artifact_id':'summary','artifact_sha256':'${artifact.summary.sha256}'}),
                   dict(common, id='title-input', locator='[data-testid="title-input"]', actions=['fill'], allowed_operation_ids=[],
                        input_schema={'type':'object','properties':{'value':{'type':'string','maxLength':128}},'required':['value'],'additionalProperties':False}),
                   dict(common, id='label-select', locator='[data-testid="label-select"]', actions=['select'], allowed_operation_ids=[],
                        input_schema={'type':'object','properties':{'option_id':{'type':'string','enum':['one','two']}},'required':['option_id'],'additionalProperties':False}),
                   dict(common, id='escape-button', locator='[data-testid="escape"]', actions=['click'], allowed_operation_ids=[])]
        fixture.source['application']['browser_targets'] = targets
        fixture.source['stages'][0]['browser_targets'] = [target['id'] for target in targets]
        fixture.build()
        phase = 'launch-real-browser'
        controller = browser.BrowserClient(fixture.client, admission)
        phase = 'explicit-api-identity'
        assert fixture.call()['ok'] is True
        def action(verb, target, **fields):
            nonlocal phase
            phase = verb + ':' + target
            raw = {'action':verb, 'target_id':target, **fields}
            native, grant = 'native-browser-' + uuid.uuid4().hex, uuid.uuid4().hex * 2
            fixture.grants[grant] = (copy.deepcopy(fixture.scope), native, 'app_browser', copy.deepcopy(raw))
            observed = controller.execute(fixture.bearer, fixture.scope, native, raw, grant)
            observations.append({'action':verb,'target_id':target,'ok':observed.get('ok'), 'outcome':observed.get('outcome'),
                                 'reason':observed.get('reason'),'action_id':observed.get('action_id')})
            return observed
        assert action('navigate','summary-page')['ok'] is True
        if case == 'positive':
            assert action('snapshot','summary-page')['ok'] is True
            filled=action('fill','title-input',value='Reviewed title'); assert filled['ok'] is True
            form=c.loads((fixture.evidence/'browser-actions'/filled['action_id']/'dom_after.txt').read_bytes())['form_state']
            assert next(field['value'] for field in form if field['test_id']=='title-input')=='Reviewed title'
            selected=action('select','label-select',option_id='two'); assert selected['ok'] is True
            form=c.loads((fixture.evidence/'browser-actions'/selected['action_id']/'dom_after.txt').read_bytes())['form_state']
            assert next(field['value'] for field in form if field['test_id']=='label-select')=='two'
            shot = action('screenshot','summary-page'); assert shot['ok'] is True
            assert any(item['kind']=='screenshot' and item['bytes']<=2097152 for item in shot['captures'])
            first=action('click','records-button'); assert first['ok'] is True
            observed=c.loads((fixture.evidence/'browser-actions'/first['action_id']/'dom_after.txt').read_bytes())['html']
            assert 'r1:First' in observed and 'r2:Second' in observed
            second=action('click','records-button'); assert second['ok'] is True
            observed=c.loads((fixture.evidence/'browser-actions'/second['action_id']/'dom_after.txt').read_bytes())['html']
            assert 'r3:Third' in observed
            assert action('click','publish-button')['ok'] is True
            assert len(fixture.effects)==1
            assert fixture.effects[0]['content']==fixture.content
            receipts = [fixture.read_receipt(receipt_id) for receipt_id in fixture.client.receipt_index(fixture.scope)]
            pages=[row['pagination'] for row in receipts if row['pagination']]
            assert [page['state'] for page in pages]==['more','exhausted']
        elif case == 'ambiguous':
            fixture.mode='disconnect'
            observed=action('click','publish-button')
            assert observed.get('outcome')=='outcome_unknown'
            assert len(fixture.effects)==1
            assert action('click','publish-button')['ok'] is False
            assert len(fixture.effects)==1
        elif case == 'network-denial':
            action('click','escape-button')
            assert forbidden_requests==[]
            assert fixture.effects==[]
        elif case == 'double-write':
            observed=action('click','publish-button')
            assert observed['ok'] is False and observed.get('outcome')=='outcome_unknown'
            assert len(fixture.effects)==1
            assert len([request for request in fixture.requests if request['method']=='POST'])==1
            assert fixture.client.quarantined is True
            assert controller.bridge.process.poll() is not None
            sealed=c.loads((fixture.evidence/'browser-actions'/observed['action_id']/'receipt.json').read_bytes())
            assert sealed['document_type']=='application_browser_action_receipt'
            assert sealed['action']=='click' and sealed['target_id']=='publish-button'
            assert sealed['ok'] is False and sealed['outcome']=='outcome_unknown'
            assert sealed['denied_requests']>=1
            count=len(fixture.requests)
            assert fixture.call()['ok'] is False
            assert action('click','publish-button')['ok'] is False
            assert len(fixture.requests)==count and len(fixture.effects)==1
            result['double_write_proof']={'one_explicit_click':True,'server_posts':1,
                'sealed_outcome':'outcome_unknown','quarantined':True,'bridge_closed':True,
                'later_api_and_browser_extra_http':0}
        elif case == 'capture-denial':
            observed=action('screenshot','summary-page')
            assert observed['ok'] is False
            assert not any(item['kind']=='screenshot' for item in observed.get('captures',[]))
            assert not any(fixture.evidence.rglob('*.png'))
            assert fixture.effects==[]
            sealed=c.loads((fixture.evidence/'browser-actions'/observed['action_id']/'receipt.json').read_bytes())
            assert sealed['diagnostic']['code']=='unsupported_opaque_capture'
            assert sealed['diagnostic']['phase']=='screenshot'
            dom=c.loads((fixture.evidence/'browser-actions'/observed['action_id']/'dom_after.txt').read_bytes())['html']
            assert 'closed-capture-host' in dom and "attachShadow({mode:'closed'})" in dom
            assert '<canvas' not in dom.lower() and '<style' not in dom.lower() and 'style=' not in dom.lower()
            assert not any(request['method']=='POST' for request in fixture.requests)
            result['capture_denial_proof']={'closed_author_shadow_canvas':True,'author_css':False,
                'light_dom_opaque_element':False,'diagnostic':'unsupported_opaque_capture',
                'diagnostic_phase':'screenshot','retained_pngs':0,'server_writes':0}
        else:
            raise ValueError('unknown fixed native case')
        phase='verify-retained-evidence'
        controller.close(); controller=None
        for path in fixture.evidence.rglob('*'):
            if path.is_file():
                assert not fixture.authority.redactor.contains(path.read_bytes())
        result.update(status='PASS', browser_actions=observations, actual_application_requests=len(fixture.requests),
            server_effects=len(fixture.effects), forbidden_origin_requests=len(forbidden_requests),
            key_withheld_from_browser=True, image_id=fixture.plan['runtime']['image_id'], platform='linux/arm64',
            plan_sha256=fixture.plan['plan_sha256'])
    except Exception:
        result.update(status='FAIL', failed_phase=phase, browser_actions=observations)
    finally:
        result.update(actual_application_requests=len(getattr(fixture,'requests', [])),
            server_effects=len(getattr(fixture,'effects', [])), forbidden_origin_requests=len(forbidden_requests))
        if controller is not None:
            controller.close()
        if getattr(fixture, 'client', None) is not None:
            fixture.client.close()
        if hasattr(fixture,'evidence') and fixture.evidence.exists():
            shutil.copytree(fixture.evidence,output/'private-evidence')
        if foreign is not None:
            foreign.shutdown();foreign.server_close();foreign_thread.join(timeout=2)
        if hasattr(fixture,'server'):
            fixture.tearDown()
    result['source_sha256']={str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest() for path in
        [ROOT/'skill/runtime/application_browser.py',ROOT/'skill/runtime/application-browser-cdp.mjs',
         ROOT/'skill/runtime/application_api.py',ROOT/'skill/scripts/application_evidence.py',Path(__file__)]}
    (output/'native-result.json').write_bytes(c.canonical(result)+b'\n')
    print(json.dumps({'status':result['status'],'case':case,'failed_phase':result.get('failed_phase')}))
    return 0 if result['status']=='PASS' else 2


if __name__ == '__main__':
    if '--native-browser' in sys.argv:
        import argparse
        parser=argparse.ArgumentParser()
        parser.add_argument('--native-browser',action='store_true')
        parser.add_argument('--admission',required=True)
        parser.add_argument('--output-dir',required=True)
        parser.add_argument('--case',choices=('positive','ambiguous','network-denial','double-write','capture-denial'),default='positive')
        args=parser.parse_args()
        raise SystemExit(native_harness(args.admission,args.output_dir,args.case))
    unittest.main()
