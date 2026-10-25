"""Credential/capture regressions with pure JS and a controlled browser bridge.

Only the disposable localhost HTTP fixture is real transport. No Chromium,
Docker, Pi, model, application account or external service is used.
"""
import html
import json
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'skill/scripts'), str(ROOT / 'skill/runtime')]
import application_api
from application_credentials import Redactor
import test_application_client_api as api_fixture
import test_application_client_browser as browser_fixture

CANARY = 'synthetic-review-canary-12345678'


class ResponseCredentialNormalizationTests(unittest.TestCase):
    def reject(self, body, media='text/html'):
        raw = ('HTTP/1.1 200 OK\r\nContent-Type: ' + media + '\r\n\r\n' + body).encode()
        self.assertNotIn(CANARY.encode(), raw, 'case must evade the direct contiguous-byte check')
        with self.assertRaises(application_api.APIError) as error:
            application_api._redacted_response(raw, Redactor([CANARY]))
        self.assertEqual(error.exception.reason, 'evidence_unavailable')

    def test_css_hex_escapes_cannot_forward_renderable_credential(self):
        for representation in (''.join('\\' + format(ord(char), 'x') + ' ' for char in CANARY),
                               ''.join('\\' + format(ord(char), '06x') for char in CANARY)):
            with self.subTest(representation=representation):
                self.reject('body::before { content:"' + representation + '"; }', 'text/css')

    def test_css_string_continuations_cannot_hide_known_credential(self):
        for newline in ('\n', '\r\n', '\r', '\f'):
            with self.subTest(newline=repr(newline)):
                self.reject('body::before {content:"' + ('\\' + newline).join(CANARY) + '"}', 'text/css')

    def test_javascript_code_point_escapes_cannot_forward_known_credential(self):
        for digits in ('x', 'X', '016x'):
            encoded = ''.join('\\u{' + format(ord(char), digits) + '}' for char in CANARY)
            with self.subTest(digits=digits):
                self.reject('globalThis.exposed="' + encoded + '";', 'application/javascript')

    def test_safe_javascript_code_point_escapes_remain_byte_preserving(self):
        raw = b'HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nconst publicText="\\u{1f642}";'
        sanitized, redactions = application_api._redacted_response(raw, Redactor([CANARY]))
        self.assertEqual(sanitized, raw)
        self.assertEqual(redactions, [])

    def test_html_text_nodes_and_entities_cannot_split_known_credential(self):
        midpoint = len(CANARY) // 2
        cases = ['<span>' + CANARY[:midpoint] + '</span><span>' + CANARY[midpoint:] + '</span>',
                 '<p>' + '<!--separator-->'.join(CANARY) + '</p>',
                 '<span>' + CANARY[:midpoint] + '</span><span>' +
                 ''.join('&#' + str(ord(char)) + ';' for char in CANARY[midpoint:]) + '</span>']
        for case in cases:
            with self.subTest(case=case): self.reject(case)

    def test_safe_text_and_css_remain_byte_preserving(self):
        for media, body in [('text/html', '<p>Public <span>summary</span></p>'),
                            ('text/css', 'body { color: #123456; }')]:
            raw = ('HTTP/1.1 200 OK\r\nContent-Type: ' + media + '\r\n\r\n' + body).encode()
            sanitized, redactions = application_api._redacted_response(raw, Redactor([CANARY]))
            self.assertEqual(sanitized, raw)
            self.assertEqual(redactions, [])


class AggregatedDOMBridge(browser_fixture.ControlledBridge):
    """Protocol fixture supplies the aggregate text observed by native capture."""
    def __init__(self):
        super().__init__()
        key = api_fixture.KEY_A
        midpoint = len(key) // 2
        self.fragments = (key[:midpoint], key[midpoint:])

    def send(self, message, deadline):
        super().send(message, deadline)
        if message['kind'] != 'action': return
        key = api_fixture.KEY_A
        for event in self.events:
            if event['kind'] != 'result': continue
            for field in ('dom_before', 'dom_after'):
                capture = json.loads(event[field])
                capture.update(html='<html><body><span>' + html.escape(self.fragments[0]) + '</span><span>' +
                    html.escape(self.fragments[1]) + '</span>PRIVATE-DOM-SENTINEL</body></html>',
                    text_content=key, inner_text=key)
                event[field] = json.dumps(capture)


class ControlledBrowserCredentialTests(unittest.TestCase):
    def setUp(self):
        self.case = browser_fixture.ControlledBrowserTests(methodName='runTest')
        self.case.setUp(); self.addCleanup(self.case.tearDown)
        self.fixture = self.case.fixture
        self.assertTrue(self.fixture.call()['ok'])

    def aggregate_bridge(self):
        self.case.bridge.close()
        self.case.bridge = AggregatedDOMBridge()
        self.case.controller.bridge = self.case.bridge
        return self.case.bridge

    def evidence_bytes(self):
        return b'\n'.join(path.read_bytes() for path in self.fixture.evidence.rglob('*') if path.is_file())

    def test_denied_second_request_after_committed_write_durably_quarantines_stage(self):
        first = self.case.request('publish-summary', self.fixture.publication_body())
        self.case.bridge.script = [{'kind': 'effect_boundary'}, first,
                                  {**first, 'request_id': 'denied-second-write'}]
        result = self.case.call('click')
        self.assertFalse(result['ok'])
        self.assertEqual(result['outcome'], 'outcome_unknown')
        self.assertEqual(len(self.fixture.effects), 1)
        self.assertEqual([answer['ok'] for answer in self.case.bridge.answers], [True, False])
        self.assertTrue(self.fixture.client.quarantined)
        self.assertTrue(self.case.bridge.closed)
        state = json.loads((self.fixture.evidence / 'state.json').read_text())
        self.assertEqual(state['blocked'][self.fixture.scope['stage_id']], 'browser_action_outcome_unknown')
        audit_path = self.fixture.evidence / 'browser-actions' / result['action_id'] / 'receipt.json'
        audit = json.loads(audit_path.read_text())
        self.assertEqual(audit['outcome'], 'outcome_unknown')
        self.assertFalse(audit['ok'])
        self.assertEqual(audit['denied_requests'], 1)
        publication = self.fixture.read_receipt(audit['operation_receipt_ids'][0])
        self.assertEqual(publication['outcome'], 'succeeded')
        effects, requests, commands = len(self.fixture.effects), len(self.fixture.requests), len(self.case.bridge.commands)
        later_read = self.fixture.call('list-records')
        self.assertFalse(later_read['ok'])
        self.assertEqual(later_read['reason'], 'evidence_unavailable')
        self.assertFalse(self.case.call('snapshot')['ok'])
        self.assertFalse(self.case.call('click')['ok'])
        self.assertEqual((len(self.fixture.effects), len(self.fixture.requests), len(self.case.bridge.commands)),
                         (effects, requests, commands))

    def test_sensitive_aggregate_snapshot_withholds_whole_dom_and_key_fragments(self):
        bridge = self.aggregate_bridge()
        result = self.case.call('snapshot')
        self.assertTrue(result['ok'], result)
        self.assertTrue(result['capture_unavailable'])
        marker = {'schema': 1, 'document_type': 'application_dom_capture_unavailable', 'reason': 'credential_sensitive'}
        self.assertEqual(json.loads(result['dom']), marker)
        for field in ('dom_before', 'dom_after'):
            body = (self.fixture.evidence / 'browser-actions' / result['action_id'] / (field + '.txt')).read_text()
            self.assertEqual(json.loads(body), marker)
        combined = self.evidence_bytes() + json.dumps(result).encode()
        self.assertNotIn(api_fixture.KEY_A.encode(), combined)
        self.assertNotIn(b'PRIVATE-DOM-SENTINEL', combined)
        for fragment in bridge.fragments:
            self.assertNotIn(fragment.encode(), combined)
        self.assertEqual(len(self.fixture.requests), 1, 'DOM capture must not fetch or repair anything')

    def test_sensitive_aggregate_screenshot_denies_without_persisting_png_or_dom_fragments(self):
        bridge = self.aggregate_bridge()
        result = self.case.call('screenshot')
        self.assertFalse(result['ok'])
        self.assertEqual(result['reason'], 'evidence_unavailable')
        self.assertTrue(bridge.closed)
        self.assertFalse(any(item['kind'] == 'screenshot' for item in result.get('captures', [])))
        self.assertFalse(list(self.fixture.evidence.rglob('*.png')))
        combined = self.evidence_bytes() + json.dumps(result).encode()
        for forbidden in (b'\x89PNG\r\n\x1a\n', api_fixture.KEY_A.encode(), b'PRIVATE-DOM-SENTINEL',
                          *(fragment.encode() for fragment in bridge.fragments)):
            self.assertNotIn(forbidden, combined)
        self.assertEqual(len(self.fixture.requests), 1)


@unittest.skipUnless(shutil.which('node'), 'Node required for controlled capture predicate checks')
class ControlledNativeCaptureContractTests(unittest.TestCase):
    def run_js(self, script):
        result = subprocess.run(['node', '--input-type=module', '-e', script],
                                capture_output=True, text=True, timeout=10, cwd=ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_screenshot_tree_rejects_author_styles_and_retains_plain_form_support(self):
        source = (ROOT / 'skill/runtime/application-browser-cdp.mjs').read_text()
        function = source[source.index('function safeScreenshotTree('):source.index('\nasync function nodeFor(')]
        script = '''import vm from 'node:vm';
const check=vm.runInNewContext(FUNCTION);
const node=(name,extra={})=>({nodeName:name,nodeType:1,...extra});
for(const root of [node('STYLE'),node('style'),node('SPAN',{attributes:['style','content:"secret"']}),
 node('LINK',{attributes:['rel','alternate stylesheet','href','/style.css']}),
 node('link',{attributes:['REL','STYLESHEET']})]) {
 if(check(root))throw Error('author CSS was admitted');
}
if(!check(node('INPUT',{shadowRoots:[{nodeName:'#document-fragment',nodeType:11,shadowRootType:'user-agent',children:[node('DIV',{attributes:['style','display:block']}),node('STYLE')]}]})))throw Error('browser-owned user-agent form styling rejected');
if(!check(node('LINK',{attributes:['rel','canonical','href','/page']})))throw Error('non-stylesheet link rejected');
'''.replace('FUNCTION', json.dumps('(' + function + ')'))
        self.run_js(script)

    def test_actual_capture_expression_contains_aggregate_text_for_python_credential_scan(self):
        source = (ROOT / 'skill/runtime/application-browser-cdp.mjs').read_text()
        start = source.index('const info = await evaluateFixed(`') + len('const info = await evaluateFixed(`')
        expression = source[start:source.index('`,world.id);', start)].replace('${DOM_LIMIT}', '262144')
        script = '''import vm from 'node:vm';
const key=KEY;
const document={documentElement:{outerHTML:'<span>'+key.slice(0,12)+'</span><span>'+key.slice(12)+'</span>',textContent:key,innerText:key},
 querySelectorAll:selector=>selector.startsWith('meta')?[{content:'review-page'}]:[],querySelector:()=>null,readyState:'complete',styleSheets:[],adoptedStyleSheets:[]};
const capture=()=>vm.runInNewContext(EXPRESSION,{document,location:{href:'https://fixture.invalid/page'},TextEncoder});
const value=capture();
const captured=JSON.parse(value.html);
if(captured.html.includes(key))throw Error('fixture does not split source text');
if(captured.text_content!==key||captured.inner_text!==key)throw Error('aggregate text absent');
if(value.opaque!==false)throw Error('fixture unexpectedly opaque');
document.styleSheets=[{}];
if(capture().opaque!==true)throw Error('author stylesheet admitted');
document.styleSheets=[];document.adoptedStyleSheets=[{}];
if(capture().opaque!==true)throw Error('adopted stylesheet admitted');
'''.replace('KEY', json.dumps(CANARY)).replace('EXPRESSION', json.dumps(expression))
        self.run_js(script)


if __name__ == '__main__': unittest.main()
