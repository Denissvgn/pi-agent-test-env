"""A05 real localhost typed-API requests; disposable keys, no Docker/Pi/model."""
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'skill/scripts'), str(ROOT / 'skill/runtime')]
import application_api as api
import application_client_service as service
import application_compiler as compiler
import application_contracts as c
import completion_contract
import test_application_compiler as compiler_fixtures

KEY_A = 'disposable-application-A-\\"-123456'
KEY_B = 'disposable-application-B-987654321'


class ProjectionTests(unittest.TestCase):
    def test_root_array_projection_keeps_json_array_shape_and_sparse_indices(self):
        value = [{'id': 'first', 'private': 'omit'}, {'id': 'second', 'private': 'omit'}]
        original = copy.deepcopy(value)
        projected = api._projection(value, ['/1/id'])
        self.assertEqual(projected, [None, {'id': 'second'}])
        self.assertEqual(c.loads(c.canonical(projected)), projected)
        self.assertEqual(value, original)

    def test_numeric_object_keys_remain_strings(self):
        projected = api._projection({'0': {'id': 'first', 'private': 'omit'}}, ['/0/id'])
        self.assertEqual(projected, {'0': {'id': 'first'}})
        self.assertEqual(c.loads(c.canonical(projected)), projected)


class APITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=getattr(self, 'temporary_root', '/private/tmp'))
        self.root = Path(self.temp.name)
        self.evidence = self.root / 'evidence'; self.evidence.mkdir(mode=0o700)
        self.artifacts = self.root / 'artifacts'; self.artifacts.mkdir(mode=0o700)
        (self.artifacts / 'outputs').mkdir(mode=0o700)
        self.content = '# Typed application summary\n'
        (self.artifacts / 'outputs/summary.md').write_text(self.content)
        self.requests, self.effects, self.grants, self.intent_observations = [], [], {}, []
        self.mode, self.time, self.client = 'normal', 100.0, None
        fixture = self
        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self, *args):
                pass
            def dispatch(self):
                content = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                fixture.requests.append({'method': self.command, 'path': self.path,
                    'key': self.headers.get('X-Agent-API-Key'), 'body': content, 'host': self.headers.get('Host')})
                state = c.loads((fixture.evidence / 'state.json').read_bytes(), max_bytes=8388608)
                fixture.intent_observations.append({'pending': bool(state['pending']), 'writes': bool(state['writes'])})
                route = urlsplit(self.path)
                if route.path == '/identity':
                    value = copy.deepcopy(fixture.source['stages'][0]['participant'])
                    if self.headers.get('X-Agent-API-Key') == KEY_B:
                        value['actor_id'] = 'wrong-actor'
                elif route.path.startswith('/records'):
                    cursor = parse_qs(route.query).get('cursor', [None])[0]
                    first = cursor is None
                    value = {'items': [{'id': 'r1', 'text': 'First'}, {'id': 'r2', 'text': 'Second'}] if first else [{'id': 'r3', 'text': 'Third'}],
                             'next_cursor': 'upstream-page-2' if first else None, 'snapshot_id': 'snapshot-1'}
                    if fixture.mode == 'empty-pages':
                        value['items'] = []
                        value['next_cursor'] = 'next-' + str(len(fixture.requests))
                    if fixture.mode == 'cyclic-pages':
                        value['next_cursor'] = 'upstream-page-2'
                    if fixture.mode == 'canary':
                        value['items'][0]['text'] = 'echo=' + KEY_A
                    if fixture.mode == 'large-projection':
                        value['items'] = [{'id': 'r1', 'text': 'x' * 1000}] * 10
                    if fixture.mode == 'root-array':
                        value = value['items']
                else:
                    payload = json.loads(content)
                    if fixture.mode == 'informational':
                        self.wfile.write(b'HTTP/1.1 100 Continue\r\n\r\n'); self.wfile.flush()
                    fixture.effects.append(payload)
                    if fixture.mode == 'upgrade':
                        self.wfile.write(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
                        self.wfile.flush()
                        return
                    value = {'actor_id': fixture.source['stages'][0]['participant']['actor_id'],
                             'target_id': payload['target_id'], 'artifact_sha256': payload['artifact_sha256'],
                             'publication_id': 'server-publication-1', 'state': 'published'}
                    if fixture.mode == 'disconnect':
                        self.connection.shutdown(socket.SHUT_RDWR)
                        self.connection.close()
                        return
                    if fixture.mode == 'wrong-publication':
                        value['actor_id'] = 'wrong-actor'
                status = 500 if fixture.mode == 'http-failure' else 302 if fixture.mode == 'redirect' else 200
                body = c.canonical(value)
                if fixture.mode == 'invalid-json':
                    body = b'{"duplicate":1,"duplicate":2}'
                if fixture.mode == 'oversize':
                    body = b'x' * 1048577
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                if fixture.mode == 'redirect':
                    self.send_header('Location', 'http://127.0.0.1:' + str(self.server.server_port) + '/foreign')
                if fixture.mode == 'canary':
                    self.send_header('Set-Cookie', 'auth=' + KEY_A)
                    self.send_header('X-Refresh-Token', KEY_A)
                self.end_headers()
                try:
                    if fixture.mode == 'trickle':
                        for byte in body:
                            self.wfile.write(bytes([byte])); self.wfile.flush(); time.sleep(0.1)
                    else:
                        self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            do_GET = dispatch
            do_POST = dispatch
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
        self.thread.start()
        self.source, self.compiler_kwargs = compiler_fixtures.inputs()
        self.source['application']['origins']['fixture']['url'] = 'http://fixture.invalid:' + str(self.server.server_port)
        self.source['application']['origins']['fixture']['allowed_addresses'] = ['127.0.0.1']
        self.build()

    def tearDown(self):
        if self.client is not None:
            self.client.close()
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2)
        self.temp.cleanup()

    def verifier(self, grant, scope, call_id, tool, arguments):
        expected = self.grants.pop(grant, None)
        return expected == (scope, call_id, tool, arguments)

    def build(self):
        if self.client is not None:
            self.client.close()
        self.plan = compiler.compile_plan(self.source, **self.compiler_kwargs)
        stage = self.plan['stages'][0]
        self.scope = {key: str(uuid.uuid4()) for key in service.BINDING_FIELDS - {'plan_sha256', 'trial_id'}}
        self.scope.update(trial_id=None, plan_sha256=self.plan['plan_sha256'], stage_name=stage['id'],
            participant=stage['participant'], operation_ids=stage['operations'], credential_aliases=stage['credential_aliases'],
            authority_generation=str(uuid.uuid4()))
        self.bearer = secrets.token_hex(32)
        authorities = {alias: KEY_A if alias == 'persona' else KEY_B for alias in stage['credential_aliases']}
        configuration = {'schema': 1, 'document_type': 'application_client_private_bootstrap',
            'mode': 'authority-only', 'plan': self.plan, 'authorities': {stage['id']: authorities},
            'capabilities': [{'token': self.bearer, 'scope': self.scope}], 'control_token': secrets.token_hex(32),
            'evidence_root': str(self.evidence),
            'code_identity': {name: hashlib.sha256((ROOT / 'skill' / name).read_bytes()).hexdigest() for name in service.TRUSTED_CODE}}
        self.authority = service.CapabilityService(configuration)
        self.configuration = configuration
        self.client = api.APIClient(self.authority, self.evidence, self.artifacts,
                                   clock=lambda: self.time, budget_verifier=self.verifier)

    def call(self, operation='identity', *, arguments=None, call_id=None, cursor=None, body=None, query=None):
        call_id = call_id or 'call_' + uuid.uuid4().hex
        arguments = arguments if arguments is not None else {'operation_id': operation, 'path_params': {}, 'query': query or {}, 'body': body, 'cursor': cursor}
        grant = secrets.token_hex(32)
        self.grants[grant] = (copy.deepcopy(self.scope), call_id, 'app_api', copy.deepcopy(arguments))
        return self.client.execute(self.bearer, self.scope, call_id, arguments, grant)

    def publication_body(self):
        return {'target_id': 'team-summary', 'artifact_id': 'summary',
                'artifact_sha256': hashlib.sha256((self.artifacts / 'outputs/summary.md').read_bytes()).hexdigest()}

    def read_receipt(self, receipt_id):
        item = self.client.receipt_index(self.scope)[receipt_id]
        body = (self.evidence / item['path']).read_bytes()
        self.assertEqual(hashlib.sha256(body).hexdigest(), item['sha256'])
        return c.validate_receipt(c.loads(body))

    def test_identity_two_pages_publication_complete_without_hidden_requests(self):
        identity = self.call()
        first = self.call('list-records')
        self.assertTrue(first['ok'])
        self.assertNotIn('upstream-page-2', json.dumps(first))
        second = self.call('list-records', cursor=first['pagination']['cursor'])
        self.assertEqual(second['pagination']['state'], 'exhausted')
        publication = self.call('publish-summary', body=self.publication_body())
        self.assertTrue(publication['ok'])
        self.assertEqual(len(self.requests), 4)
        self.assertEqual(len(self.effects), 1)
        self.assertTrue(all(item['pending'] for item in self.intent_observations))
        self.assertTrue(self.intent_observations[-1]['writes'])
        self.assertEqual(self.effects[0]['content'], self.content)
        self.assertIn('cursor=upstream-page-2', self.requests[2]['path'])
        receipts = [self.read_receipt(result['receipt_id']) for result in (identity, first, second, publication)]
        report = {'schema': 1, 'document_type': 'application_completion_report', 'contract_id': 'participant-report',
            'participant': self.scope['participant'], 'artifacts': [{'id': 'summary', 'path': 'outputs/summary.md',
                'sha256': self.publication_body()['artifact_sha256'], 'bytes': len(self.content.encode())}],
            'pagination': {'list-records': [first['receipt_id'], second['receipt_id']]},
            'publications': [{'id': 'summary-publication', 'receipt_id': publication['receipt_id']}], 'unresolved': []}
        (self.artifacts / 'outputs/completion.json').write_bytes(c.canonical(report))
        result = completion_contract.evaluate(self.plan['stages'][0]['completion'], report_root=self.artifacts,
            evidence_root=self.evidence, receipts=self.client.receipt_index(self.scope), binding=receipts[0]['binding'], writers_confirmed=True)
        self.assertEqual(result['status'], 'complete', result)

    def test_declared_root_array_response_returns_selected_results_and_receipt(self):
        operation = next(row for row in self.source['application']['operations'] if row['id'] == 'list-records')
        operation['response_schema'] = copy.deepcopy(operation['response_schema']['properties']['items'])
        operation.update(pagination=None, result_fields=['/0/id', '/1/text'])
        self.source['stages'][0]['completion']['pagination'] = []
        self.build(); self.mode = 'root-array'
        self.assertTrue(self.call()['ok'])
        result = self.call('list-records')
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['data'], [{'id': 'r1'}, {'text': 'Second'}])
        self.assertEqual(self.read_receipt(result['receipt_id'])['outcome'], 'succeeded')
        self.assertEqual(len(self.requests), 2)

    def test_missing_or_rejected_budget_proof_has_zero_network_effects(self):
        arguments = {'operation_id': 'identity', 'path_params': {}, 'query': {}, 'body': None, 'cursor': None}
        self.assertEqual(self.client.execute(self.bearer, self.scope, 'call_A', arguments)['reason'], 'accounting_unavailable')
        self.assertEqual(self.client.execute(self.bearer, self.scope, 'call_B', arguments, '0' * 64)['reason'], 'accounting_unavailable')
        self.client.budget_verifier = None
        self.assertEqual(self.call()['reason'], 'accounting_unavailable')
        self.assertEqual(self.requests, [])

    def test_secret_canary_native_call_identity_is_neither_persisted_nor_fingerprinted(self):
        before = {str(p): p.read_bytes() for p in self.evidence.rglob('*') if p.is_file()}
        for operation in ('identity', 'unknown'):
            result = self.call(operation, call_id=KEY_A)
            self.assertFalse(result['ok'])
            self.assertEqual(result['reason'], 'request_invalid')
        result = self.call(arguments={'operation_id': 'identity', 'path_params': {}, 'query': {}, 'body': {'secret': KEY_A}, 'cursor': None})
        self.assertEqual(result['reason'], 'request_invalid')
        self.assertEqual(self.requests, [])
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.evidence.rglob('*') if p.is_file()})
        for path in self.evidence.rglob('*'):
            if path.is_file():
                body = path.read_bytes()
                self.assertNotIn(KEY_A.encode(), body)
                self.assertNotIn(json.dumps(KEY_A)[1:-1].encode(), body)

    def test_typed_unknown_and_injected_fields_send_zero_requests(self):
        base = {'operation_id': 'identity', 'path_params': {}, 'query': {}, 'body': None, 'cursor': None}
        variants = [dict(base, operation_id='unknown'), dict(base, method='POST'), dict(base, headers={'Authorization': 'x'}),
                    dict(base, url='http://foreign.invalid'), dict(base, body={}), dict(base, query={'cursor': 'upstream'}),
                    dict(base, path_params={'id': '../escape'}), dict(base, cursor='raw-upstream')]
        for arguments in variants:
            with self.subTest(fields=list(arguments)):
                self.assertFalse(self.call(arguments=arguments)['ok'])
        self.assertEqual(self.requests, [])

    def test_wrong_scope_capability_native_replay_and_transport_are_denied(self):
        arguments = {'operation_id': 'identity', 'path_params': {}, 'query': {}, 'body': None, 'cursor': None}
        result = self.client.execute('0' * 64, self.scope, 'call_X', arguments, 'f' * 64)
        self.assertFalse(result['ok']); self.assertEqual(len(self.requests), 0)
        wrong_scope = copy.deepcopy(self.scope); wrong_scope['participant']['actor_id'] = 'other-actor'
        result = self.client.execute(self.bearer, wrong_scope, 'call_X', arguments, 'f' * 64)
        self.assertFalse(result['ok']); self.assertEqual(len(self.requests), 0)
        self.assertTrue(self.call(call_id='call_ABC-123')['ok'])
        self.assertFalse(self.call(call_id='call_ABC-123')['ok'])
        self.assertEqual(len(self.requests), 1)

    def test_api_entrypoint_cannot_execute_browser_only_descriptors(self):
        self.client.close(); self.client = None
        self.source['application']['operations'][1]['transport'] = 'browser'
        self.build()
        result = self.call('list-records')
        self.assertEqual(result['reason'], 'operation_not_granted')
        self.assertEqual(self.requests, [])

    def test_business_read_and_publication_require_explicit_identity(self):
        self.assertEqual(self.call('list-records')['reason'], 'identity_unverified')
        self.assertEqual(self.call('publish-summary', body=self.publication_body())['reason'], 'identity_unverified')
        self.assertEqual(self.requests, [])

    def test_each_alias_needs_its_own_identity_and_wrong_actor_never_unlocks(self):
        self.client.close(); self.client = None
        for name, effect in [('identity-other', 'identity'), ('records-other', 'read')]:
            original = copy.deepcopy(self.source['application']['operations'][0 if effect == 'identity' else 1])
            original.update(id=name, credential_alias='other')
            self.source['application']['operations'].append(original)
            self.source['stages'][0]['operations'].append(name)
        self.source['application']['credentials']['other'] = 'DIAGNOSTIC_BOB'
        self.source['stages'][0]['credential_aliases'].append('other')
        self.build()
        self.assertTrue(self.call()['ok'])
        self.assertEqual(self.call('records-other')['reason'], 'identity_unverified')
        failed = self.call('identity-other')
        self.assertEqual(failed['outcome'], 'failed')
        self.assertEqual(failed['reason'], 'participant_mismatch')
        self.assertNotIn('wrong-actor', json.dumps(failed))
        self.assertEqual(self.read_receipt(failed['receipt_id'])['http_status'], 200)
        self.assertEqual(self.call('records-other')['reason'], 'identity_unverified')
        self.assertEqual([r['path'] for r in self.requests], ['/identity', '/identity'])

    def test_redirect_never_receives_a_second_authenticated_request(self):
        self.mode = 'redirect'
        result = self.call()
        self.assertEqual(result['outcome'], 'failed')
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.requests[0]['path'], '/identity')

    def test_connect_uses_frozen_first_ip_without_hostname_resolution(self):
        with patch.object(socket, 'getaddrinfo', side_effect=AssertionError('ambient DNS forbidden')):
            self.assertTrue(self.call()['ok'])
        self.assertEqual(self.requests[0]['host'], 'fixture.invalid:' + str(self.server.server_port))

    def test_first_pinned_address_failure_never_falls_back_to_a_second_address(self):
        self.client.close(); self.client = None
        self.source['application']['origins']['fixture']['allowed_addresses'] = ['127.0.0.2', '127.0.0.1']
        self.source['application']['operations'][0]['max_request_seconds'] = 1
        self.build()
        self.assertFalse(self.call()['ok'])
        self.assertEqual(self.requests, [])

    def test_canonical_path_parameters_deny_traversal_and_encode_unicode_once(self):
        self.client.close(); self.client = None
        op = self.source['application']['operations'][1]
        op['path_template'] = '/records/{record_id}'
        op['path_params_schema'] = {'type': 'object', 'properties': {'record_id': {'type': 'string', 'minLength': 1, 'maxLength': 128}},
                                    'required': ['record_id'], 'additionalProperties': False}
        self.build(); self.call()
        arguments = {'operation_id': 'list-records', 'path_params': {}, 'query': {}, 'body': None, 'cursor': None}
        for value in ('..', '.', '../escape', '%2e%2e', 'a/b', 'a\\b', 'a?url=foreign', 'a#fragment'):
            arguments['path_params'] = {'record_id': value}
            self.assertFalse(self.call(arguments=arguments)['ok'])
        self.assertEqual(len(self.requests), 1)
        arguments['path_params'] = {'record_id': 'résumé id'}
        self.assertTrue(self.call(arguments=arguments)['ok'])
        self.assertIn('/records/r%C3%A9sum%C3%A9%20id', self.requests[-1]['path'])

    def test_publication_hash_target_and_body_schema_fail_before_send(self):
        self.call()
        base = self.publication_body()
        for body in [dict(base, target_id='different'), dict(base, artifact_sha256='0' * 64),
                     dict(base, artifact_id='other'), dict(base, content='invented')]:
            self.assertFalse(self.call('publish-summary', body=body)['ok'])
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.effects, [])
        self.assertTrue(self.call('publish-summary', body=base)['ok'])
        self.assertEqual(len(self.effects), 1)

    def test_final_constructed_wire_schema_is_checked_before_publication(self):
        self.client.close(); self.client = None
        self.source['application']['operations'][2]['wire_body_schema']['properties']['content']['maxLength'] = 1
        self.build(); self.call()
        self.assertFalse(self.call('publish-summary', body=self.publication_body())['ok'])
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.effects, [])
        (self.artifacts / 'outputs/summary.md').write_text('x')
        self.assertTrue(self.call('publish-summary', body=self.publication_body())['ok'])
        self.assertEqual(self.effects[0]['content'], 'x')

    def test_commit_response_lost_blocks_all_business_and_survives_recreation(self):
        self.call(); self.mode = 'disconnect'
        result = self.call('publish-summary', body=self.publication_body())
        self.assertEqual(result['outcome'], 'outcome_unknown')
        self.assertEqual(len(self.effects), 1)
        self.assertEqual(self.read_receipt(result['receipt_id'])['outcome'], 'outcome_unknown')
        self.assertFalse(self.call('publish-summary', body=self.publication_body())['ok'])
        self.client.close()
        self.client = api.APIClient(self.authority, self.evidence, self.artifacts, clock=lambda: self.time, budget_verifier=self.verifier)
        self.assertFalse(self.call('publish-summary', body=self.publication_body())['ok'])
        self.assertFalse(self.call('list-records')['ok'])
        self.assertEqual(len(self.effects), 1)

    def test_definitive_http_failure_still_consumes_write_grant(self):
        self.call(); self.mode = 'http-failure'
        result = self.call('publish-summary', body=self.publication_body())
        self.assertEqual(result['outcome'], 'failed')
        self.mode = 'normal'
        self.assertFalse(self.call('publish-summary', body=self.publication_body())['ok'])
        self.assertEqual(len(self.effects), 1)

    def test_success_publication_snapshot_survives_later_artifact_edit(self):
        self.call()
        result = self.call('publish-summary', body=self.publication_body())
        original = self.effects[0]['content']
        (self.artifacts / 'outputs/summary.md').write_text('changed later')
        snapshot = self.evidence / ('snapshots/' + result['receipt_id'] + '.txt')
        self.assertEqual(snapshot.read_text(), original)
        self.assertFalse(self.call('publish-summary', body=self.publication_body())['ok'])
        self.assertEqual(len(self.effects), 1)

    def test_wrong_publication_attestation_is_unknown_without_replay(self):
        self.call(); self.mode = 'wrong-publication'
        result = self.call('publish-summary', body=self.publication_body())
        self.assertEqual(result['outcome'], 'outcome_unknown')
        self.assertEqual(len(self.effects), 1)

    def test_informational_status_never_claims_definitive_write_failure_or_retries(self):
        self.call(); self.mode = 'informational'
        result = self.call('publish-summary', body=self.publication_body())
        self.assertEqual(result['outcome'], 'outcome_unknown')
        self.assertFalse(self.call('publish-summary', body=self.publication_body())['ok'])
        self.assertEqual(len(self.effects), 1)
        self.assertEqual(len(self.requests), 2)

    def test_protocol_upgrade_is_unknown_for_transmitted_write(self):
        self.call(); self.mode = 'upgrade'
        result = self.call('publish-summary', body=self.publication_body())
        self.assertEqual(result['outcome'], 'outcome_unknown')
        self.assertEqual(self.read_receipt(result['receipt_id'])['http_status'], 101)
        self.assertEqual(len(self.effects), 1)

    def test_explicit_authorized_segment_reuses_native_id_and_page_chain_with_filtered_index(self):
        self.client.close(); self.client = None
        original_scope = copy.deepcopy(self.scope)
        next_scope = copy.deepcopy(self.scope)
        next_scope['segment_id'] = str(uuid.uuid4())
        next_bearer = secrets.token_hex(32)
        configuration = copy.deepcopy(self.configuration)
        configuration['capabilities'].append({'token': next_bearer, 'scope': next_scope})
        self.authority = service.CapabilityService(configuration)
        self.client = api.APIClient(self.authority, self.evidence, self.artifacts, clock=lambda: self.time, budget_verifier=self.verifier)
        self.call(call_id='call_reused')
        first = self.call('list-records')
        old_index = self.client.receipt_index(original_scope)
        self.scope, self.bearer = next_scope, next_bearer
        self.assertTrue(self.call(call_id='call_reused')['ok'])
        second = self.call('list-records', cursor=first['pagination']['cursor'])
        self.assertTrue(second['ok'])
        current = self.client.receipt_index(self.scope)
        self.assertFalse(set(current) & set(old_index))
        combined = self.client.receipt_index(self.scope, allowed_segment_ids=[original_scope['segment_id'], self.scope['segment_id']])
        self.assertEqual(set(combined), set(current) | set(old_index))

    def test_cursor_repeated_tampered_and_expired_requests_are_zero_effect(self):
        self.call(); first = self.call('list-records'); cursor = first['pagination']['cursor']
        before = len(self.requests)
        self.assertEqual(self.call('list-records', cursor='0' * 64)['reason'], 'cursor_invalid')
        self.assertEqual(len(self.requests), before)
        self.assertTrue(self.call('list-records', cursor=cursor)['ok'])
        before = len(self.requests)
        self.assertEqual(self.call('list-records', cursor=cursor)['reason'], 'cursor_invalid')
        self.assertEqual(len(self.requests), before)

    def test_expired_cursor_and_reserved_cursor_injection_reject_before_send(self):
        self.call(); first = self.call('list-records'); before = len(self.requests)
        self.time += 121
        self.assertEqual(self.call('list-records', cursor=first['pagination']['cursor'])['reason'], 'cursor_invalid')
        self.assertFalse(self.call('list-records', query={'cursor': 'upstream-page-2'})['ok'])
        self.assertEqual(len(self.requests), before)

    def test_cursor_cannot_change_operation_or_canonical_query(self):
        self.client.close(); self.client = None
        operation = self.source['application']['operations'][1]
        operation['query_schema']['properties']['filter'] = {'type': 'string', 'maxLength': 32}
        alternative = copy.deepcopy(operation); alternative['id'] = 'list-alternative'
        self.source['application']['operations'].append(alternative)
        self.source['stages'][0]['operations'].append(alternative['id'])
        self.build(); self.call()
        first = self.call('list-records', query={'filter': 'one'})
        cursor = first['pagination']['cursor']; before = len(self.requests)
        self.assertEqual(self.call('list-alternative', query={'filter': 'one'}, cursor=cursor)['reason'], 'cursor_invalid')
        self.assertEqual(self.call('list-records', query={'filter': 'two'}, cursor=cursor)['reason'], 'cursor_invalid')
        self.assertEqual(len(self.requests), before)
        self.assertTrue(self.call('list-records', query={'filter': 'one'}, cursor=cursor)['ok'])

    def test_item_cap_with_remaining_data_is_truncated(self):
        self.client.close(); self.client = None
        self.source['application']['operations'][1]['pagination']['max_items'] = 2
        self.build(); self.call()
        result = self.call('list-records')
        self.assertEqual(result['pagination']['state'], 'truncated')
        self.assertEqual(result['pagination']['reason'], 'item_limit')
        self.assertIsNone(result['pagination']['cursor'])

    def test_byte_cap_cannot_issue_a_cursor_that_cannot_send_its_next_request(self):
        self.client.close(); self.client = None
        self.source['application']['operations'][1]['pagination']['max_total_bytes'] = 500
        self.build(); self.call()
        result = self.call('list-records')
        self.assertEqual(result['pagination']['state'], 'truncated')
        self.assertEqual(result['pagination']['reason'], 'byte_limit')
        self.assertIsNone(result['pagination']['cursor'])

    def test_page_and_item_caps_return_truncated_even_for_empty_pages(self):
        self.client.close(); self.client = None
        self.source['application']['operations'][1]['pagination']['max_pages'] = 1
        self.build(); self.call(); self.mode = 'empty-pages'
        result = self.call('list-records')
        self.assertEqual(result['pagination']['state'], 'truncated')
        self.assertEqual(result['pagination']['reason'], 'page_limit')
        self.assertIsNone(result['pagination']['cursor'])
        before = len(self.requests)
        self.assertEqual(self.call('list-records')['reason'], 'pagination_limit')
        self.assertEqual(len(self.requests), before)

    def test_cyclic_server_token_never_produces_a_reusable_helper_cursor(self):
        self.call(); self.mode = 'cyclic-pages'
        first = self.call('list-records')
        second = self.call('list-records', cursor=first['pagination']['cursor'])
        self.assertEqual(second['pagination']['state'], 'truncated')
        self.assertEqual(second['pagination']['reason'], 'cursor_cycle')
        self.assertIsNone(second['pagination']['cursor'])

    def test_credentials_cookies_and_upstream_tokens_are_withheld_from_model_projection(self):
        self.call(); self.mode = 'canary'
        result = self.call('list-records')
        self.assertTrue(result['ok'])
        self.assertNotIn(KEY_A, json.dumps(result))
        self.assertNotIn('upstream-page-2', json.dumps(result))
        for path in self.evidence.rglob('*'):
            if path.is_file():
                body = path.read_bytes()
                self.assertNotIn(KEY_A.encode(), body)
                self.assertNotIn(json.dumps(KEY_A)[1:-1].encode(), body)
        receipt = self.read_receipt(result['receipt_id'])
        response = (self.evidence / receipt['evidence'][1]['path']).read_bytes()
        self.assertIn(b'Set-Cookie: [REDACTED]', response)
        self.assertIn(b'X-Refresh-Token: [REDACTED]', response)
        self.assertIn(b'upstream-page-2', response)

    def test_projection_limit_is_explicit_and_raw_response_is_retained(self):
        self.client.close(); self.client = None
        self.source['application']['operations'][1]['pagination']['max_items'] = 100
        self.build()
        self.call(); self.mode = 'large-projection'
        result = self.call('list-records')
        self.assertFalse(result['ok'])
        self.assertEqual(result['reason'], 'evidence_unavailable')
        self.assertEqual(result['detail'], 'projection_limit')
        self.assertLessEqual(len(c.canonical(result)), 8192)
        receipt = self.read_receipt(result['receipt_id'])
        self.assertEqual(receipt['outcome'], 'succeeded')
        self.assertGreater(receipt['evidence'][1]['bytes'], 8192)

    def test_response_oversize_invalid_json_and_hard_deadline_do_not_retry(self):
        self.call()
        for mode in ('oversize', 'invalid-json'):
            with self.subTest(mode=mode):
                self.mode = mode; before = len(self.requests)
                result = self.call('list-records')
                self.assertFalse(result['ok'])
                self.assertEqual(result['outcome'], 'failed')
                self.assertEqual(len(self.requests), before + 1)
        self.mode = 'trickle'
        # Descriptor remains immutable in production; construct a fresh reviewed
        # one-second plan for this deadline oracle.
        self.client.close(); self.client = None
        self.source['application']['operations'][1]['max_request_seconds'] = 1
        self.build(); self.mode = 'normal'; self.call(); self.mode = 'trickle'
        start = time.monotonic(); before = len(self.requests)
        result = self.call('list-records')
        self.assertLess(time.monotonic() - start, 2.5)
        self.assertEqual(result['outcome'], 'failed')
        self.assertEqual(len(self.requests), before + 1)

    def test_evidence_capacity_or_persistence_failure_precedes_any_application_request(self):
        with patch.object(self.client.evidence, 'reserve', side_effect=api.EvidenceError('evidence_limit')):
            self.assertFalse(self.call()['ok'])
        self.assertEqual(self.requests, [])
        with patch.object(self.client.evidence, 'put', side_effect=api.EvidenceError()):
            self.assertFalse(self.call()['ok'])
        self.assertEqual(self.requests, [])

    def test_post_send_evidence_failure_is_unknown_and_cannot_replay(self):
        self.call()
        with patch.object(self.client.evidence, 'seal', side_effect=api.EvidenceError()):
            result = self.call('publish-summary', body=self.publication_body())
        self.assertFalse(result['ok'])
        self.assertEqual(result['outcome'], 'outcome_unknown')
        self.assertTrue(self.client.quarantined)
        self.assertEqual(len(self.effects), 1)
        self.client.close()
        self.client = api.APIClient(self.authority, self.evidence, self.artifacts, clock=lambda: self.time, budget_verifier=self.verifier)
        self.assertFalse(self.call('publish-summary', body=self.publication_body())['ok'])
        self.assertEqual(len(self.effects), 1)

    def test_atomic_state_replace_then_directory_fsync_failure_keeps_restart_fenced(self):
        self.call()
        original_replace, original_fsync = os.replace, os.fsync
        failed_after_clear = False
        def replace(source, target, *args, **kwargs):
            nonlocal failed_after_clear
            result = original_replace(source, target, *args, **kwargs)
            if target == 'state.json':
                state = c.loads((self.evidence / 'state.json').read_bytes(), max_bytes=8388608)
                if state['writes'] and not state['pending']:
                    failed_after_clear = True
            return result
        def fsync(fd):
            if failed_after_clear and stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError('injected directory fsync failure')
            return original_fsync(fd)
        with patch.object(os, 'replace', side_effect=replace), patch.object(os, 'fsync', side_effect=fsync):
            result = self.call('publish-summary', body=self.publication_body())
        self.assertTrue(failed_after_clear)
        self.assertEqual(result['outcome'], 'outcome_unknown')
        self.assertEqual(len(self.effects), 1)
        self.client.close()
        self.client = api.APIClient(self.authority, self.evidence, self.artifacts, clock=lambda: self.time, budget_verifier=self.verifier)
        self.assertTrue(self.client.quarantined)
        self.assertFalse(self.call('list-records')['ok'])
        self.assertFalse(self.call('publish-summary', body=self.publication_body())['ok'])
        self.assertEqual(len(self.effects), 1)

    def test_even_confirmed_successful_write_requires_fresh_preparation_after_helper_restart(self):
        self.call()
        self.assertTrue(self.call('publish-summary', body=self.publication_body())['ok'])
        self.client.close()
        self.client = api.APIClient(self.authority, self.evidence, self.artifacts, clock=lambda: self.time, budget_verifier=self.verifier)
        self.assertTrue(self.client.quarantined)
        before = len(self.requests)
        self.assertFalse(self.call('list-records')['ok'])
        self.assertEqual(len(self.requests), before)

    def test_nested_state_corruption_cannot_erase_consumed_write_or_native_call_evidence(self):
        self.call()
        self.assertTrue(self.call('publish-summary', body=self.publication_body())['ok'])
        self.client.close(); self.client = None
        state_path = self.evidence / 'state.json'
        original = state_path.read_bytes()
        before = len(self.requests)
        for field in ('writes', 'calls', 'stages'):
            with self.subTest(field=field):
                corrupted = c.loads(original, max_bytes=8388608)
                corrupted[field] = {}
                state_path.write_bytes(c.canonical(corrupted))
                with self.assertRaises(api.EvidenceError):
                    api.APIClient(self.authority, self.evidence, self.artifacts, clock=lambda: self.time, budget_verifier=self.verifier)
                self.assertEqual(len(self.requests), before)
                state_path.write_bytes(original)
        state_path.unlink()
        with self.assertRaises(api.EvidenceError):
            api.APIClient(self.authority, self.evidence, self.artifacts, clock=lambda: self.time, budget_verifier=self.verifier)
        self.assertEqual(len(self.requests), before)

    def test_publication_artifact_symlink_is_denied_without_consuming_grant(self):
        self.call()
        path = self.artifacts / 'outputs/summary.md'
        secret = self.root / 'private-file'; secret.write_text('private')
        path.unlink(); path.symlink_to(secret)
        body = {'target_id': 'team-summary', 'artifact_id': 'summary', 'artifact_sha256': hashlib.sha256(b'private').hexdigest()}
        self.assertFalse(self.call('publish-summary', body=body)['ok'])
        self.assertEqual(len(self.requests), 1)
        path.unlink(); path.write_text(self.content)
        self.assertTrue(self.call('publish-summary', body=self.publication_body())['ok'])
        self.assertEqual(len(self.effects), 1)


if __name__ == '__main__':
    unittest.main()
