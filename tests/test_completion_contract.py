"""Local filesystem and explicit HTTP evidence for independent completion gates."""
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from http.client import HTTPConnection, RemoteDisconnected
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
import uuid
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'skill/scripts'))
import application_contracts as c
import completion_contract as completion

FIXTURE = json.loads((ROOT / 'tests/fixtures/application-contracts/completion.json').read_text())


class CompletionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.outputs = self.base / 'outputs'
        self.evidence = self.base / 'private'
        self.outputs.mkdir(mode=0o700)
        self.evidence.mkdir(mode=0o700)
        self.contract = copy.deepcopy(FIXTURE['completion'])
        self.binding = copy.deepcopy(FIXTURE['binding'])
        self.report = copy.deepcopy(FIXTURE['report'])
        self.documents = copy.deepcopy(FIXTURE['receipts'])
        for relative, content in FIXTURE['stored_artifacts'].items():
            self.write(self.outputs / relative, content.encode())
        for relative, content in FIXTURE['stored_evidence'].items():
            self.write(self.evidence / relative, content.encode())
        self.index = {}
        self.store_report()
        self.store_receipts()

    def tearDown(self):
        self.temp.cleanup()

    def write(self, path, body):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)

    def store_report(self):
        self.write(self.outputs / self.contract['report_path'], c.canonical(self.report))

    def store_receipts(self):
        self.index = {}
        for receipt in self.documents:
            body = c.canonical(receipt)
            path = 'receipts/' + receipt['receipt_id'] + '.json'
            self.write(self.evidence / path, body)
            self.index[receipt['receipt_id']] = {'path': path, 'sha256': hashlib.sha256(body).hexdigest()}

    def evaluate(self, **overrides):
        values = dict(report_root=self.outputs, evidence_root=self.evidence,
                      receipts=self.index, binding=self.binding, writers_confirmed=True)
        values.update(overrides)
        return completion.evaluate(self.contract, **values)

    def codes(self, result):
        return [item['code'] for item in result['diagnostics']]

    def test_valid_fixture_is_complete_and_read_only(self):
        before = {str(path): path.read_bytes() for path in self.base.rglob('*') if path.is_file()}
        self.assertEqual(self.evaluate(), FIXTURE['expected_completion'])
        self.assertEqual(before, {str(path): path.read_bytes() for path in self.base.rglob('*') if path.is_file()})

    def test_explicit_parent_segment_lineage_accepts_prior_receipts_without_resetting_write_grants(self):
        first=self.binding['segment_id'];second=str(uuid.uuid4())
        self.binding['segment_id']=second
        self.documents[-1]['binding']['segment_id']=second
        self.store_receipts()
        self.assertEqual(self.evaluate()['status'],'invalid')
        self.assertEqual(self.evaluate(authorized_segment_ids=[first,second])['status'],'complete')
        self.documents[-1]['binding']['attempt_id']=str(uuid.uuid4());self.store_receipts()
        self.assertEqual(self.evaluate(authorized_segment_ids=[first,second])['status'],'invalid')

    def test_parent_segment_lineage_rejects_duplicate_non_uuid_or_wrong_current_binding(self):
        segment=self.binding['segment_id']
        for values in ([],[segment,segment],['not-a-uuid',segment],[str(uuid.uuid4())]):
            with self.subTest(values=values),self.assertRaises(c.ContractError):
                self.evaluate(authorized_segment_ids=values)

    def test_same_native_call_id_is_scoped_to_approved_segment_and_write_fence_remains_stage_wide(self):
        first=self.binding['segment_id'];second=str(uuid.uuid4());self.binding['segment_id']=second
        self.documents[-1]['binding']['segment_id']=second
        self.documents[-1]['native_call_id']=self.documents[0]['native_call_id']
        self.store_receipts()
        self.assertEqual(self.evaluate(authorized_segment_ids=[first,second])['status'],'complete')

    def test_normally_settled_missing_report_is_incomplete(self):
        (self.outputs / self.contract['report_path']).unlink()
        result = self.evaluate()
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual(self.codes(result), ['report_missing'])
        self.assertFalse((self.outputs / self.contract['report_path']).exists())

    def test_missing_or_malformed_report_diagnoses_independent_missing_requirements(self):
        for malformed in (False, True):
            with self.subTest(malformed=malformed):
                path = self.outputs / self.contract['report_path']
                if malformed:
                    path.write_bytes(b'{"schema":1,"schema":1}')
                else:
                    path.unlink(missing_ok=True)
                (self.outputs / 'outputs/summary.md').unlink(missing_ok=True)
                self.index = {}
                result = self.evaluate()
                self.assertIn('report_malformed' if malformed else 'report_missing', self.codes(result))
                self.assertIn('artifact_missing', self.codes(result))
                self.assertIn('pagination_incomplete', self.codes(result))
                self.assertIn('publication_missing', self.codes(result))

    def test_unknown_writers_never_open_a_file(self):
        with patch.object(completion.os, 'open', side_effect=AssertionError('unexpected file read')):
            result = self.evaluate(writers_confirmed=False)
        self.assertEqual(result['status'], 'not_evaluated')
        self.assertEqual(self.codes(result), ['writers_unconfirmed'])

    def test_wrong_actor_tenant_and_role_are_exact(self):
        for field in ('actor_id', 'tenant_id', 'role'):
            with self.subTest(field=field):
                self.report = copy.deepcopy(FIXTURE['report'])
                self.report['participant'][field] += '-other'
                self.store_report()
                result = self.evaluate()
                self.assertEqual(result['status'], 'invalid')
                self.assertIn('participant_mismatch', self.codes(result))
                diagnostic = next(d for d in result['diagnostics'] if d['code'] == 'participant_mismatch')
                self.assertEqual(diagnostic['observed'], {'mismatched_fields': [field]})
                self.assertNotIn(self.report['participant'][field], json.dumps(result))

    def test_missing_service_identity_cannot_be_replaced_by_report_tuple(self):
        del self.index['receipt-1']
        result = self.evaluate()
        self.assertEqual(result['status'], 'incomplete')
        self.assertTrue(any(d['code'] == 'receipt_missing' and d['pointer'] == '/participant'
                            for d in result['diagnostics']))

    def test_identity_for_another_alias_does_not_authorize_business_receipt(self):
        self.documents[-1]['request']['credential_alias'] = 'other-alias'
        self.store_receipts()
        result = self.evaluate()
        self.assertEqual(result['status'], 'incomplete')
        self.assertTrue(any(d['code'] == 'receipt_missing' and
                            d['expected'].get('credential_alias') == 'other-alias'
                            for d in result['diagnostics'] if type(d['expected']) is dict))

    def test_identity_after_business_is_invalid_even_with_exact_participant(self):
        self.documents[0]['sequence'] = 5
        self.store_receipts()
        result = self.evaluate()
        self.assertEqual(result['status'], 'invalid')
        self.assertTrue(any(d['code'] == 'participant_mismatch' and
                            d['observed'] == {'mismatched_fields': ['identity_sequence']}
                            for d in result['diagnostics']))

    def test_protocol_failed_identity_http200_is_retained_without_identity_proof(self):
        receipt = self.documents[0]
        receipt.update(outcome='failed', reason='identity_response_invalid', http_status=200)
        self.assertEqual(c.validate_receipt(receipt), receipt)
        self.store_receipts()
        result = self.evaluate()
        self.assertEqual(result['status'], 'incomplete')
        self.assertIn('receipt_missing', self.codes(result))
        self.assertNotIn('receipt_integrity_failed', self.codes(result))

    def test_service_rejected_exact_identity_is_invalid_without_echoing_observed_actor(self):
        self.documents[0].update(outcome='failed', reason='participant_mismatch', http_status=200)
        self.store_receipts()
        result = self.evaluate()
        self.assertEqual(result['status'], 'invalid')
        self.assertIn('participant_mismatch', self.codes(result))
        self.assertNotIn('receipt_integrity_failed', self.codes(result))

    def test_protocol_failed_read_http200_does_not_prove_page_coverage(self):
        receipt = self.documents[2]
        receipt.update(outcome='failed', reason='response_schema_invalid', http_status=200, pagination=None)
        self.assertEqual(c.validate_receipt(receipt), receipt)
        self.store_receipts()
        result = self.evaluate()
        self.assertNotEqual(result['status'], 'complete')
        self.assertIn('pagination_incomplete', self.codes(result))
        self.assertNotIn('receipt_integrity_failed', self.codes(result))

    def test_protocol_write_http200_validation_failure_is_unknown_never_definitively_failed(self):
        for effect in ('mutation', 'publication'):
            with self.subTest(effect=effect):
                receipt = copy.deepcopy(self.documents[-1])
                receipt.update(effect=effect, outcome='failed', reason='response_schema_invalid',
                               http_status=200, publication=None)
                with self.assertRaises(c.ContractError) as error:
                    c.validate_receipt(receipt)
                self.assertEqual(error.exception.pointer, '/http_status')
                receipt['outcome'] = 'outcome_unknown'
                self.assertEqual(c.validate_receipt(receipt), receipt)
                receipt.update(outcome='failed', http_status=None)
                with self.assertRaises(c.ContractError) as error:
                    c.validate_receipt(receipt)
                self.assertEqual(error.exception.pointer, '/outcome')

    def test_manifest_hash_path_and_byte_count(self):
        for field, value, code in [('sha256', '0' * 64, 'artifact_hash_mismatch'),
                                   ('bytes', 1, 'artifact_hash_mismatch'),
                                   ('path', 'outputs/other.md', 'artifact_path_unsafe')]:
            with self.subTest(field=field):
                self.report = copy.deepcopy(FIXTURE['report'])
                self.report['artifacts'][0][field] = value
                self.store_report()
                result = self.evaluate()
                self.assertEqual(result['status'], 'invalid')
                self.assertIn(code, self.codes(result))

    def test_stale_publication_hash_after_artifact_edit(self):
        (self.outputs / 'outputs/summary.md').write_text('changed content')
        result = self.evaluate()
        self.assertIn('artifact_hash_mismatch', self.codes(result))
        self.assertIn('publication_binding_mismatch', self.codes(result))

    def test_oversize_and_non_utf8_artifacts(self):
        for content in (b'x' * 4097, b'\xff'):
            with self.subTest(content_length=len(content)):
                (self.outputs / 'outputs/summary.md').write_bytes(content)
                result = self.evaluate()
                self.assertEqual(result['status'], 'invalid')
                self.assertIn('report_malformed', self.codes(result))

    def test_json_artifacts_parse_strictly_and_unsupported_media_fails_admission(self):
        self.contract['artifacts'][0]['media_type'] = 'application/json'
        self.binding['report_contract_sha256'] = c.digest(self.contract)
        (self.outputs / 'outputs/summary.md').write_bytes(b'{"x":1,"x":2}')
        self.assertIn('report_malformed', self.codes(self.evaluate()))
        self.contract['artifacts'][0]['media_type'] = 'image/png'
        with self.assertRaises(c.ContractError):
            self.evaluate()

    def test_report_contract_mismatch_unresolved_and_undeclared(self):
        self.report['contract_id'] = 'wrong-contract'
        self.report['unresolved'] = ['unfinished']
        self.report['artifacts'].append({'id': 'extra', 'path': 'outputs/extra.md', 'sha256': '0' * 64, 'bytes': 0})
        self.store_report()
        result = self.evaluate()
        self.assertEqual(result['status'], 'invalid')
        self.assertIn('report_unresolved', self.codes(result))
        self.assertIn('report_malformed', self.codes(result))

    def test_missing_receipt_and_missing_raw_evidence(self):
        for path in ('receipts/receipt-4.json', 'evidence/0004/response.txt'):
            with self.subTest(path=path):
                original = (self.evidence / path).read_bytes()
                (self.evidence / path).unlink()
                result = self.evaluate()
                self.assertEqual(result['status'], 'incomplete')
                self.assertIn('receipt_missing', self.codes(result))
                self.write(self.evidence / path, original)

    def test_tampered_receipt_and_raw_evidence(self):
        for path in ('receipts/receipt-4.json', 'evidence/0004/response.txt'):
            with self.subTest(path=path):
                original = (self.evidence / path).read_bytes()
                (self.evidence / path).write_bytes(original + b' ')
                result = self.evaluate()
                self.assertEqual(result['status'], 'invalid')
                self.assertIn('receipt_integrity_failed', self.codes(result))
                self.write(self.evidence / path, original)

    def test_cross_attempt_profile_and_participant_receipts(self):
        for field in ('attempt_id', 'profile_sha256', 'participant'):
            with self.subTest(field=field):
                self.documents = copy.deepcopy(FIXTURE['receipts'])
                if field == 'participant':
                    self.documents[-1]['participant']['actor_id'] = 'wrong-actor'
                else:
                    self.documents[-1]['binding'][field] = '9' * 64 if 'sha256' in field else '99999999-9999-4999-8999-999999999999'
                self.store_receipts()
                result = self.evaluate()
                self.assertEqual(result['status'], 'invalid')
                self.assertIn('participant_mismatch' if field == 'participant' else 'receipt_integrity_failed', self.codes(result))

    def test_forged_child_receipt_dictionaries_are_never_authority(self):
        child = {item['receipt_id']: item for item in self.documents}
        result = self.evaluate(receipts=child)
        self.assertEqual(result['status'], 'invalid')
        self.assertIn('receipt_integrity_failed', self.codes(result))

    def test_duplicate_receipt_call_sequence_instance_and_report_refs(self):
        for field in ('native_call_id', 'sequence', 'operation_instance_id'):
            with self.subTest(field=field):
                self.documents = copy.deepcopy(FIXTURE['receipts'])
                self.documents[-1][field] = self.documents[0][field]
                self.store_receipts()
                self.assertIn('receipt_duplicate', self.codes(self.evaluate()))
        self.report['pagination']['list-records'].append('receipt-3')
        self.store_report()
        self.assertIn('report_malformed', self.codes(self.evaluate()))

    def test_wrong_publication_target_payload_operation_state(self):
        for field in ('target_id', 'artifact_sha256', 'operation_id', 'state'):
            with self.subTest(field=field):
                self.documents = copy.deepcopy(FIXTURE['receipts'])
                receipt = self.documents[-1]
                if field == 'operation_id':
                    receipt[field] = 'other-publication'
                else:
                    receipt['publication'][field] = '0' * 64 if field == 'artifact_sha256' else 'different'
                self.store_receipts()
                result = self.evaluate()
                self.assertEqual(result['status'], 'invalid')
                self.assertTrue({'publication_binding_mismatch', 'receipt_integrity_failed'} & set(self.codes(result)))

    def test_duplicate_publication_effect_never_completes(self):
        duplicate = copy.deepcopy(self.documents[-1])
        duplicate.update(receipt_id='receipt-5', native_call_id='call-5', operation_instance_id='operation-5', sequence=5)
        self.documents.append(duplicate)
        self.store_receipts()
        result = self.evaluate()
        self.assertEqual(result['status'], 'invalid')
        self.assertIn('receipt_duplicate', self.codes(result))

    def test_definitively_failed_write_cannot_be_reissued_with_fresh_call_identity(self):
        failed = copy.deepcopy(self.documents[-1])
        failed.update(receipt_id='receipt-5', native_call_id='call-5', operation_instance_id='operation-5',
                      sequence=5, outcome='failed', reason='http_failure', http_status=500, publication=None)
        self.documents.append(failed)
        self.store_receipts()
        result = self.evaluate()
        self.assertEqual(result['status'], 'invalid')
        self.assertIn('receipt_duplicate', self.codes(result))

    def test_private_index_digest_does_not_override_receipt_identity(self):
        self.documents[-1]['receipt_id'] = 'forged-id'
        self.store_receipts()
        reference = self.index.pop('forged-id')
        self.index['receipt-4'] = reference
        self.assertIn('receipt_integrity_failed', self.codes(self.evaluate()))

    def test_parent_index_iteration_order_does_not_change_verdict(self):
        (self.outputs / self.contract['report_path']).unlink()
        result = self.evaluate()
        self.assertEqual(result, self.evaluate(receipts=dict(reversed(list(self.index.items())))))

    def test_browser_network_receipts_share_only_one_bounded_action_call(self):
        self.documents[0].update(transport='browser', action_id='action-1')
        self.documents[1].update(transport='browser', action_id='action-1', native_call_id='call-1')
        self.store_receipts()
        self.assertEqual(self.evaluate()['status'], 'complete')
        for mutation in ('api-mix', 'different-action', 'same-operation', 'different-call'):
            with self.subTest(mutation=mutation):
                documents = copy.deepcopy(self.documents)
                if mutation == 'api-mix':
                    documents[1].update(transport='api', action_id=None)
                if mutation == 'different-action':
                    documents[1]['action_id'] = 'action-2'
                if mutation == 'same-operation':
                    documents[2].update(transport='browser', action_id='action-1', native_call_id='call-1')
                if mutation == 'different-call':
                    documents[1]['native_call_id'] = 'call-other'
                original = self.documents
                self.documents = documents
                self.store_receipts()
                result = self.evaluate()
                self.assertEqual(result['status'], 'invalid')
                self.assertIn('receipt_duplicate', self.codes(result))
                self.documents = original

    def test_pagination_requires_unbroken_exhausted_chain(self):
        for mutation in ('missing-last', 'truncated', 'wrong-snapshot', 'wrong-order'):
            with self.subTest(mutation=mutation):
                self.report = copy.deepcopy(FIXTURE['report'])
                self.documents = copy.deepcopy(FIXTURE['receipts'])
                if mutation == 'missing-last':
                    self.report['pagination']['list-records'].pop()
                if mutation == 'wrong-order':
                    self.report['pagination']['list-records'].reverse()
                if mutation == 'truncated':
                    self.documents[2]['pagination'].update(state='truncated', reason='page_limit')
                if mutation == 'wrong-snapshot':
                    self.documents[2]['pagination']['snapshot_id'] = 'other-snapshot'
                self.store_report()
                self.store_receipts()
                result = self.evaluate()
                self.assertNotEqual(result['status'], 'complete')
                self.assertIn('pagination_incomplete', self.codes(result))

    def test_missing_first_page_is_incomplete_not_a_forged_chain(self):
        del self.index['receipt-2']
        result = self.evaluate()
        self.assertEqual(result['status'], 'incomplete')
        self.assertIn('pagination_incomplete', self.codes(result))

    def test_missing_report_can_diagnose_complete_chain_despite_unused_new_read_chain(self):
        extra = copy.deepcopy(self.documents[1])
        extra.update(receipt_id='receipt-5', native_call_id='call-5', operation_instance_id='operation-5', sequence=5)
        extra['pagination']['chain_id'] = 'unused-chain'
        for evidence in extra['evidence']:
            old_path = evidence['path']
            evidence['path'] = old_path.replace('/0002/', '/0005/')
            self.write(self.evidence / evidence['path'], (self.evidence / old_path).read_bytes())
        self.documents.append(extra)
        self.store_receipts()
        (self.outputs / self.contract['report_path']).unlink()
        result = self.evaluate()
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual(self.codes(result), ['report_missing'])

    def test_symlink_hardlink_fifo_and_escaping_artifacts(self):
        artifact = self.outputs / 'outputs/summary.md'
        secret = self.base / 'secret'
        secret.write_text('private')
        for mode in ('symlink', 'hardlink', 'fifo'):
            with self.subTest(mode=mode):
                artifact.unlink()
                if mode == 'symlink':
                    artifact.symlink_to(secret)
                if mode == 'hardlink':
                    os.link(secret, artifact)
                if mode == 'fifo':
                    os.mkfifo(artifact)
                result = self.evaluate()
                self.assertEqual(result['status'], 'invalid')
                self.assertIn('artifact_path_unsafe', self.codes(result))
        self.contract['artifacts'][0]['path'] = '../secret'
        with self.assertRaises(c.ContractError):
            self.evaluate()

    def test_symlink_report_and_root_ancestor_are_rejected(self):
        report = self.outputs / self.contract['report_path']
        report.unlink()
        report.symlink_to(self.evidence / 'receipts/receipt-1.json')
        self.assertIn('report_malformed', self.codes(self.evaluate()))
        alias = self.base / 'alias'
        alias.symlink_to(self.outputs, target_is_directory=True)
        result = self.evaluate(report_root=alias)
        self.assertEqual(result['status'], 'invalid')
        self.assertIn('artifact_path_unsafe', self.codes(result))

    def test_evidence_private_root_and_symlink_reject(self):
        self.evidence.chmod(0o755)
        result = self.evaluate()
        self.assertEqual(result['status'], 'not_evaluated')
        self.evidence.chmod(0o700)
        path = self.evidence / 'receipts/receipt-4.json'
        path.unlink()
        path.symlink_to(self.outputs / self.contract['report_path'])
        self.assertIn('receipt_integrity_failed', self.codes(self.evaluate()))

    def test_overlapping_roots_are_not_evaluated(self):
        self.assertEqual(self.evaluate(evidence_root=self.outputs)['status'], 'not_evaluated')

    def test_open_directory_fds_defeat_ancestor_replacement(self):
        root = completion._directory(self.outputs)
        original_open = completion.os.open
        original = self.outputs / 'outputs'
        foreign = self.base / 'foreign'
        foreign.mkdir()
        (foreign / 'summary.md').write_text('secret replacement')
        swapped = False
        def replacing_open(path, flags, *args, **kwargs):
            nonlocal swapped
            fd = original_open(path, flags, *args, **kwargs)
            if path == 'outputs' and flags & os.O_DIRECTORY and not swapped:
                original.rename(self.outputs / 'retained')
                original.symlink_to(foreign, target_is_directory=True)
                swapped = True
            return fd
        try:
            with patch.object(completion.os, 'open', side_effect=replacing_open):
                data = completion._read(root, 'outputs/summary.md', 4096)
            self.assertEqual(data.decode(), FIXTURE['stored_artifacts']['outputs/summary.md'])
            self.assertNotIn(b'secret replacement', data)
        finally:
            os.close(root)

    def test_report_binding_must_match_contract(self):
        self.binding['report_contract_sha256'] = '0' * 64
        with self.assertRaises(c.ContractError):
            self.evaluate()

    def test_diagnostic_cap_and_stable_order(self):
        self.contract['artifacts'] = [dict(id='item-' + str(i), path='outputs/item-' + str(i), media_type='text/plain', max_bytes=10) for i in range(64)]
        self.contract['publications'] = [dict(id='pub-' + str(i), operation_id='publish-' + str(i), artifact_id='item-' + str(i), target_id='target-' + str(i), required_state='published') for i in range(64)]
        self.contract['pagination'] = [dict(operation_id='page-' + str(i), require_exhausted=True) for i in range(64)]
        self.binding['report_contract_sha256'] = c.digest(self.contract)
        (self.outputs / self.contract['report_path']).unlink()
        self.index = {}
        result = self.evaluate()
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual(len(result['diagnostics']), 100)
        self.assertTrue(result['diagnostics_truncated'])
        self.assertEqual(self.codes(result)[:2], ['report_missing', 'artifact_missing'])
        self.assertEqual(result, self.evaluate())

    def test_committed_response_lost_local_service_is_unknown_and_never_replayed(self):
        effects = []
        observed_requests = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers['Content-Length']))
                effects.append(body)
                observed_requests.append((self.requestline + '\r\n' + str(self.headers) + '\r\n').encode() + body)
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
            def log_message(self, *args):
                pass
        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        connection = HTTPConnection('127.0.0.1', server.server_port, timeout=2)
        try:
            payload = c.canonical({'target_id': 'team-summary', 'artifact_id': 'summary',
                                   'artifact_sha256': self.documents[-1]['publication']['artifact_sha256'],
                                   'content': FIXTURE['stored_artifacts']['outputs/summary.md']})
            connection.request('POST', '/publications', body=payload, headers={'Content-Type': 'application/json'})
            with self.assertRaises(RemoteDisconnected):
                connection.getresponse()
            self.assertEqual(len(effects), 1)
            self.assertEqual(effects[0], payload)
            self.documents[-1].update(outcome='outcome_unknown', reason='response_lost', http_status=None, publication=None)
            self.documents[-1]['evidence'] = self.documents[-1]['evidence'][:1]
            capture = observed_requests[0]
            request_evidence = self.documents[-1]['evidence'][0]
            request_evidence.update(sha256=hashlib.sha256(capture).hexdigest(), bytes=len(capture), redactions=[])
            self.write(self.evidence / request_evidence['path'], capture)
            self.store_receipts()
            result = self.evaluate()
            self.assertEqual(result['status'], 'incomplete')
            self.assertIn('publication_outcome_unknown', self.codes(result))
            self.assertEqual(len(effects), 1)
        finally:
            connection.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == '__main__':
    unittest.main()
