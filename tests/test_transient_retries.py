import copy
import json
import re
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'skill/scripts'), str(ROOT / 'skill/runtime')]
import indexed_contract
import pi_contract
import pi_lab
import segments
from evidence import analyze


def endpoint(**extra):
    return {'base_url': 'http://127.0.0.1:8080/v1', 'model': 'test-model', 'context_window': 32768,
            'max_tokens': 1024, 'api_key_env': 'PI_API_KEY', **extra}


def retry_trace():
    """The reviewed diagnostic retry example, adapted to the Pi 1.2.0 settlement contract."""
    data = json.loads((ROOT / 'skill/references/pi-0.87.1.examples.json').read_text())
    records = copy.deepcopy(data['event_examples'][1]['records'])
    for event in records:
        for message in [event.get('message'), *event.get('messages', [])]:
            if isinstance(message, dict) and message.get('role') == 'assistant':
                message['model'] = 'test-model'
        if event['type'] == 'agent_settled':
            event['aborted'] = False
    return records


def analyze_records(records, **options):
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / 'stdout.jsonl'
        path.write_text(''.join(json.dumps(record) + '\n' for record in records))
        return analyze(path, 'test-model', [], 0, release='1.2.0', **options)


class PiConfigurationTests(unittest.TestCase):
    def test_default_keeps_every_pi_retry_disabled(self):
        unused, settings, unused_args, receipt = pi_contract.model_configuration(endpoint(), '1.2.0')
        self.assertEqual(settings['retry'], {'enabled': False, 'provider': {'maxRetries': 0}})
        self.assertNotIn('transient_retries', receipt)

    def test_opt_in_enables_traced_agent_retries_only(self):
        unused, settings, unused_args, receipt = pi_contract.model_configuration(endpoint(transient_retries=2), '1.2.0')
        self.assertEqual(settings['retry'], {'enabled': True, 'maxRetries': 2, 'baseDelayMs': 2000,
                                             'provider': {'maxRetries': 0}})
        self.assertEqual(settings['compaction'], {'enabled': False})
        self.assertEqual(receipt['transient_retries']['requested'], 2)
        self.assertEqual(receipt['transient_retries']['pi_configuration'], settings['retry'])

    def test_invalid_budgets_and_unreviewed_releases_are_rejected(self):
        for value in (True, -1, 4, 1.0, '1', None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                pi_contract.transient_retry_settings({'transient_retries': value})
        with self.assertRaisesRegex(ValueError, re.escape('Pi ' + ', '.join(pi_contract.TRANSIENT_RETRY_RELEASES) + ' only')):
            pi_contract.model_configuration(endpoint(transient_retries=1), '0.87.1')
        with self.assertRaises(ValueError):
            pi_contract.model_configuration(endpoint(transient_retries=1), None)
        self.assertEqual(pi_contract.transient_retry_settings({'transient_retries': 0}, '0.87.1'), 0)


class EndpointValidationTests(unittest.TestCase):
    def test_saved_endpoints_accept_a_bounded_budget(self):
        for value in (0, 1, 3):
            self.assertEqual(pi_lab.normalize_endpoint(endpoint(transient_retries=value))['transient_retries'], value)
        for value in (4, True, 'two'):
            with self.subTest(value=value), self.assertRaises(pi_lab.LabError):
                pi_lab.normalize_endpoint(endpoint(transient_retries=value))

    def test_indexed_bindings_reject_transient_retries(self):
        configuration = {'api': indexed_contract.API, 'adapter_contract': indexed_contract.ADAPTER,
                         'endpoint': {key: value for key, value in endpoint().items() if key != 'api_key_env'},
                         'credential': {'source': 'store', 'name': 'PI_API_KEY'}, 'capacity_group': 'retained-shared'}
        indexed_contract.configuration(copy.deepcopy(configuration), pi_lab.normalize_endpoint)
        configuration['endpoint']['transient_retries'] = 1
        with self.assertRaises(indexed_contract.IndexedError) as caught:
            indexed_contract.configuration(configuration, pi_lab.normalize_endpoint)
        self.assertEqual(caught.exception.reason, 'transient-retries-unsupported')


class RetryEvidenceTests(unittest.TestCase):
    def test_a_retry_within_the_endpoint_budget_is_clean_and_recorded(self):
        receipt = analyze_records(retry_trace(), provider_retries=3)
        self.assertTrue(receipt['agent_invocation_verified'], receipt['errors'])
        self.assertEqual(receipt['invocation_status'], 'verified')
        self.assertEqual(receipt['provider_retries'], {'allowed': 3, 'attempts': 1,
                                                       'retried_errors': ['Synthetic transient failure']})
        self.assertEqual(receipt['unsuccessful_messages'], ['error'])

    def test_retries_stay_policy_errors_without_an_opt_in(self):
        receipt = analyze_records(retry_trace())
        self.assertFalse(receipt['agent_invocation_verified'])
        self.assertIn('Retry disabled by invocation policy', receipt['policy_errors'])
        self.assertIn('Unsuccessful assistant messages retained', receipt['policy_errors'])
        self.assertEqual(receipt['provider_retries']['attempts'], 1)

    def test_pi_retrying_beyond_the_endpoint_budget_is_rejected(self):
        receipt = analyze_records(retry_trace(), provider_retries=2)
        self.assertFalse(receipt['completion_verified'])
        self.assertIn('Retry exceeds the endpoint transient_retries budget', receipt['policy_errors'])

    def test_exhausted_retries_and_unretried_errors_still_fail(self):
        records = retry_trace()
        end = next(record for record in records if record['type'] == 'auto_retry_end')
        end['success'] = False
        receipt = analyze_records(records, provider_retries=3)
        self.assertIn('Provider retries exhausted', receipt['policy_errors'])
        self.assertFalse(receipt['agent_invocation_verified'])


class AggregateTests(unittest.TestCase):
    def test_stage_evidence_sums_segment_retries(self):
        evidence = {'session_id': 's', 'identity_verified': True, 'agent_invocation_verified': True,
                    'successful_tools': {}, 'final_text': 'done',
                    'provider_retries': {'allowed': 2, 'attempts': 2, 'retried_errors': ['a', 'b']}}
        record = {'segment_id': 'one', 'ordinal': 1, 'session_id': 's', 'evidence': evidence,
                  'process': {'cleanup_confirmed': True}}
        result = segments.aggregate([record], 'test-model', [], set())
        self.assertEqual(result['invocation_status'], 'verified')
        self.assertEqual(result['provider_retries'], 2)


if __name__ == '__main__':
    unittest.main()
