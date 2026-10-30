"""Independent receiver checks reject altered private results and invented facts."""
import base64
import copy
import hashlib
import types
from unittest import TestCase

from tests.test_operation_sdk_policy import example_policy
from operation_sdk import client, collect, wire


class SDKReceiverTests(TestCase):
    def fixture(self, operation, data, rows=None, payload=None):
        p = example_policy(operation)
        p['scope']['resource'] = {'path': 'assets/policy.json', 'maximum_bytes': 16}
        p['deployment']['resources']['assets/policy.json'] = hashlib.sha256(b'policy').hexdigest()
        admitted = types.SimpleNamespace(operation=operation, context_sha256='a' * 64,
                                         policy=lambda: copy.deepcopy(p))
        session = client.Session(admitted, None)
        session._references = rows or []
        session._patterns = collect.Patterns([row['value'] for row in session._references], p['limits'])
        message = dict(schema=1, kind='result', context_sha256='a' * 64, operation=operation,
            status='ok', code=0, data=data, native=None, final_identity=None,
            facts=dict(handler_calls=1, reference_bindings_checked=len(session._references),
                       source_conserved=True, effect='none'))
        return session, message, payload

    def reject(self, session, message, payload=None):
        with self.assertRaises(wire.SDKError): session._validate(message, payload)

    def test_collection_is_exactly_bound_to_collected_aliases_and_inference(self):
        rows = [{'role': 'application', 'alias': 'PI_APP_KEY', 'value': 'fixture-application-value'},
                {'role': 'inference', 'alias': None, 'value': 'fixture-inference-value'}]
        data = dict(stage_id='prepare', participant_id='root', aliases={'PI_APP_KEY': rows[0]['value']},
                    inference_value=rows[1]['value'])
        session, message, _ = self.fixture('credentials_collect_v1', data, rows)
        session._validate(message, {})
        for key, value in [('stage_id', 'different'), ('participant_id', 'different'),
                           ('aliases', {'PI_APP_OTHER': rows[0]['value']}),
                           ('inference_value', 'different'), ('extra', True)]:
            altered = copy.deepcopy(message); altered['data'][key] = value
            with self.subTest(field=key): self.reject(session, altered, {})

    def test_resource_bytes_are_bounded_and_match_the_independent_policy_hash(self):
        data = dict(bytes_base64=base64.b64encode(b'policy').decode(), resource_sha256=hashlib.sha256(b'policy').hexdigest())
        session, message, _ = self.fixture('resource_read_v1', data)
        session._validate(message, None)
        for body in (b'changed', b'x' * 17):
            altered = copy.deepcopy(message); altered['data']['bytes_base64'] = base64.b64encode(body).decode()
            self.reject(session, altered)
        altered = copy.deepcopy(message); altered['data']['resource_sha256'] = 'f' * 64
        self.reject(session, altered)

    def test_noncanonical_base64_and_extra_output_fields_are_rejected(self):
        session, message, _ = self.fixture('resource_read_v1', {'bytes_base64': 'cG9saWN5',
            'resource_sha256': hashlib.sha256(b'policy').hexdigest()})
        for encoded in ('cG9saWN5====', 'cG9saWN5\n'):
            altered = copy.deepcopy(message); altered['data']['bytes_base64'] = encoded
            self.reject(session, altered)
        message['data']['extra'] = True
        self.reject(session, message)

    def test_typed_validation_must_preserve_the_submitted_document(self):
        original = {'schema': 1, 'private': 'same-input'}
        data = dict(normalized_plan=original, plan_sha256=hashlib.sha256(wire.encode(original, 4096)).hexdigest(),
            digest_domain='normalized_plan_utf8_v1', validation_only=True, profile_validated=False,
            project_contract_checked=False, scorer_frozen=False, dependencies_read=0)
        session, message, _ = self.fixture('plan_validate_source_v1', data)
        session._validate(message, {'plan': original})
        changed = {'schema': 1, 'private': 'replaced'}
        message['data'].update(normalized_plan=changed, plan_sha256=hashlib.sha256(wire.encode(changed, 4096)).hexdigest())
        self.reject(session, message, {'plan': original})

    def test_unchanged_typed_document_comparison_preserves_scalar_types(self):
        original={'schema':1,'private':1};changed={'schema':1,'private':True}
        data=dict(normalized_plan=changed,plan_sha256=hashlib.sha256(wire.encode(changed,4096)).hexdigest(),
            digest_domain='normalized_plan_utf8_v1',validation_only=True,profile_validated=False,
            project_contract_checked=False,scorer_frozen=False,dependencies_read=0)
        session,message,_=self.fixture('plan_validate_source_v1',data)
        self.reject(session,message,{'plan':original})

    def test_ordinary_operations_cannot_invent_native_effects_or_handler_coverage(self):
        data = dict(bytes_base64='cG9saWN5', resource_sha256=hashlib.sha256(b'policy').hexdigest())
        session, message, _ = self.fixture('resource_read_v1', data)
        for key, value in [('native', {}), ('final_identity', [1, 2])]:
            altered = copy.deepcopy(message); altered[key] = value
            self.reject(session, altered)
        for key, value in [('handler_calls', True), ('handler_calls', 0),
                           ('reference_bindings_checked', 1), ('effect', 'created')]:
            altered = copy.deepcopy(message); altered['facts'][key] = value
            self.reject(session, altered)

    def test_redaction_bounds_output_before_decoding_or_scanning(self):
        session, message, _ = self.fixture('redact_bytes_v1', {'bytes_base64': 'eA==' * 100,
                                                            'known_patterns_checked': True})
        # The actual body can expand by at most ten replacement bytes per input byte.
        self.reject(session, message, {'bytes_base64': 'eA=='})

    def test_redaction_preserves_unmatched_bytes_and_exact_replacement_relation(self):
        rows=[dict(role='redaction',alias=None,value='SECRET')]
        session,message,_=self.fixture('redact_bytes_v1',dict(bytes_base64='c2FmZTo8UkVEQUNURUQ+OmVuZA==',
                                                            known_patterns_checked=True),rows)
        payload={'bytes_base64':base64.b64encode(b'safe:SECRET:end').decode()}
        session._validate(message,payload)
        for changed in(b'',b'<REDACTED>',b'safe:<REDACTED>:changed'):
            altered=copy.deepcopy(message);altered['data']['bytes_base64']=base64.b64encode(changed).decode()
            with self.subTest(changed=changed):self.reject(session,altered,payload)
