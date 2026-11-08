"""Lifecycle models do not observe a process or authorize an operation."""
import importlib
from unittest import TestCase
import uuid

from tests.test_operation_sdk_policy import example_policy, example_request, digest
from operation_sdk import policy, state
from operation_sdk.wire import SDKError


class SDKStateTests(TestCase):
    def admission(self):
        value = example_policy(); value['input']['source_id'] = str(uuid.uuid4())
        request = example_request(value)
        request.update(request_id=str(uuid.uuid4()), operation_id=str(uuid.uuid4()),
                       worker_id=str(uuid.uuid4()), channel_id=str(uuid.uuid4()))
        return policy.compile_admission(value, request, trusted_policy_sha256=digest(value), now_ns=100)

    def test_single_use_claim_requires_ready_and_context_before_private_read(self):
        admission = self.admission(); record = state.reserve(admission, 100)
        with self.assertRaises(SDKError): record.claim(100)
        with self.assertRaises(SDKError): record.ready('0' * 64)
        record.ready(admission.context_sha256); record.claim(100)
        with self.assertRaises(SDKError): record.claim(100)

    def test_expiry_never_extends_with_progress(self):
        admission = self.admission(); record = state.reserve(admission, 100)
        record.ready(admission.context_sha256)
        with self.assertRaises(SDKError): record.claim(admission.request()['expires_ns'])
        with self.assertRaises(SDKError): state.reserve(admission, 100)

    def test_same_operation_or_source_cannot_be_rebound_through_a_new_request(self):
        admission = self.admission(); state.reserve(admission, 100)
        with self.assertRaises(SDKError): state.reserve(admission, 100)
        value = admission.policy(); request = admission.request(); request['request_id'] = str(uuid.uuid4())
        second = policy.compile_admission(value, request, trusted_policy_sha256=digest(value), now_ns=100)
        with self.assertRaises(SDKError): state.reserve(second, 100)

    def test_failure_and_close_leave_a_tombstone_even_after_module_reload(self):
        admission = self.admission(); record = state.reserve(admission, 100); record.fail()
        importlib.reload(state)
        with self.assertRaises(SDKError): state.reserve(admission, 100)
        with self.assertRaises(SDKError): record.ready(admission.context_sha256)

    def test_complete_success_requires_each_observed_protocol_stage(self):
        admission = self.admission(); record = state.reserve(admission, 100)
        with self.assertRaises(SDKError): record.accept(100)
        record.ready(admission.context_sha256); record.claim(100); record.sent(); record.received(); record.accept(100)
        self.assertEqual(record.phase, 'accepted')
        self.assertNotIn(admission.request()['request_id'], repr(record))
        with self.assertRaises(SDKError): record.sent()

    def test_late_receiver_validation_cannot_accept_an_expired_operation(self):
        admission=self.admission();record=state.reserve(admission,100)
        record.ready(admission.context_sha256);record.claim(100);record.sent();record.received()
        with self.assertRaises(SDKError):record.accept(admission.request()['expires_ns'])
        self.assertNotEqual(record.phase,'accepted')
