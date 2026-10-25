"""Real parent settlement/credential orchestration, synthetic Pi and Docker only."""
import json
from unittest import mock
import unittest

import test_application_segment_integration as fixture

execution = fixture.application_execution


class SettlementIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.case = fixture.ApplicationSegmentTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.helper_type = fixture.fixture.HelperFixture
        self.original_control = self.helper_type.control
        self.original_cleanup = self.helper_type.cleanup
        self.finish_attempts = 0
        self.cleanup_attempts = 0

    def patch_finish(self, failure):
        def control(helper, body):
            if body['action'] == 'finish':
                self.finish_attempts += 1
                raise failure
            return self.original_control(helper, body)
        patch = mock.patch.object(self.helper_type, 'control', control)
        patch.start()
        self.addCleanup(patch.stop)

    def patch_cleanup(self, failure=None):
        def cleanup(helper, *, writers_absent):
            self.cleanup_attempts += 1
            if failure is not None:
                raise failure
            return self.original_cleanup(helper, writers_absent=writers_absent)
        patch = mock.patch.object(self.helper_type, 'cleanup', cleanup)
        patch.start()
        self.addCleanup(patch.stop)

    def assert_closed(self, result, code):
        self.assertEqual(result['application_settlement_failure'], {'schema': 1, 'code': code})
        self.assertEqual(set(result['application_settlement_failure']), {'schema', 'code'})
        self.assertIn(code, execution.SETTLEMENT_CODES)
        self.assertEqual(len(self.case.tasks), 1)
        self.assertEqual(self.finish_attempts, 1)
        self.assertEqual(self.cleanup_attempts, 1)

    def test_first_finish_failure_survives_downstream_credential_and_report_gates(self):
        self.patch_finish(ValueError('private-rpc-text-must-not-be-retained'))
        self.patch_cleanup()
        result = self.case.execute()
        self.assert_closed(result, 'FINISH_RPC_FAILED')
        self.assertEqual(result['termination_reason'], 'application_credential_cleanup')
        self.assertFalse(result['cleanup_confirmed'])
        self.assertEqual(result['exit_code'], 2)
        self.assertEqual(result['native_tool_budget_error'], 'cleanup_unconfirmed')
        self.assertEqual(result['application_credentials']['status'], 'cleanup_unconfirmed')
        self.assertEqual(result['application_completion']['status'], 'not_evaluated')
        self.assertIn('writers_unconfirmed', [row['code'] for row in result['application_completion']['diagnostics']])
        self.assertFalse(result['evidence']['agent_invocation_verified'])
        self.assertEqual(self.case.parent_result()['application_settlement_failure'], result['application_settlement_failure'])
        self.assertNotIn('private-rpc-text', json.dumps(result))

    def test_secondary_helper_failure_cannot_replace_first_finish_code(self):
        self.patch_finish(ValueError('private-first-failure'))
        self.patch_cleanup(ValueError('private-secondary-failure'))
        result = self.case.execute()
        self.assert_closed(result, 'FINISH_RPC_FAILED')
        self.assertFalse(result['cleanup_confirmed'])
        self.assertNotIn('private-first-failure', json.dumps(result))
        self.assertNotIn('private-secondary-failure', json.dumps(result))

    def test_successful_settlement_adds_no_failure_field_or_automatic_continuation(self):
        result = self.case.execute()
        self.assertNotIn('application_settlement_failure', result)
        self.assertNotIn('application_settlement_failure', self.case.parent_result())
        self.assertFalse(execution.settlement_failure_recorded(self.case.coordinators[0]))
        self.assertTrue(result['cleanup_confirmed'])
        self.assertEqual(result['application_credentials']['status'], 'removed')
        self.assertEqual(result['application_completion']['status'], 'incomplete')
        self.assertEqual(len(self.case.tasks), 1)

    def test_interrupt_identity_and_metadata_survive_parent_finalization(self):
        failure = KeyboardInterrupt('private-interrupt-text')
        self.patch_finish(failure)
        self.patch_cleanup()
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.case.execute()
        self.assertIs(caught.exception, failure)
        result = self.case.parent_result()
        self.assert_closed(result, 'FINISH_RPC_FAILED')
        self.assertEqual(result['application_completion']['status'], 'not_evaluated')
        self.assertNotIn('private-interrupt-text', json.dumps(result))

    def test_deadline_identity_and_metadata_survive_parent_finalization(self):
        failure = TimeoutError('private-deadline-text')
        self.patch_finish(failure)
        self.patch_cleanup()
        with self.assertRaises(TimeoutError) as caught:
            self.case.execute()
        self.assertIs(caught.exception, failure)
        result = self.case.parent_result()
        self.assert_closed(result, 'FINISH_RPC_FAILED')
        self.assertEqual(result['application_completion']['status'], 'not_evaluated')
        self.assertNotIn('private-deadline-text', json.dumps(result))

    def test_post_close_result_capture_failure_has_safe_unknown_code(self):
        # The settlement catch also surrounds result capture. A generic failure
        # there must not be misreported as a proven helper/RPC failure.
        class HostileError(ValueError):
            def __str__(self):
                raise AssertionError('Exception text must never be inspected')
            @property
            def settlement_code(self):
                raise AssertionError('Arbitrary exception attributes must never be inspected')
        with mock.patch.object(self.case.original_class, 'completion_context', new_callable=mock.PropertyMock,
                               side_effect=HostileError('private-capture-value')):
            result = self.case.execute()
        self.assertEqual(result['application_settlement_failure'], {'schema': 1, 'code': 'UNKNOWN'})
        self.assertFalse(result['cleanup_confirmed'])
        self.assertEqual(result['native_tool_budget_error'], 'cleanup_unconfirmed')
        self.assertNotIn('private-capture-value', json.dumps(result))
        self.assertEqual(len(self.case.tasks), 1)


if __name__ == '__main__':
    unittest.main()
