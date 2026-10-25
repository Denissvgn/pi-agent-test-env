"""Settlement diagnostics over the real coordinator and synthetic owned helper.

The existing fixture uses real contract, grant, ledger, context and cleanup code;
only Docker/Pi and helper transport are replaced. No qualification credit follows.
"""
import copy
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_execution as execution
import test_application_execution as fixture


class SettlementTests(unittest.TestCase):
    def prepared(self):
        case=fixture.ApplicationCoordinatorTests();case.setUp();self.addCleanup(case.doCleanups)
        coordinator=case.prepare();_,folder,_=case.begin(coordinator)
        coordinator.mark_running();coordinator.after_segment(True)
        return case,coordinator,folder

    def failed(self,coordinator,code,*,writers=True):
        with self.assertRaises(execution.ApplicationExecutionError) as caught:coordinator.close(writers)
        error=caught.exception
        self.assertEqual(error.args,('Application execution ownership or accounting unavailable',))
        self.assertEqual(execution.settlement_diagnostic(error,coordinator),{'schema':1,'code':code})
        self.assertEqual(execution.settlement_diagnostic(error),{'schema':1,'code':code})
        self.assertTrue(coordinator.failed)
        return error

    def finish_reply(self,helper,change):
        original=helper.control
        def control(body):
            reply=original(body)
            if body['action']=='finish':change(reply)
            return reply
        return mock.patch.object(helper,'control',side_effect=control)

    def test_success_is_unchanged_and_second_close_does_not_repeat_effects(self):
        case,co,folder=self.prepared();helper=case.helpers[0]
        with mock.patch.object(helper,'cleanup',wraps=helper.cleanup) as cleanup:
            first=co.close(True);second=co.close(True)
        self.assertEqual(first,second);self.assertEqual(cleanup.call_count,1)
        self.assertTrue(first['safe_to_continue']);self.assertEqual(first['status'],'removed')
        self.assertEqual(first['workspace'],'clean');self.assertEqual(first['budget']['accounting'],'available')
        self.assertFalse((folder/'application-context.json').exists())
        self.assertEqual(sum(row['action']=='finish' for row in helper.requests),1)
        self.assertEqual(co.reservation.state,'released')
        self.assertEqual(execution.settlement_diagnostic(coordinator=co),{'schema':1,'code':'UNKNOWN'})
        self.assertNotIn('_settlement_failure_code',vars(co))
        self.assertIs(execution.settlement_failure_recorded(co),False)

    def test_finish_transport_failure_keeps_first_code_through_failed_cleanup(self):
        case,co,folder=self.prepared();helper=case.helpers[0]
        with mock.patch.object(co,'_rpc',side_effect=ValueError('private-finish-canary')) as rpc, \
                mock.patch.object(helper,'cleanup',side_effect=OSError('private-cleanup-canary')) as cleanup:
            self.failed(co,'FINISH_RPC_FAILED')
        rpc.assert_called_once_with('finish',writers_confirmed=True)
        cleanup.assert_called_once_with(writers_absent=True)
        self.assertTrue((folder/'application-context.json').exists())
        self.assertFalse(co.pool.dependent_cleanup_confirmed)

    def test_finish_repetition_refuses_without_another_RPC_but_attempts_cleanup(self):
        case,co,folder=self.prepared();co._finish_attempted=True;helper=case.helpers[0]
        with mock.patch.object(co,'_rpc',wraps=co._rpc) as rpc, \
                mock.patch.object(helper,'cleanup',wraps=helper.cleanup) as cleanup:
            self.failed(co,'FINISH_ALREADY_ATTEMPTED')
        rpc.assert_not_called();cleanup.assert_called_once_with(writers_absent=True)
        self.assertTrue((folder/'application-context.json').exists())

    def test_invalid_finish_budget_is_not_replaced_by_secondary_receipt_failure(self):
        case,co,folder=self.prepared();helper=case.helpers[0]
        def corrupt(reply):reply['budget']['schema']=True
        with self.finish_reply(helper,corrupt),mock.patch.object(helper,'cleanup',return_value={'schema':True}):
            self.failed(co,'FINISH_BUDGET_INVALID')
        self.assertTrue((folder/'application-context.json').exists())

    def test_receipt_index_type_and_reference_guards_retain_their_category(self):
        for value in ([],{'receipt':{'path':'outside.json','sha256':'a'*64}},
                      {'receipt':{'path':'receipts/../private','sha256':'a'*64}},
                      {'receipt':{'path':'receipts/result.json','sha256':'not-a-hash'}}):
            with self.subTest(kind=type(value).__name__):
                case,co,folder=self.prepared();helper=case.helpers[0]
                with self.finish_reply(helper,lambda reply:reply.update(receipts=copy.deepcopy(value))):
                    self.failed(co,'RECEIPT_INDEX_INVALID')
                self.assertTrue((folder/'application-context.json').exists())

    def test_receipt_redaction_rejects_valid_shaped_private_value_without_export(self):
        case,co,_=self.prepared();helper=case.helpers[0];canary=co.authority._control_token
        def corrupt(reply):reply['receipts']={'receipt':{'path':'receipts/result.json','sha256':canary}}
        with self.finish_reply(helper,corrupt):error=self.failed(co,'RECEIPT_REDACTION_REJECTED')
        self.assertNotIn(canary,str(error));self.assertNotIn(canary,str(execution.settlement_diagnostic(error,co)))

    def test_completion_binding_failure_still_attempts_actual_helper_cleanup(self):
        case,co,folder=self.prepared();helper=case.helpers[0]
        with mock.patch.object(co,'_completion_binding',side_effect=KeyError('private-binding-canary')), \
                mock.patch.object(helper,'cleanup',wraps=helper.cleanup) as cleanup:
            self.failed(co,'COMPLETION_BINDING_INVALID')
        cleanup.assert_called_once_with(writers_absent=True)
        self.assertEqual(helper.record['status'],'released');self.assertTrue((folder/'application-context.json').exists())

    def test_redaction_state_failure_does_not_dispatch_cleanup_past_original_guard(self):
        case,co,_=self.prepared();helper=case.helpers[0];original=co.redaction_values;calls=[]
        def redaction():
            calls.append(True)
            if len(calls)==2:raise ValueError('private-state-canary')
            return original()
        with mock.patch.object(co,'redaction_values',side_effect=redaction), \
                mock.patch.object(helper,'cleanup',wraps=helper.cleanup) as cleanup:
            self.failed(co,'REDACTION_STATE_FAILED')
        cleanup.assert_not_called();self.assertEqual(helper.record['status'],'running')

    def test_helper_cleanup_exception_never_authorizes_context_purge(self):
        case,co,folder=self.prepared();helper=case.helpers[0]
        with mock.patch.object(helper,'cleanup',side_effect=OSError('private-path-canary')) as cleanup:
            self.failed(co,'HELPER_CLEANUP_FAILED')
        cleanup.assert_called_once_with(writers_absent=True)
        self.assertTrue((folder/'application-context.json').exists());self.assertFalse(co.closed)

    def test_startup_cleanup_registry_failure_has_a_closed_category(self):
        _,co,folder=self.prepared();co.helper=None
        with mock.patch.object(co.registry,'load',side_effect=ValueError('private-registry-canary')):
            self.failed(co,'STARTUP_CLEANUP_UNCONFIRMED')
        self.assertTrue((folder/'application-context.json').exists())

    def test_unknown_writers_win_over_secondary_helper_error_without_finish(self):
        case,co,folder=self.prepared();helper=case.helpers[0]
        with mock.patch.object(co,'_rpc',wraps=co._rpc) as rpc, \
                mock.patch.object(helper,'cleanup',side_effect=ValueError('secondary-private-canary')) as cleanup:
            self.failed(co,'WRITERS_UNCONFIRMED',writers=False)
        rpc.assert_not_called();cleanup.assert_called_once_with(writers_absent=False)
        self.assertTrue((folder/'application-context.json').exists())

    def test_unfinished_binding_is_not_converted_to_successful_cleanup(self):
        case,co,folder=self.prepared();co.binding=None;helper=case.helpers[0]
        with mock.patch.object(co,'_rpc',wraps=co._rpc) as rpc, \
                mock.patch.object(helper,'cleanup',wraps=helper.cleanup) as cleanup:
            self.failed(co,'FINISH_UNCONFIRMED')
        rpc.assert_not_called();cleanup.assert_called_once_with(writers_absent=True)
        self.assertTrue((folder/'application-context.json').exists())

    def test_known_physical_cleanup_cannot_replace_malformed_helper_receipt(self):
        case,co,folder=self.prepared();helper=case.helpers[0];original=helper.cleanup
        def cleanup(**kwargs):
            receipt=original(**kwargs);receipt['schema']=True;return receipt
        with mock.patch.object(helper,'cleanup',side_effect=cleanup):self.failed(co,'HELPER_RECEIPT_INVALID')
        self.assertEqual(helper.record['status'],'released');self.assertTrue((folder/'application-context.json').exists())

    def test_uncertain_context_remains_blocked_after_known_helper_cleanup(self):
        case,co,folder=self.prepared();co._uncertain_context=True
        self.failed(co,'CONTEXT_UNCONFIRMED')
        self.assertEqual(case.helpers[0].record['status'],'released')
        self.assertTrue((folder/'application-context.json').exists())

    def test_real_context_replacement_is_not_unlinked_or_called_clean(self):
        case,co,folder=self.prepared();path=folder/'application-context.json'
        path.rename(folder/'retained-original');path.write_text('synthetic-replacement')
        self.failed(co,'CONTEXT_PURGE_FAILED')
        self.assertEqual(path.read_text(),'synthetic-replacement');self.assertFalse(co.closed)
        self.assertEqual(case.helpers[0].record['status'],'released')

    def test_finish_control_exits_keep_same_instance_and_owned_cleanup(self):
        for error in (KeyboardInterrupt('private-cancel-canary'),SystemExit(17),GeneratorExit(),TimeoutError('private-time-canary')):
            with self.subTest(kind=type(error).__name__):
                case,co,folder=self.prepared();helper=case.helpers[0]
                with mock.patch.object(co,'_rpc',side_effect=error), \
                        mock.patch.object(helper,'cleanup',wraps=helper.cleanup) as cleanup:
                    with self.assertRaises(type(error)) as caught:co.close(True)
                self.assertIs(caught.exception,error);cleanup.assert_called_once_with(writers_absent=True)
                self.assertEqual(execution.settlement_diagnostic(error,co),{'schema':1,'code':'FINISH_RPC_FAILED'})
                self.assertTrue((folder/'application-context.json').exists())

    def test_optional_diagnostic_control_exit_is_not_swallowed_or_retried(self):
        case,co,folder=self.prepared();helper=case.helpers[0];error=KeyboardInterrupt('private-diagnostic-canary')
        with mock.patch.object(co,'_retain_file_diagnostic',side_effect=error), \
                mock.patch.object(helper,'cleanup',wraps=helper.cleanup) as cleanup:
            with self.assertRaises(KeyboardInterrupt) as caught:co.close(True)
        self.assertIs(caught.exception,error);cleanup.assert_called_once_with(writers_absent=True)
        self.assertEqual(execution.settlement_diagnostic(error,co),{'schema':1,'code':'FINISH_DIAGNOSTIC_FAILED'})
        self.assertEqual(sum(row['action']=='finish' for row in helper.requests),1)
        self.assertTrue((folder/'application-context.json').exists())

    def test_control_exit_during_cleanup_preserves_original_exception_boundaries(self):
        for error in (KeyboardInterrupt(),SystemExit(23),GeneratorExit()):
            with self.subTest(kind=type(error).__name__):
                case,co,_=self.prepared()
                with mock.patch.object(case.helpers[0],'cleanup',side_effect=error):
                    with self.assertRaises(type(error)) as caught:co.close(True)
                self.assertIs(caught.exception,error)
                self.assertEqual(execution.settlement_diagnostic(error,co),{'schema':1,'code':'HELPER_CLEANUP_FAILED'})
        case,co,_=self.prepared()
        with mock.patch.object(case.helpers[0],'cleanup',side_effect=TimeoutError('private-cleanup-time-canary')):
            self.failed(co,'HELPER_CLEANUP_FAILED')  # Existing OSError conversion stays intact.

    def test_primary_finish_control_is_not_masked_by_secondary_cleanup_control(self):
        case,co,_=self.prepared();primary=KeyboardInterrupt('first-private-canary');secondary=SystemExit(37)
        with mock.patch.object(co,'_rpc',side_effect=primary),mock.patch.object(case.helpers[0],'cleanup',side_effect=secondary):
            with self.assertRaises(KeyboardInterrupt) as caught:co.close(True)
        self.assertIs(caught.exception,primary)
        self.assertEqual(execution.settlement_diagnostic(primary,co),{'schema':1,'code':'FINISH_RPC_FAILED'})

    def test_first_code_survives_another_failed_close_without_RPC_retry(self):
        case,co,_=self.prepared();helper=case.helpers[0]
        with mock.patch.object(co,'_rpc',side_effect=ValueError('first-canary')) as rpc, \
                mock.patch.object(helper,'cleanup',side_effect=ValueError('secondary-canary')) as cleanup:
            self.failed(co,'FINISH_RPC_FAILED');self.failed(co,'FINISH_RPC_FAILED')
        self.assertEqual(rpc.call_count,1);self.assertEqual(cleanup.call_count,2)

    def test_mutable_public_factory_cannot_erase_a_genuine_coordinator_failure(self):
        _,co,_=self.prepared()
        with mock.patch.object(execution,'ApplicationCoordinator',new=mock.Mock(return_value=co)), \
                mock.patch.object(co,'_rpc',side_effect=ValueError('private-factory-canary')):
            error=self.failed(co,'FINISH_RPC_FAILED')
            self.assertEqual(execution.settlement_diagnostic(error,co)['code'],'FINISH_RPC_FAILED')

    def test_unknown_fallback_never_reads_received_exception_text_or_properties(self):
        class Hostile:
            def __getattribute__(self,name):raise AssertionError('Untrusted attributes must not be read')
            def __str__(self):raise AssertionError('Untrusted text must not be read')
        class OtherError(ValueError):
            def __str__(self):raise AssertionError('Untrusted exception text must not be read')
        for error,co in ((Hostile(),Hostile()),(OtherError('private-error-canary'),Hostile()),(None,None)):
            self.assertEqual(execution.settlement_diagnostic(error,co),{'schema':1,'code':'UNKNOWN'})
        class Subclass(execution.ApplicationExecutionError):pass
        self.assertEqual(execution.settlement_diagnostic(Subclass('FINISH_RPC_FAILED')),{'schema':1,'code':'UNKNOWN'})

    def test_typed_exception_only_accepts_closed_literals_and_preserves_default_message(self):
        for code in execution.SETTLEMENT_CODES:
            error=execution.ApplicationExecutionError(code)
            self.assertEqual(execution.settlement_diagnostic(error),{'schema':1,'code':code})
            self.assertEqual(str(error),'Application execution ownership or accounting unavailable')
        for value in (None,False,1,{},[],object(),'private-unknown-canary'):
            error=execution.ApplicationExecutionError(value)
            self.assertEqual(execution.settlement_diagnostic(error),{'schema':1,'code':'UNKNOWN'})
        error=execution.ApplicationExecutionError('FINISH_RPC_FAILED');error._settlement_code={'private-canary':'not-exported'}
        self.assertEqual(execution.settlement_diagnostic(error),{'schema':1,'code':'UNKNOWN'})

    def test_first_unknown_coordinator_code_is_not_overridden_by_an_unrelated_error(self):
        _,co,_=self.prepared();execution._remember_settlement(co,'unclassified-private-canary')
        error=execution.ApplicationExecutionError('HELPER_CLEANUP_FAILED')
        self.assertEqual(execution.settlement_diagnostic(error,co),{'schema':1,'code':'UNKNOWN'})
        self.assertIs(execution.settlement_failure_recorded(co),True)
        self.assertIs(execution.settlement_failure_recorded(None),False)
        self.assertIs(execution.settlement_failure_recorded(mock.Mock(_settlement_failure_code='FINISH_RPC_FAILED')),False)
        with mock.patch.object(execution,'ApplicationCoordinator',new=mock.Mock()):
            self.assertIs(execution.settlement_failure_recorded(co),True)


if __name__=='__main__':unittest.main()
