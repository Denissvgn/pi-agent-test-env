"""Closed readiness observations preserve the original admission boundary."""
import argparse
import json
from pathlib import Path
import sys
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_client as client
from test_application_client_authority import BaseFixture

CANARY='private-readiness-message-739110-secret'


class ReadinessConditionTests(unittest.TestCase):
    def exercise(self, chunks=(), *, events=True, error=None, deadline=10):
        process=argparse.Namespace(stdout=argparse.Namespace(fileno=lambda:23),_application_readiness_condition=CANARY)
        selector=mock.Mock();selector.select.return_value=[object()] if events else []
        reader=mock.Mock(side_effect=list(chunks))
        if error is not None:reader.side_effect=error
        with mock.patch.object(client.selectors,'DefaultSelector',return_value=selector),mock.patch.object(client.os,'set_blocking'),mock.patch.object(client.os,'read',reader),mock.patch.object(client.time,'monotonic',return_value=100):
            try:result=client._ready(process,deadline=deadline)
            except BaseException as caught:result=caught
        selector.close.assert_called_once_with()
        return process,selector,reader,result
    def test_timeout_uses_original_default_wait_and_does_not_read_or_retry(self):
        p,s,r,error=self.exercise(events=False)
        self.assertIsInstance(error,client.ClientError);self.assertEqual(error.reason,'evidence_unavailable')
        self.assertEqual(p._application_readiness_condition,'timeout');s.select.assert_called_once_with(10);r.assert_not_called()
    def test_eof_keeps_original_error_without_private_bytes_in_condition(self):
        p,s,r,error=self.exercise((CANARY.encode(),b''))
        self.assertIsInstance(error,client.ClientError);self.assertEqual(error.reason,'evidence_unavailable')
        self.assertEqual(p._application_readiness_condition,'eof');self.assertEqual(r.call_count,2)
        self.assertEqual(p._application_startup_stdout,CANARY.encode())
    def test_oversize_keeps_the_original_bounded_read_sequence(self):
        p,s,r,error=self.exercise((b'x'*4096,b'x'*4096,b'x'))
        self.assertIsInstance(error,client.ClientError);self.assertTrue(p._application_startup_output_unsafe)
        self.assertEqual(p._application_readiness_condition,'oversize')
        self.assertEqual(r.call_args_list,[mock.call(23,4096),mock.call(23,4096),mock.call(23,1)])
    def test_invalid_json_preserves_contract_exception_class(self):
        p,s,r,error=self.exercise((b'not json\n',))
        self.assertIsInstance(error,client.c.ContractError);self.assertEqual(p._application_readiness_condition,'invalid_json')
        self.assertEqual(r.call_count,1)
    def test_valid_but_unexpected_shape_preserves_admission_refusal(self):
        for body in (b'[]\n',b'{"status":"blocked"}\n',b'{"status":"ready","business_effects_enabled":true}\n'):
            with self.subTest(body=body):
                p,s,r,error=self.exercise((body,));self.assertIsInstance(error,client.ClientError)
                self.assertEqual(error.reason,'evidence_unavailable');self.assertEqual(p._application_readiness_condition,'unexpected_ready')
    def test_transport_and_interrupt_rethrow_the_exact_original_error(self):
        for error,condition in ((OSError(CANARY),'transport_unavailable'),(KeyboardInterrupt(CANARY),'interrupted')):
            with self.subTest(condition=condition):
                p,s,r,result=self.exercise(error=error);self.assertIs(result,error)
                self.assertEqual(p._application_readiness_condition,condition);self.assertEqual(r.call_count,1)
    def test_ready_reply_and_primary_result_are_unchanged(self):
        body=b'{"status":"ready","business_effects_enabled":false,"port":8081}\n'
        p,s,r,result=self.exercise((body,));self.assertEqual(result,json.loads(body));self.assertIsNone(p._application_readiness_condition)
        self.assertEqual(r.call_count,1);s.select.assert_called_once_with(10)


class ReadinessReceiptTests(BaseFixture):
    def diagnostic(self, condition, *, phase='service_readiness', raw=b''):
        authority,_=self.authority()
        helper=argparse.Namespace(authority=authority,process=argparse.Namespace(_application_readiness_condition=condition),
            reservations=[],_participant_reservation=None,name='pi-application-'+uuid.uuid4().hex[:16])
        with mock.patch.object(client,'_startup_output',return_value={'status':'withheld' if not raw else 'complete','stdout':raw,'stderr':b''}):
            result=client._startup_diagnostic(helper,phase,client.ClientError('evidence_unavailable',CANARY))
        return result,json.loads(Path(result['diagnostic']['path']).read_bytes())
    def test_closed_condition_survives_withheld_pipes_without_widening_parent_projection(self):
        for condition in sorted(client.READINESS_CONDITIONS):
            with self.subTest(condition=condition):
                result,payload=self.diagnostic(condition)
                self.assertEqual(payload['readiness_condition'],condition)
                self.assertEqual((payload['output_status'],payload['stdout'],payload['stderr']),('withheld','',''))
                self.assertEqual(set(result),{'schema','phase','reason','diagnostic'})
                self.assertEqual(client.validate_startup_failure(result,runroot=self.runroot),result)
                self.assertNotIn(CANARY,json.dumps(result)+json.dumps(payload))
    def test_forged_arbitrary_attribute_and_wrong_phase_are_never_persisted(self):
        for condition in (CANARY,True,{},type('Forged',(str,),{})(CANARY)):
            with self.subTest(kind=type(condition)):
                result,payload=self.diagnostic(condition);self.assertNotIn('readiness_condition',payload)
                self.assertNotIn(CANARY,json.dumps(result)+json.dumps(payload))
        _,payload=self.diagnostic('timeout',phase='container_observation');self.assertNotIn('readiness_condition',payload)
    def test_original_secret_screening_still_withholds_output_but_preserves_closed_enum(self):
        from test_application_client_authority import KEY_A
        result,payload=self.diagnostic('eof',raw=KEY_A.encode())
        self.assertEqual((payload['output_status'],payload['stdout'],payload['stderr']),('withheld','',''))
        self.assertEqual(payload['readiness_condition'],'eof');self.assertNotIn(KEY_A,json.dumps(payload)+json.dumps(result))


if __name__=='__main__':unittest.main()
