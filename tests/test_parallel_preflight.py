"""Admission deadline propagation; no Docker, Pi or external model invocation."""
import contextlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]/'skill'
sys.path[:0]=[str(ROOT/'runtime'),str(ROOT/'scripts')]
import inference_gateway
import outcomes
import pi_lab as lab
import worker
from test_parallel_contract import selected
from test_results import fixture,mocked_suite


class PreflightReached(Exception):pass


class DeadlineTests(unittest.TestCase):
    def test_parent_propagates_parallel_budget_and_preserves_serial_for_both_releases(self):
        for release in ('0.87.1','1.2.0'):
            for parallel in (False,True):
                with self.subTest(release=release,parallel=parallel),tempfile.TemporaryDirectory() as temp,contextlib.ExitStack() as stack:
                    root=Path(temp);args=fixture(root);mocked_suite(stack)
                    stack.enter_context(mock.patch.object(lab,'probe_image',return_value={'id':'fixture','capabilities':{'pi':release}}))
                    if parallel:
                        concurrency=selected();concurrency['gateway']['queue_wait_seconds']=180
                        args._experiment_root=root/'frozen';args._experiment_root.mkdir()
                        lab.save(args._experiment_root/'experiment.json',{'concurrency':concurrency})
                        args._parallel_session=types.SimpleNamespace(endpoint=lambda endpoint:{**endpoint,'host_base_url':endpoint['base_url']},bootstrap={'credentials':{}})
                    attempt=outcomes.Attempt(args);calls=[]
                    def stage(*pos,**kw):
                        if pos[4]=='preflight':calls.append((pos[5],kw['timeout']));raise PreflightReached
                        return {'exit_code':0,'cleanup_confirmed':True}
                    stack.enter_context(mock.patch.object(lab,'run_stage',side_effect=stage))
                    with self.assertRaises(PreflightReached):lab._execute_suite(args,attempt)
                    self.assertEqual(calls,[(['preflight','--request-timeout','360'],390)] if parallel else [(['preflight'],150)])
                    if parallel:
                        self.assertEqual(attempt.record['inference_admission']['preflight'],{'request_timeout_seconds':360,'container_timeout_seconds':390})

    def test_worker_applies_declared_timeout_and_rejects_unbounded_values_before_http(self):
        config={'base_url':'http://example.invalid/v1','model':'fixture-model','context_window':4096,'max_tokens':128}
        class Reply:
            def __enter__(self):return self
            def __exit__(self,*unused):pass
            def read(self,*unused):return json.dumps({'data':[{'id':'fixture-model'}]}).encode()
        with mock.patch.dict(os.environ,{'PI_LAB_API_KEY':'synthetic-only-key'}),mock.patch.object(worker,'build_opener') as opener,mock.patch.object(worker,'emit'):
            opener.return_value.open.return_value=Reply()
            for duration in (300,360,1200):
                opener.reset_mock();worker.preflight(config,request_timeout=duration)
                self.assertTrue(all(call.kwargs['timeout']==duration for call in opener.return_value.open.call_args_list))
            opener.reset_mock();worker.preflight(config)
            self.assertTrue(all(call.kwargs['timeout']==120 for call in opener.return_value.open.call_args_list))
            opener.reset_mock()
            for invalid in (0,1201,True,None):
                with self.subTest(timeout=invalid),self.assertRaises(ValueError):worker.preflight(config,request_timeout=invalid)
            opener.assert_not_called()

    def test_one_slot_waits_for_selected_queue_budget_then_expires_without_forwarding(self):
        for wait,elapsed,admitted,release in ((30,60,False,False),(30,60,False,True),(120,60,True,True),(120,120,False,True),(120,121,False,True),(180,150,True,True),(180,180,False,True),(180,181,False,True)):
            with self.subTest(wait=wait,elapsed=elapsed,release=release),contextlib.ExitStack() as stack:
                now=[0];gate=inference_gateway.Gate({'queue_wait_seconds':wait,'max_pending':2},clock=lambda:now[0])
                first,first_peer=socket.socketpair();second,second_peer=socket.socketpair()
                for sock in (first,first_peer,second,second_peer):stack.callback(sock.close)
                active=gate.acquire(first);results=[]
                thread=threading.Thread(target=lambda:results.append(gate.acquire(second)));thread.start()
                with gate.condition:
                    self.assertTrue(gate.condition.wait_for(lambda:len(gate.queue)==1,timeout=2))
                    now[0]=elapsed;gate.condition.notify_all()
                    if release:gate.release(active[0])
                thread.join(2);self.assertFalse(thread.is_alive())
                self.assertEqual(results[0] is not None,admitted)
                self.assertEqual(gate.metrics['observed_max_inflight'],1)
                self.assertEqual(gate.metrics['forwarded_requests'],2 if admitted else 1)
                if admitted:gate.release(results[0][0])
                elif not release:gate.release(active[0])
