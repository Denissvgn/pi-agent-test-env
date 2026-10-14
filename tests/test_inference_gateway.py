"""Loopback gateway qualification; scripted responses are not model acceptance."""
import contextlib
import http.client
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
from pathlib import Path
import socket
import sys
import threading
import time
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'skill/runtime'))
import inference_gateway as gateway


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.upstream_key='synthetic-upstream-value-0123456789';self.token='synthetic-trial-value-9876543210';self.requests=[]
        self.forwarded=threading.Event();self.finish=threading.Event();self.mode='ok';case=self
        class Upstream(BaseHTTPRequestHandler):
            def log_message(self,*unused):pass
            def do_GET(self):
                self.send_response(200);self.end_headers();self.wfile.write(json.dumps({'data':[{'id':'fixture-model','description':case.upstream_key},{'id':'other-model'}]}).encode())
            def do_POST(self):
                raw=self.rfile.read(int(self.headers['Content-Length']));body=json.loads(raw)
                case.requests.append({'auth':self.headers.get('Authorization'),'body':body});case.forwarded.set()
                content=case.upstream_key if case.mode=='echo' else 'scripted reply'
                raw=json.dumps({'content':content}).encode()
                if case.mode.startswith('length-'):
                    raw=b'data: [DONE]\n\n' if case.mode!='length-long' else b'data: '+b'x'*65536+case.upstream_key.encode()+b'\n\ndata: [DONE]\n\n'
                self.send_response(503 if case.mode=='error' else 200)
                if case.mode.startswith('length-'):
                    self.send_header('Content-Length',str(len(raw)+(5 if case.mode=='length-truncated' else 0)))
                    self.send_header('Content-Type','text/event-stream')
                self.end_headers()
                if case.mode=='hold':case.finish.wait(3)
                try:self.wfile.write(raw)
                except BrokenPipeError:pass
        self.upstream=ThreadingHTTPServer(('127.0.0.1',0),Upstream)
        self.thread=threading.Thread(target=self.upstream.serve_forever,daemon=True);self.thread.start()
        self.config={'endpoint':{'base_url':f'http://127.0.0.1:{self.upstream.server_port}/v1','model':'fixture-model','max_tokens':1024},
                     'upstream_key':self.upstream_key,'tokens':{self.token:'trial-a','synthetic-trial-b-0123456789':'trial-b'},
                     'limits':{'max_inflight':1,'max_pending':2,'queue_wait_seconds':.2,'request_timeout_seconds':2}}
        self.gate=gateway.Gate(self.config['limits']);self.server=gateway.Server(('127.0.0.1',0),gateway.handler(self.config,self.gate),4)
        self.gateway_thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.gateway_thread.start()
        self.addCleanup(self.close)
    def close(self):
        self.finish.set();self.server.shutdown();self.server.server_close();self.upstream.shutdown();self.upstream.server_close()
        self.gateway_thread.join(3);self.thread.join(3)
    def request(self,method='POST',path='/v1/chat/completions',token=None,body=None):
        connection=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=4)
        payload=json.dumps(body or {'model':'fixture-model','messages':[{'role':'user','content':'synthetic prompt'}],'max_tokens':128}).encode() if method=='POST' else None
        connection.request(method,path,payload,headers={'Authorization':'Bearer '+(token or self.token),'Content-Type':'application/json'})
        reply=connection.getresponse();value=reply.read();status=reply.status;connection.close();return status,value
    def test_exact_route_model_settings_and_authority_separation(self):
        self.assertEqual(self.request()[0],200);self.assertEqual(self.requests[0]['auth'],'Bearer '+self.upstream_key)
        self.assertNotEqual(self.requests[0]['auth'],'Bearer '+self.token)
        models=json.loads(self.request('GET','/v1/models')[1]);self.assertEqual([m['id'] for m in models['data']],['fixture-model'])
        self.assertEqual(self.request(token='wrong-trial-token')[0],401)
        self.assertEqual(self.request(body={'model':'other-model','messages':[]})[0],400)
        self.assertEqual(self.request(body={'model':'fixture-model','messages':[],'max_tokens':2048})[0],400)
        self.assertEqual(self.request(body={'model':'fixture-model','messages':[],'internal_url':'synthetic'})[0],400)
        self.assertEqual(self.request(body={'model':'fixture-model','messages':[]})[0],400)
        self.assertEqual(len(self.requests),1)
    def test_upstream_credentials_and_escaped_variants_are_redacted(self):
        self.mode='echo';status,body=self.request();self.assertEqual(status,200);self.assertNotIn(self.upstream_key.encode(),body)
        for value in (self.upstream_key,json.dumps(self.upstream_key)[1:-1]):
            scrub=gateway.Scrubber([self.upstream_key]);a=scrub.feed(value[:8].encode());b=scrub.feed(value[8:].encode());c=scrub.feed(b'',True)
            self.assertNotIn(self.upstream_key.encode(),a+b+c);self.assertIn(b'[REDACTED]',a+b+c)
    def test_reviewed_pi_sdk_storage_opt_out_is_forwarded_without_enabling_storage(self):
        # Captured offline from the exact 0.87.1 and 1.2.0 SDK artifacts:
        # both local-lab adapters emit these fields, including store:false.
        payload={'model':'fixture-model','messages':[{'role':'user','content':'synthetic fixture'}],
                 'stream':True,'stream_options':{'include_usage':True},'store':False,
                 'max_tokens':128,'reasoning_effort':'low'}
        self.assertEqual(self.request(body=payload)[0],200)
        self.assertEqual(self.requests[0]['body'],payload)
        self.assertEqual(self.requests[0]['auth'],'Bearer '+self.upstream_key)
        for invalid in (True,None,0,1,'false',{},[]):
            with self.subTest(store=invalid):
                self.assertEqual(self.request(body={**payload,'store':invalid})[0],400)
        self.assertEqual(len(self.requests),1)
        self.assertEqual(self.request(body={**payload,'max_tokens':2048})[0],400)
        self.assertEqual(self.request(body={**payload,'unreviewed_field':False})[0],400)
        self.assertEqual(len(self.requests),1)
    def test_503_is_forwarded_once_without_retry(self):
        self.mode='error';self.assertEqual(self.request()[0],503);self.assertEqual(len(self.requests),1)
    def test_complete_content_length_replies_flush_tail_and_release_slot(self):
        for mode in ('length-short','length-long'):
            with self.subTest(mode=mode):
                self.mode=mode;status,body=self.request()
                expected=b'data: [DONE]\n\n' if mode=='length-short' else b'data: '+b'x'*65536+b'[REDACTED]\n\ndata: [DONE]\n\n'
                self.assertEqual(status,200);self.assertEqual(body,expected)
                self.assertFalse(self.gate.uncertain);self.assertIsNone(self.gate.active)
        self.assertEqual(len(self.requests),2)
    def test_truncated_content_length_reply_quarantines_inference(self):
        self.mode='length-truncated';status,body=self.request()
        self.assertEqual(status,200);self.assertTrue(self.gate.uncertain)
        self.assertIsNotNone(self.gate.active)
        self.assertEqual(self.request()[0],429);self.assertEqual(len(self.requests),1)
    def test_forwarded_disconnect_holds_slot_until_upstream_stops(self):
        self.mode='hold';client=socket.create_connection(('127.0.0.1',self.server.server_port))
        body=json.dumps({'model':'fixture-model','messages':[],'stream':True,'max_tokens':128}).encode()
        header=f'POST /v1/chat/completions HTTP/1.0\r\nAuthorization: Bearer {self.token}\r\nContent-Length: {len(body)}\r\n\r\n'.encode()
        client.sendall(header+body);self.assertTrue(self.forwarded.wait(2));client.close()
        self.assertEqual(self.request()[0],429);self.assertEqual(len(self.requests),1);self.assertIsNotNone(self.gate.active)
        self.finish.set();deadline=time.monotonic()+3
        while self.gate.active is not None and time.monotonic()<deadline:time.sleep(.01)
        self.assertIsNone(self.gate.active)
        observations=json.dumps(self.gate.events)
        for secret in (self.upstream_key,self.token,'synthetic prompt'):self.assertNotIn(secret,observations)
    def test_queued_disconnect_is_withdrawn_and_pending_bound_is_hard(self):
        self.mode='hold'
        first=threading.Thread(target=lambda:self.request(),daemon=True);first.start();self.assertTrue(self.forwarded.wait(2))
        queued=socket.create_connection(('127.0.0.1',self.server.server_port));body=json.dumps({'model':'fixture-model','messages':[],'max_tokens':128}).encode()
        queued.sendall(f'POST /v1/chat/completions HTTP/1.0\r\nAuthorization: Bearer {self.token}\r\nContent-Length: {len(body)}\r\n\r\n'.encode()+body)
        deadline=time.monotonic()+1
        while not self.gate.queue and time.monotonic()<deadline:time.sleep(.01)
        self.assertEqual(len(self.gate.queue),1);queued.close()
        deadline=time.monotonic()+1
        while self.gate.queue and time.monotonic()<deadline:time.sleep(.01)
        self.assertFalse(self.gate.queue);self.assertEqual(len(self.requests),1)
        self.finish.set();first.join(3)

    def test_forward_timeout_quarantines_the_slot_and_never_readmits(self):
        self.mode='hold';self.config['limits']['request_timeout_seconds']=.1
        self.request();self.assertTrue(self.gate.uncertain);self.assertIsNotNone(self.gate.active)
        self.assertEqual(self.request()[0],429);self.assertEqual(len(self.requests),1)
        self.finish.set()

    def test_unicode_and_nested_ascii_json_upstream_keys_never_cross_the_proxy(self):
        key='synthetic-"é\\-upstream-key-012345';current={key}
        for depth in range(3):
            for encoded in current:
                raw=json.dumps({'value':encoded},ensure_ascii=True).encode()
                for split in range(len(raw)+1):
                    scrub=gateway.Scrubber([key]);wire=scrub.feed(raw[:split])+scrub.feed(raw[split:])+scrub.feed(b'',True)
                    self.assertIn(b'[REDACTED]',wire)
            current={json.dumps(text,ensure_ascii=ascii_only)[1:-1] for text in current for ascii_only in (True,False)}

    def test_model_listing_redacts_ascii_escaped_unicode_credentials(self):
        self.upstream_key='synthetic-"é\\-upstream-key-012345';self.config['upstream_key']=self.upstream_key
        status,body=self.request('GET','/v1/models');self.assertEqual(status,200)
        self.assertEqual(json.loads(body)['data'][0]['description'],'[REDACTED]')
