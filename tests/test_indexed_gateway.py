"""Two independent synthetic HTTP authorities; routing is not model acceptance."""
import http.client
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'skill/runtime'))
import inference_gateway as gateway


class RoutedTests(unittest.TestCase):
    def setUp(self):
        self.keys={'alpha':'synthetic-alpha-secret','beta':'synthetic-beta-secret'}
        self.calls=[];self.servers=[];self.content_type='application/json';self.listing_id='same-fixture-model';case=self
        def upstream(name):
            class Upstream(BaseHTTPRequestHandler):
                def log_message(self,*args):pass
                def do_GET(self):
                    case.calls.append((name,self.headers.get('Authorization'),'GET'))
                    raw=json.dumps({'data':[{'id':case.listing_id,'description':case.keys['alpha']+' '+case.keys['beta']}]}).encode()
                    self.send_response(200);self.send_header('Content-Type',case.content_type);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
                def do_POST(self):
                    body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                    case.calls.append((name,self.headers.get('Authorization'),body))
                    raw=json.dumps({'reply':name,'echo':case.keys['alpha']+' '+case.keys['beta']}).encode()
                    self.send_response(200);self.send_header('Content-Type',case.content_type);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
            server=ThreadingHTTPServer(('127.0.0.1',0),Upstream);case.servers.append(server)
            threading.Thread(target=server.serve_forever,daemon=True).start();return server
        routes={}
        for name in ('alpha','beta'):
            server=upstream(name);routes[name]={'endpoint':{'base_url':f'http://127.0.0.1:{server.server_port}/v1','model':'same-fixture-model','max_tokens':64},'upstream_key':self.keys[name]}
        limits={'max_inflight':1,'max_pending':4,'queue_wait_seconds':.5,'request_timeout_seconds':2}
        self.config={'routes':routes,'tokens':{'synthetic-token-a':{'route':'alpha'},'synthetic-token-b':{'route':'beta'}},'limits':limits}
        self.gate=gateway.Gate(limits);self.proxy=gateway.Server(('127.0.0.1',0),gateway.handler(self.config,self.gate),6)
        threading.Thread(target=self.proxy.serve_forever,daemon=True).start();self.servers.append(self.proxy);self.addCleanup(self.close)
    def close(self):
        for server in self.servers:server.shutdown();server.server_close()
    def request(self,token,method='POST',payload=None):
        client=http.client.HTTPConnection('127.0.0.1',self.proxy.server_port,timeout=3)
        body=json.dumps(payload or {'model':'same-fixture-model','messages':[],'max_tokens':32}) if method=='POST' else None
        client.request(method,'/v1/chat/completions' if method=='POST' else '/v1/models',body,{'Authorization':'Bearer '+token})
        response=client.getresponse();raw=response.read();status=response.status;client.close();return status,raw
    def test_same_model_names_use_token_bound_routes_and_correct_keys(self):
        for token,name in [('synthetic-token-a','alpha'),('synthetic-token-b','beta')]:
            status,body=self.request(token);self.assertEqual(status,200);self.assertEqual(json.loads(body)['reply'],name)
            self.assertEqual(self.calls[-1][0:2],(name,'Bearer '+self.keys[name]))
            for key in self.keys.values():self.assertNotIn(key.encode(),body)
        self.assertEqual(self.gate.metrics['observed_max_inflight'],1)
    def test_list_is_route_scoped_and_all_held_keys_are_redacted(self):
        status,body=self.request('synthetic-token-b','GET');self.assertEqual(status,200)
        self.assertEqual(self.calls[-1][0:2],('beta','Bearer '+self.keys['beta']))
        self.assertEqual([m['id'] for m in json.loads(body)['data']],['same-fixture-model'])
        for key in self.keys.values():self.assertNotIn(key.encode(),body)
    def test_caller_cannot_supply_another_route_or_key_or_model(self):
        for extra in ({'base_url':'http://other.invalid/v1'},{'api_key':'synthetic-override'},{'route':'beta'},{'model':'foreign-fixture'}):
            payload={'model':'same-fixture-model','messages':[],'max_tokens':32,**extra}
            self.assertEqual(self.request('synthetic-token-a',payload=payload)[0],400)
        self.assertEqual(self.request('unassigned-token')[0],401);self.assertEqual(self.calls,[])
    def test_quarantine_is_global_across_routes(self):
        self.gate.uncertain=True
        self.assertEqual(self.request('synthetic-token-a')[0],429)
        self.assertEqual(self.request('synthetic-token-b')[0],429);self.assertEqual(self.calls,[])

    def test_untrusted_headers_cannot_echo_another_routes_authority(self):
        for media in ('application/json','text/event-stream','text/foreign'):
            self.content_type=media+'; boundary='+self.keys['beta']+'; token=synthetic-token-b'
            client=http.client.HTTPConnection('127.0.0.1',self.proxy.server_port,timeout=3)
            client.request('POST','/v1/chat/completions',json.dumps({'model':'same-fixture-model','messages':[],'max_tokens':32}),{'Authorization':'Bearer synthetic-token-a'})
            response=client.getresponse();headers=str(response.getheaders());response.read();client.close()
            self.assertNotIn(self.keys['beta'],headers);self.assertNotIn('synthetic-token-b',headers)
            self.assertEqual(response.getheader('Content-Type'),media if media in ('application/json','text/event-stream') else 'application/octet-stream')

    def test_bounded_namespace_redacts_every_future_capability_across_splits(self):
        prefix='1234567890abcdef'*2;token=prefix+'fedcba0987654321'*2
        for split in range(len(token)+1):
            scrub=gateway.Scrubber([self.keys['alpha'],self.keys['beta']],prefix)
            raw=b'prefix '+token.encode()+b' suffix'
            point=len(b'prefix ')+split
            clean=scrub.feed(raw[:point])+scrub.feed(raw[point:],True)
            self.assertEqual(clean,b'prefix [REDACTED] suffix')
        self.assertEqual(gateway.Scrubber([],prefix).feed(('unrelated '+'b'*64).encode(),True),('unrelated '+'b'*64).encode())

    def test_complete_invalid_discovery_does_not_claim_unknown_termination(self):
        self.listing_id='unavailable-fixture'
        self.assertEqual(self.request('synthetic-token-a','GET')[0],502)
        with self.gate.condition:self.assertTrue(self.gate.condition.wait_for(lambda:self.gate.active is None,timeout=1))
        self.assertFalse(self.gate.uncertain)
        self.listing_id='same-fixture-model'
        self.assertEqual(self.request('synthetic-token-b','GET')[0],200)

    def test_uniform_helper_redacts_other_selected_collection_authorities(self):
        self.config['redaction_keys']=[self.keys['beta']]
        self.config['routes'].pop('beta');self.config['tokens'].pop('synthetic-token-b')
        status,body=self.request('synthetic-token-a')
        self.assertEqual(status,200)
        self.assertNotIn(self.keys['beta'].encode(),body)
        self.assertEqual(self.calls[-1][0],'alpha')


if __name__=='__main__':unittest.main()
