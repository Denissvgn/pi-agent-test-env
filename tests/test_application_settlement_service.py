"""Owned loopback/inert backend controls; no VM, real API, model or SDK context."""
import ast
import copy
from contextlib import redirect_stdout
from http.client import HTTPConnection,RemoteDisconnected
import hashlib
import html
import io
import json
import os
from pathlib import Path
import socket
import sys
import threading
import time
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools/qualification'))
import application_settlement_service as service

KEY='NONSECRET_OWNED_LOOPBACK_TEST_KEY_065'


def activation():
    return {'root':'/home/piqual/controlled-fixture','nonce':'11111111-1111-4111-8111-111111111111','controller_sha256':'a'*64,
      **{name:{'path':'/home/piqual/controlled-fixture/'+name+'.json','sha256':str(i+1)*64}
         for i,name in enumerate(('grant','input_review','clock','preparation','candidate','admission'))}}


def bootstrap():return {'schema':1,'model':service.MODEL,'endpoint':service.ENDPOINT,'lifetime_seconds':120,
                         'inference_key':KEY,'activation':activation()}


def tools():return [{'type':'function','function':{'name':name,'description':'Owned fixture','parameters':{'type':'object'}}}
                    for name in service.diagnostic.REQUIRED_TOOLS]


def request(messages=None,stream=False):
    return {'model':service.MODEL,'messages':messages or[{'role':'user','content':'Controlled test; not a live prompt.'}],
            'stream':stream,'tools':tools()if stream else[],'max_tokens':8192,'reasoning_effort':'off'}


def parse_sse(raw):
    call=None;text=[]
    for line in raw.splitlines():
        if not line.startswith(b'data: ')or line==b'data: [DONE]':continue
        value=json.loads(line[6:]);delta=value['choices'][0]['delta']
        if 'content'in delta and delta['content']is not None:text.append(delta['content'])
        for part in delta.get('tool_calls',[]):
            if call is None:call={'id':part['id'],'name':part['function']['name'],'arguments':''}
            if 'arguments'in part.get('function',{}):call['arguments']+=part['function']['arguments']
    if call is not None:call['arguments']=json.loads(call['arguments'])
    return call,''.join(text)


def result_for(call):
    if call['name']=='app_api':return {'ok':True,**service.diagnostic.PARTICIPANT,'receipt_id':'fixture-identity'}
    if call['name']=='app_browser':
        if call['arguments']['action']=='click':return {'ok':True,'operation_receipt_ids':['fixture-page-one']}
        if call['arguments']['action']=='snapshot':
            page={'items':[{'id':'r1','text':'Actual first result'},{'id':'r2','text':'Second & value'}],
              'next_cursor':'a'*64,'snapshot_id':'fixture-snapshot'}
            dom={'url':'http://172.17.0.1:18080/summary','page_identity':['diagnostic-summary-v1'],
              'html':'<pre data-testid="records">'+html.escape(json.dumps(page))+'</pre>',
              'form_state':[],'text_content':'unused','inner_text':'unused'}
            return {'ok':True,'dom':json.dumps(dom)}
        return {'ok':True}
    if call['name']=='artifact_write':
        raw=call['arguments']['content'].encode();return {'ok':True,'artifact_id':'summary','bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    return {'ok':True,'contract_id':'participant-report','bytes':100,'sha256':'b'*64}


class SettlementServiceTests(unittest.TestCase):
    def setUp(self):self.servers=[]
    def tearDown(self):
        for server in reversed(self.servers):
            server.stop(seconds=5)
            self.assertTrue(server.closed,'owned fixture threads must be joined')
    def server(self):
        instance=service.controlled_fixture(KEY);self.servers.append(instance);return instance.start()
    def http(self,server,method='POST',path='/v1/chat/completions',body=None,key=KEY,raw=None,headers=None):
        conn=HTTPConnection('127.0.0.1',server.server.server_port,timeout=3)
        try:
            data=raw if raw is not None else json.dumps(body if body is not None else request()).encode()
            fields={'Authorization':'Bearer '+key,'Content-Type':'application/json',**(headers or{})}
            conn.request(method,path,body=None if method=='GET'else data,headers=fields)
            response=conn.getresponse();return response.status,response.read(),dict(response.getheaders())
        finally:conn.close()
    def wait(self,predicate):
        end=time.monotonic()+2
        while not predicate():
            if time.monotonic()>=end:self.fail('bounded fixture condition not reached')
            time.sleep(.005)

    def test_private_bootstrap_exact_closed_scope_without_env_or_key_fallback(self):
        original=bootstrap();self.assertEqual(service.bootstrap(original),original)
        for field,value in (('inference_key','short'),('inference_key',KEY+'\n'),('model','bartowski/Altworld_Hemmingway-1-GGUF'),
          ('endpoint','http://127.0.0.1:19081/v1'),('schema',True),('lifetime_seconds',901),('host','0.0.0.0')):
            changed=bootstrap();changed[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):service.bootstrap(changed)
        for section,field,value in (('activation','nonce','../private'),('activation','controller_sha256','WRONG')):
            changed=bootstrap();changed[section][field]=value
            with self.assertRaises(ValueError):service.bootstrap(changed)

    def test_private_pipe_read_once_and_multiple_frames_or_duplicates_refuse(self):
        for raw,valid in ((json.dumps(bootstrap()).encode(),True),(b'{"schema":1,"schema":1}',False),
                          (json.dumps(bootstrap()).encode()+b'\n'+json.dumps(bootstrap()).encode(),False)):
            readfd,writefd=os.pipe()
            try:
                os.write(writefd,raw);os.close(writefd);writefd=None
                if valid:
                    self.assertEqual(service.read_bootstrap(readfd,time.monotonic()+1)['inference_key'],KEY)
                    with self.assertRaises(ValueError):service.read_bootstrap(readfd,time.monotonic()+1)
                else:
                    with self.assertRaises(ValueError):service.read_bootstrap(readfd,time.monotonic()+1)
            finally:
                os.close(readfd)
                if writefd is not None:os.close(writefd)

    def test_production_gate_refuses_before_socket_and_has_no_host_override(self):
        with mock.patch.object(service,'admitted_permit',side_effect=service.ServiceError()), \
             mock.patch.object(service,'_Service',side_effect=AssertionError('socket construction before gate'))as constructor, \
             self.assertRaises(ValueError):service.production_service(bootstrap(),control_fd=3,parent_pid=123)
        constructor.assert_not_called()
        with mock.patch.object(service.socket,'socket',side_effect=AssertionError('socket before private permit')),self.assertRaises(ValueError):
            service._Service(KEY,address=('0.0.0.0',0),deadline_wall=time.time()+900,deadline_monotonic=time.monotonic()+900,permit=object())
        self.assertEqual((service.HOST,service.PORT),('172.17.0.1',19081))
        with self.assertRaises(TypeError):service.controlled_fixture(KEY,host='172.17.0.1')

    def test_production_factory_clips_original_endpoints_with_exact_bridge_only(self):
        cfg=bootstrap();cfg['lifetime_seconds']=100
        permit={'deadline_wall':time.time()+60,'deadline_monotonic':time.monotonic()+60}
        readfd,writefd=os.pipe()
        try:
            with mock.patch.object(service,'admitted_permit',return_value=(cfg,permit)),mock.patch.object(service,'_Service')as constructor:
                service.production_service(cfg,control_fd=readfd,parent_pid=123)
        finally:os.close(readfd);os.close(writefd)
        self.assertEqual(constructor.call_args.kwargs['address'],('172.17.0.1',19081))
        self.assertLessEqual(constructor.call_args.kwargs['deadline_wall'],permit['deadline_wall'])
        self.assertLessEqual(constructor.call_args.kwargs['deadline_monotonic'],permit['deadline_monotonic'])

    def test_cli_serve_defaults_deny_outside_normal_guest_before_bootstrap(self):
        output=io.StringIO()
        with mock.patch.object(service.os,'close'),mock.patch.object(service.sys,'platform','darwin'),mock.patch.object(service,'read_bootstrap',side_effect=AssertionError('private read before guest gate'))as read, \
             redirect_stdout(output):
            self.assertEqual(service.main(['serve','--control-fd','3','--parent-pid','123']),2)
        read.assert_not_called();value=json.loads(output.getvalue());self.assertEqual(value['status'],'SERVICE_REFUSED')
        self.assertNotIn(KEY,output.getvalue());self.assertEqual(set(value),{'schema','phase','status','counters'})
        output=io.StringIO()
        with mock.patch.object(service.os,'close'),mock.patch.object(service,'require_guest'), \
             mock.patch.object(service,'read_bootstrap',return_value=bootstrap()), \
             mock.patch.object(service,'production_service',side_effect=RuntimeError('SECRET_RUNTIME_TRACEBACK_'+KEY)), \
             redirect_stdout(output):
            self.assertEqual(service.main(['serve','--control-fd','3','--parent-pid','123']),2)
        self.assertEqual(json.loads(output.getvalue())['phase'],'ADMISSION')
        self.assertNotIn(KEY,output.getvalue());self.assertNotIn('SECRET_RUNTIME_TRACEBACK',output.getvalue())


    def test_no_tools_health_and_models_do_not_advance_state_machine(self):
        server=self.server()
        for _ in range(2):
            code,raw,_=self.http(server,method='GET',path='/v1/models');self.assertEqual(code,200)
            self.assertEqual(json.loads(raw)['data'][0]['id'],service.MODEL)
            code,raw,_=self.http(server,body=request());self.assertEqual(code,200)
            self.assertEqual(json.loads(raw)['choices'][0]['message']['content'],'OK')
        self.assertEqual(server.machine.step,0);self.assertEqual(server.machine.sent,{})
        self.assertEqual(server.snapshot()['counters']['health_requests'],4)

    def test_full_real_http_synthetic_conversation_emits_exact_six_calls_and_settles(self):
        server=self.server();history=[{'role':'user','content':'Controlled synthetic participant fixture.'}];calls=[]
        for turn in range(7):
            code,raw,headers=self.http(server,body=request(history,True));self.assertEqual(code,200)
            self.assertEqual(headers['Content-Type'],'text/event-stream');self.assertTrue(raw.endswith(b'data: [DONE]\n\n'))
            call,text=parse_sse(raw)
            if call is None:
                self.assertEqual(text,'CONTROLLED_SETTLEMENT_DIAGNOSTIC_SETTLED');break
            calls.append(call)
            history.append({'role':'assistant','content':None,'tool_calls':[{'id':call['id'],'type':'function',
              'function':{'name':call['name'],'arguments':json.dumps(call['arguments'])}}]})
            history.append({'role':'tool','tool_call_id':call['id'],'content':json.dumps(result_for(call))})
        self.assertEqual([c['name']for c in calls],list(service.diagnostic.CALLS));self.assertEqual(turn,6)
        self.assertIn('Actual first result',calls[4]['arguments']['content'])
        self.assertEqual(calls[5]['arguments']['report']['unresolved'],[service.diagnostic.UNRESOLVED])
        snapshot=server.snapshot();self.assertEqual(snapshot['counters']['script_requests'],7)
        self.assertEqual(snapshot['counters']['emitted_tool_calls'],6);self.assertEqual(snapshot['counters']['tool_results'],6)
        self.assertEqual(snapshot['counters']['script_settled'],1);self.assertEqual(snapshot['counters']['rejected'],0)

    def test_no_upstream_network_client_or_payload_logging_in_backend(self):
        source=(ROOT/'tools/qualification/application_settlement_service.py').read_text();tree=ast.parse(source)
        self.assertFalse(any(isinstance(n,ast.Attribute)and n.attr in('create_connection','urlopen','request')for n in ast.walk(tree)))
        server=self.server();self.http(server,body=request());value=server.snapshot();encoded=json.dumps(value)
        self.assertNotIn(KEY,repr(server));self.assertNotIn(KEY,encoded);self.assertNotIn('Controlled test',encoded)
        self.assertEqual(set(value),{'schema','phase','counters'});self.assertEqual(set(value['counters']),set(service.COUNTERS))

    def test_wrong_model_secret_or_malformed_request_poison_without_next_call(self):
        for fault in ('model','secret','duplicate','nonfinite','foreign-result'):
            server=self.server();body=request(stream=True);key=KEY;raw=None
            if fault=='model':body['model']='UNREVIEWED_TARGET_MODEL'
            elif fault=='secret':key='INCORRECT_NONSECRET_KEY'
            elif fault=='duplicate':raw=b'{"model":"'+service.MODEL.encode()+b'","model":"SECRET_DUPLICATE"}'
            elif fault=='nonfinite':raw=b'{"x":NaN}'
            else:body['messages'].append({'role':'tool','tool_call_id':'foreign','content':'SECRET_TOOL_BODY'})
            code,response,_=self.http(server,body=body,key=key,raw=raw)
            self.assertIn(code,(400,401));self.assertNotIn(b'SECRET',response);self.assertTrue(server.failed)
            self.assertEqual(server.machine.sent,{})
            with self.assertRaises((RemoteDisconnected,ConnectionError,OSError)):self.http(server,body=request(stream=True))

    def test_stream_false_with_tools_is_not_a_hidden_script_or_preflight(self):
        server=self.server();body=request();body['tools']=tools()
        code,_,_=self.http(server,body=body);self.assertEqual(code,400);self.assertEqual(server.machine.step,0)

    def test_duplicate_replayed_conversation_is_refused_not_retried(self):
        server=self.server();body=request(stream=True)
        self.assertEqual(self.http(server,body=body)[0],200)
        self.assertEqual(self.http(server,body=body)[0],400)
        self.assertEqual(len(server.machine.sent),1);self.assertTrue(server.failed)

    def test_request_body_bound_and_nonfinite_depth_key_domains(self):
        for raw in (b'NaN',b'1e999',b'{"x":1,"x":2}',b'['*65+b'0'+b']'*65):
            with self.assertRaises((ValueError,RecursionError)):service.decode(raw)
        server=self.server();conn=HTTPConnection('127.0.0.1',server.server.server_port,timeout=3)
        try:
            conn.putrequest('POST','/v1/chat/completions');conn.putheader('Authorization','Bearer '+KEY)
            conn.putheader('Content-Length',str(service.MAX_BODY+1));conn.endheaders()
            response=conn.getresponse();self.assertEqual(response.status,400);self.assertNotIn(KEY.encode(),response.read())
        finally:conn.close()
        self.assertEqual(server.machine.step,0)

    def test_request_ceiling_counts_preflight_and_never_advances_script(self):
        server=self.server()
        for _ in range(service.MAX_REQUESTS):
            self.assertEqual(self.http(server,method='GET',path='/v1/models')[0],200)
            self.wait(lambda:server.snapshot()['counters']['active_handlers']==0)
        with self.assertRaises((RemoteDisconnected,ConnectionError,OSError)):self.http(server,method='GET',path='/v1/models')
        self.assertEqual(server.snapshot()['counters']['requests'],64);self.assertEqual(server.machine.step,0)

    def test_max_two_handlers_and_owned_stop_reaps_slow_connections(self):
        server=self.server();connections=[]
        try:
            for _ in range(2):
                connection=socket.create_connection(('127.0.0.1',server.server.server_port),timeout=1);connections.append(connection)
                connection.sendall(b'POST /v1/chat/completions HTTP/1.1\r\n')
            self.wait(lambda:server.snapshot()['counters']['active_handlers']==2)
            third=socket.create_connection(('127.0.0.1',server.server.server_port),timeout=1);connections.append(third)
            third.sendall(b'GET /v1/models HTTP/1.1\r\n\r\n')
            try:reply=third.recv(16)
            except ConnectionResetError:reply=b''
            self.assertEqual(reply,b'')
            self.assertEqual(server.snapshot()['counters']['handler_cap_denials'],1)
            started=time.monotonic();server.stop(seconds=2);self.assertLess(time.monotonic()-started,2.1)
            self.assertTrue(server.closed);self.assertEqual(server.snapshot()['counters']['active_handlers'],0)
        finally:
            for connection in connections:connection.close()

    def test_nonblocking_inference_slot_denies_overlap_and_no_second_script(self):
        server=self.server();entered=threading.Event();release=threading.Event();original=server.machine.respond;answers=[]
        def held(*args):entered.set();release.wait(2);return original(*args)
        def first():
            try:answers.append(self.http(server,body=request(stream=True))[0])
            except (ConnectionError,OSError):answers.append('closed')
        with mock.patch.object(server.machine,'respond',side_effect=held):
            thread=threading.Thread(target=first);thread.start()
            try:
                self.assertTrue(entered.wait(1));code,_,_=self.http(server,body=request());self.assertEqual(code,429)
                self.assertEqual(server.snapshot()['counters']['active_inference'],1)
            finally:release.set();thread.join(3)
        self.assertFalse(thread.is_alive());self.assertEqual(server.snapshot()['counters']['inference_busy'],1)
        self.assertEqual(server.snapshot()['counters']['script_requests'],1)

    def test_expired_shared_deadline_cannot_advance_or_rebind(self):
        server=self.server();server._mono=time.monotonic()+29
        with self.assertRaises((RemoteDisconnected,ConnectionError,OSError)):self.http(server,body=request(stream=True))
        self.assertEqual(server.machine.sent,{});server.stop(seconds=1);self.assertTrue(server.closed)
        with self.assertRaises(ValueError):server.start()

    def test_lifeline_EOF_or_unexpected_data_stops_without_another_script(self):
        for action in ('EOF','extra'):
            readfd,writefd=os.pipe();instance=None
            try:
                instance=service.controlled_fixture(KEY,control_fd=readfd);self.servers.append(instance);instance.start()
                self.assertEqual(self.http(instance,method='GET',path='/v1/models')[0],200)
                if action=='EOF':os.close(writefd);writefd=None
                else:os.write(writefd,b'UNEXPECTED_CONTROL_BYTES')
                self.assertFalse(instance.parent_alive());self.assertEqual(instance.snapshot()['phase'],'PARENT_LOST')
                with self.assertRaises((RemoteDisconnected,ConnectionError,OSError)):self.http(instance,body=request(stream=True))
                self.assertEqual(instance.machine.sent,{})
                snapshot=instance.stop(seconds=2);self.assertTrue(instance.closed)
                self.assertEqual(snapshot['counters']['parent_loss'if action=='EOF'else'control_protocol_errors'],1)
                service.validate_terminal({'status':'SERVICE_REFUSED',**snapshot})
            finally:
                if writefd is not None:os.close(writefd)
                if instance is None:os.close(readfd)

    def test_lifeline_EOF_before_listener_and_regular_inherited_FD_refuse(self):
        readfd,writefd=os.pipe();os.close(writefd)
        try:
            with mock.patch.object(service.HTTPServer,'__init__',side_effect=AssertionError('bind before lifeline'))as bind, \
                 self.assertRaises(ValueError):service.controlled_fixture(KEY,control_fd=readfd)
            bind.assert_not_called()
        finally:os.close(readfd)
        fd=os.open(__file__,os.O_RDONLY)
        try:
            with mock.patch.object(service.os,'open',side_effect=AssertionError('source read before FIFO denial')), \
                 self.assertRaises(ValueError):service.admitted_permit(bootstrap(),control_fd=fd,parent_pid=os.getppid())
        finally:os.close(fd)
        tree=ast.parse((ROOT/'tools/qualification/application_settlement_service.py').read_text())
        self.assertFalse(any(isinstance(n,ast.Attribute)and n.attr=='flock'for n in ast.walk(tree)))

    def test_absolute_body_deadline_defeats_continuous_slow_drip(self):
        server=self.server();client=socket.create_connection(('127.0.0.1',server.server.server_port),timeout=1)
        try:
            client.sendall(('POST /v1/chat/completions HTTP/1.1\r\nHost:localhost\r\nAuthorization:Bearer '+KEY+'\r\nContent-Length:20000\r\n\r\n').encode())
            started=time.monotonic();failed=False
            while time.monotonic()-started<6:
                try:client.sendall(b'x')
                except (BrokenPipeError,ConnectionResetError):failed=True;break
                time.sleep(.05)
            self.assertTrue(failed,'continuous bytes must not reset the absolute five-second request deadline')
            self.assertLess(time.monotonic()-started,5.8);self.assertEqual(server.machine.step,0)
        finally:client.close()

    def test_terminal_parser_rejects_false_closure_extra_fields_and_secret_canaries(self):
        server=self.server();snapshot=server.stop(seconds=2)
        value={'status':'SERVICE_STOPPED',**snapshot};self.assertEqual(service.validate_terminal(value),value)
        for fault in ('active','extra','bool','badphase','counts'):
            changed=copy.deepcopy(value)
            if fault=='active':changed['counters']['active_handlers']=1
            elif fault=='extra':changed['key']=KEY
            elif fault=='bool':changed['counters']['requests']=True
            elif fault=='badphase':changed['phase']='SECRET_ERROR_TEXT'
            else:changed['counters']['emitted_tool_calls']=7
            with self.subTest(fault=fault),self.assertRaises(ValueError):service.validate_terminal(changed)

    def test_thread_and_key_closure_never_claim_global_memory_erasure(self):
        server=self.server();server.stop(seconds=2);self.assertTrue(server.closed);self.assertEqual(server._key,b'')
        snapshot=server.snapshot();self.assertEqual(snapshot['phase'],'STOPPED');self.assertEqual(snapshot['counters']['active_handlers'],0)
        self.assertNotIn('all_memory_erased',json.dumps(snapshot));self.assertEqual(server.stop(),snapshot)


if __name__=='__main__':unittest.main(verbosity=2)
