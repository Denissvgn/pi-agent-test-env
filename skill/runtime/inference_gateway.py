"""Bounded one-slot OpenAI-compatible gateway for cooperating trial tokens.

No headers, request/response bodies, prompts or tokens enter observations.
"""
from collections import deque
import http.client
from http.server import BaseHTTPRequestHandler,HTTPServer
import json
import math
import select
import socket
from socketserver import ThreadingMixIn
import threading
import time
from urllib.parse import urlsplit

MAX_BODY=2*1024*1024
MAX_REPLY=64*1024*1024
ALLOWED={'model','messages','stream','stream_options','max_tokens','max_completion_tokens','temperature','top_p','min_p','top_k',
         'repetition_penalty','seed','tools','tool_choice','parallel_tool_calls','frequency_penalty','presence_penalty','stop',
         'reasoning_effort','enable_thinking','chat_template_kwargs'}


class Gate:
    def __init__(self,limits,clock=time.monotonic,observer=None):
        self.limits=limits;self.clock=clock;self.condition=threading.Condition();self.queue=deque();self.active=None;self.events=[];self.uncertain=False;self.observer=observer
        self.metrics={'forwarded_requests':0,'completed_requests':0,'observed_max_inflight':0,'observed_max_pending':0,
                      'queue_wait_seconds_sum':0.0,'queue_wait_seconds_max':0.0}
    def note(self,kind,queued=0):
        with self.condition:
            if kind=='forwarded':self.metrics['forwarded_requests']+=1
            if kind=='completed':self.metrics['completed_requests']+=1
            self.metrics['observed_max_inflight']=max(self.metrics['observed_max_inflight'],int(self.active is not None))
            self.metrics['observed_max_pending']=max(self.metrics['observed_max_pending'],len(self.queue))
            self.events.append({'kind':kind,'queued':queued,'inflight':int(self.active is not None)})
            if len(self.events)>1024:del self.events[:512]
            if self.observer:self.observer({'inflight':int(self.active is not None),'pending':len(self.queue),'uncertain':self.uncertain,**self.metrics})
    def acquire(self,client):
        ticket=object();deadline=self.clock()+self.limits['queue_wait_seconds'];start=self.clock()
        with self.condition:
            if self.uncertain or len(self.queue)>=self.limits['max_pending']:return None
            self.queue.append(ticket);self.note('queued',len(self.queue))
            while True:
                if self.uncertain:
                    self.queue.remove(ticket);self.note('queue_cancelled',len(self.queue));self.condition.notify_all();return None
                # Queued EOF removes a caller; forwarded EOF never releases its slot.
                try:
                    if select.select([client],[],[],0)[0] and not client.recv(1,socket.MSG_PEEK):
                        self.queue.remove(ticket);self.note('queue_cancelled',len(self.queue));self.condition.notify_all();return None
                except OSError:
                    self.queue.remove(ticket);self.note('queue_cancelled',len(self.queue));self.condition.notify_all();return None
                if self.active is None and self.queue[0] is ticket:
                    self.queue.popleft();self.active=ticket;wait=self.clock()-start
                    self.metrics['queue_wait_seconds_sum']+=wait;self.metrics['queue_wait_seconds_max']=max(self.metrics['queue_wait_seconds_max'],wait)
                    self.note('forwarded',len(self.queue));return ticket,wait
                remaining=deadline-self.clock()
                if remaining<=0:
                    self.queue.remove(ticket);self.condition.notify_all();self.note('queue_deadline',len(self.queue));return None
                self.condition.wait(min(.05,remaining))
    def release(self,ticket,known=True):
        with self.condition:
            if self.active is not ticket:raise ValueError('Inference slot ownership mismatch')
            if known:self.active=None
            else:self.uncertain=True
            self.note('completed' if known else 'quarantined',len(self.queue));self.condition.notify_all()


def validate_request(body,endpoint):
    if not isinstance(body,dict) or set(body)-ALLOWED or body.get('model')!=endpoint['model'] or not isinstance(body.get('messages'),list):
        raise ValueError('Unsupported inference request')
    if not any(name in body for name in ('max_tokens','max_completion_tokens')):
        raise ValueError('Explicit bounded reply cap required')
    for name in ('max_tokens','max_completion_tokens'):
        if name in body and (type(body[name]) is not int or not 1<=body[name]<=endpoint['max_tokens']):raise ValueError('Reply cap exceeds frozen contract')
    if 'stream' in body and type(body['stream']) is not bool:raise ValueError('Invalid stream selection')
    if 'stream_options' in body and body['stream_options']!={'include_usage':True}:raise ValueError('Unsupported stream options')
    from pi_contract import SAMPLING_RANGES
    for name,(low,high) in {**SAMPLING_RANGES,'frequency_penalty':(-2,2),'presence_penalty':(-2,2)}.items():
        if name in body and (type(body[name]) not in (int,float) or not low<=body[name]<=high or not math.isfinite(body[name]) or name in ('seed','top_k') and type(body[name]) is not int):
            raise ValueError('Invalid inference setting')
    if 'enable_thinking' in body and type(body['enable_thinking']) is not bool:raise ValueError('Invalid reasoning switch')
    if 'chat_template_kwargs' in body:
        value=body['chat_template_kwargs']
        if not isinstance(value,dict) or set(value)!={'enable_thinking'} or type(value['enable_thinking']) is not bool:raise ValueError('Unsupported reasoning settings')
    if 'reasoning_effort' in body and body['reasoning_effort'] not in ('off','minimal','low','medium','high'):raise ValueError('Unsupported reasoning level')
    for name,value in endpoint.get('sampling',{}).items():
        if body.get(name)!=value:raise ValueError('Frozen sampling setting changed or missing')
    return body


class Scrubber:
    def __init__(self,values):
        self.patterns=set()
        for value in values:
            if not value:continue
            self.patterns.add(value.encode());current={value}
            for unused in range(3):
                current={json.dumps(text,ensure_ascii=ascii_only)[1:-1] for text in current for ascii_only in (True,False)}
                self.patterns.update(text.encode() for text in current)
        self.patterns.discard(b'');self.carry=max(map(len,self.patterns),default=1)-1;self.pending=b''
    def feed(self,data,final=False):
        self.pending+=data
        cut=len(self.pending) if final else max(0,len(self.pending)-self.carry)
        # Do not split a known token that begins just before the cut.
        for pattern in self.patterns:
            position=self.pending.find(pattern)
            while position>=0:
                if position<cut<position+len(pattern):cut=position
                position=self.pending.find(pattern,position+1)
        output,self.pending=self.pending[:cut],self.pending[cut:]
        for pattern in sorted(self.patterns,key=len,reverse=True):output=output.replace(pattern,b'[REDACTED]')
        return output


def handler(config,gate):
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.0'
        def log_message(self,*unused):pass
        def reply(self,status,value):
            body=json.dumps(value).encode();self.send_response(status);self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(body)));self.end_headers()
            try:self.wfile.write(body)
            except (BrokenPipeError,ConnectionResetError):pass
        def authorized(self):
            token=self.headers.get('Authorization','').removeprefix('Bearer ')
            return token if token and token in config['tokens'] else None
        def do_GET(self):
            if self.path=='/health':
                with gate.condition:return self.reply(200,{'status':'ready','max_inflight':1,'inflight':int(gate.active is not None),'pending':len(gate.queue),'uncertain':gate.uncertain})
            if self.path!='/v1/models':return self.reply(404,{'error':'route unavailable'})
            if not self.authorized():return self.reply(401,{'error':'unauthorized'})
            return self.forward('GET',None)
        def do_POST(self):
            if self.path!='/v1/chat/completions':return self.reply(404,{'error':'route unavailable'})
            if not self.authorized():return self.reply(401,{'error':'unauthorized'})
            try:
                if self.headers.get('Transfer-Encoding'):raise ValueError('Unsupported transfer encoding')
                size=int(self.headers.get('Content-Length','0'))
                if not 0<size<=MAX_BODY:raise ValueError('Bounded body required')
                self.connection.settimeout(10);raw=self.rfile.read(size)
                if len(raw)!=size:raise ValueError('Incomplete body')
                validate_request(json.loads(raw),config['endpoint'])
            except (ValueError,OSError):return self.reply(400,{'error':'request outside frozen inference contract'})
            return self.forward('POST',raw)
        def forward(self,method,body):
            grant=gate.acquire(self.connection)
            if grant is None:return self.reply(429,{'error':'inference admission unavailable'})
            ticket,wait=grant;connection=None;sent=False;known=False;forwarded=False
            deadline=time.monotonic()+config['limits']['request_timeout_seconds']
            try:
                endpoint=config['endpoint'];route=urlsplit(endpoint['base_url'])
                if route.scheme not in ('http','https') or route.username or route.password:raise ValueError('Invalid upstream')
                cls=http.client.HTTPSConnection if route.scheme=='https' else http.client.HTTPConnection
                connection=cls(route.hostname,route.port,timeout=config['limits']['request_timeout_seconds'])
                headers={'Content-Type':'application/json','Accept-Encoding':'identity'}
                if config['upstream_key']:headers['Authorization']='Bearer '+config['upstream_key']
                suffix='/models' if method=='GET' else '/chat/completions'
                forwarded=True
                connection.request(method,route.path.rstrip('/')+suffix,body=body,headers=headers)
                upstream_socket=connection.sock
                response=connection.getresponse()
                if method=='GET':
                    raw=response.read(MAX_BODY+1)
                    if len(raw)>MAX_BODY:raise ValueError('Unbounded model list')
                    models=json.loads(raw);selected=[m for m in models.get('data',[]) if m.get('id')==endpoint['model']]
                    if response.status!=200 or len(selected)!=1:raise ValueError('Exact upstream model unavailable')
                    known=True
                    safe=Scrubber([config['upstream_key'],*config['tokens']]).feed(json.dumps({'object':'list','data':selected}).encode(),True)
                    return self.reply(200,json.loads(safe))
                self.send_response(response.status);self.send_header('Content-Type',response.getheader('Content-Type','application/json'))
                self.end_headers();sent=True;connected=True;total=0
                scrubber=Scrubber([config['upstream_key'],*config['tokens']])
                while True:
                    remaining=deadline-time.monotonic()
                    if remaining<=0:raise TimeoutError('Forward deadline')
                    if upstream_socket:upstream_socket.settimeout(remaining)
                    data=response.read1(65536)
                    if not data:known=True;break
                    total+=len(data)
                    if total>MAX_REPLY:raise ValueError('Bounded response exceeded')
                    safe=scrubber.feed(data)
                    if connected:
                        try:self.wfile.write(safe);self.wfile.flush()
                        except (BrokenPipeError,ConnectionResetError):connected=False;gate.note('client_disconnected')
                if connected:
                    try:self.wfile.write(scrubber.feed(b'',True));self.wfile.flush()
                    except (BrokenPipeError,ConnectionResetError):pass
            except (OSError,ValueError,TimeoutError,http.client.HTTPException):
                gate.note('upstream_failure')
                if not sent:self.reply(502,{'error':'upstream request failed'})
            finally:
                if connection is not None:connection.close()
                gate.release(ticket,known=known or not forwarded)
    return Handler


class Server(ThreadingMixIn,HTTPServer):
    daemon_threads=True
    def __init__(self,address,handler,maximum):
        self.slots=threading.BoundedSemaphore(maximum);super().__init__(address,handler)
    def process_request(self,request,address):
        if not self.slots.acquire(False):
            try:request.sendall(b'HTTP/1.0 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n')
            finally:self.shutdown_request(request)
            return
        try:super().process_request(request,address)
        except BaseException:self.slots.release();raise
    def process_request_thread(self,request,address):
        try:super().process_request_thread(request,address)
        finally:self.slots.release()


def main(path):
    from pathlib import Path
    config=json.loads(Path(path).read_text());limits=config['limits']
    if limits['max_inflight']!=1:raise ValueError('Only one cooperating inference slot is admitted')
    import os,uuid
    def observe(value):
        target=Path('/opt/pi-control/outbox/gateway-state.json');temporary=target.with_name('.gateway-'+uuid.uuid4().hex)
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as output:json.dump({'launch_id':config['launch_id'],**value},output);output.flush();os.fsync(output.fileno())
        os.replace(temporary,target)
    gate=Gate(limits,observer=observe);observe({'inflight':0,'pending':0,'uncertain':False});server=Server(('0.0.0.0',8080),handler(config,gate),limits['max_pending']+2)
    server.serve_forever(poll_interval=.1)
