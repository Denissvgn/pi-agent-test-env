"""Bounded parent-owned scripted HTTP backend; no upstream inference or proxy.

Production serve requires the fixed reviewed controller admission verifier and
a dedicated fresh control/lifeline pipe. The normal SDK lease remains parent-only. Only controlled_fixture() binds loopback for
owned in-process tests; no runtime host/model override exists.
"""
import argparse
import copy
import fcntl
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler,HTTPServer
import importlib.util
import json
import math
import os
from pathlib import Path
import pwd
import re
import select
import stat
import types
import signal
import sys
import socket
import threading
import time
import uuid

import application_settlement_diagnostic as diagnostic
import application_scripted as scripted

HOST='172.17.0.1'
PORT=19081
ENDPOINT='http://172.17.0.1:19081/v1'
MODEL=diagnostic.MODEL
MAX_BODY=2097152
MAX_BOOTSTRAP=65536
MAX_REQUESTS=64
MAX_MESSAGES=128
MAX_TOOL_RESULTS=32
MAX_HANDLERS=2
REQUEST_SECONDS=5
MAX_LIFETIME=900
MAX_FRAMES=128
MAX_FRAME_BYTES=8192
MAX_RESPONSE_BYTES=65536
PHASES=frozenset(('BOUND','LISTENING','PREFLIGHT','SCRIPTING','SETTLED','REFUSED','PARENT_LOST','STOPPED','CLOSURE_UNCONFIRMED'))
COUNTERS=('requests','health_requests','script_requests','responses','rejected','emitted_tool_calls','tool_results',
          'unexpected_results','script_settled','parent_loss','control_protocol_errors','request_cap_denials','handler_cap_denials','inference_busy','active_handlers','active_inference')
_NORMAL_LOCK='/home/piqual/.local/state/pi-agent-test-env/operation.lock'
_SERVICE_PERMIT=object()


class ServiceError(ValueError):
    def __init__(self):super().__init__('Controlled settlement service refused')


def need(value):
    if not value:raise ServiceError()


def exact(value,keys):need(type(value)is dict and set(value)==set(keys))
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()


def decode(raw):
    need(type(raw)is bytes and len(raw)<=MAX_BODY)
    def pairs(rows):
        value={}
        for key,child in rows:need(key not in value);value[key]=child
        return value
    def number(text):
        value=float(text);need(math.isfinite(value));return value
    def integer(text):need(len(text.lstrip('-'))<=4300);return int(text)
    def bad(unused):raise ServiceError()
    value=json.loads(raw,object_pairs_hook=pairs,parse_float=number,parse_int=integer,parse_constant=bad)
    queue=[(value,0)];nodes=0
    while queue:
        child,depth=queue.pop();nodes+=1;need(nodes<=131072 and depth<=64)
        if type(child)is dict:
            need(len(child)<=1024)
            for key,item in child.items():need(type(key)is str and len(key)<=256);queue.append((item,depth+1))
        elif type(child)is list:
            need(len(child)<=4096);queue.extend((item,depth+1)for item in child)
        elif type(child)is str:need(len(child)<=262144)
    return value


def bootstrap(value):
    exact(value,{'schema','model','endpoint','lifetime_seconds','inference_key','activation'})
    need(type(value['schema'])is int and value['schema']==1 and value['model']==MODEL and value['endpoint']==ENDPOINT
      and type(value['lifetime_seconds'])is int and 1<=value['lifetime_seconds']<=MAX_LIFETIME)
    key=value['inference_key'];need(type(key)is str and key.isascii()and 16<=len(key)<=4096
      and all(32<ord(ch)<127 for ch in key))
    activation=value['activation']
    exact(activation,{'root','grant','input_review','clock','preparation','candidate','admission','nonce','controller_sha256'})
    need(type(activation['root'])is str and activation['root'].startswith('/home/piqual/')
      and '..'not in Path(activation['root']).parts and str(Path(activation['root']))==activation['root'])
    for name in ('grant','input_review','clock','preparation','candidate','admission'):
        ref=activation[name];exact(ref,{'path','sha256'})
        need(type(ref['path'])is str and Path(ref['path']).is_absolute()and '..'not in Path(ref['path']).parts
          and str(Path(ref['path']))==ref['path']and not any(ord(c)<32 or ord(c)==127 for c in ref['path']))
        need(type(ref['sha256'])is str and re.fullmatch('[a-f0-9]{64}',ref['sha256'])is not None)
    need(type(activation['controller_sha256'])is str and re.fullmatch('[a-f0-9]{64}',activation['controller_sha256'])is not None)
    try:need(type(activation['nonce'])is str and str(uuid.UUID(activation['nonce']))==activation['nonce'])
    except ValueError:raise ServiceError() from None
    return copy.deepcopy(value)


def read_bootstrap(fd,deadline):
    """One bounded private pipe body and EOF; no file/env/secret-store fallback."""
    need(type(fd)is int and fd>=0 and math.isfinite(deadline)and stat.S_ISFIFO(os.fstat(fd).st_mode))
    body=bytearray()
    while True:
        left=deadline-time.monotonic();need(left>0 and select.select([fd],[],[],left)[0])
        chunk=os.read(fd,min(8192,MAX_BOOTSTRAP+1-len(body)))
        if not chunk:break
        body.extend(chunk);need(len(body)<=MAX_BOOTSTRAP)
    need(bool(body));return bootstrap(decode(bytes(body)))


def admitted_permit(value,*,control_fd,parent_pid):
    """Only a fixed source verifier can establish authority; no caller Boolean."""
    config=bootstrap(value)
    need(type(parent_pid)is int and parent_pid>1 and parent_pid==os.getppid()
      and type(control_fd)is int and control_fd>=3)
    need(stat.S_ISFIFO(os.fstat(control_fd).st_mode)
      and fcntl.fcntl(control_fd,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY)
    controller_path=Path(__file__).with_name('application_settlement_controller.py')
    fd=os.open(controller_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=1048576)
        body=bytearray()
        while len(body)<before.st_size:
            block=os.read(fd,min(65536,before.st_size-len(body)));need(bool(block));body.extend(block)
        identity=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
        need(identity(before)==identity(os.fstat(fd))==identity(controller_path.lstat()));raw=bytes(body)
    finally:os.close(fd)
    need(hashlib.sha256(raw).hexdigest()==config['activation']['controller_sha256'])
    controller=types.ModuleType('fixed_settlement_service_controller');controller.__file__=str(controller_path)
    sys.modules[controller.__name__]=controller
    exec(compile(raw,str(controller_path),'exec'),controller.__dict__)
    permit=controller.verify_service_admission(config['activation'],control_fd=control_fd,parent_pid=parent_pid)
    exact(permit,{'schema','authorization_id','nonce','deadline_wall','deadline_monotonic','normal_lock_file','registry_root',
      'parent_registry_admission_attested','grant_sha256','input_review_sha256','clock_sha256','preparation_sha256','candidate_sha256'})
    need(type(permit['schema'])is int and permit['schema']==1 and permit['parent_registry_admission_attested']is True
      and permit['normal_lock_file']==_NORMAL_LOCK and permit['registry_root']==_NORMAL_LOCK+'.registry'
      and permit['nonce']==config['activation']['nonce'])
    try:need(type(permit['authorization_id'])is str and str(uuid.UUID(permit['authorization_id']))==permit['authorization_id'])
    except ValueError:raise ServiceError() from None
    for name in ('grant','input_review','clock','preparation','candidate'):
        need(permit[name+'_sha256']==config['activation'][name]['sha256'])
    for name,now in (('deadline_wall',time.time()),('deadline_monotonic',time.monotonic())):
        need(type(permit[name])in(int,float)and math.isfinite(permit[name])and now+30<permit[name]<=now+MAX_LIFETIME)
    return config,permit


def validate_request(body):
    fields={'model','messages','tools','tool_choice','parallel_tool_calls','stream','max_tokens','max_completion_tokens',
      'temperature','top_p','frequency_penalty','presence_penalty','stop','seed','stream_options','reasoning_effort',
      'chat_template_kwargs','enable_thinking','top_k','min_p','repetition_penalty','user','store'}
    need(type(body)is dict and not set(body)-fields and body.get('model')==MODEL
      and type(body.get('messages'))is list and 1<=len(body['messages'])<=MAX_MESSAGES)
    need(len(canonical(body['messages']))<=262144-8192)
    for message in body['messages']:need(type(message)is dict and message.get('role')in('system','developer','user','assistant','tool'))
    need(sum(message['role']=='tool'for message in body['messages'])<=MAX_TOOL_RESULTS)
    if 'stream'in body:need(type(body['stream'])is bool)
    if 'store'in body:need(body['store']is False)
    for name in ('max_tokens','max_completion_tokens'):
        if name in body:need(type(body[name])is int and 1<=body[name]<=8192)
    need(body.get('reasoning_effort')in(None,'off','none')and body.get('enable_thinking',False)is False)
    if 'chat_template_kwargs'in body:exact(body['chat_template_kwargs'],{'enable_thinking'});need(body['chat_template_kwargs']['enable_thinking']is False)
    if 'parallel_tool_calls'in body:need(type(body['parallel_tool_calls'])is bool)
    if 'tool_choice'in body:need(body['tool_choice']in('auto','required','none')and not(body.get('stream')is True and body['tool_choice']=='none'))
    if 'stream_options'in body:exact(body['stream_options'],{'include_usage'});need(type(body['stream_options']['include_usage'])is bool)
    if 'user'in body:need(type(body['user'])is str and 1<=len(body['user'])<=128)
    if body.get('stop')is not None:
        stops=[body['stop']]if type(body['stop'])is str else body['stop'];need(type(stops)is list and 1<=len(stops)<=4)
        for value in stops:need(type(value)is str and 1<=len(value)<=512)
    for name in ('temperature','top_p','frequency_penalty','presence_penalty','seed','top_k','min_p','repetition_penalty'):
        if name in body:need(type(body[name])in(int,float)and math.isfinite(body[name])and abs(body[name])<=1000000)
    tools=body.get('tools',[]);need(type(tools)is list and len(tools)<=6)
    names=[]
    for tool in tools:
        exact(tool,{'type','function'});need(tool['type']=='function'and type(tool['function'])is dict)
        name=tool['function'].get('name');need(type(name)is str and name in diagnostic.REQUIRED_TOOLS);names.append(name)
    need(len(set(names))==len(names))
    if body.get('stream')is True:need(set(names)==set(diagnostic.REQUIRED_TOOLS))
    else:need(not names and all(message['role']!='tool'for message in body['messages']))
    return set(names)


class _Service:
    def __init__(self,key,*,address,deadline_wall,deadline_monotonic,permit,control_fd=None):
        need(permit is _SERVICE_PERMIT)
        self._key=key.encode('ascii');self._wall=deadline_wall;self._mono=deadline_monotonic
        self._control_fd=control_fd;self._pipe_lock=threading.Lock();self._parent_failed=False
        self.machine=diagnostic.SettlementScript();self.lock=threading.RLock();self.inference_lock=threading.Lock()
        self.requested_stop=threading.Event();self.thread=None;self.failed=False;self.closed=False;self.phase='BOUND'
        self.counts=dict.fromkeys(COUNTERS,0);self._handlers=set();self._connections=set();self._timers=set();owner=self
        class Handler(BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def log_message(self,*unused):pass
            def log_error(self,*unused):pass
            def setup(self):
                self.timer=None;super().setup();self.connection.settimeout(max(.001,min(2,owner.remaining())))
                def expire():
                    try:self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:pass
                timer=threading.Timer(max(.001,min(REQUEST_SECONDS,owner.remaining()-30)),expire)
                timer.daemon=False
                with owner.lock:
                    owner._timers.add(timer)
                    try:timer.start();self.timer=timer
                    except BaseException:owner._timers.discard(timer);raise
            def finish(self):
                try:
                    if self.timer is not None:
                        self.timer.cancel();self.timer.join(timeout=max(0,min(1,owner.remaining())))
                        with owner.lock:
                            if not self.timer.is_alive():owner._timers.discard(self.timer)
                finally:super().finish()
            def reply(self,status,value):
                raw=canonical(value);need(len(raw)<=16384)
                self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)))
                self.send_header('Connection','close');self.end_headers();self.wfile.write(raw);self.wfile.flush();self.close_connection=True
            def send_error(self,code,message=None,explain=None):
                owner.refuse()
                try:self.reply(code if code in(400,401,404,405,408,413,429,503)else 400,{'error':'request_refused'})
                except (OSError,ValueError):self.close_connection=True
            def authorized(self):
                values=self.headers.get_all('Authorization',[]);candidate=values[0]if len(values)==1 else''
                valid=type(candidate)is str and candidate.isascii()and len(candidate)<=4110
                return valid and hmac.compare_digest(candidate.encode(),b'Bearer '+owner._key)
            def parse_request(self):
                if not super().parse_request():return False
                if len(self.headers)>32 or sum(len(k)+len(v)for k,v in self.headers.items())>16384:
                    self.send_error(400);return False
                self.close_connection=True;return True
            def permitted(self):
                if owner.expired()or owner.failed:
                    self.reply(503,{'error':'service_unavailable'});return False
                if not self.authorized():owner.refuse();self.reply(401,{'error':'unauthorized'});return False
                return True
            def do_GET(self):
                try:
                    if not self.permitted():return
                    if self.path!='/v1/models':owner.refuse();return self.reply(404,{'error':'not_found'})
                    owner.bump('health_requests');owner.phase='PREFLIGHT'
                    self.reply(200,{'object':'list','data':[{'id':MODEL,'object':'model','context_window':262144,
                      'max_tokens':8192,'input':['text'],'reasoning':False}]});owner.bump('responses')
                except (OSError,ValueError,TypeError,KeyError):owner.refuse()
            def do_POST(self):
                acquired=False
                try:
                    if not self.permitted():return
                    if self.path!='/v1/chat/completions':owner.refuse();return self.reply(404,{'error':'not_found'})
                    if not owner.inference_lock.acquire(False):
                        owner.bump('inference_busy');owner.refuse();return self.reply(429,{'error':'inference_busy'})
                    acquired=True;owner.bump('active_inference')
                    need(self.headers.get('Transfer-Encoding')is None and len(self.headers.get_all('Content-Length',[]))==1)
                    length=self.headers['Content-Length'];need(length.isascii()and length.isdecimal()and 0<int(length)<=MAX_BODY)
                    raw=self.rfile.read(int(length));need(len(raw)==int(length));body=decode(raw);tools=validate_request(body)
                    if body.get('stream')is not True:
                        owner.bump('health_requests');owner.phase='PREFLIGHT'
                        self.reply(200,{'id':'controlled-health','object':'chat.completion','model':MODEL,
                          'choices':[{'index':0,'message':{'role':'assistant','content':'OK'},'finish_reason':'stop'}],
                          'usage':dict(scripted.WIRE_USAGE)});owner.bump('responses');return
                    need(not owner.expired());owner.bump('script_requests');owner.phase='SCRIPTING'
                    decision=owner.machine.respond(body['messages'],tools)
                    with owner.lock:
                        owner.counts['emitted_tool_calls']=len(owner.machine.sent);owner.counts['tool_results']=len(owner.machine.results)
                        owner.counts['unexpected_results']=owner.machine.unexpected_results
                        owner.counts['script_settled']=1 if decision['finished']else 0
                    need(owner.machine.unexpected_results==0)
                    frames=diagnostic.response_frames(decision,max(1,len(canonical(body['messages']))))
                    need(len(frames)<=MAX_FRAMES and all(len(frame)<=MAX_FRAME_BYTES for frame in frames)
                      and sum(map(len,frames))<=MAX_RESPONSE_BYTES and not owner.expired())
                    self.send_response(200);self.send_header('Content-Type','text/event-stream');self.send_header('Cache-Control','no-cache')
                    self.send_header('Connection','close');self.end_headers()
                    for frame in frames:need(not owner.expired());self.wfile.write(frame);self.wfile.flush()
                    owner.bump('responses');owner.phase='SETTLED'if decision['finished']else'SCRIPTING'
                except (OSError,ValueError,TypeError,KeyError,IndexError,AttributeError,RecursionError):
                    owner.refuse()
                    try:self.reply(400,{'error':'scripted_request_refused'})
                    except (OSError,ValueError):pass
                finally:
                    if acquired:owner.bump('active_inference',-1);owner.inference_lock.release()
        class Server(HTTPServer):
            allow_reuse_address=False
            def process_request(self,connection,client_address):
                with owner.lock:
                    if owner.expired()or owner.failed:
                        self.shutdown_request(connection);return
                    if owner.counts['requests']>=MAX_REQUESTS:
                        owner.counts['request_cap_denials']+=1;owner.refuse();self.shutdown_request(connection);return
                    owner.counts['requests']+=1
                    if len(owner._handlers)>=MAX_HANDLERS:
                        owner.counts['handler_cap_denials']+=1;owner.refuse();self.shutdown_request(connection);return
                    thread=threading.Thread(target=self.worker,args=(connection,client_address),daemon=False)
                    owner._handlers.add(thread);owner._connections.add(connection);owner.counts['active_handlers']+=1
                try:thread.start()
                except BaseException:
                    with owner.lock:
                        owner._handlers.discard(thread);owner._connections.discard(connection);owner.counts['active_handlers']-=1
                    self.shutdown_request(connection);owner.refuse();raise
            def worker(self,connection,client_address):
                try:self.finish_request(connection,client_address)
                except Exception:owner.refuse()
                finally:
                    self.shutdown_request(connection)
                    with owner.lock:
                        owner._handlers.discard(threading.current_thread());owner._connections.discard(connection)
                        owner.counts['active_handlers']-=1
            def handle_error(self,*unused):owner.refuse()
        need(not self.expired());self.server=Server(address,Handler)
    def __repr__(self):return '<ControlledSettlementService private input withheld>'
    def remaining(self):return min(self._mono-time.monotonic(),self._wall-time.time())
    def parent_alive(self):
        if self._control_fd is None:return True  # Explicit in-process fixtures only.
        if not self._pipe_lock.acquire(False):return not self._parent_failed
        try:
            if self._parent_failed:return False
            try:
                if not select.select([self._control_fd],[],[],0)[0]:return True
                data=os.read(self._control_fd,1)
            except BlockingIOError:return True
            except OSError:data=b''
            with self.lock:
                self._parent_failed=True;self.failed=True;self.phase='PARENT_LOST'
                self.counts['parent_loss'if not data else'control_protocol_errors']+=1
            self.requested_stop.set();return False
        finally:self._pipe_lock.release()
    def expired(self):return self.requested_stop.is_set()or self.remaining()<=30 or not self.parent_alive()
    def bump(self,name,amount=1):
        with self.lock:self.counts[name]+=amount
    def refuse(self):
        with self.lock:
            self.counts['rejected']+=1
            if not self.failed:self.phase='REFUSED'
            self.failed=True
        self.requested_stop.set()
    def snapshot(self):
        with self.lock:
            need(self.phase in PHASES and set(self.counts)==set(COUNTERS)and all(type(v)is int and 0<=v<=1000000 for v in self.counts.values()))
            return {'schema':1,'phase':self.phase,'counters':dict(self.counts)}
    def start(self):
        need(self.thread is None and not self.closed and not self.expired())
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':.05},daemon=False)
        self.thread.start();self.phase='LISTENING';return self
    def stop(self,seconds=30):
        need(type(seconds)in(int,float)and 0<seconds<=30)
        if self.closed:return self.snapshot()
        self.requested_stop.set();end=min(time.monotonic()+seconds,self._mono,time.monotonic()+self._wall-time.time())
        if self.thread is not None and self.thread.is_alive():self.server.shutdown()
        self.server.server_close()
        with self.lock:connections=list(self._connections);handlers=list(self._handlers);timers=list(self._timers)
        for connection in connections:
            try:connection.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            try:connection.close()
            except OSError:pass
        for thread in handlers+timers+[self.thread]:
            if thread is not None:thread.join(timeout=max(0,end-time.monotonic()))
        with self.lock:
            closed=all(not t.is_alive()for t in handlers+timers if t is not None)and(self.thread is None or not self.thread.is_alive())
            self.closed=closed;self.phase=(self.phase if self.failed else'STOPPED')if closed else'CLOSURE_UNCONFIRMED';self._key=b''
        if self._control_fd is not None:
            os.close(self._control_fd);self._control_fd=None
        return self.snapshot()


def controlled_fixture(key,*,lifetime_seconds=60,control_fd=None):
    """Explicit in-process loopback test factory; never a production host option."""
    need(type(key)is str and key.isascii()and 16<=len(key)<=4096 and all(32<ord(c)<127 for c in key))
    need(type(lifetime_seconds)is int and 31<=lifetime_seconds<=900)
    if control_fd is not None:
        need(type(control_fd)is int and stat.S_ISFIFO(os.fstat(control_fd).st_mode));os.set_blocking(control_fd,False)
    return _Service(key,address=('127.0.0.1',0),deadline_wall=time.time()+lifetime_seconds,
      deadline_monotonic=time.monotonic()+lifetime_seconds,permit=_SERVICE_PERMIT,control_fd=control_fd)


def production_service(value,*,control_fd,parent_pid):
    config,permit=admitted_permit(value,control_fd=control_fd,parent_pid=parent_pid)
    end_wall=min(permit['deadline_wall'],time.time()+config['lifetime_seconds'])
    end_mono=min(permit['deadline_monotonic'],time.monotonic()+config['lifetime_seconds'])
    need(end_wall>time.time()+30 and end_mono>time.monotonic()+30)
    os.set_blocking(control_fd,False)
    return _Service(config['inference_key'],address=(HOST,PORT),deadline_wall=end_wall,
      deadline_monotonic=end_mono,permit=_SERVICE_PERMIT,control_fd=control_fd)


def validate_terminal(value):
    """Closed metadata parser for the owning controller; never inspect values."""
    exact(value,{'schema','status','phase','counters'})
    need(type(value['schema'])is int and value['schema']==1
      and value['status']in('SERVICE_STOPPED','SERVICE_REFUSED','SERVICE_CLOSURE_UNCONFIRMED')
      and type(value['phase'])is str and value['phase']in PHASES|{'BOOTSTRAP','ADMISSION'})
    exact(value['counters'],COUNTERS)
    need(all(type(v)is int and 0<=v<=1000000 for v in value['counters'].values()))
    counts=value['counters'];need(counts['requests']<=MAX_REQUESTS and counts['active_handlers']<=MAX_HANDLERS
      and counts['active_inference']<=1 and counts['emitted_tool_calls']<=6 and counts['tool_results']<=6
      and counts['script_settled']in(0,1)and counts['responses']<=counts['requests'])
    if value['status']=='SERVICE_STOPPED':
        need(value['phase']=='STOPPED'and counts['active_handlers']==counts['active_inference']==0
          and counts['rejected']==counts['unexpected_results']==counts['inference_busy']==0
          and counts['parent_loss']==counts['control_protocol_errors']==counts['request_cap_denials']==0)
    if value['status']=='SERVICE_CLOSURE_UNCONFIRMED':need(value['phase']=='CLOSURE_UNCONFIRMED')
    return copy.deepcopy(value)


def require_guest():
    user=pwd.getpwuid(os.getuid());need(sys.dont_write_bytecode and not sys.flags.optimize
      and os.getuid()==1000 and user.pw_name=='piqual'and user.pw_dir==os.environ.get('HOME')=='/home/piqual'
      and sys.platform=='linux'and os.uname().machine in('aarch64','arm64'))


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('serve');p.add_argument('--control-fd',type=int,required=True);p.add_argument('--parent-pid',type=int,required=True)
    args=parser.parse_args(argv);server=None;phase='BOOTSTRAP'
    try:
        require_guest()
        value=read_bootstrap(0,time.monotonic()+5);phase='ADMISSION'
        server=production_service(value,control_fd=args.control_fd,parent_pid=args.parent_pid);value['inference_key']=''
        for kind in (signal.SIGTERM,signal.SIGINT):signal.signal(kind,lambda *_:server.requested_stop.set())
        phase='LISTENING';server.start();print(json.dumps({'schema':1,'status':'SERVICE_READY','phase':'LISTENING'}),flush=True)
        while not server.requested_stop.wait(.05)and not server.expired():pass
        result=server.stop();status='SERVICE_REFUSED'if server.failed else'SERVICE_STOPPED'if server.closed else'SERVICE_CLOSURE_UNCONFIRMED'
        print(json.dumps({'schema':1,'status':status,**result}),flush=True)
        return 0 if server.closed and not server.failed else 2
    except Exception:
        result={'schema':1,'phase':phase,'counters':dict.fromkeys(COUNTERS,0)}
        if server is not None:
            try:server.refuse();result=server.stop()
            except Exception:pass
        if server is None and type(args.control_fd)is int and args.control_fd>=3:
            try:os.close(args.control_fd)
            except OSError:pass
        print(json.dumps({'status':'SERVICE_REFUSED',**result}),flush=True);return 2


if __name__=='__main__':raise SystemExit(main())
