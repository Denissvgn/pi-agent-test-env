#!/usr/bin/env python3
"""Bounded synthetic Chat Completions qualification service; not a real model.

Only actual returned tool data drives subsequent calls. No application/network
operations run from the model service, and no prompts/tool payloads/keys persist.
"""
import argparse
import copy
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import threading
import time
import uuid

MODELS=('application-script-a','application-script-b')
CASES=('request-and-persona','reporting-and-reserve','commit-and-interruption')
CONTEXT_WINDOW=262144
MAX_TOKENS=8192
MAX_BODY=2097152
MAX_REQUESTS=64
MAX_MESSAGES=128
MAX_TOOL_RESULTS=32
REJECTION_STAGES=('framing','json','request_contract','scenario','response_frames','response_write')
WIRE_USAGE={'prompt_tokens':16,'completion_tokens':16,'total_tokens':32}
ALLOWED_TOOLS={'app_api','app_browser','artifact_read','artifact_write','report_write','budget_status'}
PARTICIPANT={'application_id':'diagnostic-app','tenant_id':'team-1','actor_id':'actor-alice','role':'participant'}
RESERVE_ORACLE={'max_tool_calls':16,'reporting_reserve_calls':6,'identity_calls':1,'batch_calls':12,
    'first_reporting_denial_attempt':11,'attempted':13,'charged':10,'blocked':3,'grants_consumed':10,
    'executed_known':10,'executed_unknown':0,'helper_verified':10,'worker_observed':0,
    'remaining_calls':6,'reporting_reserve_calls_remaining':6,'batch_http_effects':0}
SCENARIOS={(CASES[0],MODELS[0]):'invalid-request',(CASES[0],MODELS[1]):'wrong-actor',
    (CASES[1],MODELS[0]):'omitted-report',(CASES[1],MODELS[1]):'native-reserve',
    (CASES[2],MODELS[0]):'commit-response-loss',(CASES[2],MODELS[1]):'participant-interruption'}


class ScriptError(ValueError):
    def __init__(self):super().__init__('Scripted qualification request rejected')


def canonical(value):return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()
def strict(body):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ScriptError()
            result[key]=value
        return result
    try:
        value=json.loads(body,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ScriptError()))
        pending=[(value,0)];nodes=0
        while pending:
            child,depth=pending.pop();nodes+=1
            if depth>64 or nodes>131072:raise ScriptError()
            if type(child) is dict:pending.extend((item,depth+1) for item in child.values())
            elif type(child) is list:pending.extend((item,depth+1) for item in child)
        return value
    except (ValueError,TypeError,RecursionError):raise ScriptError() from None


def _exact(value,fields):
    if type(value) is not dict or set(value)!=set(fields):raise ScriptError()
def _text(value,maximum=4096):
    if type(value) is not str or not value or len(value.encode())>maximum or '\0' in value:raise ScriptError()
    return value
def _receipt(value):
    if type(value) is not str or not re.fullmatch('[a-z0-9][a-z0-9-]{0,63}',value):raise ScriptError()
    return value
def _sha(value):
    if type(value) is not str or not re.fullmatch('[a-f0-9]{64}',value):raise ScriptError()
    return value


def parse_tool_result(value):
    """Accept actual profile text blocks, private HTTP envelope or native details.

    Pi serializes the profile's text content into role=tool messages. Native
    guard denials are bounded plain text, never interpreted as success data.
    """
    if type(value) is list:
        if not 1<=len(value)<=16 or any(type(row) is not dict or set(row)!={'type','text'} or row['type']!='text' for row in value):raise ScriptError()
        value='\n'.join(row['text'] for row in value)
    if type(value) is str:
        _text(value,65536)
        try:value=strict(value)
        except ScriptError:
            for reason in ('reporting_only','request_invalid','tool_budget_exhausted','accounting_unavailable'):
                if re.search(r'(?<![a-z_])'+reason+r'(?![a-z_])',value):return {'ok':False,'reason':reason}
            return {'ok':False,'reason':'tool_failed'}
    if type(value) is not dict or len(canonical(value))>65536:raise ScriptError()
    if set(value)=={'schema','ok','result'}:
        if type(value['schema']) is not int or value['schema']!=1 or value['ok'] is not True or type(value['result']) is not dict:raise ScriptError()
        return copy.deepcopy(value['result'])
    if 'content' in value and 'details' in value and set(value)<={'content','details','isError'}:
        inner=parse_tool_result(value['content'])
        failure=inner.get('ok') is False and value['details']=={} and value.get('isError',True) is True
        if inner!=value['details'] and not failure or 'isError' in value and type(value['isError']) is not bool:raise ScriptError()
        return inner
    return copy.deepcopy(value)


def api_input(operation,*,cursor=None,body=None):return {'operation_id':operation,'path_params':{},'query':{},'body':body,'cursor':cursor}


class ScriptMachine:
    """Per-cell, single-conversation pure state machine; returned data stays RAM."""
    def __init__(self,case_id,model):
        if (case_id,model) not in SCENARIOS:raise ScriptError()
        self.case_id,self.model,self.scenario=case_id,model,SCENARIOS[case_id,model]
        self.sent={};self.results={};self.pending=[];self.step=0;self.finished=False;self.held=False
        self.identity_succeeded=False;self.unexpected_results=0;self.pages=[];self.records=[];self.artifact=None;self.publication=None
    def __repr__(self):return '<ApplicationScriptMachine tool payloads withheld>'
    def _call(self,name,arguments):
        if name not in ALLOWED_TOOLS or len(self.sent)>=32:raise ScriptError()
        identifier='call-app-'+str(len(self.sent)+1).zfill(3)+'-'+uuid.uuid4().hex[:8]
        call={'id':identifier,'name':name,'arguments':copy.deepcopy(arguments)};self.sent[identifier]=call;self.pending.append(identifier);return call
    def _accept(self,messages):
        if type(messages) is not list or not 1<=len(messages)<=MAX_MESSAGES:raise ScriptError()
        seen=set();last=[]
        for message in messages:
            if type(message) is not dict or message.get('role') not in ('system','developer','user','assistant','tool'):raise ScriptError()
            if message['role']!='tool':continue
            identifier=message.get('tool_call_id')
            if identifier not in self.sent or identifier in seen or 'name' in message and message['name']!=self.sent[identifier]['name']:raise ScriptError()
            seen.add(identifier);payload=parse_tool_result(message.get('content'))
            if identifier in self.results:
                if self.results[identifier]!=payload:raise ScriptError()
            else:self.results[identifier]=payload
        if len(seen)>MAX_TOOL_RESULTS or any(identifier not in seen for identifier in self.results):raise ScriptError()
        if any(identifier not in self.results for identifier in self.pending):raise ScriptError()
        for identifier in self.pending:last.append(self.results[identifier])
        self.pending=[];return last
    def _identity(self,value):
        if value.get('ok') is not True or any(value.get(key)!=expected for key,expected in PARTICIPANT.items()):raise ScriptError()
        _receipt(value.get('receipt_id'));self.identity_succeeded=True
    def _page(self,value,state):
        page=value.get('pagination')
        if value.get('ok') is not True or type(page) is not dict or page.get('state')!=state:raise ScriptError()
        identifier=_receipt(value.get('receipt_id'));items=value.get('items')
        if type(items) is not list or len(items)!=(2 if state=='more' else 1):raise ScriptError()
        for item in items:
            _exact(item,{'id','text'});_text(item['id'],16);_text(item['text'],512)
        cursor=page.get('cursor')
        if state=='more':_sha(cursor)
        elif cursor is not None:raise ScriptError()
        self.pages.append(identifier);self.records.extend(copy.deepcopy(items));return cursor
    def _summary(self):
        if [item['id'] for item in self.records]!=['r1','r2','r3']:raise ScriptError()
        return '# Team summary\n\n'+''.join('- '+item['id']+': '+item['text']+'\n' for item in self.records)
    def _report(self):
        return {'schema':1,'document_type':'application_completion_report','contract_id':'participant-report','participant':copy.deepcopy(PARTICIPANT),
            'artifacts':[{'id':'summary','path':'outputs/summary.md','sha256':self.artifact['sha256'],'bytes':self.artifact['bytes']}],
            'pagination':{'list-records':list(self.pages)},
            'publications':[{'id':'summary-publication','receipt_id':self.publication['receipt_id']}] if self.publication.get('ok') is True else [],
            'unresolved':[] if self.publication.get('ok') is True else ['publication_outcome_unknown' if self.publication.get('outcome')=='outcome_unknown' else 'publication_failed']}
    def respond(self,messages,available_tools):
        if self.finished or self.held:raise ScriptError()
        if type(available_tools) not in (set,list,tuple) or len(set(available_tools))!=len(available_tools) or set(available_tools)-ALLOWED_TOOLS:raise ScriptError()
        actual=self._accept(messages)
        calls=[];hold=False
        try:
            if self.step==0:
                args=api_input('identity-bob' if self.scenario=='wrong-actor' else 'identity')
                if self.scenario=='invalid-request':args['unreviewed_header']='deliberately-invalid'
                calls=[self._call('app_api',args)]
            elif self.scenario in ('invalid-request','wrong-actor'):
                # Native SDK schema validation runs before tool_call and may
                # return plain Error.message, not the helper reason catalog.
                # Only this intentional invalid-input case accepts a bounded
                # failure marker; the parent independently grades denial/noHTTP.
                if (len(actual)!=1 or actual[0].get('ok') is not False
                        or self.scenario=='wrong-actor' and actual[0].get('reason')!='participant_mismatch'):self.unexpected_results+=1
                self.finished=True
            elif self.scenario=='native-reserve':
                if self.step==1:
                    self._identity(actual[0]);calls=[]
                    for _ in range(12):
                        args=api_input('list-records');args['path_params']={'undeclared':'invalid'};calls.append(self._call('app_api',args))
                else:
                    reasons=[item.get('reason') for item in actual]
                    if reasons!=['request_invalid']*9+['reporting_only']*3:self.unexpected_results+=1
                    self.finished=True
            elif self.scenario=='participant-interruption':
                if self.step==1:self._identity(actual[0]);calls=[self._call('budget_status',{})]
                else:
                    if actual[0].get('document_type')!='native_tool_budget_status' or actual[0].get('accounting')!='available':raise ScriptError()
                    self.held=True;hold=True
            elif self.step==1:
                self._identity(actual[0]);calls=[self._call('app_api',api_input('list-records'))]
            elif self.step==2:
                cursor=self._page(actual[0],'more');calls=[self._call('app_api',api_input('list-records',cursor=cursor))]
            elif self.step==3:
                self._page(actual[0],'exhausted');calls=[self._call('artifact_write',{'artifact_id':'summary','content':self._summary()})]
            elif self.step==4:
                value=actual[0]
                if value.get('ok') is not True or value.get('artifact_id')!='summary' or type(value.get('bytes')) is not int or value['bytes']!=len(self._summary().encode()) or _sha(value.get('sha256'))!=hashlib.sha256(self._summary().encode()).hexdigest():raise ScriptError()
                self.artifact={'sha256':value['sha256'],'bytes':value['bytes']}
                calls=[self._call('app_api',api_input('publish-summary',body={'target_id':'team-summary','artifact_id':'summary','artifact_sha256':value['sha256']}))]
            elif self.step==5:
                value=actual[0];self.publication=copy.deepcopy(value)
                if value.get('ok') is True:_receipt(value.get('receipt_id'))
                elif self.scenario!='commit-response-loss' or value.get('outcome')!='outcome_unknown':self.unexpected_results+=1
                if self.scenario=='omitted-report':self.finished=True
                else:calls=[self._call('report_write',{'report':self._report()})]
            else:self.finished=True
        except (ValueError,KeyError,IndexError,TypeError,AttributeError):
            self.unexpected_results+=1;self.finished=True;calls=[];self.pending=[]
        if any(call['name'] not in available_tools for call in calls):raise ScriptError()
        self.step+=1
        return {'calls':calls,'hold':hold,'finished':self.finished,'text':'SCRIPTED_SCENARIO_SETTLED' if self.finished else ''}


def bootstrap(value):
    _exact(value,{'schema','document_type','case_id','model','inference_key','lifetime_seconds'})
    if type(value['schema']) is not int or value['schema']!=1 or value['document_type']!='application_scripted_bootstrap' or (value['case_id'],value['model']) not in SCENARIOS:raise ScriptError()
    key=_text(value['inference_key'],4096)
    if not key.isascii() or len(key)<16 or any(ord(ch)<=32 or ord(ch)==127 for ch in key):raise ScriptError()
    if type(value['lifetime_seconds']) is not int or not 1<=value['lifetime_seconds']<=900:raise ScriptError()
    return copy.deepcopy(value)


def _directory(path):
    path=Path(path).absolute()
    if '..' in path.parts:raise ScriptError()
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
        info=os.fstat(fd)
        if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077:raise ScriptError()
        return fd
    except BaseException:os.close(fd);raise


def read_bootstrap(path):
    if path=='-':
        chunks=[];size=0;deadline=time.monotonic()+5
        while size<=65536:
            if time.monotonic()>=deadline or not select.select([0],[],[],max(0,deadline-time.monotonic()))[0]:raise ScriptError()
            chunk=os.read(0,min(65537-size,8192))
            if not chunk:break
            chunks.append(chunk);size+=len(chunk)
        raw=b''.join(chunks)
    else:
        path=Path(path).absolute();parent=_directory(path.parent)
        try:
            fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            with os.fdopen(fd,'rb') as stream:
                info=os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077 or info.st_size>65536:raise ScriptError()
                raw=stream.read(65537)
        finally:os.close(parent)
    if len(raw)>65536:raise ScriptError()
    return bootstrap(strict(raw))


def sse_frames(model,decision,prompt_bytes=1):
    identifier='chatcmpl-app-'+uuid.uuid4().hex
    def event(delta,finish=None,usage=None):
        value={'id':identifier,'object':'chat.completion.chunk','created':int(time.time()),'model':model,
            'choices':[{'index':0,'delta':delta,'finish_reason':finish}]}
        if usage is not None:value['usage']=usage
        return b'data: '+canonical(value)+b'\n\n'
    frames=[event({'role':'assistant','content':None})]
    calls=decision['calls']
    if calls:
        frames.append(event({'tool_calls':[{'index':index,'id':call['id'],'type':'function','function':{'name':call['name'],'arguments':''}} for index,call in enumerate(calls)]}))
        for index,call in enumerate(calls):
            arguments=canonical(call['arguments']).decode()
            for offset in range(0,len(arguments),512):frames.append(event({'tool_calls':[{'index':index,'function':{'arguments':arguments[offset:offset+512]}}]}))
    else:frames.append(event({'content':decision['text']}))
    reply_bytes=max(1,len(canonical(calls if calls else decision['text'])))
    if reply_bytes>MAX_TOKENS or type(prompt_bytes) is not int or not 1<=prompt_bytes<=CONTEXT_WINDOW-MAX_TOKENS:raise ScriptError()
    # These explicitly synthetic protocol units exercise provider usage fields;
    # they are not tokenization/performance measurements. Byte admission above
    # remains independent of the fixed16k reported stage-token budget.
    frames.extend([event({},'tool_calls' if calls else 'stop',WIRE_USAGE),b'data: [DONE]\n\n'])
    if len(frames)>128 or any(len(frame)>8192 for frame in frames) or sum(map(len,frames))>65536:raise ScriptError()
    return frames


class ScriptedServer:
    def __repr__(self):return '<ApplicationScriptedServer private bootstrap withheld>'
    def __init__(self,configuration,observations,*,host='127.0.0.1',port=0):
        self.config=bootstrap(configuration);self.machine=ScriptMachine(self.config['case_id'],self.config['model'])
        if host not in ('127.0.0.1','0.0.0.0') or type(port) is not int or not 0<=port<=65535:raise ScriptError()
        self.path=Path(observations).absolute();self.directory=_directory(self.path.parent)
        if self.path.name in ('.','..') or self.path.exists() or self.path.is_symlink():os.close(self.directory);raise ScriptError()
        self.stop_event=threading.Event();self.lock=threading.RLock();self.inference_lock=threading.Lock();self.started=time.monotonic();self.thread=None
        self.data={'schema':1,'document_type':'application_scripted_observations','case_id':self.config['case_id'],'model':self.config['model'],
            'scenario':self.machine.scenario,'requests':0,'responses':0,'rejected':0,'tool_results':0,'emitted_tool_calls':0,
            'identity_succeeded':False,'held':False,'client_disconnected':False,'stopped':False,'unexpected_results':0,'phase':'ready',
            'usage_accounting':'synthetic_fixed_16_16',
            'rejections_by_stage':{stage:0 for stage in REJECTION_STAGES},'last_rejection_stage':None}
        self._note()
        owner=self
        class Handler(BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def log_message(self,*args):pass
            def setup(self):
                super().setup();self.connection.settimeout(2);self.timer=None;self.deadline(5)
            def deadline(self,seconds):
                if self.timer is not None:self.timer.cancel()
                def expire():
                    try:self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:pass
                self.timer=threading.Timer(seconds,expire);self.timer.daemon=True;self.timer.start()
            def finish(self):
                if self.timer is not None:self.timer.cancel()
                try:super().finish()
                except OSError:pass
            def reply(self,status,value):
                raw=canonical(value)
                if len(raw)>16384:raise ScriptError()
                self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.send_header('Connection','close');self.end_headers();self.wfile.write(raw);self.wfile.flush();self.close_connection=True
            def authorized(self):
                values=self.headers.get_all('Authorization',[]);candidate=values[0] if len(values)==1 else ''
                valid=candidate.isascii() and len(candidate)<=4110
                return hmac.compare_digest(candidate.encode() if valid else b'',('Bearer '+owner.config['inference_key']).encode()) and valid
            def parse_request(self):
                if not super().parse_request():return False
                with owner.lock:
                    if owner.data['requests']>=MAX_REQUESTS or time.monotonic()-owner.started>=owner.config['lifetime_seconds']:
                        self.reply(429,{'error':'request_limit'});return False
                    owner.data['requests']+=1;owner._note()
                return True
            def do_GET(self):
                if not self.authorized():return self.reply(401,{'error':'unauthorized'})
                if self.path!='/v1/models':return self.reply(404,{'error':'not_found'})
                self.reply(200,{'object':'list','data':[{'id':owner.config['model'],'object':'model','context_window':CONTEXT_WINDOW,'max_tokens':MAX_TOKENS,'input':['text'],'reasoning':False}]})
            def do_POST(self):
                locked=False;stage='framing'
                try:
                    if self.path!='/v1/chat/completions':return self.reply(404,{'error':'not_found'})
                    if not self.authorized():return self.reply(401,{'error':'unauthorized'})
                    if not owner.inference_lock.acquire(False):return self.reply(429,{'error':'inference_busy'})
                    locked=True
                    if self.headers.get('Transfer-Encoding') is not None or len(self.headers.get_all('Content-Length',[]))!=1:raise ScriptError()
                    length=self.headers['Content-Length']
                    if not length.isascii() or not length.isdecimal() or not 0<int(length)<=MAX_BODY:raise ScriptError()
                    raw=self.rfile.read(int(length))
                    if len(raw)!=int(length):raise ScriptError()
                    stage='json';body=strict(raw)
                    stage='request_contract';owner._validate_request(body)
                    if body.get('stream') is not True:
                        stage='response_write'
                        return self.reply(200,{'id':'scripted-health','object':'chat.completion','model':owner.config['model'],
                            'choices':[{'index':0,'message':{'role':'assistant','content':'OK'},'finish_reason':'stop'}],
                            'usage':copy.deepcopy(WIRE_USAGE)})
                    tools=body.get('tools',[]);available={tool['function']['name'] for tool in tools}
                    stage='scenario'
                    decision=owner.machine.respond(body['messages'],available)
                    with owner.lock:
                        owner.data.update(tool_results=len(owner.machine.results),emitted_tool_calls=len(owner.machine.sent),identity_succeeded=owner.machine.identity_succeeded,
                            unexpected_results=owner.machine.unexpected_results,held=decision['hold'],phase='holding_after_identity' if decision['hold'] else 'settled' if decision['finished'] else 'tool_calls')
                        owner._note()
                    if decision['hold']:
                        stage='response_write'
                        remaining=min(180,max(0,owner.config['lifetime_seconds']-(time.monotonic()-owner.started)));self.deadline(remaining+1)
                        deadline=time.monotonic()+remaining
                        while not owner.stop_event.is_set() and time.monotonic()<deadline:
                            ready,_,_=select.select([self.connection],[],[],0.05)
                            if ready:
                                if not self.connection.recv(1,socket.MSG_PEEK):
                                    with owner.lock:owner.data['client_disconnected']=True;owner._note()
                                break
                        self.close_connection=True;return
                    stage='response_frames';frames=sse_frames(owner.config['model'],decision,max(1,len(canonical(body['messages']))))
                    stage='response_write'
                    self.send_response(200);self.send_header('Content-Type','text/event-stream');self.send_header('Cache-Control','no-cache');self.send_header('Connection','close');self.end_headers()
                    for frame in frames:self.wfile.write(frame);self.wfile.flush()
                    self.close_connection=True
                    with owner.lock:owner.data['responses']+=1;owner._note()
                except (OSError,ValueError,KeyError,TypeError,AttributeError,RecursionError):
                    with owner.lock:owner._record_rejection(stage)
                    try:self.reply(400,{'error':'scripted_request_rejected'})
                    except OSError:pass
                finally:
                    if locked:owner.inference_lock.release()
        class Server(ThreadingHTTPServer):
            daemon_threads=False
            def __init__(self,*args):self.slots=threading.BoundedSemaphore(2);super().__init__(*args)
            def process_request(self,request,address):
                if not self.slots.acquire(False):self.shutdown_request(request);return
                try:super().process_request(request,address)
                except BaseException:self.slots.release();raise
            def process_request_thread(self,request,address):
                try:super().process_request_thread(request,address)
                finally:self.slots.release()
            def handle_error(self,*args):pass
        try:self.server=Server((host,port),Handler)
        except BaseException:os.close(self.directory);raise
        self.base_url='http://127.0.0.1:'+str(self.server.server_port)+'/v1'
    def _note(self):
        raw=canonical(self.data);temporary='.'+self.path.name+'-'+uuid.uuid4().hex
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.directory)
        try:
            with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
            os.replace(temporary,self.path.name,src_dir_fd=self.directory,dst_dir_fd=self.directory);os.fsync(self.directory)
        finally:
            try:os.unlink(temporary,dir_fd=self.directory)
            except FileNotFoundError:pass
    def _record_rejection(self,stage):
        # Source-owned labels only: no payload, field names, headers, exception
        # strings or hashes of private values may enter retained diagnostics.
        if stage not in REJECTION_STAGES:raise ScriptError()
        self.data['rejected']+=1;self.data['rejections_by_stage'][stage]+=1
        self.data['last_rejection_stage']=stage;self._note()
    def _validate_request(self,body):
        fields={'model','messages','tools','tool_choice','parallel_tool_calls','stream','max_tokens','max_completion_tokens','temperature','top_p',
            'frequency_penalty','presence_penalty','stop','seed','stream_options','reasoning_effort','chat_template_kwargs','enable_thinking','top_k','min_p','repetition_penalty','user','store'}
        if type(body) is not dict or set(body)-fields or body.get('model')!=self.config['model'] or type(body.get('messages')) is not list or not 1<=len(body['messages'])<=MAX_MESSAGES:raise ScriptError()
        if len(canonical(body['messages']))>CONTEXT_WINDOW-MAX_TOKENS:raise ScriptError()
        if 'store' in body and body['store'] is not False:raise ScriptError()
        if 'stream' in body and type(body['stream']) is not bool:raise ScriptError()
        for field in ('max_tokens','max_completion_tokens'):
            if field in body and (type(body[field]) is not int or not 1<=body[field]<=MAX_TOKENS):raise ScriptError()
        if body.get('reasoning_effort') not in (None,'off','none') or body.get('enable_thinking',False) is not False:raise ScriptError()
        if 'chat_template_kwargs' in body:
            _exact(body['chat_template_kwargs'],{'enable_thinking'})
            if body['chat_template_kwargs']['enable_thinking'] is not False:raise ScriptError()
        if 'parallel_tool_calls' in body and type(body['parallel_tool_calls']) is not bool:raise ScriptError()
        if 'tool_choice' in body and (type(body['tool_choice']) is not str or body['tool_choice'] not in ('auto','required','none')
                or body.get('stream') is True and body['tool_choice']=='none'):raise ScriptError()
        if 'stream_options' in body:
            _exact(body['stream_options'],{'include_usage'})
            if type(body['stream_options']['include_usage']) is not bool:raise ScriptError()
        if 'user' in body:_text(body['user'],128)
        if body.get('stop') is not None:
            stops=[body['stop']] if type(body['stop']) is str else body['stop']
            if type(stops) is not list or not 1<=len(stops)<=4:raise ScriptError()
            for stop in stops:_text(stop,512)
        for field in ('temperature','top_p','frequency_penalty','presence_penalty','seed','top_k','min_p','repetition_penalty'):
            if field in body and (type(body[field]) not in (int,float) or not math.isfinite(body[field]) or abs(body[field])>1000000):raise ScriptError()
        tools=body.get('tools',[])
        if type(tools) is not list or len(tools)>6:raise ScriptError()
        names=[]
        for tool in tools:
            if type(tool) is not dict or tool.get('type')!='function' or type(tool.get('function')) is not dict or tool['function'].get('name') not in ALLOWED_TOOLS:raise ScriptError()
            names.append(tool['function']['name'])
        if len(set(names))!=len(names):raise ScriptError()
    def start(self):
        if self.thread is not None or self.stop_event.is_set():raise ScriptError()
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':0.01},daemon=True);self.thread.start();return self
    def stop(self):
        if self.stop_event.is_set():return
        self.stop_event.set()
        if self.thread is not None:self.server.shutdown();self.thread.join(timeout=5)
        self.server.server_close()
        with self.lock:self.data['stopped']=True;self.data['phase']='stopped';self._note()
        os.close(self.directory);self.config['inference_key']=''


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--private-bootstrap',required=True);parser.add_argument('--observations',required=True)
    parser.add_argument('--host',choices=['127.0.0.1','0.0.0.0'],default='0.0.0.0');parser.add_argument('--port',type=int,default=8080);args=parser.parse_args()
    config=read_bootstrap(args.private_bootstrap);server=ScriptedServer(config,args.observations,host=args.host,port=args.port)
    requested=threading.Event()
    for kind in (signal.SIGTERM,signal.SIGINT):signal.signal(kind,lambda *_:requested.set())
    server.start()
    try:requested.wait(config['lifetime_seconds'])
    finally:server.stop()


if __name__=='__main__':main()
