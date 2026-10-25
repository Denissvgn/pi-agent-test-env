#!/usr/bin/env python3
"""Disposable bounded authenticated HTTP fixture; no keys are journaled.

The root parent starts/stops this service. Participant actions never start a
workflow: each endpoint implements one declared operation and never retries.
"""
import argparse
import copy
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import socket
import stat
import threading
import time
from urllib.parse import parse_qs,urlsplit
import uuid

HERE=Path(__file__).resolve().parent
EXPECTED=json.loads((HERE/'expected.json').read_text())
PAGE_CURSOR='fixture-page-2'
MAX_BODY=65536
MAX_REQUESTS=128


def canonical(value):return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8')
def sha(body):return hashlib.sha256(body).hexdigest()
def strict_json(body):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError()
            result[key]=value
        return result
    return json.loads(body,object_pairs_hook=pairs,parse_constant=lambda value:(_ for _ in ()).throw(ValueError()))


def summary_page():
    script="""let next=null;document.querySelector('[data-testid="load-records"]').onclick=async()=>{
const response=await fetch(next?'/records?cursor='+encodeURIComponent(next):'/records');
const value=await response.json();next=value.next_cursor;document.querySelector('[data-testid="records"]').textContent=JSON.stringify(value);};
document.querySelector('[data-testid="publish-summary"]').onclick=async()=>{
const response=await fetch('/publications',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target_id:'team-summary',artifact_id:'summary',artifact_sha256:document.querySelector('[data-testid=\"summary-hash\"]').value})});
document.querySelector('[data-testid="publication"]').textContent=JSON.stringify(await response.json());};"""
    return ('<!doctype html><html><head><meta charset="utf-8"><meta name="pi-application-page" content="diagnostic-summary-v1">'
        '<title>Authenticated team records</title></head><body><h1>Team summary</h1>'
        '<button data-testid="load-records">Load next records page</button><pre data-testid="records"></pre>'
        '<label>Summary draft<textarea data-testid="summary-editor"></textarea></label>'
        '<label>Artifact SHA-256<input data-testid="summary-hash" maxlength="64"></label>'
        '<button data-testid="publish-summary">Publish declared summary artifact</button><pre data-testid="publication"></pre>'
        '<script>'+script+'</script></body></html>').encode('utf-8')


class FixtureServer:
    def __repr__(self):return '<AuthenticatedExampleFixture private keys withheld>'
    def __init__(self,journal_dir,keys,*,mode='normal',host='127.0.0.1',port=0,readiness_id=None):
        if type(keys) is not dict or set(keys)!={'alice','bob'} or mode not in ('normal','timeout-after-commit') or host not in ('127.0.0.1','0.0.0.0') or type(port) is not int or not 0<=port<=65535:raise ValueError('Invalid fixture bootstrap')
        values=list(keys.values())
        if any(type(value) is not str or not value.isascii() or not 16<=len(value)<=4096 or any(ord(ch)<=32 or ord(ch)==127 for ch in value) for value in values) or values[0]==values[1]:raise ValueError('Distinct bounded disposable fixture keys required')
        if readiness_id is not None:
            if type(readiness_id) is not str or str(uuid.UUID(readiness_id))!=readiness_id:raise ValueError('Invalid fixture readiness identity')
        self._keys=copy.deepcopy(keys);self.mode=mode;self.readiness_id=readiness_id;self.root=Path(journal_dir).absolute()
        if self.root.is_symlink():raise ValueError('Unsafe journal directory')
        self.root.mkdir(mode=0o700,parents=True,exist_ok=True);info=self.root.stat()
        if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077 or any(self.root.iterdir()):raise ValueError('Fresh owner-private journal directory required')
        self._directory=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        self.lock=threading.RLock();self.closed=False;self.thread=None
        self.journal={'schema':1,'document_type':'application_fixture_journal','fixture_id':str(uuid.uuid4()),
            'application_id':'diagnostic-app','tenant_id':'team-1','requests':[],'pages':[],'publications':[],'closed':False}
        self._write('journal.json',self.journal)
        owner=self
        class Handler(BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'
            def log_message(self,*args):pass
            def setup(self):
                super().setup();self.connection.settimeout(2)
                self.deadline=threading.Timer(3,self.expire);self.deadline.daemon=True;self.deadline.start()
            def expire(self):
                try:self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:pass
            def finish(self):
                self.deadline.cancel()
                try:super().finish()
                except OSError:pass
            def dispatch(self):
                try:owner._dispatch(self)
                except (ValueError,OSError,UnicodeError,TimeoutError):
                    self.close_connection=True
            do_GET=dispatch;do_POST=dispatch
        class BoundedServer(ThreadingHTTPServer):
            daemon_threads=False
            def __init__(self,*args):self.slots=threading.BoundedSemaphore(8);super().__init__(*args)
            def process_request(self,request,address):
                if not self.slots.acquire(blocking=False):self.shutdown_request(request);return
                try:super().process_request(request,address)
                except BaseException:self.slots.release();raise
            def process_request_thread(self,request,address):
                try:super().process_request_thread(request,address)
                finally:self.slots.release()
        self.server=BoundedServer((host,port),Handler)
        self.base_url='http://127.0.0.1:'+str(self.server.server_port)

    @classmethod
    def from_store(cls,journal_dir,*,alice_reference,bob_reference,secrets_dir,**kwargs):
        import sys
        sys.path.insert(0,str(HERE.parents[1]/'scripts'))
        import application_credentials
        if alice_reference==bob_reference:raise ValueError('Distinct explicit references required')
        keys={'alice':application_credentials.read(alice_reference,secrets_dir),'bob':application_credentials.read(bob_reference,secrets_dir)}
        return cls(journal_dir,keys,**kwargs)

    def _write(self,name,value):
        body=canonical(value)
        if len(body)>262144:raise ValueError('Fixture journal bound exceeded')
        temporary='.'+name+'-'+uuid.uuid4().hex
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self._directory)
        try:
            with os.fdopen(fd,'wb') as stream:stream.write(body);stream.flush();os.fsync(stream.fileno())
            os.replace(temporary,name,src_dir_fd=self._directory,dst_dir_fd=self._directory);os.fsync(self._directory)
        finally:
            try:os.unlink(temporary,dir_fd=self._directory)
            except FileNotFoundError:pass

    def _actor(self,handler):
        headers=handler.headers.get_all('X-Agent-API-Key',[]);candidate=headers[0] if len(headers)==1 else ''
        valid=candidate.isascii() and len(candidate)<=4096
        candidate=candidate.encode('ascii') if valid else b'';selected=None
        for name,value in self._keys.items():
            if hmac.compare_digest(candidate,value.encode('ascii')) and valid:selected='actor-'+name
        return selected

    def _dispatch(self,h):
        route=urlsplit(h.path);actor=self._actor(h);status=200;value=None;page=None;publication=None;raw=b'';media='application/json'
        operation={'/identity':'identity','/records':'list-records','/publications':'publish-summary','/summary':'summary-page'}.get(route.path,'invalid')
        safe_path=route.path if operation!='invalid' else 'invalid'
        if h.headers.get('Transfer-Encoding') is not None or len(h.headers.get_all('Content-Length',[]))>1:raise ValueError()
        length=h.headers.get('Content-Length','0')
        if not length.isascii() or not length.isdecimal() or int(length)>MAX_BODY:raise ValueError()
        body=h.rfile.read(int(length))
        if len(body)!=int(length):raise ValueError()
        with self.lock:
            if self.closed:return
            if len(self.journal['requests'])>=MAX_REQUESTS:
                raw=canonical({'error':'request_limit'});h.send_response(429);h.send_header('Content-Length',str(len(raw)));h.send_header('Connection','close');h.end_headers();h.wfile.write(raw);h.close_connection=True;return
            if h.command=='GET' and h.path=='/summary' and h.requestline.split()[1:2]==['/summary'] and not body:raw=summary_page();media='text/html'
            elif actor is None:status=401
            elif h.command=='GET' and body:status=400
            elif h.command=='GET' and route.path=='/identity' and not route.query:
                value={**EXPECTED['participant'],'actor_id':actor}
            elif h.command=='GET' and route.path=='/records':
                query=parse_qs(route.query,keep_blank_values=True,strict_parsing=True,max_num_fields=2)
                if query not in ({},{'cursor':[PAGE_CURSOR]}):status=400
                else:
                    number=2 if query else 1;records=EXPECTED['records'][:2] if number==1 else EXPECTED['records'][2:]
                    value={'items':records,'next_cursor':PAGE_CURSOR if number==1 else None,'snapshot_id':EXPECTED['snapshot_id']}
                    page={'actor_id':actor,'page_index':number,'record_ids':[row['id'] for row in records],'snapshot_id':EXPECTED['snapshot_id']}
            elif h.command=='POST' and route.path=='/publications' and not route.query:
                value=strict_json(body)
                required={'target_id','artifact_id','artifact_sha256','content'}
                if type(value) is not dict or set(value)!=required or value!={'target_id':EXPECTED['target_id'],'artifact_id':EXPECTED['artifact_id'],'artifact_sha256':sha(EXPECTED['content'].encode()),'content':EXPECTED['content']}:status=400
                elif self.journal['publications']:status=409
                else:
                    publication={'publication_id':'fixture-publication-'+self.journal['fixture_id'],'actor_id':actor,'target_id':value['target_id'],
                        'artifact_id':value['artifact_id'],'artifact_sha256':value['artifact_sha256'],'content_sha256':sha(value['content'].encode()),
                        'content_bytes':len(value['content'].encode()),'state':'committed','response_mode':self.mode}
                    value={key:publication[key] for key in ('actor_id','target_id','artifact_sha256','publication_id')};value['state']='published'
            else:status=404
            sequence=len(self.journal['requests'])+1
            self.journal['requests'].append({'sequence':sequence,'method':h.command,'path':safe_path,'actor_id':actor,
                'operation_id':operation,'status':status,'page_index':page['page_index'] if page else None,
                'publication_id':publication['publication_id'] if publication else None})
            if page:self.journal['pages'].append({'sequence':sequence,**page})
            if publication:self.journal['publications'].append({'sequence':sequence,**publication})
            self._write('journal.json',self.journal)
        if publication and self.mode=='timeout-after-commit':
            time.sleep(1.25);h.close_connection=True
            try:h.connection.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            return
        if status!=200:value={'error':'request_rejected'};raw=b''
        raw=raw or canonical(value)
        h.send_response(status);h.send_header('Content-Type',media);h.send_header('Content-Length',str(len(raw)))
        h.send_header('Connection','close')
        if media=='text/html':h.send_header('Content-Security-Policy',"default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        h.end_headers();h.wfile.write(raw);h.wfile.flush();h.close_connection=True

    def start(self):
        if self.thread is not None or self.closed:raise ValueError('Fixture cannot restart')
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':0.01},daemon=True);self.thread.start()
        try:
            if self.readiness_id is not None:self._write_readiness('ready')
        except BaseException:
            # A readiness publication failure cannot leave a running fixture.
            # Preserve the primary error even when terminal publication fails.
            try:self.stop()
            except BaseException:pass
            raise
        return self
    def _write_readiness(self,state):
        self._write('readiness.json',{'schema':1,'document_type':'application_fixture_readiness',
            'fixture_id':self.journal['fixture_id'],'readiness_id':self.readiness_id,
            'state':state,'port':self.server.server_port})
    def stop(self):
        if self.closed:raise ValueError('Fixture already stopped')
        if self.thread is not None:self.server.shutdown();self.thread.join(timeout=3)
        self.server.server_close()
        if self.thread is not None and self.thread.is_alive():raise ValueError('Fixture writers unconfirmed')
        try:
            with self.lock:
                self.closed=True
                if self.readiness_id is not None:self._write_readiness('stopped')
                self.journal['closed']=True;self._write('journal.json',self.journal)
                body=canonical(self.journal);receipt={'schema':1,'document_type':'application_fixture_terminal_receipt',
                    'fixture_id':self.journal['fixture_id'],'journal':{'path':'journal.json','sha256':sha(body),'bytes':len(body)},
                    'process':{'exit_code':0,'cleanup_confirmed':True,'writers_stopped':True}}
                self._write('terminal-receipt.json',receipt)
        finally:
            os.close(self._directory);self._keys.clear()
        return {'path':str(self.root/'terminal-receipt.json'),'sha256':sha(canonical(receipt))}
    def __enter__(self):return self.start()
    def __exit__(self,*unused):self.stop()


def seal_parent_receipt(run_root,journal_dir,terminal_sha256):
    """Trusted parent utility after fixture stop and sealed runner cleanup.

    This derives facts from the runner's cleanup receipts and our joined fixture
    terminal receipt. It does not claim to independently inspect Docker state.
    """
    import importlib.util
    spec=importlib.util.spec_from_file_location('authenticated_example_oracle',HERE/'oracle.py')
    oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
    journal_dir=Path(journal_dir).absolute();run_root=Path(run_root).absolute()
    oracle.digest(terminal_sha256);terminal_body=oracle.read(journal_dir,'terminal-receipt.json',16384)
    terminal=oracle.strict(terminal_body)
    if oracle.sha(terminal_body)!=terminal_sha256 or not oracle.fixture_stopped(terminal):raise ValueError('Fixture stop receipt unavailable')
    journal_body=oracle.read(journal_dir,'journal.json',262144)
    if terminal['journal']!={'path':'journal.json','sha256':sha(journal_body),'bytes':len(journal_body)} or oracle.strict(journal_body).get('closed') is not True:raise ValueError('Stopped journal unavailable')
    body=oracle.read(run_root,'result.json');run=oracle.strict(body)
    if not oracle.cleaned(run):raise ValueError('Sealed runner cleanup is unconfirmed')
    receipt={'schema':1,'document_type':'authenticated_application_parent_receipt',
        'run':{'run_id':run['run_id'],'attempt_id':run['attempt_id'],'result_sha256':sha(body),'writers_stopped':True,'cleanup_confirmed':True},
        'fixture':{'fixture_id':terminal['fixture_id'],'terminal_sha256':terminal_sha256,'writers_stopped':True,'cleanup_confirmed':True}}
    if not oracle.stop_gate(receipt):raise ValueError('Parent receipt unavailable')
    fd=os.open(journal_dir,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);temporary='.parent-receipt-'+uuid.uuid4().hex
    try:
        output=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
        with os.fdopen(output,'wb') as stream:stream.write(canonical(receipt));stream.flush();os.fsync(stream.fileno())
        os.link(temporary,'parent-receipt.json',src_dir_fd=fd,dst_dir_fd=fd,follow_symlinks=False)
        os.unlink(temporary,dir_fd=fd);os.fsync(fd)
    finally:
        try:os.unlink(temporary,dir_fd=fd)
        except FileNotFoundError:pass
        os.close(fd)
    return {'path':str(journal_dir/'parent-receipt.json'),'sha256':sha(canonical(receipt))}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--journal-dir',required=True);parser.add_argument('--secrets-dir')
    parser.add_argument('--alice-reference');parser.add_argument('--bob-reference')
    parser.add_argument('--seal-run-root');parser.add_argument('--terminal-sha256')
    parser.add_argument('--host',choices=['127.0.0.1','0.0.0.0'],default='127.0.0.1');parser.add_argument('--port',type=int,default=0)
    parser.add_argument('--readiness-id')
    parser.add_argument('--mode',choices=['normal','timeout-after-commit'],default='normal');parser.add_argument('--timeout-seconds',type=int,default=300);args=parser.parse_args()
    if not 1<=args.timeout_seconds<=1800:parser.error('timeout-seconds must be in1..1800')
    if args.seal_run_root:
        if not args.terminal_sha256 or any((args.secrets_dir,args.alice_reference,args.bob_reference,args.readiness_id)):parser.error('Parent seal requires terminal SHA and no credential selectors')
        print(json.dumps({'parent_receipt':seal_parent_receipt(args.seal_run_root,args.journal_dir,args.terminal_sha256)}));return
    if not all((args.secrets_dir,args.alice_reference,args.bob_reference)) or args.terminal_sha256:parser.error('Service requires explicit private store references')
    server=FixtureServer.from_store(args.journal_dir,alice_reference=args.alice_reference,bob_reference=args.bob_reference,
        secrets_dir=args.secrets_dir,host=args.host,port=args.port,mode=args.mode,readiness_id=args.readiness_id)
    stopped=threading.Event()
    for kind in (signal.SIGINT,signal.SIGTERM):signal.signal(kind,lambda *_:stopped.set())
    server.start();print(json.dumps({'fixture_id':server.journal['fixture_id'],'base_url':server.base_url,'journal_dir':str(server.root)}),flush=True)
    stopped.wait(args.timeout_seconds);print(json.dumps({'terminal_receipt':server.stop()}),flush=True)


if __name__=='__main__':main()
