"""Disposable scripted inference/actor authority for parallel native qualification.

Captures identities, scalar settings and effects only. All keys are disposable.
"""
import argparse
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
from pathlib import Path
import threading
import time

from service import sequence


def handler(authority):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*unused):pass
        def reply(self,value,status=200):
            body=json.dumps(value).encode();self.send_response(status);self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(body)));self.end_headers()
            try:self.wfile.write(body)
            except (BrokenPipeError,ConnectionResetError):pass
        def do_GET(self):
            config=authority.config()
            if self.path.startswith('/sentinel'):authority.note('sentinel_network_effect',True)
            if self.path=='/observer' and self.headers.get('X-Qualification-Observer')==config['observer_key']:
                with authority.lock:return self.reply(dict(authority.data))
            if self.path=='/v1/models':return self.reply({'data':[{'id':'qualification-diagnostic','context_length':32768}]})
            return self.reply({'error':'not found'},404)
        def do_POST(self):
            config=authority.config()
            try:
                size=int(self.headers.get('Content-Length',0))
                if not 0<size<=2*1024*1024:raise ValueError('bounded body')
                body=json.loads(self.rfile.read(size))
            except (ValueError,OSError):return self.reply({'error':'invalid'},400)
            if self.path=='/effect':
                actor=next((a for a in config['actors'] if a['key']==self.headers.get('X-Agent-Key')),None)
                namespace=self.headers.get('X-Trial-ID','')
                if actor is None or body.get('nonce')!=actor['nonce'] or not namespace:return self.reply({'error':'forbidden'},403)
                value={'role':actor['role'],'nonce':actor['nonce'],'effect':'recorded'}
                authority.note('effects',{**value,'case':actor['case'],'run_id':namespace});return self.reply(value)
            if self.path!='/v1/chat/completions':
                if self.path.startswith('/sentinel'):authority.note('sentinel_network_effect',True)
                return self.reply({'error':'not found'},404)
            if self.headers.get('Authorization')!='Bearer '+config['inference_key']:return self.reply({'error':'unauthorized'},401)
            if body.get('model')!='qualification-diagnostic':return self.reply({'error':'model'},400)
            authority.note('requests',{'stream':body.get('stream') is True,'max_tokens':body.get('max_tokens'),
                                      'reasoning_effort':body.get('reasoning_effort'),'completed_tools':sum(m.get('role')=='tool' for m in body.get('messages',[]))})
            if not body.get('stream'):return self.reply({'choices':[{'message':{'role':'assistant','content':'OK'},'finish_reason':'stop'}]})
            deadline=time.monotonic()+20
            while not config['dispatch_enabled']:
                if time.monotonic()>=deadline:return self.reply({'error':'scripted barrier deadline'},503)
                time.sleep(.02);config=authority.config()
            mode=config['mode'];completed=sum(m.get('role')=='tool' for m in body.get('messages',[]))
            if mode=='boundary' and completed>=7:
                deadline=time.monotonic()+20
                while not config.get('boundary_release',True):
                    if time.monotonic()>=deadline:return self.reply({'error':'boundary evidence deadline'},503)
                    time.sleep(.02);config=authority.config()
            if mode=='provider-fatal':return self.reply({'error':{'message':'deliberate scripted provider failure'}},503)
            commands=sequence(mode)
            if mode in ('abort','timeout','recovery','crash'):
                commands=[{'type':'function','function':{'name':'read','arguments':json.dumps({'path':'/workspace/TASK.md'})}},
                          {'type':'function','function':{'name':'bash','arguments':json.dumps({'command':
                           "python3 -c \"import os,time,json;from pathlib import Path;Path('recovered.txt').write_text('RECOVERED');k=os.environ.get('PI_APP_KEY','');Path(os.environ['TMPDIR'],'canary').write_text(k);print(json.dumps(k),flush=True);time.sleep(180)\""})}}]
            if mode in ('recovery-finish','crash-finish'):
                observed=[m for m in body.get('messages',[]) if m.get('role')=='tool']
                if not observed:
                    calls=[{'name':'read','arguments':{'path':'/workspace/TASK.md'}}]
                elif not any('RECOVERY_EFFECT_OK' in json.dumps(m) for m in observed):
                    calls=[{'name':'bash','arguments':{'command':
                          "python3 -c \"open('recovered.txt','w').write('RECOVERED');print('RECOVERY_EFFECT_OK')\""}}]
                else:calls=[]
            else:
                # Existing sequence() uses the same OpenAI tool shape.
                calls=commands[completed:completed+1]
            delta={'role':'assistant'}
            if calls:
                item=calls[0];function=item.get('function',item)
                arguments=function.get('arguments',{})
                if not isinstance(arguments,str):arguments=json.dumps(arguments)
                delta['tool_calls']=[{'index':0,'id':'parallel-call-'+str(completed),'type':'function',
                                     'function':{'name':function['name'],'arguments':arguments}}]
            else:delta['content']='SCRIPTED_FINISHED'
            chunk={'id':'parallel-scripted','object':'chat.completion.chunk','model':'qualification-diagnostic',
                   'choices':[{'index':0,'delta':delta,'finish_reason':None}]}
            end={'id':'parallel-scripted','object':'chat.completion.chunk','model':'qualification-diagnostic',
                 'choices':[{'index':0,'delta':{},'finish_reason':'tool_calls' if calls else 'stop'}],
                 'usage':{'prompt_tokens':64,'completion_tokens':32,'total_tokens':96}}
            raw=('data: '+json.dumps(chunk)+'\n\ndata: '+json.dumps(end)+'\n\ndata: [DONE]\n\n').encode()
            self.send_response(200);self.send_header('Content-Type','text/event-stream');self.send_header('Content-Length',str(len(raw)));self.end_headers()
            try:self.wfile.write(raw)
            except (BrokenPipeError,ConnectionResetError):pass
    return Handler


class Authority:
    def __init__(self,config,output):
        self.path=Path(config);self.output=Path(output);self.lock=threading.RLock()
        self.data={'effects':[],'requests':[],'sentinel_network_effect':False}
    def config(self):
        deadline=time.monotonic()+1
        while True:
            try:return json.loads(self.path.read_text())
            except FileNotFoundError:
                if time.monotonic()>=deadline:raise
                time.sleep(.01)
    def note(self,name,value):
        with self.lock:
            if name in ('effects','requests'):self.data[name].append(value)
            else:self.data[name]=value
            temp=self.output.with_suffix('.pending');temp.write_text(json.dumps(self.data));temp.replace(self.output)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True);parser.add_argument('--output',required=True)
    args=parser.parse_args();authority=Authority(args.config,args.output)
    ThreadingHTTPServer(('0.0.0.0',8080),handler(authority)).serve_forever()
