"""Owned diagnostic inference/application authority. Responses are explicitly synthetic.

Private control holds disposable credentials. Public observations never contain
headers, prompts, tool arguments/results or credential values.
"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
import time
import select
import socket


def tool(name, arguments):
    return {'name': name, 'arguments': arguments}


def sequence(mode):
    read = tool('read', {'path': '/workspace/TASK.md'})
    if mode == 'boundary':
        return [read,
            tool('write', {'path': '/etc/pi-qualification-denied', 'content': 'BAD'}),
            tool('edit', {'path': '/etc/hostname', 'oldText': 'host', 'newText': 'BAD'}),
            tool('write', {'path': '/workspace/escape/pi-qualification-denied', 'content': 'BAD'}),
            tool('bash', {'command': 'printf BAD > /opt/pi-control/task.json'}),
            tool('write', {'path': '/workspace/allowed.txt', 'content': 'OK'}),
            tool('bash', {'command': "python3 -c \"import os;from pathlib import Path;p=Path(os.environ['TMPDIR'])/'allowed';p.write_text('OK');assert p.read_text()=='OK';print('PRIVATE_TEMP_OK')\""})]
    if mode == 'contamination':
        return [read, tool('bash', {'command': "python3 -c \"import os;open('leak.txt','w').write(os.environ['PI_APP_KEY'])\""})]
    if mode == 'timeout':
        return [read, tool('bash', {'command': "python3 -c \"import os,time,json,sys;from pathlib import Path;k=os.environ['PI_APP_KEY'];Path(os.environ['TMPDIR'],'canary').write_text(k);b=k.encode();os.write(1,b[:len(b)//2]);time.sleep(.02);os.write(1,b[len(b)//2:]+b'\\n');print(json.dumps(k),file=sys.stderr,flush=True);time.sleep(60)\""})]
    if mode in ('recovery', 'crash', 'recovery-finish', 'crash-finish'):
        return [read, tool('bash', {'command': "python3 -c \"open('recovered.txt','w').write('RECOVERED');print('RECOVERY_EFFECT_OK')\""})]
    if mode == 'discovery':
        return [read, tool('bash', {'command': "python3 -c \"from pathlib import Path;assert not Path('SENTINEL_EXECUTED').exists();print('DISCOVERY_SUPPRESSED')\""})]
    return []


class Authority:
    def __init__(self, control, observations):
        self.control = Path(control); self.observations = Path(observations)
        self.lock = threading.Lock()
        self.data = {'requests': [], 'effects': [], 'held': False}

    def config(self):
        # Docker Desktop can briefly expose ENOENT while a host atomic rename
        # becomes visible through the directory bind. Wait only for that
        # transition; malformed or unreadable controls still fail immediately.
        deadline = time.monotonic() + 1
        while True:
            try:
                return json.loads(self.control.read_text())
            except FileNotFoundError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.01)

    def note(self, field, value):
        with self.lock:
            if field in ('requests', 'effects'): self.data[field].append(value)
            else: self.data[field] = value
            temp = self.observations.with_suffix('.pending')
            temp.write_text(json.dumps(self.data, sort_keys=True))
            temp.replace(self.observations)

    def reset(self):
        with self.lock: self.data = {'requests': [], 'effects': [], 'held': False}
        self.note('held', False)


def handler(authority):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def reply(self, value, status=200):
            body = json.dumps(value).encode()
            self.send_response(status); self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body))); self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            config = authority.config()
            if self.path.startswith('/sentinel'):
                authority.note('sentinel_network_effect', True)
                return self.reply({'error': 'sentinel'}, 403)
            if self.path == '/v1/models':
                return self.reply({'data': [{'id': 'qualification-diagnostic', 'context_window': 32768}]})
            if self.path == '/observer' and self.headers.get('X-Qualification-Observer') == config['observer_key']:
                with authority.lock: value = dict(authority.data)
                return self.reply(value)
            self.reply({'error': 'not found'}, 404)

        def do_POST(self):
            try:
                size = int(self.headers.get('Content-Length', 0))
                if not 0 < size <= 2 * 1024 * 1024: return self.reply({'error': 'bounded request required'}, 400)
                body = json.loads(self.rfile.read(size))
                config = authority.config()
                if self.path.startswith('/sentinel'):
                    authority.note('sentinel_network_effect', True)
                    return self.reply({'error': 'sentinel'}, 403)
                if self.path == '/reset' and self.headers.get('X-Qualification-Observer') == config['observer_key']:
                    authority.reset(); return self.reply({'reset': True})
                if self.path == '/effect':
                    key = self.headers.get('X-Agent-Key')
                    role = next((r for r, value in config['app_keys'].items() if value == key), None)
                    if role is None or body.get('nonce') != config['nonce']:
                        return self.reply({'error': 'forbidden'}, 403)
                    result = {'role': role, 'nonce': body['nonce'], 'effect': 'recorded'}
                    authority.note('effects', result); return self.reply(result)
                if self.path != '/v1/chat/completions': return self.reply({'error': 'not found'}, 404)
                if self.headers.get('Authorization') != 'Bearer ' + config['inference_key']:
                    return self.reply({'error': 'unauthorized'}, 401)
                if body.get('model') != 'qualification-diagnostic':
                    return self.reply({'error': 'unexpected diagnostic model'}, 400)
                safe = {'model': 'qualification-diagnostic'}
                for key in ('stream', 'enable_thinking'):
                    if type(body.get(key)) is bool: safe[key] = body[key]
                for key in ('max_tokens', 'max_completion_tokens', 'temperature', 'top_p',
                            'min_p', 'top_k', 'repetition_penalty', 'seed'):
                    if type(body.get(key)) in (int, float): safe[key] = body[key]
                if body.get('reasoning_effort') in ('off', 'minimal', 'low', 'medium', 'high'):
                    safe['reasoning_effort'] = body['reasoning_effort']
                template = body.get('chat_template_kwargs')
                if isinstance(template, dict) and type(template.get('enable_thinking')) is bool:
                    safe['chat_template_kwargs'] = {'enable_thinking': template['enable_thinking']}
                # Only whitelisted scalar/settings fields; no message/authorization capture.
                authority.note('requests', safe)
                if not body.get('stream'):
                    return self.reply({'id': 'diagnostic-health', 'object': 'chat.completion',
                        'model': body['model'], 'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': 'OK'}, 'finish_reason': 'stop'}],
                        'usage': {'prompt_tokens': 8, 'completion_tokens': 1, 'total_tokens': 9}})
                mode = config['mode']
                completed_tools = sum(1 for msg in body.get('messages', []) if msg.get('role') == 'tool')
                if (mode in ('abort', 'provider-fatal') or mode in ('recovery', 'crash') and completed_tools >= 1
                        or mode == 'boundary' and completed_tools >= len(sequence('boundary'))):
                    authority.note('held', True)
                    deadline = time.monotonic() + 180
                    while time.monotonic() < deadline:
                        if mode in ('abort', 'recovery', 'crash'):
                            ready, _, _ = select.select([self.connection], [], [], .05)
                            if ready and not self.connection.recv(1, socket.MSG_PEEK): return
                            # A mode switch affects a successor, never completes the interrupted request.
                            continue
                        newer = authority.config()
                        if newer['mode'] != mode:
                            config = newer; mode = newer['mode']; break
                        time.sleep(.05)
                    if mode in ('abort', 'recovery', 'crash'): return
                if mode in ('error', 'provider-fatal', 'rate-error'):
                    return self.reply({'error': {'message': 'deliberate diagnostic provider failure', 'type': 'qualification'}},
                                      429 if mode == 'rate-error' else 503)
                calls = sequence(mode)
                batch = []
                if mode == 'boundary':
                    # Three bounded tool batches plus final completion fit the
                    # frozen six-turn diagnostic cap; never relax its budget.
                    groups = {0: calls[:1], 1: calls[1:4], 4: calls[4:7]}
                    batch = groups.get(completed_tools, [])
                elif completed_tools < len(calls): batch = [calls[completed_tools]]
                finish = 'length' if mode == 'length' else ('tool_calls' if batch else 'stop')
                delta = {'role': 'assistant'}
                if batch:
                    delta['tool_calls'] = [{'index': i, 'id': 'qualification-call-' + str(completed_tools+i),
                        'type': 'function', 'function': {'name': call['name'], 'arguments': json.dumps(call['arguments'])}}
                        for i, call in enumerate(batch)]
                else: delta['content'] = 'DIAGNOSTIC_FINISHED'
                self.send_response(200); self.send_header('Content-Type', 'text/event-stream')
                self.send_header('Cache-Control', 'no-cache'); self.end_headers()
                def event(choices, usage=None):
                    value = {'id': 'qualification-response', 'object': 'chat.completion.chunk',
                             'created': int(time.time()), 'model': body['model'], 'choices': choices}
                    if usage is not None: value['usage'] = usage
                    self.wfile.write(('data: ' + json.dumps(value) + '\n\n').encode()); self.wfile.flush()
                event([{'index': 0, 'delta': delta, 'finish_reason': None}])
                event([{'index': 0, 'delta': {}, 'finish_reason': finish}],
                      {'prompt_tokens': 20, 'completion_tokens': 10, 'total_tokens': 30})
                self.wfile.write(b'data: [DONE]\n\n'); self.wfile.flush()
            except (OSError, ValueError, KeyError):
                # Never include a request body, credentials or exception payload in logs.
                try: self.reply({'error': 'diagnostic request failed'}, 400)
                except OSError: pass
    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--control', required=True); parser.add_argument('--observations', required=True)
    parser.add_argument('--port', type=int, default=8080)
    args = parser.parse_args()
    server = ThreadingHTTPServer(('0.0.0.0', args.port), handler(Authority(args.control, args.observations)))
    server.serve_forever(poll_interval=.1)


if __name__ == '__main__': main()
