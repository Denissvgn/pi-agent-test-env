#!/usr/bin/env python3
"""Ordered Pi JSONL evidence; synthetic fixtures never establish live qualification."""
from __future__ import annotations
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"runtime"))
from usage_contract import summarize

METADATA={'thinking_level_changed','session_info_changed','entry_appended'}
UPDATES={'start','text_start','text_delta','text_end','thinking_start','thinking_delta','thinking_end',
         'toolcall_start','toolcall_delta','toolcall_end','done','error'}


def analyze(path: Path, model: str, required_tools: list[str], exit_code: int,
            completion_contract: str='settled', *, allow_retries=False, release=None, allowed_tools=None) -> dict:
    if completion_contract not in ('settled','process-exit'):raise ValueError('Unknown completion contract')
    protocol=[];policy=[];counts={};assistants=[];failed_tools=[];succeeded={}
    agent=False;turn=False;message=None;settled=False;ever_started=False
    retry=False;will_retry=False;compaction=False;compaction_retry=False;summarization=False;queue=False
    declared={};started={};finished=set();turn_calls=set();last_assistant=None;header=None;retry_attempt=0;retry_max=None;truncated_tail=False
    def error(text):protocol.append(text)
    try:records=path.read_bytes().split(b'\n')
    except OSError as exc:
        records=[];error('Event artifact unavailable: '+type(exc).__name__)
    for index,raw in enumerate(records,1):
        if not raw.strip():continue
        try:
            event=json.loads(raw)
            if not isinstance(event,dict) or not isinstance(event.get('type'),str):raise ValueError('object/type required')
        except (ValueError,UnicodeDecodeError):
            if index==len(records):truncated_tail=True
            error(f'Malformed JSONL record {index}');continue
        kind=event['type'];counts[kind]=counts.get(kind,0)+1
        if settled and kind not in METADATA|{'queue_update'}:
            error('Execution event after terminal settlement');continue
        if kind=='session':
            if header or ever_started:error('Duplicate/late session header')
            if not isinstance(event.get('id'),str) or not event['id'] or not isinstance(event.get('cwd'),str):error('Invalid session identity')
            if completion_contract=='settled' and event.get('version')!=3:error('Unsupported session schema')
            header=event
        elif kind=='agent_start':
            if agent or turn or message:error('Overlapping agent lifecycle')
            if ever_started and not (retry or will_retry or compaction_retry):error('New low-level run without pending continuation')
            agent=True;ever_started=True;will_retry=False;compaction_retry=False
        elif kind=='turn_start':
            if not agent or turn or message or compaction:error('Invalid turn_start ordering')
            turn=True;last_assistant=None;turn_calls=set()
        elif kind=='message_start':
            msg=event.get('message')
            if message is not None or not isinstance(msg,dict) or (msg.get('role')!='custom' and (not agent or not turn)):error('Invalid message_start ordering/shape');continue
            role=msg.get('role')
            if role not in ('system','user','assistant','toolResult','custom'):error('Unknown message role')
            if role=='assistant' and ((msg.get('model') is not None and msg['model']!=model) or (msg.get('provider') is not None and msg['provider']!='local-lab')):policy.append('Partial assistant identity mismatch')
            message=(role,msg.get('toolCallId'))
        elif kind=='message_update':
            update=event.get('assistantMessageEvent')
            if not message or message[0]!='assistant' or not isinstance(update,dict) or update.get('type') not in UPDATES:error('Unpaired/invalid assistant update')
            if isinstance(update,dict) and 'contentIndex' in update and (type(update['contentIndex']) is not int or update['contentIndex']<0):error('Invalid content index')
        elif kind=='message_end':
            msg=event.get('message')
            if not isinstance(msg,dict):error('Invalid completed message');continue
            if message!=(msg.get('role'),msg.get('toolCallId')):error('Unmatched message_end')
            message=None
            if msg.get('role')!='custom' and (not agent or not turn):error('Message outside active turn')
            if msg.get('role')=='assistant':
                assistants.append(msg);last_assistant=msg
                if msg.get('model')!=model or msg.get('provider')!='local-lab':policy.append('Unexpected/missing model or provider identity')
                if not isinstance(msg.get('content'),list):error('Assistant content must be an array');continue
                stop=msg.get('stopReason')
                if stop not in ('stop','toolUse','length','error','aborted'):policy.append('Unsuccessful terminal assistant state')
                for block in msg['content']:
                    if not isinstance(block,dict):error('Invalid content block');continue
                    if block.get('type')=='toolCall':
                        call=block.get('id');name=block.get('name')
                        if allowed_tools is not None and name not in allowed_tools:policy.append('Tool outside declared allowlist: '+str(name))
                        if not isinstance(call,str) or not call or call in declared or not isinstance(name,str):error('Missing/duplicate declared tool call')
                        else:declared[call]=name;turn_calls.add(call)
            elif msg.get('role')=='toolResult':
                call=msg.get('toolCallId')
                if not isinstance(call,str) or call not in finished or started.get(call)!=msg.get('toolName'):error('Unpaired tool-result message')
        elif kind in ('tool_execution_start','tool_execution_update','tool_execution_end'):
            call=event.get('toolCallId');name=event.get('toolName')
            if not isinstance(call,str) or not agent or not turn or message is not None or call not in turn_calls or declared.get(call)!=name:
                error('Unpaired/undeclared tool execution');continue
            if kind=='tool_execution_start':
                if call in started:error('Duplicate tool start')
                else:started[call]=name
            elif call not in started or call in finished:error('Duplicate/unpaired tool completion/update')
            elif kind=='tool_execution_end':
                if type(event.get('isError')) is not bool:error('Missing tool success flag')
                elif not event['isError']:succeeded[name]=succeeded.get(name,0)+1
                else:failed_tools.append(name)
                finished.add(call)
        elif kind=='turn_end':
            if not agent or not turn or message is not None or not last_assistant or turn_calls-finished:error('Incomplete/out-of-order turn_end')
            if not isinstance(event.get('toolResults'),list) or not isinstance(event.get('message'),dict):error('Invalid turn_end shape')
            turn=False
        elif kind=='agent_end':
            if not agent or turn or message is not None or set(started)-finished:error('Agent ended with incomplete lifecycle')
            if type(event.get('willRetry')) is not bool or not isinstance(event.get('messages'),list):
                if completion_contract!='process-exit':error('Invalid agent_end shape')
            agent=False;will_retry=event.get('willRetry') is True
        elif kind=='auto_retry_start':
            if agent or not ever_started or not (will_retry or retry):error('Retry without ended retryable run')
            if any(type(event.get(k)) is not int or event[k]<0 for k in ('attempt','maxAttempts','delayMs')):error('Invalid retry counters')
            attempt=event.get('attempt');maximum=event.get('maxAttempts')
            if type(attempt) is int and type(maximum) is int:
                if not 1<=attempt<=maximum or attempt!=retry_attempt+1 or (retry_max is not None and retry_max!=maximum):error('Invalid retry progression')
                retry_attempt=attempt;retry_max=maximum
            retry=True;will_retry=False
            if not allow_retries:policy.append('Retry disabled by invocation policy')
        elif kind=='auto_retry_end':
            if not retry or type(event.get('success')) is not bool:error('Unpaired retry completion')
            if event.get('success') is False:policy.append('Provider retries exhausted')
            if event.get('attempt')!=retry_attempt:error('Retry completion attempt mismatch')
            retry=False;will_retry=False;retry_attempt=0;retry_max=None
        elif kind=='compaction_start':
            if compaction or agent or turn or message is not None:error('Invalid compaction start')
            compaction=True
            if not allow_retries:policy.append('Compaction disabled by invocation policy')
        elif kind=='compaction_end':
            if not compaction or type(event.get('aborted')) is not bool or type(event.get('willRetry')) is not bool:error('Unpaired/invalid compaction end')
            compaction=False;compaction_retry=event.get('willRetry') is True
            if event.get('aborted') or event.get('errorMessage'):policy.append('Compaction failed/aborted')
        elif kind=='summarization_retry_scheduled':
            if not allow_retries:policy.append('Summarization retry disabled by invocation policy')
            summarization=True
        elif kind=='summarization_retry_attempt_start':
            if not summarization:error('Unscheduled summarization retry')
        elif kind=='summarization_retry_finished':
            if not summarization:error('Unpaired summarization retry end')
            summarization=False
        elif kind=='queue_update':
            if not isinstance(event.get('steering'),list) or not isinstance(event.get('followUp'),list):error('Invalid queue update')
            queue=bool(event.get('steering') or event.get('followUp'))
            if settled and queue:error('Queued work after settlement')
        elif kind=='agent_settled':
            if not ever_started or agent or turn or message is not None or retry or will_retry or compaction or compaction_retry or summarization or queue:error('Premature/incomplete settlement')
            settled=True
        elif kind not in METADATA:error('Unsupported lifecycle event: '+kind)
    if not ever_started or not counts.get('agent_end') or agent or turn or message is not None or retry or will_retry or compaction or compaction_retry or summarization or queue:
        error('Agent/message/tool/retry work pending at process exit')
    if set(started)-finished:error('Pending tool executions')
    if completion_contract=='settled' and (not settled or not header):error('Final settlement/session header missing')
    if completion_contract=='process-exit' and release=='0.87.1':policy.append('Legacy adapter not allowed for settled release 0.87.1')
    final=assistants[-1] if assistants else {}
    content=final.get('content') if isinstance(final.get('content'),list) else []
    text='\n'.join(b.get('text','') for b in content if isinstance(b,dict) and b.get('type')=='text' and isinstance(b.get('text'),str))
    terminal_ok=final.get('stopReason')=='stop' and bool(text.strip()) and exit_code==0
    if not terminal_ok:policy.append('No successful final assistant/process completion')
    missing=[t for t in required_tools if not succeeded.get(t)]
    if missing:policy.append('Required successful tools missing: '+','.join(missing))
    failures=[m.get('stopReason') for m in assistants if m.get('stopReason') in ('error','aborted','length')]
    if failures and not allow_retries:policy.append('Unsuccessful assistant messages retained')
    completion=not protocol and not policy
    clean=completion and not failures
    measurement=summarize(assistants)
    total=measurement['categories']['total']['reported']
    return {'schema':2,'protocol_valid':not protocol,'protocol_errors':protocol,'policy_errors':policy,
            'completion_verified':completion,'agent_invocation_verified':clean,
            'invocation_status':'verified' if clean else ('recovered' if completion and failures else 'invalid'),
            'completion_contract':completion_contract,'errors':protocol+policy,
            'unsuccessful_messages':failures,'session_id':header.get('id') if header else None,
            'session_cwd':header.get('cwd') if header else None,'events':counts,'assistant_responses':len(assistants),
            'successful_tools':succeeded,'failed_tools':failed_tools,'provider_reported_total_tokens':total,
            'usage_reported':total is not None,'usage':measurement,'response_ids':[m['responseId'] for m in assistants if isinstance(m.get('responseId'),str)],
            'final_text':text,'truncated_tail':truncated_tail,'identity_conflict':any('identity' in e for e in policy),'identity_verified':bool(assistants) and not any('identity' in e for e in policy)}
