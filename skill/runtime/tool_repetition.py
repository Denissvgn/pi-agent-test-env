"""Consecutive identical tool-call detection shared by the worker and trace analysis.

A completed tool call repeats the previous one when the tool name, canonical
arguments, result text and error flag all match. Such a run means the agent is
receiving no new information. The worker stops Pi once a run exceeds
REPEATED_TOOL_CALL_LIMIT; the parent recounts the retained trace with the same
signature before it classifies the stop as ``repeated_tool_call``. The guard
only ends a stalled stage sooner: it never turns a failed stage into a pass.
"""
from __future__ import annotations

import hashlib
import json

REPEATED_TOOL_CALL_LIMIT = 5


def result_text(result) -> str:
    """Text content of a Pi tool result; details such as timing are ignored."""
    if not isinstance(result, dict) or not isinstance(result.get('content'), list):
        return ''
    return '\n'.join(part['text'] for part in result['content']
                     if isinstance(part, dict) and isinstance(part.get('text'), str))


def call_signature(name, args, result, is_error) -> str:
    payload = json.dumps([name, args, result_text(result), bool(is_error)],
                         sort_keys=True, separators=(',', ':'), default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


class RepetitionGuard:
    """Track Pi tool events in completion order; report a run over the limit."""

    def __init__(self, limit: int = REPEATED_TOOL_CALL_LIMIT):
        self.limit = limit
        self.arguments = {}
        self.previous = None
        self.run = 0
        self.longest = 0

    def observe(self, event) -> bool:
        if not isinstance(event, dict):
            return False
        kind = event.get('type')
        call = event.get('toolCallId')
        if kind == 'tool_execution_start':
            self.arguments[call] = event.get('args')
            return False
        if kind != 'tool_execution_end':
            return False
        signature = call_signature(event.get('toolName'), self.arguments.pop(call, None),
                                   event.get('result'), event.get('isError'))
        self.run = self.run + 1 if signature == self.previous else 1
        self.previous = signature
        self.longest = max(self.longest, self.run)
        return self.exceeded

    @property
    def exceeded(self) -> bool:
        return self.longest > self.limit

    def summary(self) -> dict:
        return {'longest_identical_run': self.longest, 'limit': self.limit}
