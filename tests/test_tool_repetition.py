import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'skill/scripts'), str(ROOT / 'skill/runtime')]
import release_contracts
import segments
from evidence import analyze
from tool_repetition import REPEATED_TOOL_CALL_LIMIT, RepetitionGuard, call_signature
import worker


def tool_pair(index, name='ls', args=None, text='test_slug.py', is_error=False, details=None):
    call = f'call-{index}'
    result = {'content': [{'type': 'text', 'text': text}]}
    if details is not None:
        result['details'] = details
    return [{'type': 'tool_execution_start', 'toolCallId': call, 'toolName': name,
             'args': {'path': '/workspace/tests'} if args is None else args},
            {'type': 'tool_execution_end', 'toolCallId': call, 'toolName': name,
             'result': result, 'isError': is_error}]


def observe_all(guard, events):
    return [guard.observe(event) for event in events]


class RepetitionGuardTests(unittest.TestCase):
    def test_observed_loop_stops_on_the_sixth_identical_call(self):
        # The blocked reviewer: read three files, then repeated `ls /workspace/tests`.
        guard = RepetitionGuard()
        for index in range(REPEATED_TOOL_CALL_LIMIT):
            self.assertEqual(observe_all(guard, tool_pair(index)), [False, False])
        self.assertEqual(guard.summary(), {'longest_identical_run': 5, 'limit': 5})
        self.assertEqual(observe_all(guard, tool_pair(99)), [False, True])
        self.assertTrue(guard.exceeded)
        self.assertEqual(guard.longest, 6)

    def test_new_arguments_result_tool_or_error_flag_restart_the_run(self):
        variations = [dict(args={'path': '/workspace'}), dict(text='changed'), dict(name='find'),
                      dict(is_error=True)]
        for change in variations:
            with self.subTest(change=change):
                guard = RepetitionGuard()
                for index in range(4):
                    observe_all(guard, tool_pair(index))
                observe_all(guard, tool_pair(10, **change))
                for index in range(20, 24):
                    observe_all(guard, tool_pair(index))
                self.assertEqual(guard.longest, 4)
                self.assertFalse(guard.exceeded)

    def test_argument_order_and_result_details_do_not_hide_a_repeat(self):
        first = call_signature('bash', {'command': 'npm test', 'timeout': 30},
                               {'content': [{'type': 'text', 'text': 'FAIL'}], 'details': {'ms': 10}}, False)
        second = call_signature('bash', {'timeout': 30, 'command': 'npm test'},
                                {'content': [{'type': 'text', 'text': 'FAIL'}], 'details': {'ms': 99}}, False)
        self.assertEqual(first, second)
        self.assertNotEqual(first, call_signature('bash', {'command': 'npm test', 'timeout': 30},
                                                  {'content': [{'type': 'text', 'text': 'FAIL'}]}, True))

    def test_non_tool_and_malformed_events_are_ignored(self):
        guard = RepetitionGuard()
        for event in (None, 'text', {'type': 'turn_start'}, {'type': 'message_end', 'message': {}},
                      {'type': 'tool_execution_update', 'toolCallId': 'x'}):
            self.assertFalse(guard.observe(event))
        self.assertEqual(guard.longest, 0)
        # An end without a recorded start still counts, with unknown arguments.
        self.assertFalse(guard.observe(tool_pair(1)[1]))
        self.assertEqual(guard.longest, 1)


class TraceAnalysisTests(unittest.TestCase):
    def test_analysis_reports_the_longest_identical_run_from_the_retained_trace(self):
        events = [{'type': 'agent_start'}, {'type': 'turn_start'}]
        for index in range(3):
            events += tool_pair(index, name='read', args={'path': f'/workspace/file-{index}'}, text=str(index))
        for index in range(10, 19):
            events += tool_pair(index)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'stdout.jsonl'
            path.write_text('\n'.join(json.dumps(event) for event in events))
            receipt = analyze(path, 'fixture-model', [], 124, release='1.2.0')
        self.assertEqual(receipt['tool_repetition'], {'longest_identical_run': 9, 'limit': 5})
        self.assertFalse(receipt['completion_verified'])


class LimitClassificationTests(unittest.TestCase):
    process = {'exit_code': 124, 'termination_reason': 'process_error',
               'effective_limits': {'max_turns': 12, 'max_total_tokens': 128000}}

    def evidence(self, run, turns=9):
        return {'events': {'turn_start': turns}, 'usage': {'categories': {'total': {'known_sum': 1000}}},
                'tool_repetition': {'longest_identical_run': run, 'limit': REPEATED_TOOL_CALL_LIMIT}}

    def test_a_run_over_the_limit_is_classified_from_the_trace(self):
        result = segments.classify_worker_limit(copy.deepcopy(self.process), self.evidence(6))
        self.assertEqual(result['termination_reason'], 'repeated_tool_call')
        self.assertEqual(result['supervisor_termination_reason'], 'process_error')
        self.assertEqual(result['observed_budget_counts']['longest_identical_tool_run'], 6)

    def test_a_run_at_the_limit_stays_unexplained(self):
        result = segments.classify_worker_limit(copy.deepcopy(self.process), self.evidence(5))
        self.assertEqual(result['termination_reason'], 'process_error')

    def test_existing_caps_keep_precedence_and_other_causes_are_untouched(self):
        self.assertEqual(segments.classify_worker_limit(copy.deepcopy(self.process), self.evidence(9, turns=13))
                         ['termination_reason'], 'turn_limit')
        for cause in ('timeout', 'oom', 'cancelled', 'cleanup_error'):
            value = {**self.process, 'termination_reason': cause}
            self.assertEqual(segments.classify_worker_limit(value, self.evidence(9))['termination_reason'], cause)
        legacy = segments.classify_worker_limit(copy.deepcopy(self.process),
                                                {'events': {'turn_start': 2}, 'usage': {}})
        self.assertEqual(legacy['termination_reason'], 'process_error')


FAKE_PI = textwrap.dedent('''
    import json, sys, time
    def emit(event):
        print(json.dumps(event), flush=True)
    emit({"type": "session", "version": 3, "id": "fixture", "cwd": "/workspace"})
    emit({"type": "agent_start"})
    for index in range(40):
        emit({"type": "turn_start"})
        call = "call-%d" % index
        emit({"type": "tool_execution_start", "toolCallId": call, "toolName": "ls",
              "args": {"path": "/workspace/tests"}})
        emit({"type": "tool_execution_end", "toolCallId": call, "toolName": "ls",
              "result": {"content": [{"type": "text", "text": "test_slug.py"}]}, "isError": False})
        time.sleep(0.02)
    time.sleep(60)
''')


class WorkerLoopGuardTests(unittest.TestCase):
    def test_worker_stops_pi_when_identical_calls_exceed_the_limit(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / 'agent'
            inbox = root / 'inbox'; inbox.mkdir()
            outbox = root / 'outbox'; outbox.mkdir()
            task = {'pi_release': '1.2.0', 'release_contract': release_contracts.identity('1.2.0'),
                    'tools': ['ls'], 'max_turns': 100, 'max_total_tokens': 1000000, 'timeout_seconds': 60,
                    'session_id': 'fixture', 'prompt': 'Review the project.', 'cwd': '.'}
            stdout, stderr = io.TextIOWrapper(io.BytesIO()), io.TextIOWrapper(io.BytesIO())
            with mock.patch.dict(os.environ, {'PI_CODING_AGENT_DIR': str(home)}), \
                 mock.patch.object(sys, 'stdout', stdout), mock.patch.object(sys, 'stderr', stderr), \
                 mock.patch.object(worker, 'execute', return_value='1.2.0'), \
                 mock.patch.object(worker, 'select_cwd', return_value='/workspace'), \
                 mock.patch.object(worker, 'control_dirs', return_value=(inbox, outbox)), \
                 mock.patch.object(worker, 'get_capabilities_manifest', return_value=''), \
                 mock.patch.object(worker, 'model_configuration', return_value=({}, {}, [], {})), \
                 mock.patch.object(worker, 'agent_pi_arguments', return_value=[sys.executable, '-c', FAKE_PI]):
                started = time.monotonic()
                code = worker.agent({'model': 'fixture-model'}, task)
                elapsed = time.monotonic() - started
            heartbeat = json.loads((outbox / 'heartbeat.json').read_text())
            stderr.flush()
            message = stderr.buffer.getvalue().decode()
        self.assertEqual(code, 124)
        self.assertIn('PI_LAB_LIMIT: repeated identical tool call', message)
        self.assertLess(elapsed, 30)
        self.assertEqual(heartbeat['status'], 'limited')
        self.assertEqual(heartbeat['tool_repetition']['limit'], 5)
        # Lines already read in the same chunk may still be counted before the kill.
        self.assertGreaterEqual(heartbeat['tool_repetition']['longest_identical_run'], 6)
        self.assertLess(heartbeat['turn'], 40)


if __name__ == '__main__':
    unittest.main()
