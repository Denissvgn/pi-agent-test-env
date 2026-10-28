"""A10 coordinator oracles. Real files/allocator/authority; mocked helper/Docker.

No container, socket, Pi child or model is started by these tests.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'skill/scripts'), str(ROOT / 'skill/runtime')]
import agent_profiles
from application_client import Grant
import native_budget_controls as controls
import native_budget_execution as execution
import ownership_registry
from parallel_allocator import Allocator
import resources
import stage_control

CANARY = 'synthetic-native-parent-secret-123456789'


def fresh(): return str(uuid.uuid4())


def snapshot(maximum=8, phase='business', charged=0, assisted=False):
    counts = {key: 0 for key in controls.COUNTER_FIELDS}
    counts.update(attempted=charged, charged=charged)
    remaining = maximum - charged
    return {'schema': 1, 'document_type': 'native_tool_budget_status', 'phase': phase, 'accounting': 'available',
        'limits': {'max_tool_calls': maximum, 'reporting_reserve_calls': 2, 'reporting_reserve_seconds': 10},
        'counts': counts, 'per_tool': {'bash': copy.deepcopy(counts), 'budget_status': {key: 0 for key in counts},
                                    '__unknown__': {key: 0 for key in counts}},
        'remaining_calls': remaining, 'remaining_admissible_calls': remaining if phase != 'exhausted' else 0,
        'business_calls_remaining': max(0, remaining - 2) if phase == 'business' else 0,
        'reporting_reserve_calls_remaining': min(remaining, 2), 'assisted': assisted}


class FakeHelper:
    """Only this lifecycle/transport is fake; authority and allocator are real."""
    def __init__(self, authority, allocator, participant_resources, participant_reservation=None, **kwargs):
        self.authority, self.allocator = authority, allocator
        self.calls = []; self.value = snapshot(); self.cleanup_safe = True
        self.reservations = []
        item = allocator.request('helper-' + fresh(), {'generation': 'fixture'},
            {'cpu_millis': 1000, 'memory_mib': 512, 'pids_limit': 128}, 30, 'helper')
        self.reservations.append(item)
        if participant_reservation is None:
            participant_reservation = allocator.request('participant-' + fresh(), {'generation': 'fixture'}, participant_resources, 30)
            self.reservations.append(participant_reservation)
        self.participant_reservation = participant_reservation
        allocator.dispatch()
        if any(row.state != 'reserved' for row in self.reservations): raise ValueError('fixture admission failed')
        allocator.consume(item.identity, item.capability, item.binding, item.resources); allocator.running(item.identity)
        self.network_record = {'container': 'fixture-owned-network'}
        authority._launched = True

    def native_budget_status(self): self.calls.append('status'); return copy.deepcopy(self.value)
    def checkpoint_native_budget(self): self.calls.append('checkpoint'); return copy.deepcopy(self.value)
    def extend_native_budget(self, *, max_tool_calls, remaining_seconds):
        self.calls.append(('extend', max_tool_calls, remaining_seconds))
        self.value = snapshot(max_tool_calls, self.value['phase'], self.value['counts']['charged'], True)
        return copy.deepcopy(self.value)
    def continue_native_budget(self, segment_id, extension):
        self.calls.append(('continue', segment_id))
        old = self.authority._grants[-1]
        grant = Grant({**old.scope, 'segment_id': segment_id}, 'b' * 63 + str(len(self.authority._grants)))
        self.authority._revoked.add(old.capability); self.authority._grants.append(grant)
        self.authority._grant_digests[grant.capability] = execution.c.digest(grant.scope)
        self.authority._budget_tokens[segment_id] = uuid.uuid4().hex * 2
        return self.authority.budget_context(grant, extension)
    def cleanup(self, *, writers_absent):
        self.calls.append(('cleanup', writers_absent))
        safe = writers_absent is True and self.cleanup_safe
        for item in self.reservations:
            if item.state in execution.LIVE: self.allocator.release(item.identity, safe, safe)
        return {'schema': 1, 'status': 'removed' if safe else 'cleanup_unconfirmed', 'safe_to_continue': safe}


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.run = self.root / 'run'; self.run.mkdir()
        self.workspace = self.run / 'workspace'; self.workspace.mkdir()
        self.project = self.root / 'project'; self.project.mkdir()
        self.control = self.run / 'controls' / fresh(); self.control.mkdir(parents=True)
        self.task = {'name': 'implement', 'tools': ['bash', 'budget_status'], 'timeout_seconds': 90,
                     'max_turns': 10, 'max_total_tokens': 10000, 'max_tool_calls': 8,
                     'reporting_reserve_calls': 2, 'reporting_reserve_seconds': 10, 'prompt': 'Bounded fixture'}
        self.plan = {'agents': [self.task]}; self.profile = agent_profiles.builtin()
        self.desc = {'kind': 'agent', 'run_id': fresh(), 'attempt_id': fresh(), 'stage_id': self.control.name,
                     'workspace': str(self.workspace), 'control': str(self.control), 'label': 'agent-1-implement'}
        stage = self.run / 'stages' / self.desc['stage_id']; stage.mkdir(parents=True)
        stage_control.atomic(stage / 'descriptor.json', self.desc)
        stage_control.atomic(self.run / 'identity.json', {key: self.desc[key] for key in ('run_id', 'attempt_id')})
        stage_control.atomic(self.run / 'plan.json', self.plan)
        self.runtime = self.run / 'trusted-runtime'; self.runtime.mkdir()
        for name in ('workspace-boundary.mjs', 'profile-monitor.mjs', 'tool-budget.mjs', 'native_tool_contracts.py'):
            shutil.copyfile(ROOT / 'skill/runtime' / name, self.runtime / name)
        policy = copy.deepcopy(resources.DEFAULTS)
        policy['runtime'] = {'cpus': 1., 'memory': '1g', 'pids_limit': 256, 'jobs': 1}
        self.args = argparse.Namespace(platform='linux/arm64', native_platform='linux/arm64', profile='core',
            observed_pi_version='1.2.0', project=str(self.project), network='bridge', in_place=False,
            resource_report={'effective': policy})
        self.lab = mock.Mock()
        self.lab.validate_plan.side_effect = lambda value, *args, **kwargs: copy.deepcopy(value)
        self.lab.docker_info.return_value = {'NCPU': 8, 'MemTotal': 16 * 1024 ** 3}
        self.registry = argparse.Namespace(binding={}, generation='fixture')
        token = ownership_registry.CURRENT.set(self.registry)
        self.addCleanup(ownership_registry.CURRENT.reset, token)
        self.helpers = []
        def create(authority, **kwargs):
            helper = FakeHelper(authority, **kwargs); self.helpers.append(helper); return helper
        patcher = mock.patch.object(execution.OwnedHelper, 'start', side_effect=create)
        self.start = patcher.start(); self.addCleanup(patcher.stop)
        self.session = fresh()

    def prepare(self):
        return execution.prepare(self.lab, self.args, 'sha256:' + 'a' * 64, self.run, self.workspace,
                                 self.desc, self.task, self.profile, [CANARY])

    def begin(self, coordinator, directive=None):
        segment = fresh(); folder = self.control / 'segments' / segment; folder.mkdir(parents=True)
        result = coordinator.begin_segment(segment, self.session, folder, directive)
        return segment, folder, result

    def command(self, coordinator, kind, **payload):
        identity = fresh()
        record = {'schema': 2, 'id': identity, 'intervention_id': fresh(), 'kind': kind,
            **{key: coordinator.binding[key] for key in ('run_id', 'attempt_id', 'stage_id', 'segment_id')},
            'created_at': stage_control.now(), 'expected_stage_revision': 1, **payload}
        record['payload_digest'] = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        folder = (self.run / 'stages' / self.desc['stage_id'] / 'budget-requests' if kind == 'extend_budget'
                  else self.control / 'inbox' / 'directives')
        folder.mkdir(parents=True, exist_ok=True); stage_control.atomic(folder / (identity + '.json'), record)
        for status in ('requested', 'accepted'): stage_control.audit(self.run, record, status)
        return record

    def test_absent_native_limits_no_files_or_runtime_probe(self):
        task = {'name': 'legacy'}
        self.assertIsNone(execution.prepare(None, None, None, None, None, None, task, None, ()))
        self.start.assert_not_called()

    def test_partial_limits_fail_before_helper(self):
        del self.task['reporting_reserve_calls']
        with self.assertRaises(ValueError): self.prepare()
        self.start.assert_not_called()

    def test_isolated_first_segment_private_context_and_public_projection(self):
        co = self.prepare(); segment, folder, result = self.begin(co)
        path = folder / 'native-budget-context.json'
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
        context = json.loads(path.read_bytes())
        self.assertEqual(context['scope']['segment_id'], segment)
        self.assertEqual(co.reservation.state, 'launching')
        co.mark_running(); self.assertEqual(co.reservation.state, 'running')
        self.assertEqual(set(result), {'context_path', 'network'})
        self.assertNotIn(context['capability'], json.dumps(result))
        self.assertIn(context['capability'], co.redaction_values())
        self.assertIn(CANARY, co.redaction_values())
        self.assertNotIn(CANARY, repr(co))
        co.after_segment(True); self.assertEqual(co.reservation.state, 'reserved')
        self.assertTrue(co.close(True)['safe_to_continue']); self.assertFalse(path.exists())
        self.assertEqual(co.reservation.state, 'released')
        self.assertEqual(len(self.helpers), 1)

    def test_status_cache_bounded_five_seconds_and_strict_copy(self):
        co = self.prepare()
        with mock.patch.object(execution.time, 'monotonic', return_value=100): self.begin(co)
        helper = self.helpers[0]; helper.calls.clear()
        with mock.patch.object(execution.time, 'monotonic', return_value=104.99):
            view = co.status(); view['phase'] = 'exhausted'; self.assertEqual(co.status()['phase'], 'business')
        self.assertEqual(helper.calls, [])
        with mock.patch.object(execution.time, 'monotonic', return_value=105): co.status()
        self.assertEqual(helper.calls, ['status'])

    def test_content_hash_changes_for_guard_bytes_and_release(self):
        first = execution.extension_order_sha256(self.profile, '1.2.0', runtime_root=self.runtime)
        self.assertNotEqual(first, execution.extension_order_sha256(self.profile, '0.87.1', runtime_root=self.runtime))
        (self.runtime / 'tool-budget.mjs').write_bytes(b'changed')
        self.assertNotEqual(first, execution.extension_order_sha256(self.profile, '1.2.0', runtime_root=self.runtime))

    def test_linked_guard_rejected_before_helper(self):
        path = self.runtime / 'tool-budget.mjs'; path.unlink(); path.symlink_to(ROOT / 'skill/runtime/tool-budget.mjs')
        with self.assertRaises(OSError): self.prepare()
        self.start.assert_not_called()

    def test_modified_frozen_task_rejected(self):
        self.task['prompt'] = 'changed'
        with self.assertRaises(execution.NativeExecutionError): self.prepare()
        self.start.assert_not_called()

    def test_snapshot_alias_and_in_place_reject(self):
        self.args.in_place = True
        with self.assertRaises(execution.NativeExecutionError): self.prepare()
        self.start.assert_not_called()

    def test_half_docker_capacity_admits_pair_before_helper(self):
        self.lab.docker_info.return_value['NCPU'] = 2
        co = self.prepare()
        with self.assertRaises(execution.NativeExecutionError): self.begin(co)
        self.start.assert_not_called()

    def test_declared_cpu_or_memory_fraction_denies_pair_before_helper(self):
        for cpu, memory in ((0.125, 0.5), (0.5, 0.0625)):
            with self.subTest(cpu=cpu, memory=memory):
                self.args.resource_report['effective']['host_budget'] = {'cpu_fraction': cpu, 'memory_fraction': memory}
                co = self.prepare()
                with self.assertRaises(execution.NativeExecutionError): self.begin(co)
                self.start.assert_not_called()

    def test_larger_declared_fraction_admits_fitting_pair(self):
        self.args.resource_report['effective']['host_budget'] = {'cpu_fraction': 0.75, 'memory_fraction': 0.75}
        self.lab.docker_info.return_value = {'NCPU': 3, 'MemTotal': 4 * 1024 ** 3}
        co = self.prepare(); self.begin(co)
        self.assertEqual(co.pool.capacity['cpu_millis'], 2250)
        self.assertEqual(len(self.helpers), 1)
        co.mark_running(); co.after_segment(True); co.close(True)

    def test_non_bridge_and_missing_indexed_support_reject(self):
        self.args.network = 'host'
        co = self.prepare()
        with self.assertRaises(execution.NativeExecutionError): self.begin(co)
        self.args._indexed_session = argparse.Namespace()
        with self.assertRaises(execution.NativeExecutionError): self.prepare()

    def test_new_segment_requires_parent_directive_not_normal_settlement(self):
        co = self.prepare(); self.begin(co); co.mark_running(); co.after_segment(True)
        with self.assertRaises(execution.NativeExecutionError): self.begin(co)
        self.assertFalse(any(isinstance(item, tuple) and item[0] == 'continue' for item in self.helpers[0].calls))

    def test_explicit_continuation_keeps_same_ledger_session_and_counts(self):
        co = self.prepare(); first, _, _ = self.begin(co); co.mark_running(); co.after_segment(True)
        command = self.command(co, 'steer', message='Continue only this authorized segment')
        second, _, _ = self.begin(co, command)
        self.assertNotEqual(first, second); self.assertEqual(co.binding['session_id'], self.session)
        self.assertEqual(co.reservation.state, 'launching'); self.assertEqual(len(self.helpers), 1)
        self.assertEqual(len(co.authority._grants), 2)
        co.mark_running(); co.after_segment(True); co.close(True)

    def test_forged_or_unaccepted_directive_cannot_continue(self):
        co = self.prepare(); self.begin(co); co.after_segment(True)
        command = self.command(co, 'steer', message='Retained original')
        command['message'] = 'unretained mutation'
        with self.assertRaises(execution.NativeExecutionError): self.begin(co, command)
        self.assertEqual(len(co.authority._grants), 1)

    def test_unknown_writer_preserves_context_and_quarantines_cleanup(self):
        co = self.prepare(); _, folder, _ = self.begin(co)
        with self.assertRaises(execution.NativeExecutionError): co.after_segment(False)
        with self.assertRaises(execution.NativeExecutionError): co.close(False)
        self.assertTrue((folder / 'native-budget-context.json').exists())
        self.assertEqual(co.reservation.state, 'quarantined')

    def test_clean_scan_blocks_leaked_context_capability(self):
        co = self.prepare(); self.begin(co)
        (self.workspace / 'leak').write_text(co.context['capability'])
        with self.assertRaises(execution.NativeExecutionError): co.after_segment(True)
        self.assertEqual(co.reservation.state, 'launching')

    def test_symlinked_control_ancestor_cannot_receive_context(self):
        co = self.prepare(); segment = fresh(); target = self.root / 'elsewhere'; target.mkdir()
        (self.control / 'segments').symlink_to(target, target_is_directory=True)
        folder = self.control / 'segments' / segment; folder.mkdir()
        with self.assertRaises(execution.NativeExecutionError): co.begin_segment(segment, self.session, folder)
        self.assertFalse((folder / 'native-budget-context.json').exists())

    def test_explicit_extension_once_with_retained_authorization_and_revision(self):
        co = self.prepare(); self.begin(co)
        stage_control.atomic(self.run / 'stages' / self.desc['stage_id'] / 'budget.json',
            {'revision': 2, 'started_host_monotonic': time.monotonic(),'effective_limits':{'timeout_seconds':self.task['timeout_seconds']}})
        command = self.command(co, 'extend_budget', expected_budget_revision=2,
            limits={**{key: self.task[key] for key in (*controls.LEGACY_LIMITS, *controls.NATIVE_FIELDS)}, 'max_tool_calls': 12})
        result = co.extend(command['id'], 12, 80)
        self.assertTrue(result['assisted']); self.assertEqual(result['limits']['max_tool_calls'], 12)
        with self.assertRaises(execution.NativeExecutionError): co.extend(command['id'], 12, 80)
        self.assertEqual(sum(isinstance(item, tuple) and item[0] == 'extend' for item in self.helpers[0].calls), 1)
        self.assertIsNone(next(item for item in self.helpers[0].calls if isinstance(item,tuple) and item[0]=='extend')[2])

    def test_extension_cannot_reopen_reporting(self):
        co = self.prepare(); self.begin(co); self.helpers[0].value = snapshot(8, 'reporting', 6)
        co.status(force=True)
        stage_control.atomic(self.run / 'stages' / self.desc['stage_id'] / 'budget.json',
            {'revision': 2, 'started_host_monotonic': time.monotonic(),'effective_limits':{'timeout_seconds':self.task['timeout_seconds']}})
        command = self.command(co, 'extend_budget', expected_budget_revision=2,
            limits={**{key: self.task[key] for key in (*controls.LEGACY_LIMITS, *controls.NATIVE_FIELDS)}, 'max_tool_calls': 12})
        self.assertEqual(co.extend(command['id'], 12, 80)['phase'], 'reporting')

    def test_explicit_timeout_increase_sends_positive_remaining_to_helper(self):
        co=self.prepare();self.begin(co)
        stage_control.atomic(self.run/'stages'/self.desc['stage_id']/'budget.json',
            {'revision':2,'started_host_monotonic':time.monotonic(),
             'effective_limits':{'timeout_seconds':self.task['timeout_seconds']}})
        limits={key:self.task[key] for key in (*controls.LEGACY_LIMITS,*controls.NATIVE_FIELDS)}
        limits.update(max_tool_calls=12,timeout_seconds=self.task['timeout_seconds']+30)
        command=self.command(co,'extend_budget',expected_budget_revision=2,limits=limits)
        co.extend(command['id'],12,80)
        remaining=next(row[2] for row in self.helpers[0].calls if isinstance(row,tuple) and row[0]=='extend')
        self.assertIsInstance(remaining,float);self.assertGreater(remaining,self.task['timeout_seconds'])

    def test_context_replacement_prevents_purge(self):
        co = self.prepare(); _, folder, _ = self.begin(co); co.after_segment(True)
        path = folder / 'native-budget-context.json'; path.rename(folder / 'old-context'); path.write_text('replacement')
        with self.assertRaises(execution.NativeExecutionError): co.close(True)
        self.assertEqual(path.read_text(), 'replacement')

    def indexed_support(self):
        pool = Allocator({'cpu_millis': 4000, 'memory_mib': 4096, 'pids_limit': 1024})
        weight = {'cpu_millis': 1000, 'memory_mib': 1024, 'pids_limit': 256}
        binding = {key: self.desc[key] for key in ('run_id', 'attempt_id', 'stage_id')}
        binding.update(generation='fixture', trial_id=None, workspace=str(self.workspace))
        row = pool.request('indexed-worker', binding, weight, 30); pool.dispatch()
        pool.consume(row.identity, row.capability, row.binding, row.resources)
        self.args.network = 'fixture-owned-network'
        self.args._indexed_session = argparse.Namespace(native_budget_support={
            'pool': pool, 'reservation': row, 'registry': self.registry,
            'network_record': {'container': self.args.network}})
        return pool, row

    def test_indexed_external_reservation_remains_owned_across_cleanup(self):
        pool, row = self.indexed_support()
        co = self.prepare(); self.begin(co)
        self.assertEqual(row.state, 'launching'); co.mark_running(); self.assertEqual(row.state, 'running')
        co.after_segment(True); self.assertEqual(row.state, 'running')
        co.close(True); self.assertEqual(row.state, 'running')
        self.lab.docker_info.assert_not_called()
        self.assertTrue(co.external); self.assertIs(co.pool, pool)

    def test_indexed_binding_or_capacity_mismatch_precedes_helper(self):
        _, row = self.indexed_support(); row.binding['stage_id'] = fresh()
        co = self.prepare()
        with self.assertRaises(execution.NativeExecutionError): self.begin(co)
        self.start.assert_not_called()

    def remote(self):
        remote = mock.Mock(); remote.bootstrap = {'intent': {'trial_id': fresh()}}
        value = {'snapshot': snapshot()}
        def context(binding):
            tools = execution.native_tool_contracts.selected_tools('1.2.0', self.task['tools'])
            return {'schema': 1, 'pi_release': '1.2.0',
                'scope': {**binding, 'stage_name': self.task['name'], 'pi_release': '1.2.0'},
                'allowed_tools': [tool['name'] for tool in tools],
                'prepare_arguments': execution.native_tool_contracts.prepare_arguments('1.2.0', self.task['tools']),
                'extension_order_sha256': execution.extension_order_sha256(self.profile, '1.2.0', runtime_root=self.runtime),
                'tool_schema_sha256': execution.c.digest(sorted(tools, key=lambda item: item['name'])),
                'base_url': 'http://pi-application:8081/budget', 'capability': 'c' * 64}
        def begin(name, binding):
            value['binding'] = copy.deepcopy(binding)
            return {'context': context(binding), 'binding': binding, 'network': 'parent-owned-network', 'budget': value['snapshot']}
        def continuation(stage, command, segment):
            value['binding']['segment_id'] = segment
            return {'context': context(value['binding']), 'binding': copy.deepcopy(value['binding']),
                    'network': 'parent-owned-network', 'budget': value['snapshot']}
        remote.native_budget_begin.side_effect = begin
        remote.native_budget_continue.side_effect = continuation
        remote.native_budget_status.side_effect = lambda stage: copy.deepcopy(value['snapshot'])
        remote.native_budget_checkpoint.side_effect = lambda stage: copy.deepcopy(value['snapshot'])
        remote.native_budget_close.return_value = {'cleanup': {'schema': 1, 'safe_to_continue': True}}
        self.args._parallel_session = remote
        return remote, value

    def test_parallel_remote_uses_parent_scope_checkpoint_and_cleanup(self):
        remote, _ = self.remote(); co = self.prepare(); _, folder, reply = self.begin(co)
        self.assertEqual(reply['network'], 'parent-owned-network')
        self.assertEqual(co.binding['trial_id'], remote.bootstrap['intent']['trial_id'])
        co.mark_running(); co.after_segment(True)
        remote.native_budget_checkpoint.assert_called_once_with(self.desc['stage_id'])
        command = self.command(co, 'steer', message='Authorized remote continuation')
        self.begin(co, command); co.mark_running(); co.after_segment(True); co.close(True)
        remote.native_budget_continue.assert_called_once()
        remote.native_budget_close.assert_called_once_with(self.desc['stage_id'])
        self.assertFalse((folder / 'native-budget-context.json').exists())
        self.start.assert_not_called(); self.lab.docker_info.assert_not_called()

    def test_remote_bad_scope_still_closes_attempted_parent_helper(self):
        remote, _ = self.remote()
        original = remote.native_budget_begin.side_effect
        def bad(*args):
            reply = original(*args); reply['context']['scope']['session_id'] = fresh(); return reply
        remote.native_budget_begin.side_effect = bad
        co = self.prepare()
        with self.assertRaises(execution.NativeExecutionError): self.begin(co)
        co.close(True)
        remote.native_budget_close.assert_called_once_with(self.desc['stage_id'])

    def test_status_rejects_private_or_malformed_projection_without_echo(self):
        co = self.prepare(); self.begin(co)
        self.helpers[0].value['secret'] = CANARY
        with self.assertRaises(execution.NativeExecutionError) as caught: co.status(force=True)
        self.assertNotIn(CANARY, str(caught.exception))

    def test_cleanup_uncertainty_keeps_context(self):
        co = self.prepare(); _, folder, _ = self.begin(co); co.after_segment(True)
        self.helpers[0].cleanup_safe = False
        with self.assertRaises(execution.NativeExecutionError): co.close(True)
        self.assertTrue((folder / 'native-budget-context.json').is_file())
        self.assertEqual(co.reservation.state, 'quarantined')

    def test_frozen_guard_change_prevents_new_segment(self):
        co = self.prepare(); self.begin(co); co.after_segment(True)
        command = self.command(co, 'steer', message='Authorized')
        (self.runtime / 'profile-monitor.mjs').write_bytes(b'changed')
        with self.assertRaises(execution.NativeExecutionError): self.begin(co, command)
        self.assertEqual(len(co.authority._grants), 1)

    def test_preexisting_context_not_overwritten(self):
        co = self.prepare(); segment = fresh(); folder = self.control / 'segments' / segment; folder.mkdir(parents=True)
        path = folder / 'native-budget-context.json'; path.write_bytes(b'original')
        with self.assertRaises(execution.NativeExecutionError): co.begin_segment(segment, self.session, folder)
        self.assertEqual(path.read_bytes(), b'original')

    def test_context_ancestor_replacement_never_unlinks_external_file(self):
        co = self.prepare(); _, folder, _ = self.begin(co); co.after_segment(True)
        replacement = self.root / 'external'; replacement.mkdir(); target = replacement / 'native-budget-context.json'
        target.write_bytes(b'untouched')
        folder.rename(folder.with_name(folder.name + '-original')); folder.symlink_to(replacement, target_is_directory=True)
        with self.assertRaises(execution.NativeExecutionError): co.close(True)
        self.assertEqual(target.read_bytes(), b'untouched')

    def test_actual_plan_normalizer_preserves_admitted_task_and_plan_hash(self):
        import pi_lab
        self.plan = pi_lab.validate_plan({'schema': 1, 'name': 'native-coordinator',
            'agents': [{**self.task, 'require_tools': ['bash']}],
            'checks': [{'name': 'independent', 'argv': ['true']}]}, self.run, self.profile)
        self.task = self.plan['agents'][0]
        stage_control.atomic(self.run / 'plan.json', self.plan)
        self.lab.validate_plan.side_effect = pi_lab.validate_plan
        co = self.prepare(); self.begin(co)
        self.assertEqual(co.plan_sha256, execution.provenance.digest(self.plan))
        self.assertEqual(co.authority.task, self.task)

    def test_fixture_order_hash_checks_actual_staged_entrypoint(self):
        profile = agent_profiles.load(ROOT / 'skill/assets/profiles/fixture-lookup/profile.pi-1.2.0.json')
        first = execution.extension_order_sha256(profile, '1.2.0', runtime_root=self.runtime)
        staged = self.root / 'profile'; staged.mkdir()
        for asset in profile['assets']: shutil.copyfile(asset['source'], staged / asset['target'])
        self.assertEqual(first, execution.extension_order_sha256(profile, '1.2.0', runtime_root=self.runtime, profile_root=staged))
        (staged / 'fixture-lookup.mjs').write_bytes(b'tampered')
        with self.assertRaises(execution.NativeExecutionError):
            execution.extension_order_sha256(profile, '1.2.0', runtime_root=self.runtime, profile_root=staged)

    def test_context_fsync_uncertainty_does_not_claim_clean_or_purge(self):
        co = self.prepare()
        with mock.patch.object(execution, '_private_context', side_effect=OSError('fixture storage unavailable')):
            with self.assertRaises(execution.NativeExecutionError): self.begin(co)
        with self.assertRaises(execution.NativeExecutionError): co.close(True)
        self.assertTrue(co.failed)

    def test_unrequested_limit_increase_is_not_publicly_accepted(self):
        co = self.prepare(); self.begin(co); self.helpers[0].value = snapshot(9)
        with self.assertRaises(execution.NativeExecutionError): co.status(force=True)

    def test_checkpoint_can_resolve_unknown_execution_without_resetting_charges(self):
        co = self.prepare(); self.begin(co)
        value = snapshot(charged=1)
        value['counts'].update(grants_consumed=1, executed_unknown=1, executed=None)
        value['per_tool']['bash'] = copy.deepcopy(value['counts'])
        self.helpers[0].value = value; self.assertIsNone(co.status(force=True)['counts']['executed'])
        value['counts'].update(executed_known=1, executed_unknown=0, executed=1, helper_verified=1)
        value['per_tool']['bash'] = copy.deepcopy(value['counts'])
        result = co.after_segment(True)
        self.assertEqual(result['counts']['executed'], 1)
        self.assertEqual(result['counts']['charged'], 1)


if __name__ == '__main__': unittest.main()
