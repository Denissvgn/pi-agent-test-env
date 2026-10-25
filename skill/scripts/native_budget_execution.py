"""Parent-owned native-budget coordination across one explicitly steered stage.

Context capabilities remain in memory and owner-only control files. This module
does not launch participants, infer continuation authority, or reset a ledger.
"""
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import stat
import time

import agent_profiles
import application_contracts as c
import application_credentials as credentials
from application_client import OwnedHelper, _binding
from native_budget_client import NativeBudgetAuthority
import native_budget_controls as budgets
import native_tool_contracts
import ownership_registry
from parallel_allocator import Allocator, LIVE
import provenance
import resources
import stage_control as controls


class NativeExecutionError(ValueError):
    """Bounded parent diagnostic; never includes private authority or arguments."""


def extension_order_sha256(profile, pi_release, *, runtime_root, profile_root=None):
    """Bind actual ordered frozen extension bytes, profile, and native schemas."""
    root = Path(runtime_root).absolute()
    ordered = []
    for name in ('workspace-boundary.mjs', 'profile-monitor.mjs'):
        ordered.append({'path': '/opt/pi-lab/' + name,
                        'sha256': hashlib.sha256(agent_profiles.read_asset(root / name)).hexdigest()})
    if profile['kind'] == 'fixture-lookup':
        assets = [asset for asset in profile['assets'] if asset['target'] == 'fixture-lookup.mjs']
        if len(assets) != 1:
            raise NativeExecutionError('Native fixture extension identity unavailable')
        asset = assets[0]
        source = Path(profile_root) / asset['target'] if profile_root is not None else Path(asset['source'])
        observed = hashlib.sha256(agent_profiles.read_asset(source)).hexdigest()
        if observed != asset['sha256']:
            raise NativeExecutionError('Native fixture extension content changed')
        ordered.append({'path': '/opt/pi-profile/fixture-lookup.mjs', 'sha256': observed})
    elif profile != agent_profiles.builtin():
        raise NativeExecutionError('Unsupported native profile')
    ordered.append({'path': '/opt/pi-lab/tool-budget.mjs',
                    'sha256': hashlib.sha256(agent_profiles.read_asset(root / 'tool-budget.mjs')).hexdigest()})
    return c.digest({'schema': 1, 'extensions': ordered,
        'profile_sha256': agent_profiles.identity(profile),
        'native_tool_contract': native_tool_contracts.identity(pi_release),
        'native_tool_contracts_sha256': hashlib.sha256(agent_profiles.read_asset(root / 'native_tool_contracts.py')).hexdigest()})


def _private_context(path, value):
    """Create once through directory descriptors; no ancestor links or replace."""
    path = Path(path).absolute()
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent); parent = child
        body = c.canonical(value)
        if len(body) > 64 * 1024:
            raise NativeExecutionError('Native context exceeds bound')
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=parent)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(body); stream.flush(); os.fsync(stream.fileno())
        os.fsync(parent)
        info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o400:
            raise NativeExecutionError('Native context storage unavailable')
        return (info.st_dev, info.st_ino)
    finally:
        os.close(parent)


def _purge_context(path, identity):
    path = Path(path).absolute()
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent); parent = child
        info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if ((info.st_dev, info.st_ino) != identity or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o400):
            raise NativeExecutionError('Native context storage changed')
        os.unlink(path.name, dir_fd=parent); os.fsync(parent)
    finally:
        os.close(parent)


class Coordinator:
    def __repr__(self):
        return '<NativeBudgetCoordinator private capabilities withheld>'

    def __init__(self, lab, args, image, runroot, workspace, desc, task, profile, redaction_values):
        self.lab, self.args, self.image = lab, args, image
        self.runroot, self.workspace = Path(runroot).absolute(), Path(workspace).absolute()
        self.desc, self.task, self.profile = copy.deepcopy(desc), copy.deepcopy(task), copy.deepcopy(profile)
        self._values = list(dict.fromkeys(value for value in redaction_values if value))
        self.authority = self.helper = self.pool = self.reservation = None
        self.remote = getattr(args, '_parallel_session', None)
        self.external = False; self.failed = False; self.closed = False
        self.binding = self.context = None; self._cached = None; self._cached_at = None
        self._paths = []; self._used = set(); self._settled = True; self._running = False
        self._remote_started = False
        self._helper_attempted = False
        self._uncertain_context = False
        self.release = getattr(args, 'observed_pi_version', None)
        self.allowed_tools = [tool['name'] for tool in native_tool_contracts.selected_tools(self.release, task['tools'])]
        self._maximum = task['max_tool_calls']
        if self.workspace != self.runroot / 'workspace' or self.workspace.is_symlink() or not self.workspace.is_dir():
            raise NativeExecutionError('Native budgets require the isolated owned snapshot')
        if (getattr(args, 'in_place', False) or args.platform != 'linux/arm64'
                or getattr(args, 'native_platform', None) != 'linux/arm64'):
            raise NativeExecutionError('Native budget runtime admission unavailable')
        identity = controls.read(self.runroot / 'identity.json')
        if any(identity.get(key) != desc.get(key) for key in ('run_id', 'attempt_id')):
            raise NativeExecutionError('Native stage identity differs from run')
        if (desc.get('kind') != 'agent' or desc.get('workspace') != str(self.workspace)
                or not controls.valid_id(desc.get('stage_id'))
                or Path(desc.get('control', '')).absolute() != self.runroot / 'controls' / desc['stage_id']):
            raise NativeExecutionError('Native stage descriptor invalid')
        if controls.read(self.runroot / 'stages' / desc['stage_id'] / 'descriptor.json') != desc:
            raise NativeExecutionError('Native stage descriptor changed')
        plan = lab.validate_plan(controls.read(self.runroot / 'plan.json'), self.runroot, profile,
                                external_bindings=bool(getattr(args, '_indexed_binding', None)))
        matches = [item for item in plan['agents'] if item['name'] == task['name']]
        if matches != [task] or desc.get('label') != 'agent-' + str(plan['agents'].index(task) + 1) + '-' + task['name']:
            raise NativeExecutionError('Native task differs from normalized frozen plan')
        self.plan_sha256 = provenance.digest(plan)
        self.extension_sha256 = extension_order_sha256(profile, self.release, runtime_root=self.runroot / 'trusted-runtime')
        self.registry = ownership_registry.CURRENT.get()
        if self.remote is None and self.registry is None:
            raise NativeExecutionError('Native budget requires the current ownership lease')
        self.trial_id = (getattr(self.remote, 'bootstrap', {}).get('intent', {}).get('trial_id')
                         if self.remote is not None else self.registry.binding.get('trial_id'))
        self._support = getattr(getattr(args, '_indexed_session', None), 'native_budget_support', None)
        if getattr(args, '_indexed_session', None) is not None and self.remote is None and self._support is None:
            raise NativeExecutionError('Indexed native budget lacks frozen helper admission')

    def _error(self):
        self.failed = True
        raise NativeExecutionError('Native budget ownership or accounting unavailable')

    def _active(self):
        if self.failed or self.closed or self.binding is None:
            self._error()

    def _snapshot(self, value, *, maximum=None):
        value = budgets.public_snapshot(value, allowed_tools=self.allowed_tools)
        expected = {key: self.task[key] for key in budgets.NATIVE_FIELDS}
        expected['max_tool_calls'] = self._maximum if maximum is None else maximum
        if value['limits'] != expected: self._error()
        if self._cached is not None:
            before = self._cached
            if (budgets.PHASES.index(value['phase']) < budgets.PHASES.index(before['phase'])
                    or value['limits']['max_tool_calls'] < before['limits']['max_tool_calls']
                    or any(value['limits'][key] != before['limits'][key] for key in
                           ('reporting_reserve_calls', 'reporting_reserve_seconds'))
                    or before['assisted'] and not value['assisted']
                    or any(value['counts'][key] < old for key, old in before['counts'].items()
                           if key != 'executed_unknown' and type(old) is int and type(value['counts'].get(key)) is int)):
                self._error()
            for tool in before['per_tool']:
                if any(value['per_tool'][tool][key] < old for key, old in before['per_tool'][tool].items()
                       if key != 'executed_unknown' and type(old) is int and type(value['per_tool'][tool].get(key)) is int): self._error()
        elif value['assisted'] or any(value['counts'].values()):
            self._error()
        self._maximum = expected['max_tool_calls']
        self._cached, self._cached_at = copy.deepcopy(value), time.monotonic()
        return copy.deepcopy(value)

    def _verify_context(self, context, binding):
        c.exact(context, {'schema', 'pi_release', 'scope', 'allowed_tools', 'prepare_arguments',
                         'extension_order_sha256', 'tool_schema_sha256', 'base_url', 'capability'}, '/context')
        expected = {**binding, 'stage_name': self.task['name'], 'pi_release': self.release}
        tools = native_tool_contracts.selected_tools(self.release, self.task['tools'])
        if (type(context['schema']) is not int or context['schema'] != 1 or context['scope'] != expected
                or context['pi_release'] != self.release or context['allowed_tools'] != self.allowed_tools
                or context['prepare_arguments'] != native_tool_contracts.prepare_arguments(self.release, self.task['tools'])
                or context['extension_order_sha256'] != self.extension_sha256
                or context['tool_schema_sha256'] != c.digest(sorted(tools, key=lambda item: item['name']))
                or context['base_url'] != 'http://pi-application:8081/budget'):
            self._error()
        c.sha256(context['capability'], '/context/capability')
        if context['capability'] not in self._values: self._values.append(context['capability'])
        return copy.deepcopy(context)

    def _start(self, binding):
        runtime_policy = copy.deepcopy(self.args.resource_report['effective'])
        runtime = runtime_policy['runtime']
        weight = {'cpu_millis': round(runtime['cpus'] * 1000),
                  'memory_mib': resources.memory_bytes(runtime['memory']) // 1024 ** 2,
                  'pids_limit': runtime['pids_limit']}
        borrowed = None
        if self._support is not None:
            if type(self._support) is not dict or set(self._support) != {'pool', 'reservation', 'registry', 'network_record'}:
                self._error()
            self.pool, self.reservation = self._support['pool'], self._support['reservation']
            if self._support['registry'] is not self.registry: self._error()
            borrowed = self._support['network_record']; self.external = True
            row = self.reservation
            if (self.args.network != borrowed.get('container') or self.pool.records.get(row.identity) is not row
                    or row.kind != 'stage' or row.state not in ('reserved', 'launching', 'running') or row.resources != weight
                    or row.binding.get('generation') != self.registry.generation
                    or any(row.binding.get(key) != binding[key] for key in ('run_id', 'attempt_id', 'trial_id', 'stage_id'))
                    or row.binding.get('workspace') != str(self.workspace)):
                self._error()
        else:
            if self.args.network != 'bridge':
                raise NativeExecutionError('Native budget requires bridge or the admitted broker network')
            daemon = self.lab.docker_info()
            if (type(daemon.get('NCPU')) is not int or daemon['NCPU'] < 1
                    or type(daemon.get('MemTotal')) is not int or daemon['MemTotal'] < 1): self._error()
            capacity = {'cpu_millis': math.floor(daemon['NCPU'] * .5 * 1000),
                        'memory_mib': math.floor(daemon['MemTotal'] * .5 / 1024 ** 2),
                        'pids_limit': weight['pids_limit'] + 128}
            if any(weight[key] + extra > capacity[key] for key, extra in
                   (('cpu_millis', 1000), ('memory_mib', 512), ('pids_limit', 128))):
                raise NativeExecutionError('Native helper and participant exceed half Docker capacity')
            self.pool = Allocator(capacity)
        self.authority = NativeBudgetAuthority(runtime={'pi_release': self.release, 'image_id': self.image,
            'platform': self.args.platform, 'container_profile': self.args.profile, 'resources': runtime_policy},
            task=self.task, plan_sha256=self.plan_sha256, project=self.args.project, runroot=self.runroot,
            profile=self.profile['kind'], redaction_values=self._values)
        grant = self.authority.grant(self.task['name'], binding)
        self._helper_attempted = True
        self.helper = OwnedHelper.start(self.authority, lab=self.lab, args=self.args, registry=self.registry,
            allocator=self.pool, participant_resources=weight, participant_reservation=self.reservation, borrowed_network=borrowed)
        self.reservation = self.helper.participant_reservation
        network = borrowed['container'] if borrowed else self.helper.network_record['container']
        return self.authority.budget_context(grant, self.extension_sha256), network, self.helper.native_budget_status()

    def begin_segment(self, segment_id, session_id, control, directive=None):
        if self.failed or self.closed or not self._settled or not controls.valid_id(segment_id) or not controls.valid_id(session_id):
            self._error()
        binding = {'run_id': self.desc['run_id'], 'trial_id': self.trial_id, 'attempt_id': self.desc['attempt_id'],
            'stage_id': self.desc['stage_id'], 'segment_id': segment_id, 'session_id': session_id, 'plan_sha256': self.plan_sha256}
        _binding(binding, self.plan_sha256)
        expected_control = Path(self.desc['control']) / 'segments' / segment_id
        if Path(control).absolute() != expected_control.absolute() or segment_id in self._used: self._error()
        try:
            if extension_order_sha256(self.profile, self.release, runtime_root=self.runroot / 'trusted-runtime') != self.extension_sha256:
                self._error()
            if self.binding is None:
                if directive is not None: self._error()
                if self.remote is not None:
                    self._remote_started = True
                    reply = self.remote.native_budget_begin(self.task['name'], binding)
                    if reply.get('binding') != binding: self._error()
                    context, network, snapshot = reply['context'], reply['network'], reply['budget']
                else:
                    context, network, snapshot = self._start(binding)
            else:
                if session_id != self.binding['session_id'] or type(directive) is not dict: self._error()
                record, target, intent = self._command(directive.get('id'), 'steer')
                if record != directive: self._error()
                before = self.status(force=True)
                if before['accounting'] != 'available': self._error()
                if self.remote is not None:
                    reply = self.remote.native_budget_continue(self.binding['stage_id'], directive['id'], segment_id)
                    if reply.get('binding') != binding: self._error()
                    context, network, snapshot = reply['context'], reply['network'], reply['budget']
                else:
                    context = self.helper.continue_native_budget(segment_id, self.extension_sha256)
                    snapshot = self.helper.native_budget_status(); network = self._network
                if snapshot['limits'] != before['limits'] or snapshot['counts'] != before['counts']: self._error()
                controls.atomic(target, {**intent, 'status': 'applied', 'budget': snapshot})
            self.context = self._verify_context(context, binding)
            if type(network) is not str or not network or len(network) > 128: self._error()
            self.binding, self._network = binding, network
            self._snapshot(snapshot)
            path = expected_control / 'native-budget-context.json'
            self._uncertain_context = True
            identity = _private_context(path, self.context); self._paths.append((path, identity))
            self._uncertain_context = False
            self._used.add(segment_id)
            if self.remote is None and not self.external:
                item = self.reservation
                self.pool.consume(item.identity, item.capability, item.binding, item.resources)
            self._settled = False; self._running = False
            return {'context_path': '/opt/pi-control/segments/' + segment_id + '/native-budget-context.json', 'network': network}
        except (OSError, ValueError, KeyError, TypeError):
            self._error()

    def mark_running(self):
        self._active()
        if self._settled or self._running: self._error()
        if self.remote is None:
            if self.reservation.state == 'launching': self.pool.running(self.reservation.identity)
            elif not self.external or self.reservation.state != 'running': self._error()
        self._running = True

    def status(self, force=False):
        self._active()
        if type(force) is not bool: self._error()
        if not force and self._cached_at is not None and 0 <= time.monotonic() - self._cached_at < 5:
            return copy.deepcopy(self._cached)
        try:
            value = (self.remote.native_budget_status(self.binding['stage_id']) if self.remote is not None
                     else self.helper.native_budget_status())
            return self._snapshot(value)
        except (OSError, ValueError, KeyError, TypeError): self._error()

    def _command(self, command_id, kind):
        self._active()
        if not controls.valid_id(command_id): self._error()
        # Remote peer verifies and durably consumes the same parent request.
        suffix = 'budget-requests' if kind == 'extend_budget' else None
        path = (self.runroot / 'stages' / self.binding['stage_id'] / suffix / (command_id + '.json') if suffix
                else Path(self.desc['control']) / 'inbox' / 'directives' / (command_id + '.json'))
        record = controls.read(path)
        fields = ('id', 'intervention_id', 'run_id', 'attempt_id', 'stage_id', 'segment_id', 'kind')
        if (record.get('id') != command_id or record.get('kind') != kind
                or any(record.get(key) != self.binding[key] for key in ('run_id', 'attempt_id', 'stage_id', 'segment_id'))): self._error()
        metadata = {'schema', 'id', 'intervention_id', 'payload_digest', 'run_id', 'attempt_id',
                    'stage_id', 'segment_id', 'kind', 'expected_stage_revision', 'created_at'}
        payload = {key: value for key, value in record.items() if key not in metadata}
        if hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest() != record.get('payload_digest'): self._error()
        history = controls.history(self.runroot)
        for status in ('requested', 'accepted'):
            selected = fields + (('payload_digest', 'expected_stage_revision', 'expected_budget_revision') if status == 'accepted' else ())
            if not any(event.get('status') == status and event.get('authorization_source') == 'parent_cli'
                       and all(event.get(key) == record.get(key) for key in selected) for event in history): self._error()
        folder = self.runroot / 'stages' / self.binding['stage_id'] / 'native-budget-execution'
        folder.mkdir(mode=0o700, exist_ok=True)
        target = folder / (command_id + '.json')
        if target.exists() or target.is_symlink(): self._error()
        intent = {'schema': 1, 'command_id': command_id, 'kind': kind, 'stage_id': self.binding['stage_id'],
                  'payload_digest': record['payload_digest'], 'status': 'intent'}
        controls.atomic(target, intent)
        return record, target, intent

    def extend(self, command_id, max_tool_calls, remaining_seconds):
        try:
            record, target, intent = self._command(command_id, 'extend_budget')
            budget = controls.read(self.runroot / 'stages' / self.binding['stage_id'] / 'budget.json')
            limits = record['limits']; before = self.status(force=True)
            if (type(record.get('expected_budget_revision')) is not int or record['expected_budget_revision'] != budget['revision']
                    or limits.get('max_tool_calls') != max_tool_calls or type(max_tool_calls) is not int
                    or not before['limits']['max_tool_calls'] <= max_tool_calls <= 500
                    or any(limits.get(key) != before['limits'][key] for key in ('reporting_reserve_calls', 'reporting_reserve_seconds'))
                    or type(remaining_seconds) not in (int, float) or not math.isfinite(remaining_seconds)
                    or not 0 < remaining_seconds <= limits['timeout_seconds']): self._error()
            remaining = budget['started_host_monotonic'] + limits['timeout_seconds'] - time.monotonic()
            if not math.isfinite(remaining) or not 0 < remaining <= 3600: self._error()
            prior_timeout=budget['effective_limits']['timeout_seconds']
            if type(prior_timeout) is not int or limits['timeout_seconds']<prior_timeout:self._error()
            helper_remaining=None if limits['timeout_seconds']==prior_timeout else remaining
            value = (self.remote.native_budget_extend(self.binding['stage_id'], command_id, max_tool_calls, remaining)
                     if self.remote is not None else self.helper.extend_native_budget(max_tool_calls=max_tool_calls, remaining_seconds=helper_remaining))
            result = self._snapshot(value, maximum=max_tool_calls)
            controls.atomic(target, {**intent, 'status': 'applied', 'budget': result})
            return result
        except (OSError, ValueError, KeyError, TypeError): self._error()

    def after_segment(self, writers_confirmed):
        self._active()
        if writers_confirmed is not True or self._settled: self._error()
        try:
            value = (self.remote.native_budget_checkpoint(self.binding['stage_id']) if self.remote is not None
                     else self.helper.checkpoint_native_budget())
            result = self._snapshot(value)
            if self.remote is None:
                if not credentials.workspace_inspected_clean(self.workspace, self.authority.redactor()): self._error()
                if not self.external:
                    if self.reservation.state not in ('launching', 'running'): self._error()
                    # Hold the exact finite footprint across explicitly steered
                    # segments. Only physical absence + clean scan permit rearm.
                    self.reservation.state = 'reserved'; self.reservation.capability = secrets.token_hex(32)
            self._settled = True; self._running = False
            return result
        except (OSError, ValueError, KeyError, TypeError): self._error()

    def redaction_values(self):
        values = list(self._values)
        if self.authority is not None:
            values.extend([*self.authority._values, self.authority._control_token,
                           *(grant.capability for grant in self.authority._grants), *self.authority._budget_tokens.values()])
        if self.reservation is not None and self.reservation.capability: values.append(self.reservation.capability)
        if self.helper is not None:
            values.extend(item.capability for item in self.helper.reservations if item.capability)
        if self.remote is not None:
            bootstrap = self.remote.bootstrap
            values.extend(value for value in (bootstrap.get('capability'), bootstrap.get('inference', {}).get('token')) if value)
            values.extend(value for assignment in bootstrap.get('credentials', {}).values() for value in assignment.values() if value)
            values.extend(value for value in bootstrap.get('indexed', {}).get('tokens', {}).values() if value)
        self._values=list(dict.fromkeys(values))
        return list(self._values)

    def close(self, writers_confirmed):
        if self.closed: return copy.deepcopy(self._cleanup)
        safe = writers_confirmed is True
        try:
            if self.remote is not None:
                if not safe: self._error()
                result = self.remote.native_budget_close(self.desc['stage_id']) if self._remote_started else {'cleanup': {'safe_to_continue': True}}
                receipt = result['cleanup']
            elif self.helper is not None:
                receipt = self.helper.cleanup(writers_absent=safe)
            else:
                if self._helper_attempted:
                    if self.pool is not None and any(item.kind=='helper' and item.state in LIVE
                                                     for item in self.pool.records.values()):
                        self.pool.dependent_cleanup_confirmed=False;self.pool.stop();self._error()
                    if not callable(getattr(self.registry,'load',None)):self._error()
                    for record in self.registry.load():
                        binding=record.get('binding',{})
                        if (record.get('application_helper') is True and record.get('client_mode')=='budget-only'
                                and binding.get('stage_id')==self.desc['stage_id']
                                and record.get('status') not in ('absent','released')):
                            self.pool.dependent_cleanup_confirmed=False;self.pool.stop()
                            self._error()
                receipt = {'schema': 1, 'status': 'removed', 'safe_to_continue': safe}
            if receipt.get('safe_to_continue') is not True: self._error()
            if self._uncertain_context: self._error()
            for path, identity in self._paths:
                _purge_context(path, identity)
            self.closed = True; self._cleanup = copy.deepcopy(receipt)
            return copy.deepcopy(receipt)
        except (OSError, ValueError, KeyError, TypeError): self._error()


def prepare(lab, args, image, runroot, workspace, desc, task, profile, redaction_values):
    if not budgets.NATIVE_FIELDS.intersection(task): return None
    budgets.native_limits({key: task[key] for key in budgets.NATIVE_FIELDS if key in task},
                          timeout_seconds=task['timeout_seconds'], required=True)
    return Coordinator(lab, args, image, runroot, workspace, desc, task, profile, redaction_values)
