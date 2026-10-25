"""Parent-owned native-budget helpers for explicit parallel cohorts.

No child chooses helper commands, files, credentials, weights or grant policies.
Buddy reservations precede worker queue entries, so a helper cannot deadlock
behind a third queued worker. The same reserved footprint is held for a trial.
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
import experiments
import native_budget_controls
import ownership_registry
from parallel_allocator import Allocator, LIVE, AXES
from parallel_contract import ParallelError, NATIVE_HELPER_RESOURCES, native_helper, native_resources
import provenance
import resources
import stage_control as controls


def _read_owned(path, *, private=False, maximum=1024*1024):
    path=Path(path).absolute(); parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            os.close(parent);parent=child
        descriptor=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        with os.fdopen(descriptor,'rb') as source:
            info=os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.getuid()
                    or stat.S_IMODE(info.st_mode)&(0o077 if private else 0o022) or info.st_size>maximum):
                raise ParallelError('Unsafe native parent record')
            return c.loads(source.read(maximum+1),max_bytes=maximum)
    finally:os.close(parent)


class NativeAllocator(Allocator):
    def __init__(self, capacity, max_stages=2, max_pending=16, *, native_trials, generation, helper_resources=None, **kwargs):
        # A selected trial has one worker and one buddy queue entry.
        if type(max_pending) is not int or not 2 <= max_pending <= 64:
            raise ParallelError('Invalid native helper queue bound')
        super().__init__(capacity, max_stages, max_pending, **kwargs)
        # Public max_pending counts trials; this reviewed native sub-contract
        # gives each trial at most two internal FIFO records, bounded at128.
        self.max_pending = max_pending * 2
        self.trial_pending_limit = max_pending
        self.native_trials = set(native_trials); self.generation = generation
        self.buddies = {}
        self.native_helper_resources=native_resources(NATIVE_HELPER_RESOURCES if helper_resources is None else helper_resources)

    def request(self, identity, binding, resources, wait_seconds, kind='stage'):
        if kind == 'stage' and identity in self.native_trials:
            if identity in self.buddies or identity in self.records:
                raise ParallelError('Duplicate native trial reservation')
            if len(self.queue) + 2 > self.max_pending:
                raise ParallelError('Native trial pair exceeds finite queue capacity')
            helper = super().request(identity + '-native-budget',
                {'generation': self.generation, 'trial_id': identity}, self.native_helper_resources,
                wait_seconds, 'helper')
            self.buddies[identity] = helper
        return super().request(identity, binding, resources, wait_seconds, kind)

    def dispatch(self):
        admitted = []
        buddy_ids = {item.identity for item in self.buddies.values()}
        while self.queue and not self.closed:
            item = self.records[self.queue[0]]
            if self.clock() >= item.deadline:
                item.state = 'expired'; self.queue.popleft(); continue
            used = self.used()
            stages = sum(row.kind == 'stage' and row.state in LIVE for row in self.records.values())
            helpers = sum(row.identity in buddy_ids and row.state in LIVE for row in self.records.values())
            if (item.kind == 'stage' and stages >= self.max_stages
                    or item.identity in buddy_ids and (helpers >= self.max_stages or stages >= self.max_stages)):
                break
            authorities = set(item.binding.get('credential_authorities', []))
            if any(authorities.intersection(row.binding.get('credential_authorities', []))
                   for row in self.records.values() if row.state in LIVE):
                break
            if any(used[key] + item.resources[key] > self.capacity[key] for key in AXES):
                break
            self.queue.popleft(); item.state = 'reserved'; item.capability = secrets.token_hex(32)
            admitted.append(item)
        return admitted


class _HeldHelperSlot:
    """Allocator view that lends one already-reserved buddy to OwnedHelper."""
    def __init__(self, pool, trial_id, plan_sha256):
        self.pool, self.item = pool, pool.buddies[trial_id]
        self.trial_id, self.plan_sha256 = trial_id, plan_sha256
        self.in_use = False

    @property
    def records(self): return self.pool.records

    def request(self, identity, binding, resources, wait_seconds, kind='helper'):
        expected = {'generation': self.pool.generation, 'credential_authorities': [], 'plan_sha256': self.plan_sha256}
        if (self.in_use or self.pool.closed or self.item.state != 'reserved' or kind != 'helper'
                or resources != self.pool.native_helper_resources or binding != expected
                or type(wait_seconds) not in (int, float) or not 0 < wait_seconds <= 3600):
            raise ParallelError('Helper request differs from its held native reservation')
        self.item.binding = {**copy.deepcopy(binding), 'trial_id': self.trial_id}
        self.in_use = True
        return self.item

    def dispatch(self): return []

    def consume(self, identity, capability, binding, resources):
        if identity != self.item.identity or not self.in_use:
            raise ParallelError('Foreign native helper reservation')
        return self.pool.consume(identity, capability, binding, resources)

    def running(self, identity):
        if identity != self.item.identity: raise ParallelError('Foreign native helper reservation')
        return self.pool.running(identity)

    def release(self, identity, absent, sensitive_clean):
        if identity != self.item.identity or self.item.state not in LIVE:
            raise ParallelError('Invalid native helper release')
        if absent is not True or sensitive_clean is not True:
            return self.pool.release(identity, False, False)
        # Physical absence + purge are established by OwnedHelper before this
        # transition. Keep its finite weight held until trial finalization.
        self.item.state = 'reserved'; self.item.capability = secrets.token_hex(32)
        self.in_use = False
        return True

    def cancel_queued(self, identity):
        raise ParallelError('A held helper slot cannot become an anonymous queue item')

    def finalize(self):
        if self.in_use or self.item.state != 'reserved':
            self.pool.dependent_cleanup_confirmed = False
            raise ParallelError('Native helper writer or accounting remains uncertain')
        self.pool.release(self.item.identity, True, True)

    def quarantine(self):
        if self.item.state in LIVE:
            self.pool.release(self.item.identity, False, False)
        else:
            self.pool.stop()


class NativeCohort:
    def __init__(self, root, metadata, matrix, work, lab, args, registry, *,
                 redaction_values=(), per_trial_redaction=None, helper_factory=None):
        self.root = Path(root).resolve(); self.metadata = metadata; self.lab = lab
        self.args, self.registry = args, registry
        self.topology = native_helper(metadata.get('concurrency', {}))
        if self.topology is not None and self.topology!=NATIVE_HELPER_RESOURCES:
            raise ParallelError('Legacy native cohort requires the reviewed budget-only helper class')
        if self.topology is not None and metadata['execution']['platform'] != 'linux/arm64':
            raise ParallelError('Native budget helpers require this workstation native ARM64 platform')
        self.resources = resources.validate_policy(_read_owned(self.root / 'inputs' / 'resources.json')) if self.topology is not None else None
        self.plans, self.profiles, self.cells = {}, {}, {}
        self.native_trials = set(); self.release = None; self.pool = None
        self._values = list(dict.fromkeys(value for value in redaction_values if value))
        self._trial_values = copy.deepcopy(per_trial_redaction or {})
        self.helper_factory = helper_factory
        for cell in work:
            profile = agent_profiles.load(self.root / cell['agent_profile'])
            planpath = self.root / cell['plan']
            plan = lab.validate_plan(experiments.read_json(planpath), planpath.parent, profile,
                                     external_bindings=metadata.get('schema') == 3)
            if provenance.digest(plan) != cell['plan_sha256']:
                raise ParallelError('Native frozen plan identity changed')
            for task in plan['agents']:
                if any(key in task for key in native_budget_controls.NATIVE_FIELDS):
                    native_budget_controls.native_limits({key: task[key] for key in native_budget_controls.NATIVE_FIELDS if key in task},
                                                         timeout_seconds=task['timeout_seconds'], required=True)
                    self.native_trials.add(cell['trial_id'])
            self.plans[cell['trial_id']], self.profiles[cell['trial_id']], self.cells[cell['trial_id']] = plan, profile, cell
        if self.native_trials and self.topology is None:
            raise ParallelError('Native budgets require an explicitly frozen helper topology')

    def allocator(self, capacity, max_stages=2, max_pending=16):
        if self.topology is None:
            return Allocator(capacity, max_stages, max_pending)
        return NativeAllocator(capacity, max_stages, max_pending,
                               native_trials=self.native_trials, generation=self.registry.generation,helper_resources=self.topology)

    def attach(self, pool):
        self.pool = pool
        if self.topology is not None:
            if not isinstance(pool, NativeAllocator) or pool.native_trials != self.native_trials:
                raise ParallelError('Missing native helper pool admission')
            if getattr(self.registry, '_native_budget_cohort', self) is not self:
                raise ParallelError('Ambiguous native helper owner')
            self.registry._native_budget_cohort = self

    def admit_release(self, release):
        if release not in ('0.87.1', '1.2.0'): raise ParallelError('Unsupported exact native release')
        self.release = release

    def add_redaction_values(self, values, trial_id=None):
        target = self._values if trial_id is None else self._trial_values.setdefault(trial_id, [])
        for value in values:
            if value and value not in target: target.append(value)

    def bind(self, peer):
        trial = peer.bootstrap.get('intent', {}).get('trial_id')
        if trial not in self.native_trials: return None
        if self.release is None or self.pool is not peer.allocator:
            raise ParallelError('Native helper cohort lacks exact runtime admission')
        return NativePeer(self, peer)


class NativePeer:
    def __init__(self, cohort, peer):
        self.cohort, self.peer = cohort, peer
        self.trial_id = peer.bootstrap['intent']['trial_id']
        self.plan, self.profile = cohort.plans[self.trial_id], cohort.profiles[self.trial_id]
        self.cell = cohort.cells[self.trial_id]
        self.slot = _HeldHelperSlot(peer.allocator, self.trial_id, self.cell['plan_sha256'])
        self.helper = None; self.authority = None; self.current = None
        self.context = None; self.closed_stages = set(); self.failed = False; self.finalized = False
        self.extension_sha256 = None

    def _extension(self):
        from native_budget_execution import extension_order_sha256
        actual = extension_order_sha256(self.profile, self.cohort.release,
            runtime_root=self.peer.runroot / 'trusted-runtime',
            profile_root=(self.cohort.root / self.cell['agent_profile']).parent)
        if self.extension_sha256 is not None and actual != self.extension_sha256:
            raise ParallelError('Native guard content changed during a trial')
        return actual

    def _error(self):
        self.failed = True; self.slot.quarantine()
        raise ParallelError('Native helper ownership or accounting unavailable')

    def _binding(self, value, stage_name):
        from application_client import _binding
        _binding(value, self.cell['plan_sha256'])
        intent = self.peer.bootstrap['intent']
        if any(value[key] != intent[key] for key in ('run_id', 'attempt_id', 'trial_id')):
            raise ParallelError('Foreign native stage binding')
        stage = self.peer.runroot / 'stages' / value['stage_id'] / 'descriptor.json'
        desc = _read_owned(stage)
        if (any(desc.get(key) != value[key] for key in ('run_id', 'attempt_id', 'stage_id'))
                or desc.get('kind') != 'agent' or desc.get('workspace') != str(self.peer.runroot / 'workspace')
                or self.peer.runroot != self.cohort.root / 'runs' / intent['run_id']):
            raise ParallelError('Native stage descriptor differs from the frozen trial')
        task = next((task for task in self.plan['agents'] if task['name'] == stage_name), None)
        if task is None or not native_budget_controls.NATIVE_FIELDS <= set(task):
            raise ParallelError('Stage has no frozen native tool budget')
        if desc.get('label') != 'agent-' + str(self.plan['agents'].index(task) + 1) + '-' + stage_name:
            raise ParallelError('Native stage label differs from frozen order')
        return task

    def _network(self):
        found = [record for record in self.peer.registry.load() if record.get('kind') == 'network'
                 and record.get('container') == self.peer.bootstrap['network']
                 and record.get('generation') == self.peer.registry.generation
                 and record.get('registry') == self.peer.registry.registry_id
                 and record.get('daemon') == self.peer.registry.daemon
                 and record.get('status') not in ('released', 'quarantined')]
        if len(found) != 1: raise ParallelError('Missing verified native trial network')
        return found[0]

    def _reply(self, budget):
        return {'context': copy.deepcopy(self.context), 'network': self.peer.bootstrap['network'],
                'binding': copy.deepcopy(self.current), 'budget': budget}

    def begin(self, stage_name, binding):
        if self.failed or self.finalized or self.helper is not None or self.peer.active is not None:
            self._error()
        try:
            task = self._binding(binding, stage_name)
            if binding['stage_id'] in self.closed_stages: raise ParallelError('Native stage cannot reopen')
            extension = self._extension()
            from native_budget_client import NativeBudgetAuthority
            from application_client import OwnedHelper
            runtime = {'pi_release': self.cohort.release, 'image_id': self.cohort.metadata['execution']['image'],
                       'platform': self.cohort.metadata['execution']['platform'],
                       'container_profile': self.cohort.metadata['execution'].get('profile', 'core'),
                       'resources': copy.deepcopy(self.cohort.resources)}
            values = [*self.cohort._values, *self.cohort._trial_values.get(self.trial_id, [])]
            values.extend(value for assigned in self.peer.bootstrap.get('credentials', {}).values() for value in assigned.values())
            values.append(self.peer.bootstrap.get('inference', {}).get('token'))
            values.extend(self.peer.bootstrap.get('indexed', {}).get('tokens', {}).values())
            values = list(dict.fromkeys(value for value in values if value))
            authority = NativeBudgetAuthority(runtime=runtime, task=task, plan_sha256=self.cell['plan_sha256'],
                project=self.cohort.root / self.cell['source'], runroot=self.peer.runroot,
                profile=self.profile['kind'], redaction_values=values)
            grant = authority.grant(stage_name, binding)
            options = copy.copy(self.cohort.args)
            options.uid, options.gid = __import__('os').getuid(), __import__('os').getgid()
            if getattr(options, 'native_platform', None) != 'linux/arm64' or options.platform != runtime['platform']:
                raise ParallelError('Native helper architecture was not observed at admission')
            helper = (self.cohort.helper_factory or OwnedHelper.start)(authority, lab=self.cohort.lab,
                args=options, registry=self.peer.registry, allocator=self.slot,
                participant_resources=self.peer.reservation.resources,
                participant_reservation=self.peer.reservation, borrowed_network=self._network())
            self.helper, self.authority, self.current = helper, authority, copy.deepcopy(binding)
            self.extension_sha256 = extension
            self.context = authority.budget_context(grant, extension)
            return self._reply(helper.native_budget_status())
        except (OSError, ValueError, KeyError, TypeError):
            self._error()

    def _stage(self, stage_id):
        if self.failed or self.finalized or self.helper is None or self.current['stage_id'] != stage_id:
            self._error()

    def status(self, stage_id):
        self._stage(stage_id)
        try: return self.helper.native_budget_status()
        except (OSError, ValueError): self._error()

    def validate_agent_launch(self, argv, binding):
        """A task cannot remove, redirect or substitute its parent guard context."""
        worker = argv.index('/opt/pi-lab/worker.py')
        if argv[worker + 1:worker + 2] != ['agent']: return
        if set(binding) != {'stage_id', 'segment_id'} or not all(controls.valid_id(binding[key]) for key in binding):
            raise ParallelError('Native agent launch lacks exact parent stage identity')
        tail = argv[worker + 1:]
        expected_task = '/opt/pi-control/segments/' + binding['segment_id'] + '/task.json'
        if tail != ['agent', '--task', expected_task]:
            raise ParallelError('Native agent task locator differs from its admitted segment')
        segment = self.peer.runroot / 'controls' / binding['stage_id'] / 'segments' / binding['segment_id']
        task = _read_owned(segment / 'task.json')
        frozen = next((item for item in self.plan['agents'] if item['name'] == task.get('name')), None)
        if frozen is None: raise ParallelError('Agent does not belong to the frozen native trial')
        budgeted = native_budget_controls.NATIVE_FIELDS <= set(frozen)
        if not budgeted:
            if native_budget_controls.NATIVE_FIELDS.intersection(task) or task.get('native_budget_context'):
                raise ParallelError('Unbudgeted stage cannot acquire native helper authority')
            return
        if (self.failed or self.helper is None or any(self.current[key] != binding[key] for key in binding)
                or any(task.get(key) != frozen[key] for key in native_budget_controls.NATIVE_FIELDS)):
            raise ParallelError('Native agent has no matching live helper authority')
        locator = task.get('native_budget_context')
        prefix = '/opt/pi-control/segments/' + binding['segment_id'] + '/'
        if type(locator) is not str or not locator.startswith(prefix):
            raise ParallelError('Native agent omitted its protected guard context')
        relative = locator[len(prefix):]; c.relative(relative, '')
        if '/' in relative: raise ParallelError('Native guard context must be a direct private segment file')
        path = segment / relative
        context = _read_owned(path,private=True,maximum=65536)
        if context != self.context or self._extension() != self.extension_sha256:
            raise ParallelError('Native guard context or code identity changed')

    def checkpoint(self, stage_id):
        self._stage(stage_id)
        if self.peer.active is not None: self._error()
        try: return self.helper.checkpoint_native_budget()
        except (OSError, ValueError): self._error()

    def _command(self, stage_id, command_id, kind):
        self._stage(stage_id)
        if not controls.valid_id(command_id): raise ParallelError('Invalid native control identity')
        path = (self.peer.runroot / 'stages' / stage_id / 'budget-requests' / (command_id + '.json')
                if kind == 'extend_budget' else self.peer.runroot / 'controls' / stage_id / 'inbox' / 'directives' / (command_id + '.json'))
        record = _read_owned(path)
        fields = ('id', 'intervention_id', 'run_id', 'attempt_id', 'stage_id', 'segment_id', 'kind')
        if (record.get('id') != command_id or record.get('kind') != kind
                or any(record.get(key) != self.current[key] for key in ('run_id', 'attempt_id', 'stage_id', 'segment_id'))):
            raise ParallelError('Native control scope differs from current segment')
        metadata = {'schema', 'id', 'intervention_id', 'payload_digest', 'run_id', 'attempt_id',
                    'stage_id', 'segment_id', 'kind', 'expected_stage_revision', 'created_at'}
        payload = {key: value for key, value in record.items() if key not in metadata}
        if hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest() != record.get('payload_digest'):
            raise ParallelError('Native control payload differs from its retained digest')
        history = controls.history(self.peer.runroot)
        # The requested CLI form and accepted normalized payload have different
        # digests. Match requested identity, then exact accepted payload/revisions.
        for status in ('requested', 'accepted'):
            selected = fields + (('payload_digest', 'expected_stage_revision', 'expected_budget_revision') if status == 'accepted' else ())
            if not any(event.get('status') == status and event.get('authorization_source') == 'parent_cli'
                       and all(event.get(key) == record.get(key) for key in selected) for event in history):
                raise ParallelError('Native control lacks retained parent authorization')
        folder = self.peer.runroot / 'stages' / stage_id / 'native-budget-parent'
        folder.mkdir(mode=0o700, exist_ok=True)
        target = folder / (command_id + '.json')
        if target.exists() or target.is_symlink(): raise ParallelError('Native control cannot be replayed')
        intent = {'schema': 1, 'command_id': command_id, 'kind': kind,
                  'stage_id': stage_id, 'payload_digest': record['payload_digest'], 'status': 'intent'}
        controls.atomic(target, intent)
        return record, target, intent

    def extend(self, stage_id, command_id, max_tool_calls, remaining_seconds):
        try:
            record, target, intent = self._command(stage_id, command_id, 'extend_budget')
            budget = _read_owned(self.peer.runroot / 'stages' / stage_id / 'budget.json')
            values = record['limits']
            expected = record.get('expected_budget_revision')
            if type(expected) is not int or expected != budget['revision'] or values.get('max_tool_calls') != max_tool_calls:
                raise ParallelError('Native extension revision or limits differ')
            before = self.helper.native_budget_status()
            for field in ('reporting_reserve_calls', 'reporting_reserve_seconds'):
                if values.get(field) != before['limits'][field]: raise ParallelError('Native reserves cannot be reduced or replaced')
            if (type(remaining_seconds) not in (int, float) or not math.isfinite(remaining_seconds)
                    or not 0 < remaining_seconds <= values['timeout_seconds']):
                raise ParallelError('Native extension remaining duration is invalid')
            if type(max_tool_calls) is not int or not before['limits']['max_tool_calls'] <= max_tool_calls <= 500:
                raise ParallelError('Native call maximum cannot shrink')
            remaining = budget['started_host_monotonic'] + values['timeout_seconds'] - time.monotonic()
            if not math.isfinite(remaining) or not 0 < remaining <= 3600:
                raise ParallelError('Native extension missed the parent hard deadline')
            prior_timeout=budget['effective_limits']['timeout_seconds']
            if type(prior_timeout) is not int or values['timeout_seconds']<prior_timeout:
                raise ParallelError('Native timeout cannot shrink')
            helper_remaining=None if values['timeout_seconds']==prior_timeout else remaining
            result = self.helper.extend_native_budget(max_tool_calls=max_tool_calls, remaining_seconds=helper_remaining)
            if native_budget_controls.PHASES.index(result['phase']) < native_budget_controls.PHASES.index(before['phase']):
                raise ParallelError('Native extension reopened a terminal budget phase')
            controls.atomic(target, {**intent, 'status': 'applied', 'budget': result})
            return result
        except (OSError, ValueError, KeyError, TypeError): self._error()

    def continuation(self, stage_id, command_id, segment_id):
        if self.peer.active is not None: self._error()
        try:
            record, target, intent = self._command(stage_id, command_id, 'steer')
            before = self.helper.native_budget_status()
            context = self.helper.continue_native_budget(segment_id, self._extension())
            result = self.helper.native_budget_status()
            if (result['limits'] != before['limits'] or result['counts'] != before['counts']
                    or native_budget_controls.PHASES.index(result['phase']) < native_budget_controls.PHASES.index(before['phase'])):
                raise ParallelError('Native continuation reset its budget')
            self.current['segment_id'] = segment_id; self.context = context
            controls.atomic(target, {**intent, 'status': 'applied', 'budget': result})
            return self._reply(result)
        except (OSError, ValueError, KeyError, TypeError): self._error()

    def close(self, stage_id):
        self._stage(stage_id)
        if self.peer.active is not None: self._error()
        try:
            result = self.helper.native_budget_status()
            self.helper.revoke(self.authority._grants[-1])
            receipt = self.helper.cleanup(writers_absent=True); self.helper.require_clean()
            self.closed_stages.add(stage_id); self.helper = None; self.authority = None; self.context = None; self.current = None
            return {'budget': result, 'cleanup': receipt}
        except (OSError, ValueError): self._error()

    def finalize(self):
        if self.finalized: return True
        try:
            if self.peer.active is not None: self._error()
            if self.failed:
                # An accounting failure still needs physical cleanup once writer
                # absence is established. It never resumes or repairs the stage.
                if self.helper is not None:
                    try:
                        self.helper.cleanup(writers_absent=True);self.helper.require_clean()
                        self.helper=None
                        self.slot.finalize();self.finalized=True
                    except (OSError,ValueError):
                        self.slot.quarantine()
                raise ParallelError('Native stage failed; known cleanup retained without continuation')
            if self.helper is not None: self.close(self.current['stage_id'])
            self.slot.finalize(); self.finalized = True
            return True
        except (OSError,ValueError):
            if not self.finalized:self.peer.allocator.dependent_cleanup_confirmed=False
            raise


def stop_owned_worker(peer):
    """After its host controller exits, stop only an exactly matched container."""
    record = peer.active
    if record is None: return True
    try:
        daemon = peer.registry.command(['docker', 'info', '--format', '{{.ID}}'])
        if daemon.returncode or daemon.stdout.strip() != peer.registry.daemon:
            raise ParallelError('Native cleanup daemon changed')
        reply = peer.registry.command(['docker', 'container', 'inspect', record['container']])
        if not ownership_registry.absent(reply):
            if reply.returncode or len(reply.stdout.encode()) > 1048576:
                raise ParallelError('Native worker ownership unavailable')
            rows = json.loads(reply.stdout)
            if (type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict
                    or type(rows[0].get('Config')) is not dict
                    or type(rows[0]['Config'].get('Labels')) is not dict
                    or type(rows[0].get('Mounts')) is not list
                    or any(type(mount) is not dict for mount in rows[0]['Mounts'])):
                raise ParallelError('Native worker ownership response is malformed')
            observed = rows[0]; labels = observed['Config']['Labels']
            identifier = observed.get('Id'); mounts = observed.get('Mounts', [])
            if (type(identifier) is not str or len(identifier) != 64 or any(ch not in '0123456789abcdef' for ch in identifier)
                    or observed.get('Image') != record['image']
                    or labels.get(ownership_registry.LABEL) != record['launch_id']
                    or labels.get(ownership_registry.REGISTRY_LABEL) != record['registry']
                    or len(mounts) != len(record['mounts'])
                    or any(not any(actual.get('Source') == expected['source'] and actual.get('Destination') == expected['target']
                                       and actual.get('RW') == expected['rw'] for actual in mounts) for expected in record['mounts'])):
                raise ParallelError('Native worker cleanup ownership mismatch')
            peer.registry.command(['docker', 'rm', '--force', identifier])
        if not peer.registry.confirm_absent(record): raise ParallelError('Native worker absence unconfirmed')
        peer.active = None
        return True
    except (OSError, ValueError, KeyError, TypeError):
        peer.allocator.dependent_cleanup_confirmed = False
        record['status'] = 'quarantined'; peer.registry.write(record)
        if peer.native_budget is not None: peer.native_budget._error()
        raise ParallelError('Native worker cleanup unavailable') from None
