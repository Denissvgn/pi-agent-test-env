"""Durable native-call admission, independent of model turns and tool subprocesses.

The owner supplies reviewed native schemas and a protected ledger directory. Every
assistant batch is committed before any of its tools may start. Payloads and their
digests stay private; snapshot() is the only public projection. This module does
not launch inference, extend a session or retry an operation.

Deadlines use the helper's monotonic clock, NOT a host's monotonic timestamp.
Cross-process restoration requires the same explicitly bound clock_domain. The
default process-specific domain deliberately refuses ambiguous restoration.
"""
from contextlib import contextmanager
import copy
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import time
import uuid

import application_contracts as c

MAX_STATE_BYTES = 8 * 1024 * 1024
MAX_BATCH_CALLS = 500
MAX_CALL_BYTES = 320 * 1024
MAX_UNIQUE_CALLS = 50000  # 100 reviewed turns x 500 declarations; no unbounded history.
BINDING_FIELDS = {'plan_sha256', 'run_id', 'trial_id', 'attempt_id', 'stage_id',
                  'session_id', 'pi_release'}
COUNTERS = ('attempted', 'charged', 'executed_known', 'executed_unknown',
            'grants_consumed', 'blocked', 'worker_observed', 'helper_verified')
PHASES = ('business', 'reporting', 'exhausted')
PROCESS_CLOCK_DOMAIN = 'process-' + str(os.getpid()) + '-' + uuid.uuid4().hex


class BudgetError(ValueError):
    def __init__(self, reason='accounting_unavailable', *, poison=False):
        self.reason, self.poison = reason, poison
        super().__init__(reason)


def _native(value):
    if type(value) is not str or not re.fullmatch(r'[\x21-\x7e]{1,128}', value):
        raise BudgetError(poison=True)
    return value


def _uuid(value, nullable=False):
    if nullable and value is None:
        return value
    try:
        if type(value) is not str or str(uuid.UUID(value)) != value:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise BudgetError(poison=True) from None
    return value


def _digest(value):
    return hashlib.sha256(c.canonical(value)).hexdigest()


def _args_digest(value):
    raw = c.canonical(value)
    if len(raw) > MAX_CALL_BYTES:
        raise BudgetError('request_invalid')
    return hashlib.sha256(raw).hexdigest()


def _binding(value):
    c.exact(value, BINDING_FIELDS, '/binding')
    c.sha256(value['plan_sha256'], '/binding/plan_sha256')
    c.choice(value['pi_release'], c.RELEASES, '/binding/pi_release')
    for name in BINDING_FIELDS - {'plan_sha256', 'pi_release'}:
        _uuid(value[name], name == 'trial_id')
    return copy.deepcopy(value)


def _schema(schema, depth=0):
    """Reviewed bounded JSON-schema subset; no references or coercion."""
    if type(schema) is not dict or depth > 12:
        raise BudgetError('contract_invalid')
    allowed = {'type', 'properties', 'required', 'additionalProperties', 'items',
               'minItems', 'maxItems', 'minLength', 'maxLength', 'minimum',
               'maximum', 'enum', 'description', 'anyOf', 'pattern'}
    if set(schema) - allowed:
        raise BudgetError('contract_invalid')
    if 'pattern' in schema and schema['pattern'] != '^[a-z0-9-]+$':
        raise BudgetError('contract_invalid')
    types = schema.get('type', [])
    types = types if type(types) is list else [types]
    if any(t not in ('object', 'array', 'string', 'integer', 'number', 'boolean', 'null')
           for t in types) or len(types) != len(set(types)):
        raise BudgetError('contract_invalid')
    properties = schema.get('properties', {})
    required = schema.get('required', [])
    if (type(properties) is not dict or len(properties) > 64 or type(required) is not list
            or any(type(k) is not str for k in required) or len(set(required)) != len(required)
            or set(required) - set(properties) or type(schema.get('additionalProperties', True)) is not bool):
        raise BudgetError('contract_invalid')
    for name, child in properties.items():
        if type(name) is not str or not 1 <= len(name) <= 128:
            raise BudgetError('contract_invalid')
        _schema(child, depth + 1)
    if 'items' in schema:
        _schema(schema['items'], depth + 1)
    if 'anyOf' in schema:
        if type(schema['anyOf']) is not list or not 1 <= len(schema['anyOf']) <= 8:
            raise BudgetError('contract_invalid')
        for child in schema['anyOf']:
            _schema(child, depth + 1)
    for name in ('minItems', 'maxItems', 'minLength', 'maxLength'):
        if name in schema and (type(schema[name]) is not int or not 0 <= schema[name] <= 1048576):
            raise BudgetError('contract_invalid')
    for name in ('minimum', 'maximum'):
        if name in schema and (type(schema[name]) not in (int, float) or not math.isfinite(schema[name])):
            raise BudgetError('contract_invalid')
    if 'enum' in schema and (type(schema['enum']) is not list or not 1 <= len(schema['enum']) <= 128):
        raise BudgetError('contract_invalid')


def _value(value, schema):
    if 'anyOf' in schema and not any(_value(value, branch) for branch in schema['anyOf']):
        return False
    actual = {dict: 'object', list: 'array', str: 'string', int: 'integer', float: 'number',
              bool: 'boolean', type(None): 'null'}.get(type(value))
    kinds = schema.get('type')
    kinds = kinds if type(kinds) is list else [kinds] if kinds is not None else []
    if kinds and actual not in kinds and not (actual == 'integer' and 'number' in kinds):
        return False
    if 'enum' in schema and c.canonical(value) not in [c.canonical(v) for v in schema['enum']]:
        return False
    if actual == 'object':
        props = schema.get('properties', {})
        if set(schema.get('required', [])) - set(value):
            return False
        if schema.get('additionalProperties', True) is False and set(value) - set(props):
            return False
        if any(not _value(child, props[name]) for name, child in value.items() if name in props):
            return False
    elif actual == 'array':
        if not schema.get('minItems', 0) <= len(value) <= schema.get('maxItems', 100000):
            return False
        if 'items' in schema and any(not _value(child, schema['items']) for child in value):
            return False
    elif actual == 'string':
        if not schema.get('minLength', 0) <= len(value) <= schema.get('maxLength', MAX_CALL_BYTES):
            return False
        if 'pattern' in schema and re.fullmatch(schema['pattern'], value) is None:
            return False
    elif actual in ('integer', 'number'):
        if not schema.get('minimum', -float('inf')) <= value <= schema.get('maximum', float('inf')):
            return False
    return actual is not None


def _tools(native_tools):
    c.array(native_tools, '/native_tools', 64, 1)
    result = {}
    for tool in native_tools:
        c.exact(tool, {'name', 'description', 'parameters'}, '/native_tools')
        name = tool['name']
        if type(name) is not str or not re.fullmatch('[A-Za-z_][A-Za-z0-9_.-]{0,63}', name) or name in result:
            raise BudgetError('contract_invalid')
        c.text(tool['description'], '/native_tools/description', 8192)
        _schema(tool['parameters'])
        result[name] = copy.deepcopy(tool['parameters'])
    if 'budget_status' not in result:
        raise BudgetError('contract_invalid')
    return result


def _private_parent(path):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.absolute().parent.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise BudgetError()
    finally:
        os.close(fd)


class BudgetLedger:
    """One serialized parent/helper-owned ledger for one attempt/stage."""
    def __init__(self, path, binding, clock, clock_domain):
        self.path = Path(path).absolute()
        self.lock_path = self.path.with_name(self.path.name + '.lock')
        self.pending_path = self.path.with_name(self.path.name + '.pending')
        self.binding, self.clock = _binding(binding), clock
        self.clock_domain = clock_domain or PROCESS_CLOCK_DOMAIN
        self._failed = False
        try:
            _private_parent(self.path)
        except OSError:
            raise BudgetError() from None

    @classmethod
    def create(cls, path, *, binding, limits, native_tools, initial_segment_id,
               deadline, profile='application-client', completion=None,
               prepare_arguments=None, clock=time.monotonic, clock_domain=None):
        ledger = cls(path, binding, clock, clock_domain)
        _uuid(initial_segment_id)
        c.exact(limits, {'max_tool_calls', 'reporting_reserve_calls',
                         'reporting_reserve_seconds'}, '/limits')
        c.integer(limits['max_tool_calls'], '/limits/max_tool_calls', 1, 500)
        c.integer(limits['reporting_reserve_calls'], '/limits/reporting_reserve_calls',
                  1, min(20, limits['max_tool_calls'] - 1))
        c.integer(limits['reporting_reserve_seconds'], '/limits/reporting_reserve_seconds', 1, 120)
        tools = _tools(native_tools)
        preparation = {name: 'none' for name in tools} if prepare_arguments is None else prepare_arguments
        c.exact(preparation, set(tools), '/prepare_arguments')
        if any(value not in ('none', 'reviewed_pure') for value in preparation.values()):
            raise BudgetError('contract_invalid')
        if profile not in ('application-client', 'builtin', 'fixture-lookup'):
            raise BudgetError('contract_invalid')
        if profile == 'application-client':
            completion = c.validate_completion(completion)
        elif completion is not None:
            raise BudgetError('contract_invalid')
        now = clock()
        if (type(now) not in (int, float) or not math.isfinite(now) or type(deadline) not in (int, float)
                or not math.isfinite(deadline) or not 0 < deadline - now <= 3600
                or not limits['reporting_reserve_seconds'] < deadline - now):
            raise BudgetError('contract_invalid')
        c.text(ledger.clock_domain, '/clock_domain', 256)
        configuration = {'binding': copy.deepcopy(binding), 'limits': copy.deepcopy(limits),
                         'tools': tools, 'profile': profile, 'completion': completion,
                         'prepare_arguments': copy.deepcopy(preparation),
                         'clock_domain': ledger.clock_domain}
        state = {'schema': 1, 'document_type': 'native_tool_budget_ledger',
                 'configuration': configuration, 'configuration_sha256': _digest(configuration),
                 'deadline': deadline, 'last_now': now, 'phase': 'business', 'accounting': 'available',
                 'assisted': False, 'segments': [initial_segment_id], 'batches': {}, 'calls': {},
                 'seen_calls': {}, 'seen_batches': {},
                 'counts': {name: 0 for name in COUNTERS},
                 'per_tool': {name: {key: 0 for key in COUNTERS} for name in [*tools, '__unknown__']}}
        try:
            lock = os.open(ledger.lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(lock)
            ledger._persist(state, initial=True)
        except (OSError, c.ContractError):
            raise BudgetError() from None
        return ledger

    @classmethod
    def open(cls, path, *, binding, clock=time.monotonic, clock_domain=None):
        ledger = cls(path, binding, clock, clock_domain)
        ledger._run(lambda state: ledger._public(state))
        return ledger

    @contextmanager
    def _lock(self):
        fd = os.open(self.lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise BudgetError()
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def _read(self):
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > MAX_STATE_BYTES):
                raise BudgetError()
            state = c.loads(source.read(MAX_STATE_BYTES + 1), max_bytes=MAX_STATE_BYTES)
        if (state.get('schema') != 1 or state.get('document_type') != 'native_tool_budget_ledger'
                or state.get('state_sha256') != _digest({k: v for k, v in state.items() if k != 'state_sha256'})
                or state.get('configuration_sha256') != _digest(state['configuration'])
                or state['configuration']['binding'] != self.binding
                or state['configuration']['clock_domain'] != self.clock_domain):
            raise BudgetError()
        return state

    def _persist(self, state, initial=False):
        state['state_sha256'] = _digest({k: v for k, v in state.items() if k != 'state_sha256'})
        raw = c.canonical(state)
        if len(raw) > MAX_STATE_BYTES:
            raise BudgetError()
        temporary = self.path if initial else self.path.with_name('.' + self.path.name + '-' + uuid.uuid4().hex)
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as output:
                output.write(raw); output.flush(); os.fsync(output.fileno())
            if not initial:
                os.replace(temporary, self.path)
            parent = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        finally:
            if not initial:
                temporary.unlink(missing_ok=True)

    def _run(self, operation, *, allow_poisoned=False):
        if self._failed:
            raise BudgetError()
        try:
            with self._lock():
                if self.pending_path.exists() or self.pending_path.is_symlink():
                    raise BudgetError()
                state = self._read()
                if state['accounting'] != 'available' and not allow_poisoned:
                    raise BudgetError()
                # An interrupted/uncertain transaction cannot be mistaken for an
                # unused old budget after process loss. Never auto-delete this intent.
                pending = os.open(self.pending_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(pending, 'wb') as output:
                    output.write(b'pending\n'); output.flush(); os.fsync(output.fileno())
                self._sync_parent()
                try:
                    now = self.clock()
                    if type(now) not in (int, float) or not math.isfinite(now) or now < state['last_now']:
                        raise BudgetError(poison=True)
                    state['last_now'] = now
                    self._phase(state)
                    result = operation(state)
                except BudgetError as exc:
                    if exc.poison:
                        state['accounting'] = 'unavailable'
                    self._persist(state)
                    self._finish_pending()
                    raise
                except (c.ContractError, KeyError, TypeError, ValueError, OverflowError, RecursionError):
                    state['accounting'] = 'unavailable'; self._persist(state)
                    self._finish_pending()
                    raise BudgetError() from None
                self._persist(state)
                self._finish_pending()
                return result
        except BudgetError:
            raise
        except (OSError, c.ContractError, KeyError, TypeError, ValueError):
            self._failed = True
            raise BudgetError() from None

    def _sync_parent(self):
        fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _finish_pending(self):
        self.pending_path.unlink()
        self._sync_parent()

    def _phase(self, state):
        limits = state['configuration']['limits']
        if state['counts']['charged'] >= limits['max_tool_calls'] or state['last_now'] >= state['deadline']:
            state['phase'] = 'exhausted'
        elif (state['phase'] == 'business' and
              (state['counts']['charged'] >= limits['max_tool_calls'] - limits['reporting_reserve_calls']
               or state['deadline'] - state['last_now'] <= limits['reporting_reserve_seconds'])):
            state['phase'] = 'reporting'

    def _public(self, state):
        limits, counts = state['configuration']['limits'], copy.deepcopy(state['counts'])
        remaining = max(0, limits['max_tool_calls'] - counts['charged'])
        counts['executed'] = None if counts['executed_unknown'] else counts['executed_known']
        per_tool = copy.deepcopy(state['per_tool'])
        for item in per_tool.values():
            item['executed'] = None if item['executed_unknown'] else item['executed_known']
        return {'schema': 1, 'document_type': 'native_tool_budget_status',
                'phase': state['phase'], 'accounting': state['accounting'],
                'limits': copy.deepcopy(limits), 'counts': counts, 'per_tool': per_tool,
                'remaining_calls': remaining,
                'remaining_admissible_calls': remaining if state['accounting'] == 'available' and state['phase'] != 'exhausted' else 0,
                'business_calls_remaining': max(0, remaining - limits['reporting_reserve_calls']) if state['phase'] == 'business' else 0,
                'reporting_reserve_calls_remaining': min(remaining, limits['reporting_reserve_calls']),
                'assisted': state['assisted']}

    def _scope(self, state, scope):
        if type(scope) is not dict:
            raise BudgetError(poison=True)
        for key, value in self.binding.items():
            if key == 'pi_release' and key not in scope:
                continue
            if scope.get(key) != value:
                raise BudgetError(poison=True)
        segment = _uuid(scope.get('segment_id'))
        if not state['segments'] or segment != state['segments'][-1]:
            raise BudgetError(poison=True)
        completion = state['configuration']['completion']
        if completion is not None and 'participant' in scope and scope['participant'] != completion['participant']:
            raise BudgetError(poison=True)
        return segment

    def _count(self, state, tool, field, amount=1):
        state['counts'][field] += amount
        name = tool if type(tool) is str and tool in state['configuration']['tools'] else '__unknown__'
        state['per_tool'][name][field] += amount

    def _report_safe(self, state, name, args):
        if name == 'budget_status':
            return args == {}
        config = state['configuration']
        if config['profile'] != 'application-client':
            return False
        completion = config['completion']
        artifacts = {a['id']: a for a in completion['artifacts']}
        if name in ('artifact_read', 'artifact_write'):
            expected = {'artifact_id'} | ({'content'} if name == 'artifact_write' else set())
            if type(args) is not dict or set(args) != expected or args['artifact_id'] not in artifacts:
                return False
            if name == 'artifact_write':
                artifact, content = artifacts[args['artifact_id']], args['content']
                if type(content) is not str or len(content.encode()) > artifact['max_bytes']:
                    return False
                if artifact['media_type'] == 'application/json':
                    try:
                        c.loads(content)
                    except c.ContractError:
                        return False
            return True
        if name == 'report_write':
            if type(args) is not dict or set(args) != {'report'}:
                return False
            try:
                report = c.validate_report(args['report'])
            except c.ContractError:
                return False
            return report['contract_id'] == completion['id'] and report['participant'] == completion['participant']
        return False

    def reserve_batch(self, scope, batch_id, calls, stop_reason='toolUse'):
        def apply(state):
            segment = self._scope(state, scope); _native(batch_id)
            if type(calls) is not list or not 1 <= len(calls) <= MAX_BATCH_CALLS:
                raise BudgetError(poison=True)
            batch_key = _digest([segment, batch_id])
            # Record every received native declaration, including duplicate attempts.
            for call in calls:
                self._count(state, call.get('name') if type(call) is dict else None, 'attempted')
            keys = []
            try:
                for call in calls:
                    c.exact(call, {'id', 'name', 'arguments'}, '/calls')
                    _native(call['id']); _native(call['name'])
                    keys.append(_digest([segment, call['id']]))
            except (BudgetError, c.ContractError):
                for call in calls:
                    self._count(state, call.get('name') if type(call) is dict else None, 'blocked')
                raise BudgetError(poison=True) from None
            if (batch_key in state['batches'] or batch_key in state['seen_batches'] or len(set(keys)) != len(keys)
                    or any(key in state['seen_calls'] for key in keys)
                    or any(not b['reconciled'] for b in state['batches'].values())
                    or len(state['seen_calls']) + len(calls) > MAX_UNIQUE_CALLS):
                for call in calls:
                    self._count(state, call['name'], 'blocked')
                raise BudgetError(poison=True)
            if stop_reason not in ('toolUse', 'stop', 'length', 'error', 'aborted'):
                raise BudgetError(poison=True)
            results = []
            for key, call in zip(keys, calls):
                name, args = call['name'], call['arguments']
                try:
                    digest = _args_digest(args)
                    valid = name in state['configuration']['tools'] and _value(args, state['configuration']['tools'][name])
                except (BudgetError, c.ContractError):
                    digest, valid = None, False
                safe = valid and self._report_safe(state, name, args)
                self._phase(state)
                reason, charged = None, False
                if state['phase'] == 'exhausted':
                    reason = 'tool_budget_exhausted'
                elif state['phase'] == 'reporting' and not safe:
                    reason = 'reporting_only'
                else:
                    self._count(state, name, 'charged')
                    charged = True
                    if not valid or stop_reason in ('length', 'error', 'aborted'):
                        reason = 'request_invalid'
                if reason is not None:
                    self._count(state, name, 'blocked')
                entry = {'segment_id': segment, 'batch_id': batch_id, 'native_call_id': call['id'],
                         'tool_name': name, 'arguments_sha256': digest, 'admitted': reason is None,
                         'charged': charged,
                         'reason': reason, 'consumed': False, 'execution_nonce': None,
                         'effect_used': False, 'execution_observed': False,
                         'worker_observed': False, 'helper_verified': False,
                         'completed': False, 'is_error': None}
                state['calls'][key] = entry
                state['seen_calls'][key] = True
                results.append({'id': call['id'], 'name': name, 'admitted': reason is None, 'reason': reason})
                self._phase(state)
            state['batches'][batch_key] = {'segment_id': segment, 'batch_id': batch_id,
                                          'keys': keys, 'reconciled': False}
            return {'schema': 1, 'calls': results, 'snapshot': self._public(state)}
        return self._run(apply)

    def _entry(self, state, scope, native_call_id, tool_name, raw_input=None, check_input=False):
        segment = self._scope(state, scope); _native(native_call_id); _native(tool_name)
        entry = state['calls'].get(_digest([segment, native_call_id]))
        if entry is None or entry['tool_name'] != tool_name:
            raise BudgetError(poison=True)
        if check_input and (entry['arguments_sha256'] is None or _args_digest(raw_input) != entry['arguments_sha256']):
            raise BudgetError(poison=True)
        return entry

    def consume(self, scope, batch_id, native_call_id, tool_name, raw_input):
        def apply(state):
            entry = self._entry(state, scope, native_call_id, tool_name, raw_input, True)
            if entry['batch_id'] != batch_id or entry['consumed'] or entry['completed']:
                raise BudgetError(poison=True)
            if not entry['admitted']:
                raise BudgetError(entry['reason'])
            if state['last_now'] >= state['deadline']:
                raise BudgetError('tool_budget_exhausted')
            entry['consumed'] = True; entry['execution_nonce'] = secrets.token_hex(32)
            self._count(state, tool_name, 'grants_consumed')
            self._count(state, tool_name, 'executed_unknown')
            return {'execution_nonce': entry['execution_nonce'], 'snapshot': self._public(state)}
        return self._run(apply)

    def _execution(self, grant, scope, native_call_id, tool_name, raw_input, effect):
        def apply(state):
            entry = self._entry(state, scope, native_call_id, tool_name, raw_input, True)
            candidate = grant if type(grant) is str and re.fullmatch('[a-f0-9]{64}', grant) else '0' * 64
            matched = secrets.compare_digest(candidate, entry['execution_nonce'] or 'f' * 64)
            if (candidate != grant or not matched or not entry['admitted'] or not entry['consumed']
                    or entry['completed'] or effect and entry['effect_used']
                    or not effect and entry['worker_observed']):
                raise BudgetError(poison=True)
            if state['last_now'] >= state['deadline']:
                raise BudgetError('tool_budget_exhausted')
            if not entry['execution_observed']:
                entry['execution_observed'] = True; self._count(state, tool_name, 'executed_known')
                self._count(state, tool_name, 'executed_unknown', -1)
            if effect:
                entry['effect_used'] = True
                entry['helper_verified'] = True; self._count(state, tool_name, 'helper_verified')
            else:
                entry['worker_observed'] = True; self._count(state, tool_name, 'worker_observed')
            return True
        return self._run(apply)

    def verify_effect(self, grant, scope, native_call_id, tool_name, raw_input):
        """Trusted service consumes the one-use action nonce, without another charge."""
        return self._execution(grant, scope, native_call_id, tool_name, raw_input, True)

    def observe_execution(self, grant, scope, native_call_id, tool_name, raw_input):
        """Reviewed builtin/custom execute-entry wrapper; not a post-start inference."""
        return self._execution(grant, scope, native_call_id, tool_name, raw_input, False)

    def complete(self, scope, batch_id, native_call_id, tool_name, is_error):
        def apply(state):
            entry = self._entry(state, scope, native_call_id, tool_name)
            if type(is_error) is not bool or entry['batch_id'] != batch_id or entry['completed']:
                raise BudgetError(poison=True)
            if not entry['admitted'] and not is_error:
                raise BudgetError(poison=True)
            if entry['admitted'] and not entry['consumed']:
                if not is_error:
                    raise BudgetError(poison=True)
                self._count(state, tool_name, 'blocked')
            entry['completed'] = True; entry['is_error'] = is_error
            return self._public(state)
        return self._run(apply)

    def reconcile(self, scope, batch_id):
        def apply(state):
            segment = self._scope(state, scope); _native(batch_id)
            batch = state['batches'].get(_digest([segment, batch_id]))
            if batch is None or batch['reconciled'] or any(not state['calls'][k]['completed'] for k in batch['keys']):
                raise BudgetError(poison=True)
            batch['reconciled'] = True
            # Keep a permanent private duplicate detector, not arbitrary denied
            # payloads/rows. Application receipts/effects are never evicted here.
            for key in batch['keys']:
                if not state['calls'][key]['charged']:
                    del state['calls'][key]
            batch_key = _digest([segment, batch_id])
            state['seen_batches'][batch_key] = True
            del state['batches'][batch_key]
            return self._public(state)
        return self._run(apply)

    def checkpoint(self, scope):
        def apply(state):
            self._scope(state, scope)
            if any(not b['reconciled'] for b in state['batches'].values()):
                raise BudgetError(poison=True)
            return self._public(state)
        return self._run(apply)

    def add_segment(self, segment_id):
        """Parent-only: explicit continuation carries totals and phase."""
        def apply(state):
            _uuid(segment_id)
            if segment_id in state['segments'] or len(state['segments']) >= 64 or any(not b['reconciled'] for b in state['batches'].values()):
                raise BudgetError(poison=True)
            state['segments'].append(segment_id)
            return self._public(state)
        return self._run(apply)

    def extend(self, *, max_tool_calls=None, deadline=None, authorized=False):
        """Parent-only explicit assistance; never returns reporting/exhausted to business."""
        if authorized is not True:
            raise BudgetError('operation_not_granted')
        def apply(state):
            limits = state['configuration']['limits']
            if max_tool_calls is not None:
                if type(max_tool_calls) is not int or not limits['max_tool_calls'] <= max_tool_calls <= 500:
                    raise BudgetError('contract_invalid')
                limits['max_tool_calls'] = max_tool_calls
            if deadline is not None:
                if type(deadline) not in (int, float) or not math.isfinite(deadline) or not state['deadline'] <= deadline <= state['last_now'] + 3600:
                    raise BudgetError('contract_invalid')
                state['deadline'] = deadline
            state['assisted'] = True
            state['configuration_sha256'] = _digest(state['configuration'])
            self._phase(state)
            return self._public(state)
        return self._run(apply)

    def snapshot(self):
        return self._run(lambda state: self._public(state), allow_poisoned=True)

    def poison(self, scope):
        """A guard may revoke its own accounting, never restore it."""
        def apply(state):
            self._scope(state, scope)
            state['accounting'] = 'unavailable'
            return self._public(state)
        return self._run(apply, allow_poisoned=True)

    def rpc(self, scope, request):
        """Stage-capability router. Authority growth is deliberately not an RPC action."""
        c.exact(request, {'action', 'payload'}, '')
        action, payload = request['action'], request['payload']
        fields = {'reserve': {'batch_id', 'calls', 'stop_reason'},
                  'consume': {'batch_id', 'native_call_id', 'tool_name', 'raw_input'},
                  'entry': {'grant', 'native_call_id', 'tool_name', 'raw_input'},
                  'complete': {'batch_id', 'native_call_id', 'tool_name', 'is_error'},
                  'reconcile': {'batch_id'}, 'checkpoint': set(), 'status': set(), 'poison': set()}
        if action not in fields:
            raise BudgetError('operation_not_granted')
        c.exact(payload, fields[action], '/payload')
        if action == 'reserve':
            return self.reserve_batch(scope, **payload)
        if action == 'consume':
            return self.consume(scope, **payload)
        if action == 'entry':
            return self.observe_execution(scope=scope, **payload)
        if action == 'complete':
            return self.complete(scope, **payload)
        if action == 'reconcile':
            return self.reconcile(scope, **payload)
        if action == 'checkpoint':
            return self.checkpoint(scope)
        if action == 'poison':
            return self.poison(scope)
        return self._run(lambda state: (self._scope(state, scope), self._public(state))[1])
