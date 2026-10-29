"""Pure, bounded validation of create-only registration observation models.

No filesystem, transport, provider, or registration capability is implemented.
The caller supplies expectations independently of the observation. Accepting a
model cannot prove that its claimed native observations occurred. In particular,
neither assessment grants operational authority or application admission.
"""
from dataclasses import dataclass
import re
import uuid


class TraceError(ValueError):
    """A fixed reason, never an input value, path, or exception representation."""


def _require(condition, reason):
    if not condition:
        raise TraceError(reason)


def _fields(value, names):
    _require(type(value) is dict and len(value) == len(names) and set(value) == names, 'fields')


def _integer(value, minimum, maximum):
    _require(type(value) is int and minimum <= value <= maximum, 'integer')


def _choice(value, choices):
    _require(type(value) is str and value in choices, 'choice')


def _uuid(value):
    _require(type(value) is str and len(value) == 36
             and re.fullmatch('[0-9a-f-]{36}', value) is not None, 'operation_id')
    try:
        _require(str(uuid.UUID(value)) == value, 'operation_id')
    except ValueError:
        raise TraceError('operation_id') from None


def _sha(value):
    _require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None, 'context')


def _token(value):
    _require(type(value) is str and 1 <= len(value) <= 64
             and re.fullmatch(r'value|store_duplicate|ancestor:[0-9]+', value) is not None, 'fd_token')


_CONTRACTS = {'normalized_secret_1': 1, 'application_credential_1': 16}
_WORKER = set(('schema document_type operation_id context_binding_sha256 value_contract outcome reason '
               'phase calls trace_complete effects file_persistence directory_persistence final_verified '
               'owned_fd_closure ack_ready admission_authorized').split())
_RECEIVER = set(('schema document_type operation_id context_binding_sha256 dispatch_started worker_result '
                 'frame_complete request_and_origin_verified current_namespace_verified ack_state accepted '
                 'admission_authorized').split())
_CALL = set('ordinal kind state fd_token attempted_bytes confirmed_bytes'.split())
_BUSINESS = ('temp_create', 'write', 'file_fsync', 'link', 'temp_unlink', 'directory_fsync')
_REASONS = set(('ok invalid_input missing_permission unsupported_filesystem target_exists temp_exists '
                'identity_mismatch permission_error io_error interrupted observation_incomplete '
                'owned_fd_close_unconfirmed').split())
_PHASES = set(_BUSINESS) | {'admission', 'preflight', 'final_verify', 'fd_close', 'ack_ready'}
_EVIDENCE = set(('dispatch_started frame_complete request_and_origin_verified '
                 'current_namespace_verified').split())
_EXPECTED = set(('expected_operation_id expected_context_sha256 expected_value_contract '
                 'expected_value_utf8_bytes owned_fd_tokens max_mutating_calls max_owned_fds').split())


@dataclass(frozen=True)
class WorkerAssessment:
    outcome: str
    ack_ready: bool
    operational_authorized: bool = False


@dataclass(frozen=True)
class ReceiverAssessment:
    accepted: bool
    ack_state: str
    operational_authorized: bool = False


def validate_value(value, value_contract):
    """Check the exact string without normalization; return only its byte count."""
    _choice(value_contract, _CONTRACTS)
    _require(type(value) is str and _CONTRACTS[value_contract] <= len(value) <= 4096, 'value_shape')
    _require(not any(c.isspace() or ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF
                     for c in value), 'value_shape')
    count = len(value.encode('utf-8'))
    _require(count <= 16384, 'value_shape')
    return count


def _expected(operation, context, value_contract, value_bytes, tokens, max_calls, max_fds):
    _uuid(operation); _sha(context); _choice(value_contract, _CONTRACTS)
    _integer(value_bytes, _CONTRACTS[value_contract], 16384)
    _integer(max_calls, 1, 4096); _integer(max_fds, 0, 128)
    _require(type(tokens) in (tuple, list) and len(tokens) <= max_fds, 'fd_budget')
    for token in tokens:
        _token(token)
    _require(len(set(tokens)) == len(tokens), 'fd_duplicate')
    return set(tokens)


def validate_worker(document, *, expected_operation_id, expected_context_sha256,
                    expected_value_contract, expected_value_utf8_bytes, owned_fd_tokens,
                    max_mutating_calls, max_owned_fds):
    """Compare a literal worker trace to independently supplied bounded facts.

    owned_fd_tokens describes actually known acquisitions, including ancestors
    and the store duplicate; it never includes the borrowed caller descriptor.
    The byte count must come from separately validated exact private input.
    This function observes none of those facts itself and invokes no callbacks.
    """
    owned = _expected(expected_operation_id, expected_context_sha256, expected_value_contract,
                      expected_value_utf8_bytes, owned_fd_tokens, max_mutating_calls, max_owned_fds)
    _fields(document, _WORKER)
    _require(type(document['schema']) is int and document['schema'] == 1
             and document['document_type'] == 'secret_registration_worker_observation', 'schema')
    _uuid(document['operation_id']); _sha(document['context_binding_sha256'])
    _choice(document['value_contract'], _CONTRACTS)
    _require(document['operation_id'] == expected_operation_id
             and document['context_binding_sha256'] == expected_context_sha256
             and document['value_contract'] == expected_value_contract, 'binding')
    _choice(document['outcome'], {'created', 'refused', 'blocked', 'uncertain'})
    _choice(document['reason'], _REASONS); _choice(document['phase'], _PHASES)
    _choice(document['effects'], {'none', 'temp_only', 'leaf_with_temp', 'leaf_only', 'unknown'})
    for name in ('file_persistence', 'directory_persistence', 'owned_fd_closure'):
        _choice(document[name], {'not_started', 'confirmed', 'unknown'})
    for name in ('trace_complete', 'final_verified', 'ack_ready', 'admission_authorized'):
        _require(type(document[name]) is bool, 'boolean')
    _require(document['admission_authorized'] is False, 'admission')
    calls = document['calls']
    _require(type(calls) is list and len(calls) <= max_mutating_calls, 'call_budget')
    stage = total = 0
    effects, file_sync, directory_sync = 'none', 'not_started', 'not_started'
    stopped = uncertain = closing = False
    closed, unknown_closes = set(), set()
    temp_entered = False
    for ordinal, row in enumerate(calls, 1):
        _fields(row, _CALL)
        _integer(row['ordinal'], 1, max_mutating_calls)
        _require(row['ordinal'] == ordinal, 'ordinal')
        kind, state, token = row['kind'], row['state'], row['fd_token']
        _choice(kind, set(_BUSINESS) | {'fd_close'})
        _choice(state, {'attempted', 'confirmed', 'no_effect', 'unknown'})
        if kind != 'write':
            _require(row['attempted_bytes'] is None and row['confirmed_bytes'] is None, 'call_bytes')
        if token is not None:
            _token(token)
            _require(token in owned, 'borrowed_fd')
        if kind == 'fd_close':
            _require(token is not None and token not in closed and state != 'no_effect', 'close_once')
            closed.add(token)  # Spend before interpreting a possibly ambiguous native return.
            closing = True
            if state != 'confirmed':
                uncertain = True
                unknown_closes.add(token)
            continue
        _require(not stopped and not closing and stage < len(_BUSINESS)
                 and kind == _BUSINESS[stage], 'business_order')
        if kind == 'temp_create':
            _require('store_duplicate' in owned, 'store_fd_missing')
            temp_entered = state != 'no_effect'
        if kind == 'write':
            _require(token == 'value', 'write_fd')
            _integer(row['attempted_bytes'], 1, 16384)
            _integer(row['confirmed_bytes'], 0, 16384)
            _require(row['attempted_bytes'] == expected_value_utf8_bytes - total
                     and row['confirmed_bytes'] <= row['attempted_bytes'], 'write_count')
            if state == 'confirmed':
                _require(row['confirmed_bytes'] > 0, 'zero_write')
                total += row['confirmed_bytes']
            else:
                _require(row['confirmed_bytes'] == 0, 'unknown_write_count')
        if state != 'confirmed':
            _require(state != 'no_effect' or kind in ('temp_create', 'write', 'link'), 'no_effect')
            stopped = True
            uncertain |= state in ('attempted', 'unknown')
            if state in ('attempted', 'unknown'):
                if kind in ('temp_create', 'link', 'temp_unlink'):
                    effects = 'unknown'
                elif kind == 'file_fsync':
                    file_sync = 'unknown'
                elif kind == 'directory_fsync':
                    directory_sync = 'unknown'
            continue
        if kind == 'temp_create':
            _require('value' in owned, 'value_fd_missing')
            effects = 'temp_only'
        elif kind == 'file_fsync':
            file_sync = 'confirmed'
        elif kind == 'link':
            effects = 'leaf_with_temp'
        elif kind == 'temp_unlink':
            effects = 'leaf_only'
        elif kind == 'directory_fsync':
            directory_sync = 'confirmed'
        if kind != 'write' or total == expected_value_utf8_bytes:
            stage += 1
    _require('value' not in owned or temp_entered, 'value_fd_before_create')
    if 'value' in unknown_closes:
        file_sync = 'unknown'
    if 'store_duplicate' in unknown_closes:
        directory_sync = 'unknown'
    closure = ('confirmed' if closed == owned and not unknown_closes
               else 'not_started' if not closed else 'unknown')
    if not document['trace_complete']:
        effects = file_sync = directory_sync = closure = 'unknown'
        uncertain = True
    _require(document['effects'] == effects and document['file_persistence'] == file_sync
             and document['directory_persistence'] == directory_sync
             and document['owned_fd_closure'] == closure, 'derived_state')
    complete_business = stage == len(_BUSINESS) and not stopped
    _require(not document['final_verified'] or complete_business and document['trace_complete'], 'final_verify')
    ready = (complete_business and document['trace_complete'] and document['final_verified']
             and closure == 'confirmed' and file_sync == directory_sync == 'confirmed')
    _require(document['ack_ready'] == ready, 'readiness')
    if ready:
        _require(document['outcome'] == 'created' and document['reason'] == 'ok'
                 and document['phase'] == 'ack_ready', 'created_state')
    else:
        _require(document['reason'] != 'ok' and document['phase'] != 'ack_ready', 'failure_state')
        if uncertain or closure == 'unknown':
            _require(document['outcome'] == 'uncertain', 'uncertain_state')
        else:
            _require(document['outcome'] in ('refused', 'blocked'), 'failure_state')
            _require(document['outcome'] != 'refused' or effects == 'none', 'refusal_effects')
    return WorkerAssessment(document['outcome'], ready)


def validate_receiver(document, *, worker_expectations, evidence):
    """Validate receiver model facts separately from worker readiness/emission."""
    _fields(worker_expectations, _EXPECTED); _fields(evidence, _EVIDENCE)
    _expected(worker_expectations['expected_operation_id'], worker_expectations['expected_context_sha256'],
              worker_expectations['expected_value_contract'], worker_expectations['expected_value_utf8_bytes'],
              worker_expectations['owned_fd_tokens'], worker_expectations['max_mutating_calls'],
              worker_expectations['max_owned_fds'])
    _fields(document, _RECEIVER)
    _require(type(document['schema']) is int and document['schema'] == 1
             and document['document_type'] == 'secret_registration_receiver_observation', 'schema')
    _uuid(document['operation_id']); _sha(document['context_binding_sha256'])
    _require(document['operation_id'] == worker_expectations['expected_operation_id']
             and document['context_binding_sha256'] == worker_expectations['expected_context_sha256'], 'binding')
    for name in _EVIDENCE:
        _require(type(evidence[name]) is bool and type(document[name]) is bool
                 and document[name] == evidence[name], 'receiver_evidence')
    _require(evidence['dispatch_started'] or not any(evidence.values()), 'dispatch_state')
    _require(evidence['frame_complete'] or not (evidence['request_and_origin_verified']
                                              or evidence['current_namespace_verified']), 'frame_state')
    _require(type(document['accepted']) is bool and document['admission_authorized'] is False, 'boolean')
    _choice(document['ack_state'], {'not_received', 'received_unverified', 'verified', 'rejected'})
    worker = document['worker_result']
    _require(worker is None or evidence['dispatch_started'] and evidence['frame_complete'], 'worker_frame')
    assessment = None if worker is None else validate_worker(worker, **worker_expectations)
    if document['ack_state'] == 'not_received':
        _require(worker is None and not evidence['frame_complete'] and not document['accepted'], 'lost_reply')
    elif document['ack_state'] == 'verified':
        _require(all(evidence.values()) and assessment is not None and assessment.ack_ready
                 and document['accepted'], 'receiver_acceptance')
    else:
        _require(not document['accepted'], 'receiver_acceptance')
    _require(not document['accepted'] or document['ack_state'] == 'verified', 'receiver_acceptance')
    return ReceiverAssessment(document['accepted'], document['ack_state'])
