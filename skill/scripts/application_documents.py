"""Pure validators for application completion declarations and evidence documents.

These validate structure only. Receipt ownership, bytes, cross-document bindings
and stopped-writer checks belong to the independent completion evaluator.
"""
from copy import deepcopy
from datetime import datetime
import json
import re
from urllib.parse import unquote_to_bytes
import unicodedata
import uuid

import application_contracts as c


MAX_DECLARATIONS = 64
MAX_ARTIFACT_BYTES = 256 * 1024
MAX_STAGE_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_REPORT_BYTES = 64 * 1024
MAX_STAGE_EVIDENCE_BYTES = 32 * 1024 * 1024
MEDIA_TYPES = ('text/plain', 'text/markdown', 'application/json')
EVIDENCE_KINDS = ('request', 'response', 'dom_before', 'dom_after',
                  'screenshot_before', 'screenshot_after')


def _size(value, maximum, pointer=''):
    c.safe_json(value)
    try:
        body = json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(',', ':'), allow_nan=False).encode('utf-8')
    except (ValueError, OverflowError, UnicodeError, RecursionError):
        c.fail(pointer, 'Document cannot be represented as bounded JSON')
    if len(body) > maximum:
        c.fail(pointer, 'Document exceeds its byte limit')


def _unique(value, seen, pointer):
    if value in seen:
        c.fail(pointer, 'Duplicate declaration')
    seen.add(value)


def _code(value, pointer):
    c.text(value, pointer, maximum=128)
    if not re.fullmatch(r'[a-z][a-z0-9_-]{0,127}', value):
        c.fail(pointer, 'Expected a bounded reason or redaction code')


def _boolean(value, pointer):
    if type(value) is not bool:
        c.fail(pointer, 'Expected a boolean')


def _path_conflicts(path, paths, pointer):
    path = unicodedata.normalize('NFC', path.casefold())
    for existing in paths:
        if path == existing or path.startswith(existing + '/') or existing.startswith(path + '/'):
            c.fail(pointer, 'Artifact and report paths must have distinct file producers')
    paths.add(path)


def validate_completion(value, participant=None):
    """Validate a stage declaration, without reading any report or artifacts."""
    _size(value, MAX_REPORT_BYTES)
    c.exact(value, {'id', 'participant', 'report_path', 'artifacts', 'pagination', 'publications'}, '')
    c.slug(value['id'], '/id')
    c.participant(value['participant'], '/participant')
    if participant is not None:
        c.participant(participant, '/participant')
        if participant != value['participant']:
            c.fail('/participant', 'Completion participant must exactly match the stage participant')
    c.relative(value['report_path'], '/report_path')
    paths = {unicodedata.normalize('NFC', value['report_path'].casefold())}
    artifact_ids = set()
    total_bytes = 0
    for index, item in enumerate(c.array(value['artifacts'], '/artifacts', maximum=MAX_DECLARATIONS)):
        p = '/artifacts/' + str(index)
        c.exact(item, {'id', 'path', 'media_type', 'max_bytes'}, p)
        c.slug(item['id'], p + '/id')
        _unique(item['id'], artifact_ids, p + '/id')
        c.relative(item['path'], p + '/path')
        _path_conflicts(item['path'], paths, p + '/path')
        c.choice(item['media_type'], MEDIA_TYPES, p + '/media_type')
        c.integer(item['max_bytes'], p + '/max_bytes', minimum=1, maximum=MAX_ARTIFACT_BYTES)
        total_bytes += item['max_bytes']
    if total_bytes > MAX_STAGE_ARTIFACT_BYTES:
        c.fail('/artifacts', 'Declared artifact capacity exceeds the stage limit')
    operation_ids = set()
    for index, item in enumerate(c.array(value['pagination'], '/pagination', maximum=MAX_DECLARATIONS)):
        p = '/pagination/' + str(index)
        c.exact(item, {'operation_id', 'require_exhausted'}, p)
        c.slug(item['operation_id'], p + '/operation_id')
        _unique(item['operation_id'], operation_ids, p + '/operation_id')
        _boolean(item['require_exhausted'], p + '/require_exhausted')
    publication_ids = set()
    publication_operations = set()
    publication_destinations = set()
    for index, item in enumerate(c.array(value['publications'], '/publications', maximum=MAX_DECLARATIONS)):
        p = '/publications/' + str(index)
        c.exact(item, {'id', 'operation_id', 'artifact_id', 'target_id', 'required_state'}, p)
        for field in ('id', 'operation_id', 'artifact_id', 'target_id'):
            c.slug(item[field], p + '/' + field)
        _unique(item['id'], publication_ids, p + '/id')
        _unique(item['operation_id'], publication_operations, p + '/operation_id')
        _unique((item['target_id'], item['artifact_id']), publication_destinations, p + '/target_id')
        if item['operation_id'] in operation_ids:
            c.fail(p + '/operation_id', 'A publication cannot be a paginated read')
        if item['artifact_id'] not in artifact_ids:
            c.fail(p + '/artifact_id', 'Publication must refer to a declared output artifact')
        c.choice(item['required_state'], ('published',), p + '/required_state')
    return deepcopy(value)


def validate_report(value):
    """Validate a report's shape; declaration/evidence matching is separate."""
    _size(value, MAX_REPORT_BYTES)
    c.exact(value, {'schema', 'document_type', 'contract_id', 'participant', 'artifacts',
                    'pagination', 'publications', 'unresolved'}, '')
    c.integer(value['schema'], '/schema', minimum=1, maximum=1)
    c.choice(value['document_type'], ('application_completion_report',), '/document_type')
    c.slug(value['contract_id'], '/contract_id')
    c.participant(value['participant'], '/participant')
    artifact_ids, paths = set(), set()
    total_bytes = 0
    for index, item in enumerate(c.array(value['artifacts'], '/artifacts', maximum=MAX_DECLARATIONS)):
        p = '/artifacts/' + str(index)
        c.exact(item, {'id', 'path', 'sha256', 'bytes'}, p)
        c.slug(item['id'], p + '/id')
        _unique(item['id'], artifact_ids, p + '/id')
        c.relative(item['path'], p + '/path')
        _path_conflicts(item['path'], paths, p + '/path')
        c.sha256(item['sha256'], p + '/sha256')
        c.integer(item['bytes'], p + '/bytes', maximum=MAX_ARTIFACT_BYTES)
        total_bytes += item['bytes']
    if total_bytes > MAX_STAGE_ARTIFACT_BYTES:
        c.fail('/artifacts', 'Artifact bytes exceed the stage limit')
    if type(value['pagination']) is not dict or len(value['pagination']) > MAX_DECLARATIONS:
        c.fail('/pagination', 'Expected a bounded operation-to-receipt map')
    receipt_ids = set()
    for operation_id, receipts in value['pagination'].items():
        c.slug(operation_id, '/pagination')
        p = '/pagination/' + operation_id
        for index, receipt_id in enumerate(c.array(receipts, p, maximum=20)):
            c.slug(receipt_id, p + '/' + str(index))
            _unique(receipt_id, receipt_ids, p + '/' + str(index))
    publication_ids = set()
    for index, item in enumerate(c.array(value['publications'], '/publications', maximum=MAX_DECLARATIONS)):
        p = '/publications/' + str(index)
        c.exact(item, {'id', 'receipt_id'}, p)
        c.slug(item['id'], p + '/id')
        _unique(item['id'], publication_ids, p + '/id')
        c.slug(item['receipt_id'], p + '/receipt_id')
        _unique(item['receipt_id'], receipt_ids, p + '/receipt_id')
    if len(receipt_ids) > 500:
        c.fail('/pagination', 'Report references exceed the receipt limit')
    for index, diagnostic in enumerate(c.array(value['unresolved'], '/unresolved', maximum=20)):
        c.text(diagnostic, '/unresolved/' + str(index), maximum=4096)
    return deepcopy(value)


def _uuid(value, pointer):
    c.text(value, pointer, maximum=36)
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        c.fail(pointer, 'Expected a canonical UUID')
    if str(parsed) != value:
        c.fail(pointer, 'Expected a canonical UUID')


def _binding(value, pointer):
    identities = ('run_id', 'trial_id', 'attempt_id', 'stage_id', 'segment_id', 'session_id')
    digests = ('plan_sha256', 'profile_sha256', 'release_contract_sha256', 'report_contract_sha256')
    c.exact(value, {*identities, *digests, 'pi_release'}, pointer)
    for field in identities:
        if field == 'trial_id' and value[field] is None:
            continue
        _uuid(value[field], pointer + '/' + field)
    for field in digests:
        c.sha256(value[field], pointer + '/' + field)
    c.choice(value['pi_release'], ('0.87.1', '1.2.0'), pointer + '/pi_release')


def _timestamp(value, pointer):
    c.text(value, pointer, maximum=32)
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z', value):
        c.fail(pointer, 'Expected a UTC RFC3339 timestamp')
    try:
        return datetime.fromisoformat(value[:-1] + '+00:00')
    except ValueError:
        c.fail(pointer, 'Expected a valid UTC timestamp')


def _request_path(value, pointer):
    c.text(value, pointer, maximum=4096)
    if (not value.startswith('/') or value.startswith('//') or
            any(ord(char) < 33 or ord(char) > 126 for char in value) or
            any(char in value for char in '\\?#') or re.search(r'%(?![0-9A-F]{2})', value) or
            (value != '/' and any(not part for part in value[1:].split('/')))):
        c.fail(pointer, 'Expected a canonical absolute operation path')
    for part in value.split('/')[1:]:
        try:
            decoded = unquote_to_bytes(part).decode('utf-8')
        except UnicodeError:
            c.fail(pointer, 'Operation path must encode UTF-8')
        if (decoded in ('.', '..') or any(char in decoded for char in '/\\%?#') or
                any(ord(char) < 32 or ord(char) == 127 for char in decoded)):
            c.fail(pointer, 'Unsafe operation path component')
        if any(chr(int(encoded, 16)) in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~'
               for encoded in re.findall(r'%([0-9A-F]{2})', part)):
            c.fail(pointer, 'Unreserved path characters must use their canonical literal form')


def _pagination(value, pointer, receipt_id):
    c.exact(value, {'chain_id', 'snapshot_id', 'page', 'items', 'total_items',
                    'state', 'reason', 'predecessor_receipt_id'}, pointer)
    c.slug(value['chain_id'], pointer + '/chain_id')
    c.text(value['snapshot_id'], pointer + '/snapshot_id', maximum=512)
    c.integer(value['page'], pointer + '/page', minimum=1, maximum=20)
    c.integer(value['items'], pointer + '/items', maximum=1000)
    c.integer(value['total_items'], pointer + '/total_items', maximum=1000)
    if value['total_items'] < value['items']:
        c.fail(pointer + '/total_items', 'Cumulative items cannot be below this page')
    c.choice(value['state'], ('more', 'exhausted', 'truncated'), pointer + '/state')
    if value['state'] == 'truncated':
        _code(value['reason'], pointer + '/reason')
    elif value['reason'] is not None:
        c.fail(pointer + '/reason', 'Only truncated pagination has a reason')
    if value['state'] == 'more' and value['page'] == 20:
        c.fail(pointer + '/state', 'Pagination at the page cap must be exhausted or truncated')
    predecessor = value['predecessor_receipt_id']
    if value['page'] == 1:
        if predecessor is not None or value['total_items'] != value['items']:
            c.fail(pointer, 'The initial page has no predecessor and initializes item totals')
    else:
        c.slug(predecessor, pointer + '/predecessor_receipt_id')
        if predecessor == receipt_id:
            c.fail(pointer + '/predecessor_receipt_id', 'A receipt cannot precede itself')


def validate_receipt(value):
    """Validate one receipt, without asserting its provenance or stored bytes."""
    _size(value, MAX_REPORT_BYTES)
    c.exact(value, {'schema', 'document_type', 'receipt_id', 'operation_instance_id',
                    'native_call_id', 'transport', 'action_id', 'sequence', 'binding', 'participant', 'operation_id',
                    'effect', 'request', 'evidence', 'started_at', 'ended_at', 'outcome',
                    'reason', 'http_status', 'pagination', 'publication'}, '')
    c.integer(value['schema'], '/schema', minimum=1, maximum=1)
    c.choice(value['document_type'], ('application_operation_receipt',), '/document_type')
    for field in ('receipt_id', 'operation_id'):
        c.slug(value[field], '/' + field)
    c.native_id(value['native_call_id'], '/native_call_id')
    c.choice(value['transport'], ('api', 'browser'), '/transport')
    if value['transport'] == 'browser':
        c.slug(value['action_id'], '/action_id')
    elif value['action_id'] is not None:
        c.fail('/action_id', 'API receipts cannot claim a browser action')
    c.integer(value['sequence'], '/sequence', minimum=1, maximum=500)
    _binding(value['binding'], '/binding')
    c.participant(value['participant'], '/participant')
    c.choice(value['effect'], ('identity', 'read', 'mutation', 'publication'), '/effect')
    c.choice(value['outcome'], ('succeeded', 'rejected', 'failed', 'outcome_unknown'), '/outcome')
    if value['operation_instance_id'] is not None:
        c.slug(value['operation_instance_id'], '/operation_instance_id')
    elif value['outcome'] != 'rejected':
        c.fail('/operation_instance_id', 'A transmitted operation requires an instance identity')
    request = value['request']
    c.exact(request, {'method', 'origin_id', 'path', 'credential_alias'}, '/request')
    methods = ('GET',) if value['effect'] in ('identity', 'read') else ('POST', 'PATCH', 'PUT', 'DELETE')
    c.choice(request['method'], methods, '/request/method')
    for field in ('origin_id', 'credential_alias'):
        c.slug(request[field], '/request/' + field)
    _request_path(request['path'], '/request/path')
    evidence_paths, evidence_kinds = set(), set()
    total_bytes = 0
    for index, item in enumerate(c.array(value['evidence'], '/evidence', maximum=64)):
        p = '/evidence/' + str(index)
        c.exact(item, {'kind', 'path', 'sha256', 'bytes', 'redactions'}, p)
        c.choice(item['kind'], EVIDENCE_KINDS, p + '/kind')
        _unique(item['kind'], evidence_kinds, p + '/kind')
        c.relative(item['path'], p + '/path')
        _path_conflicts(item['path'], evidence_paths, p + '/path')
        c.sha256(item['sha256'], p + '/sha256')
        maximum = (2 * 1024 * 1024 if item['kind'].startswith('screenshot_') else
                   256 * 1024 if item['kind'].startswith('dom_') else 1024 * 1024)
        c.integer(item['bytes'], p + '/bytes', maximum=maximum)
        total_bytes += item['bytes']
        redactions = set()
        for redaction_index, code in enumerate(c.array(item['redactions'], p + '/redactions', maximum=64)):
            code_pointer = p + '/redactions/' + str(redaction_index)
            _code(code, code_pointer)
            _unique(code, redactions, code_pointer)
    if total_bytes > MAX_STAGE_EVIDENCE_BYTES:
        c.fail('/evidence', 'Evidence bytes exceed the stage limit')
    started = _timestamp(value['started_at'], '/started_at')
    ended = _timestamp(value['ended_at'], '/ended_at')
    if ended < started:
        c.fail('/ended_at', 'Receipt cannot end before it starts')
    status = value['http_status']
    if status is not None:
        c.integer(status, '/http_status', minimum=100, maximum=599)
    if value['outcome'] == 'succeeded':
        if value['reason'] is not None or status is None or not 200 <= status <= 299:
            c.fail('/outcome', 'Success requires an observed HTTP success and no failure reason')
        if not {'request', 'response'} <= evidence_kinds:
            c.fail('/evidence', 'Success requires raw request and response evidence')
    else:
        _code(value['reason'], '/reason')
        if value['outcome'] == 'rejected' and status is not None:
            c.fail('/http_status', 'Rejected requests cannot have an HTTP response')
        if value['outcome'] == 'failed':
            if status is not None and 200 <= status <= 299 and value['effect'] in ('mutation', 'publication'):
                c.fail('/http_status', 'A write with an invalid HTTP success response has an unknown outcome')
            if status is None and value['effect'] in ('mutation', 'publication'):
                c.fail('/outcome', 'An unobserved write outcome is unknown')
        if value['outcome'] == 'outcome_unknown' and value['effect'] not in ('mutation', 'publication'):
            c.fail('/outcome', 'Unknown outcomes are reserved for writes')
    if value['pagination'] is not None:
        if value['effect'] != 'read' or value['outcome'] != 'succeeded':
            c.fail('/pagination', 'Only successful reads can attest to pagination')
        _pagination(value['pagination'], '/pagination', value['receipt_id'])
    publication = value['publication']
    if publication is not None:
        if value['effect'] != 'publication' or value['outcome'] != 'succeeded':
            c.fail('/publication', 'Only successful publications can attest to publication')
        c.exact(publication, {'id', 'publication_id', 'artifact_id', 'artifact_sha256',
                              'target_id', 'state'}, '/publication')
        for field in ('id', 'artifact_id', 'target_id'):
            c.slug(publication[field], '/publication/' + field)
        c.text(publication['publication_id'], '/publication/publication_id', maximum=512)
        c.sha256(publication['artifact_sha256'], '/publication/artifact_sha256')
        c.choice(publication['state'], ('published',), '/publication/state')
    elif value['effect'] == 'publication' and value['outcome'] == 'succeeded':
        c.fail('/publication', 'HTTP success alone cannot attest to publication')
    return deepcopy(value)
