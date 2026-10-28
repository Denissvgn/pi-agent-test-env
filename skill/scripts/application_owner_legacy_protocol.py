"""Closed installed request and passive receipt dispatch for retained legacy proof.

This module validates data and current registry observations. It never publishes
proof, purges a root, probes a process or calls a native service.
"""
from pathlib import Path
import re

import application_owner_cleanup as cleanup
import application_owner_legacy as legacy

COMMON_FIELDS = frozenset({'invocation_id', 'method', 'cohort', 'variant', 'started_at',
    'subject', 'lease', 'request', 'metadata', 'roots', 'related_subjects', 'runner_content_sha256',
    'admission_authorized', 'original_outcome_regraded', 'new_containers', 'participant_stages', 'model_requests'})
INTENT_FIELDS = COMMON_FIELDS | {'schema', 'document_type', 'status'}
RECEIPT_FIELDS = INTENT_FIELDS | {'finished_at', 'cleanup_completed', 'scope', 'global_actor_census',
    'credential_memory_erasure', 'effects', 'evidence_sha256', 'intent'}


def request_shape(request):
    """Validate the complete new request before consulting the registry."""
    cleanup.exact(request, legacy.REQUEST_FIELDS)
    legacy._request(request, request['subject'])


def _plan(registry, request, reader, *, current=None):
    request_shape(request)
    current = registry.load() if current is None else current
    matches = [row for row in current if row['launch_id'] == request['subject']['launch_id']]
    cleanup.require(len(matches) == 1)
    record = matches[0]
    cleanup.require(record['registry'] == registry.registry_id)
    related = sorted((row for row in current if row.get('runroot') == record['runroot']),
                     key=lambda row: row['launch_id'])
    plan = legacy.prepare(request, record, related, reader=reader)
    return record, related, plan


def prepare(registry, request, *, reader=None):
    reader = cleanup.Reader() if reader is None else reader
    record, related, plan = _plan(registry, request, reader)
    return record, related, reader, plan['metadata'], plan['roots'], plan['physical']


def _document(value, fields, name, schema, subject):
    cleanup.exact(value, fields)
    cleanup.require(type(value['schema']) is int and value['schema'] == schema
        and value['document_type'] == 'application_owner_cleanup_' + name
        and cleanup.canonical(value['subject']) == cleanup.canonical(subject)
        and value['method'] == legacy.METHOD and value['cohort'] == legacy.COHORT,
        'owner_legacy_unsupported')


def _metadata(value):
    cleanup.require(type(value) is list and len(value) <= cleanup.MAX_REFERENCES)
    for item in value:legacy.reference(item)
    paths = [item['path'] for item in value]
    cleanup.require(paths == sorted(set(paths)))


def _roots(value):
    cleanup.require(type(value) is list and 1 <= len(value) <= cleanup.MAX_ENTRIES)
    for item in value:
        cleanup.exact(item, {'path', 'state', 'identity'}); cleanup.path(item['path'])
        cleanup.require(item['state'] in ('present', 'absent'))
        if item['state'] == 'present':legacy._identity(item['identity'])
        else:cleanup.require(item['identity'] is None)
    paths = [item['path'] for item in value]
    cleanup.require(paths == sorted(set(paths)))


def _outside_output(registry, record, receipt_ref, intent_ref, plan):
    receipt = cleanup.path(receipt_ref['path']); intent = cleanup.path(intent_ref['path'])
    cleanup.require(receipt.name == 'terminal.json' and intent == receipt.parent / 'intent.json')
    excluded = [Path(record['runroot']), registry.root, cleanup.store_path(registry),
                registry.root.with_name(registry.root.name + '.owner-selected')]
    excluded += [Path(item['path']) for item in plan['roots'] + plan['metadata']]
    output = receipt.parent
    cleanup.require(not any(output == target or output in target.parents or target in output.parents
                            for target in excluded), 'unsafe_path')


@cleanup.diagnostics.scoped('owner_legacy_replay', 'cleanup_proof_invalid')
def validate_accepted(registry, record, index, anchor, reader):
    """Require the whole selected graph; replay uses no native observations."""
    subject = cleanup.subject(record)
    _document(index, {'schema', 'document_type', 'subject', 'method', 'cohort', 'receipt'}, 'index', 2, subject)
    selection, unused = reader.read(cleanup._selection(registry, record), private=True)
    _document(selection, {'schema', 'document_type', 'subject', 'method', 'cohort'}, 'selection', 2, subject)
    _document(anchor, {'schema', 'document_type', 'subject', 'method', 'cohort', 'intent'}, 'anchor', 1, subject)
    legacy.reference(index['receipt'])
    receipt = reader.reference(index['receipt'], private=True)
    _document(receipt, RECEIPT_FIELDS, 'receipt', 2, subject)
    cleanup.require(receipt['status'] == 'CLEANED' and receipt['cleanup_completed'] is True
        and receipt['admission_authorized'] is False and receipt['original_outcome_regraded'] is False
        and receipt['scope'] == 'owned_host_files_only' and receipt['effects'] == 'may_have_occurred'
        and receipt['global_actor_census'] == 'not_attested' and receipt['credential_memory_erasure'] == 'not_attested')
    cleanup.require(cleanup.controls.valid_id(receipt['invocation_id']))
    for field in ('started_at', 'finished_at'):legacy.timestamp(receipt[field])
    for field in ('new_containers', 'participant_stages', 'model_requests'):
        cleanup.require(type(receipt[field]) is int and receipt[field] == 0)
    cleanup.require(type(receipt['runner_content_sha256']) is str
                    and re.fullmatch('[a-f0-9]{64}', receipt['runner_content_sha256']) is not None)
    cleanup.require(cleanup.canonical(receipt['lease']) == cleanup.canonical(cleanup.lease_identity(registry)))
    legacy.reference(receipt['intent'])
    cleanup.require(receipt['intent'] == anchor['intent'])
    intent = reader.reference(receipt['intent'], private=True)
    _document(intent, INTENT_FIELDS, 'intent', 1, subject)
    cleanup.require(intent['status'] == 'RUNNING')
    cleanup.require(all(cleanup.canonical(intent[field]) == cleanup.canonical(receipt[field]) for field in COMMON_FIELDS))
    request_shape(receipt['request'])
    cleanup.require(receipt['variant'] == receipt['request']['variant']
                    and receipt['evidence_sha256'] == receipt['request']['evidence']['sha256'])
    _metadata(receipt['metadata']); _roots(receipt['roots'])
    original, related, plan = _plan(registry, receipt['request'], reader)
    cleanup.require(cleanup.canonical(original) == cleanup.canonical(record))
    cleanup.require(receipt['metadata'] == plan['metadata'] and all(row['state'] == 'absent' for row in plan['roots']))
    cleanup.require([row['path'] for row in receipt['roots']] == [row['path'] for row in plan['roots']])
    cleanup.require(cleanup._canonical_subjects(receipt['related_subjects']) == [cleanup._resource_subject(row) for row in related])
    custody = next(claim['value'] for claim in plan['claims'] if claim['obligation'] == 'original_root_custody')
    for row in receipt['roots']:
        if row['path'] == custody['path'] and plan['root_plan']['original_removed']:
            cleanup.require(row['state'] == 'absent', 'sensitive_identity_mismatch')
        if row['path'] == custody['path'] and row['state'] == 'present':
            cleanup.require(row['identity'] == custody['identity'], 'sensitive_identity_mismatch')
    _outside_output(registry, record, index['receipt'], receipt['intent'], plan)
    return True
