"""Independent, read-only evaluation of stopped application completion outputs.

The caller supplies the parent-owned receipt index and exact expected binding.
Receipt index values are {path, sha256}; participant-authored receipt dictionaries
are never authority. Roots must use absolute paths without symlink ancestors.
This evaluator never seals, repairs, publishes or resumes participant work.
"""
import errno
import hashlib
import os
from pathlib import PurePosixPath
import stat
import uuid

import application_contracts as c
import application_documents as documents


class ReadError(ValueError):
    def __init__(self, kind):
        self.kind = kind


def _directory(path, private=False):
    raw = os.fspath(path)
    if not isinstance(raw, str) or not raw.startswith('/') or str(PurePosixPath(raw)) != raw:
        raise ReadError('unsafe')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in PurePosixPath(raw).parts[1:]:
            if part in ('.', '..'):
                raise ReadError('unsafe')
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or (private and stat.S_IMODE(info.st_mode) & 0o077):
            raise ReadError('unsafe')
        return fd
    except OSError as exc:
        os.close(fd)
        raise ReadError('missing' if exc.errno == errno.ENOENT else 'unsafe') from None
    except BaseException:
        os.close(fd)
        raise


def _read(root, path, maximum, private=False):
    c.relative(path, '')
    parent = os.dup(root)
    fd = None
    try:
        components = path.split('/')
        for part in components[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            if info.st_uid != os.getuid() or (private and stat.S_IMODE(info.st_mode) & 0o022):
                raise ReadError('unsafe')
        fd = os.open(components[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.getuid()
                or (private and stat.S_IMODE(before.st_mode) & 0o022)):
            raise ReadError('unsafe')
        if before.st_size > maximum:
            raise ReadError('oversize')
        chunks, remaining = [], maximum + 1
        while remaining:
            data = os.read(fd, min(65536, remaining))
            if not data:
                break
            chunks.append(data)
            remaining -= len(data)
        body = b''.join(chunks)
        after = os.fstat(fd)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink', 'st_mode')
        if any(getattr(before, field) != getattr(after, field) for field in fields):
            raise ReadError('unsafe')
        if len(body) > maximum:
            raise ReadError('oversize')
        return body
    except OSError as exc:
        raise ReadError('missing' if exc.errno == errno.ENOENT else 'unsafe') from None
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


class _Verdict:
    def __init__(self, contract_id):
        self.result = {'schema': 1, 'document_type': 'application_completion_result',
                       'contract_id': contract_id, 'status': 'complete',
                       'diagnostics': [], 'diagnostics_truncated': False}
        self.rank = 0

    def add(self, code, pointer, expected, observed, receipts=(), status='invalid'):
        rank = {'complete': 0, 'incomplete': 1, 'invalid': 2, 'not_evaluated': 3}[status]
        if rank > self.rank:
            self.rank = rank
            self.result['status'] = status
        if len(self.result['diagnostics']) == 100:
            self.result['diagnostics_truncated'] = True
            return
        self.result['diagnostics'].append({'code': code, 'pointer': pointer, 'expected': expected,
                                           'observed': observed, 'receipt_ids': list(receipts)[:20]})


def _index(receipts):
    if type(receipts) is not dict or len(receipts) > 500:
        c.fail('/receipts', 'Parent receipt index must be a bounded map')
    paths = set()
    for receipt_id, reference in receipts.items():
        p = '/receipts/' + c.escape(receipt_id)
        c.slug(receipt_id, p)
        c.exact(reference, {'path', 'sha256'}, p)
        c.relative(reference['path'], p + '/path')
        c.sha256(reference['sha256'], p + '/sha256')
        if reference['path'] in paths:
            c.fail(p + '/path', 'Duplicate parent receipt path')
        paths.add(reference['path'])


def evaluate(contract, *, report_root, evidence_root, receipts, binding, writers_confirmed,
             authorized_segment_ids=None):
    """Return a bounded completion verdict, without changing any input bytes.

    `report_root` must be a stopped/sealed output snapshot. `evidence_root` is a
    separate private parent-owned directory. `receipts` is the parent's protected
    ID-to-file/digest index, not model input. Admission contract errors raise
    ContractError; missing or hostile output data produce verdict diagnostics.
    """
    contract = c.validate_completion(contract)
    verdict = _Verdict(contract['id'])
    if writers_confirmed is not True:
        verdict.add('writers_unconfirmed', '', 'confirmed stopped writers', 'unconfirmed', status='not_evaluated')
        return verdict.result
    documents._binding(binding, '/binding')
    if binding['report_contract_sha256'] != c.digest(contract):
        c.fail('/binding/report_contract_sha256', 'Expected binding must identify the declared completion contract')
    segments=[binding['segment_id']] if authorized_segment_ids is None else authorized_segment_ids
    c.array(segments,'/authorized_segment_ids',64,1)
    for index,segment in enumerate(segments):
        try:
            if type(segment) is not str or str(uuid.UUID(segment))!=segment:raise ValueError()
        except (ValueError,AttributeError,TypeError):
            c.fail('/authorized_segment_ids/'+str(index),'Exact parent-authorized segment UUID required')
    if len(set(segments))!=len(segments) or segments[-1]!=binding['segment_id']:
        c.fail('/authorized_segment_ids','Unique ordered segments ending in the current bound segment required')
    bindings=[{**binding,'segment_id':segment} for segment in segments]
    try:
        _index(receipts)
    except c.ContractError:
        verdict.add('receipt_integrity_failed', '/receipts', 'parent-owned receipt index', 'malformed index')
        receipts = {}
    report_fd = evidence_fd = None
    try:
        try:
            report_fd = _directory(report_root)
        except ReadError:
            verdict.add('artifact_path_unsafe', '', 'safe stopped output root', 'unavailable root')
        try:
            evidence_fd = _directory(evidence_root, private=True)
            report_path = PurePosixPath(os.fspath(report_root))
            evidence_path = PurePosixPath(os.fspath(evidence_root))
            if report_path == evidence_path or report_path in evidence_path.parents or evidence_path in report_path.parents:
                raise ReadError('unsafe')
            if report_fd is not None:
                a, b = os.fstat(report_fd), os.fstat(evidence_fd)
                if (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino):
                    raise ReadError('unsafe')
        except ReadError:
            if evidence_fd is not None:
                os.close(evidence_fd)
                evidence_fd = None
            verdict.add('evidence_unavailable', '/receipts', 'separate private parent evidence',
                        'unavailable evidence root', status='not_evaluated')
        _evaluate(contract, report_fd, evidence_fd, receipts, bindings, verdict)
        return verdict.result
    finally:
        if report_fd is not None:
            os.close(report_fd)
        if evidence_fd is not None:
            os.close(evidence_fd)


def _evaluate(contract, report_fd, evidence_fd, index, binding, verdict):
    report = None
    if report_fd is not None:
        try:
            report = c.validate_report(c.loads(_read(report_fd, contract['report_path'], 65536), max_bytes=65536))
        except ReadError as exc:
            verdict.add('report_missing' if exc.kind == 'missing' else 'report_malformed', '/report',
                        'declared bounded report', exc.kind, status='incomplete' if exc.kind == 'missing' else 'invalid')
        except c.ContractError:
            verdict.add('report_malformed', '/report', 'strict declared report', 'malformed report')
    else:
        verdict.add('report_missing', '/report', 'declared report', 'unavailable report', status='incomplete')
    if report is not None:
        if report['contract_id'] != contract['id']:
            verdict.add('report_malformed', '/report/contract_id', 'declared contract', 'different contract')
        if report['participant'] != contract['participant']:
            verdict.add('participant_mismatch', '/report/participant', contract['participant'],
                        {'mismatched_fields': [key for key in contract['participant'] if report['participant'][key] != contract['participant'][key]]})
        if report['unresolved']:
            verdict.add('report_unresolved', '/report/unresolved', 'no unresolved requirements',
                        len(report['unresolved']), status='incomplete')
        for field, key in (('artifacts', 'id'), ('publications', 'id')):
            declared = {item[key] for item in contract[field]}
            if {item[key] for item in report[field]} - declared:
                verdict.add('report_malformed', '/report/' + field, 'only declared IDs', 'undeclared IDs')
        if set(report['pagination']) - {p['operation_id'] for p in contract['pagination']}:
            verdict.add('report_malformed', '/report/pagination', 'only declared operations', 'undeclared operations')
    report_artifacts = {a['id']: a for a in report['artifacts']} if report else {}
    artifacts = {}
    for number, artifact in enumerate(contract['artifacts']):
        p = '/artifacts/' + str(number)
        try:
            if report_fd is None:
                raise ReadError('missing')
            data = _read(report_fd, artifact['path'], artifact['max_bytes'])
            data.decode('utf-8')
            if artifact['media_type'] == 'application/json':
                c.loads(data, max_bytes=artifact['max_bytes'])
            artifacts[artifact['id']] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
        except ReadError as exc:
            code = 'artifact_missing' if exc.kind == 'missing' else 'artifact_path_unsafe' if exc.kind == 'unsafe' else 'report_malformed'
            verdict.add(code, p, 'safe artifact within declared byte limit', exc.kind,
                        status='incomplete' if exc.kind == 'missing' else 'invalid')
        except (UnicodeError, c.ContractError):
            verdict.add('report_malformed', p, 'declared UTF-8 artifact media', 'invalid artifact media')
        observed = report_artifacts.get(artifact['id'])
        if observed is None:
            if report is not None:
                verdict.add('artifact_missing', p, 'artifact manifest entry', 'missing entry', status='incomplete')
        else:
            if observed['path'] != artifact['path']:
                verdict.add('artifact_path_unsafe', p + '/path', 'declared artifact path', 'different path')
            actual = artifacts.get(artifact['id'])
            if actual is not None and (observed['sha256'] != actual['sha256'] or observed['bytes'] != actual['bytes']):
                verdict.add('artifact_hash_mismatch', p, 'sealed artifact digest and byte count', 'different artifact bytes')
    trusted = _receipts(contract, evidence_fd, index, binding, verdict)
    _identity(trusted, verdict)
    _pages(contract, report, trusted, verdict)
    _publications(contract, report, trusted, artifacts, verdict)


def _receipts(contract, root, index, binding, verdict):
    trusted, instances, calls, sequences = {}, set(), {}, set()
    actions = {}
    writes, evidence_paths = set(), set()
    receipt_paths = {item['path'] for item in index.values()}
    total_bytes = 0
    for receipt_id in sorted(index):
        reference = index[receipt_id]
        p = '/receipts/' + receipt_id
        if root is None:
            continue
        try:
            data = _read(root, reference['path'], min(65536, max(0, 33554432 - total_bytes)), private=True)
            total_bytes += len(data)
            if total_bytes > 33554432:
                raise ReadError('oversize')
            if hashlib.sha256(data).hexdigest() != reference['sha256']:
                raise ReadError('digest')
            receipt = c.validate_receipt(c.loads(data, max_bytes=65536))
            if receipt['receipt_id'] != receipt_id or receipt['binding'] not in binding:
                raise ReadError('binding')
            if receipt['participant'] != contract['participant']:
                verdict.add('participant_mismatch', p + '/participant', contract['participant'],
                            {'mismatched_fields': [key for key in contract['participant'] if receipt['participant'][key] != contract['participant'][key]]}, [receipt_id])
                continue
            instance = receipt['operation_instance_id']
            call_id, operation_id = (receipt['binding']['segment_id'], receipt['native_call_id']), receipt['operation_id']
            prior_call = calls.get(call_id)
            repeated_call_invalid = prior_call is not None and (
                receipt['transport'] != 'browser' or prior_call['transport'] != 'browser' or
                receipt['action_id'] != prior_call['action_id'] or instance is None or
                None in prior_call['instances'] or operation_id in prior_call['operations'] or
                len(prior_call['operations']) >= 16)
            repeated_action_invalid = receipt['transport'] == 'browser' and (
                receipt['action_id'] in actions and actions[receipt['action_id']] != call_id)
            if (instance is not None and instance in instances) or repeated_call_invalid or repeated_action_invalid or receipt['sequence'] in sequences:
                verdict.add('receipt_duplicate', p, 'unique operation/call/action/sequence', 'duplicate receipt identity', [receipt_id])
                continue
            if instance is not None:
                instances.add(instance)
            if prior_call is None:
                prior_call = {'transport': receipt['transport'], 'action_id': receipt['action_id'],
                              'instances': set(), 'operations': set()}
                calls[call_id] = prior_call
            prior_call['instances'].add(instance)
            prior_call['operations'].add(operation_id)
            if receipt['transport'] == 'browser':
                actions[receipt['action_id']] = call_id
            sequences.add(receipt['sequence'])
            if receipt['effect'] in ('mutation', 'publication') and receipt['outcome'] != 'rejected':
                if receipt['operation_id'] in writes:
                    verdict.add('receipt_duplicate', p, 'one transmitted write per operation grant', 'repeated write grant', [receipt_id])
                    continue
                writes.add(receipt['operation_id'])
            for evidence in receipt['evidence']:
                if evidence['path'] in evidence_paths or evidence['path'] in receipt_paths:
                    raise ReadError('duplicate_evidence')
                evidence_paths.add(evidence['path'])
                if evidence['bytes'] > 33554432 - total_bytes:
                    raise ReadError('oversize')
                raw = _read(root, evidence['path'], evidence['bytes'], private=True)
                total_bytes += len(raw)
                if (total_bytes > 33554432 or len(raw) != evidence['bytes'] or
                        hashlib.sha256(raw).hexdigest() != evidence['sha256']):
                    raise ReadError('digest')
            trusted[receipt_id] = receipt
        except ReadError as exc:
            code = 'receipt_missing' if exc.kind == 'missing' else 'receipt_integrity_failed'
            verdict.add(code, p, 'intact parent-owned bound receipt and evidence', exc.kind, [receipt_id],
                        status='incomplete' if exc.kind == 'missing' else 'invalid')
        except c.ContractError:
            verdict.add('receipt_integrity_failed', p, 'strict bound receipt', 'malformed receipt', [receipt_id])
    return trusted


def _identity(trusted, verdict):
    identities = {}
    for receipt in trusted.values():
        if receipt['effect'] == 'identity' and receipt['reason'] == 'participant_mismatch':
            verdict.add('participant_mismatch', '/receipts/' + receipt['receipt_id'] + '/participant',
                        'exact declared participant identity', 'service rejected participant identity',
                        [receipt['receipt_id']])
        if receipt['effect'] == 'identity' and receipt['outcome'] == 'succeeded':
            alias = receipt['request']['credential_alias']
            identities.setdefault(alias, []).append(receipt)
    business = sorted((r for r in trusted.values() if r['effect'] != 'identity' and r['outcome'] == 'succeeded'),
                      key=lambda receipt: receipt['sequence'])
    if not identities:
        verdict.add('receipt_missing', '/participant', 'successful trusted participant identity receipt',
                    'no verified participant identity', status='incomplete')
    missing_aliases = set()
    for receipt in business:
        alias = receipt['request']['credential_alias']
        proofs = identities.get(alias, [])
        if not proofs:
            # One participant diagnostic already covers complete absence; when
            # another alias was verified, identify the unverified alias safely.
            if identities and alias not in missing_aliases:
                verdict.add('receipt_missing', '/participant',
                            {'credential_alias': alias, 'identity': 'successful prior identity receipt'},
                            'credential alias has no identity proof', [receipt['receipt_id']], status='incomplete')
                missing_aliases.add(alias)
        elif not any(proof['sequence'] < receipt['sequence'] for proof in proofs):
            verdict.add('participant_mismatch', '/receipts/' + receipt['receipt_id'] + '/participant',
                        {'credential_alias': alias, 'identity': 'successful prior identity receipt'},
                        {'mismatched_fields': ['identity_sequence']}, [receipt['receipt_id']])


def _pages(contract, report, trusted, verdict):
    def chain_status(selected, operation, require_exhausted):
        valid, conflict, previous = bool(selected), False, None
        for page_number, receipt in enumerate(selected, 1):
            if receipt is None:
                valid, previous = False, None
                continue
            page = receipt['pagination']
            if receipt['operation_id'] != operation or receipt['outcome'] != 'succeeded' or page is None:
                valid, conflict, previous = False, True, None
                continue
            if (page['page'] != page_number or (page_number == 1 and page['predecessor_receipt_id'] is not None)
                    or (previous and (page['predecessor_receipt_id'] != previous['receipt_id']
                                      or page['chain_id'] != previous['pagination']['chain_id']
                                      or page['snapshot_id'] != previous['pagination']['snapshot_id']
                                      or page['total_items'] != previous['pagination']['total_items'] + page['items']
                                      or previous['pagination']['state'] != 'more'))):
                valid, conflict = False, True
            previous = receipt
        if require_exhausted and (previous is None or previous['pagination']['state'] != 'exhausted'):
            valid = False
        return valid, conflict

    for number, requirement in enumerate(contract['pagination']):
        p = '/pagination/' + str(number)
        operation = requirement['operation_id']
        ids = report['pagination'].get(operation, []) if report else []
        observed = sorted((receipt for receipt in trusted.values() if receipt['operation_id'] == operation and receipt['pagination'] is not None), key=lambda receipt: receipt['sequence'])
        # Even malformed/absent reports cannot hide an independently missing chain.
        selected = [trusted.get(receipt_id) for receipt_id in ids] if report else observed
        missing = [receipt_id for receipt_id in ids if receipt_id not in trusted]
        for receipt_id in missing:
            verdict.add('receipt_missing', p, 'parent receipt', 'missing receipt', [receipt_id], status='incomplete')
        if report is None:
            # Independent diagnostic reads may start another chain; absence of a
            # manifest does not itself make those unused reads conflicting.
            groups = {}
            for receipt in observed:
                groups.setdefault(receipt['pagination']['chain_id'], []).append(receipt)
            states = [chain_status(group, operation, requirement['require_exhausted']) for group in groups.values()]
            valid = any(state[0] for state in states)
            conflict = not valid and any(state[1] for state in states)
        else:
            valid, conflict = chain_status(selected, operation, requirement['require_exhausted'])
        if not valid:
            verdict.add('pagination_incomplete', p, 'unbroken declared pagination coverage', 'missing, conflicting or unexhausted chain', ids,
                        status='invalid' if conflict else 'incomplete')


def _publications(contract, report, trusted, artifacts, verdict):
    reported = {item['id']: item['receipt_id'] for item in report['publications']} if report else {}
    for number, requirement in enumerate(contract['publications']):
        p = '/publications/' + str(number)
        matching = [receipt for receipt in trusted.values() if receipt['operation_id'] == requirement['operation_id']]
        successful = [r for r in matching if r['outcome'] == 'succeeded']
        if len(successful) > 1:
            verdict.add('receipt_duplicate', p, 'one publication effect', 'multiple publication receipts', [r['receipt_id'] for r in successful])
        if any(r['outcome'] == 'outcome_unknown' for r in matching):
            verdict.add('publication_outcome_unknown', p, 'definitive publication receipt', 'unknown write outcome',
                        [r['receipt_id'] for r in matching if r['outcome'] == 'outcome_unknown'], status='incomplete')
        selected_id = reported.get(requirement['id'])
        selected = trusted.get(selected_id) if selected_id else (successful[0] if len(successful) == 1 else None)
        if report is not None and selected_id is None:
            verdict.add('publication_missing', p, 'publication manifest entry', 'missing entry', status='incomplete')
        if selected_id and selected is None:
            verdict.add('receipt_missing', p, 'parent publication receipt', 'missing receipt', [selected_id], status='incomplete')
        if selected is None:
            if not matching:
                verdict.add('publication_missing', p, 'publication receipt', 'missing receipt', status='incomplete')
            continue
        if selected['outcome'] == 'outcome_unknown':
            continue
        pub = selected['publication']
        actual = artifacts.get(requirement['artifact_id'])
        expected = {key: requirement[key] for key in ('id', 'artifact_id', 'target_id')}
        mismatches = [field for field, required in [('operation_id', requirement['operation_id']),
                      ('effect', 'publication'), ('outcome', 'succeeded')] if selected[field] != required]
        if pub is None:
            mismatches.append('publication')
        else:
            mismatches += [field for field, required in expected.items() if pub[field] != required]
            if pub['state'] != requirement['required_state']:
                mismatches.append('state')
            if actual is not None and pub['artifact_sha256'] != actual['sha256']:
                mismatches.append('artifact_sha256')
        if mismatches:
            expected.update(operation_id=requirement['operation_id'], state=requirement['required_state'])
            verdict.add('publication_binding_mismatch', p, expected,
                        {'mismatched_fields': mismatches}, [selected['receipt_id']])
