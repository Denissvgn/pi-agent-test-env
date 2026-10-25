"""Read-only application completion finalization and argument-free projections.

Private evaluator results are returned separately from the versioned public
projection. No function dispatches tools, inference, repairs or continuations.
"""
import copy
from collections import Counter

import application_contracts as c
import completion_contract

STATUSES=frozenset(('complete','incomplete','invalid','not_evaluated','dependency_blocked','prior_failure'))
EVALUATOR_CODES=frozenset(('writers_unconfirmed','artifact_hash_mismatch','artifact_missing',
    'artifact_path_unsafe','evidence_unavailable','pagination_incomplete','participant_mismatch',
    'publication_binding_mismatch','publication_missing','publication_outcome_unknown',
    'receipt_duplicate','receipt_integrity_failed','receipt_missing','report_malformed',
    'report_missing','report_unresolved'))
CODES=EVALUATOR_CODES|frozenset(('helper_cleanup_unconfirmed','credentials_unclean',
    'completion_context_invalid','completion_contract_invalid','dependency_blocked','prior_failure','stage_not_evaluated'))
STAGE_FIELDS={'stage','status','diagnostics','diagnostics_truncated'}


class CompletionReportingError(ValueError):
    def __init__(self):super().__init__('Invalid application completion projection')


def _name(value):
    try:return c.slug(value,'')
    except (ValueError,TypeError):raise CompletionReportingError() from None


def _projection(stage,status,codes=(),truncated=False):
    counts=Counter(codes)
    return {'stage':stage,'status':status,
        'diagnostics':[{'code':code,'count':counts[code]} for code in sorted(counts)],
        'diagnostics_truncated':truncated}


def validate_stage(value):
    """Exact public schema; never copies arbitrary diagnostic strings/fields."""
    if type(value) is not dict or set(value)!=STAGE_FIELDS:raise CompletionReportingError()
    name=_name(value['stage']);status=value['status'];diagnostics=value['diagnostics']
    if (type(status) is not str or status not in STATUSES or type(value['diagnostics_truncated']) is not bool
            or type(diagnostics) is not list or len(diagnostics)>len(CODES)):raise CompletionReportingError()
    total=0;seen=set();rows=[]
    for row in diagnostics:
        if (type(row) is not dict or set(row)!={'code','count'} or type(row['code']) is not str
                or row['code'] not in CODES or row['code'] in seen or type(row['count']) is not int
                or not 1<=row['count']<=100):raise CompletionReportingError()
        seen.add(row['code']);total+=row['count'];rows.append({'code':row['code'],'count':row['count']})
    if total>100 or (status=='complete' and (rows or value['diagnostics_truncated'])) or (status!='complete' and not rows):
        raise CompletionReportingError()
    return {'stage':name,'status':status,'diagnostics':sorted(rows,key=lambda row:row['code']),
            'diagnostics_truncated':value['diagnostics_truncated']}


def _blocked(stage,status,code):
    return {'projection':_projection(stage,status,[code]),'result':None}


def stage_result(stage,context,process,credential_receipt):
    """Evaluate only after independent writer/helper/credential cleanup proof.

    context is exactly {binding, authorized_segment_ids, report_root,
    evidence_root, parent_receipts}. process.application_helper_cleanup is the
    parent's helper receipt. Invocation settlement/task scoring remain untouched.
    """
    if type(stage) is not dict:raise CompletionReportingError()
    name=_name(stage.get('id'))
    if type(process) is not dict or process.get('cleanup_confirmed') is not True:
        return _blocked(name,'not_evaluated','writers_unconfirmed')
    if (process.get('cancelled') is True or process.get('termination_reason') in
            ('cancelled','application_credential_cleanup','cleanup_error') or process.get('exit_code')==130
            or 'cancelled' in process and type(process['cancelled']) is not bool
            or 'exit_code' in process and type(process['exit_code']) is not int
            or 'termination_reason' in process and type(process['termination_reason']) is not str):
        return _blocked(name,'not_evaluated','stage_not_evaluated')
    helper=process.get('application_helper_cleanup')
    if (type(helper) is not dict or type(helper.get('schema')) is not int or helper.get('schema')!=1
            or helper.get('status')!='removed' or helper.get('workspace')!='clean'
            or helper.get('safe_to_continue') is not True):
        return _blocked(name,'not_evaluated','helper_cleanup_unconfirmed')
    if (type(credential_receipt) is not dict or type(credential_receipt.get('schema')) is not int
            or credential_receipt.get('schema')!=1 or credential_receipt.get('status')!='removed'
            or credential_receipt.get('workspace')!='clean'):
        return _blocked(name,'not_evaluated','credentials_unclean')
    try:contract=c.validate_completion(stage.get('completion'))
    except (ValueError,TypeError):return _blocked(name,'invalid','completion_contract_invalid')
    fields={'binding','authorized_segment_ids','report_root','evidence_root','parent_receipts'}
    if type(context) is not dict or set(context)!=fields:
        return _blocked(name,'invalid','completion_context_invalid')
    try:
        result=completion_contract.evaluate(contract,report_root=context['report_root'],
            evidence_root=context['evidence_root'],receipts=context['parent_receipts'],binding=context['binding'],
            authorized_segment_ids=context['authorized_segment_ids'],writers_confirmed=True)
        if (type(result) is not dict or set(result)!={'schema','document_type','contract_id','status',
                'diagnostics','diagnostics_truncated'} or type(result['schema']) is not int or result['schema']!=1
                or result['document_type']!='application_completion_result' or result['contract_id']!=contract['id']
                or type(result['status']) is not str or result['status'] not in ('complete','incomplete','invalid','not_evaluated')
                or type(result['diagnostics']) is not list or len(result['diagnostics'])>100
                or type(result['diagnostics_truncated']) is not bool):raise CompletionReportingError()
        codes=[]
        for diagnostic in result['diagnostics']:
            if (type(diagnostic) is not dict or type(diagnostic.get('code')) is not str
                    or diagnostic['code'] not in EVALUATOR_CODES):raise CompletionReportingError()
            codes.append(diagnostic['code'])
        projection=validate_stage(_projection(name,result['status'],codes,result['diagnostics_truncated']))
        return {'projection':projection,'result':copy.deepcopy(result)}
    except (ValueError,TypeError,KeyError,RecursionError):
        return _blocked(name,'invalid','completion_context_invalid')
    except OSError:return _blocked(name,'not_evaluated','evidence_unavailable')


def run_projection(stages):
    """Build the optional public record field from safe stage projections only."""
    if stages is None:return None
    if type(stages) not in (list,tuple) or not 1<=len(stages)<=8:raise CompletionReportingError()
    rows=[validate_stage(row) for row in stages]
    if len({row['stage'] for row in rows})!=len(rows):raise CompletionReportingError()
    return {'schema':1,'document_type':'application_run_completion','stages':rows}


def blocked_stage(stage,status):
    if type(status) is not str or status not in ('dependency_blocked','prior_failure'):raise CompletionReportingError()
    return _projection(_name(stage),status,[status])


def gate(value,*,required_stages=None):
    """None is legacy only when no frozen required stage was supplied."""
    try:
        required=None
        if required_stages is not None:
            if type(required_stages) not in (list,tuple) or not 1<=len(required_stages)<=8:return False
            required=[_name(name) for name in required_stages]
            if len(set(required))!=len(required):return False
        if value is None:return required is None
        if (type(value) is not dict or set(value)!={'schema','document_type','stages'}
                or type(value['schema']) is not int or value['schema']!=1
                or value['document_type']!='application_run_completion'):return False
        checked=run_projection(value['stages'])
        if required is not None and [row['stage'] for row in checked['stages']]!=required:return False
        return all(row['status']=='complete' for row in checked['stages'])
    except (ValueError,TypeError,KeyError,RecursionError):return False


def dependency_status(plan,completed_results,nextstage):
    """Return None or a blocked status from parent invocation/cleanup/report facts.

    completed_results maps each prior IR stage ID to exactly
    {invocation_ok:bool, cleanup_ok:bool, completion:<safe stage projection>}.
    Task scorer results remain independent. A malformed/missing prior row fails
    closed; no successor, instruction, repair or model action is generated.
    """
    try:
        final=c.validate_ir(plan);names=[stage['id'] for stage in final['stages']]
        name=_name(nextstage)
        if name not in names or type(completed_results) is not dict:raise CompletionReportingError()
        prior=names[:names.index(name)]
        if any(key not in prior for key in completed_results):return 'prior_failure'
        failed=set()
        for stageid in prior:
            row=completed_results.get(stageid)
            if (type(row) is not dict or set(row)!={'invocation_ok','cleanup_ok','completion'}
                    or type(row['invocation_ok']) is not bool or type(row['cleanup_ok']) is not bool):
                failed.add(stageid);continue
            try:projection=validate_stage(row['completion'])
            except (ValueError,TypeError,KeyError):failed.add(stageid);continue
            if (projection['stage']!=stageid or not row['invocation_ok'] or not row['cleanup_ok']
                    or projection['status']!='complete'):failed.add(stageid)
        ancestors=set();byid={stage['id']:stage for stage in final['stages']}
        pending=list(byid[name]['depends_on'])
        while pending:
            parent=pending.pop()
            if parent in ancestors:continue
            ancestors.add(parent);pending.extend(byid[parent]['depends_on'])
        return 'dependency_blocked' if failed&ancestors else 'prior_failure' if failed else None
    except (ValueError,TypeError,KeyError,RecursionError):return 'prior_failure'
