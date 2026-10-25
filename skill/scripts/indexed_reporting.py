"""Private assignment identities and public allowlists, never credential hashes."""
import math
import indexed_contract as contract
import native_budget_reporting
import application_completion
import application_contracts


def _application_names(value):
    if type(value) not in (list,tuple) or not 1<=len(value)<=8:raise ValueError()
    names=[application_contracts.slug(name,'') for name in value]
    if len(set(names))!=len(names):raise ValueError()
    return names


def application_projection(record,*,required_stages=None,stage_names=None,public=False):
    """Allowlisted completion only; malformed declared data stays unavailable.

    stage_names/required_stages are frozen parent metadata. Public stage ordinals
    never expose participant IDs, paths, receipts or arbitrary marker values.
    """
    if type(public) is not bool:raise ValueError('Invalid completion projection mode')
    present=type(record) is dict and bool({'application_execution','application_completion'}&set(record))
    if not present and (required_stages is None or required_stages==() or required_stages==[]):return None
    names=None;required=None
    try:
        if stage_names is not None:names=_application_names(stage_names)
        if required_stages is not None:required=_application_names(required_stages)
        marker=record.get('application_execution') if type(record) is dict else None
        if (type(marker) is not dict or set(marker)!={'schema','plan_sha256','required_stages'}
                or type(marker['schema']) is not int or marker['schema']!=1):raise ValueError()
        application_contracts.sha256(marker['plan_sha256'],'')
        declared=_application_names(marker['required_stages'])
        if required is not None and declared!=required:raise ValueError()
        required=declared
        if names is not None and any(stage not in names for stage in required):raise ValueError()
        value=record.get('application_completion')
        if (type(value) is not dict or set(value)!={'schema','document_type','stages'}
                or type(value['schema']) is not int or value['schema']!=1
                or value['document_type']!='application_run_completion'):raise ValueError()
        result=application_completion.run_projection(value['stages'])
        if [row['stage'] for row in result['stages']]!=required:raise ValueError()
    except (ValueError,TypeError,KeyError,RecursionError):
        # Only known parent names or validated required slugs are retained. An
        # invalid marker with no usable identity gets a fixed unknown position.
        safe=required or names or ['stage-1']
        result=application_completion.run_projection([{'stage':name,'status':'not_evaluated',
            'diagnostics':[{'code':'stage_not_evaluated','count':1}],'diagnostics_truncated':False} for name in safe])
    if public:
        mapping={name:number for number,name in enumerate(names or [row['stage'] for row in result['stages']],1)}
        for number,row in enumerate(result['stages'],1):row['stage']=mapping.get(row['stage'],number)
    return result


def identity(binding):
    return {'environment_incarnation':binding['incarnation'],'configuration':binding['fingerprint'],
            'authority_id':binding['authority_id'],'adapter':contract.ADAPTER}


def finite(value):
    return value if type(value) in (int,float) and math.isfinite(value) else None


def public_rows(rows,read_binding,stage_names,*,required_native_stages=None,required_application_stages=None):
    """Opaque labels are local to this export. No user-selected strings survive."""
    labels={};cases={};variants={};out=[]
    for row in rows:
        cases.setdefault(row['case'],'case-'+str(len(cases)+1));variants.setdefault(row['variant'],'variant-'+str(len(variants)+1))
        bindings=read_binding(row);assignments=[]
        names=stage_names(row)
        required=required_native_stages(row) if required_native_stages is not None else ()
        application_required=required_application_stages(row) if required_application_stages is not None else None
        if set(names)!=set(bindings) or len(names)!=len(set(names)):raise contract.IndexedError('selection-conflict')
        for number,name in enumerate(names,1):
            binding=bindings[name]
            key=(binding['incarnation'],binding['fingerprint'],binding['authority_id'])
            labels.setdefault(key,'binding-'+str(len(labels)+1))
            assignments.append({'stage':number,'binding':labels[key],'adapter':contract.ADAPTER})
        attempts=[]
        for attempt in row['attempts']:
            record=attempt.get('result') or {};status=record.get('status')
            statuses={'PASS','FAIL','BLOCKED','INTERRUPTED','RECOVERED','ASSISTED'}
            reason=record.get('infrastructure',{}).get('reason')
            usage=record.get('measurement',{}).get('usage',{}).get('categories',{})
            attempts.append({'index':attempt['attempt_index'],'status':status if status in statuses else 'incomplete',
                'reason':reason if reason in contract.REASONS else None,'score':finite(record.get('task_result',{}).get('score')),
                'reported_usage':{name:finite(usage.get(name,{}).get('reported')) for name in ('input','output','cache_read','cache_write','total')},
                'inference_seconds':None})
            budget=native_budget_reporting.record_projection(record,stage_names=names,required_stages=required,public=True)
            if budget is not None:attempts[-1]['native_tool_budgets']=budget
            completion=application_projection(record,stage_names=names,required_stages=application_required,public=True)
            if completion is not None:attempts[-1]['application_completion']=completion
        out.append({'schema':1,'document_type':'public_indexed_trial','cell':len(out)+1,
            'case':cases[row['case']],'variant':variants[row['variant']],'repetition':row['repetition'],
            'bindings':assignments,'attempts':attempts,'scope':'Opaque labels apply only within this collection; provider capacity and inference timing unknown.'})
    return out
