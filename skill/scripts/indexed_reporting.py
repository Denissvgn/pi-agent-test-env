"""Private assignment identities and public allowlists, never credential hashes."""
import math
import indexed_contract as contract


def identity(binding):
    return {'environment_incarnation':binding['incarnation'],'configuration':binding['fingerprint'],
            'authority_id':binding['authority_id'],'adapter':contract.ADAPTER}


def finite(value):
    return value if type(value) in (int,float) and math.isfinite(value) else None


def public_rows(rows,read_binding,stage_names):
    """Opaque labels are local to this export. No user-selected strings survive."""
    labels={};cases={};variants={};out=[]
    for row in rows:
        cases.setdefault(row['case'],'case-'+str(len(cases)+1));variants.setdefault(row['variant'],'variant-'+str(len(variants)+1))
        bindings=read_binding(row);assignments=[]
        names=stage_names(row)
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
        out.append({'schema':1,'document_type':'public_indexed_trial','cell':len(out)+1,
            'case':cases[row['case']],'variant':variants[row['variant']],'repetition':row['repetition'],
            'bindings':assignments,'attempts':attempts,'scope':'Opaque labels apply only within this collection; provider capacity and inference timing unknown.'})
    return out
