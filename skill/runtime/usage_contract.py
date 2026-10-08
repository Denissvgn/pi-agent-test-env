"""Completed assistant usage only; streaming updates are cumulative, never additive."""
FIELDS={'input':'input','output':'output','cache_read':'cacheRead','cache_write':'cacheWrite','total':'totalTokens'}


def summarize(messages):
    categories={name:{'known_sum':0,'missing_messages':0,'reported':None} for name in FIELDS}
    for message in messages:
        usage=message.get('usage') if isinstance(message.get('usage'),dict) else {}
        meaningful=any(type(v) is int and v>0 for v in usage.values())
        for name,key in FIELDS.items():
            value=usage.get(key)
            if meaningful and type(value) is int and value>=0:categories[name]['known_sum']+=value
            else:categories[name]['missing_messages']+=1
    for value in categories.values():
        if messages and value['missing_messages']==0:value['reported']=value['known_sum']
    return {'schema':1,'completed_messages':len(messages),'categories':categories,
            'aggregation':'completed_message_end_once; streaming updates and turn/agent summaries excluded',
            'inference_seconds':None,'inference_timing_status':'not_exposed',
            'zero_usage_policy':'all-zero placeholders treated as unknown'}


def combine(receipts):
    result=summarize([])
    result['missing_invocations']=sum(not x.get('completed_messages') for x in receipts)
    result['completed_messages']=sum(x.get('completed_messages',0) for x in receipts)
    for name in FIELDS:
        rows=[x['categories'][name] for x in receipts]
        known=sum(x['known_sum'] for x in rows);missing=sum(x['missing_messages'] for x in rows)
        result['categories'][name]={'known_sum':known,'missing_messages':missing,'reported':known if result['completed_messages'] and not missing and not result['missing_invocations'] else None}
    return result
