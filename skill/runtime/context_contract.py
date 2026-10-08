"""Shared conservative interpretation of model-associated serving context limits."""
CURRENT_FIELDS=('max_model_len','context_length','context_window','max_context_length','loaded_context_length')
TRAINING_FIELDS=('n_ctx_train','training_context_length')


def interpret_context(model, models, props=None):
    item=next((x for x in models if isinstance(x,dict) and x.get('id')==model),{})
    effective=[];training=[];ignored=[]
    def collect(obj,fields,prefix,target):
        if not isinstance(obj,dict):return
        for field in fields:
            if field not in obj:continue
            value=obj[field]
            if type(value) is int and value>0:target.append({'source':prefix+field,'value':value,'scope':'training' if target is training else 'loaded' if field in ('loaded_context_length','n_ctx') else 'current'})
            else:ignored.append({'source':prefix+field,'reason':'invalid_positive_integer'})
    collect(item,CURRENT_FIELDS,'models.',effective)
    meta=item.get('meta',{})
    collect(meta,CURRENT_FIELDS,'models.meta.',effective)
    collect(meta,TRAINING_FIELDS,'models.meta.',training)
    collect(item,TRAINING_FIELDS,'models.',training)
    association='unavailable'
    if isinstance(props,dict):
        identities=[props[x] for x in ('model','model_id','model_alias') if isinstance(props.get(x),str)]
        if identities:association='exact_model' if all(x==model for x in identities) else 'unrelated_model'
        elif len(models)==1 and item:association='single_listed_model_inference'
        else:association='unknown_model'
        if association in ('exact_model','single_listed_model_inference'):
            collect(props,CURRENT_FIELDS,'props.',effective)
            collect(props.get('default_generation_settings'),('n_ctx',),'props.default_generation_settings.',effective)
        else:ignored.append({'source':'props','reason':association})
    limit=min((x['value'] for x in effective),default=None)
    return {'effective_limit':limit,'capacity_status':'reported' if limit is not None else 'unknown',
            'effective_sources':effective,'training_maxima':training,'props_association':association,
            'conflict':len({x['value'] for x in effective})>1,'ignored':ignored}


def check_context(context,requested):
    limit=context['effective_limit']
    if limit is not None and requested>limit:
        raise ValueError(f'Configured context {requested} exceeds reported effective server context {limit}')
    return context
