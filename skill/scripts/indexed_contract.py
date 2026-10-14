"""Strict offline contracts for explicitly indexed inference execution."""
import copy
import hashlib
import json
import re
import uuid

API='openai-completions'
ADAPTER='chat-completions-v1'
EXECUTION='indexed-inference-v1'
SCHEDULER='parallel-trials-v2'
HOST_GENERATION=2
MAX_ENTRIES=32
MAX_BYTES=1024*1024
MAX_SELECTED=8
ID=re.compile(r'[a-z][a-z0-9-]{0,63}')
KEY=re.compile(r'[A-Z_][A-Z0-9_]*')
REASONS={
    'environment-not-found':'Select an existing named inference environment.',
    'environment-index-stale':'List the catalog again and select the intended named environment.',
    'selection-conflict':'Choose one explicit owner for each agent stage binding.',
    'unsupported-api-adapter':'Select the reviewed Chat Completions adapter for the exact Pi release.',
    'environment-unconfirmed':'Confirm the selected environment in this session before execution.',
    'environment-configuration-changed':'Confirm the new configuration and prepare a fresh execution.',
    'inference-authority-changed':'Reauthorize the selected credential source and prepare a fresh execution.',
    'environment-revoked':'Select and confirm an active environment; retain existing sealed results.',
    'credential-unavailable':'Configure the explicitly selected credential source securely.',
    'catalog-insecure':'Use an owner-only catalog of regular, singly linked files.',
    'catalog-invalid':'Repair the bounded catalog using the documented schema.',
    'inference-input-unsafe':'Use inspectable, credential-free projects, plans and configuration inputs.',
    'inference-configuration-secret':'Use nonsecret configuration values and named credential references only.',
    'inference-queue-expired':'Inspect the frozen queue budget; prepare an explicitly approved adjustment.',
    'inference-quarantined':'Reconcile upstream uncertainty before new inference admission.',
}


class IndexedError(ValueError):
    def __init__(self,reason='catalog-invalid'):
        if reason not in REASONS:reason='catalog-invalid'
        self.reason=reason;self.guidance=REASONS[reason]
        super().__init__(self.guidance)
    def public(self):return {'reason':self.reason,'guidance':self.guidance}


def fields(value,required,optional=()):
    if not isinstance(value,dict) or not set(required)<=set(value) or set(value)-set(required)-set(optional):
        raise IndexedError()


def identifier(value):
    if not isinstance(value,str) or not ID.fullmatch(value):raise IndexedError()
    return value


def integer(value,low=1,high=2**63-1):
    if type(value) is not int or not low<=value<=high:raise IndexedError()
    return value


def identity(value):
    try:
        parsed=str(uuid.UUID(value))
        if parsed!=value:raise IndexedError()
        return parsed
    except (ValueError,TypeError,AttributeError):raise IndexedError() from None


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()


def diagnostic(exc):
    if type(exc) is not IndexedError:return None
    code=exc.reason if isinstance(exc.reason,str) and exc.reason in REASONS else 'catalog-invalid'
    return {'reason':code,'message':REASONS[code],'remedy':REASONS[code]}


def credential(value):
    fields(value,('source',),('name',))
    if value['source'] not in ('store','env','none'):raise IndexedError()
    if value['source']=='none':
        if 'name' in value:raise IndexedError()
    elif not isinstance(value.get('name'),str) or len(value['name'])>128 or not KEY.fullmatch(value['name']):raise IndexedError()
    return copy.deepcopy(value)


def limits(value=None):
    if value is None:value={'queue_wait_seconds':180,'request_timeout_seconds':180}
    fields(value,('queue_wait_seconds','request_timeout_seconds'))
    integer(value['queue_wait_seconds'],1,600);integer(value['request_timeout_seconds'],30,600)
    if value['queue_wait_seconds']>value['request_timeout_seconds']:raise IndexedError()
    return copy.deepcopy(value)


def configuration(value,normalize):
    fields(value,('api','adapter_contract','endpoint','credential','capacity_group'),('account_groups','request_limits'))
    if value['api']!=API or value['adapter_contract']!=ADAPTER:raise IndexedError('unsupported-api-adapter')
    result=copy.deepcopy(value);result['credential']=credential(value['credential'])
    raw=copy.deepcopy(value['endpoint'])
    if not isinstance(raw,dict) or 'api_key_env' in raw:raise IndexedError()
    raw['api_key_env']=result['credential'].get('name','PI_LAB_NOAUTH')
    result['endpoint']=normalize(raw)
    for field,maximum in (('base_url',4096),('host_base_url',4096),('model',512)):
        if len(result['endpoint'][field].encode('utf-8'))>maximum:raise IndexedError()
    integer(result['endpoint']['context_window'],2,2**31-1);integer(result['endpoint']['max_tokens'],1,2**31-2)
    # The canonical endpoint retains compatibility with the reviewed adapter;
    # the source binding, not this variable name, controls credential resolution.
    identifier(result['capacity_group'])
    groups=result.setdefault('account_groups',[])
    if not isinstance(groups,list) or len(groups)>8:raise IndexedError()
    for group in groups:identifier(group)
    if len(groups)!=len(set(groups)):raise IndexedError()
    result['request_limits']=limits(result.get('request_limits'))
    return result


def entry(value,normalize):
    fields(value,('id','incarnation','revision','configuration','fingerprint'))
    identifier(value['id']);identity(value['incarnation']);integer(value['revision'])
    original=copy.deepcopy(value['configuration'])
    # Stored endpoint has already been normalized. Never expand parameters again.
    endpoint=original.get('endpoint',{})
    if not isinstance(endpoint,dict) or any('${' in str(endpoint.get(k,'')) for k in ('base_url','host_base_url','model')):raise IndexedError()
    supplied=endpoint.pop('api_key_env',None)
    config=configuration(original,normalize)
    if supplied!=config['endpoint']['api_key_env'] or config!=value['configuration'] or digest(config)!=value['fingerprint']:raise IndexedError()
    return copy.deepcopy(value)


def catalog(value,normalize):
    fields(value,('schema','revision','default_id','entries','tombstones'))
    if type(value['schema']) is not int or value['schema']!=1:raise IndexedError()
    integer(value['revision']);items=value['entries'];tombstones=value['tombstones']
    if not isinstance(items,list) or len(items)>MAX_ENTRIES or not isinstance(tombstones,list) or len(tombstones)>256:raise IndexedError()
    seen=set();incarnations=set()
    for item in items:
        selected=entry(item,normalize)
        if selected['id'] in seen or selected['incarnation'] in incarnations:raise IndexedError()
        seen.add(selected['id']);incarnations.add(selected['incarnation'])
    for item in tombstones:
        fields(item,('id','incarnation','revision'));identifier(item['id']);identity(item['incarnation']);integer(item['revision'])
        if item['incarnation'] in incarnations:raise IndexedError()
        incarnations.add(item['incarnation'])
    if value['default_id'] is not None and value['default_id'] not in seen:raise IndexedError()
    if len(json.dumps(value).encode())>MAX_BYTES:raise IndexedError()
    return copy.deepcopy(value)


def stage_map(value,names):
    if not isinstance(value,dict) or set(value)!=set(names) or len(names)!=len(set(names)) or not 1<=len(names)<=8:
        raise IndexedError('selection-conflict')
    for selected in value.values():identifier(selected)
    if len(set(value.values()))>MAX_SELECTED:raise IndexedError()
    return copy.deepcopy(value)


def case_maps(value,cases):
    if not isinstance(value,dict) or set(value)!=set(cases):raise IndexedError('selection-conflict')
    result={name:stage_map(value[name],names) for name,names in cases.items()}
    if len({v for m in result.values() for v in m.values()})>MAX_SELECTED:raise IndexedError()
    return result


def helper_contract(value):
    fields(value,('contract','host_generation','max_workers','aggregate','gateway'))
    if value['contract']!=EXECUTION or type(value['host_generation']) is not int or value['host_generation']!=HOST_GENERATION:
        raise IndexedError()
    integer(value['max_workers'],1,2)
    import parallel_contract
    candidate={'scheduler':parallel_contract.VERSION,'host_generation':1,'registry_aware_cohort':True,
        'max_trials':2,'max_stages':2,'max_pending':16,'queue_wait_seconds':3600,'collection_timeout_seconds':14400,
        'aggregate':value['aggregate'],'gateway':value['gateway']}
    try:parallel_contract.validate(candidate)
    except ValueError:raise IndexedError() from None
    return copy.deepcopy(value)


def preflight(value):
    selected=limits(value);request=max(120,sum(selected.values()))
    return {'request_timeout_seconds':request,'container_timeout_seconds':request+30}


def parallel(value):
    import parallel_contract
    original=copy.deepcopy(value)
    if not isinstance(original,dict) or original.get('scheduler')!=SCHEDULER or type(original.get('host_generation')) is not int or original['host_generation']!=2:
        raise IndexedError()
    predecessor={**original,'scheduler':parallel_contract.VERSION,'host_generation':1}
    try:parallel_contract.validate(predecessor)
    except ValueError:raise IndexedError() from None
    return original


def secret_free(values,keys):
    import application_credentials
    if application_credentials.Redactor(keys).contains(json.dumps(values,ensure_ascii=False).encode()):
        raise IndexedError('inference-configuration-secret')
