"""Pure, bounded contracts for explicitly reviewed application execution.

Validation does not read files, resolve credentials, discover components or perform
network effects. A valid structure alone is not authorization or qualification.
"""
import copy
import hashlib
import ipaddress
import json
import math
from pathlib import Path, PurePosixPath
import re
import unicodedata
import sys
from functools import wraps
from urllib.parse import unquote, urlsplit

import resources
sys.path.insert(0, str(Path(__file__).absolute().parents[1] / 'runtime'))
import prompt_contract

RELEASES = ('0.87.1', '1.2.0')
APP_TOOLS = ('app_api', 'app_browser', 'artifact_read', 'artifact_write', 'report_write', 'budget_status')
SOURCE_FIELDS = {'schema', 'document_type', 'name', 'runtime', 'application', 'stages', 'checks'}
STAGE_FIELDS = {'id', 'depends_on', 'participant', 'credential_aliases', 'profile', 'prompt',
                'operations', 'browser_targets', 'input_artifacts', 'limits', 'completion'}
HASH_FIELDS = {'source', 'profiles', 'prompt_renderer', 'operations', 'completion', 'scorers',
               'release_contract', 'runner'}


class ContractError(ValueError):
    def __init__(self, message, pointer='', reason='contract_invalid'):
        self.reason, self.pointer = reason, pointer
        super().__init__(f'{reason} at {pointer or "/"}: {message}')


def fail(pointer, message, reason='contract_invalid'):
    raise ContractError(message, pointer, reason)


def escape(value):
    return str(value).replace('~', '~0').replace('/', '~1')


def exact(value, fields, pointer):
    if type(value) is not dict:
        fail(pointer, 'Exact object required')
    unknown = set(value) - set(fields)
    missing = set(fields) - set(value)
    if unknown or missing:
        field = sorted(unknown or missing)[0]
        fail(pointer + '/' + escape(field), 'Unexpected field' if unknown else 'Required field missing')
    return value


def text(value, pointer, maximum=4096, empty=False):
    if type(value) is not str:
        fail(pointer, 'String required')
    try:
        size = len(value.encode('utf-8'))
    except UnicodeError:
        fail(pointer, 'Invalid Unicode')
    if size > maximum or (not empty and not value.strip()) or '\0' in value:
        fail(pointer, 'Nonempty bounded string required')
    return value


def slug(value, pointer):
    text(value, pointer, 64)
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', value):
        fail(pointer, 'Lowercase identifier required')
    return value


def native_id(value, pointer):
    text(value, pointer, 128)
    if not re.fullmatch(r'[!-~]{1,128}', value):
        fail(pointer, 'Opaque printable ASCII native call ID required')
    return value


def integer(value, pointer, minimum=0, maximum=10000000):
    if type(value) is not int or not minimum <= value <= maximum:
        fail(pointer, 'Integer outside finite bounds')
    return value


def array(value, pointer, maximum=64, minimum=0):
    if type(value) is not list or not minimum <= len(value) <= maximum:
        fail(pointer, 'Bounded array required')
    return value


def choice(value, allowed, pointer):
    if type(value) not in (str, int, bool, type(None)) or not any(
            type(value) is type(item) and value == item for item in allowed):
        fail(pointer, 'Unsupported value')
    return value


def unique_strings(value, pointer, maximum=64, minimum=0, identifier=True):
    array(value, pointer, maximum, minimum)
    for i, item in enumerate(value):
        (slug if identifier else text)(item, f'{pointer}/{i}')
    if len(set(value)) != len(value):
        fail(pointer, 'Duplicate entries')
    return value


def relative(value, pointer):
    text(value, pointer, 512)
    path = PurePosixPath(value)
    if (value in ('.', '..') or path.is_absolute() or path.as_posix() != value
            or any(part in ('.', '..') for part in value.split('/'))
            or any(c in value for c in ('\\', ':', '%')) or any(ord(c) < 32 for c in value)):
        fail(pointer, 'Canonical contained relative POSIX path required')
    return value


def participant(value, pointer):
    exact(value, {'application_id', 'tenant_id', 'actor_id', 'role'}, pointer)
    for key, item in value.items():
        text(item, pointer + '/' + key, 128)
        if item.strip() != item or any(ord(c) < 32 for c in item):
            fail(pointer + '/' + key, 'Exact non-control identity required')
    return value


def sha256(value, pointer):
    if type(value) is not str or not re.fullmatch(r'[a-f0-9]{64}', value):
        fail(pointer, 'SHA-256 required')
    return value


def safe_json(value):
    nodes = [0]
    def walk(item, pointer, depth):
        nodes[0] += 1
        if depth > 64 or nodes[0] > 100000:
            fail(pointer, 'JSON complexity limit')
        if type(item) is dict:
            for key, child in item.items():
                text(key, pointer, 512, empty=True)
                walk(child, pointer + '/' + escape(key), depth + 1)
        elif type(item) is list:
            for i, child in enumerate(item):
                walk(child, pointer + '/' + str(i), depth + 1)
        elif type(item) is str:
            text(item, pointer, 2 * 1024 * 1024, empty=True)
        elif type(item) is int:
            if item.bit_length() > 4096:
                fail(pointer, 'Integer magnitude limit')
        elif type(item) is float:
            if not math.isfinite(item):
                fail(pointer, 'Non-finite number')
        elif type(item) not in (int, bool, type(None)):
            fail(pointer, 'JSON value required')
    walk(value, '', 0)
    return value


def canonical(value):
    safe_json(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def loads(value, max_bytes=2 * 1024 * 1024):
    if type(value) not in (str, bytes):
        fail('', 'JSON text required')
    try:
        body = value if type(value) is bytes else value.encode('utf-8')
        if len(body) > max_bytes:
            fail('', 'JSON byte limit')
        class ObjectPairs(list):
            pass
        def constant(_):
            fail('', 'Non-finite number')
        def parse_integer(raw):
            if len(raw.lstrip('-')) > 1233:
                fail('', 'Integer magnitude limit')
            return int(raw)
        parsed = json.loads(body.decode('utf-8'), object_pairs_hook=ObjectPairs,
                            parse_constant=constant, parse_int=parse_integer)
        def convert(item, pointer='', depth=0):
            if depth > 64:
                fail(pointer, 'JSON depth limit')
            if isinstance(item, ObjectPairs):
                result = {}
                for key, child in item:
                    child_pointer = pointer + '/' + escape(key)
                    if key in result:
                        fail(child_pointer, 'Duplicate JSON key')
                    result[key] = convert(child, child_pointer, depth + 1)
                return result
            if type(item) is list:
                return [convert(child, pointer + '/' + str(i), depth + 1)
                        for i, child in enumerate(item)]
            return item
        result = convert(parsed)
        safe_json(result)
        return result
    except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError) as exc:
        raise ContractError('Malformed or excessively nested JSON') from exc


def _schema(value, pointer, depth=0):
    if depth > 8 or type(value) is not dict or len(canonical(value)) > 32768:
        fail(pointer, 'Bounded nonrecursive schema required')
    allowed = {'type', 'properties', 'required', 'additionalProperties', 'items', 'enum',
               'minimum', 'maximum', 'minLength', 'maxLength', 'minItems', 'maxItems', 'pattern'}
    if set(value) - allowed or 'type' not in value:
        fail(pointer, 'Unsupported schema keyword')
    types = value['type'] if type(value['type']) is list else [value['type']]
    if (not types or len(types) != len(set(str(t) for t in types)) or
            any(type(t) is not str or t not in {'object','array','string','integer','boolean','null'} for t in types)
            or (len(types) > 1 and (len(types) != 2 or 'null' not in types))):
        fail(pointer + '/type', 'Supported type or nullable union required')
    vocabulary = {'type', 'enum'}
    if 'object' in types:
        vocabulary |= {'properties','required','additionalProperties'}
        props = value.get('properties')
        if type(props) is not dict or len(props) > 64 or value.get('additionalProperties') is not False:
            fail(pointer, 'Exact bounded object schema required')
        required = unique_strings(value.get('required'), pointer + '/required', identifier=False)
        if set(required) - set(props):
            fail(pointer + '/required', 'Unknown required property')
        for key, child in props.items():
            text(key, pointer + '/properties', 128)
            _schema(child, pointer + '/properties/' + escape(key), depth + 1)
    if 'array' in types:
        vocabulary |= {'items','minItems','maxItems'}
        integer(value.get('maxItems'), pointer + '/maxItems', 0, 1000)
        integer(value.get('minItems', 0), pointer + '/minItems', 0, value['maxItems'])
        _schema(value.get('items'), pointer + '/items', depth + 1)
    if 'string' in types:
        vocabulary |= {'minLength','maxLength','pattern'}
        if 'enum' not in value:
            integer(value.get('maxLength'), pointer + '/maxLength', 0, 262144)
        if 'maxLength' in value:
            integer(value['maxLength'], pointer + '/maxLength', 0, 262144)
        integer(value.get('minLength', 0), pointer + '/minLength', 0, value.get('maxLength',262144))
        if 'pattern' in value:
            _pattern(value['pattern'], pointer + '/pattern')
    if 'integer' in types:
        vocabulary |= {'minimum','maximum'}
        integer(value.get('minimum'), pointer + '/minimum', -1000000000, 1000000000)
        integer(value.get('maximum'), pointer + '/maximum', value['minimum'], 1000000000)
    if set(value) - vocabulary:
        fail(pointer, 'Schema keywords do not match type')
    if 'enum' in value:
        array(value['enum'], pointer + '/enum', 64, 1)
        if len({canonical(item) for item in value['enum']}) != len(value['enum']):
            fail(pointer + '/enum', 'Duplicate enum values')
        without = {k:v for k,v in value.items() if k != 'enum'}
        for i, item in enumerate(value['enum']):
            validate_value(item, without, pointer + '/enum/' + str(i), schema_checked=True)


def _pattern(value, pointer):
    text(value, pointer, 128)
    # Finite repetition of simple ASCII atoms only: no groups, backtracking,
    # alternation, backrefs, wildcard or unbounded quantifiers.
    atom = r'(?:\[[A-Za-z0-9_\-]+\]|[A-Za-z0-9_\-/])(?:\{[0-9]{1,4}\})?'
    if not re.fullmatch(r'\^(?:' + atom + r')+\$', value):
        fail(pointer, 'Only anchored finite ASCII patterns supported')
    try:
        re.compile(value)
    except re.error:
        fail(pointer, 'Invalid bounded pattern')
    for low, high in re.findall(r'\{([0-9]+)(?:,([0-9]+))?\}', value):
        if int(low) > 4096 or (high and not int(low) <= int(high) <= 4096):
            fail(pointer, 'Pattern repetition exceeds bound')


def validate_value(value, schema, pointer='', schema_checked=False):
    if not schema_checked:
        _schema(schema, '/schema')
        safe_json(value)
    types = schema['type'] if type(schema['type']) is list else [schema['type']]
    actual = {dict:'object',list:'array',str:'string',int:'integer',bool:'boolean',type(None):'null'}.get(type(value))
    if actual not in types:
        fail(pointer, 'Value has wrong type', 'request_invalid')
    if 'enum' in schema and canonical(value) not in [canonical(item) for item in schema['enum']]:
        fail(pointer, 'Value outside enum', 'request_invalid')
    if actual == 'object':
        props = schema['properties']
        if set(value) - set(props) or set(schema['required']) - set(value):
            fail(pointer, 'Unexpected or missing property', 'request_invalid')
        for key, item in value.items():
            validate_value(item, props[key], pointer + '/' + escape(key), True)
    elif actual == 'array':
        if not schema.get('minItems',0) <= len(value) <= schema['maxItems']:
            fail(pointer, 'Array outside bounds', 'request_invalid')
        for i, item in enumerate(value):
            validate_value(item, schema['items'], pointer + '/' + str(i), True)
    elif actual == 'string':
        if not schema.get('minLength',0) <= len(value) <= schema.get('maxLength',262144):
            fail(pointer, 'String outside bounds', 'request_invalid')
        if 'pattern' in schema and re.fullmatch(schema['pattern'],value) is None:
            fail(pointer, 'Pattern mismatch', 'request_invalid')
    elif actual == 'integer' and not schema['minimum'] <= value <= schema['maximum']:
        fail(pointer, 'Integer outside bounds', 'request_invalid')
    return copy.deepcopy(value)


def _operation(value, pointer):
    fields = {'id','transport','effect','credential_alias','method','origin','path_template',
              'path_params_schema','query_schema','body_schema','wire_body_schema','response_schema',
              'response_media_type','pagination','publication','max_request_seconds','result_fields','max_result_bytes'}
    exact(value, fields, pointer)
    for field in ('id','credential_alias','origin'):
        slug(value[field], pointer + '/' + field)
    choice(value['transport'], ('api','browser'), pointer + '/transport')
    effect = choice(value['effect'], ('identity','read','mutation','publication'), pointer + '/effect')
    choice(value['method'], ('GET',) if effect in ('identity','read') else ('POST','PATCH','PUT','DELETE'), pointer + '/method')
    path = text(value['path_template'], pointer + '/path_template',512)
    if (not path.startswith('/') or path.startswith('//') or '?' in path or '#' in path or '\\' in path
            or any(ord(c)<33 for c in path) or '%' in path or any(x in ('.','..','') for x in path[1:].split('/'))):
        fail(pointer + '/path_template', 'Canonical absolute route required')
    params = re.findall(r'\{([a-z][a-z0-9_]*)\}', path)
    remainder = re.sub(r'\{[a-z][a-z0-9_]*\}', 'x', path)
    if '{' in remainder or '}' in remainder or len(params) != len(set(params)):
        fail(pointer + '/path_template', 'Invalid route parameters')
    for field in ('path_params_schema','query_schema','body_schema','wire_body_schema'):
        _schema(value[field], pointer + '/' + field)
    for field in ('path_params_schema','query_schema'):
        if value[field]['type'] != 'object':
            fail(pointer + '/' + field, 'Object schema required')
    for field in value['query_schema']['properties'].values():
        if field['type'] not in ('string','integer','boolean'):fail(pointer+'/query_schema','Query values must be bounded scalar fields')
    if set(params) != set(value['path_params_schema']['properties']) or set(params) != set(value['path_params_schema']['required']):
        fail(pointer + '/path_params_schema', 'Route/schema parameter mismatch')
    for name in params:
        if value['path_params_schema']['properties'][name]['type'] not in ('string','integer'):
            fail(pointer, 'Scalar route parameters required')
    if value['response_schema'] is not None:
        _schema(value['response_schema'], pointer + '/response_schema')
    elif value['transport'] != 'browser':
        fail(pointer + '/response_schema', 'API needs JSON response schema')
    choice(value['response_media_type'], ('application/json','text/html','text/css','application/javascript','image/png','image/jpeg'),pointer + '/response_media_type')
    if value['transport']=='api' and value['response_media_type']!='application/json':
        fail(pointer + '/response_media_type','API requires JSON')
    if effect=='identity':
        response=value['response_schema']
        fields={'application_id','tenant_id','actor_id','role'}
        if (value['transport']!='api' or type(response) is not dict or response.get('type')!='object' or set(response['properties'])!=fields or set(response['required'])!=fields or any(item['type']!='string' for item in response['properties'].values())):fail(pointer+'/response_schema','Identity returns exactly the four participant string fields')
    if value['method']=='GET' and (value['body_schema']!={'type':'null'} or value['wire_body_schema']!={'type':'null'}):
        fail(pointer + '/body_schema', 'GET cannot carry a body')
    integer(value['max_request_seconds'],pointer + '/max_request_seconds',1,15)
    integer(value['max_result_bytes'],pointer + '/max_result_bytes',256,8192)
    unique_strings(value['result_fields'],pointer + '/result_fields',64,identifier=False)
    for field in value['result_fields']:
        if not field.startswith('/') or re.search(r'~(?![01])',field):
            fail(pointer + '/result_fields','Exact JSON pointers required')
        node=value['response_schema']
        if node is None:fail(pointer+'/result_fields','No JSON projections for raw browser resource')
        for part in field[1:].split('/'):
            part=part.replace('~1','/').replace('~0','~')
            typ=node.get('type')
            if typ=='object' and part in node['properties']:node=node['properties'][part]
            elif typ=='array' and re.fullmatch('0|[1-9][0-9]*',part) and int(part)<node['maxItems']:node=node['items']
            else:fail(pointer+'/result_fields','Projection path does not exist in response schema')
    pagination=value['pagination']
    if pagination is not None:
        p=pointer + '/pagination'
        exact(pagination, {'cursor_field','items_field','snapshot_field','max_pages','max_items',
                          'max_response_bytes','max_total_bytes','timeout_seconds','request_cursor'},p)
        if effect!='read' or value['response_schema'] is None or value['response_schema']['type']!='object':
            fail(p,'Only JSON read operations paginate')
        for field in ('cursor_field','items_field','snapshot_field'):
            text(pagination[field],p+'/'+field,128)
            if pagination[field] not in value['response_schema']['properties'] or pagination[field] not in value['response_schema']['required']:
                fail(p+'/'+field,'Missing response field')
        props=value['response_schema']['properties']
        if set(props[pagination['cursor_field']]['type'] if type(props[pagination['cursor_field']]['type']) is list else [props[pagination['cursor_field']]['type']])!={'string','null'} or props[pagination['items_field']]['type']!='array' or props[pagination['snapshot_field']]['type']!='string' or len({pagination[k] for k in ('cursor_field','items_field','snapshot_field')})!=3:fail(p,'Pagination response types do not match cursor/items/snapshot')
        for field,bound in [('max_pages',20),('max_items',1000),('max_response_bytes',1048576),('max_total_bytes',8388608),('timeout_seconds',120)]:
            integer(pagination[field],p+'/'+field,1,bound)
        rc=pagination['request_cursor'];exact(rc,{'location','name','encoding'},p+'/request_cursor')
        choice(rc['location'],('query','body'),p+'/request_cursor/location')
        text(rc['name'],p+'/request_cursor/name',64)
        choice(rc['encoding'],('opaque_string',),p+'/request_cursor/encoding')
        schema=value['query_schema'] if rc['location']=='query' else value['body_schema']
        if schema['type']!='object' or rc['name'] in schema['properties']:
            fail(p+'/request_cursor','Reserved cursor cannot be model input')
        if '/' + pagination['cursor_field'] in value['result_fields']:
            fail(pointer+'/result_fields','Upstream cursor cannot be projected')
    pub=value['publication']
    if effect=='publication':
        p=pointer+'/publication'
        exact(pub,{'id','artifact_id','target_id','required_state','payload_source'},p)
        for key in ('id','artifact_id','target_id'):slug(pub[key],p+'/'+key)
        choice(pub['required_state'],('published',),p+'/required_state')
        choice(pub['payload_source'],('declared_artifact',),p+'/payload_source')
        if value['body_schema']['type']!='object' or value['wire_body_schema']['type']!='object':fail(p,'Publication requires object input and wire schemas')
        if 'content' in value['body_schema']['properties']:fail(p,'Participant cannot supply publication content')
        expected=copy.deepcopy(value['wire_body_schema']);content=expected['properties'].pop('content',None)
        if content is None or content.get('type')!='string' or 'content' not in expected['required']:fail(p,'Wire schema requires artifact content')
        expected['required'].remove('content')
        if expected!=value['body_schema']:fail(p,'Only fixed content injection is supported')
    elif pub is not None or value['wire_body_schema']!=value['body_schema']:
        fail(pointer+'/publication','Unexpected publication/body transformation')


def validate_operation(value):
    safe_json(value);_operation(value,'');return copy.deepcopy(value)


def _origin(value,p):
    exact(value,{'url','diagnostic_fixture','allowed_addresses'},p)
    raw=text(value['url'],p+'/url',512)
    try:
        parsed=urlsplit(raw);port=parsed.port
    except ValueError:fail(p+'/url','Invalid origin')
    if (parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.path or parsed.query or parsed.fragment or '%' in raw
            or any(ord(c)<33 for c in raw) or raw.rstrip('/')!=raw or parsed.netloc.lower()!=parsed.netloc):
        fail(p+'/url','Exact canonical HTTP(S) origin required')
    choice(value['diagnostic_fixture'],(True,False),p+'/diagnostic_fixture')
    if parsed.scheme=='http' and not value['diagnostic_fixture']:fail(p,'HTTP only for explicit diagnostic fixtures')
    array(value['allowed_addresses'],p+'/allowed_addresses',16,1)
    for i,addr in enumerate(value['allowed_addresses']):
        try:
            if type(addr) is not str:raise ValueError()
            ipaddress.ip_address(addr)
        except (ValueError,TypeError):fail(p+'/allowed_addresses/'+str(i),'Pinned IP address required')
    if len(set(value['allowed_addresses']))!=len(value['allowed_addresses']):fail(p,'Duplicate address')


def _browser(value,p):
    exact(value,{'id','page_identity','url','locator','actions','credential_alias','allowed_operation_ids',
                 'static_resources','request_body_template','input_schema'},p)
    for key in ('id','credential_alias'):slug(value[key],p+'/'+key)
    text(value['page_identity'],p+'/page_identity',128)
    raw=text(value['url'],p+'/url',1024)
    try:parsed=urlsplit(raw)
    except ValueError:fail(p+'/url','Invalid target URL')
    try:port=parsed.port
    except ValueError:fail(p+'/url','Invalid browser port')
    if (parsed.scheme not in ('https','http') or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment or parsed.query or '%' in raw or '\\' in raw or any(ord(c)<33 for c in raw) or parsed.netloc!=parsed.netloc.lower() or not parsed.path.startswith('/') or any(x in ('.','..','') for x in parsed.path[1:].split('/'))):fail(p+'/url','Exact browser URL required')
    if value['locator'] is not None:
        # Only exact reviewed data-testid selectors in the first implementation.
        if type(value['locator']) is not str or not re.fullmatch(r'\[data-testid="[a-z0-9-]{1,64}"\]',value['locator']):fail(p+'/locator','Exact data-testid locator required')
    unique_strings(value['actions'],p+'/actions',6,1)
    for action in value['actions']:choice(action,('navigate','snapshot','screenshot','click','fill','select'),p+'/actions')
    if any(a in value['actions'] for a in ('click','fill','select')) and value['locator'] is None:fail(p+'/locator','Action needs exact locator')
    unique_strings(value['allowed_operation_ids'],p+'/allowed_operation_ids',64)
    array(value['static_resources'],p+'/static_resources',64)
    for i,res in enumerate(value['static_resources']):
        q=p+'/static_resources/'+str(i);exact(res,{'method','origin','path','media_type','max_bytes'},q)
        choice(res['method'],('GET',),q+'/method');slug(res['origin'],q+'/origin')
        path=text(res['path'],q+'/path',512)
        if not path.startswith('/') or path.startswith('//') or any(c in path for c in ('%','?','#','\\','{','}')) or any(v in ('..','.','') for v in path[1:].split('/')) or any(ord(c)<33 for c in path):fail(q+'/path','Exact resource path required')
        choice(res['media_type'],('text/html','text/css','application/javascript','image/png','image/jpeg'),q+'/media_type')
        integer(res['max_bytes'],q+'/max_bytes',1,1048576)
    if len({(v['origin'],v['path']) for v in value['static_resources']})!=len(value['static_resources']):fail(p+'/static_resources','Duplicate static resource')
    _schema(value['input_schema'],p+'/input_schema')
    if value['input_schema']['type']!='object':fail(p+'/input_schema','Object input required')
    template=value['request_body_template']
    if template is not None and type(template) is not dict:fail(p+'/request_body_template','Object template or null required')
    def check_template(item,q):
        if type(item) is str and '${' in item:
            if not re.fullmatch(r'\$\{(?:input\.(?:value|option_id)|artifact\.[a-z0-9-]+\.sha256)\}',item):fail(q,'Only exact template substitutions supported')
        elif type(item) is dict:
            for k,v in item.items():check_template(v,q+'/'+escape(k))
        elif type(item) is list:
            for i,v in enumerate(item):check_template(v,q+'/'+str(i))
    check_template(template,p+'/request_body_template')


def _scorer(value,p,frozen=False):
    required={'schema','id','version','assets','score_domain','required_assertions','test_counts_required','zero_test_policy','all_skipped_policy'}
    if type(value) is not dict or not required<=set(value) or set(value)-required-{'allow_partial'}:fail(p,'Exact scorer contract required')
    choice(value['schema'],(1,),p+'/schema')
    for key in ('id','version'):text(value[key],p+'/'+key,100)
    d=value['score_domain'];exact(d,{'min','max','direction','pass_threshold'},p+'/score_domain')
    if not all(type(d[k]) in (int,float) and math.isfinite(d[k]) for k in ('min','max','pass_threshold')) or not d['min']<d['max'] or not d['min']<=d['pass_threshold']<=d['max']:fail(p+'/score_domain','Invalid finite score domain')
    choice(d['direction'],('higher','lower'),p+'/score_domain/direction')
    unique_strings(value['required_assertions'],p+'/required_assertions',100,1,False)
    for key in ('test_counts_required','allow_partial'):
        if key in value:choice(value[key],(True,False),p+'/'+key)
    for key in ('zero_test_policy','all_skipped_policy'):choice(value[key],('fail','allow'),p+'/'+key)
    array(value['assets'],p+'/assets',32,1);seen=[]
    for i,asset in enumerate(value['assets']):
        q=p+'/assets/'+str(i);exact(asset,{'target','sha256'} if frozen else {'source','target'},q)
        relative(asset['target'],q+'/target')
        if frozen:sha256(asset['sha256'],q+'/sha256')
        else:relative(asset['source'],q+'/source')
        seen.append(asset['target'])
    _unique_paths(seen,p+'/assets')


def _unique_paths(paths,p):
    seen=[]
    for path in paths:
        low=unicodedata.normalize('NFC',path).casefold()
        if any(low==old or low.startswith(old+'/') or old.startswith(low+'/') for old in seen):fail(p,'Conflicting producer paths')
        seen.append(low)


def _source(value,frozen=False):
    exact(value,SOURCE_FIELDS,'')
    choice(value['schema'],(1,),'/schema');choice(value['document_type'],('application_plan_source',),'/document_type')
    slug(value['name'],'/name')
    rt=value['runtime'];p='/runtime'
    exact(rt,{'pi_release','image_id','platform','container_profile','browser_sandbox_policy','resources','inference_owner'},p)
    choice(rt['pi_release'],RELEASES,p+'/pi_release')
    if type(rt['image_id']) is not str or not re.fullmatch('sha256:[a-f0-9]{64}',rt['image_id']):fail(p+'/image_id','Immutable image identity required','runtime_mismatch')
    choice(rt['platform'],('linux/arm64',),p+'/platform')
    choice(rt['container_profile'],('core','browser'),p+'/container_profile')
    choice(rt['browser_sandbox_policy'],('chromium-userns',) if rt['container_profile']=='browser' else (None,),p+'/browser_sandbox_policy')
    choice(rt['inference_owner'],('compiler_input','experiment_variant'),p+'/inference_owner')
    try:resources.validate_policy(rt['resources'])
    except (ValueError,TypeError,KeyError):fail(p+'/resources','Invalid reviewed resource policy')
    if type(rt['resources'].get('schema',1)) is not int:fail(p+'/resources/schema','Integer schema required')
    app=value['application'];p='/application'
    exact(app,{'id','origins','credentials','operations','browser_targets','limits'},p);slug(app['id'],p+'/id')
    for field in ('origins','credentials'):
        if type(app[field]) is not dict or not 1<=len(app[field])<=8:fail(p+'/'+field,'Bounded nonempty map required')
        for key in app[field]:slug(key,p+'/'+field+'/'+escape(key))
    for key,origin in app['origins'].items():_origin(origin,p+'/origins/'+key)
    for key,reference in app['credentials'].items():
        if type(reference) is not str or not re.fullmatch('[A-Z_][A-Z0-9_]{0,63}',reference):fail(p+'/credentials/'+key,'Host store reference required','credential_scope_invalid')
    exact(app['limits'],{'max_evidence_bytes','max_receipts'},p+'/limits')
    integer(app['limits']['max_evidence_bytes'],p+'/limits/max_evidence_bytes',1,33554432)
    integer(app['limits']['max_receipts'],p+'/limits/max_receipts',1,500)
    array(app['operations'],p+'/operations',64,1);ops={}
    for i,op in enumerate(app['operations']):
        q=p+'/operations/'+str(i);_operation(op,q)
        if op['id'] in ops:fail(q+'/id','Duplicate operation')
        if op['origin'] not in app['origins'] or op['credential_alias'] not in app['credentials']:fail(q,'Unknown origin/credential scope','credential_scope_invalid')
        ops[op['id']]=op
    array(app['browser_targets'],p+'/browser_targets',64);targets={}
    for i,target in enumerate(app['browser_targets']):
        q=p+'/browser_targets/'+str(i);_browser(target,q)
        if target['id'] in targets:fail(q+'/id','Duplicate browser target')
        if target['credential_alias'] not in app['credentials'] or set(target['allowed_operation_ids'])-set(ops):fail(q,'Unknown target grant')
        origin=urlsplit(target['url']);origin=origin.scheme+'://'+origin.netloc
        if origin not in [v['url'] for v in app['origins'].values()]:fail(q+'/url','Target origin not reviewed')
        if any(r['origin'] not in app['origins'] for r in target['static_resources']):fail(q+'/static_resources','Unknown resource origin')
        if any(ops[oid]['credential_alias']!=target['credential_alias'] for oid in target['allowed_operation_ids']):fail(q+'/allowed_operation_ids','Target/operation credential mismatch')
        if target['request_body_template'] is not None and not any(ops[oid]['effect'] in ('mutation','publication') for oid in target['allowed_operation_ids']):fail(q+'/request_body_template','Write template requires reviewed mutation operation')
        targets[target['id']]=target
    if targets and rt['container_profile']!='browser':fail('/runtime/container_profile','Browser targets require browser runtime','runtime_mismatch')
    array(value['stages'],'/stages',8,1);names=[];paths=[];contracts=set()
    for i,stage in enumerate(value['stages']):
        p='/stages/'+str(i);exact(stage,STAGE_FIELDS,p);slug(stage['id'],p+'/id');names.append(stage['id'])
        for key in ('depends_on','credential_aliases','operations','browser_targets'):unique_strings(stage[key],p+'/'+key,64)
        participant(stage['participant'],p+'/participant')
        if stage['participant']['application_id']!=app['id']:fail(p+'/participant','Application identity mismatch')
        choice(stage['profile'],('application-client',),p+'/profile')
        text(stage['prompt'],p+'/prompt',131072)
        if not stage['credential_aliases'] or set(stage['credential_aliases'])-set(app['credentials']):fail(p+'/credential_aliases','Unknown credential grant','credential_scope_invalid')
        if set(stage['operations'])-set(ops):fail(p+'/operations','Unknown operation grant')
        if set(stage['browser_targets'])-set(targets):fail(p+'/browser_targets','Unknown browser target grant')
        for opid in stage['operations']:
            if ops[opid]['credential_alias'] not in stage['credential_aliases']:fail(p+'/operations','Operation exceeds credential scope','credential_scope_invalid')
        for alias in stage['credential_aliases']:
            if not any(ops[oid]['effect']=='identity' and ops[oid]['credential_alias']==alias for oid in stage['operations']):fail(p+'/operations','Each alias needs explicit identity grant')
        for tid in stage['browser_targets']:
            target=targets[tid]
            if target['credential_alias'] not in stage['credential_aliases'] or set(target['allowed_operation_ids'])-set(stage['operations']):fail(p+'/browser_targets','Browser target exceeds stage grants')
        limits=stage['limits'];exact(limits,{'timeout_seconds','max_turns','max_total_tokens','max_tool_calls','reporting_reserve_calls','reporting_reserve_seconds'},p+'/limits')
        for key,bound in [('timeout_seconds',3600),('max_turns',100),('max_total_tokens',10000000),('max_tool_calls',500)]:integer(limits[key],p+'/limits/'+key,1,bound)
        integer(limits['reporting_reserve_calls'],p+'/limits/reporting_reserve_calls',1,min(20,limits['max_tool_calls']-1))
        integer(limits['reporting_reserve_seconds'],p+'/limits/reporting_reserve_seconds',1,min(120,limits['timeout_seconds']-1))
        try:
            comp=validate_completion(stage['completion'],stage['participant'])
        except ContractError as exc:
            raise ContractError('Invalid stage completion contract',p+'/completion'+exc.pointer,exc.reason) from None
        if comp['id'] in contracts:fail(p+'/completion/id','Duplicate completion ID')
        contracts.add(comp['id']);paths += [comp['report_path']]+[a['path'] for a in comp['artifacts']]
        if {oid for oid in stage['operations'] if ops[oid]['effect']=='publication'} != {item['operation_id'] for item in comp['publications']}:fail(p+'/completion/publications','Every granted publication requires exactly one completion binding')
        arts={a['id']:a for a in comp['artifacts']}
        for tid in stage['browser_targets']:
            target=targets[tid]
            def template_refs(item):
                if type(item) is str:
                    match=re.fullmatch(r'\$\{artifact\.([a-z0-9-]+)\.sha256\}',item)
                    if match and match[1] not in arts:fail(p+'/browser_targets','Template artifact is undeclared')
                    match=re.fullmatch(r'\$\{input\.(value|option_id)\}',item)
                    if match and match[1] not in target['input_schema']['properties']:fail(p+'/browser_targets','Template input is undeclared')
                elif type(item) is dict:
                    for child in item.values():template_refs(child)
                elif type(item) is list:
                    for child in item:template_refs(child)
            template_refs(target['request_body_template'])
        for pub in comp['publications']:
            op=ops.get(pub['operation_id'])
            if pub['operation_id'] not in stage['operations'] or op['effect']!='publication':fail(p+'/completion/publications','Ungrantable publication')
            expected={k:v for k,v in pub.items() if k!='operation_id'};expected['payload_source']='declared_artifact'
            if op['publication']!=expected:fail(p+'/completion/publications','Publication binding conflict')
        for page in comp['pagination']:
            op=ops.get(page['operation_id'])
            if page['operation_id'] not in stage['operations'] or op['pagination'] is None:fail(p+'/completion/pagination','Pagination operation not granted')
        array(stage['input_artifacts'],p+'/input_artifacts',64)
        for j,item in enumerate(stage['input_artifacts']):
            q=p+'/input_artifacts/'+str(j);exact(item,{'stage_id','artifact_id'},q)
            slug(item['stage_id'],q+'/stage_id');slug(item['artifact_id'],q+'/artifact_id')
        if len({(x['stage_id'],x['artifact_id']) for x in stage['input_artifacts']})!=len(stage['input_artifacts']):fail(p+'/input_artifacts','Duplicate read grant')
        read_ids=[item['artifact_id'] for item in stage['input_artifacts']]
        if len(set(read_ids))!=len(read_ids) or set(read_ids)&set(arts):fail(p+'/input_artifacts','Artifact IDs must resolve to exactly one stage-local read or output')
    if len(set(names))!=len(names):
        duplicate=next(i for i,n in enumerate(names) if n in names[:i])
        fail('/stages/'+str(duplicate)+'/id','Duplicate stage ID','dependency_invalid')
    seen_paths=[]
    for i,stage in enumerate(value['stages']):
        for path in [stage['completion']['report_path']]+[a['path'] for a in stage['completion']['artifacts']]:
            _unique_paths(seen_paths+[path],'/stages/'+str(i)+'/completion');seen_paths.append(path)
    order=stage_order(value['stages'])
    stages={s['id']:s for s in value['stages']}
    def ancestors(name):
        result=set()
        for dep in stages[name]['depends_on']:result.add(dep);result.update(ancestors(dep))
        return result
    for i,stage in enumerate(value['stages']):
        for item in stage['input_artifacts']:
            producer=stages.get(item['stage_id'])
            if not producer or item['stage_id'] not in ancestors(stage['id']) or item['artifact_id'] not in {a['id'] for a in producer['completion']['artifacts']}:fail('/stages/'+str(i)+'/input_artifacts','Read grant requires declared ancestor producer','dependency_invalid')
    array(value['checks'],'/checks',20,1);checknames=[]
    for i,check in enumerate(value['checks']):
        p='/checks/'+str(i)
        if type(check) is not dict:fail(p,'Check object required')
        unknown=set(check)-{'id','argv','cwd','timeout_seconds','network','scorer'}
        missing={'id','argv','timeout_seconds','network'}-set(check)
        if unknown or missing:fail(p+'/'+escape(sorted(unknown or missing)[0]),'Unexpected or missing check field')
        slug(check['id'],p+'/id');checknames.append(check['id'])
        array(check['argv'],p+'/argv',64,1)
        for j,arg in enumerate(check['argv']):text(arg,p+'/argv/'+str(j),4096)
        if check.get('cwd','.')!='.':relative(check['cwd'],p+'/cwd')
        integer(check['timeout_seconds'],p+'/timeout_seconds',1,3600)
        choice(check['network'],('none',),p+'/network')
        if 'scorer' in check:_scorer(check['scorer'],p+'/scorer',frozen)
        elif rt['inference_owner']=='experiment_variant':fail(p+'/scorer','Experiments require independent structured scorer')
    if len(set(names+checknames))!=len(names+checknames):
        duplicate=next(i for i,n in enumerate(checknames) if n in names+checknames[:i])
        fail('/checks/'+str(duplicate)+'/id','Stage/check IDs must be globally unique')
    return value


def stage_order(stages):
    names=[s['id'] for s in stages];remaining=set(names);result=[]
    for i,s in enumerate(stages):
        if s['id'] in s['depends_on'] or set(s['depends_on'])-set(names):fail('/stages/'+str(i)+'/depends_on','Missing/self dependency','dependency_invalid')
    while remaining:
        ready=[s['id'] for s in stages if s['id'] in remaining and set(s['depends_on'])<=set(result)]
        if not ready:fail('/stages','Dependency cycle','dependency_invalid')
        # One at a time preserves the declaration-order tie break after each node.
        result.append(ready[0]);remaining.remove(ready[0])
    return result


def validate_source(value):
    safe_json(value);_source(value);return copy.deepcopy(value)


def validate_ir(value):
    safe_json(value)
    exact(value,(SOURCE_FIELDS-{'document_type'})|{'document_type','compiler_contract','input_hashes','plan_sha256'},'')
    choice(value['schema'],(1,),'/schema');choice(value['document_type'],('application_execution_plan',),'/document_type')
    cc=value['compiler_contract'];exact(cc,{'id','revision','sha256'},'/compiler_contract')
    choice(cc['id'],('application-plan-v1',),'/compiler_contract/id');choice(cc['revision'],(1,),'/compiler_contract/revision');sha256(cc['sha256'],'/compiler_contract/sha256')
    exact(value['input_hashes'],HASH_FIELDS,'/input_hashes')
    for key,item in value['input_hashes'].items():sha256(item,'/input_hashes/'+key)
    source={k:copy.deepcopy(value[k]) for k in SOURCE_FIELDS};source['document_type']='application_plan_source'
    if type(value['runtime']) is not dict or 'resources' not in value['runtime']:fail('/runtime','Runtime object required')
    if value['runtime']['resources'] != resources.validate_policy(value['runtime']['resources']):fail('/runtime/resources','Final IR must materialize complete resource defaults')
    for i,stage in enumerate(value['stages']):
        p='/stages/'+str(i)
        exact(stage,(STAGE_FIELDS-{'prompt'})|{'effective_prompt','prompt_admission','tools','profile_binding','inference_binding','resolved_operations','tool_schemas'},p)
        text(stage['effective_prompt'],p+'/effective_prompt',131072)
        unique_strings(stage['tools'],p+'/tools',6,1,False)
        expected={'app_api','artifact_read','artifact_write','report_write','budget_status'}
        if stage['browser_targets']:expected.add('app_browser')
        if set(stage['tools'])!=expected:fail(p+'/tools','Restrictive tool set mismatch')
        if stage['tool_schemas']!=prompt_contract.tool_schemas(stage):fail(p+'/tool_schemas','Frozen native schema differs from reviewed representation')
        profile=stage['profile_binding'];exact(profile,{'id','pi_release','sha256','assets'},p+'/profile_binding')
        choice(profile['id'],('application-client',),p+'/profile_binding/id');choice(profile['pi_release'],(value['runtime']['pi_release'],),p+'/profile_binding/pi_release');sha256(profile['sha256'],p+'/profile_binding/sha256')
        if type(profile['assets']) is not dict or not 1<=len(profile['assets'])<=16:fail(p+'/profile_binding/assets','Bounded asset identity map required')
        for target,h in profile['assets'].items():relative(target,p+'/profile_binding/assets');sha256(h,p+'/profile_binding/assets/'+escape(target))
        binding=stage['inference_binding'];q=p+'/inference_binding'
        exact(binding,{'kind','configuration_sha256','context_window','max_tokens','input_modalities','selection'},q)
        choice(binding['kind'],('legacy','indexed'),q+'/kind');sha256(binding['configuration_sha256'],q+'/configuration_sha256')
        integer(binding['context_window'],q+'/context_window',2049,100000000);integer(binding['max_tokens'],q+'/max_tokens',1,binding['context_window']-1)
        if binding['input_modalities']!=['text']:fail(q+'/input_modalities','Reviewed text input only')
        exact(binding['selection'],{'owner','id'},q+'/selection');choice(binding['selection']['owner'],(value['runtime']['inference_owner'],),q+'/selection/owner');text(binding['selection']['id'],q+'/selection/id',128)
        ad=stage['prompt_admission'];q=p+'/prompt_admission'
        exact(ad,{'method','prompt_bytes','tool_schema_bytes','framing_upper_bound','reply_tokens','history_reserve_tokens','context_window','total_upper_bound'},q)
        choice(ad['method'],('conservative_bytes',),q+'/method')
        for k in set(ad)-{'method'}:integer(ad[k],q+'/'+k,0,100000000)
        if (ad['tool_schema_bytes']<len(canonical(stage['tool_schemas'])) or ad['framing_upper_bound']<=0 or ad['prompt_bytes']!=len(stage['effective_prompt'].encode()) or ad['reply_tokens']!=binding['max_tokens'] or ad['context_window']!=binding['context_window'] or ad['history_reserve_tokens']<2048 or ad['total_upper_bound']!=sum(ad[k] for k in ('prompt_bytes','tool_schema_bytes','framing_upper_bound','reply_tokens','history_reserve_tokens')) or ad['total_upper_bound']>ad['context_window']):fail(q,'Prompt admission proof mismatch')
        if stage['resolved_operations']!=[op for op in value['application']['operations'] if op['id'] in stage['operations']]:fail(p+'/resolved_operations','Operation materialization mismatch')
        source['stages'][i]={k:copy.deepcopy(stage[k]) for k in STAGE_FIELDS if k!='prompt'}
        source['stages'][i]['prompt']=stage['effective_prompt']
    _source(source,True)
    if [s['id'] for s in value['stages']]!=stage_order(value['stages']):fail('/stages','IR must use stable dependency order')
    sha256(value['plan_sha256'],'/plan_sha256')
    if value['plan_sha256']!=digest({k:v for k,v in value.items() if k!='plan_sha256'}):fail('/plan_sha256','IR identity mismatch')
    return copy.deepcopy(value)


def validate_completion(value, participant=None):
    from application_documents import validate_completion as validate
    return validate(value,participant)


def validate_report(value):
    from application_documents import validate_report as validate
    return validate(value)


def validate_receipt(value):
    from application_documents import validate_receipt as validate
    return validate(value)


def _bounded_errors(function):
    @wraps(function)
    def checked(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except ContractError:
            raise
        except (KeyError, TypeError, ValueError, IndexError, RecursionError, OverflowError):
            raise ContractError('Malformed contract structure') from None
    return checked


for _validator_name in ('validate_source','validate_ir','validate_operation',
                        'validate_completion','validate_report','validate_receipt','validate_value'):
    globals()[_validator_name] = _bounded_errors(globals()[_validator_name])
