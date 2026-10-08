"""One explicit reviewed integration contract; never discover plugins from projects/home."""
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

ROOT=Path(__file__).resolve().parents[1]
TARGETS={'fixture-lookup.mjs','fixtures.json','config.json','instructions.md'}
BUILTIN_TOOLS={'read','write','edit','bash','grep','find','ls'}

class ProfileError(ValueError):pass


def builtin():
    return {'schema':1,'document_type':'agent_profile','id':'builtin','kind':'builtin','components':[],
            'tools':[],'required_tools':[],'assets':[],'service_endpoints':[]}


def read_asset(path,max_bytes=1024*1024):
    path=Path(path).absolute()
    parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);os.close(parent);parent=child
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        with os.fdopen(fd,'rb') as f:
            info=os.fstat(f.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise ProfileError('Profile assets must be regular non-linked files')
            body=f.read(max_bytes+1)
        if len(body)>max_bytes:raise ProfileError('Profile asset exceeded its bound')
        return body
    finally:os.close(parent)


def identity(profile):
    value=copy.deepcopy(profile)
    for asset in value['assets']:asset.pop('source',None)
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def validate(value,base):
    required={'schema','document_type','id','kind','components','tools','required_tools','assets','service_endpoints'}
    if not isinstance(value,dict) or set(value)!=required or type(value['schema']) is not int or value['schema']!=1 or value['document_type']!='agent_profile':raise ProfileError('Agent profile schema 1 with exact fields required')
    if value['kind']=='builtin':
        if value!=builtin():raise ProfileError('Built-in profile must be explicitly empty')
        return copy.deepcopy(value)
    if value['kind']!='fixture-lookup' or value['id']!='fixture-lookup':raise ProfileError('Unsupported integration kind/id; only reviewed fixture-lookup is supported')
    if value['components']!=[{'id':'fixture-lookup','kind':'pi-extension','version':'1','pi_release':'0.87.1','entrypoint':'fixture-lookup.mjs'}]:raise ProfileError('Exact reviewed component/release/entrypoint required')
    if value['tools']!=['fixture_lookup'] or value['required_tools']!=['fixture_lookup']:raise ProfileError('Declare only fixture_lookup and require its successful use')
    if value['service_endpoints']!=[]:raise ProfileError('This integration needs no service endpoint or additional network privilege')
    if not isinstance(value['assets'],list) or len(value['assets'])!=4:raise ProfileError('Declare exactly four reviewed profile assets')
    base=Path(base).resolve();assets=[];bodies={};seen=set()
    for asset in value['assets']:
        if not isinstance(asset,dict) or set(asset)!={'source','target','sha256'}:raise ProfileError('Profile asset requires source/target/sha256')
        for field in ('source','target'):
            name=asset[field]
            if not isinstance(name,str) or not name or '\\' in name or '\0' in name or PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts:raise ProfileError('Escaping profile asset path rejected')
        if asset['target'] not in TARGETS or asset['target'] in seen:raise ProfileError('Unknown/duplicate profile target')
        if not isinstance(asset['sha256'],str) or not re.fullmatch('[a-f0-9]{64}',asset['sha256']):raise ProfileError('Explicit SHA-256 required')
        source=base/asset['source'];body=read_asset(source)
        if hashlib.sha256(body).hexdigest()!=asset['sha256']:raise ProfileError('Profile asset hash mismatch: '+asset['target'])
        assets.append({**asset,'source':str(source)});bodies[asset['target']]=body;seen.add(asset['target'])
    if seen!=TARGETS:raise ProfileError('Required profile asset missing')
    canonical=read_asset(ROOT/'assets/profiles/fixture-lookup/fixture-lookup.mjs')
    if bodies['fixture-lookup.mjs']!=canonical:raise ProfileError('Only the reviewed bundled extension implementation is supported; arbitrary JavaScript is not a profile')
    config=json.loads(bodies['config.json'])
    if not isinstance(config,dict) or config!={'schema':1,'table':'fixtures.json','max_result_bytes':4096} or type(config['schema']) is not int or type(config['max_result_bytes']) is not int:raise ProfileError('Unsupported fixture configuration/privileges')
    table=json.loads(bodies['fixtures.json'])
    if not isinstance(table,dict) or not 1<=len(table)<=128 or any(not re.fullmatch('[a-z0-9-]{1,64}',k) for k in table):raise ProfileError('Bounded exact-key fixture object required')
    for fixture_value in table.values():
        encoded=json.dumps(fixture_value,allow_nan=False).encode()
        if len(encoded)>3800:raise ProfileError('Fixture value exceeds result budget')
    prompt=bodies['instructions.md'].decode('utf8')
    if not prompt.strip() or len(bodies['instructions.md'])>8192:raise ProfileError('Bounded nonempty profile instructions required')
    # The caller's declaration is copied, not normalized from child observations.
    return {'schema':1,'document_type':'agent_profile','id':'fixture-lookup','kind':'fixture-lookup',
            'components':[{'id':'fixture-lookup','kind':'pi-extension','version':'1','pi_release':'0.87.1','entrypoint':'fixture-lookup.mjs'}],
            'tools':['fixture_lookup'],'required_tools':['fixture_lookup'],'assets':assets,'service_endpoints':[]}


def load(path):
    path=Path(path).absolute()
    if path.is_symlink():raise ProfileError('Linked profile declaration rejected')
    path=path.parent.resolve()/path.name
    return validate(json.loads(read_asset(path)),path.parent)


def toolset(task,profile):
    allowed=BUILTIN_TOOLS|set(profile['tools'])
    if set(task.get('tools',[]))-allowed or set(task.get('require_tools',[]))-set(task.get('tools',[])):raise ProfileError('Undeclared custom tool or missing allowlist entry')
    if profile['kind']=='builtin' and (set(task.get('tools',[]))-BUILTIN_TOOLS):raise ProfileError('Built-in profile cannot use custom tools')
    return allowed


def freeze(profile,destination):
    destination=Path(destination).absolute();destination=destination.parent.resolve()/destination.name
    if destination.exists() or destination.is_symlink():raise ProfileError('Profile staging destination must be new')
    destination.mkdir(parents=True)
    frozen=copy.deepcopy(profile)
    for asset in frozen['assets']:
        body=read_asset(asset['source'])
        if hashlib.sha256(body).hexdigest()!=asset['sha256']:raise ProfileError('Profile changed before staging')
        target=destination/asset['target'];target.write_bytes(body);target.chmod(0o444);asset['source']=asset['target']
    (destination/'profile.json').write_text(json.dumps(frozen,indent=2)+'\n');(destination/'profile.json').chmod(0o444)
    return {'root':str(destination),'profile':frozen,'sha256':identity(frozen)}


def staged(receipt):
    root=Path(receipt['root']);profile=load(root/'profile.json')
    if identity(profile)!=receipt['sha256']:raise ProfileError('Staged profile identity changed')
    expected={a['target'] for a in profile['assets']}|{'profile.json'}
    if {p.name for p in root.iterdir()}!=expected:raise ProfileError('Staged profile file set changed')
    return profile


def apply(plan,profile):
    out=copy.deepcopy(plan)
    for task in out['agents']:
        for name in profile['tools']:
            if name not in task['tools']:task['tools'].append(name)
        for name in profile['required_tools']:
            if name not in task['require_tools']:task['require_tools'].append(name)
        toolset(task,profile)
    return out


def observed(path,context):
    """Receipts never grant authority; require actual registered/active and paired successful use."""
    events=[]
    for line in Path(path).read_bytes().split(b'\n'):
        if not line.strip():continue
        try:
            event=json.loads(line)
            if isinstance(event,dict):events.append(event)
        except (ValueError,UnicodeDecodeError):continue
    receipts=[e['entry'].get('data') for e in events if e.get('type')=='entry_appended' and isinstance(e.get('entry'),dict) and e['entry'].get('customType')=='pi_lab_profile']
    errors=[];profile=context['profile'];fields=('run_id','attempt_id','stage_id','segment_id','profile_sha256')
    valid=[r for r in receipts if isinstance(r,dict) and all(r.get(k)==context[k] for k in fields)]
    if len(valid)!=1:errors.append('Missing/duplicate/unrelated profile registration receipt')
    else:
        r=valid[0]
        if r.get('active_tools')!=context['allowed_tools']:errors.append('Effective active tool set differs from declared allowlist')
        if profile['kind']=='builtin' and 'fixture_lookup' in r.get('registered_tools',[]):errors.append('Built-in profile registered custom fixture tool')
        if not all(t in r.get('registered_tools',[]) for t in profile['tools']):errors.append('Declared custom tool never registered')
        if r.get('assets_sha256')!={a['target']:a['sha256'] for a in profile['assets']}:errors.append('Loaded asset hashes differ')
    registration_ok=bool(valid) and not errors
    requested=profile['tools'];calls=[];declared={}
    for event in events:
        message=event.get('message')
        if event.get('type')=='message_end' and isinstance(message,dict) and message.get('role')=='assistant':
            for block in message.get('content',[]) if isinstance(message.get('content'),list) else []:
                if isinstance(block,dict) and block.get('type')=='toolCall':declared[block.get('id')]=block
        if event.get('type')=='tool_execution_end' and event.get('toolName') in requested and event.get('isError') is False:
            block=declared.get(event.get('toolCallId'));result=event.get('result')
            details=result.get('details',{}) if isinstance(result,dict) else {}
            table=json.loads(read_asset(Path(context['asset_root'])/'fixtures.json'))
            table_sha=next(a['sha256'] for a in profile['assets'] if a['target']=='fixtures.json')
            arguments=block.get('arguments') if block else None
            key=arguments.get('key') if isinstance(arguments,dict) else None
            if not isinstance(key,str) or not re.fullmatch('[a-z0-9-]{1,64}',key) or not block or block.get('name')!='fixture_lookup' or not isinstance(details,dict) or details.get('component_id')!='fixture-lookup' or details.get('table_sha256')!=table_sha or details.get('key')!=key or details.get('found') is not (key in table) or details.get('value')!=table.get(key):errors.append('Custom tool arguments/result do not match frozen fixture')
            else:calls.append({'tool_call_id':event['toolCallId'],'tool':'fixture_lookup','key':key,'table_sha256':table_sha})
    if requested and not calls:errors.append('No observed successful declared integration use')
    return {'schema':1,'profile_id':profile['id'],'profile_sha256':context['profile_sha256'],'loading':'observed' if registration_ok else 'unverified','use':'observed' if calls else 'not_requested' if not requested else 'unverified',
            'successful_calls':calls,'errors':errors,'scope':'observed registration/active tools/paired results; no server or authority attestation'}
