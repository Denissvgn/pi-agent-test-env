"""Private, durable launch accounting for the fixed application qualification.

This is maintainer instrumentation, not an installed runtime or a sandbox. It
forwards reviewed calls unchanged and never serializes argv, env or bootstrap
stdin. Physical absence and sensitive cleanup remain distinct facts.
"""
import calendar
import contextlib
import datetime
import copy
import fcntl
import hashlib
import inspect
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import threading
import time
import uuid

import application_timing as timing

LIMITS={'global_seconds':14400,'cleanup_reserve_seconds':30,'container_launch_attempts':240,
        'live':4,'participant_segments':24}
ROLES={'fixture','scripted-inference','probe','boundary','preflight','application-helper','participant','scorer','browser-check'}
WORKER_ROLES={'probe':'probe','boundary':'boundary','preflight':'preflight','agent':'participant','check':'scorer','browser':'browser-check'}
EXTERNAL={'fixture':'/opt/pi-skill/examples/authenticated-application/fixture.py',
          'scripted-inference':'/qualification/application_scripted.py'}
LABEL='org.pi-agent-test-env.launch';REGISTRY_LABEL='org.pi-agent-test-env.registry'
MAX_BYTES=2*1024*1024
_PATCH_LOCK=threading.Lock()


class LaunchError(ValueError):
    def __init__(self,reason='qualification_launch_denied'):
        self.reason=reason;super().__init__(reason)


def _deny(reason='qualification_launch_denied'):raise LaunchError(reason)
def _json(value):return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()
def _digest(value):return hashlib.sha256(_json(value)).hexdigest()
def _exact(value,fields):
    if type(value) is not dict or set(value)!=set(fields):_deny('qualification_contract_invalid')
def _integer(value,minimum,maximum):
    if type(value) is not int or not minimum<=value<=maximum:_deny('qualification_contract_invalid')
def _slug(value):
    if type(value) is not str or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9.-]{0,127}',value):_deny('qualification_contract_invalid')
def _sha(value):
    if type(value) is not str or not re.fullmatch('[a-f0-9]{64}',value):_deny('qualification_contract_invalid')
def _uuid(value):
    try:
        if type(value) is not str or str(uuid.UUID(value))!=value:_deny()
    except ValueError:_deny('qualification_contract_invalid')
def _number(value):
    if type(value) not in (int,float) or not math.isfinite(value):_deny('qualification_clock_invalid')
    return value


def _intent_identity(record):
    return _digest({key:value for key,value in record.items() if key not in ('status','container_id','qualification_service_cleanup','qualification_preworker_cleanup')})


def _role_weight(manifest,cell,role):
    if 'diagnostic' in manifest:return {'cpu_millis':1000,'memory_mib':512,'pids_limit':128}
    browser=cell['image_id']==manifest['images']['browser-'+cell['release']]['id']
    if role in EXTERNAL:return {'cpu_millis':250,'memory_mib':128,'pids_limit':64}
    if role=='application-helper':return {'cpu_millis':2000,'memory_mib':2048,'pids_limit':512} if browser else {'cpu_millis':1000,'memory_mib':512,'pids_limit':128}
    return {'cpu_millis':2000,'memory_mib':2048,'pids_limit':512} if browser and cell['group']=='N01' else {'cpu_millis':1000,'memory_mib':1024,'pids_limit':256}


def _mounts(options):
    result=[];targets=set()
    for value in options.get('--mount',[]):
        fields={};flags=[]
        for part in value.split(','):
            if '=' in part:
                key,item=part.split('=',1)
                if key in fields:_deny('qualification_mount_changed')
                fields[key]=item
            else:flags.append(part)
        if (set(fields)!={'type','src','dst','bind-recursive'} or fields['type']!='bind' or fields['bind-recursive']!='disabled'
                or flags not in ([],['readonly']) or fields['dst'] in targets):_deny('qualification_mount_changed')
        fd=_dir(Path(fields['src']).absolute(),False);os.close(fd)
        targets.add(fields['dst']);result.append({'source':str(Path(fields['src']).absolute()),'target':fields['dst'],'rw':not flags})
    return result


def validate_manifest(value):
    if type(value) is dict and 'settlement_diagnostic' in value:
        import application_settlement_controller
        return application_settlement_controller.validate_launch_manifest(value)
    if type(value) is dict and 'diagnostic' in value:
        import application_followup
        return application_followup.validate_diagnostic_manifest(value)
    fixture_browser = type(value) is dict and 'browser_fixture_followup' in value
    browser = type(value) is dict and ('browser_followup' in value or fixture_browser)
    browser_key='browser_fixture_followup' if fixture_browser else 'browser_followup'
    retained = type(value) is dict and 'retained_requalification' in value
    _exact(value,{'qualification_id','images','cells','limits','planned_container_launches'}|({'predecessor'} if 'predecessor' in value else set())|({'campaign_boundary'} if 'campaign_boundary' in value else set())|({'campaign_amendment'} if 'campaign_amendment' in value else set())|({'retained_requalification'} if retained else set())|({browser_key} if browser else set()))
    if browser:
        if set(value)&{'predecessor','campaign_boundary','campaign_amendment','retained_requalification'}:_deny('qualification_contract_invalid')
        if fixture_browser:
            if 'browser_followup' in value:_deny('qualification_contract_invalid')
            import application_browser_fixture_followup as browser_selection
        else:
            import application_browser_followup as browser_selection
        browser_selection.validate_marker(value[browser_key])
    if retained:
        if set(value)&{'predecessor','campaign_boundary','campaign_amendment'}:_deny('qualification_contract_invalid')
        import application_retained
        application_retained.validate_marker(value['retained_requalification'])
    if 'predecessor' in value:_predecessor_shape(value['predecessor'])
    if 'campaign_boundary' in value:
        if 'predecessor' not in value:_deny('qualification_contract_invalid')
        _exact(value['campaign_boundary'],{'path','sha256'});_canonical_root(value['campaign_boundary']['path']);_sha(value['campaign_boundary']['sha256'])
    _uuid(value['qualification_id'])
    if value['limits']!=effective_limits(value) or any(type(value['limits'].get(k)) is not int for k in LIMITS):_deny('qualification_contract_invalid')
    planned_max=42 if browser else 140 if retained else 186
    if type(value['planned_container_launches']) is not int or value['planned_container_launches']!=planned_max:_deny('qualification_contract_invalid')
    keys={profile+'-'+release for profile in ('core','browser') for release in ('0.87.1','1.2.0')}
    _exact(value['images'],keys);images=set()
    for name,image in value['images'].items():
        if type(image) is not dict or set(image)!={'id','platform','capabilities'}:_deny('qualification_contract_invalid')
        if type(image['id']) is not str or not re.fullmatch('sha256:[a-f0-9]{64}',image['id']):_deny('qualification_contract_invalid')
        if image['platform']!='linux/arm64' or type(image['capabilities']) is not dict or image['capabilities'].get('pi')!=name.split('-',1)[1]:_deny('qualification_contract_invalid')
        images.add(image['id'])
    if len(images)!=4 or type(value['cells']) is not list or not 1<=len(value['cells'])<=186:_deny('qualification_contract_invalid')
    ids=set();planned=segments=0
    for cell in value['cells']:
        _exact(cell,{'id','group','release','image_id','allowed_images','role_limits','container_launches_max','participant_segments_max'})
        _slug(cell['id'])
        if cell['group'] not in ('N01','N02','N03','N04'):_deny('qualification_contract_invalid')
        if cell['id'] in ids or cell['release'] not in ('0.87.1','1.2.0'):_deny('qualification_contract_invalid')
        ids.add(cell['id']);allowed=[image['id'] for name,image in value['images'].items() if name.endswith('-'+cell['release'])]
        if (type(cell['allowed_images']) is not list or not cell['allowed_images'] or len(set(cell['allowed_images']))!=len(cell['allowed_images'])
                or set(cell['allowed_images'])-set(allowed) or cell['image_id'] not in cell['allowed_images']):_deny('qualification_contract_invalid')
        roles=cell['role_limits']
        if type(roles) is not dict or not roles or set(roles)-ROLES:_deny('qualification_contract_invalid')
        for count in roles.values():_integer(count,1,186)
        _integer(cell['container_launches_max'],1,186);_integer(cell['participant_segments_max'],0,24)
        if sum(roles.values())!=cell['container_launches_max'] or roles.get('participant',0)!=cell['participant_segments_max']:_deny('qualification_contract_invalid')
        planned+=cell['container_launches_max'];segments+=cell['participant_segments_max']
    if planned!=planned_max or segments>(6 if browser else 19 if retained else 24):_deny('qualification_contract_invalid')
    if retained:
        if ids!=set(application_retained.FRESH_IDS) or segments!=19:_deny('qualification_contract_invalid')
        for cell in value['cells']:
            group,release=cell['group'],cell['release']
            if group not in ('N02','N03','N04') or not cell['id'].startswith(group+'-'+release+'-'):_deny('qualification_contract_invalid')
            roles={'fixture':1,'probe':1,'boundary':1,'preflight':1,'application-helper':1,'participant':1,'scorer':1}
            if group=='N02':roles['scripted-inference']=1
            profile='browser' if group=='N04' else 'core'
            image=value['images'][profile+'-'+release]['id']
            allowed=list(dict.fromkeys([image,value['images']['core-'+release]['id']]))
            if (cell['role_limits']!=roles or cell['image_id']!=image or cell['allowed_images']!=allowed
                    or cell['container_launches_max']!=sum(roles.values()) or cell['participant_segments_max']!=1):_deny('qualification_contract_invalid')
    if browser:
        if ids!=set(browser_selection.FRESH_IDS) or segments!=6:_deny('qualification_contract_invalid')
        for cell in value['cells']:
            roles=dict.fromkeys(('fixture','probe','boundary','preflight','application-helper','participant','scorer'),1)
            image=value['images']['browser-'+cell['release']]['id']
            allowed=list(dict.fromkeys([image,value['images']['core-'+cell['release']]['id']]))
            if (cell['group']!='N04' or cell['role_limits']!=roles or cell['image_id']!=image
                    or cell['allowed_images']!=allowed or cell['container_launches_max']!=7
                    or cell['participant_segments_max']!=1):_deny('qualification_contract_invalid')
    return copy.deepcopy(value)


def effective_limits(manifest):
    if 'settlement_diagnostic' in manifest:
        import application_settlement_controller
        application_settlement_controller.validate_launch_manifest(manifest)
        return application_settlement_controller.effective_limits()
    if 'browser_fixture_followup' in manifest:
        if set(manifest)&{'browser_followup','predecessor','campaign_boundary','campaign_amendment','retained_requalification','diagnostic'}:_deny('qualification_contract_invalid')
        import application_browser_fixture_followup
        application_browser_fixture_followup.validate_marker(manifest['browser_fixture_followup'])
        return dict(application_browser_fixture_followup.LIMITS)
    if 'browser_followup' in manifest:
        if set(manifest)&{'predecessor','campaign_boundary','campaign_amendment','retained_requalification','diagnostic'}:_deny('qualification_contract_invalid')
        import application_browser_followup
        application_browser_followup.validate_marker(manifest['browser_followup'])
        return dict(application_browser_followup.LIMITS)
    if 'retained_requalification' in manifest:
        if set(manifest)&{'predecessor','campaign_boundary','campaign_amendment','diagnostic'}:_deny('qualification_contract_invalid')
        import application_retained
        application_retained.validate_marker(manifest['retained_requalification'])
        return dict(application_retained.LIMITS)
    if 'campaign_amendment' not in manifest:return dict(LIMITS)
    if 'predecessor' not in manifest or 'campaign_boundary' not in manifest:_deny('qualification_contract_invalid')
    module=amendment_module(manifest['campaign_amendment'])
    if manifest['campaign_boundary']!=module.BOUNDARY_REFERENCE:_deny('qualification_contract_invalid')
    return module.effective_limits(manifest['campaign_amendment'])


def amendment_module(reference):
    """Select only one exact retained human authority; never import from input."""
    import application_amendment
    if reference=={'path':str(application_amendment.AUTHORIZATION_PATH),'sha256':application_amendment.AUTHORIZATION_SHA256}:
        application_amendment.effective_limits(reference)
        return application_amendment
    import application_successor
    if reference=={'path':str(application_successor.AUTHORIZATION_PATH),'sha256':application_successor.AUTHORIZATION_SHA256}:
        application_successor.effective_limits(reference)
        return application_successor
    import application_followup
    if reference=={'path':str(application_followup.AUTHORIZATION_PATH),'sha256':application_followup.AUTHORIZATION_SHA256}:
        application_followup.effective_limits(reference)
        return application_followup
    import application_requalification
    if reference=={'path':str(application_requalification.AUTHORIZATION_PATH),'sha256':application_requalification.AUTHORIZATION_SHA256}:
        application_requalification.effective_limits(reference)
        return application_requalification
    import application_matrix13
    if reference=={'path':str(application_matrix13.AUTHORIZATION_PATH),'sha256':application_matrix13.AUTHORIZATION_SHA256}:
        application_matrix13.effective_limits(reference)
        return application_matrix13
    import application_matrix14
    if reference=={'path':str(application_matrix14.AUTHORIZATION_PATH),'sha256':application_matrix14.AUTHORIZATION_SHA256}:
        application_matrix14.effective_limits(reference)
        return application_matrix14
    import application_matrix15
    if reference=={'path':str(application_matrix15.AUTHORIZATION_PATH),'sha256':application_matrix15.AUTHORIZATION_SHA256}:
        application_matrix15.effective_limits(reference)
        return application_matrix15
    import application_matrix16
    if reference=={'path':str(application_matrix16.AUTHORIZATION_PATH),'sha256':application_matrix16.AUTHORIZATION_SHA256}:
        application_matrix16.effective_limits(reference)
        return application_matrix16
    import application_matrix17
    if reference=={'path':str(application_matrix17.AUTHORIZATION_PATH),'sha256':application_matrix17.AUTHORIZATION_SHA256}:
        application_matrix17.effective_limits(reference)
        return application_matrix17
    import application_matrix18
    if reference=={'path':str(application_matrix18.AUTHORIZATION_PATH),'sha256':application_matrix18.AUTHORIZATION_SHA256}:
        application_matrix18.effective_limits(reference)
        return application_matrix18
    import application_matrix19
    if reference=={'path':str(application_matrix19.AUTHORIZATION_PATH),'sha256':application_matrix19.AUTHORIZATION_SHA256}:
        application_matrix19.effective_limits(reference)
        return application_matrix19
    import application_matrix20
    if application_matrix20.accepts(reference):
        application_matrix20.effective_limits(reference)
        return application_matrix20
    _deny('qualification_matrix_amendment_invalid')


def maximum_origins(reference=None):
    if reference is None:return 8
    return {'application_amendment':9,'application_successor':10,'application_followup':11,'application_requalification':12,'application_matrix13':13,'application_matrix14':14,'application_matrix15':15,'application_matrix16':16,'application_matrix17':17,'application_matrix18':18,'application_matrix19':19,'application_matrix20':20}[amendment_module(reference).__name__]


def _dir(path,private=True):
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts:_deny('qualification_state_invalid')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
        info=os.fstat(fd)
        if private and (info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077):_deny('qualification_state_invalid')
        return fd
    except BaseException:os.close(fd);raise


def _file(root,name,flags):
    fd=os.open(name,flags|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=root);st=os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)&0o077 or st.st_size>MAX_BYTES:
        os.close(fd);_deny('qualification_state_invalid')
    return fd


def _read(root,name):
    with os.fdopen(_file(root,name,os.O_RDONLY),'rb') as stream:
        def pairs(rows):
            result={}
            for key,value in rows:
                if key in result:_deny('qualification_state_invalid')
                result[key]=value
            return result
        return json.loads(stream.read(MAX_BYTES+1),object_pairs_hook=pairs,parse_constant=lambda _: _deny('qualification_state_invalid'))


def _write(root,name,value):
    body=_json(value)
    if len(body)>MAX_BYTES:_deny('qualification_state_invalid')
    temporary='.'+name+'-'+uuid.uuid4().hex
    try:
        with os.fdopen(_file(root,temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL),'wb') as stream:
            stream.write(body);stream.flush();os.fsync(stream.fileno())
        os.rename(temporary,name,src_dir_fd=root,dst_dir_fd=root);os.fsync(root)
    finally:
        try:os.unlink(temporary,dir_fd=root)
        except FileNotFoundError:pass


def _hard_admission(*,attempts,live,segments,participant,now,deadline,limits=None):
    """Fixed hard-cap decision; tested directly independently of tighter roles."""
    limits=LIMITS if limits is None else limits
    if now>=deadline-limits['cleanup_reserve_seconds']:_deny('qualification_deadline')
    if attempts>=limits['container_launch_attempts']:_deny('qualification_launch_limit')
    if live>=limits['live']:_deny('qualification_live_limit')
    if participant and segments>=limits['participant_segments']:_deny('qualification_segment_limit')


def _canonical_root(value):
    if (type(value) is not str or not value.startswith('/') or value.startswith('//') or value=='/' or len(value)>4096
            or any(ord(ch)<32 or ord(ch)==127 for ch in value) or '..' in Path(value).parts or str(Path(value))!=value):
        _deny('qualification_predecessor_invalid')
    return Path(value)


def _predecessor_shape(value):
    _exact(value,{'schema','root','manifest_sha256','ledger_sha256','state_sha256','cleanup_receipts'})
    if type(value['schema']) is not int or value['schema']!=1:_deny('qualification_predecessor_invalid')
    _canonical_root(value['root'])
    for key in ('manifest_sha256','ledger_sha256','state_sha256'):_sha(value[key])
    receipts=value['cleanup_receipts']
    if type(receipts) is not list or not 1<=len(receipts)<=241:_deny('qualification_predecessor_invalid')
    paths=set()
    for item in receipts:
        _exact(item,{'path','sha256'});_sha(item['sha256'])
        if (type(item['path']) is not str or not Path(item['path']).is_absolute() or '..' in Path(item['path']).parts
                or item['path'] in paths):_deny('qualification_predecessor_invalid')
        paths.add(item['path'])
    return value


def _bound_json(path,expected=None):
    """Read one immutable, bounded owner-private file without following aliases."""
    path=Path(path);parent=_dir(path.parent,False)
    try:
        fd=_file(parent,path.name,os.O_RDONLY)
        with os.fdopen(fd,'rb') as stream:
            before=os.fstat(stream.fileno());body=stream.read(MAX_BYTES+1);after=os.fstat(stream.fileno())
            named=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        identity=lambda st:(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
        if len(body)>MAX_BYTES or identity(before)!=identity(after) or identity(after)!=identity(named):_deny('qualification_predecessor_changed')
        if expected is not None and hashlib.sha256(body).hexdigest()!=expected:_deny('qualification_predecessor_changed')
        def pairs(items):
            value={}
            for key,item in items:
                if key in value:_deny('qualification_predecessor_invalid')
                value[key]=item
            return value
        return json.loads(body,object_pairs_hook=pairs,parse_constant=lambda _: _deny('qualification_predecessor_invalid'))
    finally:os.close(parent)


def _historical_controller_absent(pid,terminal,wallnow):
    """Do not confuse a later process reusing a PID with a sealed controller.

    The caller has already bound the original terminal, sealed child and cleanup
    provenance. A missing PID needs no new observation. A live PID is accepted
    only when two stable UTC birth observations prove it was born strictly after
    that terminal, allowing one full second for ps timestamp rounding. This does
    not signal or otherwise operate on the observed process beyond kill(pid,0).
    Unknown identity or observation races remain closed.
    """
    _integer(pid,1,2**31-1)
    try:os.kill(pid,0)
    except ProcessLookupError:return True
    except OSError:return False
    try:
        if type(terminal) is not dict or type(terminal.get('actual_exit')) is not int or terminal['actual_exit']!=2:return False
        started=_number(terminal.get('started_at'));elapsed=_number(terminal.get('elapsed_seconds'));current=_number(wallnow)
        ended=_number(started+elapsed)
        if started<=0 or elapsed<=0 or current<=0 or ended>current:return False
        argv=['/bin/ps','-p',str(pid),'-o','pid=','-o','lstart=']
        environment={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C','TZ':'UTC0'}
        previous=None
        for _ in range(2):
            result=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,text=True,encoding='ascii',errors='strict',
                timeout=1,env=environment,shell=False)
            if type(result.returncode) is not int or result.returncode!=0 or result.stderr!='' or type(result.stdout) is not str or len(result.stdout)>512:return False
            match=re.fullmatch(r'\s*([0-9]+) +([A-Z][a-z]{2}) +([A-Z][a-z]{2}) +([0-9]{1,2}) +([0-9]{2}):([0-9]{2}):([0-9]{2}) +([0-9]{4})\s*',result.stdout)
            if match is None or int(match[1])!=pid:return False
            weekdays=('Mon','Tue','Wed','Thu','Fri','Sat','Sun');months=('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec')
            observed=datetime.datetime(int(match[8]),months.index(match[3])+1,int(match[4]),int(match[5]),int(match[6]),int(match[7]),tzinfo=datetime.timezone.utc)
            if match[2]!=weekdays[observed.weekday()]:return False
            birth=calendar.timegm(observed.utctimetuple())
            if birth<=ended+1 or birth>current+1:return False
            identity=(pid,birth)
            if previous is not None and identity!=previous:return False
            previous=identity
            # Disappearance or replacement during the paired observation is not
            # positive custody evidence, even if the sealed controller is gone.
            os.kill(pid,0)
        return True
    except (OSError,ValueError,TypeError,OverflowError,subprocess.SubprocessError):return False


def _validate_first_predecessor(predecessor,*,daemon_id=None,clock=time.monotonic,wall=time.time,_launch_window=True):
    """Validate retained failed-campaign custody without updating its ledger.

    This is a new candidate's admission proof, never a recovery/reset operation.
    Current authoritative registry records and explicit owner cleanup receipts
    must prove absence and private removal. No Docker command is issued here.
    """
    try:
        value=_predecessor_shape(predecessor);root=Path(value['root'])
        full=_bound_json(root/'manifest.json',value['manifest_sha256'])
        if (type(full) is not dict or type(full.get('schema')) is not int or full['schema']!=1
                or full.get('document_type')!='application_client_qualification' or full.get('prepared_root')!=str(root)
                or 'predecessor' in full):_deny('qualification_predecessor_invalid')
        fields=('id','group','release','image_id','allowed_images','role_limits','container_launches_max','participant_segments_max')
        old=validate_manifest({'qualification_id':full['qualification_id'],'images':full['images'],
            'cells':[{k:cell[k] for k in fields} for cell in full['cells']],
            'limits':dict(LIMITS),'planned_container_launches':full['planned_container_launches']})
        cells={cell['id']:cell for cell in old['cells']}
        if len(cells)!=28 or {group:sum(c['group']==group for c in old['cells']) for group in ('N01','N02','N03','N04')}!={'N01':4,'N02':12,'N03':6,'N04':6}:_deny('qualification_predecessor_invalid')
        state=_bound_json(root/'state.json',value['state_sha256'])
        _exact(state,{'schema','phase','active_cell','cells','started_at'})
        if type(state['schema']) is not int or state['schema']!=1 or state['phase']!='blocked' or type(state['cells']) is not dict or set(state['cells'])-set(cells):_deny('qualification_predecessor_invalid')
        active=state['active_cell'];_exact(active,{'id','pid','run_id','attempt_id'})
        if active['id'] not in cells:_deny('qualification_predecessor_invalid')
        _integer(active['pid'],1,2**31-1);_uuid(active['run_id']);_uuid(active['attempt_id'])
        prior=[]
        for cell in old['cells']:
            row=state['cells'].get(cell['id'],{'status':'NOT_RUN','attempts':0})
            if (type(row) is not dict or row.get('status') not in ('PASS','FAIL','BLOCKED','NOT_RUN') or type(row.get('attempts')) is not int
                    or row['attempts'] not in (0,1) or (row['status']=='NOT_RUN')!=(row['attempts']==0)):_deny('qualification_predecessor_invalid')
            prior.append({'cell':cell['id'],'status':row['status'],'attempts':row['attempts']})
        if state['cells'].get(active['id'],{}).get('status')!='BLOCKED':_deny('qualification_predecessor_invalid')
        ledger=_bound_json(root/'launch-ledger/ledger.json',value['ledger_sha256'])
        verifier=object.__new__(LaunchLedger);verifier.manifest=old;verifier.expected_daemon=None;verifier.expected_capacity=None;verifier._carry=None
        verifier._validate(ledger)
        if ledger['poisoned'] is not True or not ledger['launches'] or any(row['physical']!='absent' or row['container_id'] is None for row in ledger['launches']):_deny('qualification_predecessor_unclean')
        role_counts={role:sum(row['role']==role for row in ledger['launches']) for role in ROLES}
        if (len(ledger['launches'])!=7 or {key:n for key,n in role_counts.items() if n}!={'probe':4,'browser-check':2,'fixture':1}
                or cells[active['id']]['group']!='N02'
                or any(state['cells'].get(row['cell'],{}).get('attempts')!=1 for row in ledger['launches'])
                or {row['cell'] for row in ledger['launches']}!=set(state['cells'])):_deny('qualification_predecessor_invalid')
        if daemon_id is not None and ledger['daemon']!=daemon_id:_deny('qualification_daemon_changed')
        now,wallnow=_number(clock()),_number(wall())
        if now<ledger['last_now'] or wallnow<ledger['last_wall']:_deny('qualification_clock_invalid')
        if _launch_window and (now>=ledger['deadline']-30 or wallnow>=ledger['deadline_wall']-30):_deny('qualification_deadline')
        receipts={item['path']:_bound_json(item['path'],item['sha256']) for item in value['cleanup_receipts']}
        campaign=[receipt for receipt in receipts.values() if receipt.get('document_type')=='qualification_campaign_cleanup']
        if len(campaign)!=1:_deny('qualification_predecessor_unclean')
        campaign=campaign[0]
        _exact(campaign,{'schema','document_type','qualification_id','manifest_sha256','ledger_sha256','state_sha256','daemon','controller','parent_bootstrap','launches','safe_to_continue'})
        if (type(campaign['schema']) is not int or campaign['schema']!=1 or campaign['safe_to_continue'] is not True
                or campaign['qualification_id']!=old['qualification_id'] or campaign['daemon']!=ledger['daemon']
                or any(campaign[k]!=value[k] for k in ('manifest_sha256','ledger_sha256','state_sha256'))):_deny('qualification_predecessor_unclean')
        controller=campaign['controller'];_exact(controller,{'pid','exited','pid_absence_observed','provenance','parent_terminal','child_result','original_invocation'})
        if (type(controller['pid']) is not int or controller['pid']!=active['pid'] or controller['exited'] is not True
                or controller['pid_absence_observed'] is not True or controller['provenance']!='terminal_parent_and_pid_absence'):_deny('qualification_predecessor_unclean')
        observations={}
        for key in ('parent_terminal','child_result','original_invocation'):
            reference=controller[key];_exact(reference,{'path','sha256'});_sha(reference['sha256'])
            if type(reference['path']) is not str or not Path(reference['path']).is_absolute() or '..' in Path(reference['path']).parts:_deny('qualification_predecessor_invalid')
            observations[key]=_bound_json(reference['path'],reference['sha256'])
        terminal=observations['parent_terminal'];child=observations['child_result'];invocation=observations['original_invocation']
        original_source=full.get('source',{}).get('files',{}).get('tools/qualification/application_client.py')
        if (original_source!='9439748664fb6393dce3061687f041d49813ad35636fe0c72a7b46b0f70bf3b4'
                or type(terminal.get('actual_exit')) is not int or terminal['actual_exit']!=2
                or terminal.get('argv')!=['python3','tools/qualification/application_client.py','collect','--root',str(root),'--group',cells[active['id']]['group'],'--release',cells[active['id']]['release']]
                or terminal.get('cwd')!=str(Path(__file__).resolve().parents[2])
                or child.get('sealed') is not True or child.get('status')!='BLOCKED' or type(child.get('exit_code')) is not int or child['exit_code']!=2
                or child.get('agents')!=[] or child.get('invocation')!={'status':'not_started','attempted_stages':0}
                or any(child.get(key)!=active[key] for key in ('run_id','attempt_id'))):_deny('qualification_predecessor_unclean')
        expected_invocation=['_cell-run','--root',str(root),'--cell-id',active['id'],'--private-envelope']
        argv=invocation.get('argv')
        if (type(argv) is not list or len(argv)!=9 or argv[1]!=str(Path(__file__).resolve().parent/'application_client.py')
                or argv[2:8]!=expected_invocation or invocation.get('cwd')!=str(Path(__file__).resolve().parents[2])
                or invocation.get('classification')!='native_scripted_protocol'):_deny('qualification_predecessor_unclean')
        bootstrap=campaign['parent_bootstrap'];_exact(bootstrap,{'path','device','inode','private_bootstrap_removed'})
        if (type(bootstrap['path']) is not str or Path(argv[-1]).name!='initial.json' or str(Path(argv[-1]).parent)!=bootstrap['path']
                or not Path(bootstrap['path']).name.startswith('pi-qualification-cell-') or bootstrap['private_bootstrap_removed'] is not True):_deny('qualification_predecessor_unclean')
        _integer(bootstrap['device'],0,2**64-1);_integer(bootstrap['inode'],1,2**64-1)
        parent=_dir(Path(bootstrap['path']).parent,False)
        try:
            try:os.stat(Path(bootstrap['path']).name,dir_fd=parent,follow_symlinks=False)
            except FileNotFoundError:pass
            else:_deny('qualification_predecessor_unclean')
        finally:os.close(parent)
        if not _historical_controller_absent(active['pid'],terminal,wallnow):_deny('qualification_predecessor_unclean')
        if type(campaign['launches']) is not list or len(campaign['launches'])!=len(ledger['launches']):_deny('qualification_predecessor_unclean')
        cleanup={}
        for row in campaign['launches']:
            _exact(row,{'launch_id','container_id','physical_absence_confirmed','private_cleanup_confirmed'})
            if row['launch_id'] in cleanup or row['physical_absence_confirmed'] is not True or row['private_cleanup_confirmed'] is not True:_deny('qualification_predecessor_unclean')
            cleanup[row['launch_id']]=row
        admission=full['host_admission'];_exact(admission,{'lock_file','wait_seconds'})
        if (type(admission['lock_file']) is not str or not Path(admission['lock_file']).is_absolute()
                or type(admission['wait_seconds']) is not int or admission['wait_seconds']!=30):_deny('qualification_predecessor_invalid')
        import ownership_registry
        used={path for path,receipt in receipts.items() if receipt is campaign}
        for row in ledger['launches']:
            if cleanup.get(row['launch_id'],{}).get('container_id')!=row['container_id']:_deny('qualification_predecessor_unclean')
            record=_bound_json(Path(admission['lock_file']+'.registry')/(row['launch_id']+'.json'))
            if (record.get('status')!='released' or _intent_identity(record)!=row['intent_sha256'] or record.get('container_id') not in (None,row['container_id'])
                    or record.get('daemon')!=ledger['daemon'] or record.get('registry')!=row['registry']
                    or record.get('launch_id')!=row['launch_id']):_deny('qualification_predecessor_unclean')
            if not row['private_cleanup']:
                reference=record.get('qualification_service_cleanup')
                _exact(reference,{'path','sha256'})
                if reference not in value['cleanup_receipts']:_deny('qualification_predecessor_unclean')
                receipt=ownership_registry.validate_qualification_service_cleanup(record,reference)
                if receipt.get('intent_sha256')!=row['intent_sha256'] or receipt.get('container_id')!=row['container_id']:_deny('qualification_predecessor_unclean')
                used.add(reference['path'])
        if used!=set(receipts):_deny('qualification_predecessor_invalid')
        attempts=len(ledger['launches']);segments=sum(row['role']=='participant' for row in ledger['launches'])
        if attempts+186>240 or segments+24>24:_deny('qualification_predecessor_limit')
        return {'attempts':attempts,'participant_segments':segments,'started':ledger['started'],'deadline':ledger['deadline'],
            'started_wall':ledger['started_wall'],'deadline_wall':ledger['deadline_wall'],'daemon':ledger['daemon'],
            'daemon_capacity':copy.deepcopy(ledger['daemon_capacity']),'qualification_id':old['qualification_id'],
            **{k:value[k] for k in ('manifest_sha256','ledger_sha256','state_sha256')},'planned_cells':28,'prior_rows':prior}
    except (OSError,ValueError,TypeError,KeyError,AttributeError,RecursionError) as error:
        if isinstance(error,LaunchError):raise
        raise LaunchError('qualification_predecessor_invalid') from None


def known_preworker_inventory(runroot):
    """Bounded read-only identity inventory; never a substitute for key scanning."""
    runroot=_canonical_root(str(runroot));directory=_dir(runroot,False);files={};total=0;nodes=0
    def walk(folder,prefix=''):
        nonlocal total,nodes
        names=os.listdir(folder)
        if len(names)>4096:_deny('qualification_preworker_inventory')
        for name in names:
            nodes+=1
            if nodes>8192:_deny('qualification_preworker_inventory')
            relative=prefix+name;info=os.stat(name,dir_fd=folder,follow_symlinks=False)
            if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o022:_deny('qualification_preworker_inventory')
            if stat.S_ISDIR(info.st_mode):
                if relative.count('/')>32:_deny('qualification_preworker_inventory')
                child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=folder)
                try:walk(child,relative+'/')
                finally:os.close(child)
            else:
                if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>MAX_BYTES or len(files)>=4096:_deny('qualification_preworker_inventory')
                fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=folder)
                with os.fdopen(fd,'rb') as stream:
                    before=os.fstat(stream.fileno());body=stream.read(MAX_BYTES+1);after=os.fstat(stream.fileno())
                named=os.stat(name,dir_fd=folder,follow_symlinks=False)
                identity=lambda st:(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
                if len(body)>MAX_BYTES or identity(before)!=identity(after) or identity(after)!=identity(named):_deny('qualification_preworker_inventory')
                total+=len(body)
                if total>64*1024*1024:_deny('qualification_preworker_inventory')
                files[relative]={'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
    try:walk(directory)
    finally:os.close(directory)
    return {'files':len(files),'bytes':total,'sha256':_digest(files)}


def _known_context(campaign,*,clock=time.monotonic,wall=time.time):
    _exact(campaign,{'root','manifest_sha256','ledger_sha256','state_sha256'});root=_canonical_root(campaign['root'])
    for key in ('manifest_sha256','ledger_sha256','state_sha256'):_sha(campaign[key])
    full=_bound_json(root/'manifest.json',campaign['manifest_sha256'])
    if full.get('prepared_root')!=str(root) or full.get('document_type')!='application_client_qualification' or 'predecessor' not in full:_deny('qualification_preworker_invalid')
    prior=validate_predecessor(full['predecessor'],clock=clock,wall=wall,_launch_window=False,_lineage=(str(root),))
    fields=('id','group','release','image_id','allowed_images','role_limits','container_launches_max','participant_segments_max')
    old=validate_manifest({'qualification_id':full['qualification_id'],'images':full['images'],'cells':[{k:c[k] for k in fields} for c in full['cells']],
        'limits':dict(LIMITS),'planned_container_launches':full['planned_container_launches'],'predecessor':full['predecessor']})
    state=_bound_json(root/'state.json',campaign['state_sha256']);_exact(state,{'schema','phase','active_cell','cells','started_at'})
    if type(state['schema']) is not int or state['schema']!=1:_deny('qualification_preworker_invalid')
    ledger=_bound_json(root/'launch-ledger/ledger.json',campaign['ledger_sha256'])
    verifier=object.__new__(LaunchLedger);verifier.root=root/'launch-ledger';verifier.manifest=old;verifier.expected_daemon=None
    verifier.expected_capacity=None;verifier._carry=None;verifier._prevalidated_carry=prior;verifier._validate(ledger)
    return {'root':root,'full':full,'state':state,'ledger':ledger,'prior':prior}


def _known_preworker_payload(campaign,value,context,*,require_released=False):
    import ownership_registry
    root,full,state,ledger,prior=(context[key] for key in ('root','full','state','ledger','prior'))
    _exact(value,{'schema','document_type','campaign','qualification_id','daemon','qualification','controller','stage','parent_bootstrap',
        'control','workspace','launches','service_receipts','privacy_scan'})
    if (type(value['schema']) is not int or value['schema']!=1 or value['document_type']!='qualification_known_preworker_cleanup'
            or value['campaign']!=campaign or value['qualification_id']!=full['qualification_id'] or value['daemon']!=ledger['daemon']):_deny('qualification_preworker_invalid')
    if state.get('phase')!='blocked' or ledger['poisoned'] is not True:_deny('qualification_preworker_invalid')
    active=state['active_cell'];_exact(active,{'id','pid','run_id','attempt_id'});_integer(active['pid'],1,2**31-1)
    cells={cell['id']:cell for cell in full['cells']}
    if len(cells)!=28 or active['id'] not in cells or cells[active['id']]['group']!='N02' or state['cells'].get(active['id'],{}).get('status')!='BLOCKED':_deny('qualification_preworker_invalid')
    counts={role:sum(row['role']==role for row in ledger['launches']) for role in ROLES}
    if (len(ledger['launches'])!=12 or {k:n for k,n in counts.items() if n}!={'probe':5,'browser-check':2,'fixture':1,'scripted-inference':1,'boundary':1,'preflight':1,'application-helper':1}
            or any(row['physical']!='absent' or row['container_id'] is None for row in ledger['launches'])):_deny('qualification_preworker_unclean')
    qualification=value['qualification'];_exact(qualification,{'lineage','cumulative_attempts','participant_segments'})
    lineage=qualification['lineage']
    if type(lineage) is not list or len(lineage)!=len(prior['lineage'])+1 or len(lineage)>8:_deny('qualification_preworker_invalid')
    allrows=[]
    expected=prior['lineage']+[{'root':str(root),'qualification_id':full['qualification_id'],**{k:campaign[k] for k in ('manifest_sha256','ledger_sha256','state_sha256')}}]
    for entry,bound in zip(lineage,expected):
        _exact(entry,{'root','manifest','state','ledger'})
        if entry['root']!=bound['root'] or any(entry[key].get('sha256')!=bound[key+'_sha256'] or entry[key].get('path')!=str(Path(bound['root'])/relative)
                for key,relative in (('manifest','manifest.json'),('state','state.json'),('ledger','launch-ledger/ledger.json'))):_deny('qualification_preworker_changed')
        for key in ('manifest','state'):_bound_json(entry[key]['path'],entry[key]['sha256'])
        allrows.extend(_bound_json(entry['ledger']['path'],entry['ledger']['sha256'])['launches'])
    total=prior['attempts']+len(ledger['launches']);segments=prior['participant_segments']+sum(row['role']=='participant' for row in ledger['launches'])
    if (type(qualification['cumulative_attempts']) is not int or qualification['cumulative_attempts']!=total or type(qualification['participant_segments']) is not int
            or qualification['participant_segments']!=segments or segments!=0 or total+186>240):_deny('qualification_preworker_limit')
    stage=value['stage'];_exact(stage,{'descriptor','state','process','credentials','result','stage_id','segment_id'})
    _uuid(stage['stage_id']);_uuid(stage['segment_id'])
    result=ownership_registry._qualification_reference(stage['result']);runroot=_canonical_root(str(Path(stage['result']['path']).parent))
    if runroot!=root/('scripted-'+cells[active['id']]['release'])/'runs'/active['run_id']:_deny('qualification_preworker_rerooted')
    expected_paths={'descriptor':runroot/'stages'/stage['stage_id']/'descriptor.json','state':runroot/'stages'/stage['stage_id']/'state.json',
        'credentials':runroot/'stages'/stage['stage_id']/'application-credentials.json','process':runroot/'agent-1-participant/process.json','result':runroot/'result.json'}
    if any(stage[key].get('path')!=str(path) for key,path in expected_paths.items()):_deny('qualification_preworker_rerooted')
    desc=ownership_registry._qualification_reference(stage['descriptor']);status=ownership_registry._qualification_reference(stage['state'])
    process=ownership_registry._qualification_reference(stage['process']);credential=ownership_registry._qualification_reference(stage['credentials'])
    if (result.get('sealed') is not True or result.get('status')!='FAIL' or type(result.get('exit_code')) is not int or result['exit_code']!=1
            or result.get('agents')!=[] or result.get('invocation')!={'status':'invalid','attempted_stages':1}
            or result.get('infrastructure',{}).get('phase')!='agents' or result['infrastructure'].get('reason')!='ApplicationExecutionError'
            or result.get('termination',{}).get('reason')!='application_startup_failed' or result['termination'].get('process_exit_code') is not None
            or any(result.get(key)!=active[key] or desc.get(key)!=active[key] for key in ('run_id','attempt_id'))
            or desc.get('kind')!='agent' or desc.get('label')!='agent-1-participant' or desc.get('stage_id')!=stage['stage_id']
            or desc.get('control')!=str(runroot/'controls'/stage['stage_id']) or desc.get('workspace')!=str(runroot/'workspace')
            or status.get('status')!='finalized' or status.get('cleanup_confirmed') is not True or status.get('exit_code') is not None or status.get('segment_id')!=stage['segment_id']):_deny('qualification_preworker_invalid')
    if _json(result.get('last_process'))!=_json(process):_deny('qualification_preworker_process_mismatch')
    if (not {'schema','document_type','started','worker_launch_attempted','exit_code','cleanup_confirmed','native_tool_budget'}.issubset(process)
            or type(process.get('schema')) is not int or process['schema']!=1 or process.get('termination_reason')!='application_startup_failed'
            or process.get('native_tool_budget_error')!='accounting_unavailable' or process.get('native_tool_budget') is not None
            or process.get('document_type')!='application_preworker_failure' or process.get('started') is not False or process.get('worker_launch_attempted') is not False
            or process.get('exit_code') is not None or process.get('cleanup_confirmed') is not True or process.get('application_completion',{}).get('status')!='not_evaluated'
            or process.get('application_completion_context') is not None or process.get('application_completion_result') is not None):_deny('qualification_preworker_worker_started')
    clean=process.get('application_preworker_cleanup');_exact(clean,{'schema','binding','worker_launch_attempted','helper_launch_attempted','writers_absent',
        'physical_cleanup_confirmed','private_cleanup_confirmed','accounting','completion_eligible'})
    binding=clean['binding'];_exact(binding,{'run_id','trial_id','attempt_id','stage_id','segment_id','session_id','plan_sha256'})
    for key in ('run_id','attempt_id','stage_id','segment_id','session_id'):_uuid(binding[key])
    if binding['trial_id'] is not None:_uuid(binding['trial_id'])
    _sha(binding['plan_sha256'])
    if (type(clean['schema']) is not int or clean['schema']!=1 or clean['worker_launch_attempted'] is not False or clean['helper_launch_attempted'] is not True
            or any(clean[key] is not True for key in ('writers_absent','physical_cleanup_confirmed','private_cleanup_confirmed')) or clean['accounting']!='unavailable'
            or clean['completion_eligible'] is not False or any(binding[key]!=active[key] for key in ('run_id','attempt_id'))
            or binding['stage_id']!=stage['stage_id'] or binding['segment_id']!=stage['segment_id']
            or cells[active['id']].get('plan_sha256')!=binding['plan_sha256'] or cells[active['id']].get('trial_id')!=binding['trial_id']):_deny('qualification_preworker_unclean')
    _exact(credential,{'schema','status','workspace','references'})
    if type(credential['schema']) is not int or credential['schema']!=1:_deny('qualification_preworker_unclean')
    helper_cleanup=process.get('application_helper_cleanup');_exact(helper_cleanup,{'schema','status','workspace','evidence','evidence_root','safe_to_continue','budget'})
    if (type(helper_cleanup['schema']) is not int or helper_cleanup['schema']!=1 or helper_cleanup['status']!='removed' or helper_cleanup['workspace']!='clean'
            or helper_cleanup['evidence']!='retained' or helper_cleanup['safe_to_continue'] is not True or helper_cleanup['budget'] is not None
            or _json(process.get('native_tool_budget_cleanup'))!=_json(helper_cleanup) or credential!={'schema':1,'status':'removed','workspace':'clean','references':{}}
            or _json(process.get('application_credentials'))!=_json({'schema':1,'status':'removed','workspace':'clean'}) or ownership_registry._application_stage_pending(runroot)):_deny('qualification_preworker_unclean')
    controller=value['controller'];_exact(controller,{'pid','parent_terminal','original_invocation','pid_absence_observed','provenance'})
    if controller['pid']!=active['pid'] or type(controller['pid']) is not int or controller['pid_absence_observed'] is not True or controller['provenance']!='terminal_parent_and_pid_absence':_deny('qualification_preworker_controller')
    terminal=ownership_registry._qualification_reference(controller['parent_terminal']);invocation=ownership_registry._qualification_reference(controller['original_invocation']);argv=invocation.get('argv')
    if (type(terminal.get('actual_exit')) is not int or terminal['actual_exit']!=2 or type(argv) is not list or len(argv)!=9
            or argv[2:8]!=['_cell-run','--root',str(root),'--cell-id',active['id'],'--private-envelope']
            or terminal.get('argv')!=['python3','tools/qualification/application_client.py','collect','--root',str(root),'--group','N02','--release',cells[active['id']]['release']]
            or terminal.get('cwd')!=invocation.get('cwd') or terminal.get('cwd')!=str(Path(__file__).resolve().parents[2])
            or argv[1]!=str(Path(__file__).resolve().parent/'application_client.py') or invocation.get('classification')!='native_scripted_protocol'):_deny('qualification_preworker_controller')
    if not _historical_controller_absent(active['pid'],terminal,time.time()):_deny('qualification_preworker_controller')
    bootstrap=value['parent_bootstrap'];ownership_registry._preworker_fd(bootstrap,removed=True)
    if Path(argv[-1]).name!='initial.json' or str(Path(argv[-1]).parent)!=bootstrap['path'] or not Path(bootstrap['path']).name.startswith('pi-qualification-cell-'):_deny('qualification_preworker_controller')
    ownership_registry._preworker_control(value['control'],desc,stage['segment_id'])
    workspace=value['workspace'];_exact(workspace,{'path','device','inode','status','files','all_parent_authorities_scanned'})
    ownership_registry._preworker_fd({k:workspace[k] for k in ('path','device','inode')})
    if workspace['path']!=desc['workspace'] or workspace['status']!='clean' or workspace['all_parent_authorities_scanned'] is not True or [workspace['device'],workspace['inode']]!=desc.get('workspace_identity'):_deny('qualification_preworker_workspace')
    directory=_dir(Path(workspace['path']),False)
    try:
        info=os.fstat(directory)
        if (info.st_dev,info.st_ino)!=(workspace['device'],workspace['inode']):_deny('qualification_preworker_workspace')
    finally:os.close(directory)
    inventory=known_preworker_inventory(workspace['path'])
    files=workspace['files']
    if type(files) is not list or not 1<=len(files)<=64:_deny('qualification_preworker_workspace')
    seen=set();size=0;mapping={}
    for item in files:
        _exact(item,{'path','sha256','bytes'});_sha(item['sha256']);_integer(item['bytes'],0,MAX_BYTES)
        if type(item['path']) is not str or item['path'] in seen or Path(item['path']).is_absolute() or '..' in Path(item['path']).parts or str(Path(item['path']))!=item['path']:_deny('qualification_preworker_workspace')
        seen.add(item['path']);size+=item['bytes'];mapping[item['path']]={'bytes':item['bytes'],'sha256':item['sha256']}
    if inventory!={'files':len(files),'bytes':size,'sha256':_digest(mapping)}:_deny('qualification_preworker_workspace')
    scan=value['privacy_scan'];_exact(scan,{'runroot','method','status','all_parent_authorities_scanned','inventory'})
    _exact(scan['inventory'],{'files','bytes','sha256'});_integer(scan['inventory']['files'],0,4096);_integer(scan['inventory']['bytes'],0,64*1024*1024);_sha(scan['inventory']['sha256'])
    if (scan['runroot']!=str(runroot) or scan['method']!='existing_scan_cell_and_cleanup_material' or scan['status']!='clean'
            or scan['all_parent_authorities_scanned'] is not True or scan['inventory']!=known_preworker_inventory(runroot)):_deny('qualification_preworker_scan')
    observations=value['launches']
    if type(observations) is not list or len(observations)!=total or len({row.get('launch_id') for row in observations})!=total:_deny('qualification_preworker_history')
    observations={row['launch_id']:row for row in observations};service_refs=value['service_receipts']
    if type(service_refs) is not list or len(service_refs)!=2:_deny('qualification_preworker_service')
    registry_root=Path(full['host_admission']['lock_file']+'.registry');current_ids={row['launch_id'] for row in ledger['launches']};used=[];helpers=[]
    for row in allrows:
        observed=observations.get(row['launch_id']);_exact(observed,{'registry','generation','launch_id','container_id','physical_absence_confirmed','private_cleanup_confirmed'})
        if any(observed[k]!=row[k] for k in ('registry','generation','launch_id','container_id')) or observed['physical_absence_confirmed'] is not True or observed['private_cleanup_confirmed'] is not True:_deny('qualification_preworker_history')
        record=_bound_json(registry_root/(row['launch_id']+'.json'))
        ordinary=(row['launch_id'] in current_ids and row['cell']==active['id'] and row['role'] in ('probe','boundary','preflight') and row['private_cleanup'] is False)
        allowed=('released',) if require_released or not ordinary else ('absent','released')
        if (record.get('status') not in allowed or _intent_identity(record)!=row['intent_sha256'] or record.get('container_id') not in (None,row['container_id'])
                or record.get('daemon')!=ledger['daemon'] or record.get('registry')!=row['registry'] or record.get('generation')!=row['generation']):_deny('qualification_preworker_history')
        if row['launch_id'] not in current_ids:continue
        if row['private_cleanup'] is not True and not ordinary:_deny('qualification_preworker_unclean')
        if row['role'] in ('fixture','scripted-inference'):
            reference=record.get('qualification_service_cleanup')
            if reference not in service_refs:_deny('qualification_preworker_service')
            ownership_registry.validate_qualification_service_cleanup(record,reference);used.append(reference)
        if row['role']=='application-helper':
            helpers.append(record)
            if (record.get('container_id')!=row['container_id'] or record.get('client_mode')!='application-execution' or record.get('application_helper') is not True
                    or record.get('runroot')!=str(runroot) or not ownership_registry._qualification_absent(record['private_store'])
                    or helper_cleanup['evidence_root']!=str(runroot/'application-evidence'/record['container'])
                    or record['binding'].get('plan_sha256')!=binding['plan_sha256']
                    or any(record['binding'].get(k)!=binding[k] for k in ('run_id','attempt_id','trial_id'))):_deny('qualification_preworker_unclean')
    if len(helpers)!=1 or len(used)!=2 or any(ref not in used for ref in service_refs):_deny('qualification_preworker_unclean')
    return value


def validate_known_preworker_cleanup(campaign,reference,*,require_released=False,clock=time.monotonic,wall=time.time):
    """Tools-only stopped positive-product-cleanup proof; no Registry exception."""
    try:
        _exact(reference,{'path','sha256'});_sha(reference['sha256'])
        value=_bound_json(reference['path'],reference['sha256']);context=_known_context(campaign,clock=clock,wall=wall)
        return _known_preworker_payload(campaign,value,context,require_released=require_released)
    except (OSError,ValueError,TypeError,KeyError,AttributeError,IndexError,RecursionError) as error:
        if isinstance(error,LaunchError):raise
        raise LaunchError('qualification_preworker_invalid') from None


def write_known_preworker_cleanup(campaign,path,*,proof,clock=time.monotonic,wall=time.time):
    """Publish owner observations only after explicit stopped-parent cleanup."""
    folder=fd=None
    try:
        context=_known_context(campaign,clock=clock,wall=wall)
        _exact(proof,{'qualification','controller','stage','parent_bootstrap','control','workspace','launches','service_receipts','privacy_scan'})
        value={'schema':1,'document_type':'qualification_known_preworker_cleanup','campaign':campaign,
            'qualification_id':context['full']['qualification_id'],'daemon':context['ledger']['daemon'],**proof}
        _known_preworker_payload(campaign,value,context);body=_json(value)
        if len(body)>262144:_deny('qualification_preworker_invalid')
        path=Path(path);folder=_dir(path.parent);fd=_file(folder,path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL)
        with os.fdopen(fd,'wb') as stream:fd=None;stream.write(body);stream.flush();os.fsync(stream.fileno())
        os.fsync(folder);reference={'path':str(path),'sha256':hashlib.sha256(body).hexdigest()}
        validate_known_preworker_cleanup(campaign,reference,clock=clock,wall=wall);return reference
    except (OSError,ValueError,TypeError,KeyError,AttributeError,IndexError,RecursionError) as error:
        if isinstance(error,LaunchError):raise
        raise LaunchError('qualification_preworker_invalid') from None
    finally:
        if fd is not None:os.close(fd)
        if folder is not None:os.close(folder)


def _known_admission_payload(campaign,value,context,*,require_released=True):
    """Only a completely stopped, zero-stage admission failure may use this route."""
    import ownership_registry
    root,full,state,ledger,prior=(context[k] for k in ('root','full','state','ledger','prior'))
    _exact(value,{'schema','document_type','campaign','qualification_id','daemon','qualification','controller','run','parent_bootstrap','launches','service_receipts','privacy_scan'})
    if (type(value['schema']) is not int or value['schema']!=1 or value['document_type']!='qualification_known_admission_cleanup'
            or value['campaign']!=campaign or value['qualification_id']!=full['qualification_id'] or value['daemon']!=ledger['daemon']
            or state.get('phase')!='blocked' or ledger['poisoned'] is not False):_deny('qualification_admission_invalid')
    active=state['active_cell'];_exact(active,{'id','pid','run_id','attempt_id'});_integer(active['pid'],1,2**31-1)
    for key in ('run_id','attempt_id'):_uuid(active[key])
    cells={cell['id']:cell for cell in full['cells']}
    if len(cells)!=28 or active['id'] not in cells or cells[active['id']]['group']!='N02' or state['cells'].get(active['id'],{}).get('status')!='BLOCKED':_deny('qualification_admission_invalid')
    counts={role:sum(row['role']==role for row in ledger['launches']) for role in ROLES}
    if (len(ledger['launches'])!=8 or {k:n for k,n in counts.items() if n}!={'probe':4,'browser-check':2,'fixture':1,'scripted-inference':1}
            or any(row['physical']!='absent' or row['private_cleanup'] is not True or row['container_id'] is None for row in ledger['launches'])
            or any(state['cells'].get(row['cell'],{}).get('attempts')!=1 for row in ledger['launches'])
            or {row['cell'] for row in ledger['launches']}!=set(state['cells'])):_deny('qualification_admission_unclean')
    qualification=value['qualification'];_exact(qualification,{'lineage','cumulative_attempts','participant_segments'})
    total=prior['attempts']+8
    if (type(qualification['cumulative_attempts']) is not int or qualification['cumulative_attempts']!=total
            or type(qualification['participant_segments']) is not int or qualification['participant_segments']!=0 or prior['participant_segments']!=0 or total+186>240):_deny('qualification_admission_limit')
    lineage=qualification['lineage'];expected=prior['lineage']+[{'root':str(root),'qualification_id':full['qualification_id'],**{k:campaign[k] for k in ('manifest_sha256','ledger_sha256','state_sha256')}}]
    if type(lineage) is not list or len(lineage)!=len(expected) or len(lineage)>8:_deny('qualification_admission_invalid')
    allrows=[]
    for entry,bound in zip(lineage,expected):
        _exact(entry,{'root','manifest','state','ledger'})
        if entry['root']!=bound['root'] or any(entry[key].get('path')!=str(Path(bound['root'])/relative) or entry[key].get('sha256')!=bound[key+'_sha256']
                for key,relative in (('manifest','manifest.json'),('state','state.json'),('ledger','launch-ledger/ledger.json'))):_deny('qualification_admission_changed')
        for key in ('manifest','state'):_bound_json(entry[key]['path'],entry[key]['sha256'])
        allrows.extend(_bound_json(entry['ledger']['path'],entry['ledger']['sha256'])['launches'])
    run=value['run'];_exact(run,{'result','child_completion'})
    runroot=root/('scripted-'+cells[active['id']]['release'])/'runs'/active['run_id']
    if run['result'].get('path')!=str(runroot/'result.json') or run['child_completion'].get('path')!=str(root/'cells'/active['id']/'child-completion.json'):_deny('qualification_admission_rerooted')
    result=ownership_registry._qualification_reference(run['result']);completion=ownership_registry._qualification_reference(run['child_completion'])
    if (type(result.get('schema')) is not int or result['schema']!=2 or result.get('document_type')!='run_result' or result.get('sealed') is not True
            or result.get('status')!='BLOCKED' or type(result.get('exit_code')) is not int or result['exit_code']!=2
            or result.get('agents')!=[] or result.get('checks')!=[] or result.get('workspace') is not None or result.get('last_process') is not None
            or _json(result.get('invocation'))!=_json({'status':'not_started','attempted_stages':0})
            or result.get('infrastructure',{}).get('status')!='failed' or result['infrastructure'].get('phase')!='admission'
            or result['infrastructure'].get('reason')!='QualificationError'
            or _json(result.get('termination'))!=_json({'reason':'not_started','trigger':None,'process_exit_code':None})
            or any(result.get(key)!=active[key] for key in ('run_id','attempt_id'))):_deny('qualification_admission_started')
    execution=result.get('application_execution');_exact(execution,{'schema','plan_sha256','required_stages'})
    if type(execution['schema']) is not int or execution['schema']!=1 or execution['plan_sha256']!=cells[active['id']].get('plan_sha256') or execution['required_stages']!=['participant']:_deny('qualification_admission_invalid')
    _exact(completion,{'schema','run_id','attempt_id','result_sha256','cleanup_checked'})
    if (type(completion['schema']) is not int or completion['schema']!=1 or completion['cleanup_checked'] is not True
            or completion['result_sha256']!=run['result']['sha256'] or any(completion[key]!=active[key] for key in ('run_id','attempt_id'))):_deny('qualification_admission_completion')
    for name in ('stages','controls','children','workspace','application-helpers','application-evidence','application-startup'):
        if not ownership_registry._qualification_absent(str(runroot/name)):_deny('qualification_admission_started')
    controller=value['controller'];_exact(controller,{'pid','parent_terminal','original_invocation','pid_absence_observed','provenance'})
    if type(controller['pid']) is not int or controller['pid']!=active['pid'] or controller['pid_absence_observed'] is not True or controller['provenance']!='terminal_parent_and_pid_absence':_deny('qualification_admission_controller')
    terminal=ownership_registry._qualification_reference(controller['parent_terminal']);invocation=ownership_registry._qualification_reference(controller['original_invocation']);argv=invocation.get('argv')
    if (type(terminal.get('actual_exit')) is not int or terminal['actual_exit']!=2 or type(argv) is not list or len(argv)!=9
            or argv[1]!=str(Path(__file__).resolve().parent/'application_client.py')
            or argv[2:8]!=['_cell-run','--root',str(root),'--cell-id',active['id'],'--private-envelope']
            or terminal.get('argv')!=['python3','tools/qualification/application_client.py','collect','--root',str(root),'--group','N02','--release',cells[active['id']]['release']]
            or terminal.get('cwd')!=str(Path(__file__).resolve().parents[2]) or invocation.get('cwd')!=terminal['cwd'] or invocation.get('classification')!='native_scripted_protocol'):_deny('qualification_admission_controller')
    if not _historical_controller_absent(active['pid'],terminal,time.time()):_deny('qualification_admission_controller')
    bootstrap=value['parent_bootstrap'];ownership_registry._preworker_fd(bootstrap,removed=True)
    if Path(argv[-1]).name!='initial.json' or str(Path(argv[-1]).parent)!=bootstrap['path'] or not Path(bootstrap['path']).name.startswith('pi-qualification-cell-'):_deny('qualification_admission_controller')
    scan=value['privacy_scan'];_exact(scan,{'runroot','method','status','all_parent_authorities_scanned','inventory'})
    _exact(scan['inventory'],{'files','bytes','sha256'});_integer(scan['inventory']['files'],0,4096);_integer(scan['inventory']['bytes'],0,64*1024*1024);_sha(scan['inventory']['sha256'])
    if (scan['runroot']!=str(runroot) or scan['method']!='existing_scan_cell_and_cleanup_material' or scan['status']!='clean'
            or scan['all_parent_authorities_scanned'] is not True or scan['inventory']!=known_preworker_inventory(runroot)):_deny('qualification_admission_scan')
    observations=value['launches'];services=value['service_receipts']
    if type(observations) is not list or len(observations)!=total or len({row.get('launch_id') for row in observations})!=total or type(services) is not list or len(services)!=2:_deny('qualification_admission_history')
    observations={row['launch_id']:row for row in observations};registry_root=Path(full['host_admission']['lock_file']+'.registry');current={row['launch_id'] for row in ledger['launches']};used=[]
    for row in allrows:
        observed=observations.get(row['launch_id']);_exact(observed,{'registry','generation','launch_id','container_id','physical_absence_confirmed','private_cleanup_confirmed'})
        if any(observed[k]!=row[k] for k in ('registry','generation','launch_id','container_id')) or observed['physical_absence_confirmed'] is not True or observed['private_cleanup_confirmed'] is not True:_deny('qualification_admission_history')
        record=_bound_json(registry_root/(row['launch_id']+'.json'))
        if (record.get('status')!='released' or _intent_identity(record)!=row['intent_sha256'] or record.get('container_id') not in (None,row['container_id'])
                or record.get('daemon')!=ledger['daemon'] or record.get('registry')!=row['registry'] or record.get('generation')!=row['generation']):_deny('qualification_admission_unclean')
        if row['launch_id'] in current and row['role'] in ('fixture','scripted-inference'):
            reference=record.get('qualification_service_cleanup')
            if reference not in services:_deny('qualification_admission_service')
            receipt=ownership_registry.validate_qualification_service_cleanup(record,reference)
            if receipt['container_id']!=row['container_id'] or receipt['intent_sha256']!=row['intent_sha256']:_deny('qualification_admission_service')
            used.append(reference)
    if len(used)!=2 or any(reference not in used for reference in services):_deny('qualification_admission_service')
    return value


def validate_known_admission_cleanup(campaign,reference,*,require_released=True,clock=time.monotonic,wall=time.time):
    """No stage or worker receipt is manufactured for an admission-only stop."""
    try:
        _exact(reference,{'path','sha256'});_sha(reference['sha256']);value=_bound_json(reference['path'],reference['sha256'])
        return _known_admission_payload(campaign,value,_known_context(campaign,clock=clock,wall=wall),require_released=require_released)
    except (OSError,ValueError,TypeError,KeyError,AttributeError,IndexError,RecursionError) as error:
        if isinstance(error,LaunchError):raise
        raise LaunchError('qualification_admission_invalid') from None


def write_known_admission_cleanup(campaign,path,*,proof,clock=time.monotonic,wall=time.time):
    folder=fd=None
    try:
        context=_known_context(campaign,clock=clock,wall=wall)
        _exact(proof,{'qualification','controller','run','parent_bootstrap','launches','service_receipts','privacy_scan'})
        value={'schema':1,'document_type':'qualification_known_admission_cleanup','campaign':campaign,'qualification_id':context['full']['qualification_id'],'daemon':context['ledger']['daemon'],**proof}
        _known_admission_payload(campaign,value,context);body=_json(value)
        if len(body)>262144:_deny('qualification_admission_invalid')
        path=Path(path);folder=_dir(path.parent);fd=_file(folder,path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL)
        with os.fdopen(fd,'wb') as stream:fd=None;stream.write(body);stream.flush();os.fsync(stream.fileno())
        os.fsync(folder);reference={'path':str(path),'sha256':hashlib.sha256(body).hexdigest()}
        validate_known_admission_cleanup(campaign,reference,clock=clock,wall=wall);return reference
    except (OSError,ValueError,TypeError,KeyError,AttributeError,IndexError,RecursionError) as error:
        if isinstance(error,LaunchError):raise
        raise LaunchError('qualification_admission_invalid') from None
    finally:
        if fd is not None:os.close(fd)
        if folder is not None:os.close(folder)


def _known_zero_launch_payload(campaign,value,context,*,require_released=True):
    """A stopped first image admission with no launched object has no worker identity."""
    import ownership_registry
    root,full,state,ledger,prior=(context[k] for k in ('root','full','state','ledger','prior'))
    _exact(value,{'schema','document_type','campaign','qualification_id','daemon','qualification','controller','inputs','launches','prior_cleanup'})
    cells={cell['id']:cell for cell in full['cells']};first='N01-0.87.1-core'
    if (type(value['schema']) is not int or value['schema']!=1 or value['document_type']!='qualification_known_zero_launch_cleanup'
            or value['campaign']!=campaign or value['qualification_id']!=full['qualification_id'] or value['daemon']!=ledger['daemon']
            or state['phase']!='blocked' or state['active_cell'] is not None or ledger['poisoned'] is not False or ledger['launches']!=[]
            or set(state['cells'])!={first} or first not in cells or cells[first]['group']!='N01'
            or _json(state['cells'][first])!=_json({'status':'BLOCKED','attempts':1,'reason':'infrastructure_qualification_failed'})
            or prior['attempts']!=39 or prior['participant_segments']!=0 or not 4<=len(prior['lineage'])<8
            or prior['planned_cells']!=28*len(prior['lineage'])):_deny('qualification_zero_launch_invalid')
    qualification=value['qualification'];_exact(qualification,{'lineage','cumulative_attempts','participant_segments'})
    if (type(qualification['cumulative_attempts']) is not int or qualification['cumulative_attempts']!=39
            or type(qualification['participant_segments']) is not int or qualification['participant_segments']!=0):_deny('qualification_zero_launch_limit')
    lineage=qualification['lineage'];expected=prior['lineage']+[{'root':str(root),**{k:campaign[k] for k in ('manifest_sha256','ledger_sha256','state_sha256')}}]
    if type(lineage) is not list or len(lineage)!=len(expected) or len(lineage)>8:_deny('qualification_zero_launch_invalid')
    allrows=[]
    for entry,bound in zip(lineage,expected):
        _exact(entry,{'root','manifest','state','ledger'})
        if entry['root']!=bound['root']:_deny('qualification_zero_launch_changed')
        for key,relative in (('manifest','manifest.json'),('state','state.json'),('ledger','launch-ledger/ledger.json')):
            _exact(entry[key],{'path','sha256'})
            if entry[key]['path']!=str(Path(bound['root'])/relative) or entry[key]['sha256']!=bound[key+'_sha256']:_deny('qualification_zero_launch_changed')
            data=_bound_json(entry[key]['path'],entry[key]['sha256'])
            if key=='ledger':allrows.extend(data['launches'])
    if value['prior_cleanup'] not in full['predecessor']['cleanup_receipts'] or len(full['predecessor']['cleanup_receipts'])!=1:_deny('qualification_zero_launch_prior')
    prior_proof=ownership_registry._qualification_reference(value['prior_cleanup'])
    if prior_proof.get('document_type') not in ('qualification_known_admission_cleanup','qualification_known_zero_launch_cleanup'):_deny('qualification_zero_launch_prior')
    inputs=value['inputs'];_exact(inputs,{'candidate','source_sha256'});_sha(inputs['source_sha256'])
    if inputs['candidate'].get('path')!=str(root/'candidate.json') or inputs['source_sha256']!=full['source']['sha256']:_deny('qualification_zero_launch_inputs')
    candidate=ownership_registry._qualification_reference(inputs['candidate']);_exact(candidate,{'archive_sha256','runner_sha256','scope'})
    _sha(candidate['archive_sha256']);_sha(candidate['runner_sha256'])
    if candidate['scope']!='extracted_candidate' or candidate['runner_sha256']!=full['source']['runner']:_deny('qualification_zero_launch_inputs')
    controller=value['controller'];_exact(controller,{'parent_terminal'})
    terminal=ownership_registry._qualification_reference(controller['parent_terminal'])
    if (type(terminal.get('actual_exit')) is not int or terminal['actual_exit']!=2
            or terminal.get('argv')!=['python3','tools/qualification/application_client.py','admit','--root',str(root)]
            or terminal.get('cwd')!=str(Path(__file__).resolve().parents[2])):_deny('qualification_zero_launch_controller')
    # Prepared inputs exist; runtime trees and N02 child/controller identities must not.
    for base in (root,root/'scripted-0.87.1',root/'scripted-1.2.0'):
        for name in ('runs','stages','controls','children','workspace','application-helpers','application-evidence','application-startup','private'):
            if not ownership_registry._qualification_absent(str(base/name)):_deny('qualification_zero_launch_started')
    for cell in cells:
        for name in ('child-completion.json','result.json','process.json','private','runs','stages','controls','children','workspace','application-helpers','application-evidence','application-startup','service-cleanup-receipts','services-cleanup.json'):
            if not ownership_registry._qualification_absent(str(root/'cells'/cell/name)):_deny('qualification_zero_launch_started')
    observations=value['launches']
    if type(observations) is not list or len(observations)!=39 or len(allrows)!=39 or len({row.get('launch_id') for row in observations})!=39:_deny('qualification_zero_launch_history')
    observations={row['launch_id']:row for row in observations};registry_root=Path(full['host_admission']['lock_file']+'.registry')
    for row in allrows:
        observed=observations.get(row['launch_id']);_exact(observed,{'registry','generation','launch_id','container_id','physical_absence_confirmed','private_cleanup_confirmed'})
        if any(observed[k]!=row[k] for k in ('registry','generation','launch_id','container_id')) or observed['physical_absence_confirmed'] is not True or observed['private_cleanup_confirmed'] is not True:_deny('qualification_zero_launch_history')
        record=_bound_json(registry_root/(row['launch_id']+'.json'))
        if (record.get('status')!='released' or _intent_identity(record)!=row['intent_sha256'] or record.get('container_id') not in (None,row['container_id'])
                or record.get('daemon')!=ledger['daemon'] or record.get('registry')!=row['registry'] or record.get('generation')!=row['generation']):_deny('qualification_zero_launch_unclean')
    return value


def validate_known_zero_launch_cleanup(campaign,reference,*,require_released=True,clock=time.monotonic,wall=time.time):
    try:
        _exact(reference,{'path','sha256'});_sha(reference['sha256']);value=_bound_json(reference['path'],reference['sha256'])
        return _known_zero_launch_payload(campaign,value,_known_context(campaign,clock=clock,wall=wall),require_released=require_released)
    except (OSError,ValueError,TypeError,KeyError,AttributeError,IndexError,RecursionError) as error:
        if isinstance(error,LaunchError):raise
        raise LaunchError('qualification_zero_launch_invalid') from None


def write_known_zero_launch_cleanup(campaign,path,*,proof,clock=time.monotonic,wall=time.time):
    folder=fd=None
    try:
        context=_known_context(campaign,clock=clock,wall=wall)
        _exact(proof,{'qualification','controller','inputs','launches','prior_cleanup'})
        value={'schema':1,'document_type':'qualification_known_zero_launch_cleanup','campaign':campaign,'qualification_id':context['full']['qualification_id'],'daemon':context['ledger']['daemon'],**proof}
        _known_zero_launch_payload(campaign,value,context);body=_json(value)
        if len(body)>262144:_deny('qualification_zero_launch_invalid')
        path=Path(path);folder=_dir(path.parent);fd=_file(folder,path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL)
        with os.fdopen(fd,'wb') as stream:fd=None;stream.write(body);stream.flush();os.fsync(stream.fileno())
        os.fsync(folder);reference={'path':str(path),'sha256':hashlib.sha256(body).hexdigest()}
        validate_known_zero_launch_cleanup(campaign,reference,clock=clock,wall=wall);return reference
    except (OSError,ValueError,TypeError,KeyError,AttributeError,IndexError,RecursionError) as error:
        if isinstance(error,LaunchError):raise
        raise LaunchError('qualification_zero_launch_invalid') from None
    finally:
        if fd is not None:os.close(fd)
        if folder is not None:os.close(folder)


def validate_predecessor(predecessor,*,daemon_id=None,clock=time.monotonic,wall=time.time,_launch_window=True,_lineage=()):
    """Read a finite linear history; every ancestor retains its permanent claim."""
    try:
        value=_predecessor_shape(predecessor);root=Path(value['root'])
        if len(_lineage)>=8 or str(root) in _lineage:_deny('qualification_predecessor_cycle')
        full=_bound_json(root/'manifest.json',value['manifest_sha256'])
        if (full.get('document_type')!='application_client_qualification' or full.get('prepared_root')!=str(root)
                or type(full.get('schema')) is not int or full['schema']!=1):_deny('qualification_predecessor_invalid')
        if 'predecessor' not in full:
            result=_validate_first_predecessor(value,daemon_id=daemon_id,clock=clock,wall=wall,_launch_window=_launch_window)
            result['prior_rows']=[{'qualification_id':result['qualification_id'],**row} for row in result['prior_rows']]
            result['lineage']=[{'root':str(root),'qualification_id':result['qualification_id'],
                **{k:value[k] for k in ('manifest_sha256','state_sha256','ledger_sha256')}}]
            return result
        prior=validate_predecessor(full['predecessor'],daemon_id=daemon_id,clock=clock,wall=wall,_launch_window=_launch_window,_lineage=(*_lineage,str(root)))
        if full['qualification_id'] in {row['qualification_id'] for row in prior['lineage']}:_deny('qualification_predecessor_cycle')
        fields=('id','group','release','image_id','allowed_images','role_limits','container_launches_max','participant_segments_max')
        old=validate_manifest({'qualification_id':full['qualification_id'],'images':full['images'],
            'cells':[{k:cell[k] for k in fields} for cell in full['cells']],'limits':dict(LIMITS),
            'planned_container_launches':full['planned_container_launches'],'predecessor':full['predecessor']})
        cells={cell['id']:cell for cell in old['cells']}
        if len(cells)!=28 or {group:sum(c['group']==group for c in old['cells']) for group in ('N01','N02','N03','N04')}!={'N01':4,'N02':12,'N03':6,'N04':6}:_deny('qualification_predecessor_invalid')
        state=_bound_json(root/'state.json',value['state_sha256']);_exact(state,{'schema','phase','active_cell','cells','started_at'})
        if type(state['schema']) is not int or state['schema']!=1 or state['phase']!='blocked' or type(state['cells']) is not dict or set(state['cells'])-set(cells):_deny('qualification_predecessor_invalid')
        active=state['active_cell']
        if active is not None:
            _exact(active,{'id','pid','run_id','attempt_id'})
            if active['id'] not in cells or cells[active['id']]['group']!='N02' or state['cells'].get(active['id'],{}).get('status')!='BLOCKED':_deny('qualification_predecessor_invalid')
            _integer(active['pid'],1,2**31-1);_uuid(active['run_id']);_uuid(active['attempt_id'])
        rows=[]
        for cell in old['cells']:
            observed=state['cells'].get(cell['id'],{'status':'NOT_RUN','attempts':0})
            if (type(observed) is not dict or observed.get('status') not in ('PASS','FAIL','BLOCKED','NOT_RUN') or type(observed.get('attempts')) is not int
                    or observed['attempts'] not in (0,1) or (observed['status']=='NOT_RUN')!=(observed['attempts']==0)):_deny('qualification_predecessor_invalid')
            rows.append({'qualification_id':full['qualification_id'],'cell':cell['id'],'status':observed['status'],'attempts':observed['attempts']})
        ledger=_bound_json(root/'launch-ledger/ledger.json',value['ledger_sha256'])
        verifier=object.__new__(LaunchLedger);verifier.root=root/'launch-ledger';verifier.manifest=old
        verifier.expected_daemon=None;verifier.expected_capacity=None;verifier._carry=None;verifier._prevalidated_carry=prior
        verifier._validate(ledger)
        refs=value['cleanup_receipts']
        if len(refs)!=1:_deny('qualification_predecessor_unclean')
        candidate_proof=_bound_json(refs[0]['path'],refs[0]['sha256'])
        admission_only=candidate_proof.get('document_type')=='qualification_known_admission_cleanup'
        zero_launch=candidate_proof.get('document_type')=='qualification_known_zero_launch_cleanup'
        role_counts={role:sum(row['role']==role for row in ledger['launches']) for role in ROLES}
        if not admission_only and not zero_launch and (active is None or ledger['poisoned'] is not True or len(ledger['launches'])!=12
                or {key:n for key,n in role_counts.items() if n}!={'probe':5,'browser-check':2,'fixture':1,'scripted-inference':1,'boundary':1,'preflight':1,'application-helper':1}
                or any(row['physical']!='absent' or row['container_id'] is None for row in ledger['launches'])
                or any(state['cells'].get(row['cell'],{}).get('attempts')!=1 for row in ledger['launches'])
                or {row['cell'] for row in ledger['launches']}!=set(state['cells'])):_deny('qualification_predecessor_unclean')
        if daemon_id is not None and ledger['daemon']!=daemon_id:_deny('qualification_daemon_changed')
        now,wallnow=_number(clock()),_number(wall())
        if now<ledger['last_now'] or wallnow<ledger['last_wall']:_deny('qualification_clock_invalid')
        if _launch_window and (now>=ledger['deadline']-30 or wallnow>=ledger['deadline_wall']-30):_deny('qualification_deadline')
        refs=value['cleanup_receipts']
        if len(refs)!=1:_deny('qualification_predecessor_unclean')
        import ownership_registry
        admission=full['host_admission'];_exact(admission,{'lock_file','wait_seconds'})
        if type(admission['lock_file']) is not str or not Path(admission['lock_file']).is_absolute() or type(admission['wait_seconds']) is not int or admission['wait_seconds']!=30:_deny('qualification_predecessor_invalid')
        candidate_proof=_bound_json(refs[0]['path'],refs[0]['sha256'])
        known=candidate_proof.get('document_type')=='qualification_known_preworker_cleanup'
        proof=None
        if known or admission_only or zero_launch:
            campaign={k:value[k] for k in ('root','manifest_sha256','ledger_sha256','state_sha256')}
            validator=_known_zero_launch_payload if zero_launch else _known_admission_payload if admission_only else _known_preworker_payload
            proof=validator(campaign,candidate_proof,{'root':root,'full':full,'state':state,'ledger':ledger,'prior':prior},require_released=True)
        for row in ledger['launches']:
            record=_bound_json(Path(admission['lock_file']+'.registry')/(row['launch_id']+'.json'))
            if (record.get('status')!='released' or _intent_identity(record)!=row['intent_sha256'] or record.get('container_id') not in (None,row['container_id'])
                    or record.get('daemon')!=ledger['daemon'] or record.get('registry')!=row['registry'] or record.get('generation')!=row['generation']):_deny('qualification_predecessor_unclean')
            if row['role']=='application-helper' and not known and not admission_only:
                if record.get('qualification_preworker_cleanup')!=refs[0]:_deny('qualification_predecessor_unclean')
                proof=ownership_registry.validate_qualification_preworker_cleanup(record,refs[0],historical_replay=True)
        if proof is None:_deny('qualification_predecessor_unclean')
        lineage=proof['qualification']['lineage']
        if (len(lineage)!=len(prior['lineage'])+1 or lineage[-1]['root']!=str(root)
                or any(lineage[-1][key]['sha256']!=value[key+'_sha256'] for key in ('manifest','state','ledger'))
                or any(entry['root']!=bound['root'] or any(entry[key]['sha256']!=bound[key+'_sha256'] for key in ('manifest','state','ledger')) for entry,bound in zip(lineage,prior['lineage']))):_deny('qualification_predecessor_changed')
        attempts=prior['attempts']+len(ledger['launches']);segments=prior['participant_segments']+sum(row['role']=='participant' for row in ledger['launches'])
        if attempts!=proof['qualification']['cumulative_attempts'] or segments!=proof['qualification']['participant_segments'] or attempts+186>240 or segments+24>24:_deny('qualification_predecessor_limit')
        capacity={key:min(prior['daemon_capacity'][key],ledger['daemon_capacity'][key]) for key in ('cpu_millis','memory_mib')}
        return {'attempts':attempts,'participant_segments':segments,**{key:prior[key] for key in ('started','deadline','started_wall','deadline_wall')},
            'daemon':ledger['daemon'],'daemon_capacity':capacity,'qualification_id':full['qualification_id'],
            **{k:value[k] for k in ('manifest_sha256','ledger_sha256','state_sha256')},'planned_cells':prior['planned_cells']+28,
            'prior_rows':prior['prior_rows']+rows,'lineage':prior['lineage']+[{'root':str(root),'qualification_id':full['qualification_id'],
                **{k:value[k] for k in ('manifest_sha256','state_sha256','ledger_sha256')}}]}
    except (OSError,ValueError,TypeError,KeyError,AttributeError,RecursionError,IndexError) as error:
        if isinstance(error,LaunchError):raise
        raise LaunchError('qualification_predecessor_invalid') from None


def _successor_claim(root,manifest,carry,*,create=False):
    """One permanent successor, outside the predecessor's sealed directory.

    A claim survives a crash before ledger creation and is never released.
    Read-only preparation does not claim; actual ledger creation does, before
    any Docker admission. Separate candidate roots cannot fork a campaign.
    """
    if 'diagnostic' in manifest:
        return amendment_module(manifest['campaign_amendment']).bind_diagnostic(root,manifest,carry,create=create)
    if 'campaign_amendment' in manifest:
        return amendment_module(manifest['campaign_amendment']).bind_final(root,manifest,carry,create=create)
    if len(carry['lineage'])>=8:_deny('qualification_predecessor_cycle')
    if 'campaign_boundary' in manifest:
        import application_campaign
        return application_campaign.bind_final(root,manifest,carry,create=create)
    predecessor=_predecessor_shape(manifest['predecessor'])
    predecessor_root=_canonical_root(predecessor['root'])
    parent=_dir(predecessor_root.parent,False);folder=lock=None
    try:
        info=os.fstat(parent)
        if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o022:_deny('qualification_successor_unavailable')
        if create:
            try:os.mkdir('campaign-successor-claims',0o700,dir_fd=parent);os.fsync(parent)
            except FileExistsError:pass
        folder=os.open('campaign-successor-claims',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        info=os.fstat(folder)
        if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:_deny('qualification_successor_unavailable')
        name=_digest({'root':str(predecessor_root),'qualification_id':carry['qualification_id']})
        # Creating the lock itself is part of the permanent claim. A crash
        # between it and the JSON receipt cannot make the campaign reusable.
        lock=_file(folder,name+'.lock',os.O_RDWR|(os.O_CREAT|os.O_EXCL if create else 0));os.fsync(lock);os.fsync(folder)
        fcntl.flock(lock,fcntl.LOCK_EX)
        expected={'schema':1,'document_type':'qualification_campaign_successor','predecessor_qualification_id':carry['qualification_id'],
            'predecessor_sha256':_digest(manifest['predecessor']),'qualification_id':manifest['qualification_id'],
            'ledger_root':str(Path(root).absolute()),'manifest_sha256':_digest(manifest)}
        if create:
            fd=_file(folder,name+'.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL)
            with os.fdopen(fd,'wb') as stream:stream.write(_json(expected));stream.flush();os.fsync(stream.fileno())
            os.fsync(folder)
        if _read(folder,name+'.json')!=expected:_deny('qualification_successor_unavailable')
    except (OSError,ValueError,TypeError,KeyError) as error:
        if isinstance(error,LaunchError):raise
        raise LaunchError('qualification_successor_unavailable') from None
    finally:
        if lock is not None:os.close(lock)
        if folder is not None:os.close(folder)
        os.close(parent)


def _effective_carry(manifest,*,daemon_id=None,clock=time.monotonic,wall=time.time,_launch_window=True):
    if 'campaign_boundary' not in manifest:
        return validate_predecessor(manifest['predecessor'],daemon_id=daemon_id,clock=clock,wall=wall,_launch_window=_launch_window)
    import application_campaign
    if 'diagnostic' in manifest:
        carry=amendment_module(manifest['campaign_amendment']).validate_diagnostic(manifest['campaign_amendment'],manifest['predecessor'],clock=clock,wall=wall,window=_launch_window)
    elif 'campaign_amendment' in manifest:
        carry=amendment_module(manifest['campaign_amendment']).validate_amendment(manifest['campaign_amendment'],manifest['predecessor'],clock=clock,wall=wall,window=_launch_window)
    else:carry=application_campaign.validate_boundary(manifest['campaign_boundary'],manifest['predecessor'],clock=clock,wall=wall,window=_launch_window)
    if daemon_id is not None and carry['daemon']!=daemon_id:_deny('qualification_daemon_changed')
    return carry


class LaunchLedger:
    def __init__(self,root,manifest,*,daemon_id=None,daemon_capacity=None,clock=time.monotonic,wall=time.time):
        self.root=Path(root).absolute();self.manifest=validate_manifest(manifest);self.clock,self.wall=clock,wall
        self.expected_daemon,self.expected_capacity=daemon_id,copy.deepcopy(daemon_capacity)
        self._carry=None
        fd=_dir(self.root)
        try:self._identity=(os.fstat(fd).st_dev,os.fstat(fd).st_ino)
        finally:os.close(fd)
        self._transaction(lambda state:None)

    @classmethod
    def create(cls,root,manifest,*,daemon_id,daemon_capacity,clock=time.monotonic,wall=time.time):
        manifest=validate_manifest(manifest)
        carry=_effective_carry(manifest,daemon_id=daemon_id,clock=clock,wall=wall) if 'predecessor' in manifest else None
        max_origins=maximum_origins(manifest.get('campaign_amendment'))
        if carry and (len(carry['lineage'])>=max_origins or manifest['qualification_id'] in {row['qualification_id'] for row in carry['lineage']} or manifest['planned_container_launches']+carry['attempts']>manifest['limits']['container_launch_attempts']):_deny('qualification_predecessor_invalid')
        if 'diagnostic' in manifest:
            marker=manifest['diagnostic'];now,wallnow=_number(clock()),_number(wall())
            if now<marker['started'] or wallnow<marker['started_wall'] or now>=marker['deadline']-30 or wallnow>=marker['deadline_wall']-30:_deny('qualification_deadline')
        if carry:_successor_claim(root,manifest,carry,create=True)
        root=Path(root).absolute();parent=_dir(root.parent,False)
        try:os.mkdir(root.name,0o700,dir_fd=parent)
        finally:os.close(parent)
        if type(daemon_id) is not str or not 1<=len(daemon_id)<=256:_deny('qualification_contract_invalid')
        _exact(daemon_capacity,{'cpu_millis','memory_mib'})
        for value in daemon_capacity.values():_integer(value,1,10**12)
        now,wallnow=_number(clock()),_number(wall());fd=_dir(root)
        try:
            lock=_file(fd,'ledger.lock',os.O_RDWR|os.O_CREAT|os.O_EXCL);os.fsync(lock);os.close(lock)
            state={'schema':1,'manifest_sha256':_digest(manifest),'daemon':daemon_id,
                'daemon_capacity':daemon_capacity,'started':carry['started'] if carry else now,
                'deadline':carry['deadline'] if carry else now+14400,'started_wall':carry['started_wall'] if carry else wallnow,
                'deadline_wall':carry['deadline_wall'] if carry else wallnow+14400,'last_now':now,'last_wall':wallnow,'poisoned':False,'launches':[]}
            if 'settlement_diagnostic' in manifest:
                window=manifest['settlement_diagnostic']['clock']
                if (now<window['started'] or wallnow<window['started_wall']
                        or now>=window['deadline']-30 or wallnow>=window['deadline_wall']-30):_deny('qualification_deadline')
                state.update({key:window[key] for key in ('started','deadline','started_wall','deadline_wall')})
            if carry:state['carry']={'descriptor_sha256':_digest(manifest['predecessor']),**{key:carry[key] for key in ('attempts','participant_segments','qualification_id','planned_cells')}}
            _write(fd,'ledger.json',state)
        finally:os.close(fd)
        return cls(root,manifest,clock=clock,wall=wall)

    def _validate(self,state):
        keys={'schema','manifest_sha256','daemon','daemon_capacity','started','deadline','started_wall','deadline_wall','last_now','last_wall','poisoned','launches'}
        if 'predecessor' in self.manifest:
            keys.add('carry');self._carry=getattr(self,'_prevalidated_carry',None) or _effective_carry(self.manifest,daemon_id=state.get('daemon'),clock=self.clock,wall=self.wall,_launch_window=False)
            expected={'descriptor_sha256':_digest(self.manifest['predecessor']),**{key:self._carry[key] for key in ('attempts','participant_segments','qualification_id','planned_cells')}}
            if state.get('carry')!=expected or self.manifest['qualification_id']==self._carry['qualification_id']:_deny('qualification_predecessor_invalid')
            if any(state.get(k)!=self._carry[k] for k in ('started','deadline','started_wall','deadline_wall')):_deny('qualification_predecessor_changed')
            _successor_claim(self.root,self.manifest,self._carry)
        _exact(state,keys)
        if type(state['schema']) is not int or state['schema']!=1 or state['manifest_sha256']!=_digest(self.manifest) or type(state['poisoned']) is not bool:_deny('qualification_state_invalid')
        if type(state['daemon']) is not str or not 1<=len(state['daemon'])<=256:_deny('qualification_state_invalid')
        _exact(state['daemon_capacity'],{'cpu_millis','memory_mib'})
        for value in state['daemon_capacity'].values():_integer(value,1,10**12)
        if self.expected_daemon is not None and state['daemon']!=self.expected_daemon:_deny('qualification_daemon_changed')
        if self.expected_capacity is not None and state['daemon_capacity']!=self.expected_capacity:_deny('qualification_daemon_changed')
        for key in ('started','deadline','started_wall','deadline_wall','last_now','last_wall'):_number(state[key])
        duration=900 if 'settlement_diagnostic' in self.manifest else 14400
        if state['deadline']!=state['started']+duration or state['deadline_wall']!=state['started_wall']+duration:_deny('qualification_state_invalid')
        if 'settlement_diagnostic' in self.manifest:
            window=self.manifest['settlement_diagnostic']['clock']
            if any(state[key]!=window[key] for key in ('started','deadline','started_wall','deadline_wall')):_deny('qualification_state_invalid')
        if type(state['launches']) is not list or len(state['launches'])>self.manifest['limits']['container_launch_attempts']:_deny('qualification_state_invalid')
        keys=set();counts={};cells={c['id']:c for c in self.manifest['cells']}
        for item in state['launches']:
            _exact(item,{'key','cell','role','registry','generation','launch_id','container','image','resources','physical','private_cleanup','pid','intent_sha256','container_id','cleanup_requests','launch_policy'})
            if item['launch_policy'] not in ('explicit_pull_never_owned_id_5s','inserted_pull_never_owned_id_5s'):_deny('qualification_state_invalid')
            _sha(item['key']);_sha(item['registry']);_uuid(item['generation']);_uuid(item['launch_id'])
            _sha(item['intent_sha256'])
            if item['container_id'] is not None:_sha(item['container_id'])
            if type(item['cleanup_requests']) is not list or len(item['cleanup_requests'])>16:_deny('qualification_state_invalid')
            for audit in item['cleanup_requests']:
                _exact(audit,{'operation','requested_target','effective_target'})
                if (audit['operation'] not in ('rm','stop','kill') or audit['requested_target'] not in ('name','immutable_id')
                        or audit['effective_target'] not in ('immutable_id','read_only_absence_check')):_deny('qualification_state_invalid')
            if item['key'] in keys or item['cell'] not in cells or item['role'] not in cells[item['cell']]['role_limits']:_deny('qualification_state_invalid')
            keys.add(item['key']);counts[item['cell'],item['role']]=counts.get((item['cell'],item['role']),0)+1
            if counts[item['cell'],item['role']]>cells[item['cell']]['role_limits'][item['role']]:_deny('qualification_state_invalid')
            if item['image'] not in cells[item['cell']]['allowed_images'] or item['physical'] not in ('pending','started','absent','uncertain') or type(item['private_cleanup']) is not bool:_deny('qualification_state_invalid')
            if item['private_cleanup'] and item['physical']!='absent':_deny('qualification_state_invalid')
            if item['pid'] is not None:_integer(item['pid'],1,2**31-1)
            _slug(item['container']);_exact(item['resources'],{'cpu_millis','memory_mib','pids_limit'})
            for v in item['resources'].values():_integer(v,1,10**9)
            if item['resources']!=_role_weight(self.manifest,cells[item['cell']],item['role']):_deny('qualification_state_invalid')
            if item['key']!=_digest({'registry':item['registry'],'launch_id':item['launch_id']}):_deny('qualification_state_invalid')
        prior=self._carry or {'attempts':0,'participant_segments':0}
        if (len(state['launches'])+prior['attempts']>self.manifest['limits']['container_launch_attempts'] or sum(r['physical']!='absent' for r in state['launches'])>4
                or sum(r['role']=='participant' for r in state['launches'])+prior['participant_segments']>self.manifest['limits']['participant_segments']):_deny('qualification_state_invalid')

    def _transaction(self,operation,*,after_commit=None,preserve_operation_errors=False):
        committed=False;operation_error=False;fd=_dir(self.root)
        try:
            if (os.fstat(fd).st_dev,os.fstat(fd).st_ino)!=self._identity:_deny('qualification_state_invalid')
            lock=_file(fd,'ledger.lock',os.O_RDWR)
            try:
                fcntl.flock(lock,fcntl.LOCK_EX);state=_read(fd,'ledger.json');self._validate(state)
                now,wall=_number(self.clock()),_number(self.wall())
                if now<state['last_now'] or wall<state['last_wall']:
                    state['poisoned']=True;_write(fd,'ledger.json',state);_deny('qualification_clock_invalid')
                state['last_now'],state['last_wall']=now,wall
                try:value=operation(state)
                except BaseException as error:
                    operation_error=preserve_operation_errors
                    if isinstance(error,LaunchError):_write(fd,'ledger.json',state)
                    raise
                self._validate(state);_write(fd,'ledger.json',state);committed=True
                return after_commit(value,state,fd,lock) if after_commit is not None else value
            finally:os.close(lock)
        except (OSError,ValueError,TypeError,KeyError,RecursionError) as error:
            if committed or operation_error or isinstance(error,LaunchError):raise
            raise LaunchError('qualification_state_invalid') from None
        finally:os.close(fd)

    def _reserve_apply(self,state,cell_id,role,record,weight,daemon,*,pull_policy):
        if state['poisoned']:_deny('qualification_accounting_unavailable')
        cell=next((c for c in self.manifest['cells'] if c['id']==cell_id),None)
        if cell is None or role not in cell['role_limits']:_deny()
        expected_image=self.manifest['images']['core-'+cell['release']]['id'] if role in EXTERNAL else cell['image_id']
        if record['image']!=expected_image or weight!=_role_weight(self.manifest,cell,role):_deny('qualification_resources_invalid')
        if daemon['id']!=state['daemon']:_deny('qualification_daemon_changed')
        rows=state['launches'];live=[r for r in rows if r['physical']!='absent']
        prior=self._carry or {'attempts':0,'participant_segments':0}
        if 'diagnostic' in self.manifest:
            marker=self.manifest['diagnostic']
            if state['last_now']>=marker['deadline']-30 or state['last_wall']>=marker['deadline_wall']-30:_deny('qualification_deadline')
        _hard_admission(attempts=len(rows)+prior['attempts'],live=len(live),segments=sum(r['role']=='participant' for r in rows)+prior['participant_segments'],participant=role=='participant',now=state['last_now'],deadline=state['deadline'],limits=self.manifest['limits'])
        if state['last_wall']>=state['deadline_wall']-30:_deny('qualification_deadline')
        if sum(r['cell']==cell_id and r['role']==role for r in rows)>=cell['role_limits'][role]:_deny('qualification_role_limit')
        if any(r['cell']!=cell_id and not r['private_cleanup'] for r in rows):_deny('qualification_prior_cleanup_unconfirmed')
        capacity=self._carry['daemon_capacity'] if self._carry else state['daemon_capacity']
        if any(sum(r['resources'][key] for r in live)+weight[key]>min(state['daemon_capacity'][key],capacity[key],daemon[key])/2 for key in ('cpu_millis','memory_mib')):_deny('qualification_aggregate_limit')
        key=_digest({'registry':record['registry'],'launch_id':record['launch_id']})
        if any(r['key']==key for r in rows):_deny('qualification_duplicate_launch')
        item={'key':key,'cell':cell_id,'role':role,'registry':record['registry'],'generation':record['generation'],
              'launch_id':record['launch_id'],'container':record['container'],'image':record['image'],'resources':weight,
              'physical':'pending','private_cleanup':False,'pid':None,'intent_sha256':_intent_identity(record),
              'container_id':None,'cleanup_requests':[],'launch_policy':pull_policy+'_pull_never_owned_id_5s'}
        rows.append(copy.deepcopy(item));return key

    def reserve(self,cell_id,role,record,weight,daemon,*,pull_policy='explicit'):
        return self._transaction(lambda state:self._reserve_apply(state,cell_id,role,record,weight,daemon,pull_policy=pull_policy))

    def _note_apply(self,state,key,*,pid=None,physical=None,private_cleanup=None,poison=False,container_id=None,cleanup_request=None):
        rows=[r for r in state['launches'] if r['key']==key]
        if len(rows)!=1:_deny('qualification_state_invalid')
        item=rows[0]
        if pid is not None:item['pid']=pid
        if container_id is not None:
            _sha(container_id)
            if item['container_id'] not in (None,container_id):_deny('qualification_ownership_changed')
            item['container_id']=container_id
        if cleanup_request is not None:
            if len(item['cleanup_requests'])>=16:_deny('qualification_cleanup_limit')
            item['cleanup_requests'].append(copy.deepcopy(cleanup_request))
        if physical is not None:
            if item['physical']=='absent' and physical!='absent' and not (physical=='uncertain' and poison):_deny('qualification_state_invalid')
            item['physical']=physical
            if physical=='uncertain':item['private_cleanup']=False
        if private_cleanup is not None:item['private_cleanup']=private_cleanup
        state['poisoned']=state['poisoned'] or poison

    def note(self,key,*,pid=None,physical=None,private_cleanup=None,poison=False,container_id=None,cleanup_request=None):
        return self._transaction(lambda state:self._note_apply(state,key,pid=pid,physical=physical,private_cleanup=private_cleanup,poison=poison,container_id=container_id,cleanup_request=cleanup_request))

    def poison_scope(self,cell_id,*,force=False):
        def apply(state):
            pending=[row for row in state['launches'] if row['cell']==cell_id and not row['private_cleanup']]
            if pending or force:
                state['poisoned']=True
                for row in pending:
                    if row['physical']!='absent':row['physical']='uncertain'
        self._transaction(apply)

    def _snapshot_view(self,state):
        rows=state['launches'];prior=self._carry or {'attempts':0,'participant_segments':0}
        result={'schema':1,'daemon':state['daemon'],'attempts':len(rows)+prior['attempts'],'live':sum(r['physical']!='absent' for r in rows),
            'participant_segments':sum(r['role']=='participant' for r in rows)+prior['participant_segments'],'private_cleanup_pending':sum(not r['private_cleanup'] for r in rows),
            'poisoned':state['poisoned'],'remaining_seconds':max(0,min(state['deadline']-state['last_now'],state['deadline_wall']-state['last_wall'])),
            'launches':copy.deepcopy(rows)}
        if self._carry:result['predecessor']={'attempts':prior['attempts'],'participant_segments':prior['participant_segments'],
            'qualification_id':prior['qualification_id'],'planned_cells':prior['planned_cells'],'prior_rows':copy.deepcopy(prior['prior_rows'])}
        if 'diagnostic' in self.manifest:
            marker=self.manifest['diagnostic'];result['remaining_seconds']=max(0,min(result['remaining_seconds'],marker['deadline']-state['last_now'],marker['deadline_wall']-state['last_wall']))
        if 'startup_diagnostic' in prior:result['startup_diagnostic']=copy.deepcopy(prior['startup_diagnostic'])
        if 'campaign_boundary' in prior:
            result['campaign_boundary']={'reference':copy.deepcopy(prior['campaign_boundary']),'base_attempts':prior['base_attempts'],
                'auxiliary_attempts':prior['auxiliary_attempts'],'original_window':copy.deepcopy(prior['original_window']),
                'authorized_window':copy.deepcopy(prior['previous_window']) if 'previous_window' in prior else {key:prior[key] for key in ('started','deadline','started_wall','deadline_wall')}}
        if 'campaign_amendment' in prior:
            result['campaign_amendment']={'reference':copy.deepcopy(prior['campaign_amendment']),'attempts':prior['attempts'],
                'participant_segments':prior['participant_segments'],'planned_cells':prior['planned_cells'],'maximum_matrix_origins':maximum_origins(prior['campaign_amendment']),
                'container_launch_attempts':self.manifest['limits']['container_launch_attempts'],'deadline_wall':prior['deadline_wall']}
        return result

    def snapshot(self):
        return self._transaction(lambda state:self._snapshot_view(state))

    def _dispatch_ready_check(self,state,key):
        if state['poisoned'] or not any(row['key']==key and row['physical']=='pending' for row in state['launches']):_deny('qualification_accounting_unavailable')
        if state['last_now']>=state['deadline']-30 or state['last_wall']>=state['deadline_wall']-30:_deny('qualification_deadline')
        if 'diagnostic' in self.manifest:
            marker=self.manifest['diagnostic']
            if state['last_now']>=marker['deadline']-30 or state['last_wall']>=marker['deadline_wall']-30:_deny('qualification_deadline')

    def dispatch_ready(self,key):
        return self._transaction(lambda state:self._dispatch_ready_check(state,key))

    def refuse_poisoned(self):
        """Read-only early refusal, never an admission or a cached validation.

        The full locked validation still runs before every native delegate.
        """
        root=_dir(self.root);lock=None
        try:
            if (os.fstat(root).st_dev,os.fstat(root).st_ino)!=self._identity:_deny('qualification_state_invalid')
            lock=_file(root,'ledger.lock',os.O_RDONLY);fcntl.flock(lock,fcntl.LOCK_SH)
            state=_read(root,'ledger.json')
            if type(state) is not dict or type(state.get('poisoned')) is not bool:_deny('qualification_state_invalid')
            if state['poisoned']:_deny('qualification_accounting_unavailable')
        finally:
            if lock is not None:os.close(lock)
            os.close(root)

    def _logical_clock(self,state):
        now,wall=_number(self.clock()),_number(self.wall())
        if now<state['last_now'] or wall<state['last_wall']:
            state['poisoned']=True;_deny('qualification_clock_invalid')
        state['last_now'],state['last_wall']=now,wall

    def _remaining_now(self,state):
        now,wall=_number(self.clock()),_number(self.wall())
        if now<state['last_now'] or wall<state['last_wall']:_deny('qualification_clock_invalid')
        remaining=min(state['deadline']-now,state['deadline_wall']-wall)
        if 'diagnostic' in self.manifest:
            marker=self.manifest['diagnostic'];remaining=min(remaining,marker['deadline']-now,marker['deadline_wall']-wall)
        return max(0,remaining)

    def application_dispatch(self,cell_id,record,weight,daemon,delegate,*,pull_policy='explicit',before_delegate=None,role='application-helper'):
        """One pending intent, fsynced before a one-use delegate under its flock.

        All original view/reserve/ready predicates run; history is never cached.
        The lock stays held through delegate return, before PID/identity writes.
        """
        if not callable(delegate) or before_delegate is not None and not callable(before_delegate):_deny('qualification_contract_invalid')
        reserved=[None]
        def apply(state):
            self._logical_clock(state);snapshot=self._snapshot_view(state)
            if snapshot['remaining_seconds']<=30:_deny('qualification_deadline')
            if snapshot['poisoned']:_deny('qualification_accounting_unavailable')
            self._logical_clock(state)
            key=self._reserve_apply(state,cell_id,role,record,weight,daemon,pull_policy=pull_policy);reserved[0]=key
            self._logical_clock(state);self._dispatch_ready_check(state,key)
            return key
        def effect(key,state,root,lock):
            current=_dir(self.root)
            try:
                if (os.fstat(current).st_dev,os.fstat(current).st_ino)!=self._identity:_deny('qualification_state_invalid')
                named=os.stat('ledger.lock',dir_fd=current,follow_symlinks=False);held=os.fstat(lock)
                if (named.st_dev,named.st_ino)!=(held.st_dev,held.st_ino):_deny('qualification_state_invalid')
                if _read(current,'ledger.json')!=state:_deny('qualification_state_invalid')
            finally:os.close(current)
            if before_delegate is not None:before_delegate()
            # Includes post-validation/fsync latency; never reset either helper clock.
            if self._remaining_now(state)<=30:_deny('qualification_deadline')
            if state['poisoned']:_deny('qualification_accounting_unavailable')
            return key,delegate(key)
        try:return self._transaction(apply,after_commit=effect,preserve_operation_errors=True)
        except BaseException:
            if reserved[0] is not None:
                try:self.note(reserved[0],physical='uncertain',poison=True)
                except BaseException:pass  # Keep the original refusal/cancellation.
            raise

    def application_startup(self,cell_id,record,weight,daemon,delegate,capture,*,pull_policy='explicit',before_delegate=None):
        """One helper scope; fresh history initially, before effect and after CID.

        The detached verifier repeats changed-state predicates using only this
        held scope's carry. No live-ledger cache survives this call or unlock.
        """
        if not callable(delegate) or not callable(capture) or before_delegate is not None and not callable(before_delegate):_deny('qualification_contract_invalid')
        root=_dir(self.root);lock=None;state=None;proof=None;validated=False;key=None;pid=None;identifier=None
        def anchored():
            current=_dir(self.root)
            try:
                if (os.fstat(current).st_dev,os.fstat(current).st_ino)!=self._identity:_deny('qualification_state_invalid')
                named=os.stat('ledger.lock',dir_fd=current,follow_symlinks=False);held=os.fstat(lock)
                if (named.st_dev,named.st_ino)!=(held.st_dev,held.st_ino) or _read(current,'ledger.json')!=state:_deny('qualification_state_invalid')
            finally:os.close(current)
        def local(value):
            verifier=object.__new__(LaunchLedger);verifier.root=self.root;verifier.manifest=self.manifest
            verifier.expected_daemon=self.expected_daemon;verifier.expected_capacity=self.expected_capacity
            verifier._carry=None;verifier._prevalidated_carry=proof
            verifier._validate(value)
        try:
            if (os.fstat(root).st_dev,os.fstat(root).st_ino)!=self._identity:_deny('qualification_state_invalid')
            lock=_file(root,'ledger.lock',os.O_RDWR);fcntl.flock(lock,fcntl.LOCK_EX)
            state=_read(root,'ledger.json');self._validate(state);proof=copy.deepcopy(self._carry);validated=True
            self._logical_clock(state);snapshot=self._snapshot_view(state)
            if snapshot['remaining_seconds']<=30:_deny('qualification_deadline')
            if snapshot['poisoned']:_deny('qualification_accounting_unavailable')
            self._logical_clock(state)
            key=self._reserve_apply(state,cell_id,'application-helper',record,weight,daemon,pull_policy=pull_policy)
            self._logical_clock(state);self._dispatch_ready_check(state,key)
            local(state);_write(root,'ledger.json',state)
            anchored()
            if before_delegate is not None:before_delegate()
            # Re-read retained authority after the pending intent is durable and
            # after its current Registry callback, immediately before effects.
            self._validate(state);proof=copy.deepcopy(self._carry);anchored()
            if self._remaining_now(state)<=30:_deny('qualification_deadline')
            if state['poisoned']:_deny('qualification_accounting_unavailable')
            process=delegate(key);actual_pid=process.pid;_integer(actual_pid,1,2**31-1);pid=actual_pid
            self._logical_clock(state);self._note_apply(state,key,pid=pid,physical='started')
            local(state);_write(root,'ledger.json',state)
            identifier,deadline=capture(state,process,self._remaining_now(state));_sha(identifier);_number(deadline)
            self._logical_clock(state);self._note_apply(state,key,container_id=identifier)
            local(state);_write(root,'ledger.json',state)
            # A new read of all retained custody catches drift during the native
            # observation. It deliberately ignores the detached local proof.
            self._validate(state);anchored()
            if self._remaining_now(state)<=30:_deny('qualification_deadline')
            if time.monotonic()>=deadline:_deny('qualification_container_id_unconfirmed')
            return key,process
        except BaseException:
            # Preserve exact exceptions/cancellation and the latest durable PID
            # and CID. Failure accounting never invokes another full transaction
            # while the flock is held and never calls the delegate again.
            if validated:
                try:
                    poisoned=state is not None and state['poisoned']
                    latest=_read(root,'ledger.json');state=latest;anchored()
                    if key is not None and any(row['key']==key for row in latest['launches']):
                        self._note_apply(latest,key,pid=pid,container_id=identifier,physical='uncertain',poison=True)
                    elif poisoned:latest['poisoned']=True
                    local(latest);_write(root,'ledger.json',latest)
                except BaseException:pass
            raise
        finally:
            proof=None
            if lock is not None:os.close(lock)
            os.close(root)

    def application_started(self,key,pid):
        def apply(state):
            self._logical_clock(state);self._note_apply(state,key,pid=pid,physical='started')
            self._logical_clock(state);return self._snapshot_view(state)['remaining_seconds']
        return self._transaction(apply,after_commit=lambda value,state,root,lock:self._remaining_now(state),preserve_operation_errors=True)

    def application_identity(self,guard,registry,record,observed):
        known=[False];key=_digest({'registry':record['registry'],'launch_id':record['launch_id']})
        def apply(state):
            self._logical_clock(state);known[0]=any(row['key']==key for row in state['launches'])
            selected=guard._owned_key_state(state,record,registry)
            if selected is None:_deny('qualification_ownership_missing')
            row=next(row for row in state['launches'] if row['key']==key)
            identifier=guard._verify_owned_observation(record,row,observed)
            self._logical_clock(state);self._note_apply(state,key,container_id=identifier)
            return identifier
        try:return self._transaction(apply,preserve_operation_errors=True)
        except BaseException:
            if known[0]:
                try:self.note(key,physical='uncertain',poison=True)
                except BaseException:pass
            raise

    def application_lifecycle(self,guard,registry,record,original,*,release=False,sensitive_clean=None):
        """Group existing before/after absence checks around one Registry call."""
        key=_digest({'registry':record['registry'],'launch_id':record['launch_id']});known=[False]
        def apply(state):
            self._logical_clock(state);known[0]=any(row['key']==key for row in state['launches'])
            if not known[0]:
                return original(registry,record,sensitive_clean) if release else original(registry,record)
            bounded=record.get('qualification_role') in EXTERNAL and getattr(guard,'_service_cleanup_deadline',None) is not None
            if bounded:guard._service_left()
            guard._physical_state(state,registry,record)
            value=original(registry,record,sensitive_clean) if release else original(registry,record)
            self._logical_clock(state)
            if bounded:guard._service_left()
            if release:
                if sensitive_clean is not True or record.get('status')!='released':_deny('qualification_cleanup_unconfirmed')
                guard._physical_state(state,registry,record)
                self._note_apply(state,key,private_cleanup=True)
            elif value:
                guard._physical_state(state,registry,record)
            else:self._note_apply(state,key,physical='uncertain',poison=True)
            return value
        try:return self._transaction(apply,preserve_operation_errors=True)
        except BaseException:
            if known[0]:
                try:self.note(key,physical='uncertain',poison=True)
                except BaseException:pass
            raise

    def owned_absence(self,guard,registry,record):
        key=_digest({'registry':record['registry'],'launch_id':record['launch_id']});known=[False]
        def apply(state):
            known[0]=any(row['key']==key for row in state['launches'])
            return guard._physical_state(state,registry,record)
        try:return self._transaction(apply,preserve_operation_errors=True)
        except BaseException:
            if known[0]:
                try:self.note(key,physical='uncertain',poison=True)
                except BaseException:pass
            raise

    def assert_cell_released(self,cell_id):
        if cell_id not in {cell['id'] for cell in self.manifest['cells']}:_deny('qualification_contract_invalid')
        if any(row['cell']==cell_id and not row['private_cleanup'] for row in self.snapshot()['launches']):_deny('qualification_cleanup_unconfirmed')


def _options(argv):
    if type(argv) not in (list,tuple) or any(type(x) is not str for x in argv):_deny()
    if Path(argv[0]).name!='docker':return None
    values=list(argv[1:])
    if values[:2]==['container','run']:values=values[1:]
    if not values or values[0]!='run':return ('command',values)
    flags={'--rm','--init','--read-only','--interactive','--detach','-i','-d','-t','--tty'}
    valued={'--name','--label','--platform','--cpus','--memory','--memory-swap','--pids-limit','--user','--cap-drop','--security-opt',
            '--ipc','--network','--network-alias','--publish','--entrypoint','--workdir','--env','--env-file','--mount','--tmpfs',
            '--add-host','--shm-size','--pull','--ulimit','--stop-timeout'}
    options={};index=1
    while index<len(values) and values[index].startswith('-'):
        key,sep,value=values[index].partition('=')
        if key in flags and not sep:value=True
        elif key in valued:
            if not sep:
                index+=1
                if index>=len(values):_deny()
                value=values[index]
        else:_deny()
        options.setdefault(key,[]).append(value);index+=1
    if index>=len(values):_deny()
    image,command=values[index],values[index+1:]
    for key in ('--name','--platform','--cpus','--memory','--memory-swap','--pids-limit'):
        if len(options.get(key,[]))!=1:_deny()
    if options['--platform']!=['linux/arm64']:_deny('qualification_architecture')
    if options.get('--entrypoint')!=['python3']:_deny('qualification_role_invalid')
    if '--pull' in options and options['--pull']!=['never']:_deny('qualification_unplanned_docker')
    def memory(raw):
        match=re.fullmatch(r'([1-9][0-9]*)([bBkKmMgG]?)',raw)
        if match is None:_deny('qualification_resources_invalid')
        return int(match[1])*{'':1,'b':1,'k':1024,'m':1024**2,'g':1024**3}[match[2].lower()]
    try:
        cpu=float(options['--cpus'][0]);pids=int(options['--pids-limit'][0]);mem=memory(options['--memory'][0])
        if not math.isfinite(cpu) or not 0<cpu<=64 or cpu*1000!=int(cpu*1000) or not 1<=pids<=4096 or memory(options['--memory-swap'][0])!=mem:_deny('qualification_resources_invalid')
    except (ValueError,OverflowError):_deny('qualification_resources_invalid')
    if mem%1048576:_deny('qualification_resources_invalid')
    return ('run',options,image,command,{'cpu_millis':int(cpu*1000),'memory_mib':mem//1048576,'pids_limit':pids})


class LaunchGuard:
    def __init__(self,ledger,cell_id,registry_getter,original_popen,command,observe_command=None):
        self.ledger,self.cell_id,self.registry_getter,self.original_popen=ledger,cell_id,registry_getter,original_popen
        self._custom_command=command is not None
        self._observe_command=observe_command
        self.command=command or (lambda argv,timeout=15:subprocess.run(argv,text=True,capture_output=True,timeout=timeout))
        self._networks={}
        self._timings={}

    def _observe(self,argv,timeout=15):
        if self._observe_command is not None:return self._observe_command(argv,timeout=timeout)
        return self.command(argv) if self._custom_command else self.command(argv,timeout=timeout)

    def _daemon(self,timeout=15):
        reply=self._observe(['docker','info','--format','{{json .}}'],timeout)
        if reply.returncode:_deny('qualification_daemon_changed')
        try:value=json.loads(reply.stdout)
        except (ValueError,TypeError):_deny('qualification_daemon_changed')
        if value.get('OSType')!='linux' or value.get('Architecture') not in ('arm64','aarch64'):_deny('qualification_architecture')
        for key in ('NCPU','MemTotal'):_integer(value.get(key),1,10**14)
        return {'id':value.get('ID'),'cpu_millis':value['NCPU']*1000,'memory_mib':value['MemTotal']//1048576}

    def _record(self,registry,options,image):
        if registry is None:_deny('qualification_ownership_missing')
        labels=dict(value.split('=',1) for value in options.get('--label',[]) if '=' in value)
        record=self._authoritative(registry,labels.get(LABEL))
        if (record.get('kind','container')!='container' or record.get('status')!='intent' or record.get('image')!=image
                or record.get('container')!=options['--name'][0] or record.get('registry')!=registry.registry_id
                or labels.get(REGISTRY_LABEL)!=registry.registry_id or record.get('generation')!=registry.generation
                or record.get('daemon')!=registry.daemon or record.get('owner_pid')!=os.getpid()):_deny('qualification_ownership_missing')
        if _mounts(options)!=record.get('mounts'):_deny('qualification_mount_changed')
        if record.get('qualification_role') in EXTERNAL:self._service_mounts(record['mounts'])
        return record

    @staticmethod
    def _authoritative(registry,launch_id):
        _uuid(launch_id);fd=_dir(registry.root)
        try:record=_read(fd,launch_id+'.json')
        finally:os.close(fd)
        if (type(record) is not dict or record.get('launch_id')!=launch_id or record.get('registry')!=registry.registry_id
                or record.get('generation')!=registry.generation or record.get('daemon')!=registry.daemon):_deny('qualification_ownership_changed')
        return record

    @staticmethod
    def _verify_owned_observation(record,row,observed):
        labels=observed.get('Config',{}).get('Labels') or {}
        actual=observed.get('Mounts')
        if (observed.get('Image')!=record['image'] or labels.get(LABEL)!=record['launch_id'] or labels.get(REGISTRY_LABEL)!=record['registry']
                or type(actual) is not list or len(actual)!=len(record['mounts'])
                or any(not any(m.get('Source')==r['source'] and m.get('Destination')==r['target'] and m.get('RW') is r['rw'] for m in actual) for r in record['mounts'])):_deny('qualification_ownership_changed')
        identifier=observed.get('Id');_sha(identifier)
        if row['container_id'] not in (None,identifier) or record.get('container_id') not in (None,identifier):_deny('qualification_ownership_changed')
        return identifier

    def _owned_observation(self,registry,record,observed):
        return self.ledger.application_identity(self,registry,record,observed)

    def _capture(self,registry,record,process,*,remaining=None):
        if remaining is None:remaining=self.ledger.snapshot()['remaining_seconds']
        deadline=time.monotonic()+min(5,max(0,remaining-30))
        while time.monotonic()<deadline:
            left=deadline-time.monotonic()
            if left<=0:break
            daemon=self._daemon(left)
            if daemon['id']!=record['daemon']:_deny('qualification_daemon_changed')
            left=min(1,deadline-time.monotonic())
            if left<=0:break
            reply=self._observe(['docker','container','inspect',record['container']],left)
            if reply.returncode==0:
                data=json.loads(reply.stdout)
                if type(data) is not list or len(data)!=1:_deny('qualification_ownership_changed')
                self._owned_observation(registry,record,data[0])
                if time.monotonic()>=deadline:_deny('qualification_container_id_unconfirmed')
                return
            if not self._absent(reply,record['container']):_deny('qualification_absence_unknown')
            time.sleep(min(.05,max(0,deadline-time.monotonic())))
        _deny('qualification_container_id_unconfirmed')

    def _capture_held(self,registry,record,process,state,*,remaining):
        """The same observation predicates against the already held state."""
        deadline=time.monotonic()+min(5,max(0,remaining-30))
        while time.monotonic()<deadline:
            left=deadline-time.monotonic()
            if left<=0:break
            daemon=self._daemon(left)
            if daemon['id']!=record['daemon']:_deny('qualification_daemon_changed')
            left=min(1,deadline-time.monotonic())
            if left<=0:break
            reply=self._observe(['docker','container','inspect',record['container']],left)
            if reply.returncode==0:
                data=json.loads(reply.stdout)
                if type(data) is not list or len(data)!=1:_deny('qualification_ownership_changed')
                key=self._owned_key_state(state,record,registry)
                if key is None:_deny('qualification_ownership_missing')
                row=next(row for row in state['launches'] if row['key']==key)
                return self._verify_owned_observation(record,row,data[0]),deadline
            if not self._absent(reply,record['container']):_deny('qualification_absence_unknown')
            time.sleep(min(.05,max(0,deadline-time.monotonic())))
        _deny('qualification_container_id_unconfirmed')

    @staticmethod
    def _absent(reply,target):
        return reply.returncode!=0 and re.fullmatch(r'(?:(?:Error response from daemon|Error): )?No such (?:container|object):? '+re.escape(target),reply.stderr.strip()) is not None

    def popen(self,argv,*args,**kwargs):return self.spawn(self.original_popen,argv,*args,**kwargs)

    def recorder_for_helper(self,helper):
        record=getattr(helper,'record',None)
        return self._timings.get(record.get('launch_id')) if type(record) is dict else None

    def flush_timings(self,directory,*,kind='qualification'):
        """Owner invokes after the attempt and cleanup; no critical-path I/O."""
        hashes=timing.source_hashes(kind=kind);results=[]
        for launch_id,recorder in self._timings.items():
            recorder.terminal()
            results.append(timing.flush_terminal(directory,recorder,identity={
                'kind':kind,'scope_id':self.ledger.manifest['qualification_id'],
                'cell_id':self.cell_id,'launch_id':launch_id},source_hashes=hashes))
        return results

    def spawn(self,delegate,argv,*args,**kwargs):
        parsed=_options(argv)
        recorder=None
        if parsed is not None and parsed[0]!='command' and parsed[3][:1]==['/opt/pi-application/runtime/application_client_service.py']:
            recorder=timing.Recorder();recorder.emit('guard_enter')
        try:
            return self._spawn(delegate,argv,parsed,recorder,*args,**kwargs)
        except BaseException:
            if recorder is not None:
                try:recorder.emit('guard_failed',status='raised')
                except BaseException:pass
            raise

    def _spawn(self,delegate,argv,parsed,recorder,*args,**kwargs):
        if parsed is None:return delegate(argv,*args,**kwargs)
        if kwargs.get('shell') or kwargs.get('executable'):_deny()
        # Observe only Docker connection selectors, never application/private
        # environment values. Identity probes and the actual call must target
        # the same CLI/configuration; the original environment is still passed.
        environment=kwargs.get('env')
        if environment is not None:
            if type(environment) is not dict:_deny('qualification_daemon_changed')
            for key in ('PATH','HOME','DOCKER_HOST','DOCKER_CONTEXT','DOCKER_CONFIG','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH','DOCKER_API_VERSION'):
                expected=os.environ.get(key)
                if key=='HOME':expected=str(Path.home())
                if key=='PATH':expected=os.environ.get(key,'/usr/bin:/bin')
                if environment.get(key)!=expected:_deny('qualification_daemon_changed')
        if parsed[0]=='command':
            values=parsed[1]
            effective=self._command_allowed(values,argv)
            if values[:2]==['network','create'] and 'campaign_amendment' in self.ledger.manifest:
                amendment=amendment_module(self.ledger.manifest['campaign_amendment'])
                if amendment.__name__=='application_matrix20':
                    amendment.validate_native_dispatch(self.registry_getter(),self)
            return delegate(effective or argv,*args,**kwargs)
        _,options,image,command,weight=parsed
        # Labels are parsed separately because they may repeat legitimately.
        registry=self.registry_getter();record=self._record(registry,options,image)
        if 'campaign_amendment' in self.ledger.manifest:
            amendment=amendment_module(self.ledger.manifest['campaign_amendment'])
            if amendment.__name__=='application_matrix20':
                amendment.validate_native_dispatch(registry,self,record)
        if recorder is not None:self._timings[record['launch_id']]=recorder
        cell=next((c for c in self.ledger.manifest['cells'] if c['id']==self.cell_id),None)
        if cell is None or image not in cell['allowed_images']:_deny('qualification_image_changed')
        if command[:1]==['/opt/pi-lab/worker.py'] and len(command)>1:role=WORKER_ROLES.get(command[1])
        elif (command[:1]==['/opt/pi-application/runtime/application_client_service.py'] and record.get('application_helper') is True
                and record.get('client_mode')=='application-execution'):role='application-helper'
        else:role=record.get('qualification_role') if command[:1]==[EXTERNAL.get(record.get('qualification_role'))] and record.get('qualification_cell')==self.cell_id else None
        if role is None:_deny('qualification_role_invalid')
        self.ledger.refuse_poisoned()
        daemon=self._daemon()
        if record['daemon']!=daemon['id']:_deny('qualification_daemon_changed')
        observed=self.command(['docker','image','inspect',image])
        try:data=json.loads(observed.stdout)
        except (ValueError,TypeError):_deny('qualification_image_changed')
        if observed.returncode or type(data) is not list or len(data)!=1 or data[0].get('Id')!=image or data[0].get('Architecture')!='arm64' or data[0].get('Os')!='linux':_deny('qualification_image_changed')
        if recorder is not None:recorder.emit('prelaunch_checks_done')
        effective=argv
        if '--pull' not in options:
            index=2 if list(argv[1:2])==['run'] else 3
            effective=list(argv[:index])+['--pull=never']+list(argv[index:])
        key=None
        try:
            def dispatch(reserved):
                nonlocal key
                key=reserved
                if recorder is not None:
                    recorder.emit('reserve_done');recorder.emit('dispatch_ready_done');recorder.emit('delegate_enter')
                value=delegate(effective,*args,**kwargs)
                if recorder is not None:recorder.emit('delegate_return')
                return value
            def revalidate():
                if _intent_identity(self._record(registry,options,image))!=_intent_identity(record):_deny('qualification_ownership_changed')
            if role=='application-helper':
                def capture(state,process,remaining):
                    if recorder is not None:recorder.emit('capture_enter')
                    return self._capture_held(registry,record,process,state,remaining=remaining)
                key,process=self.ledger.application_startup(self.cell_id,record,weight,daemon,dispatch,capture,
                    pull_policy='explicit' if '--pull' in options else 'inserted',before_delegate=revalidate)
            else:
                key,process=self.ledger.application_dispatch(self.cell_id,record,weight,daemon,dispatch,
                    pull_policy='explicit' if '--pull' in options else 'inserted',before_delegate=revalidate,role=role)
                remaining=self.ledger.application_started(key,process.pid)
                if recorder is not None:recorder.emit('capture_enter')
                self._capture(registry,record,process,remaining=remaining)
            if recorder is not None:
                recorder.emit('capture_return');recorder.emit('guard_return')
            return process
        except BaseException:
            if key is not None and role!='application-helper':
                try:self.ledger.note(key,physical='uncertain',poison=True)
                except BaseException:pass
            raise

    def _command_allowed(self,values,argv):
        if not values:_deny('qualification_unplanned_docker')
        if values[0] in ('info','version','ps','port','inspect') or values[:2] in (
                ['context','show'],['context','inspect'],['image','inspect'],['image','ls'],
                ['container','inspect'],['container','ls'],['network','inspect'],['network','ls']):return
        registry=self.registry_getter()
        if registry is None:_deny('qualification_ownership_missing')
        records=[self._authoritative(registry,row['launch_id']) for row in self.ledger.snapshot()['launches']
            if row['cell']==self.cell_id and row['registry']==registry.registry_id and row['generation']==registry.generation]
        if values[:3]==['logs','--tail','20'] and len(values)==4:
            for record in records:
                if record.get('qualification_role') not in EXTERNAL or record.get('qualification_cell')!=self.cell_id:continue
                key=self.owned_key(record)
                if key is None:continue
                bound=next(row['container_id'] for row in self.ledger.snapshot()['launches'] if row['key']==key)
                # Startup can fail before the readiness owner publishes its ID
                # to Registry. The guard's postlaunch ownership observation has
                # already frozen the same immutable ID in the central ledger.
                if values[-1] in (record['container'],record.get('container_id'),bound):return
            _deny('qualification_ownership_missing')
        if values[:2]==['network','create']:
            labels=[]
            for index,value in enumerate(values):
                if value=='--label' and index+1<len(values):labels.append(values[index+1])
                elif value.startswith('--label='):labels.append(value.split('=',1)[1])
            fields=dict(label.split('=',1) for label in labels if '=' in label)
            record=self._authoritative(registry,fields.get(LABEL))
            if (record.get('kind')!='network' or record['container']!=values[-1] or record.get('status')!='intent'
                    or fields.get(REGISTRY_LABEL)!=registry.registry_id):_deny('qualification_ownership_missing')
            self._networks[record['container']]=record
            return
        normalized=values[1:] if values[:1]==['container'] else values
        kind='network' if values[:2]==['network','rm'] else 'container'
        if kind=='network':normalized=values[1:]
        if normalized[:1] not in (['rm'],['stop'],['kill']):_deny('qualification_unplanned_docker')
        flags={'-f','--force','-v','--volumes'};targets=[];index=1
        while index<len(normalized):
            value=normalized[index]
            if value in ('--signal','--time','-s','-t'):
                index+=1
                if index>=len(normalized):_deny()
            elif value in flags or value.startswith(('--signal=','--time=')):pass
            elif value.startswith('-'):_deny()
            else:targets.append(value)
            index+=1
        if not targets:_deny('qualification_unplanned_docker')
        if len(targets)!=1:_deny('qualification_unplanned_docker')
        if kind=='network':
            for target in targets:
                record=self._networks.get(target)
                if record is None:_deny('qualification_ownership_missing')
                authoritative=self._authoritative(registry,record['launch_id'])
                if _intent_identity(authoritative)!=_intent_identity(record):_deny('qualification_ownership_changed')
                if self._daemon()['id']!=record['daemon']:_deny('qualification_daemon_changed')
                reply=self._observe(['docker','network','inspect',target])
                if reply.returncode:
                    return [argv[0],'network','inspect',target]
                data=json.loads(reply.stdout)
                if type(data) is not list or len(data)!=1:_deny('qualification_ownership_changed')
                data=data[0];labels=data.get('Labels') or {};identifier=data.get('Id');_sha(identifier)
                if (data.get('Driver')!='bridge' or data.get('Containers') or labels.get(LABEL)!=record['launch_id']
                        or labels.get(REGISTRY_LABEL)!=record['registry']):_deny('qualification_ownership_changed')
                effective=list(argv);positions=[index for index,value in enumerate(argv) if value==target]
                if len(positions)!=1:_deny('qualification_unplanned_docker')
                effective[positions[0]]=identifier;return effective
        target=targets[0];key=None
        try:
            daemon=self._daemon()
            if daemon['id']!=registry.daemon:_deny('qualification_daemon_changed')
            reply=self._observe(['docker','container','inspect',target])
            data=json.loads(reply.stdout) if reply.returncode==0 else None
            matching=[r for r in records if r.get('kind','container')=='container' and target in (r.get('container'),r.get('container_id'))]
            if not matching and type(data) is list and len(data)==1:
                labels=data[0].get('Config',{}).get('Labels') or {}
                matching=[r for r in records if r['launch_id']==labels.get(LABEL) and r['registry']==labels.get(REGISTRY_LABEL)]
            if len(matching)!=1:_deny('qualification_ownership_missing')
            record=matching[0];key=self.owned_key(record,registry)
            if key is None:_deny('qualification_ownership_missing')
            row=next(r for r in self.ledger.snapshot()['launches'] if r['key']==key)
            if reply.returncode==0:
                if type(data) is not list or len(data)!=1:_deny('qualification_ownership_changed')
                identifier=self._owned_observation(registry,record,data[0]);effective=list(argv);classification='immutable_id'
                positions=[index for index,value in enumerate(argv) if value==target]
                if len(positions)!=1:_deny('qualification_unplanned_docker')
                effective[positions[0]]=identifier
            elif self._absent(reply,target):
                if row['container_id'] is not None:
                    effective=list(argv);positions=[index for index,value in enumerate(argv) if value==target]
                    if len(positions)!=1:_deny('qualification_unplanned_docker')
                    effective[positions[0]]=row['container_id'];classification='immutable_id'
                else:
                    effective=[argv[0],'container','inspect',target];classification='read_only_absence_check'
            else:_deny('qualification_absence_unknown')
            self.ledger.note(key,cleanup_request={'operation':normalized[0],'requested_target':'immutable_id' if re.fullmatch('[a-f0-9]{64}',target) else 'name','effective_target':classification})
            return effective
        except BaseException:
            if key:self.ledger.note(key,physical='uncertain',poison=True)
            else:self.ledger.poison_scope(self.cell_id,force=True)
            raise

    def service_readiness_check(self,record,observed,deadline):
        diagnostic=None
        try:
            diagnostic=timing.ServiceDiagnostic(clock=time.monotonic,command_deadline=deadline,
                cleanup_deadline=getattr(self,'_service_cleanup_deadline',None),readiness=True)
            return self._service_readiness_check(record,observed,deadline,diagnostic)
        except BaseException as error:
            try:
                value=diagnostic.snapshot() if diagnostic is not None else None
                if value is not None:error.service_deadline_diagnostic=value
            except BaseException:pass
            raise

    def _service_readiness_check(self,record,observed,deadline,diagnostic):
        """Fixture-only custody for one fresh caller inspection, without adoption.

        The caller's record can still have no CID. Only the already captured
        central immutable ID may be returned; no record is updated here.
        """
        _number(deadline);registry=self.registry_getter()
        if (type(record) is not dict or type(observed) is not dict or registry is None
                or record.get('qualification_role')!='fixture' or record.get('qualification_cell')!=self.cell_id
                or record.get('kind','container')!='container' or record.get('status') not in ('intent','running')):_deny('qualification_role_invalid')
        def left(state):
            self.ledger._logical_clock(state)
            now=time.monotonic();campaign=self.ledger._remaining_now(state)
            cleanup=getattr(self,'_service_cleanup_deadline',None)
            absolute=min(deadline,cleanup) if cleanup is not None else deadline
            remaining=min(absolute-now,campaign);diagnostic.observed_remaining(now,campaign)
            if remaining<=0:_deny('qualification_deadline')
            return remaining
        def identity(state,*,initial=False):
            if initial:diagnostic.mark('ownership_check')
            key=self._owned_key_state(state,record,registry)
            if key is None:_deny('qualification_ownership_missing')
            row=next(row for row in state['launches'] if row['key']==key)
            if (state['poisoned'] or row['role']!='fixture' or row['cell']!=self.cell_id or row['physical']!='started'
                    or row['pid'] is None):_deny('qualification_ownership_changed')
            if row['container_id'] is None:_deny('qualification_container_id_unconfirmed')
            if initial:diagnostic.mark('container_check')
            return self._verify_owned_observation(record,row,observed)
        def prepare(state):
            try:
                left(state);identifier=identity(state,initial=True)
                diagnostic.mark('daemon_check');daemon=self._daemon(left(state))
                if daemon['id']!=record['daemon'] or daemon['id']!=state['daemon']:_deny('qualification_daemon_changed')
                left(state);diagnostic.mark('authority_commit');return identifier
            except BaseException:
                try:diagnostic.freeze_failure()
                except BaseException:pass
                raise
        def committed(identifier,state,root,lock):
            try:
                diagnostic.mark('durable_fence');current=_dir(self.ledger.root)
                try:
                    if (os.fstat(current).st_dev,os.fstat(current).st_ino)!=self.ledger._identity:_deny('qualification_state_invalid')
                    named=os.stat('ledger.lock',dir_fd=current,follow_symlinks=False);held=os.fstat(lock)
                    if (named.st_dev,named.st_ino)!=(held.st_dev,held.st_ino) or _read(current,'ledger.json')!=state:_deny('qualification_state_invalid')
                finally:os.close(current)
                diagnostic.mark('ownership_recheck')
                if identity(state)!=identifier:_deny('qualification_ownership_changed')
                diagnostic.mark('readiness_acceptance');left(state);return identifier
            except BaseException:
                try:diagnostic.freeze_failure()
                except BaseException:pass
                raise
        return self.ledger._transaction(prepare,after_commit=committed,preserve_operation_errors=True)

    def service_process(self,record,operation,deadline,**kwargs):
        diagnostic=None
        try:
            diagnostic=timing.ServiceDiagnostic(clock=time.monotonic,command_deadline=deadline,
                cleanup_deadline=getattr(self,'_service_cleanup_deadline',None))
            return self._service_process(record,operation,deadline,diagnostic,**kwargs)
        except BaseException as error:
            # Failure metadata cannot replace the original guard/cancellation.
            try:
                value=diagnostic.snapshot() if diagnostic is not None else None
                if value is not None:error.service_deadline_diagnostic=value
            except BaseException:pass
            raise

    def _service_process(self,record,operation,deadline,diagnostic,**kwargs):
        """Fresh, single-command external-service custody; never an admission cache.

        The anchored transaction stays locked through durable audit and Popen.
        Only the fixed logs/stop/rm grammar can reach the captured delegate.
        """
        if operation not in ('logs','stop','rm'):_deny('qualification_unplanned_docker')
        if set(kwargs)-{'stdout','stderr','text'} or any(kwargs.get(key) not in (None,subprocess.PIPE) for key in ('stdout','stderr')) or ('text' in kwargs and type(kwargs['text']) is not bool):_deny('qualification_unplanned_docker')
        _number(deadline);registry=self.registry_getter();key=None;last_observed_now=None
        def left(state):
            nonlocal last_observed_now
            self.ledger._logical_clock(state)
            bound=getattr(self,'_service_cleanup_deadline',None)
            absolute=min(deadline,bound) if bound is not None else deadline
            now=time.monotonic();campaign=self.ledger._remaining_now(state)
            last_observed_now=now
            remaining=min(absolute-now,campaign)
            diagnostic.observed_remaining(now,campaign)
            if remaining<=0:_deny('qualification_deadline')
            return remaining
        def prepare(state):
            nonlocal key
            left(state)
            diagnostic.mark('ownership_check')
            if registry is None or record.get('qualification_role') not in EXTERNAL or record.get('qualification_cell')!=self.cell_id:_deny('qualification_role_invalid')
            candidate=_digest({'registry':record['registry'],'launch_id':record['launch_id']})
            if any(row['key']==candidate for row in state['launches']):key=candidate
            selected=self._owned_key_state(state,record,registry)
            if selected is None:_deny('qualification_ownership_missing')
            row=next(row for row in state['launches'] if row['key']==key)
            if row['cell']!=self.cell_id or row['role']!=record['qualification_role']:_deny('qualification_role_invalid')
            diagnostic.mark('daemon_check')
            if self._daemon(left(state))['id']!=record['daemon']:_deny('qualification_daemon_changed')
            target=row['container_id'] or record.get('container_id') or record['container']
            diagnostic.mark('container_check')
            reply=self._observe(['docker','container','inspect',target],left(state))
            if reply.returncode==0:
                data=json.loads(reply.stdout)
                if type(data) is not list or len(data)!=1:_deny('qualification_ownership_changed')
                identifier=self._verify_owned_observation(record,row,data[0])
                self.ledger._note_apply(state,key,container_id=identifier)
                classification='immutable_id'
            elif self._absent(reply,target):
                identifier=row['container_id'];classification='immutable_id' if identifier else 'read_only_absence_check'
                if operation=='logs':_deny('qualification_ownership_missing')
            else:_deny('qualification_absence_unknown')
            diagnostic.mark('command_preparation')
            if operation=='logs':argv=['docker','logs','--tail','20',identifier]
            elif identifier:
                argv=['docker',operation,*(['--time','15'] if operation=='stop' else []),identifier]
            else:argv=['docker','container','inspect',target]
            if operation!='logs':
                self.ledger._note_apply(state,key,cleanup_request={'operation':operation,'requested_target':'immutable_id' if record.get('container_id') else 'name','effective_target':classification})
            left(state);return argv
        def fenced(state,lock):
            current=_dir(self.ledger.root)
            try:
                if (os.fstat(current).st_dev,os.fstat(current).st_ino)!=self.ledger._identity:_deny('qualification_state_invalid')
                named=os.stat('ledger.lock',dir_fd=current,follow_symlinks=False);held=os.fstat(lock)
                if (named.st_dev,named.st_ino)!=(held.st_dev,held.st_ino) or _read(current,'ledger.json')!=state:_deny('qualification_state_invalid')
            finally:os.close(current)
        def effect(argv,state,root,lock):
            diagnostic.mark('durable_fence')
            fenced(state,lock)
            # The post-operation full authority read/fsync can consume time or
            # expose Registry drift. No effect uses a pre-guard timeout budget.
            diagnostic.mark('ownership_recheck')
            if self._owned_key_state(state,record,registry)!=key:_deny('qualification_ownership_changed')
            diagnostic.mark('delegate_gate')
            left(state)
            # Reuse the existing gate sample: telemetry cannot add a clock
            # callback between the authoritative deadline check and Popen.
            diagnostic.mark('delegate',observed_now=last_observed_now)
            return self.original_popen(argv,**kwargs)
        def prepared(state):
            try:
                value=prepare(state);diagnostic.mark('authority_commit');return True,value
            except BaseException as error:
                try:diagnostic.freeze_failure()
                except BaseException:pass
                if operation!='logs' and key is not None:
                    self.ledger._note_apply(state,key,physical='uncertain',poison=True)
                # Commit failure accounting through the same validated/fsynced
                # transaction, then rethrow the exact error without delegation.
                return False,error
        def committed(value,state,root,lock):
            ready,payload=value
            if not ready:raise payload
            durable=copy.deepcopy(state)
            try:return effect(payload,state,root,lock)
            except BaseException:
                try:diagnostic.freeze_failure()
                except BaseException:pass
                if operation!='logs' and key is not None:
                    try:
                        # Never overwrite a replaced/tampered authority during
                        # failure accounting; retain its unconfirmed disposition.
                        fenced(durable,lock)
                        self.ledger._note_apply(state,key,physical='uncertain',poison=True)
                        _write(root,'ledger.json',state)
                    except BaseException:pass
                raise
        return self.ledger._transaction(prepared,after_commit=committed,preserve_operation_errors=True)

    @contextlib.contextmanager
    def service_cleanup(self,registry,deadline):
        """Only external lifecycle observations share this caller's fixed budget."""
        _number(deadline)
        if getattr(self,'_service_cleanup_deadline',None) is not None:_deny('qualification_nested_instrumentation')
        original=registry.command;self._service_cleanup_deadline=deadline
        def observe(argv):
            if argv[:3]!=['docker','container','inspect'] or len(argv)!=4:_deny('qualification_unplanned_docker')
            return self._observe(argv,self._service_left())
        registry.command=observe
        try:yield
        finally:
            registry.command=original;self._service_cleanup_deadline=None

    def _service_left(self):
        remaining=self._service_cleanup_deadline-time.monotonic()
        if remaining<=0:_deny('qualification_deadline')
        return remaining

    def external_service_intent(self,registry,argv,role,runroot):
        parsed=_options(argv)
        if role not in EXTERNAL or parsed is None or parsed[0]!='run' or parsed[3][:1]!=[EXTERNAL[role]]:_deny('qualification_role_invalid')
        _,options,image,command,weight=parsed;name=options['--name'][0]
        cell=next((cell for cell in self.ledger.manifest['cells'] if cell['id']==self.cell_id),None)
        if cell is None or role not in cell['role_limits'] or image not in cell['allowed_images']:_deny('qualification_role_invalid')
        if registry is None or registry.daemon is None:_deny('qualification_ownership_missing')
        mounts=_mounts(options);self._service_mounts(mounts)
        record={'schema':1,'launch_id':str(uuid.uuid4()),'registry':registry.registry_id,'generation':registry.generation,
                'status':'intent','container':name,'image':image,'mounts':mounts,'binding':copy.deepcopy(registry.binding),
                'daemon':registry.daemon,'runroot':str(Path(runroot).absolute()),'owner_pid':os.getpid(),
                'qualification_cell':self.cell_id,'qualification_role':role,
                'application_helper':True,'client_mode':'qualification-'+role}
        registry.write(record)
        # Preserve docker run spelling; real registry labels precede every effect.
        index=2 if argv[1]=='run' else 3
        labelled=list(argv[:index])+['--label',LABEL+'='+record['launch_id'],'--label',REGISTRY_LABEL+'='+registry.registry_id]+list(argv[index:])
        return record,labelled

    def _service_mounts(self,mounts):
        by_target={row['target']:row for row in mounts};repository=Path(__file__).resolve().parents[2]
        if set(by_target)!={'/opt/pi-skill','/qualification','/private','/observations'}:_deny('qualification_mount_changed')
        for target,source in (('/opt/pi-skill',repository/'skill'),('/qualification',repository/'tools/qualification')):
            if by_target[target]!={'source':str(source),'target':target,'rw':False}:_deny('qualification_mount_changed')
        private=Path(by_target['/private']['source']);observations=Path(by_target['/observations']['source'])
        if by_target['/private']['rw'] or not by_target['/observations']['rw']:_deny('qualification_mount_changed')
        if private==self.ledger.root.parent or self.ledger.root.parent in private.parents:_deny('qualification_mount_changed')
        if self.ledger.root.parent/'cells'/self.cell_id not in observations.parents:_deny('qualification_mount_changed')
        for path in (private,observations):fd=_dir(path);os.close(fd)

    def _owned_key_state(self,state,record,registry):
        key=_digest({'registry':record['registry'],'launch_id':record['launch_id']})
        rows=[row for row in state['launches'] if row['key']==key]
        if not rows:return None
        row=rows[0];current=self._authoritative(registry,record['launch_id'])
        if (_intent_identity(record)!=row['intent_sha256'] or _intent_identity(current)!=row['intent_sha256']
                or current.get('status')!=record.get('status') or current.get('container_id')!=record.get('container_id')
                or registry.registry_id!=row['registry'] or registry.generation!=row['generation'] or record.get('daemon')!=state['daemon']
                or row['container_id'] is not None and record.get('container_id') not in (None,row['container_id'])):_deny('qualification_ownership_changed')
        return key

    def owned_key(self,record,registry=None):
        key=_digest({'registry':record['registry'],'launch_id':record['launch_id']})
        snapshot=self.ledger.snapshot()
        try:return self._owned_key_state(snapshot,record,registry or self.registry_getter())
        except BaseException:
            self.ledger.note(key,physical='uncertain',poison=True);raise

    def _physical_state(self,state,registry,record):
        self.ledger._logical_clock(state)
        key=self._owned_key_state(state,record,registry)
        if key is None:return None
        bounded=record.get('qualification_role') in EXTERNAL and getattr(self,'_service_cleanup_deadline',None) is not None
        daemon=self._daemon(self._service_left()) if bounded else self._daemon()
        if daemon['id']!=record['daemon']:_deny('qualification_daemon_changed')
        row=next(r for r in state['launches'] if r['key']==key)
        if row['container_id'] is None:_deny('qualification_container_id_unconfirmed')
        reply=self._observe(['docker','container','inspect',row['container_id']],self._service_left()) if bounded else self._observe(['docker','container','inspect',row['container_id']])
        if bounded:self._service_left()
        if not self._absent(reply,row['container_id']):_deny('qualification_absence_unknown')
        self.ledger._logical_clock(state);self.ledger._note_apply(state,key,physical='absent')
        return key

    def confirm_physical(self,registry,record):
        self.ledger.owned_absence(self,registry,record)

    def release(self,registry,record,*,owner_cleanup_confirmed):
        key=self.owned_key(record)
        if key is None:return
        if owner_cleanup_confirmed is not True or record.get('status')!='released':_deny('qualification_cleanup_unconfirmed')
        self.confirm_physical(registry,record);self.ledger.note(key,private_cleanup=True)

    def assert_cell_released(self):return self.ledger.assert_cell_released(self.cell_id)


@contextlib.contextmanager
def instrument(ledger,cell_id,*,registry_getter=None,original_popen=None,command=None,observe_command=None):
    """Process-scoped reviewed qualification hooks; no runtime files are edited."""
    import ownership_registry
    from application_client import OwnedHelper
    if cell_id not in {cell['id'] for cell in ledger.manifest['cells']}:_deny('qualification_contract_invalid')
    if not _PATCH_LOCK.acquire(blocking=False):_deny('qualification_nested_instrumentation')
    original=subprocess.Popen;helper=OwnedHelper.__dict__['start'];confirm=ownership_registry.Registry.confirm_absent;release=ownership_registry.Registry.release
    guard=LaunchGuard(ledger,cell_id,registry_getter or ownership_registry.CURRENT.get,original_popen or original,command,observe_command)
    function=helper.__func__;default=inspect.signature(function).parameters['popen'].default
    def helper_start(cls,*args,**kwargs):
        delegate=kwargs.pop('popen',default)
        if getattr(delegate,'__self__',None) is guard and getattr(delegate,'__func__',None) is LaunchGuard.popen:
            delegate=guard.original_popen
        kwargs['popen']=lambda argv,*a,**kw:guard.spawn(delegate,argv,*a,**kw)
        return function(cls,*args,**kwargs)
    def confirmed(registry,record):
        return ledger.application_lifecycle(guard,registry,record,confirm)
    def released(registry,record,sensitive_clean):
        return ledger.application_lifecycle(guard,registry,record,release,release=True,sensitive_clean=sensitive_clean)
    try:
        subprocess.Popen=guard.popen;OwnedHelper.start=classmethod(helper_start)
        ownership_registry.Registry.confirm_absent=confirmed;ownership_registry.Registry.release=released
        try:
            with timing.observe_identity_binding(OwnedHelper,guard.recorder_for_helper):yield guard
        except BaseException:
            ledger.poison_scope(cell_id);raise
    finally:
        subprocess.Popen=original;OwnedHelper.start=helper
        ownership_registry.Registry.confirm_absent=confirm;ownership_registry.Registry.release=release;_PATCH_LOCK.release()
