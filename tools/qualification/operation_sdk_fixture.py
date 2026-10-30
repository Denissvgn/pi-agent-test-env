"""Fixture-only actual operation SDK qualification inside an owned Linux container.

Requires /opt/provider read-only, /fixtures read-only and /results writable.
The fixture operator separately approves the code/policy/runtime closure. This
program selects only literal fake values and new temporary stores; it is not an
SDK deployment bootstrap, real credential importer or application runner.
"""
import argparse,base64,copy,fcntl,hashlib,json,os,platform,sys,tempfile,time,traceback,types,uuid
from pathlib import Path

def encode(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
def pin(value):return hashlib.sha256(encode(value)).hexdigest()
def identity(path):
 info=path.stat()
 return[info.st_dev,info.st_ino]


def run_store():
 p=json.loads(Path('/fixtures/policy-template.json').read_text());observed=json.loads(Path('/fixtures/runtime-profile.json').read_text())['runtime']
 p['deployment'].update(python_sha256=observed['python_sha256'],runtime_files=observed['files'],runtime_sizes=observed['sizes'],
     runtime_modules=observed['modules'],mapped_files=observed['mapped_files'])
 root=p['deployment']['consumer_root'];file=root+'/__init__.py';body=Path(file).read_bytes();assert hashlib.sha256(body).hexdigest()==p['deployment']['consumer_files']['__init__.py']
 package=types.ModuleType('operation_sdk');package.__file__=file;package.__path__=[root];sys.modules['operation_sdk']=package;exec(compile(body,file,'exec',dont_inherit=True),package.__dict__)
 client=package.load_verified(root,p['deployment']['consumer_files'])
 from operation_sdk import wire
 rows=[]
 with tempfile.TemporaryDirectory(prefix='sdk-actual-store-')as temp:
  directory=Path(temp);store=directory/'store';store.mkdir(mode=0o700);lease=directory/'coordination';lease.write_bytes(b'');lease.chmod(0o600)
  p['scope'].update(resource=None,store={'path':str(store),'identity':identity(store)},coordination={'path':str(lease),'identity':identity(lease)})
  def reference(name,role,alias=None):
   info=(store/name).stat()
   return dict(reference=name,role=role,alias=alias,value_contract='application_credential_1'if role=='application'else'normalized_secret_1',
       identity=[info.st_dev,info.st_ino],size=info.st_size,mtime_ns=info.st_mtime_ns,ctime_ns=info.st_ctime_ns)
  def operation(kind,payload,name=None,contract=None,references=None):
   value=copy.deepcopy(p);value['operation']=kind;value['scope'].update(references=references or[],write_reference=name,value_contract=contract)
   fd=os.memfd_create('sdk-private',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING);os.fchmod(fd,0o600)
   content=wire.encode(payload,value['limits']['max_payload_bytes']);framed=len(content).to_bytes(4,'big')+content
   offset=0
   while offset<len(framed):offset+=os.write(fd,framed[offset:])
   os.lseek(fd,0,os.SEEK_SET);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
   s=os.fstat(fd);source_id=str(uuid.uuid4());value['input']={'source_id':source_id,'identity':[s.st_dev,s.st_ino],
       'kind':'sealed_memfd','maximum_bytes':65536}
   now=time.monotonic_ns();new=lambda:str(uuid.uuid4());request=dict(schema=1,document_type='operation_sdk_request',operation=kind,
       policy_sha256=pin(value),actor_id=value['actor_id'],participant_id=value['participant_id'],stage_id=value['stage_id'],
       operation_id=new(),request_id=new(),worker_id=new(),channel_id=new(),source_id=source_id,created_ns=now,
       expires_ns=now+value['limits']['max_runtime_millis']*1000000)
   try:
    with client.prepare(value,request,trusted_policy_sha256=pin(value))as capability:
     result=capability.execute(fd)
     rows.append({'operation':kind,'accepted':result.accepted,'code':result.code,'facts':result.facts()})
     Path('/results/transactions.json').write_text(json.dumps(rows,indent=2)+'\n')
     assert result.accepted
     return result
   except BaseException as error:
    frames=[{'file':f.filename,'line':f.lineno,'function':f.name}for f in traceback.extract_tb(error.__traceback__)]
    Path('/results/store-error.json').write_text(json.dumps({'code':getattr(error,'code',None),'frames':frames},indent=2)+'\n')
    raise
  inference='fixture-inference-value-0123456789';app='fixture-application-value-0123456789'
  operation('secret_register_create_only_v1',{'value':inference},'INFERENCE_FAKE','normalized_secret_1')
  inf=reference('INFERENCE_FAKE','inference')
  operation('secret_register_create_only_v1',{'value':app},'APP_FAKE','application_credential_1',[inf])
  selected=[reference('APP_FAKE','application','PI_APP_KEY'),inf]
  result=operation('credentials_collect_v1',{},references=selected)
  assert result.private()['aliases']=={'PI_APP_KEY':app}and result.private()['inference_value']==inference
  assert(store/'APP_FAKE').read_text()==app and(store/'INFERENCE_FAKE').read_text()==inference
 print(json.dumps({'actual_SDK_store_operations':len(rows),'all_accepted':True,'real_credentials':False}))

def run_redaction():
 p=json.loads(Path('/fixtures/policy-template.json').read_text());observed=json.loads(Path('/fixtures/runtime-profile.json').read_text())['runtime']
 p['deployment'].update(python_sha256=observed['python_sha256'],runtime_files=observed['files'],runtime_sizes=observed['sizes'],runtime_modules=observed['modules'],mapped_files=observed['mapped_files'])
 root=p['deployment']['consumer_root'];file=root+'/__init__.py';body=Path(file).read_bytes();assert hashlib.sha256(body).hexdigest()==p['deployment']['consumer_files']['__init__.py']
 package=types.ModuleType('operation_sdk');package.__file__=file;package.__path__=[root];sys.modules['operation_sdk']=package;exec(compile(body,file,'exec',dont_inherit=True),package.__dict__)
 client=package.load_verified(root,p['deployment']['consumer_files'])
 rows=[]
 cases=[('binary','fixture-secret-0123456789',b'\x00\xff|fixture-secret-0123456789|\x80',True,b'\x00\xff|<REDACTED>|\x80'),
        ('one-character','X',b'XX',True,b'<REDACTED><REDACTED>'),
        ('marker-collision','<',b'<',False,None),
        ('three-json-layers','fixture-\"-\\-é',None,True,None)]
 for case,value,body,accepted,expected in cases:
  if body is None:
   layers=[value];current=value
   for i in range(3):current=json.dumps(current,ensure_ascii=True)[1:-1];layers.append(current)
   body='|'.join(layers).encode();expected=b'|'.join([b'<REDACTED>']*4)
  with tempfile.TemporaryDirectory(prefix='sdk-redact-')as temp:
   directory=Path(temp);store=directory/'store';store.mkdir(mode=0o700);lease=directory/'coordination';lease.write_bytes(b'');lease.chmod(0o600)
   leaf=store/'FAKE';leaf.write_text(value);leaf.chmod(0o600);info=leaf.stat();ident=lambda path:[path.stat().st_dev,path.stat().st_ino]
   selected=copy.deepcopy(p);selected['operation']='redact_bytes_v1';selected['scope'].update(resource=None,store={'path':str(store),'identity':ident(store)},coordination={'path':str(lease),'identity':ident(lease)},references=[dict(reference='FAKE',alias=None,role='redaction',value_contract='normalized_secret_1',identity=[info.st_dev,info.st_ino],size=info.st_size,mtime_ns=info.st_mtime_ns,ctime_ns=info.st_ctime_ns)])
   fd=os.memfd_create('sdk-private',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING);os.fchmod(fd,0o600);framed=len(body).to_bytes(4,'big')+body;assert os.write(fd,framed)==len(framed);os.lseek(fd,0,0);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
   info=os.fstat(fd);source_id=str(uuid.uuid4());selected['input']=dict(source_id=source_id,identity=[info.st_dev,info.st_ino],kind='sealed_memfd',maximum_bytes=65536)
   now=time.monotonic_ns();new=lambda:str(uuid.uuid4());request=dict(schema=1,document_type='operation_sdk_request',operation=selected['operation'],policy_sha256=pin(selected),actor_id=selected['actor_id'],participant_id=selected['participant_id'],stage_id=selected['stage_id'],operation_id=new(),request_id=new(),worker_id=new(),channel_id=new(),source_id=source_id,created_ns=now,expires_ns=now+selected['limits']['max_runtime_millis']*1000000)
   with client.prepare(selected,request,trusted_policy_sha256=pin(selected))as capability:
    result=capability.execute(fd);rows.append(dict(case=case,accepted=result.accepted,code=result.code,facts=result.facts()))
    Path('/results/transactions.json').write_text(json.dumps(rows,indent=2)+'\n')
    assert result.accepted is accepted
    assert len(result.public_wire())==12 and all(c<32 for c in result.public_wire())
    if accepted:assert result.bytes()==expected
    else:assert result.code==10
 print(json.dumps({'actual_SDK_redaction_operations':len(rows),'oracles_passed':True,'real_credentials':False}))

def run_plans():
 p=json.loads(Path('/fixtures/policy-template.json').read_text());observed=json.loads(Path('/fixtures/runtime-profile.json').read_text())['runtime']
 # Both frozen typed documents declare two scorer assets. This grant is exact;
 # the one-asset negative below must still refuse before provider validation.
 p['limits']['max_scorer_assets']=2
 p['deployment'].update(python_sha256=observed['python_sha256'],runtime_files=observed['files'],runtime_sizes=observed['sizes'],runtime_modules=observed['modules'],mapped_files=observed['mapped_files'])
 root=p['deployment']['consumer_root'];file=root+'/__init__.py';body=Path(file).read_bytes();assert hashlib.sha256(body).hexdigest()==p['deployment']['consumer_files']['__init__.py']
 package=types.ModuleType('operation_sdk');package.__file__=file;package.__path__=[root];sys.modules['operation_sdk']=package;exec(compile(body,file,'exec',dont_inherit=True),package.__dict__)
 client=package.load_verified(root,p['deployment']['consumer_files']);rows=[]
 def operation(case,kind,plan,*,dependencies=(),profile=None,metadata=False,external=False,accepted=True,limits=None):
  selected=copy.deepcopy(p);selected['operation']=kind;selected['scope']['resource']=None
  if kind in('plan_validate_legacy_v1','plan_check_project_v1'):
   selected['scope'].update(base='/fixtures/project',profile=profile,external_bindings=external)
   selected['scope']['dependencies']=[dict(path='/fixtures/project/'+name,sha256=hashlib.sha256(Path('/fixtures/project',name).read_bytes()).hexdigest(),maximum_bytes=4096,role=role)for name,role in dependencies]
   selected['limits']['max_scorer_assets']=1
  if metadata:
   selected['scope']['metadata']=[dict(path=str(path),identity=[path.stat().st_dev,path.stat().st_ino],kind='directory')for path in(Path('/fixtures/project'),Path('/fixtures/project/data'))]
  if limits:selected['limits'].update(limits)
  content=encode({'plan':plan});fd=os.memfd_create('sdk-private',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING);os.fchmod(fd,0o600);framed=len(content).to_bytes(4,'big')+content
  assert os.write(fd,framed)==len(framed);os.lseek(fd,0,0);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
  info=os.fstat(fd);source_id=str(uuid.uuid4());selected['input']=dict(source_id=source_id,identity=[info.st_dev,info.st_ino],kind='sealed_memfd',maximum_bytes=65536)
  now=time.monotonic_ns();new=lambda:str(uuid.uuid4());request=dict(schema=1,document_type='operation_sdk_request',operation=kind,policy_sha256=pin(selected),actor_id=selected['actor_id'],participant_id=selected['participant_id'],stage_id=selected['stage_id'],operation_id=new(),request_id=new(),worker_id=new(),channel_id=new(),source_id=source_id,created_ns=now,expires_ns=now+selected['limits']['max_runtime_millis']*1000000)
  with client.prepare(selected,request,trusted_policy_sha256=pin(selected))as capability:
   result=capability.execute(fd);data=result.private();rows.append(dict(case=case,operation=kind,accepted=result.accepted,code=result.code,facts=result.facts()))
   Path('/results/transactions.json').write_text(json.dumps(rows,indent=2)+'\n')
   assert result.accepted is accepted
   if accepted:
    assert data['validation_only']is True and data['scorer_frozen']is False
    assert data['project_contract_checked']is(kind=='plan_check_project_v1')
    if kind in('plan_validate_source_v1','plan_validate_ir_v1'):assert data['normalized_plan']==plan
   return data
 for kind,name in(('plan_validate_source_v1','source'),('plan_validate_ir_v1','ir')):
  value=json.loads(Path('/fixtures/'+name+'.json').read_text())
  assert sum(len(check.get('scorer',{}).get('assets',[]))for check in value['checks'])==2
  operation(name,kind,value)
  operation(name+'-scorer-budget',kind,value,limits={'max_scorer_assets':1},accepted=False)
  altered=copy.deepcopy(value);altered['unexpected']=True;operation(name+'-unknown-field',kind,altered,accepted=False)
 legacy=dict(schema=1,agents=[dict(name='inspect',prompt='Inspect the fixture',tools=['read'],require_tools=['read'],application_secrets={'PI_APP_KEY':'FAKE_APP'})],checks=[dict(argv=['true'])])
 data=operation('legacy-inline','plan_validate_legacy_v1',legacy)
 assert data['normalized_plan']['agents'][0]['application_secrets']=={'PI_APP_KEY':'FAKE_APP'}
 value=copy.deepcopy(legacy);value['agents'][0].pop('prompt');value['agents'][0]['prompt_file']='prompt.txt'
 data=operation('legacy-prompt-profile','plan_validate_legacy_v1',value,dependencies=[('prompt.txt','prompt'),('profile.json','profile')],profile='/fixtures/project/profile.json')
 assert data['normalized_plan']['agents'][0]['prompt']==Path('/fixtures/project/prompt.txt').read_text() and data['dependencies_read']==2
 operation('legacy-undeclared-prompt','plan_validate_legacy_v1',value,accepted=False)
 operation('legacy-prompt-budget','plan_validate_legacy_v1',value,dependencies=[('prompt.txt','prompt')],limits={'max_prompt_bytes':1},accepted=False)
 value=copy.deepcopy(legacy);value.update(schema=2,inference_bindings='external')
 assert operation('legacy-schema2','plan_validate_legacy_v1',value,external=True)['normalized_plan']['schema']==2
 operation('legacy-schema2-no-external-authority','plan_validate_legacy_v1',value,accepted=False)
 value=copy.deepcopy(legacy);value['required_paths']=['data'];operation('project-metadata','plan_check_project_v1',value,metadata=True)
 value=copy.deepcopy(legacy);value['checks'][0]['scorer']=dict(schema=1,id='fixture',version='1',assets=[dict(source='scorer.py',target='scorer.py')],score_domain=dict(min=0,max=1,direction='higher',pass_threshold=1),required_assertions=['fake'],zero_test_policy='fail',all_skipped_policy='fail')
 data=operation('scorer-normalization','plan_validate_legacy_v1',value,dependencies=[('scorer.py','scorer')]);assert data['dependencies_read']==1
 assert data['normalized_plan']['checks'][0]['scorer']['assets'][0]['source']=='/fixtures/project/scorer.py'
 print(json.dumps({'actual_SDK_plan_operations':len(rows),'all_case_oracles_passed':True,'commands_executed':0}))

def run_resource():
    p=json.loads(Path('/fixtures/policy-template.json').read_text())
    observed=json.loads(Path('/fixtures/runtime-profile.json').read_text())['runtime']
    p['deployment'].update(python_sha256=observed['python_sha256'],runtime_files=observed['files'],
        runtime_sizes=observed['sizes'],runtime_modules=observed['modules'],mapped_files=observed['mapped_files'])
    now=time.monotonic_ns();new=lambda:str(uuid.uuid4())
    request=dict(schema=1,document_type='operation_sdk_request',operation=p['operation'],policy_sha256=pin(p),
        actor_id=p['actor_id'],participant_id=p['participant_id'],stage_id=p['stage_id'],operation_id=new(),
        request_id=new(),worker_id=new(),channel_id=new(),source_id=None,created_ns=now,
        expires_ns=now+p['limits']['max_runtime_millis']*1000000)
    root=p['deployment']['consumer_root'];path=root+'/__init__.py';body=Path(path).read_bytes()
    assert hashlib.sha256(body).hexdigest()==p['deployment']['consumer_files']['__init__.py']
    package=types.ModuleType('operation_sdk');package.__file__=path;package.__path__=[root];sys.modules['operation_sdk']=package
    exec(compile(body,path,'exec',dont_inherit=True),package.__dict__)
    client=package.load_verified(root,p['deployment']['consumer_files'])
    try:
        with client.prepare(p,request,trusted_policy_sha256=pin(p))as capability:
            result=capability.execute()
            data=result.bytes()if result.accepted else b''
            output={'accepted':result.accepted,'code':result.code,'facts':result.facts(),
                'resource_bytes':len(data),'resource_sha256':hashlib.sha256(data).hexdigest(),
                'public_wire_hex':result.public_wire().hex(),'scope':'actual SDK resource call only'}
            Path('/results/resource.json').write_text(json.dumps(output,indent=2)+'\n')
            assert result.accepted and hashlib.sha256(data).hexdigest()==p['deployment']['resources'][p['scope']['resource']['path']]
    except BaseException as error:
        frames=[{'function':frame.name,'line':frame.lineno,'file':frame.filename}for frame in traceback.extract_tb(error.__traceback__)]
        Path('/results/resource-error.json').write_text(json.dumps({'code':getattr(error,'code',None),'frames':frames},indent=2)+'\n')
        raise
    print(json.dumps({'SDK_resource':'PASS','bytes':len(data),'no_credentials_or_store':True}))

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--case-set',required=True,choices=('store','redaction','plans','resource'))
 args=parser.parse_args()
 if sys.platform!='linux' or platform.machine()!='aarch64' or sys.version_info[:3]!=(3,12,13):
  parser.error('Use the exact isolated Linux ARM64 CPython3.12.13 qualification profile')
 if not os.statvfs('/opt/provider').f_flag&os.ST_RDONLY or not os.statvfs('/fixtures').f_flag&os.ST_RDONLY:
  parser.error('Provider and fixture inputs must be mounted read-only')
 {'store':run_store,'redaction':run_redaction,'plans':run_plans,'resource':run_resource}[args.case_set]()

if __name__=='__main__':main()
