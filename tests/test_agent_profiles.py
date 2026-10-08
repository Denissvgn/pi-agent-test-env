"""Explicit profile contract/load fixtures; synthetic SDK does not qualify real Pi."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
ROOT=(Path(__file__).resolve().parents[1] / 'skill')
sys.path.insert(0,str(ROOT/'scripts'))
import agent_profiles as profiles
import pi_lab as lab


class ProfileFixture(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        shutil.copytree(ROOT/'assets/profiles/fixture-lookup',self.root/'profile')
        self.value=json.load(open(self.root/'profile/profile.json'))

    def validate(self,value=None):return profiles.validate(value or self.value,self.root/'profile')


class ProfileTests(ProfileFixture):
    def test_explicit_builtin_and_minimal_custom_contract(self):
        self.assertEqual(profiles.validate(profiles.builtin(),self.root),profiles.builtin())
        profile=self.validate();self.assertEqual(profile['tools'],['fixture_lookup']);self.assertEqual(profile['service_endpoints'],[])
        self.assertEqual(profiles.identity(profile),profiles.identity(self.validate()))
        plan={'schema':1,'agents':[{'prompt':'Lookup the data.','tools':['read','fixture_lookup'],'require_tools':['fixture_lookup']}],'checks':[{'argv':['python3','-V']}]}
        self.assertIn('fixture_lookup',lab.validate_plan(plan,self.root,profile)['agents'][0]['tools'])
        with self.assertRaises(lab.LabError):lab.validate_plan(plan,self.root)

    def test_escaping_missing_links_mismatch_duplicate_and_unsupported_reject(self):
        invalid=[]
        for field,value in [('kind','mcp'),('tools',['other_tool']),('service_endpoints',['http://server']),('new_privileges',True)]:
            item=copy.deepcopy(self.value);item[field]=value;invalid.append(item)
        for field,value in [('source','../outside'),('source','/outside'),('target','../outside'),('target','/outside'),('sha256','0'*64)]:
            item=copy.deepcopy(self.value);item['assets'][0][field]=value;invalid.append(item)
        item=copy.deepcopy(self.value);item['assets'][1]=copy.deepcopy(item['assets'][0]);invalid.append(item)
        for item in invalid:
            with self.subTest(item=item),self.assertRaises((profiles.ProfileError,OSError)):self.validate(item)
        path=self.root/'profile/fixtures.json';path.unlink()
        with self.assertRaises(OSError):self.validate()
        path.symlink_to(ROOT/'assets/profiles/fixture-lookup/fixtures.json')
        with self.assertRaises(OSError):self.validate()

    def test_rehashed_arbitrary_code_or_unbounded_config_is_not_supported(self):
        for target,body in [('fixture-lookup.mjs','export default function(pi){pi.registerTool({name:"other"})}'),('config.json','{"schema":1,"table":"/etc/passwd","max_result_bytes":100000}')]:
            shutil.copyfile(ROOT/'assets/profiles/fixture-lookup'/target,self.root/'profile'/target)
            value=copy.deepcopy(self.value);path=self.root/'profile'/target;path.write_text(body)
            next(a for a in value['assets'] if a['target']==target)['sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaises(profiles.ProfileError):self.validate(value)
            shutil.copyfile(ROOT/'assets/profiles/fixture-lookup'/target,path)

    def test_identity_changes_with_declared_table_and_undeclared_tools_reject(self):
        before=profiles.identity(self.validate());path=self.root/'profile/fixtures.json';path.write_text('{"alpha":{"amount":99}}\n')
        value=copy.deepcopy(self.value);next(a for a in value['assets'] if a['target']=='fixtures.json')['sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertNotEqual(before,profiles.identity(self.validate(value)))
        with self.assertRaises(profiles.ProfileError):profiles.toolset({'tools':['unlisted'],'require_tools':[]},self.validate(value))
        invalid=profiles.builtin();invalid['assets']=[{'source':'ambient'}]
        with self.assertRaises(profiles.ProfileError):profiles.validate(invalid,self.root)

import subprocess
import uuid
from unittest import mock


class LoaderTests(ProfileFixture):
    def node_receipt(self,custom=True):
        profile=self.validate() if custom else profiles.builtin()
        context={'schema':1,'profile':profile,'profile_sha256':profiles.identity(profile),
                 **{k:str(uuid.uuid4()) for k in ('run_id','attempt_id','stage_id','segment_id')},
                 'allowed_tools':sorted(['read','fixture_lookup'] if custom else ['read'])}
        (self.root/'context.json').write_text(json.dumps(context))
        # Exact source with a tiny explicitly synthetic Pi SDK API, not a real Pi loader.
        package=self.root/'profile/node_modules/@earendil-works/pi-ai';package.mkdir(parents=True)
        (package/'package.json').write_text('{"type":"module","exports":"./index.js"}')
        (package/'index.js').write_text('export const Type={Object:(x)=>({type:"object",properties:x}),String:()=>({type:"string"})};')
        monitor=self.root/'monitor.mjs';shutil.copyfile(ROOT/'runtime/profile-monitor.mjs',monitor)
        # Path relocation only: monitor's fixed read-only mount is mirrored by a temporary fixture directory.
        monitor.write_text(monitor.read_text().replace("'/opt/pi-profile/'",json.dumps(str(self.root/'profile')+'/')))
        program=self.root/'exercise.mjs'
        program.write_text('''import fs from 'node:fs';
process.env.PI_LAB_PROFILE_CONTEXT=process.argv[2];
const context=JSON.parse(fs.readFileSync(process.argv[2]));
const allowed=new Set(process.argv[3].split(','));
const handlers={};const tools=new Map([['read',{name:'read'}]]);let active=['read'];const entries=[];
const pi={registerTool:t=>{if(allowed.has(t.name))tools.set(t.name,t)},on:(n,f)=>{(handlers[n]??=[]).push(f)},setActiveTools:v=>{active=v.filter(n=>tools.has(n))},getActiveTools:()=>active,getAllTools:()=>[...tools.values()],appendEntry:(customType,data)=>entries.push({type:'entry_appended',entry:{customType,data}})};
if(context.profile.kind!=='builtin')(await import('./profile/fixture-lookup.mjs')).default(pi);
(await import('./monitor.mjs')).default(pi);
for(const f of handlers.session_start??[])await f();
for(const f of handlers.before_agent_start??[])await f();
let result=null;if(tools.has('fixture_lookup'))result=await tools.get('fixture_lookup').execute('call-a',{key:'alpha'});
console.log(JSON.stringify({entries,result,active}));
''')
        sys.path.insert(0,str(ROOT/'runtime'));import worker
        argv=worker.agent_pi_arguments({'model':'test-model'},{'tools':context['allowed_tools']},self.root,['--thinking','off'],context)
        result=subprocess.run(['node',str(program),str(self.root/'context.json'),argv[argv.index('--tools')+1]],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)
        return context,json.loads(result.stdout)

    def test_real_node_extension_registry_monitor_and_matching_tool_result(self):
        context,result=self.node_receipt()
        self.assertEqual(result['active'],['fixture_lookup','read']);self.assertEqual(result['result']['details']['value']['amount'],17)
        events=result['entries']+[{'type':'message_end','message':{'role':'assistant','content':[{'type':'toolCall','id':'call-a','name':'fixture_lookup','arguments':{'key':'alpha'}}]}},
                                  {'type':'tool_execution_end','toolName':'fixture_lookup','toolCallId':'call-a','isError':False,'result':result['result']}]
        path=self.root/'trace.jsonl';path.write_text('\n'.join(json.dumps(e) for e in events))
        observation=profiles.observed(path,{**context,'asset_root':str(self.root/'profile')})
        self.assertEqual(observation['errors'],[]);self.assertEqual(observation['loading'],'observed');self.assertEqual(observation['use'],'observed')
        events[-1]['result']['details']['value']['amount']=999;path.write_text('\n'.join(json.dumps(e) for e in events))
        self.assertTrue(profiles.observed(path,{**context,'asset_root':str(self.root/'profile')})['errors'])

    def test_builtin_monitor_never_registers_or_uses_custom_tool(self):
        context,result=self.node_receipt(False)
        self.assertEqual(result['active'],['read']);self.assertIsNone(result['result'])
        path=self.root/'trace.jsonl';path.write_text('\n'.join(json.dumps(e) for e in result['entries']))
        observation=profiles.observed(path,{**context,'asset_root':''})
        self.assertEqual(observation['errors'],[]);self.assertEqual(observation['use'],'not_requested')
        path.write_text('');self.assertTrue(profiles.observed(path,{**context,'asset_root':''})['errors'])

    def test_parent_staging_is_fresh_readonly_and_tamper_rejects(self):
        receipt=profiles.freeze(self.validate(),self.root/'staged');before=profiles.identity(profiles.staged(receipt))
        (self.root/'profile/fixtures.json').write_text('{}')
        self.assertEqual(profiles.identity(profiles.staged(receipt)),before)
        path=self.root/'staged/fixtures.json';path.chmod(0o600);path.write_text('{}')
        with self.assertRaises(profiles.ProfileError):profiles.staged(receipt)

    def test_load_receipt_alone_cannot_establish_successful_use(self):
        context,result=self.node_receipt();path=self.root/'trace.jsonl';path.write_text('\n'.join(json.dumps(e) for e in result['entries']))
        observation=profiles.observed(path,{**context,'asset_root':str(self.root/'profile')})
        self.assertEqual(observation['loading'],'observed');self.assertEqual(observation['use'],'unverified');self.assertTrue(observation['errors'])

    def test_complete_protocol_and_profile_receipt_are_independent_required_gates(self):
        from test_lab import events
        from evidence import analyze
        context,result=self.node_receipt()
        fixture=events()
        for event in fixture:
            if event.get('toolName')=='read':event['toolName']='fixture_lookup'
            message=event.get('message')
            if isinstance(message,dict):
                if message.get('toolName')=='read':message['toolName']='fixture_lookup'
                for block in message.get('content',[]) if isinstance(message.get('content'),list) else []:
                    if block.get('type')=='toolCall':block.update(name='fixture_lookup',arguments={'key':'alpha'})
            if event.get('type')=='tool_execution_end':event['result']=result['result']
        fixture[1:1]=result['entries']
        path=self.root/'complete.jsonl';path.write_text('\n'.join(json.dumps(e) for e in fixture))
        evidence=analyze(path,'test-model',['fixture_lookup'],0,allowed_tools=['fixture_lookup'])
        self.assertTrue(evidence['agent_invocation_verified'],evidence['errors'])
        observation=profiles.observed(path,{**context,'asset_root':str(self.root/'profile')});self.assertEqual(observation['errors'],[])
        denied=analyze(path,'test-model',[],0,allowed_tools=['read']);self.assertFalse(denied['agent_invocation_verified'])
        fixture=[e for e in fixture if e.get('type')!='entry_appended'];path.write_text('\n'.join(json.dumps(e) for e in fixture))
        self.assertTrue(analyze(path,'test-model',['fixture_lookup'],0,allowed_tools=['fixture_lookup'])['agent_invocation_verified'])
        self.assertTrue(profiles.observed(path,{**context,'asset_root':str(self.root/'profile')})['errors'])
