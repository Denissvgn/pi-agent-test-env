"""Reviewed application profile and controlled Node SDK; no Pi/runtime qualification."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'skill/scripts'), str(ROOT / 'skill/runtime')]
import agent_profiles as profiles
import application_runtime_contracts
import prompt_contract
import release_contracts


class ApplicationProfileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def test_exact_release_bundle_and_profile_binding_assets_freeze_without_legacy_changes(self):
        baseline = json.loads((ROOT / 'tests/fixtures/application-contracts/legacy-baseline.json').read_text())
        for release in ('0.87.1', '1.2.0'):
            with self.subTest(release=release):
                legacy = release_contracts.identity(release)
                application_identity = application_runtime_contracts.identity(release)
                profile = profiles.application(release)
                self.assertEqual(profile['components'], [application_runtime_contracts.profile_component(release)])
                self.assertEqual(profile['tools'], profiles.APPLICATION_TOOLS)
                self.assertEqual(profile['required_tools'], [])
                self.assertEqual({asset['target'] for asset in profile['assets']}, {'application-client.mjs', 'instructions.md'})
                self.assertEqual(profiles.admit(profile, release), legacy)
                receipt = profiles.freeze(profile, self.root / release)
                staged = profiles.staged(receipt)
                self.assertEqual(profiles.identity(staged), profiles.identity(profile))
                self.assertEqual({asset['target']: asset['sha256'] for asset in staged['assets']},
                                 {asset['target']: asset['sha256'] for asset in profile['assets']})
                self.assertEqual(release_contracts.identity(release), legacy)
                self.assertEqual(application_runtime_contracts.identity(release), application_identity)
        self.assertNotEqual(profiles.identity(profiles.application('0.87.1')), profiles.identity(profiles.application('1.2.0')))
        fixture = profiles.load(ROOT / 'skill/assets/profiles/fixture-lookup/profile.json')
        self.assertEqual(fixture['tools'], ['fixture_lookup'])
        self.assertEqual(baseline['profile_identities']['profile.json'], profiles.identity(fixture))
        for relative, expected in baseline['file_sha256'].items():
            if relative.startswith('skill/assets/profiles/fixture-lookup/'):
                self.assertEqual(hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(), expected)

    def test_exact_component_rejects_release_substitution(self):
        for release in ('0.87.1', '1.2.0'):
            profile = profiles.application(release)
            other = '1.2.0' if release == '0.87.1' else '0.87.1'
            with self.assertRaises(profiles.ProfileError): profiles.admit(profile, other)
        with self.assertRaises(ValueError): profiles.application('future')

    def test_closed_application_tool_subset_never_admits_builtin_or_blanket_application(self):
        profile = profiles.application('1.2.0')
        task = {'tools': ['artifact_read', 'report_write', 'budget_status'], 'require_tools': ['report_write']}
        self.assertEqual(profiles.toolset(task, profile), set(task['tools']))
        for tools in ([], ['app_api'], ['read', 'budget_status'], ['bash', 'budget_status'],
                      ['fixture_lookup', 'budget_status'], ['report_write', 'budget_status', 'report_write']):
            with self.subTest(tools=tools), self.assertRaises(profiles.ProfileError):
                profiles.toolset({'tools': tools}, profile)
        with self.assertRaises(profiles.ProfileError): profiles.apply({'agents': [task]}, profile)

    def test_rehashed_code_privilege_changes_links_and_noncanonical_assets_reject(self):
        source = ROOT / 'skill/assets/profiles/application-client'
        shutil.copytree(source, self.root / 'profile')
        declaration = json.loads((self.root / 'profile/profile.json').read_text())
        for key, value in [('tools', ['bash']), ('required_tools', ['app_api']),
                           ('service_endpoints', ['http://foreign.invalid/tool'])]:
            changed = copy.deepcopy(declaration); changed[key] = value
            with self.assertRaises(profiles.ProfileError): profiles.validate(changed, self.root / 'profile')
        file = self.root / 'profile/application-client.mjs'
        file.write_text('export default function(pi){pi.registerTool({name:"bash"});}\n')
        changed = copy.deepcopy(declaration)
        changed['assets'][0]['sha256'] = hashlib.sha256(file.read_bytes()).hexdigest()
        with self.assertRaises(profiles.ProfileError): profiles.validate(changed, self.root / 'profile')
        shutil.copyfile(source / 'application-client.mjs', file)
        for name in ('./application-client.mjs', '../application-client.mjs', 'x//application-client.mjs'):
            changed = copy.deepcopy(declaration); changed['assets'][0]['source'] = name
            with self.assertRaises(profiles.ProfileError): profiles.validate(changed, self.root / 'profile')
        file.unlink(); file.symlink_to(source / 'application-client.mjs')
        with self.assertRaises(OSError): profiles.validate(declaration, self.root / 'profile')

    def test_application_observation_requires_exact_stage_registry_and_pairs_use_without_fixture_assets(self):
        profile = profiles.application('1.2.0'); names = ['artifact_read', 'budget_status']
        context = {'profile': profile, 'profile_sha256': profiles.identity(profile), 'allowed_tools': names,
                   **{key: str(uuid.uuid4()) for key in ('run_id', 'attempt_id', 'stage_id', 'segment_id')}}
        data = {key: context[key] for key in ('profile_sha256', 'run_id', 'attempt_id', 'stage_id', 'segment_id')}
        data.update(active_tools=names, registered_tools=names,
                    assets_sha256={asset['target']: asset['sha256'] for asset in profile['assets']})
        events = [{'type': 'entry_appended', 'entry': {'customType': 'pi_lab_profile', 'data': data}},
                  {'type': 'message_end', 'message': {'role': 'assistant', 'content': [
                      {'type': 'toolCall', 'id': 'call-1', 'name': 'artifact_read', 'arguments': {'artifact_id': 'summary'}}]}},
                  {'type': 'tool_execution_end', 'toolCallId': 'call-1', 'toolName': 'artifact_read', 'isError': False,
                   'result': {'content': [{'type': 'text', 'text': 'public'}]}}]
        path = self.root / 'trace.jsonl'; path.write_text('\n'.join(json.dumps(event) for event in events))
        observation = profiles.observed(path, context)
        self.assertEqual(observation['errors'], [])
        self.assertEqual((observation['loading'], observation['use']), ('observed', 'observed'))
        events[0]['entry']['data']['registered_tools'] = [*names, 'bash']
        path.write_text('\n'.join(json.dumps(event) for event in events))
        self.assertTrue(profiles.observed(path, context)['errors'])


NODE = r'''
import fs from 'node:fs';
process.env.PI_LAB_APPLICATION_CONTEXT=process.argv[2];
const input=JSON.parse(fs.readFileSync(0,'utf8'));
const handlers=new Map(), tools=new Map();let active=[], fetches=0, business=0, aborted=0;
const ctx={abort(){aborted++;}};
const pi={registerTool(tool){if(tools.has(tool.name))throw Error('duplicate tool');tools.set(tool.name,tool);},
 on(name,handler){if(!handlers.has(name))handlers.set(name,[]);handlers.get(name).push(handler);},
 getAllTools(){return [...tools.values()];},getActiveTools(){return active;},setActiveTools(names){active=[...names];}};
const invoke=async(name,event)=>{for(const handler of handlers.get(name)||[])await handler(event,ctx);};
const status={accounting:'available'};
globalThis.fetch=async(url,options)=>{
 fetches++;
 if(options.redirect!=='error'||options.method!=='POST'||!options.signal)throw Error('unsafe request options');
 const body=JSON.parse(options.body);
 if(url.endsWith('/budget')){
  let result=status;
  if(body.action==='reserve')result={calls:body.payload.calls.map(call=>({id:call.id,name:call.name,admitted:true,reason:null})),snapshot:status};
  if(body.action==='consume')result={execution_nonce:'f'.repeat(64),snapshot:status};
  return new Response(JSON.stringify({ok:true,result}),{status:200});
 }
 if(url!=='http://pi-application:8081/tool')throw Error('foreign endpoint');
 business++;
 const keys=Object.keys(body).sort().join(',');
 if(keys!=='budget_grant,input,native_call_id,schema,scope,tool_name'||body.schema!==1||body.budget_grant!=='f'.repeat(64)
   ||Object.keys(body.scope).length!==Object.keys(input.scope).length
   ||Object.keys(body.scope).some(key=>JSON.stringify(body.scope[key])!==JSON.stringify(input.scope[key]))
   ||options.headers.Authorization!=='Bearer '+input.capability)throw Error('bad tool binding');
 if(input.scenario==='loss')throw Error('private transport error '+input.capability);
 if(input.scenario==='oversize')return new Response('x'.repeat(8193),{status:200});
 const result=input.scenario==='helper-denial'?{ok:false,reason:'operation_not_granted'}:{ok:true,value:'public-result'};
 return new Response(JSON.stringify({schema:1,ok:true,result}),{status:200});
};
let result=null, initialized=false;
try {
 (await import('./application-client.mjs')).default(pi);
 await invoke('session_start',{});
 if(input.scenario==='builtin')tools.set('read',{name:'read',description:'ambient',parameters:{}});
 await invoke('before_agent_start',{});initialized=true;
 if(input.scenario==='ungranted')result=await tools.get('artifact_read').execute('call-1',{artifact_id:'summary'});
 else {
  const name=input.scenario==='budget-status'?'budget_status':input.scenario.startsWith('content-')?'artifact_write':'artifact_read';
  const args=name==='budget_status'?{}:name==='artifact_write'?{artifact_id:'summary',content:input.scenario==='content-oversize'?'\x01'.repeat(60000):'x'.repeat(262144)}:{artifact_id:'summary'};
  await invoke('message_end',{message:{role:'assistant',stopReason:'toolUse',content:[{type:'toolCall',id:'call-1',name,arguments:args}]}});
  await invoke('tool_execution_start',{toolCallId:'call-1',toolName:name,args});
  let blocked;for(const handler of handlers.get('tool_call')||[])blocked=await handler({toolCallId:'call-1',toolName:name,input:args},ctx);
  if(blocked?.block)throw Error('blocked');
  result=await tools.get(name).execute('call-1',args);
 }
} catch(_){result={isError:true,details:{ok:false,reason:'application_tool_unavailable'}};}
console.log(JSON.stringify({initialized,registered:[...tools.keys()],active,fetches,business,result,aborted}));
'''


@unittest.skipUnless(shutil.which('node'), 'Node required for controlled SDK checks')
class ApplicationExtensionTests(unittest.TestCase):
    def run_profile(self, scenario='success', *, permissions=0o400, mutate=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            names = ['artifact_read', 'budget_status']
            if scenario == 'all-tools' or scenario.startswith('content-'): names = profiles.APPLICATION_TOOLS
            definitions = prompt_contract.tool_schemas({'tools': names, 'operations': ['read-summary'], 'browser_targets': ['summary-page']})
            scope = {key: str(uuid.uuid4()) for key in ('run_id', 'attempt_id', 'stage_id', 'segment_id', 'session_id')}
            scope.update(trial_id=None, plan_sha256='a' * 64, stage_name='participant',
                         participant={'actor_id': 'actor'}, operation_ids=['read-summary'], credential_aliases=['persona'],
                         authority_generation=str(uuid.uuid4()))
            context = {'schema': 1, 'scope': scope, 'capability': 'b' * 64,
                'base_url': 'http://pi-application:8081/tool', 'tool_schemas': definitions,
                'budget_context': {'schema': 1, 'pi_release': '1.2.0', 'scope': scope,
                    'allowed_tools': names, 'prepare_arguments': {name: 'none' for name in names},
                    'extension_order_sha256': 'c' * 64,
                    'tool_schema_sha256': hashlib.sha256(json.dumps(sorted(definitions, key=lambda row: row['name']), sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                    'base_url': 'http://pi-application:8081/budget', 'capability': 'd' * 64}}
            if mutate: mutate(context)
            path = root / 'context.json'; path.write_text(json.dumps(context)); path.chmod(permissions)
            source = (ROOT / 'skill/assets/profiles/application-client/application-client.mjs').read_text()
            source = source.replace("'/opt/pi-lab/tool-budget.mjs'", json.dumps((ROOT / 'skill/runtime/tool-budget.mjs').as_uri()))
            (root / 'application-client.mjs').write_text(source)
            (root / 'exercise.mjs').write_text(NODE)
            result = subprocess.run(['node', str(root / 'exercise.mjs'), str(path)], input=json.dumps({
                'scope': scope, 'capability': 'b' * 64, 'scenario': scenario}), capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            for private in ('b' * 64, 'd' * 64, 'f' * 64): self.assertNotIn(private, result.stdout + result.stderr)
            return json.loads(result.stdout)

    def test_exact_stage_subset_and_all_six_catalog_tools_register_without_builtin(self):
        subset = self.run_profile()
        self.assertTrue(subset['initialized'])
        self.assertEqual(set(subset['registered']), {'artifact_read', 'budget_status'})
        self.assertEqual(subset['business'], 1)
        self.assertEqual(subset['result']['details'], {'ok': True, 'value': 'public-result'})
        all_tools = self.run_profile('all-tools')
        self.assertEqual(set(all_tools['registered']), set(profiles.APPLICATION_TOOLS))
        self.assertEqual(all_tools['registered'].count('budget_status'), 1)

    def test_guard_owns_budget_status_and_ungranted_execution_has_zero_business_requests(self):
        status = self.run_profile('budget-status')
        self.assertEqual(status['business'], 0)
        self.assertEqual(status['result']['details'], {'accounting': 'available'})
        ungranted = self.run_profile('ungranted')
        self.assertTrue(ungranted['result']['isError'])
        self.assertEqual(ungranted['business'], 0)

    def test_ambient_builtin_registry_mismatch_blocks_before_helper_effect(self):
        value = self.run_profile('builtin')
        self.assertFalse(value['initialized'])
        self.assertEqual(value['business'], 0)
        self.assertGreater(value['aborted'], 0)

    def test_private_context_permissions_endpoint_scope_and_schema_must_match(self):
        cases = [lambda value: value.update(base_url='http://foreign.invalid/tool'),
                 lambda value: value['budget_context'].update(scope={**value['scope'], 'stage_id': str(uuid.uuid4())}),
                 lambda value: value['budget_context'].update(tool_schema_sha256='0' * 64)]
        for change in cases:
            with self.subTest(change=change):
                value = self.run_profile(mutate=change)
                self.assertFalse(value['initialized']); self.assertEqual(value['fetches'], 0)
        value = self.run_profile(permissions=0o444)
        self.assertFalse(value['initialized']); self.assertEqual(value['fetches'], 0)

    def test_loss_oversize_and_helper_denial_are_bounded_errors_without_retry_or_echo(self):
        for scenario in ('loss', 'oversize', 'helper-denial'):
            with self.subTest(scenario=scenario):
                value = self.run_profile(scenario)
                self.assertEqual(value['business'], 1)
                self.assertTrue(value['result']['isError'])
                self.assertLess(len(json.dumps(value['result'])), 256)

    def test_utf8_content_limit_and_json_escape_request_bound_are_independent(self):
        allowed = self.run_profile('content-maximum')
        self.assertEqual(allowed['business'], 1)
        self.assertFalse(allowed['result']['isError'])
        escaped = self.run_profile('content-oversize')
        self.assertTrue(escaped['result']['isError'])
        self.assertEqual(escaped['business'], 0)
        self.assertGreater(escaped['aborted'], 0)


if __name__ == '__main__': unittest.main()
