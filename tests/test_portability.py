"""Project-independent contracts and explicit compatibility behavior; no live LLM."""
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest import mock

ROOT = (Path(__file__).resolve().parents[1] / 'skill')
sys.path.insert(0, str(ROOT / 'scripts'))
import pi_lab as lab
from evidence import analyze
from test_lab import events, task, final_event


class EnvironmentContractTests(unittest.TestCase):
    def test_empty_is_valid(self):
        self.assertEqual(lab.validate_environment({})['required_commands'], [])

    def test_all_templates(self):
        for p in (ROOT/'assets/environments').glob('*.json'):
            lab.validate_environment(json.loads(p.read_text()))

    def test_rejects_shell_expression_command(self):
        with self.assertRaises(lab.LabError):
            lab.validate_environment({'required_commands':['node; echo unsafe']})

    def test_probes_require_argv_array(self):
        with self.assertRaises(lab.LabError):
            lab.validate_environment({'probes':[{'name':'version','argv':'node --version'}]})

    def test_probes_require_unique_names(self):
        t={'name':'version','argv':['node','--version']}
        with self.assertRaises(lab.LabError):lab.validate_environment({'probes':[t,t]})

    def test_probe_timeout_bounded(self):
        with self.assertRaises(lab.LabError):
            lab.validate_environment({'probes':[{'name':'version','argv':['node'],'timeout_seconds':9999}]})

    def test_invalid_regex_rejected(self):
        with self.assertRaises(lab.LabError):
            lab.validate_environment({'probes':[{'name':'version','argv':['node'],'stdout_regex':'['}]})

    def test_unknown_probe_field_rejected(self):
        with self.assertRaises(lab.LabError):
            lab.validate_environment({'probes':[{'name':'version','argv':['node'],'network':'host'}]})

    def test_known_regex_preserved(self):
        out=lab.validate_environment({'probes':[{'name':'version','argv':['node'],'stdout_regex':'^v24'}]})
        self.assertEqual(out['probes'][0]['stdout_regex'],'^v24')


class GenericEndpointTests(unittest.TestCase):
    def load(self,update=None):
        obj={'base_url':'${TEST_BASE}', 'model':'${TEST_MODEL}', 'context_window':16384,
             'max_tokens':2048, 'api_key_env':'TEST_KEY'}
        obj.update(update or {})
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'e.json';p.write_text(json.dumps(obj))
            with mock.patch.dict(os.environ,{'TEST_BASE':'http://model-server:9000/v1','TEST_MODEL':'custom-served-id'}):
                return lab.load_endpoint(p)

    def test_model_not_tied_to_unsloth(self):
        obj=self.load()
        self.assertEqual(obj['model'],'custom-served-id')
        self.assertEqual(obj['base_url'],'http://model-server:9000/v1')

    def test_missing_template_environment_fails(self):
        with self.assertRaises(lab.LabError):self.load({'model':'${PI_TEST_MISSING_VALUE_12345}'})

    def test_compatibility_options_checked(self):
        obj=self.load({'compat':{'maxTokensField':'max_completion_tokens','supportsDeveloperRole':False}})
        self.assertEqual(obj['compat']['maxTokensField'],'max_completion_tokens')

    def test_unknown_protocol_option_fails(self):
        with self.assertRaises(lab.LabError):self.load({'compat':{'pretendSuccess':True}})

    def test_literal_secret_field_fails(self):
        with self.assertRaises(lab.LabError):self.load({'apiKey':'secret'})

    def test_context_must_be_real_integer(self):
        with self.assertRaises(lab.LabError):self.load({'context_window':True})

    def test_image_input_supported_as_explicit_capability(self):
        self.assertEqual(self.load({'input':['text','image']})['input'],['text','image'])

    def test_base_url_query_rejected(self):
        with self.assertRaises(lab.LabError):self.load({'base_url':'http://server/v1?key=x'})


class LocalEndpointAssetTests(unittest.TestCase):
    """The shipped endpoint for this installation must stay loadable and secret-free."""
    def test_local_endpoint_loads(self):
        os.environ['PI_BASE_URL']='http://example.invalid:8000/v1'; os.environ['PI_MODEL']='m'
        obj=lab.load_endpoint(ROOT/'assets/endpoint.example.json')
        self.assertTrue(obj['base_url'].endswith('/v1'))
        self.assertLess(obj['max_tokens'],obj['context_window'])
        self.assertEqual(obj['api_key_env'],'PI_API_KEY')

    def test_local_endpoint_has_no_literal_key(self):
        raw=json.loads((ROOT/'assets/endpoint.example.json').read_text())
        self.assertNotIn('apiKey',raw)
        self.assertRegex(raw['api_key_env'],r'^[A-Z_][A-Z0-9_]*$')


class ProjectContractTests(unittest.TestCase):
    def test_monorepo_cwd(self):
        t=task();t['agents'][0]['cwd']='services/api'
        t['checks'][0]['cwd']='packages/client'
        p=lab.validate_plan(t,ROOT)
        self.assertEqual(p['agents'][0]['cwd'],'services/api')

    def test_escape_cwd_rejected(self):
        for cwd in ('../project','/etc','a\\b','.pi-lab'):
            t=task();t['agents'][0]['cwd']=cwd
            with self.subTest(cwd=cwd),self.assertRaises(lab.LabError):lab.validate_plan(t,ROOT)

    def test_dot_cwd_accepted(self):
        self.assertEqual(lab.working_directory('.'),'.')

    def test_required_missing_blocked(self):
        t=lab.validate_plan(task(),ROOT)
        with tempfile.TemporaryDirectory() as td, self.assertRaises(lab.LabError):
            lab.check_project_contract(Path(td),t)

    def test_required_and_cwd_present(self):
        t=task();t['required_paths']=['SPEC.md'];t['agents'][0]['cwd']='src'
        p=lab.validate_plan(t,ROOT)
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/'SPEC.md').write_text('fixture');(root/'tests').mkdir();(root/'src').mkdir()
            lab.check_project_contract(root,p)

    def test_invalid_stage_object(self):
        t=task();t['agents']=['not an object']
        with self.assertRaises(lab.LabError):lab.validate_plan(t,ROOT)

    def test_tool_string_not_array(self):
        t=task();t['agents'][0]['tools']='read'
        with self.assertRaises(lab.LabError):lab.validate_plan(t,ROOT)

    def test_missing_protected_test_prevents_execution(self):
        p=lab.validate_plan(json.loads((ROOT/'assets/python-feature.plan.json').read_text()),ROOT)
        with tempfile.TemporaryDirectory() as td, self.assertRaises(lab.LabError):
            lab.check_project_contract(Path(td),p)

    def test_bundled_demo_paths_exist(self):
        for project,plan in [('python-project','python-feature.plan.json'),('node-project','node-cli.plan.json')]:
            p=lab.validate_plan(json.loads((ROOT/'assets'/plan).read_text()),ROOT/'assets')
            lab.check_project_contract(ROOT/'examples'/project,p)


class LegacyEventTests(unittest.TestCase):
    def result(self,ev,contract):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'events.jsonl';p.write_text(''.join(json.dumps(e)+'\n' for e in ev))
            return analyze(p,'test-model',['read'],0,contract,
                           release=None if contract=='process-exit' else '0.87.1',
                           historical=contract=='process-exit')

    def test_explicit_legacy_accepts_clean_exit(self):
        self.assertTrue(self.result(events()[:-1],'process-exit')['agent_invocation_verified'])

    def test_default_does_not_automatically_downgrade(self):
        self.assertFalse(self.result(events()[:-1],'settled')['agent_invocation_verified'])

    def test_legacy_rejects_pending_retry(self):
        ev=events()[:-1];ev[-1]['willRetry']=True
        self.assertFalse(self.result(ev,'process-exit')['agent_invocation_verified'])

    def test_legacy_rejects_unended_lifecycle(self):
        self.assertFalse(self.result(events()[:-2],'process-exit')['agent_invocation_verified'])

    def test_bad_contract_rejected(self):
        with self.assertRaises(ValueError):self.result(events(),'ignore-errors')

    def test_pending_message_rejected(self):
        ev=events();ev.insert(-1,{'type':'message_start','message':{'role':'assistant'}})
        self.assertFalse(self.result(ev,'process-exit')['agent_invocation_verified'])


class PackageTests(unittest.TestCase):
    def test_all_material_english(self):
        for p in ROOT.rglob('*'):
            if p.is_file() and p.suffix in ('.md','.py','.mjs','.json') and '__pycache__' not in p.parts:
                text=p.read_text()
                self.assertFalse(any('\u0400'<=c<='\u04ff' for c in text),str(p))

    def test_skill_frontmatter_name(self):
        text=(ROOT/'SKILL.md').read_text()
        self.assertTrue(text.startswith('---\nname: pi-agent-test-env\n'))
        _,frontmatter,body=text.split('---',2)
        self.assertEqual(set(re.findall(r'^([a-z][a-z0-9-]*):',frontmatter,re.MULTILINE)),{'name','description'})
        self.assertIn('Instructions are in English.',body)
        self.assertEqual(json.loads((ROOT/'skill.json').read_text())['language'],'en')
        self.assertIn('Package version: '+json.loads((ROOT/'skill.json').read_text())['version']+'.',body)
        self.assertLess(len(text.splitlines()),500)

    def test_runtime_browser_helper_export(self):
        self.assertIn('export function browserOptions(', (ROOT/'runtime/browser-options.mjs').read_text())
