"""Offline configuration/context/measurement regressions; not live qualification."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT=(Path(__file__).resolve().parents[1] / 'skill')
sys.path.insert(0,str(ROOT/'runtime'));sys.path.insert(0,str(ROOT/'scripts'))
import pi_contract


def endpoint():
    return {'base_url':'http://example.invalid/v1','model':'exact/model','context_window':32768,
            'max_tokens':4096,'api_key_env':'PI_API_KEY'}


class ReasoningTests(unittest.TestCase):
    def test_off_on_and_levels_emit_exact_supported_configuration(self):
        for value,level,enabled in [(False,'off',False),(True,'low',True),*[(dict(enabled=True,level=x),x,True) for x in pi_contract.LEVELS]]:
            with self.subTest(value=value):
                config=endpoint();config['reasoning']=value
                models,settings,argv,receipt=pi_contract.model_configuration(config,'0.87.1')
                self.assertEqual(argv,['--thinking',level]);self.assertEqual(settings['defaultThinkingLevel'],level)
                self.assertIs(models['providers']['local-lab']['models'][0]['reasoning'],enabled)
                self.assertNotIn('thinkingBudget',settings);self.assertNotIn('--thinking-budget',argv)
                self.assertFalse(settings['retry']['enabled']);self.assertFalse(settings['compaction']['enabled'])
                self.assertEqual(receipt['server_enforcement'],'unverified')

    def test_budget_and_unqualified_release_fail_without_substitution(self):
        config=endpoint();config['reasoning']={'enabled':True,'level':'medium','budget_tokens':2048}
        before=copy.deepcopy(config)
        with self.assertRaisesRegex(ValueError,'unsupported'):pi_contract.model_configuration(config,'0.87.1')
        self.assertEqual(config,before)
        config['reasoning']=True
        with self.assertRaisesRegex(ValueError,'No version/model substitution'):pi_contract.model_configuration(config,'different')
        config['reasoning']=False
        with self.assertRaises(ValueError):pi_contract.model_configuration(config,None)

import context_contract
import lab_env
import worker


class ContextTests(unittest.TestCase):
    def test_effective_fields_and_conflicts_are_conservative(self):
        for prefix in ('','meta'):
            for field in context_contract.CURRENT_FIELDS:
                item={'id':'m',**({prefix:{field:2048}} if prefix else {field:2048})}
                with self.assertRaises(ValueError):context_contract.check_context(context_contract.interpret_context('m',[item]),4096)
        value=context_contract.interpret_context('m',[{'id':'m','context_length':8192,'max_model_len':4096}],{'model':'m','default_generation_settings':{'n_ctx':2048}})
        self.assertEqual(value['effective_limit'],2048);self.assertTrue(value['conflict'])

    def test_invalid_training_and_unassociated_values_are_unknown(self):
        for bad in (True,False,-1,0,'8192',None,1.5):
            value=context_contract.interpret_context('m',[{'id':'m','context_length':bad,'meta':{'n_ctx_train':131072}}])
            self.assertIsNone(value['effective_limit']);self.assertEqual(value['training_maxima'][0]['value'],131072)
        for props in ({'model':'other','context_length':1024},{'default_generation_settings':{'n_ctx':1024}}):
            self.assertIsNone(context_contract.interpret_context('m',[{'id':'m'},{'id':'other'}],props)['effective_limit'])
        value=context_contract.interpret_context('m',[{'id':'m'}],{'default_generation_settings':{'n_ctx':2048}})
        self.assertEqual(value['props_association'],'single_listed_model_inference')

    def test_host_and_runtime_recheck_the_same_changed_limit(self):
        config=endpoint();config['model']='m';config['context_window']=4096
        listing={'data':[{'id':'m','meta':{'max_model_len':2048}}]}
        with mock.patch.object(lab_env.secret_store,'resolve_secret',return_value=('test-key','env')),mock.patch.object(lab_env,'http_json',return_value=listing):
            with self.assertRaisesRegex(lab_env.EnvError,'2048'):lab_env.health_check(config,chat=False)
        class Reply:
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def read(self,*a):return json.dumps(listing).encode()
        with mock.patch.dict(os.environ,{'PI_LAB_API_KEY':'test-key'}),mock.patch.object(worker,'build_opener') as opener:
            opener.return_value.open.return_value=Reply()
            with self.assertRaisesRegex(ValueError,'2048'):worker.preflight(config)

import pi_lab


class RouteTests(unittest.TestCase):
    def validate(self,value):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'endpoint.json';path.write_text(json.dumps(value))
            return pi_lab.load_endpoint(path)

    def test_additive_default_and_invalid_routes(self):
        self.assertEqual(self.validate(endpoint())['host_base_url'],endpoint()['base_url'])
        for route in ('base_url','host_base_url'):
            for bad in ('http://key:secret@host/v1','http://host:bad/v1','http://host/v1?q=1','ftp://host/v1',False):
                with self.subTest(route=route,bad=bad),self.assertRaises(pi_lab.LabError):self.validate({**endpoint(),route:bad})
        pair=self.validate({**endpoint(),'base_url':'http://model-container:8080/v1','host_base_url':'http://127.0.0.1:18080/v1'})
        self.assertNotEqual(pair['base_url'],pair['host_base_url'])
        self.assertNotEqual(lab_env.fingerprint_of(pair),lab_env.fingerprint_of({**pair,'host_base_url':'http://127.0.0.1:18081/v1'}))

    def test_health_uses_host_and_child_preflight_uses_child_without_fallback(self):
        config={**endpoint(),'base_url':'http://docker-model:8080/v1','host_base_url':'http://127.0.0.1:18080/v1'}
        listing={'data':[{'id':config['model']}]}
        with mock.patch.object(lab_env.secret_store,'resolve_secret',return_value=('test-key','env')),mock.patch.object(lab_env,'http_json',return_value=listing) as http:
            lab_env.health_check(config,chat=False)
            self.assertEqual(http.call_args_list[0].args[0],config['host_base_url']+'/models')
            http.return_value={'data':[{'id':'wrong'}]}
            with self.assertRaises(lab_env.EnvError):lab_env.health_check(config,chat=False)
        class Reply:
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def read(self,*a):return json.dumps(listing).encode()
        with mock.patch.dict(os.environ,{'PI_LAB_API_KEY':'test-key'}),mock.patch.object(worker,'build_opener') as opener,mock.patch.object(worker,'emit'):
            opener.return_value.open.return_value=Reply();worker.preflight(config)
            self.assertEqual(opener.return_value.open.call_args_list[0].args[0].full_url,config['base_url']+'/models')

import subprocess


class NestedVerifierTests(unittest.TestCase):
    def run_helper(self,files,cwd='',extra=()):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name,content in files.items():
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(content)
            env={k:v for k,v in os.environ.items() if k!='PYTHONPATH'}
            return subprocess.run([sys.executable,str(ROOT/'runtime/verify-unittest.py'),*extra],cwd=root/cwd,env=env,text=True,capture_output=True)

    def test_nested_root_and_package_imports_by_absolute_helper(self):
        test='import unittest\nfrom app import add\nclass TestApp(unittest.TestCase):\n def test_add(self):self.assertEqual(add(2,3),5)\n'
        for prefix in ('','services/api/'):
            result=self.run_helper({prefix+'app.py':'def add(a,b):return a+b\n',prefix+'tests/test_app.py':test},cwd=prefix)
            self.assertEqual(result.returncode,0,result.stderr);self.assertIn('INDEPENDENT_TESTS_RUN=1',result.stdout)
        result=self.run_helper({'pkg/__init__.py':'','pkg/app.py':'value=7','pkg/tests/__init__.py':'','pkg/tests/test_app.py':'import unittest\nfrom pkg.app import value\nclass TestApp(unittest.TestCase):\n def test_value(self):self.assertEqual(value,7)\n'},cwd='pkg',extra=('--top-level-dir','..'))
        self.assertEqual(result.returncode,0,result.stderr)

    def test_missing_import_assertion_and_no_tests_fail(self):
        for content in ('import absent_module_xyz\n','import unittest\nclass TestApp(unittest.TestCase):\n def test_fail(self):self.fail("expected")\n',''):
            result=self.run_helper({'tests/__init__.py':'','tests/test_app.py':content})
            self.assertNotEqual(result.returncode,0)

import provenance


class ProvenanceTests(unittest.TestCase):
    def test_sampling_emits_exact_allowlist_and_rejects_overrides(self):
        config={**endpoint(),'sampling':{'temperature':0.5,'top_p':0.9,'top_k':40,'min_p':0.05,'repetition_penalty':1.1,'seed':123}}
        models,settings,argv,receipt=pi_contract.model_configuration(config,'0.87.1')
        self.assertEqual(models['providers']['local-lab']['models'][0]['samplingParams'],config['sampling'])
        self.assertEqual(receipt['sampling']['server_enforcement'],'unverified')
        for bad in ({'model':'other'},{'max_tokens':100000},{'temperature':True},{'top_p':1.5},{'seed':1.5},{'temperature':float('nan')},{'top_k':-1}):
            with self.subTest(bad=bad),self.assertRaises(ValueError):pi_contract.model_configuration({**endpoint(),'sampling':bad},'0.87.1')
        with self.assertRaises(ValueError):pi_contract.model_configuration(config,'other')

    def test_provenance_differs_without_git_and_excludes_credentials(self):
        image={'id':'sha256:fixture','platform':'linux/arm64','capabilities':{'pi':'0.87.1'}}
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'runtime').mkdir();(root/'runtime/worker.py').write_text('reviewed source')
            a=provenance.execution(endpoint(),image,root)
            b=provenance.execution({**endpoint(),'sampling':{'seed':2},'server_provenance':{'weights':'declared/model'}},image,root)
            self.assertNotEqual(a['configuration_sha256'],b['configuration_sha256']);self.assertIsNone(a['server']['values']['weights'])
            self.assertEqual(b['server']['origin'],'user_declared');self.assertNotIn('PI_API_KEY',json.dumps(a))
            self.assertEqual(a['configuration_sha256'],provenance.execution({**endpoint(),'api_key_env':'OTHER_KEY'},image,root)['configuration_sha256'])

    def test_child_emissions_are_bounded_and_never_follow_links_or_copy_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);runtime=root/'runtime';runtime.mkdir();logs=root/'logs';logs.mkdir()
            (runtime/'effective-prompt.txt').write_text('actual prompt');(runtime/'effective-configuration.json').write_text('secret-value')
            (runtime/'agent').symlink_to(root)
            result=provenance.collect_emitted(runtime,logs,'secret-value')
            self.assertEqual(result['effective-prompt.txt']['origin'],'worker_reported')
            self.assertEqual(result['agent/models.json']['status'],'unavailable_or_unsafe')
            self.assertEqual(result['effective-configuration.json']['status'],'unavailable_or_unsafe')
            self.assertNotIn('secret-value',''.join(p.read_text() for p in logs.iterdir()))

import usage_contract
from evidence import analyze


class UsageTests(unittest.TestCase):
    def test_categories_missingness_cache_and_segments(self):
        first=usage_contract.summarize([{'usage':{'input':100,'output':10,'cacheRead':50,'cacheWrite':0,'totalTokens':160}},
                                       {'usage':{'input':100,'output':20,'cacheRead':50,'cacheWrite':0,'totalTokens':170}}])
        self.assertEqual(first['categories']['input']['reported'],200)
        self.assertEqual(first['categories']['total']['reported'],330)
        second=usage_contract.summarize([{'usage':{'input':100,'output':5,'cacheRead':0,'cacheWrite':25,'totalTokens':130}}])
        combined=usage_contract.combine([first,second])
        self.assertEqual(combined['categories']['cache_read']['reported'],100)
        self.assertEqual(combined['categories']['cache_write']['reported'],25)
        self.assertIsNone(combined['inference_seconds'])
        self.assertIsNone(usage_contract.combine([first,usage_contract.summarize([])])['categories']['total']['reported'])
        partial=usage_contract.combine([first,usage_contract.summarize([{}])])
        self.assertIsNone(partial['categories']['total']['reported'])
        self.assertEqual(partial['categories']['total']['known_sum'],330)
        self.assertEqual(partial['categories']['total']['missing_messages'],1)
        self.assertIsNone(usage_contract.summarize([{'usage':{'totalTokens':0}}])['categories']['total']['reported'])

    def test_stream_updates_and_end_summaries_do_not_duplicate_final_usage(self):
        from test_lab import events, final_event
        fixture=events();message=final_event(fixture)['message'];message['usage']={'input':100,'output':7,'cacheRead':0,'cacheWrite':0,'totalTokens':107}
        position=fixture.index(final_event(fixture))
        updates=[{'type':'message_update','message':message,'assistantMessageEvent':{'type':'text_delta','contentIndex':0,'delta':'x','partial':message}} for _ in range(3)]
        fixture[position:position]=updates
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'trace.jsonl';path.write_text('\n'.join(json.dumps(x) for x in fixture))
            receipt=analyze(path,'test-model',['read'],0)
        self.assertTrue(receipt['agent_invocation_verified'],receipt['errors'])
        self.assertIsNone(receipt['provider_reported_total_tokens'])
        self.assertEqual(receipt['usage']['categories']['total']['known_sum'],107)
        self.assertEqual(receipt['usage']['categories']['output']['known_sum'],7)


import segments


class LiveReviewRegressionTests(unittest.TestCase):
    def test_limit_classification_uses_cumulative_counts_and_approved_caps(self):
        process={'exit_code':124,'termination_reason':'process_error','effective_limits':{'max_turns':3,'max_total_tokens':100}}
        evidence={'events':{'turn_start':2},'usage':usage_contract.summarize([{'usage':{'totalTokens':60}}])}
        self.assertEqual(segments.classify_worker_limit(copy.deepcopy(process),evidence,2,0)['termination_reason'],'turn_limit')
        revised=copy.deepcopy(process);revised['effective_limits']['max_turns']=10
        self.assertEqual(segments.classify_worker_limit(revised,evidence,2,50)['termination_reason'],'token_limit')
        self.assertEqual(segments.classify_worker_limit(copy.deepcopy(process),evidence)['termination_reason'],'process_error')
        for cause in ('cancelled','timeout','oom','cleanup_error','interrupted'):
            value={**process,'termination_reason':cause}
            self.assertEqual(segments.classify_worker_limit(value,evidence,10,1000)['termination_reason'],cause)
