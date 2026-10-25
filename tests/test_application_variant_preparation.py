"""Frozen explicit experiment variants; no catalog/key/runtime lookup in compile."""
import copy
import hashlib
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_contracts as c
import application_preparation as preparation
import application_variants
import inference_catalog
import pi_lab
import resources
import test_application_preparation as base_fixture
import test_indexed_contract as indexed_fixture


class VariantArtifactTests(unittest.TestCase):
    def setUp(self):
        self.fixture=base_fixture.PreparationTests(methodName='runTest');self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups);self.root=self.fixture.root
        source=self.fixture.source;source['runtime']['inference_owner']='experiment_variant'
        second=copy.deepcopy(source['stages'][0]);second['id']='reviewer';second['depends_on']=['participant']
        second['completion']['id']='reviewer-report';second['completion']['report_path']='reviewer/completion.json'
        second['completion']['artifacts'][0]['path']='reviewer/summary.md'
        source['stages'].append(second);self.fixture.write('source.json',source)
        first=pi_lab.normalize_endpoint(self.fixture.endpoint)
        second=pi_lab.normalize_endpoint({**self.fixture.endpoint,'model':'heterogeneous-review-model',
            'api_key_env':'REVIEW_MODEL_REFERENCE','context_window':900000,'max_tokens':2048})
        self.bindings={'participant':{'kind':'legacy','endpoint':first},'reviewer':{'kind':'legacy','endpoint':second}}

    def compile(self,name='variant',**changes):
        args={'variant_id':'candidate','bindings':self.bindings};args.update(changes)
        return preparation.compile_variant_artifact(self.fixture.spec,self.root/name,self.fixture.runtime_path,**args)

    def json(self,root,name):return c.loads((Path(root)/name).read_bytes())

    def rehash(self,root,updates,plan_sha256=None):
        root=Path(root);manifest=self.json(root,'input-manifest.json')
        for name,value in updates.items():
            path=root/name;path.chmod(0o600);path.write_bytes(c.canonical(value))
            manifest['files'][name]=hashlib.sha256(path.read_bytes()).hexdigest()
        if plan_sha256 is not None:manifest['plan_sha256']=plan_sha256
        manifest['manifest_sha256']=c.digest({key:value for key,value in manifest.items() if key!='manifest_sha256'})
        path=root/'input-manifest.json';path.chmod(0o600);path.write_bytes(c.canonical(manifest))

    def test_repeatable_variant_freezes_original_source_explicit_nulls_and_heterogeneous_full_bindings(self):
        before=copy.deepcopy((self.fixture.source,self.bindings))
        with mock.patch.object(socket,'socket',side_effect=AssertionError('No network')), \
             mock.patch.object(subprocess,'Popen',side_effect=AssertionError('No child')), \
             mock.patch.object(inference_catalog.Catalog,'select',side_effect=AssertionError('No selector lookup')), \
             mock.patch.object(inference_catalog.Catalog,'_secret',side_effect=AssertionError('No key reads')):
            first=self.compile();second=self.compile('second')
            loaded=preparation.load_compiled(Path(first['root'])/'plan.json',verify_runner=True)
        self.assertEqual(first['plan'],second['plan']);self.assertEqual(first['manifest'],second['manifest'])
        self.assertEqual(loaded,first);self.assertEqual((self.fixture.source,self.bindings),before)
        self.assertEqual(first['manifest']['document_type'],'application_variant_input_manifest')
        self.assertEqual(set(first['manifest']),preparation.MANIFEST_FIELDS)
        variant=self.json(first['root'],'variant.json')
        self.assertEqual(variant,{'schema':1,'variant_id':'candidate','bindings':self.bindings,
            'runtime':None,'resources':None,'budgets':None,'prompt_suffix':''})
        self.assertEqual(self.json(first['root'],'source.json'),self.fixture.source)
        inference=self.json(first['root'],'inference.json')
        self.assertEqual(set(inference),{'kind','variant_id','stages'});self.assertEqual(inference['kind'],'variant')
        for stage in first['plan']['stages']:
            wrapper=self.bindings[stage['id']];endpoint=wrapper['endpoint'];binding=stage['inference_binding']
            self.assertEqual(binding['selection'],application_variants.variant_selection('candidate','legacy',endpoint))
            self.assertEqual(binding['selection']['owner'],'experiment_variant')
            self.assertEqual(binding['configuration_sha256'],c.digest(endpoint))
            self.assertEqual((binding['context_window'],binding['max_tokens']),(endpoint['context_window'],endpoint['max_tokens']))
            self.assertEqual(inference['stages'][stage['id']]['configuration'],endpoint)

    def test_runtime_resources_budgets_and_suffix_are_applied_before_final_render_validation(self):
        runtime={'pi_release':'0.87.1','image_id':'sha256:'+'e'*64}
        observation={**self.fixture.runtime,'id':runtime['image_id'],'capabilities':{'pi':'0.87.1'}}
        self.fixture.write('runtime.json',observation)
        policy=copy.deepcopy(resources.DEFAULTS);policy['runtime'].update(cpus=1,memory='2g',pids_limit=128,jobs=1)
        budgets={'timeout_seconds':60,'max_turns':5,'max_total_tokens':10000,'max_tool_calls':12,
                 'reporting_reserve_calls':2,'reporting_reserve_seconds':10}
        suffix='UNIQUE_VARIANT_SUFFIX_BEFORE_RENDER'
        result=self.compile(runtime=runtime,resources=policy,budgets=budgets,prompt_suffix=suffix)
        self.assertEqual(result['plan']['runtime']['pi_release'],'0.87.1')
        self.assertEqual(result['plan']['runtime']['image_id'],runtime['image_id'])
        self.assertEqual(result['plan']['runtime']['resources'],resources.validate_policy(policy))
        self.assertEqual(self.json(result['root'],'source.json'),self.fixture.source)
        for stage in result['plan']['stages']:
            self.assertEqual(stage['limits'],budgets);self.assertEqual(stage['profile_binding']['pi_release'],'0.87.1')
            self.assertEqual(stage['effective_prompt'].count(suffix),1)
            self.assertIn('"max_tool_calls":12',stage['effective_prompt'])
            self.assertIn('"timeout_seconds":60',stage['effective_prompt'])
            self.assertEqual(self.json(result['root'],'prompt-policy.json')['variant_instructions'][stage['id']],suffix)
        self.assertEqual(preparation.load_compiled(Path(result['root'])/'plan.json'),result)

    def test_selected_context_and_suffix_caps_reject_final_prompt_without_output(self):
        baseline=self.compile('baseline')
        for stage in baseline['plan']['stages']:
            self.bindings[stage['id']]['endpoint']['context_window']=stage['prompt_admission']['total_upper_bound']+1024
        self.compile('tight-context')
        with self.assertRaises(preparation.PreparationError):self.compile('too-large',prompt_suffix='x'*4096)
        self.assertFalse((self.root/'too-large').exists())
        invalid={**self.fixture.source['stages'][0]['limits'],'timeout_seconds':5,'reporting_reserve_seconds':10}
        with self.assertRaises(preparation.PreparationError):self.compile('invalid-budget',budgets=invalid)
        self.assertFalse((self.root/'invalid-budget').exists())

    def test_runtime_observation_must_match_transformed_runtime_not_original(self):
        with self.assertRaises(preparation.PreparationError):self.compile(runtime={'image_id':'sha256:'+'f'*64})
        self.assertFalse((self.root/'variant').exists())

    def indexed_bindings(self):
        catalog=self.root/'catalog';selected=inference_catalog.Catalog(pi_lab.normalize_endpoint,catalog,self.root/'absent-store')
        result={}
        for name in self.bindings:
            config=indexed_fixture.config();config['endpoint'].update(context_window=1000000,max_tokens=4096,model=name+'-model')
            config['credential']['name']='REFERENCE_'+name.upper()
            selected.register(name,config)
            entry=selected.select(name);entry['authority_id']=str(uuid.uuid4())
            result[name]={'kind':'indexed','entry':entry}
        return catalog,result

    def test_indexed_explicit_entries_compile_without_catalog_or_keys_and_load_after_deletion(self):
        catalog,bindings=self.indexed_bindings()
        with mock.patch.object(inference_catalog.Catalog,'select',side_effect=AssertionError('No selector lookup')), \
             mock.patch.object(inference_catalog.Catalog,'_secret',side_effect=AssertionError('No key reads')):
            result=self.compile(bindings=bindings)
        variant=self.json(result['root'],'variant.json');inference=self.json(result['root'],'inference.json')
        self.assertEqual(variant['bindings'],bindings)
        for name,selected in inference['stages'].items():
            self.assertNotIn('authority_id',selected['catalog_entry'])
            self.assertEqual(selected['selection'],application_variants.variant_selection('candidate','indexed',bindings[name]['entry']))
        shutil.rmtree(catalog);shutil.rmtree(self.fixture.inputs)
        with mock.patch.object(inference_catalog.Catalog,'select',side_effect=AssertionError('No catalog reselection')):
            self.assertEqual(preparation.load_compiled(Path(result['root'])/'plan.json'),result)

    def test_authority_ids_do_not_change_variant_ir_selection(self):
        _,bindings=self.indexed_bindings();first=self.compile(bindings=bindings)
        changed=copy.deepcopy(bindings)
        for wrapper in changed.values():wrapper['entry']['authority_id']=str(uuid.uuid4())
        second=self.compile('second',bindings=changed)
        self.assertEqual(first['plan'],second['plan'])
        self.assertNotEqual(first['manifest']['manifest_sha256'],second['manifest']['manifest_sha256'])

    def test_exhaustive_uniform_bindings_and_reference_scopes_reject_before_publication(self):
        _,indexed=self.indexed_bindings()
        cases=[{'participant':self.bindings['participant']},
               {**self.bindings,'unknown':self.bindings['participant']},
               {'participant':self.bindings['participant'],'reviewer':indexed['reviewer']}]
        reference=next(iter(self.fixture.source['application']['credentials'].values()))
        collision=copy.deepcopy(self.bindings);collision['reviewer']['endpoint']['api_key_env']=reference;cases.append(collision)
        for number,value in enumerate(cases):
            with self.subTest(number=number),self.assertRaises(preparation.PreparationError):self.compile('rejected-'+str(number),bindings=value)
            self.assertFalse((self.root/('rejected-'+str(number))).exists())

    def test_variant_owner_required_and_standalone_selector_arguments_are_not_accepted(self):
        with self.assertRaises(TypeError):
            preparation.compile_variant_artifact(self.fixture.spec,self.root/'bad',self.fixture.runtime_path,
                variant_id='candidate',bindings=self.bindings,endpoint_path=self.fixture.endpoint_path)
        self.fixture.source['runtime']['inference_owner']='compiler_input';self.fixture.write('source.json',self.fixture.source)
        with self.assertRaises(preparation.PreparationError):self.compile()
        self.assertFalse((self.root/'variant').exists())

    def test_rehashed_variant_suffix_policy_and_budget_changes_cannot_keep_old_ir(self):
        for number,change in enumerate(('suffix','budget')):
            result=self.compile('frozen-'+str(number));root=result['root'];variant=self.json(root,'variant.json')
            updates={}
            if change=='suffix':
                variant['prompt_suffix']='changed frozen instruction'
                policy=self.json(root,'prompt-policy.json')
                policy['variant_instructions']={name:variant['prompt_suffix'] for name in self.bindings}
                updates['prompt-policy.json']=policy
            else:
                variant['budgets']=copy.deepcopy(self.fixture.source['stages'][0]['limits'])
                variant['budgets']['max_tool_calls']+=1
            updates['variant.json']=variant;self.rehash(root,updates)
            with self.subTest(change=change),self.assertRaises(preparation.PreparationError):preparation.load_compiled(Path(root)/'plan.json')

    def test_rehashed_full_configuration_and_self_rehashed_ir_mutations_fail_reconstruction(self):
        for number,change in enumerate(('configuration','ir')):
            result=self.compile('tampered-'+str(number));root=result['root']
            if change=='configuration':
                inference=self.json(root,'inference.json');inference['stages']['reviewer']['configuration']['api_key_env']='DIFFERENT_REFERENCE'
                self.rehash(root,{'inference.json':inference})
            else:
                plan=copy.deepcopy(result['plan']);prompt=plan['stages'][0]['effective_prompt']
                plan['stages'][0]['effective_prompt']=('u' if prompt[0]!='u' else 'v')+prompt[1:]
                plan['plan_sha256']=c.digest({key:value for key,value in plan.items() if key!='plan_sha256'})
                diagnostics=self.json(root,'diagnostics.json');diagnostics['plan_sha256']=plan['plan_sha256']
                self.rehash(root,{'plan.json':plan,'diagnostics.json':diagnostics},plan['plan_sha256'])
            with self.subTest(change=change),self.assertRaises(preparation.PreparationError):preparation.load_compiled(Path(root)/'plan.json')

    def test_variant_publish_uses_shared_no_overwrite_and_fd_cleanup_on_failure(self):
        result=self.compile();before=self.fixture.inventory(Path(result['root']))
        with self.assertRaises(preparation.PreparationError):self.compile()
        self.assertEqual(self.fixture.inventory(Path(result['root'])),before)
        original=self.fixture.inventory(self.fixture.inputs)
        with mock.patch.object(preparation,'_sync_tree',side_effect=OSError('controlled sync fault')):
            with self.assertRaises(preparation.PreparationError):self.compile('fault')
        self.assertFalse((self.root/'fault').exists());self.assertFalse(list(self.root.glob('.application-compile-*')))
        self.assertEqual(self.fixture.inventory(self.fixture.inputs),original)

    def test_frozen_loader_never_treats_variant_manifest_as_standalone(self):
        result=self.compile();root=Path(result['root']);manifest=self.json(root,'input-manifest.json')
        manifest['document_type']='application_input_manifest'
        manifest['manifest_sha256']=c.digest({key:value for key,value in manifest.items() if key!='manifest_sha256'})
        path=root/'input-manifest.json';path.chmod(0o600);path.write_bytes(c.canonical(manifest))
        with self.assertRaises(preparation.PreparationError):preparation.load_compiled(root/'plan.json')


if __name__=='__main__':unittest.main()
