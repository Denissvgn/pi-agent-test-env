"""Pure variant compilation from explicit bytes; no experiment dispatch claim."""
import copy
from pathlib import Path
import sys
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import agent_profiles
import application_compiler
import application_contracts as c
import application_variants as variants
import indexed_contract
import inference_catalog
import pi_lab
import resources
import secret_store
import test_application_compiler as fixtures
from test_indexed_contract import config


def inputs(kind='legacy',source=None):
    source,kwargs=fixtures.inputs(fixtures.two_stages() if source is None else source)
    source['runtime']['inference_owner']='experiment_variant'
    profile=agent_profiles.application(source['runtime']['pi_release'])
    bindings={}
    for stage in source['stages']:
        name=stage['id']
        kwargs['profile_bindings'][name]={'id':'application-client','pi_release':source['runtime']['pi_release'],
            'sha256':agent_profiles.identity(profile),'assets':{asset['target']:asset['sha256'] for asset in profile['assets']}}
        for asset in profile['assets']:
            kwargs['input_assets']['profiles/'+name+'/'+asset['target']]=agent_profiles.read_asset(asset['source'])
        kwargs['prompt_policy']['profile_instructions'][name]=kwargs['input_assets']['profiles/'+name+'/instructions.md'].decode()
        endpoint=pi_lab.normalize_endpoint({'base_url':'http://model-fixture.invalid/v1',
            'model':'frozen-'+name,'api_key_env':'MODEL_REFERENCE','context_window':1000000,'max_tokens':4096})
        if kind=='legacy':bindings[name]={'kind':'legacy','endpoint':endpoint}
        else:
            value=config();value['endpoint']={key:child for key,child in endpoint.items() if key!='api_key_env'}
            value['endpoint']['model']='frozen-é-'+name
            configuration=indexed_contract.configuration(value,pi_lab.normalize_endpoint)
            entry={'id':'env-'+name,'incarnation':str(uuid.uuid4()),'revision':1,
                'configuration':configuration,'fingerprint':indexed_contract.digest(configuration)}
            bindings[name]={'kind':'indexed','entry':entry}
    kwargs.pop('inference_bindings')
    return source,dict(kwargs,variant_id='candidate',bindings=bindings)


class VariantTests(unittest.TestCase):
    def test_determinism_same_compiler_and_input_immutability(self):
        source,kwargs=inputs();before=copy.deepcopy((source,kwargs))
        with mock.patch.object(application_compiler,'compile_plan',wraps=application_compiler.compile_plan) as compile_plan:
            first=variants.compile_variant(source,**kwargs)
        self.assertEqual(compile_plan.call_count,1)
        self.assertEqual(first,variants.compile_variant(source,**kwargs));self.assertEqual((source,kwargs),before)
        built=variants.build_variant_inputs(source,**kwargs)
        self.assertEqual(first,application_compiler.compile_plan(built['source'],**built['compiler_kwargs']))
        self.assertEqual([stage['id'] for stage in first['stages']],['participant','second'])

    def test_owner_required_and_no_competing_selector_api(self):
        source,kwargs=inputs();source['runtime']['inference_owner']='compiler_input'
        with self.assertRaises(variants.VariantError):variants.compile_variant(source,**kwargs)
        source['runtime']['inference_owner']='experiment_variant'
        for key in ('endpoint_path','catalog_root','inference_env_id','inference_key'):
            with self.subTest(key=key),self.assertRaises(TypeError):variants.compile_variant(source,**kwargs,**{key:'forbidden'})
        with self.assertRaises(variants.VariantError):variants.compile_variant(source,**kwargs,runtime={'inference_owner':'compiler_input'})

    def test_missing_extra_mixed_and_conflicting_binding_maps_reject(self):
        source,kwargs=inputs();_,indexed=inputs('indexed')
        for fault in ('missing','extra','mixed','selector','unknown'):
            with self.subTest(fault=fault):
                selected=copy.deepcopy(kwargs)
                if fault=='missing':selected['bindings'].pop('second')
                elif fault=='extra':selected['bindings']['extra']=copy.deepcopy(selected['bindings']['participant'])
                elif fault=='mixed':selected['bindings']['second']=indexed['bindings']['second']
                elif fault=='selector':selected['bindings']['participant']['inference_env']='mutable-default'
                else:selected['bindings']['participant']['kind']='unknown'
                with self.assertRaises((ValueError,TypeError)):variants.compile_variant(source,**selected)

    def test_indexed_full_entry_identity_changes_but_authority_only_does_not(self):
        source,kwargs=inputs('indexed');base=variants.compile_variant(source,**kwargs)
        for field,value in [('incarnation',str(uuid.uuid4())),('revision',2),('id','different-env')]:
            with self.subTest(field=field):
                selected=copy.deepcopy(kwargs);selected['bindings']['participant']['entry'][field]=value
                changed=variants.compile_variant(source,**selected)
                self.assertNotEqual(changed['plan_sha256'],base['plan_sha256'])
                self.assertEqual(changed['stages'][0]['inference_binding']['configuration_sha256'],base['stages'][0]['inference_binding']['configuration_sha256'])
        selected=copy.deepcopy(kwargs)
        for item in selected['bindings'].values():item['entry']['authority_id']=str(uuid.uuid4())
        self.assertEqual(variants.compile_variant(source,**selected),base)
        entry=kwargs['bindings']['participant']['entry']
        self.assertNotEqual(c.digest(entry['configuration']),entry['fingerprint'])
        self.assertEqual(base['stages'][0]['inference_binding']['selection'],variants.variant_selection('candidate','indexed',entry))

    def test_variant_name_reference_caps_and_request_flags_change_frozen_identity(self):
        source,kwargs=inputs('indexed');base=variants.compile_variant(source,**kwargs)
        selected=copy.deepcopy(kwargs);selected['variant_id']='another-candidate'
        self.assertNotEqual(variants.compile_variant(source,**selected)['plan_sha256'],base['plan_sha256'])
        for fault in ('reference','max_tokens','compat','reasoning'):
            with self.subTest(fault=fault):
                selected=copy.deepcopy(kwargs);entry=selected['bindings']['participant']['entry'];configuration=entry['configuration']
                if fault=='reference':
                    configuration['credential']['name']='OTHER_REFERENCE';configuration['endpoint']['api_key_env']='OTHER_REFERENCE'
                elif fault=='max_tokens':configuration['endpoint']['max_tokens']=2048
                elif fault=='compat':configuration['endpoint'].setdefault('compat',{})['supportsDeveloperRole']=True
                else:configuration['endpoint']['reasoning']={'enabled':True}
                entry['fingerprint']=indexed_contract.digest(configuration)
                self.assertNotEqual(variants.compile_variant(source,**selected)['plan_sha256'],base['plan_sha256'])

    def test_explicit_runtime_resources_budgets_suffix_are_applied_before_shared_validation(self):
        source,kwargs=inputs();base=variants.compile_variant(source,**kwargs)
        policy=resources.validate_policy(source['runtime']['resources']);policy['runtime']['memory']='8192m'
        limits=copy.deepcopy(source['stages'][0]['limits']);limits['max_tool_calls']+=1
        changed=variants.compile_variant(source,**kwargs,runtime={'image_id':'sha256:'+'f'*64},resources=policy,
            budgets=limits,prompt_suffix='Explicit variant guidance.')
        self.assertNotEqual(changed['plan_sha256'],base['plan_sha256'])
        self.assertEqual(changed['runtime']['resources'],policy)
        for stage,original in zip(changed['stages'],base['stages']):
            self.assertEqual(stage['limits'],limits);self.assertIn('Explicit variant guidance.',stage['effective_prompt'])
            self.assertEqual(stage['tools'],original['tools']);self.assertEqual(stage['profile_binding'],original['profile_binding'])
        with self.assertRaises(ValueError):variants.compile_variant(source,**kwargs,resources={'runtime':{'memory':'8g'}})
        policy['schema']=True
        with self.assertRaises(variants.VariantError):variants.compile_variant(source,**kwargs,resources=policy)

    def test_partial_or_invalid_post_transform_reporting_reserves_reject(self):
        source,kwargs=inputs()
        for fault in ('partial','calls','seconds'):
            with self.subTest(fault=fault):
                limits=copy.deepcopy(source['stages'][0]['limits'])
                if fault=='partial':limits.pop('max_turns')
                elif fault=='calls':limits['reporting_reserve_calls']=limits['max_tool_calls']
                else:limits['reporting_reserve_seconds']=limits['timeout_seconds']
                with self.assertRaises(ValueError):variants.compile_variant(source,**kwargs,budgets=limits)

    def test_every_heterogeneous_endpoint_rechecks_context_after_full_prompt_overhead(self):
        source,kwargs=inputs('indexed');base=variants.compile_variant(source,**kwargs)
        for stage in base['stages']:
            with self.subTest(stage=stage['id']):
                selected=copy.deepcopy(kwargs);entry=selected['bindings'][stage['id']]['entry']
                # Context is itself rendered metadata; leave room for its
                # shorter decimal spelling while still undersizing the full
                # actual prompt/schema/reply/history representation.
                entry['configuration']['endpoint']['context_window']=stage['prompt_admission']['total_upper_bound']-32
                entry['fingerprint']=indexed_contract.digest(entry['configuration'])
                with self.assertRaises(c.ContractError):variants.compile_variant(source,**selected)

    def test_suffix_context_and_global_prompt_overflows_are_checked_after_transform(self):
        source,kwargs=inputs();base=variants.compile_variant(source,**kwargs)
        for stage in base['stages']:
            kwargs['bindings'][stage['id']]['endpoint']['context_window']=stage['prompt_admission']['total_upper_bound']+8
        with self.assertRaises(c.ContractError):variants.compile_variant(source,**kwargs,prompt_suffix='x'*256)
        source,kwargs=inputs();source['stages'][0]['prompt']='x'*120000
        with self.assertRaises(c.ContractError):variants.compile_variant(source,**kwargs,prompt_suffix='x'*15000)

    def test_profile_assets_release_and_schema_factors_are_frozen(self):
        source,kwargs=inputs();base=variants.compile_variant(source,**kwargs)
        bad=copy.deepcopy(kwargs);bad['profile_bindings']['participant']['sha256']='e'*64
        with self.assertRaises(ValueError):variants.compile_variant(source,**bad)
        bad=copy.deepcopy(kwargs);bad['input_assets']['profiles/participant/application-client.mjs']+=b'// changed'
        with self.assertRaises(ValueError):variants.compile_variant(source,**bad)
        other='1.2.0' if source['runtime']['pi_release']=='0.87.1' else '0.87.1'
        with self.assertRaises(ValueError):variants.compile_variant(source,**kwargs,runtime={'pi_release':other})
        source['application']['operations'][0]['response_schema']['properties']['role']['maxLength']=127
        self.assertNotEqual(variants.compile_variant(source,**kwargs)['plan_sha256'],base['plan_sha256'])

    def test_dependencies_and_runtime_browser_constraints_cannot_be_repaired_or_bypassed(self):
        source,kwargs=inputs();source['stages'][1]['depends_on']=['missing']
        with self.assertRaises(ValueError):variants.compile_variant(source,**kwargs,budgets=copy.deepcopy(source['stages'][0]['limits']))
        source,kwargs=inputs(source=fixtures.browser_source())
        with self.assertRaises(ValueError):variants.compile_variant(source,**kwargs,runtime={'container_profile':'core','browser_sandbox_policy':None})

    def test_no_filesystem_catalog_key_lookup_process_or_network_during_compile(self):
        source,kwargs=inputs('indexed')
        with mock.patch('builtins.open',side_effect=AssertionError('No file')),\
             mock.patch('os.open',side_effect=AssertionError('No file descriptor')),\
             mock.patch('socket.socket',side_effect=AssertionError('No network')),\
             mock.patch('subprocess.Popen',side_effect=AssertionError('No child')),\
             mock.patch.object(inference_catalog,'Catalog',side_effect=AssertionError('No mutable catalog')),\
             mock.patch.object(agent_profiles,'application',side_effect=AssertionError('Explicit profile only')),\
             mock.patch.object(secret_store,'read_secret',side_effect=AssertionError('No credential')):
            self.assertEqual(variants.compile_variant(source,**kwargs)['runtime']['inference_owner'],'experiment_variant')
        source,kwargs=inputs();kwargs['bindings']['participant']['endpoint']['model']='${MUTABLE_MODEL}'
        with mock.patch.dict('os.environ',{'MUTABLE_MODEL':'different-model'}),self.assertRaises(variants.VariantError):
            variants.compile_variant(source,**kwargs)


if __name__=='__main__':unittest.main()
