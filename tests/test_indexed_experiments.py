"""Indexed serial input identity fixtures; no model or Docker invocation."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'skill/scripts'))
import experiments
import indexed_experiments
import inference_catalog
import pi_lab as lab
from test_experiments import ExperimentFixture
from test_indexed_contract import config
from test_parallel_contract import selected


class IndexedSetup(ExperimentFixture):
    def setUp(self):
        super().setUp();self.catalog=inference_catalog.Catalog(lab.normalize_endpoint,self.root/'catalog',self.root/'store')
        for name in ('alpha','beta'):
            value=config();value['credential']={'source':'none'};value['endpoint']['model']=name+'-fixture'
            self.catalog.register(name,value);self.catalog.confirm(name,'fixture')
        self.definition['budgets']['timeout_seconds']=600
        self.definition['schema']=3;self.definition['mode']='serial'
        legacy=selected();legacy['gateway']['queue_wait_seconds']=180;self.definition['indexed_execution']={'contract':'indexed-inference-v1','host_generation':2,'max_workers':1,'aggregate':legacy['aggregate'],'gateway':legacy['gateway']}
        for variant,name in zip(self.definition['variants'],('alpha','beta')):
            variant['inference_env']=name
        self.write('experiment.json',self.definition)


class IndexedFixture(IndexedSetup):
    def test_frozen_fixture_profile_reaches_serial_parallel_admission_on_both_releases(self):
        import contextlib,json,shutil,types
        from unittest.mock import patch
        import indexed_parallel,release_contracts
        class ProbeBoundary(Exception):pass
        @contextlib.contextmanager
        def lease(*args,**kwargs):yield types.SimpleNamespace(binding={},generation='synthetic-generation',load=lambda:[])
        for release in ('0.87.1','1.2.0'):
            for mode in ('serial','parallel'):
                for resume in (False,True):
                    with self.subTest(release=release,mode=mode,resume=resume):
                        fixture=IndexedSetup();fixture.setUp()
                        try:
                            directory=fixture.root/'profile';shutil.copytree(lab.ROOT/'assets/profiles/fixture-lookup',directory)
                            profile=experiments.read_json(directory/'profile.json');profile['components']=[release_contracts.contract(release)['fixture_component']]
                            (directory/'profile.json').write_text(json.dumps(profile))
                            for variant in fixture.definition['variants']:variant['agent_profile']='profile/profile.json'
                            if mode=='parallel':
                                concurrency=selected();concurrency['gateway']['queue_wait_seconds']=180;concurrency.update(scheduler='parallel-trials-v2',host_generation=2)
                                fixture.definition.update(mode=mode,concurrency=concurrency);fixture.definition['indexed_execution']['max_workers']=2
                            fixture.write('experiment.json',fixture.definition);root=fixture.root/'prepared'
                            indexed_experiments.prepare(fixture.root/'experiment.json',root,lab,'fixture',fixture.catalog)
                            metadata,matrix=experiments.verify(root,lab);cell=matrix['cells'][0]
                            plan=indexed_experiments.frozen_plan(root,cell,lab)
                            self.assertIn('fixture_lookup',plan['agents'][0]['tools']);self.assertIn('fixture_lookup',plan['agents'][0]['require_tools'])
                            if resume:experiments.reserve_attempt(root,metadata,cell)
                            with patch.object(experiments.resources,'admission_lock',lease),patch.object(lab,'require_host',return_value={}),patch.object(lab,'command',side_effect=AssertionError('No native commands')) as commands,patch.object(indexed_parallel.indexed_execution,'capacity',return_value=(metadata['indexed_execution'],{'cpu_millis':1000,'memory_mib':128,'pids_limit':64})),patch.object(lab,'probe_image',side_effect=ProbeBoundary()) as probes:
                                with self.assertRaises(ProbeBoundary):experiments.execute(root,lab,'fixture',resume=resume)
                                self.assertEqual(probes.call_count,1);self.assertEqual(commands.call_count,0)
                            if resume:
                                intent=experiments.attempt_intents(root,cell)[0];self.assertTrue((root/'runs'/intent['run_id']/'result.json').is_file())
                            # A normalized fixture plan cannot be admitted with a
                            # builtin profile, even outside the integrity gate.
                            plain=fixture.write('builtin.json',__import__('agent_profiles').builtin())
                            with self.assertRaises(lab.LabError):indexed_experiments.frozen_plan(root,{**cell,'agent_profile':str(plain)},lab)
                            frozen_profile=root/cell['agent_profile'];frozen_profile.chmod(0o600);frozen_profile.write_text(json.dumps(__import__('agent_profiles').builtin()))
                            with patch.object(lab,'probe_image',side_effect=AssertionError('No probe')),patch.object(lab,'command',side_effect=AssertionError('No command')):
                                with self.assertRaises(ValueError):experiments.execute(root,lab,'fixture',resume=resume)
                        finally:fixture.doCleanups()
    def test_serial_variants_freeze_exact_bindings_and_old_schema_does_not_change(self):
        prepared=experiments.prepare(self.root/'experiment.json',self.root/'indexed',lab,session='fixture',catalog=self.catalog)
        metadata,matrix=experiments.verify(self.root/'indexed',lab)
        self.assertEqual(metadata['schema'],3);self.assertEqual(prepared['schema'],3)
        for cell in matrix['cells']:
            args=experiments.trial_args(self.root/'indexed',metadata,cell,lab,'fixture')
            binding=next(iter(args._indexed_bindings.values()));self.assertEqual(binding['id'],cell['variant'] if cell['variant'] in ('alpha','beta') else ('alpha' if cell['variant']=='baseline' else 'beta'))
            self.assertIsNone(args.endpoint)
        self.catalog.revoke('alpha',1)
        experiments.verify(self.root/'indexed',lab) # stored evidence is unchanged
        with self.assertRaises(ValueError):self.catalog.admit(next(iter(lab.controls.read(self.root/'indexed'/matrix['cells'][0]['inference_bindings']).values())),'fixture')
    def test_binding_tamper_rejects_without_rewriting_evidence(self):
        experiments.prepare(self.root/'experiment.json',self.root/'indexed',lab,session='fixture',catalog=self.catalog)
        metadata,matrix=experiments.verify(self.root/'indexed',lab);path=self.root/'indexed'/matrix['cells'][0]['inference_bindings']
        path.chmod(0o600);value=experiments.read_json(path);next(iter(value.values()))['configuration']['endpoint']['model']='wrong-fixture';lab.save(path,value)
        with self.assertRaises(ValueError):experiments.verify(self.root/'indexed',lab)
    def test_parallel_requires_matching_worker_and_scheduler_contract(self):
        self.definition['mode']='parallel';self.write('experiment.json',self.definition)
        with self.assertRaises(ValueError):indexed_experiments.validate(self.root/'experiment.json',lab,self.catalog)
    def test_parallel_v2_prepares_without_weakening_predecessor_schema(self):
        concurrency=selected();concurrency['gateway']['queue_wait_seconds']=180;concurrency.update(scheduler='parallel-trials-v2',host_generation=2)
        self.definition.update(mode='parallel',concurrency=concurrency)
        self.definition['indexed_execution']['max_workers']=2
        self.write('experiment.json',self.definition)
        experiments.prepare(self.root/'experiment.json',self.root/'indexed',lab,session='fixture',catalog=self.catalog)
        metadata,matrix=experiments.verify(self.root/'indexed',lab)
        self.assertEqual(metadata['concurrency']['scheduler'],'parallel-trials-v2')
        self.assertEqual(experiments.controller_state(self.root/'indexed')['active_attempts'],{})
        self.assertEqual(len(matrix['cells']),4)

    def test_invalid_variant_cannot_write_an_absolute_destination(self):
        sentinel=self.root/'sentinel.json';sentinel.write_text('keep')
        self.definition['variants'][0]['name']=str(sentinel)
        self.write('experiment.json',self.definition)
        with self.assertRaises(ValueError):indexed_experiments.validate(self.root/'experiment.json',lab,self.catalog)
        self.assertEqual(sentinel.read_text(),'keep')
    def test_catalog_or_store_inside_original_project_never_snapshots(self):
        for field in ('root','store'):
            with self.subTest(field=field):
                original=getattr(self.catalog,field);setattr(self.catalog,field,self.root/'project'/'private')
                with self.assertRaises(ValueError):experiments.prepare(self.root/'experiment.json',self.root/'indexed',lab,session='fixture',catalog=self.catalog)
                self.assertFalse((self.root/'indexed').exists());setattr(self.catalog,field,original)
    def test_route_deadlines_must_fit_effective_case_budgets(self):
        self.definition['budgets']['timeout_seconds']=4
        self.write('experiment.json',self.definition)
        with self.assertRaises(ValueError):experiments.prepare(self.root/'experiment.json',self.root/'indexed',lab,session='fixture',catalog=self.catalog)
        self.assertFalse((self.root/'indexed').exists())
    def test_stage_maps_are_exhaustive_and_external_plans_freeze(self):
        self.plan['schema']=2;self.plan['inference_bindings']='external'
        self.write('plan.json',self.plan)
        for variant in self.definition['variants']:
            variant.pop('inference_env');variant['inference_bindings']={'case':{'dev':'alpha'}}
        self.definition['variants'][1]['inference_bindings']['case']['dev']='beta'
        self.write('experiment.json',self.definition)
        experiments.prepare(self.root/'experiment.json',self.root/'indexed',lab,session='fixture',catalog=self.catalog)
        metadata,matrix=experiments.verify(self.root/'indexed',lab)
        for cell in matrix['cells']:
            plan=experiments.read_json(self.root/'indexed'/cell['plan'])
            self.assertEqual(plan['schema'],2);self.assertEqual(plan['inference_bindings'],'external')
        self.plan['inference_bindings']={'dev':'alpha'};self.write('plan.json',self.plan)
        with self.assertRaises(ValueError):indexed_experiments.validate(self.root/'experiment.json',lab,self.catalog)

    def test_preparation_rejects_literal_keys_before_copying_any_source(self):
        import secret_store
        value=config();value['credential']={'source':'store','name':'SYNTHETIC_SELECTED'}
        secret_store.write_secret('SYNTHETIC_SELECTED','synthetic-profile-secret',self.catalog.store)
        self.catalog.register('alpha',value,1);self.catalog.confirm('alpha','fixture')
        (self.root/'project/leak.txt').write_text('synthetic-profile-secret')
        with self.assertRaises(ValueError):experiments.prepare(self.root/'experiment.json',self.root/'indexed',lab,session='fixture',catalog=self.catalog)
        self.assertFalse((self.root/'indexed').exists())
    def test_selected_key_in_another_profiles_model_rejects_before_freezing(self):
        import secret_store
        value=config();value['credential']={'source':'store','name':'SYNTHETIC_SECOND'}
        secret_store.write_secret('SYNTHETIC_SECOND','synthetic-cross-profile-authority',self.catalog.store)
        self.catalog.register('beta',value,1);self.catalog.confirm('beta','fixture')
        first=config();first['credential']={'source':'none'};first['endpoint']['model']='synthetic-cross-profile-authority'
        self.catalog.register('alpha',first,1);self.catalog.confirm('alpha','fixture')
        with self.assertRaises(ValueError):experiments.prepare(self.root/'experiment.json',self.root/'indexed',lab,session='fixture',catalog=self.catalog)
        self.assertFalse((self.root/'indexed').exists())

    def test_each_cases_first_stage_has_its_own_endpoint_and_configuration(self):
        self.definition['cases'].append({**self.definition['cases'][0],'name':'other'})
        for variant,ids in zip(self.definition['variants'],(('alpha','beta'),('beta','alpha'))):
            variant.pop('inference_env');variant['inference_bindings']={name:{'dev':identifier} for name,identifier in zip(('case','other'),ids)}
        self.write('experiment.json',self.definition)
        experiments.prepare(self.root/'experiment.json',self.root/'indexed',lab,session='fixture',catalog=self.catalog)
        metadata,matrix=experiments.verify(self.root/'indexed',lab)
        import comparisons
        expected=comparisons.expected_contracts(self.root/'indexed',metadata,matrix['cells'],lab)
        for cell in matrix['cells']:
            binding=experiments.read_json(self.root/'indexed'/cell['inference_bindings'])['dev']
            endpoint=experiments.read_json(self.root/'indexed'/cell['endpoint'])
            self.assertEqual(endpoint,binding['configuration']['endpoint'])
            self.assertEqual(expected[cell['trial_id']]['endpoint_sha256'],__import__('provenance').digest({k:v for k,v in endpoint.items() if k!='api_key_env'}))


if __name__=='__main__':unittest.main()
