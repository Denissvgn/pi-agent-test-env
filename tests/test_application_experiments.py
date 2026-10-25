"""Offline application experiment artifacts and disposable-key admission only."""
import copy
import hashlib
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_contracts as c
import application_experiments as app
import application_preparation as preparation
import inference_catalog
import indexed_contract
import pi_lab as lab
import provenance
import resources
import secret_store
import test_application_preparation as base_fixture
import test_indexed_contract as indexed_fixture
import test_parallel_contract as parallel_fixture

APP_KEY='disposable-app-experiment-key-496383'
MODEL_KEY='disposable-model-experiment-key-02983'


class ApplicationExperimentTests(unittest.TestCase):
    def setUp(self):
        self.fixture=base_fixture.PreparationTests(methodName='runTest');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.root=self.fixture.root;self.inputs=self.fixture.inputs;self.source=self.fixture.source
        self.source['runtime']['inference_owner']='experiment_variant';self.fixture.write('source.json',self.source)
        self.project=self.root/'project';self.project.mkdir();(self.project/'README.md').write_text('source fixture\n')
        self.store=self.root/'store';secret_store.write_secret('DIAGNOSTIC_ALICE',APP_KEY,self.store)
        secret_store.write_secret('MODEL_REFERENCE',MODEL_KEY,self.store)
        patch=mock.patch.dict(os.environ,{'PI_LAB_SECRETS_DIR':str(self.store),'MODEL_REFERENCE':''});patch.start();self.addCleanup(patch.stop)
        self.policy=copy.deepcopy(resources.DEFAULTS);self.policy['runtime'].update(cpus=1,memory='1g',pids_limit=64,jobs=1)
        self.fixture.write('resources.json',self.policy)
        self.definition={'schema':1,'document_type':app.SOURCE_TYPE,'name':'authenticated-experiment','baseline':'baseline','repetitions':1,
            'cases':[{'name':'account','project':str(self.project),'plan':'source.json','runtime_receipt':'runtime.json'}],
            'variants':[{'name':'baseline','endpoint':'endpoint.json'},{'name':'candidate','endpoint':'endpoint.json','prompt_suffix':'EXPLICIT_CANDIDATE_SUFFIX'}],
            'budgets':copy.deepcopy(self.source['stages'][0]['limits']),
            'execution':{'image':self.source['runtime']['image_id'],'platform':'linux/arm64','resources':'resources.json'},
            'policies':{'primary_attempt':'first','assistance':'exclude','on_failure':'continue','max_attempts':2}}
        self.path=self.fixture.write('experiment.json',self.definition)

    def write(self,value=None):return self.fixture.write('experiment.json',self.definition if value is None else value)
    def validate(self,value=None):return app.validate(self.write(value),lab)
    def prepare(self,name='prepared',**kwargs):return app.prepare(self.write(),self.root/name,lab,**kwargs)
    def inventory(self,path):return {str(p.relative_to(path)):p.read_bytes() for p in path.rglob('*') if p.is_file()}
    def json(self,path):return c.loads(Path(path).read_bytes())
    def put(self,path,value):
        path=Path(path);path.chmod(0o600);path.write_bytes(c.canonical(value));path.chmod(0o444)
    def rehash(self,root,updates):
        for name,value in updates.items():self.put(root/name,value)
        integrity=self.json(root/'integrity.json')
        for name in updates:integrity['files'][name]='0444:'+hashlib.sha256((root/name).read_bytes()).hexdigest()
        integrity['fingerprint']=provenance.digest(integrity['files']);self.put(root/'integrity.json',integrity)

    def offline(self):
        stack=__import__('contextlib').ExitStack()
        for target in [(socket,'socket'),(subprocess,'Popen'),(subprocess,'run')]:
            stack.enter_context(mock.patch.object(*target,side_effect=AssertionError('Offline fixture must have zero external effects')))
        return stack

    def test_legacy_prepare_freezes_exact_final_ir_and_all_transforms_offline(self):
        before=self.inventory(self.inputs);project=self.inventory(self.project)
        with self.offline(),mock.patch.object(lab,'endpoint_secret',side_effect=AssertionError('Legacy prepare does not read original keys')):
            result=self.prepare();metadata,matrix=app.verify(self.root/'prepared',lab)
        self.assertEqual(result['planned'],2);self.assertEqual(self.inventory(self.inputs),before);self.assertEqual(self.inventory(self.project),project)
        self.assertEqual(metadata['document_type'],app.EXPERIMENT_TYPE);self.assertEqual(metadata['execution']['profile'],'core')
        self.assertEqual(metadata['source_admission'],'legacy_offline_unverified_until_admit_work')
        self.assertEqual(self.json(self.root/'prepared/state.json'),{'schema':1,'status':'prepared','active_attempt_id':None})
        plans=[]
        for cell in matrix['cells']:
            compiled=preparation.load_compiled(self.root/'prepared'/cell['compiled_plan'],verify_runner=True);plan=compiled['plan'];plans.append(plan)
            self.assertEqual(cell['plan'],cell['compiled_plan']);self.assertEqual(cell['plan_sha256'],plan['plan_sha256'])
            self.assertEqual(plan['runtime']['resources'],resources.validate_policy(self.policy))
            self.assertEqual(plan['runtime']['inference_owner'],'experiment_variant')
            for stage in plan['stages']:
                self.assertEqual(stage['limits'],self.definition['budgets']);self.assertEqual(stage['profile_binding']['id'],'application-client')
                self.assertEqual(stage['inference_binding']['selection']['owner'],'experiment_variant')
                self.assertEqual(stage['effective_prompt'].count('EXPLICIT_CANDIDATE_SUFFIX'),int(cell['variant']=='candidate'))
        self.assertNotEqual(plans[0]['plan_sha256'],plans[1]['plan_sha256'])
        raw=b'\n'.join(self.inventory(self.root/'prepared').values())
        for key in (APP_KEY,MODEL_KEY):self.assertNotIn(key.encode(),raw);self.assertNotIn(hashlib.sha256(key.encode()).hexdigest().encode(),raw)

    def test_empty_project_is_materialized_without_markers_and_remains_verifiable(self):
        (self.project/'README.md').unlink();self.prepare();root=self.root/'prepared'
        metadata,matrix=app.verify(root,lab);source=root/matrix['cells'][0]['source']
        self.assertTrue(source.is_dir());self.assertEqual(list(source.iterdir()),[])
        self.assertEqual(metadata['source_receipts']['account']['snapshot_sha256'],provenance.digest({}))
        self.assertEqual(metadata['source_receipts']['account']['source_sha256'],provenance.digest({}))
        self.assertFalse(any(name.startswith('inputs/sources/account/') for name in self.json(root/'integrity.json')['files']))

    def test_frozen_verification_needs_no_original_definition_project_endpoint_or_scorer(self):
        self.prepare();root=self.root/'prepared';before=app.verify(root,lab)
        shutil.rmtree(self.inputs);shutil.rmtree(self.project)
        with self.offline(),mock.patch.object(inference_catalog.Catalog,'select',side_effect=AssertionError('No original catalog')):
            self.assertEqual(app.verify(root,lab),before)
            for cell in before[1]['cells']:preparation.load_compiled(root/cell['compiled_plan'])

    def test_trial_args_only_select_final_plan_project_and_results(self):
        self.prepare();root=self.root/'prepared';metadata,matrix=app.verify(root,lab)
        args=app.trial_args(root,metadata,matrix['cells'][0],lab,'fixture-session')
        self.assertEqual(args.compiled_plan,str(root/matrix['cells'][0]['compiled_plan']))
        self.assertEqual(args.project,str(root/matrix['cells'][0]['source']));self.assertEqual(args.session,'fixture-session')
        self.assertEqual(args._application_variant_context,{'experiment_root':str(root),'experiment_id':metadata['experiment_id'],
            'trial_id':matrix['cells'][0]['trial_id'],'variant_id':'baseline','configuration_digest':matrix['cells'][0]['configuration_digest']})
        self.assertIsNone(args.endpoint);self.assertEqual(args._experiment_root,str(root))
        self.assertEqual(args.image,metadata['execution']['image']);self.assertEqual(args.platform,'linux/arm64')
        self.assertEqual(args._resource_request,resources.validate_policy(self.policy));self.assertEqual(args._explicit_options,())

    def test_strict_opt_in_owner_budget_profile_and_endpoint_selectors_reject_before_output(self):
        changes=[lambda d:d.update(document_type='experiment'),lambda d:d.update(schema=True),
            lambda d:d['budgets'].pop('max_tool_calls'),lambda d:d['cases'][0].pop('runtime_receipt'),
            lambda d:d['execution'].update(environment='hidden.json'),lambda d:d['execution'].update(platform='linux/amd64'),
            lambda d:d['execution'].update(network='host'),lambda d:d['variants'][0].update(agent_profile='builtin'),
            lambda d:d['cases'][0].update(budgets={'timeout_seconds':60}),
            lambda d:d['budgets'].update(reporting_reserve_seconds=300)]
        before=self.inventory(self.project)
        for number,change in enumerate(changes):
            bad=copy.deepcopy(self.definition);change(bad)
            with self.subTest(number=number),self.offline(),self.assertRaises(app.ApplicationExperimentError):
                app.prepare(self.write(bad),self.root/('bad-'+str(number)),lab)
            self.assertFalse((self.root/('bad-'+str(number))).exists())
        self.assertEqual(self.inventory(self.project),before)
        self.source['runtime']['inference_owner']='compiler_input';self.fixture.write('source.json',self.source)
        with self.assertRaises(app.ApplicationExperimentError):self.prepare()
        self.assertFalse((self.root/'prepared').exists())

    def test_standalone_endpoint_override_and_implicit_endpoints_are_rejected(self):
        with self.assertRaises(app.ApplicationExperimentError):app.validate(self.path,lab,endpoint_path=self.fixture.endpoint_path)
        self.definition['variants'][0].pop('endpoint')
        with self.assertRaises(app.ApplicationExperimentError):self.prepare()
        self.assertFalse((self.root/'prepared').exists())

    def test_final_context_and_explicit_resource_overflow_reject_before_publication(self):
        selected=self.validate();bound=selected['pairs'][0]['plan']['stages'][0]['prompt_admission']['total_upper_bound']
        self.fixture.endpoint['context_window']=bound-1;self.fixture.write('endpoint.json',self.fixture.endpoint)
        with self.assertRaises(app.ApplicationExperimentError):self.prepare('oversized')
        self.assertFalse((self.root/'oversized').exists())
        self.fixture.endpoint['context_window']=1000000;self.fixture.write('endpoint.json',self.fixture.endpoint)
        self.policy['runtime']['memory']='1m';self.fixture.write('resources.json',self.policy)
        with self.assertRaises(app.ApplicationExperimentError):self.prepare('resources')
        self.assertFalse((self.root/'resources').exists())

    def test_frozen_ir_tamper_source_link_and_unowned_input_directory_reject(self):
        self.prepare();root=self.root/'prepared';metadata,matrix=app.verify(root,lab);cell=matrix['cells'][0]
        (root/'inputs/unowned-empty-directory').mkdir()
        with self.assertRaises(app.ApplicationExperimentError):app.verify(root,lab)
        (root/'inputs/unowned-empty-directory').rmdir()
        plan=root/cell['compiled_plan'];original=plan.read_bytes();plan.chmod(0o600);plan.write_bytes(original+b' ');plan.chmod(0o444)
        with self.assertRaises(app.ApplicationExperimentError):app.verify(root,lab)
        plan.chmod(0o600);plan.write_bytes(original);plan.chmod(0o444)
        source=root/cell['source']/'README.md';source.unlink();source.symlink_to(self.project/'README.md')
        with self.assertRaises(app.ApplicationExperimentError):app.verify(root,lab)

    def test_rehashed_matrix_path_and_contradictory_execution_reject(self):
        self.prepare();root=self.root/'prepared';metadata,matrix=app.verify(root,lab)
        matrix['cells'][0]['compiled_plan']='../foreign/plan.json';self.rehash(root,{'matrix.json':matrix})
        with self.assertRaises(app.ApplicationExperimentError):app.verify(root,lab)
        self.prepare('second');root=self.root/'second';metadata,matrix=app.verify(root,lab)
        metadata['execution']['image']='sha256:'+'e'*64;self.rehash(root,{'experiment.json':metadata})
        with self.assertRaises(app.ApplicationExperimentError):app.verify(root,lab)

    def test_output_is_fresh_and_failure_preserves_previous_artifacts_and_source(self):
        self.prepare();root=self.root/'prepared';before=self.inventory(root);source=self.inventory(self.project)
        with self.assertRaises(app.ApplicationExperimentError):self.prepare()
        self.assertEqual(self.inventory(root),before);self.assertEqual(self.inventory(self.project),source)
        with mock.patch.object(app,'verify',side_effect=app.ApplicationExperimentError()):
            with self.assertRaises(app.ApplicationExperimentError):self.prepare('unpublished')
        self.assertFalse((self.root/'unpublished').exists())

    def test_legacy_admission_uses_each_original_explicit_reference_and_private_exhaustive_maps(self):
        second={**self.fixture.endpoint,'api_key_env':'SECOND_MODEL_REFERENCE','model':'declared-other-model'}
        self.fixture.write('second.json',second);self.definition['variants'][1]['endpoint']='second.json'
        secret_store.write_secret('SECOND_MODEL_REFERENCE','disposable-second-model-key-4957',self.store)
        self.prepare();root=self.root/'prepared';metadata,matrix=app.verify(root,lab)
        real=lab.endpoint_secret
        with self.offline(),mock.patch.object(lab,'endpoint_secret',wraps=real) as resolve:
            result=app.admit_work(root,metadata,matrix['cells'],lab,'fixture-session')
        self.assertEqual(len(resolve.call_args_list),2)
        self.assertEqual({call.args[0]['api_key_env'] for call in resolve.call_args_list},{'MODEL_REFERENCE','SECOND_MODEL_REFERENCE'})
        self.assertEqual(set(result),{'authorities_by_trial','keys','redaction_values'})
        self.assertEqual(set(result['authorities_by_trial']),{cell['trial_id'] for cell in matrix['cells']})
        self.assertIn(APP_KEY,result['redaction_values']);self.assertNotIn(APP_KEY,result['keys'])
        for spec in result['authorities_by_trial'].values():
            hashes={stage['inference_binding']['configuration_sha256'] for stage in spec['plan']['stages']}
            self.assertEqual(set(spec['inference_authorities']),hashes);self.assertEqual(spec['inference_key'],spec['inference_authorities'][next(iter(hashes))]['value'])
        with self.assertRaises(app.ApplicationExperimentError):app.admit_work(root,metadata,[matrix['cells'][0]]*2,lab,'fixture-session')
        self.assertEqual(app.admit_work(root,metadata,[],lab,'fixture-session'),{'authorities_by_trial':{},'keys':[],'redaction_values':[]})

    def test_missing_colliding_and_literal_application_keys_reject_before_host_or_probe(self):
        self.prepare();root=self.root/'prepared';metadata,matrix=app.verify(root,lab)
        for fault in ('missing','inference-collision','literal-project'):
            path=self.store/'DIAGNOSTIC_ALICE'
            if fault=='missing':path.unlink()
            elif fault=='inference-collision':secret_store.write_secret('DIAGNOSTIC_ALICE',MODEL_KEY,self.store)
            else:
                secret_store.write_secret('DIAGNOSTIC_ALICE',APP_KEY,self.store)
                source=root/matrix['cells'][0]['source']/'README.md';source.chmod(0o600);source.write_text(APP_KEY);source.chmod(0o444)
            with self.subTest(fault=fault),self.offline(),self.assertRaises(app.ApplicationExperimentError):
                app.admit_work(root,metadata,matrix['cells'],lab,'fixture-session')
            if fault=='missing':secret_store.write_secret('DIAGNOSTIC_ALICE',APP_KEY,self.store)

    def indexed(self,parallel=False):
        catalog=inference_catalog.Catalog(lab.normalize_endpoint,self.root/'catalog',self.store)
        for name in ('alpha','beta'):
            raw=indexed_fixture.config();raw['endpoint'].update(context_window=1000000,max_tokens=4096,model=name+'-explicit-model')
            raw['credential']={'source':'none'};raw['request_limits']={'queue_wait_seconds':30,'request_timeout_seconds':60}
            
            try:catalog.select(name)
            except indexed_contract.IndexedError:catalog.register(name,raw)
            catalog.confirm(name,'fixture-session')
        self.definition['schema']=3;self.definition['mode']='parallel' if parallel else 'serial'
        self.definition['variants']=[{'name':'baseline','inference_env':'alpha'},
            {'name':'candidate','inference_bindings':{'account':{'participant':'beta'}},'prompt_suffix':'INDEXED_SUFFIX'}]
        self.definition['budgets']['timeout_seconds']=600
        concurrency=parallel_fixture.selected();concurrency['aggregate']={'cpu_millis':5000,'memory_mib':4096,'pids_limit':1024}
        concurrency['native_budget']=indexed_contract.native_helper_contract(app.API_RESOURCES)
        self.definition['indexed_execution']={'contract':indexed_contract.EXECUTION,'host_generation':indexed_contract.HOST_GENERATION,
            'max_workers':2 if parallel else 1,'aggregate':copy.deepcopy(concurrency['aggregate']),
            'gateway':copy.deepcopy(concurrency['gateway']),'native_budget':copy.deepcopy(concurrency['native_budget'])}
        if parallel:
            concurrency.update(scheduler=indexed_contract.SCHEDULER,host_generation=2);self.definition['concurrency']=concurrency
        return catalog

    def test_indexed_prepare_confirms_and_scans_before_copy_then_frozen_load_ignores_catalog(self):
        catalog=self.indexed();snapshot=lab.snapshot
        def checked_snapshot(*args,**kwargs):
            self.assertTrue(catalog.freeze('alpha','fixture-session')['authority_id']);return snapshot(*args,**kwargs)
        with self.offline(),mock.patch.object(lab,'snapshot',side_effect=checked_snapshot):
            self.prepare(catalog=catalog,session='fixture-session')
        root=self.root/'prepared';metadata,matrix=app.verify(root,lab)
        self.assertEqual(metadata['source_admission'],'indexed_confirmed_and_scanned')
        for cell in matrix['cells']:
            bindings=self.json(root/cell['inference_bindings']);self.assertEqual(set(bindings),{'participant'})
            self.assertIn('authority_id',bindings['participant'])
        shutil.rmtree(self.inputs);shutil.rmtree(self.project);shutil.rmtree(catalog.root)
        with self.offline(),mock.patch.object(inference_catalog.Catalog,'select',side_effect=AssertionError('No catalog reload')):
            self.assertEqual(app.verify(root,lab),(metadata,matrix))

    def test_indexed_missing_confirmation_or_original_canary_reject_before_snapshot(self):
        catalog=self.indexed();(self.project/'README.md').write_text(APP_KEY)
        with mock.patch.object(lab,'snapshot',side_effect=AssertionError('Admission must precede source copy')),self.offline():
            with self.assertRaises(app.ApplicationExperimentError):self.prepare(catalog=catalog,session='fixture-session')
        self.assertFalse((self.root/'prepared').exists());self.assertEqual((self.project/'README.md').read_text(),APP_KEY)
        (self.project/'README.md').write_text('clean source')
        with mock.patch.object(lab,'snapshot',side_effect=AssertionError('Confirmation must precede source copy')),self.offline():
            with self.assertRaises(app.ApplicationExperimentError):self.prepare(catalog=catalog,session='unconfirmed-session')
        self.assertFalse((self.root/'prepared').exists())

    def test_indexed_exhaustive_maps_and_explicit_helper_capacity_are_required(self):
        catalog=self.indexed();self.definition['variants'][1]['inference_bindings']['account']={}
        with self.assertRaises(app.ApplicationExperimentError):self.prepare(catalog=catalog,session='fixture-session')
        self.assertFalse((self.root/'prepared').exists())
        self.indexed();self.definition['indexed_execution'].pop('native_budget')
        with self.assertRaises(app.ApplicationExperimentError):self.prepare(catalog=catalog,session='fixture-session')
        self.assertFalse((self.root/'prepared').exists())

    def test_parallel_legacy_same_upstream_and_exact_uniform_helper_are_explicit(self):
        self.definition['schema']=2;self.definition['budgets']['timeout_seconds']=600
        selected=parallel_fixture.selected();selected['aggregate']={'cpu_millis':5000,'memory_mib':4096,'pids_limit':1024}
        selected['native_budget']=indexed_contract.native_helper_contract(app.API_RESOURCES);self.definition['concurrency']=selected
        self.prepare();metadata,matrix=app.verify(self.root/'prepared',lab)
        self.assertEqual(self.json(self.root/'prepared/state.json'),{'schema':2,'status':'prepared','active_attempts':{}})
        self.assertEqual([cell['variant'] for cell in matrix['cells']],['baseline','candidate'])
        second={**self.fixture.endpoint,'model':'different-route'};self.fixture.write('second.json',second);self.definition['variants'][1]['endpoint']='second.json'
        with self.assertRaises(app.ApplicationExperimentError):self.prepare('heterogeneous')
        self.assertFalse((self.root/'heterogeneous').exists())
        self.definition['variants'][1]['endpoint']='endpoint.json';selected['aggregate']['cpu_millis']=3000
        with self.assertRaises(app.ApplicationExperimentError):self.prepare('insufficient')
        self.assertFalse((self.root/'insufficient').exists())

    def test_indexed_parallel_keeps_exact_frozen_contracts_and_heterogeneous_routes(self):
        catalog=self.indexed(parallel=True);self.prepare(catalog=catalog,session='fixture-session');root=self.root/'prepared'
        metadata,matrix=app.verify(root,lab)
        self.assertEqual(metadata['mode'],'parallel');self.assertEqual(self.json(root/'inputs/concurrency.json'),metadata['concurrency'])
        self.assertNotEqual(self.json(root/matrix['cells'][0]['endpoint'])['model'],self.json(root/matrix['cells'][1]['endpoint'])['model'])
        args=app.trial_args(root,metadata,matrix['cells'][0],lab,'fixture-session')
        self.assertEqual(args._indexed_bindings,self.json(root/matrix['cells'][0]['inference_bindings']))
        self.assertEqual(args._indexed_contract,metadata['indexed_execution'])

    def test_indexed_multistage_heterogeneous_authority_is_exhaustive_and_rechecks_current_approval(self):
        second=copy.deepcopy(self.source['stages'][0]);second['id']='reviewer';second['depends_on']=['participant']
        second['completion']['id']='reviewer-report';second['completion']['report_path']='reviewer/completion.json'
        second['completion']['artifacts'][0]['path']='reviewer/summary.md';self.source['stages'].append(second)
        self.fixture.write('source.json',self.source);catalog=self.indexed()
        self.definition['variants'][1]['inference_bindings']['account']={'participant':'alpha','reviewer':'beta'}
        self.prepare(catalog=catalog,session='fixture-session');root=self.root/'prepared';metadata,matrix=app.verify(root,lab)
        with self.offline():admission=app.admit_work(root,metadata,matrix['cells'],lab,'fixture-session')
        candidate=next(cell for cell in matrix['cells'] if cell['variant']=='candidate');spec=admission['authorities_by_trial'][candidate['trial_id']]
        self.assertEqual(len(spec['inference_authorities']),2);self.assertEqual(spec['endpoint']['model'],'alpha-explicit-model')
        self.assertEqual({value['reference'] for value in spec['inference_authorities'].values()},{None})
        entry=catalog.select('beta');catalog.revoke('beta',entry['revision'])
        with self.offline(),self.assertRaises(app.ApplicationExperimentError):app.admit_work(root,metadata,[candidate],lab,'fixture-session')

    def test_rehashed_variant_with_stale_ir_and_contradictory_helper_contract_cannot_verify(self):
        self.prepare();root=self.root/'prepared';metadata,matrix=app.verify(root,lab);artifact=(root/matrix['cells'][0]['compiled_plan']).parent
        record=self.json(artifact/'variant.json');record['bindings']['participant']['endpoint']['model']='different-explicit-model'
        manifest=self.json(artifact/'input-manifest.json');body=c.canonical(record)
        manifest['files']['variant.json']=hashlib.sha256(body).hexdigest()
        manifest['manifest_sha256']=c.digest({key:value for key,value in manifest.items() if key!='manifest_sha256'})
        relative=str(artifact.relative_to(root));self.rehash(root,{relative+'/variant.json':record,relative+'/input-manifest.json':manifest})
        with self.assertRaises(app.ApplicationExperimentError):app.verify(root,lab)
        catalog=self.indexed();self.prepare('indexed',catalog=catalog,session='fixture-session');root=self.root/'indexed'
        contract=self.json(root/'inputs/indexed-contract.json');contract['aggregate']['memory_mib']+=1
        self.rehash(root,{'inputs/indexed-contract.json':contract})
        with self.assertRaises(app.ApplicationExperimentError):app.verify(root,lab)

    def test_unsafe_source_aliases_and_nested_destinations_reject_without_copying(self):
        (self.project/'linked').symlink_to(self.project/'README.md')
        with mock.patch.object(lab,'snapshot',side_effect=AssertionError('Source aliases reject before copying')):
            with self.assertRaises(app.ApplicationExperimentError):self.prepare()
        self.assertFalse((self.root/'prepared').exists());(self.project/'linked').unlink()
        with mock.patch.object(lab,'snapshot',side_effect=AssertionError('Nested destination rejects before copying')):
            with self.assertRaises(app.ApplicationExperimentError):app.prepare(self.write(),self.project/'nested',lab)
        self.assertFalse((self.project/'nested').exists())

    def test_key_free_root_scorer_is_checked_before_indexed_copy_and_legacy_live_admission(self):
        scorer=self.inputs/self.source['checks'][0]['scorer']['assets'][0]['source']
        scorer.write_text('fixture evaluator containing '+APP_KEY+'\n')
        self.assertNotIn(APP_KEY,(self.project/'README.md').read_text())
        self.prepare();root=self.root/'prepared';metadata,matrix=app.verify(root,lab)
        with self.offline(),self.assertRaises(app.ApplicationExperimentError):app.admit_work(root,metadata,matrix['cells'],lab,'fixture-session')
        catalog=self.indexed()
        with self.offline(),mock.patch.object(lab,'snapshot',side_effect=AssertionError('Known key in evaluator must block before source copying')):
            with self.assertRaises(app.ApplicationExperimentError):self.prepare('indexed',catalog=catalog,session='fixture-session')
        self.assertFalse((self.root/'indexed').exists())

    def test_keyless_selected_inference_does_not_add_empty_redaction_values(self):
        catalog=self.indexed();self.prepare(catalog=catalog,session='fixture-session');root=self.root/'prepared'
        metadata,matrix=app.verify(root,lab);admission=app.admit_work(root,metadata,matrix['cells'],lab,'fixture-session')
        self.assertEqual(admission['keys'],[]);self.assertEqual(admission['redaction_values'],[APP_KEY])

    def test_explicit_legacy_secret_store_is_frozen_and_used_instead_of_ambient_default(self):
        selected=self.root/'explicit-store';app_value='disposable-explicit-app-key-93857';model_value='disposable-explicit-model-key-81724'
        secret_store.write_secret('DIAGNOSTIC_ALICE',app_value,selected);secret_store.write_secret('MODEL_REFERENCE',model_value,selected)
        source_before=self.inventory(self.project);store_before=self.inventory(selected)
        with self.offline(),mock.patch.object(lab,'endpoint_secret',side_effect=AssertionError('Legacy preparation must remain key-free')):
            definition=app.validate(self.write(),lab,secrets_dir=selected)
            self.prepare(secrets_dir=selected)
        self.assertEqual(definition['credential_store'],str(selected))
        root=self.root/'prepared';metadata,matrix=app.verify(root,lab)
        self.assertEqual(metadata['credential_store'],str(selected));self.assertNotEqual(str(selected),os.environ['PI_LAB_SECRETS_DIR'])
        for cell in matrix['cells']:self.assertEqual(app.trial_args(root,metadata,cell,lab,'fixture-session').secrets_dir,str(selected))
        with self.offline():admission=app.admit_work(root,metadata,matrix['cells'],lab,'fixture-session')
        self.assertEqual(admission['keys'],[model_value]);self.assertEqual(set(admission['redaction_values']),{app_value,model_value})
        self.assertEqual({spec['store'] for spec in admission['authorities_by_trial'].values()},{str(selected)})
        self.assertNotIn(APP_KEY,admission['redaction_values']);self.assertNotIn(MODEL_KEY,admission['redaction_values'])
        self.assertEqual(self.inventory(self.project),source_before);self.assertEqual(self.inventory(selected),store_before)
        frozen=b'\n'.join(self.inventory(root).values())
        self.assertNotIn(app_value.encode(),frozen);self.assertNotIn(model_value.encode(),frozen)

    def test_explicit_secret_store_inside_source_rejects_before_snapshot_or_publication(self):
        selected=self.project/'private-store';secret_store.write_secret('DIAGNOSTIC_ALICE',APP_KEY,selected)
        before=self.inventory(self.project)
        with self.offline(),mock.patch.object(lab,'snapshot',side_effect=AssertionError('Nested secret store must reject before source copying')):
            with self.assertRaises(app.ApplicationExperimentError):app.validate(self.write(),lab,secrets_dir=selected)
            with self.assertRaises(app.ApplicationExperimentError):self.prepare(secrets_dir=selected)
        self.assertFalse((self.root/'prepared').exists());self.assertEqual(self.inventory(self.project),before)

    def test_resolved_secret_store_alias_inside_source_rejects_before_source_copy(self):
        selected=self.project/'private-store';selected.mkdir(mode=0o700);alias=self.root/'store-alias';alias.symlink_to(selected,target_is_directory=True)
        before=self.inventory(self.project)
        with self.offline(),mock.patch.object(lab,'snapshot',side_effect=AssertionError('Resolved nested store must reject before source copying')):
            with self.assertRaises(app.ApplicationExperimentError):self.prepare(secrets_dir=alias)
        self.assertFalse((self.root/'prepared').exists());self.assertEqual(self.inventory(self.project),before)

    def test_secret_store_inside_fresh_destination_rejects_before_any_output_exists(self):
        destination=self.root/'prepared';selected=destination/'private-store';before=self.inventory(self.project)
        with self.offline(),mock.patch.object(lab,'snapshot',side_effect=AssertionError('Destination-local store must reject before source copying')):
            with self.assertRaises(app.ApplicationExperimentError):self.prepare(secrets_dir=selected)
        self.assertFalse(destination.exists());self.assertEqual(self.inventory(self.project),before)

    def test_indexed_explicit_secret_store_must_match_frozen_catalog_store(self):
        catalog=self.indexed();other=self.root/'other-store';other.mkdir(mode=0o700)
        with self.offline(),mock.patch.object(lab,'snapshot',side_effect=AssertionError('Competing store must reject before copying')):
            with self.assertRaises(app.ApplicationExperimentError):self.prepare(catalog=catalog,session='fixture-session',secrets_dir=other)
        self.assertFalse((self.root/'prepared').exists())
        with self.offline():self.prepare(catalog=catalog,session='fixture-session',secrets_dir=self.store)
        metadata,matrix=app.verify(self.root/'prepared',lab)
        self.assertEqual(metadata['credential_store'],str(self.store));self.assertEqual(len(matrix['cells']),2)

    def test_coherent_schema2_variant_recompile_cannot_widen_single_upstream_contract(self):
        self.definition['schema']=2;self.definition['budgets']['timeout_seconds']=600
        selected=parallel_fixture.selected();selected['aggregate']={'cpu_millis':5000,'memory_mib':4096,'pids_limit':1024}
        selected['native_budget']=indexed_contract.native_helper_contract(app.API_RESOURCES);self.definition['concurrency']=selected
        self.prepare();root=self.root/'prepared';metadata,matrix=app.verify(root,lab)
        cell=next(cell for cell in matrix['cells'] if cell['variant']=='candidate');artifact=(root/cell['compiled_plan']).parent
        record=self.json(artifact/'variant.json')
        record['bindings']['participant']['endpoint']['model']='independently-valid-other-model'
        replacement=preparation.compile_variant_artifact(self.fixture.spec,self.root/'replacement',self.fixture.runtime_path,
            variant_id=record['variant_id'],bindings=record['bindings'],runtime=record['runtime'],resources=record['resources'],
            budgets=record['budgets'],prompt_suffix=record['prompt_suffix'])
        # Every replaced compiled byte is independently valid. Repair the public
        # consistency hashes so this checks the frozen schema2 policy itself.
        self.assertEqual(preparation.load_compiled(Path(replacement['root'])/'plan.json'),replacement)
        shutil.rmtree(artifact);shutil.copytree(replacement['root'],artifact)
        cell['plan_sha256']=replacement['plan']['plan_sha256'];cell['configuration_digest']=app._cell_digest(metadata,cell,replacement)
        self.put(root/'matrix.json',matrix);self.put(root/cell['endpoint'],record['bindings']['participant']['endpoint'])
        integrity=self.json(root/'integrity.json')
        for path in integrity['files']:integrity['files'][path]='0444:'+hashlib.sha256((root/path).read_bytes()).hexdigest()
        integrity['fingerprint']=provenance.digest(integrity['files']);self.put(root/'integrity.json',integrity)
        self.assertNotEqual(self.json(root/matrix['cells'][0]['endpoint'])['model'],self.json(root/cell['endpoint'])['model'])
        with self.offline(),self.assertRaises(app.ApplicationExperimentError):app.verify(root,lab)
        with self.offline(),self.assertRaises(app.ApplicationExperimentError):app.admit_work(root,metadata,matrix['cells'],lab,'fixture-session')


if __name__=='__main__':unittest.main()
