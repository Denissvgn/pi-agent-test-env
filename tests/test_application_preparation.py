"""Offline compilation artifact filesystem oracles; no credentials/runtime calls."""
import copy
import os
import ctypes
import hashlib
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_contracts as c
import application_preparation as preparation
import inference_catalog
import pi_lab
import provenance
import test_application_compiler as compiler_fixture
import test_indexed_contract as indexed_fixture


class PreparationTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.inputs=self.root/'inputs';self.inputs.mkdir()
        self.source=copy.deepcopy(compiler_fixture.POSITIVE['source'])
        self.endpoint={'base_url':'http://model-fixture.invalid/v1','model':'explicit-model',
            'api_key_env':'MODEL_REFERENCE','context_window':1000000,'max_tokens':4096}
        self.runtime={'id':self.source['runtime']['image_id'],'platform':'linux/arm64',
                      'capabilities':{'pi':self.source['runtime']['pi_release']}}
        self.spec=self.write('source.json',self.source)
        self.endpoint_path=self.write('endpoint.json',self.endpoint)
        self.runtime_path=self.write('runtime.json',self.runtime)
        for check in self.source['checks']:
            for asset in check.get('scorer',{}).get('assets',[]):
                path=self.inputs/asset['source'];path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(b'print("independent offline scorer fixture; never executed")\n' if path.suffix=='.py' else b'{"fixture":true}\n')

    def write(self,name,value):
        path=self.inputs/name;path.write_bytes(c.canonical(value));return path

    def compile(self,name='compiled',**kwargs):
        if not kwargs:kwargs={'endpoint_path':self.endpoint_path}
        return preparation.compile_artifact(self.spec,self.root/name,self.runtime_path,**kwargs)

    def inventory(self,path):
        return {str(file.relative_to(path)):file.read_bytes() for file in path.rglob('*') if file.is_file()}

    def test_fresh_offline_compile_is_repeatable_and_freezes_same_final_representation(self):
        before=self.inventory(self.inputs)
        with mock.patch.object(socket,'socket',side_effect=AssertionError('No network')), \
             mock.patch.object(subprocess,'Popen',side_effect=AssertionError('No child')), \
             mock.patch.object(subprocess,'run',side_effect=AssertionError('No command')), \
             mock.patch.object(inference_catalog.Catalog,'_secret',side_effect=AssertionError('No key reads')):
            first=self.compile();second=self.compile('second')
            loaded=preparation.load_compiled(Path(first['root'])/'plan.json',verify_runner=True)
        self.assertEqual(first['plan'],second['plan']);self.assertEqual(first['manifest'],second['manifest'])
        self.assertEqual(loaded,first)
        self.assertEqual(self.inventory(self.inputs),before)
        self.assertEqual(first['manifest']['runner']['files'],provenance.execution({}, {},preparation.ROOT)['runner_files'])
        self.assertEqual(first['manifest']['runner']['sha256'],provenance.execution({}, {},preparation.ROOT)['runner_content_sha256'])
        stage=first['plan']['stages'][0]
        self.assertEqual(stage['prompt_admission']['framing_upper_bound'],65536)
        self.assertEqual(stage['prompt_admission']['history_reserve_tokens'],2048)
        diagnostics=c.loads((Path(first['root'])/'diagnostics.json').read_bytes())
        self.assertEqual(diagnostics['qualification'],'not performed')
        self.assertEqual(diagnostics['status'],'compiled_offline')

    def test_credential_reference_changes_both_manifest_and_ir_configuration_identity(self):
        first=self.compile()
        self.endpoint['api_key_env']='OTHER_MODEL_REFERENCE';self.write('endpoint.json',self.endpoint)
        second=self.compile('second')
        self.assertNotEqual(first['manifest']['manifest_sha256'],second['manifest']['manifest_sha256'])
        self.assertNotEqual(first['plan']['stages'][0]['inference_binding']['configuration_sha256'],
                            second['plan']['stages'][0]['inference_binding']['configuration_sha256'])
        normalized=pi_lab.normalize_endpoint(self.endpoint)
        self.assertEqual(second['plan']['stages'][0]['inference_binding']['configuration_sha256'],c.digest(normalized))

    def test_deleting_original_inputs_does_not_change_frozen_loading(self):
        result=self.compile();shutil.rmtree(self.inputs)
        with mock.patch.object(preparation,'_inference',side_effect=AssertionError('No selection')), \
             mock.patch.object(preparation,'_runner',side_effect=AssertionError('No implicit current source check')):
            self.assertEqual(preparation.load_compiled(Path(result['root'])/'plan.json'),result)

    def test_indexed_selection_needs_no_confirmation_or_key_and_frozen_load_survives_catalog_removal(self):
        catalog=self.root/'catalog';entry=inference_catalog.Catalog(pi_lab.normalize_endpoint,catalog,self.root/'nonexistent-store')
        configuration=indexed_fixture.config();configuration['endpoint'].update(context_window=1000000,max_tokens=4096)
        entry.register('named-model',configuration,default=True)
        with mock.patch.object(inference_catalog.Catalog,'_secret',side_effect=AssertionError('No credential reads')), \
             mock.patch.object(inference_catalog.Catalog,'confirm',side_effect=AssertionError('No confirmation')), \
             mock.patch.object(inference_catalog.Catalog,'freeze',side_effect=AssertionError('No authority freeze')):
            result=self.compile(inference_env_id='named-model',catalog_root=catalog)
        frozen=c.loads((Path(result['root'])/'inference.json').read_bytes())
        self.assertEqual(frozen['kind'],'indexed')
        self.assertEqual(frozen['configuration']['credential'],{'source':'store','name':'SYNTHETIC_REFERENCE'})
        self.assertNotIn('authority_id',json.dumps(frozen))
        shutil.rmtree(catalog);shutil.rmtree(self.inputs)
        self.assertEqual(preparation.load_compiled(Path(result['root'])/'plan.json'),result)

    def test_selection_is_exclusive_explicit_and_experiment_owner_cannot_be_overridden(self):
        for kwargs in ({},{'endpoint_path':self.endpoint_path,'inference_env_id':'other'},
                       {'inference_env_id':'named-model'},{'endpoint_path':self.endpoint_path,'catalog_root':self.root}):
            with self.subTest(kwargs=kwargs),self.assertRaises(preparation.PreparationError):
                preparation.compile_artifact(self.spec,self.root/'rejected',self.runtime_path,**kwargs)
        self.source['runtime']['inference_owner']='experiment_variant';self.write('source.json',self.source)
        with self.assertRaises(preparation.PreparationError):self.compile()
        self.assertFalse((self.root/'compiled').exists())

    def test_mismatched_image_platform_release_and_unproven_browser_receipt_reject_before_output(self):
        for field,value in [('id','sha256:'+'f'*64),('platform','linux/amd64'),('capabilities',{'pi':'unreviewed'})]:
            bad={**self.runtime,field:value};self.write('runtime.json',bad)
            with self.subTest(field=field),self.assertRaises(preparation.PreparationError):self.compile()
            self.assertFalse((self.root/'compiled').exists())
        self.write('runtime.json',self.runtime)
        self.source=compiler_fixture.browser_source();self.write('source.json',self.source)
        with self.assertRaises(preparation.PreparationError):self.compile()
        self.assertFalse((self.root/'compiled').exists())

    def test_supplied_browser_admission_is_frozen_as_observation_without_qualification_claim(self):
        self.source=compiler_fixture.browser_source();self.write('source.json',self.source)
        image={**self.runtime,'capabilities':{**self.runtime['capabilities'],'chromium':'Chromium 123.0.0.1'}}
        browser={'schema':1,'document_type':'browser_admission','status':'PASS','image':image,
            'host':{'native_platform':'linux/arm64','selected_platform':'linux/arm64'},
            'browser_security':{'policy':'chromium-userns'},'process':{'exit_code':0,'cleanup_confirmed':True},
            'observations':[{'browser_sandbox':{'namespace_and_seccomp_verified':True}}]}
        self.write('runtime.json',browser)
        result=self.compile();loaded=preparation.load_compiled(Path(result['root'])/'plan.json')
        receipt=c.loads((Path(result['root'])/'runtime-receipt.json').read_bytes())
        self.assertEqual(receipt['browser_admission']['observations'],browser['observations'])
        self.assertEqual(loaded['plan']['runtime']['browser_sandbox_policy'],'chromium-userns')
        self.assertEqual(c.loads((Path(result['root'])/'diagnostics.json').read_bytes())['qualification'],'not performed')

    def test_small_context_and_environment_templates_reject_without_implicit_shrinking_or_expansion(self):
        for change in ({'context_window':32768},{'model':'${PRIVATE_MODEL_KEY}'},{'api_key':'literal-forbidden-key'}):
            with self.subTest(change=change):
                self.write('endpoint.json',{**self.endpoint,**change})
                with self.assertRaises(preparation.PreparationError):self.compile()
                self.assertFalse((self.root/'compiled').exists())

    def test_no_overwrite_existing_file_or_directory_and_no_partial_output_on_write_failure(self):
        for directory in (False,True):
            output=self.root/('directory' if directory else 'file')
            if directory:output.mkdir();(output/'sentinel').write_text('prior')
            else:output.write_text('prior')
            with self.assertRaises(preparation.PreparationError):
                preparation.compile_artifact(self.spec,output,self.runtime_path,endpoint_path=self.endpoint_path)
            self.assertEqual((output/'sentinel').read_text() if directory else output.read_text(),'prior')
        with mock.patch.object(preparation.os,'fsync',side_effect=OSError('synthetic fsync failure')):
            with self.assertRaises(preparation.PreparationError):self.compile()
        self.assertFalse((self.root/'compiled').exists())
        self.assertFalse(list(self.root.glob('.application-compile-*')))

    def test_exclusive_atomic_publication_cannot_replace_a_racing_destination(self):
        original=ctypes.CDLL
        output=self.root/'compiled'
        def library(*args,**kwargs):
            native=original(*args,**kwargs);name='renameatx_np' if sys.platform=='darwin' else 'renameat2'
            function=getattr(native,name)
            def race(*arguments):
                output.mkdir();(output/'sentinel').write_text('racing destination')
                return function(*arguments)
            return types.SimpleNamespace(**{name:race})
        with mock.patch.object(preparation.ctypes,'CDLL',side_effect=library):
            with self.assertRaises(preparation.PreparationError):self.compile()
        self.assertEqual((output/'sentinel').read_text(),'racing destination')
        self.assertFalse((output/'plan.json').exists())
        self.assertFalse(list(self.root.glob('.application-compile-*')))

    def test_parent_directory_move_during_publication_keeps_unrelated_files(self):
        parent=self.root/'destination';parent.mkdir()
        moved=self.root/'moved-destination';outside=self.root/'unrelated';outside.mkdir()
        original_mkdir=os.mkdir;retained=[]
        def move_parent(path,*args,**kwargs):
            result=original_mkdir(path,*args,**kwargs)
            if str(path).startswith('.application-compile-') and not retained:
                retained.append(str(path));parent.rename(moved);parent.symlink_to(outside,target_is_directory=True)
                original_mkdir(outside/str(path));(outside/str(path)/'unrelated.txt').write_text('preserve')
            return result
        with mock.patch.object(preparation.os,'mkdir',side_effect=move_parent):
            with self.assertRaises(preparation.PreparationError):
                preparation.compile_artifact(self.spec,parent/'compiled',self.runtime_path,endpoint_path=self.endpoint_path)
        self.assertEqual((outside/retained[0]/'unrelated.txt').read_text(),'preserve')
        self.assertFalse((outside/'compiled').exists())
        self.assertFalse(list(moved.glob('.application-compile-*')))

    def test_linked_input_ancestor_leaf_and_hardlinks_are_not_compiler_inputs(self):
        alias=self.root/'alias';alias.symlink_to(self.inputs,target_is_directory=True)
        with self.assertRaises(preparation.PreparationError):
            preparation.compile_artifact(alias/'source.json',self.root/'compiled',self.runtime_path,endpoint_path=self.endpoint_path)
        linked=self.inputs/'linked.json';linked.symlink_to(self.endpoint_path)
        with self.assertRaises(preparation.PreparationError):self.compile(endpoint_path=linked)
        linked.unlink();linked.hardlink_to(self.endpoint_path)
        with self.assertRaises(preparation.PreparationError):self.compile()

    def test_mutated_ir_assets_manifest_and_unlisted_files_or_directories_fail_loading(self):
        for index,kind in enumerate(('plan','profile','scorer','manifest','extra-file','empty-directory','linked-asset')):
            result=self.compile('artifact-'+str(index));root=Path(result['root'])
            if kind=='plan':path=root/'plan.json';value=c.loads(path.read_bytes());value['stages'][0]['effective_prompt']+='changed'
            elif kind=='profile':path=root/'profiles/participant/application-client.mjs';value=None
            elif kind=='scorer':path=root/result['manifest']['scorer_assets'][0]['path'];value=None
            elif kind=='manifest':path=root/'input-manifest.json';value=c.loads(path.read_bytes());value['unreviewed']=True
            elif kind=='extra-file':path=root/'unlisted';value=None
            elif kind=='empty-directory':(root/'unlisted').mkdir();path=None;value=None
            else:
                path=root/'profiles/participant/application-client.mjs';path.unlink();path.symlink_to(ROOT/'skill/assets/profiles/application-client/application-client.mjs');path=None;value=None
            if path is not None:
                if path.exists():path.chmod(0o600)
                path.write_bytes(b'changed' if value is None else c.canonical(value))
            with self.subTest(kind=kind),self.assertRaises(preparation.PreparationError):preparation.load_compiled(root/'plan.json')

    def test_runner_comparison_is_explicit_and_source_configuration_loading_never_reselects(self):
        result=self.compile();root=Path(result['root'])
        with mock.patch.object(preparation,'_runner',return_value={'sha256':'0'*64,'files':{}}) as runner:
            self.assertEqual(preparation.load_compiled(root/'plan.json'),result)
            runner.assert_not_called()
            with self.assertRaises(preparation.PreparationError):preparation.load_compiled(root/'plan.json',verify_runner=True)
        self.assertNotIn(str(self.inputs),json.dumps(result['manifest']))

    def test_rehashed_frozen_reference_change_cannot_keep_original_ir_binding(self):
        result=self.compile();root=Path(result['root'])
        path=root/'inference.json';inference=c.loads(path.read_bytes())
        inference['configuration']['api_key_env']='CHANGED_REFERENCE'
        path.chmod(0o600);path.write_bytes(c.canonical(inference))
        manifest_path=root/'input-manifest.json';manifest=c.loads(manifest_path.read_bytes())
        manifest['files']['inference.json']=hashlib.sha256(path.read_bytes()).hexdigest()
        manifest['manifest_sha256']=c.digest({key:value for key,value in manifest.items() if key!='manifest_sha256'})
        manifest_path.chmod(0o600);manifest_path.write_bytes(c.canonical(manifest))
        with self.assertRaises(preparation.PreparationError):preparation.load_compiled(root/'plan.json')
        self.assertEqual(c.loads((root/'plan.json').read_bytes()),result['plan'])

    def test_oversize_regular_inputs_reject_from_metadata_without_partial_output(self):
        asset=self.inputs/self.source['checks'][0]['scorer']['assets'][0]['source']
        with asset.open('wb') as handle:handle.truncate(16*1024*1024+1)
        with self.assertRaises(preparation.PreparationError):self.compile()
        self.assertFalse((self.root/'compiled').exists())
        self.assertFalse(list(self.root.glob('.application-compile-*')))

    def test_application_and_selected_inference_reference_collision_rejects_without_output_or_source_change(self):
        reference=next(iter(self.source['application']['credentials'].values()))
        self.endpoint['api_key_env']=reference;self.write('endpoint.json',self.endpoint)
        before=self.inventory(self.inputs)
        with self.assertRaises(preparation.PreparationError):self.compile()
        self.assertFalse((self.root/'compiled').exists());self.assertEqual(self.inventory(self.inputs),before)
        catalog=self.root/'catalog';entry=inference_catalog.Catalog(pi_lab.normalize_endpoint,catalog,self.root/'absent-store')
        configuration=indexed_fixture.config();configuration['credential']['name']=reference
        configuration['endpoint'].update(context_window=1000000,max_tokens=4096)
        entry.register('same-reference',configuration)
        with mock.patch.object(inference_catalog.Catalog,'_secret',side_effect=AssertionError('No key reads')):
            with self.assertRaises(preparation.PreparationError):
                self.compile(inference_env_id='same-reference',catalog_root=catalog)
        self.assertFalse((self.root/'compiled').exists());self.assertEqual(self.inventory(self.inputs),before)


if __name__=='__main__':unittest.main()
