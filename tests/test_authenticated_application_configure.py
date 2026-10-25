"""Actual example source/IR generation from explicit receipts; zero live effects."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1];EXAMPLE=ROOT/'skill/examples/authenticated-application'
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_contracts as c
import application_preparation
import agent_profiles
import inference_catalog
import pi_lab
import test_indexed_contract as indexed_fixture

spec=importlib.util.spec_from_file_location('authenticated_application_configure',EXAMPLE/'configure.py')
configure=importlib.util.module_from_spec(spec);spec.loader.exec_module(configure)


class ConfigureTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        self.image='sha256:'+'a'*64
        self.runtime={'id':self.image,'platform':'linux/arm64','capabilities':{'pi':'1.2.0'}}
        self.endpoint={'base_url':'http://model.invalid:8000/v1','model':'explicit-model','api_key_env':'MODEL_REFERENCE',
            'context_window':1000000,'max_tokens':4096}
        self.receipt=self.write('runtime.json',self.runtime);self.endpoint_path=self.write('endpoint.json',self.endpoint)
        self.options={'runtime_receipt':self.receipt,'origin':'http://fixture.invalid:8080','allowed_addresses':['192.0.2.10'],
            'credential_reference':'DIAGNOSTIC_ALICE','variant':'api','output_dir':self.root/'configured','endpoint':self.endpoint_path}
        for target,name in ((socket,'socket'),(subprocess,'Popen'),(subprocess,'run'),(pi_lab,'endpoint_secret'),(inference_catalog.Catalog,'_secret')):
            patch=mock.patch.object(target,name,side_effect=AssertionError('Configuration must be offline and key-free'));patch.start();self.addCleanup(patch.stop)

    def write(self,name,value):
        path=self.root/name;path.write_bytes(c.canonical(value));return path
    def inventory(self,path):return {str(file.relative_to(path)):file.read_bytes() for file in Path(path).rglob('*') if file.is_file()}
    def generate(self,**changes):return configure.configure(**{**self.options,**changes})
    def browser(self,release='1.2.0'):
        image={**self.runtime,'capabilities':{'pi':release,'chromium':'Chromium explicit fixture'}}
        return {'schema':1,'document_type':'browser_admission','status':'PASS','image':image,
            'host':{'native_platform':'linux/arm64','selected_platform':'linux/arm64'},'browser_security':{'policy':'chromium-userns'},
            'process':{'exit_code':0,'cleanup_confirmed':True},'observations':[{'browser_sandbox':{'namespace_and_seccomp_verified':True}}]}

    def test_api_actual_compiler_binds_explicit_origin_reference_resources_prompt_and_report(self):
        before=self.inventory(EXAMPLE);result=self.generate();root=Path(result['configured'])
        compiled=application_preparation.load_compiled(root/'compiled/plan.json',verify_runner=True);plan=compiled['plan'];stage=plan['stages'][0]
        self.assertEqual(plan['runtime']['image_id'],self.image);self.assertEqual(plan['runtime']['pi_release'],'1.2.0')
        self.assertEqual(plan['runtime']['container_profile'],'core');self.assertEqual(stage['profile_binding']['sha256'],agent_profiles.identity(agent_profiles.application('1.2.0')))
        self.assertEqual(plan['application']['origins']['fixture'],{'url':'http://fixture.invalid:8080','diagnostic_fixture':True,'allowed_addresses':['192.0.2.10']})
        self.assertEqual(plan['application']['credentials'],{'persona':'DIAGNOSTIC_ALICE'})
        self.assertEqual(plan['runtime']['resources']['runtime'],{'cpus':1,'memory':'1g','pids_limit':256,'jobs':1})
        self.assertEqual(stage['limits'],{'timeout_seconds':300,'max_turns':16,'max_total_tokens':64000,'max_tool_calls':32,'reporting_reserve_calls':6,'reporting_reserve_seconds':30})
        self.assertEqual([operation['id'] for operation in plan['application']['operations']],['identity','list-records','publish-summary'])
        self.assertEqual(stage['completion']['pagination'],[{'operation_id':'list-records','require_exhausted':True}])
        self.assertEqual(stage['completion']['publications'][0]['target_id'],'team-summary')
        self.assertEqual(stage['participant'],{'application_id':'diagnostic-app','tenant_id':'team-1','actor_id':'actor-alice','role':'participant'})
        self.assertIn('second explicit app_api',stage['effective_prompt']);self.assertIn('report_write',stage['effective_prompt'])
        self.assertNotIn('bash',stage['tools']);self.assertNotIn('app_browser',stage['tools'])
        self.assertEqual(set(self.inventory(root/'project')),{'TASK.md'})
        self.assertEqual(self.inventory(EXAMPLE),before)
        self.assertEqual(result['qualification'],'not performed')
        self.assertEqual(c.loads((root/'source.json').read_bytes()),c.loads((root/'compiled/source.json').read_bytes()))

    def test_exact_release_specific_api_and_browser_profiles_compile_for_both_reviewed_releases(self):
        hashes={}
        for release in ('0.87.1','1.2.0'):
            for variant in ('api','browser'):
                receipt=self.browser(release) if variant=='browser' else {**self.runtime,'capabilities':{'pi':release}}
                path=self.write('runtime-'+variant+release+'.json',receipt);root=self.root/(variant+release)
                self.generate(runtime_receipt=path,variant=variant,output_dir=root)
                plan=application_preparation.load_compiled(root/'compiled/plan.json')['plan'];stage=plan['stages'][0]
                self.assertEqual(stage['profile_binding']['pi_release'],release);hashes[(release,variant)]=stage['profile_binding']['sha256']
                if variant=='browser':
                    self.assertEqual({operation['id']:operation['transport'] for operation in plan['application']['operations']},
                        {'identity':'api','list-records':'browser','publish-summary':'browser'})
                    self.assertEqual(plan['runtime']['browser_sandbox_policy'],'chromium-userns')
                    targets={target['id']:target for target in plan['application']['browser_targets']}
                    self.assertEqual(targets['records-button']['actions'],['click']);self.assertEqual(targets['records-button']['allowed_operation_ids'],['list-records'])
                    self.assertEqual(targets['publish-button']['allowed_operation_ids'],['publish-summary'])
                    self.assertEqual(targets['summary-editor']['actions'],['fill']);self.assertEqual(targets['summary-editor']['allowed_operation_ids'],[])
                    self.assertEqual(targets['summary-hash']['actions'],['fill']);self.assertEqual(targets['summary-hash']['allowed_operation_ids'],[])
                    self.assertIn('snapshot target_id summary-page and verify its DOM form_state',stage['effective_prompt'])
                    self.assertEqual(targets['summary-page']['allowed_operation_ids'],[])
                    self.assertIn('app_browser',stage['tools']);self.assertNotIn('evaluate',stage['tools'])
        self.assertNotEqual(hashes[('0.87.1','api')],hashes[('1.2.0','api')])

    def test_explicit_catalog_selection_is_offline_and_never_uses_a_default_or_key(self):
        catalog=self.root/'catalog';configuration=indexed_fixture.config();configuration['endpoint'].update(context_window=1000000,max_tokens=4096)
        inference_catalog.Catalog(pi_lab.normalize_endpoint,catalog,self.root/'missing-store').register('selected',configuration,default=True)
        self.generate(endpoint=None,inference_env='selected',catalog_dir=catalog)
        frozen=c.loads((self.root/'configured/compiled/inference.json').read_bytes())
        self.assertEqual(frozen['selection']['id'],'selected');self.assertEqual(frozen['kind'],'indexed');self.assertNotIn('authority_id',json.dumps(frozen))

    def test_invalid_runtime_origin_address_reference_and_context_leave_no_partial_bundle(self):
        mutations=[{'runtime_receipt':self.write('wrongarch.json',{**self.runtime,'platform':'linux/amd64'})},
            {'runtime_receipt':self.write('tag.json',{**self.runtime,'id':'example:latest'})},
            {'runtime_receipt':self.write('wrongrelease.json',{**self.runtime,'capabilities':{'pi':'unreviewed'}})},
            {'runtime_receipt':self.write('wrongprofile.json',{**self.runtime,'profile':'browser'})},
            {'runtime_receipt':self.write('browser.json',self.browser()),'variant':'api'},
            {'variant':'browser'},{'origin':'http://fixture.invalid:8080/path'}, {'origin':'http://key@fixture.invalid:8080'},
            {'allowed_addresses':[]},{'allowed_addresses':['127.0.0.1','127.0.0.1']},{'allowed_addresses':['fixture.invalid']},
            {'credential_reference':'literal key with spaces'},{'endpoint':self.write('small.json',{**self.endpoint,'context_window':32768})},
            {'endpoint':None},{'inference_env':'selected'},{'catalog_dir':self.root}]
        for index,changes in enumerate(mutations):
            output=self.root/('rejected-'+str(index))
            with self.subTest(index=index),self.assertRaises((ValueError,TypeError)):
                self.generate(output_dir=output,**changes)
            self.assertFalse(output.exists());self.assertFalse(list(self.root.glob('.application-compile-*')))

    def test_existing_outputs_survive_failure_and_atomic_publish_failure_retains_no_bundle(self):
        self.generate();root=self.root/'configured';before=self.inventory(root)
        with self.assertRaises(ValueError):self.generate()
        self.assertEqual(self.inventory(root),before)
        output=self.root/'fsync-failure'
        publish=application_preparation._publish
        def final_failure(path,*args,**kwargs):
            if Path(path)==output:
                with mock.patch.object(application_preparation.os,'fsync',side_effect=OSError('controlled final publication fsync failure')):
                    return publish(path,*args,**kwargs)
            return publish(path,*args,**kwargs)
        with mock.patch.object(application_preparation,'_publish',side_effect=final_failure),self.assertRaises((ValueError,OSError)):
            self.generate(output_dir=output)
        self.assertFalse(output.exists());self.assertEqual(self.inventory(root),before)

    def test_cli_requires_all_runtime_origin_reference_and_inference_choices(self):
        for argv in ([],['--runtime-receipt',str(self.receipt)],['--endpoint',str(self.endpoint_path),'--inference-env','selected']):
            with self.subTest(argv=argv),mock.patch('sys.stderr'),self.assertRaises(SystemExit):configure.main(argv)


if __name__=='__main__':unittest.main()
