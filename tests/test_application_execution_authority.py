"""A07 reviewed authority integrity; actual bundled assets, no Docker/Pi/model."""
import argparse
import copy
import hashlib
from pathlib import Path
import sys
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import agent_profiles
import application_contracts as c
import application_compiler as compiler
import application_client as client
import provenance
from application_execution_authority import ReviewedAuthority
import test_application_compiler as inputs
from test_application_client_authority import BaseFixture,binding,code_identity,INFERENCE_KEY,KEY_A,KEY_B


class ReviewedAuthorityTests(BaseFixture):
    def setUp(self):
        super().setUp()
        self.synthetic_plan=copy.deepcopy(self.plan)
        self.plan=self.compile_reviewed()

    def compile_reviewed(self,source=None):
        source,kwargs=inputs.inputs(source)
        release=source['runtime']['pi_release'];profile=agent_profiles.application(release)
        self.profile=profile
        for stage in source['stages']:
            name=stage['id']
            kwargs['profile_bindings'][name]={'id':'application-client','pi_release':release,
                'sha256':agent_profiles.identity(profile),
                'assets':{asset['target']:asset['sha256'] for asset in profile['assets']}}
            for asset in profile['assets']:
                kwargs['input_assets']['profiles/'+name+'/'+asset['target']]=agent_profiles.read_asset(asset['source'])
            kwargs['prompt_policy']['profile_instructions'][name]=kwargs['input_assets']['profiles/'+name+'/instructions.md'].decode()
        return compiler.compile_plan(source,**kwargs)

    def reviewed(self,plan=None,**extra):
        return ReviewedAuthority(self.plan if plan is None else plan,
            endpoint={'api_key_env':'PI_API_KEY'},inference_key=INFERENCE_KEY,
            store=self.store,project=self.project,runroot=self.runroot,**extra)

    def issued(self):
        authority=self.reviewed();grant=authority.grant('participant',binding(self.plan))
        return authority,grant

    def denied_before_probe(self,authority,grant):
        with self.assertRaises(client.ClientError):authority.revalidate()
        with self.assertRaises(client.ClientError):authority.application_context(grant,'a'*64)
        lab,popen=mock.Mock(),mock.Mock()
        with self.assertRaises(client.ClientError):
            client.OwnedHelper.start(authority,lab=lab,args=argparse.Namespace(),registry=mock.Mock(),
                allocator=mock.Mock(),participant_resources={},popen=popen)
        self.assertEqual(lab.mock_calls,[]);popen.assert_not_called()

    def test_actual_reviewed_profile_context_and_execution_bootstrap_are_explicit(self):
        authority,grant=self.issued();self.assertTrue(authority.revalidate())
        context=authority.application_context(grant,'a'*64)
        self.assertEqual(authority.launch_spec()['mode'],'application-execution')
        self.assertEqual(context['scope'],grant.scope)
        self.assertNotEqual(context['capability'],context['budget_context']['capability'])
        self.assertEqual(context['tool_schemas'],self.plan['stages'][0]['tool_schemas'])
        bootstrap=c.loads(authority._bootstrap('/pi-client/evidence',code_identity(),state_root='/pi-client/state'))
        self.assertEqual(bootstrap['document_type'],'application_execution_private_bootstrap')
        self.assertEqual(bootstrap['authority']['mode'],'authority-only')
        self.assertEqual(bootstrap['budget_grants'][0]['scope'],grant.scope)
        public=str(context)+repr(authority)+repr(grant)
        for value in (KEY_A,KEY_B,INFERENCE_KEY):self.assertNotIn(value,public)

    def test_synthetic_or_mismatched_profile_binding_rejects_constructor(self):
        for selected in (self.synthetic_plan,{**self.plan,'stages':[copy.deepcopy(self.plan['stages'][0])]}):
            selected=copy.deepcopy(selected)
            selected['stages'][0]['profile_binding']['sha256']='f'*64
            selected['plan_sha256']=c.digest({k:v for k,v in selected.items() if k!='plan_sha256'})
            with self.assertRaises(client.ClientError) as caught:self.reviewed(selected)
            self.assertEqual(caught.exception.reason,'runtime_mismatch')

    def test_rehashed_semantic_plan_mutations_reject_before_any_probe(self):
        mutations=[lambda p:p['runtime'].update(image_id='sha256:'+'f'*64),
            lambda p:p['stages'][0]['limits'].update(max_tool_calls=p['stages'][0]['limits']['max_tool_calls']+1),
            lambda p:p['stages'][0]['profile_binding'].update(sha256='f'*64),
            lambda p:p['stages'][0]['completion']['artifacts'][0].update(max_bytes=1024),
            lambda p:p['stages'][0]['inference_binding'].update(configuration_sha256='f'*64)]
        for index,mutate in enumerate(mutations):
            with self.subTest(factor=index):
                authority,grant=self.issued();mutate(authority._plan)
                authority._plan['plan_sha256']=c.digest({k:v for k,v in authority._plan.items() if k!='plan_sha256'})
                self.denied_before_probe(authority,grant)

    def test_browser_receipt_generation_and_parent_control_mutations_reject(self):
        for field,value in [('_browser_admission',{'status':'unreviewed'}),('_generation',str(uuid.uuid4())),('_control_token','f'*64)]:
            with self.subTest(field=field):
                authority,grant=self.issued();setattr(authority,field,value)
                self.denied_before_probe(authority,grant)

    def test_issued_scope_mutations_reject_context_bootstrap_and_launch(self):
        for field in ('stage_id','segment_id','session_id','authority_generation'):
            with self.subTest(field=field):
                authority,grant=self.issued();grant.scope[field]=str(uuid.uuid4())
                self.denied_before_probe(authority,grant)
                with self.assertRaises(client.ClientError):
                    authority._bootstrap('/pi-client/evidence',code_identity(),state_root='/pi-client/state')

    def test_missing_replaced_or_extra_budget_capability_rejects(self):
        for change in ('missing','replaced','extra'):
            with self.subTest(change=change):
                authority,grant=self.issued()
                if change=='missing':authority._budget_tokens.pop(grant.capability)
                elif change=='replaced':authority._budget_tokens[grant.capability]='f'*64
                else:authority._budget_tokens['e'*64]='f'*64
                self.denied_before_probe(authority,grant)

    def test_changed_reviewed_asset_identity_rejects_revalidation(self):
        authority,grant=self.issued();changed=copy.deepcopy(self.profile)
        changed['assets'][0]['sha256']='f'*64
        with mock.patch.object(agent_profiles,'application',return_value=changed):
            self.denied_before_probe(authority,grant)

    def test_browser_admission_cannot_be_added_to_nonbrowser_plan(self):
        with self.assertRaises(client.ClientError):self.reviewed(browser_admission={'status':'PASS'})

    def pinned(self):
        files={name:hashlib.sha256(agent_profiles.read_asset(client.PACKAGE_ROOT/name)).hexdigest()
               for name in client.TRUSTED_CODE}
        plan=copy.deepcopy(self.plan);plan['input_hashes']['runner']=provenance.digest(files)
        plan['plan_sha256']=c.digest({key:value for key,value in plan.items() if key!='plan_sha256'})
        authority=self.reviewed(plan,runner_files=files)
        grant=authority.grant('participant',binding(plan))
        return authority,grant,files

    def test_pinned_current_helper_bytes_allow_private_bootstrap(self):
        authority,grant,files=self.pinned()
        authority.preflight_bootstrap();authority.verify_code_identity(files)
        self.assertEqual(authority.application_context(grant,'a'*64)['scope'],grant.scope)

    def test_changed_helper_bytes_reject_before_any_probe(self):
        authority,grant,files=self.pinned();read=agent_profiles.read_asset
        selected=client.PACKAGE_ROOT/next(iter(files))
        def changed(path,*args,**kwargs):
            body=read(path,*args,**kwargs)
            return body+b'\n# changed after preparation\n' if Path(path)==selected else body
        with mock.patch.object(agent_profiles,'read_asset',side_effect=changed):
            self.denied_before_probe(authority,grant)

    def test_actual_helper_launch_requires_prepared_runner_inventory_before_probe(self):
        authority,_=self.issued();lab,popen=mock.Mock(),mock.Mock()
        with self.assertRaises(client.ClientError):
            client.OwnedHelper.start(authority,lab=lab,args=argparse.Namespace(),registry=mock.Mock(),
                allocator=mock.Mock(),participant_resources={},popen=popen)
        self.assertEqual(lab.mock_calls,[]);popen.assert_not_called()

    def test_frozen_code_identity_cannot_diverge_from_prepared_inventory(self):
        authority,_,files=self.pinned();changed={**files,next(iter(files)):'f'*64}
        with self.assertRaises(client.ClientError):authority.verify_code_identity(changed)

    def test_browser_runtime_requires_admission_even_without_browser_targets(self):
        source=copy.deepcopy(inputs.POSITIVE['source'])
        source['runtime'].update(container_profile='browser',browser_sandbox_policy='chromium-userns')
        plan=self.compile_reviewed(source)
        with self.assertRaises(client.ClientError):self.reviewed(plan)

    def test_actual_browser_admission_is_frozen_before_context_or_probe(self):
        plan=self.compile_reviewed(inputs.browser_source())
        receipt={'schema':1,'document_type':'browser_admission','status':'PASS',
            'image':{'id':plan['runtime']['image_id'],'platform':'linux/arm64'},
            'host':{'native_platform':'linux/arm64','selected_platform':'linux/arm64'},
            'browser_security':{'policy':'chromium-userns'},
            'process':{'exit_code':0,'cleanup_confirmed':True},
            'observations':[{'browser_sandbox':{'namespace_and_seccomp_verified':True}}]}
        authority=self.reviewed(plan,browser_admission=receipt)
        grant=authority.grant('participant',binding(plan));self.assertTrue(authority.revalidate())
        authority._browser_admission['process']['cleanup_confirmed']=False
        self.denied_before_probe(authority,grant)


if __name__=='__main__':unittest.main()
