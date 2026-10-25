"""Synthetic q11/one-diagnostic dispatch policy and central durable accounting.

Prior sealed q10 custody is injected at _current_carry; actual retained-history
validation is separately exercised by the coordinator. No Docker/Pi/key effects.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools/qualification'),str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_followup as followup
import application_successor as successor
import application_launch as launch
from test_application_launch import manifest


class FollowupTests(unittest.TestCase):
    def put(self,path,value):
        path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.write_bytes(launch._json(value));path.chmod(0o600)
        return {'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    def patch(self,owner,name,value):
        p=mock.patch.object(owner,name,value);v=p.start();self.addCleanup(p.stop);return v
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
        self.prior=self.root/'tenth';self.prior.mkdir(mode=0o700);self.final=self.root/'eleventh';self.final.mkdir(mode=0o700)
        self.diag=self.root/'startup-diagnostic-001';self.diag.mkdir(mode=0o700);self.authpath=self.root/'authorization.json'
        self.now=[1000.0];self.wallnow=[1000000.0];self.clock=lambda:self.now[0];self.wall=lambda:self.wallnow[0]
        for owner,key,value in [(successor,'STARTED_WALL',999000.0),(successor,'STARTED_MONOTONIC',0.0),(successor,'DEADLINE_WALL',1013400.0),(successor,'DEADLINE_MONOTONIC',14400.0),
            (followup,'AUTHORIZATION_PATH',self.authpath),(followup,'AUTHORIZATION_ID','11111111-1111-4111-8111-111111111111'),(followup,'PRIOR_ROOT',self.prior),(followup,'FINAL_ROOT',self.final),
            (followup,'DIAGNOSTIC_ROOT',self.diag),(followup,'BINDING_ROOT',self.root/'final-binding'),(followup,'DIAGNOSTIC_BINDING_ROOT',self.root/'diagnostic-claim')]:self.patch(owner,key,value)
        self.boundary={'path':str(self.root/'boundary.json'),'sha256':'a'*64};self.patch(followup,'BOUNDARY_REFERENCE',self.boundary)
        self.oldauthority={'path':str(self.root/'q10auth.json'),'sha256':'b'*64};self.patch(followup,'PRIOR_AUTHORITY',self.oldauthority)
        window=self.put(self.root/'window.json',{'deadline_wall':successor.DEADLINE_WALL,'deadline_monotonic':successor.DEADLINE_MONOTONIC});self.patch(followup,'WINDOW_AUTHORITY',window)
        self.auth={'schema':1,'document_type':'qualification_diagnostic_and_matrix_authorization','authorization_id':followup.AUTHORIZATION_ID,'human_authorization':'SYNTHETIC ONLY',
            'recorded_wall':self.wallnow[0]-10,'prior_matrix_origins':10,'maximum_matrix_origins':11,'cumulative_container_launches':75,'cumulative_participant_segments':0,
            'previous_container_cap':249,'container_cap':262,'diagnostic_max_container_launches':1,'diagnostic_max_participant_segments':0,'diagnostic_max_seconds':120,'diagnostic_cleanup_seconds':30,
            'diagnostic_root':str(self.diag),'final_root':str(self.final),'planned_matrix_container_ceiling':186,'planned_matrix_participant_segments':24,'participant_cap':24,'live_cap':4,
            'trial_cap':1,'inference_slot_cap':1,'platform':'linux/arm64','automatic_retries':0,'continuations':0,'additional_auxiliary_launches_authorized':0,'twelfth_origin_authorized':False,
            'window_authorization':window,'deadline_wall':successor.DEADLINE_WALL,'deadline_monotonic':successor.DEADLINE_MONOTONIC,'prior_execution_authorization':self.oldauthority,
            'original_boundary':self.boundary,'prior_manifest':{'path':str(self.prior/'manifest.json'),'sha256':'1'*64},'prior_state':{'path':str(self.prior/'state.json'),'sha256':'2'*64},
            'prior_ledger':{'path':str(self.prior/'launch-ledger/ledger.json'),'sha256':'3'*64},'prior_cleanup':{'path':str(self.root/'cleanup.json'),'sha256':'4'*64},
            'prior_independent_review':{'path':str(self.root/'review.json'),'sha256':'5'*64},'prior_boundary_review':{'path':str(self.root/'boundaryreview.json'),'sha256':'6'*64},
            'original_evidence_modified':False,'window_reset':False,'diagnostic_uses_real_inference_or_application_credentials':False}
        self.refresh()
        self.base={'schema':1,'root':str(self.root/'seventh'),'manifest_sha256':'1'*64,'ledger_sha256':'2'*64,'state_sha256':'3'*64,'cleanup_receipts':[{'path':str(self.root/'proof.json'),'sha256':'4'*64}]}
        self.carry={'attempts':75,'participant_segments':0,'planned_cells':280,'qualification_id':str(uuid.uuid4()),'daemon':'fixture-daemon','daemon_capacity':{'cpu_millis':64000,'memory_mib':65536},
            'started':0.0,'deadline':14400.0,'started_wall':999000.0,'deadline_wall':1013400.0,'lineage':[{'root':str(self.root/('history'+str(i))),'qualification_id':str(uuid.uuid4()),'manifest_sha256':'1'*64,'state_sha256':'2'*64,'ledger_sha256':'3'*64} for i in range(10)],
            'prior_rows':[{'qualification_id':'prior','cell':'cell'+str(i),'status':'NOT_RUN','attempts':0} for i in range(280)],'campaign_amendment':self.ref,'effective_limits':followup.effective_limits(self.ref)}
        self.current=self.patch(followup,'_current_carry',mock.Mock(side_effect=lambda *a,**kw:copy.deepcopy(self.carry)))
        self.image={'id':followup.DIAGNOSTIC_IMAGE,'platform':'linux/arm64','capabilities':{'pi':'0.87.1'}}
        self.daemon={'id':'fixture-daemon',**self.carry['daemon_capacity']};self.weight={'cpu_millis':1000,'memory_mib':512,'pids_limit':128}
    def refresh(self):
        self.ref=self.put(self.authpath,self.auth)
        if not hasattr(self,'hashpatch'):self.hashpatch=self.patch(followup,'AUTHORIZATION_SHA256',self.ref['sha256'])
        else:followup.AUTHORIZATION_SHA256=self.ref['sha256']
    def diagnostic(self):
        policy=followup.build_diagnostic_manifest(self.ref,self.image,self.base,clock=self.clock,wall=self.wall);self.put(self.diag/'manifest.json',policy)
        ledger=followup.DiagnosticLedger.create(self.diag/'launch-ledger',policy,daemon_id='fixture-daemon',daemon_capacity=self.carry['daemon_capacity'],clock=self.clock,wall=self.wall)
        return policy,ledger
    def record(self,image=None):
        return {'schema':1,'registry':'a'*64,'generation':str(uuid.uuid4()),'launch_id':str(uuid.uuid4()),'container':'inert-'+uuid.uuid4().hex,
            'status':'intent','image':image or self.image['id'],'daemon':'fixture-daemon','runroot':str(self.diag/'run'),'application_helper':True,'client_mode':'application-execution','private_store':str(self.diag/'private')}
    def finish(self,outcome='startup_failed',poison=False):
        policy,ledger=self.diagnostic();record=self.record();key=ledger.reserve(followup.DIAGNOSTIC_CELL,'application-helper',record,self.weight,self.daemon);ledger.dispatch_ready(key)
        ledger.note(key,physical='absent',private_cleanup=True,container_id='c'*64,poison=poison)
        self.now[0]+=1;self.wallnow[0]+=1
        record.update(status='released',container_id='c'*64);recordref=self.put(self.diag/'record.json',record)
        terminal={'schema':1,'document_type':'qualification_startup_diagnostic_terminal','authorization':self.ref,'qualification_id':policy['qualification_id'],
            'manifest':{'path':str(self.diag/'manifest.json'),'sha256':hashlib.sha256((self.diag/'manifest.json').read_bytes()).hexdigest()},
            'ledger':{'path':str(self.diag/'launch-ledger/ledger.json'),'sha256':hashlib.sha256((self.diag/'launch-ledger/ledger.json').read_bytes()).hexdigest()},
            'registry_record':recordref,'container_id':'c'*64,'diagnostic_outcome':outcome,'process_exit_code':0 if outcome=='ready' else 2,'process_exit_code_available':True,'network_removed':True,'network_record':None,'participant_segments':0,'inference_calls':0,'application_requests':0,
            'real_credentials_used':False,'physical_absence_confirmed':True,'private_cleanup_confirmed':True,'all_writers_absent':True,
            'private_roots_removed':[{'path':str(self.diag/'private'),'device':1,'inode':2,'removed':True}],
            'started_wall':policy['diagnostic']['started_wall'],'finished_wall':self.wallnow[0],'elapsed_seconds':1.0,'cleanup_elapsed_seconds':.1,'original_lease_held':True,'raw_ledger_preserved':True}
        self.put(self.diag/'terminal.json',terminal);return policy,terminal
    def validate(self):return followup.validate_amendment(self.ref,self.base,clock=self.clock,wall=self.wall)
    def full(self):
        policy=manifest();policy.update(predecessor=self.base,campaign_boundary=self.boundary,campaign_amendment=self.ref,limits=followup.effective_limits(self.ref))
        spec=importlib.util.spec_from_file_location('followup_matrix_fixture',ROOT/'tools/qualification/application_client.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        cells=module.matrix(policy['images']);fields=('id','group','release','image_id','allowed_images','role_limits','container_launches_max','participant_segments_max');policy['cells']=[{k:c[k] for k in fields} for c in cells]
        limits={k:v for k,v in policy['limits'].items() if k!='live'};limits.update(simultaneously_registered_live_container_intents=4,automatic_retries=0,continuations=0)
        full={'schema':1,'document_type':'application_client_qualification','prepared_root':str(self.final),'qualification_id':policy['qualification_id'],'images':policy['images'],'cells':cells,'limits':limits,
            'predecessor':self.base,'campaign_boundary':self.boundary,'campaign_amendment':self.ref,'source':{'runner':'d'*64},'planned_container_launches':186}
        fullref=self.put(self.final/'manifest.json',full);candidate=self.put(self.final/'candidate.json',{'scope':'extracted_candidate','runner_sha256':'d'*64,'archive_sha256':'e'*64})
        followup.finalize_candidate(self.ref,fullref,candidate,clock=self.clock,wall=self.wall)
        return policy
    def test_one_diagnostic_uses_same_central_ledger_and_role_cap(self):
        policy,ledger=self.diagnostic();self.assertIsInstance(ledger,launch.LaunchLedger)
        self.assertEqual(ledger.snapshot()['attempts'],75);self.assertEqual(ledger.snapshot()['remaining_seconds'],120)
        key=ledger.reserve(followup.DIAGNOSTIC_CELL,'application-helper',self.record(),self.weight,self.daemon);ledger.dispatch_ready(key)
        self.assertEqual(ledger.snapshot()['attempts'],76)
        ledger.note(key,physical='absent',private_cleanup=True)
        with self.assertRaises(launch.LaunchError) as caught:ledger.reserve(followup.DIAGNOSTIC_CELL,'application-helper',self.record(),self.weight,self.daemon)
        self.assertEqual(caught.exception.reason,'qualification_role_limit');self.assertEqual(ledger.snapshot()['attempts'],76)
    def test_unknown_or_extra_diagnostic_roles_never_charge_or_dispatch(self):
        _,ledger=self.diagnostic()
        for role in ('participant','probe','boundary','preflight','scorer','browser-check','fixture','scripted-inference'):
            with self.assertRaises(launch.LaunchError):ledger.reserve(followup.DIAGNOSTIC_CELL,role,self.record(),self.weight,self.daemon)
        self.assertEqual(ledger.snapshot()['attempts'],75)
    def test_diagnostic_absolute90second_reporting_boundary_denies_reserve_and_dispatch(self):
        _,ledger=self.diagnostic();key=ledger.reserve(followup.DIAGNOSTIC_CELL,'application-helper',self.record(),self.weight,self.daemon)
        self.now[0]+=90;self.wallnow[0]+=90
        self.assertEqual(ledger.snapshot()['remaining_seconds'],30)
        with self.assertRaises(launch.LaunchError):ledger.dispatch_ready(key)
        with self.assertRaises(launch.LaunchError):ledger.reserve(followup.DIAGNOSTIC_CELL,'application-helper',self.record(),self.weight,self.daemon)
    def test_changed_resources_or_image_denied_before_reservation(self):
        _,ledger=self.diagnostic()
        for weight in ({**self.weight,'memory_mib':1024},{**self.weight,'cpu_millis':2000},{**self.weight,'pids_limit':256}):
            with self.assertRaises(launch.LaunchError):ledger.reserve(followup.DIAGNOSTIC_CELL,'application-helper',self.record(),weight,self.daemon)
        self.assertEqual(ledger.snapshot()['attempts'],75)
    def test_unfinished_diagnostic_denies_full_matrix_and_claim(self):
        with self.assertRaises((OSError,launch.LaunchError)):self.full()
        self.assertFalse(followup.BINDING_ROOT.exists());self.assertFalse((self.prior.parent/'campaign-successor-claims').exists())
    def test_failed_diagnostic_cleaned_positive_adds_one_container_no_native_rows(self):
        self.finish(poison=True);carry=self.validate();self.assertEqual((carry['attempts'],carry['participant_segments'],carry['planned_cells'],len(carry['lineage'])),(76,0,280,10))
        self.assertEqual(carry['startup_diagnostic']['native_rows'],0)
    def test_full_matrix_central_cumulative262_and_participant24_then_denies263(self):
        self.finish();policy=self.full();ledger=launch.LaunchLedger.create(self.final/'launch-ledger',policy,daemon_id='fixture-daemon',daemon_capacity=self.carry['daemon_capacity'],clock=self.clock,wall=self.wall)
        for cell in policy['cells']:
            for role,count in cell['role_limits'].items():
                for _ in range(count):
                    image=policy['images']['core-'+cell['release']]['id'] if role in launch.EXTERNAL else cell['image_id'];record=self.record(image)
                    key=ledger.reserve(cell['id'],role,record,launch._role_weight(policy,cell,role),self.daemon);ledger.note(key,physical='absent',private_cleanup=True)
        snap=ledger.snapshot();self.assertEqual((snap['attempts'],snap['participant_segments'],snap['live']),(262,24,0));self.assertGreater(snap['remaining_seconds'],120)
        with self.assertRaises(launch.LaunchError) as caught:ledger.reserve(policy['cells'][0]['id'],'probe',self.record(policy['cells'][0]['image_id']),launch._role_weight(policy,policy['cells'][0],'probe'),self.daemon)
        self.assertEqual(caught.exception.reason,'qualification_launch_limit')
    def test_private_uncertainty_real_keys_inference_or_extra_segment_denies_followup(self):
        _,terminal=self.finish();original=copy.deepcopy(terminal)
        for key,value in [('physical_absence_confirmed',False),('private_cleanup_confirmed',False),('all_writers_absent',False),('participant_segments',1),('inference_calls',1),('application_requests',1),('real_credentials_used',True),('original_lease_held',False),('elapsed_seconds',121.0)]:
            changed={**original,key:value};self.put(self.diag/'terminal.json',changed)
            with self.subTest(key=key),self.assertRaises(launch.LaunchError):self.validate()
    def test_unknown_raw_cid_or_unreleased_record_cannot_supply_cleanup(self):
        _,terminal=self.finish();path=Path(terminal['registry_record']['path']);value=json.loads(path.read_text());value['status']='quarantined';terminal['registry_record']=self.put(path,value);self.put(self.diag/'terminal.json',terminal)
        with self.assertRaises(launch.LaunchError):self.validate()
    def test_diagnostic_duplicate_claim_wrong_root_and_unfrozen_manifest_denied(self):
        policy,_=self.diagnostic()
        for root in (self.root/'other/launch-ledger',self.diag/'launch-ledger'):
            with self.assertRaises((OSError,launch.LaunchError)):followup.DiagnosticLedger.create(root,policy,daemon_id='fixture-daemon',daemon_capacity=self.carry['daemon_capacity'],clock=self.clock,wall=self.wall)
        self.assertTrue((followup.DIAGNOSTIC_BINDING_ROOT/'claim.json').exists())
    def test_unavailable_exit_is_explicit_and_does_not_invent_success(self):
        _,terminal=self.finish();terminal.update(process_exit_code=None,process_exit_code_available=False);self.put(self.diag/'terminal.json',terminal)
        self.assertEqual(self.validate()['attempts'],76)
        for code,available in ((0,False),(None,True),(True,True),(None,1)):
            terminal.update(process_exit_code=code,process_exit_code_available=available);self.put(self.diag/'terminal.json',terminal)
            with self.subTest(code=code,available=available),self.assertRaises(launch.LaunchError):self.validate()
    def test_owned_network_release_must_be_positive_and_match_helper_custody(self):
        _,terminal=self.finish();record=json.loads(Path(terminal['registry_record']['path']).read_text())
        network={**record,'kind':'network','status':'released','container':record['container']+'-network','launch_id':str(uuid.uuid4())}
        terminal['network_record']=self.put(self.diag/'network-record.json',network);self.put(self.diag/'terminal.json',terminal)
        self.assertEqual(self.validate()['attempts'],76)
        network['runroot']=None;terminal['network_record']=self.put(self.diag/'network-record.json',network);self.put(self.diag/'terminal.json',terminal)
        self.assertEqual(self.validate()['attempts'],76)
        original=copy.deepcopy(network)
        for key,value in (('status','quarantined'),('kind','container'),('container','unrelated-owned-network'),('daemon','foreign'),('registry','f'*64),('generation',str(uuid.uuid4())),('runroot',str(self.root/'foreign'))):
            changed={**original,key:value};terminal['network_record']=self.put(self.diag/'network-record.json',changed);self.put(self.diag/'terminal.json',terminal)
            with self.subTest(key=key),self.assertRaises(launch.LaunchError):self.validate()
        terminal['network_record']=self.put(self.diag/'network-record.json',original);terminal['network_removed']=False;self.put(self.diag/'terminal.json',terminal)
        with self.assertRaises(launch.LaunchError):self.validate()
    def test_manifest_one_container_exception_cannot_expand_default_contract(self):
        p=manifest();p['planned_container_launches']=1
        with self.assertRaises(launch.LaunchError):launch.validate_manifest(p)
        p=followup.build_diagnostic_manifest(self.ref,self.image,self.base,clock=self.clock,wall=self.wall)
        for change in (lambda x:x['cells'][0].update(group='N02'),lambda x:x['cells'][0].update(participant_segments_max=1),lambda x:x['diagnostic'].update(root=str(self.root/'alias')),lambda x:x['diagnostic'].update(deadline=x['diagnostic']['deadline']+1),lambda x:x['images'].update({'browser-0.87.1':self.image})):
            value=copy.deepcopy(p);change(value)
            with self.assertRaises(launch.LaunchError):launch.validate_manifest(value)
    def test_authority_twelfth_cap263_realkeys_or_extra_diagnostic_denied(self):
        original=copy.deepcopy(self.auth)
        for key,value in [('container_cap',263),('maximum_matrix_origins',12),('twelfth_origin_authorized',True),('diagnostic_max_container_launches',2),('diagnostic_max_seconds',121),('window_reset',True),('diagnostic_uses_real_inference_or_application_credentials',True)]:
            self.auth={**original,key:value};self.refresh()
            with self.subTest(key=key),self.assertRaises(launch.LaunchError):followup.effective_limits(self.ref)
    def test_full_twelfth_root_duplicate_and_alias_denied(self):
        self.finish();policy=self.full()
        for root in (self.root/'twelfth/launch-ledger',str(self.final)+'/./launch-ledger'):
            with self.assertRaises((OSError,launch.LaunchError)):launch.LaunchLedger.create(root,policy,daemon_id='fixture-daemon',daemon_capacity=self.carry['daemon_capacity'],clock=self.clock,wall=self.wall)
    def test_absent_terminal_routes_once_before_current_carry_validation(self):
        import application_diagnostic_cleanup as cleanup
        selected={'attempts':76,'participant_segments':0,'planned_cells':280,'startup_diagnostic':{'native_rows':0}}
        with mock.patch.object(cleanup,'validate_known_cleanup',return_value=selected) as known:
            actual=followup.validate_amendment(self.ref,self.base,clock=self.clock,wall=self.wall,window=False)
        self.assertIs(actual,selected);known.assert_called_once_with(self.ref,self.base,clock=self.clock,wall=self.wall,window=False);self.current.assert_not_called()
    def test_known_cleanup_refusal_is_preserved_without_normal_branch_retry(self):
        import application_diagnostic_cleanup as cleanup
        failure=launch.LaunchError('qualification_known_cleanup_invalid')
        with mock.patch.object(cleanup,'validate_known_cleanup',side_effect=failure) as known,self.assertRaises(launch.LaunchError) as caught:self.validate()
        self.assertIs(caught.exception,failure);known.assert_called_once();self.current.assert_not_called()
    def test_valid_original_terminal_never_selects_known_cleanup_overlay(self):
        import application_diagnostic_cleanup as cleanup
        self.finish()
        with mock.patch.object(cleanup,'validate_known_cleanup',side_effect=AssertionError('overlay_must_not_replace_original')) as known:
            self.assertEqual(self.validate()['attempts'],76)
        known.assert_not_called()
    def test_invalid_existing_terminal_never_falls_back_to_known_cleanup(self):
        import application_diagnostic_cleanup as cleanup
        self.put(self.diag/'terminal.json',{})
        with mock.patch.object(cleanup,'validate_known_cleanup') as known,self.assertRaises(launch.LaunchError):self.validate()
        known.assert_not_called()
    def test_terminal_symlink_or_directory_is_not_positive_absence(self):
        import application_diagnostic_cleanup as cleanup
        terminal=self.diag/'terminal.json';terminal.symlink_to(self.root/'missing-terminal')
        with mock.patch.object(cleanup,'validate_known_cleanup') as known,self.assertRaises((OSError,launch.LaunchError)):self.validate()
        known.assert_not_called();terminal.unlink();terminal.mkdir(mode=0o700)
        with mock.patch.object(cleanup,'validate_known_cleanup') as known,self.assertRaises((OSError,launch.LaunchError)):self.validate()
        known.assert_not_called()
    def test_unknown_terminal_parent_identity_refuses_before_overlay(self):
        import application_diagnostic_cleanup as cleanup
        alias=self.root/'alias-root';alias.symlink_to(self.diag)
        with mock.patch.object(followup,'DIAGNOSTIC_ROOT',alias),mock.patch.object(cleanup,'validate_known_cleanup') as known,self.assertRaises(OSError):self.validate()
        known.assert_not_called();self.current.assert_not_called()
    def test_legacy_caps_remain_default240_and_pinned_refs_required(self):
        self.assertEqual(launch.LIMITS['container_launch_attempts'],240);self.assertEqual(launch.maximum_origins(),8);self.assertEqual(launch.maximum_origins(self.ref),11)
        for ref in ({**self.ref,'sha256':'f'*64},{**self.ref,'path':str(self.root/'arbitrary.py')}):
            with self.assertRaises(launch.LaunchError):launch.amendment_module(ref)


if __name__=='__main__':unittest.main()
