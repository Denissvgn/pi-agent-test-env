"""Synthetic matrix12 custody, permanent claims and unchanged hard ceilings.

No Docker/Pi/key effects. Historical custody is injected; a separate retained
coordinator check validates the actual public evidence without mocks.
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

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime'),str(ROOT/'tools/qualification')]
import application_requalification as current
import application_launch as launch
from test_application_launch import manifest
spec = importlib.util.spec_from_file_location('requalification_matrix_fixture',ROOT/'tools/qualification/application_client.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


def authority():
    return {'schema':1,'document_type':'qualification_matrix_requalification_authorization','authorization_id':current.AUTHORIZATION_ID,
        'human_authorization':'SYNTHETIC explicit matrix12/cap265/four hours','recorded_wall':current.STARTED_WALL,
        'final_root':str(current.FINAL_ROOT),'maximum_matrix_origins':12,'prior_matrix_origins':11,
        'cumulative_container_launches':79,'cumulative_participant_segments':0,'previous_container_cap':262,'container_cap':265,
        'participant_cap':24,'live_cap':4,'trial_cap':1,'inference_slot_cap':1,'platform':'linux/arm64','automatic_retries':0,'continuations':0,
        'planned_new_container_launches':186,'planned_new_participant_segments':24,'window_authorization':copy.deepcopy(current.WINDOW_AUTHORIZATION),
        'started_wall':current.STARTED_WALL,'started_monotonic':current.STARTED_MONOTONIC,
        'deadline_wall':current.DEADLINE_WALL,'deadline_monotonic':current.DEADLINE_MONOTONIC,
        'prior_amendment':copy.deepcopy(current.PRIOR_AMENDMENT_REFERENCE),'original_boundary':copy.deepcopy(current.BOUNDARY_REFERENCE),
        **{'prior_'+key:{'path':str(current.PRIOR_ROOT/relative),'sha256':str(index)*64}
            for index,(key,relative) in enumerate((('manifest','manifest.json'),('state','state.json'),('ledger','launch-ledger/ledger.json')),1)},
        **{key:{'path':'/synthetic/'+key+'.json','sha256':'a'*64} for key in ('prior_cleanup','prior_independent_review','prior_boundary_review')},
        'original_evidence_modified':False,'historical_windows_modified':False,'additional_auxiliary_launches_authorized':0,
        'additional_startup_diagnostic_authorized':False,'thirteenth_origin_authorized':False}


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.value = authority()
        self.reference = {'path':str(current.AUTHORIZATION_PATH),'sha256':current.AUTHORIZATION_SHA256}
        self.window = {'document_type':'qualification_window_authorization','window_seconds':14400,
            'authorization':self.value['human_authorization'],'original_deadline_wall':current.prior_amendment.prior_successor.DEADLINE_WALL,
            'prior_campaign_modified':False,'new_native_admission_requires_positive_owned_cleanup':True,
            **{key:self.value[key] for key in ('started_wall','started_monotonic','deadline_wall','deadline_monotonic',
                'cumulative_container_launches','cumulative_participant_segments','container_cap','participant_cap','live_cap','trial_cap',
                'inference_slot_cap','platform','automatic_retries','continuations')}}
        patch = mock.patch.object(current,'_reference',side_effect=lambda ref:copy.deepcopy(self.window if ref == current.WINDOW_AUTHORIZATION else self.value))
        patch.start();self.addCleanup(patch.stop)
    def test_exact_matrix12_and_four_hour_limits(self):
        self.assertEqual(current.effective_limits(self.reference),{**launch.LIMITS,'container_launch_attempts':265})
    def test_alias_changed_hash_or_unreviewed_authority_denied(self):
        for ref in ({**self.reference,'path':self.reference['path']+'/../matrix-012-authorization.json'},
            {**self.reference,'sha256':'f'*64},{**self.reference,'path':'/unreviewed/authority.json'}):
            with self.assertRaises(launch.LaunchError):current._authorization(ref)
    def test_cap_origin_diagnostic_retry_platform_and_root_expansion_denied(self):
        for key,bad in (('container_cap',266),('maximum_matrix_origins',13),('additional_startup_diagnostic_authorized',True),
            ('additional_auxiliary_launches_authorized',1),('automatic_retries',1),('continuations',1),('platform','linux/amd64'),
            ('participant_cap',25),('live_cap',5),('trial_cap',2),('inference_slot_cap',2),('final_root','/different-root')):
            with self.subTest(key=key):
                old=self.value[key];self.value[key]=bad
                with self.assertRaises(launch.LaunchError):current._authorization(self.reference)
                self.value[key]=old
    def test_bool_for_integer_and_extra_authority_fields_denied(self):
        self.value['schema']=True
        with self.assertRaises(launch.LaunchError):current._authorization(self.reference)
        self.value['schema']=1;self.value['implicit_retry']=False
        with self.assertRaises(launch.LaunchError):current._authorization(self.reference)
    def test_changed_historical_window_or_missing_positive_cleanup_denied(self):
        for key,bad in (('prior_campaign_modified',True),('new_native_admission_requires_positive_owned_cleanup',False),
            ('deadline_wall',current.DEADLINE_WALL+1),('started_monotonic',current.STARTED_MONOTONIC+1),('container_cap',264)):
            old=self.window[key];self.window[key]=bad
            with self.assertRaises(launch.LaunchError):current._authorization(self.reference)
            self.window[key]=old
    def test_nonfinite_or_earlier_recording_denied(self):
        for bad in (float('nan'),float('inf'),current.STARTED_WALL-1,current.DEADLINE_WALL):
            self.value['recorded_wall']=bad
            with self.assertRaises(launch.LaunchError):current._authorization(self.reference)


class CarryTests(unittest.TestCase):
    def patch(self,owner,key,value):
        patch=mock.patch.object(owner,key,value);result=patch.start();self.addCleanup(patch.stop);return result
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
        self.prior_root=self.root/'attempt011'/'qualification';self.prior_root.mkdir(mode=0o700,parents=True)
        self.final_root=self.root/'attempt012'/'qualification';self.final_root.mkdir(mode=0o700,parents=True)
        for key,value in (('PRIOR_ROOT',self.prior_root),('FINAL_ROOT',self.final_root),('BINDING_ROOT',self.root/'binding')):
            self.patch(current,key,value)
        self.auth=authority();self.reference={'path':str(current.AUTHORIZATION_PATH),'sha256':current.AUTHORIZATION_SHA256}
        self.patch(current,'_authorization',lambda ref:copy.deepcopy(self.auth) if ref==self.reference else current.require(False))
        self.now=current.STARTED_MONOTONIC+10;self.wall=current.STARTED_WALL+10
        self.base={'schema':1,'root':str(self.root/'seventh'),'manifest_sha256':'1'*64,'state_sha256':'2'*64,'ledger_sha256':'3'*64,
            'cleanup_receipts':[{'path':str(self.root/'old-clean.json'),'sha256':'4'*64}]}
        self.prior={'attempts':76,'participant_segments':0,'planned_cells':280,'qualification_id':str(uuid.uuid4()),
            'daemon':'fixture-daemon','daemon_capacity':{'cpu_millis':64000,'memory_mib':65536},
            'started':current.STARTED_MONOTONIC-1000,'deadline':current.STARTED_MONOTONIC-1000+14400,
            'started_wall':current.STARTED_WALL-1000,'deadline_wall':current.STARTED_WALL-1000+14400,
            'lineage':[{'root':'/synthetic/'+str(i),'qualification_id':str(uuid.uuid4()),'manifest_sha256':'1'*64,'state_sha256':'2'*64,'ledger_sha256':'3'*64} for i in range(10)],
            'prior_rows':[{'qualification_id':'old','cell':str(i),'status':'NOT_RUN','attempts':0} for i in range(280)],
            'startup_diagnostic':{'reference':{'path':'/synthetic/known-cleanup.json','sha256':'1'*64},'attempts':1,'participant_segments':0,'native_rows':0}}
        self.old_validation=self.patch(current.prior_amendment,'validate_amendment',mock.Mock(side_effect=lambda *a,**kw:copy.deepcopy(self.prior)))
        self.policy=manifest();self.policy['cells']=client.matrix(self.policy['images'])
        self.policy['limits']={**launch.LIMITS,'container_launch_attempts':262}
        self.full={'prepared_root':str(self.prior_root),'document_type':'application_client_qualification','predecessor':self.base,
            'campaign_boundary':current.BOUNDARY_REFERENCE,'campaign_amendment':current.PRIOR_AMENDMENT_REFERENCE,
            'qualification_id':self.policy['qualification_id'],'cells':self.policy['cells'],'secrets_dir':str(self.root/'gone-parent'/'store')}
        self.patch(current.prior_amendment,'_launch_policy',lambda *a:self.policy)
        self.state={'schema':1,'phase':'blocked','active_cell':None,'started_at':self.prior['started_wall'],'cells':{
            'N01-0.87.1-core':{'status':'PASS','attempts':1,'evidence_level':'native_infrastructure'},
            'N01-0.87.1-browser':{'status':'BLOCKED','attempts':1,'reason':'infrastructure_qualification_failed'}}}
        self.ledger={'schema':1,'manifest_sha256':launch._digest(self.policy),'daemon':'fixture-daemon','daemon_capacity':self.prior['daemon_capacity'],
            **{k:self.prior[k] for k in ('started','deadline','started_wall','deadline_wall')},'last_now':self.now-1,'last_wall':self.wall-1,'poisoned':True,'launches':[]}
        self.records=[]
        for i,(cell,role) in enumerate((('N01-0.87.1-core','probe'),('N01-0.87.1-browser','probe'),('N01-0.87.1-browser','browser-check'))):
            entry=next(c for c in self.policy['cells'] if c['id']==cell)
            record={'launch_id':str(uuid.uuid4()),'registry':'a'*64,'generation':str(uuid.uuid4()),'image':entry['image_id'],
                'container':'synthetic-'+str(i),'status':'released','daemon':'fixture-daemon'}
            self.records.append(record)
            self.ledger['launches'].append({'key':launch._digest({k:record[k] for k in ('registry','launch_id')}),'cell':cell,'role':role,
                **{k:record[k] for k in ('registry','generation','launch_id','container','image')},'resources':launch._role_weight(self.policy,entry,role),
                'physical':'absent','private_cleanup':i==0,'pid':100+i,'intent_sha256':launch._intent_identity(record),'container_id':str(i+1)*64,
                'cleanup_requests':[],'launch_policy':'explicit_pull_never_owned_id_5s'})
        self.objects={}
        for key,obj in (('prior_manifest',self.full),('prior_state',self.state),('prior_ledger',self.ledger)):
            self.objects[self.auth[key]['path']]=obj
        ids=[str(i+1)*64 for i in range(3)]+[hashlib.sha256(str(i).encode()).hexdigest() for i in range(76)]
        self.cleanup={'status':'PASS','qualification_id':self.full['qualification_id'],'cumulative_container_launches':79,'participant_segments':0,
            'live_owned_containers':0,'enforced_live_ceiling':4,'safe_to_continue':False,'continued_execution_authorized':False,'safe_for_final_handoff':True,
            'qualification_eligible':False,'original_operator_store_touched':False,'raw_ledger_rewritten':False,
            'raw_product_private_cleanup_false_rows':2,'planned_rows':308,'all_owned_container_ids':ids,
            **{k:True for k in ('physical_absence_confirmed','private_cleanup_confirmed','master011_copy_removed','temporary_parent_absence_confirmed',
                'all79_ids_absent','raw_history_poison_and_pending_flags_preserved','raw_product_cleanup_unconfirmed_preserved')}}
        self.boundary={'status':'PASS','unresolved_findings':[],'final_cleanup':self.auth['prior_cleanup'],'registry_cleanup_verified':True,
            'all79_physical_absence_proof_verified':True,'raw_current_ledger_preserved':True,'raw_historical_ledgers_preserved':True,
            'raw_private_cleanup_false_rows_preserved':2,'cumulative_container_launches':79,'participant_segments':0,'live_owned_containers':0}
        self.physical={'status':'PASS','qualification_id':self.full['qualification_id'],'manifest':self.auth['prior_manifest'],
            'ledger':self.auth['prior_ledger'],'state':self.auth['prior_state'],'cumulative_container_launches':79,'participant_segments':0,
            'live_owned_containers':0,'resource_mutations':0,'raw_product_private_cleanup_false_rows_preserved':2,'all_owned_container_ids':ids,
            **{k:True for k in ('all79_ids_absent','original_lease_held','controller_lock_held','lock_inodes_unchanged','all_native_writers_absent',
                'all_service_writers_stopped','all_helper_writers_stopped','all_qualification_controllers_stopped','all_issued_capabilities_revoked',
                'raw_history_unchanged','raw_poison_preserved','physical_absence_confirmed','private_cleanup_confirmed')}}
        self.physical['after_records']=[self.remember('after'+str(i),r) for i,r in enumerate(self.records)]
        self.custody={'status':'PASS','unresolved_findings':[],'target':self.full['secrets_dir'],'program_sha256':'a'*64,
            'authorization':self.remember('master-auth',{}),'observation':self.remember('master-observation',{})}
        self.master={'status':'removed','store_removed':True,'temporary_parent_removed':True,'operator_original_store_selected':False,
            'values_opened':False,'value_hashes_computed':False,'removed_references':['PI_API_KEY','QUAL_APPLICATION_ALICE','QUAL_APPLICATION_BOB','QUAL_APPLICATION_SCRIPTED'],
            'target':self.full['secrets_dir'],'independent_review':self.remember('custody',self.custody),
            **{k:self.custody[k] for k in ('authorization','observation','program_sha256')}}
        for key,obj in (('physical_and_ownership_closure',self.physical),('independent_physical_ownership_review',{'status':'PASS','unresolved_findings':[]}),
            ('master_cleanup',self.master),('independent_actual_custody',self.custody)):
            self.cleanup[key]=self.remember(key,obj)
        for key,obj in (('prior_cleanup',self.cleanup),('prior_independent_review',{'status':'PASS','unresolved_findings':[]}),('prior_boundary_review',self.boundary)):
            self.objects[self.auth[key]['path']]=obj
        self.patch(current,'_reference',lambda ref:copy.deepcopy(self.objects[ref['path']]))
        self.patch(current,'_relative_reference',lambda ref:copy.deepcopy(self.objects[ref['path']]))
        original_bound_json=launch._bound_json
        def bound_json(path,sha=None):
            matches=[r for r in self.records if r['launch_id']==Path(path).stem]
            return copy.deepcopy(matches[0]) if matches else original_bound_json(path,sha)
        self.patch(launch,'_bound_json',bound_json)
    def remember(self,key,obj):
        path=str(self.root/(key+'.json'));self.objects[path]=obj
        return {'path':path,'sha256':launch._digest(obj)}
    def validate(self,**kwargs):
        return current.validate_amendment(self.reference,self.base,clock=lambda:self.now,wall=lambda:self.wall,**kwargs)
    def test_positive_carry_preserves_old_clocks_rows_and_failed_diagnostic(self):
        before=copy.deepcopy(self.prior);carry=self.validate()
        self.assertEqual((carry['attempts'],carry['participant_segments'],carry['planned_cells'],len(carry['lineage'])),(79,0,308,11))
        self.assertEqual([r['status'] for r in carry['prior_rows'][-28:]].count('NOT_RUN'),26)
        self.assertEqual(carry['startup_diagnostic'],before['startup_diagnostic']);self.assertEqual(self.prior,before)
        self.assertEqual(carry['started'],current.STARTED_MONOTONIC);self.assertEqual(carry['effective_limits']['container_launch_attempts'],265)
        self.assertFalse(self.old_validation.call_args.kwargs['window'])
    def test_new_window_expiry_and_clock_regression_denied(self):
        for now,wall in ((current.DEADLINE_MONOTONIC-30,self.wall),(self.now,current.DEADLINE_WALL-30),
            (current.STARTED_MONOTONIC-1,self.wall),(self.now,current.STARTED_WALL-1)):
            with self.subTest(now=now,wall=wall):
                with self.assertRaises(launch.LaunchError):
                    current.validate_amendment(self.reference,self.base,clock=lambda:now,wall=lambda:wall)
    def test_historical_validation_ignores_expiry_only_not_clock_origin(self):
        self.now=current.DEADLINE_MONOTONIC+1;self.wall=current.DEADLINE_WALL+1
        self.assertEqual(self.validate(window=False)['attempts'],79)
    def test_incomplete_or_extra_previous_lineage_denied(self):
        self.prior['lineage'].append(copy.deepcopy(self.prior['lineage'][0]))
        with self.assertRaises(launch.LaunchError):self.validate()
    def test_raw_ledger_resource_image_or_identity_drift_denied(self):
        row=self.ledger['launches'][0]
        for key,bad in (('image','sha256:'+'f'*64),('key','e'*64),('resources',{'cpu_millis':999,'memory_mib':1024,'pids_limit':256})):
            old=row[key];row[key]=bad
            with self.assertRaises(launch.LaunchError):self.validate()
            row[key]=old
    def test_raw_private_cleanup_repair_or_poison_removal_denied(self):
        self.ledger['launches'][1]['private_cleanup']=True
        with self.assertRaises(launch.LaunchError):self.validate()
        self.ledger['launches'][1]['private_cleanup']=False;self.ledger['poisoned']=False
        with self.assertRaises(launch.LaunchError):self.validate()
    def test_raw_current_row_cannot_be_relabelled_pass(self):
        self.state['cells']['N01-0.87.1-browser']['status']='PASS'
        with self.assertRaises(launch.LaunchError):self.validate()
    def test_custody_requires_positive_79_absence_writers_and_revocation(self):
        for key in ('all79_ids_absent','all_native_writers_absent','all_issued_capabilities_revoked','original_lease_held','private_cleanup_confirmed'):
            self.physical[key]=False
            with self.assertRaises(launch.LaunchError):self.validate()
            self.physical[key]=True
    def test_duplicate_or_missing_owned_id_denied(self):
        self.cleanup['all_owned_container_ids'][-1]=self.cleanup['all_owned_container_ids'][0]
        with self.assertRaises(launch.LaunchError):self.validate()
    def test_unreleased_registry_record_or_wrong_generation_denied(self):
        for key,bad in (('status','absent'),('generation',str(uuid.uuid4()))):
            old=self.records[0][key];self.records[0][key]=bad
            with self.assertRaises(launch.LaunchError):self.validate()
            self.records[0][key]=old
    def test_master_custody_or_namespace_absence_required(self):
        self.custody['program_sha256']='b'*64
        with self.assertRaises(launch.LaunchError):self.validate()
        self.custody['program_sha256']='a'*64;Path(self.full['secrets_dir']).mkdir(parents=True)
        with self.assertRaises(launch.LaunchError):self.validate()
    def test_positive_claim_is_permanent_and_second_origin_denied(self):
        carry=self.validate();current._fence(self.reference,carry,create=True)
        current._fence(self.reference,carry)
        with self.assertRaises((OSError,launch.LaunchError)):current._fence(self.reference,carry,create=True)
        claims=self.prior_root.parent/'campaign-successor-claims'
        self.assertEqual(len(list(claims.glob('*.json'))),2)
    def test_alias_or_public_claim_folder_denied(self):
        folder=self.prior_root.parent/'campaign-successor-claims';folder.mkdir(mode=0o755)
        with self.assertRaises(launch.LaunchError):current._fence(self.reference,self.validate(),create=True)
    def test_265_central_boundary_denies_266_without_effect(self):
        limits=current.effective_limits(self.reference)
        launch._hard_admission(attempts=264,live=0,segments=0,participant=False,now=self.now,deadline=current.DEADLINE_MONOTONIC,limits=limits)
        with self.assertRaises(launch.LaunchError):
            launch._hard_admission(attempts=265,live=0,segments=0,participant=False,now=self.now,deadline=current.DEADLINE_MONOTONIC,limits=limits)
    def candidate(self):
        cells=copy.deepcopy(self.policy['cells']);fields=('id','group','release','image_id','allowed_images','role_limits','container_launches_max','participant_segments_max')
        limits={k:v for k,v in current.effective_limits(self.reference).items() if k!='live'}
        limits.update(simultaneously_registered_live_container_intents=4,automatic_retries=0,continuations=0)
        full={'schema':1,'document_type':'application_client_qualification','prepared_root':str(self.final_root),
            'qualification_id':str(uuid.uuid4()),'images':self.policy['images'],'cells':cells,'limits':limits,
            'planned_container_launches':186,'predecessor':self.base,'campaign_boundary':current.BOUNDARY_REFERENCE,
            'campaign_amendment':self.reference,'source':{'runner':'d'*64}}
        candidate={'archive_sha256':'e'*64,'runner_sha256':'d'*64,'scope':'extracted_candidate'}
        refs=[]
        for name,obj in (('manifest.json',full),('candidate.json',candidate)):
            path=self.final_root/name;path.write_bytes(launch._json(obj));path.chmod(0o600)
            self.objects[str(path)]=obj;refs.append({'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
        policy={k:full[k] for k in ('qualification_id','images','predecessor','campaign_boundary','campaign_amendment','planned_container_launches')}
        policy.update(cells=[{k:c[k] for k in fields} for c in cells],limits=current.effective_limits(self.reference))
        return full,candidate,refs,policy
    def test_final_candidate_and_launch_binding_match_same_validated_policy(self):
        _,_,refs,policy=self.candidate()
        current.finalize_candidate(self.reference,*refs,clock=lambda:self.now,wall=lambda:self.wall)
        current.bind_final(self.final_root/'launch-ledger',policy,self.validate(),create=True)
        current.bind_final(self.final_root/'launch-ledger',policy,self.validate())
        binding=json.loads((current.BINDING_ROOT/'launch-binding.json').read_text())
        self.assertEqual(binding['cumulative_attempts'],79)
        with self.assertRaises((OSError,launch.LaunchError)):
            current.bind_final(self.final_root/'launch-ledger',policy,self.validate(),create=True)
    def test_candidate_runner_mismatch_denied_before_claim(self):
        _,candidate,refs,_=self.candidate();candidate['runner_sha256']='f'*64
        with self.assertRaises(launch.LaunchError):
            current.finalize_candidate(self.reference,*refs,clock=lambda:self.now,wall=lambda:self.wall)
        self.assertFalse(current.BINDING_ROOT.exists())
    def test_final_root_or_limits_cannot_expand_through_candidate(self):
        full,_,refs,_=self.candidate();full['limits']['container_launch_attempts']=266
        with self.assertRaises(launch.LaunchError):
            current.finalize_candidate(self.reference,*refs,clock=lambda:self.now,wall=lambda:self.wall)
        self.assertFalse(current.BINDING_ROOT.exists())


if __name__ == '__main__':
    unittest.main()
