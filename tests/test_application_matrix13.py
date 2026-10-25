"""Synthetic matrix13 custody, permanent claims and unchanged hard ceilings.

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
import application_matrix13 as current
import application_launch as launch
REAL_BOUND_JSON = launch._bound_json
from test_application_launch import manifest
spec = importlib.util.spec_from_file_location('requalification_matrix_fixture',ROOT/'tools/qualification/application_client.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


def authority():
    return {'schema':1,'document_type':'qualification_matrix_requalification_authorization','authorization_id':current.AUTHORIZATION_ID,
        'human_authorization':'SYNTHETIC explicit matrix13/cap277/four hours','recorded_wall':current.STARTED_WALL,
        'final_root':str(current.FINAL_ROOT),'maximum_matrix_origins':13,'prior_matrix_origins':12,
        'cumulative_container_launches':91,'cumulative_participant_segments':0,'previous_container_cap':265,'container_cap':277,
        'participant_cap':24,'live_cap':4,'trial_cap':1,'inference_slot_cap':1,'platform':'linux/arm64','automatic_retries':0,'continuations':0,
        'planned_new_container_launches':186,'planned_new_participant_segments':24,'window_authorization':copy.deepcopy(current.WINDOW_AUTHORIZATION),
        'started_wall':current.STARTED_WALL,'started_monotonic':current.STARTED_MONOTONIC,
        'deadline_wall':current.DEADLINE_WALL,'deadline_monotonic':current.DEADLINE_MONOTONIC,
        'prior_amendment':copy.deepcopy(current.PRIOR_AMENDMENT_REFERENCE),'original_boundary':copy.deepcopy(current.BOUNDARY_REFERENCE),
        **{'prior_'+key:{'path':str(current.PRIOR_ROOT/relative),'sha256':str(index)*64}
            for index,(key,relative) in enumerate((('manifest','manifest.json'),('state','state.json'),('ledger','launch-ledger/ledger.json')),1)},
        **{key:{'path':'/synthetic/'+key+'.json','sha256':'a'*64} for key in ('prior_cleanup','prior_independent_review','prior_boundary_review')},
        'original_evidence_modified':False,'historical_windows_modified':False,'additional_auxiliary_launches_authorized':0,
        'additional_startup_diagnostic_authorized':False,'fourteenth_origin_authorized':False}


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.value = authority()
        self.reference = {'path':str(current.AUTHORIZATION_PATH),'sha256':current.AUTHORIZATION_SHA256}
        self.window = {'document_type':'qualification_window_authorization','window_seconds':14400,
            'authorization':self.value['human_authorization'],'original_deadline_wall':current.prior_amendment.DEADLINE_WALL,
            'prior_campaign_modified':False,'new_native_admission_requires_positive_owned_cleanup':True,
            **{key:self.value[key] for key in ('started_wall','started_monotonic','deadline_wall','deadline_monotonic',
                'cumulative_container_launches','cumulative_participant_segments','container_cap','participant_cap','live_cap','trial_cap',
                'inference_slot_cap','platform','automatic_retries','continuations')}}
        patch = mock.patch.object(current,'_reference',side_effect=lambda ref:copy.deepcopy(self.window if ref == current.WINDOW_AUTHORIZATION else self.value))
        patch.start();self.addCleanup(patch.stop)
    def test_exact_matrix13_and_four_hour_limits(self):
        self.assertEqual(current.effective_limits(self.reference),{**launch.LIMITS,'container_launch_attempts':277})
    def test_alias_changed_hash_or_unreviewed_authority_denied(self):
        for ref in ({**self.reference,'path':self.reference['path']+'/../matrix-012-authorization.json'},
            {**self.reference,'sha256':'f'*64},{**self.reference,'path':'/unreviewed/authority.json'}):
            with self.assertRaises(launch.LaunchError):current._authorization(ref)
    def test_cap_origin_diagnostic_retry_platform_and_root_expansion_denied(self):
        for key,bad in (('container_cap',278),('maximum_matrix_origins',14),('additional_startup_diagnostic_authorized',True),
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
            ('deadline_wall',current.DEADLINE_WALL+1),('started_monotonic',current.STARTED_MONOTONIC+1),('container_cap',276)):
            old=self.window[key];self.window[key]=bad
            with self.assertRaises(launch.LaunchError):current._authorization(self.reference)
            self.window[key]=old
    def test_nonfinite_or_earlier_recording_denied(self):
        for bad in (float('nan'),float('inf'),current.STARTED_WALL-1,current.DEADLINE_WALL):
            self.value['recorded_wall']=bad
            with self.assertRaises(launch.LaunchError):current._authorization(self.reference)


class Matrix13Tests(unittest.TestCase):
    def patch(self,owner,key,value):
        patch=mock.patch.object(owner,key,value);result=patch.start();self.addCleanup(patch.stop);return result
    def setUp(self):
        from test_application_requalification import CarryTests
        e=self.e=CarryTests(methodName='runTest');e.setUp();self.addCleanup(e.doCleanups)
        for key,value in (('PRIOR_ROOT',e.prior_root),('FINAL_ROOT',e.final_root),('BINDING_ROOT',e.root/'matrix13-binding')):self.patch(current,key,value)
        self.auth=authority();self.reference={'path':str(current.AUTHORIZATION_PATH),'sha256':current.AUTHORIZATION_SHA256}
        self.patch(current,'_authorization',lambda ref:copy.deepcopy(self.auth) if ref==self.reference else current.require(False))
        self.now=current.STARTED_MONOTONIC+10;self.wall=current.STARTED_WALL+10
        self.prior=copy.deepcopy(e.prior);self.prior.update(attempts=79,planned_cells=308)
        self.prior['lineage'].append({**self.prior['lineage'][0],'root':'/synthetic/eleventh','qualification_id':str(uuid.uuid4())})
        self.prior['prior_rows'] += [{'qualification_id':'old','cell':str(i),'status':'NOT_RUN','attempts':0} for i in range(28)]
        self.old=self.patch(current.prior_amendment,'validate_amendment',mock.Mock(side_effect=lambda *a,**kw:copy.deepcopy(self.prior)))
        self.patch(current.prior_amendment,'_launch_policy',lambda *args:e.policy)
        self.full=e.full;self.full.update(campaign_amendment=current.PRIOR_AMENDMENT_REFERENCE,campaign_boundary=current.BOUNDARY_REFERENCE)
        self.state=e.state;active={'id':next(c for c in e.policy['cells'] if c['group']=='N02')['id'],'pid':123,'run_id':str(uuid.uuid4()),'attempt_id':str(uuid.uuid4())}
        self.state.update(active_cell=active,cells={c['id']:{'status':'PASS','attempts':1,'evidence_level':'native_infrastructure'} for c in e.policy['cells'] if c['group']=='N01'})
        self.state['cells'][active['id']]={'status':'BLOCKED','attempts':1,'run_id':active['run_id'],'attempt_id':active['attempt_id'],'private_cleanup':'unconfirmed'}
        self.ledger=e.ledger;self.ledger.update(last_now=self.now-1,last_wall=self.wall-1,launches=[])
        e.records=[];self.roots=[str(e.root/('removed-'+str(i))) for i in range(8)]
        topology=[('N01-0.87.1-core','probe'),('N01-0.87.1-browser','probe'),('N01-0.87.1-browser','browser-check'),
            ('N01-1.2.0-core','probe'),('N01-1.2.0-browser','probe'),('N01-1.2.0-browser','browser-check')]
        topology += [(active['id'],role) for role in ('fixture','scripted-inference','probe','boundary','preflight','application-helper')]
        for index,(cell,role) in enumerate(topology):
            spec=next(c for c in e.policy['cells'] if c['id']==cell)
            record={'launch_id':str(uuid.uuid4()),'registry':'a'*64,'generation':str(uuid.uuid4()),'image':spec['image_id'],
                'container':'inert-'+str(index),'status':'released','daemon':'fixture-daemon','runroot':str(e.root/'run')}
            if role=='application-helper':record.update(application_helper=True,client_mode='application-execution',private_store=self.roots[0],container_id=hashlib.sha256(str(index).encode()).hexdigest())
            e.records.append(record)
            self.ledger['launches'].append({'key':launch._digest({k:record[k] for k in ('registry','launch_id')}),'cell':cell,'role':role,
                **{k:record[k] for k in ('registry','generation','launch_id','container','image')},'resources':launch._role_weight(e.policy,spec,role),
                'physical':'uncertain' if role in ('fixture','application-helper') else 'absent','private_cleanup':index<6,'pid':100+index,
                'intent_sha256':launch._intent_identity(record),'container_id':hashlib.sha256(str(index).encode()).hexdigest(),
                'cleanup_requests':[],'launch_policy':'explicit_pull_never_owned_id_5s'})
        ids=[r['container_id'] for r in self.ledger['launches']]+[hashlib.sha256(('history'+str(i)).encode()).hexdigest() for i in range(79)]
        self.cleanup=e.cleanup;self.cleanup.update(cumulative_container_launches=91,all_owned_container_ids=ids,all91_ids_absent=True,master012_copy_removed=True,
            raw_product_private_cleanup_false_rows=6,planned_rows=336,raw_ledger=self.auth['prior_ledger'],parent_envelope_removed=True,
            service_private_roots_removed=True,application_helper_private_removed=True,runtime_private_roots_removed=True,
            all4_values_RAM_matched_and_scanned=True,owned_application_network_removed_and_released=True)
        self.boundary=e.boundary;self.boundary.update(final_cleanup=self.auth['prior_cleanup'],cumulative_container_launches=91,
            **{k:True for k in ('actual_master_parent_store_absent','all8_private_roots_absent','all13_current_matrix_registry_records_released_unchanged',
                'all91_immutable_container_absence_retained','raw_manifest_state_candidate_integrity_ledger_preserved','raw_poison_true_and_six_private_false_preserved')})
        helper=e.records[-1];self.network={'launch_id':str(uuid.uuid4()),'kind':'network','status':'released','daemon':'fixture-daemon',
            'registry':helper['registry'],'generation':helper['generation'],'container':helper['container']+'-network','runroot':helper['runroot']}
        self.physical={'status':'PASS','qualification_id':self.full['qualification_id'],'raw_state_sha256':self.auth['prior_state']['sha256'],
            'raw_ledger_sha256':self.auth['prior_ledger']['sha256'],'cumulative_container_launches':91,'participant_segments':0,'all91_ids_absent':True,
            'original_lease_held':True,'controller_lock_held':True,'raw_history_unchanged':True,'all_owned_container_ids':ids,
            'network_record_released':self.network['launch_id'],'network_cleanup_confirmed':True}
        custody={'status':'PASS','qualification_id':self.full['qualification_id'],'cumulative_container_launches':91,'participant_segments':0,
            'all_owned_container_ids':ids,'raw_product_and_history_unchanged':True,'sealed_product_cleanup_status':'cleanup_unconfirmed',
            'report_repaired':False,'private_roots_removed':self.roots}
        self.manual={'status':'PASS','cumulative_container_launches':91,'participant_segments':0,'all91_ids_absent':True,'live_owned_containers':0,
            'all_owned_container_ids':ids,'manual_owner_custody':e.remember('manual13-custody',custody),
            **{k:True for k in ('original_lease_held','controller_lock_held','raw_history_unchanged','physical_absence_confirmed','private_cleanup_confirmed',
                'parent_envelope_removed','service_private_roots_removed','application_helper_private_removed','runtime_private_roots_removed',
                'all4_values_RAM_matched_and_scanned','raw_poison_and_flags_unchanged','raw_product_cleanup_unconfirmed_preserved')}}
        self.manual['service_cleanup_receipts']=[e.remember('service13-'+str(i),{'document_type':'qualification_service_cleanup',
            'physical_absence_confirmed':True,'private_bootstrap_removed':True,'daemon':'fixture-daemon',
            **{k:r[k] for k in ('launch_id','registry','generation','image','container','container_id','intent_sha256','role','cell')}})
            for i,r in enumerate(self.ledger['launches']) if r['role'] in ('fixture','scripted-inference')]
        self.cleanup['physical_cleanup']=e.remember('physical13',self.physical)
        self.cleanup['service_helper_runtime_parent_cleanup']=e.remember('manual13',self.manual)
        self.cleanup['independent_private_review']=e.remember('private13-review',{'status':'PASS','unresolved_findings':[],'actual_private_proof':self.cleanup['service_helper_runtime_parent_cleanup']})
        registry_root=Path.home()/'.local/state/pi-agentic-development/operation.lock.registry'
        observed={'status':'PASS','target':self.full['secrets_dir'],'cumulative_container_launches':91,'participant_segments':0,
            'original_lease_held':True,'controller_lock_held':True,'all91_absence_reused_from_retained_leased_hygiene':True,
            'current_registry_records':[{'path':str(registry_root/(r['launch_id']+'.json')),'sha256':launch._digest(r)} for r in e.records+[self.network]]}
        self.cleanup['master_cleanup_command']=e.remember('master13-command',{'status':'PASS','actual_exit':0,'native_launches':0,
            'credential_values_opened':False,'automatic_retry_performed':False,'custody_before_action':observed})
        for key,obj in (('prior_manifest',self.full),('prior_state',self.state),('prior_ledger',self.ledger),('prior_cleanup',self.cleanup),
            ('prior_independent_review',{'status':'PASS','unresolved_findings':[]}),('prior_boundary_review',self.boundary)):e.objects[self.auth[key]['path']]=obj
        self.patch(current,'_reference',lambda ref:copy.deepcopy(e.objects[ref['path']]))
        self.patch(current,'_relative_reference',lambda ref:copy.deepcopy(e.objects[ref['path']]))
        original=launch._bound_json
        def bound(path,sha=None):
            found=[r for r in e.records+[self.network] if r['launch_id']==Path(path).stem]
            if not found:return original(path,sha)
            if sha is not None and launch._digest(found[0])!=sha:raise launch.LaunchError('qualification_state_invalid')
            return copy.deepcopy(found[0])
        self.patch(launch,'_bound_json',bound)
    def validate(self,**kwargs):return current.validate_amendment(self.reference,self.e.base,clock=lambda:self.now,wall=lambda:self.wall,**kwargs)
    def test_exact91_carry_preserves_all336_rows_and_failed_diagnostic(self):
        before=copy.deepcopy(self.prior);carry=self.validate()
        self.assertEqual((carry['attempts'],carry['participant_segments'],carry['planned_cells'],len(carry['lineage'])),(91,0,336,12))
        self.assertEqual({s:sum(r['status']==s for r in carry['prior_rows'][-28:]) for s in ('PASS','BLOCKED','NOT_RUN')},{'PASS':4,'BLOCKED':1,'NOT_RUN':23})
        self.assertEqual(carry['startup_diagnostic'],before['startup_diagnostic']);self.assertEqual(self.prior,before);self.assertFalse(self.old.call_args.kwargs['window'])
        self.assertEqual(carry['deadline_wall'],current.DEADLINE_WALL);self.assertEqual(carry['effective_limits']['container_launch_attempts'],277)
    def test_new_window_reporting_boundary_and_regression_refuse(self):
        for now,wall in ((current.DEADLINE_MONOTONIC-30,self.wall),(self.now,current.DEADLINE_WALL-30),(current.STARTED_MONOTONIC-1,self.wall),(self.now,current.STARTED_WALL-1)):
            with self.assertRaises(launch.LaunchError):current.validate_amendment(self.reference,self.e.base,clock=lambda:now,wall=lambda:wall)
    def test_historical_validation_after_window5_expiry_requires_explicit_window_false(self):
        self.now=current.DEADLINE_MONOTONIC+1;self.wall=current.DEADLINE_WALL+1
        with self.assertRaises(launch.LaunchError):self.validate()
        self.assertEqual(self.validate(window=False)['attempts'],91)
    def test_raw_poison_or_private_flag_repair_refuses(self):
        self.ledger['poisoned']=False
        with self.assertRaises(launch.LaunchError):self.validate()
        self.ledger['poisoned']=True;self.ledger['launches'][-1]['private_cleanup']=True
        with self.assertRaises(launch.LaunchError):self.validate()
    def test_raw_resources_and_duplicate_id_refuse(self):
        row=self.ledger['launches'][0];old=row['resources'];row['resources']={**old,'cpu_millis':999}
        with self.assertRaises(launch.LaunchError):self.validate()
        row['resources']=old;row['container_id']=self.ledger['launches'][1]['container_id']
        with self.assertRaises(launch.LaunchError):self.validate()
    def test_unreleased_current_record_or_foreign_network_refuses(self):
        self.e.records[-1]['status']='absent'
        with self.assertRaises(launch.LaunchError):self.validate()
        self.e.records[-1]['status']='released';self.network['generation']=str(uuid.uuid4())
        with self.assertRaises(launch.LaunchError):self.validate()
    def test_excluded_cleanup_pointer_drift_cannot_hide_behind_intent_identity(self):
        for key in ('qualification_service_cleanup','qualification_preworker_cleanup'):
            original=launch._intent_identity(self.e.records[6])
            self.e.records[6][key]={'path':'/changed/cleanup.json','sha256':'f'*64}
            self.assertEqual(launch._intent_identity(self.e.records[6]),original)
            with self.assertRaises(launch.LaunchError):self.validate()
            del self.e.records[6][key]
    def test_real_registry_hash_rejects_excluded_cleanup_pointer_drift(self):
        registry_root=self.e.root/'.local/state/pi-agentic-development/operation.lock.registry'
        registry_root.mkdir(mode=0o700,parents=True)
        references=[]
        for record in self.e.records+[self.network]:
            path=registry_root/(record['launch_id']+'.json');path.write_bytes(launch._json(record));path.chmod(0o600)
            references.append({'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
        command=self.e.objects[self.cleanup['master_cleanup_command']['path']]
        command['custody_before_action']['current_registry_records']=references
        with mock.patch.object(Path,'home',return_value=self.e.root),mock.patch.object(launch,'_bound_json',REAL_BOUND_JSON):
            self.assertEqual(self.validate()['attempts'],91)
            record=copy.deepcopy(self.e.records[6]);before=launch._intent_identity(record)
            record['qualification_service_cleanup']={'path':'/unreviewed/cleanup.json','sha256':'f'*64}
            self.assertEqual(launch._intent_identity(record),before)
            path=registry_root/(record['launch_id']+'.json');path.write_bytes(launch._json(record));path.chmod(0o600)
            with self.assertRaises(launch.LaunchError):self.validate()
    def test_missing_private_root_cleanup_or_master_custody_refuses(self):
        Path(self.roots[0]).mkdir()
        with self.assertRaises(launch.LaunchError):self.validate()
        Path(self.roots[0]).rmdir();self.e.master['program_sha256']='f'*64
        with self.assertRaises(launch.LaunchError):self.validate()
    def test_missing_absence_or_incomplete_manual_cleanup_refuses(self):
        self.physical['all91_ids_absent']=False
        with self.assertRaises(launch.LaunchError):self.validate()
        self.physical['all91_ids_absent']=True;self.manual['raw_poison_and_flags_unchanged']=False
        with self.assertRaises(launch.LaunchError):self.validate()
    def test_wrong_previous_lineage_and_fabricated_current_success_refuse(self):
        self.prior['lineage'].pop()
        with self.assertRaises(launch.LaunchError):self.validate()
        self.prior['lineage'].append({'qualification_id':str(uuid.uuid4())});self.state['cells'][self.state['active_cell']['id']]['status']='PASS'
        with self.assertRaises(launch.LaunchError):self.validate()
    def test_permanent_single_origin_fence(self):
        carry=self.validate();current._fence(self.reference,carry,create=True);current._fence(self.reference,carry)
        with self.assertRaises((OSError,launch.LaunchError)):current._fence(self.reference,carry,create=True)
    def test_central277_boundary_denies278(self):
        limits=current.effective_limits(self.reference)
        launch._hard_admission(attempts=276,live=0,segments=0,participant=False,now=self.now,deadline=current.DEADLINE_MONOTONIC,limits=limits)
        with self.assertRaises(launch.LaunchError):launch._hard_admission(attempts=277,live=0,segments=0,participant=False,now=self.now,deadline=current.DEADLINE_MONOTONIC,limits=limits)
    def candidate(self):
        import test_application_requalification as fixtures
        saved=self.e.reference;self.e.reference=self.reference
        try:
            with mock.patch.object(fixtures,'current',current):return self.e.candidate()
        finally:self.e.reference=saved
    def test_final_candidate_and_single_launch_binding_use_same277_policy(self):
        _,_,refs,policy=self.candidate()
        current.finalize_candidate(self.reference,*refs,clock=lambda:self.now,wall=lambda:self.wall)
        current.bind_final(self.e.final_root/'launch-ledger',policy,self.validate(),create=True)
        current.bind_final(self.e.final_root/'launch-ledger',policy,self.validate())
        binding=json.loads((current.BINDING_ROOT/'launch-binding.json').read_text());self.assertEqual(binding['cumulative_attempts'],91)
        with self.assertRaises((OSError,launch.LaunchError)):current.bind_final(self.e.final_root/'launch-ledger',policy,self.validate(),create=True)
    def test_expanded_final_policy_refuses_before_permanent_claim(self):
        full,_,refs,_=self.candidate();full['limits']['container_launch_attempts']=278
        with self.assertRaises(launch.LaunchError):current.finalize_candidate(self.reference,*refs,clock=lambda:self.now,wall=lambda:self.wall)
        self.assertFalse(current.BINDING_ROOT.exists())



if __name__=='__main__':unittest.main()
