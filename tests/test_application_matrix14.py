"""Synthetic matrix14 custody, permanent claims and unchanged hard ceilings.

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
import application_matrix14 as current
import application_launch as launch
REAL_BOUND_JSON = launch._bound_json
from test_application_launch import manifest
spec = importlib.util.spec_from_file_location('requalification_matrix_fixture',ROOT/'tools/qualification/application_client.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


def authority():
    return {'schema':1,'document_type':'qualification_matrix_requalification_authorization','authorization_id':current.AUTHORIZATION_ID,
        'human_authorization':'SYNTHETIC explicit matrix14/cap291/four hours','recorded_wall':current.STARTED_WALL,
        'final_root':str(current.FINAL_ROOT),'maximum_matrix_origins':14,'prior_matrix_origins':13,
        'cumulative_container_launches':105,'cumulative_participant_segments':1,'previous_container_cap':277,'container_cap':291,'previous_participant_cap':24,
        'participant_cap':25,'live_cap':4,'trial_cap':1,'inference_slot_cap':1,'platform':'linux/arm64','automatic_retries':0,'continuations':0,
        'planned_new_container_launches':186,'planned_new_participant_segments':24,'window_authorization':copy.deepcopy(current.WINDOW_AUTHORIZATION),
        'started_wall':current.STARTED_WALL,'started_monotonic':current.STARTED_MONOTONIC,
        'deadline_wall':current.DEADLINE_WALL,'deadline_monotonic':current.DEADLINE_MONOTONIC,
        'prior_amendment':copy.deepcopy(current.PRIOR_AMENDMENT_REFERENCE),'original_boundary':copy.deepcopy(current.BOUNDARY_REFERENCE),
        **{'prior_'+key:{'path':str(current.PRIOR_ROOT/relative),'sha256':str(index)*64}
            for index,(key,relative) in enumerate((('manifest','manifest.json'),('state','state.json'),('ledger','launch-ledger/ledger.json')),1)},
        **{key:{'path':'/synthetic/'+key+'.json','sha256':'a'*64} for key in ('prior_cleanup','prior_independent_review','prior_boundary_review')},
        'original_evidence_modified':False,'historical_windows_modified':False,'additional_auxiliary_launches_authorized':0,
        'additional_startup_diagnostic_authorized':False,'fifteenth_origin_authorized':False}


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
    def test_exact_matrix14_and_four_hour_limits(self):
        self.assertEqual(current.effective_limits(self.reference),{**launch.LIMITS,'container_launch_attempts':291,'participant_segments':25})
    def test_alias_changed_hash_or_unreviewed_authority_denied(self):
        for ref in ({**self.reference,'path':self.reference['path']+'/../matrix-012-authorization.json'},
            {**self.reference,'sha256':'f'*64},{**self.reference,'path':'/unreviewed/authority.json'}):
            with self.assertRaises(launch.LaunchError):current._authorization(ref)
    def test_cap_origin_diagnostic_retry_platform_and_root_expansion_denied(self):
        for key,bad in (('container_cap',292),('maximum_matrix_origins',15),('additional_startup_diagnostic_authorized',True),
            ('additional_auxiliary_launches_authorized',1),('automatic_retries',1),('continuations',1),('platform','linux/amd64'),
            ('participant_cap',26),('live_cap',5),('trial_cap',2),('inference_slot_cap',2),('final_root','/different-root')):
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
            ('deadline_wall',current.DEADLINE_WALL+1),('started_monotonic',current.STARTED_MONOTONIC+1),('container_cap',290)):
            old=self.window[key];self.window[key]=bad
            with self.assertRaises(launch.LaunchError):current._authorization(self.reference)
            self.window[key]=old
    def test_nonfinite_or_earlier_recording_denied(self):
        for bad in (float('nan'),float('inf'),current.STARTED_WALL-1,current.DEADLINE_WALL):
            self.value['recorded_wall']=bad
            with self.assertRaises(launch.LaunchError):current._authorization(self.reference)


class Matrix14Tests(unittest.TestCase):
    def patch(self,owner,key,value):
        patch=mock.patch.object(owner,key,value);result=patch.start();self.addCleanup(patch.stop);return result
    def setUp(self):
        from test_application_matrix13 import Matrix13Tests
        self.previous=Matrix13Tests(methodName='runTest');self.previous.setUp();self.addCleanup(self.previous.doCleanups)
        old=self.previous;e=self.e=old.e
        for key,value in (('PRIOR_ROOT',e.prior_root),('FINAL_ROOT',e.final_root),('BINDING_ROOT',e.root/'matrix14-binding')):self.patch(current,key,value)
        self.auth=authority();self.reference={'path':str(current.AUTHORIZATION_PATH),'sha256':current.AUTHORIZATION_SHA256}
        self.patch(current,'_authorization',lambda ref:copy.deepcopy(self.auth) if ref==self.reference else current.require(False))
        self.now=current.STARTED_MONOTONIC+10;self.wall=current.STARTED_WALL+10
        self.prior=copy.deepcopy(old.prior);self.prior.update(attempts=91,planned_cells=336)
        self.prior['lineage'].append({**self.prior['lineage'][0],'root':'/synthetic/twelfth','qualification_id':str(uuid.uuid4())})
        self.prior['prior_rows'] += [{'qualification_id':'older','cell':str(i),'status':'NOT_RUN','attempts':0} for i in range(28)]
        self.old=self.patch(current.prior_amendment,'validate_amendment',mock.Mock(side_effect=lambda *a,**kw:copy.deepcopy(self.prior)))
        self.patch(current.prior_amendment,'_launch_policy',lambda *args:e.policy)
        self.full=old.full;self.full.update(campaign_amendment=current.PRIOR_AMENDMENT_REFERENCE,campaign_boundary=current.BOUNDARY_REFERENCE)
        self.state=old.state;self.ledger=old.ledger;self.ledger.update(last_now=self.now-1,last_wall=self.wall-1)
        active=self.state['active_cell']['id'];spec=next(c for c in e.policy['cells'] if c['id']==active)
        helper=e.records[-1];self.ledger['launches'][-1].update(physical='absent',private_cleanup=True)
        for index,role in enumerate(('participant','scorer'),12):
            record={'launch_id':str(uuid.uuid4()),'registry':'a'*64,'generation':str(uuid.uuid4()),'image':spec['image_id'],
                'container':'inert-'+str(index),'status':'released','daemon':'fixture-daemon','runroot':str(e.root/'run')}
            e.records.append(record)
            self.ledger['launches'].append({'key':launch._digest({k:record[k] for k in ('registry','launch_id')}),'cell':active,'role':role,
                **{k:record[k] for k in ('registry','generation','launch_id','container','image')},'resources':launch._role_weight(e.policy,spec,role),
                'physical':'absent','private_cleanup':False,'pid':100+index,'intent_sha256':launch._intent_identity(record),
                'container_id':hashlib.sha256(str(index).encode()).hexdigest(),'cleanup_requests':[],'launch_policy':'explicit_pull_never_owned_id_5s'})
        self.ids=[r['container_id'] for r in self.ledger['launches']]+[hashlib.sha256(('history14-'+str(i)).encode()).hexdigest() for i in range(91)]
        self.roots=old.roots[3:];self.absent=old.roots[:3]
        self.cleanup=old.cleanup;self.cleanup.update(cumulative_container_launches=105,participant_segments=1,all_owned_container_ids=self.ids,
            all105_ids_absent=True,master013_copy_removed=True,raw_product_private_cleanup_false_rows=7,planned_rows=364,
            retained_evidence_key_free=True,retained_evidence_bytes_unchanged=True,selected_private_roots_removed=self.roots,already_removed_private_roots_verified=self.absent)
        self.boundary=old.boundary;self.boundary.update(final_cleanup=self.auth['prior_cleanup'],native_counters={'containers':105,'participants':1,'raw_rows':364,'PASS':37,'BLOCKED':13,'NOT_RUN':314},
            **{k:True for k in ('actual_master_parent_store_and_four_leaves_removed','five_selected_and_three_prior_credential_roots_absent',
                'retained_two_automatic_rawfiles_and178sealed_pins_unchanged','all28_current_registry_bodies_still_released_and_pinned',
                'all105_immutable_ids_positive_retained_absence','raw_five_pairs_poison_and_seven_privatefalse_unchanged')})
        self.physical=old.physical;self.physical.update(cumulative_container_launches=105,participant_segments=1,all105_ids_absent=True,all_owned_container_ids=self.ids)
        self.manual=old.manual;self.manual.update(cumulative_container_launches=105,participant_segments=1,all105_ids_absent=True,all_owned_container_ids=self.ids,
            remaining_runtime_private_roots_removed=True,positive_participant_helper_cleanup_preserved=True,retained_evidence_key_free=True,
            retained_evidence_bytes_unchanged=True,retained_evidence_credential_match_count=0,credential_values_or_hashes_retained=False,
            raw_product_private_false_rows_preserved=7,retained_evidence_files_preserved=['raw/.owner.lock','raw/state.json'],
            selected_private_roots_removed=self.roots,already_removed_private_roots_verified=self.absent)
        custody=e.objects[self.manual['manual_owner_custody']['path']];custody.update(cumulative_container_launches=105,participant_segments=1,
            all_owned_container_ids=self.ids,private_roots_removed=self.roots,already_removed_private_roots_verified=self.absent,
            positive_participant_cleanup_preserved=True,positive_helper_cleanup_preserved=True)
        self.private_review=e.objects[self.cleanup['independent_private_review']['path']]
        self.private_review['source_input_review']=e.remember('inputs-review',{'status':'PASS','unresolved_findings':[],'design_inputs_sha256':'a'*64})
        evidence=e.prior_root/'application-evidence/inert/private/raw';evidence.mkdir(parents=True,mode=0o700)
        for directory in evidence.parents:
            if directory==e.prior_root.parent:break
            directory.chmod(0o700)
        for name,body in (('.owner.lock',b''),('state.json',b'{"synthetic":true}')):
            path=evidence/name;path.write_bytes(body);path.chmod(0o600)
        self.evidence=evidence
        self.inputs={'history_pins':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in evidence.iterdir()}}
        e.objects[str(e.prior_root.parent/'manual-cleanup-design/design-inputs-002.json')]=self.inputs
        command=e.objects[self.cleanup['master_cleanup_command']['path']];self.command=command
        observed=command['custody_before_action'];observed.update(cumulative_container_launches=105,participant_segments=1,
            all_known_container_ids_freshly_absent=True,actual_container_id_count=105)
        self.network=old.network;self.extra=[]
        for _ in range(13):self.extra.append({'launch_id':str(uuid.uuid4()),'status':'released','daemon':'fixture-daemon'})
        registry_root=Path.home()/'.local/state/pi-agentic-development/operation.lock.registry'
        observed['current_registry_records']=[{'path':str(registry_root/(r['launch_id']+'.json')),'sha256':launch._digest(r)} for r in e.records+[self.network]+self.extra]
        for key,obj in (('prior_manifest',self.full),('prior_state',self.state),('prior_ledger',self.ledger),('prior_cleanup',self.cleanup),
            ('prior_independent_review',{'status':'PASS','unresolved_findings':[]}),('prior_boundary_review',self.boundary)):e.objects[self.auth[key]['path']]=obj
        self.patch(current,'_reference',lambda ref:copy.deepcopy(e.objects[ref['path']]))
        self.patch(current,'_relative_reference',lambda ref:copy.deepcopy(e.objects[ref['path']]))
        original=launch._bound_json
        def bound(path,sha=None):
            found=[r for r in e.records+[self.network]+self.extra if r['launch_id']==Path(path).stem]
            if not found:return original(path,sha)
            if sha is not None and launch._digest(found[0])!=sha:raise launch.LaunchError('qualification_state_invalid')
            return copy.deepcopy(found[0])
        self.patch(launch,'_bound_json',bound)
    def validate(self,**kwargs):return current.validate_amendment(self.reference,self.e.base,clock=lambda:self.now,wall=lambda:self.wall,**kwargs)
    def test_exact105_one_participant_364_rows_and13_origins(self):
        before=copy.deepcopy(self.prior);carry=self.validate()
        self.assertEqual((carry['attempts'],carry['participant_segments'],carry['planned_cells'],len(carry['lineage'])),(105,1,364,13))
        self.assertEqual(carry['startup_diagnostic'],before['startup_diagnostic']);self.assertEqual(self.prior,before)
        self.assertFalse(self.old.call_args.kwargs['window']);self.assertEqual(carry['effective_limits']['participant_segments'],25)
    def test_window_expiry_reporting_reserve_and_regression_refuse(self):
        for now,wall in ((current.DEADLINE_MONOTONIC-30,self.wall),(self.now,current.DEADLINE_WALL-30),(current.STARTED_MONOTONIC-1,self.wall),(self.now,current.STARTED_WALL-1)):
            with self.assertRaises(launch.LaunchError):current.validate_amendment(self.reference,self.e.base,clock=lambda:now,wall=lambda:wall)
        self.now=current.DEADLINE_MONOTONIC+1;self.wall=current.DEADLINE_WALL+1
        self.assertEqual(self.validate(window=False)['attempts'],105)
    def test_raw_poison_private_flags_or_participant_role_repair_refuse(self):
        for obj,key,value in ((self.ledger,'poisoned',False),(self.ledger['launches'][-1],'private_cleanup',True),(self.ledger['launches'][-2],'role','probe')):
            old=obj[key];obj[key]=value
            with self.assertRaises(launch.LaunchError):self.validate()
            obj[key]=old
    def test_prior_participant_or_origin_count_drift_refuse(self):
        self.prior['participant_segments']=1
        with self.assertRaises(launch.LaunchError):self.validate()
        self.prior['participant_segments']=0;self.prior['lineage'].append(self.prior['lineage'][0])
        with self.assertRaises(launch.LaunchError):self.validate()
    def test_foreign_network_or_excluded_registry_cleanup_pointer_drift_refuse(self):
        for record,key,value in ((self.network,'generation',str(uuid.uuid4())),(self.e.records[6],'qualification_service_cleanup',{'path':'/foreign','sha256':'f'*64}),(self.extra[0],'status','absent')):
            before=copy.deepcopy(record);record[key]=value
            with self.assertRaises(launch.LaunchError):self.validate()
            record.clear();record.update(before)
    def test_actual_temp_evidence_bytes_drift_or_symlink_refuse(self):
        path=self.evidence/'state.json';original=path.read_bytes();path.write_bytes(b'changed')
        with self.assertRaises(launch.LaunchError):self.validate()
        path.unlink();target=self.evidence/'other';target.write_bytes(original);target.chmod(0o600);path.symlink_to(target)
        with self.assertRaises(OSError):self.validate()
    def test_missing_retained_evidence_proof_or_positive_worker_custody_refuse(self):
        for obj,key,value in ((self.manual,'retained_evidence_key_free',False),(self.manual,'retained_evidence_credential_match_count',1),(self.boundary,'retained_two_automatic_rawfiles_and178sealed_pins_unchanged',False)):
            old=obj[key];obj[key]=value
            with self.assertRaises(launch.LaunchError):self.validate()
            obj[key]=old
    def test_private_root_recreated_or_master_parent_present_refuse(self):
        path=Path(self.roots[0]);path.mkdir()
        with self.assertRaises(launch.LaunchError):self.validate()
        path.rmdir();master=Path(self.full['secrets_dir']).parent;master.mkdir(parents=True)
        with self.assertRaises(launch.LaunchError):self.validate()
    def test_one_origin_claims_permanent_and_second_claim_refused(self):
        carry=self.validate();current._fence(self.reference,carry,create=True);current._fence(self.reference,carry)
        with self.assertRaises(FileExistsError):current._fence(self.reference,carry,create=True)
    def test_bind_final_refuses_new_identity_or_missing_persistent_candidate(self):
        carry=self.validate();current._fence(self.reference,carry,create=True)
        policy=copy.deepcopy(self.e.policy);policy['campaign_amendment']=self.reference
        with self.assertRaises((launch.LaunchError,FileNotFoundError)):current.bind_final(current.FINAL_ROOT/'launch-ledger',policy,carry)
    def candidate(self):
        import test_application_requalification as fixtures
        saved=self.e.reference;self.e.reference=self.reference
        try:
            with mock.patch.object(fixtures,'current',current):return self.e.candidate()
        finally:self.e.reference=saved
    def test_final_candidate_and_launch_binding_share291_and25_policy(self):
        _,_,refs,policy=self.candidate()
        current.finalize_candidate(self.reference,*refs,clock=lambda:self.now,wall=lambda:self.wall)
        carry=self.validate();current.bind_final(self.e.final_root/'launch-ledger',policy,carry,create=True)
        current.bind_final(self.e.final_root/'launch-ledger',policy,carry)
        binding=json.loads((current.BINDING_ROOT/'launch-binding.json').read_bytes())
        self.assertEqual((binding['cumulative_attempts'],binding['participant_segments']),(105,1))
        with self.assertRaises((OSError,launch.LaunchError)):current.bind_final(self.e.final_root/'launch-ledger',policy,carry,create=True)
    def test_expanded_candidate_refuses_before_claim_or_binding(self):
        full,_,refs,_=self.candidate();full['limits']['participant_segments']=26
        with self.assertRaises(launch.LaunchError):current.finalize_candidate(self.reference,*refs,clock=lambda:self.now,wall=lambda:self.wall)
        self.assertFalse(current.BINDING_ROOT.exists())


class ParticipantCeilingTests(unittest.TestCase):
    def test_central_ledger_accepts24_current_plus1_prior_only_at_effective25(self):
        policy=manifest();policy['limits']={**launch.LIMITS,'container_launch_attempts':291,'participant_segments':25}
        verifier=object.__new__(launch.LaunchLedger);verifier.manifest=policy
        verifier.expected_daemon=verifier.expected_capacity=None;verifier._carry={'attempts':105,'participant_segments':1}
        rows=[]
        for index in range(24):
            identifier=str(uuid.uuid4());registry='a'*64
            rows.append({'key':launch._digest({'registry':registry,'launch_id':identifier}),'cell':'cell-a','role':'participant',
                'registry':registry,'generation':str(uuid.uuid4()),'launch_id':identifier,'container':'inert-'+str(index),
                'image':policy['cells'][0]['image_id'],'resources':launch._role_weight(policy,policy['cells'][0],'participant'),
                'physical':'absent','private_cleanup':True,'pid':100+index,'intent_sha256':'b'*64,'container_id':None,
                'cleanup_requests':[],'launch_policy':'explicit_pull_never_owned_id_5s'})
        state={'schema':1,'manifest_sha256':launch._digest(policy),'daemon':'fixture-daemon','daemon_capacity':{'cpu_millis':1000,'memory_mib':1024},
            'started':10.,'deadline':14410.,'started_wall':100.,'deadline_wall':14500.,'last_now':11.,'last_wall':101.,'poisoned':False,'launches':rows}
        verifier._validate(state)
        verifier._carry['participant_segments']=2
        with self.assertRaises(launch.LaunchError):verifier._validate(state)
        verifier._carry['participant_segments']=1;policy['limits']['participant_segments']=24;state['manifest_sha256']=launch._digest(policy)
        with self.assertRaises(launch.LaunchError):verifier._validate(state)
    def test_effective25_admits_last_segment_and_refuses26(self):
        limits={**launch.LIMITS,'container_launch_attempts':291,'participant_segments':25}
        launch._hard_admission(attempts=290,live=0,segments=24,participant=True,now=10,deadline=100,limits=limits)
        with self.assertRaises(launch.LaunchError):launch._hard_admission(attempts=290,live=0,segments=25,participant=True,now=10,deadline=100,limits=limits)
        with self.assertRaises(launch.LaunchError):launch._hard_admission(attempts=291,live=0,segments=24,participant=True,now=10,deadline=100,limits=limits)
    def test_legacy_limits_remain24_and8_origins(self):
        self.assertEqual(launch.LIMITS['participant_segments'],24);self.assertEqual(launch.maximum_origins(),8)
        with self.assertRaises(launch.LaunchError):launch._hard_admission(attempts=100,live=0,segments=24,participant=True,now=10,deadline=100)


class QualifierProjectionTests(unittest.TestCase):
    def setUp(self):
        from test_application_qualification import QualificationTests,harness
        self.harness=harness
        self.carry_fixture=Matrix14Tests(methodName='runTest');self.carry_fixture.setUp();self.addCleanup(self.carry_fixture.doCleanups)
        self.q=QualificationTests(methodName='runTest');self.q.setUp();self.addCleanup(self.q.doCleanups)
        current.FINAL_ROOT=self.q.output  # Existing fixture patch restores the module after the test.
        self.reference=self.carry_fixture.reference
        original=current._reference
        def public(reference):
            path=Path(reference['path'])
            if path in (self.q.output/'manifest.json',self.q.output/'candidate.json'):
                body=path.read_bytes()
                if hashlib.sha256(body).hexdigest()!=reference['sha256']:raise launch.LaunchError('qualification_predecessor_changed')
                return json.loads(body)
            return original(reference)
        patch=mock.patch.object(current,'_reference',public);patch.start();self.addCleanup(patch.stop)
        # Archived authority intervals are data. Pin BOTH captured entrypoint
        # clock defaults only for this projection fixture's own authority.
        self.projection_now=current.STARTED_MONOTONIC+10
        self.projection_wall=current.STARTED_WALL+10
        self.projection_entry=launch._effective_carry
        self.projection_clock_observations=[]
        def fixture_clocks(manifest,**kwargs):
            if manifest.get('campaign_amendment')==self.reference:
                kwargs.update(clock=lambda:self.projection_now,wall=lambda:self.projection_wall)
                self.projection_clock_observations.append((kwargs['clock'](),kwargs['wall']()))
            return self.projection_entry(manifest,**kwargs)
        patch=mock.patch.object(launch,'_effective_carry',side_effect=fixture_clocks);patch.start();self.addCleanup(patch.stop)
    def test_archived_projection_ignores_expired_or_pre_authority_host_defaults(self):
        old_defaults=dict(self.projection_entry.__kwdefaults__)
        # The production entrypoint captured clock functions at definition time;
        # changing time.time alone cannot exercise that historical-default bug.
        for now,wall in ((current.DEADLINE_MONOTONIC+60,current.DEADLINE_WALL+60),
                (current.STARTED_MONOTONIC-60,current.STARTED_WALL-60)):
            with self.subTest(now=now):
                defaults={**old_defaults,'clock':lambda:now,'wall':lambda:wall}
                with mock.patch.object(self.projection_entry,'__kwdefaults__',defaults):
                    policy={'campaign_boundary':current.BOUNDARY_REFERENCE,'campaign_amendment':self.reference,'predecessor':self.carry_fixture.e.base}
                    carry=launch._effective_carry(policy)
                self.assertEqual(carry['effective_limits']['participant_segments'],25)
        self.assertEqual(self.projection_clock_observations,[(self.projection_now,self.projection_wall)]*2)
    def freeze(self):
        return self.q.freeze(predecessor=self.carry_fixture.e.base,campaign_boundary=current.BOUNDARY_REFERENCE,campaign_amendment=self.reference)
    def test_real_qualifier_freeze_verify_candidate_and_permanent_bind_keep25(self):
        self.freeze();full,state=self.harness.verify(self.q.output)
        self.assertEqual(full['limits']['participant_segments'],25)
        self.assertEqual(full['limits']['container_launch_attempts'],291)
        self.assertEqual(sum(row['participant_segments_max'] for row in full['cells']),24)
        projected=self.harness._launch_manifest(full)
        self.assertEqual(projected['limits']['participant_segments'],25)
        self.assertEqual(projected['limits']['container_launch_attempts'],291)
        launch.validate_manifest(projected)  # Production selector and exact limit validation, not mocked.
        candidate={'archive_sha256':'e'*64,'runner_sha256':full['source']['runner'],'scope':'extracted_candidate'}
        self.harness.bind_candidate(self.q.output,candidate)
        self.harness.verify(self.q.output,require_candidate=True)
        refs=[{'path':str(self.q.output/name),'sha256':hashlib.sha256((self.q.output/name).read_bytes()).hexdigest()} for name in ('manifest.json','candidate.json')]
        fixture=self.carry_fixture
        current.finalize_candidate(self.reference,*refs,clock=lambda:self.projection_now,wall=lambda:self.projection_wall)
        current.bind_final(self.q.output/'launch-ledger',projected,fixture.validate(),create=True)
        current.bind_final(self.q.output/'launch-ledger',projected,fixture.validate())
        binding=json.loads((current.BINDING_ROOT/'launch-binding.json').read_bytes())
        self.assertEqual((binding['cumulative_attempts'],binding['participant_segments']),(105,1))
        self.assertEqual(state['phase'],'frozen');self.assertFalse((self.q.output/'launch-ledger').exists())
    def test_projection24_mismatch_refuses_candidate_before_origin_claim(self):
        self.freeze();full,_=self.harness.verify(self.q.output)
        original=self.harness._launch_manifest
        def wrong(manifest):
            projection=original(manifest);projection['limits']['participant_segments']=24;return projection
        candidate={'archive_sha256':'e'*64,'runner_sha256':full['source']['runner'],'scope':'extracted_candidate'}
        with mock.patch.object(self.harness,'_launch_manifest',side_effect=wrong),self.assertRaises(launch.LaunchError):
            self.harness.bind_candidate(self.q.output,candidate)
        self.assertFalse((self.q.output/'candidate.json').exists());self.assertFalse(current.BINDING_ROOT.exists())
        self.assertFalse((current.PRIOR_ROOT.parent/'campaign-successor-claims').exists())
    def test_legacy_full_qualifier_still_freezes_and_projects24(self):
        self.q.freeze();full,_=self.harness.verify(self.q.output)
        self.assertEqual(full['limits']['participant_segments'],24)
        self.assertEqual(self.harness._launch_manifest(full)['limits']['participant_segments'],24)
        self.assertEqual(sum(row['participant_segments_max'] for row in full['cells']),24)


