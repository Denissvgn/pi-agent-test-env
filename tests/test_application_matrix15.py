"""Synthetic matrix15 custody, permanent claims and unchanged hard ceilings.

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
import application_matrix15 as current
import application_launch as launch
REAL_BOUND_JSON = launch._bound_json
from test_application_launch import manifest
spec = importlib.util.spec_from_file_location('requalification_matrix_fixture',ROOT/'tools/qualification/application_client.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


def authority():
    return {'schema':1,'document_type':'qualification_matrix_requalification_authorization','authorization_id':current.AUTHORIZATION_ID,
        'human_authorization':'SYNTHETIC explicit matrix15/cap305/four hours','recorded_wall':current.STARTED_WALL,
        'final_root':str(current.FINAL_ROOT),'maximum_matrix_origins':15,'prior_matrix_origins':14,
        'cumulative_container_launches':119,'cumulative_participant_segments':2,'previous_container_cap':291,'container_cap':305,'previous_participant_cap':25,
        'participant_cap':26,'live_cap':4,'trial_cap':1,'inference_slot_cap':1,'platform':'linux/arm64','automatic_retries':0,'continuations':0,
        'planned_new_container_launches':186,'planned_new_participant_segments':24,'window_authorization':copy.deepcopy(current.WINDOW_AUTHORIZATION),
        'started_wall':current.STARTED_WALL,'started_monotonic':current.STARTED_MONOTONIC,
        'deadline_wall':current.DEADLINE_WALL,'deadline_monotonic':current.DEADLINE_MONOTONIC,
        'prior_amendment':copy.deepcopy(current.PRIOR_AMENDMENT_REFERENCE),'original_boundary':copy.deepcopy(current.BOUNDARY_REFERENCE),
        **{'prior_'+key:{'path':str(current.PRIOR_ROOT/relative),'sha256':str(index)*64}
            for index,(key,relative) in enumerate((('manifest','manifest.json'),('state','state.json'),('ledger','launch-ledger/ledger.json')),1)},
        **{key:{'path':'/synthetic/'+key+'.json','sha256':'a'*64} for key in ('prior_cleanup','prior_independent_review','prior_boundary_review')},
        'original_evidence_modified':False,'historical_windows_modified':False,'additional_auxiliary_launches_authorized':0,
        'additional_startup_diagnostic_authorized':False,'sixteenth_origin_authorized':False}


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
    def test_exact_matrix15_and_four_hour_limits(self):
        self.assertEqual(current.effective_limits(self.reference),{**launch.LIMITS,'container_launch_attempts':305,'participant_segments':26})
    def test_alias_changed_hash_or_unreviewed_authority_denied(self):
        for ref in ({**self.reference,'path':self.reference['path']+'/../matrix-012-authorization.json'},
            {**self.reference,'sha256':'f'*64},{**self.reference,'path':'/unreviewed/authority.json'}):
            with self.assertRaises(launch.LaunchError):current._authorization(ref)
    def test_cap_origin_diagnostic_retry_platform_and_root_expansion_denied(self):
        for key,bad in (('container_cap',306),('maximum_matrix_origins',16),('additional_startup_diagnostic_authorized',True),
            ('additional_auxiliary_launches_authorized',1),('automatic_retries',1),('continuations',1),('platform','linux/amd64'),
            ('participant_cap',27),('live_cap',5),('trial_cap',2),('inference_slot_cap',2),('final_root','/different-root')):
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
            ('deadline_wall',current.DEADLINE_WALL+1),('started_monotonic',current.STARTED_MONOTONIC+1),('container_cap',304)):
            old=self.window[key];self.window[key]=bad
            with self.assertRaises(launch.LaunchError):current._authorization(self.reference)
            self.window[key]=old
    def test_nonfinite_or_earlier_recording_denied(self):
        for bad in (float('nan'),float('inf'),current.STARTED_WALL-1,current.DEADLINE_WALL):
            self.value['recorded_wall']=bad
            with self.assertRaises(launch.LaunchError):current._authorization(self.reference)
    def test_exact_router15_preserves_default8_and_prior14(self):
        self.assertIs(launch.amendment_module(self.reference),current)
        self.assertEqual(launch.maximum_origins(self.reference),15);self.assertEqual(launch.maximum_origins(),8)
        oldref=current.PRIOR_AMENDMENT_REFERENCE
        with mock.patch.object(current.prior_amendment,'effective_limits',return_value={**launch.LIMITS,'container_launch_attempts':291,'participant_segments':25}):
            self.assertEqual(launch.maximum_origins(oldref),14)



class Matrix15Tests(unittest.TestCase):
    def patch(self,owner,key,value):
        patch=mock.patch.object(owner,key,value);result=patch.start();self.addCleanup(patch.stop);return result
    def setUp(self):
        from test_application_matrix14 import Matrix14Tests
        self.previous=Matrix14Tests(methodName='runTest');self.previous.setUp();self.addCleanup(self.previous.doCleanups)
        old=self.previous;e=self.e=old.e
        # Freeze a synthetic prior carry before replacing the current14 graph.
        self.prior=old.validate()
        for key,value in (('PRIOR_ROOT',e.prior_root),('FINAL_ROOT',e.final_root),('BINDING_ROOT',e.root/'matrix15-binding')):self.patch(current,key,value)
        self.auth=authority();self.reference={'path':str(current.AUTHORIZATION_PATH),'sha256':current.AUTHORIZATION_SHA256}
        self.patch(current,'_authorization',lambda ref:copy.deepcopy(self.auth) if ref==self.reference else current.require(False))
        self.now=current.STARTED_MONOTONIC+10;self.wall=current.STARTED_WALL+10
        self.old=self.patch(current.prior_amendment,'validate_amendment',mock.Mock(side_effect=lambda *a,**kw:copy.deepcopy(self.prior)))
        self.patch(current.prior_amendment,'_launch_policy',lambda *args:e.policy)
        self.full=copy.deepcopy(old.full);self.full['qualification_id']=str(uuid.uuid4());self.full.update(campaign_amendment=current.PRIOR_AMENDMENT_REFERENCE,campaign_boundary=current.BOUNDARY_REFERENCE)
        self.state=copy.deepcopy(old.state);self.state['started_at']=self.prior['started_wall']
        self.ledger=copy.deepcopy(old.ledger);self.ledger.update(last_now=self.now-1,last_wall=self.wall-1)
        self.ids=[r['container_id'] for r in self.ledger['launches']]+[hashlib.sha256(('history15-'+str(i)).encode()).hexdigest() for i in range(105)]
        self.roots=old.roots;self.absent=old.absent
        self.cleanup=copy.deepcopy(old.cleanup);self.cleanup.update(qualification_id=self.full['qualification_id'],cumulative_container_launches=119,participant_segments=2,
            all_owned_container_ids=self.ids,all119_ids_absent=True,master014_copy_removed=True,planned_rows=392,
            raw_state=self.auth['prior_state'],frozen_native_manifest=self.auth['prior_manifest'],
            all_planned_raw_counts={'PASS':41,'BLOCKED':14,'NOT_RUN':337},current_matrix_raw_counts={'PASS':4,'BLOCKED':1,'NOT_RUN':23})
        self.boundary={'status':'PASS','unresolved_findings':[],'final_cleanup':self.auth['prior_cleanup'],
            'safe_for_final_handoff':True,'safe_to_continue':False,'qualification_eligible':False,'verified':{key:True for key in (
            'all119_IDs_2scripted_participants_zero_real_model_all_owned_hygiene_closed',
            '43released_fullbody_records_24known_actors_and5purged3priorabsent_roots_positive',
            'master4files_store_and_parent_removed_original_operator_store_untouched','two_retained_files_keyfree_and_bytepreserved',
            'failed001_diagnostic002_correctedcleanup002_and_original_native_rawfailure_preserved',
            'raw_poison_seven_private_false_rows_not_rewritten_or_repaired','392native_planned_rows41PASS14BLOCKED337NOTRUN_and_invalid023prep28separate')}}
        self.physical=copy.deepcopy(old.physical);self.physical.update(qualification_id=self.full['qualification_id'],cumulative_container_launches=119,participant_segments=2,
            all119_ids_absent=True,all_owned_container_ids=self.ids,private_cleanup_confirmed=False,container_registry_releases_performed=False)
        self.manual=copy.deepcopy(old.manual);self.manual.update(cumulative_container_launches=119,participant_segments=2,all119_ids_absent=True,
            all_owned_container_ids=self.ids,master014_cleanup_pending=True,credential_values_readonly_RAM=True,
            retained_evidence_schema_validated_inside_scanner=True,retained_evidence_keyfree_before_evidence_hashing=True)
        self.evidence=old.evidence;hashes={str(p.relative_to(self.evidence.parent)):hashlib.sha256(p.read_bytes()).hexdigest() for p in self.evidence.iterdir()}
        self.manual['retained_evidence_file_sha256']=hashes
        custody=e.objects[self.manual['manual_owner_custody']['path']];custody.update(qualification_id=self.full['qualification_id'],cumulative_container_launches=119,participant_segments=2,
            all_owned_container_ids=self.ids,retained_evidence_file_sha256=hashes)
        self.private_review=e.objects[self.cleanup['independent_private_review']['path']]
        self.private_review.update(private_cleanup=self.cleanup['service_helper_runtime_parent_cleanup'],physical_proof=self.cleanup['physical_cleanup'],
            private_cleanup_command=e.remember('private-command',{'status':'PASS'}),retained_evidence_sha256=hashes)
        self.cleanup['successful_private_cleanup_command']=self.private_review['private_cleanup_command']
        inputref={'path':str(e.prior_root.parent/'manual-cleanup-design/design-inputs-final-002.json'),'sha256':'a'*64}
        self.private_review['source_review']=e.remember('input-review15',{'status':'PASS','unresolved_findings':[],'design_inputs_sha256':'a'*64,'design_inputs':inputref})
        metadata={}
        for path in [self.evidence.parent,*self.evidence.parent.rglob('*')]:
            info=path.stat();metadata[str(path.relative_to(self.evidence.parent))]={'kind':'dir' if path.is_dir() else 'file','device':info.st_dev,'inode':info.st_ino,'mode':info.st_mode&0o777,'size':info.st_size}
        (self.evidence.parent/'outputs').mkdir(mode=0o700,exist_ok=True)
        info=(self.evidence.parent/'outputs').stat();metadata['outputs']={'kind':'dir','device':info.st_dev,'inode':info.st_ino,'mode':0o700,'size':info.st_size}
        self.inputs={'credential_or_bootstrap_values_opened_or_hashed':False,'retained_trusted_empty_evidence_schema_read_and_hashed':False,
            'master_excluded':self.full['secrets_dir'],'retained_evidence_metadata':metadata}
        e.objects[inputref['path']]=self.inputs
        helper=next(r for r in e.records if r.get('client_mode')=='application-execution')
        helper.setdefault('mounts',[]).append({'source':str(self.evidence.parents[1]),'target':'/pi-client/evidence','rw':True})
        helperrow=next(r for r in self.ledger['launches'] if r['role']=='application-helper');helperrow['intent_sha256']=launch._intent_identity(helper)
        self.network=old.network;self.extra=old.extra+[{'launch_id':str(uuid.uuid4()),'status':'released','daemon':'fixture-daemon'} for _ in range(15)]
        registry_root=Path.home()/'.local/state/pi-agentic-development/operation.lock.registry'
        records=e.records+[self.network]+self.extra
        references=[{'path':str(registry_root/(r['launch_id']+'.json')),'sha256':launch._digest(r)} for r in records]
        retained=[e.remember('retained-'+r['launch_id'],copy.deepcopy(r)) for r in records]
        for ref,r in zip(retained,records):ref['sha256']=launch._digest(r)
        self.terminal={'status':'PASS','qualification_id':self.full['qualification_id'],'cumulative_container_launches':119,'participant_segments':2,
            'all_owned_container_ids':self.ids,'current_ledger':self.auth['prior_ledger'],'current_state':self.auth['prior_state'],
            'private_proof':self.cleanup['service_helper_runtime_parent_cleanup'],'removed_private_roots':self.roots,
            'already_removed_private_roots':self.absent,'current_registry_records_verified':43,'credential_values_opened':False,
            'failed_key_reader_zero_leaf_reads_proven':False,'host_pids':list(range(100,124)),'current_registry_records':retained,
            'network_launch_ids':[self.network['launch_id']],**{k:True for k in ('all_root_readers_stopped','all_native_writers_absent',
            'all_service_writers_stopped','all_helper_writers_stopped','all_qualification_controllers_stopped','all_issued_capabilities_revoked',
            'owned_networks_removed','all_container_ids_absent','raw_preserved','retained_evidence_key_free','original_lease_held','controller_lock_held','lock_inodes_unchanged')}}
        self.cleanup['terminal_hygiene']=e.remember('terminal15',self.terminal)
        self.cleanup['terminal_hygiene_independent_review']=e.remember('terminal-review15',{'status':'PASS','unresolved_findings':[],'terminal_hygiene':self.cleanup['terminal_hygiene']})
        self.command=copy.deepcopy(old.command);observed=self.command['custody_before_action']
        observed.update(cumulative_container_launches=119,participant_segments=2,actual_container_id_count=119,current_registry_records=references,
            terminal_resource_hygiene=self.cleanup['terminal_hygiene'],writer_pid_absence=[{'pid':p,'absent':True} for p in self.terminal['host_pids']])
        e.objects[self.cleanup['master_cleanup']['path']]['independent_review']=self.cleanup['independent_actual_custody']
        self.cleanup['independent_actual_master_cleanup']=e.remember('master-review15',{'status':'PASS','unresolved_findings':[],
            'master_cleanup':self.cleanup['master_cleanup'],'store_and_parent_absent_at_review':True,'current43Registry_hashes_unchanged_since_preaction':True})
        for key,obj in (('prior_manifest',self.full),('prior_state',self.state),('prior_ledger',self.ledger),('prior_cleanup',self.cleanup),
            ('prior_independent_review',{'status':'PASS','unresolved_findings':[],'supports_ac80':True}),('prior_boundary_review',self.boundary)):
            e.objects[self.auth[key]['path']]=obj
        for ref,obj in ((self.cleanup['physical_cleanup'],self.physical),(self.cleanup['service_helper_runtime_parent_cleanup'],self.manual),(self.cleanup['master_cleanup_command'],self.command)):
            e.objects[ref['path']]=obj
        self.patch(current,'_reference',lambda ref:copy.deepcopy(e.objects[ref['path']]))
        self.patch(current,'_relative_reference',lambda ref:copy.deepcopy(e.objects[ref['path']]))
        original=launch._bound_json
        def bound(path,sha=None):
            found=[r for r in records if r['launch_id']==Path(path).stem]
            if not found:return original(path,sha)
            if sha is not None and launch._digest(found[0])!=sha:raise launch.LaunchError('qualification_state_invalid')
            return copy.deepcopy(found[0])
        self.patch(launch,'_bound_json',bound)
    def validate(self,**kwargs):return current.validate_amendment(self.reference,self.e.base,clock=lambda:self.now,wall=lambda:self.wall,**kwargs)
    def test_exact119_two_participants_392_rows_and14_origins(self):
        before=copy.deepcopy(self.prior);carry=self.validate()
        self.assertEqual((carry['attempts'],carry['participant_segments'],carry['planned_cells'],len(carry['lineage'])),(119,2,392,14))
        self.assertEqual(carry['startup_diagnostic'],before['startup_diagnostic']);self.assertEqual(self.prior,before)
        self.assertFalse(self.old.call_args.kwargs['window']);self.assertEqual(carry['effective_limits']['participant_segments'],26)
    def test_window_expiry_reporting_reserve_and_regression_refuse(self):
        for now,wall in ((current.DEADLINE_MONOTONIC-30,self.wall),(self.now,current.DEADLINE_WALL-30),(current.STARTED_MONOTONIC-1,self.wall),(self.now,current.STARTED_WALL-1)):
            with self.assertRaises(launch.LaunchError):current.validate_amendment(self.reference,self.e.base,clock=lambda:now,wall=lambda:wall)
        self.now=current.DEADLINE_MONOTONIC+1;self.wall=current.DEADLINE_WALL+1
        self.assertEqual(self.validate(window=False)['attempts'],119)
    def test_raw_poison_private_flags_or_participant_role_repair_refuse(self):
        for obj,key,value in ((self.ledger,'poisoned',False),(self.ledger['launches'][-1],'private_cleanup',True),(self.ledger['launches'][-2],'role','probe')):
            old=obj[key];obj[key]=value
            with self.assertRaises(launch.LaunchError):self.validate()
            obj[key]=old
    def test_prior_participant_or_origin_count_drift_refuse(self):
        self.prior['participant_segments']=2
        with self.assertRaises(launch.LaunchError):self.validate()
        self.prior['participant_segments']=1;self.prior['lineage'].append(self.prior['lineage'][0])
        with self.assertRaises(launch.LaunchError):self.validate()
    def test_foreign_network_or_excluded_registry_cleanup_pointer_drift_refuse(self):
        for record,key,value in ((self.network,'generation',str(uuid.uuid4())),(self.e.records[6],'qualification_service_cleanup',{'path':'/foreign','sha256':'f'*64}),(self.extra[0],'status','absent')):
            before=copy.deepcopy(record);record[key]=value
            with self.assertRaises(launch.LaunchError):self.validate()
            record.clear();record.update(before)
    def test_actual_temp_evidence_bytes_drift_or_symlink_refuse(self):
        path=self.evidence/'state.json';original=path.read_bytes();path.write_bytes(b'changed')
        with self.assertRaises(launch.LaunchError):self.validate()
        path.unlink();target=self.evidence.parent.parent/'other-evidence-copy';target.write_bytes(original);target.chmod(0o600);path.symlink_to(target)
        with self.assertRaises(OSError):self.validate()
    def test_missing_retained_evidence_proof_or_positive_worker_custody_refuse(self):
        for obj,key,value in ((self.manual,'retained_evidence_key_free',False),(self.manual,'retained_evidence_credential_match_count',1),(self.boundary['verified'],'two_retained_files_keyfree_and_bytepreserved',False)):
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
    def test_intermediate_and_final014_custody_are_distinct(self):
        for obj,key,bad in ((self.physical,'private_cleanup_confirmed',True),(self.manual,'master014_cleanup_pending',False),
            (self.terminal,'failed_key_reader_zero_leaf_reads_proven',True),(self.inputs,'credential_or_bootstrap_values_opened_or_hashed',True)):
            old=obj[key];obj[key]=bad
            with self.subTest(key=key),self.assertRaises(launch.LaunchError):self.validate()
            obj[key]=old
    def test_exact43_current_records_and24_stopped_actor_proofs_required(self):
        records=self.command['custody_before_action']['current_registry_records'];removed=records.pop()
        with self.assertRaises(launch.LaunchError):self.validate()
        records.append(removed)
        stops=self.command['custody_before_action']['writer_pid_absence'];stops[0]['absent']=False
        with self.assertRaises(launch.LaunchError):self.validate()
        stops[0]['absent']=True;self.terminal['host_pids'][-1]=self.terminal['host_pids'][0]
        with self.assertRaises(launch.LaunchError):self.validate()
    def test_recycled_historical_pid_is_never_probed_or_signaled(self):
        with mock.patch.object(current.os,'kill',side_effect=AssertionError('No historicalPID signal')):
            self.assertEqual(self.validate()['participant_segments'],2)
    def test_same_bytes_with_replaced_evidence_inode_refuses(self):
        path=self.evidence/'state.json';temporary=self.evidence/'replacement'
        temporary.write_bytes(path.read_bytes());temporary.chmod(0o600);temporary.replace(path)
        with self.assertRaises(launch.LaunchError):self.validate()
    def test_extra_retained_evidence_file_refuses_without_opening_unknown_leaf(self):
        path=self.evidence.parent/'outputs/unexpected';path.write_bytes(b'INERT_NOT_READ');path.chmod(0o600)
        original=current.os.open;opened=[]
        def observe(name,*args,**kwargs):
            opened.append(str(name));return original(name,*args,**kwargs)
        with mock.patch.object(current.os,'open',side_effect=observe),self.assertRaises(launch.LaunchError):self.validate()
        self.assertNotIn('unexpected',opened);self.assertEqual(path.read_bytes(),b'INERT_NOT_READ')
    def test_extra_retained_evidence_directory_refuses_without_traversal(self):
        path=self.evidence/'unexpected';path.mkdir(mode=0o700)
        original=current.os.open;opened=[]
        def observe(name,*args,**kwargs):
            opened.append(str(name));return original(name,*args,**kwargs)
        with mock.patch.object(current.os,'open',side_effect=observe),self.assertRaises(launch.LaunchError):self.validate()
        self.assertNotIn('unexpected',opened);self.assertTrue(path.is_dir())
    def test_missing_actual_master_review_or_reintroduced_key_root_refuses(self):
        proof=self.e.objects[self.cleanup['independent_actual_master_cleanup']['path']]
        proof['store_and_parent_absent_at_review']=False
        with self.assertRaises(launch.LaunchError):self.validate()
        proof['store_and_parent_absent_at_review']=True
        self.cleanup['all_owned_container_ids'].append(self.ids[0])
        with self.assertRaises(launch.LaunchError):self.validate()
    def test_current43_body_pin_uses_real_temp_files_and_rejects_excluded_pointer_drift(self):
        home=self.e.root/'inert-home';registry=home/'.local/state/pi-agentic-development/operation.lock.registry';registry.mkdir(mode=0o700,parents=True)
        for directory in registry.parents:
            if directory==self.e.root:break
            directory.chmod(0o700)
        references=self.command['custody_before_action']['current_registry_records']
        records=self.e.records+[self.network]+self.extra
        for ref in references:
            record=next(r for r in records if r['launch_id']==Path(ref['path']).stem)
            path=registry/(record['launch_id']+'.json');path.write_bytes(launch._json(record));path.chmod(0o600)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),ref['sha256']);ref['path']=str(path)
        with mock.patch.object(current.Path,'home',return_value=home),mock.patch.object(launch,'_bound_json',REAL_BOUND_JSON):
            self.assertEqual(self.validate()['attempts'],119)
            path=registry/(self.e.records[6]['launch_id']+'.json');body=json.loads(path.read_bytes())
            body['qualification_service_cleanup']={'path':'/inert/changed','sha256':'f'*64}
            path.write_bytes(launch._json(body));path.chmod(0o600)
            with self.assertRaises(launch.LaunchError):self.validate()

    def candidate(self):
        import test_application_requalification as fixtures
        saved=self.e.reference;self.e.reference=self.reference
        try:
            with mock.patch.object(fixtures,'current',current):return self.e.candidate()
        finally:self.e.reference=saved
    def test_final_candidate_and_launch_binding_share305_and26_policy(self):
        _,_,refs,policy=self.candidate()
        current.finalize_candidate(self.reference,*refs,clock=lambda:self.now,wall=lambda:self.wall)
        carry=self.validate();current.bind_final(self.e.final_root/'launch-ledger',policy,carry,create=True)
        current.bind_final(self.e.final_root/'launch-ledger',policy,carry)
        binding=json.loads((current.BINDING_ROOT/'launch-binding.json').read_bytes())
        self.assertEqual((binding['cumulative_attempts'],binding['participant_segments']),(119,2))
        with self.assertRaises((OSError,launch.LaunchError)):current.bind_final(self.e.final_root/'launch-ledger',policy,carry,create=True)
    def test_expanded_candidate_refuses_before_claim_or_binding(self):
        full,_,refs,_=self.candidate();full['limits']['participant_segments']=27
        with self.assertRaises(launch.LaunchError):current.finalize_candidate(self.reference,*refs,clock=lambda:self.now,wall=lambda:self.wall)
        self.assertFalse(current.BINDING_ROOT.exists())


class ParticipantCeilingTests(unittest.TestCase):
    def test_central_ledger_accepts24_current_plus2_prior_only_at_effective26(self):
        policy=manifest();policy['limits']={**launch.LIMITS,'container_launch_attempts':305,'participant_segments':26}
        verifier=object.__new__(launch.LaunchLedger);verifier.manifest=policy
        verifier.expected_daemon=verifier.expected_capacity=None;verifier._carry={'attempts':119,'participant_segments':2}
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
        verifier._carry['participant_segments']=3
        with self.assertRaises(launch.LaunchError):verifier._validate(state)
        verifier._carry['participant_segments']=2;policy['limits']['participant_segments']=25;state['manifest_sha256']=launch._digest(policy)
        with self.assertRaises(launch.LaunchError):verifier._validate(state)
    def test_effective26_admits_last_segment_and_refuses27(self):
        limits={**launch.LIMITS,'container_launch_attempts':305,'participant_segments':26}
        launch._hard_admission(attempts=304,live=0,segments=25,participant=True,now=10,deadline=100,limits=limits)
        with self.assertRaises(launch.LaunchError):launch._hard_admission(attempts=304,live=0,segments=26,participant=True,now=10,deadline=100,limits=limits)
        with self.assertRaises(launch.LaunchError):launch._hard_admission(attempts=305,live=0,segments=25,participant=True,now=10,deadline=100,limits=limits)
    def test_legacy_limits_remain24_and8_origins(self):
        self.assertEqual(launch.LIMITS['participant_segments'],24);self.assertEqual(launch.maximum_origins(),8)
        with self.assertRaises(launch.LaunchError):launch._hard_admission(attempts=100,live=0,segments=24,participant=True,now=10,deadline=100)


class QualifierProjectionTests(unittest.TestCase):
    def setUp(self):
        from test_application_qualification import QualificationTests,harness
        self.harness=harness
        self.carry_fixture=Matrix15Tests(methodName='runTest');self.carry_fixture.setUp();self.addCleanup(self.carry_fixture.doCleanups)
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
                self.assertEqual(carry['effective_limits']['participant_segments'],26)
        self.assertEqual(self.projection_clock_observations,[(self.projection_now,self.projection_wall)]*2)
    def freeze(self):
        return self.q.freeze(predecessor=self.carry_fixture.e.base,campaign_boundary=current.BOUNDARY_REFERENCE,campaign_amendment=self.reference)
    def test_real_qualifier_freeze_verify_candidate_and_permanent_bind_keep26(self):
        self.freeze();full,state=self.harness.verify(self.q.output)
        self.assertEqual(full['limits']['participant_segments'],26)
        self.assertEqual(full['limits']['container_launch_attempts'],305)
        self.assertEqual(sum(row['participant_segments_max'] for row in full['cells']),24)
        projected=self.harness._launch_manifest(full)
        self.assertEqual(projected['limits']['participant_segments'],26)
        self.assertEqual(projected['limits']['container_launch_attempts'],305)
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
        self.assertEqual((binding['cumulative_attempts'],binding['participant_segments']),(119,2))
        self.assertEqual(state['phase'],'frozen');self.assertFalse((self.q.output/'launch-ledger').exists())
    def test_projection25_mismatch_refuses_candidate_before_origin_claim(self):
        self.freeze();full,_=self.harness.verify(self.q.output)
        original=self.harness._launch_manifest
        def wrong(manifest):
            projection=original(manifest);projection['limits']['participant_segments']=25;return projection
        candidate={'archive_sha256':'e'*64,'runner_sha256':full['source']['runner'],'scope':'extracted_candidate'}
        with mock.patch.object(self.harness,'_launch_manifest',side_effect=wrong),self.assertRaises(launch.LaunchError):
            self.harness.bind_candidate(self.q.output,candidate)
        self.assertFalse((self.q.output/'candidate.json').exists());self.assertFalse(current.BINDING_ROOT.exists())
        self.assertFalse((current.PRIOR_ROOT.parent/'campaign-successor-claims').exists())
    def test_effective26_never_expands_the_declared_new_matrix24(self):
        self.freeze();full,_=self.harness.verify(self.q.output);projection=self.harness._launch_manifest(full)
        row=next(r for r in projection['cells'] if r['participant_segments_max'])
        row['participant_segments_max']=25
        with self.assertRaises(launch.LaunchError):launch.validate_manifest(projection)
        self.assertFalse((self.q.output/'candidate.json').exists());self.assertFalse(current.BINDING_ROOT.exists())
    def test_legacy_full_qualifier_still_freezes_and_projects24(self):
        self.q.freeze();full,_=self.harness.verify(self.q.output)
        self.assertEqual(full['limits']['participant_segments'],24)
        self.assertEqual(self.harness._launch_manifest(full)['limits']['participant_segments'],24)
        self.assertEqual(sum(row['participant_segments_max'] for row in full['cells']),24)


