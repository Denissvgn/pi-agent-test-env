"""Synthetic tenth-matrix authority, custody and durable launch accounting.

No actual qualification authority, lease, Docker, model or credential is used.
The existing q9 fixture supplies reviewed prior-boundary behavior; q10 validates
its own immutable eight-launch failed history and cleanup graph.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools/qualification'),str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_successor as successor
import application_amendment as amendment
import application_launch as launch
import test_application_amendment as old_tests


class SuccessorTests(unittest.TestCase):
    put=old_tests.AmendmentTests.put
    patch=old_tests.AmendmentTests.patch
    def setUp(self):
        old=old_tests.AmendmentTests(methodName='runTest');old.setUp();self.addCleanup(old.doCleanups);self.old=old
        self.root=old.root;self.prior_root=old.final;self.final=self.root/'tenth';self.final.mkdir(mode=0o700)
        self.now=[old.now[0]+20000.0];self.wallnow=[old.wallnow[0]+20000.0]
        self.clock=lambda:self.now[0];self.wall=lambda:self.wallnow[0]
        self.policy,self.prior_manifest_ref,_=old.finalize();self.prior_manifest=json.loads(Path(self.prior_manifest_ref['path']).read_text())
        self.carry=old.validate()
        self.ledger=launch.LaunchLedger.create(old.final/'launch-ledger',self.policy,daemon_id='fixture-daemon',daemon_capacity=old.prior['daemon_capacity'],clock=old.clock,wall=old.wall)
        for cell in self.policy['cells']:
            if cell['group']!='N01':continue
            for role,count in cell['role_limits'].items():
                for i in range(count):self.reserve(cell,role,clean=True)
        cell=next(c for c in self.policy['cells'] if c['group']=='N02');self.active={'id':cell['id'],'pid':123,'run_id':str(uuid.uuid4()),'attempt_id':str(uuid.uuid4())}
        for role in ('fixture','scripted-inference'):self.reserve(cell,role,clean=False)
        self.ledger.poison_scope(cell['id'])
        # Retain the observed failed raw row distinction, without repairing it.
        raw=json.loads((old.final/'launch-ledger/ledger.json').read_text());next(r for r in raw['launches'] if r['role']=='scripted-inference')['physical']='absent'
        self.raw=raw;self.ledgerref=self.put(old.final/'launch-ledger/ledger.json',raw)
        states={c['id']:{'status':'PASS','attempts':1,'evidence_level':'native_infrastructure'} for c in self.policy['cells'] if c['group']=='N01'}
        states[cell['id']]={'status':'BLOCKED','attempts':1,'run_id':self.active['run_id'],'attempt_id':self.active['attempt_id'],'private_cleanup':'unconfirmed'}
        self.state={'schema':1,'phase':'blocked','active_cell':self.active,'cells':states,'started_at':self.carry['started_wall']}
        self.stateref=self.put(old.final/'state.json',self.state)
        self.patch(amendment,'validate_amendment',mock.Mock(return_value=copy.deepcopy(self.carry)))
        authpath=self.root/'execution.json';folder=self.root/'tenth-binding';self.authpath=authpath
        for key,value in [('AUTHORIZATION_PATH',authpath),('AUTHORIZATION_ID','22222222-2222-4222-8222-222222222222'),('PRIOR_ROOT',old.final),('FINAL_ROOT',self.final),
                          ('BINDING_ROOT',folder),('BOUNDARY_REFERENCE',old.boundary),('PRIOR_AMENDMENT_REFERENCE',old.ref),('REPO',self.root),
                          ('STARTED_WALL',self.wallnow[0]-100),('STARTED_MONOTONIC',self.now[0]-100),('DEADLINE_WALL',self.wallnow[0]-100+14400),('DEADLINE_MONOTONIC',self.now[0]-100+14400)]:self.patch(successor,key,value)
        parent=self.put(self.root/'parent.json',{'actual_exit':2,'cwd':str(self.root),'argv':['python3','tools/qualification/application_client.py','collect','--root',str(old.final),'--group','N02','--release','0.87.1']})
        sr=[]
        for row in raw['launches']:
            if row['role'] not in ('fixture','scripted-inference'):continue
            sr.append(self.put(self.root/(row['role']+'-cleanup.json'),{**{k:row[k] for k in ('intent_sha256','container_id','launch_id','registry','generation','image','container','role','cell')},
                'document_type':'qualification_service_cleanup','physical_absence_confirmed':True,'private_bootstrap_removed':True,'qualification_eligible':False,'terminal_available':False,'daemon':'fixture-daemon'}))
        ids=[hashlib.sha256(('history'+str(i)).encode()).hexdigest() for i in range(55)]+[r['container_id'] for r in raw['launches']]
        self.terminal={'status':'PASS','cumulative_container_launches':63,'participant_segments':0,'all63_ids_absent':True,'parent_envelope_removed':True,'service_private_roots_removed':True,
            'all4_values_RAM_matched_and_scanned':True,'raw_history_unchanged':True,'raw_poison_unchanged':True,'raw_private_flags_unchanged':True,'controller_lock_held':True,'original_lease_held':True,
            'safe_to_continue':False,'original_operator_store_touched':False,'all_owned_container_ids':ids,'writer_pids_absent':[123],'parent_terminal':parent,'service_cleanup_receipts':sr}
        terminalref=self.put(self.root/'terminal.json',self.terminal)
        control=self.put(self.root/'master-auth.json',{'inert':True});observation=self.put(self.root/'master-observation.json',{'inert':True})
        review=self.put(self.root/'review.json',{'status':'PASS','unresolved_findings':[],'authorization':control,'observation':observation,'program_sha256':'a'*64})
        master=self.put(self.root/'master.json',{'status':'removed','store_removed':True,'temporary_parent_removed':True,'operator_original_store_selected':False,'values_opened':False,'value_hashes_computed':False,
            'removed_references':['PI_API_KEY','QUAL_APPLICATION_ALICE','QUAL_APPLICATION_BOB','QUAL_APPLICATION_SCRIPTED'],'independent_review':review,'authorization':control,'observation':observation,'program_sha256':'a'*64})
        self.cleanup={'status':'PASS','qualification_id':self.policy['qualification_id'],'safe_to_continue':False,'safe_for_final_handoff':True,'continued_execution_authorized':False,
            'cumulative_container_launches':63,'participant_segments':0,'live_owned_containers':0,'enforced_live_ceiling':4,'original_operator_store_touched':False,
            'physical_absence_confirmed':True,'private_cleanup_confirmed':True,'master009_copy_removed':True,'raw_history_poison_and_pending_flags_preserved':True,
            'service_and_parent_cleanup':terminalref,'master_cleanup':master,'independent_actual_custody':review}
        cleanupref=self.put(self.root/'cleanup.json',self.cleanup)
        self.matrix={'recorded_wall':successor.STARTED_WALL-100,'container_cap':249,'maximum_matrix_origins':10,'prior_matrix_origins':9,'cumulative_container_launches':63,'cumulative_participant_segments':0,'human_authorization':'SYNTHETIC ONLY'}
        self.window={'document_type':'qualification_window_authorization','window_seconds':14400,'original_deadline_wall':amendment.DEADLINE_WALL,
            'cumulative_container_launches':63,'cumulative_participant_segments':0,'container_cap':249,'participant_cap':24,'live_cap':4,'trial_cap':1,'inference_slot_cap':1,'platform':'linux/arm64',
            'automatic_retries':0,'continuations':0,'prior_campaign_modified':False,'new_native_admission_requires_positive_owned_cleanup':True,'authorization':'SYNTHETIC ONLY',
            'started_wall':successor.STARTED_WALL,'started_monotonic':successor.STARTED_MONOTONIC,'deadline_wall':successor.DEADLINE_WALL,'deadline_monotonic':successor.DEADLINE_MONOTONIC}
        self.matrix.update(prior_amendment=old.ref,original_boundary=old.boundary,prior_manifest=self.prior_manifest_ref,prior_state=self.stateref,prior_ledger=self.ledgerref,prior_cleanup=cleanupref,prior_independent_review=review,
            final_root=str(self.final),native_window_authorized=False,requires_separate_window_authorization=True,original_evidence_modified=False,additional_auxiliary_launches_authorized=0)
        matrixref=self.put(self.root/'matrix-authority.json',self.matrix);windowref=self.put(self.root/'window-authority.json',self.window)
        self.patch(successor,'MATRIX_AUTHORIZATION',matrixref);self.patch(successor,'WINDOW_AUTHORIZATION',windowref)
        self.auth={'schema':1,'document_type':'qualification_matrix_successor_authorization','authorization_id':successor.AUTHORIZATION_ID,'human_authorization':'SYNTHETIC ONLY',
            'recorded_wall':successor.STARTED_WALL,'final_root':str(self.final),'maximum_matrix_origins':10,'prior_matrix_origins':9,'cumulative_container_launches':63,'cumulative_participant_segments':0,
            'previous_container_cap':241,'container_cap':249,'participant_cap':24,'live_cap':4,'trial_cap':1,'inference_slot_cap':1,'platform':'linux/arm64','automatic_retries':0,'continuations':0,
            'planned_new_container_launches':186,'planned_new_participant_segments':24,'matrix_authorization':matrixref,'window_authorization':windowref,
            **{k:self.window[k] for k in ('started_wall','started_monotonic','deadline_wall','deadline_monotonic')},'prior_amendment':old.ref,'original_boundary':old.boundary,
            'prior_manifest':self.prior_manifest_ref,'prior_state':self.stateref,'prior_ledger':self.ledgerref,'prior_cleanup':cleanupref,'prior_independent_review':review,'prior_terminal_proof':terminalref,'prior_boundary_review':review,
            'original_evidence_modified':False,'window_reset':False,'additional_auxiliary_launches_authorized':0}
        self.refresh();self.before={str(p):p.read_bytes() for p in old.final.rglob('*') if p.is_file()}
    def reserve(self,cell,role,clean):
        record={**self.old.record,'launch_id':str(uuid.uuid4()),'container':'synthetic-'+uuid.uuid4().hex,'image':self.policy['images']['core-'+cell['release']]['id'] if role in launch.EXTERNAL else cell['image_id']}
        key=self.ledger.reserve(cell['id'],role,record,launch._role_weight(self.policy,cell,role),{'id':'fixture-daemon',**self.old.prior['daemon_capacity']})
        self.ledger.note(key,container_id=hashlib.sha256(record['launch_id'].encode()).hexdigest(),physical='absent' if clean else 'started',private_cleanup=clean)
    def refresh(self):
        # A disposable synthetic reauthorization lets each deeper custody guard
        # reject bad data independently of the outer immutable authority hash.
        for key in ('prior_amendment','original_boundary','prior_manifest','prior_state','prior_ledger','prior_cleanup','prior_independent_review'):
            self.matrix[key]=copy.deepcopy(self.auth[key])
        successor.MATRIX_AUTHORIZATION=self.put(self.root/'matrix-authority.json',self.matrix)
        self.auth['matrix_authorization']=copy.deepcopy(successor.MATRIX_AUTHORIZATION)
        self.ref=self.put(self.authpath,self.auth)
        if not hasattr(self,'hashpatch'):self.hashpatch=self.patch(successor,'AUTHORIZATION_SHA256',self.ref['sha256'])
        else:successor.AUTHORIZATION_SHA256=self.ref['sha256']
    def validate(self):return successor.validate_amendment(self.ref,self.old.predecessor,clock=self.clock,wall=self.wall)
    def finalize(self):
        p=copy.deepcopy(self.policy);p.update(qualification_id=str(uuid.uuid4()),campaign_amendment=self.ref,limits=successor.effective_limits(self.ref))
        full=copy.deepcopy(self.prior_manifest);full.update(qualification_id=p['qualification_id'],prepared_root=str(self.final),campaign_amendment=self.ref)
        full['limits']['container_launch_attempts']=249
        fullref=self.put(self.final/'manifest.json',full);candidate=self.put(self.final/'candidate.json',{'scope':'extracted_candidate','runner_sha256':'d'*64,'archive_sha256':'e'*64})
        successor.finalize_candidate(self.ref,fullref,candidate,clock=self.clock,wall=self.wall)
        return p,fullref,candidate
    def test_exact_composed_carry63_rows252_and_separate_window_preserve_history(self):
        carry=self.validate();self.assertEqual((carry['attempts'],carry['participant_segments'],carry['planned_cells'],len(carry['lineage'])),(63,0,252,9))
        self.assertEqual((carry['started'],carry['deadline']),(successor.STARTED_MONOTONIC,successor.DEADLINE_MONOTONIC))
        self.assertEqual(carry['previous_window']['deadline'],self.carry['deadline']);self.assertEqual(amendment.validate_amendment.call_args.kwargs['window'],False)
        self.assertEqual(self.before,{str(p):p.read_bytes() for p in self.old.final.rglob('*') if p.is_file()})
    def test_atomic249_reservations_keep24_participants_and_deny250(self):
        policy,_,_=self.finalize();ledger=launch.LaunchLedger.create(self.final/'launch-ledger',policy,daemon_id='fixture-daemon',daemon_capacity=self.old.prior['daemon_capacity'],clock=self.clock,wall=self.wall)
        daemon={'id':'fixture-daemon',**self.old.prior['daemon_capacity']}
        for cell in policy['cells']:
            for role,count in cell['role_limits'].items():
                for _ in range(count):
                    record={**self.old.record,'launch_id':str(uuid.uuid4()),'container':'inert-'+uuid.uuid4().hex,'image':policy['images']['core-'+cell['release']]['id'] if role in launch.EXTERNAL else cell['image_id']}
                    key=ledger.reserve(cell['id'],role,record,launch._role_weight(policy,cell,role),daemon);ledger.note(key,physical='absent',private_cleanup=True)
        self.assertEqual((ledger.snapshot()['attempts'],ledger.snapshot()['participant_segments'],ledger.snapshot()['live']),(249,24,0))
        with self.assertRaises(launch.LaunchError) as err:ledger.reserve(policy['cells'][0]['id'],'probe',self.old.record,self.old.row['resources'],daemon)
        self.assertEqual(err.exception.reason,'qualification_launch_limit');self.assertEqual(ledger.snapshot()['attempts'],249)
    def test_default240_and_q9_241_and_maximum_origins_unchanged(self):
        self.assertEqual(launch.LIMITS['container_launch_attempts'],240);self.assertEqual(launch.maximum_origins(),8)
        self.assertEqual(launch.maximum_origins(self.old.ref),9);self.assertEqual(amendment.effective_limits(self.old.ref)['container_launch_attempts'],241)
        self.assertEqual(launch.maximum_origins(self.ref),10);self.assertEqual(launch.amendment_module(self.ref),successor)
    def test_arbitrary_or_aliased_authority_rejected_before_effect(self):
        for ref in ({**self.ref,'sha256':'f'*64},{**self.ref,'path':str(self.root/'other.json')},{**self.ref,'path':str(self.authpath.parent)+'/./'+self.authpath.name}):
            with self.assertRaises(launch.LaunchError):launch.amendment_module(ref)
        self.assertFalse(successor.BINDING_ROOT.exists())
    def test_unclean_rehashed_cleanup_rejected(self):
        for key,value in [('physical_absence_confirmed',False),('private_cleanup_confirmed',False),('master009_copy_removed',False),('safe_to_continue',True),('original_operator_store_touched',True)]:
            changed={**self.cleanup,key:value};self.auth['prior_cleanup']=self.put(self.root/'cleanup.json',changed);self.refresh()
            with self.subTest(key=key),self.assertRaises(launch.LaunchError):self.validate()
    def test_changed_poison_or_pending_or_cid_or_role_rejected(self):
        for mutate in (lambda x:x.update(poisoned=False),lambda x:x['launches'][-1].update(private_cleanup=True),lambda x:x['launches'][-1].update(container_id=None),lambda x:x['launches'][-1].update(role='participant')):
            changed=copy.deepcopy(self.raw);mutate(changed);self.auth['prior_ledger']=self.put(self.prior_root/'launch-ledger/ledger.json',changed);self.refresh()
            with self.assertRaises(launch.LaunchError):self.validate()
    def test_duplicate_unknown_container_id_in_known_cleanup_rejected(self):
        for ids in (self.terminal['all_owned_container_ids'][:-1],[self.terminal['all_owned_container_ids'][0]]*63):
            changed={**self.terminal,'all_owned_container_ids':ids};self.auth['prior_terminal_proof']=self.put(self.root/'terminal.json',changed)
            cleanup={**self.cleanup,'service_and_parent_cleanup':self.auth['prior_terminal_proof']};self.auth['prior_cleanup']=self.put(self.root/'cleanup.json',cleanup);self.refresh()
            with self.assertRaises(launch.LaunchError):self.validate()
    def test_cap250_extra_origin_retry_and_implicit_window_reset_denied(self):
        original=copy.deepcopy(self.auth)
        for key,value in [('container_cap',250),('maximum_matrix_origins',11),('cumulative_container_launches',62),('cumulative_participant_segments',1),('window_reset',True),('automatic_retries',1),('additional_auxiliary_launches_authorized',1)]:
            self.auth={**original,key:value};self.refresh()
            with self.subTest(key=key),self.assertRaises(launch.LaunchError):self.validate()
    def test_stale_backwards_or_new_unpinned_window_denied(self):
        self.now[0]=successor.DEADLINE_MONOTONIC-30
        with self.assertRaises(launch.LaunchError):self.validate()
        self.now[0]=successor.STARTED_MONOTONIC-1
        with self.assertRaises(launch.LaunchError):self.validate()
        self.now[0]=successor.STARTED_MONOTONIC+1;self.auth['window_authorization']={**self.auth['window_authorization'],'sha256':'f'*64};self.refresh()
        with self.assertRaises(launch.LaunchError):self.validate()
    def test_root11_alias_duplicate_candidate_and_ancestor_id_denied(self):
        policy,full,candidate=self.finalize()
        for root in (self.root/'eleventh/launch-ledger',str(self.final)+'/./launch-ledger'):
            with self.assertRaises((OSError,launch.LaunchError)):launch.LaunchLedger.create(root,policy,daemon_id='fixture-daemon',daemon_capacity=self.old.prior['daemon_capacity'],clock=self.clock,wall=self.wall)
        with self.assertRaises((OSError,launch.LaunchError)):successor.finalize_candidate(self.ref,full,candidate,clock=self.clock,wall=self.wall)
        policy['qualification_id']=self.carry['lineage'][0]['qualification_id']
        with self.assertRaises(launch.LaunchError):launch.LaunchLedger.create(self.final/'launch-ledger',policy,daemon_id='fixture-daemon',daemon_capacity=self.old.prior['daemon_capacity'],clock=self.clock,wall=self.wall)
        self.assertFalse((self.final/'launch-ledger').exists())
    def test_drifted_prior_proof_hash_and_public_symlink_rejected(self):
        path=Path(self.auth['prior_independent_review']['path']);body=path.read_bytes();path.write_bytes(body+b' ')
        with self.assertRaises(launch.LaunchError):self.validate()
        path.write_bytes(body);path.chmod(0o666)
        with self.assertRaises(launch.LaunchError):self.validate()
    def test_claim_cannot_change_final_candidate_bytes(self):
        policy,_,candidate=self.finalize();Path(candidate['path']).write_text('{}')
        with self.assertRaises(launch.LaunchError):launch.LaunchLedger.create(self.final/'launch-ledger',policy,daemon_id='fixture-daemon',daemon_capacity=self.old.prior['daemon_capacity'],clock=self.clock,wall=self.wall)
        self.assertFalse((self.final/'launch-ledger').exists())


if __name__=='__main__':unittest.main()
