"""Synthetic matrix16 custody, permanent claims and unchanged hard ceilings.

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
import application_matrix16 as current
import application_launch as launch
REAL_BOUND_JSON = launch._bound_json
from test_application_launch import manifest
spec = importlib.util.spec_from_file_location('requalification_matrix_fixture',ROOT/'tools/qualification/application_client.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


def authority():
    return {'schema':1,'document_type':'qualification_matrix_requalification_authorization','authorization_id':current.AUTHORIZATION_ID,
        'human_authorization':'SYNTHETIC explicit matrix16/cap349/four hours','recorded_wall':current.STARTED_WALL,
        'final_root':str(current.FINAL_ROOT),'maximum_matrix_origins':16,'prior_matrix_origins':15,
        'cumulative_container_launches':163,'cumulative_participant_segments':6,'previous_container_cap':305,'container_cap':349,'previous_participant_cap':26,
        'participant_cap':30,'live_cap':4,'trial_cap':1,'inference_slot_cap':1,'platform':'linux/arm64','automatic_retries':0,'continuations':0,
        'planned_new_container_launches':186,'planned_new_participant_segments':24,'window_authorization':copy.deepcopy(current.WINDOW_AUTHORIZATION),
        'started_wall':current.STARTED_WALL,'started_monotonic':current.STARTED_MONOTONIC,
        'deadline_wall':current.DEADLINE_WALL,'deadline_monotonic':current.DEADLINE_MONOTONIC,
        'prior_amendment':copy.deepcopy(current.PRIOR_AMENDMENT_REFERENCE),'original_boundary':copy.deepcopy(current.BOUNDARY_REFERENCE),
        **{'prior_'+key:{'path':str(current.PRIOR_ROOT/relative),'sha256':str(index)*64}
            for index,(key,relative) in enumerate((('manifest','manifest.json'),('state','state.json'),('ledger','launch-ledger/ledger.json')),1)},
        **{key:{'path':'/synthetic/'+key+'.json','sha256':'a'*64} for key in ('prior_cleanup','prior_independent_review','prior_boundary_review')},
        'original_evidence_modified':False,'historical_windows_modified':False,'additional_auxiliary_launches_authorized':0,
        'additional_startup_diagnostic_authorized':False,'seventeenth_origin_authorized':False}


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
    def test_exact_matrix16_and_four_hour_limits(self):
        self.assertEqual(current.effective_limits(self.reference),{**launch.LIMITS,'container_launch_attempts':349,'participant_segments':30})
    def test_alias_changed_hash_or_unreviewed_authority_denied(self):
        for ref in ({**self.reference,'path':self.reference['path']+'/../matrix-012-authorization.json'},
            {**self.reference,'sha256':'f'*64},{**self.reference,'path':'/unreviewed/authority.json'}):
            with self.assertRaises(launch.LaunchError):current._authorization(ref)
    def test_cap_origin_diagnostic_retry_platform_and_root_expansion_denied(self):
        for key,bad in (('container_cap',350),('maximum_matrix_origins',17),('additional_startup_diagnostic_authorized',True),
            ('additional_auxiliary_launches_authorized',1),('automatic_retries',1),('continuations',1),('platform','linux/amd64'),
            ('participant_cap',31),('live_cap',5),('trial_cap',2),('inference_slot_cap',2),('final_root','/different-root')):
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
            ('deadline_wall',current.DEADLINE_WALL+1),('started_monotonic',current.STARTED_MONOTONIC+1),('container_cap',348)):
            old=self.window[key];self.window[key]=bad
            with self.assertRaises(launch.LaunchError):current._authorization(self.reference)
            self.window[key]=old
    def test_nonfinite_or_earlier_recording_denied(self):
        for bad in (float('nan'),float('inf'),current.STARTED_WALL-1,current.DEADLINE_WALL):
            self.value['recorded_wall']=bad
            with self.assertRaises(launch.LaunchError):current._authorization(self.reference)
    def test_exact_router16_preserves_default8_and_prior15(self):
        self.assertIs(launch.amendment_module(self.reference),current)
        self.assertEqual(launch.maximum_origins(self.reference),16);self.assertEqual(launch.maximum_origins(),8)
        oldref=current.PRIOR_AMENDMENT_REFERENCE
        with mock.patch.object(current.prior_amendment,'effective_limits',return_value={**launch.LIMITS,'container_launch_attempts':305,'participant_segments':26}):
            self.assertEqual(launch.maximum_origins(oldref),15)



class ParticipantCeilingTests(unittest.TestCase):
    def test_central_ledger_accepts24_current_plus6_prior_only_at_effective30(self):
        policy=manifest();policy['limits']={**launch.LIMITS,'container_launch_attempts':349,'participant_segments':30}
        verifier=object.__new__(launch.LaunchLedger);verifier.manifest=policy
        verifier.expected_daemon=verifier.expected_capacity=None;verifier._carry={'attempts':163,'participant_segments':6}
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
        verifier._carry['participant_segments']=7
        with self.assertRaises(launch.LaunchError):verifier._validate(state)
        verifier._carry['participant_segments']=6;policy['limits']['participant_segments']=29;state['manifest_sha256']=launch._digest(policy)
        with self.assertRaises(launch.LaunchError):verifier._validate(state)
    def test_effective30_admits_last_segment_and_refuses31(self):
        limits={**launch.LIMITS,'container_launch_attempts':349,'participant_segments':30}
        launch._hard_admission(attempts=348,live=0,segments=29,participant=True,now=10,deadline=100,limits=limits)
        with self.assertRaises(launch.LaunchError):launch._hard_admission(attempts=348,live=0,segments=30,participant=True,now=10,deadline=100,limits=limits)
        with self.assertRaises(launch.LaunchError):launch._hard_admission(attempts=349,live=0,segments=29,participant=True,now=10,deadline=100,limits=limits)
    def test_legacy_limits_remain24_and8_origins(self):
        self.assertEqual(launch.LIMITS['participant_segments'],24);self.assertEqual(launch.maximum_origins(),8)
        with self.assertRaises(launch.LaunchError):launch._hard_admission(attempts=100,live=0,segments=24,participant=True,now=10,deadline=100)


class QualifierProjectionTests(unittest.TestCase):
    def setUp(self):
        from test_application_qualification import QualificationTests,harness
        self.harness=harness
        from test_application_matrix15 import Matrix15Tests
        self.carry_fixture=Matrix15Tests(methodName='runTest');self.carry_fixture.setUp();self.addCleanup(self.carry_fixture.doCleanups)
        from types import SimpleNamespace
        self.carry=copy.deepcopy(self.carry_fixture.validate());self.carry.update(attempts=163,participant_segments=6,planned_cells=420,
            campaign_amendment={'path':str(current.AUTHORIZATION_PATH),'sha256':current.AUTHORIZATION_SHA256},effective_limits={**launch.LIMITS,'container_launch_attempts':349,'participant_segments':30})
        self.carry['qualification_id']=str(uuid.uuid4());self.carry['lineage'].append({'root':'/inert/matrix15','qualification_id':self.carry['qualification_id']})
        self.reference={'path':str(current.AUTHORIZATION_PATH),'sha256':current.AUTHORIZATION_SHA256}
        for name,value in [('PRIOR_ROOT',self.carry_fixture.e.root/'matrix15-prior'),('BINDING_ROOT',self.carry_fixture.e.root/'matrix16-bind'),
            ('_authorization',lambda ref:authority() if ref==self.reference else current.require(False)),
            ('validate_amendment',lambda *args,**kwargs:copy.deepcopy(self.carry))]:
            patch=mock.patch.object(current,name,value);patch.start();self.addCleanup(patch.stop)
        self.q=QualificationTests(methodName='runTest');self.q.setUp();self.addCleanup(self.q.doCleanups)
        patch=mock.patch.object(current,'FINAL_ROOT',self.q.output);patch.start();self.addCleanup(patch.stop)
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
                self.assertEqual(carry['effective_limits']['participant_segments'],30)
        self.assertEqual(self.projection_clock_observations,[(self.projection_now,self.projection_wall)]*2)
    def freeze(self):
        return self.q.freeze(predecessor=self.carry_fixture.e.base,campaign_boundary=current.BOUNDARY_REFERENCE,campaign_amendment=self.reference)
    def test_real_qualifier_freeze_verify_candidate_and_permanent_bind_keep30(self):
        self.freeze();full,state=self.harness.verify(self.q.output)
        self.assertEqual(full['limits']['participant_segments'],30)
        self.assertEqual(full['limits']['container_launch_attempts'],349)
        self.assertEqual(sum(row['participant_segments_max'] for row in full['cells']),24)
        projected=self.harness._launch_manifest(full)
        self.assertEqual(projected['limits']['participant_segments'],30)
        self.assertEqual(projected['limits']['container_launch_attempts'],349)
        launch.validate_manifest(projected)  # Production selector and exact limit validation, not mocked.
        candidate={'archive_sha256':'e'*64,'runner_sha256':full['source']['runner'],'scope':'extracted_candidate'}
        self.harness.bind_candidate(self.q.output,candidate)
        self.harness.verify(self.q.output,require_candidate=True)
        refs=[{'path':str(self.q.output/name),'sha256':hashlib.sha256((self.q.output/name).read_bytes()).hexdigest()} for name in ('manifest.json','candidate.json')]
        fixture=self.carry_fixture
        current.finalize_candidate(self.reference,*refs,clock=lambda:self.projection_now,wall=lambda:self.projection_wall)
        current.bind_final(self.q.output/'launch-ledger',projected,self.carry,create=True)
        current.bind_final(self.q.output/'launch-ledger',projected,self.carry)
        binding=json.loads((current.BINDING_ROOT/'launch-binding.json').read_bytes())
        self.assertEqual((binding['cumulative_attempts'],binding['participant_segments']),(163,6))
        self.assertEqual(state['phase'],'frozen');self.assertFalse((self.q.output/'launch-ledger').exists())
    def test_projection25_mismatch_refuses_candidate_before_origin_claim(self):
        self.freeze();full,_=self.harness.verify(self.q.output)
        original=self.harness._launch_manifest
        def wrong(manifest):
            projection=original(manifest);projection['limits']['participant_segments']=29;return projection
        candidate={'archive_sha256':'e'*64,'runner_sha256':full['source']['runner'],'scope':'extracted_candidate'}
        with mock.patch.object(self.harness,'_launch_manifest',side_effect=wrong),self.assertRaises(launch.LaunchError):
            self.harness.bind_candidate(self.q.output,candidate)
        self.assertFalse((self.q.output/'candidate.json').exists());self.assertFalse(current.BINDING_ROOT.exists())
        self.assertFalse((current.PRIOR_ROOT.parent/'campaign-successor-claims').exists())
    def test_effective30_never_expands_the_declared_new_matrix24(self):
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


class RetainedTreeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
        self.tree=self.root/'evidence';self.tree.mkdir(mode=0o700);(self.tree/'raw').mkdir(mode=0o700);(self.tree/'outputs').mkdir(mode=0o700)
        for name,value in (('.owner.lock',b''),('state.json',b'INERT_KEYFREE_FIXTURE')):
            p=self.tree/'raw'/name;p.write_bytes(value);p.chmod(0o600)
        self.metadata={}
        for p in (self.tree,*self.tree.rglob('*')):
            info=p.stat();self.metadata[str(p.relative_to(self.tree))]={'device':info.st_dev,'inode':info.st_ino,'size':info.st_size,'mode':info.st_mode&0o777,'kind':'dir' if p.is_dir() else 'file'}
        self.hashes={str(p.relative_to(self.tree)):hashlib.sha256(p.read_bytes()).hexdigest() for p in self.tree.rglob('*') if p.is_file()}
        patch=mock.patch.object(current,'PRIOR_ROOT',self.root);patch.start();self.addCleanup(patch.stop)
    def verify(self):return current._retained_tree(str(self.tree),self.metadata,self.hashes)
    def test_exact_known_tree_passes(self):self.verify()
    def test_extra_file_refuses_before_opening_unknown_leaf(self):
        extra=self.tree/'outputs/unknown';extra.write_bytes(b'NEVER_OPEN');extra.chmod(0o600);original=current.os.open;opened=[]
        def observe(name,*args,**kwargs):opened.append(str(name));return original(name,*args,**kwargs)
        with mock.patch.object(current.os,'open',side_effect=observe),self.assertRaises(launch.LaunchError):self.verify()
        self.assertNotIn('unknown',opened)
    def test_extra_directory_refuses_before_traversal(self):
        (self.tree/'raw/unknown').mkdir(mode=0o700);original=current.os.open;opened=[]
        def observe(name,*args,**kwargs):opened.append(str(name));return original(name,*args,**kwargs)
        with mock.patch.object(current.os,'open',side_effect=observe),self.assertRaises(launch.LaunchError):self.verify()
        self.assertNotIn('unknown',opened)
    def test_same_bytes_new_inode_refuses(self):
        p=self.tree/'raw/state.json';other=self.root/'replacement';other.write_bytes(p.read_bytes());other.chmod(0o600);other.replace(p)
        with self.assertRaises(launch.LaunchError):self.verify()
    def test_mutated_bytes_refuse(self):
        (self.tree/'raw/state.json').write_bytes(b'CHANGED')
        with self.assertRaises(launch.LaunchError):self.verify()
    def test_symlink_leaf_refuses(self):
        p=self.tree/'raw/state.json';p.unlink();p.symlink_to('/etc/passwd')
        with self.assertRaises((OSError,launch.LaunchError)):self.verify()
    def test_foreign_root_refuses(self):
        with mock.patch.object(current,'PRIOR_ROOT',self.root/'different'),self.assertRaises(launch.LaunchError):self.verify()

class ActorCustodyTests(unittest.TestCase):
    def setUp(self):
        self.pids=list(range(100,185));self.refs=[{'path':'/inert/proof-a','sha256':'a'*64},{'path':'/inert/proof-b','sha256':'b'*64}]
        self.actors=[{'pid':pid,'basis':'reviewed_owner_terminal_chain','evidence':self.refs[0 if i<80 else 1]} for i,pid in enumerate(self.pids)]
        self.proofs={r['path']:{'status':'PASS','positive_terminal_chain':True,'no_unconfirmed_owned_children':True,'covered_pids':self.pids[:80] if i==0 else self.pids[80:]} for i,r in enumerate(self.refs)}
        patch=mock.patch.object(current,'_reference',side_effect=lambda r:copy.deepcopy(self.proofs[r['path']]));patch.start();self.addCleanup(patch.stop)
    def test_exact_own_positive_evidence_passes(self):current._terminal_actors(self.pids,self.actors)
    def test_wrong_proof_still_globally_covered_refuses(self):
        self.actors[0]['evidence']=self.refs[1]
        with self.assertRaises(launch.LaunchError):current._terminal_actors(self.pids,self.actors)
    def test_wrong_basis_refuses(self):
        self.actors[0]['basis']='numeric_pid_absent'
        with self.assertRaises(launch.LaunchError):current._terminal_actors(self.pids,self.actors)
    def test_duplicate_or_unconfirmed_proof_refuses(self):
        self.proofs[self.refs[0]['path']]['covered_pids'].append(self.pids[0])
        with self.assertRaises(launch.LaunchError):current._terminal_actors(self.pids,self.actors)
