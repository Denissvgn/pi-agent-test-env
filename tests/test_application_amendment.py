"""Self-contained ninth-matrix fixtures; no native/lease/real authorization IO.

The already-reviewed boundary validator and old final binding are injected at
their interfaces. Actual ledger validation, amended claims/final binding and
durable reservation compose here on disposable files.
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
import application_amendment as amendment
import application_campaign as campaign
import application_launch as launch
import ownership_registry
from test_application_launch import manifest


class AmendmentTests(unittest.TestCase):
    def put(self,path,value,mode=0o600):
        path.parent.mkdir(parents=True,mode=0o700,exist_ok=True);path.write_bytes(launch._json(value));path.chmod(mode)
        return {'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    def patch(self,owner,name,value):
        patch=mock.patch.object(owner,name,value);result=patch.start();self.addCleanup(patch.stop);return result
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
        self.old=self.root/'eighth';self.final=self.root/'ninth';self.folder=self.root/'amendment';self.authpath=self.root/'authorization.json'
        self.old.mkdir(mode=0o700);self.final.mkdir(mode=0o700)
        self.patch(amendment,'AUTHORIZATION_ID','11111111-1111-4111-8111-111111111111')
        self.patch(amendment,'DEADLINE_WALL',1014400.0);self.patch(amendment,'DEADLINE_MONOTONIC',34400.0)
        self.patch(campaign,'AUTHORIZATION_PATH',self.root/'window.json');self.patch(campaign,'AUTHORIZATION_SHA256','e'*64)
        self.predecessor={'schema':1,'root':str(self.root/'seventh'),'manifest_sha256':'1'*64,'ledger_sha256':'2'*64,'state_sha256':'3'*64,
            'cleanup_receipts':[{'path':str(self.root/'seventh-proof.json'),'sha256':'4'*64}]}
        self.boundary={'path':str(self.root/'boundary.json'),'sha256':'a'*64}
        self.now=[amendment.DEADLINE_MONOTONIC-1000];self.wallnow=[amendment.DEADLINE_WALL-1000]
        self.clock=lambda:self.now[0];self.wall=lambda:self.wallnow[0]
        self.prior={'attempts':54,'participant_segments':0,'planned_cells':196,'qualification_id':str(uuid.uuid4()),'daemon':'fixture-daemon',
            'daemon_capacity':{'cpu_millis':64000,'memory_mib':65536},'started':amendment.DEADLINE_MONOTONIC-14400,'deadline':amendment.DEADLINE_MONOTONIC,
            'started_wall':amendment.DEADLINE_WALL-14400,'deadline_wall':amendment.DEADLINE_WALL,
            'lineage':[{'root':str(self.root/('history'+str(i))),'qualification_id':str(uuid.uuid4()),'manifest_sha256':'1'*64,'state_sha256':'2'*64,'ledger_sha256':'3'*64} for i in range(7)],
            'prior_rows':[{'qualification_id':'prior','cell':'cell'+str(i),'status':'NOT_RUN','attempts':0} for i in range(196)],
            'campaign_boundary':self.boundary,'base_attempts':51,'auxiliary_attempts':3,'original_window':{'started':0,'deadline':14400,'started_wall':0,'deadline_wall':14400}}
        self.patch(campaign,'validate_boundary',mock.Mock(return_value=copy.deepcopy(self.prior)))
        self.patch(campaign,'bind_final',mock.Mock())
        for name,value in [('AUTHORIZATION_PATH',self.authpath),('PRIOR_ROOT',self.old),('FINAL_ROOT',self.final),('BINDING_ROOT',self.folder),('BOUNDARY_REFERENCE',self.boundary)]:self.patch(amendment,name,value)
        p=manifest();p.update(predecessor=self.predecessor,campaign_boundary=self.boundary)
        spec=importlib.util.spec_from_file_location('amendment_matrix_fixture',ROOT/'tools/qualification/application_client.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        cells=module.matrix(p['images']);fields=('id','group','release','image_id','allowed_images','role_limits','container_launches_max','participant_segments_max')
        p['cells']=[{k:cell[k] for k in fields} for cell in cells];self.policy=p
        limits={k:v for k,v in launch.LIMITS.items() if k!='live'};limits.update(simultaneously_registered_live_container_intents=4,automatic_retries=0,continuations=0)
        full={'schema':1,'document_type':'application_client_qualification','prepared_root':str(self.old),'qualification_id':p['qualification_id'],
            'predecessor':self.predecessor,'campaign_boundary':self.boundary,'source':{'runner':'d'*64},'cells':cells,'images':p['images'],'limits':limits,'planned_container_launches':186}
        self.full=full;self.manifestref=self.put(self.old/'manifest.json',full)
        self.registry=ownership_registry.Registry(self.root/'registry');self.registry.bind_daemon('fixture-daemon')
        name='pi-lab-probe-inert';image=p['images']['core-0.87.1']['id']
        record,argv=self.registry.intent(['docker','run','--name',name,'--platform','linux/arm64','--cpus','1','--memory','1g','--memory-swap','1g','--pids-limit','256',image,'/opt/pi-lab/worker.py','probe'],name,runroot=self.old/'cells'/cells[0]['id'])
        self.record=record;self.cid='c'*64
        row={'key':launch._digest({'registry':record['registry'],'launch_id':record['launch_id']}),'cell':cells[0]['id'],'role':'probe','registry':record['registry'],
            'generation':record['generation'],'launch_id':record['launch_id'],'container':name,'image':image,'resources':{'cpu_millis':1000,'memory_mib':1024,'pids_limit':256},
            'physical':'absent','private_cleanup':False,'pid':123,'intent_sha256':launch._intent_identity(record),'container_id':self.cid,'cleanup_requests':[],
            'launch_policy':'explicit_pull_never_owned_id_5s'}
        self.row=row
        ledger={'schema':1,'manifest_sha256':launch._digest(p),'daemon':'fixture-daemon','daemon_capacity':self.prior['daemon_capacity'],
            **{key:self.prior[key] for key in ('started','deadline','started_wall','deadline_wall')},'last_now':self.now[0]-10,'last_wall':self.wallnow[0]-10,
            'poisoned':True,'launches':[row],'carry':{'descriptor_sha256':launch._digest(self.predecessor),**{k:self.prior[k] for k in ('attempts','participant_segments','qualification_id','planned_cells')}}}
        self.ledger=ledger;ledgerref=self.put(self.old/'launch-ledger/ledger.json',ledger)
        self.state={'schema':1,'phase':'blocked','active_cell':None,'cells':{cells[0]['id']:{'status':'BLOCKED','attempts':1}},'started_at':self.prior['started_wall']}
        stateref=self.put(self.old/'state.json',self.state)
        originalref=self.put(self.root/'original-record.json',{**record,'status':'absent'})
        releasedref=self.put(self.root/'released-record.json',{**record,'status':'released'})
        ids=[hashlib.sha256(str(i).encode()).hexdigest() for i in range(54)]+[self.cid]
        self.terminal={'schema':1,'status':'PASS','qualification_id':p['qualification_id'],'cumulative_container_launches':55,'cumulative_participant_segments':0,
            'current_launches':1,'historical_launches':51,'auxiliary_launches':3,'all_owned_ids_absent':True,'live_owned_containers':0,'daemon_id':'fixture-daemon',
            'current_registry_status':'released','raw_ledger_poison_preserved':True,'raw_ledger_private_cleanup_flag_preserved':False,'ledger':ledgerref,'state':stateref,
            'boundary':self.boundary,'all_owned_container_ids':ids,'released_record':releasedref,'original_record':originalref}
        terminalref=self.put(self.root/'terminal.json',self.terminal)
        master=self.put(self.root/'master.json',{'status':'removed','store_removed':True,'temporary_parent_removed':True,'operator_original_store_selected':False,'values_opened':False,'value_hashes_computed':False})
        review=self.put(self.root/'review.json',{'status':'PASS','unresolved_findings':[]})
        cleanup={'status':'PASS','qualification_id':p['qualification_id'],'safe_to_continue':False,'safe_for_final_handoff':True,'cumulative_container_launches':55,'participant_segments':0,
            'live_owned_containers':0,'enforced_live_ceiling':4,'continued_execution_authorized':False,'physical_absence_confirmed':True,'private_cleanup_confirmed':True,
            'all_issued_validating_processes_gone':True,'all_master_copy_readers_stopped':True,'master006_copy_removed':True,'raw_poison_and_matrix_preserved':True,
            'original_operator_store_touched':False,'terminal_observation':terminalref,'master_cleanup':master,'independent_actual_custody':review}
        cleanupref=self.put(self.root/'cleanup.json',cleanup,mode=0o644)
        self.auth={'schema':1,'document_type':'qualification_matrix_amendment_authorization','authorization_id':amendment.AUTHORIZATION_ID,'human_authorization':'INERT SYNTHETIC AUTHORITY; NO NATIVE PERMISSION',
            'recorded_wall':self.wallnow[0]-20,'final_root':str(self.final),'maximum_matrix_origins':9,'prior_matrix_origins':8,'cumulative_container_launches':55,
            'cumulative_participant_segments':0,'previous_container_cap':240,'container_cap':241,'participant_cap':24,'live_cap':4,'trial_cap':1,'inference_slot_cap':1,
            'platform':'linux/arm64','automatic_retries':0,'continuations':0,'planned_new_container_launches':186,'planned_new_participant_segments':24,
            'window_authorization':{'path':str(campaign.AUTHORIZATION_PATH),'sha256':campaign.AUTHORIZATION_SHA256},'deadline_wall':amendment.DEADLINE_WALL,
            'deadline_monotonic':amendment.DEADLINE_MONOTONIC,'original_boundary':self.boundary,'prior_manifest':self.manifestref,'prior_state':stateref,'prior_ledger':ledgerref,
            'prior_cleanup':cleanupref,'prior_terminal_proof':terminalref,'prior_independent_review':review,'original_evidence_modified':False,'window_reset':False,'additional_auxiliary_launches_authorized':0}
        self.refresh_auth()
        self.before={str(p):p.read_bytes() for p in self.old.rglob('*') if p.is_file()}
    def refresh_auth(self):
        self.ref=self.put(self.authpath,self.auth)
        if not hasattr(self,'_hash_patch'):self._hash_patch=self.patch(amendment,'AUTHORIZATION_SHA256',self.ref['sha256'])
        else:amendment.AUTHORIZATION_SHA256=self.ref['sha256']
    def validate(self):return amendment.validate_amendment(self.ref,self.predecessor,clock=self.clock,wall=self.wall)
    def finalize(self):
        policy=copy.deepcopy(self.policy);policy.update(qualification_id=str(uuid.uuid4()),campaign_amendment=self.ref,limits={**launch.LIMITS,'container_launch_attempts':241})
        full=copy.deepcopy(self.full);full.update(prepared_root=str(self.final),qualification_id=policy['qualification_id'],campaign_amendment=self.ref)
        full['limits']['container_launch_attempts']=241
        fullref=self.put(self.final/'manifest.json',full);candidate=self.put(self.final/'candidate.json',{'scope':'extracted_candidate','runner_sha256':'d'*64,'archive_sha256':'e'*64})
        amendment.finalize_candidate(self.ref,fullref,candidate,clock=self.clock,wall=self.wall)
        return policy,fullref,candidate
    def test_actual_composed_old_ledger_amendment_binding_create_and_reserve(self):
        carry=self.validate();self.assertEqual((carry['attempts'],carry['participant_segments'],carry['planned_cells'],len(carry['lineage'])),(55,0,224,8))
        self.assertEqual((carry['deadline'],carry['deadline_wall']),(self.prior['deadline'],self.prior['deadline_wall']))
        policy,_,_=self.finalize();ledger=launch.LaunchLedger.create(self.final/'launch-ledger',policy,daemon_id='fixture-daemon',daemon_capacity=self.prior['daemon_capacity'],clock=self.clock,wall=self.wall)
        snap=ledger.snapshot();self.assertEqual(snap['attempts'],55);self.assertEqual(snap['campaign_amendment']['container_launch_attempts'],241)
        key=ledger.reserve(policy['cells'][0]['id'],'probe',self.record,self.row['resources'],{'id':'fixture-daemon',**self.prior['daemon_capacity']})
        self.assertIsInstance(key,str);self.assertEqual(ledger.snapshot()['attempts'],56)
        self.assertEqual(self.before,{str(p):p.read_bytes() for p in self.old.rglob('*') if p.is_file()})
    def test_legacy_cap240_unchanged_and241_requires_exact_amendment(self):
        self.assertEqual(launch.LIMITS['container_launch_attempts'],240)
        value=manifest();value['limits']['container_launch_attempts']=241
        with self.assertRaises(launch.LaunchError):launch.validate_manifest(value)
        with self.assertRaises(launch.LaunchError):launch._hard_admission(attempts=240,live=0,segments=0,participant=False,now=0,deadline=100)
        launch._hard_admission(attempts=240,live=0,segments=0,participant=False,now=0,deadline=100,limits=amendment.effective_limits(self.ref))
        with self.assertRaises(launch.LaunchError):launch._hard_admission(attempts=241,live=0,segments=0,participant=False,now=0,deadline=100,limits=amendment.effective_limits(self.ref))
    def test_actual_central_reservations_stop_at241_and_keep_participant_limit24(self):
        policy,_,_=self.finalize();ledger=launch.LaunchLedger.create(self.final/'launch-ledger',policy,daemon_id='fixture-daemon',daemon_capacity=self.prior['daemon_capacity'],clock=self.clock,wall=self.wall)
        daemon={'id':'fixture-daemon',**self.prior['daemon_capacity']}
        # Synthetic accounting decisions only: no executor/container/Pi is used.
        for cell in policy['cells']:
            for role,count in cell['role_limits'].items():
                for _ in range(count):
                    record={**self.record,'launch_id':str(uuid.uuid4()),'container':'synthetic-'+uuid.uuid4().hex,
                        'image':policy['images']['core-'+cell['release']]['id'] if role in launch.EXTERNAL else cell['image_id']}
                    key=ledger.reserve(cell['id'],role,record,launch._role_weight(policy,cell,role),daemon)
                    ledger.note(key,physical='absent',private_cleanup=True)
        snapshot=ledger.snapshot();self.assertEqual((snapshot['attempts'],snapshot['participant_segments'],snapshot['live']),(241,24,0))
        with self.assertRaises(launch.LaunchError) as caught:ledger.reserve(policy['cells'][0]['id'],'probe',self.record,self.row['resources'],daemon)
        self.assertEqual(caught.exception.reason,'qualification_launch_limit');self.assertEqual(ledger.snapshot()['attempts'],241)
    def test_authority_hash_or_reference_change_rejected_without_claims(self):
        for value in ({**self.ref,'sha256':'f'*64},{**self.ref,'path':str(self.root/'other.json')}):
            with self.assertRaises(launch.LaunchError):amendment.validate_amendment(value,self.predecessor,clock=self.clock,wall=self.wall)
        self.assertFalse(self.folder.exists());self.assertFalse((self.old.parent/'campaign-successor-claims').exists())
    def test_authority_cannot_change_window_counters_caps_aux_or_origins(self):
        original=copy.deepcopy(self.auth)
        for key,value in [('deadline_wall',self.auth['deadline_wall']+1),('deadline_monotonic',self.auth['deadline_monotonic']+1),('container_cap',242),
                          ('live_cap',5),('participant_cap',25),('automatic_retries',1),('window_reset',True),('additional_auxiliary_launches_authorized',1),
                          ('cumulative_container_launches',54),('maximum_matrix_origins',10),('cumulative_participant_segments',1)]:
            with self.subTest(key=key):
                self.auth=copy.deepcopy(original);self.auth[key]=value;self.refresh_auth()
                with self.assertRaises(launch.LaunchError):self.validate()
        self.assertFalse(self.folder.exists())
    def test_expired_original_window_or_backwards_clock_denied(self):
        # Boundary validation owns the immutable original window check.
        campaign.validate_boundary.side_effect=launch.LaunchError('qualification_deadline')
        with self.assertRaises(launch.LaunchError):self.validate()
        campaign.validate_boundary.side_effect=None;self.wallnow[0]=self.auth['recorded_wall']-1
        with self.assertRaises(launch.LaunchError):self.validate()
    def test_raw_q8_changed_or_lifecycle_not_known_denies_even_rehashed_authority(self):
        original=copy.deepcopy(self.ledger)
        for mutate in (lambda v:v.update(poisoned=False),lambda v:v['launches'][0].update(physical='uncertain'),lambda v:v['launches'][0].update(private_cleanup=True),
                       lambda v:v['launches'][0].update(container_id=None),lambda v:v['launches'][0].update(role='participant')):
            changed=copy.deepcopy(original);mutate(changed);self.auth['prior_ledger']=self.put(self.old/'launch-ledger/ledger.json',changed);self.refresh_auth()
            with self.assertRaises(launch.LaunchError):self.validate()
    def test_cleanup_or_terminal_tamper_rejected_and_public_metadata_safety_retained(self):
        path=Path(self.auth['prior_cleanup']['path']);before=path.read_bytes();path.write_bytes(before+b' ')
        with self.assertRaises(launch.LaunchError):self.validate()
        path.write_bytes(before);path.chmod(0o666)
        with self.assertRaises(launch.LaunchError):self.validate()
    def test_public_metadata_reader_rejects_duplicate_nonfinite_and_exponent_overflow(self):
        path=self.root/'malformed-public.json'
        for body in (b'{"outer":{"key":1,"key":2}}',b'{"value":NaN}',b'{"value":Infinity}',b'{"value":1e9999}'):
            with self.subTest(body=body):
                path.write_bytes(body);path.chmod(0o644)
                reference={'path':str(path),'sha256':hashlib.sha256(body).hexdigest()}
                with self.assertRaises(launch.LaunchError):amendment._reference(reference)
    def test_root10_alias_duplicate_authorization_and_candidate_rebind_denied(self):
        policy,fullref,candidate=self.finalize()
        for root in (self.root/'tenth/launch-ledger',str(self.final)+'/./launch-ledger'):
            with self.assertRaises((OSError,launch.LaunchError)):launch.LaunchLedger.create(root,policy,daemon_id='fixture-daemon',daemon_capacity=self.prior['daemon_capacity'],clock=self.clock,wall=self.wall)
        with self.assertRaises((OSError,launch.LaunchError)):amendment.finalize_candidate(self.ref,fullref,candidate,clock=self.clock,wall=self.wall)
        ledger=launch.LaunchLedger.create(self.final/'launch-ledger',policy,daemon_id='fixture-daemon',daemon_capacity=self.prior['daemon_capacity'],clock=self.clock,wall=self.wall)
        with self.assertRaises((OSError,launch.LaunchError)):launch.LaunchLedger.create(self.final/'launch-ledger',policy,daemon_id='fixture-daemon',daemon_capacity=self.prior['daemon_capacity'],clock=self.clock,wall=self.wall)
        self.assertEqual(ledger.snapshot()['attempts'],55)
    def test_different_final_dispatch_policy_or_changed_candidate_fails_before_ledger(self):
        policy,_,candidate=self.finalize();policy['cells'][0]['image_id']=policy['images']['browser-0.87.1']['id']
        with self.assertRaises(launch.LaunchError):launch.LaunchLedger.create(self.final/'launch-ledger',policy,daemon_id='fixture-daemon',daemon_capacity=self.prior['daemon_capacity'],clock=self.clock,wall=self.wall)
        self.assertFalse((self.final/'launch-ledger').exists())
    def test_full_current_manifest_cannot_reuse_ancestor_id_or_claim_tenth(self):
        carry=self.validate();policy=copy.deepcopy(self.policy);policy.update(campaign_amendment=self.ref,limits=amendment.effective_limits(self.ref))
        policy['qualification_id']=carry['lineage'][0]['qualification_id']
        with self.assertRaises(launch.LaunchError):launch.LaunchLedger.create(self.final/'launch-ledger',policy,daemon_id='fixture-daemon',daemon_capacity=self.prior['daemon_capacity'],clock=self.clock,wall=self.wall)
        self.assertFalse((self.final/'launch-ledger').exists())


if __name__=='__main__':unittest.main()
