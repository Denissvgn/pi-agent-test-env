"""Boundary tests use disposable files/Registry and synthetic trusted base facts.

The existing predecessor validator has independent full-history coverage. Here
its result is injected at that interface; no original lease/key/Docker is used.
"""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools/qualification'),str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_campaign as campaign
import application_launch as launch
import ownership_registry
from test_application_launch import manifest

AUTHORIZATION_FIXTURE={'schema': 1, 'document_type': 'qualification_window_authorization', 'authorization_id': '11111111-1111-4111-8111-111111111111', 'authorization': 'INERT TEST FIXTURE. This synthetic document grants no native authority.', 'original_deadline_wall': 1000800, 'started_wall': 1000000, 'started_monotonic': 20000, 'deadline_wall': 1014400, 'deadline_monotonic': 34400, 'window_seconds': 14400, 'cumulative_container_launches': 51, 'cumulative_participant_segments': 0, 'container_cap': 240, 'participant_cap': 24, 'live_cap': 4, 'trial_cap': 1, 'inference_slot_cap': 1, 'platform': 'linux/arm64', 'automatic_retries': 0, 'continuations': 0, 'prior_campaign_modified': False, 'new_native_admission_requires_positive_owned_cleanup': True, 'created_utc': '1970-01-12T13:46:40+00:00', 'deadline_utc': '1970-01-12T17:46:40+00:00', 'deadline_madrid': 'synthetic-fixture-only'}


class CampaignBoundaryTests(unittest.TestCase):
    def put(self,path,value):
        path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.write_bytes(launch._json(value));path.chmod(0o600);return campaign.ref(path)
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve();self.aux=self.root/'auxiliary';self.final=self.root/'final'
        self.old=self.root/'seventh';self.old.mkdir(mode=0o700);self.auth=copy.deepcopy(AUTHORIZATION_FIXTURE)
        auth_path=self.root/'authorization.json';auth_path.write_text(json.dumps(self.auth,indent=2)+'\n');auth_path.chmod(0o600)
        auth_hash=hashlib.sha256(auth_path.read_bytes()).hexdigest()
        for name,value in [('AUTHORIZATION_PATH',auth_path),('AUTHORIZATION_SHA256',auth_hash),('AUTHORIZATION_ID',self.auth['authorization_id'])]:
            patcher=mock.patch.object(campaign,name,value);patcher.start();self.addCleanup(patcher.stop)
        self.code_bodies={name:('harmless frozen code fixture '+name+'\n').encode() for name in campaign.CODE_FILES}
        self.input_bodies={name:('harmless frozen input fixture '+name+'\n').encode() for name in campaign.INPUT_FILES}
        self.code_hashes={name:hashlib.sha256(body).hexdigest() for name,body in self.code_bodies.items()}
        self.input_hashes={name:hashlib.sha256(body).hexdigest() for name,body in self.input_bodies.items()}
        for name,value in [('APPROVED_CODE_REVISIONS',(self.code_hashes,)),('APPROVED_INPUT_REVISIONS',(self.input_hashes,)),('APPROVED_PUBLISHED_INPUT_REVISIONS',(self.input_hashes,))]:
            patcher=mock.patch.object(campaign,name,value);patcher.start();self.addCleanup(patcher.stop)
        self.now=[self.auth['started_monotonic']+100];self.wallnow=[self.auth['started_wall']+100];self.clock=lambda:self.now[0];self.wall=lambda:self.wallnow[0]
        self.lock=self.root/'operation.lock';self.lock.write_bytes(b'');self.lock.chmod(0o600);self.fd=os.open(self.lock,os.O_RDWR);fcntl.flock(self.fd,fcntl.LOCK_EX)
        self.addCleanup(os.close,self.fd);self.put(self.old/'manifest.json',{'host_admission':{'lock_file':str(self.lock),'wait_seconds':30}})
        proof=self.put(self.old/'cleanup.json',{'document_type':'qualification_known_preworker_cleanup'})
        self.predecessor={'schema':1,'root':str(self.old),'manifest_sha256':campaign.ref(self.old/'manifest.json')['sha256'],'state_sha256':'b'*64,'ledger_sha256':'c'*64,'cleanup_receipts':[proof]}
        base_ref=self.put(self.root/'base-predecessor.json',self.predecessor)
        deadline=self.auth['started_monotonic']+self.auth['original_deadline_wall']-self.auth['started_wall']
        self.base={'attempts':51,'participant_segments':0,'planned_cells':196,'qualification_id':str(uuid.uuid4()),'daemon':'fixture-daemon',
            'daemon_capacity':{'cpu_millis':8000,'memory_mib':8000},'started':deadline-14400,'deadline':deadline,
            'started_wall':self.auth['original_deadline_wall']-14400,'deadline_wall':self.auth['original_deadline_wall'],
            'lineage':[{'root':str(self.root/('history-'+str(i))),'qualification_id':str(uuid.uuid4())} for i in range(7)],'prior_rows':[{'row':i} for i in range(196)]}
        for key,value in [('AUXILIARY_ROOT',self.aux),('FINAL_ROOT',self.final),('BASE_PREDECESSOR_REFERENCE',base_ref)]:
            patcher=mock.patch.object(campaign,key,value);patcher.start();self.addCleanup(patcher.stop)
        patcher=mock.patch.object(launch,'validate_predecessor',return_value=copy.deepcopy(self.base));self.validate_mock=patcher.start();self.addCleanup(patcher.stop)
        self.authorization={'path':str(campaign.AUTHORIZATION_PATH),'sha256':campaign.AUTHORIZATION_SHA256}
        self.registry=ownership_registry.Registry(Path(str(self.lock)+'.registry'));self.registry.bind_daemon('fixture-daemon')
        self.daemon={'id':'fixture-daemon','cpu_millis':8000,'memory_mib':8000,'image_id':campaign.IMAGE,'architecture':'arm64','os':'linux'}
    def create(self):
        return campaign.AuxiliaryCampaign.create(self.aux,base_predecessor=self.predecessor,authorization_ref=self.authorization,final_root=self.final,clock=self.clock,wall=self.wall)
    def recipe(self,owner,case_id=1,*,freeze=True):
        case=self.aux/'cases'/str(case_id);case.mkdir(mode=0o700)
        for name in ('code','inputs','state','evidence'):(case/name).mkdir(mode=0o700)
        for relative in campaign.CODE_FILES:
            target=case/'code'/relative;target.parent.mkdir(mode=0o700,exist_ok=True);target.write_bytes(self.code_bodies[relative]);target.chmod(0o400)
        for relative in campaign.INPUT_FILES:
            target=case/'inputs'/relative;target.write_bytes(self.input_bodies[relative]);target.chmod(0o400)
        identities={name:{'device':(case/name).stat().st_dev,'inode':(case/name).stat().st_ino} for name in ('state','evidence')}
        recipe={'schema':1,'case_id':case_id,'program_sha256':campaign.APPROVED_INPUT_REVISIONS[0]['guest.py'],
            'code_files':campaign._tree(case/'code',campaign.CODE_FILES),'input_files':campaign._tree(case/'inputs',campaign.INPUT_FILES),'image_id':campaign.IMAGE,'platform':'linux/arm64',
            'uid':'501:20','resources':copy.deepcopy(campaign.RESOURCES),'timeout_seconds':60,'mounts':[{'source':str(case/name),'target':target,'rw':rw} for name,target,rw in campaign.TARGETS],
            'writable_identities':identities}
        if case_id==3:
            children={}
            for name in ('state','evidence'):
                child=case/name/'private';child.mkdir(mode=0o700);info=child.stat();children[name]={'device':info.st_dev,'inode':info.st_ino}
            recipe.update(schema=2,transport='host-loopback-published',private_children=children)
        if freeze:owner.freeze_recipe(case_id,recipe,lease_fd=self.fd)
        return recipe
    def reserve(self,owner,case_id=1):
        recipe=self.recipe(owner,case_id);record,argv=owner.create_intent(case_id,self.registry,lease_fd=self.fd,name='diagnostic-'+str(case_id))
        key=owner.reserve(case_id,record,argv,self.daemon,lease_fd=self.fd);return key,record,argv,recipe
    def cleaned(self,owner,key,record,recipe,*,exit_code=2,timed_out=False):
        cid=hashlib.sha256(key.encode()).hexdigest();owner.note(key,pid=123,container_id=cid,physical='started')
        record.update(container_id=cid,status='absent');self.registry.write(record)
        roots={}
        for name in ('state','evidence'):
            path=self.aux/'cases'/str(recipe['case_id'])/name;roots[name]={'path':str(path),**recipe['writable_identities'][name],'removed':True}
            if (path/'private').exists():(path/'private').rmdir()
            path.rmdir()
        self.registry.release(record,True)
        terminal=self.put(self.aux/'cases'/str(recipe['case_id'])/'terminal.json',{'schema':1,'launch_id':key,'container_id':cid,'exit_code':exit_code,'exit_code_source':'docker_cli_returncode','timed_out':timed_out,'writers_stopped':True})
        receipt=self.put(self.aux/'cases'/str(recipe['case_id'])/'cleanup.json',{'schema':1,'document_type':'qualification_auxiliary_cleanup','authorization_id':campaign.AUTHORIZATION_ID,
            'binding_sha256':campaign.digest(owner.binding),'case_id':recipe['case_id'],'launch_id':key,'registry':record['registry'],'generation':record['generation'],'container_id':cid,
            'intent_sha256':launch._intent_identity(record),'daemon':'fixture-daemon','physical_absence_confirmed':True,'private_cleanup_confirmed':True,'writable_roots':roots,'terminal':terminal})
        owner.confirm_cleanup(key,receipt,lease_fd=self.fd);return receipt
    def seal(self,owner):return owner.seal(self.aux/'boundary.json',lease_fd=self.fd)
    def finalize(self,boundary):
        self.final.mkdir(mode=0o700);policy=manifest();policy.update(predecessor=copy.deepcopy(self.predecessor),campaign_boundary=boundary)
        limits={key:value for key,value in launch.LIMITS.items() if key!='live'};limits.update(simultaneously_registered_live_container_intents=4,automatic_retries=0,continuations=0)
        full=self.put(self.final/'manifest.json',{'document_type':'application_client_qualification','prepared_root':str(self.final),'qualification_id':policy['qualification_id'],
            'predecessor':self.predecessor,'campaign_boundary':boundary,'source':{'runner':'d'*64},'images':policy['images'],'cells':policy['cells'],'limits':limits,'planned_container_launches':186})
        candidate=self.put(self.final/'candidate.json',{'scope':'extracted_candidate','runner_sha256':'d'*64,'archive_sha256':'e'*64})
        campaign.finalize_candidate(boundary,full,candidate,clock=self.clock,wall=self.wall);return policy
    def test_zero_diagnostics_explicit_new_window_old_history_retained_final_bound_once(self):
        owner=self.create();boundary=self.seal(owner);before=(self.aux/'ledger.json').read_bytes();owner.snapshot();self.assertEqual((self.aux/'ledger.json').read_bytes(),before)
        carry=campaign.validate_boundary(boundary,self.predecessor,clock=self.clock,wall=self.wall)
        self.assertEqual((carry['attempts'],carry['participant_segments'],carry['planned_cells'],len(carry['lineage'])),(51,0,196,7))
        self.assertEqual(carry['deadline_wall'],self.auth['deadline_wall']);self.assertEqual(carry['original_window']['deadline_wall'],self.base['deadline_wall'])
        policy=self.finalize(boundary);ledger=launch.LaunchLedger.create(self.final/'launch-ledger',policy,daemon_id='fixture-daemon',daemon_capacity=self.base['daemon_capacity'],clock=self.clock,wall=self.wall)
        self.assertEqual(ledger.snapshot()['attempts'],51);self.assertEqual(json.loads((ledger.root/'ledger.json').read_bytes())['deadline_wall'],self.auth['deadline_wall'])
        other=copy.deepcopy(policy);other['qualification_id']=str(uuid.uuid4())
        with self.assertRaises((OSError,launch.LaunchError)):launch.LaunchLedger.create(self.final/'another-ledger',other,daemon_id='fixture-daemon',daemon_capacity=self.base['daemon_capacity'],clock=self.clock,wall=self.wall)
    def test_three_charged_diagnostics_total54_plus186_equals240_and_fourth_denied(self):
        owner=self.create()
        for case_id in (1,2,3):
            key,record,argv,recipe=self.reserve(owner,case_id);self.assertEqual(len(owner.snapshot()['launches']),case_id);self.cleaned(owner,key,record,recipe,exit_code=-15 if case_id==3 else 2,timed_out=case_id==3)
        boundary=self.seal(owner);carry=campaign.validate_boundary(boundary,self.predecessor,clock=self.clock,wall=self.wall)
        self.assertEqual(carry['attempts'],54);self.assertEqual(carry['attempts']+186,240)
        with self.assertRaises(launch.LaunchError):owner.create_intent(4,self.registry,lease_fd=self.fd,name='fourth')
    def test_durable_charge_before_executor_and_unknown_spawn_poison_retained(self):
        owner=self.create();recipe=self.recipe(owner);record,argv=owner.create_intent(1,self.registry,lease_fd=self.fd,name='diagnostic-one');calls=[]
        def failure(actual):
            self.assertEqual(actual,argv);self.assertEqual(len(owner.snapshot()['launches']),1);calls.append(True);raise RuntimeError('controlled spawn failure')
        with self.assertRaises(RuntimeError):owner.dispatch(1,record,argv,self.daemon,lease_fd=self.fd,popen=failure)
        self.assertEqual(calls,[True]);state=owner.snapshot();self.assertTrue(state['poisoned']);self.assertEqual(len(state['launches']),1)
        with self.assertRaises(launch.LaunchError):self.seal(owner)
    def test_original_legacy_slot_and_authorization_fenced_before_any_auxiliary(self):
        owner=self.create();folder,name=campaign._claim_names(self.predecessor,self.base);self.assertTrue((folder/(name+'.lock')).exists())
        with self.assertRaises(OSError):self.create()
        legacy=manifest();legacy['predecessor']=self.predecessor
        with self.assertRaises(launch.LaunchError):launch._successor_claim(self.final/'launch-ledger',legacy,self.base,create=True)
        self.assertEqual(owner.snapshot()['launches'],[])
    def test_approved_authorization_only_no_minted_clock_or_counter_reset(self):
        for change in (lambda a:a.update(sha256='f'*64),lambda a:a.update(path=str(self.root/'made-up.json'))):
            auth=copy.deepcopy(self.authorization);change(auth)
            with self.assertRaises(launch.LaunchError):campaign.AuxiliaryCampaign.create(self.aux,base_predecessor=self.predecessor,authorization_ref=auth,final_root=self.final,clock=self.clock,wall=self.wall)
        self.now[0]=self.auth['deadline_monotonic']-29
        with self.assertRaises(launch.LaunchError):self.create()
        self.assertFalse(self.aux.exists())
    def test_other_lock_holder_is_not_caller_custody(self):
        owner=self.create();other=os.open(self.lock,os.O_RDWR)
        try:
            with self.assertRaises(launch.LaunchError):campaign._lease(other,owner.binding)
        finally:os.close(other)
        campaign._lease(self.fd,owner.binding)
    def test_pending_or_uncertain_cleanup_blocks_next_and_seal(self):
        owner=self.create();key,record,argv,recipe=self.reserve(owner)
        with self.assertRaises(launch.LaunchError):self.seal(owner)
        owner.note(key,physical='uncertain',poison=True)
        with self.assertRaises(launch.LaunchError):self.seal(owner)
        self.assertFalse((self.aux/'boundary.json').exists())
    def test_wrong_argv_network_real_store_mount_swap_image_uid_and_resource_reject(self):
        owner=self.create();recipe=self.recipe(owner);record,argv=owner.create_intent(1,self.registry,lease_fd=self.fd,name='diagnostic-one')
        for changed in (argv+['extra'],['changed' if x=='none' else x for x in argv],['2g' if x=='512m' else x for x in argv]):
            with self.assertRaises(launch.LaunchError):owner.reserve(1,record,changed,self.daemon,lease_fd=self.fd)
        for key,value in [('architecture','amd64'),('image_id','sha256:'+'f'*64),('id','another')]:
            daemon=copy.deepcopy(self.daemon);daemon[key]=value
            with self.assertRaises(launch.LaunchError):owner.reserve(1,record,argv,daemon,lease_fd=self.fd)
        self.assertEqual(owner.snapshot()['launches'],[])
        for key,value in [('uid','0:0'),('platform','linux/amd64'),('timeout_seconds',61),('resources',{**campaign.RESOURCES,'pids_limit':129})]:
            changed=copy.deepcopy(recipe);changed[key]=value
            with self.assertRaises(launch.LaunchError):campaign._recipe(owner.binding,changed)
        changed=copy.deepcopy(recipe);changed['mounts'][0]['source']='/operator/store'
        with self.assertRaises(launch.LaunchError):campaign._recipe(owner.binding,changed)
    def test_cleanup_recreated_private_or_nonreleased_registry_blocks(self):
        owner=self.create();key,record,argv,recipe=self.reserve(owner);receipt=self.cleaned(owner,key,record,recipe)
        path=self.aux/'cases/1/state';path.mkdir(mode=0o700)
        with self.assertRaises(launch.LaunchError):self.seal(owner)
        path.rmdir();record['status']='absent';self.registry.write(record)
        with self.assertRaises(launch.LaunchError):self.seal(owner)
    def test_sealed_boundary_ref_tamper_and_new_intent_or_new_recipe_deny(self):
        owner=self.create();self.recipe(owner);boundary=self.seal(owner)
        with self.assertRaises(launch.LaunchError):owner.create_intent(1,self.registry,lease_fd=self.fd,name='after-seal')
        self.assertEqual(self.registry.load(),[])
        path=self.aux/'ledger.json';path.write_bytes(path.read_bytes()+b' ')
        with self.assertRaises(launch.LaunchError):campaign.validate_boundary(boundary,self.predecessor,clock=self.clock,wall=self.wall)
    def test_arbitrary_program_binding_or_recipe_slot_cannot_be_registered(self):
        owner=self.create();recipe=self.recipe(owner)
        changed=copy.deepcopy(recipe);changed['input_files']['guest.py']='f'*64;changed['program_sha256']='f'*64
        with self.assertRaises(launch.LaunchError):campaign._recipe(owner.binding,changed,verify_files=False)
        for case_id in (True,0,4):
            with self.assertRaises(launch.LaunchError):owner.create_intent(case_id,self.registry,lease_fd=self.fd,name='bad-case')
        self.assertEqual(self.registry.load(),[])
    def test_rehashed_changed_service_source_cannot_be_admitted(self):
        owner=self.create();recipe=self.recipe(owner);path=self.aux/'cases/1/code/runtime/application_client_service.py'
        path.chmod(0o600);path.write_bytes(path.read_bytes()+b'\n# controlled changed code\n');path.chmod(0o400)
        changed=copy.deepcopy(recipe);changed['code_files']['runtime/application_client_service.py']=hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaises(launch.LaunchError):campaign._recipe(owner.binding,changed)
        with self.assertRaises(launch.LaunchError):owner.create_intent(1,self.registry,lease_fd=self.fd,name='changed-service')
        self.assertEqual(self.registry.load(),[])
    def test_orphan_intent_cannot_be_hidden_by_zero_count_boundary(self):
        owner=self.create();self.recipe(owner);owner.create_intent(1,self.registry,lease_fd=self.fd,name='never-dispatched')
        self.assertEqual(len(self.registry.load()),1);self.assertEqual(owner.snapshot()['launches'],[])
        with self.assertRaises(launch.LaunchError):self.seal(owner)
        self.assertFalse((self.aux/'boundary.json').exists())
    def test_persisted_fake_private_true_without_cleanup_receipt_denied(self):
        owner=self.create();key,record,argv,recipe=self.reserve(owner)
        path=self.aux/'ledger.json';state=json.loads(path.read_bytes());state['launches'][0].update(physical='absent',private_cleanup=True);self.put(path,state)
        with self.assertRaises(launch.LaunchError):owner.snapshot()
    def test_candidate_after_finalization_and_missing_claim_cannot_be_rebound(self):
        owner=self.create();boundary=self.seal(owner);policy=self.finalize(boundary)
        path=self.final/'candidate.json';candidate=json.loads(path.read_bytes());candidate['archive_sha256']='f'*64;self.put(path,candidate)
        with self.assertRaises(launch.LaunchError):launch.LaunchLedger.create(self.final/'launch-ledger',policy,daemon_id='fixture-daemon',daemon_capacity=self.base['daemon_capacity'],clock=self.clock,wall=self.wall)
        self.assertFalse((self.final/'launch-ledger').exists())
        folder,name=campaign._claim_names(self.predecessor,self.base);(folder/('authorization-'+campaign.AUTHORIZATION_ID+'.json')).unlink()
        with self.assertRaises((launch.LaunchError,FileNotFoundError)):campaign.AuxiliaryCampaign(self.aux,clock=self.clock,wall=self.wall)
    def test_final_dispatch_policy_must_match_same_frozen_full_manifest(self):
        owner=self.create();boundary=self.seal(owner);policy=self.finalize(boundary)
        policy['cells'][0]['image_id']=policy['cells'][0]['allowed_images'][1]
        launch.validate_manifest(policy)
        with self.assertRaises(launch.LaunchError):launch.LaunchLedger.create(self.final/'launch-ledger',policy,daemon_id='fixture-daemon',daemon_capacity=self.base['daemon_capacity'],clock=self.clock,wall=self.wall)
        self.assertFalse((self.final/'launch-ledger').exists());self.assertFalse((self.aux/'final-binding.json').exists())
    def first_two_clean(self,owner):
        for case_id in (1,2):
            key,record,argv,recipe=self.reserve(owner,case_id);self.cleaned(owner,key,record,recipe)
    def test_case_three_schema_two_private_layout_published_transport_exact(self):
        owner=self.create();self.first_two_clean(owner);key,record,argv,recipe=self.reserve(owner,3)
        self.assertEqual(recipe['schema'],2);self.assertEqual(argv[argv.index('--network')+1],'bridge')
        self.assertEqual(argv[argv.index('--publish')+1],'127.0.0.1::8081')
        self.cleaned(owner,key,record,recipe);boundary=self.seal(owner)
        self.assertEqual(campaign.validate_boundary(boundary,self.predecessor,clock=self.clock,wall=self.wall)['attempts'],54)
    def test_private_child_wrong_uid_mode_symlink_deny_before_new_intent(self):
        owner=self.create();self.first_two_clean(owner);recipe=self.recipe(owner,3,freeze=False)
        child=self.aux/'cases/3/state/private';info=child.stat();before=len(self.registry.load())
        real_fstat=os.fstat
        def wrong_uid(fd):
            actual=real_fstat(fd)
            if (actual.st_dev,actual.st_ino)==(info.st_dev,info.st_ino):
                return types.SimpleNamespace(st_uid=os.getuid()+1,st_mode=actual.st_mode,st_dev=actual.st_dev,st_ino=actual.st_ino)
            return actual
        with mock.patch.object(campaign.os,'fstat',side_effect=wrong_uid),self.assertRaises(launch.LaunchError):owner.freeze_recipe(3,recipe,lease_fd=self.fd)
        child.chmod(0o755)
        with self.assertRaises(launch.LaunchError):owner.freeze_recipe(3,recipe,lease_fd=self.fd)
        child.chmod(0o700);child.rmdir();target=self.root/'unrelated';target.mkdir(mode=0o700);child.symlink_to(target,target_is_directory=True)
        with self.assertRaises((OSError,launch.LaunchError)):owner.freeze_recipe(3,recipe,lease_fd=self.fd)
        self.assertEqual(len(self.registry.load()),before);self.assertEqual(len(owner.snapshot()['launches']),2);self.assertTrue(target.exists())
    def test_private_child_and_transport_rechecked_before_dispatch(self):
        owner=self.create();self.first_two_clean(owner);recipe=self.recipe(owner,3);record,argv=owner.create_intent(3,self.registry,lease_fd=self.fd,name='third-case')
        wrong=list(argv);wrong[wrong.index('--network')+1]='none';executor=mock.Mock()
        with self.assertRaises(launch.LaunchError):owner.dispatch(3,record,wrong,self.daemon,lease_fd=self.fd,popen=executor)
        child=self.aux/'cases/3/evidence/private';child.chmod(0o755)
        with self.assertRaises(launch.LaunchError):owner.dispatch(3,record,argv,self.daemon,lease_fd=self.fd,popen=executor)
        self.assertEqual(len(owner.snapshot()['launches']),2);executor.assert_not_called()
    def test_case_one_cannot_publish_or_adopt_schema_two(self):
        owner=self.create();recipe=self.recipe(owner);record,argv=owner.create_intent(1,self.registry,lease_fd=self.fd,name='first-case')
        wrong=list(argv);wrong[wrong.index('--network')+1]='bridge';wrong+=['--publish','127.0.0.1::8081'];executor=mock.Mock()
        with self.assertRaises(launch.LaunchError):owner.dispatch(1,record,wrong,self.daemon,lease_fd=self.fd,popen=executor)
        executor.assert_not_called();self.assertEqual(owner.snapshot()['launches'],[])
        recipe.update(schema=2,private_children=copy.deepcopy(recipe['writable_identities']),transport='host-loopback-published')
        with self.assertRaises(launch.LaunchError):campaign._recipe(owner.binding,recipe,verify_files=False)

if __name__=='__main__':unittest.main()


class ReviewedInputRevisionTests(unittest.TestCase):
    """Independent fixed revision metadata; no filesystem/native operations."""
    OLD={'guest.py': '45f7b93252e9be82fa0ac201ff52095308a94c40ec5c487ba827714834ec7aa0', 'service_wrapper.py': '18dab15aa19a0f5ef9db4d67caa03eb5283b755d47186260bd946fcb79ff1398', 'diagnostic_instrumentation.py': 'c0e61f0383d8072b41ba9dd123acc3bca0da7d2ce3bb1523a3005f8d84af4579', 'parent_control.py': 'a42f378d640b9b4d118f53ecde096e28e0de48c941b8dcca787ee03349c68932', 'plan.json': 'e8cbcb7cc9e56e55113c8bd1dbb60f95b670204d114308b438cf93ea8598db09', 'binding.json': 'b955594f9708c46ba667acd7339c00efd651b89006055b78282fb3d66a66ae0e'}
    NEW={'guest.py': '3e2285680f8f89654b80c9b6f11cf5c8919ebba207721e3986efc205bef4653b', 'service_wrapper.py': '18dab15aa19a0f5ef9db4d67caa03eb5283b755d47186260bd946fcb79ff1398', 'diagnostic_instrumentation.py': 'c0e61f0383d8072b41ba9dd123acc3bca0da7d2ce3bb1523a3005f8d84af4579', 'parent_control.py': 'a42f378d640b9b4d118f53ecde096e28e0de48c941b8dcca787ee03349c68932', 'plan.json': 'e8cbcb7cc9e56e55113c8bd1dbb60f95b670204d114308b438cf93ea8598db09', 'binding.json': 'b955594f9708c46ba667acd7339c00efd651b89006055b78282fb3d66a66ae0e'}
    def recipe(self,inputs):
        case=campaign.AUXILIARY_ROOT/'cases/1'
        return {'schema':1,'case_id':1,'program_sha256':inputs['guest.py'],'code_files':copy.deepcopy(campaign.APPROVED_CODE_REVISIONS[0]),
            'input_files':copy.deepcopy(inputs),'image_id':campaign.IMAGE,'platform':'linux/arm64','uid':'501:20','resources':copy.deepcopy(campaign.RESOURCES),
            'timeout_seconds':60,'mounts':[{'source':str(case/name),'target':target,'rw':rw} for name,target,rw in campaign.TARGETS],
            'writable_identities':{'state':{'device':1,'inode':2},'evidence':{'device':1,'inode':3}}}
    def test_exact_old_and_new_revisions_both_validate_old_receipt_identity_unchanged(self):
        self.assertEqual(campaign.APPROVED_INPUT_REVISIONS,(self.OLD,self.NEW))
        for inputs in (self.OLD,self.NEW):
            recipe=self.recipe(inputs);before=launch._json(recipe)
            self.assertEqual(campaign._recipe({'root':str(campaign.AUXILIARY_ROOT)},recipe,verify_files=False),recipe)
            self.assertEqual(launch._json(recipe),before)
        self.assertNotEqual(self.OLD['guest.py'],self.NEW['guest.py'])
    def test_rehashed_unknown_or_cross_mixed_program_revision_denied(self):
        for inputs in ({**self.NEW,'guest.py':'f'*64},{**self.NEW,'service_wrapper.py':self.OLD['parent_control.py']}):
            recipe=self.recipe(inputs)
            with self.assertRaises(launch.LaunchError):campaign._recipe({'root':str(campaign.AUXILIARY_ROOT)},recipe,verify_files=False)

    def test_published_revision004_is_case_three_schema_two_only(self):
        published={'guest.py': '72f3c678fc6b2dd600b6b57939ca5670695d97e3ce9b5d2b01b954eea6f69d51', 'service_wrapper.py': '095af773734b644e3de87e773b9f37fd67a7694dd0be3bbe48214322cfee8fa1', 'diagnostic_instrumentation.py': 'c0e61f0383d8072b41ba9dd123acc3bca0da7d2ce3bb1523a3005f8d84af4579', 'parent_control.py': 'a42f378d640b9b4d118f53ecde096e28e0de48c941b8dcca787ee03349c68932', 'plan.json': 'e8cbcb7cc9e56e55113c8bd1dbb60f95b670204d114308b438cf93ea8598db09', 'binding.json': 'b955594f9708c46ba667acd7339c00efd651b89006055b78282fb3d66a66ae0e'}
        self.assertEqual(campaign.APPROVED_PUBLISHED_INPUT_REVISIONS,(published,))
        recipe=self.recipe(published);recipe.update(schema=2,case_id=3,transport='host-loopback-published',
            private_children={'state':{'device':1,'inode':4},'evidence':{'device':1,'inode':5}})
        case=campaign.AUXILIARY_ROOT/'cases/3';recipe['mounts']=[{'source':str(case/name),'target':target,'rw':rw} for name,target,rw in campaign.TARGETS]
        self.assertEqual(campaign._recipe({'root':str(campaign.AUXILIARY_ROOT)},recipe,verify_files=False),recipe)
        legacy=self.recipe(published)
        with self.assertRaises(launch.LaunchError):campaign._recipe({'root':str(campaign.AUXILIARY_ROOT)},legacy,verify_files=False)
        for fields in (self.OLD,self.NEW):
            wrong=copy.deepcopy(recipe);wrong.update(input_files=copy.deepcopy(fields),program_sha256=fields['guest.py'])
            with self.assertRaises(launch.LaunchError):campaign._recipe({'root':str(campaign.AUXILIARY_ROOT)},wrong,verify_files=False)


class KnownAuxiliaryRecoveryTests(unittest.TestCase):
    """Synthetic exact-incident overlay; no real incident files/IDs/authority used."""
    put=CampaignBoundaryTests.put
    create=CampaignBoundaryTests.create
    recipe=CampaignBoundaryTests.recipe
    reserve=CampaignBoundaryTests.reserve
    cleaned=CampaignBoundaryTests.cleaned
    first_two_clean=CampaignBoundaryTests.first_two_clean
    finalize=CampaignBoundaryTests.finalize
    def raw(self,path,body):
        path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.write_bytes(body);path.chmod(0o600);return campaign.ref(path)
    def setUp(self):
        CampaignBoundaryTests.setUp(self);self.owner=self.create();self.first_two_clean(self.owner);self.fixture_recipe=self.recipe(self.owner,3)
        with mock.patch.object(campaign.os,'getpid',return_value=2147483647):
            self.record,self.argv=self.owner.create_intent(3,self.registry,lease_fd=self.fd,name='known-third')
        self.key=self.owner.reserve(3,self.record,self.argv,self.daemon,lease_fd=self.fd)
        self.owner.note(self.key,pid=2147483646,physical='uncertain',poison=True)
        self.output=self.aux/'recovery';self.output.mkdir(mode=0o700);self.cid='a'*64
        source=self.put(self.output/'source.json',self.record);original=copy.deepcopy(self.record)
        self.record['status']='quarantined';self.registry.write(self.record);quarantine=self.put(self.output/'quarantine.json',self.record)
        self.record.update(status='absent',container_id=self.cid);self.registry.write(self.record)
        roots={}
        for name in ('state','evidence'):
            path=self.aux/'cases/3'/name;roots[name]={'path':str(path),**self.fixture_recipe['writable_identities'][name],'removed':True};(path/'private').rmdir();path.rmdir()
        self.registry.release(self.record,True)
        terminal=self.put(self.output/'terminal.json',{'schema':1,'launch_id':self.key,'container_id':self.cid,'exit_code':2,'exit_code_source':'container_state_exit_code','timed_out':False,'writers_stopped':True})
        self.cleanup=self.put(self.output/'cleanup.json',{'schema':1,'document_type':'qualification_auxiliary_cleanup','authorization_id':campaign.AUTHORIZATION_ID,
            'binding_sha256':campaign.digest(self.owner.binding),'case_id':3,'launch_id':self.key,'registry':self.record['registry'],'generation':self.record['generation'],
            'container_id':self.cid,'intent_sha256':launch._intent_identity(self.record),'daemon':'fixture-daemon','physical_absence_confirmed':True,'private_cleanup_confirmed':True,'writable_roots':roots,'terminal':terminal})
        controller_source=self.raw(self.output/'controller.py',b'harmless immutable controller fixture\n');failure=self.raw(self.output/'failure.log',b'controlled failure before bootstrap\n')
        command=self.put(self.output/'command.json',{'actual_exit':1,'outer_timeout':False,'program_before':controller_source['sha256'],'program_after':controller_source['sha256'],'logs':{'stderr.log':failure['sha256']}})
        dispatch=self.put(self.aux/'cases/3/dispatch.json',{'schema':1,'argv':self.argv,'classification':'dummy host control component; no Pi/model/application actions','daemon':self.daemon})
        row=self.owner.snapshot()['launches'][2];binding=campaign.ref(self.aux/'binding.json');ledger=campaign.ref(self.aux/'ledger.json')
        self.known={'binding_sha256':binding['sha256'],'ledger_sha256':ledger['sha256'],'dispatch_sha256':dispatch['sha256'],'recipe_sha256':row['recipe']['sha256'],
            'intent_marker_sha256':campaign.ref(self.aux/'cases/3/intent.json')['sha256'],'source_record_sha256':source['sha256'],'launch_id':self.key,
            'registry':self.record['registry'],'generation':self.record['generation'],'intent_sha256':row['intent_sha256'],'container_id':self.cid,'owner_pid':2147483647,'docker_cli_pid':2147483646,
            'controller_sha256':controller_source['sha256'],'command_sha256':command['sha256'],'failure_sha256':failure['sha256']}
        patcher=mock.patch.object(campaign,'KNOWN_AUXILIARY_INCIDENT',self.known);patcher.start();self.addCleanup(patcher.stop)
        bound=self.put(self.output/'bound.json',{'schema':1,'container_id':self.cid,'launch_id':self.key,'daemon':'fixture-daemon',
            'verified_stopped_identity_user_resources_mounts_labels':True,'late_binding':True,'source_registry_sha256':source['sha256'],'source_ledger_sha256':ledger['sha256'],'no_bootstrap_or_control_request_sent':True})
        observation=self.put(self.output/'observation.json',{'schema':1,'document_type':'qualification_auxiliary_recovery_observation','launch_id':self.key,'container_id':self.cid,'daemon':'fixture-daemon',
            'image_id':campaign.IMAGE,'user':'501:20','workdir':'/pi-client/state','labels':{launch.LABEL:self.key,launch.REGISTRY_LABEL:self.record['registry']},
            'host_config':{'ReadonlyRootfs':True,'NetworkMode':'bridge','IpcMode':'none','NanoCpus':1000000000,'Memory':536870912,'MemorySwap':536870912,'PidsLimit':128,
                'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges=true'],'PortBindings':{'8081/tcp':[{'HostIp':'127.0.0.1','HostPort':''}]}},
            'mounts':sorted(self.fixture_recipe['mounts'],key=lambda item:item['target']),'state':{'status':'exited','running':False,'exit_code':2},'physical_absence_confirmed':True,'bound_observation':bound})
        controller=self.put(self.output/'controller.json',{'schema':1,'document_type':'qualification_auxiliary_recovery_controller','owner_pid':2147483647,'docker_cli_pid':2147483646,
            'owner_pid_absent':True,'docker_cli_pid_absent':True,'configuration_bootstrap_sent':False,'control_rpc_attempted':False,'command_verification':command,'controller_failure':failure,'reviewed_controller':controller_source})
        self.value={'schema':1,'document_type':'qualification_known_auxiliary_cleanup','binding':binding,'ledger':ledger,'dispatch':dispatch,'source_record':source,
            'quarantine_record':quarantine,'observation':observation,'controller':controller,'cleanup':self.cleanup}
        self.recovery=self.put(self.output/'known-cleanup.json',self.value);self.original_ledger=(self.aux/'ledger.json').read_bytes()
    def validate(self):return campaign.validate_known_auxiliary_cleanup(self.recovery,clock=self.clock,wall=self.wall)
    def rewrite(self,key,value):
        updated=copy.deepcopy(self.value);updated[key]=self.put(Path(updated[key]['path']),value);self.recovery=self.put(self.output/'known-cleanup.json',updated)
    def test_known_overlay_seals_without_rewriting_raw_poison_null_id_or_counters(self):
        self.assertEqual(self.validate(),self.value)
        boundary=campaign.seal_known_cleanup(self.aux,self.aux/'boundary.json',recovery_ref=self.recovery,lease_fd=self.fd,clock=self.clock,wall=self.wall)
        carry=campaign.validate_boundary(boundary,self.predecessor,clock=self.clock,wall=self.wall)
        self.assertEqual((carry['attempts'],carry['participant_segments'],carry['planned_cells'],len(carry['lineage'])),(54,0,196,7));self.assertEqual(carry['attempts']+186,240)
        self.assertEqual((self.aux/'ledger.json').read_bytes(),self.original_ledger)
        state=self.owner.snapshot();self.assertTrue(state['poisoned']);self.assertFalse(state['sealed']);self.assertIsNone(state['launches'][2]['container_id']);self.assertEqual(state['launches'][2]['physical'],'uncertain')
        policy=self.finalize(boundary);ledger=launch.LaunchLedger.create(self.final/'launch-ledger',policy,daemon_id='fixture-daemon',daemon_capacity=self.base['daemon_capacity'],clock=self.clock,wall=self.wall)
        self.assertEqual(ledger.snapshot()['attempts'],54)
    def test_normal_seal_fourth_aux_or_second_overlay_stay_closed(self):
        with self.assertRaises(launch.LaunchError):self.owner.seal(self.aux/'normal.json',lease_fd=self.fd)
        with self.assertRaises(launch.LaunchError):self.owner.create_intent(4,self.registry,lease_fd=self.fd,name='forbidden-fourth')
        campaign.seal_known_cleanup(self.aux,self.aux/'boundary.json',recovery_ref=self.recovery,lease_fd=self.fd,clock=self.clock,wall=self.wall)
        with self.assertRaises(FileExistsError):campaign.seal_known_cleanup(self.aux,self.aux/'boundary.json',recovery_ref=self.recovery,lease_fd=self.fd,clock=self.clock,wall=self.wall)
        self.assertEqual((self.aux/'ledger.json').read_bytes(),self.original_ledger)
    def test_modified_raw_ledger_cannot_be_rehashed_into_recovery(self):
        path=self.aux/'ledger.json';state=json.loads(path.read_bytes());state['launches'][2]['container_id']=self.cid;newref=self.put(path,state)
        self.value['ledger']=newref;self.recovery=self.put(self.output/'known-cleanup.json',self.value)
        with self.assertRaises(launch.LaunchError):self.validate()
        self.assertFalse((self.aux/'boundary.json').exists())
    def test_foreign_observation_quarantine_or_bootstrap_claim_denied(self):
        for key,change in [('observation',lambda x:x.update(container_id='f'*64)),('observation',lambda x:x['host_config'].update(NetworkMode='host')),
                           ('quarantine_record',lambda x:x.update(container_id=self.cid)),('controller',lambda x:x.update(configuration_bootstrap_sent=True)),
                           ('controller',lambda x:x.update(owner_pid=2147483647.0))]:
            old=json.loads(Path(self.value[key]['path']).read_bytes());changed=copy.deepcopy(old);change(changed);self.rewrite(key,changed)
            with self.subTest(key=key),self.assertRaises(launch.LaunchError):self.validate()
            self.put(Path(self.value[key]['path']),old);self.recovery=self.put(self.output/'known-cleanup.json',self.value)
    def test_live_controller_recreated_private_or_unreleased_current_record_denied(self):
        with mock.patch.object(campaign.os,'kill',return_value=None),self.assertRaises(launch.LaunchError):self.validate()
        path=self.aux/'cases/3/state';path.mkdir(mode=0o700)
        with self.assertRaises(launch.LaunchError):self.validate()
        path.rmdir();self.record['status']='quarantined';self.registry.write(self.record)
        with self.assertRaises(launch.LaunchError):self.validate()
    def test_missing_old_cleanup_or_wrong_controller_source_hash_denied(self):
        state=json.loads(self.original_ledger);old=Path(state['launches'][0]['cleanup']['path']);original=old.read_bytes();old.write_bytes(original+b' ')
        with self.assertRaises(launch.LaunchError):self.validate()
        old.write_bytes(original);controller=json.loads(Path(self.value['controller']['path']).read_bytes());source=Path(controller['reviewed_controller']['path'])
        source.write_bytes(b'unreviewed controller source\n')
        with self.assertRaises(launch.LaunchError):self.validate()
