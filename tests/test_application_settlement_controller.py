"""Controlled controller contracts; every native/SDK execution boundary is inert.

Compiler and durable-launch checks use genuine public code on owned nonsecret
fixtures. Fake SDK pipelines do not establish actual admission or eligibility.
"""
import argparse
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

REPO=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(REPO/'tools/qualification'),str(REPO/'skill/scripts'),str(REPO/'skill/runtime'),str(REPO/'tests')]
import application_settlement_controller as controller
import application_settlement_service as service
import application_launch as launch
import ownership_registry
import stage_control
import test_application_settlement_diagnostic as preparation_fixture
import test_application_launch as launch_fixture
import test_application_qualification as qualification


def fresh():return str(uuid.uuid4())
def clock():
    mono,wall=time.monotonic()-1,time.time()-1
    return {'schema':1,'authorization_id':fresh(),'started':mono,'deadline':mono+900,'started_wall':wall,'deadline_wall':wall+900}
def reference(path):return {'path':str(path),'sha256':controller.sha(Path(path).read_bytes())}


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='inert-settlement-controller-');self.addCleanup(self.temp.cleanup)
        self.top=Path(self.temp.name).resolve();self.root=self.top/'diagnostic';self.root.mkdir(mode=0o700)
        self.prepared=self.top/'prepared';self.lock=self.top/'operation.lock';self.lock.write_bytes(b'NONSECRET_LEASE');self.lock.chmod(0o600)
        for name,value in (('ROOT',self.root),('PREPARED_ROOT',self.prepared),('NORMAL_LOCK',self.lock)):
            patch=mock.patch.object(controller,name,value);patch.start();self.addCleanup(patch.stop)

    def put(self,path,value):
        path=Path(path);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        path.write_bytes(controller.canonical(value));path.chmod(0o600);return reference(path)

    def manifest(self,c=None):
        c=c or clock();return controller.launch_manifest(fresh(),c,{'path':str(self.prepared/'PREPARATION.json'),'sha256':'a'*64},
            {'path':str(self.root/'candidate.json'),'sha256':'b'*64})

    def inputs(self):
        checker=mock.patch.object(controller,'_ownership_checker',return_value=SimpleNamespace(validate_ownership_input=lambda value:None))
        checker.start();self.addCleanup(checker.stop)  # Original-input observer is a separately tested source boundary.
        case=preparation_fixture.SettlementDiagnosticTests();case.setUp();self.addCleanup(case.doCleanups)
        fixture,endpoint=case.compiler_fixture();q=qualification.harness
        controller.diagnostic.prepare(self.prepared,image_receipts={'core':fixture.paths['core-0.87.1'],'browser':fixture.paths['browser-0.87.1']},
          scripted_endpoint=endpoint,fixture_route={'origin':'http://172.17.0.1:18080','allowed_addresses':['172.17.0.1']},credential_reference='CONTROLLED_ACTOR_REFERENCE')
        c=clock();prep=reference(self.prepared/'PREPARATION.json');candidate=self.put(self.root/'candidate.json',
          {'archive_sha256':'a'*64,'runner_sha256':q.source_identity()['runner'],'scope':'extracted_candidate'})
        manifest=controller.launch_manifest(fresh(),c,prep,candidate);mref=self.put(self.root/'manifest.json',manifest);cref=self.put(self.root/'clock.json',c)
        config={'session':'inert-controller-session','secrets_dir':str(self.top/'normal-store'),
          'credential_references':{'alice':'CONTROLLED_ACTOR_REFERENCE','bob':'CONTROLLED_BOB_REFERENCE','scripted_inference':controller.diagnostic.SCRIPT_KEY_REFERENCE},
          'fixture_route':{'origin':'http://172.17.0.1:18080','allowed_addresses':['172.17.0.1'],'fixture_port':18080,
            'scripted_base_url':'http://172.17.0.1:19081/v1','scripted_host_base_url':'http://127.0.0.1:19081/v1','scripted_port':19081,'publish_host':'172.17.0.1'},
          'source':q.source_identity(),'daemon':dict(controller.DAEMON)}
        eref=self.put(self.root/'execution.json',config);source=reference(Path(controller.__file__));backend=reference(Path(service.__file__))
        ownership=self.put(self.root/'ownership-input.json',{'NONSECRET_SEPARATE_CHECKER_BOUNDARY':True})
        normalized=q.lab.normalize_endpoint(preparation_fixture.endpoint())
        grant={'schema':1,'document_type':'controlled_settlement_native_authorization','status':'AUTHORIZED_CONTROLLED_DIAGNOSTIC_ONLY',
          'authorization_id':c['authorization_id'],'qualification_id':manifest['qualification_id'],'run_id':fresh(),'attempt_id':fresh(),
          'root':str(self.root),'cell_id':controller.CELL,'preparation':prep,'candidate':candidate,'execution':eref,'controller':source,'service':backend,
          'historical_use':dict(controller.diagnostic.CURRENT_USE),'local_plan':dict(controller.diagnostic.PLAN_MAX),'caps':dict(controller.diagnostic.CAPS),
          'live_limits':dict(controller.diagnostic.LIVE),'automatic_retries':0,'native_qualification_credit':False,
          'ownership_input':ownership,'ownership_read_scope':{'record_body_passes_max':6,'record_body_bytes_each_max':1048576,
            'seconds_max':120,'proof_reference_follows':0,'Docker_PID_queries':0,'record_writes':0},
          'controlled_environment_consent':{'endpoint':normalized,'config_dir':str(self.root/'controlled-config'),
            'session':config['session'],'new_confirmation_only':True,'default_state_namespace_unchanged':True}}
        gref=self.put(self.root/'native-authorization.json',grant)
        peer={'schema':1,'status':'PASS','grant':gref,'clock':cref,'manifest':mref,'preparation':prep,'candidate':candidate,
          'execution':eref,'controller':source,'service':backend,'ownership_input':ownership,'supports_exact_controlled_settlement':True,'unresolved':[]}
        pref=self.put(self.root/'independent-input-review.json',peer)
        activation={'root':str(self.root),'grant':gref,'clock':cref,'input_review':pref,'preparation':prep,'candidate':candidate,
          'admission':{'path':str(self.root/'service-admission.json'),'sha256':'0'*64},'nonce':fresh(),'controller_sha256':source['sha256']}
        return q,activation,grant,c,manifest,config

    def test_exact_two_images_one_cell_roles_and_accounting(self):
        value=self.manifest();self.assertEqual(controller.validate_launch_manifest(value),value)
        self.assertEqual(set(value['images']),{'core-0.87.1','browser-0.87.1'})
        self.assertEqual(sum(value['cells'][0]['role_limits'].values()),7);self.assertEqual(value['cells'][0]['group'],'N04')
        self.assertEqual((501+7,42+1),(508,43));self.assertEqual(controller.effective_limits(value)['global_seconds'],900)
        with mock.patch.object(launch,'effective_limits',side_effect=AssertionError('recursive dispatch')):
            self.assertEqual(controller.effective_limits(value),controller.LIMITS)

    def test_mixed_markers_extra_role_wrong_images_and_bool_growth_refuse(self):
        for change in (lambda v:v.update(predecessor={}),lambda v:v.update(browser_followup={}),
          lambda v:v['cells'][0]['role_limits'].update(extra=1),lambda v:v['images']['core-0.87.1'].update(platform='linux/amd64'),
          lambda v:v['limits'].update(live=True),lambda v:v.update(planned_container_launches=8)):
            value=self.manifest();change(value)
            with self.subTest(change=change),self.assertRaises(ValueError):controller.validate_launch_manifest(value)

    def test_clock_cannot_be_old_qualification_window_or_reset(self):
        value=clock();controller.validate_clock(value)
        for key,changed in (('deadline',value['started']+14400),('started_wall',value['started_wall']-1),('deadline',float('inf')),('started',False)):
            row={**value,key:changed}
            with self.subTest(key=key),self.assertRaises(ValueError):controller.validate_clock(row)
        with mock.patch.object(controller.time,'monotonic',return_value=value['started']-1),self.assertRaises(ValueError):controller.remaining(value)

    def test_real_original_compilation_and_exact_positive_activation(self):
        q,a,g,c,m,configuration=self.inputs()
        with mock.patch.object(q,'_native',side_effect=AssertionError('no runtime observation')),mock.patch.object(q,'OwnedServices',side_effect=AssertionError('no roles')):
            actual=controller.load_activation(a,q)
        self.assertEqual(actual[:4],(g,c,m,configuration))
        self.assertFalse((self.root/'attempt-intent.json').exists());self.assertFalse((self.root/'launch-ledger').exists())

    def test_actual_bindings_reject_tamper_and_arbitrary_reference_before_native(self):
        q,a,_,_,_,_=self.inputs()
        for key in ('grant','input_review','clock','preparation','candidate'):
            changed=copy.deepcopy(a);changed[key]['sha256']='f'*64
            with self.subTest(key=key),self.assertRaises(ValueError):controller.load_activation(changed,q)
        changed=copy.deepcopy(a);changed['grant']['path']=str(self.top/'private-not-authorized.json')
        with self.assertRaises(ValueError):controller.load_activation(changed,q)

    def test_coherent_cap_or_original_read_permission_growth_still_refuses(self):
        q,a,grant,_,_,_=self.inputs();peer=json.loads((self.root/'independent-input-review.json').read_bytes())
        for fault in ('caps','ownership','consent'):
            changed=copy.deepcopy(grant)
            if fault=='caps':changed['caps']['containers']=538
            elif fault=='ownership':changed['ownership_read_scope']['record_body_passes_max']=7
            else:changed['controlled_environment_consent']['new_confirmation_only']=1
            new=copy.deepcopy(a);new['grant']=self.put(self.root/'native-authorization.json',changed)
            review=copy.deepcopy(peer);review['grant']=new['grant'];new['input_review']=self.put(self.root/'independent-input-review.json',review)
            with self.subTest(fault=fault),self.assertRaises(ValueError):controller.load_activation(new,q)

    def test_absent_grant_refuses_before_SDK_or_attempt_output(self):
        a={'root':str(self.root),'grant':{'path':str(self.root/'native-authorization.json'),'sha256':'a'*64},'input_review':{},'clock':{},
          'preparation':{},'candidate':{},'admission':{},'nonce':fresh(),'controller_sha256':'a'*64}
        with mock.patch.object(controller,'_sdk',side_effect=AssertionError('SDK before grant')) as sdk, \
          mock.patch.object(controller.signal,'signal'),mock.patch.object(controller.signal,'setitimer'),mock.patch.object(controller.signal,'getitimer',return_value=(0,0)):
            with self.assertRaises(FileNotFoundError):controller.execute(a,inference_key='NONSECRET-TEST-KEY-0123')
        sdk.assert_not_called();self.assertFalse((self.root/'attempt-intent.json').exists())

    def test_normal_launch_ledger_uses_exact900_and_original_guard(self):
        c=clock();value=self.manifest(c)
        ledger=launch.LaunchLedger.create(self.top/'ledger',value,daemon_id='synthetic-daemon',
          daemon_capacity={'cpu_millis':64000,'memory_mib':65536})
        raw=json.loads((ledger.root/'ledger.json').read_bytes())
        self.assertEqual(raw['started'],c['started']);self.assertEqual(raw['deadline'],c['deadline'])
        self.assertEqual(raw['deadline']-raw['started'],900)
        wrong=copy.deepcopy(raw);wrong['deadline']=wrong['started']+14400
        with self.assertRaises(launch.LaunchError):ledger._validate(wrong)

    def test_genuine_original_guard_accepts_worker_and_denies_forged_source(self):
        case=launch_fixture.LaunchTests();case.setUp();self.addCleanup(case.doCleanups)
        value=self.manifest();case.policy=value;case.image=value['cells'][0]['image_id']
        case.ledger=launch.LaunchLedger.create(case.root/'controlled-ledger',value,daemon_id='fixture-daemon',
          daemon_capacity={'cpu_millis':64000,'memory_mib':65536})
        record,argv=case.intent();case.guard(controller.CELL).popen(argv)
        self.assertEqual(len(case.effects),1);self.assertEqual(case.ledger.snapshot()['participant_segments'],0)
        record,forged=case.intent();forged[-2]='/untrusted/caller-worker.py'
        with self.assertRaises(launch.LaunchError):case.guard(controller.CELL).popen(forged)
        self.assertEqual(len(case.effects),1)

    def test_case_session_uses_original_confirmation_without_ttl_or_old_replacement(self):
        q,a,_,_,_,config=self.inputs();home=self.top/'synthetic-home';home.mkdir();old_config=self.top/'old-environment'
        with mock.patch.dict(os.environ,{'HOME':str(home),'PI_LAB_CONFIG_DIR':str(old_config)}):
            q.lab_env.save_environment({'model':'old-saved-model'},name='preserved')
            old_endpoint=(old_config/'endpoint.json').read_bytes();sessions=q.lab_env.state_dir()/'sessions';sessions.mkdir(mode=0o700,parents=True)
            old=sessions/'old-session.json';old.write_text('NONSECRET_PRESERVED_SESSION');before=old.read_bytes()
            with mock.patch.object(q.lab_env,'purge_old_sessions',side_effect=AssertionError('TTL purge')), \
                 mock.patch.object(q.lab_env,'health_check',side_effect=AssertionError('health request')):
                controller.prepare_session(q,config)
            self.assertEqual(old.read_bytes(),before);self.assertEqual((old_config/'endpoint.json').read_bytes(),old_endpoint)
            self.assertEqual(q.lab_env.evaluate(config['session'],check=False)['state'],'ready')
            self.assertFalse(os.environ.get('PI_LAB_STATE_DIR'))

    def service_admission(self,q,a,g,c,*,barrier=None,regular=False):
        if regular:
            r=os.open(self.lock,os.O_RDONLY);w=None
        else:r,w=os.pipe()
        self.addCleanup(os.close,r)
        if w is not None:self.addCleanup(os.close,w)
        stamp=os.fstat(r)
        permit={'schema':1,'authorization_id':g['authorization_id'],'nonce':a['nonce'],'deadline_wall':c['deadline_wall'],
          'deadline_monotonic':c['deadline'],'normal_lock_file':str(self.lock),'registry_root':str(self.lock)+'.registry',
          'parent_registry_admission_attested':True,'grant_sha256':a['grant']['sha256'],'input_review_sha256':a['input_review']['sha256'],
          'clock_sha256':a['clock']['sha256'],'preparation_sha256':a['preparation']['sha256'],'candidate_sha256':a['candidate']['sha256']}
        a=copy.deepcopy(a);a['admission']=self.put(self.root/'service-admission.json',{'schema':1,'permit':permit,'lease_identity':[1,2,3,384,1],
          'control_pipe_identity':[stamp.st_dev,stamp.st_ino,stamp.st_uid,stamp.st_mode&0o7777],
          'parent_pid':os.getppid(),'registry_id':'a'*64,'generation':fresh(),'daemon_id':controller.DAEMON['id']})
        if w is not None:os.write(w,controller.canonical(barrier or {'schema':1,'status':'PARENT_ORIGINAL_ADMISSION_ATTESTED','nonce':a['nonce']})+b'\n')
        return a,r,permit

    def test_child_verifier_uses_only_FIFO_attestation_not_normal_lease(self):
        q,a,g,c,_,_=self.inputs();a,r,expected=self.service_admission(q,a,g,c)
        with mock.patch.object(controller,'_sdk',return_value=q):actual=controller.verify_service_admission(a,control_fd=r,parent_pid=os.getppid())
        self.assertEqual(actual,expected);self.assertNotIn('original_registry_admission',actual)
        self.assertEqual(os.fstat(r).st_ino,os.fstat(r).st_ino)

    def test_child_wrong_pipe_parent_or_nonce_never_becomes_clearance(self):
        q,a,g,c,_,_=self.inputs();bad,r,_=self.service_admission(q,a,g,c,barrier={'schema':1,'status':'PARENT_ORIGINAL_ADMISSION_ATTESTED','nonce':fresh()})
        with mock.patch.object(controller,'_sdk',return_value=q),self.assertRaises(ValueError):controller.verify_service_admission(bad,control_fd=r,parent_pid=os.getppid())
        (self.root/'service-admission.json').unlink();bad,r,_=self.service_admission(q,a,g,c,regular=True)
        with mock.patch.object(controller,'_sdk',return_value=q),self.assertRaises(ValueError):controller.verify_service_admission(bad,control_fd=r,parent_pid=os.getppid())

    def test_service_process_returned_barrier_and_no_lease_inheritance(self):
        c=clock();a={'nonce':fresh()};events=[];captured={};processes=[]
        class Input(io.BytesIO):
            def close(self):
                if not self.closed:captured['stdin']=self.getvalue()
                super().close()
        class Child:
            def __init__(self):
                self.stdin=Input();self.r,self.w=os.pipe();self.stdout=os.fdopen(self.r,'rb');self.stderr=None;self.returncode=None
                os.write(self.w,b'{"schema":1,"status":"SERVICE_READY","phase":"LISTENING"}\n')
            def poll(self):return self.returncode
            def terminate(self):
                events.append('stop');terminal={'schema':1,'status':'SERVICE_STOPPED','phase':'STOPPED','counters':dict.fromkeys(service.COUNTERS,0)}
                os.write(self.w,controller.canonical(terminal)+b'\n');os.close(self.w);os.close(self.control);self.returncode=0
            def wait(self,timeout=None):return self.returncode
            def kill(self):self.returncode=-9
        def popen(argv,**kwargs):
            captured.update(argv=argv,kwargs=kwargs);events.append('returned_handle');child=Child()
            child.control=os.dup(kwargs['pass_fds'][0]);processes.append(child);return child
        handle=controller.ServiceProcess(popen,a,SimpleNamespace(lease_fd=123456),c,'NONSECRET-CONTROLLED-KEY-0123')
        self.addCleanup(lambda:handle.close()if not handle.cleanup_attempted else None)
        handle.start();bootstrap=json.loads(captured['stdin'])
        self.assertIs(type(bootstrap['lifetime_seconds']),int);self.assertLessEqual(bootstrap['lifetime_seconds'],900)
        self.assertEqual(captured['kwargs']['pass_fds'],(int(captured['argv'][captured['argv'].index('--control-fd')+1]),))
        self.assertNotIn(123456,captured['kwargs']['pass_fds']);self.assertTrue(captured['kwargs']['close_fds'])
        self.assertNotIn(controller.diagnostic.SCRIPT_KEY_REFERENCE,captured['kwargs']['env'])
        self.assertEqual(json.loads(os.read(processes[0].control,4096)),{'schema':1,'status':'PARENT_ORIGINAL_ADMISSION_ATTESTED','nonce':a['nonce']})
        self.assertEqual(events,['returned_handle']);handle.close();handle.close()
        self.assertEqual(events,['returned_handle','stop']);self.assertTrue(handle.closed)
        self.assertTrue(processes[0].stdin.closed and processes[0].stdout.closed)

    def test_invalid_key_or_uncertain_constructor_never_reports_closed_success(self):
        for key in ('short','private-key-with-space xxxxxxxxx','é'*16):
            handle=controller.ServiceProcess(mock.Mock(),{'nonce':fresh()},SimpleNamespace(lease_fd=123),clock(),key)
            try:
                with self.assertRaises(ValueError):handle.start()
                handle.popen.assert_not_called()
            finally:handle.close()
        handle=controller.ServiceProcess(mock.Mock(side_effect=OSError('synthetic constructor failure')),
          {'nonce':fresh()},SimpleNamespace(lease_fd=123),clock(),'NONSECRET-CONTROLLED-KEY-0123')
        with self.assertRaises(OSError):handle.start()
        with self.assertRaises(ValueError):handle.close()
        self.assertTrue(handle.constructor_uncertain);self.assertFalse(handle.closed)
        self.assertIsNone(handle.control_read);self.assertIsNone(handle.control_write)
        handle=controller.ServiceProcess(mock.Mock(),{'nonce':fresh()},SimpleNamespace(lease_fd=123),clock(),'NONSECRET_UNIT_KEY_012345')
        primary=TimeoutError('NONSECRET_LOGICAL_CLOCK_FAILURE')
        child=SimpleNamespace(returncode=None,stdin=io.BytesIO(),stdout=io.BytesIO(),stderr=io.BytesIO(),terminate=mock.Mock())
        child.poll=lambda:child.returncode
        child.kill=mock.Mock(side_effect=lambda:setattr(child,'returncode',0))
        child.wait=mock.Mock(side_effect=[primary,0]);handle.child=child
        with self.assertRaises(TimeoutError)as caught:handle.close()
        self.assertIs(caught.exception,primary);child.kill.assert_called_once();self.assertEqual(child.wait.call_count,2)
        self.assertTrue(child.stdin.closed and child.stdout.closed and child.stderr.closed)

    def test_one_stream_close_failure_still_closes_other_streams_and_pipe(self):
        handle=controller.ServiceProcess(mock.Mock(),{'nonce':fresh()},SimpleNamespace(lease_fd=123),clock(),'NONSECRET_UNIT_KEY_012345')
        terminal={'schema':1,'status':'SERVICE_STOPPED','phase':'STOPPED','counters':dict.fromkeys(service.COUNTERS,0)}
        output=io.BytesIO(controller.canonical(terminal));error=io.BytesIO()
        handle.child=SimpleNamespace(returncode=0,stdin=SimpleNamespace(close=mock.Mock(side_effect=OSError('NONSECRET_CLOSE_ERROR'))),
          stdout=output,stderr=error,poll=lambda:0,wait=lambda timeout=None:0)
        with self.assertRaises(OSError):handle.close()
        self.assertTrue(output.closed and error.closed)
        self.assertIsNone(handle.control_read);self.assertIsNone(handle.control_write)
        with self.assertRaises(ValueError):handle.close()  # No second stop/read attempt.

    def test_fixed_metadata_projection_suppresses_values_paths_and_body_hashes(self):
        initial={'run_id':fresh(),'attempt_id':fresh()};run=self.root/'cells'/controller.CELL/'runs'/initial['run_id'];folder=run.parent.parent
        result={'schema':2,'document_type':'run_result',**initial,'trial_id':None,'experiment_id':None,'sealed':True,'status':'FAIL',
          'last_process':{'application_settlement_failure':{'schema':1,'code':'FINISH_RPC_FAILED'}},'private-canary':'NOT_EXPORTED'}
        ref=self.put(run/'result.json',result)
        self.put(folder/'child-completion.json',{'schema':1,**initial,'result_sha256':ref['sha256'],'cleanup_checked':True})
        value=controller.evidence_projection(self.root,initial);text=json.dumps(value)
        self.assertEqual(value['application_settlement_failure']['code'],'FINISH_RPC_FAILED')
        for private in ('NOT_EXPORTED',initial['run_id'],initial['attempt_id'],ref['sha256'],str(run)):
            self.assertNotIn(private,text)
        self.assertFalse(value['native_qualification_credit']);self.assertLessEqual(value['metadata_static_path_attempts'],8)

    def test_summary_fallback_is_conditional_and_present_null_refuses(self):
        initial={'run_id':fresh(),'attempt_id':fresh()};run=self.root/'cells'/controller.CELL/'runs'/initial['run_id']
        summary={'schema':2,'document_type':'run_result',**initial,'trial_id':None,'experiment_id':None,'sealed':False,'status':'RUNNING'}
        self.put(run/'summary.json',summary);value=controller.evidence_projection(self.root,initial)
        self.assertIn('summary',value['metadata_roles_present']);self.assertFalse(value['sealed_result_present'])
        self.put(run/'result.json',None)
        with self.assertRaises(ValueError):controller.evidence_projection(self.root,initial)

    def test_oversized_child_receipt_is_rejected_before_body_read(self):
        initial={'run_id':fresh(),'attempt_id':fresh()}
        child=self.root/'cells'/controller.CELL/'child-completion.json'
        self.put(child,{'schema':1});child.write_bytes(b'x'*65537)
        with mock.patch.object(controller.os,'read',side_effect=AssertionError('Oversized child body must remain unread'))as body_read:
            with self.assertRaises(ValueError):controller.evidence_projection(self.root,initial)
        body_read.assert_not_called()

    def test_metadata_identity_symlink_and_duplicate_or_nonfinite_JSON_fail_closed(self):
        initial={'run_id':fresh(),'attempt_id':fresh()};run=self.root/'cells'/controller.CELL/'runs'/initial['run_id']
        self.put(run/'result.json',{'schema':2,'document_type':'run_result','run_id':fresh(),'attempt_id':initial['attempt_id'],'sealed':True})
        with self.assertRaises(ValueError):controller.evidence_projection(self.root,initial)
        original=self.top/'original';original.write_bytes(b'NONSECRET');linked=self.top/'linked';linked.symlink_to(original)
        with self.assertRaises(OSError):controller.read(linked)
        for raw in (b'{"code":1,"code":2}',b'{"value":1e999}',b'NaN'):
            with self.assertRaises(ValueError):controller.decoded(raw)

    def test_final_metadata_header_fence_detects_changed_body_without_reread(self):
        initial={'run_id':fresh(),'attempt_id':fresh()};run=self.root/'cells'/controller.CELL/'runs'/initial['run_id'];path=run/'result.json'
        self.put(path,{'schema':2,'document_type':'run_result',**initial,'trial_id':None,'experiment_id':None,'sealed':True})
        original=controller.decoded;changed=[]
        def decode(raw):
            value=original(raw)
            if not changed:changed.append(True);path.write_bytes(raw+b' ')
            return value
        with mock.patch.object(controller,'decoded',side_effect=decode),self.assertRaises(ValueError):controller.evidence_projection(self.root,initial)

    def test_fresh_writes_do_not_overwrite_any_existing_attempt(self):
        path=self.root/'attempt-intent.json';controller.write(path,{'attempts':1})
        before=path.read_bytes()
        with self.assertRaises(FileExistsError):controller.write(path,{'attempts':2})
        self.assertEqual(path.read_bytes(),before)

    def pipeline(self,*,deny=False,sdk_error=None,hook_return=None,cleanup_steps=None):
        """Only the SDK/native effects are mocked; actual_lease is original code."""
        q=qualification.harness;events=[];c=clock();manifest=self.manifest(c);elapsed=[0.0]
        def advance(index):
            if cleanup_steps is not None:elapsed[0]+=cleanup_steps[index]
        grant={'run_id':fresh(),'attempt_id':fresh(),'authorization_id':c['authorization_id']}
        grant['ownership_input']=self.put(self.root/'ownership-input.json',{'NONSECRET_UNIT_SELECTION':True})
        a={'root':str(self.root),'grant':self.put(self.root/'native-authorization.json',{}),'input_review':{'path':str(self.root/'peer.json'),'sha256':'a'*64},
          'clock':{'path':str(self.root/'clock.json'),'sha256':'b'*64},'preparation':{'path':str(self.prepared/'PREPARATION.json'),'sha256':'c'*64},
          'candidate':{'path':str(self.root/'candidate.json'),'sha256':'d'*64},'admission':{'path':str(self.root/'service-admission.json'),'sha256':'0'*64},
          'nonce':fresh(),'controller_sha256':'e'*64}
        config={'session':'NONSECRET_UNIT_SESSION','secrets_dir':str(self.top/'store'),
          'credential_references':{'alice':'UNIT_ALICE','bob':'UNIT_BOB','scripted_inference':controller.diagnostic.SCRIPT_KEY_REFERENCE},'fixture_route':{}}
        lease=os.open(self.lock,os.O_RDONLY);self.addCleanup(os.close,lease)
        registry=SimpleNamespace(lease_fd=lease,registry_id='1'*64,generation=fresh(),bind_daemon=lambda value:events.append('daemon_bound'))
        @contextlib.contextmanager
        def original(path,wait,*,before_registry):
            events.append('normal_lock');self.assertEqual(Path(path),self.lock);self.assertEqual(wait,30)
            before_registry(lease_fd=lease,lock_path=self.lock,registry_root=Path(str(self.lock)+'.registry'))
            if deny:raise ValueError('NONSECRET_ORIGINAL_RECONCILE_DENIED')
            events.append('original_reconcile');token=ownership_registry.CURRENT.set(registry)
            try:yield registry;advance(2);events.append('original_Registry_close')
            finally:ownership_registry.CURRENT.reset(token)
        class Ledger:
            def poison_scope(self,cell):events.append('poison_local_only')
            def snapshot(self):return {'launches':[{'role':role,'cell':controller.CELL,'physical':'absent','private_cleanup':True}for role in set(controller.diagnostic.ROLES)-{'scorer'}]}
        ledger=Ledger()
        @contextlib.contextmanager
        def instrument(*args):yield SimpleNamespace(assert_cell_released=lambda:events.append('original_role_release_check'))
        module=SimpleNamespace(LaunchLedger=SimpleNamespace(create=lambda *a,**kw:ledger),instrument=instrument)
        class Backend:
            def __init__(self,*args):
                self.r,self.w=os.pipe();self.control_identity=os.fstat(self.r);self.closed=False
            def start(self):events.append('backend_started');self.assert_current()
            def assert_current(self):
                if ownership_registry.CURRENT.get()is not registry:raise AssertionError('backend before original CURRENT')
            def close(self):
                if not self.closed:advance(0);events.append('backend_stopped');os.close(self.r);os.close(self.w);self.closed=True
        class Services:
            def __init__(self,*args):events.append('fixture_constructed')
            def start(self):
                if ownership_registry.CURRENT.get()is not registry:raise AssertionError('fixture before original CURRENT')
                events.append('fixture_started')
            def close(self):advance(1);events.append('fixture_closed')
        def suite(args,*,initial_record):
            events.append('SDK_entry');args._attempt_root=self.root/'cells'/controller.CELL/'runs'/initial_record['run_id']
            args._attempt_identity={k:initial_record[k]for k in ('run_id','attempt_id')}
            with fake.lab.admission_lock(args.lock_file,args.lock_wait_seconds):
                if sdk_error is not None:raise sdk_error
                record={'schema':2,'document_type':'run_result','run_id':initial_record['run_id'],'attempt_id':initial_record['attempt_id'],
                  'trial_id':None,'experiment_id':None,'sealed':True,'status':'FAIL','application_completion':{'stages':[{'status':'incomplete'}]}}
                self.put(args._attempt_root/'result.json',record)
                self.put(args._attempt_root/'agent-1-participant/process.json',{'application_settlement_failure':{'schema':1,'code':'UNKNOWN'}})
            return 1
        args=SimpleNamespace(lock_file=str(self.lock),lock_wait_seconds=30)
        fake=SimpleNamespace(lab=SimpleNamespace(admission_lock=original,default_lock_file=lambda:self.lock,
          parser=lambda:SimpleNamespace(parse_args=lambda argv:args),run_suite=suite,command=mock.Mock()),
          resources=SimpleNamespace(admission_lock=original),actual_lease=q.actual_lease,ownership_registry=ownership_registry,
          outcomes=q.outcomes,_launch_module=lambda:module,_native=lambda:(controller.DAEMON['id'],{k:controller.DAEMON[k]for k in ('cpu_millis','memory_mib')}),
          _aggregate=lambda *a:None,credentials=SimpleNamespace(read=lambda *a:'NONSECRET_UNIT_KEY_123456'),OwnedServices=Services,
          read=lambda path:json.loads(Path(path).read_bytes()),_runtime_valid=lambda *a:True)
        checker=SimpleNamespace(deny_unsafe_original_ownership=lambda *a,**kw:hook_return)
        patches=contextlib.ExitStack();self.addCleanup(patches.close)
        for target,name,value in ((controller,'_sdk',lambda:fake),(controller,'load_activation',lambda *a:(grant,c,manifest,config,{})),
          (controller,'prepare_session',lambda *a:None),(controller,'_ownership_checker',lambda:checker),
          (controller,'_host_identity',lambda *a:None),
          (controller,'ServiceProcess',Backend),(controller.diagnostic.preparation,'load_compiled',lambda *a:{'plan':{'stages':[{}]}})):
            patches.enter_context(mock.patch.object(target,name,new=value))
        patches.enter_context(mock.patch.object(controller.signal,'signal'))
        if cleanup_steps is not None:
            patches.enter_context(mock.patch.object(controller.time,'monotonic',side_effect=lambda:c['started']+1+elapsed[0]))
            patches.enter_context(mock.patch.object(controller.time,'time',side_effect=lambda:c['started_wall']+1+elapsed[0]))
        timer_end=[0.0];calls=[]
        def gettimer(which):return(max(0,timer_end[0]-elapsed[0]),0)
        def settimer(which,value):
            previous=gettimer(which);calls.append((elapsed[0],value));timer_end[0]=elapsed[0]+value if value else 0;return previous
        patches.enter_context(mock.patch.object(controller.signal,'setitimer',side_effect=settimer))
        patches.enter_context(mock.patch.object(controller.signal,'getitimer',side_effect=gettimer))
        self.pipeline_timer_calls=calls
        return a,events

    def test_mocked_SDK_pipeline_retains_original_single_lease_order_and_task_FAIL(self):
        a,events=self.pipeline();terminal=controller.execute(a,inference_key='NONSECRET_UNIT_KEY_123456')
        self.assertEqual(events.count('normal_lock'),1);self.assertEqual(events.count('original_reconcile'),1)
        self.assertLess(events.index('original_reconcile'),events.index('fixture_constructed'))
        self.assertLess(events.index('original_reconcile'),events.index('backend_started'))
        self.assertIn('original_Registry_close',events);self.assertFalse(terminal['native_qualification_credit'])
        self.assertEqual(terminal['status'],'SETTLEMENT_CONFIRMED_TASK_INCOMPLETE_NO_QUALIFICATION_CREDIT')
        before=list(events)
        with self.assertRaises(FileExistsError):controller.execute(a,inference_key='NONSECRET_UNIT_KEY_123456')
        self.assertEqual(events,before)

    def test_original_reconcile_denial_or_hook_true_starts_no_fixture_or_server(self):
        a,events=self.pipeline(deny=True)
        with self.assertRaises(ValueError):controller.execute(a,inference_key='NONSECRET_UNIT_KEY_123456')
        self.assertNotIn('fixture_constructed',events);self.assertNotIn('backend_started',events)

    def test_denial_only_hook_cannot_return_True_as_ownership_clearance(self):
        a,events=self.pipeline(hook_return=True)
        with self.assertRaises(ValueError):controller.execute(a,inference_key='NONSECRET_UNIT_KEY_123456')
        self.assertNotIn('original_reconcile',events);self.assertNotIn('fixture_constructed',events)

    def test_SDK_control_instance_survives_owned_cleanup_and_terminal(self):
        error=KeyboardInterrupt('NONSECRET_CANCELLED');a,events=self.pipeline(sdk_error=error)
        with self.assertRaises(KeyboardInterrupt)as caught:controller.execute(a,inference_key='NONSECRET_UNIT_KEY_123456')
        self.assertIs(caught.exception,error);self.assertIn('backend_stopped',events);self.assertIn('fixture_closed',events)
        self.assertNotIn('original_Registry_close',events)
        self.assertEqual(json.loads((self.root/'phase-terminal.json').read_bytes())['status'],'BLOCKED_NO_RETRY')

    def test_private_frame_requires_one_complete_bounded_value_and_EOF(self):
        c=clock();deadline=(c['deadline'],c['deadline_wall'])
        for body,valid in ((b'{"inference_key":"NONSECRET_UNIT_KEY_123456"}\n',True),
            (b'{"inference_key":"NONSECRET_UNIT_KEY_123456"}\n{}',False),(b' '*65537,False)):
            r,w=os.pipe()
            try:
                # Oversize input is supplied by a nonsecret in-memory stream;
                # pipe writes below PIPE_BUF cover real EOF/framing behavior.
                if len(body)>4096:
                    with mock.patch.object(controller.os,'read',side_effect=[body,b'']),mock.patch.object(controller.select,'select',return_value=([r],[],[])),self.assertRaises(ValueError):
                        controller._private_frame(SimpleNamespace(fileno=lambda:r),c,deadline)
                else:
                    os.write(w,body);os.close(w);w=None
                    if valid:self.assertEqual(controller._private_frame(SimpleNamespace(fileno=lambda:r),c,deadline),{'inference_key':'NONSECRET_UNIT_KEY_123456'})
                    else:
                        with self.assertRaises(ValueError):controller._private_frame(SimpleNamespace(fileno=lambda:r),c,deadline)
            finally:
                os.close(r)
                if w is not None:os.close(w)

    def test_private_partial_frame_or_missing_EOF_times_out_before_execute(self):
        c=clock()
        for body in (b'{"inference_key":',b'{"inference_key":"NONSECRET_UNIT_KEY_123456"}\n'):
            r,w=os.pipe()
            try:
                os.write(w,body);start=time.monotonic()
                with mock.patch.object(controller,'INPUT_SECONDS',.01),self.assertRaises(ValueError):
                    controller._private_frame(SimpleNamespace(fileno=lambda:r),c,(c['deadline'],c['deadline_wall']))
                self.assertLess(time.monotonic()-start,.5)
            finally:os.close(r);os.close(w)

    def test_main_passes_same_clipped_entry_deadline_and_rejects_expired_clock(self):
        c=clock();cref=self.put(self.root/'clock.json',c)
        a={'root':str(self.root),'grant':{},'input_review':{},'clock':cref,'preparation':{},'candidate':{},'admission':{},'nonce':fresh(),'controller_sha256':'a'*64}
        self.put(self.root/'activation.json',a);r,w=os.pipe();os.write(w,b'{"inference_key":"NONSECRET_UNIT_KEY_123456"}\n');os.close(w)
        with os.fdopen(r,'rb')as stream,mock.patch.object(controller.sys,'stdin',SimpleNamespace(buffer=stream)), \
          mock.patch.object(controller,'execute',return_value={'status':'NONSECRET_UNIT_SUCCESS'})as execute, \
          mock.patch.object(controller.signal,'signal'),mock.patch.object(controller.signal,'setitimer')as timer, \
          mock.patch.object(controller.signal,'getitimer',side_effect=[(0,0),(900,0)]),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(controller.main(['--activation',str(self.root/'activation.json')]),0)
        passed=execute.call_args.kwargs['_entry_deadline'];self.assertLessEqual(passed[0],c['deadline']);self.assertLessEqual(passed[1],c['deadline_wall'])
        self.assertLessEqual(timer.call_args_list[1].args[1],900)
        c.update(started=c['started']-1000,deadline=c['deadline']-1000,started_wall=c['started_wall']-1000,deadline_wall=c['deadline_wall']-1000)
        a['clock']=self.put(self.root/'clock.json',c);self.put(self.root/'activation.json',a)
        with mock.patch.object(controller,'_private_frame',side_effect=AssertionError('private input after expiry'))as frame, \
          mock.patch.object(controller.signal,'signal'),mock.patch.object(controller.signal,'setitimer'),mock.patch.object(controller.signal,'getitimer',return_value=(0,0)),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(controller.main(['--activation',str(self.root/'activation.json')]),2)
        frame.assert_not_called()

    def test_active_or_pending_outer_timer_is_not_borrowed_or_reset(self):
        for timer,pending in ((12,frozenset()),(0,{controller.signal.SIGALRM})):
            with mock.patch.object(controller.signal,'getitimer',return_value=(timer,0)),mock.patch.object(controller.signal,'sigpending',return_value=pending), \
              mock.patch.object(controller.signal,'setitimer')as arm,mock.patch.object(controller,'_sdk',side_effect=AssertionError('SDK under outer timer'))as sdk:
                with self.assertRaises(ValueError):controller.execute({},inference_key='NONSECRET_UNIT_KEY_123456')
                with self.assertRaises(ValueError):controller.main(['--activation',str(self.root/'activation.json')])
            arm.assert_not_called();sdk.assert_not_called()

    def test_early_grant_and_clock_selectors_refuse_external_body_before_read(self):
        external=self.put(self.top/'external-private-shaped-body.json',{'NONSECRET_DO_NOT_READ':True})
        a={'root':str(self.root),'grant':external,'input_review':{},'clock':external,'preparation':{},
          'candidate':{},'admission':{},'nonce':fresh(),'controller_sha256':'a'*64}
        self.put(self.root/'activation.json',a)
        with mock.patch.object(controller,'bound_reference',side_effect=AssertionError('external body read'))as reader, \
          mock.patch.object(controller,'_sdk',side_effect=AssertionError('SDK before selector'))as sdk, \
          mock.patch.object(controller.signal,'signal'),mock.patch.object(controller.signal,'setitimer'), \
          mock.patch.object(controller.signal,'getitimer',return_value=(0,0)),contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(ValueError):controller.execute(a,inference_key='NONSECRET_UNIT_KEY_123456')
            self.assertEqual(controller.main(['--activation',str(self.root/'activation.json')]),2)
        reader.assert_not_called();sdk.assert_not_called()
        self.assertFalse((self.root/'attempt-intent.json').exists())

    def test_all_Docker_selectors_are_denied_before_admission_identity_or_reconcile(self):
        for name in controller.DOCKER_SELECTORS:
            q=SimpleNamespace(lab=SimpleNamespace(default_lock_file=mock.Mock(side_effect=AssertionError('later host gate'))))
            with mock.patch.dict(os.environ,{name:''}),self.assertRaises(ValueError):controller._host_identity(q)
            q.lab.default_lock_file.assert_not_called()

    def test_single_cleanup_endpoint_covers_backend_services_Registry_and_no_child_is_invented(self):
        a,events=self.pipeline(cleanup_steps=(6,14,3));terminal=controller.execute(a,inference_key='NONSECRET_UNIT_KEY_123456')
        calls=self.pipeline_timer_calls;first=next(index for index,(_,seconds)in enumerate(calls)if 0<seconds<=24.01)
        later=[seconds for _,seconds in calls[first:]if seconds>0]
        self.assertLessEqual(max(later),24.01);self.assertTrue(any(seconds<=1.01 for seconds in later))
        self.assertNotIn('child',terminal['evidence']['metadata_roles_present'])
        self.assertFalse((self.root/'cells'/controller.CELL/'child-completion.json').exists())
        self.assertIn('original_Registry_close',events);self.assertFalse(terminal['native_qualification_credit'])


if __name__=='__main__':unittest.main()
