"""Offline harness/oracle checks with local HTTP; no Pi/Docker/model qualification."""
import importlib.util
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
HERE = REPO/'tools/qualification'
sys.path.insert(0, str(HERE))
import fixtures
spec = importlib.util.spec_from_file_location('qualification_driver', HERE/'pi_release.py')
driver = importlib.util.module_from_spec(spec); spec.loader.exec_module(driver)
spec = importlib.util.spec_from_file_location('qualification_service', HERE/'service.py')
service = importlib.util.module_from_spec(spec); spec.loader.exec_module(service)


class PlanningTests(unittest.TestCase):
    def test_contamination_fail_requires_actual_write_discard_no_successor_and_physical_cleanup(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);run=root/'run';project=root/'project';project.mkdir()
            (project/'TASK.md').write_text('unchanged')
            stage=run/'stages'/'assigned';logs=run/'agent-1-diagnostic'/'segments'/'segment'
            logs.mkdir(parents=True);(stage/'segments').mkdir(parents=True)
            driver.atomic(stage/'descriptor.json',{'kind':'agent','label':'agent-1-diagnostic','stage_id':'assigned'})
            receipt={'schema':1,'status':'removed','workspace':'discarded'}
            driver.atomic(stage/'application-credentials.json',receipt)
            driver.atomic(stage/'segments'/'segment.json',{'logs':str(logs)})
            driver.atomic(run/'files-before.json',driver.lab.tree_hashes(project))
            physical={'exit_code':0,'termination_reason':'completed','cleanup_confirmed':True}
            driver.atomic(logs/'process.json',physical)
            command="python3 -c \"import os;open('leak.txt','w').write(os.environ['PI_APP_KEY'])\""
            events=[{'type':'tool_execution_start','toolName':'bash','toolCallId':'write',
                     'args':{'command':command}},
                    {'type':'tool_execution_end','toolName':'bash','toolCallId':'write','isError':False}]
            def save_events(): (logs/'stdout.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events))
            save_events()
            result={'status':'FAIL','exit_code':1,'workspace':str(run/'workspace'),'checks':[],
                    'scoring':{'status':'skipped','reason':'cleanup_unconfirmed'},
                    'agents':[{'process':{'cleanup_confirmed':False,'termination_reason':'application_credential_cleanup',
                                         'application_credentials':receipt}}]}
            def validate(value=result):
                stopped=driver.validate_contamination_execution(run,project,value)
                driver.validate_cell_execution('contamination',value,{'exit_code':1},{},1,1,stopped)
            validate()
            for field,value in (('status','PASS'),('agents',[]),('checks',[{'name':'unexpected'}]),
                                ('scoring',{'status':'completed'}),('workspace',str(project))):
                with self.subTest(field=field),self.assertRaises(RuntimeError):validate({**result,field:value})
            physical['cleanup_confirmed']=False;driver.atomic(logs/'process.json',physical)
            with self.assertRaisesRegex(RuntimeError,'cleanup'):validate()
            physical['cleanup_confirmed']=True;physical['exit_code']=124;driver.atomic(logs/'process.json',physical)
            with self.assertRaisesRegex(RuntimeError,'unrelated'):validate()
            physical['exit_code']=0;driver.atomic(logs/'process.json',physical)
            events[1]['isError']=True;save_events()
            with self.assertRaisesRegex(RuntimeError,'canary write'):validate()
            events[1]['isError']=False;save_events()
            driver.atomic(stage/'application-credentials.json',{'status':'cleanup_unconfirmed'})
            with self.assertRaisesRegex(RuntimeError,'sensitive cleanup'):validate()
            driver.atomic(stage/'application-credentials.json',receipt)
            second=run/'stages'/'successor';second.mkdir()
            driver.atomic(second/'descriptor.json',{'kind':'agent','label':'agent-2-forbidden-successor'})
            with self.assertRaisesRegex(RuntimeError,'successor'):validate()
            (second/'descriptor.json').unlink();second.rmdir()
            (run/'workspace').mkdir()
            with self.assertRaisesRegex(RuntimeError,'snapshot'):validate()
            (run/'workspace').rmdir();(project/'TASK.md').write_text('changed')
            with self.assertRaisesRegex(RuntimeError,'unchanged source'):validate()

    def test_context_over_limit_requires_correct_cause_no_inference_and_cleanup(self):
        report={'process':{'exit_code':2,'cleanup_confirmed':True},
                'stderr_tail':'Configured context 32769 exceeds reported effective server context 32768'}
        driver.validate_context_guard({'exit_code':2},report,1,1)
        for bad,before,after in (({**report,'stderr_tail':'unrelated provider error'},1,1),
                (report,1,2),({**report,'process':{'exit_code':2,'cleanup_confirmed':False}},1,1)):
            with self.assertRaisesRegex(RuntimeError,'before inference'):
                driver.validate_context_guard({'exit_code':2},bad,before,after)

    def test_fault_acceptance_rejects_wrong_failure_cause_exit_cleanup_and_segment_count(self):
        process={'cleanup_confirmed':True,'timed_out':True,'exit_code':124,'termination_reason':'timeout','segments':[]}
        result={'status':'FAIL','exit_code':1,'agents':[{'process':process}], 'scoring':{'status':'completed'}}
        invocation={'exit_code':1}
        driver.validate_cell_execution('timeout',result,invocation,{},1,1)
        for field,value in (('timed_out',False),('exit_code',1),('termination_reason','process_error'),('cleanup_confirmed',False)):
            bad=copy.deepcopy(result);bad['agents'][0]['process'][field]=value
            with self.subTest(field=field),self.assertRaises(RuntimeError):
                driver.validate_cell_execution('timeout',bad,invocation,{},1,1)
        with self.assertRaisesRegex(RuntimeError,'exit disagree'):
            driver.validate_cell_execution('timeout',result,{'exit_code':0},{},1,1)
        with self.assertRaisesRegex(RuntimeError,'segment count'):
            driver.validate_cell_execution('timeout',result,invocation,{},1,2)
        with self.assertRaisesRegex(RuntimeError,'assistant cause'):
            driver.validate_cell_execution('length',result,invocation,{},1,1)
        process['segments']=[{'evidence':{'unsuccessful_messages':['length']}}]
        driver.validate_cell_execution('length',result,invocation,{},1,1)
        with self.assertRaisesRegex(RuntimeError,'assistant cause'):
            driver.validate_cell_execution('error',result,invocation,{},1,1)
        cancelled={'status':'INTERRUPTED','exit_code':2,'agents':[],'scoring':{'status':'skipped'}}
        invocation={'exit_code':2,'action':'parent_cancelled_before_first_assistant'}
        stopped=[{'cleanup_confirmed':True,'cancelled':True,'termination_reason':'cancelled'}]
        driver.validate_cell_execution('abort',cancelled,invocation,{},1,1,stopped)
        with self.assertRaisesRegex(RuntimeError,'cleanup'):
            driver.validate_cell_execution('abort',cancelled,invocation,{},1,1,[])
        stopped[0]['cancelled']=False
        with self.assertRaisesRegex(RuntimeError,'Cancellation'):
            driver.validate_cell_execution('abort',cancelled,invocation,{},1,1,stopped)

    def test_crash_acceptance_requires_actual_kill_and_reconciled_controller_loss(self):
        first={'exit_code':-driver.signal.SIGKILL,'action':'owner_controller_killed_after_persisted_tool_round'}
        successor={'exit_code':0};abandoned={'controller_interruption':{'kind':'controller_lost','cleanup_confirmed':True}}
        driver.validate_crash_execution(first,successor,abandoned)
        for owner,next_process,record in (({**first,'exit_code':1},successor,abandoned),
                ({**first,'action':None},successor,abandoned),(first,{'exit_code':1},abandoned),
                (first,successor,{'controller_interruption':{'kind':'explicit_controller_cancel','cleanup_confirmed':True}}),
                (first,successor,{'controller_interruption':{'kind':'controller_lost','cleanup_confirmed':False}})):
            with self.assertRaisesRegex(RuntimeError,'actual owner kill'):
                driver.validate_crash_execution(owner,next_process,record)

    def test_image_reuse_freezes_immutable_ids_only_for_unchanged_admitted_runtime_inputs(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);source=driver.source_identity()
            prior={'base':driver.BASE,'buildkit':driver.BUILDKIT,'platform':'linux/arm64','source':copy.deepcopy(source)}
            prior['source']['harness_sha256']='previous-collector'
            images={profile+'-'+release:{'id':'sha256:'+format(index,'064x'),'capabilities':{'pi':release}}
                    for index,(release,profile) in enumerate((r,p) for r in driver.release_contracts.RELEASES for p in ('core','browser'))}
            def save():
                driver.atomic(root/'manifest.json',prior)
                driver.atomic(root/'integrity.json',{'manifest_sha256':driver.hashlib.sha256((root/'manifest.json').read_bytes()).hexdigest()})
                driver.atomic(root/'state.json',{'phase':'images_admitted','images':images})
            save();self.assertEqual(driver.reuse_admitted_images(root,source),{key:value['id'] for key,value in images.items()})
            prior['source']['runner']='changed';save()
            with self.assertRaisesRegex(ValueError,'scope'):driver.reuse_admitted_images(root,source)
            prior['source']['runner']=source['runner'];images['core-0.87.1']['id']='mutable:tag';save()
            with self.assertRaisesRegex(ValueError,'immutable'):driver.reuse_admitted_images(root,source)
            (root/'manifest.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'manifest changed'):driver.reuse_admitted_images(root,source)

    def test_service_cleanup_requires_owned_network_absence_before_private_store_removal(self):
        for network_exists in (True,False):
            with self.subTest(network_exists=network_exists), tempfile.TemporaryDirectory() as td:
                root=Path(td);authority=object.__new__(driver.Services)
                authority.root=root;authority.private=root/'private';authority.private.mkdir()
                authority.name='owned-authority';authority.network='owned-network'
                def command(argv,**kwargs):
                    self.assertLessEqual(kwargs['timeout'],10)
                    if argv[1:3]==['container','inspect']:
                        return subprocess.CompletedProcess(argv,1,stdout='',stderr='No such container: owned-authority')
                    if argv[1:3]==['network','inspect']:
                        return subprocess.CompletedProcess(argv,0 if network_exists else 1,stdout='',
                            stderr='' if network_exists else 'network owned-network not found')
                    return subprocess.CompletedProcess(argv,0,stdout='',stderr='')
                with mock.patch.object(driver,'command',side_effect=command):
                    if network_exists:
                        with self.assertRaisesRegex(RuntimeError,'network cleanup'):authority.close()
                        self.assertTrue(authority.private.exists())
                        self.assertFalse((root/'service-cleanup.json').exists())
                    else:
                        authority.close()
                        self.assertFalse(authority.private.exists())
                        self.assertTrue(json.loads((root/'service-cleanup.json').read_text())['network_confirmed_absent'])

    def test_browser_scorer_is_single_json_and_preserves_required_read_tool(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);project,planpath=fixtures.prepare(root/'fixture','browser','nonce')
            plan=json.loads(planpath.read_text())
            self.assertEqual(plan['agents'][0]['require_tools'],['read','bash'])
            self.assertIn('Use the read tool',plan['agents'][0]['prompt'])
            code=(root/'fixture/check.py').read_text().replace('/opt/pi-scorer/expected.json',str(root/'fixture/expected.json'))
            script=root/'check.py'
            stub="import subprocess\nsubprocess.run=lambda *a,**k: subprocess.CompletedProcess(a,0,stdout='ARM64_DOM_INTERACTION_OK\\n')\n"
            script.write_text(stub+code)
            env=driver.checker_env({'PI_LAB_RUN_ID':'run','PI_LAB_ATTEMPT_ID':'attempt'})
            result=subprocess.run([sys.executable,str(script)],cwd=project,env=env,capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads(result.stdout)['score'],1)
            self.assertEqual(len(result.stdout.splitlines()),1)
            self.assertIn('ARM64_DOM_INTERACTION_OK',result.stderr)
            script.write_text(stub.replace('ARM64_DOM_INTERACTION_OK','forged-proof')+code)
            bad=subprocess.run([sys.executable,str(script)],cwd=project,env=env,capture_output=True,text=True,timeout=5)
            self.assertNotEqual(bad.returncode,0)
            self.assertEqual(bad.stdout,'')

    def test_control_poll_tolerates_only_missing_initial_stage_state(self):
        with tempfile.TemporaryDirectory() as td:
            folder=Path(td);stage=folder/'runs/run-id/stages/stage-id';stage.mkdir(parents=True)
            driver.atomic(stage/'descriptor.json', {'kind':'agent','stage_id':'stage-id'})
            self.assertEqual(driver.active_run(folder),(None,None))
            driver.atomic(stage/'state.json', {'status':'running'})
            self.assertEqual(driver.active_run(folder)[0],folder/'runs/run-id')
            (stage/'state.json').write_text('malformed')
            with self.assertRaises(json.JSONDecodeError):driver.active_run(folder)

    def test_run_lookup_and_segment_counts_ignore_latest_alias(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);folder=root/'cells/cell';run=folder/'runs/run-id'
            stage=run/'stages/stage-id';(stage/'segments').mkdir(parents=True)
            driver.atomic(run/'result.json', {'status':'PASS'})
            driver.atomic(stage/'descriptor.json', {'kind':'agent','stage_id':'stage-id'})
            driver.atomic(stage/'state.json', {'status':'running'})
            driver.atomic(stage/'segments/segment.json', {})
            (folder/'runs/latest').symlink_to('run-id', target_is_directory=True)
            self.assertEqual(driver.run_result(folder), (run, {'status':'PASS'}))
            self.assertEqual(driver.active_run(folder)[0], run)
            self.assertEqual(driver.registered_segments(root), 1)
            second=folder/'runs/second';second.mkdir();driver.atomic(second/'result.json', {})
            with self.assertRaisesRegex(RuntimeError,'exactly one'):driver.run_result(folder)

    def test_failed_cell_retains_actual_launched_segment_count(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);endpoint={'model':'synthetic','api_key_env':'KEY'}
            cell={'id':'test-cell','kind':'smoke','segments_max':1}
            manifest={'endpoint_sha256':driver.provenance.digest({'model':'synthetic'}),
                      'execution_seconds_ceiling':10,'cells':[cell]}
            state={'phase':'images_admitted','images':{'core-0.87.1':{'id':'synthetic'}},
                   'cells':[],'attempted_cells':[],'participant_segments':0}
            def fail(*_args,**_kwargs):
                driver.atomic(root/'cells/test-cell/runs/run-id/stages/stage/segments/segment.json', {})
                raise RuntimeError('deliberate observation failure')
            with mock.patch.object(driver,'verify',return_value=(manifest,state)), \
                 mock.patch.object(driver.lab,'resolve_endpoint_path',return_value='unused'), \
                 mock.patch.object(driver.lab,'load_endpoint',return_value=endpoint), \
                 mock.patch.object(driver,'Services',return_value=mock.Mock()), \
                 mock.patch.object(driver,'cell_run',side_effect=fail):
                with self.assertRaisesRegex(RuntimeError,'observation'):driver.collect(root,'synthetic-session')
            final=json.loads((root/'state.json').read_text())
            self.assertEqual(final['participant_segments'],1)
            self.assertEqual(final['phase'],'blocked')
            self.assertEqual(final['failed_or_blocked_cell'],'test-cell')

    def test_matrix_is_fixed_serial_and_distinguishes_real_inference(self):
        cells = driver.cells()
        self.assertEqual(len(cells), 60)
        self.assertEqual(sum(c['segments_max'] for c in cells), 90)
        self.assertEqual(len({c['id'] for c in cells}), 60)
        self.assertEqual(sum(c['real_model'] for c in cells), 36)
        self.assertTrue(all(not c['real_model'] for c in cells if c['gate'] == 'N09'))
        self.assertEqual([c['gate'] for c in cells], sorted([c['gate'] for c in cells]))

    def test_frozen_source_identity_includes_profiles_security_and_subjects(self):
        value = driver.source_identity()
        self.assertIn('assets/profiles/fixture-lookup/profile.json', value['input_files'])
        self.assertIn('assets/profiles/fixture-lookup/profile.pi-1.2.0.json', value['input_files'])
        self.assertIn('assets/security/chromium-userns.json', value['input_files'])
        self.assertIn('examples/python-project/slug.py', value['input_files'])

    def test_all_generated_plans_admit_exact_budgets_and_no_literal_credentials(self):
        for kind in ('smoke', 'protocol', 'length', 'error', 'abort', 'timeout', 'recovery',
                     'discovery', 'boundary', 'contamination', 'provider-fatal', 'crash', 'credentials', 'browser'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as td:
                project, path = fixtures.prepare(Path(td)/'fixture', kind, 'nonsecret-nonce',
                    child_service='http://diagnostic.invalid:8080', references={'A':'QA_A','B':'QA_B'})
                plan = driver.lab.validate_plan(json.loads(path.read_text()), path.parent)
                self.assertTrue(all(c['timeout_seconds'] <= 120 for c in plan['checks']))
                self.assertTrue(all(a['max_total_tokens'] <= 64000 for a in plan['agents']))
                if kind == 'contamination': self.assertEqual(len(plan['agents']), 2)
                if kind == 'timeout': self.assertEqual(plan['agents'][0]['application_secrets'], {'PI_APP_KEY':'QA_A'})
                if kind == 'credentials':
                    for task in plan['agents']:
                        self.assertIn('exactly once',task['prompt'])
                        self.assertIn('non-idempotent application action',task['prompt'])
                        self.assertIn('Verify by reading the saved',task['prompt'])

    def test_independent_smoke_oracle_rejects_forged_proof_and_checks_are_key_free(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            # Execute the actual generated oracle after only adapting its fixed mount path locally.
            project, _ = fixtures.prepare(root/'fixture', 'smoke', 'nonce')
            code = (root/'fixture/check.py').read_text().replace('/opt/pi-scorer/expected.json', str(root/'fixture/expected.json'))
            script = root/'check.py'; script.write_text(code)
            env = {**os.environ, 'PI_LAB_RUN_ID':'run', 'PI_LAB_ATTEMPT_ID':'attempt', 'PYTHONDONTWRITEBYTECODE':'1'}
            (project/'proof.json').write_text(json.dumps({'nonce':'nonce','sum':356}))
            good = subprocess.run([sys.executable,str(script)],cwd=project,env=env,capture_output=True,text=True,timeout=5)
            self.assertEqual(good.returncode,0,good.stderr)
            self.assertEqual(json.loads(good.stdout)['score'],1)
            (project/'proof.json').write_text(json.dumps({'nonce':'forged','sum':356}))
            bad = subprocess.run([sys.executable,str(script)],cwd=project,env=env,capture_output=True,timeout=5)
            self.assertNotEqual(bad.returncode,0)
            (project/'proof.json').write_text(json.dumps({'nonce':'nonce','sum':356}))
            bad = subprocess.run([sys.executable,str(script)],cwd=project,env={**env,'PI_APP_KEY':'synthetic'},capture_output=True,timeout=5)
            self.assertNotEqual(bad.returncode,0)

    def test_shortened_or_resealed_matrix_cannot_qualify(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/'qualification'
            endpoint={'model':'synthetic','api_key_env':'SYNTHETIC','context_window':32768,'max_tokens':4096}
            with mock.patch.object(driver.lab,'resolve_endpoint_path',return_value='unused'), \
                 mock.patch.object(driver.lab,'load_endpoint',return_value=endpoint):
                driver.freeze(root,'synthetic-session')
            value=json.loads((root/'manifest.json').read_text());value['cells']=[]
            driver.atomic(root/'manifest.json',value)
            with self.assertRaisesRegex(ValueError,'manifest changed'):driver.verify(root)
            driver.atomic(root/'integrity.json',{'manifest_sha256':driver.hashlib.sha256((root/'manifest.json').read_bytes()).hexdigest()})
            with self.assertRaisesRegex(ValueError,'matrix'):driver.verify(root)

    def test_cleanup_failure_never_returns_a_successful_collection(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);endpoint={'model':'synthetic','api_key_env':'KEY'}
            cell={'id':'test-cell','kind':'smoke','segments_max':1}
            manifest={'endpoint_sha256':driver.provenance.digest({'model':'synthetic'}),
                      'execution_seconds_ceiling':10,'cells':[cell]}
            state={'phase':'images_admitted','images':{'core-0.87.1':{'id':'synthetic'}},
                   'cells':[],'attempted_cells':[],'participant_segments':0}
            authority=mock.Mock();authority.close.side_effect=RuntimeError('cleanup unconfirmed')
            def cell_run(*_args,**_kwargs):
                state['participant_segments']+=1
                return {'id':'test-cell','passed':True,'segments':1}
            with mock.patch.object(driver,'verify',return_value=(manifest,state)), \
                 mock.patch.object(driver.lab,'resolve_endpoint_path',return_value='unused'), \
                 mock.patch.object(driver.lab,'load_endpoint',return_value=endpoint), \
                 mock.patch.object(driver,'Services',return_value=authority), \
                 mock.patch.object(driver,'cell_run',side_effect=cell_run):
                with self.assertRaisesRegex(RuntimeError,'cleanup'):driver.collect(root,'synthetic-session')
            self.assertEqual(json.loads((root/'state.json').read_text())['phase'],'blocked')

    def test_completed_cell_counts_cannot_replace_registered_segment_inventory(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);endpoint={'model':'synthetic','api_key_env':'KEY'}
            cell={'id':'test-cell','kind':'smoke','segments_max':1}
            manifest={'endpoint_sha256':driver.provenance.digest({'model':'synthetic'}),
                      'execution_seconds_ceiling':10,'cells':[cell]}
            state={'phase':'images_admitted','images':{'core-0.87.1':{'id':'synthetic'}},
                   'cells':[],'attempted_cells':[],'participant_segments':0}
            def phantom(*_args,**_kwargs):
                state['participant_segments']=1
                return {'id':'test-cell','passed':True,'segments':1}
            with mock.patch.object(driver,'verify',return_value=(manifest,state)), \
                 mock.patch.object(driver.lab,'resolve_endpoint_path',return_value='unused'), \
                 mock.patch.object(driver.lab,'load_endpoint',return_value=endpoint), \
                 mock.patch.object(driver,'Services',return_value=mock.Mock()), \
                 mock.patch.object(driver,'cell_run',side_effect=phantom):
                with self.assertRaisesRegex(RuntimeError,'completion'):driver.collect(root,'synthetic-session')
            final=json.loads((root/'state.json').read_text())
            self.assertEqual(final['phase'],'blocked')
            self.assertEqual(final['participant_segments'],0)
            self.assertIn('inventory',final['reason'])

    def test_sensitive_cleanup_checks_assigned_runtime_and_all_public_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);stage=root/'stages/assigned';stage.mkdir(parents=True)
            runtime=root/'children/assigned';runtime.mkdir(parents=True)
            control=root/'controls/assigned';control.mkdir(parents=True)
            driver.atomic(stage/'descriptor.json',{'runtime':str(runtime),'control':str(control)})
            driver.atomic(stage/'application-credentials.json',{'status':'removed'})
            with self.assertRaisesRegex(RuntimeError,'raw runtime'):driver.sensitive_clean(root,['synthetic-app-value'])
            runtime.rmdir()
            unassigned=root/'children/unassigned/sessions';unassigned.mkdir(parents=True)
            (unassigned/'session.jsonl').write_text('key-free unassigned state')
            driver.sensitive_clean(root,['synthetic-app-value'])
            (root/'leak.json').write_text(json.dumps({'value':'synthetic-app-value'}))
            with self.assertRaisesRegex(RuntimeError,'canary'):driver.sensitive_clean(root,['synthetic-app-value'])

    def test_crash_integrity_never_invents_segments_or_skips_canary_checks(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);runs=[root/'first',root/'successor']
            for run in runs:run.mkdir()
            with self.assertRaisesRegex(RuntimeError,'registered'):driver.crash_integrity(runs,['synthetic-app-value'])
            for run in runs:
                folder=run/'stages/agent/segments';folder.mkdir(parents=True)
                (folder/'segment.json').write_text('{}')
            self.assertEqual(driver.crash_integrity(runs,['synthetic-app-value']),2)
            (runs[0]/'leak.json').write_text(json.dumps({'value':'synthetic-app-value'}))
            with self.assertRaisesRegex(RuntimeError,'canary'):driver.crash_integrity(runs,['synthetic-app-value'])


class ServiceTests(unittest.TestCase):
    def test_atomic_control_visibility_wait_is_bounded_and_does_not_hide_malformed_data(self):
        authority = service.Authority('unused', 'unused')
        with mock.patch.object(Path, 'read_text', side_effect=[FileNotFoundError(), '{"mode":"settings"}']), mock.patch.object(service.time, 'sleep') as sleep:
            self.assertEqual(authority.config(), {'mode':'settings'})
            sleep.assert_called_once_with(.01)
        with mock.patch.object(Path, 'read_text', side_effect=FileNotFoundError()), mock.patch.object(service.time, 'monotonic', side_effect=[0, 1]):
            with self.assertRaises(FileNotFoundError): authority.config()
        with mock.patch.object(Path, 'read_text', return_value='malformed'), mock.patch.object(service.time, 'sleep') as sleep:
            with self.assertRaises(json.JSONDecodeError): authority.config()
            sleep.assert_not_called()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.control = self.root/'control.json'
        self.settings = {'mode':'settings','nonce':'nonce','app_keys':{'A':'synthetic-app-key-AAAA','B':'synthetic-app-key-BBBB'},
                         'inference_key':'synthetic-inference-key','observer_key':'synthetic-observer-key'}
        self.control.write_text(json.dumps(self.settings))
        self.authority = service.Authority(self.control,self.root/'observations.json')
        self.server = ThreadingHTTPServer(('127.0.0.1',0),service.handler(self.authority))
        self.thread = threading.Thread(target=self.server.serve_forever,daemon=True); self.thread.start()
        self.addCleanup(self.stop)
        self.base = 'http://127.0.0.1:'+str(self.server.server_port)

    def stop(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2)

    def post(self,path,body,headers=None):
        req=urllib.request.Request(self.base+path,data=json.dumps(body).encode(),headers=headers or {})
        with urllib.request.urlopen(req,timeout=3) as response:return response.read()

    def test_stream_and_safe_observations_do_not_capture_prompts_headers_or_nested_keys(self):
        key='synthetic-sensitive-tool-value'
        body={'model':'qualification-diagnostic','stream':True,'messages':[{'role':'user','content':key}],
              'temperature':.5,'chat_template_kwargs':{'secret':key,'enable_thinking':True}}
        wire=self.post('/v1/chat/completions',body,{'Authorization':'Bearer '+self.settings['inference_key']})
        self.assertIn(b'data: [DONE]',wire)
        observed=(self.root/'observations.json').read_text()
        self.assertNotIn(key,observed); self.assertNotIn(self.settings['inference_key'],observed)
        value=json.loads(observed)['requests'][0]
        self.assertEqual(value['temperature'],.5)
        self.assertEqual(value['chat_template_kwargs'],{'enable_thinking':True})

    def test_actor_authority_distinguishes_keys_and_exposes_only_identity_effects(self):
        for role in ('A','B'):
            value=json.loads(self.post('/effect',{'nonce':'nonce'},{'X-Agent-Key':self.settings['app_keys'][role]}))
            self.assertEqual(value['role'],role)
        with self.assertRaises(urllib.error.HTTPError):self.post('/effect',{'nonce':'nonce'},{'X-Agent-Key':'wrong'})
        observed=(self.root/'observations.json').read_text()
        self.assertNotIn(self.settings['app_keys']['A'],observed)
        self.assertEqual(len(json.loads(observed)['effects']),2)

    def test_rate_limit_and_length_are_injected_only_into_streaming_inference(self):
        headers={'Authorization':'Bearer '+self.settings['inference_key']}
        self.settings['mode']='rate-error'; self.control.write_text(json.dumps(self.settings))
        body={'model':'qualification-diagnostic','stream':False,'messages':[]}
        self.assertIn(b'OK',self.post('/v1/chat/completions',body,headers))
        body['stream']=True
        with self.assertRaises(urllib.error.HTTPError) as raised:self.post('/v1/chat/completions',body,headers)
        self.assertEqual(raised.exception.code,429)
        self.settings['mode']='length'; self.control.write_text(json.dumps(self.settings))
        self.assertIn(b'"finish_reason": "length"',self.post('/v1/chat/completions',body,headers))

    def test_boundary_batches_fit_the_frozen_turn_budget(self):
        self.settings['mode']='boundary'; self.control.write_text(json.dumps(self.settings))
        headers={'Authorization':'Bearer '+self.settings['inference_key']}
        counts=[]
        for completed in (0,1,4):
            body={'model':'qualification-diagnostic','stream':True,
                  'messages':[{'role':'tool','content':'result'} for _ in range(completed)]}
            wire=self.post('/v1/chat/completions',body,headers).decode()
            packets=[json.loads(line[6:]) for line in wire.splitlines() if line.startswith('data: {')]
            counts.append(len(packets[0]['choices'][0]['delta']['tool_calls']))
        self.assertEqual(counts,[1,3,3])
        self.assertLessEqual(len(counts)+1,fixtures.DIAGNOSTIC_BUDGET['max_turns'])


if __name__ == '__main__': unittest.main()
