"""Frozen native harness contracts; these fixtures never launch Docker or a model."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parents[1]/'tools/qualification'
sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('parallel_qualification',HERE/'parallel.py')
qualification=importlib.util.module_from_spec(spec);spec.loader.exec_module(qualification)
import experiments
import pi_lab as lab
import secret_store


class QualificationTests(unittest.TestCase):
    def test_segment_inventory_counts_latest_alias_once_and_all_real_attempts(self):
        import uuid
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);runs=root/'runs';runs.mkdir();created=[]
            for unused in range(2):
                run=runs/str(uuid.uuid4());segments=run/'stages'/str(uuid.uuid4())/'segments';segments.mkdir(parents=True)
                (segments/(str(uuid.uuid4())+'.json')).write_text('{}');created.append(run)
            (runs/'latest').symlink_to(created[-1])
            self.assertEqual(qualification.count_segments(root),2)
            self.assertEqual(qualification.canonical_runs(runs),sorted(created))
    def test_segment_inventory_rejects_foreign_or_unexpected_aliases(self):
        import uuid
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);runs=root/'runs';runs.mkdir();outside=root/str(uuid.uuid4());outside.mkdir()
            (runs/'latest').symlink_to(outside)
            with self.assertRaises(RuntimeError):qualification.count_segments(root)
            (runs/'latest').unlink();(runs/str(uuid.uuid4())).symlink_to(outside)
            with self.assertRaises(RuntimeError):qualification.count_segments(root)
    def test_segment_inventory_rejects_linked_stages_and_segment_files(self):
        import uuid
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);run=root/'runs'/str(uuid.uuid4());run.mkdir(parents=True);outside=root/'outside';outside.mkdir()
            (run/'stages').symlink_to(outside)
            with self.assertRaises(RuntimeError):qualification.count_segments(root)
            (run/'stages').unlink();stage=run/'stages'/str(uuid.uuid4());stage.mkdir(parents=True)
            segments=stage/'segments';segments.mkdir();target=outside/'record';target.write_text('{}')
            (segments/(str(uuid.uuid4())+'.json')).symlink_to(target)
            with self.assertRaises(RuntimeError):qualification.count_segments(root)

    def test_segment_inventory_rejects_linked_experiment_ancestor(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);real=root/'real';real.mkdir();(real/'runs').mkdir();alias=root/'alias';alias.symlink_to(real)
            with self.assertRaises(RuntimeError):qualification.count_segments(alias)
            with self.assertRaises(RuntimeError):qualification.canonical_runs(alias/'runs')

    def test_fixed_matrix_contains_both_releases_three_positive_repetitions_and_eight_faults(self):
        rows=qualification.matrix();self.assertEqual(len(rows),24)
        self.assertEqual(sum(r['cells'] for r in rows),124);self.assertEqual(sum(r['segments_ceiling'] for r in rows),192)
        for release in ('0.87.1','1.2.0'):
            subset=[r for r in rows if r['release']==release]
            self.assertEqual({r['kind'] for r in subset if not r['real_model']},set(qualification.FAULTS))
            self.assertTrue(all(r['repetitions']==3 for r in subset if r['real_model']))

    def test_every_definition_freezes_before_dispatch_and_keeps_real_scripted_endpoints_distinct(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();qualification.controls.atomic(root/'worker.json',qualification.WORKER)
            manifest={'images':{p+'-'+r:{'id':'sha256:'+'a'*64} for p in ('core','browser') for r in ('0.87.1','1.2.0')},'coding_max_total_tokens':128000,'other_positive_max_total_tokens':128000}
            endpoint={'base_url':'http://example.invalid/v1','model':'synthetic-real-lane-label','api_key_env':'MODEL_KEY',
                      'context_window':32768,'max_tokens':1024}
            with mock.patch.object(qualification.pi_release,'native',side_effect=lambda image:image),mock.patch.object(secret_store,'resolve_secret',return_value=('synthetic-model-key-0123456789','fixture')):
                owner=qualification.AuthorityOwner(root,'sha256:'+'a'*64,endpoint)
            self.addCleanup(lambda:__import__('shutil').rmtree(owner.private) if owner.private.exists() else None)
            owner.host='http://127.0.0.1:12345';owner.child='http://host.docker.internal:12345'
            for batch in qualification.matrix():
                folder,exp=qualification.definition(root,batch,manifest,owner)
                metadata,matrix=experiments.verify(exp,lab)
                self.assertEqual(metadata['schema'],2);self.assertEqual(len(matrix['cells']),batch['cells'])
                expected=128000 if batch['real_model'] else 16000
                for cell in matrix['cells']:
                    plan=experiments.read_json(exp/cell['plan'])
                    self.assertTrue(all(agent['max_total_tokens']==expected for agent in plan['agents']))
                frozen=lab.load_endpoint(exp/matrix['cells'][0]['endpoint'])
                self.assertEqual(frozen['model'],endpoint['model'] if batch['real_model'] else 'qualification-diagnostic')
                if batch['kind']=='credentials':
                    for cell in matrix['cells']:
                        plan=experiments.read_json(exp/cell['plan']);self.assertTrue(plan['agents'][0]['application_secrets'])
                if batch['kind'] in ('boundary','discovery'):
                    for cell in matrix['cells']:
                        plan=experiments.read_json(exp/cell['plan']);self.assertFalse(any(t.get('application_secrets') for t in plan['agents']))
            self.assertFalse(list(root.glob('**/result.json')))

    def test_coding_budget_selection_is_bounded_and_invalid_values_reject_before_native_inspection(self):
        self.assertEqual(qualification.token_budget(64000),64000)
        self.assertEqual(qualification.token_budget(128000),128000)
        with tempfile.TemporaryDirectory() as temp,mock.patch.object(qualification.pi_release,'native') as native:
            root=Path(temp)/'uncreated'
            for invalid in (True,None,0,64001,128001,128000.0):
                with self.subTest(budget=invalid),self.assertRaises(ValueError):
                    qualification.freeze(root,'unused-images','unused-endpoint','fixture-session',invalid)
                with self.subTest(other_budget=invalid),self.assertRaises(ValueError):
                    qualification.freeze(root,'unused-images','unused-endpoint','fixture-session',64000,invalid)
            native.assert_not_called();self.assertFalse(root.exists())

from http.server import ThreadingHTTPServer
import threading
import urllib.request
import parallel_service


class ScriptedServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.config={'mode':'recovery-finish','dispatch_enabled':True,'inference_key':'synthetic-only-key-0123456789',
                     'observer_key':'synthetic-observer-0123456789','actors':[]}
        self.path=self.root/'config.json';self.path.write_text(json.dumps(self.config))
        self.authority=parallel_service.Authority(self.path,self.root/'observations.json')
        self.server=ThreadingHTTPServer(('127.0.0.1',0),parallel_service.handler(self.authority))
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start();self.addCleanup(self.close)
    def close(self):self.server.shutdown();self.server.server_close();self.thread.join(3)
    def post(self,messages):
        request=urllib.request.Request(f'http://127.0.0.1:{self.server.server_port}/v1/chat/completions',
                data=json.dumps({'model':'qualification-diagnostic','messages':messages,'stream':True,'max_tokens':128}).encode(),
                headers={'Authorization':'Bearer '+self.config['inference_key'],'Content-Type':'application/json'})
        with urllib.request.urlopen(request) as reply:body=reply.read().decode()
        chunks=[json.loads(line[6:]) for line in body.splitlines() if line.startswith('data: ') and line!='data: [DONE]']
        return chunks[0]['choices'][0]['delta']
    def test_continuation_executes_bash_after_interrupted_tool_history(self):
        history=[{'role':'tool','content':'TASK read'},{'role':'tool','content':'bash interrupted'}]
        result=self.post(history);self.assertEqual(result['tool_calls'][0]['function']['name'],'bash')
        done=self.post(history+[{'role':'tool','content':'RECOVERY_EFFECT_OK'}]);self.assertEqual(done['content'],'SCRIPTED_FINISHED')
    def test_fresh_pending_trial_still_reads_before_its_bash(self):
        first=self.post([]);self.assertEqual(first['tool_calls'][0]['function']['name'],'read')
        second=self.post([{'role':'tool','content':'TASK read'}]);self.assertEqual(second['tool_calls'][0]['function']['name'],'bash')
    def test_boundary_finishes_after_denied_and_allowed_tool_sequence(self):
        self.config['mode']='boundary';self.path.write_text(json.dumps(self.config))
        history=[];names=[]
        for unused in range(7):
            delta=self.post(history);names.append(delta['tool_calls'][0]['function']['name']);history.append({'role':'tool','content':'scripted observed tool result'})
        self.assertEqual(names,['read','write','edit','write','bash','write','bash'])
        self.assertEqual(self.post(history)['content'],'SCRIPTED_FINISHED')
    def test_truncation_is_selected_by_exact_controlled_request_without_file_update(self):
        import http.client
        self.config.update(routing_fixture=True,route_keys={'route-a':'synthetic-route-a','route-b':'synthetic-route-b'})
        self.path.write_text(json.dumps(self.config));before=self.path.read_bytes()
        def request(messages,key='synthetic-route-a'):
            connection=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=2)
            connection.request('POST','/route-a/v1/chat/completions',json.dumps({'messages':messages}),{'Authorization':'Bearer '+key})
            reply=connection.getresponse()
            try:return reply.status,reply.read()
            finally:connection.close()
        self.assertEqual(request([])[0],200)
        self.assertEqual(request([{'role':'user','content':'qualification:truncate-extra'}])[0],200)
        self.assertEqual(request(parallel_service.TRUNCATION_MESSAGES,'foreign')[0],401)
        with self.assertRaises(http.client.IncompleteRead):request(parallel_service.TRUNCATION_MESSAGES)
        self.assertEqual(self.path.read_bytes(),before)
    def test_truncation_marker_does_not_change_generic_scripted_chat(self):
        result=self.post(parallel_service.TRUNCATION_MESSAGES)
        self.assertEqual(result['tool_calls'][0]['function']['name'],'read')

import copy
import uuid


class FaultOracleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.rows=[];self.records=[];self.receipts=[]
        for index in range(4):
            trial=str(uuid.uuid4());row={'trial_id':trial,'configuration_digest':'synthetic-frozen-digest','attempts':[]};self.rows.append(row)
            if index>=2:continue
            run_id=str(uuid.uuid4());record={'run_id':run_id,'trial_id':trial,'status':'FAIL','exit_code':1,
                        'termination':{'reason':'process_error'},'scoring':{'status':'skipped'}}
            row['attempts']=[{'result':record}];self.records.append(record)
            folder=self.root/'runs'/run_id/'stages'/str(uuid.uuid4())/'segments';folder.mkdir(parents=True)
            logs=self.root/'logs'/run_id;logs.mkdir(parents=True)
            segment={'segment_id':str(uuid.uuid4()),'logs':str(logs),'evidence':{'unsuccessful_messages':[]}}
            qualification.controls.atomic(folder/(segment['segment_id']+'.json'),segment)
            receipt={'cleanup_confirmed':True,'timed_out':False,'exit_code':1,'termination_reason':'process_error'}
            self.receipts.append((logs/'process.json',receipt));qualification.controls.atomic(logs/'process.json',receipt)
        self.batch={'cells':4};self.invocation={'exit_code':1,'observation':{'barrier_released_after_overlap':True}}
    def write_receipts(self):
        for path,value in self.receipts:qualification.controls.atomic(path,value)
    def test_unrelated_failure_cannot_qualify_as_timeout(self):
        with self.assertRaisesRegex(RuntimeError,'unrelated FAIL'):qualification.validate_fault(self.root,'timeout',self.rows,self.invocation,self.batch)
        for record in self.records:record['termination']['reason']='timeout'
        for path,value in self.receipts:value.update(timed_out=True,exit_code=124,termination_reason='timeout')
        self.write_receipts();qualification.validate_fault(self.root,'timeout',self.rows,self.invocation,self.batch)
        self.rows[2]['attempts']=[{'result':self.records[0]}]
        with self.assertRaisesRegex(RuntimeError,'denominator'):qualification.validate_fault(self.root,'timeout',self.rows,self.invocation,self.batch)
    def test_unrelated_failure_cannot_qualify_as_provider_fatal(self):
        with self.assertRaisesRegex(RuntimeError,'unrelated FAIL'):qualification.validate_fault(self.root,'provider-fatal',self.rows,self.invocation,self.batch)
    def test_cancelled_status_without_actual_parent_action_cannot_qualify(self):
        for record in self.records:record.update(status='INTERRUPTED',exit_code=2);record['termination']['reason']='cancelled'
        for path,value in self.receipts:value.update(cancelled=True,termination_reason='cancelled')
        self.write_receipts();self.invocation['exit_code']=2
        with self.assertRaisesRegex(RuntimeError,'controlled parent cancellation'):qualification.validate_fault(self.root,'abort',self.rows,self.invocation,self.batch)
        self.invocation['observation']['cancelled']=True;qualification.validate_fault(self.root,'abort',self.rows,self.invocation,self.batch)


class FreezeIntegrityTests(unittest.TestCase):
    def test_changed_worker_policy_rejects_before_any_native_action(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve()/'frozen';images=Path(temp)/'images.json';endpoint=Path(temp)/'endpoint.json'
            images.write_text(json.dumps({p+'-'+r:{'id':'sha256:'+'a'*64} for p in ('core','browser') for r in ('0.87.1','1.2.0')}))
            endpoint.write_text(json.dumps({'base_url':'http://example.invalid/v1','model':'fixture','api_key_env':'MODEL_KEY','context_window':32768,'max_tokens':1024}))
            def native(image=None):return image or {'NCPU':18,'MemTotal':8*1024**3,'OSType':'linux','Architecture':'arm64'}
            with mock.patch.object(qualification.pi_release,'native',side_effect=native):qualification.freeze(str(root),str(images),str(endpoint),session='synthetic-confirmed-session')
            qualification.verify(root)
            bad=copy.deepcopy(qualification.WORKER);bad['runtime']['cpus']=3;qualification.controls.atomic(root/'worker.json',bad)
            with mock.patch.object(qualification,'command') as docker,self.assertRaisesRegex(ValueError,'policy bytes changed'):
                qualification.infrastructure(root)
            docker.assert_not_called()

class PositiveOracleTests(unittest.TestCase):
    setUp=FaultOracleTests.setUp
    def test_controller_failure_and_missing_native_segments_reject_even_with_pass_records(self):
        import comparisons
        rows=self.rows[:2]
        for record in self.records:record.update(status='PASS',exit_code=0,agents=[{'process':{}}])
        expected={row['trial_id']:{} for row in rows};batch={'kind':'lookup','cells':2}
        with mock.patch.object(comparisons,'expected_contracts',return_value=expected),mock.patch.object(comparisons,'assessment',return_value={'successful':True}):
            with self.assertRaisesRegex(RuntimeError,'controller failed'):qualification.validate_positive(self.root,{},rows,{'exit_code':2},batch)
            qualification.validate_positive(self.root,{},rows,{'exit_code':0},batch)
            segment=next((self.root/'runs'/self.records[0]['run_id']).glob('stages/*/segments/*.json'));segment.unlink()
            with self.assertRaisesRegex(RuntimeError,'stage/segment evidence'):qualification.validate_positive(self.root,{},rows,{'exit_code':0},batch)


class SentinelTests(unittest.TestCase):
    setUp=ScriptedServiceTests.setUp
    close=ScriptedServiceTests.close
    def test_get_sentinel_contact_is_retained_even_when_rejected(self):
        import urllib.error
        with self.assertRaises(urllib.error.HTTPError) as response:urllib.request.urlopen(f'http://127.0.0.1:{self.server.server_port}/sentinel')
        response.exception.close()
        self.assertTrue(self.authority.data['sentinel_network_effect'])

class NativeCliTests(unittest.TestCase):
    def test_all_four_image_gates_use_supported_key_free_native_cli_arguments(self):
        manifest={'session':'synthetic-confirmed-session','images':{p+'-'+r:{'id':'sha256:'+'a'*64} for p in ('core','browser') for r in ('0.87.1','1.2.0')}}
        for name in manifest['images']:
            arguments=qualification.image_arguments(Path('/tmp/synthetic-native-evidence'),manifest,name)
            parsed=lab.parser().parse_args(arguments)
            self.assertEqual(parsed.platform,'linux/arm64');self.assertEqual(parsed.policy,'reuse');self.assertNotIn('--session',arguments)
            self.assertEqual(parsed.pi_version,name.rsplit('-',1)[1]);self.assertNotIn('--endpoint',arguments)
