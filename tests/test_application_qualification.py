"""Maintainer matrix/freeze/real lease and closed oracles, no native execution."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[1];HERE=ROOT/'tools/qualification'
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime'),str(HERE)]
import application_client as helper_client
import application_contracts as c
import application_preparation
import experiments
import ownership_registry
import provenance
import resources
import secret_store
spec=importlib.util.spec_from_file_location('application_qualification_harness',HERE/'application_client.py')
harness=importlib.util.module_from_spec(spec);spec.loader.exec_module(harness)


def fresh():return str(uuid.uuid4())


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        self.output=self.root/'qualification';self.store=self.root/'store';self.store.mkdir(mode=0o700)
        self.endpoint={'base_url':'http://model.invalid:8000/v1','model':'explicit-reviewed-model','api_key_env':'MODEL_REFERENCE','context_window':262144,'max_tokens':8192}
        self.endpoint_path=self.write('endpoint.json',self.endpoint)
        self.images={};self.paths={}
        for release in harness.RELEASES:
            for profile in ('core','browser'):
                token={('0.87.1','core'):'a',('0.87.1','browser'):'d',('1.2.0','core'):'b',('1.2.0','browser'):'c'}[(release,profile)]
                image={'id':'sha256:'+token*64,'platform':'linux/arm64','capabilities':{'pi':release}}
                if profile=='browser':
                    image['capabilities']['chromium']='Explicit controlled Chromium'
                    receipt={'schema':1,'document_type':'browser_admission','status':'PASS','image':image,
                        'host':{'native_platform':'linux/arm64','selected_platform':'linux/arm64'},'browser_security':{'policy':'chromium-userns'},
                        'process':{'exit_code':0,'cleanup_confirmed':True},'observations':[{'browser_sandbox':{'namespace_and_seccomp_verified':True}}]}
                else:receipt=image
                key=profile+'-'+release;self.images[key]=image;self.paths[key]=self.write(key+'.json',receipt)
        self.route={'origin':'http://fixture.invalid:18080','allowed_addresses':['192.0.2.10'],'fixture_port':18080,
            'scripted_base_url':'http://scripted.invalid:18081/v1','scripted_host_base_url':'http://127.0.0.1:18081/v1','scripted_port':18081,'publish_host':'0.0.0.0'}
        self.refs={'alice':'QUALIFICATION_ALICE','bob':'QUALIFICATION_BOB','scripted_inference':'QUALIFICATION_INFERENCE'}
        self.identity={'runner':provenance.execution({}, {},harness.SKILL)['runner_content_sha256'],'files':{'controlled':'fixture'},'sha256':'a'*64}
        mock.patch.object(harness,'source_identity',return_value=self.identity).start()
        mock.patch.object(harness.lab_env,'load_saved',return_value=(self.endpoint,{})).start()
        mock.patch.object(harness.lab_env,'evaluate',return_value={'state':'ready'}).start()
        self.addCleanup(mock.patch.stopall)
        for target,name in ((socket,'socket'),(subprocess,'Popen'),(subprocess,'run'),(harness.lab,'endpoint_secret'),(secret_store,'read_secret')):
            mock.patch.object(target,name,side_effect=AssertionError('Offline unit must not launch or read keys')).start()
    def write(self,name,value):
        path=self.root/name;path.write_bytes(c.canonical(value));return path
    def test_cli_admission_diagnostic_uses_closed_catalog_without_exception_text(self):
        error=resources.AdmissionError('host-admission-busy','private-key-value')
        captured=io.StringIO()
        with mock.patch.object(harness,'admit_images',side_effect=error),contextlib.redirect_stderr(captured):
            self.assertEqual(harness.main(['admit','--root',str(self.output)]),2)
        value=json.loads(captured.getvalue())
        self.assertEqual(value['admission'],resources.admission_diagnostic(error))
        self.assertNotIn('private-key-value',captured.getvalue())
    def test_cli_does_not_infer_admission_reason_from_arbitrary_error_text(self):
        captured=io.StringIO()
        with mock.patch.object(harness,'admit_images',side_effect=ValueError('host-admission-busy private-key-value')),contextlib.redirect_stderr(captured):
            self.assertEqual(harness.main(['admit','--root',str(self.output)]),2)
        self.assertEqual(json.loads(captured.getvalue()),{'status':'BLOCKED','reason':'qualification_inputs_or_ownership_unavailable'})
    def freeze(self,**changes):return harness.freeze(self.output,session='controlled-confirmed-session',approved_endpoint_path=self.endpoint_path,
        image_receipts=self.paths,fixture_route=self.route,credential_references=self.refs,secrets_dir=self.store,**changes)
    def test_fixed_matrix_has_no_unlisted_or_extra_participant_denominators(self):
        cells=harness.matrix(self.images)
        self.assertEqual(len(cells),28);self.assertEqual(sum(row['participant_segments_max'] for row in cells),24)
        self.assertEqual(sum(row['container_launches_max'] for row in cells),186)
        self.assertEqual(sum(row['real_model'] for row in cells),12)
        self.assertTrue(all(row['max_attempts']==1 for row in cells))
        for release in harness.RELEASES:
            negative=[row for row in cells if row['group']=='N02' and row['release']==release]
            self.assertEqual(len(negative),6);self.assertEqual(negative[-1]['scenario'],'sensitive-participant-interruption')
            self.assertEqual({(row['case'],row['variant']) for row in negative},{(case,variant) for case,variant,_ in harness.NEGATIVES})
    def test_actual_compiled_freeze_keeps_explicit_sixcell_variant_plans_and_real_saved_endpoint(self):
        self.freeze();manifest,state=harness.verify(self.output)
        self.assertEqual(state['phase'],'frozen');self.assertEqual(manifest['endpoint'],harness.lab.normalize_endpoint(self.endpoint))
        self.assertEqual(manifest['source'],self.identity);self.assertEqual(harness.lab_env.evaluate.call_args.kwargs,{'check':False})
        self.assertEqual(manifest['host_admission']['wait_seconds'],30)
        for cell in manifest['cells']:
            if cell['participant_segments_max']:
                args=harness._cell_args(self.output,manifest,cell)
                self.assertEqual((args.lock_file,args.lock_wait_seconds),(manifest['host_admission']['lock_file'],30))
        for release in harness.RELEASES:
            metadata,matrix=experiments.verify(self.output/('scripted-'+release),harness.lab)
            self.assertEqual(len(matrix['cells']),6);self.assertEqual(metadata['policies']['max_attempts'],1)
            self.assertEqual(metadata['policies']['on_failure'],'continue')
            for cell in matrix['cells']:
                plan=application_preparation.load_compiled(self.output/('scripted-'+release)/cell['compiled_plan'])['plan'];stage=plan['stages'][0]
                self.assertEqual(stage['limits'],harness.NEGATIVE_LIMITS);self.assertEqual(plan['runtime']['inference_owner'],'experiment_variant')
                if cell['case']=='request-and-persona':
                    wrong=next(operation for operation in plan['application']['operations'] if operation['id']=='identity-bob')
                    self.assertEqual(wrong['credential_alias'],'bob');self.assertEqual(stage['participant']['actor_id'],'actor-alice')
                self.assertIn('QUALIFICATION_SCRIPT_VARIANT_'+cell['variant'].upper(),stage['effective_prompt'])
        self.assertEqual(self.endpoint_path.read_bytes(),c.canonical(self.endpoint))
        projected=harness._launch_manifest(manifest)
        self.assertEqual(set(projected),{'qualification_id','images','cells','limits','planned_container_launches'})
        self.assertEqual(projected['limits']['live'],4);self.assertEqual(projected['planned_container_launches'],186)
    def test_freeze_no_overwrite_and_invalid_real_or_runtime_selection_before_native_effects(self):
        self.freeze();body=(self.output/'manifest.json').read_bytes()
        with self.assertRaises(ValueError):self.freeze()
        self.assertEqual((self.output/'manifest.json').read_bytes(),body)
        with mock.patch.object(harness.lab_env,'evaluate',return_value={'state':'needs-confirmation'}),self.assertRaises(ValueError):
            harness.freeze(self.root/'unconfirmed',session='other',approved_endpoint_path=self.endpoint_path,image_receipts=self.paths,
                fixture_route=self.route,credential_references=self.refs,secrets_dir=self.store)
        self.assertFalse((self.root/'unconfirmed').exists())
    def test_exact_source_and_immutable_input_mutation_rejects_without_recompiling(self):
        self.freeze();path=self.output/'inputs/endpoint.json';body=path.read_bytes();path.write_bytes(body+b' ')
        with self.assertRaises(ValueError):harness.verify(self.output)
        path.write_bytes(body)
        with mock.patch.object(harness,'source_identity',return_value={**self.identity,'sha256':'b'*64}),self.assertRaises(ValueError):harness.verify(self.output)
    def test_candidate_binding_has_no_archive_self_hash_cycle_and_is_immutable(self):
        self.freeze();manifest,_=harness.verify(self.output);before=(self.output/'manifest.json').read_bytes()
        identity={'archive_sha256':'c'*64,'runner_sha256':manifest['source']['runner'],'scope':'extracted_candidate'}
        harness.bind_candidate(self.output,identity);harness.verify(self.output,require_candidate=True)
        self.assertEqual((self.output/'manifest.json').read_bytes(),before)
        with self.assertRaises(ValueError):harness.bind_candidate(self.output,identity)
    def test_aggregate_admits_all_services_and_helper_without_clamping(self):
        self.assertEqual(harness._aggregate({'cpu_millis':18000,'memory_mib':7932},True,False),{'cpu_millis':3250,'memory_mib':3200,'pids_limit':832})
        with self.assertRaises(ValueError):harness._aggregate({'cpu_millis':4000,'memory_mib':4096},True,False)
    def test_report_retains_every_planned_cell_and_never_calls_an_executor(self):
        self.freeze();report=harness.report(self.output)
        self.assertEqual(report['status'],'NOT_READY');self.assertEqual(len(report['cells']),28)
        self.assertTrue(all(row['attempts']==0 and row['status']=='NOT_RUN' for row in report['cells']))
    def test_authorized_boundary_preserves_raw_history_and_uses_fixed_effective_clock(self):
        previous={'schema':1,'root':str(self.root/'old-blocked'),'manifest_sha256':'a'*64,'ledger_sha256':'b'*64,
            'state_sha256':'c'*64,'cleanup_receipts':[{'path':str(self.root/'old-cleanup.json'),'sha256':'d'*64}]}
        boundary={'path':str(self.root/'boundary.json'),'sha256':'e'*64}
        raw={'qualification_id':fresh(),'attempts':51,'participant_segments':0,'started_wall':1000,'deadline_wall':15400,
            'planned_cells':196,'prior_rows':[{'cell':'prior-'+str(i),'status':'NOT_RUN','attempts':0} for i in range(196)]}
        effective={**raw,'attempts':52,'base_attempts':51,'auxiliary_attempts':1,'started_wall':15000,'deadline_wall':29400,
            'original_window':{'started_wall':1000,'deadline_wall':15400},'campaign_boundary':boundary}
        module=harness._launch_module()
        with mock.patch.object(module,'_effective_carry',return_value=effective) as derive,mock.patch.object(module,'validate_predecessor',return_value=raw),mock.patch.object(harness.time,'time',return_value=16000):
            self.freeze(predecessor=previous,campaign_boundary=boundary)
            manifest,state=harness.verify(self.output)
            self.assertEqual(state['started_at'],15000);self.assertEqual(harness._remaining(self.output),13400)
            self.assertEqual(harness._launch_manifest(manifest)['campaign_boundary'],boundary)
            report=harness.report(self.output)
            self.assertEqual(report['predecessor']['attempts'],51);self.assertEqual(report['predecessor']['deadline_wall'],15400)
            self.assertEqual(len(report['predecessor']['prior_rows']),196);self.assertEqual(len(report['cells']),28)
            self.assertEqual(report['campaign_boundary']['attempts'],52);self.assertEqual(report['campaign_boundary']['deadline_wall'],29400)
            self.assertTrue(derive.called)
            state['started_at']=16000;harness.atomic(self.output/'state.json',state)
            with self.assertRaises(ValueError):harness.verify(self.output)
    def test_campaign_boundary_without_predecessor_is_denied_before_freeze(self):
        with self.assertRaises(ValueError):self.freeze(campaign_boundary={'path':str(self.root/'boundary'),'sha256':'e'*64})
        self.assertFalse(self.output.exists())
    def test_matrix_amendment_requires_original_chain_and_exact_root_before_effects(self):
        amendment={'path':str(self.root/'authorization.json'),'sha256':'f'*64}
        with self.assertRaises(ValueError):self.freeze(campaign_amendment=amendment)
        with self.assertRaises(ValueError):self.freeze(predecessor={'untrusted':'unused'},campaign_boundary={'untrusted':'unused'},campaign_amendment=amendment)
        self.assertFalse(self.output.exists())
    def test_unamended_manifest_cannot_raise_its_container_ceiling(self):
        self.freeze();manifest=harness.read(self.output/'manifest.json');manifest['limits']['container_launch_attempts']=241
        harness.atomic(self.output/'manifest.json',manifest);harness.atomic(self.output/'integrity.json',{'manifest_sha256':harness.sha(self.output/'manifest.json')})
        with self.assertRaises(ValueError):harness.verify(self.output)
    def test_amended_client_preserves_three_distinct_history_layers_and_fixed_clock(self):
        previous={'schema':1,'root':str(self.root/'old-blocked'),'manifest_sha256':'a'*64,'ledger_sha256':'b'*64,
            'state_sha256':'c'*64,'cleanup_receipts':[{'path':str(self.root/'cleanup.json'),'sha256':'d'*64}]}
        boundary={'path':str(self.root/'boundary.json'),'sha256':'e'*64};amendment={'path':str(self.root/'amendment.json'),'sha256':'f'*64}
        raw={'qualification_id':fresh(),'attempts':51,'participant_segments':0,'started_wall':1000,'deadline_wall':15400,
            'planned_cells':196,'prior_rows':[{'cell':'prior-'+str(i),'status':'NOT_RUN','attempts':0} for i in range(196)]}
        base={**raw,'attempts':54,'base_attempts':51,'auxiliary_attempts':3,'started_wall':15000,'deadline_wall':29400,
            'original_window':{'started_wall':1000,'deadline_wall':15400},'campaign_boundary':boundary}
        effective={**base,'attempts':55,'planned_cells':224,'prior_rows':[*raw['prior_rows'],*[{'cell':'eighth-'+str(i),'status':'NOT_RUN','attempts':0} for i in range(28)]],
            'lineage':[{'qualification_id':fresh()} for _ in range(8)],'campaign_amendment':amendment}
        module=harness._launch_module();caps={**module.LIMITS,'container_launch_attempts':241}
        with mock.patch.dict(sys.modules,{'application_campaign':SimpleNamespace(validate_boundary=lambda *args,**kwargs:base)}),\
             mock.patch.object(module,'amendment_module',return_value=SimpleNamespace(FINAL_ROOT=self.output)),\
             mock.patch.object(module,'effective_limits',return_value=caps),mock.patch.object(module,'_effective_carry',return_value=effective),\
             mock.patch.object(module,'validate_predecessor',return_value=raw),mock.patch.object(module,'validate_manifest'),mock.patch.object(harness.time,'time',return_value=16000):
            self.freeze(predecessor=previous,campaign_boundary=boundary,campaign_amendment=amendment)
            manifest,state=harness.verify(self.output);self.assertEqual(state['started_at'],15000);self.assertEqual(harness._remaining(self.output),13400)
            self.assertEqual(manifest['limits'],{**harness.LIMITS,'container_launch_attempts':241})
            self.assertEqual(harness._launch_manifest(manifest)['campaign_amendment'],amendment)
            report=harness.report(self.output);self.assertEqual(report['predecessor']['attempts'],51);self.assertEqual(report['campaign_boundary']['attempts'],54)
            self.assertEqual(report['campaign_amendment']['attempts'],55);self.assertEqual(len(report['campaign_amendment']['prior_rows']),224)
            self.assertEqual(report['campaign_amendment']['container_launch_attempts'],241);self.assertEqual(len(report['cells']),28)
    def test_tenth_client_keeps_old_deadlines_and_uses_separately_authorized_window(self):
        previous={'schema':1,'root':str(self.root/'old-blocked'),'manifest_sha256':'a'*64,'ledger_sha256':'b'*64,
            'state_sha256':'c'*64,'cleanup_receipts':[{'path':str(self.root/'cleanup.json'),'sha256':'d'*64}]}
        boundary={'path':str(self.root/'boundary.json'),'sha256':'e'*64};amendment={'path':str(self.root/'tenth.json'),'sha256':'f'*64}
        raw={'qualification_id':fresh(),'attempts':51,'participant_segments':0,'started_wall':1000,'deadline_wall':15400,
            'planned_cells':196,'prior_rows':[{'cell':'prior-'+str(i),'status':'NOT_RUN','attempts':0} for i in range(196)]}
        base={**raw,'attempts':54,'base_attempts':51,'auxiliary_attempts':3,'started_wall':15000,'deadline_wall':29400,
            'original_window':{'started_wall':1000,'deadline_wall':15400},'campaign_boundary':boundary}
        effective={**base,'attempts':63,'planned_cells':252,'started_wall':40000,'deadline_wall':54400,
            'prior_rows':[*raw['prior_rows'],*[{'cell':'later-'+str(i),'status':'NOT_RUN','attempts':0} for i in range(56)]],
            'lineage':[{'qualification_id':fresh()} for _ in range(9)],'campaign_amendment':amendment}
        module=harness._launch_module();caps={**module.LIMITS,'container_launch_attempts':249}
        with mock.patch.dict(sys.modules,{'application_campaign':SimpleNamespace(validate_boundary=lambda *args,**kwargs:base)}),\
             mock.patch.object(module,'amendment_module',return_value=SimpleNamespace(FINAL_ROOT=self.output)) as select,\
             mock.patch.object(module,'effective_limits',return_value=caps),mock.patch.object(module,'_effective_carry',return_value=effective),\
             mock.patch.object(module,'validate_predecessor',return_value=raw),mock.patch.object(module,'validate_manifest'),mock.patch.object(harness.time,'time',return_value=41000):
            self.freeze(predecessor=previous,campaign_boundary=boundary,campaign_amendment=amendment)
            manifest,state=harness.verify(self.output)
            self.assertEqual(state['started_at'],40000);self.assertEqual(harness._remaining(self.output),13400)
            self.assertEqual(manifest['limits'],{**harness.LIMITS,'container_launch_attempts':249})
            report=harness.report(self.output)
            self.assertEqual(report['predecessor']['attempts'],51);self.assertEqual(report['predecessor']['deadline_wall'],15400)
            self.assertEqual(report['campaign_boundary']['attempts'],54);self.assertEqual(report['campaign_boundary']['deadline_wall'],29400)
            self.assertEqual(report['campaign_amendment']['attempts'],63);self.assertEqual(len(report['campaign_amendment']['prior_rows']),252)
            self.assertEqual(report['campaign_amendment']['deadline_wall'],54400)
            self.assertEqual(report['campaign_amendment']['container_launch_attempts'],249);self.assertEqual(len(report['cells']),28)
            select.assert_called_with(amendment)
    def test_collection_rejects_missing_candidate_and_prior_gate_without_launch(self):
        self.freeze()
        with self.assertRaises((ValueError,OSError)):harness.collect(self.output,group='N03',release='1.2.0')
        self.assertEqual(harness.read(self.output/'state.json')['cells'],{})
    def test_explicit_predecessor_keeps_oldest_clock_and_separate_all_prior_rows(self):
        previous={'schema':1,'root':str(self.root/'old-blocked'),'manifest_sha256':'a'*64,'ledger_sha256':'b'*64,
            'state_sha256':'c'*64,'cleanup_receipts':[{'path':str(self.root/'old-cleanup.json'),'sha256':'d'*64}]}
        summary={'qualification_id':fresh(),'attempts':7,'participant_segments':0,'started_wall':1000,'deadline_wall':15400,
            'planned_cells':28,'prior_rows':[{'cell':'prior-'+str(i),'status':'BLOCKED' if i==4 else 'PASS' if i<4 else 'NOT_RUN','attempts':1 if i<5 else 0} for i in range(28)]}
        module=harness._launch_module()
        with mock.patch.object(module,'validate_predecessor',return_value=summary),mock.patch.object(harness.time,'time',return_value=1400):
            self.freeze(predecessor=previous);manifest,state=harness.verify(self.output)
            self.assertEqual(state['started_at'],1000);self.assertEqual(state['cells'],{})
            self.assertEqual(harness._remaining(self.output),14000)
            state['started_at']=None;harness.atomic(self.output/'state.json',state)
            self.assertEqual(harness._remaining(self.output),14000)
            self.assertEqual(harness._launch_manifest(manifest)['predecessor'],previous)
            public=harness.report(self.output);self.assertEqual(len(public['cells']),28);self.assertEqual(len(public['predecessor']['prior_rows']),28)
            self.assertTrue(all(row['attempts']==0 for row in public['cells']));self.assertEqual(public['predecessor']['attempts'],7)
            self.assertNotIn('root',public['predecessor'])
        self.assertFalse((self.root/'old-blocked').exists())
    def test_cleanup_remaining_does_not_require_a_new_launch_window(self):
        path=self.root/'cleanup';path.mkdir();harness.atomic(path/'state.json',{'started_at':None})
        harness.atomic(path/'manifest.json',{'predecessor':{'protected':'validated descriptor'}})
        with mock.patch.object(harness._launch_module(),'validate_predecessor',return_value={'deadline_wall':1405}) as validate,\
             mock.patch.object(harness.time,'time',return_value=1400):
            self.assertEqual(harness._remaining(path),5)
        self.assertEqual(validate.call_args.kwargs,{'_launch_window':False})
    def test_unconfirmed_predecessor_rejects_before_creating_successor_inputs(self):
        with mock.patch.object(harness._launch_module(),'validate_predecessor',side_effect=ValueError('unconfirmed cleanup')),self.assertRaises(ValueError):
            self.freeze(predecessor={'untrusted':'closed validator rejects'})
        self.assertFalse(self.output.exists())

    def test_internal_child_preserves_real_prepared_variant_and_initial_record_through_runner(self):
        self.freeze();manifest,_=harness.verify(self.output)
        harness.bind_candidate(self.output,{'archive_sha256':'c'*64,'runner_sha256':self.identity['runner'],'scope':'extracted_candidate'})
        cell=next(row for row in manifest['cells'] if row['group']=='N02')
        experiment=self.output/('scripted-'+cell['release']);metadata,mapping=experiments.verify(experiment,harness.lab)
        trial=next(row for row in mapping['cells'] if row['trial_id']==cell['trial_id']);intent,_=experiments.reserve_attempt(experiment,metadata,trial)
        record=intent['initial_record'];state=harness.read(self.output/'state.json')
        state['active_cell']={'id':cell['id'],'pid':os.getpid(),'run_id':record['run_id'],'attempt_id':record['attempt_id']}
        state['cells'][cell['id']]={'status':'started','attempts':1}
        (self.output/'cells'/cell['id']).mkdir(mode=0o700)
        harness.atomic(self.output/'state.json',state);envelope=self.write('private-child.json',{'initial_record':record,'redaction_values':[]});envelope.chmod(0o400)
        events=[];guard=mock.Mock(unsafe=True);guard.assert_cell_released.return_value=None
        @contextlib.contextmanager
        def instrumentation(*args,**kwargs):yield guard
        module=SimpleNamespace(instrument=instrumentation,validate_manifest=harness._launch_module().validate_manifest)
        def runner(args,initial_record):
            self.assertEqual(initial_record,record);self.assertEqual(args._application_variant_context['trial_id'],trial['trial_id'])
            self.assertEqual(args.compiled_plan,str(experiment/trial['compiled_plan']))
            args._attempt_root=experiment/'runs'/record['run_id'];args._attempt_root.mkdir(parents=True)
            args._attempt_identity={key:record[key] for key in ('run_id','attempt_id')}
            with harness.lab.admission_lock(args.lock_file,args.lock_wait_seconds):events.append('runner_under_lease')
            harness.atomic(args._attempt_root/'result.json',{'fixture':'controlled runner return'})
            return 1
        @contextlib.contextmanager
        def original(path,wait):
            registry=SimpleNamespace(command=None,bind_daemon=lambda value:events.append('daemon_bound'))
            token=ownership_registry.CURRENT.set(registry)
            try:events.append('real_lease');yield registry
            finally:events.append('lease_closed');ownership_registry.CURRENT.reset(token)
        services=SimpleNamespace(start=lambda:events.append('service_start'),close=lambda:events.append('service_close'))
        with mock.patch.object(harness,'_launch_module',return_value=module),mock.patch.object(harness,'_ledger',return_value=object()),\
             mock.patch.object(harness,'_native',return_value=('daemon',{'cpu_millis':18000,'memory_mib':7932})),\
             mock.patch.object(harness,'OwnedServices',return_value=services),mock.patch.object(harness.lab,'admission_lock',side_effect=original),\
             mock.patch.object(harness.lab,'run_suite',side_effect=runner) as run:
            self.assertEqual(harness._child(self.output,cell['id'],envelope),1)
        self.assertEqual(events,['real_lease','daemon_bound','service_start','runner_under_lease','service_close','lease_closed'])
        run.assert_called_once();guard.assert_cell_released.assert_called_once()


class ActualLeaseTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        self.args=SimpleNamespace(lock_file=str(self.root/'host.lock'),lock_wait_seconds=0,_attempt_root=self.root/'run',
            _attempt_identity={'run_id':fresh(),'attempt_id':fresh()})
        self.events=[]
    def test_real_flock_registry_custody_and_service_cleanup_precede_release(self):
        def factory(registry):
            self.assertIs(ownership_registry.CURRENT.get(),registry)
            return SimpleNamespace(start=lambda:self.events.append('start'),close=lambda:self.events.append('close'))
        with harness.actual_lease(self.args,factory) as registry:
            self.events.append('run');self.assertIs(ownership_registry.CURRENT.get(),registry)
            self.assertEqual(registry.runroot,self.args._attempt_root)
            with self.assertRaises(resources.AdmissionError):
                with resources.admission_lock(self.args.lock_file,0):pass
        self.assertEqual(self.events,['start','run','close']);self.assertIsNone(ownership_registry.CURRENT.get())
        with resources.admission_lock(self.args.lock_file,0):self.events.append('reacquired')
    def test_service_start_failure_still_executes_owned_cleanup_and_never_runs_participant(self):
        def fail():self.events.append('start');raise ValueError('controlled')
        def factory(registry):return SimpleNamespace(start=fail,close=lambda:self.events.append('close'))
        with self.assertRaises(ValueError):
            with harness.actual_lease(self.args,factory):self.events.append('participant')
        self.assertEqual(self.events,['start','close'])
    def test_primary_start_failure_survives_a_different_cleanup_failure(self):
        original=ValueError('controlled primary startup')
        def start():raise original
        def close():raise RuntimeError('controlled cleanup')
        with self.assertRaises(ValueError) as caught:
            with harness.actual_lease(self.args,lambda registry:SimpleNamespace(start=start,close=close)):
                self.fail('participant must not start')
        self.assertIs(caught.exception,original)


class ClosedOracleTests(unittest.TestCase):
    def baseline(self):
        process={'cleanup_confirmed':True,'application_helper_cleanup':{'safe_to_continue':True},'application_credentials':{'status':'removed'},
            'native_tool_budget':{'phase':'reporting','counts':dict(harness.RESERVE_COUNTS),'reporting_reserve_calls_remaining':6}}
        record={'status':'FAIL','agents':[{'process':process}],'application_completion':{'stages':[{'status':'incomplete','diagnostics':[{'code':'report_missing','count':1}]}]},
            'invocation':{'status':'verified'},'task_result':{'status':'pass'}}
        return record,{'requests':[],'publications':[]},{'status':'FAIL','diagnostics':[]}
    def test_invalid_request_oracle_requires_zero_http_and_known_cleanup(self):
        record,journal,oracle=self.baseline()
        record['agents'][0]['process']['native_tool_budget']['counts'].update(attempted=1,charged=1,blocked=1)
        self.assertEqual(harness.negative_verdict('invalid-typed-request',record,journal,oracle)['status'],'PASS')
        journal['requests']=[{'method':'GET','path':'/identity'}]
        self.assertEqual(harness.negative_verdict('invalid-typed-request',record,journal,oracle)['status'],'FAIL')
    def test_exact_reserve_counts_ignore_claimed_task_success_and_extra_effect_fails(self):
        record,journal,oracle=self.baseline();journal['requests']=[{'method':'GET','path':'/identity'}]
        self.assertEqual(harness.negative_verdict('multi-call-reserve-boundary',record,journal,oracle)['status'],'PASS')
        record['agents'][0]['process']['native_tool_budget']['counts']['charged']=11
        self.assertEqual(harness.negative_verdict('multi-call-reserve-boundary',record,journal,oracle)['status'],'FAIL')
    def test_sensitive_interruption_requires_actual_signal_interrupted_not_evaluated_and_safe_cleanup(self):
        record,journal,oracle=self.baseline();record['status']='INTERRUPTED';record['application_completion']['stages'][0]['status']='not_evaluated';oracle['status']='NOT_EVALUATED'
        record.update(run_id=fresh(),attempt_id=fresh());record['invocation']['attempted_stages']=1
        proof={'participant_launches':1,'stage_metadata':[{'kind':'agent','run_id':record['run_id'],'attempt_id':record['attempt_id'],'stage_id':fresh(),'label':'agent-1-participant'}]}
        self.assertEqual(harness.negative_verdict('sensitive-participant-interruption',record,journal,oracle,interruption_sent=True,**proof)['status'],'PASS')
        self.assertEqual(harness.negative_verdict('sensitive-participant-interruption',record,journal,oracle)['status'],'FAIL')
        record['agents'][0]['process']['application_helper_cleanup']['safe_to_continue']=False
        self.assertEqual(harness.negative_verdict('sensitive-participant-interruption',record,journal,oracle,interruption_sent=True,**proof)['status'],'FAIL')
    def test_actual_exception_shape_uses_last_process_without_synthesizing_agent_or_report(self):
        record,journal,oracle=self.baseline();process=record['agents'][0]['process'];process['application_completion']={'status':'not_evaluated'}
        record.update(status='INTERRUPTED',agents=[],last_process=process,run_id=fresh(),attempt_id=fresh())
        record['invocation'].update(attempted_stages=1,status='invalid');record['application_completion']['stages'][0]['status']='prior_failure'
        oracle['status']='NOT_EVALUATED';proof={'participant_launches':1,'stage_metadata':[{'kind':'agent','run_id':record['run_id'],'attempt_id':record['attempt_id'],'stage_id':fresh(),'label':'agent-1-participant'}]}
        before=copy.deepcopy(record)
        self.assertEqual(harness.negative_verdict('sensitive-participant-interruption',record,journal,oracle,interruption_sent=True,**proof)['status'],'PASS')
        self.assertEqual(record,before)
        self.assertEqual(harness.negative_verdict('sensitive-participant-interruption',record,journal,oracle,interruption_sent=True,
            participant_launches=2,stage_metadata=proof['stage_metadata'])['status'],'FAIL')
    def test_unknown_oracle_has_no_success_default(self):
        with self.assertRaises(ValueError):harness.negative_verdict('other',*self.baseline())
    def test_status_pass_without_native_webgl_or_sandbox_is_not_browser_admission(self):
        cell={'release':'1.2.0','image_id':'sha256:'+'a'*64}
        value={'status':'PASS','image':{'id':cell['image_id'],'platform':'linux/arm64','capabilities':{'pi':'1.2.0'}},
            'host':{'native_platform':'linux/arm64','selected_platform':'linux/arm64'},'browser_security':{'policy':'chromium-userns'},
            'process':{'exit_code':0,'cleanup_confirmed':True},'observations':[{'browser_dom_ok':True,'webgl_ok':True,'no_browser_sandbox':False,'software_webgl':False},
                {'browser_sandbox':{'namespace_and_seccomp_verified':True}}]}
        self.assertTrue(harness._browser_admitted(value,cell))
        for fault in ('webgl-false','webgl-missing','software','sandbox','cleanup'):
            bad=copy.deepcopy(value)
            if fault=='webgl-false':bad['observations'][0]['webgl_ok']=False
            elif fault=='webgl-missing':del bad['observations'][0]['webgl_ok']
            elif fault=='software':bad['observations'][0]['software_webgl']=True
            elif fault=='sandbox':bad['observations'][1]['browser_sandbox']['namespace_and_seccomp_verified']=False
            else:bad['process']['cleanup_confirmed']=False
            with self.subTest(fault=fault):self.assertFalse(harness._browser_admitted(bad,cell))


class OwnedServiceBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        self.refs={'alice':'ALICE_REFERENCE','bob':'BOB_REFERENCE','scripted_inference':'SCRIPT_REFERENCE'}
        harness.atomic(self.root/'state.json',{'started_at':None})
        self.values={'ALICE_REFERENCE':'alice-disposable-value-138749','BOB_REFERENCE':'bob-disposable-value-49732',
            'SCRIPT_REFERENCE':'scripted-inference-value-02495','MODEL_REFERENCE':'original-model-never-mounted-192837'}
        self.cell={'id':'N02-1.2.0-request-and-persona-a','group':'N02','release':'1.2.0','case':'request-and-persona','variant':'a'}
        self.manifest={'credential_references':self.refs,'secrets_dir':str(self.root/'original-store'),'fixture_route':{'fixture_port':18080,'scripted_port':18081}}
        self.registry=mock.Mock();self.registry.registry_id='registry'
        self.service=harness.OwnedServices(self.root,self.manifest,self.cell,SimpleNamespace(_attempt_root=self.root/'run'),self.registry,mock.Mock(),list(self.values.values()))
        # This suite isolates private ownership boundaries; real guard command
        # and deadline behavior is exercised by test_application_service_cleanup.
        self.service.guard.service_cleanup.side_effect=lambda *args:contextlib.nullcontext()
        self.service.guard.service_readiness_check.side_effect=lambda record,observed,deadline:observed['Id']
        self.service._service_command=lambda record,operation,deadline,seconds:harness.lab.command(
            ['docker',operation,*(['--time','15'] if operation=='stop' else []),record['container_id']],timeout=seconds,required=False)
    def test_service_bootstraps_are_disjoint_and_never_mount_the_original_model_store(self):
        captured={}
        def start(role,observations,command,port,private):captured[role]=(private,{str(path.relative_to(private)):path.read_bytes() for path in private.rglob('*') if path.is_file()})
        with mock.patch.object(harness.credentials,'read',side_effect=lambda name,store:self.values[name]),\
             mock.patch.object(harness.secret_store,'resolve_secret',side_effect=lambda name,store:(self.values[name],'fixture')),mock.patch.object(self.service,'_start',side_effect=start):
            self.service.start()
        fixture=captured['fixture'];script=captured['scripted-inference']
        self.assertNotEqual(fixture[0],script[0]);self.assertEqual(set(fixture[1]),{'store/ALICE_REFERENCE','store/BOB_REFERENCE'})
        self.assertEqual(set(script[1]),{'bootstrap/config.json'});self.assertNotIn(self.values['MODEL_REFERENCE'].encode(),b''.join([*fixture[1].values(),*script[1].values()]))
        self.assertNotIn(self.values['SCRIPT_REFERENCE'].encode(),b''.join(fixture[1].values()))
        self.assertNotIn(self.values['ALICE_REFERENCE'].encode(),b''.join(script[1].values()))
        private=self.service.private;self.service.close();self.assertFalse(private.exists())
    def scripted_tree(self):
        captured={}
        def start(role,observations,command,port,private):captured[role]={'private':private,'command':command,'observations':observations}
        with mock.patch.object(harness.credentials,'read',side_effect=lambda name,store:self.values[name]),\
             mock.patch.object(harness.secret_store,'resolve_secret',side_effect=lambda name,store:(self.values[name],'fixture')),\
             mock.patch.object(self.service,'_start',side_effect=start):self.service.start()
        self.addCleanup(self.service.close)
        return captured
    def test_both_service_observations_use_owned_children_of_the_bind_wrappers(self):
        captured=self.scripted_tree()
        for item in captured.values():
            self.assertEqual(item['observations'].stat().st_mode&0o777,0o700)
            self.assertEqual((item['observations']/'private').stat().st_mode&0o777,0o700)
            self.assertEqual(set(p.name for p in item['observations'].iterdir()),{'private'})
        self.assertEqual(self.service.journal,captured['fixture']['observations']/'private')
        command=captured['fixture']['command'];self.assertEqual(command[command.index('--journal-dir')+1],'/observations/private')
        command=captured['scripted-inference']['command'];self.assertEqual(command[command.index('--observations')+1],'/observations/private/scripted.json')
    def test_strict_scripted_startup_and_parent_readiness_work_with_foreign_mount_root_metadata(self):
        captured=self.scripted_tree();item=captured['scripted-inference'];wrapper=item['observations'];child=wrapper/'private'
        script=harness._module('qualification_observation_child',harness.HERE/'application_scripted.py')
        original=os.fstat;identity=(wrapper.stat().st_dev,wrapper.stat().st_ino)
        def mount_view(fd):
            info=original(fd)
            return SimpleNamespace(st_uid=info.st_uid+1,st_mode=info.st_mode) if (info.st_dev,info.st_ino)==identity else info
        with mock.patch.object(script.os,'fstat',side_effect=mount_view):
            with self.assertRaises(script.ScriptError):script._directory(wrapper)
            server=script.ScriptedServer(script.read_bootstrap(item['private']/'bootstrap/config.json'),child/'scripted.json')
        self.addCleanup(server.stop)
        self.assertEqual(harness.read(child/'scripted.json')['phase'],'ready');self.assertFalse((wrapper/'scripted.json').exists())
        record={'launch_id':fresh(),'container_id':'a'*64,'image':'sha256:'+'b'*64}
        self.service.service_states[record['launch_id']]={'role':'scripted-inference','ready':False,'observations':wrapper}
        observed={'Id':record['container_id'],'Image':record['image'],'HostConfig':{'NanoCpus':250000000,'Memory':134217728,'MemorySwap':134217728,'PidsLimit':64},'State':{'Running':True}}
        with mock.patch.object(harness.lab,'command',return_value=SimpleNamespace(returncode=0)),mock.patch.object(self.service,'_observation',return_value=observed):
            self.service._await_ready(record,'controlled-name','scripted-inference',wrapper,['never-executed'],record['image'])
        self.assertTrue(self.service.service_states[record['launch_id']]['ready'])
    def test_public_or_linked_observations_child_denies_before_socket_creation(self):
        captured=self.scripted_tree();item=captured['scripted-inference'];wrapper=item['observations'];child=wrapper/'private'
        script=harness._module('qualification_observation_denials',harness.HERE/'application_scripted.py');config=script.read_bootstrap(item['private']/'bootstrap/config.json')
        fixture=harness._module('qualification_fixture_observation_denials',harness.EXAMPLE/'fixture.py')
        keys={'alice':self.values['ALICE_REFERENCE'],'bob':self.values['BOB_REFERENCE']}
        with mock.patch.object(socket,'socket',side_effect=AssertionError('Unsafe observation must not reach network')):
            child.chmod(0o755)
            with self.assertRaises(script.ScriptError):script.ScriptedServer(config,child/'scripted.json')
            with self.assertRaises(ValueError):fixture.FixtureServer(child,keys)
            self.assertEqual(list(child.iterdir()),[]);child.chmod(0o700)
            owned=wrapper/'owned-private';child.rename(owned);child.symlink_to(owned,target_is_directory=True)
            with self.assertRaises((OSError,script.ScriptError)):script.ScriptedServer(config,child/'scripted.json')
            with self.assertRaises(ValueError):fixture.FixtureServer(child,keys)
            self.assertEqual(list(owned.iterdir()),[]);child.unlink();owned.rename(child)
    def test_fixture_journal_uses_strict_child_with_foreign_mount_root_metadata(self):
        captured=self.scripted_tree();wrapper=captured['fixture']['observations'];child=wrapper/'private'
        fixture=harness._module('qualification_fixture_observation_child',harness.EXAMPLE/'fixture.py')
        keys={'alice':self.values['ALICE_REFERENCE'],'bob':self.values['BOB_REFERENCE']};original=Path.stat
        def mount_view(path,*args,**kwargs):
            info=original(path,*args,**kwargs)
            return SimpleNamespace(st_uid=info.st_uid+1,st_mode=info.st_mode) if path==wrapper else info
        with mock.patch.object(Path,'stat',mount_view):
            with self.assertRaises(ValueError):fixture.FixtureServer(wrapper,keys)
            server=fixture.FixtureServer(child,keys)
        self.addCleanup(server.stop);self.assertEqual(server.root,self.service.journal)
        self.assertEqual(server.journal['requests'],[]);self.assertTrue((child/'journal.json').is_file())
        self.assertFalse((wrapper/'journal.json').exists())
    def test_scripted_bootstrap_uses_only_protected_child_and_exact_fixed_argument(self):
        captured=self.scripted_tree();script=captured['scripted-inference'];wrapper=script['private'];child=wrapper/'bootstrap';path=child/'config.json'
        self.assertEqual(wrapper.stat().st_mode&0o777,0o700);self.assertEqual(child.stat().st_mode&0o777,0o700)
        self.assertEqual(path.stat().st_mode&0o777,0o600);self.assertEqual(path.stat().st_nlink,1)
        self.assertEqual(script['command'][1:3],['--private-bootstrap','/private/bootstrap/config.json'])
        self.assertFalse((wrapper/'config.json').exists());self.assertEqual(set(p.name for p in wrapper.iterdir()),{'bootstrap'})
        self.assertEqual(set(p.name for p in captured['fixture']['private'].iterdir()),{'store'})
        self.assertNotEqual(wrapper,captured['fixture']['private'])
    def test_simulated_mount_root_metadata_failure_keeps_existing_strict_child_check(self):
        captured=self.scripted_tree();wrapper=captured['scripted-inference']['private'];child=wrapper/'bootstrap';path=child/'config.json'
        script=harness._module('qualification_private_child_reader',harness.HERE/'application_scripted.py')
        # A host-only simulation of the failed root predicate, not a claim about
        # which UID/mode the native read-only bind actually exposed.
        wrapper.chmod(0o755)
        with self.assertRaises(script.ScriptError):script._directory(wrapper)
        with mock.patch.object(script,'ScriptedServer',side_effect=AssertionError('No server startup')),\
             mock.patch.object(harness.subprocess,'Popen',side_effect=AssertionError('No child/container launch')),\
             mock.patch.object(socket,'socket',side_effect=AssertionError('No network')):
            value=script.read_bootstrap(path)
        self.assertEqual(value['inference_key'],self.values['SCRIPT_REFERENCE'])
        self.assertEqual(child.stat().st_mode&0o777,0o700)
        wrapper.chmod(0o700);original=os.fstat;identity=(wrapper.stat().st_dev,wrapper.stat().st_ino)
        def root_uid_view(fd):
            info=original(fd)
            return SimpleNamespace(st_uid=info.st_uid+1,st_mode=info.st_mode) if (info.st_dev,info.st_ino)==identity else info
        with mock.patch.object(script.os,'fstat',side_effect=root_uid_view):
            with self.assertRaises(script.ScriptError):script._directory(wrapper)
            self.assertEqual(script.read_bootstrap(path)['inference_key'],self.values['SCRIPT_REFERENCE'])
    def test_bad_private_child_or_file_still_denies_without_launch_or_network(self):
        captured=self.scripted_tree();wrapper=captured['scripted-inference']['private'];child=wrapper/'bootstrap';path=child/'config.json'
        script=harness._module('qualification_bad_child_reader',harness.HERE/'application_scripted.py')
        with mock.patch.object(script,'ScriptedServer',side_effect=AssertionError('No server startup')),\
             mock.patch.object(harness.subprocess,'Popen',side_effect=AssertionError('No child/container launch')),\
             mock.patch.object(socket,'socket',side_effect=AssertionError('No network')):
            child.chmod(0o755)
            with self.assertRaises(script.ScriptError):script.read_bootstrap(path)
            child.chmod(0o700);original=os.fstat;identity=(child.stat().st_dev,child.stat().st_ino)
            def child_uid_view(fd):
                info=original(fd)
                return SimpleNamespace(st_uid=info.st_uid+1,st_mode=info.st_mode) if (info.st_dev,info.st_ino)==identity else info
            with mock.patch.object(script.os,'fstat',side_effect=child_uid_view):
                with self.assertRaises(script.ScriptError):script.read_bootstrap(path)
            path.chmod(0o644)
            with self.assertRaises(script.ScriptError):script.read_bootstrap(path)
            path.chmod(0o600);other=wrapper/'linked';os.link(path,other)
            with self.assertRaises(script.ScriptError):script.read_bootstrap(path)
            other.unlink();moved=wrapper/'owned-bootstrap';child.rename(moved);child.symlink_to(moved,target_is_directory=True)
            with self.assertRaises((OSError,script.ScriptError)):script.read_bootstrap(path)
            child.unlink();moved.rename(child)
    def test_foreign_container_observation_never_stops_or_removes_it_and_keeps_private_state(self):
        private=self.root/'private';private.mkdir(mode=0o700);(private/'owned.txt').write_text('owned')
        self.service.private=private;self.service.private_identity=harness._private_identity(private)
        record={'container_id':'owned-id','image':'sha256:'+'a'*64,'launch_id':fresh()}
        self.service.items=[(record,'owned-name')];self.service.journal=self.root/'journal';self.service.journal.mkdir()
        (self.service.journal/'terminal-receipt.json').write_text('{}')
        observed={'Id':'foreign-id','Image':record['image'],'Config':{'Labels':{}}}
        with mock.patch.object(harness.lab,'command',return_value=SimpleNamespace(returncode=0,stdout=json.dumps([observed]))) as command,self.assertRaises(ValueError):
            self.service.close()
        self.assertTrue(private.exists());self.registry.confirm_absent.assert_not_called()
        self.assertEqual([call.args[0][:3] for call in command.call_args_list],[['docker','container','inspect']])
    def test_private_directory_replacement_does_not_delete_foreign_contents(self):
        path=self.root/'private';path.mkdir(mode=0o700);(path/'secret').write_text('controlled')
        identity=harness._private_identity(path);moved=self.root/'original';path.rename(moved)
        path.mkdir(mode=0o700);(path/'unrelated').write_text('preserve')
        with self.assertRaises(ValueError):harness._purge_private(path,identity)
        self.assertEqual((path/'unrelated').read_text(),'preserve');self.assertTrue((moved/'secret').exists())
    def owned_record(self):
        private=self.root/'private';private.mkdir(mode=0o700);(private/'owned.txt').write_text('owned')
        self.service.private=private;self.service.private_identity=harness._private_identity(private)
        record={'container_id':'a'*64,'image':'sha256:'+'a'*64,'launch_id':fresh(),'mounts':[],'status':'running'}
        self.service.items=[(record,'owned-name')]
        self.service.private_identities[record['launch_id']]={'source':str(private),'device':private.stat().st_dev,'inode':private.stat().st_ino}
        self.service.service_states[record['launch_id']]={'role':'fixture','ready':False,'observations':self.root/'journal'}
        self.service.journal=self.root/'journal';self.service.journal.mkdir()
        observed={'Id':record['container_id'],'Image':record['image'],'Config':{'Labels':{ownership_registry.LABEL:record['launch_id'],
            ownership_registry.REGISTRY_LABEL:self.registry.registry_id}},'Mounts':[],'State':{'Running':False,'Status':'exited','ExitCode':1,'OOMKilled':False}}
        return private,record,observed
    def test_stopped_before_readiness_can_have_positive_private_cleanup_without_terminal(self):
        private,record,observed=self.owned_record();events=[]
        def absent(value):value['status']='absent';events.append('physical_absent');return True
        def receipt(value,path,**kwargs):
            self.assertFalse(private.exists());self.assertEqual(value['status'],'absent')
            self.assertFalse(kwargs['terminal_available']);self.assertFalse(kwargs['startup_readied'])
            events.append('receipt');return {'path':str(path),'sha256':'b'*64}
        def release(value,confirmed):
            self.assertTrue(confirmed);self.assertIn('qualification_service_cleanup',value);events.append('release')
        self.registry.confirm_absent.side_effect=absent
        self.registry.release.side_effect=release
        with mock.patch.object(harness.lab,'command',return_value=SimpleNamespace(returncode=0,stdout=json.dumps([observed]))),\
             mock.patch.object(harness.ownership_registry,'write_qualification_service_cleanup',side_effect=receipt),\
             mock.patch.object(harness,'_bounded_service_logs',return_value={'complete':True,'stdout':b'','stderr':b'controlled startup error'}):
            self.service.close()
        cleanup=harness.read(self.service.folder/'services-cleanup.json')
        self.assertTrue(cleanup['safe_to_continue']);self.assertTrue(cleanup['physical_absence_confirmed'])
        self.assertTrue(cleanup['private_bootstrap_removed']);self.assertFalse(cleanup['terminal_available']);self.assertFalse(cleanup['qualification_eligible'])
        self.assertEqual(events,['physical_absent','receipt','release']);self.assertFalse((self.service.journal/'terminal-receipt.json').exists())
        diagnostic=harness.read(next(self.service.folder.glob('service-diagnostic-*')))
        self.assertEqual(diagnostic['logs']['stderr'],'controlled startup error');self.assertEqual(diagnostic['exit_code'],1)
    def test_secret_or_truncated_startup_logs_are_withheld_entirely(self):
        _,record,observed=self.owned_record()
        for capture in ({'complete':True,'stdout':self.values['ALICE_REFERENCE'].encode(),'stderr':b'controlled'},
                        {'complete':False,'stdout':b'partial private','stderr':b'partial'}):
            with mock.patch.object(harness.lab,'command',return_value=SimpleNamespace(returncode=0,stdout=json.dumps([observed]))),\
                 mock.patch.object(harness,'_bounded_service_logs',return_value=capture):
                self.service._diagnose(record,'owned-name','startup_failed')
            diagnostic=harness.read(next(self.service.folder.glob('service-diagnostic-*')))
            self.assertEqual(diagnostic['logs'],{'available':False,'stdout':'','stderr':''})
    def test_failed_start_preserves_original_error_and_retains_owned_state_and_stderr(self):
        private,record,observed=self.owned_record();self.service.items=[]
        observations=self.root/'startup-observations';observations.mkdir(mode=0o700)
        (observations/'private').mkdir(mode=0o700)
        self.manifest['images']={'core-1.2.0':{'id':record['image']}};self.manifest['fixture_route']['publish_host']='127.0.0.1'
        self.service.guard.external_service_intent.return_value=(record,['controlled-boundary-never-executed'])
        original=ValueError('controlled original startup failure')
        with mock.patch.object(harness.ownership_registry,'observe_qualification_private',return_value=self.service.private_identities[record['launch_id']]),\
             mock.patch.object(self.service,'_await_ready',side_effect=original),\
             mock.patch.object(harness.lab,'command',return_value=SimpleNamespace(returncode=0,stdout=json.dumps([observed]))),\
             mock.patch.object(harness,'_bounded_service_logs',return_value={'complete':True,'stdout':b'','stderr':b'controlled early startup error'}),self.assertRaises(ValueError) as caught:
            self.service._start('fixture',observations,['controlled'],18080,private)
        self.assertIs(caught.exception,original)
        diagnostic=harness.read(next(self.service.folder.glob('*startup_failed.json')))
        self.assertEqual(diagnostic['phase'],'startup_failed');self.assertFalse(diagnostic['running']);self.assertEqual(diagnostic['exit_code'],1)
        self.assertEqual(diagnostic['logs']['stderr'],'controlled early startup error')
    def test_owned_early_exit_is_diagnosed_separately_from_a_foreign_observation(self):
        _,record,observed=self.owned_record()
        observed['HostConfig']={'NanoCpus':250000000,'Memory':134217728,'MemorySwap':134217728,'PidsLimit':64}
        with mock.patch.object(harness.lab,'command'),mock.patch.object(self.service,'_observation',return_value=observed),\
             self.assertRaisesRegex(ValueError,'Owned service exited before readiness'):
            self.service._await_ready(record,'owned-name','fixture',self.service.journal,['controlled-never-executed'],record['image'])
    def test_external_service_persists_verified_id_before_early_readiness_failure(self):
        _,record,observed=self.owned_record();record.pop('container_id');record['status']='intent'
        observed['HostConfig']={'NanoCpus':250000000,'Memory':134217728,'MemorySwap':134217728,'PidsLimit':64}
        with mock.patch.object(harness.lab,'command'),mock.patch.object(self.service,'_observation',return_value=observed),\
             self.assertRaisesRegex(ValueError,'Owned service exited before readiness'):
            self.service._await_ready(record,'owned-name','fixture',self.service.journal,['controlled-never-executed'],record['image'])
        self.assertEqual(record['container_id'],observed['Id']);self.assertEqual(record['status'],'intent')
        self.registry.write.assert_called_with(record)
    def test_private_purge_failure_preserves_true_physical_absence_and_prevents_release(self):
        private,record,observed=self.owned_record();self.registry.confirm_absent.return_value=True
        with mock.patch.object(harness.lab,'command',return_value=SimpleNamespace(returncode=0,stdout=json.dumps([observed]))),\
             mock.patch.object(self.service,'_diagnose'),mock.patch.object(harness,'_purge_private',side_effect=ValueError('controlled')),self.assertRaises(ValueError):
            self.service.close()
        cleanup=harness.read(self.service.folder/'services-cleanup.json')
        self.assertTrue(cleanup['physical_absence_confirmed']);self.assertFalse(cleanup['private_bootstrap_removed']);self.assertFalse(cleanup['safe_to_continue'])
        self.registry.release.assert_not_called();self.assertTrue(private.exists())
    def test_real_registry_accepts_exact_parent_cleanup_receipt_without_a_fixture_terminal(self):
        private,_,_=self.owned_record()
        reply=SimpleNamespace(returncode=1,stdout='',stderr='No such container: '+'a'*64)
        registry=ownership_registry.Registry(self.root/'real-registry',command=mock.Mock(return_value=reply))
        registry.bind_daemon('controlled-daemon')
        record,_=registry.intent(['docker','run','--name','owned-service','--mount',f'type=bind,src={private},dst=/private,readonly',
            'sha256:'+'a'*64,'/opt/pi-lab/worker.py','check'],'owned-service',{'run_id':fresh(),'attempt_id':fresh()},self.root/'run')
        record.update(application_helper=True,client_mode='qualification-fixture',qualification_role='fixture',
            qualification_cell=self.cell['id'],container_id='a'*64)
        registry.write(record);self.service.registry=registry;self.service.items=[(record,'owned-service')]
        self.service.private_identities={record['launch_id']:ownership_registry.observe_qualification_private(record)}
        self.service.service_states={record['launch_id']:{'role':'fixture','ready':False,'observations':self.service.journal}}
        observed={'Id':record['container_id'],'Image':record['image'],'Config':{'Labels':{ownership_registry.LABEL:record['launch_id'],
            ownership_registry.REGISTRY_LABEL:registry.registry_id}},'Mounts':[{'Type':'bind','Source':str(private),'Destination':'/private','RW':False}]}
        with mock.patch.object(harness.lab,'command',return_value=SimpleNamespace(returncode=0,stdout=json.dumps([observed]))),\
             mock.patch.object(self.service,'_diagnose'):
            self.service.close()
        retained=registry.load()[0];self.assertEqual(retained['status'],'released')
        receipt=ownership_registry.validate_qualification_service_cleanup(retained)
        self.assertTrue(receipt['physical_absence_confirmed']);self.assertTrue(receipt['private_bootstrap_removed'])
        self.assertFalse(receipt['qualification_eligible']);self.assertFalse(private.exists());registry.close()


class BoundedServiceLogTests(unittest.TestCase):
    def capture(self,program):
        original=subprocess.Popen
        def child(argv,**kwargs):
            self.assertEqual(argv,['docker','logs','--tail','20','owned-id'])
            return original([sys.executable,'-B','-c',program],**kwargs)
        with mock.patch.object(harness.subprocess,'Popen',side_effect=child):return harness._bounded_service_logs('owned-id',maximum=1024,seconds=1)
    def test_both_pipes_are_bounded_and_complete_bytes_are_retained(self):
        value=self.capture('import sys;sys.stdout.write("out");sys.stderr.write("err")')
        self.assertEqual(value,{'complete':True,'stdout':b'out','stderr':b'err'})
    def test_overlarge_output_and_stalled_reader_return_no_partial_bytes(self):
        for program in ('import sys;sys.stdout.write("x"*4096)','import time;time.sleep(10)'):
            value=self.capture(program);self.assertFalse(value['complete']);self.assertEqual(value['stdout'],b'');self.assertEqual(value['stderr'],b'')


class PrimarySchedulingTests(unittest.TestCase):
    def invoke(self,group):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);root=Path(temporary.name).resolve()
        harness.atomic(root/'state.json',{'schema':1,'phase':'collecting','started_at':None,'active_cell':None,'cells':{}})
        cell={'id':group+'-1.2.0-controlled','group':group,'release':'1.2.0','real_model':group!='N02','scenario':'omitted-report'}
        initial=harness.outcomes.initial();result={**copy.deepcopy(initial),'sealed':True,'status':'FAIL','exit_code':1}
        runroot=root/'runs'/initial['run_id'];runroot.mkdir(parents=True)
        args=SimpleNamespace(results_dir=str(root/'runs'),compiled_plan=str(root/'unused.json'))
        def launch(argv,**kwargs):
            harness.atomic(runroot/'result.json',result)
            harness.atomic(root/'cells'/cell['id']/'child-completion.json',{'schema':1,'run_id':initial['run_id'],'attempt_id':initial['attempt_id'],
                'result_sha256':harness.sha(runroot/'result.json'),'cleanup_checked':True})
            self.envelope=Path(argv[-1]);return SimpleNamespace(pid=12345,returncode=1,poll=lambda:1)
        with mock.patch.object(harness.subprocess,'Popen',side_effect=launch),mock.patch.object(harness,'_cell_args',return_value=args),\
             mock.patch.object(harness.preparation,'load_compiled',return_value={'plan':{'stages':[{}]}}),mock.patch.object(harness,'_runtime_valid',return_value=True),\
             mock.patch.object(harness,'_evaluate',return_value={'status':'FAIL'}) as evaluate:
            if group=='N02':
                with self.assertRaises(harness.QualificationError):harness._invoke_cell(root,{},cell,initial,[])
            else:self.assertEqual(harness._invoke_cell(root,{},cell,initial,[]),result)
        self.assertEqual(harness.read(root/'state.json')['cells'][cell['id']]['status'],'FAIL')
        self.assertIsNone(harness.read(root/'state.json')['active_cell']);self.assertFalse(self.envelope.parent.exists())
        self.assertEqual(harness.read(runroot/'result.json'),result);evaluate.assert_called_once()
    def test_scripted_oracle_failure_stops_without_relabeling_or_replacing_the_failed_primary(self):self.invoke('N02')
    def test_clean_verified_real_quality_failure_remains_a_measurement_and_allows_next_independent_primary(self):self.invoke('N03')
    def test_actual_standalone_latest_alias_is_not_followed_or_counted_as_second_run(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);folder=Path(temporary.name).resolve()
        runs=folder/'runs';run=runs/fresh();run.mkdir(parents=True);harness.atomic(run/'result.json',{'fixture':'stopped'})
        (runs/'latest').symlink_to(run);harness._scan_cell(folder,run,[])
        self.assertTrue((runs/'latest').is_symlink())
        (runs/'latest').unlink();(runs/'latest').symlink_to(folder)
        with self.assertRaises(ValueError):harness._scan_cell(folder,run,[])


class CredentialSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve();self.store=self.root/'store'
        self.refs={'alice':'ALICE_REFERENCE','bob':'BOB_REFERENCE','scripted_inference':'SCRIPT_REFERENCE'}
        self.stored={'ALICE_REFERENCE':'store-alice-value-928374','BOB_REFERENCE':'store-bob-value-583974'}
        for name,value in self.stored.items():secret_store.write_secret(name,value,self.store)
        self.manifest={'credential_references':self.refs,'secrets_dir':str(self.store),'endpoint':{'api_key_env':'MODEL_REFERENCE'},'session':'fixture'}
    def test_application_store_values_override_ambient_aliases_for_both_corpus_and_fixture(self):
        environment={'ALICE_REFERENCE':'ambient-alice-must-not-be-used','BOB_REFERENCE':'ambient-bob-must-not-be-used',
            'SCRIPT_REFERENCE':'script-ambient-value-239847','MODEL_REFERENCE':'model-ambient-value-239847'}
        with mock.patch.dict(os.environ,environment):values=harness._known_values(self.manifest)
        self.assertEqual(values,[self.stored['ALICE_REFERENCE'],self.stored['BOB_REFERENCE'],environment['SCRIPT_REFERENCE'],environment['MODEL_REFERENCE']])
        harness.atomic(self.root/'state.json',{'started_at':None})
        cell={'id':'N03-1.2.0-1','group':'N03','release':'1.2.0'};manifest={**self.manifest,'fixture_route':{'fixture_port':18080}}
        services=harness.OwnedServices(self.root,manifest,cell,SimpleNamespace(_attempt_root=self.root/'run'),mock.Mock(),mock.Mock(),values)
        services.guard.service_cleanup.side_effect=lambda *args:contextlib.nullcontext()
        captured={}
        def start(role,observations,command,port,private):captured.update({path.name:path.read_text() for path in (private/'store').iterdir()})
        with mock.patch.dict(os.environ,environment),mock.patch.object(services,'_start',side_effect=start):services.start()
        self.assertEqual(captured,self.stored);services.close()
    def test_ambient_application_value_cannot_mask_missing_store_before_n01_effects(self):
        (self.store/'ALICE_REFERENCE').unlink();harness.atomic(self.root/'state.json',{'phase':'frozen','cells':{}})
        with mock.patch.dict(os.environ,{'ALICE_REFERENCE':'ambient-cannot-mask-missing-store'}),\
             mock.patch.object(harness,'verify',return_value=(self.manifest,{'phase':'frozen','cells':{}})),\
             mock.patch.object(harness,'_endpoint'),mock.patch.object(harness,'_ledger') as ledger,mock.patch.object(harness,'_native') as native,\
             self.assertRaises(ValueError):harness.admit_images(self.root)
        ledger.assert_not_called();native.assert_not_called()
        self.assertEqual(harness.read(self.root/'state.json'),{'phase':'frozen','cells':{}})
    def test_scripted_diagnostic_authority_cannot_reuse_the_original_model_key(self):
        with mock.patch.dict(os.environ,{'SCRIPT_REFERENCE':'same-original-model-value-192837','MODEL_REFERENCE':'same-original-model-value-192837'}),self.assertRaises(ValueError):
            harness._known_values(self.manifest)


class BrowserDomAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        fixture=c.loads((ROOT/'tests/fixtures/application-contracts/positive.json').read_bytes());self.stage=fixture['source']['stages'][0]
        self.url='http://fixture.invalid:8080/summary';self.stage['_resolved_browser_targets']=[{'id':target,'page_identity':'diagnostic-summary-v1','url':self.url,
            'allowed_operation_ids':[operation]} for target,operation in [('records-button','list-records'),('publish-button','publish-summary')]]
        data=self.root/'application-evidence'/('pi-application-'+'1'*16)/'private';data.mkdir(mode=0o700,parents=True)
        self.evidence=data/'raw';self.evidence.mkdir(mode=0o700)
        self.context={'binding':fixture['receipts'][0]['binding'],'evidence_root':str(self.evidence),'parent_receipts':{}};self.audits=[]
        for index,original in enumerate(fixture['receipts']):
            receipt=copy.deepcopy(original)
            if index:
                action='action-'+str(index).zfill(6);receipt.update(transport='browser',action_id=action)
                captures=[]
                for kind in ('dom_before','dom_after'):
                    dom={'url':self.url,'page_identity':['diagnostic-summary-v1'],'html':'<html>PRIVATE_DOM_NOT_PUBLIC</html>',
                        'form_state':[],'text_content':'PRIVATE_DOM_NOT_PUBLIC','inner_text':'PRIVATE_DOM_NOT_PUBLIC'}
                    path='browser-actions/'+action+'/'+kind+'.txt';body=c.canonical(dom);self.put(path,body)
                    captures.append({'kind':kind,'path':path,'media_type':'application/json','bytes':len(body),'sha256':__import__('hashlib').sha256(body).hexdigest()})
                audit={'schema':1,'document_type':'application_browser_action_receipt','action_id':action,'native_call_id':receipt['native_call_id'],
                    'binding':receipt['binding'],'participant':self.stage['participant'],'target_id':'records-button' if index<3 else 'publish-button',
                    'page_identity':'diagnostic-summary-v1','action':'click','operation_receipt_ids':[receipt['receipt_id']],'resource_receipt_ids':[],
                    'captures':captures,'ok':True,'outcome':'succeeded','reason':None,'denied_requests':0,'elapsed_seconds':0.01,
                    'classification':'native_chromium_cdp','diagnostic':None}
                path='browser-actions/'+action+'/receipt.json';self.put(path,c.canonical(audit));self.audits.append(path)
            path='receipts/'+receipt['receipt_id']+'.json';body=c.canonical(receipt);self.put(path,body)
            self.context['parent_receipts'][receipt['receipt_id']]={'path':path,'sha256':__import__('hashlib').sha256(body).hexdigest()}
    def put(self,relative,body):
        path=self.evidence/relative;path.parent.mkdir(parents=True,mode=0o700,exist_ok=True);path.write_bytes(body);path.chmod(0o600)
    def check(self):return harness.browser_dom_audit(self.root,self.stage,self.context)
    def test_three_bound_business_audits_and_six_dom_captures_yield_only_safe_counts_and_hashes(self):
        result=self.check();self.assertEqual((result['status'],result['actions_verified'],result['dom_captures_verified']),('PASS',3,6))
        self.assertEqual(len(result['capture_sha256']),6);self.assertNotIn('PRIVATE_DOM_NOT_PUBLIC',json.dumps(result))
    def test_forged_classification_fails_without_echoing_the_observed_string(self):
        path=self.evidence/self.audits[0];value=harness.read(path);value['classification']='FORGED_PRIVATE_CANARY';path.write_bytes(c.canonical(value))
        result=self.check();self.assertEqual(result['status'],'FAIL');self.assertNotIn('FORGED_PRIVATE_CANARY',json.dumps(result))
    def test_tampered_dom_fails_against_its_retained_bytes_and_hash(self):
        value=harness.read(self.evidence/self.audits[0]);path=self.evidence/value['captures'][0]['path'];path.write_bytes(path.read_bytes()+b' ')
        self.assertEqual(self.check()['status'],'FAIL')
    def test_missing_audit_or_cross_binding_never_becomes_native_dom_proof(self):
        path=self.evidence/self.audits[0];body=path.read_bytes();path.unlink();self.assertEqual(self.check()['status'],'FAIL')
        value=c.loads(body);value['native_call_id']='different-call';path.write_bytes(c.canonical(value));self.assertEqual(self.check()['status'],'FAIL')
    def test_old_wrapper_or_noncanonical_namespace_fails_before_any_evidence_open(self):
        old=self.evidence.parent.parent/'raw'
        for path in (str(old),str(self.evidence.parent)+'//raw',str(self.evidence.parent)+'/./raw'):
            self.context['evidence_root']=path
            with mock.patch.object(harness,'open_directory') as opening,mock.patch.object(harness,'read_file') as reading:
                self.assertEqual(self.check()['status'],'FAIL')
            opening.assert_not_called();reading.assert_not_called()
    def test_public_or_linked_private_parent_rejects_before_capture_reads(self):
        parent=self.evidence.parent;parent.chmod(0o755)
        with mock.patch.object(harness,'read_file') as reading:self.assertEqual(self.check()['status'],'FAIL')
        reading.assert_not_called();parent.chmod(0o700)
        retained=parent.with_name('retained-private');parent.rename(retained);parent.symlink_to(retained,target_is_directory=True)
        with mock.patch.object(harness,'read_file') as reading:self.assertEqual(self.check()['status'],'FAIL')
        reading.assert_not_called();self.assertTrue((retained/'raw').is_dir())


class PublicReportProjectionTests(unittest.TestCase):
    def test_unknown_status_runner_status_and_noninteger_attempts_are_rejected(self):
        manifest={'qualification_id':fresh(),'cells':[{'id':'N03-1.2.0-1','group':'N03','release':'1.2.0','real_model':True}],
            'limits':harness.LIMITS,'sensitive_negative_scope':'PRIVATE_CANARY'}
        for observed in ({'status':'PRIVATE_CANARY'},{'status':'FAIL','runner_status':'PRIVATE_CANARY'},
                         {'status':'FAIL','attempts':{'private':'PRIVATE_CANARY'}},{'status':'FAIL','attempts':True}):
            with self.subTest(observed=observed),mock.patch.object(harness,'verify',return_value=(manifest,{'phase':'collecting','cells':{'N03-1.2.0-1':observed}})),self.assertRaises(ValueError):harness.report('/unused')
        with mock.patch.object(harness,'verify',return_value=(manifest,{'phase':'collecting','cells':{'N03-1.2.0-1':{'status':'FAIL','runner_status':'FAIL','attempts':1}}})):
            result=harness.report('/unused');self.assertEqual(result['cells'][0]['runner_status'],'FAIL');self.assertNotIn('PRIVATE_CANARY',json.dumps(result))


if __name__=='__main__':unittest.main()
