"""Retained qualification contracts using only NONSECRET owned fixtures.

No Docker, VM, API, model, real credential, old evidence or PID query. Tests are
authored independently from the retained implementation; Root runs them later.
"""
import copy
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime'),
              str(ROOT/'tools/qualification'),str(ROOT/'tests')]
import application_retained as retained
import application_launch as launch
import test_application_qualification as qualification_fixtures

q=qualification_fixtures.harness
ORIGINAL_SECRET_READ=q.secret_store.read_secret
ORIGINAL_ENDPOINT_SECRET=q.lab.endpoint_secret
SENSITIVE='N02-0.87.1-commit-and-interruption-b'
EXPECTED_RETAINED={
    'N01-0.87.1-core','N01-0.87.1-browser','N01-1.2.0-core','N01-1.2.0-browser',
    'N02-0.87.1-request-and-persona-a','N02-0.87.1-request-and-persona-b',
    'N02-0.87.1-reporting-and-reserve-a','N02-0.87.1-reporting-and-reserve-b',
    'N02-0.87.1-commit-and-interruption-a'}


class RetainedQualificationTests(unittest.TestCase):
    def write(self,name,value):
        return qualification_fixtures.QualificationTests.write(self,name,value)

    def setUp(self):
        # Composition deliberately does not inherit/re-discover the old tests.
        complete_source=q.source_identity()
        qualification_fixtures.QualificationTests.setUp(self)
        self.identity.update(copy.deepcopy(complete_source))

    def full_cells(self):
        return q.matrix(self.images)

    def put(self,path,value):
        path=Path(path);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        q.atomic(path,value)
        return path

    def reference(self,path):
        return {'path':str(Path(path)),'sha256':q.sha(path)}

    def freeze_kwargs(self):
        return {'session':'controlled-confirmed-session','approved_endpoint_path':self.endpoint_path,
                'image_receipts':self.paths,'fixture_route':self.route,
                'credential_references':self.refs,'secrets_dir':self.store}

    def native_snapshot(self,stage,scenario):
        fields=q.native_budget_controls.COUNTER_FIELDS
        counts=dict.fromkeys(fields,0)
        calls=q.SCRIPT_RESULTS[scenario]
        counts.update(attempted=calls,charged=calls,grants_consumed=calls,
                      executed_known=calls,helper_verified=calls,executed=calls)
        phase='business'
        if scenario=='invalid-typed-request':
            counts.update(charged=1,grants_consumed=0,executed_known=0,
                          helper_verified=0,blocked=1,executed=0)
        if scenario=='multi-call-reserve-boundary':
            counts.update(q.RESERVE_COUNTS);counts['executed']=counts['executed_known'];phase='reporting'
        limits={k:stage['limits'][k] for k in q.native_budget_controls.NATIVE_FIELDS}
        remaining=limits['max_tool_calls']-counts['charged']
        per_tool={name:dict.fromkeys(fields,0) for name in [*stage['tools'],'__unknown__']}
        per_tool['app_api']=copy.deepcopy(counts)
        result={'schema':1,'document_type':'native_tool_budget_status','phase':phase,
                'accounting':'available','limits':limits,'counts':counts,'per_tool':per_tool,
                'remaining_calls':remaining,'remaining_admissible_calls':remaining,
                'business_calls_remaining':max(0,remaining-limits['reporting_reserve_calls']) if phase=='business' else 0,
                'reporting_reserve_calls_remaining':min(remaining,limits['reporting_reserve_calls']),
                'assisted':False}
        # A genuine validator checks the synthetic worker-boundary snapshot.
        return q.native_budget_controls.public_snapshot(result,allowed_tools=stage['tools'])

    def original_negative_artifacts(self,root,cell,initial,*,unsafe=False):
        """Native execution is the fake boundary; sealing and all oracles are real."""
        experiment=Path(root)/('scripted-'+cell['release'])
        metadata,mapping=q.experiments.verify(experiment,q.lab)
        trial=next(v for v in mapping['cells'] if v['trial_id']==cell['trial_id'])
        plan=q.preparation.load_compiled(experiment/trial['compiled_plan'],verify_runner=True)['plan']
        stage=plan['stages'][0];run=experiment/'runs'/initial['run_id']
        args=SimpleNamespace(results_dir=str(experiment/'runs'),project=str(experiment/trial['source']))
        attempt=q.outcomes.Attempt(args,copy.deepcopy(initial))
        self.assertEqual(attempt.root,run)
        record=attempt.record
        binding={'run_id':initial['run_id'],'attempt_id':initial['attempt_id'],
                 'trial_id':initial['trial_id'],'stage_id':str(uuid.uuid4()),
                 'segment_id':str(uuid.uuid4()),'plan_sha256':plan['plan_sha256'],
                 'profile_sha256':stage['profile_binding']['sha256'],
                 'report_contract_sha256':q.c.digest(stage['completion'])}
        report_root=run/'reports';evidence_root=run/'evidence'
        report_root.mkdir(mode=0o700);(evidence_root/'receipts').mkdir(parents=True,mode=0o700)
        lost=cell['scenario']=='publication-response-loss'
        receipt_id='nonsecret-fixture-receipt'
        receipt={'schema':1,'document_type':'application_operation_receipt',
                 'receipt_id':receipt_id,'binding':binding,'participant':stage['participant'],
                 'sequence':1,'operation_instance_id':str(uuid.uuid4()),'evidence':[],
                 'operation_id':'publish-summary' if lost else 'identity','pagination':None,
                 'effect':'publication' if lost else 'identity',
                 'outcome':'outcome_unknown' if lost else 'failed'}
        receipt_path=self.put(evidence_root/'receipts/fixture.json',receipt)
        context={'binding':binding,'authorized_segment_ids':[binding['segment_id']],
                 'parent_receipts':{receipt_id:{'path':'receipts/fixture.json','sha256':q.sha(receipt_path)}},
                 'report_root':str(report_root),'evidence_root':str(evidence_root)}
        completion={'status':'incomplete','diagnostics':[]}
        if cell['scenario']=='wrong-actor':completion.update(status='invalid',diagnostics=[{'code':'participant_mismatch'}])
        if cell['scenario']=='omitted-report':completion['diagnostics']=[{'code':'report_missing'}]
        if lost:completion['diagnostics']=[{'code':'publication_outcome_unknown'}]
        process={'cleanup_confirmed':not unsafe,'exit_code':0,'segments':[{'synthetic_worker_boundary':True}],
                 'application_helper_cleanup':{'schema':1,'status':'removed','workspace':'clean','safe_to_continue':not unsafe},
                 'application_credentials':{'schema':1,'status':'removed','workspace':'clean'},
                 'native_tool_manifest':{'schema':1,'tools':stage['tools']},
                 'native_tool_budget':self.native_snapshot(stage,cell['scenario']),
                 'evidence':{'completion_verified':True},'application_completion_context':context,
                 'application_completion':copy.deepcopy(completion)}
        self.put(run/'stages'/binding['stage_id']/'descriptor.json',
            {'schema':2,'kind':'agent','label':'agent-1-participant',
             'stage_id':binding['stage_id'],'run_id':initial['run_id'],'attempt_id':initial['attempt_id']})
        self.put(run/'stages'/binding['stage_id']/'state.json',
            {'status':'finalized','cleanup_confirmed':not unsafe,
             'segment_id':binding['segment_id'],'exit_code':130 if cell['scenario']=='sensitive-participant-interruption' else 0})
        record.update(infrastructure={'status':'ready','phase':'complete'},
                      invocation={'status':'verified','attempted_stages':1},
                      termination={'reason':'completed'},scoring={'status':'completed'},
                      task_result={'status':'pass'},protected_inputs={'status':'unchanged'},
                      agents=[{'name':stage['id'],'process':process}],checks=[],
                      application_completion={'stages':[copy.deepcopy(completion)]},
                      synthetic_fixture='NONSECRET fake execution boundary, not native evidence')
        sensitive=cell['scenario']=='sensitive-participant-interruption'
        if sensitive:
            record['termination']['reason']='cancelled'
            record['application_completion']['stages'][0]['status']='not_evaluated'
            process['application_completion']['status']='not_evaluated'
            process.update(exit_code=130,cancelled=True,timed_out=False)
        result=attempt.finalize()
        self.put(run/'plan.json',plan)
        folder=Path(root)/'cells'/cell['id'];folder.mkdir(parents=True,exist_ok=True,mode=0o700)
        fixture_id=str(uuid.uuid4());requests=[];publications=[]
        if cell['scenario']=='wrong-actor':requests=[{'method':'GET','path':'/identity','actor_id':'actor-bob'}]
        if cell['scenario']=='multi-call-reserve-boundary':requests=[{'method':'GET','path':'/identity','actor_id':'actor-alice'}]
        if cell['scenario'] in ('omitted-report','publication-response-loss'):
            requests=[{'method':'POST','path':'/publish','actor_id':'actor-alice'}]
            expected=q.read(q.EXAMPLE/'expected.json')
            content_hash=hashlib.sha256(expected['content'].encode()).hexdigest()
            publications=[{'actor_id':expected['participant']['actor_id'],'target_id':expected['target_id'],
                'artifact_id':expected['artifact_id'],'artifact_sha256':content_hash,'content_sha256':content_hash,
                'content_bytes':len(expected['content'].encode()),'publication_id':str(uuid.uuid4())}]
        journal_path=self.put(folder/'fixture-journal/private/journal.json',
            {'fixture_id':fixture_id,'closed':True,'requests':requests,'pages':[],'publications':publications})
        terminal_path=self.put(folder/'fixture-journal/private/terminal-receipt.json',
            {'schema':1,'document_type':'application_fixture_terminal_receipt','fixture_id':fixture_id,
             'journal':{'path':'journal.json','sha256':q.sha(journal_path),'bytes':journal_path.stat().st_size},
             'process':{'exit_code':0,'cleanup_confirmed':True,'writers_stopped':True}})
        parent_path=self.put(folder/'fixture-journal/private/parent-receipt.json',
            {'schema':1,'document_type':'authenticated_application_parent_receipt',
             'run':{'run_id':initial['run_id'],'attempt_id':initial['attempt_id'],
                    'result_sha256':q.sha(run/'result.json'),'writers_stopped':True,'cleanup_confirmed':True},
             'fixture':{'fixture_id':fixture_id,'terminal_sha256':q.sha(terminal_path),
                        'writers_stopped':True,'cleanup_confirmed':True}})
        oracle_module=q._module('retained_test_original_oracle',q.EXAMPLE/'oracle.py')
        oracle=oracle_module.evaluate(run,journal_path.parent,None if sensitive else q.read(parent_path))
        oracle_path=self.put(folder/'oracle.json',oracle)
        services_path=self.put(folder/'services-cleanup.json',{'schema':1,'safe_to_continue':not unsafe})
        completion_path=self.put(folder/'child-completion.json',{'schema':1,'run_id':initial['run_id'],
            'attempt_id':initial['attempt_id'],'result_sha256':q.sha(run/'result.json'),'cleanup_checked':not unsafe})
        script_path=self.put(folder/'scripted-observations/private/scripted.json',
            {'case_id':cell['case'],'model':'application-script-'+cell['variant'],'stopped':True,
             'unexpected_results':0,'tool_results':q.SCRIPT_RESULTS[cell['scenario']],
             'emitted_tool_calls':q.SCRIPT_RESULTS[cell['scenario']],'usage_accounting':'synthetic_fixed_16_16'})
        stage_metadata=[{'kind':'agent','run_id':initial['run_id'],'attempt_id':initial['attempt_id'],
                         'stage_id':binding['stage_id'],'label':'agent-1-participant'}]
        verdict=q.negative_verdict(cell['scenario'],result,q.read(journal_path),oracle,
            interruption_sent=sensitive,participant_launches=1,stage_metadata=stage_metadata)
        verdict['checks']['scripted_result_sequence']=True
        verdict['status']='PASS' if all(verdict['checks'].values()) else 'FAIL'
        qualification_path=self.put(folder/'qualification.json',{'cell_id':cell['id'],
            'run_id':initial['run_id'],'attempt_id':initial['attempt_id'],
            'result_sha256':q.sha(run/'result.json'),'real_model':False,**verdict})
        return {'run':run,'result':result,'verdict':verdict,'paths':{
            'qualification':qualification_path,'result':run/'result.json','plan':run/'plan.json',
            'oracle':oracle_path,'journal':journal_path,'scripted':script_path,
            'services_cleanup':services_path,'child_completion':completion_path,
            'parent_receipt':parent_path,'fixture_terminal':terminal_path}}

    def prior_fixture(self):
        self.prior=self.output
        q.freeze(self.prior,**self.freeze_kwargs())
        manifest,state=q.verify(self.prior)
        q.bind_candidate(self.prior,{'archive_sha256':'a'*64,'runner_sha256':self.identity['runner'],
                                     'scope':'extracted_candidate'})
        self.full=manifest['cells'];old,fresh=retained.partition(self.full)
        index_rows=[];state['phase']='blocked';state['cells']={}
        for cell in old:
            folder=self.prior/'cells'/cell['id'];folder.mkdir(mode=0o700,parents=True,exist_ok=True)
            if cell['group']=='N01':
                if cell['profile']=='core':
                    admission_path=self.put(folder/'runtime.json',manifest['images']['core-'+cell['release']])
                else:
                    admission=q.read(self.paths['browser-'+cell['release']])
                    admission['image']=manifest['images']['browser-'+cell['release']]
                    admission['observations']=[{'browser_sandbox':{'namespace_and_seccomp_verified':True}},
                        {'browser_dom_ok':True,'webgl_ok':True,'no_browser_sandbox':False,'software_webgl':False}]
                    admission_path=self.put(folder/('browser-'+uuid.uuid4().hex)/'browser-admission.json',admission)
                    self.assertTrue(q._browser_admitted(admission,cell))
                index_rows.append({'cell_id':cell['id'],'kind':'admission','admission':self.reference(admission_path)})
                state['cells'][cell['id']]={'status':'PASS','attempts':1}
                continue
            exp=self.prior/('scripted-'+cell['release']);metadata,mapping=q.experiments.verify(exp,q.lab)
            trial=next(v for v in mapping['cells'] if v['trial_id']==cell['trial_id'])
            intent,path=q.experiments.reserve_attempt(exp,metadata,trial)
            artifact=self.original_negative_artifacts(self.prior,cell,intent['initial_record'])
            self.assertEqual(artifact['verdict']['status'],'PASS',cell['scenario'])
            self.assertTrue(q._runtime_valid(artifact['result'],q.read(artifact['paths']['plan'])['stages'][0]))
            intent.update(status='finalized',result='runs/'+intent['run_id']+'/result.json',
                          result_sha256=q.sha(artifact['paths']['result']))
            q.atomic(path,intent)
            self.assertEqual(q.experiments.sealed_result(exp,intent),artifact['result'])
            self.assertTrue(q.experiments.cleanup_known(exp,intent,artifact['result']))
            index_rows.append({'cell_id':cell['id'],'kind':'negative','run_id':intent['run_id'],
                'attempt_id':intent['attempt_id'],'attempt_intent':self.reference(path),
                **{k:self.reference(v) for k,v in artifact['paths'].items()}})
            state['cells'][cell['id']]={'status':'PASS','attempts':1,'run_id':intent['run_id'],
                                      'attempt_id':intent['attempt_id']}
        failed_identity=q.outcomes.initial()
        state['cells'][SENSITIVE]={'status':'BLOCKED','attempts':1,'run_id':failed_identity['run_id'],
                                  'attempt_id':failed_identity['attempt_id'],'private_cleanup':'unconfirmed'}
        state['active_cell']={'id':SENSITIVE,'pid':123456,'run_id':failed_identity['run_id'],
                              'attempt_id':failed_identity['attempt_id']}
        self.put(self.prior/'state.json',state)
        policy=q._launch_manifest(manifest)
        ledger=launch.LaunchLedger.create(self.prior/'launch-ledger',policy,
            daemon_id='NONSECRET_FAKE_DAEMON',daemon_capacity={'cpu_millis':7000,'memory_mib':8192},
            clock=lambda:100.,wall=lambda:1000.)
        daemon={'id':'NONSECRET_FAKE_DAEMON','cpu_millis':7000,'memory_mib':8192}
        registry=q.ownership_registry.Registry(self.root/'synthetic-registry',command=mock.Mock(side_effect=AssertionError('NO_DOCKER')))
        pending=[]
        for cell in [*old,next(c for c in fresh if c['id']==SENSITIVE)]:
            for role in cell['role_limits']:
                if cell['id']==SENSITIVE and role=='scorer':continue
                image=manifest['images']['core-'+cell['release']]['id'] if role in launch.EXTERNAL else cell['image_id']
                ident=str(uuid.uuid4())
                record={'schema':1,'registry':registry.registry_id,'generation':registry.generation,
                        'launch_id':ident,'container':'synthetic-'+uuid.uuid4().hex[:12],'image':image,
                        'status':'intent','mounts':[],'binding':{},'runroot':None,
                        'daemon':daemon['id'],'created_at':'NONSECRET_FIXTURE'}
                weight=launch._role_weight(policy,cell,role)
                key=ledger.reserve(cell['id'],role,record,weight,daemon)
                ledger.note(key,physical='absent',private_cleanup=True,
                            container_id=hashlib.sha256(ident.encode()).hexdigest())
                if cell['id']==SENSITIVE and role in ('probe','boundary','preflight','participant'):pending.append(key)
        for key in pending:ledger.note(key,private_cleanup=False,poison=True)
        self.assertEqual(len(q.read(self.prior/'launch-ledger/ledger.json')['launches']),53)
        index={'schema':1,'document_type':'application_retained_evidence_index','prior_root':str(self.prior),
            'prior_manifest':self.reference(self.prior/'manifest.json'),
            'prior_candidate':self.reference(self.prior/'candidate.json'),
            'prior_state':self.reference(self.prior/'state.json'),
            'prior_ledger':self.reference(self.prior/'launch-ledger/ledger.json'),
            'historical_use':{'containers':387,'participants':27},
            'excluded_failed_cell':{'cell_id':SENSITIVE,'disposition':'NOT_RETAINED',
                                    'reason':'signal_provenance_not_established'},'cells':index_rows}
        self.index=index
        self.compatibility={'schema':1,'document_type':'application_retained_compatibility_review',
            'status':'PASS','unresolved':[],'index_sha256':q.c.digest(index),
            'prior_source_sha256':manifest['source']['sha256'],'current_source_sha256':self.identity['sha256'],
            'runner_sha256':self.identity['runner'],'runner_files_sha256':q.c.digest(self.identity['runner_files']),
            'release_contracts_sha256':q.c.digest(self.identity['release_contracts']),
            'changed_qualification_files':[]}
        self.new=self.root/'retained-qualification'
        return index

    def prepare(self):
        return retained.prepare(q,self.new,retained_index=self.index,
            compatibility=self.compatibility,freeze_kwargs=self.freeze_kwargs())

    def refresh_index(self):
        self.compatibility['index_sha256']=q.c.digest(self.index)

    @contextlib.contextmanager
    def disposable_authorities(self):
        """Real original admission reads ONLY explicitly owned NONSECRET files."""
        values={self.refs['alice']:'NONSECRET-retained-alice-183746',
                self.refs['bob']:'NONSECRET-retained-bob-276491',
                self.refs['scripted_inference']:'NONSECRET-retained-script-398127',
                'MODEL_REFERENCE':'NONSECRET-retained-model-475163'}
        for name,value in values.items():q.secret_store.write_secret(name,value,self.store)
        def read(name,store=None):
            self.assertIn(name,values);self.assertEqual(Path(store),self.store)
            return ORIGINAL_SECRET_READ(name,store)
        def endpoint(endpoint,args):
            self.assertIn(endpoint['api_key_env'],values)
            self.assertEqual(Path(args.secrets_dir),self.store)
            return ORIGINAL_ENDPOINT_SECRET(endpoint,args)
        with mock.patch.dict(os.environ,{name:'' for name in values}), \
             mock.patch.object(q.secret_store,'read_secret',side_effect=read), \
             mock.patch.object(q.lab,'endpoint_secret',side_effect=endpoint):
            yield

    def scripted_fixture(self,release,*,unsafe=False,fail_before_result=False):
        self.prior_fixture();self.prepare();manifest,_=retained.verify(q,self.new)
        selected=[c for c in manifest['cells'] if c['group']=='N02' and c['release']==release]
        seen=[]
        def invoke(root,full,cell,initial,values):
            seen.append((cell['id'],copy.deepcopy(initial)))
            experiment=self.new/('scripted-'+release)
            metadata,mapping=q.experiments.verify(experiment,q.lab)
            trial=next(c for c in mapping['cells'] if c['trial_id']==cell['trial_id'])
            intents=q.experiments.attempt_intents(experiment,trial)
            self.assertEqual(len(intents),1)
            self.assertEqual(intents[0]['initial_record'],initial)
            args=q.experiments.trial_args(experiment,metadata,trial,q.lab,manifest['session'])
            self.assertEqual(args._application_variant_context['trial_id'],cell['trial_id'])
            self.assertEqual(Path(args.compiled_plan),experiment/trial['compiled_plan'])
            if fail_before_result:raise ValueError('NONSECRET_FAKE_WORKER_FAILURE')
            artifact=self.original_negative_artifacts(root,cell,initial,unsafe=unsafe)
            state=q.read(self.new/'state.json')
            state['cells'][cell['id']]={'status':artifact['verdict']['status'],'attempts':1,
                'run_id':initial['run_id'],'attempt_id':initial['attempt_id'],
                'runner_status':artifact['result']['status'],
                'exit_code':artifact['result']['exit_code'],
                'interruption_sent':cell['scenario']=='sensitive-participant-interruption'}
            self.put(self.new/'state.json',state)
            return artifact['result']
        return manifest,selected,seen,invoke

    def test_exact_nine_retained_nineteen_fresh_partition_preserves_input(self):
        cells=self.full_cells();before=copy.deepcopy(cells)
        old,fresh=retained.partition(cells)
        self.assertEqual(cells,before)
        self.assertEqual({c['id'] for c in old},EXPECTED_RETAINED)
        self.assertEqual((len(old),len(fresh)),(9,19))
        self.assertFalse({c['id'] for c in old}&{c['id'] for c in fresh})
        self.assertEqual({c['id'] for c in old}|{c['id'] for c in fresh},
                         {c['id'] for c in cells})

    def test_failed_old_sensitive_case_is_fresh_not_a_retained_pass(self):
        old,fresh=retained.partition(self.full_cells())
        self.assertNotIn(SENSITIVE,{c['id'] for c in old})
        selected=[c for c in fresh if c['id']==SENSITIVE]
        self.assertEqual(len(selected),1)
        self.assertEqual(selected[0]['scenario'],'sensitive-participant-interruption')
        self.assertEqual(selected[0]['max_attempts'],1)

    def test_fresh_role_envelope_is140_19_and_carry_is527_46(self):
        old,fresh=retained.partition(self.full_cells())
        self.assertEqual(sum(c['container_launches_max'] for c in fresh),140)
        self.assertEqual(sum(c['participant_segments_max'] for c in fresh),19)
        self.assertTrue(all(c['container_launches_max']==sum(c['role_limits'].values()) for c in fresh))
        self.assertTrue(all(type(c['max_attempts']) is int and c['max_attempts']==1 for c in fresh))
        self.assertEqual(387+sum(c['container_launches_max'] for c in fresh),527)
        self.assertEqual(27+sum(c['participant_segments_max'] for c in fresh),46)
        self.assertEqual(sum(c['container_launches_max'] for c in old),46)

    def test_only_one_sensitive_old_release_and_six_new_release_scripted_trials(self):
        _,fresh=retained.partition(self.full_cells())
        first=[c for c in fresh if c['group']=='N02' and c['release']=='0.87.1']
        second=[c for c in fresh if c['group']=='N02' and c['release']=='1.2.0']
        self.assertEqual([c['id'] for c in first],[SENSITIVE])
        self.assertEqual(len(second),6)
        self.assertEqual({(c['case'],c['variant']) for c in second},
                         {(case,variant) for case,variant,_ in q.NEGATIVES})
        self.assertFalse(any(c['group']=='N01' for c in fresh))
        self.assertEqual(sum(c['real_model'] for c in fresh),12)

    def test_partition_refuses_duplicate_missing_or_unlisted_cells(self):
        for kind in ('duplicate','missing','unknown'):
            cells=self.full_cells()
            if kind=='duplicate':cells[-1]=copy.deepcopy(cells[0])
            elif kind=='missing':cells.pop()
            else:cells[-1]['id']='N05-unbudgeted'
            with self.subTest(kind=kind),self.assertRaises(ValueError):retained.partition(cells)

    def test_genuine_retained_predicates_prepare_empty_actual_state_without_clock(self):
        self.prior_fixture()
        prior_state=(self.prior/'state.json').read_bytes()
        prior_ledger=(self.prior/'launch-ledger/ledger.json').read_bytes()
        self.prepare();manifest,state=retained.verify(q,self.new)
        self.assertEqual(state,{'schema':1,'phase':'frozen','active_cell':None,'cells':{},'started_at':None})
        self.assertEqual(len(manifest['cells']),19)
        self.assertEqual(manifest['planned_container_launches'],140)
        self.assertEqual(manifest['limits']['container_launch_attempts'],140)
        self.assertEqual(manifest['limits']['participant_segments'],19)
        self.assertFalse((self.new/'launch-ledger').exists())
        self.assertEqual((self.prior/'state.json').read_bytes(),prior_state)
        self.assertEqual((self.prior/'launch-ledger/ledger.json').read_bytes(),prior_ledger)
        self.assertTrue(q.read(self.prior/'launch-ledger/ledger.json')['poisoned'])
        self.assertIsNotNone(q.read(self.prior/'state.json')['active_cell'])
        report=retained.report(q,self.new)
        self.assertEqual(report['status'],'NOT_READY')
        self.assertEqual(sum(r['origin']=='retained' for r in report['cells']),9)
        self.assertTrue(all(r['attempts_this_scope']==0 for r in report['cells']))
        self.assertTrue(all(r['status']=='NOT_RUN' for r in report['cells'] if r['origin']=='new'))
        self.assertEqual(report['excluded_failed_cell'],{'id':SENSITIVE,'status':'BLOCKED','retained':False})

    def test_typed_launch_manifest_enforces_local140_19_without_fake_carry(self):
        self.prior_fixture();self.prepare();manifest,_=retained.verify(q,self.new)
        projected=retained.launch_manifest(q,manifest)
        self.assertEqual(len(projected['cells']),19)
        self.assertEqual(projected['planned_container_launches'],140)
        self.assertEqual(projected['limits'],{'global_seconds':14400,'cleanup_reserve_seconds':30,
            'container_launch_attempts':140,'live':4,'participant_segments':19})
        self.assertNotIn('predecessor',projected);self.assertNotIn('carry',projected)
        self.assertEqual(launch.validate_manifest(projected),projected)
        for key,value in (('container_launch_attempts',141),('participant_segments',20),('live',5),('global_seconds',14401)):
            wrong=copy.deepcopy(projected);wrong['limits'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):launch.validate_manifest(wrong)
        wrong=copy.deepcopy(projected);wrong.pop('retained_requalification')
        with self.assertRaises(ValueError):launch.validate_manifest(wrong)

    def test_marker_rejects_old_caps_other_caps_bool_counts_and_new_role(self):
        self.prior_fixture();self.prepare();manifest,_=retained.verify(q,self.new)
        marker=manifest['retained_requalification']
        for caps in ({'containers':520,'participants':45},{'containers':573,'participants':51}):
            wrong=copy.deepcopy(marker);wrong['cumulative_ceiling']=caps
            with self.subTest(caps=caps),self.assertRaises(ValueError):retained.validate_marker(wrong)
        for field,key in (('historical_use','participants'),('local_plan','participants')):
            wrong=copy.deepcopy(marker);wrong[field][key]=True
            with self.assertRaises(ValueError):retained.validate_marker(wrong)
        wrong=retained.launch_manifest(q,manifest);wrong['cells'][0]['role_limits']['auxiliary']=1
        wrong['cells'][0]['container_launches_max']+=1
        with self.assertRaises(ValueError):launch.validate_manifest(wrong)

    def test_index_rejects_blocked_cell_substitution_duplicate_and_PASS_carrier(self):
        self.prior_fixture();before=copy.deepcopy(self.index)
        retained.validate_index(self.index,self.full)
        self.assertEqual(self.index,before)
        for kind in ('failed','duplicate','boolean'):
            value=copy.deepcopy(self.index)
            if kind=='failed':value['cells'][-1]['cell_id']=SENSITIVE
            elif kind=='duplicate':value['cells'][-1]=copy.deepcopy(value['cells'][0])
            else:value['cells'][0]['PASS']=True
            with self.subTest(kind=kind),self.assertRaises(ValueError):retained.validate_index(value,self.full)

    def test_mutated_evidence_hash_is_rejected_before_any_runtime_delegate(self):
        self.prior_fixture()
        row=next(r for r in self.index['cells'] if r['kind']=='negative')
        path=Path(row['scripted']['path']);path.write_bytes(path.read_bytes()+b' ')
        with mock.patch.object(q,'_invoke_cell') as invoke,self.assertRaises(ValueError):self.prepare()
        invoke.assert_not_called()

    def test_rehashed_wrong_role_or_false_history_cannot_become_retained_evidence(self):
        self.prior_fixture()
        ledger_path=self.prior/'launch-ledger/ledger.json';original=ledger_path.read_bytes()
        ledger=q.read(ledger_path);ledger['launches'][0]['role']='unreviewed-auxiliary'
        self.put(ledger_path,ledger);self.index['prior_ledger']=self.reference(ledger_path);self.refresh_index()
        malformed=ledger_path.read_bytes()
        with self.assertRaises(ValueError):self.prepare()
        self.assertEqual(ledger_path.read_bytes(),malformed)
        self.assertNotEqual(ledger_path.read_bytes(),original)

    def test_rehashed_old_BLOCKED_is_not_retained_even_with_a_PASS_review(self):
        self.prior_fixture()
        path=self.prior/'state.json';state=q.read(path)
        state['cells'][next(iter(EXPECTED_RETAINED))]['status']='BLOCKED'
        self.put(path,state);self.index['prior_state']=self.reference(path);self.refresh_index()
        with self.assertRaises(ValueError):self.prepare()
        self.assertEqual(q.read(path)['cells'][SENSITIVE]['status'],'BLOCKED')

    def test_rehashed_scripted_tool_usage_and_unknown_sequence_do_not_pass(self):
        self.prior_fixture();row=next(r for r in self.index['cells'] if r['kind']=='negative')
        path=Path(row['scripted']['path']);value=q.read(path)
        value.update(unexpected_results=1,usage_accounting='guessed',emitted_tool_calls=999)
        self.put(path,value);row['scripted']=self.reference(path);self.refresh_index()
        with self.assertRaises(ValueError):self.prepare()

    def test_changed_model_or_runner_or_source_provenance_is_not_compatible(self):
        self.prior_fixture();original=copy.deepcopy(self.compatibility)
        for field in ('index_sha256','prior_source_sha256','current_source_sha256','runner_sha256','runner_files_sha256','release_contracts_sha256'):
            self.compatibility=copy.deepcopy(original);self.compatibility[field]='f'*64
            self.new=self.root/('bad-'+field)
            with self.subTest(field=field),self.assertRaises(ValueError):self.prepare()
        self.compatibility=original;self.new=self.root/'wrong-model'
        self.endpoint['model']='unapproved-other-model'
        self.endpoint_path.write_bytes(q.c.canonical(self.endpoint))
        with self.assertRaises(ValueError):self.prepare()

    def test_review_cannot_approve_an_oracle_source_change_outside_qualifier_delta(self):
        self.prior_fixture();path=self.prior/'manifest.json';manifest=q.read(path)
        name='skill/examples/authenticated-application/oracle.py'
        manifest['source']['files'][name]='f'*64
        manifest['source']['sha256']=q.provenance.digest(manifest['source']['files'])
        self.put(path,manifest);self.index['prior_manifest']=self.reference(path)
        self.compatibility['prior_source_sha256']=manifest['source']['sha256']
        self.compatibility['changed_qualification_files']=[name];self.refresh_index()
        with self.assertRaises(ValueError):self.prepare()

    def test_rehashed_prior_ledger_clock_extension_is_rejected_by_original_validator(self):
        self.prior_fixture();path=self.prior/'launch-ledger/ledger.json';ledger=q.read(path)
        ledger['deadline']=ledger['started']+14401
        self.put(path,ledger);self.index['prior_ledger']=self.reference(path);self.refresh_index()
        with self.assertRaises(ValueError):self.prepare()

    def test_fake_retained_PASS_in_new_actual_state_is_rejected(self):
        self.prior_fixture();self.prepare()
        path=self.new/'state.json';state=q.read(path)
        state['phase']='collecting';state['cells'][next(iter(EXPECTED_RETAINED))]={'status':'PASS','attempts':1}
        self.put(path,state)
        with self.assertRaises(ValueError):retained.verify(q,self.new)
        with self.assertRaises(ValueError):retained.report(q,self.new)

    def test_new_PASS_string_without_owning_evidence_cannot_satisfy_prerequisites(self):
        self.prior_fixture();self.prepare();path=self.new/'state.json';state=q.read(path)
        state['phase']='collecting'
        state['cells'][SENSITIVE]={'status':'PASS','attempts':1,'run_id':str(uuid.uuid4()),
            'attempt_id':str(uuid.uuid4()),'runner_status':'INTERRUPTED','exit_code':2,
            'interruption_sent':True}
        self.put(path,state)
        with self.assertRaises((ValueError,OSError)):retained.verify(q,self.new)
        with self.assertRaises((ValueError,OSError)):retained.report(q,self.new)

    def test_preparation_is_immutable_and_has_no_active_ledger_or_window(self):
        self.prior_fixture();self.prepare()
        manifest=(self.new/'manifest.json').read_bytes()
        with self.assertRaises(ValueError):self.prepare()
        self.assertEqual((self.new/'manifest.json').read_bytes(),manifest)
        self.assertIsNone(q.read(self.new/'state.json')['started_at'])
        self.assertFalse((self.new/'launch-ledger').exists())

    def test_nested_or_ancestor_history_root_is_refused_before_freeze_delegation(self):
        self.prior_fixture()
        for target in (self.prior,self.prior/'nested-new',self.root):
            with self.subTest(target=target),mock.patch.object(q,'freeze',wraps=q.freeze) as freeze:
                with self.assertRaises(ValueError):retained.prepare(q,target,retained_index=self.index,
                    compatibility=self.compatibility,freeze_kwargs=self.freeze_kwargs())
                freeze.assert_not_called()
        self.assertFalse((self.prior/'nested-new').exists())

    def test_rehashed_primary_configuration_cannot_be_laundered_through_index(self):
        self.prior_fixture();row=next(r for r in self.index['cells'] if r['kind']=='negative')
        result_path=Path(row['result']['path']);record=q.read(result_path)
        record['configuration_digest']='f'*64;self.put(result_path,record)
        intent_path=Path(row['attempt_intent']['path']);intent=q.read(intent_path)
        intent['configuration_digest']='f'*64;intent['initial_record']['configuration_digest']='f'*64
        intent['result_sha256']=q.sha(result_path);self.put(intent_path,intent)
        for role,field in (('parent_receipt','run'),('child_completion',None),('qualification',None)):
            path=Path(row[role]['path']);value=q.read(path)
            if field:value[field]['result_sha256']=q.sha(result_path)
            else:value['result_sha256']=q.sha(result_path)
            self.put(path,value);row[role]=self.reference(path)
        row['result']=self.reference(result_path);row['attempt_intent']=self.reference(intent_path)
        self.refresh_index()
        with self.assertRaises(ValueError):self.prepare()

    def test_second_original_attempt_intent_is_not_a_primary_retention_chain(self):
        self.prior_fixture();row=next(r for r in self.index['cells'] if r['kind']=='negative')
        cell=next(c for c in self.full if c['id']==row['cell_id'])
        exp=self.prior/('scripted-'+cell['release']);metadata,mapping=q.experiments.verify(exp,q.lab)
        trial=next(v for v in mapping['cells'] if v['trial_id']==cell['trial_id'])
        q.experiments.reserve_attempt(exp,metadata,trial,index=2,previous=row['attempt_id'])
        self.assertEqual(len(q.experiments.attempt_intents(exp,trial)),2)
        with self.assertRaises(ValueError):self.prepare()

    def test_actual_selected_primary_reservation_and_finalization_dispatch_one_sensitive(self):
        manifest,selected,seen,invoke=self.scripted_fixture('0.87.1')
        exp=self.new/'scripted-0.87.1';metadata,mapping=q.experiments.verify(exp,q.lab)
        with self.disposable_authorities(),mock.patch.object(q,'_invoke_cell',side_effect=invoke), \
             mock.patch.object(q.application_experiments,'admit_work',wraps=q.application_experiments.admit_work) as admit:
            retained._scripted(q,self.new,manifest,selected,[])
        self.assertEqual([name for name,initial in seen],[SENSITIVE])
        self.assertEqual(len(admit.call_args.args[2]),1)
        actual=[(row,q.experiments.attempt_intents(exp,row)) for row in mapping['cells']]
        self.assertEqual(sum(bool(chain) for row,chain in actual),1)
        for row,chain in actual:
            if not chain:continue
            self.assertEqual(row['trial_id'],selected[0]['trial_id']);self.assertEqual(len(chain),1)
            self.assertEqual(chain[0]['status'],'finalized')
            raw=q.experiments.sealed_result(exp,chain[0]);self.assertEqual(raw['status'],'INTERRUPTED')
            self.assertTrue(q.experiments.cleanup_known(exp,chain[0],raw))
        self.assertEqual(q.read(exp/'state.json')['status'],'interrupted')
        before={str(p.relative_to(exp)):p.read_bytes() for p in (exp/'attempts').rglob('*.json')}
        with self.disposable_authorities(),mock.patch.object(q,'_invoke_cell') as again:
            with self.assertRaises(ValueError):retained._scripted(q,self.new,manifest,selected,[])
            again.assert_not_called()
        self.assertEqual(before,{str(p.relative_to(exp)):p.read_bytes() for p in (exp/'attempts').rglob('*.json')})

    def test_actual_other_release_selects_all_six_fresh_primaries_once(self):
        manifest,selected,seen,invoke=self.scripted_fixture('1.2.0')
        with self.disposable_authorities(),mock.patch.object(q,'_invoke_cell',side_effect=invoke):
            retained._scripted(q,self.new,manifest,selected,[])
        self.assertEqual(len(seen),6);self.assertEqual({name for name,initial in seen},{c['id'] for c in selected})
        self.assertEqual(len({initial['run_id'] for name,initial in seen}),6)
        self.assertEqual(len({initial['attempt_id'] for name,initial in seen}),6)
        self.assertTrue(all(initial['attempt_index']==1 and initial['retry_of_attempt_id'] is None for name,initial in seen))

    def test_unknown_cleanup_finalizes_real_failed_evidence_then_blocks_without_retry(self):
        manifest,selected,seen,invoke=self.scripted_fixture('0.87.1',unsafe=True)
        with self.disposable_authorities(),mock.patch.object(q,'_invoke_cell',side_effect=invoke):
            with self.assertRaises(ValueError):retained._scripted(q,self.new,manifest,selected,[])
        exp=self.new/'scripted-0.87.1';metadata,mapping=q.experiments.verify(exp,q.lab)
        trial=next(r for r in mapping['cells'] if r['trial_id']==selected[0]['trial_id'])
        intent=q.experiments.attempt_intents(exp,trial)[0]
        self.assertEqual(intent['status'],'finalized')
        result=q.experiments.sealed_result(exp,intent)
        self.assertFalse(q.experiments.cleanup_known(exp,intent,result))
        self.assertEqual(q.read(exp/'state.json')['status'],'blocked')
        self.assertEqual(len(seen),1)

    def test_worker_failure_retains_reserved_primary_and_cannot_be_replaced(self):
        manifest,selected,seen,invoke=self.scripted_fixture('0.87.1',fail_before_result=True)
        with self.disposable_authorities(),mock.patch.object(q,'_invoke_cell',side_effect=invoke):
            with self.assertRaises(ValueError):retained._scripted(q,self.new,manifest,selected,[])
        exp=self.new/'scripted-0.87.1';metadata,mapping=q.experiments.verify(exp,q.lab)
        trial=next(r for r in mapping['cells'] if r['trial_id']==selected[0]['trial_id'])
        intent=q.experiments.attempt_intents(exp,trial)[0]
        self.assertEqual(intent['status'],'reserved')
        self.assertIsNone(q.experiments.sealed_result(exp,intent))
        with self.disposable_authorities(),mock.patch.object(q,'_invoke_cell') as repeat:
            with self.assertRaises(ValueError):retained._scripted(q,self.new,manifest,selected,[])
            repeat.assert_not_called()

    def test_original_local_ledger_hard_clock_and_role_limits_still_apply(self):
        self.prior_fixture();self.prepare();manifest,_=retained.verify(q,self.new)
        policy=retained.launch_manifest(q,manifest)
        valid={'attempts':139,'live':3,'segments':18,'participant':True,'now':100,'deadline':1000,'limits':policy['limits']}
        launch._hard_admission(**valid)
        for changed in ({'attempts':140},{'segments':19},{'live':4},{'now':970}):
            with self.subTest(changed=changed),self.assertRaises(ValueError):launch._hard_admission(**{**valid,**changed})


    def test_started_row_runner_status_canary_is_rejected_before_report_projection(self):
        self.prior_fixture();self.prepare()
        state=q.read(self.new/'state.json')
        state.update(phase='collecting',started_at=1.0,cells={SENSITIVE:{
            'status':'started','attempts':1,'run_id':str(uuid.uuid4()),
            'attempt_id':str(uuid.uuid4()),'runner_status':'INTERRUPTED'}})
        self.put(self.new/'state.json',state)
        report=retained.report(q,self.new)
        observed=next(row for row in report['cells'] if row['id']==SENSITIVE)
        self.assertEqual(observed['runner_status'],'INTERRUPTED')
        self.assertEqual(observed['status'],'started')
        state['cells'][SENSITIVE]['runner_status']='NONSECRET-UNKNOWN-RUNNER-STATUS-CANARY'
        self.put(self.new/'state.json',state)
        written=(self.new/'state.json').read_bytes()
        # The genuine state validator accepts a started row without loading a result.
        # Its report boundary must nevertheless reject an unknown output value.
        retained.verify(q,self.new)
        with self.assertRaises(ValueError):retained.report(q,self.new)
        self.assertEqual((self.new/'state.json').read_bytes(),written)

    def test_copy_only_kernel_denies_retained_mode_before_copied_validator_access(self):
        import application_operational_replay as replay
        class NoValidatorAccess:
            @property
            def __globals__(self):raise AssertionError('copied validator accessed before retained deny')
            @property
            def __code__(self):raise AssertionError('copied validator code accessed before retained deny')
        # No Kernel constructor or source/history acquisition is needed. The actual
        # entry guard must reject even a minimal retained marker before any clone.
        with mock.patch.object(replay.launch,'validate_manifest',NoValidatorAccess()), \
             mock.patch.object(replay.types,'FunctionType',side_effect=AssertionError('validator cloned')) as clone:
            with self.assertRaises(launch.LaunchError):
                replay.Kernel.manifest({'retained_requalification':{'mode':retained.MODE}}, {})
        clone.assert_not_called()


if __name__=='__main__':unittest.main()
