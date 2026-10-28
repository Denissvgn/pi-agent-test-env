"""Six-browser selection and source-certificate controls using owned fixtures.

Historical reviewed-capture attestation is a modeled prerequisite boundary in
workflow controls; its separately reviewed builder has independent controls. These tests
never establish actual historical/native eligibility and never contact a VM/API.
The Source045 identity is a synthetic boundary backed by frozen public hash maps;
the current SDK is never relabelled as a historically approved runner.
"""
import ast
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[1]
import sys
sys.path[:0]=[str(ROOT/'tools/qualification'),str(ROOT/'tests')]
from ast_compat import pinned_dump
import application_browser_followup as follow
import application_launch as launch
import application_retained as retained
import test_application_qualification as qualification
import test_application_retained as retained_tests
q=qualification.harness
ACTUAL_SOURCE_IDENTITY=q.source_identity
HISTORICAL_SOURCE_IDENTITIES=json.loads((ROOT/'tests/fixtures/application-contracts/historical-browser-source-identities.json').read_bytes())


def images():
    return {profile+'-'+release:{'id':'sha256:'+format(i+1,'064x'),'platform':'linux/arm64','capabilities':{'pi':release}}
       for i,(profile,release)in enumerate((p,r)for r in('0.87.1','1.2.0')for p in('core','browser'))}


def marker(root):
    return {'schema':1,'mode':follow.MODE,
      'evidence_index':{'path':str(root/'browser-followup-index.json'),'sha256':'1'*64},
      'compatibility_review':{'path':str(root/'browser-followup-compatibility.json'),'sha256':'2'*64},
      'historical_use':dict(follow.HISTORICAL_USE),'local_plan':dict(follow.LOCAL_PLAN),
      'cumulative_ceiling':dict(follow.CUMULATIVE_CEILING),'authorization_required':True}


def selected_manifest(root):
    _,fresh=follow.partition(q.matrix(images()))
    return {'schema':1,'document_type':'application_client_qualification','qualification_id':str(uuid.uuid4()),'session':'NONSECRET_FIXTURE_SESSION',
      'images':images(),'cells':fresh,'limits':follow.effective_limits({'schema':1,'browser_followup':marker(root)}),
      'planned_container_launches':42,'browser_followup':marker(root)}


class BrowserFollowupTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='inert-browser-followup-')
        self.addCleanup(self.temporary.cleanup);self.root=Path(self.temporary.name).resolve()
        # Synthetic SourceIdentity boundary only. Compiler/freezer/tamper predicates
        # below it remain genuine; this does not establish historical eligibility.
        historical=HISTORICAL_SOURCE_IDENTITIES['source045']
        self.assertEqual(historical['runner'],follow.CURRENT_RUNNER)
        patch=mock.patch.object(q,'source_identity',side_effect=lambda:copy.deepcopy(historical))
        patch.start();self.addCleanup(patch.stop)

    def write(self,path,value):
        path=Path(path);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        q.atomic(path,value);return {'path':str(path),'sha256':q.sha(path)}

    def source_certificate(self):
        new=q.source_identity();old=copy.deepcopy(new)
        old['runner_files']['runtime/application_client_service.py']=follow.OLD_SERVICE
        old['runner']=q.c.digest(old['runner_files'])
        for name,value in {'tools/qualification/application_client.py':'4466ac6fd6fa0a3633b4d5f5bce0e6209eda21ce2750fe6901c154ca8393eccb',
           'tools/qualification/application_launch.py':'e8f40b6154ef8a8fccf13bd95b3a86cec851d16cb88ecbd534cd7215f4b66f53',
           'tools/qualification/application_operational_replay.py':'07db15be86b966a5e349650c7dd2c1470e4de9f654ccd8d26130d6e31c23a9a6',
           'tools/qualification/application_sdk_admission.py':follow.OLD_SDK}.items():old['files'][name]=value
        old['files'].pop('tools/qualification/application_browser_followup.py')
        old['sha256']=q.c.digest(old['files'])
        prior={'source':old,**{key:{'NONSECRET_FIXTURE_FIELD':key}for key in follow.SEMANTIC_FIELDS}}
        index={'historical_verification':{'sha256':'3'*64},'owned_cleanup':{'sha256':'4'*64},'owned_cleanup_review':{'sha256':'5'*64}}
        changed=sorted(k for k in set(old['files'])|set(new['files'])if old['files'].get(k)!=new['files'].get(k))
        review={'schema':1,'document_type':'application_browser_followup_compatibility_review','status':'PASS','unresolved':[],
          'index_sha256':q.c.digest(index),'historical_verification_sha256':'3'*64,'old_source':old,'new_source':new,
          'production_delta':{'path':'runtime/application_client_service.py','before':follow.OLD_SERVICE,'after':follow.CURRENT_SERVICE},
          'changed_qualification_files':changed,'semantic_inputs_sha256':q.c.digest({k:prior[k]for k in follow.SEMANTIC_FIELDS}),
          'owned_cleanup_sha256':'4'*64,'owned_cleanup_review_sha256':'5'*64}
        return prior,index,review

    def test_exact_prior22_fresh6_partition_and_complete_seven_roles(self):
        source=q.matrix(images());unchanged=copy.deepcopy(source);old,fresh=follow.partition(source)
        self.assertEqual(source,unchanged);self.assertEqual(len(old),22)
        self.assertEqual(tuple(c['id']for c in fresh),follow.FRESH_IDS)
        self.assertEqual(sum(c['container_launches_max']for c in fresh),42)
        self.assertEqual(sum(c['participant_segments_max']for c in fresh),6)
        self.assertTrue(all(c['real_model']is True and c['max_attempts']==1 and len(c['role_limits'])==7 for c in fresh))
        self.assertEqual((488+42,40+6),(530,46))

    def test_missing_duplicate_or_relabelled_browser_cell_is_not_a_fresh_matrix(self):
        for fault in('missing','duplicate','API','role','bool'):
            value=q.matrix(images())
            row=next(c for c in value if c['id']=='N04-0.87.1-1')
            if fault=='missing':value.remove(row)
            elif fault=='duplicate':value[-1]=copy.deepcopy(value[-2])
            elif fault=='API':row['group']='N03'
            elif fault=='role':row['role_limits'].pop('preflight')
            else:row['max_attempts']=True
            with self.subTest(fault=fault),self.assertRaises(ValueError):follow.partition(value)

    def test_marker_refuses_old527_caps_bool_and_old_mode(self):
        follow.validate_marker(marker(self.root))
        for key,value in(('cumulative_ceiling',{'containers':527,'participants':46}),('local_plan',{'containers':39,'participants':6}),
                          ('mode',retained.MODE),('authorization_required',False),('schema',True)):
            changed=marker(self.root);changed[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):follow.validate_marker(changed)

    def test_original_launcher_enforces_exact_six_representation(self):
        value=follow.launch_manifest(q,selected_manifest(self.root));launch.validate_manifest(value)
        for fault in('role','ID','count','mixed','image'):
            changed=copy.deepcopy(value)
            if fault=='role':changed['cells'][0]['role_limits']['extra']=1
            elif fault=='ID':changed['cells'][0]['id']='N04-0.87.1-4'
            elif fault=='count':changed['limits']['container_launch_attempts']=39
            elif fault=='mixed':changed['retained_requalification']={}
            else:changed['cells'][0]['image_id']=changed['images']['core-0.87.1']['id']
            with self.subTest(fault=fault),self.assertRaises(ValueError):launch.validate_manifest(changed)

    def test_exact_source_certificate_allows_only_reviewed_runtime_tuple_delta(self):
        prior,index,review=self.source_certificate();follow._source_compatibility(q,review,index,prior)
        for fault in('old-runner','extra-runtime','SDK','certificate','semantic'):
            p,i,r=copy.deepcopy((prior,index,review))
            if fault=='old-runner':p['source']['runner']='a'*64
            elif fault=='extra-runtime':r['new_source']['runner_files']['runtime/application_api.py']='a'*64
            elif fault=='SDK':r['new_source']['files']['tools/qualification/application_sdk_admission.py']='a'*64
            elif fault=='certificate':r['production_delta']['after']='a'*64
            else:r['semantic_inputs_sha256']='a'*64
            with self.subTest(fault=fault),self.assertRaises(ValueError):follow._source_compatibility(q,r,i,p)

    def test_actual_current_identity_and_coherent_certificate_are_not_historical_authority(self):
        current=ACTUAL_SOURCE_IDENTITY();prior,index,review=self.source_certificate()
        self.assertEqual(q.c.digest(current['runner_files']),current['runner'])
        self.assertEqual(q.c.digest(current['files']),current['sha256'])
        self.assertNotEqual(current['runner'],follow.CURRENT_RUNNER)
        review['new_source']=copy.deepcopy(current)
        review['changed_qualification_files']=sorted(key for key in set(prior['source']['files'])|set(current['files'])
            if prior['source']['files'].get(key)!=current['files'].get(key))
        with mock.patch.object(q,'source_identity',new=ACTUAL_SOURCE_IDENTITY):
            self.assertEqual(review['new_source'],q.source_identity())
            with self.assertRaises(ValueError):follow._source_compatibility(q,review,index,prior)

    def test_original_retained_runner_equality_still_rejects_new_runner(self):
        prior,index,review=self.source_certificate();new={'source':review['new_source'],**{k:prior[k]for k in follow.SEMANTIC_FIELDS}}
        oldreview={'schema':1,'document_type':'application_retained_compatibility_review','status':'PASS','unresolved':[],
          'index_sha256':q.c.digest(index),'prior_source_sha256':prior['source']['sha256'],'current_source_sha256':new['source']['sha256'],
          'runner_sha256':new['source']['runner'],'runner_files_sha256':q.c.digest(new['source']['runner_files']),
          'release_contracts_sha256':q.c.digest(new['source']['release_contracts']),'changed_qualification_files':review['changed_qualification_files']}
        with self.assertRaises(ValueError):retained._compatibility(q,index,oldreview,prior,new)

    def test_overlapping_root_refuses_before_freeze_or_historical_reads(self):
        old=self.root/'old';old.mkdir(mode=0o700)
        stub=SimpleNamespace(freeze=mock.Mock())
        for target in(old,old/'nested',self.root):
            with mock.patch.object(follow,'_evidence')as history,self.assertRaises(ValueError):
                follow.prepare(stub,target,evidence_index={'prior_root':str(old)},compatibility={},freeze_kwargs={})
            history.assert_not_called()
        stub.freeze.assert_not_called()

    def test_malformed_index_refuses_before_freeze(self):
        stub=SimpleNamespace(freeze=mock.Mock())
        with self.assertRaises(ValueError):follow.prepare(stub,self.root/'new',evidence_index={'prior_root':str(self.root/'old')},compatibility={},freeze_kwargs={})
        stub.freeze.assert_not_called()

    def genuine_prepared_fixture(self):
        # Genuine normal compiler/freezer/current six-row validator. Only historical
        # eligibility is a modeled already-reviewed prerequisite, not actual history.
        fixture=retained_tests.RetainedQualificationTests(methodName='runTest');fixture.setUp();self.addCleanup(fixture.doCleanups)
        q.freeze(fixture.output,**fixture.freeze_kwargs());prior=q.read(fixture.output/'manifest.json')
        legacy=self.write(fixture.root/'legacy-index.json',{'prior_root':str(fixture.root/'legacy-root')})
        index={'prior_root':str(fixture.output),'legacy_index':legacy};review={'NONSECRET_HISTORY_BOUNDARY':True}
        target=fixture.root/'browser-followup'
        with mock.patch.object(follow,'_evidence',return_value=(prior,{},[])), \
             mock.patch.object(q,'_native',side_effect=AssertionError('prepare native effect')), \
             mock.patch.object(q,'_known_values',side_effect=AssertionError('prepare key resolution')):
            follow.prepare(q,target,evidence_index=index,compatibility=review,freeze_kwargs=fixture.freeze_kwargs())
        return fixture,target,prior

    def test_genuine_freeze_produces_six_empty_cells_without_clock_or_authority(self):
        fixture,target,prior=self.genuine_prepared_fixture()
        manifest=q.read(target/'manifest.json');state=q.read(target/'state.json')
        self.assertEqual(len(manifest['cells']),6);self.assertEqual(manifest['planned_container_launches'],42)
        self.assertEqual(state,{'schema':1,'phase':'frozen','active_cell':None,'cells':{},'started_at':None})
        for name in('launch-ledger','candidate.json','native-authorization.json','independent-native-input-review.json'):
            self.assertFalse((target/name).exists())
        self.assertEqual(q.read(fixture.output/'manifest.json'),prior)

    def test_state_only_fake_PASS_is_rejected_without_owning_result(self):
        fixture,target,prior=self.genuine_prepared_fixture();state=q.read(target/'state.json')
        state.update(phase='collecting',started_at=1.0,cells={'N04-0.87.1-1':{'status':'PASS','attempts':1,
          'run_id':str(uuid.uuid4()),'attempt_id':str(uuid.uuid4()),'runner_status':'PASS','exit_code':0}})
        q.atomic(target/'state.json',state)
        with mock.patch.object(follow,'_evidence',return_value=(prior,{},[])),self.assertRaises((ValueError,OSError)):
            follow.verify(q,target)

    def test_candidate_index_and_certificate_tamper_deny_before_native_gate(self):
        fixture,target,prior=self.genuine_prepared_fixture()
        with mock.patch.object(follow,'_evidence',return_value=(prior,{},[])):
            q.bind_candidate(target,{'archive_sha256':'a'*64,'runner_sha256':follow.CURRENT_RUNNER,'scope':'extracted_candidate'})
        for leaf in('candidate.json','browser-followup-index.json','browser-followup-compatibility.json'):
            path=target/leaf;before=path.read_bytes()
            if leaf=='candidate.json':value=q.read(path);value['runner_sha256']=follow.SOURCE044_RUNNER;q.atomic(path,value)
            else:q.atomic(path,{'tampered':'NONSECRET'})
            with mock.patch.object(follow,'_evidence',return_value=(prior,{},[])), \
                 mock.patch.object(q,'_endpoint')as endpoint,mock.patch.object(q,'_known_values')as values, \
                 mock.patch.object(q,'_native')as native,self.assertRaises((ValueError,OSError)):
                follow.admit(q,target)
            endpoint.assert_not_called();values.assert_not_called();native.assert_not_called();path.write_bytes(before)

    def activation_fixture(self):
        manifest=selected_manifest(self.root);mref=self.write(self.root/'manifest.json',manifest)
        cref=self.write(self.root/'candidate.json',{'archive_sha256':'a'*64,'runner_sha256':follow.CURRENT_RUNNER,'scope':'extracted_candidate'})
        grant={'schema':1,'document_type':'application_browser_followup_native_authorization','status':'AUTHORIZED','authorization_id':str(uuid.uuid4()),
          'manifest':mref,'candidate':cref,'evidence_index':manifest['browser_followup']['evidence_index'],
          'compatibility_review':manifest['browser_followup']['compatibility_review'],'historical_use':follow.HISTORICAL_USE,
          'local_plan':follow.LOCAL_PLAN,'cumulative_caps':follow.CUMULATIVE_CEILING,'native_window_seconds':14400,
          'live_limits':{'containers':4,'active_trials':1,'inference_slots':1},'automatic_retries':0,'publication_authorized':False}
        gref=self.write(self.root/'native-authorization.json',grant)
        peer={'schema':1,'status':'PASS','grant':gref,'manifest':mref,'candidate':cref,'supports_exact_browser_followup_authority':True,'unresolved_findings':[]}
        self.write(self.root/'independent-native-input-review.json',peer);return manifest,grant,peer

    def test_missing_or_wrong_authority_cannot_reach_endpoint_clock_or_Docker(self):
        manifest=selected_manifest(self.root)
        with mock.patch.object(follow,'verify',return_value=(manifest,{})),mock.patch.object(q,'_native')as native, \
             mock.patch.object(q,'_endpoint')as endpoint,mock.patch.object(q,'controller')as controller,self.assertRaises(OSError):follow.admit(q,self.root)
        native.assert_not_called();endpoint.assert_not_called();controller.assert_not_called()
        manifest,grant,peer=self.activation_fixture();follow._activation(q,self.root,manifest)
        for field,value in(('cumulative_caps',{'containers':527,'participants':46}),('native_window_seconds',True),
                          ('publication_authorized',0),('document_type','retained_evidence_requalification_human_authorization')):
            changed=copy.deepcopy(grant);changed[field]=value;gref=self.write(self.root/'native-authorization.json',changed)
            changedpeer=copy.deepcopy(peer);changedpeer['grant']=gref;self.write(self.root/'independent-native-input-review.json',changedpeer)
            with self.subTest(field=field),self.assertRaises(ValueError):follow._activation(q,self.root,manifest)

    def test_direct_internal_child_requires_new_grant_before_envelope_or_SDK(self):
        manifest=selected_manifest(self.root)
        with mock.patch.object(q,'verify',return_value=(manifest,{})),mock.patch.object(q,'read',side_effect=FileNotFoundError), \
             mock.patch.object(Path,'lstat',side_effect=AssertionError('envelope read before authority')), \
             self.assertRaises(FileNotFoundError):
            q._child(self.root,follow.FRESH_IDS[0],self.root/'unused-private-envelope.json')

    def test_copy_kernel_refuses_new_mode_before_validator_clone(self):
        import application_operational_replay as replay
        class NoAccess:
            @property
            def __globals__(self):raise AssertionError('copied validator accessed')
        with mock.patch.object(replay.launch,'validate_manifest',NoAccess()), \
             mock.patch.object(replay.types,'FunctionType',side_effect=AssertionError('clone'))as clone,self.assertRaises(ValueError):
            replay.Kernel.manifest({'browser_followup':marker(self.root)},{})
        clone.assert_not_called()

    def test_historical_role_classifier_rejects_failed_private_maps_before_body_reads(self):
        old=self.root/'prior059';legacy=self.root/'prior056';run=old/'cells'/'N03-0.87.1-1'/'runs'/str(uuid.uuid4())
        allowed=run/'result.json';outside={self.root/'assessment.json'}
        ref=lambda path:{'path':str(path),'sha256':'a'*64}
        classified,seen=follow._immutable_roles([ref(allowed),ref(self.root/'assessment.json')],old,legacy,outside,[run])
        self.assertEqual([path for _,path in classified],[allowed,self.root/'assessment.json'])
        bad=[old/'cells'/'N04-0.87.1-1'/'qualification.json',legacy/'cells'/retained.FAILED_CELL/'qualification.json',
             run/'workspace'/'answer.json',run/'private-dispatch'/'initial.json',run/'files.json',
             run/'application-context.json',self.root/'private-store'/'unknown.json',
             old/'cells'/'N03-0.87.1-2'/'runs'/str(uuid.uuid4())/'result.json']
        for path in bad:
            with self.subTest(path=str(path)),mock.patch.object(q.preparation,'_read',side_effect=AssertionError('classifier body read'))as read, \
                 self.assertRaises(ValueError):follow._immutable_roles([ref(allowed),ref(path)],old,legacy,outside,[run])
            read.assert_not_called()
        with self.assertRaises(ValueError):follow._immutable_roles([ref(allowed),ref(allowed)],old,legacy,outside,[run])

    def test_missing_nonpass_wrong_verifier_or_effectful_attestation_is_not_eligibility(self):
        refs={name:{'path':str(self.root/(name+'.json')),'sha256':'a'*64}for name in
          ('prior_manifest','prior_candidate','prior_state','prior_ledger','legacy_index','legacy_compatibility','owned_cleanup','owned_cleanup_review')}
        index={'prior_root':str(self.root/'prior'),**refs}
        value={'schema':1,'document_type':'source044_browser_followup_reviewed_capture_attestation',
          'status':'PASS_22_REVIEWED_HISTORICAL_SNAPSHOTS','verifier':{'path':str(self.root/follow.HISTORY_PRODUCER_BASENAME),'sha256':'c'*64},
          'source_archive_sha256':follow.SOURCE044_ARCHIVE,**index,'historical_use':dict(follow.HISTORICAL_USE),'cells':[],
          'immutable_roles':[],'validation_scope':dict(follow.HISTORY_VALIDATION_SCOPE),
          'reviewed_captures':[{'path':str(self.root/('capture-'+str(i)+'.json')),'sha256':'a'*64}for i in range(5)],
          'independent_reviews':[{'path':str(self.root/'independent-review.json'),'sha256':'b'*64}],
          'effects':dict.fromkeys(('record_writes','SDK_contexts','Docker_calls','network_calls','model_calls','credential_resolution'),0)}
        with mock.patch.object(follow,'HISTORY_VERIFIER_SHA','c'*64):follow._validate_attestation(value,index)
        for fault in('missing','nonpass','wrong-verifier','effect','bool','fresh-claim','capture-count','duplicate-review'):
            changed=copy.deepcopy(value)
            if fault=='missing':del changed['status']
            elif fault=='nonpass':changed['status']='FAILED_ORIGINAL044_VERIFY'
            elif fault=='wrong-verifier':changed['verifier']['sha256']='0'*64
            elif fault=='effect':changed['effects']['model_calls']=1
            elif fault=='bool':changed['effects']['model_calls']=False
            elif fault=='fresh-claim':changed['validation_scope']['original_predicates_reexecuted']=True
            elif fault=='capture-count':changed['reviewed_captures'].pop()
            else:changed['independent_reviews']*=2
            with mock.patch.object(follow,'HISTORY_VERIFIER_SHA','c'*64),self.subTest(fault=fault),self.assertRaises(ValueError):follow._validate_attestation(changed,index)

    def test_original_central_ledger_and_guard_classes_are_AST_identical(self):
        source=ast.parse((ROOT/'tools/qualification/application_launch.py').read_bytes())
        expected={'LaunchLedger':'249416e94a8534581a90b40c8b55fdcfcd2bbec492aed80a2c9862b85b1b7d0e',
                  'LaunchGuard':'24290b5d862d7689cc849da8eb78976c4ddbe6b9d81f266d4104e0046d545783'}
        for name,digest in expected.items():
            node=next(n for n in source.body if isinstance(n,ast.ClassDef)and n.name==name)
            if name=='LaunchLedger':
                from test_application_settlement_launch import normalize_reviewed_settlement_ledger_ast
                node=normalize_reviewed_settlement_ledger_ast(node)
            self.assertEqual(hashlib.sha256(pinned_dump(node).encode()).hexdigest(),digest)

    def test_phase_order_three_once_and_real_failure_is_NOT_READY(self):
        manifest=selected_manifest(self.root);state={'schema':1,'phase':'images_admitted','active_cell':None,'cells':{},'started_at':1.0};calls=[]
        def verify(*a,**kw):return manifest,copy.deepcopy(state)
        def atomic(path,value):state.clear();state.update(copy.deepcopy(value))
        def invoke(root,bound,cell,initial,values):
            self.assertIs(bound,manifest);self.assertIn(cell['id'],follow.FRESH_IDS);calls.append(cell['id'])
            state['cells'][cell['id']]={'status':'FAIL'if cell['id']==follow.FRESH_IDS[0]else'PASS','attempts':1,'runner_status':'FAIL'if cell['id']==follow.FRESH_IDS[0]else'PASS'}
        stub=SimpleNamespace(controller=lambda root:contextlib.nullcontext(),_deadline_signal=lambda *a,**k:contextlib.nullcontext(),
          _endpoint=lambda *a:None,_known_values=lambda *a:['NONSECRET_FIXTURE'],_scan_frozen=lambda *a:None,
          atomic=atomic,read=lambda path:copy.deepcopy(state),_invoke_cell=invoke,outcomes=SimpleNamespace(initial=lambda:{}))
        with mock.patch.object(follow,'verify',side_effect=verify),mock.patch.object(follow,'_activation'):
            with self.assertRaises(ValueError):follow.collect(stub,self.root,group='N04',release='1.2.0')
            first=follow.collect(stub,self.root,group='N04',release='0.87.1');self.assertEqual(len(calls),3)
            with self.assertRaises(ValueError):follow.collect(stub,self.root,group='N04',release='0.87.1')
            final=follow.collect(stub,self.root,group='N04',release='1.2.0')
        self.assertEqual(calls,list(follow.FRESH_IDS));self.assertEqual(final['status'],'NOT_READY')
        self.assertEqual(len(final['cells']),6);self.assertFalse(final['same_source_full28_execution_claimed'])
        self.assertFalse(final['prior_failed_browser_retained']);self.assertEqual(first['prior_source_scoped_passes'],22)


if __name__=='__main__':unittest.main()
