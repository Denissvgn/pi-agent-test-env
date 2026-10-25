"""Only temporary operational metadata/fake boundaries; no live inputs."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import uuid
import signal
import contextlib
from unittest import mock

# Direct runs get a hard process bound; discovery uses the outer suite runner.
if __name__=='__main__':
    signal.signal(signal.SIGALRM,lambda *_: os._exit(124)); signal.setitimer(signal.ITIMER_REAL,30)
HERE=Path(__file__).resolve().parent
REPO=next(p for p in HERE.parents if (p/'tools/qualification/application_launch.py').is_file())
sys.path[:0]=[str(HERE),str(REPO/'tools/qualification'),str(REPO/'skill/scripts'),str(REPO/'skill/runtime')]
with contextlib.ExitStack() as imports:
    for name in ('subprocess.Popen','subprocess.run','os.kill','socket.socket'):
        imports.enter_context(mock.patch(name,side_effect=AssertionError('import effect forbidden')))
    import application_launch as launch
    import application_operational_replay as r
    SUBJECT=HERE/'application_matrix20.py' if (HERE/'application_matrix20.py').is_file() else REPO/'tools/qualification/application_matrix20.py'
    spec=importlib.util.spec_from_file_location('proposed_matrix20',SUBJECT)
    m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def uid(): return str(uuid.uuid4())


def policy():
    images={p+'-'+v:{'id':'sha256:'+str(i+1)*64,'platform':'linux/arm64','capabilities':{'pi':v}}
        for i,(p,v) in enumerate((('core','0.87.1'),('browser','0.87.1'),('core','1.2.0'),('browser','1.2.0')))}
    cells=[{k:c[k] for k in r.FIELDS} for c in r.matrix_cells(images)]
    return {'qualification_id':uid(),'images':images,'cells':cells,'limits':dict(launch.LIMITS),'planned_container_launches':186}


class Fixture:
    def __init__(self,root):
        self.root=Path(root); self.objects={}; self.entries=[]; self.events=[]; self.record_digests={}
    def add(self,path,value,kind):
        body=launch._json(value); sha=hashlib.sha256(body).hexdigest()
        ref={'path':path,'sha256':sha}; target=self.root/'objects'/(sha+'.json')
        if not target.exists(): target.write_bytes(body); target.chmod(0o600)
        self.objects[path]=copy.deepcopy(value)
        entry={'original':ref,'copy':{'path':str(target),'sha256':sha},'kind':kind}
        if entry not in self.entries: self.entries.append(entry)
        return ref
    def matrix(self,prior=None,*,root_override=None,clock_start=100.):
        origin=len(self.events)+1; root=root_override or '/synthetic/origin-'+str(origin); p=policy()
        if prior:
            previous=self.events[-1]
            p['predecessor']={'schema':1,'root':previous['root'],
                **{k+'_sha256':previous[k]['sha256'] for k in ('manifest','state','ledger')},
                'cleanup_receipts':[previous['review']]}
        source={'runner':'a'*64,'files':{'tools/qualification/application_client.py':'e'*64},'runner_files':{}}
        source['sha256']=launch._digest(source['files'])
        full={**copy.deepcopy(p),'schema':1,'document_type':'application_client_qualification','prepared_root':root,'source':source,
            'created_at':'2026-01-01T00:00:00Z','session':uid(),'endpoint':{},'endpoint_sha256':launch._digest({}),
            'image_receipts':{},'fixture_route':{},'credential_references':{'alice':'TEST_ALICE','bob':'TEST_BOB','scripted_inference':'TEST_SCRIPT'},
            'host_admission':{'lock_file':'/synthetic/original.lock','wait_seconds':30},'secrets_dir':'/synthetic/store',
            'files':{'inputs/input.json':'f'*64},'negative_oracles':r.negative_oracles()}
        full['limits']={k:v for k,v in p['limits'].items() if k!='live'}
        full['limits'].update(simultaneously_registered_live_container_intents=4,automatic_retries=0,continuations=0)
        full['cells']=r.matrix_cells(p['images'])
        for cell in full['cells']:
            if cell['group']=='N02': cell['trial_id']=uid()
            if cell['participant_segments_max']: cell['plan_sha256']='e'*64
        # A real original Ledger row is produced with the inherited reserve body.
        cell=p['cells'][0]; record={'registry':hashlib.sha256(b'/synthetic/original.lock.registry').hexdigest(),'generation':uid(),'launch_id':uid(),
            'container':'fixture-'+str(origin),'image':cell['image_id'],'daemon':'fixture-daemon','status':'intent'}
        ledger={'schema':1,'manifest_sha256':launch._digest(p),'daemon':'fixture-daemon',
            'daemon_capacity':{'cpu_millis':64000,'memory_mib':65536},'started':clock_start,'deadline':clock_start+14400.,
            'started_wall':1000.,'deadline_wall':15400.,'last_now':101.,'last_wall':1001.,'poisoned':False,'launches':[]}
        verifier=object.__new__(launch.LaunchLedger); verifier.manifest=p; verifier._carry=prior
        verifier._reserve_apply(ledger,cell['id'],'probe',record,launch._role_weight(p,cell,'probe'),
            {'id':'fixture-daemon','cpu_millis':64000,'memory_mib':65536},pull_policy='explicit')
        row=ledger['launches'][0]; row.update(physical='absent',private_cleanup=True,pid=123,container_id=str(origin)*64)
        if prior:
            ledger['carry']={'descriptor_sha256':launch._digest(p['predecessor']),
                **{k:prior[k] for k in ('attempts','participant_segments','qualification_id','planned_cells')}}
        state={'schema':1,'phase':'blocked','active_cell':None,'started_at':1000.,
            'cells':{cell['id']:{'status':'BLOCKED','attempts':1}}}
        event={'kind':'matrix','origin':origin,'root':root,'effective_limits':p['limits'],'claims':[]}
        for k,value,kind,path in (('manifest',full,'manifest','manifest.json'),('state',state,'state','state.json'),
                                  ('ledger',ledger,'ledger','launch-ledger/ledger.json')):
            event[k]=self.add(root+'/'+path,value,kind)
        released={**record,'status':'released','container_id':None}
        event['records']=[self.add(root+'/record.json',released,'record')]
        self.record_digests[record['launch_id']]=launch._digest(released)
        event['candidate']=self.add(root+'/candidate.json',{'scope':'extracted_candidate','runner_sha256':'a'*64,'archive_sha256':'c'*64},'candidate')
        anchor=self.add(root+'/retained-proof.json',{'status':'PASS_RETAINED_SYNTHETIC_EVIDENCE'},'operational-projection')
        def predicates(names):
            result={}
            for name in names:
                value={'predicate':name,'status':'PASS_SCOPED_RETAINED',
                    'scope':'original_terminal_evidence_only_not_current_global_clearance','origin':origin,
                    **{k:event[k] for k in ('manifest','state','ledger')},
                    'original_validator':{'path':'/synthetic/source.py','sha256':'d'*64,'callable':'verify'},'evidence':[anchor]}
                result[name]=self.add(root+'/'+name+'.json',value,'retained-predicate')
            return result
        event['source_review']=self.add(root+'/source-review.json',{'status':'PASS','unresolved_findings':[],
            'historical_source':source,'effective_limits':p['limits'],'manifest':event['manifest'],'origin':origin,
            'predecessor':p.get('predecessor'),'original_claim_family':'linear' if prior else 'initial',
            'host_admission':full['host_admission'],'frozen_input_inventory':full['files'],
            'retained_predicates':predicates(('original_endpoint_and_session_admission','original_frozen_input_bytes_and_compiled_bindings','original_source_and_candidate_gate'))},'source-review')
        event['review']=self.add(root+'/cleanup-review.json',{'status':'PASS','unresolved_findings':[],
            'supports_original_historical_operational_invariants':True,**{k:event[k] for k in ('manifest','state','ledger')},
            'raw_state_and_failure_flags_preserved':True,
            'retained_predicates':predicates(('original_controller_and_owner_terminal_provenance','original_guest_and_owned_sensitive_file_cleanup','original_lineage_cleanup_proof_bindings'))},'cleanup-review')
        if prior:
            event['predecessor_origin']=origin-1
            expected={'schema':1,'document_type':'qualification_campaign_successor',
                'predecessor_qualification_id':prior['qualification_id'],'predecessor_sha256':launch._digest(p['predecessor']),
                'qualification_id':p['qualification_id'],'ledger_root':root+'/launch-ledger','manifest_sha256':launch._digest(p)}
            event['claims']=[self.add(root+'/successor.json',expected,'claim')]
        self.events.append(event)
        return self.run()
    def closure(self):
        return r.FiniteClosure(self.root,self.entries,{'status':'PASS','unresolved_findings':[],
            'supports_exact_operational_metadata_closure':True,'closure_root':str(self.root),
            'entries_sha256':launch._digest(self.entries),'runtime_payload_files_included':False,
            'original_runtime_fallback_permitted':False},approved_root=self.root)
    def index(self):
        observation=self.add('/synthetic/observation.json',{'status':'PASS_METADATA_ONLY','selected_records':[
            {'launch_id':key,'canonical_body_sha256':digest,'status':'released'} for key,digest in self.record_digests.items()]},'operational-projection')
        review=self.add('/synthetic/observation-review.json',{'status':'PASS_METADATA_ONLY','subjects':{'verification':observation},
            'unresolved_findings':[],'supports_selected_record_metadata_and_known_guest_absence':True},'operational-projection')
        bindings=[];selected=[]
        namespace='/synthetic/original.lock.registry'
        for event in self.events:
            for ref in event['records']:
                body=self.objects[ref['path']];selected.append(ref)
                snapshot=self.add(event['root']+'/record-snapshot-'+str(len(self.entries))+'.json',{
                    'document_type':'qualification_retained_released_record_snapshot','namespace':namespace,
                    'capture':observation,'records':{body['launch_id']:{'record':ref,'status':'released',
                        'canonical_body_sha256':launch._digest(body),**{k:body[k] for k in ('registry','generation','daemon')}}}},'operational-projection')
                provenance=self.add(event['root']+'/record-provenance-'+str(len(self.entries))+'.json',{
                    'status':'PASS_SCOPED_RELEASED_RECORD_SNAPSHOT','unresolved_findings':[],
                    'supports_retained_released_record_bindings':True,'snapshot':snapshot,'namespace':namespace,
                    'scope':'retained_at_capture_not_current_global_liveness','evidence':[observation]},'operational-projection')
                bindings.append({'origin':event['origin'],'launch_id':body['launch_id'],'record':ref,
                    'namespace':namespace,'snapshot':snapshot,'provenance':provenance,'capture':observation})
        return {'schema':1,'document_type':'matrix20_operational_carry_index','events':self.events,
            'canonical_record_sha256':self.record_digests,'record_observation':observation,'record_observation_review':review,
            'selected_record_bodies':selected,'historical_record_bindings':bindings}
    def run(self):
        index=self.index()
        return r.replay(self.closure(),index,expected_origins=len(self.events),expected_attempts=len(self.events),expected_segments=0)


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve(); self.root.chmod(0o700); (self.root/'objects').mkdir(mode=0o700)
        self.f=Fixture(self.root)
        self.denies=[]
        for name in ('subprocess.Popen','subprocess.run','os.kill','socket.socket'):
            patcher=mock.patch(name,side_effect=AssertionError('live effect forbidden'))
            self.denies.append(patcher.start()); self.addCleanup(patcher.stop)
    def test_original_kernel_two_origins_real_reserve_and_claim_full_replay(self):
        first=self.f.matrix(); result=self.f.matrix(first)
        self.assertEqual((result['attempts'],result['participant_segments'],result['planned_cells']),(2,0,56))
        self.assertEqual(len(result['lineage']),2); self.assertEqual(len(result['prior_rows']),56)
        for deny in self.denies: deny.assert_not_called()
    def test_wrong_original_row_resources_rejected_even_with_rehashed_copy(self):
        self.f.matrix(); event=self.f.events[0]; closure=self.f.closure()
        full=closure.get(event['manifest'],'manifest'); ledger=closure.get(event['ledger'],'ledger')
        policy={k:full[k] for k in ('qualification_id','images','planned_container_launches')}
        policy.update(cells=[{k:c[k] for k in r.FIELDS} for c in full['cells']],limits=event['effective_limits'])
        ledger['launches'][0]['resources']['memory_mib']+=1
        with self.assertRaises(launch.LaunchError):
            r.Kernel.ledger(policy,ledger,event['root'],None,lambda *a:None)
    def test_poison_and_carry_types_are_original_kernel_guards(self):
        p=policy(); state={'schema':1,'manifest_sha256':launch._digest(p),'daemon':'fixture-daemon',
            'daemon_capacity':{'cpu_millis':1000,'memory_mib':1000},'started':0.,'deadline':14400.,
            'started_wall':0.,'deadline_wall':14400.,'last_now':0.,'last_wall':0.,'poisoned':False,'launches':[]}
        r.Kernel.ledger(p,state,'/synthetic',None,lambda *a:None)
        state['poisoned']=0
        with self.assertRaises(launch.LaunchError): r.Kernel.ledger(p,state,'/synthetic',None,lambda *a:None)
    def test_counter_certificate_without_original_ledgers_refuses(self):
        with self.assertRaises((launch.LaunchError,KeyError)):
            r.replay(self.f.closure(),{'schema':1,'document_type':'matrix20_operational_carry_index','events':[],
                'attempts':334,'participant_segments':21})
    def test_no_original_path_fallback_even_when_original_exists(self):
        original=self.root/'original.json'; original.write_text('{}'); original.chmod(0o600)
        ref={'path':str(original),'sha256':hashlib.sha256(b'{}').hexdigest()}
        with mock.patch.object(r,'safe_copy_json',side_effect=AssertionError('unexpected read')):
            with self.assertRaises(launch.LaunchError): self.f.closure().get(ref,'ledger')
    def test_copy_hash_and_symlink_denied(self):
        ref=self.f.add('/synthetic/object.json',{'schema':1},'state'); obj=self.root/'objects'/(ref['sha256']+'.json')
        obj.write_bytes(b'{}')
        with self.assertRaises(launch.LaunchError): self.f.closure().get(ref,'state')
        obj.unlink(); elsewhere=self.root/'other'; elsewhere.write_bytes(b'{}'); elsewhere.chmod(0o600); obj.symlink_to(elsewhere)
        with self.assertRaises(OSError): self.f.closure().get(ref,'state')
    def test_manifest_original_role_limit_and_arm64_checks(self):
        p=policy(); self.assertEqual(len(r.Kernel.manifest(p,p['limits'])['cells']),28)
        p['images']['core-0.87.1']['platform']='linux/amd64'
        with self.assertRaises(launch.LaunchError): r.Kernel.manifest(p,p['limits'])
    def test_real_claim_tamper_not_accepted_as_exists_boolean(self):
        first=self.f.matrix(); self.f.matrix(first)
        event=self.f.events[-1]; claim=self.f.objects[event['claims'][0]['path']]
        bad={**claim,'ledger_root':'/foreign/launch-ledger'}
        event['claims']=[self.f.add('/synthetic/badclaim.json',bad,'claim')]
        with self.assertRaises(launch.LaunchError): self.f.run()
    def test_native_carry_default_still_requires_exact19_334_21_not_fixture_counts(self):
        self.f.matrix()
        with self.assertRaises(launch.LaunchError):
            index=self.f.index(); r.replay(self.f.closure(),index)
    def test_rehashed_copied_record_CID_status_and_intent_tampering_rejected(self):
        self.f.matrix(); event=self.f.events[0]
        reference=event['records'][0]; original=self.f.objects[reference['path']]
        for changes in ({'container_id':'d'*64},{'status':'absent'},{'container':'foreign-name'}):
            record={**original,**changes}
            event['records']=[self.f.add('/synthetic/record-'+str(len(self.f.entries))+'.json',record,'record')]
            self.f.record_digests[record['launch_id']]=launch._digest(record)
            with self.subTest(changes=changes),self.assertRaises(launch.LaunchError): self.f.run()
        # Missing CID is original permitted None, never a fabricated actual ID.
        event['records']=[reference]; self.f.record_digests[original['launch_id']]=launch._digest(original)
        self.assertEqual(self.f.run()['attempts'],1)
    def test_rehashed_linear_window_reset_rejected_by_original_Ledger(self):
        first=self.f.matrix()
        with self.assertRaises(launch.LaunchError): self.f.matrix(first,clock_start=200.)
    def test_rehashed_duplicate_root_rejected(self):
        first=self.f.matrix()
        with self.assertRaises(launch.LaunchError): self.f.matrix(first,root_override=self.f.events[0]['root'])
    def test_full_manifest_limits_cannot_disagree_with_policy(self):
        self.f.matrix(); event=self.f.events[0]; closure=self.f.closure()
        full=closure.get(event['manifest'],'manifest'); source=closure.get(event['source_review'],'source-review')
        full['limits']['container_launch_attempts']+=1
        with self.assertRaises(launch.LaunchError): r.frozen_metadata(full,event['effective_limits'],source,closure,event)
    def test_original_create_planned_headroom_not_just_actual_rows(self):
        first=self.f.matrix(); first['attempts']=55
        # Valid actual row would fit240, but planned186+55 exceeds240.
        with self.assertRaises(launch.LaunchError): self.f.matrix(first)
    def test_real_temporary_Registry_network_and_worker_mirror_before_write(self):
        import ownership_registry
        from types import SimpleNamespace
        root=self.root/'scope'; root.mkdir(mode=0o700)
        registry=ownership_registry.Registry(self.root/'registry'); registry.runroot=root; registry.bind_daemon('fixture-daemon')
        original=registry.write; observed=[]
        def checked(record):
            mirror=root/('intent-'+record['launch_id']+'.json')
            self.assertTrue(mirror.is_file())
            body=json.loads(mirror.read_bytes())
            self.assertTrue(body['before_original_Registry_write'])
            self.assertEqual(body['intent_sha256'],launch._intent_identity(record))
            observed.append(record['launch_id']); return original(record)
        registry.write=checked
        manifest={'qualification_id':uid(),'campaign_amendment':{'path':'/synthetic/auth','sha256':'a'*64}}
        with mock.patch.object(m,'FINAL_ROOT',root),mock.patch.object(m,'_clock',return_value=None):
            with m.intent_mirrors(registry,manifest,SimpleNamespace(expected={})):
                network=registry.network_intent('pi-application-'+uuid.uuid4().hex+'-network')
                record,argv=registry.intent(['docker','run','--name','pi-lab-fixture',
                    'sha256:'+'a'*64,'/opt/pi-lab/worker.py','probe'],'pi-lab-fixture')
                self.assertIsNone(network.get('owner_pid')); self.assertIsNone(network['runroot'])
                count=len(list(root.iterdir()))
                with mock.patch.object(m,'_clock',side_effect=AssertionError('cleanup must not use work gate')):
                    record['status']='released'; registry.write(record)
                self.assertEqual(len(list(root.iterdir())),count)
            self.assertIs(registry.write,checked)
        self.assertEqual(len(observed),3)
    def test_mirror_failure_prevents_original_first_write_and_restores_instance(self):
        from types import SimpleNamespace
        root=self.root/'scope'; root.mkdir(mode=0o700)
        identifier=uid(); (root/('intent-'+identifier+'.json')).write_text('{}')
        original=mock.Mock()
        registry=SimpleNamespace(write=original,registry_id='a'*64,generation=uid(),daemon='fixture-daemon')
        record={'launch_id':identifier,'kind':'network','schema':1,'status':'intent','registry':registry.registry_id,
            'generation':registry.generation,'daemon':registry.daemon,'container':'pi-application-fixture-network',
            'runroot':None,'image':None,'mounts':[]}
        with mock.patch.object(m,'FINAL_ROOT',root),mock.patch.object(m,'_clock',return_value=None):
            with self.assertRaises(FileExistsError):
                with m.intent_mirrors(registry,{'qualification_id':uid(),'campaign_amendment':{}},SimpleNamespace(expected={})):
                    registry.write(record)
        original.assert_not_called(); self.assertIs(registry.write,original)
    def test_external_absent_seal_refuses_all_public_apis_before_historical_read(self):
        with mock.patch.object(m.launch,'_bound_json',side_effect=launch.LaunchError('unbound')) as read:
            self.assertFalse(m.accepts({'path':'/synthetic/auth.json','sha256':'a'*64}))
            for action in (lambda:m.effective_limits({}),lambda:m.validate_amendment({},{}),
                           lambda:m.finalize_candidate({}, {}, {}),lambda:m.bind_final('/synthetic',{},{})):
                with self.assertRaises(launch.LaunchError): action()
            self.assertTrue(all(call.args[0]==str(m.PREPARATION_SEAL_PATH) for call in read.call_args_list))
    def test_private_function_namespaces_do_not_mutate_original_functions(self):
        before=dict(launch.validate_manifest.__globals__); p=policy(); r.Kernel.manifest(p,p['limits'])
        self.assertIs(launch.validate_manifest.__globals__['effective_limits'],before['effective_limits'])
        self.assertIs(launch.LaunchLedger._validate.__globals__['_successor_claim'],before['_successor_claim'])


class ExternalSealDependencies(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.root.chmod(0o700)
        for name in ('subprocess.Popen','subprocess.run','os.kill','socket.socket'):
            guard=mock.patch(name,side_effect=AssertionError('live effect forbidden'))
            guard.start();self.addCleanup(guard.stop)

    def seal_fixture(self,path):
        names=('application_matrix20.py','application_operational_replay.py',
            'application_scoped_retained_checks.py','application_launch.py',
            'application_sdk_admission.py','application_client.py')
        programs={}
        for name in names:
            body=('synthetic reviewed source '+name).encode()
            (self.root/name).write_bytes(body);programs[name]=hashlib.sha256(body).hexdigest()
        binding={'path':str(m.CAMPAIGN/'matrix20-preparation-binding.json'),'sha256':'b'*64}
        review={'path':str(m.CAMPAIGN/'synthetic-source-input-review.json'),'sha256':'c'*64}
        seal={'schema':1,'document_type':'matrix20_preparation_seal','status':'ROOT_SEALED',
            'native_execution_authorized':False,'authorization':{'path':path,'sha256':'a'*64},
            'run_binding':binding,'program_sha256':programs,'runner_sha256':'d'*64,
            'public_documents':[binding,review],'source_input_review':review}
        source_review={'status':'PASS','unresolved_findings':[],
            'supports_matrix20_source_input_preparation':True,'program_sha256':programs,
            'run_binding':binding}
        def read(name,digest=None):
            if name==str(m.PREPARATION_SEAL_PATH):return copy.deepcopy(seal)
            if name==review['path'] and digest==review['sha256']:return copy.deepcopy(source_review)
            raise AssertionError('unbound fixture read')
        return seal,read

    def test_exact_six_program_seal_accepts_helper_but_missing_or_changed_helper_denies(self):
        import provenance
        path=str(m.CAMPAIGN/'matrix-020-authorization-002.json')
        seal,read=self.seal_fixture(path)
        with mock.patch.object(m,'__file__',str(self.root/'application_matrix20.py')), \
             mock.patch.object(m.launch,'_bound_json',side_effect=read), \
             mock.patch.object(provenance,'execution',return_value={'runner_content_sha256':'d'*64}):
            self.assertEqual(m.bound()['authorization'],{'path':path,'sha256':'a'*64})
            helper_hash=seal['program_sha256'].pop('application_scoped_retained_checks.py')
            with self.assertRaises(launch.LaunchError):m.bound()
            seal['program_sha256']['application_scoped_retained_checks.py']=helper_hash
            (self.root/'application_scoped_retained_checks.py').write_bytes(b'tampered helper')
            with self.assertRaises(launch.LaunchError):m.bound()

    def test_three_fixed_authority_paths_need_exact_seal_and_unknown_path_has_zero_selector_io(self):
        old={'path':str(m.AUTHORIZATION_PATH),'sha256':'a'*64}
        future={'path':str(m.CAMPAIGN/'matrix-020-authorization-002.json'),'sha256':'b'*64}
        with mock.patch.object(m,'bound',return_value={'authorization':future})as read:
            self.assertTrue(m.accepts(future));self.assertFalse(m.accepts(old))
            read.reset_mock()
            for wrong in ({'path':str(m.CAMPAIGN/'matrix-020-authorization-004.json'),'sha256':'b'*64},
                          {'path':'/synthetic/unrelated.json','sha256':'b'*64},
                          {**future,'unexpected':True}, {'path':[],'sha256':'b'*64}):
                self.assertFalse(m.accepts(wrong))
            read.assert_not_called()
        with mock.patch.object(m,'bound',side_effect=launch.LaunchError('unbound')):
            self.assertFalse(m.accepts(future))

    def test_auth003_matching_reviewed_seal_accepts_only_its_exact_reference(self):
        import provenance
        path=str(m.CAMPAIGN/'matrix-020-authorization-003.json')
        reference={'path':path,'sha256':'a'*64}
        seal,read=self.seal_fixture(path)
        with mock.patch.object(m,'__file__',str(self.root/'application_matrix20.py')), \
             mock.patch.object(m.launch,'_bound_json',side_effect=read), \
             mock.patch.object(provenance,'execution',return_value={'runner_content_sha256':'d'*64}):
            self.assertEqual(m.bound()['authorization'],reference)
            self.assertTrue(m.accepts(reference))
            self.assertFalse(m.accepts({**reference,'sha256':'b'*64}))
            for other in (str(m.AUTHORIZATION_PATH),str(m.CAMPAIGN/'matrix-020-authorization-002.json')):
                self.assertFalse(m.accepts({'path':other,'sha256':'a'*64}))

    def test_auth003_absent_unbound_or_non_allowed_seal_cannot_activate_selector(self):
        import provenance
        path=str(m.CAMPAIGN/'matrix-020-authorization-003.json')
        reference={'path':path,'sha256':'a'*64}
        seal,read=self.seal_fixture(path)
        with mock.patch.object(m,'__file__',str(self.root/'application_matrix20.py')), \
             mock.patch.object(provenance,'execution',return_value={'runner_content_sha256':'d'*64}):
            with mock.patch.object(m.launch,'_bound_json',side_effect=FileNotFoundError('synthetic absent seal')):
                self.assertFalse(m.accepts(reference))
            with mock.patch.object(m.launch,'_bound_json',side_effect=read):
                seal['status']='UNBOUND'
                self.assertFalse(m.accepts(reference))
                seal['status']='ROOT_SEALED'
                seal['authorization']={'path':str(m.CAMPAIGN/'matrix-020-authorization-004.json'),'sha256':'a'*64}
                self.assertFalse(m.accepts(reference))

    def test_new_path_does_not_reset_or_widen_authorized_clock(self):
        # Existing context's real closed auth/bounds validator is used; no native
        # operation or actual grant/body is read. All three selectors share it.
        tree=__import__('ast').parse(SUBJECT.read_bytes())
        function=next(n for n in tree.body if isinstance(n,__import__('ast').FunctionDef)and n.name=='context')
        fixed=next(__import__('ast').literal_eval(n.value)for n in __import__('ast').walk(function)
            if isinstance(n,__import__('ast').Assign)and any(isinstance(k,__import__('ast').Name)and k.id=='fixed'for k in n.targets))
        for path in m.AUTHORIZATION_PATHS:
            reference={'path':path,'sha256':'a'*64};clockref={'path':str(m.CAMPAIGN/'synthetic-clock.json'),'sha256':'b'*64}
            bindingref={'path':str(m.CAMPAIGN/'matrix20-preparation-binding.json'),'sha256':'c'*64}
            bounds={'started_monotonic':100.,'started_wall':1000.,'deadline_monotonic':14500.,'deadline_wall':15400.}
            auth={'schema':1,'document_type':'qualification_matrix20_amendment','status':'AUTHORIZED',
                'authorization_id':'synthetic-closed-authority',**fixed,**bounds}
            clock={'document_type':'matrix20_authorization_clock','authorization':reference,
                'authorization_id':auth['authorization_id'],**bounds}
            binding={'schema':1,'document_type':'matrix20_run_binding','authorization':reference,
                'final_root':str(m.FINAL_ROOT),'binding_root':str(m.BINDING_ROOT),
                'boundary':m.BOUNDARY_REFERENCE,'runner_sha256':'d'*64,
                'new_A14_candidate_required':True,'window':clockref}
            seal={'authorization':reference,'run_binding':bindingref,'runner_sha256':'d'*64}
            objects={bindingref['path']:binding,path:auth,clockref['path']:clock}
            with mock.patch.object(m,'bound',return_value=seal), \
                 mock.patch.object(m,'public',side_effect=lambda ref,**kw:copy.deepcopy(objects[ref['path']])):
                self.assertEqual(m.context(reference,clock=lambda:101.,wall=lambda:1001.,window=True)[2],bounds)
                auth['container_cap']=True
                with self.assertRaises(launch.LaunchError):
                    m.context(reference,clock=lambda:101.,wall=lambda:1001.,window=True)
                auth['container_cap']=fixed['container_cap']
                with self.assertRaises(launch.LaunchError):
                    m.context(reference,clock=lambda:14500.,wall=lambda:15400.,window=True)
                auth['deadline_wall']=15401.;clock['deadline_wall']=15401.
                with self.assertRaises(launch.LaunchError):
                    m.context(reference,clock=lambda:101.,wall=lambda:1001.,window=True)


if __name__=='__main__': unittest.main(verbosity=2)
