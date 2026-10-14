"""Frozen maintainer intent/launch accounting, synthetic stores and no Docker/model."""
import copy,json,os,shutil,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools/qualification'),str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import indexed,indexed_budget,experiments,secret_store
from test_indexed_contract import config

class IntentTests(unittest.TestCase):
    def coding_inspection_fixture(self):
        import uuid
        manifest={'batches':[{'id':'serial','kind':'coding'},{'id':'parallel','kind':'coding'}]};runs=[]
        for number in range(36):
            parent=(self.root/'batches/serial/standalone-runs'/str(number)/'runs') if number<24 else self.root/'batches/parallel/experiment/runs'
            run=parent/str(uuid.uuid4());run.mkdir(parents=True);workspace=self.root/('workspace-'+str(number));workspace.mkdir();(workspace/'slug.py').write_text('synthetic=True\n')
            reviewer=run/'logs/reviewer';reviewer.mkdir(parents=True);(reviewer/'final.txt').write_text('Synthetic inspection fixture.\n')
            indexed.controls.atomic(run/'result.json',{'run_id':run.name,'workspace':str(workspace),'agents':[{}, {'logs':'logs/reviewer'}],'protected_inputs':{'status':'unchanged'}})
            alias=parent/'latest'
            if alias.is_symlink():alias.unlink()
            alias.symlink_to(run);runs.append(run)
        return manifest,runs
    def test_coding_inspection_collects_exactly_36_canonical_pipelines_with_latest_aliases(self):
        manifest,runs=self.coding_inspection_fixture();targets=indexed.inspection_targets(self.root,manifest)
        self.assertEqual(len(targets),36);self.assertEqual({r['run_id'] for r in targets},{run.name for run in runs})
    def test_coding_inspection_rejects_run_identity_mismatch_and_foreign_alias(self):
        manifest,runs=self.coding_inspection_fixture();path=runs[0]/'result.json';record=experiments.read_json(path);record['run_id']='foreign';indexed.controls.atomic(path,record)
        with self.assertRaises(RuntimeError):indexed.inspection_targets(self.root,manifest)
        record['run_id']=runs[0].name;indexed.controls.atomic(path,record)
        alias=runs[-1].parent/'latest';alias.unlink();alias.symlink_to(runs[0])
        with self.assertRaises(RuntimeError):indexed.inspection_targets(self.root,manifest)
    def test_coding_inspection_rejects_linked_experiment_and_batch_ancestors(self):
        manifest,runs=self.coding_inspection_fixture();folder=self.root/'batches/parallel';experiment=folder/'experiment';real=folder/'experiment-real';experiment.rename(real);experiment.symlink_to(real)
        with self.assertRaises(RuntimeError):indexed.inspection_targets(self.root,manifest)
        experiment.unlink();real.rename(experiment);batch_real=self.root/'parallel-real';folder.rename(batch_real);folder.symlink_to(batch_real)
        with self.assertRaises(RuntimeError):indexed.inspection_targets(self.root,manifest)
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name).resolve()
        self.store=self.root/'operator-store'
        secret_store.write_secret('SYNTHETIC_A','synthetic-qualification-a',self.store);secret_store.write_secret('SYNTHETIC_B','synthetic-qualification-b',self.store)
        a=config();a['credential']['name']='SYNTHETIC_A';b=config();b['credential']['name']='SYNTHETIC_B'
        profiles={'a':a,'b':b,'scope':'Synthetic same-backend authority fixtures; no live qualification','deployment_limits':'unknown'}
        self.write('profiles.json',profiles);self.write('images.json',{kind+'-'+release:{'id':'sha256:'+'a'*64,'platform':'linux/arm64'} for release in ('0.87.1','1.2.0') for kind in ('core','browser')})
    def write(self,name,value):
        path=self.root/name;path.write_text(json.dumps(value));return path
    def frozen(self):
        with patch.object(secret_store,'default_store',return_value=self.store),patch.object(indexed.lab,'command',side_effect=AssertionError('No Docker permitted')),patch.object(indexed.pi_release,'native',side_effect=AssertionError('No native execution permitted')):
            result=indexed.freeze(self.root/'intent',self.root/'profiles.json',self.root/'images.json','fixture')
        manifest=experiments.read_json(self.root/'intent/manifest.json');self.addCleanup(shutil.rmtree,manifest['private_root'],ignore_errors=True)
        return result,manifest
    def test_matrix_and_launch_envelope_exactly_match_ordered_plan(self):
        rows=indexed.matrix()
        self.assertEqual([(sum(r['cells'] for r in rows if r['collection']==p),sum(r['segments_ceiling'] for r in rows if r['collection']==p)) for p in ('A','B')],[(84,108),(136,204)])
        self.assertEqual([r['collection'] for r in rows],sorted(r['collection'] for r in rows))
        derivation=indexed.launch_derivation();self.assertLessEqual(derivation['whole']['containers'],1600);self.assertLessEqual(derivation['whole']['networks'],256)
        self.assertEqual(derivation['whole']['containers'],sum(derivation[p]['containers'] for p in ('infrastructure','A','B')))
        paths={row['id']:row['containers'] for row in derivation['batches']}
        self.assertEqual(paths['b-0.87.1-coding'],44)
        self.assertEqual(paths['b-0.87.1-credentials'],110)
        self.assertEqual(paths['b-0.87.1-crash'],24)
        self.assertEqual(paths['b-0.87.1-discovery'],26)
    def test_freeze_is_offline_private_and_tamper_rejects(self):
        result,manifest=self.frozen();self.assertEqual(result['planned_cells'],220);self.assertEqual(len({c['id'] for c in manifest['cell_oracles']}),220)
        text=(self.root/'intent/manifest.json').read_text();self.assertNotIn('synthetic-qualification-a',text);self.assertNotIn('synthetic-qualification-b',text)
        indexed.verify(self.root/'intent')
        path=self.root/'intent/worker.json';path.chmod(0o600);path.write_text('{}')
        with self.assertRaises(ValueError):indexed.verify(self.root/'intent')
    def test_private_namespace_cannot_merge_distinct_same_name_sources(self):
        value=experiments.read_json(self.root/'profiles.json')
        value['a']['credential']={'source':'env','name':'SYNTHETIC_B'}
        self.write('profiles.json',value)
        with patch.dict(os.environ,{'SYNTHETIC_B':'synthetic-different-env-authority'}),patch.object(secret_store,'default_store',return_value=self.store):
            with self.assertRaises(ValueError):indexed.freeze(self.root/'intent',self.root/'profiles.json',self.root/'images.json','fixture')
        self.assertFalse((self.root/'intent').exists())
    def test_counter_charges_before_launch_and_rejects_architecture_caps_cleanup(self):
        self.frozen();root=self.root/'intent';now=time.monotonic()
        value={'phase':'A','whole_deadline':now+100,'phase_deadline':now+50,'docker':'/synthetic/docker','counts':{p:{'containers':0,'networks':0} for p in ('infrastructure','A','B')}}
        self.write('unused.json',{})
        indexed.controls.atomic(root/'budget.json',value)
        with self.assertRaises(ValueError):indexed_budget.charge(root,'A',['run','--platform','linux/amd64'])
        indexed_budget.charge(root,'A',['run','--platform','linux/arm64'])
        recorded=experiments.read_json(root/'budget.json');self.assertEqual(recorded['counts']['A']['containers'],1)
        recorded['cleanup']=True;indexed.controls.atomic(root/'budget.json',recorded)
        with self.assertRaises(ValueError):indexed_budget.charge(root,'A',['network','create','namespace'])
        with self.assertRaises(TimeoutError):indexed_budget.charge(root,'A',['rm','owned'],now=now+101)
    def test_segment_ceiling_is_atomic_with_container_charge(self):
        self.frozen();root=self.root/'intent';now=time.monotonic()
        value={'phase':'A','whole_deadline':now+100,'phase_deadline':now+50,'docker':'/synthetic/docker','counts':{p:{'containers':0,'networks':0,'segments':0} for p in ('infrastructure','A','B')}}
        value['counts']['A']['segments']=108;indexed.controls.atomic(root/'budget.json',value)
        with self.assertRaises(ValueError):indexed_budget.charge(root,'A',['run','--platform','linux/arm64','/opt/pi-lab/worker.py','agent','--task','/synthetic/task.json'])
        self.assertEqual(experiments.read_json(root/'budget.json')['counts']['A']['containers'],0)
    def test_failed_or_unapproved_collection_never_dispatches(self):
        self.frozen();root=self.root/'intent';indexed.controls.atomic(root/'state.json',{'phase':'blocked'})
        with patch.object(indexed.predecessor,'command',side_effect=AssertionError('No dispatch')):
            with self.assertRaises(ValueError):indexed.infrastructure(root)
            with self.assertRaises(ValueError):indexed.collect_phase(root,'A')
    def test_finish_requires_all_inspections_and_removes_only_private_fixture_namespace(self):
        result,manifest=self.frozen();root=self.root/'intent';now=time.monotonic()
        targets=[]
        for number in range(36):
            target=root/('implementation-'+str(number)+'.py');target.write_text('synthetic_fixture=True\n')
            reviewer=root/('reviewer-'+str(number)+'.txt');reviewer.write_text('Synthetic fixture inspection only.\n')
            targets.append({'run_id':str(number),'implementation_sha256':indexed.hashlib.sha256(target.read_bytes()).hexdigest(),'reviewer_sha256':indexed.hashlib.sha256(reviewer.read_bytes()).hexdigest()})
        indexed.controls.atomic(root/'state.json',{'phase':'B_qualified','remaining_not_run':[],'segments':292,'observed_segments':292})
        indexed.controls.atomic(root/'budget.json',{'whole_deadline':now+100})
        inspection=self.write('inspection.json',[{**target,'reviewed':True} for target in targets])
        with patch.object(indexed,'inspection_targets',return_value=targets):
            finished=indexed.finish(root,inspection)
        self.assertEqual(finished['phase'],'qualified');self.assertFalse(Path(manifest['private_root']).exists())
        self.assertTrue(self.store.exists());self.assertEqual(secret_store.read_secret('SYNTHETIC_A',self.store),'synthetic-qualification-a')
    def test_required_usage_and_effective_caps_cannot_be_replaced_with_unknown(self):
        record={'measurement':{'usage':{'categories':{'total':{'reported':100}}}},'agents':[{'process':{'stage_reported_tokens':100,'stage_turns':2}}]}
        indexed.positive_usage(record)
        for field,value in (('stage_reported_tokens',None),('stage_reported_tokens',128001),('stage_turns',13)):
            changed=copy.deepcopy(record);changed['agents'][0]['process'][field]=value
            with self.assertRaises(RuntimeError):indexed.positive_usage(changed)
        record['measurement']['usage']['categories']['total']['reported']=0
        with self.assertRaises(RuntimeError):indexed.positive_usage(record)
    def test_all_fixture_definitions_prepare_with_exhaustive_bindings(self):
        result,manifest=self.frozen();root=self.root/'intent'
        class Authority:
            endpoint=manifest['profiles']['a']['configuration']['endpoint'];store=Path(manifest['store'])
            child='http://fixture.invalid:12345';host='http://127.0.0.1:12345';inference='synthetic-fault-a';second_inference='synthetic-fault-b';issued=[];config={}
            def write(self):pass
            def actors(self,case,nonce):
                refs={}
                for role in ('A','B'):
                    reference='SYNTHETIC_'+case.upper()+'_'+role;secret_store.write_secret(reference,'synthetic-actor-'+case+'-'+role,self.store);refs[role]=reference
                return refs
        authority=Authority()
        for batch in indexed.matrix():
            with self.subTest(batch=batch['id']):
                folder,prepared=indexed.builder(root,batch,manifest,authority)
                if prepared.name=='standalone':
                    definition=experiments.read_json(prepared/'definition.json');self.assertEqual(len(definition['variants'])*definition['repetitions'],batch['cells'])
                else:
                    metadata,matrix=experiments.verify(prepared,indexed.lab);self.assertEqual(len(matrix['cells']),batch['cells'])
                    if metadata['schema']==3:
                        for cell in matrix['cells']:self.assertTrue(experiments.read_json(prepared/cell['inference_bindings']))

if __name__=='__main__':unittest.main()
