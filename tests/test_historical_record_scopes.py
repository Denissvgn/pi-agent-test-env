"""Production-cardinality metadata fixtures; no original/current data IO."""
import contextlib
import copy
import hashlib
import os
from pathlib import Path
import signal
import sys
import unittest
import uuid
from unittest import mock

if __name__=='__main__':
    signal.signal(signal.SIGALRM,lambda *_:os._exit(124));signal.setitimer(signal.ITIMER_REAL,30)
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'tools/qualification/application_launch.py').is_file())
sys.path[:0]=[str(HERE),str(ROOT/'tools/qualification')]
with contextlib.ExitStack() as imports:
    for name in ('subprocess.Popen','subprocess.run','os.kill','socket.socket'):
        imports.enter_context(mock.patch(name,side_effect=AssertionError('native import effect')))
    import application_launch as launch
    import application_operational_replay as replay


class Memory:
    def __init__(self): self.values={};self.count=0;self.entries=[]
    def add(self,value,kind='operational-projection',path=None):
        self.count+=1; path=path or '/synthetic/object-'+str(self.count)+'.json'
        ref={'path':path,'sha256':launch._digest(value)}
        self.values[(path,ref['sha256'],kind)]=copy.deepcopy(value)
        self.entries.append({'original':ref,'copy':{'path':'/synthetic/copies/objects/'+ref['sha256']+'.json','sha256':ref['sha256']},'kind':kind})
        return ref
    def get(self,ref,kind):
        return copy.deepcopy(self.values[(ref['path'],ref['sha256'],kind)])


def fixture(*,changed_proof=False,same_capture=False):
    memory=Memory(); namespace='/synthetic/operation.lock.registry'
    registry=hashlib.sha256(namespace.encode()).hexdigest(); generation=str(uuid.uuid4())
    old=[];oldrefs=[]
    for n in range(309):
        body={'schema':1,'launch_id':str(uuid.uuid5(uuid.NAMESPACE_OID,'fixture-historical-'+str(n))),
            'registry':registry,'generation':generation,'daemon':'fixture-daemon','status':'released',
            'container':'fixture-'+str(n),'image':'sha256:'+'a'*64,'mounts':[],
            'container_id':format(n+1,'064x'),'runroot':'/synthetic/origin-'+str(n%19+1)}
        old.append(body);oldrefs.append(memory.add(body,'record'))
    current=[]; current_refs=[]
    for n,body in enumerate(old[:255]):
        value=copy.deepcopy(body)
        if n==0 and changed_proof:
            value['qualification_service_cleanup']={'path':'/synthetic/later-proof.json','sha256':'f'*64}
        current.append(value);current_refs.append(memory.add(value,'record'))
    for n in range(26):
        current.append({'schema':1,'launch_id':str(uuid.uuid5(uuid.NAMESPACE_OID,'fixture-network-'+str(n))),
            'registry':registry,'generation':generation,'status':'released','kind':'network','container':'network-'+str(n),
            'image':None,'mounts':[],'runroot':None,'daemon':'fixture-daemon'})
    observed={b['launch_id']:launch._digest(b) for b in current}
    observation=memory.add({'status':'PASS_METADATA_ONLY','selected_records':[
        {'launch_id':key,'canonical_body_sha256':digest,'status':'released'} for key,digest in observed.items()]})
    peer=memory.add({'status':'PASS_METADATA_ONLY','subjects':{'verification':observation},
        'unresolved_findings':[],'supports_selected_record_metadata_and_known_guest_absence':True})
    capture=observation if same_capture else memory.add({'schema':1,'document_type':'fixture_original_capture'})
    bindings=[]
    for n,(body,ref) in enumerate(zip(old,oldrefs)):
        snapshot=memory.add({'document_type':'qualification_retained_released_record_snapshot',
            'namespace':namespace,'capture':capture,'records':{body['launch_id']:{'record':ref,'status':'released',
                'canonical_body_sha256':launch._digest(body),**{k:body[k] for k in ('registry','generation','daemon')}}}})
        provenance=memory.add({'status':'PASS_SCOPED_RELEASED_RECORD_SNAPSHOT','unresolved_findings':[],
            'supports_retained_released_record_bindings':True,'snapshot':snapshot,'namespace':namespace,
            'scope':'retained_at_capture_not_current_global_liveness','evidence':[capture]})
        bindings.append({'origin':n%19+1,'launch_id':body['launch_id'],'record':ref,'namespace':namespace,
            'snapshot':snapshot,'provenance':provenance,'capture':capture})
    index={'record_observation':observation,'record_observation_review':peer,
        'canonical_record_sha256':observed,'selected_record_bodies':current_refs,
        'historical_record_bindings':bindings}
    return memory,index,old


# Self-contained RAM-only production geometry for normal unittest discovery.
r=replay
COUNTS=[7,12,6,8,6,6,6,1,8,12,3,12,14,14,44,30,39,28,53]
PARTICIPANTS=[0]*12+[1,1,4,3,4,2,6]
def uid(label):return str(uuid.uuid5(uuid.NAMESPACE_OID,'matrix20-fixture-'+label))

class ProductionMemory:
    def __init__(self):self.values={};self.entries=[];self.serial=0
    def add(self,value,kind='operational-projection',path=None,reference=None):
        self.serial+=1
        ref=reference or {'path':path or '/synthetic/object-'+str(self.serial)+'.json','sha256':launch._digest(value)}
        key=(ref['path'],ref['sha256'],kind)
        if key in self.values:
            assert self.values[key]==value;return copy.deepcopy(ref)
        self.values[key]=copy.deepcopy(value)
        self.entries.append({'original':copy.deepcopy(ref),'copy':{'path':'/synthetic/objects/'+ref['sha256']+'.json','sha256':ref['sha256']},'kind':kind})
        return copy.deepcopy(ref)
    def get(self,ref,kind):return copy.deepcopy(self.values[ref['path'],ref['sha256'],kind])

def production_history():
    m=ProductionMemory();events=[];selectors=[];evidence={};record_evidence={};allrecords=[];bindings=[]
    namespace='/synthetic/operation.lock.registry';registry=hashlib.sha256(namespace.encode()).hexdigest()
    images={p+'-'+v:{'id':'sha256:'+str(i+1)*64,'platform':'linux/arm64','capabilities':{'pi':v}}
        for i,(p,v) in enumerate((('core','0.87.1'),('browser','0.87.1'),('core','1.2.0'),('browser','1.2.0')))}
    first={k:r.HISTORICAL_POLICY[9][v]-14400 if k.startswith('started') else r.HISTORICAL_POLICY[9][v]
        for k,v in (('started','deadline'),('deadline','deadline'),('started_wall','deadline_wall'),('deadline_wall','deadline_wall'))}
    rootlist=list(r.HISTORICAL_RUNTIME_ROOTS)
    initial_capture=m.add({'schema':1,'document_type':'fixture_retained_record_capture'})
    prior=None;originrows=[];attempts=segments=0;lineage=[];base=None;auxiliary={};base_carry=None
    boundary_ref={'path':'/Users/bramen/Projects/pi-agentic-development/reports/application-agent-enhancements/A15/campaign-002/auxiliary/boundary.json','sha256':'a5512d47f9b4428144b5a47205cb999c69b0f9c893dc5c03ac19acddfcfb1f3b'}
    for origin,(count,parts) in enumerate(zip(COUNTS,PARTICIPANTS),1):
        root=rootlist[origin-1];qid=uid('qualification-'+str(origin));cells=r.matrix_cells(images)
        for c in cells:
            if c['group']=='N02':c['trial_id']=uid('trial-'+str(origin)+c['id'])
            if c['participant_segments_max']:c['plan_sha256']='e'*64
        limits=dict(launch.LIMITS);window=copy.deepcopy(first)
        if origin>=9:
            rule=r.HISTORICAL_POLICY[origin];limits.update(container_launch_attempts=rule['container_cap'],participant_segments=rule['participant_cap'])
            window={'started':rule['deadline']-14400,'deadline':rule['deadline'],
                'started_wall':rule['deadline_wall']-14400,'deadline_wall':rule['deadline_wall']}
            m.add({'authorization_id':rule['authorization_id'],'container_cap':rule['container_cap'],
                'participant_cap':rule['participant_cap']},'authority',reference=rule['authorization'])
        policy={'qualification_id':qid,'images':images,'cells':[{k:c[k] for k in r.FIELDS} for c in cells],
            'limits':limits,'planned_container_launches':186}
        if origin>1:
            pred=base if origin>=8 else lineage[-1]
            policy['predecessor']={'schema':1,'root':pred['root'],**{k:pred[k] for k in ('manifest_sha256','state_sha256','ledger_sha256')},
                'cleanup_receipts':[initial_capture]}
        if origin>=8:policy['campaign_boundary']=boundary_ref
        if origin>=9:policy['campaign_amendment']=r.HISTORICAL_POLICY[origin]['authorization']
        source_files={'tools/qualification/application_client.py':'d'*64}
        if origin>=9:source_files[r.HISTORICAL_POLICY[origin]['source_path']]=r.HISTORICAL_POLICY[origin]['source_sha256']
        source={'runner':'a'*64,'runner_files':{},'files':source_files,'sha256':launch._digest(source_files)}
        full={**copy.deepcopy(policy),'schema':1,'document_type':'application_client_qualification','created_at':'fixture',
            'prepared_root':root,'session':uid('session'),'endpoint':{},'endpoint_sha256':launch._digest({}),
            'image_receipts':{},'fixture_route':{},'credential_references':{'alice':'FIXTURE_A','bob':'FIXTURE_B','scripted_inference':'FIXTURE_S'},
            'host_admission':{'lock_file':'/synthetic/operation.lock','wait_seconds':30},'secrets_dir':'/synthetic/store',
            'source':source,'files':{'inputs/fixture.json':'f'*64},'negative_oracles':r.negative_oracles()}
        full['cells']=cells;full['limits']={k:v for k,v in limits.items() if k!='live'}
        full['limits'].update(simultaneously_registered_live_container_intents=4,automatic_retries=0,continuations=0)
        ledger={'schema':1,'manifest_sha256':launch._digest(policy),'daemon':'fixture-daemon',
            'daemon_capacity':{'cpu_millis':64000,'memory_mib':65536},**window,
            'last_now':window['started']+1,'last_wall':window['started_wall']+1,'poisoned':False,'launches':[]}
        expected_prior=None
        if prior:
            expected_prior={**prior,'attempts':attempts,'participant_segments':segments,**window}
            ledger['carry']={'descriptor_sha256':launch._digest(policy['predecessor']),
                'attempts':attempts,'participant_segments':segments,'qualification_id':prior['qualification_id'],'planned_cells':(origin-1)*28}
        verifier=object.__new__(launch.LaunchLedger);verifier.manifest=policy;verifier._carry=expected_prior
        choices=[]
        # Participant counts are precise; all remaining rows are legal unused
        # N01/N02 role slots. This is accounting, not a runtime-sequence claim.
        for c in cells:
            if c['group']=='N02' and parts:
                choices.append((c,'participant'));parts-=1
        for c in cells:
            if c['group'] not in ('N01','N02'):continue
            for role in c['role_limits']:
                if role!='participant':choices.append((c,role))
        usedcells={}
        for n,(c,role) in enumerate(choices[:count]):
            record={'schema':1,'registry':registry,'generation':uid('generation-'+str(origin)),
                'launch_id':uid('launch-'+str(origin)+'-'+str(n)),'container':'fixture-'+str(origin)+'-'+str(n),
                'image':images['core-'+c['release']]['id'] if role in launch.EXTERNAL else c['image_id'],
                'mounts':[],'status':'intent','daemon':'fixture-daemon','runroot':root+'/cells/'+c['id'],'owner_pid':123}
            verifier._reserve_apply(ledger,c['id'],role,record,launch._role_weight(policy,c,role),
                {'id':'fixture-daemon','cpu_millis':64000,'memory_mib':65536},pull_policy='explicit')
            row=ledger['launches'][-1];cid=hashlib.sha256(record['launch_id'].encode()).hexdigest()
            row.update(physical='absent',private_cleanup=True,container_id=cid,pid=123)
            released={**record,'status':'released','container_id':None if role=='probe' else cid}
            ref=m.add(released,'record',path='/synthetic/records/'+record['launch_id']+'.json')
            allrecords.append((origin,released,ref));usedcells[c['id']]={'status':'BLOCKED','attempts':1}
        ledger['poisoned']=True
        if origin==19:
            for row in ledger['launches'][-4:]:row['private_cleanup']=False
            ledger['launches'][-1]['pid']=None
        state={'schema':1,'phase':'blocked','active_cell':None,'cells':usedcells,'started_at':window['started_wall']}
        if origin==19:
            active=ledger['launches'][-1]['cell'];state['active_cell']={'id':active,'pid':11568,'run_id':uid('active-run'),'attempt_id':uid('active-attempt')}
        refs={k:m.add(v,k,path=str(Path(root)/leaf)) for k,v,leaf in (
            ('manifest',full,'manifest.json'),('state',state,'state.json'),('ledger',ledger,'launch-ledger/ledger.json'))}
        selectors.extend({'origin':origin,'kind':k,'original':ref} for k,ref in refs.items())
        candidate={'scope':'extracted_candidate','runner_sha256':'a'*64,'archive_sha256':'c'*64}
        candidate_ref=m.add(candidate,'candidate',path=root+'/candidate.json')
        event={'kind':'matrix','origin':origin,'root':root,**refs,'candidate':candidate_ref,'effective_limits':limits,'records':[
            ref for i,_,ref in allrecords if i==origin],'claims':[]}
        if origin>1:event['predecessor_origin']=7 if origin>=8 else origin-1
        if origin>=9:
            rule=r.HISTORICAL_POLICY[origin]
            binding=Path(rule['authorization']['path']).parent/('matrix-009-amendment' if origin==9 else f'matrix-{origin:03d}-successor')
            folder=Path(lineage[-1]['root']).parent/'campaign-successor-claims'
            name=launch._digest({'root':lineage[-1]['root'],'qualification_id':lineage[-1]['qualification_id']})
            fence={'schema':1,'document_type':'qualification_matrix_amendment_claim','amendment':policy['campaign_amendment'],
                'prior_root':lineage[-1]['root'],'prior_qualification_id':lineage[-1]['qualification_id'],'final_root':root}
            event['claims']=[m.add(fence,'claim',path=str(folder/(name+'.json'))),
                m.add(fence,'claim',path=str(folder/('amendment-'+rule['authorization_id']+'.json')))]
            cb={'schema':1,'amendment':policy['campaign_amendment'],'qualification_id':qid,'full_manifest':refs['manifest'],
                'candidate':candidate_ref,'launch_manifest_sha256':launch._digest(policy)}
            cr=m.add(cb,'claim',path=str(binding/'candidate-binding.json'));event['claims'].append(cr)
            event['claims'].append(m.add({'schema':1,'document_type':'qualification_matrix_amendment_launch_binding',
                'amendment':policy['campaign_amendment'],'qualification_id':qid,'manifest_sha256':launch._digest(policy),
                'ledger_root':root+'/launch-ledger','cumulative_attempts':attempts,'participant_segments':segments,
                'candidate_binding':cr},'claim',path=str(binding/'launch-binding.json')))
        elif origin==8:
            authref=m.add({'authorization_id':uid('boundary-auth'),'started_monotonic':window['started'],
                'started_wall':window['started_wall'],'deadline_monotonic':window['deadline'],'deadline_wall':window['deadline_wall']},'authority')
            binding={'base_predecessor':policy['predecessor'],'final_root':root,'root':'/synthetic/auxiliary','authorization':authref}
            br=m.add(binding);m.add({'binding':br},reference=boundary_ref);event['boundary_binding']=br
            folder=Path(base['root']).parent/'campaign-successor-claims';name=launch._digest({'root':base['root'],'qualification_id':base['qualification_id']})
            fence={'schema':1,'document_type':'qualification_campaign_boundary_fence','binding_sha256':launch._digest(binding),
                'auxiliary_root':binding['root'],'final_root':root,'authorization':authref,'base_predecessor':policy['predecessor']}
            event['claims']=[m.add(fence,'claim',path=str(folder/(name+'.json'))),m.add(fence,'claim',path=str(folder/('authorization-'+uid('boundary-auth')+'.json')))]
            cr=m.add({'schema':1,'boundary':boundary_ref,'qualification_id':qid,'full_manifest':refs['manifest'],'candidate':candidate_ref,
                'launch_manifest_sha256':launch._digest(policy)},'claim',path=binding['root']+'/candidate-binding.json');event['claims'].append(cr)
            event['claims'].append(m.add({'schema':1,'document_type':'qualification_boundary_final_binding','boundary':boundary_ref,
                'qualification_id':qid,'manifest_sha256':launch._digest(policy),'ledger_root':root+'/launch-ledger','base_attempts':51,
                'auxiliary_attempts':3,'cumulative_attempts':attempts,'candidate_binding':cr},'claim',path=binding['root']+'/final-binding.json'))
        elif origin>1:
            folder=Path(lineage[-1]['root']).parent/'campaign-successor-claims';name=launch._digest({'root':lineage[-1]['root'],'qualification_id':lineage[-1]['qualification_id']})
            event['claims']=[m.add({'schema':1,'document_type':'qualification_campaign_successor',
                'predecessor_qualification_id':lineage[-1]['qualification_id'],'predecessor_sha256':launch._digest(policy['predecessor']),
                'qualification_id':qid,'ledger_root':root+'/launch-ledger','manifest_sha256':launch._digest(policy)},'claim',path=str(folder/(name+'.json')))]
        names={}
        source_names=('original_endpoint_and_session_admission','original_frozen_input_bytes_and_compiled_bindings','original_source_and_candidate_gate')
        cleanup_names=('original_controller_and_owner_terminal_provenance','original_guest_and_owned_sensitive_file_cleanup','original_lineage_cleanup_proof_bindings')
        evidence[str(origin)]={}
        for label in source_names+cleanup_names:
            ev={'original_validator':{'path':'/synthetic/original-source.py','sha256':'d'*64,'callable':'verify'},'evidence':[initial_capture]}
            evidence[str(origin)][label]=ev
            names[label]=m.add({'predicate':label,'status':'PASS_SCOPED_RETAINED','scope':'original_terminal_evidence_only_not_current_global_clearance',
                'origin':origin,**refs,**ev},'retained-predicate')
        event['source_review']=m.add({'status':'PASS','unresolved_findings':[],'historical_source':source,'effective_limits':limits,
            'manifest':refs['manifest'],'origin':origin,'predecessor':full.get('predecessor'),
            'original_claim_family':'amendment' if origin>=9 else 'boundary' if origin==8 else 'linear' if origin>1 else 'initial',
            'host_admission':full['host_admission'],'frozen_input_inventory':full['files'],'retained_predicates':{k:names[k] for k in source_names}},'source-review')
        event['review']=m.add({'status':'PASS','unresolved_findings':[],'supports_original_historical_operational_invariants':True,**refs,
            'raw_state_and_failure_flags_preserved':True,'retained_predicates':{k:names[k] for k in cleanup_names}},'cleanup-review')
        events.append(event);attempts+=count;segments+=PARTICIPANTS[origin-1]
        lineage.append({'root':root,'qualification_id':qid,**{k+'_sha256':refs[k]['sha256'] for k in refs}})
        prior={'attempts':attempts,'participant_segments':segments,'qualification_id':qid,'planned_cells':origin*28,
            'lineage':copy.deepcopy(lineage),'prior_rows':[],**window,'daemon_capacity':ledger['daemon_capacity']}
        if origin==7:base=copy.deepcopy(lineage[-1]);base_carry=copy.deepcopy(prior)
        for diagnostic,(after,total) in r.AUXILIARY_STAGES.items():
            if after!=origin:continue
            intents=[]
            for n in range(total):
                role='image-recovery' if diagnostic=='image-recovery' else 'fixture' if diagnostic in ('fixture-startup','auxiliary-campaign') else 'application-helper'
                delegated=not(diagnostic=='D06' and n==5)
                identity=uid(diagnostic+'-'+str(n));provenance=m.add({'launch_id':identity,'role':role,
                    'canonical_intent_counted':True,'OS_delegate_returned':delegated})
                intents.append({'launch_id':identity,'role':role,'delegated':delegated,'source_reference':provenance})
            summary={'schema':1,'diagnostic':diagnostic,'canonical_container_intents':total,'participant_segments':0,
                'native_OS_delegates':sum(x['delegated'] for x in intents),'matrix_origins_added':0,'planned_matrix_rows_added':0,
                'intents':intents,'native_oracle_exercised':False}
            ref=m.add(summary);review=m.add({'status':'PASS','unresolved_findings':[],
                'supports_exact_auxiliary_intent_accounting':True,'summary':ref},'cleanup-review')
            events.append({'kind':'auxiliary','summary':ref,'review':review});attempts+=total
            auxiliary[diagnostic]={'summary':ref,'evidence':[initial_capture]}
    selected=[];selected_refs=[]
    for _,body,ref in allrecords[:255]:selected.append(body);selected_refs.append(ref)
    for n in range(26):
        body={'schema':1,'launch_id':uid('network-'+str(n)),'registry':registry,'generation':uid('network-generation'),
            'status':'released','kind':'network','container':'network-'+str(n),'image':None,'mounts':[],'runroot':None,'daemon':'fixture-daemon'}
        selected.append(body);selected_refs.append(m.add(body,'record'))
    observed={b['launch_id']:launch._digest(b) for b in selected}
    observation=m.add({'status':'PASS_METADATA_ONLY','selected_records':[{'launch_id':key,'canonical_body_sha256':digest,'status':'released'} for key,digest in observed.items()]})
    peer=m.add({'status':'PASS_METADATA_ONLY','subjects':{'verification':observation},'unresolved_findings':[],
        'supports_selected_record_metadata_and_known_guest_absence':True})
    for origin,body,ref in allrecords:
        snapshot=m.add({'document_type':'qualification_retained_released_record_snapshot','namespace':namespace,'capture':initial_capture,
            'records':{body['launch_id']:{'record':ref,'status':'released','canonical_body_sha256':launch._digest(body),
                **{k:body[k] for k in ('registry','generation','daemon')}}}})
        provenance=m.add({'status':'PASS_SCOPED_RELEASED_RECORD_SNAPSHOT','unresolved_findings':[],
            'supports_retained_released_record_bindings':True,'snapshot':snapshot,'namespace':namespace,
            'scope':'retained_at_capture_not_current_global_liveness','evidence':[initial_capture]})
        bindings.append({'origin':origin,'launch_id':body['launch_id'],'record':ref,'namespace':namespace,
            'snapshot':snapshot,'provenance':provenance,'capture':initial_capture})
        record_evidence[body['launch_id']]={'record':ref,'capture':initial_capture,'evidence':[initial_capture]}
    index={'schema':1,'document_type':'matrix20_operational_carry_index','entries':m.entries,'events':events,
        'record_observation':observation,'record_observation_review':peer,'canonical_record_sha256':observed,
        'selected_record_bodies':selected_refs,'historical_record_bindings':bindings}
    return m,index,{'selectors':{'count':57,'original_documents':selectors},'evidence':evidence,
        'auxiliary':auxiliary,'record_evidence':record_evidence,'raw_origin19':next(e['ledger'] for e in events if e.get('origin')==19)}


class Tests(unittest.TestCase):
    def setUp(self):
        for name in ('subprocess.Popen','subprocess.run','os.kill','socket.socket'):
            patch=mock.patch(name,side_effect=AssertionError('no native or PID effects'))
            patch.start();self.addCleanup(patch.stop)
    def test309_retained_rows_and281_selected_with26_nonmatrix_networks(self):
        memory,index,_=fixture()
        selected,bodies,bindings=replay.record_scopes(memory,index)
        self.assertEqual((len(selected),len(bindings)),(281,309))
        retained={key[1] for key in bindings}
        self.assertEqual(len(retained-set(selected)),54)
        self.assertEqual(len(set(selected)-retained),26)
    def test_later_attached_proof_accepts_same_immutable_intent(self):
        memory,index,_=fixture(changed_proof=True)
        self.assertEqual(len(replay.record_scopes(memory,index)[2]),309)
    def test_same_capture_requires_whole_canonical_equality(self):
        memory,index,_=fixture(changed_proof=True,same_capture=True)
        with self.assertRaises(launch.LaunchError):replay.record_scopes(memory,index)
    def test_changed_body_without_current_copied_identity_refuses(self):
        memory,index,_=fixture(changed_proof=True);index['selected_record_bodies']=[]
        with self.assertRaises(launch.LaunchError):replay.record_scopes(memory,index)
    def test_counter_map_cannot_replace_positive_namespace_snapshot(self):
        memory,index,_=fixture(); binding=index['historical_record_bindings'][0]
        value=memory.get(binding['snapshot'],'operational-projection');value['namespace']='/foreign/registry'
        binding['snapshot']=memory.add(value)
        with self.assertRaises(launch.LaunchError):replay.record_scopes(memory,index)
    def test_foreign_registry_or_unreleased_record_denied(self):
        for change in ({'registry':'e'*64},{'status':'absent'}):
            memory,index,_=fixture();item=index['historical_record_bindings'][0]
            body=memory.get(item['record'],'record');body.update(change);item['record']=memory.add(body,'record')
            with self.subTest(change=change),self.assertRaises(launch.LaunchError):replay.record_scopes(memory,index)
    def test_full19_real_kernel_309_matrix_plus25_auxiliary(self):
        memory,index,inputs=production_history()
        raw=memory.get(inputs['raw_origin19'],'ledger')
        before=launch._digest(raw)
        result=replay.replay(memory,index)
        self.assertEqual((result['attempts'],result['participant_segments'],result['planned_cells']),(334,21,532))
        self.assertEqual(len(result['lineage']),19)
        self.assertTrue(raw['poisoned'])
        self.assertEqual(sum(row['private_cleanup'] is False for row in raw['launches']),4)
        self.assertIsNone(raw['launches'][-1]['pid'])
        self.assertEqual(launch._digest(memory.get(inputs['raw_origin19'],'ledger')),before)

    def test_changed_current_CID_or_immutable_intent_denied(self):
        for change in ({'container_id':'e'*64},{'container':'foreign-container'}):
            memory,index,_=fixture(changed_proof=True)
            ref=index['selected_record_bodies'][0];body=memory.get(ref,'record');body.update(change)
            ref=memory.add(body,'record');index['selected_record_bodies'][0]=ref
            observation=memory.get(index['record_observation'],'operational-projection')
            observation['selected_records'][0]['canonical_body_sha256']=launch._digest(body)
            index['record_observation']=memory.add(observation)
            index['canonical_record_sha256'][body['launch_id']]=launch._digest(body)
            peer=memory.get(index['record_observation_review'],'operational-projection')
            peer['subjects']['verification']=index['record_observation'];index['record_observation_review']=memory.add(peer)
            with self.subTest(change=change),self.assertRaises(launch.LaunchError):replay.record_scopes(memory,index)
    def test_full19_missing_retained_binding_cannot_hide_behind281_map(self):
        memory,index,_=production_history();index['historical_record_bindings'].pop()
        with self.assertRaises(launch.LaunchError):replay.replay(memory,index)

    def test_full_original_Ledger_method_code_is_preserved(self):
        # The source035 fix changes record proof selection, not Kernel row/cap/
        # clock/resource validation or the original source function object.
        self.assertIn('launch.LaunchLedger._validate.__code__',__import__('inspect').getsource(replay.Kernel.ledger))


if __name__=='__main__':unittest.main(verbosity=2)
