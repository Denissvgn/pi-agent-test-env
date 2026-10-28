"""Prepared synthetic pure scoped-method controls; Root runs after entry review."""
import ast
import sys
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import types
import unittest
from unittest import mock

if __name__=='__main__':
    _old=signal.signal(signal.SIGALRM,lambda *_:os._exit(124))
    signal.setitimer(signal.ITIMER_REAL,30)
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'tools/qualification'))
from ast_compat import pinned_dump
SUBJECT_ROOT = HERE if (HERE/'application_scoped_retained_checks.py').is_file() else HERE.parent/'tools/qualification'
SOURCE=(SUBJECT_ROOT/'application_scoped_retained_checks.py').read_bytes()
HELPER_SHA='0daef9e6b7763d5a4cef6333d5a4cb7c07652e67f515339a3ead60ace9743f96'
UNCHANGED_DEFINITIONS_SHA='4f7e0f226468fa7ed8e3204ddb05946874eb66c3c21472e78f574610d0c92540'
ORIGINAL_REPLAY_AST_SHA='afe033e39d4d1b2ad9b50492f6adc7c48baa6e97a08ffd1fbb923e98f6fecf81'
if hashlib.sha256(SOURCE).hexdigest()!=HELPER_SHA:raise RuntimeError('source_changed')
NEW=(SUBJECT_ROOT/'application_operational_replay.py').read_bytes()


def normalize_reviewed_ast_renderer(node):
    """Undo only the exact serializer adaptation before the historical pin."""
    if node.name != 'matrix_cells':return node
    detached=copy.deepcopy(node)
    expected=ast.parse('need(hashlib.sha256(pinned_dump(fn).encode()).hexdigest()==MATRIX_AST_SHA256)').body[0]
    assert len(detached.body)>5 and pinned_dump(detached.body[5])==pinned_dump(expected)
    detached.body[5]=ast.parse('need(hashlib.sha256(ast.dump(fn,include_attributes=False).encode()).hexdigest()==MATRIX_AST_SHA256)').body[0]
    return detached


def forbidden(*a,**k):raise AssertionError('inert_IO_or_native_effect_forbidden')


@contextlib.contextmanager
def denied():
    with contextlib.ExitStack()as stack:
        for name in ('os.open','os.kill','os.system','subprocess.Popen','subprocess.run',
                     'socket.socket','socket.create_connection'):
            stack.enter_context(mock.patch(name,side_effect=forbidden))
        yield


with denied():
    S=types.ModuleType('scoped_retained_inert');S.__file__=str(SUBJECT_ROOT/'application_scoped_retained_checks.py')
    exec(compile(SOURCE,S.__file__,'exec'),S.__dict__)
    node=next(n for n in ast.parse(NEW).body if isinstance(n,ast.FunctionDef)and n.name=='retained_predicates')
    launch=types.SimpleNamespace(_sha=lambda v:S.need(type(v)is str and re.fullmatch('[a-f0-9]{64}',v)),
        _canonical_root=lambda v:S.need(type(v)is str and v.startswith('/')),
        _number=lambda v:S.need(type(v)in(int,float)and v==v and abs(v)!=float('inf')))
    NS={'need':S.need,'launch':launch,'scoped_checks':S}
    exec(compile(ast.Module(body=[node],type_ignores=[]),'<staged-retained-function>','exec'),NS)
    guards=ast.parse(NEW)
    names={'LATER_ABSENCE_SUBJECTS','RETAINED_UNCERTAIN_ROWS','HISTORICAL_POLICY'}
    nodes=[n for n in guards.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id in names for t in n.targets)]
    nodes+=[n for n in guards.body if isinstance(n,ast.FunctionDef)and n.name=='later_retained_physical_absence']
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<pure-later-absence-guard>','exec'),NS)



class Closure:
    def __init__(self):self.values={};self.reads=[]
    def put(self,ref,value,kind='operational-projection'):self.values[(ref['path'],ref['sha256'],kind)]=value
    def get(self,ref,kind):
        self.reads.append((ref['path'],ref['sha256'],kind))
        key=(ref['path'],ref['sha256'],kind)
        if key not in self.values:raise S.ScopedCoverageError('missing_classified_copy')
        return copy.deepcopy(self.values[key])


def fixture():
    c=Closure();event={'origin':19,'root':str(Path(S.SUBJECTS['manifest']['path']).parent),**copy.deepcopy(S.SUBJECTS)}
    rows=[{'launch_id':str(i),'container_id':f'{i:064x}','physical':'absent',
           'private_cleanup':i>=4,'pid':None if i==52 else 100+i}for i in range(53)]
    ledger={'launches':rows,'poisoned':True,'carry':{'attempts':275,'participant_segments':15}}
    c.put(S.SUBJECTS['ledger'],ledger,'ledger');c.put(S.SUBJECTS['state'],{'phase':'blocked'},'state')
    c.put(S.SUBJECTS['manifest'],{'prepared_root':event['root']},'manifest')
    cleanup={'status':'PASS','document_type':'qualification_scoped_final_file_cleanup',
        'scope':'task_scoped_file_hygiene_with_trusted_platform_readcache','cumulative_container_launches':328,
        'participant_segments':21,'real_model_participant_segments':0,'all274_task_records_released':True,
        'master019_copy_removed':True,'all_known_owned_file_contexts_closed':True,
        'all_known_private_roots_closed':True,'private_store_readers':0,
        'global_actor_terminal_status':'PENDING','individual_unknown_hostclient_wait_or_reap_confirmed':False,
        'all_credential_memory_erased_claimed':False,'census_complete':False,
        'safe_to_continue':False,'qualification_eligible':False,
        'raw_poison_private_flags_and_stale_active_preserved':True,
        'all_owned_container_ids':[r['container_id']for r in rows]}
    docs={'prior_cleanup':cleanup,'prior_cleanup_review':{'status':'PASS'},
        'prior_file_hygiene_review':{'status':'PASS'},
        'handoff':{'status':'NOT_READY','cumulative_container_intents':328},
        'R2':{'status':'PASS','unresolved_findings':[],'supports_actual_final_publication':True}}
    for k,ref in S.DOCS.items():c.put(ref,docs[k])
    receipt={'document_type':'qualification_public_source_and_historical_preservation_baseline',
        'status':'PASS','program':S.METHOD_SOURCE,
        'counter_baseline':{'container_intents':328,'scripted_participant_intents':21,'real_model_participants':0},
        'public_references':{**S.DOCS,**{'raw_'+k+'.json':v for k,v in S.SUBJECTS.items()}},
        'prior_global_actor_status':'PENDING','prior_inner_client_reap_or_memory_clearance_claimed':False,
        'prior_census_complete':False,'prior_raw_ledger_poisoned':True,'prior_raw_private_cleanup_false_count':4,
        'prior_scoped_task_records_released':274}
    c.put(S.BASELINE,receipt)
    c.put(S.ACTUAL_REVIEW,{'document_type':'independent_origin19_actual_scoped_main_result_review',
        'status':'PASS','unresolved_findings':[],'supports_actual_scoped_original19_file_checker_result':True,
        'supports_binding_actual_scoped_main_without_rename':True,
        'actual_scoped_method':{'source':S.METHOD_SOURCE,'callable':'main','published_check_receipt':S.BASELINE},
        'original19_subject_refs':S.SUBJECTS,'supports_original19_legacy_own_cleanup_validator_execution':False,
        'supports_original19_all_controller_POSIX_waits':False,'supports_original19_global_RAM_or_census_clearance':False,
        'supports_native_or_old_scope_resume':False})
    c.put(S.CAPABILITY,{'status':'PASS','launch_id':'52','immutable_container_id_from_ledger':rows[-1]['container_id'],
        'fixed_builtin_docker_run':True,'host_file_output_or_envfile_options_present':False,'close_fds_default_true':True,
        'pass_fds_or_shell_or_executable_override_in_source':False,'inherited_environment_may_have_credentials':True,
        'individual_hostclient_wait_or_reap_attested':False,'hostclient_terminal_confirmed':False})
    c.put(S.CAPABILITY_REVIEW,{'status':'PASS','unresolved_findings':[],
        'supports_host_file_writer_capability_analysis':True,'supports_selected_file_writer_scope_input':True,
        'host_file_writer_capability':S.CAPABILITY,'source_owner_assessment':S.OWNER})
    c.put(S.OWNER,{'status':'PASS','unresolved_findings':[],'source_owner_terminal_chain_reviewed':True,
        'unresolved_inner_hostclient':{'launch_id':'52','individual_wait_or_reap_confirmed':False,'hostclient_terminal_confirmed':False}})
    return c,event


def proof(c,event,name):
    computed=S.evaluate(c,event,name)
    return {'predicate':name,'status':'PASS_SCOPED_RETAINED',
        'scope':'original_terminal_evidence_only_not_current_global_clearance',
        'origin':19,**copy.deepcopy(S.SUBJECTS),'original_validator':copy.deepcopy(S.METHOD_OBJECT),
        'evidence':computed['evidence']}


class Checks(unittest.TestCase):
    def test_serializer_adaptation_normalizes_only_its_exact_reviewed_guard(self):
        original=next(n for n in ast.parse(NEW).body if isinstance(n,ast.FunctionDef)and n.name=='matrix_cells')
        before=pinned_dump(original)
        normalized=normalize_reviewed_ast_renderer(original)
        self.assertEqual(pinned_dump(original),before)
        self.assertIn('ast.dump',ast.unparse(normalized.body[5]))
        for statement in ('need(True)', 'need(hashlib.sha256(pinned_dump(fn).encode()).hexdigest()!=MATRIX_AST_SHA256)'):
            changed=copy.deepcopy(original);changed.body[5]=ast.parse(statement).body[0]
            with self.subTest(statement=statement),self.assertRaises(AssertionError):normalize_reviewed_ast_renderer(changed)

    def setUp(self):self.guard=denied();self.guard.__enter__();self.addCleanup(self.guard.__exit__,None,None,None)

    def test_complete_scoped_metadata_branch_preserves_false_unknowns(self):
        c,e=fixture();name=S.NAMES[0];p=proof(c,e,name)
        r={'path':'/synthetic/retained.json','sha256':'f'*64};c.put(r,p,'retained-predicate')
        NS['retained_predicates'](c,{'retained_predicates':{name:r}},e,(name,))
        self.assertFalse(p['original_validator']['legacy_original_cleanup_execution_claimed'])

    def test_both_names_accept_same_exact_scoped_method_without_legacy_rename(self):
        for name in S.NAMES:
            c,e=fixture();S.validate(c,e,name,proof(c,e,name))
        self.assertEqual(S.METHOD_OBJECT['callable'],'main')

    def test_wrong_origin_type_or_predicate_denies_before_copy_read(self):
        for origin,name in [(18,S.NAMES[0]),(19.0,S.NAMES[0]),(True,S.NAMES[0]),(19,'original_source_and_candidate_gate')]:
            c,e=fixture();e['origin']=origin
            with self.assertRaises(S.ScopedCoverageError):S.evaluate(c,e,name)
            self.assertEqual(c.reads,[])

    def test_wrong_source_receipt_or_coverage_kind_cannot_promote(self):
        for key,value in [('callable','verify'),('sha256','0'*64),('scope','global'),('legacy_original_cleanup_execution_claimed',True)]:
            c,e=fixture();p=proof(c,e,S.NAMES[0]);p['original_validator'][key]=value
            with self.assertRaises(S.ScopedCoverageError):S.validate(c,e,S.NAMES[0],p)

    def test_missing_required_copy_and_owner_review_refuse(self):
        for ref in [S.ACTUAL_REVIEW,S.OWNER,S.CAPABILITY_REVIEW,S.DOCS['prior_cleanup']]:
            c,e=fixture();del c.values[(ref['path'],ref['sha256'],'operational-projection')]
            with self.assertRaises(S.ScopedCoverageError):S.evaluate(c,e,S.NAMES[0])

    def test_no_master_or_uncovered_CID_or_source_owner_is_denied(self):
        for ref,key,value in [(S.DOCS['prior_cleanup'],'master019_copy_removed',False),
            (S.DOCS['prior_cleanup'],'all_owned_container_ids',[]),(S.OWNER,'source_owner_terminal_chain_reviewed',False),
            (S.CAPABILITY,'host_file_output_or_envfile_options_present',True)]:
            c,e=fixture();c.values[(ref['path'],ref['sha256'],'operational-projection')][key]=value
            with self.assertRaises(S.ScopedCoverageError):S.evaluate(c,e,S.NAMES[0])

    def test_old_global_wait_memory_or_census_promotion_is_denied(self):
        for key,value in [('global_actor_terminal_status','PASS'),('individual_unknown_hostclient_wait_or_reap_confirmed',True),
                          ('all_credential_memory_erased_claimed',True),('census_complete',True)]:
            c,e=fixture();c.values[(S.DOCS['prior_cleanup']['path'],S.DOCS['prior_cleanup']['sha256'],'operational-projection')][key]=value
            with self.assertRaises(S.ScopedCoverageError):S.evaluate(c,e,S.NAMES[0])

    def test_evidence_omission_and_subject_drift_refuse(self):
        c,e=fixture();p=proof(c,e,S.NAMES[0]);p['evidence']=[]
        with self.assertRaises(S.ScopedCoverageError):S.validate(c,e,S.NAMES[0],p)
        e['ledger']={'path':e['ledger']['path'],'sha256':'0'*64}
        with self.assertRaises(S.ScopedCoverageError):S.evaluate(c,e,S.NAMES[0])

    def test_legacy_seven_names_and_kernel_functions_remain_original(self):
        newtree=ast.parse(NEW)
        expected_guard=ast.parse("need(type(value) is dict and 'retained_requalification' not in value and 'browser_followup' not in value and 'browser_fixture_followup' not in value and 'settlement_diagnostic' not in value)").body[0]
        def without_exact_retained_guard(tree):
            # Accept exactly the independently reviewed early rejection. All of
            # Kernel's original code remains under the unchanged fingerprint.
            normalized=copy.deepcopy(tree)
            kernels=[n for n in normalized.body if isinstance(n,ast.ClassDef)and n.name=='Kernel']
            self.assertEqual(len(kernels),1)
            manifests=[n for n in kernels[0].body if isinstance(n,ast.FunctionDef)and n.name=='manifest']
            self.assertEqual(len(manifests),1)
            body=manifests[0].body
            self.assertTrue(body)
            self.assertEqual(pinned_dump(body[0]),
                             pinned_dump(expected_guard))
            del body[0]
            return normalized
        normalized=without_exact_retained_guard(newtree)
        # A missing, weakened or late guard must fail normalization rather than
        # being silently removed or accommodated by a new expected fingerprint.
        for fault in ('missing','weakened','late'):
            mutant=copy.deepcopy(newtree)
            kernel=next(n for n in mutant.body if isinstance(n,ast.ClassDef)and n.name=='Kernel')
            manifest=next(n for n in kernel.body if isinstance(n,ast.FunctionDef)and n.name=='manifest')
            if fault=='missing':del manifest.body[0]
            elif fault=='weakened':manifest.body[0]=ast.parse('need(type(value) is dict)').body[0]
            else:manifest.body.append(manifest.body.pop(0))
            with self.subTest(guard_fault=fault),self.assertRaises(AssertionError):
                without_exact_retained_guard(mutant)
        def defs(tree):return {n.name:pinned_dump(normalize_reviewed_ast_renderer(n))for n in tree.body
            if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name not in ('retained_predicates','replay','later_retained_physical_absence')}
        fingerprint=hashlib.sha256(json.dumps(defs(normalized),sort_keys=True,separators=(',',':')).encode()).hexdigest()
        self.assertEqual(fingerprint,UNCHANGED_DEFINITIONS_SHA)
        replay=next(n for n in newtree.body if isinstance(n,ast.FunctionDef)and n.name=='replay')
        altered=0
        for node in ast.walk(replay):
            for attr,value in ast.iter_fields(node):
                if not isinstance(value,list):continue
                for i,statement in enumerate(list(value)):
                    if isinstance(statement,ast.If)and ast.unparse(statement.test)=="row['physical'] != 'absent'":
                        self.assertEqual(ast.unparse(statement.body[0]),'later_retained_physical_absence(closure, index, event, row)')
                        self.assertEqual(ast.unparse(value[i-1]),"need(row['container_id'] is not None)")
                        value[i-1:i+1]=ast.parse("need(row['physical'] == 'absent' and row['container_id'] is not None)").body
                        altered+=1
        self.assertEqual(altered,1)
        self.assertEqual(hashlib.sha256(pinned_dump(replay).encode()).hexdigest(),ORIGINAL_REPLAY_AST_SHA)

        allowed=('validate_predecessor','_validate_first_predecessor','_native_prior','_current_cleanup',
                 '_replay_prior','verify','validate_qualification_preworker_cleanup')
        for name in allowed:
            c=Closure();ref={'path':'/synthetic/legacy.json','sha256':'a'*64}
            p={'predicate':'x','status':'PASS_SCOPED_RETAINED','scope':'original_terminal_evidence_only_not_current_global_clearance',
               'origin':1,'manifest':{},'state':{},'ledger':{},'original_validator':{'path':'/synthetic/source.py','sha256':'b'*64,'callable':name},
               'evidence':[{'path':'/synthetic/evidence.json','sha256':'c'*64}]}
            c.put(ref,p,'retained-predicate');c.put(p['evidence'][0],{})
            NS['retained_predicates'](c,{'retained_predicates':{'x':ref}},{'origin':1,'manifest':{},'state':{},'ledger':{}},('x',))




class LaterAbsenceTests(unittest.TestCase):
    def basis(self):
        c=Closure();subjects=NS['LATER_ABSENCE_SUBJECTS'];table=NS['RETAINED_UNCERTAIN_ROWS']
        events=[]
        for fixed in table:
            if not any(e['origin']==fixed['origin']for e in events):events.append({'kind':'matrix','origin':fixed['origin'],'ledger':copy.deepcopy(fixed['ledger'])})
        prior={'kind':'matrix','origin':18,**{k:copy.deepcopy(subjects[k])for k in ('manifest','state','ledger')}}
        incoming={'kind':'matrix','origin':19,**copy.deepcopy(S.SUBJECTS)};events.extend([prior,incoming])
        for event in events:
            if event['origin']not in(18,19):
                rows=[{**{k:fixed[k]for k in ('launch_id','role','container_id')},'physical':'uncertain','private_cleanup':False}
                    for fixed in table if fixed['origin']==event['origin']]
                c.put(event['ledger'],{'daemon':'same-retained-daemon','poisoned':True,'last_wall':10.,'launches':rows},'ledger')
        c.put(prior['ledger'],{'daemon':'same-retained-daemon','last_wall':20.},'ledger')
        rule=NS['HISTORICAL_POLICY'][19]
        c.put(prior['manifest'],{'qualification_id':'retained18'},'manifest')
        c.put(incoming['manifest'],{'campaign_amendment':rule['authorization'],'source':{'files':{rule['source_path']:rule['source_sha256']}}},'manifest')
        ids=[x['container_id']for x in table]+[f'{i:064x}'for i in range(259)]
        cleanup={'document_type':'qualification_final_cleanup_and_safe_handoff','status':'PASS','qualification_id':'retained18',
            'raw_ledger':prior['ledger'],'raw_state':prior['state'],'cumulative_container_launches':274,'participant_segments':15,
            'real_model_participant_segments':0,'all_owned_container_ids_absent':True,'all_known_container_ids_and_names_absent':True,
            'raw_poisoned_true_preserved':True,'raw_private_cleanup_false_preserved':True,'all_owned_container_ids':ids,
            'actual_immutable_container_id_count':266,'live_owned_containers':0,'safe_to_continue':False,'qualification_eligible':False}
        c.put(subjects['cleanup'],cleanup)
        c.put(subjects['cleanup_review'],{'status':'PASS','unresolved_findings':[],'supports_final_handoff':True,'final_cleanup':subjects['cleanup']})
        return c,{'events':events}
    def run_row(self,c,index,fixed=None):
        fixed=fixed or NS['RETAINED_UNCERTAIN_ROWS'][0]
        e=next(x for x in index['events']if x['origin']==fixed['origin'])
        row={k:copy.deepcopy(fixed[k])for k in ('launch_id','role','container_id')}
        row.update(physical='uncertain',private_cleanup=False)
        before=copy.deepcopy((index,row,c.values))
        result=NS['later_retained_physical_absence'](c,index,e,row)
        self.assertEqual((index,row,c.values),before)
        return result
    def test_all_seven_later_absence_preserves_raw_flags(self):
        with denied():
            for fixed in NS['RETAINED_UNCERTAIN_ROWS']:
                c,i=self.basis();self.assertTrue(self.run_row(c,i,fixed))
    def test_missing_proof_or_unreviewed_absence_denied(self):
        for target in ('cleanup','cleanup_review'):
            c,i=self.basis();ref=NS['LATER_ABSENCE_SUBJECTS'][target];del c.values[(ref['path'],ref['sha256'],'operational-projection')]
            with denied(),self.assertRaises(S.ScopedCoverageError):self.run_row(c,i)
        for key in ('all_owned_container_ids_absent','all_known_container_ids_and_names_absent'):
            c,i=self.basis();ref=NS['LATER_ABSENCE_SUBJECTS']['cleanup'];c.values[(ref['path'],ref['sha256'],'operational-projection')][key]=False
            with denied(),self.assertRaises(S.ScopedCoverageError):self.run_row(c,i)
    def test_wrong_cid_or_uncovered_cid_denied(self):
        c,i=self.basis();fixed=copy.deepcopy(NS['RETAINED_UNCERTAIN_ROWS'][0]);fixed['container_id']='f'*64
        with denied(),self.assertRaises(S.ScopedCoverageError):self.run_row(c,i,fixed)
        c,i=self.basis();ref=NS['LATER_ABSENCE_SUBJECTS']['cleanup'];body=c.values[(ref['path'],ref['sha256'],'operational-projection')]
        body['all_owned_container_ids'][0]='f'*64
        with denied(),self.assertRaises(S.ScopedCoverageError):self.run_row(c,i)
    def test_wrong_raw_ledger_or_incoming_source_denied(self):
        c,i=self.basis();i['events'][0]['ledger']={'path':'/wrong','sha256':'0'*64}
        with denied(),self.assertRaises(S.ScopedCoverageError):self.run_row(c,i)
        c,i=self.basis();ref=S.SUBJECTS['manifest'];c.values[(ref['path'],ref['sha256'],'manifest')]['source']['files'].clear()
        with denied(),self.assertRaises((S.ScopedCoverageError,KeyError)):self.run_row(c,i)
    def test_unknown_row_and_wrong_phase_deny_before_proof_read(self):
        for mutation in ('launch_id','physical'):
            c,i=self.basis();fixed=NS['RETAINED_UNCERTAIN_ROWS'][0];e=i['events'][0]
            row={k:fixed[k]for k in ('launch_id','role','container_id')};row.update(physical='uncertain',private_cleanup=False)
            row[mutation]='unknown'
            with denied(),self.assertRaises(S.ScopedCoverageError):NS['later_retained_physical_absence'](c,i,e,row)
            self.assertEqual(c.reads,[])


    def test_cross_daemon_or_nonlater_witness_denied(self):
        for key,value in [('daemon','another-daemon'),('last_wall',10.),('last_wall',True)]:
            c,i=self.basis();ref=NS['LATER_ABSENCE_SUBJECTS']['ledger']
            c.values[(ref['path'],ref['sha256'],'ledger')][key]=value
            with denied(),self.assertRaises(S.ScopedCoverageError):self.run_row(c,i)

if __name__=='__main__':
    try:unittest.main(verbosity=2)
    finally:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,_old)
