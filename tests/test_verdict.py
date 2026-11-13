"""Verdict, usage summary and run-wide budgets of the run record; synthetic records and mocked stages only."""
import ast
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT=(Path(__file__).resolve().parents[1] / 'skill')
sys.path.insert(0,str(ROOT/'scripts'))
import pi_lab as lab
import outcomes
import stage_control as controls
from usage_contract import summarize

# The decided closed lists, written out here so a change to the code's lists fails a test.
OUTCOMES=['pass','pass_recovered','pass_assisted','check_failed','agent_incomplete','protected_input_changed',
          'turn_limit','token_limit','repeated_tool_call','agent_timeout','log_limit','out_of_memory',
          'endpoint_unreachable','endpoint_auth_failed','endpoint_error','setup_failed','blocked',
          'infrastructure_fault','cancelled']
ATTRIBUTION={'pass':{'none'},'pass_recovered':{'none'},'pass_assisted':{'none'},
    'check_failed':{'model'},'agent_incomplete':{'model'},'protected_input_changed':{'model'},'turn_limit':{'model'},
    'token_limit':{'model'},'repeated_tool_call':{'model'},'agent_timeout':{'model'},'log_limit':{'model'},
    'endpoint_unreachable':{'endpoint'},'endpoint_auth_failed':{'endpoint'},'endpoint_error':{'endpoint'},
    'setup_failed':{'configuration'},'out_of_memory':{'configuration'},'blocked':{'configuration','infrastructure'},
    'infrastructure_fault':{'infrastructure'},'cancelled':{'operator'}}
PHASES=['admission','image','preflight','setup','agent','check','cleanup']
UNVERIFIED={'agent_invocation_verified':False,'completion_verified':False,'invocation_status':'invalid','errors':['fixture']}


def agent(name='dev',index=1,**process):
    base={'exit_code':0,'started':True,'cleanup_confirmed':True,'termination_reason':'completed',
          'evidence':{'agent_invocation_verified':True,'completion_verified':True,'invocation_status':'verified','errors':[]}}
    base.update(process)
    return {'name':name,'logs':f'agent-{index}-{name}','process':base,'invocation_verified':base['evidence']['agent_invocation_verified'],'errors':[]}


def check(name='oracle',index=1,task='pass',status='completed',reason=None,**process):
    base={'exit_code':0,'started':True,'cleanup_confirmed':True,'termination_reason':'completed'};base.update(process)
    return {'name':name,'logs':f'check-{index}-{name}','process':base,
            'scorer':{'schema':1,'scorer_id':'command-only','status':status,'reason':reason,'task_status':task,
                      'score':None,'test_counts':None,'assertions':None}}


def record(**sections):
    """A clean pass with one agent and one check, then the given sections on top; status is derived."""
    value=outcomes.initial()
    value['infrastructure'].update(status='ready',phase='agents')
    value['invocation'].update(status='verified',attempted_stages=1)
    value['termination'].update(reason='completed',process_exit_code=0)
    value['scoring'].update(status='completed');value['task_result'].update(status='pass')
    value['protected_inputs']['status']='unchanged'
    value['agents']=[agent()];value['checks']=[check()]
    for name,update in sections.items():
        if isinstance(value.get(name),dict) and isinstance(update,dict):value[name].update(update)
        else:value[name]=update
    value['status'],value['exit_code']=outcomes.status(value)
    return value


def blocked(phase,reason,**sections):
    base={'infrastructure':{'status':'failed','phase':phase,'reason':reason},
          'invocation':{'status':'not_started','attempted_stages':0},
          'termination':{'reason':'not_started','process_exit_code':None},
          'scoring':{'status':'skipped','reason':'infrastructure_failure'},
          'task_result':{'status':'unknown'},'protected_inputs':{'status':'unknown'},'agents':[],'checks':[]}
    base.update(sections)
    return record(**base)


def stopped(reason,code=1,**process):
    """An agent stage whose process ended for `reason` without a verified completion."""
    return {'invocation':{'status':'invalid'},'termination':{'reason':reason,'process_exit_code':code},
            'agents':[agent(termination_reason=reason,exit_code=code,evidence=dict(UNVERIFIED),**process)]}


def ran(*rows):return {'schema':1,'stages':[{'stage':stage,'kind':kind,'wall_seconds':1.0} for stage,kind in rows]}


def provider(stops,allowed=0,attempts=0):
    return [{'segment_id':'s1','evidence':{'unsuccessful_messages':stops,
             'provider_retries':{'allowed':allowed,'attempts':attempts,'retried_errors':[]}}}]


FAILING_CHECK={'task_result':{'status':'fail'},'checks':[check(task='fail',exit_code=1)]}
SCORER_ERROR={'scoring':{'status':'error','reason':'scorer_error'},'task_result':{'status':'unknown'},
              'checks':[check(status='error',reason='scorer_nonzero_exit',task='unknown',exit_code=1)]}
UNCONFIRMED={'invocation':{'status':'invalid'},'termination':{'reason':'cleanup_error','trigger':'completed','process_exit_code':2},
             'scoring':{'status':'skipped','reason':'cleanup_unconfirmed'},'task_result':{'status':'unknown'},
             'protected_inputs':{'status':'unknown'},'checks':[],
             'agents':[agent(cleanup_confirmed=False,termination_reason='cleanup_error',termination_trigger='completed',exit_code=2,evidence=dict(UNVERIFIED))]}
CANCELLED={'invocation':{'status':'invalid'},'termination':{'reason':'cancelled','process_exit_code':130},
           'scoring':{'status':'skipped','reason':'user_cancelled'},'task_result':{'status':'unknown'},'agents':[],'checks':[]}

# name, record, outcome, attribution, phase, stage, reason
FIXTURES=[
    ('pass',record(),'pass','none',None,None,'completed'),
    ('pass_recovered',record(invocation={'status':'recovered'}),'pass_recovered','none',None,None,'completed'),
    ('pass_assisted',record(assistance={'status':'assisted','intervention_ids':['steer-1']}),'pass_assisted','none',None,None,'completed'),
    ('check_failed',record(**FAILING_CHECK),'check_failed','model','check','check-1-oracle','task_fail'),
    ('check_partial',record(task_result={'status':'partial'},checks=[check(task='partial')]),'check_failed','model','check','check-1-oracle','task_partial'),
    ('agent_incomplete',record(**stopped('process_error')),'agent_incomplete','model','agent','agent-1-dev','process_error'),
    ('agent_incomplete_trace',record(invocation={'status':'invalid'},agents=[agent(evidence=dict(UNVERIFIED))]),'agent_incomplete','model','agent','agent-1-dev','completed'),
    ('protected_input_changed',record(protected_inputs={'status':'changed'}),'protected_input_changed','model','agent','agent-1-dev','protected_inputs_changed'),
    ('turn_limit',record(**stopped('turn_limit',124)),'turn_limit','model','agent','agent-1-dev','turn_limit'),
    ('token_limit',record(**stopped('token_limit',124)),'token_limit','model','agent','agent-1-dev','token_limit'),
    ('repeated_tool_call',record(**stopped('repeated_tool_call',124)),'repeated_tool_call','model','agent','agent-1-dev','repeated_tool_call'),
    ('agent_timeout',record(**stopped('timeout',124,timed_out=True)),'agent_timeout','model','agent','agent-1-dev','timeout'),
    ('log_limit',record(**stopped('log_limit',2,log_limit_exceeded=True)),'log_limit','model','agent','agent-1-dev','log_limit'),
    ('out_of_memory',record(**stopped('oom',137,container_state={'ExitCode':137,'OOMKilled':True,'Error':''})),'out_of_memory','configuration','agent','agent-1-dev','oom'),
    ('out_of_memory_check',record(task_result={'status':'fail'},checks=[check(task='fail',exit_code=137,termination_reason='oom')]),'out_of_memory','configuration','check','check-1-oracle','oom'),
    ('endpoint_unreachable',blocked('preflight','endpoint-unreachable'),'endpoint_unreachable','endpoint','preflight',None,'endpoint-unreachable'),
    ('endpoint_auth_failed',blocked('preflight','endpoint-auth-failed'),'endpoint_auth_failed','endpoint','preflight',None,'endpoint-auth-failed'),
    ('endpoint_error_preflight',blocked('preflight','LabError',termination={'reason':'process_error','process_exit_code':1},
        usage_summary=ran(('boundary','preflight'),('preflight','preflight'))),'endpoint_error','endpoint','preflight','preflight','process_error'),
    ('endpoint_error_agent',record(**stopped('process_error',segments=provider(['error']))),'endpoint_error','endpoint','agent','agent-1-dev','process_error'),
    ('endpoint_error_retries_exhausted',record(**stopped('process_error',segments=provider(['error','error','error'],2,2))),'endpoint_error','endpoint','agent','agent-1-dev','process_error'),
    ('setup_failed',blocked('setup','LabError',termination={'reason':'process_error','process_exit_code':1},
        usage_summary=ran(('boundary','preflight'),('preflight','preflight'),('setup-1-prepare','setup'))),'setup_failed','configuration','setup','setup-1-prepare','process_error'),
    ('blocked_configuration',blocked('secret','missing-secret'),'blocked','configuration','admission',None,'missing-secret'),
    ('blocked_validation',blocked('secret','LabError'),'blocked','configuration','admission',None,'LabError'),
    ('blocked_infrastructure',blocked('host','docker-daemon-unavailable'),'blocked','infrastructure','admission',None,'docker-daemon-unavailable'),
    ('blocked_lock',blocked('admission','host-admission-busy'),'blocked','infrastructure','admission',None,'host-admission-busy'),
    ('blocked_image',blocked('image','unsupported-pi-release'),'blocked','configuration','image',None,'unsupported-pi-release'),
    ('blocked_unknown_reason',blocked('host','PermissionError'),'blocked','infrastructure','admission',None,'PermissionError'),
    ('blocked_probe',blocked('preflight','LabError',termination={'reason':'process_error','process_exit_code':1},
        usage_summary=ran(('boundary','preflight'))),'blocked','configuration','preflight','boundary','LabError'),
    ('infrastructure_fault_cleanup',record(**UNCONFIRMED),'infrastructure_fault','infrastructure','cleanup','agent-1-dev','cleanup_error'),
    ('infrastructure_fault_scorer',record(**SCORER_ERROR),'infrastructure_fault','infrastructure','check','check-1-oracle','scorer_nonzero_exit'),
    ('infrastructure_fault_check_launch',record(scoring={'status':'error','reason':'scorer_error'},task_result={'status':'unknown'},
        checks=[{**check(status='error',reason='cleanup_unconfirmed',task='unknown'),'process':{'exit_code':2,'cleanup_confirmed':False}}]),
        'infrastructure_fault','infrastructure','check','check-1-oracle','check_not_started'),
    ('infrastructure_fault_snapshot',record(scoring={'status':'skipped','reason':'workspace_snapshot_failed'},task_result={'status':'unknown'},checks=[]),
        'infrastructure_fault','infrastructure','check',None,'workspace_snapshot_failed'),
    ('infrastructure_fault_controller',record(infrastructure={'status':'failed','reason':'controller_lost'},invocation={'status':'invalid'},
        termination={'reason':'process_error','trigger':'controller_lost'},scoring={'status':'skipped','reason':'controller_lost'},
        task_result={'status':'unknown'},agents=[],checks=[],controller_interruption={'kind':'controller_lost'}),
        'infrastructure_fault','infrastructure','agent',None,'controller_lost'),
    ('infrastructure_fault_runner',record(infrastructure={'status':'failed','reason':'OSError'},invocation={'status':'invalid'},
        scoring={'status':'skipped','reason':'infrastructure_failure'},task_result={'status':'unknown'},agents=[],checks=[]),
        'infrastructure_fault','infrastructure','agent',None,'OSError'),
    ('infrastructure_fault_supervisor',record(invocation={'status':'invalid'},termination={'reason':'process_error','process_exit_code':2},
        agents=[agent(exit_code=2,termination_reason='process_error',observation_error=True,evidence=dict(UNVERIFIED))]),
        'infrastructure_fault','infrastructure','agent','agent-1-dev','observation_error'),
    ('cancelled',record(**CANCELLED),'cancelled','operator','agent',None,'cancelled'),
    ('cancelled_scoring',record(termination={'reason':'cancelled'},scoring={'status':'cancelled','reason':'user_cancelled'},task_result={'status':'unknown'},checks=[]),
        'cancelled','operator','check',None,'cancelled'),
    ('cancelled_before_launch',blocked('image',None,infrastructure={'status':'not_started','phase':'image','reason':None},
        termination={'reason':'cancelled','process_exit_code':None},scoring={'status':'skipped','reason':'user_cancelled'}),
        'cancelled','operator','image',None,'cancelled'),
]

# A record that matches two rows gets the earlier one:
# name, record matching both rows, earlier outcome, its phase, record matching the later row only, later outcome.
TURN_LIMIT=stopped('turn_limit',124)
PROVIDER_ERROR=stopped('process_error',segments=provider(['error']))
PRECEDENCE=[
    ('cancelled over blocked',blocked('secret','missing-secret',termination={'reason':'cancelled','process_exit_code':None}),'cancelled','admission',
        blocked('secret','missing-secret'),'blocked'),
    ('cancelled over cleanup',record(**{**UNCONFIRMED,'termination':{'reason':'cancelled','trigger':'cleanup_error','process_exit_code':130}}),'cancelled','agent',
        record(**UNCONFIRMED),'infrastructure_fault'),
    ('cleanup over endpoint',record(**{**UNCONFIRMED,'agents':[agent(cleanup_confirmed=False,termination_reason='cleanup_error',termination_trigger='process_error',
        exit_code=2,evidence=dict(UNVERIFIED),segments=provider(['error']))]}),'infrastructure_fault','cleanup',
        record(**PROVIDER_ERROR),'endpoint_error'),
    ('cleanup over turn limit',record(**{**UNCONFIRMED,'termination':{'reason':'cleanup_error','trigger':'turn_limit','process_exit_code':2}}),'infrastructure_fault','cleanup',
        record(**TURN_LIMIT),'turn_limit'),
    ('endpoint over scorer error',record(**{**PROVIDER_ERROR,**SCORER_ERROR}),'endpoint_error','agent',
        record(**SCORER_ERROR),'infrastructure_fault'),
    ('endpoint over turn limit',record(**stopped('turn_limit',124,segments=provider(['error']))),'endpoint_error','agent',
        record(**TURN_LIMIT),'turn_limit'),
    ('scorer error over turn limit',record(**{**TURN_LIMIT,**SCORER_ERROR}),'infrastructure_fault','check',
        record(**TURN_LIMIT),'turn_limit'),
    ('setup failure over memory',blocked('setup','LabError',termination={'reason':'oom','process_exit_code':137},
        usage_summary=ran(('setup-1-prepare','setup'))),'setup_failed','setup',
        record(**stopped('oom',137,container_state={'OOMKilled':True})),'out_of_memory'),
    ('memory over turn limit',record(**stopped('turn_limit',124,container_state={'OOMKilled':True})),'out_of_memory','agent',
        record(**TURN_LIMIT),'turn_limit'),
    ('turn limit over protected inputs',record(**{**TURN_LIMIT,'protected_inputs':{'status':'changed'}}),'turn_limit','agent',
        record(protected_inputs={'status':'changed'}),'protected_input_changed'),
    ('turn limit over failing check',record(**{**TURN_LIMIT,**FAILING_CHECK}),'turn_limit','agent',
        record(**FAILING_CHECK),'check_failed'),
    ('protected inputs over incomplete agent',record(**{**stopped('process_error'),'protected_inputs':{'status':'changed'}}),'protected_input_changed','agent',
        record(**stopped('process_error')),'agent_incomplete'),
    ('incomplete agent over failing check',record(**{**stopped('process_error'),**FAILING_CHECK}),'agent_incomplete','agent',
        record(**FAILING_CHECK),'check_failed'),
]


class VerdictTableTests(unittest.TestCase):
    def test_closed_lists_are_the_decided_ones(self):
        self.assertEqual(list(outcomes.VERDICT_OUTCOMES),OUTCOMES)
        self.assertEqual(list(outcomes.VERDICT_PHASES),PHASES)
        self.assertEqual(set(outcomes.VERDICT_ATTRIBUTIONS),{'none','model','endpoint','configuration','infrastructure','operator'})
        self.assertEqual({name:{value} for name,value in outcomes.OUTCOME_ATTRIBUTION.items()},
                         {name:value for name,value in ATTRIBUTION.items() if name!='blocked'})

    def test_one_fixture_per_outcome_has_the_decided_outcome_attribution_and_phase(self):
        for name,value,outcome,attribution,phase,stage,reason in FIXTURES:
            with self.subTest(fixture=name):
                result=outcomes.verdict(value)
                self.assertEqual(set(result),{'schema','outcome','attribution','phase','stage','reason','exit_code'})
                self.assertEqual((result['schema'],result['outcome'],result['attribution'],result['phase']),(1,outcome,attribution,phase))
                self.assertEqual((result['stage'],result['reason']),(stage,reason))
                self.assertEqual(result['exit_code'],value['exit_code'])
                self.assertIn(result['attribution'],ATTRIBUTION[result['outcome']])
                self.assertIn(result['phase'],[None,*PHASES])
                self.assertEqual(result['phase'] is None,outcome.startswith('pass'))
        self.assertEqual({row[2] for row in FIXTURES},set(OUTCOMES))

    def test_a_record_matching_two_rows_gets_the_earlier_one(self):
        self.assertGreaterEqual(len(PRECEDENCE),4)
        for name,value,outcome,phase,alone,later in PRECEDENCE:
            with self.subTest(precedence=name):
                result=outcomes.verdict(value)
                self.assertEqual((result['outcome'],result['phase']),(outcome,phase))
                self.assertEqual(outcomes.verdict(alone)['outcome'],later)

    def test_status_and_exit_code_are_not_changed_by_the_derivation(self):
        expected={'pass':('PASS',0),'pass_recovered':('RECOVERED',1),'pass_assisted':('ASSISTED',1),'cancelled':('INTERRUPTED',2),
                  'blocked':('BLOCKED',2),'turn_limit':('FAIL',1),'check_failed':('FAIL',1),'endpoint_unreachable':('BLOCKED',2),
                  'setup_failed':('BLOCKED',2),'infrastructure_fault_cleanup':('FAIL',1)}
        for name,value,*_ in FIXTURES:
            before=json.dumps(value,sort_keys=True);outcomes.verdict(value)
            self.assertEqual(json.dumps(value,sort_keys=True),before)
            if name in expected:self.assertEqual((value['status'],value['exit_code']),expected[name])
        self.assertEqual(expected['blocked'],next((v['status'],v['exit_code']) for n,v,*_ in FIXTURES if n=='blocked_configuration'))

    def test_a_check_that_could_not_run_is_a_fault_unless_its_target_is_missing(self):
        def could_not_run(reason):
            return record(scoring={'status':'error','reason':'scorer_error'},task_result={'status':'unknown'},
                          checks=[check(status='error',reason=reason,task='unknown',exit_code=2)])
        fault=outcomes.verdict(could_not_run('scorer_output_missing'))
        self.assertEqual((fault['outcome'],fault['attribution'],fault['phase']),('infrastructure_fault','infrastructure','check'))
        missing=outcomes.verdict(could_not_run('check-target-missing'))
        self.assertEqual((missing['outcome'],missing['attribution'],missing['phase'],missing['stage'],missing['reason']),
                         ('check_failed','model','check','check-1-oracle','check-target-missing'))
        unstarted=could_not_run('check-target-missing');unstarted['checks'][0]['process']={'exit_code':2,'cleanup_confirmed':False}
        self.assertEqual(outcomes.verdict(unstarted)['outcome'],'check_failed')
        ran_and_failed=outcomes.verdict(record(**FAILING_CHECK))
        self.assertEqual((ran_and_failed['outcome'],ran_and_failed['reason']),('check_failed','task_fail'))

    def test_absorbed_provider_errors_do_not_move_a_limit_to_the_endpoint(self):
        absorbed=record(**stopped('turn_limit',124,segments=provider(['error'],2,1)))
        self.assertEqual(outcomes.verdict(absorbed)['outcome'],'turn_limit')
        completed=record(agents=[agent(segments=provider(['error']))])
        self.assertEqual(outcomes.verdict(completed)['outcome'],'pass')
        aborted=record(**stopped('process_error',segments=provider(['aborted','length'])))
        self.assertEqual(outcomes.verdict(aborted)['outcome'],'agent_incomplete')

    def test_malformed_sections_never_raise_or_blame_the_model(self):
        for value in ({},{'status':'FAIL','exit_code':1,'agents':'x','checks':[None],'termination':None},
                      {'status':'FAIL','exit_code':1,'infrastructure':{'status':'ready'},'invocation':{'status':'verified'},
                       'termination':{'reason':'completed'},'scoring':{'status':'completed'},'task_result':{'status':'pass'}}):
            result=outcomes.verdict(value)
            self.assertIn(result['outcome'],OUTCOMES);self.assertNotEqual(result['attribution'],'model')


class BlockedAttributionTests(unittest.TestCase):
    def test_tables_are_disjoint_and_unknown_reasons_are_infrastructure(self):
        self.assertFalse(outcomes.BLOCKED_CONFIGURATION & outcomes.BLOCKED_INFRASTRUCTURE)
        self.assertFalse((outcomes.BLOCKED_CONFIGURATION | outcomes.BLOCKED_INFRASTRUCTURE) & set(outcomes.ENDPOINT_REASONS))
        for reason in outcomes.BLOCKED_CONFIGURATION:self.assertEqual(outcomes.blocked_attribution(reason),'configuration')
        for reason in (*outcomes.BLOCKED_INFRASTRUCTURE,'ValueError','ControlError','not-a-known-code','',None,7,['missing-secret']):
            self.assertEqual(outcomes.blocked_attribution(reason),'infrastructure')

    def test_every_reason_code_of_this_runner_is_assigned(self):
        import diagnostics, egress, indexed_contract, lab_env, resources
        known=outcomes.BLOCKED_CONFIGURATION | outcomes.BLOCKED_INFRASTRUCTURE | set(outcomes.ENDPOINT_REASONS)
        # Reason arguments of LabError in the runner; two belong to control commands, which never block a run.
        literal=set()
        for node in ast.walk(ast.parse((ROOT/'scripts/pi_lab.py').read_text())):
            if isinstance(node,ast.Call) and getattr(node.func,'id',None)=='LabError' and len(node.args)>1:
                if isinstance(node.args[1],ast.Constant) and isinstance(node.args[1].value,str):literal.add(node.args[1].value)
        literal-={'invalid-stage-control','unsafe-workspace-patch'}
        self.assertIn('missing-secret',literal)
        environment={'environment-'+state for state in ('needs-session','no-environment','needs-confirmation','broken')}
        saved=set()
        for node in ast.walk(ast.parse((ROOT/'scripts/lab_env.py').read_text())):
            if isinstance(node,ast.Call) and getattr(node.func,'id',None)=='EnvError' and len(node.args)>2:
                if isinstance(node.args[2],ast.Constant) and isinstance(node.args[2].value,str):saved.add(node.args[2].value)
        self.assertIn('environment-corrupt',saved)
        sources={'LabError reason':literal,'saved environment state':environment,'saved environment reason':saved,
                 'admission failure':set(resources.ADMISSION_FAILURES),'indexed reason':set(indexed_contract.REASONS),
                 'remedy':set(diagnostics.REMEDIES),'network mode reason':set(egress.REMEDIES),'recorded class name':{'LabError'}}
        for source,codes in sources.items():
            self.assertFalse(codes-known,f'{source} without an attribution; add it to BLOCKED_CONFIGURATION or BLOCKED_INFRASTRUCTURE in outcomes.py')


def arguments(top,*extra,agents=None,setup=None,checks=None):
    project=top/'project';project.mkdir();(project/'code.py').write_text('pass')
    plan={'schema':1,'agents':agents or [{'name':'dev','prompt':'Synthetic task','require_tools':[]}],
          'checks':checks or [{'name':'oracle','argv':['true']}]}
    if setup:plan['setup']=setup
    lab.save(top/'plan.json',plan)
    a=lab.parser().parse_args(['run','--project',str(project),'--plan',str(top/'plan.json'),'--endpoint',str(top/'endpoint.json'),
        '--results-dir',str(top/'results'),'--lock-file',str(top/'lease'),'--platform','linux/arm64','--memory','1g','--cpus','1',*extra])
    a.observed_pi_version='0.87.1'
    return a


def receipt(**fields):
    return {'exit_code':0,'started':True,'timed_out':False,'log_limit_exceeded':False,'cleanup_confirmed':True,
            'termination_reason':'completed','elapsed_seconds':0.25,**fields}


def suite(stack,receipts=None,evidence=None,completed=True):
    """Everything up to the supervisor is real; Docker, the endpoint and the trace analysis are synthetic.

    receipts(label, stage) returns the fields a supervisor receipt differs in; stage is the
    (run root, descriptor) pair of an agent stage and None for every other stage.
    """
    endpoint={'base_url':'http://example.invalid/v1','model':'fixture-model','api_key_env':'PI_API_KEY','context_window':8192,'max_tokens':1024}
    stack.enter_context(mock.patch.object(lab,'load_endpoint',return_value=endpoint))
    stack.enter_context(mock.patch.object(lab,'endpoint_secret',return_value='synthetic-key'))
    stack.enter_context(mock.patch.object(lab,'require_host',return_value={}))
    stack.enter_context(mock.patch.object(lab,'probe_image',return_value={'id':'fixture','reference':'fixture','capabilities':{'pi':'0.87.1'}}))
    stack.enter_context(mock.patch.object(lab,'command',side_effect=AssertionError('No Docker command in this test')))
    def fake(argv,logdir,timeout,name,secret='',stage=None,**kw):
        label=stage[1]['label'] if stage else logdir.name
        logdir.mkdir(parents=True,exist_ok=True);(logdir/'stdout.jsonl').write_text('');(logdir/'stderr.log').write_text('')
        result=receipt(**(receipts(label,stage) if receipts else {}))
        lab.save(logdir/'process.json',result)
        return result
    stream=stack.enter_context(mock.patch.object(lab,'stream_run',side_effect=fake))
    def analyzed(path,*args,**kw):
        label=Path(path).parents[2].name
        return {'agent_invocation_verified':completed,'completion_verified':completed,'errors':[],'final_text':'synthetic',
                'events':{'turn_start':3},'usage':summarize([]),**(evidence(label) if evidence else {})}
    stack.enter_context(mock.patch.object(lab,'analyze',side_effect=analyzed))
    stack.enter_context(mock.patch.object(lab.segments,'aggregate',return_value={'agent_invocation_verified':completed,'completion_verified':completed,
        'invocation_status':'verified' if completed else 'invalid','errors':[],'final_text':'synthetic'}))
    stack.enter_context(contextlib.redirect_stdout(io.StringIO()));stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
    return stream


def sealed(top):
    root=(top/'results/latest').resolve();result=controls.read(root/'result.json')
    return root,result


class SealedRunTests(unittest.TestCase):
    def test_unconfirmed_removal_in_a_check_stage_after_a_passing_score_is_a_cleanup_fault(self):
        with tempfile.TemporaryDirectory() as td,contextlib.ExitStack() as stack:
            top=Path(td);a=arguments(top,checks=[{'name':'oracle','argv':['true']},{'name':'lint','argv':['true']}])
            # The first check passes. The second command completes too; only the removal of its container is not confirmed.
            suite(stack,receipts=lambda label,stage:{'exit_code':2,'cleanup_confirmed':False,'termination_reason':'cleanup_error',
                                                     'termination_trigger':'completed'} if label.startswith('check-2-') else {})
            self.assertEqual(lab.run_suite(a),1)
            root,result=sealed(top)
            self.assertEqual((result['status'],result['invocation']['status'],result['termination']['reason']),('FAIL','verified','completed'))
            self.assertEqual([(row['scorer']['status'],row['scorer']['task_status']) for row in result['checks']],[('completed','pass'),('error','unknown')])
            self.assertEqual(result['verdict'],{'schema':1,'outcome':'infrastructure_fault','attribution':'infrastructure','phase':'cleanup',
                                                'stage':'check-2-lint','reason':'cleanup_error','exit_code':1})
            self.assertEqual(controls.read(root/'summary.json')['verdict'],result['verdict'])
        two=record(scoring={'status':'error','reason':'scorer_error'},task_result={'status':'unknown'},
                   checks=[check(),check('second',2,status='error',reason='cleanup_unconfirmed',task='unknown',exit_code=2,
                                 cleanup_confirmed=False,termination_reason='cleanup_error',termination_trigger='completed')])
        result=outcomes.verdict(two)
        self.assertEqual((result['outcome'],result['phase'],result['stage']),('infrastructure_fault','cleanup','check-2-second'))

    def test_agent_stage_that_exceeded_its_turns_is_a_turn_limit_of_the_model(self):
        with tempfile.TemporaryDirectory() as td,contextlib.ExitStack() as stack:
            top=Path(td);a=arguments(top)
            # Exit 124 from the worker; the parent recount of the retained trace (3 turns against 2) names the limit.
            suite(stack,completed=False,receipts=lambda label,stage:{'exit_code':124,'termination_reason':'process_error',
                'effective_limits':{'timeout_seconds':900,'max_turns':2,'max_total_tokens':500000}} if stage else {})
            self.assertEqual(lab.run_suite(a),1)
            root,result=sealed(top)
            self.assertEqual((result['status'],result['termination']['reason'],result['task_result']['status']),('FAIL','turn_limit','pass'))
            self.assertEqual(result['verdict'],{'schema':1,'outcome':'turn_limit','attribution':'model','phase':'agent',
                                                'stage':'agent-1-dev','reason':'turn_limit','exit_code':1})

    def test_setup_failure_and_failed_preflight_are_named_from_the_stage_records(self):
        cases={'setup':('setup-1-prepare',{'outcome':'setup_failed','attribution':'configuration','phase':'setup','stage':'setup-1-prepare','reason':'process_error'}),
               'preflight':('preflight',{'outcome':'endpoint_error','attribution':'endpoint','phase':'preflight','stage':'preflight','reason':'process_error'}),
               'boundary':('boundary',{'outcome':'blocked','attribution':'configuration','phase':'preflight','stage':'boundary','reason':'LabError'})}
        for name,(failing,expected) in cases.items():
            with self.subTest(stage=name),tempfile.TemporaryDirectory() as td,contextlib.ExitStack() as stack:
                top=Path(td);a=arguments(top,setup=[{'name':'prepare','argv':['false']}])
                suite(stack,receipts=lambda label,stage:{'exit_code':1,'termination_reason':'process_error'} if label==failing else {})
                self.assertEqual(lab.run_suite(a),2)
                root,result=sealed(top)
                self.assertEqual((result['status'],result['exit_code']),('BLOCKED',2))
                self.assertEqual(result['verdict'],{'schema':1,**expected,'exit_code':2})
                self.assertEqual(result['usage_summary']['stages'][-1],{'stage':failing,'kind':'setup' if name=='setup' else 'preflight','wall_seconds':0.25})
                self.assertFalse(any(row['kind']=='agent' for row in result['usage_summary']['stages']))

    def test_usage_summary_of_a_sealed_run_with_an_extended_stage(self):
        with tempfile.TemporaryDirectory() as td,contextlib.ExitStack() as stack:
            top=Path(td)
            a=arguments(top,agents=[{'name':'dev','prompt':'Synthetic task','require_tools':[]},
                                    {'name':'review','prompt':'Synthetic review','require_tools':[],'max_turns':12,'timeout_seconds':600,'max_total_tokens':200000}])
            def receipts(label,stage):
                if not stage:return {}
                runroot,desc=stage
                controls.start_budget(runroot,desc,time.monotonic())
                if label=='agent-1-dev':
                    # The real extend-budget command, applied by the supervisor's own request processing.
                    self.assertEqual(lab.main(['extend-budget','--run',str(runroot),'--stage',desc['stage_id'],'--turns','+10','--tokens','+250000']),0)
                budget=controls.process_budget_requests(runroot,desc)
                return {'original_limits':budget['original_limits'],'effective_limits':budget['effective_limits'],'budget_revision':budget['revision']}
            reported=summarize([{'usage':{'input':900,'output':120,'cacheRead':0,'cacheWrite':0,'totalTokens':1020}},
                                {'usage':{'input':1100,'output':80,'cacheRead':0,'cacheWrite':0,'totalTokens':1180}}])
            silent=summarize([{'role':'assistant'},{'role':'assistant'}])
            suite(stack,receipts=receipts,evidence=lambda label:{'usage':reported,'events':{'turn_start':4}} if label=='agent-1-dev' else {'usage':silent,'events':{'turn_start':2}})
            self.assertEqual(lab.run_suite(a),1)
            root,result=sealed(top)
            self.assertTrue(result['sealed']);self.assertEqual(result['status'],'ASSISTED')
            self.assertEqual(result['verdict']['outcome'],'pass_assisted')
            usage=result['usage_summary'];self.assertEqual(usage['schema'],1)
            self.assertEqual([(row['stage'],row['kind']) for row in usage['stages']],
                             [('boundary','preflight'),('preflight','preflight'),('agent-1-dev','agent'),('agent-2-review','agent'),('check-1-oracle','check')])
            first,second=usage['stages'][2:4]
            self.assertEqual(set(first),{'stage','kind','wall_seconds','turns','tokens','limits'})
            self.assertEqual(first['limits'],{'plan':{'timeout_seconds':900,'max_turns':24,'max_total_tokens':500000},
                                              'effective':{'timeout_seconds':900,'max_turns':34,'max_total_tokens':750000}})
            self.assertEqual(second['limits'],{'plan':{'timeout_seconds':600,'max_turns':12,'max_total_tokens':200000},
                                               'effective':{'timeout_seconds':600,'max_turns':12,'max_total_tokens':200000}})
            self.assertEqual((first['turns'],second['turns']),(4,2))
            self.assertEqual(first['tokens'],{'input':2000,'output':200,'total':2200,'reported':True})
            # The trace of the second stage reports no token usage: null, never zero.
            self.assertEqual(second['tokens'],{'input':None,'output':None,'total':None,'reported':False})
            for row in usage['stages']:
                self.assertTrue(type(row['wall_seconds']) in (int,float) and row['wall_seconds']>=0)
                if row['kind']!='agent':self.assertEqual(row,{'stage':row['stage'],'kind':row['kind'],'wall_seconds':0.25})
            self.assertEqual(controls.read(root/'summary.json'),result)

    def test_usage_summary_from_the_record_alone_and_with_missing_values(self):
        value=record(agents=[agent(stage_turns=5,elapsed_seconds=9.5,timing={'stage_end_to_end_seconds':12.25},
                                   usage=summarize([{'usage':{'input':10,'output':2,'totalTokens':12}}]),
                                   original_limits={'timeout_seconds':900,'max_turns':24,'max_total_tokens':500000},
                                   effective_limits={'timeout_seconds':1500,'max_turns':24,'max_total_tokens':500000}),
                             agent('late',2)],checks=[check(elapsed_seconds=0.75)])
        rows=outcomes.usage_summary(value)['stages']
        self.assertEqual([(row['stage'],row['kind'],row['wall_seconds']) for row in rows],
                         [('agent-1-dev','agent',12.25),('agent-2-late','agent',None),('check-1-oracle','check',0.75)])
        self.assertEqual(rows[0]['tokens'],{'input':10,'output':2,'total':12,'reported':True})
        self.assertEqual(rows[0]['limits']['effective']['timeout_seconds'],1500)
        self.assertEqual(rows[1],{'stage':'agent-2-late','kind':'agent','wall_seconds':None,'turns':None,
                                  'tokens':{'input':None,'output':None,'total':None,'reported':False},
                                  'limits':{'plan':{'timeout_seconds':None,'max_turns':None,'max_total_tokens':None},
                                            'effective':{'timeout_seconds':None,'max_turns':None,'max_total_tokens':None}}})


class BudgetOverrideTests(unittest.TestCase):
    AGENTS=[{'name':'dev','prompt':'Synthetic task','require_tools':[],'max_turns':10,'max_total_tokens':100000,'timeout_seconds':300},
            {'name':'review','prompt':'Synthetic review','require_tools':[]}]

    def test_options_replace_the_values_of_every_agent_stage_and_are_recorded(self):
        with tempfile.TemporaryDirectory() as td,contextlib.ExitStack() as stack:
            top=Path(td);a=arguments(top,'--max-turns','30','--max-total-tokens','800000',agents=self.AGENTS)
            suite(stack)
            self.assertEqual(lab.run_suite(a),0)
            root,result=sealed(top)
            self.assertEqual(result['budget_overrides'],{'max_turns':30,'max_total_tokens':800000})
            plan=controls.read(root/'plan.json')
            self.assertEqual([(t['max_turns'],t['max_total_tokens'],t['timeout_seconds']) for t in plan['agents']],[(30,800000,300),(30,800000,900)])
            launched=[controls.read(path)['original_limits'] for path in (root/'stages').glob('*/descriptor.json') if controls.read(path)['kind']=='agent']
            self.assertEqual(sorted(limits['timeout_seconds'] for limits in launched),[300,900])
            self.assertTrue(all((limits['max_turns'],limits['max_total_tokens'])==(30,800000) for limits in launched))
            self.assertEqual((result['status'],result['verdict']['outcome']),('PASS','pass'))
            # The plan file the caller supplied is not rewritten.
            self.assertEqual(json.loads((top/'plan.json').read_text())['agents'][0]['max_turns'],10)

    def test_agent_timeout_option_and_absence_of_options(self):
        with tempfile.TemporaryDirectory() as td,contextlib.ExitStack() as stack:
            top=Path(td);a=arguments(top,'--agent-timeout-seconds','1200',agents=self.AGENTS);suite(stack)
            self.assertEqual(lab.run_suite(a),0)
            root,result=sealed(top)
            self.assertEqual(result['budget_overrides'],{'timeout_seconds':1200})
            self.assertEqual([(t['max_turns'],t['timeout_seconds']) for t in controls.read(root/'plan.json')['agents']],[(10,1200),(24,1200)])
        with tempfile.TemporaryDirectory() as td,contextlib.ExitStack() as stack:
            top=Path(td);a=arguments(top,agents=self.AGENTS);suite(stack)
            self.assertEqual(lab.run_suite(a),0)
            root,result=sealed(top)
            self.assertNotIn('budget_overrides',result)
            self.assertEqual(controls.read(root/'plan.json')['agents'][0]['max_turns'],10)

    def test_values_outside_the_plan_bounds_are_refused_before_any_container_starts(self):
        for option,value in (('--max-turns','101'),('--max-turns','0'),('--max-total-tokens','10000001'),
                             ('--agent-timeout-seconds','3601'),('--agent-timeout-seconds','-5')):
            with self.subTest(option=option,value=value),tempfile.TemporaryDirectory() as td,contextlib.ExitStack() as stack:
                top=Path(td);a=arguments(top,option,value,agents=self.AGENTS);stream=suite(stack)
                host=stack.enter_context(mock.patch.object(lab,'require_host',side_effect=AssertionError('host reached')))
                image=stack.enter_context(mock.patch.object(lab,'probe_image',side_effect=AssertionError('image reached')))
                stage=stack.enter_context(mock.patch.object(lab,'run_stage',side_effect=AssertionError('stage reached')))
                self.assertEqual(lab.run_suite(a),2)
                root,result=sealed(top)
                for reached in (stream,host,image,stage):reached.assert_not_called()
                self.assertEqual((result['status'],result['infrastructure']['phase'],result['infrastructure']['reason']),('BLOCKED','admission','budget-override-invalid'))
                self.assertEqual((result['verdict']['outcome'],result['verdict']['attribution'],result['verdict']['phase']),('blocked','configuration','admission'))
                self.assertFalse((root/'stages').exists());self.assertFalse((root/'plan.json').exists())
                self.assertNotIn('budget_overrides',result)

    def test_combination_with_a_compiled_plan_is_refused_before_any_container_starts(self):
        import application_dispatch
        for option,value in (('--max-turns','30'),('--max-total-tokens','800000'),('--agent-timeout-seconds','600')):
            with self.subTest(option=option),tempfile.TemporaryDirectory() as td,contextlib.ExitStack() as stack:
                top=Path(td);(top/'project').mkdir()
                a=lab.parser().parse_args(['run','--project',str(top/'project'),'--compiled-plan',str(top/'compiled/plan.json'),
                    '--results-dir',str(top/'results'),'--lock-file',str(top/'lease'),option,value])
                stream=suite(stack)
                prepare=stack.enter_context(mock.patch.object(application_dispatch,'prepare',side_effect=AssertionError('compiled plan read')))
                stage=stack.enter_context(mock.patch.object(lab,'run_stage',side_effect=AssertionError('stage reached')))
                self.assertEqual(lab.run_suite(a),2)
                root,result=sealed(top)
                for reached in (stream,prepare,stage):reached.assert_not_called()
                self.assertEqual((result['status'],result['infrastructure']['reason']),('BLOCKED','budget-override-invalid'))
                self.assertEqual((result['verdict']['outcome'],result['verdict']['attribution']),('blocked','configuration'))

    def test_options_exist_on_run_only_and_a_native_budget_stays_consistent(self):
        for name in ('smoke','preflight'):
            with self.assertRaises(SystemExit),contextlib.redirect_stderr(io.StringIO()):lab.parser().parse_args([name,'--max-turns','30'])
        native={'name':'dev','prompt':'Synthetic task','tools':['read'],'require_tools':[],'timeout_seconds':600,
                'max_tool_calls':20,'reporting_reserve_calls':2,'reporting_reserve_seconds':60}
        plan=lab.validate_plan({'schema':1,'agents':[native],'checks':[{'name':'oracle','argv':['true']}]},Path('.'))
        a=lab.parser().parse_args(['run','--agent-timeout-seconds','30'])
        with self.assertRaises(lab.LabError) as refused:lab.budget_overrides(a,plan)
        self.assertEqual(refused.exception.reason,'budget-override-invalid')
        a=lab.parser().parse_args(['run','--agent-timeout-seconds','1200','--max-turns','40'])
        self.assertEqual(lab.budget_overrides(a,plan),{'max_turns':40,'timeout_seconds':1200})
        self.assertEqual((plan['agents'][0]['timeout_seconds'],plan['agents'][0]['max_turns'],plan['agents'][0]['max_tool_calls']),(1200,40,20))


class ReferenceTests(unittest.TestCase):
    STATUS={'clean_success':('PASS',0),'infrastructure_failure':('BLOCKED',2),'timeout_with_passing_task_score':('FAIL',1),
            'scorer_error':('FAIL',1),'authorized_recovery':('RECOVERED',1),'retry_original':('FAIL',1),'retry_success':('PASS',0),
            'cancellation_before_scoring':('INTERRUPTED',2),'cancellation_during_scoring':('INTERRUPTED',2),'assisted_success':('ASSISTED',1)}

    def test_every_outcome_example_has_a_verdict_the_derivation_reproduces(self):
        examples=json.loads((ROOT/'references/outcome-examples.json').read_text())['examples']
        self.assertEqual({example['example'] for example in examples},set(self.STATUS))
        for example in examples:
            with self.subTest(example=example['example']):
                value=example['projection'];expected=value['verdict']
                self.assertEqual(set(expected),{'schema','outcome','attribution','phase','stage','reason','exit_code'})
                self.assertEqual(outcomes.verdict(value),expected)
                self.assertEqual(outcomes.verdict({key:item for key,item in value.items() if key!='verdict'}),expected)
                # Status and exit code are the ones the examples always had.
                self.assertEqual((value['status'],value['exit_code']),self.STATUS[example['example']])
                self.assertEqual(outcomes.status(value),self.STATUS[example['example']])
                self.assertEqual(expected['exit_code'],value['exit_code'])
                self.assertIn(expected['attribution'],ATTRIBUTION[expected['outcome']])

    def test_contract_page_lists_every_outcome_attribution_phase_and_blocked_reason(self):
        text=(ROOT/'references/EVALUATION-CONTRACT.md').read_text()
        for word in (*OUTCOMES,*PHASES,'none','model','endpoint','configuration','infrastructure','operator',
                     'usage_summary','budget_overrides','--max-turns','--max-total-tokens','--agent-timeout-seconds'):
            self.assertIn('`'+word+'`',text)
        for reason in outcomes.BLOCKED_CONFIGURATION | outcomes.BLOCKED_INFRASTRUCTURE | set(outcomes.ENDPOINT_REASONS):
            self.assertIn('`'+reason+'`',text)

    def test_status_prints_the_verdict_as_one_line_once_the_run_is_sealed(self):
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);a=arguments(top);attempt=outcomes.Attempt(a)
            def shown():
                out=io.StringIO()
                with contextlib.redirect_stdout(out):self.assertEqual(lab.main(['status','--run',str(attempt.root)]),0)
                return [line for line in out.getvalue().splitlines() if line.startswith('Verdict:')]
            self.assertEqual(shown(),[])
            attempt.fail(lab.LabError('fixture','missing-secret'));result=attempt.finalize()
            self.assertEqual(shown(),['Verdict: blocked (attribution: configuration; phase: admission; stage: -; reason: missing-secret; exit 2)'])
            self.assertEqual(result['verdict']['outcome'],'blocked');self.assertEqual(result['usage_summary'],{'schema':1,'stages':[]})
        self.assertEqual(outcomes.verdict_lines({}),[]);self.assertEqual(outcomes.verdict_lines({'verdict':'x'}),[])


if __name__=='__main__':
    unittest.main()
