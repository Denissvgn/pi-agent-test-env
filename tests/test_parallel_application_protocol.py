"""Composed real Peer/RemoteAdmission/application coordinators and helper ledger.

The transport is an in-process message bridge. Docker admission/launch/absence
and Pi execution are controlled boundaries; no sockets, containers or model.
"""
import copy
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import agent_profiles
import application_execution
from application_remote import RemoteApplicationCoordinator,ApplicationExecutionError
import ownership_registry
from parallel_dispatch import Peer,RemoteAdmission
import parallel_contract
import stage_control as controls
import test_parallel_application as parent_fixture
import test_application_execution as helper_fixture
import test_application_client_authority as private_fixture


def fresh():return str(uuid.uuid4())


class Bridge:
    """Serialize actual protocol messages; parent CURRENT never becomes child."""
    def __init__(self,parent,registry):self.parent=parent;self.registry=registry;self.messages=[];self.replies=[];self.pending=None;self.mutate=None
    def send(self,message):
        self.messages.append(json.loads(json.dumps(message)));token=ownership_registry.CURRENT.set(self.registry)
        try:
            try:self.pending=self.parent.handle(self.messages[-1])
            except parallel_contract.ParallelError:self.pending={'op':'error'}
        finally:ownership_registry.CURRENT.reset(token)
    def receive(self,*args):
        value=json.loads(json.dumps(self.pending));self.pending=None
        if self.mutate:self.mutate(value)
        self.replies.append(value);return value
    def ready(self):return False


class ComposedApplicationProtocolTests(unittest.TestCase):
    def setUp(self):
        self.case=parent_fixture.ParallelApplicationTests(methodName='runTest');self.case.setUp();self.addCleanup(self.case.doCleanups)
        case=self.case;case.cohort.peers.pop(case.trial)
        self.parent=Peer(copy.deepcopy(case.peer.bootstrap),case.registry,case.pool,case.peer.reservation,case.metadata,case.run)
        self.parent.entered=True # Fixture already consumed the exact held worker grant.
        case.peer=self.parent;case.adapter=self.parent.native_budget
        original=case.start.side_effect
        def helper(*args,**kwargs):
            with mock.patch.object(helper_fixture,'fresh',side_effect=lambda:'pi-application-'+uuid.uuid4().hex[:16]):return original(*args,**kwargs)
        case.start.side_effect=helper
        def intent(argv,name,binding,runroot):
            record={'launch_id':fresh(),'binding':copy.deepcopy(binding),'status':'running','container':name}
            case.registry.records.append(record);return record,list(argv)
        case.registry.intent=intent
        def absent(record):record['status']='absent';return True
        case.registry.confirm_absent=absent
        # Generic Docker argv policy is separately tested; application task and
        # private context launch verification remain real in ApplicationPeer.
        self.parent.validate_launch=mock.Mock(return_value=None)
        self.sid,self.session=fresh(),fresh();self.stage=case.plan['stages'][0]
        self.control=case.run/'controls'/self.sid;(self.control/'segments').mkdir(parents=True,mode=0o700)
        self.desc={'run_id':case.runid,'attempt_id':case.attempt,'stage_id':self.sid,'kind':'agent','workspace':str(case.run/'workspace'),
            'control':str(self.control),'label':'agent-1-'+self.stage['id']}
        folder=case.run/'stages'/self.sid;folder.mkdir(parents=True)
        controls.atomic(folder/'descriptor.json',self.desc);controls.atomic(folder/'state.json',{'status':'running','cleanup_confirmed':False})
        self.profile=agent_profiles.staged({'root':str(case.run/'agent-profile'),'sha256':self.stage['profile_binding']['sha256']})
        self.task=case.adapter._task(self.stage,self.profile)
        self.bridge=Bridge(self.parent,case.registry)
        bootstrap=copy.deepcopy(self.parent.bootstrap);bootstrap['experiment']=str(case.root)
        self.remote=RemoteAdmission(self.bridge,bootstrap,mock.Mock())
        self.args=copy.copy(case.args);self.args._parallel_session=self.remote
        self.args._application_execution={'plan':case.plan,'stage_id':self.stage['id'],'authority':None}
        self.args.browser_sandbox_policy='docker-default'
        self.args.frozen_agent_profile={'root':str(case.run/'agent-profile'),'sha256':self.stage['profile_binding']['sha256']}
        token=ownership_registry.CURRENT.set(self.remote);self.addCleanup(ownership_registry.CURRENT.reset,token)
        self.child=RemoteApplicationCoordinator(case.lab,self.args,case.plan['runtime']['image_id'],case.run,case.run/'workspace',
            self.desc,self.task,self.profile,[])

    def begin(self,directive=None):
        segment=fresh();folder=self.control/'segments'/segment;folder.mkdir(mode=0o700)
        reply=self.child.begin_segment(segment,self.session,folder,directive)
        return segment,folder,reply

    def launch(self,segment,folder):
        task={**self.task,'session_id':self.session,'pi_release':self.case.cohort.release,'allowed_tools':self.stage['tools'],
            'release_contract':parent_fixture.app.release_contracts.identity(self.case.cohort.release),
            'application_context':'/opt/pi-control/segments/'+segment+'/application-context.json',
            'agent_profile_context':'/opt/pi-control/segments/'+segment+'/profile-context.json'}
        proof=self.parent.native_budget.continuation_proof
        if proof:task.update(application_continuation=proof,resume_session='/opt/pi-control/segments/'+segment+'/session.jsonl')
        controls.atomic(folder/'task.json',task,0o644)
        argv=['docker','run','/opt/pi-lab/worker.py','agent','--task','/opt/pi-control/segments/'+segment+'/task.json']
        record,_=self.remote.intent(argv,'controlled-participant',{'stage_id':self.sid,'segment_id':segment})
        self.child.mark_running();return record

    def settle(self,record):
        self.assertTrue(self.remote.confirm_absent(record));return self.child.after_segment(True)

    def charge_status(self):
        context=self.child.context;helper=self.case.helpers[0];scope=context['scope'];token=context['budget_context']['capability'];batch=fresh()
        def request(action,payload):return helper.service.request('/budget',token,{'schema':1,'scope':scope,'action':action,'payload':payload})['result']
        request('reserve',{'batch_id':batch,'calls':[{'id':'call_status_1','name':'budget_status','arguments':{}}],'stop_reason':'toolUse'})
        grant=request('consume',{'batch_id':batch,'native_call_id':'call_status_1','tool_name':'budget_status','raw_input':{}})
        request('entry',{'grant':grant['execution_nonce'],'native_call_id':'call_status_1','tool_name':'budget_status','raw_input':{}})
        request('complete',{'batch_id':batch,'native_call_id':'call_status_1','tool_name':'budget_status','is_error':False})
        request('reconcile',{'batch_id':batch})

    def finalized(self):
        controls.atomic(self.case.run/'stages'/self.sid/'state.json',{'status':'finalized','cleanup_confirmed':True})
        controls.atomic(self.case.run/'stages'/self.sid/'application-credentials.json',{'schema':1,'status':'removed','workspace':'clean'})
        folder=self.case.run/self.desc['label'];folder.mkdir()
        controls.atomic(folder/'process.json',{'cleanup_confirmed':True,'exit_code':0,'termination_reason':'completed',
            'application_helper_cleanup':self.child._cleanup,'evidence':{'completion_verified':True}})

    def test_real_protocol_preserves_context_inode_charged_ledger_and_parent_cleanup(self):
        segment,folder,reply=self.begin();path=folder/'application-context.json';inode=path.stat().st_ino
        self.assertEqual(self.child.context,self.parent.native_budget.context);self.assertEqual(path.stat().st_mode&0o777,0o400)
        record=self.launch(segment,folder);self.charge_status();snapshot=self.settle(record)
        self.assertEqual(snapshot['counts']['charged'],1);self.assertEqual(self.child.status(True),self.parent.native_budget.status(self.sid))
        self.assertEqual(path.stat().st_ino,inode);self.assertEqual(len(self.case.pool.records),2)
        cleanup=self.child.close(True);self.assertTrue(cleanup['safe_to_continue']);self.assertFalse(path.exists())
        self.assertTrue(folder.exists());self.assertEqual(self.child.completion_context,self.parent.native_budget.closed[0]['context'])
        self.assertEqual(self.child.completion_context['authorized_segment_ids'],[segment])
        self.finalized();self.assertTrue(self.parent.native_budget.finalize())
        self.assertEqual(self.case.pool.buddies[self.case.trial].state,'released');self.assertEqual(self.parent.reservation.state,'running')
        raw=json.dumps(self.bridge.messages)+json.dumps(self.remote.bootstrap)
        for value in (private_fixture.KEY_A,private_fixture.KEY_B,private_fixture.INFERENCE_KEY):self.assertNotIn(value,raw)
        self.assertNotIn('native-budget-continue',[message['op'] for message in self.bridge.messages])

    def test_explicit_parent_cli_continuation_retains_counts_and_revokes_old_context(self):
        first,folder,_=self.begin();record=self.launch(first,folder);self.charge_status();self.settle(record)
        authority=self.parent.native_budget.coordinator.authority;old=self.child.context['capability']
        command=helper_fixture.ApplicationCoordinatorTests.command(SimpleNamespace(run=self.case.run,desc=self.desc),
            self.parent.native_budget.coordinator,'steer',message='Explicit parent-owned continuation')
        second,folder2,_=self.begin(command)
        self.assertIn(old,authority._revoked);self.assertNotEqual(old,self.child.context['capability'])
        self.assertEqual(self.child.status(True)['counts']['charged'],1);self.assertEqual(len(self.case.helpers),1)
        record=self.launch(second,folder2);self.settle(record);self.child.close(True)
        self.assertEqual(self.child.completion_context['authorized_segment_ids'],[first,second])
        self.assertEqual(self.child.task['prompt'],self.stage['effective_prompt'])
        self.finalized();self.assertTrue(self.parent.native_budget.finalize())

    def test_runtime_mismatch_is_rejected_before_parent_begin_or_helper(self):
        self.args.jobs+=1
        with self.assertRaises(ApplicationExecutionError):RemoteApplicationCoordinator(self.case.lab,self.args,self.case.plan['runtime']['image_id'],
            self.case.run,self.case.run/'workspace',self.desc,self.task,self.profile,[])
        self.assertEqual(self.bridge.messages,[]);self.case.start.assert_not_called()

    def test_unconfirmed_participant_absence_prevents_checkpoint_and_keeps_parent_context(self):
        segment,folder,_=self.begin();record=self.launch(segment,folder)
        with self.assertRaises(ApplicationExecutionError):self.child.after_segment(False)
        self.assertTrue((folder/'application-context.json').exists())
        self.assertEqual(self.parent.active,record)
        self.assertNotIn('native-budget-checkpoint',[message['op'] for message in self.bridge.messages])
        self.assertNotIn('native-budget-close',[message['op'] for message in self.bridge.messages])

    def test_parent_reply_context_tamper_is_rejected_against_actual_private_file(self):
        self.bridge.mutate=lambda reply:reply['context']['scope']['participant'].update(role='unreviewed-role')
        with self.assertRaises(ApplicationExecutionError):self.begin()
        self.assertEqual(len(self.case.helpers),1);self.assertTrue(self.child.failed)
        self.assertEqual(self.parent.native_budget.context['scope']['participant'],self.stage['participant'])
        self.assertEqual([message['op'] for message in self.bridge.messages],['native-budget-begin'])
        self.bridge.mutate=None;cleanup=self.remote.native_budget_close(self.sid)
        self.assertTrue(cleanup['cleanup']['safe_to_continue'])

    def test_uncertain_helper_cleanup_quarantines_before_child_accepts_close(self):
        segment,folder,_=self.begin();record=self.launch(segment,folder);self.settle(record)
        helper=self.case.helpers[0];helper.cleanup_safe=False
        with self.assertRaises(ApplicationExecutionError):self.child.close(True)
        self.assertFalse(self.case.pool.dependent_cleanup_confirmed);self.assertTrue(self.case.pool.closed)
        self.assertTrue(helper.private_root.exists());self.assertTrue((folder/'application-context.json').exists())


if __name__=='__main__':unittest.main()
