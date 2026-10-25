"""Application coordinator: real reviewed authority/service/files, mocked Docker.

No container, Pi child, application request, browser or model is executed.
"""
import argparse
from contextlib import nullcontext
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import sys
import time
import unittest
from unittest import mock
import uuid
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import agent_profiles
import application_contracts as c
import application_execution as execution
from application_execution_service import ApplicationService
import ownership_registry
from parallel_allocator import Allocator
import stage_control as controls
import test_application_execution_authority as authority_fixture
import test_application_client_authority as client_fixture
REAL_CONTROL=execution.helper_control


def fresh():return str(uuid.uuid4())


class HelperFixture:
    def __init__(self,authority,*,allocator,participant_resources,participant_reservation=None,registry,**kwargs):
        self.authority,self.allocator,self.registry=authority,allocator,registry
        self.host_port=12345;self.reservations=[];self.requests=[];self.cleanup_safe=True
        self.record={'application_helper':True,'client_mode':'application-execution','runroot':str(authority.runroot),'status':'running'}
        registry.records.append(self.record)
        self.evidence_root=authority.runroot/'application-evidence'/fresh();self.evidence_root.mkdir(mode=0o700,parents=True)
        self.evidence_data_root=self.evidence_root/'private';self.evidence_data_root.mkdir(mode=0o700)
        self.private_root=authority.runroot/'application-helpers'/fresh();self.private_root.mkdir(mode=0o700,parents=True)
        state=self.private_root/'state';state.mkdir(mode=0o700)
        state=state/'private';state.mkdir(mode=0o700)
        row=allocator.request('helper-'+fresh(),{'generation':registry.generation},execution.API_RESOURCES,30,'helper')
        self.reservations.append(row)
        if participant_reservation is None:
            participant_reservation=allocator.request('participant-'+fresh(),{'generation':registry.generation},participant_resources,30)
            self.reservations.append(participant_reservation)
        self.participant_reservation=participant_reservation;allocator.dispatch()
        if any(row.state!='reserved' for row in self.reservations):raise ValueError('Fixture reservation not admitted')
        allocator.consume(row.identity,row.capability,row.binding,row.resources);allocator.running(row.identity)
        self.network_record={'container':'owned-application-network'}
        configuration=c.loads(authority._bootstrap(str(self.evidence_data_root),client_fixture.code_identity(),state_root=str(state)))
        self.service=ApplicationService(configuration,clock=lambda:1000.)
        authority._launched=True
    def control(self,body):
        self.requests.append(copy.deepcopy(body))
        return self.service.request('/control',self.authority._control_token,body)
    def cleanup(self,*,writers_absent):
        self.service.close();safe=writers_absent is True and self.cleanup_safe
        self.record['status']='released' if safe else 'quarantined'
        for row in self.reservations:
            if row.state in execution.LIVE:self.allocator.release(row.identity,safe,safe)
        if safe:shutil.rmtree(self.private_root)
        return {'schema':1,'status':'removed' if safe else 'cleanup_unconfirmed','workspace':'clean' if safe else 'quarantined','safe_to_continue':safe}


class ApplicationCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.fixture=authority_fixture.ReviewedAuthorityTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.run=self.fixture.runroot;self.workspace=self.run/'workspace';self.plan=self.fixture.plan
        self.stage=self.plan['stages'][0];self.authority=self.fixture.reviewed()
        self.profile_receipt=agent_profiles.freeze(self.fixture.profile,self.run/'profile')
        self.profile=agent_profiles.staged(self.profile_receipt)
        runtime=self.run/'trusted-runtime';runtime.mkdir()
        for name in ('workspace-boundary.mjs','profile-monitor.mjs','tool-budget.mjs'):
            shutil.copyfile(ROOT/'skill/runtime'/name,runtime/name)
        self.extension=execution.extension_order_sha256(self.stage,self.profile,runtime_root=runtime)
        marker={'schema':1,'plan_sha256':self.plan['plan_sha256'],'stage_id':self.stage['id'],
            'effective_prompt_sha256':hashlib.sha256(self.stage['effective_prompt'].encode()).hexdigest(),
            'tool_schema_sha256':c.digest(sorted(self.stage['tool_schemas'],key=lambda item:item['name'])),
            'profile_binding':copy.deepcopy(self.stage['profile_binding']),'extension_order_sha256':self.extension}
        self.task={'name':self.stage['id'],'prompt':self.stage['effective_prompt'],'tools':self.stage['tools'],
            'tool_schemas':self.stage['tool_schemas'],'cwd':'.','require_tools':[],'application_execution':marker,**self.stage['limits']}
        stage_id=fresh();self.desc={'kind':'agent','run_id':fresh(),'attempt_id':fresh(),'stage_id':stage_id,
            'workspace':str(self.workspace),'control':str(self.run/'controls'/stage_id),'label':'agent-1-'+self.stage['id']}
        stage=self.run/'stages'/stage_id;stage.mkdir(parents=True);Path(self.desc['control']).mkdir(parents=True)
        controls.atomic(self.run/'identity.json',{key:self.desc[key] for key in ('run_id','attempt_id')})
        controls.atomic(self.run/'plan.json',self.plan);controls.atomic(stage/'descriptor.json',self.desc)
        self.sink=[];self.args=argparse.Namespace(platform='linux/arm64',native_platform='linux/arm64',
            observed_pi_version=self.plan['runtime']['pi_release'],profile=self.plan['runtime']['container_profile'],
            project=str(self.fixture.project),network='bridge',in_place=False,frozen_agent_profile=self.profile_receipt,
            resource_report={'effective':copy.deepcopy(self.plan['runtime']['resources'])},
            _application_execution={'plan':self.plan,'stage_id':self.stage['id'],'authority':self.authority,'redaction_sink':lambda values:self.sink.extend(values)})
        for key,value in self.plan['runtime']['resources']['runtime'].items():setattr(self.args,key,value)
        self.registry=argparse.Namespace(binding={},generation='gen',records=[])
        self.registry.load=lambda:list(self.registry.records)
        token=ownership_registry.CURRENT.set(self.registry);self.addCleanup(ownership_registry.CURRENT.reset,token)
        self.lab=mock.Mock();self.lab.docker_info.return_value={'NCPU':32,'MemTotal':64*1024**3}
        self.helpers=[]
        def start(authority,**kwargs):
            helper=HelperFixture(authority,**kwargs);self.helpers.append(helper);return helper
        patch=mock.patch.object(execution.OwnedHelper,'start',side_effect=start);self.start=patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(execution,'helper_control',side_effect=lambda helper,body:helper.control(body));patch.start();self.addCleanup(patch.stop)
        self.session=fresh();self.coordinator=None
        def cleanup():
            for helper in self.helpers:
                helper.service.close()
        self.addCleanup(cleanup)

    def prepare(self):
        self.coordinator=execution.prepare(self.lab,self.args,self.plan['runtime']['image_id'],self.run,self.workspace,self.desc,self.task,self.profile,[])
        return self.coordinator

    def begin(self,coordinator,directive=None):
        segment=fresh();folder=Path(self.desc['control'])/'segments'/segment;folder.mkdir(parents=True)
        reply=coordinator.begin_segment(segment,self.session,folder,directive)
        return segment,folder,reply

    def command(self,coordinator,kind,**payload):
        record={'schema':2,'id':fresh(),'intervention_id':fresh(),'kind':kind,'created_at':controls.now(),'expected_stage_revision':1,
            **{key:coordinator.binding[key] for key in ('run_id','attempt_id','stage_id','segment_id')},**payload}
        record['payload_digest']=hashlib.sha256(json.dumps(payload,sort_keys=True).encode()).hexdigest()
        folder=(self.run/'stages'/self.desc['stage_id']/'budget-requests' if kind=='extend_budget'
                else Path(self.desc['control'])/'inbox'/'directives')
        folder.mkdir(parents=True,exist_ok=True);controls.atomic(folder/(record['id']+'.json'),record)
        for status in ('requested','accepted'):controls.audit(self.run,record,status)
        return record

    def test_exact_ir_starts_one_service_grant_private_context_and_safe_completion_context(self):
        co=self.prepare();segment,folder,reply=self.begin(co)
        self.assertEqual(reply['context_path'],'/opt/pi-control/segments/'+segment+'/application-context.json')
        context=json.loads((folder/'application-context.json').read_bytes())
        self.assertEqual(stat.S_IMODE((folder/'application-context.json').stat().st_mode),0o400)
        self.assertEqual(context['tool_schemas'],self.stage['tool_schemas'])
        self.assertEqual(context['budget_context']['extension_order_sha256'],self.extension)
        self.assertEqual(len(self.authority._grants),1);self.assertIn(context['capability'],co.redaction_values())
        self.assertIn(context['budget_context']['capability'],self.sink)
        co.mark_running();co.after_segment(True);self.assertTrue(co.close(True)['safe_to_continue'])
        self.assertFalse((folder/'application-context.json').exists())
        completion=co.completion_context
        self.assertEqual(set(completion),{'binding','authorized_segment_ids','report_root','evidence_root','parent_receipts'})
        self.assertEqual(completion['authorized_segment_ids'],[segment]);self.assertEqual(completion['parent_receipts'],{})
        self.assertTrue(Path(completion['report_root']).is_dir());self.assertTrue(Path(completion['evidence_root']).is_dir())
        self.assertEqual(co.reservation.state,'released')

    def test_task_prompt_schema_marker_limits_profile_and_runtime_mismatch_deny_before_helper(self):
        for mutation in ('prompt','schemas','marker','limits','profile','image'):
            task,args=copy.deepcopy(self.task),copy.copy(self.args)
            if mutation=='prompt':self.task['prompt']='altered'
            elif mutation=='schemas':self.task['tool_schemas']=[]
            elif mutation=='marker':self.task['application_execution']['schema']=True
            elif mutation=='limits':self.task['max_tool_calls']+=1
            elif mutation=='profile':self.args.frozen_agent_profile=None
            else:self.args.observed_pi_version='unreviewed'
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.prepare()
            self.task,self.args=task,args
        self.start.assert_not_called()

    def test_missing_spec_does_not_activate_legacy_and_forged_marker_fails_closed(self):
        args=copy.copy(self.args);del args._application_execution
        self.assertIsNone(execution.prepare(self.lab,args,'unused',None,None,None,{},None,()))
        with self.assertRaises(execution.ApplicationExecutionError):execution.prepare(self.lab,args,'unused',None,None,None,self.task,None,())

    def test_stored_ir_or_runtime_guard_change_rejected_before_effects(self):
        co=self.prepare();(self.run/'trusted-runtime/tool-budget.mjs').write_text('changed')
        with self.assertRaises(execution.ApplicationExecutionError):self.begin(co)
        self.start.assert_not_called()

    def test_no_automatic_continuation_after_normal_settlement(self):
        co=self.prepare();self.begin(co);co.mark_running();co.after_segment(True)
        with self.assertRaises(execution.ApplicationExecutionError):self.begin(co)
        self.assertEqual(len(self.authority._grants),1)

    def test_explicit_continuation_keeps_service_ledger_and_revokes_old_caps(self):
        co=self.prepare();first,_,_=self.begin(co);old=self.authority._grants[-1]
        co.mark_running();co.after_segment(True)
        command=self.command(co,'steer',message='Explicit parent continuation')
        second,_,_=self.begin(co,command)
        self.assertEqual(len(self.helpers),1);self.assertIn(old.capability,self.authority._revoked)
        self.assertNotEqual(old.capability,self.authority._grants[-1].capability)
        self.assertEqual(co.status()['counts']['charged'],0)
        co.mark_running();co.after_segment(True);co.close(True)
        self.assertEqual(co.completion_context['authorized_segment_ids'],[first,second])

    def test_unaccepted_or_mutated_directive_cannot_activate_successor(self):
        co=self.prepare();self.begin(co);co.after_segment(True)
        command=self.command(co,'steer',message='original');command['message']='forged'
        with self.assertRaises(execution.ApplicationExecutionError):self.begin(co,command)
        self.assertEqual(len(self.authority._grants),1)

    def test_known_secret_continuation_is_rejected_before_control_intent_or_helper_rpc(self):
        co=self.prepare();self.begin(co);co.after_segment(True)
        command=self.command(co,'steer',message=client_fixture.KEY_A)
        with self.assertRaises(execution.ApplicationExecutionError):self.begin(co,command)
        self.assertFalse(any(body['action']=='continue' for body in self.helpers[0].requests))
        self.assertFalse((self.run/'stages'/self.desc['stage_id']/'native-budget-execution').exists())

    def test_explicit_budget_extension_binds_revision_and_never_replays(self):
        co=self.prepare();self.begin(co)
        controls.atomic(self.run/'stages'/self.desc['stage_id']/'budget.json',{'revision':2,'started_host_monotonic':time.monotonic(),
            'effective_limits':self.stage['limits']})
        command=self.command(co,'extend_budget',expected_budget_revision=2,limits={**self.stage['limits'],'max_tool_calls':40,'timeout_seconds':360})
        self.assertEqual(co.extend(command['id'],40,350)['limits']['max_tool_calls'],40)
        with self.assertRaises(execution.ApplicationExecutionError):co.extend(command['id'],40,350)
        self.assertEqual(sum(body['action']=='extend' for body in self.helpers[0].requests),1)

    def test_cap_only_extension_preserves_exact_helper_deadline_counts_and_phase(self):
        co=self.prepare();self.begin(co)
        ledger=next(iter(self.helpers[0].service._ledgers.values()));before=ledger._read()
        controls.atomic(self.run/'stages'/self.desc['stage_id']/'budget.json',{'revision':2,'started_host_monotonic':time.monotonic(),
            'effective_limits':self.stage['limits']})
        command=self.command(co,'extend_budget',expected_budget_revision=2,limits={**self.stage['limits'],'max_tool_calls':40})
        result=co.extend(command['id'],40,290);after=ledger._read()
        self.assertEqual(after['deadline'],before['deadline']);self.assertEqual(after['counts'],before['counts'])
        self.assertEqual(after['phase'],before['phase']);self.assertEqual(result['limits']['max_tool_calls'],40)
        self.assertIsNone(self.helpers[0].requests[-1]['remaining_seconds'])

    def test_unknown_writer_never_finishes_or_purges_and_quarantines_capacity(self):
        co=self.prepare();_,folder,_=self.begin(co)
        with self.assertRaises(execution.ApplicationExecutionError):co.after_segment(False)
        with self.assertRaises(execution.ApplicationExecutionError):co.close(False)
        self.assertFalse(any(body['action']=='finish' for body in self.helpers[0].requests))
        self.assertTrue((folder/'application-context.json').exists());self.assertFalse(co.pool.dependent_cleanup_confirmed)

    def test_context_replacement_does_not_become_successful_purge(self):
        co=self.prepare();_,folder,_=self.begin(co);co.after_segment(True)
        path=folder/'application-context.json';path.rename(folder/'retained-original');path.write_text('replaced')
        with self.assertRaises(execution.ApplicationExecutionError):co.close(True)
        self.assertEqual(path.read_text(),'replaced');self.assertFalse(co.pool.dependent_cleanup_confirmed)

    def test_helper_finish_failure_still_attempts_physical_cleanup_and_retains_context(self):
        co=self.prepare();_,folder,_=self.begin(co);co.after_segment(True)
        original=self.helpers[0].control
        def fail(body):
            if body['action']=='finish':raise ValueError('untrusted raw details')
            return original(body)
        self.helpers[0].control=fail
        with self.assertRaises(execution.ApplicationExecutionError) as caught:co.close(True)
        self.assertEqual(self.helpers[0].record['status'],'released');self.assertTrue((folder/'application-context.json').exists())
        self.assertNotIn('untrusted',str(caught.exception))

    def test_indexed_external_reservation_is_verified_and_never_released(self):
        runtime=self.plan['runtime']['resources']['runtime'];weight={'cpu_millis':round(runtime['cpus']*1000),
            'memory_mib':execution.resources.memory_bytes(runtime['memory'])//1024**2,'pids_limit':runtime['pids_limit']}
        capacity={key:weight[key]+execution.API_RESOURCES[key] for key in weight};pool=Allocator(capacity)
        binding={key:self.desc[key] for key in ('run_id','attempt_id','stage_id')}
        binding.update(generation='gen',trial_id=None,workspace=str(self.workspace))
        row=pool.request('external-worker',binding,weight,30);pool.dispatch();pool.consume(row.identity,row.capability,row.binding,row.resources)
        self.args.network='owned-application-network'
        support={'pool':pool,'reservation':row,'registry':self.registry,'network_record':{'container':self.args.network}}
        self.args._application_execution['external_support']=support
        co=self.prepare();self.begin(co);co.mark_running();co.after_segment(True);co.close(True)
        self.assertEqual(row.state,'running');self.lab.docker_info.assert_not_called()

    def test_remote_worker_has_no_local_authority_fallback(self):
        self.args._parallel_session=argparse.Namespace()
        with self.assertRaises(execution.ApplicationExecutionError):self.prepare()
        self.start.assert_not_called()

    def test_helper_pair_exceeding_half_docker_budget_denies_before_helper(self):
        self.lab.docker_info.return_value={'NCPU':1,'MemTotal':1024**3};co=self.prepare()
        with self.assertRaises(execution.ApplicationExecutionError):self.begin(co)
        self.start.assert_not_called()

    def host_budget_case(self, cpu, memory):
        original = authority_fixture.ReviewedAuthorityTests.compile_reviewed
        def compile_with_budget(fixture, source=None):
            source, _ = authority_fixture.inputs.inputs(source)
            source['runtime']['resources']['host_budget'] = {'cpu_fraction': cpu, 'memory_fraction': memory}
            source['runtime']['resources']['runtime'] = {'cpus': 1.0, 'memory': '1g', 'pids_limit': 256, 'jobs': 1}
            return original(fixture, source)
        case = ApplicationCoordinatorTests(methodName='runTest')
        self.addCleanup(case.doCleanups)
        with mock.patch.object(authority_fixture.ReviewedAuthorityTests, 'compile_reviewed', compile_with_budget):
            case.setUp()
        return case

    def test_declared_cpu_or_memory_fraction_denies_pair_before_helper(self):
        for cpu, memory in ((0.125, 0.5), (0.5, 0.0625)):
            with self.subTest(cpu=cpu, memory=memory):
                case = self.host_budget_case(cpu, memory)
                case.lab.docker_info.return_value = {'NCPU': 8, 'MemTotal': 16 * 1024 ** 3}
                co = case.prepare()
                with self.assertRaises(execution.ApplicationExecutionError): case.begin(co)
                case.start.assert_not_called()

    def test_larger_declared_fraction_admits_fitting_pair(self):
        case = self.host_budget_case(0.75, 0.75)
        case.lab.docker_info.return_value = {'NCPU': 3, 'MemTotal': 4 * 1024 ** 3}
        co = case.prepare(); case.begin(co)
        self.assertEqual(co.pool.capacity['cpu_millis'], 2250)
        self.assertEqual(len(case.helpers), 1)
        co.mark_running(); co.after_segment(True); co.close(True)

    def test_byte_equivalent_memory_units_pass_without_mutating_frozen_ir(self):
        before=copy.deepcopy(self.plan)
        for section in ('runtime','build'):
            memory=self.args.resource_report['effective'][section]['memory']
            self.args.resource_report['effective'][section]['memory']=str(execution.resources.memory_bytes(memory)//1024**2)+'m'
        self.args.memory=self.args.resource_report['effective']['runtime']['memory']
        self.prepare();self.assertEqual(self.plan,before)

    def test_clamped_runtime_or_build_resources_and_actual_flags_reject_before_helper(self):
        policy=copy.deepcopy(self.args.resource_report['effective']);cpus=self.args.cpus
        for mutation in ('runtime','build','flags'):
            if mutation=='flags':self.args.cpus=cpus+.5
            else:self.args.resource_report['effective'][mutation]['memory']='64m'
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.prepare()
            self.args.resource_report['effective']=copy.deepcopy(policy);self.args.cpus=cpus
        self.start.assert_not_called()

    def test_empty_external_support_cannot_fall_back_to_a_new_pool(self):
        self.args._application_execution['external_support']={}
        with self.assertRaises(execution.ApplicationExecutionError):self.prepare()
        self.start.assert_not_called()

    def emitted(self,task=None):
        task=copy.deepcopy(task or self.task);continuation=task.get('application_continuation')
        prompt=continuation['message'] if continuation else self.stage['effective_prompt']
        proof={'schema':1,'frozen_effective_prompt_sha256':hashlib.sha256(self.stage['effective_prompt'].encode()).hexdigest(),
            'sent_prompt_sha256':hashlib.sha256(prompt.encode()).hexdigest(),
            'continuation':{key:continuation[key] for key in ('command_id','continues_segment_id','sha256')} if continuation else None}
        folder=self.run/('emitted-'+fresh());folder.mkdir();result={}
        for name,body in (('effective-prompt.txt',prompt.encode()),('application-prompt.json',c.canonical(proof))):
            path=folder/name;path.write_bytes(body)
            result[name]={'path':str(path),'sha256':hashlib.sha256(body).hexdigest(),'origin':'worker_reported'}
        return result

    def test_parent_verifies_exact_initial_worker_prompt_and_proof(self):
        emitted=self.emitted();self.assertTrue(execution.verify_emitted(self.stage,self.task,emitted))
        Path(emitted['effective-prompt.txt']['path']).write_text('altered')
        with self.assertRaises(execution.ApplicationExecutionError):execution.verify_emitted(self.stage,self.task,emitted)

    def test_parent_verifies_explicit_continuation_without_changing_frozen_prompt(self):
        task=copy.deepcopy(self.task);segment=fresh();message='Parent-approved direction'
        task.update(application_context='/opt/pi-control/segments/'+segment+'/application-context.json',
            resume_session='/opt/pi-control/segments/'+segment+'/session.jsonl',
            application_continuation={'schema':1,'command_id':fresh(),'continues_segment_id':fresh(),'message':message,
                                      'sha256':hashlib.sha256(message.encode()).hexdigest()})
        emitted=self.emitted(task);self.assertTrue(execution.verify_emitted(self.stage,task,emitted))
        task['prompt']=message
        with self.assertRaises(execution.ApplicationExecutionError):execution.verify_emitted(self.stage,task,emitted)

    def test_missing_linked_or_private_extra_worker_proof_is_rejected(self):
        for mutation in ('missing','symlink','hardlink','extra'):
            emitted=self.emitted();proof=Path(emitted['application-prompt.json']['path'])
            if mutation=='missing':proof.unlink()
            elif mutation=='symlink':
                original=proof.with_name('original');proof.rename(original);proof.symlink_to(original)
            elif mutation=='hardlink':os.link(proof,proof.with_name('alias'))
            else:
                value=c.loads(proof.read_bytes());value['capability']='untrusted-private-value';body=c.canonical(value)
                proof.write_bytes(body);emitted['application-prompt.json']['sha256']=hashlib.sha256(body).hexdigest()
            with self.subTest(mutation=mutation),self.assertRaises(execution.ApplicationExecutionError):execution.verify_emitted(self.stage,self.task,emitted)

    def test_parent_control_is_fixed_loopback_one_request_and_bounded_response(self):
        requests=[];fixture=self
        class Connection:
            def __init__(self,host,port,timeout):
                fixture.assertEqual((host,port,timeout),('127.0.0.1',12345,5));self.sock=None
            def connect(self):self.sock=mock.Mock()
            def request(self,method,path,body,headers):
                self.connect();requests.append((method,path,body,headers))
            def getresponse(self):return SimpleNamespace(status=200,read=lambda maximum:c.canonical({'schema':1,'ok':True,'budget':{}}))
            def close(self):pass
        helper=SimpleNamespace(host_port=12345,authority=self.authority)
        with mock.patch.object(execution.http.client,'HTTPConnection',Connection):
            result=REAL_CONTROL(helper,{'schema':1,'action':'status'})
        self.assertEqual(result['budget'],{});self.assertEqual(len(requests),1)
        self.assertEqual(requests[0][0:2],('POST','/control'))
        self.assertEqual(requests[0][3]['Authorization'],'Bearer '+self.authority._control_token)

    def test_parent_control_redirect_oversize_bad_json_and_expired_connect_never_retry(self):
        helper=SimpleNamespace(host_port=12345,authority=self.authority)
        for mode in ('redirect','oversize','badjson','timeout'):
            requests=[]
            class Connection:
                def __init__(self,*args,**kwargs):self.sock=None
                def connect(self):self.sock=mock.Mock()
                def request(self,*args,**kwargs):requests.append(1);self.connect()
                def getresponse(self):
                    body=(b'x'*(256*1024+1) if mode=='oversize' else b'not-json' if mode=='badjson' else b'{"schema":1,"ok":true}')
                    return SimpleNamespace(status=302 if mode=='redirect' else 200,read=lambda maximum:body)
                def close(self):pass
            class Timer:
                def __init__(self,seconds,callback):self.callback=callback
                def start(self):self.callback()
                def cancel(self):pass
            with self.subTest(mode=mode),mock.patch.object(execution.http.client,'HTTPConnection',Connection):
                timer=mock.patch.object(execution.threading,'Timer',Timer) if mode=='timeout' else nullcontext()
                with timer,self.assertRaises(execution.ApplicationExecutionError):REAL_CONTROL(helper,{'schema':1,'action':'status'})
            self.assertEqual(len(requests),1)


if __name__=='__main__':unittest.main()
