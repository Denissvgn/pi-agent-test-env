"""Credential-free child protocol fixtures with actual frozen files/profile bytes.

RemoteAdmission is real; only its parent protocol methods are controlled. These
fixtures never create Docker, helper, HTTP, Pi or model processes.
"""
import argparse
import copy
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import agent_profiles
import application_client
import application_contracts as c
import application_compiler
import application_execution
import application_runtime_contracts
from application_remote import RemoteApplicationCoordinator,ApplicationExecutionError
import ownership_registry
from parallel_dispatch import RemoteAdmission
import pi_lab as lab
import secret_store
import stage_control as controls
import test_application_compiler as fixtures


def fresh():return str(uuid.uuid4())


class RemoteTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/private/tmp');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.experiment=self.root/'experiment'
        self.run,self.attempt,self.trial,self.stageid,self.session=fresh(),fresh(),fresh(),fresh(),fresh()
        self.runroot=self.experiment/'runs'/self.run;self.runroot.mkdir(parents=True,mode=0o700)
        self.workspace=self.runroot/'workspace';self.workspace.mkdir(mode=0o700)
        (self.workspace/'original.txt').write_text('Protected original.\n')
        source,kwargs=fixtures.inputs();release=source['runtime']['pi_release']
        self.profile=agent_profiles.application(release)
        for stage in source['stages']:
            name=stage['id'];kwargs['profile_bindings'][name]={'id':'application-client','pi_release':release,
                'sha256':agent_profiles.identity(self.profile),'assets':{a['target']:a['sha256'] for a in self.profile['assets']}}
            for asset in self.profile['assets']:kwargs['input_assets']['profiles/'+name+'/'+asset['target']]=agent_profiles.read_asset(asset['source'])
            kwargs['prompt_policy']['profile_instructions'][name]=kwargs['input_assets']['profiles/'+name+'/instructions.md'].decode()
        self.plan=application_compiler.compile_plan(source,**kwargs);self.stage=self.plan['stages'][0]
        controls.atomic(self.runroot/'plan.json',self.plan)
        controls.atomic(self.runroot/'identity.json',{'schema':2,'run_id':self.run,'attempt_id':self.attempt})
        self.control=self.runroot/'controls'/self.stageid;self.control.mkdir(parents=True,mode=0o700)
        self.control.joinpath('segments').mkdir(mode=0o700)
        lab.trusted_runtime(self.runroot)
        receipt=agent_profiles.freeze(self.profile,self.runroot/'agent-profile')
        self.profile=agent_profiles.staged(receipt)
        self.extension=application_execution.extension_order_sha256(self.stage,self.profile,runtime_root=self.runroot/'trusted-runtime')
        marker={'schema':1,'plan_sha256':self.plan['plan_sha256'],'stage_id':self.stage['id'],
            'effective_prompt_sha256':hashlib.sha256(self.stage['effective_prompt'].encode()).hexdigest(),
            'tool_schema_sha256':c.digest(sorted(self.stage['tool_schemas'],key=lambda row:row['name'])),
            'profile_binding':self.stage['profile_binding'],'extension_order_sha256':self.extension}
        self.task={'name':self.stage['id'],'prompt':self.stage['effective_prompt'],'tools':self.stage['tools'],
            'tool_schemas':self.stage['tool_schemas'],'require_tools':[],'cwd':'.','access':'ro',
            **self.stage['limits'],'application_execution':marker}
        self.desc=controls.create(self.runroot,self.workspace,'agent-1-'+self.stage['id'],'agent',self.task,
            self.control,self.runroot/'state',self.stageid,'controlled-worker')
        bootstrap={'experiment':str(self.experiment),'intent':{'run_id':self.run,'attempt_id':self.attempt,'trial_id':self.trial},
            'application':{'schema':1,'plan_sha256':self.plan['plan_sha256'],'participant_keys_withheld':True},
            'credentials':{},'capability':'e'*64,'network':'pi-trial-fixture','inference':{'token':'f'*64}}
        self.remote=RemoteAdmission(mock.Mock(),bootstrap,mock.Mock())
        token=ownership_registry.CURRENT.set(self.remote);self.addCleanup(ownership_registry.CURRENT.reset,token)
        self.sink=[];runtime=self.plan['runtime']['resources']['runtime']
        self.args=argparse.Namespace(_parallel_session=self.remote,_application_execution={'plan':self.plan,'stage_id':self.stage['id'],
            'authority':None,'redaction_sink':lambda values:self.sink.append(list(values))},in_place=False,
            platform='linux/arm64',native_platform='linux/arm64',observed_pi_version=release,
            profile=self.plan['runtime']['container_profile'],browser_sandbox_policy='docker-default',
            resource_report={'effective':self.plan['runtime']['resources']},cpus=runtime['cpus'],memory=runtime['memory'],
            pids_limit=runtime['pids_limit'],jobs=runtime['jobs'],frozen_agent_profile=receipt)
        self.generation=fresh();self.paths=[];self.contexts=[];self.ordinal=0;self.charged=0;self.maximum=self.stage['limits']['max_tool_calls'];self.assisted=False
        self.remote.native_budget_begin=mock.Mock(side_effect=lambda stage,binding:self.parent_context(binding))
        self.remote.native_budget_continue=mock.Mock(side_effect=self.parent_continue)
        self.remote.native_budget_status=mock.Mock(side_effect=lambda stage:self.budget())
        self.remote.native_budget_checkpoint=mock.Mock(side_effect=lambda stage:self.budget())
        self.remote.native_budget_extend=mock.Mock(side_effect=self.parent_extend)
        self.remote.native_budget_close=mock.Mock(side_effect=self.parent_close)

    def coordinator(self):
        return RemoteApplicationCoordinator(lab,self.args,self.plan['runtime']['image_id'],self.runroot,
            self.workspace,self.desc,self.task,self.profile,[])

    def budget(self):
        limits={key:self.stage['limits'][key] for key in ('max_tool_calls','reporting_reserve_calls','reporting_reserve_seconds')}
        limits['max_tool_calls']=self.maximum
        counters={'attempted':self.charged,'charged':self.charged,'executed_known':0,'executed_unknown':0,
            'grants_consumed':0,'blocked':self.charged,'worker_observed':0,'helper_verified':0,'executed':0}
        empty={key:0 for key in counters};per={name:dict(empty) for name in [*self.stage['tools'],'__unknown__']}
        per['app_api']=dict(counters);remaining=self.maximum-self.charged
        return {'schema':1,'document_type':'native_tool_budget_status','phase':'business','accounting':'available','limits':limits,
            'counts':counters,'per_tool':per,'remaining_calls':remaining,'remaining_admissible_calls':remaining,
            'business_calls_remaining':max(0,remaining-limits['reporting_reserve_calls']),
            'reporting_reserve_calls_remaining':min(remaining,limits['reporting_reserve_calls']),'assisted':self.assisted}

    def parent_context(self,binding):
        self.ordinal+=1
        scope={**copy.deepcopy(binding),'stage_name':self.stage['id'],'participant':self.stage['participant'],
            'operation_ids':self.stage['operations'],'credential_aliases':self.stage['credential_aliases'],
            'authority_generation':self.generation}
        app,budget=('a'*64,'b'*64) if self.ordinal==1 else ('c'*64,'d'*64)
        context={'schema':1,'scope':scope,'capability':app,'base_url':'http://pi-application:8081/tool','tool_schemas':self.stage['tool_schemas'],
            'budget_context':{'schema':1,'pi_release':self.plan['runtime']['pi_release'],'scope':scope,'allowed_tools':self.stage['tools'],
                'prepare_arguments':{name:'none' for name in self.stage['tools']},'extension_order_sha256':self.extension,
                'tool_schema_sha256':c.digest(sorted(self.stage['tool_schemas'],key=lambda row:row['name'])),
                'base_url':'http://pi-application:8081/budget','capability':budget}}
        path=self.control/'segments'/binding['segment_id']/'application-context.json'
        controls.atomic(path,context,0o400);self.paths.append(path);self.contexts.append(copy.deepcopy(context))
        return {'context':copy.deepcopy(context),'network':self.remote.bootstrap['network'],'binding':copy.deepcopy(binding),'budget':self.budget()}

    def parent_continue(self,stage,command,segment):
        binding={key:self.contexts[-1]['scope'][key] for key in ('run_id','attempt_id','trial_id','stage_id','segment_id','session_id','plan_sha256')}
        binding['segment_id']=segment;return self.parent_context(binding)

    def parent_extend(self,stage,command,maximum,remaining):
        self.maximum=maximum;self.assisted=True;return self.budget()

    def parent_close(self,stage):
        for path in self.paths:path.unlink()
        root=self.runroot/'application-evidence'/('pi-application-'+'1'*16)/'private'
        root.mkdir(parents=True,mode=0o700,exist_ok=True)
        for name in ('raw','outputs'):(root/name).mkdir(parents=True,mode=0o700,exist_ok=True)
        scope=self.contexts[-1]['scope'];binding={key:scope[key] for key in ('run_id','trial_id','attempt_id','stage_id','segment_id','session_id','plan_sha256')}
        binding.update(profile_sha256=self.stage['profile_binding']['sha256'],
            release_contract_sha256=application_runtime_contracts.identity(self.plan['runtime']['pi_release'])['sha256'],
            report_contract_sha256=c.digest(self.stage['completion']),pi_release=self.plan['runtime']['pi_release'])
        return {'budget':self.budget(),'cleanup':{'schema':1,'status':'removed','workspace':'clean','safe_to_continue':True},
            'completion_context':{'binding':binding,'authorized_segment_ids':[item['scope']['segment_id'] for item in self.contexts],
                'report_root':str(root/'outputs'),'evidence_root':str(root/'raw'),'parent_receipts':{}}}

    def begin(self,co,directive=None):
        segment=fresh();folder=self.control/'segments'/segment;folder.mkdir(mode=0o700)
        return segment,co.begin_segment(segment,self.session,folder,directive)

    def settled(self,co):co.mark_running();return co.after_segment(True)

    def directive(self,co):
        return {'id':fresh(),'kind':'steer',**{key:co.binding[key] for key in ('run_id','attempt_id','stage_id','segment_id')},'message':'Explicit authorized continuation.'}

    def test_first_segment_reuses_parent_0400_file_without_authority_store_or_helper(self):
        with mock.patch.object(application_client.OwnedHelper,'start',side_effect=AssertionError('No helper')),\
             mock.patch.object(secret_store,'read_secret',side_effect=AssertionError('No credentials')),\
             mock.patch('subprocess.Popen',side_effect=AssertionError('No process')):
            co=self.coordinator();segment,reply=self.begin(co);before=self.paths[0].stat().st_ino
            self.assertEqual(reply['context_path'],'/opt/pi-control/segments/'+segment+'/application-context.json')
            self.assertEqual(self.paths[0].stat().st_ino,before);self.assertEqual(self.paths[0].stat().st_mode&0o777,0o400)
            co.mark_running();co.after_segment(True)
        self.assertFalse(hasattr(co,'authority'));self.assertFalse(hasattr(co,'helper'));self.assertFalse(hasattr(co,'pool'))
        self.assertEqual((self.runroot/'stages'/self.stageid).stat().st_mode&0o777,0o755)
        for value in ('a'*64,'b'*64,'e'*64,'f'*64):self.assertIn(value,co.redaction_values());self.assertIn(value,self.sink[-1])
        self.assertEqual((self.workspace/'original.txt').read_text(),'Protected original.\n')

    def test_continuation_carries_exact_session_counts_and_never_creates_control_intents(self):
        co=self.coordinator();self.begin(co);self.charged=1;self.settled(co);directive=self.directive(co)
        with mock.patch.object(application_execution.NativeCoordinator,'_command',side_effect=AssertionError('No duplicate control intent')):
            self.begin(co,directive)
        self.assertEqual(co._cached['counts']['charged'],1);self.assertEqual(co.binding['session_id'],self.session)
        self.assertEqual(self.remote.native_budget_continue.call_args.args[1],directive['id'])
        for value in ('a'*64,'b'*64,'c'*64,'d'*64):self.assertIn(value,co.redaction_values())
        self.assertFalse((self.runroot/'stages'/self.stageid/'native-budget-execution').exists())

    def test_normal_settlement_never_automatically_continues_or_repairs(self):
        co=self.coordinator();self.begin(co);self.settled(co)
        self.remote.native_budget_continue.assert_not_called()
        with self.assertRaises(ApplicationExecutionError):self.begin(co)
        self.remote.native_budget_continue.assert_not_called()

    def test_extension_forwards_parent_command_once_and_preserves_counts(self):
        co=self.coordinator();self.begin(co);self.charged=1;co.status(force=True)
        command=fresh();result=co.extend(command,self.maximum+2,120.5)
        self.assertEqual(result['counts']['charged'],1);self.assertTrue(result['assisted'])
        self.assertEqual(self.remote.native_budget_extend.call_args.args[1],command)
        with self.assertRaises(ApplicationExecutionError):co.extend(command,self.maximum+2,120.5)
        self.assertEqual(self.remote.native_budget_extend.call_count,1)

    def test_parent_close_purges_context_child_only_checks_absence_and_roots(self):
        co=self.coordinator();self.begin(co);self.settled(co)
        reply=self.parent_close(self.stageid);self.remote.native_budget_close=mock.Mock(return_value=reply)
        with mock.patch('os.unlink',side_effect=AssertionError('Child must not purge parent context')):
            cleanup=co.close(True)
        self.assertTrue(cleanup['safe_to_continue']);self.assertEqual(co.completion_context,reply['completion_context'])
        self.assertEqual(co.close(True),cleanup);self.assertEqual(self.remote.native_budget_close.call_count,1)

    def test_unknown_writer_blocks_checkpoint_and_close_before_parent_requests(self):
        co=self.coordinator();self.begin(co);co.mark_running()
        with self.assertRaises(ApplicationExecutionError):co.after_segment(False)
        self.remote.native_budget_checkpoint.assert_not_called()
        with self.assertRaises(ApplicationExecutionError):co.close(False)
        self.remote.native_budget_close.assert_not_called();self.assertTrue(self.paths[0].exists())

    def test_retained_context_after_claimed_clean_parent_close_is_unconfirmed_not_unlinked(self):
        co=self.coordinator();self.begin(co);self.settled(co)
        reply=self.parent_close(self.stageid);controls.atomic(self.paths[0],self.contexts[0],0o400)
        self.remote.native_budget_close=mock.Mock(return_value=reply)
        with self.assertRaises(ApplicationExecutionError):co.close(True)
        self.assertTrue(self.paths[0].exists());self.assertTrue(co.failed)

    def test_parent_context_permission_scope_schema_and_guard_changes_fail_closed(self):
        for fault in ('mode','actor','schema','guard','same-token'):
            with self.subTest(fault=fault):
                co=self.coordinator();original=self.parent_context
                def changed(binding):
                    reply=original(binding)
                    if fault=='mode':self.paths[-1].chmod(0o600)
                    elif fault=='actor':reply['context']['scope']['participant']={**self.stage['participant'],'role':'other'}
                    elif fault=='schema':reply['context']['tool_schemas']=[]
                    elif fault=='guard':reply['context']['budget_context']['extension_order_sha256']='0'*64
                    else:reply['context']['budget_context']['capability']=reply['context']['capability']
                    return reply
                self.remote.native_budget_begin.side_effect=lambda stage,binding:changed(binding)
                with self.assertRaises(ApplicationExecutionError):self.begin(co)
                self.assertTrue(co.failed)
                # Start each independent parent protocol fixture with fresh caps.
                for path in self.paths:path.unlink(missing_ok=True)
                self.paths=[];self.contexts=[];self.ordinal=0

    def test_bootstrap_with_keys_or_fake_authority_or_unowned_channel_rejects_before_rpc(self):
        for fault in ('marker','keys','authority','channel'):
            with self.subTest(fault=fault):
                bootstrap=copy.deepcopy(self.remote.bootstrap);spec=dict(self.args._application_execution)
                if fault=='marker':self.remote.bootstrap['application']['participant_keys_withheld']=False
                elif fault=='keys':self.remote.bootstrap['credentials']={'participant':{'PI_APP_ALIAS_0':'must-not-enter-child'}}
                elif fault=='authority':self.args._application_execution['authority']=object()
                else:self.args._parallel_session=mock.Mock(spec=RemoteAdmission)
                with self.assertRaises(ApplicationExecutionError):self.coordinator()
                self.remote.bootstrap=bootstrap;self.args._application_execution=spec;self.args._parallel_session=self.remote
        self.remote.native_budget_begin.assert_not_called()

    def test_frozen_prompt_runtime_or_extension_change_rejects_before_rpc(self):
        for fault in ('prompt','runtime','guard'):
            with self.subTest(fault=fault):
                if fault=='prompt':
                    original=self.task['prompt'];self.task['prompt']+=' changed'
                elif fault=='runtime':original=self.args.jobs;self.args.jobs+=1
                else:
                    path=self.runroot/'trusted-runtime/tool-budget.mjs';original=path.read_bytes();path.write_bytes(b'changed')
                with self.assertRaises(ApplicationExecutionError):self.coordinator()
                if fault=='prompt':self.task['prompt']=original
                elif fault=='runtime':self.args.jobs=original
                else:path.write_bytes(original)
        self.remote.native_budget_begin.assert_not_called()

    def test_owner_loss_or_counter_reset_never_falls_back_to_local_helper(self):
        co=self.coordinator();self.begin(co);self.charged=1;co.status(force=True);self.charged=0
        with self.assertRaises(ApplicationExecutionError):co.status(force=True)
        other=self.coordinator();self.remote.owner_lost=True
        with self.assertRaises(ApplicationExecutionError):other.status(force=True)
        self.remote.native_budget_continue.assert_not_called()

    def test_completion_context_cannot_redirect_to_workspace_or_other_stage(self):
        co=self.coordinator();self.begin(co);self.settled(co);reply=self.parent_close(self.stageid)
        reply['completion_context']['report_root']=str(self.workspace)
        self.remote.native_budget_close=mock.Mock(return_value=reply)
        with self.assertRaises(ApplicationExecutionError):co.close(True)
        self.assertIsNone(co.completion_context)

    def test_completion_rejects_old_wrapper_layout_before_reading_outputs(self):
        co=self.coordinator();self.begin(co);self.settled(co);reply=self.parent_close(self.stageid)
        context=reply['completion_context'];wrapper=Path(context['report_root']).parent.parent
        for name in ('outputs','raw'):(wrapper/name).mkdir(mode=0o700)
        context.update(report_root=str(wrapper/'outputs'),evidence_root=str(wrapper/'raw'))
        self.remote.native_budget_close=mock.Mock(return_value=reply)
        with mock.patch('application_remote.open_directory',side_effect=AssertionError('Wrong namespace must fail before reads')):
            with self.assertRaises(ApplicationExecutionError):co.close(True)
        self.assertIsNone(co.completion_context)

    def test_replaced_context_parent_directory_is_not_accepted_as_confirmed_purge(self):
        co=self.coordinator();self.begin(co);self.settled(co);reply=self.parent_close(self.stageid)
        parent=self.paths[0].parent;parent.rename(parent.with_name(parent.name+'-moved'));parent.mkdir(mode=0o700)
        self.remote.native_budget_close=mock.Mock(return_value=reply)
        with self.assertRaises(ApplicationExecutionError):co.close(True)
        self.assertIsNone(co.completion_context)

    def test_parent_denied_continuation_or_unknown_channel_blocks_without_fallback(self):
        co=self.coordinator();self.begin(co);self.settled(co);directive=self.directive(co)
        self.remote.native_budget_continue.side_effect=ValueError('Controlled parent audit denial')
        with self.assertRaises(ApplicationExecutionError):self.begin(co,directive)
        self.assertTrue(co.failed);self.assertEqual(self.remote.native_budget_continue.call_count,1)
        other=self.coordinator();self.remote.native_budget_begin.side_effect=EOFError('Controlled owner loss')
        with self.assertRaises(ApplicationExecutionError):self.begin(other)
        self.assertTrue(other.failed)


if __name__=='__main__':unittest.main()
