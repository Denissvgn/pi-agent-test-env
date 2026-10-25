"""Host-parent application helpers for the frozen two-trial runner.

Workers select only already-admitted stage/segment IDs. Original application and
inference values, authority construction and helper control remain in this owner.
"""
import copy
import hashlib
import os
from pathlib import Path

import agent_profiles
import application_completion
import application_contracts as c
import application_credentials as credentials
import application_execution
from application_execution_authority import ReviewedAuthority
from application_evidence import open_directory,read_file
import application_preparation
from parallel_native_budget import NativeAllocator,_HeldHelperSlot,_read_owned,stop_owned_worker
from parallel_contract import ParallelError,native_helper,NATIVE_HELPER_RESOURCES,NATIVE_BROWSER_HELPER_RESOURCES
import release_contracts
import resources
import stage_control as controls


class _IncompleteStage(ParallelError):
    """Report/invocation failure with independently confirmed clean writers."""


def _relative(root,value):
    c.relative(value,'/frozen_path');path=Path(root)/value
    # All actual reads also walk no-follow; resolve is never used to authorize.
    return path


def _values(values):
    if type(values) not in (list,tuple) or len(values)>1024:raise ParallelError('Application private corpus exceeds its bound')
    for value in values:c.text(value,'/redaction_values',16384,empty=True)
    result=list(dict.fromkeys(value for value in values if value))
    if len(c.canonical(result))>2*1024*1024:raise ParallelError('Application private corpus exceeds its byte bound')
    return result


class _ApplicationSlot(_HeldHelperSlot):
    def __init__(self,pool,trial_id,plan_sha256,actors,worker):
        super().__init__(pool,trial_id,plan_sha256);self.actors=list(actors);self.worker=worker
    @property
    def closed(self):return self.pool.closed
    @property
    def dependent_cleanup_confirmed(self):return getattr(self.pool,'dependent_cleanup_confirmed',True)
    @dependent_cleanup_confirmed.setter
    def dependent_cleanup_confirmed(self,value):self.pool.dependent_cleanup_confirmed=value
    def stop(self):self.pool.stop()
    def request(self,identity,binding,resources,wait_seconds,kind='helper'):
        expected={'generation':self.pool.generation,'credential_authorities':self.actors,'plan_sha256':self.plan_sha256}
        if (self.in_use or self.pool.closed or self.item.state!='reserved' or kind!='helper'
                or resources!=self.pool.native_helper_resources or binding!=expected
                or type(wait_seconds) not in (int,float) or not 0<wait_seconds<=3600):
            raise ParallelError('Application helper differs from held actor/resource admission')
        self.item.binding={**copy.deepcopy(binding),'trial_id':self.trial_id};self.in_use=True;return self.item
    def running(self,identity):
        if identity==self.worker.identity:return self.pool.running(identity)
        return super().running(identity)


class ApplicationCohort:
    def __init__(self,root,metadata,matrix,work,lab,args,registry,*,authorities_by_trial,redaction_values,per_trial_redaction):
        self.root=Path(root).absolute();self.metadata=copy.deepcopy(metadata);self.lab,self.args,self.registry=lab,args,registry
        self.resource_class=native_helper(metadata.get('concurrency',{}))
        if self.resource_class is None:raise ParallelError('Explicit application helper topology required')
        self.pool=None;self.release=None;self.cells={};self.plans={};self.entries={};self.profiles={};self.admissions={};self.peers={};self.runner_files={}
        self._values=_values(redaction_values);self._trial_values=copy.deepcopy(per_trial_redaction or {});self._original_values=[]
        if type(authorities_by_trial) is not dict or type(per_trial_redaction) is not dict:raise ParallelError('Private application admission mapping required')
        known={cell['trial_id'] for cell in matrix['cells']}
        if set(authorities_by_trial)-known or set(self._trial_values)-known:raise ParallelError('Foreign application trial admission')
        for cell in work:
            trial=cell['trial_id'];entry=authorities_by_trial.get(trial)
            if type(entry) is not dict or not {'plan','endpoint','inference_key','store','project','inference_authorities','browser_admission'}<=set(entry) or set(entry)-{'plan','endpoint','inference_key','store','project','inference_authorities','browser_admission','sealed_inputs'}:
                raise ParallelError('Exact parent application authority declaration required')
            plan=c.validate_ir(_read_owned(_relative(self.root,cell['plan']),maximum=2*1024*1024))
            compiled=application_preparation.load_compiled(_relative(self.root,cell['compiled_plan']),verify_runner=True)
            if plan!=compiled['plan'] or plan!=entry['plan'] or cell['plan_sha256']!=plan['plan_sha256']:raise ParallelError('Final application IR identity changed')
            runtime=plan['runtime'];execution=metadata['execution']
            if 'resources' not in execution:policy=_read_owned(self.root/'inputs/resources.json')
            elif type(execution['resources']) is dict:policy=execution['resources']
            elif type(execution['resources']) is str:policy=_read_owned(_relative(self.root,execution['resources']))
            else:raise ParallelError('Frozen application resource policy declaration invalid')
            if (runtime['image_id']!=execution['image'] or runtime['platform']!='linux/arm64' or execution['platform']!='linux/arm64'
                    or runtime['container_profile']!=execution.get('profile','core')
                    or not application_execution._same_policy(policy,runtime['resources'])):raise ParallelError('Application runtime differs from frozen cohort')
            actual=NATIVE_BROWSER_HELPER_RESOURCES if plan['application']['browser_targets'] else NATIVE_HELPER_RESOURCES
            if actual!=self.resource_class:raise ParallelError('Mixed or mismatched application helper resource class')
            inference=c.loads(agent_profiles.read_asset(Path(compiled['root'])/'inference.json'))
            if inference.get('kind')=='variant':
                c.exact(inference,{'kind','variant_id','stages'},'/inference');c.slug(inference['variant_id'],'/inference/variant_id')
                if 'variant' in cell and inference['variant_id']!=cell['variant']:raise ParallelError('Frozen application variant changed')
                c.exact(inference['stages'],{stage['id'] for stage in plan['stages']},'/inference/stages');selected=inference['stages']
            else:selected={stage['id']:inference for stage in plan['stages']}
            endpoints={};configuration_ids=set()
            for stage in plan['stages']:
                record=selected[stage['id']];c.exact(record,{'kind','selection','configuration','catalog_entry'},'/inference/stage')
                if (record['kind']!=stage['inference_binding']['kind'] or record['selection']!=stage['inference_binding']['selection']
                        or c.digest(record['configuration'])!=stage['inference_binding']['configuration_sha256']):
                    raise ParallelError('Application per-stage inference binding changed')
                if record['kind']=='legacy':endpoint=record['configuration'];reference=endpoint['api_key_env']
                elif record['kind']=='indexed':endpoint=record['configuration']['endpoint'];reference=record['configuration']['credential'].get('name')
                else:raise ParallelError('Unsupported application inference binding')
                configuration=stage['inference_binding']['configuration_sha256'];configuration_ids.add(configuration)
                if entry['inference_authorities'].get(configuration,{}).get('reference')!=reference:
                    raise ParallelError('Application per-stage inference authority reference changed')
                endpoints[stage['id']]=endpoint
            first=plan['stages'][0];endpoint=endpoints[first['id']]
            if (set(entry['inference_authorities'])!=configuration_ids or
                    entry['inference_authorities'][first['inference_binding']['configuration_sha256']]['value']!=entry['inference_key']):
                raise ParallelError('Application inference authority set differs')
            browser=c.loads(agent_profiles.read_asset(Path(compiled['root'])/'runtime-receipt.json'))['browser_admission']
            project=_relative(self.root,cell['source']);directory=open_directory(project);os.close(directory)
            if Path(entry['project']).absolute()!=project or entry['endpoint']!=endpoint or entry['browser_admission']!=browser:
                raise ParallelError('Private application authority differs from prepared inputs')
            self.cells[trial]=copy.deepcopy(cell);self.plans[trial]=plan;self.entries[trial]=copy.deepcopy(entry)
            self.runner_files[trial]=copy.deepcopy(compiled['manifest']['runner']['files'])
            profile=agent_profiles.load(Path(compiled['root'])/'profiles'/plan['stages'][0]['id']/'profile.json');self.profiles[trial]=profile
            # Credential/reference admission occurs before the parent's image
            # probe. This authority is never granted or launched.
            authority=self._authority(trial,self.root/'application-admission'/trial,{})
            authority.revalidate();self.admissions[trial]=authority
            original=[*authority._inference_values,*(value for aliases in authority._values.values() for value in aliases.values())]
            self._original_values=_values([*self._original_values,*original]);self.add_redaction_values(original)
        self.native_trials=set(self.cells)
        redactor=credentials.Redactor(self._values)
        for trial,plan in self.plans.items():
            compiled_root=_relative(self.root,self.cells[trial]['compiled_plan']).parent
            if (redactor.contains(c.canonical(plan)) or not credentials.workspace_inspected_clean(Path(self.entries[trial]['project']),redactor)
                    or not credentials.workspace_inspected_clean(compiled_root,redactor)):
                raise ParallelError('Known private authority appears in application input')

    def _private_values(self,trial):return _values([*self._values,*self._trial_values.get(trial,[])])
    def _authority(self,trial,runroot,sealed):
        entry=self.entries[trial]
        return ReviewedAuthority(self.plans[trial],entry['endpoint'],entry['inference_key'],entry['store'],entry['project'],runroot,
            inference_authorities=entry['inference_authorities'],browser_admission=entry['browser_admission'],
            sealed_inputs={**entry.get('sealed_inputs',{}),**sealed},redaction_values=tuple(self._private_values(trial)),
            runner_files=self.runner_files[trial])
    def authorities(self,trial):
        plan=self.plans[trial]
        return sorted(set(plan['application']['credentials'].values())|{'application-actor:'+c.digest(stage['participant']) for stage in plan['stages']})
    def add_redaction_values(self,values,trial_id=None):
        target=self._values if trial_id is None else self._trial_values.setdefault(trial_id,[])
        updated=_values([*target,*values])
        if trial_id is not None:_values([*self._values,*updated])
        else:
            for private in self._trial_values.values():_values([*updated,*private])
        target[:]=updated
    def allocator(self,capacity,max_stages=2,max_pending=16):
        return NativeAllocator(capacity,max_stages,max_pending,native_trials=self.native_trials,
            generation=self.registry.generation,helper_resources=self.resource_class)
    def attach(self,pool):
        if (not isinstance(pool,NativeAllocator) or pool.native_trials!=self.native_trials
                or pool.native_helper_resources!=self.resource_class or getattr(self.registry,'_native_budget_cohort',self) is not self):
            raise ParallelError('Application helper pool admission differs')
        self.pool=pool;self.registry._native_budget_cohort=self
    def admit_release(self,release):
        if release not in ('0.87.1','1.2.0') or any(plan['runtime']['pi_release']!=release for plan in self.plans.values()):
            raise ParallelError('Application exact Pi release differs')
        self.release=release
    def bind(self,peer):
        trial=peer.bootstrap.get('intent',{}).get('trial_id')
        if trial not in self.cells:return None
        if self.release is None or peer.allocator is not self.pool or trial in self.peers:raise ParallelError('Application cohort runtime not admitted or trial already bound')
        marker={'schema':1,'plan_sha256':self.plans[trial]['plan_sha256'],'participant_keys_withheld':True}
        if peer.bootstrap.get('credentials',{}) or ('application' in peer.bootstrap and c.canonical(peer.bootstrap['application'])!=c.canonical(marker)):
            raise ParallelError('Worker bootstrap cannot acquire application keys or change its marker')
        peer.bootstrap['application']=marker
        result=ApplicationPeer(self,peer);self.peers[trial]=result;return result
    def admit_inference_stage(self,trial,stage_name,renew=False):
        """Parent model activation gate; no catalog calls or token values here."""
        if type(renew) is not bool or trial not in self.plans or self.pool is None or self.pool.closed:
            raise ParallelError('Application inference stage admission unavailable')
        names=[stage['id'] for stage in self.plans[trial]['stages']];peer=self.peers.get(trial)
        if peer is None:
            if stage_name!=names[0] or renew:raise ParallelError('Only first frozen model stage can activate before worker binding')
        elif peer.failed or peer.finalized:raise ParallelError('Application inference owner is unavailable')
        elif peer.coordinator is None:
            if renew or len(peer.closed)>=len(names) or stage_name!=names[len(peer.closed)]:
                raise ParallelError('Application model activation differs from next frozen stage')
            for previous in peer.closed:peer._proof(previous,True)
        else:
            key=(peer.current['stage_id'],peer.current['segment_id'])
            if (not renew or stage_name!=peer.coordinator.stage['id'] or not peer.coordinator._settled
                    or peer.peer.active is not None or key in peer.inference_renewed):
                raise ParallelError('Application model renewal requires the stopped current segment')
            peer.inference_renewed.add(key)
        self.admissions[trial].revalidate();return True


class ApplicationPeer:
    def __init__(self,cohort,peer):
        self.cohort,self.peer=cohort,peer;self.trial_id=peer.bootstrap['intent']['trial_id'];self.plan=cohort.plans[self.trial_id]
        actors=sorted({'application-actor:'+c.digest(stage['participant']) for stage in self.plan['stages']})
        self.slot=_ApplicationSlot(peer.allocator,self.trial_id,self.plan['plan_sha256'],actors,peer.reservation)
        self.coordinator=None;self.current=None;self.context=None;self.closed=[];self.failed=False;self.finalized=False;self.sealed={};self.continuation_proof=None;self.inference_renewed=set()
        marker={'schema':1,'plan_sha256':self.plan['plan_sha256'],'participant_keys_withheld':True}
        if (c.canonical(peer.bootstrap.get('application'))!=c.canonical(marker) or peer.bootstrap.get('credentials',{})
                or credentials.Redactor(cohort._values).contains(c.canonical(peer.bootstrap))):self._error()
    def _error(self):
        self.failed=True;self.peer.allocator.dependent_cleanup_confirmed=False;self.slot.quarantine();self.peer.allocator.stop()
        raise ParallelError('Application helper ownership or cleanup unavailable')
    def _stage(self,stage_id):
        if self.failed or self.finalized or self.coordinator is None or self.current['stage_id']!=stage_id:self._error()
    def _network(self):
        matches=[row for row in self.peer.registry.load() if row.get('kind')=='network' and row.get('container')==self.peer.bootstrap['network']
            and row.get('registry')==self.peer.registry.registry_id and row.get('generation')==self.peer.registry.generation
            and row.get('daemon')==self.peer.registry.daemon and row.get('status') in ('intent','running')]
        if len(matches)!=1:self._error()
        return matches[0]
    def _task(self,stage,profile):
        extension=application_execution.extension_order_sha256(stage,profile,runtime_root=self.peer.runroot/'trusted-runtime')
        return {'name':stage['id'],'prompt':stage['effective_prompt'],'tools':copy.deepcopy(stage['tools']),
            'tool_schemas':copy.deepcopy(stage['tool_schemas']),'require_tools':[],'cwd':'.','access':'ro',**stage['limits'],
            'application_execution':{'schema':1,'plan_sha256':self.plan['plan_sha256'],'stage_id':stage['id'],
                'effective_prompt_sha256':hashlib.sha256(stage['effective_prompt'].encode()).hexdigest(),
                'tool_schema_sha256':c.digest(sorted(stage['tool_schemas'],key=lambda item:item['name'])),
                'profile_binding':copy.deepcopy(stage['profile_binding']),'extension_order_sha256':extension}}
    def _proof(self,item,require_complete):
        stage=item['stage'];desc=item['desc'];folder=self.peer.runroot/'stages'/desc['stage_id']
        state=_read_owned(folder/'state.json');credential=_read_owned(folder/'application-credentials.json')
        process=_read_owned(self.peer.runroot/desc['label']/'process.json',maximum=2*1024*1024)
        if (state.get('status')!='finalized' or state.get('cleanup_confirmed') is not True
                or credential.get('status')!='removed' or credential.get('workspace')!='clean'
                or process.get('cleanup_confirmed') is not True or 'native_tool_budget_error' in process
                or item['cleanup'].get('safe_to_continue') is not True
                or any(record.get('status') not in ('absent','released') for record in self.peer.records
                       if record.get('binding',{}).get('stage_id')==desc['stage_id'])
                or any((Path(desc['control'])/'segments').glob('*/application-context.json'))):self._error()
        actual={**process,'application_helper_cleanup':item['cleanup']}
        verdict=application_completion.stage_result(stage,item['context'],actual,credential)['projection']
        if require_complete and (verdict['status']!='complete' or process.get('evidence',{}).get('completion_verified') is not True):
            self.peer.allocator.stop();raise _IncompleteStage('Prior application stage did not independently complete')
        if verdict['status']=='complete':
            root=open_directory(item['context']['report_root'])
            try:
                report=c.validate_report(c.loads(read_file(root,stage['completion']['report_path'],65536)))
                expected={row['id']:row for row in report['artifacts']}
                for artifact in stage['completion']['artifacts']:
                    body=read_file(root,artifact['path'],artifact['max_bytes']);reported=expected[artifact['id']]
                    if (credentials.Redactor(self.cohort._private_values(self.trial_id)).contains(body)
                            or len(body)!=reported['bytes'] or hashlib.sha256(body).hexdigest()!=reported['sha256']):self._error()
                    self.sealed[(stage['id'],artifact['id'])]=body
            finally:os.close(root)
        return verdict
    def _reply(self,budget):return {'context':copy.deepcopy(self.context),'network':self.peer.bootstrap['network'],'binding':copy.deepcopy(self.current),'budget':budget}
    def begin(self,stage_name,binding):
        if self.failed or self.finalized or self.coordinator is not None or self.peer.active is not None:self._error()
        try:
            from application_client import _binding
            _binding(binding,self.plan['plan_sha256']);intent=self.peer.bootstrap['intent']
            if (any(binding[key]!=intent[key] for key in ('run_id','attempt_id','trial_id'))
                    or self.peer.runroot!=self.cohort.root/'runs'/intent['run_id']):self._error()
            if len(self.closed)>=len(self.plan['stages']) or self.plan['stages'][len(self.closed)]['id']!=stage_name:self._error()
            for previous in self.closed:self._proof(previous,True)
            cell=self.cohort.cells[self.trial_id]
            if (application_preparation.load_compiled(_relative(self.cohort.root,cell['compiled_plan']),verify_runner=True)['plan']!=self.plan
                    or _read_owned(_relative(self.cohort.root,cell['plan']),maximum=2*1024*1024)!=self.plan):self._error()
            stage=self.plan['stages'][len(self.closed)];desc=_read_owned(self.peer.runroot/'stages'/binding['stage_id']/'descriptor.json')
            if (any(desc.get(key)!=binding[key] for key in ('run_id','attempt_id','stage_id')) or desc.get('workspace')!=str(self.peer.runroot/'workspace')
                    or desc.get('label')!='agent-'+str(len(self.closed)+1)+'-'+stage_name):self._error()
            self.cohort.admissions[self.trial_id].revalidate()
            profile=agent_profiles.staged({'root':str(self.peer.runroot/'agent-profile'),'sha256':stage['profile_binding']['sha256']})
            task=self._task(stage,profile);authority=self.cohort._authority(self.trial_id,self.peer.runroot,self.sealed)
            options=copy.copy(self.cohort.args);options.uid,options.gid=os.getuid(),os.getgid()
            options.project=str(self.cohort.entries[self.trial_id]['project']);options.network=self.peer.bootstrap['network']
            options.frozen_agent_profile={'root':str(self.peer.runroot/'agent-profile'),'sha256':stage['profile_binding']['sha256']}
            options._parallel_session=None;options._indexed_session=None;options.observed_pi_version=self.cohort.release
            options._application_execution={'plan':self.plan,'stage_id':stage_name,'authority':authority,
                'external_support':{'pool':self.slot,'reservation':self.peer.reservation,'registry':self.peer.registry,'network_record':self._network()},
                'redaction_sink':lambda values:self.cohort.add_redaction_values(values,self.trial_id)}
            self.coordinator=application_execution.ApplicationCoordinator(self.cohort.lab,options,self.plan['runtime']['image_id'],
                self.peer.runroot,self.peer.runroot/'workspace',desc,task,profile,self.cohort._private_values(self.trial_id))
            self.current=copy.deepcopy(binding)
            self.coordinator.begin_segment(binding['segment_id'],binding['session_id'],Path(desc['control'])/'segments'/binding['segment_id'])
            self.current=copy.deepcopy(binding);self.context=copy.deepcopy(self.coordinator.context)
            self.continuation_proof=None
            return self._reply(self.coordinator.status(force=True))
        except _IncompleteStage:raise
        except (OSError,ValueError,KeyError,TypeError):self._error()
    def status(self,stage_id):
        self._stage(stage_id)
        try:return self.coordinator.status(force=True)
        except (OSError,ValueError):self._error()
    def checkpoint(self,stage_id):
        self._stage(stage_id)
        if self.peer.active is not None:self._error()
        try:return self.coordinator.after_segment(True)
        except (OSError,ValueError):self._error()
    def extend(self,stage_id,command_id,max_tool_calls,remaining_seconds):
        self._stage(stage_id)
        try:return self.coordinator.extend(command_id,max_tool_calls,remaining_seconds)
        except (OSError,ValueError):self._error()
    def continuation(self,stage_id,command_id,segment_id):
        self._stage(stage_id)
        if self.peer.active is not None or not controls.valid_id(command_id) or not controls.valid_id(segment_id):self._error()
        try:
            directive=_read_owned(Path(self.coordinator.desc['control'])/'inbox/directives'/(command_id+'.json'))
            previous=self.current['segment_id']
            self.coordinator.begin_segment(segment_id,self.current['session_id'],Path(self.coordinator.desc['control'])/'segments'/segment_id,directive)
            self.current['segment_id']=segment_id;self.context=copy.deepcopy(self.coordinator.context)
            self.continuation_proof={'schema':1,'command_id':command_id,'continues_segment_id':previous,
                'message':directive['message'],'sha256':hashlib.sha256(directive['message'].encode()).hexdigest()}
            return self._reply(self.coordinator.status(force=True))
        except (OSError,ValueError,KeyError,TypeError):self._error()
    def close(self,stage_id):
        self._stage(stage_id)
        if self.peer.active is not None:self._error()
        try:
            cleanup=self.coordinator.close(True);context=self.coordinator.completion_context;budget=copy.deepcopy(cleanup['budget'])
            self.closed.append({'stage':self.coordinator.stage,'desc':self.coordinator.desc,'cleanup':cleanup,'context':context})
            self.coordinator=None;self.current=None;self.context=None
            return {'budget':budget,'cleanup':cleanup,'completion_context':copy.deepcopy(context)}
        except (OSError,ValueError,KeyError,TypeError):self._error()
    def validate_agent_launch(self,argv,binding):
        try:
            index=argv.index('/opt/pi-lab/worker.py');tail=argv[index+1:]
            if tail[:1]!=['agent']:return
            if set(binding)!={'stage_id','segment_id'} or any(not controls.valid_id(value) for value in binding.values()):self._error()
            self._stage(binding['stage_id'])
            if self.current['segment_id']!=binding['segment_id'] or tail!=['agent','--task','/opt/pi-control/segments/'+binding['segment_id']+'/task.json']:self._error()
            folder=Path(self.coordinator.desc['control'])/'segments'/binding['segment_id'];task=_read_owned(folder/'task.json')
            frozen=self.coordinator.task
            if any(c.canonical(task.get(key))!=c.canonical(value) for key,value in frozen.items()):self._error()
            allowed=set(frozen)|{'session_id','prior_turns','prior_reported_tokens','prior_usage_known','pi_release','allowed_tools','release_contract',
                'application_context','agent_profile_context','resume_session','application_continuation'}
            if (set(task)-allowed or task.get('session_id')!=self.current['session_id'] or task.get('pi_release')!=self.cohort.release
                    or task.get('allowed_tools')!=self.coordinator.allowed_tools or task.get('release_contract')!=release_contracts.identity(self.cohort.release)
                    or task.get('application_context')!='/opt/pi-control/segments/'+binding['segment_id']+'/application-context.json'
                    or task.get('agent_profile_context')!='/opt/pi-control/segments/'+binding['segment_id']+'/profile-context.json'
                    or _read_owned(folder/'application-context.json',private=True,maximum=65536)!=self.context):self._error()
            if self.continuation_proof is None:
                if 'application_continuation' in task or 'resume_session' in task:self._error()
            elif (c.canonical(task.get('application_continuation'))!=c.canonical(self.continuation_proof)
                    or task.get('resume_session')!='/opt/pi-control/segments/'+binding['segment_id']+'/session.jsonl'):self._error()
            if not self.coordinator._running:self.coordinator.mark_running()
        except (OSError,ValueError,KeyError,TypeError):self._error()
    def finalize(self):
        if self.finalized:return True
        if self.peer.active is not None:
            stop_owned_worker(self.peer)
        if self.coordinator is not None:
            try:
                # Parent finalization must still stop a partially started helper
                # after a denied request; failed public methods cannot skip it.
                cleanup=self.coordinator.close(self.peer.active is None)
                self.closed.append({'stage':self.coordinator.stage,'desc':self.coordinator.desc,'cleanup':cleanup,'context':self.coordinator.completion_context})
                self.coordinator=None;self.current=None;self.context=None
            except (OSError,ValueError):self._error()
        try:
            for item in self.closed:self._proof(item,False)
            if self.failed:self._error()
            self.slot.finalize();self.finalized=True;return True
        except (OSError,ValueError,KeyError,TypeError):self._error()
