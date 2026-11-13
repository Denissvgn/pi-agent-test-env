"""Versioned attempt records and one-way finalization, independent of Docker."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import uuid

import stage_control as controls
from resources import admission_diagnostic
from application_credentials import CredentialError


def initial():
    return {'schema':2,'document_type':'run_result','run_id':str(uuid.uuid4()),
            'attempt_id':str(uuid.uuid4()),'experiment_id':None,'trial_id':None,
            'attempt_index':1,'retry_of_attempt_id':None,'status':'RUNNING',
            'started_at':controls.now(),'run_dir':None,'workspace':None,
            'infrastructure':{'status':'not_started','phase':'evidence_destination','reason':None},
            'invocation':{'status':'not_started','attempted_stages':0},
            'termination':{'reason':'not_started','trigger':None,'process_exit_code':None},
            'scoring':{'status':'not_started','reason':None,'results':[]},
            'task_result':{'status':'unknown','score':None,'test_counts':None},
            'assistance':{'status':'autonomous','intervention_ids':[]},
            'protected_inputs':{'status':'unknown'},'agents':[],'checks':[],'sealed':False}


def status(record):
    if record['termination']['reason']=='cancelled':return 'INTERRUPTED',2
    if record['infrastructure']['status']!='ready' and record['invocation']['status']=='not_started':return 'BLOCKED',2
    native_ok=True
    import native_budget_reporting
    declared=record.get('native_tool_budgets')
    try:
        required=[]
        if declared is not None:
            if (type(declared) is not dict or set(declared)!={'schema','scope','stages'}
                    or type(declared['schema']) is not int or declared['schema']!=1
                    or declared['scope']!=native_budget_reporting.SCOPE
                    or type(declared['stages']) is not list or not 1<=len(declared['stages'])<=8):raise ValueError()
            required=[stage['stage'] for stage in declared['stages']]
        native=native_budget_reporting.record_projection(record,required_stages=required)
        if native is not None:
            native_ok=all(stage['accounting']=='available' and stage['error'] is None for stage in native['stages'])
        if declared is not None and native!=declared:native_ok=False
    except (KeyError,ValueError,TypeError):native_ok=False
    application_ok=True
    if 'application_execution' in record or 'application_completion' in record:
        import application_completion
        try:
            marker=record.get('application_execution')
            if (type(marker) is not dict or set(marker)!={'schema','plan_sha256','required_stages'}
                    or type(marker['schema']) is not int or marker['schema']!=1):raise ValueError()
            import application_contracts
            application_contracts.sha256(marker['plan_sha256'],'/application_execution/plan_sha256')
            application_contracts.unique_strings(marker['required_stages'],'/application_execution/required_stages',8,1)
            application_ok=application_completion.gate(record.get('application_completion'),required_stages=marker['required_stages'])
        except (ValueError,TypeError,KeyError):application_ok=False
    gates=(native_ok and application_ok and record['infrastructure']['status']=='ready' and record['termination']['reason']=='completed'
           and record['invocation']['status'] in ('verified','recovered')
           and record['scoring']['status']=='completed' and record['task_result']['status']=='pass'
           and record['protected_inputs']['status']=='unchanged')
    if not gates:return 'FAIL',1
    if record['invocation']['status']=='recovered':return 'RECOVERED',1
    if record['assistance']['status']=='assisted':return 'ASSISTED',1
    return 'PASS',0


# One closed outcome for callers. Derived from recorded fields and retained trace
# evidence only; never from log text. EVALUATION-CONTRACT.md lists the precedence.
VERDICT_OUTCOMES=('pass','pass_recovered','pass_assisted','check_failed','agent_incomplete','protected_input_changed',
                  'turn_limit','token_limit','repeated_tool_call','agent_timeout','log_limit','out_of_memory',
                  'endpoint_unreachable','endpoint_auth_failed','endpoint_error','setup_failed','blocked',
                  'infrastructure_fault','cancelled')
VERDICT_ATTRIBUTIONS=('none','model','endpoint','configuration','infrastructure','operator')
VERDICT_PHASES=('admission','image','preflight','setup','agent','check','cleanup')
OUTCOME_ATTRIBUTION={'pass':'none','pass_recovered':'none','pass_assisted':'none',
    'check_failed':'model','agent_incomplete':'model','protected_input_changed':'model','turn_limit':'model',
    'token_limit':'model','repeated_tool_call':'model','agent_timeout':'model','log_limit':'model',
    'endpoint_unreachable':'endpoint','endpoint_auth_failed':'endpoint','endpoint_error':'endpoint',
    'setup_failed':'configuration','out_of_memory':'configuration',
    'infrastructure_fault':'infrastructure','cancelled':'operator'}
# Attribution of a blocked run by its recorded infrastructure reason. Configuration is the
# caller's input (plan, project, endpoint, key, image choice, options); infrastructure is the
# host (Docker, admission lock, launch registry, inference queue, the runner itself). A reason
# absent from this closed table, including any other exception class name, is infrastructure.
BLOCKED_CONFIGURATION=frozenset((
    # Class names recorded for uncoded errors whose raise sites validate caller input.
    'LabError','ScorerError','ProfileError','JSONDecodeError',
    'application-credentials','browser-policy-invalid','browser-sandbox-blocked','budget-override-invalid',
    'image-missing','in-place-inspection-error','in-place-linked-entry','invalid-project','missing-secret',
    'model-not-found','resource-policy-invalid','secret-store-insecure','unsupported-agent-profile',
    'unsupported-event-contract','unsupported-pi-release','unsupported-pi-settings',
    'environment-broken','environment-invalid-input','environment-missing','environment-needs-confirmation',
    'environment-needs-session','environment-no-environment',
    'confirmation-conflict','confirmation-invalid','context-too-small','environment-corrupt',
    'invalid-base-url','invalid-endpoint','invalid-session','missing-session',
    'catalog-insecure','catalog-invalid','credential-unavailable','environment-configuration-changed',
    'environment-index-stale','environment-not-found','environment-revoked','environment-unconfirmed',
    'inference-authority-changed','inference-configuration-secret','inference-input-unsafe',
    'selection-conflict','transient-retries-unsupported','unsupported-api-adapter',
    'egress-route-unsupported','feature-conflict','network-mode-refused'))
BLOCKED_INFRASTRUCTURE=frozenset((
    'docker-cli-missing','docker-context-invalid','docker-daemon-unavailable','docker-error',
    'docker-permission-denied','docker-remote',
    'admission-error','admission-lock-insecure','admission-lock-unavailable','host-admission-busy',
    'host-registry-capacity','host-registry-unsafe','inference-queue-expired','inference-quarantined',
    'controller_lost','evidence_destination_unavailable','evidence_finalization_failed',
    'egress-not-contained','egress-relay-exited','egress-cleanup-unconfirmed','egress-proof-unavailable'))
# Reason codes that name the model endpoint; either spelling of the separator is read.
ENDPOINT_REASONS={'endpoint-unreachable':'endpoint_unreachable','endpoint-auth-failed':'endpoint_auth_failed',
                  'endpoint-error':'endpoint_error','chat-failed':'endpoint_error'}
LIMIT_OUTCOMES={'turn_limit':'turn_limit','token_limit':'token_limit','repeated_tool_call':'repeated_tool_call',
                'timeout':'agent_timeout','log_limit':'log_limit'}
INFRASTRUCTURE_PHASES={'image':'image','preflight':'preflight','setup':'setup','agents':'agent','finished':'check'}
# Fields a supervisor or the parent sets on a stage result when its own machinery failed.
SUPERVISOR_FAULTS=('native_tool_budget_error','recovery_error','observation_error','budget_error','capture_errors')
BUDGET_LIMITS=('timeout_seconds','max_turns','max_total_tokens')


def blocked_attribution(reason):
    return 'configuration' if isinstance(reason,str) and reason in BLOCKED_CONFIGURATION else 'infrastructure'


def _section(record,name):
    value=record.get(name) if isinstance(record,dict) else None
    return value if isinstance(value,dict) else {}


def _rows(record,name):
    value=record.get(name) if isinstance(record,dict) else None
    return [row for row in value if isinstance(row,dict)] if isinstance(value,list) else []


def _text(value):return value if isinstance(value,str) else None


def _label(row):return _text(row.get('logs')) or _text(row.get('name')) if row else None


def _trace(process):
    """Evidence of the last Pi process of a stage: the final segment, else the stage itself."""
    segments=_rows(process,'segments')
    if segments and isinstance(segments[-1].get('evidence'),dict):return segments[-1]['evidence']
    return _section(process,'evidence')


def _completed(process):
    evidence=_section(process,'evidence')
    return evidence.get('completion_verified',evidence.get('agent_invocation_verified')) is True


def _provider_errors(process):
    """Provider error stops the retry policy did not absorb, counted as evidence.analyze() counts them."""
    trace=_trace(process);stops=trace.get('unsuccessful_messages')
    errors=stops.count('error') if isinstance(stops,list) else 0
    retries=trace.get('provider_retries')
    if isinstance(retries,dict) and retries.get('allowed') and type(retries.get('attempts')) is int:
        errors-=min(max(retries['attempts'],0),errors)
    return errors


def _unconfirmed(process):
    """A supervisor receipt whose container removal was not confirmed."""
    receipt='termination_reason' in process or 'started' in process
    return process.get('termination_reason')=='cleanup_error' or (receipt and process.get('cleanup_confirmed') is not True)


def _unstarted(process):
    """The placeholder recorded when a check stage raised before any supervisor receipt existed."""
    return (bool(process) and process.get('cleanup_confirmed') is not True
            and 'termination_reason' not in process and 'started' not in process)


def _target_missing(row):return _section(row,'scorer').get('reason')=='check-target-missing'


def _out_of_memory(process):
    return ('oom' in (process.get('termination_reason'),process.get('termination_trigger'))
            or _section(process,'container_state').get('OOMKilled') is True)


def _derive(record):
    term=_section(record,'termination');infra=_section(record,'infrastructure');invocation=_section(record,'invocation')
    scoring=_section(record,'scoring');reason=_text(term.get('reason'));trigger=_text(term.get('trigger'))
    agents=_rows(record,'agents');checks=_rows(record,'checks')
    ran=_rows(_section(record,'usage_summary'),'stages');last=ran[-1] if ran else {}
    def process(row):return _section(row,'process')
    def latest(kind):return _text(last.get('stage')) if last.get('kind')==kind else None
    launched=invocation.get('status') not in (None,'not_started') or bool(invocation.get('attempted_stages'))
    prelaunch=infra.get('status')!='ready' and not launched
    failed_process=reason not in (None,'not_started','completed','cancelled')
    code=_text(infra.get('reason'))
    before=INFRASTRUCTURE_PHASES.get(infra.get('phase'),'admission')
    if before in ('admission','image') and last.get('kind') in ('preflight','setup'):before=last['kind']
    here='agent' if launched else before
    # 1. Explicit cancellation.
    if reason=='cancelled':
        phase='check' if launched and scoring.get('status')=='cancelled' else here
        return 'cancelled',phase,latest(phase),'cancelled'
    # Stage failures that a later row names; a run they stopped before launch is not `blocked`.
    unconfirmed=next((row for row in agents+checks if _unconfirmed(process(row))),None)
    cleanup=(unconfirmed is not None or 'cleanup_error' in (reason,trigger)
             or (scoring.get('status')=='skipped' and scoring.get('reason')=='cleanup_unconfirmed'))
    endpoint=ENDPOINT_REASONS.get((code or '').replace('_','-')) if infra.get('status')=='failed' else None
    stage=_text(last.get('stage')) or ''
    preflight=(infra.get('status')=='failed' and failed_process and last.get('kind')=='preflight'
               and (stage=='preflight' or stage.startswith('preflight-')))
    lost=trigger=='controller_lost' or code=='controller_lost' or 'controller_interruption' in record
    setup=prelaunch and failed_process and infra.get('phase')=='setup'
    # 2. Blocked before any agent stage was launched.
    if prelaunch and not (cleanup or endpoint or preflight or lost or setup):
        return 'blocked',before,_text(last.get('stage')) if failed_process else None,code
    # 3. A removal that was not confirmed, in any stage.
    if cleanup:
        return 'infrastructure_fault','cleanup',_label(unconfirmed) or _text(last.get('stage')) or _label((agents or [None])[-1]),'cleanup_error'
    # 4. The model endpoint: a failed preflight, or provider errors the retry policy did not absorb.
    if endpoint or preflight:
        return endpoint or 'endpoint_error','preflight',stage if preflight else latest('preflight'),code if endpoint else reason
    provider=next((row for row in agents if _provider_errors(process(row))>0 and not _completed(process(row))),None)
    if provider is not None:
        return 'endpoint_error','agent',_label(provider),_text(process(provider).get('termination_reason')) or reason
    # 5. The runner, a supervisor, a check launch or a scorer failed.
    if lost:
        phase='check' if launched and scoring.get('status')=='error' else here
        return 'infrastructure_fault',phase,latest(phase),'controller_lost'
    if launched and infra.get('status')=='failed':
        phase='check' if scoring.get('reason')=='scorer_execution_failed' else 'agent'
        return 'infrastructure_fault',phase,latest(phase),code
    for phase,rows in (('agent',agents),('check',checks)):
        for row in rows:
            fault=next((name for name in SUPERVISOR_FAULTS if process(row).get(name)),None)
            if fault:return 'infrastructure_fault',phase,_label(row),fault
    unstarted=next((row for row in checks if _unstarted(process(row)) and not _target_missing(row)),None)
    if unstarted is not None:return 'infrastructure_fault','check',_label(unstarted),'check_not_started'
    if scoring.get('status')=='error':
        errors=[row for row in checks if _section(row,'scorer').get('status')=='error']
        broken=next((row for row in errors if not _target_missing(row)),None)
        if broken is not None:
            return 'infrastructure_fault','check',_label(broken),_text(_section(broken,'scorer').get('reason')) or _text(scoring.get('reason'))
        if not errors and scoring.get('reason')!='check-target-missing':
            return 'infrastructure_fault','check',None,_text(scoring.get('reason'))
    if scoring.get('status')=='skipped' and scoring.get('reason') in ('workspace_missing','workspace_snapshot_failed'):
        return 'infrastructure_fault','check',None,scoring['reason']
    # 6. A setup command failed.
    if setup:return 'setup_failed','setup',latest('setup'),reason
    # 7. The memory limit killed a stage.
    for phase,rows in (('agent',agents),('check',checks)):
        killed=next((row for row in rows if _out_of_memory(process(row))),None)
        if killed is not None:return 'out_of_memory',phase,_label(killed),'oom'
    if 'oom' in (reason,trigger):return 'out_of_memory',here,latest(here),'oom'
    # 8. An agent stage ran into one of its limits.
    if launched and reason in LIMIT_OUTCOMES:
        limited=next((row for row in agents if process(row).get('termination_reason')==reason),None)
        return LIMIT_OUTCOMES[reason],'agent',_label(limited) or _label((agents or [None])[-1]) or latest('agent'),reason
    # 9. Protected inputs changed.
    if _section(record,'protected_inputs').get('status')=='changed':
        return 'protected_input_changed','agent',_label(agents[0]) if len(agents)==1 else None,'protected_inputs_changed'
    # 10. The agent process ended without a verified completion.
    if launched and invocation.get('status') not in ('verified','recovered'):
        open_stage=next((row for row in agents if not _completed(process(row))),None)
        return 'agent_incomplete','agent',_label(open_stage) or _label((agents or [None])[-1]) or latest('agent'),reason
    unreported=next((row for row in _rows(_section(record,'application_completion'),'stages')
                     if row.get('status') in ('incomplete','invalid')),None)
    if launched and unreported is not None:
        owner=next((row for row in agents if row.get('name')==unreported.get('stage')),None)
        return 'agent_incomplete','agent',_label(owner),'application_completion_'+unreported['status']
    # 11. A check ran and failed, or the agent removed what the check needs.
    missing=next((row for row in checks if _target_missing(row)),None)
    if missing is not None or scoring.get('reason')=='check-target-missing':
        return 'check_failed','check',_label(missing),'check-target-missing'
    task=_section(record,'task_result').get('status')
    if scoring.get('status')=='completed' and task in ('fail','partial'):
        failing=next((row for row in checks if _section(row,'scorer').get('task_status') in ('fail','partial')),None)
        return 'check_failed','check',_label(failing),'task_'+task
    # 12. The pass outcomes follow the sealed status.
    passed={'PASS':'pass','RECOVERED':'pass_recovered','ASSISTED':'pass_assisted'}.get(record.get('status'))
    if passed:return passed,None,None,reason
    # A failed gate that no row names is never billed to the model.
    return 'infrastructure_fault',here,None,'unclassified'


def verdict(record):
    """Pure. What a caller should act on, as one closed outcome with its attribution.

    The record must already carry the derived status and exit code. Rows are tried
    in the documented order and the first match wins.
    """
    try:outcome,phase,stage,reason=_derive(record)
    except (KeyError,TypeError,ValueError,AttributeError,IndexError):
        # Never let a malformed section stop finalization or blame the model.
        outcome,phase,stage,reason='infrastructure_fault',None,None,'verdict_unavailable'
    attribution=blocked_attribution(reason) if outcome=='blocked' else OUTCOME_ATTRIBUTION[outcome]
    return {'schema':1,'outcome':outcome,'attribution':attribution,'phase':phase,'stage':stage,
            'reason':reason,'exit_code':record.get('exit_code') if isinstance(record,dict) else None}


def verdict_lines(summary):
    """Text view of a recorded verdict for `status`; nothing before finalization."""
    value=summary.get('verdict') if isinstance(summary,dict) else None
    if not isinstance(value,dict) or not isinstance(value.get('outcome'),str):return []
    return ['Verdict: {outcome} (attribution: {attribution}; phase: {phase}; stage: {stage}; reason: {reason}; exit {exit_code})'.format(
        **{key:value.get(key) if value.get(key) is not None else '-' for key in ('outcome','attribution','phase','stage','reason','exit_code')})]


def _wall_seconds(process):
    for value in (_section(process,'timing').get('stage_end_to_end_seconds'),process.get('elapsed_seconds')):
        if type(value) in (int,float):return value
    return None


def _stage_usage(label,kind,process):
    return {'stage':label,'kind':kind,'wall_seconds':_wall_seconds(process)}


def _agent_usage(label,process):
    turns=process.get('stage_turns')
    if type(turns) is not int:
        counts=[_section(_section(segment,'evidence'),'events').get('turn_start',0) if isinstance(segment.get('evidence'),dict) else None
                for segment in _rows(process,'segments')]
        turns=sum(counts) if counts and all(type(count) is int for count in counts) else None
    categories=_section(_section(process,'usage'),'categories')
    tokens={name:_section(categories,name).get('reported') for name in ('input','output','total')}
    # A count the model server did not report for every completed message stays null, never zero.
    tokens={name:value if type(value) is int else None for name,value in tokens.items()}
    tokens['reported']=tokens['total'] is not None
    limits={view:{key:_section(process,source).get(key) if type(_section(process,source).get(key)) is int else None for key in BUDGET_LIMITS}
            for view,source in (('plan','original_limits'),('effective','effective_limits'))}
    return {**_stage_usage(label,'agent',process),'turns':turns,'tokens':tokens,'limits':limits}


def usage_summary(record,observed=None):
    """Pure. One row for each stage the runner launched, in launch order.

    `observed` is stage_observations() of the run root; without it only the agent
    and check stages held by the record are listed.
    """
    agents={_label(row):_section(row,'process') for row in _rows(record,'agents')}
    checks={_label(row):_section(row,'process') for row in _rows(record,'checks')}
    rows=[];seen=set()
    for item in observed or []:
        label=item.get('stage');process=item.get('process') if isinstance(item.get('process'),dict) else {}
        if not isinstance(label,str) or label in seen:continue
        seen.add(label)
        if label in agents:rows.append(_agent_usage(label,agents[label]))
        elif label in checks:rows.append(_stage_usage(label,'check',checks[label]))
        elif item.get('kind')=='agent':rows.append(_agent_usage(label,process))
        elif item.get('kind')=='check':rows.append(_stage_usage(label,'setup' if label.startswith('setup-') else 'check',process))
        else:rows.append(_stage_usage(label,'preflight',process))
    rows+=[_agent_usage(label,process) for label,process in agents.items() if label not in seen]
    rows+=[_stage_usage(label,'check',process) for label,process in checks.items() if label not in seen]
    return {'schema':1,'stages':rows}


def stage_observations(root):
    """Parent-owned stage records of one run in launch order; an unreadable stage is skipped."""
    rows=[]
    try:paths=list(Path(root).glob('stages/*/descriptor.json'))
    except OSError:return rows
    for path in paths:
        try:
            desc=controls.read(path);state=controls.read(path.with_name('state.json'))
            if not isinstance(desc.get('label'),str) or not isinstance(state.get('started_at'),str):continue
            try:process=controls.read(Path(root)/desc['label']/'process.json')
            except (OSError,ValueError,controls.ControlError):process=None
            rows.append({'stage':desc['label'],'kind':desc.get('kind'),'started_at':state['started_at'],'process':process})
        except (OSError,ValueError,AttributeError,controls.ControlError):continue
    return sorted(rows,key=lambda row:row['started_at'])


class Attempt:
    def __init__(self,args,record=None):
        self.record=record or initial();self.root=None;self.sealed=None
        # Validate lexical and canonical placement before creating any evidence.
        destination=Path(args.results_dir).expanduser().absolute()
        project=Path(args.project).expanduser().absolute() if getattr(args,'project',None) else None
        canonical=destination.resolve()
        if project:
            project_root=project.resolve()
            if any(p==project_root or project_root in p.parents or p==project or project in p.parents for p in (destination,canonical)):
                raise ValueError('unsafe-evidence-destination')
        # Resolve trusted host aliases once; every subsequent component is opened no-follow.
        parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
        try:
            for part in canonical.parts[1:]:
                try:child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                except FileNotFoundError:
                    os.mkdir(part,0o700,dir_fd=parent)
                    child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                os.close(parent);parent=child
            name=self.record['run_id']
            os.mkdir(name,0o700,dir_fd=parent)
            self.root=canonical/name;self.record['run_dir']=str(self.root)
        finally:os.close(parent)
        controls.atomic(self.root/'identity.json',{k:self.record[k] for k in ('schema','run_id','attempt_id')})
        self.persist()
        latest=canonical/'latest'
        try:
            if getattr(args,'_parallel_session',None):return
            if latest.is_symlink():latest.unlink()
            if not latest.exists():latest.symlink_to(self.root)
        except OSError:pass

    @classmethod
    def attach_unsealed(cls,root,record):
        """Parent recovery only, after exclusive leases and independently confirmed cleanup."""
        root=Path(root)
        if root.is_symlink() or (root/'result.json').exists():raise controls.ControlError('Cannot attach sealed/linked attempt')
        identity=controls.read(root/'identity.json')
        if any(identity.get(k)!=record.get(k) for k in ('run_id','attempt_id')):raise controls.ControlError('Recovery identity mismatch')
        result=cls.__new__(cls);result.root=root;result.record=copy.deepcopy(record);result.sealed=None
        result.record['sealed']=False
        return result

    def persist(self):
        if self.sealed is None:controls.atomic(self.root/'summary.json',self.record)

    def cause(self,reason,exit_code=None):
        term=self.record['termination']
        if term['reason'] in ('not_started','completed') or reason in ('cleanup_error','cancelled'):
            if term['reason'] not in ('not_started','completed',reason):term['trigger']=term['reason']
            term['reason']=reason
        if exit_code is not None:term['process_exit_code']=exit_code

    def process(self,result):
        reason=result.get('termination_reason') or ('completed' if result.get('exit_code')==0 else 'process_error')
        if reason=='cleanup_error' and result.get('termination_trigger'):self.cause(result['termination_trigger'],result.get('exit_code'))
        if result.get('exit_code') or reason!='completed':self.cause(reason,result.get('exit_code'))
        if result.get('cleanup_confirmed') is False:self.cause('cleanup_error')

    def fail(self,exc):
        self.record['infrastructure']['status']='failed'
        diagnostic = admission_diagnostic(exc)
        self.record['infrastructure']['reason']=(diagnostic['reason'] if diagnostic is not None
                                               else CredentialError.reason if type(exc) is CredentialError
                                               else type(exc).__name__ if isinstance(exc,ValueError)
                                               else getattr(exc,'reason','') or type(exc).__name__)
        # Keep diagnostic identifiers, never raw exception text/keys/URLs.
        guidance = (diagnostic.get('remedy', '') if diagnostic is not None else '' if isinstance(exc,ValueError)
                    else getattr(exc,'remedy',''))
        if guidance:self.record['infrastructure']['remedy']=guidance
        else:self.record['infrastructure'].pop('remedy',None)
        if diagnostic is not None and 'registry_diagnostic' in diagnostic:
            self.record['infrastructure']['registry_diagnostic']=diagnostic['registry_diagnostic']
        else:self.record['infrastructure'].pop('registry_diagnostic',None)
        self.record['infrastructure']['error_digest']=hashlib.sha256(str(exc).encode()).hexdigest()
        if self.record['scoring']['status']=='not_started':
            self.record['scoring'].update(status='skipped',reason='infrastructure_failure')
        elif self.record['scoring']['status']=='running':
            self.record['scoring'].update(status='error',reason='scorer_execution_failed')

    def cancel(self):
        self.cause('cancelled')
        scoring=self.record['scoring']
        if scoring['status']=='running':scoring.update(status='cancelled',reason='user_cancelled')
        elif scoring['status']=='not_started':scoring.update(status='skipped',reason='user_cancelled')

    def finalize(self):
        if self.sealed is not None:return copy.deepcopy(self.sealed)
        path=self.root/'result.json'
        with controls.lock(self.root):
            if path.exists():
                saved=controls.read(path)
                if saved.get('attempt_id')!=self.record['attempt_id'] or not saved.get('sealed'):
                    raise controls.ControlError('Invalid sealed result identity')
                self.sealed=saved
                return copy.deepcopy(self.sealed)
            self.record['assistance']=controls.assistance(self.root)
            self.record['status'],self.record['exit_code']=status(self.record)
            # Neither addition may stop the one-way seal; both are total over malformed sections.
            try:self.record['usage_summary']=usage_summary(self.record,stage_observations(self.root))
            except (KeyError,TypeError,ValueError,AttributeError):self.record['usage_summary']={'schema':1,'stages':[]}
            self.record['verdict']=verdict(self.record)
            self.record.update(sealed=True,finished_at=controls.now())
            encoded=(json.dumps(self.record,ensure_ascii=False,indent=2)+'\n').encode()
            temp=path.with_name('.result-'+uuid.uuid4().hex)
            published=False
            try:
                fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb') as f:f.write(encoded);f.flush();os.fsync(f.fileno())
                os.rename(temp,path);published=True
                parent=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:os.fsync(parent)
                finally:os.close(parent)
            except Exception:
                if published:path.unlink()
                self.record['sealed']=False
                raise
            finally:temp.unlink(missing_ok=True)
            self.sealed=copy.deepcopy(self.record)
        # The sealed result is authoritative even if the compatibility view fails.
        try:controls.atomic(self.root/'summary.json',self.sealed)
        except (OSError,ValueError,controls.ControlError):
            import sys
            print(json.dumps({'schema':2,'attempt_id':self.record['attempt_id'],
                              'reason':'progress_view_unavailable','result_persisted':True}),file=sys.stderr)
        return copy.deepcopy(self.sealed)


def fallback(record,phase,reason):
    result=copy.deepcopy(record)
    result.update(status='BLOCKED',exit_code=2,sealed=False,persistence='unavailable')
    result['infrastructure'].update(status='failed',phase=phase,reason=reason)
    result['scoring'].update(status='skipped',reason='evidence_unavailable')
    # An ID and sanitized dimensions are retained even if no file could be saved.
    return {k:result[k] for k in ('schema','document_type','run_id','attempt_id','status','exit_code',
                                 'infrastructure','invocation','termination','scoring','task_result','persistence')}
