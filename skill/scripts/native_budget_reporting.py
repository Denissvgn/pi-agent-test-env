"""Strict parent-ledger reporting. Never reconstruct accounting from Pi events.

Only an explicit parent tool manifest grants names to the snapshot validator.
Malformed or missing native accounting is unavailable, never legacy or zero.
"""
import copy
import re

import native_budget_controls as controls

SCOPE='parent_ledger; runtime_qualification_separate'
ERRORS=frozenset({'accounting_unavailable','cleanup_unconfirmed'})
PROCESS_FIELDS=frozenset({'native_tool_manifest','native_tool_budget','native_tool_budget_error'})
STAGE=re.compile(r'[a-z0-9][a-z0-9-]{0,50}')


class NativeBudgetReportingError(ValueError):
    def __init__(self):super().__init__('Invalid parent native budget reporting metadata')


def manifest_tools(value):
    """Closed manifest, known literal tool names, no received names in errors."""
    if (type(value) is not dict or set(value)!={'schema','tools'} or type(value['schema']) is not int
            or value['schema']!=1 or type(value['tools']) is not list or not 1<=len(value['tools'])<=64
            or any(type(name) is not str or name not in controls.SAFE_TOOLS for name in value['tools'])
            or len(set(value['tools']))!=len(value['tools']) or 'budget_status' not in value['tools']):
        raise NativeBudgetReportingError()
    return list(value['tools'])


def unavailable():
    return {'accounting':'unavailable','budget':None,'error':'accounting_unavailable'}


def process_projection(process, *, required=False):
    """Optional safe projection, with explicit unavailability for declared stages."""
    if type(required) is not bool:raise NativeBudgetReportingError()
    if type(process) is not dict:
        return unavailable() if required else None
    if not PROCESS_FIELDS.intersection(process) and not required:return None
    try:
        tools=manifest_tools(process.get('native_tool_manifest'))
        snapshot=controls.public_snapshot(process.get('native_tool_budget'),allowed_tools=tools)
        error=process.get('native_tool_budget_error')
        if 'native_tool_budget_error' in process and (type(error) is not str or error not in ERRORS):
            raise NativeBudgetReportingError()
    except (ValueError,TypeError,KeyError):
        return unavailable()
    if error is None and snapshot['accounting']=='unavailable':error='accounting_unavailable'
    return {'accounting':'unavailable' if error else snapshot['accounting'],
            'budget':copy.deepcopy(snapshot),'error':error}


def _names(value):
    if (type(value) not in (list,tuple) or len(value)>8 or any(type(name) is not str or not STAGE.fullmatch(name) for name in value)
            or len(set(value))!=len(value)):
        raise NativeBudgetReportingError()
    return list(value)


def record_projection(record, *, stage_names=None, required_stages=(), public=False):
    """Keep each stage boundary; public indexed exports use existing ordinals.

    stage_names/required_stages are frozen parent metadata, never inferred from
    tool results. The recorded agent name is parent metadata when no list is
    supplied. No paths, arguments, native IDs, receipt IDs or digests survive.
    """
    if type(public) is not bool:raise NativeBudgetReportingError()
    required=_names(required_stages)
    agents=record.get('agents',[]) if type(record) is dict else []
    if type(agents) is not list or len(agents)>8:
        if required:
            names=_names(stage_names) if stage_names is not None else required
            if set(required)-set(names):raise NativeBudgetReportingError()
            return {'schema':1,'scope':SCOPE,'stages':[{'stage':names.index(name)+1 if public else name,**unavailable()} for name in required]}
        if type(agents) is not list:return None
        if any(type(agent) is dict and type(agent.get('process')) is dict and PROCESS_FIELDS.intersection(agent['process']) for agent in agents[:9]):
            return {'schema':1,'scope':SCOPE,'stages':[{'stage':1 if public else 'undeclared-stage',**unavailable()}]}
        return None
    if stage_names is None:
        names=[]
        for number,agent in enumerate(agents,1):
            if type(agent) is not dict:continue
            name=agent.get('name')
            if type(name) is not str or not STAGE.fullmatch(name):
                if type(agent.get('process')) is dict and PROCESS_FIELDS.intersection(agent['process']):
                    name='unavailable-stage-'+str(number)
                else:continue
            if name not in names:names.append(name)
        for name in required:
            if name not in names:names.append(name)
        names=_names(names)
    else:names=_names(stage_names)
    if set(required)-set(names):raise NativeBudgetReportingError()
    stages=[]
    for number,name in enumerate(names,1):
        selected=[agent for agent in agents if type(agent) is dict and agent.get('name')==name]
        process=selected[0].get('process') if len(selected)==1 else None
        declared=any(type(agent.get('process')) is dict and PROCESS_FIELDS.intersection(agent['process']) for agent in selected)
        value=process_projection(process,required=name in required or declared)
        if value is not None:stages.append({'stage':number if public else name,**value})
    # A foreign/malformed agent name with native fields cannot become an
    # apparently successful omission. Emit one fixed diagnostic, never its name.
    if any(type(agent) is dict and agent.get('name') not in names and type(agent.get('process')) is dict
           and PROCESS_FIELDS.intersection(agent['process']) for agent in agents):
        stages.append({'stage':len(names)+1 if public else 'undeclared-stage',**unavailable()})
    return {'schema':1,'scope':SCOPE,'stages':stages} if stages else None
