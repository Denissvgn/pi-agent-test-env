"""Frozen opt-in two-trial contract. No runtime admission or model access."""
import copy
import math

VERSION = 'parallel-trials-v1'
HOST_GENERATION = 1


class ParallelError(ValueError):
    reason = 'parallel-contract-invalid'


def fields(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ParallelError('Parallel contract has missing or unsupported fields')


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ParallelError('Parallel contract requires bounded integer limits')
    return value


def weight(value):
    fields(value, ('cpu_millis','memory_mib','pids_limit'))
    integer(value['cpu_millis'],100,256000)
    integer(value['memory_mib'],64,1048576)
    integer(value['pids_limit'],64,8192)
    return copy.deepcopy(value)


def validate(value):
    fields(value, ('scheduler','host_generation','registry_aware_cohort','max_trials','max_stages',
                   'max_pending','queue_wait_seconds','collection_timeout_seconds','aggregate','gateway'))
    if value['scheduler'] != VERSION or type(value['host_generation']) is not int or value['host_generation'] != HOST_GENERATION:
        raise ParallelError('Unsupported parallel scheduler or host generation')
    if value['registry_aware_cohort'] is not True:
        raise ParallelError('Parallel mode requires an explicitly selected registry-aware client cohort')
    if type(value['max_trials']) is not int or value['max_trials'] != 2 or type(value['max_stages']) is not int or value['max_stages'] != 2:
        raise ParallelError('The reviewed parallel mode supports exactly two trial/stage slots')
    integer(value['max_pending'],2,64)
    integer(value['queue_wait_seconds'],1,3600)
    integer(value['collection_timeout_seconds'],60,14400)
    aggregate=weight(value['aggregate'])
    gateway=value['gateway']
    fields(gateway,('resources','max_inflight','max_pending','queue_wait_seconds','request_timeout_seconds'))
    weight(gateway['resources'])
    if type(gateway['max_inflight']) is not int or gateway['max_inflight'] != 1:
        raise ParallelError('Only one cooperating model request is qualified by this contract')
    integer(gateway['max_pending'],2,16)
    integer(gateway['queue_wait_seconds'],1,600)
    integer(gateway['request_timeout_seconds'],30,600)
    if gateway['queue_wait_seconds'] >= gateway['request_timeout_seconds']:
        raise ParallelError('Inference queue wait must be below request deadline')
    if any(gateway['resources'][k] >= aggregate[k] for k in aggregate):
        raise ParallelError('Gateway reservation must leave worker capacity')
    return copy.deepcopy(value)


def preflight_limits(value):
    gateway=validate(value)['gateway']
    # A model-list request can queue behind the other trial's generation.
    # Keep the original serial floors; cover the selected queue plus upstream
    # deadline and retain bounded container-start/exit headroom.
    request=max(120,gateway['queue_wait_seconds']+gateway['request_timeout_seconds'])
    return {'request_timeout_seconds':request,'container_timeout_seconds':request+30}


def worker_weight(policy):
    runtime=policy['runtime']
    cpu=runtime['cpus']
    if type(cpu) not in (int,float) or not 0.1 <= cpu <= 256 or not math.isfinite(cpu) or cpu*1000 != round(cpu*1000):
        raise ParallelError('Parallel CPU quotas require exact integer milli-CPU units')
    import resources
    memory=resources.memory_bytes(runtime['memory'])
    return weight({'cpu_millis':round(cpu*1000),'memory_mib':memory//(1024**2),'pids_limit':runtime['pids_limit']})


def admit_capacity(contract, policy, daemon):
    contract=validate(contract);worker=worker_weight(policy)
    aggregate=contract['aggregate'];gateway=contract['gateway']['resources']
    if type(daemon.get('NCPU')) is not int or type(daemon.get('MemTotal')) is not int:
        raise ParallelError('Observed daemon capacity is required')
    budget=policy['host_budget']
    cap_cpu=math.floor(daemon['NCPU']*budget['cpu_fraction']*1000)
    cap_memory=math.floor(daemon['MemTotal']*budget['memory_fraction']/(1024**2))
    if aggregate['cpu_millis'] > cap_cpu or aggregate['memory_mib'] > cap_memory:
        raise ParallelError('Frozen aggregate exceeds the configured daemon budget')
    if any(2*worker[k]+gateway[k] > aggregate[k] for k in aggregate):
        raise ParallelError('Two unchanged workers and gateway do not fit the frozen aggregate')
    return {'worker':worker,'gateway':gateway,'aggregate':aggregate,'host_generation':HOST_GENERATION}
