"""Finite Docker resource budgets and same-user admission control (host-side).

No cgroup changes are made to the model server or unrelated containers. Quotas
are per container; the host lock serializes this runner's cooperating processes.
"""
from __future__ import annotations
import contextlib
import copy
import fcntl
import json
import math
import os
from pathlib import Path
import re
import time

DEFAULTS = {
    'schema': 1,
    'runtime': {'cpus': 2.0, 'memory': '4g', 'pids_limit': 256, 'jobs': 2},
    'build': {'cpus': 2.0, 'memory': '4g', 'max_parallelism': 2, 'timeout_seconds': 1800},
    'host_budget': {'cpu_fraction': 0.5, 'memory_fraction': 0.5},
}


def memory_bytes(value):
    if not isinstance(value, str) or not re.fullmatch(r'[1-9][0-9]*[mg]', value.lower()):
        raise ValueError('Memory must be a finite positive MiB/GiB string, e.g. 1024m or 4g')
    n = int(value[:-1]) * (1024 ** (2 if value[-1].lower() == 'm' else 3))
    if n < 64 * 1024 ** 2:
        raise ValueError('Memory must be at least 64 MiB')
    return n


def validate_policy(value):
    if not isinstance(value, dict) or set(value) - set(DEFAULTS) or value.get('schema', 1) != 1:
        raise ValueError('Resource policy schema 1 accepts runtime, build, host_budget')
    result = copy.deepcopy(DEFAULTS)
    for section in ('runtime', 'build', 'host_budget'):
        supplied = value.get(section, {})
        if not isinstance(supplied, dict) or set(supplied) - set(DEFAULTS[section]):
            raise ValueError(f'Unknown resource field in {section}')
        result[section].update(supplied)
    for section in ('runtime', 'build'):
        cpus = result[section]['cpus']
        if type(cpus) not in (int, float) or not math.isfinite(cpus) or not 0.1 <= cpus <= 256:
            raise ValueError(f'{section}.cpus must be finite and in 0.1..256; 0/unlimited is not allowed')
        memory_bytes(result[section]['memory'])
    bounds = [('runtime', 'pids_limit', 64, 4096), ('runtime', 'jobs', 1, 64),
              ('build', 'max_parallelism', 1, 16), ('build', 'timeout_seconds', 60, 14400)]
    for section, field, low, high in bounds:
        value = result[section][field]
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f'{section}.{field} must be in {low}..{high}')
    for field in ('cpu_fraction', 'memory_fraction'):
        value = result['host_budget'][field]
        if type(value) not in (int, float) or not math.isfinite(value) or not 0.05 <= value <= 0.9:
            raise ValueError(f'host_budget.{field} must be in 0.05..0.9')
    return result


def requested_policy(args):
    value = json.loads(Path(args.resources).expanduser().read_text()) if getattr(args, 'resources', None) else {}
    result = validate_policy(value)
    overrides = {'cpus': ('runtime', 'cpus'), 'memory': ('runtime', 'memory'),
                 'pids_limit': ('runtime', 'pids_limit'), 'jobs': ('runtime', 'jobs'),
                 'build_cpus': ('build', 'cpus'), 'build_memory': ('build', 'memory'),
                 'build_parallelism': ('build', 'max_parallelism'),
                 'build_timeout': ('build', 'timeout_seconds')}
    for option, (section, field) in overrides.items():
        supplied = getattr(args, option, None)
        if supplied is not None:
            result[section][field] = supplied
    return validate_policy(result)


def configure(args, docker_info):
    """Clamp against total resources allocated to the daemon, not host os.cpu_count()."""
    requested = copy.deepcopy(getattr(args, '_resource_request', None) or requested_policy(args))
    args._resource_request = copy.deepcopy(requested)
    cpus = docker_info.get('NCPU')
    memory = docker_info.get('MemTotal')
    if type(cpus) is not int or cpus < 1 or type(memory) is not int or memory <= 0:
        raise ValueError('Docker did not report NCPU/MemTotal; cannot establish the resource budget')
    warnings = '\n'.join(docker_info.get('Warnings') or []).lower()
    if any(text in warnings for text in ('no memory limit support', 'no cpu cfs quota support', 'no swap limit support')):
        raise ValueError('Docker reports missing CPU/memory/swap limit support; fix the daemon, not an unlimited fallback')
    effective = copy.deepcopy(requested)
    cap_cpu = math.floor(cpus * requested['host_budget']['cpu_fraction'] * 1000) / 1000
    cap_mem = int(memory * requested['host_budget']['memory_fraction']) // (1024 ** 2) * (1024 ** 2)
    if cap_cpu < 0.1 or cap_mem < 64 * 1024 ** 2:
        raise ValueError('Docker allocation is too small for the configured host-budget fractions')
    for section in ('runtime', 'build'):
        effective[section]['cpus'] = min(float(requested[section]['cpus']), cap_cpu)
        effective[section]['memory'] = str(min(memory_bytes(requested[section]['memory']), cap_mem) // (1024 ** 2)) + 'm'
    jobs = max(1, math.floor(effective['runtime']['cpus']))
    effective['runtime']['jobs'] = min(requested['runtime']['jobs'], jobs)
    effective['build']['max_parallelism'] = min(requested['build']['max_parallelism'], max(1, math.floor(effective['build']['cpus'])))
    for field in ('cpus', 'memory', 'pids_limit', 'jobs'):
        setattr(args, field, effective['runtime'][field])
    # Retain the original policy. A second configure must not mistake clamped values for CLI overrides.
    args.resource_report = {'requested': requested, 'effective': effective,
                            'docker_cpus': cpus, 'docker_memory_bytes': memory,
                            'memory_swap': effective['runtime']['memory'],
                            'parallel_stages': 1, 'scope': 'Cooperating runs of this runner under the same host lock; model server excluded'}
    return args.resource_report


def thread_environment(jobs):
    n = str(jobs)
    return {'PI_TEST_JOBS': n, 'OMP_NUM_THREADS': n, 'OPENBLAS_NUM_THREADS': n,
            'MKL_NUM_THREADS': n, 'NUMEXPR_NUM_THREADS': n, 'VECLIB_MAXIMUM_THREADS': n,
            'UV_THREADPOOL_SIZE': n, 'CMAKE_BUILD_PARALLEL_LEVEL': n, 'MAKEFLAGS': '-j' + n,
            'CARGO_BUILD_JOBS': n, 'RAYON_NUM_THREADS': n, 'GOMAXPROCS': n,
            'npm_config_jobs': n}


@contextlib.contextmanager
def admission_lock(path, wait_seconds=0):
    """Serialize this tool across cooperating processes for one host user.

    flock releases automatically on crash. File stays in place to avoid unlink races.
    This is not a host-wide scheduler; separate users/lock files do not cooperate.
    """
    if not 0 <= wait_seconds <= 3600:
        raise ValueError('lock wait must be between 0 and 3600 seconds')
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError('Refusing a symlinked admission-lock file')
    with path.open('a+') as handle:
        os.chmod(path, 0o600)
        deadline = time.monotonic() + wait_seconds
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ValueError('Another pi-agent-test-env operation holds the host lock; wait or use --lock-wait-seconds')
                time.sleep(0.1)
        try:
            handle.seek(0)
            handle.truncate()
            handle.write(json.dumps({'pid': os.getpid(), 'started_unix': time.time()}) + '\n')
            handle.flush()
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
