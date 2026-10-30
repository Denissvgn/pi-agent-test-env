"""Linux ARM64 worker observations. Own child only; no historical PID lookup."""
import hashlib
import math
import os
import platform
import resource
import select
import signal
import stat
import subprocess
import sys
import threading
import types

from . import secret_registration_posix as native
from .source import ApprovedReader
from .wire import SDKError, require
_DIAGNOSTIC=None


def platform_check():
    require(sys.platform == 'linux' and platform.machine() == 'aarch64'
            and sys.implementation.name == 'cpython' and sys.version_info[:3] == (3, 12, 13)
            and hasattr(os, 'pidfd_open') and threading.active_count() == 1, 4)


def kernel_bytes(path, maximum=4096):
    allowed={'/proc/self/maps':1048576,'/proc/self/cgroup':4096,
        '/sys/fs/cgroup/cpu.max':4096,'/sys/fs/cgroup/memory.max':4096,
        '/sys/fs/cgroup/memory.current':4096,'/sys/fs/cgroup/pids.max':4096}
    require(type(path)is str and path in allowed and type(maximum)is int and 0<maximum<=allowed[path],2)
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        body = bytearray()
        while True:
            chunk = os.read(fd, min(65536, maximum + 1 - len(body)))
            if not chunk: break
            body.extend(chunk); require(len(body) <= maximum, 5)
        return bytes(body)
    except OSError: raise SDKError(4) from None
    finally:
        if fd is not None:
            try: native.close(fd)
            except BaseException: raise SDKError(6) from None


def cgroup_limits(limits):
    try:
        quota, period = kernel_bytes('/sys/fs/cgroup/cpu.max').decode('ascii').split()
        memory = kernel_bytes('/sys/fs/cgroup/memory.max').decode('ascii').strip()
        pids = kernel_bytes('/sys/fs/cgroup/pids.max').decode('ascii').strip()
        require(quota.isdigit() and period.isdigit() and memory.isdigit() and pids.isdigit(), 4)
        quota, period, memory, pids = map(int, (quota, period, memory, pids))
        require(quota > 0 and period > 0 and memory > 0 and pids > 0, 4)
        require(quota * 1000 <= period * limits['max_cpu_millicores']
                and memory <= limits['max_memory_bytes'] and pids <= limits['max_pids'], 4)
        return {'cpu_millicores': math.ceil(quota * 1000 / period), 'memory_bytes': memory, 'pids': pids}
    except (ValueError, UnicodeError): raise SDKError(4) from None


def worker_limits(limits):
    platform_check(); measured = cgroup_limits(limits)
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_AS, (limits['max_memory_bytes'], limits['max_memory_bytes']))
    require(limits['max_cpu_millis']%1000==0,5)
    cpu = limits['max_cpu_millis']//1000
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    return measured


def sole_reaper():
    platform_check()
    require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL
            and not getattr(subprocess, '_active', []), 4)
    # Pinned CPython3.12.13 installs default SA_ONSTACK, not SA_NOCLDWAIT.
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)


def mapped_paths(body):
    require(type(body) is bytes and len(body) <= 1048576, 5)
    lines = body.splitlines(); require(len(lines) <= 4096, 5); paths = set()
    try:
        for line in lines:
            fields = line.split(None, 5)
            if len(fields) == 6 and fields[5].startswith(b'/'):
                path = fields[5].decode('utf-8')
                require(not path.endswith(' (deleted)') and path.startswith(('/usr/', '/lib/')), 4)
                paths.add(path)
        require(len(paths) <= 64, 5)
        return sorted(paths)
    except UnicodeError: raise SDKError(4) from None


def module_descriptors(excluded):
    global _DIAGNOSTIC
    result = {}
    for name, module in sorted(list(sys.modules.items())):
        if name == '__main__' or name == 'operation_sdk' or name.startswith('operation_sdk.') or name in excluded:
            continue
        _DIAGNOSTIC='module:'+name
        require(module is not None, 4)
        if name in ('typing.io','typing.re') and not isinstance(module,types.ModuleType):
            owner=sys.modules.get('typing');attribute=name.split('.',1)[1]
            require(owner is not None and vars(owner).get(attribute)is module,4)
            result[name]={'kind':'export_alias','path':None,'spec_name':None,'owner':'typing'}
            continue
        spec = getattr(module, '__spec__', None); origin = getattr(spec, 'origin', None)
        spec_name = getattr(spec, 'name', None)
        if origin in ('built-in', 'frozen'):
            result[name] = {'kind': origin, 'path': None, 'spec_name': spec_name}
        else:
            path = getattr(module, '__file__', None)
            require(type(path) is str and origin == path and path.startswith(('/usr/local/lib/python3.12/', '/usr/lib/')), 4)
            result[name] = {'kind': 'file', 'path': path, 'spec_name': spec_name}
    require(len(result) <= 512, 5)
    return result


def capture(deployment, limits, excluded, *, discovery=False, budget=None):
    """Measured current files/modules/maps; discovery never grants approval."""
    global _DIAGNOSTIC
    modules = module_descriptors(excluded)
    mapped = mapped_paths(kernel_bytes('/proc/self/maps', 1048576))
    paths = {row['path'] for row in modules.values() if row['path']} | set(mapped) | {deployment['python_path']}
    if not discovery:
        require(modules == deployment['runtime_modules'] and mapped == sorted(deployment['mapped_files']), 4)
        require(paths == set(deployment['runtime_files']), 4)
    allowed = {}
    for path in paths:
        allowed[path] = {'sha256': None if discovery else deployment['runtime_files'][path],
                         'maximum_bytes': limits['max_source_file_bytes']if discovery else deployment['runtime_sizes'][path],
                         'size':None if discovery else deployment['runtime_sizes'][path],'readonly': True}
    reader = ApprovedReader(allowed, max_file_bytes=limits['max_source_file_bytes'],
                            max_total_bytes=limits['max_source_bytes'] // 2, max_files=limits['max_source_files'],budget=budget)
    files = {};sizes={}
    for path in sorted(paths):
        _DIAGNOSTIC='runtime_file:'+path
        body = reader.read(path, limits['max_source_file_bytes']); files[path] = hashlib.sha256(body).hexdigest();sizes[path]=len(body)
    if not discovery: require(files[deployment['python_path']] == deployment['python_sha256'], 4)
    return {'modules': modules, 'mapped_files': mapped, 'files': files,'sizes':sizes,
            'python_sha256': files[deployment['python_path']], 'observed_source_bytes': reader.total,
            'observed_source_files':len(paths),'approval': False}


class OwnedProcess:
    @classmethod
    def launch(cls, command, pass_fds, stdout_fd, stderr_fd):
        sole_reaper()
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout_fd, stderr=stderr_fd,
            pass_fds=tuple(pass_fds), close_fds=True, start_new_session=True,
            env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'})
        owner = object.__new__(cls); owner.process = process; owner.reaped = False
        owner.pidfd = owner.proc_fd = None; owner.close_known = True
        try:
            owner.pidfd = os.pidfd_open(process.pid, 0)  # Before any poll/wait/other reaper.
            owner.proc_fd = os.open('/proc/' + str(process.pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            return owner
        except OSError:
            owner.close(); raise SDKError(4) from None

    def exited(self):
        require(not self.reaped, 4)
        poller = select.poll(); poller.register(self.pidfd, select.POLLIN | select.POLLHUP)
        return bool(poller.poll(0))

    def proc_bytes(self, name, maximum=1048576):
        require(not self.reaped and name in ('stat', 'maps'), 4)
        fd = None
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.proc_fd)
            body = bytearray()
            while True:
                chunk = os.read(fd, min(65536, maximum + 1 - len(body)))
                if not chunk: break
                body.extend(chunk); require(len(body) <= maximum, 5)
            return bytes(body)
        except OSError: raise SDKError(4) from None
        finally:
            if fd is not None:
                try: native.close(fd)
                except BaseException: raise SDKError(6) from None

    def observe(self, deployment, limits, *, budget=None):
        require(not self.exited(), 4)
        before = self.proc_bytes('stat', 65536)
        try: started = int(before[before.rfind(b')') + 2:].split()[19])
        except (IndexError, ValueError): raise SDKError(4) from None
        executable = os.readlink('exe', dir_fd=self.proc_fd)
        require(executable == deployment['python_path'], 4)
        fd = os.open('exe', os.O_RDONLY | os.O_CLOEXEC, dir_fd=self.proc_fd)
        try:
            before_exe=os.fstat(fd);size=deployment['runtime_sizes'][deployment['python_path']]
            require(stat.S_ISREG(before_exe.st_mode)and before_exe.st_size==size
                    and size<=limits['max_source_file_bytes'],4)
            if budget is not None:budget.attempt();budget.reserve(size)
            digest = hashlib.sha256(); total = 0
            while total<size:
                body = os.read(fd,min(65536,size-total));require(bool(body),4)
                total += len(body);digest.update(body)
            from .source import header
            require(header(before_exe)==header(os.fstat(fd))==header(os.stat('exe',dir_fd=self.proc_fd)),4)
            require(digest.hexdigest() == deployment['python_sha256'], 4)
        finally:
            try: native.close(fd)
            except BaseException: raise SDKError(6) from None
        after = self.proc_bytes('stat', 65536)
        require(int(after[after.rfind(b')') + 2:].split()[19]) == started and not self.exited(), 4)
        require(mapped_paths(self.proc_bytes('maps')) == sorted(deployment['mapped_files']), 4)
        return {'pid': self.process.pid, 'start_ticks': started, 'python_sha256': digest.hexdigest(),
                'pidfd_bound_before_wait': True, 'scope': 'own_linux_child_only'}

    def wait(self, timeout):
        require(not self.reaped, 4)
        try: code = self.process.wait(timeout=timeout)
        except (OSError, subprocess.TimeoutExpired): raise SDKError(9) from None
        self.reaped = True; return code

    def close(self):
        if not self.reaped:
            try:
                self.process.terminate()
                try: self.wait(2)
                except SDKError: self.process.kill(); self.wait(3)
            except (OSError, SDKError): self.close_known = False
        for name in ('proc_fd', 'pidfd'):
            fd = getattr(self, name)
            if fd is not None:
                setattr(self, name, None)
                try: native.close(fd)
                except BaseException: self.close_known = False
        return self.close_known and self.reaped
