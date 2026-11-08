"""OS-specific readiness models cannot supply approval by matching labels."""
import signal
import types
from unittest import TestCase, mock
from tests.test_operation_sdk_policy import example_policy
from operation_sdk import runtime
from operation_sdk.wire import SDKError


class SDKRuntimeTests(TestCase):
    def test_platform_check_refuses_unsupported_before_kernel_lookup(self):
        with (mock.patch.object(runtime.sys, 'platform', 'darwin'),
              mock.patch.object(runtime, 'kernel_bytes', side_effect=AssertionError('unsupported kernel read'))):
            with self.assertRaises(SDKError): runtime.platform_check()

    def test_cgroup_limits_require_finite_exact_actual_bounds(self):
        limits = example_policy()['limits']
        values = {'cpu.max': b'100000 100000\n', 'memory.max': b'536870912\n', 'pids.max': b'128\n'}
        with mock.patch.object(runtime, 'kernel_bytes', side_effect=lambda path, maximum=4096: values[path.rsplit('/', 1)[-1]]):
            self.assertEqual(runtime.cgroup_limits(limits)['cpu_millicores'], 1000)
        for field, bad in [('cpu.max', b'max 100000'), ('memory.max', b'max'), ('pids.max', b'129')]:
            changed = dict(values); changed[field] = bad
            with self.subTest(field=field), mock.patch.object(runtime, 'kernel_bytes',
                    side_effect=lambda path, maximum=4096: changed[path.rsplit('/', 1)[-1]]):
                with self.assertRaises(SDKError): runtime.cgroup_limits(limits)

    def test_no_pidfd_or_proc_probe_after_reap(self):
        process = object.__new__(runtime.OwnedProcess); process.reaped = True
        with mock.patch.object(runtime.os, 'open', side_effect=AssertionError('reused numeric PID lookup')):
            with self.assertRaises(SDKError): process.proc_bytes('stat')

    def test_immediate_pidfd_precedes_proc_or_any_waiter(self):
        events = []; process = mock.Mock(pid=123)
        with (mock.patch.object(runtime, 'sole_reaper', side_effect=lambda: events.append('preflight')),
              mock.patch.object(runtime.subprocess, 'Popen', side_effect=lambda *a, **k: (events.append('launch') or process)),
              mock.patch.object(runtime.os, 'pidfd_open', side_effect=lambda *a: (events.append('pidfd') or 71), create=True),
              mock.patch.object(runtime.os, 'open', side_effect=lambda *a, **k: (events.append('proc') or 72))):
            owned = runtime.OwnedProcess.launch(['/approved/python', '-I', '-S', '-B', '/approved/worker.py'], (), 1, 2)
        self.assertFalse(owned.reaped)
        self.assertEqual(events, ['preflight', 'launch', 'pidfd', 'proc'])

    def test_ignored_sigchld_is_not_normalized_to_bypass_the_gate(self):
        with (mock.patch.object(runtime, 'platform_check'),
              mock.patch.object(runtime.signal, 'getsignal', return_value=signal.SIG_IGN),
              mock.patch.object(runtime.signal, 'signal', side_effect=AssertionError('signal repair'))):
            with self.assertRaises(SDKError): runtime.sole_reaper()

    def test_maps_parser_is_bounded_and_rejects_deleted_or_unknown_files(self):
        body = b'1000-2000 r-xp 000000 00:01 123 /usr/local/bin/python3.12\n'
        self.assertEqual(runtime.mapped_paths(body), ['/usr/local/bin/python3.12'])
        with self.assertRaises(SDKError): runtime.mapped_paths(body.replace(b'python3.12', b'python3.12 (deleted)'))

    def test_kernel_file_allowlist_rejects_traversal_before_lookup(self):
        with mock.patch.object(runtime.os, 'open', side_effect=AssertionError('escaped kernel lookup')):
            for path in ('/sys/fs/cgroup/../../../tmp/fixture-key','/sys/fs/cgroup/private', '/proc/123/maps'):
                with self.subTest(path=path), self.assertRaises(SDKError): runtime.kernel_bytes(path)

    def test_executable_verification_reserves_shared_budget_before_payload_read(self):
        from operation_sdk.source import ReadBudget
        p=example_policy();deployment=p['deployment'];path=deployment['python_path']
        deployment['runtime_sizes'][path]=6
        owned=object.__new__(runtime.OwnedProcess);owned.reaped=False;owned.proc_fd=72
        owned.process=mock.Mock(pid=123);owned.exited=mock.Mock(return_value=False)
        owned.proc_bytes=mock.Mock(return_value=b'123 (fixture) '+b' '.join([b'S']+[b'0']*18+[b'123']))
        info=types.SimpleNamespace(st_dev=1,st_ino=2,st_uid=0,st_mode=0o100755,st_nlink=1,
                                   st_size=6,st_mtime_ns=1,st_ctime_ns=1)
        budget=ReadBudget(0,1)
        with (mock.patch.object(runtime.os,'readlink',return_value=path),
              mock.patch.object(runtime.os,'open',return_value=71),
              mock.patch.object(runtime.os,'fstat',return_value=info),
              mock.patch.object(runtime.os,'read',side_effect=AssertionError('unreserved executable read')),
              mock.patch.object(runtime.native,'close')):
            with self.assertRaises(SDKError):owned.observe(deployment,p['limits'],budget=budget)
        self.assertEqual(budget.count,1)

    def test_deprecated_typing_export_is_an_alias_not_a_fabricated_module_spec(self):
        owner=types.ModuleType('typing');owner.__file__='/usr/local/lib/python3.12/typing.py'
        owner.__spec__=types.SimpleNamespace(origin=owner.__file__,name='typing')
        alias=type('io',(),{});owner.io=alias
        with mock.patch.dict(runtime.sys.modules,{'typing':owner,'typing.io':alias},clear=True):
            descriptor=runtime.module_descriptors(set())['typing.io']
        self.assertEqual(descriptor,{'kind':'export_alias','path':None,'spec_name':None,'owner':'typing'})
