"""Unit tests for finite budgets, builder flags, and local admission locking.

Docker interactions are mocked. These tests do not claim a real image build.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = (Path(__file__).resolve().parents[1] / 'skill')
sys.path.insert(0, str(ROOT / 'scripts'))
import pi_lab as lab
import resources as res
import builder


def args(**overrides):
    a = lab.parser().parse_args(['doctor', '--uid', '1000'])
    for k, v in overrides.items(): setattr(a, k, v)
    return a


class PolicyTests(unittest.TestCase):
    def test_balanced_default(self):
        p = res.validate_policy({})
        self.assertEqual(p['runtime']['cpus'], 2)
        self.assertEqual(p['runtime']['memory'], '4g')
        self.assertEqual(p['build']['cpus'], 2)

    def test_zero_cpu_rejected(self):
        with self.assertRaises(ValueError): res.validate_policy({'runtime': {'cpus': 0}})

    def test_cpu_nan_rejected(self):
        with self.assertRaises(ValueError): res.validate_policy({'runtime': {'cpus': float('nan')}})

    def test_cpu_infinity_rejected(self):
        with self.assertRaises(ValueError): res.validate_policy({'build': {'cpus': float('inf')}})

    def test_boolean_cpu_rejected(self):
        with self.assertRaises(ValueError): res.validate_policy({'runtime': {'cpus': True}})

    def test_unlimited_memory_rejected(self):
        for value in ('-1', '0g', '', 'unlimited', 0):
            with self.subTest(value=value), self.assertRaises(ValueError):
                res.validate_policy({'runtime': {'memory': value}})

    def test_unknown_field_rejected(self):
        with self.assertRaises(ValueError): res.validate_policy({'runtime': {'privileged': True}})

    def test_invalid_policy_object(self):
        with self.assertRaises(ValueError): res.validate_policy([])

    def test_all_host_budget_rejected(self):
        with self.assertRaises(ValueError): res.validate_policy({'host_budget': {'cpu_fraction': 1.0}})

    def test_zero_pids_rejected(self):
        with self.assertRaises(ValueError): res.validate_policy({'runtime': {'pids_limit': 0}})

    def test_build_time_bounded(self):
        with self.assertRaises(ValueError): res.validate_policy({'build': {'timeout_seconds': 999999}})

    def test_override_not_mutate_defaults(self):
        p = res.validate_policy({'runtime': {'cpus': 1}})
        self.assertEqual(p['runtime']['cpus'], 1)
        self.assertEqual(res.DEFAULTS['runtime']['cpus'], 2)

    def test_cli_overrides_file(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td)/'r.json'; f.write_text(json.dumps({'runtime': {'cpus': 1, 'memory': '2g'}}))
            p = res.requested_policy(args(resources=str(f), cpus=1.5))
            self.assertEqual(p['runtime']['cpus'], 1.5)
            self.assertEqual(p['runtime']['memory'], '2g')

    def test_engine_capacity_not_host_cpu_count(self):
        a = args()
        r = res.configure(a, {'NCPU': 2, 'MemTotal': 2 * 1024**3})
        self.assertEqual(a.cpus, 1)
        self.assertEqual(a.memory, '1024m')
        self.assertEqual(a.jobs, 1)
        self.assertEqual(r['effective']['build']['cpus'], 1)

    def test_fractional_quota_on_small_daemon(self):
        a = args()
        res.configure(a, {'NCPU': 1, 'MemTotal': 1024**3})
        self.assertEqual(a.cpus, 0.5)
        self.assertEqual(a.jobs, 1)

    def test_requested_and_effective_distinct(self):
        a = args(cpus=10)
        r = res.configure(a, {'NCPU': 4, 'MemTotal': 16*1024**3})
        self.assertEqual(r['requested']['runtime']['cpus'], 10)
        self.assertEqual(r['effective']['runtime']['cpus'], 2)

    def test_repeated_resolution_preserves_requested(self):
        a = args(cpus=10)
        info={'NCPU': 4,'MemTotal': 16*1024**3}
        self.assertEqual(res.configure(a, info), res.configure(a, info))

    def test_no_extra_swap(self):
        r=res.configure(args(), {'NCPU':8,'MemTotal':16*1024**3})
        self.assertEqual(r['memory_swap'], r['effective']['runtime']['memory'])

    def test_unknown_engine_resources_rejected(self):
        with self.assertRaises(ValueError): res.configure(args(), {'NCPU':8})

    def test_unsupported_quota_rejected(self):
        with self.assertRaises(ValueError):
            res.configure(args(), {'NCPU':8,'MemTotal':16*1024**3,'Warnings':['WARNING: No cpu cfs quota support']})

    def test_resource_templates(self):
        for file in (ROOT/'assets/resources').glob('*.json'):
            res.validate_policy(json.loads(file.read_text()))

    def test_thread_hints_finite(self):
        e=res.thread_environment(1)
        self.assertEqual(e['MAKEFLAGS'],'-j1')
        self.assertEqual(e['GOMAXPROCS'],'1')
        self.assertEqual(e['CARGO_BUILD_JOBS'],'1')

    def test_all_runtime_command_limits(self):
        a=args();a.platform='linux/amd64'
        res.configure(a, {'NCPU':8,'MemTotal':16*1024**3})
        cmd=lab.docker_args(a,'image',Path('/x/w'),Path('/x/c'),Path('/x/w/.pi-lab/state'),'test','none')
        self.assertEqual(cmd[cmd.index('--cpus')+1], '2.0')
        self.assertEqual(cmd[cmd.index('--memory')+1], cmd[cmd.index('--memory-swap')+1])
        self.assertEqual(cmd[cmd.index('--pids-limit')+1], '256')
        self.assertIn('PI_TEST_JOBS=2', cmd)
        self.assertNotIn('--rm',cmd) # preserve OOM state until explicit cleanup


class AdmissionTests(unittest.TestCase):
    def test_conflicting_operations_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'operation.lock'
            with res.admission_lock(p):
                with self.assertRaises(ValueError):
                    with res.admission_lock(p): pass

    def test_release_on_exception(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'operation.lock'
            try:
                with res.admission_lock(p): raise RuntimeError('fixture')
            except RuntimeError: pass
            with res.admission_lock(p): pass
            self.assertTrue(p.exists())

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'operation.lock';p.symlink_to(Path(td)/'other')
            with self.assertRaises(ValueError):
                with res.admission_lock(p): pass

    def test_lock_blocks_another_process(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'operation.lock'
            code='from resources import admission_lock\nimport sys\nwith admission_lock(sys.argv[1]): print("unexpected")'
            with res.admission_lock(p):
                result=subprocess.run([sys.executable,'-c',code,str(p)],capture_output=True,text=True,
                                      env={**os.environ,'PYTHONPATH':str(ROOT/'scripts')},timeout=5)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('Another',result.stderr)


class BuilderTests(unittest.TestCase):
    def limits(self):
        return {'cpus': 1.5,'memory':'2g','max_parallelism':1,'timeout_seconds':120}

    def observed(self):
        return {'Id':'container-fixture','Image':'sha256:fixture','HostConfig':{
            'CpuPeriod':100000,'CpuQuota':150000,'Memory':2*1024**3,'MemorySwap':2*1024**3}}

    def test_builder_flags_limit_whole_build(self):
        cmd=builder.builder_options('fixture',self.limits(),'/tmp/config','trusted-buildkit')
        for expected in ('cpu-period=100000','cpu-quota=150000','memory=2g','memory-swap=2g'):
            self.assertIn(expected,cmd)
        self.assertIn('docker-container',cmd)
        self.assertNotIn('--use',cmd)

    def test_verify_actual_limits(self):
        self.assertEqual(builder.verify_builder(self.observed(),self.limits())['cpu_quota'],150000)

    def test_missing_or_different_limits_block(self):
        for key in ('CpuQuota','CpuPeriod','Memory','MemorySwap'):
            d=self.observed();d['HostConfig'][key]=0
            with self.subTest(key=key),self.assertRaises(ValueError): builder.verify_builder(d,self.limits())

    def build_args(self):
        a=lab.parser().parse_args(['ensure-image','--uid','1000','--pi-version','1.0.3'])
        a.platform='linux/arm64';a.resource_report={'effective':{'build':self.limits()}}
        return a

    def fake_command(self,argv,**kw):
        return argparse.Namespace(returncode=0,stderr='',stdout=json.dumps([{'Id':'sha256:arm-fixture','Os':'linux','Architecture':'arm64'}]) if argv[1:3]==['image','inspect'] else json.dumps([self.observed()]) if argv[1]=='inspect' else '')

    def test_build_loads_then_removes_builder(self):
        with mock.patch.object(builder.subprocess,'run',return_value=argparse.Namespace(returncode=0)) as build:
            cmd=mock.Mock(side_effect=self.fake_command)
            result=builder.limited_build(self.build_args(),ROOT/'docker/Dockerfile',ROOT/'docker',cmd)
        self.assertIn('--load',result['argv'])
        self.assertEqual(result['argv'][-1],str(ROOT/'docker'))
        self.assertEqual(build.call_args.kwargs['timeout'],120)
        self.assertTrue(any(c.args[0][1:4]==['buildx','rm','--force'] for c in cmd.call_args_list))

    def test_wrong_buildkit_architecture_blocks_before_bootstrap(self):
        def command(argv,**kw):
            if argv[1:3]==['image','inspect']:return argparse.Namespace(stdout=json.dumps([{'Id':'wrong','Os':'linux','Architecture':'amd64'}]))
            return self.fake_command(argv,**kw)
        cmd=mock.Mock(side_effect=command)
        with self.assertRaisesRegex(ValueError,'architecture'):builder.limited_build(self.build_args(),ROOT/'docker/Dockerfile',ROOT/'docker',cmd)
        self.assertFalse(any(c.args[0][1:3]==['buildx','create'] for c in cmd.call_args_list))
        self.assertEqual(cmd.call_args_list[1].args[0][1:4],['pull','--platform','linux/arm64'])

    def test_failed_build_still_removes_builder(self):
        with mock.patch.object(builder.subprocess,'run',return_value=argparse.Namespace(returncode=1)):
            cmd=mock.Mock(side_effect=self.fake_command)
            with self.assertRaises(ValueError): builder.limited_build(self.build_args(),ROOT/'docker/Dockerfile',ROOT/'docker',cmd)
        self.assertTrue(any(c.args[0][1:4]==['buildx','rm','--force'] for c in cmd.call_args_list))

    def test_build_timeout_still_removes_builder(self):
        with mock.patch.object(builder.subprocess,'run',side_effect=subprocess.TimeoutExpired('fixture',120)):
            cmd=mock.Mock(side_effect=self.fake_command)
            with self.assertRaises(ValueError): builder.limited_build(self.build_args(),ROOT/'docker/Dockerfile',ROOT/'docker',cmd)
        self.assertTrue(any(c.args[0][1:4]==['buildx','rm','--force'] for c in cmd.call_args_list))

    def test_missing_buildx_no_unbounded_fallback(self):
        cmd=mock.Mock(side_effect=RuntimeError('buildx missing'))
        with mock.patch.object(builder.subprocess,'run') as build:
            with self.assertRaises(RuntimeError): builder.limited_build(self.build_args(),ROOT/'docker/Dockerfile',ROOT/'docker',cmd)
            build.assert_not_called()
