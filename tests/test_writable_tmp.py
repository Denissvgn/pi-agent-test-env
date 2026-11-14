"""Writable, non-executable /tmp in child containers; probe, boundary and doctor observations."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1] / 'skill'
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'runtime'))
import pi_lab as lab
import ownership_registry
import resources
import worker

IMAGE = 'sha256:' + 'b' * 64
GOOD = {'writable': True, 'noexec': True, 'filesystem': 'tmpfs', 'error': None}


def arguments(*extra):
    return lab.parser().parse_args(['run', '--platform', 'linux/arm64', '--cpus', '1', '--memory', '128m', *extra])


class DockerArgumentTests(unittest.TestCase):
    def build(self, args, access='rw'):
        with tempfile.TemporaryDirectory() as td:
            top = Path(td)
            return lab.docker_args(args, IMAGE, top / 'w', top / 'c', top / 's', 'pi-lab-fixture', 'none', access=access)

    def test_every_child_container_gets_one_small_noexec_tmp(self):
        for access in ('rw', 'ro'):
            with self.subTest(access=access):
                argv = self.build(arguments(), access)
                self.assertEqual(argv.count('--tmpfs'), 1)
                self.assertEqual(argv[argv.index('--tmpfs') + 1], '/tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777')
                self.assertIn('--read-only', argv)
                self.assertLess(argv.index('--tmpfs'), argv.index(IMAGE))

    def test_tmp_options_never_allow_programs_devices_or_set_uid(self):
        options = resources.TMP_MOUNT.split(':', 1)[1].split(',')
        for required in ('noexec', 'nosuid', 'nodev'):
            self.assertIn(required, options)
        self.assertNotIn('exec', options)

    def test_runtime_directories_stay_under_pi_state(self):
        argv = self.build(arguments())
        environment = dict(value.split('=', 1) for value in argv if '=' in value and value.split('=', 1)[0] in ('TMPDIR', 'HOME'))
        self.assertEqual(environment, {'TMPDIR': '/pi-state/tmp', 'HOME': '/pi-state/home'})


class ParallelGrantTests(unittest.TestCase):
    def peer(self, root, run_id):
        from parallel_allocator import Allocator
        from parallel_dispatch import Peer
        pool = Allocator({'cpu_millis': 2500, 'memory_mib': 1024, 'pids_limit': 256})
        reservation = pool.request('trial', {'trial_id': 'trial', 'generation': 'private'},
                                   {'cpu_millis': 1000, 'memory_mib': 128, 'pids_limit': 64}, 10); pool.dispatch()
        return Peer({'network': 'pi-fixture', 'experiment': str(root), 'intent': {'run_id': run_id}},
                    ownership_registry.Registry(root / 'registry', mock.Mock()), pool, reservation,
                    {'execution': {'platform': 'linux/arm64', 'image': IMAGE}}, root / 'runs/run')

    def test_a_trial_grant_admits_exactly_the_reviewed_tmp_mount(self):
        from parallel_contract import ParallelError
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve(); run = root / 'runs/run'; run.mkdir(parents=True); run_id = str(uuid.uuid4())
            peer = self.peer(root, run_id)
            args = arguments('--pids-limit', '64'); args._attempt_identity = {'run_id': run_id, 'attempt_id': str(uuid.uuid4())}
            argv = lab.docker_args(args, IMAGE, run / 'workspace', run / 'control', run / 'state', 'pi-lab-fixture',
                                   'pi-fixture', helpers=run / 'runtime')
            peer.validate_launch(argv)
            index = argv.index('--tmpfs')
            for changed in ('/tmp:rw,nosuid,nodev,exec,size=256m,mode=1777', '/tmp:rw,size=4g', '/workspace:rw'):
                with self.subTest(mount=changed), self.assertRaises(ParallelError):
                    peer.validate_launch(argv[:index + 1] + [changed] + argv[index + 2:])
            with self.assertRaises(ParallelError):
                peer.validate_launch(argv[:index] + ['--tmpfs', '/var:rw'] + argv[index:])


class WorkerObservationTests(unittest.TestCase):
    def mounts(self, options):
        return f'overlay / overlay ro 0 0\ntmpfs /tmp tmpfs {options} 0 0\n'

    def test_observation_through_a_temporary_directory(self):
        with tempfile.TemporaryDirectory() as td:
            mounts = Path(td) / 'mounts'; scratch = Path(td) / 'tmp'; scratch.mkdir()
            mounts.write_text(self.mounts('rw,nosuid,nodev,noexec,relatime,size=262144k,mode=1777'))
            original = worker.Path
            def path(value, *rest):
                return {'/tmp': scratch, '/proc/mounts': mounts}.get(value) or original(value, *rest)
            with mock.patch.object(worker, 'Path', side_effect=path):
                self.assertEqual(worker.tmp_observation(), GOOD)
                mounts.write_text(self.mounts('rw,nosuid,nodev,relatime'))
                self.assertEqual(worker.tmp_observation()['noexec'], False)
                scratch.chmod(0o500)
                try:
                    seen = worker.tmp_observation()
                finally:
                    scratch.chmod(0o700)
                if seen['writable'] is False:  # Unprivileged users only; root ignores the mode.
                    self.assertEqual(seen['error'], 'EACCES')

    SOCKETS = ('/var/run/docker.sock', '/run/podman/podman.sock')
    REAL_EXISTS = Path.exists

    def no_engine_socket(self, path):
        # The test host may run Docker; the check under test is the one after the socket check.
        return False if str(path) in self.SOCKETS else self.REAL_EXISTS(path)

    def test_boundary_refuses_a_tmp_that_is_read_only_or_runs_programs(self):
        for observed in ({'writable': False, 'noexec': True, 'filesystem': 'overlay', 'error': 'EROFS'},
                         {'writable': True, 'noexec': False, 'filesystem': 'tmpfs', 'error': None},
                         {'writable': True, 'noexec': None, 'filesystem': None, 'error': None}):
            with self.subTest(observed=observed), tempfile.TemporaryDirectory() as td, \
                 mock.patch.object(worker, 'tmp_observation', return_value=observed), \
                 mock.patch.object(worker.os, 'getuid', return_value=1000), \
                 mock.patch.object(worker.Path, 'exists', autospec=True, side_effect=self.no_engine_socket), \
                 mock.patch.dict(worker.os.environ, {'PI_LAB_READONLY_PROJECT': '1', 'TMPDIR': td}):
                with self.assertRaisesRegex(RuntimeError, '/tmp must be a writable noexec'):
                    worker.boundary()


class DoctorCheckTests(unittest.TestCase):
    def run_check(self, caller, other, exit_code=0):
        launched = []
        def stage(argv, logdir, timeout, name, *a, **k):
            launched.append(list(argv)); logdir.mkdir(parents=True, exist_ok=True)
            (logdir / 'stdout.jsonl').write_text(json.dumps({'workspace_access': 'ro', 'tmp': other}) + '\n' if other else '')
            (logdir / 'stderr.log').write_text('' if not exit_code else 'boundary refused')
            return {'exit_code': exit_code, 'cleanup_confirmed': True}
        args = arguments()
        with mock.patch.object(lab, 'stream_run', side_effect=stage):
            item = lab._tmp_check(args, {'id': IMAGE, 'capabilities': {'tmp': caller}})
        return item, launched

    def test_passes_when_both_uids_can_write_and_tmp_is_noexec(self):
        item, launched = self.run_check(GOOD, GOOD)
        self.assertEqual((item['check'], item['status']), ('tmp-writable', 'ok'))
        self.assertEqual(set(item['observed']), {'caller', 'uid_65534'})
        argv = launched[0]
        self.assertEqual(argv[argv.index('--user') + 1], '65534:65534')
        self.assertEqual(argv[argv.index('--network') + 1], 'none')
        self.assertEqual(argv[argv.index('/opt/pi-lab/worker.py') + 1], 'boundary')
        self.assertIn('PI_LAB_READONLY_PROJECT=1', argv)

    def test_fails_with_a_remedy_when_any_uid_cannot_use_tmp(self):
        bad = {'writable': False, 'noexec': True, 'filesystem': 'overlay', 'error': 'EROFS'}
        for caller, other, code in ((bad, GOOD, 0), (GOOD, bad, 0), (GOOD, None, 1), (None, GOOD, 0)):
            with self.subTest(caller=caller, other=other, code=code):
                item, _ = self.run_check(caller, other, code)
                self.assertEqual((item['status'], item['reason']), ('fail', 'tmp-not-writable'))
                self.assertTrue(item['remedy'])


if __name__ == '__main__':
    unittest.main()
