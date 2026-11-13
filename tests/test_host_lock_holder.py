"""The holder of a busy host lease is named; real local flock, no Docker, endpoint or keys."""
import argparse
import contextlib
import fcntl
import io
import json
import os
from pathlib import Path
import re
import select
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]/'skill'
sys.path.insert(0, str(ROOT/'scripts'))
import pi_lab as lab
import resources

HELD_BY = re.compile(r'Held by pid (\d+) \(([a-z-]+)\) for (\d+) seconds')
# A real `run` whose stage body is replaced: it holds the lease until stdin closes.
RUN_HOLDER = ('import json,sys,time\n'
              'import pi_lab\n'
              'def body(args,attempt,*rest,**named):\n'
              ' print(json.dumps({"run_id":attempt.record["run_id"],"entered_unix":time.time()}),flush=True)\n'
              ' sys.stdin.read()\n'
              'pi_lab._execute_suite=body\n'
              'sys.exit(pi_lab.main(sys.argv[1:]))\n')
# A library client that names its run only after it entered the lease.
LATE_HOLDER = ('import sys\n'
               'import resources\n'
               'resources.describe_holder(op="browser-check")\n'
               'with resources.admission_lock(sys.argv[1]):\n'
               ' print("entered",flush=True);sys.stdin.readline()\n'
               ' resources.describe_holder(run_id=sys.argv[2],held=True)\n'
               ' print("named",flush=True);sys.stdin.read()\n')


class HostLockHolderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.lease = self.root/'lease'
        self.children = []
        self.addCleanup(self.stop_children)
        saved = resources._holder_op, resources._holder_next_run
        self.addCleanup(lambda: (setattr(resources, '_holder_op', saved[0]), setattr(resources, '_holder_next_run', saved[1])))
        resources._holder_op = resources._holder_next_run = None
        self.assertEqual(resources._holder_leases, [])

    def stop_children(self):
        for child in self.children:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)

    def environment(self, **extra):
        """No key, no Docker on PATH and a private home, so nothing outside the test is reached."""
        empty = self.root/'no-tools';empty.mkdir(exist_ok=True)
        home = self.root/'home';home.mkdir(exist_ok=True)
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(('PI_APP_', 'PI_LAB_')) and k not in ('PI_API_KEY', 'DOCKER_HOST')}
        env.update(PYTHONPATH=str(ROOT/'scripts'), PYTHONDONTWRITEBYTECODE='1', PATH=str(empty), HOME=str(home))
        env.update(extra)
        return env

    def run_arguments(self, name, lease=None):
        project = self.root/(name+'-project');project.mkdir(exist_ok=True)
        argv = ['run', '--project', str(project), '--endpoint', str(self.root/'never-read.json'),
                '--results-dir', str(self.root/(name+'-results')), '--platform', 'linux/arm64']
        return argv + (['--lock-file', str(lease)] if lease else [])

    def start(self, code, argv, cwd=None, env=None):
        child = subprocess.Popen([sys.executable, '-c', code]+[str(value) for value in argv], cwd=cwd,
                                 env=env or self.environment(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        self.children.append(child)
        return child

    def line(self, child):
        self.assertTrue(select.select([child.stdout], [], [], 60)[0], 'the helper never reported')
        return child.stdout.readline().strip()

    def run_holder(self, lease=None, cwd=None, env=None):
        child = self.start(RUN_HOLDER, self.run_arguments('holder', lease), cwd, env)
        return child, json.loads(self.line(child))

    def cli(self, argv, cwd=None, env=None):
        return subprocess.run([sys.executable, str(ROOT/'scripts/pi_lab.py')]+argv, cwd=cwd, env=env or self.environment(),
                              capture_output=True, text=True, timeout=120)

    @contextlib.contextmanager
    def raw_holder(self, content):
        """Hold the lease in this process without the runner, with an arbitrary record."""
        with open(self.lease, 'a+') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            self.lease.write_bytes(content)
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    def refused_run(self):
        """An in-process run that must be refused before any stage: (result, stderr)."""
        args = lab.parser().parse_args(self.run_arguments('refused', self.lease))
        output, errors = io.StringIO(), io.StringIO()
        with mock.patch.object(lab, '_execute_suite') as body, contextlib.redirect_stdout(output), \
             contextlib.redirect_stderr(errors):
            self.assertEqual(lab.run_suite(args), 2)
        body.assert_not_called()
        result = json.loads(output.getvalue())
        self.assertEqual((result['status'], result['exit_code']), ('BLOCKED', 2))
        self.assertEqual(result['infrastructure']['reason'], 'host-admission-busy')
        self.assertEqual(lab.controls.read(Path(result['run_dir'])/'result.json'), result)
        return result, errors.getvalue()

    def refused_command(self):
        """An in-process ensure-image refused at admission: (failure object, later stderr lines)."""
        argv = ['ensure-image', '--policy', 'reuse', '--image', 'not-launched', '--platform', 'linux/arm64',
                '--lock-file', str(self.lease)]
        with mock.patch.object(lab, 'dispatch', side_effect=AssertionError('entered a busy lease')), \
             self.assertRaises(resources.AdmissionError) as caught:
            lab.main(argv)
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            self.assertEqual(lab.cli_failure(caught.exception), 2)
        lines = errors.getvalue().splitlines()
        failure = json.loads(lines[0])
        self.assertEqual((failure['document_type'], failure['status'], failure['exit_code']), ('admission_failure', 'BLOCKED', 2))
        self.assertEqual(failure['infrastructure']['reason'], 'host-admission-busy')
        return failure, lines[1:]

    def record(self, **fields):
        return (json.dumps({'pid': os.getpid(), 'started_unix': time.time(), **fields})+'\n').encode()

    def doctor(self, lease, environment):
        endpoint = self.root/'endpoint.json'
        endpoint.write_text(json.dumps({'base_url': 'http://localhost:8000/v1', 'model': 'test-model',
                                        'context_window': 8192, 'max_tokens': 2048, 'api_key_env': 'PI_API_KEY'}))
        args = argparse.Namespace(image='pi-agent-tests:core', endpoint=str(endpoint), secrets_dir=str(self.root/'secrets'),
                                  skip_network=True, project=None, probe_image=False, lock_file=str(lease), lock_wait_seconds=0)

        def docker(argv, **named):
            if argv[:3] == ['docker', 'context', 'inspect']:
                return argparse.Namespace(returncode=0, stdout=json.dumps([{'Endpoints': {'docker': {'Host': 'unix:///var/run/docker.sock'}}}]))
            return argparse.Namespace(returncode=0, stdout='arm64\n')
        output = io.StringIO()
        with mock.patch.object(lab, 'docker_info', return_value={'ServerVersion': '27.0.0', 'OSType': 'linux', 'Architecture': 'aarch64'}), \
             mock.patch.object(lab, 'command', side_effect=docker), \
             mock.patch.dict(os.environ, {'HOME': str(self.root/'home'), **environment}, clear=True), \
             contextlib.redirect_stdout(output):
            lab.cmd_doctor(args)
        report = json.loads(output.getvalue())
        found = [item for item in report['checks'] if item['check'] == 'host-lock']
        self.assertEqual(len(found), 1)
        self.assertFalse(any('host-lock' in step for step in report['next_steps']))
        return found[0]

    def test_run_refused_by_a_running_helper_names_its_pid_command_run_and_age(self):
        helper, entered = self.run_holder(self.lease)
        before = time.time()
        result = self.cli(self.run_arguments('second', self.lease))
        after = time.time()
        self.assertEqual(result.returncode, 2, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual((value['status'], value['infrastructure']['reason']), ('BLOCKED', 'host-admission-busy'))
        holder = value['infrastructure']['holder']
        self.assertEqual(list(holder), ['pid', 'op', 'started_unix', 'age_seconds', 'run_id', 'alive'])
        self.assertEqual((holder['pid'], holder['op'], holder['run_id'], holder['alive']),
                         (helper.pid, 'run', entered['run_id'], True))
        self.assertNotEqual(value['run_id'], holder['run_id'])
        self.assertLessEqual(before-entered['entered_unix']-2, holder['age_seconds'])
        self.assertLessEqual(holder['age_seconds'], after-entered['entered_unix']+2)
        text = HELD_BY.fullmatch(result.stderr.strip())
        self.assertIsNotNone(text, result.stderr)
        self.assertEqual((int(text.group(1)), text.group(2), int(text.group(3))),
                         (helper.pid, 'run', int(holder['age_seconds'])))
        self.assertEqual(lab.controls.read(Path(value['run_dir'])/'result.json'), value)
        # The record stays one JSON line that only the holder wrote.
        self.assertEqual(json.loads(self.lease.read_text()), {'pid': helper.pid, 'started_unix': holder['started_unix'],
                                                              'op': 'run', 'run_id': entered['run_id']})
        self.assertEqual(self.lease.read_text().count('\n'), 1)

    def test_other_commands_add_the_holder_to_the_failure_line_and_one_text_line(self):
        helper, entered = self.run_holder(self.lease)
        result = self.cli(['ensure-image', '--policy', 'reuse', '--image', 'not-launched', '--platform', 'linux/arm64',
                           '--lock-file', str(self.lease)])
        self.assertEqual((result.returncode, result.stdout), (2, ''))
        lines = result.stderr.splitlines()
        self.assertEqual(len(lines), 2, result.stderr)
        failure = json.loads(lines[0])
        self.assertEqual((failure['document_type'], failure['exit_code']), ('admission_failure', 2))
        self.assertEqual(failure['infrastructure']['reason'], 'host-admission-busy')
        holder = failure['infrastructure']['holder']
        self.assertEqual((holder['pid'], holder['op'], holder['run_id'], holder['alive']),
                         (helper.pid, 'run', entered['run_id'], True))
        self.assertEqual(lines[1], resources.holder_text(holder))
        self.assertIsNotNone(HELD_BY.fullmatch(lines[1]))

    def test_recorded_age_is_reported_within_two_seconds(self):
        with self.raw_holder(self.record(started_unix=time.time()-1234.5, op='smoke')):
            result, errors = self.refused_run()
            holder = result['infrastructure']['holder']
            self.assertEqual((holder['pid'], holder['op'], holder['alive']), (os.getpid(), 'smoke', True))
            self.assertNotIn('run_id', holder)
            self.assertLess(abs(holder['age_seconds']-1234.5), 2)
            text = HELD_BY.fullmatch(errors.strip())
            self.assertEqual((int(text.group(1)), text.group(2)), (os.getpid(), 'smoke'))
            self.assertLess(abs(int(text.group(3))-1234.5), 2)
            failure, lines = self.refused_command()
            self.assertLess(abs(failure['infrastructure']['holder']['age_seconds']-1234.5), 2)
            self.assertEqual(len(lines), 1)

    def test_unusable_record_gives_a_null_holder_with_the_same_exit_code_and_reason(self):
        padded = self.record(op='run')[:-1]+b' '*resources.HOLDER_RECORD_LIMIT+b'\n'
        cases = {'empty': b'', 'blank-line': b'\n', 'not-json': b'pid 12\n', 'cut-short': self.record()[:-3],
                 'not-an-object': b'[12, 1.0]\n', 'text-pid': b'{"pid": "12", "started_unix": 1.0}\n',
                 'boolean-pid': b'{"pid": true, "started_unix": 1.0}\n', 'zero-pid': b'{"pid": 0, "started_unix": 1.0}\n',
                 'negative-pid': b'{"pid": -5, "started_unix": 1.0}\n', 'no-start': b'{"pid": 12}\n',
                 'nonfinite-start': b'{"pid": 12, "started_unix": NaN}\n', 'unsafe-op': self.record(op='run; rm -rf'),
                 'unsafe-run': self.record(run_id='a b'), 'two-lines': self.record()+self.record(),
                 'not-text': b'\xff\xfe'+self.record(), 'larger-than-the-limit': padded}
        self.assertGreater(len(padded), resources.HOLDER_RECORD_LIMIT)
        for name, content in cases.items():
            with self.subTest(record=name), self.raw_holder(content):
                self.assertIsNone(resources.read_holder(self.lease))
                self.assertEqual(resources.lease_state(self.lease), {'state': 'held', 'holder': None})
                result, errors = self.refused_run()
                self.assertIn('holder', result['infrastructure']);self.assertIsNone(result['infrastructure']['holder'])
                self.assertEqual(errors, '')
                failure, lines = self.refused_command()
                self.assertIn('holder', failure['infrastructure']);self.assertIsNone(failure['infrastructure']['holder'])
                self.assertEqual(lines, [])
                self.assertEqual(self.lease.read_bytes(), content)

    def test_record_at_the_size_limit_is_still_read(self):
        content = self.record(op='run')[:-1]
        content += b' '*(resources.HOLDER_RECORD_LIMIT-len(content)-1)+b'\n'
        self.assertEqual(len(content), resources.HOLDER_RECORD_LIMIT)
        with self.raw_holder(content):
            self.assertEqual(resources.read_holder(self.lease)['pid'], os.getpid())

    def test_symbolic_link_or_replaced_record_is_never_read(self):
        other = self.root/'other';other.write_bytes(self.record(op='run'))
        link = self.root/'link';link.symlink_to(other)
        self.assertEqual(resources.read_holder(other)['op'], 'run')
        self.assertIsNone(resources.read_holder(link))
        self.assertEqual(resources.lease_state(link), {'state': 'unavailable', 'holder': None})
        self.assertIsNone(resources.read_holder(self.root/'missing'))
        os.mkfifo(self.root/'pipe')
        self.assertIsNone(resources.read_holder(self.root/'pipe'))
        self.assertEqual(resources.lease_state(self.root/'pipe')['state'], 'unavailable')
        # The lease is replaced between its open and the refusal: by a link, then by another file.
        original = fcntl.flock
        for replacement in ('link', 'file'):
            with self.subTest(replacement=replacement), self.raw_holder(self.record(op='smoke')):
                kept = self.root/('kept-'+replacement)

                def refuse(fd, flags):
                    if flags == fcntl.LOCK_EX | fcntl.LOCK_NB and not kept.exists():
                        os.rename(self.lease, kept)
                        if replacement == 'link':self.lease.symlink_to(other)
                        else:self.lease.write_bytes(self.record(op='run'))
                    return original(fd, flags)
                with mock.patch.object(resources.fcntl, 'flock', side_effect=refuse):
                    result, errors = self.refused_run()
                self.assertIsNone(result['infrastructure']['holder']);self.assertEqual(errors, '')
                self.lease.unlink();os.rename(kept, self.lease)

    def test_reading_the_holder_cannot_change_admission(self):
        with self.raw_holder(self.record(op='run')):
            with mock.patch.object(resources, 'read_holder', side_effect=RuntimeError('unreadable')):
                result, errors = self.refused_run()
            self.assertIsNone(result['infrastructure']['holder']);self.assertEqual(errors, '')
            with mock.patch.object(resources.os, 'fstat', side_effect=OSError('unavailable')):
                with self.assertRaises(resources.AdmissionError) as caught:
                    with resources.admission_lock(self.lease):self.fail('entered a busy lease')
            self.assertEqual(caught.exception.reason, 'host-admission-busy')
            self.assertIsNone(resources.admission_holder(caught.exception))
            # A bounded wait that expires names the holder like an immediate refusal.
            with mock.patch.object(resources, '_queued_flock', side_effect=resources.AdmissionError('host-admission-busy')):
                with self.assertRaises(resources.AdmissionError) as caught:
                    with resources.admission_lock(self.lease, 1):self.fail('entered a busy lease')
            self.assertEqual(resources.admission_holder(caught.exception)['op'], 'run')
        with resources.admission_lock(self.lease):pass

    def test_holder_is_a_closed_projection_of_the_failure(self):
        good = {'pid': 12, 'op': 'run', 'started_unix': 5.0, 'age_seconds': 1.5, 'run_id': 'a-1', 'alive': True}
        error = resources.AdmissionError('host-admission-busy');error._lease_holder = dict(good)
        self.assertEqual(resources.admission_holder(error), good)
        self.assertIsNot(resources.admission_holder(error), error._lease_holder)
        for change in ({'pid': '12'}, {'op': 'https://private.example.invalid'}, {'alive': 'yes'}, {'age_seconds': float('inf')},
                       {'run_id': 'a b'}, {'extra': 'text'}):
            with self.subTest(change=change):
                error._lease_holder = {**good, **change}
                self.assertIsNone(resources.admission_holder(error))
        other = resources.AdmissionError('admission-lock-unavailable');other._lease_holder = dict(good)
        self.assertIsNone(resources.admission_holder(other))
        spoof = ValueError('busy');spoof._lease_holder = dict(good);spoof._admission_reason = 'host-admission-busy'
        self.assertIsNone(resources.admission_holder(spoof))
        # Only a busy failure carries the key at all.
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            self.assertEqual(lab.cli_failure(other), 2)
        self.assertNotIn('holder', json.loads(errors.getvalue())['infrastructure'])

    def test_record_written_under_the_lease_names_command_and_run(self):
        with resources.admission_lock(self.lease):
            plain = json.loads(self.lease.read_text())
        self.assertEqual(set(plain), {'pid', 'started_unix'})
        resources.describe_holder(op='Not A Command');resources.describe_holder(run_id='not a run')
        with resources.admission_lock(self.lease):
            self.assertEqual(set(json.loads(self.lease.read_text())), {'pid', 'started_unix'})
        resources.describe_holder(op='smoke', run_id='run-1')
        other = self.record()
        with self.raw_holder(other):
            with self.assertRaises(resources.AdmissionError):
                with resources.admission_lock(self.lease):self.fail('entered a busy lease')
            self.assertEqual(self.lease.read_bytes(), other)
        # The run id belonged to the refused admission only; the command name stays.
        with resources.admission_lock(self.lease):
            self.assertEqual(json.loads(self.lease.read_text()), {'pid': os.getpid(), 'started_unix': mock.ANY, 'op': 'smoke'})
            resources.describe_holder(run_id='run-2')
            self.assertNotIn('run_id', json.loads(self.lease.read_text()))
        with resources.admission_lock(self.lease):
            first = self.lease.read_text()
            self.assertEqual(json.loads(first)['run_id'], 'run-2')
            resources.describe_holder(run_id='run-3', held=True)
            second = self.lease.read_text()
            self.assertEqual(json.loads(second), {**json.loads(first), 'run_id': 'run-3'})
            self.assertEqual((second.count('\n'), second[-1]), (1, '\n'))
        self.assertEqual(resources._holder_leases, [])
        resources.describe_holder(run_id='run-4', held=True)
        self.assertEqual(self.lease.read_text(), second)

    def test_run_id_named_under_the_lease_is_rewritten_in_place(self):
        helper = self.start(LATE_HOLDER, [self.lease, 'late-run'])
        self.assertEqual(self.line(helper), 'entered')
        identity = os.stat(self.lease).st_ino
        early = resources.read_holder(self.lease)
        self.assertEqual((early['pid'], early['op'], early['alive']), (helper.pid, 'browser-check', True))
        self.assertNotIn('run_id', early)
        helper.stdin.write('\n');helper.stdin.flush()
        self.assertEqual(self.line(helper), 'named')
        late = resources.read_holder(self.lease)
        self.assertEqual((late['pid'], late['run_id'], late['started_unix']), (helper.pid, 'late-run', early['started_unix']))
        self.assertEqual((os.stat(self.lease).st_ino, self.lease.read_text().count('\n')), (identity, 1))

    def test_record_of_a_dead_process_is_marked_and_the_remedy_does_not_call_it_stuck(self):
        gone = subprocess.Popen([sys.executable, '-c', 'pass']);gone.wait(timeout=30)
        with self.raw_holder(self.record(pid=gone.pid, op='run')):
            result, errors = self.refused_run()
            holder = result['infrastructure']['holder']
            self.assertEqual((holder['pid'], holder['alive']), (gone.pid, False))
            self.assertTrue(errors.startswith('Held by pid %d (run) for ' % gone.pid), errors)
            self.assertIn('no process with that pid exists', errors)
            remedy = result['infrastructure']['remedy']
        self.assertEqual(remedy, resources.ADMISSION_FAILURES['host-admission-busy'][1])
        self.assertIn('not a stuck lock', remedy);self.assertIn('kernel releases', remedy)
        self.assertLessEqual(len(remedy), 384)
        self.assertEqual(re.findall(r'[^.]*\b(?:delete|remove|unlink)\b[^.]*', remedy.lower()),
                         [' do not delete the lock or use another lock file to bypass admission'])
        # A record written before commands were named is still a holder.
        with self.raw_holder(self.record()):
            old = resources.read_holder(self.lease)
            self.assertIsNone(old['op'])
            self.assertEqual(resources.holder_text(old), 'Held by pid %d (unknown) for 0 seconds' % os.getpid())

    def test_doctor_reports_a_free_lease_its_path_and_how_it_was_selected(self):
        item = self.doctor(self.lease, {})
        self.assertEqual((item['status'], item['state'], item['path'], item['selected_by']), ('ok', 'free', str(self.lease), '--lock-file'))
        self.assertTrue(item['detail'].startswith('free: '+str(self.lease)), item['detail'])
        self.assertIn('PI_LAB_LOCK_FILE did not select it', item['detail'])
        self.assertNotIn('holder', item);self.assertNotIn('remedy', item)
        self.assertFalse(self.lease.exists(), 'doctor must not create the lease')
        # A lease that was used and released is free although its last record remains.
        with resources.admission_lock(self.lease):pass
        before = self.lease.read_bytes(), os.stat(self.lease).st_mtime_ns
        selected = self.doctor(self.lease, {'PI_LAB_LOCK_FILE': str(self.lease)})
        self.assertEqual((selected['status'], selected['state'], selected['path'], selected['selected_by']),
                         ('ok', 'free', str(self.lease), 'PI_LAB_LOCK_FILE'))
        self.assertIn('selected by PI_LAB_LOCK_FILE', selected['detail'])
        self.assertEqual((self.lease.read_bytes(), os.stat(self.lease).st_mtime_ns), before)
        overridden = self.doctor(self.lease, {'PI_LAB_LOCK_FILE': str(self.root/'another')})
        self.assertEqual(overridden['selected_by'], '--lock-file')
        with mock.patch.dict(os.environ, {'HOME': str(self.root/'home')}):
            os.environ.pop('PI_LAB_LOCK_FILE', None)
            shared = lab.default_lock_file()
        self.assertTrue(shared.startswith(str(self.root/'home')))
        default = self.doctor(shared, {})
        self.assertEqual((default['state'], default['path'], default['selected_by']), ('free', shared, 'default'))
        self.assertIn('shared host lease', default['detail'])
        link = self.root/'link';link.symlink_to(self.lease)
        unsafe = self.doctor(link, {})
        self.assertEqual((unsafe['status'], unsafe['state'], unsafe['path']), ('warn', 'unavailable', str(link)))

    def test_doctor_names_the_holder_of_a_held_lease(self):
        helper, entered = self.run_holder(self.lease)
        item = self.doctor(self.lease, {'PI_LAB_LOCK_FILE': str(self.lease)})
        self.assertEqual((item['status'], item['state'], item['path'], item['selected_by']),
                         ('warn', 'held', str(self.lease), 'PI_LAB_LOCK_FILE'))
        holder = item['holder']
        self.assertEqual((holder['pid'], holder['op'], holder['run_id'], holder['alive']),
                         (helper.pid, 'run', entered['run_id'], True))
        self.assertTrue(item['detail'].startswith(resources.holder_text(holder)+': '+str(self.lease)), item['detail'])
        self.assertEqual((item['reason'], item['remedy']), ('host-admission-busy', resources.ADMISSION_FAILURES['host-admission-busy'][1]))
        helper.kill();helper.wait(timeout=30)
        freed = self.doctor(self.lease, {'PI_LAB_LOCK_FILE': str(self.lease)})
        self.assertEqual((freed['status'], freed['state']), ('ok', 'free'))
        self.assertNotIn('holder', freed)

    def test_default_lease_excludes_invocations_from_different_working_directories(self):
        first = self.root/'checkout-one';second = self.root/'checkout-two'
        first.mkdir();second.mkdir()
        env = self.environment()
        self.assertNotIn('PI_LAB_LOCK_FILE', env)
        helper, entered = self.run_holder(cwd=first, env=env)
        shared = Path(env['HOME'])/'.local/state/pi-agent-test-env/operation.lock'
        self.assertEqual(json.loads(shared.read_text())['pid'], helper.pid)
        result = self.cli(self.run_arguments('second'), cwd=second, env=env)
        self.assertEqual(result.returncode, 2, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value['infrastructure']['reason'], 'host-admission-busy')
        self.assertEqual(value['invocation'], {'status': 'not_started', 'attempted_stages': 0})
        holder = value['infrastructure']['holder']
        self.assertEqual((holder['pid'], holder['op'], holder['run_id']), (helper.pid, 'run', entered['run_id']))
        self.assertIsNotNone(HELD_BY.fullmatch(result.stderr.strip()), result.stderr)
        self.assertEqual(sorted(p.name for p in shared.parent.iterdir()), ['operation.lock', 'operation.lock.registry'])
        self.assertFalse(any(path.name.startswith('operation.lock') for path in list(first.iterdir())+list(second.iterdir())))


if __name__ == '__main__':unittest.main()
