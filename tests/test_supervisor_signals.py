"""Supervisor signals, deadlines and control-plane locks, with real signals.

A fake `docker` executable stands in for the daemon: `run` is a long-running
child that records its PID, `rm -f` kills it and logs the removal, `inspect`
reports an exited container. Supervisors run as separate processes so the
signals, process groups and inherited dispositions are real. Run this module in
the foreground: a shell background job starts with SIGINT ignored.
"""
import ast
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skill' / 'scripts'
RUNTIME = ROOT / 'skill' / 'runtime'
sys.path.insert(0, str(SCRIPTS))
import pi_lab as lab
import resources
import stage_control as controls

FAKE_DOCKER = '''#!{python}
import json, os, signal, sys, time
from pathlib import Path
state = Path({state!r})
args = sys.argv[1:]
def log(text):
    with open(state / 'calls.log', 'a') as stream:
        stream.write(text + '\\n')
if args[:1] == ['run']:
    name = args[args.index('--name') + 1]
    (state / (name + '.pid')).write_text(str(os.getpid()))
    log('run ' + name)
    # Runs until removed, or until FAKE_RUN_UNTIL names a file that exists.
    until = os.environ.get('FAKE_RUN_UNTIL')
    while not (until and os.path.exists(until)):
        time.sleep(0.05)
    log('run-exit ' + name)
elif args[:2] == ['rm', '-f']:
    name = args[2]
    log('rm-start ' + name)
    time.sleep(float(os.environ.get('FAKE_RM_SECONDS', '0')))
    pid = state / (name + '.pid')
    if pid.exists():
        try:
            os.kill(int(pid.read_text()), signal.SIGKILL)
        except ProcessLookupError:
            pass
        pid.unlink()
    log('rm-done ' + name)
    print(name)
elif args[:1] == ['inspect']:
    print(json.dumps([{{'State': {{'ExitCode': 137, 'OOMKilled': False, 'Error': ''}}, 'HostConfig': {{}}}}]))
else:
    log('other ' + ' '.join(args))
'''

# Installs the handlers exactly as the pi_lab.py entry point does, then supervises.
SUPERVISOR = '''
import sys
from pathlib import Path
sys.path.insert(0, {scripts!r})
import pi_lab as lab
import resources
resources.install_interrupt_handlers()
name = sys.argv[2]
try:
    lab.stream_run(['docker', 'run', '--name', name, 'fixture'], Path(sys.argv[1]), 600, name)
except KeyboardInterrupt:
    sys.exit(130)
'''

# A steer or extend-budget helper stopped while it holds the stage lock.
STOPPED_HOLDER = '''
import os, signal, sys
from pathlib import Path
sys.path.insert(0, {scripts!r})
import stage_control as controls
with controls.lock(Path(sys.argv[1]), sys.argv[2]):
    print('locked', flush=True)
    os.kill(os.getpid(), signal.SIGSTOP)
'''

# The same helper against a stage that run_stage() creates: it waits until the
# stage is running, takes its lock, leaves a marker and stops while holding it.
RUNNING_STAGE_HOLDER = '''
import os, signal, sys, time
from pathlib import Path
sys.path.insert(0, {scripts!r})
import stage_control as controls
run, marker = Path(sys.argv[1]), Path(sys.argv[2])
def running():
    for path in (run / 'stages').glob('*/state.json'):
        try:
            if controls.read(path).get('status') == 'running':
                return path.parent.name
        except (OSError, ValueError, controls.ControlError):
            pass
deadline = time.monotonic() + 60
stage = running()
while stage is None and time.monotonic() < deadline:
    time.sleep(0.02)
    stage = running()
with controls.lock(run, stage):
    marker.write_text(stage)
    os.kill(os.getpid(), signal.SIGSTOP)
'''

# Exit status 0 when another process can take the history lock without waiting.
HISTORY_PROBE = ('import fcntl, os, sys\n'
                 'fd = os.open(sys.argv[1], os.O_RDONLY)\n'
                 'operation = fcntl.LOCK_EX if sys.argv[2] == "exclusive" else fcntl.LOCK_SH\n'
                 'try:\n'
                 '    fcntl.flock(fd, operation | fcntl.LOCK_NB)\n'
                 'except BlockingIOError:\n'
                 '    sys.exit(1)\n')


def history_free(run, mode):
    """Whether a separate process could take the intervention history lock now."""
    return subprocess.run([sys.executable, '-c', HISTORY_PROBE, str(run / 'interventions.jsonl'), mode],
                          timeout=30).returncode == 0


def stage_args(**fields):
    import argparse
    value = dict(platform='linux/arm64', uid=os.getuid(), gid=os.getgid(), memory='1g', cpus=1,
                 allow_browser_no_sandbox=False, software_webgl=False, network='none')
    value.update(fields)
    return argparse.Namespace(**value)


def ignore_sigint():
    """Runs in the forked child before exec, as a shell does for a background job."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def wait_for(predicate, timeout=30, message='condition'):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError('Timed out waiting for ' + message)


class FakeDocker:
    def __init__(self, top):
        self.state = top / 'docker-state'
        self.state.mkdir()
        self.bin = top / 'bin'
        self.bin.mkdir()
        docker = self.bin / 'docker'
        docker.write_text(FAKE_DOCKER.format(python=sys.executable, state=str(self.state)))
        docker.chmod(0o700)

    def environment(self, **extra):
        return {**os.environ, 'PATH': str(self.bin) + os.pathsep + os.environ.get('PATH', ''),
                'PYTHONDONTWRITEBYTECODE': '1', **extra}

    def calls(self):
        path = self.state / 'calls.log'
        return path.read_text().splitlines() if path.exists() else []


def prepare_stage(top, timeout_seconds, native_limits=None, native_control=None):
    run = top / 'run'
    run.mkdir()
    workspace = top / 'project'
    workspace.mkdir()
    stage_id = str(uuid.uuid4())
    control = run / 'controls' / stage_id
    control.mkdir(parents=True)
    lab.control_channels(control, os.getuid())
    state = lab.state_dir(run / 'children', stage_id, os.getuid())
    task = {'max_turns': 10, 'timeout_seconds': timeout_seconds, 'max_total_tokens': 1000, **(native_limits or {})}
    desc = controls.create(run, workspace, 'dev', 'agent', task, control, state, stage_id, 'fixture-' + stage_id,
                           top / 'admission.lock')
    parent_state = controls.transition(run, desc, 'running')
    controls.atomic(control / 'stage.json', {**desc, 'stage_revision': parent_state['revision']})
    controls.start_budget(run, desc, time.monotonic(), native_control=native_control)
    return run, desc


def queue_extension(run, desc, limits):
    """An extend-budget request as the CLI records it: requested event, then the file."""
    state = controls.resolve(run, desc['stage_id'])[1]
    request = controls.command_record(desc, state, 'extend_budget', {'expected_budget_revision': 0, 'limits': limits})
    controls.audit(run, request, 'requested')
    folder = controls.budget_path(run, desc).parent / 'budget-requests'
    folder.mkdir(exist_ok=True)
    controls.atomic(folder / (request['id'] + '.json'), request)
    return request, controls.budget_path(run, desc).parent / 'budget-updates' / (request['id'] + '.json')


def events(run, request, status):
    return [e for e in controls.history(run) if e['id'] == request['id'] and e['status'] == status]


class FakeNativeControl:
    """A live native helper control whose extension always succeeds."""
    def __init__(self, during_extend=None):
        self.during_extend = during_extend
        self.extended = []

    def status(self, force=False):
        return {'phase': 'active', 'extensions': len(self.extended)}

    def extend(self, command_id, max_tool_calls, remaining_seconds):
        if self.during_extend:
            self.during_extend()
        self.extended.append(command_id)
        return {'phase': 'active', 'max_tool_calls': max_tool_calls}


class HeldHistory:
    """Another open file holding the intervention history lock, as a stopped helper would."""
    def __init__(self, test, run):
        import fcntl
        self.fd = os.open(run / 'interventions.jsonl', os.O_RDWR | os.O_CREAT, 0o600)
        test.addCleanup(self.release)
        fcntl.flock(self.fd, fcntl.LOCK_EX)

    def release(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class SupervisorProcess:
    """A supervisor in its own process group, like a foreground terminal job."""
    def __init__(self, test, top, docker, **environment):
        self.name = 'pi-lab-' + uuid.uuid4().hex[:12]
        self.logs = top / 'logs'
        script = top / 'supervisor.py'
        script.write_text(SUPERVISOR.format(scripts=str(SCRIPTS)))
        self.process = subprocess.Popen([sys.executable, '-B', str(script), str(self.logs), self.name],
                                        env=docker.environment(**environment), start_new_session=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        test.addCleanup(self.close)
        wait_for(lambda: 'run ' + self.name in docker.calls() or self.process.poll() is not None,
                 message='the fake container to start')
        if self.process.poll() is not None:
            test.fail(self.process.stderr.read().decode(errors='replace'))

    def finish(self, timeout=60):
        self.process.wait(timeout=timeout)
        return self.process.returncode

    def record(self):
        return json.loads((self.logs / 'process.json').read_text())

    def close(self):
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait()
        self.process.stdout.close()
        self.process.stderr.close()


class InterruptPathTests(unittest.TestCase):
    def test_sighup_removes_container_and_writes_process_record(self):
        with tempfile.TemporaryDirectory() as td:
            top = Path(td)
            docker = FakeDocker(top)
            supervisor = SupervisorProcess(self, top, docker)
            os.kill(supervisor.process.pid, signal.SIGHUP)
            self.assertEqual(supervisor.finish(), 130)
            self.assertIn('rm-done ' + supervisor.name, docker.calls())
            self.assertFalse((docker.state / (supervisor.name + '.pid')).exists())
            record = supervisor.record()
            self.assertTrue(record['cancelled'])
            self.assertTrue(record['cleanup_confirmed'])
            self.assertEqual(record['termination_reason'], 'cancelled')
            self.assertEqual(record['exit_code'], 130)

    def test_second_sigint_does_not_stop_container_removal(self):
        with tempfile.TemporaryDirectory() as td:
            top = Path(td)
            docker = FakeDocker(top)
            supervisor = SupervisorProcess(self, top, docker, FAKE_RM_SECONDS='1.5')
            # A terminal Ctrl-C reaches the whole foreground process group,
            # including the removal command once it runs.
            os.killpg(supervisor.process.pid, signal.SIGINT)
            wait_for(lambda: 'rm-start ' + supervisor.name in docker.calls(), message='the removal to start')
            os.killpg(supervisor.process.pid, signal.SIGINT)
            self.assertEqual(supervisor.finish(), 130)
            self.assertIn('rm-done ' + supervisor.name, docker.calls())
            self.assertFalse((docker.state / (supervisor.name + '.pid')).exists())
            record = supervisor.record()
            self.assertTrue(record['cleanup_confirmed'])
            self.assertEqual(record['termination_reason'], 'cancelled')

    def test_deferred_interrupt_is_delivered_after_the_section(self):
        previous = signal.signal(signal.SIGINT, signal.default_int_handler)
        self.addCleanup(signal.signal, signal.SIGINT, previous)
        finished = []
        with self.assertRaises(KeyboardInterrupt):
            with resources.deferred_interrupts():
                os.kill(os.getpid(), signal.SIGINT)
                time.sleep(0.05)
                finished.append(True)
        self.assertEqual(finished, [True])
        self.assertNotIn(signal.SIGINT, signal.pthread_sigmask(signal.SIG_BLOCK, set()))


class IgnoredSigintEntryPointTests(unittest.TestCase):
    def interrupt_until_exit(self, process, timeout=60):
        # The entry point installs its handler only after its imports, so
        # repeat SIGINT until it exits; an ignored SIGINT never ends it.
        deadline = time.monotonic() + timeout
        while process.poll() is None and time.monotonic() < deadline:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=0.2)
            except subprocess.TimeoutExpired:
                pass
        if process.poll() is None:
            process.kill()
            process.wait()
            self.fail('Entry point ignored SIGINT')
        return process.returncode

    def test_launcher_really_ignores_sigint_before_exec(self):
        probe = 'import signal, sys; sys.exit(0 if signal.getsignal(signal.SIGINT) is signal.SIG_IGN else 1)'
        self.assertEqual(subprocess.run([sys.executable, '-c', probe], preexec_fn=ignore_sigint).returncode, 0)

    def test_pi_lab_exits_130_on_sigint_inherited_as_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            plan = Path(td) / 'plan.json'
            os.mkfifo(plan)  # Reading it blocks until interrupted.
            process = subprocess.Popen([sys.executable, '-B', str(SCRIPTS / 'pi_lab.py'),
                                        'validate-plan', '--plan', str(plan)], preexec_fn=ignore_sigint,
                                       env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'},
                                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                self.assertEqual(self.interrupt_until_exit(process), 130)
                self.assertIn('INTERRUPTED', process.stderr.read().decode(errors='replace'))
            finally:
                process.stderr.close()

    def test_parallel_worker_exits_130_on_sigint_inherited_as_ignored(self):
        parent, child = socket.socketpair()
        with tempfile.TemporaryFile() as lease, parent:
            try:
                process = subprocess.Popen([sys.executable, '-B', str(SCRIPTS / 'parallel_worker.py'),
                                            str(child.fileno()), str(lease.fileno())],
                                           pass_fds=(child.fileno(), lease.fileno()), preexec_fn=ignore_sigint,
                                           env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'},
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            finally:
                child.close()
            # The worker waits for its private bootstrap, which never arrives.
            self.assertEqual(self.interrupt_until_exit(process), 130)

    def test_campaign_tools_install_handlers_and_exit_130(self):
        for path in (SCRIPTS / 'pi_lab.py', SCRIPTS / 'parallel_worker.py',
                     *(ROOT / 'tools' / 'qualification' / (name + '.py') for name in ('pi_release', 'parallel', 'indexed'))):
            with self.subTest(entry_point=path.name):
                tree = ast.parse(path.read_text())
                block = next(node for node in tree.body if isinstance(node, ast.If)
                             and ast.unparse(node.test) == "__name__ == '__main__'")
                statements = [ast.unparse(node) for node in block.body]
                install = statements.index('resources.install_interrupt_handlers()')
                self.assertLess(install, next(i for i, node in enumerate(block.body) if isinstance(node, ast.Try)))
                handlers = [handler for node in ast.walk(block) if isinstance(node, ast.Try) for handler in node.handlers
                            if handler.type is not None and ast.unparse(handler.type) == 'KeyboardInterrupt']
                self.assertEqual(len(handlers), 1)
                self.assertIn('sys.exit(130)', ast.unparse(handlers[0]))

    def test_installed_handlers_route_hangup_and_quit_to_interrupt(self):
        saved = {kind: signal.getsignal(kind) for kind in resources.INTERRUPT_SIGNALS}
        for kind, handler in saved.items():
            self.addCleanup(signal.signal, kind, handler)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        resources.install_interrupt_handlers()
        self.assertIs(signal.getsignal(signal.SIGINT), signal.default_int_handler)
        for kind in (signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
            with self.subTest(signal=kind.name), self.assertRaises(KeyboardInterrupt):
                os.kill(os.getpid(), kind)
                time.sleep(0.5)


class DeadlineAndControlTests(unittest.TestCase):
    def test_stopped_lock_holder_cannot_delay_host_deadline(self):
        with tempfile.TemporaryDirectory() as td:
            top = Path(td)
            docker = FakeDocker(top)
            run, desc = prepare_stage(top, timeout_seconds=4)
            script = top / 'holder.py'
            script.write_text(STOPPED_HOLDER.format(scripts=str(SCRIPTS)))
            holder = subprocess.Popen([sys.executable, '-B', str(script), str(run), desc['stage_id']],
                                      stdout=subprocess.PIPE, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
            def release():
                if holder.poll() is None:
                    holder.send_signal(signal.SIGCONT)
                    try:
                        holder.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        holder.kill(); holder.wait()
                holder.stdout.close()
            self.addCleanup(release)
            self.assertEqual(holder.stdout.readline().strip(), b'locked')
            name = 'pi-lab-' + uuid.uuid4().hex[:12]
            with mock.patch.dict(os.environ, {'PATH': docker.environment()['PATH']}):
                result = lab.stream_run(['docker', 'run', '--name', name, 'fixture'], top / 'logs', 5, name,
                                        stage=(run, desc), resume_budget=True)
            self.assertIsNone(holder.poll(), 'the holder must still hold the lock')
            self.assertTrue(result['timed_out'])
            self.assertEqual(result['exit_code'], 124)
            self.assertEqual(result['termination_reason'], 'timeout')
            self.assertTrue(result['cleanup_confirmed'])
            self.assertEqual(result['control_warnings'], ['control_lock_busy'])
            # Deadline 4 s after the budget started, at most one bounded lock
            # wait (2 s) past it in the loop and one at closing, then removal.
            self.assertLess(result['elapsed_seconds'], 14)
            self.assertIn('rm-done ' + name, docker.calls())
            self.assertEqual(json.loads((top / 'logs' / 'process.json').read_text())['control_warnings'],
                             ['control_lock_busy'])
            self.assertEqual(controls.read(controls.budget_path(run, desc))['phase'], 'stopped')

    def test_run_stage_finishes_with_stopped_stage_lock_holder(self):
        import threading
        import outcomes
        with tempfile.TemporaryDirectory() as td:
            top = Path(td)
            docker = FakeDocker(top)
            run = top / 'run'
            run.mkdir()
            workspace = top / 'project'
            workspace.mkdir()
            marker = top / 'holder-locked'
            script = top / 'holder.py'
            script.write_text(RUNNING_STAGE_HOLDER.format(scripts=str(SCRIPTS)))
            holder = subprocess.Popen([sys.executable, '-B', str(script), str(run), str(marker)],
                                      env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
            def release():
                if holder.poll() is None:
                    holder.send_signal(signal.SIGCONT)
                    try:
                        holder.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        holder.kill(); holder.wait()
            self.addCleanup(release)
            outcome = {}
            def stage():
                try:
                    outcome['result'] = lab.run_stage(stage_args(lock_file=str(top / 'lease')), 'fixture', run,
                                                      workspace, 'check-one', ['check'], timeout=60)
                except BaseException as exc:  # Reported by the test thread below.
                    outcome['error'] = exc
            # The container exits only once the helper holds the stage lock, so
            # the helper is stopped holding it when termination is observed.
            with mock.patch.dict(os.environ, {'PATH': docker.environment()['PATH'], 'FAKE_RUN_UNTIL': str(marker)}):
                started = time.monotonic()
                thread = threading.Thread(target=stage, daemon=True)
                thread.start()
                thread.join(timeout=60)
                elapsed = time.monotonic() - started
            if thread.is_alive():
                release()
                thread.join(timeout=30)
                self.fail('run_stage stayed blocked on the stopped holder')
            if 'error' in outcome:
                raise outcome['error']
            result = outcome['result']
            stage_id = marker.read_text()
            # The holder is still stopped and still holds the lock.
            pid, status = os.waitpid(holder.pid, os.WNOHANG | os.WUNTRACED)
            self.assertEqual(pid, holder.pid)
            self.assertTrue(os.WIFSTOPPED(status))
            # One bounded wait at the first closing transition, then no more.
            self.assertLess(elapsed, controls.LOCK_WAIT_SECONDS + 12)
            # Process and cleanup evidence are kept as the supervisor wrote them.
            self.assertTrue(result['cleanup_confirmed'])
            self.assertEqual(result['termination_reason'], 'completed')
            self.assertIn('rm-done ' + next(line.split()[1] for line in docker.calls() if line.startswith('run ')),
                          docker.calls())
            # The blocked lifecycle is reported with existing receipt fields only,
            # never a fabricated finalization: the existing recovery_error fault,
            # the control_lock_busy warning and a nonzero exit.
            self.assertEqual(result['recovery_error'], 'LockBusy')
            self.assertEqual(result['control_warnings'], ['control_lock_busy'])
            self.assertEqual(result['exit_code'], 2)
            self.assertNotIn('lifecycle_error', result)
            # The pre-existing outcome classification is unchanged.
            self.assertEqual(outcomes.SUPERVISOR_FAULTS, ('native_tool_budget_error', 'recovery_error',
                                                          'observation_error', 'budget_error', 'capture_errors'))
            record = json.loads((run / 'check-one' / 'process.json').read_text())
            for key in ('recovery_error', 'cleanup_confirmed', 'termination_reason', 'exit_code', 'control_warnings'):
                self.assertEqual(record[key], result[key])
            # The stage state is authoritative: last committed status, not finalized.
            state = controls.read(run / 'stages' / stage_id / 'state.json')
            self.assertEqual(state['status'], 'running')
            self.assertFalse(state['cleanup_confirmed'])
            # Recoverable: once the holder goes, the stage takes its lifecycle again.
            release()
            desc = controls.resolve(run, stage_id)[0]
            with controls.bounded_locks():
                self.assertEqual(controls.transition(run, desc, 'stopping')['status'], 'stopping')

    def test_lifecycle_record_keeps_an_already_recorded_fault(self):
        lifecycle = lab.StageLifecycle(Path('/nonexistent'), {'stage_id': 'unused'})
        lifecycle.blocked = 'stopping'
        result = {'exit_code': 2, 'observation_error': True}
        lifecycle.record(result)
        self.assertNotIn('recovery_error', result)
        self.assertEqual(result['control_warnings'], ['control_lock_busy'])
        result = {'exit_code': 0, 'recovery_error': 'OSError', 'control_warnings': ['control_lock_busy']}
        lifecycle.record(result)
        self.assertEqual(result, {'exit_code': 2, 'recovery_error': 'OSError', 'control_warnings': ['control_lock_busy']})

    def test_busy_stage_lock_launches_no_follow_on_segment(self):
        import fcntl
        import types
        import segments
        with tempfile.TemporaryDirectory() as td:
            top = Path(td)
            run, desc = prepare_stage(top, timeout_seconds=60)
            launches = []

            def stream_run(argv, logdir, *args, **kwargs):
                # The first segment ends while a stopped helper holds the stage lock.
                launches.append(logdir)
                fd = os.open(run / 'stages' / desc['stage_id'] / 'lock', os.O_RDWR | os.O_CREAT, 0o600)
                self.addCleanup(os.close, fd)
                fcntl.flock(fd, fcntl.LOCK_EX)
                return {'exit_code': 0, 'cleanup_confirmed': True, 'termination_reason': 'completed'}

            def save(path, data):
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                controls.atomic(Path(path), data)

            fake = types.SimpleNamespace(
                state_dir=lab.state_dir, docker_args=lambda *a, **k: ['docker', 'run', 'fixture', 'pi'],
                stream_run=stream_run, save=save, note_control_lock_busy=lab.note_control_lock_busy,
                analyze=lambda *a, **k: {'agent_invocation_verified': True, 'completion_verified': False,
                                         'events': {'turn_start': 1}, 'provider_reported_total_tokens': 5,
                                         'errors': []})
            directive = {'id': str(uuid.uuid4()), 'intervention_id': str(uuid.uuid4()), 'message': 'continue',
                         'created_at': controls.now()}
            args = stage_args(event_contract=None)
            task = {'tools': ['read'], 'require_tools': [], 'cwd': '.'}
            with mock.patch.object(segments.release_contracts, 'identity', return_value={'id': 'fixture'}), \
                 mock.patch.object(segments.release_contracts, 'validate_binding'), \
                 mock.patch.object(segments.provenance, 'collect_emitted', return_value={'status': 'fixture'}), \
                 mock.patch.object(segments, 'pending', return_value=[directive]):
                started = time.monotonic()
                result = segments.execute(fake, args, 'fixture', run, top / 'project', 'agent', task,
                                          {'model': 'fixture'}, '', desc, 'rw', 'none', 60, [])
                elapsed = time.monotonic() - started
            # One participant only; the follow-on launch gave up within its bound.
            self.assertEqual(len(launches), 1)
            self.assertLess(elapsed, 2 * controls.LOCK_WAIT_SECONDS + 3)
            # The existing recoverable failure path, with the first segment's evidence.
            self.assertEqual(result['recovery_error'], 'LockBusy')
            self.assertEqual(result['control_warnings'], ['control_lock_busy'])
            self.assertTrue(result['cleanup_confirmed'])
            self.assertEqual(len(result['segments']), 1)
            self.assertNotIn('control_warnings', result['segments'][0]['process'])
            self.assertEqual(json.loads((run / 'agent' / 'process.json').read_text())['recovery_error'], 'LockBusy')
            # The stage still names the first segment; no second one was activated.
            state = controls.read(run / 'stages' / desc['stage_id'] / 'state.json')
            self.assertEqual(state['status'], 'running')
            self.assertEqual(Path(state['logs']), launches[0])

    def test_malformed_budget_request_is_rejected_and_stage_continues(self):
        with tempfile.TemporaryDirectory() as td:
            top = Path(td)
            run, desc = prepare_stage(top, timeout_seconds=30)
            requests = controls.budget_path(run, desc).parent / 'budget-requests'
            requests.mkdir()
            (requests / 'broken.json').write_text('{not json')
            (requests / 'listed.json').write_text('[]')
            state = controls.resolve(run, desc['stage_id'])[1]
            valid = controls.command_record(desc, state, 'extend_budget', {
                'expected_budget_revision': 0,
                'limits': {'max_turns': 10, 'timeout_seconds': 60, 'max_total_tokens': 1000}})
            controls.audit(run, valid, 'requested')
            controls.atomic(requests / (valid['id'] + '.json'), valid)

            budget = controls.process_budget_requests(run, desc)

            self.assertEqual(budget['revision'], 1)
            self.assertEqual(budget['effective_limits']['timeout_seconds'], 60)
            responses = requests.parent / 'budget-updates'
            self.assertEqual(controls.read(responses / (valid['id'] + '.json'))['status'], 'applied')
            for name, error in (('broken', 'JSONDecodeError'), ('listed', 'ControlError')):
                with self.subTest(request=name):
                    self.assertFalse((requests / (name + '.json')).exists())
                    self.assertTrue((requests / 'rejected' / (name + '.json')).exists())
                    reason = controls.read(requests / 'rejected' / (name + '.reason.json'))
                    self.assertEqual(reason['status'], 'rejected')
                    self.assertEqual(reason['reason'], 'Unreadable budget request: ' + error)
                    self.assertEqual(controls.read(responses / (name + '.json'))['status'], 'rejected')

            # A supervised stage keeps running past a malformed request.
            (requests / 'late.json').write_text('\x00')
            result = lab.stream_run([sys.executable, '-c', 'import time; time.sleep(0.6)'], top / 'logs', 60, 'check',
                                    stage=(run, desc), resume_budget=True)
            self.assertEqual(result['exit_code'], 0)
            self.assertEqual(result['termination_reason'], 'completed')
            self.assertTrue((requests / 'rejected' / 'late.json').exists())

    def test_worker_kills_check_process_group_at_its_timeout(self):
        sys.path.insert(0, str(RUNTIME))
        import worker
        with tempfile.TemporaryDirectory() as td:
            pidfile = Path(td) / 'grandchild.pid'
            spawn = ('import subprocess, sys, time; '
                     "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
                     'open(sys.argv[1], "w").write(str(child.pid)); time.sleep(60)')
            task = {'argv': [sys.executable, '-c', spawn, str(pidfile)], 'timeout_seconds': 1}
            stderr = io.StringIO()
            started = time.monotonic()
            with contextlib.redirect_stderr(stderr):
                code = worker.check(task, workspace=td)
            self.assertEqual(code, 124)
            self.assertLess(time.monotonic() - started, 10)
            line = next(text for text in stderr.getvalue().splitlines() if text.startswith('PI_LAB_LIMIT: '))
            self.assertEqual(json.loads(line.split(': ', 1)[1]),
                             {'check_timeout': True, 'timeout_seconds': 1, 'action': 'process_group_killed'})
            grandchild = int(pidfile.read_text())
            def gone():
                try:
                    os.kill(grandchild, 0)
                except ProcessLookupError:
                    return True
                except PermissionError:
                    return False
                # A killed orphan can stay a zombie under a PID 1 that never reaps.
                stat_path = Path('/proc') / str(grandchild) / 'stat'
                try:
                    return stat_path.read_text().rsplit(')', 1)[1].split()[0] == 'Z'
                except (OSError, IndexError):
                    return False
            wait_for(gone, timeout=10, message='the check process group to be killed')

    def test_worker_check_returns_the_command_status(self):
        sys.path.insert(0, str(RUNTIME))
        import worker
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(worker.check({'argv': [sys.executable, '-c', 'raise SystemExit(3)'], 'timeout_seconds': 30},
                                          workspace=td), 3)
            with self.assertRaises(ValueError):
                worker.check({'argv': ['true'], 'timeout_seconds': 0}, workspace=td)


class BudgetHistoryTests(unittest.TestCase):
    LIMITS = {'max_turns': 10, 'timeout_seconds': 60, 'max_total_tokens': 1000}

    def test_busy_history_delays_extension_whole_and_retry_applies_it_once(self):
        with tempfile.TemporaryDirectory() as td:
            top = Path(td)
            run, desc = prepare_stage(top, timeout_seconds=30)
            request, response = queue_extension(run, desc, self.LIMITS)
            held = HeldHistory(self, run)
            with self.assertRaises(controls.LockBusy), controls.bounded_locks():
                controls.process_budget_requests(run, desc)
            held.release()
            # Nothing of the commit exists: no response, no budget change, no event.
            self.assertFalse(response.exists())
            self.assertEqual(controls.read(controls.budget_path(run, desc))['revision'], 0)
            self.assertEqual(events(run, request, 'accepted'), [])
            self.assertEqual(controls.assistance(run)['status'], 'autonomous')

            # The applied response is published only while the history is held,
            # so no other process can start holding it before the applied event.
            probes = []
            publish = controls.publish_budget
            def observed_publish(*arguments, **keywords):
                probes.append(history_free(run, 'shared'))
                return publish(*arguments, **keywords)
            with mock.patch.object(controls, 'publish_budget', observed_publish), controls.bounded_locks():
                budget = controls.process_budget_requests(run, desc)
            self.assertEqual(probes, [False])
            self.assertTrue(history_free(run, 'exclusive'))
            self.assertEqual(budget['revision'], 1)
            self.assertEqual(controls.read(response)['status'], 'applied')
            self.assertEqual(sorted(controls.read(response)), sorted(
                ['schema', 'id', 'stage_id', 'status', 'reason', 'before', 'updated_at', 'budget_revision', 'after',
                 'host_applied', 'worker_applied']))
            # A later pass changes nothing: each effect happened exactly once.
            with controls.bounded_locks():
                controls.process_budget_requests(run, desc)
            self.assertEqual(len(events(run, request, 'accepted')), 1)
            self.assertEqual(len(events(run, request, 'applied')), 1)
            self.assertEqual(events(run, request, 'applied')[0]['budget_revision'], 1)
            self.assertEqual(controls.read(controls.budget_path(run, desc))['revision'], 1)
            self.assertEqual(controls.assistance(run), {'status': 'assisted', 'intervention_ids': [request['intervention_id']]})

    def test_native_extension_runs_unlocked_and_busy_history_fails_closed_once(self):
        native_limits = {'max_tool_calls': 10, 'reporting_reserve_calls': 2, 'reporting_reserve_seconds': 10}
        with tempfile.TemporaryDirectory() as td:
            top = Path(td)
            seen = []
            holders = []
            def during_extend():
                # The parallel engine answers by reading the history itself.
                seen.append(history_free(run, 'shared'))
                holders.append(HeldHistory(self, run))
            native = FakeNativeControl(during_extend)
            run, desc = prepare_stage(top, timeout_seconds=30, native_limits=native_limits, native_control=native)
            request, response = queue_extension(run, desc, {**self.LIMITS, **native_limits, 'max_tool_calls': 20})
            with self.assertRaises(controls.ControlError) as caught, controls.bounded_locks():
                controls.process_budget_requests(run, desc, native_control=native)
            self.assertNotIsInstance(caught.exception, controls.LockBusy)
            self.assertEqual(seen, [True])
            holders[0].release()
            record = controls.read(response)
            self.assertEqual((record['status'], record['reason'], record['helper_applied']),
                             ('rejected', 'native_budget_update_unconfirmed', 'unknown'))
            budget = controls.read(controls.budget_path(run, desc))
            self.assertEqual((budget['revision'], budget['native_budget_error']), (0, 'accounting_unavailable'))
            # No retry grows helper authority again or repeats an event.
            with self.assertRaises(controls.ControlError), controls.bounded_locks():
                controls.process_budget_requests(run, desc, native_control=native)
            self.assertEqual(native.extended, [request['id']])
            self.assertEqual(len(events(run, request, 'accepted')), 1)
            self.assertEqual(events(run, request, 'applied'), [])


class BoundedLockTests(unittest.TestCase):
    def test_bounded_lock_raises_lock_busy_after_two_seconds(self):
        with tempfile.TemporaryDirectory() as td:
            run = Path(td)
            holder = os.open(run / 'control.lock', os.O_RDWR | os.O_CREAT, 0o600)
            self.addCleanup(os.close, holder)
            import fcntl
            fcntl.flock(holder, fcntl.LOCK_EX)
            started = time.monotonic()
            with self.assertRaises(controls.LockBusy), controls.bounded_locks():
                with controls.lock(run):
                    pass
            self.assertGreaterEqual(time.monotonic() - started, controls.LOCK_WAIT_SECONDS)
            self.assertLess(time.monotonic() - started, controls.LOCK_WAIT_SECONDS + 1)
            fcntl.flock(holder, fcntl.LOCK_UN)
            with controls.bounded_locks():
                with controls.lock(run):
                    pass


if __name__ == '__main__':
    unittest.main()
