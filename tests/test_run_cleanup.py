"""Run labels, leftovers and per-run cleanup against a fake docker command.

Real temporary leases, registries and run directories. The only `docker` on PATH
is a recording fixture; no daemon, image or model endpoint is contacted.
"""
import contextlib
import fcntl
import io
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1] / 'skill'
sys.path.insert(0, str(ROOT / 'scripts'))
import pi_lab as lab
import application_owner_cleanup
import outcomes
import ownership_registry
import resources
import run_cleanup
import stage_control as controls
import test_results as suite

MANAGED = 'org.pi-agent-test-env.managed'
RUN = 'org.pi-agent-test-env.run'
IMAGE = 'sha256:' + 'a' * 64

FAKE_DOCKER = r'''#!%(python)s
import fcntl, json, os, re, sys
argv = sys.argv[1:]
code, out, err = 0, '', ''
with open(os.environ['FAKE_DOCKER_STATE'], 'r+') as handle:
    fcntl.flock(handle, fcntl.LOCK_EX)
    state = json.load(handle)
    state['log'].append(argv)
    def matches(row):
        for value in [argv[i + 1] for i, item in enumerate(argv[:-1]) if item == '--filter']:
            key, sep, wanted = value.split('=', 1)[1].partition('=')
            if not value.startswith('label=') or key not in row['labels'] or (sep and row['labels'][key] != wanted):
                return False
        return True
    def render(row, name):
        text = argv[argv.index('--format') + 1]
        for key, field in (('{{.ID}}', 'id'), (name, 'name'), ('{{.State}}', 'state'), ('{{.CreatedAt}}', 'created')):
            text = text.replace(key, row.get(field) or '')
        return re.sub(r'\{\{\.Label "([^"]+)"\}\}', lambda m: row['labels'].get(m.group(1), ''), text)
    def listing(kind, name):
        rows = [row for row in state[kind] if matches(row)]
        return ''.join((render(row, name) if '--format' in argv else row['id']) + '\n' for row in rows)
    def find(kind):
        return next((row for row in state[kind] if argv[-1] in (row['id'], row['name'])), None)
    if state.get('down'):
        code, err = 1, 'Cannot connect to the Docker daemon. Is the docker daemon running?\n'
    elif argv[:1] == ['ps']:
        out = listing('containers', '{{.Names}}')
    elif argv[:2] == ['network', 'ls']:
        out = listing('networks', '{{.Name}}')
    elif argv[:1] == ['rm'] or argv[:2] == ['network', 'rm']:
        kind = 'networks' if argv[0] == 'network' else 'containers'
        row = find(kind)
        if row is None:
            code, err = 1, 'Error response from daemon: No such %%s: %%s\n' %% (kind[:-1], argv[-1])
        elif row['name'] in state.get('stuck', []):
            code, err = 1, 'Error response from daemon: removal refused by fixture\n'
        else:
            state[kind].remove(row); out = argv[-1] + '\n'
    elif argv[:2] == ['container', 'inspect']:
        row = find('containers')
        if row is None:
            code, out, err = 1, '[]\n', 'Error response from daemon: No such container: ' + argv[-1] + '\n'
        else:
            out = json.dumps([{'Id': row['id'], 'Image': row.get('image'), 'Config': {'Labels': row['labels']}, 'Mounts': []}])
    elif argv[:1] == ['info']:
        out = 'fixture-daemon\n'
    else:
        code, err = 64, 'unexpected fixture docker command\n'
    handle.seek(0); handle.truncate(); json.dump(state, handle)
sys.stdout.write(out); sys.stderr.write(err); sys.exit(code)
'''


def resource(name, run_id=None, managed=True, state='running', **extra):
    labels = dict(extra.pop('labels', {}))
    if managed:
        labels[MANAGED] = '1'
    if run_id is not None:
        labels[RUN] = run_id
    return {'id': uuid.uuid4().hex * 2, 'name': name, 'state': state,
            'created': '2020-01-02 03:04:05 +0000 UTC', 'labels': labels, **extra}


class FakeDockerCase(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.top = Path(temp.name).resolve()
        self.results = self.top / 'results'; self.results.mkdir()
        self.lease = self.top / 'lease'
        self.state = self.top / 'docker-state.json'
        binary = self.top / 'bin' / 'docker'; binary.parent.mkdir()
        binary.write_text(FAKE_DOCKER % {'python': sys.executable}); binary.chmod(0o755)
        self.environment = {**os.environ, 'PATH': str(binary.parent) + os.pathsep + '/usr/bin:/bin',
                            'FAKE_DOCKER_STATE': str(self.state), 'PYTHONDONTWRITEBYTECODE': '1'}
        self.environment.pop('PI_LAB_LOCK_FILE', None)
        patched = mock.patch.dict(os.environ, self.environment, clear=True); patched.start(); self.addCleanup(patched.stop)
        self.docker(containers=[], networks=[])

    def docker(self, **values):
        current = json.loads(self.state.read_text()) if self.state.exists() else {'log': []}
        self.state.write_text(json.dumps({**current, **values}))

    def observed(self):
        return json.loads(self.state.read_text())

    def names(self, kind='containers'):
        return sorted(row['name'] for row in self.observed()[kind])

    def effects(self):
        return [call for call in self.observed()['log'] if call[:1] == ['rm'] or call[:2] == ['network', 'rm']]

    def arguments(self):
        return argparse_for(self.top, self.results, self.lease)

    def attempt(self, seal=False):
        attempt = outcomes.Attempt(self.arguments())
        if seal:
            attempt.fail(lab.LabError('Synthetic prerequisite failure', 'docker-error')); attempt.finalize()
        return attempt

    def call(self, *argv, json_output=True):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = lab.main([*argv, '--results-dir', str(self.results), '--lock-file', str(self.lease),
                             *(['--json'] if json_output else [])])
        return code, (json.loads(stream.getvalue()) if json_output else stream.getvalue())

    def hold(self, lease):
        """An operation that holds a lease, as a supervisor does for its whole run."""
        fd = os.open(lease, os.O_RDWR | os.O_CREAT, 0o600); self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd

    def stage(self, attempt, lease):
        """A stage descriptor, which is where a run records the lease it was admitted under."""
        workspace = attempt.root / 'workspace'; workspace.mkdir(exist_ok=True)
        stage_id = str(uuid.uuid4()); control = attempt.root / 'controls' / stage_id; control.mkdir(parents=True)
        return controls.create(attempt.root, workspace, 'setup-1-wait', 'check', None, control,
                               attempt.root / 'children' / stage_id, stage_id, 'pi-lab-fixture', lease)


def argparse_for(top, results, lease):
    project = top / 'project'; project.mkdir(exist_ok=True)
    return lab.parser().parse_args(['run', '--project', str(project), '--plan', str(top / 'plan.json'),
                                    '--endpoint', str(top / 'endpoint.json'), '--results-dir', str(results),
                                    '--lock-file', str(lease), '--platform', 'linux/arm64', '--memory', '1g', '--cpus', '1'])


class RunLabelTests(unittest.TestCase):
    def arguments(self):
        return lab.parser().parse_args(['run', '--platform', 'linux/arm64', '--memory', '1g', '--cpus', '1'])

    def build(self, args):
        return lab.docker_args(args, IMAGE, Path('/x/project'), Path('/x/control'), Path('/x/state'), 'pi-lab-fixture', 'none')

    def test_stage_container_arguments_carry_the_run_id_beside_the_managed_labels(self):
        args = self.arguments(); run_id = str(uuid.uuid4())
        args._attempt_identity = {'run_id': run_id, 'attempt_id': str(uuid.uuid4())}
        argv = self.build(args)
        self.assertEqual([value for value in argv if value.startswith('--label')],
                         ['--label=' + MANAGED + '=1', '--label=org.pi-agentic-development.managed=1',
                          '--label=' + RUN + '=' + run_id])
        self.assertLess(argv.index('--label=' + RUN + '=' + run_id), argv.index(IMAGE))

    def test_a_container_outside_a_run_is_labelled_none(self):
        self.assertIn('--label=' + RUN + '=none', self.build(self.arguments()))
        for value in (None, '', 7, 'with space', 'a=b', 'x' * 200):
            with self.subTest(value=value):
                self.assertEqual(ownership_registry.run_label(value), RUN + '=none')
        self.assertFalse(run_cleanup.valid_run_id('none'))

    def test_every_stage_container_of_a_suite_carries_its_run_id(self):
        launched = []
        def stage(argv, logdir, timeout, name, secret='', stage=None, **kw):
            launched.append(list(argv))
            logdir.mkdir(parents=True, exist_ok=True); (logdir / 'stdout.jsonl').write_text(''); (logdir / 'stderr.log').write_text('')
            return {'exit_code': 0, 'cleanup_confirmed': True}
        with tempfile.TemporaryDirectory() as td, contextlib.ExitStack() as stack:
            top = Path(td).resolve(); args = suite.fixture(top); suite.mocked_suite(stack, stage)
            stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            lab.run_suite(args)
            run_id = controls.read((top / 'results' / 'latest').resolve() / 'result.json')['run_id']
        containers = [argv for argv in launched if argv[:2] == ['docker', 'run']]
        self.assertGreaterEqual(len(containers), 4)  # boundary, preflight, agent, check
        for argv in containers:
            self.assertEqual([value for value in argv if value.startswith('--label=' + RUN + '=')],
                             ['--label=' + RUN + '=' + run_id])
        self.assertEqual({argv[argv.index('/opt/pi-lab/worker.py') + 1] for argv in containers},
                         {'boundary', 'preflight', 'agent', 'check'})

    def test_the_preflight_command_labels_its_stage_with_the_identity_it_records(self):
        captured = {}
        def stage(args, image, runroot, workspace, label, operation, **kw):
            captured['identity'] = controls.read(runroot / 'identity.json')
            captured['argv'] = lab.docker_args(args, image, workspace, runroot / 'c', runroot / 's', 'pi-lab-fixture', 'none')
            return {'exit_code': 0, 'cleanup_confirmed': True}
        with tempfile.TemporaryDirectory() as td, contextlib.ExitStack() as stack:
            args = lab.parser().parse_args(['preflight', '--results-dir', td, '--platform', 'linux/arm64', '--memory', '1g', '--cpus', '1'])
            for name, value in (('load_endpoint', {'api_key_env': 'PI_API_KEY'}), ('resolve_endpoint_path', Path(td)),
                                ('endpoint_secret', 'synthetic-key'), ('require_host', {}),
                                ('probe_image', {'id': IMAGE}), ('admit_image', {'release': '1.5.2'})):
                stack.enter_context(mock.patch.object(lab, name, return_value=value))
            stack.enter_context(mock.patch.object(lab.pi_contract, 'model_configuration'))
            stack.enter_context(mock.patch.object(lab, 'run_stage', side_effect=stage))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            self.assertEqual(lab.preflight_only(args), 0)
        self.assertTrue(run_cleanup.valid_run_id(captured['identity']['run_id']))
        self.assertIn('--label=' + RUN + '=' + captured['identity']['run_id'], captured['argv'])

    def test_a_private_trial_grant_admits_only_its_own_run_label(self):
        from parallel_allocator import Allocator
        from parallel_contract import ParallelError
        from parallel_dispatch import Peer
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve(); run = root / 'runs/run'; run.mkdir(parents=True); run_id = str(uuid.uuid4())
            pool = Allocator({'cpu_millis': 2500, 'memory_mib': 1024, 'pids_limit': 256})
            reservation = pool.request('trial', {'trial_id': 'trial', 'generation': 'private'},
                                       {'cpu_millis': 1000, 'memory_mib': 128, 'pids_limit': 64}, 10); pool.dispatch()
            peer = Peer({'network': 'pi-fixture', 'experiment': str(root), 'intent': {'run_id': run_id}},
                        ownership_registry.Registry(root / 'registry', mock.Mock()), pool, reservation,
                        {'execution': {'platform': 'linux/arm64', 'image': IMAGE}}, run)
            args = lab.parser().parse_args(['run', '--platform', 'linux/arm64', '--cpus', '1', '--memory', '128m', '--pids-limit', '64'])
            def build():
                return lab.docker_args(args, IMAGE, run / 'workspace', run / 'control', run / 'state', 'pi-lab-fixture',
                                       'pi-fixture', helpers=run / 'runtime')
            args._attempt_identity = {'run_id': run_id, 'attempt_id': str(uuid.uuid4())}
            peer.validate_launch(build())
            for foreign in ({'run_id': str(uuid.uuid4())}, None):
                args._attempt_identity = foreign
                with self.subTest(identity=foreign), self.assertRaises(ParallelError):
                    peer.validate_launch(build())

    def test_helper_launch_validation_accepts_the_run_label_and_only_for_its_own_run(self):
        run_id = str(uuid.uuid4())
        record = {'container': 'pi-application-fixture', 'image': IMAGE, 'launch_id': str(uuid.uuid4()),
                  'registry': 'f' * 64, 'mounts': [], 'binding': {'run_id': run_id}}
        owned = ['--label', ownership_registry.LABEL + '=' + record['launch_id'],
                 '--label', ownership_registry.REGISTRY_LABEL + '=' + record['registry']]
        def argv(*labels):
            extra = [value for label in labels for value in ('--label', label)]
            return ['docker', 'run', '--name', record['container'], *owned, *extra, IMAGE, '/opt/pi-lab/worker.py']
        application_owner_cleanup.validate_launcher_arguments(argv(), record)  # launches before the label existed
        application_owner_cleanup.validate_launcher_arguments(argv(RUN + '=' + run_id), record)
        for labels in ((RUN + '=' + str(uuid.uuid4()),), (RUN + '=none',), (RUN + '=' + run_id, RUN + '=' + run_id),
                       (RUN + '=bad value',), (MANAGED + '=1',)):
            with self.subTest(labels=labels), self.assertRaises(ownership_registry.RegistryError):
                application_owner_cleanup.validate_launcher_arguments(argv(*labels), record)

    def test_a_created_trial_network_carries_the_run_label(self):
        import test_inference_broker as broker
        case = broker.BrokerTests('test_secret_stays_in_helper_and_worker_receives_only_surrogate'); case.setUp()
        self.addCleanup(case.doCleanups)
        case.registry.network_intent = lambda name: {'launch_id': str(uuid.uuid4()), 'container': name}
        case.registry.remove_network = lambda record: None
        case.registry.registry_id = 'f' * 64
        run_id = str(uuid.uuid4())
        with mock.patch.object(broker.inference_broker, 'urlopen', case.health):
            with case.owner() as (inference, factory, cleanup):
                first = factory({'trial_id': 'fixture-trial', 'run_id': run_id})
                second = factory({'trial_id': 'fixture-trial'})
                cleanup(first); cleanup(second)
        created = {call[-1]: call for call in case.calls if call[:3] == ['docker', 'network', 'create']}
        def labels(call):
            return [call[i + 1] for i, value in enumerate(call[:-1]) if value == '--label']
        self.assertIn(RUN + '=' + run_id, labels(created[first])); self.assertIn(MANAGED + '=1', labels(created[first]))
        self.assertIn(RUN + '=none', labels(created[second]))
        self.assertEqual(len(labels(created[first])), 4)


class LeftoverTests(FakeDockerCase):
    def scene(self):
        """Two labelled containers of a sealed run, one of an active run, and decoys."""
        self.done = self.attempt(seal=True); self.live = self.attempt()
        self.other = self.top / 'other-lease'
        self.stage(self.live, self.other); self.hold(self.other)
        done, live = self.done.record['run_id'], self.live.record['run_id']
        self.docker(containers=[
            resource('pi-lab-done-one', done), resource('pi-lab-done-two', done, state='exited'),
            resource('pi-lab-live', live),
            resource('pi-lab-done-lookalike'),                      # managed, but no run label
            resource('pi-lab-probe', 'none'),                       # outside a run
            resource('pi-lab-done-unmanaged', done, managed=False),  # run label without the managed label
            resource('pi-lab-stranger', str(uuid.uuid4()))],         # a run this results directory does not know
            networks=[resource('pi-trial-done', done, state=None), resource('pi-trial-live', live, state=None)])
        return done, live

    def test_leftovers_lists_the_sealed_run_and_not_the_active_one_and_changes_nothing(self):
        done, live = self.scene(); before = {path: path.read_bytes() for path in self.results.rglob('*') if path.is_file()}
        code, report = self.call('leftovers')
        self.assertEqual(code, 0)
        listed = [row for row in report['leftovers'] if row['kind'] == 'container' and row['managed']]
        self.assertEqual(sorted(row['name'] for row in listed), ['pi-lab-done-one', 'pi-lab-done-two'])
        for row in listed:
            self.assertEqual((row['run_id'], row['run_state']), (done, 'sealed'))
            self.assertIn(row['state'], ('running', 'exited')); self.assertGreater(row['age_seconds'], 0)
        self.assertNotIn(live, json.dumps(report['leftovers']))
        self.assertEqual(report['active_resources'], 2)
        self.assertEqual({row['name']: row['reason'] for row in report['unclassified']},
                         {'pi-lab-probe': 'no_run', 'pi-lab-stranger': 'run_directory_not_found'})
        self.assertEqual(self.effects(), [])
        self.assertEqual(len(self.names()), 7); self.assertEqual(len(self.names('networks')), 2)
        self.assertEqual({path: path.read_bytes() for path in self.results.rglob('*') if path.is_file()}, before)
        self.assertFalse(self.lease.exists())

    def test_leftovers_for_one_run_and_text_view(self):
        done, live = self.scene()
        code, report = self.call('leftovers', '--run', done)
        self.assertEqual(sorted(row['name'] for row in report['leftovers']),
                         ['pi-lab-done-one', 'pi-lab-done-two', 'pi-lab-done-unmanaged', 'pi-trial-done'])
        self.assertEqual(report['unclassified'], [])
        self.assertEqual(self.call('leftovers', '--run', str(self.live.root))[1]['leftovers'], [])
        code, text = self.call('leftovers', '--run', done, json_output=False)
        self.assertIn('pi-lab-done-one', text); self.assertIn('sealed', text); self.assertIn('Nothing was changed.', text)

    def test_an_unsealed_run_is_a_leftover_only_once_its_lease_is_free(self):
        attempt = self.attempt(); run_id = attempt.record['run_id']
        self.docker(containers=[resource('pi-lab-abandoned', run_id)])
        fd = self.hold(self.lease)
        self.assertEqual(self.call('leftovers')[1]['leftovers'], [])
        fcntl.flock(fd, fcntl.LOCK_UN)
        row, = self.call('leftovers')[1]['leftovers']
        self.assertEqual((row['name'], row['run_state']), ('pi-lab-abandoned', 'supervisor_gone'))

    def test_cleanup_without_yes_removes_nothing_and_with_yes_exactly_the_labelled_two(self):
        done, live = self.scene(); self.docker(networks=[resource('pi-trial-live', live, state=None)])
        code, report = self.call('cleanup', '--run', done)
        self.assertEqual((code, report['status'], report['dry_run']), (0, 'DRY_RUN', True))
        self.assertEqual(sorted(row['name'] for row in report['would_remove']), ['pi-lab-done-one', 'pi-lab-done-two'])
        self.assertEqual(self.effects(), []); self.assertEqual(len(self.names()), 7)
        self.assertFalse((self.done.root / 'cleanup.json').exists()); self.assertFalse(self.lease.exists())
        sealed = (self.done.root / 'result.json').read_bytes()

        code, report = self.call('cleanup', '--run', done, '--yes')
        self.assertEqual((code, report['status'], report['cleanup_confirmed']), (0, 'CLEANED', True))
        self.assertEqual(sorted(row['name'] for row in report['removed']), ['pi-lab-done-one', 'pi-lab-done-two'])
        self.assertEqual(self.names(), ['pi-lab-done-lookalike', 'pi-lab-done-unmanaged', 'pi-lab-live',
                                        'pi-lab-probe', 'pi-lab-stranger'])
        self.assertEqual(self.names('networks'), ['pi-trial-live'])
        self.assertEqual([row['name'] for row in report['unmanaged']], ['pi-lab-done-unmanaged'])
        self.assertEqual(report['remaining'], {'containers': [], 'networks': []})
        self.assertEqual(controls.read(self.done.root / 'cleanup.json'), report)
        self.assertEqual(report['finalization'], {'action': 'already_sealed'})
        self.assertEqual((self.done.root / 'result.json').read_bytes(), sealed)
        # Removal is by the Docker ID of a row that carried both labels, never by a name or pattern.
        ids = {row['id'] for row in report['would_remove']}
        self.assertEqual({call[-1] for call in self.effects()}, ids)
        log = self.observed()['log']
        self.assertIn(['ps', '-aq', '--filter', 'label=' + MANAGED + '=1', '--filter', 'label=' + RUN + '=' + done], log)
        self.assertIn(['network', 'ls', '-q', '--filter', 'label=' + MANAGED + '=1', '--filter', 'label=' + RUN + '=' + done], log)

    def test_cleanup_removes_containers_before_networks(self):
        attempt = self.attempt(seal=True); run_id = attempt.record['run_id']
        self.docker(containers=[resource('pi-lab-one', run_id)], networks=[resource('pi-trial-one', run_id, state=None)])
        code, report = self.call('cleanup', '--run', str(attempt.root), '--yes')
        self.assertEqual(code, 0)
        self.assertEqual([call[0] for call in self.effects()], ['rm', 'network'])
        self.assertEqual([row['kind'] for row in report['removed']], ['container', 'network'])
        code, text = self.call('cleanup', '--run', run_id, '--yes', json_output=False)
        self.assertEqual(code, 0); self.assertIn('absence confirmed', text)

    def test_a_refused_removal_is_incomplete_and_does_not_seal_the_run(self):
        attempt = self.attempt(); run_id = attempt.record['run_id']
        self.docker(containers=[resource('pi-lab-stuck', run_id), resource('pi-lab-free', run_id)], stuck=['pi-lab-stuck'])
        code, report = self.call('cleanup', '--run', run_id, '--yes')
        self.assertEqual((code, report['status'], report['cleanup_confirmed']), (2, 'INCOMPLETE', False))
        self.assertEqual([row['name'] for row in report['failed']], ['pi-lab-stuck'])
        self.assertEqual(len(report['remaining']['containers']), 1)
        self.assertEqual(report['finalization'], {'action': 'not_attempted'})
        self.assertFalse((attempt.root / 'result.json').exists())
        self.assertEqual(controls.read(attempt.root / 'cleanup.json')['status'], 'INCOMPLETE')

    def test_cleanup_refuses_a_run_admitted_under_another_lease_and_unknown_runs(self):
        attempt = self.attempt(); run_id = attempt.record['run_id']
        self.stage(attempt, self.top / 'other-lease')
        self.docker(containers=[resource('pi-lab-elsewhere', run_id)])
        for arguments in (['--run', run_id, '--yes'], ['--run', run_id]):
            with self.assertRaises(run_cleanup.CleanupError) as caught:
                self.call('cleanup', *arguments)
            self.assertEqual(caught.exception.reason, 'cleanup-lease-mismatch')
        for value in ('none', str(uuid.uuid4()), 'not a run'):
            with self.subTest(run=value), self.assertRaises(run_cleanup.CleanupError) as caught:
                self.call('cleanup', '--run', value, '--yes')
            self.assertEqual(caught.exception.reason, 'run-not-found')
        self.assertEqual(self.effects(), []); self.assertEqual(self.names(), ['pi-lab-elsewhere'])
        self.assertFalse(self.lease.exists())

    def test_cleanup_lets_the_registry_reconcile_and_deletes_no_record(self):
        attempt = self.attempt(seal=True); run_id = attempt.record['run_id']
        argv = ['docker', 'run', '--name', 'pi-lab-owned', IMAGE, '/opt/pi-lab/worker.py', 'check']
        with self.assertRaises(lab.LabError):
            with resources.admission_lock(self.lease) as owner:
                record, labelled = owner.intent(argv, 'pi-lab-owned', runroot=attempt.root)
                raise lab.LabError('Synthetic supervisor death')
        labels = dict(value.split('=', 1) for i, value in enumerate(labelled) if labelled[i - 1] == '--label')
        self.docker(containers=[resource('pi-lab-owned', run_id, image=IMAGE, labels=labels),
                                resource('pi-lab-unregistered', run_id)])
        registry = ownership_registry.Registry(Path(str(self.lease) + '.registry'), create=False)
        self.assertEqual([row['status'] for row in registry.load()], ['intent'])
        code, report = self.call('cleanup', '--run', run_id, '--yes')
        self.assertEqual((code, report['registry_reconciled']), (0, True))
        self.assertEqual(self.names(), [])
        # The registry removed its own launch by name; the label pass removed only what was left.
        self.assertIn(['rm', '--force', 'pi-lab-owned'], self.observed()['log'])
        self.assertEqual([row['name'] for row in report['removed']], ['pi-lab-unregistered'])
        self.assertEqual([row['name'] for row in report['reconciled']], ['pi-lab-owned'])
        self.assertEqual({call[-1] for call in self.effects()} - {'pi-lab-owned'}, {report['removed'][0]['id']})
        after = registry.load()
        self.assertEqual([(row['launch_id'], row['status']) for row in after], [(record['launch_id'], 'released')])

    def test_an_unsafe_registry_blocks_cleanup_before_any_removal(self):
        attempt = self.attempt(seal=True); run_id = attempt.record['run_id']
        argv = ['docker', 'run', '--name', 'pi-lab-owned', IMAGE, '/opt/pi-lab/worker.py', 'check']
        with self.assertRaises(lab.LabError):
            with resources.admission_lock(self.lease) as owner:
                owner.intent(argv, 'pi-lab-owned', runroot=attempt.root)
                raise lab.LabError('Synthetic supervisor death')
        # Same name, foreign labels: the registry refuses, and cleanup does not go around it.
        self.docker(containers=[resource('pi-lab-owned', run_id, image=IMAGE)])
        with self.assertRaises(resources.AdmissionError) as caught:
            self.call('cleanup', '--run', run_id, '--yes')
        self.assertEqual(caught.exception.reason, 'host-registry-unsafe')
        self.assertEqual(self.effects(), []); self.assertEqual(self.names(), ['pi-lab-owned'])
        self.assertFalse((attempt.root / 'cleanup.json').exists())

    def test_docker_that_cannot_be_asked_is_a_named_blocker(self):
        attempt = self.attempt(seal=True); self.docker(down=True)
        for arguments in (['leftovers'], ['cleanup', '--run', attempt.record['run_id']]):
            with self.subTest(command=arguments[0]), self.assertRaises(run_cleanup.CleanupError) as caught:
                self.call(*arguments)
            self.assertEqual(caught.exception.reason, 'docker-daemon-unavailable')
        code, report = self.call('cleanup', '--run', attempt.record['run_id'], '--yes')
        self.assertEqual((code, report['status'], report['docker_error']), (2, 'INCOMPLETE', 'docker-daemon-unavailable'))


class BusyLeaseTests(FakeDockerCase):
    def test_cleanup_exits_2_with_host_admission_busy_while_a_helper_process_holds_the_lease(self):
        attempt = self.attempt(seal=True); run_id = attempt.record['run_id']
        self.docker(containers=[resource('pi-lab-left', run_id)])
        holder = "from resources import admission_lock;import sys\nwith admission_lock(sys.argv[1]):\n print('locked',flush=True)\n sys.stdin.read()\n"
        environment = {**self.environment, 'PYTHONPATH': str(ROOT / 'scripts')}
        with subprocess.Popen([sys.executable, '-c', holder, str(self.lease)], env=environment, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as owner:
            try:
                self.assertTrue(select.select([owner.stdout], [], [], 10)[0], 'helper never acquired the lease')
                self.assertEqual(owner.stdout.readline().strip(), 'locked')
                for extra in (['--yes'], []):
                    with self.subTest(arguments=extra):
                        done = subprocess.run([sys.executable, str(ROOT / 'scripts/pi_lab.py'), 'cleanup', '--run', run_id,
                                               '--results-dir', str(self.results), '--lock-file', str(self.lease), *extra],
                                              env=self.environment, capture_output=True, text=True, timeout=60)
                        self.assertEqual(done.returncode, 2, done.stderr)
                        lines = done.stderr.splitlines()
                        failure = json.loads(lines[0])
                        self.assertEqual(failure['infrastructure']['reason'], 'host-admission-busy')
                        self.assertEqual(failure['infrastructure']['holder']['pid'], owner.pid)
                        self.assertTrue(lines[1].startswith(f'Held by pid {owner.pid} '), lines)
                        self.assertEqual((failure['status'], failure['exit_code']), ('BLOCKED', 2))
                self.assertEqual(self.effects(), []); self.assertEqual(self.names(), ['pi-lab-left'])
                self.assertFalse((attempt.root / 'cleanup.json').exists())
            finally:
                owner.kill(); owner.wait(timeout=10)
        done = subprocess.run([sys.executable, str(ROOT / 'scripts/pi_lab.py'), 'cleanup', '--run', run_id, '--yes', '--json',
                               '--results-dir', str(self.results), '--lock-file', str(self.lease)],
                              env=self.environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(done.stdout)['status'], 'CLEANED'); self.assertEqual(self.names(), [])


class LostSupervisorTests(FakeDockerCase):
    def passing(self):
        """An unsealed record that would seal as PASS if its supervisor had lived to finalize it."""
        attempt = self.attempt(); record = attempt.record
        record['infrastructure'].update(status='ready', phase='agents')
        record['invocation'].update(status='verified', attempted_stages=1)
        record['termination'].update(reason='completed', process_exit_code=0)
        record['scoring'].update(status='completed'); record['task_result'].update(status='pass', score=1.0)
        record['protected_inputs']['status'] = 'unchanged'
        self.assertEqual(outcomes.status(record)[0], 'PASS')
        attempt.persist()
        return attempt

    def test_cleanup_seals_an_unsealed_run_whose_supervisor_is_gone_and_never_as_a_pass(self):
        attempt = self.passing(); run_id = attempt.record['run_id']
        self.stage(attempt, self.lease)
        self.docker(containers=[resource('pi-lab-orphan', run_id)])
        code, report = self.call('cleanup', '--run', run_id, '--yes')
        self.assertEqual((code, report['status']), (0, 'CLEANED'))
        result = controls.read(attempt.root / 'result.json')
        self.assertTrue(result['sealed']); self.assertEqual((result['status'], result['exit_code']), ('FAIL', 1))
        self.assertNotEqual(result['status'], 'PASS')
        self.assertEqual(report['finalization'], {'action': 'sealed', 'status': 'FAIL', 'exit_code': 1})
        interruption = result['controller_interruption']
        self.assertEqual((interruption['kind'], interruption['cleanup_confirmed']), ('controller_lost', True))
        self.assertEqual([(row['name'], row['removed_by']) for row in interruption['observations']],
                         [('pi-lab-orphan', 'run_label')])
        self.assertEqual(result['termination'], {'reason': 'process_error', 'trigger': 'controller_lost', 'process_exit_code': 0})
        self.assertEqual(result['infrastructure']['reason'], 'controller_lost')
        self.assertEqual(controls.read(attempt.root / 'summary.json'), result)
        self.assertEqual(controls.read(attempt.root / 'cleanup.json')['finalization']['action'], 'sealed')
        self.assertEqual(self.names(), [])
        # A second cleanup finds a sealed run and leaves its result alone.
        sealed = (attempt.root / 'result.json').read_bytes()
        self.assertEqual(self.call('cleanup', '--run', run_id, '--yes')[1]['finalization'], {'action': 'already_sealed'})
        self.assertEqual((attempt.root / 'result.json').read_bytes(), sealed)

    def test_a_run_killed_before_any_stage_seals_as_blocked_with_nothing_to_remove(self):
        attempt = self.attempt(); run_id = attempt.record['run_id']
        code, report = self.call('cleanup', '--run', run_id, '--yes')
        self.assertEqual((code, report['removed'], report['finalization']['status']), (0, [], 'BLOCKED'))
        result = controls.read(attempt.root / 'result.json')
        self.assertEqual(result['scoring']['reason'], 'controller_lost'); self.assertEqual(result['task_result']['status'], 'unknown')

    def test_a_dry_run_does_not_seal(self):
        attempt = self.passing()
        self.assertEqual(self.call('cleanup', '--run', attempt.record['run_id'])[0], 0)
        self.assertFalse((attempt.root / 'result.json').exists()); self.assertFalse((attempt.root / 'cleanup.json').exists())

    def test_experiment_attempts_and_directories_without_an_attempt_record_are_not_sealed(self):
        trial = self.attempt(); trial.record.update(experiment_id=str(uuid.uuid4()), trial_id='trial-1'); trial.persist()
        plain = self.results / 'preflight-fixture'; plain.mkdir()
        identity = {'schema': 2, 'run_id': str(uuid.uuid4()), 'attempt_id': str(uuid.uuid4())}
        controls.atomic(plain / 'identity.json', identity)
        self.docker(containers=[resource('pi-lab-preflight', identity['run_id'])])
        self.assertEqual(self.call('cleanup', '--run', trial.record['run_id'], '--yes')[1]['finalization'],
                         {'action': 'deferred', 'reason': 'experiment_attempt'})
        code, report = self.call('cleanup', '--run', identity['run_id'], '--yes')
        self.assertEqual((code, report['finalization']), (0, {'action': 'not_applicable', 'reason': 'no_attempt_record'}))
        self.assertEqual([row['name'] for row in report['removed']], ['pi-lab-preflight'])
        for root in (trial.root, plain):
            self.assertFalse((root / 'result.json').exists()); self.assertTrue((root / 'cleanup.json').exists())


class StatusLineTests(FakeDockerCase):
    def status(self, attempt):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            self.assertEqual(lab.main(['status', '--run', str(attempt.root)]), 0)
        return [line for line in stream.getvalue().splitlines() if line.startswith('Labelled Docker Resources:')]

    def test_status_counts_what_still_carries_the_run_label(self):
        attempt = self.attempt(seal=True); run_id = attempt.record['run_id']
        self.docker(containers=[resource('pi-lab-a', run_id), resource('pi-lab-b', run_id), resource('pi-lab-c', 'none')],
                    networks=[resource('pi-trial-a', run_id, state=None)])
        self.assertEqual(self.status(attempt), [
            f'Labelled Docker Resources: 2 container(s), 1 network(s) still exist for run {run_id}'])
        self.docker(containers=[], networks=[])
        self.assertEqual(self.status(attempt), [
            f'Labelled Docker Resources: 0 container(s), 0 network(s) still exist for run {run_id}'])
        self.assertEqual(self.effects(), [])

    def test_status_says_unknown_when_docker_cannot_be_asked(self):
        attempt = self.attempt(seal=True)
        self.docker(down=True)
        self.assertEqual(self.status(attempt), ['Labelled Docker Resources: unknown (Docker cannot be asked)'])
        with mock.patch.dict(os.environ, {'PATH': str(self.top / 'empty')}):
            self.assertEqual(self.status(attempt), ['Labelled Docker Resources: unknown (Docker cannot be asked)'])


if __name__ == '__main__':
    unittest.main()
