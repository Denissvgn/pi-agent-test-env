"""Registry compaction on real temporary leases and records; Docker and models are forbidden."""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skill/scripts'))
import ownership_registry as registry
import pi_lab as lab
import registry_compaction
import registry_maintenance as maintenance
import resources

IMAGE = 'sha256:' + 'a' * 64


def forbid_external():
    stack = contextlib.ExitStack()
    for target in ('subprocess.run', 'subprocess.Popen', 'socket.socket', 'os.system'):
        stack.enter_context(mock.patch(target, side_effect=AssertionError('External effect forbidden')))
    return stack


class CompactionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='registry-compaction-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.lease = self.root / 'operation.lock'
        fd = os.open(self.lease, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        self.registry = registry.Registry(Path(str(self.lease) + '.registry'), command=self.no_docker)
        self.archive = self.registry.root / registry.ARCHIVE_NAME
        self.generation = str(uuid.uuid4())
        external = forbid_external()
        external.__enter__()
        self.addCleanup(external.__exit__, None, None, None)

    @staticmethod
    def no_docker(argv):
        raise AssertionError('Docker is forbidden: ' + ' '.join(argv))

    def record(self, *, status='released', kind='container', generation=None, runroot=None, **fields):
        value = {'schema': 1, 'launch_id': str(uuid.uuid4()), 'generation': generation or self.generation,
                 'registry': self.registry.registry_id, 'status': status, 'container': 'pi-lab-synthetic',
                 'image': None if kind == 'network' else IMAGE, 'mounts': [], 'binding': {},
                 'runroot': runroot, 'created_at': '2026-01-01T00:00:00+00:00', 'daemon': 'synthetic-daemon'}
        if kind != 'container':
            value['kind'] = kind
        value.update(fields)
        return value

    def put(self, value):
        """Commit a synthetic record without the per-write inventory scan."""
        path = self.registry.root / (value['launch_id'] + '.json')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, indent=2)
        return value

    def fill(self, count, **fields):
        return [self.put(self.record(**fields)) for _ in range(count)]

    def record_files(self):
        return sorted(p.name for p in self.registry.root.iterdir() if p.name != registry.ARCHIVE_NAME)

    def archive_lines(self):
        if not self.archive.exists():
            return []
        return [json.loads(line) for line in self.archive.read_text().splitlines()]

    def snapshot(self):
        return {p.name: (p.read_bytes(), p.stat().st_ino, p.stat().st_mode) for p in self.registry.root.iterdir()}

    def cli(self, *arguments):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = lab.main([*arguments, '--lock-file', str(self.lease)])
        value = json.loads(stream.getvalue())
        self.assertEqual(code, value['exit_code'])
        return value

    def test_full_registry_compacts_completely_and_admits_again(self):
        self.fill(registry.MAX_RECORDS)
        with self.assertRaises(registry.RegistryCapacityError):
            self.registry.require_capacity(1)
        value = self.cli('registry-compact')
        self.assertEqual((value['status'], value['exit_code']), ('COMPACTED', 0))
        self.assertEqual((value['before'], value['after']), ({'records': 8192}, {'records': 0}))
        self.assertEqual((value['selected'], value['archived'], value['already_archived']), (8192, 8192, 0))
        self.assertEqual(self.record_files(), [])
        lines = self.archive_lines()
        self.assertEqual(len(lines), 8192)
        self.assertEqual(len({line['launch_id'] for line in lines}), 8192)
        self.assertTrue(all(type(line['archived_at']) is str for line in lines))
        self.assertEqual(self.archive.stat().st_mode & 0o777, 0o600)
        with resources.admission_lock(self.lease) as admitted:
            self.assertEqual(admitted.require_capacity(1)['retained_records'], 0)
            network = admitted.network_intent('pi-lab-after-compaction')
            network['status'] = 'absent'
            admitted.write(network)
        self.assertEqual([r['status'] for r in self.registry.load()], ['released'])
        self.assertEqual(len(self.archive_lines()), 8192)

    def test_archive_line_is_the_record_with_its_archive_time(self):
        kept = [self.put(self.record(kind=kind)) for kind in ('container', 'network', 'builder')]
        self.registry.compact()
        lines = {line['launch_id']: line for line in self.archive_lines()}
        for value in kept:
            line = dict(lines[value['launch_id']])
            line.pop('archived_at')
            self.assertEqual(line, value)

    def test_retained_ownership_is_byte_identical_after_compaction(self):
        run = str(self.root / 'helper-run')
        pending = self.put(self.record(status='intent', generation=str(uuid.uuid4())))
        quarantined = self.put(self.record(status='quarantined', generation=str(uuid.uuid4())))
        helper = self.put(self.record(schema=3, application_helper=True, owner_cleanup_contract=1,
                                      client_mode='application-execution', generation=str(uuid.uuid4()), runroot=run))
        legacy_helper = self.put(self.record(application_helper=True, generation=str(uuid.uuid4())))
        proven = self.put(self.record(generation=str(uuid.uuid4())))
        custody = Path(str(self.registry.root) + '.owner-proofs') / 'custody' / proven['launch_id']
        custody.mkdir(parents=True, mode=0o700)
        # Released records that a retained record still needs.
        same_pending_generation = self.put(self.record(generation=pending['generation']))
        same_quarantine_generation = self.put(self.record(generation=quarantined['generation']))
        same_helper_run = self.put(self.record(generation=str(uuid.uuid4()), runroot=run))
        named = self.put(self.record(generation=str(uuid.uuid4())))
        pending['binding'] = {'peer_launch_id': named['launch_id']}
        os.unlink(self.registry.root / (pending['launch_id'] + '.json'))
        self.put(pending)
        released = self.fill(5, generation=str(uuid.uuid4()))
        protected = [pending, quarantined, helper, legacy_helper, proven, same_pending_generation,
                     same_quarantine_generation, same_helper_run, named]
        before = self.snapshot()
        value = self.cli('registry-compact')
        self.assertEqual(value['status'], 'COMPACTED')
        self.assertEqual(value['archived'], len(released))
        after = self.snapshot()
        for record in protected:
            name = record['launch_id'] + '.json'
            with self.subTest(record=name):
                self.assertEqual(after[name], before[name])
        self.assertEqual({line['launch_id'] for line in self.archive_lines()}, {r['launch_id'] for r in released})
        self.assertEqual(sorted(self.record_files()), sorted(r['launch_id'] + '.json' for r in protected))
        self.assertTrue(custody.is_dir())

    def test_interrupted_removal_is_completed_without_a_second_line(self):
        released = self.fill(6)
        real = os.unlink
        calls = []

        def interrupted(path, *args, **kwargs):
            if str(path).endswith('.json') and 'dir_fd' in kwargs:
                calls.append(path)
                if len(calls) >= 3:
                    raise OSError(5, 'synthetic interruption before removal finished')
            return real(path, *args, **kwargs)

        with mock.patch.object(registry.os, 'unlink', side_effect=interrupted):
            with self.assertRaises(registry.RegistryError) as caught:
                self.registry.compact()
        diagnostic = registry.diagnostics.diagnostic(caught.exception)
        self.assertEqual((diagnostic['phase'], diagnostic['operation'], diagnostic['effects']),
                         ('registry_compaction', 'record_remove', 'may_have_occurred'))
        self.assertEqual(len(self.archive_lines()), 6)
        self.assertEqual(len(self.record_files()), 4)
        result = self.registry.compact()
        self.assertEqual((result['selected'], result['archived'], result['already_archived'], result['after']),
                         (4, 0, 4, 0))
        self.assertEqual(self.record_files(), [])
        lines = self.archive_lines()
        self.assertEqual(sorted(line['launch_id'] for line in lines), sorted(r['launch_id'] for r in released))

    def test_crash_before_any_removal_and_a_torn_final_line_leave_no_duplicates(self):
        released = self.fill(3)
        with mock.patch.object(registry.os, 'unlink', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.registry.compact()
        self.assertEqual(len(self.record_files()), 3)
        with self.archive.open('ab') as stream:
            stream.write(b'{"launch_id":"torn')
        later = self.fill(2)
        result = self.registry.compact()
        self.assertEqual((result['archived'], result['already_archived']), (2, 3))
        self.assertEqual(self.record_files(), [])
        ids = [line['launch_id'] for line in self.archive_lines()]
        self.assertEqual(sorted(ids), sorted(r['launch_id'] for r in released + later))

    def test_archived_copy_that_differs_refuses_removal(self):
        value = self.put(self.record())
        line = {**value, 'container': 'other', 'archived_at': '2026-01-01T00:00:00+00:00'}
        fd = os.open(self.archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(json.dumps(line) + '\n')
        before = self.snapshot()
        with self.assertRaises(registry.RegistryError):
            self.registry.compact()
        self.assertEqual(self.snapshot(), before)

    def test_malformed_or_insecure_archive_refuses_compaction(self):
        self.fill(2)
        for body, mode in ((b'not json\n', 0o600), (b'', 0o644)):
            with self.subTest(mode=oct(mode)):
                if self.archive.exists():
                    self.archive.unlink()
                fd = os.open(self.archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.write(fd, body)
                os.close(fd)
                self.archive.chmod(mode)
                before = self.snapshot()
                value = self.cli('registry-compact')
                self.assertEqual((value['status'], value['infrastructure']['reason']), ('BLOCKED', 'host-registry-unsafe'))
                self.assertEqual(value['infrastructure']['registry_diagnostic']['phase'], 'registry_compaction')
                self.assertEqual(self.snapshot(), before)

    def test_dry_run_changes_nothing(self):
        self.fill(3)
        self.put(self.record(status='intent', generation=str(uuid.uuid4())))
        before = self.snapshot()
        value = self.cli('registry-compact', '--dry-run')
        self.assertEqual((value['status'], value['exit_code'], value['dry_run']), ('DRY_RUN', 0, True))
        self.assertEqual((value['before'], value['after'], value['selected'], value['archived']),
                         ({'records': 4}, {'records': 4}, 3, 0))
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.archive.exists())
        self.registry.compact()
        self.fill(2)
        before = self.snapshot()
        value = self.cli('registry-compact', '--dry-run')
        self.assertEqual((value['selected'], value['archived']), (2, 0))
        self.assertEqual(self.snapshot(), before)

    def test_missing_lease_is_never_created(self):
        missing = self.root / 'missing.lock'
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = lab.main(['registry-compact', '--lock-file', str(missing)])
        value = json.loads(stream.getvalue())
        self.assertEqual((code, value['infrastructure']['reason']), (2, 'admission-lock-unavailable'))
        self.assertFalse(missing.exists())
        self.assertFalse(Path(str(missing) + '.registry').exists())

    def test_close_compacts_only_above_half_the_limit(self):
        self.fill(registry.COMPACT_ABOVE)
        with resources.admission_lock(self.lease):
            pass
        self.assertEqual(len(self.record_files()), registry.COMPACT_ABOVE)
        self.assertFalse(self.archive.exists())
        self.fill(1)
        with resources.admission_lock(self.lease):
            pass
        self.assertEqual(self.record_files(), [])
        self.assertEqual(len(self.archive_lines()), registry.COMPACT_ABOVE + 1)

    def test_refused_automatic_compaction_does_not_fail_close(self):
        self.fill(registry.COMPACT_ABOVE + 1)
        fd = os.open(self.archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, b'not json\n')
        os.close(fd)
        with resources.admission_lock(self.lease):
            pass
        self.assertEqual(len(self.record_files()), registry.COMPACT_ABOVE + 1)

    def test_admission_never_reads_the_archive(self):
        self.fill(2)
        self.registry.compact()
        real = registry.read_private

        def guarded(path, *args, **kwargs):
            if Path(path).name == registry.ARCHIVE_NAME:
                raise AssertionError('Admission read the archive')
            return real(path, *args, **kwargs)

        self.put(self.record(status='absent', generation=str(uuid.uuid4()), daemon=None))

        def gone(argv):
            self.assertEqual(argv[:3], ['docker', 'container', 'inspect'])
            return argparse.Namespace(returncode=1, stdout='[]\n', stderr='Error: No such container: ' + argv[-1])
        with mock.patch.object(registry, 'read_private', side_effect=guarded), \
                mock.patch.object(registry.Registry, '_open_archive', side_effect=AssertionError('archive opened')):
            changed = registry.Registry(self.registry.root, command=gone, recover_sensitive=lambda path: None)
            changed.reconcile()
            changed.validate_history(changed.load())
        self.assertEqual([r['status'] for r in changed.load()], ['released'])


class CapacityWarningTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='registry-warning-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.lease = self.root / 'operation.lock'
        os.close(os.open(self.lease, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        self.registry_root = registry.private_directory(Path(str(self.lease) + '.registry'))

    def names(self, count):
        for _ in range(count):
            os.close(os.open(self.registry_root / (str(uuid.uuid4()) + '.json'), os.O_WRONLY | os.O_CREAT, 0o600))

    def doctor(self):
        endpoint = self.root / 'endpoint.json'
        endpoint.write_text(json.dumps({'base_url': 'http://localhost:8000/v1', 'model': 'test-model',
                                        'context_window': 8192, 'max_tokens': 2048, 'api_key_env': 'PI_API_KEY'}))
        args = argparse.Namespace(image='pi-agent-tests:core', endpoint=str(endpoint), secrets_dir=str(self.root / 'secrets'),
                                  skip_network=True, project=None, probe_image=False, lock_file=str(self.lease),
                                  lock_wait_seconds=0)

        def docker(argv, **named):
            if argv[:3] == ['docker', 'context', 'inspect']:
                return argparse.Namespace(returncode=0, stdout=json.dumps([{'Endpoints': {'docker': {'Host': 'unix:///var/run/docker.sock'}}}]))
            return argparse.Namespace(returncode=0, stdout='arm64\n')
        output = io.StringIO()
        with mock.patch.object(lab, 'docker_info', return_value={'ServerVersion': '27.0.0', 'OSType': 'linux', 'Architecture': 'aarch64'}), \
                mock.patch.object(lab, 'command', side_effect=docker), \
                mock.patch.dict(os.environ, {'HOME': str(self.root / 'home')}, clear=True), \
                contextlib.redirect_stdout(output):
            lab.cmd_doctor(args)
        report = json.loads(output.getvalue())
        found = [item for item in report['checks'] if item['check'] == 'host-registry']
        self.assertEqual(len(found), 1)
        return found[0]

    def test_doctor_warns_from_three_quarters_with_the_remedy(self):
        self.assertEqual(registry.WARN_FROM, 6144)
        self.names(registry.WARN_FROM - 1)
        before = self.doctor()
        self.assertEqual((before['status'], before['records']), ('ok', 6143))
        self.assertNotIn('reason', before)
        self.names(1)
        item = self.doctor()
        self.assertEqual((item['status'], item['reason'], item['records'], item['limit']),
                         ('warn', 'registry-nearly-full', 6144, 8192))
        self.assertIn('registry-compact', item['remedy'])
        self.assertEqual(item['remedy'], maintenance.NEARLY_FULL_REMEDY)

    def test_doctor_without_a_registry_is_ok_and_creates_nothing(self):
        other = self.root / 'fresh.lock'
        item = maintenance.doctor_check(other)
        self.assertEqual((item['status'], item['records']), ('ok', 0))
        self.assertFalse(Path(str(other) + '.registry').exists())

    def test_registry_inspect_warns_from_three_quarters(self):
        owner = registry.Registry(self.registry_root, create=False)
        generation = str(uuid.uuid4())

        def fill(count):
            for _ in range(count):
                launch = str(uuid.uuid4())
                value = {'schema': 1, 'launch_id': launch, 'generation': generation, 'registry': owner.registry_id,
                         'status': 'released', 'container': 'pi-lab-synthetic', 'image': IMAGE, 'mounts': [],
                         'binding': {}, 'runroot': None, 'created_at': '2026-01-01T00:00:00+00:00', 'daemon': None}
                fd = os.open(self.registry_root / (launch + '.json'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'w') as stream:
                    json.dump(value, stream)

        def inspect():
            stream = io.StringIO()
            with forbid_external(), contextlib.redirect_stdout(stream):
                code = lab.main(['registry-inspect', '--lock-file', str(self.lease)])
            value = json.loads(stream.getvalue())
            self.assertEqual((code, value['status']), (0, 'OBSERVED'))
            return value

        fill(registry.WARN_FROM - 1)
        self.assertEqual(inspect()['warnings'], [])
        fill(1)
        value = inspect()
        self.assertEqual(value['capacity'], {'records': 6144, 'limit': 8192, 'warn_from': 6144})
        self.assertEqual(value['warnings'], [{'reason': 'registry-nearly-full', 'records': 6144, 'limit': 8192,
                                              'remedy': maintenance.NEARLY_FULL_REMEDY}])

    def test_command_module_is_registered(self):
        import command_modules
        self.assertIn('registry_compaction', command_modules.COMMAND_MODULES)
        args = lab.parser().parse_args(['registry-compact', '--dry-run', '--lock-file', str(self.lease)])
        self.assertIs(args.handler, registry_compaction.command)
        self.assertTrue(args.dry_run)


if __name__ == '__main__':
    unittest.main()
