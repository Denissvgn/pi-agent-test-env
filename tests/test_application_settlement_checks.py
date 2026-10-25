"""Bounded prerequisite-check controls; no real Registry, Docker or bridge read."""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/qualification'))
import application_settlement_checks as checks


def snapshot():
    registry = checks.sha(checks.REGISTRY.encode())
    generation = str(uuid.uuid4())
    return {'poisoned': True, 'launches': [
        {'cell': checks.CELL, 'role': role, 'registry': registry, 'generation': generation,
         'launch_id': str(uuid.uuid4()), 'intent_sha256': 'a' * 64, 'image': 'sha256:' + 'b' * 64,
         'container_id': 'c' * 64, 'physical': 'absent', 'private_cleanup': role in ('fixture', 'application-helper')}
        for role in sorted(checks.ROLES)]}


def selection():
    raw = checks.wire(snapshot())
    return checks.selection_from_snapshot(raw, checks.sha(raw))


class PrerequisiteCheckTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def hook_fixture(self, *, pending=False):
        lock = self.root / 'operation.lock'; lock.write_bytes(b'preserved-header'); lock.chmod(0o600)
        registry = self.root / 'operation.lock.registry'; registry.mkdir(mode=0o700)
        with mock.patch.object(checks, 'LOCK', str(lock)), mock.patch.object(checks, 'REGISTRY', str(registry)):
            captured = snapshot()
            for index, item in enumerate(captured['launches']):
                record = {'schema': 1, **{key: item[key] for key in ('registry', 'generation', 'launch_id', 'image', 'container_id')},
                          'container': 'inert-' + str(index), 'mounts': [],
                          'status': 'quarantined' if pending and index == 0 else 'released'}
                item['intent_sha256'] = checks.sha(checks.wire({key: value for key, value in record.items()
                                                            if key not in ('status', 'container_id')}))
                path = registry / (item['launch_id'] + '.json'); path.write_bytes(checks.wire(record)); path.chmod(0o600)
            raw = checks.wire(captured)
            descriptor = checks.preparation('ownership', checks.selection_from_snapshot(raw, checks.sha(raw)))
        return lock, registry, descriptor

    def test_offline_preparation_exact_six_static_records_zero_clearance(self):
        value = checks.preparation('ownership', selection())
        checks.verify_preparation(value)
        self.assertEqual(len(value['selection']['records']), 6)
        self.assertFalse(value['clearance_or_dispatch_authority'])
        self.assertTrue(value['normal_SDK_admission_still_required'])
        self.assertEqual(value['original_record_writes'], 0)
        self.assertEqual(value['limits']['target_bytes_max'], 6 * 1048576)

    def test_snapshot_digest_or_role_or_source_selection_drift_denied(self):
        raw = checks.wire(snapshot())
        with self.assertRaises(ValueError): checks.selection_from_snapshot(raw, '0' * 64)
        for fault in ('role', 'count', 'physical', 'cell', 'registry', 'path'):
            value = snapshot()
            if fault == 'role': value['launches'][0]['role'] = 'foreign'
            elif fault == 'count': value['launches'].pop()
            elif fault == 'physical': value['launches'][0]['physical'] = 'running'
            elif fault == 'cell': value['launches'][0]['cell'] = 'N04-1.2.0-1'
            elif fault == 'registry': value['launches'][0]['registry'] = 'e' * 64
            else:
                value = selection(); value['records'][0]['path'] = '/private/foreign.json'
                with self.assertRaises(ValueError): checks.validate_selection(value)
                continue
            encoded = checks.wire(value)
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                checks.selection_from_snapshot(encoded, checks.sha(encoded))

    def test_rehashed_preparation_cannot_change_lock_limits_or_authority(self):
        value = checks.preparation('bridge')
        for key, item in [('normal_lock', '/tmp/bypass.lock'), ('limits', {**checks.LIMITS, 'docker_queries_max': 3}),
                          ('clearance_or_dispatch_authority', True), ('output', checks.PRESERVED_ROOT + '/result')]:
            changed = copy.deepcopy(value); changed[key] = item
            with self.subTest(key=key), self.assertRaises(ValueError): checks.verify_preparation(changed)

    def test_record_projection_has_only_declared_status_and_no_sensitive_values(self):
        selected = selection()['records'][0]
        record = {'schema': 1, **{key: selected[key] for key in ('launch_id', 'registry', 'generation', 'image', 'container_id')},
                  'status': 'released', 'private_store': '/secret/private-path', 'token': 'SECRET-DO-NOT-EXPORT',
                  'qualification_service_cleanup': {'path': '/secret/proof', 'sha256': 'd' * 64}}
        selected['intent_sha256'] = checks.sha(checks.wire({key: item for key, item in record.items()
            if key not in ('status', 'container_id', 'qualification_service_cleanup', 'qualification_preworker_cleanup')}))
        result = checks.owner_projection(record, selected)
        self.assertTrue(result['intent_binding_matches'])
        self.assertEqual(result['declared_status'], 'released')
        self.assertFalse(result['physical_or_private_absence_verified'])
        self.assertFalse(result['normal_registry_release_verified'])
        encoded = checks.wire(result)
        for private in (b'SECRET', b'/secret/', selected['launch_id'].encode(), selected['intent_sha256'].encode()):
            self.assertNotIn(private, encoded)

    def test_record_identity_null_or_status_drift_denied(self):
        selected = selection()['records'][0]
        for value in (None, [], {'schema': True}, {'schema': 1, 'launch_id': str(uuid.uuid4())}):
            with self.subTest(value=value), self.assertRaises(ValueError): checks.owner_projection(value, selected)

    def test_genuine_ordinary_worker_producer_allows_missing_CID_without_clearance(self):
        sys.path.insert(0,str(ROOT/'skill/scripts'))
        import ownership_registry
        for schema in (1,2):
            registry=object.__new__(ownership_registry.Registry)
            registry.generation=str(uuid.uuid4());registry.registry_id='a'*64
            registry.binding={}if schema==1 else{'indexed_host_generation':2}
            registry.runroot=None;registry.daemon='NONSECRET_FIXTURE_DAEMON';writes=[];registry.write=writes.append
            image='sha256:'+'b'*64
            record,_=registry.intent(['docker','run','--name','inert-probe',image,'/opt/pi-lab/worker.py'],'inert-probe')
            self.assertEqual(record['schema'],schema);self.assertNotIn('container_id',record)
            record['status']='released'
            selected={'role':'probe',**{key:record[key]for key in('registry','generation','launch_id','image')},'container_id':'c'*64}
            selected['intent_sha256']=checks.sha(checks.wire({key:value for key,value in record.items()if key!='status'}))
            before=copy.deepcopy(record);value=checks.owner_projection(record,selected)
            self.assertTrue(value['intent_binding_matches']);self.assertEqual(record,before)
            self.assertFalse(value['physical_or_private_absence_verified']);self.assertFalse(value['normal_registry_release_verified'])
            record['container_id']=None;self.assertTrue(checks.owner_projection(record,selected)['intent_binding_matches'])
            record['container_id']='d'*64
            with self.assertRaises(ValueError):checks.owner_projection(record,selected)

    def test_optional_CID_rule_cannot_relax_service_or_sensitive_helper_identity(self):
        selected=selection()['records'][0]
        for role,sensitive in (('fixture',False),('application-helper',True),('probe',True)):
            item={**selected,'role':role};record={'schema':1,**{key:item[key]for key in('launch_id','registry','generation','image')},
                'status':'released','application_helper':sensitive}
            with self.subTest(role=role),self.assertRaises(ValueError):checks.owner_projection(record,item)
        item={**selected,'role':'probe'}
        for marker,value in [('application_helper',1),('qualification_role','fixture'),
                             ('qualification_service_cleanup',{}),('qualification_preworker_cleanup',{}),
                             ('client_mode','qualification-fixture')]:
            record={'schema':1,**{key:item[key]for key in('launch_id','registry','generation','image')},'status':'released',marker:value}
            with self.subTest(marker=marker),self.assertRaises(ValueError):checks.owner_projection(record,item)

    def test_denial_hook_accepts_ordinary_missing_CID_but_keeps_release_gate(self):
        lock,registry,descriptor=self.hook_fixture()
        worker=next(row for row in descriptor['selection']['records']if row['role']=='probe')
        path=registry/(worker['launch_id']+'.json');record=json.loads(path.read_bytes());del record['container_id']
        path.write_bytes(checks.wire(record))
        with lock.open('rb')as lease,mock.patch.object(checks,'LOCK',str(lock)),mock.patch.object(checks,'REGISTRY',str(registry)):
            self.assertIsNone(checks.deny_unsafe_original_ownership(descriptor,lease_fd=lease.fileno(),lock_path=lock,registry_root=registry))
        record['status']='quarantined';path.write_bytes(checks.wire(record))
        with lock.open('rb')as lease,mock.patch.object(checks,'LOCK',str(lock)),mock.patch.object(checks,'REGISTRY',str(registry)),self.assertRaises(ValueError):
            checks.deny_unsafe_original_ownership(descriptor,lease_fd=lease.fileno(),lock_path=lock,registry_root=registry)

    def test_bridge_metadata_never_claims_listener_container_or_ownership_proof(self):
        info = {'ID': checks.DAEMON, 'OSType': 'linux', 'Architecture': 'arm64'}
        network = [{'Name': 'bridge', 'Driver': 'bridge', 'Scope': 'local',
                    'IPAM': {'Config': [{'Gateway': '172.17.0.1', 'Subnet': '172.17.0.0/16'}]}}]
        result = checks.bridge_projection(info, network)
        self.assertEqual(result['server_listener_exposure'], 'NOT_OBSERVED')
        self.assertEqual(result['container_reachability'], 'NOT_OBSERVED')
        self.assertFalse(result['dispatch_ready']); self.assertFalse(result['ownership_clearance'])
        for field, replacement in [('ID', 'other'), ('Architecture', 'amd64'), ('OSType', 'darwin')]:
            changed = dict(info); changed[field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError): checks.bridge_projection(changed, network)
        for change in ('public', 'gateway', 'driver', 'multiple'):
            modified = copy.deepcopy(network)
            if change == 'public': modified[0]['IPAM']['Config'][0]['Subnet'] = '8.8.8.0/24'
            elif change == 'gateway': modified[0]['IPAM']['Config'][0]['Gateway'] = '172.17.0.2'
            elif change == 'driver': modified[0]['Driver'] = 'overlay'
            else: modified.append(copy.deepcopy(modified[0]))
            with self.subTest(change=change), self.assertRaises(ValueError): checks.bridge_projection(info, modified)

    def test_reader_one_pass_custody_mode_symlink_and_replacement_controls(self):
        path = self.root / 'record.json'; path.write_bytes(b'{"schema":1}'); path.chmod(0o600)
        reader = checks.Reader()
        try:
            self.assertEqual(reader.read(path, 100), b'{"schema":1}')
            self.assertEqual((reader.attempts, reader.bytes), (1, 12))
            reader.fence()
            replacement = self.root / 'new'; replacement.write_bytes(b'{"schema":1}'); replacement.chmod(0o600); replacement.replace(path)
            with self.assertRaises(ValueError): reader.fence()
        finally: reader.close()
        link = self.root / 'link'; link.symlink_to(path)
        reader = checks.Reader()
        with self.assertRaises((OSError, ValueError)): reader.read(link, 100)
        self.assertEqual(reader.attempts, 1); reader.close()
        path.chmod(0o644)
        reader = checks.Reader()
        with self.assertRaises(ValueError): reader.read(path, 100)
        reader.close()

    def test_reader_limits_and_decode_failure_preserve_real_read_cost(self):
        path = self.root / 'record'; path.write_bytes(b'null'); path.chmod(0o600)
        reader = checks.Reader()
        try:
            body = reader.read(path, 4)
            with self.assertRaises(ValueError): checks.owner_projection(checks.decode(body), selection()['records'][0])
            self.assertEqual((reader.attempts, reader.bytes), (1, 4))
        finally: reader.close()
        reader = checks.Reader()
        with self.assertRaises(ValueError): reader.read(path, 3)
        self.assertEqual((reader.attempts, reader.bytes), (1, 0)); reader.close()

    def test_original_lock_observation_never_truncates_or_changes_mode(self):
        path = self.root / 'operation.lock'; path.write_bytes(b'preserve-original-header'); path.chmod(0o600)
        before = path.stat()
        with mock.patch.object(checks, 'LOCK', str(path)):
            with checks.readonly_original_lock(time.monotonic() + 1): pass
        after = path.stat()
        self.assertEqual(path.read_bytes(), b'preserve-original-header')
        self.assertEqual((before.st_ino, before.st_mode, before.st_mtime_ns), (after.st_ino, after.st_mode, after.st_mtime_ns))

    def test_busy_original_lock_is_not_replaced_or_bypassed(self):
        path = self.root / 'operation.lock'; path.write_bytes(b'busy'); path.chmod(0o600)
        with path.open('rb') as owner:
            fcntl.flock(owner.fileno(), fcntl.LOCK_EX)
            with mock.patch.object(checks, 'LOCK', str(path)), self.assertRaises(ValueError):
                with checks.readonly_original_lock(time.monotonic() + .02): self.fail('Busy lease admitted')
        self.assertEqual(path.read_bytes(), b'busy')

    def test_missing_wrong_or_native_grant_denies_without_runtime_queries(self):
        prepared = checks.wire(checks.preparation('bridge'))
        with mock.patch.object(checks.subprocess, 'Popen', side_effect=AssertionError('No runtime effect')):
            for grant in ({}, {'schema': 1, 'status': 'AUTHORIZED'}, {'status': 'AUTHORIZED_CHECK_ONLY'}):
                with self.subTest(grant=grant), self.assertRaises((ValueError, KeyError)):
                    checks.authorize(prepared, checks.wire(grant), b'{}')

    def test_exact_check_grant_is_distinct_from_execution_or_clearance(self):
        prepared = checks.wire(checks.preparation('bridge'))
        grant = {'schema': 1, 'document_type': 'bounded_settlement_check_grant', 'status': 'AUTHORIZED_CHECK_ONLY',
            'authorization_id': str(uuid.uuid4()), 'kind': 'bridge', 'preparation_sha256': checks.sha(prepared),
            'source_sha256': checks.sha(Path(checks.__file__).read_bytes()), 'issued_wall': time.time() - 1,
            'deadline_wall': time.time() + 100, 'max_attempts': 1,
            'effects': {'containers': 0, 'participants': 0, 'model_business_calls': 0, 'record_writes': 0, 'docker_queries': 2}}
        encoded = checks.wire(grant)
        review = {'schema': 1, 'document_type': 'independent_bounded_settlement_check_review', 'status': 'PASS',
            'grant_sha256': checks.sha(encoded), 'preparation_sha256': checks.sha(prepared),
            'source_sha256': grant['source_sha256'], 'supports_check_only': True, 'unresolved': []}
        value, _ = checks.authorize(prepared, encoded, checks.wire(review))
        self.assertFalse(value['clearance_or_dispatch_authority'])
        for key, replacement in [('status', 'AUTHORIZED_EXECUTION'), ('max_attempts', 2), ('kind', 'ownership')]:
            changed = dict(grant); changed[key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError): checks.authorize(prepared, checks.wire(changed), checks.wire(review))

    def test_bounded_docker_output_is_killed_waited_and_never_exported(self):
        original = subprocess.Popen
        handles = []
        def oversized(*args, **kwargs):
            process = original([sys.executable, '-c', "import os,time;os.write(1,b'SECRET'*200000);time.sleep(30)"], **kwargs)
            handles.append(process); return process
        costs = {'docker_queries': 0, 'returned_handles': 0, 'constructor_uncertain': False}
        started = time.monotonic()
        with mock.patch.object(checks.subprocess, 'Popen', side_effect=oversized), self.assertRaises(ValueError):
            checks.bridge_observation(time.monotonic() + 5, costs)
        self.assertLess(time.monotonic() - started, 6)
        self.assertEqual(costs['docker_queries'], 1); self.assertEqual(costs['returned_handles'], 1)
        self.assertIsNotNone(handles[0].returncode)
        self.assertTrue(handles[0].stdout.closed and handles[0].stderr.closed)

    def test_parser_duplicate_nonfinite_depth_and_oversize_are_refused(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'[' * 30 + b'0' + b']' * 30, b'{}' * 600000):
            with self.subTest(size=len(raw)), self.assertRaises((ValueError, RecursionError)): checks.decode(raw)

    def test_runtime_rejects_unbound_control_paths_before_any_body_read(self):
        with mock.patch.object(checks.Reader, 'read', side_effect=AssertionError('No unbound body read')):
            with self.assertRaises(ValueError):
                checks.run_check('/private/secret', '/private/secret2', '/private/secret3', '/private/output')

    def test_expired_reader_does_not_open_or_charge_target(self):
        reader = checks.Reader()
        reader.deadline_check = lambda: checks.need(False)
        with mock.patch.object(checks, 'directory', side_effect=AssertionError('No target open')):
            with self.assertRaises(ValueError): reader.read(self.root / 'absent', 100)
        self.assertEqual((reader.attempts, reader.bytes), (0, 0))
        reader.close()

    def test_existing_alarm_is_not_borrowed_or_reset_by_a_check(self):
        with mock.patch.object(checks.signal, 'getitimer', return_value=(25., 0.)), \
             mock.patch.object(checks.signal, 'setitimer') as timer, \
             mock.patch.object(checks.Reader, 'read', side_effect=AssertionError('No body read')):
            with self.assertRaises(ValueError):
                checks.run_check('/unbound', '/unbound', '/unbound', '/unbound')
        timer.assert_not_called()

    def test_entry_timer_covers_first_authorization_body_read(self):
        def first_read(*args, **kwargs):
            left, interval = signal.getitimer(signal.ITIMER_REAL)
            self.assertGreater(left, 0); self.assertLessEqual(left, 120); self.assertEqual(interval, 0)
            raise ValueError('inert stop before control read')
        prepared = Path(checks.OUTPUT_BASE) / 'bridge/PREPARATION.json'
        previous = signal.getsignal(signal.SIGALRM)
        with mock.patch.object(checks.Reader, 'read', side_effect=first_read) as read:
            with self.assertRaises(ValueError):
                checks.run_check(prepared, prepared.parent/'grant.json', prepared.parent/'review.json', '/unbound')
        read.assert_called_once()
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0., 0.))
        self.assertIs(signal.getsignal(signal.SIGALRM), previous)

    def test_authorization_elapsed_time_consumes_entry_budget_without_reset(self):
        reader = mock.Mock(); reader.read.return_value = b'{}'
        prepared = Path(checks.OUTPUT_BASE) / 'bridge/PREPARATION.json'
        entry = [226., 1126.]
        with mock.patch.object(checks, 'authorize', return_value=({'kind':'bridge', 'output':'/never'}, {'deadline_wall':1800.})), \
             mock.patch.object(checks.os, 'getuid', return_value=1000), \
             mock.patch.object(checks.pwd, 'getpwuid', return_value=mock.Mock(pw_name='piqual', pw_dir='/home/piqual')), \
             mock.patch.object(checks.os, 'uname', return_value=mock.Mock(machine='aarch64')), \
             mock.patch.dict(checks.os.environ, {'HOME':'/home/piqual'}, clear=True), \
             mock.patch.object(checks.time, 'monotonic', return_value=120.), \
             mock.patch.object(checks.time, 'time', return_value=1020.), \
             mock.patch.object(checks.signal, 'setitimer') as timer, \
             mock.patch.object(checks, 'directory', side_effect=AssertionError('No output or target open')):
            with self.assertRaises(ValueError):
                checks._run_check(prepared, prepared.parent/'grant.json', prepared.parent/'review.json', '/unbound', reader,
                                  started=100., started_wall=1000., hard_deadlines=entry)
        self.assertEqual(timer.call_args_list[0], mock.call(signal.ITIMER_REAL, 100.))
        self.assertEqual(entry, [226., 1126.])

    def test_denial_only_hook_keeps_original_header_and_records_and_never_nests_flock(self):
        lock, registry, descriptor = self.hook_fixture()
        before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in registry.iterdir()}
        with lock.open('rb') as lease, mock.patch.object(checks, 'LOCK', str(lock)), \
             mock.patch.object(checks, 'REGISTRY', str(registry)), \
             mock.patch.object(checks.fcntl, 'flock', side_effect=AssertionError('Hook may not acquire another lock')):
            self.assertIsNone(checks.deny_unsafe_original_ownership(descriptor, lease_fd=lease.fileno(),
                lock_path=lock, registry_root=registry))
        self.assertEqual(lock.read_bytes(), b'preserved-header')
        self.assertEqual(before, {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in registry.iterdir()})
        self.assertFalse(descriptor['clearance_or_dispatch_authority'])

    def test_denial_only_hook_refuses_pending_record_before_original_registry_effects(self):
        lock, registry, descriptor = self.hook_fixture(pending=True)
        with lock.open('rb') as lease, mock.patch.object(checks, 'LOCK', str(lock)), \
             mock.patch.object(checks, 'REGISTRY', str(registry)), self.assertRaises(ValueError):
            checks.deny_unsafe_original_ownership(descriptor, lease_fd=lease.fileno(), lock_path=lock, registry_root=registry)
        self.assertEqual(lock.read_bytes(), b'preserved-header')
        states = [json.loads(path.read_bytes())['status'] for path in registry.iterdir()]
        self.assertEqual(states.count('quarantined'), 1)


if __name__ == '__main__':
    unittest.main()
