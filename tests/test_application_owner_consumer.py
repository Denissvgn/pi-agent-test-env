"""Fresh consumer workers never inherit provider modules or operational approval."""
import copy
import hashlib
import json
import importlib.util
import marshal
import os
from pathlib import Path
import shutil
import stat
import struct
import sys
import tempfile
from unittest import TestCase, mock

from tests.test_application_owner_consumer_policy import example_policy, selection
from tools.qualification import application_owner_consumer as consumer
from tools.qualification import application_owner_consumer_policy as policy

ROOT = Path(__file__).resolve().parents[1]


def actual_policy(root, *, provider_root=None):
    value = example_policy()
    provider_root = ROOT / 'skill' if provider_root is None else provider_root
    value['provider'] = {'root': str(provider_root), 'files': {
        str(p.relative_to(provider_root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(provider_root.rglob('*')) if p.is_file() and '__pycache__' not in p.parts}}
    value['provider']['inventory_sha256'] = policy.digest(value['provider']['files'])
    value['consumer'] = {'files': {name: hashlib.sha256((ROOT/'tools/qualification'/name).read_bytes()).hexdigest()
                                 for name in policy.CONSUMER_FILES},
                         'python_sha256': hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
                         'python_version': list(sys.version_info[:3])}
    old = value['lease']['path']; new = str(root / 'original.lock')
    value['lease']['path'] = new
    for key in ('registry', 'store', 'anchor'):
        value['read_scope'][key] = value['read_scope'][key].replace(old, new)
    for row in value['read_scope']['files']:row['path'] = row['path'].replace(old, new)
    value['read_scope']['directories'] = [p.replace(old, new) for p in value['read_scope']['directories']]
    value['read_scope']['absent_paths'] = [str(root / 'disposable')]
    value['subject']['registry'] = hashlib.sha256(value['read_scope']['registry'].encode()).hexdigest()
    return value


class ConsumerTests(TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve(); self.root.chmod(0o700)

    def test_missing_or_changed_policy_denies_before_process_or_file_access(self):
        value = example_policy()
        for pin in (None, '', '0'*64, 'b'*64):
            with (self.subTest(pin=pin),
                  mock.patch.object(consumer, 'exchange', side_effect=AssertionError('factory')),
                  mock.patch('os.open', side_effect=AssertionError('file'))):
                result = consumer.evaluate(value, trusted_policy_sha256=pin, selection=selection(value))
                self.assertEqual(result['decision'], 'extension_required')
                self.assertFalse(result['provider_imported']); self.assertFalse(result['admission_authorized'])

    def test_unapproved_mode_cannot_start_a_provider(self):
        value = example_policy()
        with mock.patch.object(consumer, 'exchange', side_effect=AssertionError('factory')):
            result = consumer.evaluate(value, trusted_policy_sha256=policy.digest(value),
                                       selection=selection(value), mode='cleanup')
        self.assertEqual(result['decision'], 'extension_required')

    def test_origin_only_capability_cannot_be_used_for_replay_or_history_io(self):
        value=example_policy();value.update(capabilities=['origins'],subject=None,lease=None,read_scope=None)
        with (mock.patch.object(consumer,'exchange',side_effect=AssertionError('origin approval used for replay')),
              mock.patch('os.open',side_effect=AssertionError('history read'))):
            result=consumer.evaluate(value,trusted_policy_sha256=policy.digest(value),selection=selection(value),mode='replay')
        self.assertEqual(result['decision'],'extension_required');self.assertFalse(result['provider_imported'])

    def test_worker_refuses_a_nonisolated_direct_invocation(self):
        code,stdout,stderr=consumer.exchange([sys.executable,'-B',
            str(ROOT/'tools/qualification/application_owner_consumer_worker.py')],b'{}')
        self.assertEqual(code,0);self.assertEqual(stderr,b'')
        self.assertEqual(json.loads(stdout),{'invalid_worker_result':True})

    def test_consumer_or_interpreter_substitution_denies_before_worker(self):
        value = actual_policy(self.root)
        for part in ('python_sha256', 'files'):
            trial = copy.deepcopy(value)
            if part == 'files':trial['consumer']['files']['application_owner_consumer_worker.py'] = 'b'*64
            else:trial['consumer'][part] = 'b'*64
            with self.subTest(part=part), mock.patch.object(consumer, 'exchange', side_effect=AssertionError('factory')):
                result = consumer.evaluate(trial, trusted_policy_sha256=policy.digest(trial), selection=selection(trial))
                self.assertEqual(result['decision'], 'extension_required')

    def test_provider_inventory_rejects_unapproved_files_symlinks_and_changed_bytes(self):
        provider = self.root/'provider'; shutil.copytree(ROOT/'skill', provider, ignore=shutil.ignore_patterns('__pycache__'))
        value = actual_policy(self.root, provider_root=provider)
        approved = policy.compile_policy(value, trusted_policy_sha256=policy.digest(value), selection=selection(value))
        consumer.provider_inventory(approved)
        extra = provider/'unexpected.py'; extra.write_text('raise AssertionError("not approved")')
        read=consumer.stable_read;reads=[]
        def observed(path,**options):reads.append(Path(path));return read(path,**options)
        with mock.patch.object(consumer,'stable_read',side_effect=observed):
            with self.assertRaises(consumer.ConsumerError):consumer.provider_inventory(approved)
        self.assertNotIn(extra,reads)
        extra.unlink();folder=provider/'unexpected-directory';folder.mkdir();(folder/'private').write_bytes(b'not approved')
        reads.clear()
        with mock.patch.object(consumer,'stable_read',side_effect=observed):
            with self.assertRaises(consumer.ConsumerError):consumer.provider_inventory(approved)
        self.assertFalse(any(folder in path.parents for path in reads))
        shutil.rmtree(folder)
        target = provider/'SKILL.md'; saved = target.read_bytes(); target.write_bytes(saved+b'changed')
        with self.assertRaises(consumer.ConsumerError):consumer.provider_inventory(approved)
        target.unlink(); target.symlink_to(provider/'LICENSE')
        with self.assertRaises(consumer.ConsumerError):consumer.provider_inventory(approved)

    def test_verified_consumer_source_ignores_valid_unapproved_bytecode(self):
        artifact=self.root/'consumer';artifact.mkdir(mode=0o700)
        for name in policy.CONSUMER_FILES:shutil.copyfile(ROOT/'tools/qualification'/name,artifact/name)
        source=artifact/'application_owner_consumer_policy.py'
        cached=Path(importlib.util.cache_from_source(str(source)));cached.parent.mkdir()
        header=importlib.util.MAGIC_NUMBER+struct.pack('<III',0,int(source.stat().st_mtime)&0xffffffff,source.stat().st_size)
        code=compile('raise RuntimeError("unapproved bytecode executed")',str(source),'exec')
        cached.write_bytes(header+marshal.dumps(code))
        control='import sys;sys.path.insert(0,'+repr(str(artifact))+');import application_owner_consumer_policy'
        exit_code,unused,stderr=consumer.exchange([sys.executable,'-I','-S','-B','-c',control],b'')
        self.assertNotEqual(exit_code,0);self.assertIn(b'unapproved bytecode executed',stderr)
        value=actual_policy(self.root);value.update(capabilities=['origins'],subject=None,lease=None,read_scope=None)
        packet={'policy':value,'trusted_policy_sha256':policy.digest(value),'selection':selection(value),
                'mode':'origins','memory':consumer.empty_memory()}
        probe=('import runpy,sys;module=runpy.run_path('+repr(str(artifact/'application_owner_consumer_worker.py'))+');'
               '\ntry: module["bootstrap"]()\nexcept ValueError as error:'
               '\n if type(error).__name__ not in ("ConsumerError","PolicyError"): raise'
               '\nassert sys.modules["application_owner_consumer_policy"].CONTRACT=="application_owner_legacy_reader_1"'
               '\nprint("verified source loaded")')
        exit_code,stdout,stderr=consumer.exchange([sys.executable,'-I','-S','-B','-c',probe],policy.canonical(packet))
        self.assertEqual((exit_code,stdout,stderr),(0,b'verified source loaded\n',b''))

    def test_mutable_provider_filesystem_stops_before_provider_import(self):
        from tools.qualification import application_owner_consumer_worker as worker
        provider = self.root/'provider'; shutil.copytree(ROOT/'skill', provider, ignore=shutil.ignore_patterns('__pycache__'))
        if os.statvfs(provider).f_flag & os.ST_RDONLY:self.skipTest('Requires a writable temporary filesystem')
        value = actual_policy(self.root, provider_root=provider)
        approved = policy.compile_policy(value, trusted_policy_sha256=policy.digest(value), selection=selection(value))
        with mock.patch.object(consumer, 'provider_inventory', side_effect=AssertionError('before readonly gate')):
            result = worker.run(consumer, approved, {'mode':'origins','memory':consumer.empty_memory()})
        self.assertEqual(result['decision'], 'invalid_proof')
        self.assertFalse(result['provider_imported'])
        self.assertEqual(result['condition'], 'provider_readonly_required')

    def test_invalid_worker_output_is_closed_and_does_not_leak_exception_bodies(self):
        value = actual_policy(self.root)
        for reply in ((0, b'{"secret":"private exception"}', b''),
                      (2, b'', b'/private/source exception contains credential'),
                      (0, b'{"schema":1,"schema":2}', b'')):
            with (self.subTest(reply=reply[0]), mock.patch.object(consumer, 'exchange', return_value=reply),
                  mock.patch.object(consumer, 'verify_consumer')):
                result = consumer.evaluate(value, trusted_policy_sha256=policy.digest(value), selection=selection(value))
                self.assertEqual(result['decision'], 'invalid_proof')
                self.assertNotIn('private', json.dumps(result)); self.assertNotIn('credential', json.dumps(result))

    def test_group_writable_interpreter_denies_before_worker(self):
        binary = self.root/'untrusted-python'; binary.write_bytes(b'untrusted executable'); binary.chmod(0o775)
        value = actual_policy(self.root)
        value['consumer']['python_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
        with (mock.patch.object(sys, 'executable', str(binary)),
              mock.patch.object(consumer, 'exchange', side_effect=AssertionError('untrusted runtime'))):
            result = consumer.evaluate(value, trusted_policy_sha256=policy.digest(value), selection=selection(value))
        self.assertEqual(result['decision'], 'extension_required')

    def test_unknown_worker_effects_are_not_fabricated_selected_state_and_survive_new_handles(self):
        value=actual_policy(self.root)
        with (mock.patch.object(consumer,'verify_consumer'),
              mock.patch.object(consumer,'exchange',return_value=(0,b'{}',b''))):
            observed=consumer.evaluate(value,trusted_policy_sha256=policy.digest(value),selection=selection(value))
        self.assertFalse(observed['memory']['selected']);self.assertTrue(observed['memory']['indeterminate'])
        self.assertIsNone(observed['provider_imported']);self.assertIsNone(observed['history_read'])
        with mock.patch.object(consumer,'exchange',side_effect=AssertionError('uncertain state fallback')):
            observed=consumer.evaluate(value,trusted_policy_sha256=policy.digest(value),selection=selection(value),mode='replay')
        self.assertEqual(observed['decision'],'invalid_proof')

    def test_consumer_module_reload_cannot_erase_indeterminate_state(self):
        import importlib
        value=actual_policy(self.root)
        with (mock.patch.object(consumer,'verify_consumer'),
              mock.patch.object(consumer,'exchange',return_value=(0,b'{}',b''))):
            consumer.evaluate(value,trusted_policy_sha256=policy.digest(value),selection=selection(value))
        importlib.reload(consumer)
        with mock.patch.object(consumer,'exchange',side_effect=AssertionError('module reload fallback')):
            observed=consumer.evaluate(value,trusted_policy_sha256=policy.digest(value),selection=selection(value),mode='replay')
        self.assertEqual(observed['decision'],'invalid_proof');self.assertTrue(observed['memory']['indeterminate'])

    def test_root_traversal_descriptor_does_not_approve_root_listing_or_payload(self):
        from tools.qualification import application_owner_consumer_worker as worker
        value = example_policy()
        approved = policy.compile_policy(value, trusted_policy_sha256=policy.digest(value), selection=selection(value))
        guard = worker.Guard(consumer, approved)
        self.assertEqual(guard.path('/'), Path('/'))
        guard.allowed(Path('/'), directory=True)
        with self.assertRaises(consumer.ConsumerError):guard.allowed(Path('/'), directory=False)
        with self.assertRaises(consumer.ConsumerError):guard.audit('os.listdir', ('/',))

    def test_historical_source_and_arbitrary_generated_code_are_not_executable(self):
        from tools.qualification import application_owner_consumer_worker as worker
        value = example_policy()
        approved = policy.compile_policy(value, trusted_policy_sha256=policy.digest(value), selection=selection(value))
        guard = worker.Guard(consumer, approved)
        for filename in ('/owner/original-program.py', '<string>'):
            with self.subTest(filename=filename), self.assertRaises(consumer.ConsumerError):
                guard.audit('exec', (compile('pass', filename, 'exec'),))
        for event,args in (('subprocess.Popen',()),('os.kill',(123,0)),('os.remove',('/owner/file',)),
                           ('socket.__new__',()),('open',('/owner/credentials','r',os.O_RDONLY))):
            with self.subTest(event=event), self.assertRaises(consumer.ConsumerError):guard.audit(event,args)

    def test_origins_mode_has_no_historical_metadata_or_read_grant(self):
        from tools.qualification import application_owner_consumer_worker as worker
        value=example_policy()
        approved=policy.compile_policy(value,trusted_policy_sha256=policy.digest(value),selection=selection(value))
        origin=worker.Guard(consumer,approved)
        history=worker.Guard(consumer,approved,allow_history=True)
        for text in (value['lease']['path'],value['read_scope']['files'][0]['path']):
            with self.subTest(path=text),self.assertRaises(consumer.ConsumerError):origin.metadata(Path(text))
            with self.subTest(path=text),self.assertRaises(consumer.ConsumerError):origin.allowed(Path(text))
            history.metadata(Path(text));history.allowed(Path(text))

    def test_readonly_provider_has_fresh_observed_module_origins(self):
        if not os.statvfs(ROOT/'skill').f_flag & os.ST_RDONLY:
            self.skipTest('Actual read-only provider mount is exercised in ARM64 Docker')
        value = actual_policy(self.root)
        value.update(capabilities=['origins'],subject=None,lease=None,read_scope=None)
        result = consumer.evaluate(value, trusted_policy_sha256=policy.digest(value), selection=selection(value))
        self.assertEqual(result['condition'], 'origins_observed')
        self.assertTrue(result['provider_imported']); self.assertFalse(result['history_read'])
        self.assertFalse(result['admission_authorized'])
        self.assertEqual(result['decision'], 'extension_required')
        names = {row['name'] for row in result['origins']['modules']}
        self.assertIn('application_owner_cleanup', names)
        self.assertTrue(all(row['path'].startswith(str(ROOT/'skill')+'/') for row in result['origins']['modules']))
        self.assertEqual(result['origins']['inventory_sha256'], value['provider']['inventory_sha256'])

    def test_readonly_passive_replay_not_selected_keeps_original_lease_bytes(self):
        if not os.statvfs(ROOT/'skill').f_flag & os.ST_RDONLY:
            self.skipTest('Actual read-only provider mount is exercised in ARM64 Docker')
        from tests.test_application_owner_legacy_dispatch import LegacyDispatchTests
        original_popen = consumer.subprocess.Popen
        case = LegacyDispatchTests('test_complete_new_method_graph_replays_without_native_actions')
        case.setUp(); self.addCleanup(case.doCleanups)
        value = actual_policy(case.root)
        value['lease']['path'] = str(case.lease)
        value['lease']['identity'] = [case.lease.stat().st_dev, case.lease.stat().st_ino]
        value['subject'] = json.loads(json.dumps(case.fixture.envelope['subject']))
        old = value['read_scope']['registry']; new = str(case.owner.root)
        for field in ('registry', 'store', 'anchor'):value['read_scope'][field] = value['read_scope'][field].replace(old, new)
        for row in value['read_scope']['files']:
            row['path'] = row['path'].replace(old,new).replace('12345678-1234-4234-8234-123456789abc',case.fixture.launch_id)
        value['read_scope']['files'].sort(key=lambda row:(row['path'],row['role']))
        value['read_scope']['directories'] = sorted(p.replace(old,new) for p in value['read_scope']['directories'])
        record_path = case.owner.root/(case.fixture.launch_id+'.json')
        value['read_scope']['registry_records'] = [{'path': str(record_path), 'sha256': hashlib.sha256(record_path.read_bytes()).hexdigest()}]
        before = case.lease.read_bytes()
        def worker_only(argv, **options):
            self.assertEqual(argv, [sys.executable, '-I', '-S', '-B',
                str(ROOT/'tools/qualification/application_owner_consumer_worker.py')])
            return original_popen(argv, **options)
        with mock.patch.object(consumer.subprocess, 'Popen', side_effect=worker_only):
            result = consumer.evaluate(value, trusted_policy_sha256=policy.digest(value), selection=selection(value),mode='replay')
        self.assertEqual(result['decision'], 'not_selected',result)
        self.assertTrue(result['history_read']); self.assertFalse(result['admission_authorized'])
        self.assertEqual(case.lease.read_bytes(), before)
