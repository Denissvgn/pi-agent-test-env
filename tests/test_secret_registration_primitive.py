"""Native syscall regressions in fresh test-owned stores with literal fake data."""
import errno
import json
import os
from pathlib import Path
import stat
import tempfile
from unittest import TestCase, mock

from tools.qualification import secret_registration_contract as model
from tools.qualification import secret_registration_primitive as primitive


FAKE = 'fixture-only-value-0123456789abcdef'
OPERATION = '12345678-1234-4234-8234-123456789abc'
CONTEXT = 'a' * 64


class RegistrationPrimitiveTests(TestCase):
    def setUp(self):
        self.sandbox = tempfile.TemporaryDirectory(prefix='registration-native-')
        self.addCleanup(self.sandbox.cleanup)
        self.root = Path(self.sandbox.name).resolve()
        self.store = self.root / 'store'
        self.store.mkdir(mode=0o700)
        self.caller = os.open(self.store, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.addCleanup(os.close, self.caller)
        info = os.fstat(self.caller)
        self.identity = (info.st_dev, info.st_ino)
        self.limits = primitive.RegistrationLimits(max_mutating_calls=256, max_owned_fds=48,
                                                    max_control_bytes=65536)

    def arguments(self):
        return dict(store_path=str(self.store), store_fd=self.caller, expected_identity=self.identity,
                    reference='APP_FAKE', operation_id=OPERATION, context_sha256=CONTEXT,
                    value=FAKE, value_contract='application_credential_1', limits=self.limits)

    def register(self, **overrides):
        return primitive.register_create_only(**{**self.arguments(), **overrides})

    def validate(self, result):
        observation = result.to_wire()
        assessment = model.validate_worker(observation, expected_operation_id=OPERATION,
            expected_context_sha256=CONTEXT, expected_value_contract='application_credential_1',
            expected_value_utf8_bytes=len(FAKE.encode()), owned_fd_tokens=result.owned_fd_tokens,
            max_mutating_calls=256, max_owned_fds=48)
        self.assertFalse(assessment.operational_authorized)
        self.assertNotIn(FAKE, json.dumps(observation))
        self.assertNotIn(str(self.store), json.dumps(observation))
        self.assertNotIn(FAKE, repr(result))
        self.assertFalse(observation['admission_authorized'])
        return observation

    def test_native_success_exact_bytes_private_single_link_and_borrowed_fd_survives(self):
        result = self.register()
        observation = self.validate(result)
        self.assertEqual(observation['outcome'], 'created')
        self.assertTrue(observation['ack_ready'])
        leaf = self.store / 'APP_FAKE'
        self.assertEqual(leaf.read_bytes(), FAKE.encode())  # Independent test owner only.
        info = leaf.lstat()
        self.assertEqual((stat.S_IMODE(info.st_mode), info.st_uid, info.st_nlink), (0o600, os.geteuid(), 1))
        self.assertEqual(set(self.store.iterdir()), {leaf})
        self.assertEqual(os.fstat(self.caller).st_ino, self.identity[1])

    def test_invalid_inputs_fail_before_native_lookup_and_do_not_use_environment(self):
        changes = [dict(reference='APP_FAKE\n'), dict(reference='../APP_FAKE'),
                   dict(operation_id=OPERATION + '\n'), dict(context_sha256='b' * 63),
                   dict(value='short'), dict(value=FAKE + '\n'), dict(value='x\ud800'),
                   dict(expected_identity=(True, 1)), dict(store_fd=True), dict(store_fd=2**40),
                   dict(store_path=str(self.store) + '/'), dict(store_path='/tmp/../not-selected')]
        for changed in changes:
            with self.subTest(changed=list(changed)), mock.patch.object(primitive, '_open',
                    side_effect=AssertionError('lookup before admission')):
                with self.assertRaises(primitive.RegistrationError): self.register(**changed)
        self.assertEqual(list(self.store.iterdir()), [])

    def test_complete_write_fd_and_control_forecasts_refuse_before_native_lookup(self):
        for limits in (primitive.RegistrationLimits(2, 48, 65536),
                       primitive.RegistrationLimits(256, 1, 65536),
                       primitive.RegistrationLimits(256, 48, 512)):
            with self.subTest(limits=limits), mock.patch.object(primitive, '_open',
                    side_effect=AssertionError('IO before complete forecast')):
                with self.assertRaises(primitive.RegistrationError): self.register(limits=limits)

    def test_existing_final_regular_symlink_and_hardlink_targets_are_preserved(self):
        original = self.root / 'retained'
        original.write_bytes(b'preserved test owner data')
        for kind in ('regular', 'symlink', 'hardlink'):
            leaf = self.store / 'APP_FAKE'
            if kind == 'regular': leaf.write_bytes(b'original leaf')
            elif kind == 'symlink': leaf.symlink_to(original)
            else: os.link(original, leaf)
            before = leaf.lstat()
            result = self.register(); observation = self.validate(result)
            self.assertEqual((observation['outcome'], observation['effects']), ('refused', 'none'))
            self.assertEqual(leaf.lstat().st_ino, before.st_ino)
            self.assertEqual(original.read_bytes(), b'preserved test owner data')
            self.assertEqual(len(list(self.store.iterdir())), 1)
            leaf.unlink()

    def test_existing_exact_temp_is_preserved_without_adoption(self):
        temp = self.store / ('.APP_FAKE.' + OPERATION + '.pending')
        temp.write_bytes(b'owned by another attempt')
        observation = self.validate(self.register())
        self.assertEqual((observation['reason'], observation['effects']), ('temp_exists', 'none'))
        self.assertEqual(temp.read_bytes(), b'owned by another attempt')
        self.assertFalse((self.store / 'APP_FAKE').exists())

    def test_store_mode_identity_and_symlink_alias_refuse_without_repair(self):
        for mode in (0o701, 0o750, 0o770):
            os.chmod(self.store, mode)
            observation = self.validate(self.register())
            self.assertFalse(observation['ack_ready'])
            self.assertEqual(observation['effects'], 'none')
            self.assertEqual(stat.S_IMODE(self.store.stat().st_mode), mode)
        os.chmod(self.store, 0o700)
        observation = self.validate(self.register(expected_identity=(self.identity[0], self.identity[1] + 1)))
        self.assertEqual(observation['effects'], 'none')
        alias = self.root / 'alias'; alias.symlink_to(self.store, target_is_directory=True)
        observation = self.validate(self.register(store_path=str(alias)))
        self.assertFalse(observation['ack_ready'])
        self.assertEqual(observation['effects'], 'none')

    def test_partial_native_writes_have_separate_positive_rows_and_exact_total(self):
        real_write = primitive._write
        def partial(fd, body): return real_write(fd, body[:3])
        with mock.patch.object(primitive, '_write', side_effect=partial):
            observation = self.validate(self.register())
        rows = [row for row in observation['calls'] if row['kind'] == 'write']
        self.assertGreater(len(rows), 1)
        self.assertEqual(sum(row['confirmed_bytes'] for row in rows), len(FAKE.encode()))
        self.assertEqual((self.store / 'APP_FAKE').read_bytes(), FAKE.encode())

    def test_zero_write_stops_once_retains_temp_and_never_publishes(self):
        with mock.patch.object(primitive, '_write', return_value=0) as writes:
            observation = self.validate(self.register())
        self.assertEqual(writes.call_count, 1)
        self.assertFalse(observation['ack_ready'])
        self.assertEqual(observation['effects'], 'temp_only')
        self.assertFalse((self.store / 'APP_FAKE').exists())
        self.assertEqual(len(list(self.store.iterdir())), 1)

    def test_transient_two_link_window_and_final_single_link_are_observed(self):
        real_unlink = primitive._unlink
        observed = []
        def inspect_window(name, **kwargs):
            final = os.stat('APP_FAKE', dir_fd=self.caller, follow_symlinks=False)
            temp = os.stat(name, dir_fd=self.caller, follow_symlinks=False)
            observed.append((final.st_ino, temp.st_ino, final.st_nlink, temp.st_nlink))
            return real_unlink(name, **kwargs)
        with mock.patch.object(primitive, '_unlink', side_effect=inspect_window):
            self.assertTrue(self.validate(self.register())['ack_ready'])
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0][0], observed[0][1])
        self.assertEqual(observed[0][2:], (2, 2))

    def test_target_race_at_link_is_no_replace_and_retains_own_temp(self):
        real_link = primitive._link
        def target_race(*args, **kwargs):
            (self.store / 'APP_FAKE').write_bytes(b'concurrent test owner target')
            return real_link(*args, **kwargs)
        with mock.patch.object(primitive, '_link', side_effect=target_race):
            observation = self.validate(self.register())
        self.assertEqual(observation['reason'], 'target_exists')
        self.assertEqual(observation['effects'], 'temp_only')
        self.assertFalse(observation['ack_ready'])
        self.assertEqual((self.store / 'APP_FAKE').read_bytes(), b'concurrent test owner target')
        self.assertEqual(len(list(self.store.iterdir())), 2)

    def test_before_and_after_effect_errors_stop_business_and_never_cleanup_paths(self):
        for function in ('_write', '_fsync', '_link', '_unlink'):
            for after in (False, True):
                with self.subTest(function=function, after=after):
                    real = getattr(primitive, function)
                    count = 0
                    def fail(*args, **kwargs):
                        nonlocal count
                        count += 1
                        if after: real(*args, **kwargs)
                        raise OSError(errno.EIO, 'synthetic untrusted ' + FAKE)
                    with mock.patch.object(primitive, function, side_effect=fail):
                        observation = self.validate(self.register(operation_id=OPERATION))
                    self.assertEqual(count, 1)
                    self.assertFalse(observation['ack_ready'])
                    unknown = next(i for i, row in enumerate(observation['calls'])
                                   if row['state'] in ('attempted', 'unknown'))
                    self.assertTrue(all(row['kind'] == 'fd_close' for row in observation['calls'][unknown + 1:]))
                    self.assertGreaterEqual(len(list(self.store.iterdir())), 1)
                    # This is independent test-owner teardown, never primitive cleanup.
                    for path in self.store.iterdir(): path.unlink()

    def test_directory_sync_failure_retains_leaf_but_prevents_readiness(self):
        real_fsync = primitive._fsync
        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode): raise OSError(errno.EIO, 'test directory sync')
            return real_fsync(fd)
        with mock.patch.object(primitive, '_fsync', side_effect=fail_directory):
            observation = self.validate(self.register())
        self.assertEqual(observation['effects'], 'leaf_only')
        self.assertEqual(observation['file_persistence'], 'confirmed')
        self.assertEqual(observation['directory_persistence'], 'unknown')
        self.assertFalse(observation['ack_ready'])
        self.assertEqual((self.store / 'APP_FAKE').read_bytes(), FAKE.encode())

    def test_ambiguous_close_spends_each_owned_token_once_and_closes_others(self):
        real_close = primitive._close
        for target in ('value', 'store', 'ancestor'):
            calls = []; injected = False
            def ambiguous(fd):
                nonlocal injected
                info = os.fstat(fd)
                is_store = (info.st_dev, info.st_ino) == self.identity
                matches = (target == 'value' and stat.S_ISREG(info.st_mode)
                           or target == 'store' and is_store
                           or target == 'ancestor' and stat.S_ISDIR(info.st_mode) and not is_store)
                calls.append(fd)
                real_close(fd)
                if matches and not injected:
                    injected = True
                    raise OSError(errno.EINTR, 'synthetic close after native return')
            with mock.patch.object(primitive, '_close', side_effect=ambiguous):
                result = self.register()
                observation = self.validate(result)
            self.assertTrue(injected)
            self.assertEqual(len(calls), len(set(calls)))
            self.assertEqual(len(calls), len(result.owned_fd_tokens))
            self.assertEqual(observation['owned_fd_closure'], 'unknown')
            self.assertFalse(observation['ack_ready'])
            self.assertEqual(os.fstat(self.caller).st_ino, self.identity[1])
            (self.store / 'APP_FAKE').unlink()

    def test_replaced_named_store_during_effects_cannot_ack_or_reopen(self):
        real_write = primitive._write
        detached = self.root / 'detached'
        def move_store(fd, body):
            result = real_write(fd, body)
            self.store.rename(detached)
            self.store.mkdir(mode=0o700)
            return result
        with mock.patch.object(primitive, '_write', side_effect=move_store):
            observation = self.validate(self.register())
        self.assertFalse(observation['ack_ready'])
        self.assertEqual(list(self.store.iterdir()), [])
        self.assertEqual(len(list(detached.iterdir())), 1)

    def test_no_payload_readback_discovery_chmod_or_legacy_writer(self):
        with (mock.patch('os.read', side_effect=AssertionError('primitive payload readback')),
              mock.patch('os.listdir', side_effect=AssertionError('primitive discovery')),
              mock.patch('os.scandir', side_effect=AssertionError('primitive discovery')),
              mock.patch('os.chmod', side_effect=AssertionError('primitive permission repair'))):
            result = self.register()
        self.assertTrue(self.validate(result)['ack_ready'])

    def test_result_is_immutable_and_forecast_covers_actual_ledger_and_control(self):
        result = self.register(); observation = self.validate(result)
        self.assertLessEqual(len(observation['calls']), result.forecast.max_calls)
        self.assertLessEqual(len(result.owned_fd_tokens), result.forecast.max_owned_fds)
        self.assertLessEqual(len(json.dumps(observation).encode()), result.forecast.control_bytes)
        observation['ack_ready'] = False
        self.assertTrue(result.to_wire()['ack_ready'])
        with self.assertRaises((TypeError, AttributeError)): result.forecast.max_calls = 0

    def test_changed_temp_before_link_is_refused_before_publication(self):
        real_verify = primitive._Operation.verify_chain
        real_link = primitive._link
        changed = False
        retained = self.root / 'retained'
        retained.write_bytes(b'independent owner retained data')
        def replace_at_boundary(operation):
            nonlocal changed
            calls = operation.report['calls']
            if not changed and calls and calls[-1]['kind'] == 'file_fsync' and calls[-1]['state'] == 'confirmed':
                changed = True
                temp = self.store / operation.temp
                temp.unlink(); temp.symlink_to(retained)
            return real_verify(operation)
        with (mock.patch.object(primitive._Operation, 'verify_chain', replace_at_boundary),
              mock.patch.object(primitive, '_link', wraps=real_link) as links):
            observation = self.validate(self.register())
        self.assertTrue(changed)
        self.assertEqual(links.call_count, 0)
        self.assertFalse(observation['ack_ready'])
        self.assertFalse((self.store / 'APP_FAKE').exists())
        self.assertEqual(retained.read_bytes(), b'independent owner retained data')

    def test_create_error_before_or_after_native_effect_is_never_adopted(self):
        for after in (False, True):
            real_open = primitive._open
            def fail_create(*args, **kwargs):
                if args[1] & os.O_CREAT:
                    if after:
                        created = real_open(*args, **kwargs)
                        primitive.native.close(created)  # Fault owner retains unknown return boundary.
                    raise OSError(errno.EIO, 'synthetic create failure')
                return real_open(*args, **kwargs)
            with mock.patch.object(primitive, '_open', side_effect=fail_create):
                observation = self.validate(self.register())
            self.assertEqual(observation['effects'], 'unknown')
            self.assertEqual(observation['outcome'], 'uncertain')
            self.assertFalse(observation['ack_ready'])
            self.assertEqual(len(list(self.store.iterdir())), int(after))
            for name in self.store.iterdir(): name.unlink()  # Independent test-owner teardown.

    def test_store_replacement_at_every_business_boundary_never_reopens_or_acks(self):
        for index, boundary in enumerate(('temp_create', 'write', 'file_fsync', 'link',
                                           'temp_unlink', 'directory_fsync')):
            store = self.root / ('slot_' + str(index)); store.mkdir(mode=0o700)
            borrowed = os.open(store, os.O_RDONLY | os.O_DIRECTORY)
            info = os.fstat(borrowed)
            detached = self.root / ('detached_' + str(index))
            real_verify = primitive._Operation.verify_chain
            changed = False
            def replace_at_boundary(operation):
                nonlocal changed
                calls = operation.report['calls']
                if not changed and calls and calls[-1]['kind'] == boundary and calls[-1]['state'] == 'confirmed':
                    changed = True
                    store.rename(detached); store.mkdir(mode=0o700)
                return real_verify(operation)
            try:
                with mock.patch.object(primitive._Operation, 'verify_chain', replace_at_boundary):
                    observation = self.validate(self.register(store_path=str(store), store_fd=borrowed,
                                                              expected_identity=(info.st_dev, info.st_ino)))
                self.assertTrue(changed, boundary)
                self.assertFalse(observation['ack_ready'])
                self.assertEqual(list(store.iterdir()), [])
                self.assertGreaterEqual(len(list(detached.iterdir())), 1)
                self.assertEqual(os.fstat(borrowed).st_ino, info.st_ino)
            finally:
                os.close(borrowed)

    def test_reappearing_temp_after_planned_unlink_prevents_readiness(self):
        real_unlink = primitive._unlink
        def reappear(name, **kwargs):
            real_unlink(name, **kwargs)
            (self.store / name).write_bytes(b'other test-owner file')
        with mock.patch.object(primitive, '_unlink', side_effect=reappear):
            observation = self.validate(self.register())
        self.assertFalse(observation['ack_ready'])
        self.assertEqual(len(list(self.store.iterdir())), 2)

    def test_post_sync_identity_loss_does_not_keep_a_complete_namespace_claim(self):
        real_sync = primitive._fsync
        def change_after_sync(fd):
            real_sync(fd)
            if stat.S_ISREG(os.fstat(fd).st_mode):
                temp = self.store / ('.APP_FAKE.' + OPERATION + '.pending')
                temp.rename(self.store / 'changed_by_test_owner')
        with mock.patch.object(primitive, '_fsync', side_effect=change_after_sync):
            observation = self.validate(self.register())
        self.assertFalse(observation['ack_ready'])
        self.assertFalse(observation['trace_complete'])
        self.assertEqual(observation['effects'], 'unknown')

    def test_reentrant_operation_is_refused_before_inner_native_lookup(self):
        real_write = primitive._write
        rejected = []
        def reenter(fd, body):
            with self.assertRaises(primitive.RegistrationError) as caught:
                self.register(reference='OTHER_FAKE')
            rejected.append(str(caught.exception))
            return real_write(fd, body)
        with mock.patch.object(primitive, '_write', side_effect=reenter):
            self.assertTrue(self.validate(self.register())['ack_ready'])
        self.assertEqual(rejected, ['operation_busy'])
        self.assertFalse((self.store / 'OTHER_FAKE').exists())

    def test_additional_python_threads_are_unsupported_before_native_lookup(self):
        with (mock.patch.object(primitive.threading, 'active_count', return_value=2),
              mock.patch.object(primitive, '_open', side_effect=AssertionError('concurrent native lookup'))):
            with self.assertRaises(primitive.RegistrationError) as caught: self.register()
        self.assertEqual(str(caught.exception), 'unsupported_runtime')
        self.assertEqual(list(self.store.iterdir()), [])

    def test_generic_short_unicode_and_application_utf8_have_distinct_native_contracts(self):
        for value, selected in [('λ', 'normalized_secret_1'), ('é' * 16, 'application_credential_1')]:
            result = self.register(value=value, value_contract=selected)
            observation = result.to_wire()
            assessment = model.validate_worker(observation, expected_operation_id=OPERATION,
                expected_context_sha256=CONTEXT, expected_value_contract=selected,
                expected_value_utf8_bytes=len(value.encode()), owned_fd_tokens=result.owned_fd_tokens,
                max_mutating_calls=256, max_owned_fds=48)
            self.assertTrue(assessment.ack_ready)
            self.assertFalse(assessment.operational_authorized)
            self.assertEqual((self.store / 'APP_FAKE').read_bytes(), value.encode())
            (self.store / 'APP_FAKE').unlink()

    def test_test_owner_independently_observes_actual_acquisitions_and_close_conservation(self):
        # Expected roles come from independent native-boundary observations,
        # never from the worker's reported owned_fd_tokens or close ledger.
        for ambiguous_token in (None, 'value', 'store_duplicate', 'ancestor:0'):
            acquired = {}; actual_closes = []; ancestor_count = 0
            real_open, real_dup, real_close = primitive._open, os.dup, primitive._close
            def duplicate(fd):
                self.assertEqual(fd, self.caller)
                result = real_dup(fd)
                acquired[result] = 'store_duplicate'
                return result
            def opened(path, flags, *args, **kwargs):
                nonlocal ancestor_count
                fd = real_open(path, flags, *args, **kwargs)
                self.assertNotIn(fd, acquired)
                if flags & os.O_CREAT:
                    acquired[fd] = 'value'
                else:
                    acquired[fd] = 'ancestor:' + str(ancestor_count)
                    ancestor_count += 1
                return fd
            def closed(fd):
                self.assertNotEqual(fd, self.caller)
                self.assertIn(fd, acquired)
                self.assertNotIn(fd, actual_closes)
                actual_closes.append(fd)
                real_close(fd)
                if acquired[fd] == ambiguous_token:
                    raise OSError(errno.EINTR, 'test-owner lost native close return')
            with (mock.patch.object(primitive, '_open', side_effect=opened),
                  mock.patch.object(primitive.os, 'dup', side_effect=duplicate),
                  mock.patch.object(primitive, '_close', side_effect=closed)):
                result = self.register()
            independently_owned = tuple(acquired.values())
            self.assertEqual(set(actual_closes), set(acquired))
            self.assertEqual(set(result.owned_fd_tokens), set(independently_owned))
            self.assertEqual(len(result.owned_fd_tokens), len(independently_owned))
            observation = result.to_wire()
            rows = [row for row in observation['calls'] if row['kind'] == 'fd_close']
            self.assertEqual([row['fd_token'] for row in rows], [acquired[fd] for fd in actual_closes])
            assessment = model.validate_worker(observation, expected_operation_id=OPERATION,
                expected_context_sha256=CONTEXT, expected_value_contract='application_credential_1',
                expected_value_utf8_bytes=len(FAKE.encode()), owned_fd_tokens=independently_owned,
                max_mutating_calls=256, max_owned_fds=48)
            self.assertEqual(assessment.ack_ready, ambiguous_token is None)
            for fd in acquired:
                with self.assertRaises(OSError) as caught: os.fstat(fd)
                self.assertEqual(caught.exception.errno, errno.EBADF)
            # This independent release observation never rewrites a lost return.
            unknown = [row['fd_token'] for row in rows if row['state'] == 'unknown']
            self.assertEqual(unknown, [] if ambiguous_token is None else [ambiguous_token])
            self.assertEqual(os.fstat(self.caller).st_ino, self.identity[1])
            (self.store / 'APP_FAKE').unlink()  # Independent test-owner teardown.
