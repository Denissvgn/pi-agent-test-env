"""Normal custody fault cuts using temporary synthetic ownership only.

No Docker, model, application or original-history operation runs. The fixture
models a newly created schema-3 helper, not an upgrade of retained history.
"""
import contextlib
import errno
import os
import stat
import threading
import unittest
from unittest import mock

import test_application_owner_cleanup as fixtures


def capture_stage(body):
    kind = body.get('document_type')
    witnesses = {
        'application_owned_snapshot': 'snapshot-witness',
        'owned_process_invocation': 'launcher-witness',
        'owned_container_identity': 'guard-witness',
        'owned_process_terminal': 'terminal-witness',
        'application_owner_cleanup_receipt': 'final-receipt',
    }
    if kind != 'application_helper_custody':
        return witnesses.get(kind)
    events = body['events']
    if events == ['intent']:
        return 'snapshot-state' if body['snapshot'] is not None else 'initial-custody'
    if events == ['intent', 'launch_attempted']:
        if body['guard'] is not None:
            return 'guard-state'
        return 'launcher-state' if body['launcher'] is not None else 'attempt-state'
    return {
        'container_bound': 'bound-state',
        'bootstrap_sent': 'bootstrap-state',
        'helper_cleanup': 'cleanup-state',
    }[events[-1]]


CAPTURE_STAGES = (
    'initial-custody', 'snapshot-witness', 'snapshot-state', 'attempt-state',
    'launcher-witness', 'launcher-state', 'guard-witness', 'guard-state',
    'bound-state', 'bootstrap-state', 'terminal-witness', 'cleanup-state',
    'final-receipt',
)


class NormalCustodyFaultTests(unittest.TestCase):
    @contextlib.contextmanager
    def expect_fault(self, fault_type):
        if fault_type is KeyboardInterrupt:
            with self.assertRaises(KeyboardInterrupt):
                yield
            return
        self.assertIs(fault_type, OSError)
        with self.assertRaises((OSError, fixtures.registry.RegistryError)) as caught:
            yield
        error = caught.exception
        if isinstance(error, OSError):
            self.assertEqual(error.errno, errno.EIO)
        else:
            # Public scoped APIs translate OS errors into the closed registry
            # diagnostic while unscoped capture hooks preserve the OS error.
            self.assertEqual(fixtures.diagnostics.diagnostic(error)['os_error'], 'io_error')

    @contextlib.contextmanager
    def fixture(self):
        fixture = fixtures.OwnerCleanupTests()
        try:
            fixture.setUp()
            yield fixture
        finally:
            fixture.doCleanups()

    def assert_outcome(self, fixture, metadata, descriptors, receipts, *, accepted=False):
        self.assertEqual(fixture.metadata(), metadata)
        self.assertEqual(fixture.calls, [])
        with fixture.held():
            try:
                actual = fixture.api.validate_accepted(fixture.owner, fixture.helper)
            except fixtures.registry.RegistryError:
                actual = False
            self.assertIs(actual, accepted)
            if accepted:
                self.assertEqual(fixture.owner.validate_history(fixture.owner.load()), [])
            else:
                with self.assertRaises(fixtures.registry.RegistryError):
                    fixture.owner.validate_history(fixture.owner.load())
        for receipt in receipts:
            self.assertIsNone(receipt.fd)
            self.assertIsNone(receipt.parent)
        for fd, signature in descriptors:
            try:
                info = os.fstat(fd)
            except OSError as error:
                self.assertEqual(error.errno, errno.EBADF)
            else:
                # Another test's asynchronous cleanup may reuse a closed FD.
                # A descriptor still referring to this captured inode leaks.
                self.assertNotEqual((info.st_dev, info.st_ino), signature)

    @contextlib.contextmanager
    def track_receipts(self):
        receipts = []
        descriptors = []
        owner_thread = threading.get_ident()
        original = fixtures.maintenance._Receipt.__init__
        original_open, original_dup = os.open, os.dup
        def initialize(receipt, *args, **kwargs):
            original(receipt, *args, **kwargs)
            receipts.append(receipt)
        def remember(fd):
            if threading.get_ident() == owner_thread:
                info = os.fstat(fd)
                descriptors.append((fd, (info.st_dev, info.st_ino)))
            return fd
        def opened(*args, **kwargs):
            return remember(original_open(*args, **kwargs))
        def duplicated(fd):
            return remember(original_dup(fd))
        with mock.patch.object(fixtures.maintenance._Receipt, '__init__', new=initialize), \
             mock.patch.object(os, 'open', new=opened), \
             mock.patch.object(os, 'dup', new=duplicated):
            yield receipts, descriptors

    def publication_cuts(self, fault):
        for stage in CAPTURE_STAGES:
            for moment in ('before', 'after'):
                with self.subTest(stage=stage, moment=moment), self.fixture() as fixture:
                    metadata = fixture.metadata()
                    original = fixtures.maintenance._Receipt.publish
                    hits = []
                    def publish(receipt, body):
                        selected = capture_stage(body) == stage
                        if selected:
                            hits.append(stage)
                            if moment == 'before':
                                raise fault()
                        result = original(receipt, body)
                        if selected and moment == 'after':
                            raise fault()
                        return result
                    with self.track_receipts() as (receipts, descriptors), fixture.held(), \
                         mock.patch.object(fixtures.maintenance._Receipt, 'publish', new=publish):
                        with self.expect_fault(type(fault())):
                            fixture.runtime_cleanup()
                            fixture.owner.close()
                    self.assertEqual(hits, [stage])
                    self.assert_outcome(fixture, metadata, descriptors, receipts)

    def test_persistence_failure_at_each_capture_publication_is_not_proof(self):
        self.publication_cuts(lambda: OSError(errno.EIO, 'synthetic persistence fault'))

    def test_interruption_at_each_capture_publication_is_not_proof(self):
        self.publication_cuts(KeyboardInterrupt)

    def test_partial_write_boundaries_close_descriptors_and_block_acceptance(self):
        for stage in CAPTURE_STAGES:
            for boundary in ('file-fsync', 'atomic-replace', 'directory-fsync'):
                with self.subTest(stage=stage, boundary=boundary), self.fixture() as fixture:
                    metadata = fixture.metadata()
                    original_publish = fixtures.maintenance._Receipt.publish
                    original_fsync, original_replace = os.fsync, os.replace
                    active = [None]
                    hits = []
                    def publish(receipt, body):
                        active[0] = capture_stage(body)
                        try:
                            return original_publish(receipt, body)
                        finally:
                            active[0] = None
                    def fsync(fd):
                        selected = ('file-fsync' if stat.S_ISREG(os.fstat(fd).st_mode)
                                    else 'directory-fsync')
                        if active[0] == stage and selected == boundary:
                            hits.append(boundary)
                            raise OSError(errno.EIO, 'synthetic sync fault')
                        return original_fsync(fd)
                    def replace(*args, **kwargs):
                        if active[0] == stage and boundary == 'atomic-replace':
                            hits.append(boundary)
                            raise OSError(errno.EIO, 'synthetic replace fault')
                        return original_replace(*args, **kwargs)
                    with self.track_receipts() as (receipts, descriptors), fixture.held(), \
                         mock.patch.object(fixtures.maintenance._Receipt, 'publish', new=publish), \
                         mock.patch.object(os, 'fsync', side_effect=fsync), \
                         mock.patch.object(os, 'replace', side_effect=replace):
                        with self.expect_fault(OSError):
                            fixture.runtime_cleanup()
                            fixture.owner.close()
                    self.assertEqual(hits, [boundary])
                    self.assert_outcome(fixture, metadata, descriptors, receipts)

    def test_selection_and_index_cuts_follow_the_durable_commit_boundary(self):
        for target in ('_mark_selected', '_publish_index'):
            for moment in ('before', 'after'):
                for fault in (lambda: OSError(errno.EIO, 'synthetic publication fault'), KeyboardInterrupt):
                    with self.subTest(target=target, moment=moment, fault=fault), self.fixture() as fixture:
                        metadata = fixture.metadata()
                        original = getattr(fixture.api, target)
                        hits = []
                        def cut(*args, **kwargs):
                            hits.append(target)
                            if moment == 'before':
                                raise fault()
                            original(*args, **kwargs)
                            raise fault()
                        with self.track_receipts() as (receipts, descriptors), fixture.held(), \
                             mock.patch.object(fixture.api, target, side_effect=cut):
                            with self.expect_fault(type(fault())):
                                fixture.runtime_cleanup()
                                fixture.owner.close()
                        self.assertEqual(hits, [target])
                        # A lost response after the complete durable index does
                        # not invalidate an independently valid committed graph.
                        self.assert_outcome(fixture, metadata, descriptors, receipts,
                                            accepted=target == '_publish_index' and moment == 'after')

    def test_selection_and_index_sync_failure_never_allows_fallback_after_loss(self):
        for target in ('_mark_selected', '_publish_index'):
            for boundary in ('file-fsync', 'directory-fsync'):
                with self.subTest(target=target, boundary=boundary), self.fixture() as fixture:
                    metadata = fixture.metadata()
                    original = getattr(fixture.api, target)
                    original_fsync = os.fsync
                    active, file_synced, hits = [False], [False], []
                    def publish(*args, **kwargs):
                        active[0] = True
                        try:
                            return original(*args, **kwargs)
                        finally:
                            active[0] = False
                    def fsync(fd):
                        regular = stat.S_ISREG(os.fstat(fd).st_mode)
                        if active[0] and ((boundary == 'file-fsync' and regular)
                                or (boundary == 'directory-fsync' and not regular and file_synced[0])):
                            hits.append(boundary)
                            raise OSError(errno.EIO, 'synthetic index sync fault')
                        result = original_fsync(fd)
                        if active[0] and regular:
                            file_synced[0] = True
                        return result
                    with self.track_receipts() as (receipts, descriptors), fixture.held(), \
                         mock.patch.object(fixture.api, target, side_effect=publish), \
                         mock.patch.object(os, 'fsync', side_effect=fsync):
                        with self.expect_fault(OSError):
                            fixture.runtime_cleanup()
                            fixture.owner.close()
                    self.assertEqual(hits, [boundary])
                    # A surviving complete graph may validate, while the failed
                    # call cannot claim confirmed persistence. Losing its index
                    # must still block under the original schema-3 owner marker.
                    self.assert_outcome(fixture, metadata, descriptors, receipts,
                                        accepted=target == '_publish_index')
                    if target == '_publish_index':
                        fixture.api._index(fixture.owner, fixture.helper).unlink()
                        self.assert_outcome(fixture, metadata, descriptors, receipts)

    def test_normal_capture_keeps_original_invocation_and_uses_normal_method(self):
        with self.fixture() as fixture:
            metadata = fixture.metadata()
            import application_owner_legacy_protocol as legacy
            with self.track_receipts() as (receipts, descriptors), fixture.held(), \
                 mock.patch.object(legacy, 'prepare', side_effect=AssertionError('No legacy shortcut')):
                helper = fixture.runtime_cleanup()
                fixture.owner.close()
            custody, unused = fixture.api.Reader().read(fixture.api._custody_path(fixture.owner, fixture.helper), private=True)
            invocation = fixture.api.Reader().reference(custody['launcher'])
            terminal = fixture.api.Reader().reference(custody['terminal'])
            index, unused = fixture.api.Reader().read(fixture.api._index(fixture.owner, fixture.helper), private=True)
            report = fixture.api.Reader().reference(index['receipt'])
            self.assertEqual(report['method'], 'runtime_finalization')
            self.assertEqual(invocation['argv'], fixture.launch_arguments())
            self.assertEqual(invocation['cwd'], os.getcwd())
            self.assertEqual(terminal['pid'], helper.process.pid)
            self.assertEqual(terminal['actual_exit'], helper.process.returncode)
            self.assert_outcome(fixture, metadata, descriptors, receipts, accepted=True)


if __name__ == '__main__':
    unittest.main()
