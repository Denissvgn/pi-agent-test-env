"""Real temporary leases/files; all Docker and model effects are forbidden/mocked."""
import argparse
import contextlib
import errno
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skill/scripts'))
import ownership_registry as registry
import registry_maintenance as maintenance
import registry_diagnostics as diagnostics
import resources
import pi_lab as lab
import test_registry_reconciliation_diagnostics as fixtures


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name).resolve();self.lease=self.root/'lease'
        self.docker=fixtures.DockerFixture()
        self.external=fixtures.mocked_external(self.docker);self.external.__enter__()
        self.addCleanup(self.external.__exit__,None,None,None)
        self.owner=fixtures.leave_pending(self.lease,self.root/'run')
        self.docker.calls.clear()

    def call(self, op='registry-inspect', output=None, lease=None):
        args=[op,'--lock-file',str(lease or self.lease)]
        if op=='registry-recover':args+=['--output-dir',str(output or self.root/'recovery')]
        stream=io.StringIO()
        with contextlib.redirect_stdout(stream):code=lab.main(args)
        value=json.loads(stream.getvalue());self.assertEqual(code,value['exit_code'])
        return value

    def snapshot(self):
        paths=[self.lease,*self.owner.root.iterdir()]
        return {p.name:(p.read_bytes(),p.stat().st_ino,p.stat().st_mode) for p in paths}

    def test_offline_inspection_preserves_every_record_and_lock(self):
        before=self.snapshot();value=self.call()
        self.assertEqual(value['status'],'OBSERVED')
        self.assertFalse(value['admission_authorized'])
        self.assertEqual(value['before']['statuses'],{'absent':3})
        self.assertIn('record_write_and_fsync',value['untested'])
        self.assertEqual(self.snapshot(),before);self.assertEqual(self.docker.calls,[])
        self.assertEqual(value['lease']['inode'],self.lease.stat().st_ino)

    def test_inspection_pending_helper_denies_without_quarantine_or_purge(self):
        row=self.owner.load()[0];row['application_helper']=True;self.owner.write(row)
        before=self.snapshot();value=self.call()
        self.assertEqual(value['status'],'BLOCKED')
        self.assertEqual(value['infrastructure']['registry_diagnostic']['condition'],'owned_application_cleanup_required')
        self.assertEqual(self.snapshot(),before);self.assertEqual(self.docker.calls,[])

    def test_recovery_preserves_original_failure_and_only_reconciles_owned_records(self):
        original=self.root/'run/result.json';original.write_text('{"sealed":true,"status":"BLOCKED"}')
        before=original.read_bytes();lock=self.lease.read_bytes();inode=self.lease.stat().st_ino
        value=self.call('registry-recover')
        self.assertEqual(value['status'],'RECONCILED')
        self.assertFalse(value['admission_authorized'])
        self.assertEqual(value['after']['statuses'],{'released':3})
        self.assertEqual(len(value['transitions']),3)
        self.assertTrue(all(row[1:]==['absent','released'] for row in value['transitions']))
        self.assertEqual(value['receipt_persistence'],'confirmed')
        saved=json.loads((self.root/'recovery/recovery.json').read_text())
        self.assertEqual(saved['invocation_id'],value['invocation_id'])
        self.assertEqual(saved['reconciliation'],'completed')
        self.assertEqual(original.read_bytes(),before)
        self.assertEqual((self.lease.read_bytes(),self.lease.stat().st_ino),(lock,inode))
        self.assertEqual(len(self.docker.calls),4)
        self.assertFalse(any(a[:2]==['docker','run'] for a in self.docker.calls))
        self.assertEqual((self.root/'recovery').stat().st_mode&0o777,0o700)
        self.assertEqual((self.root/'recovery/recovery.json').stat().st_mode&0o777,0o600)

    def test_missing_unsafe_or_busy_lease_never_creates_an_alternative(self):
        missing=self.root/'missing'
        value=self.call(lease=missing)
        self.assertEqual(value['infrastructure']['reason'],'admission-lock-unavailable')
        self.assertFalse(missing.exists());self.assertFalse(Path(str(missing)+'.registry').exists())
        link=self.root/'alias';link.symlink_to(self.lease)
        self.assertEqual(self.call(lease=link)['infrastructure']['reason'],'admission-lock-insecure')
        with resources.admission_lock(self.lease):
            before=self.lease.read_bytes()
            self.assertEqual(self.call()['infrastructure']['reason'],'host-admission-busy')
            self.assertEqual(self.lease.read_bytes(),before)

    def test_receipt_must_be_new_and_outside_retained_execution_paths(self):
        existing=self.root/'existing';existing.mkdir()
        for output in (existing,self.owner.root/'receipt',self.root/'run/receipt'):
            with self.subTest(output=output):
                before=self.snapshot();value=self.call('registry-recover',output)
                self.assertEqual(value['status'],'BLOCKED')
                self.assertEqual(value['infrastructure']['registry_diagnostic']['phase'],'recovery_receipt')
                self.assertEqual(self.snapshot(),before);self.assertEqual(self.docker.calls,[])
        target=self.root/'target';target.mkdir();alias=self.root/'receipt-alias';alias.symlink_to(target)
        self.assertEqual(self.call('registry-recover',alias)['status'],'BLOCKED')
        self.assertEqual(list(target.iterdir()),[])

    def test_failed_initial_receipt_persistence_prevents_all_recovery_effects(self):
        before=self.snapshot()
        with mock.patch.object(maintenance,'_publish',side_effect=OSError(errno.EIO,'private-canary')):
            value=self.call('registry-recover')
        self.assertEqual(value['status'],'BLOCKED')
        self.assertEqual(value['receipt_persistence'],'unconfirmed')
        self.assertEqual(value['infrastructure']['registry_diagnostic']['phase'],'recovery_receipt')
        self.assertEqual(self.snapshot(),before);self.assertEqual(self.docker.calls,[])
        self.assertNotIn('private-canary',json.dumps(value))

    def test_secondary_receipt_failure_cannot_replace_primary_denial(self):
        self.docker.fault='daemon';real=maintenance._publish;calls=[]
        def publish(folder,value):
            calls.append(True)
            if len(calls)==2:raise OSError(errno.ENOSPC,'private-receipt-canary')
            return real(folder,value)
        with mock.patch.object(maintenance,'_publish',side_effect=publish):value=self.call('registry-recover')
        self.assertEqual(value['infrastructure']['registry_diagnostic']['condition'],'daemon_changed')
        self.assertEqual(value['receipt_failure']['registry_diagnostic']['phase'],'recovery_receipt')
        self.assertEqual(value['reconciliation'],'attempted')
        self.assertEqual(value['receipt_persistence'],'unconfirmed')
        self.assertNotIn('private-receipt-canary',json.dumps(value))

    def test_interrupted_partial_release_has_separate_receipt_and_no_automatic_retry(self):
        real=registry.Registry.write
        def interrupted(owner,row):
            real(owner,row)
            if row['status']=='released':raise KeyboardInterrupt
        with mock.patch.object(registry.Registry,'write',interrupted):value=self.call('registry-recover')
        self.assertEqual(value['status'],'INTERRUPTED');self.assertEqual(value['exit_code'],130)
        self.assertEqual(value['after']['statuses'],{'absent':2,'released':1})
        self.assertEqual(len(value['transitions']),1)
        saved=json.loads((self.root/'recovery/recovery.json').read_text())
        self.assertEqual(saved['status'],'INTERRUPTED')
        # A fresh explicit operation is distinct and preserves the earlier receipt.
        before=(self.root/'recovery/recovery.json').read_bytes()
        later=self.call('registry-recover',self.root/'second-recovery')
        self.assertEqual(later['status'],'RECONCILED')
        self.assertNotEqual(later['invocation_id'],value['invocation_id'])
        self.assertEqual((self.root/'recovery/recovery.json').read_bytes(),before)

    def test_read_only_constructor_never_creates_missing_registry(self):
        path=self.root/'missing-registry'
        with self.assertRaises(registry.RegistryError) as caught:registry.Registry(path,create=False)
        self.assertFalse(path.exists())
        context=diagnostics.diagnostic(caught.exception)
        self.assertEqual((context['phase'],context['os_error']),('registry_initialization','missing'))

    def test_lock_inode_replacement_while_waiting_is_rejected(self):
        def replaced(fd,wait):
            resources.fcntl.flock(fd,resources.fcntl.LOCK_EX)
            self.lease.rename(self.root/'old-lease')
            self.lease.write_text('replacement');self.lease.chmod(0o600)
        with mock.patch.object(resources,'_queued_flock',side_effect=replaced):
            with self.assertRaises(resources.AdmissionError):
                with maintenance.existing_lease(self.lease,1):self.fail('replacement admitted')
        self.assertEqual(self.lease.read_text(),'replacement')

    def test_receipt_directory_replacement_cannot_overwrite_foreign_evidence(self):
        output=self.root/'recovery';outside=self.root/'outside';outside.mkdir(mode=0o700)
        victim=outside/'recovery.json';victim.write_bytes(b'foreign historical evidence')
        real=maintenance._publish;calls=[]
        def replaced(receipt,report):
            calls.append(True)
            if len(calls)==2:
                output.rename(self.root/'original-recovery')
                output.symlink_to(outside)
            return real(receipt,report)
        with mock.patch.object(maintenance,'_publish',side_effect=replaced):value=self.call('registry-recover')
        self.assertEqual(victim.read_bytes(),b'foreign historical evidence')
        self.assertEqual(value['status'],'BLOCKED')
        self.assertEqual(value['receipt_persistence'],'unconfirmed')

    def test_receipt_parent_replacement_cannot_redirect_publication(self):
        parent=self.root/'receipts';parent.mkdir(mode=0o700);output=parent/'attempt'
        outside=self.root/'outside';(outside/'attempt').mkdir(parents=True,mode=0o700)
        victim=outside/'attempt/recovery.json';victim.write_bytes(b'foreign historical evidence')
        real=maintenance._publish;calls=[]
        def replaced(receipt,report):
            calls.append(True)
            if len(calls)==2:
                parent.rename(self.root/'original-receipts');parent.symlink_to(outside)
            return real(receipt,report)
        with mock.patch.object(maintenance,'_publish',side_effect=replaced):value=self.call('registry-recover',output)
        self.assertEqual(victim.read_bytes(),b'foreign historical evidence')
        self.assertEqual(value['status'],'BLOCKED')

    def test_receipt_swap_during_temporary_creation_stays_on_owned_directory(self):
        output=self.root/'recovery';outside=self.root/'outside';outside.mkdir(mode=0o700)
        victim=outside/'recovery.json';victim.write_bytes(b'foreign historical evidence')
        real=os.open;creates=[]
        def swap(path,*args,**kwargs):
            if Path(path).name.startswith('.recovery.json-'):
                creates.append(True)
                if len(creates)==2:
                    output.rename(self.root/'original-recovery');output.symlink_to(outside)
            return real(path,*args,**kwargs)
        with mock.patch.object(os,'open',side_effect=swap):value=self.call('registry-recover')
        self.assertEqual(victim.read_bytes(),b'foreign historical evidence')
        self.assertEqual(value['status'],'BLOCKED')

    def test_interrupt_after_reconciliation_retains_terminal_receipt_under_lease(self):
        real_reconcile=registry.Registry.reconcile;real_load=registry.Registry.load
        completed=[];interrupted=[];publications=[];real_publish=maintenance._publish
        def reconcile(owner):
            result=real_reconcile(owner);completed.append(True);return result
        def load(owner,*args,**kwargs):
            if completed and not interrupted:
                interrupted.append(True);raise KeyboardInterrupt
            return real_load(owner,*args,**kwargs)
        def publish(receipt,report):
            publications.append(report['status'])
            fd=os.open(self.lease,os.O_RDONLY)
            try:
                with self.assertRaises(BlockingIOError):
                    resources.fcntl.flock(fd,resources.fcntl.LOCK_EX|resources.fcntl.LOCK_NB)
            finally:os.close(fd)
            return real_publish(receipt,report)
        with mock.patch.object(registry.Registry,'reconcile',reconcile),mock.patch.object(registry.Registry,'load',load), \
             mock.patch.object(maintenance,'_publish',side_effect=publish):
            value=self.call('registry-recover')
        self.assertEqual(value['status'],'INTERRUPTED')
        self.assertEqual(value['exit_code'],130)
        self.assertEqual(publications,['RUNNING','INTERRUPTED'])
        saved=json.loads((self.root/'recovery/recovery.json').read_text())
        self.assertEqual(saved['status'],'INTERRUPTED')
        self.assertEqual(saved['reconciliation'],'completed')

    def test_existing_lease_does_not_reclassify_body_filesystem_error(self):
        error=PermissionError(errno.EACCES,'private body path')
        with self.assertRaises(PermissionError) as caught:
            with maintenance.existing_lease(self.lease):raise error
        self.assertIs(caught.exception,error)

    def test_existing_lease_preserves_outer_queue_callback_error(self):
        error=PermissionError(errno.EACCES,'private outer callback')
        with mock.patch.object(resources,'_queued_flock',side_effect=error):
            with self.assertRaises(PermissionError) as caught:
                with maintenance.existing_lease(self.lease,1):self.fail('callback failure admitted')
        self.assertIs(caught.exception,error)
        with maintenance.existing_lease(self.lease):pass

    def test_initial_receipt_swap_blocks_before_reconciliation(self):
        output=self.root/'recovery';outside=self.root/'outside';outside.mkdir(mode=0o700)
        victim=outside/'recovery.json';victim.write_bytes(b'foreign historical evidence')
        before=self.snapshot();real=os.open;swapped=[]
        def swap(path,*args,**kwargs):
            if Path(path).name.startswith('.recovery.json-') and not swapped:
                swapped.append(True)
                output.rename(self.root/'original-recovery');output.symlink_to(outside)
            return real(path,*args,**kwargs)
        with mock.patch.object(os,'open',side_effect=swap):value=self.call('registry-recover')
        self.assertEqual(value['status'],'BLOCKED')
        self.assertEqual(value['reconciliation'],'not_started')
        self.assertEqual(victim.read_bytes(),b'foreign historical evidence')
        self.assertEqual(self.snapshot(),before);self.assertEqual(self.docker.calls,[])

    def test_replacement_with_regular_directory_is_not_accepted(self):
        output=self.root/'recovery';real=maintenance._publish;calls=[]
        def replaced(receipt,report):
            calls.append(True)
            if len(calls)==2:
                output.rename(self.root/'original-recovery');output.mkdir(mode=0o700)
                (output/'recovery.json').write_bytes(b'foreign receipt')
            return real(receipt,report)
        with mock.patch.object(maintenance,'_publish',side_effect=replaced):value=self.call('registry-recover')
        self.assertEqual(value['status'],'BLOCKED')
        self.assertEqual((output/'recovery.json').read_bytes(),b'foreign receipt')

    def test_prior_receipt_tampering_or_alias_is_not_overwritten(self):
        for kind in ('contents','hardlink','symlink','mode'):
            with self.subTest(kind=kind):
                output=self.root/('receipt-'+kind);foreign=self.root/('foreign-'+kind)
                foreign.write_bytes(b'foreign receipt');foreign.chmod(0o600)
                real=maintenance._publish;calls=[]
                def changed(receipt,report):
                    calls.append(True)
                    if len(calls)==2:
                        leaf=output/'recovery.json'
                        if kind=='contents':leaf.write_bytes(b'tampered receipt')
                        elif kind=='mode':leaf.chmod(0o644)
                        else:
                            leaf.unlink()
                            if kind=='hardlink':os.link(foreign,leaf)
                            else:leaf.symlink_to(foreign)
                    return real(receipt,report)
                with mock.patch.object(maintenance,'_publish',side_effect=changed):value=self.call('registry-recover',output)
                self.assertEqual(value['status'],'BLOCKED')
                self.assertEqual(foreign.read_bytes(),b'foreign receipt')
                if kind=='contents':self.assertEqual((output/'recovery.json').read_bytes(),b'tampered receipt')

    def test_terminal_publication_interruption_is_not_retried(self):
        real=maintenance._publish;calls=[]
        def interrupted(receipt,report):
            calls.append(True)
            if len(calls)==2:raise KeyboardInterrupt
            return real(receipt,report)
        with mock.patch.object(maintenance,'_publish',side_effect=interrupted):value=self.call('registry-recover')
        self.assertEqual(len(calls),2)
        self.assertEqual(value['status'],'INTERRUPTED')
        self.assertEqual(value['receipt_persistence'],'unconfirmed')
        self.assertEqual(value['interrupted_phase'],'terminal_receipt_publication')
        self.assertEqual(value['reconciliation'],'completed')

    def test_receipt_descriptors_close_after_success_and_failure(self):
        for failure in (False,True):
            with self.subTest(failure=failure):
                if failure:fixtures.leave_pending(self.lease,self.root/'next-run')
                captured=[];real_close=maintenance._Receipt.close
                def close(receipt):
                    captured.extend([receipt.fd,receipt.parent]);return real_close(receipt)
                self.docker.fault='daemon' if failure else None
                with mock.patch.object(maintenance._Receipt,'close',close):
                    value=self.call('registry-recover',self.root/('close-'+str(failure)))
                self.assertEqual(value['status'],'BLOCKED' if failure else 'RECONCILED')
                for fd in captured:
                    with self.assertRaises(OSError) as caught:os.fstat(fd)
                    self.assertEqual(caught.exception.errno,errno.EBADF)

    def test_oversize_receipt_denies_before_reconciliation(self):
        before=self.snapshot()
        with mock.patch.object(maintenance,'MAX_RECEIPT_BYTES',100):value=self.call('registry-recover')
        self.assertEqual(value['status'],'BLOCKED')
        self.assertEqual(value['reconciliation'],'not_started')
        self.assertEqual(value['infrastructure']['registry_diagnostic']['condition'],'inventory_unbounded')
        self.assertEqual(self.snapshot(),before);self.assertEqual(self.docker.calls,[])


if __name__=='__main__':unittest.main()
