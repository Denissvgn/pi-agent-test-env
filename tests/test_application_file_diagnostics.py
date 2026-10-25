"""Passive private file-failure metadata: synthetic authorities/files only.

No Docker/Pi/model, actual credentials, extra RPC or participant repair is used.
"""
import copy
import errno
import json
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_files as files
import application_execution as execution
from application_evidence import EvidenceError
import test_application_files as file_fixture
import test_application_execution as execution_fixture


def record():
    return {'schema':1,'document_type':'application_file_failure_diagnostic',
            'phase':'rename_parent_fsync','error_class':'OSError','errno':errno.EROFS,
            'roots_present':True,'quarantine_before':False,'storage_entered':True,'storage_returned':False}


class FileFailureDiagnostics(unittest.TestCase):
    def setUp(self):
        self.f=file_fixture.ApplicationFileTests(methodName='runTest');self.f.setUp();self.addCleanup(self.f.doCleanups)

    def test_success_has_original_result_and_no_optional_diagnostic(self):
        value=self.f.call()
        self.assertEqual(set(value),{'ok','artifact_id','bytes','sha256'});self.assertTrue(value['ok'])
        self.assertIsNone(self.f.client.file_diagnostic);self.assertEqual(len(self.f.verifications),1)
        self.assertEqual(self.f.authority.authorizations,2)

    def test_first_storage_errno_is_closed_and_not_overwritten_by_quarantine(self):
        with mock.patch.object(files.os,'replace',side_effect=OSError(errno.EROFS,'CANARY '+file_fixture.KEY+'/private/unknown')) as replace:
            result=self.f.call()
        self.assertEqual(result,{'ok':False,'reason':'artifact_unavailable'});replace.assert_called_once()
        first=self.f.client.file_diagnostic;self.assertEqual(first,record())
        self.assertNotIn('CANARY',json.dumps(first));self.assertNotIn(file_fixture.KEY,json.dumps(first))
        self.assertNotIn('/private',json.dumps(first));self.assertLess(len(json.dumps(first,indent=2).encode()),1024)
        again=self.f.call();self.assertEqual(again,result);self.assertEqual(self.f.client.file_diagnostic,first)
        first['phase']='CANARY';self.assertEqual(self.f.client.file_diagnostic,record())

    def test_closed_roots_fail_before_verifier_and_no_extra_filesystem_probe(self):
        self.f.client.close()
        with mock.patch.object(files.os,'open') as opened,mock.patch.object(files.os,'stat') as observed:
            value=self.f.call()
        self.assertEqual(value,{'ok':False,'reason':'artifact_unavailable'});opened.assert_not_called();observed.assert_not_called()
        diagnostic=self.f.client.file_diagnostic;self.assertEqual(diagnostic['phase'],'root_state')
        self.assertFalse(diagnostic['roots_present']);self.assertFalse(diagnostic['storage_entered']);self.assertEqual(self.f.verifications,[])

    def test_preexisting_quarantine_is_distinct_from_closed_roots(self):
        self.f.client.quarantined=True;self.assertFalse(self.f.call()['ok'])
        diagnostic=self.f.client.file_diagnostic;self.assertEqual(diagnostic['phase'],'root_state')
        self.assertTrue(diagnostic['roots_present']);self.assertTrue(diagnostic['quarantine_before'])

    def test_direct_verifier_OSError_records_budget_phase_without_storage_probe(self):
        self.f.client.budget_verifier=mock.Mock(side_effect=OSError(errno.EIO,'CANARY'))
        with mock.patch.object(files.os,'open') as opened,mock.patch.object(files.os,'stat') as observed:
            value=self.f.call()
        self.assertEqual(value,{'ok':False,'reason':'artifact_unavailable'});opened.assert_not_called();observed.assert_not_called()
        diagnostic=self.f.client.file_diagnostic;self.assertEqual(diagnostic['phase'],'budget_verify');self.assertEqual(diagnostic['errno'],errno.EIO)
        self.assertFalse(diagnostic['storage_entered']);self.f.client.budget_verifier.assert_called_once()

    def test_false_verifier_remains_accounting_unavailable_without_file_diagnostic(self):
        self.f.client.budget_verifier=mock.Mock(return_value=False)
        self.assertEqual(self.f.call(),{'ok':False,'reason':'accounting_unavailable'})
        self.assertIsNone(self.f.client.file_diagnostic);self.assertFalse((self.f.artifacts/'outputs').exists())

    def test_outer_EvidenceError_retains_phase_without_message(self):
        with mock.patch.object(self.f.client,'_read',side_effect=EvidenceError('CANARY')):
            value=self.f.call('artifact_read',{'artifact_id':'summary'})
        self.assertEqual(value,{'ok':False,'reason':'artifact_unavailable'})
        diagnostic=self.f.client.file_diagnostic;self.assertEqual(diagnostic['phase'],'artifact_read');self.assertEqual(diagnostic['error_class'],'EvidenceError')
        self.assertNotIn('CANARY',json.dumps(diagnostic))

    def test_root_reopen_errno_retains_original_guard_result(self):
        with mock.patch.object(self.f.client,'_root',side_effect=OSError(errno.EBADF,'CANARY')):
            value=self.f.call()
        self.assertEqual(value,{'ok':False,'reason':'artifact_unavailable'})
        diagnostic=self.f.client.file_diagnostic;self.assertEqual(diagnostic['phase'],'root_reopen');self.assertEqual(diagnostic['errno'],errno.EBADF)
        self.assertTrue(diagnostic['storage_entered']);self.assertFalse(diagnostic['storage_returned'])

    def test_recorder_internal_failure_cannot_mask_original_file_outcome(self):
        with mock.patch.object(files,'validate_file_diagnostic',side_effect=ValueError('CANARY')):
            with mock.patch.object(files.os,'replace',side_effect=OSError(errno.EIO,'CANARY')):
                value=self.f.call()
        self.assertEqual(value,{'ok':False,'reason':'artifact_unavailable'});self.assertTrue(self.f.client.quarantined)
        self.assertIsNone(self.f.client.file_diagnostic)

    def test_recorder_deadline_is_conserved_without_losing_original_quarantine(self):
        cancelled=TimeoutError('CANARY deadline')
        with mock.patch.object(files,'validate_file_diagnostic',side_effect=cancelled):
            with mock.patch.object(files.os,'replace',side_effect=OSError(errno.EIO,'CANARY')):
                with self.assertRaises(TimeoutError) as caught:self.f.call()
        self.assertIs(caught.exception,cancelled);self.assertTrue(self.f.client.quarantined)
        self.assertIsNone(self.f.client.file_diagnostic)

    def test_closed_schema_rejects_unknown_or_value_derived_metadata(self):
        changes=[lambda v:v.update(payload='CANARY'),lambda v:v.update(phase='CANARY'),lambda v:v.update(error_class='CANARY'),
                 lambda v:v.update(errno=True),lambda v:v.update(errno=65536),lambda v:v.update(roots_present=1),lambda v:v.update(schema=True)]
        for change in changes:
            value=record();change(value)
            with self.subTest(value=value),self.assertRaises(ValueError):files.validate_file_diagnostic(value)
        self.assertEqual(files.validate_file_diagnostic(record()),record())


class FinishAndOwnerRetention(unittest.TestCase):
    def setUp(self):
        self.f=execution_fixture.ApplicationCoordinatorTests(methodName='runTest');self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.co=self.f.prepare();self.f.begin(self.co);self.helper=self.f.helpers[0]
        self.co.mark_running();self.co.after_segment(True)
        self.path=self.f.run/'stages'/self.f.desc['stage_id']/'application-file-diagnostic.json'

    def test_existing_success_finish_shape_and_completion_context_unchanged(self):
        replies=[];original=self.helper.control
        def control(body):
            value=original(body)
            if body['action']=='finish':replies.append(copy.deepcopy(value))
            return value
        self.helper.control=control;result=self.co.close(True)
        self.assertTrue(result['safe_to_continue']);self.assertEqual(set(replies[0]),{'schema','ok','budget','receipts'})
        self.assertFalse(self.path.exists());self.assertEqual(set(self.co.completion_context),{'binding','authorized_segment_ids','report_root','evidence_root','parent_receipts'})

    def test_failure_record_captured_before_files_close_in_existing_finish_once(self):
        self.helper.service.files._file_diagnostic=record();result=self.co.close(True)
        self.assertTrue(result['safe_to_continue']);self.assertEqual(json.loads(self.path.read_text()),record())
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode),0o600);self.assertLessEqual(self.path.stat().st_size,1024)
        self.assertEqual(sum(b['action']=='finish' for b in self.helper.requests),1)
        self.assertNotIn('file_diagnostic',self.co.completion_context);self.assertNotIn('file_diagnostic',result)
        self.assertEqual(self.helper.record['status'],'released');self.assertFalse((Path(self.co.completion_context['report_root'])/'outputs/completion.json').exists())

    def test_invalid_optional_finish_metadata_is_unknown_and_does_not_skip_cleanup(self):
        original=self.helper.control
        def control(body):
            value=original(body)
            if body['action']=='finish':value['file_diagnostic']={**record(),'phase':'CANARY'}
            return value
        self.helper.control=control;result=self.co.close(True)
        self.assertTrue(result['safe_to_continue']);self.assertFalse(self.path.exists());self.assertEqual(self.helper.record['status'],'released')

    def test_service_invalid_RAM_record_is_omitted(self):
        self.helper.service.files._file_diagnostic={**record(),'private_path':'CANARY'}
        self.assertTrue(self.co.close(True)['safe_to_continue']);self.assertFalse(self.path.exists())

    def test_atomic_persistence_failure_does_not_mask_finish_or_skip_helper_cleanup(self):
        self.helper.service.files._file_diagnostic=record()
        with mock.patch.object(execution.controls,'atomic',side_effect=OSError('CANARY')) as writer:
            result=self.co.close(True)
        self.assertTrue(result['safe_to_continue']);writer.assert_called_once_with(self.path,record(),0o600)
        self.assertFalse(self.path.exists());self.assertEqual(self.helper.record['status'],'released')

    def assert_metadata_control_preserved(self,cancelled):
        self.helper.service.files._file_diagnostic=record()
        with mock.patch.object(execution.controls,'atomic',side_effect=cancelled):
            with self.assertRaises(type(cancelled)) as caught:self.co.close(True)
        self.assertIs(caught.exception,cancelled);self.assertFalse(self.path.exists())
        self.assertEqual(self.helper.record['status'],'released');self.assertTrue(self.co.failed)
        before=len(self.helper.requests)
        with self.assertRaises(execution.ApplicationExecutionError):self.f.begin(self.co)
        self.assertEqual(len(self.helper.requests),before)

    def test_metadata_cancellation_cleans_helper_then_rethrows_same_interrupt(self):
        self.assert_metadata_control_preserved(KeyboardInterrupt())

    def test_metadata_deadline_cleans_helper_then_rethrows_same_timeout(self):
        self.assert_metadata_control_preserved(TimeoutError('CANARY'))

    def test_metadata_exit_cleans_helper_then_rethrows_same_exit(self):
        self.assert_metadata_control_preserved(SystemExit(99))

    def test_service_metadata_deadline_revokes_and_parent_cleans_then_propagates(self):
        self.helper.service.files._file_diagnostic=record();cancelled=TimeoutError('CANARY')
        with mock.patch.object(files,'validate_file_diagnostic',side_effect=cancelled):
            with self.assertRaises(TimeoutError) as caught:self.co.close(True)
        self.assertIs(caught.exception,cancelled);self.assertEqual(self.helper.record['status'],'released')
        self.assertTrue(self.co.failed);self.assertFalse(self.path.exists())
        self.assertIsNone(self.helper.service._active);self.assertIsNone(self.helper.service._router)


if __name__=='__main__':unittest.main()
