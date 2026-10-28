"""Safe offline inspection and truthful new-method CLI operation projections."""
import argparse
import contextlib
import importlib
import io
import json
import os
from pathlib import Path
import unittest
from unittest import mock

from tests import test_application_owner_legacy_lifecycle as lifecycle
import application_owner_cleanup as cleanup
import ownership_registry as ownership


class LegacyInspectionTests(unittest.TestCase):
    def setUp(self):
        self.f=lifecycle.LegacyLifecycleTests('test_complete_publication_preserves_primary_and_failed_metadata')
        self.f.setUp();self.addCleanup(self.f.doCleanups)

    @contextlib.contextmanager
    def catalog(self):
        legacy=importlib.import_module('application_owner_legacy')
        with mock.patch.dict(legacy.SOURCE_FAMILIES,self.f.fixture.family(),clear=True):yield

    def cli(self,*,inspect=False,summary=False):
        actual=ownership.Registry
        def factory(path,**kwargs):return actual(path,command=self.f.command,create=False)
        request=self.f.root/'request.json';request.write_bytes(cleanup.canonical(self.f.fixture.request()));request.chmod(0o600)
        args=argparse.Namespace(op='application-owner-inspect' if inspect else 'application-owner-recover',
            lock_file=str(self.f.lease),lock_wait_seconds=0,request=str(request),
            output_dir=str(self.f.root/'cli-output'),discard_workspace=True,summary=summary)
        output=io.StringIO()
        with self.catalog(),mock.patch.object(ownership,'Registry',side_effect=factory),contextlib.redirect_stdout(output):
            code=cleanup.command(args)
        return code,json.loads(output.getvalue()),output.getvalue()

    def test_accepted_stored_proof_is_distinct_from_cleanup_observation(self):
        self.f.recover();before=self.f.protected();self.f.calls.clear()
        with self.catalog(),self.f.held(),mock.patch.object(os,'kill',side_effect=AssertionError('Inspection PID probe')):
            rows=cleanup.inspect_helpers(self.f.owner,self.f.owner.load())
        self.assertEqual(rows[0]['proof_status'],'accepted')
        self.assertEqual(rows[0]['condition'],'owner_proof_accepted')
        self.assertEqual(self.f.calls,[]);self.assertEqual(self.f.protected(),before)

    def test_missing_proof_does_not_become_accepted_from_metadata(self):
        with self.catalog(),self.f.held():rows=cleanup.inspect_helpers(self.f.owner,self.f.owner.load())
        self.assertEqual(rows[0]['proof_status'],'not_selected')
        self.assertEqual(rows[0]['condition'],'owner_proof_required')

    def test_accepted_new_graph_is_not_invalidated_by_older_shape_parser(self):
        self.f.recover()
        with self.catalog(),self.f.held(),mock.patch.object(cleanup,'_stages',side_effect=ownership.RegistryError('Unsupported old shape')):
            rows=cleanup.inspect_helpers(self.f.owner,self.f.owner.load())
        self.assertEqual(rows[0]['proof_status'],'accepted');self.assertEqual(rows[0]['execution_shape'],'unknown')

    def test_incomplete_publication_is_invalid_and_inspection_never_repairs_it(self):
        self.f.recover();cleanup._index(self.f.owner,self.f.fixture.record).unlink();self.f.calls.clear()
        before={str(p):p.read_bytes() for p in self.f.root.rglob('*.json')}
        with self.catalog(),self.f.held():rows=cleanup.inspect_helpers(self.f.owner,self.f.owner.load())
        self.assertEqual(rows[0]['proof_status'],'invalid');self.assertEqual(rows[0]['condition'],'cleanup_proof_invalid')
        self.assertEqual(set(rows[0]['diagnostic']),{'schema','phase','condition','operation','os_error','effects'})
        self.assertEqual({str(p):p.read_bytes() for p in self.f.root.rglob('*.json')},before)
        self.assertEqual(self.f.calls,[])

    def test_summary_has_no_identifiers_and_does_not_claim_an_inspection_cleanup(self):
        self.f.recover();self.f.calls.clear();code,result,text=self.cli(inspect=True,summary=True)
        self.assertEqual(code,0);self.assertEqual(result['status'],'OBSERVED')
        self.assertEqual(result['summary']['accepted_proofs'],1)
        self.assertFalse(result['cleanup_completed']);self.assertFalse(result['admission_authorized'])
        self.assertNotIn('helpers',result)
        for value in (str(self.f.root),self.f.fixture.launch_id,self.f.fixture.cid):self.assertNotIn(value,text)
        self.assertEqual(self.f.calls,[])

    def test_summary_selector_is_supported_by_the_existing_parser(self):
        import pi_lab
        output=io.StringIO()
        with self.catalog(),contextlib.redirect_stdout(output):
            code=pi_lab.main(['application-owner-inspect','--lock-file',str(self.f.lease),'--summary'])
        self.assertEqual(code,0);result=json.loads(output.getvalue())
        self.assertEqual(result['summary']['accepted_proofs'],0);self.assertFalse(result['admission_authorized'])

    def test_success_cli_reports_complete_confirmed_cleanup_without_private_fields(self):
        code,result,text=self.cli()
        self.assertEqual(code,0);self.assertEqual(result['status'],'CLEANED');self.assertTrue(result['cleanup_completed'])
        self.assertEqual(result['receipt_persistence'],'confirmed');self.assertEqual(result['effects'],'may_have_occurred')
        self.assertFalse(result['admission_authorized'])
        for value in (str(self.f.root),self.f.fixture.launch_id,self.f.fixture.cid):self.assertNotIn(value,text)

    def test_blocked_cli_uses_only_closed_diagnostic_without_exception_digest(self):
        publisher=importlib.import_module('application_owner_legacy_publication')
        with mock.patch.object(publisher,'recover',side_effect=OSError('SYNTHETIC_PRIVATE_EXCEPTION')):
            code,result,text=self.cli()
        self.assertEqual(code,2);self.assertFalse(result['cleanup_completed'])
        self.assertEqual(result['effects'],'none_observed');self.assertEqual(result['receipt_persistence'],'not_started')
        self.assertEqual(set(result['diagnostic']),{'schema','phase','condition','operation','os_error','effects'})
        self.assertNotIn('infrastructure',result);self.assertNotIn('SYNTHETIC_PRIVATE_EXCEPTION',text)
        self.assertNotIn(str(self.f.root),text)

    def test_interruption_after_purge_keeps_false_completion_and_possible_effects(self):
        original=cleanup._purge;interrupted=[]
        def purge(observation,**kwargs):
            original(observation,**kwargs)
            if not interrupted:interrupted.append(True);raise KeyboardInterrupt()
        with mock.patch.object(cleanup,'_purge',side_effect=purge):code,result,text=self.cli()
        self.assertEqual(code,130);self.assertEqual(result['status'],'INTERRUPTED')
        self.assertFalse(result['cleanup_completed']);self.assertEqual(result['effects'],'may_have_occurred')
        self.assertEqual(result['receipt_persistence'],'unconfirmed');self.assertFalse(result['admission_authorized'])
        self.assertNotIn(str(self.f.root),text)

    def test_failure_after_terminal_never_prints_cleaned_or_confirmed(self):
        with mock.patch.object(cleanup,'_publish_index',side_effect=OSError('SYNTHETIC_PRIVATE_INDEX_ERROR')):
            code,result,text=self.cli()
        self.assertEqual(code,2);self.assertEqual(result['status'],'BLOCKED');self.assertFalse(result['cleanup_completed'])
        self.assertEqual(result['effects'],'may_have_occurred');self.assertEqual(result['receipt_persistence'],'unconfirmed')
        self.assertNotIn('SYNTHETIC_PRIVATE_INDEX_ERROR',text)
        terminal=json.loads((self.f.root/'cli-output'/'terminal.json').read_bytes())
        self.assertEqual(terminal['status'],'CLEANED');self.assertTrue(terminal['cleanup_completed'])

    def test_malformed_request_and_missing_lease_summary_remain_closed(self):
        output=io.StringIO()
        args=argparse.Namespace(op='application-owner-inspect',lock_file=str(self.f.root/'missing-lock'),lock_wait_seconds=0,summary=True)
        with contextlib.redirect_stdout(output):code=cleanup.command(args)
        result=json.loads(output.getvalue());self.assertEqual(code,2);self.assertFalse(result['cleanup_completed'])
        self.assertNotIn('infrastructure',result);self.assertNotIn(str(self.f.root),output.getvalue())
        self.assertFalse((self.f.root/'missing-lock').exists())

    def test_structural_or_incomplete_result_cannot_print_cleanup_success(self):
        publisher=importlib.import_module('application_owner_legacy_publication')
        base={'method':'legacy_derived_v1','status':'CLEANED','cleanup_completed':True,
              'receipt_persistence':'confirmed','effects':'none_observed'}
        for change in ({'status':'eligible_for_native_checks'},{'cleanup_completed':False},
                       {'receipt_persistence':'unconfirmed'}):
            with self.subTest(change=change),mock.patch.object(publisher,'recover',return_value={**base,**change}):
                code,result,text=self.cli()
            self.assertEqual(code,2);self.assertEqual(result['status'],'BLOCKED')
            self.assertFalse(result['cleanup_completed']);self.assertFalse(result['admission_authorized'])
