"""Installed version dispatch; all histories and cleanup observations are synthetic."""
import contextlib
import copy
import hashlib
import importlib
import json
from pathlib import Path
import shutil
import uuid
from unittest import mock

from tests.test_application_owner_legacy_support import AcceptanceFixture, LegacyContractTests
import application_owner_cleanup as cleanup
import ownership_registry as ownership
import registry_maintenance as maintenance


class LegacyDispatchTests(LegacyContractTests):
    def setUp(self):
        super().setUp()
        self.lease=self.root/'lease';self.lease.write_text('synthetic original lease\n');self.lease.chmod(0o600)
        self.owner=ownership.Registry(Path(str(self.lease)+'.registry'),
            command=mock.Mock(side_effect=AssertionError('Dispatch or passive replay called Docker')))
        self.owner.bind_daemon('synthetic-daemon')
        self.fixture=AcceptanceFixture(self.root/'case',registry_id=self.owner.registry_id,generation=self.owner.generation)
        self.owner.write(self.fixture.record)
        self.api=importlib.import_module('application_owner_legacy')
        self.catalog=mock.patch.dict(self.api.SOURCE_FAMILIES,self.fixture.family(),clear=True)
        self.catalog.start();self.addCleanup(self.catalog.stop)

    @contextlib.contextmanager
    def held(self):
        with maintenance.existing_lease(self.lease) as (fd,unused,selected):
            self.owner.lease_fd=fd
            yield

    def put(self,path,value):
        self.assertTrue(path.is_relative_to(self.root))
        for parent in reversed(path.parents):
            if parent == self.root or parent.is_relative_to(self.root):
                parent.mkdir(mode=0o700,exist_ok=True)
        path.write_bytes(cleanup.canonical(value));path.chmod(0o600)
        return {'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}

    def graph(self):
        """Emulate durable bytes and absent roots; never call native cleanup."""
        request=self.fixture.request()
        with self.held():
            record,related,reader,metadata,roots,physical=cleanup._prepare(self.owner,request)
            lease=cleanup.lease_identity(self.owner)
        common={'invocation_id':str(uuid.uuid4()),'method':self.api.METHOD,'cohort':self.api.COHORT,
            'variant':request['variant'],'started_at':cleanup.controls.now().replace('+00:00','Z'),'subject':cleanup.subject(record),
            'lease':lease,'request':request,'metadata':metadata,'roots':roots,
            'related_subjects':[cleanup._resource_subject(row) for row in related],
            'runner_content_sha256':'f'*64,'admission_authorized':False,'original_outcome_regraded':False,
            'new_containers':0,'participant_stages':0,'model_requests':0}
        intent={'schema':1,'document_type':'application_owner_cleanup_intent','status':'RUNNING',**common}
        intent_ref=self.put(self.root/'receipt'/'intent.json',intent)
        receipt={'schema':2,'document_type':'application_owner_cleanup_receipt','status':'CLEANED',
            **common,'finished_at':cleanup.controls.now().replace('+00:00','Z'),'cleanup_completed':True,
            'scope':'owned_host_files_only','global_actor_census':'not_attested',
            'credential_memory_erasure':'not_attested','effects':'may_have_occurred',
            'evidence_sha256':request['evidence']['sha256'],'intent':intent_ref}
        self.receipt_path=self.root/'receipt'/'terminal.json'
        receipt_ref=self.put(self.receipt_path,receipt)
        selected={'schema':2,'document_type':'application_owner_cleanup_selection',
            'subject':common['subject'],'method':self.api.METHOD,'cohort':self.api.COHORT}
        self.put(cleanup._selection(self.owner,record),selected)
        self.index={'schema':2,'document_type':'application_owner_cleanup_index',
            'subject':common['subject'],'method':self.api.METHOD,'cohort':self.api.COHORT,'receipt':receipt_ref}
        self.put(cleanup._index(self.owner,record),self.index)
        self.anchor_path=self.owner.root.with_name(self.owner.root.name+'.owner-selected')/(record['launch_id']+'.json')
        self.put(self.anchor_path,{'schema':1,'document_type':'application_owner_cleanup_anchor',
            'subject':common['subject'],'method':self.api.METHOD,'cohort':self.api.COHORT,'intent':intent_ref})
        for observation in roots:
            target=Path(observation['path'])
            if target.exists():shutil.rmtree(target)
        return receipt

    def rewrite_receipt(self,receipt):
        self.index['receipt']=self.put(self.receipt_path,receipt)
        self.put(cleanup._index(self.owner,self.fixture.record),self.index)

    def replay(self):
        with self.held():return cleanup.validate_accepted(self.owner,self.fixture.record)

    def test_schema_two_preparation_uses_current_registry_and_shared_pure_layer(self):
        before=self.fixture.bytes_snapshot()
        result=cleanup._prepare(self.owner,self.fixture.request())
        self.assertEqual(result[0],self.fixture.record)
        self.assertEqual(result[1],[self.fixture.record]);self.assertTrue(result[3]);self.assertTrue(result[4])
        self.assertEqual(self.fixture.bytes_snapshot(),before)
        self.owner.command.assert_not_called()

    def test_incomplete_original_graph_cannot_enter_retained_terminal_fallback(self):
        self.fixture.rewrite('launcher-terminal.json',lambda body:body.update(wait_confirmed=False,unknown_owned_child=True))
        with self.assertRaises(ownership.RegistryError):cleanup._prepare(self.owner,self.fixture.request())

    def test_unknown_or_mixed_request_versions_deny_before_registry_reads(self):
        request=self.fixture.request()
        for update in ({'schema':True},{'schema':999},{'schema':1},{'method':'retained_terminals'},
                       {'cohort':'other'},{'variant':'other'}):
            with self.subTest(update=update),mock.patch.object(self.owner,'load',side_effect=AssertionError('Invalid dispatch read registry')):
                with self.assertRaises(ownership.RegistryError):cleanup._prepare(self.owner,{**request,**update})

    def test_new_request_cannot_use_old_mutating_recovery_path(self):
        with self.held():
            with mock.patch.object(cleanup,'_purge',side_effect=AssertionError('Premature purge')):
                with self.assertRaises(ownership.RegistryError):
                    cleanup.recover(self.owner,self.fixture.request(),self.root/'no-output',discard_workspace=True)
        self.assertFalse((self.root/'no-output').exists());self.assertTrue(self.fixture.private.exists())
        self.owner.command.assert_not_called()

    def test_complete_new_method_graph_replays_without_native_actions(self):
        primary=self.owner.root/(self.fixture.launch_id+'.json');before=primary.read_bytes()
        protected=self.fixture.body('protected-result.json')
        receipt=self.graph()
        self.owner=ownership.Registry(self.owner.root,command=self.owner.command,create=False)
        self.assertTrue(self.replay());self.assertEqual(primary.read_bytes(),before)
        self.assertEqual(self.fixture.body('protected-result.json'),protected)
        self.assertIsNotNone(receipt['roots'][0]['identity'])
        self.owner.command.assert_not_called()

    def test_selected_graph_and_originals_share_one_reference_budget(self):
        receipt=self.graph();self.assertTrue(self.replay())
        # The original closure fits alone; the five selected protocol documents
        # must count against the same ceiling rather than getting another Reader.
        with mock.patch.object(cleanup,'MAX_REFERENCES',len(receipt['metadata'])+4):
            with self.assertRaises(ownership.RegistryError):self.replay()

    def test_schema_three_identity_is_not_downgraded_to_an_old_subject(self):
        original=copy.deepcopy(self.fixture.record)
        current={**original,'schema':3,'owner_cleanup_contract':1}
        with mock.patch.object(self.owner,'load',return_value=[current]):
            with self.assertRaises(ownership.RegistryError):cleanup._prepare(self.owner,self.fixture.request())
        self.assertEqual(self.owner.load(),[original])

    def test_independent_anchor_blocks_fallback_after_entire_store_loss(self):
        self.graph();shutil.rmtree(cleanup.store_path(self.owner))
        self.owner=ownership.Registry(self.owner.root,command=self.owner.command,create=False)
        with self.assertRaises(ownership.RegistryError):self.replay()

    def test_new_method_requires_anchor_intent_and_selection(self):
        receipt=self.graph()
        for target in (self.anchor_path,Path(receipt['intent']['path']),cleanup._selection(self.owner,self.fixture.record)):
            with self.subTest(target=target.name):
                saved=target.with_suffix('.saved');target.rename(saved)
                try:
                    with self.assertRaises(ownership.RegistryError):self.replay()
                finally:saved.rename(target)

    def test_receipt_invariants_are_checked_after_rehashing_the_terminal(self):
        original=self.graph()
        mutations=[{'schema':True},{'schema':1},{'method':'retained_terminals'},{'cohort':'unknown'},
            {'variant':'diagnostic_disposable_v1'},{'evidence_sha256':'a'*64},{'new_containers':True},
            {'model_requests':1},{'participant_stages':1},{'effects':'none_observed'},
            {'admission_authorized':True},{'cleanup_completed':False},{'original_outcome_regraded':True},
            {'related_subjects':[]},{'metadata':[]},{'roots':[]},{'intent':self.fixture.capture}]
        for update in mutations:
            with self.subTest(update=tuple(update)):
                self.rewrite_receipt({**copy.deepcopy(original),**update})
                with self.assertRaises(ownership.RegistryError):self.replay()
        self.rewrite_receipt(original);self.assertTrue(self.replay())

    def test_unknown_index_schema_never_falls_back_to_old_receipts(self):
        self.graph();self.put(cleanup._index(self.owner,self.fixture.record),{**self.index,'schema':999})
        with self.assertRaises(ownership.RegistryError):self.replay()

    def test_rehashed_intent_and_anchor_cannot_disagree_with_terminal_commitments(self):
        receipt=self.graph();intent_path=Path(receipt['intent']['path'])
        intent=json.loads(intent_path.read_bytes());intent['runner_content_sha256']='a'*64
        new_ref=self.put(intent_path,intent);receipt['intent']=new_ref
        anchor=json.loads(self.anchor_path.read_bytes());anchor['intent']=new_ref
        self.put(self.anchor_path,anchor);self.rewrite_receipt(receipt)
        with self.assertRaises(ownership.RegistryError):self.replay()

    def test_mixed_schema_index_and_selection_pairs_are_not_accepted(self):
        self.graph();selection_path=cleanup._selection(self.owner,self.fixture.record)
        original=json.loads(selection_path.read_bytes())
        for update in ({'schema':1},{'schema':True},{'method':'retained_terminals'},{'cohort':'unknown'}):
            with self.subTest(update=tuple(update)):
                self.put(selection_path,{**original,**update})
                with self.assertRaises(ownership.RegistryError):self.replay()
        self.put(selection_path,original);self.assertTrue(self.replay())

    def test_current_recreated_root_rejects_passive_proof(self):
        self.graph();self.fixture.private.mkdir(mode=0o700)
        with self.assertRaises(ownership.RegistryError):self.replay()
