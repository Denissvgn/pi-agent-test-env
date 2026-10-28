"""Portable synthetic reader vectors and pre-import frozen-policy denial."""
import copy
import contextlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import unittest
import uuid
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('published_owner_reader_conformance',ROOT/'tools/qualification/application_owner_reader_conformance.py')
model=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(model)


class ReaderContractTests(unittest.TestCase):
    def policy(self,profile='qualified'):
        return {'schema':1,'contracts':[model.CONTRACT] if profile!='frozen' else [],
                'approved_provider':'a'*64 if profile!='unapproved_provider' else 'b'*64,
                'scopes':[model.SCOPE],
                'variants':['diagnostic_disposable_v1'] if profile=='diagnostic_only' else ['diagnostic_disposable_v1','standard_workspace_v1']}

    def test_frozen_or_unapproved_reader_stops_before_import_or_fixture_access(self):
        for profile,scope in (('frozen',model.SCOPE),('unapproved_provider',model.SCOPE),
                              ('qualified','generic_integration_qualification')):
            with self.subTest(profile=profile,scope=scope):
                reader=mock.Mock(side_effect=AssertionError('Forbidden provider import/read'))
                self.assertEqual(model.replay(self.policy(profile),'a'*64,scope,reader),'extension_required')
                reader.assert_not_called()

    def test_malformed_capabilities_cannot_call_a_reader(self):
        for update in ({'schema':True},{'contracts':[['not-a-contract']]},{'scopes':[{}]},
                       {'approved_provider':'0'*64},{'contracts':[model.CONTRACT,model.CONTRACT]}):
            with self.subTest(update=tuple(update)):
                reader=mock.Mock(side_effect=AssertionError('Forbidden reader'))
                self.assertEqual(model.replay({**self.policy(),**update},'a'*64,model.SCOPE,reader),'extension_required')
                reader.assert_not_called()

    def test_contract_matches_closed_runtime_document_interfaces(self):
        contract=json.loads((ROOT/'skill/assets/application-owner-reader-v1.json').read_text())
        with mock.patch.object(sys,'path',[str(ROOT/'skill/scripts'),*sys.path]):
            protocol=importlib.import_module('application_owner_legacy_protocol')
            legacy=importlib.import_module('application_owner_legacy')
        self.assertEqual(set(contract['documents']['receipt']['fields']),set(protocol.RECEIPT_FIELDS))
        self.assertEqual(set(contract['documents']['intent']['fields']),set(protocol.INTENT_FIELDS))
        self.assertEqual(set(contract['documents']['request']['fields']),set(legacy.REQUEST_FIELDS))
        self.assertFalse(contract['admission_authorized']);self.assertEqual(contract['native_replay_calls'],0)

    def test_descriptor_and_vectors_are_generic_and_cover_all_declared_decisions(self):
        contract_path=ROOT/'skill/assets/application-owner-reader-v1.json'
        vectors_path=ROOT/'skill/assets/application-owner-reader-vectors-v1.json'
        contract=json.loads(contract_path.read_text());vectors=json.loads(vectors_path.read_text())
        self.assertEqual(contract['contract_id'],vectors['contract_id'])
        self.assertEqual({row['expected'] for row in vectors['cases']},set(contract['decisions']))
        self.assertTrue((contract_path.parent/contract['normative_specification']).is_file())
        text=contract_path.read_text()+vectors_path.read_text()
        for private in (str(Path.home()),'reports/'):
            self.assertNotIn(private,text)

    def _reader(self,vector):
        # Provider/test fixture imports occur only after the modeled policy gate.
        from tests import test_application_owner_legacy_dispatch as fixtures
        from tests.test_application_owner_legacy_support import AcceptanceFixture
        import application_owner_cleanup as cleanup
        case=fixtures.LegacyDispatchTests('test_complete_new_method_graph_replays_without_native_actions')
        case.setUp()
        try:
            if vector['fixture']=='diagnostic':
                case.fixture=AcceptanceFixture(case.root/'diagnostic',scope='diagnostic_disposable',
                    registry_id=case.owner.registry_id,generation=case.owner.generation)
                case.owner.write(case.fixture.record)
            legacy=importlib.import_module('application_owner_legacy')
            with mock.patch.dict(legacy.SOURCE_FAMILIES,case.fixture.family(),clear=True):
                terminal=case.graph();mutation=vector['mutation'];stack=contextlib.ExitStack()
                with stack:
                    index_path=cleanup._index(case.owner,case.fixture.record)
                    paths={'missing_index':index_path,'missing_anchor':case.anchor_path,
                        'missing_selection':cleanup._selection(case.owner,case.fixture.record),
                        'missing_intent':Path(terminal['intent']['path']),'missing_terminal':case.receipt_path}
                    if mutation in paths:paths[mutation].unlink()
                    elif mutation in ('missing_store','no_selection'):
                        shutil.rmtree(cleanup.store_path(case.owner))
                        if mutation=='no_selection':shutil.rmtree(case.anchor_path.parent)
                    elif mutation=='wrong_lease':
                        case.lease.rename(case.root/'saved-lease');case.lease.write_text('replacement');case.lease.chmod(0o600)
                    elif mutation=='wrong_subject':
                        changed=copy.deepcopy(case.index);changed['subject']['launch_id']=str(uuid.uuid4())
                        case.put(index_path,changed)
                    elif mutation=='recreated_root':case.fixture.private.mkdir(mode=0o700)
                    elif mutation=='changed_metadata':Path(case.fixture.refs['protected-result.json']['path']).write_text('{}')
                    elif mutation in ('unknown_method','unknown_cohort','unknown_variant','nonzero_dispatch'):
                        field={'unknown_method':'method','unknown_cohort':'cohort','unknown_variant':'variant','nonzero_dispatch':'model_requests'}[mutation]
                        terminal[field]=1 if mutation=='nonzero_dispatch' else 'unsupported';case.rewrite_receipt(terminal)
                    elif mutation=='unknown_index_schema':case.put(index_path,{**case.index,'schema':999})
                    elif mutation=='mixed_selection_schema':
                        target=cleanup._selection(case.owner,case.fixture.record);value=json.loads(target.read_bytes());value['schema']=1;case.put(target,value)
                    elif mutation in ('duplicate_related','missing_related','extra_related','unknown_rule'):
                        intent_path=Path(terminal['intent']['path']);intent=json.loads(intent_path.read_bytes())
                        if mutation=='unknown_rule':
                            target=Path(case.fixture.refs['legacy-evidence.json']['path']);value=json.loads(target.read_bytes())
                            value['controller']['rule_id']='unsupported_rule';reference=case.put(target,value)
                            for body in (intent,terminal):
                                body['request']['evidence']=reference
                                body['metadata']=[reference if item['path']==reference['path'] else item for item in body['metadata']]
                            terminal['evidence_sha256']=reference['sha256']
                        else:
                            subjects=terminal['related_subjects']
                            subjects=[] if mutation=='missing_related' else subjects+subjects if mutation=='duplicate_related' else subjects+[{'launch_id':str(uuid.uuid4()),'identity':'a'*64}]
                            intent['related_subjects']=subjects;terminal['related_subjects']=subjects
                        reference=case.put(intent_path,intent);terminal['intent']=reference
                        anchor=json.loads(case.anchor_path.read_bytes());anchor['intent']=reference;case.put(case.anchor_path,anchor);case.rewrite_receipt(terminal)
                    elif mutation=='private_mode':case.receipt_path.chmod(0o644)
                    elif mutation=='hardlinked_terminal':os.link(case.receipt_path,case.root/'extra-link')
                    elif mutation=='symlinked_terminal':
                        saved=case.root/'saved-terminal';case.receipt_path.rename(saved);case.receipt_path.symlink_to(saved)
                    elif mutation in ('reference_budget','aggregate_budget','file_budget'):
                        refs={row['path'] for row in terminal['metadata']}
                        refs.update(str(path) for path in (index_path,case.anchor_path,case.receipt_path,
                            Path(terminal['intent']['path']),cleanup._selection(case.owner,case.fixture.record)))
                        if mutation=='reference_budget':field='MAX_REFERENCES';limit=len(refs)-1
                        elif mutation=='aggregate_budget':field='MAX_AGGREGATE_BYTES';limit=sum(Path(p).stat().st_size for p in refs)-1
                        else:field='MAX_BYTES';limit=max(Path(p).stat().st_size for p in refs)-1
                        stack.enter_context(mock.patch.object(cleanup,field,limit))
                    elif mutation=='strongest_privacy':
                        reader=cleanup.Reader();reader.read(case.receipt_path,private=True);case.receipt_path.chmod(0o644)
                        reader.read(case.receipt_path,private=False);return True
                    elif mutation=='strongest_role_limit':
                        path=case.root/'empty.bin';path.write_bytes(b'');path.chmod(0o600);reader=cleanup.Reader()
                        reader.read_bytes(path,maximum=0);path.write_bytes(b'changed');reader.read_bytes(path);return True
                    elif mutation!='none':raise AssertionError('Unknown vector mutation')
                    return case.replay()
        finally:case.doCleanups()

    def test_published_vectors(self):
        vectors=json.loads((ROOT/'skill/assets/application-owner-reader-vectors-v1.json').read_text())
        self.assertEqual(len({row['id'] for row in vectors['cases']}),len(vectors['cases']))
        self.assertFalse(vectors['real_cleanup_or_integration_qualification'])
        for vector in vectors['cases']:
            with self.subTest(vector=vector['id']):
                variant='diagnostic_disposable_v1' if vector['fixture']=='diagnostic' else 'standard_workspace_v1'
                decision=model.replay(self.policy(vector['policy']),'a'*64,vector['scope'],lambda:self._reader(vector),variant=variant)
                self.assertEqual(decision,vector['expected'])
