"""Synthetic source-catalog worker coverage; never a real producer qualification."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
from unittest import TestCase, mock

from tests.test_application_owner_consumer import ROOT, actual_policy
from tests.test_application_owner_consumer_policy import selection
from tools.qualification import application_owner_consumer as consumer
from tools.qualification import application_owner_consumer_policy as policy


class IsolatedGraphTests(TestCase):
    def setUp(self):
        text = os.environ.get('PI_SYNTHETIC_READER_PROVIDER')
        if not text:self.skipTest('Requires the separate synthetic catalog provider mounted read-only in Docker')
        self.provider = Path(text)
        self.assertTrue(os.statvfs(self.provider).f_flag & os.ST_RDONLY)
        self.original_popen = consumer.subprocess.Popen
        from tests.test_application_owner_legacy_dispatch import LegacyDispatchTests
        self.case = LegacyDispatchTests('test_complete_new_method_graph_replays_without_native_actions')
        self.case.setUp(); self.addCleanup(self.case.doCleanups)
        def worker_only(argv, **options):
            self.assertEqual(argv, [sys.executable, '-I', '-S', '-B',
                str(ROOT/'tools/qualification/application_owner_consumer_worker.py')])
            return self.original_popen(argv, **options)
        patch = mock.patch.object(consumer.subprocess, 'Popen', side_effect=worker_only)
        patch.start(); self.addCleanup(patch.stop)

    def approval(self, terminal):
        case = self.case; value = actual_policy(case.root, provider_root=self.provider)
        value['lease'] = {'path':str(case.lease),'identity':[terminal['lease']['device'],terminal['lease']['inode']]}
        old = value['read_scope']['registry']; new = str(case.owner.root)
        for key in ('registry','store','anchor'):value['read_scope'][key] = value['read_scope'][key].replace(old,new)
        value['subject'] = copy.deepcopy(terminal['subject'])
        value['binding']['variant'] = case.fixture.scope+'_v1'
        records = sorted(case.owner.root.glob('*.json'))
        value['read_scope']['registry_records'] = [dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in records]
        runroot=Path(case.fixture.record['runroot'])
        value['read_scope']['directories'] = sorted({str(case.root),str(runroot/'controls'),str(runroot/'stages'),
            value['read_scope']['registry'],value['read_scope']['store'],value['read_scope']['store']+'/selected',value['read_scope']['anchor'],
            *[str(p) for p in case.root.rglob('*') if p.is_dir()]})
        value['read_scope']['absent_paths'] = sorted(row['path'] for row in terminal['roots'])
        roles = {row['path']: {'original_metadata'} for row in terminal['metadata']}
        special = [(case.anchor_path,'anchor'), (case.receipt_path,'terminal'),
                   (Path(terminal['intent']['path']),'intent'),
                   (Path(terminal['request']['evidence']['path']),'evidence'),
                   (case.owner.root.with_name(case.owner.root.name+'.owner-proofs')/(case.fixture.launch_id+'.json'),'index'),
                   (case.owner.root.with_name(case.owner.root.name+'.owner-proofs')/'selected'/(case.fixture.launch_id+'.json'),'selection')]
        for path,role in special:roles.setdefault(str(path),set()).add(role)
        roles.setdefault(str(runroot/'result.json'),set()).add('original_metadata')
        rows = []
        for text, declared in sorted(roles.items()):
            data=Path(text).read_bytes() if Path(text).exists() else None
            for role in sorted(declared):
                empty = data == b'' and role == 'original_metadata'
                rows.append({'path':text,'sha256':hashlib.sha256(data).hexdigest() if data is not None else None,
                    'role':'empty_metadata' if empty else role,'maximum_bytes':0 if empty else policy.FILE_BYTES,
                    'private':True,'private_parent':True})
        value['read_scope']['files'] = sorted(rows,key=lambda row:(row['path'],row['role']))
        return value

    def reader(self, value):
        return consumer.Consumer(value,trusted_policy_sha256=policy.digest(value),selection=selection(value))

    def test_complete_standard_graph_replays_in_a_fresh_readonly_provider(self):
        terminal=self.case.graph(); value=self.approval(terminal)
        before={str(p):p.read_bytes() for p in self.case.root.rglob('*') if p.is_file()}
        observed=self.reader(value).evaluate('replay')
        self.assertEqual(observed['decision'],'proof_accepted',observed)
        self.assertTrue(observed['memory']['selected']);self.assertFalse(observed['admission_authorized'])
        self.assertEqual(before,{str(p):p.read_bytes() for p in self.case.root.rglob('*') if p.is_file()})

    def test_complete_diagnostic_graph_uses_its_distinct_variant(self):
        from tests.test_application_owner_legacy_support import AcceptanceFixture
        self.case.fixture=AcceptanceFixture(self.case.root/'diagnostic',scope='diagnostic_disposable',
            registry_id=self.case.owner.registry_id,generation=self.case.owner.generation)
        self.case.owner.write(self.case.fixture.record)
        terminal=self.case.graph();value=self.approval(terminal)
        observed=self.reader(value).evaluate('replay')
        self.assertEqual(observed['decision'],'proof_accepted',observed)

    def test_selected_and_namespace_loss_never_restore_not_selected_across_workers(self):
        terminal=self.case.graph();value=self.approval(terminal);reader=self.reader(value)
        self.assertEqual(reader.evaluate('replay')['decision'],'proof_accepted')
        self.case.anchor_path.unlink()
        self.assertEqual(reader.evaluate('replay')['decision'],'invalid_proof')
        shutil.rmtree(self.case.anchor_path.parent)
        shutil.rmtree(self.case.owner.root.with_name(self.case.owner.root.name+'.owner-proofs'))
        observed=self.reader(value).evaluate('replay')
        self.assertEqual(observed['decision'],'invalid_proof');self.assertTrue(observed['memory']['selected'])

    def test_coherently_rebound_related_contradiction_is_not_just_a_hash_failure(self):
        case=self.case;terminal=case.graph()
        intent_path=Path(terminal['intent']['path']);intent=json.loads(intent_path.read_bytes())
        intent['related_subjects']=[];terminal['related_subjects']=[]
        reference=case.put(intent_path,intent);terminal['intent']=reference
        anchor=json.loads(case.anchor_path.read_bytes());anchor['intent']=reference;case.put(case.anchor_path,anchor)
        case.rewrite_receipt(terminal)
        value=self.approval(terminal)
        self.assertEqual(self.reader(value).evaluate('replay')['decision'],'invalid_proof')

    def test_whole_graph_aggregate_bound_with_valid_file_hashes(self):
        case=self.case;terminal=case.graph();intent_path=Path(terminal['intent']['path'])
        def padded(path,body):
            data=policy.canonical(body);data += b' '*(3500000-len(data));path.write_bytes(data)
            return {'path':str(path),'sha256':hashlib.sha256(data).hexdigest()}
        intent=json.loads(intent_path.read_bytes());reference=padded(intent_path,intent)
        terminal['intent']=reference;anchor=json.loads(case.anchor_path.read_bytes());anchor['intent']=reference
        receipt=padded(case.receipt_path,terminal);index=copy.deepcopy(case.index);index['receipt']=receipt
        store=case.owner.root.with_name(case.owner.root.name+'.owner-proofs')
        padded(store/(case.fixture.launch_id+'.json'),index)
        selected=store/'selected'/(case.fixture.launch_id+'.json')
        padded(selected,json.loads(selected.read_bytes()));padded(case.anchor_path,anchor)
        value=self.approval(terminal)
        self.assertTrue(all(not Path(row['path']).exists() or Path(row['path']).stat().st_size<=policy.FILE_BYTES
                            for row in value['read_scope']['files']))
        self.assertEqual(self.reader(value).evaluate('replay')['decision'],'invalid_proof')

    def test_unapproved_transitive_metadata_is_denied(self):
        terminal=self.case.graph();value=self.approval(terminal)
        target=next(row['path'] for row in value['read_scope']['files'] if row['role']=='evidence')
        value['read_scope']['files']=[row for row in value['read_scope']['files'] if row['path']!=target]
        self.assertEqual(self.reader(value).evaluate('replay')['decision'],'invalid_proof')

    def test_generic_role_cannot_hide_borrowing_a_different_variant(self):
        terminal=self.case.graph();value=self.approval(terminal)
        self.assertEqual(terminal['variant'],'standard_workspace_v1')
        value['binding']['variant']='diagnostic_disposable_v1'
        rows={}
        for row in value['read_scope']['files']:
            if row['role'] in ('intent','terminal','evidence'):row['role']='original_metadata'
            rows[(row['path'],row['role'])]=row
        value['read_scope']['files']=[rows[key] for key in sorted(rows)]
        observed=self.reader(value).evaluate('replay')
        self.assertEqual(observed['decision'],'invalid_proof')
