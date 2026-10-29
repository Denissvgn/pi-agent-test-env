"""Published vectors cross the actual isolated boundary using test-only providers."""
import copy
import json
import os
from pathlib import Path
import sys
from unittest import TestCase, mock

from tests.test_application_owner_consumer import ROOT
from tests import test_application_owner_consumer_graph as graphs
from tests.test_application_owner_consumer_policy import example_policy, selection
from tests import test_application_owner_reader_contract as core
from tools.qualification import application_owner_consumer as consumer
from tools.qualification import application_owner_consumer_policy as policy


class IsolatedVectorTests(TestCase):
    def test_all_published_vectors_through_the_consumer_boundary(self):
        text=os.environ.get('PI_SYNTHETIC_READER_PROVIDER')
        if not text:self.skipTest('Requires pinned read-only synthetic providers in Docker')
        base=Path(text);original_popen=consumer.subprocess.Popen
        vectors=json.loads((ROOT/'skill/assets/application-owner-reader-vectors-v1.json').read_text())['cases']
        oracle=core.ReaderContractTests('test_published_vectors')
        def worker_only(argv, **options):
            self.assertEqual(argv,[sys.executable,'-I','-S','-B',
                str(ROOT/'tools/qualification/application_owner_consumer_worker.py')])
            return original_popen(argv,**options)
        for vector in vectors:
            with self.subTest(vector=vector['id']):
                if vector['expected']=='extension_required':
                    value=example_policy();requested=selection(value)
                    if vector['policy']=='frozen':value['binding']['contract_id']='frozen_unsupported'
                    elif vector['policy']=='unapproved_provider':requested['provider_inventory_sha256']='b'*64
                    elif vector['policy']=='diagnostic_only':requested['binding']['variant']='standard_workspace_v1'
                    else:requested['binding']['scope']=vector['scope']
                    with (mock.patch.object(consumer,'exchange',side_effect=AssertionError('frozen factory')),
                          mock.patch('os.open',side_effect=AssertionError('frozen file read'))):
                        observed=consumer.evaluate(value,trusted_policy_sha256=policy.digest(value),selection=requested)
                    self.assertEqual(observed['decision'],vector['expected']);continue
                def replay(case,terminal,mutation):
                    holder=graphs.IsolatedGraphTests('test_complete_standard_graph_replays_in_a_fresh_readonly_provider')
                    holder.case=case;holder.provider=base
                    if mutation in ('reference_budget','file_budget'):
                        holder.provider=base.with_name(base.name+'-'+mutation)
                    if mutation=='aggregate_budget':
                        self._inflate(case,terminal)
                    value=holder.approval(terminal)
                    if mutation in ('strongest_privacy','strongest_role_limit'):
                        row=next(copy.deepcopy(r) for r in value['read_scope']['files']
                                 if r['path']==str(case.receipt_path) and r['role']=='terminal')
                        row.update(role='source',private=False,private_parent=False)
                        if mutation=='strongest_role_limit':row['maximum_bytes']=0
                        value['read_scope']['files'].append(row)
                        value['read_scope']['files'].sort(key=lambda r:(r['path'],r['role']))
                    with mock.patch.object(consumer.subprocess,'Popen',side_effect=worker_only):
                        result=consumer.evaluate(value,trusted_policy_sha256=policy.digest(value),
                                                 selection=selection(value),mode='replay')
                    self.assertFalse(result['admission_authorized'])
                    return result['decision']
                decision=oracle._reader(vector,replay=replay)
                self.assertEqual(decision,vector['expected'])

    @staticmethod
    def _inflate(case,terminal):
        def padded(path,value):
            import hashlib
            body=policy.canonical(value);body+=b' '*(3500000-len(body));path.write_bytes(body)
            return {'path':str(path),'sha256':hashlib.sha256(body).hexdigest()}
        intent_path=Path(terminal['intent']['path']);intent=json.loads(intent_path.read_bytes())
        reference=padded(intent_path,intent);terminal['intent']=reference
        anchor=json.loads(case.anchor_path.read_bytes());anchor['intent']=reference
        receipt=padded(case.receipt_path,terminal);index=copy.deepcopy(case.index);index['receipt']=receipt
        store=case.owner.root.with_name(case.owner.root.name+'.owner-proofs')
        padded(store/(case.fixture.launch_id+'.json'),index)
        selected=store/'selected'/(case.fixture.launch_id+'.json')
        padded(selected,json.loads(selected.read_bytes()));padded(case.anchor_path,anchor)
