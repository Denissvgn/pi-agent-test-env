"""Indexed comparison and public export boundary fixtures, with no provider calls."""
import copy
import json
from pathlib import Path
import sys
import unittest
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/'skill/scripts'),str(Path(__file__).resolve().parents[1]/'skill/runtime')]
import comparisons
import experiments
import indexed_reporting
import test_indexed_experiments

class PublicTests(test_indexed_experiments.IndexedSetup):
    def test_public_export_strips_inventory_and_preserves_missing_cells(self):
        experiments.prepare(self.root/'experiment.json',self.root/'indexed',__import__('pi_lab'),session='fixture',catalog=self.catalog)
        receipt=experiments.export_ledger(self.root/'indexed',__import__('pi_lab'),public=True)
        body=Path(receipt['path']).read_text();rows=[json.loads(line) for line in body.splitlines()]
        self.assertEqual(len(rows),4);self.assertTrue(all(row['attempts']==[] for row in rows))
        for private in ('alpha','beta','synthetic.invalid','fixture-model','catalog','authority_id','fingerprint',str(self.root)):
            self.assertNotIn(private,body)
        self.assertEqual({x['bindings'][0]['binding'] for x in rows},{'binding-1','binding-2'})
    def test_private_expected_contracts_use_exhaustive_stage_identities(self):
        lab=__import__('pi_lab');experiments.prepare(self.root/'experiment.json',self.root/'indexed',lab,session='fixture',catalog=self.catalog)
        metadata,matrix=experiments.verify(self.root/'indexed',lab)
        expected=comparisons.expected_contracts(self.root/'indexed',metadata,matrix['cells'],lab)
        for cell in matrix['cells']:
            value=expected[cell['trial_id']];self.assertEqual(set(value['indexed_bindings']),{'dev'})
            self.assertEqual(len(value['bindings_sha256']),64)
    def test_allowlist_rejects_secret_status_reason_and_nonfinite_usage(self):
        row={'case':'https://private.invalid','variant':'synthetic-secret','repetition':0,'attempts':[{'attempt_index':1,'result':{
            'status':'synthetic-private-key','infrastructure':{'reason':'http://private.invalid'},
            'task_result':{'score':float('nan')},'measurement':{'usage':{'categories':{'total':{'reported':float('inf')}}}}}}]}
        binding={'incarnation':'private-incarnation','fingerprint':'private-fingerprint','authority_id':'private-authority'}
        public=indexed_reporting.public_rows([row],lambda unused:{'secret-stage':binding},lambda unused:['secret-stage'])
        text=json.dumps(public,allow_nan=False)
        for value in ('private','synthetic','secret'):self.assertNotIn(value,text)
        self.assertIsNone(public[0]['attempts'][0]['score']);self.assertIsNone(public[0]['attempts'][0]['reason'])

    def test_binding_object_order_cannot_erase_a_role_swap(self):
        first={'incarnation':'a','fingerprint':'a','authority_id':'a'};second={'incarnation':'b','fingerprint':'b','authority_id':'b'}
        rows=[{'case':'case','variant':v,'repetition':0,'attempts':[]} for v in ('baseline','candidate')]
        maps={'baseline':{'reviewer':second,'implementer':first},'candidate':{'implementer':second,'reviewer':first}}
        exported=indexed_reporting.public_rows(rows,lambda row:maps[row['variant']],lambda row:['implementer','reviewer'])
        self.assertEqual([b['binding'] for b in exported[0]['bindings']],['binding-1','binding-2'])
        self.assertEqual([b['binding'] for b in exported[1]['bindings']],['binding-2','binding-1'])

if __name__=='__main__':unittest.main()
