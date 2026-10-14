"""Immutable stage/recovery admission against actual owner-private catalog files."""
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'skill/scripts'))
import indexed_execution
import indexed_contract
import test_inference_catalog
from test_indexed_contract import config
import secret_store

class StageTests(unittest.TestCase):
    def setUp(self):
        test_inference_catalog.CatalogTests.setUp(self);self.catalog.register('beta',config());self.catalog.confirm('alpha','fixture');self.catalog.confirm('beta','fixture')
        self.bindings={'implementer':self.catalog.freeze('alpha','fixture'),'reviewer':self.catalog.freeze('beta','fixture')}
        self.active=[];self.args=SimpleNamespace()
        route={'base_url':'http://broker.invalid/v1','host_base_url':'http://127.0.0.1:12345/v1','activate':lambda values:self.active.append(list(values))}
        self.tokens={'implementer':['synthetic-token-a','synthetic-token-b'],'reviewer':['synthetic-token-c','synthetic-token-d']}
        self.session=indexed_execution.Session(self.catalog,self.bindings,'fixture',route,self.tokens,{},['synthetic-authority-one'],{})
    def test_stage_switch_and_recovery_rotate_only_capability(self):
        self.session.stage('implementer',self.args);identity=self.args._indexed_binding.copy()
        self.assertEqual(self.session.continuation(),'synthetic-token-a');self.session.release_segment()
        self.assertEqual(self.active[-1],[])
        self.assertEqual(self.session.continuation(renew=True),'synthetic-token-b')
        self.assertEqual(self.args._indexed_binding,identity)
        self.session.stage('reviewer',self.args);self.assertEqual(self.active[-1],['synthetic-token-c'])
        self.assertNotEqual(self.args._indexed_binding['environment_incarnation'],identity['environment_incarnation'])
    def test_rotation_and_revocation_stop_continuation_before_activation(self):
        self.session.stage('implementer',self.args);count=len(self.active)
        secret_store.write_secret('SYNTHETIC_REFERENCE','synthetic-rotated-authority',self.root/'store')
        with self.assertRaises(indexed_contract.IndexedError):self.session.continuation(renew=True)
        self.assertEqual(len(self.active),count)
        self.catalog.revoke('alpha',1)
        with self.assertRaises(indexed_contract.IndexedError):self.session.stage('implementer',self.args)
        self.assertEqual(len(self.active),count)

if __name__=='__main__':unittest.main()
