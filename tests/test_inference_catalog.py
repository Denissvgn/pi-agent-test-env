"""Actual owner-private catalog operations, with synthetic credential sources."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import subprocess
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'skill/scripts'))
import indexed_contract as contract
import inference_catalog
import pi_lab
import secret_store
from test_indexed_contract import config


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.catalog=inference_catalog.Catalog(pi_lab.normalize_endpoint,self.root/'catalog',self.root/'store')
        secret_store.write_secret('SYNTHETIC_REFERENCE','synthetic-authority-one',self.root/'store')
        self.catalog.register('alpha',config())
    def test_listing_is_metadata_only_and_does_not_resolve_keys(self):
        with patch.object(secret_store,'read_secret',side_effect=AssertionError('must not resolve')):
            listing=self.catalog.list();self.assertEqual(listing['entries'][0]['credential_availability'],'present')
        text=json.dumps(listing);self.assertNotIn('synthetic-authority-one',text);self.assertNotIn('synthetic.invalid',text)
    def test_confirmation_freeze_and_source_rotation(self):
        self.catalog.confirm('alpha','fixture');binding=self.catalog.freeze('alpha','fixture')
        self.assertEqual(self.catalog.admit(binding,'fixture'),'synthetic-authority-one')
        self.assertNotIn('synthetic-authority-one',json.dumps(binding))
        secret_store.write_secret('SYNTHETIC_REFERENCE','synthetic-authority-two',self.root/'store')
        with self.assertRaisesRegex(contract.IndexedError,'Reauthorize'):self.catalog.admit(binding,'fixture')
        self.catalog.confirm('alpha','fixture')
        with self.assertRaises(contract.IndexedError):self.catalog.admit(binding,'fixture')
        self.assertEqual(self.catalog.admit(self.catalog.freeze('alpha','fixture'),'fixture'),'synthetic-authority-two')
    def test_store_binding_does_not_accept_ambient_override(self):
        with patch.dict(os.environ,{'SYNTHETIC_REFERENCE':'synthetic-other-env-value'}):
            self.catalog.confirm('alpha','fixture');self.assertEqual(self.catalog.admit(self.catalog.freeze('alpha','fixture'),'fixture'),'synthetic-authority-one')
    def test_env_binding_does_not_fallback_to_store(self):
        changed=config();changed['credential']['source']='env';self.catalog.register('alpha',changed,1)
        with patch.dict(os.environ,{},clear=True):
            with self.assertRaises(contract.IndexedError):self.catalog.confirm('alpha','fixture')
        with patch.dict(os.environ,{'SYNTHETIC_REFERENCE':'synthetic-env-only'}):
            self.catalog.confirm('alpha','fixture');binding=self.catalog.freeze('alpha','fixture')
        with patch.dict(os.environ,{},clear=True):
            with self.assertRaises(contract.IndexedError):self.catalog.admit(binding,'fixture')
    def test_unrelated_change_preserves_approval_but_selected_change_does_not(self):
        self.catalog.confirm('alpha','fixture');binding=self.catalog.freeze('alpha','fixture')
        self.catalog.register('beta',config());self.assertEqual(self.catalog.admit(binding,'fixture'),'synthetic-authority-one')
        changed=config();changed['endpoint']['model']='another-fixture';self.catalog.register('alpha',changed,1)
        with self.assertRaises(contract.IndexedError):self.catalog.admit(binding,'fixture')
    def test_stale_index_and_delete_recreate_cannot_rebind(self):
        listing=self.catalog.list();self.catalog.confirm('alpha','fixture');binding=self.catalog.freeze('alpha','fixture')
        self.catalog.register('beta',config())
        with self.assertRaises(contract.IndexedError):self.catalog.select(index=1,revision=listing['catalog_revision'])
        self.catalog.revoke('alpha',1);self.catalog.register('alpha',config())
        with self.assertRaises(contract.IndexedError):self.catalog.admit(binding,'fixture')
        self.assertEqual(self.catalog.status('alpha','fixture')['reason'],'environment-unconfirmed')
    def test_insecure_link_temporary_and_modes_block(self):
        target=self.catalog.root/'catalog.json'
        os.chmod(target,0o644)
        with self.assertRaises(contract.IndexedError):self.catalog.list()
        os.chmod(target,0o600);temporary=self.catalog.root/'.abandoned';temporary.write_text('{}')
        with self.assertRaises(contract.IndexedError):self.catalog.list()
        temporary.unlink();hard=self.root/'hard';os.link(target,hard)
        with self.assertRaises(contract.IndexedError):self.catalog.list()
        hard.unlink();target.unlink();target.symlink_to(self.root/'missing')
        with self.assertRaises(contract.IndexedError):self.catalog.list()
    def test_compare_and_swap_rejects_stale_revision(self):
        self.catalog.register('alpha',config(),1)
        with self.assertRaises(contract.IndexedError):self.catalog.register('alpha',config(),1)
        self.assertEqual(self.catalog.inspect('alpha')['revision'],2)
    def test_keyless_source_has_no_original_authority(self):
        changed=config();changed['credential']={'source':'none'};self.catalog.register('alpha',changed,1)
        self.catalog.confirm('alpha','fixture');self.assertEqual(self.catalog.admit(self.catalog.freeze('alpha','fixture'),'fixture'),'')
    def test_normalized_parameters_are_frozen(self):
        changed=config();changed['endpoint']['model']='${SYNTHETIC_MODEL}'
        with patch.dict(os.environ,{'SYNTHETIC_MODEL':'first-fixture'}):self.catalog.register('alpha',changed,1)
        with patch.dict(os.environ,{'SYNTHETIC_MODEL':'second-fixture'}):self.assertEqual(self.catalog.select('alpha')['configuration']['endpoint']['model'],'first-fixture')
    def test_actual_cli_list_confirm_and_private_inspection(self):
        script=Path(__file__).resolve().parents[1]/'skill/scripts/pi_lab.py'
        def cli(*args):
            command=[sys.executable,str(script),'env',*args,'--catalog-dir',str(self.catalog.root),'--secrets-dir',str(self.root/'store')]
            reply=subprocess.run(command,text=True,capture_output=True,timeout=10)
            self.assertEqual(reply.returncode,0,reply.stderr);return json.loads(reply.stdout)
        self.assertTrue(cli('list','--json')['offline'])
        self.assertTrue(cli('confirm','--id','alpha','--session','fixture')['confirmed'])
        self.assertEqual(cli('status','--id','alpha','--session','fixture')['state'],'ready')
        self.assertNotIn('configuration',cli('inspect','--id','alpha'))
        self.assertIn('configuration',cli('inspect','--id','alpha','--private'))
    def test_directory_permissions_and_linked_secret_block_admission(self):
        os.chmod(self.catalog.root,0o755)
        with self.assertRaises(contract.IndexedError):self.catalog.list()
        os.chmod(self.catalog.root,0o700)
        path=secret_store.secret_path('SYNTHETIC_REFERENCE',self.root/'store');os.link(path,self.root/'duplicate-secret')
        with self.assertRaises(contract.IndexedError):self.catalog.confirm('alpha','fixture')

    def test_unchanged_expired_confirmation_renews_without_rebinding(self):
        with patch.object(inference_catalog.time,'time',return_value=1000000):
            self.catalog.confirm('alpha','fixture');binding=self.catalog.freeze('alpha','fixture')
        with patch.object(inference_catalog.time,'time',return_value=1000000+inference_catalog.lab_env.SESSION_TTL_SECONDS+1):
            self.assertEqual(self.catalog.status('alpha','fixture')['state'],'blocked')
            self.catalog.confirm('alpha','fixture')
            self.assertEqual(self.catalog.freeze('alpha','fixture'),binding)
            self.assertEqual(self.catalog.status('alpha','fixture')['state'],'ready')
    def test_reader_waits_until_writer_replaces_atomic_temporary(self):
        import threading
        entered=threading.Event();released=threading.Event();errors=[]
        def reader():
            entered.set()
            try:self.catalog.list()
            except Exception as exc:errors.append(exc)
            finally:released.set()
        with self.catalog.locked():
            temporary=self.catalog.root/'.catalog.json-active';temporary.write_text('{}')
            worker=threading.Thread(target=reader);worker.start();self.assertTrue(entered.wait(1))
            self.assertFalse(released.wait(.05));temporary.unlink()
        worker.join(2);self.assertTrue(released.is_set());self.assertEqual(errors,[])

    def test_inference_key_cannot_be_disguised_as_model_configuration(self):
        value=config();value['endpoint']['model']='synthetic-authority-one'
        self.catalog.register('alpha',value,1)
        with self.assertRaises(contract.IndexedError) as caught:self.catalog.confirm('alpha','fixture')
        self.assertEqual(caught.exception.reason,'inference-configuration-secret')
        self.assertNotIn('synthetic-authority-one',str(caught.exception.public()))

    def test_store_source_preserves_existing_character_limit_for_utf8_values(self):
        value='é'*secret_store.MAX_LEN
        secret_store.write_secret('SYNTHETIC_REFERENCE',value,self.root/'store')
        self.catalog.confirm('alpha','fixture');binding=self.catalog.freeze('alpha','fixture')
        self.assertEqual(self.catalog.admit(binding,'fixture'),value)

    def test_changed_store_location_requires_reauthorization_even_for_same_value(self):
        self.catalog.confirm('alpha','fixture');binding=self.catalog.freeze('alpha','fixture')
        secret_store.write_secret('SYNTHETIC_REFERENCE','synthetic-authority-one',self.root/'other-store')
        other=inference_catalog.Catalog(pi_lab.normalize_endpoint,self.catalog.root,self.root/'other-store')
        with self.assertRaises(contract.IndexedError) as caught:other.admit(binding,'fixture')
        self.assertEqual(caught.exception.reason,'inference-authority-changed')
        other.confirm('alpha','fixture')
        with self.assertRaises(contract.IndexedError):other.admit(binding,'fixture')
        self.assertEqual(other.admit(other.freeze('alpha','fixture'),'fixture'),'synthetic-authority-one')


if __name__=='__main__':unittest.main()
