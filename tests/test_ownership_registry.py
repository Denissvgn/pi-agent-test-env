"""Host owner-death fixtures; mocked Docker is never native qualification."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'skill/scripts'))
import ownership_registry as registry


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        self.command=mock.Mock();self.clean=mock.Mock()
        self.registry=registry.Registry(self.root/'registry',self.command,self.clean)
        self.argv=['docker','run','--name','pi-lab-fixture','--mount',f'type=bind,src={self.root}/control,dst=/opt/pi-control,readonly',
                   'sha256:'+'a'*64,'/opt/pi-lab/worker.py','check']
    def intent(self):return self.registry.intent(self.argv,'pi-lab-fixture',{'trial':'fixture'},self.root/'run')
    def reply(self,code=0,body='',error=''):return type('Reply',(),{'returncode':code,'stdout':body,'stderr':error})()
    def observed(self,record):
        return [{'Image':record['image'],'Config':{'Labels':{registry.LABEL:record['launch_id'],registry.REGISTRY_LABEL:self.registry.registry_id}},
                 'Mounts':[{'Source':record['mounts'][0]['source'],'Destination':'/opt/pi-control','RW':False}]}]

    def test_durable_intent_before_launch_and_recovery_without_launch(self):
        record,argv=self.intent();self.assertEqual(self.registry.load(),[record]);self.assertIn(registry.LABEL+'='+record['launch_id'],argv)
        self.command.return_value=self.reply(1,error='No such container')
        changed=registry.Registry(self.registry.root,self.command,self.clean)
        self.assertNotEqual(changed.generation,record['generation']);changed.reconcile()
        self.clean.assert_called_once_with(self.root/'run');self.assertEqual(changed.load()[0]['status'],'released')

    def test_owner_pid_reuse_cannot_establish_or_prevent_cleanup(self):
        record,_=self.intent();record['owner_pid']=os.getpid();self.registry.write(record)
        self.command.side_effect=[self.reply(body=json.dumps(self.observed(record))),self.reply(),self.reply(1,error='No such container')]
        self.registry.reconcile();self.assertEqual(self.command.call_args_list[1].args[0],['docker','rm','--force','pi-lab-fixture'])
        self.clean.assert_called_once();self.assertEqual(self.registry.load()[0]['status'],'released')

    def test_unknown_container_is_never_removed(self):
        record,_=self.intent();data=self.observed(record);data[0]['Config']['Labels'][registry.LABEL]='different'
        self.command.return_value=self.reply(body=json.dumps(data))
        with self.assertRaises(registry.RegistryError):self.registry.reconcile()
        self.assertEqual(self.command.call_count,1);self.clean.assert_not_called();self.assertEqual(self.registry.load()[0]['status'],'quarantined')

    def test_unknown_absence_or_purge_retains_capacity_for_next_owner(self):
        record,_=self.intent();self.command.return_value=self.reply(1,error='daemon unavailable')
        with self.assertRaises(registry.RegistryError):self.registry.reconcile()
        self.assertEqual(self.registry.load()[0]['status'],'intent')
        self.command.return_value=self.reply(1,error='No such container');self.clean.side_effect=ValueError('fixture purge uncertainty')
        with self.assertRaises(ValueError):self.registry.reconcile()
        self.assertEqual(self.registry.load()[0]['status'],'absent')

    def test_insecure_symlink_hardlink_and_malformed_records_reject(self):
        record,_=self.intent();path=self.registry.root/(record['launch_id']+'.json')
        path.chmod(0o644)
        with self.assertRaises(registry.RegistryError):self.registry.load()
        path.chmod(0o600);os.link(path,self.root/'alias')
        with self.assertRaises(registry.RegistryError):self.registry.load()
        (self.root/'alias').unlink();path.write_text('{}')
        with self.assertRaises(registry.RegistryError):self.registry.load()
        (self.root/'link').symlink_to(self.registry.root)
        with self.assertRaises(registry.RegistryError):registry.Registry(self.root/'link')
        self.registry.root.chmod(0o755)
        with self.assertRaises(registry.RegistryError):registry.Registry(self.registry.root)

import resources


class CohortTests(unittest.TestCase):
    def test_new_serial_admission_reconciles_before_body(self):
        with tempfile.TemporaryDirectory() as temp:
            lease=Path(temp).resolve()/'host.lock';seen=[]
            with mock.patch.object(registry.Registry,'reconcile',side_effect=lambda:seen.append('reconciled')):
                with resources.admission_lock(lease):
                    self.assertIsInstance(registry.CURRENT.get(),registry.Registry);seen.append('body')
            self.assertEqual(seen,['reconciled','body']);self.assertIsNone(registry.CURRENT.get())

    def test_insecure_registry_blocks_serial_and_uses_safe_code(self):
        with tempfile.TemporaryDirectory() as temp:
            lease=Path(temp).resolve()/'host.lock';root=Path(str(lease)+'.registry');root.mkdir(mode=0o755)
            with self.assertRaises(resources.AdmissionError) as failure:
                with resources.admission_lock(lease):self.fail('No serial dispatch with an unsafe registry')
            self.assertEqual(resources.admission_diagnostic(failure.exception)['reason'],'host-registry-unsafe')

    def test_old_client_after_owner_death_is_explicitly_unsupported(self):
        import fcntl
        import subprocess
        with tempfile.TemporaryDirectory() as temp:
            lease=Path(temp).resolve()/'host.lock';registry_root=Path(str(lease)+'.registry')
            registry_root.mkdir(mode=0o700);(registry_root/'malformed.json').write_text('{}')
            # Old behavior only acquires flock; it ignores surviving records.
            with lease.open('a+') as old_client:
                fcntl.flock(old_client,fcntl.LOCK_EX|fcntl.LOCK_NB)
                fcntl.flock(old_client,fcntl.LOCK_UN)
            with self.assertRaises(resources.AdmissionError):
                with resources.admission_lock(lease):self.fail('New cohort must not repeat old crash exposure')

class NetworkAbsenceTests(unittest.TestCase):
    def reply(self,code,error):return type('Reply',(),{'returncode':code,'stderr':error})()
    def test_exact_native_and_legacy_missing_network_replies(self):
        for error in ('Error response from daemon: network pi-trial-fixture not found',
                      'Error response from daemon: No such network: pi-trial-fixture',
                      'Error: No such network: pi-trial-fixture'):
            self.assertTrue(registry.network_absent(self.reply(1,error),'pi-trial-fixture'))
    def test_other_identity_daemon_failure_generic_not_found_and_success_are_unknown(self):
        for code,error in ((1,'Error response from daemon: network another-trial not found'),
                           (1,'cannot connect to daemon: not found'),(1,'Docker CLI not found'),
                           (1,'No such network'),(1,'Error: No such network'),(1,'Error response from daemon: No such network'),
                           (1,'Error response from daemon: network pi-trial-fixture not found; credential=synthetic'),
                           (0,'Error response from daemon: network pi-trial-fixture not found')):
            self.assertFalse(registry.network_absent(self.reply(code,error),'pi-trial-fixture'))
    def test_remove_network_persists_confirmed_absence_without_retrying_dispatch(self):
        with tempfile.TemporaryDirectory() as temp:
            command=mock.Mock(return_value=self.reply(1,'Error response from daemon: network pi-trial-fixture not found'))
            owned=registry.Registry(Path(temp).resolve()/'registry',command)
            record=owned.network_intent('pi-trial-fixture');owned.remove_network(record);owned.release(record,True)
            self.assertEqual(owned.load()[0]['status'],'released');self.assertEqual(command.call_count,1)

class ConcurrentObservationTests(unittest.TestCase):
    def test_open_inode_replaced_before_fstat_reads_the_committed_replacement(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'record.json';replacement=Path(temp)/'replacement'
            path.write_text('{"generation":"old"}');path.chmod(0o600)
            replacement.write_text('{"generation":"new"}');replacement.chmod(0o600)
            original=os.fstat;changed=False
            def during_open(fd):
                nonlocal changed
                if not changed:changed=True;os.replace(replacement,path)
                return original(fd)
            with mock.patch.object(registry.os,'fstat',side_effect=during_open):
                self.assertEqual(registry.read_private(path),{'generation':'new'})
    def test_live_secure_atomic_temporary_is_not_a_committed_launch_or_admission_bypass(self):
        import uuid
        with tempfile.TemporaryDirectory() as temp:
            owned=registry.Registry(Path(temp).resolve()/'registry')
            record=owned.network_intent('pi-trial-fixture')
            temporary=owned.root/('.'+record['launch_id']+'.json-'+uuid.uuid4().hex)
            temporary.write_text('{"incomplete":');temporary.chmod(0o600)
            self.assertEqual(owned.load(observe=True),[record])
            with self.assertRaises(registry.RegistryError):owned.load()
            temporary.chmod(0o644)
            with self.assertRaises(registry.RegistryError):owned.load(observe=True)
    def test_insecure_current_replacement_is_never_accepted_on_retry(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'record.json';replacement=Path(temp)/'replacement'
            path.write_text('{}');path.chmod(0o600);replacement.write_text('{}');replacement.chmod(0o644)
            original=os.fstat;changed=False
            def during_open(fd):
                nonlocal changed
                if not changed:changed=True;os.replace(replacement,path)
                return original(fd)
            with mock.patch.object(registry.os,'fstat',side_effect=during_open),self.assertRaises(registry.RegistryError):registry.read_private(path)

    def test_continuous_commits_can_be_observed_without_accepting_partial_intents(self):
        import threading
        with tempfile.TemporaryDirectory() as temp:
            owned=registry.Registry(Path(temp).resolve()/'registry');record=owned.network_intent('pi-trial-fixture')
            complete=threading.Event();errors=[]
            def writer():
                try:
                    for index in range(100):record['observation']=index;owned.write(record)
                except BaseException as exc:errors.append(type(exc).__name__)
                finally:complete.set()
            thread=threading.Thread(target=writer);thread.start()
            try:
                while not complete.is_set():
                    values=owned.load(observe=True)
                    self.assertEqual(len(values),1);self.assertEqual(values[0]['launch_id'],record['launch_id'])
            finally:thread.join(5)
            self.assertFalse(errors);self.assertEqual(owned.load()[0]['observation'],99)
