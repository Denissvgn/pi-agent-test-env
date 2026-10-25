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

    def test_unresolved_application_helper_blocks_generic_recovery_before_all_docker_and_cleanup(self):
        record,unused=self.intent();record.update(application_helper=True,client_mode='application-execution',
            private_store=str(self.root/'private-application-store'),daemon='expected-daemon')
        self.registry.write(record)
        network=self.registry.network_intent('owned-application-network')
        private=self.root/'private-application-store';private.mkdir();(private/'retained.txt').write_text('retain')
        for status in ('intent','running','absent','quarantined'):
            with self.subTest(status=status):
                record['status']=status;self.registry.write(record)
                with self.assertRaises(registry.RegistryError):self.registry.reconcile()
                self.command.assert_not_called();self.clean.assert_not_called()
                self.assertEqual((private/'retained.txt').read_text(),'retain')
                self.assertEqual(next(r for r in self.registry.load() if r['launch_id']==network['launch_id'])['status'],'intent')
                self.assertEqual(next(r for r in self.registry.load() if r['launch_id']==record['launch_id'])['status'],'quarantined')

    def test_released_helper_with_unpurged_context_or_pending_receipt_still_blocks_recovery(self):
        import uuid
        record,unused=self.intent();record.update(application_helper=True,status='released')
        self.registry.write(record);self.registry.network_intent('pending-application-network')
        run=Path(record['runroot']);stage=str(uuid.uuid4());segment=str(uuid.uuid4())
        context=run/'controls'/stage/'segments'/segment/'application-context.json'
        context.parent.mkdir(parents=True);context.write_text('private context');context.chmod(0o400)
        with self.assertRaises(registry.RegistryError):self.registry.reconcile()
        self.command.assert_not_called();self.clean.assert_not_called();self.assertTrue(context.exists())
        context.unlink();receipt=run/'stages'/stage/'application-credentials.json';receipt.parent.mkdir(parents=True)
        descriptor=receipt.parent/'descriptor.json'
        descriptor.write_text(json.dumps({'stage_id':stage,'kind':'agent','label':'agent-1-participant'}))
        receipt.write_text(json.dumps({'schema':1,'status':'pending','workspace':'quarantined'}));receipt.chmod(0o600)
        with self.assertRaises(registry.RegistryError):self.registry.reconcile()
        self.command.assert_not_called();self.clean.assert_not_called()
        receipt.write_text(json.dumps({'schema':1,'status':'removed','workspace':'clean'}))
        with self.assertRaises(registry.RegistryError):self.registry.reconcile()
        self.command.assert_not_called();self.clean.assert_not_called()
        (receipt.parent/'state.json').write_text(json.dumps({'status':'finalized','cleanup_confirmed':True}))
        output=run/'agent-1-participant';output.mkdir()
        (output/'process.json').write_text(json.dumps({'cleanup_confirmed':True,
            'application_helper_cleanup':{'status':'removed','workspace':'clean','safe_to_continue':True},
            'application_credentials':{'schema':1,'status':'removed','workspace':'clean'}}))
        self.assertFalse(registry._application_stage_pending(run))

    def test_released_helper_missing_or_renamed_context_without_positive_parent_proof_denies_before_docker(self):
        import uuid
        record,_=self.intent();record.update(application_helper=True,status='released')
        self.registry.write(record);self.registry.network_intent('pending-application-network')
        run=Path(record['runroot']);stage=str(uuid.uuid4());segment=str(uuid.uuid4())
        folder=run/'controls'/stage/'segments'/segment;folder.mkdir(parents=True)
        for renamed in (False,True):
            if renamed:(folder/'renamed-private-context.json').write_text('private capability')
            with self.subTest(renamed=renamed),self.assertRaises(registry.RegistryError):self.registry.reconcile()
            self.command.assert_not_called();self.clean.assert_not_called()
        stages=run/'stages'/stage;stages.mkdir(parents=True)
        (stages/'descriptor.json').write_text(json.dumps({'stage_id':stage,'kind':'agent','label':'agent-1-participant'}))
        with self.assertRaises(registry.RegistryError):self.registry.reconcile()
        self.command.assert_not_called();self.clean.assert_not_called()

    def test_all_intent_types_reject_before_creation_at_capacity_but_cleanup_updates_work(self):
        with mock.patch.object(registry,'MAX_RECORDS',1):
            first,unused=self.intent()
            for create in (self.intent,lambda:self.registry.network_intent('pi-network-fixture'),
                           lambda:self.registry.builder_intent('fixture','sha256:'+'a'*64)):
                with self.subTest(create=create),self.assertRaises(registry.RegistryCapacityError):create()
                self.assertEqual(len(list(self.registry.root.iterdir())),1)
            first['status']='absent';self.registry.write(first)
            self.registry.release(first,True)
            self.assertEqual(self.registry.load()[0]['status'],'released')
            self.command.assert_not_called()

    def test_capacity_check_exact_fit_invalid_reservations_and_excess_inventory(self):
        import uuid
        with mock.patch.object(registry,'MAX_RECORDS',2):
            first,unused=self.intent()
            self.assertEqual(self.registry.require_capacity(1),{'retained_records':1,'new_records_ceiling':1,'committed_records_limit':2})
            for value in (2,True,-1,3,1.0):
                with self.subTest(value=value),self.assertRaises(registry.RegistryCapacityError):self.registry.require_capacity(value)
            self.intent()
            self.assertEqual(self.registry.require_capacity(0)['retained_records'],2)
            overflow={**first,'launch_id':str(uuid.uuid4())}
            registry.controls.atomic(self.registry.root/(overflow['launch_id']+'.json'),overflow)
            with self.assertRaises(registry.RegistryCapacityError):self.registry.load()

    def test_secure_transients_do_not_consume_committed_capacity_or_allow_new_intents(self):
        import uuid
        with mock.patch.object(registry,'MAX_RECORDS',1):
            record,unused=self.intent();temporary=self.registry.root/('.'+record['launch_id']+'.json-'+uuid.uuid4().hex)
            temporary.write_text('{"partial":');temporary.chmod(0o600)
            self.assertEqual(self.registry.load(observe=True),[record])
            with self.assertRaises(registry.RegistryCapacityError):self.intent()
            record['status']='absent';self.registry.write(record)
            self.assertEqual(self.registry.load(observe=True)[0]['status'],'absent')
            with self.assertRaises(registry.RegistryError):self.registry.load()
            temporary.chmod(0o644)
            with self.assertRaises(registry.RegistryError):self.registry.load(observe=True)

    def test_transient_inventory_and_serialized_record_sizes_remain_bounded(self):
        import uuid
        record,unused=self.intent()
        with mock.patch.object(registry,'MAX_TRANSIENT_RECORDS',1):
            for number in range(2):
                p=self.registry.root/('.'+record['launch_id']+'.json-'+uuid.uuid4().hex);p.write_text('{}');p.chmod(0o600)
            with self.assertRaises(registry.RegistryError):self.registry.load(observe=True)
        record['oversize']='x'*(1024*1024)
        with self.assertRaises(registry.RegistryError):self.registry.write(record)
        self.assertNotIn('oversize',registry.read_private(self.registry.root/(record['launch_id']+'.json')))

    def test_concurrent_creates_cannot_overrun_the_last_slot(self):
        import threading
        barrier=threading.Barrier(2);created=[];rejected=[]
        def create():
            barrier.wait()
            try:created.append(self.intent()[0])
            except registry.RegistryCapacityError:rejected.append(True)
        with mock.patch.object(registry,'MAX_RECORDS',1):
            threads=[threading.Thread(target=create) for unused in range(2)]
            for thread in threads:thread.start()
            for thread in threads:thread.join(5);self.assertFalse(thread.is_alive())
            self.assertEqual((len(created),len(rejected)),(1,1));self.assertEqual(len(self.registry.load()),1)

    def test_capacity_diagnostic_never_exposes_raw_exception_data(self):
        import resources
        raw='synthetic-private-key https://private.invalid/secret'
        value=resources.admission_diagnostic(registry.RegistryCapacityError(raw))
        self.assertEqual(value['reason'],'host-registry-capacity')
        self.assertNotIn(raw,json.dumps(value));self.assertNotIn('private.invalid',json.dumps(value))
        class Spoof(registry.RegistryCapacityError):pass
        self.assertIsNone(resources.admission_diagnostic(Spoof(raw)))

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


class QualificationServiceCleanupTests(unittest.TestCase):
    """Pure local owner receipts; no Docker/native cleanup is claimed."""
    def setUp(self):
        import uuid
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        self.command=mock.Mock();self.clean=mock.Mock();self.registry=registry.Registry(self.root/'registry',self.command,self.clean)
        self.private=self.root/'private-role';self.private.mkdir(mode=0o700)
        self.proofs=self.root/'proofs';self.proofs.mkdir(mode=0o700)
        argv=['docker','run','--name','qualification-fixture','--mount',f'type=bind,src={self.private},dst=/private,readonly',
            'sha256:'+'a'*64,'/opt/pi-lab/worker.py','check']
        self.record,_=self.registry.intent(argv,'qualification-fixture',{'run_id':str(uuid.uuid4()),'attempt_id':str(uuid.uuid4())},self.root/'run')
        self.record.update(application_helper=True,client_mode='qualification-fixture',qualification_role='fixture',
            qualification_cell='N02-0.87.1-request-and-persona-a',daemon='same-daemon',container_id='b'*64)
        self.registry.write(self.record)
        self.identity=registry.observe_qualification_private(self.record)
    def receipt(self,*,terminal=False,ready=False):
        self.private.rmdir();self.record['status']='absent';self.registry.write(self.record)
        ref=registry.write_qualification_service_cleanup(self.record,self.proofs/'cleanup.json',private_identity=self.identity,
            physical_absence_confirmed=True,private_bootstrap_removed=True,terminal_available=terminal,startup_readied=ready)
        self.record['qualification_service_cleanup']=ref;self.registry.write(self.record);return ref
    def rewrite_proof(self,change):
        import hashlib
        ref=self.record['qualification_service_cleanup'];p=Path(ref['path']);value=json.loads(p.read_text());change(value)
        p.write_text(json.dumps(value));ref['sha256']=hashlib.sha256(p.read_bytes()).hexdigest();self.registry.write(self.record)
    def test_prelaunch_fd_identity_and_missing_terminal_still_allows_only_cleanup(self):
        self.assertEqual(self.identity,{'source':str(self.private),'device':self.private.stat().st_dev,'inode':self.private.stat().st_ino})
        self.receipt();value=registry.validate_qualification_service_cleanup(self.record)
        self.assertFalse(value['qualification_eligible']);self.assertFalse(value['terminal_available']);self.assertFalse(value['startup_readied'])
        self.registry.release(self.record,True);self.assertEqual(self.registry.reconcile(),[])
        self.command.assert_not_called();self.clean.assert_not_called()
    def test_ready_and_terminal_flags_are_exact_boolean_eligibility_not_fake_agent_proof(self):
        self.receipt(terminal=True,ready=True);value=registry.validate_qualification_service_cleanup(self.record)
        self.assertTrue(value['qualification_eligible']);self.assertFalse((self.root/'run/stages').exists())
    def test_private_must_be_gone_before_publication_and_receipt_is_exclusive(self):
        self.record['status']='absent'
        kwargs=dict(private_identity=self.identity,physical_absence_confirmed=True,private_bootstrap_removed=True,terminal_available=False,startup_readied=False)
        with self.assertRaises(registry.RegistryError):registry.write_qualification_service_cleanup(self.record,self.proofs/'cleanup.json',**kwargs)
        self.assertFalse((self.proofs/'cleanup.json').exists());self.receipt()
        with self.assertRaises(registry.RegistryError):registry.write_qualification_service_cleanup(self.record,self.proofs/'cleanup.json',**kwargs)
    def test_pending_subtype_never_uses_even_valid_receipt_or_docker(self):
        self.receipt()
        for status in ('intent','running','absent','quarantined'):
            with self.subTest(status=status):
                self.record['status']=status;self.registry.write(self.record)
                with self.assertRaises(registry.RegistryError):self.registry.reconcile()
                self.command.assert_not_called();self.clean.assert_not_called()
    def test_missing_and_tampered_reference_block_released_record_without_fallback(self):
        self.receipt();self.registry.release(self.record,True)
        original=dict(self.record['qualification_service_cleanup'])
        for ref in (None,{'path':original['path'],'sha256':'0'*64},{**original,'extra':True}):
            with self.subTest(ref=ref):
                if ref is None:self.record.pop('qualification_service_cleanup',None)
                else:self.record['qualification_service_cleanup']=ref
                self.registry.write(self.record)
                with self.assertRaises(registry.RegistryError):self.registry.reconcile()
                self.command.assert_not_called();self.clean.assert_not_called()
    def test_recreated_directory_file_or_symlink_blocks_release_and_generic_recovery(self):
        self.receipt();self.registry.release(self.record,True)
        for kind in ('directory','file','symlink'):
            with self.subTest(kind=kind):
                if kind=='directory':self.private.mkdir(mode=0o700)
                elif kind=='file':self.private.write_text('untrusted replacement')
                else:self.private.symlink_to(self.proofs,target_is_directory=True)
                with self.assertRaises(registry.RegistryError):self.registry.reconcile()
                if self.private.is_dir() and not self.private.is_symlink():self.private.rmdir()
                else:self.private.unlink()
        self.command.assert_not_called();self.clean.assert_not_called()
    def test_every_immutable_identity_change_is_rejected(self):
        import copy
        self.receipt();original=copy.deepcopy(self.record)
        mutations={'container_id':'c'*64,'image':'sha256:'+'c'*64,'daemon':'other-daemon','registry':'d'*64,
            'generation':'00000000-0000-4000-8000-000000000000','container':'other-name','runroot':str(self.root/'other'),
            'binding':{'run_id':'other'},'qualification_cell':'other-cell','qualification_role':'scripted-inference','client_mode':'application-execution'}
        for key,value in mutations.items():
            with self.subTest(key=key):
                record=copy.deepcopy(original);record[key]=value
                with self.assertRaises(registry.RegistryError):registry.validate_qualification_service_cleanup(record)
    def test_wrong_role_never_falls_back_even_with_mocked_clean_agent_root(self):
        self.receipt();self.record['status']='released';self.record['qualification_role']='participant';self.registry.write(self.record)
        with mock.patch.object(registry,'_application_stage_pending',return_value=False) as check:
            with self.assertRaises(registry.RegistryError):self.registry.reconcile()
            check.assert_not_called()
        self.command.assert_not_called()
    def test_exact_payload_flags_and_fd_identity_required_even_with_rehashed_file(self):
        import copy
        self.receipt();p=Path(self.record['qualification_service_cleanup']['path']);original=p.read_bytes()
        mutations=[lambda v:v.update(extra=True),lambda v:v.update(physical_absence_confirmed=False),
            lambda v:v.update(private_bootstrap_removed=False),lambda v:v.update(terminal_available=1),
            lambda v:v.update(qualification_eligible=True),lambda v:v['private_mount'].update(inode=True),
            lambda v:v['private_mount'].update(source=str(self.root/'elsewhere'))]
        for change in mutations:
            p.write_bytes(original);self.rewrite_proof(change)
            with self.assertRaises(registry.RegistryError):registry.validate_qualification_service_cleanup(self.record)
    def test_receipt_symlink_hardlink_insecure_mode_and_ancestor_alias_reject(self):
        self.receipt();p=Path(self.record['qualification_service_cleanup']['path']);body=p.read_bytes();ref=dict(self.record['qualification_service_cleanup'])
        p.chmod(0o644)
        with self.assertRaises(registry.RegistryError):registry.validate_qualification_service_cleanup(self.record)
        p.chmod(0o600);other=self.proofs/'hardlink';os.link(p,other)
        with self.assertRaises(registry.RegistryError):registry.validate_qualification_service_cleanup(self.record)
        other.unlink();p.unlink();other.write_bytes(body);other.chmod(0o600);p.symlink_to(other)
        with self.assertRaises(registry.RegistryError):registry.validate_qualification_service_cleanup(self.record)
        p.unlink();p.write_bytes(body);p.chmod(0o600);alias=self.root/'alias';alias.symlink_to(self.proofs,target_is_directory=True)
        with self.assertRaises(registry.RegistryError):registry.validate_qualification_service_cleanup(self.record,{**ref,'path':str(alias/p.name)})
    def test_duplicate_json_fields_and_oversized_receipt_reject(self):
        import hashlib
        self.receipt();p=Path(self.record['qualification_service_cleanup']['path'])
        for body in (b'{"schema":1,"schema":1}',b' '*(65537)):
            p.write_bytes(body);ref={'path':str(p),'sha256':hashlib.sha256(body).hexdigest()}
            with self.assertRaises(registry.RegistryError):registry.validate_qualification_service_cleanup(self.record,ref)
    def test_real_application_record_same_root_still_requires_agent_cleanup_per_record(self):
        import copy,uuid
        self.receipt();self.registry.release(self.record,True)
        real=copy.deepcopy(self.record);real.update(launch_id=str(uuid.uuid4()),client_mode='application-execution')
        for key in ('qualification_role','qualification_cell','qualification_service_cleanup'):real.pop(key)
        self.registry.write(real);self.registry.network_intent('pending-real-application-network')
        with mock.patch.object(registry,'_application_stage_pending',return_value=True) as check:
            with self.assertRaises(registry.RegistryError):self.registry.reconcile()
            check.assert_called_once_with(self.record['runroot'])
        self.command.assert_not_called();self.clean.assert_not_called()
    def test_successful_service_proof_allows_dependent_network_recovery_only_after_all_gates(self):
        self.receipt();self.registry.release(self.record,True)
        network=self.registry.network_intent('service-leftover-network')
        self.command.return_value=type('Reply',(),{'returncode':1,'stdout':'','stderr':'Error response from daemon: network service-leftover-network not found'})()
        self.registry.reconcile();self.assertEqual(next(x for x in self.registry.load() if x['launch_id']==network['launch_id'])['status'],'released')
        self.clean.assert_not_called()
    def test_release_without_positive_receipt_quarantines_subtype(self):
        self.private.rmdir();self.record['status']='absent';self.registry.write(self.record)
        with self.assertRaises(registry.RegistryError):self.registry.release(self.record,True)
        self.assertEqual(self.registry.load()[0]['status'],'quarantined');self.command.assert_not_called()

    def test_legacy_released_application_history_with_no_pending_records_retains_original_semantics(self):
        self.record.update(client_mode='application-execution',status='released')
        for key in ('qualification_role','qualification_cell'):self.record.pop(key)
        self.registry.write(self.record)
        with mock.patch.object(registry,'_application_stage_pending') as check:
            self.assertEqual(self.registry.reconcile(),[]);check.assert_not_called()
        self.command.assert_not_called()
    def test_closed_identity_types_reject_rehashed_boolean_integer_alias(self):
        self.receipt();self.rewrite_proof(lambda value:value['mounts'][0].update(rw=0))
        with self.assertRaises(registry.RegistryError):registry.validate_qualification_service_cleanup(self.record)
    def test_root_alias_and_malformed_public_inputs_reject_with_registry_error(self):
        for path in ('/','//private/alias','/private/../alias','/private/./alias','/private/control\nname'):
            with self.subTest(path=path),self.assertRaises(registry.RegistryError):registry._qualification_path(path)
        for value in (None,[],1,'record'):
            with self.subTest(value=value),self.assertRaises(registry.RegistryError):registry.validate_qualification_service_cleanup(value)
            with self.assertRaises(registry.RegistryError):registry.observe_qualification_private(value)
            with self.assertRaises(registry.RegistryError):registry.write_qualification_service_cleanup(value,self.proofs/'invalid.json',
                private_identity=self.identity,physical_absence_confirmed=True,private_bootstrap_removed=True,terminal_available=False,startup_readied=False)


class QualificationPreworkerTests(unittest.TestCase):
    """Synthetic stopped preworker campaign; no actual Docker or purge evidence."""
    def setUp(self):
        import copy,hashlib,uuid
        import test_application_launch as fixture
        self.fixture=fixture.CampaignCarryTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        f=self.fixture;self.root=f.root;self.registry=f.registry;self.command=mock.Mock();self.clean=mock.Mock()
        self.registry.command=self.command;self.registry.recover_sensitive=self.clean
        self.q=self.root/'successor';self.q.mkdir(mode=0o700)
        self.active={'id':f.active['id'],'pid':2**31-1,'run_id':str(uuid.uuid4()),'attempt_id':str(uuid.uuid4())}
        self.full=copy.deepcopy(f.full);self.full.update(prepared_root=str(self.q),qualification_id=f.current['qualification_id'],predecessor=f.predecessor)
        self.full['source']['files']['tools/qualification/application_client.py']='7f9ad372c65564f34a8e92ccae4d0f250ff99a4b8b23b8ec838b3d4b339c940d'
        self.run=self.q/'scripted-0.87.1/runs'/self.active['run_id'];self.run.mkdir(mode=0o700,parents=True)
        self.stage=str(uuid.uuid4());self.segment=str(uuid.uuid4());self.control=self.run/'controls'/self.stage;self.control.mkdir(mode=0o755,parents=True)
        for name in ('task.json','endpoint.json','stage.json'):f.put(self.control/name,{'public_metadata':name})
        (self.control/'inbox').mkdir();(self.control/'segments'/self.segment).mkdir(parents=True,mode=0o700)
        self.workspace=self.run/'workspace';self.workspace.mkdir();wi=self.workspace.stat();self.workspace.rmdir()
        self.descriptor={'stage_id':self.stage,'kind':'agent','label':'agent-1-participant',
            'run_id':self.active['run_id'],'attempt_id':self.active['attempt_id'],'admission_lock_file':str(self.root/'operation.lock'),
            'control':str(self.control),'workspace':str(self.workspace),'workspace_identity':[wi.st_dev,wi.st_ino]}
        self.descriptor_ref=f.put(self.run/'stages'/self.stage/'descriptor.json',self.descriptor)
        self.stage_ref=f.put(self.run/'stages'/self.stage/'state.json',{'status':'finalized','cleanup_confirmed':False,'segment_id':self.segment})
        self.process_ref=f.put(self.run/'agent-1-participant/process.json',{'cleanup_confirmed':False,'termination_reason':'application_credential_cleanup'})
        self.result_ref=f.put(self.run/'result.json',{'sealed':True,'status':'FAIL','exit_code':1,'agents':[],
            'invocation':{'status':'invalid','attempted_stages':1},'infrastructure':{'phase':'agents','reason':'ApplicationExecutionError'},
            'run_id':self.active['run_id'],'attempt_id':self.active['attempt_id']})
        f.put(self.q/'manifest.json',self.full)
        ledger=fixture.launch.LaunchLedger.create(self.q/'launch-ledger',f.current,daemon_id=f.daemon,daemon_capacity=f.capacity,clock=f.clock,wall=f.wall)
        service_refs=[f.service_reference];states={};self.helper=None
        for cell in sorted(f.current['cells'],key=lambda cell:cell['group']!='N01'):
            if cell['group']!='N01' and cell['id']!=self.active['id']:continue
            roles=cell['role_limits'] if cell['group']=='N01' else {'fixture':1,'scripted-inference':1,'probe':1,'boundary':1,'preflight':1,'application-helper':1}
            states[cell['id']]={'status':'PASS' if cell['group']=='N01' else 'BLOCKED','attempts':1}
            for role in roles:
                launchid=str(uuid.uuid4());cid=hashlib.sha256(launchid.encode()).hexdigest()
                record={'schema':1,'launch_id':launchid,'registry':self.registry.registry_id,'generation':self.registry.generation,
                    'status':'intent','container':'owned-'+launchid,'image':f.current['images']['core-'+cell['release']]['id'] if role in fixture.launch.EXTERNAL else cell['image_id'],
                    'mounts':[],'binding':{'run_id':self.active['run_id'],'attempt_id':self.active['attempt_id']},'daemon':f.daemon,
                    'runroot':str(self.run),'owner_pid':os.getpid()}
                private=None
                if role in ('fixture','scripted-inference'):
                    private=self.root/('second-'+role);private.mkdir(mode=0o700)
                    record.update(application_helper=True,client_mode='qualification-'+role,qualification_role=role,qualification_cell=cell['id'],
                        mounts=[{'source':str(private),'target':'/private','rw':False}])
                if role=='application-helper':
                    private=self.run/'application-helpers'/uuid.uuid4().hex;private.mkdir(mode=0o700,parents=True)
                    record.update(application_helper=True,client_mode='application-execution',private_store=str(private),code_identity={'runtime/service.py':'a'*64})
                    record['mounts']=[{'source':str(private/'code'),'target':'/opt/pi-application','rw':False},
                        {'source':str(private/'state'),'target':'/pi-client/state','rw':True},
                        {'source':str(self.run/'application-evidence'/record['container']),'target':'/pi-client/evidence','rw':True}]
                self.registry.write(record)
                key=ledger.reserve(cell['id'],role,record,fixture.launch._role_weight(f.current,cell,role),{'id':f.daemon,**f.capacity})
                ledger.note(key,pid=123,container_id=cid,physical='absent',private_cleanup=not(cell['group']=='N02' and role in ('probe','boundary','preflight')))
                record.update(status='released',container_id=cid)
                if role in ('fixture','scripted-inference'):
                    record['status']='absent';identity=registry.observe_qualification_private(record);private.rmdir()
                    ref=registry.write_qualification_service_cleanup(record,self.q/(role+'-cleanup.json'),private_identity=identity,
                        physical_absence_confirmed=True,private_bootstrap_removed=True,terminal_available=True,startup_readied=True)
                    record['qualification_service_cleanup']=ref;record['status']='released';service_refs.append(ref)
                if role=='application-helper':private.rmdir();self.helper=record
                self.registry.write(record)
        ledger.poison_scope(self.active['id'],force=True)
        f.put(self.q/'state.json',{'schema':1,'phase':'blocked','active_cell':self.active,'cells':states,'started_at':1000})
        def entry(path):return {'root':str(path),**{k:{'path':str(path/rel),'sha256':hashlib.sha256((path/rel).read_bytes()).hexdigest()}
            for k,rel in [('manifest','manifest.json'),('state','state.json'),('ledger','launch-ledger/ledger.json')]}}
        self.envelope=self.root/'pi-qualification-cell-second';self.envelope.mkdir(mode=0o700);ei=self.envelope.stat();self.envelope.rmdir()
        terminal=f.put(self.q/'terminal.json',{'actual_exit':2,'cwd':str(fixture.ROOT),'argv':['python3','tools/qualification/application_client.py','collect','--root',str(self.q),'--group','N02','--release','0.87.1']})
        invocation=f.put(self.q/'invocation.json',{'argv':['python3',str(fixture.ROOT/'tools/qualification/application_client.py'),'_cell-run','--root',str(self.q),'--cell-id',self.active['id'],'--private-envelope',str(self.envelope/'initial.json')],
            'cwd':str(fixture.ROOT),'classification':'native_scripted_protocol'})
        ci=self.control.stat();allrows=json.loads((f.old/'launch-ledger/ledger.json').read_text())['launches']+json.loads((self.q/'launch-ledger/ledger.json').read_text())['launches']
        self.proof={'qualification':{'lineage':[entry(f.old),entry(self.q)],'cumulative_attempts':19,'participant_segments':0},
            'controller':{'pid':self.active['pid'],'parent_terminal':terminal,'original_invocation':invocation,'pid_absence_observed':True,'provenance':'terminal_parent_and_pid_absence'},
            'stage':{'descriptor':self.descriptor_ref,'state':self.stage_ref,'process':self.process_ref,'result':self.result_ref,'stage_id':self.stage,'segment_id':self.segment,'worker_launch_attempted':False,'application_context_issued':False},
            'private_cleanup':{'helper':{'source':self.helper['private_store'],'provenance':'prior_owned_cleanup','removed':True,'container_id_provenance':'original_guard_ledger'},
                'parent_bootstrap':{'path':str(self.envelope),'device':ei.st_dev,'inode':ei.st_ino,'removed':True},
                'control':{'path':str(self.control),'device':ci.st_dev,'inode':ci.st_ino,'retained_files':[{'path':n,'sha256':hashlib.sha256((self.control/n).read_bytes()).hexdigest(),'bytes':(self.control/n).stat().st_size} for n in ('endpoint.json','stage.json','task.json')],
                    'directories':['inbox','segments','segments/'+self.segment],'private_contexts_absent':True,'all_parent_authorities_scanned':True},
                'workspace':{'path':str(self.workspace),'device':wi.st_dev,'inode':wi.st_ino,'status':'discarded','provenance':'original_descriptor','all_parent_authorities_scanned':True}},
            'launches':[{**{k:row[k] for k in ('registry','generation','launch_id','container_id')},'physical_absence_confirmed':True,'private_cleanup_confirmed':True} for row in allrows],
            'service_receipts':service_refs}
        self.proofs=self.root/'owner-proof';self.proofs.mkdir(mode=0o700)
    def write(self):
        ref=registry.write_qualification_preworker_cleanup(self.helper,self.proofs/'preworker.json',proof=self.proof)
        self.helper['qualification_preworker_cleanup']=ref;self.registry.write(self.helper);return ref
    def test_positive_closed_owner_sidecar_preserves_old_failure_and_unblocks_only_its_record(self):
        originals={str(p):p.read_bytes() for p in [Path(self.stage_ref['path']),Path(self.result_ref['path']),Path(self.process_ref['path'])]}
        self.write();receipt=registry.validate_qualification_preworker_cleanup(self.helper)
        self.assertEqual(receipt['qualification']['cumulative_attempts'],19);self.assertFalse(receipt['stage']['worker_launch_attempted'])
        self.assertEqual(self.registry.reconcile(),[]);self.command.assert_not_called();self.clean.assert_not_called()
        self.assertEqual({p:Path(p).read_bytes() for p in originals},originals)
    def test_participant_or_issued_context_claims_and_wrong_scope_cannot_be_rehashed_into_positive(self):
        import copy
        original=copy.deepcopy(self.proof)
        changes=[lambda p:p['stage'].update(worker_launch_attempted=True),lambda p:p['stage'].update(application_context_issued=True),
            lambda p:p['qualification'].update(cumulative_attempts=0),lambda p:p['qualification'].update(participant_segments=1),
            lambda p:p['private_cleanup']['workspace'].update(provenance='fresh_observation'),lambda p:p['launches'].pop(),
            lambda p:p['launches'][0].update(container_id='f'*64),lambda p:p['service_receipts'].pop()]
        for change in changes:
            self.proof=copy.deepcopy(original);change(self.proof)
            with self.subTest(change=change),self.assertRaises(registry.RegistryError):self.write()
            self.assertFalse((self.proofs/'preworker.json').exists())
        self.command.assert_not_called()
    def test_historical_failure_hash_and_retained_metadata_cannot_change(self):
        for path in (Path(self.result_ref['path']),self.control/'endpoint.json'):
            body=path.read_bytes();path.write_bytes(body+b' ')
            with self.subTest(path=path),self.assertRaises(registry.RegistryError):self.write()
            path.write_bytes(body)
    def test_private_context_leaf_or_extra_control_file_denies_before_effects(self):
        for path in (self.control/'segments'/self.segment/'application-context.json',self.control/'unexpected.json'):
            path.write_text('synthetic private metadata')
            with self.subTest(path=path),self.assertRaises(registry.RegistryError):self.write()
            path.unlink()
        self.command.assert_not_called()
    def test_recreated_helper_parent_envelope_or_discarded_workspace_denies(self):
        for path in (Path(self.helper['private_store']),self.envelope,self.workspace):
            path.mkdir(mode=0o700)
            with self.subTest(path=path),self.assertRaises(registry.RegistryError):self.write()
            path.rmdir()
    def test_live_controller_false_absence_or_immutable_record_change_denies(self):
        with mock.patch.object(registry.os,'kill',return_value=None),self.assertRaises(registry.RegistryError):self.write()
        self.proof['launches'][0]['physical_absence_confirmed']=False
        with self.assertRaises(registry.RegistryError):self.write()
        self.proof['launches'][0]['physical_absence_confirmed']=True
        self.helper['code_identity']['runtime/service.py']='b'*64;self.registry.write(self.helper)
        with self.assertRaises(registry.RegistryError):self.write()
    def test_pending_helper_never_uses_positive_sidecar_and_real_same_root_helper_still_blocks(self):
        import copy,uuid
        self.write();self.helper['status']='absent';self.registry.write(self.helper)
        with self.assertRaises(registry.RegistryError):self.registry.reconcile()
        self.command.assert_not_called();self.helper['status']='released';self.registry.write(self.helper)
        real=copy.deepcopy(self.helper);real['launch_id']=str(uuid.uuid4());real.pop('qualification_preworker_cleanup');self.registry.write(real)
        self.registry.network_intent('pending-unrelated-network')
        with self.assertRaises(registry.RegistryError):self.registry.reconcile()
        self.command.assert_not_called()
    def test_sidecar_reference_missing_tampered_symlink_or_recreated_fd_control_fails(self):
        self.write();reference=self.helper['qualification_preworker_cleanup'];path=Path(reference['path'])
        self.helper['qualification_preworker_cleanup']={**reference,'sha256':'0'*64};self.registry.write(self.helper)
        with self.assertRaises(registry.RegistryError):self.registry.reconcile()
        self.helper['qualification_preworker_cleanup']=reference;self.registry.write(self.helper)
        body=path.read_bytes();copy=path.with_name('copy.json');copy.write_bytes(body);copy.chmod(0o600);path.unlink();path.symlink_to(copy)
        with self.assertRaises(registry.RegistryError):self.registry.reconcile()
        self.command.assert_not_called()

    def test_rehashed_participant_ledger_or_deadline_reset_and_false_fd_claim_are_rejected(self):
        import copy,hashlib
        original=copy.deepcopy(self.proof);entry=self.proof['qualification']['lineage'][-1];path=Path(entry['ledger']['path']);body=path.read_bytes()
        for mutation in ('participant','deadline'):
            data=json.loads(body)
            if mutation=='participant':data['launches'][-1]['role']='participant'
            else:data['deadline']+=100;data['deadline_wall']+=100
            path.write_text(json.dumps(data));self.proof=copy.deepcopy(original)
            self.proof['qualification']['lineage'][-1]['ledger']['sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
            with self.subTest(mutation=mutation),self.assertRaises(registry.RegistryError):self.write()
        path.write_bytes(body);self.proof=copy.deepcopy(original);self.proof['private_cleanup']['helper']['removed']=1
        with self.assertRaises(registry.RegistryError):self.write()
    def test_retained_public_755_644_modes_are_valid_but_group_writable_metadata_denies(self):
        self.control.chmod(0o755)
        for child in self.control.iterdir():child.chmod(0o755 if child.is_dir() else 0o644)
        self.write();self.assertEqual(registry.validate_qualification_preworker_cleanup(self.helper)['stage']['stage_id'],self.stage)
        (self.control/'task.json').chmod(0o664)
        with self.assertRaises(registry.RegistryError):registry.validate_qualification_preworker_cleanup(self.helper)

    def test_original_helper_record_missing_id_needs_exact_owner_late_binding_before_sidecar(self):
        import hashlib
        ledger=Path(self.proof['qualification']['lineage'][-1]['ledger']['path']);before=ledger.read_bytes()
        identifier=self.helper.pop('container_id');self.registry.write(self.helper)
        with self.assertRaises(registry.RegistryError):self.write()
        self.assertFalse((self.proofs/'preworker.json').exists())
        # Trusted owner verified this exact original frozen ledger ID externally;
        # this controlled test records no native observation or actual recovery.
        row=next(x for x in json.loads(before)['launches'] if x['launch_id']==self.helper['launch_id'])
        self.assertEqual(identifier,row['container_id']);self.helper['container_id']=row['container_id'];self.registry.write(self.helper)
        self.write();self.assertEqual(ledger.read_bytes(),before)
        self.assertEqual(registry.validate_qualification_preworker_cleanup(self.helper)['private_cleanup']['helper']['container_id_provenance'],'original_guard_ledger')


class ApplicationHelperImmutableAbsenceTests(unittest.TestCase):
    def setUp(self):
        self.fixture=RegistryTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.registry=self.fixture.registry;self.record,_=self.fixture.intent();self.record['application_helper']=True
    def test_missing_or_malformed_id_never_uses_name_absence(self):
        for identifier in (None,'','a'*63,'f'*65,True,'foreign-name'):
            with self.subTest(identifier=identifier):
                self.record['container_id']=identifier;self.registry.write(self.record)
                self.assertFalse(self.registry.confirm_absent(self.record));self.fixture.command.assert_not_called()
                self.assertEqual(self.record['status'],'quarantined')
    def test_exact_bound_id_absence_only_and_foreign_error_cannot_release(self):
        self.record['container_id']='b'*64;self.registry.write(self.record)
        for stderr,expected in [('No such container',False),('No such container: '+'c'*64,False),('daemon unavailable',False),('Error: No such object: '+'b'*64,True)]:
            with self.subTest(stderr=stderr):
                self.fixture.command.return_value=self.fixture.reply(1,error=stderr)
                self.assertIs(self.registry.confirm_absent(self.record),expected)
                self.assertEqual(self.fixture.command.call_args.args[0],['docker','container','inspect','b'*64])
    def test_legacy_non_application_record_still_observes_name(self):
        self.record.pop('application_helper');self.fixture.command.return_value=self.fixture.reply(1,error='No such container')
        self.assertTrue(self.registry.confirm_absent(self.record))
        self.assertEqual(self.fixture.command.call_args.args[0],['docker','container','inspect',self.record['container']])
