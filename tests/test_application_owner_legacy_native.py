"""Fresh owner observations in disposable registries; no live Docker or campaign."""
import contextlib
import errno
import importlib
import os
from pathlib import Path
import subprocess
import sys
import unittest
import uuid
from unittest import mock

from tests.test_application_owner_legacy_support import AcceptanceFixture, LegacyContractTests
from tests import test_application_owner_legacy_namespace as namespace_fixtures
import application_owner_cleanup as cleanup
import ownership_registry as ownership
import registry_maintenance as maintenance

REAL_POPEN = subprocess.Popen


class LegacyNativeTests(LegacyContractTests):
    def setUp(self):
        super().setUp()
        self.lease=self.root/'lease';self.lease.write_text('synthetic original lease\n');self.lease.chmod(0o600)
        self.calls=[];self.hook=None;self.registry_ids=''
        self.owner=ownership.Registry(Path(str(self.lease)+'.registry'),command=self.command)
        self.owner.bind_daemon('synthetic-daemon')
        self.fixture=self.build();self.owner.write(self.fixture.record)
        patch=mock.patch.object(os,'kill',side_effect=ProcessLookupError(errno.ESRCH,'synthetic absent PID'))
        self.kill=patch.start();self.addCleanup(patch.stop)

    def build(self,name='case',**kwargs):
        return AcceptanceFixture(self.root/name,registry_id=self.owner.registry_id,generation=self.owner.generation,**kwargs)

    def artifact(self,name='artifact'):
        return namespace_fixtures.LegacyNamespaceTests.artifact(self,name)

    @staticmethod
    def reply(code,out='',err=''):
        return subprocess.CompletedProcess([],code,out,err)

    def command(self,argv):
        self.calls.append(list(argv))
        if self.hook:self.hook(argv)
        if argv==['docker','info','--format','{{.ID}}']:return self.reply(0,'synthetic-daemon\n')
        if argv[:3]==['docker','container','inspect']:
            self.assertEqual(argv[3:5],['--format','{{.Id}}'])
            return self.reply(1,'','Error response from daemon: No such container: '+argv[-1])
        if argv[:2]==['docker','ps']:
            wide=len(argv)==7 and argv[-1]=='label='+ownership.REGISTRY_LABEL+'='+self.owner.registry_id
            return self.reply(0,self.registry_ids if wide else '')
        raise AssertionError('Effectful or unreviewed Docker command: '+repr(argv))

    @contextlib.contextmanager
    def held(self):
        with maintenance.existing_lease(self.lease) as (fd,unused,selected):
            self.owner.lease_fd=fd;yield

    def observe(self,expected=None):
        native=importlib.import_module('application_owner_legacy_native')
        legacy=importlib.import_module('application_owner_legacy')
        family=self.fixture.family()
        profile=next(iter(family.values()))
        if profile['binding_format']=='artifact_diagnostic_v1':profile['execution_rule']='absolute_owned_host_paths_v1'
        with mock.patch.dict(legacy.SOURCE_FAMILIES,family,clear=True),self.held():
            return native.observe(self.owner,self.fixture.request(),expected=expected)

    def foreign(self,source,*,rw=True,runroot=None,cid='f'*64):
        row={'schema':1,'launch_id':str(uuid.uuid4()),'generation':str(uuid.uuid4()),'registry':self.owner.registry_id,
            'status':'running','container':'pi-other-synthetic','image':'sha256:'+'e'*64,'container_id':cid,
            'daemon':'synthetic-daemon','runroot':str(runroot or self.root/'other'),
            'mounts':[{'source':str(source),'target':'/workspace','rw':rw}]}
        self.owner.write(row);return row

    def test_complete_observation_preserves_records_inputs_and_private_files(self):
        before=self.fixture.bytes_snapshot();primary=self.owner.load()
        result=self.observe()
        self.assertEqual(result['lease'],{'device':self.lease.stat().st_dev,'inode':self.lease.stat().st_ino})
        self.assertEqual(result['plan']['status'],'eligible_for_native_checks')
        self.assertEqual(self.fixture.bytes_snapshot(),before);self.assertEqual(self.owner.load(),primary)
        self.assertTrue(self.calls);self.assertTrue(all(call.args[1]==0 for call in self.kill.call_args_list))

    def test_unknown_wait_blocks_before_native_metadata(self):
        self.fixture.rewrite('launcher-terminal.json',lambda body:body.update(wait_confirmed=False,unknown_owned_child=True))
        with self.assertRaises(ownership.RegistryError):self.observe()
        self.assertEqual(self.calls,[]);self.kill.assert_not_called()

    def test_bound_metadata_supervisor_must_also_be_absent(self):
        parent=self.fixture.owner_pid-2
        self.fixture.rewrite('controller-start.json',lambda body:body.update(wrapper_pid=parent))
        self.fixture.rewrite('controller-verification.json',lambda body:body.update(wrapper_pid=parent))
        def probe(pid,signal):
            if pid==parent:return None
            raise ProcessLookupError(errno.ESRCH,'synthetic absent PID')
        self.kill.side_effect=probe
        with self.assertRaises(ownership.RegistryError):self.observe()
        self.assertEqual(self.calls,[])

    def test_registry_namespace_must_remain_private_before_observation(self):
        self.owner.root.chmod(0o755)
        try:
            with self.assertRaises(ownership.RegistryError):self.observe()
            self.assertEqual(self.calls,[])
        finally:self.owner.root.chmod(0o700)

    def test_default_registry_commands_route_through_bounded_private_runner(self):
        native=importlib.import_module('application_owner_legacy_native')
        for command in (ownership.docker,cleanup._owner_docker):
            with self.subTest(command=command.__name__),mock.patch.object(self.owner,'command',command),mock.patch.object(native,'docker',side_effect=self.command) as bounded:
                self.observe();self.assertTrue(bounded.called)

    def test_alive_reused_or_unobservable_pid_blocks_without_signalling(self):
        for effect in (None,PermissionError(errno.EPERM,'synthetic'),OSError(errno.EIO,'synthetic')):
            with self.subTest(effect=type(effect).__name__):
                self.kill.side_effect=effect;self.calls.clear()
                with self.assertRaises(ownership.RegistryError):self.observe()
                self.assertEqual(self.calls,[])
        self.assertTrue(all(call.args[1]==0 for call in self.kill.call_args_list))

    def test_wrong_daemon_blocks_before_target_inspection(self):
        native=importlib.import_module('application_owner_legacy_native')
        with mock.patch.object(self.owner,'command',return_value=self.reply(0,'another-daemon\n')):
            with self.assertRaises(ownership.RegistryError):self.observe()
        self.assertTrue(self.fixture.private.exists())

    def test_access_denied_inspect_is_not_absence(self):
        original=self.owner.command
        def command(argv):
            return self.reply(1,'','permission denied') if argv[:3]==['docker','container','inspect'] else original(argv)
        with mock.patch.object(self.owner,'command',side_effect=command):
            with self.assertRaises(ownership.RegistryError):self.observe()

    def test_existing_cid_or_name_blocks_even_with_empty_label_queries(self):
        original=self.owner.command
        for target in (self.fixture.cid,self.fixture.record['container']):
            def command(argv):
                return self.reply(0,self.fixture.cid+'\n') if argv[:3]==['docker','container','inspect'] and argv[-1]==target else original(argv)
            with self.subTest(target=target),mock.patch.object(self.owner,'command',side_effect=command):
                with self.assertRaises(ownership.RegistryError):self.observe()

    def test_renamed_or_unregistered_labelled_container_blocks(self):
        original=self.owner.command
        def command(argv):
            return self.reply(0,'c'*64+'\n') if argv[:2]==['docker','ps'] else original(argv)
        with mock.patch.object(self.owner,'command',side_effect=command):
            with self.assertRaises(ownership.RegistryError):self.observe()

    def test_registry_label_inventory_rejects_unknown_and_released_resources(self):
        self.registry_ids='c'*64+'\n'
        with self.assertRaises(ownership.RegistryError):self.observe()
        other=self.foreign(self.root/'unrelated');other['status']='released';self.owner.write(other)
        self.registry_ids=other['container_id']+'\n'
        with self.assertRaises(ownership.RegistryError):self.observe()

    def test_readonly_or_aliased_pending_holder_blocks_before_native_calls(self):
        alias=self.root/'alias';alias.symlink_to(self.fixture.private,target_is_directory=True)
        self.foreign(alias,rw=False)
        with self.assertRaises(ownership.RegistryError):self.observe()
        self.assertEqual(self.calls,[]);self.assertTrue(self.fixture.private.exists())

    def test_disjoint_pending_registered_container_is_allowed(self):
        self.foreign(self.root/'unrelated');self.registry_ids='f'*64+'\n'
        self.observe()

    def test_new_holder_or_changed_record_during_observation_blocks(self):
        changed=[]
        def hook(argv):
            if not changed:
                changed.append(True);self.foreign(self.fixture.private,rw=False)
        self.hook=hook
        with self.assertRaises(ownership.RegistryError):self.observe()
        self.assertTrue(self.fixture.private.exists())

    def test_writer_reappearance_during_final_daemon_check_is_not_cached_away(self):
        info=[0]
        def hook(argv):
            if argv==['docker','info','--format','{{.ID}}']:
                info[0]+=1
                if info[0]==2:self.kill.side_effect=None
        self.hook=hook
        with self.assertRaises(ownership.RegistryError):self.observe()

    def test_replaced_registry_directory_with_copied_records_still_denies(self):
        changed=[]
        def hook(argv):
            if not changed:
                changed.append(True);original=self.owner.root
                original.rename(self.root/'saved-registry');original.mkdir(mode=0o700)
                for source in (self.root/'saved-registry').glob('*.json'):
                    target=original/source.name;target.write_bytes(source.read_bytes());target.chmod(0o600)
        self.hook=hook
        with self.assertRaises(ownership.RegistryError):self.observe()

    def test_alias_retarget_during_native_observation_is_rechecked(self):
        outside=self.root/'outside';outside.mkdir(mode=0o700)
        alias=self.root/'alias';alias.symlink_to(outside,target_is_directory=True)
        self.foreign(alias,rw=False)
        changed=[]
        def hook(argv):
            if not changed:
                changed.append(True);alias.unlink();alias.symlink_to(self.fixture.private,target_is_directory=True)
        self.hook=hook
        with self.assertRaises(ownership.RegistryError):self.observe()

    def test_original_lease_replacement_during_observation_blocks(self):
        changed=[]
        def hook(argv):
            if not changed:
                changed.append(True);self.lease.rename(self.root/'saved-lease')
                self.lease.write_text('replacement\n');self.lease.chmod(0o600)
        self.hook=hook
        with self.assertRaises(ownership.RegistryError):self.observe()

    def test_missing_original_lease_fd_never_creates_native_calls(self):
        native=importlib.import_module('application_owner_legacy_native')
        with self.assertRaises(ownership.RegistryError):native.observe(self.owner,self.fixture.request())
        self.assertEqual(self.calls,[])

    def test_reobservation_cannot_reuse_previous_writer_absence(self):
        previous=self.observe();self.calls.clear();self.kill.side_effect=None
        with self.assertRaises(ownership.RegistryError):self.observe(previous)
        self.assertEqual(self.calls,[])

    def test_operation_request_is_frozen_before_native_callbacks(self):
        native=importlib.import_module('application_owner_legacy_native')
        legacy=importlib.import_module('application_owner_legacy')
        request=self.fixture.request();original_shape=request['shape']
        def hook(argv):request['shape']='interrupted'
        self.hook=hook
        with mock.patch.dict(legacy.SOURCE_FAMILIES,self.fixture.family(),clear=True),self.held():
            observed=native.observe(self.owner,request)
        self.assertEqual(observed['commitment']['request']['shape'],original_shape)

    def test_reobservation_rejects_changed_discard_inode(self):
        previous=self.observe();self.fixture.private.rename(self.root/'saved-private')
        self.fixture.private.mkdir(mode=0o700)
        with self.assertRaises(ownership.RegistryError):self.observe(previous)

    def test_diagnostic_shared_parent_does_not_claim_unrelated_sibling(self):
        self.fixture=namespace_fixtures.LegacyNamespaceTests.full_artifact(self)
        self.owner.write(self.fixture.record)
        sibling=Path(self.fixture.record['runroot'])/'unrelated-campaign-child'
        self.foreign(sibling,runroot=sibling)
        result=self.observe()
        self.assertNotIn(self.fixture.record['runroot'],result['plan']['retained_roots'])


class BoundedDockerTests(unittest.TestCase):
    def spawn(self,code):
        self.processes=[]
        def popen(argv,**kwargs):
            self.spawn_kwargs=kwargs
            child=REAL_POPEN([sys.executable,'-I','-B','-c',code],**kwargs);self.processes.append(child);return child
        return mock.patch.object(subprocess,'Popen',side_effect=popen)

    def test_closed_metadata_command_uses_restricted_environment_and_drains_both_streams(self):
        native=importlib.import_module('application_owner_legacy_native')
        with self.spawn("import sys;sys.stdout.write('synthetic-daemon\\n');sys.stderr.write('metadata\\n')"),mock.patch.dict(os.environ,{'PI_API_KEY':'SYNTHETIC_SECRET','PI_APP_TEST':'SYNTHETIC_SECRET'}):
            result=native.docker(['docker','info','--format','{{.ID}}'])
        self.assertEqual(result.returncode,0);self.assertEqual(result.stdout,'synthetic-daemon\n')
        self.assertNotIn('PI_API_KEY',self.spawn_kwargs['env']);self.assertNotIn('PI_APP_TEST',self.spawn_kwargs['env'])
        self.assertTrue(all(child.poll() is not None for child in self.processes))

    def test_unbounded_output_and_timeout_fail_and_reap_only_the_owned_cli(self):
        native=importlib.import_module('application_owner_legacy_native')
        cases=[("import sys;sys.stdout.write('x'*2097152);sys.stdout.flush()",ownership.RegistryError),
               ("import time;time.sleep(10)",subprocess.TimeoutExpired)]
        for code,error in cases:
            timeout=0.25 if error is subprocess.TimeoutExpired else 15
            with self.subTest(error=error.__name__),self.spawn(code),mock.patch.object(native,'COMMAND_SECONDS',timeout):
                with self.assertRaises(error):native.docker(['docker','info','--format','{{.ID}}'])
                self.assertTrue(all(child.poll() is not None for child in self.processes))

    def test_effectful_or_arbitrary_command_rejected_before_spawn(self):
        native=importlib.import_module('application_owner_legacy_native')
        for argv in (['docker','stop','x'],['docker','container','inspect','x'],['sh','-c','anything']):
            with self.subTest(argv=argv),mock.patch.object(subprocess,'Popen',side_effect=AssertionError('spawn forbidden')):
                with self.assertRaises(ownership.RegistryError):native.docker(argv)
