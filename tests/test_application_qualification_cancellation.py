"""Controlled cancellation with real lease/Registry/launch ledger, fake Docker.

No container, worker, model, API or subprocess is launched. Parent-owned stage
receipts are nonsecret fixtures; actual Registry.close and qualification release
hooks, rather than a mocked assert_cell_released, decide ordinary worker release.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime'),str(ROOT/'tools/qualification')]
import ownership_registry
import resources
import stage_control as controls
spec=importlib.util.spec_from_file_location('qualification_cancellation_harness',ROOT/'tools/qualification/application_client.py')
harness=importlib.util.module_from_spec(spec);spec.loader.exec_module(harness)
launch=harness._launch_module()


def fresh():return str(uuid.uuid4())


class Process:
    def __init__(self,pid):self.pid=pid;self.returncode=0
    def poll(self):return self.returncode
    def wait(self,timeout=None):return self.returncode


class ControlledCancellationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name).resolve();self.root=self.base/'qualification';self.root.mkdir(mode=0o700)
        self.initial={'run_id':fresh(),'attempt_id':fresh(),'trial_id':fresh()}
        images={}
        for index,(release,profile) in enumerate((('0.87.1','core'),('0.87.1','browser'),('1.2.0','core'),('1.2.0','browser')),1):
            images[profile+'-'+release]={'id':'sha256:'+str(index)*64,'platform':'linux/arm64','capabilities':{'pi':release}}
        self.manifest={'qualification_id':fresh(),'images':images,'cells':harness.matrix(images)}
        self.cell=next(row for row in self.manifest['cells'] if row.get('scenario')=='sensitive-participant-interruption')
        policy=harness._launch_manifest(self.manifest)
        self.ledger=launch.LaunchLedger.create(self.root/'launch-ledger',policy,daemon_id='NONSECRET_DAEMON',
            daemon_capacity={'cpu_millis':18000,'memory_mib':16384})
        self.runroot=self.root/'runs'/self.initial['run_id'];self.runroot.mkdir(parents=True,mode=0o700)
        self.args=SimpleNamespace(lock_file=str(self.base/'operation.lock'),lock_wait_seconds=0,
            _attempt_root=self.runroot,_attempt_identity={k:self.initial[k] for k in ('run_id','attempt_id')})
        self.image=images['core-0.87.1']['id'];self.registry=None;self.guard=None;self.services=None
        self.observations={};self.absent=set();self.effects=[];self.events=[]
        self.error=KeyboardInterrupt('NONSECRET_CONTROLLED_INTERRUPTION')
        self.scope=harness._ControlledCancellation(self.root,self.manifest,self.cell,self.initial,[])
        self.patchers=[]
        for target,name in ((subprocess,'Popen'),(subprocess,'run'),(socket,'socket')):
            patcher=mock.patch.object(target,name,side_effect=AssertionError('OFFLINE_ONLY_NO_NATIVE_EFFECT'))
            patcher.start();self.patchers.append(patcher)
        self.addCleanup(lambda:[p.stop() for p in reversed(self.patchers)])
        patcher=mock.patch.object(harness,'_cell_args',return_value=SimpleNamespace(results_dir=str(self.runroot.parent)))
        patcher.start();self.patchers.append(patcher)
        harness.atomic(self.root/'state.json',{'schema':1,'phase':'collecting','started_at':None,
            'active_cell':{'id':self.cell['id'],'pid':os.getpid(),**{k:self.initial[k] for k in ('run_id','attempt_id')}},
            'cells':{self.cell['id']:{'status':'started','attempts':1,**{k:self.initial[k] for k in ('run_id','attempt_id')}}}})

    def command(self,argv,timeout=None):
        if argv[1:2]==['info']:
            value={'ID':'NONSECRET_DAEMON','NCPU':18,'MemTotal':16384*1048576,'Architecture':'aarch64','OSType':'linux'}
        elif argv[1:3]==['image','inspect']:
            value=[{'Id':argv[-1],'Architecture':'arm64','Os':'linux'}]
        elif argv[1:3] in (['container','inspect'],['inspect',argv[-1]]):
            observed=self.observations.get(argv[-1])
            if observed is None or observed['Id'] in self.absent:
                return subprocess.CompletedProcess(argv,1,'','No such container: '+argv[-1])
            value=[observed]
        else:raise AssertionError('UNREVIEWED_FAKE_DOCKER_ROUTE')
        return subprocess.CompletedProcess(argv,0,json.dumps(value),'')

    def executor(self,argv,*args,**kwargs):
        options=launch._options(argv)[1];name=options['--name'][0]
        record=next(row for row in self.registry.load() if row['container']==name)
        observed={'Id':hashlib.sha256(name.encode()).hexdigest(),'Image':record['image'],
            'Config':{'Labels':{launch.LABEL:record['launch_id'],launch.REGISTRY_LABEL:record['registry']}},'Mounts':[]}
        self.observations[name]=self.observations[observed['Id']]=observed
        self.effects.append(argv)
        return Process(10000+len(self.effects))

    def factory(self,registry):
        self.registry=registry;registry.bind_daemon('NONSECRET_DAEMON');registry.command=self.command
        registry.binding['trial_id']=self.initial['trial_id']
        self.services=harness.OwnedServices(self.root,self.manifest,self.cell,self.args,registry,self.guard,[])
        # External services are intentionally absent in this orchestration-only
        # fixture. Their original empty close path still writes its real receipt.
        self.services.start=lambda:self.events.append('service_start')
        return self.services

    def worker_rows(self):
        for operation in ('probe','boundary','preflight','agent'):
            name='pi-lab-'+uuid.uuid4().hex[:12]
            argv=['docker','run','--name',name,'--platform','linux/arm64','--cpus','1','--memory','1g',
                '--memory-swap','1g','--pids-limit','256','--entrypoint=python3','--pull=never',
                self.image,'/opt/pi-lab/worker.py',operation]
            record,labelled=self.registry.intent(argv,name)
            self.guard.popen(labelled)
            row=next(row for row in self.ledger.snapshot()['launches'] if row['launch_id']==record['launch_id'])
            self.absent.add(row['container_id'])
            self.assertTrue(self.registry.confirm_absent(record))

    def stage_receipts(self):
        (self.runroot/'workspace').mkdir(mode=0o700)
        harness.atomic(self.runroot/'identity.json',{'schema':2,**{key:self.initial[key] for key in ('run_id','attempt_id')}})
        stage_id,segment_id=fresh(),fresh();control=self.runroot/'controls'/stage_id
        control.mkdir(parents=True,mode=0o700);runtime=self.runroot/'children/.pi-lab'/stage_id
        runtime.mkdir(parents=True,mode=0o700)
        desc=controls.create(self.runroot,self.runroot/'workspace','agent-1-participant','agent',None,
            control,runtime,stage_id,'NONSECRET_PARTICIPANT',self.args.lock_file)
        controls.transition(self.runroot,desc,'running',segment_id=segment_id)
        controls.transition(self.runroot,desc,'stopping')
        controls.transition(self.runroot,desc,'stopped',exit_code=130,cleanup_confirmed=True)
        controls.transition(self.runroot,desc,'finalized')
        marker=harness._handoff_marker_value(self.manifest,self.cell,self.initial,desc,
            {**{key:self.initial[key] for key in ('run_id','attempt_id')},'stage_id':stage_id,'segment_id':segment_id},os.getpid())
        harness.atomic(self.root/'cells'/self.cell['id']/'participant-handoff.json',marker)
        credential={'schema':1,'status':'removed','workspace':'clean'}
        self.process={'exit_code':130,'cancelled':True,'timed_out':False,'cleanup_confirmed':True,
            'application_helper_cleanup':{'schema':1,'status':'removed','workspace':'clean','safe_to_continue':True},
            'application_credentials':credential,'native_tool_budget':{'accounting':'available'},
            'application_completion':{'status':'not_evaluated'}}
        self.process_path=self.runroot/'agent-1-participant/process.json';self.process_path.parent.mkdir(mode=0o700)
        harness.atomic(self.process_path,self.process)
        harness.atomic(self.runroot/'stages'/stage_id/'application-credentials.json',credential)
        self.stage_id=stage_id

    def controlled(self,change=None,scope=True):
        with launch.instrument(self.ledger,self.cell['id'],original_popen=self.executor,
                command=self.command,observe_command=self.command) as guard:
            self.guard=guard
            with self.assertRaises(KeyboardInterrupt) as caught:
                with harness.actual_lease(self.args,self.factory,_cancellation=self.scope if scope else None):
                    self.worker_rows();self.stage_receipts()
                    if change:change()
                    raise self.error
            self.assertIs(caught.exception,self.error)
            return self.ledger.snapshot()

    def test_known_controlled_cancellation_runs_real_original_close_release_hooks(self):
        snapshot=self.controlled()
        self.assertEqual(len(self.effects),4)
        self.assertEqual(snapshot['live'],0);self.assertEqual(snapshot['private_cleanup_pending'],0)
        self.assertFalse(snapshot['poisoned']);self.ledger.assert_cell_released(self.cell['id'])
        self.assertTrue(all(row['status']=='released' for row in self.registry.load()))
        self.assertIsNone(ownership_registry.CURRENT.get())

    def test_without_child_scope_original_exception_does_not_release_workers(self):
        snapshot=self.controlled(scope=False)
        self.assertEqual(snapshot['private_cleanup_pending'],4)
        with self.assertRaises(launch.LaunchError):self.ledger.assert_cell_released(self.cell['id'])

    def test_pre_handoff_cancellation_keeps_all_worker_private_flags_pending(self):
        def change():(self.root/'cells'/self.cell['id']/'participant-handoff.json').unlink()
        self.assertEqual(self.controlled(change)['private_cleanup_pending'],4)

    def test_unknown_credential_or_helper_cleanup_is_not_deferred(self):
        for key in ('application_credentials','application_helper_cleanup'):
            with self.subTest(key=key):
                # Each test owns one real ledger/lease; independent instances
                # below prevent stale records from acting as fresh fixtures.
                fixture=type(self)('runTest');fixture.setUp()
                try:
                    def change():
                        fixture.process[key]['status']='cleanup_unconfirmed'
                        harness.atomic(fixture.process_path,fixture.process)
                    self.assertEqual(fixture.controlled(change)['private_cleanup_pending'],4)
                finally:fixture.doCleanups()

    def test_helper_close_failure_preserves_same_interrupt_and_pending_workers(self):
        def change():
            self.services.close=lambda:(_ for _ in ()).throw(ValueError('NONSECRET_CLEANUP_FAILURE'))
        self.assertEqual(self.controlled(change)['private_cleanup_pending'],4)

    def test_wrong_owner_or_finalized_stage_identity_does_not_defer(self):
        def change():
            path=self.root/'cells'/self.cell['id']/'participant-handoff.json'
            marker=harness.read(path);marker['owner_pid']+=1;harness.atomic(path,marker)
        self.assertEqual(self.controlled(change)['private_cleanup_pending'],4)

    def test_pending_sensitive_context_denies_even_with_clean_boolean_receipts(self):
        def change():
            path=self.runroot/'controls'/self.stage_id/'segments'/fresh();path.mkdir(parents=True,mode=0o700)
            harness.atomic(path/'application-context.json',{'NONSECRET_FIXTURE':True})
        self.assertEqual(self.controlled(change)['private_cleanup_pending'],4)

    def test_original_registry_close_failure_cannot_become_successful_cancellation(self):
        with self.assertRaises(resources.AdmissionError) as caught:
            with launch.instrument(self.ledger,self.cell['id'],original_popen=self.executor,
                    command=self.command,observe_command=self.command) as guard:
                self.guard=guard
                with mock.patch.object(ownership_registry.Registry,'close',side_effect=ownership_registry.RegistryError('NONSECRET_CLOSE_FAILURE')):
                    with harness.actual_lease(self.args,self.factory,_cancellation=self.scope):
                        self.worker_rows();self.stage_receipts();raise self.error
        self.assertEqual(resources.admission_diagnostic(caught.exception)['reason'],'host-registry-unsafe')
        snapshot=self.ledger.snapshot();self.assertEqual(snapshot['private_cleanup_pending'],4)
        self.assertTrue(snapshot['poisoned']);self.assertIsNone(ownership_registry.CURRENT.get())

    def test_normal_exit_still_closes_original_registry_without_cancellation_scope(self):
        with launch.instrument(self.ledger,self.cell['id'],original_popen=self.executor,
                command=self.command,observe_command=self.command) as guard:
            self.guard=guard
            with harness.actual_lease(self.args,self.factory):self.worker_rows()
            guard.assert_cell_released()
        self.assertEqual(self.ledger.snapshot()['private_cleanup_pending'],0)

    def test_startup_and_second_interruption_fail_closed(self):
        primary=ValueError('NONSECRET_STARTUP_FAILURE')
        def factory(registry):
            value=self.factory(registry)
            value.start=lambda:(_ for _ in ()).throw(primary)
            return value
        with self.assertRaises(ValueError) as caught:
            with harness.actual_lease(self.args,factory,_cancellation=self.scope):self.fail('No participant after startup failure')
        self.assertIs(caught.exception,primary);self.assertEqual(self.ledger.snapshot()['attempts'],0)
        second=KeyboardInterrupt('NONSECRET_SECOND_INTERRUPT')
        with self.assertRaises(KeyboardInterrupt) as caught:
            with launch.instrument(self.ledger,self.cell['id'],original_popen=self.executor,
                    command=self.command,observe_command=self.command) as guard:
                self.guard=guard
                with mock.patch.object(harness,'_cleanup_material',side_effect=second):
                    with harness.actual_lease(self.args,self.factory,_cancellation=self.scope):
                        self.worker_rows();self.stage_receipts();raise self.error
        self.assertIs(caught.exception,second)
        self.assertEqual(self.ledger.snapshot()['private_cleanup_pending'],4)


if __name__=='__main__':unittest.main()
