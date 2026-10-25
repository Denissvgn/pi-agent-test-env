"""Qualification launch policy with real durable registries and mocked Docker.

No Docker, Pi, model, browser or application service is launched here. Hard-cap
240/24 component checks do not claim that many containers were executed.
"""
import copy
import hashlib
import io
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime'),str(ROOT/'tools/qualification')]
import application_launch as launch
import application_client
import ownership_registry


def manifest():
    images={profile+'-'+release:{'id':'sha256:'+str(index+1)*64,'platform':'linux/arm64','capabilities':{'pi':release}}
            for index,(profile,release) in enumerate((('core','0.87.1'),('browser','0.87.1'),('core','1.2.0'),('browser','1.2.0')))}
    roles={role:1 for role in launch.ROLES};roles.update(probe=148,participant=24)
    cells=[{'id':'cell-a','group':'N02','release':'0.87.1','image_id':images['core-0.87.1']['id'],
        'allowed_images':[images['core-0.87.1']['id'],images['browser-0.87.1']['id']],
        'role_limits':roles,'container_launches_max':sum(roles.values()),'participant_segments_max':24}]
    cells.append({'id':'cell-b','group':'N01','release':'1.2.0','image_id':images['core-1.2.0']['id'],
        'allowed_images':[images['core-1.2.0']['id']],'role_limits':{'probe':186-sum(roles.values())},
        'container_launches_max':186-sum(roles.values()),'participant_segments_max':0})
    return {'qualification_id':str(uuid.uuid4()),'images':images,'cells':cells,'limits':copy.deepcopy(launch.LIMITS),'planned_container_launches':186}


class Process:
    def __init__(self,pid=123):self.pid=pid;self.returncode=0;self.stdin=io.BytesIO();self.stdout=io.BytesIO();self.stderr=io.BytesIO()
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def communicate(self,input=None,timeout=None):return b'',b''
    def poll(self):return self.returncode
    def wait(self,timeout=None):return self.returncode
    def kill(self):pass


def observation(record):
    return {'Id':hashlib.sha256(record['container'].encode()).hexdigest(),'Image':record['image'],
        'Config':{'Labels':{launch.LABEL:record['launch_id'],launch.REGISTRY_LABEL:record['registry']}},
        'Mounts':[{'Source':m['source'],'Destination':m['target'],'RW':m['rw']} for m in record['mounts']]}


def _child_reserve(root,policy,queue):
    """A real host process, with only its Docker boundary mocked."""
    try:
        ledger=launch.LaunchLedger(Path(root)/'launches',policy,clock=lambda:100.0,wall=lambda:1000.0)
        registry=ownership_registry.Registry(Path(root)/('child-registry-'+uuid.uuid4().hex));registry.bind_daemon('fixture-daemon')
        image=policy['cells'][0]['image_id'];name='pi-lab-'+uuid.uuid4().hex[:12]
        argv=['docker','run','--name',name,'--platform','linux/arm64','--cpus','1','--memory','1g','--memory-swap','1g',
            '--pids-limit','256','--entrypoint=python3',image,'/opt/pi-lab/worker.py','probe']
        record,argv=registry.intent(argv,name)
        observed=observation(record)
        def command(args):
            body={'ID':'fixture-daemon','NCPU':64,'MemTotal':65536*1048576,'Architecture':'arm64','OSType':'linux'} if args[1]=='info' else [observed] if args[1]=='container' else [{'Id':image,'Architecture':'arm64','Os':'linux'}]
            return subprocess.CompletedProcess(args,0,json.dumps(body),'')
        launch.LaunchGuard(ledger,'cell-a',lambda:registry,lambda *a,**kw:Process(os.getpid()),command).popen(argv)
        queue.put('launched_mock')
    except launch.LaunchError as error:queue.put(error.reason)


class LaunchTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
        self.policy=manifest();self.image=self.policy['cells'][0]['image_id'];self.now=[100.0];self.wall=[1000.0]
        self.ledger=launch.LaunchLedger.create(self.root/'launches',self.policy,daemon_id='fixture-daemon',
            daemon_capacity={'cpu_millis':64000,'memory_mib':65536},clock=lambda:self.now[0],wall=lambda:self.wall[0])
        self.registry=ownership_registry.Registry(self.root/'registry');self.registry.bind_daemon('fixture-daemon')
        self.effects=[];self.absent=False;self.observed_arch='arm64';self.daemon_id='fixture-daemon';self.observations={}
        self.registry.command=self.command;self.executor=mock.Mock(side_effect=self.execute)
    def execute(self,argv,*args,**kwargs):
        parsed=launch._options(argv)
        if parsed and parsed[0]=='run':
            name=parsed[1]['--name'][0];record=next(row for row in self.registry.load() if row['container']==name);observed=observation(record)
            self.observations[name]=self.observations[observed['Id']]=observed
        self.effects.append((argv,args,kwargs));process=Process(100+len(self.effects));process.args=argv;return process
    def command(self,argv):
        if argv[1:2]==['info']:
            return subprocess.CompletedProcess(argv,0,json.dumps({'ID':self.daemon_id,'NCPU':64,'MemTotal':65536*1048576,'Architecture':'aarch64','OSType':'linux'}),'')
        if argv[1:3]==['image','inspect']:
            return subprocess.CompletedProcess(argv,0,json.dumps([{'Id':argv[3],'Architecture':self.observed_arch,'Os':'linux'}]),'')
        if argv[1:3]==['container','inspect']:
            missing=self.absent or argv[-1] not in self.observations
            return subprocess.CompletedProcess(argv,1 if missing else 0,json.dumps([] if missing else [self.observations[argv[-1]]]),'No such container: '+argv[-1] if missing else '')
        raise AssertionError('Unexpected mocked Docker observation')
    def guard(self,cell='cell-a'):
        return launch.LaunchGuard(self.ledger,cell,lambda:self.registry,self.executor,self.command)
    def argv(self,operation='probe',image=None):
        return ['docker','run','--name','pi-lab-'+uuid.uuid4().hex[:12],'--platform','linux/arm64',
            '--cpus','1','--memory','1g','--memory-swap','1g','--pids-limit','256',
            '--entrypoint=python3','--pull=never',
            image or self.image,'/opt/pi-lab/worker.py',operation]
    def intent(self,operation='probe',image=None):
        argv=self.argv(operation,image);return self.registry.intent(argv,argv[argv.index('--name')+1],runroot=self.root/'run')
    def launch(self,operation='probe'):
        record,argv=self.intent(operation);self.guard().popen(argv);return record,argv
    def release(self,record):
        self.absent=True
        if record.get('qualification_role') in launch.EXTERNAL:
            record['container_id']=next(r['container_id'] for r in self.ledger.snapshot()['launches'] if r['launch_id']==record['launch_id'])
            self.registry.write(record)
            private=ownership_registry.observe_qualification_private(record)
            Path(private['source']).rmdir()
        self.registry.confirm_absent(record);self.guard().confirm_physical(self.registry,record)
        if record.get('qualification_role') in launch.EXTERNAL:
            record['qualification_service_cleanup']=ownership_registry.write_qualification_service_cleanup(record,self.root/(record['launch_id']+'-cleanup.json'),
                private_identity=private,physical_absence_confirmed=True,private_bootstrap_removed=True,terminal_available=False,startup_readied=False)
            self.registry.write(record)
        self.registry.release(record,True);self.guard().release(self.registry,record,owner_cleanup_confirmed=True)
        self.absent=False

    def service_argv(self,role):
        argv=self.argv();argv[-2:]=[launch.EXTERNAL[role],'--help']
        for key,value in (('--cpus','0.25'),('--memory','128m'),('--memory-swap','128m'),('--pids-limit','64')):argv[argv.index(key)+1]=value
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);private=Path(temporary.name).resolve()
        observations=self.root/'cells/cell-a'/role;observations.mkdir(mode=0o700,parents=True,exist_ok=True)
        mounts=[]
        for source,target,readonly in ((ROOT/'skill','/opt/pi-skill',True),(ROOT/'tools/qualification','/qualification',True),(private,'/private',True),(observations,'/observations',False)):
            mounts+=['--mount','type=bind,src='+str(source)+',dst='+target+',bind-recursive=disabled'+(',readonly' if readonly else '')]
        index=argv.index(self.image);argv[index:index]=mounts;return argv

    def test_fixed_manifest_rejects_extra_missing_role_images_arch_and_plan_growth(self):
        self.assertEqual(launch.validate_manifest(self.policy),self.policy)
        mutations=[lambda v:v.update(extra=True),lambda v:v['limits'].update(live=5),
            lambda v:v.update(planned_container_launches=187),lambda v:v['images']['core-0.87.1'].update(platform='linux/amd64'),
            lambda v:v['cells'][0]['role_limits'].update(unknown=1),lambda v:v['cells'][0].update(container_launches_max=180)]
        for change in mutations:
            value=copy.deepcopy(self.policy);change(value)
            with self.subTest(change=change),self.assertRaises(launch.LaunchError):launch.validate_manifest(value)

    def test_hard_boundaries_are_fixed_component_decisions_before_executor(self):
        valid={'attempts':239,'live':3,'segments':23,'participant':True,'now':100,'deadline':1000}
        launch._hard_admission(**valid)
        for change,reason in (({'attempts':240},'qualification_launch_limit'),({'live':4},'qualification_live_limit'),
            ({'segments':24},'qualification_segment_limit'),({'now':970},'qualification_deadline')):
            with self.subTest(change=change),self.assertRaises(launch.LaunchError) as caught:launch._hard_admission(**{**valid,**change})
            self.assertEqual(caught.exception.reason,reason)
        self.executor.assert_not_called()

    def test_fifth_real_preintent_route_denies_before_mock_executor_and_exit_never_frees(self):
        for _ in range(4):self.launch()
        record,argv=self.intent()
        with self.assertRaises(launch.LaunchError):self.guard().popen(argv)
        self.assertEqual(len(self.effects),4);self.assertEqual(self.ledger.snapshot()['live'],4)
        self.assertEqual(self.ledger.snapshot()['attempts'],4)
        # Every mocked CLI has already exited0; only physical proof can free.
        self.assertEqual([effect[0][-1] for effect in self.effects],['probe']*4)

    def test_closed_worker_roles_are_counted_and_current_cell_cleanup_is_independent(self):
        for operation in ('probe','boundary','preflight','agent','check','browser'):
            record,_=self.launch(operation);self.release(record)
        snapshot=self.ledger.snapshot();self.assertEqual(snapshot['attempts'],6)
        self.assertEqual(snapshot['participant_segments'],1);self.assertEqual(snapshot['live'],0)
        self.assertEqual({r['role'] for r in snapshot['launches']},{'probe','boundary','preflight','participant','scorer','browser-check'})
        self.ledger.assert_cell_released('cell-a')

    def test_physical_absence_frees_only_physical_capacity_not_next_cell_admission(self):
        record,_=self.launch();self.absent=True;self.registry.confirm_absent(record);self.guard().confirm_physical(self.registry,record)
        self.assertEqual(self.ledger.snapshot()['live'],0)
        self.assertEqual(self.ledger.snapshot()['private_cleanup_pending'],1)
        with self.assertRaises(launch.LaunchError):self.ledger.assert_cell_released('cell-a')
        image=self.policy['cells'][1]['image_id'];other,argv=self.intent(image=image)
        with self.assertRaises(launch.LaunchError):self.guard('cell-b').popen(argv)
        self.assertEqual(len(self.effects),1)
        self.registry.release(record,True);self.guard().release(self.registry,record,owner_cleanup_confirmed=True)
        self.absent=False
        self.guard('cell-b').popen(argv);self.assertEqual(len(self.effects),2)

    def test_unknown_absence_retains_slot_and_poison_blocks_retries(self):
        record,_=self.launch();self.absent=False
        with self.assertRaises(launch.LaunchError):self.guard().confirm_physical(self.registry,record)
        self.assertTrue(self.ledger.snapshot()['poisoned']);self.assertEqual(self.ledger.snapshot()['live'],1)
        self.absent=True;new,argv=self.intent()
        with self.assertRaises(launch.LaunchError):self.guard().popen(argv)
        self.assertEqual(len(self.effects),1)

    def test_failed_cli_spawn_consumes_attempt_and_keeps_uncertain_live_slot(self):
        record,argv=self.intent();guard=self.guard();guard.original_popen=mock.Mock(side_effect=OSError('private diagnostic'))
        with self.assertRaises(OSError):guard.popen(argv)
        snapshot=self.ledger.snapshot();self.assertEqual(snapshot['attempts'],1);self.assertEqual(snapshot['live'],1);self.assertTrue(snapshot['poisoned'])
        loaded=launch.LaunchLedger(self.ledger.root,self.policy,clock=lambda:self.now[0],wall=lambda:self.wall[0])
        self.assertEqual(loaded.snapshot()['attempts'],1)

    def test_capture_slow_daemon_uses_remaining_total_deadline_then_bounded_inspection(self):
        record,argv=self.intent();guard=self.guard();elapsed=[0.0];observed=[]
        def command(args,timeout=15):
            if self.effects:
                observed.append((args[1:3],timeout))
                if args[1]=='info':elapsed[0]+=4.9
            return self.command(args)
        guard.command=command;guard._custom_command=False
        with mock.patch.object(launch.time,'monotonic',side_effect=lambda:elapsed[0]):guard.popen(argv)
        self.assertEqual(len(self.effects),1)
        self.assertEqual(observed[0][0],['info','--format']);self.assertEqual(observed[0][1],5)
        self.assertEqual(observed[1][0],['container','inspect'])
        self.assertGreater(observed[1][1],0);self.assertLessEqual(observed[1][1],5-elapsed[0])
        self.assertLess(observed[1][1],.11)
        snapshot=self.ledger.snapshot();self.assertFalse(snapshot['poisoned'])
        self.assertEqual(snapshot['launches'][0]['container_id'],observation(record)['Id'])

    def test_capture_exhausted_daemon_deadline_starts_no_inspection_and_poison_blocks_retry(self):
        record,argv=self.intent();guard=self.guard();elapsed=[0.0];observed=[]
        def command(args,timeout=15):
            if self.effects:
                observed.append((args[1:3],timeout))
                if args[1]=='info':elapsed[0]+=timeout
            return self.command(args)
        guard.command=command;guard._custom_command=False
        with mock.patch.object(launch.time,'monotonic',side_effect=lambda:elapsed[0]):
            with self.assertRaises(launch.LaunchError) as caught:guard.popen(argv)
        self.assertEqual(caught.exception.reason,'qualification_container_id_unconfirmed')
        self.assertEqual(elapsed[0],5);self.assertEqual(observed,[(['info','--format'],5)])
        snapshot=self.ledger.snapshot();self.assertTrue(snapshot['poisoned'])
        self.assertEqual((snapshot['attempts'],snapshot['live']), (1,1))
        self.assertEqual(snapshot['launches'][0]['physical'],'uncertain')
        _,newargv=self.intent()
        with self.assertRaises(launch.LaunchError):guard.popen(newargv)
        self.assertEqual(len(self.effects),1)

    def test_capture_daemon_timeout_remains_charged_uncertain_without_retry(self):
        _,argv=self.intent();guard=self.guard();elapsed=[0.0];allowances=[]
        def command(args,timeout=15):
            if self.effects:
                allowances.append(timeout)
                raise subprocess.TimeoutExpired(args,timeout)
            return self.command(args)
        guard.command=command;guard._custom_command=False
        with mock.patch.object(launch.time,'monotonic',side_effect=lambda:elapsed[0]):
            with self.assertRaises(subprocess.TimeoutExpired) as caught:guard.popen(argv)
        self.assertEqual(allowances,[5]);self.assertEqual(caught.exception.timeout,5)
        snapshot=self.ledger.snapshot();self.assertTrue(snapshot['poisoned'])
        self.assertEqual((snapshot['attempts'],snapshot['live']), (1,1))
        self.assertEqual(snapshot['launches'][0]['physical'],'uncertain')
        _,newargv=self.intent()
        with self.assertRaises(launch.LaunchError):guard.popen(newargv)
        self.assertEqual(len(self.effects),1)

    def test_deadline_arch_image_daemon_and_resource_denials_precede_executor(self):
        record,argv=self.intent();self.now[0]=self.ledger.snapshot()['remaining_seconds']+100-30
        with self.assertRaises(launch.LaunchError):self.guard().popen(argv)
        self.executor.assert_not_called()
        self.now[0]+=1;self.wall[0]+=14400
        with self.assertRaises(launch.LaunchError):self.guard().popen(argv)
    def test_native_arch_and_owned_intent_are_required_before_effects(self):
        record,argv=self.intent();self.observed_arch='amd64'
        with self.assertRaises(launch.LaunchError):self.guard().popen(argv)
        self.observed_arch='arm64';self.daemon_id='other-daemon'
        with self.assertRaises(launch.LaunchError):self.guard().popen(argv)
        self.daemon_id='fixture-daemon';argv[argv.index('--memory-swap')+1]='256m'
        with self.assertRaises(launch.LaunchError):self.guard().popen(argv)
        self.executor.assert_not_called()

    def test_all_mutating_unplanned_commands_and_foreign_cleanup_are_denied(self):
        for args in (['create',self.image],['container','start','foreign'],['build','.'],['pull','tag'],
            ['system','prune','--all'],['exec','foreign','true'],['rm','-f','foreign'],['network','rm','foreign']):
            with self.subTest(args=args),self.assertRaises(launch.LaunchError):self.guard().popen(['docker',*args])
        self.executor.assert_not_called()

    def test_fixture_and_scripted_service_have_real_persisted_intents(self):
        guard=self.guard()
        for role,path in launch.EXTERNAL.items():
            argv=self.service_argv(role)
            record,labelled=guard.external_service_intent(self.registry,argv,role,self.root/'services')
            self.assertIn(record,self.registry.load());self.assertIn(launch.LABEL+'='+record['launch_id'],labelled)
            guard.popen(labelled);self.release(record)
        self.assertEqual({r['role'] for r in self.ledger.snapshot()['launches']},{'fixture','scripted-inference'})

    def test_service_logs_accept_exact_bound_immutable_id_and_reject_foreign_id(self):
        guard=self.guard();record,argv=guard.external_service_intent(self.registry,self.service_argv('fixture'),'fixture',self.root/'services')
        guard.popen(argv)
        identifier=self.ledger.snapshot()['launches'][0]['container_id']
        self.assertNotIn('container_id',record)
        guard.popen(['docker','logs','--tail','20',identifier])
        record['container_id']=identifier;self.registry.write(record)
        guard.popen(['docker','logs','--tail','20',record['container_id']])
        self.assertEqual(self.effects[-1][0][-1],record['container_id'])
        count=len(self.effects)
        with self.assertRaises(launch.LaunchError):guard.popen(['docker','logs','--tail','20','f'*64])
        self.assertEqual(len(self.effects),count)

    def test_early_exited_service_diagnostic_uses_owned_ledger_id_without_registry_mutation(self):
        spec=importlib.util.spec_from_file_location('qualification_diagnostic_fixture',ROOT/'tools/qualification/application_client.py')
        qualification=importlib.util.module_from_spec(spec);spec.loader.exec_module(qualification)
        guard=self.guard();record,argv=guard.external_service_intent(self.registry,self.service_argv('fixture'),'fixture',self.root/'services')
        guard.popen(argv);observed=copy.deepcopy(self.observations[record['container']]);observed['State']={'Running':False,'Status':'exited','ExitCode':1}
        for mount in observed['Mounts']:mount['Type']='bind'
        self.observations[record['container']]=observed
        folder=self.root/'diagnostic';folder.mkdir(mode=0o700)
        owner=object.__new__(qualification.OwnedServices);owner.registry=self.registry;owner.folder=folder
        owner.redactor=qualification.credentials.Redactor(['private-not-logged']);owner.service_states={record['launch_id']:{'role':'fixture','ready':False}}
        def logs(identifier,**kwargs):
            guard.popen(['docker','logs','--tail','20',identifier])
            return {'complete':True,'stdout':b'bounded startup exception','stderr':b''}
        with mock.patch.object(qualification.lab,'command',side_effect=lambda args,**kw:self.command(args)),mock.patch.object(qualification,'_bounded_service_logs',side_effect=logs):
            owner._diagnose(record,record['container'],'startup_failed')
        receipt=json.loads(next(folder.glob('*.json')).read_bytes())
        self.assertEqual((receipt['running'],receipt['status'],receipt['exit_code'],receipt['startup_readied']),(False,'exited',1,False))
        self.assertTrue(receipt['logs']['available']);self.assertNotIn('container_id',self.registry.load()[0])
        # A native worker's real ledger ID cannot authorize external-service logs.
        native,nativeargv=self.launch();nativeid=next(row['container_id'] for row in self.ledger.snapshot()['launches'] if row['launch_id']==native['launch_id'])
        count=len(self.effects)
        with self.assertRaises(launch.LaunchError):guard.popen(['docker','logs','--tail','20',nativeid])
        self.assertEqual(len(self.effects),count)

    def test_scoped_global_run_and_captured_helper_delegate_are_counted_once_and_preserved(self):
        worker,worker_argv=self.intent('probe');helper_argv=self.argv()
        helper_argv[-2:]=['/opt/pi-application/runtime/application_client_service.py','--port']
        helper_argv[helper_argv.index('--memory')+1]='512m';helper_argv[helper_argv.index('--memory-swap')+1]='512m';helper_argv[helper_argv.index('--pids-limit')+1]='128'
        helper,helper_argv=application_client._intent(self.registry,helper_argv,helper_argv[helper_argv.index('--name')+1],self.image,self.root/'private/helper',{}, {},'application-execution')
        original=subprocess.Popen;original_helper=application_client.OwnedHelper.__dict__['start']
        private={key:os.environ[key] for key in ('PATH','DOCKER_HOST','DOCKER_CONTEXT','DOCKER_CONFIG','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH','DOCKER_API_VERSION') if key in os.environ}
        private.update(HOME=str(Path.home()),PRIVATE_BOOTSTRAP='do-not-log-qualification-secret')
        def frozen_helper(cls,*,popen=self.executor):return popen(helper_argv,stdin=subprocess.PIPE,env=private,start_new_session=True)
        with mock.patch.object(application_client.OwnedHelper,'start',classmethod(frozen_helper)):
            with launch.instrument(self.ledger,'cell-a',registry_getter=lambda:self.registry,original_popen=self.executor,command=self.command):
                subprocess.run(worker_argv,capture_output=True,check=True)
                process=application_client.OwnedHelper.start();self.assertEqual(process.pid,102)
                self.assertEqual(self.ledger.snapshot()['attempts'],2)
                self.assertIs(self.effects[1][2]['env'],private);self.assertTrue(self.effects[1][2]['start_new_session'])
                self.assertIs(self.effects[1][2]['stdin'],subprocess.PIPE)
        self.assertIs(subprocess.Popen,original);self.assertIs(application_client.OwnedHelper.__dict__['start'],original_helper)
        for file in self.ledger.root.iterdir():
            if file.is_file():self.assertNotIn(b'do-not-log-qualification-secret',file.read_bytes())

    def test_scoped_real_registry_hooks_separate_physical_and_private_cleanup(self):
        record,argv=self.intent()
        with launch.instrument(self.ledger,'cell-a',registry_getter=lambda:self.registry,original_popen=self.executor,command=self.command):
            subprocess.Popen(argv)
            self.absent=True
            self.assertTrue(self.registry.confirm_absent(record));self.assertEqual(self.ledger.snapshot()['live'],0)
            self.assertEqual(self.ledger.snapshot()['private_cleanup_pending'],1)
            self.registry.release(record,True);self.assertEqual(self.ledger.snapshot()['private_cleanup_pending'],0)

    def test_parallel_reservation_is_serialized_without_lost_updates(self):
        errors=[];threads=[]
        for _ in range(5):
            record,argv=self.intent()
            def run(argv=argv):
                try:self.guard().popen(argv)
                except launch.LaunchError as error:errors.append(error.reason)
            threads.append(threading.Thread(target=run))
        for thread in threads:thread.start()
        for thread in threads:thread.join()
        self.assertEqual(len(self.effects),4);self.assertEqual(len(errors),1);self.assertEqual(self.ledger.snapshot()['attempts'],4)

    def test_flocked_budget_is_shared_across_real_host_child_processes(self):
        context=multiprocessing.get_context('fork');queue=context.Queue()
        processes=[context.Process(target=_child_reserve,args=(str(self.root),self.policy,queue)) for _ in range(5)]
        for process in processes:process.start()
        for process in processes:
            process.join(5);self.assertFalse(process.is_alive());self.assertEqual(process.exitcode,0)
        observed=[queue.get(timeout=2) for _ in processes];queue.close();queue.join_thread()
        self.assertEqual(observed.count('launched_mock'),4);self.assertEqual(observed.count('qualification_live_limit'),1)
        self.assertEqual(self.ledger.snapshot()['attempts'],4);self.assertEqual(self.ledger.snapshot()['live'],4)

    def test_current_daemon_half_capacity_is_not_silently_expanded(self):
        actual=self.command
        def limited(argv):
            reply=actual(argv)
            if argv[1]=='info':
                value=json.loads(reply.stdout);value.update(NCPU=2,MemTotal=4096*1048576);reply.stdout=json.dumps(value)
            return reply
        guard=self.guard();guard.command=limited
        for number in range(2):
            record,argv=self.intent()
            if number:
                with self.assertRaises(launch.LaunchError) as caught:guard.popen(argv)
                self.assertEqual(caught.exception.reason,'qualification_aggregate_limit')
            else:guard.popen(argv)
        self.assertEqual(len(self.effects),1)

    def test_docker_environment_cannot_change_identity_target_or_log_private_values(self):
        record,argv=self.intent()
        with self.assertRaises(launch.LaunchError):self.guard().popen(argv,env={**os.environ,'DOCKER_HOST':'tcp://foreign.invalid:2375','PRIVATE':'no-log-private-value'})
        self.executor.assert_not_called();self.assertEqual(self.ledger.snapshot()['attempts'],0)
        self.assertNotIn(b'no-log-private-value',(self.ledger.root/'ledger.json').read_bytes())

    def test_tampered_overcounted_persisted_state_cannot_reach_executor(self):
        record,argv=self.intent();self.guard().popen(argv)
        path=self.ledger.root/'ledger.json';value=json.loads(path.read_bytes());value['launches']*=241;path.write_text(json.dumps(value))
        second,args=self.intent()
        with self.assertRaises(launch.LaunchError):self.guard().popen(args)
        self.assertEqual(len(self.effects),1)

    def test_only_owned_bounded_service_logs_and_owned_cleanup_pass(self):
        guard=self.guard();argv=self.service_argv('fixture')
        record,argv=guard.external_service_intent(self.registry,argv,'fixture',self.root/'services');guard.popen(argv)
        guard.popen(['docker','logs','--tail','20',record['container']]);guard.popen(['docker','stop','--time','15',record['container']])
        for args in (['logs','--tail','200',record['container']],['logs','--follow',record['container']],['logs','--tail','20','foreign']):
            with self.subTest(args=args),self.assertRaises(launch.LaunchError):guard.popen(['docker',*args])
        self.assertEqual(self.ledger.snapshot()['attempts'],1)

    def test_container_run_spelling_is_counted_without_changing_original_argv(self):
        record,argv=self.intent();argv=[argv[0],'container','run',*argv[2:]];before=list(argv)
        self.guard().popen(argv)
        self.assertEqual(argv,before);self.assertIs(self.effects[0][0],argv);self.assertEqual(self.ledger.snapshot()['attempts'],1)

    def test_failed_owner_cleanup_poison_blocks_new_same_cell_actions(self):
        record,argv=self.intent()
        with launch.instrument(self.ledger,'cell-a',registry_getter=lambda:self.registry,original_popen=self.executor,command=self.command):
            subprocess.Popen(argv);self.absent=True;self.registry.confirm_absent(record)
            with self.assertRaises(ownership_registry.RegistryError):self.registry.release(record,False)
            second,args=self.intent()
            with self.assertRaises(launch.LaunchError):subprocess.Popen(args)
        self.assertTrue(self.ledger.snapshot()['poisoned']);self.assertEqual(len(self.effects),1)

    def test_entrypoint_override_cannot_reclassify_an_arbitrary_executable_as_worker(self):
        record,argv=self.intent();argv[argv.index('--entrypoint=python3')]='--entrypoint=bash'
        with self.assertRaises(launch.LaunchError):self.guard().popen(argv)
        self.executor.assert_not_called();self.assertEqual(self.ledger.snapshot()['attempts'],0)

    def test_real_host_subprocess_stdio_forwarding_preserves_private_input_without_capture(self):
        marker=b'private-host-stdio-fixture-4938';original=subprocess.Popen;processes=[]
        def delegate(*args,**kwargs):
            process=original(*args,**kwargs);processes.append(process);return process
        with launch.instrument(self.ledger,'cell-a',registry_getter=lambda:self.registry,original_popen=delegate,command=self.command):
            result=subprocess.run([sys.executable,'-c','import sys;print(len(sys.stdin.buffer.read()))'],
                input=marker,capture_output=True,check=True,timeout=3,start_new_session=True)
        self.assertEqual(result.stdout,str(len(marker)).encode()+b'\n');self.assertEqual(result.stderr,b'')
        self.assertEqual(len(processes),1);self.assertIsInstance(processes[0],original);self.assertEqual(processes[0].returncode,0)
        self.assertEqual(self.ledger.snapshot()['attempts'],0)
        self.assertNotIn(marker,(self.ledger.root/'ledger.json').read_bytes())

    def test_post_intent_mount_and_frozen_service_resources_cannot_change(self):
        source=self.root/'mounted';source.mkdir(mode=0o700);argv=self.argv();index=argv.index(self.image)
        argv[index:index]=['--mount','type=bind,src='+str(source)+',dst=/workspace,readonly,bind-recursive=disabled']
        record,labelled=self.registry.intent(argv,argv[argv.index('--name')+1])
        changed=list(labelled);mount=changed.index('--mount')+1;changed[mount]='type=bind,src=/,dst=/workspace,bind-recursive=disabled'
        with self.assertRaises(launch.LaunchError):self.guard().popen(changed)
        service=self.service_argv('scripted-inference');record,service=self.guard().external_service_intent(self.registry,service,'scripted-inference',self.root/'services')
        for key,value in (('--cpus','2'),('--memory','2g'),('--memory-swap','2g'),('--pids-limit','512')):service[service.index(key)+1]=value
        with self.assertRaises(launch.LaunchError):self.guard().popen(service)
        self.executor.assert_not_called();self.assertEqual(self.ledger.snapshot()['attempts'],0)

    def test_foreign_current_container_is_never_deleted_from_unlaunched_or_launched_intent(self):
        record,argv=self.intent();foreign=observation(record);foreign['Config']['Labels'][launch.LABEL]=str(uuid.uuid4())
        self.observations[record['container']]=foreign
        with self.assertRaises(launch.LaunchError):self.guard().popen(['docker','rm','-f',record['container']])
        self.executor.assert_not_called();self.assertTrue(self.ledger.snapshot()['poisoned'])

    def test_owned_name_cleanup_is_fenced_to_bound_id_and_absent_never_deletes_name(self):
        record,argv=self.launch();requested=['docker','rm','-f',record['container']];before=list(requested)
        identifier=observation(record)['Id'];self.guard().popen(requested)
        self.assertEqual(requested,before);self.assertEqual(self.effects[-1][0],['docker','rm','-f',identifier])
        self.assertEqual(self.ledger.snapshot()['launches'][0]['cleanup_requests'][-1],
            {'operation':'rm','requested_target':'name','effective_target':'immutable_id'})
        self.absent=True;self.guard().popen(requested);self.assertEqual(self.effects[-1][0][-1],identifier)
        self.assertNotEqual(self.effects[-1][0][-1],record['container'])

    def test_renamed_original_cannot_be_freed_by_name_absence(self):
        record,argv=self.intent();original=copy.deepcopy(record)
        with launch.instrument(self.ledger,'cell-a',registry_getter=lambda:self.registry,original_popen=self.executor,command=self.command):
            subprocess.Popen(argv);self.observations.pop(record['container'])
            with self.assertRaises(launch.LaunchError):self.registry.confirm_absent(record)
        self.assertEqual(next(r for r in self.registry.load() if r['launch_id']==record['launch_id']),original)
        self.assertEqual(self.ledger.snapshot()['live'],1);self.assertTrue(self.ledger.snapshot()['poisoned'])

    def test_copied_or_rerooted_cleanup_record_cannot_write_or_release_authority(self):
        record,argv=self.intent();original=copy.deepcopy(record)
        with launch.instrument(self.ledger,'cell-a',registry_getter=lambda:self.registry,original_popen=self.executor,command=self.command):
            subprocess.Popen(argv)
            for change in ({'container':'foreign-absent'},{'runroot':str(self.root/'foreign')},{'binding':{'unexpected':'scope'}},
                    {'image':self.policy['cells'][1]['image_id']},{'daemon':'other'},{'status':'released'}):
                forged={**copy.deepcopy(record),**change}
                with self.subTest(change=change),self.assertRaises(launch.LaunchError):self.registry.confirm_absent(forged)
                self.assertEqual(next(r for r in self.registry.load() if r['launch_id']==record['launch_id']),original)
            forged={**record,'status':'released','container':'foreign-absent'}
            with self.assertRaises(launch.LaunchError):self.guard().release(self.registry,forged,owner_cleanup_confirmed=True)
        self.assertEqual(self.ledger.snapshot()['live'],1);self.assertEqual(self.ledger.snapshot()['private_cleanup_pending'],1)

    def test_body_exception_poison_restores_hooks_and_forbids_same_cell_retry(self):
        record,argv=self.intent();original=subprocess.Popen;helper=application_client.OwnedHelper.__dict__['start']
        with self.assertRaises(RuntimeError):
            with launch.instrument(self.ledger,'cell-a',registry_getter=lambda:self.registry,original_popen=self.executor,command=self.command):
                subprocess.Popen(argv);raise RuntimeError('controlled qualification body failure')
        self.assertIs(subprocess.Popen,original);self.assertIs(application_client.OwnedHelper.__dict__['start'],helper)
        self.assertTrue(self.ledger.snapshot()['poisoned']);next_record,next_argv=self.intent()
        with launch.instrument(self.ledger,'cell-a',registry_getter=lambda:self.registry,original_popen=self.executor,command=self.command):
            with self.assertRaises(launch.LaunchError):subprocess.Popen(next_argv)
        self.assertEqual(len(self.effects),1)

    def test_external_private_authority_intent_blocks_generic_crash_recovery_before_docker(self):
        guard=self.guard();record,argv=guard.external_service_intent(self.registry,self.service_argv('fixture'),'fixture',self.root/'services')
        self.assertIs(record['application_helper'],True);self.assertEqual(record['client_mode'],'qualification-fixture')
        command=mock.Mock(side_effect=AssertionError('No generic recovery Docker operation'))
        fresh=ownership_registry.Registry(self.registry.root,command=command)
        with self.assertRaises(ownership_registry.RegistryError):fresh.reconcile()
        command.assert_not_called()

    def test_foreign_replacement_after_launch_cannot_reach_destructive_delegate(self):
        record,argv=self.launch();foreign=observation(record);foreign['Id']='f'*64;foreign['Config']['Labels'][launch.LABEL]=str(uuid.uuid4())
        self.observations[record['container']]=foreign;before=len(self.effects)
        with self.assertRaises(launch.LaunchError):self.guard().popen(['docker','rm','-f',record['container']])
        self.assertEqual(len(self.effects),before);self.assertTrue(self.ledger.snapshot()['poisoned']);self.assertEqual(self.ledger.snapshot()['live'],1)

    def test_pull_policy_never_downloads_and_omission_is_explicitly_recorded(self):
        record,argv=self.intent();bad=list(argv);bad[bad.index('--pull=never')]='--pull=always'
        with self.assertRaises(launch.LaunchError):self.guard().popen(bad)
        self.executor.assert_not_called();missing=list(argv);missing.remove('--pull=never');before=list(missing)
        self.guard().popen(missing)
        self.assertEqual(missing,before);self.assertIn('--pull=never',self.effects[-1][0])
        self.assertEqual(self.ledger.snapshot()['launches'][0]['launch_policy'],'inserted_pull_never_owned_id_5s')

    def test_missing_postlaunch_id_is_bounded_and_never_releases_unknown_container(self):
        record,argv=self.intent();actual=self.command;counter=[0.0]
        def clock():counter[0]+=1;return counter[0]
        def invisible(args):
            if args[1:3]==['container','inspect']:return subprocess.CompletedProcess(args,1,'[]','No such container: '+args[-1])
            return actual(args)
        guard=self.guard();guard.command=invisible
        with mock.patch.object(launch.time,'monotonic',side_effect=clock),mock.patch.object(launch.time,'sleep'),self.assertRaises(launch.LaunchError):guard.popen(argv)
        snapshot=self.ledger.snapshot();self.assertEqual(snapshot['attempts'],1);self.assertEqual(snapshot['live'],1)
        self.assertIsNone(snapshot['launches'][0]['container_id']);self.assertTrue(snapshot['poisoned'])

    def test_missing_corrupt_unknown_symlinked_state_and_backward_clock_fail_closed(self):
        original=(self.ledger.root/'ledger.json').read_bytes()
        for body in (b'{',b'{}',json.dumps({**json.loads(original),'unexpected':True}).encode()):
            (self.ledger.root/'ledger.json').write_bytes(body)
            with self.assertRaises(launch.LaunchError):self.ledger.snapshot()
        (self.ledger.root/'ledger.json').write_bytes(original);self.wall[0]-=1
        with self.assertRaises(launch.LaunchError):self.ledger.snapshot()
        self.wall[0]+=1;self.assertTrue(self.ledger.snapshot()['poisoned'])
        (self.ledger.root/'ledger.json').unlink()
        with self.assertRaises(launch.LaunchError):self.ledger.snapshot()
        outside=self.root/'outside';outside.write_bytes(original);outside.chmod(0o600)
        (self.ledger.root/'ledger.json').symlink_to(outside)
        with self.assertRaises(launch.LaunchError):self.ledger.snapshot()


class CampaignCarryTests(unittest.TestCase):
    """Controlled files/owner receipts only; no native or cleanup evidence claim."""
    def put(self,path,value):
        path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        path.write_text(json.dumps(value,sort_keys=True)+'\n');path.chmod(0o600)
        return {'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve();self.old=self.root/'previous';self.old.mkdir(mode=0o700)
        self.clock=lambda:200.0;self.wall=lambda:1100.0;self.daemon='fixture-daemon';self.capacity={'cpu_millis':18000,'memory_mib':7931}
        spec=importlib.util.spec_from_file_location('qualification_carry_fixture',ROOT/'tools/qualification/application_client.py')
        qualification=importlib.util.module_from_spec(spec);spec.loader.exec_module(qualification)
        images=manifest()['images'];self.cells=qualification.matrix(images)
        self.policy=qualification._launch_manifest({'qualification_id':str(uuid.uuid4()),'images':images,'cells':self.cells})
        self.registry=ownership_registry.Registry(self.root/'operation.lock.registry');self.registry.bind_daemon(self.daemon)
        self.active={'id':'N02-0.87.1-request-and-persona-a','pid':2**31-1,'run_id':str(uuid.uuid4()),'attempt_id':str(uuid.uuid4())}
        self.full={'schema':1,'document_type':'application_client_qualification','qualification_id':self.policy['qualification_id'],
            'prepared_root':str(self.old),'images':images,'cells':self.cells,'planned_container_launches':186,
            'host_admission':{'lock_file':str(self.root/'operation.lock'),'wait_seconds':30},
            'source':{'files':{'tools/qualification/application_client.py':'9439748664fb6393dce3061687f041d49813ad35636fe0c72a7b46b0f70bf3b4'}}}
        self.put(self.old/'manifest.json',self.full)
        oldledger=launch.LaunchLedger.create(self.old/'launch-ledger',self.policy,daemon_id=self.daemon,daemon_capacity=self.capacity,clock=lambda:100.0,wall=lambda:1000.0)
        rows=[];states={};self.service_record=None
        for cell in sorted(self.policy['cells'],key=lambda cell:cell['group']!='N01'):
            if cell['group']!='N01' and cell['id']!=self.active['id']:continue
            roles=cell['role_limits'] if cell['group']=='N01' else {'fixture':1}
            states[cell['id']]={'status':'PASS' if cell['group']=='N01' else 'BLOCKED','attempts':1}
            for role in roles:
                identifier=str(uuid.uuid4());containerid=hashlib.sha256(identifier.encode()).hexdigest()
                record={'schema':1,'launch_id':identifier,'registry':self.registry.registry_id,'generation':self.registry.generation,
                    'status':'intent','container':'owned-'+identifier,'image':self.policy['images']['core-'+cell['release']]['id'] if role in launch.EXTERNAL else cell['image_id'],
                    'mounts':[],'binding':{'run_id':self.active['run_id'],'attempt_id':self.active['attempt_id']},'daemon':self.daemon,
                    'runroot':str(self.old/'scripted-0.87.1/runs'/self.active['run_id']),'owner_pid':os.getpid()}
                if role=='fixture':
                    self.private=self.root/'old-private';self.private.mkdir(mode=0o700)
                    record.update(application_helper=True,client_mode='qualification-fixture',qualification_role='fixture',qualification_cell=cell['id'],
                        mounts=[{'source':str(self.private),'target':'/private','rw':False}])
                self.registry.write(record)
                key=oldledger.reserve(cell['id'],role,record,launch._role_weight(self.policy,cell,role),{'id':self.daemon,**self.capacity})
                oldledger.note(key,pid=123,container_id=containerid,physical='absent',private_cleanup=role!='fixture')
                record.update(status='released',container_id=containerid)
                if role=='fixture':
                    record['status']='absent';self.identity=ownership_registry.observe_qualification_private(record);self.private.rmdir()
                    self.service_reference=ownership_registry.write_qualification_service_cleanup(record,self.old/'fixture-cleanup.json',private_identity=self.identity,
                        physical_absence_confirmed=True,private_bootstrap_removed=True,terminal_available=False,startup_readied=False)
                    record['qualification_service_cleanup']=self.service_reference;record['status']='released';self.service_record=record
                self.registry.write(record)
                rows.append({'launch_id':identifier,'container_id':containerid,'physical_absence_confirmed':True,'private_cleanup_confirmed':True})
        oldledger.poison_scope(self.active['id'],force=True)
        self.put(self.old/'state.json',{'schema':1,'phase':'blocked','active_cell':self.active,'cells':states,'started_at':999.0})
        self.predecessor={'schema':1,'root':str(self.old),**{key:hashlib.sha256((self.old/path).read_bytes()).hexdigest()
            for key,path in [('manifest_sha256','manifest.json'),('ledger_sha256','launch-ledger/ledger.json'),('state_sha256','state.json')]},'cleanup_receipts':[]}
        terminal=self.put(self.root/'terminal.json',{'actual_exit':2,'cwd':str(ROOT),
            'argv':['python3','tools/qualification/application_client.py','collect','--root',str(self.old),'--group','N02','--release','0.87.1']})
        child=self.put(self.root/'child.json',{'sealed':True,'status':'BLOCKED','exit_code':2,'agents':[],
            'invocation':{'status':'not_started','attempted_stages':0},'run_id':self.active['run_id'],'attempt_id':self.active['attempt_id']})
        envelope=self.root/'pi-qualification-cell-previous'
        invocation=self.put(self.root/'invocation.json',{'argv':['python3',str(ROOT/'tools/qualification/application_client.py'),'_cell-run',
            '--root',str(self.old),'--cell-id',self.active['id'],'--private-envelope',str(envelope/'initial.json')],
            'cwd':str(ROOT),'classification':'native_scripted_protocol'})
        self.campaign={'schema':1,'document_type':'qualification_campaign_cleanup','qualification_id':self.policy['qualification_id'],
            **{k:self.predecessor[k] for k in ('manifest_sha256','ledger_sha256','state_sha256')},'daemon':self.daemon,
            'controller':{'pid':self.active['pid'],'exited':True,'pid_absence_observed':True,'provenance':'terminal_parent_and_pid_absence',
                'parent_terminal':terminal,'child_result':child,'original_invocation':invocation},
            'parent_bootstrap':{'path':str(envelope),'device':1,'inode':2,'private_bootstrap_removed':True},'launches':rows,'safe_to_continue':True}
        self.campaign_reference=self.put(self.old/'campaign-cleanup.json',self.campaign)
        self.predecessor['cleanup_receipts']=[self.campaign_reference,self.service_reference]
        self.current=copy.deepcopy(self.policy);self.current['qualification_id']=str(uuid.uuid4());self.current['predecessor']=self.predecessor
        self.originals={str(p):p.read_bytes() for p in self.old.rglob('*') if p.is_file()}
    def create(self):
        return launch.LaunchLedger.create(self.root/'candidate-ledger',self.current,daemon_id=self.daemon,daemon_capacity=self.capacity,clock=self.clock,wall=self.wall)
    def rewrite_campaign(self,change):
        change(self.campaign);new=self.put(Path(self.campaign_reference['path']),self.campaign)
        self.predecessor['cleanup_receipts'][0]=new;self.campaign_reference=new
    def test_positive_carry_preserves_original_poison_deadlines_denominator_and_counts(self):
        summary=launch.validate_predecessor(self.predecessor,daemon_id=self.daemon,clock=self.clock,wall=self.wall)
        self.assertEqual((summary['attempts'],summary['participant_segments'],summary['planned_cells']),(7,0,28))
        self.assertEqual(sum(r['status']=='NOT_RUN' for r in summary['prior_rows']),23)
        current=self.create();snap=current.snapshot();self.assertEqual((snap['attempts'],snap['live'],snap['participant_segments']),(7,0,0))
        state=json.loads((current.root/'ledger.json').read_bytes())
        self.assertEqual((state['started'],state['deadline'],state['started_wall'],state['deadline_wall']),(100,14500,1000,15400))
        self.assertEqual(snap['remaining_seconds'],14300);self.assertFalse(snap['poisoned']);self.assertEqual(snap['launches'],[])
        self.assertTrue(json.loads((self.old/'launch-ledger/ledger.json').read_bytes())['poisoned'])
        self.assertEqual({str(p):p.read_bytes() for p in self.old.rglob('*') if p.is_file()},self.originals)
    def test_missing_changed_or_symlinked_predecessor_blocks_before_candidate_state(self):
        path=self.old/'state.json';body=path.read_bytes()
        for mode in ('changed','missing','symlink'):
            with self.subTest(mode=mode):
                path.unlink()
                if mode=='changed':path.write_bytes(body+b' ');path.chmod(0o600)
                elif mode=='symlink':
                    target=self.root/'state-copy';target.write_bytes(body);target.chmod(0o600);path.symlink_to(target)
                with self.assertRaises(launch.LaunchError):self.create()
                self.assertFalse((self.root/'candidate-ledger').exists())
                if path.exists() or path.is_symlink():path.unlink()
                path.write_bytes(body);path.chmod(0o600)
    def test_missing_external_cleanup_reference_and_extra_proof_fail_closed(self):
        self.predecessor['cleanup_receipts'].pop()
        with self.assertRaises(launch.LaunchError):self.create()
        self.predecessor['cleanup_receipts'].append(self.service_reference)
        self.predecessor['cleanup_receipts'].append(self.put(self.old/'unexpected.json',{'payload':'do-not-echo'}))
        with self.assertRaises(launch.LaunchError) as error:self.create()
        self.assertNotIn('do-not-echo',str(error.exception))
    def test_original_clean_probe_records_need_not_retain_id_already_frozen_in_ledger(self):
        for record in self.registry.load():
            if record['launch_id']!=self.service_record['launch_id']:
                record.pop('container_id');self.registry.write(record)
        self.assertEqual(self.create().snapshot()['attempts'],7)
    def test_restored_private_mount_and_original_parent_bootstrap_deny(self):
        for path in (self.private,Path(self.campaign['parent_bootstrap']['path'])):
            with self.subTest(path=path.name):
                path.mkdir(mode=0o700)
                with self.assertRaises(launch.LaunchError):self.create()
                path.rmdir()
    def test_terminal_not_complete_cancelled_child_and_live_pid_cannot_supply_writer_proof(self):
        for section,key,value in [('parent_terminal','actual_exit',0),('child_result','status','PASS'),('child_result','exit_code',130),
                ('child_result','agents',[{}]),('child_result','run_id',str(uuid.uuid4())),('child_result','sealed',False)]:
            with self.subTest(section=section,key=key):
                ref=self.campaign['controller'][section];path=Path(ref['path']);original=path.read_bytes();data=json.loads(original);data[key]=value
                self.campaign['controller'][section]=self.put(path,data);self.rewrite_campaign(lambda _:None)
                with self.assertRaises(launch.LaunchError):self.create()
                path.write_bytes(original);self.campaign['controller'][section]=ref;self.rewrite_campaign(lambda _:None)
        with mock.patch.object(launch.os,'kill',return_value=None),self.assertRaises(launch.LaunchError):self.create()
    def test_campaign_ownership_omitted_row_typed_flags_and_old_state_cannot_be_relabelled(self):
        original=copy.deepcopy(self.campaign)
        changes=[lambda v:v.update(qualification_id=str(uuid.uuid4())),lambda v:v['launches'].pop(),
            lambda v:v['launches'][0].update(physical_absence_confirmed=1),lambda v:v['controller'].update(provenance='observed_child_exit'),
            lambda v:v['parent_bootstrap'].update(device=True)]
        for change in changes:
            self.campaign=copy.deepcopy(original);self.rewrite_campaign(change)
            with self.subTest(change=change),self.assertRaises(launch.LaunchError):self.create()
    def test_original_record_rerooting_or_wrong_daemon_cannot_free_or_transfer_capacity(self):
        original=copy.deepcopy(self.service_record)
        for key,value in [('runroot',str(self.root/'wrong')),('container_id','f'*64),('status','absent')]:
            self.service_record={**original,key:value};self.registry.write(self.service_record)
            with self.subTest(key=key),self.assertRaises(launch.LaunchError):self.create()
        self.registry.write(original)
        with self.assertRaises(launch.LaunchError):launch.validate_predecessor(self.predecessor,daemon_id='another',clock=self.clock,wall=self.wall)
    def test_unchanged_old_deadline_and_revalidation_before_each_business_launch(self):
        current=self.create();self.clock=lambda:14471
        with self.assertRaises(launch.LaunchError):launch.validate_predecessor(self.predecessor,clock=self.clock,wall=self.wall)
        cleanup=launch.LaunchLedger(current.root,self.current,clock=self.clock,wall=self.wall)
        self.assertEqual(cleanup.snapshot()['remaining_seconds'],29)
        with self.assertRaises(launch.LaunchError):launch._hard_admission(attempts=7,live=0,segments=0,participant=False,now=14471,deadline=14500)
        self.clock=lambda:200
        path=self.old/'state.json';path.write_bytes(path.read_bytes()+b' ')
        effects=mock.Mock();guard=launch.LaunchGuard(current,self.current['cells'][0]['id'],lambda:self.registry,effects,lambda _:None)
        with self.assertRaises(launch.LaunchError):current.snapshot()
        effects.assert_not_called()
    def test_carry_counts_prevent_241st_call_and_resource_capacity_never_increases(self):
        current=self.create();prior=current.snapshot()['attempts'];self.assertEqual(prior,7)
        with self.assertRaises(launch.LaunchError):launch._hard_admission(attempts=prior+233,live=0,segments=0,participant=False,now=200,deadline=14500)
        # A smaller original daemon remains the resource ceiling even if the
        # candidate/current daemon capacity is larger; this is a mock-boundary check.
        self.assertEqual(current._carry['daemon_capacity'],self.capacity)
        state=json.loads((current.root/'ledger.json').read_bytes());state['carry']['attempts']=0
        (current.root/'ledger.json').write_text(json.dumps(state))
        with self.assertRaises(launch.LaunchError):current.snapshot()

    def test_frozen_original_capacity_limits_actual_new_reservations(self):
        enlarged={'cpu_millis':64000,'memory_mib':65536}
        current=launch.LaunchLedger.create(self.root/'candidate-ledger',self.current,daemon_id=self.daemon,
            daemon_capacity=enlarged,clock=self.clock,wall=self.wall)
        cell=next(cell for cell in current.manifest['cells'] if cell['group']=='N02')
        for index,role in enumerate(('probe','boundary','preflight','participant')):
            record={'schema':1,'launch_id':str(uuid.uuid4()),'registry':self.registry.registry_id,
                'generation':self.registry.generation,'container':'new-probe-'+str(index),'image':cell['image_id'],'mounts':[],
                'status':'intent','daemon':self.daemon,'binding':{},'runroot':str(self.root/'candidate-run')}
            self.registry.write(record)
            if index<3:
                current.reserve(cell['id'],role,record,{'cpu_millis':1000,'memory_mib':1024,'pids_limit':256},{'id':self.daemon,**enlarged})
            else:
                with self.assertRaises(launch.LaunchError) as error:
                    current.reserve(cell['id'],role,record,{'cpu_millis':1000,'memory_mib':1024,'pids_limit':256},{'id':self.daemon,**enlarged})
                self.assertEqual(error.exception.reason,'qualification_aggregate_limit')
        self.assertEqual(current._carry['daemon_capacity'],self.capacity)
        self.assertEqual(current.snapshot()['live'],3)

    def test_predecessor_cannot_fork_into_new_or_same_id_different_roots(self):
        first=self.create()
        for changed_id in (False,True):
            second=copy.deepcopy(self.current)
            if changed_id:second['qualification_id']=str(uuid.uuid4())
            with self.subTest(changed_id=changed_id),self.assertRaises(launch.LaunchError):
                launch.LaunchLedger.create(self.root/('sibling-'+str(changed_id)),second,daemon_id=self.daemon,
                    daemon_capacity=self.capacity,clock=self.clock,wall=self.wall)
        self.assertEqual(first.snapshot()['attempts'],7)
        self.assertFalse((self.root/'sibling-False').exists());self.assertFalse((self.root/'sibling-True').exists())
        self.assertEqual({str(p):p.read_bytes() for p in self.old.rglob('*') if p.is_file()},self.originals)

    def test_successor_claim_survives_crash_before_candidate_directory_and_cannot_retry(self):
        mkdir=launch.os.mkdir
        def crash(path,*args,**kwargs):
            if path=='candidate-ledger':raise OSError('controlled pre-state crash')
            return mkdir(path,*args,**kwargs)
        with mock.patch.object(launch.os,'mkdir',side_effect=crash),self.assertRaises(OSError):self.create()
        self.assertEqual(len(list((self.root/'campaign-successor-claims').glob('*.json'))),1)
        self.assertFalse((self.root/'candidate-ledger').exists())
        with self.assertRaises(launch.LaunchError):self.create()

    def test_claim_missing_corrupt_or_rerooted_denies_existing_and_new_successors(self):
        first=self.create();path=next((self.root/'campaign-successor-claims').glob('*.json'));body=path.read_bytes()
        for mutation in ('corrupt','rerooted','missing'):
            if mutation=='corrupt':path.write_bytes(b'{')
            elif mutation=='rerooted':
                value=json.loads(body);value['ledger_root']=str(self.root/'foreign');path.write_text(json.dumps(value))
            else:path.unlink()
            with self.subTest(mutation=mutation),self.assertRaises(launch.LaunchError):first.snapshot()
            with self.assertRaises(launch.LaunchError):
                launch.LaunchLedger.create(self.root/'sibling',self.current,daemon_id=self.daemon,
                    daemon_capacity=self.capacity,clock=self.clock,wall=self.wall)
            path.write_bytes(body);path.chmod(0o600)

    def test_parallel_candidate_creators_receive_only_one_durable_claim(self):
        results=[]
        def create(index):
            candidate=copy.deepcopy(self.current);candidate['qualification_id']=str(uuid.uuid4())
            try:
                result=launch.LaunchLedger.create(self.root/('parallel-'+str(index)),candidate,daemon_id=self.daemon,
                    daemon_capacity=self.capacity,clock=self.clock,wall=self.wall)
                results.append(('admitted',result.snapshot()['attempts']))
            except launch.LaunchError:results.append(('denied',None))
        workers=[threading.Thread(target=create,args=(index,)) for index in range(2)]
        for worker in workers:worker.start()
        for worker in workers:worker.join(5)
        self.assertEqual(sorted(results),[('admitted',7),('denied',None)])


if __name__=='__main__':unittest.main()


class LinearCampaignCarryTests(unittest.TestCase):
    """Stopped two-generation files/sidecars; no Docker or real owner facts."""
    def setUp(self):
        import test_ownership_registry as owners
        self.owner=owners.QualificationPreworkerTests();self.owner.setUp();self.addCleanup(self.owner.doCleanups)
        self.owner.write();self.f=self.owner.fixture;self.q=self.owner.q
        self.predecessor={'schema':1,'root':str(self.q),**{k+'_sha256':hashlib.sha256((self.q/rel).read_bytes()).hexdigest()
            for k,rel in [('manifest','manifest.json'),('state','state.json'),('ledger','launch-ledger/ledger.json')]},
            'cleanup_receipts':[self.owner.helper['qualification_preworker_cleanup']]}
        self.current=copy.deepcopy(self.f.current);self.current['qualification_id']=str(uuid.uuid4());self.current['predecessor']=self.predecessor
    def create(self,path=None):
        return launch.LaunchLedger.create(path or self.f.root/'third-ledger',self.current,daemon_id=self.f.daemon,
            daemon_capacity=self.f.capacity,clock=self.f.clock,wall=self.f.wall)
    def test_two_generations_carry_19_zero_segments_56_rows_and_original_deadlines(self):
        before={str(p):p.read_bytes() for root in (self.f.old,self.q) for p in root.rglob('*') if p.is_file()}
        summary=launch.validate_predecessor(self.predecessor,daemon_id=self.f.daemon,clock=self.f.clock,wall=self.f.wall)
        self.assertEqual((summary['attempts'],summary['participant_segments'],summary['planned_cells'],len(summary['prior_rows'])),(19,0,56,56))
        self.assertEqual(len({r['qualification_id'] for r in summary['prior_rows']}),2)
        self.assertEqual((summary['started'],summary['deadline'],summary['started_wall'],summary['deadline_wall']),(100,14500,1000,15400))
        ledger=self.create();snap=ledger.snapshot();self.assertEqual((snap['attempts'],snap['participant_segments'],snap['live']),(19,0,0))
        self.assertEqual(snap['predecessor']['planned_cells'],56)
        self.assertEqual({p:Path(p).read_bytes() for p in before},before)
        self.assertTrue(json.loads((self.q/'launch-ledger/ledger.json').read_bytes())['poisoned'])
    def test_each_root_has_its_own_single_permanent_successor_and_prior_claim_stays_bound(self):
        self.create();other=copy.deepcopy(self.current);other['qualification_id']=str(uuid.uuid4())
        with self.assertRaises(launch.LaunchError):launch.LaunchLedger.create(self.f.root/'sibling-third-ledger',other,daemon_id=self.f.daemon,daemon_capacity=self.f.capacity,clock=self.f.clock,wall=self.f.wall)
        self.assertFalse((self.f.root/'sibling-third-ledger').exists())
        self.assertEqual(len(list((self.f.old.parent/'campaign-successor-claims').glob('*.json'))),2)
    def test_ancestor_claim_corruption_or_metadata_hash_change_blocks_before_new_state(self):
        claim=next((self.f.old.parent/'campaign-successor-claims').glob('*.json'));body=claim.read_bytes();claim.write_bytes(body+b' ')
        # Whitespace preserves JSON semantics; alter a binding rather than a serialization detail.
        value=json.loads(body);value['qualification_id']=str(uuid.uuid4());claim.write_text(json.dumps(value))
        with self.assertRaises(launch.LaunchError):self.create()
        self.assertFalse((self.f.root/'third-ledger').exists());claim.write_bytes(body)
        path=self.f.old/'state.json';path.write_bytes(path.read_bytes()+b' ')
        with self.assertRaises(launch.LaunchError):self.create()
    def test_missing_preworker_sidecar_pending_old_record_or_private_reappearance_denies(self):
        original=copy.deepcopy(self.owner.helper)
        for kind in ('missing','pending','private'):
            self.owner.helper=copy.deepcopy(original)
            if kind=='missing':self.owner.helper.pop('qualification_preworker_cleanup')
            elif kind=='pending':self.owner.helper['status']='absent'
            else:Path(self.owner.helper['private_store']).mkdir(mode=0o700)
            self.owner.registry.write(self.owner.helper)
            with self.subTest(kind=kind),self.assertRaises(launch.LaunchError):self.create()
            if kind=='private':Path(self.owner.helper['private_store']).rmdir()
        self.owner.registry.write(original)
    def test_eighth_ancestor_bound_and_cycle_deny_without_recursing_or_resetting(self):
        with self.assertRaises(launch.LaunchError):launch.validate_predecessor(self.predecessor,clock=self.f.clock,wall=self.f.wall,_lineage=tuple('ancestor-'+str(i) for i in range(8)))
        with self.assertRaises(launch.LaunchError):launch.validate_predecessor(self.predecessor,clock=self.f.clock,wall=self.f.wall,_lineage=(str(self.q),))
    def test_oldest_deadline_and_cumulative_hard_limit_still_apply(self):
        ledger=self.create()
        with self.assertRaises(launch.LaunchError):launch._hard_admission(attempts=19+221,live=0,segments=0,participant=False,now=200,deadline=14500)
        self.assertEqual(ledger.snapshot()['attempts']+186,205)
        cleanup=launch.LaunchLedger(ledger.root,self.current,clock=lambda:14480,wall=self.f.wall)
        self.assertEqual(cleanup.snapshot()['remaining_seconds'],20)
        with self.assertRaises(launch.LaunchError):launch.validate_predecessor(self.predecessor,clock=lambda:14480,wall=self.f.wall)
    def test_old_private_false_probe_rows_require_whole_positive_owner_sidecar(self):
        self.predecessor['cleanup_receipts']=[]
        with self.assertRaises(launch.LaunchError):self.create()
        self.assertFalse((self.f.root/'third-ledger').exists())


class CanonicalCampaignRootTests(unittest.TestCase):
    def setUp(self):
        self.f=CampaignCarryTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
    def test_lexical_predecessor_aliases_cannot_create_another_permanent_successor(self):
        first=self.f.create();root=str(self.f.old)
        aliases=[root+'/',root+'/.',root.replace('/previous','/./previous'),root.replace('/previous','//previous'),'//'+root.lstrip('/'),str(self.f.old.parent/'x/../previous')]
        for index,alias in enumerate(aliases):
            other=copy.deepcopy(self.f.current);other['qualification_id']=str(uuid.uuid4());other['predecessor']['root']=alias
            with self.subTest(alias=alias),self.assertRaises(launch.LaunchError):launch.LaunchLedger.create(self.f.root/('alias-candidate-'+str(index)),other,
                daemon_id=self.f.daemon,daemon_capacity=self.f.capacity,clock=self.f.clock,wall=self.f.wall)
            self.assertFalse((self.f.root/('alias-candidate-'+str(index))).exists())
        self.assertEqual(len(list((self.f.old.parent/'campaign-successor-claims').glob('*.json'))),1)
        self.assertEqual(first.snapshot()['attempts'],7)
    def test_claim_key_itself_rejects_alias_even_when_called_outside_manifest_validation(self):
        first=self.f.create();carry=launch.validate_predecessor(self.f.predecessor,daemon_id=self.f.daemon,clock=self.f.clock,wall=self.f.wall)
        other=copy.deepcopy(self.f.current);other['qualification_id']=str(uuid.uuid4());other['predecessor']['root']+='/'
        with self.assertRaises(launch.LaunchError):launch._successor_claim(self.f.root/'another-candidate',other,carry,create=True)
        self.assertEqual(len(list((self.f.old.parent/'campaign-successor-claims').glob('*.json'))),1)
    def test_canonical_original_root_remains_valid_and_old_history_unmodified(self):
        launch.validate_predecessor(self.f.predecessor,daemon_id=self.f.daemon,clock=self.f.clock,wall=self.f.wall)
        self.f.create()
        self.assertEqual({str(p):p.read_bytes() for p in self.f.old.rglob('*') if p.is_file()},self.f.originals)


class KnownPreworkerCarryTests(unittest.TestCase):
    """Real product-shaped parent cleanup envelopes, synthetic stopped ownership."""
    def setUp(self):
        self.base=LinearCampaignCarryTests();self.base.setUp();self.addCleanup(self.base.doCleanups)
        self.f=self.base.f;self.owner=self.base.owner;self.registry=self.owner.registry
        self.q=self.f.root/'known-preworker';self.q.mkdir(mode=0o700)
        self.policy=copy.deepcopy(self.base.current);self.qid=self.policy['qualification_id']
        self.full=copy.deepcopy(self.owner.full);self.full.update(qualification_id=self.qid,prepared_root=str(self.q),predecessor=self.base.predecessor)
        self.active={'id':self.owner.active['id'],'pid':2**31-1,'run_id':str(uuid.uuid4()),'attempt_id':str(uuid.uuid4())}
        self.trial=str(uuid.uuid4());self.plan='9'*64
        next(c for c in self.full['cells'] if c['id']==self.active['id']).update(plan_sha256=self.plan,trial_id=self.trial)
        self.run=self.q/'scripted-0.87.1/runs'/self.active['run_id'];self.run.mkdir(mode=0o700,parents=True)
        self.stage=str(uuid.uuid4());self.segment=str(uuid.uuid4());self.session=str(uuid.uuid4())
        self.control=self.run/'controls'/self.stage;self.control.mkdir(mode=0o755,parents=True)
        for n in ('task.json','endpoint.json','stage.json'):self.f.put(self.control/n,{'public_metadata':n})
        (self.control/'inbox').mkdir();(self.control/'segments'/self.segment).mkdir(mode=0o700,parents=True)
        self.workspace=self.run/'workspace';self.workspace.mkdir(mode=0o755);self.task=self.workspace/'TASK.md';self.task.write_text('Frozen harmless task\n')
        wi=self.workspace.stat()
        self.desc={'stage_id':self.stage,'kind':'agent','label':'agent-1-participant','run_id':self.active['run_id'],'attempt_id':self.active['attempt_id'],
            'control':str(self.control),'workspace':str(self.workspace),'workspace_identity':[wi.st_dev,wi.st_ino],'admission_lock_file':str(self.f.root/'operation.lock')}
        self.desc_ref=self.f.put(self.run/'stages'/self.stage/'descriptor.json',self.desc)
        self.state_ref=self.f.put(self.run/'stages'/self.stage/'state.json',{'status':'finalized','cleanup_confirmed':True,'exit_code':None,'segment_id':self.segment})
        self.cred_ref=self.f.put(self.run/'stages'/self.stage/'application-credentials.json',{'schema':1,'status':'removed','workspace':'clean','references':{}})
        self.result_ref=self.f.put(self.run/'result.json',{'sealed':True,'status':'FAIL','exit_code':1,'agents':[],
            'invocation':{'status':'invalid','attempted_stages':1},'infrastructure':{'phase':'agents','reason':'ApplicationExecutionError'},
            'termination':{'reason':'application_startup_failed','process_exit_code':None},'run_id':self.active['run_id'],'attempt_id':self.active['attempt_id']})
        self.f.put(self.q/'manifest.json',self.full)
        ledger=launch.LaunchLedger.create(self.q/'launch-ledger',self.policy,daemon_id=self.f.daemon,daemon_capacity=self.f.capacity,clock=self.f.clock,wall=self.f.wall)
        states={};self.services=[];self.ordinary=[];self.helper=None
        for cell in sorted(self.policy['cells'],key=lambda c:c['group']!='N01'):
            if cell['group']!='N01' and cell['id']!=self.active['id']:continue
            roles=cell['role_limits'] if cell['group']=='N01' else {'fixture':1,'scripted-inference':1,'probe':1,'boundary':1,'preflight':1,'application-helper':1}
            states[cell['id']]={'status':'PASS' if cell['group']=='N01' else 'BLOCKED','attempts':1}
            for role in roles:
                lid=str(uuid.uuid4());cid=hashlib.sha256(lid.encode()).hexdigest()
                record={'schema':1,'launch_id':lid,'registry':self.registry.registry_id,'generation':self.registry.generation,'status':'intent','container':'known-'+lid,
                    'image':self.policy['images']['core-'+cell['release']]['id'] if role in launch.EXTERNAL else cell['image_id'],
                    'mounts':[],'binding':{'run_id':self.active['run_id'],'attempt_id':self.active['attempt_id'],'trial_id':self.trial,'plan_sha256':self.plan},
                    'daemon':self.f.daemon,'runroot':str(self.run),'owner_pid':os.getpid()}
                private=None
                if role in launch.EXTERNAL:
                    private=self.f.root/('known-'+role);private.mkdir(mode=0o700)
                    record.update(application_helper=True,client_mode='qualification-'+role,qualification_role=role,qualification_cell=cell['id'],mounts=[{'source':str(private),'target':'/private','rw':False}])
                if role=='application-helper':
                    private=self.run/'application-helpers'/uuid.uuid4().hex;private.mkdir(mode=0o700,parents=True)
                    record.update(application_helper=True,client_mode='application-execution',private_store=str(private),code_identity={'runtime/service.py':'b'*64})
                    record['mounts']=[{'source':str(private/'code'),'target':'/opt/pi-application','rw':False},{'source':str(private/'state'),'target':'/pi-client/state','rw':True},
                        {'source':str(self.run/'application-evidence'/record['container']),'target':'/pi-client/evidence','rw':True}]
                self.registry.write(record);key=ledger.reserve(cell['id'],role,record,launch._role_weight(self.policy,cell,role),{'id':self.f.daemon,**self.f.capacity})
                ordinary=cell['group']=='N02' and role in ('probe','boundary','preflight')
                ledger.note(key,pid=123,container_id=cid,physical='absent',private_cleanup=not ordinary)
                record.update(container_id=cid,status='absent' if ordinary else 'released')
                if role in launch.EXTERNAL:
                    record['status']='absent';identity=ownership_registry.observe_qualification_private(record);private.rmdir()
                    reference=ownership_registry.write_qualification_service_cleanup(record,self.q/(role+'-cleanup.json'),private_identity=identity,
                        physical_absence_confirmed=True,private_bootstrap_removed=True,terminal_available=True,startup_readied=True)
                    record['qualification_service_cleanup']=reference;record['status']='released';self.services.append(reference)
                if role=='application-helper':private.rmdir();self.helper=record
                if ordinary:self.ordinary.append(record)
                self.registry.write(record)
        ledger.poison_scope(self.active['id'],force=True)
        self.f.put(self.q/'state.json',{'schema':1,'phase':'blocked','active_cell':self.active,'cells':states,'started_at':1000})
        cleanup={'schema':1,'status':'removed','workspace':'clean','evidence':'retained','evidence_root':str(self.run/'application-evidence'/self.helper['container']),'safe_to_continue':True,'budget':None}
        self.process={'schema':1,'document_type':'application_preworker_failure','native_tool_budget':None,'native_tool_budget_error':'accounting_unavailable','termination_reason':'application_startup_failed','started':False,'worker_launch_attempted':False,'exit_code':None,'cleanup_confirmed':True,
            'application_completion':{'status':'not_evaluated'},'application_completion_context':None,'application_completion_result':None,
            'application_preworker_cleanup':{'schema':1,'binding':{'run_id':self.active['run_id'],'attempt_id':self.active['attempt_id'],'trial_id':self.trial,'stage_id':self.stage,'segment_id':self.segment,'session_id':self.session,'plan_sha256':self.plan},
                'worker_launch_attempted':False,'helper_launch_attempted':True,'writers_absent':True,'physical_cleanup_confirmed':True,'private_cleanup_confirmed':True,'accounting':'unavailable','completion_eligible':False},
            'application_helper_cleanup':cleanup,'native_tool_budget_cleanup':copy.deepcopy(cleanup),'application_credentials':{'schema':1,'status':'removed','workspace':'clean'}}
        self.process_ref=self.f.put(self.run/'agent-1-participant/process.json',self.process)
        actual_result=json.loads(Path(self.result_ref['path']).read_bytes());actual_result['last_process']=copy.deepcopy(self.process)
        self.result_ref=self.f.put(Path(self.result_ref['path']),actual_result)
        self.envelope=self.f.root/'pi-qualification-cell-known';self.envelope.mkdir(mode=0o700);ei=self.envelope.stat();self.envelope.rmdir()
        self.terminal=self.f.put(self.q/'terminal.json',{'actual_exit':2,'cwd':str(ROOT),'argv':['python3','tools/qualification/application_client.py','collect','--root',str(self.q),'--group','N02','--release','0.87.1']})
        self.invocation=self.f.put(self.q/'invocation.json',{'argv':['python3',str(ROOT/'tools/qualification/application_client.py'),'_cell-run','--root',str(self.q),'--cell-id',self.active['id'],'--private-envelope',str(self.envelope/'initial.json')],'cwd':str(ROOT),'classification':'native_scripted_protocol'})
        self.campaign={'root':str(self.q),**{key+'_sha256':hashlib.sha256((self.q/relative).read_bytes()).hexdigest() for key,relative in [('manifest','manifest.json'),('state','state.json'),('ledger','launch-ledger/ledger.json')]}}
        lineage=copy.deepcopy(self.owner.proof['qualification']['lineage']);lineage.append({'root':str(self.q),**{key:{'path':str(self.q/relative),'sha256':self.campaign[key+'_sha256']} for key,relative in [('manifest','manifest.json'),('state','state.json'),('ledger','launch-ledger/ledger.json')]}})
        allrows=[]
        for entry in lineage:allrows.extend(json.loads(Path(entry['ledger']['path']).read_bytes())['launches'])
        ci=self.control.stat()
        self.proof={'qualification':{'lineage':lineage,'cumulative_attempts':31,'participant_segments':0},
            'controller':{'pid':self.active['pid'],'parent_terminal':self.terminal,'original_invocation':self.invocation,'pid_absence_observed':True,'provenance':'terminal_parent_and_pid_absence'},
            'stage':{'descriptor':self.desc_ref,'state':self.state_ref,'process':self.process_ref,'credentials':self.cred_ref,'result':self.result_ref,'stage_id':self.stage,'segment_id':self.segment},
            'parent_bootstrap':{'path':str(self.envelope),'device':ei.st_dev,'inode':ei.st_ino,'removed':True},
            'control':{'path':str(self.control),'device':ci.st_dev,'inode':ci.st_ino,'retained_files':[{'path':n,'sha256':hashlib.sha256((self.control/n).read_bytes()).hexdigest(),'bytes':(self.control/n).stat().st_size} for n in ('endpoint.json','stage.json','task.json')],
                'directories':['inbox','segments','segments/'+self.segment],'private_contexts_absent':True,'all_parent_authorities_scanned':True},
            'workspace':{'path':str(self.workspace),'device':wi.st_dev,'inode':wi.st_ino,'status':'clean','files':[{'path':'TASK.md','sha256':hashlib.sha256(self.task.read_bytes()).hexdigest(),'bytes':self.task.stat().st_size}],'all_parent_authorities_scanned':True},
            'launches':[{**{k:r[k] for k in ('registry','generation','launch_id','container_id')},'physical_absence_confirmed':True,'private_cleanup_confirmed':True} for r in allrows],
            'service_receipts':self.services,'privacy_scan':{'runroot':str(self.run),'method':'existing_scan_cell_and_cleanup_material','status':'clean','all_parent_authorities_scanned':True,'inventory':launch.known_preworker_inventory(self.run)}}
        self.out=self.f.root/'known-proof';self.out.mkdir(mode=0o700)
    def replace_process(self,data):
        self.proof['stage']['process']=self.f.put(Path(self.process_ref['path']),data)
        result=json.loads(Path(self.result_ref['path']).read_bytes());result['last_process']=copy.deepcopy(data)
        self.proof['stage']['result']=self.f.put(Path(self.result_ref['path']),result)
        self.proof['privacy_scan']['inventory']=launch.known_preworker_inventory(self.run)
    def write(self):return launch.write_known_preworker_cleanup(self.campaign,self.out/'cleanup.json',proof=self.proof,clock=self.f.clock,wall=self.f.wall)
    def release(self):
        for record in self.ordinary:self.registry.release(record,True)
    def validate(self,reference,**kwargs):return launch.validate_known_preworker_cleanup(self.campaign,reference,clock=self.f.clock,wall=self.f.wall,**kwargs)
    def test_positive_product_known_cleanup_allows_sidecar_before_release_then_final31_carry(self):
        originals={str(p):p.read_bytes() for p in (self.run/'agent-1-participant/process.json',Path(self.result_ref['path']),Path(self.state_ref['path']))}
        reference=self.write();self.validate(reference)
        with self.assertRaises(launch.LaunchError):self.validate(reference,require_released=True)
        self.release();self.validate(reference,require_released=True)
        descriptor={'schema':1,**self.campaign,'cleanup_receipts':[reference]};summary=launch.validate_predecessor(descriptor,clock=self.f.clock,wall=self.f.wall)
        self.assertEqual((summary['attempts'],summary['participant_segments'],summary['planned_cells'],len(summary['prior_rows'])),(31,0,84,84))
        policy=copy.deepcopy(self.policy);policy['qualification_id']=str(uuid.uuid4());policy['predecessor']=descriptor
        current=launch.LaunchLedger.create(self.f.root/'fourth-ledger',policy,daemon_id=self.f.daemon,daemon_capacity=self.f.capacity,clock=self.f.clock,wall=self.f.wall)
        self.assertEqual(current.snapshot()['attempts'],31);self.assertEqual(current.snapshot()['predecessor']['planned_cells'],84)
        self.assertEqual(31+186,217);self.assertEqual({p:Path(p).read_bytes() for p in originals},originals)
        self.assertNotIn('qualification_preworker_cleanup',self.helper)
    def test_worker_started_exit_code_or_unconfirmed_product_flags_never_become_positive(self):
        original=copy.deepcopy(self.process)
        for path,value in [('started',True),('worker_launch_attempted',True),('exit_code',0),('cleanup_confirmed',False),('document_type','worker_process')]:
            data=copy.deepcopy(original);data[path]=value;self.replace_process(data)
            with self.subTest(path=path),self.assertRaises(launch.LaunchError):self.write()
            self.assertFalse((self.out/'cleanup.json').exists())
    def test_nested_cleanup_accounting_or_completion_cannot_be_fabricated(self):
        for field,value in [('writers_absent',False),('physical_cleanup_confirmed',False),('private_cleanup_confirmed',False),('accounting','available'),('completion_eligible',True)]:
            data=copy.deepcopy(self.process);data['application_preworker_cleanup'][field]=value
            self.replace_process(data)
            with self.subTest(field=field),self.assertRaises(launch.LaunchError):self.write()
    def test_missing_changed_credentials_or_private_context_blocks_known_cleanup(self):
        original=Path(self.cred_ref['path']).read_bytes();Path(self.cred_ref['path']).write_bytes(original+b' ')
        with self.assertRaises(launch.LaunchError):self.write()
        Path(self.cred_ref['path']).write_bytes(original)
        private=self.control/'segments'/self.segment/'application-context.json';private.write_text('synthetic private context')
        with self.assertRaises(launch.LaunchError):self.write()
    def test_workspace_unchanged_fd_and_whole_run_scan_are_required(self):
        self.task.write_text('changed workspace')
        with self.assertRaises(launch.LaunchError):self.write()
        self.task.write_text('Frozen harmless task\n');self.proof['privacy_scan']['inventory']['sha256']='0'*64
        with self.assertRaises(launch.LaunchError):self.write()
    def test_live_parent_or_recreated_parent_envelope_denies(self):
        with mock.patch.object(launch.os,'kill',return_value=None),self.assertRaises(launch.LaunchError):self.write()
        self.envelope.mkdir(mode=0o700)
        with self.assertRaises(launch.LaunchError):self.write()
    def test_all31_bound_ids_and_current_two_service_proofs_are_mandatory(self):
        original=copy.deepcopy(self.proof)
        for change in (lambda p:p['launches'].pop(),lambda p:p['launches'][-1].update(container_id='f'*64),lambda p:p['service_receipts'].pop(),lambda p:p['qualification'].update(cumulative_attempts=12)):
            self.proof=copy.deepcopy(original);change(self.proof)
            with self.assertRaises(launch.LaunchError):self.write()
    def test_unknown_ordinary_record_status_does_not_use_positive_cleanup(self):
        self.ordinary[0]['status']='quarantined';self.registry.write(self.ordinary[0])
        with self.assertRaises(launch.LaunchError):self.write()

    def test_product_unknown_budget_must_stay_null_and_required_worker_fields_cannot_be_omitted(self):
        original=copy.deepcopy(self.process)
        for mutation in ('missing_exit','budget_zero','boolean_schema'):
            data=copy.deepcopy(original)
            if mutation=='missing_exit':data.pop('exit_code')
            elif mutation=='budget_zero':data['native_tool_budget']={'calls_total':0}
            else:data['schema']=True
            self.replace_process(data)
            with self.subTest(mutation=mutation),self.assertRaises(launch.LaunchError):self.write()
    def test_whole_run_changed_after_scan_or_linked_workspace_cannot_supply_privacy_proof(self):
        extra=self.run/'unscanned.txt';extra.write_text('new unscanned material')
        with self.assertRaises(launch.LaunchError):self.write()
        extra.unlink();alias=self.workspace/'linked';alias.symlink_to(self.task)
        with self.assertRaises(launch.LaunchError):self.write()

    def test_sealed_result_last_process_must_exist_and_canonically_equal_actual_process(self):
        original=json.loads(Path(self.result_ref['path']).read_bytes())
        for mutation in ('missing','session_mismatch','typed_schema_alias'):
            result=copy.deepcopy(original)
            if mutation=='missing':result.pop('last_process')
            elif mutation=='session_mismatch':result['last_process']['application_preworker_cleanup']['binding']['session_id']=str(uuid.uuid4())
            else:result['last_process']['schema']=1.0
            self.proof['stage']['result']=self.f.put(Path(self.result_ref['path']),result)
            self.proof['privacy_scan']['inventory']=launch.known_preworker_inventory(self.run)
            with self.subTest(mutation=mutation),self.assertRaises(launch.LaunchError):self.write()
            self.assertFalse((self.out/'cleanup.json').exists())


class KnownAdmissionCarryTests(unittest.TestCase):
    """Synthetic closed admission-only campaign; no real cleanup/native facts."""
    def setUp(self):
        self.parent=KnownPreworkerCarryTests();self.parent.setUp();self.addCleanup(self.parent.doCleanups)
        reference=self.parent.write();self.parent.release();self.f=self.parent.f;self.registry=self.parent.registry
        previous={'schema':1,**self.parent.campaign,'cleanup_receipts':[reference]}
        self.q=self.f.root/'admission-clean';self.q.mkdir(mode=0o700)
        self.policy=copy.deepcopy(self.parent.policy);self.policy.update(qualification_id=str(uuid.uuid4()),predecessor=previous)
        self.full=copy.deepcopy(self.parent.full);self.full.update(qualification_id=self.policy['qualification_id'],prepared_root=str(self.q),predecessor=previous)
        self.active={'id':self.parent.active['id'],'pid':2**31-1,'run_id':str(uuid.uuid4()),'attempt_id':str(uuid.uuid4())}
        self.run=self.q/'scripted-0.87.1/runs'/self.active['run_id'];self.run.mkdir(mode=0o700,parents=True)
        self.result={'schema':2,'document_type':'run_result','sealed':True,'status':'BLOCKED','exit_code':2,'agents':[],'checks':[],'workspace':None,
            'invocation':{'status':'not_started','attempted_stages':0},'infrastructure':{'status':'failed','phase':'admission','reason':'QualificationError'},
            'termination':{'reason':'not_started','trigger':None,'process_exit_code':None},'run_id':self.active['run_id'],'attempt_id':self.active['attempt_id'],
            'application_execution':{'schema':1,'plan_sha256':self.parent.plan,'required_stages':['participant']}}
        self.result_ref=self.f.put(self.run/'result.json',self.result);self.f.put(self.run/'summary.json',{'status':'BLOCKED'})
        self.child={'schema':1,'run_id':self.active['run_id'],'attempt_id':self.active['attempt_id'],'result_sha256':self.result_ref['sha256'],'cleanup_checked':True}
        self.child_ref=self.f.put(self.q/'cells'/self.active['id']/'child-completion.json',self.child)
        self.f.put(self.q/'manifest.json',self.full)
        ledger=launch.LaunchLedger.create(self.q/'launch-ledger',self.policy,daemon_id=self.f.daemon,daemon_capacity=self.f.capacity,clock=self.f.clock,wall=self.f.wall)
        states={};self.services=[]
        for cell in sorted(self.policy['cells'],key=lambda c:c['group']!='N01'):
            if cell['group']!='N01' and cell['id']!=self.active['id']:continue
            roles=cell['role_limits'] if cell['group']=='N01' else {'fixture':1,'scripted-inference':1}
            states[cell['id']]={'status':'PASS' if cell['group']=='N01' else 'BLOCKED','attempts':1}
            for role in roles:
                lid=str(uuid.uuid4());cid=hashlib.sha256(lid.encode()).hexdigest()
                record={'schema':1,'launch_id':lid,'registry':self.registry.registry_id,'generation':self.registry.generation,'status':'intent','container':'admission-'+lid,
                    'image':self.policy['images']['core-'+cell['release']]['id'] if role in launch.EXTERNAL else cell['image_id'],
                    'mounts':[],'binding':{'run_id':self.active['run_id'],'attempt_id':self.active['attempt_id']},'daemon':self.f.daemon,'runroot':str(self.run),'owner_pid':os.getpid()}
                if role in launch.EXTERNAL:
                    private=self.f.root/('admission-'+role);private.mkdir(mode=0o700)
                    record.update(application_helper=True,client_mode='qualification-'+role,qualification_role=role,qualification_cell=cell['id'],mounts=[{'source':str(private),'target':'/private','rw':False}])
                self.registry.write(record);key=ledger.reserve(cell['id'],role,record,launch._role_weight(self.policy,cell,role),{'id':self.f.daemon,**self.f.capacity})
                ledger.note(key,pid=123,container_id=cid,physical='absent',private_cleanup=True);record.update(container_id=cid,status='released')
                if role in launch.EXTERNAL:
                    record['status']='absent';identity=ownership_registry.observe_qualification_private(record);private.rmdir()
                    ref=ownership_registry.write_qualification_service_cleanup(record,self.q/(role+'-cleanup.json'),private_identity=identity,
                        physical_absence_confirmed=True,private_bootstrap_removed=True,terminal_available=True,startup_readied=True)
                    record['qualification_service_cleanup']=ref;record['status']='released';self.services.append(ref)
                self.registry.write(record)
        self.f.put(self.q/'state.json',{'schema':1,'phase':'blocked','active_cell':self.active,'cells':states,'started_at':1000})
        self.envelope=self.f.root/'pi-qualification-cell-admission';self.envelope.mkdir(mode=0o700);ei=self.envelope.stat();self.envelope.rmdir()
        terminal=self.f.put(self.q/'terminal.json',{'actual_exit':2,'cwd':str(ROOT),'argv':['python3','tools/qualification/application_client.py','collect','--root',str(self.q),'--group','N02','--release','0.87.1']})
        invocation=self.f.put(self.q/'invocation.json',{'argv':['python3',str(ROOT/'tools/qualification/application_client.py'),'_cell-run','--root',str(self.q),'--cell-id',self.active['id'],'--private-envelope',str(self.envelope/'initial.json')],
            'cwd':str(ROOT),'classification':'native_scripted_protocol'})
        self.campaign={'root':str(self.q),**{key+'_sha256':hashlib.sha256((self.q/relative).read_bytes()).hexdigest() for key,relative in [('manifest','manifest.json'),('state','state.json'),('ledger','launch-ledger/ledger.json')]}}
        lineage=copy.deepcopy(self.parent.proof['qualification']['lineage']);lineage.append({'root':str(self.q),**{key:{'path':str(self.q/relative),'sha256':self.campaign[key+'_sha256']} for key,relative in [('manifest','manifest.json'),('state','state.json'),('ledger','launch-ledger/ledger.json')]}})
        allrows=[]
        for entry in lineage:allrows.extend(json.loads(Path(entry['ledger']['path']).read_bytes())['launches'])
        self.proof={'qualification':{'lineage':lineage,'cumulative_attempts':39,'participant_segments':0},
            'controller':{'pid':self.active['pid'],'parent_terminal':terminal,'original_invocation':invocation,'pid_absence_observed':True,'provenance':'terminal_parent_and_pid_absence'},
            'run':{'result':self.result_ref,'child_completion':self.child_ref},'parent_bootstrap':{'path':str(self.envelope),'device':ei.st_dev,'inode':ei.st_ino,'removed':True},
            'launches':[{**{k:r[k] for k in ('registry','generation','launch_id','container_id')},'physical_absence_confirmed':True,'private_cleanup_confirmed':True} for r in allrows],
            'service_receipts':self.services,'privacy_scan':{'runroot':str(self.run),'method':'existing_scan_cell_and_cleanup_material','status':'clean','all_parent_authorities_scanned':True,'inventory':launch.known_preworker_inventory(self.run)}}
        self.out=self.f.root/'admission-proof';self.out.mkdir(mode=0o700)
    def write(self):return launch.write_known_admission_cleanup(self.campaign,self.out/'cleanup.json',proof=self.proof,clock=self.f.clock,wall=self.f.wall)
    def replace_result(self,result):
        self.proof['run']['result']=self.f.put(Path(self.result_ref['path']),result);child=copy.deepcopy(self.child);child['result_sha256']=self.proof['run']['result']['sha256']
        self.proof['run']['child_completion']=self.f.put(Path(self.child_ref['path']),child);self.proof['privacy_scan']['inventory']=launch.known_preworker_inventory(self.run)
    def test_strict_false_clean_8roles_carry39_zero_112rows_and225planned(self):
        originals={str(p):p.read_bytes() for entry in self.proof['qualification']['lineage'] for p in (Path(entry['manifest']['path']),Path(entry['state']['path']),Path(entry['ledger']['path']))}
        ref=self.write();receipt=launch.validate_known_admission_cleanup(self.campaign,ref,clock=self.f.clock,wall=self.f.wall)
        self.assertNotIn('stage',receipt);self.assertNotIn('workspace',receipt)
        descriptor={'schema':1,**self.campaign,'cleanup_receipts':[ref]};summary=launch.validate_predecessor(descriptor,clock=self.f.clock,wall=self.f.wall)
        self.assertEqual((summary['attempts'],summary['participant_segments'],summary['planned_cells'],len(summary['prior_rows'])),(39,0,112,112))
        policy=copy.deepcopy(self.policy);policy.update(qualification_id=str(uuid.uuid4()),predecessor=descriptor)
        current=launch.LaunchLedger.create(self.f.root/'fifth-ledger',policy,daemon_id=self.f.daemon,daemon_capacity=self.f.capacity,clock=self.f.clock,wall=self.f.wall)
        self.assertEqual(current.snapshot()['attempts'],39);self.assertEqual(39+186,225)
        self.assertFalse(json.loads(Path(self.campaign['root'],'launch-ledger/ledger.json').read_bytes())['poisoned'])
        self.assertEqual({p:Path(p).read_bytes() for p in originals},originals)
    def test_missing_wrong_hash_or_unchecked_child_completion_rejects(self):
        original=copy.deepcopy(self.child)
        for key,value in [('result_sha256','f'*64),('cleanup_checked',False),('run_id',str(uuid.uuid4())),('schema',True)]:
            child=copy.deepcopy(original);child[key]=value;self.proof['run']['child_completion']=self.f.put(Path(self.child_ref['path']),child)
            with self.subTest(key=key),self.assertRaises(launch.LaunchError):self.write()
            self.assertFalse((self.out/'cleanup.json').exists())
    def test_nonzero_invocation_fake_process_or_workspace_cannot_be_admission_only(self):
        for change in (lambda r:r['invocation'].update(attempted_stages=1),lambda r:r.update(last_process={'started':False}),lambda r:r.update(workspace=str(self.run/'workspace')),
                       lambda r:r['infrastructure'].update(phase='agents'),lambda r:r.update(agents=[{}]),lambda r:r['invocation'].update(attempted_stages=False)):
            result=copy.deepcopy(self.result);change(result);self.replace_result(result)
            with self.assertRaises(launch.LaunchError):self.write()
    def test_stage_helper_or_private_runtime_directories_deny_without_fabricated_receipts(self):
        for name in ('stages','controls','children','workspace','application-helpers','application-evidence','application-startup'):
            path=self.run/name;path.mkdir(mode=0o700)
            self.proof['privacy_scan']['inventory']=launch.known_preworker_inventory(self.run)
            with self.subTest(name=name),self.assertRaises(launch.LaunchError):self.write()
            path.rmdir()
    def test_true_poison_or_unconfirmed_row_cannot_use_clean_admission_branch(self):
        ledger_path=Path(self.campaign['root'])/'launch-ledger/ledger.json';original=ledger_path.read_bytes();base=copy.deepcopy(self.campaign)
        for mutation in ('poison','private','physical'):
            data=json.loads(original)
            if mutation=='poison':data['poisoned']=True
            elif mutation=='private':data['launches'][-1]['private_cleanup']=False
            else:data['launches'][-1]['physical']='uncertain'
            ledger_path.write_text(json.dumps(data));sha=hashlib.sha256(ledger_path.read_bytes()).hexdigest();self.campaign={**base,'ledger_sha256':sha}
            self.proof['qualification']['lineage'][-1]['ledger']['sha256']=sha
            with self.subTest(mutation=mutation),self.assertRaises(launch.LaunchError):self.write()
        ledger_path.write_bytes(original)
    def test_all39_ids_two_services_and_parent_envelope_absence_required(self):
        original=copy.deepcopy(self.proof)
        for change in (lambda p:p['launches'].pop(),lambda p:p['service_receipts'].pop(),lambda p:p['launches'][-1].update(container_id='f'*64),lambda p:p['qualification'].update(cumulative_attempts=8)):
            self.proof=copy.deepcopy(original);change(self.proof)
            with self.assertRaises(launch.LaunchError):self.write()
        self.proof=original;self.envelope.mkdir(mode=0o700)
        with self.assertRaises(launch.LaunchError):self.write()
    def test_pending_current_registry_or_live_controller_and_stale_scan_deny(self):
        row=json.loads(Path(self.campaign['root'],'launch-ledger/ledger.json').read_bytes())['launches'][0]
        path=self.registry.root/(row['launch_id']+'.json');record=ownership_registry.read_private(path);original=copy.deepcopy(record)
        record['status']='absent';self.registry.write(record)
        with self.assertRaises(launch.LaunchError):self.write()
        self.registry.write(original)
        with mock.patch.object(launch.os,'kill',return_value=None),self.assertRaises(launch.LaunchError):self.write()
        self.proof['privacy_scan']['inventory']['sha256']='0'*64
        with self.assertRaises(launch.LaunchError):self.write()


class KnownZeroLaunchCarryTests(unittest.TestCase):
    """Offline synthetic fifth campaign; never launch/read keys/repair old rows."""
    def setUp(self):
        self.parent=KnownAdmissionCarryTests();self.parent.setUp();self.addCleanup(self.parent.doCleanups)
        reference=self.parent.write();self.f=self.parent.f;self.registry=self.parent.registry
        previous={'schema':1,**self.parent.campaign,'cleanup_receipts':[reference]}
        self.q=self.f.root/'zero-launch';self.q.mkdir(mode=0o700)
        self.policy=copy.deepcopy(self.parent.policy);self.policy.update(qualification_id=str(uuid.uuid4()),predecessor=previous)
        self.full=copy.deepcopy(self.parent.full);self.full.update(qualification_id=self.policy['qualification_id'],prepared_root=str(self.q),predecessor=previous,
            source={'runner':'a'*64,'sha256':'b'*64})
        self.f.put(self.q/'manifest.json',self.full)
        self.ledger=launch.LaunchLedger.create(self.q/'launch-ledger',self.policy,daemon_id=self.f.daemon,daemon_capacity=self.f.capacity,clock=self.f.clock,wall=self.f.wall)
        self.state={'schema':1,'phase':'blocked','active_cell':None,'cells':{'N01-0.87.1-core':{'status':'BLOCKED','attempts':1,'reason':'infrastructure_qualification_failed'}},'started_at':1000}
        self.f.put(self.q/'state.json',self.state)
        candidate=self.f.put(self.q/'candidate.json',{'archive_sha256':'c'*64,'runner_sha256':'a'*64,'scope':'extracted_candidate'})
        terminal=self.f.put(self.q/'terminal.json',{'argv':['python3','tools/qualification/application_client.py','admit','--root',str(self.q)],'cwd':str(ROOT),'actual_exit':2})
        self.campaign={'root':str(self.q),**{key+'_sha256':hashlib.sha256((self.q/relative).read_bytes()).hexdigest() for key,relative in [('manifest','manifest.json'),('state','state.json'),('ledger','launch-ledger/ledger.json')]}}
        lineage=copy.deepcopy(self.parent.proof['qualification']['lineage']);lineage.append({'root':str(self.q),**{key:{'path':str(self.q/relative),'sha256':self.campaign[key+'_sha256']} for key,relative in [('manifest','manifest.json'),('state','state.json'),('ledger','launch-ledger/ledger.json')]}})
        self.proof={'qualification':{'lineage':lineage,'cumulative_attempts':39,'participant_segments':0},'controller':{'parent_terminal':terminal},
            'inputs':{'candidate':candidate,'source_sha256':'b'*64},'prior_cleanup':reference,'launches':copy.deepcopy(self.parent.proof['launches'])}
        self.out=self.f.root/'zero-launch-proof';self.out.mkdir(mode=0o700)
    def write(self):return launch.write_known_zero_launch_cleanup(self.campaign,self.out/'cleanup.json',proof=self.proof,clock=self.f.clock,wall=self.f.wall)
    def advance_zero(self):
        """Create only a synthetic consecutive zero launch; immutable predecessor retained."""
        reference=self.write();previous={'schema':1,**self.campaign,'cleanup_receipts':[reference]}
        prior_q=self.q;self.q=self.f.root/('zero-launch-'+str(len(self.proof['qualification']['lineage'])+1));self.q.mkdir(mode=0o700)
        self.policy=copy.deepcopy(self.policy);self.policy.update(qualification_id=str(uuid.uuid4()),predecessor=previous)
        self.full=copy.deepcopy(self.full);self.full.update(qualification_id=self.policy['qualification_id'],prepared_root=str(self.q),predecessor=previous)
        self.f.put(self.q/'manifest.json',self.full)
        self.ledger=launch.LaunchLedger.create(self.q/'launch-ledger',self.policy,daemon_id=self.f.daemon,daemon_capacity=self.f.capacity,clock=self.f.clock,wall=self.f.wall)
        self.f.put(self.q/'state.json',self.state)
        candidate=self.f.put(self.q/'candidate.json',{'archive_sha256':'c'*64,'runner_sha256':'a'*64,'scope':'extracted_candidate'})
        terminal=self.f.put(self.q/'terminal.json',{'argv':['python3','tools/qualification/application_client.py','admit','--root',str(self.q)],'cwd':str(ROOT),'actual_exit':2})
        self.campaign={'root':str(self.q),**{key+'_sha256':hashlib.sha256((self.q/relative).read_bytes()).hexdigest() for key,relative in [('manifest','manifest.json'),('state','state.json'),('ledger','launch-ledger/ledger.json')]}}
        self.proof=copy.deepcopy(self.proof);self.proof['prior_cleanup']=reference;self.proof['controller']={'parent_terminal':terminal};self.proof['inputs']['candidate']=candidate
        self.proof['qualification']['lineage'].append({'root':str(self.q),**{key:{'path':str(self.q/relative),'sha256':self.campaign[key+'_sha256']} for key,relative in [('manifest','manifest.json'),('state','state.json'),('ledger','launch-ledger/ledger.json')]}})
        self.out=self.f.root/('zero-proof-'+str(len(self.proof['qualification']['lineage'])));self.out.mkdir(mode=0o700)
        return prior_q
    def replace(self,name,value):
        relative={'state':'state.json','ledger':'launch-ledger/ledger.json'}[name];ref=self.f.put(self.q/relative,value)
        self.campaign[name+'_sha256']=ref['sha256'];self.proof['qualification']['lineage'][-1][name]['sha256']=ref['sha256']
    def test_zero_launch_preserves_five_histories39_zero140rows_and225planned(self):
        originals={str(p):p.read_bytes() for entry in self.proof['qualification']['lineage'] for p in (Path(entry['manifest']['path']),Path(entry['state']['path']),Path(entry['ledger']['path']))}
        ref=self.write();receipt=launch.validate_known_zero_launch_cleanup(self.campaign,ref,clock=self.f.clock,wall=self.f.wall)
        self.assertNotIn('run',receipt);self.assertNotIn('pid',receipt['controller']);self.assertNotIn('parent_bootstrap',receipt)
        descriptor={'schema':1,**self.campaign,'cleanup_receipts':[ref]};summary=launch.validate_predecessor(descriptor,clock=self.f.clock,wall=self.f.wall)
        self.assertEqual((summary['attempts'],summary['participant_segments'],summary['planned_cells'],len(summary['prior_rows'])),(39,0,140,140))
        self.assertEqual(summary['deadline_wall'],json.loads((self.q/'launch-ledger/ledger.json').read_bytes())['deadline_wall'])
        policy=copy.deepcopy(self.policy);policy.update(qualification_id=str(uuid.uuid4()),predecessor=descriptor)
        current=launch.LaunchLedger.create(self.f.root/'sixth-ledger',policy,daemon_id=self.f.daemon,daemon_capacity=self.f.capacity,clock=self.f.clock,wall=self.f.wall)
        self.assertEqual(current.snapshot()['attempts'],39);self.assertEqual(39+186,225)
        self.assertEqual({p:Path(p).read_bytes() for p in originals},originals)
    def test_active_identity_poison_launches_or_other_attempts_denied(self):
        original=copy.deepcopy(self.state)
        for change in (lambda s:s.update(active_cell=copy.deepcopy(self.parent.active)),lambda s:s['cells']['N01-0.87.1-core'].update(attempts=True),
                       lambda s:s['cells'].update({'N01-1.2.0-core':{'status':'NOT_RUN','attempts':0}}),lambda s:s['cells']['N01-0.87.1-core'].update(status='PASS')):
            data=copy.deepcopy(original);change(data);self.replace('state',data)
            with self.assertRaises(launch.LaunchError):self.write()
        self.replace('state',original);ledger=json.loads((self.q/'launch-ledger/ledger.json').read_bytes());ledger['poisoned']=True;self.replace('ledger',ledger)
        with self.assertRaises(launch.LaunchError):self.write()
        self.assertFalse((self.out/'cleanup.json').exists())
    def test_expired_or_rollback_clocks_cannot_grow_the_original_window(self):
        ref=self.write();descriptor={'schema':1,**self.campaign,'cleanup_receipts':[ref]}
        ledger=json.loads((self.q/'launch-ledger/ledger.json').read_bytes())
        for clock,wall in ((lambda:ledger['deadline'],self.f.wall),(self.f.clock,lambda:ledger['deadline_wall']),
                           (lambda:ledger['last_now']-1,self.f.wall),(self.f.clock,lambda:ledger['last_wall']-1)):
            with self.assertRaises(launch.LaunchError):launch.validate_predecessor(descriptor,clock=clock,wall=wall)
    def test_terminal_candidate_source_prior_hash_and_missing_observations_denied(self):
        original=copy.deepcopy(self.proof)
        for change in (lambda p:p['qualification'].update(cumulative_attempts=0),lambda p:p['qualification'].update(participant_segments=True),
                       lambda p:p['prior_cleanup'].update(sha256='0'*64),lambda p:p['inputs'].update(source_sha256='0'*64),
                       lambda p:p['inputs']['candidate'].update(sha256='0'*64),lambda p:p['controller']['parent_terminal'].update(sha256='0'*64),
                       lambda p:p['qualification']['lineage'][0].update(root=str(self.q)),lambda p:p['launches'].pop(),
                       lambda p:p['launches'][0].update(physical_absence_confirmed=False)):
            self.proof=copy.deepcopy(original);change(self.proof)
            with self.assertRaises(launch.LaunchError):self.write()
        self.assertFalse((self.out/'cleanup.json').exists())
    def test_admit_terminal_not_other_command_or_success(self):
        path=Path(self.proof['controller']['parent_terminal']['path']);original=json.loads(path.read_bytes())
        for change in (lambda t:t.update(actual_exit=0),lambda t:t['argv'].__setitem__(2,'collect'),lambda t:t.update(cwd='/tmp')):
            terminal=copy.deepcopy(original);change(terminal);self.proof['controller']['parent_terminal']=self.f.put(path,terminal)
            with self.assertRaises(launch.LaunchError):self.write()
    def test_runtime_and_child_paths_deny_no_fake_noop_receipts(self):
        for path in (self.q/'runs',self.q/'scripted-0.87.1/runs',self.q/'scripted-1.2.0/private',self.q/'cells/N01-0.87.1-core/child-completion.json'):
            path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.mkdir(mode=0o700)
            with self.subTest(path=str(path)),self.assertRaises(launch.LaunchError):self.write()
            path.rmdir()
    def test_released_registry_identity_and_sidecar_integrity_required(self):
        row=self.proof['launches'][0];path=self.registry.root/(row['launch_id']+'.json');record=ownership_registry.read_private(path)
        bad=copy.deepcopy(record);bad['status']='absent';self.registry.write(bad)
        with self.assertRaises(launch.LaunchError):self.write()
        self.registry.write(record);ref=self.write();path=Path(ref['path']);path.write_bytes(path.read_bytes()+b' ')
        with self.assertRaises(launch.LaunchError):launch.validate_known_zero_launch_cleanup(self.campaign,ref,clock=self.f.clock,wall=self.f.wall)
    def test_one_successor_alias_and_sibling_denials_remain(self):
        ref=self.write();descriptor={'schema':1,**self.campaign,'cleanup_receipts':[ref]};policy=copy.deepcopy(self.policy)
        policy.update(qualification_id=str(uuid.uuid4()),predecessor=descriptor)
        launch.LaunchLedger.create(self.f.root/'claimed-sixth',policy,daemon_id=self.f.daemon,daemon_capacity=self.f.capacity,clock=self.f.clock,wall=self.f.wall)
        for alias in ('/','/./','//'):
            changed=copy.deepcopy(descriptor);changed['root']+=alias
            with self.assertRaises(launch.LaunchError):launch.validate_predecessor(changed,clock=self.f.clock,wall=self.f.wall)
        policy['qualification_id']=str(uuid.uuid4())
        with self.assertRaises(launch.LaunchError):launch.LaunchLedger.create(self.f.root/'sibling-sixth',policy,daemon_id=self.f.daemon,daemon_capacity=self.f.capacity,clock=self.f.clock,wall=self.f.wall)
    def test_consecutive_zero_launches_retain39_zero168_rows_no_skip_and_no_reset(self):
        originals={str(p):p.read_bytes() for entry in self.proof['qualification']['lineage'] for p in (Path(entry['manifest']['path']),Path(entry['state']['path']),Path(entry['ledger']['path']))}
        deadline=json.loads((self.q/'launch-ledger/ledger.json').read_bytes())['deadline_wall'];self.advance_zero()
        ref=self.write();descriptor={'schema':1,**self.campaign,'cleanup_receipts':[ref]};summary=launch.validate_predecessor(descriptor,clock=self.f.clock,wall=self.f.wall)
        self.assertEqual((summary['attempts'],summary['participant_segments'],summary['planned_cells'],len(summary['prior_rows']),len(summary['lineage'])),(39,0,168,168,6))
        self.assertEqual(summary['deadline_wall'],deadline);self.assertEqual({p:Path(p).read_bytes() for p in originals},originals)
        original=copy.deepcopy(self.proof)
        skipped={'path':str(self.parent.out/'cleanup.json'),'sha256':hashlib.sha256((self.parent.out/'cleanup.json').read_bytes()).hexdigest()}
        for change in (lambda p:p['qualification']['lineage'].pop(-2),lambda p:p['qualification'].update(participant_segments=1),
                       lambda p:p.update(prior_cleanup=copy.deepcopy(skipped))):
            self.proof=copy.deepcopy(original);change(self.proof)
            with self.assertRaises(launch.LaunchError):launch.write_known_zero_launch_cleanup(self.campaign,self.out/'invalid.json',proof=self.proof,clock=self.f.clock,wall=self.f.wall)
        self.proof=original;policy=copy.deepcopy(self.policy);policy.update(qualification_id=str(uuid.uuid4()),predecessor=descriptor)
        policy['limits']['live']=5
        with self.assertRaises(launch.LaunchError):launch.LaunchLedger.create(self.f.root/'raised-cap-seventh',policy,daemon_id=self.f.daemon,daemon_capacity=self.f.capacity,clock=self.f.clock,wall=self.f.wall)
        policy['limits']=copy.deepcopy(launch.LIMITS)
        launch.LaunchLedger.create(self.f.root/'seventh',policy,daemon_id=self.f.daemon,daemon_capacity=self.f.capacity,clock=self.f.clock,wall=self.f.wall)
        policy['qualification_id']=str(uuid.uuid4())
        with self.assertRaises(launch.LaunchError):launch.LaunchLedger.create(self.f.root/'seventh-sibling',policy,daemon_id=self.f.daemon,daemon_capacity=self.f.capacity,clock=self.f.clock,wall=self.f.wall)
    def test_eighth_origin_is_final_no_ninth_claim_or_ledger(self):
        for _ in range(3):self.advance_zero()
        ref=self.write();descriptor={'schema':1,**self.campaign,'cleanup_receipts':[ref]}
        summary=launch.validate_predecessor(descriptor,clock=self.f.clock,wall=self.f.wall)
        self.assertEqual((len(summary['lineage']),summary['planned_cells'],summary['attempts']),(8,224,39))
        policy=copy.deepcopy(self.policy);policy.update(qualification_id=str(uuid.uuid4()),predecessor=descriptor)
        claims=sorted(str(p) for p in self.f.root.rglob('*.json') if 'successor' in str(p));target=self.f.root/'ninth-ledger'
        with self.assertRaises(launch.LaunchError):launch.LaunchLedger.create(target,policy,daemon_id=self.f.daemon,daemon_capacity=self.f.capacity,clock=self.f.clock,wall=self.f.wall)
        self.assertFalse(target.exists());self.assertEqual(claims,sorted(str(p) for p in self.f.root.rglob('*.json') if 'successor' in str(p)))
        with self.assertRaises(launch.LaunchError):launch._successor_claim(target,policy,summary,create=True)
