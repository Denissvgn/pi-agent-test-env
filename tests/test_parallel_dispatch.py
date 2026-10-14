"""Private grant and process-channel fixtures; no Docker/Pi/model execution."""
import contextlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'skill/scripts'))
from parallel_dispatch import Channel,RemoteAdmission,Peer
from parallel_allocator import Allocator
from parallel_contract import ParallelError
import ownership_registry
import pi_lab as lab


class ChannelTests(unittest.TestCase):
    def pair(self):
        a,b=socket.socketpair();self.addCleanup(a.close);self.addCleanup(b.close);return Channel(a),Channel(b)
    def test_private_channel_round_trip_bound_and_parent_loss(self):
        a,b=self.pair();a.send({'op':'fixture','trial':'a'});self.assertEqual(b.receive()['trial'],'a')
        with self.assertRaises(ParallelError):a.send({'payload':'x'*(512*1024)})
        a.sock.close()
        with self.assertRaises(EOFError):b.receive()
    def test_cancellation_never_releases_active_slot_by_client_disappearance(self):
        a,b=self.pair();remote=RemoteAdmission(b,{},mock.Mock())
        a.send({'op':'cancel'})
        with self.assertRaises(KeyboardInterrupt):remote.check_cancel()
        self.assertTrue(remote.cancelled)
    def test_no_trial_identity_or_in_place_bypass(self):
        a,b=self.pair();remote=RemoteAdmission(b,{'intent':{'run_id':'one','trial_id':'a','attempt_id':'x'}},mock.Mock())
        with self.assertRaises(ParallelError):
            with remote.admission(type('Args',(),{'in_place':True})(),type('Attempt',(),{'record':{}})()):pass


class PeerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        self.run=self.root/'runs/run';self.run.mkdir(parents=True)
        self.image='sha256:'+'a'*64
        self.metadata={'execution':{'platform':'linux/arm64','image':self.image}}
        self.weight={'cpu_millis':1000,'memory_mib':128,'pids_limit':64}
        self.pool=Allocator({'cpu_millis':2500,'memory_mib':1024,'pids_limit':256})
        reservation=self.pool.request('trial',{'trial_id':'trial','generation':'private'},self.weight,10);self.pool.dispatch()
        self.command=mock.Mock(return_value=type('Reply',(),{'returncode':1,'stderr':'No such container'})())
        self.registry=ownership_registry.Registry(self.root/'registry',self.command)
        self.peer=Peer({'network':'pi-fixture','experiment':str(self.root)},self.registry,self.pool,reservation,self.metadata,self.run)
        args=lab.parser().parse_args(['run','--platform','linux/arm64','--cpus','1','--memory','128m','--pids-limit','64'])
        self.argv=lab.docker_args(args,self.image,self.run/'workspace',self.run/'control',self.run/'state','pi-lab-fixture','pi-fixture',helpers=self.run/'runtime')
        self.message={'op':'launch','argv':self.argv,'name':'pi-lab-fixture','binding':{'stage_id':'fixture'}}
    def enter(self):self.peer.handle({'op':'enter','capability':self.peer.reservation.capability})
    def test_no_launch_without_grant_or_duplicate_live_writer(self):
        with self.assertRaises(ParallelError):self.peer.handle(self.message)
        self.enter();reply=self.peer.handle(self.message)
        self.assertEqual(self.registry.load()[0]['status'],'intent');self.assertIn(ownership_registry.LABEL+'='+reply['record']['launch_id'],reply['argv'])
        with self.assertRaises(ParallelError):self.peer.handle(self.message)
        self.peer.handle({'op':'absent','launch_id':reply['record']['launch_id']})
        self.assertIsNone(self.peer.active);self.assertEqual(self.peer.reservation.state,'running')
    def test_foreign_mount_quota_network_image_and_argv_secrets_reject_before_intent(self):
        self.enter()
        for flag,value in (('--memory','256m'),('--cpus','2'),('--network','other-trial'),('--platform','linux/amd64')):
            argv=list(self.argv);argv[argv.index(flag)+1]=value
            with self.subTest(flag=flag),self.assertRaises(ParallelError):self.peer.validate_launch(argv)
        for extra in (['--mount','type=bind,src=/tmp/other-trial,dst=/foreign'],['--env','PI_APP_KEY=synthetic-do-not-print']):
            with self.assertRaises(ParallelError):self.peer.validate_launch(self.argv[:2]+extra+self.argv[2:])
        self.assertEqual(self.registry.load(),[])
    def test_stop_rejects_next_launch_but_accepts_owned_cleanup(self):
        self.enter();reply=self.peer.handle(self.message);self.pool.stop()
        self.assertTrue(self.peer.handle({'op':'absent','launch_id':reply['record']['launch_id']})['confirmed'])
        with self.assertRaises(ParallelError):self.peer.handle(self.message)

    def test_selected_browser_launch_preserves_the_pinned_userns_policy(self):
        import browser_security,shutil
        self.metadata['execution']['browser_sandbox_policy']='chromium-userns'
        folder=self.run/'browser-security';folder.mkdir();path=folder/'seccomp.json'
        shutil.copyfile(browser_security.ROOT/'assets/security/chromium-userns.json',path)
        argv=self.argv[:2]+['--security-opt','seccomp='+str(path)]+self.argv[2:]
        self.peer.validate_launch(argv)
        path.write_text('{}')
        with self.assertRaises(ValueError):self.peer.validate_launch(argv)
