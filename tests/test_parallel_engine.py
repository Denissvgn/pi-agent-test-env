"""Real host subprocess isolation with synthetic outcomes, never Docker/Pi acceptance."""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

from test_experiments import ExperimentFixture
from test_parallel_contract import selected
import experiments
import ownership_registry
import parallel_engine
from parallel_dispatch import Channel
from parallel_allocator import Allocator
import pi_lab as lab


class NativeCleanupGateTests(unittest.TestCase):
    def test_removed_helper_with_unknown_private_purge_retains_network_and_pool(self):
        pool=Allocator({'cpu_millis':1000,'memory_mib':128,'pids_limit':64})
        row=pool.request('trial',{},dict(pool.capacity),30);pool.dispatch()
        peer=SimpleNamespace(native_budget=object(),registry=SimpleNamespace())
        cleanup=mock.Mock()
        self.assertFalse(parallel_engine.release_trial({'peer':peer,'network':'owned-network'},'trial',True,False,cleanup,pool))
        cleanup.assert_not_called();self.assertFalse(pool.dependent_cleanup_confirmed)
        self.assertTrue(pool.closed);self.assertEqual(row.state,'quarantined')

    def test_legacy_release_does_not_add_new_gate_field(self):
        pool=Allocator({'cpu_millis':1000,'memory_mib':128,'pids_limit':64})
        pool.request('trial',{},dict(pool.capacity),30);pool.dispatch()
        peer=SimpleNamespace(native_budget=None,registry=SimpleNamespace());cleanup=mock.Mock()
        self.assertTrue(parallel_engine.release_trial({'peer':peer,'network':'owned-network'},'trial',True,True,cleanup,pool))
        cleanup.assert_called_once_with('owned-network')
        self.assertFalse(hasattr(pool,'dependent_cleanup_confirmed'))

SCRIPT='''import json,os,socket,sys,time
from unittest import mock
sys.path.insert(0,sys.argv[1])
import experiments,pi_lab as lab
from parallel_dispatch import Channel,RemoteAdmission
channel=Channel(socket.socket(fileno=int(sys.argv[2])));bootstrap=channel.receive()
root=bootstrap['experiment'];metadata,matrix=experiments.verify(root,lab)
cell=next(c for c in matrix['cells'] if c['trial_id']==bootstrap['intent']['trial_id'])
args=experiments.trial_args(root,metadata,cell,lab,None)
args._parallel_session=RemoteAdmission(channel,bootstrap,lambda argv:None)
def body(args,attempt,smoke):
 record=attempt.record;record['fixture_origin']='synthetic parallel host controller, no Pi or Docker'
 workspace=attempt.root/'workspace';lab.snapshot(__import__('pathlib').Path(args.project),workspace,[],10)
 (workspace/'private.txt').write_text(record['trial_id']);record['workspace']=str(workspace)
 attempt.persist();time.sleep(.2)
 args._parallel_session.check_cancel()
 record['infrastructure'].update(status='ready',phase='agents')
 record['invocation'].update(status='verified',attempted_stages=1)
 record['termination'].update(reason='completed',process_exit_code=0)
 record['protected_inputs']['status']='unchanged';record['scoring']['status']='completed'
 record['task_result'].update(status='pass',score=1)
 if sys.argv[3]=='failure' and cell['variant']=='baseline':record['invocation']['status']='invalid'
with mock.patch.object(lab,'_execute_suite',side_effect=body):code=lab.run_suite(args,initial_record=bootstrap['intent']['initial_record'])
channel.sock.close();os.close(int(sys.argv[4]));sys.exit(code)
'''


class EngineTests(ExperimentFixture):
    def setup_parallel(self,policy='continue'):
        self.definition.update(schema=2,concurrency=selected());self.definition['budgets']['timeout_seconds']=300;self.definition['policies']['on_failure']=policy
        self.write('experiment.json',self.definition);self.prepare()
        root=self.root/'prepared';metadata,matrix=experiments.verify(root,lab)
        return root,metadata,matrix
    def collect(self,root,metadata,matrix,mode='pass'):
        script=self.root/'fixture.py';script.write_text(SCRIPT)
        processes=[];peaks=[]
        def spawn(bootstrap,output,lease_fd):
            a,b=socket.socketpair();channel=Channel(a)
            process=subprocess.Popen([sys.executable,str(script),str(lab.ROOT/'scripts'),str(b.fileno()),mode,str(lease_fd)],
                                     pass_fds=(b.fileno(),lease_fd),stdout=output,stderr=output)
            processes.append(process);self.addCleanup(lambda:process.kill() if process.poll() is None else None)
            peaks.append(sum(p.poll() is None for p in processes));b.close();channel.send({'op':'bootstrap',**bootstrap})
            return process,channel
        pool=Allocator(selected()['aggregate']);store=ownership_registry.Registry(self.root/'registry')
        with (self.root/'lease').open('a+') as lease:
            store.lease_fd=lease.fileno()
            result=parallel_engine.collect(root,metadata,matrix,matrix['cells'],lab,store,pool,None,
                    {'worker_resources':{'cpu_millis':1000,'memory_mib':128,'pids_limit':64},'trial':lambda intent:{'token':'synthetic'}},
                    lambda intent:'fixture-'+intent['trial_id'],lambda network:None,spawn=spawn)
        self.assertLessEqual(max(peaks),2);self.assertEqual(max(peaks),2)
        return result
    def test_processes_keep_snapshots_output_and_active_map_separate(self):
        root,metadata,matrix=self.setup_parallel();result=self.collect(root,metadata,matrix)
        self.assertEqual(result['status'],'completed');self.assertEqual(result['completed_this_call'],4)
        self.assertEqual(experiments.controller_state(root)['active_attempts'],{})
        paths=[]
        for cell in matrix['cells']:
            intent=experiments.attempt_intents(root,cell)[0];record=experiments.sealed_result(root,intent)
            self.assertEqual(record['status'],'PASS');path=Path(record['workspace']);paths.append(path)
            self.assertEqual((path/'private.txt').read_text(),cell['trial_id'])
            text=(root/'logs'/(intent['attempt_id']+'.txt')).read_text();self.assertIn(intent['run_id'],text)
            self.assertNotIn('no public standalone',text.lower())
        self.assertEqual(len(set(paths)),4);self.assertEqual((self.root/'project/app.py').read_text(),'value=0\n')
        first=experiments.export_ledger(root,lab);bytes_before=(root/'trials.jsonl').read_bytes()
        self.assertEqual(first,experiments.export_ledger(root,lab));self.assertEqual(bytes_before,(root/'trials.jsonl').read_bytes())
    def test_stop_keeps_started_sibling_and_pending_cells_accountable(self):
        root,metadata,matrix=self.setup_parallel('stop');result=self.collect(root,metadata,matrix,'failure')
        self.assertEqual(result['status'],'halted')
        rows=experiments.ledger_rows(root,lab)
        self.assertEqual(len(rows),4);self.assertGreaterEqual(sum(bool(r['attempts']) for r in rows),2)
        self.assertLess(sum(bool(r['attempts']) for r in rows),4)

    def test_owner_channel_loss_is_sealed_as_controller_loss_not_user_cancel(self):
        root,metadata,matrix=self.setup_parallel();cell=matrix['cells'][0]
        intent,path=experiments.reserve_attempt(root,metadata,cell)
        script=self.root/'owner-loss.py';script.write_text(SCRIPT)
        a,b=socket.socketpair();channel=Channel(a)
        args={'op':'bootstrap','experiment':str(root),'intent':intent,'capability':'synthetic-private-capability','inference':{}}
        with (self.root/'lease').open('a+') as lease,(self.root/'owner-loss.log').open('w') as output:
            process=subprocess.Popen([sys.executable,str(script),str(lab.ROOT/'scripts'),str(b.fileno()),'pass',str(lease.fileno())],
                                     pass_fds=(b.fileno(),lease.fileno()),stdout=output,stderr=output)
            self.addCleanup(lambda:process.kill() if process.poll() is None else None)
            b.close();channel.send(args);self.assertEqual(channel.receive()['op'],'enter');channel.send({'op':'ok'});a.close()
            process.wait(timeout=5)
        result=experiments.sealed_result(root,intent)
        self.assertEqual(result['controller_interruption']['kind'],'controller_lost')
        self.assertNotEqual(result['termination']['reason'],'cancelled');self.assertNotEqual(result['status'],'INTERRUPTED')
        self.assertEqual(result['scoring']['reason'],'controller_lost')
        original=(root/'runs'/intent['run_id']/'result.json').read_bytes()
        experiments.reconcile(root,metadata,matrix,lab,cleanup=lambda *unused:[])
        self.assertEqual((root/'runs'/intent['run_id']/'result.json').read_bytes(),original)
