"""Broker launch/ownership boundary fixtures; no Docker or real credentials."""
from contextlib import contextmanager
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'skill/scripts'))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'skill/runtime'))
import inference_broker
from parallel_allocator import Allocator
from parallel_contract import ParallelError
import stage_control as controls


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.records=[];self.absent=True;self.uncertain=False;self.config=None;self.calls=[]
        self.args=SimpleNamespace(platform='linux/arm64',uid=1)
        self.weight={'cpu_millis':1000,'memory_mib':1536,'pids_limit':512}
        self.limits={'resources':{'cpu_millis':250,'memory_mib':128,'pids_limit':64},'max_inflight':1,'max_pending':4,'queue_wait_seconds':180,'request_timeout_seconds':180}
        self.pool=Allocator({'cpu_millis':2500,'memory_mib':3328,'pids_limit':1152})
        case=self
        class Registry:
            generation=str(uuid.uuid4())
            def intent(self,argv,name,runroot=None):
                record={'launch_id':str(uuid.uuid4()),'container':name,'status':'intent'};case.records.append(record);return record,argv
            def write(self,record):pass
            def load(self):return case.records
            def confirm_absent(self,record):record['status']='absent' if case.absent else 'quarantined';return case.absent
            def release(self,record,clean):record['status']='released'
        self.registry=Registry()
        class Lab:
            RUNTIME=case.root/'runtime'
            def control_channels(self,path,uid):
                (path/'outbox').mkdir();controls.atomic(path/'placeholder.json',{})
            def state_dir(self,path,identity,uid):path.mkdir(parents=True);return path
            def image_info(self,image,platform):return {'id':image}
            def docker_args(self,args,image,workspace,control,state,name,network,helpers):
                case.control=control;return ['docker','run','--name',name,image]
            def command(self,argv,**kwargs):
                case.calls.append(argv)
                if argv[:2]==['docker','run']:
                    case.config=json.loads((case.control/'inference.json').read_text())
                    controls.atomic(case.control/'outbox/gateway-state.json',{'launch_id':case.config['launch_id'],'inflight':0,'pending':0,'uncertain':case.uncertain})
                if argv[:3]==['docker','container','inspect']:
                    data={'HostConfig':{'NanoCpus':250000000,'Memory':128*1024**2,'MemorySwap':128*1024**2,'PidsLimit':64},'NetworkSettings':{'Ports':{'8080/tcp':[{'HostIp':'127.0.0.1','HostPort':'12345'}]}}}
                    return SimpleNamespace(stdout=json.dumps([data]),returncode=0,stderr='')
                return SimpleNamespace(stdout='',stderr='',returncode=0)
        self.lab=Lab();self.payload={'endpoint':{'base_url':'http://synthetic.invalid/v1','model':'fixture'},'upstream_key':'synthetic-private-key','tokens':{'synthetic-surrogate':'fixture-trial'}}
    @contextmanager
    def health(self,*args,**kwargs):yield io.BytesIO(b'{"status":"ready"}')
    def owner(self):return inference_broker.owner(self.lab,self.args,self.root,self.registry,self.pool,self.weight,self.payload,'sha256:'+'a'*64,self.limits)
    def test_secret_stays_in_helper_and_worker_receives_only_surrogate(self):
        with patch.object(inference_broker,'urlopen',self.health):
            with self.owner() as (inference,factory,cleanup):
                route=inference['trial']({'trial_id':'fixture-trial'})
                self.assertEqual(route['token'],'synthetic-surrogate');self.assertNotIn('synthetic-private-key',json.dumps(route))
                self.assertEqual(self.config['upstream_key'],'synthetic-private-key')
                private=Path(self.records[0]['private_store']);self.assertEqual((private/'control/inference.json').stat().st_mode&0o777,0o600)
        self.assertFalse(private.exists());self.assertEqual(self.records[0]['status'],'released');self.assertEqual(self.pool.records['gateway'].state,'released')
    def test_unknown_remote_completion_quarantines_after_physical_cleanup(self):
        self.uncertain=True
        with patch.object(inference_broker,'urlopen',self.health):
            with self.assertRaises(ParallelError):
                with self.owner():pass
        self.assertTrue(self.records[0]['inference_uncertain']);self.assertEqual(self.pool.records['gateway'].state,'quarantined')
        self.assertFalse(Path(self.records[0]['private_store']).exists())
    def test_unknown_physical_absence_retains_private_store_and_blocks_release(self):
        self.absent=False
        with patch.object(inference_broker,'urlopen',self.health):
            with self.assertRaises(ParallelError):
                with self.owner():pass
        private=Path(self.records[0]['private_store']);self.assertTrue(private.exists());self.addCleanup(shutil.rmtree,private)
        self.assertEqual(self.pool.records['gateway'].state,'quarantined')

    def test_uncertainty_stops_future_admission_without_a_new_request(self):
        with patch.object(inference_broker,'urlopen',self.health):
            with self.assertRaises(ParallelError):
                with self.owner() as (inference,factory,cleanup):
                    inference['admit']()
                    controls.atomic(self.control/'outbox/gateway-state.json',{'launch_id':self.config['launch_id'],'inflight':1,'pending':0,'uncertain':True})
                    with self.assertRaises(ValueError) as blocked:inference['admit']()
                    self.assertEqual(blocked.exception.reason,'inference-quarantined')

    def test_activation_waits_for_exact_owner_bound_container_revision(self):
        self.payload['active_tokens_file']=True;seen=[]
        original=inference_broker.ownership_registry.read_private
        with patch.object(inference_broker,'urlopen',self.health):
            with self.owner() as (inference,factory,cleanup):
                def visibility(path):
                    state=original(path);revision=json.loads((self.control/'active-tokens.json').read_text())['revision'];seen.append(revision)
                    state['activation_revision']=revision if len(seen)>=3 else revision-1
                    return state
                with patch.object(inference_broker.ownership_registry,'read_private',side_effect=visibility):
                    inference['activate'](['synthetic-surrogate'])
                self.assertEqual(len(seen),3)
                self.assertEqual(json.loads((self.control/'active-tokens.json').read_text())['revision'],1)
                self.assertEqual(len([c for c in self.calls if c[:2]==['docker','run']]),1)

    def test_activation_timeout_or_wrong_owner_cannot_authorize_dispatch(self):
        self.payload['active_tokens_file']=True
        with patch.object(inference_broker,'urlopen',self.health):
            with self.owner() as (inference,factory,cleanup):
                with patch.object(inference_broker.time,'monotonic',side_effect=[0,11]):
                    with self.assertRaises(ValueError) as blocked:inference['activate'](['synthetic-surrogate'])
                self.assertEqual(blocked.exception.reason,'inference-quarantined')
                with self.assertRaises(ValueError):inference['admit']()
                controls.atomic(self.control/'outbox/gateway-state.json',{'launch_id':'foreign','uncertain':False,'activation_revision':2})
                with self.assertRaises(ValueError):inference['activate'](['synthetic-surrogate'])
                controls.atomic(self.control/'outbox/gateway-state.json',{'launch_id':self.config['launch_id'],'inflight':0,'pending':0,'uncertain':False})

    def test_activation_rejects_unknown_or_excess_capabilities_before_writing(self):
        self.payload['active_tokens_file']=True
        with patch.object(inference_broker,'urlopen',self.health):
            with self.owner() as (inference,factory,cleanup):
                before=(self.control/'active-tokens.json').read_bytes()
                for tokens in (['foreign'],['synthetic-surrogate']*2,['a','b','c']):
                    with self.assertRaises(ValueError):inference['activate'](tokens)
                    self.assertEqual((self.control/'active-tokens.json').read_bytes(),before)

    def test_activation_wrong_owner_blocks_even_an_exact_revision(self):
        self.payload['active_tokens_file']=True
        with patch.object(inference_broker,'urlopen',self.health):
            with self.owner() as (inference,factory,cleanup):
                controls.atomic(self.control/'outbox/gateway-state.json',{'launch_id':'foreign','inflight':0,'pending':0,'uncertain':False,'activation_revision':1})
                with self.assertRaises(ValueError):inference['activate'](['synthetic-surrogate'])
                controls.atomic(self.control/'outbox/gateway-state.json',{'launch_id':self.config['launch_id'],'inflight':0,'pending':0,'uncertain':False,'activation_revision':1})
                with self.assertRaises(ValueError):inference['admit']()

    def test_activation_clips_wait_to_collection_deadline_and_rejects_bool_ack(self):
        self.payload['active_tokens_file']=True
        with patch.object(inference_broker,'urlopen',self.health):
            with self.owner() as (inference,factory,cleanup):
                inference['control_deadline']=2
                controls.atomic(self.control/'outbox/gateway-state.json',{'launch_id':self.config['launch_id'],'inflight':0,'pending':0,'uncertain':False,'activation_revision':True})
                with patch.object(inference_broker.time,'monotonic',side_effect=[0,1,3]),patch.object(inference_broker.time,'sleep'):
                    with self.assertRaises(ValueError):inference['activate'](['synthetic-surrogate'])
                with self.assertRaises(ValueError):inference['admit']()


if __name__=='__main__':unittest.main()
