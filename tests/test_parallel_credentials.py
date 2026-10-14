"""Two-host-worker credential boundaries with synthetic canaries only."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'skill/scripts'))
from parallel_dispatch import private_credentials
from parallel_allocator import Allocator
from parallel_contract import ParallelError
import application_credentials as credentials
import pi_lab as lab
import subprocess
import json


class CredentialTests(unittest.TestCase):
    def test_only_frozen_assigned_stages_receive_private_values(self):
        plan={'agents':[{'name':'assigned','application_secrets':{'PI_APP_ACTOR':'ACTOR_A'}},{'name':'reviewer'}]}
        assigned={'assigned':{'PI_APP_ACTOR':'synthetic-actor-a-value'}}
        self.assertEqual(private_credentials(plan,assigned),assigned)
        for bad in ({'reviewer':assigned['assigned']},{'assigned':{'PI_APP_OTHER':'synthetic-actor-a-value'}},{}):
            with self.assertRaises(ParallelError):private_credentials(plan,bad)

    def test_same_actor_cannot_overlap_and_different_actor_can(self):
        weight={'cpu_millis':1000,'memory_mib':128,'pids_limit':64}
        pool=Allocator({'cpu_millis':2000,'memory_mib':256,'pids_limit':128})
        a=pool.request('a',{'credential_authorities':['ACTOR_A']},weight,10)
        b=pool.request('b',{'credential_authorities':['ACTOR_B']},weight,10)
        c=pool.request('c',{'credential_authorities':['ACTOR_A']},weight,10)
        self.assertEqual(pool.dispatch(),[a,b]);pool.consume('a',a.capability,a.binding,a.resources)
        pool.release('b',True,True);self.assertEqual(pool.dispatch(),[])
        pool.release('a',True,True);self.assertEqual(pool.dispatch(),[c])

    def test_concurrent_capture_is_redacted_independently_and_no_ambient_app_key(self):
        import concurrent.futures
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);values=['synthetic-canary-a-0123456789','synthetic-canary-b-9876543210']
            script="import os,json,time;v=os.environ['PI_APP_ACTOR'];print(v[:8],end='',flush=True);time.sleep(.05);print(v[8:]);print(json.dumps(v));assert 'PI_APP_AMBIENT' not in os.environ"
            def trial(index):
                return lab.stream_run([sys.executable,'-c',script],root/str(index),3,'fixture-'+str(index),application_secrets={'PI_APP_ACTOR':values[index]})
            # Each real trial controller is a process; this fixture exercises only
            # stream draining (which has no global stdout redirection).
            with mock.patch.dict('os.environ',{'PI_APP_AMBIENT':'synthetic-forbidden-ambient'}):
                with concurrent.futures.ThreadPoolExecutor(2) as pool:results=list(pool.map(trial,range(2)))
            self.assertTrue(all(r['exit_code']==0 and r['cleanup_confirmed'] for r in results))
            for path in root.rglob('*'):
                if path.is_file():self.assertFalse(any(v.encode() in path.read_bytes() for v in values))
