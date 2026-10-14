"""Parent allocator fixtures; no Docker or model execution."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'skill/scripts'))
from parallel_allocator import Allocator
from parallel_contract import ParallelError


def footprint(cpu=1000,memory=1024,pids=256):
    return {'cpu_millis':cpu,'memory_mib':memory,'pids_limit':pids}


class AllocatorTests(unittest.TestCase):
    def setUp(self):self.now=0;self.pool=Allocator(footprint(2500,2304,576),clock=lambda:self.now)
    def request(self,name,resources=None,kind='stage'):
        return self.pool.request(name,{'trial':name,'generation':'fixture'},resources or footprint(),10,kind)
    def consume(self,item):return self.pool.consume(item.identity,item.capability,item.binding,item.resources)

    def test_exact_fit_accounts_workers_and_helper_and_hard_stage_ceiling(self):
        helper=self.request('gateway',footprint(500,256,64),'helper');a=self.request('a');b=self.request('b');c=self.request('c')
        self.assertEqual(self.pool.dispatch(),[helper,a,b]);self.assertEqual(self.pool.used(),self.pool.capacity)
        for item in (helper,a,b):self.consume(item);self.pool.running(item.identity)
        self.pool.stopping('a');self.assertEqual(self.pool.dispatch(),[])
        self.assertTrue(self.pool.release('a',True,True));self.assertEqual(self.pool.dispatch(),[c])
        with self.assertRaises(ParallelError):self.consume(a)
        with self.assertRaises(ParallelError):self.pool.release('a',True,True)

    def test_fifo_does_not_let_small_younger_request_starve_browser(self):
        a=self.request('a');self.pool.dispatch();self.consume(a)
        b=self.request('browser',footprint(2000,2048));helper=self.request('tiny',footprint(100,64,64),'helper')
        self.assertEqual(self.pool.dispatch(),[])
        self.pool.release('a',True,True)
        self.assertEqual(self.pool.dispatch(),[b,helper])

    def test_expiry_is_monotonic_and_never_releases_live_writer(self):
        a=self.request('a');b=self.request('b');self.pool.dispatch();self.consume(a);self.consume(b)
        c=self.request('queued');self.now=11
        self.assertEqual(self.pool.dispatch(),[]);self.assertEqual(c.state,'expired');self.assertEqual(a.state,'launching')
        self.assertEqual(self.pool.used(),footprint(2000,2048,512))

    def test_uncertain_absence_or_sensitive_purge_quarantines_and_stops(self):
        for absent,clean in ((False,True),(True,False),(None,True),(True,None)):
            self.setUp();a=self.request('a');self.pool.dispatch();self.consume(a);b=self.request('b')
            self.assertFalse(self.pool.release('a',absent,clean));self.assertEqual(a.state,'quarantined')
            self.assertEqual(b.state,'cancelled');self.assertTrue(self.pool.closed);self.assertNotEqual(self.pool.used(),footprint(0,0,0))

    def test_wrong_binding_weight_capability_duplicate_and_unbounded_queue_reject(self):
        a=self.request('a');self.pool.dispatch()
        for token,binding,resources in (('wrong',a.binding,a.resources),(a.capability,{'trial':'other'},a.resources),(a.capability,a.binding,footprint(2000))):
            with self.assertRaises(ParallelError):self.pool.consume('a',token,binding,resources)
        with self.assertRaises(ParallelError):self.request('a')
        with self.assertRaises(ParallelError):self.request('oversize',footprint(3000))
        self.consume(a)
        with self.assertRaises(ParallelError):self.pool.cancel_queued('a')
        for n in range(16):self.request(str(n))
        with self.assertRaises(ParallelError):self.request('queue-overflow')
