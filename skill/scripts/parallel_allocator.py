"""Parent-only weighted FIFO admission. A lease expires only through observed cleanup."""
from collections import deque
from dataclasses import dataclass
import secrets
import time

from parallel_contract import ParallelError, weight

AXES=('cpu_millis','memory_mib','pids_limit')
LIVE={'reserved','launching','running','stopping','quarantined'}


@dataclass
class Reservation:
    identity: str
    binding: dict
    resources: dict
    kind: str
    queued_at: float
    deadline: float
    state: str='queued'
    capability: str=''


class Allocator:
    def __init__(self,capacity,max_stages=2,max_pending=16,clock=time.monotonic):
        self.capacity=weight(capacity)
        if type(max_stages) is not int or max_stages!=2 or type(max_pending) is not int or not 2<=max_pending<=64:
            raise ParallelError('Unsupported allocator limits')
        self.max_stages=max_stages;self.max_pending=max_pending;self.clock=clock
        self.queue=deque();self.records={};self.closed=False

    def used(self):
        return {k:sum(r.resources[k] for r in self.records.values() if r.state in LIVE) for k in AXES}

    def request(self,identity,binding,resources,wait_seconds,kind='stage'):
        resources=weight(resources)
        if self.closed or identity in self.records or kind not in ('stage','helper'):
            raise ParallelError('Closed allocator or duplicate/unsupported reservation')
        if len(self.queue)>=self.max_pending or type(wait_seconds) not in (int,float) or not 0<wait_seconds<=3600:
            raise ParallelError('Admission queue is full or deadline invalid')
        if any(resources[k]>self.capacity[k] for k in AXES):
            raise ParallelError('Reservation exceeds frozen aggregate capacity')
        now=self.clock()
        item=Reservation(identity,dict(binding),resources,kind,now,now+wait_seconds)
        self.records[identity]=item;self.queue.append(identity)
        return item

    def dispatch(self):
        admitted=[]
        while self.queue and not self.closed:
            item=self.records[self.queue[0]]
            if self.clock()>=item.deadline:
                item.state='expired';self.queue.popleft();continue
            used=self.used()
            stages=sum(r.kind=='stage' and r.state in LIVE for r in self.records.values())
            if item.kind=='stage' and stages>=self.max_stages:break
            authorities=set(item.binding.get('credential_authorities',[]))
            if any(authorities.intersection(r.binding.get('credential_authorities',[])) for r in self.records.values() if r.state in LIVE):break
            if any(used[k]+item.resources[k]>self.capacity[k] for k in AXES):break
            # Strict FIFO: a younger helper cannot consume the head's awaited capacity.
            self.queue.popleft();item.state='reserved';item.capability=secrets.token_hex(32);admitted.append(item)
        return admitted

    def consume(self,identity,capability,binding,resources):
        item=self.records.get(identity)
        if (item is None or item.state!='reserved' or not secrets.compare_digest(item.capability,capability)
            or item.binding!=binding or item.resources!=resources):
            raise ParallelError('Stale, duplicate or mismatched private admission grant')
        item.state='launching';return item

    def running(self,identity):
        item=self.records[identity]
        if item.state!='launching':raise ParallelError('Invalid launch transition')
        item.state='running'

    def stopping(self,identity):
        item=self.records[identity]
        if item.state not in ('launching','running'):raise ParallelError('Invalid stop transition')
        item.state='stopping'

    def release(self,identity,absent,sensitive_clean):
        item=self.records[identity]
        if item.state not in LIVE:raise ParallelError('Duplicate or invalid release')
        if absent is not True or sensitive_clean is not True:
            item.state='quarantined';self.stop();return False
        item.state='released';item.capability='';return True

    def cancel_queued(self,identity):
        item=self.records[identity]
        if item.state!='queued':raise ParallelError('Only queued work may be withdrawn without cleanup')
        self.queue.remove(identity);item.state='cancelled'

    def stop(self):
        self.closed=True
        while self.queue:self.records[self.queue.popleft()].state='cancelled'
