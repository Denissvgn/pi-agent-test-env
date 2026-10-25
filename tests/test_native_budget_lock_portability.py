"""Real independent-process exclusion and a writable-lock backend contract.

All files/processes are disposable; no container, endpoint or global lease.
"""
import errno
import fcntl
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import types
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import tool_budgets as budgets
import test_tool_budgets as fixtures

CHILD=r'''
import json,signal,sys
sys.path[:0]=[sys.argv[1]]
import tool_budgets as budgets
signal.alarm(8)
ledger=budgets.BudgetLedger(sys.argv[2],json.loads(sys.argv[3]),lambda:1000.,'controlled-test-boot')
role=sys.argv[4];original=budgets.fcntl.flock
if role=='contender':
 def attempted(fd,operation):
  print(json.dumps({'event':'attempting'}),flush=True)
  return original(fd,operation)
 budgets.fcntl.flock=attempted
with ledger._lock():
 print(json.dumps({'event':'acquired','role':role}),flush=True)
 if role=='holder':sys.stdin.buffer.readline()
 state=ledger._read()
 print(json.dumps({'event':'state','counts':state['counts'],'accounting':state['accounting']}),flush=True)
'''


class NativeBudgetLockPortabilityTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.LedgerFixture();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.ledger=self.fixture.ledger(profile='builtin');self.original=self.ledger.path.read_bytes()
    def child(self,role):
        process=subprocess.Popen([sys.executable,'-I','-B','-c',CHILD,str(ROOT/'skill/scripts'),str(self.ledger.path),json.dumps(self.fixture.binding),role],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'PYTHONDONTWRITEBYTECODE':'1'})
        def stop():
            if process.poll() is None:process.terminate();process.wait(timeout=3)
            for stream in (process.stdin,process.stdout,process.stderr):
                if not stream.closed:stream.close()
        self.addCleanup(stop);return process
    def frame(self,process):
        self.assertTrue(select.select([process.stdout],[],[],5)[0],'bounded child event missing')
        line=process.stdout.readline();self.assertTrue(line,'child exited before event');return json.loads(line)
    def assert_ledger_untouched(self):
        self.assertEqual(self.ledger.path.read_bytes(),self.original);self.assertFalse(self.ledger.pending_path.exists())
    def test_two_independently_opened_processes_exclude_then_observe_identical_state(self):
        holder=self.child('holder');self.assertEqual(self.frame(holder),{'event':'acquired','role':'holder'})
        contender=self.child('contender');self.assertEqual(self.frame(contender),{'event':'attempting'})
        self.assertFalse(select.select([contender.stdout],[],[],.25)[0],'second process entered while first held exclusive lock')
        self.assertIsNone(contender.poll());holder.stdin.write(b'release\n');holder.stdin.flush()
        self.assertEqual(self.frame(contender),{'event':'acquired','role':'contender'})
        out_a,err_a=holder.communicate(timeout=5);out_b,err_b=contender.communicate(timeout=5)
        self.assertEqual(holder.returncode,0,err_a.decode());self.assertEqual(contender.returncode,0,err_b.decode())
        observed=[json.loads(out_a),json.loads(out_b)]
        self.assertTrue(all(row['event']=='state' and row['accounting']=='available' and all(n==0 for n in row['counts'].values()) for row in observed))
        self.assert_ledger_untouched()
    def test_backend_requiring_writer_access_can_commit_one_admission_and_read_it(self):
        original=budgets.fcntl.flock;calls=[]
        def writable_exclusive(fd,operation):
            if operation & fcntl.LOCK_EX:
                if fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY:
                    raise OSError(errno.EBADF,'controlled backend requires writer access for exclusive locks')
                calls.append(True)
            return original(fd,operation)
        with mock.patch.object(budgets.fcntl,'flock',side_effect=writable_exclusive):
            result=self.ledger.reserve_batch(self.fixture.scope,'portable-batch',[fixtures.call('portable-call')])
            self.assertTrue(result['calls'][0]['admitted']);snapshot=self.ledger.snapshot()
        self.assertGreaterEqual(len(calls),2);self.assertEqual(snapshot['counts']['attempted'],1);self.assertEqual(snapshot['counts']['charged'],1)
        self.assertEqual(snapshot['counts']['executed_known'],0);self.assertEqual(snapshot['accounting'],'available')
    def test_nonprivate_lock_permissions_reject_before_pending_or_state_changes(self):
        self.ledger.lock_path.chmod(0o644)
        with self.assertRaises(budgets.BudgetError):self.ledger.snapshot()
        self.assert_ledger_untouched()
    def test_lock_uid_mismatch_rejects_without_mutating_ledger(self):
        identity=self.ledger.lock_path.stat();original=os.fstat
        def foreign(fd):
            info=original(fd)
            if (info.st_dev,info.st_ino)==(identity.st_dev,identity.st_ino):
                return types.SimpleNamespace(st_mode=info.st_mode,st_nlink=info.st_nlink,st_uid=os.getuid()+1)
            return info
        with mock.patch.object(budgets.os,'fstat',side_effect=foreign),self.assertRaises(budgets.BudgetError):self.ledger.snapshot()
        self.assert_ledger_untouched()
    def test_linked_lock_rejects_without_touching_its_target(self):
        target=self.fixture.root/'target';target.write_bytes(b'controlled unrelated data');target.chmod(0o600)
        self.ledger.lock_path.unlink();self.ledger.lock_path.symlink_to(target)
        with self.assertRaises(budgets.BudgetError):self.ledger.snapshot()
        self.assertEqual(target.read_bytes(),b'controlled unrelated data');self.assert_ledger_untouched()
    def test_hardlinked_lock_rejects_without_state_effects(self):
        os.link(self.ledger.lock_path,self.fixture.root/'alias.lock')
        with self.assertRaises(budgets.BudgetError):self.ledger.snapshot()
        self.assert_ledger_untouched()

if __name__=='__main__':unittest.main()
