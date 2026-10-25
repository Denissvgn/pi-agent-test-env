"""Bounded read-only historical controller identity checks; no real processes.

kill(pid,0) and /bin/ps are mocked. This proves PID-reuse decision behavior only,
not custody of any actual qualification or liveness of a native participant.
"""
import datetime
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools/qualification'))
import application_launch as launch


class HistoricalPidTests(unittest.TestCase):
    def setUp(self):
        self.pid=17398;self.wall=1792310000.0
        self.terminal={'actual_exit':2,'started_at':1792256005.267305,'elapsed_seconds':5.691}
        self.birth=1792308500
        self.kill=mock.patch.object(launch.os,'kill',return_value=None).start();self.addCleanup(mock.patch.stopall)
        self.command=mock.patch.object(launch.subprocess,'run',side_effect=lambda *a,**k:self.result()).start()
    def result(self,birth=None,pid=None,**kwargs):
        birth=self.birth if birth is None else birth;pid=self.pid if pid is None else pid
        date=datetime.datetime.fromtimestamp(birth,datetime.timezone.utc)
        days=('Mon','Tue','Wed','Thu','Fri','Sat','Sun');months=('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec')
        line=f'  {pid} {days[date.weekday()]} {months[date.month-1]} {date.day:2} {date:%H:%M:%S} {date.year}\n'
        return subprocess.CompletedProcess([],kwargs.get('returncode',0),kwargs.get('stdout',line),kwargs.get('stderr',''))
    def absent(self):return launch._historical_controller_absent(self.pid,self.terminal,self.wall)
    def test_absent_pid_preserves_old_behavior_without_process_command(self):
        self.kill.side_effect=ProcessLookupError
        self.terminal={}
        self.assertTrue(self.absent());self.command.assert_not_called();self.kill.assert_called_once_with(self.pid,0)
    def test_later_pid_birth_passes_only_two_stable_explicit_utc_observations(self):
        self.assertTrue(self.absent());self.assertEqual(self.kill.call_args_list,[mock.call(self.pid,0)]*3)
        self.assertEqual(self.command.call_count,2)
        for args,kwargs in self.command.call_args_list:
            self.assertEqual(args,(['/bin/ps','-p',str(self.pid),'-o','pid=','-o','lstart='],))
            self.assertEqual(kwargs['timeout'],1);self.assertEqual(kwargs['env'],{'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C','TZ':'UTC0'})
            self.assertIs(kwargs['shell'],False);self.assertEqual(kwargs['stdin'],subprocess.DEVNULL)
    def test_same_older_or_within_rounding_margin_birth_denied(self):
        ended=self.terminal['started_at']+self.terminal['elapsed_seconds']
        for birth in (int(ended)-100,int(ended),int(ended)+1):
            with self.subTest(birth=birth):
                self.birth=birth;self.assertFalse(self.absent())
    def test_future_birth_denied_beyond_one_second_rounding_margin(self):
        self.birth=int(self.wall)+2;self.assertFalse(self.absent())
    def test_permission_or_unknown_kill_failure_denied(self):
        for error in (PermissionError(),OSError('unknown')):
            self.kill.side_effect=error
            with self.subTest(error=type(error).__name__):self.assertFalse(self.absent())
        self.command.assert_not_called()
    def test_disappearance_between_observations_denied(self):
        for sequence in ([None,ProcessLookupError()],[None,None,ProcessLookupError()]):
            self.kill.side_effect=sequence;self.assertFalse(self.absent())
    def test_changed_birth_or_pid_between_observations_denied(self):
        for second in (self.result(birth=self.birth+1),self.result(pid=self.pid+1)):
            self.command.side_effect=[self.result(),second];self.assertFalse(self.absent())
    def test_ps_timeout_permission_encoding_or_unknown_result_denied(self):
        for error in (subprocess.TimeoutExpired('ps',1),PermissionError(),UnicodeDecodeError('ascii',b'\xff',0,1,'bad')):
            self.command.side_effect=error
            with self.subTest(error=type(error).__name__):self.assertFalse(self.absent())
        for result in (self.result(returncode=1),self.result(stderr='warning'),self.result(stdout=''),self.result(stdout='x'*513)):
            self.command.side_effect=None;self.command.return_value=result;self.assertFalse(self.absent())
    def test_malformed_timezone_weekday_calendar_and_multiple_rows_denied(self):
        good=self.result().stdout
        for body in (good+'\n1 Sun Oct 18 10:00:00 2026\n',good.replace('Sun','Mon'),good.replace('Oct','Bad'),good.replace('Oct 18','Feb 31'),good.replace('2026','2026 UTC'),good.replace('07:28','25:28')):
            self.command.side_effect=None;self.command.return_value=self.result(stdout=body)
            with self.subTest(body=body):self.assertFalse(self.absent())
    def test_missing_nonpositive_nonfinite_and_overflow_terminal_bounds_denied(self):
        original=dict(self.terminal)
        for key,value in (('started_at',None),('started_at',0),('started_at',True),('started_at',float('nan')),('elapsed_seconds',None),('elapsed_seconds',0),('elapsed_seconds',-1),('elapsed_seconds',float('inf')),('actual_exit',True),('actual_exit',0)):
            self.terminal={**original,key:value}
            with self.subTest(key=key,value=value):self.assertFalse(self.absent())
        self.terminal={**original,'started_at':1e308,'elapsed_seconds':1e308};self.assertFalse(self.absent())
        self.command.assert_not_called()
    def test_invalid_wall_or_terminal_end_in_future_denied(self):
        for wall in (float('inf'),float('nan'),0,True,self.terminal['started_at']):
            self.wall=wall;self.assertFalse(self.absent())
        self.command.assert_not_called()
    def test_alive_pid_without_original_bound_timestamp_cannot_qualify(self):
        self.terminal={'actual_exit':2};self.assertFalse(self.absent());self.command.assert_not_called()


class HistoricalControllerIntegrationTests(unittest.TestCase):
    """Exercise all three sealed custody paths using their existing fixtures."""
    def check_path(self,name):
        import test_application_launch as fixtures
        fixture_class={'first':fixtures.CampaignCarryTests,'preworker':fixtures.KnownPreworkerCarryTests,'admission':fixtures.KnownAdmissionCarryTests}[name]
        fixture=fixture_class(methodName='runTest');fixture.setUp();self.addCleanup(fixture.doCleanups)
        root=fixture.old if name=='first' else fixture.q
        target=str(root);observed=[];allow=[True]
        def controller_check(pid,terminal,wallnow):
            argv=terminal.get('argv',[])
            if '--root' in argv and argv[argv.index('--root')+1]==target:
                self.assertEqual(pid,fixture.active['pid']);self.assertEqual(terminal['actual_exit'],2)
                self.assertGreater(wallnow,0);observed.append((pid,terminal,wallnow));return allow[0]
            # Unchanged earlier synthetic histories are independent of this
            # target controller's later PID reuse decision.
            return True
        with mock.patch.object(launch,'_historical_controller_absent',side_effect=controller_check):
            result=fixture.create() if name=='first' else fixture.write()
            self.assertTrue(result);self.assertTrue(observed)
            allow[0]=False
            with self.assertRaises(launch.LaunchError):
                fixture.create() if name=='first' else fixture.write()
        self.assertGreaterEqual(len(observed),2)
    def test_first_predecessor_requires_positive_controller_identity(self):self.check_path('first')
    def test_preworker_cleanup_requires_positive_controller_identity(self):self.check_path('preworker')
    def test_admission_cleanup_requires_positive_controller_identity(self):self.check_path('admission')


if __name__=='__main__':unittest.main()
