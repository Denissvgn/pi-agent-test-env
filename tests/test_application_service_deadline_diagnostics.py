"""Closed service-guard failure telemetry with controlled clocks and FakeDocker.

No real Docker, network, model, global lease or credential values are used.
The fixture is composed, so its existing test cases are not inherited/repeated.
"""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tests'),str(ROOT/'tools/qualification'),str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import test_application_service_cleanup as services
import application_launch as launch
import application_timing as timing


class GuardDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.case=services.ServiceCleanupTests(methodName='runTest')
        self.case.setUp();self.addCleanup(self.case.doCleanups)
        self.guard=self.case.guard;self.backend=self.case.backend

    def failure(self,*,seconds=3):
        with self.assertRaises(launch.LaunchError)as caught:
            self.guard.service_process(self.case.record,'logs',self.case.fixture.now[0]+seconds)
        self.assertEqual(str(caught.exception),'qualification_deadline')
        value=timing.extract_service_diagnostic(caught.exception);self.assertIsNotNone(value)
        self.assertFalse(any(argv[1]=='logs'for argv in self.backend.commands))
        return value

    def phase(self,value,name):return next(row for row in value['observations']if row['phase']==name)

    def test_initial_four_second_validation_reports_original_deadline_without_effect(self):
        self.case.validation_hook=lambda state:self.backend.advance(4)
        value=self.failure();self.assertEqual(value['phase'],'authority_validation')
        self.assertEqual(value['elapsed_seconds'],8)
        row=value['observations'][0];self.assertEqual(row['command_remaining_seconds'],-1)
        self.assertEqual(row['observed_elapsed_seconds'],4)
        self.assertGreater(row['campaign_remaining_seconds'],0)
        self.assertEqual(self.case.transactions,1);self.assertEqual(self.case.validations,2)

    def test_two_two_second_validations_identify_commit_cost_before_delegate_gate(self):
        self.case.validation_hook=lambda state:self.backend.advance(2)
        value=self.failure();self.assertEqual(value['phase'],'delegate_gate')
        self.assertEqual(value['elapsed_seconds'],4);self.assertEqual(self.case.validations,2)
        row=self.phase(value,'authority_commit')
        self.assertEqual(row['observed_elapsed_seconds']-row['entered_elapsed_seconds'],2)
        self.assertEqual(value['observations'][-1]['command_remaining_seconds'],-1)

    def test_fsync_cost_is_accounted_under_authority_commit_with_no_added_validation(self):
        original=launch._write
        def delayed(*args):
            result=original(*args);self.backend.advance(4);return result
        with mock.patch.object(launch,'_write',side_effect=delayed):value=self.failure()
        self.assertEqual(value['phase'],'delegate_gate');self.assertEqual(self.case.validations,2)
        row=self.phase(value,'authority_commit');self.assertEqual(row['observed_elapsed_seconds']-row['entered_elapsed_seconds'],4)

    def test_daemon_delay_records_daemon_phase_and_refuses_before_container_inspect(self):
        original=self.guard._daemon
        def delayed(*args):
            result=original(*args);self.backend.advance(4);return result
        with mock.patch.object(self.guard,'_daemon',side_effect=delayed):value=self.failure()
        self.assertEqual(value['phase'],'container_check')
        row=self.phase(value,'daemon_check');self.assertEqual(row['observed_elapsed_seconds']-row['entered_elapsed_seconds'],4)
        self.assertFalse(any(argv[1:3]==['container','inspect']for argv in self.backend.commands))

    def test_inspect_delay_is_attributed_without_inventing_a_delegate_attempt(self):
        original=self.guard._observe
        def delayed(argv,*args):
            result=original(argv,*args)
            if argv[1:3]==['container','inspect']:self.backend.advance(4)
            return result
        with mock.patch.object(self.guard,'_observe',side_effect=delayed):value=self.failure()
        self.assertEqual(value['phase'],'command_preparation')
        row=self.phase(value,'container_check');self.assertEqual(row['observed_elapsed_seconds']-row['entered_elapsed_seconds'],4)

    def test_campaign_expiry_and_command_expiry_remain_distinguishable(self):
        advance=self.case.raw()['deadline']-self.case.fixture.now[0]+1
        self.case.validation_hook=lambda state:self.backend.advance(advance)if self.case.validations==1 else None
        value=self.failure(seconds=advance+10);row=value['observations'][0]
        self.assertEqual(value['phase'],'authority_validation');self.assertEqual(row['campaign_remaining_seconds'],0)
        self.assertGreater(row['command_remaining_seconds'],0)

    def test_active_cleanup_bound_is_observed_separately_and_never_extended(self):
        self.case.validation_hook=lambda state:self.backend.advance(1)
        with self.guard.service_cleanup(self.case.registry,self.case.fixture.now[0]+.5):value=self.failure(seconds=30)
        row=value['observations'][0];self.assertEqual(row['cleanup_remaining_seconds'],-.5)
        self.assertGreater(row['command_remaining_seconds'],0)

    def test_original_launch_and_cancellation_objects_propagate_without_payload_metadata(self):
        for primary in (launch.LaunchError('CANARY_SECRET_PATH'),KeyboardInterrupt('CANARY_SECRET_PATH'),SystemExit('CANARY_SECRET_PATH')):
            with self.subTest(kind=type(primary).__name__),mock.patch.object(self.guard,'_daemon',side_effect=primary):
                with self.assertRaises(type(primary))as caught:self.guard.service_process(self.case.record,'logs',self.case.fixture.now[0]+3)
                self.assertIs(caught.exception,primary)
                value=timing.extract_service_diagnostic(primary);self.assertEqual(value['phase'],'daemon_check')
                self.assertNotIn('CANARY',json.dumps(value));self.assertNotIn('exception',json.dumps(value))

    def test_metadata_snapshot_failure_never_masks_primary(self):
        primary=KeyboardInterrupt('PRIMARY_CANARY')
        with mock.patch.object(self.guard,'_daemon',side_effect=primary),mock.patch.object(timing.ServiceDiagnostic,'snapshot',side_effect=SystemExit('TELEMETRY_CANARY')):
            with self.assertRaises(KeyboardInterrupt)as caught:self.guard.service_process(self.case.record,'logs',self.case.fixture.now[0]+3)
        self.assertIs(caught.exception,primary);self.assertIsNone(timing.extract_service_diagnostic(primary))

    def test_late_fence_ownership_and_delegate_failures_keep_the_exact_phase(self):
        for site in ('ownership_check','durable_fence','ownership_recheck','delegate_gate','delegate'):
            primary=launch.LaunchError('CANARY_PRIMARY')
            count=[0]
            if site=='durable_fence':
                original=launch._read
                def injected(fd,name):
                    if name=='ledger.json':
                        count[0]+=1
                        if count[0]==2:raise primary
                    return original(fd,name)
                target=mock.patch.object(launch,'_read',side_effect=injected)
            elif site in ('ownership_check','ownership_recheck'):
                original=self.guard._owned_key_state
                def injected(*args):
                    count[0]+=1
                    if count[0]==(1 if site=='ownership_check'else 2):raise primary
                    return original(*args)
                target=mock.patch.object(self.guard,'_owned_key_state',side_effect=injected)
            elif site=='delegate_gate':
                original=self.case.fixture.ledger._remaining_now
                def injected(*args):
                    count[0]+=1
                    if count[0]==5:raise primary
                    return original(*args)
                target=mock.patch.object(self.case.fixture.ledger,'_remaining_now',side_effect=injected)
            else:
                original=self.guard.original_popen
                def injected(argv,**kwargs):
                    if argv[1]=='logs':count[0]+=1;raise primary
                    return original(argv,**kwargs)
                target=mock.patch.object(self.guard,'original_popen',side_effect=injected)
            with self.subTest(site=site),target,self.assertRaises(launch.LaunchError)as caught:
                self.guard.service_process(self.case.record,'logs',self.case.fixture.now[0]+3)
            self.assertIs(caught.exception,primary);self.assertEqual(timing.extract_service_diagnostic(primary)['phase'],site)
            if site=='delegate':self.assertEqual(count[0],1)

    def test_normal_dispatch_has_two_validations_and_one_unchanged_delegate(self):
        child=self.guard.service_process(self.case.record,'logs',self.case.fixture.now[0]+3)
        with child:pass
        self.assertEqual(self.case.validations,2);self.assertEqual(self.case.transactions,1)
        self.assertEqual(sum(argv[1]=='logs'for argv in self.backend.commands),1)

    def test_no_telemetry_clock_callback_between_last_gate_and_popen(self):
        gated=[False];calls=[0];late=[];deadline=self.case.fixture.now[0]+3
        original=self.case.fixture.ledger._remaining_now
        def remaining(state):
            result=original(state);calls[0]+=1
            if calls[0]==5:gated[0]=True
            return result
        def slow_if_after_gate():
            if gated[0]:late.append(True);self.backend.advance(4)
            return self.case.fixture.now[0]
        delegate=self.guard.original_popen
        def checked(argv,**kwargs):
            if argv[1]=='logs':self.assertLess(self.case.fixture.now[0],deadline)
            return delegate(argv,**kwargs)
        with mock.patch.object(launch.time,'monotonic',side_effect=slow_if_after_gate),mock.patch.object(self.case.fixture.ledger,'_remaining_now',side_effect=remaining),mock.patch.object(self.guard,'original_popen',side_effect=checked):
            child=self.guard.service_process(self.case.record,'logs',deadline)
            with child:pass
        self.assertEqual(late,[]);self.assertEqual(calls[0],5)


class ClosedMetadataTests(unittest.TestCase):
    def valid(self):
        clock=[10.];rec=timing.ServiceDiagnostic(clock=lambda:clock[0],command_deadline=13,cleanup_deadline=40)
        rec.observed_remaining(10.,100.)
        for phase in timing.SERVICE_PHASES[1:]:clock[0]+=.1;rec.mark(phase)
        error=ValueError('CANARY_NOT_READ');error.service_deadline_diagnostic=rec.snapshot();return error

    def test_closed_copy_is_independent_bounded_and_contains_no_absolute_clock(self):
        error=self.valid();value=timing.extract_service_diagnostic(error)
        self.assertEqual(len(value['observations']),10);self.assertLessEqual(len(json.dumps(value).encode()),timing.MAX_SERVICE_DIAGNOSTIC_BYTES)
        value['observations'][0]['phase']='CANARY';self.assertEqual(timing.extract_service_diagnostic(error)['observations'][0]['phase'],'authority_validation')
        self.assertNotIn('monotonic',json.dumps(value));self.assertNotIn('CANARY_NOT_READ',json.dumps(value))

    def test_unknown_fields_types_order_and_unbounded_numbers_are_dropped(self):
        mutations=[lambda v:v.update(path='CANARY'),lambda v:v.update(schema=True),lambda v:v.update(phase='CANARY'),
            lambda v:v['observations'].append(copy.deepcopy(v['observations'][0])),lambda v:v.update(elapsed_seconds=float('nan')),
            lambda v:v['observations'][0].update(command_remaining_seconds=10**10000),lambda v:v['observations'][0].update(payload=object()),
            lambda v:v['observations'][1].update(phase='authority_validation')]
        for mutate in mutations:
            error=self.valid();mutate(error.service_deadline_diagnostic);self.assertIsNone(timing.extract_service_diagnostic(error))

    def test_event_overflow_and_regressed_clock_cannot_grow_or_fabricate_trace(self):
        now=[1.];rec=timing.ServiceDiagnostic(clock=lambda:now[0],command_deadline=10)
        for phase in timing.SERVICE_PHASES[1:]:rec.mark(phase)
        for _ in range(1000):rec.mark('CANARY')
        self.assertEqual(len(rec.rows),10);self.assertIsNone(rec.snapshot())
        rec=timing.ServiceDiagnostic(clock=lambda:now[0],command_deadline=10);now[0]=0
        self.assertIsNone(rec.snapshot())

    def test_extractor_does_not_read_exception_string_or_arbitrary_attributes(self):
        class ClosedError(ValueError):
            def __str__(self):raise AssertionError('exception rendering forbidden')
        error=ClosedError();error.service_deadline_diagnostic=self.valid().service_deadline_diagnostic
        self.assertIsNotNone(timing.extract_service_diagnostic(error));self.assertIsNone(timing.extract_service_diagnostic({}))


class ReadinessCustodyTests(unittest.TestCase):
    def setUp(self):
        GuardDiagnosticTests.setUp(self)
        self.record=copy.deepcopy(self.case.owner.items[0][0])
        self.observed=copy.deepcopy(self.backend.objects[self.record['container']])
        self.identifier=self.record['container_id'];self.record.update(container_id=None,status='intent')
        self.case.registry.write(self.record);self.backend.commands.clear()

    def check(self,seconds=15):return self.guard.service_readiness_check(self.record,self.observed,self.case.fixture.now[0]+seconds)

    def write_state(self,state):
        path=self.case.fixture.ledger.root/'ledger.json';path.write_text(json.dumps(state));path.chmod(0o600)

    def test_null_owner_cid_accepts_only_existing_captured_id_without_adopting_it(self):
        before=self.case.raw()['launches'];self.assertEqual(self.check(),self.identifier)
        self.assertIsNone(self.record['container_id']);self.assertEqual(self.case.raw()['launches'],before)
        self.assertEqual(self.case.validations,2);self.assertEqual(self.case.transactions,1)
        self.assertEqual([argv[1]for argv in self.backend.commands],['info'])

    def test_foreign_observation_never_populates_null_caller_id(self):
        self.observed['Id']='f'*64
        with self.assertRaises(launch.LaunchError):self.check()
        self.assertIsNone(self.record['container_id']);self.assertEqual(self.backend.commands,[])

    def test_poison_pending_absent_uncertain_and_missing_captured_identity_refuse(self):
        before=self.case.raw()
        for change in ('poison','pending','absent','uncertain','pid','cid'):
            state=copy.deepcopy(before);row=next(r for r in state['launches']if r['launch_id']==self.record['launch_id'])
            if change=='poison':state['poisoned']=True
            elif change in ('pid','cid'):row['pid'if change=='pid'else'container_id']=None
            else:row['physical']=change
            self.write_state(state)
            with self.subTest(change=change),self.assertRaises(launch.LaunchError):self.check()
            self.assertIsNone(self.record['container_id'])
        self.assertEqual(self.backend.commands,[])

    def test_mount_label_image_daemon_and_registry_drift_refuse_before_id_return(self):
        baseline=copy.deepcopy(self.observed)
        for change in ('mount','label','image'):
            self.observed=copy.deepcopy(baseline)
            if change=='mount':self.observed['Mounts'][0]['RW']=not self.observed['Mounts'][0]['RW']
            elif change=='label':self.observed['Config']['Labels'][launch.LABEL]='00000000-0000-0000-0000-000000000000'
            else:self.observed['Image']='sha256:'+'f'*64
            with self.subTest(change=change),self.assertRaises(launch.LaunchError):self.check()
        self.observed=baseline
        with mock.patch.object(self.guard,'_daemon',return_value={'id':'foreign'}),self.assertRaises(launch.LaunchError):self.check()
        def drift(state):
            if self.case.validations%2==0:
                modified=copy.deepcopy(self.record);modified['image']='sha256:'+'f'*64;self.case.registry.write(modified)
        self.case.validation_hook=drift
        with self.assertRaises(launch.LaunchError):self.check()
        self.assertIsNone(self.record['container_id'])

    def test_post_fsync_deadline_refuses_and_preserves_no_record_overwrite(self):
        original=launch._write
        def delayed(*args):result=original(*args);self.backend.advance(16);return result
        with mock.patch.object(launch,'_write',side_effect=delayed),self.assertRaises(launch.LaunchError)as caught:self.check()
        self.assertEqual(str(caught.exception),'qualification_deadline');self.assertIsNone(self.record['container_id'])
        self.assertEqual(self.case.validations,2)
        self.assertEqual(timing.extract_service_diagnostic(caught.exception)['phase'],'readiness_acceptance')

    def test_readiness_two_by_two_seconds_accepts_but_eight_by_eight_has_closed_budget_failure(self):
        self.case.validation_hook=lambda state:self.backend.advance(2)
        self.assertEqual(self.check(),self.identifier);self.assertIsNone(self.record['container_id'])
        self.case.validation_hook=lambda state:self.backend.advance(8)
        with self.assertRaises(launch.LaunchError)as caught:self.check()
        value=timing.extract_service_diagnostic(caught.exception);self.assertEqual(value['phase'],'readiness_acceptance')
        self.assertEqual(value['elapsed_seconds'],16);self.assertEqual(value['observations'][-1]['command_remaining_seconds'],-1)
        row=next(row for row in value['observations']if row['phase']=='authority_commit')
        self.assertEqual(row['observed_elapsed_seconds']-row['entered_elapsed_seconds'],8)
        self.assertIsNone(self.record['container_id']);self.assertFalse(any(argv[1]=='logs'for argv in self.backend.commands))

    def test_readiness_campaign_expiry_is_distinct_from_fifteen_second_bound(self):
        advance=self.case.raw()['deadline']-self.case.fixture.now[0]+1
        self.case.validation_hook=lambda state:self.backend.advance(advance)
        with self.assertRaises(launch.LaunchError)as caught:self.check(seconds=advance+10)
        value=timing.extract_service_diagnostic(caught.exception);self.assertEqual(value['phase'],'authority_validation')
        self.assertEqual(value['observations'][0]['campaign_remaining_seconds'],0)
        self.assertGreater(value['observations'][0]['command_remaining_seconds'],0)
        self.assertIsNone(self.record['container_id']);self.assertEqual(self.backend.commands,[])

    def test_ownership_cancellation_propagates_exactly_and_no_delegate_is_available(self):
        for primary in (KeyboardInterrupt('CANARY'),SystemExit('CANARY')):
            with mock.patch.object(self.guard,'_daemon',side_effect=primary),self.assertRaises(type(primary))as caught:self.check()
            self.assertIs(caught.exception,primary);self.assertIsNone(self.record['container_id'])
            self.assertEqual(timing.extract_service_diagnostic(primary)['phase'],'daemon_check')

    def test_durable_named_lock_replacement_refuses_after_commit(self):
        original=launch._write
        def replaced(*args):
            result=original(*args);path=self.case.fixture.ledger.root/'ledger.lock';path.unlink();path.write_bytes(b'');path.chmod(0o600);return result
        with mock.patch.object(launch,'_write',side_effect=replaced),self.assertRaises(launch.LaunchError):self.check()
        self.assertIsNone(self.record['container_id'])


if __name__=='__main__':unittest.main()
