"""Real host filesystem regressions; Docker calls here are explicitly mocked."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str((Path(__file__).resolve().parents[1] / 'skill') / 'scripts'))
import pi_lab as lab


def args(**fields):
    value = dict(platform='linux/arm64', uid=os.getuid(), gid=os.getgid(), memory='1g',
                 cpus=1, allow_browser_no_sandbox=False, software_webgl=False, network='none')
    value.update(fields)
    return argparse.Namespace(**value)


class ParentSourcesTests(unittest.TestCase):
    def test_child_control_symlinks_cannot_redirect_next_stage(self):
        with tempfile.TemporaryDirectory() as td:
            top = Path(td); workspace = top / 'project'; workspace.mkdir()
            runroot = top / 'results'; runroot.mkdir()
            sentinel = top / 'sentinel'; sentinel.write_text('unchanged')
            runtime = workspace / '.pi-runtime'; runtime.mkdir()
            (runtime / 'task.json').symlink_to(sentinel)
            (workspace / '.pi-lab').symlink_to(top / 'outside')
            with mock.patch.object(lab, 'stream_run', return_value={'exit_code': 0}) as stream:
                lab.run_stage(args(), 'fixture', runroot, workspace, 'one', ['check'], task={'name':'one'})
                runtime.rename(workspace / 'old-control')
                (workspace / '.pi-runtime').symlink_to(top)
                lab.run_stage(args(), 'fixture', runroot, workspace, 'two', ['check'], task={'name':'two'})
            self.assertEqual(sentinel.read_text(), 'unchanged')
            self.assertFalse((top / 'outside').exists())
            sources = list((runroot / 'controls').iterdir())
            self.assertEqual(len(sources), 2)
            self.assertEqual({json.loads((p / 'task.json').read_text())['name'] for p in sources}, {'one','two'})
            for call in stream.call_args_list:
                mounts = [x for x in call.args[0] if x.startswith('type=bind')]
                self.assertFalse(any('dst=/workspace/.pi-' in x for x in mounts))
                self.assertTrue(any('dst=/opt/pi-control,readonly' in x for x in mounts))
                self.assertTrue(any('dst=/pi-state,' in x for x in mounts))
                writable = [x.split('src=',1)[1].split(',dst=',1)[0] for x in mounts if ',readonly' not in x]
                controls = [x for x in mounts if 'dst=/opt/pi-control,readonly' in x][0].split('src=',1)[1].split(',dst=',1)[0]
                self.assertNotIn(controls, writable)

    def test_readonly_and_in_place_use_external_runtime(self):
        for access in ('rw','ro'):
            with self.subTest(access=access), tempfile.TemporaryDirectory() as td:
                top=Path(td); workspace=top/'original';workspace.mkdir();runroot=top/'results';runroot.mkdir()
                with mock.patch.object(lab,'stream_run',return_value={'exit_code':0}) as stream:
                    lab.run_stage(args(), 'fixture', runroot, workspace, 'review', ['check'], access=access)
                argv=stream.call_args.args[0]
                self.assertTrue(any(f'src={workspace},dst=/workspace,' in x and (',readonly' in x)==(access=='ro') for x in argv))
                self.assertFalse(list(workspace.iterdir()))

    def test_save_rejects_symlink_without_touching_sentinel(self):
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);sentinel=top/'sentinel';sentinel.write_text('safe');target=top/'task';target.symlink_to(sentinel)
            with self.assertRaises(lab.LabError):lab.save(target, {'bad':True})
            self.assertEqual(sentinel.read_text(),'safe')

    def test_channel_permission_errors_are_not_ignored(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(Path,'chmod',side_effect=PermissionError('denied')):
            with self.assertRaises(PermissionError):lab.control_channels(Path(td)/'controls')

    def test_in_place_runtime_helper_alias_cannot_change_next_stage_helpers(self):
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);workspace=top/'project';workspace.mkdir();original=workspace/'runtime';original.mkdir()
            (original/'worker.py').write_text('reviewed helper')
            run=top/'results';run.mkdir()
            with mock.patch.object(lab,'RUNTIME',original),mock.patch.object(lab,'stream_run',return_value={'exit_code':0,'cleanup_confirmed':True}) as stream:
                lab.run_stage(args(),'fixture',run,workspace,'one',['check'])
                (original/'worker.py').write_text('child changed original')
                lab.run_stage(args(),'fixture',run,workspace,'two',['check'])
            self.assertEqual((run/'trusted-runtime/worker.py').read_text(),'reviewed helper')
            for call in stream.call_args_list:
                self.assertIn(f'type=bind,src={run}/trusted-runtime,dst=/opt/pi-lab,readonly,bind-recursive=disabled',call.args[0])
            self.assertNotEqual((original/'worker.py').stat().st_ino,(run/'trusted-runtime/worker.py').stat().st_ino)

    def test_parent_sources_inside_workspace_are_rejected_before_writes(self):
        with tempfile.TemporaryDirectory() as td:
            w=Path(td);run=w/'results';run.mkdir()
            with self.assertRaises(lab.LabError):lab.run_stage(args(),'fixture',run,w,'dev',['check'])
            self.assertFalse(list(run.iterdir()))


def prepare(top, name='dev', workspace=None, limits=None, running=True):
    import stage_control as controls
    import uuid
    run=top/'run';run.mkdir(exist_ok=True)
    workspace=workspace or top/'project';workspace.mkdir(exist_ok=True)
    stage_id=str(uuid.uuid4());control=run/'controls'/stage_id;control.mkdir(parents=True)
    lab.control_channels(control,os.getuid())
    state=lab.state_dir(run/'children',stage_id,os.getuid())
    task=limits or {'max_turns':10,'timeout_seconds':30,'max_total_tokens':1000}
    lab.save(control/'task.json',task)
    desc=controls.create(run,workspace,name,'agent',task,control,state,stage_id,'fixture-'+stage_id,top/'admission.lock')
    if running:
        parent_state=controls.transition(run,desc,'running')
    else:
        parent_state=controls.resolve(run,stage_id)[1]
    controls.atomic(control/'stage.json',{**desc,'stage_revision':parent_state['revision']})
    if running:
        import time
        controls.start_budget(run,desc,time.monotonic())
    return run,desc


class StageRoutingTests(unittest.TestCase):
    def test_two_stages_have_distinct_budgets_directives_and_observations(self):
        import stage_control as controls
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);run,one=prepare(top,'one');_,two=prepare(top,'two',limits={'max_turns':20,'timeout_seconds':40,'max_total_tokens':2000})
            for desc in (one,two):
                a=args(run=str(run),stage=desc['stage_id'],revision=1,message=desc['label'],interrupt=False)
                lab.cmd_steer(a)
                lab.cmd_extend_budget(args(run=str(run),stage=desc['stage_id'],turns='+2',timeout=None,tokens=None))
                controls.process_budget_requests(run,desc)
                lab.save(Path(desc['outbox'])/'heartbeat.json',{'schema':2,'stage_id':desc['stage_id'],'status':'forged','workspace':'/outside'})
            for desc,limit in ((one,12),(two,22)):
                self.assertEqual(controls.read(Path(desc['inbox'])/'limits.json')['max_turns'],limit)
                files=list((Path(desc['inbox'])/'directives').glob('*.json'))
                self.assertEqual(len(files),1)
                self.assertEqual(controls.read(files[0])['message'],desc['label'])
                self.assertEqual(lab.stage_channels(run,desc['stage_id'])[0],Path(desc['inbox']))
                self.assertEqual(controls.resolve(run,desc['stage_id'])[1]['status'],'running')

    def test_wrong_stale_completed_and_ambiguous_targets_rejected(self):
        import stage_control as controls
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);run,one=prepare(top)
            for target,revision in [('unknown',None),(one['stage_id'],0)]:
                with self.assertRaises((lab.LabError,controls.ControlError)):
                    lab.cmd_steer(args(run=str(run),stage=target,revision=revision,message='x',interrupt=False))
            controls.transition(run,one,'stopping');controls.transition(run,one,'stopped',cleanup_confirmed=True);controls.transition(run,one,'finalized')
            with self.assertRaises(lab.LabError):lab.cmd_steer(args(run=str(run),stage=one['stage_id'],message='x',interrupt=False))
            prepare(top)
            with self.assertRaises(lab.LabError):lab.cmd_steer(args(run=str(run),stage='dev',message='x',interrupt=False))

    def test_worker_rejects_cross_stage_stale_and_forged_acknowledgements(self):
        sys.path.insert(0,str((Path(__file__).resolve().parents[1] / 'skill')/'runtime'));import worker
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);run,desc=prepare(top)
            lab.cmd_steer(args(run=str(run),stage=desc['stage_id'],message='first',interrupt=False))
            context={**desc,'stage_revision':1}
            inbox=Path(desc['inbox']);outbox=Path(desc['outbox'])
            with mock.patch.object(worker,'directive_context',return_value=context):
                directive=worker.check_steering(inbox,outbox)
                lab.save(outbox/'steer_ack.json',{'schema':2,**directive,'status':'applied'})
                self.assertIsNotNone(worker.check_steering(inbox,outbox))
                worker.acknowledge_steering(outbox,directive['id'])
                self.assertIsNone(worker.check_steering(inbox,outbox))
                context['stage_id']='wrong'
                self.assertIsNone(worker.check_steering(inbox,outbox))


class PatchProtocolTests(unittest.TestCase):
    def patch_args(self,run,desc,source,target):
        return args(run=str(run),stage=desc['stage_id'],file=str(source),target=target,message=None,interrupt=False)

    def test_legitimate_nested_patch_in_snapshot_and_original(self):
        import stage_control as controls
        for mode in ('snapshot','original'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as td:
                top=Path(td);run,desc=prepare(top,workspace=top/mode,running=False)
                source=top/'fix';source.write_text('new')
                self.assertEqual(lab.cmd_patch_session(self.patch_args(run,desc,source,'lib/deep/file.py')),0)
                self.assertEqual((Path(desc['workspace'])/'lib/deep/file.py').read_text(),'new')
                records=list((Path(desc['inbox'])/'directives').glob('*.json'))
                self.assertEqual(len(records),1)
                self.assertEqual(controls.read(records[0])['kind'],'patch')

    def test_symlinks_hardlinks_and_traversal_reject_without_receipts(self):
        for kind in ('leaf','ancestor','hardlink','traversal','absolute','protected'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as td:
                top=Path(td);run,desc=prepare(top,running=False);w=Path(desc['workspace'])
                sentinel=top/'sentinel';sentinel.write_text('safe');source=top/'fix';source.write_text('bad')
                target='dir/file';(w/'dir').mkdir()
                if kind=='leaf':(w/target).symlink_to(sentinel)
                elif kind=='ancestor':(w/'dir').rmdir();(w/'dir').symlink_to(top);target='dir/sentinel'
                elif kind=='hardlink':os.link(sentinel,w/target)
                elif kind=='traversal':target='../sentinel'
                elif kind=='absolute':target=str(sentinel)
                else:
                    import stage_control as controls
                    # Trusted test setup simulates a protected-input descriptor.
                    desc['protected_paths']=['dir'];controls.atomic(run/'stages'/desc['stage_id']/'descriptor.json',desc)
                with self.assertRaises(lab.LabError):lab.cmd_patch_session(self.patch_args(run,desc,source,target))
                self.assertEqual(sentinel.read_text(),'safe')
                self.assertFalse((Path(desc['inbox'])/'directives').exists())

    def test_replaced_ancestor_detected_before_atomic_replace(self):
        import workspace_patch
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);run,desc=prepare(top,running=False);w=Path(desc['workspace']);(w/'dir').mkdir();(w/'dir/file').write_text('safe')
            source=top/'fix';source.write_text('bad');real_check=workspace_patch.same_tree
            def replace_ancestor(root,parts,fds):
                (w/'dir').rename(top/'moved');(w/'dir').symlink_to(top)
                return real_check(root,parts,fds)
            with mock.patch.object(workspace_patch,'same_tree',side_effect=replace_ancestor):
                with self.assertRaises(lab.LabError):lab.cmd_patch_session(self.patch_args(run,desc,source,'dir/file'))
            self.assertEqual((top/'moved/file').read_text(),'safe')
            self.assertFalse((Path(desc['inbox'])/'directives').exists())

    def test_active_replacement_subprocess_is_not_admitted(self):
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);run,desc=prepare(top);w=Path(desc['workspace']);sentinel=top/'sentinel';sentinel.write_text('safe');source=top/'fix';source.write_text('bad')
            process=subprocess.Popen([sys.executable,'-c',
                'import pathlib,sys,time; p=pathlib.Path(sys.argv[1]); t=sys.argv[2]; print("READY",flush=True);\nwhile True:\n p.symlink_to(t) if not p.exists() else None\n p.unlink(missing_ok=True)\n time.sleep(.001)',str(w/'race'),str(top)],stdout=subprocess.PIPE,text=True)
            try:
                import select
                self.assertTrue(select.select([process.stdout],[],[],3)[0])
                self.assertEqual(process.stdout.readline().strip(),'READY')
                for i in range(5):
                    with self.assertRaises(lab.LabError):lab.cmd_patch_session(self.patch_args(run,desc,source,'race/sentinel'))
            finally:process.terminate();process.wait(timeout=5);process.stdout.close()
            self.assertEqual(sentinel.read_text(),'safe')
            self.assertFalse((Path(desc['inbox'])/'directives').exists())

    def test_unconfirmed_previous_writer_and_unsupported_host_reject(self):
        import stage_control as controls
        import workspace_patch
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);run,old=prepare(top);controls.transition(run,old,'stopping');controls.transition(run,old,'stopped');controls.transition(run,old,'finalized')
            _,desc=prepare(top,'next',running=False);source=top/'fix';source.write_text('bad')
            with self.assertRaises(lab.LabError):lab.cmd_patch_session(self.patch_args(run,desc,source,'file'))
            with mock.patch.object(workspace_patch.os,'supports_dir_fd',set()):
                with self.assertRaises(workspace_patch.PatchError):workspace_patch.apply(desc['workspace'],desc['workspace_identity'],'file',b'bad',[])

    def test_host_lease_blocks_pending_patch_while_another_runner_operates(self):
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);run,desc=prepare(top,running=False);source=top/'fix';source.write_text('bad')
            with lab.admission_lock(desc['admission_lock_file'],0):
                with self.assertRaises(lab.AdmissionError) as caught:lab.cmd_patch_session(self.patch_args(run,desc,source,'file'))
                self.assertEqual(caught.exception.reason,'host-admission-busy')
            self.assertFalse((Path(desc['workspace'])/'file').exists())


class DeadlineTests(unittest.TestCase):
    def test_real_subprocess_survives_original_deadline_then_stops_at_extension(self):
        import threading,time
        import stage_control as controls
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);run,desc=prepare(top,limits={'max_turns':10,'timeout_seconds':1,'max_total_tokens':1000})
            results={}
            def execute():
                results.update(lab.stream_run([sys.executable,'-u','-c','import time; time.sleep(1.2); print("SURVIVED"); time.sleep(10)'],top/'logs',1,'short-process',stage=(run,desc)))
            thread=threading.Thread(target=execute);thread.start()
            try:
                time.sleep(.25)
                self.assertEqual(lab.cmd_extend_budget(args(run=str(run),stage=desc['stage_id'],turns=None,timeout='+1',tokens=None)),0)
                thread.join(timeout=4)
                self.assertFalse(thread.is_alive())
                self.assertEqual(results['effective_limits']['timeout_seconds'],2)
                self.assertEqual(results['termination_reason'],'timeout')
                self.assertTrue(results['cleanup_confirmed'])
                self.assertIn('SURVIVED',(top/'logs/stdout.jsonl').read_text())
                self.assertGreaterEqual(results['elapsed_seconds'],2)
                self.assertLess(results['elapsed_seconds'],3)
            finally:
                thread.join(timeout=4)

    def test_worker_revision_does_not_renew_timer(self):
        sys.path.insert(0,str((Path(__file__).resolve().parents[1] / 'skill')/'runtime'))
        import worker
        import stage_control as controls
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);run,desc=prepare(top)
            task=dict(desc['original_limits']);context={**desc,'stage_revision':1}
            with mock.patch.object(worker,'directive_context',return_value=context),mock.patch.object(worker,'control_dirs',return_value=(Path(desc['inbox']),Path(desc['outbox']))):
                self.assertTrue(worker.sync_dynamic_limits(Path(desc['inbox']),task))
                first=task['_worker_deadline']
                self.assertFalse(worker.sync_dynamic_limits(Path(desc['inbox']),task))
                self.assertEqual(task['_worker_deadline'],first)
                lab.cmd_extend_budget(args(run=str(run),stage=desc['stage_id'],turns='+1',timeout='+1',tokens='+1'))
                controls.process_budget_requests(run,desc)
                self.assertTrue(worker.sync_dynamic_limits(Path(desc['inbox']),task))
                self.assertEqual(task['_budget_revision'],1)
                self.assertEqual(task['max_turns'],11)

    def test_malformed_stale_late_and_ineffective_limits_reject(self):
        import time
        import stage_control as controls
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);run,desc=prepare(top)
            for value in ('nan','inf','+0','-1','1000000000','1.5'):
                with self.subTest(value=value), self.assertRaises(lab.LabError):
                    lab.cmd_extend_budget(args(run=str(run),stage=desc['stage_id'],turns=value,timeout=None,tokens=None))
            with self.assertRaises(lab.LabError):lab.cmd_extend_budget(args(run=str(run),stage=desc['stage_id'],budget_revision=99,turns='+1',timeout=None,tokens=None))
            budget=controls.read(controls.budget_path(run,desc));budget['deadline_host_monotonic']=time.monotonic()-1;controls.atomic(controls.budget_path(run,desc),budget)
            with self.assertRaises(lab.LabError):lab.cmd_extend_budget(args(run=str(run),stage=desc['stage_id'],turns=None,timeout='+1',tokens=None))

    def test_cleanup_failure_and_oom_remain_distinct_from_timeout(self):
        with tempfile.TemporaryDirectory() as td:
            # Synthetic Docker observation; this is not a live OOM.
            process=mock.Mock();process.poll.return_value=0;process.wait.return_value=137
            import io
            process.stdout=io.BytesIO();process.stderr=io.BytesIO()
            def cmd(argv,**kw):
                if argv[1]=='inspect':return argparse.Namespace(returncode=0,stdout=json.dumps([{'State':{'OOMKilled':True},'HostConfig':{}}]),stderr='')
                return argparse.Namespace(returncode=1,stdout='',stderr='daemon unavailable')
            with mock.patch.object(lab.subprocess,'Popen',return_value=process),mock.patch.object(lab,'command',side_effect=cmd):
                result=lab.stream_run(['docker','run','fixture'],Path(td),1,'fake')
            self.assertEqual(result['termination_reason'],'cleanup_error')
            self.assertEqual(result['termination_trigger'],'oom')
            self.assertFalse(result['cleanup_confirmed'])

    def test_wait_reports_host_application_and_stale_queued_request_rejection(self):
        import threading,time,io,contextlib
        import stage_control as controls
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);run,desc=prepare(top)
            updater=threading.Thread(target=lambda:(time.sleep(.1),controls.process_budget_requests(run,desc)))
            updater.start();output=io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(lab.cmd_extend_budget(args(run=str(run),stage=desc['stage_id'],turns='+1',timeout=None,tokens=None,wait_seconds=1)),0)
            updater.join(timeout=2)
            self.assertEqual(json.loads(output.getvalue())['status'],'applied')
            for _ in range(2):lab.cmd_extend_budget(args(run=str(run),stage=desc['stage_id'],turns='+1',timeout=None,tokens=None))
            controls.process_budget_requests(run,desc)
            responses=[controls.read(p) for p in (controls.budget_path(run,desc).parent/'budget-updates').glob('*.json')]
            self.assertEqual(sum(r['status']=='rejected' for r in responses),1)
            self.assertEqual(controls.read(controls.budget_path(run,desc))['effective_limits']['max_turns'],12)

    def test_worker_malformed_view_never_changes_limits(self):
        sys.path.insert(0,str((Path(__file__).resolve().parents[1] / 'skill')/'runtime'));import worker
        import stage_control as controls
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);run,desc=prepare(top);inbox=Path(desc['inbox']);view=controls.read(inbox/'limits.json')
            with mock.patch.object(worker,'directive_context',return_value={**desc,'stage_revision':1}):
                for field,value in [('max_turns',True),('timeout_seconds',99999),('remaining_seconds',float('nan')),('remaining_seconds',float('inf')),('budget_revision',True)]:
                    changed={**view,field:value};controls.atomic(inbox/'limits.json',changed)
                    task=dict(desc['original_limits'])
                    self.assertFalse(worker.sync_dynamic_limits(inbox,task))
                    self.assertEqual(task,desc['original_limits'])


class InterventionTests(unittest.TestCase):
    def test_multiple_commands_survive_reload_and_forged_stale_ack_is_observation_only(self):
        import importlib,uuid
        import stage_control as controls
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);run,desc=prepare(top)
            for message in ('one','two'):
                lab.cmd_steer(args(run=str(run),stage=desc['stage_id'],message=message,interrupt=False))
            before=controls.history(run);assist=controls.assistance(run)
            self.assertEqual(len(assist['intervention_ids']),2)
            requests=[e for e in before if e['status']=='accepted']
            folder=Path(desc['outbox'])/'acks';folder.mkdir()
            forged={**requests[0],'id':str(uuid.uuid4()),'status':'applied'}
            lab.save(folder/(forged['id']+'.json'),forged)
            stale={**requests[0],'expected_stage_revision':0,'status':'applied'}
            lab.save(folder/(stale['id']+'.json'),stale)
            controls.capture_observations(run,desc)
            self.assertEqual(controls.history(run),before)
            correct={**requests[0],'status':'applied'};lab.save(folder/(correct['id']+'.json'),correct)
            controls.capture_observations(run,desc)
            self.assertEqual(len(controls.history(run)),len(before)+1)
            self.assertFalse(controls.history(run)[-1]['trusted'])
            controls.capture_observations(run,desc)
            self.assertEqual(len(controls.history(run)),len(before)+1)
            importlib.reload(controls)
            self.assertEqual(controls.assistance(run),assist)
            self.assertEqual(sum(e['status']=='accepted' for e in controls.history(run)),2)

    def test_rejections_remain_distinct_and_do_not_mark_assisted(self):
        import stage_control as controls
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);run,desc=prepare(top)
            for value in ('nan','+0','1000'):
                with self.assertRaises(lab.LabError):lab.cmd_extend_budget(args(run=str(run),stage=desc['stage_id'],turns=value,timeout=None,tokens=None))
            history=controls.history(run)
            self.assertEqual(sum(e['status']=='requested' for e in history),3)
            self.assertEqual(sum(e['status']=='rejected' for e in history),3)
            self.assertEqual(len({e['intervention_id'] for e in history}),3)
            self.assertEqual(controls.assistance(run)['status'],'autonomous')

    def test_budget_history_has_authorized_before_after_and_application(self):
        import stage_control as controls
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);run,desc=prepare(top)
            lab.cmd_extend_budget(args(run=str(run),stage=desc['stage_id'],turns='+1',timeout=None,tokens=None))
            self.assertEqual(controls.assistance(run)['status'],'autonomous')
            controls.process_budget_requests(run,desc)
            events=controls.history(run)
            self.assertEqual([e['status'] for e in events],['requested','queued','accepted','applied'])
            self.assertEqual(events[-1]['before']['max_turns'],10)
            self.assertEqual(events[-1]['after']['max_turns'],11)
            self.assertEqual(controls.assistance(run)['status'],'assisted')

    def test_protected_patch_is_rejected_and_successful_patch_has_hash(self):
        import stage_control as controls,hashlib
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);run,desc=prepare(top,running=False);source=top/'fix';source.write_text('patch-content')
            desc['protected_paths']=['oracle'];controls.atomic(run/'stages'/desc['stage_id']/'descriptor.json',desc)
            a=args(run=str(run),stage=desc['stage_id'],file=str(source),target='oracle/check.py',message=None,interrupt=False)
            with self.assertRaises(lab.LabError):lab.cmd_patch_session(a)
            self.assertEqual(controls.assistance(run)['status'],'autonomous')
            a.target='lib/code.py';lab.cmd_patch_session(a)
            applied=[e for e in controls.history(run) if e['status']=='applied']
            self.assertEqual(applied[0]['patch_sha256'],hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertEqual(controls.assistance(run)['status'],'assisted')

    def test_history_excludes_secrets_payload_text_and_child_reason_strings(self):
        import stage_control as controls
        with tempfile.TemporaryDirectory() as td, mock.patch.dict(os.environ,{'PI_API_KEY':'audit-secret-value'}):
            top=Path(td);run,desc=prepare(top)
            lab.cmd_steer(args(run=str(run),stage=desc['stage_id'],message='audit-secret-value http://private.example/v1',interrupt=False))
            accepted=next(e for e in controls.history(run) if e['status']=='accepted')
            folder=Path(desc['outbox'])/'acks';folder.mkdir()
            lab.save(folder/(accepted['id']+'.json'),{**accepted,'status':'audit-secret-value'})
            controls.capture_observations(run,desc)
            text=(run/'interventions.jsonl').read_text()
            self.assertNotIn('audit-secret-value',text);self.assertNotIn('private.example',text)
            self.assertEqual(controls.history(run)[-1]['child_status'],'unknown')

    def test_concurrent_appends_are_complete_and_observation_links_fail_closed(self):
        from concurrent.futures import ThreadPoolExecutor
        import stage_control as controls
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);run,desc=prepare(top)
            with ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(lambda n:lab.cmd_steer(args(run=str(run),stage=desc['stage_id'],message=str(n),interrupt=False)),range(8)))
            events=controls.history(run)
            self.assertEqual(len(events),24)
            self.assertEqual([e['sequence'] for e in events],list(range(1,25)))
            sentinel=top/'sentinel';sentinel.mkdir();(Path(desc['outbox'])/'acks').symlink_to(sentinel)
            controls.capture_observations(run,desc)
            self.assertEqual(len(controls.history(run)),24)
            ledger=run/'interventions.jsonl';ledger.unlink();external=top/'external';external.write_text('safe');ledger.symlink_to(external)
            with self.assertRaises(OSError):controls.audit(run,events[0],'requested')
            self.assertEqual(external.read_text(),'safe')
            ledger.unlink();os.link(external,ledger)
            with self.assertRaises(controls.ControlError):controls.audit(run,events[0],'requested')
            self.assertEqual(external.read_text(),'safe')

    def test_assisted_summary_cannot_return_clean_pass(self):
        """Synthetic mechanical success isolates attribution; no Pi/Docker invocation."""
        import io,contextlib
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);project=top/'project';project.mkdir();(project/'code.py').write_text('pass')
            plan=top/'plan.json';lab.save(plan,{'schema':1,'agents':[{'name':'dev','prompt':'Synthetic task','require_tools':[]}],'checks':[{'name':'oracle','argv':['true']}]})
            a=lab.parser().parse_args(['run','--project',str(project),'--plan',str(plan),'--endpoint',str(top/'endpoint.json'),'--results-dir',str(top/'results'),'--platform','linux/arm64','--uid',str(os.getuid()),'--memory','1g','--cpus','1'])
            a.lock_file=str(top/'admission.lock')
            endpoint={'base_url':'http://example.invalid/v1','model':'fixture-model','api_key_env':'PI_API_KEY','context_window':8192,'max_tokens':1024}
            def fake_stream(argv,logdir,timeout,name,secret='',stage=None,**kw):
                logdir.mkdir(parents=True,exist_ok=True);(logdir/'stdout.jsonl').write_text('');(logdir/'stderr.log').write_text('')
                if stage:
                    run,desc=stage
                    lab.cmd_steer(args(run=str(run),stage=desc['stage_id'],message='parent assistance',interrupt=False))
                    lifecycle=lab.controls.resolve(run,desc['stage_id'])[1]
                    session=logdir.name
                    # Suppress continuation in this attribution-only fixture.
                    lab.controls.atomic(lab.controls.budget_path(run,desc),{'schema':2,'phase':'active','revision':0,'effective_limits':{'max_turns':1,'max_total_tokens':1},'deadline_host_monotonic':0})
                return {'exit_code':0,'cleanup_confirmed':True}
            with mock.patch.object(lab,'load_endpoint',return_value=endpoint),mock.patch.object(lab,'endpoint_secret',return_value='synthetic-key'),mock.patch.object(lab,'require_host',return_value={}),mock.patch.object(lab,'probe_image',return_value={'id':'fixture','reference':'fixture','capabilities':{'pi':'0.87.1'}}),mock.patch.object(lab,'stream_run',side_effect=fake_stream),mock.patch.object(lab,'analyze',return_value={'agent_invocation_verified':True,'errors':[],'final_text':'Synthetic fixture'}),mock.patch.object(lab.segments,'aggregate',return_value={'agent_invocation_verified':True,'completion_verified':True,'invocation_status':'verified','errors':[],'final_text':'Synthetic fixture'}),contextlib.redirect_stdout(io.StringIO()):
                code=lab.run_suite(a)
            summary=lab.controls.read((top/'results/latest').resolve()/'summary.json')
            self.assertEqual(code,1)
            self.assertEqual(summary['status'],'ASSISTED')
            self.assertEqual(summary['schema'],2)
            self.assertEqual(summary['assistance']['status'],'assisted')
            self.assertEqual(summary['agents'][0]['process']['exit_code'],0)
