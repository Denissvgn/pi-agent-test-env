"""Disposable FD and mocked diagnostic orchestration; no native/container calls."""
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools/qualification'),str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_startup_diagnostic as diagnostic


class DiagnosticDriverTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
        self.private=self.root/'private';self.private.mkdir(mode=0o700)
        self.leaf=self.private/'fake';self.leaf.write_bytes(b'FAKE_DISPOSABLE_ONLY');self.leaf.chmod(0o600)
        self.budget=SimpleNamespace(remaining=mock.Mock(return_value=30))
    def test_purge_is_inode_bound_and_never_opens_private_leaf_values(self):
        ident=diagnostic.private_identity(self.private);opened=[];original=os.open
        def observed(path,flags,*args,**kwargs):opened.append(flags);return original(path,flags,*args,**kwargs)
        with mock.patch.object(os,'open',side_effect=observed):diagnostic.purge_private(self.private,ident,self.budget)
        self.assertFalse(self.private.exists());self.assertTrue(all(flags&os.O_DIRECTORY for flags in opened))
    def test_replaced_root_linked_file_or_unsafe_mode_denies_before_removal(self):
        ident=diagnostic.private_identity(self.private);wrong={**ident,'inode':ident['inode']+1}
        with self.assertRaises(diagnostic.DiagnosticError):diagnostic.purge_private(self.private,wrong,self.budget)
        self.assertTrue(self.leaf.exists())
        self.leaf.unlink();self.leaf.symlink_to(self.root/'foreign')
        with self.assertRaises(diagnostic.DiagnosticError):diagnostic.purge_private(self.private,ident,self.budget)
        self.leaf.unlink();self.leaf.write_bytes(b'inert');self.leaf.chmod(0o644)
        with self.assertRaises(diagnostic.DiagnosticError):diagnostic.purge_private(self.private,ident,self.budget)
    def test_deadline_or_named_lease_replacement_prevents_private_effects(self):
        budget=diagnostic.Budget(time.monotonic(),time.time());path=self.root/'operation.lock';path.write_bytes(b'');path.chmod(0o600);fd=os.open(path,os.O_RDWR)
        try:
            budget.locks=[(fd,path)];path.rename(self.root/'old-lock');path.write_bytes(b'');path.chmod(0o600)
            with self.assertRaises(diagnostic.DiagnosticError):diagnostic.purge_private(self.private,diagnostic.private_identity(self.private),budget)
            self.assertTrue(self.leaf.exists())
        finally:os.close(fd)
    def test_shared120_window_preserves30_cleanup_and_checks_expiry(self):
        with mock.patch.object(diagnostic.time,'monotonic',return_value=1000),mock.patch.object(diagnostic.time,'time',return_value=1000000),mock.patch.object(diagnostic.followup.prior_successor,'DEADLINE_MONOTONIC',100000),mock.patch.object(diagnostic.followup.prior_successor,'DEADLINE_WALL',2000000):
            budget=diagnostic.Budget(1000,1000000);self.assertEqual(budget.remaining(),90)
            budget.cleanup();self.assertEqual(budget.remaining(),30)
            with mock.patch.object(diagnostic.time,'monotonic',return_value=1030),self.assertRaises(diagnostic.DiagnosticError):budget.remaining()
    def test_cleanup_budget_starts_once_and_fallback_cannot_reset_it(self):
        with mock.patch.object(diagnostic.time,'monotonic',return_value=1000):
            budget=diagnostic.Budget(1000,1000000);budget.cleanup();self.assertEqual(budget.cleanup_deadline,1030)
        with mock.patch.object(diagnostic.time,'monotonic',return_value=1010):
            budget.cleanup();self.assertEqual(budget.cleanup_started,1000);self.assertEqual(budget.cleanup_deadline,1030)
    def test_actual_completed_direct_child_is_reaped_without_popen_reference(self):
        pid=os.fork()
        if pid==0:os._exit(7)
        absent,code=diagnostic.wait_writer_absent(pid,self.budget)
        self.assertTrue(absent);self.assertEqual(code,7)
        with self.assertRaises(ChildProcessError):os.waitpid(pid,os.WNOHANG)
    def test_original_popen_destructor_path_allows_known_or_unavailable_exit(self):
        import gc
        process=subprocess.Popen([sys.executable,'-c','import time;time.sleep(.03);raise SystemExit(5)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        pid=process.pid;del process;gc.collect()
        absent,code=diagnostic.wait_writer_absent(pid,self.budget)
        self.assertTrue(absent);self.assertIn(code,(5,None))
    def test_nonchild_alive_or_unknown_pid_never_claims_writer_absence(self):
        with mock.patch.object(diagnostic.os,'waitpid',side_effect=ChildProcessError),mock.patch.object(diagnostic,'pid_absent',return_value=False):
            self.assertEqual(diagnostic.wait_writer_absent(123,self.budget),(False,None))
    def test_lab_denies_extra_launch_and_mutation_retry_without_executor(self):
        proxy=diagnostic.DiagnosticLab(self.budget);proxy.original=mock.Mock(return_value=subprocess.CompletedProcess([],0,'',''))
        for argv in (['docker','run','image'],['docker','pull','image'],['docker','exec','owned','command']):
            with self.assertRaises(diagnostic.DiagnosticError):proxy.command(argv)
        proxy.original.assert_not_called();proxy.command(['docker','rm','--force','c'*64])
        with self.assertRaises(diagnostic.DiagnosticError):proxy.command(['docker','rm','--force','c'*64])
        self.assertEqual(proxy.original.call_count,1)
    def test_guard_observation_preserves_nonzero_absence_and_supplied_timeout(self):
        proxy=diagnostic.DiagnosticLab(self.budget);proxy.original=mock.Mock(return_value=subprocess.CompletedProcess([],1,'[]','Error: No such container'))
        reply=proxy.observe_command(['docker','container','inspect','c'*64],timeout=.25)
        self.assertEqual(reply.returncode,1);self.assertFalse(proxy.original.call_args.kwargs['required']);self.assertEqual(proxy.original.call_args.kwargs['timeout'],.25)
    def test_first_original_cleanup_deadline_callback_runs_once(self):
        budget=diagnostic.Budget(1000,1000000);budget.on_cleanup=mock.Mock()
        with mock.patch.object(diagnostic.time,'monotonic',return_value=1001):budget.cleanup()
        with mock.patch.object(diagnostic.time,'monotonic',return_value=1010):budget.cleanup()
        budget.on_cleanup.assert_called_once();self.assertEqual(budget.cleanup_started,1001);self.assertEqual(budget.cleanup_deadline,1031)
    def test_container_observation_checks_exact_ids_labels_mounts_and_resources(self):
        record={'container_id':'c'*64,'image':'sha256:'+'a'*64,'launch_id':'owned','registry':'registry','mounts':[{'source':'/inert','target':'/private','rw':False}]}
        value={'Id':record['container_id'],'Image':record['image'],'Config':{'User':str(os.getuid())+':'+str(os.getgid()),'Labels':{diagnostic.ownership.LABEL:'owned',diagnostic.ownership.REGISTRY_LABEL:'registry'}},
            'Mounts':[{'Source':'/inert','Destination':'/private','RW':False}],'HostConfig':{'ReadonlyRootfs':True,'NanoCpus':1000000000,'Memory':536870912,'MemorySwap':536870912,'PidsLimit':128}}
        diagnostic.owned_container(record,value)
        for change in (lambda x:x.update(Id='f'*64),lambda x:x['Config']['Labels'].update({diagnostic.ownership.LABEL:'foreign'}),lambda x:x['Mounts'][0].update(RW=True),lambda x:x['HostConfig'].update(MemorySwap=0)):
            changed=copy.deepcopy(value);change(changed)
            with self.assertRaises(diagnostic.DiagnosticError):diagnostic.owned_container(record,changed)
    def test_source_gate_rejects_unstable_or_failed_wrappers_before_native(self):
        gate={'schema':1,'status':'PASS','source_gate':{'path':'/inert/source','sha256':'1'*64},'extracted_gate':{'path':'/inert/extracted','sha256':'2'*64},'extracted_result':{'path':'/inert/result','sha256':'4'*64},'independent_review':{'path':'/inert/review','sha256':'3'*64}}
        wrapper={'actual_exit':0,'expected_exit':0,'source_stable':False,'source_before':{},'source_after':{}}
        with mock.patch.object(diagnostic,'read',return_value=gate),mock.patch.object(diagnostic.followup,'_reference',side_effect=[wrapper,wrapper,{}, {'status':'PASS','unresolved_findings':[]}]),self.assertRaises(diagnostic.DiagnosticError):diagnostic.source_gate('/inert/gate')
    def test_source_gate_requires_exact_review_and_matching_nonempty_zero_skip_candidate(self):
        files={'tools/qualification/application_startup_diagnostic.py':'a'*64,'tools/qualification/application_followup.py':'a'*64,'tools/qualification/application_launch.py':'a'*64,'skill/runtime/client.py':'a'*64}
        gate={'schema':1,'status':'PASS','source_gate':{'path':'/inert/source','sha256':'1'*64},'extracted_gate':{'path':'/inert/extracted','sha256':'2'*64},'extracted_result':{'path':'/inert/result','sha256':'3'*64},'independent_review':{'path':'/inert/review','sha256':'4'*64}}
        wrapper={'actual_exit':0,'expected_exit':0,'source_stable':True,'source_before':files,'source_after':files,'tests_run':10,'tests_skipped':0}
        inventory={name:{'sha256':sha} for name,sha in files.items()}
        result={'status':'pass','tests_run':10,'tests_skipped':0,'unit_tests':{'exit_code':0},'source_unchanged':True,'archives_unchanged':True,'extracted_inventory_before':inventory,'extracted_inventory_after':inventory}
        review={'status':'PASS','unresolved_findings':[],'source_gate':gate['source_gate'],'extracted_gate':gate['extracted_gate'],'extracted_result':gate['extracted_result'],'source_files':files}
        def run(values):
            with mock.patch.object(diagnostic,'read',return_value=gate),mock.patch.object(diagnostic.followup,'_reference',side_effect=values),mock.patch.object(diagnostic,'digest',return_value='a'*64),mock.patch.object(diagnostic,'inventory',return_value=files),mock.patch.object(diagnostic,'reference',return_value={'path':'/gate','sha256':'a'*64}):return diagnostic.source_gate('/gate')
        self.assertEqual(run([wrapper,wrapper,result,review])['path'],'/gate')
        for changed in ({**review,'source_gate':gate['extracted_gate']},{**review,'source_files':{}}):
            with self.assertRaises(diagnostic.DiagnosticError):run([wrapper,wrapper,result,changed])
        for changed in ({**result,'tests_run':9},{**result,'tests_skipped':1},{**result,'status':'fail'}):
            with self.assertRaises(diagnostic.DiagnosticError):run([wrapper,wrapper,changed,review])
        with self.assertRaises(diagnostic.DiagnosticError):run([{**wrapper,'tests_run':0},wrapper,result,review])
    def projection_gate(self,mutate=None):
        files={name:'a'*64 for name in ('tools/qualification/application_startup_diagnostic.py','tools/qualification/application_followup.py','tools/qualification/application_launch.py',
            'skill/runtime/client.py','tests/test_runtime.py','tools/release-hardening/internal.py','tools/release-hardening/another.py')}
        gate={'schema':1,'status':'PASS','source_gate':{'path':'/source','sha256':'1'*64},'extracted_gate':{'path':'/extracted','sha256':'2'*64},'extracted_result':{'path':'/result','sha256':'3'*64},'independent_review':{'path':'/review','sha256':'4'*64}}
        wrapper={'actual_exit':0,'expected_exit':0,'source_stable':True,'source_before':files,'source_after':files,'tests_run':10,'tests_skipped':0}
        archived={name:{'sha256':sha} for name,sha in files.items() if not name.startswith('tools/release-hardening/')}
        if mutate is not None:mutate(archived)
        result={'status':'pass','tests_run':10,'tests_skipped':0,'unit_tests':{'exit_code':0},'source_unchanged':True,'archives_unchanged':True,'extracted_inventory_before':archived,'extracted_inventory_after':archived}
        review={'status':'PASS','unresolved_findings':[],'source_gate':gate['source_gate'],'extracted_gate':gate['extracted_gate'],'extracted_result':gate['extracted_result'],'source_files':files}
        with mock.patch.object(diagnostic,'read',return_value=gate),mock.patch.object(diagnostic.followup,'_reference',side_effect=[wrapper,wrapper,result,review]),mock.patch.object(diagnostic,'inventory',return_value=files),mock.patch.object(diagnostic,'digest',return_value='a'*64),mock.patch.object(diagnostic,'reference',return_value=gate['source_gate']):return diagnostic.source_gate('/gate')
    def test_source_gate_preserves_complete_source_map_with_only_internal_release_tools_unpublished(self):
        self.assertEqual(self.projection_gate()['path'],'/source')
    def test_source_gate_rejects_missing_unrelated_runtime_test_or_dispatch_source(self):
        for path in ('skill/runtime/client.py','tests/test_runtime.py','tools/qualification/application_startup_diagnostic.py'):
            with self.subTest(path=path),self.assertRaises(diagnostic.DiagnosticError):self.projection_gate(lambda archive:archive.pop(path))
    def test_source_gate_rejects_different_published_source_hash(self):
        with self.assertRaises(diagnostic.DiagnosticError):self.projection_gate(lambda archive:archive['tools/qualification/application_followup.py'].update(sha256='b'*64))
    def test_source_gate_rejects_forbidden_release_hardening_content_or_directory_in_archive(self):
        for path in ('tools/release-hardening/internal.py','tools/release-hardening/unknown.py','tools/release-hardening'):
            with self.subTest(path=path),self.assertRaises(diagnostic.DiagnosticError):self.projection_gate(lambda archive:archive.update({path:{'sha256':'a'*64}}))
    def test_complete_source_inventory_includes_all_three_trees_and_refuses_aliases(self):
        for name in ('skill/runtime/client.py','tests/test_one.py','tools/tool.py','tests/__pycache__/cached.pyc','tests/loose.pyc'):
            p=self.root/name;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True);p.write_bytes(b'inert');p.chmod(0o600)
        with mock.patch.object(diagnostic,'REPO',self.root):
            actual=diagnostic.inventory();self.assertEqual(set(actual),{'skill/runtime/client.py','tests/test_one.py','tools/tool.py'})
            extra=self.root/'tools/extra.py';extra.write_bytes(b'extra');extra.chmod(0o600);self.assertIn('tools/extra.py',diagnostic.inventory())
            alias=self.root/'tools/alias.py';alias.symlink_to(extra)
            with self.assertRaises(diagnostic.DiagnosticError):diagnostic.inventory()
    def test_partial_source_map_cannot_claim_a_complete_source_gate(self):
        gate={'schema':1,'status':'PASS','source_gate':{'path':'/source','sha256':'1'*64},'extracted_gate':{'path':'/extracted','sha256':'2'*64},'extracted_result':{'path':'/result','sha256':'3'*64},'independent_review':{'path':'/review','sha256':'4'*64}}
        partial={'tools/qualification/application_startup_diagnostic.py':'a'*64}
        wrapper={'actual_exit':0,'expected_exit':0,'source_stable':True,'source_before':partial,'source_after':partial,'tests_run':1,'tests_skipped':0}
        inv={name:{'sha256':sha} for name,sha in partial.items()};result={'status':'pass','tests_run':1,'tests_skipped':0,'unit_tests':{'exit_code':0},'source_unchanged':True,'archives_unchanged':True,'extracted_inventory_before':inv,'extracted_inventory_after':inv}
        review={'status':'PASS','unresolved_findings':[],'source_gate':gate['source_gate'],'extracted_gate':gate['extracted_gate'],'extracted_result':gate['extracted_result'],'source_files':partial}
        with mock.patch.object(diagnostic,'read',return_value=gate),mock.patch.object(diagnostic.followup,'_reference',side_effect=[wrapper,wrapper,result,review]),mock.patch.object(diagnostic,'inventory',return_value={**partial,'tests/other.py':'b'*64}),self.assertRaises(diagnostic.DiagnosticError):diagnostic.source_gate('/gate')
    def test_digest_and_json_reader_refuse_symlink_and_nonfinite_metadata(self):
        target=self.root/'target.json';target.write_text('{"v":1e9999}');target.chmod(0o600)
        with self.assertRaises(ValueError):diagnostic.read(target)
        alias=self.root/'alias';alias.symlink_to(target)
        with self.assertRaises(OSError):diagnostic.digest(alias)

    def orchestration(self,start_error=False):
        # This disposable fixture models its historical authorization window;
        # real wall time must not expire mocked orchestration after that window.
        monotonic_ticks=iter(diagnostic.followup.prior_successor.STARTED_MONOTONIC+60+i/100 for i in range(1000))
        wall_ticks=iter(diagnostic.followup.prior_successor.STARTED_WALL+60+i/100 for i in range(1000))
        root=self.root/'diagnostic';run=root/'run'
        plan={'application':{'credentials':{'persona':'QUAL_FAKE'}},'stages':[{'id':'participant'}],'plan_sha256':'1'*64}
        grant=object();authority=mock.Mock();authority.grant.return_value=grant
        registry=SimpleNamespace(generation='generation',binding={},root=self.root/'registry',bind_daemon=mock.Mock());registry.root.mkdir(mode=0o700)
        record={'launch_id':'owned','container_id':'c'*64};(registry.root/'owned.json').write_text('{}');(registry.root/'owned.json').chmod(0o600)
        ledger=mock.Mock();ledger.snapshot.return_value={'attempts':76,'participant_segments':0,'live':0,'private_cleanup_pending':0}
        guard=mock.Mock();guard.flush_timings.return_value=[]
        @contextlib.contextmanager
        def lease(*args):yield registry
        @contextlib.contextmanager
        def instrument(*args,**kwargs):yield guard
        def metadata(path):
            return {'authority':{'path':'/inert/auth','sha256':'a'*64},'base':{},'image':{'id':diagnostic.followup.DIAGNOSTIC_IMAGE,'platform':'linux/arm64','capabilities':{'pi':'0.87.1'}}}[str(path)]
        removed=[{'path':str(root/'private'),'device':1,'inode':2,'removed':True}]
        def cleanup(*args):
            args[-1].cleanup();return record,None,removed,None
        with contextlib.ExitStack() as stack:
            patches=[mock.patch.object(diagnostic.time,'monotonic',side_effect=lambda:next(monotonic_ticks)),mock.patch.object(diagnostic.time,'time',side_effect=lambda:next(wall_ticks)),
                mock.patch.object(diagnostic,'ROOT',root),mock.patch.object(diagnostic,'source_gate',return_value={'path':'/gate','sha256':'b'*64}),mock.patch.object(diagnostic,'read',side_effect=metadata),
                mock.patch.object(diagnostic.followup,'_authorization',return_value={}),mock.patch.object(diagnostic,'public_inputs',return_value=(plan,{'runner':{'sha256':'d'*64,'files':{}}},{},{})),
                mock.patch.object(diagnostic.followup,'build_diagnostic_manifest',return_value={'qualification_id':'qual'}),mock.patch.object(diagnostic,'ReviewedAuthority',return_value=authority),
                mock.patch.object(diagnostic,'original_lease',lease),mock.patch.object(diagnostic.followup.DiagnosticLedger,'create',return_value=ledger),mock.patch.object(diagnostic.launch,'instrument',instrument),
                mock.patch.object(diagnostic,'cleanup_native',side_effect=cleanup),mock.patch.object(diagnostic.DiagnosticLab,'command',return_value=subprocess.CompletedProcess([],0,json.dumps({'ID':'3f2581a9-2d2e-46ae-aa44-b5477f9302b2','OSType':'linux','Architecture':'arm64','NCPU':18,'MemTotal':8*1024**3}),'')),
                mock.patch.object(diagnostic.signal,'setitimer'),mock.patch.object(diagnostic.signal,'signal'),mock.patch.object(diagnostic.signal,'getitimer',return_value=(0,0)),mock.patch.object(Path,'read_bytes',return_value=b'Frozen public TASK'),
                mock.patch.object(diagnostic,'reference',side_effect=lambda p:{'path':str(p),'sha256':'f'*64})]
            for patch in patches:stack.enter_context(patch)
            start=stack.enter_context(mock.patch.object(diagnostic.client.OwnedHelper,'start',side_effect=diagnostic.client.ClientError('cleanup_unconfirmed') if start_error else None,return_value=mock.Mock()))
            with mock.patch('builtins.print'):self.assertEqual(diagnostic.execute(SimpleNamespace(source_gate='gate',authority_ref='authority',base_predecessor='base',image_receipt='image')),0)
            terminal=json.loads((root/'terminal.json').read_text())
            self.assertEqual(terminal['diagnostic_outcome'],'startup_failed' if start_error else 'ready');self.assertIsNone(terminal['process_exit_code']);self.assertFalse(terminal['process_exit_code_available'])
            self.assertEqual(terminal['inference_calls'],0);self.assertEqual(terminal['application_requests'],0);self.assertEqual(terminal['participant_segments'],0);self.assertFalse(terminal['real_credentials_used'])
            start.assert_called_once();self.assertNotIn('popen',start.call_args.kwargs);guard.flush_timings.assert_called_once_with(root,kind='startup_diagnostic')
    def test_ready_orchestration_never_activates_launches_pi_or_uses_real_credentials(self):self.orchestration()
    def test_startup_exception_still_runs_one_cleanup_and_explicit_unknown_exit(self):self.orchestration(start_error=True)


if __name__=='__main__':unittest.main()
