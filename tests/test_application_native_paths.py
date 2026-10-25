"""Application child roots with real isolated HTTP service, mocked Docker only.

No native container, Pi/model, application endpoint or real credential is used.
The ownership/image/cgroup observations are controlled boundary fixtures.
"""
import copy
import json
import os
from pathlib import Path
import stat
import sys
import types
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_client as client
import application_execution as execution
from native_budget_service import private_root
from tool_budgets import BudgetError
import test_application_client_authority as lifecycle
import test_application_execution_authority as authority_fixture
import test_application_execution as coordinator_fixture
import test_native_budget_client as budget_fixture


class ApplicationNativePathTests(unittest.TestCase):
    def setUp(self):
        self.fixture=authority_fixture.ReviewedAuthorityTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.root,self.runroot=self.fixture.root,self.fixture.runroot
    def launch(self,authority,boundary):
        return lifecycle.OwnedLifecycleTests.launch(self,authority=authority,boundary=boundary)
    def test_application_bootstrap_private_children_exist_before_popen_and_are_used_by_real_service(self):
        authority,grant,_=self.fixture.pinned();boundary=lifecycle.DockerBoundary();capture={};bootstrap=authority._bootstrap
        def capture_bootstrap(*args,**kwargs):
            raw=bootstrap(*args,**kwargs);capture['configuration']=client.c.loads(raw);return raw
        delegate=boundary.popen
        def before_popen(argv,**kwargs):
            config=capture['configuration'];self.assertEqual(config['state_root'],'/pi-client/state/private')
            self.assertEqual(config['authority']['evidence_root'],'/pi-client/evidence/private')
            self.assertEqual(config['outputs_root'],'/pi-client/evidence/private/outputs')
            mounts={}
            for index,argument in enumerate(argv):
                if argument=='--mount':
                    parts=dict(piece.split('=',1) for piece in argv[index+1].split(',') if '=' in piece);mounts[parts['dst']]=Path(parts['src'])
            for target in ('/pi-client/state','/pi-client/evidence'):
                parent=mounts[target];child=parent/'private';info=child.lstat()
                self.assertTrue(stat.S_ISDIR(info.st_mode));self.assertEqual(info.st_uid,os.getuid());self.assertEqual(stat.S_IMODE(info.st_mode),0o700)
                self.assertEqual(list(child.iterdir()),[])
            self.assertIn('HOME=/pi-client/state/private/home',argv);self.assertIn('TMPDIR=/pi-client/state/private/tmp',argv)
            capture['prelaunch_verified']=True;return delegate(argv,**kwargs)
        boundary.popen=before_popen
        with mock.patch.object(authority,'_bootstrap',side_effect=capture_bootstrap):helper,boundary,registry,pool=self.launch(authority,boundary)
        self.assertTrue(capture['prelaunch_verified']);self.assertEqual(helper.state_data_root,helper.state_root/'private')
        self.assertEqual(helper.evidence_data_root,helper.evidence_root/'private')
        actual_mounts={mount['target']:Path(mount['source']) for mount in helper.record['mounts']}
        self.assertEqual(actual_mounts['/pi-client/state'],helper.state_root);self.assertEqual(actual_mounts['/pi-client/evidence'],helper.evidence_root)
        status=client._request('127.0.0.1',helper.host_port,'/ipc',grant.capability,{'schema':1,'action':'status','scope':grant.scope,'operation_id':None})
        self.assertEqual(status['participant'],self.fixture.plan['stages'][0]['participant']);self.assertFalse(status['business_effects_enabled'])
        for field,value in [('actor_id','foreign-actor'),('team_id','foreign-team'),('role','foreign-role')]:
            scope=copy.deepcopy(grant.scope);scope['participant'][field]=value
            with self.subTest(field=field),self.assertRaises(client.ClientError):
                client._request('127.0.0.1',helper.host_port,'/ipc',grant.capability,{'schema':1,'action':'status','scope':scope,'operation_id':None})
        activated=execution.helper_control(helper,{'schema':1,'action':'activate','capability':grant.capability,'remaining_seconds':120})
        self.assertTrue(all(value==0 for value in activated['budget']['counts'].values()))
        finished=execution.helper_control(helper,{'schema':1,'action':'finish','writers_confirmed':True});self.assertEqual(finished['receipts'],{})
        self.assertTrue(all(value==0 for value in finished['budget']['counts'].values()))
        marker=helper.evidence_data_root/'retained-component-marker.txt';marker.write_text('public component fixture\n')
        wrapper=helper.evidence_root;state_wrapper=helper.state_root;private=helper.private_root
        receipt=helper.cleanup(writers_absent=True)
        self.assertEqual(receipt['evidence_root'],str(wrapper));self.assertTrue(receipt['safe_to_continue']);self.assertEqual(receipt['evidence'],'retained')
        self.assertTrue(marker.exists());self.assertFalse(private.exists());self.assertFalse(state_wrapper.exists())
        self.assertTrue(all(record['status']=='released' for record in registry.load()))
    def test_private_root_predicate_rejects_mapped_public_mount_root_without_relaxing_child(self):
        parent=self.root/'mapped-root';parent.mkdir(mode=0o700);child=parent/'private';child.mkdir(mode=0o700)
        identity=(parent.stat().st_dev,parent.stat().st_ino);real=os.fstat
        def mapped_root(fd):
            info=real(fd)
            if (info.st_dev,info.st_ino)==identity:
                return types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFDIR|0o755)
            return info
        with mock.patch('native_budget_service.os.fstat',side_effect=mapped_root):
            with self.assertRaises(BudgetError):private_root(str(parent))
            self.assertEqual(private_root(str(child)),child)
        child.chmod(0o755)
        with self.assertRaises(BudgetError):private_root(str(child))
    def test_authority_only_mode_preserves_original_mount_root_protocol(self):
        authority,grant=self.fixture.authority();boundary=lifecycle.DockerBoundary();capture={};bootstrap=authority._bootstrap
        def record(*args,**kwargs):
            raw=bootstrap(*args,**kwargs);capture.update(client.c.loads(raw));return raw
        with mock.patch.object(authority,'_bootstrap',side_effect=record):helper,_,_,_=self.launch(authority,boundary)
        self.assertEqual(capture['evidence_root'],'/pi-client/evidence');self.assertNotIn('state_root',capture)
        self.assertEqual(helper.evidence_data_root,helper.evidence_root);self.assertEqual(helper.state_data_root,helper.state_root)
        self.assertFalse((helper.state_root/'private').exists());self.assertFalse((helper.evidence_root/'private').exists())
        self.assertFalse(any('/private/home' in item or '/private/tmp' in item for item in boundary.argv))
    def test_budget_only_mode_preserves_original_state_and_evidence_roots(self):
        fixture=budget_fixture.NativeBudgetClientTests();fixture.setUp();self.addCleanup(fixture.doCleanups);helper=fixture.launch()
        config=json.loads(fixture.lab.bootstrap);self.assertEqual(config['state_root'],'/pi-client/state');self.assertEqual(config['evidence_root'],'/pi-client/evidence')
        self.assertEqual(helper.state_data_root,helper.state_root);self.assertEqual(helper.evidence_data_root,helper.evidence_root)
        self.assertFalse((helper.state_root/'private').exists());self.assertFalse((helper.evidence_root/'private').exists())
        self.assertFalse(any('/private/home' in item or '/private/tmp' in item for item in fixture.lab.argv))


class CoordinatorDataRootTests(unittest.TestCase):
    def test_independent_completion_uses_private_data_children_not_wrapper_paths(self):
        fixture=coordinator_fixture.ApplicationCoordinatorTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        coordinator=fixture.prepare();segment,folder,reply=fixture.begin(coordinator);helper=fixture.helpers[0]
        self.assertEqual(helper.evidence_data_root,helper.evidence_root/'private')
        coordinator.mark_running();coordinator.after_segment(True);cleanup=coordinator.close(True)
        self.assertTrue(cleanup['safe_to_continue']);context=coordinator.completion_context
        self.assertEqual(context['evidence_root'],str(helper.evidence_data_root/'raw'));self.assertEqual(context['report_root'],str(helper.evidence_data_root/'outputs'))
        self.assertNotEqual(context['evidence_root'],str(helper.evidence_root/'raw'));self.assertEqual(context['authorized_segment_ids'],[segment])
        self.assertEqual(context['parent_receipts'],{});self.assertFalse((folder/'application-context.json').exists())

if __name__=='__main__':unittest.main()
