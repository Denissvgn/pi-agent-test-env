"""Synthetic failed-diagnostic hygiene proofs; no Docker, keys or real sidecar.

The original carry validator alone is injected using the existing followup
fixture. The central diagnostic ledger, strict readers, current Registry files,
retained source archive and negative ownership/clock/proof checks remain real.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools/qualification'),str(ROOT/'skill/scripts'),str(ROOT/'skill/runtime')]
import application_diagnostic_cleanup as cleanup
import application_followup as followup
import application_launch as launch
import test_application_followup as followup_tests


class DiagnosticCleanupTests(unittest.TestCase):
    def patch(self,owner,name,value):
        patch=mock.patch.object(owner,name,value);result=patch.start();self.addCleanup(patch.stop);return result

    def setUp(self):
        self.env=followup_tests.FollowupTests();self.env.setUp();self.addCleanup(self.env.doCleanups)
        e=self.env;self.repo=e.root;self.campaign=self.repo/'reports/application-agent-enhancements/A15/campaign-004'
        self.known=self.campaign/'diagnostic-known-cleanup-001';self.known.mkdir(parents=True,mode=0o700)
        for key,value in [('REPO',self.repo),('CAMPAIGN',self.campaign),('ROOT',e.diag),('KNOWN_ROOT',self.known),
            ('KNOWN_PATH',self.known/'known-cleanup.json'),('REVIEW_PATH',self.known/'independent-review.json')]:self.patch(cleanup,key,value)
        self.patch(Path,'home',lambda:self.repo)
        # Public files are constrained to this disposable report tree.
        e.diag=self.campaign/'startup-diagnostic-001';e.diag.mkdir(mode=0o700)
        self.patch(followup,'DIAGNOSTIC_ROOT',e.diag);self.patch(cleanup,'ROOT',e.diag)
        self.patch(followup,'DIAGNOSTIC_BINDING_ROOT',self.campaign/'diagnostic-claim')
        e.auth['diagnostic_root']=str(e.diag);e.refresh();e.carry['campaign_amendment']=e.ref
        self.policy,self.ledger=e.diagnostic();self.patch(cleanup,'QUALIFICATION_ID',self.policy['qualification_id'])
        self.record=e.record();self.record.update(owner_pid=2147483646,private_store=str(e.diag/'run/application-helpers/owned'))
        self.patch(cleanup,'LAUNCH_ID',self.record['launch_id']);self.network_id='22222222-2222-4222-8222-222222222222';self.patch(cleanup,'NETWORK_ID',self.network_id)
        self.cid='c'*64;self.patch(cleanup,'CONTAINER_ID',self.cid)
        key=self.ledger.reserve(followup.DIAGNOSTIC_CELL,'application-helper',self.record,e.weight,e.daemon)
        self.ledger.dispatch_ready(key);self.ledger.note(key,pid=2147483645,container_id=self.cid,physical='uncertain',poison=True,
            cleanup_request={'effective_target':'immutable_id','operation':'rm','requested_target':'immutable_id'})
        self.record.update(status='absent',container_id=self.cid)
        self.network={'schema':1,'launch_id':self.network_id,'registry':self.record['registry'],'generation':self.record['generation'],
            'kind':'network','status':'released','container':self.record['container']+'-network','daemon':'fixture-daemon','mounts':[],'image':None,'runroot':None}
        self.paths=[{'path':str(p),'absent':True} for p in (e.diag/'private',Path(self.record['private_store']),e.diag/'run/application-evidence'/self.record['container']/'private')]
        marker=e.diag/'run/application-startup/marker.json';marker.parent.mkdir(parents=True,mode=0o700)
        fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as f:f.write(b'{"synthetic":true}')
        info=marker.stat();self.assertEqual(info.st_mtime_ns,info.st_ctime_ns)
        self.patch(cleanup,'MARKER_MTIME_NS',info.st_mtime_ns);self.patch(cleanup,'NETWORK_MTIME_NS',info.st_mtime_ns+26_000_000_000)
        self.patch(cleanup,'NETWORK_CTIME_NS',info.st_mtime_ns+26_100_000_000)
        self.registry=self.repo/'.local/state/pi-agentic-development/operation.lock.registry';self.registry.mkdir(parents=True,mode=0o700)
        helper_before=self.put(self.known/'helper-before.json',self.record)
        helper_after=self.put(self.known/'helper-after.json',{**self.record,'status':'released'})
        network_copy=self.put(self.known/'network.json',self.network)
        current_helper=self.put(self.registry/(self.record['launch_id']+'.json'),{**self.record,'status':'released'})
        current_network=self.put(self.registry/(self.network_id+'.json'),self.network)
        self.observation={'manifest':self.ref(e.diag/'manifest.json'),'raw_ledger_sha256':self.ref(e.diag/'launch-ledger/ledger.json')['sha256'],
            'original_lease_held':True,'cumulative_container_launches':76,'participant_segments':0,'new_container_launches':0,'raw_ledger_unchanged':True,
            'host_pid':2147483645,'host_pid_absent':True,'observed_wall':e.wallnow[0]+140,'private_absence':self.paths,
            'registry_records':[{'path':str(self.registry/(self.record['launch_id']+'.json')),'sha256':helper_before['sha256'],'record':self.record,'mtime_ns':info.st_mtime_ns+20_000_000_000,'ctime_ns':info.st_mtime_ns+20_000_000_000},
                {'path':str(self.registry/(self.network_id+'.json')),'sha256':network_copy['sha256'],'record':self.network,'mtime_ns':cleanup.NETWORK_MTIME_NS,'ctime_ns':cleanup.NETWORK_CTIME_NS}]}
        command={'argv':['python3','-B','tools/qualification/application_startup_diagnostic.py'],'cwd':str(self.repo),'actual_exit':2,'expected_exit':0,
            'started_wall':e.wallnow[0],'elapsed_seconds':55.0}
        self.frozen={'tools/qualification/application_startup_diagnostic.py':b'SYNTHETIC DRIVER', 'tools/qualification/application_launch.py':b'SYNTHETIC GUARD',
            'skill/scripts/application_client.py':b'SYNTHETIC CLIENT','skill/scripts/ownership_registry.py':b'SYNTHETIC REGISTRY'}
        self.patch(cleanup,'FROZEN_SOURCES',{k:hashlib.sha256(v).hexdigest() for k,v in self.frozen.items()})
        archive=self.known/'source.zip'
        with zipfile.ZipFile(archive,'w') as z:
            for name,body in self.frozen.items():z.writestr('pi-agent-test-env-source/'+name,body)
        self.patch(cleanup,'ARCHIVE',archive);self.patch(cleanup,'ARCHIVE_SHA',self.ref(archive)['sha256'])
        timing={'terminal':True,'native_success_attested':False,'deadline_changed':False,'extra_dispatches':0,'runtime_identity_seconds':5,'guard_capture_seconds':5,
            'identity_deadline_already_expired_at_entry':True,'identity_bind_outcome':'raised','identity_bind_remaining_seconds_at_entry':-6.0,
            'identity':{'cell_id':followup.DIAGNOSTIC_CELL,'kind':'startup_diagnostic','launch_id':self.record['launch_id'],'scope_id':self.policy['qualification_id']},
            'source_hashes':{'guard':cleanup.FROZEN_SOURCES['tools/qualification/application_launch.py'],'runtime':cleanup.FROZEN_SOURCES['skill/scripts/application_client.py'],
                'orchestrator':cleanup.FROZEN_SOURCES['tools/qualification/application_startup_diagnostic.py']}}
        refs={'manifest':self.ref(e.diag/'manifest.json'),'ledger':self.ref(e.diag/'launch-ledger/ledger.json'),
            'failure':self.put(e.diag/'failure.json',{'continuation_authorized':False,'diagnostic_outcome':'startup_failed','qualification_eligible':False,'raw_evidence_preserved':True,'schema':1,'status':'BLOCKED'}),
            'timing':self.put(e.diag/'timing.json',timing),'command':self.put(self.campaign/'command.json',command),
            'observation':self.put(self.campaign/'observation.json',self.observation),'claim':self.ref(followup.DIAGNOSTIC_BINDING_ROOT/'claim.json'),'marker':self.ref(marker)}
        self.patch(cleanup,'STATIC',{k:(Path(v['path']),v['sha256']) for k,v in refs.items()})
        program=self.known/'release.py';program.write_text('# SYNTHETIC, NEVER EXECUTED\n')
        source_review=self.put(self.known/'release-source-review.json',{'status':'PASS','unresolved_findings':[],'program':self.ref(program)})
        bounds_review=self.put(self.known/'bounds-review.json',{'status':'PASS','unresolved_findings':[]})
        self.release={'schema':1,'document_type':'qualification_diagnostic_metadata_release','status':'PASS','authorization':e.ref,'qualification_id':self.policy['qualification_id'],
            'program':self.ref(program),'source_review':source_review,'bounds_review':bounds_review,'observation':refs['observation'],'manifest':refs['manifest'],'ledger':refs['ledger'],
            'original_helper_record':helper_before,'released_helper_record':helper_after,'helper_registry_record':current_helper,'released_network_record':network_copy,'network_registry_record':current_network,
            'container_id':self.cid,'host_pid':2147483645,'host_pid_absent':True,'private_absence':self.paths,
            'docker_observations':[{'kind':'daemon','target':'fixture-daemon','exit':0,'stdout':'fixture-daemon\n','stderr':''},
                {'kind':'container','target':self.cid,'exit':1,'stdout':'[]\n','stderr':'Error response from daemon: No such container: '+self.cid+'\n'},
                {'kind':'network','target':self.network['container'],'exit':1,'stdout':'[]\n','stderr':'Error response from daemon: network '+self.network['container']+' not found\n'}],
            'original_lease_held':True,'lease_inode_unchanged':True,'new_container_launches':0,'participant_segments':0,'cumulative_container_launches':76,'resource_mutations':0,'registry_status_changes':1,
            'raw_ledger_preserved':True,'driver_terminal_absent':True,'metadata_only_reporting':True,'elapsed_seconds':2.0,'completed_wall':e.wallnow[0]+150}
        self.value={'schema':1,'document_type':'qualification_failed_startup_diagnostic_known_cleanup','authorization':e.ref,'qualification_id':self.policy['qualification_id'],
            **{k:refs[k] for k in ('manifest','ledger','failure','timing','command','observation')},'metadata_release':{},
            'startup_marker':{**refs['marker'],**cleanup._metadata(info)},'network_record_before':{k:self.observation['registry_records'][1][k] for k in ('path','sha256','mtime_ns','ctime_ns')},
            'driver_status':'BLOCKED','cleanup_accounting':'FAILED','native_success_attested':False,'diagnostic_terminal_absent':True,'raw_ledger_preserved':True}
        e.now[0]+=200;e.wallnow[0]+=200;self.refresh()

    def put(self,path,value):
        return self.env.put(path,value)

    def ref(self,path):
        return {'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}

    def refresh(self):
        self.value['metadata_release']=self.put(self.known/'release.json',self.release)
        known=self.put(cleanup.KNOWN_PATH,self.value)
        self.put(cleanup.REVIEW_PATH,{'schema':1,'status':'PASS','unresolved_findings':[],'known_cleanup':known,
            'validator_sha256':self.ref(Path(cleanup.__file__))['sha256'],'classification':cleanup.REVIEW_CLASSIFICATION})

    def validate(self):
        return cleanup.validate_known_cleanup(self.env.ref,self.env.base,clock=self.env.clock,wall=self.env.wall)

    def test_failed_diagnostic_returns_only_charged_carry_without_rewriting_raw_evidence(self):
        before={k:self.ref(v[0])['sha256'] for k,v in cleanup.STATIC.items()}
        result=self.validate();self.assertEqual((result['attempts'],result['participant_segments'],result['planned_cells'],len(result['lineage'])),(76,0,280,10))
        self.assertEqual(result['startup_diagnostic']['driver_status'],'BLOCKED');self.assertFalse(result['startup_diagnostic']['native_success_attested'])
        self.assertEqual(before,{k:self.ref(v[0])['sha256'] for k,v in cleanup.STATIC.items()});self.assertFalse((cleanup.ROOT/'terminal.json').exists())

    def test_any_existing_terminal_including_invalid_dangling_symlink_denies(self):
        p=cleanup.ROOT/'terminal.json'
        for body in (b'{}',b'invalid'):
            p.write_bytes(body)
            with self.assertRaises(launch.LaunchError):self.validate()
            p.unlink()
        p.symlink_to(cleanup.ROOT/'never-existed')
        with self.assertRaises(launch.LaunchError):self.validate()

    def test_resource_timestamps_must_match_retained_original_metadata(self):
        self.value['network_record_before']['ctime_ns']+=1;self.refresh()
        with self.assertRaises(launch.LaunchError):self.validate()

    def test_thirty_second_resource_bound_is_not_extended(self):
        self.patch(cleanup,'NETWORK_CTIME_NS',cleanup.MARKER_MTIME_NS+30_000_000_000)
        self.value['network_record_before']['ctime_ns']=cleanup.NETWORK_CTIME_NS
        self.observation['registry_records'][1]['ctime_ns']=cleanup.NETWORK_CTIME_NS
        ref=self.put(Path(cleanup.STATIC['observation'][0]),self.observation)
        cleanup.STATIC['observation']=(Path(ref['path']),ref['sha256']);self.value['observation']=ref;self.release['observation']=ref;self.refresh()
        with self.assertRaises(launch.LaunchError):self.validate()

    def test_current_registry_replacement_denies_despite_retained_released_copy(self):
        self.put(Path(self.release['helper_registry_record']['path']),{**self.record,'status':'quarantined'})
        with self.assertRaises(launch.LaunchError):self.validate()

    def test_current_private_reappearance_denies(self):
        p=Path(self.paths[0]['path']);p.mkdir(mode=0o700)
        with self.assertRaises(launch.LaunchError):self.validate()

    def test_current_writer_predicate_reexecutes_on_each_validation(self):
        with mock.patch.object(launch,'_historical_controller_absent',return_value=True) as absent:
            self.validate();self.assertEqual(absent.call_count,2)
            absent.return_value=False
            with self.assertRaises(launch.LaunchError):self.validate()

    def test_pid_reuse_terminal_maps_actual_wrapper_start_without_rewriting_proof(self):
        command_path=Path(cleanup.STATIC['command'][0]);original=command_path.read_bytes();command=json.loads(original)
        with mock.patch.object(launch,'_historical_controller_absent',return_value=True) as absent:
            self.validate();self.assertEqual(absent.call_count,2)
        for call in absent.call_args_list:
            terminal=call.args[1]
            self.assertEqual(terminal['started_at'],command['started_wall'])
            self.assertEqual(terminal['elapsed_seconds'],command['elapsed_seconds'])
            self.assertEqual(terminal['started_at']+terminal['elapsed_seconds'],command['started_wall']+command['elapsed_seconds'])
            self.assertEqual({k:v for k,v in terminal.items() if k!='started_at'},command)
        self.assertEqual(command_path.read_bytes(),original);self.assertNotIn('started_at',command)

    def test_missing_lease_or_added_effect_denies_even_with_fresh_review_hash(self):
        original=copy.deepcopy(self.release)
        for key,value in (('original_lease_held',False),('resource_mutations',1),('new_container_launches',1),('participant_segments',1),('registry_status_changes',2),('metadata_only_reporting',False)):
            self.release={**original,key:value};self.refresh()
            with self.subTest(key=key),self.assertRaises(launch.LaunchError):self.validate()

    def test_foreign_daemon_or_nonabsence_projection_denies(self):
        self.release['docker_observations'][0]['stdout']='foreign\n';self.refresh()
        with self.assertRaises(launch.LaunchError):self.validate()
        self.release['docker_observations'][0]['stdout']='fixture-daemon\n';self.release['docker_observations'][1]['stderr']='permission denied';self.refresh()
        with self.assertRaises(launch.LaunchError):self.validate()

    def test_no_driver_pass_or_accounting_pass_relabel(self):
        for key,value in (('driver_status','PASS'),('cleanup_accounting','PASS'),('native_success_attested',True)):
            old=self.value[key];self.value[key]=value;self.refresh()
            with self.subTest(key=key),self.assertRaises(launch.LaunchError):self.validate()
            self.value[key]=old

    def test_changed_frozen_source_archive_denies(self):
        self.patch(cleanup,'ARCHIVE_SHA','f'*64)
        with self.assertRaises(launch.LaunchError):self.validate()

    def test_changed_metadata_release_program_denies(self):
        Path(self.release['program']['path']).write_text('# DIFFERENT SYNTHETIC PROGRAM\n')
        with self.assertRaises(launch.LaunchError):self.validate()

    def test_extra_diagnostic_row_or_bootstrap_relabel_is_not_a_new_carry(self):
        ledger_path=Path(cleanup.STATIC['ledger'][0]);ledger=json.loads(ledger_path.read_text())
        ledger['launches'].append(copy.deepcopy(ledger['launches'][0]));reference=self.put(ledger_path,ledger)
        cleanup.STATIC['ledger']=(ledger_path,reference['sha256']);self.value['ledger']=reference;self.release['ledger']=reference
        self.observation['raw_ledger_sha256']=reference['sha256'];observation_ref=self.put(Path(cleanup.STATIC['observation'][0]),self.observation)
        cleanup.STATIC['observation']=(Path(observation_ref['path']),observation_ref['sha256']);self.value['observation']=observation_ref;self.release['observation']=observation_ref
        self.refresh()
        with self.assertRaises(launch.LaunchError):self.validate()

    def test_changed_validator_review_and_unknown_fields_deny(self):
        review=json.loads(cleanup.REVIEW_PATH.read_text());review['validator_sha256']='f'*64;self.put(cleanup.REVIEW_PATH,review)
        with self.assertRaises(launch.LaunchError):self.validate()
        self.value['invented_original_private_inodes']=[];self.refresh()
        with self.assertRaises(launch.LaunchError):self.validate()

    def test_clock_regression_or_expired_fixed_window_denies(self):
        self.env.wallnow[0]-=300
        with self.assertRaises(launch.LaunchError):self.validate()
        self.env.wallnow[0]+=300;self.env.current.side_effect=launch.LaunchError('qualification_followup_invalid')
        with self.assertRaises(launch.LaunchError):self.validate()

    def test_public_proofs_reject_duplicate_and_nonfinite_json(self):
        p=self.known/'bad.json'
        for body in (b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":1e9999}'):
            p.write_bytes(body);p.chmod(0o600)
            with self.subTest(body=body),self.assertRaises(launch.LaunchError):cleanup._public(self.ref(p))

    def test_owner_public0644_proofs_and_reviews_are_allowed_without_chmod_history(self):
        for p in (Path(cleanup.STATIC['command'][0]),Path(self.release['source_review']['path']),Path(self.release['bounds_review']['path']),cleanup.KNOWN_PATH,cleanup.REVIEW_PATH):p.chmod(0o644)
        self.assertEqual(self.validate()['attempts'],76)

    def test_public_world_or_group_writable_symlink_and_current_registry0644_deny(self):
        p=self.known/'unsafe.json';self.put(p,{'synthetic':True})
        for mode in (0o622,0o660,0o666):
            p.chmod(mode)
            with self.subTest(mode=mode),self.assertRaises(launch.LaunchError):cleanup._public(self.ref(p))
        p.chmod(0o600);alias=self.known/'alias.json';alias.symlink_to(p)
        with self.assertRaises(OSError):cleanup._public(self.ref(alias))
        Path(self.release['helper_registry_record']['path']).chmod(0o644)
        with self.assertRaises(launch.LaunchError):self.validate()


if __name__=='__main__':unittest.main()
