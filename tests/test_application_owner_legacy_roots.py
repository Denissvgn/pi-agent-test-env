"""Direct root custody tests; pending namespace checks cannot mask failures."""
import copy
import json
from pathlib import Path
import shutil
import uuid
from unittest import mock

from tests.test_application_owner_legacy_support import LegacyContractTests
from tests import test_application_owner_legacy_launchers as launcher_fixtures
import application_owner_cleanup as cleanup


class LegacyRootTests(LegacyContractTests):
    def exercise(self, *args, **kwargs):
        api = __import__('application_owner_legacy')
        selected = {key: value for key, value in api._ADAPTERS.items() if key != 'namespace'}
        with mock.patch.dict(api._ADAPTERS, selected, clear=True):return super().exercise(*args, **kwargs)

    def artifact(self, name='artifact'):
        return launcher_fixtures.LegacyLauncherTests.artifact(self, name)

    def artifact_full(self):
        fixture = launcher_fixtures.LegacyLauncherTests.artifact_children(self)
        old = dict(fixture.refs['diagnostic-terminal.json']); previous = fixture.body('diagnostic-terminal.json')
        document = {'schema': 1, 'document_type': 'bounded_artifact_write_diagnostic_terminal',
            'status': 'PASS', 'scope': 'fixture-owned-files', 'authorization': fixture.refs['authority-observation.json'],
            'claim': fixture.refs['authority-observation.json'], 'cleanup_seconds': 1.0,
            'container_id': fixture.cid, 'credentials': 'none', 'cumulative_container_intents': 1,
            'cumulative_participant_segments': 0, 'disposable_root': str(fixture.private),
            'disposable_root_identity': fixture.original_identity, 'disposable_root_removed': False,
            'elapsed_seconds': 1.0, 'failure_before_positive_cleanup': False, 'finished': 2.0,
            'finished_wall': 3.0, 'historical_failure_cause_established': False, 'inference_calls': 0,
            'inputs': fixture.refs['emission-inputs.json'], 'ledger': fixture.refs['ledger.json'],
            'manifest': fixture.refs['runtime-manifest.json'], 'network': 'none', 'networks_created': 0,
            'new_container_intents': 1, 'new_participants': 0, 'original_lease_held': True,
            'physical_absence_confirmed': True, 'primitive_outcome': 'fixture', 'primitive_qualified': False,
            'prior_container_intents': 0, 'private_cleanup_confirmed': False, 'probe_observation': None,
            'process_receipts': previous['process_receipts'], 'qualification_id': fixture.record['binding']['qualification_id'],
            'raw_ledger_preserved': True, 'registry_record': fixture.refs['primary-record.json'],
            'source_review': fixture.refs['source-bindings.json'], 'started': 1.0, 'started_wall': 2.0,
            'all_owned_host_children_waited': True}
        new = fixture.put_retained('diagnostic-terminal.json', fixture.private.parent / 'terminal.json', document)
        fixture._rebind(old, new)
        return fixture

    def rejects_analysis(self, fixture, request=None):
        with self.assertRaises(cleanup.ownership.RegistryError):self.exercise(fixture, request, analyze=True)

    def test_original_standard_descriptor_supplies_host_identity_without_new_snapshot(self):
        fixture = self.build(); result = self.exercise(fixture, analyze=True)
        claim = self.claim(result, 'original_root_custody')
        self.assertEqual(claim['class'], 'original')
        self.assertEqual(claim['value'], {'variant': 'standard_workspace_v1', 'path': str(fixture.workspace),
            'identity': fixture.original_identity, 'binding': fixture.record['binding']})
        self.assertEqual(result['status'], 'blocked')

    def test_original_typed_snapshot_is_an_alternative_to_a_descriptor(self):
        fixture = self.build()
        witness = fixture.put('original-snapshot.json', {'schema': 1, 'document_type': 'application_owned_snapshot',
            'registry': fixture.record['registry'], 'generation': fixture.record['generation'],
            'runroot': str(fixture.run), 'binding': fixture.record['binding'], 'workspace': str(fixture.workspace),
            'workspace_identity': fixture.original_identity})
        fixture.envelope['root']['originals']['witness'] = witness; fixture.flush_envelope()
        result = self.exercise(fixture, analyze=True)
        self.assertEqual(self.claim(result, 'original_root_custody')['value']['identity'], fixture.original_identity)

    def test_genuine_disposable_identity_remains_a_distinct_scope(self):
        fixture = self.build(scope='diagnostic_disposable'); result = self.exercise(fixture, analyze=True)
        claim = self.claim(result, 'original_root_custody')
        self.assertEqual(claim['class'], 'original')
        self.assertEqual(claim['value']['path'], str(fixture.private))
        self.assertEqual(claim['value']['variant'], 'diagnostic_disposable_v1')
        self.assertNotIn(str(fixture.run), [x['path'] for x in result['roots']])

    def test_missing_standard_identity_cannot_be_filled_with_current_stat(self):
        fixture = self.build(gap='missing_workspace_identity')
        result = self.exercise(fixture, analyze=True)
        self.assertTrue(any(u['obligation'] == 'original_root_custody' for u in result['unresolved']))
        self.assertFalse(any(c['obligation'] == 'original_root_custody' and c['class'] in ('original', 'derived')
                             for c in result['claims']))

    def test_dummy_or_disposable_witness_never_satisfies_standard_workspace(self):
        for kind in ('dummy', 'disposable'):
            with self.subTest(kind=kind):
                fixture = self.build(kind)
                info = fixture.private.stat()
                witness = fixture.put('unrelated-root.json', {'schema': 1,
                    'document_type': 'empty_root' if kind == 'dummy' else 'bounded_artifact_write_diagnostic_terminal',
                    'disposable_root': str(fixture.private), 'disposable_root_identity': [info.st_dev, info.st_ino]})
                fixture.envelope['root']['originals']['witness'] = witness; fixture.flush_envelope()
                result = self.exercise(fixture, analyze=True)
                self.assertTrue(any(u['obligation'] == 'original_root_custody' for u in result['unresolved']))

    def test_present_root_recreation_rejects_without_deleting_either_directory(self):
        fixture = self.build(); saved = fixture.root / 'original-workspace'
        fixture.workspace.rename(saved); fixture.workspace.mkdir(mode=0o700)
        self.rejects_analysis(fixture); self.assertTrue(saved.is_dir()); self.assertTrue(fixture.workspace.is_dir())

    def test_absence_preserves_original_identity_instead_of_inventing_one(self):
        fixture = self.build(); shutil.rmtree(fixture.workspace)
        result = self.exercise(fixture, analyze=True)
        self.assertEqual(self.claim(result, 'original_root_custody')['value']['identity'], fixture.original_identity)
        observation = next(o for o in result['roots'] if o['path'] == str(fixture.workspace))
        self.assertEqual(observation, {'path': str(fixture.workspace), 'identity': None, 'state': 'absent'})

    def test_descriptor_binding_path_and_identity_types_are_exact(self):
        for field, value in (('run_id', str(uuid.uuid4())), ('attempt_id', str(uuid.uuid4())),
                              ('workspace', '/synthetic/another-root'), ('workspace_identity', [0, True])):
            with self.subTest(field=field):
                fixture = self.build(field); fixture.rewrite('descriptor.json', lambda body: body.update({field: value}))
                self.rejects_analysis(fixture)

    def test_descriptor_from_another_run_cannot_be_copied_into_this_proof(self):
        first = self.build('first'); second = self.build('second')
        first.envelope['root']['originals']['witness'] = second.refs['descriptor.json']; first.flush_envelope()
        self.rejects_analysis(first)

    def test_container_or_other_host_inode_is_not_this_root(self):
        fixture = self.build(); info = fixture.private.stat()
        fixture.rewrite('descriptor.json', lambda body: body.update(workspace_identity=[info.st_dev, info.st_ino]))
        self.rejects_analysis(fixture)

    def test_exact_mount_set_is_independent_of_original_list_order(self):
        fixture = self.build()
        fixture.record['mounts'].reverse(); fixture.envelope['subject'] = cleanup.subject(fixture.record); fixture.flush_envelope()
        api = __import__('application_owner_legacy')
        from unittest import mock
        with mock.patch.dict(api._ADAPTERS, {'root': api._root}, clear=True):result = self.exercise(fixture, analyze=True)
        self.assertEqual(self.claim(result, 'mount_scope')['value'], fixture.record['mounts'])
        self.assertEqual(fixture.record['mounts'][-1]['target'], '/opt/pi-application')

    def test_mount_duplicates_or_changed_access_are_not_admitted(self):
        for kind in ('duplicate', 'code_writable', 'outside'):
            with self.subTest(kind=kind):
                fixture = self.build(kind)
                # Isolate the root adapter from earlier immutable-intent checks.
                if kind == 'duplicate':fixture.record['mounts'][1] = copy.deepcopy(fixture.record['mounts'][0])
                elif kind == 'code_writable':fixture.record['mounts'][0]['rw'] = True
                else:fixture.record['mounts'][1]['source'] = str(fixture.root)
                fixture.envelope['subject'] = cleanup.subject(fixture.record); fixture.flush_envelope()
                api = __import__('application_owner_legacy')
                from unittest import mock
                with mock.patch.dict(api._ADAPTERS, {'root': api._root}, clear=True):self.rejects_analysis(fixture)

    def test_missing_selected_guard_remains_unresolved_even_with_valid_workspace(self):
        fixture = self.build(gap='missing_helper_guard_cid'); result = self.exercise(fixture, analyze=True)
        self.assertEqual(self.claim(result, 'original_root_custody')['class'], 'original')
        self.assertTrue(any(u['obligation'] == 'helper_guard_identity' for u in result['unresolved']))

    def test_artifact_scope_uses_disposable_child_and_protects_shared_campaign(self):
        fixture = self.artifact_full()
        result = self.exercise(fixture, analyze=True)
        root = self.claim(result, 'original_root_custody')['value']
        self.assertEqual(root['path'], str(fixture.private))
        self.assertEqual(result['root_plan']['retained_root'], str(fixture.private.parent))
        self.assertEqual([o['path'] for o in result['roots']], [str(fixture.private)])

    def test_original_metadata_bytes_remain_unchanged_while_scopes_are_planned(self):
        fixture = self.build(); before = fixture.bytes_snapshot(); self.exercise(fixture, analyze=True)
        self.assertEqual(fixture.bytes_snapshot(), before)
        self.assertFalse(fixture.body('protected-result.json')['cleanup_confirmed'])

    def test_original_snapshot_cannot_be_inside_its_discarded_workspace(self):
        fixture = self.build()
        witness = fixture.put_retained('unsafe-snapshot.json', fixture.workspace / 'snapshot.json',
            {'schema': 1, 'document_type': 'application_owned_snapshot', 'registry': fixture.record['registry'],
             'generation': fixture.record['generation'], 'runroot': str(fixture.run), 'binding': fixture.record['binding'],
             'workspace': str(fixture.workspace), 'workspace_identity': fixture.original_identity})
        fixture.envelope['root']['originals']['witness'] = witness; fixture.flush_envelope()
        self.rejects_analysis(fixture); self.assertTrue(Path(witness['path']).is_file())

    def test_removed_diagnostic_root_cannot_reappear_even_with_same_reported_identity(self):
        fixture = self.build(scope='diagnostic_disposable')
        fixture.rewrite('diagnostic-terminal.json', lambda body: body.update(disposable_root_removed=True))
        self.rejects_analysis(fixture)

    def test_real_retained_guard_can_bind_missing_primary_cid_without_borrowing(self):
        fixture = self.build(scope='diagnostic_disposable'); fixture.record.pop('container_id')
        fixture.envelope['subject'] = cleanup.subject(fixture.record); fixture.flush_envelope()
        result = self.exercise(fixture, analyze=True)
        self.assertEqual(self.claim(result, 'helper_guard_identity', fixture.launch_id)['value']['container_id'], fixture.cid)
        self.assertEqual(self.claim(result, 'original_root_custody')['class'], 'original')

    def test_diagnostic_witness_cid_must_match_its_own_guard(self):
        fixture = self.build(scope='diagnostic_disposable')
        fixture.rewrite('diagnostic-terminal.json', lambda body: body.update(container_id='c' * 64))
        self.rejects_analysis(fixture)
