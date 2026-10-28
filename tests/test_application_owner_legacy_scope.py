"""Red-first scope, retained namespace and authority regressions."""
import copy
from pathlib import Path
import shutil
from types import SimpleNamespace
import uuid

from tests.test_application_owner_legacy_support import LegacyContractTests
import application_owner_cleanup as cleanup


class LegacyScopeTests(LegacyContractTests):
    def test_disposable_host_identity_has_its_own_supported_scope(self):
        fixture = self.build(scope='diagnostic_disposable', exit_code=0)
        result = self.exercise(fixture)
        root = self.claim(result, 'original_root_custody')
        self.assertEqual(root['value']['variant'], 'diagnostic_disposable_v1')
        self.assertEqual(root['value']['path'], str(fixture.private))
        self.assertEqual(root['value']['identity'], fixture.original_identity)
        self.assertFalse(any(item['path'] == str(fixture.run) for item in result['roots']))

    def test_disposable_identity_cannot_be_retyped_as_standard_workspace(self):
        fixture = self.build(scope='diagnostic_disposable')
        fixture.envelope['variant'] = 'standard_workspace_v1'
        fixture.envelope['root']['rule_id'] = 'standard_workspace_v1'
        fixture.flush_envelope(); request = fixture.request(); request['variant'] = 'standard_workspace_v1'
        self.reject(fixture, request)

    def test_helper_or_dummy_identity_cannot_fill_missing_original_workspace(self):
        fixture = self.build(gap='missing_workspace_identity')
        identity = fixture.private.stat()
        witness = fixture.put('dummy-root.json', {'schema': 1, 'document_type': 'empty_root',
            'path': str(fixture.private), 'identity': [identity.st_dev, identity.st_ino]})
        fixture.envelope['root']['originals']['witness'] = witness; fixture.flush_envelope()
        self.reject(fixture)

    def test_present_root_identity_must_match_original_host_witness(self):
        fixture = self.build()
        fixture.workspace.rename(fixture.root / 'saved-original-workspace')
        fixture.workspace.mkdir(mode=0o700)
        self.reject(fixture)

    def test_already_absent_root_still_uses_original_identity(self):
        fixture = self.build(); shutil.rmtree(fixture.workspace)
        result = self.exercise(fixture)
        self.assertEqual(self.claim(result, 'original_root_custody')['value']['identity'], fixture.original_identity)

    def test_container_side_inode_or_other_host_directory_is_not_original_scope(self):
        fixture = self.build()
        other = fixture.private.stat()
        fixture.rewrite('descriptor.json', lambda body: body.update(workspace_identity=[other.st_dev, other.st_ino]))
        self.reject(fixture)

    def test_symlink_and_lexical_aliases_do_not_expand_runroot_authority(self):
        for alias in ('lexical', 'symlink'):
            with self.subTest(alias=alias):
                fixture = self.build(alias)
                if alias == 'lexical':
                    fixture.record['runroot'] = str(fixture.run) + '/.'
                else:
                    link = fixture.root / 'run-alias'; link.symlink_to(fixture.run, target_is_directory=True)
                    fixture.record['runroot'] = str(link)
                self.reject(fixture)

    def test_unrelated_parent_root_is_never_added_by_a_discard_request(self):
        fixture = self.build(); unrelated = fixture.root / 'unrelated-campaign'; unrelated.mkdir(mode=0o700)
        sentinel = unrelated / 'sentinel'; sentinel.write_text('must be retained')
        request = fixture.request(); request['extra_private_roots'] = [{
            'path': str(unrelated), 'origin': fixture.refs['controller-context.json']}]
        self.reject(fixture, request); self.assertEqual(sentinel.read_text(), 'must be retained')

    def test_exact_mount_topology_rejects_duplicates_and_permission_changes(self):
        for variant in ('duplicate', 'code_writable', 'wrong_source'):
            with self.subTest(variant=variant):
                fixture = self.build(variant)
                if variant == 'duplicate':fixture.record['mounts'][1] = copy.deepcopy(fixture.record['mounts'][0])
                elif variant == 'code_writable':fixture.record['mounts'][0]['rw'] = True
                else:fixture.record['mounts'][1]['source'] = str(fixture.root)
                self.reject(fixture)

    def test_readonly_foreign_holder_blocks_disposable_scope(self):
        fixture = self.build(scope='diagnostic_disposable')
        other = {'launch_id': str(uuid.uuid4()), 'status': 'running',
            'runroot': str(fixture.root / 'other'),
            'mounts': [{'source': str(fixture.private), 'target': '/readonly', 'rw': False}]}
        registry = SimpleNamespace(load=lambda: [*fixture.related, other])
        roots = [{'path': str(fixture.private), 'identity': fixture.original_identity, 'state': 'present'}]
        before = fixture.bytes_snapshot()
        with self.assertRaises(cleanup.ownership.RegistryError):
            cleanup._no_foreign_holders(registry, fixture.record, fixture.related, cleanup.Reader(), roots)
        self.assertEqual(fixture.bytes_snapshot(), before)

    def test_orphan_controls_and_unreviewed_retained_payloads_block(self):
        for gap in ('orphan_controls', 'unknown_retained_namespace'):
            with self.subTest(gap=gap):self.reject(self.build(gap, gap=gap))

    def test_prepared_agent_descriptor_cannot_hide_missing_actual_process_metadata(self):
        fixture = self.build()
        Path(fixture.refs['process.json']['path']).unlink()
        self.reject(fixture)

    def test_required_original_metadata_is_protected_without_regrading(self):
        fixture = self.build(); result = self.exercise(fixture)
        preserved = {ref['path'] for ref in result['metadata']}
        for key in ('descriptor.json', 'stage-state.json', 'stage-credentials.json', 'process.json', 'protected-result.json'):
            self.assertIn(fixture.refs[key]['path'], preserved)
        self.assertFalse(fixture.body('stage-credentials.json').get('cleanup_confirmed', False))
        self.assertEqual(fixture.body('protected-result.json')['status'], 'FAIL')

    def test_issued_contexts_need_explicit_supported_revocation_closure(self):
        fixture = self.build()
        fixture.rewrite('authority-observation.json', lambda body: body.update(
            issued_contexts=[{'id': str(uuid.uuid4()), 'revoked': False}], external_authority='issued'))
        self.reject(fixture)

    def test_partial_redaction_or_secret_scan_is_not_namespace_authority(self):
        fixture = self.build(gap='unknown_retained_namespace')
        fixture.envelope['namespace']['scan_passed'] = True
        fixture.envelope['namespace']['known_secret_count'] = 1
        fixture.flush_envelope(); self.reject(fixture)

    def test_historical_pass_from_a_different_scope_cannot_certify_namespace(self):
        fixture = self.build()
        scoped_pass = fixture.put('historical-scoped-pass.json', {'schema': 1, 'status': 'PASS',
            'scope': 'unrelated-dummy-root', 'private_leaf_reads_or_hashes': False})
        fixture.envelope['namespace']['originals']['authority'] = scoped_pass
        fixture.flush_envelope(); self.reject(fixture)

    def test_specialized_related_proof_cannot_be_retyped_as_ordinary(self):
        self.reject(self.build(gap='specialized_related_unvalidated'))

    def test_diagnostic_scope_does_not_claim_participant_agent_execution(self):
        fixture = self.build(scope='diagnostic_disposable')
        request = fixture.request(); request['shape'] = 'agent'; request['stages'] = [str(uuid.uuid4())]
        self.reject(fixture, request)
