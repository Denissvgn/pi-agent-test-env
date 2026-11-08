"""Consumer-owned approval is required before provider or historical file IO."""
import copy
import hashlib
import json
from unittest import TestCase, mock

from tools.qualification import application_owner_consumer_policy as policy


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def example_policy():
    launch = '12345678-1234-4234-8234-123456789abc'
    registry = '/owner/original.lock.registry'
    files = {'SKILL.md': 'a' * 64, 'MANIFEST.sha256': 'b' * 64,
             'scripts/application_owner_cleanup.py': 'c' * 64,
             'assets/application-owner-reader-v1.json': 'd' * 64}
    binding = {'contract_id': 'application_owner_legacy_reader_1',
               'contract_version': 1, 'method': 'legacy_derived_v1',
               'cohort': 'application_owner_legacy_1',
               'variant': 'diagnostic_disposable_v1', 'scope': 'owned_host_files_only'}
    grants = []
    for role, path in (
        ('anchor', registry + '.owner-selected/' + launch + '.json'),
        ('index', registry + '.owner-proofs/' + launch + '.json'),
        ('selection', registry + '.owner-proofs/selected/' + launch + '.json'),
    ):
        grants.append({'path': path, 'role': role, 'sha256': None,
                       'maximum_bytes': 4194304, 'private': True, 'private_parent': True})
    return {'schema': 1, 'document_type': 'application_owner_consumer_policy',
            'capabilities': ['origins', 'replay'],
            'binding': binding,
            'subject': {'registry': hashlib.sha256(registry.encode()).hexdigest(),
                        'generation': '87654321-4321-4321-8321-cba987654321',
                        'launch_id': launch, 'intent_sha256': 'e' * 64,
                        'container_id': 'f' * 64},
            'provider': {'root': '/approved/provider', 'files': files,
                         'inventory_sha256': digest(files)},
            'consumer': {'files': {name: 'a' * 64 for name in (
                'application_owner_consumer_policy.py', 'application_owner_consumer.py',
                'application_owner_consumer_worker.py')},
                'python_sha256': 'b' * 64, 'python_version': [3, 14, 5]},
            'lease': {'path': '/owner/original.lock', 'identity': [7, 11]},
            'read_scope': {'registry': registry, 'store': registry + '.owner-proofs',
                           'anchor': registry + '.owner-selected',
                           'files': sorted(grants, key=lambda row: (row['path'], row['role'])),
                           'registry_records': [],
                           'directories': sorted([registry, registry + '.owner-proofs',
                               registry + '.owner-proofs/selected', registry + '.owner-selected']),
                           'absent_paths': ['/owner/disposable']}}


def selection(value):
    return {'binding': copy.deepcopy(value['binding']), 'subject': copy.deepcopy(value['subject']),
            'provider_inventory_sha256': value['provider']['inventory_sha256']}


class ConsumerPolicyTests(TestCase):
    def compile(self, value, requested=None, pin=None):
        return policy.compile_policy(value, trusted_policy_sha256=digest(value) if pin is None else pin,
                                     selection=selection(value) if requested is None else requested)

    def test_valid_compilation_is_pure_and_does_not_consult_provider_or_history(self):
        value = example_policy()
        with (mock.patch('builtins.open', side_effect=AssertionError('pre-import file read')),
              mock.patch('os.open', side_effect=AssertionError('pre-import FD read')),
              mock.patch('os.stat', side_effect=AssertionError('pre-import stat'))):
            approved = self.compile(value)
        self.assertEqual(approved.policy_sha256, digest(value))
        self.assertEqual(approved.to_wire(), value)

    def test_origin_only_approval_has_no_invented_subject_lease_or_read_authority(self):
        value=example_policy();value.update(capabilities=['origins'],subject=None,lease=None,read_scope=None)
        with mock.patch('os.open',side_effect=AssertionError('origin policy IO')):
            approved=self.compile(value)
        self.assertEqual(approved.files,());self.assertIsNone(approved.to_wire()['read_scope'])
        for field in ('subject','lease','read_scope'):
            changed=copy.deepcopy(value);changed[field]=example_policy()[field]
            with self.subTest(field=field),self.assertRaises(policy.PolicyError):self.compile(changed)

    def test_missing_trusted_pin_cannot_be_supplied_by_a_receipt_or_approval_flag(self):
        for pin in (None, '', '0' * 64, 'b' * 64, True):
            with self.subTest(pin=pin), self.assertRaises(policy.PolicyError):
                policy.compile_policy(example_policy(), trusted_policy_sha256=pin,
                                      selection=selection(example_policy()))
        value = example_policy(); value['approved'] = True
        with self.assertRaises(policy.PolicyError):self.compile(value)

    def test_each_requested_binding_and_subject_is_exact_before_any_io(self):
        value = example_policy()
        requests = []
        for field in value['binding']:
            changed = selection(value); changed['binding'][field] = 'unsupported'
            requests.append(changed)
        for field in value['subject']:
            changed = selection(value); changed['subject'][field] = 'unrelated'
            requests.append(changed)
        changed = selection(value); changed['provider_inventory_sha256'] = 'b' * 64
        requests.append(changed)
        for requested in requests:
            with self.subTest(requested=requested), mock.patch('os.open', side_effect=AssertionError('IO')):
                with self.assertRaises(policy.PolicyError):self.compile(value, requested)

    def test_mutation_after_compilation_cannot_change_approved_scope(self):
        value = example_policy(); approved = self.compile(value)
        saved = approved.to_wire()
        value['provider']['files'].clear(); value['read_scope']['files'].clear()
        value['subject']['container_id'] = 'a' * 64
        exposed = approved.to_wire(); exposed['provider']['root'] = '/other'
        self.assertEqual(approved.to_wire(), saved)
        with self.assertRaises((AttributeError, TypeError)):approved.policy_sha256 = 'b' * 64

    def test_reused_path_keeps_strongest_privacy_parent_and_smallest_role_limit(self):
        value = example_policy(); path = '/owner/metadata/empty'
        rows = [dict(path=path, role='source', sha256='c' * 64, maximum_bytes=4096,
                     private=False, private_parent=False),
                dict(path=path, role='empty_metadata', sha256='c' * 64, maximum_bytes=0,
                     private=True, private_parent=True)]
        for declarations in (rows, list(reversed(rows))):
            trial = copy.deepcopy(value); trial['read_scope']['files'] += declarations
            trial['read_scope']['files'].sort(key=lambda row: (row['path'], row['role']))
            grant = self.compile(trial).file_grant(path)
            self.assertEqual((grant.maximum_bytes, grant.private, grant.private_parent), (0, True, True))

    def observer_policy(self):
        value = example_policy()
        value['read_scope']['files'].append(dict(
            path='/owner/command/root-tool-terminal.json', role='artifact_tool_observation',
            sha256='c' * 64, maximum_bytes=16384, private=False, private_parent=True))
        value['read_scope']['files'].sort(key=lambda row: (row['path'], row['role']))
        return value

    def test_exact_artifact_observer_has_a_distinct_bounded_public_file_role(self):
        value = self.observer_policy()
        with mock.patch('os.open', side_effect=AssertionError('pure compiler performed IO')):
            approved = self.compile(value)
        grant = approved.file_grant('/owner/command/root-tool-terminal.json')
        self.assertEqual(grant.roles, ('artifact_tool_observation',))
        self.assertEqual((grant.private, grant.private_parent, grant.maximum_bytes), (False, True, 16384))

    def test_artifact_observer_role_does_not_open_generic_public_metadata(self):
        for field, replacement in (
                ('path', '/owner/command/other.json'), ('sha256', None),
                ('maximum_bytes', 16385), ('maximum_bytes', 0),
                ('private', True), ('private_parent', False), ('role', 'original_metadata')):
            value = self.observer_policy()
            row = next(row for row in value['read_scope']['files'] if row['role'] == 'artifact_tool_observation')
            row[field] = replacement
            value['read_scope']['files'].sort(key=lambda row: (row['path'], row['role']))
            with self.subTest(field=field, replacement=replacement), self.assertRaises(policy.PolicyError):
                self.compile(value)
        value = self.observer_policy(); value['binding']['variant'] = 'standard_workspace_v1'
        with self.assertRaises(policy.PolicyError):self.compile(value)

    def test_observer_overlap_keeps_stricter_privacy_and_the_smallest_limit(self):
        value = self.observer_policy()
        value['read_scope']['files'].append(dict(
            path='/owner/command/root-tool-terminal.json', role='original_metadata',
            sha256='c' * 64, maximum_bytes=1024, private=True, private_parent=True))
        value['read_scope']['files'].sort(key=lambda row: (row['path'], row['role']))
        grant = self.compile(value).file_grant('/owner/command/root-tool-terminal.json')
        self.assertTrue(grant.private); self.assertTrue(grant.private_parent)
        self.assertEqual(grant.maximum_bytes, 1024)

    def test_conflicting_reused_hash_and_duplicate_role_do_not_broaden_scope(self):
        value = example_policy(); row = value['read_scope']['files'][0]
        for changed in ({**row}, {**row, 'role': 'source', 'sha256': 'a' * 64}):
            trial = copy.deepcopy(value); trial['read_scope']['files'].append(changed)
            trial['read_scope']['files'].sort(key=lambda item: (item['path'], item['role']))
            with self.subTest(changed=changed), self.assertRaises(policy.PolicyError):self.compile(trial)

    def test_absent_permission_does_not_grant_payload_access_or_unknown_paths(self):
        approved = self.compile(example_policy())
        self.assertIsNone(approved.file_grant(example_policy()['read_scope']['files'][0]['path']).sha256)
        with self.assertRaises(policy.PolicyError):approved.file_grant('/owner/credentials')

    def test_independent_anchor_and_original_namespaces_are_mandatory(self):
        for key in ('registry', 'store', 'anchor'):
            value = example_policy(); value['read_scope'][key] = '/other/' + key
            with self.subTest(key=key), self.assertRaises(policy.PolicyError):self.compile(value)
        for role in ('anchor', 'index', 'selection'):
            value = example_policy(); value['read_scope']['files'] = [r for r in value['read_scope']['files'] if r['role'] != role]
            with self.subTest(role=role), self.assertRaises(policy.PolicyError):self.compile(value)

    def test_invalid_types_unknown_fields_versions_and_paths_fail_closed(self):
        changes = [('schema', True), ('schema', 2), ('extra', 'approval'),
                   ('binding.contract_version', True), ('binding.method', 'other'),
                   ('binding.cohort', 'other'), ('binding.variant', 'other'),
                   ('binding.scope', 'integration_qualification'),
                   ('subject.container_id', '0' * 64), ('lease.identity', [True, 1]),
                   ('provider.root', '/approved/../provider'), ('provider.root', '/'),
                   ('provider.root', '/approved//provider'),
                   ('read_scope.absent_paths', ['/owner']),
                   ('consumer.python_version', [3, 9, 1]),
                   ('consumer.python_version', (3, 14, 5))]
        for dotted, changed in changes:
            value = example_policy(); parent = value
            parts = dotted.split('.')
            for field in parts[:-1]:parent = parent[field]
            parent[parts[-1]] = changed
            with self.subTest(field=dotted), self.assertRaises(policy.PolicyError):self.compile(value)

    def test_complete_provider_inventory_and_canonical_identity_are_bound(self):
        for name in ('SKILL.md', 'MANIFEST.sha256', 'scripts/application_owner_cleanup.py',
                     'assets/application-owner-reader-v1.json'):
            value = example_policy(); del value['provider']['files'][name]
            value['provider']['inventory_sha256'] = digest(value['provider']['files'])
            with self.subTest(name=name), self.assertRaises(policy.PolicyError):self.compile(value)
        for name in ('../outside.py', '/outside.py', 'scripts//bad.py', 'scripts/./bad.py', '__pycache__/bad.pyc'):
            value = example_policy(); value['provider']['files'][name] = 'a' * 64
            value['provider']['inventory_sha256'] = digest(value['provider']['files'])
            with self.subTest(name=name), self.assertRaises(policy.PolicyError):self.compile(value)
        value = example_policy(); value['provider']['files']['scripts/helper.py'] = 'a' * 64
        with self.assertRaises(policy.PolicyError):self.compile(value)

    def test_file_limits_and_primitive_only_inputs_are_not_coerced(self):
        for field, changed in (('maximum_bytes', True), ('maximum_bytes', -1),
                               ('maximum_bytes', 4194305), ('private', 1),
                               ('private_parent', 0), ('role', 'credentials'),
                               ('sha256', float('nan'))):
            value = example_policy(); value['read_scope']['files'][0][field] = changed
            with self.subTest(field=field), self.assertRaises(policy.PolicyError):
                self.compile(value, pin='a' * 64 if field == 'sha256' else None)
        value = example_policy(); value['read_scope']['files'][0]['private'] = False
        with self.assertRaises(policy.PolicyError):self.compile(value)
