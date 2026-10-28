"""Reader and version fences shared by source bytes and JSON evidence."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tests.test_application_owner_legacy_support import LegacyContractTests
import application_owner_cleanup as cleanup


class LegacyReaderTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def put(self, name, data, mode=0o600):
        target = self.root / name; target.write_bytes(data); target.chmod(mode)
        return {'path': str(target), 'sha256': hashlib.sha256(data).hexdigest()}

    def test_source_bytes_are_data_and_share_json_graph_budget(self):
        ref = self.put('source.py', b'raise RuntimeError("source must never run")\n')
        other = self.put('metadata.json', b'{"schema":1}')
        reader = cleanup.Reader()
        self.assertEqual(reader.reference_bytes(ref), Path(ref['path']).read_bytes())
        self.assertEqual(reader.reference(other), {'schema': 1})
        self.assertEqual(reader.bytes, sum(Path(r['path']).stat().st_size for r in (ref, other)))
        self.assertEqual(len(reader.references), 2)

    def test_reusing_bytes_as_json_does_not_reset_limits(self):
        ref = self.put('metadata.json', b'{"schema":1}')
        reader = cleanup.Reader(); reader.reference_bytes(ref); reader.reference(ref)
        self.assertEqual(reader.bytes, len(b'{"schema":1}'))
        self.assertEqual(len(reader.references), 1)

    def test_duplicate_keys_and_every_nonfinite_encoding_reject(self):
        for n, body in enumerate((b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}',
                                  b'{"a":-Infinity}', b'{"a":1e9999}')):
            with self.subTest(body=body):
                ref = self.put(str(n) + '.json', body)
                with self.assertRaises((cleanup.ownership.RegistryError, ValueError)):
                    cleanup.Reader().reference(ref)

    def test_symlink_hardlink_and_writable_source_reject(self):
        for variant in ('symlink', 'hardlink', 'writable'):
            with self.subTest(variant=variant):
                ref = self.put(variant + '.py', b'source bytes')
                p = Path(ref['path'])
                if variant == 'symlink':
                    other = p.with_suffix('.original'); p.rename(other); p.symlink_to(other)
                elif variant == 'hardlink':os.link(p, p.with_suffix('.alias'))
                else:p.chmod(0o666)
                with self.assertRaises((cleanup.ownership.RegistryError, OSError)):
                    cleanup.Reader().reference_bytes(ref)

    def test_private_upgrade_remains_strong_across_byte_and_json_reads(self):
        ref = self.put('public.json', b'{"schema":1}', mode=0o644)
        reader = cleanup.Reader(); reader.reference_bytes(ref)
        with self.assertRaises(cleanup.ownership.RegistryError):
            reader.read_bytes(ref['path'], private=True)
        with self.assertRaises(cleanup.ownership.RegistryError):reader.reference(ref)

    def test_changed_reference_bytes_cannot_reenter_under_same_path(self):
        ref = self.put('source.py', b'one'); reader = cleanup.Reader(); reader.reference_bytes(ref)
        Path(ref['path']).write_bytes(b'two')
        changed = {**ref, 'sha256': hashlib.sha256(b'two').hexdigest()}
        with self.assertRaises(cleanup.ownership.RegistryError):reader.reference_bytes(changed)

    def test_source_and_json_reference_counts_use_one_limit(self):
        first = self.put('first.py', b'x'); second = self.put('second.json', b'{}')
        reader = cleanup.Reader()
        with mock.patch.object(cleanup, 'MAX_REFERENCES', 1):
            reader.reference_bytes(first)
            with self.assertRaises(cleanup.ownership.RegistryError):reader.reference(second)

    def test_source_and_json_bytes_use_one_aggregate_limit(self):
        first = self.put('first.py', b'x'); second = self.put('second.json', b'{}')
        reader = cleanup.Reader()
        with mock.patch.object(cleanup, 'MAX_AGGREGATE_BYTES', 2):
            reader.reference_bytes(first)
            with self.assertRaises(cleanup.ownership.RegistryError):reader.reference(second)

    def test_source_file_limit_is_not_a_json_only_limit(self):
        ref = self.put('source.py', b'1234')
        with mock.patch.object(cleanup, 'MAX_BYTES', 3):
            with self.assertRaises(cleanup.ownership.RegistryError):cleanup.Reader().reference_bytes(ref)

    def test_fixed_reference_source_pins_do_not_depend_on_ast_serialization(self):
        from tests.test_application_owner_legacy_support import AcceptanceFixture
        from tests.test_application_owner_legacy_fixtures import CONTROLLER_SOURCE, EMISSION_SOURCE, SUPERVISOR_SOURCE
        catalog = AcceptanceFixture.family()
        family = catalog[hashlib.sha256(CONTROLLER_SOURCE).hexdigest()]
        self.assertEqual(family['emitter_sha256'], hashlib.sha256(EMISSION_SOURCE).hexdigest())
        self.assertEqual(family['supervisor_sha256'], hashlib.sha256(SUPERVISOR_SOURCE).hexdigest())

    def test_replaced_parent_is_not_the_same_reference_even_with_identical_bytes(self):
        parent = self.root / 'proof'; parent.mkdir(mode=0o700)
        target = parent / 'source.py'; target.write_bytes(b'source bytes'); target.chmod(0o600)
        info = target.stat(); ref = {'path': str(target), 'sha256': hashlib.sha256(target.read_bytes()).hexdigest()}
        original = os.fstat; replaced = [False]
        def replace(fd):
            observed = original(fd)
            if (observed.st_dev, observed.st_ino) == (info.st_dev, info.st_ino) and not replaced[0]:
                parent.rename(self.root / 'moved-proof'); parent.mkdir(mode=0o700)
                target.write_bytes(b'source bytes'); target.chmod(0o600); replaced[0] = True
            return observed
        with mock.patch.object(os, 'fstat', side_effect=replace):
            with self.assertRaises(cleanup.ownership.RegistryError):cleanup.Reader().reference_bytes(ref)
        self.assertTrue(replaced[0])

    def test_private_file_in_readable_parent_needs_explicit_parent_classification(self):
        parent = self.root / 'metadata'; parent.mkdir(mode=0o755); parent.chmod(0o755)
        target = parent / 'record.json'; target.write_bytes(b'{"schema":1}'); target.chmod(0o600)
        ref = {'path': str(target), 'sha256': hashlib.sha256(target.read_bytes()).hexdigest()}
        with self.assertRaises(cleanup.ownership.RegistryError):cleanup.Reader().reference(ref, private=True)
        reader = cleanup.Reader()
        self.assertEqual(reader.reference(ref, private=True, private_parent=False), {'schema': 1})
        target.chmod(0o644)
        with self.assertRaises(cleanup.ownership.RegistryError):reader.reference(ref)

    def test_strict_parent_upgrade_cannot_be_downgraded_after_a_failed_read(self):
        parent = self.root / 'metadata'; parent.mkdir(mode=0o755); parent.chmod(0o755)
        target = parent / 'record.json'; target.write_bytes(b'{"schema":1}'); target.chmod(0o600)
        ref = {'path': str(target), 'sha256': hashlib.sha256(target.read_bytes()).hexdigest()}
        reader = cleanup.Reader(); reader.reference(ref, private=True, private_parent=False)
        with self.assertRaises(cleanup.ownership.RegistryError):reader.reference(ref, private=True)
        with self.assertRaises(cleanup.ownership.RegistryError):reader.reference(ref, private=True, private_parent=False)

    def test_readable_parent_classification_never_allows_other_writers(self):
        parent = self.root / 'metadata'; parent.mkdir(mode=0o755)
        target = parent / 'record.json'; target.write_bytes(b'{"schema":1}'); target.chmod(0o600)
        ref = {'path': str(target), 'sha256': hashlib.sha256(target.read_bytes()).hexdigest()}
        parent.chmod(0o775)
        with self.assertRaises(cleanup.ownership.RegistryError):cleanup.Reader().reference(ref, private=True, private_parent=False)


class LegacyVersionTests(LegacyContractTests):
    def test_unknown_fields_and_bool_versions_reject_at_each_new_boundary(self):
        for boundary in ('request_extra', 'request_bool', 'envelope_extra', 'envelope_bool', 'role_extra'):
            with self.subTest(boundary=boundary):
                fixture = self.build(boundary); request = fixture.request()
                if boundary == 'request_extra':request['approved'] = True
                elif boundary == 'request_bool':request['schema'] = True
                elif boundary == 'envelope_extra':fixture.envelope['operator_passed'] = True
                elif boundary == 'envelope_bool':fixture.envelope['schema'] = True
                else:fixture.envelope['root']['originals']['owner_selected_code'] = fixture.refs['controller-driver.py']
                fixture.flush_envelope(); request['evidence'] = fixture.refs['legacy-evidence.json']
                self.reject(fixture, request)

    def test_unsupported_method_cohort_and_scope_do_not_downgrade(self):
        for key, value in (('method', 'retained_terminals'), ('cohort', 'unknown_cohort'),
                           ('variant', 'any_directory_v1'), ('schema', 3)):
            with self.subTest(key=key):
                fixture = self.build(key); request = fixture.request(); request[key] = value
                self.reject(fixture, request)

    def test_new_envelope_is_not_accepted_by_schema_one_request(self):
        fixture = self.build(); request = fixture.request(); request['schema'] = 1
        self.reject(fixture, request)

    def test_specialized_record_subtypes_keep_their_ordinary_subject_fence(self):
        fixture = self.build()
        for field in ('qualification_role', 'qualification_preworker_cleanup', 'qualification_service_cleanup'):
            with self.subTest(field=field):
                row = dict(fixture.record); row[field] = 'unsupported-retyping'
                with self.assertRaises(cleanup.ownership.RegistryError):cleanup.subject(row)

    def test_canonical_subject_lists_reject_duplicates_instead_of_set_collapsing(self):
        fixture = self.build(); subject = cleanup._resource_subject(fixture.record)
        with self.assertRaises(cleanup.ownership.RegistryError):cleanup._canonical_subjects([subject, subject])
