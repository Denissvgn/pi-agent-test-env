"""Red-first legacy subject, process and source-derivation regressions."""
import copy
import uuid

from tests.test_application_owner_legacy_support import LegacyContractTests


class LegacyIdentityTests(LegacyContractTests):
    def test_complete_reference_binds_originals_without_modern_witnesses(self):
        fixture = self.build()
        result = self.exercise(fixture)
        self.assertEqual(result['status'], 'eligible_for_native_checks')
        self.assertEqual(result['unresolved'], [])
        command = self.claim(result, 'launcher_execution', fixture.launch_id)
        self.assertEqual(command['class'], 'derived')
        self.assertEqual(command['value']['argv'], fixture.oracle['emission_argv'])
        self.assertEqual(command['value']['cwd'], str(fixture.root))
        self.assertEqual(self.claim(result, 'original_root_custody')['value']['identity'], fixture.original_identity)

    def test_actual_nonzero_controller_and_helper_exits_remain_distinct(self):
        fixture = self.build(exit_code=137)
        result = self.exercise(fixture)
        self.assertEqual(self.claim(result, 'controller_terminal')['value']['actual_exit'], 2)
        self.assertEqual(self.claim(result, 'launcher_terminal', fixture.launch_id)['value']['actual_exit'], 137)
        self.assertEqual(fixture.body('protected-result.json')['status'], 'FAIL')

    def test_metadata_exit_zero_does_not_replace_controller_exit_two(self):
        fixture = self.build()
        fixture.rewrite('controller-context.json', lambda body: body.update(actual_exit=0))
        self.reject(fixture)

    def test_helper_signal_exit_is_preserved(self):
        fixture = self.build(exit_code=-9)
        result = self.exercise(fixture)
        self.assertEqual(self.claim(result, 'launcher_terminal', fixture.launch_id)['value']['actual_exit'], -9)

    def test_each_subject_identity_field_is_exact(self):
        for key in ('registry', 'generation', 'launch_id', 'intent_sha256', 'container_id'):
            with self.subTest(key=key):
                fixture = self.build(key); request = fixture.request()
                request['subject'][key] = str(uuid.uuid4()) if key in ('generation', 'launch_id') else 'f' * 64
                self.reject(fixture, request)

    def test_ledger_binding_must_match_every_original_subject_field(self):
        for key in ('registry', 'generation', 'launch_id', 'container', 'image', 'container_id', 'intent_sha256', 'pid'):
            with self.subTest(key=key):
                fixture = self.build(key)
                def change(body):
                    row = body['launches'][0]
                    row[key] = row[key] - 1 if key == 'pid' else str(uuid.uuid4()) if key in ('generation', 'launch_id') else 'f' * 64
                fixture.rewrite('ledger.json', change); self.reject(fixture)

    def test_daemon_mismatch_is_not_a_metadata_association(self):
        fixture = self.build()
        fixture.rewrite('ledger.json', lambda body: body.update(daemon='another-daemon'))
        self.reject(fixture)

    def test_zero_cid_and_borrowed_related_cid_both_reject(self):
        for variant in ('zero', 'other'):
            with self.subTest(variant=variant):
                fixture = self.build(variant)
                fixture.rewrite('ledger.json', lambda body: body['launches'][0].update(
                    container_id=('0' if variant == 'zero' else 'c') * 64))
                self.reject(fixture)

    def test_missing_guard_cid_cannot_be_repaired_from_another_launch(self):
        fixture = self.build(gap='missing_helper_guard_cid')
        self.reject(fixture)

    def test_worker_terminal_cannot_be_used_as_helper_terminal(self):
        fixture = self.build(gap='interrupted_worker_only')
        self.reject(fixture)

    def test_unconfirmed_or_unknown_child_waits_reject(self):
        for field, value in (('wait_confirmed', False), ('unknown_owned_child', True), ('returncode', None)):
            with self.subTest(field=field):
                fixture = self.build(field)
                fixture.rewrite('launcher-terminal.json', lambda body: body.update({field: value}))
                self.reject(fixture)

    def test_controller_also_requires_an_actual_confirmed_wait(self):
        fixture = self.build()
        fixture.rewrite('controller-verification.json', lambda body: body.update(child_wait_confirmed=False))
        self.reject(fixture)

    def test_pid_ordinal_and_parent_are_independently_bound(self):
        for name, field in (('launcher-terminal.json', 'pid'), ('launcher-terminal.json', 'ordinal'),
                            ('launcher-start.json', 'parent_pid'), ('controller-start.json', 'pid'),
                            ('controller-verification.json', 'wrapper_pid')):
            with self.subTest(name=name, field=field):
                fixture = self.build(name + field)
                fixture.rewrite(name, lambda body: body.update({field: body[field] - 1}))
                self.reject(fixture)

    def test_missing_related_launcher_and_duplicate_rows_reject(self):
        for variant in ('omitted', 'duplicate'):
            with self.subTest(variant=variant):
                fixture = self.build(variant)
                if variant == 'omitted':
                    row = copy.deepcopy(fixture.record); row['launch_id'] = str(uuid.uuid4())
                    row['container'] = 'pi-other-related'; fixture.related.append(row)
                else:
                    fixture.envelope['launchers'].append(copy.deepcopy(fixture.envelope['launchers'][0]))
                    fixture.flush_envelope()
                self.reject(fixture)

    def test_cross_case_controller_reference_cannot_borrow_a_terminal(self):
        first = self.build('first'); other = self.build('other')
        first.envelope['controller']['originals']['terminal'] = other.refs['controller-verification.json']
        first.flush_envelope(); self.reject(first)

    def test_prepared_source_without_executed_binding_rejects(self):
        self.reject(self.build(gap='prepared_command_only'))

    def test_input_source_and_cwd_premises_are_each_required(self):
        for premise in ('input', 'cwd', 'dependency', 'invoker'):
            with self.subTest(premise=premise):
                fixture = self.build(premise)
                if premise == 'input':
                    fixture.rewrite('emission-inputs.json', lambda body: body.update(container='other-container'))
                elif premise == 'cwd':
                    fixture.rewrite('controller-context.json', lambda body: body.pop('cwd'))
                elif premise == 'dependency':
                    fixture.rewrite('source-bindings.json', lambda body: body.update(source_dependencies=[]))
                else:
                    fixture.rewrite('controller-context.json', lambda body: body.update(invoker_sha256='0' * 64))
                self.reject(fixture)

    def test_unrecognized_source_family_is_not_authorized_by_matching_input_hash(self):
        self.reject(self.build(), known_family=False)

    def test_unknown_rule_and_version_do_not_fall_back(self):
        for field, value in (('rule_id', 'owner_supplied_PASS'), ('rule_version', 2), ('rule_version', True)):
            with self.subTest(field=field, value=value):
                fixture = self.build(str(value))
                fixture.envelope['controller'][field] = value; fixture.flush_envelope()
                self.reject(fixture)

    def test_changed_source_bytes_are_not_executed_or_accepted(self):
        fixture = self.build()
        ref = fixture.refs['controller-driver.py']
        with open(ref['path'], 'ab') as output:output.write(b'\nraise RuntimeError("must never execute")\n')
        self.reject(fixture)

    def test_rehashed_arbitrary_source_cannot_create_a_new_trusted_rule(self):
        fixture = self.build()
        fixture.rewrite_bytes('controller-driver.py', b'raise RuntimeError("never execute this source")\n')
        self.reject(fixture)

    def test_explicit_unknowns_cannot_be_omitted_to_make_an_incomplete_history_pass(self):
        fixture = self.build(gap='unconfirmed_wait')
        result = self.exercise(fixture, analyze=True)
        self.assertNotEqual(result['status'], 'eligible_for_native_checks')
        self.assertTrue(result['unresolved'])
        self.reject(fixture)

    def test_new_envelope_cannot_supply_asserted_command_or_original_witness(self):
        for key, value in (('derived_argv', ['docker', 'run']), ('owned_process_invocation', {}), ('accepted', True)):
            with self.subTest(key=key):
                fixture = self.build(key); fixture.envelope[key] = value; fixture.flush_envelope()
                self.reject(fixture)
