"""Literal registration observations; these tests perform no store operation."""
from unittest import TestCase, mock

from tools.qualification import secret_registration_contract as contract


def expectations():
    return dict(expected_operation_id='12345678-1234-4234-8234-123456789abc',
                expected_context_sha256='a' * 64,
                expected_value_contract='application_credential_1',
                expected_value_utf8_bytes=16,
                owned_fd_tokens=('store_duplicate', 'ancestor:0', 'value'),
                max_mutating_calls=32, max_owned_fds=8)


def successful_worker():
    calls = []
    for kind, token, attempted, confirmed in (
        ('temp_create', None, None, None),
        ('write', 'value', 16, 5), ('write', 'value', 11, 11),
        ('file_fsync', None, None, None), ('link', None, None, None),
        ('temp_unlink', None, None, None), ('directory_fsync', None, None, None),
        ('fd_close', 'value', None, None),
        ('fd_close', 'ancestor:0', None, None),
        ('fd_close', 'store_duplicate', None, None),
    ):
        calls.append(dict(ordinal=len(calls) + 1, kind=kind, state='confirmed',
                          fd_token=token, attempted_bytes=attempted, confirmed_bytes=confirmed))
    return dict(schema=1, document_type='secret_registration_worker_observation',
                operation_id=expectations()['expected_operation_id'],
                context_binding_sha256='a' * 64, value_contract='application_credential_1',
                outcome='created', reason='ok', phase='ack_ready', calls=calls,
                trace_complete=True, effects='leaf_only', file_persistence='confirmed',
                directory_persistence='confirmed', final_verified=True,
                owned_fd_closure='confirmed', ack_ready=True, admission_authorized=False)


def receiver():
    return dict(schema=1, document_type='secret_registration_receiver_observation',
                operation_id=expectations()['expected_operation_id'], context_binding_sha256='a' * 64,
                dispatch_started=True, worker_result=successful_worker(), frame_complete=True,
                request_and_origin_verified=True, current_namespace_verified=True,
                ack_state='verified', accepted=True, admission_authorized=False)


def evidence():
    return dict(dispatch_started=True, frame_complete=True,
                request_and_origin_verified=True, current_namespace_verified=True)


class RegistrationContractTests(TestCase):
    def validate(self, value, **overrides):
        return contract.validate_worker(value, **{**expectations(), **overrides})

    def reject(self, value, **overrides):
        with self.assertRaises(contract.TraceError) as caught:
            self.validate(value, **overrides)
        self.assertNotIn('12345678', str(caught.exception))

    def test_complete_partial_write_trace_is_pure_and_never_operational_approval(self):
        with (mock.patch('os.open', side_effect=AssertionError('native IO')),
              mock.patch('builtins.open', side_effect=AssertionError('file IO'))):
            result = self.validate(successful_worker())
        self.assertTrue(result.ack_ready)
        self.assertFalse(result.operational_authorized)
        self.assertFalse(hasattr(result, 'accepted'))

    def test_exact_integer_types_and_closed_fields(self):
        mutations = [('schema', True), ('schema', 1.0), ('admission_authorized', 0),
                     ('ack_ready', 1), ('trace_complete', 1), ('extra', True)]
        for name, value in mutations:
            document = successful_worker(); document[name] = value
            with self.subTest(name=name): self.reject(document)
        for name, value in [('ordinal', True), ('attempted_bytes', 16.0), ('confirmed_bytes', True)]:
            document = successful_worker(); document['calls'][1][name] = value
            with self.subTest(name=name): self.reject(document)

    def test_independent_operation_context_and_value_contract_cannot_be_self_approved(self):
        for name, value in [('operation_id', '87654321-4321-4321-8321-cba987654321'),
                            ('context_binding_sha256', 'b' * 64),
                            ('value_contract', 'normalized_secret_1')]:
            document = successful_worker(); document[name] = value
            with self.subTest(name=name): self.reject(document)
        for name in ('operation_id', 'context_binding_sha256'):
            document = successful_worker(); document[name] += '\n'
            self.reject(document)

    def test_ordinals_kind_order_duplicate_and_missing_business_steps(self):
        for mutation in ('ordinal', 'swap', 'duplicate', 'omit'):
            document = successful_worker()
            if mutation == 'ordinal': document['calls'][1]['ordinal'] = 1
            elif mutation == 'swap': document['calls'][3]['kind'] = 'link'
            elif mutation == 'duplicate': document['calls'][4]['kind'] = 'file_fsync'
            else: document['calls'].pop(4)
            with self.subTest(mutation=mutation): self.reject(document)

    def test_write_counts_match_each_request_and_total_before_sync(self):
        for index, name, value in [(1, 'confirmed_bytes', 17), (1, 'confirmed_bytes', 0),
                                   (2, 'attempted_bytes', 16), (2, 'confirmed_bytes', 10),
                                   (2, 'confirmed_bytes', -1)]:
            document = successful_worker(); document['calls'][index][name] = value
            with self.subTest(index=index, name=name, value=value): self.reject(document)

    def test_unknown_or_no_effect_call_cannot_be_followed_by_business_effect(self):
        for state in ('attempted', 'unknown', 'no_effect'):
            document = successful_worker(); document['calls'][4]['state'] = state
            self.reject(document)

    def test_unknown_link_keeps_namespace_unknown_and_only_closes_remaining_fds(self):
        document = successful_worker()
        document['calls'] = document['calls'][:5] + document['calls'][7:]
        document['calls'][4]['state'] = 'unknown'
        for i, row in enumerate(document['calls'], 1): row['ordinal'] = i
        document.update(outcome='uncertain', reason='io_error', phase='fd_close',
                        effects='unknown', directory_persistence='not_started',
                        final_verified=False, ack_ready=False)
        self.assertFalse(self.validate(document).ack_ready)
        document['effects'] = 'temp_only'; self.reject(document)

    def test_zero_write_is_terminal_and_does_not_spin_or_claim_sync(self):
        document = successful_worker()
        document['calls'] = document['calls'][:2] + document['calls'][7:]
        document['calls'][1].update(state='no_effect', confirmed_bytes=0)
        for i, row in enumerate(document['calls'], 1): row['ordinal'] = i
        document.update(outcome='blocked', reason='io_error', phase='fd_close', effects='temp_only',
                        file_persistence='not_started', directory_persistence='not_started',
                        final_verified=False, ack_ready=False)
        self.assertFalse(self.validate(document).ack_ready)

    def test_unknown_value_store_and_ancestor_close_never_ack(self):
        for index, persistence in [(7, 'file_persistence'), (8, None), (9, 'directory_persistence')]:
            document = successful_worker(); document['calls'][index]['state'] = 'unknown'
            document.update(outcome='uncertain', reason='owned_fd_close_unconfirmed', phase='fd_close',
                            owned_fd_closure='unknown', ack_ready=False)
            if persistence: document[persistence] = 'unknown'
            with self.subTest(index=index): self.assertFalse(self.validate(document).ack_ready)
            document['ack_ready'] = True; self.reject(document)

    def test_ambiguous_fd_is_never_closed_twice_or_used_for_later_business(self):
        document = successful_worker(); document['calls'][7]['state'] = 'unknown'
        document['calls'][8]['fd_token'] = 'value'
        self.reject(document)
        document = successful_worker(); document['calls'][8]['kind'] = 'file_fsync'
        self.reject(document)

    def test_exact_known_owned_set_excludes_caller_fd_and_requires_all_closes(self):
        for token in ('caller', 'value\n', 'ancestor:0\n', 'store_duplicate\n'):
            document = successful_worker(); document['calls'][8]['fd_token'] = token
            self.reject(document)
        document = successful_worker(); document['calls'].pop()
        self.reject(document)
        self.reject(successful_worker(), owned_fd_tokens=('value', 'store_duplicate'))

    def test_dynamic_call_and_fd_budgets_are_checked_before_trace(self):
        for overrides in (dict(max_mutating_calls=9), dict(max_owned_fds=2),
                          dict(max_mutating_calls=True), dict(expected_value_utf8_bytes=True),
                          dict(owned_fd_tokens=('value', 'value'))):
            self.reject(successful_worker(), **overrides)

    def test_truncated_trace_cannot_claim_no_effect_or_durable_ack(self):
        document = successful_worker()
        document['calls'] = document['calls'][:4]
        document.update(trace_complete=False, outcome='uncertain', reason='observation_incomplete',
                        phase='file_fsync', effects='unknown', file_persistence='unknown',
                        directory_persistence='unknown', final_verified=False,
                        owned_fd_closure='unknown', ack_ready=False)
        self.assertFalse(self.validate(document).ack_ready)
        document['effects'] = 'none'; self.reject(document)

    def test_created_claim_cannot_skip_sync_identity_or_closure(self):
        for field, value in [('file_persistence', 'unknown'), ('directory_persistence', 'not_started'),
                             ('final_verified', False), ('owned_fd_closure', 'unknown'),
                             ('phase', 'file_fsync'), ('effects', 'temp_only'), ('reason', 'io_error')]:
            document = successful_worker(); document[field] = value
            self.reject(document)

    def test_receiver_acceptance_is_separate_and_requires_independent_current_facts(self):
        result = contract.validate_receiver(receiver(), worker_expectations=expectations(), evidence=evidence())
        self.assertTrue(result.accepted)
        self.assertFalse(result.operational_authorized)
        for field in evidence():
            facts = evidence(); facts[field] = False
            with self.subTest(field=field), self.assertRaises(contract.TraceError):
                contract.validate_receiver(receiver(), worker_expectations=expectations(), evidence=facts)

    def test_lost_reply_stays_unreceived_even_when_worker_might_have_created(self):
        document = receiver()
        document.update(worker_result=None, frame_complete=False, request_and_origin_verified=False,
                        current_namespace_verified=False, ack_state='not_received', accepted=False)
        facts = dict(dispatch_started=True, frame_complete=False, request_and_origin_verified=False,
                     current_namespace_verified=False)
        result = contract.validate_receiver(document, worker_expectations=expectations(), evidence=facts)
        self.assertFalse(result.accepted)
        document['worker_result'] = successful_worker()
        with self.assertRaises(contract.TraceError):
            contract.validate_receiver(document, worker_expectations=expectations(), evidence=facts)

    def test_generic_and_application_values_are_distinct_without_trim_or_fingerprints(self):
        self.assertEqual(contract.validate_value('x', 'normalized_secret_1'), 1)
        self.assertEqual(contract.validate_value('é' * 16, 'application_credential_1'), 32)
        for value, selected in [('short', 'application_credential_1'), (' x', 'normalized_secret_1'),
                                ('x\x00', 'normalized_secret_1'), ('x\x7f', 'normalized_secret_1'),
                                ('x\ud800', 'normalized_secret_1'), ('x' * 4097, 'normalized_secret_1')]:
            with self.subTest(selected=selected), self.assertRaises(contract.TraceError):
                contract.validate_value(value, selected)

    def test_failure_prefixes_preserve_observed_namespace_and_sync_facts(self):
        # Literal states immediately after each confirmed business call. Close
        # the independently known owned tokens; no completion/retry is inferred.
        states = [(1, 'temp_only', 'not_started', 'not_started'),
                  (2, 'temp_only', 'not_started', 'not_started'),
                  (3, 'temp_only', 'not_started', 'not_started'),
                  (4, 'temp_only', 'confirmed', 'not_started'),
                  (5, 'leaf_with_temp', 'confirmed', 'not_started'),
                  (6, 'leaf_only', 'confirmed', 'not_started'),
                  (7, 'leaf_only', 'confirmed', 'confirmed')]
        for prefix, effects, file_sync, directory_sync in states:
            document = successful_worker()
            document['calls'] = document['calls'][:prefix] + document['calls'][7:]
            for i, row in enumerate(document['calls'], 1): row['ordinal'] = i
            document.update(outcome='blocked', reason='identity_mismatch', phase='fd_close',
                            effects=effects, file_persistence=file_sync,
                            directory_persistence=directory_sync, final_verified=False, ack_ready=False)
            with self.subTest(prefix=prefix): self.assertFalse(self.validate(document).ack_ready)

    def test_receiver_rejects_impossible_frame_dispatch_and_verification_combinations(self):
        for field in ('dispatch_started', 'frame_complete'):
            document = receiver(); facts = evidence()
            document.update(accepted=False, ack_state='received_unverified')
            document[field] = facts[field] = False
            with self.subTest(field=field), self.assertRaises(contract.TraceError):
                contract.validate_receiver(document, worker_expectations=expectations(), evidence=facts)

    def test_receiver_always_validates_independent_expectations_even_without_a_reply(self):
        document = receiver()
        document.update(worker_result=None, frame_complete=False, request_and_origin_verified=False,
                        current_namespace_verified=False, ack_state='not_received', accepted=False)
        facts = {name: document[name] for name in evidence()}
        invalid = expectations(); invalid['max_owned_fds'] = True
        with self.assertRaises(contract.TraceError):
            contract.validate_receiver(document, worker_expectations=invalid, evidence=facts)

    def test_each_unknown_business_call_stops_with_honest_partial_facts(self):
        states = [(1, 'unknown', 'not_started', 'not_started'),
                  (2, 'temp_only', 'not_started', 'not_started'),
                  (3, 'temp_only', 'not_started', 'not_started'),
                  (4, 'temp_only', 'unknown', 'not_started'),
                  (5, 'unknown', 'confirmed', 'not_started'),
                  (6, 'unknown', 'confirmed', 'not_started'),
                  (7, 'leaf_only', 'confirmed', 'unknown')]
        for prefix, effects, file_sync, directory_sync in states:
            document = successful_worker()
            document['calls'] = document['calls'][:prefix] + document['calls'][7:]
            document['calls'][prefix - 1]['state'] = 'unknown'
            if document['calls'][prefix - 1]['kind'] == 'write':
                document['calls'][prefix - 1]['confirmed_bytes'] = 0
            for i, row in enumerate(document['calls'], 1): row['ordinal'] = i
            document.update(outcome='uncertain', reason='interrupted', phase='fd_close', effects=effects,
                            file_persistence=file_sync, directory_persistence=directory_sync,
                            final_verified=False, ack_ready=False)
            with self.subTest(prefix=prefix): self.assertFalse(self.validate(document).ack_ready)

    def test_preflight_and_exclusive_create_refusals_cannot_acquire_a_value_fd(self):
        document = successful_worker()
        document['calls'] = document['calls'][8:]
        for i, row in enumerate(document['calls'], 1): row['ordinal'] = i
        document.update(outcome='refused', reason='invalid_input', phase='fd_close', effects='none',
                        file_persistence='not_started', directory_persistence='not_started',
                        final_verified=False, ack_ready=False)
        owns = ('ancestor:0', 'store_duplicate')
        self.assertFalse(self.validate(document, owned_fd_tokens=owns).ack_ready)
        document['calls'].insert(0, dict(ordinal=1, kind='temp_create', state='no_effect', fd_token=None,
                                          attempted_bytes=None, confirmed_bytes=None))
        for i, row in enumerate(document['calls'], 1): row['ordinal'] = i
        document['reason'] = 'temp_exists'
        self.assertFalse(self.validate(document, owned_fd_tokens=owns).ack_ready)
        document['calls'].append(dict(ordinal=4, kind='fd_close', state='confirmed', fd_token='value',
                                      attempted_bytes=None, confirmed_bytes=None))
        self.reject(document)

    def test_received_unverified_requires_a_dispatched_complete_worker_observation(self):
        document = receiver()
        document.update(worker_result=None, dispatch_started=False, frame_complete=False,
                        request_and_origin_verified=False, current_namespace_verified=False,
                        ack_state='received_unverified', accepted=False)
        facts = {name: document[name] for name in evidence()}
        with self.assertRaises(contract.TraceError):
            contract.validate_receiver(document, worker_expectations=expectations(), evidence=facts)
        document = receiver(); document.update(ack_state='received_unverified', accepted=False,
                                               current_namespace_verified=False)
        facts = {name: document[name] for name in evidence()}
        self.assertFalse(contract.validate_receiver(document, worker_expectations=expectations(),
                                                    evidence=facts).accepted)

    def test_failure_phase_tracks_last_observed_progress_including_owned_cleanup(self):
        document = successful_worker()
        document.update(outcome='blocked', reason='identity_mismatch', phase='admission',
                        final_verified=False, ack_ready=False)
        self.reject(document)
        document['phase'] = 'fd_close'
        self.assertFalse(self.validate(document).ack_ready)
        document['calls'] = document['calls'][:4]
        document.update(trace_complete=False, outcome='uncertain', reason='observation_incomplete',
                        phase='admission', effects='unknown', file_persistence='unknown',
                        directory_persistence='unknown', owned_fd_closure='unknown')
        self.reject(document)
        document['phase'] = 'file_fsync'
        self.assertFalse(self.validate(document).ack_ready)
