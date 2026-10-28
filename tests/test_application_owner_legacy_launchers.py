"""Launcher predicates tested directly before any cleanup/lifecycle support."""
import copy
import importlib
import uuid
from pathlib import Path

from tests.test_application_owner_legacy_support import LegacyContractTests
from tests import test_application_owner_legacy_controller as controller_fixtures
import application_owner_cleanup as cleanup

original_digest = controller_fixtures.original_digest


def artifact_base_command(fixture, uid=0, gid=0):
    # Data template from the retained producer format, independent of the
    # consumer's construction function. It never executes a container.
    command = ['docker', 'run', '--pull=never', '--interactive', '--name', '{name}', '--init',
        '--platform', 'linux/arm64', '--read-only', '--user', '{uid}:{gid}', '--cap-drop=ALL',
        '--security-opt=no-new-privileges=true', '--ipc=none', '--pids-limit', '128', '--memory', '512m',
        '--memory-swap', '512m', '--cpus', '1.0', '--network', 'none', '--entrypoint=python3',
        '--workdir=/pi-client/state', '--env', 'PYTHONDONTWRITEBYTECODE=1', '--env', 'PYTHONUNBUFFERED=1',
        '--env', 'HOME=/pi-client/state/private/home', '--env', 'TMPDIR=/pi-client/state/private/tmp',
        '--mount', 'type=bind,src={root}/code,dst=/opt/pi-application,readonly,bind-recursive=disabled',
        '--mount', 'type=bind,src={root}/evidence,dst=/pi-client/evidence,bind-recursive=disabled',
        '--mount', 'type=bind,src={root}/state,dst=/pi-client/state,bind-recursive=disabled',
        '{image}', '/opt/pi-application/runtime/application_client_service.py']
    return [value.format(name=fixture.record['container'], root=fixture.private,
                         image=fixture.record['image'], uid=uid, gid=gid) for value in command]


class LegacyLauncherTests(LegacyContractTests):
    def artifact(self, name='artifact'):
        fixture = controller_fixtures.LegacyControllerTests.artifact(self, name)
        command = artifact_base_command(fixture)
        fixture.rewrite('runtime-manifest.json', lambda body: body.update(command=command))
        manifest = fixture.body('runtime-manifest.json')
        base = fixture.body('ledger.json')['launches'][0]
        row = {**base, 'cell': 'fixture-cell', 'cleanup_requests': [], 'key': 'fixture-key',
               'launch_policy': 'explicit_pull_never_owned_id_5s', 'physical': 'absent',
               'resources': {'cpu_millis': 1000, 'memory_mib': 512, 'pids_limit': 128}, 'role': 'application-helper'}
        ledger = {'schema': 1, 'daemon': fixture.record['daemon'], 'daemon_capacity': {},
            'deadline': 90.0, 'deadline_wall': 92.0, 'last_now': 3.0, 'last_wall': 4.0,
            'launches': [row], 'manifest_sha256': original_digest(manifest), 'poisoned': True,
            'started': 1.0, 'started_wall': 2.0}
        fixture.rewrite('ledger.json', lambda body: (body.clear(), body.update(ledger)))
        return fixture

    def artifact_children(self, name='artifact'):
        fixture = self.artifact(name); root = fixture.private.parent
        for kind in ('start', 'terminal'):
            name = 'launcher-' + kind + '.json'; old = dict(fixture.refs[name]); body = fixture.body(name); body['ordinal'] = 2
            new = fixture.put_retained(name, root / ('process-002-' + kind + '.json'), body); fixture._rebind(old, new)
        metadata_start = fixture.put_retained('metadata-start.json', root / 'process-001-start.json',
            {'schema': 1, 'ordinal': 1, 'kind': 'owned_docker_metadata_or_cleanup_cli', 'pid': fixture.launcher_pid - 10,
             'started_monotonic': 1.0, 'started_wall': 2.0})
        metadata_terminal = fixture.put_retained('metadata-terminal.json', root / 'process-001-terminal.json',
            {'schema': 1, 'ordinal': 1, 'pid': fixture.launcher_pid - 10, 'returncode': 0,
             'wait_confirmed': True, 'unknown_owned_child': False, 'failure_class': None})
        last_start = fixture.put_retained('metadata-last-start.json', root / 'process-003-start.json',
            {'schema': 1, 'ordinal': 3, 'kind': 'owned_docker_metadata_or_cleanup_cli', 'pid': fixture.launcher_pid - 11,
             'started_monotonic': 1.0, 'started_wall': 2.0})
        last_terminal = fixture.put_retained('metadata-last-terminal.json', root / 'process-003-terminal.json',
            {'schema': 1, 'ordinal': 3, 'pid': fixture.launcher_pid - 11, 'returncode': 0,
             'wait_confirmed': True, 'unknown_owned_child': False, 'failure_class': None})
        witness = fixture.body('diagnostic-terminal.json')
        witness.update(document_type='bounded_artifact_write_diagnostic_terminal',
            inputs=fixture.refs['emission-inputs.json'], source_review=fixture.refs['source-bindings.json'],
            ledger=fixture.refs['ledger.json'], qualification_id=fixture.record['binding']['qualification_id'],
            all_owned_host_children_waited=True, process_receipts=[{'start': metadata_start, 'terminal': metadata_terminal},
                {'start': fixture.refs['launcher-start.json'], 'terminal': fixture.refs['launcher-terminal.json']},
                {'start': last_start, 'terminal': last_terminal}])
        fixture.rewrite('diagnostic-terminal.json', lambda body: (body.clear(), body.update(witness)))
        return fixture

    def reject_analysis(self, fixture):
        with self.assertRaises(cleanup.ownership.RegistryError):self.exercise(fixture, analyze=True)

    def test_original_ledger_and_wait_bind_derived_command_without_new_witnesses(self):
        fixture = self.build(); result = self.exercise(fixture, analyze=True)
        command = self.claim(result, 'launcher_execution', fixture.launch_id)
        self.assertEqual(command['class'], 'derived')
        self.assertEqual(command['value']['argv'], fixture.oracle['emission_argv'])
        self.assertEqual(command['value']['cwd'], str(fixture.root))
        self.assertEqual(command['value']['parent_pid'], fixture.owner_pid)
        self.assertEqual(self.claim(result, 'helper_guard_identity', fixture.launch_id)['value']['container_id'], fixture.cid)
        self.assertEqual(result['status'], 'blocked')

    def test_actual_helper_exits_zero_137_and_signal_stay_distinct(self):
        for code in (0, 137, -9):
            with self.subTest(code=code):
                fixture = self.build(str(code), exit_code=code); result = self.exercise(fixture, analyze=True)
                terminal = self.claim(result, 'launcher_terminal', fixture.launch_id)
                self.assertEqual(terminal['class'], 'original'); self.assertEqual(terminal['value']['actual_exit'], code)
                self.assertEqual(self.claim(result, 'controller_terminal')['value']['actual_exit'], 0 if code == 0 else 2)

    def test_source_mapped_controller_exit_cannot_be_falsely_zero_for_failed_helper(self):
        fixture = self.build(exit_code=137)
        fixture.rewrite('controller-context.json', lambda body: body.update(actual_exit=0))
        fixture.rewrite('controller-verification.json', lambda body: body.update(actual_exit=0))
        self.reject_analysis(fixture)

    def test_pid_parent_and_ordinal_mismatches_reject_in_analysis(self):
        for n, (name, key) in enumerate((('launcher-start.json', 'parent_pid'), ('launcher-terminal.json', 'ordinal'),
                                        ('launcher-terminal.json', 'pid'))):
            with self.subTest(name=name, key=key):
                fixture = self.build(str(n)); fixture.rewrite(name, lambda body: body.update({key: body[key] - 1}))
                self.reject_analysis(fixture)

    def test_each_selected_ledger_binding_is_validated(self):
        for key in ('registry', 'generation', 'container', 'image', 'container_id', 'intent_sha256', 'pid'):
            with self.subTest(key=key):
                fixture = self.build(key)
                def change(body):
                    body['launches'][0][key] = fixture.launcher_pid - 1 if key == 'pid' else 'f' * 64
                fixture.rewrite('ledger.json', change); self.reject_analysis(fixture)

    def test_unknown_wait_or_unknown_owned_child_cannot_discharge_terminal(self):
        for field, value in (('wait_confirmed', False), ('unknown_owned_child', True)):
            with self.subTest(field=field):
                fixture = self.build(field)
                fixture.rewrite('launcher-terminal.json', lambda body: body.update({field: value}))
                result = self.exercise(fixture, analyze=True)
                self.assertEqual(self.claim(result, 'launcher_terminal', fixture.launch_id)['class'], 'candidate')
                self.assertTrue(any(u['obligation'] == 'launcher_terminal' for u in result['unresolved']))

    def test_null_returncode_with_confirmed_wait_is_a_contradiction(self):
        fixture = self.build()
        fixture.rewrite('launcher-terminal.json', lambda body: body.update(returncode=None))
        self.reject_analysis(fixture)

    def test_absent_selected_guard_row_never_borrows_another_cid(self):
        fixture = self.build(gap='missing_helper_guard_cid'); result = self.exercise(fixture, analyze=True)
        self.assertFalse(any(c['obligation'] == 'helper_guard_identity' for c in result['claims']))
        self.assertTrue(any(u['obligation'] == 'helper_guard_identity' for u in result['unresolved']))

    def test_zero_cid_and_duplicate_rows_are_not_identity_evidence(self):
        for variant in ('zero', 'duplicate', 'extra'):
            with self.subTest(variant=variant):
                fixture = self.build(variant)
                def change(body):
                    if variant == 'zero':body['launches'][0]['container_id'] = '0' * 64
                    else:
                        row = copy.deepcopy(body['launches'][0])
                        if variant == 'extra':row['launch_id'] = str(uuid.uuid4())
                        body['launches'].append(row)
                fixture.rewrite('ledger.json', change); self.reject_analysis(fixture)

    def test_source_identity_cannot_be_replaced_only_for_one_launcher(self):
        first = self.build('first'); other = self.build('other')
        first.envelope['launchers'][0]['originals']['producer'] = other.refs['controller-driver.py']
        first.flush_envelope(); self.reject_analysis(first)

    def test_worker_only_interruption_has_no_helper_terminal_or_guard_fact(self):
        fixture = self.build(gap='interrupted_worker_only')
        self.reject_analysis(fixture)

    def test_artifact_command_includes_actual_client_labels_and_guard_options(self):
        fixture = self.artifact(); result = self.exercise(fixture, analyze=True)
        expected = artifact_base_command(fixture)
        labels = ['--label', cleanup.ownership.LABEL + '=' + fixture.launch_id,
                  '--label', cleanup.ownership.REGISTRY_LABEL + '=' + fixture.record['registry']]
        plan = result['launchers'][0]
        self.assertEqual(plan['argv'], expected[:2] + labels + expected[2:])
        self.assertEqual(plan['argv'].count('--pull=never'), 1)
        self.assertIsNone(plan['cwd']); self.assertEqual(plan['argv_basis'], 'source_bound_post_guard')
        self.assertEqual(self.claim(result, 'launcher_execution', fixture.launch_id)['class'], 'candidate')
        self.assertEqual(self.claim(result, 'launcher_terminal', fixture.launch_id)['class'], 'original')

    def test_prepared_artifact_command_changed_before_dispatch_is_rejected(self):
        fixture = self.artifact()
        fixture.rewrite('runtime-manifest.json', lambda body: body['command'].insert(2, '--privileged'))
        fixture.rewrite('ledger.json', lambda body: body.update(manifest_sha256=original_digest(fixture.body('runtime-manifest.json'))))
        self.reject_analysis(fixture)

    def test_worker_kind_cannot_satisfy_artifact_container_launcher(self):
        fixture = self.artifact()
        fixture.rewrite('launcher-start.json', lambda body: body.update(kind='worker'))
        self.reject_analysis(fixture)

    def test_historical_qualification_hash_excludes_only_its_typed_attachments(self):
        api = importlib.import_module('application_owner_legacy_launchers'); fixture = self.build()
        qualified = {**fixture.record, 'client_mode': 'qualification-fixture', 'qualification_role': 'fixture'}
        before = api.historical_intent(qualified)
        qualified['qualification_service_cleanup'] = {'path': '/synthetic/proof.json', 'sha256': 'a' * 64}
        self.assertEqual(api.historical_intent(qualified), before)
        qualified['image'] = 'sha256:' + 'b' * 64
        self.assertNotEqual(api.historical_intent(qualified), before)
        wrong = {**fixture.record, 'qualification_role': 'fixture'}
        with self.assertRaises(cleanup.ownership.RegistryError):api.historical_intent(wrong)

    def test_preworker_hash_domain_does_not_accept_mixed_service_retyping(self):
        api = importlib.import_module('application_owner_legacy_launchers'); fixture = self.build()
        row = {**fixture.record, 'qualification_preworker_cleanup': {'path': '/synthetic/old.json', 'sha256': 'a' * 64}}
        before = api.historical_intent(row)
        row['qualification_preworker_cleanup'] = {'path': '/synthetic/later.json', 'sha256': 'b' * 64}
        self.assertEqual(api.historical_intent(row), before)
        row['qualification_role'] = 'fixture'
        with self.assertRaises(cleanup.ownership.RegistryError):api.historical_intent(row)

    def test_artifact_source_cannot_be_retyped_as_another_client_mode(self):
        fixture = self.artifact(); fixture.record['client_mode'] = 'authority-only'
        fixture.envelope['subject'] = cleanup.subject(fixture.record); fixture.flush_envelope()
        changed = original_digest({k: v for k, v in fixture.record.items() if k not in ('status', 'container_id')})
        fixture.rewrite('ledger.json', lambda body: body['launches'][0].update(intent_sha256=changed))
        self.reject_analysis(fixture)

    def test_historical_ordinary_intent_keeps_unicode_and_original_bytes(self):
        api = importlib.import_module('application_owner_legacy_launchers'); fixture = self.build('fixture-λ')
        expected = original_digest({k: v for k, v in fixture.record.items() if k not in ('status', 'container_id')})
        self.assertEqual(api.historical_intent(fixture.record), expected)
        self.assertNotEqual(expected, cleanup.subject(fixture.record)['intent_sha256'])

    def test_all_metadata_children_are_bound_before_scoped_wait_closure(self):
        fixture = self.artifact_children(); result = self.exercise(fixture, analyze=True)
        self.assertEqual(len(result['owned_processes']), 3)
        self.assertEqual(self.claim(result, 'scoped_writers')['class'], 'derived')
        self.assertEqual(self.claim(result, 'scoped_writers')['value']['pids'],
                         sorted([fixture.owner_pid, fixture.launcher_pid, fixture.launcher_pid - 10, fixture.launcher_pid - 11]))

    def test_omitted_or_reordered_metadata_child_cannot_hide_in_retained_root(self):
        for variant in ('omitted', 'reordered'):
            with self.subTest(variant=variant):
                fixture = self.artifact_children(variant)
                def change(body):
                    if variant == 'omitted':body['process_receipts'].pop()
                    else:body['process_receipts'].reverse()
                fixture.rewrite('diagnostic-terminal.json', change); self.reject_analysis(fixture)

    def test_unknown_wait_in_metadata_child_is_not_helper_cleanup_success(self):
        fixture = self.artifact_children()
        fixture.rewrite('metadata-terminal.json', lambda body: body.update(wait_confirmed=False, unknown_owned_child=True))
        self.reject_analysis(fixture)

    def test_claim_replacement_does_not_treat_related_subject_list_as_launcher(self):
        fixture = self.build(); result = self.exercise(fixture, analyze=True)
        self.assertEqual(self.claim(result, 'related_closure')['class'], 'candidate')
        self.assertEqual(self.claim(result, 'launcher_execution', fixture.launch_id)['class'], 'derived')

    def test_fixture_mutation_preserves_retained_path_and_changes_that_original(self):
        fixture = self.artifact(); before = Path(fixture.refs['runtime-manifest.json']['path'])
        fixture.rewrite('runtime-manifest.json', lambda body: body.update(planned_container_launches=2))
        self.assertEqual(Path(fixture.refs['runtime-manifest.json']['path']), before)
        self.assertEqual(fixture.body('runtime-manifest.json')['planned_container_launches'], 2)
