"""Original central ledger against the new typed seven-role route; no Docker."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
import uuid
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools/qualification'), str(ROOT / 'tests')]
from ast_compat import pinned_dump
import application_launch as launch
import application_settlement_controller as controller
import test_application_launch as legacy


def normalize_reviewed_settlement_ledger_ast(node):
    """Undo only the exact reviewed Source048 clock delta on a copied class AST.

    Fixed statement positions intentionally fail if guards disappear, move or
    change. The caller still checks the unchanged legacy249416 fingerprint.
    No generic search/replacement of14400 or other clock code is performed.
    """
    def need(value):
        if not value:raise ValueError('unreviewed_settlement_ledger_AST')
    def same(left,right):return pinned_dump(left)==pinned_dump(right)
    need(isinstance(node,ast.ClassDef)and node.name=='LaunchLedger')
    normalized=copy.deepcopy(node)
    need(len(normalized.body)>2)
    create,validate=normalized.body[1:3]
    need(isinstance(create,ast.FunctionDef)and create.name=='create'
      and isinstance(validate,ast.FunctionDef)and validate.name=='_validate')
    need(len(create.body)==16 and isinstance(create.body[14],ast.Try))
    block=create.body[14];need(len(block.body)==7)
    expected_create=ast.parse("""
if 'settlement_diagnostic' in manifest:
    window=manifest['settlement_diagnostic']['clock']
    if (now<window['started'] or wallnow<window['started_wall']
            or now>=window['deadline']-30 or wallnow>=window['deadline_wall']-30):_deny('qualification_deadline')
    state.update({key:window[key] for key in ('started','deadline','started_wall','deadline_wall')})
""").body[0]
    need(same(block.body[4],expected_create))
    expected_validation=ast.parse("""
duration=900 if 'settlement_diagnostic' in self.manifest else 14400
if state['deadline']!=state['started']+duration or state['deadline_wall']!=state['started_wall']+duration:_deny('qualification_state_invalid')
if 'settlement_diagnostic' in self.manifest:
    window=self.manifest['settlement_diagnostic']['clock']
    if any(state[key]!=window[key] for key in ('started','deadline','started_wall','deadline_wall')):_deny('qualification_state_invalid')
""").body
    need(len(validate.body)==20 and len(expected_validation)==3)
    need(all(same(actual,expected)for actual,expected in zip(validate.body[10:13],expected_validation)))
    # Both additions are proven exact before either is removed/restored.
    del block.body[4]
    validate.body[10:13]=ast.parse("""
if state['deadline']!=state['started']+14400 or state['deadline_wall']!=state['started_wall']+14400:_deny('qualification_state_invalid')
""").body
    return normalized


def policy():
    clock = {'schema': 1, 'authorization_id': str(uuid.uuid4()), 'started': 100., 'deadline': 1000.,
             'started_wall': 200., 'deadline_wall': 1100.}
    return controller.launch_manifest(str(uuid.uuid4()), clock,
        {'path': '/inert/preparation.json', 'sha256': 'a' * 64},
        {'path': '/inert/candidate.json', 'sha256': 'b' * 64})


class SettlementLaunchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.now = 110.; self.wall = 220.; self.manifest = policy()
        self.capacity = {'cpu_millis': 7000, 'memory_mib': 7921}

    def create(self, name='ledger'):
        return launch.LaunchLedger.create(self.root / name, self.manifest, daemon_id='inert-daemon',
            daemon_capacity=self.capacity, clock=lambda: self.now, wall=lambda: self.wall)

    def test_exact_seven_role_route_uses_original_role_weights_and_local_limits(self):
        self.assertEqual(launch.validate_manifest(self.manifest), self.manifest)
        self.assertEqual(launch.effective_limits(self.manifest),
            {'global_seconds': 900, 'cleanup_reserve_seconds': 30, 'container_launch_attempts': 7,
             'live': 4, 'participant_segments': 1})
        self.assertEqual(len(self.manifest['cells']), 1)
        cell = self.manifest['cells'][0]
        self.assertEqual(sum(cell['role_limits'].values()), 7)
        self.assertEqual(launch._role_weight(self.manifest, cell, 'fixture'),
                         {'cpu_millis': 250, 'memory_mib': 128, 'pids_limit': 64})
        self.assertEqual(launch._role_weight(self.manifest, cell, 'application-helper'),
                         {'cpu_millis': 2000, 'memory_mib': 2048, 'pids_limit': 512})

    def test_ledger_uses_exact_shared_clock_without_late_reset(self):
        ledger = self.create()
        state = json.loads((ledger.root / 'ledger.json').read_text())
        self.assertEqual((state['started'], state['deadline'], state['started_wall'], state['deadline_wall']),
                         (100., 1000., 200., 1100.))
        self.assertEqual(state['last_now'], 110.)
        self.assertEqual(state['last_wall'], 220.)
        self.now = 120.; self.wall = 230.
        later = launch.LaunchLedger(ledger.root, self.manifest, clock=lambda: self.now, wall=lambda: self.wall)
        self.assertEqual(json.loads((later.root / 'ledger.json').read_text())['deadline'], 1000.)

    def test_coherent_local_clock_shift_cannot_extend_reviewed_marker(self):
        ledger = self.create(); path = ledger.root / 'ledger.json'; state = json.loads(path.read_text())
        for name in ('started', 'deadline', 'started_wall', 'deadline_wall'): state[name] += 50
        path.write_bytes(launch._json(state))
        with self.assertRaises(ValueError): launch.LaunchLedger(ledger.root, self.manifest, clock=lambda: self.now, wall=lambda: self.wall)

    def test_new_marker_rejects_mixed_legacy_route_or_resource_mutation(self):
        for fault in ('legacy', 'old-diagnostic', 'extra-role', 'participant', 'clock', 'bool', 'image'):
            value = copy.deepcopy(self.manifest)
            if fault == 'legacy': value['browser_followup'] = {}
            elif fault == 'old-diagnostic': value['diagnostic'] = {}
            elif fault == 'extra-role': value['cells'][0]['role_limits']['scripted-inference'] = 1
            elif fault == 'participant': value['limits']['participant_segments'] = 2
            elif fault == 'clock': value['settlement_diagnostic']['clock']['deadline'] += 1
            elif fault == 'bool': value['limits']['live'] = True
            else: value['images']['browser-0.87.1']['platform'] = 'linux/amd64'
            with self.subTest(fault=fault), self.assertRaises(ValueError): launch.validate_manifest(value)

    def test_seven_original_role_reservations_stop_before_an_eighth_or_second_participant(self):
        ledger = self.create(); cell = self.manifest['cells'][0]
        for index, role in enumerate(cell['role_limits']):
            image = self.manifest['images']['core-0.87.1']['id'] if role == 'fixture' else cell['image_id']
            record = {'registry': 'c' * 64, 'generation': str(uuid.uuid4()), 'launch_id': str(uuid.uuid4()),
                      'container': 'inert-' + str(index), 'image': image}
            key = ledger.reserve(cell['id'], role, record, launch._role_weight(self.manifest, cell, role),
                                 {'id': 'inert-daemon', **self.capacity})
            ledger.note(key, physical='absent', private_cleanup=True)
        self.assertEqual(len(json.loads((ledger.root / 'ledger.json').read_text())['launches']), 7)
        record = {'registry': 'd' * 64, 'generation': str(uuid.uuid4()), 'launch_id': str(uuid.uuid4()),
                  'container': 'eighth', 'image': cell['image_id']}
        with self.assertRaises(ValueError):
            ledger.reserve(cell['id'], 'participant', record, launch._role_weight(self.manifest, cell, 'participant'),
                           {'id': 'inert-daemon', **self.capacity})

    def test_cleanup_reserve_prevents_new_admission(self):
        self.now = 971.; self.wall = 1071.
        with self.assertRaises(ValueError): self.create()

    def test_legacy_manifest_and_four_hour_clock_remain_unchanged(self):
        old = legacy.manifest(); original = copy.deepcopy(old)
        self.assertEqual(launch.validate_manifest(old), original)
        ledger = launch.LaunchLedger.create(self.root / 'legacy', old, daemon_id='inert-daemon',
            daemon_capacity={'cpu_millis': 64000, 'memory_mib': 65536}, clock=lambda: 100., wall=lambda: 200.)
        state = json.loads((ledger.root / 'ledger.json').read_text())
        self.assertEqual(state['deadline'], 14500.)
        self.assertEqual(state['deadline_wall'], 14600.)
        self.assertEqual(launch.effective_limits(old), launch.LIMITS)

    def test_copy_only_replay_keeps_exact_launch_pin_and_refuses_new_mode_before_clone(self):
        import application_operational_replay as replay
        replay.Kernel()
        with mock.patch.object(replay.types, 'FunctionType', side_effect=AssertionError('clone forbidden')) as clone:
            with self.assertRaises(ValueError): replay.Kernel.manifest(self.manifest, launch.LIMITS)
            clone.assert_not_called()


    def test_exact_reviewed_clock_normalization_rejects_missing_weakened_moved_or_altered_guards(self):
        tree=ast.parse((ROOT/'tools/qualification/application_launch.py').read_bytes())
        ledger=next(n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='LaunchLedger')
        raw=pinned_dump(ledger)
        normalized=normalize_reviewed_settlement_ledger_ast(ledger)
        self.assertEqual(pinned_dump(ledger),raw,'normalization must not mutate its input')
        self.assertEqual(hashlib.sha256(pinned_dump(normalized).encode()).hexdigest(),
          '249416e94a8534581a90b40c8b55fdcfcd2bbec492aed80a2c9862b85b1b7d0e')
        for location in ('create','validate'):
            for fault in ('missing','weakened','moved','altered'):
                changed=copy.deepcopy(ledger)
                if location=='create':
                    body=changed.body[1].body[14].body
                    if fault=='missing':del body[4]
                    elif fault=='weakened':body[4].body[1].test=ast.Constant(value=False)
                    elif fault=='moved':body[4],body[5]=body[5],body[4]
                    else:body[4].body[1].body[0]=ast.parse("_deny('another_reason')").body[0]
                else:
                    body=changed.body[2].body
                    if fault=='missing':del body[12]
                    elif fault=='weakened':body[12].body[1].test=ast.Constant(value=False)
                    elif fault=='moved':body[12],body[13]=body[13],body[12]
                    else:body[10].value.body=ast.Constant(value=901)
                with self.subTest(location=location,fault=fault),self.assertRaises(ValueError):
                    normalize_reviewed_settlement_ledger_ast(changed)


if __name__ == '__main__':
    unittest.main()
