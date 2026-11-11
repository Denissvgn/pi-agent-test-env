"""Reviewed Pi release registry: frozen identities and complete entries.

Receipts and sealed results bind each reviewed release's contract identities,
so neither a refactor nor a later release may change them. Admitting a release
appends a complete registry entry plus its REVIEWED_IDENTITIES line, printed by
`python3 tests/test_release_registry.py --freeze <release>`. Nothing is inherited
from an earlier release.
"""
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'skill/scripts'), str(ROOT / 'skill/runtime')]
import application_contracts  # noqa: E402
import application_runtime_contracts  # noqa: E402
import native_tool_contracts  # noqa: E402
import pi_contract  # noqa: E402
import release_contracts  # noqa: E402

# Never edit a line once its release is admitted. The two predecessors were frozen on
# 2026-11-10 from the modules before the registry existed; "entry" covers the
# canonical JSON of the complete registry entry, including fields no identity holds.
# The registry's pi_schema field (2026-11-11) changed only the two "entry" hashes:
# both entries state pi_schema None, and no identity holds the field for them.
REVIEWED_IDENTITIES = {
    '0.87.1': {'release': '4f15d43728d06659bd5156458c895aea8babfcbfebcfc0d4ba9819ef98df3acb',
               'native_tools': 'd130e44d0ea7fe9537dd16c8aa605836c121495a302c81ca3f802c36503f1abb',
               'application_runtime': 'a5f0c4797d6611e82f1c0529277f330256920e63b6f5ff2038a2a8149e454ae2',
               'entry': '4cb977df5e406197542aee502e078772f9709885931c0cdbc06591708e67fef3'},
    '1.2.0': {'release': '65a4620bd2d51eec37524bfe0c5cb3e6c648b4460dee2612637129f25eec36bc',
              'native_tools': '23717f1683eef9c647139842fab51e426c0912ae32442dfd2165d825d3684df8',
              'application_runtime': 'f4b79ced3398cf5b2e8bf4cb40eb6f670ce65b335acb1f150c1717ddd409dcb0',
              'entry': '8db8bcfca0e7375bd4f03b6dd4bc172d9359cd7d1eb0964caf039ae3775724d0'},
    '1.5.2': {'release': '6eccc3493473a5d033e2622d6bae0f0f45280bfbf5ba60892d9a9d52f4ba8d80',
              'native_tools': 'aee28949afc22354f11798ff8251d72a00fdc8dff120b056378be33246095098',
              'application_runtime': '409d05722557fbc9b0aea0c0300d079fbd08493fd7d17278e8a4742808ff1838',
              'entry': '232ec3eda94e506bd27de2f310065c85fce00ac1d48b1d1825f0f90f7b3c3fff'},
}


def canonical(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def identities(release):
    return {'release': release_contracts.identity(release)['sha256'],
            'native_tools': native_tool_contracts.identity(release)['sha256'],
            'application_runtime': application_runtime_contracts.identity(release)['sha256'],
            'entry': canonical(release_contracts.entry(release))}


class FrozenIdentityTests(unittest.TestCase):
    def test_every_reviewed_release_has_frozen_identities_in_order(self):
        self.assertEqual(tuple(REVIEWED_IDENTITIES), release_contracts.RELEASES,
                         'Add the --freeze line for each newly admitted release')

    def test_reviewed_identities_are_frozen(self):
        for release, expected in REVIEWED_IDENTITIES.items():
            with self.subTest(release=release):
                self.assertEqual(identities(release), expected)


class RegistryTests(unittest.TestCase):
    def table(self):
        return {release: release_contracts.entry(release) for release in release_contracts.RELEASES}

    def test_every_entry_states_every_field(self):
        self.assertEqual(release_contracts.check_registry(self.table()), release_contracts.RELEASES)
        for release in release_contracts.RELEASES:
            with self.subTest(release=release):
                value = release_contracts.entry(release)
                self.assertEqual(set(value), set(release_contracts.ENTRY_FIELDS))
                self.assertTrue(all(type(value[field]) in (kind if type(kind) is tuple else (kind,))
                                    for field, kind in release_contracts.ENTRY_FIELDS.items()))

    def test_incomplete_malformed_or_unordered_tables_are_refused(self):
        newest = release_contracts.RELEASES[-1]
        cases = {
            'missing field': lambda table: table[newest].pop('early_session_file'),
            'extra field': lambda table: table[newest].update(inherits='0.87.1'),
            'wrong type': lambda table: table[newest].update(transient_retries=1),
            'short commit': lambda table: table[newest].update(upstream_commit='abc123'),
            'unknown settlement': lambda table: table[newest].update(settlement_aborted='optional'),
            'common flag': lambda table: table[newest].update(extra_cli_flags=('--offline',)),
            'bad digest': lambda table: table[newest]['native_tool_sources'].update({'packages/x.ts': 'f' * 63}),
            'escaping path': lambda table: table[newest]['application_runtime_sources'].update({'../x.ts': '0' * 64}),
            'bad profile': lambda table: table[newest].update(fixture_profile='../profile.json'),
            'partial validator pin': lambda table: table[newest].update(pi_schema={'version': '1.5.2'}),
            'validator pin type': lambda table: table[newest].update(pi_schema=['1.5.2']),
            'missing constructor pin': lambda table: table[newest].update(typebox=None),
        }
        for name, change in cases.items():
            with self.subTest(case=name):
                table = self.table()
                change(table)
                with self.assertRaisesRegex(ValueError, f'Reviewed Pi {re.escape(newest)} entry'):
                    release_contracts.check_registry(table)
        for name, table in {'unordered': dict(reversed(list(self.table().items()))),
                            'inexact version': {'1.2': release_contracts.entry(newest)}, 'empty': {}}.items():
            with self.subTest(case=name), self.assertRaises(ValueError):
                release_contracts.check_registry(table)

    def test_entries_are_copies(self):
        release = release_contracts.RELEASES[-1]
        value = release_contracts.entry(release)
        before = copy.deepcopy(value)
        value['native_tool_sources'].clear()
        value['typebox']['version'] = 'changed'
        self.assertEqual(release_contracts.entry(release), before)
        with self.assertRaisesRegex(ValueError, re.escape(f'({release_contracts.describe()})')):
            release_contracts.entry('0.0.1')

    def test_contracts_are_built_only_from_entries(self):
        for release in release_contracts.RELEASES:
            with self.subTest(release=release):
                value, selected = release_contracts.contract(release), release_contracts.entry(release)
                for field in ('upstream_commit', 'revision', 'session_version', 'settlement_aborted',
                              'numeric_reasoning_budgets', 'sampling'):
                    self.assertEqual(value[field], selected[field])
                self.assertEqual(value['extra_cli_flags'], list(selected['extra_cli_flags']))
                self.assertEqual(value['required_flags'],
                                 list(release_contracts.COMMON_FLAGS) + list(selected['extra_cli_flags']))
                self.assertEqual(value['reasoning_levels'], list(selected['reasoning_levels']))
                native = native_tool_contracts.contract(release)
                self.assertEqual((native['upstream_commit'], native['source_pins'], native['typebox']),
                                 (selected['upstream_commit'], selected['native_tool_sources'], selected['typebox']))
                # Only a release that validates with pi-schema states it, so earlier identities stay fixed.
                if selected['pi_schema'] is None:
                    self.assertNotIn('pi_schema', native)
                else:
                    self.assertEqual(native['pi_schema'], selected['pi_schema'])
                self.assertEqual(application_runtime_contracts.contract(release)['source_pins'],
                                 selected['application_runtime_sources'])

    def test_release_lists_follow_the_registry(self):
        self.assertIs(application_contracts.RELEASES, release_contracts.RELEASES)
        self.assertEqual(pi_contract.TRANSIENT_RETRY_RELEASES,
                         tuple(release for release in release_contracts.RELEASES
                               if release_contracts.entry(release)['transient_retries']))
        self.assertEqual(set(application_runtime_contracts.SOURCE_PINS), set(release_contracts.RELEASES))

    def test_fixture_profile_declarations_match_their_release(self):
        profiles = ROOT / 'skill/assets/profiles/fixture-lookup'
        for release in release_contracts.RELEASES:
            with self.subTest(release=release):
                declared = json.loads((profiles / release_contracts.entry(release)['fixture_profile']).read_text())
                self.assertEqual(declared['components'], [release_contracts.contract(release)['fixture_component']])

    def test_tool_budget_extension_admits_exactly_the_reviewed_releases(self):
        source = (ROOT / 'skill/runtime/tool-budget.mjs').read_text()
        listed = re.findall(r"!\[([^\]]*)\]\.includes\(value\.pi_release\)", source)
        self.assertEqual(len(listed), 1)
        self.assertEqual(re.findall(r"'([^']+)'", listed[0]), list(release_contracts.RELEASES),
                         'Add each reviewed release to the pi_release check in tool-budget.mjs')

    def test_describe_lists_releases_for_messages(self):
        self.assertEqual(release_contracts.describe(['1.0.0']), '1.0.0')
        self.assertEqual(release_contracts.describe(['1.0.0', '1.1.0']), '1.0.0 or 1.1.0')
        self.assertEqual(release_contracts.describe(['1.0.0', '1.1.0', '1.2.0']), '1.0.0, 1.1.0 or 1.2.0')
        self.assertEqual(release_contracts.describe(), release_contracts.describe(release_contracts.RELEASES))


if __name__ == '__main__':
    if sys.argv[1:2] == ['--freeze'] and len(sys.argv) == 3:
        print(f'    {sys.argv[2]!r}: {identities(sys.argv[2])!r},')
    else:
        unittest.main()
