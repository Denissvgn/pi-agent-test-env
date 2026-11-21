# Check file for defaults_layers.resolve. This header is the whole specification.
#
#     KEYS = ('image', 'platform', 'profile', 'resources', 'host_gateway',
#             'results_dir', 'network', 'exclude', 'session')
#     resolve(layers) -> (values, sources)
#
# Specification
#   layers is an ordered list of (source_name, mapping) from lowest to highest
#   precedence. resolve returns (values, sources).
#   - An unknown key (one that is not in KEYS) raises ValueError that names the
#     key and its source.
#   - A value of None does not override.
#   - exclude is a list of strings and concatenates across layers in order
#     without duplicates; every other key is last-wins.
#   - host_gateway must be a bool and every other value a non-empty string, or
#     ValueError.
#   - sources maps each set key to the name of the layer that won, and for
#     exclude to the list of layers that contributed.
#   - resolve is a pure function of its arguments.
#
# How the checks read it
#   - Each mapping may be any collections.abc.Mapping; a plain dict is not
#     required. The checks include a read-only types.MappingProxyType.
#   - An unknown key raises ValueError that names the key and its layer whatever
#     its value is, None included, and whichever layer holds it.
#   - Pure means the call does not modify its arguments, checked when the call
#     returns.
#   - A key is set when some layer gives it a value that is not None; a key that
#     is never set is in neither values nor sources.
#   - "Every other value" means every value except host_gateway and exclude.
#     The checks reject an empty string and values that are not strings (an int,
#     a bool, a list) for those keys, and every value that is not True or False
#     for host_gateway, including the ints 0 and 1 and the strings 'true' and
#     'false'. False is a value like any other: it overrides True.
#   - An exclude of None is as if the layer had no exclude.
#   - exclude keeps the first occurrence of each string, in layer order, with
#     repeats inside one list and across lists appearing once.
#   - A layer that adds at least one string that no lower layer has is a
#     contributor, and sources['exclude'] holds each contributor once.
#   - The checks use distinct source names.
#
# Not specified, so not checked: how an empty exclude list, or a list that only
# repeats strings already seen, is credited in sources['exclude'] (a layer that
# adds nothing may or may not be listed); the order of the names in
# sources['exclude']; a lone empty exclude list; what an invalid exclude (not a
# list, or with entries that are not strings) raises; whether an invalid value in
# a layer that a higher layer overrides raises; which error is raised when
# several mappings are invalid at once; whitespace-only strings; whether the
# returned values share objects with the arguments or change when they change
# later.
#
# The file runs in the repository and, unchanged, in a scratch project: it
# puts skill/scripts (when present) and the working directory on the import
# path, and it is skipped while defaults_layers does not exist.
import copy
import sys
import unittest
from pathlib import Path
from types import MappingProxyType

for _dir in (Path(__file__).resolve().parents[1]/'skill'/'scripts',
             Path.cwd()/'skill'/'scripts', Path.cwd()):
    if _dir.is_dir() and str(_dir) not in sys.path:
        sys.path.insert(0, str(_dir))
try:
    import defaults_layers
except ModuleNotFoundError as exc:
    if exc.name != 'defaults_layers':
        raise
    defaults_layers = None

KEYS = ('image', 'platform', 'profile', 'resources', 'host_gateway',
        'results_dir', 'network', 'exclude', 'session')
STRING_KEYS = tuple(key for key in KEYS if key not in ('host_gateway', 'exclude'))


def snapshot(layers):
    return [(name, copy.deepcopy(dict(mapping))) for name, mapping in layers]


def resolve(layers):
    """Return (values, sources) as plain dicts, with exclude entries as lists."""
    before = snapshot(layers)
    values, sources = defaults_layers.resolve(layers)
    if snapshot(layers) != before:
        raise AssertionError('resolve modified its layers argument')
    values, sources = dict(values), dict(sources)
    if 'exclude' in values:
        values['exclude'] = list(values['exclude'])
    if 'exclude' in sources:
        sources['exclude'] = list(sources['exclude'])
    return values, sources


class DefaultsLayersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if defaults_layers is None:
            raise unittest.SkipTest('module not present')

    # Shape and empty input

    def test_keys_are_the_documented_tuple(self):
        self.assertEqual(defaults_layers.KEYS, KEYS)
        self.assertIsInstance(defaults_layers.KEYS, tuple)

    def test_no_layers_and_empty_mappings_resolve_to_nothing(self):
        self.assertEqual(resolve([]), ({}, {}))
        self.assertEqual(resolve([('a', {}), ('b', {})]), ({}, {}))

    def test_a_single_layer_sets_every_key(self):
        mapping = {'image': 'img:1', 'platform': 'linux/arm64', 'profile': 'fast',
                   'resources': 'small', 'host_gateway': True, 'results_dir': 'out',
                   'network': 'none', 'exclude': ['a', 'b'], 'session': 'one'}
        values, sources = resolve([('file', mapping)])
        self.assertEqual(values, mapping)
        self.assertEqual(sources, {'image': 'file', 'platform': 'file', 'profile': 'file',
                                   'resources': 'file', 'host_gateway': 'file',
                                   'results_dir': 'file', 'network': 'file',
                                   'exclude': ['file'], 'session': 'file'})

    def test_only_keys_that_are_set_appear(self):
        values, sources = resolve([('a', {'image': 'img'}), ('b', {'session': 's'})])
        self.assertEqual(values, {'image': 'img', 'session': 's'})
        self.assertEqual(sources, {'image': 'a', 'session': 'b'})

    # Last wins

    def test_last_wins_for_every_string_key(self):
        for key in STRING_KEYS:
            with self.subTest(key=key):
                values, sources = resolve([('low', {key: 'one'}), ('high', {key: 'two'})])
                self.assertEqual(values, {key: 'two'})
                self.assertEqual(sources, {key: 'high'})

    def test_last_wins_for_host_gateway_and_false_is_a_value(self):
        values, sources = resolve([('low', {'host_gateway': True}), ('high', {'host_gateway': False})])
        self.assertIs(values['host_gateway'], False)
        self.assertEqual(sources, {'host_gateway': 'high'})
        values, sources = resolve([('low', {'host_gateway': False}), ('high', {'host_gateway': True})])
        self.assertIs(values['host_gateway'], True)
        self.assertEqual(sources, {'host_gateway': 'high'})
        values, sources = resolve([('only', {'host_gateway': False})])
        self.assertEqual((values, sources), ({'host_gateway': False}, {'host_gateway': 'only'}))

    def test_precedence_follows_layer_order_not_name_order(self):
        values, sources = resolve([('zzz', {'image': 'first'}), ('aaa', {'image': 'second'})])
        self.assertEqual((values, sources), ({'image': 'second'}, {'image': 'aaa'}))

    def test_each_key_takes_its_own_winner(self):
        layers = [('one', {'image': 'i1', 'platform': 'p1', 'profile': 'f1'}),
                  ('two', {'platform': 'p2', 'session': 's2'}),
                  ('three', {'profile': 'f3', 'session': 's3'}),
                  ('four', {})]
        values, sources = resolve(layers)
        self.assertEqual(values, {'image': 'i1', 'platform': 'p2', 'profile': 'f3', 'session': 's3'})
        self.assertEqual(sources, {'image': 'one', 'platform': 'two', 'profile': 'three',
                                   'session': 'three'})

    # None does not override

    def test_none_does_not_override_a_lower_value(self):
        for key in STRING_KEYS:
            with self.subTest(key=key):
                values, sources = resolve([('low', {key: 'kept'}), ('high', {key: None})])
                self.assertEqual((values, sources), ({key: 'kept'}, {key: 'low'}))

    def test_none_does_not_override_host_gateway(self):
        values, sources = resolve([('low', {'host_gateway': False}), ('high', {'host_gateway': None})])
        self.assertEqual((values, sources), ({'host_gateway': False}, {'host_gateway': 'low'}))

    def test_none_between_values_is_skipped(self):
        layers = [('low', {'image': 'a'}), ('mid', {'image': None}), ('high', {'image': 'c'}),
                  ('top', {'image': None})]
        self.assertEqual(resolve(layers), ({'image': 'c'}, {'image': 'high'}))

    def test_a_key_that_is_only_none_is_not_set(self):
        layers = [('a', {'image': None, 'host_gateway': None, 'exclude': None}),
                  ('b', {'image': None})]
        self.assertEqual(resolve(layers), ({}, {}))

    # Mapping types

    def test_layers_may_be_read_only_mappings(self):
        low = MappingProxyType({'image': 'a', 'session': None, 'exclude': ['x']})
        high = MappingProxyType({'image': 'b', 'host_gateway': False, 'exclude': ['y', 'x']})
        values, sources = resolve([('low', low), ('high', high)])
        self.assertEqual(values, {'image': 'b', 'host_gateway': False, 'exclude': ['x', 'y']})
        self.assertEqual({key: sources[key] for key in ('image', 'host_gateway')},
                         {'image': 'high', 'host_gateway': 'high'})
        self.assertCountEqual(sources['exclude'], ['low', 'high'])
        self.assertEqual(set(sources), {'image', 'host_gateway', 'exclude'})

    def test_read_only_and_plain_mappings_mix(self):
        layers = [('plain', {'profile': 'p1', 'platform': 'a'}),
                  ('proxy', MappingProxyType({'profile': 'p2'}))]
        self.assertEqual(resolve(layers),
                         ({'profile': 'p2', 'platform': 'a'}, {'profile': 'proxy', 'platform': 'plain'}))

    def test_read_only_mappings_are_validated_like_any_other(self):
        self.assertUnknownKey([('file', MappingProxyType({'bogus_key': 'x'}))], 'bogus_key', 'file')
        with self.assertRaises(ValueError):
            resolve([('file', MappingProxyType({'host_gateway': 'true'}))])

    # exclude

    def test_exclude_concatenates_in_layer_order(self):
        layers = [('low', {'exclude': ['a', 'b']}), ('mid', {'exclude': ['c']}),
                  ('high', {'exclude': ['d', 'e']})]
        values, sources = resolve(layers)
        self.assertEqual(values, {'exclude': ['a', 'b', 'c', 'd', 'e']})
        self.assertCountEqual(sources['exclude'], ['low', 'mid', 'high'])

    def test_exclude_keeps_the_first_occurrence_across_layers(self):
        layers = [('low', {'exclude': ['a', 'b']}), ('high', {'exclude': ['c', 'a', 'd', 'b']})]
        values, sources = resolve(layers)
        self.assertEqual(values['exclude'], ['a', 'b', 'c', 'd'])
        self.assertCountEqual(sources['exclude'], ['low', 'high'])

    def test_exclude_removes_repeats_inside_one_list(self):
        values, sources = resolve([('only', {'exclude': ['a', 'b', 'a', 'a', 'c', 'b']})])
        self.assertEqual(values['exclude'], ['a', 'b', 'c'])
        self.assertEqual(sources['exclude'], ['only'])

    def test_a_layer_that_adds_one_new_string_is_a_contributor(self):
        values, sources = resolve([('low', {'exclude': ['a']}), ('high', {'exclude': ['a', 'b']})])
        self.assertEqual(values['exclude'], ['a', 'b'])
        self.assertCountEqual(sources['exclude'], ['low', 'high'])

    def test_exclude_with_an_empty_list_in_a_layer_keeps_the_other_strings(self):
        values, sources = resolve([('low', {'exclude': ['a']}), ('high', {'exclude': []})])
        self.assertEqual(values['exclude'], ['a'])
        self.assertIn('low', sources['exclude'])

    def test_exclude_does_not_depend_on_other_keys_or_layers_without_it(self):
        layers = [('one', {'image': 'i'}), ('two', {'exclude': ['x']}), ('three', {'image': 'j'})]
        values, sources = resolve(layers)
        self.assertEqual(values, {'image': 'j', 'exclude': ['x']})
        self.assertEqual(sources, {'image': 'three', 'exclude': ['two']})

    def test_a_none_exclude_layer_does_not_contribute(self):
        layers = [('low', {'exclude': ['a']}), ('mid', {'exclude': None}), ('high', {'exclude': ['b']})]
        values, sources = resolve(layers)
        self.assertEqual(values['exclude'], ['a', 'b'])
        self.assertCountEqual(sources['exclude'], ['low', 'high'])

    # Unknown keys

    def test_unknown_key_raises_and_names_key_and_source(self):
        with self.assertRaises(ValueError) as caught:
            resolve([('base', {'image': 'img'}), ('cli-flags', {'bogus_key': 'x'})])
        message = str(caught.exception)
        self.assertIn('bogus_key', message)
        self.assertIn('cli-flags', message)

    def test_unknown_key_in_the_lowest_layer_names_that_layer(self):
        with self.assertRaises(ValueError) as caught:
            resolve([('env-file', {'extra': 'x'}), ('cli', {'image': 'img'})])
        message = str(caught.exception)
        self.assertIn('extra', message)
        self.assertIn('env-file', message)

    def assertUnknownKey(self, layers, key, source):
        with self.assertRaises(ValueError) as caught:
            defaults_layers.resolve(layers)
        message = str(caught.exception)
        self.assertIn(key, message)
        self.assertIn(source, message)

    def test_unknown_key_with_a_none_value_still_raises_and_names_key_and_source(self):
        self.assertUnknownKey([('base', {'image': 'img'}), ('cli-flags', {'bogus_key': None})],
                              'bogus_key', 'cli-flags')
        self.assertUnknownKey([('only-layer', {'bogus_key': None})], 'bogus_key', 'only-layer')

    def test_unknown_none_key_beside_known_keys_names_its_own_layer(self):
        self.assertUnknownKey(
            [('env-file', {'extra': None, 'image': 'a'}), ('cli', {'image': 'b'})],
            'extra', 'env-file')
        self.assertUnknownKey(
            [('low', {'image': 'a'}), ('mid-layer', {'image': None, 'stray': None}),
             ('top', {'image': 'c'})],
            'stray', 'mid-layer')

    def test_keys_match_exactly(self):
        for key in ('Image', 'results-dir', 'host-gateway'):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    resolve([('file', {key: 'x'})])

    # Validation

    def test_string_keys_reject_empty_strings(self):
        for key in STRING_KEYS:
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    resolve([('file', {key: ''})])

    def test_string_keys_reject_values_that_are_not_strings(self):
        for key in STRING_KEYS:
            for bad in (5, True, ['x']):
                with self.subTest(key=key, bad=bad):
                    with self.assertRaises(ValueError):
                        resolve([('file', {key: bad})])

    def test_host_gateway_rejects_non_bools(self):
        for bad in (0, 1, 'true', 'false'):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    resolve([('file', {'host_gateway': bad})])

    def test_host_gateway_accepts_both_bools(self):
        for good in (True, False):
            with self.subTest(good=good):
                values, _ = resolve([('file', {'host_gateway': good})])
                self.assertIs(values['host_gateway'], good)

    def test_an_invalid_value_in_the_highest_layer_raises(self):
        with self.assertRaises(ValueError):
            resolve([('low', {'image': 'good'}), ('high', {'image': 7})])
        with self.assertRaises(ValueError):
            resolve([('low', {'host_gateway': True}), ('high', {'host_gateway': 'no'})])


if __name__ == '__main__':
    unittest.main()
