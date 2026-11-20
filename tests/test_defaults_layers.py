# Check file for defaults_layers.resolve. This header is the whole specification.
#
#     KEYS = ('image', 'platform', 'profile', 'resources', 'host_gateway',
#             'results_dir', 'network', 'exclude', 'session')
#     resolve(layers) -> (values, sources)
#
# Input
#   layers   an ordered list of (source_name, mapping) pairs, from the lowest
#            to the highest precedence. Source names are distinct strings. A
#            mapping is a dict that may be empty.
#
# Result
#   A tuple of two new dicts. values holds every key that is set; sources has
#   exactly the same keys. A key is set when at least one layer gives it a value
#   that is not None. A key that is never set appears in neither dict. The input
#   layers and their mappings, including exclude lists, are never modified.
#
# Rules
#   1. A key that is not in KEYS raises ValueError. The message names the key
#      and the source of the layer it came from. This holds for every layer,
#      including one that a higher layer would override, and also when the
#      value is None. Keys match exactly: 'Image' is not 'image'.
#   2. A value of None never overrides: it is as if the key were absent from
#      that layer.
#   3. Every key except exclude is last-wins: values[key] is the value from the
#      highest layer that gives it a non-None value, and sources[key] is the
#      name of that layer.
#   4. exclude is a list of strings. The lists of all layers that give a
#      non-None exclude are concatenated in layer order, keeping only the first
#      occurrence of each string (a string repeated inside one list or across
#      lists appears once, at its first position). sources['exclude'] is the
#      list of the names of those layers, in layer order. A layer contributes
#      when its exclude is not None, even if its list is empty or all of its
#      entries are repeats. A lower layer's exclude is never replaced by a
#      higher layer.
#   5. Validation applies to every non-None value of every layer, including a
#      value that a higher layer overrides:
#        - host_gateway must be a bool (True or False). Other types, including
#          the ints 0 and 1 and the strings 'true' and 'false', raise
#          ValueError. False is a value like any other: it overrides True.
#        - exclude must be a list (a bare string is not a list) and every entry
#          must be a str, or ValueError is raised.
#        - every other key must be a str that is not empty, or ValueError is
#          raised. Only the empty string is rejected: ' ' is accepted, and a
#          bool or an int is rejected.
#
# Not specified, so not checked: which error is raised when several mappings
# are invalid at once, repeated source names, and empty strings inside exclude.
#
# Boundaries covered below: no layers, empty mappings, None-only keys, False for
# host_gateway, empty lists for exclude, repeats inside and across exclude lists,
# and invalid values that are overridden.
#
# The file runs in the repository and, unchanged, in a scratch project: it
# puts skill/scripts (when present) and the working directory on the import
# path, and it is skipped while defaults_layers does not exist.
import copy
import sys
import unittest
from pathlib import Path

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


def resolve(layers):
    return defaults_layers.resolve(layers)


class DefaultsLayersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if defaults_layers is None:
            raise unittest.SkipTest('module not present')

    # Shape

    def test_keys_are_the_documented_tuple(self):
        self.assertEqual(defaults_layers.KEYS, KEYS)
        self.assertIsInstance(defaults_layers.KEYS, tuple)

    def test_result_is_a_pair_of_dicts(self):
        result = resolve([('base', {'image': 'img'})])
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        self.assertIsInstance(result[0], dict)
        self.assertIsInstance(result[1], dict)

    def test_no_layers_resolve_to_empty_dicts(self):
        self.assertEqual(resolve([]), ({}, {}))

    def test_empty_mappings_resolve_to_empty_dicts(self):
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

    # Rule 3: last wins

    def test_last_wins_for_every_string_key(self):
        for key in STRING_KEYS:
            with self.subTest(key=key):
                values, sources = resolve([('low', {key: 'one'}), ('high', {key: 'two'})])
                self.assertEqual(values, {key: 'two'})
                self.assertEqual(sources, {key: 'high'})

    def test_last_wins_for_host_gateway(self):
        values, sources = resolve([('low', {'host_gateway': True}), ('high', {'host_gateway': False})])
        self.assertEqual(values, {'host_gateway': False})
        self.assertEqual(sources, {'host_gateway': 'high'})
        values, sources = resolve([('low', {'host_gateway': False}), ('high', {'host_gateway': True})])
        self.assertEqual(values, {'host_gateway': True})
        self.assertEqual(sources, {'host_gateway': 'high'})

    def test_false_host_gateway_is_set(self):
        values, sources = resolve([('only', {'host_gateway': False})])
        self.assertEqual(values, {'host_gateway': False})
        self.assertIs(values['host_gateway'], False)
        self.assertEqual(sources, {'host_gateway': 'only'})

    def test_precedence_follows_layer_order_not_name_order(self):
        values, sources = resolve([('zzz', {'image': 'first'}), ('aaa', {'image': 'second'})])
        self.assertEqual(values, {'image': 'second'})
        self.assertEqual(sources, {'image': 'aaa'})

    def test_each_key_takes_its_own_winner(self):
        layers = [('one', {'image': 'i1', 'platform': 'p1', 'profile': 'f1'}),
                  ('two', {'platform': 'p2'}),
                  ('three', {'profile': 'f3', 'session': 's3'})]
        values, sources = resolve(layers)
        self.assertEqual(values, {'image': 'i1', 'platform': 'p2', 'profile': 'f3', 'session': 's3'})
        self.assertEqual(sources, {'image': 'one', 'platform': 'two', 'profile': 'three',
                                   'session': 'three'})

    def test_a_layer_in_the_middle_can_win(self):
        layers = [('low', {'image': 'a'}), ('mid', {'image': 'b'}), ('high', {})]
        self.assertEqual(resolve(layers), ({'image': 'b'}, {'image': 'mid'}))

    # Rule 2: None

    def test_none_does_not_override_a_lower_value(self):
        for key in STRING_KEYS:
            with self.subTest(key=key):
                values, sources = resolve([('low', {key: 'kept'}), ('high', {key: None})])
                self.assertEqual(values, {key: 'kept'})
                self.assertEqual(sources, {key: 'low'})

    def test_none_does_not_override_host_gateway(self):
        values, sources = resolve([('low', {'host_gateway': False}), ('high', {'host_gateway': None})])
        self.assertEqual(values, {'host_gateway': False})
        self.assertEqual(sources, {'host_gateway': 'low'})

    def test_none_between_values_is_skipped(self):
        layers = [('low', {'image': 'a'}), ('mid', {'image': 'b'}), ('high', {'image': None})]
        self.assertEqual(resolve(layers), ({'image': 'b'}, {'image': 'mid'}))

    def test_a_key_that_is_only_none_is_not_set(self):
        layers = [('a', {'image': None, 'host_gateway': None, 'exclude': None}),
                  ('b', {'image': None})]
        self.assertEqual(resolve(layers), ({}, {}))

    # Rule 4: exclude

    def test_exclude_concatenates_in_layer_order(self):
        layers = [('low', {'exclude': ['a', 'b']}), ('mid', {'exclude': ['c']}),
                  ('high', {'exclude': ['d', 'e']})]
        values, sources = resolve(layers)
        self.assertEqual(values, {'exclude': ['a', 'b', 'c', 'd', 'e']})
        self.assertEqual(sources, {'exclude': ['low', 'mid', 'high']})

    def test_exclude_is_not_last_wins(self):
        values, sources = resolve([('low', {'exclude': ['a']}), ('high', {'exclude': ['b']})])
        self.assertEqual(values['exclude'], ['a', 'b'])
        self.assertEqual(sources['exclude'], ['low', 'high'])

    def test_exclude_keeps_the_first_occurrence_across_layers(self):
        layers = [('low', {'exclude': ['a', 'b']}), ('high', {'exclude': ['c', 'a', 'd', 'b']})]
        values, _ = resolve(layers)
        self.assertEqual(values['exclude'], ['a', 'b', 'c', 'd'])

    def test_exclude_removes_repeats_inside_one_list(self):
        values, sources = resolve([('only', {'exclude': ['a', 'b', 'a', 'a', 'c', 'b']})])
        self.assertEqual(values, {'exclude': ['a', 'b', 'c']})
        self.assertEqual(sources, {'exclude': ['only']})

    def test_exclude_repeats_are_case_sensitive(self):
        values, _ = resolve([('only', {'exclude': ['a', 'A']})])
        self.assertEqual(values['exclude'], ['a', 'A'])

    def test_exclude_only_in_one_layer(self):
        layers = [('one', {'image': 'i'}), ('two', {'exclude': ['x']}), ('three', {'image': 'j'})]
        values, sources = resolve(layers)
        self.assertEqual(values, {'image': 'j', 'exclude': ['x']})
        self.assertEqual(sources, {'image': 'three', 'exclude': ['two']})

    def test_none_exclude_layers_do_not_contribute(self):
        layers = [('low', {'exclude': ['a']}), ('mid', {'exclude': None}), ('high', {'exclude': ['b']})]
        values, sources = resolve(layers)
        self.assertEqual(values['exclude'], ['a', 'b'])
        self.assertEqual(sources['exclude'], ['low', 'high'])

    def test_empty_exclude_list_is_set_and_contributes(self):
        values, sources = resolve([('only', {'exclude': []})])
        self.assertEqual(values, {'exclude': []})
        self.assertEqual(sources, {'exclude': ['only']})
        values, sources = resolve([('low', {'exclude': ['a']}), ('high', {'exclude': []})])
        self.assertEqual(values['exclude'], ['a'])
        self.assertEqual(sources['exclude'], ['low', 'high'])

    def test_layer_with_only_repeated_exclude_entries_still_contributes(self):
        layers = [('low', {'exclude': ['a', 'b']}), ('high', {'exclude': ['b', 'a']})]
        values, sources = resolve(layers)
        self.assertEqual(values['exclude'], ['a', 'b'])
        self.assertEqual(sources['exclude'], ['low', 'high'])

    # Rule 1: unknown keys

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

    def test_unknown_key_with_a_none_value_raises(self):
        with self.assertRaises(ValueError) as caught:
            resolve([('file', {'bogus': None})])
        self.assertIn('bogus', str(caught.exception))
        self.assertIn('file', str(caught.exception))

    def test_keys_match_exactly(self):
        for key in ('Image', 'IMAGE', 'image ', 'results-dir', 'host-gateway'):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    resolve([('file', {key: 'x'})])

    # Rule 5: validation

    def test_string_keys_reject_empty_strings(self):
        for key in STRING_KEYS:
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    resolve([('file', {key: ''})])

    def test_string_keys_reject_other_types(self):
        for key in STRING_KEYS:
            for bad in (5, 1.5, True, False, ['x'], ('x',), {'x': 'y'}, b'x'):
                with self.subTest(key=key, bad=bad):
                    with self.assertRaises(ValueError):
                        resolve([('file', {key: bad})])

    def test_string_keys_accept_a_whitespace_string(self):
        values, _ = resolve([('file', {'image': ' '})])
        self.assertEqual(values, {'image': ' '})

    def test_host_gateway_rejects_non_bools(self):
        for bad in (0, 1, 'true', 'false', '', 'yes', [], [True], 1.0):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    resolve([('file', {'host_gateway': bad})])

    def test_host_gateway_accepts_both_bools(self):
        for good in (True, False):
            with self.subTest(good=good):
                values, _ = resolve([('file', {'host_gateway': good})])
                self.assertIs(values['host_gateway'], good)

    def test_exclude_rejects_a_non_list(self):
        for bad in ('a', 'a,b', '', 5, True, {'a': 1}):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    resolve([('file', {'exclude': bad})])

    def test_exclude_rejects_entries_that_are_not_strings(self):
        for bad in ([1], ['a', 2], [None], [['a']], ['a', True], [b'a']):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    resolve([('file', {'exclude': bad})])

    def test_invalid_value_in_an_overridden_layer_still_raises(self):
        with self.assertRaises(ValueError):
            resolve([('low', {'image': ''}), ('high', {'image': 'good'})])
        with self.assertRaises(ValueError):
            resolve([('low', {'host_gateway': 'yes'}), ('high', {'host_gateway': True})])
        with self.assertRaises(ValueError):
            resolve([('low', {'exclude': 'a'}), ('high', {'exclude': ['b']})])
        with self.assertRaises(ValueError):
            resolve([('low', {'exclude': [1]}), ('high', {})])

    def test_invalid_value_in_the_highest_layer_raises(self):
        with self.assertRaises(ValueError):
            resolve([('low', {'image': 'good'}), ('high', {'image': 7})])

    # Inputs and results are independent

    def test_input_is_not_modified(self):
        layers = [('low', {'image': 'a', 'exclude': ['x', 'y']}),
                  ('high', {'image': None, 'exclude': ['y', 'z'], 'host_gateway': False})]
        before = copy.deepcopy(layers)
        resolve(layers)
        self.assertEqual(layers, before)

    def test_result_does_not_share_the_exclude_list_with_the_input(self):
        low = ['x']
        values, _ = resolve([('only', {'exclude': low})])
        values['exclude'].append('changed')
        self.assertEqual(low, ['x'])
        values, _ = resolve([('only', {'exclude': low})])
        self.assertEqual(values['exclude'], ['x'])

    def test_resolving_twice_gives_equal_results(self):
        layers = [('low', {'exclude': ['a']}), ('high', {'exclude': ['b'], 'image': 'i'})]
        self.assertEqual(resolve(layers), resolve(layers))


if __name__ == '__main__':
    unittest.main()
