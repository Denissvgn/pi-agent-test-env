# Specification for defaults_layers.resolve(layers)
#
# resolve merges configuration layers and returns the pair (values, sources),
# both plain dicts.
#
# Input
#   layers  an ordered list of (source_name, mapping) pairs, from the lowest to
#           the highest precedence. It may be empty; a mapping may be empty.
#
# KEYS is the tuple
#   ("image", "platform", "profile", "resources", "host_gateway",
#    "results_dir", "network", "exclude", "session")
#
# Rules
#   R1  A key that is not in KEYS raises ValueError. The message contains the key
#       and the name of the layer that holds it. This applies to every layer,
#       whether or not a higher layer would override the key, and whatever the
#       value is, None included.
#   R2  A value of None never overrides and counts as absent. A key that is None
#       in every layer that mentions it is not set: it appears in neither values
#       nor sources.
#   R3  Every key except exclude is last-wins: the value from the highest layer
#       that sets it (non-None) is used.
#   R4  exclude is a list of strings. Its entries are concatenated across the
#       layers in layer order and entries already present are dropped, so the
#       first occurrence keeps its place. This also removes repeats inside a
#       single layer. A str entry is accepted as it is, the empty string
#       included.
#   R5  Every non-None value in every layer is validated, also when a higher
#       layer overrides it. host_gateway must be a bool (True or False; 0 and 1
#       are not accepted). Every other key except exclude must be a non-empty str
#       (a str such as " " is non-empty). exclude must be a list whose entries
#       are all str; a str, a tuple or a set is not accepted. A violation raises
#       ValueError. False is a value, not an absent one, and does override.
#   R6  sources maps each set key to the name of the layer that won it (a str).
#       For exclude it maps to a list: the names of the layers that contributed
#       to the result, in layer order, each name once. A layer whose exclude is
#       None, or that holds no exclude, does not contribute. A layer that adds
#       at least one entry not already present must be listed. Whether a layer
#       that adds nothing new (an empty list, or only entries already present)
#       is listed is not specified, and no case below depends on it.
#   R7  The result does not share lists with the input and the input is not
#       modified.
#
# Boundaries covered below: no layers, empty layers, None in the lowest and the
# highest layer, unknown keys in a low layer, bad values in an overridden layer,
# False overriding True, duplicate and empty exclude lists.
#
# The file runs in the repository and, unchanged, in a scratch project. It puts
# skill/scripts (when present) and the working directory on the import path and
# skipped as a whole, with the reason "module not present", while the module
# defaults_layers does not exist. Once it exists, every case runs and an import
# error raised inside it is reported, not hidden.

import copy
import importlib
import sys
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
for _base in (_HERE.parent, Path.cwd()):
    for _dir in (_base / "skill" / "scripts", _base):
        if _dir.is_dir() and str(_dir) not in sys.path:
            sys.path.append(str(_dir))


def _load():
    try:
        return importlib.import_module("defaults_layers")
    except ModuleNotFoundError as exc:
        if exc.name == "defaults_layers":
            return None
        raise


defaults_layers = _load()
if defaults_layers is None:
    if __name__ == "__main__":
        print("skipped: module not present")
        sys.exit(0)
    raise unittest.SkipTest("module not present")

KEYS = (
    "image",
    "platform",
    "profile",
    "resources",
    "host_gateway",
    "results_dir",
    "network",
    "exclude",
    "session",
)
STRING_KEYS = tuple(k for k in KEYS if k not in ("host_gateway", "exclude"))


def resolve(layers):
    return defaults_layers.resolve(layers)


class DefaultsLayersTests(unittest.TestCase):
    def test_keys_constant(self):
        self.assertEqual(defaults_layers.KEYS, KEYS)
        self.assertIsInstance(defaults_layers.KEYS, tuple)

    def test_no_layers_and_empty_layers(self):
        self.assertEqual(resolve([]), ({}, {}))
        self.assertEqual(resolve([("a", {})]), ({}, {}))
        self.assertEqual(resolve([("a", {}), ("b", {})]), ({}, {}))

    def test_result_is_a_pair_of_dicts(self):
        result = resolve([("a", {"image": "img"})])
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        self.assertIsInstance(result[0], dict)
        self.assertIsInstance(result[1], dict)

    def test_every_key_can_be_set_by_one_layer(self):
        for key in STRING_KEYS:
            with self.subTest(key=key):
                self.assertEqual(
                    resolve([("only", {key: "v"})]),
                    ({key: "v"}, {key: "only"}),
                )
        self.assertEqual(
            resolve([("only", {"host_gateway": True})]),
            ({"host_gateway": True}, {"host_gateway": "only"}),
        )
        self.assertEqual(
            resolve([("only", {"exclude": ["x"]})]),
            ({"exclude": ["x"]}, {"exclude": ["only"]}),
        )

    def test_last_wins_by_layer_order(self):
        layers = [
            ("low", {"image": "i1", "platform": "p1", "session": "s1"}),
            ("mid", {"image": "i2", "platform": "p2"}),
            ("high", {"image": "i3"}),
        ]
        values, sources = resolve(layers)
        self.assertEqual(values, {"image": "i3", "platform": "p2", "session": "s1"})
        self.assertEqual(sources, {"image": "high", "platform": "mid", "session": "low"})

    def test_layer_order_not_name_order_decides(self):
        values, sources = resolve([("z", {"image": "from-z"}), ("a", {"image": "from-a"})])
        self.assertEqual(values, {"image": "from-a"})
        self.assertEqual(sources, {"image": "a"})

    def test_none_does_not_override(self):
        layers = [("low", {"image": "i1"}), ("high", {"image": None})]
        self.assertEqual(resolve(layers), ({"image": "i1"}, {"image": "low"}))

    def test_none_in_the_lowest_layer_is_absent(self):
        layers = [("low", {"image": None}), ("high", {"image": "i2"})]
        self.assertEqual(resolve(layers), ({"image": "i2"}, {"image": "high"}))

    def test_key_that_is_only_none_is_not_set(self):
        layers = [("low", {"image": None, "host_gateway": None, "exclude": None})]
        self.assertEqual(resolve(layers), ({}, {}))
        layers = [("a", {"profile": None}), ("b", {"profile": None})]
        self.assertEqual(resolve(layers), ({}, {}))

    def test_false_host_gateway_overrides_true(self):
        layers = [("low", {"host_gateway": True}), ("high", {"host_gateway": False})]
        self.assertEqual(resolve(layers), ({"host_gateway": False}, {"host_gateway": "high"}))
        layers = [("low", {"host_gateway": False}), ("high", {"host_gateway": True})]
        self.assertEqual(resolve(layers), ({"host_gateway": True}, {"host_gateway": "high"}))

    def test_false_host_gateway_is_set_when_alone(self):
        self.assertEqual(
            resolve([("only", {"host_gateway": False})]),
            ({"host_gateway": False}, {"host_gateway": "only"}),
        )

    def test_exclude_concatenates_in_layer_order_without_duplicates(self):
        layers = [
            ("base", {"exclude": ["a", "b"]}),
            ("user", {"exclude": ["b", "c"]}),
            ("cli", {"exclude": ["d", "a"]}),
        ]
        values, sources = resolve(layers)
        self.assertEqual(values, {"exclude": ["a", "b", "c", "d"]})
        self.assertEqual(sources, {"exclude": ["base", "user", "cli"]})

    def test_exclude_removes_repeats_inside_one_layer(self):
        values, sources = resolve([("only", {"exclude": ["x", "y", "x", "y", "z"]})])
        self.assertEqual(values, {"exclude": ["x", "y", "z"]})
        self.assertEqual(sources, {"exclude": ["only"]})

    def test_exclude_is_not_last_wins(self):
        layers = [("low", {"exclude": ["a"]}), ("high", {"exclude": ["b"]})]
        values, _ = resolve(layers)
        self.assertEqual(values["exclude"], ["a", "b"])

    def test_exclude_none_layer_does_not_contribute(self):
        layers = [
            ("a", {"exclude": ["x"]}),
            ("b", {"exclude": None}),
            ("c", {"exclude": ["y"]}),
            ("d", {}),
        ]
        values, sources = resolve(layers)
        self.assertEqual(values, {"exclude": ["x", "y"]})
        self.assertEqual(sources, {"exclude": ["a", "c"]})

    def test_exclude_empty_and_repeated_entries_add_nothing(self):
        values, _ = resolve([("only", {"exclude": []})])
        self.assertEqual(values.get("exclude", []), [])
        layers = [("a", {"exclude": ["x"]}), ("b", {"exclude": []}), ("c", {"exclude": ["x"]})]
        values, sources = resolve(layers)
        self.assertEqual(values, {"exclude": ["x"]})
        self.assertIn("a", sources["exclude"])

    def test_exclude_sources_list_contributing_layers_in_order(self):
        layers = [
            ("a", {"exclude": ["x"]}),
            ("b", {"exclude": []}),
            ("c", {"exclude": ["y"]}),
        ]
        values, sources = resolve(layers)
        self.assertEqual(values, {"exclude": ["x", "y"]})
        listed = sources["exclude"]
        self.assertEqual([n for n in listed if n in ("a", "c")], ["a", "c"])
        self.assertEqual(len(listed), len(set(listed)))
        self.assertTrue(set(listed) <= {"a", "b", "c"})

    def test_exclude_keeps_an_empty_string_entry(self):
        values, _ = resolve([("only", {"exclude": ["", "a", ""]})])
        self.assertEqual(values, {"exclude": ["", "a"]})

    def test_source_of_other_keys_is_a_name_not_a_list(self):
        _, sources = resolve([("a", {"image": "i", "exclude": ["x"]})])
        self.assertEqual(sources["image"], "a")
        self.assertIsInstance(sources["exclude"], list)

    def test_full_example(self):
        layers = [
            (
                "base",
                {
                    "image": "img:1",
                    "platform": "linux/arm64",
                    "profile": "p0",
                    "exclude": ["a", "b"],
                    "network": "none",
                },
            ),
            (
                "user",
                {
                    "image": "img:2",
                    "profile": None,
                    "exclude": ["b", "c"],
                    "host_gateway": True,
                    "resources": "cpus=2",
                },
            ),
            (
                "cli",
                {
                    "image": None,
                    "results_dir": "out",
                    "exclude": ["d", "a"],
                    "host_gateway": False,
                    "session": "s1",
                },
            ),
        ]
        values, sources = resolve(layers)
        self.assertEqual(
            values,
            {
                "image": "img:2",
                "platform": "linux/arm64",
                "profile": "p0",
                "resources": "cpus=2",
                "host_gateway": False,
                "results_dir": "out",
                "network": "none",
                "exclude": ["a", "b", "c", "d"],
                "session": "s1",
            },
        )
        self.assertEqual(
            sources,
            {
                "image": "user",
                "platform": "base",
                "profile": "base",
                "resources": "user",
                "host_gateway": "cli",
                "results_dir": "cli",
                "network": "base",
                "exclude": ["base", "user", "cli"],
                "session": "cli",
            },
        )

    def test_unknown_key_names_key_and_source(self):
        with self.assertRaises(ValueError) as caught:
            resolve([("team-config", {"colour": "red"})])
        message = str(caught.exception)
        self.assertIn("colour", message)
        self.assertIn("team-config", message)

    def test_unknown_key_names_the_layer_that_holds_it(self):
        layers = [
            ("first-layer", {"image": "i"}),
            ("second-layer", {"flavour": "x"}),
            ("third-layer", {"image": "j"}),
        ]
        with self.assertRaises(ValueError) as caught:
            resolve(layers)
        message = str(caught.exception)
        self.assertIn("flavour", message)
        self.assertIn("second-layer", message)

    def test_unknown_key_with_none_value_still_raises(self):
        with self.assertRaises(ValueError) as caught:
            resolve([("low-layer", {"colour": None})])
        self.assertIn("colour", str(caught.exception))
        self.assertIn("low-layer", str(caught.exception))

    def test_unknown_key_in_a_low_layer_raises_though_later_layers_are_valid(self):
        with self.assertRaises(ValueError):
            resolve([("low", {"colour": "red"}), ("high", {"image": "i"})])

    def test_string_keys_reject_bad_values(self):
        bad_values = ("", 5, 1.5, True, False, ["a"], ("a",), b"x", {})
        for key in STRING_KEYS:
            for bad in bad_values:
                with self.subTest(key=key, value=bad):
                    with self.assertRaises(ValueError):
                        resolve([("l", {key: bad})])

    def test_string_keys_accept_a_blank_but_non_empty_string(self):
        self.assertEqual(resolve([("l", {"image": " "})]), ({"image": " "}, {"image": "l"}))

    def test_host_gateway_must_be_bool(self):
        for bad in ("true", "", 1, 0, 1.0, [], [True]):
            with self.subTest(value=bad):
                with self.assertRaises(ValueError):
                    resolve([("l", {"host_gateway": bad})])

    def test_exclude_must_be_a_list_of_strings(self):
        for bad in ("abc", "", ("a",), {"a"}, 5, True, ["a", 1], ["a", None], [["a"]], [b"a"]):
            with self.subTest(value=bad):
                with self.assertRaises(ValueError):
                    resolve([("l", {"exclude": bad})])

    def test_bad_value_in_an_overridden_layer_still_raises(self):
        with self.assertRaises(ValueError):
            resolve([("low", {"image": ""}), ("high", {"image": "ok"})])
        with self.assertRaises(ValueError):
            resolve([("low", {"host_gateway": "yes"}), ("high", {"host_gateway": True})])
        with self.assertRaises(ValueError):
            resolve([("low", {"exclude": "a"}), ("high", {"exclude": ["b"]})])

    def test_result_does_not_share_lists_with_input(self):
        layers = [("a", {"exclude": ["x"]})]
        values, _ = resolve(layers)
        values["exclude"].append("y")
        self.assertEqual(layers[0][1]["exclude"], ["x"])
        again, _ = resolve(layers)
        self.assertEqual(again["exclude"], ["x"])

    def test_input_is_not_modified(self):
        layers = [
            ("a", {"image": "i", "exclude": ["x", "x"], "network": None}),
            ("b", {"exclude": ["y"], "host_gateway": False}),
        ]
        before = copy.deepcopy(layers)
        resolve(layers)
        self.assertEqual(layers, before)


if __name__ == "__main__":
    unittest.main()
