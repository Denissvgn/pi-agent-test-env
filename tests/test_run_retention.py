# Specification for run_retention.select(runs, keep=None, older_than_days=None, now=None)
#
# select returns the ids of the runs to delete, as a new list of str.
#
# Inputs
#   runs             list of dicts, possibly empty. Each has id (str), started
#                    (seconds since the epoch, a number), sealed (bool) and
#                    protected (bool).
#   keep             None, or an integer >= 0.
#   older_than_days  None, or a number >= 0.
#   now              None, or seconds since the epoch. It is the reference
#                    point for older_than_days and is always supplied by the
#                    caller (see R8).
#
# Definitions
#   candidate  a run with sealed True and protected False.
#   age order  candidates sorted ascending by (started, id). The id is compared
#              as a plain str, so "10" sorts before "9". The first entry is the
#              oldest, the last the newest. Equal started values are therefore
#              ordered by id, and the greater id counts as the newer run.
#
# Rules
#   R1  An unsealed run and a protected run are never selected. They are not
#       candidates, so they do not count towards keep either.
#   R2  The result is in age order (oldest first) whatever the order of runs.
#       The input list and its dicts are not modified.
#   R3  keep=N spares the N newest candidates in age order. keep=0 spares
#       nothing. N at or above the number of candidates spares all of them.
#       The newest are counted among all candidates, not only among the old ones.
#   R4  older_than_days=D selects only candidates whose started is strictly less
#       than now - D * 86400. A run started exactly at that cutoff is not
#       selected. D=0 therefore selects candidates started before now.
#   R5  With both keep and older_than_days a candidate is selected only when it
#       is not spared by R3 and is old by R4.
#   R6  With neither keep nor older_than_days the result is [], even when now is
#       given.
#   R7  A negative keep or a negative older_than_days raises ValueError. The
#       check happens before anything else, so it applies to empty runs too.
#       keep=0 and older_than_days=0 are valid.
#   R8  The module imports only the Python standard library and reads no file,
#       environment variable or clock. Age filtering is measured only from the
#       now the caller passes. With keep alone, or with no rule, now may be
#       omitted and has no effect. What older_than_days does when now is
#       omitted is not specified, and no case below depends on it, apart from
#       R7, whose validation comes first and so applies whether or not now is
#       given.
#
# Boundaries covered below: empty runs, no rules, keep of 0 / exactly the
# candidate count / more than it, equal started values, ids that sort
# differently as numbers and as text, started one second either side of the
# cutoff and exactly at it, several runs sharing the cutoff or the second just
# before it, zero days, negative values.
#
# The file runs in the repository and, unchanged, in a scratch project. It puts
# skill/scripts (when present) and the working directory on the import path and
# skipped as a whole, with the reason "module not present", while the module
# run_retention does not exist. Once it exists, every case runs and an import
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
        return importlib.import_module("run_retention")
    except ModuleNotFoundError as exc:
        if exc.name == "run_retention":
            return None
        raise


run_retention = _load()
if run_retention is None:
    if __name__ == "__main__":
        print("skipped: module not present")
        sys.exit(0)
    raise unittest.SkipTest("module not present")

DAY = 86400


def run(rid, started, sealed=True, protected=False):
    return {"id": rid, "started": started, "sealed": sealed, "protected": protected}


def select(*args, **kwargs):
    return run_retention.select(*args, **kwargs)


class RunRetentionTests(unittest.TestCase):
    def test_empty_runs(self):
        self.assertEqual(select([]), [])
        self.assertEqual(select([], keep=0), [])
        self.assertEqual(select([], keep=3), [])
        self.assertEqual(select([], older_than_days=0, now=5), [])
        self.assertEqual(select([], keep=2, older_than_days=1, now=5), [])

    def test_neither_rule_selects_nothing(self):
        runs = [run("a", 1), run("b", 2, sealed=False), run("c", 3, protected=True)]
        self.assertEqual(select(runs), [])
        self.assertEqual(select(runs, now=10**9), [])
        self.assertEqual(select(runs, keep=None, older_than_days=None, now=10**9), [])

    def test_unsealed_run_is_never_selected(self):
        runs = [run("a", 1), run("b", 2, sealed=False)]
        self.assertEqual(select(runs, keep=0), ["a"])
        self.assertEqual(select(runs, older_than_days=1, now=100 * DAY), ["a"])
        self.assertEqual(select(runs, keep=0, older_than_days=1, now=100 * DAY), ["a"])

    def test_protected_run_is_never_selected(self):
        runs = [run("a", 1), run("b", 2, protected=True)]
        self.assertEqual(select(runs, keep=0), ["a"])
        self.assertEqual(select(runs, older_than_days=1, now=100 * DAY), ["a"])
        self.assertEqual(select(runs, keep=0, older_than_days=1, now=100 * DAY), ["a"])

    def test_unsealed_and_protected_run_is_never_selected(self):
        runs = [run("a", 1, sealed=False, protected=True)]
        self.assertEqual(select(runs, keep=0), [])
        self.assertEqual(select(runs, older_than_days=0, now=100 * DAY), [])

    def test_only_ineligible_runs(self):
        runs = [run("a", 1, sealed=False), run("b", 2, protected=True)]
        self.assertEqual(select(runs, keep=0), [])

    def test_unsealed_and_protected_runs_do_not_count_towards_keep(self):
        runs = [
            run("a1", 1),
            run("a2", 2),
            run("u", 3, sealed=False),
            run("p", 4, protected=True),
        ]
        self.assertEqual(select(runs, keep=1), ["a1"])
        self.assertEqual(select(runs, keep=2), [])

    def test_keep_spares_the_newest_and_returns_oldest_first(self):
        runs = [
            run("r3", 30),
            run("r5", 50),
            run("r1", 10),
            run("r4", 40),
            run("r2", 20),
        ]
        self.assertEqual(select(runs, keep=2), ["r1", "r2", "r3"])
        self.assertEqual(select(runs, keep=4), ["r1"])
        self.assertEqual(select(runs, keep=1), ["r1", "r2", "r3", "r4"])

    def test_keep_zero_selects_every_candidate(self):
        runs = [run("r3", 30), run("r1", 10), run("r2", 20)]
        self.assertEqual(select(runs, keep=0), ["r1", "r2", "r3"])

    def test_keep_at_or_above_candidate_count_selects_nothing(self):
        runs = [run("r1", 10), run("r2", 20), run("r3", 30)]
        self.assertEqual(select(runs, keep=3), [])
        self.assertEqual(select(runs, keep=4), [])
        self.assertEqual(select(runs, keep=100), [])

    def test_equal_started_ties_are_broken_by_id(self):
        runs = [run("c", 100), run("a", 100), run("b", 100)]
        self.assertEqual(select(runs, keep=0), ["a", "b", "c"])
        self.assertEqual(select(runs, keep=1), ["a", "b"])
        self.assertEqual(select(runs, keep=2), ["a"])
        self.assertEqual(select(runs, keep=3), [])

    def test_tie_between_distinct_timestamps(self):
        runs = [run("b", 10), run("x", 5), run("a", 10)]
        self.assertEqual(select(runs, keep=1), ["x", "a"])
        self.assertEqual(select(runs, keep=2), ["x"])

    def test_ids_are_compared_as_text(self):
        runs = [run("9", 100), run("10", 100)]
        self.assertEqual(select(runs, keep=0), ["10", "9"])
        self.assertEqual(select(runs, keep=1), ["10"])

    def test_older_than_days_cutoff_is_strict(self):
        now = 10 * DAY
        runs = [
            run("after", 7 * DAY + 1),
            run("edge", 7 * DAY),
            run("before", 7 * DAY - 1),
            run("epoch", 0),
        ]
        self.assertEqual(select(runs, older_than_days=3, now=now), ["epoch", "before"])

    def test_zero_days_selects_runs_started_before_now(self):
        now = 5000
        runs = [run("future", now + 1), run("same", now), run("past", now - 1)]
        self.assertEqual(select(runs, older_than_days=0, now=now), ["past"])

    def test_large_days_selects_nothing(self):
        runs = [run("a", 0), run("b", DAY)]
        self.assertEqual(select(runs, older_than_days=1000, now=10 * DAY), [])

    def test_older_than_days_result_is_oldest_first(self):
        now = 100 * DAY
        runs = [run("b", 5), run("c", 7), run("a", 5), run("z", 1)]
        self.assertEqual(select(runs, older_than_days=1, now=now), ["z", "a", "b", "c"])

    def test_older_than_days_is_measured_from_the_given_now(self):
        runs = [run("a", 4 * DAY)]
        self.assertEqual(select(runs, older_than_days=2, now=5 * DAY), [])
        self.assertEqual(select(runs, older_than_days=2, now=6 * DAY + 1), ["a"])

    def test_equal_started_values_at_and_before_the_cutoff(self):
        now = 10 * DAY
        cutoff = now - 3 * DAY
        runs = [
            run("d", cutoff),
            run("c", cutoff),
            run("b", cutoff - 1),
            run("a", cutoff - 1),
        ]
        self.assertEqual(select(runs, older_than_days=3, now=now), ["a", "b"])
        self.assertEqual(select(runs, keep=1, older_than_days=3, now=now), ["a", "b"])
        self.assertEqual(select(runs, keep=3, older_than_days=3, now=now), [])

    def test_keep_alone_does_not_need_now(self):
        runs = [run("a", 1), run("b", 2), run("c", 3)]
        self.assertEqual(select(runs, keep=1), ["a", "b"])
        self.assertEqual(select(runs, keep=1, now=None), ["a", "b"])

    def test_both_rules_need_both_to_select(self):
        now = 100 * DAY
        runs = [
            run("e", 99 * DAY),
            run("d", 95 * DAY),
            run("c", 30 * DAY),
            run("a", 10 * DAY),
            run("b", 20 * DAY),
            run("f", 1 * DAY, sealed=False),
            run("g", 2 * DAY, protected=True),
        ]
        self.assertEqual(select(runs, older_than_days=30, now=now), ["a", "b", "c"])
        self.assertEqual(select(runs, keep=1), ["a", "b", "c", "d"])
        self.assertEqual(select(runs, keep=1, older_than_days=30, now=now), ["a", "b", "c"])
        self.assertEqual(select(runs, keep=0, older_than_days=30, now=now), ["a", "b", "c"])
        self.assertEqual(select(runs, keep=4, older_than_days=30, now=now), ["a"])
        self.assertEqual(select(runs, keep=5, older_than_days=30, now=now), [])
        self.assertEqual(select(runs, keep=2, older_than_days=0, now=now), ["a", "b", "c"])

    def test_both_rules_with_cutoff_boundary(self):
        now = 10 * DAY
        runs = [run("a", 7 * DAY - 1), run("b", 7 * DAY), run("c", 7 * DAY + 1)]
        self.assertEqual(select(runs, keep=0, older_than_days=3, now=now), ["a"])
        self.assertEqual(select(runs, keep=1, older_than_days=3, now=now), ["a"])
        self.assertEqual(select(runs, keep=3, older_than_days=3, now=now), [])

    def test_negative_keep_raises(self):
        with self.assertRaises(ValueError):
            select([run("a", 1)], keep=-1)
        with self.assertRaises(ValueError):
            select([], keep=-1)
        with self.assertRaises(ValueError):
            select([run("a", 1)], keep=-1, older_than_days=1, now=10 * DAY)

    def test_negative_days_raises(self):
        with self.assertRaises(ValueError):
            select([run("a", 1)], older_than_days=-1, now=10 * DAY)
        with self.assertRaises(ValueError):
            select([], older_than_days=-1)
        with self.assertRaises(ValueError):
            select([run("a", 1)], keep=1, older_than_days=-1, now=10 * DAY)

    def test_zero_values_are_valid(self):
        runs = [run("a", 1)]
        self.assertEqual(select(runs, keep=0), ["a"])
        self.assertEqual(select(runs, older_than_days=0, now=2), ["a"])
        self.assertEqual(select(runs, keep=0, older_than_days=0, now=2), ["a"])

    def test_result_is_a_new_list_of_ids_and_input_is_unchanged(self):
        runs = [run("b", 2), run("a", 1), run("c", 3, protected=True)]
        before = copy.deepcopy(runs)
        result = select(runs, keep=0)
        self.assertIsInstance(result, list)
        self.assertEqual(result, ["a", "b"])
        for item in result:
            self.assertIsInstance(item, str)
        self.assertEqual(runs, before)
        result.append("x")
        self.assertEqual(runs, before)


if __name__ == "__main__":
    unittest.main()
