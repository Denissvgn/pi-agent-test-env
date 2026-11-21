# Check file for run_retention.select. This header is the whole specification.
#
#     select(runs, keep=None, older_than_days=None, now=None)
#
# Specification
#   runs is a list of dicts with id (str), started (seconds since the epoch),
#   sealed (bool) and protected (bool). select returns the ids of the runs to
#   delete, oldest first.
#   - An unsealed or protected run is never selected.
#   - With keep, the keep newest sealed, unprotected runs are spared, ties
#     broken by id.
#   - With older_than_days, only runs started before now minus that many days
#     are selected.
#   - With both, a run is selected only when both rules select it.
#   - With neither, nothing is selected.
#   - A negative keep or a negative number of days raises ValueError.
#   - select is a pure function of its arguments.
#
# How the checks read it
#   - "Eligible" means sealed and not protected. Runs that are not eligible do
#     not use up keep slots: keep ranks the eligible runs only.
#   - keep=0 spares nothing (it is a rule, unlike keep=None); a keep at or above
#     the number of eligible runs spares them all.
#   - "Started before" is strict: a run that started exactly at now minus the
#     days is not selected, and with 0 days a run that started exactly at now
#     is not selected. A day is 86400 seconds.
#   - With both rules the keep rule still ranks every eligible run, whatever its
#     age, and the age rule then removes the runs that are not old enough.
#   - now is the reference time for older_than_days. The checks always pass it
#     explicitly when they use older_than_days, so a synthetic now fixes every
#     boundary.
#   - Oldest first is checked for runs whose started values differ.
#   - A negative keep or a negative number of days raises ValueError from the
#     call itself, whatever runs holds: an empty list and a list of runs that are
#     all ineligible are refused like any other, and an invalid argument is never
#     hidden in the returned value. The checks call select directly and do not
#     iterate its result for these.
#   - Pure means the call does not modify its arguments, checked when the call
#     returns.
#
# Ties
#   The brief says only "ties broken by id", so no order of ids is assumed. For
#   runs with equal started values the checks require exactly the right number
#   of runs to be spared, that the runs with different started values are
#   handled correctly around them, and that the answer is the same whatever
#   order the runs are given in.
#
# Not specified, so not checked: the direction of the id tie-break, the order of
# equal-started runs in the result, what now=None means, whether the result
# shares objects with the arguments or changes when they change later, and
# non-integer numbers.
#
# The file runs in the repository and, unchanged, in a scratch project: it
# puts skill/scripts (when present) and the working directory on the import
# path, and it is skipped while run_retention does not exist.
import copy
import itertools
import sys
import unittest
from pathlib import Path

for _dir in (Path(__file__).resolve().parents[1]/'skill'/'scripts',
             Path.cwd()/'skill'/'scripts', Path.cwd()):
    if _dir.is_dir() and str(_dir) not in sys.path:
        sys.path.insert(0, str(_dir))
try:
    import run_retention
except ModuleNotFoundError as exc:
    if exc.name != 'run_retention':
        raise
    run_retention = None

DAY = 86400
NOW = 10_000_000


def run(run_id, started, sealed=True, protected=False):
    return {'id': run_id, 'started': started, 'sealed': sealed, 'protected': protected}


def select(runs, **kwargs):
    before = copy.deepcopy(runs)
    result = run_retention.select(runs, **kwargs)
    if runs != before:
        raise AssertionError('select modified its runs argument')
    return list(result)


class RunRetentionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if run_retention is None:
            raise unittest.SkipTest('module not present')

    # Empty input, neither rule, order

    def test_empty_runs_select_nothing(self):
        self.assertEqual(select([]), [])
        self.assertEqual(select([], keep=0), [])
        self.assertEqual(select([], keep=3), [])
        self.assertEqual(select([], older_than_days=0, now=NOW), [])
        self.assertEqual(select([], keep=1, older_than_days=1, now=NOW), [])

    def test_neither_rule_selects_nothing(self):
        runs = [run('a', 1), run('b', 2), run('c', 3)]
        self.assertEqual(select(runs), [])
        self.assertEqual(select(runs, keep=None, older_than_days=None), [])
        self.assertEqual(select(runs, now=NOW), [])

    def test_selected_ids_are_oldest_first(self):
        runs = [run('m', 50), run('z', 10), run('a', 90), run('k', 30)]
        self.assertEqual(select(runs, keep=0), ['z', 'k', 'm', 'a'])
        self.assertEqual(select(runs, older_than_days=0, now=NOW), ['z', 'k', 'm', 'a'])

    # Unsealed and protected runs

    def test_unsealed_and_protected_runs_are_never_selected(self):
        runs = [run('open', 1, sealed=False), run('safe', 2, protected=True),
                run('both', 3, sealed=False, protected=True), run('done', 4)]
        self.assertEqual(select(runs, keep=0), ['done'])
        self.assertEqual(select(runs, older_than_days=0, now=NOW), ['done'])
        self.assertEqual(select(runs, keep=0, older_than_days=0, now=NOW), ['done'])

    def test_only_ineligible_runs_select_nothing(self):
        runs = [run('a', 1, sealed=False), run('b', 2, protected=True)]
        self.assertEqual(select(runs, keep=0), [])

    def test_ineligible_runs_do_not_use_up_keep_slots(self):
        runs = [run('old1', 1), run('old2', 2), run('new', 3),
                run('newer-open', 4, sealed=False), run('newest-safe', 5, protected=True)]
        # Only old1, old2 and new are eligible; the newest of them is spared.
        self.assertEqual(select(runs, keep=1), ['old1', 'old2'])
        self.assertEqual(select(runs, keep=2), ['old1'])
        self.assertEqual(select(runs, keep=3), [])

    # keep

    def test_keep_spares_the_newest_and_selects_the_rest(self):
        runs = [run(str(i), i) for i in (5, 3, 1, 4, 2)]
        self.assertEqual(select(runs, keep=2), ['1', '2', '3'])
        self.assertEqual(select(runs, keep=4), ['1'])

    def test_keep_zero_selects_every_eligible_run(self):
        runs = [run('b', 2), run('a', 1), run('p', 3, protected=True)]
        self.assertEqual(select(runs, keep=0), ['a', 'b'])

    def test_keep_at_or_above_the_eligible_count_selects_nothing(self):
        runs = [run('a', 1), run('b', 2), run('c', 3)]
        self.assertEqual(select(runs, keep=3), [])
        self.assertEqual(select(runs, keep=4), [])
        self.assertEqual(select([run('a', 1)], keep=1), [])

    # Ties (equal started values)

    def test_equal_started_values_give_one_answer_for_any_input_order(self):
        runs = [run('a', 100), run('b', 100), run('c', 100)]
        for keep in (0, 1, 2, 3):
            results = [select(list(order), keep=keep) for order in itertools.permutations(runs)]
            with self.subTest(keep=keep):
                for result in results:
                    self.assertEqual(result, results[0])
                    self.assertEqual(len(set(result)), 3 - keep)
                    self.assertTrue(set(result) <= {'a', 'b', 'c'})

    def test_a_tie_at_the_keep_edge_only_affects_the_tied_runs(self):
        runs = [run('x', 10), run('t1', 20), run('t2', 20), run('y', 30)]
        # y is the newest. The tied runs are next, and keep=2 spares only one of them.
        for keep, tied_selected in ((1, 2), (2, 1), (3, 0)):
            results = [select(list(order), keep=keep) for order in itertools.permutations(runs)]
            with self.subTest(keep=keep):
                for result in results:
                    self.assertEqual(result, results[0])
                    self.assertEqual(result[0], 'x')
                    self.assertEqual(len(result), 1 + tied_selected)
                    self.assertEqual(len(set(result[1:])), tied_selected)
                    self.assertTrue(set(result[1:]) <= {'t1', 't2'})

    def test_equal_started_runs_are_selected_together_by_the_age_rule(self):
        runs = [run('b', 100), run('a', 100), run('new', NOW)]
        result = select(runs, older_than_days=1, now=NOW)
        self.assertEqual(sorted(result), ['a', 'b'])

    # older_than_days

    def test_older_than_days_selects_runs_before_the_cutoff(self):
        cutoff = NOW - 2*DAY
        runs = [run('old', cutoff - 10), run('edge', cutoff), run('new', cutoff + 10)]
        self.assertEqual(select(runs, older_than_days=2, now=NOW), ['old'])

    def test_run_started_exactly_at_the_cutoff_is_not_selected(self):
        cutoff = NOW - 7*DAY
        self.assertEqual(select([run('edge', cutoff)], older_than_days=7, now=NOW), [])
        self.assertEqual(select([run('just', cutoff - 1)], older_than_days=7, now=NOW), ['just'])

    def test_zero_days_selects_runs_started_before_now(self):
        runs = [run('past', NOW - 1), run('same', NOW), run('future', NOW + 1)]
        self.assertEqual(select(runs, older_than_days=0, now=NOW), ['past'])

    # Both rules

    def test_both_rules_select_only_the_intersection(self):
        cutoff = NOW - 10*DAY
        runs = [run('old1', cutoff - 300), run('old2', cutoff - 200), run('old3', cutoff - 100),
                run('new1', cutoff + 100), run('new2', cutoff + 200)]
        # keep=2 spares new1 and new2, which the age rule would spare anyway.
        self.assertEqual(select(runs, keep=2, older_than_days=10, now=NOW),
                         ['old1', 'old2', 'old3'])
        # keep=4 also spares old2 and old3, although both are old enough.
        self.assertEqual(select(runs, keep=4, older_than_days=10, now=NOW), ['old1'])
        # keep=0 leaves the age rule alone.
        self.assertEqual(select(runs, keep=0, older_than_days=10, now=NOW),
                         ['old1', 'old2', 'old3'])

    def test_keep_ranks_all_eligible_runs_whatever_their_age(self):
        cutoff = NOW - 10*DAY
        runs = [run('old1', cutoff - 200), run('old2', cutoff - 100), run('new', cutoff + 100)]
        # new is the newest of all, so keep=1 spares it and both old runs go.
        self.assertEqual(select(runs, keep=1, older_than_days=10, now=NOW), ['old1', 'old2'])
        # keep=2 spares new and old2.
        self.assertEqual(select(runs, keep=2, older_than_days=10, now=NOW), ['old1'])

    def test_age_spares_young_runs_that_keep_would_select(self):
        cutoff = NOW - 10*DAY
        runs = [run('old', cutoff - 100), run('young1', cutoff + 100), run('young2', cutoff + 200)]
        self.assertEqual(select(runs, keep=1, older_than_days=10, now=NOW), ['old'])

    def test_both_rules_still_skip_unsealed_and_protected_runs(self):
        cutoff = NOW - DAY
        runs = [run('open', cutoff - 5, sealed=False), run('safe', cutoff - 4, protected=True),
                run('old', cutoff - 3), run('new', cutoff + 3)]
        self.assertEqual(select(runs, keep=1, older_than_days=1, now=NOW), ['old'])

    # Negative arguments

    def refuses(self, runs, **kwargs):
        # The call itself must raise: the result is not consumed here.
        with self.assertRaises(ValueError):
            run_retention.select(copy.deepcopy(runs), **kwargs)

    NO_RUNS = []
    ALL_INELIGIBLE = [run('open', 1, sealed=False), run('safe', 2, protected=True),
                      run('both', 3, sealed=False, protected=True)]

    def test_negative_keep_raises_value_error(self):
        runs = [run('a', 1), run('b', 2)]
        self.refuses(runs, keep=-1)
        self.refuses(runs, keep=-5, older_than_days=1, now=NOW)

    def test_negative_days_raise_value_error(self):
        runs = [run('a', 1), run('b', 2)]
        self.refuses(runs, older_than_days=-1, now=NOW)
        self.refuses(runs, keep=1, older_than_days=-1, now=NOW)

    def test_negative_keep_raises_for_empty_and_all_ineligible_runs(self):
        for name, runs in (('empty', self.NO_RUNS), ('ineligible', self.ALL_INELIGIBLE)):
            with self.subTest(runs=name):
                self.refuses(runs, keep=-1)
                self.refuses(runs, keep=-7)
                self.refuses(runs, keep=-1, older_than_days=1, now=NOW)
                self.refuses(runs, keep=-1, older_than_days=0, now=NOW)

    def test_negative_days_raise_for_empty_and_all_ineligible_runs(self):
        for name, runs in (('empty', self.NO_RUNS), ('ineligible', self.ALL_INELIGIBLE)):
            with self.subTest(runs=name):
                self.refuses(runs, older_than_days=-1, now=NOW)
                self.refuses(runs, older_than_days=-30, now=NOW)
                self.refuses(runs, keep=0, older_than_days=-1, now=NOW)
                self.refuses(runs, keep=3, older_than_days=-1, now=NOW)


if __name__ == '__main__':
    unittest.main()
