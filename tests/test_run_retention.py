# Check file for run_retention.select. This header is the whole specification.
#
#     select(runs, keep=None, older_than_days=None, now=None) -> list of str
#
# Input
#   runs            a list of dicts: id (str), started (seconds since the epoch,
#                   int or float), sealed (bool) and protected (bool).
#   keep            None, or an integer >= 0.
#   older_than_days None, or a number >= 0 (it may be fractional); one day is
#                   86400 seconds.
#   now             None, or seconds since the epoch. None means the current
#                   time. It only matters together with older_than_days.
#
# Result
#   The ids of the runs to delete, as a new list, oldest first. Order is by
#   (started, id) ascending; ids compare as plain strings, so 'run-10' sorts
#   before 'run-9'. The input list and its dicts are never modified.
#
# Rules
#   1. A run that is not sealed, or is protected, is never selected and never
#      counts as a run to keep. Only sealed, unprotected runs are "eligible".
#   2. keep=N: of the eligible runs, the N newest are spared. Newest means the
#      greatest (started, id): when two runs have the same started, the one
#      with the greater id is newer. The other eligible runs are selected.
#      keep=0 spares nothing; keep larger than the number of eligible runs
#      spares all of them. keep=0 is a rule, unlike keep=None.
#   3. older_than_days=D: an eligible run is selected only when
#      started < now - D * 86400. A run that started exactly at that moment is
#      not selected. D=0 therefore selects runs that started before now.
#   4. With both keep and older_than_days, a run is selected only when both
#      rules select it. The keep rule ranks all eligible runs, whatever their
#      age; it does not rank only the runs that are old enough.
#   5. With neither keep nor older_than_days (both None), nothing is selected.
#   6. A negative keep or a negative older_than_days raises ValueError. The
#      arguments are validated even when runs is empty or no run is eligible.
#
# Boundaries covered below: empty input, equal timestamps, ties at the edge of
# keep, keep=0, days=0, the exact cutoff, fractional days, the default now,
# runs given out of order, and arguments that must stay unmodified.
#
# The file runs in the repository and, unchanged, in a scratch project: it
# puts skill/scripts (when present) and the working directory on the import
# path, and it is skipped while run_retention does not exist.
import copy
import sys
import time
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
    return run_retention.select(runs, **kwargs)


class RunRetentionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if run_retention is None:
            raise unittest.SkipTest('module not present')

    # Input and result shape

    def test_empty_runs_select_nothing(self):
        self.assertEqual(select([]), [])
        self.assertEqual(select([], keep=0), [])
        self.assertEqual(select([], keep=3), [])
        self.assertEqual(select([], older_than_days=0, now=NOW), [])
        self.assertEqual(select([], keep=1, older_than_days=1, now=NOW), [])

    def test_result_is_a_new_list_of_ids(self):
        runs = [run('a', 1), run('b', 2)]
        result = select(runs, keep=0)
        self.assertIsInstance(result, list)
        self.assertEqual(result, ['a', 'b'])
        self.assertTrue(all(isinstance(item, str) for item in result))
        self.assertIsNot(result, runs)

    def test_input_is_not_modified(self):
        runs = [run('c', 3), run('a', 1, protected=True), run('b', 2)]
        before = copy.deepcopy(runs)
        select(runs, keep=1, older_than_days=0, now=NOW)
        self.assertEqual(runs, before)

    def test_runs_given_out_of_order_are_returned_oldest_first(self):
        runs = [run('m', 50), run('z', 10), run('a', 90), run('k', 30)]
        self.assertEqual(select(runs, keep=0), ['z', 'k', 'm', 'a'])

    # Rule 5: neither rule

    def test_neither_rule_selects_nothing(self):
        runs = [run('a', 1), run('b', 2), run('c', 3)]
        self.assertEqual(select(runs), [])
        self.assertEqual(select(runs, keep=None, older_than_days=None), [])
        self.assertEqual(select(runs, now=NOW), [])

    # Rule 1: unsealed and protected runs

    def test_unsealed_run_is_never_selected(self):
        runs = [run('open', 1, sealed=False), run('done', 2)]
        self.assertEqual(select(runs, keep=0), ['done'])
        self.assertEqual(select(runs, older_than_days=0, now=NOW), ['done'])
        self.assertEqual(select(runs, keep=0, older_than_days=0, now=NOW), ['done'])

    def test_protected_run_is_never_selected(self):
        runs = [run('safe', 1, protected=True), run('done', 2)]
        self.assertEqual(select(runs, keep=0), ['done'])
        self.assertEqual(select(runs, older_than_days=0, now=NOW), ['done'])
        self.assertEqual(select(runs, keep=0, older_than_days=0, now=NOW), ['done'])

    def test_unsealed_and_protected_run_is_never_selected(self):
        runs = [run('both', 1, sealed=False, protected=True)]
        self.assertEqual(select(runs, keep=0, older_than_days=0, now=NOW), [])

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

    # Rule 2: keep

    def test_keep_spares_the_newest_and_selects_the_rest_oldest_first(self):
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
        self.assertEqual(select(runs, keep=1000), [])

    def test_keep_one_with_a_single_run(self):
        self.assertEqual(select([run('a', 1)], keep=1), [])
        self.assertEqual(select([run('a', 1)], keep=0), ['a'])

    # Ties and ordering

    def test_equal_started_ties_are_broken_by_id_when_keeping(self):
        runs = [run('c', 100), run('a', 100), run('b', 100)]
        # The greater id counts as newer, so it is the one spared.
        self.assertEqual(select(runs, keep=1), ['a', 'b'])
        self.assertEqual(select(runs, keep=2), ['a'])
        self.assertEqual(select(runs, keep=3), [])

    def test_tie_at_the_keep_edge_only_affects_the_tied_runs(self):
        runs = [run('x', 10), run('b', 20), run('a', 20), run('y', 30)]
        # Newest first: y, then b (greater id), then a, then x.
        self.assertEqual(select(runs, keep=2), ['x', 'a'])
        self.assertEqual(select(runs, keep=3), ['x'])

    def test_equal_started_ties_are_returned_in_id_order(self):
        runs = [run('c', 100), run('a', 100), run('b', 100)]
        self.assertEqual(select(runs, keep=0), ['a', 'b', 'c'])
        self.assertEqual(select(runs, older_than_days=0, now=NOW), ['a', 'b', 'c'])

    def test_order_follows_started_before_id(self):
        runs = [run('a', 20), run('b', 10)]
        self.assertEqual(select(runs, keep=0), ['b', 'a'])

    def test_ids_compare_as_plain_strings(self):
        runs = [run('run-9', 5), run('run-10', 5)]
        self.assertEqual(select(runs, keep=0), ['run-10', 'run-9'])
        self.assertEqual(select(runs, keep=1), ['run-10'])

    def test_fractional_started_values_are_ordered(self):
        runs = [run('b', 1.75), run('a', 1.5), run('c', 1.25)]
        self.assertEqual(select(runs, keep=1), ['c', 'a'])

    # Rule 3: older_than_days

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

    def test_fractional_days(self):
        cutoff = NOW - DAY//2
        runs = [run('old', cutoff - 1), run('edge', cutoff), run('new', cutoff + 1)]
        self.assertEqual(select(runs, older_than_days=0.5, now=NOW), ['old'])

    def test_age_rule_keeps_runs_in_started_order(self):
        runs = [run('b', 300), run('a', 100), run('c', 200)]
        self.assertEqual(select(runs, older_than_days=1, now=NOW), ['a', 'c', 'b'])

    def test_now_defaults_to_the_current_time(self):
        current = time.time()
        runs = [run('ancient', 0), run('recent', current - 60), run('future', current + 400*DAY)]
        self.assertEqual(select(runs, older_than_days=1), ['ancient'])
        self.assertEqual(select(runs, older_than_days=1, now=None), ['ancient'])

    def test_now_has_no_effect_without_older_than_days(self):
        runs = [run('a', 1), run('b', 2)]
        self.assertEqual(select(runs, now=NOW), [])
        self.assertEqual(select(runs, keep=1, now=0), ['a'])
        self.assertEqual(select(runs, keep=1, now=10**12), ['a'])

    # Rule 4: both rules

    def test_both_rules_select_only_the_intersection(self):
        cutoff = NOW - 10*DAY
        runs = [run('old1', cutoff - 300), run('old2', cutoff - 200), run('old3', cutoff - 100),
                run('new1', cutoff + 100), run('new2', cutoff + 200)]
        # keep spares new1 and new2 anyway; age spares nothing beyond them.
        self.assertEqual(select(runs, keep=2, older_than_days=10, now=NOW),
                         ['old1', 'old2', 'old3'])
        # keep=4 spares old2 and old3 as well, although both are old enough.
        self.assertEqual(select(runs, keep=4, older_than_days=10, now=NOW), ['old1'])
        # keep=0 leaves the age rule alone.
        self.assertEqual(select(runs, keep=0, older_than_days=10, now=NOW),
                         ['old1', 'old2', 'old3'])

    def test_keep_ranks_runs_regardless_of_age(self):
        cutoff = NOW - 10*DAY
        runs = [run('old1', cutoff - 200), run('old2', cutoff - 100), run('new', cutoff + 100)]
        # new is the newest, so keep=1 spares it and both old runs go (ranking
        # only the old runs would spare old2 and select old1 alone).
        self.assertEqual(select(runs, keep=1, older_than_days=10, now=NOW), ['old1', 'old2'])
        # Ranking only the old runs would spare both of them and select nothing.
        self.assertEqual(select(runs, keep=2, older_than_days=10, now=NOW), ['old1'])
        self.assertEqual(select(runs, keep=3, older_than_days=10, now=NOW), [])

    def test_age_spares_young_runs_that_keep_would_select(self):
        cutoff = NOW - 10*DAY
        runs = [run('old', cutoff - 100), run('young1', cutoff + 100), run('young2', cutoff + 200)]
        self.assertEqual(select(runs, keep=1, older_than_days=10, now=NOW), ['old'])
        self.assertEqual(select(runs, keep=0, older_than_days=10, now=NOW), ['old'])

    def test_both_rules_still_skip_unsealed_and_protected_runs(self):
        cutoff = NOW - DAY
        runs = [run('open', cutoff - 5, sealed=False), run('safe', cutoff - 4, protected=True),
                run('old', cutoff - 3), run('new', cutoff + 3)]
        self.assertEqual(select(runs, keep=1, older_than_days=1, now=NOW), ['old'])

    def test_both_rules_with_zero_keep_and_zero_days(self):
        runs = [run('past', NOW - 1), run('same', NOW)]
        self.assertEqual(select(runs, keep=0, older_than_days=0, now=NOW), ['past'])

    def test_both_rules_with_equal_started_ties(self):
        cutoff = NOW - DAY
        runs = [run('b', cutoff - 5), run('a', cutoff - 5), run('c', cutoff - 5)]
        self.assertEqual(select(runs, keep=1, older_than_days=1, now=NOW), ['a', 'b'])

    # Rule 6: negative arguments

    def test_negative_keep_raises_value_error(self):
        runs = [run('a', 1)]
        with self.assertRaises(ValueError):
            select(runs, keep=-1)
        with self.assertRaises(ValueError):
            select(runs, keep=-5, older_than_days=1, now=NOW)

    def test_negative_days_raise_value_error(self):
        runs = [run('a', 1)]
        with self.assertRaises(ValueError):
            select(runs, older_than_days=-1, now=NOW)
        with self.assertRaises(ValueError):
            select(runs, older_than_days=-0.5, now=NOW)
        with self.assertRaises(ValueError):
            select(runs, keep=1, older_than_days=-1, now=NOW)

    def test_negative_arguments_raise_without_runs_or_eligible_runs(self):
        with self.assertRaises(ValueError):
            select([], keep=-1)
        with self.assertRaises(ValueError):
            select([], older_than_days=-1, now=NOW)
        with self.assertRaises(ValueError):
            select([run('a', 1, sealed=False)], keep=-1)
        with self.assertRaises(ValueError):
            select([run('a', 1, protected=True)], older_than_days=-1)

    def test_negative_argument_raises_even_when_now_is_omitted(self):
        with self.assertRaises(ValueError):
            select([run('a', 1)], older_than_days=-1)


if __name__ == '__main__':
    unittest.main()
