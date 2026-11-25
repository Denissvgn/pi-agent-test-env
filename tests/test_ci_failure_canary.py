"""Deliberate failure: a control that proves the required check blocks a merge.

This file must never reach main. Its pull request is closed without merging.
"""

import unittest


class CiFailureCanary(unittest.TestCase):
    def test_deliberate_failure(self) -> None:
        self.fail("deliberate failure: the required check must report this and block the merge")


if __name__ == "__main__":
    unittest.main()
