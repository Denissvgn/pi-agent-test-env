"""Isolated CI negative control. This branch must never be merged."""
import unittest


class IntentionalFailure(unittest.TestCase):
    def test_required_ci_gate_reports_failure(self):
        self.fail("Intentional CI negative control")
