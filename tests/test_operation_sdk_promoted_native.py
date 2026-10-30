"""Replay the independent primitive regressions against the installed SDK copy."""
import io
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'skill/scripts'))
from operation_sdk import secret_registration_contract as model
from operation_sdk import secret_registration_primitive as primitive
from operation_sdk import secret_registration_posix as native
from tests import test_secret_registration_contract as contract_tests
from tests import test_secret_registration_primitive as primitive_tests
from tests import test_secret_registration_posix as native_tests


class SDKNativePromotionTests(unittest.TestCase):
    def test_all_existing_independent_regressions_apply_to_the_installed_copies(self):
        suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromModule(module)
                                 for module in(contract_tests,primitive_tests,native_tests))
        output=io.StringIO()
        with (mock.patch.object(contract_tests,'contract',model),
              mock.patch.object(primitive_tests,'model',model),
              mock.patch.object(primitive_tests,'primitive',primitive),
              mock.patch.object(native_tests,'native',native)):
            result=unittest.TextTestRunner(stream=output).run(suite)
        self.assertEqual(result.testsRun,53)
        self.assertFalse(result.skipped)
        self.assertTrue(result.wasSuccessful(),output.getvalue())
