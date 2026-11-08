"""An explicit dedicated lease is selected only by an absolute PI_LAB_LOCK_FILE."""
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skill/scripts'))
import pi_lab


class DedicatedLeaseTests(unittest.TestCase):
    def test_unset_keeps_the_shared_host_lease(self):
        with mock.patch.dict(os.environ):
            os.environ.pop('PI_LAB_LOCK_FILE', None)
            self.assertEqual(pi_lab.default_lock_file(), pi_lab.host_lock_file())
            self.assertTrue(pi_lab.host_lock_file().endswith('/operation.lock'))

    def test_absolute_override_selects_the_dedicated_lease_for_every_command_default(self):
        lease = '/private/dedicated/campaign.lock'
        with mock.patch.dict(os.environ, {'PI_LAB_LOCK_FILE': lease}):
            self.assertEqual(pi_lab.default_lock_file(), lease)
            parser = pi_lab.parser()
            for argv in (['registry-inspect'], ['application-owner-inspect']):
                with self.subTest(argv=argv):
                    self.assertEqual(parser.parse_args(argv).lock_file, lease)

    def test_relative_or_empty_override_is_refused(self):
        for value in ('', 'relative/campaign.lock', './campaign.lock'):
            with self.subTest(value=value), mock.patch.dict(os.environ, {'PI_LAB_LOCK_FILE': value}):
                with self.assertRaises(SystemExit):
                    pi_lab.default_lock_file()


if __name__ == '__main__':
    unittest.main()
