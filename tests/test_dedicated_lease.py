"""An explicit dedicated lease is selected only by an absolute PI_LAB_LOCK_FILE."""
import os
import io
import json
from pathlib import Path
import sys
import unittest
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skill/scripts'))
import pi_lab


class DedicatedLeaseTests(unittest.TestCase):
    def test_doctor_python_floor_is_312(self):
        self.assertEqual(pi_lab.python_floor_check((3,11,99), '3.11.99'), ('fail','3.11.99'))
        self.assertEqual(pi_lab.python_floor_check((3,12,0), '3.12.0'), ('ok','3.12.0'))

    def test_explicit_doctor_lease_does_not_resolve_unavailable_home(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(Path, 'home', side_effect=RuntimeError('uid has no passwd entry')), \
             mock.patch.object(pi_lab, 'docker_info', side_effect=pi_lab.LabError('Docker unavailable','docker-cli-missing')):
            output=io.StringIO()
            with redirect_stdout(output):
                pi_lab.main(['doctor','--lock-file','/tmp/explicit.lock','--skip-network'])
            checks=json.loads(output.getvalue())['checks']
            observed=next(item for item in checks if item['check']=='host-lock')
        self.assertEqual(observed['selected_by'],'--lock-file')
        self.assertEqual(observed['state'],'free')

    def test_default_doctor_lease_without_home_warns_instead_of_failing(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(Path, 'home', side_effect=RuntimeError('uid has no passwd entry')), \
             mock.patch.object(pi_lab, 'docker_info', side_effect=pi_lab.LabError('Docker unavailable','docker-cli-missing')):
            output=io.StringIO()
            with redirect_stdout(output):
                pi_lab.main(['doctor','--skip-network'])
            checks=json.loads(output.getvalue())['checks']
            observed=next(item for item in checks if item['check']=='host-lock')
        self.assertEqual((observed['status'],observed['state']),('warn','unknown'))
        self.assertIn('--lock-file',observed['detail'])

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
