"""Fresh confirmation metadata controls; no real environment/session is read."""
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'skill/scripts'))
import lab_env


class OneShotConfirmationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.state = self.root / 'state'; self.state.mkdir(mode=0o700)
        self.config = self.root / 'controlled-config'; self.config.mkdir(mode=0o700)
        patch = mock.patch.object(lab_env, 'state_dir', return_value=self.state); patch.start(); self.addCleanup(patch.stop)
        patch = mock.patch.object(lab_env, 'config_dir', return_value=self.config); patch.start(); self.addCleanup(patch.stop)

    def test_fresh_record_preserves_expired_and_other_session_bytes_and_times(self):
        sessions = self.state / 'sessions'; sessions.mkdir(mode=0o700)
        old = sessions / 'old.json'; old.write_bytes(b'preserved-old-evidence'); old.chmod(0o600)
        past = time.time() - 30 * 86400; os.utime(old, (past, past))
        before = old.stat()
        with mock.patch.object(lab_env, 'purge_old_sessions', side_effect=AssertionError('No TTL maintenance')):
            result = lab_env.confirm_session_once('pl-controlled', 'env:012345abcdef')
        self.assertEqual(old.read_bytes(), b'preserved-old-evidence')
        self.assertEqual((before.st_ino, before.st_mtime_ns, before.st_ctime_ns),
                         (old.stat().st_ino, old.stat().st_mtime_ns, old.stat().st_ctime_ns))
        current = sessions / 'pl-controlled.json'
        self.assertEqual(json.loads(current.read_text()), result)
        self.assertEqual(stat.S_IMODE(current.stat().st_mode), 0o600)
        self.assertEqual(set(result), {'session', 'confirmed_fingerprint', 'confirmed_at'})

    def test_existing_record_is_never_replaced_even_for_same_fingerprint(self):
        lab_env.confirm_session_once('pl-controlled', 'env:012345abcdef')
        path = lab_env.session_path('pl-controlled'); before = (path.read_bytes(), path.stat())
        with self.assertRaises(lab_env.EnvError) as caught:
            lab_env.confirm_session_once('pl-controlled', 'env:012345abcdef')
        self.assertEqual(caught.exception.reason, 'confirmation-conflict')
        self.assertEqual(before[0], path.read_bytes())
        self.assertEqual(before[1].st_ino, path.stat().st_ino)

    def test_original_confirmation_gate_accepts_matching_endpoint_and_denies_drift(self):
        endpoint = {'base_url': 'http://172.17.0.1:19081/v1', 'model': 'controlled-fixture',
                    'context_window': 262144, 'max_tokens': 8192, 'api_key_env': 'PI_FIXTURE_KEY', 'input': ['text']}
        meta = lab_env.save_environment(endpoint)
        with mock.patch.object(lab_env, 'health_check', side_effect=AssertionError('No live health in metadata test')):
            lab_env.confirm_session_once('pl-controlled', meta['fingerprint'])
            self.assertEqual(lab_env.evaluate('pl-controlled', check=False)['state'], 'ready')
            changed = dict(endpoint, model='other')
            lab_env.save_environment(changed)
            self.assertEqual(lab_env.evaluate('pl-controlled', check=False)['state'], 'needs-confirmation')

    def test_invalid_identity_or_fingerprint_writes_nothing(self):
        for session, fingerprint in [('../foreign', 'env:012345abcdef'), ('ok', 'x'),
                                     ('ok', 'env:012345abcdef/secret'), ('ok', True)]:
            with self.subTest(session=session), self.assertRaises(lab_env.EnvError):
                lab_env.confirm_session_once(session, fingerprint)
        self.assertFalse((self.state / 'sessions').exists())

    def test_symlinked_session_directory_or_leaf_is_denied(self):
        target = self.root / 'foreign'; target.mkdir(mode=0o700)
        (self.state / 'sessions').symlink_to(target, target_is_directory=True)
        with self.assertRaises(OSError): lab_env.confirm_session_once('pl-controlled', 'env:012345abcdef')
        self.assertEqual(list(target.iterdir()), [])
        (self.state / 'sessions').unlink(); (self.state / 'sessions').mkdir(mode=0o700)
        victim = target / 'evidence'; victim.write_bytes(b'untouched')
        lab_env.session_path('pl-controlled').symlink_to(victim)
        with self.assertRaises(lab_env.EnvError): lab_env.confirm_session_once('pl-controlled', 'env:012345abcdef')
        self.assertEqual(victim.read_bytes(), b'untouched')

    def test_existing_insecure_directory_is_not_chmodded_or_used(self):
        sessions = self.state / 'sessions'; sessions.mkdir(mode=0o755)
        with self.assertRaises(lab_env.EnvError): lab_env.confirm_session_once('pl-controlled', 'env:012345abcdef')
        self.assertEqual(stat.S_IMODE(sessions.stat().st_mode), 0o755)
        self.assertEqual(list(sessions.iterdir()), [])

    def test_default_confirmation_retains_original_maintenance_behavior(self):
        with mock.patch.object(lab_env, 'purge_old_sessions') as maintenance:
            lab_env.confirm_session('legacy-session', 'legacy-fingerprint')
        maintenance.assert_called_once_with()
        self.assertEqual(lab_env.read_session('legacy-session')['confirmed_fingerprint'], 'legacy-fingerprint')


if __name__ == '__main__':
    unittest.main()
