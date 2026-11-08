"""The admission pattern forecast is a true upper bound for the actual generator."""
from pathlib import Path
import sys
from unittest import TestCase

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skill/scripts'))
from operation_sdk import collect, policy
from tests.test_operation_sdk_policy import digest, example_policy, example_request

FACTOR, COUNT = 259, 15
# Quote/backslash runs, every UTF-8 width, mixed-width values (which keep the most
# distinct escape variants alive) and maximum-length strings.
ADVERSARIAL = ['"', '\\', 'é', '中', '\U0001f600', '"\\' * 40, 'é' + '"' * 4000,
    '\U0001f600' + '\\' * 4000, '"é\\\U0001f600中' * 400, 'é' * 4096,
    '\U0001f600' * 4096, 'aé"\\中\U0001f600' * 600, '\u0080߿ࠀ￿\U00010000\U0010ffff' * 600]


class PatternForecastBoundTests(TestCase):
    def test_actual_patterns_fit_the_forecast_for_adversarial_values(self):
        for value in ADVERSARIAL:
            value = value[:4096]
            size = len(value.encode('utf-8'))
            if size > 16384: value = value[:16384 // 4]; size = len(value.encode('utf-8'))
            limits = {'max_pattern_count': COUNT + 1, 'max_pattern_bytes': FACTOR * size,
                      'max_regex_bytes': 2 * FACTOR * size + 3 * COUNT}
            with self.subTest(value=value[:12], size=size):
                # Construction refuses (code 5) if real patterns exceed either forecast bound.
                collect.Patterns([value], limits)

    def redaction(self, reference_bytes, **limits):
        value = example_policy('redact_bytes_v1')
        value['deployment']['modules'] = {}
        value['scope'].update(store={'path': '/private/store', 'identity': [17, 25]},
                              coordination={'path': '/private/coord.lock', 'identity': [17, 26]},
                              references=[{'reference': 'REDACT_FAKE', 'alias': None, 'role': 'redaction',
                                  'value_contract': 'normalized_secret_1', 'identity': [17, 28],
                                  'size': reference_bytes, 'mtime_ns': 10, 'ctime_ns': 10}])
        value['limits'].update(**limits)
        return policy.compile_admission(value, example_request(value), trusted_policy_sha256=digest(value), now_ns=100)

    def test_maximum_size_reference_is_admissible_within_policy_ranges(self):
        # The former 1885x forecast capped all protected references at about 4.4 KB.
        compiled = self.redaction(16384)
        self.assertEqual(compiled.policy()['scope']['references'][0]['size'], 16384)

    def test_forecast_still_refuses_below_the_bound(self):
        with self.assertRaises(policy.PolicyError):
            self.redaction(16384, max_pattern_bytes=FACTOR * 16384 - 1)
        with self.assertRaises(policy.PolicyError):
            self.redaction(16384, max_regex_bytes=2 * FACTOR * 16384 + 3 * COUNT - 1)
