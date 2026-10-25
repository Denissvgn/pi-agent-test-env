"""Current archive guidance follows metadata; historical discovery stays scoped."""
import json
from pathlib import Path
import re
import sys
import unittest

SKILL = Path(__file__).resolve().parents[1] / 'skill'
sys.path.insert(0, str(SKILL / 'scripts'))
import export_skill as exporter


class HarnessVersionTests(unittest.TestCase):
    def setUp(self):
        self.guide = (SKILL / 'references/HARNESSES.md').read_text()
        self.metadata = json.loads((SKILL / 'skill.json').read_text())

    def test_current_archive_guidance_matches_metadata_and_actual_export_names(self):
        archive_section = self.guide.split('## Archive installation', 1)[1].split('\n## ', 1)[0]
        current = re.findall(r'The package version is ([0-9]+\.[0-9]+\.[0-9]+)\.', archive_section)
        self.assertEqual(current, [self.metadata['version']])
        documented = set(re.findall(r'^\| `([^`]+\.zip)` \|', archive_section, re.MULTILINE))
        expected = set(exporter.archive_specs(SKILL))
        self.assertEqual(documented, expected)
        self.assertIn(f"{self.metadata['name']}-{self.metadata['version']}.zip", documented)

    def test_discovery_observations_retain_historical_versions_and_qualification_limits(self):
        observed = self.guide.split('## Observed compatibility', 1)[1]
        rows = [row for row in observed.splitlines() if row.startswith('| ') and not row.startswith('| Parent')]
        codex = next(row for row in rows if row.startswith('| Codex CLI'))
        antigravity = next(row for row in rows if row.startswith('| Antigravity CLI'))
        self.assertIn('0.144.6', codex)
        self.assertIn('4.0.1', codex)
        self.assertIn('no automatic relevance selection or parent model turn', codex)
        for version in ['1.2.9', '1.3.1', '3.0.0', '4.0.0', '4.0.1']:
            self.assertIn(version, antigravity)
        self.assertIn('unqualified', antigravity)
        self.assertIn('current package has no new discovery qualification', antigravity)
        self.assertNotIn('4.2.0', antigravity)
        self.assertIn('2026-10-07', self.guide)


if __name__ == '__main__':
    unittest.main()
