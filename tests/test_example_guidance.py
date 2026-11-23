import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ExampleGuidanceTests(unittest.TestCase):
    def test_authenticated_guide_defers_release_list_to_compatibility_reference(self):
        guide = (ROOT / "skill/examples/authenticated-application/README.md").read_text()
        self.assertIn("an exact", guide)
        self.assertIn("../../references/PI-COMPATIBILITY.md", guide)
        self.assertNotRegex(guide, r"Pi [0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}")

    def test_indexed_guide_documents_existing_configure_options_and_campaign_reference(self):
        guide = (ROOT / "skill/examples/indexed-inference/README.md").read_text()
        command = """python3 "$SKILL_DIR/examples/indexed-inference/configure.py" --image-receipt "$IMAGE_RECEIPT" --output-dir /path/to/new-definitions --a builder-local --b reviewer-local"""
        self.assertIn(command, guide)
        self.assertNotRegex(guide, r"Pi [0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}")
        self.assertIn("../../QUALIFICATION.md", guide)
        help_text = subprocess.run(
            [sys.executable, str(ROOT / "skill/examples/indexed-inference/configure.py"), "--help"],
            check=True, capture_output=True, text=True,
        ).stdout
        for option in ("--image-receipt", "--output-dir", "--a", "--b"):
            self.assertIn(option, help_text)

    def test_baseline_marks_observations_as_dated_and_links_current_scope(self):
        guide = (ROOT / "skill/examples/application-baseline/README.md").read_text()
        self.assertIn("dated Docker/Pi observations from", guide)
        self.assertIn("../../QUALIFICATION.md", guide)
        self.assertNotRegex(guide, r"Pi [0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}")


if __name__ == "__main__":
    unittest.main()
