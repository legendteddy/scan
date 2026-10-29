"""ScanBench 2.0 external holdout precommitment tests."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from scan_core.errors import CommandError
from scan_core.scanbench2 import GROUND_TRUTH_VERSION, TRUTH_KINDS, load_ground_truth_file
from scan_core.scanbench2_holdout import (
    HOLDOUT_MANIFEST_VERSION,
    validate_holdout_manifest,
    verify_revealed_holdout,
)
from scan_core.scanbench2_review import fixture_source_digest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "scanbench" / "ground_truth" / "fixtures" / "authorization-ownership"


class ScanBench2HoldoutTests(unittest.TestCase):
    def _manifest(self, fixture: Path) -> dict:
        truth = load_ground_truth_file(fixture / "truth.json")
        counts = Counter(row["truth"] for row in truth["conditions"])
        return {
            "scanbench2_version": GROUND_TRUTH_VERSION,
            "holdout_manifest_version": HOLDOUT_MANIFEST_VERSION,
            "set_id": "private-holdout-a",
            "custodian": "independent-benchmark-custodian",
            "entries": [{
                "project_id": truth["project_id"],
                "fixture_digest": fixture_source_digest(fixture),
                "condition_count": len(truth["conditions"]),
                "truth_kind_counts": {kind: counts[kind] for kind in TRUTH_KINDS},
            }],
        }

    def test_precommit_verifies_exact_later_reveal(self):
        manifest = self._manifest(FIXTURE)
        result = verify_revealed_holdout(manifest, "authorization-ownership", FIXTURE)
        self.assertTrue(result["verified"])
        self.assertEqual(result["condition_count"], 4)
        self.assertIn("not reviewer independence", result["note"])

    def test_source_or_truth_mutation_breaks_precommitment(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "fixture"
            shutil.copytree(FIXTURE, fixture)
            manifest = self._manifest(fixture)
            app = fixture / "project" / "app.py"
            app.write_text(app.read_text(encoding="utf-8") + "\n# changed after precommit\n", encoding="utf-8")
            with self.assertRaisesRegex(CommandError, "digest"):
                verify_revealed_holdout(manifest, "authorization-ownership", fixture)

    def test_duplicate_project_ids_fail_closed(self):
        manifest = self._manifest(FIXTURE)
        manifest["entries"].append(deepcopy(manifest["entries"][0]))
        with self.assertRaisesRegex(CommandError, "duplicate holdout project_id"):
            validate_holdout_manifest(manifest)

    def test_truth_counts_must_sum_to_condition_count(self):
        manifest = self._manifest(FIXTURE)
        manifest["entries"][0]["truth_kind_counts"]["must_find"] += 1
        with self.assertRaisesRegex(CommandError, "sum to condition_count"):
            validate_holdout_manifest(manifest)

    def test_reveal_counts_are_checked_in_addition_to_digest(self):
        manifest = self._manifest(FIXTURE)
        # Recompute a syntactically valid precommit with dishonest count metadata.
        manifest["entries"][0]["condition_count"] = 5
        manifest["entries"][0]["truth_kind_counts"]["must_find"] = 2
        with self.assertRaisesRegex(CommandError, "condition_count"):
            verify_revealed_holdout(manifest, "authorization-ownership", FIXTURE)

    def test_schema_example_shape_contains_no_secret_fixture_content(self):
        schema = json.loads((ROOT / "scanbench" / "ground_truth" / "holdout-manifest-schema-v2.json").read_text(encoding="utf-8"))
        entry_properties = schema["properties"]["entries"]["items"]["properties"]
        self.assertEqual(
            set(entry_properties),
            {"project_id", "fixture_digest", "condition_count", "truth_kind_counts"},
        )
        self.assertNotIn("description", entry_properties)
        self.assertNotIn("artifact_locators", entry_properties)
        self.assertNotIn("truth", entry_properties)


if __name__ == "__main__":
    unittest.main()
