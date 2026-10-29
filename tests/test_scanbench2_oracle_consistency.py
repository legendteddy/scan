"""ScanBench 2.0 mutation/oracle-consistency tests."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from scan_core.errors import CommandError
from scan_core.scanbench2_oracle_consistency import (
    ORACLE_CONSISTENCY_VERSION,
    project_source_digest,
    verify_oracle_consistency,
)
from scan_core.scanbench2_review import fixture_source_digest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scanbench" / "ground_truth" / "fixtures" / "authorization-ownership"


class ScanBench2OracleConsistencyTests(unittest.TestCase):
    def _variant(self, root: Path):
        original = root / "original"
        variant = root / "variant"
        (original / "project").mkdir(parents=True)
        (variant / "project").mkdir(parents=True)
        source_text = (SOURCE / "project" / "app.py").read_text(encoding="utf-8-sig")
        truth = json.loads((SOURCE / "truth.json").read_text(encoding="utf-8-sig"))
        (original / "project" / "app.py").write_text(source_text, encoding="utf-8")
        (original / "truth.json").write_text(json.dumps(truth), encoding="utf-8")

        variant_truth = deepcopy(truth)
        variant_truth["project_id"] = "authorization-ownership-mutated"
        condition_map = {}
        for index, condition in enumerate(variant_truth["conditions"], start=1):
            original_id = condition["id"]
            variant_id = f"MUT-{index:03d}"
            condition["id"] = variant_id
            condition_map[original_id] = variant_id
        (variant / "project" / "app.py").write_text(
            "# semantics-preserving comment mutation\n" + source_text,
            encoding="utf-8",
        )
        (variant / "truth.json").write_text(json.dumps(variant_truth), encoding="utf-8")
        manifest = {
            "scanbench2_version": "2.0-alpha1",
            "oracle_consistency_version": ORACLE_CONSISTENCY_VERSION,
            "transformation_id": "comment-prefix-and-randomized-condition-ids",
            "equivalence_claim": "semantics-preserving",
            "original_project_id": truth["project_id"],
            "variant_project_id": variant_truth["project_id"],
            "original_fixture_digest": fixture_source_digest(original),
            "variant_fixture_digest": fixture_source_digest(variant),
            "original_project_digest": project_source_digest(original),
            "variant_project_digest": project_source_digest(variant),
            "condition_map": condition_map,
            "artifact_map": {},
        }
        return original, variant, manifest

    def test_source_mutation_and_randomized_condition_ids_preserve_oracle(self):
        with tempfile.TemporaryDirectory() as directory:
            original, variant, manifest = self._variant(Path(directory))
            result = verify_oracle_consistency(original, variant, manifest)
        self.assertTrue(result["oracle_consistent"])
        self.assertEqual(result["condition_count"], 4)
        self.assertNotEqual(result["original_project_digest"], result["variant_project_digest"])
        self.assertEqual(
            {row["variant_condition_id"] for row in result["conditions"]},
            {"MUT-001", "MUT-002", "MUT-003", "MUT-004"},
        )

    def test_truth_drift_under_equivalence_claim_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            original, variant, manifest = self._variant(Path(directory))
            truth_path = variant / "truth.json"
            truth = json.loads(truth_path.read_text(encoding="utf-8"))
            truth["conditions"][0]["truth"] = "must_not_find"
            truth_path.write_text(json.dumps(truth), encoding="utf-8")
            manifest["variant_fixture_digest"] = fixture_source_digest(variant)
            with self.assertRaisesRegex(CommandError, "oracle drift"):
                verify_oracle_consistency(original, variant, manifest)

    def test_truth_only_change_does_not_count_as_source_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            original, variant, manifest = self._variant(Path(directory))
            source_text = (original / "project" / "app.py").read_text(encoding="utf-8")
            (variant / "project" / "app.py").write_text(source_text, encoding="utf-8")
            manifest["variant_project_digest"] = project_source_digest(variant)
            manifest["variant_fixture_digest"] = fixture_source_digest(variant)
            with self.assertRaisesRegex(CommandError, "must change project source bytes"):
                verify_oracle_consistency(original, variant, manifest)


if __name__ == "__main__":
    unittest.main()
