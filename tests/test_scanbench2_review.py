"""ScanBench 2.0 independent review receipt tests."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import shutil
import tempfile
import unittest

from scan_core.errors import CommandError
from scan_core.scanbench2 import load_ground_truth_file
from scan_core.scanbench2_review import (
    REVIEW_RECEIPT_VERSION,
    fixture_source_digest,
    validate_review_receipt,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "scanbench" / "ground_truth" / "fixtures" / "authorization-ownership"


class ScanBench2ReviewTests(unittest.TestCase):
    def _receipt(self, fixture: Path) -> dict:
        truth = load_ground_truth_file(fixture / "truth.json")
        return {
            "scanbench2_version": truth["scanbench2_version"],
            "review_receipt_version": REVIEW_RECEIPT_VERSION,
            "project_id": truth["project_id"],
            "fixture_digest": fixture_source_digest(fixture),
            "reviewer": "independent-reviewer-1",
            "reviewer_role": "benchmark-ground-truth-review",
            "independent_of_fixture_author": True,
            "decision": "approved",
            "reviewed_condition_ids": [row["id"] for row in truth["conditions"]],
            "notes": "Reviewed source and negative/unknown controls against the stated oracle.",
        }

    def test_independent_approval_binds_exact_fixture_bytes_and_all_conditions(self):
        receipt = self._receipt(FIXTURE)
        validated = validate_review_receipt(receipt, FIXTURE)
        self.assertEqual(validated["decision"], "approved")
        self.assertTrue(validated["independent_of_fixture_author"])
        self.assertEqual(validated["fixture_digest"], fixture_source_digest(FIXTURE))

    def test_fixture_mutation_invalidates_existing_review_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "fixture"
            shutil.copytree(FIXTURE, fixture)
            receipt = self._receipt(fixture)
            app = fixture / "project" / "app.py"
            app.write_text(app.read_text(encoding="utf-8") + "\n# semantics-preserving review invalidation\n", encoding="utf-8")
            with self.assertRaisesRegex(CommandError, "fixture_digest"):
                validate_review_receipt(receipt, fixture)

    def test_review_must_cover_every_condition_exactly(self):
        receipt = self._receipt(FIXTURE)
        receipt["reviewed_condition_ids"] = receipt["reviewed_condition_ids"][:-1]
        with self.assertRaisesRegex(CommandError, "condition coverage mismatch"):
            validate_review_receipt(receipt, FIXTURE)

    def test_approved_receipt_cannot_claim_author_self_review_as_independent(self):
        receipt = self._receipt(FIXTURE)
        receipt["independent_of_fixture_author"] = False
        with self.assertRaisesRegex(CommandError, "must be independent"):
            validate_review_receipt(receipt, FIXTURE)

    def test_wrong_project_or_stale_digest_fails_closed(self):
        receipt = self._receipt(FIXTURE)
        wrong_project = deepcopy(receipt)
        wrong_project["project_id"] = "other-project"
        with self.assertRaisesRegex(CommandError, "project_id"):
            validate_review_receipt(wrong_project, FIXTURE)
        stale = deepcopy(receipt)
        stale["fixture_digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(CommandError, "fixture_digest"):
            validate_review_receipt(stale, FIXTURE)


if __name__ == "__main__":
    unittest.main()
