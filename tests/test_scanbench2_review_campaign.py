"""ScanBench 2.0 corpus-wide independent-review campaign tests."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scan_core.scanbench2_review import review_request
from scan_core.scanbench2_review_campaign import prepare_campaign, summarize_review_coverage

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "scanbench" / "ground_truth"


class ScanBench2ReviewCampaignTests(unittest.TestCase):
    def test_prepare_campaign_contains_no_approval_evidence(self):
        campaign = prepare_campaign(CORPUS)
        self.assertEqual(campaign["project_count"], 26)
        self.assertEqual(campaign["condition_count"], 209)
        self.assertEqual(len(campaign["requests"]), 26)
        for request in campaign["requests"]:
            template = request["receipt_template"]
            self.assertEqual(template["reviewer"], "")
            self.assertEqual(template["reviewer_role"], "")
            self.assertFalse(template["independent_of_fixture_author"])
            self.assertEqual(template["decision"], "changes_requested")
        self.assertIn("no independent approval", campaign["warning"])

    def test_empty_receipt_directory_remains_explicitly_unreviewed(self):
        with tempfile.TemporaryDirectory() as directory:
            result = summarize_review_coverage(CORPUS, Path(directory))
        self.assertEqual(result["approved_project_count"], 0)
        self.assertEqual(result["approved_condition_count"], 0)
        self.assertEqual(result["missing_project_count"], 26)
        self.assertEqual(result["invalid_project_count"], 0)
        self.assertFalse(result["review_target_satisfied"])
        self.assertFalse(result["all_corpus_fixtures_approved"])
        self.assertTrue(result["no_blended_quality_score"])

    def test_valid_approval_counts_and_stale_receipt_does_not(self):
        project_ids = ["authorization-ownership", "data-loss-transaction"]
        with tempfile.TemporaryDirectory() as directory:
            receipts = Path(directory)
            first_root = CORPUS / "fixtures" / project_ids[0]
            approved = review_request(first_root)["receipt_template"]
            approved.update({
                "reviewer": "independent-reviewer",
                "reviewer_role": "benchmark oracle reviewer",
                "independent_of_fixture_author": True,
                "decision": "approved",
                "notes": "Reviewed against the exact fixture bytes.",
            })
            (receipts / f"{project_ids[0]}.json").write_text(
                json.dumps(approved), encoding="utf-8"
            )

            second_root = CORPUS / "fixtures" / project_ids[1]
            stale = review_request(second_root)["receipt_template"]
            stale.update({
                "reviewer": "independent-reviewer-2",
                "reviewer_role": "benchmark oracle reviewer",
                "independent_of_fixture_author": True,
                "decision": "approved",
                "fixture_digest": "sha256:" + "0" * 64,
            })
            (receipts / f"{project_ids[1]}.json").write_text(
                json.dumps(stale), encoding="utf-8"
            )
            (receipts / "not-in-corpus.json").write_text("{}", encoding="utf-8")

            result = summarize_review_coverage(CORPUS, receipts)

        first_conditions = result["statuses"][0]["condition_count"]
        self.assertEqual(result["approved_project_count"], 1)
        self.assertEqual(result["approved_condition_count"], first_conditions)
        self.assertEqual(result["invalid_project_count"], 1)
        self.assertEqual(result["missing_project_count"], 24)
        self.assertEqual(result["orphan_receipts"], ["not-in-corpus.json"])
        self.assertFalse(result["review_target_satisfied"])
        status = {row["project_id"]: row["status"] for row in result["statuses"]}
        self.assertEqual(status[project_ids[0]], "approved")
        self.assertEqual(status[project_ids[1]], "invalid")


if __name__ == "__main__":
    unittest.main()
