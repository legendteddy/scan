"""Review-request workflow tests for ScanBench 2.0."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from scan_core.errors import CommandError
from scan_core.scanbench2_review import (
    REVIEW_RECEIPT_VERSION,
    fixture_source_digest,
    main,
    review_request,
    validate_review_receipt,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "scanbench" / "ground_truth" / "fixtures" / "authorization-ownership"


class ScanBench2ReviewWorkflowTests(unittest.TestCase):
    def test_prepare_package_is_neutral_and_not_an_approval(self):
        package = review_request(FIXTURE)
        self.assertEqual(package["review_receipt_version"], REVIEW_RECEIPT_VERSION)
        self.assertEqual(package["project_id"], "authorization-ownership")
        self.assertEqual(package["fixture_digest"], fixture_source_digest(FIXTURE))
        self.assertEqual(package["condition_count"], 4)
        self.assertEqual(set(package["condition_ids"]), {"AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004"})
        self.assertIn("not a review receipt", package["warning"])
        template = package["receipt_template"]
        self.assertEqual(template["reviewer"], "")
        self.assertEqual(template["reviewer_role"], "")
        self.assertFalse(template["independent_of_fixture_author"])
        self.assertEqual(template["decision"], "changes_requested")
        with self.assertRaisesRegex(CommandError, "reviewer"):
            validate_review_receipt(template, FIXTURE)

    def test_prepare_cli_can_write_request_without_mutating_fixture(self):
        before = fixture_source_digest(FIXTURE)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "request.json"
            code = main(["prepare", str(FIXTURE), "--output", str(output)])
            self.assertEqual(code, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(payload["fixture_digest"], before)
        self.assertEqual(fixture_source_digest(FIXTURE), before)

    def test_verify_cli_accepts_completed_realistic_receipt(self):
        package = review_request(FIXTURE)
        receipt = dict(package["receipt_template"])
        receipt.update({
            "reviewer": "independent-reviewer-7",
            "reviewer_role": "benchmark-ground-truth-review",
            "independent_of_fixture_author": True,
            "decision": "approved",
            "notes": "Reviewed all conditions against the exact fixture bytes.",
        })
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = Path(directory) / "receipt.json"
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(["verify", str(FIXTURE), str(receipt_path), "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertTrue(payload["valid"])
        self.assertEqual(payload["receipt"]["decision"], "approved")
        self.assertTrue(payload["receipt"]["independent_of_fixture_author"])

    def test_stale_prepared_template_cannot_become_valid_after_fixture_change(self):
        package = review_request(FIXTURE)
        template = package["receipt_template"]
        self.assertEqual(template["fixture_digest"], fixture_source_digest(FIXTURE))
        # Existing digest validation is the freshness gate; an approval cannot simply
        # edit reviewer fields if fixture bytes later differ from the request package.
        stale = dict(template)
        stale.update({
            "reviewer": "reviewer",
            "reviewer_role": "review",
            "independent_of_fixture_author": True,
            "decision": "approved",
            "fixture_digest": "sha256:" + "0" * 64,
        })
        with self.assertRaisesRegex(CommandError, "fixture_digest"):
            validate_review_receipt(stale, FIXTURE)


if __name__ == "__main__":
    unittest.main()
