"""Tests for privacy-safe post-run agent feedback receipts."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scan_core.feedback import (
    _issue_body,
    _submission_authorized,
    build_receipt,
    record_and_maybe_submit,
)


class FeedbackReceiptTests(unittest.TestCase):
    def test_receipt_binds_state_by_digest_without_copying_target_content_or_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "private-customer-project" / "state.json"
            state.parent.mkdir()
            secret = "customer-source-should-never-leave"
            state.write_text(json.dumps({"schema_version": "1.4", "secret_example": secret}), encoding="utf-8")
            receipt = build_receipt(state_path=state, tests=["validate=pass"])
            encoded = json.dumps(receipt, sort_keys=True)
            self.assertEqual(receipt["state"]["schema_version"], "1.4")
            self.assertTrue(receipt["state"]["digest"].startswith("sha256:"))
            self.assertNotIn(secret, encoded)
            self.assertNotIn(str(state), encoded)
            self.assertFalse(receipt["privacy"]["target_content_included"])
            self.assertFalse(receipt["privacy"]["absolute_target_paths_included"])

    def test_feedback_redacts_tokens_and_absolute_paths(self):
        receipt = build_receipt(
            feedback=[r"Failed near C:\\Users\\alice\\SecretProject\\app.py token=super-secret-value"],
            issues=["Bearer abcdefghijklmnopqrstuvwxyz leaked from /home/alice/private/repo/file.py"],
        )
        encoded = json.dumps(receipt)
        self.assertNotIn("super-secret-value", encoded)
        self.assertNotIn("SecretProject", encoded)
        self.assertNotIn("/home/alice/private", encoded)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", encoded)
        self.assertIn("[REDACTED]", encoded)
        self.assertIn("[PATH]", encoded)

    def test_fingerprint_is_stable_across_time_agent_and_host(self):
        first = build_receipt(
            agent="agent-a",
            host="host-a",
            tests=["validate=pass"],
            feedback=["CLI output was clear"],
            created_at="2026-01-01T00:00:00+00:00",
        )
        second = build_receipt(
            agent="agent-b",
            host="host-b",
            tests=["validate=pass"],
            feedback=["CLI output was clear"],
            created_at="2026-02-01T00:00:00+00:00",
        )
        self.assertEqual(first["fingerprint"], second["fingerprint"])
        self.assertEqual(first["receipt_id"], second["receipt_id"])

    def test_test_result_requires_explicit_bounded_status(self):
        with self.assertRaisesRegex(ValueError, "NAME=RESULT"):
            build_receipt(tests=["validate"])
        with self.assertRaisesRegex(ValueError, "test result"):
            build_receipt(tests=["validate=excellent"])

    def test_auto_mode_does_not_submit_without_explicit_host_opt_in(self):
        receipt = build_receipt(tests=["validate=pass"])
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {}, clear=True), patch("scan_core.feedback.submit_github") as submit:
                result = record_and_maybe_submit(receipt, mode="auto", root=Path(directory))
        submit.assert_not_called()
        self.assertEqual(result["status"], "queued")
        self.assertFalse(result["submission_authorized"])
        self.assertIsNotNone(result["outbox_path"])

    def test_auto_mode_submits_when_host_explicitly_opts_in(self):
        receipt = build_receipt(tests=["validate=pass"])
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"SCAN_FEEDBACK_SUBMIT": "1"}, clear=True), patch(
                "scan_core.feedback.submit_github",
                return_value={"status": "submitted", "url": "https://example.invalid/1", "repository": "legendteddy/scan"},
            ) as submit:
                result = record_and_maybe_submit(receipt, mode="auto", root=Path(directory))
        submit.assert_called_once_with(receipt)
        self.assertEqual(result["status"], "submitted")
        self.assertTrue(result["submission_authorized"])
        self.assertIsNone(result["outbox_path"])

    def test_submission_failure_preserves_outbox_receipt(self):
        receipt = build_receipt(tests=["validate=fail"], issues=["validator exited unexpectedly"])
        with tempfile.TemporaryDirectory() as directory:
            with patch("scan_core.feedback.submit_github", side_effect=RuntimeError("credential unavailable")):
                result = record_and_maybe_submit(receipt, mode="github", root=Path(directory))
                queued = Path(result["outbox_path"])
                self.assertTrue(queued.is_file())
                stored = json.loads(queued.read_text(encoding="utf-8"))
        self.assertEqual(stored["fingerprint"], receipt["fingerprint"])
        self.assertEqual(result["status"], "queued")
        self.assertIn("credential unavailable", result["submission_error"])

    def test_issue_body_contains_only_bounded_receipt_fields(self):
        receipt = build_receipt(
            agent="codex",
            host="chatgpt",
            tests=["scan validate=pass"],
            feedback=["Report navigation is useful"],
            issues=["One validation error was hard to diagnose"],
        )
        body = _issue_body(receipt)
        self.assertIn("scan-feedback-fingerprint:", body)
        self.assertIn("scan validate", body)
        self.assertIn("Report navigation is useful", body)
        self.assertIn("One validation error was hard to diagnose", body)
        self.assertIn("excludes inspected project source", body)

    def test_submission_gate_values(self):
        with patch.dict(os.environ, {"SCAN_FEEDBACK_SUBMIT": "yes"}, clear=True):
            self.assertTrue(_submission_authorized("auto"))
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(_submission_authorized("auto"))
            self.assertTrue(_submission_authorized("github"))
            self.assertFalse(_submission_authorized("never"))


if __name__ == "__main__":
    unittest.main()
