"""Slice 4 deterministic privacy, redaction and egress-preview tests."""

from __future__ import annotations

import contextlib
import copy
import io
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest import mock

from scan_core import ScanConfig, build_inventory, scan_project
from scan_core.cli import main
from scan_core.errors import ExitCode, ValidationError
from scan_core.privacy import (
    RedactionPolicy,
    assess_privacy,
    build_egress_preview,
    prepare_text_for_egress,
    redact_value,
)
from scan_core.state import canonical_state_json, configuration_digest
from scan_core.validate import validate_state

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "scanbench" / "fixtures" / "privacy-redaction" / "target"
SYNTHETIC_GH = "gh" + "p_" + ("A" * 40)
SYNTHETIC_SK = "s" + "k-" + ("B" * 32)
SYNTHETIC_TOKEN = "synthetic-token-value-1234567890"
SYNTHETIC_API_KEY = "synthetic-api-key-value-1234567890"
SYNTHETIC_PRIVATE_KEY = "synthetic-private-key-material-12345"
SYNTHETIC_PASSWORD = "synthetic-password-123"


class PrivacyRedactionTests(unittest.TestCase):
    def test_standard_redacts_credentials_but_not_general_pii(self):
        text = f"API_TOKEN={SYNTHETIC_GH}\nContact: alice@example.test\n"
        result = redact_value(text, RedactionPolicy(level="standard"))
        self.assertNotIn(SYNTHETIC_GH, result.value)
        self.assertIn("[REDACTED:credential]", result.value)
        self.assertIn("alice@example.test", result.value)
        self.assertEqual(result.count, 1)

    def test_strict_adds_email_phone_and_labeled_identifier_redaction(self):
        text = "Contact: alice@example.test\nPhone: +673 812 3456\naccount_number = BRN-001-9999\n"
        result = redact_value(text, RedactionPolicy(level="strict"))
        self.assertNotIn("alice@example.test", result.value)
        self.assertNotIn("+673 812 3456", result.value)
        self.assertNotIn("BRN-001-9999", result.value)
        self.assertIn("[REDACTED:email]", result.value)
        self.assertIn("[REDACTED:phone]", result.value)
        self.assertIn("[REDACTED:identifier]", result.value)
        self.assertEqual(result.count, 3)

    def test_private_key_block_is_replaced_without_retaining_body(self):
        begin = "-----BEGIN " + "PRIVATE KEY-----"
        end = "-----END " + "PRIVATE KEY-----"
        text = begin + "\nSYNTHETIC-NOT-A-REAL-KEY\n" + end
        result = redact_value(text, RedactionPolicy(level="standard"))
        self.assertEqual(result.value, "[REDACTED:private-key]")
        self.assertEqual(result.count, 1)

    def test_redaction_none_preserves_input_exactly(self):
        text = f"PASSWORD={SYNTHETIC_PASSWORD}"
        result = redact_value(text, RedactionPolicy(level="none"))
        self.assertEqual(result.value, text)
        self.assertEqual(result.count, 0)

    def test_redaction_is_idempotent_for_its_own_markers(self):
        first = redact_value(f"PASSWORD={SYNTHETIC_PASSWORD}", RedactionPolicy(level="standard"))
        second = redact_value(first.value, RedactionPolicy(level="standard"))
        self.assertEqual(second.value, first.value)
        self.assertEqual(second.count, 0)

    def test_prepare_text_for_egress_returns_only_redacted_text(self):
        path = FIXTURE / "credentials.env"
        result = prepare_text_for_egress(path, RedactionPolicy(level="standard"), max_bytes=10_000)
        self.assertNotIn(SYNTHETIC_TOKEN, result.value)
        self.assertNotIn(SYNTHETIC_API_KEY, result.value)
        self.assertNotIn(SYNTHETIC_PASSWORD, result.value)
        self.assertGreaterEqual(result.count, 3)

    def test_standard_assessment_marks_secret_files_and_sensitive_paths(self):
        config = ScanConfig(
            root=FIXTURE,
            redaction_level="standard",
            sensitive_paths=("private/**",),
        )
        inventory = build_inventory(config)
        assessment = assess_privacy(config, inventory)
        rows = {row.locator: row for row in assessment.artifacts}
        self.assertEqual(rows["credentials.env"].redaction_state, "content_redacted")
        self.assertEqual(rows["key.pem"].redaction_state, "content_redacted")
        self.assertEqual(rows["pii.txt"].redaction_state, "none")
        self.assertEqual(rows["private"].redaction_state, "path_redacted")
        self.assertEqual(rows["private/customer.txt"].redaction_state, "fully_omitted")
        self.assertEqual(assessment.sensitive_path_count, 2)
        self.assertGreaterEqual(assessment.redaction_count, 4)

    def test_strict_assessment_redacts_pii_file_too(self):
        config = ScanConfig(root=FIXTURE, redaction_level="strict", sensitive_paths=("private/**",))
        assessment = assess_privacy(config, build_inventory(config))
        rows = {row.locator: row for row in assessment.artifacts}
        self.assertEqual(rows["pii.txt"].redaction_state, "content_redacted")
        self.assertGreaterEqual(rows["pii.txt"].redaction_count, 3)

    def test_generated_state_contains_counts_but_no_raw_sensitive_values(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "state.json"
            result = scan_project(ScanConfig(
                root=FIXTURE,
                output_state=output,
                redaction_level="strict",
                sensitive_paths=("private/**",),
            ))
        serialized = canonical_state_json(result.state)
        for raw in (SYNTHETIC_TOKEN, SYNTHETIC_API_KEY, SYNTHETIC_PRIVATE_KEY, SYNTHETIC_PASSWORD, "alice@example.test", "+673 812 3456", "BRN-001-9999"):
            self.assertNotIn(raw, serialized)
        self.assertGreaterEqual(result.state["privacy"]["redaction_count"], 7)
        self.assertEqual(result.state["privacy"]["sensitive_path_count"], 2)
        validate_state(result.state)

    def test_sensitive_locator_is_replaced_before_canonical_state(self):
        result = scan_project(ScanConfig(
            root=FIXTURE,
            redaction_level="none",
            sensitive_paths=("private/**",),
        ))
        serialized = canonical_state_json(result.state)
        self.assertNotIn("private/customer.txt", serialized)
        self.assertNotIn('"locator":"private"', serialized)
        sensitive = [row for row in result.state["artifacts"] if row["redaction_state"] in {"path_redacted", "fully_omitted"}]
        self.assertEqual(len(sensitive), 2)
        self.assertTrue(all(row["locator"].startswith("[REDACTED:path]/") for row in sensitive))

    def test_sensitive_path_pattern_itself_is_not_serialized(self):
        pattern = "private/**"
        result = scan_project(ScanConfig(root=FIXTURE, sensitive_paths=(pattern,)))
        self.assertNotIn(pattern, canonical_state_json(result.state))
        self.assertNotEqual(configuration_digest(ScanConfig(root=FIXTURE)), configuration_digest(ScanConfig(root=FIXTURE, sensitive_paths=(pattern,))))

    def test_sensitive_exclusion_and_custom_output_paths_are_masked_in_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "private"
            private.mkdir()
            (private / "source.txt").write_text("safe fixture", encoding="utf-8")
            output = private / "scan-state.json"
            result = scan_project(ScanConfig(
                root=root,
                output_state=output,
                excludes=("private/source.txt",),
                sensitive_paths=("private/**",),
            ))
            serialized = canonical_state_json(result.state)
            self.assertNotIn("private/source.txt", serialized)
            self.assertNotIn("private/scan-state.json", serialized)
            self.assertIn("[REDACTED:path-pattern]/", serialized)

    def test_previous_non_redacted_13_artifacts_without_match_count_still_validate(self):
        result = scan_project(ScanConfig(root=FIXTURE, redaction_level="none"))
        legacy_dev_state = copy.deepcopy(result.state)
        for row in legacy_dev_state["artifacts"]:
            row.pop("redaction_count", None)
        validate_state(legacy_dev_state)

    def test_validator_rejects_redaction_count_mismatch(self):
        result = scan_project(ScanConfig(root=FIXTURE, redaction_level="standard"))
        broken = copy.deepcopy(result.state)
        broken["privacy"]["redaction_count"] += 1
        with self.assertRaisesRegex(ValidationError, "redaction_count"):
            validate_state(broken)

    def test_validator_rejects_raw_locator_for_path_redaction_state(self):
        result = scan_project(ScanConfig(root=FIXTURE, sensitive_paths=("private/**",)))
        broken = copy.deepcopy(result.state)
        row = next(item for item in broken["artifacts"] if item["redaction_state"] == "fully_omitted")
        row["locator"] = "private/customer.txt"
        with self.assertRaisesRegex(ValidationError, "redacted locator"):
            validate_state(broken)

    def test_binary_content_is_metadata_only_for_egress(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "binary.bin").write_bytes(b"abc\x00def")
            config = ScanConfig(root=root)
            assessment = assess_privacy(config, build_inventory(config))
            row = assessment.artifacts[0]
            self.assertEqual(row.redaction_state, "metadata_only")
            self.assertFalse(row.egress_eligible)
            self.assertEqual(assessment.files_selected, 0)

    def test_egress_preview_is_deterministic_and_never_networks(self):
        config = ScanConfig(
            root=FIXTURE,
            privacy_mode="controlled-remote",
            redaction_level="strict",
            sensitive_paths=("private/**",),
        )
        inventory = build_inventory(config)
        with mock.patch.object(socket.socket, "connect", side_effect=AssertionError("network attempted")):
            first = build_egress_preview(config, inventory)
            second = build_egress_preview(config, inventory)
        self.assertEqual(first, second)
        self.assertEqual(first.network_action, "none")
        self.assertEqual(first.sensitive_paths_omitted, 2)
        self.assertGreater(first.redaction_count, 0)

    def test_cli_egress_emits_counts_only(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main([
                "egress", str(FIXTURE),
                "--privacy", "controlled-remote",
                "--redact", "strict",
                "--sensitive-path", "private/**",
                "--json",
            ])
        self.assertEqual(code, ExitCode.OK)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["network_action"], "none")
        self.assertEqual(payload["privacy_mode"], "controlled-remote")
        self.assertEqual(payload["sensitive_paths_omitted"], 2)
        output = stdout.getvalue() + stderr.getvalue()
        for raw in (SYNTHETIC_TOKEN, SYNTHETIC_API_KEY, SYNTHETIC_PRIVATE_KEY, SYNTHETIC_PASSWORD, "alice@example.test"):
            self.assertNotIn(raw, output)


if __name__ == "__main__":
    unittest.main()
