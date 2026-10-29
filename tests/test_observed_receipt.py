"""Observed runtime/test evidence receipt import tests."""
from __future__ import annotations

from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest

from scan_core import ScanConfig, scan_project
from scan_core.cli import main as cli_main
from scan_core.observed_receipt import import_observed_receipt
from scan_core.state import canonical_state_json, state_digest


class ObservedReceiptTests(unittest.TestCase):
    def _state(self):
        directory = tempfile.TemporaryDirectory()
        root = Path(directory.name)
        (root / "app.py").write_text("def ping():\n    return 'pong'\n", encoding="utf-8")
        state = scan_project(ScanConfig(root=root, baseline_mode="none", reuse_enabled=False)).state
        artifact = next(row for row in state["artifacts"] if row["locator"] == "app.py")
        self.addCleanup(directory.cleanup)
        return state, artifact

    def _receipt(self, state, artifact, *, outcome="fail"):
        observation = {
            "external_id": "OBS-001",
            "outcome": outcome,
            "artifact_locator": "app.py",
            "artifact_content_identity": artifact["content_identity"],
            "locator": "app.py:1-2",
            "claim": "Authorized external test observed the ping behavior.",
            "result": "Observed response did not satisfy the expected assertion.",
            "method": "External integration test runner; Scan only imports the receipt.",
            "limitations": "One bounded test case in a non-production environment.",
            "observed_at": "2026-10-29T02:45:00Z",
        }
        if outcome == "fail":
            observation["finding"] = {
                "title": "Observed ping behavior failed the expected assertion",
                "impact": "The tested behavior does not meet its expected contract.",
                "severity": "medium",
                "confidence": "externally-observed",
                "uncertainty": "Only the declared test case was observed.",
                "recommendation": "Investigate the failing behavior and add a regression test.",
                "safe_verification": "Rerun the same authorized test after the change.",
            }
        elif outcome == "pass":
            observation["control"] = {
                "description": "The declared ping integration test passed in the external runner.",
                "limitations": "A passing bounded test does not establish behavior outside the declared case.",
            }
        else:
            observation["unknown"] = {
                "question": "Why was the external ping observation inconclusive?",
                "reason": "The runner returned an inconclusive result.",
                "impact": "The runtime behavior remains unverified for this case.",
                "next_safe_step": "Inspect the runner diagnostics and rerun under the same authorization.",
            }
        return {
            "scan_observed_receipt_version": "1",
            "target": {
                "snapshot_digest": state["provenance"]["snapshot_digest"],
                "state_digest": state_digest(state),
            },
            "executor": {"kind": "external-tool", "name": "ExampleTestRunner", "version": "7.4"},
            "authorization": {
                "basis": "workflow-owner approval",
                "scope": "Run the declared integration test against this fixture only.",
                "reference": "approval-ticket-123",
            },
            "execution": {
                "execution_id": "run-456",
                "started_at": "2026-10-29T02:44:00Z",
                "completed_at": "2026-10-29T02:45:00Z",
                "environment": "isolated test environment",
                "target_executed": True,
                "network_used": False,
            },
            "coverage": {
                "scope": "One integration test for app.py ping behavior.",
                "limitations": "No production traffic, load, or broader runtime behavior was observed.",
                "whole_project_complete": False,
            },
            "observations": [observation],
        }

    def test_fail_import_creates_observed_evidence_and_finding(self):
        state, artifact = self._state()
        receipt = self._receipt(state, artifact, outcome="fail")
        raw = json.dumps(receipt, sort_keys=True).encode("utf-8")
        imported = import_observed_receipt(state, receipt, source_bytes=raw)
        self.assertEqual(imported.imported_findings, 1)
        self.assertEqual(imported.imported_controls, 0)
        self.assertEqual(imported.imported_evidence, 1)
        evidence = next(row for row in imported.state["evidence"] if row["id"].startswith("evidence:observed:"))
        finding = next(row for row in imported.state["findings"] if row["id"].startswith("finding:observed:"))
        self.assertEqual(evidence["kind"], "observed")
        self.assertEqual(evidence["source_digest"], imported.receipt_digest)
        self.assertEqual(evidence["artifact_content_digest"], artifact["content_identity"])
        self.assertEqual(finding["verification_state"], "observed")
        self.assertEqual(finding["evidence_ids"], [evidence["id"]])
        imported_artifact = next(row for row in imported.state["artifacts"] if row["id"] == artifact["id"])
        self.assertEqual(imported_artifact["status"], "partial")
        self.assertFalse(imported.state["coverage"]["analysis_complete"])

    def test_pass_import_creates_observed_control_without_clearance(self):
        state, artifact = self._state()
        receipt = self._receipt(state, artifact, outcome="pass")
        imported = import_observed_receipt(state, receipt)
        self.assertEqual(imported.imported_controls, 1)
        self.assertEqual(imported.imported_findings, 0)
        control = next(row for row in imported.state["controls"] if row["id"].startswith("control:observed:"))
        self.assertEqual(control["effectiveness_status"], "observed_effective")
        self.assertIn("does not establish behavior outside", control["limitations"])
        self.assertFalse(imported.state["coverage"]["analysis_complete"])

    def test_unknown_import_preserves_runtime_uncertainty(self):
        state, artifact = self._state()
        receipt = self._receipt(state, artifact, outcome="unknown")
        imported = import_observed_receipt(state, receipt)
        self.assertEqual(imported.imported_unknowns, 1)
        unknown = next(row for row in imported.state["unknowns"] if row["id"].startswith("unknown:observed:"))
        self.assertIn("inconclusive", unknown["reason"])
        self.assertEqual(len(unknown["evidence_ids"]), 1)

    def test_snapshot_and_state_binding_fail_closed(self):
        state, artifact = self._state()
        receipt = self._receipt(state, artifact)
        receipt["target"]["snapshot_digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(ValueError, "snapshot_digest does not match"):
            import_observed_receipt(state, receipt)
        receipt = self._receipt(state, artifact)
        receipt["target"]["state_digest"] = "sha256:" + "1" * 64
        with self.assertRaisesRegex(ValueError, "state_digest does not match"):
            import_observed_receipt(state, receipt)

    def test_mapped_artifact_byte_mismatch_fails_closed(self):
        state, artifact = self._state()
        receipt = self._receipt(state, artifact)
        receipt["observations"][0]["artifact_content_identity"] = "sha256:" + "2" * 64
        with self.assertRaisesRegex(ValueError, "artifact_content_identity does not match"):
            import_observed_receipt(state, receipt)

    def test_unmapped_observation_becomes_unknown_not_finding_or_control(self):
        state, artifact = self._state()
        receipt = self._receipt(state, artifact, outcome="fail")
        receipt["observations"][0]["artifact_locator"] = "missing.py"
        receipt["observations"][0]["artifact_content_identity"] = "sha256:" + "3" * 64
        imported = import_observed_receipt(state, receipt)
        self.assertEqual(imported.imported_findings, 0)
        self.assertEqual(imported.imported_controls, 0)
        self.assertEqual(imported.imported_unknowns, 1)
        self.assertEqual(imported.unmapped_observations, 1)
        unknown = next(row for row in imported.state["unknowns"] if row["id"].startswith("unknown:observed:"))
        self.assertEqual(unknown["artifact_ids"], [])

    def test_authorization_is_recorded_but_never_claimed_verified_by_scan(self):
        state, artifact = self._state()
        receipt = self._receipt(state, artifact, outcome="pass")
        receipt["authorization"]["reference"] = "ghp_abcdefghijklmnopqrstuvwxyz123456"
        imported = import_observed_receipt(state, receipt)
        import_receipt = imported.state["extensions"]["observed_evidence_imports"][-1]
        attestation = import_receipt["authorization_attestation"]
        execution = import_receipt["execution"]
        self.assertFalse(attestation["verified_by_scan"])
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz123456", attestation["reference"])
        self.assertFalse(execution["target_executed_by_scan_during_import"])
        self.assertFalse(execution["network_used_by_scan_during_import"])
        self.assertTrue(execution["target_executed_by_external_system"])

    def test_whole_project_complete_claim_is_rejected(self):
        state, artifact = self._state()
        receipt = self._receipt(state, artifact)
        receipt["coverage"]["whole_project_complete"] = True
        with self.assertRaisesRegex(ValueError, "whole_project_complete must be false"):
            import_observed_receipt(state, receipt)

    def test_duplicate_identical_observation_is_ignored_conflict_fails(self):
        state, artifact = self._state()
        receipt = self._receipt(state, artifact)
        receipt["observations"].append(deepcopy(receipt["observations"][0]))
        imported = import_observed_receipt(state, receipt)
        self.assertEqual(imported.imported_findings, 1)
        self.assertEqual(imported.ignored_observations, 1)

        conflict = self._receipt(state, artifact)
        second = deepcopy(conflict["observations"][0])
        second["result"] = "conflicting observation under the same external ID"
        conflict["observations"].append(second)
        with self.assertRaisesRegex(ValueError, "conflicts with an earlier observation"):
            import_observed_receipt(state, conflict)

    def test_cli_import_observed_executes_and_preserves_honesty_boundary(self):
        state, artifact = self._state()
        receipt = self._receipt(state, artifact, outcome="pass")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / "state.json"
            receipt_path = root / "observed.json"
            output_path = root / "observed-state.json"
            state_path.write_text(canonical_state_json(state) + "\n", encoding="utf-8", newline="\n")
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = cli_main([
                    "import-observed",
                    str(state_path),
                    str(receipt_path),
                    "--output",
                    str(output_path),
                    "--json",
                ])
            self.assertEqual(code, 0)
            summary = json.loads(stdout.getvalue())
            self.assertEqual(summary["imported_controls"], 1)
            self.assertEqual(summary["imported_evidence"], 1)
            imported_state = json.loads(output_path.read_text(encoding="utf-8"))
            import_receipt = imported_state["extensions"]["observed_evidence_imports"][-1]
            self.assertFalse(import_receipt["authorization_attestation"]["verified_by_scan"])
            self.assertFalse(import_receipt["execution"]["target_executed_by_scan_during_import"])
            self.assertFalse(import_receipt["execution"]["network_used_by_scan_during_import"])
            self.assertFalse(imported_state["coverage"]["analysis_complete"])


if __name__ == "__main__":
    unittest.main()
