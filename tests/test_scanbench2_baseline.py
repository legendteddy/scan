"""ScanBench 2.0 multi-project baseline ledger tests."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scan_core import ScanConfig, SemanticStateBuilder, scan_project
from scan_core.errors import CommandError
from scan_core.scanbench2 import GROUND_TRUTH_VERSION
from scan_core.scanbench2_baseline import BASELINE_MANIFEST_VERSION, evaluate_baseline
from scan_core.state import canonical_state_json, state_digest

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "scanbench" / "ground_truth"
FIXTURE = CORPUS / "fixtures" / "authorization-ownership"


class ScanBench2BaselineTests(unittest.TestCase):
    def _state_and_submission(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text((FIXTURE / "project" / "app.py").read_text(encoding="utf-8"), encoding="utf-8")
            state = scan_project(ScanConfig(root=root, baseline_mode="none", reuse_enabled=False)).state
        artifact = next(row for row in state["artifacts"] if row["locator"] == "app.py")
        builder = SemanticStateBuilder.from_state(state)
        evidence_id = builder.add_evidence(
            artifact_id=artifact["id"], locator="app.py:5-12", kind="static",
            claim="delete_document checks authentication but not document ownership",
            result="The loaded owner_id is never compared with current_user.id before DELETE",
            method="static semantic source review", limitations="Runtime routing was not executed",
            source_digest=artifact["content_identity"], producer_kind="human",
            producer_name="baseline-fixture-reviewer", producer_version="1",
        )
        finding_id = builder.add_finding(
            title="Missing object ownership authorization on document deletion",
            impact="An authenticated user can delete another user's document",
            severity="high", confidence="high", verification_state="static",
            artifact_ids=[artifact["id"]], evidence_ids=[evidence_id],
            uncertainty="Static function-level evidence",
            recommendation="Require ownership authorization before deletion",
            safe_verification="Add cross-user authorization tests in an authorized test environment",
        )
        mfa_unknown = builder.add_unknown(
            record_id="unknown:production-mfa",
            question="Does the production identity provider enforce MFA?",
            reason="No production identity-provider configuration is present",
            impact="Production account hardening is unverified",
            next_safe_step="Inspect authoritative IdP configuration",
        )
        state = builder.build()
        submission = {
            "scanbench2_version": GROUND_TRUTH_VERSION,
            "project_id": "authorization-ownership",
            "state_digest": state_digest(state),
            "adjudications": [
                {"condition_id": "AUTH-001", "outcome": "found", "finding_ids": [finding_id], "unknown_ids": [], "evidence_ids": [evidence_id]},
                {"condition_id": "AUTH-002", "outcome": "not_found", "finding_ids": [], "unknown_ids": [], "evidence_ids": []},
                {"condition_id": "AUTH-003", "outcome": "unknown", "finding_ids": [], "unknown_ids": [mfa_unknown], "evidence_ids": []},
                {"condition_id": "AUTH-004", "outcome": "found", "finding_ids": [finding_id], "unknown_ids": [], "evidence_ids": [evidence_id]},
            ],
        }
        return state, submission

    def test_partial_baseline_is_measured_without_being_called_complete(self):
        state, submission = self._state_and_submission()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "states").mkdir()
            (root / "submissions").mkdir()
            (root / "states" / "auth.json").write_text(canonical_state_json(state), encoding="utf-8")
            (root / "submissions" / "auth.json").write_text(json.dumps(submission), encoding="utf-8")
            manifest = {
                "scanbench2_version": GROUND_TRUTH_VERSION,
                "baseline_manifest_version": BASELINE_MANIFEST_VERSION,
                "baseline_id": "unit-baseline",
                "inspector": {"name": "Scan", "version": "test", "configuration": "static test fixture"},
                "runs": [{
                    "project_id": "authorization-ownership",
                    "state": "states/auth.json",
                    "submission": "submissions/auth.json",
                }],
            }
            manifest_path = root / "baseline.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            result = evaluate_baseline(CORPUS, manifest_path)

        self.assertEqual(result["evaluated_project_count"], 1)
        self.assertEqual(result["evaluated_condition_count"], 4)
        self.assertEqual(result["project_pass_count"], 1)
        self.assertEqual(result["metrics"]["detection"]["recall"], 1.0)
        self.assertEqual(result["metrics"]["negative_controls"]["specificity"], 1.0)
        self.assertEqual(result["metrics"]["unknown_honesty"]["rate"], 1.0)
        self.assertEqual(result["metrics"]["false_clearance"]["violations"], 0)
        self.assertEqual(len(result["missing_project_ids"]), 25)
        self.assertFalse(result["baseline_target_coverage_satisfied"])
        self.assertFalse(result["complete_corpus_baseline"])
        self.assertTrue(result["no_blended_quality_score"])
        self.assertNotIn("overall_score", result)

    def test_baseline_input_paths_cannot_escape_manifest_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = {
                "scanbench2_version": GROUND_TRUTH_VERSION,
                "baseline_manifest_version": BASELINE_MANIFEST_VERSION,
                "baseline_id": "escape-test",
                "inspector": {"name": "Scan", "version": "test"},
                "runs": [{
                    "project_id": "authorization-ownership",
                    "state": "../outside-state.json",
                    "submission": "submission.json",
                }],
            }
            manifest_path = root / "baseline.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(CommandError, "canonical relative path"):
                evaluate_baseline(CORPUS, manifest_path)


if __name__ == "__main__":
    unittest.main()
