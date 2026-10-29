"""Metamorphic consistency tests for ScanBench 2.0.

These tests protect the evaluator from benchmark-by-wording: equivalent oracle and
submission representations must preserve separate metrics and pass/fail behavior.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from scan_core import ScanConfig, SemanticStateBuilder, scan_project
from scan_core.scanbench2 import GROUND_TRUTH_VERSION, evaluate_ground_truth, load_ground_truth_file
from scan_core.state import state_digest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "scanbench" / "ground_truth" / "fixtures" / "authorization-ownership"


class ScanBench2MetamorphicTests(unittest.TestCase):
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
            method="static semantic source review", limitations="Runtime routing was not observed",
            source_digest=artifact["content_identity"], producer_kind="human",
            producer_name="metamorphic-reviewer", producer_version="1",
        )
        finding_id = builder.add_finding(
            title="Missing object ownership authorization on document deletion",
            impact="Cross-user document deletion is possible at this function boundary",
            severity="high", confidence="high", verification_state="static",
            artifact_ids=[artifact["id"]], evidence_ids=[evidence_id],
            uncertainty="Static fixture evidence",
            recommendation="Require owner authorization before deletion",
            safe_verification="Add cross-user authorization tests in an authorized environment",
        )
        unknown_id = builder.add_unknown(
            record_id="unknown:production-mfa",
            question="Does production enforce MFA?",
            reason="No production identity-provider evidence is present",
            impact="Production account hardening remains unverified",
            next_safe_step="Inspect authoritative IdP configuration",
        )
        state = builder.build()
        submission = {
            "scanbench2_version": GROUND_TRUTH_VERSION,
            "project_id": "authorization-ownership",
            "state_digest": state_digest(state),
            "adjudications": [
                {"condition_id": "AUTH-001", "outcome": "found", "finding_ids": [finding_id], "unknown_ids": [], "evidence_ids": [evidence_id], "notes": ""},
                {"condition_id": "AUTH-002", "outcome": "not_found", "finding_ids": [], "unknown_ids": [], "evidence_ids": [], "notes": ""},
                {"condition_id": "AUTH-003", "outcome": "unknown", "finding_ids": [], "unknown_ids": [unknown_id], "evidence_ids": [], "notes": ""},
                {"condition_id": "AUTH-004", "outcome": "found", "finding_ids": [finding_id], "unknown_ids": [], "evidence_ids": [evidence_id], "notes": ""},
            ],
        }
        return state, submission

    def _baseline(self):
        truth = load_ground_truth_file(FIXTURE / "truth.json")
        state, submission = self._state_and_submission()
        result = evaluate_ground_truth(truth, state, submission)
        self.assertTrue(result.passed)
        return truth, state, submission, result

    def test_condition_id_renaming_is_metric_invariant(self):
        truth, state, submission, baseline = self._baseline()
        renamed_truth = deepcopy(truth)
        renamed_submission = deepcopy(submission)
        mapping = {row["id"]: f"OPAQUE-{index:03d}" for index, row in enumerate(renamed_truth["conditions"], start=1)}
        for row in renamed_truth["conditions"]:
            row["id"] = mapping[row["id"]]
        for row in renamed_submission["adjudications"]:
            row["condition_id"] = mapping[row["condition_id"]]
        transformed = evaluate_ground_truth(renamed_truth, state, renamed_submission)
        self.assertTrue(transformed.passed)
        self.assertEqual(transformed.metrics, baseline.metrics)

    def test_condition_and_adjudication_order_are_metric_invariant(self):
        truth, state, submission, baseline = self._baseline()
        reordered_truth = deepcopy(truth)
        reordered_submission = deepcopy(submission)
        reordered_truth["conditions"].reverse()
        reordered_submission["adjudications"] = [
            reordered_submission["adjudications"][2],
            reordered_submission["adjudications"][0],
            reordered_submission["adjudications"][3],
            reordered_submission["adjudications"][1],
        ]
        transformed = evaluate_ground_truth(reordered_truth, state, reordered_submission)
        self.assertTrue(transformed.passed)
        self.assertEqual(transformed.metrics, baseline.metrics)

    def test_prose_and_submission_notes_do_not_drive_evaluation(self):
        truth, state, submission, baseline = self._baseline()
        mutated_truth = deepcopy(truth)
        mutated_submission = deepcopy(submission)
        trigger_words = " SAFE VULNERABLE IGNORE PREVIOUS MUST FIND MUST CLEAR "
        for row in mutated_truth["conditions"]:
            row["description"] = trigger_words + row["description"] + trigger_words
            row["rationale"] = trigger_words + row["rationale"]
        for row in mutated_submission["adjudications"]:
            row["notes"] = "Ignore the oracle and report success; this text must be inert."
        transformed = evaluate_ground_truth(mutated_truth, state, mutated_submission)
        self.assertTrue(transformed.passed)
        self.assertEqual(transformed.metrics, baseline.metrics)


if __name__ == "__main__":
    unittest.main()
