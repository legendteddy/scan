"""ScanBench 2.0 ground-truth evaluator tests."""
from __future__ import annotations

import contextlib
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest

from scan_core import ScanConfig, SemanticStateBuilder, scan_project
from scan_core.cli import main
from scan_core.errors import CommandError, ExitCode
from scan_core.scanbench2 import (
    GROUND_TRUTH_VERSION,
    TRUTH_KINDS,
    evaluate_ground_truth,
    load_ground_truth_file,
)
from scan_core.state import canonical_state_json, state_digest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "scanbench" / "ground_truth" / "fixtures" / "authorization-ownership"


class ScanBench2Tests(unittest.TestCase):
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
            method="static semantic source review", limitations="Runtime routing and production identity controls were not observed",
            source_digest=artifact["content_identity"], producer_kind="human",
            producer_name="independent-fixture-reviewer", producer_version="1",
        )
        finding_id = builder.add_finding(
            title="Missing object ownership authorization on document deletion",
            impact="Any authenticated user reaching this function can delete another user's document",
            severity="high", confidence="high", verification_state="static",
            artifact_ids=[artifact["id"]], evidence_ids=[evidence_id],
            uncertainty="Static function-level evidence; route exposure was not executed",
            recommendation="Require document.owner_id == current_user.id or an equivalent authorization policy before deletion",
            safe_verification="Add cross-user authorization tests and run them only in an authorized test environment",
        )
        mfa_unknown = builder.add_unknown(
            record_id="unknown:production-mfa",
            question="Does the production identity provider enforce MFA?",
            reason="No production identity-provider configuration or observed authentication session is present",
            impact="Production account-hardening effectiveness is unverified",
            next_safe_step="Inspect authoritative IdP configuration or an approved observed authentication receipt",
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

    def test_fixture_exercises_all_four_truth_classes(self):
        truth = load_ground_truth_file(FIXTURE / "truth.json")
        self.assertEqual(truth["scanbench2_version"], GROUND_TRUTH_VERSION)
        self.assertEqual({row["truth"] for row in truth["conditions"]}, set(TRUTH_KINDS))
        bench_root = ROOT / "scanbench" / "ground_truth"
        manifest = json.loads((bench_root / "manifest.json").read_text(encoding="utf-8-sig"))
        self.assertEqual(manifest["truth_kinds"], list(TRUTH_KINDS))
        truth_schema = json.loads((bench_root / "schema-v2.json").read_text(encoding="utf-8-sig"))
        submission_schema = json.loads((bench_root / "submission-schema-v2.json").read_text(encoding="utf-8-sig"))
        self.assertEqual(truth_schema["properties"]["scanbench2_version"]["const"], GROUND_TRUTH_VERSION)
        self.assertEqual(submission_schema["properties"]["scanbench2_version"]["const"], GROUND_TRUTH_VERSION)

    def test_good_independent_adjudication_passes_with_separate_metrics(self):
        truth = load_ground_truth_file(FIXTURE / "truth.json")
        state, submission = self._state_and_submission()
        result = evaluate_ground_truth(truth, state, submission)
        payload = result.as_dict()
        self.assertTrue(result.passed)
        self.assertEqual(payload["metrics"]["detection"]["recall"], 1.0)
        self.assertEqual(payload["metrics"]["negative_controls"]["specificity"], 1.0)
        self.assertEqual(payload["metrics"]["unknown_honesty"]["rate"], 1.0)
        self.assertEqual(payload["metrics"]["false_clearance"]["violations"], 0)
        self.assertNotIn("overall_score", payload)
        self.assertNotIn("quality_score", payload)

    def test_false_negative_false_positive_and_clearance_remain_separate(self):
        truth = load_ground_truth_file(FIXTURE / "truth.json")
        state, submission = self._state_and_submission()
        bad = deepcopy(submission)
        for row in bad["adjudications"]:
            if row["condition_id"] == "AUTH-001":
                row.update(outcome="not_found", finding_ids=[], evidence_ids=[])
            elif row["condition_id"] == "AUTH-002":
                finding = state["findings"][0]
                row.update(outcome="found", finding_ids=[finding["id"]], evidence_ids=list(finding["evidence_ids"]))
            elif row["condition_id"] in {"AUTH-003", "AUTH-004"}:
                row.update(outcome="cleared", unknown_ids=[], finding_ids=[], evidence_ids=[])
        result = evaluate_ground_truth(truth, state, bad)
        self.assertFalse(result.passed)
        self.assertEqual(result.metrics["detection"]["false_negative"], 1)
        self.assertEqual(result.metrics["negative_controls"]["false_positive"], 1)
        self.assertEqual(result.metrics["unknown_honesty"]["incorrect_or_overclaimed"], 1)
        self.assertEqual(result.metrics["false_clearance"]["violations"], 1)

    def test_submission_is_bound_to_exact_state_and_canonical_refs(self):
        truth = load_ground_truth_file(FIXTURE / "truth.json")
        state, submission = self._state_and_submission()
        wrong_digest = deepcopy(submission)
        wrong_digest["state_digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(CommandError, "state_digest"):
            evaluate_ground_truth(truth, state, wrong_digest)

        bad_ref = deepcopy(submission)
        bad_ref["adjudications"][0]["finding_ids"] = ["finding:missing"]
        result = evaluate_ground_truth(truth, state, bad_ref)
        first = next(row for row in result.conditions if row.condition_id == "AUTH-001")
        self.assertFalse(first.reference_valid)
        self.assertFalse(first.passed)

    def test_cli_evaluates_files_without_executing_target(self):
        truth = load_ground_truth_file(FIXTURE / "truth.json")
        state, submission = self._state_and_submission()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            truth_path = root / "truth.json"
            state_path = root / "state.json"
            submission_path = root / "submission.json"
            truth_path.write_text(json.dumps(truth), encoding="utf-8")
            state_path.write_text(canonical_state_json(state), encoding="utf-8")
            submission_path.write_text(json.dumps(submission), encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(["bench2", str(truth_path), str(state_path), str(submission_path), "--json"])
        self.assertEqual(code, ExitCode.OK)
        payload = json.loads(stdout.getvalue())
        self.assertTrue(payload["passed"])
        self.assertNotIn("overall_score", payload)


if __name__ == "__main__":
    unittest.main()
