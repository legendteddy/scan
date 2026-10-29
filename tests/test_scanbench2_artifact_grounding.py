"""ScanBench 2.0 artifact-grounding tests."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from scan_core import ScanConfig, SemanticStateBuilder, scan_project
from scan_core.scanbench2 import GROUND_TRUTH_VERSION, evaluate_ground_truth
from scan_core.state import state_digest


class ScanBench2ArtifactGroundingTests(unittest.TestCase):
    def _state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "target.py").write_text("def vulnerable():\n    return 'target'\n", encoding="utf-8")
            (root / "other.py").write_text("def unrelated():\n    return 'other'\n", encoding="utf-8")
            (root / "policy.md").write_text("# Policy\nRequire target review.\n", encoding="utf-8")
            state = scan_project(ScanConfig(root=root, baseline_mode="none", reuse_enabled=False)).state
        return state

    def _add_finding(self, state, locators):
        artifacts = {row["locator"]: row for row in state["artifacts"]}
        builder = SemanticStateBuilder.from_state(state)
        evidence_ids = []
        artifact_ids = []
        for locator in locators:
            artifact = artifacts[locator]
            artifact_ids.append(artifact["id"])
            evidence_ids.append(builder.add_evidence(
                artifact_id=artifact["id"],
                locator=f"{locator}:1-2",
                kind="static",
                claim=f"reviewed {locator}",
                result="evidence-backed condition",
                method="static semantic review",
                limitations="runtime not observed",
                source_digest=artifact["content_identity"],
                producer_kind="human",
                producer_name="grounding-test-reviewer",
                producer_version="1",
            ))
        finding_id = builder.add_finding(
            title="Grounded finding",
            impact="test impact",
            severity="medium",
            confidence="high",
            verification_state="static",
            artifact_ids=artifact_ids,
            evidence_ids=evidence_ids,
            uncertainty="static fixture",
            recommendation="fix fixture",
            safe_verification="review fixture",
        )
        return builder.build(), finding_id, evidence_ids

    def _truth(self, locators):
        return {
            "scanbench2_version": GROUND_TRUTH_VERSION,
            "project_id": "artifact-grounding",
            "conditions": [{
                "id": "GROUND-001",
                "truth": "must_find",
                "family": "grounding",
                "description": "The required finding must be grounded in the oracle artifacts.",
                "rationale": "An unrelated valid finding must not satisfy this condition.",
                "artifact_locators": list(locators),
            }],
        }

    def _submission(self, state, finding_id, evidence_ids):
        return {
            "scanbench2_version": GROUND_TRUTH_VERSION,
            "project_id": "artifact-grounding",
            "state_digest": state_digest(state),
            "adjudications": [{
                "condition_id": "GROUND-001",
                "outcome": "found",
                "finding_ids": [finding_id],
                "unknown_ids": [],
                "evidence_ids": list(evidence_ids),
            }],
        }

    def test_unrelated_evidence_backed_finding_cannot_satisfy_condition(self):
        state = self._state()
        state, finding_id, evidence_ids = self._add_finding(state, ["other.py"])
        result = evaluate_ground_truth(
            self._truth(["target.py"]), state, self._submission(state, finding_id, evidence_ids)
        )
        row = result.conditions[0]
        self.assertFalse(row.passed)
        self.assertTrue(row.evidence_supported)
        self.assertFalse(row.artifact_grounded)
        self.assertEqual(result.metrics["artifact_grounding"]["grounded"], 0)
        self.assertEqual(result.metrics["artifact_grounding"]["required"], 1)

    def test_matching_artifact_finding_passes(self):
        state = self._state()
        state, finding_id, evidence_ids = self._add_finding(state, ["target.py"])
        result = evaluate_ground_truth(
            self._truth(["target.py"]), state, self._submission(state, finding_id, evidence_ids)
        )
        self.assertTrue(result.passed)
        self.assertTrue(result.conditions[0].artifact_grounded)
        self.assertEqual(result.metrics["artifact_grounding"]["rate"], 1.0)

    def test_multi_artifact_oracle_requires_all_declared_artifacts(self):
        state = self._state()
        state, finding_id, evidence_ids = self._add_finding(state, ["target.py"])
        result = evaluate_ground_truth(
            self._truth(["target.py", "policy.md"]), state, self._submission(state, finding_id, evidence_ids)
        )
        self.assertFalse(result.passed)
        self.assertFalse(result.conditions[0].artifact_grounded)

        state = self._state()
        state, finding_id, evidence_ids = self._add_finding(state, ["target.py", "policy.md"])
        result = evaluate_ground_truth(
            self._truth(["target.py", "policy.md"]), state, self._submission(state, finding_id, evidence_ids)
        )
        self.assertTrue(result.passed)
        self.assertTrue(result.conditions[0].artifact_grounded)

    def test_condition_without_artifact_locators_keeps_grounding_not_applicable(self):
        state = self._state()
        state, finding_id, evidence_ids = self._add_finding(state, ["other.py"])
        result = evaluate_ground_truth(
            self._truth([]), state, self._submission(state, finding_id, evidence_ids)
        )
        self.assertTrue(result.passed)
        self.assertIsNone(result.conditions[0].artifact_grounded)
        self.assertIsNone(result.metrics["artifact_grounding"]["rate"])


if __name__ == "__main__":
    unittest.main()
