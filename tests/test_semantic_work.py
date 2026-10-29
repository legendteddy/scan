from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scan_core.efficiency_benchmark import summarize_semantic_work
from scan_core.semantic_work import (
    SEMANTIC_WORK_SCHEMA_VERSION,
    load_semantic_work_receipt,
    validate_semantic_work_receipt,
)


def sample_state() -> dict:
    return {
        "run": {"scan_id": "scan:test"},
        "provenance": {"snapshot_digest": "sha256:snapshot"},
        "artifacts": [
            {"id": "a1"},
            {"id": "a2"},
        ],
        "evidence": [
            {"id": "e-reuse", "artifact_id": "a2", "inspection_origin": "verified_reuse"},
            {"id": "e-fresh", "artifact_id": "a1", "inspection_origin": "fresh"},
        ],
    }


def sample_receipt() -> dict:
    return {
        "schema_version": SEMANTIC_WORK_SCHEMA_VERSION,
        "scan_id": "scan:test",
        "snapshot_digest": "sha256:snapshot",
        "producer": {"name": "example-host", "model": "example-model"},
        "artifacts": [
            {"artifact_id": "a1", "action": "fresh_read", "access_count": 2},
            {
                "artifact_id": "a2",
                "action": "verified_reuse",
                "access_count": 1,
                "evidence_ids": ["e-reuse"],
            },
        ],
        "usage": {"provider": "example-host", "model": "example-model", "input_tokens": 50, "output_tokens": 5},
    }


class SemanticWorkReceiptTests(unittest.TestCase):
    def test_receipt_binds_to_state_and_summarizes_exact_work(self) -> None:
        receipt = validate_semantic_work_receipt(sample_state(), sample_receipt())
        summary = summarize_semantic_work(receipt)

        self.assertTrue(summary["available"])
        self.assertEqual(summary["fresh_read_artifact_count"], 1)
        self.assertEqual(summary["fresh_read_access_count"], 2)
        self.assertEqual(summary["repeat_fresh_read_access_count"], 1)
        self.assertEqual(summary["verified_reuse_artifact_count"], 1)
        self.assertEqual(summary["fresh_read_artifact_ids"], ["a1"])
        self.assertEqual(summary["verified_reuse_artifact_ids"], ["a2"])
        self.assertEqual(receipt["usage"]["input_tokens"], 50)

    def test_receipt_rejects_wrong_run_snapshot_and_unknown_artifact(self) -> None:
        wrong_run = sample_receipt()
        wrong_run["scan_id"] = "scan:other"
        with self.assertRaisesRegex(ValueError, "scan_id"):
            validate_semantic_work_receipt(sample_state(), wrong_run)

        wrong_snapshot = sample_receipt()
        wrong_snapshot["snapshot_digest"] = "sha256:other"
        with self.assertRaisesRegex(ValueError, "snapshot_digest"):
            validate_semantic_work_receipt(sample_state(), wrong_snapshot)

        unknown_artifact = sample_receipt()
        unknown_artifact["artifacts"][0]["artifact_id"] = "missing"
        with self.assertRaisesRegex(ValueError, "unknown artifact_id"):
            validate_semantic_work_receipt(sample_state(), unknown_artifact)

    def test_verified_reuse_must_point_to_canonical_reuse_evidence(self) -> None:
        wrong_evidence = sample_receipt()
        wrong_evidence["artifacts"][1]["evidence_ids"] = ["e-fresh"]
        with self.assertRaisesRegex(ValueError, "another artifact|not canonical verified_reuse"):
            validate_semantic_work_receipt(sample_state(), wrong_evidence)

        missing_evidence = sample_receipt()
        del missing_evidence["artifacts"][1]["evidence_ids"]
        with self.assertRaisesRegex(ValueError, "requires evidence_ids"):
            validate_semantic_work_receipt(sample_state(), missing_evidence)

    def test_duplicate_artifacts_and_fresh_reuse_claims_are_rejected(self) -> None:
        duplicate = sample_receipt()
        duplicate["artifacts"][1] = {"artifact_id": "a1", "action": "fresh_read"}
        with self.assertRaisesRegex(ValueError, "duplicate artifact_id"):
            validate_semantic_work_receipt(sample_state(), duplicate)

        fresh_with_reuse = sample_receipt()
        fresh_with_reuse["artifacts"][0]["evidence_ids"] = ["e-fresh"]
        with self.assertRaisesRegex(ValueError, "fresh_read"):
            validate_semantic_work_receipt(sample_state(), fresh_with_reuse)

    def test_loader_reads_bounded_json_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "work.json"
            path.write_text(json.dumps(sample_receipt()), encoding="utf-8")
            receipt = load_semantic_work_receipt(path, sample_state())
        self.assertEqual(receipt["schema_version"], SEMANTIC_WORK_SCHEMA_VERSION)
        self.assertEqual(len(receipt["artifacts"]), 2)


if __name__ == "__main__":
    unittest.main()
