"""Evidence federation bundle import tests."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scan_core import ScanConfig, scan_project
from scan_core.evidence_federation import import_evidence_bundle
from scan_core.state import state_digest


class EvidenceFederationTests(unittest.TestCase):
    def _state(self):
        directory = tempfile.TemporaryDirectory()
        root = Path(directory.name)
        (root / "app.py").write_text("def divide(a, b):\n    return a / b\n", encoding="utf-8")
        state = scan_project(ScanConfig(root=root, baseline_mode="none", reuse_enabled=False)).state
        artifact = next(row for row in state["artifacts"] if row["locator"] == "app.py")
        self.addCleanup(directory.cleanup)
        return state, artifact

    def _bundle(self, state, artifact):
        source_digest = "sha256:" + hashlib.sha256(b"specialist-source").hexdigest()
        return {
            "scan_evidence_bundle_version": "1",
            "target": {
                "snapshot_digest": state["provenance"]["snapshot_digest"],
                "state_digest": state_digest(state),
            },
            "producer": {"kind": "external-tool", "name": "ExampleScanner", "version": "3.2.1"},
            "adapter": {"name": "example-to-scan", "version": "1.0.0"},
            "source": {"format": "example-json", "digest": source_digest},
            "coverage": {
                "scope": "ExampleScanner rule set against app.py",
                "limitations": "External static rules only; no runtime execution and no whole-project Scan coverage claim.",
                "whole_project_complete": False,
            },
            "results": [{
                "external_id": "EX-001",
                "disposition": "finding",
                "artifact_locator": "app.py",
                "artifact_content_identity": artifact["content_identity"],
                "evidence": {
                    "locator": "app.py:1-2",
                    "kind": "static",
                    "class": "static_semantic",
                    "claim": "ExampleScanner reports an unchecked division path",
                    "result": "The divisor reaches division without a zero guard.",
                    "method": "Imported specialist static-analysis result; Scan did not execute ExampleScanner.",
                    "limitations": "External result was not independently reproduced by Scan.",
                },
                "finding": {
                    "title": "Unchecked division by zero",
                    "impact": "A zero divisor can raise an exception.",
                    "severity": "medium",
                    "confidence": "external-tool-reported",
                    "verification_state": "static",
                    "uncertainty": "Imported from a specialist result without independent reproduction.",
                    "recommendation": "Validate the divisor before division.",
                    "safe_verification": "Add an authorized unit test covering a zero divisor and rerun the same scanner configuration.",
                },
            }],
        }

    def test_mapped_finding_is_bound_to_snapshot_artifact_and_bundle(self):
        state, artifact = self._state()
        bundle = self._bundle(state, artifact)
        raw = json.dumps(bundle, sort_keys=True).encode("utf-8")
        imported = import_evidence_bundle(state, bundle, source_bytes=raw)

        self.assertEqual(imported.imported_findings, 1)
        self.assertEqual(imported.imported_unknowns, 0)
        self.assertEqual(imported.imported_evidence, 1)
        self.assertEqual(imported.unmapped_results, 0)
        evidence = next(row for row in imported.state["evidence"] if row["id"].startswith("evidence:federation:"))
        self.assertEqual(evidence["producer"], {"kind": "external-tool", "name": "ExampleScanner", "version": "3.2.1"})
        self.assertEqual(evidence["artifact_content_digest"], artifact["content_identity"])
        self.assertEqual(evidence["source_digest"], imported.bundle_digest)
        self.assertEqual(evidence["freshness"]["status"], "fresh")
        imported_artifact = next(row for row in imported.state["artifacts"] if row["id"] == artifact["id"])
        self.assertEqual(imported_artifact["status"], "partial")
        self.assertFalse(imported.state["coverage"]["analysis_complete"])
        receipt = imported.state["extensions"]["evidence_federation_imports"][-1]
        self.assertEqual(receipt["bundle_digest"], imported.bundle_digest)
        self.assertEqual(receipt["target_snapshot_digest"], state["provenance"]["snapshot_digest"])
        self.assertEqual(receipt["base_state_digest_at_import"], state_digest(state))
        self.assertFalse(receipt["source"]["digest_verified_by_scan"])
        self.assertFalse(receipt["coverage"]["whole_project_complete"])

    def test_snapshot_mismatch_fails_closed(self):
        state, artifact = self._state()
        bundle = self._bundle(state, artifact)
        bundle["target"]["snapshot_digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(ValueError, "snapshot_digest does not match"):
            import_evidence_bundle(state, bundle)

    def test_exact_base_state_digest_is_enforced_when_declared(self):
        state, artifact = self._state()
        bundle = self._bundle(state, artifact)
        bundle["target"]["state_digest"] = "sha256:" + "1" * 64
        with self.assertRaisesRegex(ValueError, "state_digest does not match"):
            import_evidence_bundle(state, bundle)

    def test_artifact_content_identity_mismatch_fails_closed(self):
        state, artifact = self._state()
        bundle = self._bundle(state, artifact)
        bundle["results"][0]["artifact_content_identity"] = "sha256:" + "2" * 64
        with self.assertRaisesRegex(ValueError, "artifact_content_identity does not match"):
            import_evidence_bundle(state, bundle)

    def test_unmapped_result_is_retained_as_unknown_not_promoted(self):
        state, artifact = self._state()
        bundle = self._bundle(state, artifact)
        bundle["results"][0]["artifact_locator"] = "missing.py"
        bundle["results"][0]["artifact_content_identity"] = "sha256:" + "3" * 64
        imported = import_evidence_bundle(state, bundle)
        self.assertEqual(imported.imported_findings, 0)
        self.assertEqual(imported.imported_unknowns, 1)
        self.assertEqual(imported.imported_evidence, 0)
        self.assertEqual(imported.unmapped_results, 1)
        unknown = next(row for row in imported.state["unknowns"] if row["id"].startswith("unknown:federation:"))
        self.assertIn("did not map", unknown["reason"])
        self.assertEqual(unknown["artifact_ids"], [])

    def test_finding_cannot_claim_stronger_verification_than_its_evidence(self):
        state, artifact = self._state()
        bundle = self._bundle(state, artifact)
        bundle["results"][0]["finding"]["verification_state"] = "observed"
        with self.assertRaisesRegex(ValueError, "must match supporting evidence.kind"):
            import_evidence_bundle(state, bundle)

    def test_coverage_receipt_is_privacy_redacted(self):
        state, artifact = self._state()
        bundle = self._bundle(state, artifact)
        secret = "ghp_abcdefghijklmnopqrstuvwxyz123456"
        bundle["coverage"]["scope"] = f"scanner scope token {secret}"
        imported = import_evidence_bundle(state, bundle)
        receipt = imported.state["extensions"]["evidence_federation_imports"][-1]
        self.assertNotIn(secret, receipt["coverage"]["scope"])

    def test_whole_project_completeness_claim_is_rejected(self):
        state, artifact = self._state()
        bundle = self._bundle(state, artifact)
        bundle["coverage"]["whole_project_complete"] = True
        with self.assertRaisesRegex(ValueError, "whole_project_complete must be false"):
            import_evidence_bundle(state, bundle)

    def test_identical_duplicate_external_result_is_ignored_but_conflict_fails(self):
        state, artifact = self._state()
        bundle = self._bundle(state, artifact)
        bundle["results"].append(deepcopy(bundle["results"][0]))
        imported = import_evidence_bundle(state, bundle)
        self.assertEqual(imported.imported_findings, 1)
        self.assertEqual(imported.ignored_results, 1)

        conflict = self._bundle(state, artifact)
        second = deepcopy(conflict["results"][0])
        second["finding"]["title"] = "Conflicting reuse of the same external ID"
        conflict["results"].append(second)
        with self.assertRaisesRegex(ValueError, "conflicts with an earlier result"):
            import_evidence_bundle(state, conflict)


if __name__ == "__main__":
    unittest.main()
