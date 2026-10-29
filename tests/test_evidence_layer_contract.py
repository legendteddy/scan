"""Cross-layer evidence contract invariants for the v0.6 development line."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scan_core import ScanConfig, scan_project
from scan_core.evidence_federation import import_evidence_bundle
from scan_core.handoff import build_handoff, canonical_handoff_json
from scan_core.inspection_bundle import create_inspection_bundle, verify_inspection_bundle
from scan_core.observed_receipt import import_observed_receipt
from scan_core.state import state_digest


class EvidenceLayerContractTests(unittest.TestCase):
    def test_federation_observation_handoff_and_bundle_preserve_one_evidence_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            (project / "app.py").write_text("def divide(a, b):\n    return a / b\n", encoding="utf-8")
            base = scan_project(ScanConfig(root=project, baseline_mode="none", reuse_enabled=False)).state
            artifact = next(row for row in base["artifacts"] if row["locator"] == "app.py")
            snapshot = base["provenance"]["snapshot_digest"]
            secret = "ghp_abcdefghijklmnopqrstuvwxyz123456"

            source_digest = "sha256:" + hashlib.sha256(b"contract-specialist-source").hexdigest()
            federation = {
                "scan_evidence_bundle_version": "1",
                "target": {"snapshot_digest": snapshot, "state_digest": state_digest(base)},
                "producer": {"kind": "external-tool", "name": "ContractScanner", "version": "1"},
                "adapter": {"name": "contract-adapter", "version": "1"},
                "source": {"format": "contract-json", "digest": source_digest},
                "coverage": {
                    "scope": f"One static rule with credential {secret}",
                    "limitations": "Specialist static result only; no runtime verification.",
                    "whole_project_complete": False,
                },
                "results": [{
                    "external_id": "FED-001",
                    "disposition": "finding",
                    "artifact_locator": "app.py",
                    "artifact_content_identity": artifact["content_identity"],
                    "evidence": {
                        "locator": "app.py:1-2",
                        "kind": "static",
                        "class": "static_semantic",
                        "claim": f"Specialist reports an unchecked divisor; token {secret}",
                        "result": f"Static result contained {secret}",
                        "method": "Imported specialist result; Scan did not execute the producer.",
                        "limitations": "Not independently reproduced by Scan.",
                    },
                    "finding": {
                        "title": "Unchecked division path",
                        "impact": "A zero divisor can raise an exception.",
                        "severity": "medium",
                        "confidence": "external-tool-reported",
                        "verification_state": "static",
                        "uncertainty": "External static evidence only.",
                        "recommendation": "Guard the divisor before division.",
                        "safe_verification": "Run an authorized bounded regression test.",
                    },
                }],
            }
            federation_raw = json.dumps(federation, sort_keys=True).encode("utf-8")
            federated = import_evidence_bundle(base, federation, source_bytes=federation_raw)
            federated_state = federated.state
            federation_receipt = federated_state["extensions"]["evidence_federation_imports"][-1]
            self.assertEqual(federation_receipt["base_state_digest_at_import"], state_digest(base))
            self.assertEqual(federation_receipt["target_snapshot_digest"], snapshot)
            self.assertFalse(federation_receipt["coverage"]["whole_project_complete"])
            self.assertFalse(federated_state["coverage"]["analysis_complete"])
            self.assertNotIn(secret, json.dumps(federated_state, sort_keys=True))

            observed = {
                "scan_observed_receipt_version": "1",
                "target": {
                    "snapshot_digest": snapshot,
                    "state_digest": state_digest(federated_state),
                },
                "executor": {"kind": "external-tool", "name": "ContractTestRunner", "version": "1"},
                "authorization": {
                    "basis": "workflow-owner approval",
                    "scope": f"One bounded regression test; reference {secret}",
                    "reference": f"ticket-{secret}",
                },
                "execution": {
                    "execution_id": "contract-run-1",
                    "started_at": "2026-10-29T00:00:00Z",
                    "completed_at": "2026-10-29T00:00:01Z",
                    "environment": "isolated contract test",
                    "target_executed": True,
                    "network_used": False,
                },
                "coverage": {
                    "scope": "One bounded zero-divisor regression test.",
                    "limitations": "No broader runtime behavior was observed.",
                    "whole_project_complete": False,
                },
                "observations": [{
                    "external_id": "OBS-001",
                    "outcome": "pass",
                    "artifact_locator": "app.py",
                    "artifact_content_identity": artifact["content_identity"],
                    "locator": "app.py:1-2",
                    "claim": "External test runner observed the declared bounded case.",
                    "result": "The declared regression assertion passed.",
                    "method": "External authorized test receipt; Scan imported data only.",
                    "limitations": "One bounded test case only.",
                    "control": {
                        "description": "The declared regression assertion passed externally.",
                        "limitations": "The pass does not establish behavior outside this case.",
                    },
                }],
            }
            observed_raw = json.dumps(observed, sort_keys=True).encode("utf-8")
            observed_result = import_observed_receipt(
                federated_state,
                observed,
                source_bytes=observed_raw,
            )
            final_state = observed_result.state
            observed_receipt = final_state["extensions"]["observed_evidence_imports"][-1]
            self.assertEqual(observed_receipt["base_state_digest_at_import"], state_digest(federated_state))
            self.assertEqual(observed_receipt["target_snapshot_digest"], snapshot)
            self.assertFalse(observed_receipt["authorization_attestation"]["verified_by_scan"])
            self.assertFalse(observed_receipt["execution"]["target_executed_by_scan_during_import"])
            self.assertFalse(observed_receipt["execution"]["network_used_by_scan_during_import"])
            self.assertTrue(observed_receipt["execution"]["target_executed_by_external_system"])
            self.assertFalse(observed_receipt["coverage"]["whole_project_complete"])
            self.assertFalse(final_state["coverage"]["analysis_complete"])
            self.assertNotIn(secret, json.dumps(final_state, sort_keys=True))

            handoff = build_handoff(final_state)
            handoff_json = canonical_handoff_json(handoff)
            self.assertEqual(handoff["identity"]["state_digest"], state_digest(final_state))
            self.assertEqual(handoff["identity"]["snapshot_digest"], snapshot)
            self.assertFalse(handoff["projection"]["contains_source_bytes"])
            self.assertFalse(handoff["projection"]["contains_raw_evidence_results"])
            self.assertNotIn(secret, handoff_json)

            bundle_path = root / "inspection.scanbundle"
            created = create_inspection_bundle(final_state, bundle_path)
            verified = verify_inspection_bundle(bundle_path)
            self.assertEqual(created.state_digest, state_digest(final_state))
            self.assertEqual(verified["state_digest"], state_digest(final_state))
            self.assertEqual(verified["snapshot_digest"], snapshot)
            self.assertEqual(verified["handoff_digest"], handoff["handoff_digest"])
            self.assertFalse(verified["target_executed"])
            self.assertFalse(verified["network_used"])
            self.assertFalse(verified["coverage"]["analysis_complete"])
            self.assertNotIn(secret.encode("utf-8"), bundle_path.read_bytes())


if __name__ == "__main__":
    unittest.main()
