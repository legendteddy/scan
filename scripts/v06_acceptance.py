"""Installed-artifact acceptance gate for Scan v0.6.0.

This gate uses only synthetic temporary inputs. Scan performs no target-code
execution and no network access. External evidence/observation payloads are
synthetic data receipts created by this script and imported by the installed
package.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from scan_core.scanbench2_corpus import summarize_corpus
from scan_core.state import state_digest
from scan_core.version import __version__
import scanbench_data

EXPECTED_VERSION = "0.6.0"


def run(*args: str, cwd: Path | None = None, capture: bool = False) -> str:
    completed = subprocess.run(
        list(args),
        cwd=cwd,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return completed.stdout if capture else ""


def executable(name: str) -> str:
    value = shutil.which(name)
    if value is None:
        raise RuntimeError(f"installed {name} console entrypoint is not on PATH")
    return value


def scan(*args: str, cwd: Path | None = None, capture: bool = False) -> str:
    return run(executable("scan"), *args, cwd=cwd, capture=capture)


def scan_bundle(*args: str, cwd: Path | None = None, capture: bool = False) -> str:
    return run(executable("scan-bundle"), *args, cwd=cwd, capture=capture)


def feedback(*args: str, cwd: Path | None = None) -> dict[str, object]:
    output = run(sys.executable, "-m", "scan_core.feedback", *args, "--json", cwd=cwd, capture=True)
    return json.loads(output)


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True), encoding="utf-8")


def main() -> int:
    installed_version = importlib.metadata.version("scan-skill")
    if __version__ != EXPECTED_VERSION or installed_version != EXPECTED_VERSION:
        raise AssertionError(
            f"release candidate version mismatch: runtime={__version__!r} metadata={installed_version!r}"
        )
    reported = scan("--version", capture=True).strip()
    if reported != f"scan {EXPECTED_VERSION}":
        raise AssertionError(f"unexpected installed CLI version: {reported!r}")

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        project = root / "Synthetic v0.6 Project"
        project.mkdir()
        (project / "app.py").write_text("def value():\n    return 1\n", encoding="utf-8")

        base_state_path = root / "base-state.json"
        scan(
            str(project), "--offline", "--baseline", "none", "--no-html",
            "--state", str(base_state_path), "--quiet",
        )
        scan("validate", str(base_state_path))
        base = json.loads(base_state_path.read_text(encoding="utf-8"))
        if base["run"]["network_used"] is not False or base["run"]["target_executed"] is not False:
            raise AssertionError("base synthetic scan unexpectedly recorded network/target execution")
        artifact = next(row for row in base["artifacts"] if row.get("locator") == "app.py")
        snapshot = base["provenance"]["snapshot_digest"]

        handoff_path = root / "handoff.json"
        handoff = json.loads(
            scan("handoff", str(base_state_path), "--output", str(handoff_path), "--json", capture=True)
        )
        if handoff["identity"]["state_digest"] != state_digest(base):
            raise AssertionError("handoff is not bound to the exact base state")
        if handoff["identity"]["snapshot_digest"] != snapshot:
            raise AssertionError("handoff snapshot identity mismatch")
        if handoff["projection"]["contains_source_bytes"] or handoff["projection"]["contains_raw_evidence_results"]:
            raise AssertionError("handoff projection crossed its privacy boundary")

        source_digest = "sha256:" + hashlib.sha256(b"v06-acceptance-specialist-source").hexdigest()
        federation = {
            "scan_evidence_bundle_version": "1",
            "target": {"snapshot_digest": snapshot, "state_digest": state_digest(base)},
            "producer": {"kind": "external-tool", "name": "V06AcceptanceScanner", "version": "1"},
            "adapter": {"name": "v06-acceptance-adapter", "version": "1"},
            "source": {"format": "synthetic-json", "digest": source_digest},
            "coverage": {
                "scope": "One synthetic static result for installed-artifact acceptance.",
                "limitations": "Synthetic static evidence only; no runtime or whole-project claim.",
                "whole_project_complete": False,
            },
            "results": [{
                "external_id": "V06-FED-001",
                "disposition": "finding",
                "artifact_locator": "app.py",
                "artifact_content_identity": artifact["content_identity"],
                "evidence": {
                    "locator": "app.py:1-2",
                    "kind": "static",
                    "class": "static_semantic",
                    "claim": "Synthetic specialist result is bound to the current artifact.",
                    "result": "Bounded synthetic result.",
                    "method": "Synthetic external-tool receipt; Scan imports data only.",
                    "limitations": "Not independently reproduced by Scan.",
                },
                "finding": {
                    "title": "Synthetic specialist finding",
                    "impact": "Acceptance-test-only impact.",
                    "severity": "low",
                    "confidence": "external-tool-reported",
                    "verification_state": "static",
                    "uncertainty": "Synthetic external evidence only.",
                    "recommendation": "No production action; this is an acceptance fixture.",
                    "safe_verification": "Repeat the installed-artifact acceptance gate.",
                },
            }],
        }
        federation_path = root / "federation.json"
        write_json(federation_path, federation)
        federated_state_path = root / "federated-state.json"
        federation_summary = json.loads(
            scan(
                "import-evidence", str(base_state_path), str(federation_path),
                "--output", str(federated_state_path), "--json", capture=True,
            )
        )
        if federation_summary["imported_findings"] != 1 or federation_summary["imported_evidence"] != 1:
            raise AssertionError(f"unexpected federation summary: {federation_summary}")
        federated = json.loads(federated_state_path.read_text(encoding="utf-8"))
        federation_receipt = federated["extensions"]["evidence_federation_imports"][-1]
        if federation_receipt["coverage"]["whole_project_complete"] is not False:
            raise AssertionError("federation import overclaimed whole-project completeness")
        if federated["coverage"]["analysis_complete"] is not False:
            raise AssertionError("federation import upgraded whole-project analysis completeness")

        observed = {
            "scan_observed_receipt_version": "1",
            "target": {"snapshot_digest": snapshot, "state_digest": state_digest(federated)},
            "executor": {"kind": "external-tool", "name": "V06AcceptanceRuntime", "version": "1"},
            "authorization": {
                "basis": "synthetic acceptance fixture",
                "scope": "Import one declared observation; no target execution by this acceptance gate.",
                "reference": "v06-acceptance",
            },
            "execution": {
                "execution_id": "v06-acceptance-observed-1",
                "started_at": "2026-01-01T00:00:00Z",
                "completed_at": "2026-01-01T00:00:01Z",
                "environment": "synthetic acceptance receipt",
                "target_executed": False,
                "network_used": False,
            },
            "coverage": {
                "scope": "One synthetic observed control.",
                "limitations": "No target execution occurred; no broader runtime behavior is established.",
                "whole_project_complete": False,
            },
            "observations": [{
                "external_id": "V06-OBS-001",
                "outcome": "pass",
                "artifact_locator": "app.py",
                "artifact_content_identity": artifact["content_identity"],
                "locator": "app.py:1-2",
                "claim": "Synthetic acceptance receipt declares one bounded pass.",
                "result": "Synthetic observation passed.",
                "method": "Data-only external receipt; Scan did not execute the target.",
                "limitations": "Acceptance fixture only.",
                "control": {
                    "description": "The declared synthetic observation passed.",
                    "limitations": "This pass establishes nothing outside the declared case.",
                },
            }],
        }
        observed_path = root / "observed.json"
        write_json(observed_path, observed)
        final_state_path = root / "final-state.json"
        observed_summary = json.loads(
            scan(
                "import-observed", str(federated_state_path), str(observed_path),
                "--output", str(final_state_path), "--json", capture=True,
            )
        )
        if observed_summary["imported_controls"] != 1 or observed_summary["imported_evidence"] != 1:
            raise AssertionError(f"unexpected observed-evidence summary: {observed_summary}")
        scan("validate", str(final_state_path))
        final_state = json.loads(final_state_path.read_text(encoding="utf-8"))
        observed_receipt = final_state["extensions"]["observed_evidence_imports"][-1]
        if observed_receipt["authorization_attestation"]["verified_by_scan"] is not False:
            raise AssertionError("Scan overclaimed authorization verification")
        execution = observed_receipt["execution"]
        if execution["target_executed_by_scan_during_import"] or execution["network_used_by_scan_during_import"]:
            raise AssertionError("observed import crossed the no-execution/no-network boundary")
        if final_state["coverage"]["analysis_complete"] is not False:
            raise AssertionError("observed import upgraded whole-project analysis completeness")

        bundle_path = root / "inspection.scanbundle"
        created = json.loads(
            scan_bundle("create", str(final_state_path), "--output", str(bundle_path), "--json", capture=True)
        )
        verified = json.loads(scan_bundle("verify", str(bundle_path), "--json", capture=True))
        if not verified["verified"]:
            raise AssertionError("Inspection Bundle verifier did not return verified=true")
        if verified["state_digest"] != state_digest(final_state):
            raise AssertionError("Inspection Bundle state digest mismatch")
        if verified["bundle_digest"] != created["bundle_digest"]:
            raise AssertionError("Inspection Bundle digest mismatch")
        if verified["target_executed"] or verified["network_used"]:
            raise AssertionError("Inspection Bundle verification crossed its safety boundary")

        feedback_home = root / "feedback-home"
        contribution = feedback(
            "--state", str(final_state_path),
            "--agent", "v06-acceptance-agent",
            "--host", "installed-artifact-gate",
            "--test", "v06 installed acceptance=pass",
            "--feedback", "Installed v0.6 evidence chain completed successfully.",
            "--submit", "never",
            "--feedback-home", str(feedback_home),
        )
        if contribution["status"] != "queued" or contribution["submission_authorized"] is not False:
            raise AssertionError(f"unexpected feedback queue result: {contribution}")
        receipt_path = Path(str(contribution["receipt_path"]))
        outbox_path = Path(str(contribution["outbox_path"]))
        if not receipt_path.is_file() or not outbox_path.is_file():
            raise AssertionError("feedback canonical receipt/outbox copy was not written")
        flushed = feedback(
            "--flush", "--submit", "never", "--feedback-home", str(feedback_home)
        )
        if flushed["status"] != "not_authorized" or flushed["processed"] != 0 or flushed["pending"] != 1:
            raise AssertionError(f"unauthorized feedback flush was not fail-closed: {flushed}")
        if not outbox_path.is_file():
            raise AssertionError("unauthorized feedback flush removed the queued receipt")

        corpus_root = Path(scanbench_data.__file__).resolve().parent / "ground_truth"
        corpus = summarize_corpus(corpus_root)
        if corpus["project_count"] != 26 or corpus["condition_count"] != 209:
            raise AssertionError(f"unexpected packaged ScanBench 2 corpus: {corpus}")
        if corpus["no_blended_quality_score"] is not True:
            raise AssertionError("ScanBench 2 corpus summary lost no-blended-score contract")

    print("PASS: Scan 0.6.0 installed-artifact acceptance")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
