"""Deterministic SARIF 2.1.0 export for canonical Scan findings."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath, Path
from typing import Any, Mapping
from urllib.parse import quote

from .version import __version__

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_SEVERITY_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "moderate": "warning",
    "low": "note",
    "info": "note",
    "informational": "note",
    "none": "none",
}
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")


def _sarif_level(severity: object) -> str:
    return _SEVERITY_LEVELS.get(str(severity).strip().lower(), "warning")


def _rule_id(finding_id: str) -> str:
    digest = hashlib.sha256(finding_id.encode("utf-8")).hexdigest()[:20]
    return f"SCAN-{digest}"


def _repository_relative_uri(locator: object) -> str:
    raw = str(locator).strip().replace("\\", "/")
    if not raw or raw in {".", ".."}:
        raise ValueError("SARIF artifact locator must be a nonempty project-relative file path")
    if raw.startswith(("/", "//")) or _WINDOWS_DRIVE.match(raw):
        raise ValueError(f"SARIF artifact locator must be project-relative: {raw!r}")
    path = PurePosixPath(raw)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"SARIF artifact locator contains unsafe path segments: {raw!r}")
    normalized = path.as_posix()
    return quote(normalized, safe="/-._~")


def _artifact_location(artifact: Mapping[str, Any]) -> dict[str, Any] | None:
    if artifact.get("path_kind") != "file" or artifact.get("type") != "file":
        return None
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": _repository_relative_uri(artifact.get("locator", ""))}
        }
    }


def _message_text(finding: Mapping[str, Any]) -> str:
    title = str(finding.get("title", "Scan finding")).strip()
    impact = str(finding.get("impact", "")).strip()
    recommendation = str(finding.get("recommendation", "")).strip()
    parts = [title.rstrip(".?!") + "."]
    if impact:
        parts.append(f"Impact: {impact}")
    if recommendation:
        parts.append(f"Recommendation: {recommendation}")
    return " ".join(parts)


def build_sarif(state: Mapping[str, Any]) -> dict[str, Any]:
    """Convert validated canonical Scan state into deterministic SARIF 2.1.0.

    Only canonical findings become SARIF results. Unknowns, controls and unassessed
    checks remain Scan-native evidence and are deliberately not promoted to alerts.
    """
    artifacts = {str(row["id"]): row for row in state.get("artifacts", [])}
    findings = list(state.get("findings", []))
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []

    for rule_index, finding in enumerate(findings):
        finding_id = str(finding["id"])
        rule_id = _rule_id(finding_id)
        level = _sarif_level(finding.get("severity"))
        locations: list[dict[str, Any]] = []
        for artifact_id in finding.get("artifact_ids", []):
            artifact = artifacts.get(str(artifact_id))
            if artifact is None:
                raise ValueError(f"{finding_id}: references unknown artifact {artifact_id!r}")
            location = _artifact_location(artifact)
            if location is not None:
                locations.append(location)
        if not locations:
            raise ValueError(
                f"{finding_id}: no repository-relative file artifact can represent this finding in SARIF"
            )

        rules.append({
            "id": rule_id,
            "shortDescription": {"text": str(finding.get("title", finding_id))},
            "fullDescription": {"text": str(finding.get("impact", "Scan finding"))},
            "defaultConfiguration": {"level": level},
            "properties": {
                "tags": ["scan", "evidence-backed"],
                "scanFindingId": finding_id,
                "scanSeverity": str(finding.get("severity", "")),
                "scanVerificationState": str(finding.get("verification_state", "")),
            },
        })

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_index,
            "level": level,
            "message": {"text": _message_text(finding)},
            "locations": [locations[0]],
            "properties": {
                "scanFindingId": finding_id,
                "confidence": str(finding.get("confidence", "")),
                "verificationState": str(finding.get("verification_state", "")),
                "uncertainty": str(finding.get("uncertainty", "")),
                "safeVerification": str(finding.get("safe_verification", "")),
                "evidenceIds": [str(value) for value in finding.get("evidence_ids", [])],
            },
        }
        if len(locations) > 1:
            result["relatedLocations"] = [
                {
                    "id": index,
                    **location,
                    "message": {"text": "Additional artifact referenced by this Scan finding"},
                }
                for index, location in enumerate(locations[1:], start=1)
            ]
        results.append(result)

    run = state.get("run", {})
    coverage = state.get("coverage", {})
    sarif_run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "Scan",
                "semanticVersion": __version__,
                "informationUri": "https://github.com/legendteddy/scan",
                "rules": rules,
            }
        },
        "automationDetails": {"id": "scan/"},
        "results": results,
        "properties": {
            "scanSchemaVersion": str(state.get("schema_version", "")),
            "scanSnapshotDigest": str(run.get("snapshot_digest", "")),
            "scanAnalysisComplete": bool(coverage.get("analysis_complete", False)),
            "scanUnknownCount": len(state.get("unknowns", [])),
            "scanFindingCount": len(findings),
            "scanExportPolicy": "Only canonical findings are exported; unknowns and unassessed checks are not alerts.",
        },
    }
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [sarif_run]}


def sarif_text(state: Mapping[str, Any], *, pretty: bool = False) -> str:
    payload = build_sarif(state)
    if pretty:
        return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"


def write_sarif(state: Mapping[str, Any], output: Path, *, pretty: bool = False) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(sarif_text(state, pretty=pretty), encoding="utf-8", newline="\n")
