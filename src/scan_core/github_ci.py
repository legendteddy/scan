"""GitHub Actions summary/output helpers for canonical Scan state."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Mapping


def _count_status(rows: list[Mapping[str, Any]], status: str) -> int:
    return sum(1 for row in rows if row.get("status") == status)


def github_summary(state: Mapping[str, Any]) -> str:
    """Return a conservative GitHub-flavored Markdown summary for Scan state."""
    coverage = state.get("coverage", {})
    artifacts = list(state.get("artifacts", []))
    checks = list(state.get("checks", []))
    findings = list(state.get("findings", []))
    unknowns = list(state.get("unknowns", []))
    severities = Counter(str(row.get("severity", "unknown")).lower() for row in findings)
    status_counts = Counter(str(row.get("status", "unknown")) for row in artifacts)
    check_counts = Counter(str(row.get("status", "unknown")) for row in checks)
    version = state.get("producer", {}).get("version", "unknown")
    scan_id = state.get("run", {}).get("scan_id", "unknown")
    analysis_complete = bool(coverage.get("analysis_complete", False))
    checks_complete = bool(coverage.get("checks_complete", False))
    discovery_complete = bool(coverage.get("discovery_complete", False))

    delta = state.get("delta", {}) if isinstance(state.get("delta", {}), Mapping) else {}
    delta_available = bool(delta.get("available", False))

    lines = [
        "## Scan project inspection",
        "",
        f"Scan `{version}` · run `{scan_id}`",
        "",
        "| Signal | Result |",
        "| --- | ---: |",
        f"| Artifacts discovered | {len(artifacts)} |",
        f"| Artifacts analyzed | {status_counts.get('analyzed', 0)} |",
        f"| Canonical findings | {len(findings)} |",
        f"| Unknowns | {len(unknowns)} |",
        f"| Checks assessed | {check_counts.get('assessed', 0)} / {len(checks)} |",
        f"| Discovery complete | {'yes' if discovery_complete else 'no'} |",
        f"| Semantic analysis complete | {'yes' if analysis_complete else 'no'} |",
        f"| Checks complete | {'yes' if checks_complete else 'no'} |",
        "",
    ]
    if delta_available:
        artifact_delta = delta.get("artifacts", {})
        finding_delta = delta.get("findings", {})
        unknown_delta = delta.get("unknowns", {})
        lines.extend([
            "### Since validated baseline",
            "",
            "| Delta | Count |",
            "| --- | ---: |",
            f"| Artifacts added | {len(artifact_delta.get('added', []))} |",
            f"| Artifacts changed | {len(artifact_delta.get('changed', []))} |",
            f"| Artifacts removed | {len(artifact_delta.get('removed', []))} |",
            f"| Findings new | {len(finding_delta.get('new', []))} |",
            f"| Findings modified | {len(finding_delta.get('modified', []))} |",
            f"| Findings resolved | {len(finding_delta.get('resolved', []))} |",
            f"| Unknowns new | {len(unknown_delta.get('new', []))} |",
            f"| Unknowns modified | {len(unknown_delta.get('modified', []))} |",
            f"| Unknowns resolved | {len(unknown_delta.get('resolved', []))} |",
            "",
            "> Resolved means absent from the current state; it is not proof that a problem was fixed.",
            "",
        ])

    if findings:
        lines.extend([
            "### Finding severity",
            "",
            f"- critical: {severities.get('critical', 0)}",
            f"- high: {severities.get('high', 0)}",
            f"- medium: {severities.get('medium', 0)}",
            f"- low: {severities.get('low', 0)}",
            f"- informational/other: {sum(v for k, v in severities.items() if k not in {'critical', 'high', 'medium', 'low'})}",
            "",
        ])
    if unknowns:
        lines.extend([
            "### Unknowns remain",
            "",
            *[f"- {row.get('question', row.get('id', 'Unknown'))}" for row in unknowns[:10]],
        ])
        if len(unknowns) > 10:
            lines.append(f"- … and {len(unknowns) - 10} more")
        lines.append("")
    lines.extend([
        "> Scan's deterministic Core does not turn inventory into semantic or runtime proof. "
        "Zero findings is not a clean bill of health; review unknowns and unassessed checks before drawing conclusions.",
        "",
    ])
    return "\n".join(lines)


def github_outputs(
    state: Mapping[str, Any],
    *,
    state_path: Path,
    report_path: Path,
    sarif_path: Path,
    summary_path: Path,
) -> dict[str, str]:
    coverage = state.get("coverage", {})
    checks = list(state.get("checks", []))
    artifacts = list(state.get("artifacts", []))
    delta = state.get("delta", {}) if isinstance(state.get("delta", {}), Mapping) else {}
    delta_available = bool(delta.get("available", False))

    def delta_count(group: str, key: str) -> str:
        if not delta_available:
            return ""
        rows = delta.get(group, {})
        return str(len(rows.get(key, []))) if isinstance(rows, Mapping) else "0"

    return {
        "state": str(state_path.resolve()),
        "report": str(report_path.resolve()),
        "sarif": str(sarif_path.resolve()),
        "summary": str(summary_path.resolve()),
        "findings-count": str(len(state.get("findings", []))),
        "unknowns-count": str(len(state.get("unknowns", []))),
        "checks-assessed": str(_count_status(checks, "assessed")),
        "checks-total": str(len(checks)),
        "artifacts-discovered": str(len(artifacts)),
        "analysis-complete": "true" if coverage.get("analysis_complete") else "false",
        "baseline-status": str(state.get("baseline", {}).get("status", "unknown")),
        "delta-available": "true" if delta_available else "false",
        "artifacts-added": delta_count("artifacts", "added"),
        "artifacts-changed": delta_count("artifacts", "changed"),
        "artifacts-removed": delta_count("artifacts", "removed"),
        "findings-new": delta_count("findings", "new"),
        "findings-modified": delta_count("findings", "modified"),
        "findings-resolved": delta_count("findings", "resolved"),
        "unknowns-new": delta_count("unknowns", "new"),
        "unknowns-modified": delta_count("unknowns", "modified"),
        "unknowns-resolved": delta_count("unknowns", "resolved"),
        "scan-version": str(state.get("producer", {}).get("version", "unknown")),
    }


def append_github_outputs(path: Path, values: Mapping[str, str]) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        for key, value in values.items():
            if "\n" in value or "\r" in value:
                raise ValueError(f"GitHub output {key!r} contains a newline")
            handle.write(f"{key}={value}\n")
