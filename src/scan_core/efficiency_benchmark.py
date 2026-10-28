"""Deterministic metrics for measuring Scan semantic-efficiency experiments.

This module summarizes validated canonical Scan state. It does not call a model,
estimate token usage, or infer savings from project size. Token metrics are only
included when supplied as exact host-reported counts by the caller.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Sequence
import json


BENCHMARK_SCHEMA_VERSION = "scan-efficiency-benchmark-1"
MAX_USAGE_BYTES = 64_000
_TOKEN_FIELDS = ("input_tokens", "output_tokens", "total_tokens", "cached_input_tokens")


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _rows(value: object) -> list[Mapping[str, Any]]:
    if not isinstance(value, list):
        return []
    return [row for row in value if isinstance(row, Mapping)]


def _nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def normalize_host_usage(usage: Mapping[str, Any] | None) -> dict[str, Any]:
    """Normalize exact host-reported token counts without estimating missing data."""
    if usage is None:
        return {"available": False}

    result: dict[str, Any] = {"available": True, "source": "host-reported"}
    for key in ("provider", "model", "request_id"):
        value = usage.get(key)
        if value is not None:
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"usage.{key} must be a non-empty string when supplied")
            result[key] = value.strip()

    present = False
    for key in _TOKEN_FIELDS:
        value = usage.get(key)
        if value is None:
            continue
        result[key] = _nonnegative_int(value, f"usage.{key}")
        present = True

    if not present:
        raise ValueError("usage must include at least one exact token count")

    if "total_tokens" not in result and "input_tokens" in result and "output_tokens" in result:
        result["total_tokens"] = result["input_tokens"] + result["output_tokens"]
        result["total_tokens_derived"] = True
    else:
        result["total_tokens_derived"] = False
    return result


def load_host_usage(path: str | Path) -> dict[str, Any]:
    """Load and validate a small JSON usage receipt supplied by the model host."""
    candidate = Path(path)
    raw = candidate.read_bytes()
    if len(raw) > MAX_USAGE_BYTES:
        raise ValueError(f"usage receipt exceeds {MAX_USAGE_BYTES} bytes")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid usage receipt: {error}") from error
    if not isinstance(payload, Mapping):
        raise ValueError("usage receipt must be a JSON object")
    normalize_host_usage(payload)
    return dict(payload)


def summarize_efficiency(
    state: Mapping[str, Any],
    *,
    label: str,
    usage: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Summarize one canonical Scan run using evidence already present in state."""
    if not isinstance(label, str) or not label.strip():
        raise ValueError("label must be a non-empty string")

    run = _mapping(state.get("run"))
    coverage = _mapping(state.get("coverage"))
    baseline = _mapping(state.get("baseline"))
    delta = _mapping(state.get("delta"))
    extensions = _mapping(state.get("extensions"))
    change_scope = _mapping(extensions.get("git_change_scope"))
    artifacts = _rows(state.get("artifacts"))
    evidence = _rows(state.get("evidence"))
    checks = _rows(state.get("checks"))

    artifact_status = Counter(str(row.get("status", "unknown")) for row in artifacts)
    artifact_origin = Counter(str(row.get("inspection_origin", "unknown")) for row in artifacts)
    check_status = Counter(str(row.get("status", "unknown")) for row in checks)
    evidence_origin = Counter(str(row.get("inspection_origin", "unknown")) for row in evidence)

    higher_level = [
        row for row in evidence
        if isinstance(row.get("evidence_class"), str) and bool(str(row.get("evidence_class")).strip())
    ]
    higher_level_origin = Counter(str(row.get("inspection_origin", "unknown")) for row in higher_level)

    priority_paths = change_scope.get("priority_paths")
    priority_count = len(priority_paths) if isinstance(priority_paths, list) else 0
    deleted = change_scope.get("deleted")
    deleted_count = len(deleted) if isinstance(deleted, list) else 0

    artifact_delta = _mapping(delta.get("artifacts"))
    finding_delta = _mapping(delta.get("findings"))
    unknown_delta = _mapping(delta.get("unknowns"))

    def count_list(group: Mapping[str, Any], key: str) -> int:
        value = group.get(key)
        return len(value) if isinstance(value, list) else 0

    return {
        "label": label.strip(),
        "scan_id": run.get("scan_id"),
        "scan_version": run.get("scan_version"),
        "scan_mode": run.get("scan_mode"),
        "snapshot_digest": _mapping(state.get("provenance")).get("snapshot_digest"),
        "coverage": {
            "discovery_complete": bool(coverage.get("discovery_complete", False)),
            "analysis_complete": bool(coverage.get("analysis_complete", False)),
            "checks_complete": bool(coverage.get("checks_complete", False)),
        },
        "artifacts": {
            "total": len(artifacts),
            "by_status": dict(sorted(artifact_status.items())),
            "by_inspection_origin": dict(sorted(artifact_origin.items())),
        },
        "checks": {
            "total": len(checks),
            "by_status": dict(sorted(check_status.items())),
        },
        "evidence": {
            "total": len(evidence),
            "by_inspection_origin": dict(sorted(evidence_origin.items())),
            "higher_level_classified_total": len(higher_level),
            "higher_level_classified_fresh": higher_level_origin.get("fresh", 0),
            "higher_level_classified_verified_reuse": higher_level_origin.get("verified_reuse", 0),
        },
        "baseline": {
            "status": baseline.get("status"),
            "reuse_enabled": bool(baseline.get("reuse_enabled", False)),
            "fresh_evidence_count": baseline.get("fresh_evidence_count"),
            "reused_evidence_count": baseline.get("reused_evidence_count"),
            "rejected_reuse_count": baseline.get("rejected_reuse_count"),
        },
        "delta": {
            "available": bool(delta.get("available", False)),
            "artifacts_added": count_list(artifact_delta, "added"),
            "artifacts_changed": count_list(artifact_delta, "changed"),
            "artifacts_removed": count_list(artifact_delta, "removed"),
            "artifacts_unchanged": count_list(artifact_delta, "unchanged"),
            "findings_new": count_list(finding_delta, "new"),
            "findings_modified": count_list(finding_delta, "modified"),
            "findings_resolved": count_list(finding_delta, "resolved"),
            "unknowns_new": count_list(unknown_delta, "new"),
            "unknowns_modified": count_list(unknown_delta, "modified"),
            "unknowns_resolved": count_list(unknown_delta, "resolved"),
        },
        "change_scope": {
            "available": bool(change_scope),
            "priority_paths_count": priority_count,
            "deleted_paths_count": deleted_count,
        },
        "host_usage": normalize_host_usage(usage),
    }


def compare_efficiency_runs(baseline: Mapping[str, Any], candidate: Mapping[str, Any]) -> dict[str, Any]:
    """Compare two benchmark summaries without inventing percentage savings."""
    before_evidence = _mapping(baseline.get("evidence"))
    after_evidence = _mapping(candidate.get("evidence"))
    before_usage = _mapping(baseline.get("host_usage"))
    after_usage = _mapping(candidate.get("host_usage"))

    common_token_fields = [
        key for key in _TOKEN_FIELDS
        if isinstance(before_usage.get(key), int)
        and not isinstance(before_usage.get(key), bool)
        and isinstance(after_usage.get(key), int)
        and not isinstance(after_usage.get(key), bool)
    ]
    provider_model_match: bool | None = None
    if all(isinstance(before_usage.get(key), str) and isinstance(after_usage.get(key), str) for key in ("provider", "model")):
        provider_model_match = (
            before_usage.get("provider") == after_usage.get("provider")
            and before_usage.get("model") == after_usage.get("model")
        )

    comparison: dict[str, Any] = {
        "baseline_label": baseline.get("label"),
        "candidate_label": candidate.get("label"),
        "higher_level_classified_fresh_delta": int(after_evidence.get("higher_level_classified_fresh", 0))
        - int(before_evidence.get("higher_level_classified_fresh", 0)),
        "higher_level_classified_verified_reuse_delta": int(
            after_evidence.get("higher_level_classified_verified_reuse", 0)
        ) - int(before_evidence.get("higher_level_classified_verified_reuse", 0)),
        "token_usage_comparable": bool(common_token_fields),
        "provider_model_match": provider_model_match,
        "token_delta": {
            key: int(after_usage[key]) - int(before_usage[key])
            for key in common_token_fields
        },
    }
    return comparison


def build_efficiency_benchmark(runs: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Build one deterministic benchmark document; comparisons use the first run as baseline."""
    if not runs:
        raise ValueError("at least one benchmark run is required")
    labels = [row.get("label") for row in runs]
    if len(set(labels)) != len(labels):
        raise ValueError("benchmark run labels must be unique")
    baseline = runs[0]
    return {
        "schema_version": BENCHMARK_SCHEMA_VERSION,
        "runs": [dict(row) for row in runs],
        "comparisons": [compare_efficiency_runs(baseline, row) for row in runs[1:]],
        "interpretation": {
            "token_counts": "Only exact host-reported usage is included; absent usage remains unavailable.",
            "coverage": "Lower work counts never upgrade partial coverage or prove equal finding quality.",
            "percent_savings": "Not calculated by this harness; measure and review raw counts before making a savings claim.",
        },
    }
