"""Deterministic bounded handoff projection for Scan state.

The handoff is a compact digest-bound projection for another agent. The full
validated Scan state remains the source of truth. Source bytes and raw evidence
results are deliberately not copied into the handoff.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Mapping, Sequence

from .state import state_digest
from .validate import validate_state

HANDOFF_VERSION = "1"
DEFAULT_SECTION_LIMIT = 100
DEFAULT_REF_LIMIT = 12
DEFAULT_TEXT_LIMIT = 800
_MAX_SECTION_LIMIT = 1000
_MAX_REF_LIMIT = 100
_MAX_TEXT_LIMIT = 4000
MAX_HANDOFF_BYTES = 4_000_000
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
_CHECK_STATUS_ORDER = {"blocked": 0, "partial": 1, "not_assessed": 2, "assessed": 3, "not_applicable": 4}


def _positive_bounded(value: int, label: str, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0 or value > maximum:
        raise ValueError(f"{label} must be an integer from 1 to {maximum}")
    return value


def _text(value: Any, *, limit: int, flags: set[str], flag: str) -> str:
    if not isinstance(value, str):
        return ""
    normalized = " ".join(value.split())
    if len(normalized) <= limit:
        return normalized
    flags.add(flag)
    return normalized[: max(0, limit - 1)] + "…"


def _refs(values: Any, *, limit: int, flags: set[str], flag: str) -> dict[str, Any]:
    rows = sorted({item for item in (values or []) if isinstance(item, str) and item})
    included = rows[:limit]
    omitted = len(rows) - len(included)
    if omitted:
        flags.add(flag)
    return {"total": len(rows), "included": len(included), "omitted": omitted, "ids": included}


def _bounded_list(
    values: Any, *, limit: int, text_limit: int, flags: set[str], flag: str
) -> dict[str, Any]:
    rows = [item for item in (values or []) if isinstance(item, str) and item]
    included_rows = rows[:limit]
    omitted = len(rows) - len(included_rows)
    if omitted:
        flags.add(flag)
    items = [
        _text(item, limit=text_limit, flags=flags, flag=f"{flag}.text")
        for item in included_rows
    ]
    return {"total": len(rows), "included": len(items), "omitted": omitted, "items": items}


def _section(items: Sequence[dict[str, Any]], total: int, flags: set[str], flag: str) -> dict[str, Any]:
    omitted = total - len(items)
    if omitted:
        flags.add(flag)
    return {"total": total, "included": len(items), "omitted": omitted, "items": list(items)}


def _finding_row(row: Mapping[str, Any], *, ref_limit: int, text_limit: int, flags: set[str]) -> dict[str, Any]:
    ident = str(row["id"])
    return {
        "id": ident,
        "title": _text(row.get("title"), limit=text_limit, flags=flags, flag=f"{ident}.title"),
        "severity": row.get("severity"),
        "confidence": row.get("confidence"),
        "verification_state": row.get("verification_state"),
        "impact": _text(row.get("impact"), limit=text_limit, flags=flags, flag=f"{ident}.impact"),
        "uncertainty": _text(row.get("uncertainty"), limit=text_limit, flags=flags, flag=f"{ident}.uncertainty"),
        "recommendation": _text(row.get("recommendation"), limit=text_limit, flags=flags, flag=f"{ident}.recommendation"),
        "safe_verification": _text(row.get("safe_verification"), limit=text_limit, flags=flags, flag=f"{ident}.safe_verification"),
        "artifact_refs": _refs(row.get("artifact_ids"), limit=ref_limit, flags=flags, flag=f"{ident}.artifact_refs"),
        "evidence_refs": _refs(row.get("evidence_ids"), limit=ref_limit, flags=flags, flag=f"{ident}.evidence_refs"),
    }


def _control_row(row: Mapping[str, Any], *, ref_limit: int, text_limit: int, flags: set[str]) -> dict[str, Any]:
    ident = str(row["id"])
    return {
        "id": ident,
        "description": _text(row.get("description"), limit=text_limit, flags=flags, flag=f"{ident}.description"),
        "effectiveness_status": row.get("effectiveness_status"),
        "limitations": _text(row.get("limitations"), limit=text_limit, flags=flags, flag=f"{ident}.limitations"),
        "artifact_refs": _refs(row.get("artifact_ids"), limit=ref_limit, flags=flags, flag=f"{ident}.artifact_refs"),
        "evidence_refs": _refs(row.get("evidence_ids"), limit=ref_limit, flags=flags, flag=f"{ident}.evidence_refs"),
    }


def _unknown_row(row: Mapping[str, Any], *, ref_limit: int, text_limit: int, flags: set[str]) -> dict[str, Any]:
    ident = str(row["id"])
    return {
        "id": ident,
        "question": _text(row.get("question"), limit=text_limit, flags=flags, flag=f"{ident}.question"),
        "reason": _text(row.get("reason"), limit=text_limit, flags=flags, flag=f"{ident}.reason"),
        "impact": _text(row.get("impact"), limit=text_limit, flags=flags, flag=f"{ident}.impact"),
        "next_safe_step": _text(row.get("next_safe_step"), limit=text_limit, flags=flags, flag=f"{ident}.next_safe_step"),
        "artifact_refs": _refs(row.get("artifact_ids"), limit=ref_limit, flags=flags, flag=f"{ident}.artifact_refs"),
        "evidence_refs": _refs(row.get("evidence_ids"), limit=ref_limit, flags=flags, flag=f"{ident}.evidence_refs"),
    }


def _check_row(row: Mapping[str, Any], *, ref_limit: int, text_limit: int, flags: set[str]) -> dict[str, Any]:
    ident = str(row["id"])
    return {
        "id": ident,
        "category": row.get("category"),
        "title": _text(row.get("title"), limit=text_limit, flags=flags, flag=f"{ident}.title"),
        "status": row.get("status"),
        "verification_state": row.get("verification_state"),
        "scope": _text(row.get("scope"), limit=text_limit, flags=flags, flag=f"{ident}.scope"),
        "result": _text(row.get("result"), limit=text_limit, flags=flags, flag=f"{ident}.result"),
        "limitations": _text(row.get("limitations"), limit=text_limit, flags=flags, flag=f"{ident}.limitations"),
        "reason": _text(row.get("reason"), limit=text_limit, flags=flags, flag=f"{ident}.reason"),
        "next_step": _text(row.get("next_step"), limit=text_limit, flags=flags, flag=f"{ident}.next_step"),
        "artifact_refs": _refs(row.get("artifact_ids"), limit=ref_limit, flags=flags, flag=f"{ident}.artifact_refs"),
        "evidence_refs": _refs(row.get("evidence_ids"), limit=ref_limit, flags=flags, flag=f"{ident}.evidence_refs"),
        "related_refs": _refs(row.get("related_ids"), limit=ref_limit, flags=flags, flag=f"{ident}.related_refs"),
    }


def _action_row(row: Mapping[str, Any], *, ref_limit: int, text_limit: int, flags: set[str]) -> dict[str, Any]:
    ident = str(row["id"])
    return {
        "id": ident,
        "priority": row.get("priority"),
        "completion_state": row.get("completion_state"),
        "description": _text(row.get("description"), limit=text_limit, flags=flags, flag=f"{ident}.description"),
        "authorization_requirements": _text(
            row.get("authorization_requirements"), limit=text_limit, flags=flags, flag=f"{ident}.authorization_requirements"
        ),
        "expected_verification": _text(
            row.get("expected_verification"), limit=text_limit, flags=flags, flag=f"{ident}.expected_verification"
        ),
        "related_refs": _refs(row.get("related_ids"), limit=ref_limit, flags=flags, flag=f"{ident}.related_refs"),
        "prerequisites": _refs(row.get("prerequisites"), limit=ref_limit, flags=flags, flag=f"{ident}.prerequisites"),
    }


def _collect_primary_refs(sections: Iterable[Mapping[str, Any]]) -> tuple[set[str], set[str]]:
    artifacts: set[str] = set()
    evidence: set[str] = set()
    for section in sections:
        for row in section.get("items", []):
            if not isinstance(row, Mapping):
                continue
            artifact_refs = row.get("artifact_refs", {})
            evidence_refs = row.get("evidence_refs", {})
            if isinstance(artifact_refs, Mapping):
                artifacts.update(artifact_refs.get("ids", []))
            if isinstance(evidence_refs, Mapping):
                evidence.update(evidence_refs.get("ids", []))
    return artifacts, evidence


def build_handoff(
    state: Mapping[str, Any],
    *,
    section_limit: int = DEFAULT_SECTION_LIMIT,
    ref_limit: int = DEFAULT_REF_LIMIT,
    text_limit: int = DEFAULT_TEXT_LIMIT,
) -> dict[str, Any]:
    """Build a deterministic bounded projection from one validated Scan state."""
    validate_state(state)
    section_limit = _positive_bounded(section_limit, "section_limit", _MAX_SECTION_LIMIT)
    ref_limit = _positive_bounded(ref_limit, "ref_limit", _MAX_REF_LIMIT)
    text_limit = _positive_bounded(text_limit, "text_limit", _MAX_TEXT_LIMIT)
    flags: set[str] = set()

    findings_all = sorted(
        state.get("findings", []),
        key=lambda row: (_SEVERITY_ORDER.get(str(row.get("severity")), 99), str(row.get("id"))),
    )
    controls_all = sorted(state.get("controls", []), key=lambda row: str(row.get("id")))
    unknowns_all = sorted(state.get("unknowns", []), key=lambda row: str(row.get("id")))
    checks_all = sorted(
        state.get("checks", []),
        key=lambda row: (_CHECK_STATUS_ORDER.get(str(row.get("status")), 99), str(row.get("category")), str(row.get("id"))),
    )
    actions_all = sorted(
        state.get("actions", []),
        key=lambda row: (str(row.get("completion_state")), str(row.get("priority")), str(row.get("id"))),
    )

    findings = _section(
        [_finding_row(row, ref_limit=ref_limit, text_limit=text_limit, flags=flags) for row in findings_all[:section_limit]],
        len(findings_all), flags, "findings.records",
    )
    controls = _section(
        [_control_row(row, ref_limit=ref_limit, text_limit=text_limit, flags=flags) for row in controls_all[:section_limit]],
        len(controls_all), flags, "controls.records",
    )
    unknowns = _section(
        [_unknown_row(row, ref_limit=ref_limit, text_limit=text_limit, flags=flags) for row in unknowns_all[:section_limit]],
        len(unknowns_all), flags, "unknowns.records",
    )
    checks = _section(
        [_check_row(row, ref_limit=ref_limit, text_limit=text_limit, flags=flags) for row in checks_all[:section_limit]],
        len(checks_all), flags, "checks.records",
    )
    actions = _section(
        [_action_row(row, ref_limit=ref_limit, text_limit=text_limit, flags=flags) for row in actions_all[:section_limit]],
        len(actions_all), flags, "actions.records",
    )

    artifact_ids, evidence_ids = _collect_primary_refs((findings, controls, unknowns, checks))
    summary_evidence = state.get("summary", {}).get("evidence_ids", [])
    summary_refs = _refs(summary_evidence, limit=ref_limit, flags=flags, flag="summary.evidence_refs")
    evidence_ids.update(summary_refs["ids"])

    evidence_by_id = {str(row["id"]): row for row in state.get("evidence", [])}
    for evidence_id in list(evidence_ids):
        row = evidence_by_id.get(evidence_id)
        if row is not None and isinstance(row.get("artifact_id"), str):
            artifact_ids.add(row["artifact_id"])
    artifact_by_id = {str(row["id"]): row for row in state.get("artifacts", [])}

    evidence_rows = []
    for ident in sorted(evidence_ids):
        row = evidence_by_id.get(ident)
        if row is None:
            continue
        evidence_rows.append({
            "id": ident,
            "artifact_id": row.get("artifact_id"),
            "locator": row.get("locator"),
            "kind": row.get("kind"),
            "inspection_origin": row.get("inspection_origin"),
            "class": row.get("evidence_class"),
            "claim": _text(row.get("claim"), limit=text_limit, flags=flags, flag=f"{ident}.claim"),
            "method": _text(row.get("method"), limit=text_limit, flags=flags, flag=f"{ident}.method"),
            "limitations": _text(row.get("limitations"), limit=text_limit, flags=flags, flag=f"{ident}.limitations"),
            "time": row.get("time"),
            "producer": row.get("producer"),
            "source_digest": row.get("source_digest"),
            "artifact_content_digest": row.get("artifact_content_digest"),
            "freshness": row.get("freshness"),
            "check_id": row.get("check_id"),
        })

    artifact_rows = []
    for ident in sorted(artifact_ids):
        row = artifact_by_id.get(ident)
        if row is None:
            continue
        artifact_rows.append({
            "id": ident,
            "locator": row.get("locator"),
            "type": row.get("type"),
            "status": row.get("status"),
            "content_identity": row.get("content_identity"),
            "inspection_origin": row.get("inspection_origin"),
            "redaction_state": row.get("redaction_state"),
            "reason": _text(row.get("reason"), limit=text_limit, flags=flags, flag=f"{ident}.reason"),
        })

    summary = state.get("summary", {})
    coverage = state.get("coverage", {})
    continuation = state.get("continuation", {})
    project = state.get("project", {})
    primary_limit = min(section_limit, 100)
    handoff: dict[str, Any] = {
        "inspection_handoff_version": HANDOFF_VERSION,
        "identity": {
            "schema_version": state.get("schema_version"),
            "state_digest": state_digest(state),
            "snapshot_digest": state.get("provenance", {}).get("snapshot_digest"),
            "scan_id": state.get("run", {}).get("scan_id"),
            "scan_version": state.get("run", {}).get("scan_version"),
            "scan_mode": state.get("run", {}).get("scan_mode"),
            "completed_at": state.get("run", {}).get("completed_at"),
        },
        "project": {
            "name": _text(project.get("name"), limit=text_limit, flags=flags, flag="project.name"),
            "purpose": _text(project.get("purpose"), limit=text_limit, flags=flags, flag="project.purpose"),
            "scope": _text(project.get("scope"), limit=text_limit, flags=flags, flag="project.scope"),
            "exclusions": _bounded_list(
                project.get("exclusions"), limit=primary_limit, text_limit=text_limit, flags=flags, flag="project.exclusions"
            ),
        },
        "coverage": {
            "discovery_complete": coverage.get("discovery_complete"),
            "analysis_complete": coverage.get("analysis_complete"),
            "checks_complete": coverage.get("checks_complete"),
            "discovered_artifact_count": coverage.get("discovered_artifact_count"),
            "counts_by_status": coverage.get("counts_by_status", {}),
            "counts_by_check_status": coverage.get("counts_by_check_status", {}),
            "unreadable_artifact_count": coverage.get("unreadable_artifact_count"),
            "redacted_artifact_count": coverage.get("redacted_artifact_count"),
            "limits": _bounded_list(
                coverage.get("limits"), limit=primary_limit, text_limit=text_limit, flags=flags, flag="coverage.limits"
            ),
            "resource_limits_hit": _bounded_list(
                coverage.get("resource_limits_hit"), limit=primary_limit, text_limit=text_limit,
                flags=flags, flag="coverage.resource_limits_hit"
            ),
        },
        "summary": {
            "overview": _text(summary.get("overview"), limit=text_limit, flags=flags, flag="summary.overview"),
            "operation": _text(summary.get("operation"), limit=text_limit, flags=flags, flag="summary.operation"),
            "condition": _text(summary.get("condition"), limit=text_limit, flags=flags, flag="summary.condition"),
            "readiness": _text(summary.get("readiness"), limit=text_limit, flags=flags, flag="summary.readiness"),
            "limitations": _text(summary.get("limitations"), limit=text_limit, flags=flags, flag="summary.limitations"),
            "strengths": _bounded_list(
                summary.get("strengths"), limit=primary_limit, text_limit=text_limit, flags=flags, flag="summary.strengths"
            ),
            "priorities": _bounded_list(
                summary.get("priorities"), limit=primary_limit, text_limit=text_limit, flags=flags, flag="summary.priorities"
            ),
            "evidence_refs": summary_refs,
        },
        "findings": findings,
        "controls": controls,
        "unknowns": unknowns,
        "checks": checks,
        "actions": actions,
        "referenced_artifacts": artifact_rows,
        "referenced_evidence": evidence_rows,
        "continuation": {
            key: _bounded_list(
                continuation.get(key), limit=primary_limit, text_limit=text_limit, flags=flags, flag=f"continuation.{key}"
            )
            for key in ("completed", "remaining", "hypotheses", "decisions", "revalidation", "source_needs")
        } | {
            "authorization_note": _text(
                continuation.get("authorization_note"), limit=text_limit, flags=flags, flag="continuation.authorization_note"
            )
        },
        "projection": {
            "section_limit": section_limit,
            "ref_limit": ref_limit,
            "text_limit": text_limit,
            "truncated": False,
            "truncation_reasons": [],
            "projection_complete": True,
            "source_of_truth": "full Scan state identified by identity.state_digest",
            "contains_source_bytes": False,
            "contains_raw_evidence_results": False,
        },
    }
    handoff["projection"]["truncated"] = bool(flags)
    handoff["projection"]["projection_complete"] = not bool(flags)
    handoff["projection"]["truncation_reasons"] = sorted(flags)
    digest_payload = json.dumps(handoff, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(digest_payload) > MAX_HANDOFF_BYTES:
        raise ValueError(
            f"handoff projection exceeds {MAX_HANDOFF_BYTES} bytes; lower section_limit, ref_limit, or text_limit"
        )
    handoff["handoff_digest"] = "sha256:" + hashlib.sha256(digest_payload).hexdigest()
    return handoff


def canonical_handoff_json(handoff: Mapping[str, Any]) -> str:
    return json.dumps(handoff, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def format_handoff_summary(handoff: Mapping[str, Any]) -> str:
    coverage = handoff["coverage"]
    projection = handoff["projection"]
    return "\n".join([
        f"Scan handoff {handoff['handoff_digest']}",
        f"State: {handoff['identity']['state_digest']}",
        f"Snapshot: {handoff['identity']['snapshot_digest']}",
        f"Readiness: {handoff['summary']['readiness']}",
        f"Coverage: discovery_complete={coverage['discovery_complete']} analysis_complete={coverage['analysis_complete']} checks_complete={coverage['checks_complete']}",
        f"Findings: {handoff['findings']['included']} / {handoff['findings']['total']}",
        f"Unknowns: {handoff['unknowns']['included']} / {handoff['unknowns']['total']}",
        f"Checks: {handoff['checks']['included']} / {handoff['checks']['total']}",
        f"Projection complete: {'yes' if projection['projection_complete'] else 'no'}",
    ])
