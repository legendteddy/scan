"""ScanBench 2.0 ground-truth adjudication foundation.

This module does not detect defects and does not replace ScanBench v1. It evaluates
an independently prepared adjudication against versioned ground truth and one exact
validated Scan state. Truth classes remain separate; no blended quality score exists.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Mapping

from .errors import CommandError
from .state import state_digest
from .validate import validate_state

GROUND_TRUTH_VERSION = "2.0-alpha1"
TRUTH_KINDS = ("must_find", "must_not_find", "must_remain_unknown", "must_not_clear")
OUTCOMES = ("found", "not_found", "unknown", "cleared")
_MAX_INPUT_BYTES = 4_000_000


@dataclass(frozen=True)
class ConditionEvaluation:
    condition_id: str
    truth: str
    family: str
    outcome: str
    passed: bool
    reference_valid: bool
    evidence_supported: bool | None
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "condition_id": self.condition_id,
            "truth": self.truth,
            "family": self.family,
            "outcome": self.outcome,
            "passed": self.passed,
            "reference_valid": self.reference_valid,
            "evidence_supported": self.evidence_supported,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class GroundTruthResult:
    project_id: str
    state_digest: str
    conditions: tuple[ConditionEvaluation, ...]
    metrics: dict[str, Any]

    @property
    def passed(self) -> bool:
        return all(row.passed for row in self.conditions)

    def as_dict(self) -> dict[str, Any]:
        return {
            "scanbench2_version": GROUND_TRUTH_VERSION,
            "project_id": self.project_id,
            "state_digest": self.state_digest,
            "conditions": [row.as_dict() for row in self.conditions],
            "metrics": self.metrics,
            "passed": self.passed,
            "note": "Metrics are reported separately; no blended overall quality score is calculated.",
        }


def _required_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CommandError(f"{label} must be a nonempty string")
    return value


def _string_array(value: Any, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise CommandError(f"{label} must be a string array")
    if len(value) != len(set(value)):
        raise CommandError(f"{label} must not contain duplicates")
    return list(value)


def _bounded_json(path: Path) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise CommandError(f"Cannot read ScanBench 2.0 input {path}: {error}") from error
    if size > _MAX_INPUT_BYTES:
        raise CommandError(f"ScanBench 2.0 input exceeds {_MAX_INPUT_BYTES} bytes: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CommandError(f"Cannot parse ScanBench 2.0 JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise CommandError(f"ScanBench 2.0 JSON root must be an object: {path}")
    return value


def validate_ground_truth(value: Mapping[str, Any]) -> dict[str, Any]:
    if value.get("scanbench2_version") != GROUND_TRUTH_VERSION:
        raise CommandError(f"ground truth scanbench2_version must be {GROUND_TRUTH_VERSION}")
    project_id = _required_string(value.get("project_id"), "ground_truth.project_id")
    conditions = value.get("conditions")
    if not isinstance(conditions, list) or not conditions:
        raise CommandError("ground_truth.conditions must be a nonempty array")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, row in enumerate(conditions):
        if not isinstance(row, Mapping):
            raise CommandError(f"ground_truth.conditions[{index}] must be an object")
        condition_id = _required_string(row.get("id"), f"ground_truth.conditions[{index}].id")
        if condition_id in seen:
            raise CommandError(f"duplicate ground-truth condition ID: {condition_id}")
        seen.add(condition_id)
        truth = row.get("truth")
        if truth not in TRUTH_KINDS:
            raise CommandError(f"{condition_id}: truth must be one of {', '.join(TRUTH_KINDS)}")
        normalized.append({
            "id": condition_id,
            "truth": truth,
            "family": _required_string(row.get("family"), f"{condition_id}.family"),
            "description": _required_string(row.get("description"), f"{condition_id}.description"),
            "rationale": _required_string(row.get("rationale"), f"{condition_id}.rationale"),
            "artifact_locators": _string_array(row.get("artifact_locators", []), f"{condition_id}.artifact_locators"),
        })
    return {"scanbench2_version": GROUND_TRUTH_VERSION, "project_id": project_id, "conditions": normalized}


def validate_submission(value: Mapping[str, Any], *, project_id: str, expected_state_digest: str,
                        condition_ids: set[str]) -> dict[str, Any]:
    if value.get("scanbench2_version") != GROUND_TRUTH_VERSION:
        raise CommandError(f"submission scanbench2_version must be {GROUND_TRUTH_VERSION}")
    if value.get("project_id") != project_id:
        raise CommandError("submission.project_id does not match ground truth")
    if value.get("state_digest") != expected_state_digest:
        raise CommandError("submission.state_digest does not match the evaluated Scan state")
    adjudications = value.get("adjudications")
    if not isinstance(adjudications, list):
        raise CommandError("submission.adjudications must be an array")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, row in enumerate(adjudications):
        if not isinstance(row, Mapping):
            raise CommandError(f"submission.adjudications[{index}] must be an object")
        condition_id = _required_string(row.get("condition_id"), f"submission.adjudications[{index}].condition_id")
        if condition_id not in condition_ids:
            raise CommandError(f"submission references unknown condition: {condition_id}")
        if condition_id in seen:
            raise CommandError(f"duplicate submission condition: {condition_id}")
        seen.add(condition_id)
        outcome = row.get("outcome")
        if outcome not in OUTCOMES:
            raise CommandError(f"{condition_id}: outcome must be one of {', '.join(OUTCOMES)}")
        normalized.append({
            "condition_id": condition_id,
            "outcome": outcome,
            "finding_ids": _string_array(row.get("finding_ids", []), f"{condition_id}.finding_ids"),
            "unknown_ids": _string_array(row.get("unknown_ids", []), f"{condition_id}.unknown_ids"),
            "evidence_ids": _string_array(row.get("evidence_ids", []), f"{condition_id}.evidence_ids"),
            "notes": str(row.get("notes", "")),
        })
    missing = condition_ids - seen
    if missing:
        raise CommandError("submission is missing condition(s): " + ", ".join(sorted(missing)))
    return {
        "scanbench2_version": GROUND_TRUTH_VERSION,
        "project_id": project_id,
        "state_digest": expected_state_digest,
        "adjudications": normalized,
    }


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def evaluate_ground_truth(ground_truth: Mapping[str, Any], state: Mapping[str, Any],
                          submission: Mapping[str, Any]) -> GroundTruthResult:
    truth = validate_ground_truth(ground_truth)
    canonical_state = dict(state)
    validate_state(canonical_state, version="1.4")
    digest = state_digest(canonical_state)
    condition_ids = {row["id"] for row in truth["conditions"]}
    judged = validate_submission(
        submission,
        project_id=truth["project_id"],
        expected_state_digest=digest,
        condition_ids=condition_ids,
    )
    by_condition = {row["condition_id"]: row for row in judged["adjudications"]}
    findings = {row["id"]: row for row in canonical_state["findings"]}
    unknowns = {row["id"]: row for row in canonical_state["unknowns"]}
    evidence = {row["id"]: row for row in canonical_state["evidence"]}

    rows: list[ConditionEvaluation] = []
    for condition in truth["conditions"]:
        adjudication = by_condition[condition["id"]]
        finding_ids = adjudication["finding_ids"]
        unknown_ids = adjudication["unknown_ids"]
        evidence_ids = adjudication["evidence_ids"]
        refs_valid = (
            all(ref in findings for ref in finding_ids)
            and all(ref in unknowns for ref in unknown_ids)
            and all(ref in evidence for ref in evidence_ids)
        )
        support_ok: bool | None = None
        if adjudication["outcome"] == "found":
            support_ok = bool(finding_ids) and refs_valid
            if support_ok:
                linked = {eid for fid in finding_ids for eid in findings[fid].get("evidence_ids", [])}
                support_ok = bool(linked) and (not evidence_ids or bool(linked.intersection(evidence_ids)))
        elif adjudication["outcome"] == "unknown":
            support_ok = bool(unknown_ids) and refs_valid

        truth_kind = condition["truth"]
        outcome = adjudication["outcome"]
        if truth_kind == "must_find":
            passed = outcome == "found" and support_ok is True
            detail = "required finding was evidence-backed" if passed else "required finding was not established with valid evidence"
        elif truth_kind == "must_not_find":
            passed = outcome == "not_found" and not finding_ids and refs_valid
            detail = "negative control was not reported as a finding" if passed else "negative control was incorrectly reported or adjudicated"
        elif truth_kind == "must_remain_unknown":
            passed = outcome == "unknown" and support_ok is True
            detail = "insufficient evidence remained an explicit unknown" if passed else "unknown-only condition was overclaimed or not represented"
        else:
            if outcome == "found":
                passed = support_ok is True
            elif outcome == "unknown":
                passed = support_ok is True
            else:
                passed = False
            detail = "condition was not falsely cleared" if passed else "condition was cleared or omitted without sufficient basis"
        rows.append(ConditionEvaluation(
            condition_id=condition["id"],
            truth=truth_kind,
            family=condition["family"],
            outcome=outcome,
            passed=passed,
            reference_valid=refs_valid,
            evidence_supported=support_ok,
            detail=detail,
        ))

    must_find = [row for row in rows if row.truth == "must_find"]
    negatives = [row for row in rows if row.truth == "must_not_find"]
    unknown_truth = [row for row in rows if row.truth == "must_remain_unknown"]
    no_clear = [row for row in rows if row.truth == "must_not_clear"]
    tp = sum(row.passed for row in must_find)
    fn = len(must_find) - tp
    tn = sum(row.passed for row in negatives)
    fp = len(negatives) - tn
    correct_unknown = sum(row.passed for row in unknown_truth)
    false_clearances = sum(not row.passed for row in no_clear)
    found_rows = [row for row in rows if row.outcome == "found"]
    supported_found = sum(row.evidence_supported is True for row in found_rows)
    metrics = {
        "detection": {"true_positive": tp, "false_negative": fn, "recall": _ratio(tp, len(must_find))},
        "negative_controls": {"true_negative": tn, "false_positive": fp, "specificity": _ratio(tn, len(negatives))},
        "unknown_honesty": {
            "correct_unknown": correct_unknown,
            "incorrect_or_overclaimed": len(unknown_truth) - correct_unknown,
            "rate": _ratio(correct_unknown, len(unknown_truth)),
        },
        "false_clearance": {"violations": false_clearances, "conditions": len(no_clear)},
        "evidence_support": {
            "supported_found_outcomes": supported_found,
            "found_outcomes": len(found_rows),
            "rate": _ratio(supported_found, len(found_rows)),
        },
        "reference_integrity": {
            "valid": sum(row.reference_valid for row in rows),
            "invalid": sum(not row.reference_valid for row in rows),
        },
    }
    return GroundTruthResult(
        project_id=truth["project_id"],
        state_digest=digest,
        conditions=tuple(rows),
        metrics=metrics,
    )


def load_ground_truth_file(path: Path) -> dict[str, Any]:
    return validate_ground_truth(_bounded_json(path))


def load_submission_file(path: Path) -> dict[str, Any]:
    return _bounded_json(path)


def format_ground_truth(result: GroundTruthResult) -> str:
    lines = [f"ScanBench 2.0 {GROUND_TRUTH_VERSION} — {result.project_id}"]
    for row in result.conditions:
        lines.append(f"{'PASS' if row.passed else 'FAIL'} [{row.truth}] {row.condition_id}: {row.detail}")
    lines.extend([
        "",
        "Metrics (separate by design)",
        f"Detection recall: {result.metrics['detection']['recall']}",
        f"Negative-control specificity: {result.metrics['negative_controls']['specificity']}",
        f"Unknown-honesty rate: {result.metrics['unknown_honesty']['rate']}",
        f"False-clearance violations: {result.metrics['false_clearance']['violations']}",
        f"Evidence-support rate: {result.metrics['evidence_support']['rate']}",
        "No blended overall quality score is calculated.",
    ])
    return "\n".join(lines)
