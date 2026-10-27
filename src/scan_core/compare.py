"""Pure deterministic comparison primitives for Scan 1.3/1.4 states."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Mapping

from .errors import ValidationError
from .state import state_digest
from .validate import validate_state

_TEMPORAL_KEYS = {
    "time",
    "timestamp",
    "started_at",
    "completed_at",
    "created_at",
    "updated_at",
    "observed_at",
    "inspected_at",
    "original_observed_at",
    "reused_at",
}
_ID_ARRAY_KEYS = {"artifact_ids", "evidence_ids", "related_ids"}


@dataclass(frozen=True)
class Comparison:
    """Deterministic logical comparison of two compatible Scan states."""

    previous_schema_version: str
    current_schema_version: str
    previous_state_digest: str
    current_state_digest: str
    previous_snapshot_digest: str
    current_snapshot_digest: str
    comparison_time: str
    snapshot_relation: str
    artifacts: Mapping[str, tuple[str, ...]]
    findings: Mapping[str, tuple[str, ...]]
    unknowns: Mapping[str, tuple[str, ...]]

    def as_dict(self) -> dict[str, Any]:
        return {
            "previous": {
                "schema_version": self.previous_schema_version,
                "state_digest": self.previous_state_digest,
                "snapshot_digest": self.previous_snapshot_digest,
            },
            "current": {
                "schema_version": self.current_schema_version,
                "state_digest": self.current_state_digest,
                "snapshot_digest": self.current_snapshot_digest,
            },
            "comparison_time": self.comparison_time,
            "snapshot_relation": self.snapshot_relation,
            "artifacts": {key: list(value) for key, value in self.artifacts.items()},
            "findings": {key: list(value) for key, value in self.findings.items()},
            "unknowns": {key: list(value) for key, value in self.unknowns.items()},
        }


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _normalize_record(value: Any, *, key: str | None = None) -> Any:
    """Remove temporal noise and normalize ID-array ordering for comparison."""
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for child_key in sorted(value):
            if child_key in _TEMPORAL_KEYS or child_key.endswith("_timestamp"):
                continue
            normalized[child_key] = _normalize_record(value[child_key], key=child_key)
        return normalized
    if isinstance(value, list):
        items = [_normalize_record(item) for item in value]
        if key in _ID_ARRAY_KEYS and all(isinstance(item, str) for item in items):
            return sorted(items)
        return items
    return value


def _artifact_fingerprint(row: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        row.get("id"),
        row.get("path_kind"),
        row.get("content_identity"),
        row.get("size_bytes"),
        row.get("status"),
        row.get("redaction_state"),
    )


def _index(rows: Any, label: str) -> dict[str, Mapping[str, Any]]:
    if not isinstance(rows, list):
        raise ValidationError(f"{label} must be an array")
    result: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping) or not isinstance(row.get("id"), str):
            raise ValidationError(f"{label} rows must contain string ids")
        ident = row["id"]
        if ident in result:
            raise ValidationError(f"Duplicate {label} ID: {ident}")
        result[ident] = row
    return result


def _compare_artifacts(previous: Mapping[str, Any], current: Mapping[str, Any]) -> dict[str, tuple[str, ...]]:
    old = _index(previous.get("artifacts"), "artifacts")
    new = _index(current.get("artifacts"), "artifacts")
    old_ids = set(old)
    new_ids = set(new)
    shared = old_ids & new_ids
    unchanged = sorted(ident for ident in shared if _artifact_fingerprint(old[ident]) == _artifact_fingerprint(new[ident]))
    changed = sorted(shared - set(unchanged))
    return {
        "added": tuple(sorted(new_ids - old_ids)),
        "changed": tuple(changed),
        "removed": tuple(sorted(old_ids - new_ids)),
        "unchanged": tuple(unchanged),
    }


def _compare_records(
    previous: Mapping[str, Any],
    current: Mapping[str, Any],
    collection: str,
) -> dict[str, tuple[str, ...]]:
    old = _index(previous.get(collection), collection)
    new = _index(current.get(collection), collection)
    old_ids = set(old)
    new_ids = set(new)
    shared = old_ids & new_ids
    modified = sorted(
        ident
        for ident in shared
        if _canonical(_normalize_record(old[ident])) != _canonical(_normalize_record(new[ident]))
    )
    return {
        "new": tuple(sorted(new_ids - old_ids)),
        "resolved": tuple(sorted(old_ids - new_ids)),
        "persisting": tuple(sorted(shared)),
        "modified": tuple(modified),
    }


def compare_states(previous: Mapping[str, Any], current: Mapping[str, Any]) -> Comparison:
    """Compare two validated Scan 1.3/1.4 states without I/O or wall-clock input."""
    old = dict(previous)
    new = dict(current)
    for label, state in (("previous", old), ("current", new)):
        version = state.get("schema_version")
        if version not in {"1.3", "1.4"}:
            raise ValidationError(f"{label} comparison state must use schema_version 1.3 or 1.4")
        validate_state(state)

    old_snapshot = old["provenance"]["snapshot_digest"]
    new_snapshot = new["provenance"]["snapshot_digest"]
    snapshot_relation = "same" if old_snapshot == new_snapshot else "changed"
    comparison_time = new["run"]["completed_at"]

    return Comparison(
        previous_schema_version=old["schema_version"],
        current_schema_version=new["schema_version"],
        previous_state_digest=state_digest(old),
        current_state_digest=state_digest(new),
        previous_snapshot_digest=old_snapshot,
        current_snapshot_digest=new_snapshot,
        comparison_time=comparison_time,
        snapshot_relation=snapshot_relation,
        artifacts=_compare_artifacts(old, new),
        findings=_compare_records(old, new, "findings"),
        unknowns=_compare_records(old, new, "unknowns"),
    )
