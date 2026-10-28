"""Provider-neutral semantic-work receipts for Scan efficiency measurement.

Receipts are host-reported telemetry bound to one canonical Scan run. They do
not prove semantic correctness, coverage, or safe reuse by themselves.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from .efficiency_benchmark import normalize_host_usage

SEMANTIC_WORK_SCHEMA_VERSION = "scan-semantic-work-receipt-1"
MAX_RECEIPT_BYTES = 2_000_000
MAX_ARTIFACT_ROWS = 50_000
_ACTIONS = {"fresh_read", "verified_reuse"}


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value.strip()


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


def validate_semantic_work_receipt(
    state: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate and normalize one semantic-work receipt against canonical state."""
    allowed_top = {"schema_version", "scan_id", "snapshot_digest", "producer", "artifacts", "usage"}
    unknown_top = set(receipt) - allowed_top
    if unknown_top:
        raise ValueError("receipt contains unsupported fields: " + ", ".join(sorted(unknown_top)))

    if receipt.get("schema_version") != SEMANTIC_WORK_SCHEMA_VERSION:
        raise ValueError(f"receipt.schema_version must be {SEMANTIC_WORK_SCHEMA_VERSION}")

    run = _mapping(state.get("run"), "state.run")
    provenance = _mapping(state.get("provenance"), "state.provenance")
    state_scan_id = _string(run.get("scan_id"), "state.run.scan_id")
    state_snapshot = _string(provenance.get("snapshot_digest"), "state.provenance.snapshot_digest")
    scan_id = _string(receipt.get("scan_id"), "receipt.scan_id")
    snapshot_digest = _string(receipt.get("snapshot_digest"), "receipt.snapshot_digest")
    if scan_id != state_scan_id:
        raise ValueError("receipt.scan_id does not match the canonical Scan state")
    if snapshot_digest != state_snapshot:
        raise ValueError("receipt.snapshot_digest does not match the canonical Scan state")

    producer = _mapping(receipt.get("producer"), "receipt.producer")
    allowed_producer = {"name", "model", "version"}
    unknown_producer = set(producer) - allowed_producer
    if unknown_producer:
        raise ValueError("receipt.producer contains unsupported fields: " + ", ".join(sorted(unknown_producer)))
    normalized_producer = {"name": _string(producer.get("name"), "receipt.producer.name")}
    for key in ("model", "version"):
        if key in producer:
            normalized_producer[key] = _string(producer.get(key), f"receipt.producer.{key}")

    artifact_rows = state.get("artifacts")
    if not isinstance(artifact_rows, list):
        raise ValueError("state.artifacts must be an array")
    artifacts_by_id = {
        row.get("id"): row
        for row in artifact_rows
        if isinstance(row, Mapping) and isinstance(row.get("id"), str)
    }
    evidence_rows = state.get("evidence")
    if not isinstance(evidence_rows, list):
        raise ValueError("state.evidence must be an array")
    evidence_by_id = {
        row.get("id"): row
        for row in evidence_rows
        if isinstance(row, Mapping) and isinstance(row.get("id"), str)
    }

    work_rows = receipt.get("artifacts")
    if not isinstance(work_rows, list):
        raise ValueError("receipt.artifacts must be an array")
    if len(work_rows) > MAX_ARTIFACT_ROWS:
        raise ValueError(f"receipt.artifacts exceeds {MAX_ARTIFACT_ROWS} rows")

    seen_artifacts: set[str] = set()
    normalized_rows: list[dict[str, Any]] = []
    for index, raw_row in enumerate(work_rows):
        row = _mapping(raw_row, f"receipt.artifacts[{index}]")
        allowed_row = {"artifact_id", "action", "access_count", "evidence_ids"}
        unknown_row = set(row) - allowed_row
        if unknown_row:
            raise ValueError(
                f"receipt.artifacts[{index}] contains unsupported fields: " + ", ".join(sorted(unknown_row))
            )
        artifact_id = _string(row.get("artifact_id"), f"receipt.artifacts[{index}].artifact_id")
        if artifact_id in seen_artifacts:
            raise ValueError(f"receipt.artifacts has duplicate artifact_id: {artifact_id}")
        seen_artifacts.add(artifact_id)
        if artifact_id not in artifacts_by_id:
            raise ValueError(f"receipt.artifacts references unknown artifact_id: {artifact_id}")

        action = _string(row.get("action"), f"receipt.artifacts[{index}].action")
        if action not in _ACTIONS:
            raise ValueError(f"receipt.artifacts[{index}].action must be fresh_read or verified_reuse")
        access_count = _positive_int(row.get("access_count", 1), f"receipt.artifacts[{index}].access_count")

        raw_evidence_ids = row.get("evidence_ids", [])
        if not isinstance(raw_evidence_ids, list) or not all(isinstance(value, str) and value.strip() for value in raw_evidence_ids):
            raise ValueError(f"receipt.artifacts[{index}].evidence_ids must be a string array")
        evidence_ids = [value.strip() for value in raw_evidence_ids]
        if len(set(evidence_ids)) != len(evidence_ids):
            raise ValueError(f"receipt.artifacts[{index}].evidence_ids contains duplicates")

        normalized_row: dict[str, Any] = {
            "artifact_id": artifact_id,
            "action": action,
            "access_count": access_count,
        }
        if action == "verified_reuse":
            if not evidence_ids:
                raise ValueError(f"receipt.artifacts[{index}] verified_reuse requires evidence_ids")
            for evidence_id in evidence_ids:
                evidence = evidence_by_id.get(evidence_id)
                if evidence is None:
                    raise ValueError(f"receipt.artifacts[{index}] references unknown evidence_id: {evidence_id}")
                if evidence.get("artifact_id") != artifact_id:
                    raise ValueError(f"receipt.artifacts[{index}] reuse evidence belongs to another artifact")
                if evidence.get("inspection_origin") != "verified_reuse":
                    raise ValueError(f"receipt.artifacts[{index}] reuse evidence is not canonical verified_reuse")
            normalized_row["evidence_ids"] = evidence_ids
        elif evidence_ids:
            raise ValueError(f"receipt.artifacts[{index}] fresh_read must not claim reuse evidence_ids")
        normalized_rows.append(normalized_row)

    normalized: dict[str, Any] = {
        "schema_version": SEMANTIC_WORK_SCHEMA_VERSION,
        "scan_id": scan_id,
        "snapshot_digest": snapshot_digest,
        "producer": normalized_producer,
        "artifacts": normalized_rows,
    }
    if "usage" in receipt:
        usage = _mapping(receipt.get("usage"), "receipt.usage")
        normalize_host_usage(usage)
        normalized["usage"] = dict(usage)
    return normalized


def load_semantic_work_receipt(path: str | Path, state: Mapping[str, Any]) -> dict[str, Any]:
    """Load a bounded JSON receipt and validate it against one Scan state."""
    candidate = Path(path)
    raw = candidate.read_bytes()
    if len(raw) > MAX_RECEIPT_BYTES:
        raise ValueError(f"semantic-work receipt exceeds {MAX_RECEIPT_BYTES} bytes")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid semantic-work receipt: {error}") from error
    if not isinstance(payload, Mapping):
        raise ValueError("semantic-work receipt must be a JSON object")
    return validate_semantic_work_receipt(state, payload)
