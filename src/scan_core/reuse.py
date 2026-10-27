"""Strict evidence freshness and safe-reuse decisions for Scan v0.3."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

from .privacy import RedactionPolicy, redact_value

_REUSABLE_CLASSES = {"static_semantic", "static_architecture", "static_content"}
_RUNTIME_CLASSES = {"runtime", "live_service", "deployment", "time_sensitive_dependency"}
_TEXT_FIELDS = ("claim", "result", "method", "limitations", "verification_depth", "status")


@dataclass(frozen=True)
class ReusePolicy:
    """Current-run compatibility requirements for prior higher-level evidence."""

    enabled: bool = True
    available_producers: tuple[tuple[str, str, str], ...] = ()
    check_definitions: tuple[tuple[str, str], ...] = ()
    redaction_level: str = "standard"
    sensitive_path_patterns: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReuseDecision:
    reusable: bool
    reason: str


def check_definition_digest(check: Mapping[str, Any]) -> str:
    """Digest the stable identity/definition fields of a current check."""
    payload = {
        "id": check.get("id"),
        "category": check.get("category"),
        "title": check.get("title"),
        "scope": check.get("scope"),
        "method": check.get("method"),
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def evaluate_reuse(
    previous_evidence: Mapping[str, Any],
    current_artifact: Mapping[str, Any],
    policy: ReusePolicy,
) -> ReuseDecision:
    """Return a deterministic reuse decision without mutating either input."""
    if not policy.enabled:
        return ReuseDecision(False, "reuse_disabled")
    if previous_evidence.get("artifact_id") != current_artifact.get("id"):
        return ReuseDecision(False, "artifact_identity_mismatch")

    source_digest = previous_evidence.get("source_digest")
    if not isinstance(source_digest, str) or not source_digest.startswith("sha256:"):
        return ReuseDecision(False, "missing_source_digest")
    current_digest = current_artifact.get("content_identity")
    if not isinstance(current_digest, str) or not current_digest.startswith("sha256:"):
        return ReuseDecision(False, "current_content_identity_incomplete")
    if source_digest != current_digest:
        return ReuseDecision(False, "changed_content")

    producer = previous_evidence.get("producer")
    if not isinstance(producer, Mapping):
        return ReuseDecision(False, "missing_producer")
    producer_key = (producer.get("kind"), producer.get("name"), producer.get("version"))
    same_identity = [row for row in policy.available_producers if row[:2] == producer_key[:2]]
    if not same_identity:
        return ReuseDecision(False, "producer_unavailable")
    if producer_key not in policy.available_producers:
        return ReuseDecision(False, "producer_version_mismatch")

    check_id = previous_evidence.get("check_id")
    if not isinstance(check_id, str) or not check_id:
        return ReuseDecision(False, "missing_check_identity")
    check_map = dict(policy.check_definitions)
    if check_id not in check_map:
        return ReuseDecision(False, "check_identity_mismatch")
    definition_digest = previous_evidence.get("check_definition_digest")
    if not isinstance(definition_digest, str) or not definition_digest.startswith("sha256:"):
        return ReuseDecision(False, "missing_check_definition_digest")
    if definition_digest != check_map[check_id]:
        return ReuseDecision(False, "check_definition_mismatch")

    evidence_class = previous_evidence.get("evidence_class")
    if not isinstance(evidence_class, str) or not evidence_class:
        return ReuseDecision(False, "missing_evidence_class")
    if previous_evidence.get("kind") == "observed" or evidence_class in _RUNTIME_CLASSES:
        return ReuseDecision(False, "runtime_evidence")
    if evidence_class not in _REUSABLE_CLASSES:
        return ReuseDecision(False, "unsupported_evidence_class")
    if previous_evidence.get("kind") == "unverified" or previous_evidence.get("inspection_origin") == "unverified_carryover":
        return ReuseDecision(False, "unverified_evidence")
    if previous_evidence.get("status") in {"blocked", "unsupported"}:
        return ReuseDecision(False, "blocked_or_unsupported")

    # A newly sensitive/omitted path is not reused at all. This is deliberately
    # stricter than attempting to reconstruct old path-bearing prose safely.
    if current_artifact.get("redaction_state") in {"path_redacted", "fully_omitted"}:
        return ReuseDecision(False, "current_privacy_policy")
    return ReuseDecision(True, "identical_content_identity")


def reused_evidence_record(
    previous_evidence: Mapping[str, Any],
    current_artifact: Mapping[str, Any],
    *,
    source_state_digest: str,
    source_scan_id: str,
    reused_at: str,
    policy: ReusePolicy,
) -> dict[str, Any]:
    """Create a privacy-safe reused evidence row after a successful decision."""
    decision = evaluate_reuse(previous_evidence, current_artifact, policy)
    if not decision.reusable:
        raise ValueError("Evidence is not reusable: " + decision.reason)

    allowed_fields = (
        "id", "artifact_id", "locator", "kind", "claim", "result", "method", "time",
        "limitations", "inspection_origin", "producer", "source_digest", "evidence_class",
        "check_id", "check_definition_digest", "verification_depth", "status",
    )
    row = {key: previous_evidence[key] for key in allowed_fields if key in previous_evidence}
    if isinstance(row.get("producer"), Mapping):
        row["producer"] = dict(row["producer"])
    prior_freshness = previous_evidence.get("freshness")
    original_observed_at = previous_evidence.get("time")
    if isinstance(prior_freshness, Mapping) and isinstance(prior_freshness.get("original_observed_at"), str):
        original_observed_at = prior_freshness["original_observed_at"]

    redaction_policy = RedactionPolicy(
        level=policy.redaction_level,  # type: ignore[arg-type]
        sensitive_path_patterns=policy.sensitive_path_patterns,
    )
    old_locator = previous_evidence.get("locator")
    current_locator = current_artifact.get("locator")
    if isinstance(current_locator, str):
        row["locator"] = current_locator
    for key in _TEXT_FIELDS:
        value = row.get(key)
        if not isinstance(value, str):
            continue
        if isinstance(old_locator, str) and isinstance(current_locator, str) and old_locator != current_locator:
            value = value.replace(old_locator, current_locator)
        row[key] = redact_value(value, redaction_policy).value

    row["inspection_origin"] = "verified_reuse"
    row["reuse"] = {
        "prior_scan_id": source_scan_id,
        "prior_inspected_at": str(previous_evidence.get("time")),
        "prior_method": str(row.get("method")),
        "prior_depth": str(previous_evidence.get("kind")),
        "prior_limits": [str(row.get("limitations"))],
        "identity_check": "source_digest_exact_match",
        "identity_match": True,
    }
    row["freshness"] = {
        "status": "verified_reuse",
        "source_state_digest": source_state_digest,
        "source_evidence_id": previous_evidence.get("id"),
        "original_observed_at": original_observed_at,
        "reused_at": reused_at,
        "reuse_reason": decision.reason,
    }
    return row
