"""Import bounded externally observed runtime/test evidence into Scan 1.4 state.

Scan does not execute the target, test runner, browser, producer, or adapter while
importing this receipt. Authorization fields are external attestations preserved
as provenance; their human/workflow identity is not independently verified.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from .builder import SemanticStateBuilder
from .privacy import RedactionPolicy, redact_value
from .state import state_digest
from .validate import validate_state

OBSERVED_RECEIPT_VERSION = "1"
OBSERVED_MAX_BYTES = 64_000_000
OBSERVED_MAX_RESULTS = 10_000
OBSERVED_MAX_TEXT = 20_000
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_OUTCOMES = {"pass", "fail", "unknown"}
_SEVERITIES = {"critical", "high", "medium", "low", "informational"}


@dataclass(frozen=True)
class ObservedImportResult:
    state: dict[str, Any]
    imported_findings: int
    imported_controls: int
    imported_unknowns: int
    imported_evidence: int
    unmapped_observations: int
    ignored_observations: int
    receipt_digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "imported_findings": self.imported_findings,
            "imported_controls": self.imported_controls,
            "imported_unknowns": self.imported_unknowns,
            "imported_evidence": self.imported_evidence,
            "unmapped_observations": self.unmapped_observations,
            "ignored_observations": self.ignored_observations,
            "receipt_digest": self.receipt_digest,
        }


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _text(value: Any, label: str, *, maximum: int = OBSERVED_MAX_TEXT) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be nonempty text")
    normalized = " ".join(value.split())
    if len(normalized) > maximum:
        raise ValueError(f"{label} exceeds {maximum} characters")
    return normalized


def _sha(value: Any, label: str) -> str:
    text = _text(value, label, maximum=71)
    if _SHA256_RE.fullmatch(text) is None:
        raise ValueError(f"{label} must be sha256:<64 lowercase hex>")
    return text


def _object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    return value


def _redact(value: str, privacy: str) -> str:
    return redact_value(value, RedactionPolicy(level=privacy)).value


def _relative_locator(value: Any, label: str) -> str:
    text = _text(value, label, maximum=4096)
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or not path.parts
        or "\\" in text
        or ":" in text
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(f"{label} must be a canonical repository-relative path")
    return path.as_posix()


def _evidence_locator(value: Any, artifact_locator: str, label: str) -> str:
    if value in (None, ""):
        return artifact_locator
    text = _text(value, label, maximum=4096)
    if text == artifact_locator or any(text.startswith(artifact_locator + sep) for sep in (":", "#", "@")):
        return text
    raise ValueError(f"{label} must equal or be anchored to artifact_locator")


def _executor(value: Any) -> dict[str, str]:
    row = _object(value, "executor")
    if row.get("kind") != "external-tool":
        raise ValueError("executor.kind must be external-tool")
    return {
        "kind": "external-tool",
        "name": _text(row.get("name"), "executor.name", maximum=256),
        "version": _text(row.get("version"), "executor.version", maximum=256),
    }


def _authorization(value: Any) -> dict[str, str]:
    row = _object(value, "authorization")
    return {
        "basis": _text(row.get("basis"), "authorization.basis", maximum=256),
        "scope": _text(row.get("scope"), "authorization.scope"),
        "reference": _text(row.get("reference"), "authorization.reference", maximum=1024),
    }


def _execution(value: Any) -> dict[str, Any]:
    row = _object(value, "execution")
    target_executed = row.get("target_executed")
    network_used = row.get("network_used")
    if not isinstance(target_executed, bool) or not isinstance(network_used, bool):
        raise ValueError("execution.target_executed and execution.network_used must be booleans")
    return {
        "execution_id": _text(row.get("execution_id"), "execution.execution_id", maximum=512),
        "started_at": _text(row.get("started_at"), "execution.started_at", maximum=128),
        "completed_at": _text(row.get("completed_at"), "execution.completed_at", maximum=128),
        "environment": _text(row.get("environment"), "execution.environment", maximum=1024),
        "target_executed": target_executed,
        "network_used": network_used,
    }


def _coverage(value: Any) -> dict[str, Any]:
    row = _object(value, "coverage")
    if row.get("whole_project_complete") is not False:
        raise ValueError("coverage.whole_project_complete must be false")
    return {
        "scope": _text(row.get("scope"), "coverage.scope"),
        "limitations": _text(row.get("limitations"), "coverage.limitations"),
        "whole_project_complete": False,
    }


def _identity(executor: Mapping[str, str], external_id: str, artifact_locator: str) -> str:
    payload = {"executor": dict(executor), "external_id": external_id, "artifact_locator": artifact_locator}
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()[:24]


def _unmapped_unknown(
    builder: SemanticStateBuilder,
    *,
    ident: str,
    executor: Mapping[str, str],
    external_id: str,
    artifact_locator: str,
    privacy: str,
) -> str:
    return builder.add_unknown(
        record_id=f"unknown:observed:{ident}",
        question=f"How should observed result {external_id} from {executor['name']} be resolved?",
        reason=_redact(
            f"Observed result {external_id} referenced {artifact_locator}, which did not map to a canonical file artifact in the current Scan state.",
            privacy,
        ),
        impact="The external observation is retained as unresolved context but cannot safely establish a finding or control without exact artifact binding.",
        next_safe_step="Map the observation to the current canonical artifact and regenerate the receipt against the same snapshot.",
    )


def import_observed_receipt(
    base_state: Mapping[str, Any],
    receipt: Mapping[str, Any],
    *,
    source_bytes: bytes | None = None,
) -> ObservedImportResult:
    """Import one data-only external observed-evidence receipt."""
    validate_state(base_state)
    if base_state.get("schema_version") != "1.4":
        raise ValueError("observed evidence receipt v1 requires Scan state schema 1.4")
    if receipt.get("scan_observed_receipt_version") != OBSERVED_RECEIPT_VERSION:
        raise ValueError(f"scan_observed_receipt_version must be {OBSERVED_RECEIPT_VERSION}")

    target = _object(receipt.get("target"), "target")
    snapshot_digest = _sha(target.get("snapshot_digest"), "target.snapshot_digest")
    if snapshot_digest != base_state.get("provenance", {}).get("snapshot_digest"):
        raise ValueError("target.snapshot_digest does not match the current Scan snapshot")
    actual_state_digest = state_digest(base_state)
    declared_state_digest = target.get("state_digest")
    if declared_state_digest is not None:
        declared_state_digest = _sha(declared_state_digest, "target.state_digest")
        if declared_state_digest != actual_state_digest:
            raise ValueError("target.state_digest does not match the exact base Scan state")

    executor = _executor(receipt.get("executor"))
    authorization = _authorization(receipt.get("authorization"))
    execution = _execution(receipt.get("execution"))
    coverage = _coverage(receipt.get("coverage"))
    observations = receipt.get("observations")
    if not isinstance(observations, list):
        raise ValueError("observations must be an array")
    if len(observations) > OBSERVED_MAX_RESULTS:
        raise ValueError(f"observation count exceeds importer limit ({OBSERVED_MAX_RESULTS})")
    if not all(isinstance(row, Mapping) for row in observations):
        raise ValueError("observations must contain objects only")

    raw = source_bytes if source_bytes is not None else _canonical_bytes(receipt)
    receipt_digest = _digest(raw)
    privacy = str(base_state.get("privacy", {}).get("redaction_level", "standard"))
    builder = SemanticStateBuilder.from_state(base_state)
    artifacts_by_locator = {
        str(row.get("locator")): row
        for row in base_state.get("artifacts", [])
        if row.get("path_kind") == "file" and row.get("type") == "file"
    }

    imported_findings = imported_controls = imported_unknowns = imported_evidence = 0
    unmapped = ignored = 0
    seen: dict[str, str] = {}
    evidence_by_artifact: dict[str, list[str]] = {}

    for index, raw_observation in enumerate(observations):
        observation = dict(raw_observation)
        external_id = _text(observation.get("external_id"), f"observations[{index}].external_id", maximum=512)
        observation_digest = _digest(_canonical_bytes(observation))
        if external_id in seen:
            if seen[external_id] != observation_digest:
                raise ValueError(f"observations[{index}].external_id conflicts with an earlier observation: {external_id}")
            ignored += 1
            continue
        seen[external_id] = observation_digest
        outcome = _text(observation.get("outcome"), f"observations[{index}].outcome", maximum=32)
        if outcome not in _OUTCOMES:
            raise ValueError(f"observations[{index}].outcome must be pass, fail, or unknown")
        artifact_locator = _relative_locator(
            observation.get("artifact_locator"), f"observations[{index}].artifact_locator"
        )
        artifact_identity = _text(
            observation.get("artifact_content_identity"),
            f"observations[{index}].artifact_content_identity",
            maximum=512,
        )
        ident = _identity(executor, external_id, artifact_locator)
        artifact = artifacts_by_locator.get(artifact_locator)
        if artifact is None:
            _unmapped_unknown(
                builder,
                ident=ident,
                executor=executor,
                external_id=external_id,
                artifact_locator=artifact_locator,
                privacy=privacy,
            )
            imported_unknowns += 1
            unmapped += 1
            continue
        if artifact_identity != artifact.get("content_identity"):
            raise ValueError(
                f"observations[{index}].artifact_content_identity does not match current artifact {artifact_locator}"
            )

        evidence_locator = _evidence_locator(
            observation.get("locator"), artifact_locator, f"observations[{index}].locator"
        )
        evidence_id = builder.add_evidence(
            record_id=f"evidence:observed:{ident}",
            artifact_id=str(artifact["id"]),
            locator=evidence_locator,
            kind="observed",
            evidence_class="runtime_observation",
            claim=_redact(_text(observation.get("claim"), f"observations[{index}].claim"), privacy),
            result=_redact(_text(observation.get("result"), f"observations[{index}].result"), privacy),
            method=_redact(_text(observation.get("method"), f"observations[{index}].method"), privacy),
            limitations=_redact(
                _text(observation.get("limitations"), f"observations[{index}].limitations"), privacy
            ),
            source_digest=receipt_digest,
            producer_kind="external-tool",
            producer_name=executor["name"],
            producer_version=executor["version"],
            time=_text(
                observation.get("observed_at", execution["completed_at"]),
                f"observations[{index}].observed_at",
                maximum=128,
            ),
        )
        imported_evidence += 1
        evidence_by_artifact.setdefault(str(artifact["id"]), []).append(evidence_id)

        if outcome == "fail":
            finding = _object(observation.get("finding"), f"observations[{index}].finding")
            severity = _text(finding.get("severity"), f"observations[{index}].finding.severity", maximum=64)
            if severity not in _SEVERITIES:
                raise ValueError(f"observations[{index}].finding.severity is invalid")
            builder.add_finding(
                record_id=f"finding:observed:{ident}",
                title=_redact(_text(finding.get("title"), f"observations[{index}].finding.title"), privacy),
                impact=_redact(_text(finding.get("impact"), f"observations[{index}].finding.impact"), privacy),
                severity=severity,
                confidence=_text(finding.get("confidence"), f"observations[{index}].finding.confidence", maximum=128),
                verification_state="observed",
                artifact_ids=[str(artifact["id"])],
                evidence_ids=[evidence_id],
                uncertainty=_redact(
                    _text(finding.get("uncertainty"), f"observations[{index}].finding.uncertainty"), privacy
                ),
                recommendation=_redact(
                    _text(finding.get("recommendation"), f"observations[{index}].finding.recommendation"), privacy
                ),
                safe_verification=_redact(
                    _text(finding.get("safe_verification"), f"observations[{index}].finding.safe_verification"), privacy
                ),
            )
            imported_findings += 1
        elif outcome == "pass":
            control = _object(observation.get("control"), f"observations[{index}].control")
            limitations = _redact(
                _text(control.get("limitations"), f"observations[{index}].control.limitations"), privacy
            )
            builder.add_control(
                record_id=f"control:observed:{ident}",
                description=_redact(
                    _text(control.get("description"), f"observations[{index}].control.description"), privacy
                ),
                artifact_ids=[str(artifact["id"])],
                evidence_ids=[evidence_id],
                effectiveness_status="observed_pass",
                limitations=limitations + " Passing this observation does not establish behavior outside its declared scope.",
            )
            imported_controls += 1
        else:
            unknown = _object(observation.get("unknown"), f"observations[{index}].unknown")
            builder.add_unknown(
                record_id=f"unknown:observed:{ident}",
                artifact_ids=[str(artifact["id"])],
                evidence_ids=[evidence_id],
                question=_redact(_text(unknown.get("question"), f"observations[{index}].unknown.question"), privacy),
                reason=_redact(_text(unknown.get("reason"), f"observations[{index}].unknown.reason"), privacy),
                impact=_redact(_text(unknown.get("impact"), f"observations[{index}].unknown.impact"), privacy),
                next_safe_step=_redact(
                    _text(unknown.get("next_safe_step"), f"observations[{index}].unknown.next_safe_step"), privacy
                ),
            )
            imported_unknowns += 1

    current_status = {str(row["id"]): str(row.get("status")) for row in base_state.get("artifacts", [])}
    for artifact_id, evidence_ids in evidence_by_artifact.items():
        if current_status.get(artifact_id) not in {"analyzed", "excluded", "unreadable"}:
            builder.mark_artifact_partial(
                artifact_id,
                evidence_ids=evidence_ids,
                reason="External observed evidence imported; Scan did not perform or reproduce the execution",
            )

    state = builder.build(analysis_complete=False)
    state.setdefault("extensions", {}).setdefault("observed_evidence_imports", []).append({
        "version": OBSERVED_RECEIPT_VERSION,
        "receipt_digest": receipt_digest,
        "target_snapshot_digest": snapshot_digest,
        "target_state_digest": declared_state_digest,
        "base_state_digest_at_import": actual_state_digest,
        "executor": executor,
        "authorization_attestation": {
            "basis": _redact(authorization["basis"], privacy),
            "scope": _redact(authorization["scope"], privacy),
            "reference": _redact(authorization["reference"], privacy),
            "verified_by_scan": False,
            "verification_note": "Scan records this external authorization attestation but does not independently verify the human/workflow identity or authorization claim.",
        },
        "execution": {
            "execution_id": _redact(execution["execution_id"], privacy),
            "started_at": execution["started_at"],
            "completed_at": execution["completed_at"],
            "environment": _redact(execution["environment"], privacy),
            "target_executed_by_external_system": execution["target_executed"],
            "network_used_by_external_system": execution["network_used"],
            "target_executed_by_scan_during_import": False,
            "network_used_by_scan_during_import": False,
        },
        "coverage": {
            "scope": _redact(coverage["scope"], privacy),
            "limitations": _redact(coverage["limitations"], privacy),
            "whole_project_complete": False,
        },
        "imported_findings": imported_findings,
        "imported_controls": imported_controls,
        "imported_unknowns": imported_unknowns,
        "imported_evidence": imported_evidence,
        "unmapped_observations": unmapped,
        "ignored_observations": ignored,
    })
    validate_state(state)
    return ObservedImportResult(
        state=state,
        imported_findings=imported_findings,
        imported_controls=imported_controls,
        imported_unknowns=imported_unknowns,
        imported_evidence=imported_evidence,
        unmapped_observations=unmapped,
        ignored_observations=ignored,
        receipt_digest=receipt_digest,
    )


def load_observed_receipt_file(
    path: Path, *, max_bytes: int = OBSERVED_MAX_BYTES
) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink():
        raise ValueError("observed evidence receipt must not be a symlink")
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError(f"observed evidence receipt exceeds importer byte limit ({max_bytes})")
    raw = path.read_bytes()
    try:
        payload = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"Invalid UTF-8 observed evidence JSON: {error}") from error
    if not isinstance(payload, dict):
        raise ValueError("observed evidence receipt root must be an object")
    return payload, raw
