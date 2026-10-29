"""Vendor-neutral bounded evidence federation into Scan 1.4 state.

The federation format is data-only. Scan does not load plugins, execute target
code, run the originating producer, or make network requests while importing a
bundle. Every mapped result is bound to the current snapshot and exact artifact
content identity before it can become canonical evidence.
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

FEDERATION_BUNDLE_VERSION = "1"
FEDERATION_MAX_BYTES = 64_000_000
FEDERATION_MAX_RESULTS = 10_000
FEDERATION_MAX_TEXT = 20_000
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ALLOWED_EVIDENCE_KINDS = {"static", "observed", "inferred", "unverified"}
_ALLOWED_DISPOSITIONS = {"finding", "unknown"}
_ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "informational"}


@dataclass(frozen=True)
class FederationImportResult:
    state: dict[str, Any]
    imported_findings: int
    imported_unknowns: int
    imported_evidence: int
    unmapped_results: int
    ignored_results: int
    bundle_digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "imported_findings": self.imported_findings,
            "imported_unknowns": self.imported_unknowns,
            "imported_evidence": self.imported_evidence,
            "unmapped_results": self.unmapped_results,
            "ignored_results": self.ignored_results,
            "bundle_digest": self.bundle_digest,
        }


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _required_text(value: Any, label: str, *, max_chars: int = FEDERATION_MAX_TEXT) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be nonempty text")
    text = value.strip()
    if len(text) > max_chars:
        raise ValueError(f"{label} exceeds {max_chars} characters")
    return text


def _sha256(value: Any, label: str) -> str:
    text = _required_text(value, label, max_chars=71)
    if _SHA256_RE.fullmatch(text) is None:
        raise ValueError(f"{label} must be sha256:<64 lowercase hex>")
    return text


def _redact(value: str, level: str) -> str:
    return redact_value(value, RedactionPolicy(level=level)).value


def _relative_locator(value: Any, label: str) -> str:
    text = _required_text(value, label, max_chars=4096)
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
    text = _required_text(value, label, max_chars=4096)
    if text == artifact_locator:
        return text
    if any(text.startswith(artifact_locator + separator) for separator in (":", "#", "@")):
        return text
    raise ValueError(f"{label} must equal or be anchored to artifact_locator")


def _object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    return value


def _producer(value: Any) -> dict[str, str]:
    row = _object(value, "producer")
    kind = _required_text(row.get("kind"), "producer.kind", max_chars=128)
    if kind != "external-tool":
        raise ValueError("producer.kind must be external-tool in federation bundle v1")
    return {
        "kind": kind,
        "name": _required_text(row.get("name"), "producer.name", max_chars=256),
        "version": _required_text(row.get("version"), "producer.version", max_chars=256),
    }


def _adapter(value: Any) -> dict[str, str]:
    row = _object(value, "adapter")
    return {
        "name": _required_text(row.get("name"), "adapter.name", max_chars=256),
        "version": _required_text(row.get("version"), "adapter.version", max_chars=256),
    }


def _source(value: Any) -> dict[str, str]:
    row = _object(value, "source")
    return {
        "format": _required_text(row.get("format"), "source.format", max_chars=256),
        "digest": _sha256(row.get("digest"), "source.digest"),
    }


def _coverage(value: Any) -> dict[str, Any]:
    row = _object(value, "coverage")
    whole = row.get("whole_project_complete")
    if whole is not False:
        raise ValueError("coverage.whole_project_complete must be false; federated evidence cannot establish Scan whole-project completeness")
    return {
        "scope": _required_text(row.get("scope"), "coverage.scope"),
        "limitations": _required_text(row.get("limitations"), "coverage.limitations"),
        "whole_project_complete": False,
    }


def _result_identity(producer: Mapping[str, str], external_id: str, artifact_locator: str) -> str:
    payload = {
        "producer": dict(producer),
        "external_id": external_id,
        "artifact_locator": artifact_locator,
    }
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()[:24]


def _unknown_from_unmapped(
    builder: SemanticStateBuilder,
    *,
    identity: str,
    producer: Mapping[str, str],
    external_id: str,
    artifact_locator: str,
    disposition: str,
    result: Mapping[str, Any],
    privacy: str,
) -> str:
    if disposition == "unknown" and isinstance(result.get("unknown"), Mapping):
        unknown = result["unknown"]
        question = _redact(_required_text(unknown.get("question"), "unknown.question"), privacy)
        impact = _redact(_required_text(unknown.get("impact"), "unknown.impact"), privacy)
        next_step = _redact(_required_text(unknown.get("next_safe_step"), "unknown.next_safe_step"), privacy)
    else:
        question = f"How should external result {external_id} from {producer['name']} be resolved?"
        impact = "The external result is retained, but Scan cannot safely promote it without a canonical artifact bound to the current snapshot."
        next_step = "Review the adapter output and target snapshot, map the result to a canonical project artifact, then regenerate and re-import the federation bundle."
    reason = _redact(
        f"Federated result {external_id} from {producer['name']} referenced {artifact_locator}, which did not map to a canonical file artifact in the current Scan state.",
        privacy,
    )
    return builder.add_unknown(
        record_id=f"unknown:federation:{identity}",
        question=question,
        reason=reason,
        impact=impact,
        next_safe_step=next_step,
    )


def import_evidence_bundle(
    base_state: Mapping[str, Any],
    bundle: Mapping[str, Any],
    *,
    source_bytes: bytes | None = None,
) -> FederationImportResult:
    """Import a bounded data-only federation bundle into canonical Scan state."""
    validate_state(base_state)
    if base_state.get("schema_version") != "1.4":
        raise ValueError("evidence federation v1 requires Scan state schema 1.4")
    if bundle.get("scan_evidence_bundle_version") != FEDERATION_BUNDLE_VERSION:
        raise ValueError(f"scan_evidence_bundle_version must be {FEDERATION_BUNDLE_VERSION}")

    target = _object(bundle.get("target"), "target")
    target_snapshot = _sha256(target.get("snapshot_digest"), "target.snapshot_digest")
    actual_snapshot = base_state.get("provenance", {}).get("snapshot_digest")
    if target_snapshot != actual_snapshot:
        raise ValueError("target.snapshot_digest does not match the current Scan snapshot")
    actual_state_digest = state_digest(base_state)
    declared_state_digest = target.get("state_digest")
    if declared_state_digest is not None:
        declared_state_digest = _sha256(declared_state_digest, "target.state_digest")
        if declared_state_digest != actual_state_digest:
            raise ValueError("target.state_digest does not match the exact base Scan state")

    producer = _producer(bundle.get("producer"))
    adapter = _adapter(bundle.get("adapter"))
    declared_source = _source(bundle.get("source"))
    coverage = _coverage(bundle.get("coverage"))
    results = bundle.get("results")
    if not isinstance(results, list):
        raise ValueError("results must be an array")
    if len(results) > FEDERATION_MAX_RESULTS:
        raise ValueError(f"federation result count exceeds importer limit ({FEDERATION_MAX_RESULTS})")
    if not all(isinstance(row, Mapping) for row in results):
        raise ValueError("results must contain objects only")

    raw = source_bytes if source_bytes is not None else _canonical_bytes(bundle)
    bundle_digest = _digest(raw)
    builder = SemanticStateBuilder.from_state(base_state)
    privacy = str(base_state.get("privacy", {}).get("redaction_level", "standard"))
    artifacts_by_locator = {
        str(row.get("locator")): row
        for row in base_state.get("artifacts", [])
        if row.get("path_kind") == "file" and row.get("type") == "file"
    }

    imported_findings = 0
    imported_unknowns = 0
    imported_evidence = 0
    unmapped_results = 0
    ignored_results = 0
    seen_external: dict[str, str] = {}
    evidence_by_artifact: dict[str, list[str]] = {}

    for index, raw_result in enumerate(results):
        result = dict(raw_result)
        external_id = _required_text(result.get("external_id"), f"results[{index}].external_id", max_chars=512)
        canonical_result_digest = _digest(_canonical_bytes(result))
        if external_id in seen_external:
            if seen_external[external_id] != canonical_result_digest:
                raise ValueError(f"results[{index}].external_id conflicts with an earlier result: {external_id}")
            ignored_results += 1
            continue
        seen_external[external_id] = canonical_result_digest

        disposition = _required_text(result.get("disposition"), f"results[{index}].disposition", max_chars=64)
        if disposition not in _ALLOWED_DISPOSITIONS:
            raise ValueError(f"results[{index}].disposition must be finding or unknown")
        artifact_locator = _relative_locator(result.get("artifact_locator"), f"results[{index}].artifact_locator")
        artifact_identity = _required_text(
            result.get("artifact_content_identity"), f"results[{index}].artifact_content_identity", max_chars=512
        )
        identity = _result_identity(producer, external_id, artifact_locator)
        artifact = artifacts_by_locator.get(artifact_locator)
        if artifact is None:
            _unknown_from_unmapped(
                builder,
                identity=identity,
                producer=producer,
                external_id=external_id,
                artifact_locator=artifact_locator,
                disposition=disposition,
                result=result,
                privacy=privacy,
            )
            imported_unknowns += 1
            unmapped_results += 1
            continue
        if artifact_identity != artifact.get("content_identity"):
            raise ValueError(
                f"results[{index}].artifact_content_identity does not match current artifact {artifact_locator}"
            )

        evidence = _object(result.get("evidence"), f"results[{index}].evidence")
        evidence_kind = _required_text(evidence.get("kind"), f"results[{index}].evidence.kind", max_chars=64)
        if evidence_kind not in _ALLOWED_EVIDENCE_KINDS:
            raise ValueError(f"results[{index}].evidence.kind is invalid")
        evidence_class = _required_text(
            evidence.get("class"), f"results[{index}].evidence.class", max_chars=128
        )
        evidence_locator = _evidence_locator(
            evidence.get("locator"), artifact_locator, f"results[{index}].evidence.locator"
        )
        evidence_id = builder.add_evidence(
            record_id=f"evidence:federation:{identity}",
            artifact_id=str(artifact["id"]),
            locator=evidence_locator,
            kind=evidence_kind,
            claim=_redact(_required_text(evidence.get("claim"), f"results[{index}].evidence.claim"), privacy),
            result=_redact(_required_text(evidence.get("result"), f"results[{index}].evidence.result"), privacy),
            method=_redact(_required_text(evidence.get("method"), f"results[{index}].evidence.method"), privacy),
            source_digest=bundle_digest,
            producer_kind=producer["kind"],
            producer_name=producer["name"],
            producer_version=producer["version"],
            limitations=_redact(
                _required_text(evidence.get("limitations"), f"results[{index}].evidence.limitations"), privacy
            ),
            time=evidence.get("observed_at"),
            evidence_class=evidence_class,
        )
        imported_evidence += 1
        evidence_by_artifact.setdefault(str(artifact["id"]), []).append(evidence_id)

        if disposition == "finding":
            finding = _object(result.get("finding"), f"results[{index}].finding")
            severity = _required_text(finding.get("severity"), f"results[{index}].finding.severity", max_chars=64)
            if severity not in _ALLOWED_SEVERITIES:
                raise ValueError(f"results[{index}].finding.severity is invalid")
            builder.add_finding(
                record_id=f"finding:federation:{identity}",
                title=_redact(_required_text(finding.get("title"), f"results[{index}].finding.title"), privacy),
                impact=_redact(_required_text(finding.get("impact"), f"results[{index}].finding.impact"), privacy),
                severity=severity,
                confidence=_required_text(finding.get("confidence"), f"results[{index}].finding.confidence", max_chars=128),
                verification_state=_required_text(
                    finding.get("verification_state"), f"results[{index}].finding.verification_state", max_chars=64
                ),
                artifact_ids=[str(artifact["id"])],
                evidence_ids=[evidence_id],
                uncertainty=_redact(
                    _required_text(finding.get("uncertainty"), f"results[{index}].finding.uncertainty"), privacy
                ),
                recommendation=_redact(
                    _required_text(finding.get("recommendation"), f"results[{index}].finding.recommendation"), privacy
                ),
                safe_verification=_redact(
                    _required_text(finding.get("safe_verification"), f"results[{index}].finding.safe_verification"), privacy
                ),
            )
            imported_findings += 1
        else:
            unknown = _object(result.get("unknown"), f"results[{index}].unknown")
            builder.add_unknown(
                record_id=f"unknown:federation:{identity}",
                artifact_ids=[str(artifact["id"])],
                evidence_ids=[evidence_id],
                question=_redact(_required_text(unknown.get("question"), f"results[{index}].unknown.question"), privacy),
                reason=_redact(_required_text(unknown.get("reason"), f"results[{index}].unknown.reason"), privacy),
                impact=_redact(_required_text(unknown.get("impact"), f"results[{index}].unknown.impact"), privacy),
                next_safe_step=_redact(
                    _required_text(unknown.get("next_safe_step"), f"results[{index}].unknown.next_safe_step"), privacy
                ),
            )
            imported_unknowns += 1

    current_status = {str(row["id"]): str(row.get("status")) for row in base_state.get("artifacts", [])}
    evidence_rows = {row["id"]: row for row in builder.state["evidence"]}
    for artifact_id, evidence_ids in evidence_by_artifact.items():
        if current_status.get(artifact_id) == "analyzed":
            continue
        substantive = [ident for ident in evidence_ids if evidence_rows[ident]["kind"] != "unverified"]
        if substantive and current_status.get(artifact_id) not in {"excluded", "unreadable"}:
            builder.mark_artifact_partial(
                artifact_id,
                evidence_ids=substantive,
                reason="Federated external evidence imported; specialist result was not independently reproduced by Scan",
            )

    state = builder.build(analysis_complete=False)
    receipt = {
        "version": FEDERATION_BUNDLE_VERSION,
        "bundle_digest": bundle_digest,
        "target_snapshot_digest": target_snapshot,
        "target_state_digest": declared_state_digest,
        "base_state_digest_at_import": actual_state_digest,
        "producer": producer,
        "adapter": adapter,
        "source": {
            **declared_source,
            "digest_verified_by_scan": False,
            "verification_note": "Scan verified the federation bundle digest, not the adapter-declared originating source payload digest.",
        },
        "coverage": coverage,
        "imported_findings": imported_findings,
        "imported_unknowns": imported_unknowns,
        "imported_evidence": imported_evidence,
        "unmapped_results": unmapped_results,
        "ignored_results": ignored_results,
    }
    state.setdefault("extensions", {}).setdefault("evidence_federation_imports", []).append(receipt)
    validate_state(state)
    return FederationImportResult(
        state=state,
        imported_findings=imported_findings,
        imported_unknowns=imported_unknowns,
        imported_evidence=imported_evidence,
        unmapped_results=unmapped_results,
        ignored_results=ignored_results,
        bundle_digest=bundle_digest,
    )


def load_evidence_bundle_file(
    path: Path, *, max_bytes: int = FEDERATION_MAX_BYTES
) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink():
        raise ValueError("evidence federation bundle must not be a symlink")
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError(f"evidence federation bundle exceeds importer byte limit ({max_bytes})")
    raw = path.read_bytes()
    try:
        payload = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"Invalid UTF-8 evidence federation JSON: {error}") from error
    if not isinstance(payload, dict):
        raise ValueError("evidence federation bundle root must be an object")
    return payload, raw
