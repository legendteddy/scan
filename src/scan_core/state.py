"""Canonical Scan state construction and deterministic serialization."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import mimetypes
from pathlib import Path
from typing import Any, Mapping

from .config import ScanConfig, mode_contract
from .git_change import GitChangeScope
from .git_provenance import GitProvenance
from .inventory import InventoryArtifact, InventoryResult
from .privacy import PrivacyAssessment, path_is_sensitive
from .snapshot import Snapshot
from .validate import CHECK_CATEGORIES
from .version import __version__

SCHEMA_VERSION = "1.4"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8", errors="surrogatepass")


def _sha256_json(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(value)).hexdigest()


def canonical_state_json(state: Mapping[str, Any]) -> str:
    """Serialize state deterministically without losing Unicode path names."""
    return _canonical_bytes(dict(state)).decode("utf-8", errors="surrogatepass")


def state_digest(state: Mapping[str, Any]) -> str:
    """Return the canonical digest of an exact Scan state record."""
    return _sha256_json(dict(state))


def configuration_digest(config: ScanConfig) -> str:
    """Digest behavior-affecting configuration, excluding output destinations."""
    payload = {
        "privacy_mode": config.privacy_mode,
        "redaction_level": config.redaction_level,
        "scan_mode": config.scan_mode,
        "excludes": sorted(pattern.replace("\\", "/") for pattern in config.excludes),
        "sensitive_paths": sorted(pattern.replace("\\", "/") for pattern in config.sensitive_paths),
        "max_file_bytes": config.max_file_bytes,
        "max_total_bytes": config.max_total_bytes,
        "follow_internal_links": config.follow_internal_links,
        "baseline_mode": config.baseline_mode,
        "reuse_enabled": config.reuse_enabled,
        "max_baseline_state_bytes": config.max_baseline_state_bytes,
        "changed_since": config.changed_since,
        "project_config_source": config.project_config_source,
    }
    if config.git_metadata_roots:
        payload["git_metadata_roots"] = sorted(str(Path(root).absolute()) for root in config.git_metadata_roots)
    return _sha256_json(payload)


def _safe_config_path(value: str, config: ScanConfig) -> str:
    normalized = value.replace("\\", "/")
    if path_is_sensitive(normalized, config.sensitive_paths):
        digest = hashlib.sha256(normalized.encode("utf-8", errors="surrogatepass")).hexdigest()[:20]
        return f"[REDACTED:path-pattern]/{digest}"
    return value


def _privacy_safe_text(value: str, privacy: PrivacyAssessment | None) -> str:
    if privacy is None:
        return value
    safe = value
    sensitive_rows = sorted(
        (row for row in privacy.artifacts if row.sensitive_path),
        key=lambda row: len(row.locator),
        reverse=True,
    )
    for row in sensitive_rows:
        safe = safe.replace(row.locator, row.safe_locator)
    return safe


def _artifact_source_digest(artifact: InventoryArtifact) -> str:
    if artifact.content_identity.startswith("sha256:"):
        return artifact.content_identity
    return _sha256_json({
        "locator": artifact.locator,
        "path_kind": artifact.path_kind,
        "size_bytes": artifact.size_bytes,
        "content_identity": artifact.content_identity,
        "symlink_scope": artifact.symlink_scope,
        "excluded": artifact.excluded,
    })


def _evidence_id(artifact_id: str) -> str:
    digest = hashlib.sha256(("inventory:" + artifact_id).encode("utf-8")).hexdigest()
    return "evidence:" + digest[:20]


def _media_type(artifact: InventoryArtifact) -> str:
    if artifact.path_kind != "file":
        return "inode/" + artifact.path_kind
    guessed, _encoding = mimetypes.guess_type(artifact.locator, strict=False)
    return guessed or "application/octet-stream"


def _artifact_status(artifact: InventoryArtifact) -> tuple[str, str, str, str | None]:
    """Map deterministic inventory depth to honest Scan coverage semantics."""
    if artifact.excluded:
        return "excluded", "fresh", artifact.reason or "excluded by configuration", "fresh"
    if artifact.content_identity.startswith("unreadable:"):
        return "unreadable", "none", artifact.reason or "artifact could not be read", None
    if artifact.path_kind == "file" and artifact.content_identity.startswith("sha256:"):
        return "content_read", "fresh", "bytes hashed; semantic behavior not analyzed", "fresh"
    if artifact.path_kind == "file" and artifact.content_identity.startswith("unhashed:"):
        return "partial", "fresh", artifact.reason or "metadata read but content identity incomplete", "fresh"
    if artifact.path_kind in {"directory", "symlink", "special", "unknown"}:
        return "metadata_only", "fresh", artifact.reason or "filesystem metadata inventoried", "fresh"
    return "discovered", "none", artifact.reason or "artifact discovered", None


def _artifact_evidence(
    artifact: InventoryArtifact,
    inspected_at: str,
    *,
    locator: str | None = None,
) -> dict[str, Any] | None:
    status, origin, reason, _ = _artifact_status(artifact)
    if origin == "none":
        return None
    result = {
        "path_kind": artifact.path_kind,
        "size_bytes": artifact.size_bytes,
        "content_identity": artifact.content_identity,
        "symlink_scope": artifact.symlink_scope,
        "excluded": artifact.excluded,
    }
    return {
        "id": _evidence_id(artifact.id),
        "artifact_id": artifact.id,
        "locator": locator or artifact.locator,
        "kind": "static",
        "claim": "Scan Core deterministically inventoried this artifact",
        "result": json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        "method": "read-only filesystem metadata inventory and bounded SHA-256 hashing",
        "time": inspected_at,
        "limitations": reason,
        "inspection_origin": "fresh",
        "producer": {"kind": "scan-core", "name": "scan-core", "version": __version__},
        "source_digest": _artifact_source_digest(artifact),
        "freshness": {
            "status": "fresh",
            "source_state_digest": None,
            "source_evidence_id": None,
            "original_observed_at": inspected_at,
            "reused_at": None,
            "reuse_reason": None,
        },
    }


def _check_rows(artifact_ids: list[str], evidence_ids: list[str], inventory_complete: bool) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for category in CHECK_CATEGORIES:
        if category == "inventory_and_provenance":
            if not evidence_ids:
                status = "not_assessed"
                verification_state = "unverified"
                result = "No artifact evidence rows exist in the declared scope"
                next_step = "Add or authorize at least one in-scope artifact, then rerun inventory/provenance assessment"
            else:
                status = "assessed" if inventory_complete else "partial"
                verification_state = "static"
                result = (
                    "Inventory and content identities were established within configured limits"
                    if inventory_complete
                    else "Inventory/provenance is partial because one or more identities or reads were incomplete"
                )
                next_step = None if inventory_complete else "Resolve unreadable/resource-limited artifacts and rerun"
            rows.append({
                "id": "check-" + category,
                "category": category,
                "title": "Inventory and provenance",
                "status": status,
                "scope": "Declared local project scope",
                "method": "Deterministic Scan Core inventory and snapshot construction",
                "artifact_ids": artifact_ids,
                "evidence_ids": evidence_ids,
                "related_ids": [],
                "verification_state": verification_state,
                "result": result,
                "limitations": "This check does not establish semantic correctness or runtime behavior",
                "reason": "Scan Core performs deterministic inventory as part of the local baseline",
                "next_step": next_step,
            })
        else:
            rows.append({
                "id": "check-" + category,
                "category": category,
                "title": category.replace("_", " "),
                "status": "not_assessed",
                "scope": "Declared local project scope",
                "method": "Not performed by deterministic Scan Core state construction",
                "artifact_ids": [],
                "evidence_ids": [],
                "related_ids": [],
                "verification_state": "unverified",
                "result": "No assessment result is available",
                "limitations": "Requires an authorized semantic or runtime assessment appropriate to this category",
                "reason": "Deterministic Scan Core does not perform this semantic or runtime assessment",
                "next_step": "Perform this check using an authorized analyzer and attach evidence",
            })
    return rows


def build_state(
    config: ScanConfig,
    inventory: InventoryResult,
    snapshot: Snapshot,
    *,
    privacy: PrivacyAssessment | None = None,
    git_provenance: GitProvenance | None = None,
    git_change_scope: GitChangeScope | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
    baseline_status: str | None = None,
) -> dict[str, Any]:
    """Build canonical Scan 1.4 state from deterministic inventory and snapshot data."""
    started = started_at or _utc_now()
    completed = completed_at or started
    config_digest = configuration_digest(config)
    scan_id_seed = {"snapshot": snapshot.digest, "config": config_digest, "started_at": started}
    scan_id = "scan:" + hashlib.sha256(_canonical_bytes(scan_id_seed)).hexdigest()[:24]

    privacy_by_id = privacy.by_id() if privacy is not None else {}
    artifacts: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    for item in inventory.artifacts:
        status, origin, reason, inspected_origin = _artifact_status(item)
        privacy_row = privacy_by_id.get(item.id)
        locator = privacy_row.safe_locator if privacy_row is not None else item.locator
        redaction_state = privacy_row.redaction_state if privacy_row is not None else "none"
        redaction_count = privacy_row.redaction_count if privacy_row is not None else 0
        evidence_row = _artifact_evidence(item, completed, locator=locator)
        evidence_ids = [evidence_row["id"]] if evidence_row is not None else []
        if evidence_row is not None:
            evidence.append(evidence_row)
        artifacts.append({
            "id": item.id,
            "locator": locator,
            "type": item.path_kind,
            "status": status,
            "reason": reason,
            "evidence_ids": evidence_ids,
            "inspection_origin": origin,
            "inspected_at": completed if inspected_origin is not None else None,
            "content_identity": item.content_identity,
            "size_bytes": item.size_bytes,
            "media_type": _media_type(item),
            "path_kind": item.path_kind,
            "redaction_state": redaction_state,
            "redaction_count": redaction_count,
        })

    artifact_ids = [item["id"] for item in artifacts]
    evidence_ids = [item["id"] for item in evidence]
    checks = _check_rows(artifact_ids, evidence_ids, inventory.complete)
    counts_by_status = dict(Counter(item["status"] for item in artifacts))
    counts_by_check_status = dict(Counter(item["status"] for item in checks))
    unreadable_count = counts_by_status.get("unreadable", 0)
    redacted_artifact_count = sum(
        1 for item in artifacts
        if item["redaction_state"] in {"content_redacted", "path_redacted", "fully_omitted"}
    )
    privacy_redaction_count = privacy.redaction_count if privacy is not None else 0
    sensitive_path_count = privacy.sensitive_path_count if privacy is not None else 0
    sensitive_omissions = [
        "sensitive artifact path omitted: " + row.artifact_id
        for row in (privacy.artifacts if privacy is not None else ())
        if row.sensitive_path
    ]

    contract = mode_contract(config.scan_mode)
    limits = [
        "Semantic analysis has not been performed by deterministic Scan Core",
        contract,
    ]
    limits.extend(_privacy_safe_text(value, privacy) for value in inventory.resource_limits_hit)
    limits.extend(_privacy_safe_text(value, privacy) for value in inventory.warnings)
    if privacy is not None:
        limits.extend(_privacy_safe_text(value, privacy) for value in privacy.warnings)
    remaining = [
        "Perform semantic analysis for applicable check categories",
        "Perform runtime verification only where separately authorized",
    ]
    if config.scan_mode == "quick":
        remaining.insert(0, "Run deep mode for broad first-party semantic accounting before making whole-project completeness claims")
    elif config.scan_mode == "deep":
        remaining.append("Use forensic mode if Git internals or provenance-heavy historical evidence are material to the review")
    if not inventory.complete:
        remaining.insert(0, "Resolve incomplete inventory/content identity boundaries and rerun")

    git = git_provenance or GitProvenance(detected=False)
    tool_versions = [{"kind": "scan-core", "name": "scan-core", "version": __version__}]
    if git_change_scope is not None:
        tool_versions.append({"kind": "external-tool", "name": "git", "version": git_change_scope.git_version})
    sampling = {
        "quick": "Intentional triage boundary: common dependency/build/cache and Git-internal trees are recorded as mode exclusions; semantic agents must limit conclusions to inspected high-value paths.",
        "deep": "No intentional first-party sampling; reads are bounded by configured resource ceilings, with Git internal storage represented separately from ordinary project artifacts.",
        "forensic": "No intentional mode suppression; reads are bounded only by explicit exclusions, safety boundaries and configured resource ceilings.",
    }[config.scan_mode]

    project_name = inventory.root.name or "project"
    resolved_baseline_status = baseline_status or ("disabled" if config.baseline_mode == "none" else "not_found")
    baseline = {
        "mode": config.baseline_mode,
        "status": resolved_baseline_status,
        "source_schema_version": None,
        "source_state_digest": None,
        "source_snapshot_digest": None,
        "snapshot_relation": "none",
        "reuse_enabled": config.reuse_enabled if config.baseline_mode != "none" else False,
        "fresh_evidence_count": len(evidence),
        "reused_evidence_count": 0,
        "rejected_reuse_count": 0,
        "rejected_reuse_reasons": {},
    }
    delta = {
        "available": False,
        "artifacts": {"added": [], "changed": [], "removed": [], "unchanged": []},
        "findings": {"new": [], "resolved": [], "persisting": [], "modified": []},
        "unknowns": {"new": [], "resolved": [], "persisting": [], "modified": []},
    }
    state: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "run": {
            "scan_id": scan_id,
            "scan_version": __version__,
            "started_at": started,
            "completed_at": completed,
            "mode": "static",
            "scan_mode": config.scan_mode,
            "target_executed": False,
            "network_used": False,
        },
        "privacy": {
            "mode": config.privacy_mode,
            "redaction_level": config.redaction_level,
            "redaction_count": privacy_redaction_count,
            "sensitive_path_count": sensitive_path_count,
            "egress_performed": False,
            "egress_bytes": 0,
        },
        "provenance": {
            "root_identity": "root:" + hashlib.sha256(snapshot.digest.encode("ascii")).hexdigest()[:24],
            "snapshot_digest": snapshot.digest,
            "state_digest_algorithm": "sha256",
            "tool_versions": tool_versions,
            "configuration_digest": config_digest,
            "git": git.as_dict(),
        },
        "baseline": baseline,
        "delta": delta,
        "project": {
            "name": project_name,
            "purpose": "Establish a deterministic static inventory and snapshot baseline",
            "target_types": ["local_directory"],
            "source_locators": ["."],
            "snapshot": {"identity": snapshot.digest, "time": completed},
            "scope": "Project-local filesystem tree rooted at the declared scan path",
            "exclusions": [
                _safe_config_path(pattern, config) for pattern in config.excludes
            ] + [
                f"scan mode {config.scan_mode}: " + _safe_config_path(pattern, config)
                for pattern in inventory.mode_omissions
            ] + [
                "tool-owned output: " + _safe_config_path(pattern, config)
                for pattern in inventory.tool_owned_omissions
            ],
            "critical_artifact_ids": [],
        },
        "summary": {
            "overview": "Deterministic inventory and provenance baseline created without executing target code",
            "operation": "Read filesystem metadata and hash eligible file bytes within configured ceilings",
            "condition": "Inventory baseline available; semantic analysis and runtime verification remain incomplete",
            "strengths": ["Artifact IDs and snapshot identity are deterministic for unchanged normalized input"],
            "priorities": ["Continue with evidence-backed semantic checks rather than inferring correctness from hashing"],
            "readiness": "not established",
            "evidence_ids": evidence_ids,
            "limitations": "Hashing and metadata inspection do not prove correctness, security, test status, deployment state or runtime behavior",
        },
        "coverage": {
            "discovery_complete": inventory.discovery_complete,
            "analysis_complete": False,
            "discovered_artifact_count": len(artifacts),
            "counts_by_status": counts_by_status,
            "counts_by_check_status": counts_by_check_status,
            "checks_complete": False,
            "limits": limits,
            "sampling": sampling,
            "methods": ["filesystem metadata inventory", "bounded SHA-256 hashing", "canonical snapshot manifest"],
            "checks_performed": ["inventory_and_provenance"],
            "checks_not_performed": [c for c in CHECK_CATEGORIES if c != "inventory_and_provenance"],
            "snapshot_consistency": "Snapshot digest is derived from a canonically ordered normalized manifest",
            "sensitive_omissions": sensitive_omissions,
            "resource_limits_hit": [
                _privacy_safe_text(value, privacy) for value in inventory.resource_limits_hit
            ],
            "unreadable_artifact_count": unreadable_count,
            "redacted_artifact_count": redacted_artifact_count,
        },
        "continuation": {
            "completed": ["Deterministic inventory", "Snapshot identity", "Canonical Scan 1.4 state construction"],
            "remaining": remaining,
            "hypotheses": [],
            "decisions": ["Target code was not executed", "No network operation was performed"],
            "revalidation": ["Rebuild inventory and compare snapshot digest after source-byte or path changes"],
            "source_needs": ["Original project bytes are required for deeper semantic continuation"],
            "authorization_note": "This state does not authorize target execution, modification or network egress",
        },
        "artifacts": artifacts,
        "components": [],
        "relationships": [],
        "evidence": evidence,
        "checks": checks,
        "findings": [],
        "controls": [],
        "unknowns": [{
            "id": "unknown:semantic-runtime",
            "question": "What semantic behavior, correctness, security and runtime properties do these artifacts have?",
            "artifact_ids": [],
            "evidence_ids": [],
            "reason": "Deterministic inventory and hashing do not answer semantic or runtime questions",
            "impact": "Project readiness cannot be established from this state alone",
            "next_safe_step": "Perform authorized semantic checks and runtime verification where appropriate",
        }],
        "actions": [],
        "extensions": {
            "scan_mode": {
                "name": config.scan_mode,
                "coverage_contract": contract,
                "mode_exclusions": [_safe_config_path(pattern, config) for pattern in inventory.mode_omissions],
                "deeper_mode": "deep" if config.scan_mode == "quick" else ("forensic" if config.scan_mode == "deep" else None),
            },
            "configuration_policy": {
                "project_config_source": config.project_config_source,
                "precedence": "caller options > project config when enabled > built-in defaults",
                "effective": {
                    "privacy_mode": config.privacy_mode,
                    "redaction_level": config.redaction_level,
                    "scan_mode": config.scan_mode,
                    "excludes": [_safe_config_path(pattern, config) for pattern in config.excludes],
                    "sensitive_path_pattern_count": len(config.sensitive_paths),
                    "max_file_bytes": config.max_file_bytes,
                    "max_total_bytes": config.max_total_bytes,
                    "follow_internal_links": config.follow_internal_links,
                    "baseline_mode": config.baseline_mode,
                    "reuse_enabled": config.reuse_enabled,
                    "max_baseline_state_bytes": config.max_baseline_state_bytes,
                },
            },
             "critical_artifact_selection": "Not determined by deterministic inventory; semantic selection is required",
            "privacy_execution": "Deterministic privacy assessment completed; raw matched sensitive values are not stored in canonical state",
            "privacy_egress_preview": {
                "files_selected": privacy.files_selected if privacy is not None else 0,
                "bytes_selected": privacy.bytes_selected if privacy is not None else 0,
                "files_omitted_by_policy": privacy.files_omitted_by_policy if privacy is not None else 0,
                "sensitive_paths_omitted": privacy.sensitive_paths_omitted if privacy is not None else 0,
                "network_action": "none",
            },
            "tool_owned_omissions": [
                _safe_config_path(pattern, config) for pattern in inventory.tool_owned_omissions
            ],
            "snapshot_identity_complete": snapshot.identity_complete,
            "inventory_total_hashed_bytes": inventory.total_hashed_bytes,
        },
    }
    if git_change_scope is not None:
        state["extensions"]["git_change_scope"] = git_change_scope.as_dict()
    return state
