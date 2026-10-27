"""Top-level deterministic Scan Core orchestration."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from .baseline import BaselineResolution, resolve_baseline
from .compare import Comparison, compare_states
from .config import ScanConfig, ScanResult
from .git_provenance import inspect_git_provenance
from .inventory import build_inventory
from .privacy import assess_privacy
from .render import render_report
from .reuse import ReusePolicy, check_definition_digest, evaluate_reuse, reused_evidence_record
from .snapshot import build_snapshot
from .state import build_state, canonical_state_json
from .validate import validate_state


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _write_state(path: Path, state: dict) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(canonical_state_json(state) + "\n", encoding="utf-8", newline="\n")
    temporary.replace(path)
    return path


def _project_locator(root: Path, path: Path) -> str | None:
    try:
        absolute = Path(path).resolve(strict=False)
        relative = absolute.relative_to(root)
    except (OSError, ValueError):
        return None
    locator = PurePosixPath(*relative.parts).as_posix()
    return None if locator in {"", "."} else locator


def _prepare_output_omissions(config: ScanConfig, root: Path) -> tuple[str, ...]:
    ignores: set[str] = set()
    for output in (config.output_state, config.output_html):
        if output is None:
            continue
        locator = _project_locator(root, output)
        if locator is None:
            continue
        first = locator.split("/", 1)[0]
        if first == ".scan":
            ignores.update({".scan", ".scan/**"})
            continue
        output_path = Path(output).resolve(strict=False)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        ignores.add(locator)
    return tuple(sorted(ignores))


def _apply_comparison(state: dict, resolution: BaselineResolution, comparison: Comparison) -> None:
    baseline = state["baseline"]
    baseline.update({
        "status": "used",
        "source_schema_version": comparison.previous_schema_version,
        "source_state_digest": comparison.previous_state_digest,
        "source_snapshot_digest": comparison.previous_snapshot_digest,
        "snapshot_relation": comparison.snapshot_relation,
        "fresh_evidence_count": len(state["evidence"]),
        "reused_evidence_count": 0,
        "rejected_reuse_count": 0,
        "rejected_reuse_reasons": {},
    })
    state["delta"] = {
        "available": True,
        "artifacts": {key: list(value) for key, value in comparison.artifacts.items()},
        "findings": {key: list(value) for key, value in comparison.findings.items()},
        "unknowns": {key: list(value) for key, value in comparison.unknowns.items()},
    }


def _reuse_policy(state: Mapping[str, Any], config: ScanConfig) -> ReusePolicy:
    producers = tuple(
        (str(row.get("kind")), str(row.get("name")), str(row.get("version")))
        for row in state["provenance"]["tool_versions"]
        if isinstance(row, Mapping)
    )
    checks = tuple((row["id"], check_definition_digest(row)) for row in state["checks"])
    return ReusePolicy(
        enabled=config.reuse_enabled,
        available_producers=producers,
        check_definitions=checks,
        redaction_level=config.redaction_level,
        sensitive_path_patterns=config.sensitive_paths,
    )


def _apply_reuse(state: dict[str, Any], previous: Mapping[str, Any], config: ScanConfig, reused_at: str) -> None:
    """Copy only explicitly reuse-aware higher-level evidence that passes every gate."""
    baseline = state["baseline"]
    if not config.reuse_enabled:
        baseline["fresh_evidence_count"] = len(state["evidence"])
        return

    source_state_digest = baseline["source_state_digest"]
    if not isinstance(source_state_digest, str):
        return
    policy = _reuse_policy(state, config)
    current_artifacts = {row["id"]: row for row in state["artifacts"]}
    previous_artifacts = {row["id"]: row for row in previous.get("artifacts", []) if isinstance(row, Mapping)}
    previous_checks = {row["id"]: row for row in previous.get("checks", []) if isinstance(row, Mapping)}
    previous_producers = {
        (row.get("kind"), row.get("name"), row.get("version"))
        for row in previous.get("provenance", {}).get("tool_versions", [])
        if isinstance(row, Mapping)
    }
    current_evidence_ids = {row["id"] for row in state["evidence"]}
    rejected: Counter[str] = Counter()
    reused_rows: list[dict[str, Any]] = []

    # Inventory/provenance evidence is intentionally not a candidate. A prior row
    # must explicitly opt into the higher-level reuse contract with evidence_class.
    candidates = [
        row for row in previous.get("evidence", [])
        if isinstance(row, Mapping) and isinstance(row.get("evidence_class"), str)
    ]
    for previous_evidence in candidates:
        artifact_id = previous_evidence.get("artifact_id")
        current_artifact = current_artifacts.get(artifact_id)
        if current_artifact is None:
            rejected["artifact_missing"] += 1
            continue
        previous_artifact = previous_artifacts.get(artifact_id)
        if previous_artifact is None:
            rejected["baseline_artifact_missing"] += 1
            continue
        if previous_evidence.get("source_digest") != previous_artifact.get("content_identity"):
            rejected["baseline_source_mismatch"] += 1
            continue
        producer = previous_evidence.get("producer")
        producer_key = (
            producer.get("kind"), producer.get("name"), producer.get("version")
        ) if isinstance(producer, Mapping) else (None, None, None)
        if producer_key not in previous_producers:
            rejected["baseline_producer_unrecorded"] += 1
            continue
        check_id = previous_evidence.get("check_id")
        previous_check = previous_checks.get(check_id)
        if previous_check is None:
            rejected["baseline_check_missing"] += 1
            continue
        if previous_evidence.get("check_definition_digest") != check_definition_digest(previous_check):
            rejected["baseline_check_definition_mismatch"] += 1
            continue
        evidence_id = previous_evidence.get("id")
        if evidence_id in current_evidence_ids:
            rejected["current_evidence_id_collision"] += 1
            continue
        decision = evaluate_reuse(previous_evidence, current_artifact, policy)
        if not decision.reusable:
            rejected[decision.reason] += 1
            continue
        reused = reused_evidence_record(
            previous_evidence,
            current_artifact,
            source_state_digest=source_state_digest,
            source_scan_id=str(previous["run"]["scan_id"]),
            reused_at=reused_at,
            policy=policy,
        )
        reused_rows.append(reused)
        current_evidence_ids.add(reused["id"])
        current_artifact["evidence_ids"].append(reused["id"])

    state["evidence"].extend(reused_rows)
    state["summary"]["evidence_ids"].extend(row["id"] for row in reused_rows)
    baseline["fresh_evidence_count"] = len(state["evidence"]) - len(reused_rows)
    baseline["reused_evidence_count"] = len(reused_rows)
    baseline["rejected_reuse_count"] = sum(rejected.values())
    baseline["rejected_reuse_reasons"] = dict(sorted(rejected.items()))


def scan_project(config: ScanConfig) -> ScanResult:
    """Build current state, compare a local baseline, safely reuse evidence, and write outputs."""
    started_at = _utc_now()
    root = Path(config.root).resolve(strict=True)

    # Baseline resolution precedes any output replacement or custom-output directory creation.
    resolution = resolve_baseline(
        mode=config.baseline_mode,
        output_state=config.output_state,
        explicit_path=config.baseline_path,
        max_state_bytes=config.max_baseline_state_bytes,
    )

    tool_owned_omissions = _prepare_output_omissions(config, root)
    git_provenance = inspect_git_provenance(root)
    inventory = build_inventory(config, _internal_ignores=tool_owned_omissions)
    snapshot = build_snapshot(inventory)
    privacy = assess_privacy(config, inventory)
    completed_at = _utc_now()

    temporary_status = "not_found" if resolution.status == "used" else resolution.status
    state = build_state(
        config,
        inventory,
        snapshot,
        privacy=privacy,
        git_provenance=git_provenance,
        started_at=started_at,
        completed_at=completed_at,
        baseline_status=temporary_status,
    )
    if resolution.state is not None:
        comparison = compare_states(resolution.state, state)
        _apply_comparison(state, resolution, comparison)
        _apply_reuse(state, resolution.state, config, completed_at)
    validate_state(state, version="1.4")

    state_path = _write_state(config.output_state, state) if config.output_state is not None else None
    report_path = render_report(state, config.output_html) if config.output_html is not None else None
    completion = "partial"
    warning_rows = list(inventory.warnings) + list(privacy.warnings)
    if resolution.warning:
        warning_rows.append(resolution.warning)
    warning_rows.append("Semantic analysis and runtime verification are not established by deterministic state construction")
    return ScanResult(
        state=state,
        state_path=state_path,
        report_path=report_path,
        completion=completion,
        warnings=tuple(warning_rows),
    )
