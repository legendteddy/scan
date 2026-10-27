"""Top-level deterministic Scan Core orchestration."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from .baseline import BaselineResolution, resolve_baseline
from .compare import Comparison, compare_states
from .config import ScanConfig, ScanResult
from .git_provenance import inspect_git_provenance
from .inventory import build_inventory
from .privacy import assess_privacy
from .render import render_report
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


def scan_project(config: ScanConfig) -> ScanResult:
    """Build current state, optionally compare against a local baseline, and write outputs."""
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
