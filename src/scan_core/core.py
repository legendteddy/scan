"""Top-level deterministic Scan Core orchestration for v0.2 Slice 3."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from .config import ScanConfig, ScanResult
from .errors import CommandError
from .inventory import build_inventory
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
    """Return explicit Scan-owned output paths omitted from target inventory.

    The conventional `.scan` directory is wholly tool-owned. For a custom output
    inside the target, only the output file is omitted; its parent directory is
    created before inventory when needed so repeat snapshots stay stable.
    """
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


def scan_project(config: ScanConfig) -> ScanResult:
    """Build deterministic inventory, snapshot and canonical Scan 1.3 JSON state.

    Slice 3 intentionally does not render HTML. Callers requesting HTML receive a
    clear command error rather than a placeholder report that could be mistaken for
    a complete v0.2 output.
    """
    if config.output_html is not None:
        raise CommandError("HTML report rendering lands in Slice 5; request state-only output for Slice 3")

    started_at = _utc_now()
    root = Path(config.root).resolve(strict=True)
    tool_owned_omissions = _prepare_output_omissions(config, root)
    inventory = build_inventory(config, _internal_ignores=tool_owned_omissions)
    snapshot = build_snapshot(inventory)
    completed_at = _utc_now()
    state = build_state(
        config,
        inventory,
        snapshot,
        started_at=started_at,
        completed_at=completed_at,
    )
    validate_state(state, version="1.3")

    state_path = _write_state(config.output_state, state) if config.output_state is not None else None
    completion = "partial"
    warnings = tuple(inventory.warnings) + (
        "Semantic analysis and runtime verification are not established by deterministic state construction",
    )
    return ScanResult(
        state=state,
        state_path=state_path,
        report_path=None,
        completion=completion,
        warnings=warnings,
    )
