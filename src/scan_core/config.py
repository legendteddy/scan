"""Frozen public configuration/result types for Scan Core."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal


PrivacyMode = Literal["offline", "local", "controlled-remote"]
RedactionLevel = Literal["none", "standard", "strict"]
ScanMode = Literal["quick", "deep", "forensic"]
Completion = Literal["complete", "partial", "blocked"]


_MODE_EXCLUDES: dict[str, tuple[str, ...]] = {
    # Quick mode preserves first-party signal while suppressing common dependency,
    # build/cache and repository-internal trees from ordinary content inspection.
    "quick": (
        ".git/**",
        "node_modules/**",
        ".venv/**",
        "venv/**",
        "__pycache__/**",
        "dist/**",
        "build/**",
    ),
    # Deep remains the whole-project first-party mode. Git object storage is
    # provenance, not normal project source, and is represented separately.
    "deep": (".git/**",),
    # Forensic deliberately opts back into repository internals/history.
    "forensic": (),
}

_MODE_CONTRACTS = {
    "quick": "Triage mode: inventory the project while bounding ordinary content inspection around first-party, high-value paths; dependency/build/cache and Git internals are explicitly suppressed.",
    "deep": "Whole-project mode: inspect safely readable project content broadly; Git internal storage is excluded from ordinary artifact analysis and represented as repository provenance.",
    "forensic": "Provenance-heavy mode: include normally suppressed Git internals and other in-scope artifacts unless the user explicitly excludes them.",
}


def mode_excludes(mode: ScanMode | str) -> tuple[str, ...]:
    try:
        return _MODE_EXCLUDES[mode]
    except KeyError as error:
        raise ValueError(f"Unsupported scan mode: {mode}") from error


def mode_contract(mode: ScanMode | str) -> str:
    try:
        return _MODE_CONTRACTS[mode]
    except KeyError as error:
        raise ValueError(f"Unsupported scan mode: {mode}") from error


@dataclass(frozen=True)
class ScanConfig:
    root: Path
    output_state: Path | None = None
    output_html: Path | None = None
    privacy_mode: PrivacyMode = "offline"
    redaction_level: RedactionLevel = "standard"
    scan_mode: ScanMode = "deep"
    excludes: tuple[str, ...] = ()
    sensitive_paths: tuple[str, ...] = ()
    max_file_bytes: int = 5_000_000
    max_total_bytes: int = 250_000_000
    follow_internal_links: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", Path(self.root))
        if self.output_state is not None:
            object.__setattr__(self, "output_state", Path(self.output_state))
        if self.output_html is not None:
            object.__setattr__(self, "output_html", Path(self.output_html))
        if self.scan_mode not in _MODE_EXCLUDES:
            raise ValueError(f"Unsupported scan mode: {self.scan_mode}")


@dataclass(frozen=True)
class ScanResult:
    state: dict[str, Any]
    state_path: Path | None
    report_path: Path | None
    completion: Completion
    warnings: tuple[str, ...] = ()
