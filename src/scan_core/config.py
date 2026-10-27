"""Public configuration/result types for Scan Core."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal


PrivacyMode = Literal["offline", "local", "controlled-remote"]
RedactionLevel = Literal["none", "standard", "strict"]
BaselineMode = Literal["auto", "none", "explicit"]
Completion = Literal["complete", "partial", "blocked"]


@dataclass(frozen=True)
class ScanConfig:
    root: Path
    output_state: Path | None = None
    output_html: Path | None = None
    privacy_mode: PrivacyMode = "offline"
    redaction_level: RedactionLevel = "standard"
    excludes: tuple[str, ...] = ()
    sensitive_paths: tuple[str, ...] = ()
    max_file_bytes: int = 5_000_000
    max_total_bytes: int = 250_000_000
    follow_internal_links: bool = False
    baseline_mode: BaselineMode = "auto"
    baseline_path: Path | None = None
    reuse_enabled: bool = True
    max_baseline_state_bytes: int = 64_000_000

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", Path(self.root))
        if self.output_state is not None:
            object.__setattr__(self, "output_state", Path(self.output_state))
        if self.output_html is not None:
            object.__setattr__(self, "output_html", Path(self.output_html))
        if self.baseline_path is not None:
            object.__setattr__(self, "baseline_path", Path(self.baseline_path))


@dataclass(frozen=True)
class ScanResult:
    state: dict[str, Any]
    state_path: Path | None
    report_path: Path | None
    completion: Completion
    warnings: tuple[str, ...] = ()
