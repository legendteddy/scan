"""Project-local .scan/config.toml loading for Scan v0.2.

Configuration is data, never executable input. CLI values are resolved separately so
precedence stays explicit: CLI > project config > built-in defaults.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tomllib
from typing import Any

from .errors import CommandError


@dataclass(frozen=True)
class ProjectSettings:
    privacy_mode: str = "offline"
    redaction_level: str = "standard"
    scan_mode: str = "deep"
    excludes: tuple[str, ...] = ()
    sensitive_paths: tuple[str, ...] = ()
    max_file_bytes: int = 5_000_000
    max_total_bytes: int = 250_000_000
    follow_internal_links: bool = False


_ALLOWED_SCAN = {
    "privacy",
    "redact",
    "mode",
    "max_file_bytes",
    "max_total_bytes",
    "follow_internal_links",
    "sensitive_paths",
}
_ALLOWED_TOP = {"scan", "exclude"}
_ALLOWED_PRIVACY = {"offline", "local", "controlled-remote"}
_ALLOWED_REDACTION = {"none", "standard", "strict"}
_ALLOWED_MODES = {"quick", "deep", "forensic"}


def _string_list(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise CommandError(f"{label} must be an array of nonempty strings")
    return tuple(value)


def load_project_settings(root: str | Path) -> ProjectSettings:
    """Load optional ``ROOT/.scan/config.toml`` without executing target content."""
    root_path = Path(root)
    path = root_path / ".scan" / "config.toml"
    if not path.exists():
        return ProjectSettings()
    if not path.is_file():
        raise CommandError(f"Scan config is not a regular file: {path}")
    try:
        with path.open("rb") as stream:
            data = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise CommandError(f"Cannot read Scan config {path}: {error}") from error
    if not isinstance(data, dict):
        raise CommandError("Scan config root must be a TOML table")
    unknown_top = set(data) - _ALLOWED_TOP
    if unknown_top:
        raise CommandError("Unknown Scan config section(s): " + ", ".join(sorted(unknown_top)))

    scan = data.get("scan", {})
    exclude = data.get("exclude", {})
    if not isinstance(scan, dict):
        raise CommandError("[scan] must be a table")
    if not isinstance(exclude, dict):
        raise CommandError("[exclude] must be a table")
    unknown_scan = set(scan) - _ALLOWED_SCAN
    if unknown_scan:
        raise CommandError("Unknown [scan] key(s): " + ", ".join(sorted(unknown_scan)))
    unknown_exclude = set(exclude) - {"patterns"}
    if unknown_exclude:
        raise CommandError("Unknown [exclude] key(s): " + ", ".join(sorted(unknown_exclude)))

    privacy = scan.get("privacy", "offline")
    redact = scan.get("redact", "standard")
    mode = scan.get("mode", "deep")
    max_file = scan.get("max_file_bytes", 5_000_000)
    max_total = scan.get("max_total_bytes", 250_000_000)
    follow = scan.get("follow_internal_links", False)
    sensitive = scan.get("sensitive_paths", [])
    patterns = exclude.get("patterns", [])

    if privacy not in _ALLOWED_PRIVACY:
        raise CommandError("scan.privacy must be offline, local, or controlled-remote")
    if redact not in _ALLOWED_REDACTION:
        raise CommandError("scan.redact must be none, standard, or strict")
    if mode not in _ALLOWED_MODES:
        raise CommandError("scan.mode must be quick, deep, or forensic")
    if type(max_file) is not int or max_file < 0:
        raise CommandError("scan.max_file_bytes must be a non-negative integer")
    if type(max_total) is not int or max_total < 0:
        raise CommandError("scan.max_total_bytes must be a non-negative integer")
    if type(follow) is not bool:
        raise CommandError("scan.follow_internal_links must be boolean")

    return ProjectSettings(
        privacy_mode=privacy,
        redaction_level=redact,
        scan_mode=mode,
        excludes=_string_list(patterns, "exclude.patterns"),
        sensitive_paths=_string_list(sensitive, "scan.sensitive_paths"),
        max_file_bytes=max_file,
        max_total_bytes=max_total,
        follow_internal_links=follow,
    )
