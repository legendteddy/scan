"""Deterministic identifiers and path normalization for Scan Core."""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath


def normalize_locator(root: Path, path: Path) -> str:
    """Return a project-relative POSIX locator and reject lexical root escape."""
    root_abs = Path(root).absolute()
    path_abs = Path(path).absolute()
    try:
        relative = path_abs.relative_to(root_abs)
    except ValueError as error:
        raise ValueError(f"Path escapes declared root: {path}") from error
    locator = PurePosixPath(*relative.parts).as_posix()
    if locator in {"", "."}:
        raise ValueError("Root itself is not an artifact locator")
    if locator == ".." or locator.startswith("../"):
        raise ValueError(f"Path escapes declared root: {path}")
    return locator


def _validated_locator(locator: str) -> str:
    if not isinstance(locator, str) or not locator or "\\" in locator:
        raise ValueError(f"Locator is not normalized POSIX-relative: {locator!r}")
    pure = PurePosixPath(locator)
    normalized = pure.as_posix()
    if pure.is_absolute() or normalized != locator or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError(f"Locator is not normalized POSIX-relative: {locator!r}")
    return normalized


def artifact_id(locator: str) -> str:
    """Derive a stable artifact ID from a normalized project-relative locator."""
    normalized = _validated_locator(locator)
    digest = hashlib.sha256(normalized.encode("utf-8", errors="surrogatepass")).hexdigest()
    return f"artifact:{digest[:20]}"


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()
