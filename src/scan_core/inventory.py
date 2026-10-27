"""Deterministic, read-only project inventory for Scan Core."""

from __future__ import annotations

import fnmatch
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .config import ScanConfig
from .errors import SourceError
from .ids import artifact_id, normalize_locator, sha256_bytes


@dataclass(frozen=True)
class InventoryArtifact:
    id: str
    locator: str
    display_name: str
    path_kind: str
    size_bytes: int
    content_identity: str
    symlink_target: str | None = None
    symlink_scope: str | None = None
    excluded: bool = False
    reason: str = ""


@dataclass(frozen=True)
class InventoryResult:
    root: Path
    artifacts: tuple[InventoryArtifact, ...]
    discovery_complete: bool
    identity_complete: bool
    total_hashed_bytes: int
    resource_limits_hit: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        return self.discovery_complete and self.identity_complete


def _normalize_pattern(pattern: str) -> str:
    return pattern.replace("\\", "/").strip()


def _is_excluded(locator: str, patterns: Iterable[str]) -> bool:
    for raw in patterns:
        pattern = _normalize_pattern(raw)
        if not pattern:
            continue
        if fnmatch.fnmatchcase(locator, pattern):
            return True
        if pattern.endswith("/**"):
            prefix = pattern[:-3].rstrip("/")
            if locator == prefix or locator.startswith(prefix + "/"):
                return True
    return False


def _hash_file(path: Path, max_bytes: int) -> tuple[str | None, int, bool]:
    """Hash at most max_bytes; report whether content exceeded the live limit."""
    digest = hashlib.sha256()
    consumed = 0
    with path.open("rb") as stream:
        while consumed < max_bytes:
            chunk = stream.read(min(1024 * 1024, max_bytes - consumed))
            if not chunk:
                return "sha256:" + digest.hexdigest(), consumed, False
            digest.update(chunk)
            consumed += len(chunk)
        if stream.read(1):
            return None, consumed, True
    return "sha256:" + digest.hexdigest(), consumed, False


def _symlink_scope(root: Path, path: Path) -> tuple[str, Path | None]:
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        return "unresolved", None
    try:
        resolved.relative_to(root)
    except ValueError:
        return "external", resolved
    return "internal", resolved


def build_inventory(config: ScanConfig) -> InventoryResult:
    """Inventory a directory deterministically without executing target content."""
    root_input = Path(config.root)
    if not root_input.exists():
        raise SourceError(f"Source path does not exist: {root_input}")
    try:
        root = root_input.resolve(strict=True)
    except OSError as error:
        raise SourceError(f"Cannot resolve source path: {root_input}: {error}") from error
    if not root.is_dir():
        raise SourceError(f"Scan root must be a directory in v0.2: {root_input}")
    if config.max_file_bytes < 0 or config.max_total_bytes < 0:
        raise ValueError("Resource ceilings must be non-negative")

    artifacts: list[InventoryArtifact] = []
    warnings: list[str] = []
    limits: list[str] = []
    discovery_complete = True
    identity_complete = True
    total_hashed = 0
    artifact_ids: set[str] = set()
    followed_directories: set[Path] = {root}

    def add_artifact(artifact: InventoryArtifact) -> None:
        if artifact.id in artifact_ids:
            raise ValueError(f"Artifact ID collision after locator normalization: {artifact.locator}")
        artifact_ids.add(artifact.id)
        artifacts.append(artifact)

    def walk(directory: Path) -> None:
        nonlocal discovery_complete, identity_complete, total_hashed
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as error:
            discovery_complete = False
            warnings.append(f"Cannot enumerate {normalize_locator(root, directory)}: {error}")
            return

        for entry in entries:
            path = Path(entry.path)
            try:
                locator = normalize_locator(root, path)
            except ValueError as error:
                discovery_complete = False
                warnings.append(str(error))
                continue

            excluded = _is_excluded(locator, config.excludes)
            try:
                metadata = path.lstat()
            except OSError as error:
                discovery_complete = False
                identity_complete = False
                add_artifact(InventoryArtifact(
                    id=artifact_id(locator), locator=locator, display_name=entry.name,
                    path_kind="unknown", size_bytes=0,
                    content_identity="unreadable:lstat-failed", reason=str(error),
                ))
                continue

            mode = metadata.st_mode
            if stat.S_ISLNK(mode):
                try:
                    raw_target = os.readlink(path)
                except OSError as error:
                    raw_target = ""
                    scope, resolved = "unresolved", None
                    identity_complete = False
                    warnings.append(f"Cannot read symlink target for {locator}: {error}")
                else:
                    scope, resolved = _symlink_scope(root, path)
                identity = "symlink-target:" + sha256_bytes(
                    raw_target.encode("utf-8", errors="surrogatepass")
                ).split(":", 1)[1]
                add_artifact(InventoryArtifact(
                    id=artifact_id(locator), locator=locator, display_name=entry.name,
                    path_kind="symlink", size_bytes=0, content_identity=identity,
                    symlink_target=raw_target, symlink_scope=scope, excluded=excluded,
                    reason="excluded by configuration" if excluded else "",
                ))
                if excluded or not config.follow_internal_links or scope != "internal" or resolved is None:
                    continue
                if resolved.is_dir() and resolved not in followed_directories:
                    followed_directories.add(resolved)
                    walk(path)
                continue

            if stat.S_ISDIR(mode):
                add_artifact(InventoryArtifact(
                    id=artifact_id(locator), locator=locator, display_name=entry.name,
                    path_kind="directory", size_bytes=0,
                    content_identity="directory", excluded=excluded,
                    reason="excluded by configuration" if excluded else "",
                ))
                if not excluded:
                    walk(path)
                continue

            if excluded:
                add_artifact(InventoryArtifact(
                    id=artifact_id(locator), locator=locator, display_name=entry.name,
                    path_kind="file" if stat.S_ISREG(mode) else "special",
                    size_bytes=metadata.st_size if stat.S_ISREG(mode) else 0,
                    content_identity="excluded:by-pattern", excluded=True,
                    reason="excluded by configuration",
                ))
                continue

            if not stat.S_ISREG(mode):
                identity_complete = False
                add_artifact(InventoryArtifact(
                    id=artifact_id(locator), locator=locator, display_name=entry.name,
                    path_kind="special", size_bytes=0,
                    content_identity="unhashed:special-file",
                    reason="special filesystem object is not read",
                ))
                continue

            size = metadata.st_size
            if size > config.max_file_bytes:
                identity_complete = False
                limit = f"max_file_bytes:{locator}"
                if limit not in limits:
                    limits.append(limit)
                add_artifact(InventoryArtifact(
                    id=artifact_id(locator), locator=locator, display_name=entry.name,
                    path_kind="file", size_bytes=size,
                    content_identity="unhashed:max-file-bytes",
                    reason=f"file exceeds max_file_bytes={config.max_file_bytes}",
                ))
                continue

            if total_hashed + size > config.max_total_bytes:
                identity_complete = False
                limit = "max_total_bytes"
                if limit not in limits:
                    limits.append(limit)
                add_artifact(InventoryArtifact(
                    id=artifact_id(locator), locator=locator, display_name=entry.name,
                    path_kind="file", size_bytes=size,
                    content_identity="unhashed:max-total-bytes",
                    reason=f"hashing would exceed max_total_bytes={config.max_total_bytes}",
                ))
                continue

            live_budget = min(config.max_file_bytes, config.max_total_bytes - total_hashed)
            try:
                identity, consumed, exceeded = _hash_file(path, live_budget)
            except OSError as error:
                identity_complete = False
                identity = "unreadable:hash-failed"
                warnings.append(f"Cannot hash {locator}: {error}")
                reason = str(error)
            else:
                if exceeded or identity is None:
                    identity_complete = False
                    total_hashed += consumed
                    if live_budget == config.max_total_bytes - (total_hashed - consumed):
                        limit = "max_total_bytes"
                        identity = "unhashed:max-total-bytes"
                        reason = f"file changed or grew beyond remaining max_total_bytes={config.max_total_bytes}"
                    else:
                        limit = f"max_file_bytes:{locator}"
                        identity = "unhashed:max-file-bytes"
                        reason = f"file changed or grew beyond max_file_bytes={config.max_file_bytes}"
                    if limit not in limits:
                        limits.append(limit)
                else:
                    total_hashed += consumed
                    reason = ""
            add_artifact(InventoryArtifact(
                id=artifact_id(locator), locator=locator, display_name=entry.name,
                path_kind="file", size_bytes=size, content_identity=identity,
                reason=reason,
            ))

    walk(root)
    artifacts.sort(key=lambda item: item.locator)
    return InventoryResult(
        root=root,
        artifacts=tuple(artifacts),
        discovery_complete=discovery_complete,
        identity_complete=identity_complete,
        total_hashed_bytes=total_hashed,
        resource_limits_hit=tuple(sorted(limits)),
        warnings=tuple(warnings),
    )
