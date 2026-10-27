"""Read-only Git provenance without traversing or hashing Git object storage."""

from __future__ import annotations

import configparser
from dataclasses import dataclass
from pathlib import Path
import re
from urllib.parse import urlsplit, urlunsplit


_HEX_COMMIT = re.compile(r"^[0-9a-fA-F]{40,64}$")


@dataclass(frozen=True)
class GitProvenance:
    detected: bool
    head: str | None = None
    branch: str | None = None
    commit: str | None = None
    working_tree_status: str = "not_assessed"
    remotes: tuple[tuple[str, str], ...] = ()
    limitations: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "detected": self.detected,
            "head": self.head,
            "branch": self.branch,
            "commit": self.commit,
            "working_tree_status": self.working_tree_status,
            "remotes": [{"name": name, "url": url} for name, url in self.remotes],
            "limitations": list(self.limitations),
        }


def _bounded_text(path: Path, limit: int = 64_000) -> str | None:
    try:
        if not path.is_file() or path.stat().st_size > limit:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _sanitize_remote(value: str) -> str:
    """Remove URL credentials/query/fragment while retaining repository identity."""
    value = value.strip()
    if not value:
        return ""
    if "://" not in value:
        # SCP-style remotes commonly use user@host:path. Repository identity does
        # not require the username, and stripping it avoids retaining token-like
        # usernames from unusual credentialed remotes.
        sanitized = value.split("?", 1)[0].split("#", 1)[0]
        if "@" in sanitized:
            sanitized = sanitized.split("@", 1)[1]
        return sanitized
    try:
        parts = urlsplit(value)
    except ValueError:
        return "[redacted-invalid-remote]"
    hostname = parts.hostname or ""
    try:
        port = parts.port
    except ValueError:
        return "[redacted-invalid-remote]"
    if port is not None:
        hostname += f":{port}"
    return urlunsplit((parts.scheme, hostname, parts.path, "", ""))


def _resolve_git_dir(root: Path) -> tuple[Path | None, list[str]]:
    marker = root / ".git"
    limitations: list[str] = []
    if marker.is_dir():
        try:
            candidate = marker.resolve(strict=True)
            candidate.relative_to(root.resolve(strict=True))
        except (OSError, ValueError):
            limitations.append("Git metadata directory resolves outside the declared scan root and was not followed")
            return None, limitations
        return candidate, limitations
    if marker.is_file():
        text = _bounded_text(marker, 4096)
        if text is None or not text.lower().startswith("gitdir:"):
            limitations.append("Git indirection file could not be read safely")
            return None, limitations
        raw = text.split(":", 1)[1].strip()
        candidate = (root / raw).resolve(strict=False) if not Path(raw).is_absolute() else Path(raw).resolve(strict=False)
        try:
            candidate.relative_to(root.resolve(strict=True))
        except (OSError, ValueError):
            limitations.append("Git metadata directory is outside the declared scan root and was not followed")
            return None, limitations
        return candidate, limitations
    return None, limitations


def _commit_for_ref(git_dir: Path, ref: str) -> str | None:
    loose = _bounded_text(git_dir / Path(*ref.split("/")), 4096)
    if loose:
        candidate = loose.strip().splitlines()[0]
        if _HEX_COMMIT.fullmatch(candidate):
            return candidate.lower()
    packed = _bounded_text(git_dir / "packed-refs", 2_000_000)
    if packed:
        for line in packed.splitlines():
            if not line or line.startswith(("#", "^")):
                continue
            try:
                commit, packed_ref = line.split(" ", 1)
            except ValueError:
                continue
            if packed_ref.strip() == ref and _HEX_COMMIT.fullmatch(commit):
                return commit.lower()
    return None


def _read_remotes(git_dir: Path) -> tuple[tuple[str, str], ...]:
    text = _bounded_text(git_dir / "config", 1_000_000)
    if text is None:
        return ()
    parser = configparser.RawConfigParser(interpolation=None, strict=False)
    try:
        parser.read_string(text)
    except configparser.Error:
        return ()
    rows: list[tuple[str, str]] = []
    for section in parser.sections():
        match = re.fullmatch(r'remote\s+"(.+)"', section)
        if not match or not parser.has_option(section, "url"):
            continue
        sanitized = _sanitize_remote(parser.get(section, "url", raw=True))
        if sanitized:
            rows.append((match.group(1), sanitized))
    return tuple(sorted(rows))


def inspect_git_provenance(root: str | Path) -> GitProvenance:
    """Return bounded repository identity without invoking Git or reading object packs."""
    root_path = Path(root).resolve(strict=True)
    marker = root_path / ".git"
    if not marker.exists():
        return GitProvenance(detected=False)

    git_dir, limitations = _resolve_git_dir(root_path)
    if git_dir is None:
        return GitProvenance(detected=True, limitations=tuple(limitations))

    head_text = _bounded_text(git_dir / "HEAD", 4096)
    if not head_text:
        limitations.append("Git HEAD could not be read")
        return GitProvenance(
            detected=True,
            remotes=_read_remotes(git_dir),
            limitations=tuple(limitations),
        )

    head = head_text.strip().splitlines()[0]
    branch: str | None = None
    commit: str | None = None
    if head.startswith("ref:"):
        ref = head.split(":", 1)[1].strip()
        if ref.startswith("refs/heads/"):
            branch = ref[len("refs/heads/"):]
        commit = _commit_for_ref(git_dir, ref)
    elif _HEX_COMMIT.fullmatch(head):
        commit = head.lower()

    limitations.append(
        "Working-tree clean/dirty status is not assessed because Scan does not invoke repository hooks or target-configured Git helpers"
    )
    return GitProvenance(
        detected=True,
        head=head,
        branch=branch,
        commit=commit,
        remotes=_read_remotes(git_dir),
        limitations=tuple(limitations),
    )
