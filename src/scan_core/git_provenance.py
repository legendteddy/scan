"""Read-only Git provenance without traversing or hashing Git object storage."""

from __future__ import annotations

import configparser
from dataclasses import dataclass
from pathlib import Path
import re
import os
from urllib.parse import urlsplit, urlunsplit

from .auxiliary import AuxiliaryReadError, auxiliary_path, auxiliary_text


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


def _authorized_directory(root: Path, candidate: Path, allowed: tuple[Path, ...]) -> Path | None:
    # In-project indirection is allowed; external roots must match exactly an
    # explicit invocation grant, never a grant to a parent containing other data.
    try:
        relative = candidate.absolute().relative_to(root)
        return auxiliary_path(root, relative)
    except (ValueError, AuxiliaryReadError):
        pass
    for grant in allowed:
        try:
            # The invocation authorizes this exact directory, including normal
            # OS aliases in ancestors (e.g. macOS /var -> /private/var). Pin its
            # canonical target; auxiliary reads still reject links below it.
            boundary = grant.resolve(strict=True)
            if boundary.is_dir() and candidate.resolve(strict=True) == boundary:
                return boundary
        except (OSError, ValueError, RuntimeError):
            continue
    return None


def _resolve_git_dir(root: Path, allowed: tuple[Path, ...] = ()) -> tuple[Path | None, list[str]]:
    limitations: list[str] = []
    try:
        marker = auxiliary_path(root, ".git")
    except AuxiliaryReadError:
        return None, ["Git metadata marker could not be read within the declared scan root"]
    if marker.is_dir():
        return marker, limitations
    text = auxiliary_text(root, ".git", max_bytes=4096)
    if text is None or not text.lower().startswith("gitdir:"):
        return None, ["Git indirection file could not be read safely"]
    raw = text.split(":", 1)[1].strip()
    # Worktree pointer paths may legitimately contain '..'; normalize only this
    # pointer, then require a contained path or an exact invocation grant.
    candidate = Path(raw) if Path(raw).is_absolute() else root / raw
    candidate = Path(os.path.abspath(candidate))
    authorized = _authorized_directory(root, candidate, allowed)
    if authorized is None or not authorized.is_dir():
        return None, ["Git metadata directory is outside the authorized scope or unsafe; not followed"]
    if not authorized.is_relative_to(root):
        limitations.append("External Git metadata explicitly authorized for bounded HEAD/ref/config reads only")
    return authorized, limitations


def _commit_for_ref(git_dir: Path, ref: str) -> str | None:
    loose = auxiliary_text(git_dir, ref, max_bytes=4096)
    if loose and loose.strip():
        candidate = loose.strip().splitlines()[0]
        if _HEX_COMMIT.fullmatch(candidate):
            return candidate.lower()
    packed = auxiliary_text(git_dir, "packed-refs", max_bytes=2_000_000)
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
    text = auxiliary_text(git_dir, "config", max_bytes=1_000_000)
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


def inspect_git_provenance(root: str | Path, *, metadata_roots: tuple[Path, ...] = ()) -> GitProvenance:
    """Return bounded repository identity without invoking Git or reading object packs."""
    root_path = Path(root).resolve(strict=True)
    marker = root_path / ".git"
    if not marker.exists():
        return GitProvenance(detected=False)

    git_dir, limitations = _resolve_git_dir(root_path, metadata_roots)
    if git_dir is None:
        return GitProvenance(detected=True, limitations=tuple(limitations))

    common_dir = git_dir
    common = auxiliary_text(git_dir, "commondir", max_bytes=4096)
    if common is not None:
        raw_common = Path(common.strip())
        candidate = Path(os.path.abspath(git_dir / raw_common))
        authorized = _authorized_directory(root_path, candidate, metadata_roots)
        if authorized is None or not authorized.is_dir():
            limitations.append("Git common metadata directory is outside the authorized scope or unsafe; not followed")
        else:
            common_dir = authorized
            if not authorized.is_relative_to(root_path):
                limitations.append("External Git common metadata explicitly authorized for bounded ref/config reads only")

    head_text = auxiliary_text(git_dir, "HEAD", max_bytes=4096)
    if not head_text or not head_text.strip():
        limitations.append("Git HEAD could not be read")
        return GitProvenance(
            detected=True,
            remotes=_read_remotes(common_dir),
            limitations=tuple(limitations),
        )

    head = head_text.strip().splitlines()[0]
    branch: str | None = None
    commit: str | None = None
    if head.startswith("ref:"):
        ref = head.split(":", 1)[1].strip()
        if ref.startswith("refs/heads/"):
            branch = ref[len("refs/heads/"):]
        if not ref.startswith("refs/") or ".." in ref.replace("\\", "/").split("/") or "\\" in ref or ":" in ref:
            limitations.append("Unsafe Git HEAD reference rejected")
            head = None
            branch = None
        else:
            commit = _commit_for_ref(common_dir, ref)
            if commit is None:
                limitations.append("Git reference unavailable, unsafe, invalid or beyond metadata byte limits")
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
        remotes=_read_remotes(common_dir),
        limitations=tuple(limitations),
    )
