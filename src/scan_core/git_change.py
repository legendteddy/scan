"""Local-only Git changed-scope context for Scan v0.3.

This module never fetches or contacts remotes. Git output is advisory context only;
Scan's filesystem inventory remains the authoritative project accounting layer.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Iterable

from .errors import CommandError
from .privacy import path_is_sensitive


_HEX_COMMIT = re.compile(r"^[0-9a-fA-F]{40,64}$")


@dataclass(frozen=True)
class GitChangeScope:
    base_ref: str
    head_ref: str
    git_version: str
    added: tuple[str, ...] = ()
    modified: tuple[str, ...] = ()
    deleted: tuple[str, ...] = ()
    renamed: tuple[dict[str, str | None], ...] = ()
    copied: tuple[dict[str, str | None], ...] = ()
    untracked: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    def priority_paths(self) -> tuple[str, ...]:
        """Return current changed paths worth inspecting first, without implying coverage."""
        paths = set(self.added) | set(self.modified) | set(self.untracked)
        for row in (*self.renamed, *self.copied):
            destination = row.get("to")
            if isinstance(destination, str) and destination:
                paths.add(destination)
        return tuple(sorted(path for path in paths if path))

    def as_dict(self) -> dict[str, object]:
        return {
            "base_ref": self.base_ref,
            "head_ref": self.head_ref,
            "git_version": self.git_version,
            "added": list(self.added),
            "modified": list(self.modified),
            "deleted": list(self.deleted),
            "renamed": [dict(row) for row in self.renamed],
            "copied": [dict(row) for row in self.copied],
            "untracked": list(self.untracked),
            "priority_paths": list(self.priority_paths()),
            "limitations": list(self.limitations),
        }


def _safe_path(path: str, sensitive_patterns: Iterable[str]) -> str:
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if path_is_sensitive(normalized, sensitive_patterns):
        digest = hashlib.sha256(normalized.encode("utf-8", errors="surrogatepass")).hexdigest()[:20]
        return f"[REDACTED:path]/{digest}"
    return normalized


def _git_env() -> dict[str, str]:
    env = dict(os.environ)
    # Do not allow repository fsmonitor or optional locks to turn a read-only
    # change query into helper execution or working-tree mutation.
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _run_git(root: Path, executable: str, args: list[str]) -> bytes:
    command = [
        executable,
        "-c", "core.fsmonitor=false",
        "-c", "core.hooksPath=",
        "-c", "protocol.allow=never",
        *args,
    ]
    try:
        result = subprocess.run(
            command,
            cwd=root,
            env=_git_env(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            shell=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CommandError(f"Git changed scope failed: {error}") from error
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise CommandError("Git changed scope failed" + (f": {message}" if message else ""))
    return result.stdout


def _parse_name_status(data: bytes, sensitive_patterns: Iterable[str]) -> dict[str, list[object]]:
    tokens = data.decode("utf-8", errors="surrogateescape").split("\0")
    if tokens and tokens[-1] == "":
        tokens.pop()
    rows: dict[str, list[object]] = {
        "added": [], "modified": [], "deleted": [], "renamed": [], "copied": []
    }
    index = 0
    while index < len(tokens):
        status = tokens[index]
        index += 1
        if not status:
            continue
        code = status[0]
        if code in {"R", "C"}:
            if index + 1 >= len(tokens):
                raise CommandError("Git changed scope returned malformed rename/copy output")
            old_path = _safe_path(tokens[index], sensitive_patterns)
            new_path = _safe_path(tokens[index + 1], sensitive_patterns)
            index += 2
            rows["renamed" if code == "R" else "copied"].append({
                "from": old_path,
                "to": new_path,
                "similarity": status[1:] or None,
            })
            continue
        if index >= len(tokens):
            raise CommandError("Git changed scope returned malformed path output")
        path = _safe_path(tokens[index], sensitive_patterns)
        index += 1
        if code == "A":
            rows["added"].append(path)
        elif code == "M" or code == "T":
            rows["modified"].append(path)
        elif code == "D":
            rows["deleted"].append(path)
        else:
            # Keep uncommon Git statuses advisory rather than inventing a new
            # canonical category. Treat them as modified paths.
            rows["modified"].append(path)
    for key in ("added", "modified", "deleted"):
        rows[key] = sorted(set(rows[key]))
    for key in ("renamed", "copied"):
        rows[key] = sorted(rows[key], key=lambda row: (row["from"], row["to"]))
    return rows


def _unstaged_tracked_changes(
    root: Path,
    executable: str,
    sensitive_patterns: Iterable[str],
) -> tuple[set[str], set[str]]:
    """Detect unstaged tracked changes without asking Git to convert worktree content.

    ``git diff <tree>`` may feed worktree bytes through repository-configured
    clean/process filters. Instead, read the index's cached stat metadata and
    compare it with ``lstat``. A stat mismatch is deliberately conservative:
    touched-but-unchanged files may be reported as modified, while no target
    helper is executed merely to prove byte equality.
    """
    data = _run_git(root, executable, ["ls-files", "--debug", "-z", "--", "."])
    position = 0
    modified: set[str] = set()
    deleted: set[str] = set()
    while position < len(data):
        nul = data.find(b"\0", position)
        if nul < 0:
            raise CommandError("Git changed scope returned malformed index debug output")
        raw_path = data[position:nul]
        position = nul + 1
        if not raw_path:
            continue

        mtime_ns: int | None = None
        cached_size: int | None = None
        for _ in range(5):
            newline = data.find(b"\n", position)
            if newline < 0:
                line = data[position:]
                position = len(data)
            else:
                line = data[position:newline]
                position = newline + 1
            text = line.decode("utf-8", errors="replace").strip()
            if text.startswith("mtime:"):
                try:
                    seconds, nanoseconds = text.removeprefix("mtime:").strip().split(":", 1)
                    mtime_ns = int(seconds) * 1_000_000_000 + int(nanoseconds)
                except ValueError as error:
                    raise CommandError("Git changed scope returned malformed index mtime") from error
            elif text.startswith("size:"):
                try:
                    cached_size = int(text.removeprefix("size:").split("\t", 1)[0].strip())
                except ValueError as error:
                    raise CommandError("Git changed scope returned malformed index size") from error

        if mtime_ns is None or cached_size is None:
            raise CommandError("Git changed scope index metadata is incomplete")

        path = raw_path.decode("utf-8", errors="surrogateescape")
        safe_path = _safe_path(path, sensitive_patterns)
        worktree_path = root.joinpath(*path.split("/"))
        try:
            stat = os.lstat(worktree_path)
        except FileNotFoundError:
            deleted.add(safe_path)
            continue
        except OSError:
            modified.add(safe_path)
            continue
        if stat.st_mtime_ns != mtime_ns or stat.st_size != cached_size:
            modified.add(safe_path)
    return modified, deleted


def inspect_git_change_scope(
    root: str | Path,
    base_ref: str,
    *,
    sensitive_patterns: Iterable[str] = (),
) -> GitChangeScope:
    """Return local Git change context relative to base_ref without network access."""
    root_path = Path(root).resolve(strict=True)
    executable = shutil.which("git")
    if executable is None:
        raise CommandError("--changed-since requires a local Git executable")
    if not isinstance(base_ref, str) or not base_ref.strip():
        raise CommandError("--changed-since requires a nonempty local Git ref")
    base_ref = base_ref.strip()

    version = _run_git(root_path, executable, ["--version"]).decode("utf-8", errors="replace").strip()
    inside = _run_git(root_path, executable, ["rev-parse", "--is-inside-work-tree"]).decode("ascii", errors="replace").strip()
    if inside != "true":
        raise CommandError("--changed-since requires the scan root to be inside a Git work tree")

    # Resolve locally only. No fetch is attempted when the ref is absent. The
    # user-supplied ref is never passed to `git diff`; only the verified commit
    # object ID is used after this boundary, preventing option-like ref injection.
    base_commit = _run_git(
        root_path, executable, ["rev-parse", "--verify", "--end-of-options", f"{base_ref}^{{commit}}"]
    ).decode("ascii", errors="replace").strip()
    if not _HEX_COMMIT.fullmatch(base_commit):
        raise CommandError("Git changed scope resolved the base ref to an invalid commit ID")
    head_commit = _run_git(root_path, executable, ["rev-parse", "--verify", "HEAD^{commit}"]).decode("ascii", errors="replace").strip()
    if not _HEX_COMMIT.fullmatch(head_commit):
        raise CommandError("Git changed scope could not resolve HEAD to a valid commit ID")

    # Compare the base commit only to the Git index. This captures committed and
    # staged changes without asking Git to convert worktree content through
    # repository-configured clean/process filters.
    diff = _run_git(root_path, executable, [
        "diff", "--cached", "--relative", "--name-status", "-z", "--no-ext-diff", "--no-textconv",
        "--find-renames", "--find-copies-harder", base_commit.lower(), "--", ".",
    ])
    parsed = _parse_name_status(diff, sensitive_patterns)

    unstaged_modified, unstaged_deleted = _unstaged_tracked_changes(
        root_path, executable, sensitive_patterns,
    )
    added = set(parsed["added"])
    deleted = set(parsed["deleted"])
    rename_targets = {row["to"] for row in parsed["renamed"] if row.get("to")}
    copy_targets = {row["to"] for row in parsed["copied"] if row.get("to")}
    modified = set(parsed["modified"])
    modified.update(
        path for path in unstaged_modified
        if path not in added and path not in deleted and path not in rename_targets and path not in copy_targets
    )
    deleted.update(path for path in unstaged_deleted if path not in added)
    parsed["modified"] = sorted(modified - deleted)
    parsed["deleted"] = sorted(deleted)

    untracked_raw = _run_git(root_path, executable, [
        "ls-files", "--others", "--exclude-standard", "-z", "--", ".",
    ]).decode("utf-8", errors="surrogateescape").split("\0")
    untracked = sorted({
        _safe_path(path, sensitive_patterns)
        for path in untracked_raw
        if path
    })

    return GitChangeScope(
        base_ref=base_ref,
        head_ref="HEAD",
        git_version=version,
        added=tuple(parsed["added"]),
        modified=tuple(parsed["modified"]),
        deleted=tuple(parsed["deleted"]),
        renamed=tuple(parsed["renamed"]),
        copied=tuple(parsed["copied"]),
        untracked=tuple(untracked),
        limitations=(
            "Git change scope is advisory source-control context and does not replace Scan filesystem inventory",
            "Tracked categories combine a base-to-index comparison with conservative index-stat detection of unstaged worktree changes",
            "Unstaged stat detection may over-report touched-but-unchanged files and cannot guarantee detection of metadata-preserving edits",
            "Unstaged rename/copy inference is not performed; such changes may appear as deletion plus untracked content",
            "Ignored files are not enumerated by Git change scope and remain governed by Scan inventory/configuration",
            "Rename/copy detection does not alter Scan path-derived artifact identity or baseline delta categories",
            "priority_paths only consolidates current changed paths for semantic ordering; it is not a dependency, import or call graph",
            "No Git fetch or remote network operation was performed",
        ),
    )
