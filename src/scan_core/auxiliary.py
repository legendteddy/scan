"""Bounded auxiliary reads within an explicitly authorized directory.

Metadata links/reparse points are rejected, including internal links. Git worktree
indirection is resolved separately and never grants access to arbitrary parents.
"""
from __future__ import annotations

import os
from pathlib import Path, PureWindowsPath
import stat
from contextlib import contextmanager
from typing import Iterator


class AuxiliaryReadError(ValueError):
    """Metadata was missing, oversized, or outside the authorized boundary."""


def is_link_or_reparse(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & 0x400
    )


def auxiliary_path(root: Path, relative: str | Path) -> Path:
    """Validate lexical scope and every component before a metadata operation."""
    raw = str(relative).replace("\\", "/")
    windows = PureWindowsPath(raw)
    if not raw or Path(raw).is_absolute() or windows.drive or windows.root or ".." in raw.split("/"):
        raise AuxiliaryReadError("absolute or parent metadata traversal rejected")
    # Colons can name Windows alternate data streams even in a relative path.
    if ":" in raw or "\x00" in raw:
        raise AuxiliaryReadError("invalid metadata path")
    try:
        boundary = root.absolute()
        if is_link_or_reparse(boundary.lstat()):
            raise AuxiliaryReadError("metadata root is a link/reparse point")
        candidate = boundary
        for part in Path(raw).parts:
            candidate /= part
            if is_link_or_reparse(candidate.lstat()):
                raise AuxiliaryReadError("metadata link/reparse point rejected")
        candidate.resolve(strict=True).relative_to(boundary.resolve(strict=True))
        return candidate
    except (OSError, ValueError, RuntimeError) as error:
        if isinstance(error, AuxiliaryReadError):
            raise
        raise AuxiliaryReadError("metadata missing or outside authorized root") from error


@contextmanager
def _open_metadata(root: Path, path: Path, flags: int) -> Iterator[int]:
    if os.name == 'nt':
        # Validate the opened handle's actual path BEFORE reading bytes. Checking
        # path.resolve() alone leaves a parent-junction replacement race.
        import ctypes
        import msvcrt
        descriptor = os.open(path, flags)
        try:
            get_path = ctypes.windll.kernel32.GetFinalPathNameByHandleW
            get_path.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
            get_path.restype = ctypes.c_uint32
            buffer = ctypes.create_unicode_buffer(32768)
            length = get_path(msvcrt.get_osfhandle(descriptor), buffer, len(buffer), 0)
            if not length or length >= len(buffer):
                raise AuxiliaryReadError('opened metadata path could not be verified')
            actual = buffer.value
            if actual.startswith('\\\\?\\UNC\\'):
                actual = '\\\\' + actual[8:]
            elif actual.startswith('\\\\?\\'):
                actual = actual[4:]
            if os.path.normcase(actual) != os.path.normcase(str(path)):
                raise AuxiliaryReadError('opened metadata escaped its authorized path')
            yield descriptor
        finally:
            os.close(descriptor)
        return

    # POSIX traverses from a pinned directory handle without following links in
    # any child component, even when an attacker replaces a parent concurrently.
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open(root.absolute(), directory_flags)
    try:
        parts = path.relative_to(root.absolute()).parts
        for part in parts[:-1]:
            child = os.open(part, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(parts[-1], flags | os.O_NOFOLLOW, dir_fd=directory)
        try:
            yield descriptor
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)


def read_auxiliary(root: Path, relative: str | Path, *, max_bytes: int) -> bytes:
    """Read at most max_bytes + one sentinel; never use an unbounded read."""
    if max_bytes < 0:
        raise ValueError("max_bytes must be non-negative")
    path = auxiliary_path(root, relative)
    try:
        before = path.lstat()
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        with _open_metadata(root, path, flags) as descriptor, os.fdopen(descriptor, "rb", closefd=False) as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise AuxiliaryReadError("metadata changed or is not a regular file")
            if opened.st_size > max_bytes:
                raise AuxiliaryReadError("metadata exceeds byte limit")
            data = stream.read(max_bytes + 1)
        auxiliary_path(root, relative)
        if len(data) > max_bytes:
            raise AuxiliaryReadError("metadata exceeds byte limit")
        return data
    except OSError as error:
        raise AuxiliaryReadError("metadata could not be read safely") from error


def auxiliary_text(root: Path, relative: str | Path, *, max_bytes: int) -> str | None:
    try:
        return read_auxiliary(root, relative, max_bytes=max_bytes).decode("utf-8", errors="replace")
    except AuxiliaryReadError:
        return None
