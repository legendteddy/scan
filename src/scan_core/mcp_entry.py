"""Installed console entry point for the full Scan MCP application."""
from __future__ import annotations

from pathlib import Path

from . import mcp_cli as _cli
from .mcp_app import create_server as _create_full_server


def _full_server_args(
    root: Path,
    *,
    redaction_level: str,
    sensitive_paths: tuple[str, ...],
) -> list[str]:
    if redaction_level not in _cli._REDACTION_LEVELS:
        raise ValueError("redaction_level must be none, standard, or strict")
    args = ["-m", "scan_core.mcp_app", str(root), "--redact", redaction_level]
    for pattern in sensitive_paths:
        if not pattern:
            raise ValueError("sensitive-path patterns must be nonempty")
        args.extend(("--sensitive-path", pattern))
    return args


def main(argv: list[str] | None = None) -> int:
    # Reuse the already-tested portable CLI surface while swapping only the
    # installed server factory/launcher to the full Core+semantic application.
    old_server = _cli.create_server
    old_args = _cli._server_args
    _cli.create_server = _create_full_server
    _cli._server_args = _full_server_args
    try:
        return _cli.main(argv)
    finally:
        _cli.create_server = old_server
        _cli._server_args = old_args


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
