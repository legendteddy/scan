"""Installed Scan MCP application: deterministic Core plus bounded semantic continuation."""
from __future__ import annotations

import argparse
from pathlib import Path

from .mcp_semantic import install_semantic_tools
from .mcp_server import MCPUnavailableError, _REDACTION_LEVELS, _state, create_server as create_core_server


def create_server(
    root: Path,
    *,
    redaction_level: str = "standard",
    sensitive_paths: tuple[str, ...] = (),
):
    """Create the full installed Scan MCP server without changing the target project."""
    root = Path(root).resolve(strict=True)
    server = create_core_server(
        root,
        redaction_level=redaction_level,
        sensitive_paths=sensitive_paths,
    )

    # Semantic continuation deliberately re-establishes a fresh deterministic
    # snapshot when it checks workspace freshness. The Core server keeps its own
    # explicit snapshot cache for inventory pagination/read consistency.
    def current_semantic_state(mode: str) -> dict:
        return _state(
            root,
            mode=mode,
            redaction_level=redaction_level,
            sensitive_paths=sensitive_paths,
        )

    install_semantic_tools(
        server,
        root=root,
        current_state=current_semantic_state,
    )
    return server


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m scan_core.mcp_app",
        description="Run Scan's full local MCP application over stdio",
    )
    parser.add_argument("path", nargs="?", default=".", help="Authorized project root")
    parser.add_argument(
        "--redact",
        choices=sorted(_REDACTION_LEVELS),
        default="standard",
        help="Redaction level for artifact text returned to the MCP host",
    )
    parser.add_argument(
        "--sensitive-path",
        action="append",
        default=[],
        help="Project-relative glob to omit from artifact-text reads; repeatable",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        server = create_server(
            Path(args.path),
            redaction_level=args.redact,
            sensitive_paths=tuple(args.sensitive_path),
        )
    except (MCPUnavailableError, OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
    server.run()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
