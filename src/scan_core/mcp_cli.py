"""Portable CLI helpers for Scan's optional local MCP bridge."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from importlib import metadata
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
from typing import Any

from .mcp_server import MCPUnavailableError, _state, create_server
from .version import __version__

_HOSTS = ("codex", "claude-desktop", "claude-code", "cursor", "vscode")
_REDACTION_LEVELS = ("none", "standard", "strict")


@dataclass(frozen=True)
class MCPDoctorCheck:
    id: str
    status: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {"id": self.id, "status": self.status, "message": self.message}


@dataclass(frozen=True)
class MCPDoctorResult:
    scan_version: str
    overall: str
    root: str | None
    mcp_version: str | None
    launch: dict[str, Any] | None
    checks: tuple[MCPDoctorCheck, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "scan_version": self.scan_version,
            "overall": self.overall,
            "root": self.root,
            "mcp_version": self.mcp_version,
            "launch": self.launch,
            "checks": [check.as_dict() for check in self.checks],
        }


def _check(status: str, ident: str, message: str) -> MCPDoctorCheck:
    if status not in {"pass", "warn", "fail"}:
        raise ValueError(f"invalid doctor status: {status}")
    return MCPDoctorCheck(id=ident, status=status, message=message)


def _overall(checks: list[MCPDoctorCheck]) -> str:
    if any(check.status == "fail" for check in checks):
        return "fail"
    if any(check.status == "warn" for check in checks):
        return "warn"
    return "pass"


def _resolve_root(path: str | Path) -> Path:
    root = Path(path).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Scan MCP root must be a directory")
    return root


def _server_args(
    root: Path,
    *,
    redaction_level: str,
    sensitive_paths: tuple[str, ...],
) -> list[str]:
    if redaction_level not in _REDACTION_LEVELS:
        raise ValueError("redaction_level must be none, standard, or strict")
    args = ["-m", "scan_core.mcp_server", str(root), "--redact", redaction_level]
    for pattern in sensitive_paths:
        if not pattern:
            raise ValueError("sensitive-path patterns must be nonempty")
        args.extend(("--sensitive-path", pattern))
    return args


def build_launch_spec(
    path: str | Path = ".",
    *,
    redaction_level: str = "standard",
    sensitive_paths: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Return a host-independent stdio launch specification using absolute paths."""
    root = _resolve_root(path)
    executable = Path(sys.executable).resolve(strict=True)
    return {
        "type": "stdio",
        "command": str(executable),
        "args": _server_args(
            root,
            redaction_level=redaction_level,
            sensitive_paths=sensitive_paths,
        ),
        "cwd": str(root),
    }


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _toml_array(values: list[str]) -> str:
    return "[" + ", ".join(_toml_string(value) for value in values) + "]"


def _shell_join(tokens: list[str]) -> str:
    return subprocess.list2cmdline(tokens) if os.name == "nt" else shlex.join(tokens)


def render_host_config(
    host: str,
    path: str | Path = ".",
    *,
    name: str = "scan",
    redaction_level: str = "standard",
    sensitive_paths: tuple[str, ...] = (),
) -> str:
    """Render a copy-paste configuration for a supported local stdio MCP host."""
    if host not in _HOSTS:
        raise ValueError(f"unsupported MCP host {host!r}; choose {', '.join(_HOSTS)}")
    if not name or any(character.isspace() for character in name):
        raise ValueError("server name must be nonempty and contain no whitespace")
    spec = build_launch_spec(
        path,
        redaction_level=redaction_level,
        sensitive_paths=sensitive_paths,
    )
    command = spec["command"]
    args = spec["args"]

    if host == "codex":
        return "\n".join((
            f"[mcp_servers.{name}]",
            f"command = {_toml_string(command)}",
            f"args = {_toml_array(args)}",
        ))

    if host in {"claude-desktop", "cursor"}:
        payload = {
            "mcpServers": {
                name: {
                    "command": command,
                    "args": args,
                }
            }
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)

    if host == "vscode":
        payload = {
            "servers": {
                name: {
                    "type": "stdio",
                    "command": command,
                    "args": args,
                }
            }
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)

    return _shell_join(["claude", "mcp", "add", name, "--", command, *args])


def render_all_host_configs(
    path: str | Path = ".",
    *,
    name: str = "scan",
    redaction_level: str = "standard",
    sensitive_paths: tuple[str, ...] = (),
) -> str:
    sections: list[str] = []
    for host in _HOSTS:
        sections.append(f"### {host}\n" + render_host_config(
            host,
            path,
            name=name,
            redaction_level=redaction_level,
            sensitive_paths=sensitive_paths,
        ))
    return "\n\n".join(sections)


def run_mcp_doctor(
    path: str | Path = ".",
    *,
    redaction_level: str = "standard",
    sensitive_paths: tuple[str, ...] = (),
) -> MCPDoctorResult:
    """Validate local MCP readiness without starting a long-lived server or writing target output."""
    checks: list[MCPDoctorCheck] = []
    python_supported = sys.version_info >= (3, 11)
    checks.append(_check(
        "pass" if python_supported else "fail",
        "python-version",
        f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro} "
        + ("supported" if python_supported else "unsupported; Scan requires Python 3.11+"),
    ))
    checks.append(_check("pass", "scan-version", f"Scan {__version__} installed"))

    mcp_version: str | None = None
    try:
        mcp_version = metadata.version("mcp")
    except metadata.PackageNotFoundError:
        checks.append(_check("fail", "mcp-sdk", "MCP SDK not installed; install scan-skill[mcp]"))
    else:
        try:
            major = int(mcp_version.split(".", 1)[0])
        except ValueError:
            major = -1
        checks.append(_check(
            "pass" if major == 2 else "fail",
            "mcp-sdk",
            f"MCP SDK {mcp_version} installed" if major == 2 else f"MCP SDK {mcp_version} is outside Scan's supported v2 line",
        ))

    root: Path | None = None
    try:
        root = _resolve_root(path)
    except (OSError, ValueError) as error:
        checks.append(_check("fail", "project-root", f"Project root unavailable: {error}"))
    else:
        checks.append(_check("pass", "project-root", "Project root exists and is a readable directory"))

    launch: dict[str, Any] | None = None
    if root is not None:
        try:
            launch = build_launch_spec(
                root,
                redaction_level=redaction_level,
                sensitive_paths=sensitive_paths,
            )
        except (OSError, ValueError) as error:
            checks.append(_check("fail", "launcher", f"Portable launcher could not be built: {error}"))
        else:
            command = Path(launch["command"])
            ok = command.is_absolute() and command.is_file()
            checks.append(_check(
                "pass" if ok else "fail",
                "launcher",
                "Absolute Python launcher available" if ok else "Python launcher is not an absolute executable file",
            ))

        before_scan_dir = (root / ".scan").exists()
        try:
            state = _state(
                root,
                mode="deep",
                redaction_level=redaction_level,
                sensitive_paths=sensitive_paths,
            )
        except Exception as error:
            checks.append(_check("fail", "core-snapshot", f"Read-only Scan snapshot failed: {error.__class__.__name__}: {error}"))
        else:
            safe = (
                state.get("schema_version") == "1.4"
                and state.get("run", {}).get("target_executed") is False
                and state.get("extensions", {}).get("privacy_egress_preview", {}).get("network_action") == "none"
            )
            checks.append(_check(
                "pass" if safe else "fail",
                "core-snapshot",
                "Canonical Scan 1.4 snapshot built with no target execution or network action"
                if safe else "Snapshot did not preserve the expected static/offline contract",
            ))
        after_scan_dir = (root / ".scan").exists()
        unchanged_output_boundary = before_scan_dir == after_scan_dir
        checks.append(_check(
            "pass" if unchanged_output_boundary else "fail",
            "target-output",
            "Doctor created no .scan output directory" if unchanged_output_boundary else "Doctor changed target .scan output presence",
        ))

        if mcp_version is not None and mcp_version.split(".", 1)[0] == "2":
            try:
                create_server(
                    root,
                    redaction_level=redaction_level,
                    sensitive_paths=sensitive_paths,
                )
            except (MCPUnavailableError, OSError, ValueError, RuntimeError) as error:
                checks.append(_check("fail", "server-factory", f"MCP server initialization failed: {error}"))
            else:
                checks.append(_check("pass", "server-factory", "Read-only stdio MCP server initializes successfully"))

    return MCPDoctorResult(
        scan_version=__version__,
        overall=_overall(checks),
        root=str(root) if root is not None else None,
        mcp_version=mcp_version,
        launch=launch,
        checks=tuple(checks),
    )


def format_mcp_doctor(result: MCPDoctorResult) -> str:
    lines = [f"Scan MCP Doctor {result.scan_version}", ""]
    for check in result.checks:
        lines.append(f"{check.status.upper():4}  {check.id:<16} {check.message}")
    if result.launch is not None:
        lines.extend((
            "",
            "Portable launcher:",
            f"  command: {result.launch['command']}",
            f"  args: {_shell_join(result.launch['args'])}",
        ))
    lines.extend(("", f"Result: {result.overall.upper()}"))
    return "\n".join(lines)


def _add_policy_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--redact",
        choices=_REDACTION_LEVELS,
        default="standard",
        help="Redaction level for artifact text returned to the MCP host",
    )
    parser.add_argument(
        "--sensitive-path",
        action="append",
        default=[],
        help="Project-relative glob to omit from artifact-text reads; repeatable",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scan-mcp",
        description="Run, diagnose, or configure Scan's optional local MCP bridge",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    serve = commands.add_parser("serve", help="Run the local read-only MCP server over stdio")
    serve.add_argument("path", nargs="?", default=".", help="Authorized project root")
    _add_policy_arguments(serve)

    doctor = commands.add_parser("doctor", help="Check installed MCP readiness without starting a host")
    doctor.add_argument("path", nargs="?", default=".", help="Authorized project root")
    doctor.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    _add_policy_arguments(doctor)

    config = commands.add_parser("config", help="Generate copy-paste configuration for a supported MCP host")
    config.add_argument("host", nargs="?", choices=(*_HOSTS, "all"), default="all")
    config.add_argument("path", nargs="?", default=".", help="Authorized project root")
    config.add_argument("--name", default="scan", help="Server name used by the host")
    _add_policy_arguments(config)
    return parser


def _normalize_argv(argv: list[str]) -> list[str]:
    if not argv:
        return ["serve"]
    if argv[0] in {"serve", "doctor", "config", "-h", "--help"}:
        return argv
    return ["serve", *argv]


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    args = _parser().parse_args(_normalize_argv(raw))
    sensitive_paths = tuple(args.sensitive_path)

    if args.command == "serve":
        try:
            server = create_server(
                Path(args.path),
                redaction_level=args.redact,
                sensitive_paths=sensitive_paths,
            )
        except (MCPUnavailableError, OSError, ValueError) as error:
            raise SystemExit(str(error)) from error
        server.run()
        return 0

    if args.command == "doctor":
        result = run_mcp_doctor(
            args.path,
            redaction_level=args.redact,
            sensitive_paths=sensitive_paths,
        )
        if args.json:
            print(json.dumps(result.as_dict(), ensure_ascii=False, sort_keys=True))
        else:
            print(format_mcp_doctor(result))
        return 1 if result.overall == "fail" else 0

    try:
        text = (
            render_all_host_configs(
                args.path,
                name=args.name,
                redaction_level=args.redact,
                sensitive_paths=sensitive_paths,
            )
            if args.host == "all"
            else render_host_config(
                args.host,
                args.path,
                name=args.name,
                redaction_level=args.redact,
                sensitive_paths=sensitive_paths,
            )
        )
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
    print(text)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
