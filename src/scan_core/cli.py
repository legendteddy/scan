"""Scan v0.2 command-line interface skeleton and stable exit codes."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .errors import (
    CommandError,
    CoverageThresholdError,
    ExitCode,
    PrivacyBlockedError,
    ResourceLimitError,
    SourceError,
    ValidationError,
)
from .validate import validate_path

UTILITY_COMMANDS = {"validate", "render", "bench", "schema", "egress"}


def _primary_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scan", description="Evidence-backed project inspection")
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--output", type=Path, default=Path(".scan/report.html"))
    parser.add_argument("--state", type=Path, default=Path(".scan/state.json"))
    parser.add_argument("--no-html", action="store_true")
    parser.add_argument("--privacy", choices=("offline", "local", "controlled-remote"), default="offline")
    parser.add_argument("--redact", choices=("none", "standard", "strict"), default="standard")
    parser.add_argument("--exclude", action="append", default=[])
    parser.add_argument("--max-file-bytes", type=int, default=5_000_000)
    parser.add_argument("--max-total-bytes", type=int, default=250_000_000)
    parser.add_argument("--follow-internal-links", action="store_true")
    parser.add_argument("--fail-on", choices=("PARTIAL", "ERROR"))
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--version", action="version", version=f"scan {__version__}")
    return parser


def _utility_parser(command: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=f"scan {command}")
    if command == "validate":
        parser.add_argument("path", type=Path)
    elif command == "render":
        parser.add_argument("state_json", type=Path)
        parser.add_argument("--output", type=Path, required=True)
    elif command == "bench":
        parser.add_argument("fixture", nargs="?")
    elif command == "schema":
        parser.add_argument("--version", choices=("1.2", "1.3"), default="1.3")
    elif command == "egress":
        parser.add_argument("path", nargs="?", type=Path, default=Path("."))
    return parser


def _run_utility(command: str, argv: Sequence[str]) -> int:
    args = _utility_parser(command).parse_args(list(argv))
    if command == "validate":
        if not args.path.exists():
            raise SourceError(f"Source path does not exist: {args.path}")
        validate_path(args.path)
        return int(ExitCode.OK)
    raise CommandError(f"'scan {command}' is reserved by the v0.2 contract but is not implemented in Slice 1")


def _run_primary(argv: Sequence[str]) -> int:
    args = _primary_parser().parse_args(list(argv))
    root = Path(args.path)
    if not root.exists():
        raise SourceError(f"Source path does not exist: {root}")
    raise CommandError("Project scanning is reserved for Slice 2; Slice 1 provides packaging and validation only")


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if args and args[0] in UTILITY_COMMANDS:
            return _run_utility(args[0], args[1:])
        return _run_primary(args)
    except CoverageThresholdError as error:
        print(f"scan: {error}", file=sys.stderr)
        return int(ExitCode.COVERAGE_THRESHOLD)
    except PrivacyBlockedError as error:
        print(f"scan: {error}", file=sys.stderr)
        return int(ExitCode.PRIVACY_BLOCKED)
    except ResourceLimitError as error:
        print(f"scan: {error}", file=sys.stderr)
        return int(ExitCode.RESOURCE_LIMIT)
    except SourceError as error:
        print(f"scan: {error}", file=sys.stderr)
        return int(ExitCode.SOURCE_ERROR)
    except (ValidationError, ValueError, KeyError, TypeError) as error:
        print(f"scan: validation failed: {error}", file=sys.stderr)
        return int(ExitCode.VALIDATION_FAILED)
    except CommandError as error:
        print(f"scan: {error}", file=sys.stderr)
        return int(ExitCode.COMMAND_ERROR)
    except OSError as error:
        print(f"scan: source error: {error}", file=sys.stderr)
        return int(ExitCode.SOURCE_ERROR)
    except Exception as error:  # pragma: no cover - final safety boundary
        print(f"scan: internal error: {error}", file=sys.stderr)
        return int(ExitCode.INTERNAL_ERROR)


if __name__ == "__main__":
    raise SystemExit(main())
