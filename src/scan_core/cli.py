"""Scan v0.2 command-line interface skeleton and stable exit codes."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .config import ScanConfig
from .core import scan_project
from .inventory import build_inventory
from .privacy import build_egress_preview
from .version import __version__
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
    parser.add_argument("--sensitive-path", action="append", default=[])
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
        parser.add_argument("--privacy", choices=("offline", "local", "controlled-remote"), default="controlled-remote")
        parser.add_argument("--redact", choices=("none", "standard", "strict"), default="standard")
        parser.add_argument("--exclude", action="append", default=[])
        parser.add_argument("--sensitive-path", action="append", default=[])
        parser.add_argument("--max-file-bytes", type=int, default=5_000_000)
        parser.add_argument("--max-total-bytes", type=int, default=250_000_000)
        parser.add_argument("--follow-internal-links", action="store_true")
        parser.add_argument("--json", action="store_true")
    return parser


def _run_utility(command: str, argv: Sequence[str]) -> int:
    args = _utility_parser(command).parse_args(list(argv))
    if command == "validate":
        if not args.path.exists():
            raise SourceError(f"Source path does not exist: {args.path}")
        validate_path(args.path)
        return int(ExitCode.OK)
    if command == "egress":
        if not args.path.exists():
            raise SourceError(f"Source path does not exist: {args.path}")
        config = ScanConfig(
            root=args.path,
            privacy_mode=args.privacy,
            redaction_level=args.redact,
            excludes=tuple(args.exclude),
            sensitive_paths=tuple(args.sensitive_path),
            max_file_bytes=args.max_file_bytes,
            max_total_bytes=args.max_total_bytes,
            follow_internal_links=args.follow_internal_links,
        )
        preview = build_egress_preview(config, build_inventory(config))
        payload = preview.as_dict()
        if args.json:
            print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        else:
            print(f"files selected: {payload['files_selected']}")
            print(f"bytes selected: {payload['bytes_selected']}")
            print(f"files omitted by policy: {payload['files_omitted_by_policy']}")
            print(f"redaction count: {payload['redaction_count']}")
            print(f"sensitive paths omitted: {payload['sensitive_paths_omitted']}")
            print(f"privacy mode: {payload['privacy_mode']}")
            print("network action: none")
        return int(ExitCode.OK)
    raise CommandError(f"'scan {command}' is reserved by the v0.2 contract but is not implemented in this slice")


def _run_primary(argv: Sequence[str]) -> int:
    args = _primary_parser().parse_args(list(argv))
    root = Path(args.path)
    if not root.exists():
        raise SourceError(f"Source path does not exist: {root}")
    if not args.no_html:
        raise CommandError("HTML rendering is not implemented yet; use --no-html for canonical Scan 1.3 state output")

    config = ScanConfig(
        root=root,
        output_state=args.state,
        output_html=None,
        privacy_mode=args.privacy,
        redaction_level=args.redact,
        excludes=tuple(args.exclude),
        sensitive_paths=tuple(args.sensitive_path),
        max_file_bytes=args.max_file_bytes,
        max_total_bytes=args.max_total_bytes,
        follow_internal_links=args.follow_internal_links,
    )
    result = scan_project(config)
    summary = {
        "schema_version": result.state["schema_version"],
        "scan_id": result.state["run"]["scan_id"],
        "snapshot_digest": result.state["provenance"]["snapshot_digest"],
        "artifact_count": result.state["coverage"]["discovered_artifact_count"],
        "completion": result.completion,
        "state_path": str(result.state_path) if result.state_path is not None else None,
    }
    if args.json:
        print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    elif not args.quiet:
        print(f"Scan state {summary['schema_version']} written to {summary['state_path']}")
        print(f"Snapshot: {summary['snapshot_digest']}")
        print(f"Artifacts: {summary['artifact_count']} | completion: {summary['completion']}")
    if args.fail_on == "PARTIAL" and result.completion != "complete":
        raise CoverageThresholdError("scan completed but the requested PARTIAL threshold was not met")
    return int(ExitCode.OK)


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
