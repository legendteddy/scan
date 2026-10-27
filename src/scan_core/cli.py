"""Scan command-line interface and stable exit codes."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .baseline import load_state_file
from .compare import compare_states
from .config import ScanConfig
from .core import scan_project
from .errors import (
    CommandError,
    CoverageThresholdError,
    ExitCode,
    PrivacyBlockedError,
    ResourceLimitError,
    SourceError,
    ValidationError,
)
from .inventory import build_inventory
from .privacy import build_egress_preview
from .render import render_report
from .scanbench import format_bench, run_bench
from .schema import schema_text
from .settings import load_project_settings
from .validate import validate_path
from .version import __version__

UTILITY_COMMANDS = {"validate", "render", "bench", "schema", "egress", "compare"}


def _add_scan_options(parser: argparse.ArgumentParser, *, include_offline: bool) -> None:
    parser.add_argument("--mode", choices=("quick", "deep", "forensic"), default=None)
    parser.add_argument("--privacy", choices=("offline", "local", "controlled-remote"), default=None)
    if include_offline:
        parser.add_argument("--offline", action="store_true", help="Explicit shorthand for --privacy offline")
    parser.add_argument("--redact", choices=("none", "standard", "strict"), default=None)
    parser.add_argument("--exclude", action="append", default=None)
    parser.add_argument("--sensitive-path", action="append", default=None)
    parser.add_argument("--max-file-bytes", type=int, default=None)
    parser.add_argument("--max-total-bytes", type=int, default=None)
    parser.add_argument("--follow-internal-links", action="store_true", default=None)


def _primary_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scan", description="Evidence-backed project inspection")
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--output", type=Path, default=Path(".scan/report.html"))
    parser.add_argument("--state", type=Path, default=Path(".scan/state.json"))
    parser.add_argument("--no-html", action="store_true")
    _add_scan_options(parser, include_offline=True)
    parser.add_argument("--baseline", default=None, help="auto | none | PATH")
    parser.add_argument("--no-reuse", action="store_true", help="Compare baseline but do not reuse prior evidence")
    parser.add_argument("--changed-since", default=None, metavar="REF", help="Add local Git change context relative to REF")
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
        parser.add_argument("--json", action="store_true")
    elif command == "schema":
        parser.add_argument("--version", choices=("1.2", "1.3", "1.4"), default="1.4")
    elif command == "compare":
        parser.add_argument("old_state", type=Path)
        parser.add_argument("new_state", type=Path)
        parser.add_argument("--json", action="store_true")
    elif command == "egress":
        parser.add_argument("path", nargs="?", type=Path, default=Path("."))
        _add_scan_options(parser, include_offline=False)
        parser.add_argument("--json", action="store_true")
    return parser


def _resolved_config(
    root: Path,
    args: argparse.Namespace,
    *,
    output_state: Path | None = None,
    output_html: Path | None = None,
) -> ScanConfig:
    settings = load_project_settings(root)
    explicit_privacy = getattr(args, "privacy", None)
    offline = bool(getattr(args, "offline", False))
    if offline and explicit_privacy not in (None, "offline"):
        raise CommandError("--offline cannot be combined with a non-offline --privacy mode")
    privacy = "offline" if offline else (explicit_privacy or settings.privacy_mode)
    redact = getattr(args, "redact", None) or settings.redaction_level
    mode = getattr(args, "mode", None) or settings.scan_mode
    excludes = tuple(args.exclude) if getattr(args, "exclude", None) is not None else settings.excludes
    sensitive = (
        tuple(args.sensitive_path)
        if getattr(args, "sensitive_path", None) is not None
        else settings.sensitive_paths
    )
    max_file = (
        args.max_file_bytes
        if getattr(args, "max_file_bytes", None) is not None
        else settings.max_file_bytes
    )
    max_total = (
        args.max_total_bytes
        if getattr(args, "max_total_bytes", None) is not None
        else settings.max_total_bytes
    )
    follow = (
        args.follow_internal_links
        if getattr(args, "follow_internal_links", None) is not None
        else settings.follow_internal_links
    )
    baseline_value = getattr(args, "baseline", None)
    baseline_path = None
    if baseline_value is None:
        baseline_mode = settings.baseline_mode
    elif baseline_value in {"auto", "none"}:
        baseline_mode = baseline_value
    else:
        baseline_mode = "explicit"
        baseline_path = Path(baseline_value)
    reuse_enabled = False if baseline_mode == "none" or bool(getattr(args, "no_reuse", False)) else settings.reuse_enabled
    return ScanConfig(
        root=root,
        output_state=output_state,
        output_html=output_html,
        privacy_mode=privacy,
        redaction_level=redact,
        scan_mode=mode,
        excludes=excludes,
        sensitive_paths=sensitive,
        max_file_bytes=max_file,
        max_total_bytes=max_total,
        follow_internal_links=follow,
        baseline_mode=baseline_mode,
        baseline_path=baseline_path,
        reuse_enabled=reuse_enabled,
        max_baseline_state_bytes=settings.max_baseline_state_bytes,
        changed_since=getattr(args, "changed_since", None),
    )


def _run_utility(command: str, argv: Sequence[str]) -> int:
    args = _utility_parser(command).parse_args(list(argv))
    if command == "validate":
        if not args.path.exists():
            raise SourceError(f"Source path does not exist: {args.path}")
        validate_path(args.path)
        return int(ExitCode.OK)
    if command == "render":
        if not args.state_json.exists():
            raise SourceError(f"Source path does not exist: {args.state_json}")
        state = validate_path(args.state_json)
        render_report(state, args.output)
        return int(ExitCode.OK)
    if command == "bench":
        result = run_bench(fixture=args.fixture)
        if args.json:
            print(json.dumps(result.as_dict(), ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        else:
            print(format_bench(result))
        return int(ExitCode.OK if result.passed else ExitCode.VALIDATION_FAILED)
    if command == "schema":
        text = schema_text(args.version)
        print(text, end="" if text.endswith("\n") else "\n")
        return int(ExitCode.OK)
    if command == "compare":
        for path in (args.old_state, args.new_state):
            if not path.exists():
                raise SourceError(f"Source path does not exist: {path}")
        old_state = load_state_file(args.old_state)
        new_state = load_state_file(args.new_state)
        comparison = compare_states(old_state, new_state)
        payload = comparison.as_dict()
        if args.json:
            print(json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        else:
            artifacts = payload["artifacts"]
            findings = payload["findings"]
            unknowns = payload["unknowns"]
            print(f"Snapshot: {payload['snapshot_relation']}")
            print(
                "Artifacts: "
                f"+{len(artifacts['added'])} ~{len(artifacts['changed'])} "
                f"-{len(artifacts['removed'])} ={len(artifacts['unchanged'])}"
            )
            print(f"Findings: +{len(findings['new'])} -{len(findings['resolved'])} ·{len(findings['persisting'])}")
            print(f"Unknowns: +{len(unknowns['new'])} -{len(unknowns['resolved'])} ·{len(unknowns['persisting'])}")
        return int(ExitCode.OK)
    if command == "egress":
        if not args.path.exists():
            raise SourceError(f"Source path does not exist: {args.path}")
        config = _resolved_config(args.path, args)
        inventory = build_inventory(config, _internal_ignores=(".scan", ".scan/**"))
        preview = build_egress_preview(config, inventory)
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
    raise CommandError(f"Unknown utility command: {command}")


def _run_primary(argv: Sequence[str]) -> int:
    args = _primary_parser().parse_args(list(argv))
    root = Path(args.path)
    if not root.exists():
        raise SourceError(f"Source path does not exist: {root}")
    config = _resolved_config(
        root,
        args,
        output_state=args.state,
        output_html=None if args.no_html else args.output,
    )
    result = scan_project(config)
    delta = result.state["delta"]
    baseline = result.state["baseline"]
    summary = {
        "schema_version": result.state["schema_version"],
        "scan_id": result.state["run"]["scan_id"],
        "mode": result.state["run"].get("scan_mode", "deep"),
        "snapshot_digest": result.state["provenance"]["snapshot_digest"],
        "artifact_count": result.state["coverage"]["discovered_artifact_count"],
        "completion": result.completion,
        "baseline_status": baseline["status"],
        "evidence_freshness": {
            "fresh": baseline["fresh_evidence_count"],
            "reused": baseline["reused_evidence_count"],
            "rejected_reuse": baseline["rejected_reuse_count"],
        },
        "delta_available": delta["available"],
        "delta": delta,
        "git_change_scope": result.state.get("extensions", {}).get("git_change_scope"),
        "state_path": str(result.state_path) if result.state_path is not None else None,
        "report_path": str(result.report_path) if result.report_path is not None else None,
    }
    if args.json:
        print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    elif not args.quiet:
        print(f"Scan state {summary['schema_version']} written to {summary['state_path']}")
        if summary["report_path"] is not None:
            print(f"Report written to {summary['report_path']}")
        print(f"Snapshot: {summary['snapshot_digest']}")
        print(f"Mode: {summary['mode']} | artifacts: {summary['artifact_count']} | completion: {summary['completion']}")
        print(f"Baseline: {summary['baseline_status']}")
        freshness = summary["evidence_freshness"]
        print(
            f"Evidence: {freshness['fresh']} fresh | {freshness['reused']} reused | "
            f"{freshness['rejected_reuse']} reuse rejected"
        )
        git_scope = summary["git_change_scope"]
        if isinstance(git_scope, dict):
            print(
                f"Git change scope {git_scope['base_ref']}..{git_scope['head_ref']}: "
                f"+{len(git_scope['added'])} ~{len(git_scope['modified'])} "
                f"-{len(git_scope['deleted'])} R{len(git_scope['renamed'])} "
                f"C{len(git_scope['copied'])} ?{len(git_scope['untracked'])} (advisory)"
            )
        if delta["available"]:
            artifacts = delta["artifacts"]
            findings = delta["findings"]
            unknowns = delta["unknowns"]
            print(
                "Since baseline: "
                f"artifacts +{len(artifacts['added'])} ~{len(artifacts['changed'])} -{len(artifacts['removed'])} ={len(artifacts['unchanged'])}; "
                f"findings +{len(findings['new'])} -{len(findings['resolved'])}; "
                f"unknowns +{len(unknowns['new'])} -{len(unknowns['resolved'])}"
            )
    for warning in result.warnings:
        if warning.startswith("Automatic baseline ignored:"):
            print(f"scan: warning: {warning}", file=sys.stderr)
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
