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
from .doctor import format_doctor, run_doctor
from .evidence_federation import import_evidence_bundle, load_evidence_bundle_file
from .handoff import build_handoff, canonical_handoff_json, format_handoff_summary
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
from .observed_receipt import import_observed_receipt, load_observed_receipt_file
from .privacy import build_egress_preview
from .render import render_report
from .sarif import write_sarif
from .sarif_import import import_sarif, load_sarif_file
from .scanbench import format_bench, run_bench
from .scanbench2 import evaluate_ground_truth, format_ground_truth, load_ground_truth_file, load_submission_file
from .schema import schema_text
from .serve import create_server
from .state import canonical_state_json
from .settings import ProjectSettings, load_project_settings
from .validate import validate_path
from .version import __version__

UTILITY_COMMANDS = {"validate", "render", "sarif", "import-sarif", "import-evidence", "import-observed", "handoff", "serve", "bench", "bench2", "schema", "egress", "compare", "doctor"}


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
    parser.add_argument("--git-metadata-root", action="append", type=Path, default=[], help="Authorize one exact external Git metadata directory for bounded provenance reads")
    parser.add_argument("--follow-internal-links", action="store_true", default=None)
    parser.add_argument(
        "--ignore-project-config", action="store_true",
        help="Ignore target-controlled .scan/config.toml and use only caller options plus built-in defaults",
    )


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
    elif command == "sarif":
        parser.add_argument("state_json", type=Path)
        parser.add_argument("--output", type=Path, required=True)
        parser.add_argument("--pretty", action="store_true")
    elif command == "import-sarif":
        parser.add_argument("state_json", type=Path)
        parser.add_argument("sarif_json", type=Path)
        parser.add_argument("--output", type=Path, required=True)
        parser.add_argument("--report", type=Path)
        parser.add_argument("--json", action="store_true")
    elif command == "import-evidence":
        parser.add_argument("state_json", type=Path)
        parser.add_argument("bundle_json", type=Path)
        parser.add_argument("--output", type=Path, required=True)
        parser.add_argument("--report", type=Path)
        parser.add_argument("--json", action="store_true")
    elif command == "import-observed":
        parser.add_argument("state_json", type=Path)
        parser.add_argument("receipt_json", type=Path)
        parser.add_argument("--output", type=Path, required=True)
        parser.add_argument("--report", type=Path)
        parser.add_argument("--json", action="store_true")
    elif command == "handoff":
        parser.add_argument("state_json", type=Path)
        parser.add_argument("--output", type=Path)
        parser.add_argument("--section-limit", type=int, default=100)
        parser.add_argument("--ref-limit", type=int, default=12)
        parser.add_argument("--text-limit", type=int, default=800)
        parser.add_argument("--json", action="store_true")
    elif command == "serve":
        parser.add_argument("source", nargs="?", type=Path, default=Path(".scan"))
        parser.add_argument("--host", default="127.0.0.1")
        parser.add_argument("--port", type=int, default=8765)
        parser.add_argument("--allow-network", action="store_true")
        parser.add_argument("--quiet", action="store_true")
    elif command == "bench":
        parser.add_argument("fixture", nargs="?")
        parser.add_argument("--json", action="store_true")
    elif command == "bench2":
        parser.add_argument("truth_json", type=Path)
        parser.add_argument("state_json", type=Path)
        parser.add_argument("submission_json", type=Path)
        parser.add_argument("--json", action="store_true")
    elif command == "schema":
        parser.add_argument("--version", choices=("1.2", "1.3", "1.4"), default="1.4")
    elif command == "doctor":
        parser.add_argument("path", nargs="?", type=Path, default=Path("."))
        parser.add_argument("--json", action="store_true")
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
    ignore_project_config = bool(getattr(args, "ignore_project_config", False))
    project_config_path = root / ".scan" / "config.toml"
    if ignore_project_config:
        settings = ProjectSettings()
        project_config_source = "ignored"
    else:
        settings = load_project_settings(root)
        project_config_source = (
            "project" if project_config_path.exists() or project_config_path.is_symlink() else "built_in"
        )
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
        git_metadata_roots=tuple(getattr(args, "git_metadata_root", ())),
        project_config_source=project_config_source,
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
    if command == "sarif":
        if not args.state_json.exists():
            raise SourceError(f"Source path does not exist: {args.state_json}")
        state = validate_path(args.state_json)
        write_sarif(state, args.output, pretty=args.pretty)
        return int(ExitCode.OK)
    if command == "import-sarif":
        for path in (args.state_json, args.sarif_json):
            if not path.exists():
                raise SourceError(f"Source path does not exist: {path}")
        state = validate_path(args.state_json)
        payload, raw = load_sarif_file(args.sarif_json)
        imported = import_sarif(state, payload, source_bytes=raw)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(canonical_state_json(imported.state) + "\n", encoding="utf-8", newline="\n")
        if args.report is not None:
            render_report(imported.state, args.report)
        summary = {**imported.as_dict(), "state_path": str(args.output), "report_path": str(args.report) if args.report else None}
        if args.json:
            print(json.dumps(summary, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        else:
            print(f"Imported findings: {imported.imported_findings}")
            print(f"Imported evidence: {imported.imported_evidence}")
            print(f"Unmapped/review results retained as unknowns: {imported.unmapped_results}")
            print(f"Ignored non-fail results: {imported.ignored_results}")
            print(f"State written to {args.output}")
        return int(ExitCode.OK)
    if command == "import-evidence":
        for path in (args.state_json, args.bundle_json):
            if not path.exists():
                raise SourceError(f"Source path does not exist: {path}")
        state = validate_path(args.state_json)
        bundle, raw = load_evidence_bundle_file(args.bundle_json)
        imported = import_evidence_bundle(state, bundle, source_bytes=raw)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(canonical_state_json(imported.state) + "\n", encoding="utf-8", newline="\n")
        if args.report is not None:
            render_report(imported.state, args.report)
        summary = {**imported.as_dict(), "state_path": str(args.output), "report_path": str(args.report) if args.report else None}
        if args.json:
            print(json.dumps(summary, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        else:
            print(f"Imported findings: {imported.imported_findings}")
            print(f"Imported unknowns: {imported.imported_unknowns}")
            print(f"Imported evidence: {imported.imported_evidence}")
            print(f"Unmapped external results retained as unknowns: {imported.unmapped_results}")
            print(f"Ignored duplicate results: {imported.ignored_results}")
            print(f"State written to {args.output}")
        return int(ExitCode.OK)
    if command == "import-observed":
        for path in (args.state_json, args.receipt_json):
            if not path.exists():
                raise SourceError(f"Source path does not exist: {path}")
        state = validate_path(args.state_json)
        receipt, raw = load_observed_receipt_file(args.receipt_json)
        imported = import_observed_receipt(state, receipt, source_bytes=raw)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(canonical_state_json(imported.state) + "\n", encoding="utf-8", newline="\n")
        if args.report is not None:
            render_report(imported.state, args.report)
        summary = {
            **imported.as_dict(),
            "state_path": str(args.output),
            "report_path": str(args.report) if args.report else None,
        }
        if args.json:
            print(json.dumps(summary, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        else:
            print(f"Imported findings: {imported.imported_findings}")
            print(f"Imported controls: {imported.imported_controls}")
            print(f"Imported unknowns: {imported.imported_unknowns}")
            print(f"Imported evidence: {imported.imported_evidence}")
            print(f"Unmapped observations retained as unknowns: {imported.unmapped_observations}")
            print(f"Ignored duplicate observations: {imported.ignored_observations}")
            print(f"State written to {args.output}")
        return int(ExitCode.OK)
    if command == "handoff":
        if not args.state_json.exists():
            raise SourceError(f"Source path does not exist: {args.state_json}")
        state = validate_path(args.state_json)
        handoff = build_handoff(
            state,
            section_limit=args.section_limit,
            ref_limit=args.ref_limit,
            text_limit=args.text_limit,
        )
        encoded = canonical_handoff_json(handoff)
        if args.output is not None:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(encoded + "\n", encoding="utf-8", newline="\n")
        if args.json:
            print(encoded)
        else:
            print(format_handoff_summary(handoff))
            if args.output is not None:
                print(f"Handoff written to {args.output}")
        return int(ExitCode.OK)
    if command == "serve":
        if not args.source.exists():
            raise SourceError(f"Source path does not exist: {args.source}")
        server, catalog = create_server(
            args.source,
            host=args.host,
            port=args.port,
            allow_network=args.allow_network,
            quiet=args.quiet,
        )
        actual_host, actual_port = server.server_address[:2]
        if not args.quiet:
            print(f"Serving {len(catalog.entries)} validated Scan receipt(s) at http://{actual_host}:{actual_port}/")
            if catalog.skipped_count:
                print(f"Ignored {catalog.skipped_count} invalid or duplicate JSON receipt(s)")
            print("Read-only local viewer; project files are not served. Press Ctrl+C to stop.")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return int(ExitCode.OK)
    if command == "bench":
        result = run_bench(fixture=args.fixture)
        if args.json:
            print(json.dumps(result.as_dict(), ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        else:
            print(format_bench(result))
        return int(ExitCode.OK if result.passed else ExitCode.VALIDATION_FAILED)
    if command == "bench2":
        for path in (args.truth_json, args.state_json, args.submission_json):
            if not path.exists():
                raise SourceError(f"Source path does not exist: {path}")
        truth = load_ground_truth_file(args.truth_json)
        state = validate_path(args.state_json)
        submission = load_submission_file(args.submission_json)
        result = evaluate_ground_truth(truth, state, submission)
        if args.json:
            print(json.dumps(result.as_dict(), ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        else:
            print(format_ground_truth(result))
        return int(ExitCode.OK if result.passed else ExitCode.VALIDATION_FAILED)
    if command == "schema":
        text = schema_text(args.version)
        print(text, end="" if text.endswith("\n") else "\n")
        return int(ExitCode.OK)
    if command == "doctor":
        result = run_doctor(args.path)
        if args.json:
            print(json.dumps(result.as_dict(), ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        else:
            print(format_doctor(result))
        return int(ExitCode.OK if result.overall != "fail" else ExitCode.COMMAND_ERROR)
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
