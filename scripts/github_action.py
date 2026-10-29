"""Entry point used by the repository's composite GitHub Action."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile

ACTION_PATH = Path(os.environ.get("GITHUB_ACTION_PATH", Path(__file__).resolve().parents[1])).resolve()
SRC = ACTION_PATH / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scan_core.cli import main as scan_main  # noqa: E402
from scan_core.github_ci import append_github_outputs, github_outputs, github_summary  # noqa: E402
from scan_core.sarif import write_sarif  # noqa: E402
from scan_core.validate import validate_path  # noqa: E402


def _input(name: str, default: str = "") -> str:
    return os.environ.get(f"SCAN_INPUT_{name.upper().replace('-', '_')}", default).strip()


def _lines(value: str) -> list[str]:
    return [line.strip() for line in value.splitlines() if line.strip()]


def _bool_input(name: str, default: bool) -> bool:
    raw = _input(name, "true" if default else "false").lower()
    if raw in {"true", "1", "yes"}:
        return True
    if raw in {"false", "0", "no"}:
        return False
    raise ValueError(f"{name} must be true or false")


def _resolve_target(workspace: Path) -> Path:
    raw = _input("path", ".")
    target = Path(raw)
    if not target.is_absolute():
        target = workspace / target
    target = target.resolve()
    if not target.exists() or not target.is_dir():
        raise ValueError(f"Scan target is not a readable directory: {target}")
    return target


def _resolve_output_dir(workspace: Path) -> Path:
    raw = _input("output-directory")
    if raw:
        output = Path(raw)
        if not output.is_absolute():
            output = workspace / output
        output = output.resolve()
        output.mkdir(parents=True, exist_ok=True)
        return output
    runner_temp = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())).resolve()
    return Path(tempfile.mkdtemp(prefix="scan-results-", dir=runner_temp))


def run() -> int:
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", ".")).resolve()
    target = _resolve_target(workspace)
    output_dir = _resolve_output_dir(workspace)
    state_path = output_dir / "state.json"
    report_path = output_dir / "report.html"
    sarif_path = output_dir / "results.sarif"
    summary_path = output_dir / "summary.md"

    mode = _input("mode", "deep").lower()
    if mode not in {"quick", "deep", "forensic"}:
        raise ValueError("mode must be quick, deep, or forensic")
    redact = _input("redact", "standard").lower()
    if redact not in {"none", "standard", "strict"}:
        raise ValueError("redact must be none, standard, or strict")
    baseline = _input("baseline", "none") or "none"
    fail_on = _input("fail-on").upper()
    if fail_on and fail_on not in {"PARTIAL", "ERROR"}:
        raise ValueError("fail-on must be empty, PARTIAL, or ERROR")

    args = [
        str(target),
        "--mode", mode,
        "--offline",
        "--redact", redact,
        "--baseline", baseline,
        "--state", str(state_path),
        "--output", str(report_path),
        "--quiet",
    ]
    if not _bool_input("project-config", False):
        args.append("--ignore-project-config")
    for pattern in _lines(_input("excludes")):
        args.extend(["--exclude", pattern])
    for pattern in _lines(_input("sensitive-paths")):
        args.extend(["--sensitive-path", pattern])
    changed_since = _input("changed-since")
    if changed_since:
        args.extend(["--changed-since", changed_since])
    if fail_on:
        args.extend(["--fail-on", fail_on])

    scan_exit = scan_main(args)
    if not state_path.exists():
        return scan_exit or 1

    state = validate_path(state_path)
    write_sarif(state, sarif_path, pretty=True)
    summary = github_summary(state)
    summary_path.write_text(summary, encoding="utf-8", newline="\n")

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        append_github_outputs(
            Path(github_output),
            github_outputs(
                state,
                state_path=state_path,
                report_path=report_path,
                sarif_path=sarif_path,
                summary_path=summary_path,
            ),
        )
    if _bool_input("job-summary", True):
        step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if step_summary:
            with Path(step_summary).open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(summary)

    print(json.dumps({
        "state": str(state_path),
        "report": str(report_path),
        "sarif": str(sarif_path),
        "summary": str(summary_path),
        "scan_exit": scan_exit,
    }, sort_keys=True))
    return scan_exit


if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except (OSError, ValueError) as error:
        print(f"scan-action: {error}", file=sys.stderr)
        raise SystemExit(2)
