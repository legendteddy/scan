#!/usr/bin/env python3
"""Compare canonical Scan runs without estimating model token usage."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from scan_core.efficiency_benchmark import (
    build_efficiency_benchmark,
    load_host_usage,
    summarize_efficiency,
)
from scan_core.validate import validate_path


def _spec(value: str, *, flag: str) -> tuple[str, Path]:
    label, separator, path = value.partition("=")
    if not separator or not label.strip() or not path.strip():
        raise argparse.ArgumentTypeError(f"{flag} must use LABEL=PATH")
    return label.strip(), Path(path.strip())


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Measure Scan efficiency from validated state plus optional exact host token receipts."
    )
    parser.add_argument(
        "--run",
        action="append",
        required=True,
        metavar="LABEL=STATE",
        help="Validated Scan state/report to include; repeat for multiple runs.",
    )
    parser.add_argument(
        "--usage",
        action="append",
        default=[],
        metavar="LABEL=JSON",
        help="Optional exact host token receipt for a matching run label.",
    )
    parser.add_argument("--output", type=Path, help="Write benchmark JSON to this path instead of stdout.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)

    run_specs = [_spec(value, flag="--run") for value in args.run]
    usage_specs = [_spec(value, flag="--usage") for value in args.usage]
    labels = [label for label, _path in run_specs]
    if len(set(labels)) != len(labels):
        parser.error("--run labels must be unique")

    usage_paths: dict[str, Path] = {}
    for label, path in usage_specs:
        if label in usage_paths:
            parser.error(f"duplicate --usage label: {label}")
        if label not in labels:
            parser.error(f"--usage label has no matching --run: {label}")
        usage_paths[label] = path

    summaries = []
    for label, state_path in run_specs:
        state = validate_path(state_path)
        usage = load_host_usage(usage_paths[label]) if label in usage_paths else None
        summaries.append(summarize_efficiency(state, label=label, usage=usage))

    payload = build_efficiency_benchmark(summaries)
    text = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        indent=2 if args.pretty else None,
        separators=None if args.pretty else (",", ":"),
        allow_nan=False,
    ) + "\n"
    if args.output is None:
        sys.stdout.write(text)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
