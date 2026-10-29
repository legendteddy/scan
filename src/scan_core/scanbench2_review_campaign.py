"""Corpus-wide independent-review campaign support for ScanBench 2.0.

This module never creates approval evidence. It prepares neutral requests and
summarizes independently returned receipts against the current fixture bytes.
Missing, stale, malformed, or non-approved receipts remain explicit.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from .errors import CommandError
from .scanbench2_corpus import summarize_corpus
from .scanbench2_review import load_review_receipt, review_request

CAMPAIGN_VERSION = "2.0-alpha1"


def prepare_campaign(corpus_root: Path) -> dict[str, Any]:
    """Return deterministic neutral review requests for every corpus fixture."""
    summary = summarize_corpus(corpus_root)
    requests: list[dict[str, Any]] = []
    for project_id in summary["fixture_condition_counts"]:
        fixture_root = corpus_root / "fixtures" / project_id
        requests.append(review_request(fixture_root))
    return {
        "scanbench2_version": summary["scanbench2_version"],
        "review_campaign_version": CAMPAIGN_VERSION,
        "project_count": summary["project_count"],
        "condition_count": summary["condition_count"],
        "maturity_target": summary["maturity_target"],
        "requests": requests,
        "warning": (
            "This campaign package contains review requests only. It contains no independent approval "
            "and must not be counted as review evidence."
        ),
    }


def _invalid_status(project_id: str, condition_count: int, message: str) -> dict[str, Any]:
    return {
        "project_id": project_id,
        "condition_count": condition_count,
        "status": "invalid",
        "decision": None,
        "reviewer": None,
        "error": message,
    }


def summarize_review_coverage(corpus_root: Path, receipts_root: Path) -> dict[str, Any]:
    """Summarize independent review evidence without converting absence into approval."""
    summary = summarize_corpus(corpus_root)
    if not receipts_root.is_dir():
        raise CommandError(f"review receipts directory is missing: {receipts_root}")

    approved_projects = 0
    approved_conditions = 0
    changes_requested_projects = 0
    reviewed_conditions = 0
    invalid_projects = 0
    missing_projects = 0
    reviewers: set[str] = set()
    statuses: list[dict[str, Any]] = []
    expected_files: set[str] = set()

    for project_id, condition_count in summary["fixture_condition_counts"].items():
        filename = f"{project_id}.json"
        expected_files.add(filename)
        receipt_path = receipts_root / filename
        if not receipt_path.exists():
            missing_projects += 1
            statuses.append({
                "project_id": project_id,
                "condition_count": condition_count,
                "status": "missing",
                "decision": None,
                "reviewer": None,
                "error": None,
            })
            continue
        if receipt_path.is_symlink() or not receipt_path.is_file():
            invalid_projects += 1
            statuses.append(_invalid_status(project_id, condition_count, "receipt must be a regular file"))
            continue
        try:
            receipt = load_review_receipt(receipt_path, corpus_root / "fixtures" / project_id)
        except CommandError as exc:
            invalid_projects += 1
            statuses.append(_invalid_status(project_id, condition_count, str(exc)))
            continue

        reviewed_conditions += condition_count
        reviewers.add(receipt["reviewer"])
        decision = receipt["decision"]
        if decision == "approved":
            approved_projects += 1
            approved_conditions += condition_count
            status = "approved"
        else:
            changes_requested_projects += 1
            status = "changes_requested"
        statuses.append({
            "project_id": project_id,
            "condition_count": condition_count,
            "status": status,
            "decision": decision,
            "reviewer": receipt["reviewer"],
            "error": None,
        })

    orphan_receipts = sorted(
        path.name
        for path in receipts_root.iterdir()
        if path.name.endswith(".json") and path.name not in expected_files
    )
    target = summary["maturity_target"]
    review_target_satisfied = (
        approved_projects >= target["projects"]
        and approved_conditions >= target["conditions"]
    )
    all_corpus_fixtures_approved = approved_projects == summary["project_count"]
    return {
        "scanbench2_version": summary["scanbench2_version"],
        "review_campaign_version": CAMPAIGN_VERSION,
        "project_count": summary["project_count"],
        "condition_count": summary["condition_count"],
        "maturity_target": target,
        "approved_project_count": approved_projects,
        "approved_condition_count": approved_conditions,
        "reviewed_condition_count": reviewed_conditions,
        "changes_requested_project_count": changes_requested_projects,
        "invalid_project_count": invalid_projects,
        "missing_project_count": missing_projects,
        "unique_reviewer_count": len(reviewers),
        "review_target_satisfied": review_target_satisfied,
        "all_corpus_fixtures_approved": all_corpus_fixtures_approved,
        "orphan_receipts": orphan_receipts,
        "statuses": statuses,
        "no_blended_quality_score": True,
        "note": (
            "Review coverage establishes only independent oracle review. Holdout custody and inspector "
            "effectiveness remain separate maturity evidence."
        ),
    }


def format_review_coverage(value: Mapping[str, Any]) -> str:
    target = value["maturity_target"]
    return "\n".join([
        f"ScanBench 2.0 independent review coverage",
        f"Approved projects: {value['approved_project_count']} / {target['projects']} target",
        f"Approved conditions: {value['approved_condition_count']} / {target['conditions']} target",
        f"Changes requested: {value['changes_requested_project_count']}",
        f"Invalid receipts: {value['invalid_project_count']}",
        f"Missing receipts: {value['missing_project_count']}",
        f"Review target satisfied: {'yes' if value['review_target_satisfied'] else 'no'}",
        "No blended overall quality score is calculated.",
    ])


def _write_or_print(value: Mapping[str, Any], output: Path | None) -> None:
    rendered = json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n"
    if output is None:
        print(rendered, end="")
        return
    output.write_text(rendered, encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m scan_core.scanbench2_review_campaign")
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare", help="prepare neutral review requests for every fixture")
    prepare.add_argument("corpus_root", type=Path)
    prepare.add_argument("--output", type=Path)

    coverage = subparsers.add_parser("coverage", help="summarize returned independent-review receipts")
    coverage.add_argument("corpus_root", type=Path)
    coverage.add_argument("receipts_root", type=Path)
    coverage.add_argument("--json", action="store_true")

    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.command == "prepare":
        _write_or_print(prepare_campaign(args.corpus_root), args.output)
        return 0

    result = summarize_review_coverage(args.corpus_root, args.receipts_root)
    if args.json:
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    else:
        print(format_review_coverage(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
