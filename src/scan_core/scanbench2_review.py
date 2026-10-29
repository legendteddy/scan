"""Independent-review receipts for ScanBench 2.0 ground truth.

Receipts bind reviewer approval to exact fixture source/truth bytes. They do not
create approval by themselves and cannot substitute for an independent reviewer.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from .errors import CommandError
from .scanbench2 import GROUND_TRUTH_VERSION, load_ground_truth_file

REVIEW_RECEIPT_VERSION = "2.0-alpha1"
DECISIONS = ("approved", "changes_requested")


def fixture_source_digest(fixture_root: Path) -> str:
    """Return a deterministic digest of truth.json plus all regular project files."""
    project_root = fixture_root / "project"
    truth_path = fixture_root / "truth.json"
    if not project_root.is_dir() or not truth_path.is_file():
        raise CommandError(f"invalid ScanBench 2.0 fixture root: {fixture_root}")
    paths = [truth_path]
    for path in sorted(project_root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise CommandError(f"review digest rejects fixture symlink: {path}")
        if path.is_file():
            paths.append(path)
    hasher = hashlib.sha256()
    for path in paths:
        relative = path.relative_to(fixture_root).as_posix().encode("utf-8")
        data = path.read_bytes()
        hasher.update(len(relative).to_bytes(8, "big"))
        hasher.update(relative)
        hasher.update(len(data).to_bytes(8, "big"))
        hasher.update(data)
    return "sha256:" + hasher.hexdigest()


def _required_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CommandError(f"{label} must be a nonempty string")
    return value


def review_request(fixture_root: Path) -> dict[str, Any]:
    """Return a neutral request package for a real independent reviewer.

    This deliberately contains no reviewer identity, independence claim, decision,
    or pre-filled approval. It is a request for evidence, not evidence itself.
    """
    truth = load_ground_truth_file(fixture_root / "truth.json")
    return {
        "scanbench2_version": GROUND_TRUTH_VERSION,
        "review_receipt_version": REVIEW_RECEIPT_VERSION,
        "project_id": truth["project_id"],
        "fixture_digest": fixture_source_digest(fixture_root),
        "condition_ids": [row["id"] for row in truth["conditions"]],
        "condition_count": len(truth["conditions"]),
        "requested_checks": [
            "Review the fixture project and truth.json independently of the fixture author.",
            "Confirm each condition truth class, description, rationale, and artifact locator against the supplied fixture bytes.",
            "Check negative controls and unknown/no-clear conditions for overclaiming or hidden assumptions.",
            "Return a separate review receipt only after completing the review; do not infer approval from this request package.",
        ],
        "receipt_template": {
            "scanbench2_version": GROUND_TRUTH_VERSION,
            "review_receipt_version": REVIEW_RECEIPT_VERSION,
            "project_id": truth["project_id"],
            "fixture_digest": fixture_source_digest(fixture_root),
            "reviewer": "",
            "reviewer_role": "",
            "independent_of_fixture_author": False,
            "decision": "changes_requested",
            "reviewed_condition_ids": [row["id"] for row in truth["conditions"]],
            "notes": "",
        },
        "warning": "This package is not a review receipt and does not establish independent approval.",
    }


def validate_review_receipt(value: Mapping[str, Any], fixture_root: Path) -> dict[str, Any]:
    truth = load_ground_truth_file(fixture_root / "truth.json")
    if value.get("scanbench2_version") != GROUND_TRUTH_VERSION:
        raise CommandError(f"review scanbench2_version must be {GROUND_TRUTH_VERSION}")
    if value.get("review_receipt_version") != REVIEW_RECEIPT_VERSION:
        raise CommandError(f"review_receipt_version must be {REVIEW_RECEIPT_VERSION}")
    if value.get("project_id") != truth["project_id"]:
        raise CommandError("review project_id does not match fixture ground truth")
    expected_digest = fixture_source_digest(fixture_root)
    if value.get("fixture_digest") != expected_digest:
        raise CommandError("review fixture_digest does not match current fixture bytes")
    reviewer = _required_string(value.get("reviewer"), "review.reviewer")
    reviewer_role = _required_string(value.get("reviewer_role"), "review.reviewer_role")
    independent = value.get("independent_of_fixture_author")
    if not isinstance(independent, bool):
        raise CommandError("review.independent_of_fixture_author must be boolean")
    decision = value.get("decision")
    if decision not in DECISIONS:
        raise CommandError(f"review.decision must be one of {', '.join(DECISIONS)}")
    reviewed = value.get("reviewed_condition_ids")
    if not isinstance(reviewed, list) or not all(isinstance(item, str) and item for item in reviewed):
        raise CommandError("review.reviewed_condition_ids must be a string array")
    if len(reviewed) != len(set(reviewed)):
        raise CommandError("review.reviewed_condition_ids must not contain duplicates")
    expected_ids = {row["id"] for row in truth["conditions"]}
    if set(reviewed) != expected_ids:
        missing = sorted(expected_ids - set(reviewed))
        extra = sorted(set(reviewed) - expected_ids)
        raise CommandError(f"review condition coverage mismatch: missing={missing}, extra={extra}")
    if decision == "approved" and not independent:
        raise CommandError("approved review must be independent of the fixture author")
    notes = value.get("notes", "")
    if not isinstance(notes, str):
        raise CommandError("review.notes must be a string")
    return {
        "scanbench2_version": GROUND_TRUTH_VERSION,
        "review_receipt_version": REVIEW_RECEIPT_VERSION,
        "project_id": truth["project_id"],
        "fixture_digest": expected_digest,
        "reviewer": reviewer,
        "reviewer_role": reviewer_role,
        "independent_of_fixture_author": independent,
        "decision": decision,
        "reviewed_condition_ids": sorted(reviewed),
        "notes": notes,
    }


def load_review_receipt(path: Path, fixture_root: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CommandError(f"Cannot parse ScanBench 2.0 review receipt {path}: {error}") from error
    if not isinstance(value, dict):
        raise CommandError("ScanBench 2.0 review receipt root must be an object")
    return validate_review_receipt(value, fixture_root)


def _print_json(value: Mapping[str, Any]) -> None:
    print(json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m scan_core.scanbench2_review")
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare", help="prepare a neutral independent-review request")
    prepare.add_argument("fixture_root", type=Path)
    prepare.add_argument("--output", type=Path)

    verify = subparsers.add_parser("verify", help="verify a completed independent-review receipt")
    verify.add_argument("fixture_root", type=Path)
    verify.add_argument("receipt", type=Path)
    verify.add_argument("--json", action="store_true")

    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.command == "prepare":
        package = review_request(args.fixture_root)
        rendered = json.dumps(package, ensure_ascii=True, sort_keys=True, indent=2) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
        return 0

    receipt = load_review_receipt(args.receipt, args.fixture_root)
    if args.json:
        _print_json({"valid": True, "receipt": receipt})
    else:
        print(f"VALID {receipt['project_id']} {receipt['decision']} {receipt['fixture_digest']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
