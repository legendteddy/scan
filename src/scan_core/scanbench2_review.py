"""Independent-review receipts for ScanBench 2.0 ground truth.

Receipts bind reviewer approval to exact fixture source/truth bytes. They do not
create approval by themselves and cannot substitute for an independent reviewer.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

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
