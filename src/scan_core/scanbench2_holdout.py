"""External holdout precommitments for ScanBench 2.0.

A holdout manifest commits to fixture bytes and coarse truth counts without
publishing the secret fixture. After reveal, Scan can verify that the revealed
fixture is exactly the one that was precommitted. This does not make a holdout
independent by itself; custody and review remain external evidence.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from .errors import CommandError
from .scanbench2 import GROUND_TRUTH_VERSION, TRUTH_KINDS, load_ground_truth_file
from .scanbench2_review import fixture_source_digest

HOLDOUT_MANIFEST_VERSION = "2.0-alpha1"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_MANIFEST_BYTES = 1_000_000


def _required_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CommandError(f"{label} must be a nonempty string")
    return value


def _nonnegative_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise CommandError(f"{label} must be a nonnegative integer")
    return value


def _positive_int(value: Any, label: str) -> int:
    result = _nonnegative_int(value, label)
    if result == 0:
        raise CommandError(f"{label} must be greater than zero")
    return result


def validate_holdout_manifest(value: Mapping[str, Any]) -> dict[str, Any]:
    if value.get("scanbench2_version") != GROUND_TRUTH_VERSION:
        raise CommandError(f"holdout scanbench2_version must be {GROUND_TRUTH_VERSION}")
    if value.get("holdout_manifest_version") != HOLDOUT_MANIFEST_VERSION:
        raise CommandError(f"holdout_manifest_version must be {HOLDOUT_MANIFEST_VERSION}")
    set_id = _required_string(value.get("set_id"), "holdout.set_id")
    custodian = _required_string(value.get("custodian"), "holdout.custodian")
    entries = value.get("entries")
    if not isinstance(entries, list) or not entries:
        raise CommandError("holdout.entries must be a nonempty array")

    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for index, row in enumerate(entries):
        if not isinstance(row, Mapping):
            raise CommandError(f"holdout.entries[{index}] must be an object")
        project_id = _required_string(row.get("project_id"), f"holdout.entries[{index}].project_id")
        if project_id in seen:
            raise CommandError(f"duplicate holdout project_id: {project_id}")
        seen.add(project_id)
        fixture_digest = row.get("fixture_digest")
        if not isinstance(fixture_digest, str) or _SHA256_RE.fullmatch(fixture_digest) is None:
            raise CommandError(f"{project_id}: fixture_digest must be sha256:<64 lowercase hex>")
        condition_count = _positive_int(row.get("condition_count"), f"{project_id}.condition_count")
        counts = row.get("truth_kind_counts")
        if not isinstance(counts, Mapping) or set(counts) != set(TRUTH_KINDS):
            raise CommandError(f"{project_id}: truth_kind_counts must contain exactly {', '.join(TRUTH_KINDS)}")
        normalized_counts = {
            kind: _nonnegative_int(counts[kind], f"{project_id}.truth_kind_counts.{kind}")
            for kind in TRUTH_KINDS
        }
        if sum(normalized_counts.values()) != condition_count:
            raise CommandError(f"{project_id}: truth_kind_counts must sum to condition_count")
        normalized.append({
            "project_id": project_id,
            "fixture_digest": fixture_digest,
            "condition_count": condition_count,
            "truth_kind_counts": normalized_counts,
        })
    return {
        "scanbench2_version": GROUND_TRUTH_VERSION,
        "holdout_manifest_version": HOLDOUT_MANIFEST_VERSION,
        "set_id": set_id,
        "custodian": custodian,
        "entries": normalized,
    }


def load_holdout_manifest(path: Path) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise CommandError(f"Cannot read ScanBench 2.0 holdout manifest {path}: {error}") from error
    if size > _MAX_MANIFEST_BYTES:
        raise CommandError(f"ScanBench 2.0 holdout manifest exceeds {_MAX_MANIFEST_BYTES} bytes: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CommandError(f"Cannot parse ScanBench 2.0 holdout manifest {path}: {error}") from error
    if not isinstance(value, dict):
        raise CommandError("ScanBench 2.0 holdout manifest root must be an object")
    return validate_holdout_manifest(value)


def holdout_entry_for(manifest: Mapping[str, Any], project_id: str) -> dict[str, Any]:
    validated = validate_holdout_manifest(manifest)
    for row in validated["entries"]:
        if row["project_id"] == project_id:
            return row
    raise CommandError(f"holdout manifest has no project_id {project_id!r}")


def verify_revealed_holdout(manifest: Mapping[str, Any], project_id: str, fixture_root: Path) -> dict[str, Any]:
    """Verify a revealed fixture against an earlier coarse-grained precommitment."""
    validated = validate_holdout_manifest(manifest)
    entry = holdout_entry_for(validated, project_id)
    truth = load_ground_truth_file(fixture_root / "truth.json")
    if truth["project_id"] != project_id:
        raise CommandError("revealed fixture project_id does not match the holdout entry")
    actual_digest = fixture_source_digest(fixture_root)
    if actual_digest != entry["fixture_digest"]:
        raise CommandError("revealed fixture digest does not match the holdout precommitment")
    actual_counts = Counter(row["truth"] for row in truth["conditions"])
    normalized_counts = {kind: actual_counts[kind] for kind in TRUTH_KINDS}
    if len(truth["conditions"]) != entry["condition_count"]:
        raise CommandError("revealed condition_count does not match the holdout precommitment")
    if normalized_counts != entry["truth_kind_counts"]:
        raise CommandError("revealed truth_kind_counts do not match the holdout precommitment")
    return {
        "scanbench2_version": GROUND_TRUTH_VERSION,
        "holdout_manifest_version": HOLDOUT_MANIFEST_VERSION,
        "set_id": validated["set_id"],
        "project_id": project_id,
        "fixture_digest": actual_digest,
        "condition_count": len(truth["conditions"]),
        "truth_kind_counts": normalized_counts,
        "verified": True,
        "note": "Precommitment verification proves fixture identity, not reviewer independence or inspector effectiveness.",
    }


def _print_json(value: Mapping[str, Any]) -> None:
    print(json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m scan_core.scanbench2_holdout")
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("manifest", type=Path)
    validate_parser.add_argument("--json", action="store_true")
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("manifest", type=Path)
    verify_parser.add_argument("project_id")
    verify_parser.add_argument("fixture_root", type=Path)
    verify_parser.add_argument("--json", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)
    manifest = load_holdout_manifest(args.manifest)
    if args.command == "validate":
        if args.json:
            _print_json(manifest)
        else:
            print(f"Holdout set {manifest['set_id']}: {len(manifest['entries'])} precommitted fixture(s)")
        return 0
    result = verify_revealed_holdout(manifest, args.project_id, args.fixture_root)
    if args.json:
        _print_json(result)
    else:
        print(f"VERIFIED {args.project_id} {result['fixture_digest']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
