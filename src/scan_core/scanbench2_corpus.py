"""Validate and summarize a ScanBench 2.0 ground-truth corpus."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path, PurePosixPath
from typing import Any, Sequence

from .errors import CommandError
from .scanbench2 import GROUND_TRUTH_VERSION, TRUTH_KINDS, load_ground_truth_file

_MAX_MANIFEST_BYTES = 1_000_000


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise CommandError(f"Cannot read ScanBench 2.0 corpus manifest {path}: {error}") from error
    if size > _MAX_MANIFEST_BYTES:
        raise CommandError(f"ScanBench 2.0 corpus manifest exceeds {_MAX_MANIFEST_BYTES} bytes: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CommandError(f"Cannot parse ScanBench 2.0 corpus manifest {path}: {error}") from error
    if not isinstance(value, dict):
        raise CommandError("ScanBench 2.0 corpus manifest root must be an object")
    return value


def _positive_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise CommandError(f"{label} must be a positive integer")
    return value


def _artifact_path(project_root: Path, locator: str, *, condition_id: str) -> Path:
    path = PurePosixPath(locator)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise CommandError(f"{condition_id}: artifact locator must be a canonical relative path: {locator!r}")
    candidate = project_root.joinpath(*path.parts)
    if not candidate.is_file():
        raise CommandError(f"{condition_id}: artifact locator does not resolve to a fixture file: {locator!r}")
    return candidate


def summarize_corpus(root: Path) -> dict[str, Any]:
    """Validate corpus structure and return separate, non-blended maturity counters."""
    manifest = _load_manifest(root / "manifest.json")
    if manifest.get("scanbench2_version") != GROUND_TRUTH_VERSION:
        raise CommandError(f"corpus scanbench2_version must be {GROUND_TRUTH_VERSION}")
    if manifest.get("truth_kinds") != list(TRUTH_KINDS):
        raise CommandError("corpus truth_kinds must exactly match the evaluator truth classes")

    fixtures = manifest.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        raise CommandError("corpus fixtures must be a nonempty array")
    if not all(isinstance(item, str) and item.strip() for item in fixtures):
        raise CommandError("corpus fixture names must be nonempty strings")
    if len(fixtures) != len(set(fixtures)):
        raise CommandError("corpus fixture names must be unique")

    target = manifest.get("maturity_target")
    if not isinstance(target, dict):
        raise CommandError("corpus maturity_target must be an object")
    target_projects = _positive_int(target.get("projects"), "maturity_target.projects")
    target_conditions = _positive_int(target.get("conditions"), "maturity_target.conditions")

    truth_counts = Counter({kind: 0 for kind in TRUTH_KINDS})
    family_counts: Counter[str] = Counter()
    fixture_condition_counts: dict[str, int] = {}
    global_condition_ids: set[str] = set()

    for fixture_name in fixtures:
        fixture_root = root / "fixtures" / fixture_name
        project_root = fixture_root / "project"
        if not project_root.is_dir():
            raise CommandError(f"fixture project directory is missing: {fixture_name}")
        truth = load_ground_truth_file(fixture_root / "truth.json")
        if truth["project_id"] != fixture_name:
            raise CommandError(
                f"fixture {fixture_name} has mismatched project_id {truth['project_id']!r}"
            )
        fixture_condition_counts[fixture_name] = len(truth["conditions"])
        for condition in truth["conditions"]:
            condition_id = condition["id"]
            if condition_id in global_condition_ids:
                raise CommandError(f"duplicate corpus condition ID: {condition_id}")
            global_condition_ids.add(condition_id)
            truth_counts[condition["truth"]] += 1
            family_counts[condition["family"]] += 1
            for locator in condition["artifact_locators"]:
                _artifact_path(project_root, locator, condition_id=condition_id)

    project_count = len(fixtures)
    condition_count = len(global_condition_ids)
    declared_milestone = manifest.get("milestone")
    if isinstance(declared_milestone, dict):
        if declared_milestone.get("projects") != project_count:
            raise CommandError("corpus milestone.projects does not match validated fixture count")
        if declared_milestone.get("conditions") != condition_count:
            raise CommandError("corpus milestone.conditions does not match validated condition count")

    return {
        "scanbench2_version": GROUND_TRUTH_VERSION,
        "project_count": project_count,
        "condition_count": condition_count,
        "truth_kind_counts": {kind: truth_counts[kind] for kind in TRUTH_KINDS},
        "family_counts": dict(sorted(family_counts.items())),
        "fixture_condition_counts": fixture_condition_counts,
        "maturity_target": {"projects": target_projects, "conditions": target_conditions},
        "maturity_progress": {
            "projects": project_count / target_projects,
            "conditions": condition_count / target_conditions,
        },
        "no_blended_quality_score": True,
    }


def format_corpus_summary(summary: dict[str, Any]) -> str:
    target = summary["maturity_target"]
    lines = [
        f"ScanBench 2.0 {summary['scanbench2_version']} corpus",
        f"Projects: {summary['project_count']} / {target['projects']}",
        f"Conditions: {summary['condition_count']} / {target['conditions']}",
        "Truth classes:",
    ]
    lines.extend(
        f"  {kind}: {summary['truth_kind_counts'][kind]}" for kind in TRUTH_KINDS
    )
    lines.append("No blended overall quality score is calculated.")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m scan_core.scanbench2_corpus")
    parser.add_argument("root", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)
    summary = summarize_corpus(args.root)
    if args.json:
        print(json.dumps(summary, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    else:
        print(format_corpus_summary(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
