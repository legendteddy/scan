"""Reproducible multi-project effectiveness baselines for ScanBench 2.0.

A baseline re-evaluates exact Scan states and adjudications against the current
fixture bytes. Poor effectiveness remains valid baseline evidence; metrics are
aggregated separately and never collapsed into one score.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from .errors import CommandError
from .scanbench2 import GROUND_TRUTH_VERSION, evaluate_ground_truth, load_ground_truth_file, load_submission_file
from .scanbench2_corpus import summarize_corpus
from .scanbench2_review import fixture_source_digest

BASELINE_MANIFEST_VERSION = "2.0-alpha1"
_MAX_MANIFEST_BYTES = 1_000_000
_MAX_STATE_BYTES = 64_000_000


def _required_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CommandError(f"{label} must be a nonempty string")
    return value


def _load_json_object(path: Path, *, max_bytes: int, label: str) -> dict[str, Any]:
    if path.is_symlink():
        raise CommandError(f"{label} must not be a symlink: {path}")
    try:
        size = path.stat().st_size
    except OSError as error:
        raise CommandError(f"Cannot read {label} {path}: {error}") from error
    if size > max_bytes:
        raise CommandError(f"{label} exceeds {max_bytes} bytes: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CommandError(f"Cannot parse {label} {path}: {error}") from error
    if not isinstance(value, dict):
        raise CommandError(f"{label} root must be an object: {path}")
    return value


def load_baseline_manifest(path: Path) -> dict[str, Any]:
    value = _load_json_object(path, max_bytes=_MAX_MANIFEST_BYTES, label="ScanBench 2.0 baseline manifest")
    if value.get("scanbench2_version") != GROUND_TRUTH_VERSION:
        raise CommandError(f"baseline scanbench2_version must be {GROUND_TRUTH_VERSION}")
    if value.get("baseline_manifest_version") != BASELINE_MANIFEST_VERSION:
        raise CommandError(f"baseline_manifest_version must be {BASELINE_MANIFEST_VERSION}")
    baseline_id = _required_string(value.get("baseline_id"), "baseline.baseline_id")
    inspector = value.get("inspector")
    if not isinstance(inspector, Mapping):
        raise CommandError("baseline.inspector must be an object")
    normalized_inspector = {
        "name": _required_string(inspector.get("name"), "baseline.inspector.name"),
        "version": _required_string(inspector.get("version"), "baseline.inspector.version"),
        "configuration": str(inspector.get("configuration", "")),
    }
    runs = value.get("runs")
    if not isinstance(runs, list) or not runs:
        raise CommandError("baseline.runs must be a nonempty array")
    normalized_runs: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, row in enumerate(runs):
        if not isinstance(row, Mapping):
            raise CommandError(f"baseline.runs[{index}] must be an object")
        project_id = _required_string(row.get("project_id"), f"baseline.runs[{index}].project_id")
        if project_id in seen:
            raise CommandError(f"duplicate baseline project_id: {project_id}")
        seen.add(project_id)
        normalized_runs.append({
            "project_id": project_id,
            "state": _required_string(row.get("state"), f"{project_id}.state"),
            "submission": _required_string(row.get("submission"), f"{project_id}.submission"),
        })
    return {
        "scanbench2_version": GROUND_TRUTH_VERSION,
        "baseline_manifest_version": BASELINE_MANIFEST_VERSION,
        "baseline_id": baseline_id,
        "inspector": normalized_inspector,
        "runs": normalized_runs,
    }


def _relative_file(base: Path, value: str, *, label: str) -> Path:
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or "\\" in value
        or ":" in value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise CommandError(f"{label} must be a canonical relative path: {value!r}")
    candidate = base
    for part in path.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise CommandError(f"{label} must not traverse a symlink: {value!r}")
    if not candidate.is_file():
        raise CommandError(f"{label} does not resolve to a file: {value!r}")
    return candidate


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _aggregate(run_results: list[dict[str, Any]]) -> dict[str, Any]:
    detection_tp = sum(row["metrics"]["detection"]["true_positive"] for row in run_results)
    detection_fn = sum(row["metrics"]["detection"]["false_negative"] for row in run_results)
    negative_tn = sum(row["metrics"]["negative_controls"]["true_negative"] for row in run_results)
    negative_fp = sum(row["metrics"]["negative_controls"]["false_positive"] for row in run_results)
    unknown_correct = sum(row["metrics"]["unknown_honesty"]["correct_unknown"] for row in run_results)
    unknown_wrong = sum(row["metrics"]["unknown_honesty"]["incorrect_or_overclaimed"] for row in run_results)
    clearance_violations = sum(row["metrics"]["false_clearance"]["violations"] for row in run_results)
    clearance_conditions = sum(row["metrics"]["false_clearance"]["conditions"] for row in run_results)
    supported_found = sum(row["metrics"]["evidence_support"]["supported_found_outcomes"] for row in run_results)
    found_outcomes = sum(row["metrics"]["evidence_support"]["found_outcomes"] for row in run_results)
    grounded = sum(row["metrics"]["artifact_grounding"]["grounded"] for row in run_results)
    grounding_required = sum(row["metrics"]["artifact_grounding"]["required"] for row in run_results)
    refs_valid = sum(row["metrics"]["reference_integrity"]["valid"] for row in run_results)
    refs_invalid = sum(row["metrics"]["reference_integrity"]["invalid"] for row in run_results)
    return {
        "detection": {
            "true_positive": detection_tp,
            "false_negative": detection_fn,
            "recall": _ratio(detection_tp, detection_tp + detection_fn),
        },
        "negative_controls": {
            "true_negative": negative_tn,
            "false_positive": negative_fp,
            "specificity": _ratio(negative_tn, negative_tn + negative_fp),
        },
        "unknown_honesty": {
            "correct_unknown": unknown_correct,
            "incorrect_or_overclaimed": unknown_wrong,
            "rate": _ratio(unknown_correct, unknown_correct + unknown_wrong),
        },
        "false_clearance": {
            "violations": clearance_violations,
            "conditions": clearance_conditions,
            "violation_rate": _ratio(clearance_violations, clearance_conditions),
        },
        "evidence_support": {
            "supported_found_outcomes": supported_found,
            "found_outcomes": found_outcomes,
            "rate": _ratio(supported_found, found_outcomes),
        },
        "artifact_grounding": {
            "grounded": grounded,
            "required": grounding_required,
            "rate": _ratio(grounded, grounding_required),
        },
        "reference_integrity": {"valid": refs_valid, "invalid": refs_invalid},
    }


def evaluate_baseline(corpus_root: Path, baseline_manifest_path: Path) -> dict[str, Any]:
    corpus = summarize_corpus(corpus_root)
    manifest = load_baseline_manifest(baseline_manifest_path)
    manifest_root = baseline_manifest_path.parent
    allowed_projects = set(corpus["fixture_condition_counts"])
    run_results: list[dict[str, Any]] = []
    evaluated_projects: set[str] = set()

    for run in manifest["runs"]:
        project_id = run["project_id"]
        if project_id not in allowed_projects:
            raise CommandError(f"baseline references project not present in corpus: {project_id}")
        state_path = _relative_file(manifest_root, run["state"], label=f"{project_id}.state")
        submission_path = _relative_file(manifest_root, run["submission"], label=f"{project_id}.submission")
        fixture_root = corpus_root / "fixtures" / project_id
        truth = load_ground_truth_file(fixture_root / "truth.json")
        state = _load_json_object(state_path, max_bytes=_MAX_STATE_BYTES, label=f"{project_id} Scan state")
        submission = load_submission_file(submission_path)
        result = evaluate_ground_truth(truth, state, submission)
        condition_count = len(result.conditions)
        expected_count = corpus["fixture_condition_counts"][project_id]
        if condition_count != expected_count:
            raise CommandError(f"{project_id}: evaluated condition count does not match corpus")
        payload = result.as_dict()
        run_results.append({
            "project_id": project_id,
            "fixture_digest": fixture_source_digest(fixture_root),
            "state_digest": result.state_digest,
            "condition_count": condition_count,
            "passed": result.passed,
            "metrics": payload["metrics"],
        })
        evaluated_projects.add(project_id)

    evaluated_condition_count = sum(row["condition_count"] for row in run_results)
    missing_projects = [
        project_id for project_id in corpus["fixture_condition_counts"] if project_id not in evaluated_projects
    ]
    target = corpus["maturity_target"]
    return {
        "scanbench2_version": GROUND_TRUTH_VERSION,
        "baseline_manifest_version": BASELINE_MANIFEST_VERSION,
        "baseline_id": manifest["baseline_id"],
        "inspector": manifest["inspector"],
        "corpus_project_count": corpus["project_count"],
        "corpus_condition_count": corpus["condition_count"],
        "evaluated_project_count": len(run_results),
        "evaluated_condition_count": evaluated_condition_count,
        "project_pass_count": sum(row["passed"] for row in run_results),
        "project_fail_count": sum(not row["passed"] for row in run_results),
        "missing_project_ids": missing_projects,
        "maturity_target": target,
        "baseline_target_coverage_satisfied": (
            len(run_results) >= target["projects"] and evaluated_condition_count >= target["conditions"]
        ),
        "complete_corpus_baseline": len(run_results) == corpus["project_count"] and not missing_projects,
        "metrics": _aggregate(run_results),
        "runs": run_results,
        "no_blended_quality_score": True,
        "note": (
            "This ledger measures inspector effectiveness on the listed exact inputs. It does not establish "
            "independent oracle review or holdout custody by itself."
        ),
    }


def format_baseline(value: Mapping[str, Any]) -> str:
    metrics = value["metrics"]
    return "\n".join([
        f"ScanBench 2.0 baseline {value['baseline_id']}",
        f"Projects evaluated: {value['evaluated_project_count']} / {value['corpus_project_count']}",
        f"Conditions evaluated: {value['evaluated_condition_count']} / {value['corpus_condition_count']}",
        f"Detection recall: {metrics['detection']['recall']}",
        f"Negative-control specificity: {metrics['negative_controls']['specificity']}",
        f"Unknown-honesty rate: {metrics['unknown_honesty']['rate']}",
        f"False-clearance violations: {metrics['false_clearance']['violations']}",
        f"Evidence-support rate: {metrics['evidence_support']['rate']}",
        f"Artifact-grounding rate: {metrics['artifact_grounding']['rate']}",
        "No blended overall quality score is calculated.",
    ])


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m scan_core.scanbench2_baseline")
    parser.add_argument("corpus_root", type=Path)
    parser.add_argument("baseline_manifest", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)
    result = evaluate_baseline(args.corpus_root, args.baseline_manifest)
    if args.json:
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    else:
        print(format_baseline(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
