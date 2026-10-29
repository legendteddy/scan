"""Evidence-gate audit for ScanBench 2.0 maturity claims.

The audit keeps corpus size, independent review, effectiveness baseline, holdout
identity, external custody, and mutation/oracle consistency as separate gates.
It deliberately does not calculate an overall quality score or infer external
custody from local files.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from .errors import CommandError
from .scanbench2 import GROUND_TRUTH_VERSION
from .scanbench2_baseline import evaluate_baseline
from .scanbench2_corpus import summarize_corpus
from .scanbench2_holdout import load_holdout_manifest, verify_revealed_holdout
from .scanbench2_oracle_consistency import verify_oracle_consistency
from .scanbench2_review_campaign import summarize_review_coverage

MATURITY_EVIDENCE_VERSION = "2.0-alpha1"
_MAX_MANIFEST_BYTES = 1_000_000


def _load_json_object(path: Path, *, label: str) -> dict[str, Any]:
    if path.is_symlink():
        raise CommandError(f"{label} must not be a symlink: {path}")
    try:
        size = path.stat().st_size
    except OSError as error:
        raise CommandError(f"Cannot read {label} {path}: {error}") from error
    if size > _MAX_MANIFEST_BYTES:
        raise CommandError(f"{label} exceeds {_MAX_MANIFEST_BYTES} bytes: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CommandError(f"Cannot parse {label} {path}: {error}") from error
    if not isinstance(value, dict):
        raise CommandError(f"{label} root must be an object")
    return value


def _safe_relative(base: Path, value: Any, *, label: str, kind: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise CommandError(f"{label} must be a nonempty relative path")
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
    if kind == "file" and not candidate.is_file():
        raise CommandError(f"{label} does not resolve to a file: {value!r}")
    if kind == "dir" and not candidate.is_dir():
        raise CommandError(f"{label} does not resolve to a directory: {value!r}")
    return candidate


def load_maturity_manifest(path: Path) -> dict[str, Any]:
    value = _load_json_object(path, label="ScanBench 2.0 maturity evidence manifest")
    if value.get("scanbench2_version") != GROUND_TRUTH_VERSION:
        raise CommandError(f"maturity scanbench2_version must be {GROUND_TRUTH_VERSION}")
    if value.get("maturity_evidence_version") != MATURITY_EVIDENCE_VERSION:
        raise CommandError(f"maturity_evidence_version must be {MATURITY_EVIDENCE_VERSION}")
    for field in ("holdout_reveals", "oracle_consistency"):
        rows = value.get(field, [])
        if not isinstance(rows, list):
            raise CommandError(f"maturity.{field} must be an array")
        for index, row in enumerate(rows):
            if not isinstance(row, Mapping):
                raise CommandError(f"maturity.{field}[{index}] must be an object")
    return value


def _missing_gate(reason: str) -> dict[str, Any]:
    return {"status": "missing", "reason": reason}


def audit_maturity(corpus_root: Path, maturity_manifest_path: Path) -> dict[str, Any]:
    """Audit each maturity evidence gate independently without a blended score."""
    corpus = summarize_corpus(corpus_root)
    manifest = load_maturity_manifest(maturity_manifest_path)
    base = maturity_manifest_path.parent
    target = corpus["maturity_target"]
    corpus_gate = {
        "status": "satisfied" if (
            corpus["project_count"] >= target["projects"]
            and corpus["condition_count"] >= target["conditions"]
        ) else "unsatisfied",
        "project_count": corpus["project_count"],
        "condition_count": corpus["condition_count"],
        "target": target,
        "truth_kind_counts": corpus["truth_kind_counts"],
    }

    review_value = manifest.get("review_receipts")
    if review_value is None:
        review_gate = _missing_gate("no independent-review receipts directory was supplied")
    else:
        receipts_root = _safe_relative(base, review_value, label="maturity.review_receipts", kind="dir")
        coverage = summarize_review_coverage(corpus_root, receipts_root)
        review_gate = {
            "status": "satisfied" if coverage["review_target_satisfied"] else "unsatisfied",
            "approved_project_count": coverage["approved_project_count"],
            "approved_condition_count": coverage["approved_condition_count"],
            "changes_requested_project_count": coverage["changes_requested_project_count"],
            "invalid_project_count": coverage["invalid_project_count"],
            "missing_project_count": coverage["missing_project_count"],
            "unique_reviewer_count": coverage["unique_reviewer_count"],
            "target_satisfied": coverage["review_target_satisfied"],
        }

    baseline_value = manifest.get("baseline_manifest")
    if baseline_value is None:
        baseline_gate = _missing_gate("no reproducible baseline manifest was supplied")
    else:
        baseline_path = _safe_relative(base, baseline_value, label="maturity.baseline_manifest", kind="file")
        baseline = evaluate_baseline(corpus_root, baseline_path)
        baseline_gate = {
            "status": "satisfied" if baseline["baseline_target_coverage_satisfied"] else "unsatisfied",
            "baseline_id": baseline["baseline_id"],
            "evaluated_project_count": baseline["evaluated_project_count"],
            "evaluated_condition_count": baseline["evaluated_condition_count"],
            "project_pass_count": baseline["project_pass_count"],
            "project_fail_count": baseline["project_fail_count"],
            "target_coverage_satisfied": baseline["baseline_target_coverage_satisfied"],
            "complete_corpus_baseline": baseline["complete_corpus_baseline"],
            "metrics": baseline["metrics"],
        }

    holdout_rows = manifest.get("holdout_reveals", [])
    if not holdout_rows:
        holdout_gate = _missing_gate("no revealed holdout precommitment was supplied")
    else:
        verified: list[dict[str, Any]] = []
        for index, row in enumerate(holdout_rows):
            project_id = row.get("project_id")
            if not isinstance(project_id, str) or not project_id.strip():
                raise CommandError(f"maturity.holdout_reveals[{index}].project_id must be nonempty text")
            holdout_path = _safe_relative(
                base, row.get("manifest"), label=f"maturity.holdout_reveals[{index}].manifest", kind="file"
            )
            fixture_root = _safe_relative(
                base, row.get("fixture"), label=f"maturity.holdout_reveals[{index}].fixture", kind="dir"
            )
            holdout_manifest = load_holdout_manifest(holdout_path)
            result = verify_revealed_holdout(holdout_manifest, project_id, fixture_root)
            verified.append({
                "set_id": result["set_id"],
                "project_id": project_id,
                "fixture_digest": result["fixture_digest"],
                "condition_count": result["condition_count"],
                "precommitment_identity_verified": True,
                "declared_custodian": holdout_manifest["custodian"],
            })
        holdout_gate = {
            "status": "requires_external_custody_evidence",
            "verified_reveal_count": len(verified),
            "precommitment_identity_verified": bool(verified),
            "external_custody_established_by_this_tool": False,
            "verified_reveals": verified,
            "reason": (
                "local verification proves revealed fixture identity against the supplied precommitment, "
                "but cannot prove that custody was external and predated evaluation"
            ),
        }

    oracle_rows = manifest.get("oracle_consistency", [])
    if not oracle_rows:
        oracle_gate = _missing_gate("no mutation/oracle-consistency evidence was supplied")
    else:
        checks: list[dict[str, Any]] = []
        for index, row in enumerate(oracle_rows):
            original = _safe_relative(
                base, row.get("original_fixture"),
                label=f"maturity.oracle_consistency[{index}].original_fixture", kind="dir"
            )
            variant = _safe_relative(
                base, row.get("variant_fixture"),
                label=f"maturity.oracle_consistency[{index}].variant_fixture", kind="dir"
            )
            consistency_path = _safe_relative(
                base, row.get("manifest"), label=f"maturity.oracle_consistency[{index}].manifest", kind="file"
            )
            consistency_manifest = _load_json_object(consistency_path, label="oracle consistency manifest")
            result = verify_oracle_consistency(original, variant, consistency_manifest)
            checks.append({
                "transformation_id": result["transformation_id"],
                "condition_count": result["condition_count"],
                "oracle_consistent": result["oracle_consistent"],
                "original_project_digest": result["original_project_digest"],
                "variant_project_digest": result["variant_project_digest"],
            })
        oracle_gate = {
            "status": "satisfied",
            "verified_check_count": len(checks),
            "checks": checks,
            "semantic_equivalence_independently_proven": False,
            "reason": (
                "the verifier establishes byte change and oracle invariance, not independent proof of runtime semantic equivalence"
            ),
        }

    return {
        "scanbench2_version": GROUND_TRUTH_VERSION,
        "maturity_evidence_version": MATURITY_EVIDENCE_VERSION,
        "gates": {
            "public_corpus": corpus_gate,
            "independent_review": review_gate,
            "effectiveness_baseline": baseline_gate,
            "holdout_precommitment": holdout_gate,
            "mutation_oracle_consistency": oracle_gate,
        },
        "no_blended_quality_score": True,
        "maturity_claim": "not automatically established",
        "note": (
            "Read each gate independently. This audit intentionally does not collapse evidence into one score or infer "
            "external custody/semantic equivalence from local declarations."
        ),
    }


def format_maturity(value: Mapping[str, Any]) -> str:
    lines = ["ScanBench 2.0 maturity evidence audit"]
    for name, gate in value["gates"].items():
        lines.append(f"{name}: {gate['status']}")
    lines.append("No blended overall quality score is calculated.")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m scan_core.scanbench2_maturity")
    parser.add_argument("corpus_root", type=Path)
    parser.add_argument("maturity_manifest", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)
    result = audit_maturity(args.corpus_root, args.maturity_manifest)
    if args.json:
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    else:
        print(format_maturity(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
