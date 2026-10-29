"""Oracle-consistency verification for semantics-preserving ScanBench 2.0 variants.

A consistency receipt binds original and variant fixtures to exact bytes, requires
project source bytes to actually change, and proves a bijective condition mapping
preserves truth/family/claim semantics. It does not prove that the transformation
is semantically preserving by itself; that claim remains reviewer evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from .errors import CommandError
from .scanbench2 import GROUND_TRUTH_VERSION, load_ground_truth_file
from .scanbench2_review import fixture_source_digest

ORACLE_CONSISTENCY_VERSION = "2.0-alpha1"
_MAX_MANIFEST_BYTES = 1_000_000


def _required_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CommandError(f"{label} must be a nonempty string")
    return value


def project_source_digest(fixture_root: Path) -> str:
    """Hash only project files so truth/identifier edits cannot fake a source mutation."""
    project_root = fixture_root / "project"
    if project_root.is_symlink() or not project_root.is_dir():
        raise CommandError(f"invalid or symlinked fixture project root: {project_root}")
    files: list[Path] = []
    for path in sorted(project_root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise CommandError(f"oracle consistency rejects project symlink: {path}")
        if path.is_file():
            files.append(path)
    if not files:
        raise CommandError(f"fixture project has no regular files: {project_root}")
    hasher = hashlib.sha256()
    for path in files:
        relative = path.relative_to(project_root).as_posix().encode("utf-8")
        data = path.read_bytes()
        hasher.update(len(relative).to_bytes(8, "big"))
        hasher.update(relative)
        hasher.update(len(data).to_bytes(8, "big"))
        hasher.update(data)
    return "sha256:" + hasher.hexdigest()


def _load_manifest(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise CommandError(f"oracle consistency manifest must not be a symlink: {path}")
    try:
        size = path.stat().st_size
    except OSError as error:
        raise CommandError(f"Cannot read oracle consistency manifest {path}: {error}") from error
    if size > _MAX_MANIFEST_BYTES:
        raise CommandError(f"oracle consistency manifest exceeds {_MAX_MANIFEST_BYTES} bytes: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CommandError(f"Cannot parse oracle consistency manifest {path}: {error}") from error
    if not isinstance(value, dict):
        raise CommandError("oracle consistency manifest root must be an object")
    return value


def _string_map(value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise CommandError(f"{label} must be an object")
    normalized: dict[str, str] = {}
    for key, target in value.items():
        source = _required_string(key, f"{label} key")
        normalized[source] = _required_string(target, f"{label}.{source}")
    if len(normalized.values()) != len(set(normalized.values())):
        raise CommandError(f"{label} values must be unique")
    return normalized


def _canonical_locator(value: str, label: str) -> str:
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or "\\" in value
        or ":" in value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise CommandError(f"{label} must be a canonical relative artifact path: {value!r}")
    return path.as_posix()


def _assert_locator_exists(fixture_root: Path, locator: str, *, label: str) -> None:
    project_root = fixture_root / "project"
    path = PurePosixPath(_canonical_locator(locator, label))
    candidate = project_root
    for part in path.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise CommandError(f"{label} must not traverse a symlink: {locator!r}")
    if not candidate.is_file():
        raise CommandError(f"{label} does not resolve to a project file: {locator!r}")


def verify_oracle_consistency(original_root: Path, variant_root: Path, manifest: Mapping[str, Any]) -> dict[str, Any]:
    if manifest.get("scanbench2_version") != GROUND_TRUTH_VERSION:
        raise CommandError(f"oracle scanbench2_version must be {GROUND_TRUTH_VERSION}")
    if manifest.get("oracle_consistency_version") != ORACLE_CONSISTENCY_VERSION:
        raise CommandError(f"oracle_consistency_version must be {ORACLE_CONSISTENCY_VERSION}")
    transformation_id = _required_string(manifest.get("transformation_id"), "oracle.transformation_id")
    if manifest.get("equivalence_claim") != "semantics-preserving":
        raise CommandError("oracle.equivalence_claim must be semantics-preserving")

    original_truth = load_ground_truth_file(original_root / "truth.json")
    variant_truth = load_ground_truth_file(variant_root / "truth.json")
    if manifest.get("original_project_id") != original_truth["project_id"]:
        raise CommandError("oracle original_project_id does not match original fixture")
    if manifest.get("variant_project_id") != variant_truth["project_id"]:
        raise CommandError("oracle variant_project_id does not match variant fixture")

    original_fixture = fixture_source_digest(original_root)
    variant_fixture = fixture_source_digest(variant_root)
    original_project = project_source_digest(original_root)
    variant_project = project_source_digest(variant_root)
    bindings = {
        "original_fixture_digest": original_fixture,
        "variant_fixture_digest": variant_fixture,
        "original_project_digest": original_project,
        "variant_project_digest": variant_project,
    }
    for key, expected in bindings.items():
        if manifest.get(key) != expected:
            raise CommandError(f"oracle {key} does not match current bytes")
    if original_project == variant_project:
        raise CommandError("oracle variant must change project source bytes; truth/identifier-only changes are insufficient")

    condition_map = _string_map(manifest.get("condition_map"), "oracle.condition_map")
    artifact_map = _string_map(manifest.get("artifact_map", {}), "oracle.artifact_map")
    original_by_id = {row["id"]: row for row in original_truth["conditions"]}
    variant_by_id = {row["id"]: row for row in variant_truth["conditions"]}
    if set(condition_map) != set(original_by_id):
        raise CommandError("oracle.condition_map must cover every original condition exactly")
    if set(condition_map.values()) != set(variant_by_id):
        raise CommandError("oracle.condition_map must cover every variant condition exactly")

    rows: list[dict[str, Any]] = []
    for original_id, variant_id in condition_map.items():
        original = original_by_id[original_id]
        variant = variant_by_id[variant_id]
        for field in ("truth", "family", "description", "rationale"):
            if original[field] != variant[field]:
                raise CommandError(
                    f"oracle drift for {original_id}->{variant_id}: {field} changed under semantics-preserving claim"
                )
        expected_variant_locators = []
        for locator in original["artifact_locators"]:
            original_locator = _canonical_locator(locator, f"{original_id}.artifact_locator")
            _assert_locator_exists(original_root, original_locator, label=f"{original_id}.artifact_locator")
            mapped = artifact_map.get(original_locator, original_locator)
            mapped = _canonical_locator(mapped, f"{variant_id}.mapped_artifact_locator")
            expected_variant_locators.append(mapped)
        actual_variant_locators = [
            _canonical_locator(locator, f"{variant_id}.artifact_locator")
            for locator in variant["artifact_locators"]
        ]
        if sorted(expected_variant_locators) != sorted(actual_variant_locators):
            raise CommandError(
                f"oracle artifact mapping mismatch for {original_id}->{variant_id}: "
                f"expected={sorted(expected_variant_locators)}, actual={sorted(actual_variant_locators)}"
            )
        for locator in actual_variant_locators:
            _assert_locator_exists(variant_root, locator, label=f"{variant_id}.artifact_locator")
        rows.append({
            "original_condition_id": original_id,
            "variant_condition_id": variant_id,
            "truth": original["truth"],
            "family": original["family"],
            "artifact_locators": actual_variant_locators,
        })

    return {
        "scanbench2_version": GROUND_TRUTH_VERSION,
        "oracle_consistency_version": ORACLE_CONSISTENCY_VERSION,
        "transformation_id": transformation_id,
        "equivalence_claim": "semantics-preserving",
        **bindings,
        "condition_count": len(rows),
        "conditions": rows,
        "oracle_consistent": True,
        "note": (
            "This verifies byte change and oracle invariance under the declared mapping. It does not independently prove "
            "that the source transformation preserves runtime semantics."
        ),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m scan_core.scanbench2_oracle_consistency")
    parser.add_argument("original_fixture", type=Path)
    parser.add_argument("variant_fixture", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)
    manifest = _load_manifest(args.manifest)
    result = verify_oracle_consistency(args.original_fixture, args.variant_fixture, manifest)
    if args.json:
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    else:
        print(
            f"CONSISTENT {result['transformation_id']} conditions={result['condition_count']} "
            f"source={result['original_project_digest']}->{result['variant_project_digest']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
