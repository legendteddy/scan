"""Scan v0.3 Slice 1: state 1.4 and pure comparison primitives."""

from __future__ import annotations

from copy import deepcopy
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from scan_core import Comparison, ScanConfig, compare_states, scan_project, schema_object, state_digest, validate_state
from scan_core.cli import main
from scan_core.errors import ExitCode, ValidationError


def _scan(files: dict[str, str]) -> dict:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for locator, content in files.items():
            target = root / locator
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return scan_project(ScanConfig(root=root)).state


def _add_finding(state: dict, ident: str = "finding:test", *, recommendation: str = "review") -> None:
    artifact = next(row for row in state["artifacts"] if row["evidence_ids"])
    state["findings"].append({
        "id": ident,
        "title": "Synthetic finding",
        "impact": "Synthetic impact",
        "severity": "medium",
        "confidence": "high",
        "verification_state": "static",
        "artifact_ids": [artifact["id"]],
        "evidence_ids": [artifact["evidence_ids"][0]],
        "uncertainty": "Synthetic uncertainty",
        "recommendation": recommendation,
        "safe_verification": "Inspect the synthetic fixture",
    })


def _add_unknown(state: dict, ident: str, *, reason: str = "unknown") -> None:
    state["unknowns"].append({
        "id": ident,
        "question": "Synthetic question?",
        "artifact_ids": [],
        "evidence_ids": [],
        "reason": reason,
        "impact": "Synthetic impact",
        "next_safe_step": "Inspect fixture",
    })


def _empty_delta() -> dict:
    return {
        "available": False,
        "artifacts": {"added": [], "changed": [], "removed": [], "unchanged": []},
        "findings": {"new": [], "resolved": [], "persisting": [], "modified": []},
        "unknowns": {"new": [], "resolved": [], "persisting": [], "modified": []},
    }


def _state_14(current: dict, previous: dict | None = None) -> dict:
    state = deepcopy(current)
    state["schema_version"] = "1.4"
    if previous is None:
        state["baseline"] = {
            "mode": "none",
            "status": "disabled",
            "source_schema_version": None,
            "source_state_digest": None,
            "source_snapshot_digest": None,
            "snapshot_relation": "none",
            "reuse_enabled": False,
            "fresh_evidence_count": len(state["evidence"]),
            "reused_evidence_count": 0,
            "rejected_reuse_count": 0,
            "rejected_reuse_reasons": {},
        }
        state["delta"] = _empty_delta()
        return state

    comparison = compare_states(previous, current)
    payload = comparison.as_dict()
    state["baseline"] = {
        "mode": "explicit",
        "status": "used",
        "source_schema_version": previous["schema_version"],
        "source_state_digest": state_digest(previous),
        "source_snapshot_digest": previous["provenance"]["snapshot_digest"],
        "snapshot_relation": comparison.snapshot_relation,
        "reuse_enabled": True,
        "fresh_evidence_count": len(state["evidence"]),
        "reused_evidence_count": 0,
        "rejected_reuse_count": 0,
        "rejected_reuse_reasons": {},
    }
    state["delta"] = {
        "available": True,
        "artifacts": payload["artifacts"],
        "findings": payload["findings"],
        "unknowns": payload["unknowns"],
    }
    return state


class ScanV03Slice1Tests(unittest.TestCase):
    def test_state_digest_is_canonical_and_includes_run_metadata(self):
        state = _scan({"app.py": "print('x')\n"})
        reordered = dict(reversed(list(state.items())))
        self.assertEqual(state_digest(state), state_digest(reordered))
        changed = deepcopy(state)
        changed["run"]["completed_at"] = "2099-01-01T00:00:00Z"
        self.assertNotEqual(state_digest(state), state_digest(changed))

    def test_artifact_comparison_covers_unchanged_changed_added_removed(self):
        old = _scan({"same.txt": "same", "changed.txt": "old", "removed.txt": "gone"})
        new = _scan({"same.txt": "same", "changed.txt": "new", "added.txt": "new"})
        comparison = compare_states(old, new)
        old_by_locator = {row["locator"]: row["id"] for row in old["artifacts"]}
        new_by_locator = {row["locator"]: row["id"] for row in new["artifacts"]}
        self.assertEqual(comparison.artifacts["unchanged"], (old_by_locator["same.txt"],))
        self.assertEqual(comparison.artifacts["changed"], (old_by_locator["changed.txt"],))
        self.assertEqual(comparison.artifacts["removed"], (old_by_locator["removed.txt"],))
        self.assertEqual(comparison.artifacts["added"], (new_by_locator["added.txt"],))
        self.assertEqual(comparison.snapshot_relation, "changed")
        self.assertEqual(comparison.comparison_time, new["run"]["completed_at"])

    def test_identical_bytes_at_new_path_are_removed_plus_added_not_rename(self):
        old = _scan({"old/path.py": "same bytes\n"})
        new = _scan({"new/path.py": "same bytes\n"})
        comparison = compare_states(old, new)
        old_file = next(row for row in old["artifacts"] if row["locator"] == "old/path.py")
        new_file = next(row for row in new["artifacts"] if row["locator"] == "new/path.py")
        self.assertIn(old_file["id"], comparison.artifacts["removed"])
        self.assertIn(new_file["id"], comparison.artifacts["added"])
        self.assertNotIn(old_file["id"], comparison.artifacts["changed"])
        self.assertNotIn(new_file["id"], comparison.artifacts["changed"])

    def test_collection_order_and_object_key_order_do_not_change_comparison(self):
        old = _scan({"a.txt": "a", "b.txt": "b"})
        new = _scan({"a.txt": "a", "b.txt": "changed", "c.txt": "c"})
        expected = compare_states(old, new)
        old_reordered = dict(reversed(list(old.items())))
        new_reordered = dict(reversed(list(new.items())))
        old_reordered["artifacts"] = list(reversed(old_reordered["artifacts"]))
        new_reordered["artifacts"] = list(reversed(new_reordered["artifacts"]))
        actual = compare_states(old_reordered, new_reordered)
        self.assertEqual(actual.artifacts, expected.artifacts)
        self.assertEqual(actual.findings, expected.findings)
        self.assertEqual(actual.unknowns, expected.unknowns)
        self.assertEqual(actual.snapshot_relation, expected.snapshot_relation)
        self.assertEqual(actual.comparison_time, expected.comparison_time)

    def test_findings_classify_new_resolved_persisting_and_modified(self):
        old = _scan({"app.txt": "same"})
        new = deepcopy(old)
        _add_finding(old, "finding:resolved")
        _add_finding(old, "finding:persist", recommendation="old")
        _add_finding(new, "finding:persist", recommendation="new")
        _add_finding(new, "finding:new")
        comparison = compare_states(old, new)
        self.assertEqual(comparison.findings["new"], ("finding:new",))
        self.assertEqual(comparison.findings["resolved"], ("finding:resolved",))
        self.assertEqual(comparison.findings["persisting"], ("finding:persist",))
        self.assertEqual(comparison.findings["modified"], ("finding:persist",))

    def test_unknown_timestamp_only_change_is_not_modified(self):
        old = _scan({"app.txt": "same"})
        new = deepcopy(old)
        _add_unknown(old, "unknown:timed")
        _add_unknown(new, "unknown:timed")
        old["unknowns"][-1]["updated_at"] = "2026-01-01T00:00:00Z"
        new["unknowns"][-1]["updated_at"] = "2026-02-01T00:00:00Z"
        comparison = compare_states(old, new)
        self.assertIn("unknown:timed", comparison.unknowns["persisting"])
        self.assertNotIn("unknown:timed", comparison.unknowns["modified"])

    def test_id_array_order_does_not_make_finding_modified(self):
        old = _scan({"a.txt": "a", "b.txt": "b"})
        new = deepcopy(old)
        first, second = [row for row in old["artifacts"] if row["path_kind"] == "file"]
        _add_finding(old, "finding:order")
        _add_finding(new, "finding:order")
        old["findings"][-1]["artifact_ids"] = [first["id"], second["id"]]
        new["findings"][-1]["artifact_ids"] = [second["id"], first["id"]]
        comparison = compare_states(old, new)
        self.assertNotIn("finding:order", comparison.findings["modified"])

    def test_compare_accepts_13_and_14_without_rewriting_inputs(self):
        old = _scan({"app.txt": "old"})
        current = _scan({"app.txt": "new"})
        current14 = _state_14(current)
        before = deepcopy(current14)
        comparison = compare_states(old, current14)
        self.assertIsInstance(comparison, Comparison)
        self.assertEqual(comparison.current_schema_version, "1.4")
        self.assertEqual(current14, before)

    def test_schema_14_disabled_baseline_state_validates(self):
        state = _state_14(_scan({"app.txt": "x"}))
        self.assertIs(validate_state(state), state)

    def test_schema_14_used_baseline_delta_validates(self):
        old = _scan({"a.txt": "a", "remove.txt": "x"})
        new = _scan({"a.txt": "changed", "add.txt": "y"})
        state = _state_14(new, old)
        self.assertIs(validate_state(state), state)

    def test_schema_14_rejects_invalid_current_delta_reference(self):
        state = _state_14(_scan({"app.txt": "x"}))
        state["baseline"].update({
            "mode": "explicit",
            "status": "used",
            "source_schema_version": "1.3",
            "source_state_digest": "sha256:" + "1" * 64,
            "source_snapshot_digest": "sha256:" + "2" * 64,
            "snapshot_relation": "changed",
        })
        state["delta"]["available"] = True
        state["delta"]["artifacts"]["added"] = ["artifact:not-present"]
        with self.assertRaises(ValidationError):
            validate_state(state)

    def test_schema_14_rejects_modified_not_in_persisting(self):
        state = _state_14(_scan({"app.txt": "x"}))
        state["baseline"].update({
            "mode": "explicit",
            "status": "used",
            "source_schema_version": "1.3",
            "source_state_digest": "sha256:" + "1" * 64,
            "source_snapshot_digest": "sha256:" + "2" * 64,
            "snapshot_relation": "changed",
        })
        state["delta"]["available"] = True
        state["delta"]["unknowns"]["modified"] = [state["unknowns"][0]["id"]]
        with self.assertRaises(ValidationError):
            validate_state(state)

    def test_bundled_schema_14_and_cli_schema_are_available(self):
        schema = schema_object("1.4")
        self.assertEqual(schema["properties"]["schema_version"]["const"], "1.4")
        self.assertIn("baseline", schema["required"])
        self.assertIn("delta", schema["required"])
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            code = main(["schema", "--version", "1.4"])
        self.assertEqual(code, ExitCode.OK)
        self.assertEqual(json.loads(stdout.getvalue())["properties"]["schema_version"]["const"], "1.4")

    def test_compare_rejects_historical_12_state(self):
        state = _scan({"app.txt": "x"})
        historical = deepcopy(state)
        historical["schema_version"] = "1.2"
        historical.pop("run")
        historical.pop("privacy")
        historical.pop("provenance")
        with self.assertRaises(ValidationError):
            compare_states(historical, state)


if __name__ == "__main__":
    unittest.main()
