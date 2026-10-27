"""Scan v0.3 Slice 2 automatic baseline and compare workflow tests."""

from __future__ import annotations

import contextlib
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scan_core import ScanConfig, canonical_state_json, scan_project, state_digest, validate_path, validate_state
from scan_core.cli import main
from scan_core.errors import ExitCode


def _write_project(root: Path, files: dict[str, str]) -> None:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def _state13_from(state14: dict) -> dict:
    state = deepcopy(state14)
    state["schema_version"] = "1.3"
    state.pop("baseline", None)
    state.pop("delta", None)
    validate_state(state, version="1.3")
    return state


class BaselineSliceTests(unittest.TestCase):
    def test_first_run_records_not_found_and_state_14(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_project(root, {"a.txt": "one"})
            output = root / ".scan" / "state.json"
            result = scan_project(ScanConfig(root=root, output_state=output))
            self.assertEqual(result.state["schema_version"], "1.4")
            self.assertEqual(result.state["baseline"]["status"], "not_found")
            self.assertFalse(result.state["delta"]["available"])
            validate_path(output)

    def test_second_run_uses_previous_state_before_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_project(root, {"same.txt": "same", "change.txt": "old", "remove.txt": "gone"})
            state_path = root / ".scan" / "state.json"
            report_path = root / ".scan" / "report.html"
            first = scan_project(ScanConfig(root=root, output_state=state_path, output_html=report_path))
            first_digest = state_digest(first.state)
            (root / "change.txt").write_text("new", encoding="utf-8")
            (root / "remove.txt").unlink()
            (root / "added.txt").write_text("added", encoding="utf-8")
            second = scan_project(ScanConfig(root=root, output_state=state_path, output_html=report_path))
            self.assertEqual(second.state["baseline"]["status"], "used")
            self.assertEqual(second.state["baseline"]["source_state_digest"], first_digest)
            self.assertTrue(second.state["delta"]["available"])
            self.assertEqual(len(second.state["delta"]["artifacts"]["added"]), 1)
            self.assertEqual(len(second.state["delta"]["artifacts"]["changed"]), 1)
            self.assertEqual(len(second.state["delta"]["artifacts"]["removed"]), 1)
            self.assertGreaterEqual(len(second.state["delta"]["artifacts"]["unchanged"]), 1)
            self.assertEqual(validate_path(state_path)["baseline"]["source_state_digest"], first_digest)
            self.assertEqual(validate_path(report_path)["baseline"]["source_state_digest"], first_digest)
            self.assertIn("Since baseline", report_path.read_text(encoding="utf-8"))

    def test_baseline_none_disables_comparison_even_when_prior_state_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_project(root, {"a.txt": "one"})
            output = root / ".scan" / "state.json"
            scan_project(ScanConfig(root=root, output_state=output))
            result = scan_project(ScanConfig(root=root, output_state=output, baseline_mode="none", reuse_enabled=False))
            self.assertEqual(result.state["baseline"]["mode"], "none")
            self.assertEqual(result.state["baseline"]["status"], "disabled")
            self.assertFalse(result.state["delta"]["available"])

    def test_explicit_valid_13_baseline_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "project"
            root.mkdir()
            _write_project(root, {"a.txt": "one"})
            initial = scan_project(ScanConfig(root=root, baseline_mode="none", reuse_enabled=False)).state
            historical = _state13_from(initial)
            baseline_path = base / "baseline-13.json"
            baseline_path.write_text(canonical_state_json(historical) + "\n", encoding="utf-8")
            (root / "a.txt").write_text("two", encoding="utf-8")
            result = scan_project(ScanConfig(
                root=root,
                output_state=base / "new.json",
                baseline_mode="explicit",
                baseline_path=baseline_path,
            ))
            self.assertEqual(result.state["baseline"]["status"], "used")
            self.assertEqual(result.state["baseline"]["source_schema_version"], "1.3")
            self.assertTrue(result.state["delta"]["available"])

    def test_explicit_invalid_baseline_fails_before_output_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "project"
            root.mkdir()
            _write_project(root, {"a.txt": "one"})
            bad = base / "bad.json"
            bad.write_text('{"schema_version":"1.4"}', encoding="utf-8")
            output = base / "state.json"
            output.write_text("DO NOT REPLACE", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = main([str(root), "--no-html", "--state", str(output), "--baseline", str(bad)])
            self.assertEqual(code, ExitCode.VALIDATION_FAILED)
            self.assertEqual(output.read_text(encoding="utf-8"), "DO NOT REPLACE")

    def test_missing_explicit_baseline_is_source_error_before_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "project"
            root.mkdir()
            _write_project(root, {"a.txt": "one"})
            output = base / "state.json"
            output.write_text("KEEP", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = main([str(root), "--no-html", "--state", str(output), "--baseline", str(base / "missing.json")])
            self.assertEqual(code, ExitCode.SOURCE_ERROR)
            self.assertEqual(output.read_text(encoding="utf-8"), "KEEP")

    def test_invalid_automatic_baseline_warns_and_continues_fresh(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_project(root, {"a.txt": "one"})
            state_path = root / ".scan" / "state.json"
            state_path.parent.mkdir()
            state_path.write_text("not-json", encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
                code = main([str(root), "--no-html", "--state", str(state_path)])
            self.assertEqual(code, ExitCode.OK)
            state = validate_path(state_path)
            self.assertEqual(state["baseline"]["status"], "invalid")
            self.assertFalse(state["delta"]["available"])
            self.assertIn("Automatic baseline ignored", stderr.getvalue())

    def test_scan_compare_json_is_deterministic_and_does_not_rescan(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "project"
            root.mkdir()
            _write_project(root, {"a.txt": "one"})
            old = scan_project(ScanConfig(root=root, baseline_mode="none", reuse_enabled=False)).state
            old_path = base / "old.json"
            old_path.write_text(canonical_state_json(old) + "\n", encoding="utf-8")
            (root / "a.txt").write_text("two", encoding="utf-8")
            new = scan_project(ScanConfig(root=root, baseline_mode="none", reuse_enabled=False)).state
            new_path = base / "new.json"
            new_path.write_text(canonical_state_json(new) + "\n", encoding="utf-8")
            stdout1 = io.StringIO()
            stdout2 = io.StringIO()
            with contextlib.redirect_stdout(stdout1), contextlib.redirect_stderr(io.StringIO()):
                code1 = main(["compare", str(old_path), str(new_path), "--json"])
            with contextlib.redirect_stdout(stdout2), contextlib.redirect_stderr(io.StringIO()):
                code2 = main(["compare", str(old_path), str(new_path), "--json"])
            self.assertEqual((code1, code2), (ExitCode.OK, ExitCode.OK))
            self.assertEqual(stdout1.getvalue(), stdout2.getvalue())
            payload = json.loads(stdout1.getvalue())
            self.assertEqual(payload["snapshot_relation"], "changed")
            self.assertEqual(len(payload["artifacts"]["changed"]), 1)

    def test_cli_no_reuse_records_policy_without_reusing_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_project(root, {"a.txt": "one"})
            state_path = root / ".scan" / "state.json"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main([str(root), "--no-html", "--state", str(state_path)]), ExitCode.OK)
                self.assertEqual(main([str(root), "--no-html", "--state", str(state_path), "--no-reuse"]), ExitCode.OK)
            state = validate_path(state_path)
            self.assertEqual(state["baseline"]["status"], "used")
            self.assertFalse(state["baseline"]["reuse_enabled"])
            self.assertEqual(state["baseline"]["reused_evidence_count"], 0)

    def test_project_baseline_config_is_respected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_project(root, {"a.txt": "one"})
            (root / ".scan").mkdir()
            (root / ".scan" / "config.toml").write_text(
                '[baseline]\nmode = "none"\nreuse = false\nmax_state_bytes = 123456\n',
                encoding="utf-8",
            )
            result = scan_project(ScanConfig(root=root, baseline_mode="none", reuse_enabled=False, max_baseline_state_bytes=123456))
            self.assertEqual(result.state["baseline"]["status"], "disabled")
            stdout = io.StringIO()
            state_path = root / ".scan" / "state.json"
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                code = main([str(root), "--no-html", "--state", str(state_path), "--json"])
            self.assertEqual(code, ExitCode.OK)
            state = validate_path(state_path)
            self.assertEqual(state["baseline"]["mode"], "none")
            self.assertFalse(state["baseline"]["reuse_enabled"])

    def test_explicit_oversized_baseline_uses_resource_limit_exit_and_preserves_output(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "project"
            root.mkdir()
            _write_project(root, {"a.txt": "one"})
            (root / ".scan").mkdir()
            (root / ".scan" / "config.toml").write_text(
                '[baseline]\nmax_state_bytes = 1\n',
                encoding="utf-8",
            )
            baseline = base / "baseline.json"
            valid = scan_project(ScanConfig(root=root, baseline_mode="none", reuse_enabled=False)).state
            baseline.write_text(canonical_state_json(valid) + "\n", encoding="utf-8")
            output = base / "state.json"
            output.write_text("KEEP", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = main([str(root), "--no-html", "--state", str(output), "--baseline", str(baseline)])
            self.assertEqual(code, ExitCode.RESOURCE_LIMIT)
            self.assertEqual(output.read_text(encoding="utf-8"), "KEEP")

    def test_failed_new_state_validation_keeps_prior_automatic_baseline_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_project(root, {"a.txt": "one"})
            output = root / ".scan" / "state.json"
            first = scan_project(ScanConfig(root=root, output_state=output))
            previous_bytes = output.read_bytes()
            (root / "a.txt").write_text("changed", encoding="utf-8")
            with patch("scan_core.core.validate_state", side_effect=ValueError("synthetic validation failure")):
                with self.assertRaisesRegex(ValueError, "synthetic validation failure"):
                    scan_project(ScanConfig(root=root, output_state=output))
            self.assertEqual(output.read_bytes(), previous_bytes)
            self.assertEqual(validate_path(output)["run"]["scan_id"], first.state["run"]["scan_id"])

    def test_explicit_baseline_path_is_not_part_of_configuration_digest(self):
        from scan_core import configuration_digest
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            one = ScanConfig(root=root, baseline_mode="explicit", baseline_path=root / "one.json")
            two = ScanConfig(root=root, baseline_mode="explicit", baseline_path=root / "two.json")
            self.assertEqual(configuration_digest(one), configuration_digest(two))


if __name__ == "__main__":
    unittest.main()
