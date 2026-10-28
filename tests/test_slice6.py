"""Slice 6 ScanBench v1, project config, schema and release-hardening tests."""

from __future__ import annotations

import contextlib
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest

from scan_core import ScanConfig, __version__, build_egress_preview, canonical_state_json, scan_project, schema_object
from scan_core.cli import main
from scan_core.errors import ExitCode
from scan_core.scanbench import DIMENSIONS, _lock_file, format_bench, run_bench
from scan_core.validate import validate_path

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "scanbench"
MANDATORY = [
    "clean-minimal",
    "hidden-files",
    "symlink-escape",
    "prompt-injection",
    "secret-redaction",
    "malformed-filename",
    "unreadable-artifact",
    "archive-boundary",
    "unsupported-binary",
    "generated-and-vendor",
    "incomplete-discovery",
    "false-runtime-claim",
]


def _normalize_golden_state(state):
    value = deepcopy(state)
    value["run"]["scan_id"] = "<volatile-run-id>"
    value["run"]["started_at"] = "<volatile-time>"
    value["run"]["completed_at"] = "<volatile-time>"
    value["project"]["snapshot"]["time"] = "<volatile-time>"
    for row in value["artifacts"]:
        if row.get("inspected_at") is not None:
            row["inspected_at"] = "<volatile-time>"
    for row in value["evidence"]:
        row["time"] = "<volatile-time>"
        freshness = row.get("freshness")
        if isinstance(freshness, dict):
            freshness["original_observed_at"] = "<volatile-time>"
            if freshness.get("reused_at") is not None:
                freshness["reused_at"] = "<volatile-time>"
    return value


def _normalize_release_version(state):
    value = deepcopy(state)
    value["run"]["scan_version"] = "<release-version>"
    for row in value["provenance"]["tool_versions"]:
        if row.get("kind") == "scan-core" and row.get("name") == "scan-core":
            row["version"] = "<release-version>"
    for row in value["evidence"]:
        producer = row.get("producer")
        if isinstance(producer, dict) and producer.get("kind") == "scan-core" and producer.get("name") == "scan-core":
            producer["version"] = "<release-version>"
    return value


class ScanBenchReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.full_bench = run_bench(bench_root=BENCH)

    def test_manifest_has_exact_mandatory_v1_fixture_set(self):
        manifest = json.loads((BENCH / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["scanbench_version"], "1")
        self.assertEqual(manifest["fixtures"], MANDATORY)
        self.assertEqual(manifest["dimensions"], list(DIMENSIONS))

    def test_every_mandatory_fixture_has_contract_files(self):
        for name in MANDATORY:
            with self.subTest(name=name):
                base = BENCH / "fixtures" / name
                self.assertTrue((base / "fixture.json").is_file())
                self.assertTrue((base / "expected.json").is_file())
                self.assertTrue((base / "README.md").is_file())
                self.assertTrue((base / "project").is_dir())

    def test_full_scanbench_passes_all_fixtures_and_dimensions(self):
        self.assertTrue(self.full_bench.passed, format_bench(self.full_bench))
        self.assertEqual(len(self.full_bench.fixtures), 12)
        self.assertTrue(all(fixture.passed for fixture in self.full_bench.fixtures))
        self.assertEqual(self.full_bench.dimensions, {dimension: True for dimension in DIMENSIONS})
        self.assertNotIn("overall_score", self.full_bench.as_dict())

    def test_golden_clean_minimal_state_matches_after_only_allowed_volatiles(self):
        root = BENCH / "fixtures" / "clean-minimal" / "project"
        actual = _normalize_golden_state(scan_project(ScanConfig(root=root)).state)
        expected = json.loads((ROOT / "tests" / "golden" / "state" / "clean-minimal.json").read_text(encoding="utf-8"))
        self.assertEqual(actual["run"]["scan_version"], __version__)
        self.assertTrue(all(
            row["version"] == __version__
            for row in actual["provenance"]["tool_versions"]
            if row.get("kind") == "scan-core" and row.get("name") == "scan-core"
        ))
        self.assertTrue(all(
            row["producer"]["version"] == __version__
            for row in actual["evidence"]
            if row.get("producer", {}).get("kind") == "scan-core" and row.get("producer", {}).get("name") == "scan-core"
        ))
        self.assertEqual(_normalize_release_version(actual), _normalize_release_version(expected))

    def test_single_fixture_does_not_fake_unexercised_dimension_passes(self):
        result = run_bench(fixture="hidden-files", bench_root=BENCH)
        self.assertTrue(result.passed)
        self.assertTrue(result.dimensions["inventory_completeness"])
        self.assertIsNone(result.dimensions["privacy_integrity"])
        self.assertIsNone(result.dimensions["safety_boundary_compliance"])

    def test_cli_scan_bench_json_is_machine_readable_and_has_no_score(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        previous = Path.cwd()
        try:
            # locate_scanbench_root intentionally supports an installed CLI run from a checkout.
            import os
            os.chdir(ROOT)
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = main(["bench", "clean-minimal", "--json"])
        finally:
            os.chdir(previous)
        self.assertEqual(code, ExitCode.OK, stderr.getvalue())
        payload = json.loads(stdout.getvalue())
        self.assertTrue(payload["passed"])
        self.assertNotIn("overall_score", payload)
        self.assertEqual(payload["fixtures"][0]["name"], "clean-minimal")

    def test_cli_unknown_bench_fixture_is_command_error(self):
        previous = Path.cwd()
        try:
            import os
            os.chdir(ROOT)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = main(["bench", "does-not-exist"])
        finally:
            os.chdir(previous)
        self.assertEqual(code, ExitCode.COMMAND_ERROR)

    def test_offline_scan_opens_no_network_socket(self):
        from unittest.mock import patch
        root = BENCH / "fixtures" / "clean-minimal" / "project"
        with patch("socket.socket", side_effect=AssertionError("network socket opened")):
            state = scan_project(ScanConfig(root=root, privacy_mode="offline")).state
        self.assertFalse(state["run"]["network_used"])

    def test_unreadable_error_state_does_not_serialize_host_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "locked.txt"
            target.write_text("locked", encoding="utf-8")
            with _lock_file(target):
                state = scan_project(ScanConfig(root=root)).state
            serialized = canonical_state_json(state)
            self.assertNotIn(str(root), serialized)
            self.assertEqual(state["coverage"]["unreadable_artifact_count"], 1)

    def test_cli_egress_excludes_scan_owned_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.txt").write_text("fixture", encoding="utf-8")
            scan_project(ScanConfig(
                root=root,
                output_state=root / ".scan" / "state.json",
                output_html=root / ".scan" / "report.html",
            ))
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                code = main(["egress", str(root), "--json"])
            self.assertEqual(code, ExitCode.OK)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["files_selected"], 1)

    def test_public_egress_preview_api_accepts_canonical_state(self):
        root = BENCH / "fixtures" / "secret-redaction" / "project"
        state = scan_project(ScanConfig(root=root, redaction_level="standard")).state
        preview = build_egress_preview(state)
        self.assertEqual(preview.network_action, "none")
        self.assertGreaterEqual(preview.redaction_count, 1)
        self.assertEqual(preview.redaction_count, state["privacy"]["redaction_count"])

    def test_bundled_schemas_are_parseable_and_versioned(self):
        schema12 = schema_object("1.2")
        schema13 = schema_object("1.3")
        self.assertEqual(schema12["properties"]["schema_version"]["const"], "1.2")
        self.assertEqual(schema13["properties"]["schema_version"]["const"], "1.3")
        self.assertIn("run", schema13["required"])
        self.assertIn("privacy", schema13["required"])
        self.assertIn("provenance", schema13["required"])

    def test_cli_schema_prints_requested_json_schema(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            code = main(["schema", "--version", "1.3"])
        self.assertEqual(code, ExitCode.OK)
        self.assertEqual(json.loads(stdout.getvalue())["properties"]["schema_version"]["const"], "1.3")

    def test_project_config_applies_when_cli_does_not_override(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "project"
            root.mkdir()
            (root / "app.txt").write_text("abcdef", encoding="utf-8")
            config_dir = root / ".scan"
            config_dir.mkdir()
            (config_dir / "config.toml").write_text(
                "[scan]\nprivacy = \"local\"\nredact = \"strict\"\nmax_file_bytes = 3\n"
                "max_total_bytes = 100\nfollow_internal_links = false\n"
                "[exclude]\npatterns = [\"ignored/**\"]\n",
                encoding="utf-8",
            )
            output = Path(directory) / "state.json"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = main([str(root), "--no-html", "--state", str(output), "--quiet"])
            self.assertEqual(code, ExitCode.OK)
            state = validate_path(output)
            self.assertEqual(state["privacy"]["mode"], "local")
            self.assertEqual(state["privacy"]["redaction_level"], "strict")
            row = next(item for item in state["artifacts"] if item["locator"] == "app.txt")
            self.assertEqual(row["status"], "partial")

    def test_cli_overrides_project_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "project"
            root.mkdir()
            (root / "app.txt").write_text("abcdef", encoding="utf-8")
            config_dir = root / ".scan"
            config_dir.mkdir()
            (config_dir / "config.toml").write_text(
                "[scan]\nprivacy = \"local\"\nredact = \"strict\"\nmax_file_bytes = 1\n",
                encoding="utf-8",
            )
            output = Path(directory) / "state.json"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = main([
                    str(root), "--no-html", "--state", str(output), "--quiet",
                    "--privacy", "offline", "--redact", "none", "--max-file-bytes", "100",
                ])
            self.assertEqual(code, ExitCode.OK)
            state = validate_path(output)
            self.assertEqual(state["privacy"]["mode"], "offline")
            self.assertEqual(state["privacy"]["redaction_level"], "none")
            row = next(item for item in state["artifacts"] if item["locator"] == "app.txt")
            self.assertEqual(row["status"], "content_read")

    def test_offline_shorthand_overrides_project_local_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "project"
            root.mkdir()
            (root / "app.txt").write_text("x", encoding="utf-8")
            (root / ".scan").mkdir()
            (root / ".scan" / "config.toml").write_text('[scan]\nprivacy = "local"\n', encoding="utf-8")
            output = Path(directory) / "state.json"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = main([str(root), "--offline", "--no-html", "--state", str(output), "--quiet"])
            self.assertEqual(code, ExitCode.OK)
            self.assertEqual(validate_path(output)["privacy"]["mode"], "offline")

    def test_invalid_project_config_is_command_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.txt").write_text("x", encoding="utf-8")
            (root / ".scan").mkdir()
            (root / ".scan" / "config.toml").write_text('[scan]\nunknown = true\n', encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = main([str(root), "--no-html", "--state", str(Path(directory) / "out.json")])
            self.assertEqual(code, ExitCode.COMMAND_ERROR)


if __name__ == "__main__":
    unittest.main()
