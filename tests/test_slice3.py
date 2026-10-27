"""Slice 3 canonical Scan 1.3 state and state-only CLI tests."""

from __future__ import annotations

import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest

from scan_core import (
    ScanConfig,
    build_inventory,
    build_snapshot,
    build_state,
    canonical_state_json,
    configuration_digest,
    scan_project,
)
from scan_core.cli import main
from scan_core.errors import ExitCode, ValidationError
from scan_core.validate import load_report_state, validate_path, validate_state

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "scanbench" / "fixtures" / "inventory-basic" / "target"
DEMO = ROOT / "examples" / "demo-report.html"
STAMP = "2026-10-27T00:00:00Z"


def fixture_state(root: Path = FIXTURE, **config_overrides):
    config = ScanConfig(root=root, **config_overrides)
    inventory = build_inventory(config)
    snapshot = build_snapshot(inventory)
    state = build_state(config, inventory, snapshot, started_at=STAMP, completed_at=STAMP)
    return config, inventory, snapshot, state


class State13Tests(unittest.TestCase):
    def test_generated_state_13_validates(self):
        _config, _inventory, snapshot, state = fixture_state()
        validated = validate_state(state, version="1.3")
        self.assertEqual(validated["schema_version"], "1.3")
        self.assertEqual(state["provenance"]["snapshot_digest"], snapshot.digest)

    def test_deterministic_core_never_promotes_hashing_to_analyzed(self):
        _config, _inventory, _snapshot, state = fixture_state()
        statuses = {row["locator"]: row["status"] for row in state["artifacts"]}
        self.assertEqual(statuses["-leading.txt"], "content_read")
        self.assertEqual(statuses["nested"], "metadata_only")
        self.assertNotIn("analyzed", statuses.values())
        self.assertFalse(state["coverage"]["analysis_complete"])

    def test_inventory_check_is_the_only_assessed_category(self):
        _config, _inventory, _snapshot, state = fixture_state()
        assessed = [row for row in state["checks"] if row["status"] == "assessed"]
        self.assertEqual([row["category"] for row in assessed], ["inventory_and_provenance"])
        self.assertEqual(state["coverage"]["counts_by_check_status"]["assessed"], 1)
        self.assertEqual(state["coverage"]["counts_by_check_status"]["not_assessed"], 13)
        self.assertFalse(state["coverage"]["checks_complete"])

    def test_state_records_no_execution_no_network_no_egress(self):
        _config, _inventory, _snapshot, state = fixture_state(privacy_mode="controlled-remote")
        self.assertFalse(state["run"]["target_executed"])
        self.assertFalse(state["run"]["network_used"])
        self.assertFalse(state["privacy"]["egress_performed"])
        self.assertEqual(state["privacy"]["egress_bytes"], 0)

    def test_configuration_digest_ignores_output_destination_but_tracks_behavior(self):
        base = ScanConfig(root=FIXTURE, output_state=Path("a.json"))
        other_output = ScanConfig(root=FIXTURE, output_state=Path("b.json"))
        changed_limit = ScanConfig(root=FIXTURE, output_state=Path("a.json"), max_file_bytes=123)
        self.assertEqual(configuration_digest(base), configuration_digest(other_output))
        self.assertNotEqual(configuration_digest(base), configuration_digest(changed_limit))

    def test_canonical_serialization_is_stable(self):
        _config, _inventory, _snapshot, state = fixture_state()
        first = canonical_state_json(state)
        second = canonical_state_json(json.loads(first))
        self.assertEqual(first, second)

    def test_absolute_local_root_path_is_not_serialized(self):
        _config, inventory, _snapshot, state = fixture_state()
        serialized = canonical_state_json(state)
        self.assertNotIn(str(inventory.root), serialized)
        self.assertEqual(state["project"]["source_locators"], ["."])

    def test_evidence_requires_producer_and_source_digest(self):
        _config, _inventory, _snapshot, state = fixture_state()
        broken = copy.deepcopy(state)
        del broken["evidence"][0]["producer"]
        with self.assertRaisesRegex(ValidationError, "producer"):
            validate_state(broken)

    def test_offline_state_rejects_network_used(self):
        _config, _inventory, _snapshot, state = fixture_state()
        broken = copy.deepcopy(state)
        broken["run"]["network_used"] = True
        with self.assertRaisesRegex(ValidationError, "network"):
            validate_state(broken)

    def test_run_completion_cannot_precede_start(self):
        _config, _inventory, _snapshot, state = fixture_state()
        broken = copy.deepcopy(state)
        broken["run"]["started_at"] = "2026-10-27T01:00:00Z"
        broken["run"]["completed_at"] = "2026-10-27T00:00:00Z"
        with self.assertRaisesRegex(ValidationError, "cannot precede"):
            validate_state(broken)

    def test_tool_version_provenance_is_typed(self):
        _config, _inventory, _snapshot, state = fixture_state()
        broken = copy.deepcopy(state)
        broken["provenance"]["tool_versions"] = [{"kind": "scan-core", "name": "scan-core"}]
        with self.assertRaisesRegex(ValidationError, "version"):
            validate_state(broken)

    def test_simple_relabel_of_12_report_is_rejected(self):
        old_state = load_report_state(DEMO)
        old_state["schema_version"] = "1.3"
        with self.assertRaisesRegex(ValidationError, "run"):
            validate_state(old_state)

    def test_resource_limits_are_explicit_and_prevent_inventory_assessment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "large.bin").write_bytes(b"abcdef")
            config, inventory, _snapshot, state = fixture_state(root, max_file_bytes=2)
            self.assertFalse(inventory.identity_complete)
            self.assertTrue(state["coverage"]["resource_limits_hit"])
            check = next(row for row in state["checks"] if row["category"] == "inventory_and_provenance")
            self.assertEqual(check["status"], "partial")
            validate_state(state)

    def test_empty_project_state_is_honest_and_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            _config, _inventory, _snapshot, state = fixture_state(Path(directory))
            check = next(row for row in state["checks"] if row["category"] == "inventory_and_provenance")
            self.assertEqual(check["status"], "not_assessed")
            self.assertEqual(state["coverage"]["discovered_artifact_count"], 0)
            validate_state(state)

    def test_scan_project_writes_valid_canonical_json(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "state.json"
            result = scan_project(ScanConfig(root=FIXTURE, output_state=output))
            self.assertEqual(result.completion, "partial")
            self.assertEqual(result.state_path, output)
            loaded = validate_path(output)
            self.assertEqual(loaded["schema_version"], "1.3")
            self.assertEqual(output.read_text(encoding="utf-8").rstrip("\n"), canonical_state_json(result.state))

    def test_scan_owned_output_inside_target_does_not_change_repeat_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.txt").write_text("same", encoding="utf-8")
            output = root / ".scan" / "state.json"
            first = scan_project(ScanConfig(root=root, output_state=output))
            second = scan_project(ScanConfig(root=root, output_state=output))
            self.assertEqual(first.state["provenance"]["snapshot_digest"], second.state["provenance"]["snapshot_digest"])
            self.assertEqual(first.state["extensions"]["tool_owned_omissions"], [".scan", ".scan/**"])
            self.assertNotIn(".scan/state.json", [row["locator"] for row in second.state["artifacts"]])

    def test_cli_state_only_scan_succeeds(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "state.json"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = main([str(FIXTURE), "--no-html", "--state", str(output), "--json"])
            self.assertEqual(code, ExitCode.OK)
            self.assertTrue(output.exists())
            self.assertEqual(validate_path(output)["schema_version"], "1.3")

    def test_cli_default_html_path_is_supported_after_renderer_slice(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            report_path = Path(directory) / "report.html"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = main([
                    str(FIXTURE),
                    "--state", str(state_path),
                    "--output", str(report_path),
                    "--quiet",
                ])
            self.assertEqual(code, ExitCode.OK)
            self.assertTrue(report_path.is_file())

    def test_cli_fail_on_partial_returns_coverage_exit_after_writing_state(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "state.json"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = main([str(FIXTURE), "--no-html", "--state", str(output), "--fail-on", "PARTIAL"])
            self.assertEqual(code, ExitCode.COVERAGE_THRESHOLD)
            self.assertTrue(output.exists())


if __name__ == "__main__":
    unittest.main()
