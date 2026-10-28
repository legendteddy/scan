"""v0.5 reusable GitHub Action contract tests."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scan_core import ScanConfig, scan_project
from scan_core.github_ci import github_outputs, github_summary

ROOT = Path(__file__).resolve().parents[1]


class GitHubSummaryTests(unittest.TestCase):
    def test_core_summary_keeps_zero_findings_separate_from_unknowns(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("answer = 42\n", encoding="utf-8")
            state = scan_project(ScanConfig(root=root, baseline_mode="none")).state
        text = github_summary(state)
        self.assertIn("Canonical findings | 0", text)
        self.assertIn("Unknowns |", text)
        self.assertIn("Zero findings is not a clean bill of health", text)
        self.assertIn("Semantic analysis complete | no", text)
        self.assertNotIn("safe", text.lower().replace("not a clean bill of health", ""))

    def test_outputs_are_machine_readable_and_absolute(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.txt").write_text("a\n", encoding="utf-8")
            state = scan_project(ScanConfig(root=root, baseline_mode="none")).state
            output = root / "out"
            output.mkdir()
            values = github_outputs(
                state,
                state_path=output / "state.json",
                report_path=output / "report.html",
                sarif_path=output / "results.sarif",
                summary_path=output / "summary.md",
            )
        self.assertTrue(Path(values["state"]).is_absolute())
        self.assertEqual(values["findings-count"], "0")
        self.assertEqual(values["analysis-complete"], "false")
        self.assertEqual(values["checks-total"], "14")
        self.assertEqual(values["delta-available"], "false")
        self.assertEqual(values["artifacts-added"], "")
        self.assertEqual(values["findings-new"], "")

    def test_validated_delta_is_rendered_without_overclaiming_resolution(self):
        state = {
            "producer": {"version": "0.4.0"},
            "run": {"scan_id": "scan:test"},
            "coverage": {"analysis_complete": False, "checks_complete": False, "discovery_complete": True},
            "artifacts": [],
            "checks": [],
            "findings": [],
            "unknowns": [],
            "baseline": {"status": "used"},
            "delta": {
                "available": True,
                "artifacts": {"added": ["a1"], "changed": ["a2", "a3"], "removed": ["a4"], "unchanged": []},
                "findings": {"new": ["f1"], "modified": ["f2"], "resolved": ["f3", "f4"], "persisting": []},
                "unknowns": {"new": [], "modified": ["u1"], "resolved": ["u2"], "persisting": []},
            },
        }
        text = github_summary(state)
        self.assertIn("Since validated baseline", text)
        self.assertIn("Artifacts changed | 2", text)
        self.assertIn("Findings resolved | 2", text)
        self.assertIn("not proof that a problem was fixed", text)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            values = github_outputs(
                state,
                state_path=root / "state.json", report_path=root / "report.html",
                sarif_path=root / "results.sarif", summary_path=root / "summary.md",
            )
        self.assertEqual(values["delta-available"], "true")
        self.assertEqual(values["artifacts-changed"], "2")
        self.assertEqual(values["findings-resolved"], "2")
        self.assertEqual(values["unknowns-modified"], "1")


class CompositeActionTests(unittest.TestCase):
    def test_action_metadata_is_pinned_and_has_no_upload_side_effects(self):
        text = (ROOT / "action.yml").read_text(encoding="utf-8")
        self.assertIn("actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0", text)
        self.assertIn("shell: python", text)
        self.assertNotIn("upload-sarif", text)
        self.assertNotIn("upload-artifact", text)
        self.assertIn("analysis-complete", text)

    def test_runner_writes_external_outputs_and_preserves_target_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            workspace = base / "workspace"
            target = workspace / "project"
            runner_temp = base / "runner-temp"
            target.mkdir(parents=True)
            runner_temp.mkdir()
            canonical_runner_temp = runner_temp.resolve()
            (target / "README.md").write_text("# Demo\n", encoding="utf-8")
            github_output = base / "github-output.txt"
            step_summary = base / "step-summary.md"
            env = os.environ.copy()
            env.update({
                "GITHUB_ACTION_PATH": str(ROOT),
                "GITHUB_WORKSPACE": str(workspace),
                "RUNNER_TEMP": str(runner_temp),
                "GITHUB_OUTPUT": str(github_output),
                "GITHUB_STEP_SUMMARY": str(step_summary),
                "SCAN_INPUT_PATH": "project",
                "SCAN_INPUT_MODE": "deep",
                "SCAN_INPUT_REDACT": "standard",
                "SCAN_INPUT_BASELINE": "none",
                "SCAN_INPUT_JOB_SUMMARY": "true",
            })
            completed = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "github_action.py")],
                cwd=workspace,
                env=env,
                check=False,
                text=True,
                capture_output=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(completed.stdout.strip().splitlines()[-1])
            state_path = Path(payload["state"])
            report_path = Path(payload["report"])
            sarif_path = Path(payload["sarif"])
            summary_path = Path(payload["summary"])
            for path in (state_path, report_path, sarif_path, summary_path):
                self.assertTrue(path.exists(), path)
                self.assertTrue(path.is_relative_to(canonical_runner_temp), path)
            self.assertFalse((target / ".scan").exists())
            self.assertIn("Zero findings is not a clean bill of health", step_summary.read_text(encoding="utf-8"))
            outputs = github_output.read_text(encoding="utf-8")
            self.assertIn("findings-count=0", outputs)
            self.assertIn("analysis-complete=false", outputs)
            self.assertIn("delta-available=false", outputs)
            self.assertIn("artifacts-added=\n", outputs)
            sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(sarif["runs"][0]["results"], [])

    def test_runner_reports_artifact_delta_from_explicit_validated_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            workspace = base / "workspace"
            target = workspace / "project"
            target.mkdir(parents=True)
            (target / "app.py").write_text("x = 1\n", encoding="utf-8")
            first_out = base / "first"
            second_out = base / "second"
            common = os.environ.copy()
            common.update({
                "GITHUB_ACTION_PATH": str(ROOT),
                "GITHUB_WORKSPACE": str(workspace),
                "SCAN_INPUT_PATH": "project",
                "SCAN_INPUT_JOB_SUMMARY": "false",
            })
            first = dict(common)
            first.update({"SCAN_INPUT_OUTPUT_DIRECTORY": str(first_out), "SCAN_INPUT_BASELINE": "none"})
            completed = subprocess.run([sys.executable, str(ROOT / "scripts" / "github_action.py")], cwd=workspace, env=first, text=True, capture_output=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            baseline_state = first_out / "state.json"
            self.assertTrue(baseline_state.exists())

            (target / "app.py").write_text("x = 2\n", encoding="utf-8")
            (target / "new.py").write_text("y = 1\n", encoding="utf-8")
            github_output = base / "github-output.txt"
            second = dict(common)
            second.update({
                "GITHUB_OUTPUT": str(github_output),
                "SCAN_INPUT_OUTPUT_DIRECTORY": str(second_out),
                "SCAN_INPUT_BASELINE": str(baseline_state),
            })
            completed = subprocess.run([sys.executable, str(ROOT / "scripts" / "github_action.py")], cwd=workspace, env=second, text=True, capture_output=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            outputs = github_output.read_text(encoding="utf-8")
            self.assertIn("baseline-status=used", outputs)
            self.assertIn("delta-available=true", outputs)
            self.assertIn("artifacts-added=1", outputs)
            self.assertIn("artifacts-changed=1", outputs)
            self.assertIn("artifacts-removed=0", outputs)
            summary = (second_out / "summary.md").read_text(encoding="utf-8")
            self.assertIn("Since validated baseline", summary)
            self.assertIn("Artifacts added | 1", summary)
            self.assertIn("Artifacts changed | 1", summary)

    def test_partial_threshold_still_emits_receipts_before_failing(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            workspace = base / "workspace"
            target = workspace / "project"
            runner_temp = base / "runner-temp"
            target.mkdir(parents=True)
            runner_temp.mkdir()
            (target / "app.py").write_text("x = 1\n", encoding="utf-8")
            github_output = base / "github-output.txt"
            env = os.environ.copy()
            env.update({
                "GITHUB_ACTION_PATH": str(ROOT),
                "GITHUB_WORKSPACE": str(workspace),
                "RUNNER_TEMP": str(runner_temp),
                "GITHUB_OUTPUT": str(github_output),
                "SCAN_INPUT_PATH": "project",
                "SCAN_INPUT_FAIL_ON": "PARTIAL",
                "SCAN_INPUT_JOB_SUMMARY": "false",
            })
            completed = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "github_action.py")],
                cwd=workspace,
                env=env,
                check=False,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertTrue(github_output.exists())
            outputs = github_output.read_text(encoding="utf-8")
            self.assertIn("state=", outputs)
            self.assertIn("sarif=", outputs)
            self.assertIn("analysis-complete=false", outputs)


if __name__ == "__main__":
    unittest.main()
