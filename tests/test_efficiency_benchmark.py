from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scan_core.config import ScanConfig
from scan_core.core import scan_project
from scan_core.efficiency_benchmark import (
    BENCHMARK_SCHEMA_VERSION,
    build_efficiency_benchmark,
    normalize_host_usage,
    summarize_efficiency,
)

ROOT = Path(__file__).resolve().parents[1]


def sample_state(*, reused: int = 1, fresh: int = 1) -> dict:
    evidence = [
        {
            "id": "inventory",
            "artifact_id": "a1",
            "inspection_origin": "fresh",
        }
    ]
    evidence.extend(
        {
            "id": f"fresh-{index}",
            "artifact_id": "a1",
            "inspection_origin": "fresh",
            "evidence_class": "static_semantic",
        }
        for index in range(fresh)
    )
    evidence.extend(
        {
            "id": f"reuse-{index}",
            "artifact_id": "a2",
            "inspection_origin": "verified_reuse",
            "evidence_class": "static_semantic",
        }
        for index in range(reused)
    )
    return {
        "run": {"scan_id": "scan:test", "scan_version": "0.test", "scan_mode": "deep"},
        "provenance": {"snapshot_digest": "sha256:test"},
        "coverage": {"discovery_complete": True, "analysis_complete": False, "checks_complete": False},
        "artifacts": [
            {"id": "a1", "status": "analyzed", "inspection_origin": "fresh"},
            {"id": "a2", "status": "content_read", "inspection_origin": "fresh"},
        ],
        "evidence": evidence,
        "checks": [
            {"id": "c1", "status": "assessed"},
            {"id": "c2", "status": "not_assessed"},
        ],
        "baseline": {
            "status": "used",
            "reuse_enabled": True,
            "fresh_evidence_count": fresh + 1,
            "reused_evidence_count": reused,
            "rejected_reuse_count": 0,
        },
        "delta": {
            "available": True,
            "artifacts": {"added": [], "changed": ["a1"], "removed": [], "unchanged": ["a2"]},
            "findings": {"new": [], "modified": [], "resolved": [], "persisting": []},
            "unknowns": {"new": [], "modified": [], "resolved": [], "persisting": []},
        },
        "extensions": {
            "git_change_scope": {
                "priority_paths": ["src/app.py", "tests/test_app.py"],
                "deleted": ["old.py"],
            }
        },
    }


class EfficiencyBenchmarkTests(unittest.TestCase):
    def test_summary_keeps_reuse_change_scope_and_coverage_separate(self) -> None:
        summary = summarize_efficiency(sample_state(reused=2, fresh=3), label="repeat")
        self.assertEqual(summary["evidence"]["higher_level_classified_fresh"], 3)
        self.assertEqual(summary["evidence"]["higher_level_classified_verified_reuse"], 2)
        self.assertEqual(summary["change_scope"]["priority_paths_count"], 2)
        self.assertEqual(summary["change_scope"]["deleted_paths_count"], 1)
        self.assertEqual(summary["delta"]["artifacts_changed"], 1)
        self.assertFalse(summary["coverage"]["analysis_complete"])
        self.assertFalse(summary["host_usage"]["available"])

    def test_usage_is_exact_and_total_is_only_derived_from_exact_components(self) -> None:
        usage = normalize_host_usage({
            "provider": "example-host",
            "model": "example-model",
            "input_tokens": 120,
            "output_tokens": 30,
        })
        self.assertEqual(usage["total_tokens"], 150)
        self.assertTrue(usage["total_tokens_derived"])
        with self.assertRaises(ValueError):
            normalize_host_usage({"input_tokens": -1})
        with self.assertRaises(ValueError):
            normalize_host_usage({"provider": "host"})

    def test_comparison_reports_raw_deltas_without_percent_savings(self) -> None:
        baseline = summarize_efficiency(
            sample_state(reused=0, fresh=5),
            label="baseline",
            usage={"input_tokens": 1000, "output_tokens": 100},
        )
        repeat = summarize_efficiency(
            sample_state(reused=4, fresh=1),
            label="repeat",
            usage={"input_tokens": 400, "output_tokens": 80},
        )
        payload = build_efficiency_benchmark([baseline, repeat])
        comparison = payload["comparisons"][0]
        self.assertEqual(payload["schema_version"], BENCHMARK_SCHEMA_VERSION)
        self.assertEqual(comparison["higher_level_classified_fresh_delta"], -4)
        self.assertEqual(comparison["higher_level_classified_verified_reuse_delta"], 4)
        self.assertEqual(comparison["token_delta"]["input_tokens"], -600)
        self.assertNotIn("percent", json.dumps(comparison).lower())

    def test_script_runs_from_checkout_against_current_validated_state(self) -> None:
        target = ROOT / "scanbench" / "fixtures" / "clean-minimal" / "project"
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            scan_project(ScanConfig(root=target, output_state=state, baseline_mode="none"))
            self.assertTrue(state.exists())
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "benchmark_efficiency.py"),
                    "--run",
                    f"baseline={state}",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["schema_version"], BENCHMARK_SCHEMA_VERSION)
        self.assertEqual(payload["runs"][0]["label"], "baseline")
        self.assertFalse(payload["runs"][0]["host_usage"]["available"])


if __name__ == "__main__":
    unittest.main()
