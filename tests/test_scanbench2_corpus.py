"""ScanBench 2.0 corpus structure and maturity tests."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scan_core.errors import CommandError
from scan_core.scanbench2_corpus import summarize_corpus

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "scanbench" / "ground_truth"


class ScanBench2CorpusTests(unittest.TestCase):
    def test_milestone_corpus_is_valid_and_counted_without_blended_score(self):
        summary = summarize_corpus(CORPUS)
        self.assertEqual(summary["project_count"], 20)
        self.assertEqual(summary["condition_count"], 149)
        self.assertEqual(summary["maturity_target"], {"projects": 20, "conditions": 200})
        self.assertEqual(
            summary["truth_kind_counts"],
            {
                "must_find": 58,
                "must_not_find": 31,
                "must_remain_unknown": 30,
                "must_not_clear": 30,
            },
        )
        self.assertTrue(summary["no_blended_quality_score"])
        self.assertNotIn("overall_score", summary)
        self.assertNotIn("quality_score", summary)
        self.assertEqual(set(summary["fixture_condition_counts"]), {
            "authorization-ownership",
            "data-loss-transaction",
            "retry-idempotency",
            "web-accessibility-form",
            "docs-code-contract",
            "test-quality-mock",
            "webhook-signature-js",
            "async-cache-race-ts",
            "shell-ci-eval",
            "go-http-body-boundary",
            "rust-archive-boundary",
            "java-http-egress",
            "c-native-bounds",
            "k8s-privilege-boundary",
            "ruby-reset-token",
            "sql-migration-safety",
            "kotlin-offline-sync",
            "terraform-destruction",
            "react-checkout-state",
            "csharp-message-delivery",
        })

    def test_every_artifact_locator_resolves_inside_its_fixture_project(self):
        summary = summarize_corpus(CORPUS)
        self.assertEqual(sum(summary["fixture_condition_counts"].values()), 149)

    def test_missing_artifact_locator_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "fixtures" / "broken"
            (fixture / "project").mkdir(parents=True)
            (root / "manifest.json").write_text(json.dumps({
                "scanbench2_version": "2.0-alpha1",
                "truth_kinds": ["must_find", "must_not_find", "must_remain_unknown", "must_not_clear"],
                "fixtures": ["broken"],
                "maturity_target": {"projects": 20, "conditions": 200},
                "milestone": {"projects": 1, "conditions": 1},
            }), encoding="utf-8")
            (fixture / "truth.json").write_text(json.dumps({
                "scanbench2_version": "2.0-alpha1",
                "project_id": "broken",
                "conditions": [{
                    "id": "BROKEN-001",
                    "truth": "must_find",
                    "family": "fixture-integrity",
                    "description": "Referenced source must exist.",
                    "rationale": "Ground truth without the stated artifact is not independently reviewable.",
                    "artifact_locators": ["missing.py"],
                }],
            }), encoding="utf-8")
            with self.assertRaisesRegex(CommandError, "does not resolve"):
                summarize_corpus(root)

    def test_duplicate_condition_ids_across_projects_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixtures = []
            for name in ("one", "two"):
                fixtures.append(name)
                fixture = root / "fixtures" / name
                (fixture / "project").mkdir(parents=True)
                (fixture / "project" / "app.py").write_text("pass\n", encoding="utf-8")
                (fixture / "truth.json").write_text(json.dumps({
                    "scanbench2_version": "2.0-alpha1",
                    "project_id": name,
                    "conditions": [{
                        "id": "DUP-001",
                        "truth": "must_not_find",
                        "family": "fixture-integrity",
                        "description": "Condition IDs are globally unique.",
                        "rationale": "Ambiguous IDs would make cross-project adjudication unsafe.",
                        "artifact_locators": ["app.py"],
                    }],
                }), encoding="utf-8")
            (root / "manifest.json").write_text(json.dumps({
                "scanbench2_version": "2.0-alpha1",
                "truth_kinds": ["must_find", "must_not_find", "must_remain_unknown", "must_not_clear"],
                "fixtures": fixtures,
                "maturity_target": {"projects": 20, "conditions": 200},
            }), encoding="utf-8")
            with self.assertRaisesRegex(CommandError, "duplicate corpus condition ID"):
                summarize_corpus(root)


if __name__ == "__main__":
    unittest.main()
