"""Agent-Honesty ScanBench regression tests."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import unittest

from scan_core.agent_honesty import (
    HONESTY_SCENARIOS,
    format_agent_honesty_bench,
    main,
    run_agent_honesty_bench,
)


class AgentHonestyScanBenchTests(unittest.TestCase):
    def test_all_false_confidence_guards_pass(self):
        result = run_agent_honesty_bench()
        self.assertTrue(result.passed)
        self.assertEqual(tuple(row.name for row in result.scenarios), HONESTY_SCENARIOS)
        self.assertEqual(len(result.scenarios), 5)
        self.assertTrue(all(row.passed for row in result.scenarios))

    def test_each_scenario_is_independently_runnable(self):
        for name in HONESTY_SCENARIOS:
            with self.subTest(name=name):
                result = run_agent_honesty_bench(scenario=name)
                self.assertTrue(result.passed)
                self.assertEqual(len(result.scenarios), 1)
                self.assertEqual(result.scenarios[0].name, name)

    def test_json_contract_has_no_blended_score(self):
        result = run_agent_honesty_bench()
        payload = result.as_dict()
        self.assertEqual(payload["agent_honesty_scanbench_version"], "1")
        self.assertTrue(payload["passed"])
        self.assertIsNone(payload["score"])
        self.assertIn("No blended", payload["score_note"])

    def test_human_output_names_every_guard(self):
        text = format_agent_honesty_bench(run_agent_honesty_bench())
        for name in HONESTY_SCENARIOS:
            self.assertIn("PASS " + name, text)
        self.assertIn("No blended honesty or intelligence score", text)

    def test_module_cli_json_runs_the_full_gate(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = main(["--json"])
        self.assertEqual(code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertTrue(payload["passed"])
        self.assertEqual(len(payload["scenarios"]), len(HONESTY_SCENARIOS))

    def test_unknown_scenario_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "Unknown Agent-Honesty"):
            run_agent_honesty_bench(scenario="invented-proof")

    def test_agent_honesty_sources_are_plain_utf8_without_bom(self):
        root = Path(__file__).resolve().parents[1]
        for relative in (
            "src/scan_core/agent_honesty.py",
            "tests/test_agent_honesty_scanbench.py",
            "docs/v0.4-agent-honesty-scanbench.md",
        ):
            with self.subTest(relative=relative):
                self.assertFalse((root / relative).read_bytes().startswith(b"\xef\xbb\xbf"))


if __name__ == "__main__":
    unittest.main()
