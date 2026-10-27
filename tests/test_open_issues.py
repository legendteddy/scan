"""Regression coverage for GitHub issues #10 through #15."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from scan_core import (
    BuilderError,
    ScanConfig,
    SemanticStateBuilder,
    render_html,
    scan_project,
    validate_state,
)
from scan_core.cli import main
from scan_core.privacy import RedactionPolicy, redact_value
from scan_core.validate import CHECK_CATEGORIES

ROOT = Path(__file__).resolve().parents[1]


class GitInventoryModeTests(unittest.TestCase):
    def _git_project(self, root: Path) -> tuple[str, str]:
        commit = "a" * 40
        git = root / ".git"
        (git / "refs" / "heads").mkdir(parents=True)
        (git / "objects" / "pack").mkdir(parents=True)
        (git / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        (git / "refs" / "heads" / "main").write_text(commit + "\n", encoding="utf-8")
        (git / "objects" / "pack" / "large.pack").write_bytes(b"x" * 128)
        (git / "config").write_text(
            '[remote "origin"]\nurl = https://user:secret@example.test/owner/repo.git?token=hidden\n',
            encoding="utf-8",
        )
        (root / "app.py").write_text("x", encoding="utf-8")
        return commit, "https://example.test/owner/repo.git"

    def test_deep_excludes_git_object_storage_but_records_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commit, sanitized_remote = self._git_project(root)
            state = scan_project(ScanConfig(root=root, scan_mode="deep", max_file_bytes=8)).state
        locators = [row["locator"] for row in state["artifacts"]]
        self.assertIn(".git", locators)
        self.assertNotIn(".git/objects/pack/large.pack", locators)
        self.assertFalse(state["coverage"]["resource_limits_hit"])
        self.assertIn("scan mode deep: .git/**", state["project"]["exclusions"])
        git = state["provenance"]["git"]
        self.assertTrue(git["detected"])
        self.assertEqual(git["branch"], "main")
        self.assertEqual(git["commit"], commit)
        self.assertEqual(git["remotes"][0]["url"], sanitized_remote)
        self.assertNotIn("secret", str(git))
        self.assertEqual(git["working_tree_status"], "not_assessed")
        validate_state(state)

    def test_forensic_opts_git_internals_back_in(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._git_project(root)
            state = scan_project(ScanConfig(root=root, scan_mode="forensic", max_file_bytes=8)).state
        locators = [row["locator"] for row in state["artifacts"]]
        self.assertIn(".git/objects/pack/large.pack", locators)
        self.assertTrue(state["coverage"]["resource_limits_hit"])
        self.assertEqual(state["extensions"]["scan_mode"]["mode_exclusions"], [])

    def test_quick_suppresses_common_generated_dependency_trees(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "node_modules" / "pkg").mkdir(parents=True)
            (root / "node_modules" / "pkg" / "index.js").write_text("large", encoding="utf-8")
            (root / "app.py").write_text("x", encoding="utf-8")
            state = scan_project(ScanConfig(root=root, scan_mode="quick")).state
        rows = {row["locator"]: row for row in state["artifacts"]}
        self.assertIn("node_modules", rows)
        self.assertEqual(rows["node_modules"]["status"], "excluded")
        self.assertNotIn("node_modules/pkg/index.js", rows)
        self.assertEqual(state["run"]["scan_mode"], "quick")
        self.assertFalse(state["coverage"]["analysis_complete"])
        self.assertEqual(state["extensions"]["scan_mode"]["deeper_mode"], "deep")
        self.assertTrue(any("Run deep mode" in item for item in state["continuation"]["remaining"]))

    def test_cli_exposes_mode_and_records_it_in_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("x", encoding="utf-8")
            state_path = root.parent / (root.name + "-state.json")
            stdout = io.StringIO()
            try:
                with contextlib.redirect_stdout(stdout):
                    code = main([
                        str(root), "--mode", "quick", "--offline", "--no-html",
                        "--state", str(state_path), "--json",
                    ])
                self.assertEqual(code, 0)
                summary = json.loads(stdout.getvalue())
                self.assertEqual(summary["mode"], "quick")
                state = json.loads(state_path.read_text(encoding="utf-8"))
                self.assertEqual(state["run"]["scan_mode"], "quick")
            finally:
                state_path.unlink(missing_ok=True)


class PrivacyPrecisionTests(unittest.TestCase):
    def test_token_like_source_identifiers_are_not_counted_as_secrets(self):
        text = "tokenizer = parser\ntoken_count=12\ntoken_type=NAME\n"
        result = redact_value(text, RedactionPolicy(level="standard"))
        self.assertEqual(result.value, text)
        self.assertEqual(result.count, 0)

    def test_true_token_assignments_remain_redacted(self):
        text = "TOKEN=synthetic-token-value-1234567890\nAPI_TOKEN=synthetic-api-token-value-1234567890\n"
        result = redact_value(text, RedactionPolicy(level="standard"))
        self.assertNotIn("synthetic-token-value", result.value)
        self.assertNotIn("synthetic-api-token-value", result.value)
        self.assertEqual(result.count, 2)


class BuilderApiTests(unittest.TestCase):
    def _base(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        (root / "app.py").write_text("answer = 42\n", encoding="utf-8")
        state = scan_project(ScanConfig(root=root)).state
        return temporary, state

    def test_builder_normalizes_scalar_refs_and_reports_bad_reference_path(self):
        temporary, state = self._base()
        self.addCleanup(temporary.cleanup)
        artifact = state["artifacts"][0]
        builder = SemanticStateBuilder.from_state(state)
        evidence_id = builder.add_evidence(
            artifact_id=artifact["id"], locator=artifact["locator"], kind="static",
            claim="Value assignment was inspected", result="answer is assigned an integer literal",
            method="semantic source read", limitations="Static evidence only",
            source_digest=artifact["content_identity"], producer_kind="human",
            producer_name="test-reviewer", producer_version="1",
        )
        finding_id = builder.add_finding(
            title="Example finding", impact="Demonstrates typed construction", severity="low",
            confidence="high", verification_state="static", artifact_ids=artifact["id"],
            evidence_ids=evidence_id, uncertainty="Runtime not observed",
            recommendation="Keep the evidence link", safe_verification="Review the source",
        )
        built = builder.build()
        finding = next(row for row in built["findings"] if row["id"] == finding_id)
        self.assertEqual(finding["artifact_ids"], [artifact["id"]])
        self.assertEqual(finding["evidence_ids"], [evidence_id])
        with self.assertRaisesRegex(BuilderError, r"evidence_ids: unknown reference"):
            builder.add_finding(
                title="Bad ref", impact="None", severity="low", confidence="high",
                verification_state="static", artifact_ids=artifact["id"], evidence_ids="evidence:missing",
                uncertainty="Known", recommendation="Fix ref", safe_verification="Validate",
            )

    def test_builder_rejects_common_agent_shape_and_omission_mistakes(self):
        temporary, state = self._base()
        self.addCleanup(temporary.cleanup)
        artifact = state["artifacts"][0]
        builder = SemanticStateBuilder.from_state(state)
        with self.assertRaisesRegex(BuilderError, r"limitations: expected a nonempty string"):
            builder.add_evidence(
                artifact_id=artifact["id"], locator=artifact["locator"], kind="static",
                claim="Reviewed", result="Result", method="semantic read",
                source_digest=artifact["content_identity"], producer_kind="human",
                producer_name="test-reviewer", producer_version="1",
            )
        with self.assertRaisesRegex(BuilderError, r"finding\.artifact_ids: expected a nonempty string or string array"):
            builder.add_finding(
                title="Bad shape", impact="None", severity="low", confidence="high",
                verification_state="static", artifact_ids=123, evidence_ids="evidence:missing",
                uncertainty="Known", recommendation="Fix input", safe_verification="Validate",
            )
        with self.assertRaisesRegex(BuilderError, r"\.artifact_ids: expected at least one artifact ID"):
            builder.add_finding(
                title="Missing artifact", impact="None", severity="low", confidence="high",
                verification_state="static", evidence_ids="evidence:missing",
                uncertainty="Known", recommendation="Attach artifact", safe_verification="Validate",
            )
        with self.assertRaisesRegex(BuilderError, r"\.related_ids: unknown reference"):
            builder.add_action(
                description="Follow up", priority="medium", related_ids="finding:missing",
                authorization_requirements="None", expected_verification="Revalidate state",
            )

    def test_builder_can_upgrade_core_state_to_validator_complete_semantic_state(self):
        temporary, state = self._base()
        self.addCleanup(temporary.cleanup)
        artifact = state["artifacts"][0]
        builder = SemanticStateBuilder.from_state(state)
        evidence_id = builder.add_evidence(
            artifact_id=artifact["id"], locator=artifact["locator"], kind="static",
            claim="Complete fixture source was semantically reviewed", result="Fixture behavior understood",
            method="complete semantic source read", limitations="No runtime execution",
            source_digest=artifact["content_identity"], producer_kind="human",
            producer_name="test-reviewer", producer_version="1",
        )
        builder.mark_artifact_analyzed(artifact["id"], evidence_ids=evidence_id)
        builder.remove_unknown("unknown:semantic-runtime")
        for category in CHECK_CATEGORIES:
            builder.assess_check(
                category=category, status="assessed", scope="Entire one-file fixture",
                method="semantic source review", artifact_ids=artifact["id"], evidence_ids=evidence_id,
                verification_state="static", result="Assessed within static fixture scope",
                limitations="Runtime behavior not observed", reason="Fixture scope was fully readable",
            )
        builder.set_summary(
            condition="Static semantic review complete within the declared fixture scope",
            readiness="conditional", evidence_ids=evidence_id,
            limitations="Runtime verification remains separate",
        )
        built = builder.build(analysis_complete=True)
        self.assertTrue(built["coverage"]["analysis_complete"])
        self.assertTrue(built["coverage"]["checks_complete"])
        self.assertEqual(built["coverage"]["counts_by_status"], {"analyzed": 1})
        validate_state(built)


class ReportAndShellTests(unittest.TestCase):
    def test_current_shells_share_dynamic_schema_placeholder(self):
        packaged = (ROOT / "src" / "scan_core" / "report" / "shell.html").read_text(encoding="utf-8")
        agent = (ROOT / "assets" / "report-shell.html").read_text(encoding="utf-8")
        self.assertEqual(agent, packaged)
        self.assertIn("Scan schema {{STATE_SCHEMA_VERSION}}", agent)
        self.assertNotIn("Scan schema 1.2 is embedded", agent)

    def test_report_is_decision_first_and_keeps_full_findings_in_appendix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("answer = 42\n", encoding="utf-8")
            state = scan_project(ScanConfig(root=root, scan_mode="deep")).state
        artifact = state["artifacts"][0]
        builder = SemanticStateBuilder.from_state(state)
        evidence_id = builder.add_evidence(
            artifact_id=artifact["id"], locator=artifact["locator"], kind="static",
            claim="Source reviewed", result="Review result", method="static review",
            limitations="Static only", source_digest=artifact["content_identity"],
            producer_kind="human", producer_name="test-reviewer", producer_version="1",
        )
        for index in range(6):
            builder.add_finding(
                title=f"Finding {index}", impact=f"Impact {index}", severity="high" if index == 0 else "low",
                confidence="high", verification_state="static", artifact_ids=artifact["id"],
                evidence_ids=evidence_id, uncertainty="Runtime not observed", recommendation="Review",
                safe_verification="Inspect source",
            )
        html = render_html(builder.build())
        self.assertLess(html.index("Decisions that matter"), html.index("Project facts"))
        self.assertLess(html.index("02 · What changed"), html.index("03 · Strengths"))
        self.assertLess(html.index("03 · Strengths"), html.index("04 · Open questions"))
        self.assertLess(html.index("04 · Open questions"), html.index("05 · Coverage"))
        self.assertLess(html.index("05 · Coverage"), html.index("06 · Anatomy"))
        self.assertLess(html.index("06 · Anatomy"), html.index("07 · The parts"))
        self.assertEqual(html.count('data-priority-finding="true"'), 5)
        self.assertIn("All findings", html)
        for index in range(6):
            self.assertIn(f"Finding {index}", html)
        self.assertIn("<strong>Mode</strong> deep", html)


if __name__ == "__main__":
    unittest.main()
