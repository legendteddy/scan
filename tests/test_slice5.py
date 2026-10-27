"""Slice 5 canonical-state HTML rendering and report integrity tests."""

from __future__ import annotations

import contextlib
import copy
import io
import os
from pathlib import Path
import re
import tempfile
import unittest

from scan_core import ScanConfig, render_html, render_report, scan_project
from scan_core.cli import main
from scan_core.errors import ExitCode, ValidationError
from scan_core.validate import load_report_state, validate_report

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "scanbench" / "fixtures" / "inventory-basic" / "target"
PRIVACY_FIXTURE = ROOT / "scanbench" / "fixtures" / "privacy-redaction" / "target"
DEMO_12 = ROOT / "examples" / "demo-report.html"


def state_for(root: Path = FIXTURE):
    return scan_project(ScanConfig(root=root)).state


class RendererSliceTests(unittest.TestCase):
    def test_render_round_trip_preserves_authoritative_state(self):
        state = state_for()
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.html"
            render_report(state, report)
            embedded = load_report_state(report)
            self.assertEqual(embedded, state)
            self.assertEqual(validate_report(report), state)

    def test_renderer_rejects_invalid_state_before_writing(self):
        state = state_for()
        broken = copy.deepcopy(state)
        broken["coverage"]["discovered_artifact_count"] += 1
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.html"
            with self.assertRaises(ValidationError):
                render_report(broken, report)
            self.assertFalse(report.exists())

    def test_renderer_does_not_upgrade_historical_12_report_state(self):
        state = load_report_state(DEMO_12)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValidationError, "1.3 only"):
                render_report(state, Path(directory) / "report.html")

    def test_embedded_json_escapes_html_sensitive_characters(self):
        state = state_for()
        state = copy.deepcopy(state)
        state["project"]["name"] = "Alpha <Beta> & Co"
        html = render_html(state)
        script = html.split('<script type="application/json" id="project-anatomy-state">', 1)[1].split("</script>", 1)[0]
        self.assertNotIn("<", script)
        self.assertNotIn(">", script)
        self.assertNotIn("&", script)
        self.assertIn("\\u003cBeta\\u003e", script)
        self.assertIn("Alpha &lt;Beta&gt; &amp; Co", html)

    def test_target_markup_is_visible_text_not_executable_html(self):
        state = state_for()
        state = copy.deepcopy(state)
        state["project"]["name"] = '<img src=x onerror="alert(1)">'
        html = render_html(state)
        visible = html.split('<script type="application/json" id="project-anatomy-state">', 1)[0]
        self.assertNotIn("<img src=x", visible)
        self.assertIn("&lt;img src=x", visible)
        self.assertNotIn("onerror=\"alert(1)\"", visible)

    def test_report_is_static_and_self_contained(self):
        html = render_html(state_for())
        self.assertEqual(html.count("<script"), 1)
        self.assertIn('type="application/json" id="project-anatomy-state"', html)
        self.assertNotRegex(html, r'<script[^>]+src=')
        self.assertNotRegex(html, r'<(?:img|link|iframe|source)[^>]+(?:src|href)=["\']https?://')
        self.assertNotIn("@import url(http", html.lower())

    def test_javascript_disabled_report_still_contains_core_content(self):
        state = state_for()
        html = render_html(state)
        visible = html.split('<script type="application/json" id="project-anatomy-state">', 1)[0]
        self.assertIn(state["project"]["name"], visible)
        self.assertIn("What was checked", visible)
        self.assertIn("Evidence and inventory", visible)
        self.assertIn(state["unknowns"][0]["question"], visible)
        self.assertIn(state["artifacts"][0]["locator"], visible)

    def test_visible_count_markers_match_state(self):
        state = state_for()
        html = render_html(state)
        expected = {
            "discovered_artifact_count": state["coverage"]["discovered_artifact_count"],
            "content_read_count": state["coverage"]["counts_by_status"].get("content_read", 0),
            "checks_assessed": state["coverage"]["counts_by_check_status"].get("assessed", 0),
            "finding_count": len(state["findings"]),
            "redaction_count": state["privacy"]["redaction_count"],
            "unknown_count": len(state["unknowns"]),
        }
        for key, value in expected.items():
            self.assertIn(f'data-scan-count="{key}">{value}</b>', html)

    def test_hand_edited_visible_count_is_rejected(self):
        state = state_for()
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.html"
            render_report(state, report)
            html = report.read_text(encoding="utf-8")
            tampered, count = re.subn(
                r'(data-scan-count="discovered_artifact_count">)\d+(</b>)',
                r'\g<1>999\2',
                html,
                count=1,
            )
            self.assertEqual(count, 1)
            report.write_text(tampered, encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, "Visible count"):
                validate_report(report)

    def test_external_resource_injection_is_rejected(self):
        state = state_for()
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.html"
            render_report(state, report)
            html = report.read_text(encoding="utf-8").replace(
                "</main>", '<img src="https://example.test/pixel.png" alt="">\n</main>', 1
            )
            report.write_text(html, encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, "external network resources"):
                validate_report(report)

    def test_executable_script_injection_is_rejected(self):
        state = state_for()
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.html"
            render_report(state, report)
            html = report.read_text(encoding="utf-8").replace("</body>", "<script>alert(1)</script></body>", 1)
            report.write_text(html, encoding="utf-8")
            with self.assertRaisesRegex(ValidationError, "executable scripts"):
                validate_report(report)

    def test_scan_project_writes_state_and_html_from_same_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            report_path = Path(directory) / "report.html"
            result = scan_project(ScanConfig(root=FIXTURE, output_state=state_path, output_html=report_path))
            self.assertEqual(result.state_path, state_path)
            self.assertEqual(result.report_path, report_path)
            self.assertEqual(load_report_state(report_path), result.state)
            self.assertTrue(state_path.is_file())
            self.assertTrue(report_path.is_file())

    def test_cli_primary_command_generates_both_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            report_path = Path(directory) / "report.html"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = main([
                    str(FIXTURE),
                    "--state", str(state_path),
                    "--output", str(report_path),
                    "--json",
                ])
            self.assertEqual(code, ExitCode.OK, stderr.getvalue())
            self.assertTrue(state_path.is_file())
            self.assertTrue(report_path.is_file())
            self.assertIn('"report_path"', stdout.getvalue())
            validate_report(report_path)

    def test_cli_render_uses_existing_valid_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            report_path = Path(directory) / "report.html"
            scan_project(ScanConfig(root=FIXTURE, output_state=state_path))
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = main(["render", str(state_path), "--output", str(report_path)])
            self.assertEqual(code, ExitCode.OK)
            self.assertTrue(report_path.is_file())
            validate_report(report_path)

    def test_definition_of_done_scan_dot_offline_uses_default_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.txt").write_text("fixture", encoding="utf-8")
            previous = Path.cwd()
            try:
                os.chdir(root)
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    code = main([".", "--offline", "--quiet"])
            finally:
                os.chdir(previous)
            self.assertEqual(code, ExitCode.OK)
            self.assertTrue((root / ".scan" / "state.json").is_file())
            self.assertTrue((root / ".scan" / "report.html").is_file())
            validate_report(root / ".scan" / "report.html")

    def test_offline_shorthand_rejects_conflicting_privacy_mode(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = main([str(FIXTURE), "--offline", "--privacy", "local", "--quiet"])
        self.assertEqual(code, ExitCode.COMMAND_ERROR)

    def test_strict_privacy_values_do_not_reappear_in_html(self):
        state = scan_project(ScanConfig(
            root=PRIVACY_FIXTURE,
            redaction_level="strict",
            sensitive_paths=("private/**",),
        )).state
        html = render_html(state)
        for raw in (
            "synthetic-token-value-1234567890",
            "synthetic-api-key-value-1234567890",
            "synthetic-private-key-material-12345",
            "synthetic-password-123",
            "alice@example.test",
            "+673 812 3456",
            "BRN-001-9999",
            "private/customer.txt",
        ):
            self.assertNotIn(raw, html)

    def test_template_has_no_unfilled_slots(self):
        html = render_html(state_for())
        self.assertIsNone(re.search(r"\{\{[A-Z_]+\}\}", html))


if __name__ == "__main__":
    unittest.main()
