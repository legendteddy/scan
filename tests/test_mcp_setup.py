"""v0.4 portable MCP setup and doctor tests."""
from __future__ import annotations

from importlib import metadata
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scan_core.mcp_cli import (
    build_launch_spec,
    main,
    render_host_config,
    run_mcp_doctor,
)


def _supported_mcp_sdk_installed() -> bool:
    if importlib.util.find_spec("mcp") is None:
        return False
    try:
        return int(metadata.version("mcp").split(".", 1)[0]) == 2
    except (metadata.PackageNotFoundError, ValueError):
        return False


class MCPSetupTests(unittest.TestCase):
    def _project(self, root: Path) -> None:
        (root / "README.md").write_text("# Demo\n", encoding="utf-8")
        (root / "app.py").write_text("print('not executed')\n", encoding="utf-8")

    def test_launch_spec_uses_absolute_python_and_fixed_project_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._project(root)
            spec = build_launch_spec(root, sensitive_paths=("private/**",))
            self.assertEqual(spec["type"], "stdio")
            self.assertTrue(Path(spec["command"]).is_absolute())
            self.assertEqual(spec["args"][:2], ["-m", "scan_core.mcp_server"])
            self.assertIn(str(root.resolve()), spec["args"])
            self.assertEqual(spec["cwd"], str(root.resolve()))
            self.assertIn("private/**", spec["args"])

    def test_json_host_configs_use_the_same_portable_launcher(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._project(root)
            claude = json.loads(render_host_config("claude-desktop", root))
            cursor = json.loads(render_host_config("cursor", root))
            vscode = json.loads(render_host_config("vscode", root))
            claude_spec = claude["mcpServers"]["scan"]
            cursor_spec = cursor["mcpServers"]["scan"]
            vscode_spec = vscode["servers"]["scan"]
            self.assertEqual(claude_spec, cursor_spec)
            self.assertEqual(vscode_spec["type"], "stdio")
            self.assertEqual(vscode_spec["command"], claude_spec["command"])
            self.assertEqual(vscode_spec["args"], claude_spec["args"])

    def test_codex_and_claude_code_configs_are_copy_paste_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._project(root)
            codex = render_host_config("codex", root, name="scan")
            self.assertIn("[mcp_servers.scan]", codex)
            self.assertIn("command = ", codex)
            self.assertIn("args = [", codex)
            claude_code = render_host_config("claude-code", root, name="scan")
            self.assertIn("claude mcp add scan --", claude_code)
            self.assertIn("scan_core.mcp_server", claude_code)

    def test_missing_mcp_sdk_is_reported_as_a_doctor_failure_not_an_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._project(root)
            with patch(
                "scan_core.mcp_cli.metadata.version",
                side_effect=metadata.PackageNotFoundError("mcp"),
            ):
                result = run_mcp_doctor(root)
            self.assertEqual(result.overall, "fail")
            checks = {check.id: check for check in result.checks}
            self.assertEqual(checks["mcp-sdk"].status, "fail")
            self.assertEqual(checks["core-snapshot"].status, "pass")
            self.assertFalse((root / ".scan").exists())

    @unittest.skipUnless(_supported_mcp_sdk_installed(), "install the supported MCP 2.x extra for the live doctor gate")
    def test_doctor_passes_with_installed_supported_sdk(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._project(root)
            result = run_mcp_doctor(root)
            self.assertEqual(result.overall, "pass")
            checks = {check.id: check for check in result.checks}
            self.assertEqual(checks["mcp-sdk"].status, "pass")
            self.assertEqual(checks["server-factory"].status, "pass")
            self.assertEqual(checks["target-output"].status, "pass")
            self.assertFalse((root / ".scan").exists())

    def test_legacy_scan_mcp_path_still_routes_to_serve(self):
        class FakeServer:
            ran = False

            def run(self):
                self.ran = True

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._project(root)
            fake = FakeServer()
            with patch("scan_core.mcp_cli.create_server", return_value=fake) as factory:
                exit_code = main([str(root)])
            self.assertEqual(exit_code, 0)
            self.assertTrue(fake.ran)
            factory.assert_called_once()


if __name__ == "__main__":
    unittest.main()
