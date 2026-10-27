"""Slice 1 packaging, dispatch and CLI contract tests."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from scan_core import ScanConfig, __version__
from scan_core.cli import main
from scan_core.errors import ExitCode
from scan_core.validate import load_report_state, validate_path, validate_state

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "demo-report.html"


class SliceOneTests(unittest.TestCase):
    def test_version_is_v02_development_release(self):
        self.assertTrue(__version__.startswith("0.2."))

    def test_scan_config_normalizes_root_to_path(self):
        self.assertEqual(ScanConfig(root=".").root, Path("."))

    def test_existing_demo_validates_through_packaged_api(self):
        with contextlib.redirect_stdout(io.StringIO()):
            state = validate_path(DEMO)
        self.assertEqual(state["schema_version"], "1.2")

    def test_json_validation_dispatches_by_schema_version(self):
        state = load_report_state(DEMO)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text(json.dumps(state), encoding="utf-8")
            validated = validate_path(path)
        self.assertEqual(validated["schema_version"], "1.2")

    def test_incomplete_schema_13_is_not_silently_accepted(self):
        with self.assertRaisesRegex(ValueError, "project"):
            validate_state({"schema_version": "1.3"})

    def test_cli_validate_success(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = main(["validate", str(DEMO)])
        self.assertEqual(code, ExitCode.OK)

    def test_cli_missing_source_uses_exit_3(self):
        with contextlib.redirect_stderr(io.StringIO()):
            code = main(["validate", str(ROOT / "does-not-exist.html")])
        self.assertEqual(code, ExitCode.SOURCE_ERROR)

    def test_cli_invalid_report_uses_exit_5(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text('{"schema_version":"9.9"}', encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                code = main(["validate", str(path)])
        self.assertEqual(code, ExitCode.VALIDATION_FAILED)

    def test_cli_reserved_command_uses_exit_2(self):
        with contextlib.redirect_stderr(io.StringIO()):
            code = main(["bench"])
        self.assertEqual(code, ExitCode.COMMAND_ERROR)

    def test_cli_primary_scan_remains_available_after_later_slices(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            report_path = Path(directory) / "report.html"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = main([
                    str(ROOT / "scanbench" / "fixtures" / "inventory-basic" / "target"),
                    "--state", str(state_path),
                    "--output", str(report_path),
                    "--quiet",
                ])
            self.assertEqual(code, ExitCode.OK)
            self.assertTrue(state_path.is_file())
            self.assertTrue(report_path.is_file())


if __name__ == "__main__":
    unittest.main()
