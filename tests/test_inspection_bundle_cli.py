"""Inspection Bundle console entry-point tests."""
from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from scan_core import ScanConfig, scan_project
from scan_core.inspection_bundle_cli import main
from scan_core.state import canonical_state_json


class InspectionBundleCliTests(unittest.TestCase):
    def test_create_then_verify_json_workflow(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            (project / "app.py").write_text("value = 1\n", encoding="utf-8")
            state = scan_project(ScanConfig(root=project, baseline_mode="none", reuse_enabled=False)).state
            state_path = root / "state.json"
            bundle_path = root / "inspection.scanbundle"
            state_path.write_text(canonical_state_json(state) + "\n", encoding="utf-8")

            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["create", str(state_path), "--output", str(bundle_path), "--json"])
            self.assertEqual(code, 0)
            created = json.loads(output.getvalue())
            self.assertTrue(bundle_path.is_file())
            self.assertTrue(created["bundle_digest"].startswith("sha256:"))

            output = io.StringIO()
            with redirect_stdout(output):
                code = main(["verify", str(bundle_path), "--json"])
            self.assertEqual(code, 0)
            verified = json.loads(output.getvalue())
            self.assertTrue(verified["verified"])
            self.assertEqual(verified["bundle_digest"], created["bundle_digest"])
            self.assertEqual(verified["state_digest"], created["state_digest"])
            self.assertEqual(verified["handoff_digest"], created["handoff_digest"])


if __name__ == "__main__":
    unittest.main()
