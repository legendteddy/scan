"""Scan v0.3 Slice 6 cross-platform path and filesystem regression tests."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from scan_core import ScanConfig, canonical_state_json, scan_project, validate_state
from scan_core.inventory import build_inventory


class CrossPlatformRegressionTests(unittest.TestCase):
    def test_release_control_files_are_plain_utf8_without_bom(self):
        root = Path(__file__).resolve().parents[1]
        for relative in (
            "pyproject.toml", ".github/workflows/validate.yml", "scripts/v03_acceptance.py",
            "src/scan_core/mcp_server.py", "tests/test_mcp_server.py",
            "README.md", "docs/v0.4-mcp-foundation.md",
        ):
            with self.subTest(relative=relative):
                self.assertFalse((root / relative).read_bytes().startswith(b"\xef\xbb\xbf"))

    def test_unicode_and_space_paths_round_trip_with_portable_locators(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "Project Ω with spaces"
            nested = root / "資料 folder"
            nested.mkdir(parents=True)
            target = nested / "Résumé file.txt"
            target.write_text("portable\n", encoding="utf-8")

            state = scan_project(ScanConfig(root=root, baseline_mode="none", reuse_enabled=False)).state
            validate_state(state, version="1.4")
            locators = {row["locator"] for row in state["artifacts"]}
            self.assertIn("資料 folder/Résumé file.txt", locators)
            self.assertFalse(any("\\" in locator for locator in locators))
            encoded = canonical_state_json(state)
            self.assertIn("Résumé file.txt", encoded)
            self.assertIn("資料 folder", encoded)

    def test_case_behavior_tracks_the_native_filesystem_without_normalizing_it_away(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            upper = root / "CaseProbe.txt"
            lower = root / "caseprobe.txt"
            upper.write_text("upper", encoding="utf-8")
            case_sensitive = not lower.exists()
            if case_sensitive:
                lower.write_text("lower", encoding="utf-8")

            inventory = build_inventory(ScanConfig(root=root))
            locators = {row.locator for row in inventory.artifacts}
            with self.subTest(case_sensitive=case_sensitive):
                if case_sensitive:
                    self.assertIn("CaseProbe.txt", locators)
                    self.assertIn("caseprobe.txt", locators)
                    self.assertEqual(len({x for x in locators if x.casefold() == "caseprobe.txt"}), 2)
                else:
                    self.assertEqual(len({x for x in locators if x.casefold() == "caseprobe.txt"}), 1)

    def test_symlink_is_exercised_or_skipped_with_an_explicit_platform_reason(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.txt"
            target.write_text("target", encoding="utf-8")
            link = root / "link.txt"
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"native symlink creation unavailable on this runner: {error}")

            inventory = build_inventory(ScanConfig(root=root))
            rows = {row.locator: row for row in inventory.artifacts}
            self.assertEqual(rows["link.txt"].path_kind, "symlink")
            self.assertIn(rows["link.txt"].symlink_scope, {"internal", "external"})


if __name__ == "__main__":
    unittest.main()
