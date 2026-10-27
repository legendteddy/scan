"""Slice 2 deterministic inventory and snapshot regression tests."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from scan_core import ScanConfig, build_inventory, build_snapshot
from scan_core.ids import artifact_id, normalize_locator

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "scanbench" / "fixtures" / "inventory-basic"
NO_EXEC_FIXTURE = ROOT / "scanbench" / "fixtures" / "no-execution" / "target"


class InventoryIdentityTests(unittest.TestCase):
    def test_artifact_id_is_locator_stable(self):
        self.assertEqual(artifact_id("src/main.py"), artifact_id("src/main.py"))
        self.assertNotEqual(artifact_id("src/main.py"), artifact_id("src/other.py"))

    def test_artifact_id_rejects_non_normalized_locator(self):
        for locator in ("/absolute.txt", "../escape.txt", "./relative.txt", "a//b.txt", "a\\b.txt"):
            with self.subTest(locator=locator), self.assertRaises(ValueError):
                artifact_id(locator)

    def test_normalize_locator_rejects_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            root.mkdir()
            with self.assertRaisesRegex(ValueError, "escapes"):
                normalize_locator(root, root.parent / "outside.txt")

    def test_scanbench_inventory_fixture_matches_expected_membership(self):
        expected = json.loads((FIXTURE / "expected.json").read_text(encoding="utf-8"))
        inventory = build_inventory(ScanConfig(root=FIXTURE / "target"))
        self.assertTrue(inventory.complete)
        self.assertEqual([item.locator for item in inventory.artifacts], expected["locators"])
        self.assertTrue(all(item.id.startswith("artifact:") for item in inventory.artifacts))

    def test_scanbench_target_code_is_never_executed(self):
        marker = NO_EXEC_FIXTURE / "EXECUTED"
        marker.unlink(missing_ok=True)
        inventory = build_inventory(ScanConfig(root=NO_EXEC_FIXTURE))
        self.assertFalse(marker.exists())
        row = next(item for item in inventory.artifacts if item.locator == "danger.py")
        self.assertTrue(row.content_identity.startswith("sha256:"))

    def test_creation_order_does_not_change_ids_or_snapshot(self):
        layouts = [
            [("b.txt", "B"), ("nested/a.txt", "A")],
            [("nested/a.txt", "A"), ("b.txt", "B")],
        ]
        snapshots = []
        identities = []
        for layout in layouts:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for relative, text in layout:
                    path = root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(text, encoding="utf-8")
                inventory = build_inventory(ScanConfig(root=root))
                snapshots.append(build_snapshot(inventory).digest)
                identities.append([(a.locator, a.id, a.content_identity) for a in inventory.artifacts])
        self.assertEqual(identities[0], identities[1])
        self.assertEqual(snapshots[0], snapshots[1])

    def test_content_change_changes_snapshot_but_not_artifact_id(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "same.txt"
            target.write_text("one", encoding="utf-8")
            first_inventory = build_inventory(ScanConfig(root=root))
            first = build_snapshot(first_inventory)
            first_id = next(a.id for a in first_inventory.artifacts if a.locator == "same.txt")
            target.write_text("two", encoding="utf-8")
            second_inventory = build_inventory(ScanConfig(root=root))
            second = build_snapshot(second_inventory)
            second_id = next(a.id for a in second_inventory.artifacts if a.locator == "same.txt")
            self.assertEqual(first_id, second_id)
            self.assertNotEqual(first.digest, second.digest)

    def test_hidden_leading_dash_and_unicode_names_are_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in (".hidden", "-leading", "unicode-λ.txt"):
                (root / name).write_text(name, encoding="utf-8")
            inventory = build_inventory(ScanConfig(root=root))
            self.assertEqual([a.locator for a in inventory.artifacts], ["-leading", ".hidden", "unicode-λ.txt"])

    def test_excluded_directory_is_recorded_but_not_traversed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vendor = root / "vendor"
            vendor.mkdir()
            (vendor / "large.js").write_text("ignored", encoding="utf-8")
            (root / "app.py").write_text("print('x')", encoding="utf-8")
            inventory = build_inventory(ScanConfig(root=root, excludes=("vendor/**",)))
            rows = {a.locator: a for a in inventory.artifacts}
            self.assertIn("vendor", rows)
            self.assertTrue(rows["vendor"].excluded)
            self.assertNotIn("vendor/large.js", rows)
            self.assertIn("app.py", rows)

    def test_max_file_bytes_preserves_metadata_and_marks_identity_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "big.bin").write_bytes(b"12345")
            inventory = build_inventory(ScanConfig(root=root, max_file_bytes=4))
            row = inventory.artifacts[0]
            self.assertEqual(row.size_bytes, 5)
            self.assertEqual(row.content_identity, "unhashed:max-file-bytes")
            self.assertFalse(inventory.identity_complete)
            self.assertIn("max_file_bytes:big.bin", inventory.resource_limits_hit)

    def test_max_total_bytes_does_not_hide_later_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.txt").write_bytes(b"123")
            (root / "b.txt").write_bytes(b"456")
            inventory = build_inventory(ScanConfig(root=root, max_total_bytes=3))
            rows = {a.locator: a for a in inventory.artifacts}
            self.assertEqual(set(rows), {"a.txt", "b.txt"})
            self.assertTrue(rows["a.txt"].content_identity.startswith("sha256:"))
            self.assertEqual(rows["b.txt"].content_identity, "unhashed:max-total-bytes")
            self.assertFalse(inventory.identity_complete)
            self.assertEqual(inventory.total_hashed_bytes, 3)

    def test_external_symlink_is_inventoried_and_never_traversed(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside_directory:
            root = Path(directory)
            outside = Path(outside_directory)
            (outside / "secret.txt").write_text("secret", encoding="utf-8")
            link = root / "outside-link"
            try:
                os.symlink(outside, link, target_is_directory=True)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"symlinks unavailable: {error}")
            inventory = build_inventory(ScanConfig(root=root, follow_internal_links=True))
            rows = {a.locator: a for a in inventory.artifacts}
            self.assertEqual(set(rows), {"outside-link"})
            self.assertEqual(rows["outside-link"].path_kind, "symlink")
            self.assertEqual(rows["outside-link"].symlink_scope, "external")
            self.assertNotIn("outside-link/secret.txt", rows)
            manifest = build_snapshot(inventory).manifest_json
            self.assertNotIn(str(outside), manifest)
            self.assertIn("symlink_target_identity", manifest)

    def test_internal_symlink_loop_terminates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            child = root / "child"
            child.mkdir()
            (child / "data.txt").write_text("safe", encoding="utf-8")
            loop = child / "loop"
            try:
                os.symlink(root, loop, target_is_directory=True)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"symlinks unavailable: {error}")
            inventory = build_inventory(ScanConfig(root=root, follow_internal_links=True))
            locators = [a.locator for a in inventory.artifacts]
            self.assertIn("child/loop", locators)
            self.assertLess(len(locators), 10)


if __name__ == "__main__":
    unittest.main()
