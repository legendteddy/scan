from __future__ import annotations

from pathlib import Path
import json
import tempfile
import threading
import time
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen

from scan_core.config import ScanConfig
from scan_core.core import scan_project
from scan_core.serve import build_compare_html, create_server, discover_receipts
from scan_core.validate import validate_state


class LocalServeTests(unittest.TestCase):
    def _history(self, root: Path):
        project = root / "project"
        history = root / "history"
        project.mkdir()
        history.mkdir()
        (project / "app.py").write_text("print('one')\n", encoding="utf-8")
        first = scan_project(ScanConfig(root=project, output_state=history / "first.json", baseline_mode="none")).state
        time.sleep(0.01)
        (project / "app.py").write_text("print('two')\n", encoding="utf-8")
        (project / "new.txt").write_text("new\n", encoding="utf-8")
        second = scan_project(ScanConfig(root=project, output_state=history / "second.json", baseline_mode="none")).state
        return project, history, first, second

    def test_discovery_keeps_only_valid_unique_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, history, first, _ = self._history(root)
            (history / "invalid.json").write_text('{"not":"scan"}\n', encoding="utf-8")
            (history / "duplicate.json").write_text(
                (history / "first.json").read_text(encoding="utf-8"), encoding="utf-8"
            )
            catalog = discover_receipts(history)
            self.assertEqual(len(catalog.entries), 2)
            self.assertEqual(catalog.skipped_count, 2)
            self.assertTrue(all(entry.state["project"]["name"] == first["project"]["name"] for entry in catalog.entries))

    def test_single_state_file_is_a_valid_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, history, _, _ = self._history(root)
            catalog = discover_receipts(history / "second.json")
            self.assertEqual(len(catalog.entries), 1)
            validate_state(catalog.entries[0].state)

    def test_http_server_exposes_receipts_not_arbitrary_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, history, _, _ = self._history(root)
            (history / "secret.txt").write_text("TOP SECRET PROJECT FILE\n", encoding="utf-8")
            before = sorted(path.name for path in history.iterdir())
            server, catalog = create_server(history, port=0, quiet=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f"http://127.0.0.1:{server.server_address[1]}"
                with urlopen(base + "/", timeout=3) as response:
                    index = response.read().decode("utf-8")
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.headers["Cache-Control"], "no-store")
                    self.assertIn("Scan report history", index)
                    self.assertNotIn("TOP SECRET PROJECT FILE", index)

                newest = catalog.entries[0]
                with urlopen(base + f"/state/{newest.id}.json", timeout=3) as response:
                    state = json.loads(response.read().decode("utf-8"))
                    validate_state(state)
                with urlopen(base + f"/report/{newest.id}", timeout=3) as response:
                    report = response.read().decode("utf-8")
                    self.assertIn("project-anatomy-state", report)
                with urlopen(base + "/healthz", timeout=3) as response:
                    self.assertEqual(response.read(), b"ok\n")
                with self.assertRaises(HTTPError) as blocked:
                    urlopen(base + "/secret.txt", timeout=3)
                self.assertEqual(blocked.exception.code, 404)

                old, new = catalog.entries[-1], catalog.entries[0]
                self.assertIn("resolved means absent", build_compare_html(old, new).lower())
                with urlopen(base + f"/compare/{old.id}/{new.id}", timeout=3) as response:
                    comparison = response.read().decode("utf-8")
                    self.assertIn("comparison", comparison.lower())
                with urlopen(base + f"/compare-json/{old.id}/{new.id}", timeout=3) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                    self.assertIn("snapshot_relation", payload)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)
            self.assertEqual(before, sorted(path.name for path in history.iterdir()))

    def test_history_limit_fails_closed_instead_of_truncating(self):
        with tempfile.TemporaryDirectory() as directory:
            history = Path(directory)
            for index in range(257):
                (history / f"{index:03}.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "receipt limit"):
                discover_receipts(history)

    def test_non_loopback_bind_requires_explicit_opt_in(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, history, _, _ = self._history(root)
            with self.assertRaisesRegex(ValueError, "allow-network"):
                create_server(history, host="0.0.0.0", port=0, quiet=True)


if __name__ == "__main__":
    unittest.main()
