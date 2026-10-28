"""Scan v0.3 Slice 5 doctor and install-readiness tests."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scan_core import DoctorResult, run_doctor
from scan_core.cli import main
from scan_core.errors import ExitCode, SourceError


class DoctorTests(unittest.TestCase):
    def test_healthy_doctor_is_typed_and_cleans_temporary_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.txt").write_text("ok", encoding="utf-8")
            result = run_doctor(root)
            self.assertIsInstance(result, DoctorResult)
            self.assertIn(result.overall, {"pass", "warn"})
            payload = result.as_dict()
            self.assertIsInstance(payload["scan_version"], str)
            self.assertIsInstance(payload["checks"], list)
            ids = {row["id"] for row in payload["checks"]}
            self.assertTrue({"python-version", "scan-version", "schema-1.2", "schema-1.3", "schema-1.4", "report-shell", "scanbench-assets", "target-read", "output-probe", "git-executable", "git-worktree"} <= ids)
            self.assertFalse((root / ".scan").exists())

    def test_existing_scan_directory_is_preserved_without_probe_leftovers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scan_dir = root / ".scan"
            scan_dir.mkdir()
            marker = scan_dir / "keep.txt"
            marker.write_text("keep", encoding="utf-8")
            run_doctor(root)
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep")
            self.assertEqual([p.name for p in scan_dir.iterdir()], ["keep.txt"])

    def test_cli_json_is_stable_typed_and_successful_for_warn_only_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stdout = io.StringIO()
            with mock.patch("scan_core.doctor.shutil.which", return_value=None):
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                    code = main(["doctor", str(root), "--json"])
            self.assertEqual(code, ExitCode.OK)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["overall"], "warn")
            self.assertEqual(payload, json.loads(json.dumps(payload, sort_keys=True)))
            git = next(row for row in payload["checks"] if row["id"] == "git-executable")
            self.assertEqual(git["status"], "warn")

    def test_missing_optional_git_is_warning_not_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch("scan_core.doctor.shutil.which", return_value=None):
                result = run_doctor(Path(directory))
            self.assertEqual(result.overall, "warn")
            statuses = {row.id: row.status for row in result.checks}
            self.assertEqual(statuses["git-executable"], "warn")
            self.assertEqual(statuses["git-worktree"], "warn")

    def test_missing_bundled_schema_is_required_failure_and_cli_exit_2(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = __import__("scan_core.doctor", fromlist=["schema_object"]).schema_object
            def broken(version: str):
                if version == "1.4":
                    raise FileNotFoundError("missing schema")
                return real(version)
            with mock.patch("scan_core.doctor.schema_object", side_effect=broken):
                result = run_doctor(root)
                self.assertEqual(result.overall, "fail")
                row = next(row for row in result.checks if row.id == "schema-1.4")
                self.assertEqual(row.status, "fail")
                with mock.patch("scan_core.cli.run_doctor", return_value=result):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        code = main(["doctor", str(root), "--json"])
            self.assertEqual(code, ExitCode.COMMAND_ERROR)

    def test_missing_target_is_source_error(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"
            with self.assertRaises(SourceError):
                run_doctor(missing)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["doctor", str(missing)]), ExitCode.SOURCE_ERROR)

    def test_file_target_is_source_error(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "file.txt"
            target.write_text("not a directory", encoding="utf-8")
            with self.assertRaises(SourceError):
                run_doctor(target)

    def test_unreadable_target_is_source_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch("scan_core.doctor.os.scandir", side_effect=PermissionError("denied")):
                with self.assertRaises(SourceError):
                    run_doctor(root)

    def test_git_probe_never_uses_network_operations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = []
            def fake_run(command, **kwargs):
                calls.append(command)
                if command[-1] == "--version":
                    return mock.Mock(returncode=0, stdout=b"git version test", stderr=b"")
                return mock.Mock(returncode=0, stdout=b"true\n", stderr=b"")
            with mock.patch("scan_core.doctor.shutil.which", return_value="git"), mock.patch("scan_core.doctor.subprocess.run", side_effect=fake_run):
                result = run_doctor(root)
            self.assertIn(result.overall, {"pass", "warn"})
            flat = " ".join(" ".join(command) for command in calls).lower()
            for forbidden in (" fetch ", " pull ", " push ", " clone ", " ls-remote "):
                self.assertNotIn(forbidden, f" {flat} ")
            self.assertIn("protocol.allow=never", flat)


if __name__ == "__main__":
    unittest.main()
