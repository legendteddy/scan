"""Scan v0.3 Slice 4 local Git changed-scope and agent-contract tests."""

from __future__ import annotations

from copy import deepcopy
import contextlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scan_core import ScanConfig, canonical_state_json, render_html, scan_project, validate_state
from scan_core.cli import main
from scan_core.errors import ExitCode
from scan_core.git_change import inspect_git_change_scope


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=root, check=True, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    return result.stdout.strip()


def _repo(root: Path) -> None:
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.name", "Scan Test")
    _git(root, "config", "user.email", "scan-test@example.invalid")
    _git(root, "config", "core.autocrlf", "false")
    files = {
        "keep.txt": "keep\n",
        "modify.txt": "before\n",
        "delete.txt": "delete\n",
        "rename-old.txt": "rename payload\n",
        "copy-source.txt": "copy payload\n",
    }
    for name, content in files.items():
        (root / name).write_text(content, encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "base")


def _hostile_filter(root: Path, kind: str) -> Path:
    sentinel = root / f"{kind}-filter-ran.txt"
    script = root / f"hostile-{kind}-filter.py"
    if kind == "clean":
        script.write_text(
            "import pathlib, sys\n"
            "pathlib.Path(sys.argv[1]).write_text('ran', encoding='utf-8')\n"
            "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
            encoding="utf-8",
        )
        _git(root, "config", "filter.evil.clean", subprocess.list2cmdline([sys.executable, str(script), str(sentinel)]))
    elif kind == "process":
        script.write_text(
            "import pathlib, sys\n"
            "pathlib.Path(sys.argv[1]).write_text('ran', encoding='utf-8')\n"
            "raise SystemExit(1)\n",
            encoding="utf-8",
        )
        _git(root, "config", "filter.evil.process", subprocess.list2cmdline([sys.executable, str(script), str(sentinel)]))
    else:
        raise AssertionError(kind)
    _git(root, "config", "filter.evil.required", "true")
    (root / ".gitattributes").write_text("*.txt filter=evil\n", encoding="utf-8")
    return sentinel


class GitChangedScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        if shutil.which("git") is None:
            self.skipTest("Git is not installed")

    def test_changed_scope_records_local_categories_without_shrinking_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _repo(root)
            (root / "modify.txt").write_text("after\n", encoding="utf-8")
            (root / "delete.txt").unlink()
            _git(root, "mv", "rename-old.txt", "rename-new.txt")
            shutil.copyfile(root / "copy-source.txt", root / "copy-new.txt")
            (root / "added.txt").write_text("added\n", encoding="utf-8")
            _git(root, "add", "added.txt", "copy-new.txt")
            (root / "untracked.txt").write_text("untracked\n", encoding="utf-8")

            result = scan_project(ScanConfig(
                root=root, baseline_mode="none", reuse_enabled=False, changed_since="HEAD",
            ))
            state = result.state
            validate_state(state, version="1.4")
            scope = state["extensions"]["git_change_scope"]
            self.assertIn("added.txt", scope["added"])
            self.assertIn("modify.txt", scope["modified"])
            self.assertIn("delete.txt", scope["deleted"])
            self.assertIn({"from": "rename-old.txt", "to": "rename-new.txt", "similarity": "100"}, scope["renamed"])
            self.assertIn({"from": "copy-source.txt", "to": "copy-new.txt", "similarity": "100"}, scope["copied"])
            self.assertIn("untracked.txt", scope["untracked"])
            locators = {row["locator"] for row in state["artifacts"]}
            self.assertIn("untracked.txt", locators)
            self.assertIn("keep.txt", locators)
            self.assertFalse(any(locator.startswith(".git/") for locator in locators))
            self.assertFalse(state["run"]["network_used"])
            git_tools = [row for row in state["provenance"]["tool_versions"] if row["name"] == "git"]
            self.assertEqual(len(git_tools), 1)
            self.assertEqual(git_tools[0]["version"], scope["git_version"])
            html = render_html(state)
            self.assertIn("Git change scope", html)
            self.assertIn("Full Scan inventory remains authoritative", html)

    def test_git_rename_remains_removed_plus_added_in_scan_delta(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _repo(root)
            state_path = root / ".scan" / "state.json"
            first = scan_project(ScanConfig(root=root, output_state=state_path, baseline_mode="none", reuse_enabled=False)).state
            old_id = next(row["id"] for row in first["artifacts"] if row["locator"] == "rename-old.txt")
            _git(root, "mv", "rename-old.txt", "rename-new.txt")
            second = scan_project(ScanConfig(root=root, output_state=state_path, changed_since="HEAD")).state
            new_id = next(row["id"] for row in second["artifacts"] if row["locator"] == "rename-new.txt")
            self.assertIn({"from": "rename-old.txt", "to": "rename-new.txt", "similarity": "100"},
                          second["extensions"]["git_change_scope"]["renamed"])
            self.assertIn(old_id, second["delta"]["artifacts"]["removed"])
            self.assertIn(new_id, second["delta"]["artifacts"]["added"])
            self.assertNotEqual(old_id, new_id)

    def test_hidden_git_path_keeps_leading_dot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _repo(root)
            (root / ".env.example").write_text("before", encoding="utf-8")
            _git(root, "add", ".env.example")
            _git(root, "commit", "-m", "hidden base")
            (root / ".env.example").write_text("after", encoding="utf-8")
            scope = inspect_git_change_scope(root, "HEAD")
            self.assertIn(".env.example", scope.modified)
            self.assertNotIn("env.example", scope.modified)

    def test_sensitive_git_paths_use_current_safe_representation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _repo(root)
            (root / "private").mkdir()
            (root / "private" / "secret.txt").write_text("before", encoding="utf-8")
            _git(root, "add", "private/secret.txt")
            _git(root, "commit", "-m", "sensitive base")
            (root / "private" / "secret.txt").write_text("after", encoding="utf-8")
            state = scan_project(ScanConfig(
                root=root, baseline_mode="none", reuse_enabled=False,
                sensitive_paths=("private/**",), changed_since="HEAD",
            )).state
            encoded = canonical_state_json(state)
            scope = state["extensions"]["git_change_scope"]
            self.assertNotIn("private/secret.txt", encoded)
            self.assertEqual(len(scope["modified"]), 1)
            self.assertTrue(scope["modified"][0].startswith("[REDACTED:path]/"))

    def test_missing_ref_and_non_git_target_fail_before_output_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            _repo(root)
            output = Path(directory) / "state.json"
            output.write_text("KEEP", encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
                code = main([
                    str(root), "--no-html", "--state", str(output), "--baseline", "none",
                    "--changed-since", "missing-local-ref",
                ])
            self.assertEqual(code, ExitCode.COMMAND_ERROR)
            self.assertEqual(output.read_text(encoding="utf-8"), "KEEP")
            self.assertIn("Git changed scope failed", stderr.getvalue())

            plain = Path(directory) / "plain"
            plain.mkdir()
            (plain / "a.txt").write_text("a", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = main([str(plain), "--no-html", "--baseline", "none", "--changed-since", "HEAD"])
            self.assertEqual(code, ExitCode.COMMAND_ERROR)

    def test_cli_json_exposes_advisory_git_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _repo(root)
            (root / "modify.txt").write_text("cli change\n", encoding="utf-8")
            output = root / ".scan" / "state.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                code = main([
                    str(root), "--no-html", "--state", str(output), "--baseline", "none",
                    "--changed-since", "HEAD", "--json",
                ])
            self.assertEqual(code, ExitCode.OK)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["git_change_scope"]["base_ref"], "HEAD")
            self.assertIn("modify.txt", payload["git_change_scope"]["modified"] )
            emitted = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["artifact_count"], len(emitted["artifacts"]))
            self.assertIn("keep.txt", {row["locator"] for row in emitted["artifacts"]})
            self.assertNotIn(".scan/state.json", {row["locator"] for row in emitted["artifacts"]})

    def test_ordinary_scan_does_not_require_git_executable(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch("scan_core.git_change.shutil.which", return_value=None):
            root = Path(directory)
            (root / "a.txt").write_text("a", encoding="utf-8")
            state = scan_project(ScanConfig(root=root, baseline_mode="none", reuse_enabled=False)).state
            self.assertNotIn("git_change_scope", state["extensions"] )
            self.assertFalse(any(row["name"] == "git" for row in state["provenance"]["tool_versions"]))
            with self.assertRaisesRegex(Exception, "local Git executable"):
                inspect_git_change_scope(root, "HEAD")

    def test_changed_scope_does_not_execute_clean_filter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _repo(root)
            sentinel = _hostile_filter(root, "clean")
            (root / "modify.txt").write_text("after\n", encoding="utf-8")

            scope = inspect_git_change_scope(root, "HEAD")

            self.assertFalse(sentinel.exists())
            self.assertIn("modify.txt", scope.modified)

    def test_changed_scope_does_not_execute_process_filter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _repo(root)
            sentinel = _hostile_filter(root, "process")
            (root / "modify.txt").write_text("after\n", encoding="utf-8")

            scope = inspect_git_change_scope(root, "HEAD")

            self.assertFalse(sentinel.exists())
            self.assertIn("modify.txt", scope.modified)

    def test_git_invocation_is_argument_array_local_only_and_disables_helpers(self):
        responses = [
            subprocess.CompletedProcess([], 0, b"git version 9.9\n", b""),
            subprocess.CompletedProcess([], 0, b"true\n", b""),
            subprocess.CompletedProcess([], 0, b"a" * 40 + b"\n", b""),
            subprocess.CompletedProcess([], 0, b"b" * 40 + b"\n", b""),
            subprocess.CompletedProcess([], 0, b"", b""),
            subprocess.CompletedProcess([], 0, b"", b""),
            subprocess.CompletedProcess([], 0, b"", b""),
        ]
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch("scan_core.git_change.shutil.which", return_value="git"), \
             mock.patch("scan_core.git_change.subprocess.run", side_effect=responses) as runner:
            inspect_git_change_scope(Path(directory), "HEAD~1")
        self.assertEqual(runner.call_count, 7)
        for call in runner.call_args_list:
            command = call.args[0]
            self.assertIsInstance(command, list)
            self.assertFalse(call.kwargs["shell"])
            self.assertIn("protocol.allow=never", command)
            self.assertNotIn("fetch", command)
            self.assertNotIn("pull", command)
            self.assertNotIn("push", command)
        subcommands = [call.args[0][call.args[0].index("protocol.allow=never") + 1] for call in runner.call_args_list]
        self.assertEqual(subcommands, ["--version", "rev-parse", "rev-parse", "rev-parse", "diff", "ls-files", "ls-files"])
        diff_command = runner.call_args_list[4].args[0]
        self.assertIn("--cached", diff_command)
        self.assertIn("a" * 40, diff_command)
        self.assertNotIn("HEAD~1", diff_command)

    def test_validator_rejects_git_scope_without_matching_tool_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _repo(root)
            state = scan_project(ScanConfig(
                root=root, baseline_mode="none", reuse_enabled=False, changed_since="HEAD",
            )).state
            broken = deepcopy(state)
            broken["provenance"]["tool_versions"] = [
                row for row in broken["provenance"]["tool_versions"] if row["name"] != "git"
            ]
            with self.assertRaisesRegex(ValueError, "Git tool provenance"):
                validate_state(broken, version="1.4")

    def test_skill_teaches_delta_git_priority_and_honest_reuse_rules(self):
        skill = (Path(__file__).resolve().parents[1] / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("consume `delta` first", skill)
        self.assertIn("prioritization context", skill)
        self.assertIn("do not rewrite Scan artifact identity", skill)
        self.assertIn("never describe it as a fresh semantic review", skill)
        self.assertIn("do not claim runtime remediation", skill)
        self.assertIn("Scan Core schema `1.4`", skill)


if __name__ == "__main__":
    unittest.main()
