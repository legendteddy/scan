"""Installed-CLI acceptance gate for Scan v0.3.

Runs only against synthetic temporary projects. It never executes target project code
and creates no network remote.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tempfile


def run(*args: str, cwd: Path | None = None, capture: bool = False) -> str:
    completed = subprocess.run(
        list(args), cwd=cwd, check=True, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        text=True, encoding="utf-8", errors="replace",
    )
    return completed.stdout if capture else ""


def scan(*args: str, cwd: Path | None = None, capture: bool = False) -> str:
    executable = shutil.which("scan")
    if executable is None:
        raise RuntimeError("installed scan console entrypoint is not on PATH")
    return run(executable, *args, cwd=cwd, capture=capture)


def git(root: Path, *args: str) -> str:
    executable = shutil.which("git")
    if executable is None:
        raise RuntimeError("Git is required by the v0.3 changed-scope acceptance fixture")
    return run(executable, *args, cwd=root, capture=True).strip()


def main() -> int:
    version = scan("--version", capture=True).strip()
    if "0.3.0.dev6" not in version:
        raise AssertionError(f"unexpected installed CLI version: {version}")

    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        project = temp / "Acceptance Project Ω with spaces"
        project.mkdir()
        (project / "app.txt").write_text("one\n", encoding="utf-8")
        (project / "資料 file.txt").write_text("unicode\n", encoding="utf-8")

        scan(".", "--offline", "--quiet", cwd=project)
        first = project / ".scan" / "state.json"
        first_copy = temp / "first-state.json"
        shutil.copyfile(first, first_copy)
        (project / "app.txt").write_text("two\n", encoding="utf-8")
        scan(".", "--offline", "--quiet", cwd=project)

        second_state = json.loads(first.read_text(encoding="utf-8"))
        if second_state["baseline"]["status"] != "used" or not second_state["delta"]["available"]:
            raise AssertionError("second scan did not use the automatic local baseline")
        if not second_state["delta"]["artifacts"]["changed"]:
            raise AssertionError("second scan did not report the modified artifact")

        scan("validate", ".scan/state.json", cwd=project)
        scan("validate", ".scan/report.html", cwd=project)
        schema = json.loads(scan("schema", "--version", "1.4", capture=True))
        if schema["properties"]["schema_version"]["const"] != "1.4":
            raise AssertionError("installed schema command did not return Scan 1.4")
        doctor = json.loads(scan("doctor", ".", "--json", cwd=project, capture=True))
        if doctor["overall"] not in {"pass", "warn"}:
            raise AssertionError(f"installed doctor failed: {doctor}")
        comparison = json.loads(scan("compare", str(first_copy), str(first), "--json", capture=True))
        if comparison["snapshot_relation"] != "changed" or not comparison["artifacts"]["changed"]:
            raise AssertionError("installed compare did not report the repeated-scan change")

        repo = temp / "Git Scope Ω with spaces"
        repo.mkdir()
        git(repo, "init", "-b", "main")
        git(repo, "config", "user.name", "Scan Acceptance")
        git(repo, "config", "user.email", "scan-acceptance@example.invalid")
        git(repo, "config", "core.autocrlf", "false")
        (repo / "tracked.txt").write_text("before\n", encoding="utf-8")
        git(repo, "add", "tracked.txt")
        git(repo, "commit", "-m", "base")
        (repo / "tracked.txt").write_text("after\n", encoding="utf-8")
        (repo / "新 file.txt").write_text("untracked\n", encoding="utf-8")
        scan(".", "--offline", "--changed-since", "HEAD", "--no-reuse", "--quiet", cwd=repo)
        git_state = json.loads((repo / ".scan" / "state.json").read_text(encoding="utf-8"))
        scope = git_state["extensions"]["git_change_scope"]
        if "tracked.txt" not in scope["modified"] or "新 file.txt" not in scope["untracked"]:
            raise AssertionError(f"installed Git scope did not preserve native changed paths: {scope}")
        if git_state["run"]["network_used"]:
            raise AssertionError("Git-scope acceptance unexpectedly recorded network use")

    print("PASS: Scan v0.3 installed-CLI acceptance")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
