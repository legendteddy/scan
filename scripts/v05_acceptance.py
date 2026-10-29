"""Installed-CLI acceptance gate for the Scan v0.5 release candidate.

Runs only against synthetic temporary projects. It never executes target project code
and creates no network remote.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

EXPECTED_VERSION = "0.5.0"


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
        raise RuntimeError("Git is required by the changed-scope acceptance fixture")
    return run(executable, *args, cwd=root, capture=True).strip()


def main() -> int:
    version = scan("--version", capture=True).strip()
    if version != f"scan {EXPECTED_VERSION}":
        raise AssertionError(f"unexpected installed CLI version: {version}")

    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        project = temp / "Acceptance Project Ω with spaces"
        project.mkdir()
        (project / "app.py").write_text("answer = 42\n", encoding="utf-8")
        state = temp / "state.json"
        report = temp / "report.html"
        sarif = temp / "results.sarif"
        scan(str(project), "--offline", "--baseline", "none", "--state", str(state), "--output", str(report), "--quiet")
        scan("validate", str(state))
        scan("validate", str(report))
        scan("sarif", str(state), "--output", str(sarif))
        sarif_payload = json.loads(sarif.read_text(encoding="utf-8"))
        if sarif_payload.get("version") != "2.1.0" or sarif_payload["runs"][0].get("results") != []:
            raise AssertionError("zero-finding SARIF must be valid and must not fabricate results")

        external = temp / "external.sarif"
        imported = temp / "imported.json"
        external.write_text(json.dumps({
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "AcceptanceScanner", "semanticVersion": "1.0", "rules": [
                    {"id": "EXT001", "shortDescription": {"text": "External static finding"}}
                ]}},
                "results": [{
                    "ruleId": "EXT001", "ruleIndex": 0, "level": "warning",
                    "message": {"text": "Synthetic external result"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 1}}}]
                }]
            }]
        }), encoding="utf-8")
        scan("import-sarif", str(state), str(external), "--output", str(imported), "--json")
        imported_state = json.loads(imported.read_text(encoding="utf-8"))
        if len(imported_state["findings"]) != 1:
            raise AssertionError("installed SARIF import did not preserve the mapped external finding")
        if imported_state["coverage"]["analysis_complete"]:
            raise AssertionError("SARIF import must not establish whole-project semantic completeness")

        repo = temp / "Git Scope Ω with spaces"
        repo.mkdir()
        git(repo, "init", "-b", "main")
        git(repo, "config", "user.name", "Scan Acceptance")
        git(repo, "config", "user.email", "scan-acceptance@example.invalid")
        git(repo, "config", "core.autocrlf", "false")
        (repo / "tracked.txt").write_text("before\n", encoding="utf-8")
        git(repo, "add", "tracked.txt")
        git(repo, "commit", "-m", "base")

        sentinel = repo / "filter-ran.txt"
        hostile = repo / "hostile-filter.py"
        hostile.write_text(
            "import pathlib,sys\n"
            "pathlib.Path(sys.argv[1]).write_text('ran', encoding='utf-8')\n"
            "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
            encoding="utf-8",
        )
        filter_command = subprocess.list2cmdline([sys.executable, str(hostile), str(sentinel)])
        git(repo, "config", "filter.scanaccept.clean", filter_command)
        git(repo, "config", "filter.scanaccept.required", "true")
        (repo / ".gitattributes").write_text("*.txt filter=scanaccept\n", encoding="utf-8")
        (repo / "tracked.txt").write_text("after\n", encoding="utf-8")
        (repo / "new.txt").write_text("untracked\n", encoding="utf-8")
        scan(".", "--offline", "--changed-since", "HEAD", "--no-reuse", "--quiet", cwd=repo)
        if sentinel.exists():
            raise AssertionError("--changed-since executed a repository-configured clean filter")
        git_state = json.loads((repo / ".scan" / "state.json").read_text(encoding="utf-8"))
        scope = git_state["extensions"]["git_change_scope"]
        if "tracked.txt" not in scope["modified"] or "new.txt" not in scope["untracked"]:
            raise AssertionError(f"installed changed scope did not preserve expected paths: {scope}")
        if git_state["run"]["network_used"] or git_state["run"]["target_executed"]:
            raise AssertionError("installed changed-scope run recorded an unsafe side effect")

    print("PASS: Scan v0.5 installed-CLI acceptance")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
