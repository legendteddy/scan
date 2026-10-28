"""Offline installation and local-environment diagnostics for Scan."""

from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import files
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any

from .errors import SourceError
from .scanbench import locate_scanbench_root
from .schema import schema_object
from .version import __version__


_DOCTOR_STATUSES = {"pass", "warn", "fail"}


@dataclass(frozen=True)
class DoctorCheck:
    id: str
    status: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {"id": self.id, "status": self.status, "message": self.message}


@dataclass(frozen=True)
class DoctorResult:
    scan_version: str
    overall: str
    checks: tuple[DoctorCheck, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "scan_version": self.scan_version,
            "overall": self.overall,
            "checks": [check.as_dict() for check in self.checks],
        }


def _overall(checks: list[DoctorCheck]) -> str:
    if any(check.status == "fail" for check in checks):
        return "fail"
    if any(check.status == "warn" for check in checks):
        return "warn"
    return "pass"


def _check(status: str, ident: str, message: str) -> DoctorCheck:
    if status not in _DOCTOR_STATUSES:
        raise ValueError(f"Invalid doctor status: {status}")
    return DoctorCheck(id=ident, status=status, message=message)


def _assert_target_access(path: Path) -> Path:
    try:
        root = path.resolve(strict=True)
    except OSError as error:
        raise SourceError(f"Doctor target cannot be resolved: {path}: {error}") from error
    if not root.is_dir():
        raise SourceError(f"Doctor target is not a directory: {path}")
    try:
        with os.scandir(root) as entries:
            next(entries, None)
    except OSError as error:
        raise SourceError(f"Doctor target cannot be read: {path}: {error}") from error
    return root


def _package_schema_check(version: str) -> DoctorCheck:
    ident = f"schema-{version}"
    try:
        schema = schema_object(version)
        declared = schema.get("properties", {}).get("schema_version", {}).get("const")
        if declared != version:
            return _check("fail", ident, f"Bundled Scan schema {version} has an inconsistent version marker")
    except Exception as error:
        return _check("fail", ident, f"Bundled Scan schema {version} is unavailable or invalid: {error}")
    return _check("pass", ident, f"Bundled Scan schema {version} available")


def _report_asset_check() -> DoctorCheck:
    try:
        shell = files("scan_core.report").joinpath("shell.html").read_text(encoding="utf-8")
        required = ("{{STATE_JSON}}", "{{STATE_SCHEMA_VERSION}}", "project-anatomy-state")
        if not shell or not all(marker in shell for marker in required):
            return _check("fail", "report-shell", "Bundled report shell is incomplete")
    except Exception as error:
        return _check("fail", "report-shell", f"Bundled report shell is unavailable: {error}")
    return _check("pass", "report-shell", "Bundled self-contained report shell available")


def _scanbench_asset_check() -> DoctorCheck:
    try:
        root = locate_scanbench_root()
        manifest = json.loads(root.joinpath("manifest.json").read_text(encoding="utf-8"))
        fixtures = manifest.get("fixtures")
        if not isinstance(fixtures, list) or not fixtures or not all(isinstance(name, str) and name for name in fixtures):
            return _check("fail", "scanbench-assets", "Bundled ScanBench manifest has no valid fixture list")
        for name in fixtures:
            fixture = root.joinpath("fixtures", name)
            for required in ("fixture.json", "expected.json", "README.md"):
                if not fixture.joinpath(required).is_file():
                    return _check("fail", "scanbench-assets", f"Bundled ScanBench fixture {name} is missing {required}")
            if not fixture.joinpath("project").is_dir():
                return _check("fail", "scanbench-assets", f"Bundled ScanBench fixture {name} is missing its project directory")
    except Exception as error:
        return _check("fail", "scanbench-assets", f"Bundled ScanBench data is unavailable or invalid: {error}")
    return _check("pass", "scanbench-assets", f"Bundled ScanBench manifest and {len(fixtures)} fixture(s) available")


def _output_probe(root: Path) -> DoctorCheck:
    scan_dir = root / ".scan"
    created_scan_dir = False
    probe_dir: Path | None = None
    try:
        if scan_dir.exists() and not scan_dir.is_dir():
            return _check("fail", "output-probe", ".scan exists but is not a directory")
        if not scan_dir.exists():
            scan_dir.mkdir()
            created_scan_dir = True
        probe_dir = Path(tempfile.mkdtemp(prefix=".doctor-", dir=scan_dir))
        marker = probe_dir / "write-probe.txt"
        marker.write_text("scan doctor", encoding="utf-8")
        marker.read_text(encoding="utf-8")
    except OSError as error:
        return _check("fail", "output-probe", f"Cannot create and remove a temporary Scan output probe: {error}")
    finally:
        if probe_dir is not None:
            shutil.rmtree(probe_dir, ignore_errors=True)
        if created_scan_dir:
            try:
                scan_dir.rmdir()
            except OSError:
                pass
    if probe_dir is not None and probe_dir.exists():
        return _check("fail", "output-probe", "Temporary Scan output probe could not be cleaned up")
    if created_scan_dir and scan_dir.exists():
        return _check("fail", "output-probe", "Temporary .scan directory could not be cleaned up")
    return _check("pass", "output-probe", "Temporary Scan output probe created and cleaned up")


def _git_checks(root: Path) -> tuple[DoctorCheck, DoctorCheck]:
    executable = shutil.which("git")
    if executable is None:
        return (
            _check("warn", "git-executable", "Git not found; ordinary Scan use still works"),
            _check("warn", "git-worktree", "Git worktree status not checked because Git is unavailable"),
        )
    try:
        version = subprocess.run(
            [executable, "--version"],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            shell=False,
            timeout=10,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"},
        )
        version_text = version.stdout.decode("utf-8", errors="replace").strip()
        if version.returncode != 0 or not version_text:
            raise OSError("Git --version failed")
        worktree = subprocess.run(
            [executable, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=", "-c", "protocol.allow=never",
             "rev-parse", "--is-inside-work-tree"],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            shell=False,
            timeout=10,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"},
        )
        inside = worktree.returncode == 0 and worktree.stdout.decode("ascii", errors="replace").strip() == "true"
    except (OSError, subprocess.SubprocessError) as error:
        return (
            _check("warn", "git-executable", f"Git was found but could not be queried safely: {error}"),
            _check("warn", "git-worktree", "Git worktree status could not be established"),
        )
    return (
        _check("pass", "git-executable", f"Optional Git integration available: {version_text}"),
        _check("pass" if inside else "warn", "git-worktree",
               "Target is inside a local Git worktree" if inside else "Target is not inside a local Git worktree; ordinary Scan use still works"),
    )


def run_doctor(path: Path) -> DoctorResult:
    """Diagnose Scan installation and local target readiness without network access."""
    root = _assert_target_access(Path(path))
    checks: list[DoctorCheck] = []
    py = sys.version_info
    checks.append(_check(
        "pass" if py >= (3, 11) else "fail",
        "python-version",
        f"Python {py.major}.{py.minor}.{py.micro} supported" if py >= (3, 11) else f"Python {py.major}.{py.minor}.{py.micro} is unsupported; Scan requires Python 3.11+",
    ))
    checks.append(_check("pass", "scan-version", f"Scan {__version__} installed"))
    checks.extend(_package_schema_check(version) for version in ("1.2", "1.3", "1.4"))
    checks.append(_report_asset_check())
    checks.append(_scanbench_asset_check())
    checks.append(_check("pass", "target-read", "Target directory exists and is readable"))
    checks.append(_output_probe(root))
    checks.extend(_git_checks(root))
    return DoctorResult(scan_version=__version__, overall=_overall(checks), checks=tuple(checks))


def format_doctor(result: DoctorResult) -> str:
    lines = [f"Scan Doctor {result.scan_version}", ""]
    for check in result.checks:
        lines.append(f"{check.status.upper():4}  {check.id:<18} {check.message}")
    lines.extend(("", f"Result: {result.overall.upper()}"))
    return "\n".join(lines)
