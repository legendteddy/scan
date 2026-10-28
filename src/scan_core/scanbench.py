"""ScanBench v1 deterministic release-gate runner.

ScanBench uses synthetic projects and objective assertions. It never executes target
code and never produces a blended quality score: each assertion belongs to one
published benchmark dimension.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import ctypes
from importlib.resources import files
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import tempfile
from typing import Any, Iterator

from .config import ScanConfig
from .core import scan_project
from .errors import CommandError
from .inventory import InventoryResult, build_inventory
from .privacy import build_egress_preview
from .snapshot import build_snapshot
from .state import canonical_state_json
from .validate import validate_report, validate_state


DIMENSIONS = (
    "inventory_completeness",
    "state_integrity",
    "evidence_correctness",
    "privacy_integrity",
    "safety_boundary_compliance",
)

DIMENSION_LABELS = {
    "inventory_completeness": "inventory completeness",
    "state_integrity": "state integrity",
    "evidence_correctness": "evidence correctness",
    "privacy_integrity": "privacy integrity",
    "safety_boundary_compliance": "safety-boundary compliance",
}


@dataclass(frozen=True)
class AssertionResult:
    fixture: str
    dimension: str
    assertion: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class FixtureResult:
    name: str
    passed: bool
    assertions: tuple[AssertionResult, ...]
    setup_notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class BenchResult:
    fixtures: tuple[FixtureResult, ...]
    dimensions: dict[str, bool | None]

    @property
    def passed(self) -> bool:
        exercised = [value for value in self.dimensions.values() if value is not None]
        return all(item.passed for item in self.fixtures) and all(exercised)

    def as_dict(self) -> dict[str, Any]:
        return {
            "scanbench_version": "1",
            "fixtures": [
                {
                    "name": fixture.name,
                    "passed": fixture.passed,
                    "setup_notes": list(fixture.setup_notes),
                    "assertions": [
                        {
                            "dimension": row.dimension,
                            "assertion": row.assertion,
                            "passed": row.passed,
                            "detail": row.detail,
                        }
                        for row in fixture.assertions
                    ],
                }
                for fixture in self.fixtures
            ],
            "dimensions": {
                name: {"label": DIMENSION_LABELS[name], "passed": self.dimensions[name]}
                for name in DIMENSIONS
            },
            "passed": self.passed,
        }


@dataclass
class _FixtureContext:
    name: str
    root: Path
    inventory: InventoryResult
    state: dict[str, Any]
    report_html: str
    snapshot_digest: str
    repeated_snapshot_digest: str
    marker_paths: dict[str, Path]


def locate_scanbench_root(start: str | Path | None = None) -> Path:
    """Locate canonical ScanBench data from a checkout or installed wheel."""
    candidates: list[Path] = []
    if start is not None:
        candidates.append(Path(start))
    candidates.append(Path.cwd() / "scanbench")
    module_repo = Path(__file__).resolve().parents[2]
    candidates.append(module_repo / "scanbench")
    try:
        packaged = Path(str(files("scanbench_data")))
    except (ModuleNotFoundError, TypeError):
        packaged = None
    if packaged is not None:
        candidates.append(packaged)
    for candidate in candidates:
        if (candidate / "manifest.json").is_file() and (candidate / "fixtures").is_dir():
            return candidate.resolve()
    raise CommandError("ScanBench fixtures were not found in the current checkout or installed Scan package")


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CommandError(f"Cannot read ScanBench file {path}: {error}") from error
    if not isinstance(value, dict):
        raise CommandError(f"ScanBench file must contain a JSON object: {path}")
    return value


def _scan_config(root: Path, raw: dict[str, Any], state_path: Path, report_path: Path) -> ScanConfig:
    allowed = {
        "privacy_mode", "redaction_level", "excludes", "sensitive_paths",
        "max_file_bytes", "max_total_bytes", "follow_internal_links",
    }
    unknown = set(raw) - allowed
    if unknown:
        raise CommandError("Unknown ScanBench config key(s): " + ", ".join(sorted(unknown)))
    return ScanConfig(
        root=root,
        output_state=state_path,
        output_html=report_path,
        privacy_mode=raw.get("privacy_mode", "offline"),
        redaction_level=raw.get("redaction_level", "standard"),
        excludes=tuple(raw.get("excludes", ())),
        sensitive_paths=tuple(raw.get("sensitive_paths", ())),
        max_file_bytes=raw.get("max_file_bytes", 5_000_000),
        max_total_bytes=raw.get("max_total_bytes", 250_000_000),
        follow_internal_links=raw.get("follow_internal_links", False),
    )


@contextmanager
def _lock_file(path: Path) -> Iterator[None]:
    """Make one synthetic fixture file unreadable without modifying Scan Core."""
    if os.name == "nt":
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        create_file = kernel32.CreateFileW
        create_file.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        create_file.restype = ctypes.c_void_p
        handle = create_file(str(path), 0x80000000, 0, None, 3, 0x80, None)
        invalid = ctypes.c_void_p(-1).value
        if handle in (None, invalid):
            raise CommandError(f"Could not lock ScanBench fixture file: {path.name}")
        try:
            yield
        finally:
            kernel32.CloseHandle(ctypes.c_void_p(handle))
        return

    original = stat.S_IMODE(path.stat().st_mode)
    path.chmod(0)
    try:
        yield
    finally:
        path.chmod(original)


def _create_windows_junction(link: Path, target: Path) -> None:
    """Create a native mount-point reparse fixture without a shell or privilege.

    Fixture paths remain data even if a custom fixture name has shell characters.
    TemporaryDirectory owns cleanup of the junction and synthetic target.
    """
    if os.name != 'nt':
        raise OSError('Windows junctions are unavailable on this platform')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    create_file = kernel.CreateFileW
    create_file.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    create_file.restype = ctypes.c_void_p
    control = kernel.DeviceIoControl
    control.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
                        ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
    control.restype = ctypes.c_int
    close_handle = kernel.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    substitute = ('\\??\\' + str(target.resolve())).encode('utf-16-le')
    printable = str(target.resolve()).encode('utf-16-le')
    names = substitute + b'\0\0' + printable + b'\0\0'
    data = struct.pack('<LHHHHHH', 0xA0000003, len(names) + 8, 0,
                       0, len(substitute), len(substitute) + 2, len(printable)) + names
    link.mkdir()
    handle = create_file(str(link), 0x40000000, 0, None, 3, 0x02200000, None)
    if handle in (None, ctypes.c_void_p(-1).value):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        returned = ctypes.c_uint32()
        buffer = ctypes.create_string_buffer(data)
        if not control(handle, 0x000900A4, buffer, len(data), None, 0, ctypes.byref(returned), None):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        close_handle(handle)


@contextmanager
def _fixture_setup(root: Path, setup: dict[str, Any], temp_root: Path) -> Iterator[dict[str, Path]]:
    marker_paths: dict[str, Path] = {}
    external_symlink = setup.get("external_symlink")
    if external_symlink is not None:
        if not isinstance(external_symlink, dict):
            raise CommandError("external_symlink setup must be an object")
        link_name = external_symlink.get("link", "escape")
        outside_name = external_symlink.get("outside_file", "outside.txt")
        outside = temp_root / "outside"
        outside.mkdir(exist_ok=True)
        (outside / outside_name).write_text("synthetic outside content", encoding="utf-8")
        link = root / link_name
        try:
            os.symlink(outside, link, target_is_directory=True)
        except (OSError, NotImplementedError) as error:
            if os.name != 'nt':
                raise CommandError(f"ScanBench symlink fixture unavailable: {error}") from error
            try:
                _create_windows_junction(link, outside)
            except OSError as junction_error:
                raise CommandError("ScanBench directory-link fixture unavailable: symlink and junction creation failed") from junction_error

    marker = setup.get("marker_absent")
    if isinstance(marker, str) and marker:
        marker_paths[marker] = root / marker
        marker_paths[marker].unlink(missing_ok=True)

    lock_name = setup.get("lock_file")
    if lock_name is not None:
        if not isinstance(lock_name, str) or not lock_name:
            raise CommandError("lock_file setup must be a nonempty string")
        with _lock_file(root / lock_name):
            yield marker_paths
        return
    yield marker_paths


def _artifact_map(ctx: _FixtureContext) -> dict[str, Any]:
    return {row["locator"]: row for row in ctx.state["artifacts"]}


def _inventory_map(ctx: _FixtureContext) -> dict[str, Any]:
    return {row.locator: row for row in ctx.inventory.artifacts}


def _assertion(ctx: _FixtureContext, row: dict[str, Any]) -> tuple[bool, str]:
    kind = row.get("type")
    value = row.get("value")
    artifacts = _artifact_map(ctx)
    inventory = _inventory_map(ctx)
    state = ctx.state

    if kind == "artifact_locator_present":
        passed = value in artifacts
        return passed, f"locator {value!r} {'present' if passed else 'missing'}"
    if kind == "artifact_locator_absent":
        passed = value not in artifacts
        return passed, f"locator {value!r} {'absent' if passed else 'unexpectedly present'}"
    if kind == "artifact_kind":
        locator = row["locator"]
        actual = artifacts.get(locator, {}).get("path_kind")
        return actual == value, f"{locator}: path_kind={actual!r}, expected {value!r}"
    if kind == "artifact_status":
        locator = row["locator"]
        actual = artifacts.get(locator, {}).get("status")
        return actual == value, f"{locator}: status={actual!r}, expected {value!r}"
    if kind == "artifact_redaction_state":
        locator = row["locator"]
        actual = artifacts.get(locator, {}).get("redaction_state")
        return actual == value, f"{locator}: redaction_state={actual!r}, expected {value!r}"
    if kind == "symlink_scope":
        locator = row["locator"]
        actual = getattr(inventory.get(locator), "symlink_scope", None)
        return actual == value, f"{locator}: symlink_scope={actual!r}, expected {value!r}"
    if kind == "discovery_complete":
        actual = ctx.inventory.discovery_complete
        return actual is value, f"discovery_complete={actual!r}, expected {value!r}"
    if kind == "identity_complete":
        actual = ctx.inventory.identity_complete
        return actual is value, f"identity_complete={actual!r}, expected {value!r}"
    if kind == "analysis_complete":
        actual = state["coverage"]["analysis_complete"]
        return actual is value, f"analysis_complete={actual!r}, expected {value!r}"
    if kind == "target_executed":
        actual = state["run"]["target_executed"]
        return actual is value, f"target_executed={actual!r}, expected {value!r}"
    if kind == "network_used":
        actual = state["run"]["network_used"]
        return actual is value, f"network_used={actual!r}, expected {value!r}"
    if kind == "snapshot_repeat":
        actual = ctx.snapshot_digest == ctx.repeated_snapshot_digest
        return actual is value, f"repeat snapshot stable={actual!r}"
    if kind == "snapshot_digest":
        actual = ctx.snapshot_digest
        return actual == value, f"snapshot_digest={actual}, expected {value}"
    if kind == "resource_limit_contains":
        actual = state["coverage"]["resource_limits_hit"]
        passed = any(str(item).startswith(str(value)) for item in actual)
        return passed, f"resource limits={actual!r}"
    if kind == "unreadable_count":
        actual = state["coverage"]["unreadable_artifact_count"]
        return actual == value, f"unreadable_artifact_count={actual}, expected {value}"
    if kind == "redaction_count_min":
        actual = state["privacy"]["redaction_count"]
        return actual >= value, f"redaction_count={actual}, expected >= {value}"
    if kind == "check_status":
        category = row["category"]
        match = next((item for item in state["checks"] if item["category"] == category), None)
        actual = None if match is None else match["status"]
        return actual == value, f"{category}: status={actual!r}, expected {value!r}"
    if kind == "raw_absent":
        needle = str(value)
        surfaces = row.get("surfaces", ["state", "report"])
        haystacks = []
        if "state" in surfaces:
            haystacks.append(("state", canonical_state_json(state)))
        if "report" in surfaces:
            haystacks.append(("report", ctx.report_html))
        found = [name for name, text in haystacks if needle in text]
        return not found, f"raw value {'absent' if not found else 'found in ' + ','.join(found)}"
    if kind == "marker_absent":
        marker = ctx.marker_paths.get(str(value), ctx.root / str(value))
        passed = not marker.exists()
        return passed, f"marker {value!r} {'absent' if passed else 'was created'}"
    if kind == "egress_network_action":
        preview = build_egress_preview(ScanConfig(root=ctx.root), ctx.inventory)
        actual = preview.network_action
        return actual == value, f"egress network_action={actual!r}, expected {value!r}"
    if kind == "no_analyzed_artifacts":
        bad = [item["locator"] for item in state["artifacts"] if item["status"] == "analyzed"]
        return not bad, f"analyzed artifacts={bad!r}"
    if kind == "readiness":
        actual = state["summary"]["readiness"]
        return actual == value, f"readiness={actual!r}, expected {value!r}"
    raise CommandError(f"Unknown ScanBench assertion type: {kind!r}")


def _run_fixture(bench_root: Path, fixture_name: str) -> FixtureResult:
    fixture_dir = bench_root / "fixtures" / fixture_name
    meta = _load_json(fixture_dir / "fixture.json")
    expected = _load_json(fixture_dir / "expected.json")
    assertions = expected.get("assertions")
    if not isinstance(assertions, list) or not assertions:
        raise CommandError(f"ScanBench fixture {fixture_name} has no assertions")

    with tempfile.TemporaryDirectory(prefix=f"scanbench-{fixture_name}-") as directory:
        temp_root = Path(directory)
        source = fixture_dir / "project"
        project = temp_root / "project"
        shutil.copytree(source, project)
        output_dir = temp_root / "output"
        output_dir.mkdir()
        state_path = output_dir / "state.json"
        report_path = output_dir / "report.html"
        setup = meta.get("setup", {})
        if not isinstance(setup, dict):
            raise CommandError(f"ScanBench fixture {fixture_name} setup must be an object")
        with _fixture_setup(project, setup, temp_root) as markers:
            setup_notes = ()
            link_setup = setup.get('external_symlink')
            if isinstance(link_setup, dict):
                link = project / link_setup.get('link', 'escape')
                if not link.is_symlink():
                    setup_notes = ('Native Windows junction/reparse escape exercised; symlink creation privilege unavailable',)
            config = _scan_config(project, meta.get("config", {}), state_path, report_path)
            inventory = build_inventory(config)
            first_snapshot = build_snapshot(inventory)
            second_snapshot = build_snapshot(build_inventory(config))
            result = scan_project(config)
            validate_state(result.state, version="1.4")
            validate_report(report_path)
            context = _FixtureContext(
                name=fixture_name,
                root=project,
                inventory=inventory,
                state=result.state,
                report_html=report_path.read_text(encoding="utf-8"),
                snapshot_digest=first_snapshot.digest,
                repeated_snapshot_digest=second_snapshot.digest,
                marker_paths=markers,
            )
            rows: list[AssertionResult] = []
            for index, assertion in enumerate(assertions, 1):
                if not isinstance(assertion, dict):
                    raise CommandError(f"ScanBench fixture {fixture_name} assertion {index} must be an object")
                dimension = assertion.get("dimension")
                if dimension not in DIMENSIONS:
                    raise CommandError(f"ScanBench fixture {fixture_name} assertion {index} has invalid dimension")
                passed, detail = _assertion(context, assertion)
                rows.append(AssertionResult(
                    fixture=fixture_name,
                    dimension=dimension,
                    assertion=str(assertion.get("type")),
                    passed=passed,
                    detail=detail,
                ))
    return FixtureResult(name=fixture_name, passed=all(row.passed for row in rows), assertions=tuple(rows), setup_notes=setup_notes)


def run_bench(*, fixture: str | None = None, bench_root: str | Path | None = None) -> BenchResult:
    root = locate_scanbench_root(bench_root)
    manifest = _load_json(root / "manifest.json")
    fixtures = manifest.get("fixtures")
    dimensions = manifest.get("dimensions")
    if not isinstance(fixtures, list) or not all(isinstance(item, str) for item in fixtures):
        raise CommandError("ScanBench manifest fixtures must be a string array")
    if dimensions != list(DIMENSIONS):
        raise CommandError("ScanBench manifest dimensions do not match the v1 contract")
    selected = fixtures
    if fixture is not None:
        if fixture not in fixtures:
            raise CommandError(f"Unknown ScanBench fixture: {fixture}")
        selected = [fixture]
    results = tuple(_run_fixture(root, name) for name in selected)
    dimension_status: dict[str, bool | None] = {}
    for dimension in DIMENSIONS:
        relevant = [row for result in results for row in result.assertions if row.dimension == dimension]
        # A single-fixture run may legitimately not exercise every dimension.
        dimension_status[dimension] = all(row.passed for row in relevant) if relevant else None
    return BenchResult(fixtures=results, dimensions=dimension_status)


def format_bench(result: BenchResult) -> str:
    lines: list[str] = []
    for fixture in result.fixtures:
        lines.append(f"{'PASS' if fixture.passed else 'FAIL'} {fixture.name}")
        for note in fixture.setup_notes:
            lines.append('  ' + note)
        for row in fixture.assertions:
            if not row.passed:
                lines.append(f"  FAIL [{DIMENSION_LABELS[row.dimension]}] {row.assertion}: {row.detail}")
    lines.append("")
    lines.append("Dimensions")
    for dimension in DIMENSIONS:
        status = result.dimensions[dimension]
        label = "PASS" if status is True else "FAIL" if status is False else "NOT RUN"
        lines.append(f"{label} {DIMENSION_LABELS[dimension]}")
    lines.append("No blended overall quality score is calculated.")
    return "\n".join(lines)
