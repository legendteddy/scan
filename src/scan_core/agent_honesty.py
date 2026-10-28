"""Deterministic Agent-Honesty ScanBench for false-confidence regressions.

This benchmark does not grade model intelligence. It exercises Scan's state,
builder, validator and evidence-reuse contracts against specific claim upgrades
that an agent must not make without stronger evidence.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import io
import json
from pathlib import Path
import tempfile
from typing import Callable, Any

from .builder import BuilderError, SemanticStateBuilder
from .config import ScanConfig
from .core import scan_project
from .state import canonical_state_json
from .version import __version__


HONESTY_SCENARIOS = (
    "tests-exist-not-passed",
    "inventory-not-semantic-review",
    "static-not-runtime-verification",
    "unchanged-not-freshly-reviewed",
    "missing-evidence-not-safe",
)


@dataclass(frozen=True)
class HonestyScenarioResult:
    name: str
    claim_guard: str
    passed: bool
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "claim_guard": self.claim_guard,
            "passed": self.passed,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class AgentHonestyBenchResult:
    scenarios: tuple[HonestyScenarioResult, ...]

    @property
    def passed(self) -> bool:
        return bool(self.scenarios) and all(row.passed for row in self.scenarios)

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent_honesty_scanbench_version": "1",
            "scan_version": __version__,
            "scenarios": [row.as_dict() for row in self.scenarios],
            "passed": self.passed,
            "score": None,
            "score_note": "No blended honesty or intelligence score is calculated.",
        }


def _write(root: Path, relative: str, content: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _artifact(state: dict[str, Any], locator: str) -> dict[str, Any]:
    return next(row for row in state["artifacts"] if row["locator"] == locator)


def _check(state: dict[str, Any], category: str) -> dict[str, Any]:
    return next(row for row in state["checks"] if row["category"] == category)


def _base_state(root: Path) -> dict[str, Any]:
    return scan_project(ScanConfig(root=root, baseline_mode="none", reuse_enabled=False)).state


def _scenario_tests_exist_not_passed() -> HonestyScenarioResult:
    with tempfile.TemporaryDirectory(prefix="scanbench-honesty-tests-") as directory:
        root = Path(directory)
        _write(root, "app.py", "def add(a, b):\n    return a + b\n")
        _write(root, "tests/test_app.py", "def test_add():\n    assert 1 + 1 == 2\n")
        state = _base_state(root)
        test_artifact = _artifact(state, "tests/test_app.py")
        testing = _check(state, "testing_and_reliability")
        passed = (
            test_artifact["status"] == "content_read"
            and testing["status"] == "not_assessed"
            and testing["verification_state"] == "unverified"
            and state["summary"]["readiness"] == "not established"
            and state["coverage"]["analysis_complete"] is False
        )
        detail = (
            f"test artifact={test_artifact['status']}; testing check={testing['status']}/"
            f"{testing['verification_state']}; readiness={state['summary']['readiness']}"
        )
        return HonestyScenarioResult(
            "tests-exist-not-passed",
            "The presence or readable contents of tests must not be reported as tests having passed.",
            passed,
            detail,
        )


def _scenario_inventory_not_semantic_review() -> HonestyScenarioResult:
    with tempfile.TemporaryDirectory(prefix="scanbench-honesty-inventory-") as directory:
        root = Path(directory)
        _write(root, "service.py", "def run():\n    return 'ok'\n")
        state = _base_state(root)
        service = _artifact(state, "service.py")
        analyzed = [row["locator"] for row in state["artifacts"] if row["status"] == "analyzed"]
        semantic_unknown = next(
            (row for row in state["unknowns"] if row["id"] == "unknown:semantic-runtime"),
            None,
        )
        passed = (
            service["status"] == "content_read"
            and not analyzed
            and state["coverage"]["analysis_complete"] is False
            and semantic_unknown is not None
            and "semantic" in semantic_unknown["reason"].lower()
        )
        detail = (
            f"service={service['status']}; analyzed={len(analyzed)}; "
            f"analysis_complete={state['coverage']['analysis_complete']}; "
            f"semantic_unknown={semantic_unknown is not None}"
        )
        return HonestyScenarioResult(
            "inventory-not-semantic-review",
            "Inventory and hashing must not be upgraded to semantic analysis.",
            passed,
            detail,
        )


def _scenario_static_not_runtime_verification() -> HonestyScenarioResult:
    with tempfile.TemporaryDirectory(prefix="scanbench-honesty-runtime-") as directory:
        root = Path(directory)
        _write(root, "worker.py", "def work():\n    return 42\n")
        state = _base_state(root)
        artifact = _artifact(state, "worker.py")
        producer = state["provenance"]["tool_versions"][0]
        builder = SemanticStateBuilder.from_state(state)
        evidence_id = builder.add_evidence(
            artifact_id=artifact["id"],
            locator=artifact["locator"],
            kind="static",
            claim="Worker source was reviewed statically",
            result="The function returns a literal value in source",
            method="bounded static semantic inspection",
            limitations="The worker was not executed",
            source_digest=artifact["content_identity"],
            producer_kind=producer["kind"],
            producer_name=producer["name"],
            producer_version=producer["version"],
            evidence_class="static_semantic",
            check_id="check-correctness_and_integrity",
        )
        builder.assess_check(
            category="correctness_and_integrity",
            status="assessed",
            scope="worker.py",
            method="static source review",
            artifact_ids=[artifact["id"]],
            evidence_ids=[evidence_id],
            verification_state="observed",
            result="Synthetic attempted runtime claim",
            limitations="No runtime observation exists",
            reason="Synthetic adversarial upgrade attempt",
            next_step=None,
        )
        rejected = False
        error_text = ""
        try:
            builder.build()
        except BuilderError as error:
            rejected = True
            error_text = str(error)
        passed = rejected and "observed" in error_text.lower()
        return HonestyScenarioResult(
            "static-not-runtime-verification",
            "Static evidence must not satisfy an observed/runtime verification claim.",
            passed,
            error_text or "invalid observed claim was unexpectedly accepted",
        )


def _scenario_unchanged_not_freshly_reviewed() -> HonestyScenarioResult:
    with tempfile.TemporaryDirectory(prefix="scanbench-honesty-reuse-") as directory:
        root = Path(directory)
        _write(root, "app.txt", "stable bytes\n")
        state_path = root / ".scan" / "state.json"
        first = scan_project(ScanConfig(root=root, output_state=state_path)).state
        artifact = _artifact(first, "app.txt")
        producer = first["provenance"]["tool_versions"][0]
        builder = SemanticStateBuilder.from_state(first)
        evidence_id = builder.add_evidence(
            artifact_id=artifact["id"],
            locator=artifact["locator"],
            kind="static",
            claim="The stable artifact received a semantic observation",
            result="This observation belongs to the previous scan",
            method="bounded static semantic inspection",
            limitations="A future unchanged scan must preserve reuse provenance",
            source_digest=artifact["content_identity"],
            producer_kind=producer["kind"],
            producer_name=producer["name"],
            producer_version=producer["version"],
            evidence_class="static_semantic",
            check_id="check-maintainability",
        )
        semantic_first = builder.build()
        original_time = next(row for row in semantic_first["evidence"] if row["id"] == evidence_id)["time"]
        state_path.write_text(canonical_state_json(semantic_first) + "\n", encoding="utf-8")

        second = scan_project(ScanConfig(root=root, output_state=state_path)).state
        reused = next((row for row in second["evidence"] if row["id"] == evidence_id), None)
        second_artifact = _artifact(second, "app.txt")
        maintainability = _check(second, "maintainability")
        passed = (
            reused is not None
            and reused["freshness"]["status"] == "verified_reuse"
            and reused["inspection_origin"] == "verified_reuse"
            and reused["time"] == original_time
            and second["baseline"]["reused_evidence_count"] >= 1
            and second_artifact["status"] == "content_read"
            and maintainability["status"] == "not_assessed"
        )
        detail = (
            "reused evidence missing"
            if reused is None
            else (
                f"freshness={reused['freshness']['status']}; origin={reused['inspection_origin']}; "
                f"artifact={second_artifact['status']}; check={maintainability['status']}"
            )
        )
        return HonestyScenarioResult(
            "unchanged-not-freshly-reviewed",
            "Unchanged bytes may support verified reuse, but must not be relabeled as a fresh review or deeper assessment.",
            passed,
            detail,
        )


def _scenario_missing_evidence_not_safe() -> HonestyScenarioResult:
    with tempfile.TemporaryDirectory(prefix="scanbench-honesty-missing-") as directory:
        root = Path(directory)
        _write(root, "config.py", "SAFE_MODE = True\n")
        state = _base_state(root)
        artifact = _artifact(state, "config.py")

        finding_rejected = False
        try:
            SemanticStateBuilder.from_state(state).add_finding(
                title="Synthetic unsupported safety claim",
                impact="Would falsely imply safety",
                severity="informational",
                confidence="high",
                verification_state="static",
                artifact_ids=[artifact["id"]],
                evidence_ids=[],
                uncertainty="No evidence was attached",
                recommendation="Do not accept unsupported claims",
                safe_verification="Attach direct evidence first",
            )
        except BuilderError:
            finding_rejected = True

        check_builder = SemanticStateBuilder.from_state(state)
        check_builder.assess_check(
            category="security_and_trust",
            status="assessed",
            scope="config.py",
            method="synthetic unsupported assessment",
            artifact_ids=[artifact["id"]],
            evidence_ids=[],
            verification_state="static",
            result="Synthetic attempted clean result",
            limitations="No evidence exists",
            reason="Synthetic adversarial upgrade attempt",
            next_step=None,
        )
        check_rejected = False
        try:
            check_builder.build()
        except BuilderError:
            check_rejected = True

        passed = (
            finding_rejected
            and check_rejected
            and len(state["findings"]) == 0
            and len(state["unknowns"]) > 0
            and state["summary"]["readiness"] == "not established"
        )
        detail = (
            f"finding_rejected={finding_rejected}; check_rejected={check_rejected}; "
            f"findings={len(state['findings'])}; unknowns={len(state['unknowns'])}; "
            f"readiness={state['summary']['readiness']}"
        )
        return HonestyScenarioResult(
            "missing-evidence-not-safe",
            "Missing findings or missing evidence must not be interpreted as a clean bill of health.",
            passed,
            detail,
        )


_SCENARIO_RUNNERS: dict[str, Callable[[], HonestyScenarioResult]] = {
    "tests-exist-not-passed": _scenario_tests_exist_not_passed,
    "inventory-not-semantic-review": _scenario_inventory_not_semantic_review,
    "static-not-runtime-verification": _scenario_static_not_runtime_verification,
    "unchanged-not-freshly-reviewed": _scenario_unchanged_not_freshly_reviewed,
    "missing-evidence-not-safe": _scenario_missing_evidence_not_safe,
}


def run_agent_honesty_bench(*, scenario: str | None = None) -> AgentHonestyBenchResult:
    """Run all deterministic false-confidence guards, or one named scenario."""
    if scenario is not None and scenario not in _SCENARIO_RUNNERS:
        raise ValueError(f"Unknown Agent-Honesty ScanBench scenario: {scenario}")
    selected = (scenario,) if scenario is not None else HONESTY_SCENARIOS
    rows = tuple(_SCENARIO_RUNNERS[name]() for name in selected)
    return AgentHonestyBenchResult(rows)


def format_agent_honesty_bench(result: AgentHonestyBenchResult) -> str:
    lines = ["Agent-Honesty ScanBench", ""]
    for row in result.scenarios:
        lines.append(f"{'PASS' if row.passed else 'FAIL'} {row.name}")
        lines.append(f"  Guard: {row.claim_guard}")
        if not row.passed:
            lines.append(f"  Detail: {row.detail}")
    lines.extend(("", "No blended honesty or intelligence score is calculated."))
    return "\n".join(lines)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m scan_core.agent_honesty",
        description="Run Scan's deterministic false-confidence contract benchmark",
    )
    parser.add_argument("scenario", nargs="?", choices=HONESTY_SCENARIOS)
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    result = run_agent_honesty_bench(scenario=args.scenario)
    if args.json:
        print(json.dumps(result.as_dict(), ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    else:
        print(format_agent_honesty_bench(result))
    return 0 if result.passed else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
