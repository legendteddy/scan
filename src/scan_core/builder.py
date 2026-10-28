"""Schema-safe semantic construction helpers for Scan 1.3/1.4 state.

The validator remains authoritative. This module makes valid records easier to
construct without asking agents to hand-edit deeply nested dictionaries.
"""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any, Iterable, Mapping, Sequence

from .errors import ValidationError
from .reuse import check_definition_digest
from .validate import CHECK_CATEGORIES, validate_state


StringInput = str | Sequence[str] | None


class BuilderError(ValidationError):
    """Raised when a semantic record cannot be constructed safely."""


def _strings(value: StringInput, path: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        values = (value,)
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        values = tuple(value)
    else:
        raise BuilderError(f"{path}: expected a nonempty string or string array")
    if not all(isinstance(item, str) and item.strip() for item in values):
        raise BuilderError(f"{path}: expected a nonempty string or string array")
    return values


def _required(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BuilderError(f"{path}: expected a nonempty string")
    return value


def _record_id(prefix: str, payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return f"{prefix}:" + hashlib.sha256(encoded).hexdigest()[:20]


def _json_record(record: object) -> dict[str, Any]:
    def convert(value: Any) -> Any:
        if isinstance(value, tuple):
            return [convert(item) for item in value]
        if isinstance(value, list):
            return [convert(item) for item in value]
        if isinstance(value, dict):
            return {key: convert(item) for key, item in value.items()}
        return value

    return convert(asdict(record))


@dataclass(frozen=True)
class ComponentRecord:
    id: str
    name: str
    purpose: str
    artifact_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    boundaries: str


@dataclass(frozen=True)
class EvidenceRecord:
    id: str
    artifact_id: str
    locator: str
    kind: str
    claim: str
    result: str
    method: str
    time: str
    limitations: str
    inspection_origin: str
    producer: dict[str, str]
    source_digest: str


@dataclass(frozen=True)
class RelationshipRecord:
    id: str
    from_id: str
    to_id: str
    kind: str
    explanation: str
    evidence_ids: tuple[str, ...]
    confidence: str
    verification_state: str


@dataclass(frozen=True)
class FindingRecord:
    id: str
    title: str
    impact: str
    severity: str
    confidence: str
    verification_state: str
    artifact_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    uncertainty: str
    recommendation: str
    safe_verification: str


@dataclass(frozen=True)
class ControlRecord:
    id: str
    description: str
    artifact_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    effectiveness_status: str
    limitations: str


@dataclass(frozen=True)
class UnknownRecord:
    id: str
    question: str
    artifact_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    reason: str
    impact: str
    next_safe_step: str


@dataclass(frozen=True)
class ActionRecord:
    id: str
    description: str
    priority: str
    related_ids: tuple[str, ...]
    prerequisites: tuple[str, ...]
    authorization_requirements: str
    expected_verification: str
    completion_state: str


@dataclass(frozen=True)
class CheckRecord:
    id: str
    category: str
    title: str
    status: str
    scope: str
    method: str
    artifact_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    related_ids: tuple[str, ...]
    verification_state: str
    result: str
    limitations: str
    reason: str
    next_step: str | None


class SemanticStateBuilder:
    """Build semantic state while normalizing list fields and checking references."""

    def __init__(self, state: Mapping[str, Any]):
        self.state: dict[str, Any] = deepcopy(dict(state))
        try:
            validate_state(self.state)
        except ValidationError as error:
            raise BuilderError(f"base_state: {error}") from error

    @classmethod
    def from_state(cls, state: Mapping[str, Any]) -> "SemanticStateBuilder":
        return cls(state)

    def _ids(self, collection: str) -> set[str]:
        return {row["id"] for row in self.state[collection]}

    def _refs(self, record_id: str, field: str, refs: Iterable[str], allowed: set[str], expected: str) -> None:
        for ref in refs:
            if ref not in allowed:
                raise BuilderError(f"{record_id}.{field}: unknown reference {ref!r}; expected {expected}")

    def _append(self, collection: str, record: object) -> str:
        row = _json_record(record)
        record_id = row["id"]
        if any(record_id in self._ids(name) for name in (
            "artifacts", "components", "relationships", "evidence", "findings", "controls", "unknowns", "actions", "checks"
        )):
            raise BuilderError(f"{record_id}.id: duplicate state ID")
        self.state[collection].append(row)
        return record_id

    def add_component(
        self, *, name: str, purpose: str, artifact_ids: StringInput = None,
        evidence_ids: StringInput = None, boundaries: str = "Not established",
        record_id: str | None = None,
    ) -> str:
        artifacts = _strings(artifact_ids, "component.artifact_ids")
        evidence = _strings(evidence_ids, "component.evidence_ids")
        payload = {"name": _required(name, "component.name"), "purpose": _required(purpose, "component.purpose")}
        ident = record_id or _record_id("component", payload)
        self._refs(ident, "artifact_ids", artifacts, self._ids("artifacts"), "artifact IDs")
        self._refs(ident, "evidence_ids", evidence, self._ids("evidence"), "evidence IDs")
        return self._append("components", ComponentRecord(ident, name, purpose, artifacts, evidence, _required(boundaries, f"{ident}.boundaries")))

    def add_evidence(
        self, *, artifact_id: str, locator: str, kind: str, claim: str, result: str,
        method: str, source_digest: str, producer_kind: str,
        producer_name: str, producer_version: str, limitations: str | None = None,
        time: str | None = None, inspection_origin: str = "fresh",
        evidence_class: str | None = None, check_id: str | None = None,
        record_id: str | None = None,
    ) -> str:
        self._refs("evidence", "artifact_id", (artifact_id,), self._ids("artifacts"), "an artifact ID")
        payload = {"artifact_id": artifact_id, "locator": locator, "kind": kind, "claim": claim, "result": result}
        ident = record_id or _record_id("evidence", payload)
        producer = {
            "kind": _required(producer_kind, f"{ident}.producer.kind"),
            "name": _required(producer_name, f"{ident}.producer.name"),
            "version": _required(producer_version, f"{ident}.producer.version"),
        }
        if self.state.get("schema_version") == "1.4" and inspection_origin != "fresh":
            raise BuilderError(f"{ident}.inspection_origin: Scan 1.4 semantic authoring creates fresh evidence only")
        if evidence_class is not None:
            evidence_class = _required(evidence_class, f"{ident}.evidence_class")
        if check_id is not None:
            check_id = _required(check_id, f"{ident}.check_id")
            self._refs(ident, "check_id", (check_id,), self._ids("checks"), "a check ID")
        observed_at = time or self.state["run"]["completed_at"]
        record = EvidenceRecord(
            ident, artifact_id, _required(locator, f"{ident}.locator"), _required(kind, f"{ident}.kind"),
            _required(claim, f"{ident}.claim"), _required(result, f"{ident}.result"),
            _required(method, f"{ident}.method"), observed_at,
            _required(limitations, f"{ident}.limitations"), _required(inspection_origin, f"{ident}.inspection_origin"),
            producer, _required(source_digest, f"{ident}.source_digest"),
        )
        evidence_id = self._append("evidence", record)
        row = next(item for item in self.state["evidence"] if item["id"] == evidence_id)
        if self.state.get("schema_version") == "1.4":
            row["freshness"] = {
                "status": "fresh",
                "source_state_digest": None,
                "source_evidence_id": None,
                "original_observed_at": observed_at,
                "reused_at": None,
                "reuse_reason": None,
            }
            if evidence_class is not None:
                row["evidence_class"] = evidence_class
            if check_id is not None:
                row["check_id"] = check_id
                check = next(item for item in self.state["checks"] if item["id"] == check_id)
                row["check_definition_digest"] = check_definition_digest(check)
        tools = self.state.get("provenance", {}).get("tool_versions")
        if isinstance(tools, list) and producer not in tools:
            tools.append(dict(producer))
        return evidence_id

    def add_relationship(
        self, *, from_id: str, to_id: str, kind: str, explanation: str,
        evidence_ids: StringInput, confidence: str, verification_state: str,
        record_id: str | None = None,
    ) -> str:
        evidence = _strings(evidence_ids, "relationship.evidence_ids")
        payload = {"from_id": from_id, "to_id": to_id, "kind": kind, "explanation": explanation}
        ident = record_id or _record_id("relationship", payload)
        endpoints = self._ids("artifacts") | self._ids("components")
        self._refs(ident, "from_id", (from_id,), endpoints, "artifact/component IDs")
        self._refs(ident, "to_id", (to_id,), endpoints, "artifact/component IDs")
        self._refs(ident, "evidence_ids", evidence, self._ids("evidence"), "evidence IDs")
        return self._append("relationships", RelationshipRecord(
            ident, from_id, to_id, _required(kind, f"{ident}.kind"), _required(explanation, f"{ident}.explanation"),
            evidence, _required(confidence, f"{ident}.confidence"), _required(verification_state, f"{ident}.verification_state"),
        ))

    def add_finding(
        self, *, title: str, impact: str, severity: str, confidence: str,
        verification_state: str, uncertainty: str, recommendation: str, safe_verification: str,
        artifact_ids: StringInput = None, evidence_ids: StringInput = None,
        record_id: str | None = None,
    ) -> str:
        artifacts = _strings(artifact_ids, "finding.artifact_ids")
        evidence = _strings(evidence_ids, "finding.evidence_ids")
        payload = {"title": title, "impact": impact, "severity": severity, "artifact_ids": artifacts}
        ident = record_id or _record_id("finding", payload)
        if not artifacts:
            raise BuilderError(f"{ident}.artifact_ids: expected at least one artifact ID")
        if not evidence:
            raise BuilderError(f"{ident}.evidence_ids: expected at least one evidence ID")
        self._refs(ident, "artifact_ids", artifacts, self._ids("artifacts"), "artifact IDs")
        self._refs(ident, "evidence_ids", evidence, self._ids("evidence"), "evidence IDs")
        record = FindingRecord(
            ident, _required(title, f"{ident}.title"), _required(impact, f"{ident}.impact"),
            _required(severity, f"{ident}.severity"), _required(confidence, f"{ident}.confidence"),
            _required(verification_state, f"{ident}.verification_state"), artifacts, evidence,
            _required(uncertainty, f"{ident}.uncertainty"), _required(recommendation, f"{ident}.recommendation"),
            _required(safe_verification, f"{ident}.safe_verification"),
        )
        return self._append("findings", record)

    def add_control(
        self, *, description: str, artifact_ids: StringInput, evidence_ids: StringInput,
        effectiveness_status: str, limitations: str, record_id: str | None = None,
    ) -> str:
        artifacts = _strings(artifact_ids, "control.artifact_ids")
        evidence = _strings(evidence_ids, "control.evidence_ids")
        payload = {"description": description, "artifact_ids": artifacts, "evidence_ids": evidence}
        ident = record_id or _record_id("control", payload)
        self._refs(ident, "artifact_ids", artifacts, self._ids("artifacts"), "artifact IDs")
        self._refs(ident, "evidence_ids", evidence, self._ids("evidence"), "evidence IDs")
        return self._append("controls", ControlRecord(
            ident, _required(description, f"{ident}.description"), artifacts, evidence,
            _required(effectiveness_status, f"{ident}.effectiveness_status"), _required(limitations, f"{ident}.limitations"),
        ))

    def add_unknown(
        self, *, question: str, artifact_ids: StringInput = None, evidence_ids: StringInput = None,
        reason: str, impact: str, next_safe_step: str, record_id: str | None = None,
    ) -> str:
        artifacts = _strings(artifact_ids, "unknown.artifact_ids")
        evidence = _strings(evidence_ids, "unknown.evidence_ids")
        payload = {"question": question, "artifact_ids": artifacts}
        ident = record_id or _record_id("unknown", payload)
        self._refs(ident, "artifact_ids", artifacts, self._ids("artifacts"), "artifact IDs")
        self._refs(ident, "evidence_ids", evidence, self._ids("evidence"), "evidence IDs")
        return self._append("unknowns", UnknownRecord(
            ident, _required(question, f"{ident}.question"), artifacts, evidence,
            _required(reason, f"{ident}.reason"), _required(impact, f"{ident}.impact"),
            _required(next_safe_step, f"{ident}.next_safe_step"),
        ))

    def add_action(
        self, *, description: str, priority: str, related_ids: StringInput = None,
        prerequisites: StringInput = None, authorization_requirements: str,
        expected_verification: str, completion_state: str = "not_started",
        record_id: str | None = None,
    ) -> str:
        related = _strings(related_ids, "action.related_ids")
        prereqs = _strings(prerequisites, "action.prerequisites")
        payload = {"description": description, "priority": priority, "related_ids": related}
        ident = record_id or _record_id("action", payload)
        all_ids: set[str] = set()
        for name in ("artifacts", "components", "relationships", "evidence", "findings", "controls", "unknowns", "actions", "checks"):
            all_ids |= self._ids(name)
        self._refs(ident, "related_ids", related, all_ids, "existing state IDs")
        return self._append("actions", ActionRecord(
            ident, _required(description, f"{ident}.description"), _required(priority, f"{ident}.priority"), related, prereqs,
            _required(authorization_requirements, f"{ident}.authorization_requirements"),
            _required(expected_verification, f"{ident}.expected_verification"),
            _required(completion_state, f"{ident}.completion_state"),
        ))

    def _check_record(
        self, *, category: str, status: str, scope: str, method: str,
        artifact_ids: StringInput, evidence_ids: StringInput, related_ids: StringInput = None,
        verification_state: str, result: str, limitations: str, reason: str,
        next_step: str | None = None, title: str | None = None, record_id: str,
    ) -> CheckRecord:
        _required(category, "check.category")
        artifacts = _strings(artifact_ids, f"check:{category}.artifact_ids")
        evidence = _strings(evidence_ids, f"check:{category}.evidence_ids")
        related = _strings(related_ids, f"check:{category}.related_ids")
        ident = _required(record_id, "check.id")
        self._refs(ident, "artifact_ids", artifacts, self._ids("artifacts"), "artifact IDs")
        self._refs(ident, "evidence_ids", evidence, self._ids("evidence"), "evidence IDs")
        allowed_related = self._ids("findings") | self._ids("controls") | self._ids("unknowns") | self._ids("actions")
        self._refs(ident, "related_ids", related, allowed_related, "finding/control/unknown/action IDs")
        record = CheckRecord(
            ident, category, title or category.replace("_", " ").title(), _required(status, f"{ident}.status"),
            _required(scope, f"{ident}.scope"), _required(method, f"{ident}.method"), artifacts, evidence, related,
            _required(verification_state, f"{ident}.verification_state"), _required(result, f"{ident}.result"),
            _required(limitations, f"{ident}.limitations"), _required(reason, f"{ident}.reason"), next_step,
        )
        return record

    def add_check(self, *, record_id: str, **definition: Any) -> str:
        """Add one concrete check; category is coverage, never identity."""
        return self._append("checks", self._check_record(record_id=record_id, **definition))

    def update_check(self, record_id: str, **changes: Any) -> str:
        """Update only an existing check ID, retaining unspecified fields."""
        current = next((row for row in self.state["checks"] if row["id"] == record_id), None)
        if current is None:
            raise BuilderError(f"{record_id}: unknown check ID")
        definition = {key: value for key, value in current.items() if key != "id"}
        definition.update(changes)
        row = _json_record(self._check_record(record_id=record_id, **definition))
        self.state["checks"][self.state["checks"].index(current)] = row
        return record_id

    def assess_check(self, *, category: str, record_id: str | None = None, **definition: Any) -> str:
        """Compatibility upsert. Prefer add_check/update_check for explicit identity.

        Category-only calls update the single existing category check. Once a
        category has multiple checks, the caller must supply an ID.
        """
        if record_id is None:
            matches = [row for row in self.state["checks"] if row["category"] == category]
            if len(matches) > 1:
                raise BuilderError(f"check.category: {category!r} is ambiguous; supply record_id")
            record_id = matches[0]["id"] if matches else f"check:{category}"
        if record_id in self._ids("checks"):
            return self.update_check(record_id, category=category, **definition)
        return self.add_check(record_id=record_id, category=category, **definition)

    def category_coverage(self) -> dict[str, tuple[str, ...]]:
        """Required coverage, independently of additional target-specific checks."""
        return {category: tuple(row["id"] for row in self.state["checks"] if row["category"] == category)
                for category in CHECK_CATEGORIES}

    def mark_artifact_analyzed(
        self, artifact_id: str, *, evidence_ids: StringInput, reason: str = "Semantic analysis completed"
    ) -> None:
        evidence = _strings(evidence_ids, f"{artifact_id}.evidence_ids")
        artifact = next((row for row in self.state["artifacts"] if row["id"] == artifact_id), None)
        if artifact is None:
            raise BuilderError(f"{artifact_id}: unknown artifact ID")
        evidence_rows = {row["id"]: row for row in self.state["evidence"]}
        self._refs(artifact_id, "evidence_ids", evidence, set(evidence_rows), "evidence IDs")
        direct = [evidence_rows[ident] for ident in evidence if evidence_rows[ident]["artifact_id"] == artifact_id]
        if not direct:
            raise BuilderError(f"{artifact_id}.evidence_ids: analyzed artifacts require evidence attached to the same artifact")
        substantive = [row for row in direct if row["kind"] != "unverified" and row["inspection_origin"] in {"fresh", "verified_reuse"}]
        if not substantive:
            raise BuilderError(f"{artifact_id}.evidence_ids: analyzed artifacts require fresh/reused substantive evidence")
        origin = substantive[0]["inspection_origin"]
        artifact["status"] = "analyzed"
        artifact["reason"] = reason
        artifact["inspection_origin"] = origin
        artifact["inspected_at"] = substantive[0]["time"]
        artifact["evidence_ids"] = list(dict.fromkeys([*artifact["evidence_ids"], *evidence]))

    def remove_unknown(self, unknown_id: str) -> None:
        before = len(self.state["unknowns"])
        self.state["unknowns"] = [row for row in self.state["unknowns"] if row["id"] != unknown_id]
        if len(self.state["unknowns"]) == before:
            raise BuilderError(f"{unknown_id}: unknown unknown-ID")

    def set_summary(
        self, *, overview: str | None = None, operation: str | None = None,
        condition: str | None = None, strengths: StringInput = None,
        priorities: StringInput = None, readiness: str | None = None,
        evidence_ids: StringInput = None, limitations: str | None = None,
    ) -> None:
        summary = self.state["summary"]
        for key, value in (("overview", overview), ("operation", operation), ("condition", condition),
                           ("readiness", readiness), ("limitations", limitations)):
            if value is not None:
                summary[key] = _required(value, f"summary.{key}")
        if strengths is not None:
            summary["strengths"] = list(_strings(strengths, "summary.strengths"))
        if priorities is not None:
            summary["priorities"] = list(_strings(priorities, "summary.priorities"))
        if evidence_ids is not None:
            refs = _strings(evidence_ids, "summary.evidence_ids")
            self._refs("summary", "evidence_ids", refs, self._ids("evidence"), "evidence IDs")
            summary["evidence_ids"] = list(refs)

    def set_continuation(
        self, *, completed: StringInput = None, remaining: StringInput = None,
        hypotheses: StringInput = None, decisions: StringInput = None,
        revalidation: StringInput = None, source_needs: StringInput = None,
        authorization_note: str | None = None,
    ) -> None:
        continuation = self.state["continuation"]
        for key, value in (
            ("completed", completed), ("remaining", remaining), ("hypotheses", hypotheses),
            ("decisions", decisions), ("revalidation", revalidation), ("source_needs", source_needs),
        ):
            if value is not None:
                continuation[key] = list(_strings(value, f"continuation.{key}"))
        if authorization_note is not None:
            continuation["authorization_note"] = _required(authorization_note, "continuation.authorization_note")

    def build(self, *, analysis_complete: bool | None = None) -> dict[str, Any]:
        coverage = self.state["coverage"]
        if self.state.get("schema_version") == "1.4":
            baseline = self.state["baseline"]
            checks_by_id = {row["id"]: row for row in self.state["checks"]}
            for evidence in self.state["evidence"]:
                freshness = evidence.get("freshness")
                if isinstance(freshness, dict) and freshness.get("status") == "fresh":
                    check_id = evidence.get("check_id")
                    if isinstance(check_id, str) and check_id in checks_by_id:
                        evidence["check_definition_digest"] = check_definition_digest(checks_by_id[check_id])
            reused = sum(
                1 for row in self.state["evidence"]
                if isinstance(row.get("freshness"), dict)
                and row["freshness"].get("status") == "verified_reuse"
            )
            fresh = sum(
                1 for row in self.state["evidence"]
                if isinstance(row.get("freshness"), dict)
                and row["freshness"].get("status") == "fresh"
            )
            if baseline["status"] != "used" and reused:
                raise BuilderError("baseline.reused_evidence_count: verified_reuse evidence requires a used baseline")
            baseline["reused_evidence_count"] = reused
            baseline["fresh_evidence_count"] = fresh
        coverage["counts_by_status"] = dict(Counter(row["status"] for row in self.state["artifacts"]))
        coverage["counts_by_check_status"] = dict(Counter(row["status"] for row in self.state["checks"]))
        coverage["checks_complete"] = all(row["status"] in {"assessed", "not_applicable"} for row in self.state["checks"])
        coverage["checks_performed"] = [row["category"] for row in self.state["checks"] if row["status"] in {"assessed", "partial"}]
        coverage["checks_not_performed"] = [row["category"] for row in self.state["checks"] if row["status"] in {"not_assessed", "blocked"}]
        if analysis_complete is not None:
            coverage["analysis_complete"] = analysis_complete
            if analysis_complete:
                coverage["limits"] = [
                    value for value in coverage["limits"]
                    if value != "Semantic analysis has not been performed by deterministic Scan Core"
                ]
                self.state["continuation"]["remaining"] = [
                    value for value in self.state["continuation"]["remaining"]
                    if not value.startswith("Perform semantic analysis for applicable check categories")
                ]
        if not coverage["analysis_complete"] and not coverage["limits"]:
            coverage["limits"] = ["Semantic analysis remains incomplete"]
        if not coverage["analysis_complete"] and not self.state["continuation"]["remaining"]:
            self.state["continuation"]["remaining"] = ["Complete remaining semantic analysis and revalidate coverage"]
        try:
            validate_state(self.state)
        except ValidationError as error:
            raise BuilderError(f"state: {error}") from error
        return deepcopy(self.state)


def upgrade_semantic_state(state: Mapping[str, Any]) -> SemanticStateBuilder:
    """Return a builder seeded from valid deterministic Scan state."""
    return SemanticStateBuilder.from_state(state)
