"""Bounded in-memory semantic continuation for Scan MCP.

This layer exposes the existing SemanticStateBuilder through MCP without writing
into the inspected project or weakening Scan's static/runtime distinction.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
from pathlib import Path
from typing import Any, Callable, Mapping

from .auxiliary import AuxiliaryReadError, read_auxiliary
from .builder import BuilderError, SemanticStateBuilder
from .render import render_html
from .state import canonical_state_json, state_digest
from .validate import CHECK_CATEGORIES, validate_state

_MAX_SEMANTIC_READ_BYTES = 1_000_000
_ALLOWED_EVIDENCE_KINDS = {"static", "inferred", "unverified"}
_ALLOWED_VERIFICATION = {"static", "inferred", "unverified"}
_ALLOWED_PRODUCERS = {"local-model", "remote-model"}
_ALLOWED_CHECK_STATUSES = {"assessed", "partial", "not_assessed", "blocked", "not_applicable"}
_ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "informational"}


class SemanticWorkspaceError(ValueError):
    """Raised when semantic continuation would cross a Scan trust boundary."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _required(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SemanticWorkspaceError(f"{label} must be a nonempty string")
    return value


def _list(value: list[str] | None, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise SemanticWorkspaceError(f"{label} must be an array of nonempty strings")
    if len(value) != len(set(value)):
        raise SemanticWorkspaceError(f"{label} must not contain duplicates")
    return value


def _blocked(error: Exception | str) -> dict[str, Any]:
    return {"status": "blocked", "reason": str(error)}


class SemanticWorkspace:
    """One in-memory semantic workspace bound to exactly one deep Scan snapshot."""

    def __init__(self, root: Path, base_state: Mapping[str, Any]):
        self.root = Path(root).resolve(strict=True)
        if not self.root.is_dir():
            raise SemanticWorkspaceError("semantic workspace root must be a directory")
        state = dict(base_state)
        validate_state(state, version="1.4")
        if state["run"].get("mode") != "static" or state["run"].get("target_executed") is not False:
            raise SemanticWorkspaceError("semantic continuation requires a static non-executing Scan state")
        if state["run"].get("network_used") is not False:
            raise SemanticWorkspaceError("semantic continuation requires a no-network Scan state")
        self.snapshot_digest = state["provenance"]["snapshot_digest"]
        self.scan_id = state["run"]["scan_id"]
        self.builder = SemanticStateBuilder.from_state(state)
        self.builder.state.setdefault("extensions", {})["semantic_workspace"] = {
            "kind": "mcp_in_memory",
            "base_scan_id": self.scan_id,
            "base_snapshot_digest": self.snapshot_digest,
            "target_writes": False,
            "target_execution": False,
            "network_action": "none",
            "allowed_evidence_kinds": sorted(_ALLOWED_EVIDENCE_KINDS),
            "runtime_verification_authorized": False,
        }

    def stale_against(self, current_state: Mapping[str, Any]) -> bool:
        return current_state["provenance"]["snapshot_digest"] != self.snapshot_digest

    def _artifact(self, artifact_id: str) -> dict[str, Any]:
        row = next((item for item in self.builder.state["artifacts"] if item["id"] == artifact_id), None)
        if row is None:
            raise SemanticWorkspaceError(f"unknown artifact ID: {artifact_id}")
        return row

    def _verify_artifact_bytes(self, artifact: Mapping[str, Any]) -> str:
        if artifact.get("path_kind") != "file":
            raise SemanticWorkspaceError("semantic evidence in this slice must attach to a regular file")
        if artifact.get("redaction_state") in {"path_redacted", "fully_omitted"}:
            raise SemanticWorkspaceError("semantic evidence cannot expose or re-open a sensitive-path artifact")
        expected = artifact.get("content_identity")
        if not isinstance(expected, str) or not expected.startswith("sha256:"):
            raise SemanticWorkspaceError("artifact lacks a complete SHA-256 content identity")
        size = artifact.get("size_bytes")
        if not isinstance(size, int) or size < 0:
            raise SemanticWorkspaceError("artifact has invalid size metadata")
        if size > _MAX_SEMANTIC_READ_BYTES:
            raise SemanticWorkspaceError(
                f"artifact exceeds semantic authoring ceiling of {_MAX_SEMANTIC_READ_BYTES} bytes"
            )
        locator = artifact.get("locator")
        if not isinstance(locator, str) or not locator:
            raise SemanticWorkspaceError("artifact locator is unavailable")
        try:
            data = read_auxiliary(self.root, locator, max_bytes=_MAX_SEMANTIC_READ_BYTES)
        except AuxiliaryReadError as error:
            raise SemanticWorkspaceError(str(error)) from error
        actual = "sha256:" + hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise SemanticWorkspaceError(
                "artifact bytes no longer match the semantic workspace snapshot; refresh Scan and reset semantic workspace"
            )
        if b"\x00" in data:
            raise SemanticWorkspaceError("binary content is not eligible for semantic text evidence")
        try:
            data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise SemanticWorkspaceError("artifact is not valid UTF-8 text for semantic authoring") from error
        return expected

    def status(self, current_state: Mapping[str, Any]) -> dict[str, Any]:
        state = self.builder.build()
        return {
            "status": "stale" if self.stale_against(current_state) else "ok",
            "base_scan_id": self.scan_id,
            "base_snapshot_digest": self.snapshot_digest,
            "current_snapshot_digest": current_state["provenance"]["snapshot_digest"],
            "state_digest": state_digest(state),
            "counts": {
                "components": len(state["components"]),
                "relationships": len(state["relationships"]),
                "evidence": len(state["evidence"]),
                "findings": len(state["findings"]),
                "unknowns": len(state["unknowns"]),
                "checks_assessed": state["coverage"]["counts_by_check_status"].get("assessed", 0),
                "artifacts_analyzed": state["coverage"]["counts_by_status"].get("analyzed", 0),
            },
            "analysis_complete": state["coverage"]["analysis_complete"],
            "checks_complete": state["coverage"]["checks_complete"],
            "target_writes": False,
            "target_executed": False,
            "network_action": "none",
        }

    def add_component(self, *, name: str, purpose: str, artifact_ids: list[str] | None = None,
                      evidence_ids: list[str] | None = None, boundaries: str = "Not established") -> str:
        return self.builder.add_component(
            name=_required(name, "name"), purpose=_required(purpose, "purpose"),
            artifact_ids=_list(artifact_ids, "artifact_ids"), evidence_ids=_list(evidence_ids, "evidence_ids"),
            boundaries=_required(boundaries, "boundaries"),
        )

    def add_evidence(self, *, artifact_id: str, kind: str, claim: str, result: str, method: str,
                     limitations: str, producer_kind: str, producer_name: str, producer_version: str,
                     check_id: str | None = None) -> str:
        if kind not in _ALLOWED_EVIDENCE_KINDS:
            raise SemanticWorkspaceError(
                "MCP semantic continuation permits static, inferred, or unverified evidence only; observed/runtime proof is not authorized"
            )
        if producer_kind not in _ALLOWED_PRODUCERS:
            raise SemanticWorkspaceError("producer_kind must be local-model or remote-model for MCP semantic authoring")
        artifact = self._artifact(_required(artifact_id, "artifact_id"))
        source_digest = self._verify_artifact_bytes(artifact)
        return self.builder.add_evidence(
            artifact_id=artifact_id, locator=artifact["locator"], kind=kind,
            claim=_required(claim, "claim"), result=_required(result, "result"), method=_required(method, "method"),
            limitations=_required(limitations, "limitations"), source_digest=source_digest,
            producer_kind=producer_kind, producer_name=_required(producer_name, "producer_name"),
            producer_version=_required(producer_version, "producer_version"), time=_utc_now(),
            inspection_origin="fresh", evidence_class="static_semantic", check_id=check_id,
        )

    def add_relationship(self, *, from_id: str, to_id: str, kind: str, explanation: str,
                         evidence_ids: list[str], confidence: str, verification_state: str) -> str:
        if verification_state not in _ALLOWED_VERIFICATION:
            raise SemanticWorkspaceError("observed/runtime relationship verification is not authorized in this slice")
        return self.builder.add_relationship(
            from_id=_required(from_id, "from_id"), to_id=_required(to_id, "to_id"),
            kind=_required(kind, "kind"), explanation=_required(explanation, "explanation"),
            evidence_ids=_list(evidence_ids, "evidence_ids"), confidence=_required(confidence, "confidence"),
            verification_state=verification_state,
        )

    def add_finding(self, *, title: str, impact: str, severity: str, confidence: str,
                    verification_state: str, uncertainty: str, recommendation: str, safe_verification: str,
                    artifact_ids: list[str], evidence_ids: list[str]) -> str:
        if severity not in _ALLOWED_SEVERITIES:
            raise SemanticWorkspaceError("severity must be critical, high, medium, low, or informational")
        if verification_state not in _ALLOWED_VERIFICATION:
            raise SemanticWorkspaceError("observed/runtime finding verification is not authorized in this slice")
        return self.builder.add_finding(
            title=_required(title, "title"), impact=_required(impact, "impact"), severity=severity,
            confidence=_required(confidence, "confidence"), verification_state=verification_state,
            uncertainty=_required(uncertainty, "uncertainty"), recommendation=_required(recommendation, "recommendation"),
            safe_verification=_required(safe_verification, "safe_verification"),
            artifact_ids=_list(artifact_ids, "artifact_ids"), evidence_ids=_list(evidence_ids, "evidence_ids"),
        )

    def add_unknown(self, *, question: str, reason: str, impact: str, next_safe_step: str,
                    artifact_ids: list[str] | None = None, evidence_ids: list[str] | None = None) -> str:
        return self.builder.add_unknown(
            question=_required(question, "question"), reason=_required(reason, "reason"),
            impact=_required(impact, "impact"), next_safe_step=_required(next_safe_step, "next_safe_step"),
            artifact_ids=_list(artifact_ids, "artifact_ids"), evidence_ids=_list(evidence_ids, "evidence_ids"),
        )

    def assess_check(self, *, category: str, status: str, scope: str, method: str,
                     artifact_ids: list[str] | None, evidence_ids: list[str] | None,
                     related_ids: list[str] | None, verification_state: str, result: str,
                     limitations: str, reason: str, next_step: str | None = None) -> str:
        if category not in CHECK_CATEGORIES:
            raise SemanticWorkspaceError(f"unsupported check category: {category}")
        if status not in _ALLOWED_CHECK_STATUSES:
            raise SemanticWorkspaceError(f"unsupported check status: {status}")
        if verification_state not in _ALLOWED_VERIFICATION:
            raise SemanticWorkspaceError("observed/runtime check verification is not authorized in this slice")
        if status in {"assessed", "partial"} and not evidence_ids:
            raise SemanticWorkspaceError("assessed/partial checks require substantive evidence")
        return self.builder.assess_check(
            category=category, status=status, scope=_required(scope, "scope"), method=_required(method, "method"),
            artifact_ids=_list(artifact_ids, "artifact_ids"), evidence_ids=_list(evidence_ids, "evidence_ids"),
            related_ids=_list(related_ids, "related_ids"), verification_state=verification_state,
            result=_required(result, "result"), limitations=_required(limitations, "limitations"),
            reason=_required(reason, "reason"), next_step=next_step,
        )

    def mark_artifact_analyzed(self, *, artifact_id: str, evidence_ids: list[str], reason: str) -> None:
        self.builder.mark_artifact_analyzed(
            _required(artifact_id, "artifact_id"), evidence_ids=_list(evidence_ids, "evidence_ids"),
            reason=_required(reason, "reason"),
        )

    def finalize(self, *, overview: str | None = None, condition: str | None = None,
                 readiness: str | None = None, strengths: list[str] | None = None,
                 priorities: list[str] | None = None, limitations: str | None = None,
                 remaining: list[str] | None = None, hypotheses: list[str] | None = None,
                 decisions: list[str] | None = None, revalidation: list[str] | None = None,
                 source_needs: list[str] | None = None, analysis_complete: bool | None = None) -> dict[str, Any]:
        self.builder.set_summary(
            overview=overview, condition=condition, readiness=readiness,
            strengths=_list(strengths, "strengths") if strengths is not None else None,
            priorities=_list(priorities, "priorities") if priorities is not None else None,
            limitations=limitations,
        )
        self.builder.set_continuation(
            remaining=_list(remaining, "remaining") if remaining is not None else None,
            hypotheses=_list(hypotheses, "hypotheses") if hypotheses is not None else None,
            decisions=_list(decisions, "decisions") if decisions is not None else None,
            revalidation=_list(revalidation, "revalidation") if revalidation is not None else None,
            source_needs=_list(source_needs, "source_needs") if source_needs is not None else None,
            authorization_note=(
                "MCP semantic continuation is static and in-memory; target execution, target writes and network egress remain unauthorized"
            ),
        )
        return self.builder.build(analysis_complete=analysis_complete)

    def state(self) -> dict[str, Any]:
        return self.builder.build()

    def report_html(self) -> str:
        return render_html(self.state())


def install_semantic_tools(server: Any, *, root: Path, current_state: Callable[[str], dict[str, Any]]) -> None:
    """Install bounded semantic continuation tools and resources onto an MCP server."""
    workspace: SemanticWorkspace | None = None

    def active() -> SemanticWorkspace:
        nonlocal workspace
        if workspace is None:
            workspace = SemanticWorkspace(root, current_state("deep"))
        return workspace

    def current_or_stale() -> tuple[SemanticWorkspace, dict[str, Any], bool]:
        ws = active()
        current = current_state("deep")
        return ws, current, ws.stale_against(current)

    def write_call(callback: Callable[[], Any]) -> dict[str, Any]:
        ws: SemanticWorkspace | None = None
        backup: dict[str, Any] | None = None
        try:
            ws, current, stale = current_or_stale()
            if stale:
                return {
                    "status": "stale",
                    "reason": "deep Scan snapshot changed; call scan_semantic_reset before adding more semantic records",
                    "base_snapshot_digest": ws.snapshot_digest,
                    "current_snapshot_digest": current["provenance"]["snapshot_digest"],
                }
            backup = deepcopy(ws.builder.state)
            value = callback()
            state = ws.state()
            result: dict[str, Any] = {"status": "ok", "state_digest": state_digest(state)}
            if isinstance(value, str):
                result["id"] = value
            return result
        except (BuilderError, SemanticWorkspaceError, AuxiliaryReadError, ValueError) as error:
            if ws is not None and backup is not None:
                ws.builder.state = backup
            return _blocked(error)

    @server.tool()
    def scan_semantic_status() -> dict[str, Any]:
        """Return semantic workspace freshness, evidence counts and completion state."""
        try:
            ws, current, _stale = current_or_stale()
            return ws.status(current)
        except (BuilderError, SemanticWorkspaceError, ValueError) as error:
            return _blocked(error)

    @server.tool()
    def scan_semantic_reset() -> dict[str, Any]:
        """Discard in-memory semantic work and seed a new workspace from the current deep Scan snapshot."""
        nonlocal workspace
        try:
            workspace = SemanticWorkspace(root, current_state("deep"))
            return workspace.status(current_state("deep"))
        except (BuilderError, SemanticWorkspaceError, ValueError) as error:
            return _blocked(error)

    @server.tool()
    def scan_semantic_add_component(name: str, purpose: str, artifact_ids: list[str] | None = None,
                                    evidence_ids: list[str] | None = None,
                                    boundaries: str = "Not established") -> dict[str, Any]:
        """Add one semantic architecture component using existing artifact/evidence IDs."""
        return write_call(lambda: active().add_component(
            name=name, purpose=purpose, artifact_ids=artifact_ids, evidence_ids=evidence_ids, boundaries=boundaries,
        ))

    @server.tool()
    def scan_semantic_add_evidence(artifact_id: str, kind: str, claim: str, result: str, method: str,
                                   limitations: str, producer_kind: str, producer_name: str,
                                   producer_version: str, check_id: str | None = None) -> dict[str, Any]:
        """Add fresh semantic evidence after rechecking the artifact bytes against the Scan snapshot."""
        return write_call(lambda: active().add_evidence(
            artifact_id=artifact_id, kind=kind, claim=claim, result=result, method=method,
            limitations=limitations, producer_kind=producer_kind, producer_name=producer_name,
            producer_version=producer_version, check_id=check_id,
        ))

    @server.tool()
    def scan_semantic_add_relationship(from_id: str, to_id: str, kind: str, explanation: str,
                                       evidence_ids: list[str], confidence: str,
                                       verification_state: str) -> dict[str, Any]:
        """Add an evidence-linked static/inferred relationship between artifacts/components."""
        return write_call(lambda: active().add_relationship(
            from_id=from_id, to_id=to_id, kind=kind, explanation=explanation,
            evidence_ids=evidence_ids, confidence=confidence, verification_state=verification_state,
        ))

    @server.tool()
    def scan_semantic_add_finding(title: str, impact: str, severity: str, confidence: str,
                                  verification_state: str, uncertainty: str, recommendation: str,
                                  safe_verification: str, artifact_ids: list[str],
                                  evidence_ids: list[str]) -> dict[str, Any]:
        """Add an evidence-linked finding; runtime/observed verification is rejected."""
        return write_call(lambda: active().add_finding(
            title=title, impact=impact, severity=severity, confidence=confidence,
            verification_state=verification_state, uncertainty=uncertainty,
            recommendation=recommendation, safe_verification=safe_verification,
            artifact_ids=artifact_ids, evidence_ids=evidence_ids,
        ))

    @server.tool()
    def scan_semantic_add_unknown(question: str, reason: str, impact: str, next_safe_step: str,
                                  artifact_ids: list[str] | None = None,
                                  evidence_ids: list[str] | None = None) -> dict[str, Any]:
        """Add an explicit unanswered question instead of converting missing evidence into a pass."""
        return write_call(lambda: active().add_unknown(
            question=question, reason=reason, impact=impact, next_safe_step=next_safe_step,
            artifact_ids=artifact_ids, evidence_ids=evidence_ids,
        ))

    @server.tool()
    def scan_semantic_assess_check(category: str, status: str, scope: str, method: str,
                                   verification_state: str, result: str, limitations: str, reason: str,
                                   artifact_ids: list[str] | None = None,
                                   evidence_ids: list[str] | None = None,
                                   related_ids: list[str] | None = None,
                                   next_step: str | None = None) -> dict[str, Any]:
        """Update one required Scan check category using evidence already in the semantic workspace."""
        return write_call(lambda: active().assess_check(
            category=category, status=status, scope=scope, method=method,
            artifact_ids=artifact_ids, evidence_ids=evidence_ids, related_ids=related_ids,
            verification_state=verification_state, result=result, limitations=limitations,
            reason=reason, next_step=next_step,
        ))

    @server.tool()
    def scan_semantic_mark_artifact_analyzed(artifact_id: str, evidence_ids: list[str],
                                             reason: str = "Semantic analysis completed") -> dict[str, Any]:
        """Mark one artifact analyzed only when direct substantive evidence supports that artifact."""
        return write_call(lambda: active().mark_artifact_analyzed(
            artifact_id=artifact_id, evidence_ids=evidence_ids, reason=reason,
        ))

    @server.tool()
    def scan_semantic_finalize(overview: str | None = None, condition: str | None = None,
                               readiness: str | None = None, strengths: list[str] | None = None,
                               priorities: list[str] | None = None, limitations: str | None = None,
                               remaining: list[str] | None = None, hypotheses: list[str] | None = None,
                               decisions: list[str] | None = None, revalidation: list[str] | None = None,
                               source_needs: list[str] | None = None,
                               analysis_complete: bool | None = None) -> dict[str, Any]:
        """Update summary/continuation fields and validate the resulting semantic state."""
        ws: SemanticWorkspace | None = None
        backup: dict[str, Any] | None = None
        try:
            ws, _current, stale = current_or_stale()
            if stale:
                return {"status": "stale", "reason": "deep Scan snapshot changed; reset semantic workspace before finalizing"}
            backup = deepcopy(ws.builder.state)
            state = ws.finalize(
                overview=overview, condition=condition, readiness=readiness, strengths=strengths,
                priorities=priorities, limitations=limitations, remaining=remaining, hypotheses=hypotheses,
                decisions=decisions, revalidation=revalidation, source_needs=source_needs,
                analysis_complete=analysis_complete,
            )
            return {
                "status": "ok", "state_digest": state_digest(state),
                "analysis_complete": state["coverage"]["analysis_complete"],
                "checks_complete": state["coverage"]["checks_complete"],
                "finding_count": len(state["findings"]), "unknown_count": len(state["unknowns"]),
            }
        except (BuilderError, SemanticWorkspaceError, ValueError) as error:
            if ws is not None and backup is not None:
                ws.builder.state = backup
            return _blocked(error)

    @server.tool()
    def scan_semantic_state() -> dict[str, Any]:
        """Return the validated in-memory Scan 1.4 semantic state; this can be large."""
        try:
            ws, _current, stale = current_or_stale()
            if stale:
                return {"status": "stale", "reason": "deep Scan snapshot changed; reset semantic workspace before exporting"}
            state = ws.state()
            return {"status": "ok", "state_digest": state_digest(state), "state": state}
        except (BuilderError, SemanticWorkspaceError, ValueError) as error:
            return _blocked(error)

    @server.resource("scan://semantic/state")
    def semantic_state_resource() -> str:
        """Return canonical JSON for the validated in-memory semantic state."""
        ws, _current, stale = current_or_stale()
        if stale:
            raise SemanticWorkspaceError("semantic workspace is stale; reset before export")
        return canonical_state_json(ws.state())

    @server.resource("scan://semantic/report")
    def semantic_report_resource() -> str:
        """Return a self-contained HTML report rendered from the validated semantic state."""
        ws, _current, stale = current_or_stale()
        if stale:
            raise SemanticWorkspaceError("semantic workspace is stale; reset before report rendering")
        return ws.report_html()
