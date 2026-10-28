"""Bounded SARIF 2.1.0 import into validated Scan semantic state."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Mapping
from urllib.parse import unquote, urlsplit

from .builder import SemanticStateBuilder
from .privacy import RedactionPolicy, redact_value
from .validate import validate_state

SARIF_IMPORT_MAX_BYTES = 64_000_000
SARIF_IMPORT_MAX_RESULTS = 10_000
SARIF_IMPORT_MAX_TEXT = 20_000
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_LEVEL_TO_SEVERITY = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "informational",
}


@dataclass(frozen=True)
class SarifImportResult:
    state: dict[str, Any]
    imported_findings: int
    imported_evidence: int
    unmapped_results: int
    ignored_results: int
    source_digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "imported_findings": self.imported_findings,
            "imported_evidence": self.imported_evidence,
            "unmapped_results": self.unmapped_results,
            "ignored_results": self.ignored_results,
            "source_digest": self.source_digest,
        }


def _canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _bounded_text(value: object, *, fallback: str = "", max_chars: int = SARIF_IMPORT_MAX_TEXT) -> str:
    text = str(value if value is not None else fallback).strip()
    if len(text) > max_chars:
        text = text[:max_chars].rstrip() + " [truncated by Scan SARIF importer]"
    return text


def _redact(text: str, level: str) -> str:
    return redact_value(text, RedactionPolicy(level=level)).value


def _normalize_relative_uri(uri: object) -> str:
    raw = _bounded_text(uri)
    if not raw:
        raise ValueError("SARIF artifactLocation.uri is empty")
    parts = urlsplit(raw)
    if parts.scheme or parts.netloc or parts.query or parts.fragment:
        raise ValueError("SARIF import accepts repository-relative artifact URIs only")
    decoded = unquote(parts.path).replace("\\", "/")
    if not decoded or decoded.startswith(("/", "//")) or _WINDOWS_DRIVE.match(decoded):
        raise ValueError("SARIF import accepts repository-relative artifact URIs only")
    path = PurePosixPath(decoded)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("SARIF artifact URI contains unsafe path segments")
    return path.as_posix()


def _rules(driver: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    rows = driver.get("rules", [])
    if rows is None:
        return []
    if not isinstance(rows, list) or not all(isinstance(row, Mapping) for row in rows):
        raise ValueError("SARIF tool.driver.rules must be an array of objects")
    return list(rows)


def _rule_for_result(result: Mapping[str, Any], rules: list[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    index = result.get("ruleIndex")
    if isinstance(index, int) and not isinstance(index, bool) and 0 <= index < len(rules):
        return rules[index]
    rule_id = result.get("ruleId")
    if isinstance(rule_id, str):
        for rule in rules:
            if rule.get("id") == rule_id:
                return rule
    return None


def _multi_text(value: object) -> str:
    if not isinstance(value, Mapping):
        return ""
    text = value.get("text")
    if isinstance(text, str) and text.strip():
        return _bounded_text(text)
    markdown = value.get("markdown")
    if isinstance(markdown, str) and markdown.strip():
        return _bounded_text(markdown)
    return ""


def _message_text(result: Mapping[str, Any], rule: Mapping[str, Any] | None) -> str:
    message = result.get("message")
    direct = _multi_text(message)
    if direct:
        return direct
    if isinstance(message, Mapping) and isinstance(message.get("id"), str) and isinstance(rule, Mapping):
        strings = rule.get("messageStrings", {})
        if isinstance(strings, Mapping):
            resolved = _multi_text(strings.get(message["id"]))
            if resolved:
                return resolved
    if isinstance(rule, Mapping):
        fallback = _multi_text(rule.get("shortDescription")) or _multi_text(rule.get("fullDescription"))
        if fallback:
            return fallback
    return "External scanner reported a result without message text"


def _rule_id(result: Mapping[str, Any], rule: Mapping[str, Any] | None) -> str:
    if isinstance(result.get("ruleId"), str) and result["ruleId"].strip():
        return _bounded_text(result["ruleId"], max_chars=512)
    if isinstance(rule, Mapping) and isinstance(rule.get("id"), str) and rule["id"].strip():
        return _bounded_text(rule["id"], max_chars=512)
    return "unidentified-rule"


def _rule_text(rule: Mapping[str, Any] | None, key: str) -> str:
    return _multi_text(rule.get(key)) if isinstance(rule, Mapping) else ""


def _tool_version(driver: Mapping[str, Any]) -> str:
    for key in ("semanticVersion", "version", "dottedQuadFileVersion"):
        value = driver.get(key)
        if isinstance(value, str) and value.strip():
            return _bounded_text(value, max_chars=256)
    return "unknown"


def _location_info(location: Mapping[str, Any]) -> tuple[str, str] | None:
    physical = location.get("physicalLocation")
    if not isinstance(physical, Mapping):
        return None
    artifact_location = physical.get("artifactLocation")
    if not isinstance(artifact_location, Mapping):
        return None
    if artifact_location.get("uriBaseId") not in (None, ""):
        return None
    try:
        locator = _normalize_relative_uri(artifact_location.get("uri"))
    except ValueError:
        return None
    region = physical.get("region")
    detail = locator
    if isinstance(region, Mapping):
        line = region.get("startLine")
        column = region.get("startColumn")
        if isinstance(line, int) and line > 0:
            detail += f":{line}"
            if isinstance(column, int) and column > 0:
                detail += f":{column}"
    return locator, detail


def _identity(tool: str, rule_id: str, result: Mapping[str, Any], locations: list[str], message: str) -> str:
    partial = result.get("partialFingerprints")
    fingerprints = result.get("fingerprints")
    stable = None
    for candidate in (partial, fingerprints):
        if isinstance(candidate, Mapping) and candidate:
            stable = {str(k): str(v) for k, v in sorted(candidate.items(), key=lambda item: str(item[0]))}
            break
    payload = {
        "tool": tool,
        "rule": rule_id,
        "fingerprint": stable,
        "locations": sorted(locations),
        "message": None if stable is not None else message,
    }
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()[:24]


def _severity(result: Mapping[str, Any], rule: Mapping[str, Any] | None) -> str:
    level = result.get("level")
    if not isinstance(level, str) and isinstance(rule, Mapping):
        default = rule.get("defaultConfiguration")
        if isinstance(default, Mapping):
            level = default.get("level")
    return _LEVEL_TO_SEVERITY.get(str(level or "warning").lower(), "medium")


def import_sarif(
    base_state: Mapping[str, Any],
    sarif: Mapping[str, Any],
    *,
    source_bytes: bytes | None = None,
) -> SarifImportResult:
    """Import bounded SARIF 2.1.0 fail results into a new canonical Scan state.

    Only results that map to canonical project file artifacts become findings.
    Review/open or unmappable fail results become Scan unknowns. Pass,
    notApplicable and informational SARIF results are counted but not promoted.
    """
    validate_state(base_state)
    if base_state.get("schema_version") not in {"1.3", "1.4"}:
        raise ValueError("SARIF import requires Scan state schema 1.3 or 1.4")
    if sarif.get("version") != "2.1.0":
        raise ValueError("SARIF importer supports version 2.1.0 only")
    runs = sarif.get("runs")
    if not isinstance(runs, list) or not all(isinstance(run, Mapping) for run in runs):
        raise ValueError("SARIF runs must be an array of objects")
    total_results = sum(len(run.get("results", [])) for run in runs if isinstance(run.get("results", []), list))
    if total_results > SARIF_IMPORT_MAX_RESULTS:
        raise ValueError(f"SARIF result count exceeds importer limit ({SARIF_IMPORT_MAX_RESULTS})")

    raw = source_bytes if source_bytes is not None else _canonical_bytes(sarif)
    source_digest = _digest(raw)
    builder = SemanticStateBuilder.from_state(base_state)
    privacy = str(base_state.get("privacy", {}).get("redaction_level", "standard"))
    artifacts_by_locator = {
        str(row.get("locator")): row
        for row in base_state.get("artifacts", [])
        if row.get("path_kind") == "file" and row.get("type") == "file"
    }
    evidence_by_artifact: dict[str, list[str]] = {}
    imported_findings = 0
    imported_evidence = 0
    unmapped_results = 0
    ignored_results = 0
    seen_identities: set[str] = set()

    for run_index, run in enumerate(runs):
        tool = run.get("tool")
        driver = tool.get("driver") if isinstance(tool, Mapping) else None
        if not isinstance(driver, Mapping) or not isinstance(driver.get("name"), str) or not driver["name"].strip():
            raise ValueError(f"SARIF run {run_index} requires tool.driver.name")
        tool_name = _bounded_text(driver["name"], max_chars=256)
        tool_version = _tool_version(driver)
        rules = _rules(driver)
        results = run.get("results", [])
        if not isinstance(results, list) or not all(isinstance(row, Mapping) for row in results):
            raise ValueError(f"SARIF run {run_index} results must be an array of objects")

        for result_index, result in enumerate(results):
            rule = _rule_for_result(result, rules)
            rule_id = _rule_id(result, rule)
            message = _redact(_message_text(result, rule), privacy)
            kind = str(result.get("kind", "fail"))
            raw_locations = result.get("locations", [])
            if not isinstance(raw_locations, list):
                raise ValueError(f"SARIF run {run_index} result {result_index} locations must be an array")
            location_rows = [row for row in raw_locations if isinstance(row, Mapping)]
            parsed_locations = [info for row in location_rows if (info := _location_info(row)) is not None]
            mapped: list[tuple[Mapping[str, Any], str]] = []
            for locator, detail in parsed_locations:
                artifact = artifacts_by_locator.get(locator)
                if artifact is not None and all(artifact["id"] != existing[0]["id"] for existing in mapped):
                    mapped.append((artifact, detail))
            identity_locations = [locator for locator, _ in parsed_locations]
            ident = _identity(tool_name, rule_id, result, identity_locations, message)
            if ident in seen_identities:
                ignored_results += 1
                continue
            seen_identities.add(ident)

            if kind in {"pass", "notApplicable", "informational"}:
                ignored_results += 1
                continue
            if kind in {"review", "open"} or not mapped:
                unmapped_results += 1
                reason = (
                    f"{tool_name} reported {rule_id}: {message}. "
                    + ("The SARIF result requires review and is not a confirmed fail result."
                       if kind in {"review", "open"}
                       else "No safe repository-relative SARIF location mapped to a canonical Scan artifact.")
                )
                builder.add_unknown(
                    record_id=f"unknown:sarif:{ident}",
                    question=f"How should external SARIF result {rule_id} from {tool_name} be resolved?",
                    reason=_redact(reason, privacy),
                    impact="The external scanner result is retained, but Scan cannot safely promote it to a canonical finding without a mapped project artifact and fail semantics.",
                    next_safe_step="Review the originating SARIF result and scanner configuration, map it to a canonical project artifact if appropriate, then re-import or record evidence explicitly.",
                )
                continue

            evidence_ids: list[str] = []
            artifact_ids: list[str] = []
            for artifact, detail in mapped:
                artifact_id = str(artifact["id"])
                evidence_id = f"evidence:sarif:{ident}:{hashlib.sha256(artifact_id.encode('utf-8')).hexdigest()[:12]}"
                result_text = _redact(f"{message} Reported location: {detail}.", privacy)
                evidence_id = builder.add_evidence(
                    record_id=evidence_id,
                    artifact_id=artifact_id,
                    locator=str(artifact["locator"]),
                    kind="static",
                    claim=f"External scanner {tool_name} reported rule {rule_id} for this artifact",
                    result=result_text,
                    method="Imported from SARIF 2.1.0; originating scanner was not executed by Scan",
                    source_digest=source_digest,
                    producer_kind="external-tool",
                    producer_name=tool_name,
                    producer_version=tool_version,
                    limitations="Imported scanner evidence. Scan did not independently reproduce the result, validate scanner configuration, or upgrade it to runtime/observed proof.",
                    evidence_class="static_semantic",
                )
                evidence_ids.append(evidence_id)
                artifact_ids.append(artifact_id)
                evidence_by_artifact.setdefault(artifact_id, []).append(evidence_id)
                imported_evidence += 1

            title = _redact(_rule_text(rule, "shortDescription") or f"{tool_name} {rule_id}", privacy)
            impact = _redact(_rule_text(rule, "fullDescription") or message, privacy)
            help_text = _redact(_rule_text(rule, "help"), privacy)
            recommendation = help_text or f"Review and remediate {rule_id} according to {tool_name} rule guidance, then rerun the same scanner configuration."
            builder.add_finding(
                record_id=f"finding:sarif:{ident}",
                title=title,
                impact=impact,
                severity=_severity(result, rule),
                confidence="external-tool-reported",
                verification_state="static",
                artifact_ids=artifact_ids,
                evidence_ids=evidence_ids,
                uncertainty="Imported from external SARIF. Scan did not execute the scanner or independently verify the reported condition.",
                recommendation=recommendation,
                safe_verification=f"Rerun {tool_name} with the same configuration and review the changed code. Absence from a later scan alone is not proof that the underlying issue was fixed.",
            )
            imported_findings += 1

    for artifact_id, evidence_ids in evidence_by_artifact.items():
        builder.mark_artifact_partial(
            artifact_id,
            evidence_ids=evidence_ids,
            reason="External SARIF rule-scoped static-analysis evidence imported; not independently reproduced by Scan",
        )
    state = builder.build(analysis_complete=False)
    return SarifImportResult(
        state=state,
        imported_findings=imported_findings,
        imported_evidence=imported_evidence,
        unmapped_results=unmapped_results,
        ignored_results=ignored_results,
        source_digest=source_digest,
    )


def load_sarif_file(path: Path, *, max_bytes: int = SARIF_IMPORT_MAX_BYTES) -> tuple[dict[str, Any], bytes]:
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError(f"SARIF file exceeds importer byte limit ({max_bytes})")
    raw = path.read_bytes()
    try:
        payload = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"Invalid UTF-8 SARIF JSON: {error}") from error
    if not isinstance(payload, dict):
        raise ValueError("SARIF root must be an object")
    return payload, raw
