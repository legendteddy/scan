"""Self-contained HTML rendering from validated canonical Scan state."""

from __future__ import annotations

from html import escape
from importlib.resources import files
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from .errors import ValidationError
from .state import canonical_state_json
from .validate import validate_report, validate_state

_TEMPLATE_PACKAGE = "scan_core.report"
_TEMPLATE_NAME = "shell.html"
_SLOT_RE = re.compile(r"\{\{[A-Z_]+\}\}")


def _h(value: Any) -> str:
    return escape(str(value), quote=True)


def _embedded_state_json(state: Mapping[str, Any]) -> str:
    """Serialize authoritative state for inert HTML embedding."""
    return (
        canonical_state_json(dict(state))
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )


def _template() -> str:
    return files(_TEMPLATE_PACKAGE).joinpath(_TEMPLATE_NAME).read_text(encoding="utf-8")


def _evidence_links(state: Mapping[str, Any], ids: Sequence[str]) -> str:
    lookup = {row["id"]: row for row in state["evidence"]}
    links = []
    for ident in ids:
        row = lookup.get(ident)
        if row is None:
            continue
        links.append(f'<a href="#e-{_h(ident)}">{_h(row["locator"])}</a>')
    return ", ".join(links) if links else "No direct evidence attached"


def _scroll_table(label: str, headings: Sequence[str], rows: Sequence[Sequence[str]], css_class: str = "") -> str:
    head = "".join(f'<th scope="col">{_h(value)}</th>' for value in headings)
    if rows:
        body = "\n".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    else:
        body = f'<tr><td colspan="{len(headings)}">No rows recorded in canonical state.</td></tr>'
    return (
        f'<div class="table-scroll" tabindex="0" role="region" aria-label="{_h(label)}">'
        f'<table class="{_h(css_class)}"><thead><tr>{head}</tr></thead>'
        f"<tbody>{body}</tbody></table></div>"
    )


def _count(value: int, key: str) -> str:
    return f'<b data-scan-count="{_h(key)}">{value}</b>'


def _metric(label: str, value_html: str, note: str) -> str:
    return f'<article class="metric"><span>{_h(label)}</span>{value_html}<small>{_h(note)}</small></article>'


def _empty_card(title: str, text: str) -> str:
    return (
        '<article class="finding unverified"><div class="finding-top">'
        '<span class="severity">None recorded</span></div>'
        f'<h3>{_h(title)}</h3><p>{_h(text)}</p></article>'
    )


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def _sorted_findings(state: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return sorted(
        state["findings"],
        key=lambda row: (_SEVERITY_ORDER.get(row.get("severity", "informational"), 99), row.get("id", "")),
    )


def _finding_cards(state: Mapping[str, Any]) -> str:
    rows = _sorted_findings(state)
    if not rows:
        return _empty_card(
            "No findings in deterministic core state",
            "Inventory, hashing and privacy checks do not create semantic findings by themselves.",
        )
    cards = "".join(
        f'<article class="finding severity-{_h(row["severity"])}" data-priority-finding="true"><div class="finding-top">'
        f'<span class="severity">{_h(row["severity"])} · {_h(row["verification_state"])}</span>'
        f'<span class="confidence">{_h(row["confidence"])} confidence</span></div>'
        f'<h3>{_h(row["title"])}</h3><p>{_h(row["impact"])} '
        f'<strong>Limit:</strong> {_h(row["uncertainty"])}</p>'
        f'<span class="evidence-ref">Evidence: {_evidence_links(state, row["evidence_ids"])}</span></article>'
        for row in rows[:5]
    )
    if len(rows) > 5:
        cards += _empty_card(
            f"{len(rows) - 5} additional finding(s)",
            "The complete finding set remains searchable in the supporting-detail appendix and embedded state.",
        )
    return cards


def _what_changed_cards(state: Mapping[str, Any]) -> str:
    findings = _sorted_findings(state)[:3]
    if not findings:
        return (
            '<article class="insight"><span>Point-in-time review</span>'
            '<h3>No semantic change claim</h3><p>No prior comparison baseline is embedded, and the current state records no semantic findings that changed the review.</p></article>'
        )
    return "".join(
        '<article class="insight"><span>Review-changing evidence</span>'
        f'<h3>{_h(row["title"])}</h3><p>{_h(row["impact"])}</p></article>'
        for row in findings
    )


def _decision_summary(state: Mapping[str, Any]) -> str:
    findings = _sorted_findings(state)[:3]
    if findings:
        return "".join(
            '<article class="hero-decision">'
            f'<span>{_h(row["severity"])} finding</span><strong>{_h(row["title"])}</strong>'
            f'<small>{_h(row["impact"])}</small></article>'
            for row in findings
        )
    priorities = list(state["summary"].get("priorities", []))[:3]
    if not priorities:
        priorities = [state["summary"]["condition"]]
    return "".join(
        '<article class="hero-decision"><span>Decision</span>'
        f'<strong>{_h(value)}</strong></article>' for value in priorities
    )


def _control_cards(state: Mapping[str, Any]) -> str:
    rows = state["controls"]
    if not rows:
        return _empty_card(
            "No controls assessed",
            "The deterministic core does not infer control effectiveness from file presence or hashes.",
        )
    return "".join(
        '<article class="control">'
        f'<span class="control-state">{_h(row["effectiveness_status"])}</span>'
        f'<h3>{_h(row["description"])}</h3><p>{_h(row["limitations"])}</p>'
        f'<span class="evidence-ref">Evidence: {_evidence_links(state, row["evidence_ids"])}</span></article>'
        for row in rows
    )


def _component_cards(state: Mapping[str, Any]) -> str:
    rows = state["components"]
    if not rows:
        return _empty_card(
            "Components not mapped yet",
            "Canonical inventory exists, but architecture/component interpretation requires a separate evidence-backed analyzer.",
        )
    return "".join(
        '<article class="module"><div class="module-head"><span class="module-dot"></span>'
        f'<h3>{_h(row["name"])}</h3></div><p class="purpose">{_h(row["purpose"])}</p>'
        f'<dl><div><dt>Boundary</dt><dd>{_h(row["boundaries"])}</dd></div>'
        f'<div><dt>Evidence</dt><dd>{_evidence_links(state, row["evidence_ids"])}</dd></div></dl></article>'
        for row in rows
    )


def _unknown_cards(state: Mapping[str, Any]) -> str:
    rows = state["unknowns"]
    if not rows:
        return _empty_card("No unknowns recorded", "Canonical state currently records no explicit open question.")
    return "".join(
        '<article class="finding unverified"><div class="finding-top">'
        '<span class="severity">Not verified</span></div>'
        f'<h3>{_h(row["question"])}</h3><p>{_h(row["reason"])} '
        f'<strong>Next:</strong> {_h(row["next_safe_step"])}</p>'
        f'<span class="evidence-ref">Evidence: {_evidence_links(state, row["evidence_ids"])}</span></article>'
        for row in rows
    )


def _action_cards(state: Mapping[str, Any]) -> str:
    rows = state["actions"]
    if not rows:
        return _empty_card(
            "No remediation actions recorded",
            "The deterministic core records boundaries and continuation needs without proposing source changes.",
        )
    return "".join(
        '<article class="action">'
        f'<span class="action-no">{index:02}</span><h3>{_h(row["description"])}</h3>'
        f'<p>Priority: {_h(row["priority"])}. Verify: {_h(row["expected_verification"])}. '
        f'Approval: {_h(row["authorization_requirements"])}.</p></article>'
        for index, row in enumerate(rows, 1)
    )


def _system_map(state: Mapping[str, Any]) -> str:
    components = state["components"]
    relationships = state["relationships"]
    if not components:
        return (
            '<div class="status-banner"><div class="status-icon" aria-hidden="true">?</div>'
            '<div><h3>Architecture not inferred by deterministic core</h3>'
            '<p>The report keeps this section explicit rather than turning file inventory into an unsupported system map.</p></div></div>'
        )
    nodes = "".join(
        f'<div class="map-node"><b>{_h(row["name"])}</b><span>{_h(row["purpose"])}</span></div>'
        for row in components[:3]
    )
    relation_note = f"{len(relationships)} evidence-linked relationship(s) recorded."
    return f'<div class="map-row">{nodes}</div><p class="evidence-ref">{_h(relation_note)}</p>'


def _baseline_section(state: Mapping[str, Any]) -> str:
    if state.get("schema_version") != "1.4":
        return ""
    baseline = state["baseline"]
    delta = state["delta"]
    artifacts = delta["artifacts"]
    findings = delta["findings"]
    unknowns = delta["unknowns"]
    title = "Since baseline" if delta["available"] else "Baseline comparison unavailable"
    note = (
        f"Baseline status: {baseline['status']}. Snapshot relation: {baseline['snapshot_relation']}."
        if delta["available"]
        else f"Baseline status: {baseline['status']}. No prior state is being presented as a comparison."
    )
    metrics = "".join([
        _metric("Artifacts added", _count(len(artifacts["added"]), "delta_artifacts_added"), "Current IDs absent from baseline"),
        _metric("Artifacts changed", _count(len(artifacts["changed"]), "delta_artifacts_changed"), "Same path identity, changed fingerprint"),
        _metric("Artifacts removed", _count(len(artifacts["removed"]), "delta_artifacts_removed"), "Baseline IDs absent from current state"),
        _metric("New findings", _count(len(findings["new"]), "delta_findings_new"), "Current finding IDs absent from baseline"),
        _metric("Resolved findings", _count(len(findings["resolved"]), "delta_findings_resolved"), "Absent now; not proof of remediation"),
        _metric("New unknowns", _count(len(unknowns["new"]), "delta_unknowns_new"), "Newly recorded unanswered questions"),
        _metric("Resolved unknowns", _count(len(unknowns["resolved"]), "delta_unknowns_resolved"), "Absent now; not proof of verification"),
        _metric("Fresh evidence", _count(baseline["fresh_evidence_count"], "fresh_evidence_count"), "Observed in this scan"),
        _metric("Reused evidence", _count(baseline["reused_evidence_count"], "reused_evidence_count"), "Safely reused at original depth"),
        _metric("Rejected reuse", _count(baseline["rejected_reuse_count"], "rejected_reuse_count"), "Prior candidates that failed a reuse gate"),
    ])
    return (
        '<section class="section" aria-labelledby="baseline-title">'
        '<div class="section-head"><div class="section-kicker">Repeat scan</div>'
        f'<h2 id="baseline-title">{_h(title)}</h2><p class="section-intro">{_h(note)}</p></div>'
        f'<div class="metric-grid">{metrics}</div></section>'
    )


def _coverage_rows(state: Mapping[str, Any]) -> str:
    coverage = state["coverage"]
    artifact_count = coverage["discovered_artifact_count"]
    statuses = coverage["counts_by_status"]
    analyzed = statuses.get("analyzed", 0)
    content_read = statuses.get("content_read", 0)
    checks = state["checks"]
    check_counts = coverage["counts_by_check_status"]
    assessed = check_counts.get("assessed", 0)
    rows = [
        ("Artifact discovery", f"{artifact_count} inventoried", 100 if coverage["discovery_complete"] else 70),
        ("Content/static depth", f"{content_read} content-read · {analyzed} analyzed", 100 if coverage["analysis_complete"] else 35),
        ("Checks assessed", f"{assessed} of {len(checks)}", round(100 * assessed / len(checks)) if checks else 0),
        ("Runtime verification", "Not established", 0),
    ]
    return "".join(
        '<div class="coverage-row">'
        f'<span>{_h(label)}</span><div class="bar" aria-hidden="true"><i style="width:{width}%"></i></div>'
        f'<b>{_h(value)}</b></div>'
        for label, value, width in rows
    )


def _check_matrix(state: Mapping[str, Any]) -> str:
    rows = []
    for check in state["checks"]:
        rows.append([
            f'<strong>{_h(check["title"])}</strong>',
            _h(check["scope"]) + "<br>" + _h(check["method"]),
            _h(check["status"]),
            _h(check["result"]) + "<br><small>" + _h(check["limitations"]) + "</small>",
            _evidence_links(state, check["evidence_ids"]),
        ])
    return _scroll_table(
        "Check coverage; scroll horizontally if needed",
        ["Check", "Scope and method", "Status", "Result and limits", "Evidence"],
        rows,
        "table-checks",
    )


def _appendix(state: Mapping[str, Any]) -> str:
    finding_rows = [
        [
            f'<code>{_h(row["id"])}</code>',
            _h(row["title"]),
            _h(row["severity"]),
            _h(row["verification_state"]),
            _h(row["recommendation"]),
            _evidence_links(state, row["evidence_ids"]),
        ]
        for row in _sorted_findings(state)
    ]
    inventory_rows = [
        [
            f'<code>{_h(row["id"])}</code>',
            _h(row["locator"]),
            _h(row["path_kind"]),
            _h(row["status"]) + " · " + _h(row["inspection_origin"]),
            f'<code>{_h(row["content_identity"])}</code>',
            _h(row["redaction_state"]),
            _evidence_links(state, row["evidence_ids"]),
        ]
        for row in state["artifacts"]
    ]
    evidence_rows = [
        [
            f'<code id="e-{_h(row["id"])}">{_h(row["id"])}</code>',
            _h(row["kind"]),
            _h(row.get("freshness", {}).get("status", row["inspection_origin"])),
            _h(row["locator"]),
            _h(row["result"]),
            _h(row["limitations"]),
        ]
        for row in state["evidence"]
    ]
    findings_html = ""
    if finding_rows:
        findings_html = "<h3>All findings</h3>" + _scroll_table(
            "All findings; scroll horizontally if needed",
            ["ID", "Finding", "Severity", "Verification", "Recommendation", "Evidence"],
            finding_rows,
            "table-findings",
        )
    return (
        findings_html
        + "<h3>Artifact inventory</h3>"
        + _scroll_table(
            "Artifact inventory; scroll horizontally if needed",
            ["ID", "Locator", "Kind", "Inspection status", "Identity", "Privacy", "Evidence"],
            inventory_rows,
            "table-inventory",
        )
        + "<h3>Evidence</h3>"
        + _scroll_table(
            "Evidence; scroll horizontally if needed",
            ["ID", "Kind", "Freshness", "Locator", "Observation", "Limitations"],
            evidence_rows,
            "table-evidence",
        )
    )


def render_html(state: Mapping[str, Any]) -> str:
    """Return self-contained HTML for validated Scan 1.3/1.4 state."""
    version = state.get("schema_version")
    if version not in {"1.3", "1.4"}:
        raise ValidationError("Renderer accepts canonical schema_version 1.3 or 1.4 only")
    validated = validate_state(dict(state), version=version)
    coverage = validated["coverage"]
    check_counts = coverage["counts_by_check_status"]
    statuses = coverage["counts_by_status"]
    assessed = check_counts.get("assessed", 0)
    partial = check_counts.get("partial", 0)
    pending = check_counts.get("not_assessed", 0) + check_counts.get("blocked", 0)
    snapshot = validated["provenance"]["snapshot_digest"]

    metric_html = "".join([
        _metric("Discovered", _count(coverage["discovered_artifact_count"], "discovered_artifact_count"), "Canonical inventory rows"),
        _metric("Content read", _count(statuses.get("content_read", 0), "content_read_count"), "Hashed bytes; not semantic analysis"),
        _metric("Checks assessed", _count(assessed, "checks_assessed"), f"{partial} partial · {pending} pending"),
        _metric("Findings", _count(len(validated["findings"]), "finding_count"), "Evidence-linked findings only"),
        _metric("Redactions", _count(validated["privacy"]["redaction_count"], "redaction_count"), "Deterministic privacy matches"),
        _metric("Unknowns", _count(len(validated["unknowns"]), "unknown_count"), "Explicit unanswered questions"),
    ])

    limitations = "; ".join(coverage["limits"]) or "No additional coverage limits recorded."
    completion_text = "Discovery complete" if coverage["discovery_complete"] else "Discovery incomplete"
    check_text = "Checks complete" if coverage["checks_complete"] else "Checks incomplete"
    analysis_text = "Analysis complete" if coverage["analysis_complete"] else "Analysis incomplete"
    status_banner = (
        '<div class="status-banner"><div class="status-icon" aria-hidden="true">i</div><div>'
        f'<h3>{_h(completion_text)} · {_h(analysis_text)} · {_h(check_text)}</h3>'
        f'<p>{_h(limitations)}</p></div></div>'
    )

    mode_state = validated.get("extensions", {}).get("scan_mode", {})
    scan_mode = validated["run"].get("scan_mode", mode_state.get("name", "deep"))
    mode_contract = mode_state.get("coverage_contract", "Scan mode coverage contract was not recorded.")
    git_state = validated["provenance"].get("git", {})
    git_detected = bool(git_state.get("detected"))
    git_identity = "Not a Git repository"
    git_detail = "No repository metadata was detected in the declared root."
    if git_detected:
        branch = git_state.get("branch") or "detached/unknown"
        commit = git_state.get("commit") or "commit not resolved"
        git_identity = f"{branch} · {commit}"
        limitations_text = "; ".join(git_state.get("limitations", [])) or "No additional Git provenance limits recorded."
        git_detail = limitations_text

    git_scope = validated.get("extensions", {}).get("git_change_scope")
    git_scope_card = ""
    if isinstance(git_scope, dict):
        changed_count = sum(
            len(git_scope.get(key, []))
            for key in ("added", "modified", "deleted", "renamed", "copied", "untracked")
        )
        git_scope_card = (
            '<article class="insight"><span>Git change scope</span>'
            f'<h3>{_h(git_scope.get("base_ref", "unknown"))} ? {_h(git_scope.get("head_ref", "HEAD"))}</h3>'
            f'<p>{changed_count} advisory path changes. Full Scan inventory remains authoritative.</p></article>'
        )

    mode_section = (
        '<section class="section" aria-labelledby="mode-title">'
        '<div class="section-head"><div class="section-kicker">Inspection boundary</div>'
        f'<h2 id="mode-title">{_h(scan_mode)} mode</h2>'
        f'<p class="section-intro">{_h(mode_contract)}</p></div>'
        '<div class="insights"><article class="insight"><span>Mode contract</span>'
        f'<h3>{_h(scan_mode)}</h3><p>{_h(coverage["sampling"])}</p></article>'
        '<article class="insight"><span>Repository provenance</span>'
        f'<h3>{_h(git_identity)}</h3><p>{_h(git_detail)}</p></article>'
        f'{git_scope_card}</div></section>'
    )
    target_specific = _baseline_section(validated) + mode_section + (
        '<section class="section" aria-labelledby="privacy-title">'
        '<div class="section-head"><div class="section-kicker">Privacy boundary</div>'
        '<h2 id="privacy-title">Local-first by construction</h2>'
        '<p class="section-intro">These values are copied from canonical state; the renderer performs no network operation.</p></div>'
        '<div class="insights"><article class="insight"><span>Mode</span>'
        f'<h3>{_h(validated["privacy"]["mode"])}</h3><p>Redaction level: {_h(validated["privacy"]["redaction_level"])}. '
        f'Egress performed: {_h(str(validated["privacy"]["egress_performed"]).lower())}.</p></article>'
        '<article class="insight"><span>Execution boundary</span>'
        f'<h3>Target executed: {_h(str(validated["run"]["target_executed"]).lower())}</h3>'
        f'<p>Network used: {_h(str(validated["run"]["network_used"]).lower())}. '
        f'Sensitive paths recorded: {_h(validated["privacy"]["sensitive_path_count"])}.</p></article></div></section>'
    )

    slots = {
        "REPORT_TITLE": _h(f'{validated["project"]["name"]} | Scan report'),
        "INSPECTION_LABEL": '<span class="live-dot" aria-hidden="true"></span> Scan Core · static inspection',
        "PROJECT_NAME": _h(validated["project"]["name"]),
        "PLAIN_LANGUAGE_PURPOSE": _h(validated["summary"]["overview"]),
        "VERDICT_PILLS_HTML": (
            f'<span class="verdict-pill"><strong>Mode</strong> {_h(scan_mode)}</span>'
            f'<span class="verdict-pill"><strong>Readiness</strong> {_h(validated["summary"]["readiness"])}</span>'
            f'<span class="verdict-pill"><strong>Discovery</strong> {_h(str(coverage["discovery_complete"]).lower())}</span>'
            f'<span class="verdict-pill"><strong>Checks</strong> {_h(str(coverage["checks_complete"]).lower())}</span>'
        ),
        "DECISION_SUMMARY_HTML": _decision_summary(validated),
        "SNAPSHOT_HTML": (
            f'Run <code>{_h(validated["run"]["scan_id"])}</code><br>'
            f'Snapshot <code>{_h(snapshot)}</code>'
        ),
        "METRIC_CARDS_HTML": metric_html,
        "VERDICT_TITLE": _h(validated["summary"]["condition"]),
        "VERDICT_SCOPE_AND_LIMITS": _h(validated["summary"]["limitations"]),
        "COVERAGE_STATUS_BANNER_HTML": status_banner,
        "PRIORITY_FINDING_CARDS_HTML": _finding_cards(validated),
        "WHAT_CHANGED_TITLE": "What changed the review",
        "WHAT_CHANGED_INTRO": "This is a point-in-time review unless a comparison baseline is embedded. These are the observations that most changed the reviewer’s understanding; they are not claims that the project itself changed over time.",
        "WHAT_CHANGED_CARDS_HTML": _what_changed_cards(validated),
        "ANATOMY_TITLE": "Architecture requires evidence",
        "ANATOMY_EXPLANATION": "Components and relationships are rendered only when canonical state records them.",
        "EVIDENCED_SYSTEM_MAP_HTML": _system_map(validated),
        "STRENGTHS_TITLE": "Recorded controls",
        "CONTROL_VERIFICATION_LIMITS": "Control presence and effectiveness remain distinct verification states.",
        "CONTROL_CARDS_HTML": _control_cards(validated),
        "PARTS_TITLE": "Recorded components",
        "PARTS_INTRO": "No component is invented from file names alone.",
        "COMPONENT_CARDS_HTML": _component_cards(validated),
        "UNKNOWNS_TITLE": "What remains unanswered",
        "UNKNOWNS_INTRO": "Unknowns sit near the verdict so incomplete work stays visible.",
        "UNKNOWN_CARDS_HTML": _unknown_cards(validated),
        "COVERAGE_TITLE": "Coverage is not confidence",
        "DISCOVERY_VS_ANALYSIS": "Discovery, content reading, semantic analysis, check assessment and runtime verification are separate dimensions.",
        "COVERAGE_ROWS_HTML": _coverage_rows(validated),
        "COVERAGE_DETAIL": _h(limitations),
        "TARGET_SPECIFIC_SECTIONS_HTML": target_specific,
        "NEXT_STEPS_TITLE": "Continuation recorded in state",
        "NEXT_STEPS_INTRO": _h("; ".join(validated["continuation"]["remaining"])),
        "ACTION_CARDS_HTML": _action_cards(validated),
        "CHECK_COVERAGE_INTRO": "Statuses and counts below are rendered directly from canonical state.",
        "CHECK_COVERAGE_MATRIX_HTML": _check_matrix(validated),
        "APPENDIX_INTRO": "The inventory and evidence tables are presentations of the same authoritative embedded state.",
        "SEARCHABLE_EVIDENCE_AND_INVENTORY_HTML": _appendix(validated),
        "INSPECTION_BOUNDARY": _h(validated["project"]["scope"]),
        "STATE_SCHEMA_VERSION": _h(validated["schema_version"]),
        "STATE_JSON": _embedded_state_json(validated),
    }

    html = _template()
    for name, value in slots.items():
        placeholder = "{{" + name + "}}"
        if html.count(placeholder) != 1:
            raise ValidationError(f"Report template slot {name} expected exactly once")
        html = html.replace(placeholder, value)
    remaining = _SLOT_RE.findall(html)
    if remaining:
        raise ValidationError("Unfilled report template slots: " + ", ".join(sorted(set(remaining))))
    return html


def render_report(state: Mapping[str, Any], output: str | Path) -> Path:
    """Validate state, write self-contained HTML atomically, then validate round-trip."""
    if state.get("schema_version") not in {"1.3", "1.4"}:
        raise ValidationError("Renderer accepts canonical schema_version 1.3 or 1.4 only")
    html = render_html(state)
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(html, encoding="utf-8", newline="\n")
    try:
        validate_report(temporary)
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return path
