"""Self-contained HTML rendering from validated canonical Scan 1.3 state."""

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


def _finding_cards(state: Mapping[str, Any]) -> str:
    rows = state["findings"]
    if not rows:
        return _empty_card(
            "No findings in deterministic core state",
            "Inventory, hashing and privacy checks do not create semantic findings by themselves.",
        )
    return "".join(
        '<article class="finding risk"><div class="finding-top">'
        f'<span class="severity">{_h(row["severity"])} · {_h(row["verification_state"])}</span>'
        f'<span class="confidence">{_h(row["confidence"])} confidence</span></div>'
        f'<h3>{_h(row["title"])}</h3><p>{_h(row["impact"])} '
        f'<strong>Limit:</strong> {_h(row["uncertainty"])}</p>'
        f'<span class="evidence-ref">Evidence: {_evidence_links(state, row["evidence_ids"])}</span></article>'
        for row in rows
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
            _h(row["locator"]),
            _h(row["result"]),
            _h(row["limitations"]),
        ]
        for row in state["evidence"]
    ]
    return (
        "<h3>Artifact inventory</h3>"
        + _scroll_table(
            "Artifact inventory; scroll horizontally if needed",
            ["ID", "Locator", "Kind", "Inspection status", "Identity", "Privacy", "Evidence"],
            inventory_rows,
            "table-inventory",
        )
        + "<h3>Evidence</h3>"
        + _scroll_table(
            "Evidence; scroll horizontally if needed",
            ["ID", "Kind", "Locator", "Observation", "Limitations"],
            evidence_rows,
            "table-evidence",
        )
    )


def render_html(state: Mapping[str, Any]) -> str:
    """Return self-contained HTML for validated Scan 1.3 state."""
    validated = validate_state(dict(state), version="1.3")
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

    target_specific = (
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
            f'<span class="verdict-pill"><strong>Readiness</strong> {_h(validated["summary"]["readiness"])}</span>'
            f'<span class="verdict-pill"><strong>Discovery</strong> {_h(str(coverage["discovery_complete"]).lower())}</span>'
            f'<span class="verdict-pill"><strong>Checks</strong> {_h(str(coverage["checks_complete"]).lower())}</span>'
        ),
        "SNAPSHOT_HTML": (
            f'Run <code>{_h(validated["run"]["scan_id"])}</code><br>'
            f'Snapshot <code>{_h(snapshot)}</code>'
        ),
        "METRIC_CARDS_HTML": metric_html,
        "VERDICT_TITLE": _h(validated["summary"]["condition"]),
        "VERDICT_SCOPE_AND_LIMITS": _h(validated["summary"]["limitations"]),
        "COVERAGE_STATUS_BANNER_HTML": status_banner,
        "PRIORITY_FINDING_CARDS_HTML": _finding_cards(validated),
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
    if state.get("schema_version") != "1.3":
        raise ValidationError("Scan v0.2 renderer accepts canonical schema_version 1.3 only")
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
