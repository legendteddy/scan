"""Self-contained, progressively disclosed HTML from validated canonical Scan state."""
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

_TEMPLATE_PACKAGE = 'scan_core.report'
_TEMPLATE_NAME = 'shell.html'
_SLOT_RE = re.compile(r'\{\{[A-Z_]+\}\}')
_SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'informational': 4}
_CONFIDENCE_ORDER = {'high': 0, 'medium': 1, 'low': 2}


def _h(value: Any) -> str:
    return escape(str(value), quote=True)


def _embedded_state_json(state: Mapping[str, Any]) -> str:
    return (canonical_state_json(dict(state)).replace('&', '\\u0026')
            .replace('<', '\\u003c').replace('>', '\\u003e'))


def _template() -> str:
    return files(_TEMPLATE_PACKAGE).joinpath(_TEMPLATE_NAME).read_text(encoding='utf-8')


def _evidence_links(state: Mapping[str, Any], ids: Sequence[str]) -> str:
    lookup = {row['id']: row for row in state['evidence']}
    links = [f'<a href="#e-{_h(ident)}">{_h(lookup[ident]["locator"])} '
             f'({_h(ident)})</a>' for ident in ids if ident in lookup]
    return ', '.join(links) if links else 'No direct evidence attached'


def _scroll_table(label: str, headings: Sequence[str], rows: Sequence[Sequence[str]], css_class: str = '') -> str:
    head = ''.join(f'<th scope="col">{_h(value)}</th>' for value in headings)
    body = '\n'.join('<tr>' + ''.join(f'<td data-label="{_h(label)}">{cell}</td>'
                                    for label, cell in zip(headings, row)) + '</tr>' for row in rows)
    if not rows:
        body = f'<tr><td colspan="{len(headings)}">No rows recorded in canonical state.</td></tr>'
    return (f'<div class="table-scroll" tabindex="0" role="region" aria-label="{_h(label)}">'
            f'<table class="{_h(css_class)}"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>')


def _count(value: int, key: str) -> str:
    return f'<b data-scan-count="{_h(key)}">{value}</b>'


def _metric(label: str, value_html: str, note: str) -> str:
    return f'<article class="metric"><span>{_h(label)}</span>{value_html}<small>{_h(note)}</small></article>'


def _disclosure(title: str, content: str, ident: str = '', note: str = '', css: str = 'audit-group') -> str:
    anchor = f' id="{_h(ident)}"' if ident else ''
    return (f'<details class="{css}"{anchor}><summary>{_h(title)}'
            f'<small>{_h(note)}</small></summary>{content}</details>')


def _technical(value: Any) -> str:
    return '<pre>' + _h(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)) + '</pre>'


def _sorted_findings(state: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    # Severity expresses consequence; confidence breaks ties without hiding weaker evidence.
    return sorted(state['findings'], key=lambda row: (
        _SEVERITY_ORDER.get(row['severity'], 99),
        _CONFIDENCE_ORDER.get(row['confidence'], 99), row['id']))


def _finding_card(state: Mapping[str, Any], row: Mapping[str, Any], *, primary: bool = False) -> str:
    attrs = ' data-priority-finding="true"' if primary else f' id="f-{_h(row["id"])}"'
    detail = (f'<p><strong>Confidence:</strong> {_h(row["confidence"])}. '
              f'<strong>Limit:</strong> {_h(row["uncertainty"])}</p>'
              f'<p><strong>Safe verification:</strong> {_h(row["safe_verification"])}</p>'
              f'<span class="evidence-ref">Evidence: {_evidence_links(state, row["evidence_ids"])}</span>'
              f'<p class="secondary">Finding ID: <code>{_h(row["id"])}</code></p>')
    return (f'<article class="finding severity-{_h(row["severity"])}"{attrs}>'
            f'<div class="finding-top"><span class="severity">{_h(row["severity"])}</span>'
            f'<span>{_h(row["verification_state"])} evidence</span></div>'
            f'<h3>{_h(row["title"])}</h3><p>{_h(row["impact"])}</p>'
            f'<p class="recommendation"><strong>Next:</strong> {_h(row["recommendation"])}</p>'
            + _disclosure('Limits and evidence', detail, css='finding-detail') + '</article>')


def _finding_cards(state: Mapping[str, Any]) -> str:
    rows = _sorted_findings(state)
    if not rows:
        return ('<div class="notice"><h3>No findings recorded</h3>'
                '<p>This is not a clean bill of health. '
                '<a href="#unknowns">Read the unknowns</a> and inspection depth before drawing a conclusion.</p></div>')
    cards = ''.join(_finding_card(state, row, primary=True) for row in rows[:5])
    if len(rows) > 5:
        cards += f'<p><a href="#all-findings">Read all {len(rows)} findings in the audit appendix</a>.</p>'
    return cards


def _baseline_section(state: Mapping[str, Any]) -> str:
    if state.get('schema_version') != '1.4':
        return '<div class="change-block"><h3>Scan baseline delta</h3><p>No comparison baseline available.</p></div>'
    delta, baseline = state['delta'], state['baseline']
    metrics = []
    for group, labels in (
        ('artifacts', (('added', 'Artifacts added'), ('changed', 'Artifacts changed'), ('removed', 'Artifacts removed'))),
        ('findings', (('new', 'New findings'), ('resolved', 'Resolved findings'))),
        ('unknowns', (('new', 'New unknowns'), ('resolved', 'Resolved unknowns'))),
    ):
        for key, label in labels:
            metrics.append(_metric(label, _count(len(delta[group][key]), f'delta_{group}_{key}'),
                                   'Absent now; not proof of a fix' if key == 'resolved' else 'Compared with the accepted baseline'))
    # The established visible-count contract includes unavailable delta counts. Keep those
    # exact receipts in a disclosure instead of presenting a wall of first-scan zeros.
    if delta['available']:
        comparison = ('<p>Since baseline. Resolved means absent from current state; it does not mean fixed or verified.</p>'
                      '<div class="metric-grid">' + ''.join(metrics) + '</div>'
                      f'<p>Modified findings: {len(delta["findings"]["modified"])}. '
                      f'Modified unknowns: {len(delta["unknowns"]["modified"])}.</p>')
    else:
        comparison = ('<p>No comparison baseline available.</p>' + _disclosure(
            'Baseline count receipts', '<div class="metric-grid">' + ''.join(metrics) + '</div>', css='baseline-receipts'))
    freshness = ''.join(_metric(label, _count(baseline[key], key), note) for label, key, note in (
        ('Fresh evidence', 'fresh_evidence_count', 'Recorded as fresh in this scan'),
        ('Verified reuse', 'reused_evidence_count', 'Safely reused at original depth; retains original observation time'),
        ('Rejected reuse', 'rejected_reuse_count', 'Candidates rejected by a reuse gate'),
    ))
    return ('<div class="change-block"><h3 id="baseline-title">Scan baseline delta</h3>' + comparison + '</div>'
            '<div class="change-block"><h3>Evidence freshness</h3><p>Evidence age is independent of baseline changes.</p>'
            f'<div class="metric-grid">{freshness}</div></div>')


def _changes(state: Mapping[str, Any]) -> str:
    scope = state.get('extensions', {}).get('git_change_scope')
    if isinstance(scope, dict):
        count = sum(len(scope.get(key, [])) for key in ('added', 'modified', 'deleted', 'renamed', 'copied', 'untracked'))
        git = (f'<p>{count} advisory path changes between <code>{_h(scope.get("base_ref", "unknown"))}</code> '
               f'and <code>{_h(scope.get("head_ref", "HEAD"))}</code>. '
               'Source-control context only. Full Scan inventory remains authoritative.</p>')
    else:
        git = '<p>No Git advisory comparison recorded.</p>'
    return _baseline_section(state) + '<div class="change-block"><h3>Git change scope (advisory)</h3>' + git + '</div>'


def _coverage_rows(state: Mapping[str, Any]) -> str:
    coverage, artifacts = state['coverage'], state['artifacts']
    def count(status: str, origin: str | None = None) -> int:
        return sum(row['status'] == status and (origin is None or row['inspection_origin'] == origin) for row in artifacts)
    assessed = sum(row['status'] == 'assessed' for row in state['checks'])
    runtime = [row for row in state.get('evidence', []) if row.get('evidence_class') == 'runtime']
    observed = sum(row['kind'] == 'observed' and row['inspection_origin'] == 'fresh' for row in runtime)
    rows = [
        ('Artifact discovery', 'Complete' if coverage['discovery_complete'] else 'Incomplete', f'{len(artifacts)} inventoried'),
        ('Semantic analysis', 'Complete' if coverage['analysis_complete'] else 'Incomplete',
         f'{count("analyzed", "fresh")} fresh analyzed · {count("analyzed", "verified_reuse")} reused analyzed'),
        ('Content reading', 'Separate from semantic analysis',
         f'{count("content_read", "fresh")} fresh content-read · {count("content_read", "verified_reuse")} reused content-read'),
        ('Limited artifact depth', 'Not analyzed',
         f'{count("metadata_only")} metadata-only · {count("partial")} partial · {count("not_inspected")} not inspected'),
        ('Unavailable artifacts', 'Read the recorded reasons',
         f'{count("unreadable")} unreadable · {count("excluded")} excluded · {count("discovered")} discovery only'),
        ('Checks assessed', 'Assessment is not a passing result', f'{assessed} of {len(state["checks"])}'),
        ('Unfinished checks', 'Separate assessment states',
         ' · '.join(f'{sum(c["status"] == status for c in state["checks"])} {status.replace("_", " ")}'
                    for status in ('not_assessed', 'partial', 'blocked', 'not_applicable'))),
        ('Runtime verification', 'Evidence records; no coverage denominator' if observed else 'Not established',
         f'{observed} fresh observed runtime records · {len(runtime)} runtime records total'),
    ]
    return ''.join(f'<div class="coverage-row"><span>{_h(label)}</span><span>{_h(status)}</span><b>{_h(value)}</b></div>'
                   for label, status, value in rows)


def _unknown_cards(state: Mapping[str, Any]) -> str:
    rows = state['unknowns']
    if not rows:
        return '<p>No unknowns recorded. Absence of recorded questions does not establish complete verification.</p>'
    def card(row):
        return (f'<article class="record" id="u-{_h(row["id"])}"><h3>{_h(row["question"])}</h3>'
                f'<p>{_h(row["reason"])}</p><p><strong>Impact:</strong> {_h(row["impact"])}</p>'
                f'<p><strong>Verify next:</strong> {_h(row["next_safe_step"])}</p>'
                + _disclosure('Evidence and identifier',
                              f'<p><code>{_h(row["id"])}</code></p>' + _evidence_links(state, row['evidence_ids']), css='unknown-detail') + '</article>')
    visible = ''.join(card(row) for row in rows[:3])
    if len(rows) > 3:
        visible += _disclosure(f'{len(rows) - 3} more unknowns', ''.join(card(row) for row in rows[3:]), 'more-unknowns')
    return visible


def _component_cards(state: Mapping[str, Any]) -> str:
    return ''.join(
        f'<article class="module" id="c-{_h(row["id"])}"><h3>{_h(row["name"])}</h3>'
        f'<p>{_h(row["purpose"])}</p><dl><div><dt>Boundary</dt><dd>{_h(row["boundaries"])}</dd></div>'
        f'<div><dt>Evidence</dt><dd>{_evidence_links(state, row["evidence_ids"])}</dd></div></dl></article>'
        for row in state['components'])


def _system_map(state: Mapping[str, Any]) -> str:
    endpoints = {row['id']: row['locator'] for row in state['artifacts']}
    endpoints.update({row['id']: row['name'] for row in state['components']})
    rows = state['relationships']
    def relation(row):
        return (f'<li class="relationship" id="r-{_h(row["id"])}"><h3>'
                f'<span>{_h(endpoints[row["from_id"]])}</span><span class="relation-kind">'
                f'→ {_h(row["kind"])} →</span><span>{_h(endpoints[row["to_id"]])}</span></h3>'
                f'<p>{_h(row["explanation"])}</p><p class="secondary">{_h(row["verification_state"])} evidence · '
                f'{_h(row["confidence"])} confidence</p>' + _disclosure('Relationship evidence',
                _evidence_links(state, row['evidence_ids']) + f'<p><code>{_h(row["id"])}</code></p>', css='relationship-detail') + '</li>')
    if not rows:
        result = '<div class="notice"><h3>No relationships recorded</h3><p>Inventory alone does not establish architecture.</p></div>'
    else:
        result = f'<p>{len(rows)} recorded relationships. All source and target endpoints are named.</p>'
        result += '<ul class="relationship-list">' + ''.join(relation(row) for row in rows[:8]) + '</ul>'
        if len(rows) > 8:
            result += _disclosure(f'{len(rows) - 8} more relationships',
                                  '<ul class="relationship-list">' + ''.join(relation(row) for row in rows[8:]) + '</ul>', 'more-relationships')
    result += _disclosure(f'Recorded components ({len(state["components"])})',
                          '<div class="components">' + _component_cards(state) + '</div>'
                          if state['components'] else '<p>No components recorded.</p>', 'parts-title')
    return result


def _action_cards(state: Mapping[str, Any]) -> str:
    items = []
    seen = set()
    for row in sorted(state['actions'], key=lambda r: (_SEVERITY_ORDER.get(r['priority'], 99), r['id'])):
        items.append((row['description'], row['priority'], row['expected_verification'], row['authorization_requirements']))
    if not items:
        items.extend((r['recommendation'], r['severity'], r['safe_verification'], 'Follow the recorded inspection boundary')
                     for r in _sorted_findings(state))
        items.extend((r['next_safe_step'], 'Verify next', r['question'], 'Follow the recorded inspection boundary') for r in state['unknowns'])
    cards = []
    for title, priority, verification, approval in items:
        if title in seen:
            continue
        seen.add(title)
        cards.append(f'<li class="action"><span class="action-label">{_h(priority)}</span><h3>{_h(title)}</h3>'
                     f'<p><strong>Verify:</strong> {_h(verification)}</p><p class="secondary">Authorization: {_h(approval)}</p></li>')
        if len(cards) == 5:
            break
    if not cards:
        return '<p>No supported actions recorded. See the continuation receipt in the appendix.</p>'
    return '<ol class="actions">' + ''.join(cards) + '</ol><p class="secondary">Complete action and continuation receipts remain in the appendix.</p>'


def _check_matrix(state: Mapping[str, Any]) -> str:
    rows = [[f'<strong>{_h(c["title"])}</strong><br><code>{_h(c["id"])}</code>',
             _h(c['scope']) + '<br>' + _h(c['method']), _h(c['status']),
             _h(c['result']) + '<br><small>' + _h(c['limitations']) + '</small>',
             _evidence_links(state, c['evidence_ids'])] for c in state['checks']]
    return _scroll_table('Check coverage; scroll horizontally if needed',
                         ['Check', 'Scope and method', 'Status', 'Result and limits', 'Evidence'], rows, 'table-checks')


def _appendix(state: Mapping[str, Any]) -> str:
    inventory = [[f'<code>{_h(a["id"])}</code>', _h(a['locator']), _h(a['path_kind']),
                  _h(a['status']) + ' · ' + _h(a['inspection_origin']), f'<code>{_h(a["content_identity"])}</code>',
                  _h(a['redaction_state']), _evidence_links(state, a['evidence_ids'])] for a in state['artifacts']]
    evidence = []
    for e in state['evidence']:
        freshness = e.get('freshness', {})
        age = (_h(freshness.get('status', e['inspection_origin']).replace('_', ' '))
               + '<br>Observed: ' + _h(e['time']))
        if freshness.get('reused_at'):
            age += '<br>Reused: ' + _h(freshness['reused_at'])
        evidence.append([
            f'<code id="e-{_h(e["id"])}">{_h(e["id"])}</code>', _h(e['kind']), age, _h(e['locator']),
            f'<strong>{_h(e["claim"])}</strong><br>{_h(e["result"])}',
            _h(e['limitations']) + '<br><small>Method: ' + _h(e['method']) + '</small>',
        ])
    findings = ''.join(_finding_card(state, row) for row in _sorted_findings(state)) or '<p>No findings recorded.</p>'
    controls = ''.join(f'<article class="control"><h3>{_h(c["description"])}</h3><p>{_h(c["effectiveness_status"])}</p>'
                       f'<p>{_h(c["limitations"])}</p><span class="evidence-ref">{_evidence_links(state, c["evidence_ids"])}</span></article>'
                       for c in state['controls']) or '<p>No controls assessed.</p>'
    metadata = {key: state[key] for key in ('run', 'project', 'provenance', 'privacy', 'coverage', 'summary', 'continuation', 'extensions')}
    # Every canonical field remains available as readable static technical receipts, as
    # well as in the one authoritative inert state block. Never truncate target data.
    records = ''.join(_disclosure(f'{group}: complete records ({len(state[group])})', _technical(state[group]), css='technical-records')
                      for group in ('checks', 'artifacts', 'evidence', 'findings', 'unknowns', 'relationships', 'components', 'controls', 'actions'))
    baseline = {key: state[key] for key in ('baseline', 'delta') if key in state}
    provenance = (f'<p><strong>Run:</strong> <code>{_h(state["run"]["scan_id"])}</code></p>'
                  f'<p><strong>Completed:</strong> {_h(state["run"]["completed_at"])}</p>'
                  f'<p><strong>Snapshot digest:</strong> <code>{_h(state["provenance"]["snapshot_digest"])}</code></p>'
                  f'<p><strong>Scope:</strong> {_h(state["project"]["scope"])}</p>'
                  f'<p id="mode-title"><strong>Inspection mode:</strong> {_h(state["run"].get("scan_mode", "not recorded"))}</p>'
                  f'<p id="privacy-title"><strong>Privacy:</strong> {_h(state["privacy"]["mode"])}; '
                  f'egress performed: {_h(str(state["privacy"]["egress_performed"]).lower())}.</p>'
                  + _technical(state['provenance'].get('git', {})))
    return ''.join([
        _disclosure('Source, snapshot and inspection boundary', provenance, 'run-metadata'),
        _disclosure('What was checked', _check_matrix(state), 'checks-title', f'{len(state["checks"])} checks'),
        _disclosure('All findings', findings, 'all-findings', f'{len(state["findings"])} findings'),
        _disclosure('Unknown receipts', _technical(state['unknowns']), 'unknown-receipts', f'{len(state["unknowns"])} unknowns'),
        _disclosure('Relationship receipts', _technical(state['relationships']), 'relationship-receipts', f'{len(state["relationships"])} relationships'),
        _disclosure('Artifact inventory', _scroll_table('Artifact inventory; scroll horizontally if needed',
            ['ID', 'Locator', 'Kind', 'Inspection status', 'Identity', 'Privacy', 'Evidence'], inventory, 'table-inventory'),
            'artifact-inventory', f'{len(state["artifacts"])} artifacts'),
        _disclosure('Evidence ledger', _scroll_table('Evidence ledger; scroll horizontally if needed',
            ['ID', 'Kind', 'Freshness', 'Locator', 'Observation', 'Limitations'], evidence, 'table-evidence'),
            'evidence-ledger', f'{len(state["evidence"])} records'),
        _disclosure('Recorded controls', controls, 'strengths-title', f'{len(state["controls"])} controls'),
        _disclosure('Actions and continuation', _technical({'actions': state['actions'], 'continuation': state['continuation']}), 'action-receipts'),
        _disclosure('Baseline and reuse metadata', _technical(baseline), 'baseline-metadata'),
        _disclosure('Raw and technical observations', _technical(metadata) + records, 'technical-observations'),
    ])


def render_html(state: Mapping[str, Any]) -> str:
    """Return deterministic, self-contained HTML for validated Scan 1.3/1.4 state."""
    version = state.get('schema_version')
    if version not in {'1.3', '1.4'}:
        raise ValidationError('Renderer accepts canonical schema_version 1.3 or 1.4 only')
    validated = validate_state(dict(state), version=version)
    coverage, summary = validated['coverage'], validated['summary']
    unknown_count = len(validated['unknowns'])
    facts = ''.join(f'<div class="fact">{_count(value, key)}<span>{label}</span></div>' for label, key, value in (
        ('Artifacts inventoried', 'discovered_artifact_count', len(validated['artifacts'])),
        ('Content read', 'content_read_count', coverage['counts_by_status'].get('content_read', 0)),
        ('Findings', 'finding_count', len(validated['findings'])),
        ('Open unknowns', 'unknown_count', unknown_count),
    ))
    mode = validated['run'].get('scan_mode', validated.get('extensions', {}).get('scan_mode', {}).get('name', 'deep'))
    source = (f'{_h(mode)} inspection · {_h(validated["run"]["completed_at"][:10])} · '
              '<a href="#run-metadata">Source and snapshot</a>')
    # Keep the remaining mandatory count receipts with their explanatory coverage context.
    counts = ('<p class="coverage-note">Checks assessed: ' + _count(coverage['counts_by_check_status'].get('assessed', 0), 'checks_assessed')
              + '. Privacy redactions: ' + _count(validated['privacy']['redaction_count'], 'redaction_count') + '.</p>')
    coverage_html = (f'<div class="coverage-card">{_coverage_rows(validated)}</div>{counts}'
                     f'<p class="coverage-note">{_h("; ".join(coverage["limits"]))}</p>'
                     f'<p class="coverage-note">{_h(summary["limitations"])}</p>')
    notice = (f'<a href="#unknowns">{unknown_count} unanswered question(s)</a>; readiness: {_h(summary["readiness"])}.'
              if unknown_count else f'Readiness: {_h(summary["readiness"])}. <a href="#coverage">Read the inspection limits</a>.')
    slots = {
        'REPORT_TITLE': _h(f'{validated["project"]["name"]} | Scan report'),
        'PROJECT_NAME': _h(validated['project']['name']), 'VERDICT': _h(summary['condition']),
        'HERO_FACTS_HTML': facts, 'UNKNOWN_NOTICE_HTML': notice,
        'SOURCE_LINE_HTML': source, 'FINDINGS_HTML': _finding_cards(validated), 'CHANGES_HTML': _changes(validated),
        'COVERAGE_HTML': coverage_html, 'UNKNOWNS_HTML': _unknown_cards(validated),
        'ARCHITECTURE_HTML': _system_map(validated), 'ACTIONS_HTML': _action_cards(validated),
        'AUDIT_HTML': _appendix(validated), 'INSPECTION_BOUNDARY': _h(validated['project']['scope']),
        'STATE_SCHEMA_VERSION': _h(version), 'STATE_JSON': _embedded_state_json(validated),
    }
    html = _template()
    # Substitute once: target text that happens to look like a slot is always text.
    expected = {'{{' + name + '}}' for name in slots}
    found = _SLOT_RE.findall(html)
    if set(found) != expected or len(found) != len(expected):
        raise ValidationError('Report template slots must occur exactly once and match renderer contract')
    return _SLOT_RE.sub(lambda match: slots[match.group()[2:-2]], html)


def render_report(state: Mapping[str, Any], output: str | Path) -> Path:
    """Validate state, write self-contained HTML atomically, then validate round-trip."""
    html = render_html(state)
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(html, encoding='utf-8', newline='\n')
    try:
        validate_report(temporary)
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return path
