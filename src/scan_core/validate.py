"""Version-dispatched structural validation for Scan state and reports.

Validation never executes report or target content and is not a factual/security audit.
The Scan 1.2 rules in this module are intentionally preserved from the launch validator.
"""

from __future__ import annotations

import json
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Mapping

from .errors import UnsupportedSchemaError, ValidationError

STATE_ID = 'project-anatomy-state'
STATUSES = {'discovered', 'metadata_only', 'content_read', 'analyzed', 'partial',
            'unreadable', 'excluded', 'not_inspected'}
ORIGINS = {'fresh', 'verified_reuse', 'unverified_carryover'}
VERIFICATION = {'static', 'observed', 'inferred', 'unverified'}
CHECK_STATUSES = {'assessed', 'partial', 'not_assessed', 'blocked', 'not_applicable'}
CHECK_CATEGORIES = (
    'purpose_and_scope', 'inventory_and_provenance', 'architecture_and_flows',
    'correctness_and_integrity', 'security_and_trust', 'privacy_and_data_lifecycle',
    'dependencies_and_licensing', 'testing_and_reliability', 'performance_and_resources',
    'maintainability', 'usability_and_accessibility', 'operations_and_recovery',
    'release_and_distribution', 'content_and_data_quality',
)
FIELDS = {
    'project': 'name purpose target_types source_locators snapshot scope exclusions critical_artifact_ids',
    'summary': 'overview operation condition strengths priorities readiness evidence_ids limitations',
    'coverage': 'discovery_complete analysis_complete discovered_artifact_count counts_by_status counts_by_check_status checks_complete limits sampling methods checks_performed checks_not_performed snapshot_consistency sensitive_omissions',
    'continuation': 'completed remaining hypotheses decisions revalidation source_needs authorization_note',
    'artifacts': 'id locator type status reason evidence_ids inspection_origin inspected_at content_identity',
    'components': 'id name purpose artifact_ids evidence_ids boundaries',
    'relationships': 'id from_id to_id kind explanation evidence_ids confidence verification_state',
    'evidence': 'id artifact_id locator kind claim result method time limitations inspection_origin',
    'findings': 'id title impact severity confidence verification_state artifact_ids evidence_ids uncertainty recommendation safe_verification',
    'controls': 'id description artifact_ids evidence_ids effectiveness_status limitations',
    'unknowns': 'id question artifact_ids evidence_ids reason impact next_safe_step',
    'actions': 'id description priority related_ids prerequisites authorization_requirements expected_verification completion_state',
    'checks': 'id category title status scope method artifact_ids evidence_ids related_ids verification_state result limitations reason next_step',
}
COLLECTIONS = ('artifacts', 'components', 'relationships', 'evidence', 'findings',
               'controls', 'unknowns', 'actions', 'checks')
STRING_LISTS = {'target_types', 'source_locators', 'exclusions', 'strengths', 'priorities',
                'limits', 'methods', 'checks_performed', 'checks_not_performed',
                'sensitive_omissions', 'completed', 'remaining', 'hypotheses',
                'decisions', 'revalidation', 'source_needs', 'prerequisites'}
SPECIAL = STRING_LISTS | {'snapshot', 'discovery_complete', 'analysis_complete',
                         'discovered_artifact_count', 'counts_by_status', 'inspected_at',
                         'counts_by_check_status', 'checks_complete', 'next_step'}


def require(condition, message):
    if not condition:
        raise ValidationError(message)


def string(value):
    return isinstance(value, str) and bool(value.strip())


def fields(obj, group):
    require(isinstance(obj, dict), group + ' must be an object')
    for key in FIELDS[group].split():
        require(key in obj, group + ': missing ' + key)
        value = obj[key]
        label = group + '.' + key
        if key.endswith('_ids') or key in STRING_LISTS:
            require(isinstance(value, list) and all(string(v) for v in value), label + ' must be a string array')
        elif key not in SPECIAL:
            require(string(value), label + ' must be a nonempty string')


class StateParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.blocks = []
        self.active = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get('id') == STATE_ID:
            require(tag == 'script' and attrs.get('type') == 'application/json',
                    'State ID must belong to an inert application/json script')
            self.blocks.append('')
            self.active = True

    def handle_endtag(self, tag):
        if tag == 'script':
            self.active = False

    def handle_data(self, data):
        if self.active:
            self.blocks[-1] += data


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON key: ' + key)
        result[key] = value
    return result


def reject_constant(value):
    raise ValidationError('Non-finite JSON number: ' + value)


def _validate_state_1_2(state):
    require(isinstance(state, dict), 'State must be an object')
    require(state.get('schema_version') == '1.2', 'Expected Scan schema_version 1.2')
    for key in ('project', 'summary', 'coverage', 'continuation'):
        fields(state.get(key), key)
    require(isinstance(state.get('extensions'), dict), 'extensions must be an object')
    require(isinstance(state['project']['snapshot'], dict) and state['project']['snapshot'],
            'project.snapshot must record identity/version and time')
    tables = {}
    all_ids = set()
    for group in COLLECTIONS:
        require(isinstance(state.get(group), list), group + ' must be an array')
        tables[group] = {}
        for item in state[group]:
            fields(item, group)
            ident = item['id']
            require(ident not in all_ids, 'Duplicate ID: ' + ident)
            all_ids.add(ident)
            tables[group][ident] = item

    def refs(obj, key, allowed, nonempty=False):
        values = obj[key]
        require(isinstance(values, list), key + ' must be an array')
        require(not nonempty or values, obj.get('id', 'state') + ': missing ' + key)
        require(all(v in allowed for v in values), obj.get('id', 'state') + ': unresolved/wrong-type ' + key)

    artifacts, evidence = tables['artifacts'], tables['evidence']
    endpoints = set(artifacts) | set(tables['components'])
    refs(state['project'], 'critical_artifact_ids', artifacts)
    refs(state['summary'], 'evidence_ids', evidence)
    for group in COLLECTIONS:
        for item in state[group]:
            if 'artifact_ids' in item:
                refs(item, 'artifact_ids', artifacts)
            if 'evidence_ids' in item:
                refs(item, 'evidence_ids', evidence, group in {'relationships', 'findings', 'controls'})
            if group in {'relationships', 'findings', 'checks'}:
                require(item['verification_state'] in VERIFICATION, 'Invalid verification_state')
            if group == 'relationships':
                require(item['from_id'] in endpoints and item['to_id'] in endpoints,
                        item['id'] + ': relationship endpoint must be artifact/component')
            if group == 'actions':
                refs(item, 'related_ids', all_ids)
            if group == 'checks':
                refs(item, 'related_ids', set(tables['findings']) | set(tables['controls']) |
                     set(tables['unknowns']) | set(tables['actions']))
            if group == 'findings':
                require(item['severity'] in {'critical', 'high', 'medium', 'low', 'informational'}, 'Invalid severity')

    for item in evidence.values():
        require(item['artifact_id'] in artifacts, item['id'] + ': invalid evidence artifact_id')
        require(item['kind'] in VERIFICATION, 'Invalid evidence kind')
        require(item['inspection_origin'] in ORIGINS, 'Invalid evidence origin')
        if item['inspection_origin'] == 'verified_reuse':
            reuse = item.get('reuse')
            require(isinstance(reuse, dict), item['id'] + ': verified reuse needs provenance')
            for key in ('prior_scan_id', 'prior_inspected_at', 'prior_method', 'prior_depth', 'identity_check'):
                require(string(reuse.get(key)), item['id'] + ': missing reuse.' + key)
            require(isinstance(reuse.get('prior_limits'), list) and all(string(v) for v in reuse['prior_limits']),
                    'reuse.prior_limits must be a string array')
            require(reuse.get('identity_match') is True, 'Verified reuse requires identity match')
    for item in artifacts.values():
        require(item['status'] in STATUSES, 'Invalid artifact status')
        require(item['inspection_origin'] in ORIGINS | {'none'}, 'Invalid artifact origin')
        require(string(item['inspected_at']) or
                (item['inspection_origin'] == 'none' and item['inspected_at'] is None),
                item['id'] + ': inspected_at must be timestamp or null for none')
        support = [evidence[v] for v in item['evidence_ids'] if evidence[v]['artifact_id'] == item['id']]
        if item['inspection_origin'] == 'verified_reuse':
            require(any(e['inspection_origin'] == 'verified_reuse' for e in support),
                    item['id'] + ': reused artifact needs its own reuse evidence')
        if item['status'] == 'analyzed':
            require(item['inspection_origin'] in {'fresh', 'verified_reuse'}, item['id'] + ': analyzed origin invalid')
            require(any(e['kind'] != 'unverified' and e['inspection_origin'] == item['inspection_origin']
                        for e in support), item['id'] + ': analyzed artifact needs direct substantive evidence')
    for item in tables['controls'].values():
        require(item['effectiveness_status'] in {'implemented_unverified', 'observed_effective',
                                               'observed_failed', 'reported_unverified'}, 'Invalid control status')
        if item['effectiveness_status'].startswith('observed_'):
            require(any(evidence[v]['kind'] == 'observed' and evidence[v]['inspection_origin'] != 'unverified_carryover'
                        for v in item['evidence_ids']), item['id'] + ': observed control status needs observed evidence')

    categories = {c['category'] for c in tables['checks'].values()}
    require(set(CHECK_CATEGORIES) <= categories,
            'Missing required check categories: ' + ', '.join(sorted(set(CHECK_CATEGORIES) - categories)))
    for check in tables['checks'].values():
        label = check['id'] + ': '
        require(check['status'] in CHECK_STATUSES, label + 'invalid check status')
        require(check['next_step'] is None or string(check['next_step']), label + 'invalid next_step')
        if check['status'] in {'partial', 'not_assessed', 'blocked'}:
            require(string(check['next_step']), label + 'unfinished check needs next_step')
        if check['status'] in {'assessed', 'partial'}:
            require(check['evidence_ids'], label + 'assessed/partial check needs evidence')
            require(any(evidence[v]['kind'] != 'unverified' and
                        evidence[v]['inspection_origin'] != 'unverified_carryover'
                        for v in check['evidence_ids']), label + 'check needs substantive evidence')
        if check['status'] == 'assessed':
            require(check['verification_state'] != 'unverified', label + 'assessed check cannot be unverified')
        if check['verification_state'] == 'observed':
            require(any(evidence[v]['kind'] == 'observed' and
                        evidence[v]['inspection_origin'] != 'unverified_carryover'
                        for v in check['evidence_ids']), label + 'observed check needs observed evidence')

    coverage = state['coverage']
    for key in ('discovery_complete', 'analysis_complete', 'checks_complete'):
        require(type(coverage[key]) is bool, 'coverage.' + key + ' must be boolean')
    count = coverage['discovered_artifact_count']
    require(type(count) is int and count >= 0 and count == len(artifacts),
            'Discovered artifact count does not match embedded inventory')
    counts = coverage['counts_by_status']
    require(isinstance(counts, dict) and all(k in STATUSES and type(v) is int and v >= 0
                                           for k, v in counts.items()), 'Invalid coverage counts_by_status')
    require({k: v for k, v in counts.items() if v} == dict(Counter(a['status'] for a in artifacts.values())),
            'Coverage status counts do not match embedded inventory')
    check_counts = coverage['counts_by_check_status']
    require(isinstance(check_counts, dict) and
            all(k in CHECK_STATUSES and type(v) is int and v >= 0 for k, v in check_counts.items()),
            'Invalid coverage counts_by_check_status')
    require({k: v for k, v in check_counts.items() if v} ==
            dict(Counter(c['status'] for c in tables['checks'].values())),
            'Check status counts do not match check matrix')
    check_complete = all(c['status'] in {'assessed', 'not_applicable'} for c in tables['checks'].values())
    require(coverage['checks_complete'] == check_complete,
            'checks_complete does not match unfinished check assessments')
    if coverage['analysis_complete']:
        require(coverage['discovery_complete'] and all(a['status'] == 'analyzed' for a in artifacts.values()),
                'Complete analysis cannot include incomplete discovery or unanalyzed artifacts')
    if not coverage['analysis_complete'] or not coverage['discovery_complete']:
        require(coverage['limits'] and state['continuation']['remaining'], 'Partial coverage needs limits and remaining work')
    for ident in state['project']['critical_artifact_ids']:
        if artifacts[ident]['status'] != 'analyzed':
            require(not coverage['analysis_complete'], 'Unread critical artifact prevents complete analysis')
            require(any(ident in u['artifact_ids'] for u in state['unknowns']),
                    ident + ': unread critical artifact needs explicit unknown')
    return state


SUPPORTED_SCHEMAS = ('1.2',)
PLANNED_SCHEMAS = ('1.3',)


def validate_state(state: Mapping[str, Any], version: str | None = None):
    """Validate canonical Scan state using its declared schema version."""
    require(isinstance(state, dict), 'State must be an object')
    declared = state.get('schema_version')
    if version is not None:
        require(declared == version,
                f'Expected Scan schema_version {version}, found {declared!r}')
    if declared == '1.2':
        return _validate_state_1_2(state)
    if declared == '1.3':
        raise UnsupportedSchemaError(
            'Scan schema_version 1.3 is reserved by the v0.2 contract but its validator ships in Slice 3')
    raise UnsupportedSchemaError(
        f'Unsupported Scan schema_version {declared!r}; supported: 1.2')


def load_report_state(path: str | Path):
    """Extract inert canonical state from a Scan HTML report without executing it."""
    parser = StateParser()
    with open(path, encoding='utf-8') as stream:
        parser.feed(stream.read())
    require(len(parser.blocks) == 1, 'Expected exactly one authoritative ' + STATE_ID + ' block')
    require(not any(c in parser.blocks[0] for c in '<>&'), 'Escape <, > and & in embedded JSON')
    return json.loads(parser.blocks[0], object_pairs_hook=unique_keys, parse_constant=reject_constant)


def validate_report(path: str | Path):
    state = load_report_state(path)
    validate_state(state)
    if state.get('schema_version') == '1.2':
        print('PASS: Scan 1.2 structure, typed references, artifact/check coverage, reuse and control evidence; semantic/visual review still required')
    return state


def validate_json(path: str | Path):
    with open(path, encoding='utf-8') as stream:
        state = json.load(stream, object_pairs_hook=unique_keys, parse_constant=reject_constant)
    validate_state(state)
    return state


def validate_path(path: str | Path):
    candidate = Path(path)
    if candidate.suffix.lower() == '.json':
        return validate_json(candidate)
    return validate_report(candidate)


# Historical API used by scripts/test_validate_report.py and external callers.
validate = validate_report
