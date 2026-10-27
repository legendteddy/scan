"""Version-dispatched structural validation for Scan state and reports.

Validation never executes report or target content and is not a factual/security audit.
The Scan 1.2 rules in this module are intentionally preserved from the launch validator.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
import re
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


SHA256_RE = re.compile(r'^sha256:[0-9a-f]{64}$')
PATH_KINDS = {'file', 'directory', 'symlink', 'archive_member', 'special', 'unknown'}
REDACTION_STATES = {'none', 'metadata_only', 'content_redacted', 'path_redacted', 'fully_omitted'}
PRODUCER_KINDS = {'scan-core', 'external-tool', 'local-model', 'remote-model', 'human'}


def _rfc3339(value, label):
    require(string(value), label + ' must be a timestamp string')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as error:
        raise ValidationError(label + ' must be RFC3339-compatible') from error
    require(parsed.tzinfo is not None, label + ' must include a timezone')
    return parsed


def _sha256(value, label):
    require(isinstance(value, str) and SHA256_RE.fullmatch(value) is not None,
            label + ' must be sha256:<64 lowercase hex>')


def _validate_state_1_3(state):
    require(isinstance(state, dict), 'State must be an object')
    require(state.get('schema_version') == '1.3', 'Expected Scan schema_version 1.3')

    # Reuse the frozen 1.2 structural/reference/coverage semantics without
    # weakening or silently rewriting any 1.2 report.
    compatibility = dict(state)
    compatibility['schema_version'] = '1.2'
    _validate_state_1_2(compatibility)

    run = state.get('run')
    require(isinstance(run, dict), 'run must be an object')
    for key in ('scan_id', 'scan_version', 'started_at', 'completed_at', 'mode',
                'target_executed', 'network_used'):
        require(key in run, 'run: missing ' + key)
    require(string(run['scan_id']) and run['scan_id'].startswith('scan:'),
            'run.scan_id must be a scan: identifier')
    require(string(run['scan_version']), 'run.scan_version must be a nonempty string')
    started_at = _rfc3339(run['started_at'], 'run.started_at')
    completed_at = _rfc3339(run['completed_at'], 'run.completed_at')
    require(completed_at >= started_at, 'run.completed_at cannot precede run.started_at')
    require(run['mode'] == 'static', 'v0.2 core state run.mode must be static')
    require(run['target_executed'] is False, 'v0.2 core-generated state cannot claim target execution')
    require(type(run['network_used']) is bool, 'run.network_used must be boolean')

    privacy = state.get('privacy')
    require(isinstance(privacy, dict), 'privacy must be an object')
    for key in ('mode', 'redaction_level', 'redaction_count', 'sensitive_path_count',
                'egress_performed', 'egress_bytes'):
        require(key in privacy, 'privacy: missing ' + key)
    require(privacy['mode'] in {'offline', 'local', 'controlled-remote'}, 'Invalid privacy.mode')
    require(privacy['redaction_level'] in {'none', 'standard', 'strict'}, 'Invalid privacy.redaction_level')
    for key in ('redaction_count', 'sensitive_path_count', 'egress_bytes'):
        require(type(privacy[key]) is int and privacy[key] >= 0, 'privacy.' + key + ' must be a non-negative integer')
    require(privacy['egress_performed'] is False, 'v0.2 core-generated state cannot record performed egress')
    if privacy['mode'] == 'offline':
        require(run['network_used'] is False, 'offline privacy mode requires run.network_used=false')
    require(run['network_used'] is False, 'v0.2 deterministic core must not use network access')

    provenance = state.get('provenance')
    require(isinstance(provenance, dict), 'provenance must be an object')
    for key in ('root_identity', 'snapshot_digest', 'state_digest_algorithm',
                'tool_versions', 'configuration_digest'):
        require(key in provenance, 'provenance: missing ' + key)
    require(string(provenance['root_identity']), 'provenance.root_identity must be nonempty')
    _sha256(provenance['snapshot_digest'], 'provenance.snapshot_digest')
    _sha256(provenance['configuration_digest'], 'provenance.configuration_digest')
    require(provenance['state_digest_algorithm'] == 'sha256', 'state_digest_algorithm must be sha256')
    require(isinstance(provenance['tool_versions'], list), 'provenance.tool_versions must be an array')
    for index, tool in enumerate(provenance['tool_versions']):
        label = f'provenance.tool_versions[{index}]'
        require(isinstance(tool, dict), label + ' must be an object')
        for key in ('kind', 'name', 'version'):
            require(string(tool.get(key)), label + '.' + key + ' must be nonempty')
    require(state['project']['snapshot'].get('identity') == provenance['snapshot_digest'],
            'project.snapshot identity must equal provenance.snapshot_digest')

    redacted_count = 0
    unreadable_count = 0
    for artifact in state['artifacts']:
        label = artifact['id'] + ': '
        for key in ('size_bytes', 'media_type', 'path_kind', 'redaction_state'):
            require(key in artifact, label + 'missing ' + key)
        require(type(artifact['size_bytes']) is int and artifact['size_bytes'] >= 0,
                label + 'size_bytes must be a non-negative integer')
        require(string(artifact['media_type']), label + 'media_type must be nonempty')
        require(artifact['path_kind'] in PATH_KINDS, label + 'invalid path_kind')
        require(artifact['redaction_state'] in REDACTION_STATES, label + 'invalid redaction_state')
        if artifact['redaction_state'] != 'none':
            redacted_count += 1
        if artifact['status'] == 'unreadable':
            unreadable_count += 1

    for evidence in state['evidence']:
        label = evidence['id'] + ': '
        require(isinstance(evidence.get('producer'), dict), label + 'producer must be an object')
        producer = evidence['producer']
        for key in ('kind', 'name', 'version'):
            require(string(producer.get(key)), label + 'producer.' + key + ' must be nonempty')
        require(producer['kind'] in PRODUCER_KINDS, label + 'invalid producer.kind')
        _sha256(evidence.get('source_digest'), label + 'source_digest')

    coverage = state['coverage']
    for key in ('resource_limits_hit', 'unreadable_artifact_count', 'redacted_artifact_count'):
        require(key in coverage, 'coverage: missing ' + key)
    require(isinstance(coverage['resource_limits_hit'], list) and
            all(string(v) for v in coverage['resource_limits_hit']),
            'coverage.resource_limits_hit must be a string array')
    require(type(coverage['unreadable_artifact_count']) is int and
            coverage['unreadable_artifact_count'] == unreadable_count,
            'coverage.unreadable_artifact_count does not match artifacts')
    require(type(coverage['redacted_artifact_count']) is int and
            coverage['redacted_artifact_count'] == redacted_count,
            'coverage.redacted_artifact_count does not match artifacts')
    require(privacy['redaction_count'] >= redacted_count,
            'privacy.redaction_count cannot be lower than redacted artifact count')
    if coverage['resource_limits_hit']:
        require(coverage['analysis_complete'] is False,
                'resource limits prevent complete analysis')
    return state


SUPPORTED_SCHEMAS = ('1.2', '1.3')
PLANNED_SCHEMAS = ()


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
        return _validate_state_1_3(state)
    raise UnsupportedSchemaError(
        f'Unsupported Scan schema_version {declared!r}; supported: 1.2, 1.3')


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
