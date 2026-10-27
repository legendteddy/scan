#!/usr/bin/env python3
"""Regression cases for report promises that failed in real use. Synthetic data only."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest

from validate_report import CHECK_CATEGORIES, validate, validate_state


def specimen():
    return {
        'schema_version': '1.2',
        'project': {'name': 'Example', 'purpose': 'Export surveys', 'target_types': ['source'],
                    'source_locators': ['fixture'], 'snapshot': {'identity': 'fixture-v1', 'time': '2026-10-26T00:00:00Z'},
                    'scope': 'One source file', 'exclusions': [], 'critical_artifact_ids': ['a1']},
        'summary': {'overview': 'Small export tool', 'operation': 'Writes CSV', 'condition': 'Statically inspected',
                    'strengths': [], 'priorities': ['Verify runtime'], 'readiness': 'not established',
                    'evidence_ids': ['e1'], 'limitations': 'No runtime observation'},
        'coverage': {'discovery_complete': True, 'analysis_complete': True, 'discovered_artifact_count': 1,
                     'counts_by_status': {'analyzed': 1}, 'checks_complete': False,
                     'counts_by_check_status': {'not_assessed': len(CHECK_CATEGORIES)}, 'limits': ['No execution'], 'sampling': 'None',
                     'methods': ['Static read'], 'checks_performed': ['Read file'], 'checks_not_performed': ['Runtime'],
                     'snapshot_consistency': 'Fixed fixture', 'sensitive_omissions': []},
        'artifacts': [{'id': 'a1', 'locator': 'export.py', 'type': 'Python', 'status': 'analyzed',
                       'reason': 'Read function', 'evidence_ids': ['e1'], 'inspection_origin': 'fresh',
                       'inspected_at': '2026-10-26T00:00:00Z', 'content_identity': 'fixture-v1'}],
        'components': [{'id': 'c1', 'name': 'Exporter', 'purpose': 'Write CSV', 'artifact_ids': ['a1'],
                        'evidence_ids': ['e1'], 'boundaries': 'Caller supplies stream'}],
        'relationships': [{'id': 'r1', 'from_id': 'a1', 'to_id': 'c1', 'kind': 'implements',
                           'explanation': 'Function implements exporter', 'evidence_ids': ['e1'],
                           'confidence': 'high', 'verification_state': 'static'}],
        'evidence': [{'id': 'e1', 'artifact_id': 'a1', 'locator': 'export.py:function', 'kind': 'static',
                      'claim': 'Function writes CSV', 'result': 'Uses CSV writer', 'method': 'Static read',
                      'time': '2026-10-26T00:00:00Z', 'limitations': 'Not executed', 'inspection_origin': 'fresh'}],
        'checks': [{'id': 'check-' + category, 'category': category,
                    'title': category.replace('_', ' '), 'status': 'not_assessed',
                    'scope': 'Synthetic one-file validator fixture',
                    'method': 'No category assessment performed by this fixture',
                    'artifact_ids': ['a1'], 'evidence_ids': [], 'related_ids': [],
                    'verification_state': 'unverified',
                    'result': 'No assessment result available',
                    'limitations': 'Fixture exercises the schema rather than project conclusions',
                    'reason': 'Only structural test records supplied',
                    'next_step': 'Perform this assessment on an actual target'}
                   for category in CHECK_CATEGORIES],
        'findings': [],
        'controls': [{'id': 'ctl1', 'description': 'CSV serializer present', 'artifact_ids': ['a1'],
                      'evidence_ids': ['e1'], 'effectiveness_status': 'implemented_unverified',
                      'limitations': 'Behavior not observed'}],
        'unknowns': [], 'actions': [],
        'continuation': {'completed': ['Static review'], 'remaining': ['Runtime verification'], 'hypotheses': [],
                         'decisions': [], 'revalidation': ['Check source identity'], 'source_needs': ['Source bytes'],
                         'authorization_note': 'Suggestions do not authorize execution'},
        'extensions': {},
    }


class ContractTests(unittest.TestCase):
    def test_valid_static_report(self):
        validate_state(specimen())

    def test_rejects_inventory_count_without_members(self):
        s = specimen(); s['coverage']['discovered_artifact_count'] = 128
        with self.assertRaisesRegex(ValueError, 'inventory'): validate_state(s)

    def test_rejects_metadata_review_claimed_complete(self):
        s = specimen(); s['artifacts'][0]['status'] = 'metadata_only'
        s['coverage']['counts_by_status'] = {'metadata_only': 1}
        with self.assertRaisesRegex(ValueError, 'Complete analysis'): validate_state(s)

    def test_rejects_wrong_status_counts(self):
        s = specimen(); s['coverage']['counts_by_status'] = {'analyzed': 2}
        with self.assertRaisesRegex(ValueError, 'status counts'): validate_state(s)

    def test_rejects_missing_relationship_evidence(self):
        s = specimen(); s['relationships'][0]['evidence_ids'] = []
        with self.assertRaisesRegex(ValueError, 'evidence_ids'): validate_state(s)

    def test_rejects_wrong_reference_type(self):
        s = specimen(); s['relationships'][0]['evidence_ids'] = ['a1']
        with self.assertRaisesRegex(ValueError, 'wrong-type'): validate_state(s)

    def test_rejects_static_control_claimed_effective(self):
        s = specimen(); s['controls'][0]['effectiveness_status'] = 'observed_effective'
        with self.assertRaisesRegex(ValueError, 'observed evidence'): validate_state(s)

    def test_rejects_reuse_without_original_inspection(self):
        s = specimen(); s['evidence'][0]['inspection_origin'] = 'verified_reuse'
        with self.assertRaisesRegex(ValueError, 'reuse needs provenance'): validate_state(s)

    def test_accepts_documented_reuse(self):
        s = specimen(); e = s['evidence'][0]; e['inspection_origin'] = 'verified_reuse'
        s['artifacts'][0]['inspection_origin'] = 'verified_reuse'
        e['reuse'] = {'prior_scan_id': 'old-scan', 'prior_inspected_at': e['time'], 'prior_method': e['method'],
                      'prior_depth': 'analyzed', 'prior_limits': ['No execution'],
                      'identity_check': 'Matched fixture identity', 'identity_match': True}
        validate_state(s)

    def test_rejects_analyzed_artifact_without_own_evidence(self):
        s = specimen(); s['artifacts'][0]['evidence_ids'] = []
        with self.assertRaisesRegex(ValueError, 'direct substantive evidence'): validate_state(s)

    def test_rejects_unread_critical_without_unknown(self):
        s = specimen(); s['artifacts'][0]['status'] = 'metadata_only'
        s['coverage']['counts_by_status'] = {'metadata_only': 1}; s['coverage']['analysis_complete'] = False
        with self.assertRaisesRegex(ValueError, 'explicit unknown'): validate_state(s)

    def test_rejects_missing_required_records(self):
        s = specimen(); del s['continuation']['source_needs']
        with self.assertRaisesRegex(ValueError, 'missing source_needs'): validate_state(s)

    def test_rejects_duplicate_ids(self):
        s = specimen(); s['artifacts'].append(copy.deepcopy(s['artifacts'][0]))
        with self.assertRaisesRegex(ValueError, 'Duplicate ID'): validate_state(s)

    def test_rejects_legacy_schema(self):
        s = specimen(); s['schema_version'] = '5.0'
        with self.assertRaisesRegex(ValueError, '1.2'): validate_state(s)


    def test_rejects_missing_check_category(self):
        s = specimen(); s['checks'].pop()
        with self.assertRaisesRegex(ValueError, 'Missing required check categories'): validate_state(s)

    def test_rejects_assessed_check_without_evidence(self):
        s = specimen(); s['checks'][0]['status'] = 'assessed'
        with self.assertRaisesRegex(ValueError, 'needs evidence'): validate_state(s)

    def test_rejects_unfinished_check_without_next_step(self):
        s = specimen(); s['checks'][0]['next_step'] = None
        with self.assertRaisesRegex(ValueError, 'unfinished check'): validate_state(s)

    def test_rejects_check_false_completion(self):
        s = specimen(); s['coverage']['checks_complete'] = True
        with self.assertRaisesRegex(ValueError, 'unfinished check assessments'): validate_state(s)

    def test_rejects_wrong_check_counts(self):
        s = specimen(); s['coverage']['counts_by_check_status']['not_assessed'] -= 1
        with self.assertRaisesRegex(ValueError, 'Check status counts'): validate_state(s)

    def test_rejects_observed_check_with_only_static_evidence(self):
        s = specimen(); c = s['checks'][0]
        c.update(status='assessed', evidence_ids=['e1'], verification_state='observed')
        with self.assertRaisesRegex(ValueError, 'observed check needs observed evidence'): validate_state(s)

    def test_rejects_wrong_check_evidence_reference_type(self):
        s = specimen(); s['checks'][0]['evidence_ids'] = ['a1']
        with self.assertRaisesRegex(ValueError, 'wrong-type evidence_ids'): validate_state(s)

    def test_accepts_completed_static_check_and_additional_category(self):
        s = specimen(); c = s['checks'][0]
        c.update(status='assessed', evidence_ids=['e1'], verification_state='static', next_step=None)
        s['checks'].append(dict(c, id='check-export-specific', category='export_field_policy'))
        s['coverage']['counts_by_check_status'] = {'not_assessed': len(CHECK_CATEGORIES)-1, 'assessed': 2}
        validate_state(s)

    def test_accepts_justified_not_applicable_check(self):
        s = specimen(); c = next(c for c in s['checks'] if c['category'] == 'usability_and_accessibility')
        c.update(status='not_applicable', reason='This synthetic package has no interactive display surface', next_step=None)
        s['coverage']['counts_by_check_status'] = {'not_assessed': len(CHECK_CATEGORIES)-1, 'not_applicable': 1}
        validate_state(s)

    def test_rejects_check_pass_as_coverage_status(self):
        s = specimen(); s['checks'][0]['status'] = 'passed'
        with self.assertRaisesRegex(ValueError, 'invalid check status'): validate_state(s)

    def test_rejects_not_applicable_without_reason(self):
        s = specimen(); s['checks'][0].update(status='not_applicable', reason='')
        with self.assertRaisesRegex(ValueError, 'reason must be a nonempty string'): validate_state(s)

    def test_accepts_completed_declared_check_plan(self):
        s = specimen()
        for c in s['checks']:
            c.update(status='assessed', evidence_ids=['e1'], verification_state='static', next_step=None)
        s['coverage']['checks_complete'] = True
        s['coverage']['counts_by_check_status'] = {'assessed': len(CHECK_CATEGORIES)}
        validate_state(s)

    def test_artifact_complete_does_not_require_runtime_checks_complete(self):
        s = specimen()
        self.assertTrue(s['coverage']['analysis_complete'])
        self.assertFalse(s['coverage']['checks_complete'])
        validate_state(s)

    def test_html_embedding(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'report.html'
            data = json.dumps(specimen()).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
            block = '<script type="application/json" id="project-anatomy-state">' + data + '</script>'
            p.write_text(block, encoding='utf-8')
            with contextlib.redirect_stdout(io.StringIO()): validate(p)
            p.write_text(block + block, encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'exactly one'): validate(p)
            p.write_text(block.replace('project-anatomy-state', 'scan-machine-state'), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'exactly one'): validate(p)
            p.write_text(block.replace('"schema_version": "1.2"', '"schema_version": "1.2", "schema_version": "1.2"'), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'Duplicate JSON key'): validate(p)
            p.write_text(block.replace('Small export tool', '</script><script>unsafe()</script>'), encoding='utf-8')
            with self.assertRaises(ValueError): validate(p)


if __name__ == '__main__':
    unittest.main()
