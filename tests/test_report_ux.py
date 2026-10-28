"""Reading-order, disclosure and receipt integrity regressions (stdlib only)."""
from copy import deepcopy
from html.parser import HTMLParser
from pathlib import Path
import re
import tempfile
import unittest

from scan_core import ScanConfig, SemanticStateBuilder, render_html, render_report, scan_project
from scan_core.validate import load_report_state, validate_report
from scan_core.compare import compare_states
from scan_core.state import state_digest

ROOT = Path(__file__).resolve().parents[1]


class Document(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.ids, self.hrefs, self.tags, self.headings = [], [], [], []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append((tag, attrs))
        if 'id' in attrs:
            self.ids.append(attrs['id'])
        if tag == 'a' and attrs.get('href', '').startswith('#'):
            self.hrefs.append(attrs['href'][1:])
        if re.fullmatch('h[1-6]', tag):
            self.headings.append(int(tag[1]))


def rich_state():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / 'app.txt').write_text('fixture\n', encoding='utf-8')
        state = scan_project(ScanConfig(root=root, baseline_mode='none')).state
    b = SemanticStateBuilder(state)
    a = state['artifacts'][0]
    evidence = b.add_evidence(record_id='e:long-id-' + 'x' * 160, artifact_id=a['id'], locator=a['locator'], kind='static',
        claim='Fixture proof', result='Inspected a bounded fixture', method='Static review', limitations='Runtime not observed',
        source_digest=a['content_identity'], producer_kind='human', producer_name='test-reviewer', producer_version='1')
    ids = [b.add_component(name=f'Component {i}', purpose=f'Purpose {i}', boundaries=f'Boundary {i}',
                           artifact_ids=[a['id']], evidence_ids=[evidence]) for i in range(12)]
    for i in range(11):
        b.add_relationship(from_id=ids[i], to_id=ids[i + 1], kind=f'relation-{i}', explanation=f'Explanation {i}',
                           evidence_ids=[evidence], confidence='high', verification_state='static')
    # Artifact endpoints are canonical too; they must not disappear when there are no components.
    b.add_relationship(from_id=a['id'], to_id=ids[0], kind='artifact-input', explanation='Artifact endpoint',
                       evidence_ids=[evidence], confidence='medium', verification_state='inferred')
    for i in range(9):
        b.add_finding(record_id=f'finding:{i}', title=f'Finding title {i}', impact=f'Visible impact {i}',
            severity='high' if i == 7 else 'low', confidence='high', verification_state='static',
            artifact_ids=[a['id']], evidence_ids=[evidence], uncertainty=f'Limit {i}',
            recommendation=f'Recommendation {i}', safe_verification=f'Verification {i}')
    for i in range(6):
        b.add_unknown(question=f'Unknown question {i}', reason=f'Reason {i}', impact=f'Unknown impact {i}',
                      next_safe_step=f'Unknown step {i}', evidence_ids=[evidence])
    return b.build()


class ReportUXTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = rich_state()
        cls.html = render_html(cls.state)
        cls.doc = Document(cls.html)

    def test_reading_order_and_navigation(self):
        anchors = ('verdict', 'findings', 'changes', 'coverage', 'architecture', 'actions', 'audit')
        self.assertEqual([self.doc.ids.index(a) for a in anchors], sorted(self.doc.ids.index(a) for a in anchors))
        for a in anchors:
            self.assertIn(a, self.doc.hrefs)

    def test_one_h1_and_no_heading_level_jumps(self):
        self.assertEqual(self.doc.headings.count(1), 1)
        for previous, current in zip(self.doc.headings, self.doc.headings[1:]):
            self.assertLessEqual(current, previous + 1)

    def test_all_fragment_links_resolve_and_ids_are_unique(self):
        self.assertEqual(len(self.doc.ids), len(set(self.doc.ids)))
        self.assertFalse(set(self.doc.hrefs) - set(self.doc.ids))

    def test_no_primary_tables_or_raw_json(self):
        primary = self.html.split('<section class="section" id="audit"')[0].split('</style>')[1]
        self.assertNotIn('<table', primary)
        self.assertNotIn('<pre', primary)

    def test_primary_findings_show_impact_and_recommendation_before_disclosure(self):
        primary = self.html.split('id="findings"')[1].split('id="changes"')[0]
        self.assertEqual(primary.count('data-priority-finding="true"'), 5)
        self.assertLess(primary.index('Finding title 7'), primary.index('Finding title 0'))
        first = primary.split('<article', 1)[1].split('<details', 1)[0]
        self.assertIn('Visible impact 7', first)
        self.assertIn('Recommendation 7', first)
        self.assertIn('static evidence', first)

    def test_every_finding_keeps_full_proof_in_appendix(self):
        appendix = self.html.split('id="all-findings"')[1]
        for row in self.state['findings']:
            for key in ('id', 'title', 'impact', 'recommendation', 'safe_verification', 'uncertainty'):
                self.assertIn(row[key], appendix)

    def test_relationships_are_not_truncated(self):
        architecture = self.html.split('id="architecture"')[1].split('id="actions"')[0]
        for row in self.state['relationships']:
            self.assertIn(row['id'], architecture)
            self.assertIn(row['kind'], architecture)
            self.assertIn(row['explanation'], architecture)
            self.assertIn(row['verification_state'], architecture)
        self.assertIn('app.txt', architecture)
        for row in self.state['components']:
            self.assertIn(row['name'], architecture)

    def test_artifact_only_relationships_still_render(self):
        state = deepcopy(self.state)
        a = state['artifacts'][0]['id']
        state['components'] = []
        state['relationships'] = [dict(state['relationships'][0], from_id=a, to_id=a)]
        html = render_html(state)
        architecture = html.split('id="architecture"')[1].split('id="actions"')[0]
        self.assertIn('Explanation 0', architecture)
        self.assertIn('app.txt', architecture)

    def test_first_scan_zeros_are_disclosed_not_promoted(self):
        changes = self.html.split('id="changes"')[1].split('id="coverage"')[0]
        self.assertIn('No comparison baseline available.', changes)
        self.assertLess(changes.index('<details'), changes.index('delta_artifacts_added'))
        self.assertNotIn('Review-changing evidence', changes)
        self.assertIn('Evidence freshness', changes)
        self.assertIn('Git change scope (advisory)', changes)

    def test_repeat_scan_keeps_modified_and_resolved_semantics_separate_from_freshness(self):
        previous = self.state
        current = deepcopy(previous)
        current['findings'] = current['findings'][1:]
        current['findings'][0]['impact'] = 'Changed impact with the same finding ID'
        current['findings'].append(dict(current['findings'][-1], id='finding:new', title='New finding'))
        comparison = compare_states(previous, current)
        current['baseline'].update(mode='explicit', status='used', source_schema_version='1.4',
            source_state_digest=state_digest(previous), source_snapshot_digest=previous['provenance']['snapshot_digest'],
            snapshot_relation='same')
        current['delta'] = {'available': True, **{group: {key: list(ids) for key, ids in getattr(comparison, group).items()}
                                               for group in ('artifacts', 'findings', 'unknowns')}}
        changes = render_html(current).split('id="changes"')[1].split('id="coverage"')[0]
        self.assertIn('delta_findings_new">1</b>', changes)
        self.assertIn('delta_findings_resolved">1</b>', changes)
        self.assertIn('Modified findings: 1.', changes)
        self.assertIn('does not mean fixed or verified', changes)
        self.assertLess(changes.index('Scan baseline delta'), changes.index('Evidence freshness'))

    def test_zero_findings_retains_unknown_warning(self):
        state = deepcopy(self.state)
        state['findings'] = []
        html = render_html(state)
        hero = html.split('</header>')[0]
        self.assertIn('7 unanswered question(s)', hero)
        self.assertIn('not a clean bill of health', html)
        self.assertNotIn('All clear', hero)

    def test_large_receipts_use_native_closed_disclosures(self):
        for ident in ('checks-title', 'all-findings', 'artifact-inventory', 'evidence-ledger', 'technical-observations'):
            tag, attrs = next((t, a) for t, a in self.doc.tags if a.get('id') == ident)
            self.assertEqual(tag, 'details')
            self.assertNotIn('open', attrs)
        self.assertIn('more-relationships', self.doc.ids)
        self.assertIn('more-unknowns', self.doc.ids)

    def test_tables_are_labeled_focusable_audit_regions_with_scopes(self):
        for tag, attrs in self.doc.tags:
            if tag == 'th':
                self.assertEqual(attrs.get('scope'), 'col')
            if attrs.get('class') == 'table-scroll':
                self.assertEqual(attrs.get('tabindex'), '0')
                self.assertEqual(attrs.get('role'), 'region')
                self.assertTrue(attrs.get('aria-label'))

    def test_exact_state_and_count_contract_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / 'report.html'
            render_report(self.state, report)
            self.assertEqual(validate_report(report), self.state)
            self.assertEqual(load_report_state(report), self.state)

    def test_evidence_receipts_include_observation_time_claim_and_method(self):
        ledger = self.html.split('id="evidence-ledger"')[1].split('id="strengths-title"')[0]
        for evidence in self.state['evidence']:
            self.assertIn(evidence['time'], ledger)
            self.assertIn(evidence['claim'], ledger)
            self.assertIn(evidence['method'], ledger)

    def test_render_is_deterministic_and_does_not_modify_input(self):
        original = deepcopy(self.state)
        self.assertEqual(render_html(self.state), self.html)
        self.assertEqual(self.state, original)

    def test_shells_synchronized_and_no_css_patch_layers(self):
        shell = (ROOT / 'assets/report-shell.html').read_bytes()
        self.assertEqual(shell, (ROOT / 'src/scan_core/report/shell.html').read_bytes())
        self.assertEqual(shell.count(b'<style>'), 1)
        self.assertNotIn(b'backdrop-filter', shell)
        self.assertNotIn(b'linear-gradient', shell)
        self.assertNotIn(b'live-dot', shell)

    def test_coverage_has_no_progress_decoration(self):
        coverage = self.html.split('id="coverage"')[1].split('id="architecture"')[0]
        self.assertNotIn('%', coverage)
        self.assertNotIn('progressbar', coverage)
        self.assertIn('fresh analyzed', coverage)
        self.assertIn('reused analyzed', coverage)

    def test_target_template_syntax_is_not_recursively_substituted(self):
        state = deepcopy(self.state)
        state['project']['name'] = '{{VERDICT}} <script>alert(1)</script>'
        html = render_html(state)
        self.assertIn('{{VERDICT}} &lt;script&gt;', html)
        self.assertEqual(html.count('<script'), 1)

    def test_print_expands_details_and_hides_navigation(self):
        self.assertIn('details::details-content', self.html)
        self.assertIn('content-visibility:visible!important', self.html)
        self.assertIn('.report-nav,.skip-link{display:none}', self.html)
        self.assertIn('@media(prefers-reduced-motion:reduce)', self.html)


if __name__ == '__main__':
    unittest.main()
