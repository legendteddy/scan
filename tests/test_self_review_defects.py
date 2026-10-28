"""Independent reproductions of the v0.3.1 self-review defects."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

from scan_core import (
    BuilderError, ScanConfig, SemanticCheckDefinition, SemanticRegistration,
    SemanticStateBuilder, canonical_state_json, render_html, scan_project,
    state_digest, validate_report, validate_state,
)
from scan_core.auxiliary import AuxiliaryReadError, read_auxiliary
from scan_core.cli import main
from scan_core.errors import CommandError, UnsafeReportError, ValidationError
from scan_core.git_provenance import inspect_git_provenance
from scan_core.inventory import build_inventory
from scan_core.render import _coverage_rows
from scan_core.reuse import check_definition_digest
from scan_core.scanbench import _create_windows_junction
from scan_core.settings import load_project_settings
from scan_core.validate import CHECK_CATEGORIES

ROOT = Path(__file__).resolve().parents[1]
COMMIT = 'a' * 40


def git_metadata(root: Path) -> Path:
    git = root / '.git'
    (git / 'refs/heads').mkdir(parents=True)
    (git / 'HEAD').write_text('ref: refs/heads/main\n', encoding='utf-8')
    (git / 'refs/heads/main').write_text(COMMIT + '\n', encoding='utf-8')
    (git / 'config').write_text('[remote "origin"]\nurl = https://example.test/project\n', encoding='utf-8')
    return git


class MetadataBoundaryTests(unittest.TestCase):
    def test_parent_and_absolute_head_traversal_never_open_outside(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'project'
            git = git_metadata(root)
            outside = Path(directory) / 'outside-ref'
            outside.write_text(COMMIT, encoding='utf-8')
            for ref in ('../../outside-ref', str(outside), '/outside-ref', r'C:\outside-ref', r'\\server\share\ref', 'refs/../../outside-ref'):
                with self.subTest(ref=ref):
                    (git / 'HEAD').write_text('ref: ' + ref, encoding='utf-8')
                    real_open = os.open
                    opened = []
                    def observed_open(path, *args, **kwargs):
                        opened.append(Path(path).resolve())
                        return real_open(path, *args, **kwargs)
                    with patch('os.open', side_effect=observed_open):
                        result = inspect_git_provenance(root)
                    self.assertIsNone(result.commit)
                    self.assertIsNone(result.head)
                    self.assertNotIn(outside.resolve(), opened)
                    self.assertIn('Unsafe Git HEAD reference rejected', result.limitations)

    def test_common_reader_rejects_cross_platform_absolute_and_parent_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for value in ('../outside', '/outside', r'C:\outside', r'C:outside', r'\\host\share', 'file:stream'):
                with self.subTest(value=value), self.assertRaises(AuxiliaryReadError):
                    read_auxiliary(root, value, max_bytes=32)

    def test_normal_repository_and_metadata_byte_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git = git_metadata(root)
            result = inspect_git_provenance(root)
            self.assertEqual(result.commit, COMMIT)
            self.assertEqual(result.branch, 'main')
            self.assertEqual(len(result.remotes), 1)
            for name, size in (('refs/heads/main', 4097), ('config', 1_000_001), ('HEAD', 4097), ('packed-refs', 2_000_001)):
                path = git / name
                original = path.read_bytes() if path.exists() else None
                path.write_bytes(b'x' * size)
                with self.subTest(name=name):
                    result = inspect_git_provenance(root)
                    if name == 'config':
                        self.assertEqual(result.remotes, ())
                    elif name != 'packed-refs':
                        self.assertIsNone(result.commit)
                    else:
                        (git / 'refs/heads/main').unlink()
                        self.assertIsNone(inspect_git_provenance(root).commit)
                if original is not None:
                    path.write_bytes(original)

    def test_config_is_bounded_and_normal_config_still_loads(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.scan').mkdir()
            path = root / '.scan/config.toml'
            path.write_text('[scan]\nmode = "quick"\n', encoding='utf-8')
            self.assertEqual(load_project_settings(root).scan_mode, 'quick')
            path.write_bytes(b'#' * 64_001)
            with self.assertRaisesRegex(CommandError, 'byte limit'):
                load_project_settings(root)

    def test_live_metadata_growth_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'metadata'
            path.write_bytes(b'ok')
            real_fstat = os.fstat
            def grow_after_stat(descriptor):
                original = real_fstat(descriptor)
                path.write_bytes(b'x' * 100_000)
                return original
            with patch('os.fstat', side_effect=grow_after_stat):
                with self.assertRaisesRegex(AuxiliaryReadError, 'byte limit'):
                    read_auxiliary(root, 'metadata', max_bytes=32)

    def test_whitespace_head_and_ref_are_unavailable_not_crashes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git = git_metadata(root)
            (git / 'refs/heads/main').write_text(' \n', encoding='utf-8')
            self.assertIsNone(inspect_git_provenance(root).commit)
            (git / 'HEAD').write_text(' \n', encoding='utf-8')
            self.assertIsNone(inspect_git_provenance(root).head)

    def test_worktree_indirection_requires_exact_external_grants(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            repo = base / 'repo'
            common = git_metadata(repo)
            root = base / 'worktree'
            root.mkdir()
            metadata = common / 'worktrees/review'
            metadata.mkdir(parents=True)
            (metadata / 'HEAD').write_text('ref: refs/heads/main', encoding='utf-8')
            (metadata / 'commondir').write_text('../..', encoding='utf-8')
            (root / '.git').write_text('gitdir: ../repo/.git/worktrees/review', encoding='utf-8')
            self.assertIsNone(inspect_git_provenance(root).commit)
            self.assertIsNone(inspect_git_provenance(root, metadata_roots=(base,)).commit)
            self.assertIsNone(inspect_git_provenance(root, metadata_roots=(metadata,)).commit)
            result = inspect_git_provenance(root, metadata_roots=(metadata, common))
            self.assertEqual(result.commit, COMMIT)
            self.assertTrue(any('explicitly authorized' in limit for limit in result.limitations))
            state = scan_project(ScanConfig(root=root, git_metadata_roots=(metadata, common))).state
            self.assertEqual(state['provenance']['git']['commit'], COMMIT)
            self.assertFalse(state['run']['target_executed'])
            self.assertFalse(state['run']['network_used'])
            self.assertNotIn(str(base), canonical_state_json(state))

    def test_in_root_git_file_indirection_remains_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git = git_metadata(root)
            git.rename(root / 'metadata')
            (root / '.git').write_text('gitdir: metadata', encoding='utf-8')
            self.assertEqual(inspect_git_provenance(root).commit, COMMIT)

    def test_symlink_ref_and_config_escape_are_explicitly_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / 'project'
            git = git_metadata(root)
            outside = base / 'outside'
            outside.write_text(COMMIT, encoding='utf-8')
            ref = git / 'refs/heads/main'
            ref.unlink()
            try:
                ref.symlink_to(outside)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f'native file symlinks unavailable; Windows junctions exercised separately: {error}')
            self.assertIsNone(inspect_git_provenance(root).commit)
            (root / '.scan').mkdir()
            (root / '.scan/config.toml').symlink_to(outside)
            with self.assertRaisesRegex(CommandError, 'link/reparse'):
                load_project_settings(root)

    @unittest.skipUnless(os.name == 'nt', 'native Windows junction regression')
    def test_windows_junction_ref_config_and_inventory_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / 'project'
            git = git_metadata(root)
            outside = base / 'outside'
            outside.mkdir()
            (outside / 'main').write_text(COMMIT, encoding='utf-8')
            (outside / 'config.toml').write_text('[scan]\nmode="quick"', encoding='utf-8')
            (git / 'refs/heads/main').unlink()
            (git / 'refs/heads').rmdir()
            for link in (git / 'refs/heads', root / '.scan', root / 'escape'):
                _create_windows_junction(link, outside)
            self.assertIsNone(inspect_git_provenance(root).commit)
            with self.assertRaisesRegex(CommandError, 'link/reparse'):
                load_project_settings(root)
            rows = {row.locator: row for row in build_inventory(ScanConfig(root=root, follow_internal_links=True)).artifacts}
            self.assertEqual(rows['escape'].symlink_scope, 'external')
            self.assertNotIn('escape/main', rows)

    @unittest.skipUnless(os.name == 'nt', 'Windows opened-handle junction race regression')
    def test_replaced_parent_junction_is_rejected_before_reading(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / 'metadata'
            parent.mkdir()
            outside = root / 'outside'
            outside.mkdir()
            (parent / 'HEAD').write_text(COMMIT, encoding='utf-8')
            (outside / 'HEAD').write_text('sensitive outside content', encoding='utf-8')
            real_open = os.open
            def replace_parent(path, *args, **kwargs):
                parent.rename(root / 'original-metadata')
                _create_windows_junction(parent, outside)
                return real_open(path, *args, **kwargs)
            with patch('os.open', side_effect=replace_parent), patch('os.fdopen') as reader:
                with self.assertRaisesRegex(AuxiliaryReadError, 'escaped'):
                    read_auxiliary(root, 'metadata/HEAD', max_bytes=4096)
            reader.assert_not_called()


class HtmlSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as directory:
            cls.state = scan_project(ScanConfig(root=Path(directory))).state
        cls.html = render_html(cls.state)

    def test_all_active_and_network_categories_are_rejected(self):
        mutations = {
            'script': '<script>alert(1)</script>',
            'module': '<script type="module">import "https://example.test/x"</script>',
            'extra JSON': '<script type="application/json">{}</script>',
            'state src': '<script type="application/json" src="https://example.test/x"></script>',
            'event': '<p onclick="alert(1)">x</p>',
            'error event': '<img onerror="alert(1)">',
            'mixed event': '<p oNcLiCk="alert(1)">x</p>',
            'javascript': '<a href="javascript:alert(1)">x</a>',
            'encoded scheme': '<a href="jav&#x61;script&#58;alert(1)">x</a>',
            'scheme whitespace': '<a href="java&#10;script:alert(1)">x</a>',
            'vbscript': '<a href="vbscript:msgbox(1)">x</a>',
            'data document': '<a href="data:text/html,hello">x</a>',
            'image resource': '<img src="https://example.test/image">',
            'protocol relative': '<video src="//example.test/movie"></video>',
            'local resource': '<img src="file:///secret">',
            'relative resource': '<img src="outside.png">',
            'srcset': '<img srcset="https://example.test/image 2x">',
            'poster': '<video poster="https://example.test/image"></video>',
            'CSS import': '<style>@import "https://example.test/style";</style>',
            'CSS escaped import': r'<style>@\69mport "https://example.test/style";</style>',
            'CSS url': '<style>p {background:url(//example.test/image)}</style>',
            'inline CSS url': '<p style="background:url(https://example.test/image)">x</p>',
            'CSS escaped url': r'<p style="background:u\72l(//example.test/image)">x</p>',
            'CSS comments': '<style>p {background:u/**/rl(//example.test/image)}</style>',
            'CSS expression': '<p style="width:expression(alert(1))">x</p>',
            'CSS image set': '<style>p {background:image-set("//example.test/image" 1x)}</style>',
            'iframe': '<iframe srcdoc="hello"></iframe>',
            'object': '<object data="https://example.test/x"></object>',
            'embed': '<embed src="https://example.test/x">',
            'form': '<form action="https://example.test/x"><input></form>',
            'base': '<base href="https://example.test/">',
            'refresh': '<meta http-equiv="refresh" content="0; url=https://example.test">',
            'ping': '<a href="#coverage" ping="https://example.test">x</a>',
            'attribution': '<a href="#coverage" attributionsrc="https://example.test">x</a>',
            'svg': '<svg><use href="https://example.test/x"></use></svg>',
            'math': '<math><mtext>x</mtext></math>',
            'duplicate attributes': '<a href="#safe" href="javascript:alert(1)">x</a>',
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.html'
            for label, markup in mutations.items():
                with self.subTest(category=label):
                    path.write_text(self.html.replace('</body>', markup + '</body>'), encoding='utf-8')
                    with self.assertRaisesRegex(UnsafeReportError, 'Unsafe/non-self-contained HTML'):
                        validate_report(path)

    def test_current_historical_and_inert_links_validate_without_network(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.html'
            markup = '<details><summary>Receipts</summary><a href="https://example.test/evidence">External evidence</a><a href="#coverage">Coverage</a></details>'
            path.write_text(self.html.replace('</body>', markup + '</body>'), encoding='utf-8')
            with patch('socket.socket', side_effect=AssertionError('validation must never use network')):
                self.assertEqual(validate_report(path), self.state)
                self.assertEqual(validate_report(ROOT / 'examples/demo-report.html')['schema_version'], '1.2')
                historical = deepcopy(self.state)
                historical['schema_version'] = '1.3'
                path.write_text(render_html(historical), encoding='utf-8')
                self.assertEqual(validate_report(path)['schema_version'], '1.3')

    def test_structural_failure_is_distinct_from_html_safety(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.html'
            path.write_text(self.html.replace('"schema_version":"1.4"', '"schema_version":"9.9"'), encoding='utf-8')
            with self.assertRaises(ValidationError) as caught:
                validate_report(path)
            self.assertNotIsInstance(caught.exception, UnsafeReportError)
            path.write_text(self.html.replace('"schema_version":"1.4"', 'broken JSON'), encoding='utf-8')
            with self.assertRaisesRegex(ValidationError, 'Invalid embedded report state JSON') as caught:
                validate_report(path)
            self.assertNotIsInstance(caught.exception, UnsafeReportError)


def pending_check(category='security_and_trust', title='Trust boundary'):
    return dict(category=category, title=title, status='not_assessed', scope='app.txt', method='static source review',
                artifact_ids=[], evidence_ids=[], verification_state='unverified', result='Not assessed',
                limitations='Runtime unverified', reason='Planned current check', next_step='Review source')


class CheckIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = scan_project(ScanConfig(root=Path(self.temp.name))).state
        self.builder = SemanticStateBuilder(self.state)

    def test_multiple_security_checks_and_updates_keep_stable_identity(self):
        self.builder.add_check(record_id='check:input', **pending_check(title='Inputs'))
        self.builder.add_check(record_id='check:output', **pending_check(title='Outputs'))
        self.builder.update_check('check:input', result='Input review pending')
        built = self.builder.build()
        checks = {row['id']: row for row in built['checks']}
        self.assertEqual(checks['check:input']['result'], 'Input review pending')
        self.assertEqual(checks['check:output']['result'], 'Not assessed')
        self.assertEqual(len([c for c in checks.values() if c['category'] == 'security_and_trust']), 3)
        self.assertIn('check:input', self.builder.category_coverage()['security_and_trust'])
        with self.assertRaisesRegex(BuilderError, 'ambiguous'):
            self.builder.assess_check(**pending_check())

    def test_explicit_assess_id_and_custom_category(self):
        self.builder.assess_check(record_id='check:custom', **pending_check('target_model_format'))
        self.builder.assess_check(record_id='check:custom', **pending_check('target_model_format', 'Updated format'))
        self.assertEqual(next(c for c in self.builder.build()['checks'] if c['id'] == 'check:custom')['title'], 'Updated format')
        with self.assertRaisesRegex(BuilderError, 'duplicate'):
            self.builder.add_check(record_id='check:custom', **pending_check('target_model_format'))
        with self.assertRaisesRegex(BuilderError, 'unknown check ID'):
            self.builder.update_check('check:missing', result='x')

    def test_required_coverage_and_reference_integrity_still_enforced(self):
        self.builder.state['checks'] = [c for c in self.builder.state['checks'] if c['category'] != 'security_and_trust']
        self.builder.add_check(record_id='check:custom', **pending_check('target_specific'))
        self.assertEqual(self.builder.category_coverage()['security_and_trust'], ())
        with self.assertRaisesRegex(BuilderError, 'Missing required check categories'):
            self.builder.build()
        with self.assertRaisesRegex(BuilderError, 'unknown reference'):
            self.builder.add_check(record_id='check:bad', **(pending_check() | {'evidence_ids': ['e:missing']}))

    def test_legacy_single_category_call_updates_original_id(self):
        original = next(c for c in self.state['checks'] if c['category'] == 'maintainability')
        ident = self.builder.assess_check(**pending_check('maintainability'))
        self.assertEqual(ident, original['id'])
        self.assertEqual(len(self.builder.build()['checks']), len(CHECK_CATEGORIES))


class SemanticContinuationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'app.txt').write_text('stable', encoding='utf-8')
        self.state_path = self.root / '.scan/state.json'
        self.config = ScanConfig(root=self.root, output_state=self.state_path)
        first = scan_project(self.config).state
        builder = SemanticStateBuilder(first)
        definition = pending_check('maintainability', 'Review application logic')
        builder.add_check(record_id='check:agent-logic', **definition)
        self.check = SemanticCheckDefinition(id='check:agent-logic', **{key: definition[key] for key in ('category', 'title', 'scope', 'method')})
        self.registration = SemanticRegistration('local-model', 'review-agent', '1', (self.check,))
        artifact = next(a for a in first['artifacts'] if a['locator'] == 'app.txt')
        self.evidence_id = builder.add_evidence(
            record_id='e:agent', artifact_id=artifact['id'], locator='app.txt', kind='static',
            claim='Application source reviewed', result='Bounded static observation', method='static source review',
            limitations='Partial inspection only; runtime unverified', source_digest=artifact['content_identity'],
            producer_kind='local-model', producer_name='review-agent', producer_version='1',
            evidence_class='static_semantic', check_id=self.check.id,
        )
        self.baseline = builder.build()
        self.state_path.write_text(canonical_state_json(self.baseline), encoding='utf-8')
        self.config = replace(self.config, output_state=None, baseline_mode='explicit', baseline_path=self.state_path,
                              excludes=('.scan/**',))

    def repeat(self, registration=None, **config_changes):
        return scan_project(replace(self.config, **config_changes),
                            semantic_registrations=(registration or self.registration,)).state

    def test_real_agent_evidence_reuses_with_current_registration_without_depth_upgrade(self):
        state = self.repeat()
        validate_state(state)
        reused = next(e for e in state['evidence'] if e['id'] == self.evidence_id)
        prior = next(e for e in self.baseline['evidence'] if e['id'] == self.evidence_id)
        for field in ('kind', 'time', 'limitations', 'method', 'source_digest', 'check_definition_digest'):
            self.assertEqual(reused[field], prior[field])
        self.assertEqual(reused['freshness']['status'], 'verified_reuse')
        self.assertEqual(reused['freshness']['source_state_digest'], state_digest(self.baseline))
        self.assertEqual(reused['freshness']['source_evidence_id'], self.evidence_id)
        self.assertEqual(reused['check_definition_digest'], self.check.digest)
        artifact = next(a for a in state['artifacts'] if a['locator'] == 'app.txt')
        self.assertEqual(artifact['status'], 'content_read')
        self.assertNotEqual(artifact['inspection_origin'], 'verified_reuse')
        self.assertEqual(next(c for c in state['checks'] if c['id'] == self.check.id)['status'], 'not_assessed')
        self.assertFalse(state['coverage']['analysis_complete'])
        self.assertEqual(state['baseline']['reused_evidence_count'], 1)

    def test_ordinary_repeat_does_not_trust_baseline_producer(self):
        state = scan_project(self.config).state
        self.assertEqual(state['baseline']['rejected_reuse_reasons'], {'producer_unavailable': 1})

    def test_each_changed_current_identity_rejects_for_specific_reason(self):
        cases = (
            (replace(self.registration, producer_name='different'), 'producer_unavailable'),
            (replace(self.registration, producer_version='2'), 'producer_version_mismatch'),
            (replace(self.registration, checks=(replace(self.check, id='check:different'),)), 'check_identity_mismatch'),
            (replace(self.registration, checks=(replace(self.check, method='different method'),)), 'check_definition_mismatch'),
        )
        for registration, reason in cases:
            with self.subTest(reason=reason):
                self.assertEqual(self.repeat(registration)['baseline']['rejected_reuse_reasons'], {reason: 1})
        (self.root / 'app.txt').write_text('changed', encoding='utf-8')
        self.assertEqual(self.repeat()['baseline']['rejected_reuse_reasons'], {'changed_content': 1})

    def test_current_privacy_runtime_and_disabled_reuse_still_win(self):
        state = self.repeat(sensitive_paths=('app.txt',))
        self.assertEqual(state['baseline']['rejected_reuse_reasons'], {'current_privacy_policy': 1})
        self.assertEqual(self.repeat(reuse_enabled=False)['baseline']['reused_evidence_count'], 0)
        for evidence_class in ('runtime', 'live_service', 'deployment', 'time_sensitive_dependency'):
            with self.subTest(evidence_class=evidence_class):
                baseline = deepcopy(self.baseline)
                next(e for e in baseline['evidence'] if e['id'] == self.evidence_id)['evidence_class'] = evidence_class
                self.state_path.write_text(canonical_state_json(baseline), encoding='utf-8')
                self.assertEqual(self.repeat()['baseline']['rejected_reuse_reasons'], {'runtime_evidence': 1})

    def test_producer_cannot_borrow_another_registration_check(self):
        other = SemanticRegistration('local-model', 'other-agent', '1', (self.check,))
        first = replace(self.registration, checks=(replace(self.check, id='check:another'),))
        state = scan_project(self.config, semantic_registrations=(first, other)).state
        self.assertEqual(state['baseline']['rejected_reuse_reasons'], {'producer_check_unregistered': 1})

    def test_registration_rejects_conflicts_impersonation_and_state_id_collisions(self):
        conflicting = replace(self.registration, checks=(replace(self.check, method='different'),))
        with self.assertRaisesRegex(ValueError, 'Conflicting'):
            scan_project(self.config, semantic_registrations=(self.registration, conflicting))
        builtin = SemanticRegistration('scan-core', 'scan-core', 'different-version', (self.check,))
        with self.assertRaisesRegex(ValueError, 'impersonate'):
            self.repeat(builtin)
        artifact_id = next(a['id'] for a in self.baseline['artifacts'] if a['locator'] == 'app.txt')
        collision = replace(self.registration, checks=(replace(self.check, id=artifact_id),))
        with self.assertRaisesRegex(BuilderError, 'duplicate state ID'):
            self.repeat(collision)

    def test_reused_chain_keeps_original_time_and_immediate_baseline_trace(self):
        second = self.repeat()
        self.state_path.write_text(canonical_state_json(second), encoding='utf-8')
        third = self.repeat()
        old = next(e for e in self.baseline['evidence'] if e['id'] == self.evidence_id)
        reused = next(e for e in third['evidence'] if e['id'] == self.evidence_id)
        self.assertEqual(reused['time'], old['time'])
        self.assertEqual(reused['limitations'], old['limitations'])
        self.assertEqual(reused['freshness']['original_observed_at'], old['time'])
        self.assertEqual(reused['freshness']['source_state_digest'], state_digest(second))

    def test_stricter_current_redaction_applies_to_reused_prose(self):
        baseline = deepcopy(self.baseline)
        next(e for e in baseline['evidence'] if e['id'] == self.evidence_id)['result'] = 'Contact reader@example.test'
        self.state_path.write_text(canonical_state_json(baseline), encoding='utf-8')
        state = self.repeat(redaction_level='strict')
        reused = next(e for e in state['evidence'] if e['id'] == self.evidence_id)
        self.assertNotIn('reader@example.test', reused['result'])
        self.assertEqual(reused['freshness']['status'], 'verified_reuse')


class AuthoringAndCoverageTests(unittest.TestCase):
    def test_current_documentation_and_shells_agree_on_14(self):
        paths = ('SKILL.md', 'references/report-contract.md', 'references/report-design.md',
                 'assets/report-components.html', 'assets/report-shell.html', 'src/scan_core/report/shell.html')
        for relative in paths:
            with self.subTest(path=relative):
                text = (ROOT / relative).read_text(encoding='utf-8')
                self.assertRegex(text, r'Current authoring version: (?:\*\*)?1\.4')
                self.assertIn('Historically accepted validation versions', text)
                self.assertNotRegex(text, r'1\.3 (?:for (?:new|current) reports|for current)')
        self.assertEqual((ROOT / paths[-1]).read_bytes(), (ROOT / paths[-2]).read_bytes())
        contract = (ROOT / paths[1]).read_text(encoding='utf-8')
        self.assertTrue(contract.startswith('# HTML state contract — 1.4\n'))
        self.assertIn('`schema_version`: `1.4` for current reports', contract)
        self.assertIn('currently 1.4 for new reports', (ROOT / paths[2]).read_text(encoding='utf-8'))
        self.assertIn('currently Scan Core schema `1.4`', (ROOT / paths[0]).read_text(encoding='utf-8'))
        for field in ('baseline', 'delta', 'freshness', 'verified_reuse', 'rejected_reuse', 'git_change_scope', 'data-scan-count', 'unknowns'):
            self.assertIn(field, contract)

    def test_readme_fences_and_python_requirement(self):
        text = (ROOT / 'README.md').read_text(encoding='utf-8')
        self.assertNotIn('\\`', text)
        self.assertNotIn('Python 3.9+', text)
        self.assertIn('historical report validator wrapper requires **Python 3.11+**', text)

    def test_coverage_has_no_invented_percentages_and_separates_origins(self):
        state = {'coverage': {'discovery_complete': False, 'analysis_complete': False},
                 'checks': [{'status': 'assessed'}, {'status': 'not_assessed'}, {'status': 'blocked'}],
                 'artifacts': [{'status': status, 'inspection_origin': origin} for status, origin in (
                     ('analyzed', 'fresh'), ('analyzed', 'verified_reuse'), ('content_read', 'fresh'),
                     ('partial', 'fresh'), ('metadata_only', 'fresh'), ('not_inspected', 'fresh'))]}
        html = _coverage_rows(state)
        self.assertNotIn('%', html)
        self.assertNotIn('width:', html)
        self.assertIn('Incomplete', html)
        self.assertIn('6 inventoried', html)
        self.assertIn('1 fresh analyzed', html)
        self.assertIn('1 reused analyzed', html)
        self.assertIn('1 fresh content-read', html)
        self.assertIn('1 metadata-only', html)
        self.assertIn('1 partial', html)
        self.assertIn('1 of 3', html)
