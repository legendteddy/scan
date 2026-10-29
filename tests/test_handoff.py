"""Deterministic bounded inspection handoff tests."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scan_core import ScanConfig, SemanticStateBuilder, scan_project
from scan_core.handoff import build_handoff, canonical_handoff_json
from scan_core.state import state_digest


class InspectionHandoffTests(unittest.TestCase):
    def _state(self, finding_count: int = 3):
        directory = tempfile.TemporaryDirectory()
        root = Path(directory.name)
        secret_source = 'UNIQUE_SOURCE_LITERAL_4d92ef = "private-source-byte"\n'
        (root / 'app.py').write_text(secret_source + 'def work():\n    return 1\n', encoding='utf-8')
        state = scan_project(ScanConfig(root=root, baseline_mode='none', reuse_enabled=False)).state
        artifact = next(row for row in state['artifacts'] if row['locator'] == 'app.py')
        builder = SemanticStateBuilder.from_state(state)
        evidence_id = builder.add_evidence(
            artifact_id=artifact['id'], locator='app.py:2-3', kind='static',
            claim='Static review establishes the work function behavior.',
            result='RAW_EVIDENCE_RESULT_17f31c should never be copied into a handoff.',
            method='static semantic source review',
            limitations='Runtime behavior was not executed.',
            source_digest=artifact['content_identity'], producer_kind='human',
            producer_name='handoff-test', producer_version='1',
        )
        for index in range(finding_count):
            builder.add_finding(
                record_id=f'finding:test:{index:03d}',
                title=f'Finding {index}', impact=f'Impact {index}', severity='high' if index == 0 else 'medium',
                confidence='high', verification_state='static',
                artifact_ids=[artifact['id']], evidence_ids=[evidence_id],
                uncertainty='Static evidence only.', recommendation='Review and fix.',
                safe_verification='Run an authorized regression test.',
            )
        builder.add_unknown(
            record_id='unknown:test', question='Is production runtime behavior safe?',
            reason='No production runtime evidence is present.', impact='Runtime safety remains unverified.',
            next_safe_step='Collect authorized runtime evidence.', artifact_ids=[artifact['id']], evidence_ids=[evidence_id],
        )
        builder.set_summary(
            overview='Evidence-backed static inspection.', condition='One area remains unverified.',
            readiness='conditional', limitations='Runtime verification is absent.', evidence_ids=[evidence_id],
            priorities=['Collect runtime evidence.'], strengths=['Exact artifact identity is available.'],
        )
        builder.set_continuation(
            completed=['Static semantic review completed.'], remaining=['Collect runtime evidence.'],
            hypotheses=['Runtime may differ from static behavior.'], decisions=['Do not claim runtime verification.'],
            revalidation=['Refresh if app.py changes.'], source_needs=['Authorized runtime receipt.'],
            authorization_note='No target execution is authorized by this handoff.',
        )
        self.addCleanup(directory.cleanup)
        return builder.build(analysis_complete=False), secret_source.strip(), evidence_id, artifact['id']

    def test_same_state_and_limits_produce_identical_handoff(self):
        state, _, evidence_id, artifact_id = self._state()
        first = build_handoff(state)
        second = build_handoff(state)
        self.assertEqual(first, second)
        self.assertEqual(first['identity']['state_digest'], state_digest(state))
        self.assertEqual(first['identity']['snapshot_digest'], state['provenance']['snapshot_digest'])
        self.assertEqual(first['inspection_handoff_version'], '1')
        self.assertEqual(first['referenced_evidence'][0]['id'], evidence_id)
        self.assertEqual(first['referenced_artifacts'][0]['id'], artifact_id)

    def test_handoff_omits_source_bytes_and_raw_evidence_result(self):
        state, source_literal, _, _ = self._state()
        encoded = canonical_handoff_json(build_handoff(state))
        self.assertNotIn(source_literal, encoded)
        self.assertNotIn('UNIQUE_SOURCE_LITERAL_4d92ef', encoded)
        self.assertNotIn('RAW_EVIDENCE_RESULT_17f31c', encoded)
        self.assertFalse(json.loads(encoded)['projection']['contains_source_bytes'])
        self.assertFalse(json.loads(encoded)['projection']['contains_raw_evidence_results'])

    def test_section_truncation_is_explicit_and_never_complete(self):
        state, _, _, _ = self._state(finding_count=4)
        handoff = build_handoff(state, section_limit=1)
        self.assertEqual(handoff['findings']['total'], 4)
        self.assertEqual(handoff['findings']['included'], 1)
        self.assertEqual(handoff['findings']['omitted'], 3)
        self.assertTrue(handoff['projection']['truncated'])
        self.assertFalse(handoff['projection']['projection_complete'])
        self.assertIn('findings.records', handoff['projection']['truncation_reasons'])

    def test_referenced_evidence_keeps_provenance_without_result_payload(self):
        state, _, evidence_id, artifact_id = self._state()
        handoff = build_handoff(state)
        evidence = next(row for row in handoff['referenced_evidence'] if row['id'] == evidence_id)
        artifact = next(row for row in handoff['referenced_artifacts'] if row['id'] == artifact_id)
        self.assertEqual(evidence['artifact_id'], artifact_id)
        self.assertEqual(evidence['artifact_content_digest'], artifact['content_identity'])
        self.assertIn('producer', evidence)
        self.assertIn('source_digest', evidence)
        self.assertNotIn('result', evidence)

    def test_payload_size_ceiling_fails_closed_instead_of_silent_truncation(self):
        state, _, _, _ = self._state(finding_count=2)
        with patch('scan_core.handoff.MAX_HANDOFF_BYTES', 500):
            with self.assertRaisesRegex(ValueError, 'handoff projection exceeds'):
                build_handoff(state)

    def test_invalid_projection_limits_are_rejected(self):
        state, _, _, _ = self._state()
        with self.assertRaisesRegex(ValueError, 'section_limit'):
            build_handoff(state, section_limit=0)
        with self.assertRaisesRegex(ValueError, 'ref_limit'):
            build_handoff(state, ref_limit=101)
        with self.assertRaisesRegex(ValueError, 'text_limit'):
            build_handoff(state, text_limit=4001)


if __name__ == '__main__':
    unittest.main()
