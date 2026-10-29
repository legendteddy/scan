"""ScanBench 2.0 maturity evidence-gate audit tests."""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from scan_core.errors import CommandError
from scan_core.scanbench2 import GROUND_TRUTH_VERSION, TRUTH_KINDS, load_ground_truth_file
from scan_core.scanbench2_maturity import MATURITY_EVIDENCE_VERSION, audit_maturity
from scan_core.scanbench2_review import fixture_source_digest

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "scanbench" / "ground_truth"
AUTH = CORPUS / "fixtures" / "authorization-ownership"


class ScanBench2MaturityTests(unittest.TestCase):
    def _manifest(self, root: Path, **updates):
        value = {
            "scanbench2_version": GROUND_TRUTH_VERSION,
            "maturity_evidence_version": MATURITY_EVIDENCE_VERSION,
        }
        value.update(updates)
        path = root / "maturity.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_missing_external_evidence_stays_missing_while_numeric_corpus_is_satisfied(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = self._manifest(Path(directory))
            result = audit_maturity(CORPUS, manifest)
        gates = result["gates"]
        self.assertEqual(gates["public_corpus"]["status"], "satisfied")
        self.assertEqual(gates["public_corpus"]["project_count"], 26)
        self.assertEqual(gates["public_corpus"]["condition_count"], 209)
        self.assertEqual(gates["independent_review"]["status"], "missing")
        self.assertEqual(gates["effectiveness_baseline"]["status"], "missing")
        self.assertEqual(gates["holdout_precommitment"]["status"], "missing")
        self.assertEqual(gates["mutation_oracle_consistency"]["status"], "missing")
        self.assertTrue(result["no_blended_quality_score"])
        self.assertEqual(result["maturity_claim"], "not automatically established")

    def test_review_path_cannot_escape_maturity_manifest_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self._manifest(root, review_receipts="../outside")
            with self.assertRaisesRegex(CommandError, "canonical relative path"):
                audit_maturity(CORPUS, manifest)

    def test_verified_holdout_identity_does_not_claim_external_custody(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "revealed" / "authorization-holdout"
            shutil.copytree(AUTH, fixture)
            truth_path = fixture / "truth.json"
            truth = json.loads(truth_path.read_text(encoding="utf-8-sig"))
            truth["project_id"] = "authorization-holdout"
            truth_path.write_text(json.dumps(truth), encoding="utf-8")
            normalized_truth = load_ground_truth_file(truth_path)
            counts = Counter(row["truth"] for row in normalized_truth["conditions"])
            holdout = {
                "scanbench2_version": GROUND_TRUTH_VERSION,
                "holdout_manifest_version": "2.0-alpha1",
                "set_id": "external-set-example",
                "custodian": "external-review-lab",
                "entries": [{
                    "project_id": "authorization-holdout",
                    "fixture_digest": fixture_source_digest(fixture),
                    "condition_count": len(normalized_truth["conditions"]),
                    "truth_kind_counts": {kind: counts[kind] for kind in TRUTH_KINDS},
                }],
            }
            holdout_path = root / "holdout.json"
            holdout_path.write_text(json.dumps(holdout), encoding="utf-8")
            manifest = self._manifest(root, holdout_reveals=[{
                "manifest": "holdout.json",
                "project_id": "authorization-holdout",
                "fixture": "revealed/authorization-holdout",
            }])
            result = audit_maturity(CORPUS, manifest)
        gate = result["gates"]["holdout_precommitment"]
        self.assertEqual(gate["status"], "requires_external_custody_evidence")
        self.assertTrue(gate["precommitment_identity_verified"])
        self.assertEqual(gate["verified_reveal_count"], 1)
        self.assertFalse(gate["external_custody_established_by_this_tool"])


if __name__ == "__main__":
    unittest.main()
