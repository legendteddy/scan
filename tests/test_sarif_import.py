"""v0.5 bounded SARIF import adapter tests."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scan_core import ScanConfig, canonical_state_json, import_sarif, scan_project, validate_state
from scan_core.cli import main as cli_main


def _base(root: Path, *, redact: str = "standard") -> dict:
    (root / "app.py").write_text("print('ok')\n", encoding="utf-8")
    return scan_project(ScanConfig(root=root, baseline_mode="none", redaction_level=redact)).state


def _sarif(*, message: str = "Unsafe call detected", uri: str = "app.py", kind: str | None = None, fingerprint: str | None = None) -> dict:
    result = {
        "ruleId": "EXT001",
        "ruleIndex": 0,
        "level": "error",
        "message": {"text": message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 1, "startColumn": 1}}}],
    }
    if kind is not None:
        result["kind"] = kind
    if fingerprint is not None:
        result["partialFingerprints"] = {"primaryLocationLineHash": fingerprint}
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "ExampleScan", "semanticVersion": "1.2.3", "rules": [{
                "id": "EXT001",
                "shortDescription": {"text": "Example external finding"},
                "fullDescription": {"text": "External scanner says this condition can be unsafe."},
                "help": {"text": "Use the safe API instead."},
            }]}},
            "results": [result],
        }],
    }


class SarifImportTests(unittest.TestCase):
    def test_fail_result_maps_to_external_static_evidence_and_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = _base(root)
            imported = import_sarif(state, _sarif())
        validate_state(imported.state)
        self.assertEqual(imported.imported_findings, 1)
        self.assertEqual(imported.imported_evidence, 1)
        finding = imported.state["findings"][0]
        evidence = next(row for row in imported.state["evidence"] if row["producer"]["kind"] == "external-tool")
        artifact = next(row for row in imported.state["artifacts"] if row["locator"] == "app.py")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["verification_state"], "static")
        self.assertEqual(finding["confidence"], "external-tool-reported")
        self.assertEqual(evidence["producer"], {"kind": "external-tool", "name": "ExampleScan", "version": "1.2.3"})
        self.assertEqual(evidence["kind"], "static")
        self.assertIn("app.py:1:1", evidence["result"])
        self.assertEqual(artifact["status"], "partial")
        self.assertFalse(imported.state["coverage"]["analysis_complete"])

    def test_unmapped_fail_and_review_are_unknowns_not_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = _base(root)
            unmapped = import_sarif(state, _sarif(uri="../outside.py"))
            review = import_sarif(state, _sarif(kind="review"))
        self.assertEqual(unmapped.imported_findings, 0)
        self.assertEqual(unmapped.unmapped_results, 1)
        self.assertTrue(any(row["id"].startswith("unknown:sarif:") for row in unmapped.state["unknowns"]))
        self.assertEqual(review.imported_findings, 0)
        self.assertEqual(review.unmapped_results, 1)

    def test_partial_fingerprint_stabilizes_finding_identity_across_message_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = _base(root)
            first = import_sarif(state, _sarif(message="first wording", fingerprint="abc123"))
            second = import_sarif(state, _sarif(message="reworded", fingerprint="abc123"))
        self.assertEqual(first.state["findings"][0]["id"], second.state["findings"][0]["id"])

    def test_imported_prose_obeys_current_scan_redaction_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = _base(root, redact="standard")
            imported = import_sarif(state, _sarif(message='api_key = "super-secret-value-123456"'))
        blob = json.dumps(imported.state, ensure_ascii=False)
        self.assertNotIn("super-secret-value-123456", blob)
        self.assertIn("[REDACTED:credential]", blob)

    def test_non_fail_result_is_counted_but_not_promoted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = _base(root)
            imported = import_sarif(state, _sarif(kind="pass"))
        self.assertEqual(imported.ignored_results, 1)
        self.assertEqual(imported.imported_findings, 0)
        self.assertEqual(imported.unmapped_results, 0)

    def test_duplicate_fingerprint_result_is_deduplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = _base(root)
            payload = _sarif(fingerprint="same-result")
            payload["runs"][0]["results"].append(dict(payload["runs"][0]["results"][0]))
            imported = import_sarif(state, payload)
        self.assertEqual(imported.imported_findings, 1)
        self.assertEqual(imported.ignored_results, 1)

    def test_cli_import_sarif_writes_valid_state_and_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = _base(root)
            base_path = root / "base.json"
            sarif_path = root / "external.sarif"
            output = root / "imported.json"
            report = root / "imported.html"
            base_path.write_text(canonical_state_json(state) + "\n", encoding="utf-8")
            sarif_path.write_text(json.dumps(_sarif(), ensure_ascii=False), encoding="utf-8")
            code = cli_main(["import-sarif", str(base_path), str(sarif_path), "--output", str(output), "--report", str(report), "--json"])
            self.assertEqual(code, 0)
            self.assertTrue(output.is_file())
            self.assertTrue(report.is_file())
            imported = json.loads(output.read_text(encoding="utf-8"))
            validate_state(imported)
            self.assertEqual(len(imported["findings"]), 1)

    def test_import_rejects_unsupported_sarif_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = _base(root)
            payload = _sarif()
            payload["version"] = "2.2.0"
            with self.assertRaisesRegex(ValueError, "2.1.0 only"):
                import_sarif(state, payload)


if __name__ == "__main__":
    unittest.main()
