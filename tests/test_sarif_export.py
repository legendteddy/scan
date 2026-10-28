"""v0.5 SARIF 2.1.0 interoperability tests."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scan_core import ScanConfig, SemanticStateBuilder, scan_project, validate_state
from scan_core.cli import main
from scan_core.sarif import SARIF_SCHEMA, SARIF_VERSION, build_sarif, sarif_text
from scan_core.version import __version__


class SarifExportTests(unittest.TestCase):
    def _state_with_finding(self, root: Path, *, severity: str = "low"):
        (root / "src").mkdir(parents=True, exist_ok=True)
        (root / "src" / "app.py").write_text("answer = 42\n", encoding="utf-8")
        state = scan_project(ScanConfig(root=root)).state
        artifact = next(row for row in state["artifacts"] if row["locator"] == "src/app.py")
        builder = SemanticStateBuilder.from_state(state)
        evidence_id = builder.add_evidence(
            artifact_id=artifact["id"],
            locator=artifact["locator"],
            kind="static",
            claim="The assignment was reviewed",
            result="The source assigns a fixed integer",
            method="bounded static source review",
            limitations="Runtime behavior was not observed",
            source_digest=artifact["content_identity"],
            producer_kind="human",
            producer_name="sarif-test",
            producer_version="1",
        )
        finding_id = builder.add_finding(
            title="Fixed value may hide configuration",
            impact="Deployments cannot change this value without editing source",
            severity=severity,
            confidence="high",
            verification_state="static",
            artifact_ids=artifact["id"],
            evidence_ids=evidence_id,
            uncertainty="Only static source was inspected",
            recommendation="Move the value to explicit configuration if variability is required",
            safe_verification="Review expected deployment configuration behavior",
        )
        built = builder.build()
        validate_state(built)
        built_artifact = next(row for row in built["artifacts"] if row["id"] == artifact["id"])
        return built, built_artifact, finding_id

    def test_core_state_without_findings_exports_empty_result_set(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("# Demo\n", encoding="utf-8")
            state = scan_project(ScanConfig(root=root)).state
        payload = build_sarif(state)
        self.assertEqual(payload["version"], SARIF_VERSION)
        self.assertEqual(payload["$schema"], SARIF_SCHEMA)
        self.assertEqual(payload["runs"][0]["results"], [])
        self.assertEqual(payload["runs"][0]["tool"]["driver"]["rules"], [])
        self.assertGreater(len(state["unknowns"]), 0)
        self.assertEqual(payload["runs"][0]["properties"]["scanUnknownCount"], len(state["unknowns"]))

    def test_finding_maps_to_github_compatible_sarif_without_fake_line_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, artifact, finding_id = self._state_with_finding(root, severity="high")
            payload = build_sarif(state)
            text = sarif_text(state)
        run = payload["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "Scan")
        self.assertEqual(run["tool"]["driver"]["semanticVersion"], __version__)
        self.assertEqual(len(run["results"]), 1)
        result = run["results"][0]
        rule = run["tool"]["driver"]["rules"][0]
        self.assertEqual(result["ruleId"], rule["id"])
        self.assertEqual(result["ruleIndex"], 0)
        self.assertEqual(result["level"], "error")
        self.assertEqual(result["properties"]["scanFindingId"], finding_id)
        physical = result["locations"][0]["physicalLocation"]
        self.assertEqual(physical["artifactLocation"]["uri"], "src/app.py")
        self.assertNotIn("region", physical)
        self.assertNotIn("partialFingerprints", result)
        self.assertNotIn(str(root), text)
        self.assertNotIn(artifact["content_identity"], text)

    def test_low_severity_maps_to_note_and_export_is_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            state, _, _ = self._state_with_finding(Path(directory), severity="low")
            first = sarif_text(state)
            second = sarif_text(state)
        self.assertEqual(first, second)
        payload = json.loads(first)
        self.assertEqual(payload["runs"][0]["results"][0]["level"], "note")
        self.assertTrue(first.endswith("\n"))

    def test_additional_artifacts_are_related_locations_not_duplicate_alerts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.py").write_text("a = 1\n", encoding="utf-8")
            (root / "b.py").write_text("b = 2\n", encoding="utf-8")
            state = scan_project(ScanConfig(root=root)).state
            artifacts = {row["locator"]: row for row in state["artifacts"]}
            builder = SemanticStateBuilder.from_state(state)
            evidence_id = builder.add_evidence(
                artifact_id=artifacts["a.py"]["id"], locator="a.py", kind="static",
                claim="Two files share one concern", result="A cross-file concern was identified",
                method="static review", limitations="Runtime not observed",
                source_digest=artifacts["a.py"]["content_identity"], producer_kind="human",
                producer_name="sarif-test", producer_version="1",
            )
            builder.add_finding(
                title="Cross-file concern", impact="Both files participate in the issue", severity="medium",
                confidence="medium", verification_state="static",
                artifact_ids=[artifacts["a.py"]["id"], artifacts["b.py"]["id"]],
                evidence_ids=evidence_id, uncertainty="Static only", recommendation="Review both files",
                safe_verification="Inspect both files together",
            )
            payload = build_sarif(builder.build())
        result = payload["runs"][0]["results"][0]
        self.assertEqual(len(payload["runs"][0]["results"]), 1)
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "a.py")
        self.assertEqual(result["relatedLocations"][0]["physicalLocation"]["artifactLocation"]["uri"], "b.py")

    def test_unsafe_or_non_file_location_is_rejected_instead_of_silently_dropped(self):
        with tempfile.TemporaryDirectory() as directory:
            state, artifact, _ = self._state_with_finding(Path(directory))
        artifact["locator"] = "../outside.py"
        with self.assertRaisesRegex(ValueError, "unsafe path segments"):
            build_sarif(state)

        artifact["locator"] = "C:/owner/private.py"
        with self.assertRaisesRegex(ValueError, "project-relative"):
            build_sarif(state)

        artifact["locator"] = "inside.py"
        artifact["path_kind"] = "archive-member"
        with self.assertRaisesRegex(ValueError, "no repository-relative file artifact"):
            build_sarif(state)

    def test_uri_encodes_unicode_spaces_and_hash_characters(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "資料 folder"
            nested.mkdir(parents=True)
            target = nested / "Résumé #1.py"
            target.write_text("value = 1\n", encoding="utf-8")
            state = scan_project(ScanConfig(root=root)).state
            artifact = next(row for row in state["artifacts"] if row["locator"] == "資料 folder/Résumé #1.py")
            builder = SemanticStateBuilder.from_state(state)
            evidence_id = builder.add_evidence(
                artifact_id=artifact["id"], locator=artifact["locator"], kind="static",
                claim="Unicode path reviewed", result="File contains an assignment", method="static review",
                limitations="Runtime not observed", source_digest=artifact["content_identity"],
                producer_kind="human", producer_name="sarif-test", producer_version="1",
            )
            builder.add_finding(
                title="Unicode path finding", impact="Exercises portable URI encoding", severity="low",
                confidence="high", verification_state="static", artifact_ids=artifact["id"],
                evidence_ids=evidence_id, uncertainty="Static only", recommendation="Keep path portable",
                safe_verification="Inspect exported SARIF URI",
            )
            payload = build_sarif(builder.build())
        uri = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "%E8%B3%87%E6%96%99%20folder/R%C3%A9sum%C3%A9%20%231.py")

    def test_cli_exports_validated_state_to_pretty_sarif(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, _, _ = self._state_with_finding(root)
            state_path = root / "state.json"
            output = root / "out" / "results.sarif"
            state_path.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
            exit_code = main(["sarif", str(state_path), "--output", str(output), "--pretty"])
            self.assertEqual(exit_code, 0)
            text = output.read_text(encoding="utf-8")
            payload = json.loads(text)
            self.assertEqual(payload["version"], "2.1.0")
            self.assertEqual(len(payload["runs"][0]["results"]), 1)
            self.assertIn("\n  \"runs\"", text)


if __name__ == "__main__":
    unittest.main()
