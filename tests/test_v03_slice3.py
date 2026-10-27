"""Scan v0.3 Slice 3 evidence freshness and safe-reuse tests."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from scan_core import (
    ReusePolicy,
    ScanConfig,
    SemanticStateBuilder,
    canonical_state_json,
    schema_object,
    evaluate_reuse,
    scan_project,
    state_digest,
    validate_path,
    validate_state,
)
from scan_core.reuse import check_definition_digest


def _write_project(root: Path, content: str = "stable") -> None:
    (root / "app.txt").write_text(content, encoding="utf-8")


def _artifact(state: dict) -> dict:
    return next(row for row in state["artifacts"] if row["locator"] == "app.txt")


def _check(state: dict, check_id: str = "check-maintainability") -> dict:
    return next(row for row in state["checks"] if row["id"] == check_id)


def _semantic_evidence(
    state: dict,
    *,
    artifact: dict | None = None,
    ident: str = "evidence:semantic-static",
    kind: str = "static",
    evidence_class: str = "static_semantic",
    producer_version: str | None = None,
    result: str = "Static semantic observation remains applicable.",
) -> dict:
    artifact = artifact or _artifact(state)
    check = _check(state)
    producer = dict(state["provenance"]["tool_versions"][0])
    if producer_version is not None:
        producer["version"] = producer_version
    observed_at = state["run"]["completed_at"]
    return {
        "id": ident,
        "artifact_id": artifact["id"],
        "locator": artifact["locator"],
        "kind": kind,
        "claim": "Static semantic evidence for the current artifact bytes",
        "result": result,
        "method": "bounded static semantic inspection",
        "time": observed_at,
        "limitations": "Static only; runtime behavior remains unverified",
        "inspection_origin": "fresh",
        "producer": producer,
        "source_digest": artifact["content_identity"],
        "evidence_class": evidence_class,
        "check_id": check["id"],
        "check_definition_digest": check_definition_digest(check),
        "verification_depth": "partial",
        "freshness": {
            "status": "fresh",
            "source_state_digest": None,
            "source_evidence_id": None,
            "original_observed_at": observed_at,
            "reused_at": None,
            "reuse_reason": None,
        },
    }


def _install_candidate(state: dict, evidence: dict) -> None:
    state["evidence"].append(evidence)
    _artifact(state)["evidence_ids"].append(evidence["id"])
    state["summary"]["evidence_ids"].append(evidence["id"])
    state["baseline"]["fresh_evidence_count"] += 1
    validate_state(state, version="1.4")


def _policy(state: dict) -> ReusePolicy:
    return ReusePolicy(
        available_producers=tuple(
            (row["kind"], row["name"], row["version"])
            for row in state["provenance"]["tool_versions"]
        ),
        check_definitions=tuple((row["id"], check_definition_digest(row)) for row in state["checks"]),
        redaction_level=state["privacy"]["redaction_level"],
    )


class EvidenceReuseTests(unittest.TestCase):
    def test_semantic_builder_emits_fresh_reuse_ready_14_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_project(root)
            state = scan_project(ScanConfig(root=root, baseline_mode="none", reuse_enabled=False)).state
            artifact = _artifact(state)
            builder = SemanticStateBuilder.from_state(state)
            evidence_id = builder.add_evidence(
                artifact_id=artifact["id"],
                locator=artifact["locator"],
                kind="static",
                claim="Maintainability was reviewed statically",
                result="The artifact has a bounded maintainability observation",
                method="semantic source review",
                limitations="Runtime behavior remains unverified",
                source_digest=artifact["content_identity"],
                producer_kind="local-model",
                producer_name="review-agent",
                producer_version="1",
                evidence_class="static_semantic",
                check_id="check-maintainability",
            )
            builder.assess_check(
                category="maintainability",
                status="partial",
                scope="Reviewed artifact only",
                method="semantic source review",
                artifact_ids=artifact["id"],
                evidence_ids=evidence_id,
                verification_state="static",
                result="Partial maintainability assessment available",
                limitations="Runtime behavior remains unverified",
                reason="Static semantic evidence exists",
                next_step="Review remaining artifacts",
            )
            built = builder.build()
            evidence = next(row for row in built["evidence"] if row["id"] == evidence_id)
            check = _check(built)
            self.assertEqual(evidence["freshness"]["status"], "fresh")
            self.assertEqual(evidence["freshness"]["original_observed_at"], evidence["time"])
            self.assertEqual(evidence["evidence_class"], "static_semantic")
            self.assertEqual(evidence["check_id"], check["id"])
            self.assertEqual(evidence["check_definition_digest"], check_definition_digest(check))
            self.assertIn(evidence["producer"], built["provenance"]["tool_versions"])
            self.assertEqual(built["baseline"]["reused_evidence_count"], 0)
            self.assertEqual(built["baseline"]["fresh_evidence_count"], len(built["evidence"]))
            validate_state(built, version="1.4")

    def test_fresh_core_evidence_always_has_freshness_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_project(root)
            state = scan_project(ScanConfig(root=root, baseline_mode="none", reuse_enabled=False)).state
            self.assertGreater(len(state["evidence"]), 0)
            for evidence in state["evidence"]:
                self.assertEqual(evidence["inspection_origin"], "fresh")
                self.assertEqual(evidence["freshness"]["status"], "fresh")
                self.assertEqual(evidence["freshness"]["original_observed_at"], evidence["time"])
                self.assertIsNone(evidence["freshness"]["source_state_digest"])

    def test_identical_higher_level_evidence_is_safely_reused_without_depth_upgrade(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_project(root)
            state_path = root / ".scan" / "state.json"
            report_path = root / ".scan" / "report.html"
            first = scan_project(ScanConfig(root=root, output_state=state_path)).state
            candidate = _semantic_evidence(first)
            original_time = candidate["time"]
            _install_candidate(first, candidate)
            state_path.write_text(canonical_state_json(first) + "\n", encoding="utf-8")
            baseline_digest = state_digest(first)

            second = scan_project(ScanConfig(root=root, output_state=state_path, output_html=report_path)).state
            reused = next(row for row in second["evidence"] if row["id"] == candidate["id"])
            self.assertEqual(second["baseline"]["reused_evidence_count"], 1)
            self.assertEqual(second["baseline"]["rejected_reuse_count"], 0)
            self.assertEqual(reused["inspection_origin"], "verified_reuse")
            self.assertEqual(reused["freshness"]["status"], "verified_reuse")
            self.assertEqual(reused["freshness"]["source_state_digest"], baseline_digest)
            self.assertEqual(reused["freshness"]["source_evidence_id"], candidate["id"])
            self.assertEqual(reused["freshness"]["original_observed_at"], original_time)
            self.assertEqual(reused["time"], original_time)
            self.assertEqual(reused["verification_depth"], "partial")
            self.assertEqual(_artifact(second)["status"], "content_read")
            self.assertEqual(_check(second)["status"], "not_assessed")
            html = report_path.read_text(encoding="utf-8")
            self.assertIn("verified_reuse", html)
            self.assertIn("Safely reused at original depth", html)
            validate_path(report_path)

    def test_changed_bytes_reject_reuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_project(root, "old")
            state_path = root / ".scan" / "state.json"
            first = scan_project(ScanConfig(root=root, output_state=state_path)).state
            candidate = _semantic_evidence(first)
            _install_candidate(first, candidate)
            state_path.write_text(canonical_state_json(first) + "\n", encoding="utf-8")
            _write_project(root, "new")
            second = scan_project(ScanConfig(root=root, output_state=state_path)).state
            self.assertEqual(second["baseline"]["reused_evidence_count"], 0)
            self.assertEqual(second["baseline"]["rejected_reuse_reasons"].get("changed_content"), 1)
            self.assertNotIn(candidate["id"], {row["id"] for row in second["evidence"]})

    def test_evaluate_reuse_rejects_producer_version_mismatch_and_missing_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_project(root)
            state = scan_project(ScanConfig(root=root, baseline_mode="none", reuse_enabled=False)).state
            current = _artifact(state)
            policy = _policy(state)
            old_version = _semantic_evidence(state, producer_version="0.0.0-old")
            self.assertEqual(evaluate_reuse(old_version, current, policy).reason, "producer_version_mismatch")
            missing = _semantic_evidence(state)
            missing.pop("source_digest")
            self.assertEqual(evaluate_reuse(missing, current, policy).reason, "missing_source_digest")

    def test_runtime_evidence_is_never_automatically_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_project(root)
            state = scan_project(ScanConfig(root=root, baseline_mode="none", reuse_enabled=False)).state
            runtime = _semantic_evidence(state, kind="observed", evidence_class="runtime")
            decision = evaluate_reuse(runtime, _artifact(state), _policy(state))
            self.assertFalse(decision.reusable)
            self.assertEqual(decision.reason, "runtime_evidence")

    def test_strict_current_redaction_sanitizes_reused_text(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_project(root)
            state_path = root / ".scan" / "state.json"
            first = scan_project(ScanConfig(root=root, output_state=state_path, redaction_level="standard")).state
            candidate = _semantic_evidence(first, result="Reviewer contact: reviewer@example.com")
            candidate["method"] = "Static review by reviewer@example.com"
            candidate["limitations"] = "Follow up with reviewer@example.com"
            candidate["untrusted_extension"] = "do not carry reviewer@example.com forward"
            _install_candidate(first, candidate)
            state_path.write_text(canonical_state_json(first) + "\n", encoding="utf-8")
            second = scan_project(ScanConfig(root=root, output_state=state_path, redaction_level="strict")).state
            encoded = canonical_state_json(second)
            self.assertEqual(second["baseline"]["reused_evidence_count"], 1)
            self.assertNotIn("reviewer@example.com", encoded)
            self.assertNotIn("untrusted_extension", encoded)
            self.assertIn("[REDACTED:email]", encoded)

    def test_new_sensitive_path_policy_rejects_prior_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "private").mkdir()
            (root / "private" / "app.txt").write_text("stable", encoding="utf-8")
            state_path = root / ".scan" / "state.json"
            first = scan_project(ScanConfig(root=root, output_state=state_path)).state
            artifact = next(row for row in first["artifacts"] if row["locator"] == "private/app.txt")
            check = _check(first)
            candidate = _semantic_evidence(first, artifact=artifact, ident="evidence:private-semantic")
            candidate["check_id"] = check["id"]
            candidate["check_definition_digest"] = check_definition_digest(check)
            first["evidence"].append(candidate)
            artifact["evidence_ids"].append(candidate["id"])
            first["summary"]["evidence_ids"].append(candidate["id"])
            first["baseline"]["fresh_evidence_count"] += 1
            validate_state(first, version="1.4")
            state_path.write_text(canonical_state_json(first) + "\n", encoding="utf-8")
            second = scan_project(ScanConfig(root=root, output_state=state_path, sensitive_paths=("private/**",))).state
            self.assertEqual(second["baseline"]["reused_evidence_count"], 0)
            self.assertEqual(second["baseline"]["rejected_reuse_reasons"].get("current_privacy_policy"), 1)
            self.assertNotIn("private/app.txt", canonical_state_json(second))

    def test_no_reuse_keeps_all_current_evidence_fresh(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_project(root)
            state_path = root / ".scan" / "state.json"
            first = scan_project(ScanConfig(root=root, output_state=state_path)).state
            candidate = _semantic_evidence(first)
            _install_candidate(first, candidate)
            state_path.write_text(canonical_state_json(first) + "\n", encoding="utf-8")
            second = scan_project(ScanConfig(root=root, output_state=state_path, reuse_enabled=False)).state
            self.assertEqual(second["baseline"]["reused_evidence_count"], 0)
            self.assertEqual(second["baseline"]["rejected_reuse_count"], 0)
            self.assertTrue(all(row["freshness"]["status"] == "fresh" for row in second["evidence"]))

    def test_validator_rejects_reused_runtime_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_project(root)
            state = scan_project(ScanConfig(root=root, baseline_mode="none", reuse_enabled=False)).state
            broken = deepcopy(state)
            evidence = broken["evidence"][0]
            evidence["inspection_origin"] = "verified_reuse"
            evidence["kind"] = "observed"
            evidence["evidence_class"] = "runtime"
            evidence["check_id"] = _check(broken)["id"]
            evidence["check_definition_digest"] = check_definition_digest(_check(broken))
            evidence["reuse"] = {
                "prior_scan_id": broken["run"]["scan_id"],
                "prior_inspected_at": evidence["time"],
                "prior_method": evidence["method"],
                "prior_depth": "observed",
                "prior_limits": [evidence["limitations"]],
                "identity_check": "source_digest_exact_match",
                "identity_match": True,
            }
            source_digest = "sha256:" + "1" * 64
            evidence["freshness"] = {
                "status": "verified_reuse",
                "source_state_digest": source_digest,
                "source_evidence_id": evidence["id"],
                "original_observed_at": evidence["time"],
                "reused_at": evidence["time"],
                "reuse_reason": "identical_content_identity",
            }
            broken["baseline"].update({
                "mode": "auto",
                "status": "used",
                "source_schema_version": "1.4",
                "source_state_digest": source_digest,
                "source_snapshot_digest": broken["provenance"]["snapshot_digest"],
                "snapshot_relation": "same",
                "reuse_enabled": True,
                "fresh_evidence_count": len(broken["evidence"]) - 1,
                "reused_evidence_count": 1,
            })
            broken["delta"]["available"] = True
            broken["delta"]["artifacts"]["unchanged"] = [row["id"] for row in broken["artifacts"]]
            with self.assertRaisesRegex(ValueError, "runtime/observed evidence"):
                validate_state(broken, version="1.4")

    def test_schema_14_requires_freshness_metadata(self):
        schema = schema_object("1.4")
        self.assertIn("freshness", schema["properties"]["evidence"]["items"]["required"])

    def test_validator_rejects_missing_freshness_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_project(root)
            state = scan_project(ScanConfig(root=root, baseline_mode="none", reuse_enabled=False)).state
            broken = deepcopy(state)
            broken["evidence"][0].pop("freshness")
            with self.assertRaisesRegex(ValueError, "requires freshness metadata"):
                validate_state(broken, version="1.4")

    def test_tampered_baseline_binding_is_rejected_before_current_reuse_checks(self):
        cases = (
            ("source", "baseline_source_mismatch"),
            ("check", "baseline_check_definition_mismatch"),
            ("producer", "baseline_producer_unrecorded"),
        )
        for mutation, expected_reason in cases:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _write_project(root)
                state_path = root / ".scan" / "state.json"
                first = scan_project(ScanConfig(root=root, output_state=state_path)).state
                candidate = _semantic_evidence(first)
                if mutation == "source":
                    candidate["source_digest"] = "sha256:" + "0" * 64
                elif mutation == "check":
                    candidate["check_definition_digest"] = "sha256:" + "0" * 64
                else:
                    candidate["producer"]["version"] = "unrecorded-version"
                _install_candidate(first, candidate)
                state_path.write_text(canonical_state_json(first) + "\n", encoding="utf-8")
                second = scan_project(ScanConfig(root=root, output_state=state_path)).state
                self.assertEqual(second["baseline"]["reused_evidence_count"], 0)
                self.assertEqual(second["baseline"]["rejected_reuse_reasons"].get(expected_reason), 1)

    def test_check_definition_mismatch_rejects_reuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_project(root)
            state = scan_project(ScanConfig(root=root, baseline_mode="none", reuse_enabled=False)).state
            evidence = _semantic_evidence(state)
            evidence["check_definition_digest"] = "sha256:" + "0" * 64
            decision = evaluate_reuse(evidence, _artifact(state), _policy(state))
            self.assertFalse(decision.reusable)
            self.assertEqual(decision.reason, "check_definition_mismatch")

    def test_compatible_13_baseline_can_reuse_when_contract_fields_exist(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "project"
            root.mkdir()
            _write_project(root)
            first = scan_project(ScanConfig(root=root, baseline_mode="none", reuse_enabled=False)).state
            candidate = _semantic_evidence(first)
            _install_candidate(first, candidate)
            historical = deepcopy(first)
            historical["schema_version"] = "1.3"
            historical.pop("baseline")
            historical.pop("delta")
            validate_state(historical, version="1.3")
            baseline_path = base / "baseline-13.json"
            baseline_path.write_text(canonical_state_json(historical) + "\n", encoding="utf-8")
            result = scan_project(ScanConfig(
                root=root,
                output_state=base / "current.json",
                baseline_mode="explicit",
                baseline_path=baseline_path,
            )).state
            self.assertEqual(result["baseline"]["source_schema_version"], "1.3")
            self.assertEqual(result["baseline"]["reused_evidence_count"], 1)
            reused = next(row for row in result["evidence"] if row["id"] == candidate["id"])
            self.assertEqual(reused["freshness"]["status"], "verified_reuse")


if __name__ == "__main__":
    unittest.main()
