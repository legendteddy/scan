"""Portable deterministic Inspection Bundle v1 tests."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from scan_core import ScanConfig, SemanticStateBuilder, scan_project
from scan_core.inspection_bundle import (
    HANDOFF_NAME,
    MANIFEST_NAME,
    MEMBER_ORDER,
    STATE_NAME,
    _canonical_json_bytes,
    _sha256,
    _zip_info,
    create_inspection_bundle,
    verify_inspection_bundle,
)


class InspectionBundleTests(unittest.TestCase):
    def _state(self):
        directory = tempfile.TemporaryDirectory()
        root = Path(directory.name)
        (root / "app.py").write_text("def work():\n    return 1\n", encoding="utf-8")
        state = scan_project(ScanConfig(root=root, baseline_mode="none", reuse_enabled=False)).state
        artifact = next(row for row in state["artifacts"] if row["locator"] == "app.py")
        builder = SemanticStateBuilder.from_state(state)
        evidence_id = builder.add_evidence(
            artifact_id=artifact["id"], locator="app.py:1-2", kind="static",
            claim="Static review establishes the declared return behavior.",
            result="The function returns the literal integer one.", method="static semantic review",
            limitations="Runtime behavior was not executed.", source_digest=artifact["content_identity"],
            producer_kind="human", producer_name="bundle-test", producer_version="1",
        )
        builder.add_finding(
            record_id="finding:bundle-test", title="Example bounded finding", impact="Test-only impact.",
            severity="low", confidence="high", verification_state="static",
            artifact_ids=[artifact["id"]], evidence_ids=[evidence_id],
            uncertainty="Static fixture only.", recommendation="No production action; this is a fixture.",
            safe_verification="Use the deterministic unit test.",
        )
        builder.add_unknown(
            record_id="unknown:bundle-test", question="Was runtime behavior observed?",
            reason="No runtime evidence is present.", impact="Runtime behavior remains unverified.",
            next_safe_step="Collect authorized observed evidence.", artifact_ids=[artifact["id"]], evidence_ids=[evidence_id],
        )
        builder.set_summary(
            overview="Bundle fixture state.", condition="Static evidence with runtime unknown.",
            readiness="conditional", limitations="Runtime not observed.",
            evidence_ids=[evidence_id], strengths=["Canonical state is valid."], priorities=["Collect runtime evidence."],
        )
        self.addCleanup(directory.cleanup)
        return builder.build(analysis_complete=False)

    def _members(self, path: Path):
        with zipfile.ZipFile(path, "r") as archive:
            return {name: archive.read(name) for name in MEMBER_ORDER}

    def _rewrite(self, path: Path, members: dict[str, bytes], *, extra: tuple[str, bytes] | None = None, duplicate: str | None = None):
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
            for name in MEMBER_ORDER:
                archive.writestr(_zip_info(name), members[name])
            if duplicate is not None:
                archive.writestr(_zip_info(duplicate), members[duplicate])
            if extra is not None:
                archive.writestr(_zip_info(extra[0]), extra[1])

    def test_same_state_produces_byte_identical_bundle_and_verifies(self):
        state = self._state()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "one.scanbundle"
            second = root / "two.scanbundle"
            a = create_inspection_bundle(state, first)
            b = create_inspection_bundle(state, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(a.bundle_digest, b.bundle_digest)
            verified = verify_inspection_bundle(first)
        self.assertTrue(verified["verified"])
        self.assertEqual(verified["bundle_digest"], a.bundle_digest)
        self.assertEqual(verified["state_digest"], a.state_digest)
        self.assertEqual(verified["handoff_digest"], a.handoff_digest)
        self.assertFalse(verified["target_executed"])
        self.assertFalse(verified["network_used"])
        self.assertTrue(verified["no_blended_quality_score"])

    def test_tampered_state_member_is_rejected_by_manifest_digest(self):
        state = self._state()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bundle.scanbundle"
            create_inspection_bundle(state, path)
            members = self._members(path)
            state_value = json.loads(members[STATE_NAME])
            state_value["summary"]["readiness"] = "blocked"
            members[STATE_NAME] = (json.dumps(state_value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode()
            self._rewrite(path, members)
            with self.assertRaisesRegex(ValueError, "digest/size does not match state.json"):
                verify_inspection_bundle(path)

    def test_handoff_tamper_is_rejected_even_when_manifest_digest_is_updated(self):
        state = self._state()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bundle.scanbundle"
            create_inspection_bundle(state, path)
            members = self._members(path)
            handoff = json.loads(members[HANDOFF_NAME])
            handoff["summary"]["readiness"] = "tampered"
            handoff.pop("handoff_digest", None)
            digest_payload = json.dumps(handoff, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
            handoff["handoff_digest"] = "sha256:" + hashlib.sha256(digest_payload).hexdigest()
            members[HANDOFF_NAME] = (json.dumps(handoff, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode()
            manifest = json.loads(members[MANIFEST_NAME])
            manifest["members"][HANDOFF_NAME]["sha256"] = _sha256(members[HANDOFF_NAME])
            manifest["members"][HANDOFF_NAME]["size_bytes"] = len(members[HANDOFF_NAME])
            manifest["identity"]["handoff_digest"] = handoff["handoff_digest"]
            members[MANIFEST_NAME] = _canonical_json_bytes(manifest)
            self._rewrite(path, members)
            with self.assertRaisesRegex(ValueError, "does not exactly match the default handoff"):
                verify_inspection_bundle(path)

    def test_duplicate_and_unexpected_members_are_rejected(self):
        state = self._state()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "bundle.scanbundle"
            create_inspection_bundle(state, path)
            members = self._members(path)
            duplicate = root / "duplicate.scanbundle"
            self._rewrite(duplicate, members, duplicate=STATE_NAME)
            with self.assertRaisesRegex(ValueError, "duplicate member names"):
                verify_inspection_bundle(duplicate)
            traversal = root / "traversal.scanbundle"
            self._rewrite(traversal, members, extra=("../evil", b"nope"))
            with self.assertRaisesRegex(ValueError, "members/order must be exactly"):
                verify_inspection_bundle(traversal)

    def test_noncanonical_member_metadata_is_rejected(self):
        state = self._state()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid = root / "valid.scanbundle"
            create_inspection_bundle(state, valid)
            members = self._members(valid)
            bad = root / "bad.scanbundle"
            with zipfile.ZipFile(bad, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr(MANIFEST_NAME, members[MANIFEST_NAME])
                archive.writestr(STATE_NAME, members[STATE_NAME])
                archive.writestr(HANDOFF_NAME, members[HANDOFF_NAME])
            with self.assertRaisesRegex(ValueError, "noncanonical timestamp|canonical Unix ZIP metadata|canonical regular file"):
                verify_inspection_bundle(bad)

    def test_archive_size_ceiling_fails_before_decompression(self):
        state = self._state()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bundle.scanbundle"
            create_inspection_bundle(state, path)
            with patch("scan_core.inspection_bundle.MAX_BUNDLE_BYTES", 10):
                with self.assertRaisesRegex(ValueError, "archive limit"):
                    verify_inspection_bundle(path)


if __name__ == "__main__":
    unittest.main()
