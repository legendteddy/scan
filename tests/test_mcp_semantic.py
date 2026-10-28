"""v0.4 bounded semantic MCP continuation tests."""
from __future__ import annotations

import asyncio
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest

try:
    from mcp import Client
except ImportError:  # Base Scan remains dependency-free.
    Client = None

from scan_core.mcp_entry import main as installed_mcp_main
from scan_core.validate import validate_state


def _structured(result):
    payload = result.structured_content
    if isinstance(payload, dict) and set(payload) == {"result"}:
        return payload["result"]
    return payload


def _resource_text(result) -> str:
    return result.contents[0].text


class InstalledMCPEntryTests(unittest.TestCase):
    def test_installed_config_routes_hosts_to_full_mcp_application(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("# Demo\n", encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                exit_code = installed_mcp_main(["config", "codex", str(root)])
            self.assertEqual(exit_code, 0)
            text = output.getvalue()
            self.assertIn("scan_core.mcp_app", text)
            self.assertNotIn("scan_core.mcp_server", text)
            self.assertIn(str(root.resolve()).replace("\\", "\\\\"), text)


@unittest.skipIf(Client is None, "install the optional MCP extra to run semantic protocol tests")
class MCPSemanticContinuationTests(unittest.TestCase):
    def _project(self, root: Path) -> None:
        (root / "README.md").write_text(
            "# Demo\nThe parser accepts one JSON document and returns a normalized result.\n",
            encoding="utf-8",
        )
        (root / "config.txt").write_text("mode=strict\n", encoding="utf-8")
        (root / "binary.bin").write_bytes(b"abc\x00def")

    async def _inventory(self, client):
        page = _structured(await client.call_tool(
            "scan_inventory", {"mode": "deep", "offset": 0, "limit": 100}
        ))
        return {row["locator"]: row for row in page["artifacts"]}

    def test_semantic_workspace_builds_valid_evidence_linked_state_and_report(self):
        async def scenario(root: Path):
            from scan_core.mcp_app import create_server

            server = create_server(root)
            async with Client(server, raise_exceptions=True) as client:
                tools = await client.list_tools()
                names = {tool.name for tool in tools.tools}
                for required in {
                    "scan_summary", "scan_inventory", "scan_read_artifact",
                    "scan_semantic_status", "scan_semantic_reset",
                    "scan_semantic_add_component", "scan_semantic_add_evidence",
                    "scan_semantic_add_relationship", "scan_semantic_add_finding",
                    "scan_semantic_add_unknown", "scan_semantic_assess_check",
                    "scan_semantic_mark_artifact_analyzed", "scan_semantic_finalize",
                    "scan_semantic_state",
                }:
                    self.assertIn(required, names)

                inventory = await self._inventory(client)
                readme = inventory["README.md"]
                config = inventory["config.txt"]

                status = _structured(await client.call_tool("scan_semantic_status", {}))
                self.assertEqual(status["status"], "ok")
                self.assertFalse(status["target_writes"])
                self.assertFalse(status["target_executed"])
                self.assertEqual(status["network_action"], "none")

                evidence = _structured(await client.call_tool("scan_semantic_add_evidence", {
                    "artifact_id": readme["id"],
                    "kind": "static",
                    "claim": "README describes a single-document normalization flow",
                    "result": "The README states that one JSON document is accepted and normalized",
                    "method": "semantic reading of the current README bytes",
                    "limitations": "Documentation describes intent and does not prove runtime behavior",
                    "producer_kind": "remote-model",
                    "producer_name": "scan-test-agent",
                    "producer_version": "1",
                    "check_id": "check-purpose_and_scope",
                }))
                self.assertEqual(evidence["status"], "ok")
                evidence_id = evidence["id"]

                component = _structured(await client.call_tool("scan_semantic_add_component", {
                    "name": "Document normalization surface",
                    "purpose": "Accept one document and describe normalization behavior",
                    "artifact_ids": [readme["id"], config["id"]],
                    "evidence_ids": [evidence_id],
                    "boundaries": "Static documentation/configuration evidence only",
                }))
                self.assertEqual(component["status"], "ok")

                finding = _structured(await client.call_tool("scan_semantic_add_finding", {
                    "title": "Runtime behavior remains unverified",
                    "impact": "The documented normalization contract may differ from executed behavior",
                    "severity": "low",
                    "confidence": "high",
                    "verification_state": "static",
                    "uncertainty": "No target code was executed",
                    "recommendation": "Run a separately authorized runtime check before making runtime claims",
                    "safe_verification": "Execute only after explicit target-execution authorization",
                    "artifact_ids": [readme["id"]],
                    "evidence_ids": [evidence_id],
                }))
                self.assertEqual(finding["status"], "ok")
                finding_id = finding["id"]

                assessed = _structured(await client.call_tool("scan_semantic_assess_check", {
                    "category": "purpose_and_scope",
                    "status": "assessed",
                    "scope": "README purpose statement",
                    "method": "static semantic review",
                    "artifact_ids": [readme["id"]],
                    "evidence_ids": [evidence_id],
                    "related_ids": [finding_id],
                    "verification_state": "static",
                    "result": "Declared purpose and input boundary were identified",
                    "limitations": "Runtime conformance was not tested",
                    "reason": "Current README bytes directly describe the intended flow",
                    "next_step": None,
                }))
                self.assertEqual(assessed["status"], "ok")

                analyzed = _structured(await client.call_tool("scan_semantic_mark_artifact_analyzed", {
                    "artifact_id": readme["id"],
                    "evidence_ids": [evidence_id],
                    "reason": "README received fresh static semantic review",
                }))
                self.assertEqual(analyzed["status"], "ok")

                finalized = _structured(await client.call_tool("scan_semantic_finalize", {
                    "overview": "Static semantic review started from a deterministic Scan snapshot",
                    "condition": "Purpose is documented; runtime behavior remains unverified",
                    "readiness": "not established",
                    "strengths": ["Purpose is explicitly documented"],
                    "priorities": ["Keep runtime claims separate from static semantic evidence"],
                    "limitations": "Only a bounded subset of artifacts has semantic evidence",
                    "remaining": ["Complete remaining semantic check categories", "Perform runtime verification only if separately authorized"],
                    "analysis_complete": False,
                }))
                self.assertEqual(finalized["status"], "ok")
                self.assertFalse(finalized["analysis_complete"])
                self.assertFalse(finalized["checks_complete"])

                exported = _structured(await client.call_tool("scan_semantic_state", {}))
                self.assertEqual(exported["status"], "ok")
                state = exported["state"]
                validate_state(state, version="1.4")
                self.assertFalse(state["run"]["target_executed"])
                self.assertFalse(state["run"]["network_used"])
                boundary = state["extensions"]["semantic_workspace"]
                self.assertFalse(boundary["target_writes"])
                self.assertFalse(boundary["runtime_verification_authorized"])
                self.assertEqual(boundary["network_action"], "none")
                self.assertTrue(any(row["id"] == finding_id for row in state["findings"]))
                self.assertEqual(
                    next(row for row in state["checks"] if row["id"] == "check-purpose_and_scope")["status"],
                    "assessed",
                )
                semantic_evidence = next(row for row in state["evidence"] if row["id"] == evidence_id)
                self.assertEqual(semantic_evidence["source_digest"], readme["content_identity"])
                self.assertEqual(semantic_evidence["freshness"]["status"], "fresh")

                state_resource = json.loads(_resource_text(await client.read_resource("scan://semantic/state")))
                validate_state(state_resource, version="1.4")
                report = _resource_text(await client.read_resource("scan://semantic/report"))
                self.assertIn("Runtime behavior remains unverified", report)
                self.assertIn("project-anatomy-state", report)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._project(root)
            asyncio.run(scenario(root))
            self.assertFalse((root / ".scan").exists())

    def test_snapshot_change_blocks_writes_until_explicit_semantic_reset(self):
        async def scenario(root: Path):
            from scan_core.mcp_app import create_server

            server = create_server(root)
            async with Client(server, raise_exceptions=True) as client:
                inventory = await self._inventory(client)
                readme_id = inventory["README.md"]["id"]
                initial = _structured(await client.call_tool("scan_semantic_status", {}))
                self.assertEqual(initial["status"], "ok")

                (root / "README.md").write_text("# Changed\nNew bytes.\n", encoding="utf-8")
                stale = _structured(await client.call_tool("scan_semantic_add_evidence", {
                    "artifact_id": readme_id,
                    "kind": "static",
                    "claim": "old claim",
                    "result": "old result",
                    "method": "static review",
                    "limitations": "stale test",
                    "producer_kind": "remote-model",
                    "producer_name": "test-agent",
                    "producer_version": "1",
                }))
                self.assertEqual(stale["status"], "stale")

                reset = _structured(await client.call_tool("scan_semantic_reset", {}))
                self.assertEqual(reset["status"], "ok")
                refreshed_inventory = _structured(await client.call_tool(
                    "scan_refresh", {"mode": "deep"}
                ))
                self.assertTrue(refreshed_inventory["refreshed"])
                inventory = await self._inventory(client)
                new_id = inventory["README.md"]["id"]
                accepted = _structured(await client.call_tool("scan_semantic_add_evidence", {
                    "artifact_id": new_id,
                    "kind": "static",
                    "claim": "new claim",
                    "result": "new bytes were reviewed",
                    "method": "static review",
                    "limitations": "runtime not checked",
                    "producer_kind": "remote-model",
                    "producer_name": "test-agent",
                    "producer_version": "1",
                }))
                self.assertEqual(accepted["status"], "ok")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._project(root)
            asyncio.run(scenario(root))

    def test_runtime_claims_binary_evidence_and_invalid_mutations_are_blocked_transactionally(self):
        async def scenario(root: Path):
            from scan_core.mcp_app import create_server

            server = create_server(root)
            async with Client(server, raise_exceptions=True) as client:
                inventory = await self._inventory(client)
                readme = inventory["README.md"]
                binary = inventory["binary.bin"]

                observed = _structured(await client.call_tool("scan_semantic_add_evidence", {
                    "artifact_id": readme["id"], "kind": "observed",
                    "claim": "it ran", "result": "runtime pass", "method": "claimed execution",
                    "limitations": "none", "producer_kind": "remote-model",
                    "producer_name": "test-agent", "producer_version": "1",
                }))
                self.assertEqual(observed["status"], "blocked")
                self.assertIn("not authorized", observed["reason"])

                binary_result = _structured(await client.call_tool("scan_semantic_add_evidence", {
                    "artifact_id": binary["id"], "kind": "static",
                    "claim": "binary claim", "result": "binary result", "method": "text review",
                    "limitations": "none", "producer_kind": "remote-model",
                    "producer_name": "test-agent", "producer_version": "1",
                }))
                self.assertEqual(binary_result["status"], "blocked")
                self.assertIn("binary", binary_result["reason"])

                valid = _structured(await client.call_tool("scan_semantic_add_evidence", {
                    "artifact_id": readme["id"], "kind": "static",
                    "claim": "static claim", "result": "static result", "method": "static review",
                    "limitations": "runtime not checked", "producer_kind": "remote-model",
                    "producer_name": "test-agent", "producer_version": "1",
                }))
                self.assertEqual(valid["status"], "ok")
                evidence_id = valid["id"]

                invalid = _structured(await client.call_tool("scan_semantic_add_finding", {
                    "title": "bad finding", "impact": "bad", "severity": "impossible",
                    "confidence": "high", "verification_state": "static",
                    "uncertainty": "none", "recommendation": "none", "safe_verification": "none",
                    "artifact_ids": [readme["id"]], "evidence_ids": [evidence_id],
                }))
                self.assertEqual(invalid["status"], "blocked")

                exported = _structured(await client.call_tool("scan_semantic_state", {}))
                self.assertEqual(exported["status"], "ok")
                state = exported["state"]
                validate_state(state, version="1.4")
                self.assertFalse(any(row["title"] == "bad finding" for row in state["findings"]))
                self.assertEqual(
                    len([row for row in state["evidence"] if row.get("producer", {}).get("name") == "test-agent"]),
                    1,
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._project(root)
            asyncio.run(scenario(root))
            self.assertFalse((root / ".scan").exists())


if __name__ == "__main__":
    unittest.main()
