"""v0.4 MCP bridge acceptance and trust-boundary tests."""
from __future__ import annotations

import asyncio
from pathlib import Path
import tempfile
import unittest

try:
    from mcp import Client
except ImportError:  # The base Scan install intentionally has no MCP dependency.
    Client = None

from scan_core.mcp_server import create_server


def _structured(result):
    payload = result.structured_content
    if isinstance(payload, dict) and set(payload) == {"result"}:
        return payload["result"]
    return payload


@unittest.skipIf(Client is None, "install the optional MCP extra to run MCP protocol tests")
class MCPServerTests(unittest.TestCase):
    def _project(self, root: Path) -> None:
        (root / "README.md").write_text("# Demo\nSafe project text.\n", encoding="utf-8")
        (root / "config.txt").write_text(
            "API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456\nmode=demo\n",
            encoding="utf-8",
        )
        (root / "secret.txt").write_text("private material\n", encoding="utf-8")
        (root / "binary.bin").write_bytes(b"abc\x00def")
        (root / "sub").mkdir()
        (root / "sub" / "inner.txt").write_text("nested\n", encoding="utf-8")

    def test_in_memory_protocol_exposes_read_only_scan_tools(self):
        async def scenario(root: Path):
            server = create_server(root, sensitive_paths=("secret.txt",))
            async with Client(server, raise_exceptions=True) as client:
                tools = await client.list_tools()
                names = {tool.name for tool in tools.tools}
                self.assertEqual(
                    names,
                    {"scan_summary", "scan_refresh", "scan_inventory", "scan_state", "scan_read_artifact"},
                )

                summary = _structured(await client.call_tool("scan_summary", {"mode": "deep"}))
                self.assertEqual(summary["schema_version"], "1.4")
                self.assertEqual(summary["scan_mode"], "deep")
                self.assertEqual(summary["inspection_mode"], "static")
                self.assertFalse(summary["target_executed"])
                self.assertTrue(summary["artifacts"]["discovery_complete"])
                self.assertFalse(summary["artifacts"]["analysis_complete"])
                self.assertFalse(summary["privacy"]["egress_performed"])
                self.assertEqual(summary["privacy"]["network_action"], "none")

                page = _structured(
                    await client.call_tool("scan_inventory", {"mode": "deep", "offset": 0, "limit": 2})
                )
                self.assertGreaterEqual(page["total"], 6)
                self.assertEqual(len(page["artifacts"]), 2)
                self.assertEqual(page["next_offset"], 2)
                self.assertEqual(page["scan_id"], summary["scan_id"])
                self.assertEqual(page["snapshot_digest"], summary["snapshot_digest"])

                about = await client.read_resource("scan://about")
                self.assertIn("does not execute target code", about.contents[0].text)

                prompt = await client.get_prompt("scan_review")
                prompt_text = "\n".join(
                    block.content.text
                    for block in prompt.messages
                    if getattr(block.content, "type", None) == "text"
                )
                self.assertIn("Separate inventory, semantic analysis, and runtime verification", prompt_text)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._project(root)
            asyncio.run(scenario(root))
            self.assertFalse((root / ".scan").exists())

    def test_artifact_reads_are_digest_checked_redacted_and_policy_bounded(self):
        async def scenario(root: Path):
            server = create_server(root, sensitive_paths=("secret.txt",))
            async with Client(server, raise_exceptions=True) as client:
                read = _structured(await client.call_tool("scan_read_artifact", {"locator": "config.txt"}))
                self.assertEqual(read["status"], "ok")
                self.assertIn("[REDACTED:credential]", read["text"])
                self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz123456", read["text"])
                self.assertGreaterEqual(read["redaction_count"], 1)
                self.assertTrue(read["source_digest"].startswith("sha256:"))

                (root / "config.txt").write_text("mode=changed\n", encoding="utf-8")
                stale = _structured(
                    await client.call_tool("scan_read_artifact", {"locator": "config.txt"})
                )
                self.assertEqual(stale["status"], "stale")
                self.assertNotEqual(stale["expected_digest"], stale["actual_digest"])

                refreshed = _structured(await client.call_tool("scan_refresh", {"mode": "deep"}))
                self.assertTrue(refreshed["refreshed"])
                after_refresh = _structured(
                    await client.call_tool("scan_read_artifact", {"locator": "config.txt"})
                )
                self.assertEqual(after_refresh["status"], "ok")
                self.assertIn("mode=changed", after_refresh["text"])

                sensitive = _structured(
                    await client.call_tool("scan_read_artifact", {"locator": "secret.txt"})
                )
                self.assertEqual(sensitive["status"], "blocked")
                self.assertEqual(sensitive["locator"], "[REDACTED:sensitive-path]")

                binary = _structured(
                    await client.call_tool("scan_read_artifact", {"locator": "binary.bin"})
                )
                self.assertEqual(binary["status"], "blocked")
                self.assertIn("binary", binary["reason"])

                too_small = _structured(
                    await client.call_tool(
                        "scan_read_artifact", {"locator": "README.md", "max_bytes": 4}
                    )
                )
                self.assertEqual(too_small["status"], "blocked")
                self.assertIn("max_bytes=4", too_small["reason"])

                traversal = _structured(
                    await client.call_tool("scan_read_artifact", {"locator": "../outside.txt"})
                )
                self.assertEqual(traversal["status"], "blocked")
                self.assertEqual(traversal["locator"], "[INVALID:project-relative-path]")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._project(root)
            asyncio.run(scenario(root))
            self.assertFalse((root / ".scan").exists())

    def test_strict_redaction_removes_email_and_phone(self):
        async def scenario(root: Path):
            server = create_server(root, redaction_level="strict")
            async with Client(server, raise_exceptions=True) as client:
                result = _structured(
                    await client.call_tool("scan_read_artifact", {"locator": "person.txt"})
                )
                self.assertEqual(result["status"], "ok")
                self.assertNotIn("person@example.com", result["text"])
                self.assertIn("[REDACTED:email]", result["text"])
                self.assertIn("[REDACTED:phone]", result["text"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "person.txt").write_text(
                "Email person@example.com Phone +673 8123456\n",
                encoding="utf-8",
            )
            asyncio.run(scenario(root))


if __name__ == "__main__":
    unittest.main()
