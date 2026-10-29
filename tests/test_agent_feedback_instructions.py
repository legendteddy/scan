"""Keep the mandatory post-run contribution workflow visible to AI agents."""
from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class AgentFeedbackInstructionTests(unittest.TestCase):
    def test_skill_requires_post_run_receipt_submission_attempt_and_status(self):
        text = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("Every capable agent must attempt this post-run step", text)
        self.assertIn("--submit auto", text)
        self.assertIn("--flush --submit auto", text)
        for status in ("submitted", "duplicate", "queued"):
            self.assertIn(status, text)

    def test_feedback_protocol_uses_mandatory_receipt_and_authorized_auto_submit(self):
        text = (ROOT / "docs" / "agent-feedback.md").read_text(encoding="utf-8")
        self.assertIn("every capable AI agent **must** create one contribution receipt", text)
        self.assertIn("Each receipt must contain at least one actual observed test/validation outcome", text)
        self.assertIn("--submit auto", text)
        self.assertIn("submits automatically when the caller/host has already authorized submission", text)
        self.assertIn("--flush --submit auto", text)

    def test_openai_agent_prompt_carries_auto_submit_flush_and_status_contract(self):
        text = (ROOT / "agents" / "openai.yaml").read_text(encoding="utf-8")
        self.assertIn("--submit auto", text)
        self.assertIn("--flush", text)
        for status in ("submitted", "duplicate", "queued"):
            self.assertIn(status, text)


if __name__ == "__main__":
    unittest.main()
