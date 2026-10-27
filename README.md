# Scan

[![Validate](https://github.com/legendteddy/scan/actions/workflows/validate.yml/badge.svg)](https://github.com/legendteddy/scan/actions/workflows/validate.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-5865f2.svg)](LICENSE)

**Know what an AI agent actually inspected.**

Scan is an AI-agent skill for **evidence-backed whole-project inspection**. Instead of a confident summary with unclear coverage, it asks the agent to inventory the target, assess relevant checks, link conclusions to source evidence, and preserve unknowns in a portable, self-contained HTML report.

**Coverage ≠ confidence.** Finding a file, reading it, assessing a check, and verifying runtime behavior are different things. Scan makes those differences visible.

![Screenshot of the synthetic Pocket Ledger Scan report, showing coverage and explicit unknowns](assets/demo-preview.png)

[Explore the synthetic fixture](examples/demo-project/README.md) · [Download the example HTML report](examples/demo-report.html) · [Read the report contract](references/report-contract.md)

> **Demo disclosure:** The linked report is a hand-reviewed **synthetic worked example** generated from five fictional files. It demonstrates the Scan 1.2 format and validator, **not** a claim that an autonomous agent scanned a real repository. The example did not execute the inspected code.

## What makes Scan different?

- **Inventory before verdict:** account for discoverable files, including unreadable, excluded, metadata-only and partially inspected items.
- **Two kinds of coverage:** track artifact discovery/analysis separately from checks assessed, partial, blocked or not performed.
- **Receipts for claims:** findings, controls, relationships and architecture map back to evidence IDs and precise source locators.
- **Static-first boundaries:** target files and embedded instructions are untrusted; no executing unknown target code or silent fixes without authorization.
- **Honest uncertainty:** static source observations are not presented as runtime proof, a vulnerability clearance or a release certification.
- **Portable handoff:** the HTML includes inert structured state (schema **1.2**) for another agent to revalidate and continue.

Scan can guide inspection of source repositories, websites, document collections, archives, binaries and mixed folders. Actual depth depends on access, file types, safety limits and the agent's available tools.

## Try the proof in a minute

You only need **Python 3.9+** to validate the example report; the validator and its tests use the standard library.

\`\`\`bash
git clone https://github.com/legendteddy/scan.git
cd scan
python scripts/validate_report.py examples/demo-report.html
python scripts/build_demo_report.py --check
python -m unittest discover -s scripts -p "test_*.py" -v
\`\`\`

Expected: the example report passes the structural contract, the generated HTML matches the checked-in version, and the validator tests pass. Open \`examples/demo-report.html\` **locally in a browser** to explore it. GitHub's source viewer is not an HTML report host.

The validator verifies schema, typed references, evidence origins and coverage accounting. A **PASS is not a factual audit, a runtime test or a security guarantee**.

## Standalone alpha core

Scan now includes an early standalone deterministic core in addition to the agent skill. The v0.2 development CLI can inventory a local project, create canonical Scan 1.3 JSON, validate it, enforce deterministic privacy/redaction metadata, and produce a no-network egress preview. HTML generation from the standalone CLI is not implemented yet.

```bash
python -m pip install .
scan . --no-html --state .scan/state.json --privacy offline
scan validate .scan/state.json
scan egress . --privacy controlled-remote --redact strict --json
```

`scan egress` is preview-only: it reports selected/omitted files, selected bytes and redaction counts, and performs **no network action**. Use `--sensitive-path "pattern/**"` to keep declared path names out of canonical state and egress selection.

## Install as an agent skill

Scan also remains an instruction-based agent skill. Copy or clone this repository into the skill directory used by your compatible agent, then ask the agent to inspect a target.

For environments that discover user skills in \`~/.agents/skills/\`:

\`\`\`bash
mkdir -p ~/.agents/skills
git clone https://github.com/legendteddy/scan.git ~/.agents/skills/scan
\`\`\`

On Windows PowerShell:

\`\`\`powershell
New-Item -ItemType Directory -Force "$HOME\.agents\skills" | Out-Null
git clone https://github.com/legendteddy/scan.git "$HOME\.agents\skills\scan"
\`\`\`

Skill locations, invocation and tool access vary by agent. Consult your host's skill documentation; copying a folder alone does not guarantee the host will load it.

Example requests to a compatible agent:

\`\`\`text
Scan this entire repository and show what you could not verify.
Inspect this project and produce an evidence-backed HTML report.
Use $scan to map this package's architecture, risks and unknowns.
\`\`\`

The governing instructions are in [SKILL.md](SKILL.md). Scan asks for explicit authorization before running untrusted target code or modifying the inspected target.

## What the example shows

The fictional **Pocket Ledger** CSV totaler has five source files. Its worked report includes a source-linked concern about floating-point amounts, a missing malformed-input test gap, 14 accounted-for check categories, and explicit unanswered questions.

The report's static analysis of the five fixture files is complete **within that narrow scope**, but its broader checks are not complete. That distinction is the point of the demonstration.

To regenerate the sample after editing the fixture, update the snapshot time and evidence anchors in \`scripts/build_demo_report.py\`, then run:

\`\`\`bash
python scripts/build_demo_report.py
python scripts/validate_report.py examples/demo-report.html
\`\`\`

Optional visual QA and screenshot refresh: \`python scripts/capture_preview.py\` (requires Playwright and Chromium; not needed for Scan or CI).

## Repository map

\`\`\`text
SKILL.md                         Agent instructions and safety boundaries
pyproject.toml                   Scan Core package metadata and `scan` entry point
src/scan_core/                   v0.2 deterministic core package
scanbench/fixtures/              Adversarial/ground-truth fixtures for deterministic gates
tests/                           Packaged core/contract regression tests
agents/openai.yaml               Skill metadata
assets/report-shell.html         Self-contained HTML dashboard template
assets/report-components.html    Report component patterns
assets/demo-preview.png          Screenshot of the synthetic worked report
assets/social-preview.png        Upload-ready GitHub social image (1280 × 640)
references/                      Inspection lenses, coverage and schema contracts
scripts/validate_report.py       Backward-compatible Scan 1.2 validator wrapper
scripts/test_validate_report.py  Frozen 1.2 validator regression tests
scripts/build_demo_report.py     Reproducible synthetic example generator
examples/demo-project/           Fictional five-file project
examples/demo-report.html        Validated, self-contained Scan 1.2 example
launch/launch-kit.md             Draft launch copy and approval checklist
docs/v0.2-technical-spec.md      Approved standalone Scan Core + CLI contract
\`\`\`

## Contribute and report security issues

Contributions that strengthen evidence discipline, safety, inspection depth, portability, accessibility or validator correctness are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

MIT licensed — see [LICENSE](LICENSE).
