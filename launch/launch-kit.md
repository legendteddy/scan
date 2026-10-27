# Scan launch kit — drafts, not published

**Status:** preparation only. Do not publish community posts, create a public release, enable GitHub Pages, or merge the launch-readiness PR without owner approval.

## Positioning and proof

**One-liner:** Scan is an AI-agent skill for evidence-backed whole-project inspection: explicit coverage, source-linked claims and honest unknowns in a self-contained HTML report.

**Problem:** An AI agent can sound confident about a repository without showing which files it actually read or which checks it completed.

**Proof to link:**
- Repository: https://github.com/legendteddy/scan
- Synthetic fixture: https://github.com/legendteddy/scan/tree/main/examples/demo-project
- Example report source/download: https://github.com/legendteddy/scan/blob/main/examples/demo-report.html
- Report screenshot: https://github.com/legendteddy/scan/blob/main/assets/demo-preview.png
- Contract validator and tests: https://github.com/legendteddy/scan/tree/main/scripts

The URLs above are **post-merge destinations**; the files are initially on the launch-readiness branch. Do not use main-branch links until merged.

**What is proven today:** The Python stdlib validator accepts the checked-in synthetic report; the generator reproduces it; the example explicitly accounts for five fixture files and 14 check categories. This does **not** demonstrate autonomous scanning accuracy on an unrelated repository.

**What is not proven:** General reliability, exploit detection, dynamic behavior, universal file-format coverage, independent real-world evaluation or production readiness.

## Draft: Show HN

**Title:** Show HN: Scan – evidence-backed whole-project inspection for AI agents

**Body:**

I built Scan because I kept seeing AI project reviews that sounded complete without showing what the agent had actually inspected.

Scan is an instruction-based skill for compatible AI agents. It asks the agent to inventory a target before drawing conclusions, distinguish file coverage from check coverage, cite source evidence, and preserve unanswered questions in a self-contained HTML report.

There's a small synthetic example in the repo. The report shows five fictional files, source-linked observations about a CSV totaler, and checks that were *not* performed. It is deliberately a worked example of the report contract, not proof of a successful autonomous scan on a large real-world codebase.

The report validator and regression tests are Python standard-library code. Scan is static-first and does not authorize executing unknown target code or making silent repairs.

I'd especially value feedback on the coverage model, whether the evidence contract is useful to other agents, and examples of where it fails.

Repo: https://github.com/legendteddy/scan

## Draft: technical Reddit discussion

**Possible title:** I made an AI-agent skill that makes repository review coverage and unknowns explicit

**Body:**

I'm experimenting with a different output contract for AI-assisted project inspections. Instead of just "here are the issues," Scan asks for an artifact inventory, a separate check-coverage matrix, source-linked evidence, and explicit unknowns.

The repo includes a synthetic five-file example and a Python validator for the HTML report's structured state. The demo is illustrative rather than an independent benchmark.

I'm looking for critical feedback: What would make a coverage claim credible to you? Which checks should never be marked "assessed" from static source inspection alone?

Repo: https://github.com/legendteddy/scan

**Posting note:** Read each community's rules before posting; adapt or refrain where self-promotion is disallowed. Never coordinate votes or repost the same copy across communities.

## Draft: personalized maintainer outreach

**Subject:** Feedback request on evidence-backed AI repo reviews

Hi [first name],

I noticed [specific public project or relevant work] and thought you might have a useful perspective on a small open-source experiment.

Scan is an AI-agent skill that separates file inventory from check coverage and asks for source-linked evidence and explicit unknowns in an HTML report. I've included a synthetic example and validator, but haven't established broad real-world reliability yet.

If you're interested, I'd value a critique of the coverage model or a suggestion for a small, public test target. No obligation.

https://github.com/legendteddy/scan

Thanks,
legendteddy

**Privacy note:** Personalize from genuinely public work only. Do not mass-send or imply an existing relationship.

## Proposed 48-hour sequence — after approval

| When | Action | Gate |
|---|---|---|
| Before launch | Merge reviewed PR, verify CI and README commands, check screenshots, proofread claims | Owner approves merge |
| Before launch | Upload assets/social-preview.png in GitHub repository Settings → General → Social preview | Manual UI action; verify appearance |
| Before launch | Consider a v0.1.0 GitHub release with exact scope and limitations | Owner approves release |
| Hour 0 | Publish Show HN as a genuine technical discussion | Owner approves exact text and timing |
| Hours 1–6 | Answer questions with evidence; record reproducible bugs | No vote requests or manufactured engagement |
| Hours 6–24 | One relevant Reddit discussion if rules permit; otherwise skip | Owner approves community and copy |
| Hours 24–48 | Send a few individualized feedback requests to relevant maintainers | Owner approves recipients and messages |
| Hour 48 | Summarize feedback and prioritize fixes | No inflated metrics or unsupported claims |

## Launch measurements

Track weekly and at 48 hours: unique repository visitors (when available), clones, stars (context only), meaningful issues/PRs, independent attempts to run the skill, verified report-validation successes, bug reports and qualitative feedback. Avoid treating stars or votes as proof of product quality.

For a genuine field test, ask volunteers to run Scan on a small public repository and share only material they are authorized to disclose. Compare the report's claimed inventory and check coverage against the source and manual inspection. Record failures, time/tool limits and false confidence. Do not publish private code or secrets.

## Release-note draft — only after approval

**v0.1.0 — initial public skill and evidence contract**

- Instruction-based, static-first whole-project inspection skill.
- Self-contained HTML report template and Scan 1.2 embedded-state contract.
- Python standard-library structural validator with regression tests.
- Synthetic Pocket Ledger worked example with explicit check gaps.
- Limitations: no standalone scanning CLI; report validation does not prove factual accuracy, security, or runtime behavior; host integration varies.

## Final launch gate

- [ ] Pull request reviewed and merged; protected branch intact.
- [ ] CI passes on the merged commit.
- [ ] Example report passes validation and deterministic regeneration check.
- [ ] README installation and quick-start commands verified.
- [ ] Screenshot and social image checked at intended sizes.
- [ ] GitHub social preview uploaded and verified (no public API upload assumed).
- [ ] Claims, privacy and permissions reviewed.
- [ ] Release and community posting separately approved.
