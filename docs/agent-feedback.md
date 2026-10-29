# Agent feedback and test receipts

Scan includes a privacy-safe post-run contribution protocol for AI agents using the skill. The purpose is to preserve real-world test outcomes, product feedback, and reproducible Scan issues instead of losing them at the end of an agent session.

## Required agent behavior

After every Scan task, every capable AI agent **must** create one contribution receipt before finishing, including when the scan or validation itself failed. This is a normal completion requirement, not optional telemetry cleanup. Each receipt must contain at least one actual observed test/validation outcome. It should also include concise feedback about Scan itself and concise Scan product issues when those were genuinely observed; agents must not invent feedback or issues merely to populate fields.

A receipt may contain:

- bounded test outcomes such as `scan validate=pass`;
- concise feedback about Scan itself when present;
- concise Scan product issues observed during the run when present;
- optional agent/host names;
- an optional digest and schema version of the generated Scan state.

A receipt must **not** contain inspected project source, raw state JSON, credentials, arbitrary logs, private records, or absolute target paths.

Run:

```bash
python -m scan_core.feedback \
  --state .scan/state.json \
  --agent "your-agent-name" \
  --host "your-host-name" \
  --test "scan validate=pass" \
  --feedback "Concise Scan-product feedback" \
  --issue "Concise reproducible Scan issue" \
  --submit auto \
  --json
```

`--feedback` and `--issue` are repeatable. `--test` accepts `NAME=RESULT`, where result is `pass`, `fail`, `partial`, `skipped`, or `unknown`.

Even when there is no feedback or issue, record the test outcome so Scan can distinguish successful use from silent abandonment.

## Submission policy

There is no covert telemetry. Capable agents should use `--submit auto` for the required post-run receipt. In `auto` mode, Scan submits automatically when the caller/host has already authorized submission; otherwise the same canonical receipt is queued locally rather than silently dropped.

`--submit auto` submits to GitHub only when the caller/host has explicitly enabled submission with:

```text
SCAN_FEEDBACK_SUBMIT=1
```

and an existing `SCAN_FEEDBACK_GITHUB_TOKEN`, `GITHUB_TOKEN`, or `GH_TOKEN` is available. The token is never written into the receipt.

`--submit github` is an explicit one-run authorization to attempt GitHub submission. Agents must use it only when the user/host policy already authorizes that external write.

`--submit never` always records locally.

Target-controlled `.scan/config.toml` cannot enable feedback submission.

## Local receipts and outbox

Every invocation writes the canonical receipt under:

```text
~/.scan/feedback/receipts/
```

If submission is disabled or fails, the same receipt is preserved under:

```text
~/.scan/feedback/outbox/
```

The root can be changed with `SCAN_FEEDBACK_HOME` or `--feedback-home`.

When submission becomes authorized, retry a bounded batch of queued receipts with:

```bash
python -m scan_core.feedback --flush --submit auto --json
```

`--flush` uses the same authorization policy as a new receipt. It validates the queued receipt structure and fingerprint, compares the queued copy with the canonical receipt under `receipts/`, and only then attempts GitHub submission. A `submitted` or `duplicate` result removes the outbox copy but preserves the canonical receipt. Invalid, tampered, or failed submissions remain queued and are reported. Each invocation processes at most 20 queued receipts so one agent session cannot create an unbounded burst of external writes.

Agents should report whether the current receipt was `submitted`, recognized as a `duplicate`, or `queued` locally, and report outbox flush failures or invalid receipts when present.

## GitHub behavior

The default destination is `legendteddy/scan`. `SCAN_FEEDBACK_REPOSITORY=owner/repo` can change the destination under host control.

Before opening an issue, Scan searches for the deterministic receipt fingerprint. Equivalent receipts are therefore deduplicated instead of creating repeated issues.

The public issue body includes only bounded receipt fields. It does not upload the inspected target or raw Scan report/state.

## Privacy boundary

The contribution protocol is product telemetry only in the literal sense that a user/host may choose to submit a structured product feedback issue. It is not automatic collection by Scan and it does not run a background service.

Agents must not copy target-derived evidence into `--feedback` or `--issue`. Describe Scan behavior generically, for example:

- good: `Validator error did not identify the missing evidence ID.`
- bad: `Customer ABC's private src/payroll.py contained ...`

The implementation also redacts common credential patterns and absolute filesystem paths as a defense in depth measure, but agents remain responsible for not placing private target content into product feedback in the first place.
