# Agent feedback and test receipts

Scan includes a privacy-safe post-run contribution protocol for AI agents using the skill. The purpose is to preserve real-world test outcomes, product feedback, and reproducible Scan issues instead of losing them at the end of an agent session.

## Required agent behavior

After completing a Scan task, a capable agent should create one contribution receipt. A receipt may contain:

- bounded test outcomes such as `scan validate=pass`;
- concise feedback about Scan itself;
- concise Scan product issues observed during the run;
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

There is no covert telemetry.

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

Agents should report whether the receipt was `submitted`, recognized as a `duplicate`, or `queued` locally.

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
