# Observed evidence receipt v1

Scan can import runtime/test observations that were already produced by an authorized external system. Import is data-only: Scan does **not** run the target, test runner, browser, package hook, command, or network request while processing the receipt.

## Command

```bash
scan import-observed .scan/state.json observed-receipt.json \
  --output .scan/state-with-observed.json \
  --report .scan/report-with-observed.html \
  --json
```

## Exact binding

A receipt must identify the current Scan `snapshot_digest`; it may also bind the exact base `state_digest`. Every mapped observation carries the exact canonical artifact `content_identity`. Snapshot/state mismatch or a mapped artifact-byte mismatch fails closed.

A safe relative locator that does not map to the current state is retained as an unknown rather than becoming a finding/control. This distinguishes “could not bind this observation” from “the observation is false.”

## External execution and authorization provenance

The receipt records an external executor name/version, execution ID, start/end time, environment label, whether the external system executed the target, and whether it used network access. It also records an authorization attestation with a basis, scope, and reference.

Scan preserves that attestation but explicitly marks `authorization_attestation.verified_by_scan: false`. The importer does not authenticate the approving human/workflow or infer that authorization merely because the receipt says it existed. The import receipt separately records:

- `target_executed_by_scan_during_import: false`
- `network_used_by_scan_during_import: false`

## Observation outcomes

Each observation has one of three outcomes:

- `fail` — observed evidence plus an observed finding;
- `pass` — observed evidence plus an `observed_effective` control limited to the declared case;
- `unknown` — observed evidence plus an explicit unknown.

Passing evidence never clears behavior outside the receipt’s scope. The bundle must declare `coverage.whole_project_complete: false`; `true` is rejected. Imported observed evidence can move an incomplete artifact only to `partial`; it never makes Scan’s whole-project analysis complete.

## Provenance and privacy

Canonical observed evidence uses the SHA-256 digest of the exact receipt bytes as `source_digest`, plus external-tool producer identity and the current artifact-content digest. Semantic text, authorization metadata, execution environment text and coverage descriptions pass through the Scan state’s configured redaction policy.

The importer accepts at most 64 MB, 10,000 observations, and 20,000 characters per semantic text field. Absolute paths, `..`, Windows drive/backslash paths and unanchored evidence locators are rejected.

Identical duplicate external observation IDs in one receipt are ignored after the first. Conflicting reuse of an ID fails closed.

## Minimal receipt

```json
{
  "scan_observed_receipt_version": "1",
  "target": {"snapshot_digest": "sha256:...", "state_digest": "sha256:..."},
  "executor": {"kind": "external-tool", "name": "CI Test Runner", "version": "1.2.3"},
  "authorization": {
    "basis": "workflow-owner approval",
    "scope": "Run one integration test against the authorized fixture",
    "reference": "approval-123"
  },
  "execution": {
    "execution_id": "run-456",
    "started_at": "2026-10-29T02:44:00Z",
    "completed_at": "2026-10-29T02:45:00Z",
    "environment": "isolated test environment",
    "target_executed": true,
    "network_used": false
  },
  "coverage": {
    "scope": "One declared integration test",
    "limitations": "No broader runtime or production behavior observed",
    "whole_project_complete": false
  },
  "observations": []
}
```

This receipt format is not an execution protocol. External systems own execution; Scan owns provenance, snapshot/artifact binding, evidence semantics, unknown preservation and coverage honesty.
