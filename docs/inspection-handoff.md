# Inspection handoff bundle v1

A Scan handoff is a deterministic, bounded projection of one validated Scan state for a new AI agent. It answers what snapshot the work belongs to, what has been established, what remains unknown, which checks are unresolved, and what the next safe work is—without copying project source bytes or raw evidence-result payloads.

The full Scan state remains the source of truth. A handoff is never a replacement state and never upgrades coverage.

## Create a handoff

```bash
scan handoff .scan/state.json \
  --output .scan/handoff.json \
  --section-limit 100 \
  --ref-limit 12 \
  --text-limit 800 \
  --json
```

Without `--json`, Scan prints a short human-readable summary. `--output` is optional.

## Exact identity

Every bundle carries:

- Scan schema version;
- exact canonical `state_digest`;
- snapshot digest;
- Scan ID and version;
- scan mode and completion time;
- a deterministic `handoff_digest` over the projection.

A receiving agent should treat the handoff as stale whenever the current Scan state or snapshot differs from those identities.

## What is included

The projection includes bounded records for findings, controls, unknowns, checks and actions; coverage/readiness limits; continuation fields; and only the artifact/evidence metadata referenced by the included semantic records.

Finding and unknown rows retain their artifact/evidence IDs. Referenced evidence includes locator, kind, provenance, source digest, artifact-content digest, freshness, method, limitations and a bounded semantic claim. It intentionally omits the evidence `result` field so raw result payloads/excerpts are not copied into the handoff. Referenced artifacts include locator, status, content identity and redaction state, not file bytes.

The continuation section preserves completed work, remaining work, hypotheses, decisions, revalidation needs, source needs and authorization notes.

## Honest truncation

Each bounded section and reference list reports `total`, `included` and `omitted`. If any record, reference, list or text field is truncated, the top-level projection says:

- `truncated: true`;
- `projection_complete: false`;
- exact deterministic `truncation_reasons`.

This means “not all full-state continuation detail is present,” not that the underlying Scan state is incomplete. The full state identified by `identity.state_digest` remains authoritative.

Default bounds are 100 primary records per section, 12 references per record and 800 characters per compact text field. Hard ceilings prevent callers from silently making the handoff unbounded. The encoded projection also has a 4 MB ceiling; an oversized projection fails closed and asks the caller to reduce limits rather than silently dropping dependency metadata.

## Safety boundary

The bundle declares `contains_source_bytes: false` and `contains_raw_evidence_results: false`. It does not execute target code, make network requests or authorize runtime verification. Existing redaction in the canonical Scan state remains in effect; the handoff does not reopen omitted or redacted source material.

## Intended use

Use the handoff when transferring an inspection to another agent or session that should understand the established evidence and next work without loading the full state first. Use the full state when the receiving system needs every artifact, every evidence record, exact complete checks, or any detail omitted by the bounded projection.
