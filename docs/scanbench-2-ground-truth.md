# ScanBench 2.0 ground-truth foundation

ScanBench v1 remains the frozen honesty/integrity benchmark. ScanBench 2.0 adds a separate effectiveness layer for questions v1 deliberately does not answer: did an inspector find a realistic defect, avoid a realistic false positive, preserve a genuine unknown, and avoid false clearance?

## Ground-truth classes

- `must_find` — a consequential condition exists and must be represented by an evidence-backed canonical finding.
- `must_not_find` — a realistic negative control must not be promoted to a finding.
- `must_remain_unknown` — the permitted evidence cannot establish the conclusion, so the state must preserve an explicit unknown.
- `must_not_clear` — the available evidence must not produce a safety/readiness clearance.

## Independent adjudication

The evaluator does not keyword-match finding titles. An external reviewer or benchmark adapter prepares an adjudication that maps each independently reviewed condition to canonical finding, unknown, and evidence IDs. The adjudication is bound to `state_digest`, so it cannot silently be reused against a different Scan state.

## Independent ground-truth review receipts

Corpus membership does not imply that a fixture has received independent review. A separate review receipt can approve a fixture only when it:

- names an independent reviewer and review role;
- covers every current condition ID exactly;
- is bound to a deterministic SHA-256 digest of `truth.json` plus all fixture project files;
- declares `independent_of_fixture_author=true` for an approval.

Any project-file or truth-file mutation invalidates the receipt. This gives oracle review a freshness boundary rather than allowing an old approval to survive changed fixture semantics. The receipt schema is `scanbench/ground_truth/review-receipt-schema-v2.json`.

The repository deliberately does not fabricate approval receipts for its own fixtures. Independent review remains an external evidence requirement for the maturity gate.

## Metrics

Detection recall, negative-control specificity, unknown honesty, false-clearance violations, evidence support, and reference integrity are published separately. There is no ScanBench quality score.

## Evaluation CLI

`scan bench2 TRUTH.json STATE.json SUBMISSION.json --json`

A failing condition exits with Scan's validation-failed code. The evaluator never executes target code.

## Corpus validation

The corpus is separately validated with:

`python -m scan_core.scanbench2_corpus scanbench/ground_truth --json`

The corpus validator verifies project/fixture identity, globally unique condition IDs, real artifact locators, declared milestone counts, and reports maturity progress without creating a blended score.

### Corpus milestone M1

M1 contains **6 projects / 29 conditions** covering authorization, data integrity, retry/idempotency, accessibility, documentation-contract drift, and test quality. It includes 10 `must_find`, 7 `must_not_find`, 6 `must_remain_unknown`, and 6 `must_not_clear` conditions.

This is intentionally a milestone rather than a maturity claim. The project count and condition count remain explicit so benchmark growth cannot be presented as complete before the gate is met.

## Maturity target

`2.0-alpha1` is the evaluation foundation, not a claim that the corpus is mature. The P0 maturity gate remains at least 20 representative projects and 200 realistic independently reviewed conditions with positive controls, negative controls, holdouts, and mutation/oracle-consistency checks.
