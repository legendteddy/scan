# ScanBench 2.0 ground-truth foundation

ScanBench v1 remains the frozen honesty/integrity benchmark. ScanBench 2.0 adds a separate effectiveness layer for questions v1 deliberately does not answer: did an inspector find a realistic defect, avoid a realistic false positive, preserve a genuine unknown, and avoid false clearance?

## Ground-truth classes

- `must_find` — a consequential condition exists and must be represented by an evidence-backed canonical finding.
- `must_not_find` — a realistic negative control must not be promoted to a finding.
- `must_remain_unknown` — the permitted evidence cannot establish the conclusion, so the state must preserve an explicit unknown.
- `must_not_clear` — the available evidence must not produce a safety/readiness clearance.

## Independent adjudication

The evaluator does not keyword-match finding titles. An external reviewer or benchmark adapter prepares an adjudication that maps each independently reviewed condition to canonical finding, unknown, and evidence IDs. The adjudication is bound to `state_digest`, so it cannot silently be reused against a different Scan state.

## Metrics

Detection recall, negative-control specificity, unknown honesty, false-clearance violations, evidence support, and reference integrity are published separately. There is no ScanBench quality score.

## CLI

`scan bench2 TRUTH.json STATE.json SUBMISSION.json --json`

A failing condition exits with Scan's validation-failed code. The evaluator never executes target code.

## Maturity target

`2.0-alpha1` is the evaluation foundation, not a claim that the corpus is mature. The P0 maturity gate remains at least 20 representative projects and 200 realistic independently reviewed conditions with positive controls, negative controls, holdouts, and mutation/oracle-consistency checks.
