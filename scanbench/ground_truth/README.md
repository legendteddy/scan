# ScanBench 2.0 ground truth

This directory is separate from frozen ScanBench v1. It contains independently reviewable ground truth for measuring actual inspection effectiveness.

The alpha evaluator does **not** infer matches from wording. An adjudication binds each ground-truth condition to canonical Scan finding/unknown/evidence IDs from one exact state digest. This avoids training the benchmark around title keywords while keeping the adjudication auditable.

Truth classes are kept separate: `must_find`, `must_not_find`, `must_remain_unknown`, and `must_not_clear`. No blended quality score is permitted.

## Corpus milestone M1

The first corpus milestone contains **6 representative projects and 29 conditions** across:

- object-level authorization;
- destructive data writes and misleading success handling;
- retries and payment idempotency;
- form accessibility and runtime AT uncertainty;
- documentation-versus-code contract drift;
- test-quality and executed-coverage uncertainty.

These fixtures deliberately mix positive conditions, realistic negative controls, repository-invisible operational facts, and conditions that must not be falsely cleared.

Validate the corpus and print separate maturity counters with:

```bash
python -m scan_core.scanbench2_corpus scanbench/ground_truth --json
```

The validator checks fixture/project identity, globally unique condition IDs, declared milestone counts, and that every artifact locator resolves to a real file within its fixture project.

## Maturity gate

M1 is not the mature benchmark. The P0 gate remains at least **20 representative projects and 200 independently reviewed realistic conditions**, with multiple project types/languages, negative controls, holdouts, mutation/oracle-consistency checks, and zero tolerated false-clearance claims.
