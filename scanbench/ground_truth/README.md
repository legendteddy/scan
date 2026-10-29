# ScanBench 2.0 ground truth

This directory is separate from frozen ScanBench v1. It contains independently reviewable ground truth for measuring actual inspection effectiveness.

The alpha evaluator does **not** infer matches from wording. An adjudication binds each ground-truth condition to canonical Scan finding/unknown/evidence IDs from one exact state digest. This avoids training the benchmark around title keywords while keeping the adjudication auditable.

Truth classes are kept separate: `must_find`, `must_not_find`, `must_remain_unknown`, and `must_not_clear`. No blended quality score is permitted.
