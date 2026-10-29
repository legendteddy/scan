# ScanBench 2.0 ground-truth foundation

ScanBench v1 remains the frozen honesty/integrity benchmark. ScanBench 2.0 adds a separate effectiveness layer for questions v1 deliberately does not answer: did an inspector find a realistic defect, avoid a realistic false positive, preserve a genuine unknown, and avoid false clearance?

## Ground-truth classes

- `must_find` — a consequential condition exists and must be represented by an evidence-backed canonical finding.
- `must_not_find` — a realistic negative control must not be promoted to a finding.
- `must_remain_unknown` — the permitted evidence cannot establish the conclusion, so the state must preserve an explicit unknown.
- `must_not_clear` — the available evidence must not produce a safety/readiness clearance.

## Independent adjudication

The evaluator does not keyword-match finding titles. An external reviewer or benchmark adapter prepares an adjudication that maps each independently reviewed condition to canonical finding, unknown, and evidence IDs. The adjudication is bound to `state_digest`, so it cannot silently be reused against a different Scan state.

For a `found` outcome, valid references and evidence are not enough when the oracle declares `artifact_locators`. The referenced findings/evidence must collectively cover **all** declared ground-truth artifacts. This prevents an unrelated but valid finding elsewhere in the project from satisfying a condition. Artifact-grounding is reported as its own metric rather than being blended into a global score.

## Independent ground-truth review receipts

Corpus membership does not imply that a fixture has received independent review. A separate review receipt can approve a fixture only when it:

- names an independent reviewer and review role;
- covers every current condition ID exactly;
- is bound to a deterministic SHA-256 digest of `truth.json` plus all fixture project files;
- declares `independent_of_fixture_author=true` for an approval.

Any project-file or truth-file mutation invalidates the receipt. This gives oracle review a freshness boundary rather than allowing an old approval to survive changed fixture semantics. The receipt schema is `scanbench/ground_truth/review-receipt-schema-v2.json`.

The repository deliberately does not fabricate approval receipts for its own fixtures. Independent review remains an external evidence requirement for the maturity gate.

### Preparing a real independent review

Generate a neutral request package for a reviewer with:

`python -m scan_core.scanbench2_review prepare FIXTURE_ROOT --output review-request.json`

The request includes the exact fixture digest, condition IDs, requested checks, and a deliberately **non-valid** receipt template. It leaves reviewer identity blank, sets independence to `false`, and defaults the decision to `changes_requested`; therefore generating the request cannot manufacture approval evidence.

After a real reviewer completes the review and returns a receipt, verify it against the current fixture bytes with:

`python -m scan_core.scanbench2_review verify FIXTURE_ROOT review-receipt.json --json`

Verification reuses the same digest, independence, and exact-condition-coverage rules described above.

## External holdout precommitments

A real holdout should not be checked into the public repository before evaluation. Instead, a custodian can publish or otherwise timestamp a small precommitment manifest containing only:

- a holdout set ID and custodian identity;
- each secret fixture's project ID;
- the deterministic fixture SHA-256 digest;
- total condition count;
- counts for the four truth classes.

The manifest deliberately omits source, descriptions, truth details, artifact paths, and condition IDs. This keeps the fixture hidden while committing the custodian to exact bytes and coarse oracle shape before an inspector is evaluated.

Validate a precommitment:

`python -m scan_core.scanbench2_holdout validate HOLDOUT.json --json`

After the fixture is revealed, verify it against the earlier commitment:

`python -m scan_core.scanbench2_holdout verify HOLDOUT.json PROJECT_ID REVEALED_FIXTURE_ROOT --json`

Verification recomputes the same fixture digest used by independent review receipts and checks project identity plus condition/truth-class counts. A changed source file, changed truth file, or rewritten oracle therefore fails verification. Precommitment verification proves fixture identity; it does **not** prove reviewer independence or inspector effectiveness.

The schema is `scanbench/ground_truth/holdout-manifest-schema-v2.json`. Secret holdout fixtures should remain outside this repository until reveal.

## Metrics

Detection recall, negative-control specificity, unknown honesty, false-clearance violations, evidence support, artifact grounding, and reference integrity are published separately. There is no ScanBench quality score.

## Evaluation CLI

`scan bench2 TRUTH.json STATE.json SUBMISSION.json --json`

A failing condition exits with Scan's validation-failed code. The evaluator never executes target code.

## Corpus validation

The corpus is separately validated with:

`python -m scan_core.scanbench2_corpus scanbench/ground_truth --json`

The corpus validator verifies project/fixture identity, globally unique condition IDs, real artifact locators, declared milestone counts, and reports maturity progress without creating a blended score.

### Current public corpus milestone

The current corpus contains **10 projects / 49 conditions** across authorization, data integrity, retry/idempotency, accessibility, documentation-contract drift, test quality, JavaScript webhook verification, TypeScript async-state races, shell/CI command injection, and Go HTTP resource boundaries.

Truth-class totals are 18 `must_find`, 11 `must_not_find`, 10 `must_remain_unknown`, and 10 `must_not_clear` conditions.

This remains a milestone rather than a maturity claim. The project count and condition count stay explicit so benchmark growth cannot be presented as complete before the gate is met.

## Maturity target

`2.0-alpha1` is the evaluation foundation, not a claim that the corpus is mature. The P0 maturity gate remains at least 20 representative projects and 200 realistic independently reviewed conditions with positive controls, negative controls, holdouts, and mutation/oracle-consistency checks.
