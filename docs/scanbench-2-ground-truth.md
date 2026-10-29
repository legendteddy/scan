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

### Corpus-wide review campaigns

For a full corpus, prepare all neutral requests in one deterministic package:

`python -m scan_core.scanbench2_review_campaign prepare scanbench/ground_truth --output review-campaign.json`

The campaign package contains one normal review request per fixture and **no approval evidence**. Its templates still have an empty reviewer identity, `independent_of_fixture_author=false`, and `decision=changes_requested`.

Store completed receipts as `PROJECT_ID.json` files in a separate receipts directory, then summarize coverage with:

`python -m scan_core.scanbench2_review_campaign coverage scanbench/ground_truth REVIEW_RECEIPTS_DIR --json`

Coverage reports approved projects and conditions separately from `changes_requested`, invalid/stale, and missing receipts. A receipt whose fixture digest no longer matches is counted as invalid, not reviewed. The tool also reports orphan receipt files and whether the independently approved project/condition counts satisfy the corpus numeric target. It does not claim holdout quality or inspector effectiveness, and it never produces a blended quality score.

## Mutation and oracle consistency

Semantics-preserving variants can test whether benchmark behavior depends on incidental source or oracle identifiers. Verify a declared variant with:

`python -m scan_core.scanbench2_oracle_consistency ORIGINAL_FIXTURE VARIANT_FIXTURE CONSISTENCY.json --json`

The consistency manifest binds both fixtures to exact fixture and project-source SHA-256 digests, declares a transformation ID, maps every original condition bijectively to every variant condition, and optionally maps renamed artifact paths. The verifier requires the **project source bytes** to change; changing only `truth.json`, project IDs, or condition IDs is not enough. Under a `semantics-preserving` claim, mapped conditions must retain the same truth class, family, description, rationale, and artifact relationship after path mapping.

This supports randomized condition IDs and equivalent source transformations without allowing oracle drift to pass silently. A successful consistency check proves byte change plus oracle invariance under the declared mapping; it does not independently prove that the transformation preserves runtime semantics. That semantic-equivalence claim still needs reviewer or transformation-method evidence.

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

## Baseline effectiveness ledger

A baseline is a set of exact Scan states plus independently prepared adjudication submissions. The baseline runner re-evaluates every listed project against the **current** fixture truth, records the deterministic fixture digest and state digest, and aggregates raw counts across projects before calculating each metric.

Create a baseline manifest such as:

```json
{
  "scanbench2_version": "2.0-alpha1",
  "baseline_manifest_version": "2.0-alpha1",
  "baseline_id": "scan-static-example",
  "inspector": {"name": "Scan", "version": "0.6.x", "configuration": "documented run configuration"},
  "runs": [
    {"project_id": "authorization-ownership", "state": "states/auth.json", "submission": "submissions/auth.json"}
  ]
}
```

State and submission paths are resolved relative to the baseline manifest and must stay within that directory tree without symlink traversal. Evaluate it with:

`python -m scan_core.scanbench2_baseline scanbench/ground_truth BASELINE.json --json`

The ledger reports corpus coverage, per-project fixture/state identities, pass/fail counts, detection recall, negative-control specificity, unknown honesty, false-clearance violations, evidence support, artifact grounding, and reference integrity separately. A poor baseline remains valid measurement evidence; the command does not turn weak effectiveness into a tool error. Partial baselines are clearly marked and list missing project IDs. The ledger does not establish independent oracle review or holdout custody by itself.

## Evaluation CLI

`scan bench2 TRUTH.json STATE.json SUBMISSION.json --json`

A failing condition exits with Scan's validation-failed code. The evaluator never executes target code.

## Corpus validation

The corpus is separately validated with:

`python -m scan_core.scanbench2_corpus scanbench/ground_truth --json`

The corpus validator verifies project/fixture identity, globally unique condition IDs, real artifact locators, declared milestone counts, and reports maturity progress without creating a blended score.

### Current public corpus milestone

The current corpus contains **26 projects / 209 conditions** across authorization, data integrity, retry/idempotency, accessibility, documentation-contract drift, test quality, JavaScript webhook verification, TypeScript async-state races, shell/CI command injection, Go HTTP resource boundaries, Rust archive extraction confinement, Java outbound HTTP/SSRF boundaries, C native memory/input bounds, Kubernetes privilege boundaries, Ruby account-recovery tokens, SQL migration safety, Kotlin offline synchronization, Terraform destruction/recovery, React checkout state/accessibility, C# message-delivery ordering, privileged GitHub Actions pull-request execution, PHP upload confinement, Swift mobile credential handling, AWS IAM least privilege, GraphQL tenant authorization, and Docker build supply-chain integrity.

Truth-class totals are 82 `must_find`, 43 `must_not_find`, 42 `must_remain_unknown`, and 42 `must_not_clear` conditions.

The public corpus now exceeds both numeric corpus thresholds: **26 projects against a target of 20** and **209 conditions against a target of 200**. This still does **not** establish ScanBench maturity. Genuine independent review receipts, externally custodied holdouts, and baseline effectiveness runs remain required before the P0 gate can close.

## Maturity evidence audit

A local maturity audit can assemble the repository-verifiable evidence without collapsing it into a single score:

`python -m scan_core.scanbench2_maturity scanbench/ground_truth MATURITY.json --json`

The maturity manifest can reference a review-receipts directory, an effectiveness baseline manifest, one or more revealed holdout precommitments, and one or more oracle-consistency checks. Every path is resolved relative to the maturity manifest and is confined against traversal and symlink escapes.

The audit reports these gates independently:

- public corpus numeric threshold;
- independent review coverage;
- effectiveness baseline coverage and its separate metrics;
- holdout precommitment/reveal identity verification;
- mutation/oracle-consistency evidence.

The holdout gate is deliberately conservative: local verification can prove that revealed bytes match the supplied precommitment, but it cannot prove that custody was genuinely external or that the precommitment predates evaluation. The output therefore reports external custody as **not established by this tool** even when reveal identity verifies. Likewise, oracle consistency does not by itself prove runtime semantic equivalence. There is no blended maturity score and no automatic maturity clearance.

## Maturity target

`2.0-alpha1` is the evaluation foundation, not a claim that the corpus is mature. The P0 maturity gate remains at least 20 representative projects and 200 realistic independently reviewed conditions with positive controls, negative controls, holdouts, and mutation/oracle-consistency checks.
