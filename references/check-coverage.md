# Check coverage — separate from file coverage

Read this reference when planning and validating every scan. Create a target-specific check plan before deep inspection and update it as new components, workflows or risks are found. Keep the plan and final results in the HTML's required `checks` collection. Reading every file does not imply that every relevant concern was assessed.

## Required category accounting

Account for every category below with at least one check row. Split broad categories into concrete checks for consequential components and journeys; one superficial umbrella row is not adequate. Add target-specific categories as needed. These categories organize analysis; they do not force the visible report into fixed sections.

| category | Assessment prompts |
|---|---|
| purpose_and_scope | Intended purpose, audience, claimed behavior, assumptions, snapshot and boundaries |
| inventory_and_provenance | Full membership, origins, versions, generated outputs, linked resources, missing bytes, submodules/LFS/nested contents where present |
| architecture_and_flows | Components, dependencies, interfaces, important end-to-end journeys, data transformations, external processors, trust boundaries |
| correctness_and_integrity | Rules, invariants, contradictions, data consistency, boundary inputs, partial failures, concurrent operations where relevant |
| security_and_trust | Entry points, permissions, authentication/authorization, injection, unsafe parsing/loading, secrets, package integrity |
| privacy_and_data_lifecycle | Sensitive fields, collection, storage, sharing, retention, deletion, access and derived copies |
| dependencies_and_licensing | Direct/transitive dependencies, exact versions, external assets/services, provenance, licenses, current advisory checks where identifiable |
| testing_and_reliability | Critical behavior mapped to assertions/evaluation, negative/failure cases, historical versus current results, unchecked assumptions |
| performance_and_resources | Resource bounds, scale, large inputs, latency/memory/size assumptions; separate static risks from measurements |
| maintainability | Duplication, change propagation, configuration drift, modularity, documentation/current-state consistency |
| usability_and_accessibility | Main user journeys, content clarity, navigation, keyboard/assistive access and relevant presentation limits |
| operations_and_recovery | Installation/environment reproduction, migrations, backups/restore, rollback, monitoring, operational ownership where applicable |
| release_and_distribution | Build/package identity, signing/update path, release gates, source-to-distributed/deployed correspondence |
| content_and_data_quality | Claim/source validity, document versions, attribution, dataset/model provenance, schemas, leakage/bias/evaluation concerns where applicable |

A category may genuinely not apply, such as keyboard interaction in a standalone noninteractive numeric dataset. Give a target-specific reason. Lack of permission, missing tools, missing files, limited time or unreadable content is not “not applicable.” A dependency manifest not being found is not proof that dependencies do not exist.

## Check record semantics

Use `status` independently from severity, findings and verification state:

- `assessed`: the stated check was completed for its explicit scope/method and has supporting evidence. It may discover a problem. It never means the whole category or project passed.
- `partial`: useful work was performed, but identified parts of the stated check remain unfinished. Record inspected and missing portions.
- `not_assessed`: relevant work was not performed. Explain why and the next safe step.
- `blocked`: a concrete access/safety/capability boundary prevented the check. Record the boundary and ordinary safe routes attempted; do not bypass it.
- `not_applicable`: the concern genuinely does not apply to this target, with a reason. Never use it to hide an unknown or scoped-out but relevant concern.

Record `id`, `category`, `title`, `status`, `scope`, `method`, `artifact_ids`, `evidence_ids`, `related_ids`, `verification_state`, `result`, `limitations`, `reason`, and `next_step` on every row. Use arrays for references. `related_ids` links relevant findings, controls, unknowns or actions; it may be empty. Use `next_step: null` only for assessed/not_applicable rows; unfinished rows need a substantive next step. `reason` must explain the status for this target, including applicability or the concrete blocker.

Assessed and partial checks require substantive evidence. A static source read can assess “which guards are implemented,” but cannot assess “guards work at runtime.” Keep those as separate checks when runtime effectiveness matters; leave unauthorized execution unassessed or blocked. Observed verification needs observed evidence. Do not invent checks performed or run target code to make the matrix look complete.

## End-to-end and external boundaries

For each consequential journey, record input → permission/validation → transformation/storage → output/consumer, plus failure/recovery behavior and relevant test evidence. For a document collection, adapt this to source → claim/content → revision/approval → published output. Name external components as their actual endpoints rather than pointing edges at an unrelated internal component.

Resolve or explicitly bound references beyond the immediate folder: linked documents, third-party packages, external services, generated assets and deployed artifacts. Stay within authorization; preserve unresolved destinations as unknowns.

## Complete the report

Derive `coverage.counts_by_check_status` from check rows. Set `coverage.checks_complete` true only when every planned applicable check is assessed and every required category has a justified row; blocked/partial/not_assessed rows prevent it. This is completeness of the declared check plan, never proof that the plan anticipated every possible issue. Do not mark artifact analysis incomplete merely because an unexecuted runtime check remains; report the distinct dimensions honestly.

Add a visible “What was checked” matrix using the existing dashboard/table patterns. Show plain-language check, scope/method, status, result/limits and readable evidence locators. Put consequential unknowns near the verdict. Never use an assessed count as a health/pass percentage or hide failed findings behind a green completion badge. Make category omissions, broad unsupported check scopes, stale evidence and missing runtime measurements explicit during semantic review.
