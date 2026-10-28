# Complete inspection workflow

## Retrieve without mistaking display limits for access limits

1. Pin the authorized snapshot and enumerate exact artifact paths, types and sizes. Preserve all discoverable members in the embedded manifest even when semantic inspection is incomplete.
2. Request complete content through the authorized connector when supported. Keep the full structured response locally rather than printing an enormous result into the conversation. A truncated tool display does not establish that source retrieval failed.
3. Compare retrieved content length and identity with source metadata where available. Preserve encoding and line endings; a hash mismatch means retrieval is not yet verified. Do not report an unchecked byte stream as an exact original.
4. If actual content is truncated, use supported line/page/range parameters with a recorded interval ledger. Alternatively obtain full bytes through an ordinary authorized read-only connector route. Do not assume a local checkout is required to read source; do not invent unavailable capabilities or bypass an access restriction.
5. Read long files in manageable numbered sections, including the beginning, middle and end; record gaps. For mixed HTML, inspect markup, styles, embedded scripts/modules and structured data separately, then trace their connections. Parse data as inert data; never evaluate it. Keep sensitive raw records out of reports.
6. Continue through every safely readable first-party artifact in a whole-project request. Prioritization determines order, not the final scope. File size, convenience, a coherent architecture, and absence of findings are not by themselves completion boundaries.

Fetching, hashing, keyword searching or parsing a file does not establish semantic analysis. Mark content_read or partial until its relevant behavior/content and connections have been examined. For generated duplicates, document exact equivalence and the substantive analysis being transferred; do not silently skip them. Test source establishes intended assertions, not current passing behavior.

## Spend semantic effort before spending more context

For repeat scans and change-focused work, use the cheapest trustworthy context before reading more source:

1. Consume canonical `delta` first when a validated baseline comparison is available.
2. If `extensions.git_change_scope.priority_paths` is present, inspect those current changed paths early. It is only deterministic prioritization context; it does not establish dependencies, semantic impact or completeness.
3. Reuse prior semantic evidence only through Scan's existing verified-reuse gates. Do not send unchanged bytes back through the same semantic check merely to recreate equivalent evidence.
4. Freshly inspect changed artifacts and then trace only the connected consequential paths needed to understand their effects. Record inferred connections as inferred; do not manufacture a dependency graph from filenames or directory proximity.
5. In `deep`, continue through the remaining safely readable first-party scope after prioritized work. Efficiency may change order and avoid redundant semantic work, but it must not silently narrow whole-project coverage.

Do not invent universal numeric token budgets or claim savings that were not measured for the actual host/model. If a real context, time, access, privacy or resource boundary prevents finishing a requested `deep` scan, stop with explicit partial coverage and prioritized remaining work rather than treating the budget as evidence of completion.

## Preserve the original depth of reused evidence

Open the prior report's actual artifact record and supporting evidence. Match the source identity, original method, inspected ranges/depth, timestamp and limitations. Keep the substantive evidence in the new HTML.

- Prior full relevant semantic analysis may support analyzed + verified_reuse after identity verification.
- Prior sampling or a truncated read supports at most partial, even when the current blob is unchanged.
- Prior metadata supports metadata_only. Prior unknowns remain unknown until resolved.
- If the old status and prose disagree, preserve the weaker supported depth, record the conflict and inspect fresh when possible.
- If the original record is unavailable, use unverified_carryover or inspect again. Never reconstruct stronger provenance from memory or a newer report's assertion.

Example: an old manifest lists validators.js as sampled. A new matching blob hash proves that file is unchanged; it does not justify relabeling the earlier read as deep/analyzed. Read it fully now, or preserve partial status and its limits.

## Decide when a report is ready

For each remaining first-party text file, determine whether a concrete boundary actually prevents further inspection. Examples include denied access, unsupported encryption, a parser safety/resource limit, or a documented tool capability limit after reasonable supported read-only alternatives. Explain the affected paths/ranges, actual limit, attempted routes and impact. Do not execute target code, evade restrictions, or weaken privacy protections to finish a checklist.

If ordinary supported reads remain available and no boundary applies, continue inspection before finalizing. Do not repeatedly repackage the same partial baseline as a new completed scan. An authorized quick/sample scan may stop at its declared scope; do not silently convert a whole-project request into one. If a real boundary prevents completion, deliver an honest partial report with precise continuation steps rather than fabricate completeness.

Derive metrics from final records: analyzed AND fresh; analyzed AND verified_reuse; partial; metadata_only; other statuses. Reconcile totals and keep source-file counts distinct from external metadata artifacts and grouped collections. Explain justified exclusions without counting them as examined.

Before delivery, manually check both the visible report and embedded state for: unsupported status upgrades, rewritten historical depth, fresh labels containing reused work, unread principal artifacts, claims based on truncated content, and missing manifest members. Structural validation cannot establish these facts on its own.
