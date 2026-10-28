# Scan report reading experience

Use `assets/report-shell.html` for new authored reports and the packaged
`src/scan_core/report/shell.html` for Core rendering. Keep their bytes synchronized;
packaging uses the latter directly. Current authoring version: **1.4**.
Historically accepted validation versions: **1.2 and 1.3**, plus current 1.4.
The current supported state contract is currently 1.4 for new reports. Historical
1.2 examples and their frozen generator/shell remain unchanged.

## Reading order and visual system

A reader should first learn what was inspected, what matters, what changed, what
is unknown, what to do, and where the proof lives. Use this order:

1. Executive verdict (`#verdict`): one H1 naming the target, one concise canonical
   condition, at most four essential facts, explicit unknown/readiness notice.
2. Top findings (`#findings`): severity, evidence type, title, impact and next step
   stay visible; confidence, limits and evidence use native disclosure.
3. What changed (`#changes`): Scan baseline delta, evidence freshness, and Git
   advisory scope are distinct blocks. Resolved means absent now, never fixed.
4. Coverage and unknowns (`#coverage`, `#unknowns`): discovery, content reading,
   fresh/reused analysis, limited depth, unfinished checks and runtime evidence
   remain distinct. Unknowns carry impact and a safe next step.
5. Architecture (`#architecture`): every canonical relationship has named source,
   type, target, explanation, confidence, verification state and evidence. Artifact
   endpoints are valid even without components. Lists avoid invented/spaghetti
   edges; beyond eight relationships, a labeled disclosure retains every row.
6. Recommended actions (`#actions`): at most five distinct priorities, from
   canonical actions or finding/unknown next steps. Preserve the complete set in
   audit receipts. Do not infer new remediation from file names or empty findings.
7. Audit appendix (`#audit`): native closed details hold checks, all findings,
   unknowns, relationships, inventory, ledger, controls, actions/continuation,
   baseline/reuse, full metadata and complete technical records.

Keep Scan's navy identity and blue evidence links. Use flat surfaces, restrained
system typography, four-pixel radii, clear spacing and readable prose. The shell
has one token system for page/reading widths, spacing, type, colors, borders,
focus, surfaces and code. Do not append override/patch layers, restore the former
gradient/glass dashboard, add progress decoration, or invent a universal score.

## Disclosure, anchors and accessibility

No script is required to read the report, navigate or reveal receipts. Keep native
`details` / `summary`; avoid an accordion that closes other evidence. Evidence
anchors retain `e-<canonical ID>`. All findings have `f-<ID>` anchors in the full
finding disclosure; unknowns and relationships have `u-<ID>` / `r-<ID>` anchors.
Source locators and complete evidence IDs stay linked. Preserve prior section
anchors such as `verdict-title`, `changed-title`, `checks-title`, `evidence-title`,
`anatomy-title`, `parts-title`, `unknowns-title`, `mode-title` and `privacy-title`.

Chromium reveals the ancestor disclosures on fragment navigation and browser
Find. Native browser behavior varies; readers can always open disclosures using
the keyboard. Keep one H1, semantic heading order, one main landmark, visible
focus, a skip link, semantic navigation anchors, text severity labels, and 44px
navigation/summary targets. No ARIA replacement for native disclosure behavior.

At 390px, primary content is stacked and never requires horizontal scrolling.
At 768/1024/1280/1536px, let summary columns grow within the page width. Only
explicitly labeled audit table regions may scroll horizontally; retain all columns
and make the region keyboard focusable. Long paths/IDs wrap without breaking
ordinary prose into character fragments. Table headings use `scope="col"`.

## Print

Print hides sticky navigation and the skip link, removes the dark header fill,
keeps severity text and references, and repeats table headers. Print CSS expands
closed details, including the ledger, all findings and inventory. Full technical
JSON, duplicate unknown receipts and duplicate relationship receipts are omitted
from print because the same information is already rendered in readable records;
they remain in HTML and in the authoritative embedded state. Baseline, source,
action and continuation receipts remain printable. No evidence rows are removed.
Full audit PDFs can be long. Chromium is captured; other print engines may need
manual disclosure expansion and remain an explicit review limit.

## Acceptance

Run the full Core and historical suites, Phase A gates, package/install gates and
`git diff --check`. `tests/test_report_ux.py` adds stdlib assertions for reading
order, links/IDs, complete findings/relationships, native disclosure, counts,
state preservation, deterministic rendering and primary/audit separation.
The safety validator is unchanged and is not an aesthetics score.

For visual acceptance (optional development dependencies only):

```console
python -m pip install playwright
python -m playwright install chromium
python scripts/build_report_review.py --output <review>/reports --self-scan
python scripts/capture_preview.py <review>/reports/scan-on-scan.html --output <review>/captures
```

Pass additional report paths to capture every fixture at all five widths. Use
`--before <old-rendered-report.html>` for a fair comparison using the same canonical
state. The builder generates small, many-findings, long-locator/ID, large-inventory,
large-ledger, repeat-baseline, verified-reuse, unknown-heavy and zero-findings with
unknowns cases. Synthetic cases are labeled; the optional self scan inventories
Scan without executing it and adds only the explicitly documented limited source
review. It does not claim complete semantic analysis.

`capture_preview.py` asserts primary width and descendant overflow, contained
expanded audit tables, state equality, anchors, scopes, no remote requests,
keyboard focus/disclosure and evidence deep links with JavaScript disabled. It
captures closed-details print PDFs for self review, many findings and long IDs.
CI uploads these reports, captures and exact browser receipt as review artifacts.
Inspect screenshots and PDF pages manually. Passing automation is not owner
acceptance, and no UI quality score is produced.
