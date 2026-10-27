# Default Scan dashboard design

Use `assets/report-shell.html` as the starting file for new reports unless the user explicitly requests a different style. Read its source before filling it. The shell preserves the user-approved dashboard visual foundation; it contains no project data or inherited conclusions.

## Preserve the visual identity

- Keep the large dark navy gradient hero, soft blue/violet ambient accents, light gray page, white rounded cards, spacious section rhythm and prominent typography.
- Keep fact cards, compact status pills, a connected anatomy view, strength cards, component cards, a dark coverage panel and numbered action cards where relevant.
- Preserve the 1240px desktop canvas, 28–38px primary radii, roughly 58px hero padding, 48–86px hero headline and broad gaps between sections. Let mobile rules reduce density naturally.
- Use gradients and shadows quietly. Avoid neon/cyber decoration, a generic white-header memo, dense audit-document styling, or collapsing the whole report into tables.
- Use tables for exact inventory/evidence and comparison details. Keep the primary narrative visual, plain-language and readable without expanding drawers.

## Adapt content within the design

Reorder, add or remove sections and change headings to fit repositories, websites, documents, packages and mixed collections. Do not force six metrics, three actions, nine map nodes or a financial section. Use only meaningful, supported counts. Never copy the old report's findings, financial amounts, project names, private content or health claims.

Treat the anatomy view as a real relationship diagram: arrows must represent evidenced connections, with clear direction and meaning. Do not join unrelated components just to fill a row. At most three node cards per row in this shell; use an accessible labeled SVG or another layout when branching needs it. Label inferred connections and provide evidence locators in ordinary visible captions.

Put incomplete analysis and critical unknowns near the verdict. Use labels such as “implemented; effectiveness unverified” when only static support exists. A green pill or glowing status dot must not imply a live connection, current PASS or verified effectiveness without evidence. The shell intentionally omits the original live indicator.

Use semantic headings and text alternatives for diagrams. Keep contrast readable, metadata wrap-safe, keyboard focus visible, mobile content complete and print layouts usable. Do not hide evidence columns on mobile. Keep core facts available without JavaScript.

## Populate and check

Escape ordinary text slots. Generate *_HTML slots only from agent-authored markup containing escaped data. Serialize STATE_JSON using the report contract's escaping rules. Fill or remove every `{{...}}` placeholder; do not ship the unfinished shell. Use the current supported Scan state contract (currently 1.3 for new reports), populate the dynamic `STATE_SCHEMA_VERSION` slot from the embedded state, and validate the report. The historical 1.2 demo remains historical. The shell is presentation scaffolding, not evidence and not a valid report until populated.

Inspect desktop, narrow-screen and print output when rendering tools are available. Check hero wrapping, card height, anatomy labels/arrows, evidence tables and consistency of visible/embedded counts. If rendering is unavailable, record that limit rather than claiming visual verification. Never weaken evidence requirements to preserve a visual arrangement.

## Component markup contract

Read `assets/report-components.html` before filling HTML slots. Copy the supplied metric/control/table patterns rather than guessing their child structure. Keep CSS and markup changes together.

Keep metric labels, values and notes on separate block rows. Use `metric-code` for a long identifier; ordinary words must wrap only at natural boundaries. Use fewer columns at intermediate widths rather than breaking “BLOCKED” or “Reachable” into fragments.

Keep control status, title, explanation and evidence in a single flowing column. Never put prose or multiword statuses in the old narrow numbered-icon grid. Evidence tables need distinct keyboard-focusable horizontal scroll regions, reasonable minimum column widths and normal word wrapping; only long machine identifiers/URLs may break within a token. Do not apply `overflow-wrap:anywhere` to ordinary prose or enum labels such as “observed”.

Inspect the populated report, not just the empty shell. Specifically check label/value separation, status/title overlap, long descriptions, normal words in enum columns, desktop and intermediate-width card grids, and narrow-screen table scrolling. Schema validation does not detect layout failures. If browser rendering is unavailable, perform structural component checks and disclose the visual limit.

## Check-coverage presentation

Include a visible “What was checked” section, using the existing appendix and keyboard-focusable table-scroll patterns. Use plain-language labels for the five check statuses. Keep scope, method, result/limitations and evidence readable; detailed machine category/ID strings can stay in the appendix. Check-completion counts must not imply project health or current test success. Preserve the established visual identity.
