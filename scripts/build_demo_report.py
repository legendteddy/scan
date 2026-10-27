#!/usr/bin/env python3
"""Build the deterministic, synthetic Scan example (stdlib only).

This is a hand-reviewed *example* of the Scan report contract, not a scanner
engine. It refuses changed fixture source or stale generated output.
"""
import argparse
from collections import Counter
from hashlib import sha256
from html import escape
import json
from pathlib import Path
import re

from validate_report import CHECK_CATEGORIES, validate

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "examples" / "demo-project"
OUTPUT = ROOT / "examples" / "demo-report.html"
SHELL = ROOT / "assets" / "report-shell.html"
INSPECTED_AT = "2026-10-27T07:34:00Z"
FILES = (
    "README.md",
    "ledger.py",
    "data/orders.csv",
    "pyproject.toml",
    "tests/test_ledger.py",
)
FILE_IDS = {name: "artifact-" + str(index) for index, name in enumerate(FILES, 1)}
LABELS = {
    "README.md": "Fixture purpose and limits",
    "ledger.py": "CSV loader, float tally and CLI",
    "data/orders.csv": "Three invented order records",
    "pyproject.toml": "Package metadata and dependencies",
    "tests/test_ledger.py": "Two happy-path unit tests",
}


def h(value):
    return escape(str(value), quote=True)


def sha(data):
    return sha256(data).hexdigest()


def load_fixture():
    actual = {
        p.relative_to(FIXTURE).as_posix()
        for p in FIXTURE.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"
    }
    if actual != set(FILES):
        raise ValueError(f"Fixture membership changed: missing={set(FILES)-actual}, extra={actual-set(FILES)}")
    content = {name: (FIXTURE / name).read_text(encoding="utf-8") for name in FILES}
    anchors = {
        "ledger.py": ('float(row["amount"])', 'csv.DictReader(source)', 'sys.argv[1]'),
        "tests/test_ledger.py": ("def test_one_amount", "def test_empty_rows"),
        "pyproject.toml": ("dependencies = []",),
        "data/orders.csv": ("ORDER-001,0.10", "ORDER-003,2.50"),
    }
    for name, needles in anchors.items():
        for needle in needles:
            if needle not in content[name]:
                raise ValueError(f"Evidence anchor changed in {name}: {needle}")
    return content


def build_state(content):
    file_hashes = {name: sha(content[name].encode("utf-8")) for name in FILES}
    manifest = "\n".join(f"{name}\t{file_hashes[name]}" for name in FILES)
    snapshot_hash = sha(manifest.encode("utf-8"))
    artifacts = []
    for name in FILES:
        artifacts.append({
            "id": FILE_IDS[name], "locator": "examples/demo-project/" + name,
            "type": Path(name).suffix.lstrip(".") or "text",
            "status": "analyzed",
            "reason": "Entire small synthetic source file read; static interpretation only",
            "evidence_ids": [], "inspection_origin": "fresh",
            "inspected_at": INSPECTED_AT, "content_identity": "sha256:" + file_hashes[name],
        })
    evidence_specs = [
        ("e-purpose", "README.md", "README.md:1-5", "Fixture is fictional",
         "README identifies the example as a synthetic CSV totaler", "Read entire file"),
        ("e-float", "ledger.py", "ledger.py:6-9", "Currency values are converted to binary floats",
         'total_amount uses sum(float(row["amount"]) for row in rows)', "Static source read"),
        ("e-parse", "ledger.py", "ledger.py:11-14", "CLI reads CSV rows without explicit row validation",
         "main opens a caller-supplied path, passes DictReader rows to total_amount and prints a formatted total; no exception handler appears in this file", "Static source read"),
        ("e-data", "data/orders.csv", "data/orders.csv:1-4", "Fixture records are invented",
         "Three ORDER-prefixed rows contain amount strings 0.10, 0.20 and 2.50", "Read entire CSV"),
        ("e-tests", "tests/test_ledger.py", "tests/test_ledger.py:11-16", "Tests cover two happy paths",
         "One amount and empty rows are asserted; malformed amount, missing column and rounding edge cases are absent from this file", "Read entire test file"),
        ("e-deps", "pyproject.toml", "pyproject.toml:1-6", "No third-party dependencies declared",
         "Project metadata declares an empty dependencies list; this is not a supply-chain audit", "Read entire manifest"),
        ("e-cli", "ledger.py", "ledger.py:16-20", "CLI expects one path argument",
         "The __main__ block checks the argument count and calls main with sys.argv[1]", "Static source read"),
        ("e-boundary", "README.md", "README.md:15-24", "Fixture warns against production finance use",
         "README labels the report as a worked example and warns not to use the program for real accounting", "Read entire file"),
    ]
    evidence = []
    for ident, name, locator, claim, result, method in evidence_specs:
        evidence.append({
            "id": ident, "artifact_id": FILE_IDS[name],
            "locator": "examples/demo-project/" + locator, "kind": "static",
            "claim": claim, "result": result, "method": method,
            "time": INSPECTED_AT,
            "limitations": "Source read only; no execution or runtime observation",
            "inspection_origin": "fresh",
        })
        next(a for a in artifacts if a["id"] == FILE_IDS[name])["evidence_ids"].append(ident)

    findings = [
        {"id": "finding-float", "title": "Floating-point totals need verification",
         "impact": "Decimal currency amounts can be represented imprecisely in binary floats; the source uses float for a money-like total.",
         "severity": "medium", "confidence": "high", "verification_state": "static",
         "artifact_ids": [FILE_IDS["ledger.py"]], "evidence_ids": ["e-float"],
         "uncertainty": "No incorrect monetary result was demonstrated; rounding and runtime behavior were not tested.",
         "recommendation": "Use decimal.Decimal with explicit rounding rules for financial use.",
         "safe_verification": "With approval, run edge-case unit tests on synthetic values in an isolated environment."},
        {"id": "finding-input", "title": "Malformed CSV handling is not specified",
         "impact": "Missing or nonnumeric amount cells may cause an exception instead of a useful input error.",
         "severity": "low", "confidence": "high", "verification_state": "static",
         "artifact_ids": [FILE_IDS["ledger.py"], FILE_IDS["tests/test_ledger.py"]],
         "evidence_ids": ["e-parse", "e-tests"],
         "uncertainty": "Exact runtime error messages and recovery behavior were not observed.",
         "recommendation": "Validate headers and numeric fields; document errors and add negative tests.",
         "safe_verification": "Add malformed synthetic rows and test expected handling before using real input."},
    ]
    controls = [
        {"id": "control-stdlib", "description": "CSV parsing uses the Python standard library",
         "artifact_ids": [FILE_IDS["ledger.py"], FILE_IDS["pyproject.toml"]],
         "evidence_ids": ["e-parse", "e-deps"],
         "effectiveness_status": "implemented_unverified",
         "limitations": "Static import/manifest evidence only; not a full dependency or runtime safety audit."},
        {"id": "control-cli", "description": "CLI checks that one argument was supplied",
         "artifact_ids": [FILE_IDS["ledger.py"]], "evidence_ids": ["e-cli"],
         "effectiveness_status": "implemented_unverified",
         "limitations": "Does not establish that the path exists, is readable, or contains valid CSV."},
    ]
    unknowns = [
        {"id": "unknown-rounding", "question": "How does rounding behave for edge-case amounts?",
         "artifact_ids": [FILE_IDS["ledger.py"]], "evidence_ids": ["e-float"],
         "reason": "No execution or precision-specific test was performed",
         "impact": "A money-like total may not meet accounting requirements",
         "next_safe_step": "Test synthetic rounding cases and define a Decimal-based policy"},
        {"id": "unknown-errors", "question": "What happens on missing columns and malformed rows?",
         "artifact_ids": [FILE_IDS["ledger.py"], FILE_IDS["tests/test_ledger.py"]],
         "evidence_ids": ["e-parse", "e-tests"],
         "reason": "Only happy-path tests are present; runtime error paths not exercised",
         "impact": "Input failures may be hard for users to diagnose",
         "next_safe_step": "Add negative unit tests with invented inputs"},
        {"id": "unknown-operations", "question": "Would this be suitable to distribute or operate?",
         "artifact_ids": [FILE_IDS["pyproject.toml"]], "evidence_ids": ["e-deps"],
         "reason": "No package build, release, performance or operational review was performed",
         "impact": "Release readiness is not established",
         "next_safe_step": "Define distribution requirements before considering a release"},
    ]
    actions = [
        {"id": "action-decimal", "description": "Define precision and rounding policy; consider Decimal instead of float",
         "priority": "high", "related_ids": ["finding-float", "unknown-rounding"],
         "prerequisites": ["Agree on intended numeric semantics"],
         "authorization_requirements": "Any code modification requires owner approval",
         "expected_verification": "Precision edge-case tests and reviewed outputs",
         "completion_state": "proposed"},
        {"id": "action-negative-tests", "description": "Add validation and negative tests for malformed CSV",
         "priority": "medium", "related_ids": ["finding-input", "unknown-errors"],
         "prerequisites": ["Define expected error behavior"],
         "authorization_requirements": "Any code modification or execution requires owner approval",
         "expected_verification": "Malformed synthetic CSV cases produce documented errors",
         "completion_state": "proposed"},
        {"id": "action-release", "description": "Assess performance and distribution only if the fixture becomes a real tool",
         "priority": "low", "related_ids": ["unknown-operations"],
         "prerequisites": ["Real-world use case and operating constraints"],
         "authorization_requirements": "Explicit approval for dynamic checks and distribution",
         "expected_verification": "Reproducible package and documented runtime limits",
         "completion_state": "deferred"},
    ]
    # This matrix describes specific checks, not an all-clear verdict.
    specs = {
        "purpose_and_scope": ("Purpose and boundaries", "assessed", ["e-purpose", "e-boundary"], "Read fixture README", "Synthetic scope and intended non-production use documented"),
        "inventory_and_provenance": ("Five-file source inventory", "assessed", ["e-purpose", "e-data", "e-deps"], "Enumerate and hash fixture files", "All five fixture source files accounted for"),
        "architecture_and_flows": ("CSV-to-total path", "assessed", ["e-parse", "e-float", "e-cli"], "Trace Python call path statically", "Input path, CSV parsing, float sum and output mapped"),
        "correctness_and_integrity": ("Arithmetic and malformed data", "partial", ["e-float", "e-parse"], "Read arithmetic and input path", "Float and missing validation noted; edge-case outcomes untested"),
        "security_and_trust": ("File input trust boundary", "partial", ["e-parse", "e-cli"], "Static review of CLI input", "User-supplied file path identified; no runtime permission/error assessment"),
        "privacy_and_data_lifecycle": ("Data represented in fixture", "assessed", ["e-data", "e-purpose"], "Read all fixture records", "Only invented order IDs and amounts in included CSV; no external transfer in inspected code"),
        "dependencies_and_licensing": ("Declared dependencies", "partial", ["e-deps"], "Read package metadata", "No third-party dependencies declared; no license file in toy fixture"),
        "testing_and_reliability": ("Existing test assertions", "assessed", ["e-tests"], "Read test source; do not execute", "Two happy-path assertions found; negative and precision cases absent"),
        "performance_and_resources": ("Runtime scale and resource use", "not_assessed", [], "No profiling performed", "Performance not measured"),
        "maintainability": ("Code and test organization", "assessed", ["e-float", "e-tests"], "Static review of small modules", "One small implementation and one test module"),
        "usability_and_accessibility": ("CLI usage and errors", "partial", ["e-cli", "e-parse"], "Read argument check and output", "Usage string exists; errors and real-user experience not tested"),
        "operations_and_recovery": ("Deployment and recovery", "not_assessed", [], "No operational environment exists", "No deployment, backup or recovery assessment"),
        "release_and_distribution": ("Packaging and release", "not_assessed", [], "No release workflow tested", "Manifest alone does not establish distribution readiness"),
        "content_and_data_quality": ("Fixture data quality", "assessed", ["e-data"], "Read complete example CSV", "Three invented rows; no claim about external data"),
    }
    checks = []
    for category in CHECK_CATEGORIES:
        title, status, evid_ids, method, result = specs[category]
        unfinished = status in {"partial", "not_assessed", "blocked"}
        checks.append({
            "id": "check-" + category, "category": category, "title": title,
            "status": status, "scope": "Five-file synthetic Pocket Ledger fixture",
            "method": method,
            "artifact_ids": sorted({e["artifact_id"] for e in evidence if e["id"] in evid_ids}),
            "evidence_ids": evid_ids, "related_ids": [],
            "verification_state": "static" if evid_ids else "unverified",
            "result": result,
            "limitations": "No target code executed; static evidence is not runtime verification",
            "reason": ("Static source review within declared scope" if status == "assessed"
                       else "Further verification is needed" if status == "partial"
                       else "This example intentionally does not perform this check"),
            "next_step": ("Perform an authorized targeted check before claiming completeness" if unfinished else None),
        })
    counts = dict(Counter(a["status"] for a in artifacts))
    check_counts = dict(Counter(c["status"] for c in checks))
    return {
        "schema_version": "1.2",
        "project": {
            "name": "Pocket Ledger (synthetic)",
            "purpose": "Demonstrate evidence-backed, static-first inspection of a tiny CSV totaler",
            "target_types": ["source", "sample data"],
            "source_locators": ["examples/demo-project/"],
            "snapshot": {"identity": "sha256:" + snapshot_hash, "time": INSPECTED_AT,
                         "method": "SHA-256 of sorted path/hash manifest"},
            "scope": "The five listed synthetic source files; no external resources or execution",
            "exclusions": ["Untracked/generated caches, if present, are outside the five-file source fixture"],
            "critical_artifact_ids": [FILE_IDS["ledger.py"], FILE_IDS["data/orders.csv"]],
        },
        "summary": {
            "overview": "A toy CSV totaler with three invented order records",
            "operation": "A CLI reads rows, converts amount strings to floats, sums and prints a two-decimal total",
            "condition": "Five files read statically; runtime behavior and release readiness unverified",
            "strengths": ["Small, readable source", "No third-party dependencies declared", "Basic happy-path tests present"],
            "priorities": ["Specify numeric precision", "Validate malformed CSV", "Verify runtime behavior before real use"],
            "readiness": "not established",
            "evidence_ids": ["e-purpose", "e-float", "e-parse", "e-tests"],
            "limitations": "Synthetic teaching example, not a real autonomous Scan run; no code execution, profiling or packaging checks",
        },
        "coverage": {
            "discovery_complete": True, "analysis_complete": True,
            "discovered_artifact_count": len(artifacts), "counts_by_status": counts,
            "counts_by_check_status": check_counts, "checks_complete": False,
            "limits": ["No runtime verification", "No performance or release assessment"],
            "sampling": "None within the five-file fixture",
            "methods": ["Full static reads", "Source path inventory", "SHA-256 per file", "Manual evidence anchoring"],
            "checks_performed": [c["title"] for c in checks if c["status"] == "assessed"],
            "checks_not_performed": [c["title"] for c in checks if c["status"] != "assessed"],
            "snapshot_consistency": "Hash-locked fixture membership and content at example generation",
            "sensitive_omissions": [],
        },
        "artifacts": artifacts,
        "components": [
            {"id": "component-cli", "name": "CLI entry point", "purpose": "Accept file path and display result",
             "artifact_ids": [FILE_IDS["ledger.py"]], "evidence_ids": ["e-cli"], "boundaries": "Caller-controlled path"},
            {"id": "component-tally", "name": "CSV totaler", "purpose": "Read CSV and sum amount cells",
             "artifact_ids": [FILE_IDS["ledger.py"], FILE_IDS["data/orders.csv"]],
             "evidence_ids": ["e-parse", "e-float", "e-data"], "boundaries": "No explicit row validation"},
            {"id": "component-tests", "name": "Unit tests", "purpose": "Assert two happy-path totals",
             "artifact_ids": [FILE_IDS["tests/test_ledger.py"]], "evidence_ids": ["e-tests"],
             "boundaries": "No negative/rounding test cases"},
        ],
        "relationships": [
            {"id": "relationship-cli", "from_id": "component-cli", "to_id": "component-tally",
             "kind": "calls", "explanation": "CLI main reads CSV then calls total_amount",
             "evidence_ids": ["e-parse", "e-cli"], "confidence": "high", "verification_state": "static"},
            {"id": "relationship-data", "from_id": FILE_IDS["data/orders.csv"], "to_id": "component-tally",
             "kind": "sample input", "explanation": "Example CSV has the amount column the code reads",
             "evidence_ids": ["e-data", "e-float"], "confidence": "high", "verification_state": "static"},
            {"id": "relationship-tests", "from_id": "component-tests", "to_id": "component-tally",
             "kind": "tests", "explanation": "Test module imports and asserts total_amount",
             "evidence_ids": ["e-tests"], "confidence": "high", "verification_state": "static"},
        ],
        "evidence": evidence, "findings": findings, "controls": controls,
        "unknowns": unknowns, "actions": actions, "checks": checks,
        "continuation": {
            "completed": ["Enumerated and read all five fixture source files", "Recorded static evidence and check coverage"],
            "remaining": ["Verify runtime rounding and errors", "Assess performance, operations and distribution if relevant"],
            "hypotheses": ["Decimal arithmetic may be preferable for money-like inputs"],
            "decisions": ["Keep this a synthetic static-only demonstration"],
            "revalidation": ["Rehash fixture files and compare source locators before reusing evidence"],
            "source_needs": ["Source bytes for any future behavioral analysis"],
            "authorization_note": "This example does not authorize execution or changes to an inspected target",
        },
        "extensions": {
            "fixture_notice": "Hand-authored synthetic worked example; not output from an autonomous scanning engine",
            "manifest_sha256": snapshot_hash, "file_sha256": file_hashes,
            "generated_by": "scripts/build_demo_report.py",
        },
    }


def evidence_links(state, ids):
    lookup = {e["id"]: e for e in state["evidence"]}
    return ", ".join(
        f'<a href="#e-{h(ident)}">{h(lookup[ident]["locator"])}</a>'
        for ident in ids
    ) if ids else "Not performed"


def scroll_table(label, headings, rows, css_class=""):
    head = "".join(f"<th scope=\"col\">{h(v)}</th>" for v in headings)
    body = "\n".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return (
        f'<div class="table-scroll" tabindex="0" role="region" aria-label="{h(label)}">'
        f'<table class="{h(css_class)}"><thead><tr>{head}</tr></thead>'
        f"<tbody>{body}</tbody></table></div>"
    )


def render(state):
    findings = state["findings"]
    unknowns = state["unknowns"]
    artifacts = state["artifacts"]
    checks = state["checks"]
    evidence = state["evidence"]
    counts = state["coverage"]["counts_by_check_status"]
    assessed = counts.get("assessed", 0)
    partial = counts.get("partial", 0)
    pending = counts.get("not_assessed", 0)
    short_hash = state["extensions"]["manifest_sha256"][:12]

    metrics = [
        ("Discovered", str(len(artifacts)), "Five fixture files"),
        ("Read & analyzed", str(sum(a["status"] == "analyzed" for a in artifacts)), "Static source only"),
        ("Checks assessed", f"{assessed}/{len(checks)}", f"{partial} partial · {pending} not assessed"),
        ("Findings", str(len(findings)), "Source-supported concerns"),
        ("Executed", "0", "No target code run"),
        ("Unknowns", str(len(unknowns)), "Explicit next questions"),
    ]
    metric_html = "".join(
        f'<article class="metric"><span>{h(label)}</span><b>{h(value)}</b>'
        f"<small>{h(note)}</small></article>"
        for label, value, note in metrics
    )
    finding_html = "".join(
        '<article class="finding risk"><div class="finding-top">'
        f'<span class="severity">{h(f["severity"])} · source review</span>'
        f'<span class="confidence">{h(f["confidence"])} confidence</span></div>'
        f'<h3>{h(f["title"])}</h3><p>{h(f["impact"])} '
        f'<strong>Limit:</strong> {h(f["uncertainty"])}</p>'
        f'<span class="evidence-ref">Evidence: {evidence_links(state, f["evidence_ids"])}</span></article>'
        for f in findings
    )
    control_html = "".join(
        '<article class="control"><span class="control-state">Implemented · effectiveness unverified</span>'
        f'<h3>{h(c["description"])}</h3><p>{h(c["limitations"])}</p>'
        f'<span class="evidence-ref">Evidence: {evidence_links(state, c["evidence_ids"])}</span></article>'
        for c in state["controls"]
    )
    component_html = "".join(
        '<article class="module"><div class="module-head"><span class="module-dot"></span>'
        f'<h3>{h(c["name"])}</h3></div><p class="purpose">{h(c["purpose"])}</p>'
        f'<dl><div><dt>Boundary</dt><dd>{h(c["boundaries"])}</dd></div>'
        f'<div><dt>Evidence</dt><dd>{evidence_links(state, c["evidence_ids"])}</dd></div></dl></article>'
        for c in state["components"]
    )
    unknown_html = "".join(
        '<article class="finding unverified"><div class="finding-top">'
        '<span class="severity">Not verified</span></div>'
        f'<h3>{h(u["question"])}</h3><p>{h(u["reason"])}. '
        f'<strong>Next:</strong> {h(u["next_safe_step"])}.</p>'
        f'<span class="evidence-ref">Evidence: {evidence_links(state, u["evidence_ids"])}</span></article>'
        for u in unknowns
    )
    action_html = "".join(
        '<article class="action">'
        f'<span class="action-no">{index:02}</span><h3>{h(a["description"])}</h3>'
        f'<p>Verify: {h(a["expected_verification"])}. '
        f'Approval: {h(a["authorization_requirements"])}.</p></article>'
        for index, a in enumerate(state["actions"], 1)
    )
    check_labels = {
        "assessed": "Assessed · scoped",
        "partial": "Partially assessed",
        "not_assessed": "Not assessed",
        "blocked": "Blocked",
        "not_applicable": "Not applicable",
    }
    check_rows = []
    for c in checks:
        check_rows.append([
            f'<strong>{h(c["title"])}</strong>',
            h(c["scope"]) + "<br>" + h(c["method"]),
            h(check_labels[c["status"]]),
            h(c["result"]) + "<br><small>" + h(c["limitations"]) + "</small>",
            evidence_links(state, c["evidence_ids"]),
        ])
    inventory_rows = [
        [f'<code>{h(a["id"])}</code>', h(a["locator"]), h(a["type"]),
         h(a["status"]) + " · " + h(a["inspection_origin"]),
         f'<code>{h(a["content_identity"][7:19])}…</code>',
         evidence_links(state, a["evidence_ids"])]
        for a in artifacts
    ]
    evidence_rows = [
        [f'<code id="e-{h(e["id"])}">{h(e["id"])}</code>', h(e["kind"]),
         h(e["locator"]), h(e["result"]), h(e["limitations"])]
        for e in evidence
    ]
    coverage_rows = [
        ("Fixture membership", "5 of 5 source files", 100),
        ("Static file analysis", "5 of 5 source files", 100),
        ("Checks assessed", f"{assessed} of {len(checks)}", round(100 * assessed / len(checks))),
        ("Dynamic verification", "Not performed", 0),
    ]
    coverage_html = "".join(
        '<div class="coverage-row">'
        f'<span>{h(label)}</span><div class="bar" aria-hidden="true">'
        f'<i style="width:{width}%"></i></div><b>{h(value)}</b></div>'
        for label, value, width in coverage_rows
    )
    system_map = (
        '<div class="map-row map-top">'
        '<div class="map-node owner"><b>CLI argument</b><span>Caller chooses a CSV path</span></div>'
        '<span class="map-arrow" aria-hidden="true">→</span>'
        '<div class="map-node"><b>CSV → float sum</b><span>DictReader + total_amount</span></div>'
        '<span class="map-arrow" aria-hidden="true">→</span>'
        '<div class="map-node tests"><b>Formatted total</b><span>Printed with two decimals</span></div>'
        '</div><p class="evidence-ref">Statically traced from '
        + evidence_links(state, ["e-cli", "e-parse", "e-float"])
        + '. The diagram does not represent an observed run.</p>'
    )
    target_specific = (
        '<section class="section" aria-labelledby="interpret-title">'
        '<div class="section-head"><div class="section-kicker">Reading this example</div>'
        '<h2 id="interpret-title">Proof, not theater</h2>'
        '<p class="section-intro">This is a manually authored synthetic example of the report format. '
        'It does not show an AI agent autonomously inspecting a real repository.</p></div>'
        '<div class="insights"><article class="insight"><span>Supported</span>'
        '<h3>What the source shows</h3><p>Exact files, hashes, code paths, tests, and '
        'the limits of the static conclusions are embedded below.</p></article>'
        '<article class="insight"><span>Not established</span><h3>What still needs work</h3>'
        '<p>No execution, benchmark, deployment, external security check, or '
        'financial correctness certification took place.</p></article></div></section>'
    )
    appendix = (
        "<h3>Source inventory · all five fixture files</h3>"
        + scroll_table("Source inventory; scroll horizontally if needed",
                       ["ID", "File", "Type", "Read status", "SHA-256 prefix", "Evidence"],
                       inventory_rows, "table-inventory")
        + "<h3>Evidence · precise source locators</h3>"
        + scroll_table("Evidence; scroll horizontally if needed",
                       ["ID", "Kind", "Locator", "Observation", "Limitations"],
                       evidence_rows, "table-evidence")
    )
    slots = {
        "REPORT_TITLE": "Pocket Ledger | Scan synthetic example",
        "INSPECTION_LABEL": '<span class="live-dot" aria-hidden="true"></span> Synthetic example · static inspection',
        "PROJECT_NAME": "Pocket Ledger",
        "PLAIN_LANGUAGE_PURPOSE": "A five-file fictional CSV totaler, inspected without running it. Every conclusion points to source evidence, and the report distinguishes file coverage from check coverage.",
        "VERDICT_PILLS_HTML": '<span class="verdict-pill"><strong>Readiness</strong> Not established</span>'
                              '<span class="verdict-pill"><strong>Source</strong> 5 / 5 analyzed</span>'
                              '<span class="verdict-pill"><strong>Checks</strong> Incomplete</span>',
        "SNAPSHOT_HTML": f'Synthetic fixture · static snapshot {h(INSPECTED_AT)}<br>'
                         f'Path/hash manifest <code>sha256:{h(short_hash)}…</code>',
        "METRIC_CARDS_HTML": metric_html,
        "VERDICT_TITLE": "Two risks worth verifying",
        "VERDICT_SCOPE_AND_LIMITS": "This verdict is limited to the five synthetic source files. It is not a security clearance, runtime test result, or production readiness decision.",
        "COVERAGE_STATUS_BANNER_HTML": '<div class="status-banner"><div class="status-icon" aria-hidden="true">?</div>'
                                       '<div><h3>All fixture files read; checks remain incomplete</h3>'
                                       f'<p>{assessed} assessed, {partial} partial, {pending} not assessed. '
                                       'File analysis does not prove runtime behavior or safety.</p></div></div>',
        "PRIORITY_FINDING_CARDS_HTML": finding_html,
        "ANATOMY_TITLE": "From CSV to total",
        "ANATOMY_EXPLANATION": "The source shows a simple call path. The relationships below are static deductions, not an observed execution trace.",
        "EVIDENCED_SYSTEM_MAP_HTML": system_map,
        "STRENGTHS_TITLE": "What is implemented",
        "CONTROL_VERIFICATION_LIMITS": "These controls exist in the source, but their effectiveness has not been observed.",
        "CONTROL_CARDS_HTML": control_html,
        "PARTS_TITLE": "Three moving parts",
        "PARTS_INTRO": "The CLI, tally function and tests are small enough to inspect in full.",
        "COMPONENT_CARDS_HTML": component_html,
        "UNKNOWNS_TITLE": "The unanswered questions",
        "UNKNOWNS_INTRO": "Unperformed work stays visible rather than being counted as passed.",
        "UNKNOWN_CARDS_HTML": unknown_html,
        "COVERAGE_TITLE": "Coverage is not a grade",
        "DISCOVERY_VS_ANALYSIS": "Discovery counts files; analysis records what was understood; check coverage records which questions were actually assessed.",
        "COVERAGE_ROWS_HTML": coverage_html,
        "COVERAGE_DETAIL": "Bars show scoped work completion, not code quality. Five files were read statically; no target code was executed. Check completeness is false.",
        "TARGET_SPECIFIC_SECTIONS_HTML": target_specific,
        "NEXT_STEPS_TITLE": "Verify before relying",
        "NEXT_STEPS_INTRO": "These are proposed follow-ups, not changes made to the toy target.",
        "ACTION_CARDS_HTML": action_html,
        "CHECK_COVERAGE_INTRO": "Each category is explicitly accounted for. Assessed means the stated narrow check was performed; it never means passed.",
        "CHECK_COVERAGE_MATRIX_HTML": scroll_table(
            "Check coverage; scroll horizontally if needed",
            ["Check", "Scope and method", "Status", "Result and limits", "Evidence"],
            check_rows, "table-checks"),
        "APPENDIX_INTRO": "Source-backed evidence and exact inventory are embedded here and in the inert JSON state. The HTML cannot recreate missing source bytes.",
        "SEARCHABLE_EVIDENCE_AND_INVENTORY_HTML": appendix,
        "INSPECTION_BOUNDARY": "Synthetic fixture only · source read, no execution · " + h(INSPECTED_AT),
        "STATE_JSON": json.dumps(state, ensure_ascii=False, indent=2).replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e"),
    }
    html = SHELL.read_text(encoding="utf-8")
    for name, value in slots.items():
        placeholder = "{{" + name + "}}"
        if html.count(placeholder) != 1:
            raise ValueError(f"Template slot {name} expected once")
        html = html.replace(placeholder, value)
    remaining = re.findall(r"\{\{[A-Z_]+\}\}", html)
    if remaining:
        raise ValueError(f"Unfilled report template slots: {remaining}")
    return html


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail if checked-in report is stale")
    args = parser.parse_args()
    output = render(build_state(load_fixture()))
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != output:
            raise SystemExit("STALE: run python scripts/build_demo_report.py")
        print("PASS: generated demo matches committed HTML")
    else:
        with OUTPUT.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(output)
        print(f"Wrote {OUTPUT.relative_to(ROOT)}")
    validate(str(OUTPUT))


if __name__ == "__main__":
    main()
