# Evidence federation bundle v1

Scan can federate evidence from specialist tools without loading or executing a plugin. The bundle is a bounded JSON interchange format for adapters that already have a specialist result and a Scan 1.4 state for the same snapshot.

## Command

```bash
scan import-evidence .scan/state.json specialist.scan-evidence.json \
  --output .scan/state-with-specialist-evidence.json \
  --report .scan/report-with-specialist-evidence.html \
  --json
```

Import is read-only with respect to the target project. It performs no network access and does not execute the producer, adapter, target code, package hooks, or arbitrary commands.

## Trust bindings

A v1 bundle must identify the target `snapshot_digest`. An adapter may additionally bind the exact base `state_digest`; when present, Scan requires an exact match. Every mapped result also carries the exact `artifact_content_identity` and Scan rejects the entire import when it differs from the current canonical artifact.

This allows multiple specialist bundles to be imported sequentially against one unchanged project snapshot while still preventing a path-only result from being replayed onto changed bytes. Use `target.state_digest` when the adapter depends on the exact pre-import state rather than only the project snapshot.

## Provenance

The bundle records three different identities:

- `producer`: the specialist external tool and version;
- `adapter`: the data-only converter that produced the Scan bundle;
- `source`: the adapter-declared originating format and SHA-256 digest.

Scan independently hashes the exact federation bundle bytes it actually imports. Canonical evidence uses that verified bundle digest as `source_digest`. The originating `source.digest` is retained in the federation import receipt but is explicitly marked as **not independently verified by Scan**, because the originating specialist payload is not supplied to this importer.

## Coverage boundary

Every bundle must include an explicit `coverage.scope`, `coverage.limitations`, and `coverage.whole_project_complete: false`. Scan rejects `true`.

Federated evidence can move a mapped artifact to `partial` when it was not already fully analyzed and the imported evidence is substantive. It never upgrades an artifact to `analyzed`, never upgrades Scan's whole-project `analysis_complete`, and never turns an external tool's silence into a clean result.

## Results

Each result has a stable `external_id`, `disposition` (`finding` or `unknown`), repository-relative artifact locator, exact artifact content identity, and an evidence record. Mapped findings become canonical Scan findings backed by external-tool evidence. Mapped unknowns become canonical unknowns backed by the same evidence.

If a safe repository-relative locator does not map to a canonical file artifact in the current state, Scan retains the result as an explicit unknown without promoting it to a finding. If the locator maps but its content identity does not match, import fails closed as stale or misbound evidence.

Repeated identical `external_id` rows in one bundle are ignored after the first. Reusing an `external_id` for conflicting content is an error.

## Privacy and limits

Target-derived strings pass through the Scan state's configured redaction policy. The importer bounds the bundle to 64 MB, 10,000 results, and 20,000 characters per semantic text field. Artifact paths must be canonical repository-relative paths; absolute paths, `..`, Windows drive syntax, and backslash paths are rejected.

The v1 schema is packaged as `scan_core/schemas/evidence-federation-bundle-1.schema.json`.

## Minimal example

```json
{
  "scan_evidence_bundle_version": "1",
  "target": {
    "snapshot_digest": "sha256:...",
    "state_digest": "sha256:..."
  },
  "producer": {"kind": "external-tool", "name": "ExampleScanner", "version": "3.2.1"},
  "adapter": {"name": "example-to-scan", "version": "1.0.0"},
  "source": {"format": "example-json", "digest": "sha256:..."},
  "coverage": {
    "scope": "ExampleScanner enabled rules over selected source files",
    "limitations": "Static specialist rules only; no runtime verification",
    "whole_project_complete": false
  },
  "results": [
    {
      "external_id": "EX-001",
      "disposition": "finding",
      "artifact_locator": "src/app.py",
      "artifact_content_identity": "sha256:...",
      "evidence": {
        "locator": "src/app.py:42",
        "kind": "static",
        "class": "static_semantic",
        "claim": "The specialist reports rule EX-001 on this artifact",
        "result": "Bounded redacted result text",
        "method": "Imported specialist static-analysis output",
        "limitations": "Not independently reproduced by Scan"
      },
      "finding": {
        "title": "Specialist-reported condition",
        "impact": "Impact described by the adapter",
        "severity": "medium",
        "confidence": "external-tool-reported",
        "verification_state": "static",
        "uncertainty": "Imported external evidence",
        "recommendation": "Review and remediate the condition",
        "safe_verification": "Rerun the same specialist configuration after the change"
      }
    }
  ]
}
```

## Non-goals

This format is not a plugin API, package manager, scanner execution protocol, or trust score. Adapters produce bounded data; specialist tools keep ownership of their analysis engines. Scan owns the imported evidence semantics, provenance, snapshot/artifact binding, unknown preservation, and coverage honesty.
